<#
.SYNOPSIS
Builds the old-to-new principal mapping file used by the import, the Group
Policy migration table, and NTFS ACL translation.

.DESCRIPTION
The new domain issues brand new SIDs, so nothing that references an old SID
survives on its own: group membership, NTFS ACEs, share permissions, and the
security principals baked into Group Policy all have to be re-pointed.

This script reads an export package and emits ONE reviewable CSV that says, for
every principal referenced anywhere in that package, what it should become in
the new domain. Every later step consumes this file, so it is the single place
to correct a rename, merge two accounts, or exclude a principal from the
rebuild.

Review the output before importing. The defaults are sensible, not authoritative:
identity decisions belong to a human.

Actions written into the map:

  Create        Recreate this principal in the new domain.
  MapToBuiltIn  Match a built-in principal by RID (locale independent).
  Keep          Well-known SID that is identical in every domain, for example
                BUILTIN\Administrators or NT AUTHORITY\SYSTEM. Used verbatim.
  MapToExisting The principal already exists in the target domain.
  Review        Referenced by an ACL but not present in the export. Usually an
                orphaned SID from a long-deleted account. Decide manually.
  Skip          Excluded from the rebuild.

.PARAMETER PackagePath
Root folder of a package produced by Export-AdEnvironment.ps1.

.PARAMETER TargetDomainDns
DNS name of the NEW domain, for example corp.contoso.com.

.PARAMETER TargetDomainNetBios
NetBIOS name of the NEW domain. Defaults to the first label of TargetDomainDns.

.PARAMETER TargetUpnSuffix
UPN suffix to assign to imported users. For an Entra hybrid deployment this MUST
be a publicly routable domain that is verified in the tenant, never a .local
name. Defaults to TargetDomainDns.

.PARAMETER OutputPath
Where to write the map. Defaults to import\principal-map.csv inside the package.

.PARAMETER QueryTargetDomain
Check the target domain for principals that already exist and mark them
MapToExisting instead of Create. Run this on the new domain controller.

.PARAMETER Server
Target domain controller to query when -QueryTargetDomain is used.

.PARAMETER Credential
Credentials for the target domain query.

.PARAMETER ExcludeSamAccountName
Principals to mark as Skip rather than Create.

.PARAMETER Force
Overwrite an existing map file. Without this the script refuses, so hand edits
are never silently discarded.

.EXAMPLE
.\New-AdPrincipalMap.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500 -TargetDomainDns corp.contoso.com -TargetUpnSuffix contoso.com

.EXAMPLE
.\New-AdPrincipalMap.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500 -TargetDomainDns corp.contoso.com -QueryTargetDomain
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PackagePath,

    [Parameter(Mandatory)]
    [string]$TargetDomainDns,

    [string]$TargetDomainNetBios,

    [string]$TargetUpnSuffix,

    [string]$OutputPath,

    [switch]$QueryTargetDomain,

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string[]]$ExcludeSamAccountName,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

$manifest = Get-AkPackageManifest -PackagePath $PackagePath

if ([string]::IsNullOrWhiteSpace($TargetDomainNetBios)) {
    $TargetDomainNetBios = $TargetDomainDns.Split(".")[0].ToUpperInvariant()
}

if ([string]::IsNullOrWhiteSpace($TargetUpnSuffix)) {
    $TargetUpnSuffix = $TargetDomainDns
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Get-AkPackageItemPath -PackagePath $PackagePath -Item PrincipalMap
}

if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) {
    throw "A principal map already exists at '$OutputPath'. Re-run with -Force to regenerate it, but note that any manual edits will be lost."
}

$logPath = Join-Path -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item LogFolder) -ChildPath "principal-map.log"
Start-AkLog -Path $logPath

$sourceDomainDn = $manifest.SourceDomainDn
$targetDomainDn = ConvertTo-AkDomainDn -DnsDomainName $TargetDomainDns
$sourceNetBios = Get-AkPropertyValue -InputObject $manifest -Name "SourceDomainNetBios" -Default ""

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  PRINCIPAL MAP" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-AkLog -Message "Source: $($manifest.SourceDomainDns) [$sourceDomainDn]" -Level Info
Write-AkLog -Message "Target: $TargetDomainDns [$targetDomainDn] NetBIOS $TargetDomainNetBios" -Level Info
Write-AkLog -Message "Target UPN suffix: $TargetUpnSuffix" -Level Info

if ($TargetUpnSuffix -match '\.(local|lan|internal|corp|home|intranet|test|localdomain)$' -or $TargetUpnSuffix -notlike "*.*") {
    Write-AkLog -Message "UPN suffix '$TargetUpnSuffix' is not publicly routable. Entra Connect cannot sync users with an unroutable UPN; they would be rewritten to onmicrosoft.com. Add and verify a routable suffix before importing." -Level Warning
}

$excluded = @($ExcludeSamAccountName)
$wellKnownRids = Get-AkWellKnownRidMap
$entries = New-Object System.Collections.Generic.List[object]
$seenSids = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)

# ---------------------------------------------------------------------------
# Optional lookup of what already exists in the target domain
# ---------------------------------------------------------------------------

$existingSam = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)

if ($QueryTargetDomain) {
    Assert-AkModule -Name "ActiveDirectory" -Reason "-QueryTargetDomain reads the target domain."

    $adParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $adParams["Server"] = $Server }
    if ($Credential) { $adParams["Credential"] = $Credential }

    Write-AkLog -Message "Reading existing principals from the target domain..." -Level Step
    foreach ($existing in @(Get-ADUser -Filter * @adParams)) { [void]$existingSam.Add($existing.SamAccountName) }
    foreach ($existing in @(Get-ADGroup -Filter * @adParams)) { [void]$existingSam.Add($existing.SamAccountName) }
    Write-AkLog -Message "Target domain already contains $($existingSam.Count) principals." -Level Info
}

function Resolve-TargetAction {
    <#
    .SYNOPSIS
    Chooses the default action for one source principal.
    #>
    param(
        [Parameter(Mandatory)][string]$SamAccountName,
        [string]$WellKnownRidName
    )

    if ($excluded -contains $SamAccountName) { return "Skip" }
    if (-not [string]::IsNullOrWhiteSpace($WellKnownRidName)) { return "MapToBuiltIn" }
    if ($existingSam.Contains($SamAccountName)) { return "MapToExisting" }
    return "Create"
}

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

$users = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Users)
Write-AkLog -Message "Mapping $($users.Count) users..." -Level Step

foreach ($user in $users) {
    $sam = Get-AkPropertyValue -InputObject $user -Name "SamAccountName"
    if ([string]::IsNullOrWhiteSpace($sam)) { continue }

    $sid = Get-AkPropertyValue -InputObject $user -Name "SourceSid" -Default ""
    $rid = Get-AkPropertyValue -InputObject $user -Name "SourceRid"
    $wellKnown = $null
    if ($rid -and $wellKnownRids.ContainsKey([string]$rid)) { $wellKnown = $wellKnownRids[[string]$rid] }

    $sourceDn = Get-AkPropertyValue -InputObject $user -Name "DistinguishedName" -Default ""
    $sourceUpn = Get-AkPropertyValue -InputObject $user -Name "UserPrincipalName" -Default ""

    # Keep the local part of the UPN, replace the suffix. Falls back to the
    # sAMAccountName when the source account had no UPN at all.
    $upnLocalPart = $sam
    if ($sourceUpn -like "*@*") { $upnLocalPart = $sourceUpn.Split("@")[0] }

    $entries.Add([pscustomobject]@{
        SourceType           = "User"
        SourceSamAccountName = $sam
        SourceDn             = $sourceDn
        SourceSid            = $sid
        SourceRid            = $rid
        SourceUpn            = $sourceUpn
        SourceAccount        = if ([string]::IsNullOrWhiteSpace($sourceNetBios)) { $sam } else { "$sourceNetBios\$sam" }
        WellKnownRidName     = $wellKnown
        Action               = Resolve-TargetAction -SamAccountName $sam -WellKnownRidName $wellKnown
        TargetSamAccountName = $sam
        TargetUpn            = "$upnLocalPart@$TargetUpnSuffix"
        TargetAccount        = "$TargetDomainNetBios\$sam"
        TargetDn             = ConvertTo-AkTargetDn -SourceDn $sourceDn -SourceDomainDn $sourceDomainDn -TargetDomainDn $targetDomainDn
        Notes                = ""
    })

    if (-not [string]::IsNullOrWhiteSpace($sid)) { [void]$seenSids.Add($sid) }
}

# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

$groups = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Groups)
Write-AkLog -Message "Mapping $($groups.Count) groups..." -Level Step

foreach ($group in $groups) {
    $sam = Get-AkPropertyValue -InputObject $group -Name "SamAccountName"
    if ([string]::IsNullOrWhiteSpace($sam)) { continue }

    $sid = Get-AkPropertyValue -InputObject $group -Name "SourceSid" -Default ""
    $rid = Get-AkPropertyValue -InputObject $group -Name "SourceRid"
    $wellKnown = Get-AkPropertyValue -InputObject $group -Name "WellKnownRidName"
    $sourceDn = Get-AkPropertyValue -InputObject $group -Name "DistinguishedName" -Default ""

    $notes = ""
    if (Test-AkIsBuiltInSid -Sid $sid) {
        $notes = "Built-in or well-known SID. Identical in the target domain."
    }
    elseif (-not [string]::IsNullOrWhiteSpace($wellKnown)) {
        $notes = "Matched by RID $rid, not by name. Built-in group names differ between locales."
    }

    $action = Resolve-TargetAction -SamAccountName $sam -WellKnownRidName $wellKnown
    if (Test-AkIsBuiltInSid -Sid $sid) { $action = "Keep" }

    $entries.Add([pscustomobject]@{
        SourceType           = "Group"
        SourceSamAccountName = $sam
        SourceDn             = $sourceDn
        SourceSid            = $sid
        SourceRid            = $rid
        SourceUpn            = ""
        SourceAccount        = if ([string]::IsNullOrWhiteSpace($sourceNetBios)) { $sam } else { "$sourceNetBios\$sam" }
        WellKnownRidName     = $wellKnown
        Action               = $action
        TargetSamAccountName = $sam
        TargetUpn            = ""
        TargetAccount        = "$TargetDomainNetBios\$sam"
        TargetDn             = ConvertTo-AkTargetDn -SourceDn $sourceDn -SourceDomainDn $sourceDomainDn -TargetDomainDn $targetDomainDn
        Notes                = $notes
    })

    if (-not [string]::IsNullOrWhiteSpace($sid)) { [void]$seenSids.Add($sid) }
}

# ---------------------------------------------------------------------------
# Principals referenced only by ACLs
# ---------------------------------------------------------------------------
# An ACE can name a principal that no longer exists as a directory object, or a
# well-known identity such as BUILTIN\Users. Both must appear in the map so the
# import never silently drops an access rule.

$aclIdentities = @{}

foreach ($ace in (Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item NtfsAcl))) {
    $sid = Get-AkPropertyValue -InputObject $ace -Name "IdentitySid" -Default ""
    $name = Get-AkPropertyValue -InputObject $ace -Name "IdentityReference" -Default ""
    if ([string]::IsNullOrWhiteSpace($sid) -and [string]::IsNullOrWhiteSpace($name)) { continue }

    $key = if ([string]::IsNullOrWhiteSpace($sid)) { $name } else { $sid }
    if (-not $aclIdentities.ContainsKey($key)) {
        $aclIdentities[$key] = [pscustomobject]@{ Sid = $sid; Name = $name; Source = "NtfsAcl" }
    }
}

foreach ($access in (Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item ShareAccess))) {
    $name = Get-AkPropertyValue -InputObject $access -Name "AccountName" -Default ""
    if ([string]::IsNullOrWhiteSpace($name)) { continue }
    if (-not $aclIdentities.ContainsKey($name)) {
        $aclIdentities[$name] = [pscustomobject]@{ Sid = ""; Name = $name; Source = "ShareAccess" }
    }
}

$aclOnlyCount = 0

foreach ($key in $aclIdentities.Keys) {
    $identity = $aclIdentities[$key]
    $sid = $identity.Sid
    $name = $identity.Name

    if (-not [string]::IsNullOrWhiteSpace($sid) -and $seenSids.Contains($sid)) {
        continue    # Already mapped as a user or group.
    }

    # Strip the domain prefix so the sAMAccountName can be matched against the map.
    $bareName = $name
    if ($name -like "*\*") { $bareName = $name.Split("\")[-1] }

    $alreadyMapped = @($entries | Where-Object { $_.SourceSamAccountName -eq $bareName })
    if ($alreadyMapped.Count -gt 0) { continue }

    $isBuiltIn = $false
    if (-not [string]::IsNullOrWhiteSpace($sid)) {
        $isBuiltIn = Test-AkIsBuiltInSid -Sid $sid
    }
    elseif ($name -match '^(BUILTIN|NT AUTHORITY|CREATOR OWNER|Everyone|NT SERVICE)\\?') {
        $isBuiltIn = $true
    }

    $action = "Review"
    $notes = "Referenced by an ACL but not present in the export. Likely an orphaned SID from a deleted account, or a principal from another domain. Decide manually before import."

    if ($isBuiltIn) {
        $action = "Keep"
        $notes = "Well-known identity. Used verbatim in the target domain."
    }

    $entries.Add([pscustomobject]@{
        SourceType           = "AclIdentity"
        SourceSamAccountName = $bareName
        SourceDn             = ""
        SourceSid            = $sid
        SourceRid            = Get-AkSidRid -Sid $sid
        SourceUpn            = ""
        SourceAccount        = $name
        WellKnownRidName     = ""
        Action               = $action
        TargetSamAccountName = if ($isBuiltIn) { $bareName } else { "" }
        TargetUpn            = ""
        TargetAccount        = if ($isBuiltIn) { $name } else { "" }
        TargetDn             = ""
        Notes                = $notes
    })

    $aclOnlyCount++
}

# ---------------------------------------------------------------------------
# Detect target collisions before they become import failures
# ---------------------------------------------------------------------------

$collisions = @($entries |
    Where-Object { $_.Action -eq "Create" -and -not [string]::IsNullOrWhiteSpace($_.TargetSamAccountName) } |
    Group-Object -Property TargetSamAccountName |
    Where-Object { $_.Count -gt 1 })

foreach ($collision in $collisions) {
    foreach ($entry in $collision.Group) {
        $entry.Notes = "COLLISION: $($collision.Count) principals map to sAMAccountName '$($collision.Name)'. Edit TargetSamAccountName to make them unique before importing. " + $entry.Notes
    }
    Write-AkLog -Message "sAMAccountName collision on '$($collision.Name)' across $($collision.Count) principals." -Level Warning
}

$upnCollisions = @($entries |
    Where-Object { $_.SourceType -eq "User" -and $_.Action -eq "Create" -and -not [string]::IsNullOrWhiteSpace($_.TargetUpn) } |
    Group-Object -Property TargetUpn |
    Where-Object { $_.Count -gt 1 })

foreach ($collision in $upnCollisions) {
    foreach ($entry in $collision.Group) {
        $entry.Notes = "COLLISION: duplicate target UPN '$($collision.Name)'. Entra Connect will refuse to sync duplicates. " + $entry.Notes
    }
    Write-AkLog -Message "UPN collision on '$($collision.Name)' across $($collision.Count) users." -Level Warning
}

# ---------------------------------------------------------------------------
# Write and summarize
# ---------------------------------------------------------------------------

$sorted = @($entries | Sort-Object SourceType, SourceSamAccountName)
[void](Export-AkCsv -InputObject $sorted -Path $OutputPath)

Write-Host ""
Write-AkLog -Message "Principal map written to $OutputPath" -Level Success
Write-Host ""
Write-Host "  Entries by action:" -ForegroundColor Cyan
foreach ($group in ($sorted | Group-Object -Property Action | Sort-Object Name)) {
    Write-Host ("    {0,-16} {1}" -f $group.Name, $group.Count)
}
Write-Host ""

$reviewCount = @($sorted | Where-Object { $_.Action -eq "Review" }).Count
if ($reviewCount -gt 0) {
    Write-Host "  $reviewCount principal(s) need manual review before import." -ForegroundColor Yellow
}
if ($collisions.Count -gt 0 -or $upnCollisions.Count -gt 0) {
    Write-Host "  Resolve the COLLISION notes in the map before importing." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Review the map, edit TargetSamAccountName / TargetUpn / Action as needed," -ForegroundColor Cyan
Write-Host "then run Import-AdEnvironment.ps1 -WhatIf." -ForegroundColor Cyan
Write-Host ""

Stop-AkLog

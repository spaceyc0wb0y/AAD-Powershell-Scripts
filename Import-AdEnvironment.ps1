<#
.SYNOPSIS
Rebuilds an exported Active Directory environment inside a NEW domain with a
different name, without any trust, replication, or connectivity to the old one.

.DESCRIPTION
Run this on the NEW domain controller, against a package folder copied from the
old domain by Export-AdEnvironment.ps1 and a principal map produced by
New-AdPrincipalMap.ps1.

The rebuild runs in ordered phases. Each phase can be run on its own, and every
phase supports -WhatIf:

  OrganizationalUnits  Recreate the OU tree, parents before children.
  Groups               Recreate groups as empty shells.
  Users                Recreate users with new random passwords.
  Membership           Second pass that fills in group membership and primary
                       groups, once every principal exists.
  WmiFilters           Recreate WMI filters, preserving their filter IDs.
  Gpo                  Import GPO backups through a generated migration table.
  GpoLinks             Re-link GPOs and restore link order, enforcement, and
                       enabled state.
  Shares               Recreate SMB shares, share permissions, and NTFS ACLs.
  Validate             Scan the rebuilt GPOs for surviving references to the old
                       domain and report anything the migration table missed.

WHAT CANNOT COME ACROSS, and why:

- Passwords. Password hashes cannot leave a domain without a trust and ADMT.
  Every imported user gets a generated password, is flagged to change it at next
  sign in, and the passwords are written to a CSV inside the package.
- SID history. Also requires a trust and ADMT. Because the new accounts have new
  SIDs, anything still secured by an old SID must be re-permissioned. That is
  what the principal map and the Shares phase are for.
- Computer accounts. Workstations and member servers must be rejoined to the new
  domain; their old accounts are exported as inventory only.

.PARAMETER PackagePath
Root folder of a package produced by Export-AdEnvironment.ps1.

.PARAMETER PrincipalMapPath
Principal map CSV. Defaults to import\principal-map.csv inside the package.

.PARAMETER Phase
Which phases to run. Defaults to All, which runs them in the correct order
regardless of the order given here.

.PARAMETER Server
Target domain controller. Defaults to the current domain's preferred DC.

.PARAMETER Credential
Credentials for the target domain.

.PARAMETER TargetOuRoot
Optional DN to nest the entire imported OU tree beneath, for example
"OU=Migrated,DC=corp,DC=contoso,DC=com". By default the tree is recreated at the
domain root, mirroring its original shape.

.PARAMETER PasswordLength
Length of generated passwords. Minimum 12.

.PARAMETER DoNotRequirePasswordChange
Leave imported accounts without the change-at-next-logon flag. Not recommended.

.PARAMETER CreateUsersDisabled
Create every user disabled regardless of their state in the source domain. Use
this for a rehearsal run or a staged cutover.

.PARAMETER ReplaceServerName
Hashtable mapping old server names to new ones, applied to UNC paths in the GPO
migration table and to share paths. For example @{ 'OLDFS01' = 'NEWFS01' }.

.PARAMETER LinkTargetMap
Hashtable mapping an exported GPO link target DN to the DN to link onto in the
new domain. Use it when the new domain has its own OU layout, so translating the
source DN by suffix would point at a container that does not exist. An empty
value drops the link deliberately. For example
@{ 'OU=Staff,DC=old,DC=net' = 'OU=Users,OU=HQ,DC=new,DC=com'; 'OU=Gone,DC=old,DC=net' = '' }.

.PARAMETER SharePathMap
Hashtable mapping old local share roots to new ones on this server, for example
@{ 'D:\Shares' = 'E:\Data' }.

.PARAMETER CreateMissingShareFolders
Create share target folders that do not exist yet.

.PARAMETER SkipExisting
Skip objects that already exist in the target rather than reporting them as
errors. On by default, which makes the whole import safely re-runnable.

.EXAMPLE
.\Import-AdEnvironment.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500 -WhatIf

.EXAMPLE
.\Import-AdEnvironment.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500 -Phase OrganizationalUnits,Groups,Users

.EXAMPLE
.\Import-AdEnvironment.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500 -Phase Shares -ReplaceServerName @{ 'OLDFS01' = 'NEWFS01' }

.NOTES
Requires the ActiveDirectory and GroupPolicy modules, and Domain Admin rights in
the target domain. Target runtime is Windows PowerShell 5.1.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory)]
    [string]$PackagePath,

    [string]$PrincipalMapPath,

    [ValidateSet("All", "OrganizationalUnits", "Groups", "Users", "Membership", "WmiFilters", "Gpo", "GpoLinks", "Shares", "Validate")]
    [string[]]$Phase = @("All"),

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$TargetOuRoot,

    [ValidateRange(12, 128)]
    [int]$PasswordLength = 20,

    [switch]$DoNotRequirePasswordChange,

    [switch]$CreateUsersDisabled,

    [hashtable]$ReplaceServerName = @{},

    [hashtable]$LinkTargetMap = @{},

    [hashtable]$SharePathMap = @{},

    [switch]$CreateMissingShareFolders,

    [bool]$SkipExisting = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force
Assert-AkModule -Name "ActiveDirectory" -Reason "Directory objects are created with the AD cmdlets."

$adParams = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $adParams["Server"] = $Server }
if ($Credential) { $adParams["Credential"] = $Credential }

# Phases always execute in dependency order, never in the order the caller typed.
$phaseOrder = @("OrganizationalUnits", "Groups", "Users", "Membership", "WmiFilters", "Gpo", "GpoLinks", "Shares", "Validate")
$requested = @($Phase)
$activePhases = @($phaseOrder | Where-Object { $requested -contains "All" -or $requested -contains $_ })

function Test-Phase {
    param([Parameter(Mandatory)][string]$Name)
    return ($activePhases -contains $Name)
}

# ---------------------------------------------------------------------------
# Load package, map, and target domain facts
# ---------------------------------------------------------------------------

$manifest = Get-AkPackageManifest -PackagePath $PackagePath
$targetDomain = Get-ADDomain @adParams

$sourceDomainDn = $manifest.SourceDomainDn
$sourceDomainDns = $manifest.SourceDomainDns
$sourceNetBios = Get-AkPropertyValue -InputObject $manifest -Name "SourceDomainNetBios" -Default ""
$targetDomainDn = $targetDomain.DistinguishedName
$targetDomainDns = $targetDomain.DNSRoot
$targetNetBios = $targetDomain.NetBIOSName

if ([string]::IsNullOrWhiteSpace($PrincipalMapPath)) {
    $PrincipalMapPath = Get-AkPackageItemPath -PackagePath $PackagePath -Item PrincipalMap
}

$principalMap = Import-AkCsv -Path $PrincipalMapPath -Required

$logPath = Join-Path -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item LogFolder) -ChildPath ("import-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
Start-AkLog -Path $logPath

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  AD ENVIRONMENT IMPORT" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-AkLog -Message "Source domain (package): $sourceDomainDns [$sourceDomainDn]" -Level Info
Write-AkLog -Message "Target domain (live)   : $targetDomainDns [$targetDomainDn] NetBIOS $targetNetBios" -Level Info
Write-AkLog -Message "Phases                 : $($activePhases -join ', ')" -Level Info
Write-AkLog -Message "Principal map          : $PrincipalMapPath ($($principalMap.Count) entries)" -Level Info

if ($sourceDomainDns -eq $targetDomainDns) {
    throw "The package was exported from '$sourceDomainDns' and this domain is also '$sourceDomainDns'. This script rebuilds into a DIFFERENT domain and will not run against the source."
}

if ($WhatIfPreference) {
    Write-AkLog -Message "Running in -WhatIf mode. No changes will be made." -Level Warning
}

# Index the principal map for fast lookup by source sAMAccountName, DN, and SID.
$mapBySam = @{}
$mapByDn = @{}
$mapBySid = @{}
$mapByUpn = @{}

foreach ($entry in $principalMap) {
    $sam = Get-AkPropertyValue -InputObject $entry -Name "SourceSamAccountName"
    $dn = Get-AkPropertyValue -InputObject $entry -Name "SourceDn"
    $sid = Get-AkPropertyValue -InputObject $entry -Name "SourceSid"
    $upn = Get-AkPropertyValue -InputObject $entry -Name "SourceUpn"

    if ($sam -and -not $mapBySam.ContainsKey($sam)) { $mapBySam[$sam] = $entry }
    if ($dn -and -not $mapByDn.ContainsKey($dn)) { $mapByDn[$dn] = $entry }
    if ($sid -and -not $mapBySid.ContainsKey($sid)) { $mapBySid[$sid] = $entry }
    if ($upn -and -not $mapByUpn.ContainsKey($upn)) { $mapByUpn[$upn] = $entry }
}

$stats = @{}
function Add-Stat {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$Count = 1
    )
    if (-not $stats.ContainsKey($Name)) { $stats[$Name] = 0 }
    $stats[$Name] = $stats[$Name] + $Count
}

function Resolve-TargetDn {
    <#
    .SYNOPSIS
    Translates a source DN into the target domain, honouring -TargetOuRoot.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$SourceDn)

    if ([string]::IsNullOrWhiteSpace($SourceDn)) { return $null }

    $translated = ConvertTo-AkTargetDn -SourceDn $SourceDn -SourceDomainDn $sourceDomainDn -TargetDomainDn $targetDomainDn
    if ([string]::IsNullOrWhiteSpace($TargetOuRoot)) { return $translated }

    # Re-root the whole tree under the requested container.
    return (ConvertTo-AkTargetDn -SourceDn $SourceDn -SourceDomainDn $sourceDomainDn -TargetDomainDn $TargetOuRoot)
}

function Test-AdObjectExists {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    try {
        [void](Get-ADObject -Identity $DistinguishedName @adParams -ErrorAction Stop)
        return $true
    }
    catch {
        return $false
    }
}

function Resolve-TargetPrincipal {
    <#
    .SYNOPSIS
    Resolves a source principal reference to its target sAMAccountName.

    .DESCRIPTION
    Accepts a source DN, a DOMAIN\name string, a bare sAMAccountName, a SID, or
    the name@domain form a GPMC migration table uses, and returns the mapped
    entry or $null when the principal is not mapped.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Reference)

    if ([string]::IsNullOrWhiteSpace($Reference)) { return $null }

    if ($mapByDn.ContainsKey($Reference)) { return $mapByDn[$Reference] }
    if ($mapBySid.ContainsKey($Reference)) { return $mapBySid[$Reference] }
    if ($mapByUpn.ContainsKey($Reference)) { return $mapByUpn[$Reference] }

    $bare = $Reference
    if ($Reference -like "*\*") { $bare = $Reference.Split("\")[-1] }
    elseif ($Reference -like "CN=*") {
        # Pull the RDN value out of a DN we do not have indexed.
        $rdn = $Reference.Split(",")[0]
        if ($rdn -like "CN=*") { $bare = $rdn.Substring(3) }
    }

    # A migration table writes principals as name@domain, and for a group that
    # name is the sAMAccountName. Strip the suffix and try again; this is what
    # matches 'Domain Admins@old.local' to the map.
    if ($bare -like "*@*") {
        $localPart = $bare.Substring(0, $bare.LastIndexOf("@"))
        if ($mapBySam.ContainsKey($localPart)) { return $mapBySam[$localPart] }
    }

    if ($mapBySam.ContainsKey($bare)) { return $mapBySam[$bare] }
    return $null
}

# ===========================================================================
# Phase: Organizational units
# ===========================================================================

if (Test-Phase -Name "OrganizationalUnits") {
    Write-Host ""
    Write-AkLog -Message "PHASE: Organizational units" -Level Step

    $ous = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item OrganizationalUnits)

    # Shallow DNs first so a parent always exists before its children.
    $orderedOus = @($ous | Sort-Object { [int](Get-AkPropertyValue -InputObject $_ -Name "Depth" -Default 0) }, DistinguishedName)

    foreach ($ou in $orderedOus) {
        $name = Get-AkPropertyValue -InputObject $ou -Name "Name"
        $sourceDn = Get-AkPropertyValue -InputObject $ou -Name "DistinguishedName"
        $targetDn = Resolve-TargetDn -SourceDn $sourceDn
        if ([string]::IsNullOrWhiteSpace($targetDn)) { continue }

        $targetParent = Get-AkParentDn -DistinguishedName $targetDn

        if (Test-AdObjectExists -DistinguishedName $targetDn) {
            if ($SkipExisting) {
                Add-Stat -Name "OusSkippedExisting"
                continue
            }
            Write-AkLog -Message "OU already exists: $targetDn" -Level Warning
            continue
        }

        if (-not (Test-AdObjectExists -DistinguishedName $targetParent)) {
            if ($WhatIfPreference) {
                # Expected during -WhatIf: the parent would have been created by
                # an earlier iteration that did not actually run.
                Write-AkLog -Message "WhatIf: would create OU '$name' once its parent '$targetParent' exists." -Level Info
                Add-Stat -Name "OusWhatIf"
                continue
            }

            Write-AkLog -Message "Cannot create OU '$name': parent '$targetParent' does not exist." -Level Error
            Add-Stat -Name "OusFailed"
            continue
        }

        if ($PSCmdlet.ShouldProcess($targetDn, "Create organizational unit")) {
            try {
                $newOuParams = @{
                    Name = $name
                    Path = $targetParent
                    ProtectedFromAccidentalDeletion = (ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $ou -Name "ProtectedFromAccidentalDeletion") -Default $false)
                }

                foreach ($optional in @(
                    @{ Csv = "Description"; Param = "Description" },
                    @{ Csv = "City"; Param = "City" },
                    @{ Csv = "State"; Param = "State" },
                    @{ Csv = "PostalCode"; Param = "PostalCode" },
                    @{ Csv = "StreetAddress"; Param = "StreetAddress" },
                    @{ Csv = "Country"; Param = "Country" })) {
                    $value = Get-AkPropertyValue -InputObject $ou -Name $optional.Csv
                    if (-not [string]::IsNullOrWhiteSpace($value)) { $newOuParams[$optional.Param] = $value }
                }

                New-ADOrganizationalUnit @newOuParams @adParams | Out-Null
                Add-Stat -Name "OusCreated"
            }
            catch {
                Write-AkLog -Message "Failed to create OU '$targetDn': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "OusFailed"
            }
        }
        else {
            Add-Stat -Name "OusWhatIf"
        }
    }

    Write-AkLog -Message "OU phase complete." -Level Success
}

# ===========================================================================
# Phase: Groups
# ===========================================================================

if (Test-Phase -Name "Groups") {
    Write-Host ""
    Write-AkLog -Message "PHASE: Groups" -Level Step

    $groups = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Groups)

    foreach ($group in $groups) {
        $sam = Get-AkPropertyValue -InputObject $group -Name "SamAccountName"
        if ([string]::IsNullOrWhiteSpace($sam)) { continue }

        $mapEntry = $null
        if ($mapBySam.ContainsKey($sam)) { $mapEntry = $mapBySam[$sam] }

        $action = "Create"
        if ($mapEntry) { $action = Get-AkPropertyValue -InputObject $mapEntry -Name "Action" -Default "Create" }

        # Built-in groups already exist in the new domain under whatever name the
        # local OS locale uses. They are never recreated.
        if ($action -ne "Create") {
            Add-Stat -Name "GroupsSkipped$action"
            continue
        }

        $targetSam = $sam
        if ($mapEntry) {
            $mapped = Get-AkPropertyValue -InputObject $mapEntry -Name "TargetSamAccountName"
            if (-not [string]::IsNullOrWhiteSpace($mapped)) { $targetSam = $mapped }
        }

        $sourceDn = Get-AkPropertyValue -InputObject $group -Name "DistinguishedName"
        $targetPath = Resolve-TargetDn -SourceDn (Get-AkPropertyValue -InputObject $group -Name "ParentDn" -Default "")
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            $targetPath = Get-AkParentDn -DistinguishedName (Resolve-TargetDn -SourceDn $sourceDn)
        }

        $existing = $null
        try { $existing = Get-ADGroup -Identity $targetSam @adParams -ErrorAction Stop } catch { $existing = $null }

        if ($existing) {
            if ($SkipExisting) { Add-Stat -Name "GroupsSkippedExisting"; continue }
            Write-AkLog -Message "Group already exists: $targetSam" -Level Warning
            continue
        }

        if (-not (Test-AdObjectExists -DistinguishedName $targetPath)) {
            if ($WhatIfPreference) {
                Write-AkLog -Message "WhatIf: would create group '$targetSam' in '$targetPath'." -Level Info
                Add-Stat -Name "GroupsWhatIf"
                continue
            }
            Write-AkLog -Message "Cannot create group '$targetSam': container '$targetPath' does not exist. Run the OrganizationalUnits phase first." -Level Error
            Add-Stat -Name "GroupsFailed"
            continue
        }

        if ($PSCmdlet.ShouldProcess("$targetSam in $targetPath", "Create group")) {
            try {
                $newGroupParams = @{
                    Name           = Get-AkPropertyValue -InputObject $group -Name "Name" -Default $targetSam
                    SamAccountName = $targetSam
                    Path           = $targetPath
                    GroupCategory  = Get-AkPropertyValue -InputObject $group -Name "GroupCategory" -Default "Security"
                    GroupScope     = Get-AkPropertyValue -InputObject $group -Name "GroupScope" -Default "Global"
                }

                $description = Get-AkPropertyValue -InputObject $group -Name "Description"
                if (-not [string]::IsNullOrWhiteSpace($description)) { $newGroupParams["Description"] = $description }

                $displayName = Get-AkPropertyValue -InputObject $group -Name "DisplayName"
                if (-not [string]::IsNullOrWhiteSpace($displayName)) { $newGroupParams["DisplayName"] = $displayName }

                New-ADGroup @newGroupParams @adParams | Out-Null
                Add-Stat -Name "GroupsCreated"
            }
            catch {
                Write-AkLog -Message "Failed to create group '$targetSam': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "GroupsFailed"
            }
        }
        else {
            Add-Stat -Name "GroupsWhatIf"
        }
    }

    Write-AkLog -Message "Group phase complete." -Level Success
}

# ===========================================================================
# Phase: Users
# ===========================================================================

if (Test-Phase -Name "Users") {
    Write-Host ""
    Write-AkLog -Message "PHASE: Users" -Level Step

    $users = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Users)
    $passwordRecords = New-Object System.Collections.Generic.List[object]

    # mailNickname arrives with the Exchange schema extension. A domain that
    # never ran Exchange does not have it, and Set-ADUser fails the whole call
    # on one unknown attribute, so check the target schema before using them.
    $candidateExtraAttributes = @("proxyAddresses", "mailNickname")
    $presentExtraAttributes = @()
    try {
        $schemaNc = (Get-ADRootDSE @adParams).schemaNamingContext
        foreach ($attr in $candidateExtraAttributes) {
            $found = @(Get-ADObject -SearchBase $schemaNc @adParams `
                -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$attr))" -ErrorAction SilentlyContinue)
            if ($found.Count -gt 0) { $presentExtraAttributes += $attr }
        }
    }
    catch {
        Write-AkLog -Message "Could not read the target schema: $($_.Exception.Message). Optional attributes will be attempted as-is." -Level Warning
        $presentExtraAttributes = $candidateExtraAttributes
    }

    $absentExtraAttributes = @($candidateExtraAttributes | Where-Object { $presentExtraAttributes -notcontains $_ })
    if ($absentExtraAttributes.Count -gt 0) {
        Write-AkLog -Message "Target schema has no $($absentExtraAttributes -join ', '). Those values are not migrated; accounts are otherwise complete." -Level Warning
    }

    foreach ($user in $users) {
        $sam = Get-AkPropertyValue -InputObject $user -Name "SamAccountName"
        if ([string]::IsNullOrWhiteSpace($sam)) { continue }

        $mapEntry = $null
        if ($mapBySam.ContainsKey($sam)) { $mapEntry = $mapBySam[$sam] }

        $action = "Create"
        if ($mapEntry) { $action = Get-AkPropertyValue -InputObject $mapEntry -Name "Action" -Default "Create" }

        if ($action -ne "Create") {
            Add-Stat -Name "UsersSkipped$action"
            continue
        }

        $targetSam = $sam
        $targetUpn = ""
        if ($mapEntry) {
            $mappedSam = Get-AkPropertyValue -InputObject $mapEntry -Name "TargetSamAccountName"
            if (-not [string]::IsNullOrWhiteSpace($mappedSam)) { $targetSam = $mappedSam }
            $targetUpn = Get-AkPropertyValue -InputObject $mapEntry -Name "TargetUpn" -Default ""
        }
        if ([string]::IsNullOrWhiteSpace($targetUpn)) { $targetUpn = "$targetSam@$targetDomainDns" }

        $targetPath = Resolve-TargetDn -SourceDn (Get-AkPropertyValue -InputObject $user -Name "ParentDn" -Default "")
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            $targetPath = $targetDomain.UsersContainer
        }

        $existing = $null
        try { $existing = Get-ADUser -Identity $targetSam @adParams -ErrorAction Stop } catch { $existing = $null }

        if ($existing) {
            if ($SkipExisting) { Add-Stat -Name "UsersSkippedExisting"; continue }
            Write-AkLog -Message "User already exists: $targetSam" -Level Warning
            continue
        }

        if (-not (Test-AdObjectExists -DistinguishedName $targetPath)) {
            if ($WhatIfPreference) {
                Write-AkLog -Message "WhatIf: would create user '$targetSam' in '$targetPath'." -Level Info
                Add-Stat -Name "UsersWhatIf"
                continue
            }
            Write-AkLog -Message "Cannot create user '$targetSam': container '$targetPath' does not exist. Run the OrganizationalUnits phase first." -Level Error
            Add-Stat -Name "UsersFailed"
            continue
        }

        $sourceEnabled = ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $user -Name "Enabled") -Default $false
        $enabled = $sourceEnabled -and -not $CreateUsersDisabled

        if ($PSCmdlet.ShouldProcess("$targetSam in $targetPath", "Create user")) {
            try {
                # Passwords cannot be migrated, so every account gets a fresh one.
                $password = New-AkPassword -Length $PasswordLength
                $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

                # Rebuild with the source CN. Two users can share a displayName
                # but never a CN inside the same OU, so using displayName here
                # would fail on exactly the accounts that are hardest to notice.
                $userCn = Get-AkRdnValue -DistinguishedName (Get-AkPropertyValue -InputObject $user -Name "DistinguishedName" -Default "")
                if ([string]::IsNullOrWhiteSpace($userCn)) {
                    $userCn = Get-AkPropertyValue -InputObject $user -Name "DisplayName" -Default $targetSam
                }

                $newUserParams = @{
                    Name                  = $userCn
                    SamAccountName        = $targetSam
                    UserPrincipalName     = $targetUpn
                    Path                  = $targetPath
                    AccountPassword       = $securePassword
                    Enabled               = $enabled
                    ChangePasswordAtLogon = (-not $DoNotRequirePasswordChange)
                }

                # A user whose password never expires cannot also be forced to
                # change it at next logon; AD rejects the combination.
                $passwordNeverExpires = ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $user -Name "PasswordNeverExpires") -Default $false
                if ($passwordNeverExpires) {
                    $newUserParams["PasswordNeverExpires"] = $true
                    $newUserParams["ChangePasswordAtLogon"] = $false
                }

                foreach ($optional in @(
                    @{ Csv = "GivenName"; Param = "GivenName" },
                    @{ Csv = "Surname"; Param = "Surname" },
                    @{ Csv = "Initials"; Param = "Initials" },
                    @{ Csv = "DisplayName"; Param = "DisplayName" },
                    @{ Csv = "Description"; Param = "Description" },
                    @{ Csv = "EmailAddress"; Param = "EmailAddress" },
                    @{ Csv = "Title"; Param = "Title" },
                    @{ Csv = "Department"; Param = "Department" },
                    @{ Csv = "Company"; Param = "Company" },
                    @{ Csv = "Division"; Param = "Division" },
                    @{ Csv = "Office"; Param = "Office" },
                    @{ Csv = "OfficePhone"; Param = "OfficePhone" },
                    @{ Csv = "MobilePhone"; Param = "MobilePhone" },
                    @{ Csv = "HomePhone"; Param = "HomePhone" },
                    @{ Csv = "Fax"; Param = "Fax" },
                    @{ Csv = "StreetAddress"; Param = "StreetAddress" },
                    @{ Csv = "City"; Param = "City" },
                    @{ Csv = "State"; Param = "State" },
                    @{ Csv = "PostalCode"; Param = "PostalCode" },
                    @{ Csv = "Country"; Param = "Country" },
                    @{ Csv = "EmployeeId"; Param = "EmployeeID" },
                    @{ Csv = "EmployeeNumber"; Param = "EmployeeNumber" },
                    @{ Csv = "HomeDirectory"; Param = "HomeDirectory" },
                    @{ Csv = "HomeDrive"; Param = "HomeDrive" },
                    @{ Csv = "ProfilePath"; Param = "ProfilePath" },
                    @{ Csv = "ScriptPath"; Param = "ScriptPath" })) {
                    $value = Get-AkPropertyValue -InputObject $user -Name $optional.Csv
                    if (-not [string]::IsNullOrWhiteSpace($value)) { $newUserParams[$optional.Param] = $value }
                }

                # Country must be a two-letter code for New-ADUser to accept it.
                if ($newUserParams.ContainsKey("Country") -and $newUserParams["Country"].Length -ne 2) {
                    $newUserParams.Remove("Country")
                }

                New-ADUser @newUserParams @adParams | Out-Null

                # Record the credential the moment the account exists. Anything
                # that fails after this point still leaves a usable account, but
                # a lost generated password cannot be recovered.
                $passwordRecords.Add([pscustomobject]@{
                    SamAccountName    = $targetSam
                    UserPrincipalName = $targetUpn
                    DisplayName       = Get-AkPropertyValue -InputObject $user -Name "DisplayName"
                    Password          = $password
                    Enabled           = $enabled
                    MustChangeAtLogon = (-not $DoNotRequirePasswordChange -and -not $passwordNeverExpires)
                })

                Add-Stat -Name "UsersCreated"

                # proxyAddresses drives Entra soft-matching, so it is set after
                # creation as a raw attribute rather than a named parameter.
                $proxyAddresses = ConvertFrom-AkMultiValue -Value (Get-AkPropertyValue -InputObject $user -Name "ProxyAddresses")
                $extraAttributes = @{}
                if ($proxyAddresses.Count -gt 0) { $extraAttributes["proxyAddresses"] = $proxyAddresses }

                $mailNickname = Get-AkPropertyValue -InputObject $user -Name "MailNickname"
                if (-not [string]::IsNullOrWhiteSpace($mailNickname)) { $extraAttributes["mailNickname"] = $mailNickname }

                $extraAttributes = Select-AkPresentAttribute -Attribute $extraAttributes -Present $presentExtraAttributes

                if ($extraAttributes.Count -gt 0) {
                    try {
                        Set-ADUser -Identity $targetSam -Replace $extraAttributes @adParams
                    }
                    catch {
                        # The account is already created and recorded; an optional
                        # attribute is not worth discarding it over.
                        Write-AkLog -Message "Created '$targetSam' but could not set $($extraAttributes.Keys -join ', '): $($_.Exception.Message)" -Level Warning
                        Add-Stat -Name "UsersMissingOptionalAttributes"
                    }
                }
            }
            catch {
                Write-AkLog -Message "Failed to create user '$targetSam': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "UsersFailed"
            }
        }
        else {
            Add-Stat -Name "UsersWhatIf"
        }
    }

    if ($passwordRecords.Count -gt 0) {
        $passwordPath = Get-AkPackageItemPath -PackagePath $PackagePath -Item GeneratedPasswords

        # The phase is re-runnable and only creates what is missing, so a second
        # run writes only the new accounts. Keep the previous file rather than
        # overwriting credentials that cannot be recovered any other way.
        if (Test-Path -LiteralPath $passwordPath) {
            $archived = [System.IO.Path]::ChangeExtension($passwordPath, $null).TrimEnd(".") +
                "-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv"
            Move-Item -LiteralPath $passwordPath -Destination $archived -Force
            Write-AkLog -Message "Existing password file kept as $archived" -Level Warning
        }

        [void](Export-AkCsv -InputObject $passwordRecords.ToArray() -Path $passwordPath)
        Write-AkLog -Message "Generated passwords written to $passwordPath" -Level Warning
        Write-AkLog -Message "That file is plaintext credentials for every imported account. Distribute it securely and delete it once users have signed in." -Level Warning
    }

    Write-AkLog -Message "User phase complete." -Level Success
}

# ===========================================================================
# Phase: Membership
# ===========================================================================

if (Test-Phase -Name "Membership") {
    Write-Host ""
    Write-AkLog -Message "PHASE: Group membership" -Level Step

    $members = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item GroupMembers)
    $wellKnownRids = Get-AkWellKnownRidMap

    # Group members by target group so each group is updated once.
    $byGroup = @{}

    foreach ($record in $members) {
        $groupSam = Get-AkPropertyValue -InputObject $record -Name "GroupSamAccountName"
        $memberDn = Get-AkPropertyValue -InputObject $record -Name "MemberDn"
        if ([string]::IsNullOrWhiteSpace($groupSam) -or [string]::IsNullOrWhiteSpace($memberDn)) { continue }

        if (ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $record -Name "MemberIsForeign") -Default $false) {
            Write-AkLog -Message "Skipping foreign security principal in '$groupSam': $memberDn" -Level Warning
            Add-Stat -Name "MembershipsSkippedForeign"
            continue
        }

        # Resolve the target group name, honouring a rename in the map.
        $targetGroupSam = $groupSam
        $groupWellKnown = Get-AkPropertyValue -InputObject $record -Name "GroupWellKnownRid"

        if (-not [string]::IsNullOrWhiteSpace($groupWellKnown)) {
            # Built-in group: find the target group by RID rather than by name so
            # this works on a non-English target domain.
            $rid = ($wellKnownRids.GetEnumerator() | Where-Object { $_.Value -eq $groupWellKnown } | Select-Object -First 1).Key
            if ($rid) {
                $targetSid = "$($targetDomain.DomainSID.Value)-$rid"
                try {
                    $resolvedGroup = Get-ADGroup -Identity $targetSid @adParams -ErrorAction Stop
                    $targetGroupSam = $resolvedGroup.SamAccountName
                }
                catch {
                    Write-AkLog -Message "Could not resolve built-in group RID $rid in the target domain: $($_.Exception.Message)" -Level Warning
                    Add-Stat -Name "MembershipsFailed"
                    continue
                }
            }
        }
        elseif ($mapBySam.ContainsKey($groupSam)) {
            $mapped = Get-AkPropertyValue -InputObject $mapBySam[$groupSam] -Name "TargetSamAccountName"
            if (-not [string]::IsNullOrWhiteSpace($mapped)) { $targetGroupSam = $mapped }
        }

        $memberEntry = Resolve-TargetPrincipal -Reference $memberDn
        if (-not $memberEntry) {
            Write-AkLog -Message "Member '$memberDn' of group '$groupSam' is not in the principal map. Skipping." -Level Warning
            Add-Stat -Name "MembershipsUnmapped"
            continue
        }

        $memberAction = Get-AkPropertyValue -InputObject $memberEntry -Name "Action" -Default "Create"
        if ($memberAction -eq "Skip" -or $memberAction -eq "Review") {
            Add-Stat -Name "MembershipsSkippedByMap"
            continue
        }

        $memberSam = Get-AkPropertyValue -InputObject $memberEntry -Name "TargetSamAccountName"
        if ([string]::IsNullOrWhiteSpace($memberSam)) { continue }

        if (-not $byGroup.ContainsKey($targetGroupSam)) {
            $byGroup[$targetGroupSam] = New-Object System.Collections.Generic.List[string]
        }
        $byGroup[$targetGroupSam].Add($memberSam)
    }

    foreach ($groupSam in $byGroup.Keys) {
        $wanted = @($byGroup[$groupSam] | Select-Object -Unique)

        $targetGroup = $null
        try { $targetGroup = Get-ADGroup -Identity $groupSam @adParams -ErrorAction Stop } catch { $targetGroup = $null }

        if (-not $targetGroup) {
            if ($WhatIfPreference) {
                Write-AkLog -Message "WhatIf: would add $($wanted.Count) member(s) to '$groupSam'." -Level Info
                Add-Stat -Name "MembershipsWhatIf"
                continue
            }
            Write-AkLog -Message "Target group '$groupSam' not found. Run the Groups phase first." -Level Error
            Add-Stat -Name "MembershipsFailed"
            continue
        }

        # Only add what is missing so the phase is safely re-runnable.
        $current = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)
        try {
            foreach ($existingMember in @(Get-ADGroupMember -Identity $targetGroup @adParams -ErrorAction Stop)) {
                [void]$current.Add($existingMember.SamAccountName)
            }
        }
        catch {
            Write-AkLog -Message "Could not read current membership of '$groupSam': $($_.Exception.Message)" -Level Warning
        }

        $toAdd = @($wanted | Where-Object { -not $current.Contains($_) })
        if ($toAdd.Count -eq 0) {
            Add-Stat -Name "GroupsAlreadyCorrect"
            continue
        }

        if ($PSCmdlet.ShouldProcess($groupSam, "Add $($toAdd.Count) member(s)")) {
            try {
                Add-ADGroupMember -Identity $targetGroup -Members $toAdd @adParams -ErrorAction Stop
                Add-Stat -Name "MembershipsAdded" -Count $toAdd.Count
            }
            catch {
                Write-AkLog -Message "Failed to add members to '$groupSam': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "MembershipsFailed"
            }
        }
        else {
            Add-Stat -Name "MembershipsWhatIf"
        }
    }

    # --- Primary groups ---------------------------------------------------
    # A user's primary group membership is implicit: it is NOT listed in the
    # group's member attribute, so the pass above cannot see it. Left alone, any
    # user whose primary group was not Domain Users silently loses that
    # membership, and the access that came with it.

    $primaryGroupUsers = @(Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Users) |
        Where-Object { [int](Get-AkPropertyValue -InputObject $_ -Name "PrimaryGroupId" -Default 513) -ne 513 })

    if ($primaryGroupUsers.Count -gt 0) {
        Write-AkLog -Message "$($primaryGroupUsers.Count) user(s) have a non-default primary group." -Level Info

        $sourceGroups = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Groups)

        foreach ($user in $primaryGroupUsers) {
            $sourceSam = Get-AkPropertyValue -InputObject $user -Name "SamAccountName"
            $primaryRid = [string](Get-AkPropertyValue -InputObject $user -Name "PrimaryGroupId" -Default 513)

            $userEntry = $null
            if ($mapBySam.ContainsKey($sourceSam)) { $userEntry = $mapBySam[$sourceSam] }
            if (-not $userEntry) { continue }

            $targetUserSam = Get-AkPropertyValue -InputObject $userEntry -Name "TargetSamAccountName"
            if ([string]::IsNullOrWhiteSpace($targetUserSam)) { continue }

            # Find which source group carried that RID, then its target group.
            $sourceGroup = @($sourceGroups | Where-Object {
                (Get-AkPropertyValue -InputObject $_ -Name "SourceRid") -eq $primaryRid
            })

            if ($sourceGroup.Count -eq 0) {
                Write-AkLog -Message "User '$sourceSam' had primary group RID $primaryRid, which is not in the package. Primary group not restored." -Level Warning
                Add-Stat -Name "PrimaryGroupsUnresolved"
                continue
            }

            $sourceGroupSam = Get-AkPropertyValue -InputObject $sourceGroup[0] -Name "SamAccountName"
            $targetGroupSam = $sourceGroupSam
            if ($mapBySam.ContainsKey($sourceGroupSam)) {
                $mapped = Get-AkPropertyValue -InputObject $mapBySam[$sourceGroupSam] -Name "TargetSamAccountName"
                if (-not [string]::IsNullOrWhiteSpace($mapped)) { $targetGroupSam = $mapped }
            }

            if ($PSCmdlet.ShouldProcess("$targetUserSam", "Set primary group to $targetGroupSam")) {
                try {
                    $targetGroup = Get-ADGroup -Identity $targetGroupSam -Properties objectSid @adParams -ErrorAction Stop
                    $targetRid = Get-AkSidRid -Sid ([string]$targetGroup.SID)

                    # AD requires membership before the group can become primary.
                    try {
                        Add-ADGroupMember -Identity $targetGroup -Members $targetUserSam @adParams -ErrorAction Stop
                    }
                    catch {
                        # Already a member, which is fine.
                    }

                    Set-ADUser -Identity $targetUserSam -Replace @{ primaryGroupID = [int]$targetRid } @adParams -ErrorAction Stop
                    Add-Stat -Name "PrimaryGroupsSet"
                }
                catch {
                    Write-AkLog -Message "Could not set primary group for '$targetUserSam': $($_.Exception.Message)" -Level Error
                    Add-Stat -Name "PrimaryGroupsFailed"
                }
            }
            else {
                Add-Stat -Name "PrimaryGroupsWhatIf"
            }
        }
    }

    Write-AkLog -Message "Membership phase complete." -Level Success
}

# ===========================================================================
# Phase: WMI filters
# ===========================================================================
# There is no New-WmiFilter cmdlet. WMI filters are msWMI-Som objects in the
# System container and are recreated here as raw directory objects. The original
# msWMI-ID is preserved deliberately: GPOs reference their filter by that GUID,
# so keeping it is what allows the Gpo phase to restore the association.

if (Test-Phase -Name "WmiFilters") {
    Write-Host ""
    Write-AkLog -Message "PHASE: WMI filters" -Level Step

    $wmiFilters = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item WmiFilters)
    $wmiContainer = "CN=SOM,CN=WMIPolicy,CN=System,$targetDomainDn"

    if ($wmiFilters.Count -gt 0 -and -not (Test-AdObjectExists -DistinguishedName $wmiContainer)) {
        Write-AkLog -Message "WMI policy container '$wmiContainer' was not found. Skipping WMI filters." -Level Error
    }
    else {
        foreach ($filter in $wmiFilters) {
            $name = Get-AkPropertyValue -InputObject $filter -Name "Name"
            $wmiId = Get-AkPropertyValue -InputObject $filter -Name "WmiId"
            $query = Get-AkPropertyValue -InputObject $filter -Name "Query"

            if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($wmiId)) {
                Write-AkLog -Message "Skipping a WMI filter with no name or ID." -Level Warning
                Add-Stat -Name "WmiFiltersSkippedInvalid"
                continue
            }

            $filterDn = "CN=$wmiId,$wmiContainer"

            if (Test-AdObjectExists -DistinguishedName $filterDn) {
                Add-Stat -Name "WmiFiltersSkippedExisting"
                continue
            }

            if ($PSCmdlet.ShouldProcess($name, "Create WMI filter")) {
                try {
                    $now = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss") + ".000000-000"

                    $attributes = @{
                        "msWMI-Name"         = $name
                        "msWMI-Parm2"        = $query
                        "msWMI-ID"           = $wmiId
                        "msWMI-Author"       = "$($env:USERNAME)@$targetDomainDns"
                        "msWMI-ChangeDate"   = $now
                        "msWMI-CreationDate" = $now
                        "instanceType"       = 4
                        "showInAdvancedViewOnly" = $true
                    }

                    $description = Get-AkPropertyValue -InputObject $filter -Name "Description"
                    if (-not [string]::IsNullOrWhiteSpace($description)) {
                        $attributes["msWMI-Parm1"] = $description
                    }

                    New-ADObject -Name $wmiId -Type "msWMI-Som" -Path $wmiContainer `
                        -OtherAttributes $attributes @adParams | Out-Null

                    Add-Stat -Name "WmiFiltersCreated"
                }
                catch {
                    Write-AkLog -Message "Failed to create WMI filter '$name': $($_.Exception.Message)" -Level Error
                    Add-Stat -Name "WmiFiltersFailed"
                }
            }
            else {
                Add-Stat -Name "WmiFiltersWhatIf"
            }
        }
    }

    Write-AkLog -Message "WMI filter phase complete." -Level Success
}

# ===========================================================================
# Phase: Group Policy Objects
# ===========================================================================

if (Test-Phase -Name "Gpo") {
    Write-Host ""
    Write-AkLog -Message "PHASE: Group Policy Objects" -Level Step

    Assert-AkModule -Name "GroupPolicy" -Reason "GPO import requires the GroupPolicy module."

    $backupFolder = Get-AkPackageItemPath -PackagePath $PackagePath -Item GpoBackupFolder
    $gpoInventory = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item GpoInventory)

    if (-not (Test-Path -LiteralPath $backupFolder)) {
        Write-AkLog -Message "No GPO backup folder found at '$backupFolder'. Skipping the Gpo phase." -Level Error
    }
    else {
        # -------------------------------------------------------------------
        # Build the migration table
        # -------------------------------------------------------------------
        # Import-GPO rewrites security principals and UNC paths only when it is
        # given a migration table. Without one, every GPO lands in the new domain
        # still referencing the old domain's users, groups, and file servers.

        $migrationTablePath = Get-AkPackageItemPath -PackagePath $PackagePath -Item MigrationTable
        $migrationTableReady = $false

        try {
            $migrationFolder = Split-Path -Path $migrationTablePath -Parent
            if (-not (Test-Path -LiteralPath $migrationFolder)) {
                New-Item -Path $migrationFolder -ItemType Directory -Force | Out-Null
            }

            $gpm = New-Object -ComObject "GPMgmt.GPM"
            $gpmConstants = $gpm.GetConstants()
            $gpmBackupDir = $gpm.GetBackupDir($backupFolder)
            $gpmSearch = $gpm.CreateSearchCriteria()
            $gpmBackups = $gpmBackupDir.SearchBackups($gpmSearch)

            $migrationTable = $gpm.CreateMigrationTable()
            foreach ($gpmBackup in $gpmBackups) {
                # ProcessSecurity also pulls principals out of each GPO's DACL,
                # not just out of policy settings.
                $migrationTable.Add($gpmConstants.ProcessSecurity, $gpmBackup)
            }

            $unmappedEntries = New-Object System.Collections.Generic.List[string]

            foreach ($entry in $migrationTable.GetEntries()) {
                $source = $entry.Source
                $destination = $null

                if ($entry.EntryType -eq $gpmConstants.EntryTypeUNCPath) {
                    # Re-point \\OLDFS01\Share at the new file server.
                    $destination = $source
                    foreach ($oldName in $ReplaceServerName.Keys) {
                        $destination = $destination -replace ("\\\\" + [regex]::Escape($oldName) + "\\"), ("\\" + $ReplaceServerName[$oldName] + "\")
                    }
                    if ($destination -eq $source) {
                        $unmappedEntries.Add("UNC path not remapped: $source")
                        continue
                    }
                }
                else {
                    if (Test-AkIsWellKnownPrincipalName -Name $source) {
                        continue    # Everyone, Authenticated Users, NT AUTHORITY\*: valid as-is.
                    }

                    $mapEntry = Resolve-TargetPrincipal -Reference $source
                    if (-not $mapEntry) {
                        $unmappedEntries.Add("Principal not in map: $source")
                        continue
                    }

                    $action = Get-AkPropertyValue -InputObject $mapEntry -Name "Action" -Default ""
                    if ($action -eq "Keep") {
                        continue    # Well-known identity, valid as-is.
                    }

                    $destination = Get-AkPropertyValue -InputObject $mapEntry -Name "TargetAccount"
                    if ([string]::IsNullOrWhiteSpace($destination)) {
                        $targetSam = Get-AkPropertyValue -InputObject $mapEntry -Name "TargetSamAccountName"
                        if ([string]::IsNullOrWhiteSpace($targetSam)) {
                            $unmappedEntries.Add("No target for: $source")
                            continue
                        }
                        $destination = "$targetNetBios\$targetSam"
                    }
                }

                try {
                    $migrationTable.UpdateDestination($source, $destination) | Out-Null
                }
                catch {
                    Write-AkLog -Message "Could not set migration destination for '$source': $($_.Exception.Message)" -Level Warning
                }
            }

            $migrationTable.Save($migrationTablePath)
            $migrationTableReady = $true

            Write-AkLog -Message "Migration table written to $migrationTablePath" -Level Success

            foreach ($unmapped in $unmappedEntries) {
                Write-AkLog -Message $unmapped -Level Warning
            }
            if ($unmappedEntries.Count -gt 0) {
                Write-AkLog -Message "$($unmappedEntries.Count) migration table entries have no destination and will keep their original value. The Validate phase will report anything this leaves behind." -Level Warning
            }
        }
        catch {
            Write-AkLog -Message "Could not build a migration table: $($_.Exception.Message)" -Level Error
            Write-AkLog -Message "GPOs will be imported WITHOUT principal and UNC translation. They will still reference the old domain. Run the Validate phase afterwards and fix the reported settings by hand." -Level Warning
        }

        # -------------------------------------------------------------------
        # Import each GPO
        # -------------------------------------------------------------------

        $packagedWmiFilters = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item WmiFilters)

        foreach ($gpo in $gpoInventory) {
            $displayName = Get-AkPropertyValue -InputObject $gpo -Name "DisplayName"
            $backupId = Get-AkPropertyValue -InputObject $gpo -Name "BackupId"

            if ([string]::IsNullOrWhiteSpace($backupId)) {
                Write-AkLog -Message "GPO '$displayName' has no backup ID and cannot be imported." -Level Error
                Add-Stat -Name "GposFailed"
                continue
            }

            $existingGpo = $null
            try { $existingGpo = Get-GPO -Name $displayName -Domain $targetDomainDns -ErrorAction Stop } catch { $existingGpo = $null }

            if ($existingGpo -and $SkipExisting) {
                Add-Stat -Name "GposSkippedExisting"
                continue
            }

            if ($PSCmdlet.ShouldProcess($displayName, "Import GPO")) {
                try {
                    $importParams = @{
                        BackupId       = $backupId
                        Path           = $backupFolder
                        TargetName     = $displayName
                        Domain         = $targetDomainDns
                        CreateIfNeeded = $true
                    }
                    if ($migrationTableReady) { $importParams["MigrationTable"] = $migrationTablePath }
                    if (-not [string]::IsNullOrWhiteSpace($Server)) { $importParams["Server"] = $Server }

                    $imported = Import-GPO @importParams

                    # Import-GPO does not carry over the description or the
                    # user/computer-side enabled state.
                    $description = Get-AkPropertyValue -InputObject $gpo -Name "Description"
                    $gpoStatus = Get-AkPropertyValue -InputObject $gpo -Name "GpoStatus"

                    if (-not [string]::IsNullOrWhiteSpace($description)) {
                        $imported.Description = $description
                    }
                    if (-not [string]::IsNullOrWhiteSpace($gpoStatus)) {
                        try { $imported.GpoStatus = $gpoStatus }
                        catch { Write-AkLog -Message "Could not set GpoStatus '$gpoStatus' on '$displayName': $($_.Exception.Message)" -Level Warning }
                    }

                    # Restore the WMI filter association by writing gPCWQLFilter
                    # directly; there is no supported cmdlet for this.
                    $wmiFilterName = Get-AkPropertyValue -InputObject $gpo -Name "WmiFilterName"
                    if (-not [string]::IsNullOrWhiteSpace($wmiFilterName)) {
                        $sourceFilter = @($packagedWmiFilters |
                            Where-Object { (Get-AkPropertyValue -InputObject $_ -Name "Name") -eq $wmiFilterName })

                        if ($sourceFilter.Count -gt 0) {
                            $wmiId = Get-AkPropertyValue -InputObject $sourceFilter[0] -Name "WmiId"
                            $gpoDn = "CN={$($imported.Id)},CN=Policies,CN=System,$targetDomainDn"
                            try {
                                Set-ADObject -Identity $gpoDn -Replace @{ "gPCWQLFilter" = "[$targetDomainDns;$wmiId;0]" } @adParams
                            }
                            catch {
                                Write-AkLog -Message "Could not attach WMI filter '$wmiFilterName' to '$displayName': $($_.Exception.Message)" -Level Warning
                            }
                        }
                        else {
                            Write-AkLog -Message "GPO '$displayName' referenced WMI filter '$wmiFilterName', which is not in the package." -Level Warning
                        }
                    }

                    Add-Stat -Name "GposImported"
                }
                catch {
                    Write-AkLog -Message "Failed to import GPO '$displayName': $($_.Exception.Message)" -Level Error
                    Add-Stat -Name "GposFailed"
                }
            }
            else {
                Add-Stat -Name "GposWhatIf"
            }
        }
    }

    Write-AkLog -Message "GPO phase complete." -Level Success
}

# ===========================================================================
# Phase: GPO links
# ===========================================================================
# Import-GPO restores a GPO's contents and nothing else. Links, link order,
# enforcement, and link-enabled state all live on the target OU's gPLink
# attribute and are replayed here from the captured values.

if (Test-Phase -Name "GpoLinks") {
    Write-Host ""
    Write-AkLog -Message "PHASE: GPO links" -Level Step

    Assert-AkModule -Name "GroupPolicy" -Reason "GPO linking requires the GroupPolicy module."

    $links = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item GpoLinks)

    $siteLinks = @($links | Where-Object { (Get-AkPropertyValue -InputObject $_ -Name "TargetType") -eq "Site" })
    if ($siteLinks.Count -gt 0) {
        Write-AkLog -Message "$($siteLinks.Count) site-level GPO link(s) were exported but are NOT replayed. Sites belong to the forest configuration and are a separate design decision in the new forest. Review gpo\gpo-links.csv and link them manually if needed." -Level Warning
    }

    $replayable = @($links | Where-Object { (Get-AkPropertyValue -InputObject $_ -Name "TargetType") -ne "Site" })

    # Apply links in ascending link order so precedence settles correctly.
    foreach ($link in ($replayable | Sort-Object TargetDn, { [int](Get-AkPropertyValue -InputObject $_ -Name "LinkOrder" -Default 1) })) {
        $gpoName = Get-AkPropertyValue -InputObject $link -Name "GpoDisplayName"
        $sourceTargetDn = Get-AkPropertyValue -InputObject $link -Name "TargetDn"
        $targetType = Get-AkPropertyValue -InputObject $link -Name "TargetType"

        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-AkLog -Message "A link on '$sourceTargetDn' could not be resolved to a GPO name in the export and is skipped." -Level Warning
            Add-Stat -Name "LinksUnresolved"
            continue
        }

        $linkTargetDn = $null
        $mappedTarget = Get-AkMappedLinkTarget -SourceDn $sourceTargetDn -LinkTargetMap $LinkTargetMap

        if ($mappedTarget.Mapped) {
            # An explicit -LinkTargetMap entry wins over DN translation, which is
            # how a link lands correctly when the new domain has its own layout.
            if ($mappedTarget.Skip) {
                Write-AkLog -Message "Link '$gpoName' on '$sourceTargetDn' is mapped to nothing and is not replayed." -Level Warning
                Add-Stat -Name "LinksSkippedByMap"
                continue
            }
            $linkTargetDn = $mappedTarget.TargetDn
        }
        elseif ($targetType -eq "Domain") {
            # The domain root itself, which is where Default Domain Policy lives.
            $linkTargetDn = $targetDomainDn
            if (-not [string]::IsNullOrWhiteSpace($TargetOuRoot)) { $linkTargetDn = $TargetOuRoot }
        }
        else {
            $linkTargetDn = Resolve-TargetDn -SourceDn $sourceTargetDn
        }

        if ([string]::IsNullOrWhiteSpace($linkTargetDn) -or -not (Test-AdObjectExists -DistinguishedName $linkTargetDn)) {
            # Only forgive a missing target under -WhatIf when the OU phase is in
            # this run and would create it. Without that, a rehearsal that stayed
            # quiet here would be lying about what the real run does.
            if ($WhatIfPreference -and (Test-Phase -Name "OrganizationalUnits")) {
                Write-AkLog -Message "WhatIf: would link '$gpoName' to '$linkTargetDn' once the OU phase creates it." -Level Info
                Add-Stat -Name "LinksWhatIf"
                continue
            }
            Write-AkLog -Message "Link target '$linkTargetDn' does not exist, so '$gpoName' cannot be linked. Run the OrganizationalUnits phase, or map this link onto a container the new domain does have with -LinkTargetMap @{ '$sourceTargetDn' = '<target DN>' }." -Level Error
            Add-Stat -Name "LinksFailed"
            continue
        }

        $targetGpo = $null
        try { $targetGpo = Get-GPO -Name $gpoName -Domain $targetDomainDns -ErrorAction Stop } catch { $targetGpo = $null }

        if (-not $targetGpo) {
            if ($WhatIfPreference) {
                Write-AkLog -Message "WhatIf: would link '$gpoName' to '$linkTargetDn' once the GPO exists." -Level Info
                Add-Stat -Name "LinksWhatIf"
                continue
            }
            Write-AkLog -Message "GPO '$gpoName' does not exist in the target domain. Run the Gpo phase first." -Level Error
            Add-Stat -Name "LinksFailed"
            continue
        }

        $enabled = ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $link -Name "Enabled") -Default $true
        $enforced = ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $link -Name "Enforced") -Default $false
        $linkOrder = [int](Get-AkPropertyValue -InputObject $link -Name "LinkOrder" -Default 1)

        if ($PSCmdlet.ShouldProcess("$gpoName -> $linkTargetDn", "Link GPO (order $linkOrder)")) {
            try {
                $linkParams = @{
                    Name        = $gpoName
                    Target      = $linkTargetDn
                    Domain      = $targetDomainDns
                    LinkEnabled = if ($enabled) { "Yes" } else { "No" }
                    Enforced    = if ($enforced) { "Yes" } else { "No" }
                    Order       = $linkOrder
                }
                if (-not [string]::IsNullOrWhiteSpace($Server)) { $linkParams["Server"] = $Server }

                try {
                    New-GPLink @linkParams -ErrorAction Stop | Out-Null
                    Add-Stat -Name "LinksCreated"
                }
                catch {
                    # Already linked: correct its order and state instead.
                    Set-GPLink @linkParams -ErrorAction Stop | Out-Null
                    Add-Stat -Name "LinksUpdated"
                }
            }
            catch {
                Write-AkLog -Message "Failed to link '$gpoName' to '$linkTargetDn': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "LinksFailed"
            }
        }
        else {
            Add-Stat -Name "LinksWhatIf"
        }
    }

    Write-AkLog -Message "GPO link phase complete." -Level Success
}

# ===========================================================================
# Phase: Shares and NTFS permissions
# ===========================================================================

if (Test-Phase -Name "Shares") {
    Write-Host ""
    Write-AkLog -Message "PHASE: Shares and NTFS permissions" -Level Step

    $shares = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Shares)
    $shareAccess = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item ShareAccess)
    $ntfsAcl = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item NtfsAcl)

    function Resolve-TargetPath {
        <#
        .SYNOPSIS
        Applies -SharePathMap to a captured share path.
        #>
        param([Parameter(Mandatory)][string]$SourcePath)

        foreach ($oldRoot in $SharePathMap.Keys) {
            if ($SourcePath.StartsWith($oldRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                return ($SharePathMap[$oldRoot] + $SourcePath.Substring($oldRoot.Length))
            }
        }
        return $SourcePath
    }

    function Resolve-AccountName {
        <#
        .SYNOPSIS
        Translates a captured ACL identity into a target-domain account name.

        .DESCRIPTION
        Returns $null when the identity is not mapped, which the caller reports
        rather than silently dropping the access rule.
        #>
        param(
            [Parameter(Mandatory)][AllowEmptyString()][string]$AccountName,
            [AllowEmptyString()][string]$Sid = ""
        )

        if (-not [string]::IsNullOrWhiteSpace($Sid) -and (Test-AkIsBuiltInSid -Sid $Sid)) {
            return $AccountName
        }

        $reference = $AccountName
        if (-not [string]::IsNullOrWhiteSpace($Sid) -and $mapBySid.ContainsKey($Sid)) { $reference = $Sid }

        $mapEntry = Resolve-TargetPrincipal -Reference $reference
        if (-not $mapEntry) { return $null }

        $action = Get-AkPropertyValue -InputObject $mapEntry -Name "Action" -Default ""
        if ($action -eq "Keep") { return $AccountName }
        if ($action -eq "Skip" -or $action -eq "Review") { return $null }

        $targetAccount = Get-AkPropertyValue -InputObject $mapEntry -Name "TargetAccount"
        if (-not [string]::IsNullOrWhiteSpace($targetAccount)) { return $targetAccount }

        $targetSam = Get-AkPropertyValue -InputObject $mapEntry -Name "TargetSamAccountName"
        if ([string]::IsNullOrWhiteSpace($targetSam)) { return $null }
        return "$targetNetBios\$targetSam"
    }

    # --- Shares --------------------------------------------------------------

    foreach ($share in $shares) {
        $shareName = Get-AkPropertyValue -InputObject $share -Name "Name"
        $sourcePath = Get-AkPropertyValue -InputObject $share -Name "Path"
        if ([string]::IsNullOrWhiteSpace($shareName) -or [string]::IsNullOrWhiteSpace($sourcePath)) { continue }

        $targetPath = Resolve-TargetPath -SourcePath $sourcePath

        if (-not (Test-Path -LiteralPath $targetPath)) {
            if ($CreateMissingShareFolders) {
                if ($PSCmdlet.ShouldProcess($targetPath, "Create share folder")) {
                    try {
                        New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
                        Add-Stat -Name "ShareFoldersCreated"
                    }
                    catch {
                        Write-AkLog -Message "Could not create folder '$targetPath': $($_.Exception.Message)" -Level Error
                        Add-Stat -Name "SharesFailed"
                        continue
                    }
                }
            }
            else {
                Write-AkLog -Message "Share path '$targetPath' does not exist on this server. Copy the data first, use -SharePathMap to point at its new location, or pass -CreateMissingShareFolders." -Level Error
                Add-Stat -Name "SharesSkippedNoPath"
                continue
            }
        }

        $existingShare = $null
        try { $existingShare = Get-SmbShare -Name $shareName -ErrorAction Stop } catch { $existingShare = $null }

        if ($existingShare) {
            if ($SkipExisting) { Add-Stat -Name "SharesSkippedExisting" }
            else { Write-AkLog -Message "Share '$shareName' already exists." -Level Warning }
        }
        elseif ($PSCmdlet.ShouldProcess("$shareName -> $targetPath", "Create SMB share")) {
            try {
                $newShareParams = @{
                    Name = $shareName
                    Path = $targetPath
                }
                $description = Get-AkPropertyValue -InputObject $share -Name "Description"
                if (-not [string]::IsNullOrWhiteSpace($description)) { $newShareParams["Description"] = $description }

                $folderEnumerationMode = Get-AkPropertyValue -InputObject $share -Name "FolderEnumerationMode"
                if (-not [string]::IsNullOrWhiteSpace($folderEnumerationMode)) { $newShareParams["FolderEnumerationMode"] = $folderEnumerationMode }

                New-SmbShare @newShareParams | Out-Null
                Add-Stat -Name "SharesCreated"
            }
            catch {
                Write-AkLog -Message "Failed to create share '$shareName': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "SharesFailed"
                continue
            }
        }
        else {
            Add-Stat -Name "SharesWhatIf"
            continue
        }

        # --- Share-level permissions ----------------------------------------
        $accessRules = @($shareAccess | Where-Object { (Get-AkPropertyValue -InputObject $_ -Name "ShareName") -eq $shareName })

        foreach ($rule in $accessRules) {
            $accountName = Get-AkPropertyValue -InputObject $rule -Name "AccountName" -Default ""
            $accessRight = Get-AkPropertyValue -InputObject $rule -Name "AccessRight" -Default "Read"
            $accessType = Get-AkPropertyValue -InputObject $rule -Name "AccessControlType" -Default "Allow"

            $targetAccount = Resolve-AccountName -AccountName $accountName
            if ([string]::IsNullOrWhiteSpace($targetAccount)) {
                Write-AkLog -Message "Share '$shareName': no mapping for '$accountName'. Permission not applied." -Level Warning
                Add-Stat -Name "ShareAcesUnmapped"
                continue
            }

            if ($PSCmdlet.ShouldProcess("$shareName : $targetAccount ($accessRight)", "Grant share access")) {
                try {
                    if ($accessType -eq "Deny") {
                        Block-SmbShareAccess -Name $shareName -AccountName $targetAccount -Force -ErrorAction Stop | Out-Null
                    }
                    else {
                        Grant-SmbShareAccess -Name $shareName -AccountName $targetAccount -AccessRight $accessRight -Force -ErrorAction Stop | Out-Null
                    }
                    Add-Stat -Name "ShareAcesApplied"
                }
                catch {
                    Write-AkLog -Message "Failed to grant '$targetAccount' on share '$shareName': $($_.Exception.Message)" -Level Error
                    Add-Stat -Name "ShareAcesFailed"
                }
            }
            else {
                Add-Stat -Name "ShareAcesWhatIf"
            }
        }
    }

    # --- NTFS permissions ----------------------------------------------------
    # ACEs are grouped by folder so each folder's ACL is read, modified, and
    # written back exactly once.

    $byFolder = @{}

    foreach ($ace in $ntfsAcl) {
        if (ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $ace -Name "IsInherited") -Default $false) {
            continue    # Inherited ACEs are recreated by inheritance itself.
        }

        $rootPath = Get-AkPropertyValue -InputObject $ace -Name "RootPath" -Default ""
        $relativePath = Get-AkPropertyValue -InputObject $ace -Name "RelativePath" -Default ""
        if ([string]::IsNullOrWhiteSpace($rootPath)) { continue }

        $targetFolder = Resolve-TargetPath -SourcePath $rootPath
        if (-not [string]::IsNullOrWhiteSpace($relativePath)) {
            $targetFolder = Join-Path -Path $targetFolder -ChildPath $relativePath
        }

        if (-not $byFolder.ContainsKey($targetFolder)) {
            $byFolder[$targetFolder] = New-Object System.Collections.Generic.List[object]
        }
        $byFolder[$targetFolder].Add($ace)
    }

    foreach ($folder in $byFolder.Keys) {
        if (-not (Test-Path -LiteralPath $folder)) {
            Write-AkLog -Message "NTFS target folder '$folder' does not exist. Permissions not applied." -Level Warning
            Add-Stat -Name "NtfsFoldersMissing"
            continue
        }

        $rules = New-Object System.Collections.Generic.List[object]
        $unmapped = 0

        foreach ($ace in $byFolder[$folder]) {
            $identity = Get-AkPropertyValue -InputObject $ace -Name "IdentityReference" -Default ""
            $sid = Get-AkPropertyValue -InputObject $ace -Name "IdentitySid" -Default ""

            $targetAccount = Resolve-AccountName -AccountName $identity -Sid $sid
            if ([string]::IsNullOrWhiteSpace($targetAccount)) {
                Write-AkLog -Message "$folder : no mapping for '$identity'. ACE not applied." -Level Warning
                $unmapped++
                continue
            }

            try {
                $rights = [System.Security.AccessControl.FileSystemRights](Get-AkPropertyValue -InputObject $ace -Name "FileSystemRights" -Default "ReadAndExecute")
                $inheritance = [System.Security.AccessControl.InheritanceFlags](Get-AkPropertyValue -InputObject $ace -Name "InheritanceFlags" -Default "None")
                $propagation = [System.Security.AccessControl.PropagationFlags](Get-AkPropertyValue -InputObject $ace -Name "PropagationFlags" -Default "None")
                $type = [System.Security.AccessControl.AccessControlType](Get-AkPropertyValue -InputObject $ace -Name "AccessControlType" -Default "Allow")

                $rules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $targetAccount, $rights, $inheritance, $propagation, $type)))
            }
            catch {
                Write-AkLog -Message "$folder : could not build an access rule for '$targetAccount': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "NtfsAcesFailed"
            }
        }

        if ($unmapped -gt 0) { Add-Stat -Name "NtfsAcesUnmapped" -Count $unmapped }
        if ($rules.Count -eq 0) { continue }

        if ($PSCmdlet.ShouldProcess($folder, "Apply $($rules.Count) NTFS access rule(s)")) {
            try {
                $acl = Get-Acl -LiteralPath $folder
                foreach ($rule in $rules) { $acl.AddAccessRule($rule) }
                Set-Acl -LiteralPath $folder -AclObject $acl
                Add-Stat -Name "NtfsAcesApplied" -Count $rules.Count
            }
            catch {
                Write-AkLog -Message "Failed to apply ACL to '$folder': $($_.Exception.Message)" -Level Error
                Add-Stat -Name "NtfsAcesFailed" -Count $rules.Count
            }
        }
        else {
            Add-Stat -Name "NtfsAcesWhatIf" -Count $rules.Count
        }
    }

    Write-AkLog -Message "Share phase complete." -Level Success
}

# ===========================================================================
# Phase: Validate
# ===========================================================================
# A migration table is best-effort. Group Policy Preferences in particular embed
# domain names and UNC paths in XML that the table does not always reach, and
# drive maps are the classic offender. This phase re-reads every imported GPO
# and reports anything still pointing at the old environment.

if (Test-Phase -Name "Validate") {
    Write-Host ""
    Write-AkLog -Message "PHASE: Validation scan" -Level Step

    Assert-AkModule -Name "GroupPolicy" -Reason "Validation reads GPO reports."

    $gpoInventory = Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item GpoInventory)

    # Everything that should no longer appear anywhere in the rebuilt policies.
    $needles = New-Object System.Collections.Generic.List[object]
    $needles.Add([pscustomobject]@{ Kind = "OldDomainDns"; Value = $sourceDomainDns })
    $needles.Add([pscustomobject]@{ Kind = "OldDomainDn"; Value = $sourceDomainDn })
    if (-not [string]::IsNullOrWhiteSpace($sourceNetBios)) {
        $needles.Add([pscustomobject]@{ Kind = "OldNetBiosName"; Value = "$sourceNetBios\" })
    }
    foreach ($oldServer in $ReplaceServerName.Keys) {
        $needles.Add([pscustomobject]@{ Kind = "OldServerName"; Value = "\\$oldServer" })
    }

    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($gpo in $gpoInventory) {
        $displayName = Get-AkPropertyValue -InputObject $gpo -Name "DisplayName"

        $reportXml = $null
        try {
            $reportParams = @{ Name = $displayName; ReportType = "Xml"; Domain = $targetDomainDns }
            if (-not [string]::IsNullOrWhiteSpace($Server)) { $reportParams["Server"] = $Server }
            $reportXml = Get-GPOReport @reportParams -ErrorAction Stop
        }
        catch {
            Write-AkLog -Message "Could not read the imported report for GPO '$displayName': $($_.Exception.Message)" -Level Warning
            continue
        }

        $lines = $reportXml -split "`n"

        foreach ($needle in $needles) {
            if ($reportXml -notmatch [regex]::Escape($needle.Value)) { continue }

            # Pull a little context so the finding is actionable rather than just
            # "this GPO mentions the old domain somewhere".
            $contexts = @($lines | Where-Object { $_ -match [regex]::Escape($needle.Value) } | Select-Object -First 3)

            foreach ($context in $contexts) {
                $trimmed = $context.Trim()
                if ($trimmed.Length -gt 300) { $trimmed = $trimmed.Substring(0, 300) + "..." }

                $findings.Add([pscustomobject]@{
                    GpoDisplayName = $displayName
                    FindingKind    = $needle.Kind
                    StaleValue     = $needle.Value
                    Context        = $trimmed
                    Recommendation = "Edit this GPO in the Group Policy Management Console and repoint the setting at the new domain or file server. Group Policy Preferences drive maps, folder redirection, printer deployments, and logon scripts are the usual sources."
                })
            }
        }
    }

    $findingsPath = Join-Path -Path $PackagePath -ChildPath ("import\validation-findings-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".csv")
    [void](Export-AkCsv -InputObject $findings.ToArray() -Path $findingsPath)

    if ($findings.Count -eq 0) {
        Write-AkLog -Message "Validation found no surviving references to '$sourceDomainDns' in the imported GPOs." -Level Success
    }
    else {
        Write-AkLog -Message "Validation found $($findings.Count) surviving reference(s) to the old environment across $(@($findings | Select-Object -ExpandProperty GpoDisplayName -Unique).Count) GPO(s)." -Level Warning
        Write-AkLog -Message "Details: $findingsPath" -Level Warning

        foreach ($group in ($findings | Group-Object GpoDisplayName)) {
            Write-Host ("    {0,-45} {1} finding(s)" -f $group.Name, $group.Count) -ForegroundColor Yellow
        }
    }

    Add-Stat -Name "ValidationFindings" -Count $findings.Count
}

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
foreach ($key in ($stats.Keys | Sort-Object)) {
    Write-Host ("  {0,-32} {1}" -f $key, $stats[$key])
}
Write-Host ""

Stop-AkLog

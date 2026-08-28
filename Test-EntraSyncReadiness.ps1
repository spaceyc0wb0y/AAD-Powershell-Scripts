<#
.SYNOPSIS
Checks an Active Directory domain, or an export package, for the object problems
that break Entra Connect synchronization.

.DESCRIPTION
This is the check to run BEFORE turning on directory synchronization, and again
before importing a rebuilt domain. It finds the same classes of problem the
Microsoft IdFix tool reports, plus the hybrid-specific ones that only matter when
you are standing up a new domain that will sync to an existing tenant.

Two modes:

  Live      Read a running domain directly. This is the default.
  Package   Read users.csv from an Export-AdEnvironment.ps1 package. Use this to
            validate the OLD domain's data before you rebuild it, so you fix the
            problems once rather than twice.

Checks performed:

  Routability   UPN suffixes that are not publicly routable (.local, .lan, single
                label). This is the single most common blocker.
  Duplicates    Duplicate userPrincipalName, mail, and proxyAddresses values.
                Entra Connect refuses to sync either object in a duplicate pair.
  Format        Invalid characters and lengths in userPrincipalName,
                sAMAccountName, mail, mailNickname, displayName, and
                proxyAddresses.
  Completeness  Missing UPN, missing or blank displayName, UPN that does not
                match the primary SMTP address.

.PARAMETER Server
Domain controller to read from in Live mode.

.PARAMETER Credential
Optional credentials for the domain.

.PARAMETER PackagePath
Read users from this export package instead of a live domain.

.PARAMETER OutputPath
Folder for the findings CSV.

.PARAMETER VerifiedDomain
One or more domains already verified in the target Entra tenant. UPN suffixes
outside this list are reported. Omit to check routability only.

.PARAMETER IncludeDisabled
Include disabled accounts. Off by default, since disabled accounts are usually
out of sync scope.

.EXAMPLE
.\Test-EntraSyncReadiness.ps1

.EXAMPLE
.\Test-EntraSyncReadiness.ps1 -VerifiedDomain contoso.com,contoso.co.uk

.EXAMPLE
.\Test-EntraSyncReadiness.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500

.NOTES
Read-only. Requires the ActiveDirectory module in Live mode only.
#>

[CmdletBinding()]
param(
    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$PackagePath,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "EntraSyncReadiness"),

    [string[]]$VerifiedDomain,

    [switch]$IncludeDisabled
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Start-AkLog -Path (Join-Path -Path $OutputPath -ChildPath "entra-readiness-$timestamp.log")

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  ENTRA CONNECT SYNC READINESS" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Load users from whichever source was requested
# ---------------------------------------------------------------------------

$users = New-Object System.Collections.Generic.List[object]
$sourceLabel = ""

if (-not [string]::IsNullOrWhiteSpace($PackagePath)) {
    $manifest = Get-AkPackageManifest -PackagePath $PackagePath
    $sourceLabel = "package: $($manifest.SourceDomainDns)"
    Write-AkLog -Message "Reading users from $sourceLabel" -Level Info

    foreach ($row in (Import-AkCsv -Path (Get-AkPackageItemPath -PackagePath $PackagePath -Item Users) -Required)) {
        $enabled = ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $row -Name "Enabled") -Default $true
        if (-not $IncludeDisabled -and -not $enabled) { continue }

        $users.Add([pscustomobject]@{
            SamAccountName    = Get-AkPropertyValue -InputObject $row -Name "SamAccountName" -Default ""
            UserPrincipalName = Get-AkPropertyValue -InputObject $row -Name "UserPrincipalName" -Default ""
            DisplayName       = Get-AkPropertyValue -InputObject $row -Name "DisplayName" -Default ""
            Mail              = Get-AkPropertyValue -InputObject $row -Name "EmailAddress" -Default ""
            MailNickname      = Get-AkPropertyValue -InputObject $row -Name "MailNickname" -Default ""
            ProxyAddresses    = ConvertFrom-AkMultiValue -Value (Get-AkPropertyValue -InputObject $row -Name "ProxyAddresses")
            DistinguishedName = Get-AkPropertyValue -InputObject $row -Name "DistinguishedName" -Default ""
            Enabled           = $enabled
        })
    }
}
else {
    Assert-AkModule -Name "ActiveDirectory" -Reason "Live mode reads the domain with the AD cmdlets."

    $adParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $adParams["Server"] = $Server }
    if ($Credential) { $adParams["Credential"] = $Credential }

    $domain = Get-ADDomain @adParams
    $sourceLabel = "live domain: $($domain.DNSRoot)"
    Write-AkLog -Message "Reading users from $sourceLabel" -Level Info

    # mailNickname arrives with the Exchange schema extension. A domain that
    # never ran Exchange does not have it, and Get-ADUser fails the whole query
    # on one unknown attribute, so check the schema before requesting them. An
    # absent attribute reads as empty, which every check already tolerates.
    $properties = @("UserPrincipalName", "DisplayName", "Enabled")
    $candidateProperties = @("mail", "mailNickname", "proxyAddresses")
    try {
        $schemaNc = (Get-ADRootDSE @adParams).schemaNamingContext
        foreach ($attr in $candidateProperties) {
            $found = @(Get-ADObject -SearchBase $schemaNc @adParams `
                -LDAPFilter "(&(objectClass=attributeSchema)(lDAPDisplayName=$attr))" -ErrorAction SilentlyContinue)
            if ($found.Count -gt 0) {
                $properties += $attr
            }
            else {
                Write-AkLog -Message "Schema has no '$attr'. Its checks report nothing for this domain." -Level Warning
            }
        }
    }
    catch {
        Write-AkLog -Message "Could not read the schema: $($_.Exception.Message). Optional attributes will be attempted as-is." -Level Warning
        $properties += $candidateProperties
    }
    foreach ($adUser in @(Get-ADUser -Filter * -Properties $properties @adParams)) {
        if (-not $IncludeDisabled -and -not $adUser.Enabled) { continue }

        $users.Add([pscustomobject]@{
            SamAccountName    = $adUser.SamAccountName
            UserPrincipalName = Get-AkPropertyValue -InputObject $adUser -Name "UserPrincipalName" -Default ""
            DisplayName       = Get-AkPropertyValue -InputObject $adUser -Name "DisplayName" -Default ""
            Mail              = Get-AkPropertyValue -InputObject $adUser -Name "mail" -Default ""
            MailNickname      = Get-AkPropertyValue -InputObject $adUser -Name "mailNickname" -Default ""
            ProxyAddresses    = @(Get-AkPropertyValue -InputObject $adUser -Name "proxyAddresses" -Default @())
            DistinguishedName = $adUser.DistinguishedName
            Enabled           = $adUser.Enabled
        })
    }
}

Write-AkLog -Message "Loaded $($users.Count) user(s)." -Level Info

$findings = New-Object System.Collections.Generic.List[object]
$severityRank = @{ "Info" = 0; "Low" = 1; "Medium" = 2; "High" = 3; "Critical" = 4 }

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet("Info", "Low", "Medium", "High", "Critical")][string]$Severity,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Finding,
        [string]$AffectedObject = "",
        [string]$Attribute = "",
        [string]$Value = "",
        [string]$SuggestedFix = "",
        [Parameter(Mandatory)][string]$Recommendation
    )

    $findings.Add([pscustomobject]@{
        Severity       = $Severity
        SeverityRank   = $severityRank[$Severity]
        Check          = $Check
        AffectedObject = $AffectedObject
        Attribute      = $Attribute
        Value          = $Value
        Finding        = $Finding
        SuggestedFix   = $SuggestedFix
        Recommendation = $Recommendation
    })
}

# Characters Entra Connect rejects in a userPrincipalName.
$invalidUpnPattern = '[\\%&\*\+/=\?\{\}\|<>\(\);:,\[\]"\s]'
# mailNickname is stricter still: no spaces and no at-sign.
$invalidNicknamePattern = '[\\%&\*\+/=\?\{\}\|<>\(\);:,\[\]"\s@]'
$unroutablePattern = '\.(local|lan|internal|intranet|corp|home|test|localdomain|priv|private)$'

# ---------------------------------------------------------------------------
# UPN suffix routability
# ---------------------------------------------------------------------------

Write-AkLog -Message "Checking UPN suffix routability..." -Level Step

$suffixes = @{}
foreach ($user in $users) {
    if ($user.UserPrincipalName -notlike "*@*") { continue }
    $suffix = $user.UserPrincipalName.Split("@")[-1].ToLowerInvariant()
    if (-not $suffixes.ContainsKey($suffix)) { $suffixes[$suffix] = 0 }
    $suffixes[$suffix]++
}

foreach ($suffix in ($suffixes.Keys | Sort-Object)) {
    $count = $suffixes[$suffix]

    $isUnroutable = ($suffix -match $unroutablePattern) -or ($suffix -notlike "*.*")

    if ($isUnroutable) {
        Add-Finding -Severity "Critical" -Check "UnroutableUpnSuffix" `
            -AffectedObject $suffix -Attribute "userPrincipalName" -Value $suffix `
            -Finding "$count user(s) have the non-routable UPN suffix '@$suffix'." `
            -SuggestedFix "Add a routable suffix and reassign these users to it." `
            -Recommendation "Entra Connect cannot sync a non-routable UPN. Those users get rewritten to <name>@<tenant>.onmicrosoft.com, which is almost never what anyone wants and is disruptive to undo. Add a verified public domain as an alternative UPN suffix in Active Directory Domains and Trusts, then change each user's UPN to it BEFORE enabling sync."
    }
    elseif ($VerifiedDomain -and $VerifiedDomain.Count -gt 0 -and $VerifiedDomain -notcontains $suffix) {
        Add-Finding -Severity "High" -Check "UnverifiedUpnSuffix" `
            -AffectedObject $suffix -Attribute "userPrincipalName" -Value $suffix `
            -Finding "$count user(s) use suffix '@$suffix', which is not in the supplied verified-domain list." `
            -SuggestedFix "Verify '$suffix' in the tenant, or move these users to a verified suffix." `
            -Recommendation "Add and verify this domain in the Entra tenant before syncing, or the affected users will be assigned onmicrosoft.com addresses."
    }
    else {
        Add-Finding -Severity "Info" -Check "UpnSuffixInventory" `
            -AffectedObject $suffix -Attribute "userPrincipalName" -Value $suffix `
            -Finding "$count user(s) use the routable suffix '@$suffix'." `
            -Recommendation "Confirm this domain is verified in the target tenant."
    }
}

# ---------------------------------------------------------------------------
# Per-user attribute checks
# ---------------------------------------------------------------------------

Write-AkLog -Message "Checking per-user attributes..." -Level Step

foreach ($user in $users) {
    $sam = $user.SamAccountName
    $upn = $user.UserPrincipalName

    if ([string]::IsNullOrWhiteSpace($upn)) {
        Add-Finding -Severity "Critical" -Check "MissingUpn" `
            -AffectedObject $sam -Attribute "userPrincipalName" `
            -Finding "Account has no userPrincipalName." `
            -SuggestedFix "Set a UPN using a verified, routable domain." `
            -Recommendation "An object with no UPN cannot be synchronized. Populate it before enabling sync."
    }
    else {
        if ($upn -match $invalidUpnPattern) {
            $badChars = @([regex]::Matches($upn, $invalidUpnPattern) | ForEach-Object { $_.Value } | Select-Object -Unique)
            Add-Finding -Severity "High" -Check "InvalidUpnCharacter" `
                -AffectedObject $sam -Attribute "userPrincipalName" -Value $upn `
                -Finding "userPrincipalName contains character(s) Entra Connect rejects: $($badChars -join ' ')" `
                -SuggestedFix ($upn -replace $invalidUpnPattern, "") `
                -Recommendation "Remove or replace the invalid characters. Accented and non-ASCII letters are generally accepted; the listed punctuation and whitespace are not."
        }

        if ($upn.Length -gt 113) {
            Add-Finding -Severity "High" -Check "UpnTooLong" `
                -AffectedObject $sam -Attribute "userPrincipalName" -Value $upn `
                -Finding "userPrincipalName is $($upn.Length) characters, over the 113 character limit." `
                -Recommendation "Shorten the UPN. The prefix is limited to 64 characters and the suffix to 48."
        }

        if ($upn -like "*@*") {
            $prefix = $upn.Split("@")[0]
            if ($prefix.Length -gt 64) {
                Add-Finding -Severity "High" -Check "UpnPrefixTooLong" `
                    -AffectedObject $sam -Attribute "userPrincipalName" -Value $upn `
                    -Finding "userPrincipalName prefix is $($prefix.Length) characters, over the 64 character limit." `
                    -Recommendation "Shorten the portion before the at-sign."
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($upn)) {
            Add-Finding -Severity "Critical" -Check "MalformedUpn" `
                -AffectedObject $sam -Attribute "userPrincipalName" -Value $upn `
                -Finding "userPrincipalName does not contain an at-sign." `
                -Recommendation "A UPN must be in user@domain form. Correct it before enabling sync."
        }
    }

    if ([string]::IsNullOrWhiteSpace($user.DisplayName)) {
        Add-Finding -Severity "Medium" -Check "MissingDisplayName" `
            -AffectedObject $sam -Attribute "displayName" `
            -Finding "Account has no displayName." `
            -SuggestedFix $sam `
            -Recommendation "Populate displayName. It is what appears in the global address list and across Microsoft 365, and a blank value is highly visible to users."
    }
    elseif ($user.DisplayName.Length -gt 256) {
        Add-Finding -Severity "Medium" -Check "DisplayNameTooLong" `
            -AffectedObject $sam -Attribute "displayName" -Value $user.DisplayName `
            -Finding "displayName is $($user.DisplayName.Length) characters, over the 256 character limit." `
            -Recommendation "Shorten displayName."
    }

    if ($user.DisplayName -ne $user.DisplayName.Trim()) {
        Add-Finding -Severity "Low" -Check "LeadingOrTrailingWhitespace" `
            -AffectedObject $sam -Attribute "displayName" -Value $user.DisplayName `
            -Finding "displayName has leading or trailing whitespace." `
            -SuggestedFix $user.DisplayName.Trim() `
            -Recommendation "Trim the value. Leading and trailing whitespace causes inconsistent matching and untidy directory entries."
    }

    if (-not [string]::IsNullOrWhiteSpace($user.MailNickname)) {
        if ($user.MailNickname -match $invalidNicknamePattern) {
            Add-Finding -Severity "Medium" -Check "InvalidMailNickname" `
                -AffectedObject $sam -Attribute "mailNickname" -Value $user.MailNickname `
                -Finding "mailNickname contains invalid characters." `
                -SuggestedFix ($user.MailNickname -replace $invalidNicknamePattern, "") `
                -Recommendation "mailNickname must not contain spaces, an at-sign, or punctuation. It becomes the mailbox alias."
        }
        if ($user.MailNickname.Length -gt 64) {
            Add-Finding -Severity "Medium" -Check "MailNicknameTooLong" `
                -AffectedObject $sam -Attribute "mailNickname" -Value $user.MailNickname `
                -Finding "mailNickname is $($user.MailNickname.Length) characters, over the 64 character limit." `
                -Recommendation "Shorten mailNickname."
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($user.Mail) -and $user.Mail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        Add-Finding -Severity "Medium" -Check "MalformedMail" `
            -AffectedObject $sam -Attribute "mail" -Value $user.Mail `
            -Finding "mail is not a well-formed address." `
            -Recommendation "Correct or clear the mail attribute. A malformed value blocks the object from syncing."
    }

    # --- proxyAddresses --------------------------------------------------
    $proxies = @($user.ProxyAddresses)
    if ($proxies.Count -gt 0) {
        $primaries = @($proxies | Where-Object { $_ -cmatch '^SMTP:' })

        if ($primaries.Count -gt 1) {
            Add-Finding -Severity "High" -Check "MultiplePrimarySmtp" `
                -AffectedObject $sam -Attribute "proxyAddresses" -Value ($primaries -join "; ") `
                -Finding "Account has $($primaries.Count) primary SMTP addresses (uppercase SMTP:)." `
                -Recommendation "Exactly one proxy address may use uppercase SMTP:. Lower-case the others to smtp:. More than one primary blocks the object from syncing."
        }
        elseif ($primaries.Count -eq 0 -and @($proxies | Where-Object { $_ -match '^smtp:' }).Count -gt 0) {
            Add-Finding -Severity "Medium" -Check "NoPrimarySmtp" `
                -AffectedObject $sam -Attribute "proxyAddresses" -Value ($proxies -join "; ") `
                -Finding "Account has SMTP proxy addresses but none marked primary." `
                -Recommendation "Set exactly one address to uppercase SMTP: to designate the primary reply address."
        }

        foreach ($proxy in $proxies) {
            if ($proxy -notmatch '^[A-Za-z0-9]+:') {
                Add-Finding -Severity "Medium" -Check "MalformedProxyAddress" `
                    -AffectedObject $sam -Attribute "proxyAddresses" -Value $proxy `
                    -Finding "Proxy address has no type prefix." `
                    -SuggestedFix "smtp:$proxy" `
                    -Recommendation "Every proxy address must be prefixed with its type, for example smtp: or x500:."
                continue
            }

            if ($proxy -match '^(?i)smtp:' -and $proxy -notmatch '^(?i)smtp:[^@\s]+@[^@\s]+\.[^@\s]+$') {
                Add-Finding -Severity "Medium" -Check "MalformedProxyAddress" `
                    -AffectedObject $sam -Attribute "proxyAddresses" -Value $proxy `
                    -Finding "SMTP proxy address is not a well-formed address." `
                    -Recommendation "Correct or remove this proxy address."
            }
        }

        # A UPN that differs from the primary SMTP address is legal but is the
        # usual cause of "why is my sign-in name different from my email".
        if ($primaries.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($upn)) {
            $primaryAddress = $primaries[0].Substring(5)
            if ($primaryAddress -ne $upn) {
                Add-Finding -Severity "Low" -Check "UpnDoesNotMatchPrimarySmtp" `
                    -AffectedObject $sam -Attribute "userPrincipalName" -Value $upn `
                    -Finding "userPrincipalName '$upn' differs from the primary SMTP address '$primaryAddress'." `
                    -SuggestedFix $primaryAddress `
                    -Recommendation "Legal, but users then sign in with one address and receive mail at another. Align them unless there is a deliberate reason not to."
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($sam) -and $sam.Length -gt 20) {
        Add-Finding -Severity "Medium" -Check "SamAccountNameTooLong" `
            -AffectedObject $sam -Attribute "sAMAccountName" -Value $sam `
            -Finding "sAMAccountName is $($sam.Length) characters, over the 20 character limit." `
            -Recommendation "Shorten it. Values over 20 characters cannot be created by every tool and cause inconsistent behaviour."
    }
}

# ---------------------------------------------------------------------------
# Duplicate detection
# ---------------------------------------------------------------------------
# Entra Connect refuses to sync BOTH objects in a duplicate pair, so a single
# duplicate silently costs two accounts.

Write-AkLog -Message "Checking for duplicate values..." -Level Step

function Test-Duplicate {
    param(
        [Parameter(Mandatory)][string]$Attribute,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][hashtable]$Index,
        [Parameter(Mandatory)][string]$Severity
    )

    foreach ($value in $Index.Keys) {
        $owners = @($Index[$value] | Select-Object -Unique)
        if ($owners.Count -lt 2) { continue }

        Add-Finding -Severity $Severity -Check $Check `
            -AffectedObject ($owners -join "; ") -Attribute $Attribute -Value $value `
            -Finding "$($owners.Count) objects share the $Attribute value '$value'." `
            -Recommendation "Make the value unique. Entra Connect will refuse to sync every object involved in a duplicate, not just one of them, so a single collision costs you all of these accounts."
    }
}

$upnIndex = @{}
$mailIndex = @{}
$proxyIndex = @{}

foreach ($user in $users) {
    $sam = $user.SamAccountName

    if (-not [string]::IsNullOrWhiteSpace($user.UserPrincipalName)) {
        $key = $user.UserPrincipalName.ToLowerInvariant()
        if (-not $upnIndex.ContainsKey($key)) { $upnIndex[$key] = New-Object System.Collections.Generic.List[string] }
        $upnIndex[$key].Add($sam)
    }

    if (-not [string]::IsNullOrWhiteSpace($user.Mail)) {
        $key = $user.Mail.ToLowerInvariant()
        if (-not $mailIndex.ContainsKey($key)) { $mailIndex[$key] = New-Object System.Collections.Generic.List[string] }
        $mailIndex[$key].Add($sam)
    }

    foreach ($proxy in @($user.ProxyAddresses)) {
        if ([string]::IsNullOrWhiteSpace($proxy)) { continue }
        # Compare case-insensitively so SMTP: and smtp: collide, which they do.
        $key = $proxy.ToLowerInvariant()
        if (-not $proxyIndex.ContainsKey($key)) { $proxyIndex[$key] = New-Object System.Collections.Generic.List[string] }
        $proxyIndex[$key].Add($sam)
    }
}

Test-Duplicate -Attribute "userPrincipalName" -Check "DuplicateUpn" -Index $upnIndex -Severity "Critical"
Test-Duplicate -Attribute "mail" -Check "DuplicateMail" -Index $mailIndex -Severity "High"
Test-Duplicate -Attribute "proxyAddresses" -Check "DuplicateProxyAddress" -Index $proxyIndex -Severity "Critical"

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$reported = @($findings | Sort-Object -Property SeverityRank -Descending)
$csvPath = Join-Path -Path $OutputPath -ChildPath "EntraSyncReadiness-$timestamp.csv"
[void](Export-AkCsv -InputObject $reported -Path $csvPath)

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  RESULTS  ($sourceLabel)" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($severity in @("Critical", "High", "Medium", "Low", "Info")) {
    $count = @($reported | Where-Object { $_.Severity -eq $severity }).Count
    if ($count -eq 0) { continue }

    $color = switch ($severity) {
        "Critical" { "Red" }
        "High"     { "Red" }
        "Medium"   { "Yellow" }
        "Low"      { "Yellow" }
        default    { "Gray" }
    }
    Write-Host ("  {0,-10} {1}" -f $severity, $count) -ForegroundColor $color
}

Write-Host ""
$blockers = @($reported | Where-Object { $_.Severity -eq "Critical" })
if ($blockers.Count -gt 0) {
    Write-Host "  Sync blockers to fix first:" -ForegroundColor Red
    foreach ($group in ($blockers | Group-Object Check | Sort-Object Count -Descending)) {
        Write-Host ("    {0,-32} {1}" -f $group.Name, $group.Count) -ForegroundColor Red
    }
}
else {
    Write-Host "  No sync blockers found." -ForegroundColor Green
}

Write-Host ""
Write-AkLog -Message "Findings written to $csvPath" -Level Success
Write-Host ""

Stop-AkLog

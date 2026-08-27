<#
.SYNOPSIS
Read-only Active Directory security assessment. Reports risks, ranks them, and
says what to do about each one.

.DESCRIPTION
Clone this repository onto a domain-joined machine and run this script to get a
prioritized picture of the domain's security posture. It makes NO changes: every
check is a read.

Checks performed:

  Identity hygiene     Stale accounts, never-logged-on accounts, ancient
                       passwords, password-never-expires, password-not-required,
                       enabled Guest account.
  Credential exposure  Kerberoastable service accounts, AS-REP roastable
                       accounts, reversible encryption, DES-only Kerberos,
                       cpassword in SYSVOL (MS14-025).
  Privilege            Membership of every privileged group, orphaned AdminCount
                       objects, Protected Users adoption, krbtgt password age.
  Delegation           Unconstrained delegation, constrained delegation with
                       protocol transition, resource-based delegation.
  Domain configuration Functional levels, machine account quota, AD Recycle Bin,
                       default password policy, Pre-Windows 2000 Compatible
                       Access membership, LAPS deployment.

.PARAMETER Server
Domain controller to read from. Defaults to the current domain's preferred DC.

.PARAMETER Credential
Optional credentials for reading the domain.

.PARAMETER OutputPath
Folder for the findings CSV and optional HTML report.

.PARAMETER StaleDays
Days without a logon before an enabled account is reported as stale.

.PARAMETER PasswordAgeDays
Password age in days before an account is reported as having a stale password.

.PARAMETER SkipSysvolScan
Skip the SYSVOL scan for Group Policy Preferences passwords. That scan reads
every XML file under SYSVOL and can be slow on a large policy set.

.PARAMETER HtmlReport
Also write a self-contained HTML report next to the CSV.

.PARAMETER MinimumSeverity
Only report findings at or above this severity.

.EXAMPLE
.\Invoke-AdSecurityScan.ps1

.EXAMPLE
.\Invoke-AdSecurityScan.ps1 -OutputPath C:\Reports -HtmlReport -StaleDays 60

.EXAMPLE
.\Invoke-AdSecurityScan.ps1 -MinimumSeverity High

.NOTES
Read-only. Requires the ActiveDirectory module and a domain user account; some
checks report more detail when run as Domain Admin.
#>

[CmdletBinding()]
param(
    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "AdSecurityScan"),

    [int]$StaleDays = 90,

    [int]$PasswordAgeDays = 365,

    [switch]$SkipSysvolScan,

    [switch]$HtmlReport,

    [ValidateSet("Info", "Low", "Medium", "High", "Critical")]
    [string]$MinimumSeverity = "Info"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force
Assert-AkModule -Name "ActiveDirectory" -Reason "The security scan reads the directory with the AD cmdlets."

$adParams = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $adParams["Server"] = $Server }
if ($Credential) { $adParams["Credential"] = $Credential }

$domain = Get-ADDomain @adParams
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Start-AkLog -Path (Join-Path -Path $OutputPath -ChildPath "security-scan-$timestamp.log")

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  ACTIVE DIRECTORY SECURITY SCAN" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-AkLog -Message "Domain: $($domain.DNSRoot)" -Level Info
Write-AkLog -Message "This scan is read-only." -Level Info

$findings = New-Object System.Collections.Generic.List[object]
$severityRank = @{ "Info" = 0; "Low" = 1; "Medium" = 2; "High" = 3; "Critical" = 4 }
$now = Get-Date

function Add-Finding {
    <#
    .SYNOPSIS
    Records one security finding.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet("Info", "Low", "Medium", "High", "Critical")][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Finding,
        [string]$AffectedObject = "",
        [string]$Detail = "",
        [Parameter(Mandatory)][string]$Recommendation
    )

    $findings.Add([pscustomobject]@{
        Severity       = $Severity
        SeverityRank   = $severityRank[$Severity]
        Category       = $Category
        Check          = $Check
        AffectedObject = $AffectedObject
        Finding        = $Finding
        Detail         = $Detail
        Recommendation = $Recommendation
    })
}

function Invoke-Check {
    <#
    .SYNOPSIS
    Runs one check and turns an unexpected failure into a finding rather than
    aborting the whole scan.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body
    )

    Write-AkLog -Message "Checking: $Name" -Level Step
    try {
        & $Body
    }
    catch {
        Write-AkLog -Message "Check '$Name' failed: $($_.Exception.Message)" -Level Error
        Add-Finding -Severity "Info" -Category "ScanCoverage" -Check $Name `
            -Finding "This check could not complete." `
            -Detail $_.Exception.Message `
            -Recommendation "Re-run the scan with sufficient rights, or investigate this check manually. Its absence is not evidence that the domain is clean."
    }
}

# ---------------------------------------------------------------------------
# Collect once, reuse across checks
# ---------------------------------------------------------------------------

$userProperties = @("SamAccountName", "Enabled", "LastLogonDate", "PasswordLastSet", "PasswordNeverExpires",
    "PasswordNotRequired", "AdminCount", "ServicePrincipalNames", "TrustedForDelegation",
    "TrustedToAuthForDelegation", "msDS-AllowedToDelegateTo", "DoesNotRequirePreAuth",
    "UserAccountControl", "whenCreated", "DistinguishedName", "UserPrincipalName", "Description",
    "AllowReversiblePasswordEncryption", "SIDHistory", "msDS-SupportedEncryptionTypes")

Write-AkLog -Message "Reading users..." -Level Info
$allUsers = @(Get-ADUser -Filter * -Properties $userProperties @adParams)

Write-AkLog -Message "Reading computers..." -Level Info
$computerProperties = @("SamAccountName", "Enabled", "LastLogonDate", "OperatingSystem", "PasswordLastSet",
    "TrustedForDelegation", "TrustedToAuthForDelegation", "msDS-AllowedToDelegateTo",
    "msDS-AllowedToActOnBehalfOfOtherIdentity", "DistinguishedName", "PrimaryGroupID", "whenCreated")
$allComputers = @(Get-ADComputer -Filter * -Properties $computerProperties @adParams)

$domainControllers = @(Get-ADDomainController -Filter * @adParams)
$dcNames = @($domainControllers | ForEach-Object { $_.Name })

Write-AkLog -Message "Found $($allUsers.Count) users, $($allComputers.Count) computers, $($dcNames.Count) domain controllers." -Level Info

# ---------------------------------------------------------------------------
# Identity hygiene
# ---------------------------------------------------------------------------

Invoke-Check -Name "Stale user accounts" -Body {
    $cutoff = $now.AddDays(-$StaleDays)

    $stale = @($allUsers | Where-Object {
        $_.Enabled -eq $true -and
        $null -ne $_.LastLogonDate -and
        $_.LastLogonDate -lt $cutoff
    })

    foreach ($user in $stale) {
        $days = [int]($now - $user.LastLogonDate).TotalDays
        Add-Finding -Severity "Medium" -Category "IdentityHygiene" -Check "StaleUserAccount" `
            -AffectedObject $user.SamAccountName `
            -Finding "Enabled account has not signed in for $days days." `
            -Detail "Last logon: $($user.LastLogonDate)" `
            -Recommendation "Confirm the account is still needed. Disable it, move it to a disabled-accounts OU, and delete it after a retention period. Dormant enabled accounts are a preferred target because nobody notices when they are used."
    }

    if ($stale.Count -gt 0) {
        Write-AkLog -Message "$($stale.Count) stale user account(s)." -Level Warning
    }
}

Invoke-Check -Name "Enabled accounts that have never signed in" -Body {
    $neverLoggedOn = @($allUsers | Where-Object {
        $_.Enabled -eq $true -and
        $null -eq $_.LastLogonDate -and
        $null -ne $_.whenCreated -and
        $_.whenCreated -lt $now.AddDays(-30)
    })

    foreach ($user in $neverLoggedOn) {
        Add-Finding -Severity "Medium" -Category "IdentityHygiene" -Check "NeverLoggedOnAccount" `
            -AffectedObject $user.SamAccountName `
            -Finding "Enabled account created more than 30 days ago has never signed in." `
            -Detail "Created: $($user.whenCreated)" `
            -Recommendation "Either the account was provisioned and never used, or it exists only as a backdoor. Disable it unless someone can name its owner and purpose."
    }
}

Invoke-Check -Name "Password never expires" -Body {
    $neverExpires = @($allUsers | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true })

    foreach ($user in $neverExpires) {
        $severity = "Medium"
        $detail = "Password last set: $($user.PasswordLastSet)"

        # An old password that also never expires is materially worse.
        if ($null -ne $user.PasswordLastSet -and $user.PasswordLastSet -lt $now.AddDays(-$PasswordAgeDays)) {
            $severity = "High"
            $detail += " (over $PasswordAgeDays days old)"
        }

        Add-Finding -Severity $severity -Category "IdentityHygiene" -Check "PasswordNeverExpires" `
            -AffectedObject $user.SamAccountName `
            -Finding "Enabled account is set to never expire its password." `
            -Detail $detail `
            -Recommendation "For service accounts, migrate to a Group Managed Service Account (gMSA), which rotates its own password automatically. For human accounts, clear the flag and enrol in the normal password policy."
    }
}

Invoke-Check -Name "Password not required" -Body {
    $notRequired = @($allUsers | Where-Object { $_.Enabled -eq $true -and $_.PasswordNotRequired -eq $true })

    foreach ($user in $notRequired) {
        Add-Finding -Severity "High" -Category "IdentityHygiene" -Check "PasswordNotRequired" `
            -AffectedObject $user.SamAccountName `
            -Finding "Account is flagged PASSWD_NOTREQD, so it may have an empty password." `
            -Detail "Password last set: $($user.PasswordLastSet)" `
            -Recommendation "Clear the PASSWD_NOTREQD flag and reset the password. This flag lets an account bypass the domain minimum length entirely, including having no password at all."
    }
}

Invoke-Check -Name "Very old passwords" -Body {
    $cutoff = $now.AddDays(-$PasswordAgeDays)

    $oldPasswords = @($allUsers | Where-Object {
        $_.Enabled -eq $true -and
        $_.PasswordNeverExpires -ne $true -and
        $null -ne $_.PasswordLastSet -and
        $_.PasswordLastSet -lt $cutoff
    })

    foreach ($user in $oldPasswords) {
        $days = [int]($now - $user.PasswordLastSet).TotalDays
        Add-Finding -Severity "Low" -Category "IdentityHygiene" -Check "StalePassword" `
            -AffectedObject $user.SamAccountName `
            -Finding "Password is $days days old." `
            -Detail "Password last set: $($user.PasswordLastSet)" `
            -Recommendation "Investigate why the domain password policy is not forcing a change. This usually indicates a fine-grained password policy or a smart-card-required account."
    }
}

Invoke-Check -Name "Guest account" -Body {
    $guestSid = "$($domain.DomainSID.Value)-501"
    $guest = $null
    try { $guest = Get-ADUser -Identity $guestSid -Properties Enabled @adParams -ErrorAction Stop } catch { $guest = $null }

    if ($guest -and $guest.Enabled) {
        Add-Finding -Severity "High" -Category "IdentityHygiene" -Check "GuestAccountEnabled" `
            -AffectedObject $guest.SamAccountName `
            -Finding "The built-in Guest account is enabled." `
            -Recommendation "Disable the Guest account. It is disabled by default and there is almost never a legitimate reason to enable it."
    }
    else {
        Add-Finding -Severity "Info" -Category "IdentityHygiene" -Check "GuestAccountEnabled" `
            -AffectedObject "Guest" -Finding "The built-in Guest account is disabled." `
            -Recommendation "No action required."
    }
}

# ---------------------------------------------------------------------------
# Credential exposure
# ---------------------------------------------------------------------------

Invoke-Check -Name "Kerberoastable accounts" -Body {
    $kerberoastable = @($allUsers | Where-Object {
        $_.Enabled -eq $true -and
        $null -ne $_.ServicePrincipalNames -and
        @($_.ServicePrincipalNames).Count -gt 0 -and
        $_.SamAccountName -ne "krbtgt"
    })

    foreach ($user in $kerberoastable) {
        # A privileged account with an SPN is the high-value version of this.
        $severity = "High"
        $extra = ""
        if ($user.AdminCount -eq 1) {
            $severity = "Critical"
            $extra = " This account is or was privileged (adminCount=1), which makes it a direct path to domain compromise."
        }

        Add-Finding -Severity $severity -Category "CredentialExposure" -Check "KerberoastableAccount" `
            -AffectedObject $user.SamAccountName `
            -Finding "User account has a service principal name and can be Kerberoasted." `
            -Detail "SPNs: $(@($user.ServicePrincipalNames) -join '; ')" `
            -Recommendation ("Any domain user can request a service ticket for this account and crack it offline against the account's password." + $extra + " Migrate the service to a Group Managed Service Account, or give it a 25+ character random password and remove it from all privileged groups.")
    }
}

Invoke-Check -Name "AS-REP roastable accounts" -Body {
    $asrep = @($allUsers | Where-Object { $_.Enabled -eq $true -and $_.DoesNotRequirePreAuth -eq $true })

    foreach ($user in $asrep) {
        Add-Finding -Severity "High" -Category "CredentialExposure" -Check "AsRepRoastable" `
            -AffectedObject $user.SamAccountName `
            -Finding "Kerberos pre-authentication is disabled, so the account is AS-REP roastable." `
            -Recommendation "Re-enable Kerberos pre-authentication on this account. With it disabled, an unauthenticated attacker who merely knows the account name can request crackable encrypted material."
    }
}

Invoke-Check -Name "Reversible password encryption" -Body {
    $reversible = @($allUsers | Where-Object { $_.AllowReversiblePasswordEncryption -eq $true })

    foreach ($user in $reversible) {
        Add-Finding -Severity "Critical" -Category "CredentialExposure" -Check "ReversibleEncryption" `
            -AffectedObject $user.SamAccountName `
            -Finding "Password is stored using reversible encryption." `
            -Recommendation "Clear this flag and reset the password immediately. Reversible encryption stores the password in a form that can be decrypted back to plaintext by anyone who can read the directory database."
    }
}

Invoke-Check -Name "DES-only Kerberos encryption" -Body {
    $desOnly = @($allUsers | Where-Object {
        $_.Enabled -eq $true -and
        $null -ne $_."msDS-SupportedEncryptionTypes" -and
        (($_."msDS-SupportedEncryptionTypes" -band 3) -ne 0) -and
        (($_."msDS-SupportedEncryptionTypes" -band 24) -eq 0)
    })

    foreach ($user in $desOnly) {
        Add-Finding -Severity "High" -Category "CredentialExposure" -Check "DesEncryptionOnly" `
            -AffectedObject $user.SamAccountName `
            -Finding "Account is configured for DES Kerberos encryption without AES." `
            -Detail "msDS-SupportedEncryptionTypes: $($user.'msDS-SupportedEncryptionTypes')" `
            -Recommendation "Enable AES128/AES256 for this account and remove DES. DES is trivially breakable and is disabled by default from Windows 7 and Server 2008 R2 onward."
    }
}

Invoke-Check -Name "Group Policy Preferences passwords in SYSVOL" -Body {
    if ($SkipSysvolScan) {
        Add-Finding -Severity "Info" -Category "ScanCoverage" -Check "SysvolCpassword" `
            -Finding "SYSVOL scan was skipped by request." `
            -Recommendation "Re-run without -SkipSysvolScan to check for Group Policy Preferences passwords."
        return
    }

    $sysvolPath = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
    if (-not (Test-Path -LiteralPath $sysvolPath)) {
        Add-Finding -Severity "Info" -Category "ScanCoverage" -Check "SysvolCpassword" `
            -Finding "SYSVOL policies path was not reachable." `
            -Detail $sysvolPath `
            -Recommendation "Run this scan from a domain-joined machine that can reach SYSVOL."
        return
    }

    # MS14-025. The AES key used to encrypt cpassword was published by Microsoft,
    # so any cpassword value in SYSVOL is readable plaintext to any domain user.
    $xmlFiles = @(Get-ChildItem -LiteralPath $sysvolPath -Recurse -Include "*.xml" -File -ErrorAction SilentlyContinue)

    foreach ($file in $xmlFiles) {
        try {
            $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            if ($content -match 'cpassword\s*=\s*"([^"]+)"') {
                Add-Finding -Severity "Critical" -Category "CredentialExposure" -Check "SysvolCpassword" `
                    -AffectedObject $file.FullName `
                    -Finding "A Group Policy Preferences file in SYSVOL contains a cpassword value." `
                    -Detail "File: $($file.Name)" `
                    -Recommendation "Remove this preference item immediately and rotate the password it contains. Microsoft published the decryption key in MS14-025, so this password is readable in plaintext by every authenticated domain user. Check whether the same password is used elsewhere."
            }
        }
        catch {
            # Unreadable file, not a finding in itself.
        }
    }

    Write-AkLog -Message "Scanned $($xmlFiles.Count) SYSVOL XML file(s)." -Level Info
}

# ---------------------------------------------------------------------------
# Privilege
# ---------------------------------------------------------------------------

Invoke-Check -Name "Privileged group membership" -Body {
    # Matched by RID where possible so this works on non-English domains.
    $privilegedRids = @{
        "512" = @{ Name = "Domain Admins"; Severity = "High" }
        "519" = @{ Name = "Enterprise Admins"; Severity = "High" }
        "518" = @{ Name = "Schema Admins"; Severity = "High" }
        "517" = @{ Name = "Cert Publishers"; Severity = "Medium" }
        "520" = @{ Name = "Group Policy Creator Owners"; Severity = "Medium" }
    }

    foreach ($rid in $privilegedRids.Keys) {
        $groupSid = "$($domain.DomainSID.Value)-$rid"
        $group = $null
        try { $group = Get-ADGroup -Identity $groupSid @adParams -ErrorAction Stop } catch { continue }

        $members = @()
        try { $members = @(Get-ADGroupMember -Identity $group -Recursive @adParams -ErrorAction Stop) } catch { continue }

        $info = $privilegedRids[$rid]

        Add-Finding -Severity "Info" -Category "Privilege" -Check "PrivilegedGroupMembership" `
            -AffectedObject $group.Name `
            -Finding "$($group.Name) has $($members.Count) effective member(s)." `
            -Detail (@($members | ForEach-Object { $_.SamAccountName }) -join "; ") `
            -Recommendation "Review this list. Every member is a path to control of the domain."

        if ($members.Count -gt 5 -and ($rid -eq "512" -or $rid -eq "519")) {
            Add-Finding -Severity $info.Severity -Category "Privilege" -Check "OversizedPrivilegedGroup" `
                -AffectedObject $group.Name `
                -Finding "$($group.Name) has $($members.Count) members, which is more than a typical environment needs." `
                -Detail (@($members | ForEach-Object { $_.SamAccountName }) -join "; ") `
                -Recommendation "Reduce to the smallest possible set of dedicated admin accounts. Administrators should hold a separate privileged account and use it only for administration, never for mail or browsing."
        }

        # Schema Admins should be empty except during a schema change.
        if ($rid -eq "518" -and $members.Count -gt 0) {
            Add-Finding -Severity "Medium" -Category "Privilege" -Check "SchemaAdminsNotEmpty" `
                -AffectedObject $group.Name `
                -Finding "Schema Admins is not empty ($($members.Count) member(s))." `
                -Detail (@($members | ForEach-Object { $_.SamAccountName }) -join "; ") `
                -Recommendation "Keep Schema Admins empty except during a planned schema extension. Schema changes are forest-wide and irreversible."
        }
    }

    # Operator groups are BUILTIN, so they are matched by their fixed SIDs.
    $builtinOperators = @{
        "S-1-5-32-548" = "Account Operators"
        "S-1-5-32-551" = "Backup Operators"
        "S-1-5-32-549" = "Server Operators"
        "S-1-5-32-550" = "Print Operators"
    }

    foreach ($sid in $builtinOperators.Keys) {
        $group = $null
        try { $group = Get-ADGroup -Identity $sid @adParams -ErrorAction Stop } catch { continue }

        $members = @()
        try { $members = @(Get-ADGroupMember -Identity $group @adParams -ErrorAction Stop) } catch { continue }
        if ($members.Count -eq 0) { continue }

        Add-Finding -Severity "High" -Category "Privilege" -Check "LegacyOperatorGroupInUse" `
            -AffectedObject $builtinOperators[$sid] `
            -Finding "$($builtinOperators[$sid]) has $($members.Count) member(s)." `
            -Detail (@($members | ForEach-Object { $_.SamAccountName }) -join "; ") `
            -Recommendation "These legacy groups grant far more than their names suggest and are effectively paths to domain compromise. Empty them and delegate the specific rights actually required instead."
    }
}

Invoke-Check -Name "Orphaned AdminCount objects" -Body {
    $adminCountUsers = @($allUsers | Where-Object { $_.AdminCount -eq 1 })
    if ($adminCountUsers.Count -eq 0) { return }

    # Build the set of accounts that are *currently* privileged.
    $currentlyPrivileged = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($rid in @("512", "519", "518", "520")) {
        try {
            $group = Get-ADGroup -Identity "$($domain.DomainSID.Value)-$rid" @adParams -ErrorAction Stop
            foreach ($member in @(Get-ADGroupMember -Identity $group -Recursive @adParams -ErrorAction Stop)) {
                [void]$currentlyPrivileged.Add($member.SamAccountName)
            }
        }
        catch { }
    }

    foreach ($sid in @("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-551", "S-1-5-32-549", "S-1-5-32-550")) {
        try {
            foreach ($member in @(Get-ADGroupMember -Identity $sid @adParams -ErrorAction Stop)) {
                [void]$currentlyPrivileged.Add($member.SamAccountName)
            }
        }
        catch { }
    }

    $orphaned = @($adminCountUsers | Where-Object { -not $currentlyPrivileged.Contains($_.SamAccountName) })

    foreach ($user in $orphaned) {
        Add-Finding -Severity "Medium" -Category "Privilege" -Check "OrphanedAdminCount" `
            -AffectedObject $user.SamAccountName `
            -Finding "Account has adminCount=1 but is no longer in any privileged group." `
            -Detail "Enabled: $($user.Enabled)" `
            -Recommendation "The account was privileged in the past. AdminSDHolder has stripped its ACL inheritance and left it that way, so it no longer receives delegated permissions as expected and its history is easy to miss. Clear adminCount and re-enable inheritance after confirming the account should not be privileged."
    }
}

Invoke-Check -Name "krbtgt password age" -Body {
    $krbtgt = $null
    try { $krbtgt = Get-ADUser -Identity "$($domain.DomainSID.Value)-502" -Properties PasswordLastSet @adParams -ErrorAction Stop } catch { return }
    if (-not $krbtgt -or $null -eq $krbtgt.PasswordLastSet) { return }

    $days = [int]($now - $krbtgt.PasswordLastSet).TotalDays

    $severity = "Info"
    if ($days -gt 180) { $severity = "Medium" }
    if ($days -gt 365) { $severity = "High" }

    Add-Finding -Severity $severity -Category "Privilege" -Check "KrbtgtPasswordAge" `
        -AffectedObject "krbtgt" `
        -Finding "The krbtgt account password is $days days old." `
        -Detail "Password last set: $($krbtgt.PasswordLastSet)" `
        -Recommendation "The krbtgt key signs every Kerberos ticket in the domain. If it has ever been stolen, an attacker can forge Golden Tickets valid until it is rotated TWICE. Rotate it twice, at least 10 hours apart, on a routine schedule and immediately after any suspected compromise."
}

Invoke-Check -Name "Protected Users adoption" -Body {
    $group = $null
    try { $group = Get-ADGroup -Identity "$($domain.DomainSID.Value)-525" @adParams -ErrorAction Stop } catch { return }

    $members = @()
    try { $members = @(Get-ADGroupMember -Identity $group @adParams -ErrorAction Stop) } catch { return }

    if ($members.Count -eq 0) {
        Add-Finding -Severity "Low" -Category "Privilege" -Check "ProtectedUsersEmpty" `
            -AffectedObject "Protected Users" `
            -Finding "The Protected Users group is empty." `
            -Recommendation "Add your Domain Admins and other tier-0 accounts to Protected Users. Membership blocks NTLM, unconstrained delegation, and credential caching for those accounts. Test first: members cannot use NTLM authentication at all, which breaks some legacy applications."
    }
    else {
        Add-Finding -Severity "Info" -Category "Privilege" -Check "ProtectedUsersEmpty" `
            -AffectedObject "Protected Users" `
            -Finding "Protected Users has $($members.Count) member(s)." `
            -Detail (@($members | ForEach-Object { $_.SamAccountName }) -join "; ") `
            -Recommendation "Confirm every tier-0 account is included."
    }
}

# ---------------------------------------------------------------------------
# Delegation
# ---------------------------------------------------------------------------

Invoke-Check -Name "Unconstrained delegation" -Body {
    # Domain controllers legitimately have this and are excluded.
    $unconstrainedComputers = @($allComputers | Where-Object {
        $_.TrustedForDelegation -eq $true -and $dcNames -notcontains $_.Name
    })

    foreach ($computer in $unconstrainedComputers) {
        Add-Finding -Severity "Critical" -Category "Delegation" -Check "UnconstrainedDelegation" `
            -AffectedObject $computer.Name `
            -Finding "Computer is trusted for unconstrained delegation." `
            -Detail "OS: $($computer.OperatingSystem)" `
            -Recommendation "Anyone who compromises this server can capture the Kerberos TGT of every user and computer that connects to it, including a Domain Admin or a domain controller. Replace with constrained delegation or resource-based constrained delegation, and add sensitive accounts to Protected Users in the meantime."
    }

    $unconstrainedUsers = @($allUsers | Where-Object { $_.TrustedForDelegation -eq $true })
    foreach ($user in $unconstrainedUsers) {
        Add-Finding -Severity "Critical" -Category "Delegation" -Check "UnconstrainedDelegation" `
            -AffectedObject $user.SamAccountName `
            -Finding "User account is trusted for unconstrained delegation." `
            -Recommendation "Remove this flag. A user account with unconstrained delegation is a direct path to capturing privileged Kerberos tickets."
    }
}

Invoke-Check -Name "Constrained delegation with protocol transition" -Body {
    $protocolTransition = @($allComputers | Where-Object { $_.TrustedToAuthForDelegation -eq $true }) +
                          @($allUsers | Where-Object { $_.TrustedToAuthForDelegation -eq $true })

    foreach ($object in $protocolTransition) {
        $targets = Get-AkPropertyValue -InputObject $object -Name "msDS-AllowedToDelegateTo" -Default @()
        Add-Finding -Severity "High" -Category "Delegation" -Check "ProtocolTransition" `
            -AffectedObject $object.SamAccountName `
            -Finding "Object is configured for constrained delegation with protocol transition (use any authentication protocol)." `
            -Detail "Delegates to: $(@($targets) -join '; ')" `
            -Recommendation "Protocol transition lets this object request tickets for any user to the listed services without that user ever authenticating. Prefer Kerberos-only constrained delegation, or resource-based constrained delegation configured on the resource itself."
    }
}

Invoke-Check -Name "Resource-based constrained delegation" -Body {
    $rbcd = @($allComputers | Where-Object {
        $null -ne (Get-AkPropertyValue -InputObject $_ -Name "msDS-AllowedToActOnBehalfOfOtherIdentity")
    })

    foreach ($computer in $rbcd) {
        Add-Finding -Severity "Medium" -Category "Delegation" -Check "ResourceBasedDelegation" `
            -AffectedObject $computer.Name `
            -Finding "Computer has resource-based constrained delegation configured." `
            -Recommendation "Verify this is intentional. Attackers write this attribute to establish persistence, and any principal that can write it on a computer object effectively controls that computer."
    }
}

# ---------------------------------------------------------------------------
# Domain configuration
# ---------------------------------------------------------------------------

Invoke-Check -Name "Machine account quota" -Body {
    $quotaObject = Get-ADObject -Identity $domain.DistinguishedName -Properties "ms-DS-MachineAccountQuota" @adParams
    $quota = Get-AkPropertyValue -InputObject $quotaObject -Name "ms-DS-MachineAccountQuota" -Default 10

    if ([int]$quota -gt 0) {
        Add-Finding -Severity "Medium" -Category "DomainConfiguration" -Check "MachineAccountQuota" `
            -AffectedObject $domain.DNSRoot `
            -Finding "Any authenticated user can join up to $quota computers to the domain." `
            -Detail "ms-DS-MachineAccountQuota = $quota" `
            -Recommendation "Set ms-DS-MachineAccountQuota to 0 and delegate machine-join rights to a specific group instead. The default of 10 is a building block for several privilege-escalation chains, including resource-based delegation attacks."
    }
    else {
        Add-Finding -Severity "Info" -Category "DomainConfiguration" -Check "MachineAccountQuota" `
            -AffectedObject $domain.DNSRoot -Finding "Machine account quota is 0." `
            -Recommendation "No action required."
    }
}

Invoke-Check -Name "Default domain password policy" -Body {
    $policy = Get-ADDefaultDomainPasswordPolicy @adParams

    if ($policy.MinPasswordLength -lt 14) {
        Add-Finding -Severity "Medium" -Category "DomainConfiguration" -Check "WeakPasswordPolicy" `
            -AffectedObject $domain.DNSRoot `
            -Finding "Minimum password length is $($policy.MinPasswordLength)." `
            -Recommendation "Raise the minimum to at least 14 characters, or deploy a passphrase policy with banned-password filtering. Length defeats offline cracking far more effectively than complexity rules do."
    }

    if (-not $policy.ComplexityEnabled) {
        Add-Finding -Severity "High" -Category "DomainConfiguration" -Check "WeakPasswordPolicy" `
            -AffectedObject $domain.DNSRoot `
            -Finding "Password complexity is disabled." `
            -Recommendation "Enable complexity, or compensate with a substantially longer minimum length plus a banned-password list."
    }

    if ($policy.ReversibleEncryptionEnabled) {
        Add-Finding -Severity "Critical" -Category "DomainConfiguration" -Check "ReversibleEncryptionDomainWide" `
            -AffectedObject $domain.DNSRoot `
            -Finding "Reversible password encryption is enabled for the entire domain." `
            -Recommendation "Disable this immediately and force a domain-wide password reset. Every password is currently recoverable in plaintext."
    }

    if ($policy.LockoutThreshold -eq 0) {
        Add-Finding -Severity "Medium" -Category "DomainConfiguration" -Check "NoAccountLockout" `
            -AffectedObject $domain.DNSRoot `
            -Finding "Account lockout is disabled (threshold 0)." `
            -Recommendation "Set a lockout threshold, for example 10 attempts with a 15-minute window. Without one, online password spraying is unlimited. Balance against the denial-of-service risk of an over-aggressive threshold."
    }
}

Invoke-Check -Name "Domain and forest functional level" -Body {
    $domainMode = [string]$domain.DomainMode
    $legacyModes = @("Windows2000Domain", "Windows2003Domain", "Windows2003InterimDomain", "Windows2008Domain", "Windows2008R2Domain")

    if ($legacyModes -contains $domainMode) {
        Add-Finding -Severity "Medium" -Category "DomainConfiguration" -Check "LegacyFunctionalLevel" `
            -AffectedObject $domain.DNSRoot `
            -Finding "Domain functional level is $domainMode." `
            -Recommendation "Raise the functional level. Levels below Windows Server 2012 block Protected Users, authentication policy silos, and Group Managed Service Accounts, all of which are primary defences against credential theft."
    }
    else {
        Add-Finding -Severity "Info" -Category "DomainConfiguration" -Check "LegacyFunctionalLevel" `
            -AffectedObject $domain.DNSRoot -Finding "Domain functional level is $domainMode." `
            -Recommendation "No action required."
    }
}

Invoke-Check -Name "AD Recycle Bin" -Body {
    try {
        $forest = Get-ADForest @adParams
        $recycleBin = Get-ADOptionalFeature -Filter 'Name -like "Recycle Bin Feature"' @adParams

        $enabled = $false
        if ($recycleBin -and @($recycleBin.EnabledScopes).Count -gt 0) { $enabled = $true }

        if (-not $enabled) {
            Add-Finding -Severity "Medium" -Category "DomainConfiguration" -Check "RecycleBinDisabled" `
                -AffectedObject $forest.Name `
                -Finding "The Active Directory Recycle Bin is not enabled." `
                -Recommendation "Enable it. Without the Recycle Bin, recovering a deleted OU or user requires an authoritative restore from backup. Enabling it is irreversible, which is the only real consideration."
        }
        else {
            Add-Finding -Severity "Info" -Category "DomainConfiguration" -Check "RecycleBinDisabled" `
                -AffectedObject $forest.Name -Finding "The AD Recycle Bin is enabled." `
                -Recommendation "No action required."
        }
    }
    catch {
        throw
    }
}

Invoke-Check -Name "Pre-Windows 2000 Compatible Access" -Body {
    $group = $null
    try { $group = Get-ADGroup -Identity "S-1-5-32-554" @adParams -ErrorAction Stop } catch { return }

    $members = @()
    try { $members = @(Get-ADGroupMember -Identity $group @adParams -ErrorAction Stop) } catch { return }

    $risky = @($members | Where-Object {
        $_.SID.Value -eq "S-1-1-0" -or      # Everyone
        $_.SID.Value -eq "S-1-5-7" -or      # Anonymous Logon
        $_.SID.Value -eq "S-1-5-11"         # Authenticated Users
    })

    foreach ($member in $risky) {
        Add-Finding -Severity "High" -Category "DomainConfiguration" -Check "PreWindows2000CompatibleAccess" `
            -AffectedObject $member.Name `
            -Finding "Pre-Windows 2000 Compatible Access contains '$($member.Name)'." `
            -Recommendation "Remove this member. The group grants broad read access across the directory, and including Everyone or Anonymous Logon enables unauthenticated enumeration of users and groups."
    }
}

Invoke-Check -Name "LAPS deployment" -Body {
    $schemaNc = (Get-ADRootDSE @adParams).schemaNamingContext

    $legacyLaps = @(Get-ADObject -Filter 'name -eq "ms-Mcs-AdmPwd"' -SearchBase $schemaNc @adParams -ErrorAction SilentlyContinue)
    $windowsLaps = @(Get-ADObject -Filter 'name -eq "ms-LAPS-Password"' -SearchBase $schemaNc @adParams -ErrorAction SilentlyContinue)

    if ($legacyLaps.Count -eq 0 -and $windowsLaps.Count -eq 0) {
        Add-Finding -Severity "High" -Category "DomainConfiguration" -Check "LapsNotDeployed" `
            -AffectedObject $domain.DNSRoot `
            -Finding "Neither legacy LAPS nor Windows LAPS is present in the schema." `
            -Recommendation "Deploy Windows LAPS. Without it, local Administrator passwords are typically identical across machines, so compromising one workstation yields local admin on all of them and enables lateral movement across the estate."
    }
    else {
        $which = if ($windowsLaps.Count -gt 0) { "Windows LAPS" } else { "legacy LAPS" }
        Add-Finding -Severity "Info" -Category "DomainConfiguration" -Check "LapsNotDeployed" `
            -AffectedObject $domain.DNSRoot `
            -Finding "$which is present in the schema." `
            -Recommendation "Confirm it is actually applied by policy and that passwords are rotating, not merely that the schema is extended."
    }
}

Invoke-Check -Name "Stale computer accounts" -Body {
    $cutoff = $now.AddDays(-$StaleDays)

    $stale = @($allComputers | Where-Object {
        $_.Enabled -eq $true -and
        $null -ne $_.LastLogonDate -and
        $_.LastLogonDate -lt $cutoff
    })

    foreach ($computer in $stale) {
        $days = [int]($now - $computer.LastLogonDate).TotalDays
        Add-Finding -Severity "Low" -Category "IdentityHygiene" -Check "StaleComputerAccount" `
            -AffectedObject $computer.Name `
            -Finding "Enabled computer account has not authenticated for $days days." `
            -Detail "OS: $($computer.OperatingSystem), last logon: $($computer.LastLogonDate)" `
            -Recommendation "Disable and then delete decommissioned computer accounts. A stale account with a known password is a usable foothold."
    }
}

Invoke-Check -Name "Unsupported operating systems" -Body {
    $unsupportedPatterns = @("Windows 2000", "Windows XP", "Windows Server 2003", "Windows Vista",
        "Windows 7", "Windows Server 2008", "Windows 8", "Windows Server 2012")

    foreach ($computer in $allComputers) {
        if (-not $computer.Enabled) { continue }
        $os = Get-AkPropertyValue -InputObject $computer -Name "OperatingSystem" -Default ""
        if ([string]::IsNullOrWhiteSpace($os)) { continue }

        $match = @($unsupportedPatterns | Where-Object { $os -like "*$_*" })
        if ($match.Count -eq 0) { continue }

        Add-Finding -Severity "High" -Category "DomainConfiguration" -Check "UnsupportedOperatingSystem" `
            -AffectedObject $computer.Name `
            -Finding "Computer runs $os, which is out of support." `
            -Detail "Last logon: $($computer.LastLogonDate)" `
            -Recommendation "Upgrade, isolate, or decommission this machine. Out-of-support systems receive no security updates and frequently still permit SMBv1 and NTLMv1."
    }
}

Invoke-Check -Name "SID history" -Body {
    $withSidHistory = @($allUsers | Where-Object {
        $null -ne (Get-AkPropertyValue -InputObject $_ -Name "SIDHistory") -and
        @(Get-AkPropertyValue -InputObject $_ -Name "SIDHistory" -Default @()).Count -gt 0
    })

    foreach ($user in $withSidHistory) {
        Add-Finding -Severity "Medium" -Category "Privilege" -Check "SidHistoryPresent" `
            -AffectedObject $user.SamAccountName `
            -Finding "Account carries SID history from a previous domain." `
            -Detail "Entries: $(@(Get-AkPropertyValue -InputObject $user -Name 'SIDHistory' -Default @()).Count)" `
            -Recommendation "SID history is legitimate during a migration and should be cleaned up once it completes. Left in place it hides effective privilege, and an injected SID history entry is a well-known persistence technique. Verify each entry corresponds to a real migrated account."
    }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$minimumRank = $severityRank[$MinimumSeverity]
$reported = @($findings | Where-Object { $_.SeverityRank -ge $minimumRank } | Sort-Object -Property SeverityRank -Descending)

$csvPath = Join-Path -Path $OutputPath -ChildPath "AdSecurityScan-$(Get-AkSafeName -Value $domain.DNSRoot)-$timestamp.csv"
[void](Export-AkCsv -InputObject $reported -Path $csvPath)

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  RESULTS" -ForegroundColor Cyan
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
$topFindings = @($reported | Where-Object { $_.Severity -eq "Critical" -or $_.Severity -eq "High" })

if ($topFindings.Count -gt 0) {
    Write-Host "  Highest priority:" -ForegroundColor Red
    foreach ($group in ($topFindings | Group-Object Check | Sort-Object Count -Descending | Select-Object -First 10)) {
        Write-Host ("    {0,-34} {1} object(s)" -f $group.Name, $group.Count) -ForegroundColor Red
    }
    Write-Host ""
}

Write-AkLog -Message "Findings written to $csvPath" -Level Success

if ($HtmlReport) {
    $htmlPath = Join-Path -Path $OutputPath -ChildPath "AdSecurityScan-$(Get-AkSafeName -Value $domain.DNSRoot)-$timestamp.html"

    # Load before the encoder is used below, not after.
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    $rows = foreach ($finding in $reported) {
        $rowClass = "sev-" + $finding.Severity.ToLowerInvariant()
        "<tr class='$rowClass'>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Severity))</td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Category))</td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Check))</td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($finding.AffectedObject))</td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Finding))</td>" +
        "<td>$([System.Web.HttpUtility]::HtmlEncode($finding.Recommendation))</td>" +
        "</tr>"
    }

    $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AD Security Scan - $($domain.DNSRoot)</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #1a1a1a; }
h1 { font-size: 1.5rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.85rem; }
th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; vertical-align: top; }
th { background: #f0f0f0; position: sticky; top: 0; }
.sev-critical td:first-child { background: #b00020; color: #fff; font-weight: bold; }
.sev-high td:first-child { background: #e65100; color: #fff; font-weight: bold; }
.sev-medium td:first-child { background: #f9a825; }
.sev-low td:first-child { background: #fff59d; }
.sev-info td:first-child { background: #e0e0e0; }
</style></head><body>
<h1>Active Directory Security Scan</h1>
<p><strong>Domain:</strong> $($domain.DNSRoot)<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Findings:</strong> $($reported.Count)</p>
<table>
<tr><th>Severity</th><th>Category</th><th>Check</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
$($rows -join "`n")
</table>
</body></html>
"@

    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
    Write-AkLog -Message "HTML report written to $htmlPath" -Level Success
}

Write-Host ""
Stop-AkLog

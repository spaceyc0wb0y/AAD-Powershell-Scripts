<#
.SYNOPSIS
Exports an Active Directory domain into a self-contained, offline package that
can be rebuilt in a different domain.

.DESCRIPTION
Run this on, or against, the OLD domain controller. It collects everything
needed to recreate the environment in a new forest with a new domain name:

- Domain facts, UPN suffixes, and password policies
- The organizational unit tree, including gPLink and gPOptions
- Users, with the attributes that matter for an Entra hybrid sync
- Groups, group membership, and primary group assignments
- Group Policy Objects: full Backup-GPO backups, XML reports, links, WMI filters
- File server shares, share permissions, and NTFS ACLs

Everything is written into ONE timestamped package folder with a manifest,
because the only supported transport to the new domain is a copy of that folder.
No trust, no replication, and no connectivity between the two domains is
required or used.

This script is READ ONLY against Active Directory. It creates files locally and
never modifies the source domain.

IMPORTANT: the resulting package contains a full description of your directory
and file server permissions. Treat it as a credential-grade secret. It is
excluded from git by the repository .gitignore.

.PARAMETER Server
Domain controller to read from. Defaults to the current domain's preferred DC.

.PARAMETER Credential
Optional credentials for reading the source domain.

.PARAMETER OutputPath
Parent folder in which the timestamped package folder is created.

.PARAMETER Include
Sections to export. Defaults to All.

.PARAMETER SearchBase
Optional distinguished name to limit the user, group, computer, and OU export to
one subtree. GPO export is not affected by this.

.PARAMETER FileServer
One or more servers whose SMB shares and NTFS ACLs should be captured. Defaults
to the local computer when the Shares section is included.

.PARAMETER ExcludeSharePath
Share names to skip when capturing shares. Administrative shares, SYSVOL, and
NETLOGON are always skipped.

.PARAMETER AclDepth
How many folder levels below each share root to capture NTFS ACLs for. 0 captures
only the share root. Higher values are much slower on large file servers.

.PARAMETER IncludeInheritedAcl
Capture inherited ACEs as well as explicit ones. Off by default because only
explicit ACEs need to be recreated.

.PARAMETER IncludeDisabledUsers
Include disabled user accounts in the export. On by default so the package is a
true backup; the import script decides separately whether to recreate them.

.EXAMPLE
.\Export-AdEnvironment.ps1 -OutputPath D:\Migration

.EXAMPLE
.\Export-AdEnvironment.ps1 -OutputPath D:\Migration -FileServer FS01,FS02 -AclDepth 2

.EXAMPLE
.\Export-AdEnvironment.ps1 -OutputPath D:\Migration -Include Domain,Users,Groups

.NOTES
Requires the ActiveDirectory and GroupPolicy modules (RSAT).
Target runtime is Windows PowerShell 5.1 on Windows Server.
#>

[CmdletBinding()]
param(
    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "AdExport"),

    [ValidateSet("All", "Domain", "OrganizationalUnits", "Users", "Groups", "Computers", "Gpo", "Shares")]
    [string[]]$Include = @("All"),

    [string]$SearchBase,

    [string[]]$FileServer,

    [string[]]$ExcludeSharePath,

    [ValidateRange(0, 10)]
    [int]$AclDepth = 1,

    [switch]$IncludeInheritedAcl,

    [bool]$IncludeDisabledUsers = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

$sectionsRequested = @($Include)
function Test-Section {
    param([Parameter(Mandatory)][string]$Name)
    return ($sectionsRequested -contains "All" -or $sectionsRequested -contains $Name)
}

# Common splat for every AD cmdlet so -Server and -Credential flow everywhere.
$adParams = @{}
if (-not [string]::IsNullOrWhiteSpace($Server)) { $adParams["Server"] = $Server }
if ($Credential) { $adParams["Credential"] = $Credential }

Assert-AkModule -Name "ActiveDirectory" -Reason "Directory objects are read with the AD cmdlets."
if (Test-Section -Name "Gpo") {
    Assert-AkModule -Name "GroupPolicy" -Reason "Group Policy backup requires the GroupPolicy module."
}

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  AD ENVIRONMENT EXPORT" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Package setup
# ---------------------------------------------------------------------------

$domain = Get-ADDomain @adParams
$forest = $null
try {
    $forest = Get-ADForest @adParams
}
catch {
    Write-Warning "Could not read forest information: $($_.Exception.Message)"
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$packageName = "AdExport-" + (Get-AkSafeName -Value $domain.DNSRoot) + "-$timestamp"
$packagePath = Join-Path -Path $OutputPath -ChildPath $packageName

New-Item -Path $packagePath -ItemType Directory -Force | Out-Null
$logPath = Join-Path -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item LogFolder) -ChildPath "export.log"
Start-AkLog -Path $logPath

Write-AkLog -Message "Source domain : $($domain.DNSRoot) ($($domain.NetBIOSName))" -Level Info
Write-AkLog -Message "Domain DN     : $($domain.DistinguishedName)" -Level Info
Write-AkLog -Message "Domain SID    : $($domain.DomainSID.Value)" -Level Info
Write-AkLog -Message "Package       : $packagePath" -Level Info
Write-AkLog -Message "Sections      : $($sectionsRequested -join ', ')" -Level Info

$counts = @{}
$exportedSections = New-Object System.Collections.Generic.List[string]

# Scope splat for subtree-limited exports.
$scopeParams = @{}
if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    $scopeParams["SearchBase"] = $SearchBase
    Write-AkLog -Message "Scope limited to subtree: $SearchBase" -Level Warning
}

# ---------------------------------------------------------------------------
# Section: Domain
# ---------------------------------------------------------------------------

if (Test-Section -Name "Domain") {
    Write-AkLog -Message "Exporting domain configuration..." -Level Step

    $upnSuffixes = @()
    if ($forest) {
        $upnSuffixes = @($forest.UPNSuffixes)
    }

    $domainInfo = [pscustomobject]@{
        DnsRoot                    = $domain.DNSRoot
        NetBiosName                = $domain.NetBIOSName
        DistinguishedName          = $domain.DistinguishedName
        DomainSid                  = $domain.DomainSID.Value
        DomainMode                 = [string]$domain.DomainMode
        ForestName                 = if ($forest) { $forest.Name } else { $null }
        ForestMode                 = if ($forest) { [string]$forest.ForestMode } else { $null }
        UpnSuffixes                = ConvertTo-AkMultiValue -Value $upnSuffixes
        UsersContainer             = $domain.UsersContainer
        ComputersContainer         = $domain.ComputersContainer
        DomainControllersContainer = $domain.DomainControllersContainer
        InfrastructureMaster       = $domain.InfrastructureMaster
        PdcEmulator                = $domain.PDCEmulator
        RidMaster                  = $domain.RIDMaster
    }

    [void](Save-AkJson -InputObject $domainInfo -Depth 5 `
        -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item DomainInfo))

    $passwordPolicy = Get-ADDefaultDomainPasswordPolicy @adParams
    $passwordPolicyInfo = [pscustomobject]@{
        ComplexityEnabled           = $passwordPolicy.ComplexityEnabled
        LockoutDuration             = [string]$passwordPolicy.LockoutDuration
        LockoutObservationWindow    = [string]$passwordPolicy.LockoutObservationWindow
        LockoutThreshold            = $passwordPolicy.LockoutThreshold
        MaxPasswordAge              = [string]$passwordPolicy.MaxPasswordAge
        MinPasswordAge              = [string]$passwordPolicy.MinPasswordAge
        MinPasswordLength           = $passwordPolicy.MinPasswordLength
        PasswordHistoryCount        = $passwordPolicy.PasswordHistoryCount
        ReversibleEncryptionEnabled = $passwordPolicy.ReversibleEncryptionEnabled
    }
    [void](Save-AkJson -InputObject $passwordPolicyInfo -Depth 4 `
        -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item DomainPasswordPolicy))

    $fgpp = @()
    try {
        $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * @adParams | ForEach-Object {
            [pscustomobject]@{
                Name                        = $_.Name
                Precedence                  = $_.Precedence
                MinPasswordLength           = $_.MinPasswordLength
                PasswordHistoryCount        = $_.PasswordHistoryCount
                ComplexityEnabled           = $_.ComplexityEnabled
                ReversibleEncryptionEnabled = $_.ReversibleEncryptionEnabled
                LockoutThreshold            = $_.LockoutThreshold
                LockoutDuration             = [string]$_.LockoutDuration
                LockoutObservationWindow    = [string]$_.LockoutObservationWindow
                MaxPasswordAge              = [string]$_.MaxPasswordAge
                MinPasswordAge              = [string]$_.MinPasswordAge
                AppliesTo                   = ConvertTo-AkMultiValue -Value $_.AppliesTo
            }
        })
    }
    catch {
        Write-AkLog -Message "Could not read fine-grained password policies: $($_.Exception.Message)" -Level Warning
    }

    [void](Export-AkCsv -InputObject $fgpp -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item FineGrainedPolicies))

    $counts["FineGrainedPasswordPolicies"] = $fgpp.Count
    $exportedSections.Add("Domain")
    Write-AkLog -Message "Domain configuration exported. Fine-grained policies: $($fgpp.Count)" -Level Success
}

# ---------------------------------------------------------------------------
# Section: Organizational units
# ---------------------------------------------------------------------------

$domainRootLinks = @()

if (Test-Section -Name "OrganizationalUnits") {
    Write-AkLog -Message "Exporting organizational unit tree..." -Level Step

    $ouProperties = @("Description", "gPLink", "gPOptions", "ManagedBy", "ProtectedFromAccidentalDeletion",
        "City", "State", "Country", "PostalCode", "StreetAddress")

    $ous = @(Get-ADOrganizationalUnit -Filter * -Properties $ouProperties @adParams @scopeParams)

    $ouRecords = foreach ($ou in ($ous | Sort-Object { Get-AkDnDepth -DistinguishedName $_.DistinguishedName }, DistinguishedName)) {
        [pscustomobject]@{
            Name                            = $ou.Name
            DistinguishedName               = $ou.DistinguishedName
            ParentDn                        = Get-AkParentDn -DistinguishedName $ou.DistinguishedName
            Depth                           = Get-AkDnDepth -DistinguishedName $ou.DistinguishedName
            Description                     = Get-AkPropertyValue -InputObject $ou -Name "Description"
            ManagedBy                       = Get-AkPropertyValue -InputObject $ou -Name "ManagedBy"
            ProtectedFromAccidentalDeletion = Get-AkPropertyValue -InputObject $ou -Name "ProtectedFromAccidentalDeletion" -Default $false
            GpOptions                       = Get-AkPropertyValue -InputObject $ou -Name "gPOptions" -Default 0
            GpLink                          = Get-AkPropertyValue -InputObject $ou -Name "gPLink"
            City                            = Get-AkPropertyValue -InputObject $ou -Name "City"
            State                           = Get-AkPropertyValue -InputObject $ou -Name "State"
            Country                         = Get-AkPropertyValue -InputObject $ou -Name "Country"
            PostalCode                      = Get-AkPropertyValue -InputObject $ou -Name "PostalCode"
            StreetAddress                   = Get-AkPropertyValue -InputObject $ou -Name "StreetAddress"
        }
    }

    [void](Export-AkCsv -InputObject @($ouRecords) -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item OrganizationalUnits))

    # The domain root can carry links too, most importantly Default Domain Policy.
    $rootObject = Get-ADObject -Identity $domain.DistinguishedName -Properties gPLink, gPOptions @adParams
    $domainRootLinks = @(ConvertFrom-AkGpLink -GpLink (Get-AkPropertyValue -InputObject $rootObject -Name "gPLink") `
        -TargetDn $domain.DistinguishedName -TargetType "Domain")

    $counts["OrganizationalUnits"] = @($ouRecords).Count
    $exportedSections.Add("OrganizationalUnits")
    Write-AkLog -Message "Organizational units exported: $(@($ouRecords).Count)" -Level Success
}

# ---------------------------------------------------------------------------
# Section: Users
# ---------------------------------------------------------------------------

if (Test-Section -Name "Users") {
    Write-AkLog -Message "Exporting users..." -Level Step

    # Explicit list rather than -Properties * so the export schema is stable and
    # every column below is guaranteed to exist on the returned object.
    $userProperties = @(
        "SamAccountName", "UserPrincipalName", "DisplayName", "GivenName", "Surname", "Initials",
        "Description", "EmailAddress", "proxyAddresses", "mailNickname", "Enabled", "DistinguishedName",
        "employeeID", "employeeNumber", "employeeType", "Title", "Department", "Company", "Division",
        "Office", "physicalDeliveryOfficeName", "OfficePhone", "MobilePhone", "HomePhone", "Fax", "ipPhone",
        "StreetAddress", "City", "State", "PostalCode", "Country", "co",
        "Manager", "PasswordNeverExpires", "CannotChangePassword", "PasswordNotRequired",
        "SmartcardLogonRequired", "TrustedForDelegation", "AccountNotDelegated", "AccountExpirationDate",
        "HomeDirectory", "HomeDrive", "ProfilePath", "ScriptPath", "primaryGroupID",
        "extensionAttribute1", "extensionAttribute2", "extensionAttribute3",
        "otherTelephone", "url", "wWWHomePage", "info", "ObjectGUID", "SID",
        "whenCreated", "LastLogonDate", "PasswordLastSet", "AdminCount", "ServicePrincipalNames", "UserType"
    )

    $userFilter = "*"
    if (-not $IncludeDisabledUsers) {
        $userFilter = "Enabled -eq 'True'"
    }

    $users = @(Get-ADUser -Filter $userFilter -Properties $userProperties @adParams @scopeParams)

    $userRecords = foreach ($user in $users) {
        [pscustomobject]@{
            SamAccountName           = $user.SamAccountName
            UserPrincipalName        = Get-AkPropertyValue -InputObject $user -Name "UserPrincipalName"
            DisplayName              = Get-AkPropertyValue -InputObject $user -Name "DisplayName"
            GivenName                = Get-AkPropertyValue -InputObject $user -Name "GivenName"
            Surname                  = Get-AkPropertyValue -InputObject $user -Name "Surname"
            Initials                 = Get-AkPropertyValue -InputObject $user -Name "Initials"
            Description              = Get-AkPropertyValue -InputObject $user -Name "Description"
            EmailAddress             = Get-AkPropertyValue -InputObject $user -Name "EmailAddress"
            ProxyAddresses           = ConvertTo-AkMultiValue -Value (Get-AkPropertyValue -InputObject $user -Name "proxyAddresses" -Default @())
            MailNickname             = Get-AkPropertyValue -InputObject $user -Name "mailNickname"
            Enabled                  = $user.Enabled
            DistinguishedName        = $user.DistinguishedName
            ParentDn                 = Get-AkParentDn -DistinguishedName $user.DistinguishedName
            SourceObjectGuid         = [string]$user.ObjectGUID
            SourceSid                = [string]$user.SID
            SourceRid                = Get-AkSidRid -Sid ([string]$user.SID)
            EmployeeId               = Get-AkPropertyValue -InputObject $user -Name "employeeID"
            EmployeeNumber           = Get-AkPropertyValue -InputObject $user -Name "employeeNumber"
            EmployeeType             = Get-AkPropertyValue -InputObject $user -Name "employeeType"
            Title                    = Get-AkPropertyValue -InputObject $user -Name "Title"
            Department               = Get-AkPropertyValue -InputObject $user -Name "Department"
            Company                  = Get-AkPropertyValue -InputObject $user -Name "Company"
            Division                 = Get-AkPropertyValue -InputObject $user -Name "Division"
            Office                   = Get-AkPropertyValue -InputObject $user -Name "Office"
            OfficePhone              = Get-AkPropertyValue -InputObject $user -Name "OfficePhone"
            MobilePhone              = Get-AkPropertyValue -InputObject $user -Name "MobilePhone"
            HomePhone                = Get-AkPropertyValue -InputObject $user -Name "HomePhone"
            Fax                      = Get-AkPropertyValue -InputObject $user -Name "Fax"
            IpPhone                  = Get-AkPropertyValue -InputObject $user -Name "ipPhone"
            StreetAddress            = Get-AkPropertyValue -InputObject $user -Name "StreetAddress"
            City                     = Get-AkPropertyValue -InputObject $user -Name "City"
            State                    = Get-AkPropertyValue -InputObject $user -Name "State"
            PostalCode               = Get-AkPropertyValue -InputObject $user -Name "PostalCode"
            Country                  = Get-AkPropertyValue -InputObject $user -Name "Country"
            Manager                  = Get-AkPropertyValue -InputObject $user -Name "Manager"
            PasswordNeverExpires     = Get-AkPropertyValue -InputObject $user -Name "PasswordNeverExpires" -Default $false
            CannotChangePassword     = Get-AkPropertyValue -InputObject $user -Name "CannotChangePassword" -Default $false
            PasswordNotRequired      = Get-AkPropertyValue -InputObject $user -Name "PasswordNotRequired" -Default $false
            SmartcardLogonRequired   = Get-AkPropertyValue -InputObject $user -Name "SmartcardLogonRequired" -Default $false
            TrustedForDelegation     = Get-AkPropertyValue -InputObject $user -Name "TrustedForDelegation" -Default $false
            AccountNotDelegated      = Get-AkPropertyValue -InputObject $user -Name "AccountNotDelegated" -Default $false
            AccountExpirationDate    = Get-AkPropertyValue -InputObject $user -Name "AccountExpirationDate"
            HomeDirectory            = Get-AkPropertyValue -InputObject $user -Name "HomeDirectory"
            HomeDrive                = Get-AkPropertyValue -InputObject $user -Name "HomeDrive"
            ProfilePath              = Get-AkPropertyValue -InputObject $user -Name "ProfilePath"
            ScriptPath               = Get-AkPropertyValue -InputObject $user -Name "ScriptPath"
            PrimaryGroupId           = Get-AkPropertyValue -InputObject $user -Name "primaryGroupID" -Default 513
            ExtensionAttribute1      = Get-AkPropertyValue -InputObject $user -Name "extensionAttribute1"
            ExtensionAttribute2      = Get-AkPropertyValue -InputObject $user -Name "extensionAttribute2"
            ExtensionAttribute3      = Get-AkPropertyValue -InputObject $user -Name "extensionAttribute3"
            Url                      = Get-AkPropertyValue -InputObject $user -Name "wWWHomePage"
            Notes                    = Get-AkPropertyValue -InputObject $user -Name "info"
            ServicePrincipalNames    = ConvertTo-AkMultiValue -Value (Get-AkPropertyValue -InputObject $user -Name "ServicePrincipalNames" -Default @())
            AdminCount               = Get-AkPropertyValue -InputObject $user -Name "AdminCount" -Default 0
            WhenCreated              = Get-AkPropertyValue -InputObject $user -Name "whenCreated"
            LastLogonDate            = Get-AkPropertyValue -InputObject $user -Name "LastLogonDate"
            PasswordLastSet          = Get-AkPropertyValue -InputObject $user -Name "PasswordLastSet"
        }
    }

    [void](Export-AkCsv -InputObject @($userRecords) -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item Users))

    $counts["Users"] = @($userRecords).Count
    $counts["UsersEnabled"] = @($userRecords | Where-Object { $_.Enabled }).Count
    $exportedSections.Add("Users")
    Write-AkLog -Message "Users exported: $(@($userRecords).Count)" -Level Success
}

# ---------------------------------------------------------------------------
# Section: Groups and membership
# ---------------------------------------------------------------------------

if (Test-Section -Name "Groups") {
    Write-AkLog -Message "Exporting groups and membership..." -Level Step

    $groupProperties = @("Description", "GroupCategory", "GroupScope", "ManagedBy", "mail",
        "proxyAddresses", "info", "member", "DistinguishedName", "ObjectGUID", "SID", "AdminCount")

    $groups = @(Get-ADGroup -Filter * -Properties $groupProperties @adParams @scopeParams)

    $wellKnownRids = Get-AkWellKnownRidMap
    $groupRecords = New-Object System.Collections.Generic.List[object]
    $memberRecords = New-Object System.Collections.Generic.List[object]

    foreach ($group in $groups) {
        $sid = [string]$group.SID
        $rid = Get-AkSidRid -Sid $sid
        $wellKnownName = $null
        if ($rid -and $wellKnownRids.ContainsKey($rid)) {
            $wellKnownName = $wellKnownRids[$rid]
        }

        $groupRecords.Add([pscustomobject]@{
            SamAccountName    = $group.SamAccountName
            Name              = $group.Name
            DisplayName       = Get-AkPropertyValue -InputObject $group -Name "DisplayName"
            Description       = Get-AkPropertyValue -InputObject $group -Name "Description"
            GroupCategory     = [string]$group.GroupCategory
            GroupScope        = [string]$group.GroupScope
            DistinguishedName = $group.DistinguishedName
            ParentDn          = Get-AkParentDn -DistinguishedName $group.DistinguishedName
            ManagedBy         = Get-AkPropertyValue -InputObject $group -Name "ManagedBy"
            Mail              = Get-AkPropertyValue -InputObject $group -Name "mail"
            ProxyAddresses    = ConvertTo-AkMultiValue -Value (Get-AkPropertyValue -InputObject $group -Name "proxyAddresses" -Default @())
            Notes             = Get-AkPropertyValue -InputObject $group -Name "info"
            SourceObjectGuid  = [string]$group.ObjectGUID
            SourceSid         = $sid
            SourceRid         = $rid
            # Built-in group names are locale dependent, so the RID label is what
            # the import matches on, never the display name.
            WellKnownRidName  = $wellKnownName
            IsBuiltIn         = (Test-AkIsBuiltInSid -Sid $sid) -or ($null -ne $wellKnownName)
            AdminCount        = Get-AkPropertyValue -InputObject $group -Name "AdminCount" -Default 0
            MemberCount       = @(Get-AkPropertyValue -InputObject $group -Name "member" -Default @()).Count
        })

        # Read the raw 'member' attribute rather than calling Get-ADGroupMember.
        # Get-ADGroupMember resolves each member and throws on foreign security
        # principals and orphaned SIDs, which are exactly what a domain being
        # retired tends to accumulate.
        foreach ($memberDn in @(Get-AkPropertyValue -InputObject $group -Name "member" -Default @())) {
            $memberRecords.Add([pscustomobject]@{
                GroupSamAccountName = $group.SamAccountName
                GroupDn             = $group.DistinguishedName
                GroupWellKnownRid   = $wellKnownName
                MemberDn            = $memberDn
                MemberIsForeign     = ($memberDn -like "*CN=ForeignSecurityPrincipals,*")
            })
        }
    }

    [void](Export-AkCsv -InputObject $groupRecords.ToArray() -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item Groups))
    [void](Export-AkCsv -InputObject $memberRecords.ToArray() -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item GroupMembers))

    $counts["Groups"] = $groupRecords.Count
    $counts["GroupMemberships"] = $memberRecords.Count
    $exportedSections.Add("Groups")
    Write-AkLog -Message "Groups exported: $($groupRecords.Count), memberships: $($memberRecords.Count)" -Level Success
}

# ---------------------------------------------------------------------------
# Section: Computers (inventory only, not recreated by the import)
# ---------------------------------------------------------------------------

if (Test-Section -Name "Computers") {
    Write-AkLog -Message "Exporting computer inventory..." -Level Step

    $computerProperties = @("OperatingSystem", "OperatingSystemVersion", "Description", "DNSHostName",
        "Enabled", "LastLogonDate", "whenCreated", "IPv4Address", "ManagedBy", "TrustedForDelegation",
        "msDS-AllowedToDelegateTo", "ServicePrincipalNames")

    $computers = @(Get-ADComputer -Filter * -Properties $computerProperties @adParams @scopeParams)

    $computerRecords = foreach ($computer in $computers) {
        [pscustomobject]@{
            Name                   = $computer.Name
            DnsHostName            = Get-AkPropertyValue -InputObject $computer -Name "DNSHostName"
            DistinguishedName      = $computer.DistinguishedName
            ParentDn               = Get-AkParentDn -DistinguishedName $computer.DistinguishedName
            Enabled                = $computer.Enabled
            OperatingSystem        = Get-AkPropertyValue -InputObject $computer -Name "OperatingSystem"
            OperatingSystemVersion = Get-AkPropertyValue -InputObject $computer -Name "OperatingSystemVersion"
            Description            = Get-AkPropertyValue -InputObject $computer -Name "Description"
            IPv4Address            = Get-AkPropertyValue -InputObject $computer -Name "IPv4Address"
            ManagedBy              = Get-AkPropertyValue -InputObject $computer -Name "ManagedBy"
            TrustedForDelegation   = Get-AkPropertyValue -InputObject $computer -Name "TrustedForDelegation" -Default $false
            LastLogonDate          = Get-AkPropertyValue -InputObject $computer -Name "LastLogonDate"
            WhenCreated            = Get-AkPropertyValue -InputObject $computer -Name "whenCreated"
            ServicePrincipalNames  = ConvertTo-AkMultiValue -Value (Get-AkPropertyValue -InputObject $computer -Name "ServicePrincipalNames" -Default @())
        }
    }

    [void](Export-AkCsv -InputObject @($computerRecords) -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item Computers))

    $counts["Computers"] = @($computerRecords).Count
    $exportedSections.Add("Computers")
    Write-AkLog -Message "Computers exported: $(@($computerRecords).Count). Note: computers are inventory only and are not recreated by the import; workstations must be rejoined to the new domain." -Level Success
}

# ---------------------------------------------------------------------------
# Section: Group Policy
# ---------------------------------------------------------------------------

if (Test-Section -Name "Gpo") {
    Write-AkLog -Message "Exporting Group Policy Objects..." -Level Step

    $gpoParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $gpoParams["Server"] = $Server }
    $gpoDomainParams = $gpoParams.Clone()
    $gpoDomainParams["Domain"] = $domain.DNSRoot

    $backupFolder = Get-AkPackageItemPath -PackagePath $packagePath -Item GpoBackupFolder
    $reportFolder = Get-AkPackageItemPath -PackagePath $packagePath -Item GpoReportFolder
    New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
    New-Item -Path $reportFolder -ItemType Directory -Force | Out-Null

    $allGpos = @(Get-GPO -All @gpoDomainParams)
    Write-AkLog -Message "Found $($allGpos.Count) GPOs. Running Backup-GPO..." -Level Info

    $backups = @(Backup-GPO -All -Path $backupFolder @gpoDomainParams)

    # Map GPO id to the BackupId that Import-GPO will need.
    $backupById = @{}
    foreach ($backup in $backups) {
        $backupById[[string]$backup.GpoId] = [string]$backup.Id
    }

    $gpoRecords = New-Object System.Collections.Generic.List[object]

    foreach ($gpo in $allGpos) {
        $gpoIdText = [string]$gpo.Id
        $safeName = Get-AkSafeName -Value $gpo.DisplayName

        $backupId = $null
        if ($backupById.ContainsKey($gpoIdText)) {
            $backupId = $backupById[$gpoIdText]
        }
        else {
            Write-AkLog -Message "No backup was produced for GPO '$($gpo.DisplayName)'. It will not be importable." -Level Warning
        }

        # The XML report is what the post-import validation scan greps for
        # leftover references to the old domain.
        try {
            Get-GPOReport -Guid $gpo.Id -ReportType Xml @gpoDomainParams |
                Set-Content -LiteralPath (Join-Path -Path $reportFolder -ChildPath "$safeName.xml") -Encoding UTF8

            Get-GPOReport -Guid $gpo.Id -ReportType Html @gpoDomainParams |
                Set-Content -LiteralPath (Join-Path -Path $reportFolder -ChildPath "$safeName.html") -Encoding UTF8
        }
        catch {
            Write-AkLog -Message "Could not generate report for GPO '$($gpo.DisplayName)': $($_.Exception.Message)" -Level Warning
        }

        $wmiFilterName = $null
        $wmiFilter = Get-AkPropertyValue -InputObject $gpo -Name "WmiFilter"
        if ($wmiFilter) {
            $wmiFilterName = Get-AkPropertyValue -InputObject $wmiFilter -Name "Name"
        }

        $gpoRecords.Add([pscustomobject]@{
            DisplayName       = $gpo.DisplayName
            GpoId             = $gpoIdText
            BackupId          = $backupId
            SafeName          = $safeName
            Description       = Get-AkPropertyValue -InputObject $gpo -Name "Description"
            GpoStatus         = [string]$gpo.GpoStatus
            WmiFilterName     = $wmiFilterName
            CreationTime      = Get-AkPropertyValue -InputObject $gpo -Name "CreationTime"
            ModificationTime  = Get-AkPropertyValue -InputObject $gpo -Name "ModificationTime"
            UserVersion       = [string](Get-AkPropertyValue -InputObject $gpo -Name "UserVersion")
            ComputerVersion   = [string](Get-AkPropertyValue -InputObject $gpo -Name "ComputerVersion")
            ReportXmlFile     = "$safeName.xml"
        })
    }

    [void](Export-AkCsv -InputObject $gpoRecords.ToArray() -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item GpoInventory))

    # --- Links -------------------------------------------------------------
    # Import-GPO restores GPO *contents* only. Links, link order, enforcement,
    # and WMI filter associations are all lost unless captured separately here.
    $linkRecords = New-Object System.Collections.Generic.List[object]

    foreach ($link in $domainRootLinks) { $linkRecords.Add($link) }

    if (-not (Test-Section -Name "OrganizationalUnits")) {
        # Links still need the OU gPLink values even when the OU section was not
        # requested, so read them here.
        $rootObject = Get-ADObject -Identity $domain.DistinguishedName -Properties gPLink @adParams
        foreach ($link in (ConvertFrom-AkGpLink -GpLink (Get-AkPropertyValue -InputObject $rootObject -Name "gPLink") -TargetDn $domain.DistinguishedName -TargetType "Domain")) {
            $linkRecords.Add($link)
        }
    }

    $linkedOus = @(Get-ADOrganizationalUnit -Filter * -Properties gPLink, gPOptions @adParams @scopeParams)
    foreach ($ou in $linkedOus) {
        foreach ($link in (ConvertFrom-AkGpLink -GpLink (Get-AkPropertyValue -InputObject $ou -Name "gPLink") -TargetDn $ou.DistinguishedName -TargetType "OrganizationalUnit")) {
            $linkRecords.Add($link)
        }
    }

    # Site links live in the forest configuration partition and are captured for
    # reporting. They are not replayed by the import, because sites in the new
    # forest are a separate design decision.
    try {
        $configNc = (Get-ADRootDSE @adParams).configurationNamingContext
        $sites = @(Get-ADObject -Filter 'objectClass -eq "site"' -SearchBase "CN=Sites,$configNc" -Properties gPLink, Name @adParams)
        foreach ($site in $sites) {
            foreach ($link in (ConvertFrom-AkGpLink -GpLink (Get-AkPropertyValue -InputObject $site -Name "gPLink") -TargetDn $site.DistinguishedName -TargetType "Site")) {
                $linkRecords.Add($link)
            }
        }
    }
    catch {
        Write-AkLog -Message "Could not enumerate site GPO links: $($_.Exception.Message)" -Level Warning
    }

    # Resolve each link to its GPO display name so the import does not have to
    # depend on source GUIDs surviving.
    $gpoNameById = @{}
    foreach ($record in $gpoRecords) { $gpoNameById[$record.GpoId.ToLowerInvariant()] = $record.DisplayName }

    $resolvedLinks = foreach ($link in $linkRecords) {
        $name = $null
        if ($link.GpoId -and $gpoNameById.ContainsKey($link.GpoId.ToLowerInvariant())) {
            $name = $gpoNameById[$link.GpoId.ToLowerInvariant()]
        }

        [pscustomobject]@{
            TargetDn       = $link.TargetDn
            TargetType     = $link.TargetType
            GpoDisplayName = $name
            GpoId          = $link.GpoId
            LinkOrder      = $link.LinkOrder
            AttributeIndex = $link.AttributeIndex
            Enabled        = $link.Enabled
            Enforced       = $link.Enforced
            RawFlag        = $link.RawFlag
            Resolved       = ($null -ne $name)
        }
    }

    [void](Export-AkCsv -InputObject @($resolvedLinks) -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item GpoLinks))

    # --- WMI filters -------------------------------------------------------
    # There is no Get-WmiFilter cmdlet. They are msWMI-Som objects in the
    # System container and must be read and recreated as raw directory objects.
    $wmiRecords = @()
    try {
        $wmiSearchBase = "CN=SOM,CN=WMIPolicy,CN=System,$($domain.DistinguishedName)"
        $wmiObjects = @(Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -SearchBase $wmiSearchBase `
            -Properties "msWMI-Name", "msWMI-Parm1", "msWMI-Parm2", "msWMI-ID", "msWMI-Author" @adParams)

        $wmiRecords = foreach ($wmi in $wmiObjects) {
            [pscustomobject]@{
                Name        = Get-AkPropertyValue -InputObject $wmi -Name "msWMI-Name"
                Description = Get-AkPropertyValue -InputObject $wmi -Name "msWMI-Parm1"
                Query       = Get-AkPropertyValue -InputObject $wmi -Name "msWMI-Parm2"
                WmiId       = Get-AkPropertyValue -InputObject $wmi -Name "msWMI-ID"
                Author      = Get-AkPropertyValue -InputObject $wmi -Name "msWMI-Author"
            }
        }
    }
    catch {
        Write-AkLog -Message "Could not enumerate WMI filters: $($_.Exception.Message)" -Level Warning
    }

    [void](Export-AkCsv -InputObject @($wmiRecords) -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item WmiFilters))

    $counts["Gpos"] = $gpoRecords.Count
    $counts["GpoLinks"] = @($resolvedLinks).Count
    $counts["WmiFilters"] = @($wmiRecords).Count
    $exportedSections.Add("Gpo")
    Write-AkLog -Message "GPOs exported: $($gpoRecords.Count), links: $(@($resolvedLinks).Count), WMI filters: $(@($wmiRecords).Count)" -Level Success
}

# ---------------------------------------------------------------------------
# Section: Shares and NTFS permissions
# ---------------------------------------------------------------------------

if (Test-Section -Name "Shares") {
    Write-AkLog -Message "Exporting file shares and NTFS permissions..." -Level Step

    $servers = @($FileServer)
    if ($servers.Count -eq 0) {
        $servers = @($env:COMPUTERNAME)
        Write-AkLog -Message "No -FileServer specified. Capturing shares on $env:COMPUTERNAME only." -Level Warning
    }

    # Administrative and replication shares are never migrated.
    $alwaysExcluded = @("ADMIN$", "IPC$", "PRINT$", "FAX$", "SYSVOL", "NETLOGON")

    $shareRecords = New-Object System.Collections.Generic.List[object]
    $shareAccessRecords = New-Object System.Collections.Generic.List[object]
    $aclRecords = New-Object System.Collections.Generic.List[object]

    foreach ($fileServer in $servers) {
        Write-AkLog -Message "Reading shares from $fileServer..." -Level Info

        $cimSession = $null
        $isLocal = ($fileServer -eq $env:COMPUTERNAME -or $fileServer -eq "." -or $fileServer -eq "localhost")

        try {
            $smbParams = @{}
            if (-not $isLocal) {
                $cimSessionParams = @{ ComputerName = $fileServer }
                if ($Credential) { $cimSessionParams["Credential"] = $Credential }
                $cimSession = New-CimSession @cimSessionParams
                $smbParams["CimSession"] = $cimSession
            }

            $shares = @(Get-SmbShare @smbParams -ErrorAction Stop | Where-Object {
                $alwaysExcluded -notcontains $_.Name -and
                $_.Name -notmatch '^[A-Za-z]\$$' -and
                ($null -eq $ExcludeSharePath -or $ExcludeSharePath -notcontains $_.Name)
            })

            foreach ($share in $shares) {
                $shareRecords.Add([pscustomobject]@{
                    Server              = $fileServer
                    Name                = $share.Name
                    Path                = $share.Path
                    Description         = Get-AkPropertyValue -InputObject $share -Name "Description"
                    UncPath             = "\\$fileServer\$($share.Name)"
                    FolderEnumerationMode = [string](Get-AkPropertyValue -InputObject $share -Name "FolderEnumerationMode")
                    CachingMode         = [string](Get-AkPropertyValue -InputObject $share -Name "CachingMode")
                    EncryptData         = Get-AkPropertyValue -InputObject $share -Name "EncryptData" -Default $false
                    ConcurrentUserLimit = Get-AkPropertyValue -InputObject $share -Name "ConcurrentUserLimit" -Default 0
                })

                try {
                    foreach ($access in @(Get-SmbShareAccess -Name $share.Name @smbParams -ErrorAction Stop)) {
                        $shareAccessRecords.Add([pscustomobject]@{
                            Server             = $fileServer
                            ShareName          = $share.Name
                            AccountName        = $access.AccountName
                            AccessControlType  = [string]$access.AccessControlType
                            AccessRight        = [string]$access.AccessRight
                        })
                    }
                }
                catch {
                    Write-AkLog -Message "Could not read share permissions for $fileServer\$($share.Name): $($_.Exception.Message)" -Level Warning
                }

                # NTFS ACLs are read over the administrative share so this works
                # whether or not the script runs on the file server itself.
                $rootPath = $share.Path
                if (-not $isLocal) {
                    $rootPath = "\\$fileServer\" + ($share.Path -replace '^([A-Za-z]):', '$1$')
                }

                $foldersToScan = New-Object System.Collections.Generic.List[string]
                $foldersToScan.Add($rootPath)

                if ($AclDepth -gt 0) {
                    try {
                        $children = @(Get-ChildItem -LiteralPath $rootPath -Directory -Recurse -Depth ($AclDepth - 1) -ErrorAction SilentlyContinue)
                        foreach ($child in $children) { $foldersToScan.Add($child.FullName) }
                    }
                    catch {
                        Write-AkLog -Message "Could not enumerate subfolders of $rootPath : $($_.Exception.Message)" -Level Warning
                    }
                }

                foreach ($folder in $foldersToScan) {
                    try {
                        $acl = Get-Acl -LiteralPath $folder -ErrorAction Stop

                        $relative = ""
                        if ($folder.Length -gt $rootPath.Length) {
                            $relative = $folder.Substring($rootPath.Length).TrimStart("\")
                        }

                        foreach ($ace in $acl.Access) {
                            if (-not $IncludeInheritedAcl -and $ace.IsInherited) { continue }

                            $sidValue = $null
                            try {
                                $sidValue = [string]$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            }
                            catch {
                                # Orphaned ACEs already store a raw SID string.
                                $sidValue = [string]$ace.IdentityReference.Value
                            }

                            $aclRecords.Add([pscustomobject]@{
                                Server                = $fileServer
                                ShareName             = $share.Name
                                RootPath              = $share.Path
                                RelativePath          = $relative
                                IdentityReference     = [string]$ace.IdentityReference.Value
                                IdentitySid           = $sidValue
                                IdentityIsBuiltIn     = Test-AkIsBuiltInSid -Sid $sidValue
                                FileSystemRights      = [string]$ace.FileSystemRights
                                AccessControlType     = [string]$ace.AccessControlType
                                IsInherited           = $ace.IsInherited
                                InheritanceFlags      = [string]$ace.InheritanceFlags
                                PropagationFlags      = [string]$ace.PropagationFlags
                                Owner                 = $acl.Owner
                                AreAccessRulesProtected = $acl.AreAccessRulesProtected
                                Sddl                  = $acl.Sddl
                            })
                        }
                    }
                    catch {
                        Write-AkLog -Message "Could not read ACL for $folder : $($_.Exception.Message)" -Level Warning
                    }
                }
            }
        }
        catch {
            Write-AkLog -Message "Failed to process file server '$fileServer': $($_.Exception.Message)" -Level Error
        }
        finally {
            if ($cimSession) { Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue }
        }
    }

    [void](Export-AkCsv -InputObject $shareRecords.ToArray() -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item Shares))
    [void](Export-AkCsv -InputObject $shareAccessRecords.ToArray() -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item ShareAccess))
    [void](Export-AkCsv -InputObject $aclRecords.ToArray() -Path (Get-AkPackageItemPath -PackagePath $packagePath -Item NtfsAcl))

    $counts["Shares"] = $shareRecords.Count
    $counts["ShareAccessRules"] = $shareAccessRecords.Count
    $counts["NtfsAccessRules"] = $aclRecords.Count
    $exportedSections.Add("Shares")
    Write-AkLog -Message "Shares exported: $($shareRecords.Count), share ACEs: $($shareAccessRecords.Count), NTFS ACEs: $($aclRecords.Count)" -Level Success
}

# ---------------------------------------------------------------------------
# Manifest and summary
# ---------------------------------------------------------------------------

$netBios = $null
if ($domain.PSObject.Properties.Name -contains "NetBIOSName") { $netBios = $domain.NetBIOSName }

[void](New-AkPackageManifest -PackagePath $packagePath `
    -SourceDomainDns $domain.DNSRoot `
    -SourceDomainNetBios $netBios `
    -SourceDomainDn $domain.DistinguishedName `
    -SourceDomainSid $domain.DomainSID.Value `
    -Counts $counts `
    -Sections $exportedSections.ToArray())

Write-Host ""
Write-AkLog -Message "Export complete." -Level Success
Write-Host ""
Write-Host "Package: $packagePath" -ForegroundColor Green
Write-Host ""
foreach ($key in ($counts.Keys | Sort-Object)) {
    Write-Host ("  {0,-32} {1}" -f $key, $counts[$key])
}
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy the entire package folder to the new domain controller."
Write-Host "  2. Run New-AdPrincipalMap.ps1 to build the old-to-new principal map."
Write-Host "  3. Review the map, then run Import-AdEnvironment.ps1 -WhatIf."
Write-Host ""
Write-Host "This package describes your whole directory. Protect it accordingly." -ForegroundColor Yellow
Write-Host ""

Stop-AkLog

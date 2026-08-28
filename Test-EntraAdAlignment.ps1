<#
.SYNOPSIS
Compares Active Directory users against the Entra tenant and reports everything
that would create duplicates, strip addresses, or block soft-match adoption
when directory synchronization is widened onto the existing tenant.

.DESCRIPTION
This automates the pre-cutover validation otherwise done by hand with portal
exports and ad-hoc one-liners. Run it after a domain rebuild, before widening
an Entra sync scope, and again after fixing what it reports.

Two data sources for the tenant, picked automatically:

  Graph     Default. The script installs its own dependency (the
            Microsoft.Graph.Authentication module, current user, from the
            PowerShell Gallery), signs in, and reads users and verified
            domains directly. This is the full check: it is the only mode
            that sees cloud proxyAddresses, so only it can warn about
            mailbox renames and stripped aliases.
  CSV       -TenantUserCsv with the Entra portal Users > Download users
            export. No network needed. UPN matching, rename detection, and
            provisioning candidates still work; the SMTP and alias checks
            are skipped because the portal export has no address columns.
            Supply -VerifiedDomain, since the export has no domain list.

Checks performed (details in Get-AkDirectoryAlignmentFinding):

  Critical  AD UPN suffix not verified in the tenant; matching cloud user
            still directory-synced (adoption blocked).
  High      Person renamed in the cloud (sync would duplicate them); same
            display name resolving to two different cloud users.
  Medium    AD user absent from the cloud (would be created); primary SMTP
            mismatch (adoption renames the mailbox); cloud alias missing
            on-prem (adoption strips it); on-prem address on an unverified
            domain (Entra drops it); malformed proxyAddresses entry.
  Info      Cloud users with no AD account - the Sync-EntraUsersToAd.ps1
            candidate list - and the matched-pair adoption count.

Single-directory hygiene (duplicate attributes, invalid characters, missing
display names) is Test-EntraSyncReadiness.ps1's job; run both.

.PARAMETER TenantId
Tenant ID or verified domain for the Graph sign-in. Optional; without it the
sign-in decides the tenant interactively.

.PARAMETER UseDeviceCode
Use the device-code flow for the Graph sign-in: the script prints a code, you
finish sign-in in a browser on any machine. Use this when the server has no
browser, or Conditional Access blocks the embedded prompt.

.PARAMETER TenantUserCsv
Entra portal user export. Switches the script to offline CSV mode.

.PARAMETER VerifiedDomain
Domains verified in the tenant. Required for the domain checks in CSV mode;
in Graph mode the list is read from the tenant and this overrides it.

.PARAMETER SearchBase
Limit the AD side to one OU subtree - use the OU scope the sync will get.

.PARAMETER Server
Domain controller to read from.

.PARAMETER Credential
Credentials for the domain.

.PARAMETER IncludeDisabled
Include disabled AD accounts. Off by default, matching a sane sync scope.

.PARAMETER OutputPath
Folder for the findings CSV.

.EXAMPLE
.\Test-EntraAdAlignment.ps1 -UseDeviceCode

.EXAMPLE
.\Test-EntraAdAlignment.ps1 -TenantUserCsv .\exportUsers.csv -VerifiedDomain contoso.com

.EXAMPLE
.\Test-EntraAdAlignment.ps1 -SearchBase "OU=Staff,DC=ad,DC=contoso,DC=com" -TenantId contoso.onmicrosoft.com

.NOTES
Windows PowerShell 5.1. Read-only against both directories. Graph mode needs
delegated User.Read.All and Domain.Read.All (an admin consents on first use).
#>

[CmdletBinding()]
param(
    [string]$TenantId,

    [switch]$UseDeviceCode,

    [string]$TenantUserCsv,

    [string[]]$VerifiedDomain,

    [string]$SearchBase,

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$IncludeDisabled,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "EntraAdAlignment")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Start-AkLog -Path (Join-Path -Path $OutputPath -ChildPath "entra-ad-alignment-$timestamp.log")

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  ENTRA / AD ALIGNMENT" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

try {
    # ------------------------------------------------------------------
    # AD side
    # ------------------------------------------------------------------
    Assert-AkModule -Name "ActiveDirectory" -Reason "reading the domain's users"

    $adParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $adParams["Server"] = $Server }
    if ($Credential) { $adParams["Credential"] = $Credential }

    $domain = Get-ADDomain @adParams
    Write-AkLog -Message "Reading users from $($domain.DNSRoot)" -Level Step

    # mail and proxyAddresses can be absent from a schema that never had
    # Exchange prep, and Get-ADUser fails the whole query on one unknown
    # attribute. Same probe as Test-EntraSyncReadiness.ps1.
    $properties = @("UserPrincipalName", "DisplayName", "Enabled")
    $candidateProperties = @("mail", "proxyAddresses")
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

    $userParams = @{ Filter = "*"; Properties = $properties }
    if ($SearchBase) { $userParams["SearchBase"] = $SearchBase }

    $adUsers = New-Object System.Collections.Generic.List[object]
    foreach ($adUser in @(Get-ADUser @userParams @adParams)) {
        if (-not $IncludeDisabled -and -not $adUser.Enabled) { continue }
        $adUsers.Add([pscustomobject]@{
            SamAccountName    = $adUser.SamAccountName
            UserPrincipalName = [string](Get-AkPropertyValue -InputObject $adUser -Name "UserPrincipalName" -Default "")
            DisplayName       = [string](Get-AkPropertyValue -InputObject $adUser -Name "DisplayName" -Default "")
            Enabled           = $adUser.Enabled
            Mail              = [string](Get-AkPropertyValue -InputObject $adUser -Name "mail" -Default "")
            ProxyAddresses    = @(Get-AkPropertyValue -InputObject $adUser -Name "proxyAddresses" -Default @())
            DistinguishedName = $adUser.DistinguishedName
        })
    }
    Write-AkLog -Message "Loaded $($adUsers.Count) AD user(s)." -Level Info

    # ------------------------------------------------------------------
    # Tenant side
    # ------------------------------------------------------------------
    $cloudUsers = New-Object System.Collections.Generic.List[object]
    $hasCloudProxyData = $false
    $verified = @()
    if ($VerifiedDomain) { $verified = @($VerifiedDomain) }

    if (-not [string]::IsNullOrWhiteSpace($TenantUserCsv)) {
        Write-AkLog -Message "Offline mode: reading the tenant from '$TenantUserCsv'." -Level Step
        $rows = Import-AkCsv -Path $TenantUserCsv -Required
        if ($rows.Count -eq 0) { throw "Tenant export '$TenantUserCsv' contains no rows." }

        $upnColumn = Get-AkCsvColumnName -Row $rows[0] -Candidate @("userPrincipalName", "User principal name", "UPN")
        if (-not $upnColumn) { throw "Tenant export '$TenantUserCsv' has no recognizable user principal name column." }
        $nameColumn = Get-AkCsvColumnName -Row $rows[0] -Candidate @("displayName", "Display name")
        $typeColumn = Get-AkCsvColumnName -Row $rows[0] -Candidate @("userType", "User type")
        $syncColumn = Get-AkCsvColumnName -Row $rows[0] -Candidate @(
            "onPremisesSyncEnabled", "directorySynced", "dirSyncEnabled", "Directory synced", "On-premises sync enabled")
        $enabledColumn = Get-AkCsvColumnName -Row $rows[0] -Candidate @("accountEnabled", "Account enabled", "Block sign in")

        foreach ($row in $rows) {
            $cloudUsers.Add([pscustomobject]@{
                Id                    = ""
                DisplayName           = if ($nameColumn) { [string](Get-AkPropertyValue -InputObject $row -Name $nameColumn -Default "") } else { "" }
                UserPrincipalName     = [string](Get-AkPropertyValue -InputObject $row -Name $upnColumn -Default "")
                AccountEnabled        = if ($enabledColumn) { ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $row -Name $enabledColumn) -Default $true } else { $true }
                UserType              = if ($typeColumn) { [string](Get-AkPropertyValue -InputObject $row -Name $typeColumn -Default "Member") } else { "Member" }
                OnPremisesSyncEnabled = if ($syncColumn) { ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $row -Name $syncColumn) -Default $false } else { $false }
                ProxyAddresses        = @()
                Mail                  = ""
            })
        }

        Write-AkLog -Message "The portal export has no proxyAddresses. Primary SMTP and alias checks are skipped; run the Graph mode for those." -Level Warning
        if ($verified.Count -eq 0) {
            Write-AkLog -Message "No -VerifiedDomain supplied. Unverified-suffix and dropped-address checks are skipped." -Level Warning
        }
    }
    else {
        Write-AkLog -Message "Graph mode: preparing the Microsoft Graph client." -Level Step
        Initialize-AkGraphDependency

        $connectParams = @{ Scopes = @("User.Read.All", "Domain.Read.All") }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $connectParams["TenantId"] = $TenantId }
        if ($UseDeviceCode) { $connectParams["UseDeviceCode"] = $true }
        if ((Get-Command Connect-MgGraph).Parameters.ContainsKey("NoWelcome")) { $connectParams["NoWelcome"] = $true }

        Write-AkLog -Message "Signing in to Microsoft Graph (delegated User.Read.All, Domain.Read.All)." -Level Info
        Connect-MgGraph @connectParams | Out-Null

        if ($verified.Count -eq 0) {
            $domainsResponse = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/domains"
            foreach ($entry in @($domainsResponse.value)) {
                if ($entry["isVerified"]) { $verified += [string]$entry["id"] }
            }
            Write-AkLog -Message "Verified domains: $($verified -join ', ')" -Level Info
        }

        Write-AkLog -Message "Reading tenant users..." -Level Step
        $uri = "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,proxyAddresses,mail&`$top=999"
        while (-not [string]::IsNullOrWhiteSpace($uri)) {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($entry in @($response.value)) {
                $cloudUsers.Add([pscustomobject]@{
                    Id                    = [string]$entry["id"]
                    DisplayName           = [string]$entry["displayName"]
                    UserPrincipalName     = [string]$entry["userPrincipalName"]
                    AccountEnabled        = ConvertTo-AkBoolean -Value $entry["accountEnabled"] -Default $true
                    UserType              = [string]$entry["userType"]
                    OnPremisesSyncEnabled = ConvertTo-AkBoolean -Value $entry["onPremisesSyncEnabled"] -Default $false
                    ProxyAddresses        = @($entry["proxyAddresses"])
                    Mail                  = [string]$entry["mail"]
                })
            }
            $uri = ""
            if ($response.ContainsKey("@odata.nextLink")) { $uri = [string]$response["@odata.nextLink"] }
        }
        $hasCloudProxyData = $true
    }

    Write-AkLog -Message "Loaded $($cloudUsers.Count) tenant user(s)." -Level Info

    # ------------------------------------------------------------------
    # Compare and report
    # ------------------------------------------------------------------
    Write-AkLog -Message "Comparing directories..." -Level Step
    $findings = Get-AkDirectoryAlignmentFinding `
        -AdUser $adUsers.ToArray() `
        -CloudUser $cloudUsers.ToArray() `
        -VerifiedDomain $verified `
        -HasCloudProxyData:$hasCloudProxyData

    $severityRank = @{ "Info" = 0; "Low" = 1; "Medium" = 2; "High" = 3; "Critical" = 4 }
    $sorted = @($findings | Sort-Object -Property @{ Expression = { $severityRank[$_.Severity] }; Descending = $true }, Check, AffectedObject)

    $resultPath = Join-Path -Path $OutputPath -ChildPath "EntraAdAlignment-$timestamp.csv"
    Export-AkCsv -InputObject $sorted -Path $resultPath

    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "  RESULTS" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""

    foreach ($severity in @("Critical", "High", "Medium", "Low", "Info")) {
        $count = @($sorted | Where-Object { $_.Severity -eq $severity }).Count
        if ($count -gt 0) {
            Write-Host ("  {0,-8} {1}" -f $severity, $count)
        }
    }

    $blockers = @($sorted | Where-Object { $_.Severity -in @("Critical", "High") })
    if ($blockers.Count -gt 0) {
        Write-Host ""
        Write-Host "  Fix before widening the sync scope:" -ForegroundColor Yellow
        foreach ($group in ($blockers | Group-Object Check | Sort-Object Count -Descending)) {
            Write-Host ("    {0,-28} {1,4}" -f $group.Name, $group.Count)
        }
    }
    else {
        Write-Host ""
        Write-AkLog -Message "No adoption blockers found." -Level Success
    }

    Write-Host ""
    Write-AkLog -Message "Findings written to $resultPath" -Level Success
}
finally {
    Stop-AkLog
}

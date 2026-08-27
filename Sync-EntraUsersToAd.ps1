<#
.SYNOPSIS
Creates and maintains on-premises Active Directory accounts for cloud-only
Microsoft Entra ID users, so they can reach file shares, printers, and anything
else that wants Kerberos.

.DESCRIPTION
Adapted from the Azure-Samples/B2B-to-AD-Sync approach (shadow AD accounts driven
by Microsoft Graph, run unattended by a scheduled task) but aimed at the opposite
population. That sample shadows B2B *guests* for Application Proxy and Kerberos
constrained delegation. This one provisions cloud-only *members* into a real OU
so they get a working on-premises identity.

Read this before deploying:

  Microsoft Graph never exposes a user password, with any permission, in any API.
  No script can copy the Entra password down to AD. What this script does instead
  is create the AD account with a generated password and record it in a
  credential-grade CSV.

  In a tenant that already runs Entra Connect or Entra Cloud Sync, the AD account
  created here soft-matches the existing cloud account on UPN or primary SMTP.
  The cloud object is then taken over by the sync, and with password hash sync
  enabled the *AD* password becomes the one password for both. That is how the
  user ends up with a single credential - but it is the generated one, so the
  password CSV is the handoff, not a side effect. Alternatively, leave password
  writeback on and have the user run one SSPR reset.

  A taken-over user flips to onPremisesSyncEnabled = true and drops out of scope
  here automatically on the next pass.

  Microsoft's own supported product for cloud-to-AD provisioning is Entra API
  driven inbound provisioning to on-premises AD, which needs Entra ID Governance
  licensing and the provisioning agent. This script is the unlicensed equivalent
  for a small tenant.

Design notes:

  - Scope defaults to the members of one or more Entra security groups. Running
    against every cloud-only user is deliberately opt-in, because break-glass
    accounts, service principals' owner accounts, and shared mailboxes are all
    cloud only and none of them should become AD users.
  - Users already synced from AD are always skipped, so this cannot loop against
    Entra Connect.
  - The Entra objectId is stamped on the AD object as an anchor. Matching is by
    anchor first and UPN second, so an account created by hand earlier is adopted
    rather than duplicated.
  - Accounts are never deleted. An orphan is reported, and optionally disabled
    and moved.
  - Authentication is the client credentials flow with a certificate, signed by
    hand, so a domain controller needs no Microsoft Graph SDK and no MSAL.

.PARAMETER TenantId
Entra tenant ID or verified domain.

.PARAMETER ClientId
Application (client) ID of the app registration.

.PARAMETER CertificateThumbprint
Thumbprint of the certificate whose public key is uploaded to the app
registration. Preferred over a client secret for an unattended run.

.PARAMETER CertificateStoreLocation
Certificate store to look in. LocalMachine suits a scheduled task running as a
gMSA; CurrentUser suits an interactive test.

.PARAMETER ClientSecret
Client secret, as an alternative to a certificate. Secrets expire and end up in
scripts; use a certificate where you can.

.PARAMETER EntraGroupObjectId
One or more Entra group object IDs. Transitive members of these groups are the
sync scope.

.PARAMETER AllCloudOnlyUsers
Take every cloud-only member of the tenant as the scope instead of a group.
Explicit because it is the dangerous option.

.PARAMETER TargetOu
Distinguished name of the OU new accounts are created in. Cloud Sync's scope must
include this OU or the takeover will never happen.

.PARAMETER OrphanOu
Distinguished name of the OU disabled orphans are moved to.

.PARAMETER OrphanAction
What to do with an AD account whose Entra user has left the scope.
Report (default), Disable, DisableAndMove, or None.

.PARAMETER AnchorAttribute
AD attribute holding the Entra objectId. adminDescription is in the base schema
and is safe on any forest. Use an extensionAttribute if adminDescription is
already spoken for.

.PARAMETER AddToGroup
AD groups every newly created account is added to. This is where the share and
printer access actually comes from.

.PARAMETER ExcludeUserPrincipalName
UPN patterns to leave alone. Wildcards supported.

.PARAMETER IncludeGuest
Also provision Entra guests. Off by default.

.PARAMETER IncludeDisabled
Also provision users whose Entra account is disabled. They are created disabled.

.PARAMETER SyncUpnChanges
Apply a changed userPrincipalName to an existing AD account. Off by default: a
UPN rename is a user-visible event and usually wants a human.

.PARAMETER SyncProxyAddresses
Copy Entra proxyAddresses onto the AD object. Off by default because in an
Exchange hybrid the addresses are owned by Exchange.

.PARAMETER ClearAbsent
Clear AD attributes that are empty in Entra. Off by default, so a desk phone
recorded only on premises survives.

.PARAMETER NoChangePasswordAtLogon
Do not flag the new account to change its password at next sign in. Consider
this when the plan is password hash sync takeover, since a must-change flag on a
freshly created account gets in the user's way in the cloud too.

.PARAMETER CreateDisabled
Create every new account disabled, for a staged cutover.

.PARAMETER Server
Domain controller to target for every AD operation.

.PARAMETER OutputPath
Folder for the plan CSV, the generated password CSV, and the log.

.PARAMETER SkipUpnSuffixCheck
Skip the check that each new UPN suffix is registered in the forest.

.EXAMPLE
.\Sync-EntraUsersToAd.ps1 -TenantId contoso.com -ClientId 1111... `
    -CertificateThumbprint AABB... -EntraGroupObjectId 2222... `
    -TargetOu "OU=Cloud Users,OU=CORP - Users,DC=ad,DC=contoso,DC=com" -WhatIf

.EXAMPLE
.\Sync-EntraUsersToAd.ps1 -TenantId contoso.com -ClientId 1111... `
    -CertificateThumbprint AABB... -EntraGroupObjectId 2222... `
    -TargetOu "OU=Cloud Users,DC=ad,DC=contoso,DC=com" `
    -AddToGroup "Firm Staff","Printer Users" -OrphanAction DisableAndMove `
    -OrphanOu "OU=Disabled,DC=ad,DC=contoso,DC=com"
#>

# ConfirmImpact is deliberately left at the default. This runs unattended on a
# schedule, and High would sit at a confirmation prompt forever. -WhatIf is the
# preview; the plan CSV is written on every run either way.
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = "Certificate")]
param(
    [Parameter(Mandatory)]
    [string]$TenantId,

    [Parameter(Mandatory)]
    [string]$ClientId,

    [Parameter(Mandatory, ParameterSetName = "Certificate")]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = "Certificate")]
    [ValidateSet("LocalMachine", "CurrentUser")]
    [string]$CertificateStoreLocation = "LocalMachine",

    [Parameter(Mandatory, ParameterSetName = "Secret")]
    [securestring]$ClientSecret,

    [string[]]$EntraGroupObjectId,

    [switch]$AllCloudOnlyUsers,

    [Parameter(Mandatory)]
    [string]$TargetOu,

    [string]$OrphanOu,

    [ValidateSet("Report", "Disable", "DisableAndMove", "None")]
    [string]$OrphanAction = "Report",

    [string]$AnchorAttribute = "adminDescription",

    [string[]]$AddToGroup,

    [string[]]$ExcludeUserPrincipalName,

    [switch]$IncludeGuest,

    [switch]$IncludeDisabled,

    [switch]$SyncUpnChanges,

    [switch]$SyncProxyAddresses,

    [switch]$ClearAbsent,

    [switch]$NoChangePasswordAtLogon,

    [switch]$CreateDisabled,

    [string]$Server,

    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath "EntraToAdSync"),

    [switch]$SkipUpnSuffixCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

# LDAP attribute behind each Set-ADUser parameter this script writes. Needed
# because clearing a value uses -Clear <ldapName>, not the parameter name.
$script:LdapNameByAdProperty = @{
    GivenName     = "givenName"
    Surname       = "sn"
    DisplayName   = "displayName"
    EmailAddress  = "mail"
    Title         = "title"
    Department    = "department"
    Company       = "company"
    Office        = "physicalDeliveryOfficeName"
    OfficePhone   = "telephoneNumber"
    MobilePhone   = "mobile"
    StreetAddress = "streetAddress"
    City          = "l"
    State         = "st"
    PostalCode    = "postalCode"
    Country       = "c"
    EmployeeID    = "employeeID"
}

$script:GraphSelect = @(
    "id", "userPrincipalName", "displayName", "givenName", "surname", "mail",
    "mailNickname", "jobTitle", "department", "companyName", "officeLocation",
    "businessPhones", "mobilePhone", "streetAddress", "city", "state",
    "postalCode", "usageLocation", "employeeId", "accountEnabled", "userType",
    "onPremisesSyncEnabled", "onPremisesSamAccountName", "proxyAddresses"
) -join ","

function Get-AdParameter {
    <#
    .SYNOPSIS
    Returns the common splat for every AD cmdlet call, honouring -Server.
    #>
    [CmdletBinding()]
    param()

    $parameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $parameters["Server"] = $Server
    }
    return $parameters
}

function Get-GraphToken {
    <#
    .SYNOPSIS
    Gets an application access token for Microsoft Graph.

    .DESCRIPTION
    Client credentials, either a hand-signed certificate assertion or a secret.
    Deliberately free of MSAL and the Graph SDK so this runs on a stock domain
    controller with Windows PowerShell 5.1.
    #>
    [CmdletBinding()]
    param()

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id  = $ClientId
        scope      = "https://graph.microsoft.com/.default"
        grant_type = "client_credentials"
    }

    # Branch on the thumbprint, not on $PSCmdlet.ParameterSetName. Inside a
    # function with its own [CmdletBinding()], $PSCmdlet is that function's
    # context and its parameter set is always __AllParameterSets, so testing it
    # here would silently send every run down the client secret path.
    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        $store = "Cert:\$CertificateStoreLocation\My"
        $certificate = Get-ChildItem -Path $store -ErrorAction SilentlyContinue |
            Where-Object { $_.Thumbprint -eq $CertificateThumbprint.Replace(" ", "").ToUpperInvariant() } |
            Select-Object -First 1

        if ($null -eq $certificate) {
            throw "Certificate $CertificateThumbprint was not found in $store. A scheduled task running as a gMSA reads LocalMachine, and the gMSA needs read access to the private key."
        }

        $body["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        $body["client_assertion"] = New-AkClientAssertion -Certificate $certificate -ClientId $ClientId -Audience $tokenUri
    }
    else {
        if ($null -eq $ClientSecret) {
            throw "Supply -CertificateThumbprint or -ClientSecret."
        }
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
        try {
            $body["client_secret"] = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    try {
        $response = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing
    }
    catch {
        throw "Token request failed: $($_.Exception.Message). Check the app registration, the admin consent on User.Read.All and GroupMember.Read.All, and that the certificate public key is uploaded."
    }

    $token = Get-AkPropertyValue -InputObject $response -Name "access_token"
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "Token endpoint returned no access_token."
    }
    return $token
}

function Invoke-GraphGet {
    <#
    .SYNOPSIS
    Runs a Graph GET and follows @odata.nextLink, returning every value.

    .PARAMETER Uri
    First page URI.

    .PARAMETER Token
    Access token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $headers = @{
        Authorization    = "Bearer $Token"
        ConsistencyLevel = "eventual"
    }

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $page++
        $attempt = 0
        $response = $null

        while ($true) {
            $attempt++
            try {
                $response = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -ContentType "application/json" -UseBasicParsing
                break
            }
            catch {
                $status = 0
                if ($null -ne $_.Exception.PSObject.Properties["Response"] -and $null -ne $_.Exception.Response) {
                    try {
                        $status = [int]$_.Exception.Response.StatusCode
                    }
                    catch {
                        $status = 0
                    }
                }

                # 429 and 5xx are the retryable ones. Everything else is a real error.
                if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 5) {
                    $wait = [System.Math]::Min(60, [System.Math]::Pow(2, $attempt) * 5)
                    Write-AkLog -Message "Graph returned $status, retrying in $wait second(s) (attempt $attempt)." -Level Warning
                    Start-Sleep -Seconds $wait
                    continue
                }

                throw "Graph request failed ($status) on page ${page}: $($_.Exception.Message)"
            }
        }

        $value = Get-AkPropertyValue -InputObject $response -Name "value"
        if ($null -ne $value) {
            foreach ($item in $value) {
                $items.Add($item)
            }
        }
        elseif ($null -ne $response) {
            $items.Add($response)
        }

        $next = Get-AkPropertyValue -InputObject $response -Name "@odata.nextLink"
    }

    return ,@($items.ToArray())
}

function ConvertTo-FlatEntraUser {
    <#
    .SYNOPSIS
    Flattens a Graph user into the scalar shape the planning helpers expect.

    .DESCRIPTION
    businessPhones is a collection and proxyAddresses is a collection; the rest
    is copied through. Missing properties are read with Get-AkPropertyValue
    because Graph omits nulls and StrictMode makes a direct access fatal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $GraphUser
    )

    $phones = Get-AkPropertyValue -InputObject $GraphUser -Name "businessPhones"
    $firstPhone = $null
    if ($null -ne $phones -and @($phones).Count -gt 0) {
        $firstPhone = @($phones)[0]
    }

    $proxy = Get-AkPropertyValue -InputObject $GraphUser -Name "proxyAddresses"
    $proxyList = @()
    if ($null -ne $proxy) {
        $proxyList = @($proxy)
    }

    return [pscustomobject]@{
        id                       = Get-AkPropertyValue -InputObject $GraphUser -Name "id"
        userPrincipalName        = Get-AkPropertyValue -InputObject $GraphUser -Name "userPrincipalName"
        displayName              = Get-AkPropertyValue -InputObject $GraphUser -Name "displayName"
        givenName                = Get-AkPropertyValue -InputObject $GraphUser -Name "givenName"
        surname                  = Get-AkPropertyValue -InputObject $GraphUser -Name "surname"
        mail                     = Get-AkPropertyValue -InputObject $GraphUser -Name "mail"
        mailNickname             = Get-AkPropertyValue -InputObject $GraphUser -Name "mailNickname"
        jobTitle                 = Get-AkPropertyValue -InputObject $GraphUser -Name "jobTitle"
        department               = Get-AkPropertyValue -InputObject $GraphUser -Name "department"
        companyName              = Get-AkPropertyValue -InputObject $GraphUser -Name "companyName"
        officeLocation           = Get-AkPropertyValue -InputObject $GraphUser -Name "officeLocation"
        businessPhone            = $firstPhone
        mobilePhone              = Get-AkPropertyValue -InputObject $GraphUser -Name "mobilePhone"
        streetAddress            = Get-AkPropertyValue -InputObject $GraphUser -Name "streetAddress"
        city                     = Get-AkPropertyValue -InputObject $GraphUser -Name "city"
        state                    = Get-AkPropertyValue -InputObject $GraphUser -Name "state"
        postalCode               = Get-AkPropertyValue -InputObject $GraphUser -Name "postalCode"
        usageLocation            = Get-AkPropertyValue -InputObject $GraphUser -Name "usageLocation"
        employeeId               = Get-AkPropertyValue -InputObject $GraphUser -Name "employeeId"
        accountEnabled           = Get-AkPropertyValue -InputObject $GraphUser -Name "accountEnabled"
        userType                 = Get-AkPropertyValue -InputObject $GraphUser -Name "userType" -Default "Member"
        onPremisesSyncEnabled    = Get-AkPropertyValue -InputObject $GraphUser -Name "onPremisesSyncEnabled"
        onPremisesSamAccountName = Get-AkPropertyValue -InputObject $GraphUser -Name "onPremisesSamAccountName"
        proxyAddresses           = $proxyList
    }
}

function Get-ScopedEntraUser {
    <#
    .SYNOPSIS
    Reads the Entra users in scope, either group members or all cloud-only users.

    .DESCRIPTION
    Filtering for cloud-only users server side needs advanced query support and
    fails in confusing ways; for a tenant this size it is simpler and more
    reliable to select the properties and let Test-AkEntraSyncCandidate decide.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    $users = New-Object System.Collections.Generic.List[object]
    $seen = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

    if ($AllCloudOnlyUsers) {
        Write-AkLog -Message "Reading all users in the tenant." -Level Step
        $raw = Invoke-GraphGet -Token $Token -Uri "https://graph.microsoft.com/v1.0/users?`$select=$script:GraphSelect&`$top=999"
        foreach ($item in $raw) {
            $flat = ConvertTo-FlatEntraUser -GraphUser $item
            if ($null -ne $flat.id -and $seen.Add([string]$flat.id)) {
                $users.Add($flat)
            }
        }
    }
    else {
        foreach ($groupId in $EntraGroupObjectId) {
            Write-AkLog -Message "Reading transitive members of group $groupId." -Level Step
            $uri = "https://graph.microsoft.com/v1.0/groups/$groupId/transitiveMembers/microsoft.graph.user?`$select=$script:GraphSelect&`$count=true&`$top=999"
            $raw = Invoke-GraphGet -Token $Token -Uri $uri
            foreach ($item in $raw) {
                $flat = ConvertTo-FlatEntraUser -GraphUser $item
                if ($null -ne $flat.id -and $seen.Add([string]$flat.id)) {
                    $users.Add($flat)
                }
            }
        }
    }

    return ,@($users.ToArray())
}

function Get-ExistingAdUser {
    <#
    .SYNOPSIS
    Reads the AD users already in the target OU, with the anchor attribute.
    #>
    [CmdletBinding()]
    param()

    $properties = @("Name", "UserPrincipalName", "DisplayName", "Enabled", "SamAccountName", $AnchorAttribute)
    foreach ($name in $script:LdapNameByAdProperty.Keys) {
        if ($properties -notcontains $name) {
            $properties += $name
        }
    }

    # The scriptblock runs from inside the module, so it cannot see this
    # function's locals. Script scope is resolved against this file, so park the
    # query parameters there.
    $script:AdQuerySplat = Get-AdParameter
    $script:AdQuerySplat["SearchBase"] = $TargetOu
    $script:AdQuerySplat["SearchScope"] = "Subtree"

    $dropped = @()
    $users = Invoke-AkAdPropertyQuery -Property $properties -DroppedProperty ([ref]$dropped) -Query {
        param($requested)
        $splat = $script:AdQuerySplat
        Get-ADUser -Filter "*" -Properties $requested @splat
    }

    if ($dropped.Count -gt 0) {
        Write-AkLog -Message "Attributes absent from this schema: $($dropped -join ', ')." -Level Warning
        if ($dropped -contains $AnchorAttribute) {
            # Without the anchor every account looks new and the next run creates
            # duplicates. Refuse rather than do that.
            throw "The anchor attribute '$AnchorAttribute' does not exist in this schema. Pick one that does, for example adminDescription."
        }
    }

    return ,@($users)
}

function Get-TakenSamAccountName {
    <#
    .SYNOPSIS
    Every sAMAccountName already in the domain.

    .DESCRIPTION
    sAMAccountName is unique domain wide across users, groups, and computers, so
    the collision set has to come from all of them, not just the target OU.
    #>
    [CmdletBinding()]
    param()

    $adParameters = Get-AdParameter
    $names = New-Object System.Collections.Generic.List[string]
    $objects = Get-ADObject -LDAPFilter "(sAMAccountName=*)" -Properties sAMAccountName -ResultSetSize $null @adParameters
    foreach ($object in $objects) {
        $name = Get-AkPropertyValue -InputObject $object -Name "sAMAccountName"
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $names.Add([string]$name)
        }
    }

    return ,@($names.ToArray())
}

function Resolve-NewUserCommonName {
    <#
    .SYNOPSIS
    Picks a CN that does not already exist in the target OU.

    .DESCRIPTION
    The CN only has to be unique within its container, but two people with the
    same name is normal, so fall back to name plus logon name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$DisplayName,

        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]]$TakenCommonName
    )

    $base = $DisplayName
    if ([string]::IsNullOrWhiteSpace($base)) {
        $base = $SamAccountName
    }

    # Characters that need escaping in a DN, removed rather than escaped.
    $base = ($base -replace '[,\\#+<>;"=\r\n]', " ").Trim()
    if ([string]::IsNullOrWhiteSpace($base)) {
        $base = $SamAccountName
    }
    if ($base.Length -gt 64) {
        $base = $base.Substring(0, 64).Trim()
    }

    if (-not $TakenCommonName.Contains($base)) {
        [void]$TakenCommonName.Add($base)
        return $base
    }

    $candidate = "$base ($SamAccountName)"
    if ($candidate.Length -gt 64) {
        $candidate = $candidate.Substring(0, 64).Trim()
    }
    if (-not $TakenCommonName.Contains($candidate)) {
        [void]$TakenCommonName.Add($candidate)
        return $candidate
    }

    for ($i = 2; $i -le 999; $i++) {
        $attempt = "$base $i"
        if (-not $TakenCommonName.Contains($attempt)) {
            [void]$TakenCommonName.Add($attempt)
            return $attempt
        }
    }

    throw "Could not derive a unique common name for $SamAccountName in $TargetOu."
}

function Get-ValidUpnSuffix {
    <#
    .SYNOPSIS
    UPN suffixes the forest will accept.
    #>
    [CmdletBinding()]
    param()

    $adParameters = Get-AdParameter
    $suffixes = New-Object System.Collections.Generic.List[string]

    $forest = Get-ADForest @adParameters
    $forestSuffixes = Get-AkPropertyValue -InputObject $forest -Name "UPNSuffixes"
    if ($null -ne $forestSuffixes) {
        foreach ($suffix in @($forestSuffixes)) {
            $suffixes.Add([string]$suffix)
        }
    }

    $domains = Get-AkPropertyValue -InputObject $forest -Name "Domains"
    if ($null -ne $domains) {
        foreach ($domain in @($domains)) {
            $suffixes.Add([string]$domain)
        }
    }

    return ,@($suffixes.ToArray())
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $OutputPath)) {
    # -WhatIf:$false because the plan CSV and the log are written on a preview
    # run too. Creating the report folder is not a change to the directory.
    New-Item -Path $OutputPath -ItemType Directory -Force -WhatIf:$false -Confirm:$false | Out-Null
}

$stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
Start-AkLog -Path (Join-Path -Path $OutputPath -ChildPath "entra-to-ad-sync-$stamp.log")

try {
    Write-AkLog -Message "Entra to Active Directory user sync starting." -Level Step

    if (-not $AllCloudOnlyUsers -and ($null -eq $EntraGroupObjectId -or $EntraGroupObjectId.Count -eq 0)) {
        throw "Specify -EntraGroupObjectId, or -AllCloudOnlyUsers to take every cloud-only member of the tenant."
    }
    if ($AllCloudOnlyUsers -and $null -ne $EntraGroupObjectId -and $EntraGroupObjectId.Count -gt 0) {
        throw "-AllCloudOnlyUsers and -EntraGroupObjectId are mutually exclusive."
    }
    if ($OrphanAction -eq "DisableAndMove" -and [string]::IsNullOrWhiteSpace($OrphanOu)) {
        throw "-OrphanAction DisableAndMove requires -OrphanOu."
    }

    Assert-AkModule -Name "ActiveDirectory"
    Import-Module ActiveDirectory -ErrorAction Stop

    $adParameters = Get-AdParameter

    if (-not (Get-ADOrganizationalUnit -Identity $TargetOu @adParameters -ErrorAction SilentlyContinue)) {
        throw "Target OU was not found: $TargetOu"
    }
    if ($OrphanAction -eq "DisableAndMove" -and -not (Get-ADOrganizationalUnit -Identity $OrphanOu @adParameters -ErrorAction SilentlyContinue)) {
        throw "Orphan OU was not found: $OrphanOu"
    }

    # TLS 1.2 is not the Windows PowerShell 5.1 default and login.microsoftonline.com
    # will not negotiate anything older.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    Write-AkLog -Message "Requesting a Microsoft Graph token for tenant $TenantId." -Level Step
    $token = Get-GraphToken

    $entraUsers = Get-ScopedEntraUser -Token $token
    Write-AkLog -Message "Entra returned $($entraUsers.Count) user(s) in scope." -Level Info

    $adUsers = Get-ExistingAdUser
    Write-AkLog -Message "Found $($adUsers.Count) existing AD user(s) under $TargetOu." -Level Info

    $plan = Get-AkEntraSyncPlan -EntraUser $entraUsers -AdUser $adUsers `
        -AnchorProperty $AnchorAttribute `
        -ExcludeUserPrincipalName $ExcludeUserPrincipalName `
        -IncludeGuest:$IncludeGuest -IncludeDisabled:$IncludeDisabled -ClearAbsent:$ClearAbsent

    $creates = @($plan | Where-Object { $_.Action -eq "Create" })
    $updates = @($plan | Where-Object { $_.Action -eq "Update" })
    $enables = @($plan | Where-Object { $_.Action -eq "Enable" })
    $orphans = @($plan | Where-Object { $_.Action -eq "Orphan" })
    $skips = @($plan | Where-Object { $_.Action -eq "Skip" })

    Write-AkLog -Message ("Plan: {0} create, {1} update, {2} enable, {3} orphan, {4} skipped, {5} already in sync." -f `
        $creates.Count, $updates.Count, $enables.Count, $orphans.Count, $skips.Count,
        @($plan | Where-Object { $_.Action -eq "None" }).Count) -Level Info

    $planRows = foreach ($item in $plan) {
        [pscustomobject]@{
            Action            = $item.Action
            Reason            = $item.Reason
            UserPrincipalName = $item.UserPrincipalName
            DisplayName       = $item.DisplayName
            EntraObjectId     = $item.EntraObjectId
            MatchedBy         = $item.MatchedBy
            ChangedAttributes = (($item.Changes.Keys | Sort-Object) -join ";")
        }
    }
    $planPath = Join-Path -Path $OutputPath -ChildPath "entra-to-ad-plan-$stamp.csv"
    [void](Export-AkCsv -InputObject @($planRows) -Path $planPath)
    Write-AkLog -Message "Plan written to $planPath" -Level Info

    # ------------------------------------------------------------------
    # Creates
    # ------------------------------------------------------------------

    $createdCredential = New-Object System.Collections.Generic.List[object]
    $failures = New-Object System.Collections.Generic.List[object]

    if ($creates.Count -gt 0) {
        $takenSam = New-Object System.Collections.Generic.List[string]
        $takenSam.AddRange([string[]](Get-TakenSamAccountName))

        $takenCn = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($account in $adUsers) {
            $name = Get-AkPropertyValue -InputObject $account -Name "Name"
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                [void]$takenCn.Add([string]$name)
            }
        }

        $validSuffixes = @()
        if (-not $SkipUpnSuffixCheck) {
            $validSuffixes = Get-ValidUpnSuffix
            Write-AkLog -Message "Forest accepts UPN suffixes: $($validSuffixes -join ', ')" -Level Info
        }

        $attributeMap = Get-AkEntraAttributeMap

        foreach ($item in $creates) {
            $entra = $item.EntraUser
            $upn = [string]$item.UserPrincipalName

            try {
                if (-not $SkipUpnSuffixCheck) {
                    $suffix = $upn.Substring($upn.IndexOf("@") + 1)
                    if ($validSuffixes -notcontains $suffix) {
                        throw "UPN suffix '$suffix' is not registered in this forest. Register it with Set-AdUpnSuffix.ps1 first, or the account cannot carry its cloud UPN and will never soft match."
                    }
                }

                $nickname = Get-AkPropertyValue -InputObject $entra -Name "onPremisesSamAccountName"
                if ($null -eq $nickname) {
                    $nickname = Get-AkPropertyValue -InputObject $entra -Name "mailNickname"
                }
                if ($null -eq $nickname) {
                    $nickname = $upn.Substring(0, $upn.IndexOf("@"))
                }

                $sam = New-AkSamAccountName -Candidate ([string]$nickname) -Taken $takenSam.ToArray()
                $commonName = Resolve-NewUserCommonName -DisplayName ([string]$item.DisplayName) -SamAccountName $sam -TakenCommonName $takenCn

                $password = New-AkPassword -Length 20
                $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

                $enabled = $true
                if ($CreateDisabled -or $false -eq (Get-AkPropertyValue -InputObject $entra -Name "accountEnabled")) {
                    $enabled = $false
                }

                $other = @{ $AnchorAttribute = [string]$item.EntraObjectId }
                if ($SyncProxyAddresses) {
                    $proxy = Get-AkPropertyValue -InputObject $entra -Name "proxyAddresses"
                    if ($null -ne $proxy -and @($proxy).Count -gt 0) {
                        $other["proxyAddresses"] = [string[]]@($proxy)
                    }
                }

                $newUser = @{
                    Name                  = $commonName
                    SamAccountName        = $sam
                    UserPrincipalName     = $upn
                    Path                  = $TargetOu
                    AccountPassword       = $securePassword
                    Enabled               = $enabled
                    ChangePasswordAtLogon = (-not $NoChangePasswordAtLogon)
                    OtherAttributes       = $other
                } + $adParameters

                foreach ($adProperty in $attributeMap.Keys) {
                    $value = Get-AkPropertyValue -InputObject $entra -Name $attributeMap[$adProperty]
                    if ($null -ne $value) {
                        $newUser[$adProperty] = [string]$value
                    }
                }

                if ($PSCmdlet.ShouldProcess("$upn ($sam)", "Create AD user in $TargetOu")) {
                    New-ADUser @newUser
                    Write-AkLog -Message "Created $upn as $sam." -Level Success

                    if ($null -ne $AddToGroup) {
                        foreach ($group in $AddToGroup) {
                            if ([string]::IsNullOrWhiteSpace($group)) {
                                continue
                            }
                            try {
                                Add-ADGroupMember -Identity $group.Trim() -Members $sam @adParameters
                                Write-AkLog -Message "  added $sam to $group." -Level Info
                            }
                            catch {
                                Write-AkLog -Message "  could not add $sam to ${group}: $($_.Exception.Message)" -Level Warning
                                $failures.Add([pscustomobject]@{
                                    UserPrincipalName = $upn
                                    Operation         = "AddToGroup:$group"
                                    Error             = $_.Exception.Message
                                })
                            }
                        }
                    }

                    $createdCredential.Add([pscustomobject]@{
                        UserPrincipalName = $upn
                        SamAccountName    = $sam
                        DisplayName       = $item.DisplayName
                        EntraObjectId     = $item.EntraObjectId
                        Password          = $password
                        Enabled           = $enabled
                        MustChange        = (-not $NoChangePasswordAtLogon)
                        CreatedUtc        = (Get-Date).ToUniversalTime().ToString("s")
                    })
                }

                # Reserve the names even under -WhatIf so a preview run does not
                # hand the same logon name to two people.
                $takenSam.Add($sam)
            }
            catch {
                Write-AkLog -Message "Create failed for ${upn}: $($_.Exception.Message)" -Level Error
                $failures.Add([pscustomobject]@{
                    UserPrincipalName = $upn
                    Operation         = "Create"
                    Error             = $_.Exception.Message
                })
            }
        }
    }

    # ------------------------------------------------------------------
    # Updates and enables
    # ------------------------------------------------------------------

    foreach ($item in ($updates + $enables)) {
        $account = $item.AdUser
        $dn = Get-AkPropertyValue -InputObject $account -Name "DistinguishedName"
        $upn = [string]$item.UserPrincipalName

        try {
            $setParameters = @{ Identity = $dn } + $adParameters
            $clear = New-Object System.Collections.Generic.List[string]
            $hasSet = $false

            foreach ($adProperty in $item.Changes.Keys) {
                $value = $item.Changes[$adProperty]
                if ($null -eq $value) {
                    if ($script:LdapNameByAdProperty.ContainsKey($adProperty)) {
                        $clear.Add($script:LdapNameByAdProperty[$adProperty])
                    }
                    continue
                }
                $setParameters[$adProperty] = $value
                $hasSet = $true
            }

            $replace = @{}
            $currentAnchor = Get-AkPropertyValue -InputObject $account -Name $AnchorAttribute
            if ([string]::IsNullOrWhiteSpace($currentAnchor) -and -not [string]::IsNullOrWhiteSpace($item.EntraObjectId)) {
                $replace[$AnchorAttribute] = [string]$item.EntraObjectId
            }

            if ($SyncUpnChanges) {
                $currentUpn = Get-AkPropertyValue -InputObject $account -Name "UserPrincipalName"
                if (-not [string]::IsNullOrWhiteSpace($upn) -and [string]$currentUpn -ne $upn) {
                    $setParameters["UserPrincipalName"] = $upn
                    $hasSet = $true
                }
            }
            else {
                $currentUpn = Get-AkPropertyValue -InputObject $account -Name "UserPrincipalName"
                if (-not [string]::IsNullOrWhiteSpace($upn) -and [string]$currentUpn -ne $upn) {
                    Write-AkLog -Message "UPN drift on ${dn}: AD has '$currentUpn', Entra has '$upn'. Rerun with -SyncUpnChanges to apply." -Level Warning
                }
            }

            if ($replace.Count -gt 0) {
                $setParameters["Replace"] = $replace
                $hasSet = $true
            }
            if ($clear.Count -gt 0) {
                $setParameters["Clear"] = $clear.ToArray()
                $hasSet = $true
            }

            if ($hasSet -and $PSCmdlet.ShouldProcess($dn, "Update AD user from Entra")) {
                Set-ADUser @setParameters
                Write-AkLog -Message "Updated $upn ($($item.Reason))." -Level Success
            }

            if ($item.Action -eq "Enable" -and $PSCmdlet.ShouldProcess($dn, "Enable AD account")) {
                Enable-ADAccount -Identity $dn @adParameters
                Write-AkLog -Message "Enabled $upn." -Level Success
            }
        }
        catch {
            Write-AkLog -Message "Update failed for ${upn}: $($_.Exception.Message)" -Level Error
            $failures.Add([pscustomobject]@{
                UserPrincipalName = $upn
                Operation         = $item.Action
                Error             = $_.Exception.Message
            })
        }
    }

    # ------------------------------------------------------------------
    # Orphans. Never deleted.
    # ------------------------------------------------------------------

    foreach ($item in $orphans) {
        $account = $item.AdUser
        $dn = Get-AkPropertyValue -InputObject $account -Name "DistinguishedName"

        if ($OrphanAction -eq "None") {
            continue
        }

        Write-AkLog -Message "Orphan: $dn no longer has an Entra user in scope." -Level Warning
        if ($OrphanAction -eq "Report") {
            continue
        }

        try {
            if ($true -eq (Get-AkPropertyValue -InputObject $account -Name "Enabled")) {
                if ($PSCmdlet.ShouldProcess($dn, "Disable orphaned AD account")) {
                    Disable-ADAccount -Identity $dn @adParameters
                    Write-AkLog -Message "  disabled." -Level Success
                }
            }

            if ($OrphanAction -eq "DisableAndMove" -and (Get-AkParentDn -DistinguishedName $dn) -ne $OrphanOu) {
                if ($PSCmdlet.ShouldProcess($dn, "Move to $OrphanOu")) {
                    Move-ADObject -Identity $dn -TargetPath $OrphanOu @adParameters
                    Write-AkLog -Message "  moved to $OrphanOu." -Level Success
                }
            }
        }
        catch {
            Write-AkLog -Message "Orphan handling failed for ${dn}: $($_.Exception.Message)" -Level Error
            $failures.Add([pscustomobject]@{
                UserPrincipalName = $item.UserPrincipalName
                Operation         = "Orphan"
                Error             = $_.Exception.Message
            })
        }
    }

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    if ($createdCredential.Count -gt 0) {
        $credentialPath = Join-Path -Path $OutputPath -ChildPath "generated-passwords-$stamp.csv"
        [void](Export-AkCsv -InputObject @($createdCredential.ToArray()) -Path $credentialPath)
        Write-AkLog -Message "Generated passwords for $($createdCredential.Count) new account(s): $credentialPath" -Level Warning
        Write-AkLog -Message "That file is plaintext credentials. Hand it over and delete it." -Level Warning
    }

    if ($failures.Count -gt 0) {
        $failurePath = Join-Path -Path $OutputPath -ChildPath "entra-to-ad-failures-$stamp.csv"
        [void](Export-AkCsv -InputObject @($failures.ToArray()) -Path $failurePath)
        Write-AkLog -Message "$($failures.Count) operation(s) failed. See $failurePath" -Level Error
    }

    Write-AkLog -Message "Sync complete." -Level Success

    if ($failures.Count -gt 0) {
        exit 1
    }
}
finally {
    Stop-AkLog
}

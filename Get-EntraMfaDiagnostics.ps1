#!/usr/bin/env pwsh

<#
.SYNOPSIS
Runs Entra ID user MFA diagnostics and optional per-user MFA remediation for one or more tenants.

.DESCRIPTION
Exports user inventory with Microsoft Graph authentication methods and per-user
MFA status values: Disabled, Enabled, or Enforced.

Optionally updates non-Global Administrator users whose per-user MFA state is
below a requested target state. Global Administrators are always skipped for
remediation.

Important:
- Microsoft Graph reports registered authentication methods.
- The exact per-user MFA values Enabled/Disabled/Enforced are collected from
  the Microsoft Graph beta authentication requirements endpoint.

.PARAMETER TenantId
One or more tenant IDs or verified tenant domains to connect to.

.PARAMETER TenantListPath
Optional path to a text file with one tenant ID or verified tenant domain per line.

.PARAMETER OutputPath
Folder where CSV output files will be written.

.PARAMETER UserPrincipalName
Optional list of UPNs to inspect. If omitted, all users are inspected.

.PARAMETER IncludeLegacyPerUserMfaStatus
Deprecated compatibility switch. Per-user MFA state is collected with Microsoft
Graph by default.

.PARAMETER InstallMissingModules
Install missing Microsoft Graph modules for the current user.

.PARAMETER StopOnTenantError
Stop the full run if one tenant fails. By default, the script logs the error and
continues to the next tenant.

.PARAMETER UseDeviceAuthentication
Use device-code authentication for Microsoft Graph sign-in. This is useful when
browser-based sign-in does not open or appears to hang.

.PARAMETER RemediateMfaState
Optional per-user MFA target state to apply to non-Global Administrator users.
When set to Enabled, users currently Disabled are updated. When set to Enforced,
users currently Disabled or Enabled are updated.

.PARAMETER PreviewRemediation
Report which users would be remediated without updating Microsoft Graph.

.PARAMETER IncludeDisabledAccountsForRemediation
Include disabled user accounts in MFA remediation. By default, disabled accounts
are reported but skipped by remediation.

.EXAMPLE
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com

.EXAMPLE
./Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com -InstallMissingModules

.EXAMPLE
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com,fabrikam.onmicrosoft.com -OutputPath C:\Temp\MfaReport

.EXAMPLE
.\Get-EntraMfaDiagnostics.ps1 -TenantListPath .\tenants.txt -OutputPath C:\Temp\MfaReport

.EXAMPLE
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com -UseDeviceAuthentication

.EXAMPLE
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com -RemediateMfaState Enforced -WhatIf

.EXAMPLE
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com -RemediateMfaState Enforced -PreviewRemediation
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [string[]]$TenantId,

    [string]$TenantListPath,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "EntraMfaDiagnostics"),

    [string[]]$UserPrincipalName,

    [switch]$IncludeLegacyPerUserMfaStatus,

    [switch]$InstallMissingModules,

    [switch]$StopOnTenantError,

    [switch]$UseDeviceAuthentication,

    [ValidateSet("Enabled", "Enforced")]
    [string]$RemediateMfaState,

    [switch]$PreviewRemediation,

    [switch]$IncludeDisabledAccountsForRemediation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-DisplayMfaState {
    param(
        [string]$State
    )

    switch ($State) {
        "disabled" { return "Disabled" }
        "enabled" { return "Enabled" }
        "enforced" { return "Enforced" }
        "unknownFutureValue" { return "UnknownFutureValue" }
        default {
            if ([string]::IsNullOrWhiteSpace($State)) {
                return "Unknown"
            }

            return $State
        }
    }
}

function Assert-Module {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [switch]$Install
    )

    Write-Host "Checking module $Name..."

    if (Get-Module -ListAvailable -Name $Name) {
        return
    }

    if (-not $Install) {
        throw "Required module '$Name' is not installed. Re-run this script with -InstallMissingModules or install it first with: Install-Module $Name -Scope CurrentUser"
    }

    if (-not (Get-Command -Name Install-Module -ErrorAction SilentlyContinue)) {
        throw "Install-Module is not available in this PowerShell session. Install PowerShellGet, then install '$Name' with: Install-Module $Name -Scope CurrentUser"
    }

    Write-Host "Installing module $Name for CurrentUser..."
    Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
}

function Get-MethodTypeName {
    param(
        [Parameter(Mandatory)]
        [object]$Method
    )

    $odataType = $null
    if ($Method.PSObject.Properties.Name -contains "AdditionalProperties" -and $Method.AdditionalProperties) {
        $odataType = $Method.AdditionalProperties["@odata.type"]
    }

    if (-not [string]::IsNullOrWhiteSpace($odataType)) {
        return ($odataType -replace "#microsoft.graph.", "" -replace "AuthenticationMethod$", "")
    }

    return ($Method.GetType().Name -replace "^MicrosoftGraph", "" -replace "AuthenticationMethod$", "")
}

function Test-IsMfaMethod {
    param(
        [Parameter(Mandatory)]
        [string]$MethodType
    )

    $nonMfaMethods = @(
        "password",
        "passwordAuthenticationMethod",
        "email",
        "emailAuthenticationMethod"
    )

    return ($nonMfaMethods -notcontains $MethodType)
}

function Get-TenantInputs {
    param(
        [string[]]$TenantIds,

        [string]$ListPath
    )

    $tenantInputs = New-Object System.Collections.Generic.List[string]

    if ($TenantIds) {
        foreach ($tenant in $TenantIds) {
            if (-not [string]::IsNullOrWhiteSpace($tenant)) {
                $tenantInputs.Add($tenant.Trim())
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ListPath)) {
        if (-not (Test-Path -Path $ListPath)) {
            throw "Tenant list file was not found: $ListPath"
        }

        foreach ($tenant in Get-Content -Path $ListPath) {
            $cleanTenant = $tenant.Trim()
            if (-not [string]::IsNullOrWhiteSpace($cleanTenant) -and -not $cleanTenant.StartsWith("#")) {
                $tenantInputs.Add($cleanTenant)
            }
        }
    }

    $uniqueTenants = @($tenantInputs | Sort-Object -Unique)
    if ($uniqueTenants.Count -eq 0) {
        throw "Provide at least one tenant with -TenantId or -TenantListPath."
    }

    return $uniqueTenants
}

function Get-SafeFileName {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return ($Value -replace '[\\/:*?"<>|]', "_" -replace "\s+", "_")
}

function Connect-EntraGraph {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    Write-Host "Preparing Microsoft Graph connection for tenant $TenantId..."

    Assert-Module -Name Microsoft.Graph.Authentication -Install:$InstallMissingModules
    Assert-Module -Name Microsoft.Graph.Users -Install:$InstallMissingModules
    Assert-Module -Name Microsoft.Graph.Identity.SignIns -Install:$InstallMissingModules

    Write-Host "Importing Microsoft Graph modules..."
    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Users
    Import-Module Microsoft.Graph.Identity.SignIns

    $scopes = @(
        "User.Read.All",
        "UserAuthenticationMethod.Read.All",
        "Directory.Read.All",
        "Policy.Read.All",
        "RoleManagement.Read.Directory"
    )

    if (-not [string]::IsNullOrWhiteSpace($RemediateMfaState)) {
        $scopes += "Policy.ReadWrite.AuthenticationMethod"
    }

    Write-Host "Connecting to Microsoft Graph tenant $TenantId..."

    $connectParameters = @{
        TenantId  = $TenantId
        Scopes    = $scopes
        NoWelcome = $true
    }

    if ($UseDeviceAuthentication) {
        $connectParameters["UseDeviceAuthentication"] = $true
    }

    Connect-MgGraph @connectParameters

    $context = Get-MgContext
    if (-not $context) {
        throw "Microsoft Graph connection did not return a context for tenant $TenantId."
    }

    Write-Host "Connected to Microsoft Graph as $($context.Account) in tenant $($context.TenantId)."
}

function Invoke-GraphPagedRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri

        $responseValue = Get-ObjectPropertyValue -InputObject $response -Name "value"
        if ($responseValue) {
            foreach ($item in $responseValue) {
                $items.Add($item)
            }
        }
        elseif ($response) {
            $items.Add($response)
        }

        $nextUri = $null
        $nextLink = Get-ObjectPropertyValue -InputObject $response -Name "@odata.nextLink"
        if (-not [string]::IsNullOrWhiteSpace($nextLink)) {
            $nextUri = $nextLink
        }
    }

    return $items
}

function Get-ObjectPropertyValue {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ($key -eq $Name) {
                return $InputObject[$key]
            }
        }
    }

    $property = $InputObject.PSObject.Properties |
        Where-Object { $_.Name -eq $Name } |
        Select-Object -First 1

    if ($property) {
        return $property.Value
    }

    return $null
}

function Get-GlobalAdministratorUserIds {
    $globalAdminRoleTemplateId = "62e90394-69f5-4237-9190-012177145e10"
    $globalAdminUserIds = New-Object "System.Collections.Generic.HashSet[string]"

    $roleUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName,roleTemplateId"
    $roles = @(
        Invoke-GraphPagedRequest -Uri $roleUri |
            Where-Object {
                (Get-ObjectPropertyValue -InputObject $_ -Name "roleTemplateId") -eq $globalAdminRoleTemplateId -or
                (Get-ObjectPropertyValue -InputObject $_ -Name "displayName") -eq "Global Administrator"
            }
    )

    foreach ($role in $roles) {
        $roleId = Get-ObjectPropertyValue -InputObject $role -Name "id"
        if ([string]::IsNullOrWhiteSpace($roleId)) {
            continue
        }

        $membersUri = "https://graph.microsoft.com/v1.0/directoryRoles/$roleId/members?`$select=id,userPrincipalName"
        $members = @(Invoke-GraphPagedRequest -Uri $membersUri)

        foreach ($member in $members) {
            $memberId = Get-ObjectPropertyValue -InputObject $member -Name "id"
            if (-not [string]::IsNullOrWhiteSpace($memberId)) {
                [void]$globalAdminUserIds.Add($memberId)
            }
        }
    }

    if ($globalAdminUserIds.Count -gt 0) {
        return ,$globalAdminUserIds
    }

    $roleDefinitionUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,templateId"
    $roleDefinitions = @(
        Invoke-GraphPagedRequest -Uri $roleDefinitionUri |
            Where-Object {
                (Get-ObjectPropertyValue -InputObject $_ -Name "templateId") -eq $globalAdminRoleTemplateId -or
                (Get-ObjectPropertyValue -InputObject $_ -Name "displayName") -eq "Global Administrator"
            }
    )

    $roleDefinitionIds = New-Object "System.Collections.Generic.HashSet[string]"

    foreach ($roleDefinition in $roleDefinitions) {
        $roleDefinitionId = Get-ObjectPropertyValue -InputObject $roleDefinition -Name "id"
        if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) {
            continue
        }

        [void]$roleDefinitionIds.Add($roleDefinitionId)
    }

    if ($roleDefinitionIds.Count -eq 0) {
        return ,$globalAdminUserIds
    }

    $assignmentUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$select=principalId,roleDefinitionId"
    $assignments = @(
        Invoke-GraphPagedRequest -Uri $assignmentUri |
            Where-Object {
                $roleDefinitionId = Get-ObjectPropertyValue -InputObject $_ -Name "roleDefinitionId"
                -not [string]::IsNullOrWhiteSpace($roleDefinitionId) -and $roleDefinitionIds.Contains($roleDefinitionId)
            }
    )

    foreach ($assignment in $assignments) {
        $principalId = Get-ObjectPropertyValue -InputObject $assignment -Name "principalId"
        if (-not [string]::IsNullOrWhiteSpace($principalId)) {
            [void]$globalAdminUserIds.Add($principalId)
        }
    }

    return ,$globalAdminUserIds
}

function Get-GraphPerUserMfaState {
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    try {
        $requirements = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$UserId/authentication/requirements"

        [pscustomobject]@{
            State = ConvertTo-DisplayMfaState -State $requirements.perUserMfaState
            Error = $null
        }
    }
    catch {
        [pscustomobject]@{
            State = "Unknown"
            Error = $_.Exception.Message
        }
    }
}

function Test-MfaRemediationRequired {
    param(
        [Parameter(Mandatory)]
        [string]$CurrentState,

        [Parameter(Mandatory)]
        [string]$TargetState
    )

    if ($TargetState -eq "Enabled") {
        return ($CurrentState -eq "Disabled")
    }

    if ($TargetState -eq "Enforced") {
        return ($CurrentState -in @("Disabled", "Enabled"))
    }

    return $false
}

function Set-GraphPerUserMfaState {
    param(
        [Parameter(Mandatory)]
        [object]$Diagnostic,

        [Parameter(Mandatory)]
        [string]$TargetState
    )

    if ($Diagnostic.IsGlobalAdministrator) {
        return [pscustomobject]@{
            Action = "Skipped"
            Error  = $null
            Reason = "GlobalAdministrator"
        }
    }

    if (-not $IncludeDisabledAccountsForRemediation -and $Diagnostic.AccountEnabled -eq $false) {
        return [pscustomobject]@{
            Action = "Skipped"
            Error  = $null
            Reason = "AccountDisabled"
        }
    }

    if (-not (Test-MfaRemediationRequired -CurrentState $Diagnostic.MfaEnforcementStatus -TargetState $TargetState)) {
        return [pscustomobject]@{
            Action = "NotRequired"
            Error  = $null
            Reason = $null
        }
    }

    $body = @{
        perUserMfaState = $TargetState.ToLowerInvariant()
    } | ConvertTo-Json

    $targetDescription = "$($Diagnostic.UserPrincipalName) per-user MFA state to $TargetState"

    if ($PreviewRemediation) {
        return [pscustomobject]@{
            Action = "Preview"
            Error  = $null
            Reason = $null
        }
    }

    if (-not $PSCmdlet.ShouldProcess($targetDescription, "Update Microsoft Graph authentication requirements")) {
        return [pscustomobject]@{
            Action = "WhatIf"
            Error  = $null
            Reason = $null
        }
    }

    try {
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/users/$($Diagnostic.UserId)/authentication/requirements" -Body $body -ContentType "application/json" | Out-Null

        return [pscustomobject]@{
            Action = "Updated"
            Error  = $null
            Reason = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Action = "Failed"
            Error  = $_.Exception.Message
            Reason = $null
        }
    }
}

function Select-MfaStatusDetail {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Diagnostic
    )

    process {
        [pscustomobject]@{
            TenantId                = $Diagnostic.TenantId
            IsGlobalAdministrator   = $Diagnostic.IsGlobalAdministrator
            MfaEnforcementStatus    = $Diagnostic.MfaEnforcementStatus
            UserPrincipalName       = $Diagnostic.UserPrincipalName
            DisplayName             = $Diagnostic.DisplayName
            Mail                    = $Diagnostic.Mail
            AccountEnabled          = $Diagnostic.AccountEnabled
            UserType                = $Diagnostic.UserType
            GraphMfaRegistered      = $Diagnostic.GraphMfaRegistered
            GraphMfaMethodCount     = $Diagnostic.GraphMfaMethodCount
            GraphMfaMethods         = $Diagnostic.GraphMfaMethods
            GraphAllAuthMethods     = $Diagnostic.GraphAllAuthMethods
            RemediationTargetState  = $Diagnostic.RemediationTargetState
            RemediationAction       = $Diagnostic.RemediationAction
            RemediationSkippedReason = $Diagnostic.RemediationSkippedReason
            RemediationError        = $Diagnostic.RemediationError
            MfaEnforcementReadError = $Diagnostic.MfaEnforcementReadError
            AuthenticationReadError = $Diagnostic.AuthenticationReadError
        }
    }
}

function Write-MfaStatusGroups {
    param(
        [Parameter(Mandatory)]
        [object[]]$Results
    )

    foreach ($status in @("Enforced", "Enabled", "Disabled", "Unknown")) {
        $statusResults = @($Results | Where-Object { $_.MfaEnforcementStatus -eq $status } | Sort-Object UserPrincipalName)

        Write-Host ""
        Write-Host "MFA enforcement status: $status ($($statusResults.Count))"

        if ($statusResults.Count -eq 0) {
            continue
        }

        $statusResults |
            Select-Object UserPrincipalName, DisplayName, AccountEnabled, IsGlobalAdministrator, GraphMfaRegistered, GraphMfaMethods, RemediationAction, RemediationSkippedReason, MfaEnforcementReadError |
            Format-Table -AutoSize
    }
}

function Get-EntraUsers {
    param(
        [string[]]$RequestedUpns
    )

    $properties = @(
        "id",
        "displayName",
        "userPrincipalName",
        "mail",
        "accountEnabled",
        "userType",
        "createdDateTime"
    )

    if ($RequestedUpns -and $RequestedUpns.Count -gt 0) {
        foreach ($upn in $RequestedUpns) {
            Get-MgUser -UserId $upn -Property $properties
        }
    }
    else {
        Get-MgUser -All -Property $properties
    }
}

function Get-UserAuthenticationDiagnostics {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [object]$User,

        [Parameter(Mandatory)]
        [System.Collections.Generic.HashSet[string]]$GlobalAdministratorUserIds
    )

    $methods = @()
    $methodErrors = $null

    try {
        $methods = @(Get-MgUserAuthenticationMethod -UserId $User.Id)
    }
    catch {
        $methodErrors = $_.Exception.Message
    }

    $methodTypes = @($methods | ForEach-Object { Get-MethodTypeName -Method $_ } | Sort-Object -Unique)
    $mfaMethodTypes = @($methodTypes | Where-Object { Test-IsMfaMethod -MethodType $_ })
    $mfaState = "Unknown"
    $mfaStateSource = "MicrosoftGraphBeta"
    $mfaStateError = $null

    $mfaStateResult = Get-GraphPerUserMfaState -UserId $User.Id
    $mfaState = $mfaStateResult.State
    $mfaStateError = $mfaStateResult.Error

    [pscustomobject]@{
        TenantId                = $TenantId
        UserId                  = $User.Id
        UserPrincipalName       = $User.UserPrincipalName
        DisplayName             = $User.DisplayName
        Mail                    = $User.Mail
        AccountEnabled          = $User.AccountEnabled
        UserType                = $User.UserType
        CreatedDateTime         = $User.CreatedDateTime
        IsGlobalAdministrator   = $GlobalAdministratorUserIds.Contains($User.Id)
        MfaEnforcementStatus    = $mfaState
        MfaEnforcementSource    = $mfaStateSource
        MfaEnforcementReadError = $mfaStateError
        GraphMfaRegistered      = ($mfaMethodTypes.Count -gt 0)
        GraphMfaMethodCount     = $mfaMethodTypes.Count
        GraphMfaMethods         = ($mfaMethodTypes -join ";")
        GraphAllAuthMethods     = ($methodTypes -join ";")
        RemediationTargetState  = $null
        RemediationAction       = $null
        RemediationSkippedReason = $null
        RemediationError        = $null
        AuthenticationReadError = $methodErrors
    }
}

New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

if ($IncludeLegacyPerUserMfaStatus) {
    Write-Warning "-IncludeLegacyPerUserMfaStatus is no longer required for Disabled/Enabled/Enforced. The script collects per-user MFA state with Microsoft Graph by default."
}

if (-not [string]::IsNullOrWhiteSpace($RemediateMfaState)) {
    Write-Warning "MFA remediation is enabled. Global Administrators will always be skipped. Use -PreviewRemediation or -WhatIf to preview write operations before applying changes."
}

$tenants = @(Get-TenantInputs -TenantIds $TenantId -ListPath $TenantListPath)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$allResults = New-Object System.Collections.Generic.List[object]
$allSummary = New-Object System.Collections.Generic.List[object]
$tenantErrors = New-Object System.Collections.Generic.List[object]

foreach ($tenant in $tenants) {
    $safeTenantName = Get-SafeFileName -Value $tenant
    $tenantOutputPath = Join-Path -Path $OutputPath -ChildPath $safeTenantName
    $detailPath = Join-Path -Path $tenantOutputPath -ChildPath "EntraMfaDiagnostics-$safeTenantName-$timestamp.csv"
    $summaryPath = Join-Path -Path $tenantOutputPath -ChildPath "EntraMfaDiagnostics-Summary-$safeTenantName-$timestamp.csv"
    $statusDetailPath = Join-Path -Path $tenantOutputPath -ChildPath "EntraMfaDiagnostics-MfaStatus-$safeTenantName-$timestamp.csv"

    New-Item -Path $tenantOutputPath -ItemType Directory -Force | Out-Null

    try {
        Write-Host ""
        Write-Host "===== Tenant: $tenant ====="

        Connect-EntraGraph -TenantId $tenant

        Write-Host "Collecting Global Administrator exclusions for tenant $tenant..."
        $globalAdministratorUserIds = Get-GlobalAdministratorUserIds
        if (-not [string]::IsNullOrWhiteSpace($RemediateMfaState) -and $globalAdministratorUserIds.Count -eq 0) {
            throw "No Global Administrator users were resolved for tenant $tenant. Remediation was not attempted because Global Administrators must remain untouched."
        }

        Write-Host "Collecting users for tenant $tenant..."
        $users = @(Get-EntraUsers -RequestedUpns $UserPrincipalName)

        $results = New-Object System.Collections.Generic.List[object]
        $index = 0

        foreach ($user in $users) {
            $index++
            Write-Progress -Activity "Collecting MFA diagnostics for $tenant" -Status $user.UserPrincipalName -PercentComplete (($index / [Math]::Max($users.Count, 1)) * 100)
            $diagnostic = Get-UserAuthenticationDiagnostics -TenantId $tenant -User $user -GlobalAdministratorUserIds $globalAdministratorUserIds

            if (-not [string]::IsNullOrWhiteSpace($RemediateMfaState)) {
                $remediationResult = Set-GraphPerUserMfaState -Diagnostic $diagnostic -TargetState $RemediateMfaState
                $diagnostic.RemediationTargetState = $RemediateMfaState
                $diagnostic.RemediationAction = $remediationResult.Action
                $diagnostic.RemediationSkippedReason = $remediationResult.Reason
                $diagnostic.RemediationError = $remediationResult.Error
            }

            $results.Add($diagnostic)
            $allResults.Add($diagnostic)
        }

        Write-Progress -Activity "Collecting MFA diagnostics for $tenant" -Completed

        $results |
            Sort-Object UserPrincipalName |
            Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8

        $results |
            Sort-Object MfaEnforcementStatus, UserPrincipalName |
            Select-MfaStatusDetail |
            Export-Csv -Path $statusDetailPath -NoTypeInformation -Encoding UTF8

        $summary = @(
            [pscustomobject]@{ TenantId = $tenant; Metric = "TotalUsers"; Count = $results.Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "MfaEnforcementStatusDisabled"; Count = @($results | Where-Object { $_.MfaEnforcementStatus -eq "Disabled" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "MfaEnforcementStatusEnabled"; Count = @($results | Where-Object { $_.MfaEnforcementStatus -eq "Enabled" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "MfaEnforcementStatusEnforced"; Count = @($results | Where-Object { $_.MfaEnforcementStatus -eq "Enforced" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "MfaEnforcementStatusUnknown"; Count = @($results | Where-Object { $_.MfaEnforcementStatus -eq "Unknown" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "GraphMfaRegistered"; Count = @($results | Where-Object { $_.GraphMfaRegistered }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "GraphMfaNotRegistered"; Count = @($results | Where-Object { -not $_.GraphMfaRegistered }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "GlobalAdministratorsExcludedFromRemediation"; Count = @($results | Where-Object { $_.IsGlobalAdministrator }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "RemediationUpdated"; Count = @($results | Where-Object { $_.RemediationAction -eq "Updated" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "RemediationPreview"; Count = @($results | Where-Object { $_.RemediationAction -eq "Preview" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "RemediationWhatIf"; Count = @($results | Where-Object { $_.RemediationAction -eq "WhatIf" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "RemediationSkipped"; Count = @($results | Where-Object { $_.RemediationAction -eq "Skipped" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "RemediationFailed"; Count = @($results | Where-Object { $_.RemediationAction -eq "Failed" }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "MfaEnforcementReadErrors"; Count = @($results | Where-Object { $_.MfaEnforcementReadError }).Count }
            [pscustomobject]@{ TenantId = $tenant; Metric = "AuthenticationReadErrors"; Count = @($results | Where-Object { $_.AuthenticationReadError }).Count }
        )

        $summary | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
        foreach ($summaryRow in $summary) {
            $allSummary.Add($summaryRow)
        }

        Write-Host "Tenant complete: $tenant"
        Write-Host "Detail report:  $detailPath"
        Write-Host "Summary report: $summaryPath"
        Write-Host "MFA status report: $statusDetailPath"
        $summary | Format-Table -AutoSize
        Write-MfaStatusGroups -Results $results
    }
    catch {
        Write-Warning "Tenant '$tenant' failed: $($_.Exception.Message)"
        $tenantError = [pscustomobject]@{
            TenantId = $tenant
            Error    = $_.Exception.Message
        }
        $tenantErrors.Add($tenantError)

        if ($StopOnTenantError) {
            throw
        }
    }
    finally {
        try {
            Disconnect-MgGraph | Out-Null
        }
        catch {
            # Ignore disconnect errors so the next tenant can still run.
        }
    }
}

$combinedDetailPath = Join-Path -Path $OutputPath -ChildPath "EntraMfaDiagnostics-AllTenants-$timestamp.csv"
$combinedSummaryPath = Join-Path -Path $OutputPath -ChildPath "EntraMfaDiagnostics-Summary-AllTenants-$timestamp.csv"
$combinedStatusDetailPath = Join-Path -Path $OutputPath -ChildPath "EntraMfaDiagnostics-MfaStatus-AllTenants-$timestamp.csv"
$tenantErrorsPath = Join-Path -Path $OutputPath -ChildPath "EntraMfaDiagnostics-TenantErrors-$timestamp.csv"

if ($allResults.Count -gt 0) {
    $allResults |
        Sort-Object TenantId, UserPrincipalName |
        Export-Csv -Path $combinedDetailPath -NoTypeInformation -Encoding UTF8

    $allResults |
        Sort-Object TenantId, MfaEnforcementStatus, UserPrincipalName |
        Select-MfaStatusDetail |
        Export-Csv -Path $combinedStatusDetailPath -NoTypeInformation -Encoding UTF8
}

if ($allSummary.Count -gt 0) {
    $allSummary |
        Sort-Object TenantId, Metric |
        Export-Csv -Path $combinedSummaryPath -NoTypeInformation -Encoding UTF8
}

if ($tenantErrors.Count -gt 0) {
    $tenantErrors | Export-Csv -Path $tenantErrorsPath -NoTypeInformation -Encoding UTF8
}

Write-Host ""
Write-Host "MFA diagnostics complete."
Write-Host "Tenants requested: $($tenants.Count)"
Write-Host "Tenants failed:    $($tenantErrors.Count)"
Write-Host "Combined detail:   $combinedDetailPath"
Write-Host "Combined summary:  $combinedSummaryPath"
Write-Host "Combined MFA status: $combinedStatusDetailPath"

if ($tenantErrors.Count -gt 0) {
    Write-Host "Tenant errors:     $tenantErrorsPath"
}

$allSummary | Format-Table -AutoSize

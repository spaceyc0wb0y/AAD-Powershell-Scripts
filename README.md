# AAD PowerShell Scripts

PowerShell utilities for Microsoft Entra ID/Azure AD administration and diagnostics.

The current script, `Get-EntraMfaDiagnostics.ps1`, collects user MFA information across one or more Entra tenants and exports CSV reports.

## Features

- Runs against one tenant or several tenants in one execution.
- Pulls user inventory from Microsoft Graph.
- Reports registered authentication methods for each user.
- Reports per-user MFA state: `Disabled`, `Enabled`, or `Enforced`.
- Clearly separates Graph MFA method registration from legacy MFA enforcement state.
- Creates per-tenant reports and combined all-tenant reports.
- Continues to the next tenant if one tenant fails, unless `-StopOnTenantError` is used.

## Requirements

- PowerShell 7+ on macOS, Linux, or Windows.
- Tenant admin permissions to consent to/read:
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `Directory.Read.All`
  - `Policy.Read.All`
- Microsoft Graph PowerShell modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Identity.SignIns`

The script can install missing modules for the current user when run with `-InstallMissingModules`.

## Quick Start

On macOS or Linux, run against one tenant:

```powershell
./Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com
```

On Windows, run against one tenant:

```powershell
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com
```

On first run, install missing Microsoft Graph modules for the current user:

```powershell
./Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com -InstallMissingModules
```

If the sign-in window does not open or the script appears to stop at the tenant banner, use device-code sign-in:

```powershell
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com -UseDeviceAuthentication
```

Run against multiple tenants:

```powershell
.\Get-EntraMfaDiagnostics.ps1 `
  -TenantId contoso.onmicrosoft.com,fabrikam.onmicrosoft.com
```

Run from a tenant list file:

```powershell
.\Get-EntraMfaDiagnostics.ps1 `
  -TenantListPath .\tenants.txt
```

Use `tenants.example.txt` as the format reference:

```text
contoso.onmicrosoft.com
fabrikam.onmicrosoft.com
```

## Per-User MFA State

Microsoft Graph authentication methods show whether users have MFA-capable methods registered. That is not the same thing as whether per-user MFA is disabled, enabled, or enforced.

The script reads per-user MFA state from the Microsoft Graph beta authentication requirements endpoint. Microsoft documents this as `perUserMfaState` under `/users/{id}/authentication/requirements`. Because this endpoint is in Graph beta, Microsoft notes that the API is subject to change.

This state is the per-user MFA state. Conditional Access policies and security defaults can require MFA without changing a user's per-user MFA state.

The detail CSV always includes `MfaEnforcementStatus`:

- `Disabled`, `Enabled`, or `Enforced` is the per-user MFA state returned by Microsoft Graph.
- `Unknown` means the state could not be read. Check `MfaEnforcementReadError` for the reason.

## Output

By default, reports are written to:

```text
.\EntraMfaDiagnostics\
```

Each tenant gets its own folder containing:

- `EntraMfaDiagnostics-<tenant>-<timestamp>.csv`
- `EntraMfaDiagnostics-Summary-<tenant>-<timestamp>.csv`
- `EntraMfaDiagnostics-MfaStatus-<tenant>-<timestamp>.csv`

The root output folder also contains combined reports:

- `EntraMfaDiagnostics-AllTenants-<timestamp>.csv`
- `EntraMfaDiagnostics-Summary-AllTenants-<timestamp>.csv`
- `EntraMfaDiagnostics-MfaStatus-AllTenants-<timestamp>.csv`
- `EntraMfaDiagnostics-TenantErrors-<timestamp>.csv`, only when failures occur

The MFA status report is sorted by `MfaEnforcementStatus` and `UserPrincipalName`, so the `Disabled`, `Enabled`, `Enforced`, and `Unknown` users are grouped together with their registered authentication method details.

## Useful Parameters

| Parameter | Description |
| --- | --- |
| `-TenantId` | One or more tenant IDs or verified domains. |
| `-TenantListPath` | Text file with one tenant per line. Lines beginning with `#` are ignored. |
| `-UserPrincipalName` | Optional list of specific users to inspect. |
| `-OutputPath` | Custom report output folder. |
| `-IncludeLegacyPerUserMfaStatus` | Deprecated compatibility switch. Per-user MFA state is collected by default with Microsoft Graph. |
| `-InstallMissingModules` | Installs required modules for the current user. |
| `-StopOnTenantError` | Stops the run when a tenant fails. |
| `-UseDeviceAuthentication` | Uses device-code sign-in when browser sign-in hangs or is unavailable. |

## Security Notes

Generated reports contain sensitive user and authentication information. Do not commit report files, customer tenant lists, credentials, tokens, certificates, or production exports.

The `.gitignore` is configured to exclude common report outputs and local tenant files.

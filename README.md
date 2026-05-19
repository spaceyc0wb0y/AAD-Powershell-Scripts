# AAD PowerShell Scripts

PowerShell utilities for Microsoft Entra ID/Azure AD administration and diagnostics.

The current script, `Get-EntraMfaDiagnostics.ps1`, collects user MFA information across one or more Entra tenants and exports CSV reports.

## Features

- Runs against one tenant or several tenants in one execution.
- Pulls user inventory from Microsoft Graph.
- Reports registered authentication methods for each user.
- Optionally reports legacy per-user MFA state: `Disabled`, `Enabled`, or `Enforced`.
- Creates per-tenant reports and combined all-tenant reports.
- Continues to the next tenant if one tenant fails, unless `-StopOnTenantError` is used.

## Requirements

- Windows PowerShell or PowerShell 7+
- Tenant admin permissions to consent to/read:
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `Directory.Read.All`
- Microsoft Graph PowerShell modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Identity.SignIns`
- Optional legacy MFA status support:
  - `MSOnline`

The script can install missing modules for the current user when run with `-InstallMissingModules`.

## Quick Start

Run against one tenant:

```powershell
.\Get-EntraMfaDiagnostics.ps1 -TenantId contoso.onmicrosoft.com
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

## Legacy Per-User MFA State

Microsoft Graph reports authentication methods registered by users. The exact values `Disabled`, `Enabled`, and `Enforced` are legacy per-user MFA states exposed by the `MSOnline` module.

To include those values:

```powershell
.\Get-EntraMfaDiagnostics.ps1 `
  -TenantListPath .\tenants.txt `
  -IncludeLegacyPerUserMfaStatus
```

When prompted for MSOnline, sign in with an admin account for the tenant being processed.

## Output

By default, reports are written to:

```text
.\EntraMfaDiagnostics\
```

Each tenant gets its own folder containing:

- `EntraMfaDiagnostics-<tenant>-<timestamp>.csv`
- `EntraMfaDiagnostics-Summary-<tenant>-<timestamp>.csv`

The root output folder also contains combined reports:

- `EntraMfaDiagnostics-AllTenants-<timestamp>.csv`
- `EntraMfaDiagnostics-Summary-AllTenants-<timestamp>.csv`
- `EntraMfaDiagnostics-TenantErrors-<timestamp>.csv`, only when failures occur

## Useful Parameters

| Parameter | Description |
| --- | --- |
| `-TenantId` | One or more tenant IDs or verified domains. |
| `-TenantListPath` | Text file with one tenant per line. Lines beginning with `#` are ignored. |
| `-UserPrincipalName` | Optional list of specific users to inspect. |
| `-OutputPath` | Custom report output folder. |
| `-IncludeLegacyPerUserMfaStatus` | Adds legacy `Disabled`/`Enabled`/`Enforced` MFA state. |
| `-InstallMissingModules` | Installs required modules for the current user. |
| `-StopOnTenantError` | Stops the run when a tenant fails. |
| `-UseDeviceAuthentication` | Uses device-code sign-in when browser sign-in hangs or is unavailable. |

## Security Notes

Generated reports contain sensitive user and authentication information. Do not commit report files, customer tenant lists, credentials, tokens, certificates, or production exports.

The `.gitignore` is configured to exclude common report outputs and local tenant files.

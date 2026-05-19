# Repository Guidelines

## Project Structure & Module Organization

This repository currently contains standalone PowerShell utilities for Entra ID/Azure AD diagnostics.

- `Get-EntraMfaDiagnostics.ps1`: Main script for collecting MFA diagnostics across one or more Entra tenants.
- `tenants.example.txt`: Example input file for batch tenant runs.
- Generated reports are written to `EntraMfaDiagnostics/` by default. Do not commit report CSVs unless they are sanitized samples.

If the repository grows, place reusable functions in a `modules/` directory and tests in a `tests/` directory.

## Build, Test, and Development Commands

There is no build step for this repository. Validate scripts with PowerShell before use:

```powershell
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path ".\Get-EntraMfaDiagnostics.ps1"),
  [ref]$tokens,
  [ref]$errors
) | Out-Null
$errors
```

Run the MFA diagnostic script with:

```powershell
.\Get-EntraMfaDiagnostics.ps1 -TenantListPath .\tenants.txt -IncludeLegacyPerUserMfaStatus
```

Use `-InstallMissingModules` only when module installation is expected and approved.

## Coding Style & Naming Conventions

- Use PowerShell advanced script patterns with `[CmdletBinding()]` and explicit `param()` blocks.
- Use four-space indentation.
- Name scripts and functions with approved verb-noun style, for example `Get-EntraMfaDiagnostics.ps1`.
- Prefer clear parameter names such as `-TenantId`, `-OutputPath`, and `-StopOnTenantError`.
- Keep comments focused on non-obvious behavior, especially Graph versus legacy MSOnline differences.

## Testing Guidelines

No automated test framework is configured yet. At minimum, run a parser check after edits and perform a limited tenant test with one known account or small tenant scope.

Future tests should use Pester and live behind `tests/`, with names like:

```text
tests/Get-EntraMfaDiagnostics.Tests.ps1
```

Avoid tests that require real tenant credentials unless they are clearly marked as integration tests.

## Commit & Pull Request Guidelines

No existing Git history is available in this workspace, so use concise, descriptive commit messages:

```text
Add multi-tenant MFA diagnostics
Fix tenant list parsing
```

Pull requests should include a short summary, validation performed, affected scripts, and any required permissions or modules. For tenant-facing changes, mention whether Microsoft Graph, MSOnline, or both are affected.

## Security & Configuration Tips

Do not commit tenant reports, exported user data, credentials, access tokens, or customer tenant lists. Treat MFA status and authentication method exports as sensitive administrative data.

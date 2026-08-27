# Repository Guidelines

## Project Structure & Module Organization

PowerShell tooling for Active Directory and Entra ID: assessment, reporting,
backup, and cross-domain migration.

```
Export-AdEnvironment.ps1        Back up a whole AD environment into one package
New-AdPrincipalMap.ps1          Build the old-to-new principal mapping
Import-AdEnvironment.ps1        Rebuild that package in a new domain
Invoke-AdSecurityScan.ps1       Read-only security assessment
Test-EntraSyncReadiness.ps1     Entra Connect sync pre-flight (IdFix-class)
Set-AdUpnSuffix.ps1             Add a routable UPN suffix and reassign user UPNs
Get-EntraMfaDiagnostics.ps1     Multi-tenant Entra MFA reporting/remediation
modules/ADMigrationKit/         Shared helpers and the export package schema
tests/Invoke-SmokeTests.ps1     Offline parser check plus helper unit tests
docs/MIGRATION-RUNBOOK.md       Step-by-step cross-domain rebuild procedure
```

Reusable logic belongs in `modules/ADMigrationKit`, not duplicated across
scripts. Anything with branching logic worth testing should live there, because
that is the only code the offline tests can reach.

Generated reports and export packages are never committed. See `.gitignore`.

## Runtime targets

Two different targets, deliberately:

- **Windows PowerShell 5.1** for every AD script and for `ADMigrationKit`. These
  run on domain controllers and member servers, where 5.1 is what exists. Do not
  use PowerShell 7 syntax: no ternary `? :`, no `??`, no `-Parallel`, no
  `Join-String`.
- **PowerShell 7+** for `Get-EntraMfaDiagnostics.ps1`, which is cross-platform.

Keep new files ASCII-only.

## Build, Test, and Development Commands

There is no build step. Run the offline test suite after every edit:

```powershell
.\tests\Invoke-SmokeTests.ps1
```

It parser-checks every `.ps1` and `.psm1` in the repository and unit-tests the
`ADMigrationKit` helpers. It needs no AD, no tenant, and no network. It must pass
before any commit.

To parser-check a single file:

```powershell
$tokens = $null; $errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path ".\Export-AdEnvironment.ps1"), [ref]$tokens, [ref]$errors) | Out-Null
$errors
```

## Coding Style & Naming Conventions

- Advanced script pattern: `[CmdletBinding()]` and an explicit `param()` block.
- Four-space indentation.
- Approved verb-noun names. Module functions use the `Ak` prefix
  (`Get-AkPackageItemPath`) to keep them distinct from AD cmdlets.
- `Set-StrictMode -Version Latest` and `$ErrorActionPreference = "Stop"` at the
  top of every script.
- Read possibly-absent properties with `Get-AkPropertyValue`. Under StrictMode a
  direct access to a missing property is fatal, and both CSV rows and AD objects
  vary in which properties are present.
- **Return arrays with the unary comma**: `return ,@($items)`. A bare
  `return @()` is unrolled by the pipeline into `$null`, and the caller's
  `.Count` then throws under StrictMode. This has already caused one bug.
- Any script that modifies AD, GPOs, or shares must support
  `SupportsShouldProcess` and honour `-WhatIf` on every write.
- Comment the non-obvious: locale-dependent built-in group names, gPLink
  precedence ordering, what `Import-GPO` silently does not restore. Skip comments
  that restate the code.

## Testing Guidelines

`tests/Invoke-SmokeTests.ps1` is the only suite runnable off a domain. Add a case
there for any new helper with real logic, especially anything touching DNs, SIDs,
gPLink parsing, or the package schema.

The AD, GPO, and SMB **write** paths cannot be tested from a workstation. When
changing them, rehearse against a lab domain or a snapshot and say plainly in the
pull request what was and was not exercised. Never imply a write path was
verified when only the parser ran.

For end-to-end read-path work, build a synthetic package (users.csv, groups.csv,
manifest.json) and run `New-AdPrincipalMap.ps1` and `Test-EntraSyncReadiness.ps1`
against it. Both work with no live directory.

## Commit & Pull Request Guidelines

Concise, descriptive commit messages:

```text
Add cross-domain AD export and rebuild tooling
Fix gPLink precedence ordering on import
```

Pull requests should state the summary, the validation actually performed, the
affected scripts, and any required modules or permissions. For anything that
writes to a directory, say explicitly whether it was tested against a live domain.

## Security & Configuration Tips

An export package is a complete description of a directory and its file
permissions, and `import\generated-passwords.csv` is plaintext credentials for
every migrated account. Both are credential-grade secrets.

Never commit: export packages, scan output, tenant reports, principal maps,
migration tables, generated password files, customer tenant or domain lists,
credentials, or tokens. The `.gitignore` covers the known patterns; check it
still covers anything new you add.

Keep the read-only scripts genuinely read-only. `Export-AdEnvironment.ps1` and
`Invoke-AdSecurityScan.ps1` must never write to the directory they inspect.

# AAD PowerShell Scripts

PowerShell tooling for Active Directory and Microsoft Entra ID administration:
assessment, reporting, backup, and cross-domain migration.

The intended workflow is to clone this repository onto a domain-joined machine
and run it against the directory in front of you.

## What is here

| Script | Purpose | Writes? |
| --- | --- | --- |
| `Invoke-AdSecurityScan.ps1` | Security assessment with severity-ranked findings and specific remediation advice. | Read-only |
| `Test-EntraSyncReadiness.ps1` | Finds the object problems that break Entra Connect sync, IdFix-style. Runs against a live domain or an export package. | Read-only |
| `Test-EntraAdAlignment.ps1` | Compares AD users against the Entra tenant (Graph sign-in with self-installed dependency, or a portal CSV offline) and reports what would duplicate, rename, or strip on sync-scope widening. | Read-only |
| `Set-AdUpnSuffix.ps1` | Registers a routable UPN suffix in the forest and reassigns user UPNs onto it, via a reviewable plan CSV. Classifies each proposed UPN against a tenant export so a soft-match target is not confused with a duplicate. | **Writes to AD** |
| `Export-AdEnvironment.ps1` | Backs up the whole environment (OUs, users, groups, GPOs, WMI filters, shares, NTFS ACLs) into one portable package. | Read-only |
| `New-AdPrincipalMap.ps1` | Builds the reviewable old-to-new principal mapping that drives a rebuild. | Writes one CSV |
| `Import-AdEnvironment.ps1` | Rebuilds an exported environment in a **new domain with a new name**, with no trust or connectivity to the old one. | **Writes to AD** |
| `Sync-EntraUsersToAd.ps1` | Provisions cloud-only Entra users into an on-premises OU on a schedule, so they can reach shares and printers. | **Writes to AD** |
| `Get-EntraMfaDiagnostics.ps1` | Multi-tenant Entra MFA reporting and optional per-user MFA remediation. | Optional writes |

Shared logic lives in `modules/ADMigrationKit`. Offline tests are in
`tests/Invoke-SmokeTests.ps1`.

## Quick start

Assess the domain you are standing in:

```powershell
.\Invoke-AdSecurityScan.ps1 -HtmlReport
```

Check whether it is ready to sync to Entra:

```powershell
.\Test-EntraSyncReadiness.ps1 -VerifiedDomain contoso.com
```

Cross-check AD against the tenant before widening a sync scope - finds the
duplicates-in-waiting, cloud renames, mailbox-rename and stripped-alias risks,
and lists the cloud-only users `Sync-EntraUsersToAd.ps1` should provision.
Installs its own Graph dependency (Microsoft.Graph.Authentication, current
user) on first run; `-TenantUserCsv` is the offline fallback:

```powershell
.\Test-EntraAdAlignment.ps1 -UseDeviceCode
.\Test-EntraAdAlignment.ps1 -TenantUserCsv .\exportUsers.csv -VerifiedDomain contoso.com
```

Back up everything, including all GPOs:

```powershell
.\Export-AdEnvironment.ps1 -OutputPath D:\Backup -FileServer FS01
```

## Requirements

- **Windows PowerShell 5.1** for the Active Directory scripts. They run on domain
  controllers and member servers, so they deliberately avoid PowerShell 7 syntax.
- **PowerShell 7+** for `Get-EntraMfaDiagnostics.ps1`, which is cross-platform.
- RSAT: `Install-WindowsFeature RSAT-AD-PowerShell, RSAT-Group-Policy-Mgmt-Tools`
- Domain Admin rights for the import; a domain user is enough for the read-only
  scans, though some checks report more detail with higher privilege.

---

# Migrating to a new domain

`Export-AdEnvironment.ps1` -> `New-AdPrincipalMap.ps1` -> `Import-AdEnvironment.ps1`
rebuilds an environment in a brand new domain, with **no trust, no replication,
and no network path** between old and new. The only thing that moves is a folder
you copy by hand.

**Read [`docs/MIGRATION-RUNBOOK.md`](docs/MIGRATION-RUNBOOK.md) before running any
of it.** The short version:

```powershell
# On the OLD domain
.\Export-AdEnvironment.ps1 -OutputPath D:\Migration -FileServer OLDFS01 -AclDepth 2

# Copy the package folder to the NEW domain controller, then:
.\Test-EntraSyncReadiness.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500
.\New-AdPrincipalMap.ps1 -PackagePath $pkg -TargetDomainDns corp.contoso.com -TargetUpnSuffix contoso.com

#  >>> REVIEW import\principal-map.csv BEFORE CONTINUING <<<

.\Import-AdEnvironment.ps1 -PackagePath $pkg -WhatIf
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase OrganizationalUnits,Groups,Users,Membership
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Gpo,GpoLinks -ReplaceServerName @{ 'OLDFS01' = 'NEWFS01' }
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Validate -ReplaceServerName @{ 'OLDFS01' = 'NEWFS01' }
```

### Three things that surprise people

1. **Passwords and SID history do not migrate.** Both need a trust and ADMT.
   Accounts get generated passwords (written to a CSV in the package) and brand
   new SIDs. Because the SIDs are new, every ACL has to be re-pointed — that is
   what the principal map is for, and it is the real work of the migration.

2. **`Import-GPO` restores GPO contents and nothing else.** Links, link order,
   enforcement, and WMI filter associations are all captured and replayed
   separately by this tooling. Note that in the raw `gPLink` attribute the GPO
   listed *last* has the *highest* precedence; the export records both the raw
   position and the resolved GPMC link order so precedence survives intact.

3. **The GPO migration table does not catch everything.** Group Policy
   Preferences XML, drive maps especially, keeps references to the old domain.
   The `Validate` phase re-reads every imported GPO and reports exactly what is
   left, with the setting types to check.

### Entra hybrid notes

- The rebuild creates **new `objectGUID`s**, so any previously synced object's
  `ImmutableId` no longer matches. Plan soft match (by UPN or primary SMTP) or a
  deliberate hard-match reset. `mail` and `proxyAddresses` are preserved by the
  export precisely so soft matching can work.
- A `.local` UPN suffix **cannot sync**. Add and verify a routable domain and
  reassign UPNs before enabling sync, or users get rewritten to
  `onmicrosoft.com`. `Test-EntraSyncReadiness.ps1` flags this as Critical.
- Narrow the sync scope off *All objects* before you enable it.

---

# Security scanning

```powershell
.\Invoke-AdSecurityScan.ps1 -OutputPath C:\Reports -HtmlReport
.\Invoke-AdSecurityScan.ps1 -MinimumSeverity High
```

Read-only. Every finding carries a severity, the affected object, and a specific
recommendation. Checks cover:

- **Identity hygiene** — stale and never-used accounts, ancient passwords,
  password-never-expires, `PASSWD_NOTREQD`, enabled Guest account.
- **Credential exposure** — Kerberoastable service accounts, AS-REP roastable
  accounts, reversible encryption, DES-only Kerberos, and `cpassword` values in
  SYSVOL (MS14-025, where the decryption key is public).
- **Privilege** — membership of every privileged and legacy operator group,
  orphaned `adminCount`, krbtgt password age, Protected Users adoption.
- **Delegation** — unconstrained delegation, constrained delegation with
  protocol transition, resource-based delegation.
- **Domain configuration** — functional levels, `ms-DS-MachineAccountQuota`,
  AD Recycle Bin, password policy, Pre-Windows 2000 Compatible Access
  membership, LAPS deployment, unsupported operating systems.

A check that cannot complete is reported as a finding rather than skipped
silently, so gaps in coverage stay visible.

---

# Provisioning cloud users into AD

`Sync-EntraUsersToAd.ps1` runs on a schedule, reads the cloud-only members of an
Entra security group, and creates them as real AD accounts in an OU you choose.
It is the fix for a user who exists only in Entra and therefore cannot open a
file share or print.

Adapted from [Azure-Samples/B2B-to-AD-Sync][b2bsample], which does the same
Graph-plus-scheduled-task dance for B2B **guests** feeding Application Proxy.
This one targets cloud-only **members** and gives them full accounts.

[b2bsample]: https://github.com/Azure-Samples/B2B-to-AD-Sync

```powershell
# Always preview first. Reads Graph and AD, writes the plan CSV, changes nothing.
.\Sync-EntraUsersToAd.ps1 -TenantId contoso.com -ClientId 1111... `
    -CertificateThumbprint AABB... -EntraGroupObjectId 2222... `
    -TargetOu "OU=Cloud Users,DC=ad,DC=contoso,DC=com" -WhatIf
```

**Read [`docs/ENTRA-TO-AD-SYNC.md`](docs/ENTRA-TO-AD-SYNC.md) before deploying
it.** Three things decide whether this works:

1. **Passwords cannot be synchronised down.** Graph never exposes a password, so
   new accounts get a generated one, written to a credential-grade CSV. In a
   tenant already running Entra Connect or Cloud Sync, the new AD account soft
   matches the cloud user, the sync takes it over, and password hash sync then
   makes the AD password authoritative for both - so the user does end up with
   one password, but it is the generated one. That CSV is the handoff.
2. **The target OU has to be inside the Cloud Sync scope**, or the takeover in
   point 1 never happens and the user ends up with two accounts.
3. **The cloud UPN suffix has to be registered in the forest.** Use
   `Set-AdUpnSuffix.ps1` first. An account created with the wrong UPN will never
   soft match.

Users already synced from AD are always skipped, so it cannot loop against Entra
Connect. The Entra objectId is stamped on each AD object as an anchor, so an
account created by hand earlier is adopted rather than duplicated. Nothing is
ever deleted; an account whose Entra user leaves the scope is reported as an
orphan and, optionally, disabled and moved.

Microsoft's supported product for this direction is Entra API-driven inbound
provisioning to on-premises AD, which needs Entra ID Governance licensing. This
is the unlicensed small-tenant equivalent.

---

# Testing

```powershell
.\tests\Invoke-SmokeTests.ps1
```

Parser-checks every script and unit-tests the helper logic. No AD, tenant, or
network access needed. Run it after any edit.

The AD, GPO, and SMB **write** paths cannot be tested from a workstation.
Rehearse those in a lab or against a snapshot.

---

# Entra MFA diagnostics

`Get-EntraMfaDiagnostics.ps1` collects user MFA information across one or more Entra tenants and exports CSV reports.
It can also optionally remediate per-user MFA state for non-Global Administrator users.

## Features

- Runs against one tenant or several tenants in one execution.
- Pulls user inventory from Microsoft Graph.
- Reports registered authentication methods for each user.
- Reports per-user MFA state: `Disabled`, `Enabled`, or `Enforced`.
- Clearly separates Graph MFA method registration from legacy MFA enforcement state.
- Creates per-tenant reports and combined all-tenant reports.
- Continues to the next tenant if one tenant fails, unless `-StopOnTenantError` is used.
- Optionally enables or enforces per-user MFA for users below the requested target state.
- Always excludes Global Administrators from MFA remediation.

## Requirements

- PowerShell 7+ on macOS, Linux, or Windows.
- Tenant admin permissions to consent to/read:
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `Directory.Read.All`
  - `Policy.Read.All`
  - `RoleManagement.Read.Directory`
- For MFA remediation, consent to/write:
  - `Policy.ReadWrite.AuthenticationMethod`
- Microsoft Graph PowerShell modules:
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Users`
  - `Microsoft.Graph.Identity.SignIns`

The script can install missing modules for the current user when run with `-InstallMissingModules`.

## Quick Start

Start the interactive Matrix-style console by running the script without parameters. It scans and reports first, then asks which eligible users should be enforced:

```powershell
.\Get-EntraMfaDiagnostics.ps1
```

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

## MFA Remediation

By default, the script only reports. To change per-user MFA state, use `-RemediateMfaState Enabled` or `-RemediateMfaState Enforced`.

For an interactive flow with the green console banner, scan results, and a post-scan enforcement picker, run:

```powershell
.\Get-EntraMfaDiagnostics.ps1 -InteractiveMenu
```

Interactive remediation scans and displays the report first, then lists only eligible licensed, enabled, non-Global Administrator users whose per-user MFA state is `Disabled` or `Enabled`. Choose `all`, `none`, or comma-separated row numbers to decide who gets enforced.

Preview the changes first:

```powershell
.\Get-EntraMfaDiagnostics.ps1 `
  -TenantId contoso.onmicrosoft.com `
  -RemediateMfaState Enforced `
  -PreviewRemediation
```

Apply the changes:

```powershell
.\Get-EntraMfaDiagnostics.ps1 `
  -TenantId contoso.onmicrosoft.com `
  -RemediateMfaState Enforced `
  -Confirm:$false
```

Remediation behavior:

- `Enabled` updates users currently `Disabled`.
- `Enforced` updates users currently `Disabled` or `Enabled`.
- Global Administrators are always skipped.
- Disabled and unlicensed user accounts are always ignored for remediation.
- `Unknown` MFA states are reported but not remediated.

Remediation results are written to the detail and MFA status CSVs with `RemediationTargetState`, `RemediationAction`, `RemediationSkippedReason`, and `RemediationError`.

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
| `-RemediateMfaState` | Optional target state, `Enabled` or `Enforced`, for per-user MFA remediation. |
| `-PreviewRemediation` | Reports which users would be remediated without applying MFA changes. |
| `-IncludeDisabledAccountsForRemediation` | Deprecated compatibility switch. Disabled accounts are always ignored for remediation. |
| `-InteractiveMenu` | Starts the old-school console menu and post-scan user picker. |
| `-WhatIf` | Shows the per-user MFA changes that would be made without applying them. |

## Security Notes

Generated reports contain sensitive user and authentication information. Do not commit report files, customer tenant lists, credentials, tokens, certificates, or production exports.

Per-user MFA remediation uses the Microsoft Graph beta authentication requirements endpoint and changes tenant user security posture. Disabled and unlicensed accounts are ignored for remediation. Preview with `-PreviewRemediation` or `-WhatIf`, review the CSV output, and use a limited `-UserPrincipalName` scope before broad rollout.

The `.gitignore` is configured to exclude common report outputs and local tenant files.

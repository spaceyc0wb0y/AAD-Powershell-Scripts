# Cross-Domain AD Rebuild Runbook

Rebuilding an existing Active Directory environment in a **new domain with a new
name**, with **no trust, no replication, and no connectivity** between the two,
and landing on a **hybrid Entra ID** setup.

The only thing that moves between the domains is a folder you copy by hand.

---

## What comes across, and what does not

| Comes across | Does not come across | Why not |
| --- | --- | --- |
| OU tree, with structure and protection flags | **Passwords** | Hashes cannot leave a domain without a trust and ADMT. Every account gets a new generated password. |
| Users and their attributes | **SID history** | Also requires a trust and ADMT. New accounts get new SIDs. |
| Groups, membership, primary groups | **Computer accounts** | Workstations and member servers must be rejoined to the new domain. They are exported as inventory only. |
| GPO contents, links, link order, enforcement | **Certificates issued by the old CA** | A new domain means a new PKI trust chain. |
| WMI filters, with their filter IDs preserved | **Anything keyed to an old SID** | This is what the principal map exists to re-point. |
| SMB shares, share permissions, NTFS ACLs | **The file data itself** | Copy data with robocopy separately; this tool moves permissions, not bytes. |
| Fine-grained and default password policies | | |

The single most important consequence: **because SIDs change, every access
control entry has to be re-pointed.** That is not a detail to handle later, it is
the core of the work, and the principal map is where you control it.

---

## Order of operations

```
  OLD DOMAIN                    sneakernet                 NEW DOMAIN
  ----------                    ----------                 ----------
  1. Export-AdEnvironment  ──►  copy package folder  ──►  2. New-AdPrincipalMap
                                                          3. REVIEW THE MAP
                                                          4. Import (-WhatIf)
                                                          5. Import (for real)
                                                          6. Validate
                                                          7. Entra Connect
```

---

## Step 1 — Export from the old domain

Run on a machine with RSAT that can reach the old DC and the file servers.

```powershell
.\Export-AdEnvironment.ps1 -OutputPath D:\Migration -FileServer OLDFS01 -AclDepth 2
```

`-AclDepth` controls how deep below each share root NTFS permissions are
captured. Depth 2 is usually right: it catches per-department folders without
walking a million files. Raise it only if permissions are set deeper than that.

You get one timestamped folder, for example
`D:\Migration\AdExport-old.local-20260827-101500`, containing everything.

**Sanity check before you move on**: open `manifest.json` and confirm the object
counts match what you expect. An export that silently scoped down is much easier
to catch here than after the rebuild.

Copy the whole folder to the new DC. Treat it as a credential-grade secret; it
is a complete description of your directory and its permissions.

---

## Step 2 — Pre-flight the data for Entra, before you rebuild

Do this now, against the package, so you fix problems once instead of twice.

```powershell
.\Test-EntraSyncReadiness.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500
```

Fix every **Critical** finding. The two that matter most:

- **`UnroutableUpnSuffix`** — `.local` UPNs cannot sync. Users get rewritten to
  `onmicrosoft.com`, which is disruptive to undo. Decide the routable suffix now
  and pass it to the next step as `-TargetUpnSuffix`.
- **`DuplicateUpn` / `DuplicateProxyAddress`** — Entra Connect refuses to sync
  **both** objects in a duplicate pair, so one collision costs you two accounts.

---

## Step 3 — Build the principal map

```powershell
.\New-AdPrincipalMap.ps1 `
  -PackagePath D:\Migration\AdExport-old.local-20260827-101500 `
  -TargetDomainDns corp.contoso.com `
  -TargetUpnSuffix contoso.com `
  -QueryTargetDomain
```

This writes `import\principal-map.csv` inside the package. It is the one file
that decides who becomes whom.

### Step 4 — Review the map. Do not skip this.

Open the CSV and work through it:

| Action | Meaning | What to check |
| --- | --- | --- |
| `Create` | Will be recreated | Is this account still needed? A migration is the cheapest time to leave dead accounts behind. |
| `MapToBuiltIn` | Matched to a built-in by RID | Normally correct as-is. |
| `Keep` | Well-known SID, identical everywhere | Nothing to do. |
| `MapToExisting` | Already exists in the target | Confirm it is genuinely the same person. |
| `Review` | Referenced by an ACL but absent from the export | Usually an orphaned SID from a deleted account. Decide: map it, or let the ACE be dropped. |
| `Skip` | Excluded | Confirm intentional. |

Any row whose `Notes` starts with `COLLISION:` **must** be resolved before you
import, by editing `TargetSamAccountName` or `TargetUpn` to something unique.

Edit `TargetSamAccountName`, `TargetUpn`, and `Action` freely. Re-running the
generator with `-Force` **overwrites your edits**, so once you have reviewed it,
either stop re-generating or keep a copy.

---

## Step 5 — Rehearse the import

```powershell
.\Import-AdEnvironment.ps1 -PackagePath D:\Migration\AdExport-old.local-20260827-101500 -WhatIf
```

Read the output. `-WhatIf` reports many "would create X once its parent exists"
lines, which is expected: nothing is actually created, so later phases cannot see
what earlier ones would have made. What you are looking for are **unmapped
principals** and **missing containers**.

---

## Step 6 — Import for real

Run phase by phase rather than all at once. It is easier to verify, and every
phase is re-runnable.

```powershell
$pkg = "D:\Migration\AdExport-old.local-20260827-101500"

.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase OrganizationalUnits
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Groups
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Users
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Membership
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase WmiFilters
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Gpo -ReplaceServerName @{ 'OLDFS01' = 'NEWFS01' }
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase GpoLinks
```

`-ReplaceServerName` is what re-points UNC paths inside GPOs — drive maps, folder
redirection, logon scripts, deployed printers. **Omit it and every drive mapping
will still point at the old, unreachable file server.**

After the Users phase, `import\generated-passwords.csv` contains a plaintext
password for every account created. Distribute securely and delete it once
people have signed in.

### Shares

Run this **on the file server**, after the data has been copied across:

```powershell
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Shares `
  -SharePathMap @{ 'D:\Shares' = 'E:\Data' } `
  -ReplaceServerName @{ 'OLDFS01' = 'NEWFS01' }
```

`-SharePathMap` handles the case where the data landed on a different drive
letter or path than it occupied on the old server.

---

## Step 7 — Validate

```powershell
.\Import-AdEnvironment.ps1 -PackagePath $pkg -Phase Validate -ReplaceServerName @{ 'OLDFS01' = 'NEWFS01' }
```

This re-reads every imported GPO and reports anything still referencing the old
domain or old servers.

**Expect findings here.** The GPO migration table is best-effort and does not
reach everything — Group Policy Preferences XML in particular. The usual
offenders, in rough order of frequency:

1. **Drive maps** (`Preferences > Windows Settings > Drive Maps`)
2. **Folder redirection** targets
3. **Deployed printers**
4. **Logon/logoff script** paths
5. **Shortcuts** pointing at old UNC paths
6. **Security filtering** on groups the table could not map

Fix each in the Group Policy Management Console, then re-run the Validate phase
until it is clean or every remaining hit is understood and accepted.

---

## Step 8 — Hybrid Entra

Before installing Entra Connect:

```powershell
.\Test-EntraSyncReadiness.ps1 -VerifiedDomain contoso.com
```

Then, in order:

1. **Add and verify the public domain in the tenant** before syncing anything.
2. **Add the routable UPN suffix** in Active Directory Domains and Trusts, and
   confirm every user's UPN uses it. This is the step most often discovered too
   late.
3. **Narrow the sync scope.** Do not leave it on *All objects*. Scope to the OUs
   you actually want in the cloud. Service accounts, disabled accounts, and
   built-in containers do not belong in the tenant.
4. **Decide matching before the first sync.**
   - *Soft match* joins an existing cloud user to the new on-premises user by
     primary SMTP address or UPN. This is why the export preserves `mail` and
     `proxyAddresses`, and why it matters that you did not change them.
   - *Hard match* uses `ImmutableId` (derived from `objectGUID`). **The rebuild
     creates new objectGUIDs**, so any previously synced object's `ImmutableId`
     is now wrong. If the tenant already holds these users, either clear the
     cloud `ImmutableId` and let soft match run, or set it explicitly from the
     new objects.
5. **Run a preview sync and read the export errors** before enabling the
   scheduler.

> If the tenant already contains these users from the *old* domain's sync, plan
> this explicitly. Two on-premises sources claiming the same cloud object is the
> single most disruptive thing that can happen at this stage.

---

## Rollback

Nothing in this process touches the old domain — the export is strictly read-only,
so the old environment remains a working fallback for as long as you keep it.

In the new domain, roll back by deleting the imported OU tree (enable the AD
Recycle Bin **first**), the imported GPOs, and the created shares. Importing into
a dedicated `-TargetOuRoot` makes this considerably easier.

---

## What has and has not been tested

- The helper logic — DN translation, gPLink parsing and precedence, RDN
  extraction, password generation, package round-trips — is covered by
  `tests\Invoke-SmokeTests.ps1` and passes.
- Every script passes a PowerShell parser check.
- The export/map/readiness data flow has been exercised end to end against a
  synthetic package.
- **The AD, GPO, and SMB write paths have not been executed against a live
  domain.** They cannot be, from a workstation. Rehearse in a lab or a snapshot
  before running against anything you care about.

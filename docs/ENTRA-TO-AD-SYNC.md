# Entra ID to on-premises AD user sync

`Sync-EntraUsersToAd.ps1` provisions cloud-only Microsoft Entra ID users into a
local Active Directory OU on a schedule, so people who only exist in the cloud
get a real on-premises identity and can reach file shares, printers, and
anything else that authenticates with Kerberos or NTLM.

It is adapted from [Azure-Samples/B2B-to-AD-Sync][sample], which shadows B2B
**guests** into AD for Application Proxy and Kerberos constrained delegation.
The shape is the same - Microsoft Graph plus a scheduled task plus shadow AD
objects - but the population is the opposite one: cloud-only **members**, given
full accounts rather than stubs.

[sample]: https://github.com/Azure-Samples/B2B-to-AD-Sync

---

## Read this first: the password

**Microsoft Graph never exposes a user's password.** There is no API, no
permission, and no licence that returns it. Nothing can copy an Entra password
down into AD. Any tool claiming otherwise is either resetting the password or
lying.

So the script generates a password for each new AD account and writes it to
`generated-passwords-<stamp>.csv`. That file is the handoff, not a byproduct.

In a tenant that already runs Entra Connect or Entra Cloud Sync, that is enough
to end up with one password again:

1. The script creates the AD account with the same UPN (and the same primary
   SMTP address, if `-SyncProxyAddresses` is used).
2. On its next cycle the sync engine **soft matches** that AD account to the
   existing cloud user, on UPN or primary SMTP, and takes it over.
3. With password hash sync on, the **AD** password becomes authoritative for
   both on-premises and cloud sign-in.
4. The user flips to `onPremisesSyncEnabled = true`, so the next run of this
   script skips them. Steady state is self-cleaning.

The user's password therefore changes once, at takeover, to the generated one.
The two ways to handle that:

- Hand the generated password over and let `-ChangePasswordAtLogon` (the
  default) force a change at first sign in.
- Or run with `-NoChangePasswordAtLogon` and have the user do one self-service
  password reset. This needs **password writeback** enabled, which is a
  Microsoft Entra ID P1 feature.

If you want none of this: Microsoft's supported product for cloud-to-AD
provisioning is **Entra API-driven inbound provisioning to on-premises Active
Directory**, using the provisioning agent. It needs Microsoft Entra ID
Governance licensing. This script is the unlicensed equivalent for a small
tenant, and it is a script, not a product.

---

## What it does each run

| Situation | Action |
| --- | --- |
| Cloud-only Entra member in scope, no AD account | **Create** in `-TargetOu` with a generated password |
| AD account already carries the Entra objectId anchor | **Update** the mapped attributes that drifted |
| AD account matches on UPN but has no anchor | **Update**, adopting the account and stamping the anchor |
| AD account disabled, Entra account enabled | **Enable** |
| AD account anchored to an Entra user no longer in scope | **Orphan** - reported, and optionally disabled and moved |
| Entra user already synced from AD | **Skip**. This is what stops it fighting Entra Connect |
| AD account in the OU with no anchor | Left completely alone. Not this tool's object |

Accounts are never deleted.

The Entra `objectId` is stamped on the AD object in `-AnchorAttribute`
(`adminDescription` by default, which exists in the base schema on every
forest). Matching is by anchor first, UPN second, which is what lets the script
adopt an account somebody created by hand rather than duplicating it.

Attributes copied: given name, surname, display name, mail, job title,
department, company, office, business phone, mobile, street, city, state,
postal code, usage location (into `c`), and employee ID. On-premises-only data
is left alone unless `-ClearAbsent` is passed.

---

## Prerequisites

### 1. A routable UPN suffix in the forest

New accounts are created with the cloud UPN. If the forest does not have that
suffix registered, the creation fails - and it must fail, because an account
with the wrong UPN will never soft match.

```powershell
(Get-ADForest).UPNSuffixes
```

If your domain is `ad.contoso.com` and users are
`someone@contoso.com`, register the suffix first. `Set-AdUpnSuffix.ps1` in
this repository does that and reassigns existing users onto it.

`-SkipUpnSuffixCheck` exists, but skipping the check does not make the creation
succeed. It just moves where it fails.

### 2. A target OU inside the Cloud Sync scope

Create the OU new accounts land in, then confirm the Entra Connect / Cloud Sync
configuration includes it. If the sync scope does not cover that OU, the
takeover in step 2 above never happens and the user is left with two separate
accounts and two separate passwords.

```powershell
New-ADOrganizationalUnit -Name "Cloud Users" -Path "OU=CORP - Users,DC=ad,DC=contoso,DC=com"
```

### 3. An app registration

In Entra ID > App registrations > New registration (single tenant).

Grant **application** permissions under Microsoft Graph, then grant admin
consent:

| Permission | Why |
| --- | --- |
| `User.Read.All` | Read the users to provision |
| `GroupMember.Read.All` | Read the members of the scope group |

Create a certificate on the machine that will run the task and upload the
public key:

```powershell
# On the domain controller, as an administrator
$cert = New-SelfSignedCertificate -Subject "CN=EntraToAdSync" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -KeyExportPolicy NonExportable -KeySpec Signature `
    -NotAfter (Get-Date).AddYears(2)

Export-Certificate -Cert $cert -FilePath C:\Temp\EntraToAdSync.cer
$cert.Thumbprint
```

Upload `EntraToAdSync.cer` under Certificates & secrets > Certificates. Keep
the thumbprint.

A client secret works too (`-ClientSecret`), but it expires and it ends up in
whatever launches the script. Prefer the certificate.

### 4. A scope group

Create a security group in Entra and put the users to provision in it. Note its
object ID.

Scoping by group is the default on purpose. `-AllCloudOnlyUsers` takes every
cloud-only member in the tenant, and break-glass accounts, licence-holder
service accounts, and shared mailbox identities are all cloud-only. Use it only
if you know that list is clean.

Removing a user from the scope group makes them an orphan on the next run.
That is the deprovisioning path, not a bug - but it means the group membership
is now load-bearing.

### 5. A service account for the scheduled task

A gMSA is the right answer. It needs:

- Delegated rights to create, delete, and manage user objects in `-TargetOu`
  (and in `-OrphanOu`, if used). Delegation Wizard on the OU, or `dsacls`.
- Read access to the certificate's private key.
- Membership in the AD groups it must add users to, or at least write access to
  those groups' membership.

```powershell
New-ADServiceAccount -Name svc-entrasync -DNSHostName dc1.ad.contoso.com `
    -PrincipalsAllowedToRetrieveManagedPassword "DC1-SRV$"
Install-ADServiceAccount -Identity svc-entrasync
```

Grant it the private key:

```powershell
$cert = Get-ChildItem Cert:\LocalMachine\My\<thumbprint>
$path = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\" +
        $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$acl = Get-Acl $path
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    "AD\svc-entrasync$", "Read", "Allow")))
Set-Acl $path $acl
```

On a CNG key (which `-KeySpec Signature` on modern Windows gives you) the
container lives under `Microsoft\Crypto\Keys` instead; the simpler route is
certlm.msc > the certificate > All Tasks > Manage Private Keys.

---

## First run

Always preview. `-WhatIf` reads Graph and AD, writes the plan CSV, and changes
nothing.

```powershell
.\Sync-EntraUsersToAd.ps1 `
    -TenantId contoso.com `
    -ClientId 1111... `
    -CertificateThumbprint AABB... `
    -EntraGroupObjectId 2222... `
    -TargetOu "OU=Cloud Users,OU=CORP - Users,DC=ad,DC=contoso,DC=com" `
    -OutputPath D:\EntraSync `
    -WhatIf
```

Read `D:\EntraSync\entra-to-ad-plan-<stamp>.csv` before doing anything else.
Every row has an Action and a Reason. Confirm that:

- Nothing you did not expect is in **Create**.
- No service or break-glass account appears at all.
- The **Skip** rows say "Already synced from on-premises AD" for the people who
  should already be hybrid.

Then run it for real:

```powershell
.\Sync-EntraUsersToAd.ps1 -TenantId contoso.com -ClientId 1111... `
    -CertificateThumbprint AABB... -EntraGroupObjectId 2222... `
    -TargetOu "OU=Cloud Users,OU=CORP - Users,DC=ad,DC=contoso,DC=com" `
    -AddToGroup "Firm Staff","Printer Users" `
    -OutputPath D:\EntraSync
```

`-AddToGroup` is where the actual share and printer access comes from. A new AD
account in an OU grants nothing on its own.

Collect `generated-passwords-<stamp>.csv`, hand the credentials over, and delete
the file. It is plaintext credentials for every account created in that run, and
`.gitignore` keeps it out of the repository but not off the disk.

---

## Scheduling it

Hourly is usually right. More often than that just burns Graph calls; less often
and a new hire waits.

```powershell
$script = "C:\Scripts\AAD-Powershell-Scripts\Sync-EntraUsersToAd.ps1"
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$script`"" +
    " -TenantId contoso.com -ClientId 1111..." +
    " -CertificateThumbprint AABB... -EntraGroupObjectId 2222..." +
    " -TargetOu `"OU=Cloud Users,OU=CORP - Users,DC=ad,DC=contoso,DC=com`"" +
    " -AddToGroup `"Firm Staff`" -OrphanAction Report" +
    " -OutputPath D:\EntraSync -Confirm:`$false"

$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)
$principal = New-ScheduledTaskPrincipal -UserId "AD\svc-entrasync$" -LogonType Password -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName "Entra to AD user sync" -Action $action `
    -Trigger $trigger -Principal $principal -Settings $settings
```

`-Confirm:$false` is belt and braces. `-MultipleInstances IgnoreNew` matters:
two concurrent runs can both decide the same user needs creating.

The task's exit code is 1 if any individual operation failed, so a monitoring
system can watch it. Each run leaves a log and a plan CSV in `-OutputPath`;
prune that folder, nothing rotates it.

Start with `-OrphanAction Report` and read the output for a few weeks before
moving to `Disable` or `DisableAndMove`. An orphan is usually a group membership
mistake, not a departure.

---

## Troubleshooting

**`AADSTS700027` / invalid client assertion.** The certificate uploaded to the
app registration is not the one being used, or the thumbprint passed does not
match a certificate in the store the task can read. A task running as a gMSA
reads `LocalMachine`, not `CurrentUser`.

**`Keyset does not exist` when signing.** The service account cannot read the
certificate's private key. See the private key grant above.

**`Insufficient privileges to complete the operation` from Graph.** The
permissions are delegated rather than application, or admin consent was never
granted. Check the app registration shows a green tick under API permissions.

**Everything comes back as Skip.** The users are already synced from AD, which
is the correct answer. Confirm in Entra that the ones you expect show
`onPremisesSyncEnabled` false.

**A user was created but the cloud account was not taken over.** The target OU
is outside the Cloud Sync scope, or the UPN does not match, or Cloud Sync has
not run yet. Check the sync scope first; that is the usual one.

**The UPN suffix check fails.** Register the suffix. See prerequisite 1.

**A user was created twice.** The anchor attribute was not readable on the first
run, or `-AnchorAttribute` was changed between runs. The script refuses to run
if the anchor attribute is absent from the schema, but changing it mid-life
orphans everything stamped with the old one.

---

## What was and was not tested

The Microsoft Graph paging and the AD write paths in this script have not been
exercised against a live tenant or a live domain. What has been verified:

- The offline suite in `tests/Invoke-SmokeTests.ps1`, which parser-checks the
  script and unit-tests the planning logic: eligibility, attribute delta,
  sAMAccountName derivation and collisions, and every action the planner can
  return.
- The hand-rolled client assertion, against a throwaway in-memory certificate:
  three JWT segments, `x5t` equal to the base64url of the raw SHA-1 certificate
  hash bytes, and an RS256 signature that verifies with the public key.

Rehearse the write path in a lab domain before pointing it at production.

<#
.SYNOPSIS
Adds a routable UPN suffix to the forest and reassigns user userPrincipalName
values onto it, using a reviewable CSV plan.

.DESCRIPTION
An unroutable UPN suffix such as @ad.contoso.com cannot be synchronized to
Microsoft Entra ID. Those users are rewritten to <name>@<tenant>.onmicrosoft.com,
which breaks sign-in expectations and, more importantly, breaks the UPN match
that soft-matching depends on when adopting cloud accounts into AD.

This script runs in two passes, deliberately, because a UPN change is visible to
every user on their next sign-in and is not something to do from a one-liner:

  Plan      Default. Reads the domain, derives a proposed UPN for every user,
            classifies it against an optional tenant export, and writes ONE CSV
            for a human to review and correct.
  Apply     -ApplyMap <csv>. Re-reads that CSV and writes only the rows still
            marked Action=Change, verifying each account still holds the UPN the
            plan recorded before touching it.

Supply -TenantUserCsv to catch the case that actually hurts: renaming a synced
user onto a UPN some other cloud object already holds, which fails the next sync
with a duplicate-attribute error. The same collision is desirable for an AD
account that is not yet synced, since that is how soft-matching adopts an
existing cloud user. The script tells those two apart and marks the dangerous
one Review. See Resolve-AkUpnTenantMatch in ADMigrationKit.

Export the tenant CSV from the Entra admin center: Entra ID > Users >
Download users. No Graph module is needed on the domain controller.

This script deliberately does NOT write mail or proxyAddresses. Once an account
is synced those on-premises values master the cloud ones, so a wrong value
silently renames somebody's email address. Address book attributes belong to the
account-adoption step, not to a UPN suffix change.

.PARAMETER UpnSuffix
The routable suffix to move users onto, for example contoso.com. It must already
be verified in the tenant.

.PARAMETER AddSuffixToForest
Register UpnSuffix in Active Directory Domains and Trusts if it is not already
present. Writes to the Partitions container in the Configuration naming context,
so this needs Enterprise Admins, not just Domain Admins.

.PARAMETER SearchBase
Limit the plan to one OU subtree. Strongly recommended: without it every user in
the domain is planned, service accounts included.

.PARAMETER Server
Domain controller to read from and write to.

.PARAMETER Credential
Credentials for the domain.

.PARAMETER TenantUserCsv
Entra user export used for collision classification.

.PARAMETER OutputPath
Folder for the plan and result CSVs.

.PARAMETER ApplyMap
Path to a reviewed plan CSV. Switches the script into Apply mode.

.PARAMETER IncludeDisabled
Include disabled accounts. Off by default.

.PARAMETER IncludeCurrentSuffix
Plan users who already use a routable suffix other than UpnSuffix. Off by
default, so a domain part-way through a rename is not undone.

.PARAMETER Force
Overwrite an existing plan CSV, or apply with a suffix that is not registered in
the forest.

.EXAMPLE
.\Set-AdUpnSuffix.ps1 -UpnSuffix contoso.com -AddSuffixToForest -SearchBase "OU=Staff,DC=ad,DC=contoso,DC=com" -TenantUserCsv .\entra-users.csv

.EXAMPLE
.\Set-AdUpnSuffix.ps1 -UpnSuffix contoso.com -ApplyMap .\UpnSuffix\upn-plan-20260827-120000.csv -WhatIf

.NOTES
Windows PowerShell 5.1. Requires the ActiveDirectory module.
Plan mode is read-only except -AddSuffixToForest, which writes the forest
suffix list. Every write in both modes is ShouldProcess-gated and honours -WhatIf.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$UpnSuffix,

    [switch]$AddSuffixToForest,

    [string]$SearchBase,

    [string]$Server,

    [System.Management.Automation.PSCredential]$Credential,

    [string]$TenantUserCsv,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "UpnSuffix"),

    [string]$ApplyMap,

    [switch]$IncludeDisabled,

    [switch]$IncludeCurrentSuffix,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Start-AkLog -Path (Join-Path -Path $OutputPath -ChildPath "upn-suffix-$timestamp.log")

Assert-AkModule -Name "ActiveDirectory" -Reason "reading and writing user objects"

$UpnSuffix = $UpnSuffix.Trim().TrimStart("@").ToLowerInvariant()
if ($UpnSuffix -notlike "*.*") {
    throw "UpnSuffix '$UpnSuffix' is single label. Entra ID cannot use a non-routable suffix."
}

# Splat reused for every AD cmdlet so -Server and -Credential stay optional.
$adParams = @{}
if ($Server) { $adParams["Server"] = $Server }
if ($Credential) { $adParams["Credential"] = $Credential }


function Get-CsvColumnName {
    <#
    .SYNOPSIS
    Finds a column by any of several candidate names, ignoring case and spaces.
    The Entra portal export has renamed its columns more than once.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()]$Row,
        [Parameter(Mandatory)][string[]]$Candidate
    )

    if ($null -eq $Row) { return $null }

    $names = @($Row.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($wanted in $Candidate) {
        $normalizedWanted = ($wanted -replace "[\s_]", "").ToLowerInvariant()
        foreach ($name in $names) {
            if (($name -replace "[\s_]", "").ToLowerInvariant() -eq $normalizedWanted) {
                return $name
            }
        }
    }

    return $null
}


function Get-PrimarySmtp {
    <#
    .SYNOPSIS
    Returns the primary SMTP address from proxyAddresses, or an empty string.
    The primary entry is the one with an uppercase SMTP: prefix, so the match
    must be case sensitive.
    #>
    param(
        [AllowNull()]$ProxyAddresses
    )

    foreach ($proxy in @($ProxyAddresses)) {
        $text = [string]$proxy
        if ($text -cmatch "^SMTP:") {
            return $text.Substring(5)
        }
    }

    return ""
}


function Get-TenantIndex {
    <#
    .SYNOPSIS
    Builds a UPN-keyed lookup of tenant objects and their directory-sync state.
    #>
    param(
        [Parameter(Mandatory)][string]$Path
    )

    $rows = @(Import-AkCsv -Path $Path -Required)
    if ($rows.Count -eq 0) {
        throw "Tenant export '$Path' contains no rows."
    }

    $upnColumn = Get-CsvColumnName -Row $rows[0] -Candidate @(
        "userPrincipalName", "User principal name", "UPN", "SignInName"
    )
    if (-not $upnColumn) {
        throw "Tenant export '$Path' has no recognizable user principal name column."
    }

    # Absent from some export vintages. When it is missing every matched object
    # is classified Unknown, which forces a human decision rather than guessing.
    $syncColumn = Get-CsvColumnName -Row $rows[0] -Candidate @(
        "directorySynced", "dirSyncEnabled", "onPremisesSyncEnabled",
        "Directory synced", "On-premises sync enabled"
    )
    if (-not $syncColumn) {
        Write-AkLog -Message "Tenant export has no directory-sync column. Matches will be reported as Unknown." -Level Warning
    }

    $index = @{}
    foreach ($row in $rows) {
        $upn = [string](Get-AkPropertyValue -InputObject $row -Name $upnColumn -Default "")
        if ([string]::IsNullOrWhiteSpace($upn)) { continue }
        $key = $upn.Trim().ToLowerInvariant()

        $state = "Unknown"
        if ($syncColumn) {
            $raw = [string](Get-AkPropertyValue -InputObject $row -Name $syncColumn -Default "")
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                if ($raw.Trim() -match "^(true|yes|1)$") { $state = "Synced" }
                elseif ($raw.Trim() -match "^(false|no|0)$") { $state = "CloudOnly" }
            }
        }

        if (-not $index.ContainsKey($key)) {
            $index[$key] = [PSCustomObject]@{
                Upn   = $upn.Trim()
                State = $state
            }
        }
    }

    Write-AkLog -Message "Tenant export: $($index.Count) unique UPNs from $($rows.Count) rows." -Level Info
    return $index
}


function Get-TenantState {
    param(
        [AllowNull()]$Index,
        [AllowEmptyString()][string]$Upn
    )

    if ($null -eq $Index) { return "Absent" }
    if ([string]::IsNullOrWhiteSpace($Upn)) { return "Absent" }

    $key = $Upn.Trim().ToLowerInvariant()
    if ($Index.ContainsKey($key)) {
        return $Index[$key].State
    }

    return "Absent"
}


function Invoke-PlanMode {
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "  UPN SUFFIX PLAN" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""

    $planPath = Join-Path -Path $OutputPath -ChildPath "upn-plan-$timestamp.csv"
    if ((Test-Path -LiteralPath $planPath) -and -not $Force) {
        throw "Plan '$planPath' already exists. Use -Force to overwrite, so hand edits are never silently discarded."
    }

    $forest = Get-ADForest @adParams
    $registered = @($forest.UPNSuffixes) | ForEach-Object { $_.ToLowerInvariant() }
    $suffixRegistered = ($registered -contains $UpnSuffix) -or ($forest.RootDomain.ToLowerInvariant() -eq $UpnSuffix)

    if ($suffixRegistered) {
        Write-AkLog -Message "Suffix '@$UpnSuffix' is already registered in the forest." -Level Success
    }
    elseif ($AddSuffixToForest) {
        if ($PSCmdlet.ShouldProcess($forest.Name, "Add UPN suffix '$UpnSuffix'")) {
            Set-ADForest -Identity $forest.Name -UPNSuffixes @{Add = $UpnSuffix} @adParams
            Write-AkLog -Message "Added UPN suffix '@$UpnSuffix' to forest $($forest.Name)." -Level Success
            $suffixRegistered = $true
        }
    }
    else {
        Write-AkLog -Message "Suffix '@$UpnSuffix' is NOT registered in the forest. Re-run with -AddSuffixToForest, or add it in Active Directory Domains and Trusts." -Level Warning
    }

    $tenantIndex = $null
    if ($TenantUserCsv) {
        $tenantIndex = Get-TenantIndex -Path $TenantUserCsv
    }
    else {
        Write-AkLog -Message "No -TenantUserCsv supplied. UPN collisions against the tenant will not be checked." -Level Warning
    }

    $userParams = @{
        Filter     = "*"
        Properties = @("UserPrincipalName", "DisplayName", "mail", "proxyAddresses", "Enabled")
    }
    if ($SearchBase) { $userParams["SearchBase"] = $SearchBase }

    Write-AkLog -Message "Reading users..." -Level Step
    $users = @(Get-ADUser @userParams @adParams)
    if (-not $IncludeDisabled) {
        $users = @($users | Where-Object { $_.Enabled })
    }
    Write-AkLog -Message "Read $($users.Count) user(s)." -Level Info

    # Every current UPN in the domain, so a proposal that lands on another AD
    # account is caught before it reaches the tenant at all.
    $adUpnIndex = @{}
    foreach ($user in $users) {
        $existing = [string](Get-AkPropertyValue -InputObject $user -Name "UserPrincipalName" -Default "")
        if ([string]::IsNullOrWhiteSpace($existing)) { continue }
        $key = $existing.Trim().ToLowerInvariant()
        if (-not $adUpnIndex.ContainsKey($key)) { $adUpnIndex[$key] = @() }
        $adUpnIndex[$key] += $user.DistinguishedName
    }

    $proposalCount = @{}
    $rows = @()

    foreach ($user in $users) {
        $sam = [string](Get-AkPropertyValue -InputObject $user -Name "SamAccountName" -Default "")
        $currentUpn = [string](Get-AkPropertyValue -InputObject $user -Name "UserPrincipalName" -Default "")
        $mail = [string](Get-AkPropertyValue -InputObject $user -Name "mail" -Default "")
        $proxies = @(Get-AkPropertyValue -InputObject $user -Name "proxyAddresses" -Default @())
        $primarySmtp = Get-PrimarySmtp -ProxyAddresses $proxies

        $currentSuffix = ""
        $currentPrefix = ""
        if ($currentUpn -like "*@*") {
            $currentPrefix = $currentUpn.Substring(0, $currentUpn.LastIndexOf("@"))
            $currentSuffix = $currentUpn.Substring($currentUpn.LastIndexOf("@") + 1).ToLowerInvariant()
        }

        # Prefer the local part of the mail address the user already publishes:
        # that is what the cloud object is keyed on, so it is what soft-matching
        # needs. Fall back to the existing UPN prefix, then sAMAccountName.
        $sourceAddress = $primarySmtp
        if ([string]::IsNullOrWhiteSpace($sourceAddress)) { $sourceAddress = $mail }

        $proposedPrefix = ""
        if ($sourceAddress -like "*@*") {
            $proposedPrefix = $sourceAddress.Substring(0, $sourceAddress.LastIndexOf("@"))
        }
        elseif (-not [string]::IsNullOrWhiteSpace($currentPrefix)) {
            $proposedPrefix = $currentPrefix
        }
        elseif (-not [string]::IsNullOrWhiteSpace($sam)) {
            $proposedPrefix = $sam
        }

        $proposedUpn = ""
        if (-not [string]::IsNullOrWhiteSpace($proposedPrefix)) {
            $proposedUpn = "$proposedPrefix@$UpnSuffix"
        }

        $prefixSource = "None"
        if ($sourceAddress -like "*@*") { $prefixSource = "PrimarySmtp" }
        elseif (-not [string]::IsNullOrWhiteSpace($currentPrefix)) { $prefixSource = "CurrentUpn" }
        elseif (-not [string]::IsNullOrWhiteSpace($sam)) { $prefixSource = "SamAccountName" }

        $verdict = Resolve-AkUpnTenantMatch `
            -CurrentUpn $currentUpn `
            -ProposedUpn $proposedUpn `
            -CurrentCloudState (Get-TenantState -Index $tenantIndex -Upn $currentUpn) `
            -ProposedCloudState (Get-TenantState -Index $tenantIndex -Upn $proposedUpn) `
            -TenantDataAvailable:($null -ne $tenantIndex)

        $action = $verdict.Action
        $note = $verdict.Note

        # A routable suffix unrelated to the target is left alone unless asked
        # for, so a partially renamed domain is not dragged backwards. A
        # subdomain of the target, such as ad.contoso.com under contoso.com, is
        # never keepable: see Test-AkKeepableUpnSuffix.
        if ($action -eq "Change" -and -not $IncludeCurrentSuffix -and
            (Test-AkKeepableUpnSuffix -CurrentSuffix $currentSuffix -TargetSuffix $UpnSuffix)) {
            $action = "Skip"
            $note = "Already uses routable suffix '@$currentSuffix'. Re-run with -IncludeCurrentSuffix to move it."
        }

        if ($action -eq "Change" -and $proposedUpn) {
            $collisionKey = $proposedUpn.ToLowerInvariant()
            if ($adUpnIndex.ContainsKey($collisionKey) -and
                ($adUpnIndex[$collisionKey] -notcontains $user.DistinguishedName)) {
                $action = "Review"
                $note = "Another AD account already holds '$proposedUpn'."
            }
        }

        if ($proposedUpn) {
            $dupKey = $proposedUpn.ToLowerInvariant()
            if (-not $proposalCount.ContainsKey($dupKey)) { $proposalCount[$dupKey] = 0 }
            $proposalCount[$dupKey]++
        }

        $rows += [PSCustomObject]@{
            SamAccountName    = $sam
            DisplayName       = [string](Get-AkPropertyValue -InputObject $user -Name "DisplayName" -Default "")
            Enabled           = [string](Get-AkPropertyValue -InputObject $user -Name "Enabled" -Default "")
            DistinguishedName = $user.DistinguishedName
            CurrentUpn        = $currentUpn
            CurrentSuffix     = $currentSuffix
            Mail              = $mail
            PrimarySmtp       = $primarySmtp
            ProposedUpn       = $proposedUpn
            PrefixSource      = $prefixSource
            TenantMatch       = $verdict.TenantMatch
            Action            = $action
            Note              = $note
        }
    }

    # Two accounts proposing the same UPN is only visible after every row exists.
    foreach ($row in $rows) {
        if (-not $row.ProposedUpn) { continue }
        $dupKey = $row.ProposedUpn.ToLowerInvariant()
        if ($proposalCount[$dupKey] -gt 1 -and $row.Action -eq "Change") {
            $row.Action = "Review"
            $row.Note = "$($proposalCount[$dupKey]) accounts propose the same UPN '$($row.ProposedUpn)'. Disambiguate before applying."
        }
    }

    Export-AkCsv -InputObject $rows -Path $planPath

    $changeCount = @($rows | Where-Object { $_.Action -eq "Change" }).Count
    $reviewCount = @($rows | Where-Object { $_.Action -eq "Review" }).Count
    $skipCount = @($rows | Where-Object { $_.Action -eq "Skip" }).Count
    $adoptCount = @($rows | Where-Object { $_.TenantMatch -eq "CloudOnlyMatch" }).Count

    Write-Host ""
    Write-AkLog -Message "Change: $changeCount   Review: $reviewCount   Skip: $skipCount" -Level Info
    if ($adoptCount -gt 0) {
        Write-AkLog -Message "$adoptCount row(s) will soft-match onto an existing cloud-only account." -Level Info
    }
    if ($reviewCount -gt 0) {
        Write-AkLog -Message "$reviewCount row(s) need a decision. They are skipped on apply until you change Action to Change." -Level Warning
    }
    if (-not $suffixRegistered) {
        Write-AkLog -Message "Register the suffix in the forest before applying, or apply refuses to run." -Level Warning
    }

    Write-Host ""
    Write-AkLog -Message "Plan written to $planPath" -Level Success
    Write-AkLog -Message "Review it, then: .\Set-AdUpnSuffix.ps1 -UpnSuffix $UpnSuffix -ApplyMap `"$planPath`" -WhatIf" -Level Info
}


function Invoke-ApplyMode {
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "  UPN SUFFIX APPLY" -ForegroundColor Cyan
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""

    $forest = Get-ADForest @adParams
    $registered = @($forest.UPNSuffixes) | ForEach-Object { $_.ToLowerInvariant() }
    if (-not (($registered -contains $UpnSuffix) -or ($forest.RootDomain.ToLowerInvariant() -eq $UpnSuffix)) -and -not $Force) {
        throw "Suffix '@$UpnSuffix' is not registered in forest $($forest.Name). Run with -AddSuffixToForest first, or -Force to proceed anyway."
    }

    $plan = @(Import-AkCsv -Path $ApplyMap -Required)
    $targets = @($plan | Where-Object { [string](Get-AkPropertyValue -InputObject $_ -Name "Action" -Default "") -eq "Change" })

    Write-AkLog -Message "Plan holds $($plan.Count) row(s); $($targets.Count) marked Change." -Level Info

    $results = @()
    $changed = 0
    $skipped = 0
    $failed = 0

    foreach ($row in $targets) {
        $dn = [string](Get-AkPropertyValue -InputObject $row -Name "DistinguishedName" -Default "")
        $expectedUpn = [string](Get-AkPropertyValue -InputObject $row -Name "CurrentUpn" -Default "")
        $newUpn = [string](Get-AkPropertyValue -InputObject $row -Name "ProposedUpn" -Default "")
        $sam = [string](Get-AkPropertyValue -InputObject $row -Name "SamAccountName" -Default "")

        $status = "Skipped"
        $detail = ""

        try {
            if ([string]::IsNullOrWhiteSpace($dn) -or [string]::IsNullOrWhiteSpace($newUpn)) {
                throw "Row is missing DistinguishedName or ProposedUpn."
            }
            if ($newUpn -notlike "*@*") {
                throw "ProposedUpn '$newUpn' is not in user@domain form."
            }

            $user = Get-ADUser -Identity $dn -Properties UserPrincipalName @adParams
            $actualUpn = [string](Get-AkPropertyValue -InputObject $user -Name "UserPrincipalName" -Default "")

            # The plan is a snapshot. If the account moved on since it was built,
            # do not write over whatever changed it.
            if ($actualUpn -ne $expectedUpn) {
                $status = "Skipped"
                $detail = "UPN is now '$actualUpn' but the plan recorded '$expectedUpn'. Re-plan this account."
                $skipped++
            }
            elseif ($actualUpn -eq $newUpn) {
                $status = "Skipped"
                $detail = "Already set."
                $skipped++
            }
            elseif ($PSCmdlet.ShouldProcess($dn, "Set userPrincipalName to '$newUpn'")) {
                Set-ADUser -Identity $dn -UserPrincipalName $newUpn @adParams
                $status = "Changed"
                $detail = "$expectedUpn -> $newUpn"
                $changed++
                Write-AkLog -Message "$sam : $detail" -Level Success
            }
            else {
                $status = "WhatIf"
                $detail = "$expectedUpn -> $newUpn"
            }
        }
        catch {
            $status = "Failed"
            $detail = $_.Exception.Message
            $failed++
            Write-AkLog -Message "$sam : $detail" -Level Error
        }

        $results += [PSCustomObject]@{
            SamAccountName    = $sam
            DistinguishedName = $dn
            PreviousUpn       = $expectedUpn
            NewUpn            = $newUpn
            Status            = $status
            Detail            = $detail
        }
    }

    $resultPath = Join-Path -Path $OutputPath -ChildPath "upn-apply-$timestamp.csv"
    Export-AkCsv -InputObject $results -Path $resultPath

    Write-Host ""
    Write-AkLog -Message "Changed: $changed   Skipped: $skipped   Failed: $failed" -Level Info
    Write-AkLog -Message "Results written to $resultPath" -Level Success
    if ($changed -gt 0) {
        Write-AkLog -Message "Users must now sign in to Microsoft 365 with the new UPN. Domain sign-in with sAMAccountName is unaffected." -Level Warning
    }
}


try {
    if ($ApplyMap) {
        Invoke-ApplyMode
    }
    else {
        Invoke-PlanMode
    }
}
finally {
    Stop-AkLog
}

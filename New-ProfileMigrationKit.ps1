<#
.SYNOPSIS
Builds a ForensiT User Profile Wizard deployment kit for moving workstation
profiles onto the new domain, plus an inventory of which profiles are local
only and therefore exist nowhere but on their workstation.

.DESCRIPTION
Rejoining a workstation to a rebuilt domain gives every user a new SID and
therefore a brand-new empty profile. ForensiT's User Profile Wizard (Profwiz)
solves this the right way round: it re-ACLs the EXISTING local profile and
re-points it at the new domain account - nothing is copied, so it is fast and
safe. What Profwiz cannot know is your migration's specifics: the domains, the
renamed accounts, which machines matter. This script generates all of that
from the same export package and live domain the rest of this toolkit uses.

It writes a self-contained kit folder:

  Profwiz.exe        Copied from -ProfwizFolder (ForensiT's download - their
                     software is licensed and never ships with this toolkit).
  Profwiz.config     The vendor's own template with this migration's values
                     merged in: new domain, old domain, exclusions, options.
  Users.csv          Old-name,new-name lookup rows generated from the
                     principal map - only written when accounts were renamed.
  Migrate.ps1        The startup/RMM script: exits if the machine is already
                     on the new domain, otherwise runs Profwiz silently.
  profiles-inventory.csv
                     When -ComputerName is given: every real profile on every
                     reachable machine, who owns it, whether it is roaming or
                     LOCAL ONLY, and when it was last used. This is the
                     migration-planning answer to "whose data lives only on
                     their workstation?".

Deploy the folder with your RMM (runs as SYSTEM) or as a GPO computer startup
script, per ForensiT's Corporate Edition guide. Domain-join credentials are
deliberately NOT written in plain text: run ForensiT's Deployment Kit over the
generated config to add encrypted <DomainPwd>/<Key> values, or supply
-JoinCredential to accept plaintext with your eyes open.

.PARAMETER ProfwizFolder
Folder holding ForensiT's Profwiz.exe and its shipped Profwiz.config
(Corporate Edition for silent enterprise use). Download from forensit.com.

.PARAMETER PackagePath
Export package from Export-AdEnvironment.ps1. Supplies the old domain name
and, when a principal map exists, the renamed-account lookup rows.

.PARAMETER TargetDomain
The new domain to migrate onto. Defaults to the domain this machine is in.

.PARAMETER OldDomain
Source domain whose profiles should be migrated. Defaults to the package
manifest's NetBIOS name. Colon-delimit to migrate from several.

.PARAMETER ComputersAdsPath
AdsPath of the OU for migrated computer accounts, for example
"OU=Workstations,DC=ad,DC=contoso,DC=com". Blank lands them in Computers.

.PARAMETER Exclude
Local account names never to migrate. Administrator is always excluded.

.PARAMETER RemoveAdmins
Do not carry users' local Administrators membership onto the new domain.
ForensiT themselves recommend this cleanup; off by default here because it
changes user capability, not just identity.

.PARAMETER JoinCredential
Domain account allowed to join machines to -TargetDomain, written to the
config IN PLAIN TEXT. Prefer running ForensiT's Deployment Kit instead, which
encrypts the password with a <Key>. If neither is done, Profwiz prompts.

.PARAMETER ComputerName
Workstations to inventory over CIM/WinRM for the profiles-inventory.csv.
Omit to skip the inventory and just build the kit.

.PARAMETER IncludeSpecialProfiles
Inventory service and system profiles too. Off by default.

.PARAMETER OutputPath
Kit destination folder.

.EXAMPLE
.\New-ProfileMigrationKit.ps1 -ProfwizFolder C:\Tools\Profwiz -PackagePath C:\AdExport-old-20260827

.EXAMPLE
.\New-ProfileMigrationKit.ps1 -ProfwizFolder C:\Tools\Profwiz -PackagePath C:\AdExport-old-20260827 `
    -ComputerName (Get-Content .\workstations.txt) -ComputersAdsPath "OU=CORP - Workstations,DC=ad,DC=contoso,DC=com" -RemoveAdmins

.NOTES
Windows PowerShell 5.1. Writes only into -OutputPath; reads AD and, for the
inventory, CIM on the named workstations. User Profile Wizard is ForensiT's
licensed software - this script only prepares its deployment.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ProfwizFolder,

    [string]$PackagePath,

    [string]$TargetDomain,

    [string]$OldDomain,

    [string]$ComputersAdsPath,

    [string[]]$Exclude = @(),

    [switch]$RemoveAdmins,

    [System.Management.Automation.PSCredential]$JoinCredential,

    [string[]]$ComputerName,

    [switch]$IncludeSpecialProfiles,

    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath "ProfileMigrationKit")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Start-AkLog -Path (Join-Path -Path $OutputPath -ChildPath "profile-kit-$timestamp.log")

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  PROFILE MIGRATION KIT" -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

try {
    # ------------------------------------------------------------------
    # The ForensiT pieces this kit is built around
    # ------------------------------------------------------------------
    $profwizExe = Join-Path -Path $ProfwizFolder -ChildPath "Profwiz.exe"
    $profwizTemplate = Join-Path -Path $ProfwizFolder -ChildPath "Profwiz.config"
    if (-not (Test-Path -LiteralPath $profwizExe)) {
        throw "Profwiz.exe not found in '$ProfwizFolder'. Download User Profile Wizard Corporate Edition from forensit.com and point -ProfwizFolder at the unpacked folder."
    }
    if (-not (Test-Path -LiteralPath $profwizTemplate)) {
        throw "Profwiz.config not found next to Profwiz.exe in '$ProfwizFolder'. The kit merges settings into the vendor's own template rather than inventing the file."
    }

    # ------------------------------------------------------------------
    # Resolve the two domains
    # ------------------------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($TargetDomain)) {
        Assert-AkModule -Name "ActiveDirectory" -Reason "resolving the target domain"
        $TargetDomain = (Get-ADDomain).DNSRoot
        Write-AkLog -Message "Target domain defaulted to $TargetDomain" -Level Info
    }

    $manifest = $null
    if (-not [string]::IsNullOrWhiteSpace($PackagePath)) {
        $manifest = Get-AkPackageManifest -PackagePath $PackagePath
    }

    if ([string]::IsNullOrWhiteSpace($OldDomain)) {
        if ($null -ne $manifest) {
            $OldDomain = [string](Get-AkPropertyValue -InputObject $manifest -Name "SourceDomainNetBios" -Default "")
            if ([string]::IsNullOrWhiteSpace($OldDomain)) {
                $OldDomain = [string](Get-AkPropertyValue -InputObject $manifest -Name "SourceDomainDns" -Default "")
            }
        }
        if ([string]::IsNullOrWhiteSpace($OldDomain)) {
            throw "Supply -OldDomain (or -PackagePath, whose manifest carries it). Without it Profwiz would migrate LOCAL account profiles instead of the old domain's."
        }
        Write-AkLog -Message "Old domain defaulted to $OldDomain from the package manifest." -Level Info
    }

    # ------------------------------------------------------------------
    # Renamed accounts -> Users.csv lookup file
    # ------------------------------------------------------------------
    $lookupRows = @()
    if ($null -ne $manifest) {
        $mapPath = Get-AkPackageItemPath -PackagePath $PackagePath -Item PrincipalMap
        if (Test-Path -LiteralPath $mapPath) {
            foreach ($row in (Import-AkCsv -Path $mapPath)) {
                $sourceSam = [string](Get-AkPropertyValue -InputObject $row -Name "SourceSamAccountName" -Default "")
                $targetSam = [string](Get-AkPropertyValue -InputObject $row -Name "TargetSamAccountName" -Default "")
                $sourceType = [string](Get-AkPropertyValue -InputObject $row -Name "SourceType" -Default "")
                if ($sourceType -ne "User") { continue }
                if ([string]::IsNullOrWhiteSpace($sourceSam) -or [string]::IsNullOrWhiteSpace($targetSam)) { continue }
                if ($sourceSam -eq $targetSam) { continue }
                $lookupRows += "$sourceSam,$targetSam"
            }
        }
    }

    $userLookupFile = ""
    if ($lookupRows.Count -gt 0) {
        $userLookupFile = "Users.csv"
        # Profwiz lookup files are bare old,new lines with no header.
        Set-Content -LiteralPath (Join-Path -Path $OutputPath -ChildPath $userLookupFile) -Value $lookupRows -Encoding ASCII
        Write-AkLog -Message "$($lookupRows.Count) renamed account(s) written to $userLookupFile." -Level Info
    }
    else {
        Write-AkLog -Message "No renamed accounts found; no user lookup file is needed." -Level Info
    }

    # ------------------------------------------------------------------
    # Merge this migration into the vendor's Profwiz.config
    # ------------------------------------------------------------------
    $excludeNames = @("Administrator") + @($Exclude) | Select-Object -Unique

    $settings = @{
        Domain       = $TargetDomain
        OldDomain    = $OldDomain
        All          = "True"
        Exclude      = ($excludeNames -join ",")
        Silent       = "True"
        NoReboot     = "False"
        RemoveAdmins = if ($RemoveAdmins) { "True" } else { "False" }
        Log          = "Migrate.log"
    }
    if (-not [string]::IsNullOrWhiteSpace($ComputersAdsPath)) { $settings["AdsPath"] = $ComputersAdsPath }
    if ($userLookupFile) { $settings["UserLookupFile"] = $userLookupFile }
    if ($JoinCredential) {
        Write-AkLog -Message "Writing the join password into Profwiz.config IN PLAIN TEXT, as requested. ForensiT's Deployment Kit can replace it with an encrypted <DomainPwd>/<Key> pair." -Level Warning
        $settings["DomainAdmin"] = $JoinCredential.UserName
        $settings["DomainPwd"] = $JoinCredential.GetNetworkCredential().Password
    }

    $configOut = Join-Path -Path $OutputPath -ChildPath "Profwiz.config"
    Update-AkProfwizConfig -TemplatePath $profwizTemplate -OutputPath $configOut -Setting $settings
    Copy-Item -LiteralPath $profwizExe -Destination (Join-Path -Path $OutputPath -ChildPath "Profwiz.exe") -Force
    Write-AkLog -Message "Profwiz.config written: $OldDomain -> $TargetDomain, exclude '$($excludeNames -join ",")'." -Level Success

    # ------------------------------------------------------------------
    # The migration script the RMM or startup GPO runs
    # ------------------------------------------------------------------
    # Per ForensiT's guide, its only jobs are: quit if the machine already
    # migrated, otherwise hand over to Profwiz, whose config drives the rest.
    $migrateScript = @(
        "# Generated by New-ProfileMigrationKit.ps1 on $timestamp",
        "# Runs as SYSTEM from RMM or a computer startup GPO.",
        "`$ErrorActionPreference = 'Stop'",
        "`$newDomain = '$TargetDomain'",
        "`$system = Get-CimInstance -ClassName Win32_ComputerSystem",
        "if (`$system.PartOfDomain -and `$system.Domain -eq `$newDomain) {",
        "    # Already migrated. Nothing to do.",
        "    exit 0",
        "}",
        "& (Join-Path -Path `$PSScriptRoot -ChildPath 'Profwiz.exe')",
        "exit `$LASTEXITCODE"
    )
    Set-Content -LiteralPath (Join-Path -Path $OutputPath -ChildPath "Migrate.ps1") -Value $migrateScript -Encoding ASCII
    Write-AkLog -Message "Migrate.ps1 written." -Level Success

    # ------------------------------------------------------------------
    # Profile inventory: whose data exists only on their workstation?
    # ------------------------------------------------------------------
    if (@($ComputerName).Count -gt 0) {
        Write-AkLog -Message "Inventorying profiles on $(@($ComputerName).Count) computer(s)..." -Level Step

        $inventory = New-Object System.Collections.Generic.List[object]
        foreach ($computer in @($ComputerName)) {
            try {
                $profiles = @(Get-CimInstance -ClassName Win32_UserProfile -ComputerName $computer -ErrorAction Stop)
            }
            catch {
                Write-AkLog -Message "${computer}: unreachable ($($_.Exception.Message))" -Level Warning
                $inventory.Add([pscustomobject]@{
                    Computer   = $computer
                    Account    = ""
                    LocalPath  = ""
                    Storage    = "UNREACHABLE"
                    LastUsed   = ""
                    Sid        = ""
                })
                continue
            }

            foreach ($userProfile in $profiles) {
                $isSpecial = Get-AkPropertyValue -InputObject $userProfile -Name "Special" -Default $false
                if ($isSpecial -and -not $IncludeSpecialProfiles) { continue }

                $sid = [string](Get-AkPropertyValue -InputObject $userProfile -Name "SID" -Default "")
                $account = ""
                try {
                    $account = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
                }
                catch {
                    # An unresolvable SID is itself informative: an account the
                    # new environment no longer knows, orphaned on that machine.
                    $account = ""
                }

                $roaming = Get-AkPropertyValue -InputObject $userProfile -Name "RoamingConfigured" -Default $false
                $lastUse = Get-AkPropertyValue -InputObject $userProfile -Name "LastUseTime" -Default $null

                $inventory.Add([pscustomobject]@{
                    Computer   = $computer
                    Account    = $account
                    LocalPath  = [string](Get-AkPropertyValue -InputObject $userProfile -Name "LocalPath" -Default "")
                    Storage    = if ($roaming) { "Roaming" } else { "LOCAL ONLY" }
                    LastUsed   = if ($null -ne $lastUse) { "{0:yyyy-MM-dd}" -f $lastUse } else { "" }
                    Sid        = $sid
                })
            }
        }

        $inventoryPath = Join-Path -Path $OutputPath -ChildPath "profiles-inventory.csv"
        [void](Export-AkCsv -InputObject $inventory.ToArray() -Path $inventoryPath)
        $localOnly = @($inventory | Where-Object { $_.Storage -eq "LOCAL ONLY" }).Count
        Write-AkLog -Message "Inventory written to $inventoryPath - $($inventory.Count) profile(s), $localOnly local only." -Level Success
    }
    else {
        Write-AkLog -Message "No -ComputerName given; skipping the profile inventory." -Level Info
    }

    # ------------------------------------------------------------------
    # What happens next
    # ------------------------------------------------------------------
    Write-Host ""
    Write-Host "Kit written to: $OutputPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. License: User Profile Wizard Corporate Edition is ForensiT's paid product."
    if (-not $JoinCredential) {
        Write-Host "  2. Join credentials: run ForensiT's Deployment Kit over this Profwiz.config to"
        Write-Host "     add the domain-join account with an ENCRYPTED password (<DomainPwd>/<Key>)."
    }
    else {
        Write-Host "  2. Join credentials are in Profwiz.config in plain text. Protect the folder;"
        Write-Host "     prefer re-running ForensiT's Deployment Kit to encrypt them."
    }
    Write-Host "  3. Deploy the folder via your RMM (execute Migrate.ps1 as SYSTEM) or copy it"
    Write-Host "     into a GPO computer startup script, per the Corporate Edition guide."
    Write-Host "  4. Pilot ONE workstation first and read its Migrate.log before fleet rollout."
    Write-Host ""
}
finally {
    Stop-AkLog
}

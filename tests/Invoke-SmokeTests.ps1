<#
.SYNOPSIS
Offline smoke tests for this repository.

.DESCRIPTION
Runs two classes of check that need no Active Directory, no Entra tenant, and no
network access:

1. A parser check of every .ps1 and .psm1 file in the repository.
2. Unit tests of the pure helper functions in the ADMigrationKit module, which
   are where the cross-domain rebuild logic actually lives.

Run this after any edit. It is the only test in this repository that can be run
from a workstation. Everything that touches AD or Graph must be validated in a
lab domain.

.EXAMPLE
.\tests\Invoke-SmokeTests.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$script:Passed = 0
$script:Failed = 0

function Test-Case {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Body
    )

    try {
        $result = & $Body
        if ($result -eq $true) {
            Write-Host "  PASS  $Name" -ForegroundColor Green
            $script:Passed++
        }
        else {
            Write-Host "  FAIL  $Name (returned '$result')" -ForegroundColor Red
            $script:Failed++
        }
    }
    catch {
        Write-Host "  FAIL  $Name ($($_.Exception.Message))" -ForegroundColor Red
        $script:Failed++
    }
}

Write-Host ""
Write-Host "=== Parser check ===" -ForegroundColor Cyan

$scriptFiles = @(
    Get-ChildItem -Path $repoRoot -Recurse -Include "*.ps1", "*.psm1" -File |
        Where-Object { $_.FullName -notmatch "\\\.git\\" }
)

foreach ($file in $scriptFiles) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)

    $relative = $file.FullName.Substring($repoRoot.Length).TrimStart("\")
    if ($errors -and $errors.Count -gt 0) {
        Write-Host "  FAIL  $relative" -ForegroundColor Red
        foreach ($parseError in $errors) {
            Write-Host "          line $($parseError.Extent.StartLineNumber): $($parseError.Message)" -ForegroundColor Red
        }
        $script:Failed++
    }
    else {
        Write-Host "  PASS  $relative" -ForegroundColor Green
        $script:Passed++
    }
}

Write-Host ""
Write-Host "=== ADMigrationKit helper tests ===" -ForegroundColor Cyan

Import-Module (Join-Path -Path $repoRoot -ChildPath "modules\ADMigrationKit\ADMigrationKit.psd1") -Force

Test-Case -Name "ConvertTo-AkDomainDn builds a domain DN" {
    (ConvertTo-AkDomainDn -DnsDomainName 'corp.old.local') -eq 'DC=corp,DC=old,DC=local'
}

Test-Case -Name "ConvertTo-AkDomainDn handles a single label domain" {
    (ConvertTo-AkDomainDn -DnsDomainName 'contoso') -eq 'DC=contoso'
}

Test-Case -Name "ConvertTo-AkTargetDn rewrites only the domain suffix" {
    $result = ConvertTo-AkTargetDn -SourceDn 'CN=Bob Smith,OU=Sales,OU=HQ,DC=old,DC=local' `
        -SourceDomainDn 'DC=old,DC=local' -TargetDomainDn 'DC=new,DC=com'
    $result -eq 'CN=Bob Smith,OU=Sales,OU=HQ,DC=new,DC=com'
}

Test-Case -Name "ConvertTo-AkTargetDn maps the domain root itself" {
    (ConvertTo-AkTargetDn -SourceDn 'DC=old,DC=local' -SourceDomainDn 'DC=old,DC=local' -TargetDomainDn 'DC=new,DC=com') -eq 'DC=new,DC=com'
}

Test-Case -Name "ConvertTo-AkTargetDn is case insensitive on the suffix" {
    (ConvertTo-AkTargetDn -SourceDn 'OU=IT,dc=OLD,dc=LOCAL' -SourceDomainDn 'DC=old,DC=local' -TargetDomainDn 'DC=new,DC=com') -eq 'OU=IT,DC=new,DC=com'
}

Test-Case -Name "ConvertTo-AkTargetDn leaves foreign DNs untouched" {
    (ConvertTo-AkTargetDn -SourceDn 'CN=X,DC=other,DC=tld' -SourceDomainDn 'DC=old,DC=local' -TargetDomainDn 'DC=new,DC=com') -eq 'CN=X,DC=other,DC=tld'
}

Test-Case -Name "ConvertTo-AkTargetDn returns null for empty input" {
    $null -eq (ConvertTo-AkTargetDn -SourceDn '' -SourceDomainDn 'DC=old,DC=local' -TargetDomainDn 'DC=new,DC=com')
}

Test-Case -Name "Get-AkParentDn returns the container" {
    (Get-AkParentDn -DistinguishedName 'OU=Sales,OU=HQ,DC=old,DC=local') -eq 'OU=HQ,DC=old,DC=local'
}

Test-Case -Name "Get-AkParentDn respects an escaped comma in the RDN" {
    (Get-AkParentDn -DistinguishedName 'CN=Smith\, Bob,OU=Sales,DC=old,DC=local') -eq 'OU=Sales,DC=old,DC=local'
}

Test-Case -Name "Get-AkDnDepth counts unescaped components" {
    (Get-AkDnDepth -DistinguishedName 'OU=Sales,OU=HQ,DC=old,DC=local') -eq 4
}

Test-Case -Name "Get-AkDnDepth ignores escaped commas" {
    (Get-AkDnDepth -DistinguishedName 'CN=Smith\, Bob,OU=Sales,DC=old,DC=local') -eq 4
}

Test-Case -Name "Get-AkDnDepth orders parents before children" {
    $parent = Get-AkDnDepth -DistinguishedName 'OU=HQ,DC=old,DC=local'
    $child = Get-AkDnDepth -DistinguishedName 'OU=Sales,OU=HQ,DC=old,DC=local'
    $parent -lt $child
}

Test-Case -Name "Get-AkSidRid returns the trailing RID" {
    (Get-AkSidRid -Sid 'S-1-5-21-111-222-333-512') -eq '512'
}

Test-Case -Name "Get-AkWellKnownRidMap maps 512 to Domain Admins" {
    (Get-AkWellKnownRidMap)['512'] -eq 'DomainAdmins'
}

Test-Case -Name "Test-AkIsBuiltInSid detects BUILTIN groups" {
    (Test-AkIsBuiltInSid -Sid 'S-1-5-32-544') -eq $true
}

Test-Case -Name "Test-AkIsBuiltInSid detects well known non-domain SIDs" {
    (Test-AkIsBuiltInSid -Sid 'S-1-1-0') -eq $true
}

Test-Case -Name "Test-AkIsBuiltInSid treats domain SIDs as migratable" {
    (Test-AkIsBuiltInSid -Sid 'S-1-5-21-1-2-3-1105') -eq $false
}

Test-Case -Name "New-AkPassword honours the requested length" {
    (New-AkPassword -Length 24).Length -eq 24
}

Test-Case -Name "New-AkPassword satisfies default complexity rules" {
    $ok = $true
    for ($i = 0; $i -lt 50; $i++) {
        $password = New-AkPassword -Length 16
        if ($password -cnotmatch '[A-Z]' -or
            $password -cnotmatch '[a-z]' -or
            $password -notmatch '[0-9]' -or
            $password -notmatch '[^a-zA-Z0-9]') {
            $ok = $false
            break
        }
    }
    $ok
}

Test-Case -Name "New-AkPassword does not repeat itself" {
    $set = New-Object System.Collections.Generic.HashSet[string]
    for ($i = 0; $i -lt 100; $i++) {
        [void]$set.Add((New-AkPassword -Length 20))
    }
    $set.Count -eq 100
}

Test-Case -Name "New-AkPassword distributes guaranteed classes past position 4" {
    # Guards against the naive build order where the first four characters are
    # always upper, lower, digit, symbol.
    $symbolLate = $false
    for ($i = 0; $i -lt 100; $i++) {
        $password = New-AkPassword -Length 20
        if ($password.Substring(4) -match '[^a-zA-Z0-9]') {
            $symbolLate = $true
            break
        }
    }
    $symbolLate
}

Test-Case -Name "ConvertTo-AkBoolean round trips CSV text" {
    (ConvertTo-AkBoolean -Value 'True') -eq $true -and
    (ConvertTo-AkBoolean -Value 'False') -eq $false -and
    (ConvertTo-AkBoolean -Value '') -eq $false -and
    (ConvertTo-AkBoolean -Value $null -Default $true) -eq $true
}

Test-Case -Name "ConvertFrom-AkMultiValue splits and trims" {
    $values = ConvertFrom-AkMultiValue -Value 'smtp:a@x.com; SMTP:b@x.com;'
    $values.Count -eq 2 -and $values[1] -eq 'SMTP:b@x.com'
}

Test-Case -Name "ConvertFrom-AkMultiValue returns an empty array for null" {
    (ConvertFrom-AkMultiValue -Value $null).Count -eq 0
}

Test-Case -Name "ConvertTo-AkMultiValue joins with semicolons" {
    (ConvertTo-AkMultiValue -Value @('a', 'b')) -eq 'a;b'
}

Test-Case -Name "Get-AkPropertyValue survives missing properties under StrictMode" {
    $object = [pscustomobject]@{ Present = 'yes' }
    (Get-AkPropertyValue -InputObject $object -Name 'Present') -eq 'yes' -and
    (Get-AkPropertyValue -InputObject $object -Name 'Absent' -Default 'fallback') -eq 'fallback' -and
    (Get-AkPropertyValue -InputObject $null -Name 'Anything' -Default 'fallback') -eq 'fallback'
}

Test-Case -Name "Get-AkSafeName strips path characters" {
    (Get-AkSafeName -Value 'old.local\bad:name') -eq 'old.local_bad_name'
}

Test-Case -Name "Get-AkPackageItemPath resolves known items" {
    (Get-AkPackageItemPath -PackagePath 'C:\pkg' -Item 'Users') -eq 'C:\pkg\identity\users.csv'
}

Test-Case -Name "Get-AkPackageItemPath rejects unknown items" {
    try {
        [void](Get-AkPackageItemPath -PackagePath 'C:\pkg' -Item 'NotAThing')
        $false
    }
    catch {
        $true
    }
}

Test-Case -Name "Import-AkCsv returns an empty array for a missing file" {
    (Import-AkCsv -Path (Join-Path $env:TEMP 'ak-does-not-exist-12345.csv')).Count -eq 0
}

Test-Case -Name "Export-AkCsv and Import-AkCsv round trip" {
    $temp = Join-Path -Path $env:TEMP -ChildPath ("ak-test-" + [System.Guid]::NewGuid().ToString("N"))
    try {
        $path = Join-Path -Path $temp -ChildPath "sub\rows.csv"
        [void](Export-AkCsv -InputObject @([pscustomobject]@{ A = 1; B = 'x' }) -Path $path)
        $rows = Import-AkCsv -Path $path
        $rows.Count -eq 1 -and $rows[0].B -eq 'x'
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

Test-Case -Name "Export-AkCsv handles an empty collection" {
    $temp = Join-Path -Path $env:TEMP -ChildPath ("ak-test-" + [System.Guid]::NewGuid().ToString("N"))
    try {
        $path = Join-Path -Path $temp -ChildPath "empty.csv"
        $count = Export-AkCsv -InputObject @() -Path $path
        $count -eq 0 -and (Test-Path -LiteralPath $path) -and (Import-AkCsv -Path $path).Count -eq 0
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

Test-Case -Name "No call site wraps a comma-returning helper in @()" {
    # These helpers return ,@($items) so an empty result survives as an array.
    # Wrapping such a call in @() does not flatten it, it nests it one level
    # deeper: @(f) becomes a one-element array holding the real array, and the
    # first .Count or [0] downstream is then wrong. Caught in the wild when
    # $users = @(Invoke-AkAdPropertyQuery ...) made every user record an array.
    # Line-based, so a call split across lines is not inspected; a pipeline on
    # the same line is fine because piping enumerates the array.
    $commaReturning = @("Import-AkCsv", "ConvertFrom-AkMultiValue", "ConvertFrom-AkGpLink", "Invoke-AkAdPropertyQuery")
    $offenders = New-Object System.Collections.Generic.List[string]

    foreach ($file in (Get-ChildItem -LiteralPath $repoRoot -Filter "*.ps1" -File)) {
        $lineNumber = 0
        foreach ($line in (Get-Content -LiteralPath $file.FullName)) {
            $lineNumber++
            if ($line -match "\|") { continue }
            foreach ($name in $commaReturning) {
                if ($line -match ("@\(\s*" + [regex]::Escape($name) + "\b")) {
                    $offenders.Add("$($file.Name):$lineNumber")
                }
            }
        }
    }

    if ($offenders.Count -gt 0) {
        Write-Host "        offenders: $($offenders -join ', ')" -ForegroundColor Yellow
    }
    $offenders.Count -eq 0
}

Test-Case -Name "Get-AkInvalidPropertyName pulls the attribute out of an AD error" {
    $message = "One or more properties are invalid.`\nParameter name: UserType"
    (Get-AkInvalidPropertyName -Message $message) -eq "UserType"
}

Test-Case -Name "Get-AkInvalidPropertyName returns null for an unrelated error" {
    $null -eq (Get-AkInvalidPropertyName -Message "The server is not operational.")
}

Test-Case -Name "Get-AkInvalidPropertyName returns null for empty input" {
    $null -eq (Get-AkInvalidPropertyName -Message "")
}

Test-Case -Name "Invoke-AkAdPropertyQuery drops an unsupported property and retries" {
    # Stands in for a schema without the Exchange extension: the fake cmdlet
    # rejects the whole call the way Get-ADUser does, naming one property.
    $script:attempts = 0
    $dropped = @()
    $result = Invoke-AkAdPropertyQuery -Property @("SamAccountName", "extensionAttribute1") `
        -DroppedProperty ([ref]$dropped) -Query {
            param($requested)
            $script:attempts++
            if ($requested -contains "extensionAttribute1") {
                throw [System.ArgumentException]::new("One or more properties are invalid.`\nParameter name: extensionAttribute1")
            }
            return @("ok")
        }
    $script:attempts -eq 2 -and $dropped.Count -eq 1 -and $dropped[0] -eq "extensionAttribute1" -and $result[0] -eq "ok"
}

Test-Case -Name "Invoke-AkAdPropertyQuery returns no dropped properties on success" {
    $dropped = @()
    $result = Invoke-AkAdPropertyQuery -Property @("SamAccountName") -DroppedProperty ([ref]$dropped) -Query {
        param($requested)
        return @("ok")
    }
    $dropped.Count -eq 0 -and $result[0] -eq "ok"
}

Test-Case -Name "Invoke-AkAdPropertyQuery rethrows an error it cannot attribute to a property" {
    try {
        [void](Invoke-AkAdPropertyQuery -Property @("SamAccountName") -Query {
            param($requested)
            throw "The server is not operational."
        })
        $false
    }
    catch {
        $_.Exception.Message -like "*not operational*"
    }
}

Test-Case -Name "Save-AkJson creates a missing package subfolder" {
    # Regression: the Domain section wrote domain\domain.json before anything
    # created the domain folder, so a full export died on its first section.
    $temp = Join-Path -Path $env:TEMP -ChildPath ("ak-test-" + [System.Guid]::NewGuid().ToString("N"))
    try {
        New-Item -Path $temp -ItemType Directory -Force | Out-Null
        $path = Get-AkPackageItemPath -PackagePath $temp -Item DomainInfo
        [void](Save-AkJson -InputObject ([pscustomobject]@{ DnsRoot = 'old.local' }) -Path $path)
        Test-Path -LiteralPath $path
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

Test-Case -Name "Save-AkJson round trips an object" {
    $temp = Join-Path -Path $env:TEMP -ChildPath ("ak-test-" + [System.Guid]::NewGuid().ToString("N"))
    try {
        $path = Join-Path -Path $temp -ChildPath "nested\deeper\policy.json"
        [void](Save-AkJson -InputObject ([pscustomobject]@{ MinPasswordLength = 14 }) -Path $path -Depth 4)
        $read = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $read.MinPasswordLength -eq 14
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

Test-Case -Name "Get-AkMappedLinkTarget reports unmapped for an empty map" {
    $result = Get-AkMappedLinkTarget -SourceDn "OU=Staff,DC=old,DC=net" -LinkTargetMap @{}
    (-not $result.Mapped) -and (-not $result.Skip) -and ($null -eq $result.TargetDn)
}

Test-Case -Name "Get-AkMappedLinkTarget returns the mapped container" {
    $map = @{ "OU=Staff,DC=old,DC=net" = "OU=Users,OU=HQ,DC=new,DC=com" }
    $result = Get-AkMappedLinkTarget -SourceDn "OU=Staff,DC=old,DC=net" -LinkTargetMap $map
    $result.Mapped -and (-not $result.Skip) -and $result.TargetDn -eq "OU=Users,OU=HQ,DC=new,DC=com"
}

Test-Case -Name "Get-AkMappedLinkTarget matches a source DN case insensitively" {
    $map = @{ "ou=staff,dc=old,dc=net" = "OU=Users,DC=new,DC=com" }
    $result = Get-AkMappedLinkTarget -SourceDn "OU=Staff,DC=old,DC=net" -LinkTargetMap $map
    $result.Mapped -and $result.TargetDn -eq "OU=Users,DC=new,DC=com"
}

Test-Case -Name "Get-AkMappedLinkTarget treats an empty value as a deliberate skip" {
    $map = @{ "OU=Gone,DC=old,DC=net" = "" }
    $result = Get-AkMappedLinkTarget -SourceDn "OU=Gone,DC=old,DC=net" -LinkTargetMap $map
    $result.Mapped -and $result.Skip -and ($null -eq $result.TargetDn)
}

Test-Case -Name "Get-AkMappedLinkTarget leaves an unlisted DN to normal translation" {
    $map = @{ "OU=Staff,DC=old,DC=net" = "OU=Users,DC=new,DC=com" }
    $result = Get-AkMappedLinkTarget -SourceDn "OU=Finance,DC=old,DC=net" -LinkTargetMap $map
    -not $result.Mapped
}

Test-Case -Name "Get-AkMappedLinkTarget returns unmapped for empty input" {
    $map = @{ "OU=Staff,DC=old,DC=net" = "OU=Users,DC=new,DC=com" }
    -not (Get-AkMappedLinkTarget -SourceDn "" -LinkTargetMap $map).Mapped
}

Test-Case -Name "Package manifest round trips" {
    $temp = Join-Path -Path $env:TEMP -ChildPath ("ak-test-" + [System.Guid]::NewGuid().ToString("N"))
    try {
        New-Item -Path $temp -ItemType Directory -Force | Out-Null
        [void](New-AkPackageManifest -PackagePath $temp -SourceDomainDns 'old.local' `
            -SourceDomainNetBios 'OLD' -SourceDomainDn 'DC=old,DC=local' `
            -SourceDomainSid 'S-1-5-21-1-2-3' -Counts @{ Users = 42 } -Sections @('Users'))
        $manifest = Get-AkPackageManifest -PackagePath $temp
        $manifest.SourceDomainDns -eq 'old.local' -and $manifest.Counts.Users -eq 42
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

Test-Case -Name "Get-AkPackageManifest fails clearly on a non-package folder" {
    $temp = Join-Path -Path $env:TEMP -ChildPath ("ak-test-" + [System.Guid]::NewGuid().ToString("N"))
    try {
        New-Item -Path $temp -ItemType Directory -Force | Out-Null
        try {
            [void](Get-AkPackageManifest -PackagePath $temp)
            $false
        }
        catch {
            $_.Exception.Message -like "*manifest.json*"
        }
    }
    finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
}

Test-Case -Name "ConvertFrom-AkGpLink returns empty for an unlinked object" {
    (ConvertFrom-AkGpLink -GpLink '' -TargetDn 'OU=X,DC=old,DC=local' -TargetType 'OrganizationalUnit').Count -eq 0
}

Test-Case -Name "ConvertFrom-AkGpLink parses a single link" {
    $raw = '[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=old,DC=local;0]'
    $links = ConvertFrom-AkGpLink -GpLink $raw -TargetDn 'DC=old,DC=local' -TargetType 'Domain'
    $links.Count -eq 1 -and
    $links[0].GpoId -eq '31B2F340-016D-11D2-945F-00C04FB984F9' -and
    $links[0].Enabled -eq $true -and
    $links[0].Enforced -eq $false -and
    $links[0].LinkOrder -eq 1
}

Test-Case -Name "ConvertFrom-AkGpLink assigns GPMC precedence in reverse attribute order" {
    # The GPO written LAST in gPLink has the HIGHEST precedence (link order 1).
    # Getting this backwards silently inverts policy precedence after a rebuild.
    $raw = '[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=old,DC=local;0]' +
           '[LDAP://cn={BBBBBBBB-0000-0000-0000-000000000002},cn=policies,cn=system,DC=old,DC=local;0]' +
           '[LDAP://cn={CCCCCCCC-0000-0000-0000-000000000003},cn=policies,cn=system,DC=old,DC=local;0]'
    $links = ConvertFrom-AkGpLink -GpLink $raw -TargetDn 'OU=Sales,DC=old,DC=local' -TargetType 'OrganizationalUnit'

    $last = $links | Where-Object { $_.GpoId -like 'CCCCCCCC*' }
    $first = $links | Where-Object { $_.GpoId -like 'AAAAAAAA*' }

    $links.Count -eq 3 -and
    $last.LinkOrder -eq 1 -and $last.AttributeIndex -eq 2 -and
    $first.LinkOrder -eq 3 -and $first.AttributeIndex -eq 0
}

Test-Case -Name "ConvertFrom-AkGpLink decodes the disabled flag" {
    $raw = '[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=old,DC=local;1]'
    $link = (ConvertFrom-AkGpLink -GpLink $raw -TargetDn 'OU=X,DC=old,DC=local' -TargetType 'OrganizationalUnit')[0]
    $link.Enabled -eq $false -and $link.Enforced -eq $false
}

Test-Case -Name "ConvertFrom-AkGpLink decodes the enforced flag" {
    $raw = '[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=old,DC=local;2]'
    $link = (ConvertFrom-AkGpLink -GpLink $raw -TargetDn 'OU=X,DC=old,DC=local' -TargetType 'OrganizationalUnit')[0]
    $link.Enabled -eq $true -and $link.Enforced -eq $true
}

Test-Case -Name "ConvertFrom-AkGpLink decodes disabled plus enforced" {
    $raw = '[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=old,DC=local;3]'
    $link = (ConvertFrom-AkGpLink -GpLink $raw -TargetDn 'OU=X,DC=old,DC=local' -TargetType 'OrganizationalUnit')[0]
    $link.Enabled -eq $false -and $link.Enforced -eq $true
}

Test-Case -Name "Get-AkRdnValue returns a simple CN" {
    (Get-AkRdnValue -DistinguishedName 'CN=John Smith,OU=Sales,DC=old,DC=local') -eq 'John Smith'
}

Test-Case -Name "Get-AkRdnValue unescapes a comma in the RDN" {
    # "Smith, Bob" is stored escaped in the DN; rebuilding with the escape
    # still present would create a visibly wrong account name.
    (Get-AkRdnValue -DistinguishedName 'CN=Smith\, Bob,OU=Sales,DC=old,DC=local') -eq 'Smith, Bob'
}

Test-Case -Name "Get-AkRdnValue handles an OU prefix" {
    (Get-AkRdnValue -DistinguishedName 'OU=Sales,OU=HQ,DC=old,DC=local') -eq 'Sales'
}

Test-Case -Name "Get-AkRdnValue returns null for empty input" {
    $null -eq (Get-AkRdnValue -DistinguishedName '')
}

Test-Case -Name "Resolve-AkUpnTenantMatch skips a UPN that already matches" {
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@contoso.com' -ProposedUpn 'bob@contoso.com' -TenantDataAvailable
    ($r.Action -eq 'Skip') -and ($r.TenantMatch -eq 'NoChange')
}

Test-Case -Name "Resolve-AkUpnTenantMatch reports unchecked without a tenant export" {
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@ad.contoso.com' -ProposedUpn 'bob@contoso.com'
    ($r.Action -eq 'Change') -and ($r.TenantMatch -eq 'NotChecked')
}

Test-Case -Name "Resolve-AkUpnTenantMatch allows a change with no tenant collision" {
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@ad.contoso.com' -ProposedUpn 'bob@contoso.com' `
        -CurrentCloudState 'Synced' -ProposedCloudState 'Absent' -TenantDataAvailable
    ($r.Action -eq 'Change') -and ($r.TenantMatch -eq 'None')
}

Test-Case -Name "Resolve-AkUpnTenantMatch treats an unsynced account hitting a cloud-only user as a soft match" {
    # This is the adoption case: the collision is the desired outcome.
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@ad.contoso.com' -ProposedUpn 'bob@contoso.com' `
        -CurrentCloudState 'Absent' -ProposedCloudState 'CloudOnly' -TenantDataAvailable
    ($r.Action -eq 'Change') -and ($r.TenantMatch -eq 'CloudOnlyMatch')
}

Test-Case -Name "Resolve-AkUpnTenantMatch flags a synced account hitting a cloud-only user" {
    # Same collision, opposite verdict: this one is a duplicate-attribute error.
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@ad.contoso.com' -ProposedUpn 'bob@contoso.com' `
        -CurrentCloudState 'Synced' -ProposedCloudState 'CloudOnly' -TenantDataAvailable
    ($r.Action -eq 'Review') -and ($r.TenantMatch -eq 'CollisionCloudOnly')
}

Test-Case -Name "Resolve-AkUpnTenantMatch flags a collision with another synced account" {
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@ad.contoso.com' -ProposedUpn 'bob@contoso.com' `
        -CurrentCloudState 'Absent' -ProposedCloudState 'Synced' -TenantDataAvailable
    ($r.Action -eq 'Review') -and ($r.TenantMatch -eq 'CollisionSynced')
}

Test-Case -Name "Resolve-AkUpnTenantMatch refuses to guess when the sync state is unknown" {
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@ad.contoso.com' -ProposedUpn 'bob@contoso.com' `
        -CurrentCloudState 'Absent' -ProposedCloudState 'Unknown' -TenantDataAvailable
    ($r.Action -eq 'Review') -and ($r.TenantMatch -eq 'CollisionUnknown')
}

Test-Case -Name "Resolve-AkUpnTenantMatch reviews a row with no derivable UPN" {
    $r = Resolve-AkUpnTenantMatch -CurrentUpn 'bob@ad.contoso.com' -ProposedUpn '' -TenantDataAvailable
    ($r.Action -eq 'Review') -and ($r.TenantMatch -eq 'NotApplicable')
}

Test-Case -Name "Test-AkKeepableUpnSuffix never keeps a subdomain of the target" {
    # ad.contoso.com has a dot and a real TLD, so every naive routability test
    # passes it, yet it is exactly the suffix that has to move.
    -not (Test-AkKeepableUpnSuffix -CurrentSuffix 'ad.contoso.com' -TargetSuffix 'contoso.com')
}

Test-Case -Name "Test-AkKeepableUpnSuffix never keeps a deeper subdomain of the target" {
    -not (Test-AkKeepableUpnSuffix -CurrentSuffix 'corp.ad.contoso.com' -TargetSuffix 'contoso.com')
}

Test-Case -Name "Test-AkKeepableUpnSuffix keeps an unrelated routable suffix" {
    Test-AkKeepableUpnSuffix -CurrentSuffix 'fabrikam.com' -TargetSuffix 'contoso.com'
}

Test-Case -Name "Test-AkKeepableUpnSuffix does not keep the target itself" {
    -not (Test-AkKeepableUpnSuffix -CurrentSuffix 'contoso.com' -TargetSuffix 'contoso.com')
}

Test-Case -Name "Test-AkKeepableUpnSuffix does not keep a private TLD" {
    -not (Test-AkKeepableUpnSuffix -CurrentSuffix 'contoso.local' -TargetSuffix 'contoso.com')
}

Test-Case -Name "Test-AkKeepableUpnSuffix does not keep a single label suffix" {
    -not (Test-AkKeepableUpnSuffix -CurrentSuffix 'contoso' -TargetSuffix 'contoso.com')
}

Test-Case -Name "Test-AkKeepableUpnSuffix does not keep an empty suffix" {
    -not (Test-AkKeepableUpnSuffix -CurrentSuffix '' -TargetSuffix 'contoso.com')
}

Test-Case -Name "Test-AkKeepableUpnSuffix is case insensitive" {
    -not (Test-AkKeepableUpnSuffix -CurrentSuffix 'AD.Contoso.COM' -TargetSuffix 'contoso.com')
}

Write-Host ""
Write-Host "=== Entra to AD sync helpers ===" -ForegroundColor Cyan

Test-Case -Name "ConvertTo-AkBase64Url drops padding and translates the alphabet" {
    # 0xFB 0xEF 0xFF is '++//' territory in standard base64.
    $encoded = ConvertTo-AkBase64Url -Bytes ([byte[]](251, 239, 190, 255))
    ($encoded -notmatch "[+/=]") -and $encoded.Length -gt 0
}

Test-Case -Name "ConvertTo-AkBase64Url round trips through base64url decoding" {
    $bytes = [byte[]](1, 2, 3, 250, 251, 252, 253)
    $encoded = ConvertTo-AkBase64Url -Bytes $bytes
    $padded = $encoded.Replace("-", "+").Replace("_", "/")
    while ($padded.Length % 4 -ne 0) { $padded += "=" }
    $decoded = [System.Convert]::FromBase64String($padded)
    (-join $decoded) -eq (-join $bytes)
}

Test-Case -Name "New-AkSamAccountName strips characters AD rejects" {
    (New-AkSamAccountName -Candidate "jane.doe@contoso.com") -eq "jane.doecontoso.com"
}

Test-Case -Name "New-AkSamAccountName truncates to the 20 character limit" {
    $name = New-AkSamAccountName -Candidate "bartholomewfitzgeraldthethird"
    $name.Length -eq 20
}

Test-Case -Name "New-AkSamAccountName resolves a collision" {
    (New-AkSamAccountName -Candidate "jdoe" -Taken @("jdoe")) -eq "jdoe2"
}

Test-Case -Name "New-AkSamAccountName collision matching is case insensitive" {
    (New-AkSamAccountName -Candidate "jdoe" -Taken @("JDOE")) -eq "jdoe2"
}

Test-Case -Name "New-AkSamAccountName keeps the suffix inside the length limit" {
    $taken = @("abcdefghijklmnopqrst")
    $name = New-AkSamAccountName -Candidate "abcdefghijklmnopqrstuvwxyz" -Taken $taken
    ($name.Length -le 20) -and ($name -eq "abcdefghijklmnopqrs2")
}

Test-Case -Name "New-AkSamAccountName falls back when nothing legal survives" {
    (New-AkSamAccountName -Candidate "@@@") -eq "user"
}

Test-Case -Name "Test-AkEntraSyncCandidate accepts a cloud only member" {
    $user = [pscustomobject]@{ userPrincipalName = "a@contoso.com"; userType = "Member"; accountEnabled = $true; onPremisesSyncEnabled = $null }
    (Test-AkEntraSyncCandidate -EntraUser $user).Eligible
}

Test-Case -Name "Test-AkEntraSyncCandidate never re-creates an already synced user" {
    $user = [pscustomobject]@{ userPrincipalName = "a@contoso.com"; userType = "Member"; accountEnabled = $true; onPremisesSyncEnabled = $true }
    -not (Test-AkEntraSyncCandidate -EntraUser $user).Eligible
}

Test-Case -Name "Test-AkEntraSyncCandidate rejects guests by default" {
    $user = [pscustomobject]@{ userPrincipalName = "a@contoso.com"; userType = "Guest"; accountEnabled = $true }
    (-not (Test-AkEntraSyncCandidate -EntraUser $user).Eligible) -and
        (Test-AkEntraSyncCandidate -EntraUser $user -IncludeGuest).Eligible
}

Test-Case -Name "Test-AkEntraSyncCandidate rejects an external UPN" {
    $user = [pscustomobject]@{ userPrincipalName = "a_fabrikam.com#EXT#@contoso.onmicrosoft.com"; userType = "Member"; accountEnabled = $true }
    -not (Test-AkEntraSyncCandidate -EntraUser $user -IncludeGuest).Eligible
}

Test-Case -Name "Test-AkEntraSyncCandidate rejects a disabled Entra account by default" {
    $user = [pscustomobject]@{ userPrincipalName = "a@contoso.com"; userType = "Member"; accountEnabled = $false }
    (-not (Test-AkEntraSyncCandidate -EntraUser $user).Eligible) -and
        (Test-AkEntraSyncCandidate -EntraUser $user -IncludeDisabled).Eligible
}

Test-Case -Name "Test-AkEntraSyncCandidate honours an exclusion pattern" {
    $user = [pscustomobject]@{ userPrincipalName = "svc-backup@contoso.com"; userType = "Member"; accountEnabled = $true }
    -not (Test-AkEntraSyncCandidate -EntraUser $user -ExcludeUserPrincipalName @("svc-*")).Eligible
}

Test-Case -Name "Test-AkEntraSyncCandidate survives a user with no UPN under StrictMode" {
    $user = [pscustomobject]@{ displayName = "Broken" }
    -not (Test-AkEntraSyncCandidate -EntraUser $user).Eligible
}

Test-Case -Name "Get-AkEntraAttributeDelta returns only what differs" {
    $entra = [pscustomobject]@{ displayName = "Jane Doe"; jobTitle = "Paralegal"; department = "Litigation" }
    $ad = [pscustomobject]@{ DisplayName = "Jane Doe"; Title = "Legal Assistant"; Department = "Litigation" }
    $delta = Get-AkEntraAttributeDelta -EntraUser $entra -AdUser $ad
    ($delta.Count -eq 1) -and ($delta["Title"] -eq "Paralegal")
}

Test-Case -Name "Get-AkEntraAttributeDelta treats a casing change as a change" {
    $entra = [pscustomobject]@{ givenName = "Jane" }
    $ad = [pscustomobject]@{ GivenName = "jane" }
    (Get-AkEntraAttributeDelta -EntraUser $entra -AdUser $ad).Count -eq 1
}

Test-Case -Name "Get-AkEntraAttributeDelta leaves on-premises only data alone" {
    $entra = [pscustomobject]@{ displayName = "Jane Doe" }
    $ad = [pscustomobject]@{ DisplayName = "Jane Doe"; OfficePhone = "x204" }
    (Get-AkEntraAttributeDelta -EntraUser $entra -AdUser $ad).Count -eq 0
}

Test-Case -Name "Get-AkEntraAttributeDelta clears absent values only when asked" {
    $entra = [pscustomobject]@{ displayName = "Jane Doe" }
    $ad = [pscustomobject]@{ DisplayName = "Jane Doe"; OfficePhone = "x204" }
    $delta = Get-AkEntraAttributeDelta -EntraUser $entra -AdUser $ad -ClearAbsent
    ($delta.Count -eq 1) -and ($null -eq $delta["OfficePhone"])
}

Test-Case -Name "Get-AkEntraSyncPlan creates an account for a new cloud user" {
    $entra = @([pscustomobject]@{ id = "1111"; userPrincipalName = "jane@contoso.com"; displayName = "Jane Doe"; userType = "Member"; accountEnabled = $true })
    $plan = Get-AkEntraSyncPlan -EntraUser $entra -AdUser @()
    ($plan.Count -eq 1) -and ($plan[0].Action -eq "Create")
}

Test-Case -Name "Get-AkEntraSyncPlan reports an anchored match in sync as None" {
    $entra = @([pscustomobject]@{ id = "1111"; userPrincipalName = "jane@contoso.com"; displayName = "Jane Doe"; userType = "Member"; accountEnabled = $true })
    $ad = @([pscustomobject]@{ adminDescription = "1111"; UserPrincipalName = "jane@contoso.com"; DisplayName = "Jane Doe"; Enabled = $true })
    $plan = Get-AkEntraSyncPlan -EntraUser $entra -AdUser $ad
    ($plan.Count -eq 1) -and ($plan[0].Action -eq "None") -and ($plan[0].MatchedBy -eq "Anchor")
}

Test-Case -Name "Get-AkEntraSyncPlan adopts an existing account by UPN and stamps the anchor" {
    $entra = @([pscustomobject]@{ id = "1111"; userPrincipalName = "jane@contoso.com"; displayName = "Jane Doe"; userType = "Member"; accountEnabled = $true })
    $ad = @([pscustomobject]@{ adminDescription = ""; UserPrincipalName = "JANE@contoso.com"; DisplayName = "Jane Doe"; Enabled = $true })
    $plan = Get-AkEntraSyncPlan -EntraUser $entra -AdUser $ad
    ($plan.Count -eq 1) -and ($plan[0].Action -eq "Update") -and ($plan[0].MatchedBy -eq "UserPrincipalName")
}

Test-Case -Name "Get-AkEntraSyncPlan updates a drifted attribute" {
    $entra = @([pscustomobject]@{ id = "1111"; userPrincipalName = "jane@contoso.com"; displayName = "Jane Doe"; jobTitle = "Partner"; userType = "Member"; accountEnabled = $true })
    $ad = @([pscustomobject]@{ adminDescription = "1111"; UserPrincipalName = "jane@contoso.com"; DisplayName = "Jane Doe"; Title = "Associate"; Enabled = $true })
    $plan = Get-AkEntraSyncPlan -EntraUser $entra -AdUser $ad
    ($plan[0].Action -eq "Update") -and ($plan[0].Changes["Title"] -eq "Partner")
}

Test-Case -Name "Get-AkEntraSyncPlan re-enables an account enabled again in Entra" {
    $entra = @([pscustomobject]@{ id = "1111"; userPrincipalName = "jane@contoso.com"; displayName = "Jane Doe"; userType = "Member"; accountEnabled = $true })
    $ad = @([pscustomobject]@{ adminDescription = "1111"; UserPrincipalName = "jane@contoso.com"; DisplayName = "Jane Doe"; Enabled = $false })
    (Get-AkEntraSyncPlan -EntraUser $entra -AdUser $ad)[0].Action -eq "Enable"
}

Test-Case -Name "Get-AkEntraSyncPlan reports an anchored account with no Entra user as an orphan" {
    $ad = @([pscustomobject]@{ adminDescription = "9999"; UserPrincipalName = "gone@contoso.com"; DisplayName = "Gone"; Enabled = $true })
    $plan = Get-AkEntraSyncPlan -EntraUser @() -AdUser $ad
    ($plan.Count -eq 1) -and ($plan[0].Action -eq "Orphan")
}

Test-Case -Name "Get-AkEntraSyncPlan never touches an account it did not stamp" {
    $ad = @([pscustomobject]@{ adminDescription = ""; UserPrincipalName = "hr@contoso.com"; DisplayName = "HR"; Enabled = $true })
    (Get-AkEntraSyncPlan -EntraUser @() -AdUser $ad).Count -eq 0
}

Test-Case -Name "Get-AkEntraSyncPlan skips a user already synced from AD" {
    $entra = @([pscustomobject]@{ id = "1111"; userPrincipalName = "jane@contoso.com"; displayName = "Jane Doe"; userType = "Member"; accountEnabled = $true; onPremisesSyncEnabled = $true })
    $plan = Get-AkEntraSyncPlan -EntraUser $entra -AdUser @()
    ($plan.Count -eq 1) -and ($plan[0].Action -eq "Skip")
}

Test-Case -Name "Get-AkEntraSyncPlan returns an array for empty input" {
    $plan = Get-AkEntraSyncPlan -EntraUser @() -AdUser @()
    $plan.Count -eq 0
}

Test-Case -Name "Get-AkEntraSyncPlan honours a custom anchor attribute" {
    $entra = @([pscustomobject]@{ id = "1111"; userPrincipalName = "jane@contoso.com"; displayName = "Jane Doe"; userType = "Member"; accountEnabled = $true })
    $ad = @([pscustomobject]@{ extensionAttribute15 = "1111"; UserPrincipalName = "other@contoso.com"; DisplayName = "Jane Doe"; Enabled = $true })
    $plan = Get-AkEntraSyncPlan -EntraUser $entra -AdUser $ad -AnchorProperty "extensionAttribute15"
    ($plan.Count -eq 1) -and ($plan[0].MatchedBy -eq "Anchor")
}

Test-Case -Name "Get-AkEntraAttributeMap maps usageLocation onto the country attribute" {
    (Get-AkEntraAttributeMap)["Country"] -eq "usageLocation"
}

Write-Host ""
Write-Host "=== Result ===" -ForegroundColor Cyan
Write-Host "Passed: $script:Passed" -ForegroundColor Green
if ($script:Failed -gt 0) {
    Write-Host "Failed: $script:Failed" -ForegroundColor Red
    exit 1
}

Write-Host "Failed: 0" -ForegroundColor Green
Write-Host ""
exit 0

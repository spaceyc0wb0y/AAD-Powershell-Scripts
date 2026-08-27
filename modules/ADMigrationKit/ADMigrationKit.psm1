<#
.SYNOPSIS
Shared helpers for the AD migration, reporting, and security scanning scripts.

.DESCRIPTION
This module defines the on-disk export package schema and the small set of
helpers every script in this repository shares: logging, package manifest
handling, distinguished name translation between two different domains,
principal mapping, and password generation.

Target platform is Windows PowerShell 5.1 on a domain-joined Windows Server.
Do not use PowerShell 7 only syntax in this module.
#>

Set-StrictMode -Version Latest

$script:LogFilePath = $null

# Relative layout of an export package. Every script agrees on these paths.
$script:PackageLayout = @{
    Manifest                = "manifest.json"
    DomainFolder            = "domain"
    DomainInfo              = "domain\domain.json"
    OrganizationalUnits     = "domain\organizational-units.csv"
    DomainPasswordPolicy    = "domain\default-domain-password-policy.json"
    FineGrainedPolicies     = "domain\fine-grained-password-policies.csv"
    IdentityFolder          = "identity"
    Users                   = "identity\users.csv"
    Groups                  = "identity\groups.csv"
    GroupMembers            = "identity\group-members.csv"
    Computers               = "identity\computers.csv"
    GpoFolder               = "gpo"
    GpoBackupFolder         = "gpo\backup"
    GpoInventory            = "gpo\gpo-inventory.csv"
    GpoLinks                = "gpo\gpo-links.csv"
    WmiFilters              = "gpo\wmi-filters.csv"
    GpoReportFolder         = "gpo\reports"
    FilesFolder             = "files"
    Shares                  = "files\shares.csv"
    ShareAccess             = "files\share-access.csv"
    NtfsAcl                 = "files\ntfs-acl.csv"
    LogFolder               = "logs"
    ImportFolder            = "import"
    PrincipalMap            = "import\principal-map.csv"
    GeneratedPasswords      = "import\generated-passwords.csv"
    MigrationTable          = "import\migration-table.migtable"
}

function Get-AkPackageLayout {
    <#
    .SYNOPSIS
    Returns the relative path map that describes an export package.
    #>
    [CmdletBinding()]
    param()

    return $script:PackageLayout
}

function Get-AkPackageItemPath {
    <#
    .SYNOPSIS
    Resolves a logical package item name to a full path inside a package root.

    .PARAMETER PackagePath
    Root folder of the export package.

    .PARAMETER Item
    Logical item name, for example Users or GpoInventory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,

        [Parameter(Mandatory)]
        [string]$Item
    )

    if (-not $script:PackageLayout.ContainsKey($Item)) {
        throw "Unknown package item '$Item'."
    }

    return (Join-Path -Path $PackagePath -ChildPath $script:PackageLayout[$Item])
}

function Start-AkLog {
    <#
    .SYNOPSIS
    Starts file logging for the current script run.

    .PARAMETER Path
    Full path of the log file to append to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $folder = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    $script:LogFilePath = $Path
    Write-AkLog -Message "Log started at $Path" -Level Info
}

function Stop-AkLog {
    <#
    .SYNOPSIS
    Stops file logging for the current script run.
    #>
    [CmdletBinding()]
    param()

    $script:LogFilePath = $null
}

function Write-AkLog {
    <#
    .SYNOPSIS
    Writes a timestamped message to the console and, when started, to the log file.

    .PARAMETER Message
    Message text.

    .PARAMETER Level
    Severity label. Controls console color only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("Info", "Success", "Warning", "Error", "Step")]
        [string]$Level = "Info"
    )

    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$stamp] [$($Level.ToUpper())] $Message"

    switch ($Level) {
        "Success" { Write-Host $line -ForegroundColor Green }
        "Warning" { Write-Host $line -ForegroundColor Yellow }
        "Error"   { Write-Host $line -ForegroundColor Red }
        "Step"    { Write-Host $line -ForegroundColor Cyan }
        default   { Write-Host $line }
    }

    if (-not [string]::IsNullOrWhiteSpace($script:LogFilePath)) {
        try {
            Add-Content -LiteralPath $script:LogFilePath -Value $line -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            # Never let logging failures stop a migration run.
            Write-Host "[$stamp] [WARNING] Could not write to log file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Get-AkSafeName {
    <#
    .SYNOPSIS
    Converts an arbitrary string into a value that is safe to use in a file name.

    .PARAMETER Value
    Source value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return "unnamed"
    }

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $builder = New-Object System.Text.StringBuilder

    foreach ($char in $Value.ToCharArray()) {
        if ($invalid -contains $char) {
            [void]$builder.Append("_")
        }
        else {
            [void]$builder.Append($char)
        }
    }

    return $builder.ToString().Trim()
}

function Assert-AkModule {
    <#
    .SYNOPSIS
    Verifies that a required PowerShell module is available.

    .PARAMETER Name
    Module name, for example ActiveDirectory or GroupPolicy.

    .PARAMETER Reason
    Text appended to the error message describing why the module is needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [string]$Reason
    )

    if (Get-Module -Name $Name) {
        return
    }

    $available = Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue
    if (-not $available) {
        $message = "Required module '$Name' is not installed."
        if (-not [string]::IsNullOrWhiteSpace($Reason)) {
            $message += " $Reason"
        }
        $message += " On Windows Server install it with: Install-WindowsFeature RSAT-AD-PowerShell, RSAT-Group-Policy-Mgmt-Tools"
        throw $message
    }

    Import-Module -Name $Name -ErrorAction Stop
}

function ConvertTo-AkDomainDn {
    <#
    .SYNOPSIS
    Converts a DNS domain name into its distinguished name form.

    .PARAMETER DnsDomainName
    DNS domain name, for example corp.contoso.local.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DnsDomainName
    )

    $parts = $DnsDomainName.Split(".") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $components = foreach ($part in $parts) { "DC=$part" }
    return ($components -join ",")
}

function ConvertTo-AkTargetDn {
    <#
    .SYNOPSIS
    Rewrites a distinguished name from the source domain naming context into the
    target domain naming context.

    .DESCRIPTION
    Only the trailing domain component is replaced. The OU path and leaf RDN are
    preserved, which is what makes a same-shape rebuild in a new domain possible.

    .PARAMETER SourceDn
    Distinguished name from the source domain.

    .PARAMETER SourceDomainDn
    Distinguished name of the source domain, for example DC=old,DC=local.

    .PARAMETER TargetDomainDn
    Distinguished name of the target domain, for example DC=new,DC=com.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$SourceDn,

        [Parameter(Mandatory)]
        [string]$SourceDomainDn,

        [Parameter(Mandatory)]
        [string]$TargetDomainDn
    )

    if ([string]::IsNullOrWhiteSpace($SourceDn)) {
        return $null
    }

    if ($SourceDn -eq $SourceDomainDn) {
        return $TargetDomainDn
    }

    $suffix = "," + $SourceDomainDn
    if ($SourceDn.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
        $prefix = $SourceDn.Substring(0, $SourceDn.Length - $suffix.Length)
        return ($prefix + "," + $TargetDomainDn)
    }

    # Not inside the source domain naming context. Return unchanged and let the
    # caller decide whether that is an error.
    return $SourceDn
}

function Get-AkParentDn {
    <#
    .SYNOPSIS
    Returns the parent container distinguished name of a distinguished name.

    .PARAMETER DistinguishedName
    Distinguished name to inspect.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    # Split on the first comma that is not escaped with a backslash.
    $index = -1
    for ($i = 0; $i -lt $DistinguishedName.Length; $i++) {
        if ($DistinguishedName[$i] -eq "," -and ($i -eq 0 -or $DistinguishedName[$i - 1] -ne "\")) {
            $index = $i
            break
        }
    }

    if ($index -lt 0) {
        return $null
    }

    return $DistinguishedName.Substring($index + 1)
}

function Get-AkDnDepth {
    <#
    .SYNOPSIS
    Returns the number of unescaped comma separated components in a DN.

    .DESCRIPTION
    Used to create parent-before-child ordering when rebuilding an OU tree.

    .PARAMETER DistinguishedName
    Distinguished name to measure.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return 0
    }

    $count = 1
    for ($i = 0; $i -lt $DistinguishedName.Length; $i++) {
        if ($DistinguishedName[$i] -eq "," -and ($i -eq 0 -or $DistinguishedName[$i - 1] -ne "\")) {
            $count++
        }
    }

    return $count
}

function Get-AkWellKnownRidMap {
    <#
    .SYNOPSIS
    Returns the map of well known domain relative identifiers to a stable label.

    .DESCRIPTION
    Built in group names change with the domain locale, so groups are matched by
    RID suffix rather than by display name when translating principals.
    #>
    [CmdletBinding()]
    param()

    return @{
        "500" = "Administrator"
        "501" = "Guest"
        "502" = "krbtgt"
        "512" = "DomainAdmins"
        "513" = "DomainUsers"
        "514" = "DomainGuests"
        "515" = "DomainComputers"
        "516" = "DomainControllers"
        "517" = "CertPublishers"
        "518" = "SchemaAdmins"
        "519" = "EnterpriseAdmins"
        "520" = "GroupPolicyCreatorOwners"
        "521" = "ReadOnlyDomainControllers"
        "522" = "CloneableDomainControllers"
        "525" = "ProtectedUsers"
        "526" = "KeyAdmins"
        "527" = "EnterpriseKeyAdmins"
        "553" = "RasAndIasServers"
        "571" = "AllowedRODCPasswordReplicationGroup"
        "572" = "DeniedRODCPasswordReplicationGroup"
    }
}

function Get-AkSidRid {
    <#
    .SYNOPSIS
    Returns the trailing relative identifier of a security identifier string.

    .PARAMETER Sid
    Security identifier in S-1-5-21-... form.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return $null
    }

    $parts = $Sid.Split("-")
    if ($parts.Count -lt 2) {
        return $null
    }

    return $parts[$parts.Count - 1]
}

function Test-AkIsBuiltInSid {
    <#
    .SYNOPSIS
    Returns true when a SID is a built in or well known SID rather than a domain
    principal that needs to be recreated.

    .PARAMETER Sid
    Security identifier string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return $false
    }

    # S-1-5-32-* is BUILTIN. Anything that is not S-1-5-21-* is not a domain SID.
    if ($Sid.StartsWith("S-1-5-32-", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    if (-not $Sid.StartsWith("S-1-5-21-", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

    return $false
}

function New-AkPassword {
    <#
    .SYNOPSIS
    Generates a random password that satisfies default AD complexity rules.

    .DESCRIPTION
    Passwords cannot be migrated across an unconnected forest without a trust and
    ADMT, so imported accounts receive a generated password and are flagged to
    change it at next sign in.

    .PARAMETER Length
    Total password length. Minimum 12.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(12, 128)]
        [int]$Length = 20
    )

    $upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower = "abcdefghijkmnpqrstuvwxyz"
    $digit = "23456789"
    $symbol = "!@#$%^&*()-_=+"
    $all = $upper + $lower + $digit + $symbol

    $bytes = New-Object "System.Byte[]" 4
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

    function Get-AkRandomChar {
        param([string]$Set)
        $rng.GetBytes($bytes)
        $value = [System.BitConverter]::ToUInt32($bytes, 0)
        return $Set[[int]($value % [uint32]$Set.Length)]
    }

    try {
        $chars = New-Object System.Collections.Generic.List[char]
        [void]$chars.Add((Get-AkRandomChar -Set $upper))
        [void]$chars.Add((Get-AkRandomChar -Set $lower))
        [void]$chars.Add((Get-AkRandomChar -Set $digit))
        [void]$chars.Add((Get-AkRandomChar -Set $symbol))

        for ($i = $chars.Count; $i -lt $Length; $i++) {
            [void]$chars.Add((Get-AkRandomChar -Set $all))
        }

        # Fisher-Yates shuffle so the guaranteed character classes are not always
        # in the first four positions.
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $rng.GetBytes($bytes)
            $value = [System.BitConverter]::ToUInt32($bytes, 0)
            $j = [int]($value % [uint32]($i + 1))
            $temp = $chars[$i]
            $chars[$i] = $chars[$j]
            $chars[$j] = $temp
        }

        return (-join $chars)
    }
    finally {
        $rng.Dispose()
    }
}

function Export-AkCsv {
    <#
    .SYNOPSIS
    Writes objects to a CSV file inside a package, creating the folder as needed.

    .PARAMETER InputObject
    Objects to write. An empty collection still creates the file when a header
    template is supplied by the caller.

    .PARAMETER Path
    Full destination path.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $folder = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    if ($null -eq $InputObject -or $InputObject.Count -eq 0) {
        Set-Content -LiteralPath $Path -Value "" -Encoding UTF8
        return 0
    }

    $InputObject | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    return $InputObject.Count
}

function Save-AkJson {
    <#
    .SYNOPSIS
    Writes an object to a JSON file inside a package, creating the folder as needed.

    .DESCRIPTION
    Package sections write into subfolders that may not exist yet. Export-AkCsv
    already creates its parent folder; this does the same for the JSON items so
    a section is not required to pre-create its own directory.

    .PARAMETER InputObject
    Object to serialise.

    .PARAMETER Path
    Full destination path.

    .PARAMETER Depth
    ConvertTo-Json depth.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateRange(1, 20)]
        [int]$Depth = 5
    )

    $folder = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($folder) -and -not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    $InputObject | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    return $Path
}

function Get-AkInvalidPropertyName {
    <#
    .SYNOPSIS
    Extracts the offending attribute name from an AD cmdlet property error.

    .DESCRIPTION
    Get-ADUser and friends fail the entire query when any single requested
    property is absent from the schema, and name it as "Parameter name: X".
    That wording is English; on a localised server this returns null and the
    caller rethrows rather than guessing.

    .PARAMETER Message
    Exception message from the failed AD cmdlet.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Message
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return $null }

    $match = [regex]::Match($Message, "Parameter name:\s*(?<name>[^\s]+)")
    if ($match.Success) { return $match.Groups["name"].Value }
    return $null
}

function Invoke-AkAdPropertyQuery {
    <#
    .SYNOPSIS
    Runs an AD query, dropping properties this schema does not have and retrying.

    .DESCRIPTION
    Property lists in this tooling are deliberately explicit, and some entries
    only exist where the schema has been extended - the Exchange attributes in
    particular. One absent attribute fails the whole query, which would lose an
    entire export section. The cmdlet names the offending property, so drop it,
    warn, and retry. A dropped property just leaves its CSV column empty, since
    every record is built with Get-AkPropertyValue.

    .PARAMETER Query
    Scriptblock taking one argument: the property list to request.

    .PARAMETER Property
    Properties to request on the first attempt.

    .PARAMETER DroppedProperty
    Optional [ref] that receives the names that had to be dropped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Query,

        [Parameter(Mandatory)]
        [string[]]$Property,

        [ref]$DroppedProperty
    )

    $current = @($Property)
    $dropped = New-Object System.Collections.Generic.List[string]

    while ($true) {
        try {
            $result = & $Query $current
            # Plain assignment, so no unary comma: nothing unrolls a property set.
            if ($DroppedProperty) { $DroppedProperty.Value = @($dropped.ToArray()) }
            return ,@($result)
        }
        catch {
            $bad = Get-AkInvalidPropertyName -Message $_.Exception.Message
            if (-not $bad -or ($current -notcontains $bad)) { throw }

            $dropped.Add($bad)
            $current = @($current | Where-Object { $_ -ne $bad })
            if ($current.Count -eq 0) { throw }

            Write-AkLog -Message "Property '$bad' does not exist in this schema. Retrying without it." -Level Warning
        }
    }
}

function Get-AkMappedLinkTarget {
    <#
    .SYNOPSIS
    Resolves one exported GPO link target through a caller-supplied link map.

    .DESCRIPTION
    When the new domain does not share the old OU layout, translating the source
    DN by suffix produces a container that does not exist and the link is lost.
    The caller supplies a hashtable keyed by source DN; the value is the DN in
    the new domain to link onto instead. An empty or null value means the link
    is deliberately not replayed, which is how you drop a link for an OU the new
    design does not have.

    Keys are matched case insensitively, because DNs read back from AD do not
    preserve the casing anyone typed.

    .PARAMETER SourceDn
    Link target DN as recorded in the export.

    .PARAMETER LinkTargetMap
    Hashtable of source DN to target DN.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$SourceDn,

        [hashtable]$LinkTargetMap
    )

    $result = [pscustomobject]@{
        Mapped   = $false
        Skip     = $false
        TargetDn = $null
    }

    if ($null -eq $LinkTargetMap -or $LinkTargetMap.Count -eq 0) { return $result }
    if ([string]::IsNullOrWhiteSpace($SourceDn)) { return $result }

    foreach ($key in $LinkTargetMap.Keys) {
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        if ([string]$key -ne $SourceDn -and ([string]$key).ToLowerInvariant() -ne $SourceDn.ToLowerInvariant()) { continue }

        $result.Mapped = $true
        $value = $LinkTargetMap[$key]
        if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) {
            $result.Skip = $true
        }
        else {
            $result.TargetDn = [string]$value
        }
        return $result
    }

    return $result
}

function Import-AkCsv {
    <#
    .SYNOPSIS
    Reads a CSV file from a package and always returns an array.

    .PARAMETER Path
    Full source path.

    .PARAMETER Required
    Throw when the file is missing instead of returning an empty array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [switch]$Required
    )

    # The unary comma on every return path is required. In Windows PowerShell an
    # array returned from a function is unrolled by the pipeline, so "return @()"
    # yields $null and a caller doing .Count fails under Set-StrictMode.
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($Required) {
            throw "Required package file was not found: $Path"
        }
        return ,@()
    }

    $content = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($content)) {
        return ,@()
    }

    return ,@(Import-Csv -LiteralPath $Path)
}

function New-AkPackageManifest {
    <#
    .SYNOPSIS
    Writes the package manifest that identifies the source domain and contents.

    .PARAMETER PackagePath
    Root folder of the export package.

    .PARAMETER SourceDomainDns
    DNS name of the exported domain.

    .PARAMETER SourceDomainNetBios
    NetBIOS name of the exported domain.

    .PARAMETER SourceDomainDn
    Distinguished name of the exported domain.

    .PARAMETER SourceDomainSid
    Domain SID of the exported domain.

    .PARAMETER Counts
    Hashtable of object counts collected during export.

    .PARAMETER Sections
    Section names that were included in this export.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,

        [Parameter(Mandatory)]
        [string]$SourceDomainDns,

        [string]$SourceDomainNetBios,

        [string]$SourceDomainDn,

        [string]$SourceDomainSid,

        [hashtable]$Counts,

        [string[]]$Sections
    )

    $manifest = [pscustomobject]@{
        SchemaVersion       = "1.0"
        ToolName            = "AAD-Powershell-Scripts/Export-AdEnvironment.ps1"
        CreatedUtc          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        CreatedBy           = "$($env:USERDOMAIN)\$($env:USERNAME)"
        CreatedOnComputer   = $env:COMPUTERNAME
        SourceDomainDns     = $SourceDomainDns
        SourceDomainNetBios = $SourceDomainNetBios
        SourceDomainDn      = $SourceDomainDn
        SourceDomainSid     = $SourceDomainSid
        Sections            = @($Sections)
        Counts              = $Counts
    }

    $path = Get-AkPackageItemPath -PackagePath $PackagePath -Item Manifest
    [void](Save-AkJson -InputObject $manifest -Path $path -Depth 6)
    return $manifest
}

function Get-AkPackageManifest {
    <#
    .SYNOPSIS
    Reads and validates the manifest of an export package.

    .PARAMETER PackagePath
    Root folder of the export package.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath
    )

    if (-not (Test-Path -LiteralPath $PackagePath)) {
        throw "Package path was not found: $PackagePath"
    }

    $path = Get-AkPackageItemPath -PackagePath $PackagePath -Item Manifest
    if (-not (Test-Path -LiteralPath $path)) {
        throw "No manifest.json was found in '$PackagePath'. Point -PackagePath at the folder created by Export-AdEnvironment.ps1."
    }

    $manifest = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json

    foreach ($required in @("SourceDomainDns", "SourceDomainDn")) {
        if (-not ($manifest.PSObject.Properties.Name -contains $required)) {
            throw "Package manifest is missing required property '$required'."
        }
    }

    return $manifest
}

function Get-AkPropertyValue {
    <#
    .SYNOPSIS
    Safely reads a property from an object that may not define it.

    .DESCRIPTION
    Set-StrictMode makes missing property access fatal, and CSV rows and AD
    objects both vary in which properties are present.

    .PARAMETER InputObject
    Object to read from.

    .PARAMETER Name
    Property name.

    .PARAMETER Default
    Value returned when the property is absent, null, or empty.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory)]
        [string]$Name,

        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }

    if (-not ($InputObject.PSObject.Properties.Name -contains $Name)) {
        return $Default
    }

    $value = $InputObject.$Name
    if ($null -eq $value) {
        return $Default
    }

    if ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }

    return $value
}

function ConvertTo-AkBoolean {
    <#
    .SYNOPSIS
    Converts a CSV string value back into a boolean.

    .PARAMETER Value
    Source value, typically "True" or "False" from a CSV round trip.

    .PARAMETER Default
    Value returned when the input cannot be interpreted.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value,

        [bool]$Default = $false
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [bool]) {
        return $Value
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $Default
    }

    switch ($text.Trim().ToLowerInvariant()) {
        "true"  { return $true }
        "false" { return $false }
        "1"     { return $true }
        "0"     { return $false }
        "yes"   { return $true }
        "no"    { return $false }
        default { return $Default }
    }
}

function ConvertFrom-AkMultiValue {
    <#
    .SYNOPSIS
    Splits a semicolon delimited CSV field back into an array.

    .PARAMETER Value
    Delimited string value.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    # See Import-AkCsv for why every return path uses the unary comma.
    if ($null -eq $Value) {
        return ,@()
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return ,@()
    }

    return ,@($text.Split(";") | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}

function ConvertTo-AkMultiValue {
    <#
    .SYNOPSIS
    Joins a multi valued attribute into a semicolon delimited CSV field.

    .PARAMETER Value
    Collection to join.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $Value
    )

    if ($null -eq $Value) {
        return ""
    }

    return (@($Value) -join ";")
}


function ConvertFrom-AkGpLink {
    <#
    .SYNOPSIS
    Parses a raw gPLink attribute into one record per linked GPO.

    .DESCRIPTION
    gPLink is a single string of the form:
        [LDAP://cn={GUID},cn=policies,cn=system,DC=old,DC=local;0][LDAP://...;2]

    The trailing number is a bit flag: 1 = link disabled, 2 = enforced.

    Precedence is the part that is easy to get wrong. The GPO written LAST in
    the attribute has the HIGHEST precedence, which the Group Policy Management
    Console displays as link order 1. Both the raw attribute position and the
    resolved GPMC link order are returned so an import can rebuild precedence
    exactly rather than approximately.

    .PARAMETER GpLink
    Raw gPLink attribute value. May be null or empty.

    .PARAMETER TargetDn
    Distinguished name of the object the links belong to.

    .PARAMETER TargetType
    Domain, OrganizationalUnit, or Site.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$GpLink,

        [Parameter(Mandatory)]
        [string]$TargetDn,

        [Parameter(Mandatory)]
        [ValidateSet("Domain", "OrganizationalUnit", "Site")]
        [string]$TargetType
    )

    $records = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($GpLink)) {
        return ,@()
    }

    $linkMatches = [regex]::Matches($GpLink, '\[LDAP://(?<dn>[^;\]]+);(?<flag>\d+)\]')
    $total = $linkMatches.Count

    for ($i = 0; $i -lt $total; $i++) {
        $dn = $linkMatches[$i].Groups["dn"].Value
        $flag = [int]$linkMatches[$i].Groups["flag"].Value

        $guid = $null
        $guidMatch = [regex]::Match($dn, '\{(?<guid>[0-9A-Fa-f\-]{36})\}')
        if ($guidMatch.Success) {
            $guid = $guidMatch.Groups["guid"].Value
        }

        $records.Add([pscustomobject]@{
            TargetDn       = $TargetDn
            TargetType     = $TargetType
            GpoId          = $guid
            GpoDn          = $dn
            AttributeIndex = $i
            LinkOrder      = $total - $i   # GPMC link order, 1 = highest precedence
            Enabled        = (($flag -band 1) -eq 0)
            Enforced       = (($flag -band 2) -eq 2)
            RawFlag        = $flag
        })
    }

    return ,$records.ToArray()
}


function Get-AkRdnValue {
    <#
    .SYNOPSIS
    Returns the value of the leading relative distinguished name component.

    .DESCRIPTION
    "CN=Smith\, Bob,OU=Sales,DC=old,DC=local" returns "Smith, Bob".

    An object's CN is not always its displayName, so recreating a user from its
    displayName can collide inside an OU where the original CNs did not. The
    source RDN is the faithful value to rebuild with.

    .PARAMETER DistinguishedName
    Distinguished name to read.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return $null
    }

    # Find the first comma that is not escaped with a backslash.
    $end = $DistinguishedName.Length
    for ($i = 0; $i -lt $DistinguishedName.Length; $i++) {
        if ($DistinguishedName[$i] -eq "," -and ($i -eq 0 -or $DistinguishedName[$i - 1] -ne "\")) {
            $end = $i
            break
        }
    }

    $rdn = $DistinguishedName.Substring(0, $end)
    $equals = $rdn.IndexOf("=")
    if ($equals -lt 0) {
        return $rdn
    }

    # Unescape the DN escaping rules that matter for a display value.
    $value = $rdn.Substring($equals + 1)
    return $value.Replace("\,", ",").Replace("\+", "+").Replace("\\", "\")
}

function Resolve-AkUpnTenantMatch {
    <#
    .SYNOPSIS
    Decides whether a proposed userPrincipalName change is safe, given what the
    target tenant already contains.

    .DESCRIPTION
    Renaming a synced user's UPN into a value another cloud object already holds
    produces a duplicate-attribute sync error. The same "collision" is the
    desired outcome when the AD account is NOT yet synced, because that is how a
    new AD account soft-matches onto an existing cloud-only user and inherits its
    mailbox, licences, and object ID.

    The two cases are indistinguishable from the AD side alone, so this function
    takes the state of both the current and the proposed UPN in the tenant and
    returns a match classification, an action, and the reason.

    .PARAMETER CurrentUpn
    The user's userPrincipalName in Active Directory today.

    .PARAMETER ProposedUpn
    The userPrincipalName the caller wants to assign.

    .PARAMETER CurrentCloudState
    State of the tenant object holding CurrentUpn: Absent, Synced, CloudOnly, or
    Unknown. Unknown means an object was found but its directory-sync flag could
    not be read from the tenant export.

    .PARAMETER ProposedCloudState
    State of the tenant object holding ProposedUpn, using the same values.

    .PARAMETER TenantDataAvailable
    Set when a tenant export was supplied. Without it no collision check is
    possible and every changeable row is reported as unchecked.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$CurrentUpn,

        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ProposedUpn,

        [ValidateSet("Absent", "Synced", "CloudOnly", "Unknown")]
        [string]$CurrentCloudState = "Absent",

        [ValidateSet("Absent", "Synced", "CloudOnly", "Unknown")]
        [string]$ProposedCloudState = "Absent",

        [switch]$TenantDataAvailable
    )

    $result = [PSCustomObject]@{
        TenantMatch = "NotChecked"
        Action      = "Review"
        Note        = ""
    }

    if ([string]::IsNullOrWhiteSpace($ProposedUpn)) {
        $result.TenantMatch = "NotApplicable"
        $result.Action = "Review"
        $result.Note = "No proposed UPN could be derived for this account."
        return $result
    }

    if ($CurrentUpn -and ($CurrentUpn.Trim() -eq $ProposedUpn.Trim())) {
        $result.TenantMatch = "NoChange"
        $result.Action = "Skip"
        $result.Note = "Already uses the target suffix."
        return $result
    }

    if (-not $TenantDataAvailable) {
        $result.TenantMatch = "NotChecked"
        $result.Action = "Change"
        $result.Note = "No tenant export supplied, so UPN collisions were not checked."
        return $result
    }

    switch ($ProposedCloudState) {
        "Absent" {
            $result.TenantMatch = "None"
            $result.Action = "Change"
            $result.Note = "No tenant object holds the proposed UPN."
        }
        "CloudOnly" {
            if ($CurrentCloudState -eq "Absent") {
                $result.TenantMatch = "CloudOnlyMatch"
                $result.Action = "Change"
                $result.Note = "Proposed UPN belongs to a cloud-only account and this AD user is not synced yet, so it should soft-match onto that account."
            }
            else {
                $result.TenantMatch = "CollisionCloudOnly"
                $result.Action = "Review"
                $result.Note = "This AD user already has a tenant object, and the proposed UPN belongs to a different cloud-only account. Renaming into it causes a duplicate-attribute error. Merge or rename the cloud-only account first."
            }
        }
        "Synced" {
            $result.TenantMatch = "CollisionSynced"
            $result.Action = "Review"
            $result.Note = "Proposed UPN is already held by a different synced account."
        }
        default {
            $result.TenantMatch = "CollisionUnknown"
            $result.Action = "Review"
            $result.Note = "Proposed UPN is held by a tenant object whose directory-sync state could not be read from the export."
        }
    }

    return $result
}


function Test-AkKeepableUpnSuffix {
    <#
    .SYNOPSIS
    Decides whether a user's existing UPN suffix should be left alone rather
    than moved onto the target suffix.

    .DESCRIPTION
    A domain part-way through a rename should not be dragged backwards, so a
    suffix that is already routable and unrelated to the target is kept.

    The trap this exists to avoid: an internal AD name that is a subdomain of
    the public domain, such as ad.contoso.com under contoso.com. It has a dot
    and a real TLD, so every naive "looks routable" test passes it, yet it is
    the single most common unverified suffix there is and is precisely what
    needs to change. Subdomains of the target are never keepable.

    .PARAMETER CurrentSuffix
    The suffix on the account today, with no leading @.

    .PARAMETER TargetSuffix
    The suffix the caller intends to move users onto.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$CurrentSuffix,

        [Parameter(Mandatory)]
        [string]$TargetSuffix
    )

    if ([string]::IsNullOrWhiteSpace($CurrentSuffix)) {
        return $false
    }

    $current = $CurrentSuffix.Trim().TrimStart("@").ToLowerInvariant()
    $target = $TargetSuffix.Trim().TrimStart("@").ToLowerInvariant()

    if ($current -eq $target) {
        return $false
    }

    # Single label names are never routable.
    if ($current -notlike "*.*") {
        return $false
    }

    # Reserved and conventional private TLDs.
    if ($current -match "\.(local|lan|internal|corp|intranet|priv|private|home|test|example|invalid|localdomain)$") {
        return $false
    }

    # ad.contoso.com under contoso.com, and any deeper nesting.
    if ($current.EndsWith(".$target")) {
        return $false
    }

    return $true
}


Export-ModuleMember -Function @(
    "Get-AkPackageLayout",
    "Get-AkPackageItemPath",
    "Start-AkLog",
    "Stop-AkLog",
    "Write-AkLog",
    "Get-AkSafeName",
    "Assert-AkModule",
    "ConvertTo-AkDomainDn",
    "ConvertTo-AkTargetDn",
    "Get-AkParentDn",
    "Get-AkDnDepth",
    "Get-AkWellKnownRidMap",
    "Get-AkSidRid",
    "Test-AkIsBuiltInSid",
    "New-AkPassword",
    "Export-AkCsv",
    "Import-AkCsv",
    "Get-AkMappedLinkTarget",
    "Get-AkInvalidPropertyName",
    "Invoke-AkAdPropertyQuery",
    "Save-AkJson",
    "New-AkPackageManifest",
    "Get-AkPackageManifest",
    "Get-AkPropertyValue",
    "ConvertTo-AkBoolean",
    "ConvertFrom-AkMultiValue",
    "ConvertTo-AkMultiValue",
    "ConvertFrom-AkGpLink",
    "Get-AkRdnValue",
    "Resolve-AkUpnTenantMatch",
    "Test-AkKeepableUpnSuffix"
)

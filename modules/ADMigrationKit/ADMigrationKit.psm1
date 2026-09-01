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
    PrintersFolder          = "printers"
    PrinterInventory        = "printers\printers.csv"
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

function Select-AkPresentAttribute {
    <#
    .SYNOPSIS
    Keeps only the attributes the target schema actually has.

    .DESCRIPTION
    Optional attributes vary by schema. mailNickname and the extensionAttribute
    range arrive with the Exchange schema extension, so a domain that never ran
    Exchange does not have them. Set-ADUser fails the whole call when any one
    attribute is unknown, which would otherwise abort a user mid-creation.

    .PARAMETER Attribute
    Hashtable of attribute name to value.

    .PARAMETER Present
    Attribute names known to exist in the target schema.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [hashtable]$Attribute,

        [string[]]$Present
    )

    $result = @{}
    if ($null -eq $Attribute -or $Attribute.Count -eq 0) { return $result }

    foreach ($key in $Attribute.Keys) {
        if ($Present -contains $key) { $result[$key] = $Attribute[$key] }
    }

    return $result
}

function Test-AkIsWellKnownPrincipalName {
    <#
    .SYNOPSIS
    True when a principal name resolves identically in any domain.

    .DESCRIPTION
    A GPO's DACL and settings reference identities like Everyone, Authenticated
    Users, and the NT AUTHORITY service accounts. They are not directory objects
    and never appear in a principal map, so a migration table must leave them
    alone rather than report them as unmapped.

    Names are matched after stripping an NT AUTHORITY or BUILTIN prefix, and a
    trailing @domain if the caller passes the UPN-style form a migration table
    uses.

    .PARAMETER Name
    Principal reference to test.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }

    $bare = $Name
    if ($bare -like "*\*") { $bare = $bare.Split("\")[-1] }
    if ($bare -like "*@*") { $bare = $bare.Substring(0, $bare.LastIndexOf("@")) }
    $bare = $bare.Trim()

    $wellKnown = @(
        "Everyone", "Authenticated Users", "ANONYMOUS LOGON", "LOCAL SERVICE",
        "NETWORK SERVICE", "SYSTEM", "SELF", "CREATOR OWNER", "CREATOR GROUP",
        "INTERACTIVE", "NETWORK", "BATCH", "SERVICE", "DIALUP",
        "ENTERPRISE DOMAIN CONTROLLERS", "TERMINAL SERVER USER",
        "REMOTE INTERACTIVE LOGON", "THIS ORGANIZATION", "OWNER RIGHTS",
        "IUSR", "RESTRICTED", "PROXY", "LOCAL", "CONSOLE LOGON"
    )

    foreach ($known in $wellKnown) {
        if ($bare -eq $known) { return $true }
    }

    return $false
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

    .DESCRIPTION
    A value can itself contain semicolons: an X.400 proxy address is
    'X400:c=US;a= ;p=Org;o=Exchange;s=Surname;g=Given', and a naive split
    shredded one of those into seven proxyAddresses entries on import
    (found 2026-08-28). ConvertTo-AkMultiValue therefore escapes ';' and '\'
    inside values, and this function splits only on unescaped semicolons.
    Packages written before the escaping contain no '\;' or '\\' sequences,
    so they parse exactly as they always did.

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

    # Split on ';' unless it is escaped. The doubled lookbehind keeps an
    # escaped backslash followed by a real separator ('a\\;b') splitting.
    $parts = [regex]::Split($text, '(?<!(?<!\\)\\);')

    return ,@($parts |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [regex]::Replace($_.Trim(), '\\([\\;])', '$1') })
}

function ConvertTo-AkMultiValue {
    <#
    .SYNOPSIS
    Joins a multi valued attribute into a semicolon delimited CSV field,
    escaping semicolons and backslashes inside each value so the field
    splits back into the original values. See ConvertFrom-AkMultiValue.

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

    return (@($Value) | ForEach-Object {
        ([string]$_ -replace '\\', '\\') -replace ';', '\;'
    }) -join ";"
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


function ConvertTo-AkBase64Url {
    <#
    .SYNOPSIS
    Encodes bytes as base64url, the encoding used by JSON Web Tokens.

    .DESCRIPTION
    Standard base64 with '+' and '/' translated and the '=' padding removed.
    RFC 7515 section 2.

    .PARAMETER Bytes
    Bytes to encode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    $text = [System.Convert]::ToBase64String($Bytes)
    return $text.TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function New-AkClientAssertion {
    <#
    .SYNOPSIS
    Builds a signed JWT client assertion for the Entra client credentials flow.

    .DESCRIPTION
    Hand rolled so that an unattended run on a domain controller needs no MSAL
    and no Microsoft Graph SDK. Windows PowerShell 5.1 on .NET 4.7.2 or later
    can sign the assertion with the certificate's CNG or CAPI private key.

    The x5t header must be the base64url of the raw SHA-1 certificate hash
    bytes, not of the hex thumbprint string. Encoding the hex string is the
    classic mistake and Entra answers it with AADSTS700027.

    .PARAMETER Certificate
    Certificate whose private key signs the assertion. Its public key must be
    uploaded to the app registration.

    .PARAMETER ClientId
    Application (client) ID of the app registration.

    .PARAMETER Audience
    Token endpoint the assertion is addressed to.

    .PARAMETER LifetimeMinutes
    Assertion lifetime. Entra rejects anything longer than 10 minutes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string]$Audience,

        [ValidateRange(1, 10)]
        [int]$LifetimeMinutes = 5
    )

    if (-not $Certificate.HasPrivateKey) {
        throw "Certificate $($Certificate.Thumbprint) has no private key available to this account."
    }

    $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($null -eq $key) {
        throw "Could not open the RSA private key for certificate $($Certificate.Thumbprint). ECC certificates are not supported here."
    }

    try {
        $epoch = New-Object System.DateTime(1970, 1, 1, 0, 0, 0, ([System.DateTimeKind]::Utc))
        $now = [System.DateTime]::UtcNow
        $notBefore = [long][System.Math]::Floor(($now.AddMinutes(-2) - $epoch).TotalSeconds)
        $expires = [long][System.Math]::Floor(($now.AddMinutes($LifetimeMinutes) - $epoch).TotalSeconds)
        $issued = [long][System.Math]::Floor(($now - $epoch).TotalSeconds)

        $header = [ordered]@{
            alg = "RS256"
            typ = "JWT"
            x5t = ConvertTo-AkBase64Url -Bytes $Certificate.GetCertHash()
        }
        $payload = [ordered]@{
            aud = $Audience
            iss = $ClientId
            sub = $ClientId
            jti = [guid]::NewGuid().ToString()
            nbf = $notBefore
            exp = $expires
            iat = $issued
        }

        $encoding = New-Object System.Text.UTF8Encoding($false)
        $headerText = ConvertTo-AkBase64Url -Bytes $encoding.GetBytes(($header | ConvertTo-Json -Compress))
        $payloadText = ConvertTo-AkBase64Url -Bytes $encoding.GetBytes(($payload | ConvertTo-Json -Compress))
        $signingInput = "$headerText.$payloadText"

        $signature = $key.SignData(
            $encoding.GetBytes($signingInput),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

        return "$signingInput." + (ConvertTo-AkBase64Url -Bytes $signature)
    }
    finally {
        if ($key -is [System.IDisposable]) {
            $key.Dispose()
        }
    }
}

function New-AkSamAccountName {
    <#
    .SYNOPSIS
    Derives a legal, unique sAMAccountName from a proposed name.

    .DESCRIPTION
    Strips the characters AD rejects, enforces the 20 character limit for user
    logon names, and resolves collisions with a numeric suffix. The suffix eats
    into the base name rather than pushing past the limit.

    .PARAMETER Candidate
    Proposed name, typically the local part of the UPN or the mail nickname.

    .PARAMETER Taken
    Names already in use. Compared case insensitively.

    .PARAMETER MaxLength
    Maximum length. 20 is the pre-Windows 2000 logon name limit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Candidate,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Taken = @(),

        [ValidateRange(4, 20)]
        [int]$MaxLength = 20
    )

    $base = ""
    if (-not [string]::IsNullOrWhiteSpace($Candidate)) {
        # Everything outside this set is either illegal in a sAMAccountName or
        # ambiguous once the account is used as DOMAIN\name.
        $base = ($Candidate -replace "[^A-Za-z0-9._-]", "").Trim(".")
    }

    if ([string]::IsNullOrWhiteSpace($base)) {
        $base = "user"
    }

    if ($base.Length -gt $MaxLength) {
        $base = $base.Substring(0, $MaxLength)
    }

    $used = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $Taken) {
        foreach ($name in $Taken) {
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                [void]$used.Add($name.Trim())
            }
        }
    }

    if (-not $used.Contains($base)) {
        return $base
    }

    for ($i = 2; $i -le 9999; $i++) {
        $suffix = [string]$i
        $room = $MaxLength - $suffix.Length
        if ($room -lt 1) {
            break
        }
        $stem = $base
        if ($stem.Length -gt $room) {
            $stem = $stem.Substring(0, $room)
        }
        $attempt = "$stem$suffix"
        if (-not $used.Contains($attempt)) {
            return $attempt
        }
    }

    throw "Could not derive a unique sAMAccountName from '$Candidate'."
}

function Get-AkEntraAttributeMap {
    <#
    .SYNOPSIS
    Returns the default Active Directory attribute to Entra property mapping.

    .DESCRIPTION
    Keys are the Set-ADUser / New-ADUser parameter names, values are the
    Microsoft Graph user property names as flattened by the sync script. Only
    directory profile data is mapped. Nothing here is a credential; Graph never
    exposes a password, so passwords cannot be part of any mapping.
    #>
    [CmdletBinding()]
    param()

    return [ordered]@{
        GivenName     = "givenName"
        Surname       = "surname"
        DisplayName   = "displayName"
        EmailAddress  = "mail"
        Title         = "jobTitle"
        Department    = "department"
        Company       = "companyName"
        Office        = "officeLocation"
        OfficePhone   = "businessPhone"
        MobilePhone   = "mobilePhone"
        StreetAddress = "streetAddress"
        City          = "city"
        State         = "state"
        PostalCode    = "postalCode"
        Country       = "usageLocation"
        EmployeeID    = "employeeId"
    }
}

function Test-AkEntraSyncCandidate {
    <#
    .SYNOPSIS
    Decides whether one Entra user is eligible to be created in Active Directory.

    .DESCRIPTION
    The eligibility test that keeps this from fighting Entra Connect. A user
    already synced from AD (onPremisesSyncEnabled true) must never be recreated;
    guests and accounts with no UPN are also out of scope.

    Returns a result object rather than a bare boolean so the caller can report
    exactly why a user was skipped.

    .PARAMETER EntraUser
    Flattened Graph user object.

    .PARAMETER ExcludeUserPrincipalName
    UPN patterns to exclude. Wildcards are supported.

    .PARAMETER IncludeGuest
    Also accept userType Guest. Off by default: guest shadow accounts are the
    B2B Application Proxy scenario, not the file and print scenario.

    .PARAMETER IncludeDisabled
    Also accept users whose Entra account is disabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $EntraUser,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExcludeUserPrincipalName = @(),

        [switch]$IncludeGuest,

        [switch]$IncludeDisabled
    )

    $upn = Get-AkPropertyValue -InputObject $EntraUser -Name "userPrincipalName"
    $result = [pscustomobject]@{
        Eligible            = $false
        Reason              = ""
        UserPrincipalName   = $upn
    }

    if ([string]::IsNullOrWhiteSpace($upn)) {
        $result.Reason = "No userPrincipalName"
        return $result
    }

    # A '#EXT#' UPN is the B2B guest form and is not a valid AD logon name.
    if ($upn -like "*#EXT#*") {
        $result.Reason = "External (#EXT#) UPN"
        return $result
    }

    $synced = Get-AkPropertyValue -InputObject $EntraUser -Name "onPremisesSyncEnabled"
    if ($true -eq $synced) {
        $result.Reason = "Already synced from on-premises AD"
        return $result
    }

    $userType = Get-AkPropertyValue -InputObject $EntraUser -Name "userType" -Default "Member"
    if (-not $IncludeGuest -and $userType -ne "Member") {
        $result.Reason = "userType is $userType"
        return $result
    }

    $enabled = Get-AkPropertyValue -InputObject $EntraUser -Name "accountEnabled"
    if (-not $IncludeDisabled -and $false -eq $enabled) {
        $result.Reason = "Entra account is disabled"
        return $result
    }

    if ($null -ne $ExcludeUserPrincipalName) {
        foreach ($pattern in $ExcludeUserPrincipalName) {
            if ([string]::IsNullOrWhiteSpace($pattern)) {
                continue
            }
            if ($upn -like $pattern.Trim()) {
                $result.Reason = "Excluded by pattern $pattern"
                return $result
            }
        }
    }

    $result.Eligible = $true
    $result.Reason = "Cloud only $userType"
    return $result
}

function Get-AkEntraAttributeDelta {
    <#
    .SYNOPSIS
    Compares an existing AD user against its Entra source and returns the changes.

    .DESCRIPTION
    Returns a hashtable of AD property name to new value, holding only the
    properties that actually differ. Comparison is case sensitive so a corrected
    name casing is treated as a change.

    .PARAMETER EntraUser
    Flattened Graph user object.

    .PARAMETER AdUser
    Existing AD user object.

    .PARAMETER AttributeMap
    AD property to Entra property mapping. Defaults to Get-AkEntraAttributeMap.

    .PARAMETER ClearAbsent
    Also clear AD attributes that are empty in Entra. Off by default, so data
    only present on premises (a desk phone, say) is left alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $EntraUser,

        [Parameter(Mandatory)]
        [AllowNull()]
        $AdUser,

        [System.Collections.IDictionary]$AttributeMap,

        [switch]$ClearAbsent
    )

    if ($null -eq $AttributeMap) {
        $AttributeMap = Get-AkEntraAttributeMap
    }

    $changes = @{}
    foreach ($adProperty in $AttributeMap.Keys) {
        $entraProperty = $AttributeMap[$adProperty]
        $newValue = Get-AkPropertyValue -InputObject $EntraUser -Name $entraProperty
        $oldValue = Get-AkPropertyValue -InputObject $AdUser -Name $adProperty

        if ($null -eq $newValue) {
            if ($ClearAbsent -and $null -ne $oldValue) {
                $changes[$adProperty] = $null
            }
            continue
        }

        $newText = [string]$newValue
        $oldText = ""
        if ($null -ne $oldValue) {
            $oldText = [string]$oldValue
        }

        if ($newText -cne $oldText) {
            $changes[$adProperty] = $newText
        }
    }

    return $changes
}

function Get-AkEntraSyncPlan {
    <#
    .SYNOPSIS
    Works out what has to happen in AD for one pass of the Entra to AD sync.

    .DESCRIPTION
    Pure planning: no directory calls, no Graph calls, so the decision logic is
    testable off a domain. Matching is by the anchor attribute first (the Entra
    objectId stamped on the AD object at creation) and by userPrincipalName
    second, which is what lets the tool adopt accounts that already exist.

    Actions returned:
      Create  - eligible Entra user with no AD account
      Update  - AD account exists and its attributes or its anchor drifted
      Enable  - AD account is disabled while the Entra account is enabled
      Orphan  - AD account carries an anchor no longer present in the Entra set
      Skip    - Entra user that failed the eligibility test

    Note the deliberate consequence of scoping by group: a user removed from the
    scope group disappears from the Entra set and is reported as an orphan. That
    is the deprovisioning path, not a bug.

    .PARAMETER EntraUser
    Flattened Graph users in scope.

    .PARAMETER AdUser
    Existing AD users read from the target OU.

    .PARAMETER AnchorProperty
    Property on the AD objects holding the stamped Entra objectId.

    .PARAMETER AttributeMap
    AD property to Entra property mapping. Defaults to Get-AkEntraAttributeMap.

    .PARAMETER ExcludeUserPrincipalName
    UPN patterns to exclude.

    .PARAMETER IncludeGuest
    Treat guests as eligible.

    .PARAMETER IncludeDisabled
    Treat Entra-disabled users as eligible.

    .PARAMETER ClearAbsent
    Clear AD attributes that are empty in Entra.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$EntraUser,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$AdUser,

        [string]$AnchorProperty = "adminDescription",

        [System.Collections.IDictionary]$AttributeMap,

        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExcludeUserPrincipalName = @(),

        [switch]$IncludeGuest,

        [switch]$IncludeDisabled,

        [switch]$ClearAbsent
    )

    if ($null -eq $AttributeMap) {
        $AttributeMap = Get-AkEntraAttributeMap
    }

    $byAnchor = @{}
    $byUpn = @{}
    $adAccounts = @()
    if ($null -ne $AdUser) {
        $adAccounts = $AdUser
    }

    foreach ($account in $adAccounts) {
        $anchor = Get-AkPropertyValue -InputObject $account -Name $AnchorProperty
        if (-not [string]::IsNullOrWhiteSpace($anchor)) {
            $key = ([string]$anchor).Trim().ToLowerInvariant()
            if (-not $byAnchor.ContainsKey($key)) {
                $byAnchor[$key] = $account
            }
        }

        $accountUpn = Get-AkPropertyValue -InputObject $account -Name "UserPrincipalName"
        if (-not [string]::IsNullOrWhiteSpace($accountUpn)) {
            $upnKey = ([string]$accountUpn).Trim().ToLowerInvariant()
            if (-not $byUpn.ContainsKey($upnKey)) {
                $byUpn[$upnKey] = $account
            }
        }
    }

    $plan = New-Object System.Collections.Generic.List[object]
    $matchedAnchors = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

    $entraAccounts = @()
    if ($null -ne $EntraUser) {
        $entraAccounts = $EntraUser
    }

    foreach ($user in $entraAccounts) {
        $upn = Get-AkPropertyValue -InputObject $user -Name "userPrincipalName"
        $objectId = Get-AkPropertyValue -InputObject $user -Name "id"
        $eligibility = Test-AkEntraSyncCandidate -EntraUser $user `
            -ExcludeUserPrincipalName $ExcludeUserPrincipalName `
            -IncludeGuest:$IncludeGuest -IncludeDisabled:$IncludeDisabled

        $item = [pscustomobject]@{
            Action            = "Skip"
            Reason            = $eligibility.Reason
            EntraObjectId     = $objectId
            UserPrincipalName = $upn
            DisplayName       = Get-AkPropertyValue -InputObject $user -Name "displayName"
            MatchedBy         = ""
            Changes           = @{}
            AdUser            = $null
            EntraUser         = $user
        }

        if (-not $eligibility.Eligible) {
            $plan.Add($item)
            continue
        }

        $match = $null
        if (-not [string]::IsNullOrWhiteSpace($objectId) -and $byAnchor.ContainsKey(([string]$objectId).ToLowerInvariant())) {
            $match = $byAnchor[([string]$objectId).ToLowerInvariant()]
            $item.MatchedBy = "Anchor"
        }
        elseif (-not [string]::IsNullOrWhiteSpace($upn) -and $byUpn.ContainsKey(([string]$upn).ToLowerInvariant())) {
            $match = $byUpn[([string]$upn).ToLowerInvariant()]
            $item.MatchedBy = "UserPrincipalName"
        }

        if ($null -eq $match) {
            $item.Action = "Create"
            $item.Reason = $eligibility.Reason
            $plan.Add($item)
            continue
        }

        $item.AdUser = $match
        $matchedAnchor = Get-AkPropertyValue -InputObject $match -Name $AnchorProperty
        if (-not [string]::IsNullOrWhiteSpace($matchedAnchor)) {
            [void]$matchedAnchors.Add(([string]$matchedAnchor).Trim())
        }

        $changes = Get-AkEntraAttributeDelta -EntraUser $user -AdUser $match -AttributeMap $AttributeMap -ClearAbsent:$ClearAbsent
        $item.Changes = $changes

        $adEnabled = Get-AkPropertyValue -InputObject $match -Name "Enabled"
        $entraEnabled = Get-AkPropertyValue -InputObject $user -Name "accountEnabled"

        $needsAnchor = [string]::IsNullOrWhiteSpace($matchedAnchor)

        if ($false -eq $adEnabled -and $true -eq $entraEnabled) {
            $item.Action = "Enable"
            $item.Reason = "AD account disabled while the Entra account is enabled"
        }
        elseif ($changes.Count -gt 0 -or $needsAnchor) {
            $item.Action = "Update"
            if ($needsAnchor) {
                $item.Reason = "Adopting existing account and stamping the anchor"
            }
            else {
                $item.Reason = "$($changes.Count) attribute(s) differ"
            }
        }
        else {
            $item.Action = "None"
            $item.Reason = "In sync"
        }

        $plan.Add($item)
    }

    foreach ($account in $adAccounts) {
        $anchor = Get-AkPropertyValue -InputObject $account -Name $AnchorProperty
        if ([string]::IsNullOrWhiteSpace($anchor)) {
            # Never touch an account this tool did not create. Anything in the OU
            # without an anchor belongs to someone else.
            continue
        }
        if ($matchedAnchors.Contains(([string]$anchor).Trim())) {
            continue
        }

        $plan.Add([pscustomobject]@{
            Action            = "Orphan"
            Reason            = "No Entra user in scope carries this anchor"
            EntraObjectId     = ([string]$anchor).Trim()
            UserPrincipalName = Get-AkPropertyValue -InputObject $account -Name "UserPrincipalName"
            DisplayName       = Get-AkPropertyValue -InputObject $account -Name "DisplayName"
            MatchedBy         = "Anchor"
            Changes           = @{}
            AdUser            = $account
            EntraUser         = $null
        })
    }

    return ,@($plan.ToArray())
}


function Update-AkProfwizConfig {
    <#
    .SYNOPSIS
    Writes a Profwiz.config for ForensiT User Profile Wizard by merging
    settings into the vendor's own template file.

    .DESCRIPTION
    Profwiz.config's root element and full schema are the vendor's to change,
    and the file ships alongside Profwiz.exe in every ForensiT download. So
    this never fabricates the file: it loads the shipped template, replaces
    the values of the elements it is given (matched by element name anywhere
    in the document), and saves the result. An element the template does not
    contain is an error, not a silent skip - that is either a typo or a
    schema change worth knowing about.

    .PARAMETER TemplatePath
    The Profwiz.config that ships with User Profile Wizard.

    .PARAMETER OutputPath
    Where to write the merged config.

    .PARAMETER Setting
    Element name to value map, for example @{ Domain = "ad.contoso.com" }.
    Values are written as element text; booleans should be passed as the
    strings "True" or "False", matching the file's own convention.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TemplatePath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [hashtable]$Setting
    )

    if (-not (Test-Path -LiteralPath $TemplatePath)) {
        throw "Profwiz.config template '$TemplatePath' does not exist."
    }

    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.Load((Resolve-Path -LiteralPath $TemplatePath).Path)

    $missing = @()
    foreach ($key in @($Setting.Keys | Sort-Object)) {
        $node = $xml.SelectSingleNode("//*[local-name()='$key']")
        if ($null -eq $node) {
            $missing += $key
            continue
        }
        $node.InnerText = [string]$Setting[$key]
    }

    if ($missing.Count -gt 0) {
        throw "Template '$TemplatePath' has no element(s): $($missing -join ', '). Is this the Profwiz.config that ships with User Profile Wizard?"
    }

    $xml.Save($OutputPath)
}


function Get-AkPrintbrmArgument {
    <#
    .SYNOPSIS
    Builds the argument list for a Printbrm.exe backup or restore.

    .DESCRIPTION
    Printbrm is the supported way to move print queues WITH their drivers,
    ports, and processors between servers. Kept as a pure builder so the
    offline tests can pin the exact arguments; Invoke-AkPrintbrm runs them.

    .PARAMETER Mode
    Backup writes a .printerExport file; Restore replays one.

    .PARAMETER FilePath
    The .printerExport file to write or read.

    .PARAMETER Server
    Remote print server to operate against (\\name is added). Omit to act on
    the local machine, which is the reliable choice: run backup ON the old
    print server and restore ON the new one where you can.

    .PARAMETER Force
    Restore only: overwrite queues that already exist on the target.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Backup", "Restore")]
        [string]$Mode,

        [Parameter(Mandatory)]
        [string]$FilePath,

        [string]$Server,

        [switch]$Force
    )

    $arguments = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $arguments.Add("-s")
        $arguments.Add("\\" + $Server.Trim().TrimStart("\"))
    }
    if ($Mode -eq "Backup") {
        $arguments.Add("-b")
    }
    else {
        $arguments.Add("-r")
        if ($Force) {
            # -o force replaces an existing queue instead of skipping it.
            $arguments.Add("-o")
            $arguments.Add("force")
        }
    }
    $arguments.Add("-f")
    $arguments.Add($FilePath)

    return ,@($arguments.ToArray())
}


function Invoke-AkPrintbrm {
    <#
    .SYNOPSIS
    Runs Printbrm.exe with the given backup or restore arguments and throws
    on failure.

    .DESCRIPTION
    Printbrm.exe ships with the Print Management tools
    (%SystemRoot%\System32\Spool\Tools). Its output is streamed into the log,
    because Printbrm reports per-queue and per-driver problems only on
    stdout, and a driver that failed to restore is exactly what you need to
    know about.

    .PARAMETER Argument
    Argument list from Get-AkPrintbrmArgument.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Argument
    )

    $printbrm = Join-Path -Path $env:SystemRoot -ChildPath "System32\Spool\Tools\Printbrm.exe"
    if (-not (Test-Path -LiteralPath $printbrm)) {
        throw "Printbrm.exe was not found at $printbrm. Install the Print Management tools (RSAT-Print-Services) or run this on a machine with the Print Server role."
    }

    Write-AkLog -Message "Printbrm $($Argument -join ' ')" -Level Info
    $output = & $printbrm @Argument 2>&1
    foreach ($line in @($output)) {
        $text = [string]$line
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            Write-AkLog -Message "  $text" -Level Info
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Printbrm.exe exited with code $LASTEXITCODE. Read its output above; a locked spooler or an in-use driver is the usual cause."
    }
}


function Get-AkPrimarySmtp {
    <#
    .SYNOPSIS
    Returns the primary SMTP address from proxyAddresses, or an empty string.

    .DESCRIPTION
    The primary entry is the one with an uppercase SMTP: prefix, so the match
    must be case sensitive. Promoted from Set-AdUpnSuffix.ps1 so the Entra
    alignment checks share it.

    .PARAMETER ProxyAddresses
    The proxyAddresses collection, or null.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $ProxyAddresses
    )

    foreach ($proxy in @($ProxyAddresses)) {
        $text = [string]$proxy
        if ($text -cmatch "^SMTP:") {
            return $text.Substring(5)
        }
    }

    return ""
}


function Get-AkCsvColumnName {
    <#
    .SYNOPSIS
    Finds a column by any of several candidate names, ignoring case and spaces.

    .DESCRIPTION
    The Entra portal user export has renamed its columns more than once, so
    consumers pass every name a column has ever had. Promoted from
    Set-AdUpnSuffix.ps1.

    .PARAMETER Row
    A sample row (any object with the export's properties), or null.

    .PARAMETER Candidate
    Column names to try, in order of preference.
    #>
    [CmdletBinding()]
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


function Initialize-AkGraphDependency {
    <#
    .SYNOPSIS
    Installs and imports Microsoft.Graph.Authentication so a script can call
    Connect-MgGraph and Invoke-MgGraphRequest on a stock server.

    .DESCRIPTION
    Windows PowerShell 5.1 ships without the Graph SDK and often without the
    NuGet package provider, and its default TLS settings cannot reach the
    PowerShell Gallery. This puts all three right, per current user, without
    needing local administrator rights:

      1. Force TLS 1.2 for this session.
      2. Install the NuGet package provider if it is missing.
      3. Install Microsoft.Graph.Authentication (CurrentUser) if it is missing.
      4. Import it.

    Only Microsoft.Graph.Authentication is installed, deliberately: with it,
    Invoke-MgGraphRequest can call any Graph endpoint, and the remaining forty
    Microsoft.Graph.* modules add nothing but install time.

    On a machine with no internet access this throws with instructions instead
    of hanging: copy the module folder from a connected machine, or use the
    calling script's offline CSV mode where it offers one.
    #>
    [CmdletBinding()]
    param()

    $moduleName = "Microsoft.Graph.Authentication"

    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-AkLog -Message "$moduleName is not installed. Installing for the current user from the PowerShell Gallery." -Level Step

        # 5.1 defaults to TLS 1.0 outbound; the Gallery requires 1.2.
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        try {
            if (-not (Get-PackageProvider -Name "NuGet" -ListAvailable -ErrorAction SilentlyContinue)) {
                Write-AkLog -Message "Installing the NuGet package provider." -Level Info
                Install-PackageProvider -Name "NuGet" -MinimumVersion "2.8.5.201" -Scope CurrentUser -Force | Out-Null
            }
            Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
        }
        catch {
            throw "Could not install $moduleName from the PowerShell Gallery: $($_.Exception.Message). If this machine has no internet access, copy the module folder from a connected machine into `$HOME\Documents\WindowsPowerShell\Modules, or use the script's -TenantUserCsv offline mode."
        }
    }

    Import-Module -Name $moduleName -ErrorAction Stop
    $version = (Get-Module -Name $moduleName).Version
    Write-AkLog -Message "$moduleName $version loaded." -Level Info
}


function Get-AkDirectoryAlignmentFinding {
    <#
    .SYNOPSIS
    Compares AD users against Entra tenant users and returns the findings that
    predict duplicates, dropped addresses, or blocked adoption when directory
    synchronization is widened.

    .DESCRIPTION
    Pure comparison, no directory or network access, so the offline smoke
    tests exercise every branch. Encodes the checks otherwise done by hand
    before widening a sync scope onto an existing tenant:

      AdUpnSuffixNotVerified   AD UPN suffix the tenant has not verified; the
                               user syncs as .onmicrosoft.com and never
                               soft-matches.
      CloudUserStillDirSynced  The matching cloud user is still flagged as
                               synced from some directory; adoption is blocked
                               until it is converted to cloud-only.
      RenamedInCloud           No cloud user holds this AD UPN, but one with
                               the same display name holds a different UPN.
                               Syncing now creates a duplicate person.
      AdUserNotInCloud         Enabled AD user with no cloud counterpart; sync
                               would create a brand-new cloud user.
      AmbiguousNameMatch       A cloud user with no AD counterpart shares a
                               display name with an AD user that matched a
                               DIFFERENT cloud user - two cloud accounts for
                               one person, or two people sharing a name.
      CloudUserNotInAd         Cloud-only user with no AD account; the input
                               list for Sync-EntraUsersToAd.ps1.
      PrimarySmtpMismatch      Matched pair whose primary SMTP differs. On-prem
                               masters the cloud after adoption, so this
                               renames the mailbox.
      CloudAliasMissingOnPrem  The cloud user holds an alias the AD object
                               lacks; adoption strips it.
      AdProxyOnUnverifiedDomain An on-prem address on a domain the tenant has
                               not verified; Entra drops it silently.
      MalformedProxyAddress    proxyAddresses entry with no scheme prefix -
                               the X.400 shredding regression check.

    .PARAMETER AdUser
    AD users as objects with SamAccountName, UserPrincipalName, DisplayName,
    Enabled, Mail, ProxyAddresses, DistinguishedName.

    .PARAMETER CloudUser
    Tenant users as objects with Id, DisplayName, UserPrincipalName,
    AccountEnabled, UserType, OnPremisesSyncEnabled, ProxyAddresses, Mail.
    Missing properties are tolerated.

    .PARAMETER VerifiedDomain
    Domains verified in the tenant. Empty skips the domain checks.

    .PARAMETER HasCloudProxyData
    The CloudUser objects carry real proxyAddresses. The portal CSV export
    does not, so without this the SMTP and alias checks are skipped rather
    than reporting every user as mismatched.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $AdUser,

        [AllowNull()]
        $CloudUser,

        [string[]]$VerifiedDomain = @(),

        [switch]$HasCloudProxyData
    )

    $findings = New-Object System.Collections.Generic.List[object]

    function Add-AlignmentFinding {
        param(
            [Parameter(Mandatory)][string]$Severity,
            [Parameter(Mandatory)][string]$Check,
            [Parameter(Mandatory)][string]$AffectedObject,
            [string]$Attribute = "",
            [string]$Value = "",
            [Parameter(Mandatory)][string]$Finding,
            [Parameter(Mandatory)][string]$Recommendation
        )
        $findings.Add([pscustomobject]@{
            Severity       = $Severity
            Check          = $Check
            AffectedObject = $AffectedObject
            Attribute      = $Attribute
            Value          = $Value
            Finding        = $Finding
            Recommendation = $Recommendation
        })
    }

    function Get-AddressDomain {
        param([AllowEmptyString()][string]$Address)
        if ($Address -like "*@*") {
            return $Address.Substring($Address.LastIndexOf("@") + 1).ToLowerInvariant()
        }
        return ""
    }

    $verified = @($VerifiedDomain | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })

    # ------------------------------------------------------------------
    # Index the tenant
    # ------------------------------------------------------------------
    $cloudByUpn = @{}
    $cloudByName = @{}
    foreach ($cloud in @($CloudUser)) {
        $upn = [string](Get-AkPropertyValue -InputObject $cloud -Name "UserPrincipalName" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($upn)) {
            $cloudByUpn[$upn.Trim().ToLowerInvariant()] = $cloud
        }
        $name = [string](Get-AkPropertyValue -InputObject $cloud -Name "DisplayName" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $key = $name.Trim().ToLowerInvariant()
            if (-not $cloudByName.ContainsKey($key)) { $cloudByName[$key] = New-Object System.Collections.Generic.List[object] }
            $cloudByName[$key].Add($cloud)
        }
    }

    $adUpnSet = @{}
    $adByName = @{}
    foreach ($ad in @($AdUser)) {
        $upn = [string](Get-AkPropertyValue -InputObject $ad -Name "UserPrincipalName" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($upn)) { $adUpnSet[$upn.Trim().ToLowerInvariant()] = $ad }
        $name = [string](Get-AkPropertyValue -InputObject $ad -Name "DisplayName" -Default "")
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $key = $name.Trim().ToLowerInvariant()
            if (-not $adByName.ContainsKey($key)) { $adByName[$key] = $ad }
        }
    }

    $matchedPairs = 0

    # ------------------------------------------------------------------
    # AD -> cloud
    # ------------------------------------------------------------------
    foreach ($ad in @($AdUser)) {
        $sam = [string](Get-AkPropertyValue -InputObject $ad -Name "SamAccountName" -Default "")
        $upn = [string](Get-AkPropertyValue -InputObject $ad -Name "UserPrincipalName" -Default "")
        $displayName = [string](Get-AkPropertyValue -InputObject $ad -Name "DisplayName" -Default "")
        $proxies = @(Get-AkPropertyValue -InputObject $ad -Name "ProxyAddresses" -Default @())

        if ([string]::IsNullOrWhiteSpace($upn)) { continue }
        $upnKey = $upn.Trim().ToLowerInvariant()
        $upnSuffix = Get-AddressDomain -Address $upn

        if ($verified.Count -gt 0 -and $upnSuffix -and ($verified -notcontains $upnSuffix)) {
            Add-AlignmentFinding -Severity "Critical" -Check "AdUpnSuffixNotVerified" -AffectedObject $sam `
                -Attribute "userPrincipalName" -Value $upn `
                -Finding "UPN suffix '@$upnSuffix' is not verified in the tenant." `
                -Recommendation "The user would sync as .onmicrosoft.com and never soft-match. Verify the domain in the tenant or move the user to a verified suffix."
        }

        $cloud = $null
        if ($cloudByUpn.ContainsKey($upnKey)) { $cloud = $cloudByUpn[$upnKey] }

        if ($null -ne $cloud) {
            $matchedPairs++

            if (ConvertTo-AkBoolean -Value (Get-AkPropertyValue -InputObject $cloud -Name "OnPremisesSyncEnabled") -Default $false) {
                Add-AlignmentFinding -Severity "Critical" -Check "CloudUserStillDirSynced" -AffectedObject $sam `
                    -Attribute "onPremisesSyncEnabled" -Value $upn `
                    -Finding "The matching cloud user is still flagged as directory-synced." `
                    -Recommendation "Soft match cannot adopt a synced object. Remove it from the old sync scope and let it convert to cloud-only before widening this sync."
            }

            if ($HasCloudProxyData) {
                $adPrimary = Get-AkPrimarySmtp -ProxyAddresses $proxies
                $cloudProxies = @(Get-AkPropertyValue -InputObject $cloud -Name "ProxyAddresses" -Default @())
                $cloudPrimary = Get-AkPrimarySmtp -ProxyAddresses $cloudProxies
                if ([string]::IsNullOrWhiteSpace($cloudPrimary)) {
                    $cloudPrimary = [string](Get-AkPropertyValue -InputObject $cloud -Name "Mail" -Default "")
                }

                if ($adPrimary -and $cloudPrimary -and ($adPrimary.ToLowerInvariant() -ne $cloudPrimary.ToLowerInvariant())) {
                    Add-AlignmentFinding -Severity "Medium" -Check "PrimarySmtpMismatch" -AffectedObject $sam `
                        -Attribute "proxyAddresses" -Value "$adPrimary -> $cloudPrimary" `
                        -Finding "On-prem primary SMTP '$adPrimary' differs from cloud primary '$cloudPrimary'." `
                        -Recommendation "On-prem masters the cloud after adoption, so syncing renames the mailbox. Align the on-prem primary with the cloud one first."
                }

                # Cloud aliases the AD object lacks are stripped when the
                # on-prem attribute becomes authoritative. onmicrosoft.com
                # entries are tenant-managed and excluded.
                $adAddressSet = @{}
                foreach ($proxy in $proxies) {
                    $text = [string]$proxy
                    if ($text -match "^(?i)smtp:") { $adAddressSet[$text.Substring(5).ToLowerInvariant()] = $true }
                }
                foreach ($proxy in $cloudProxies) {
                    $text = [string]$proxy
                    if ($text -notmatch "^(?i)smtp:") { continue }
                    $address = $text.Substring(5)
                    $domain = Get-AddressDomain -Address $address
                    if ($domain -like "*.onmicrosoft.com") { continue }
                    if (-not $adAddressSet.ContainsKey($address.ToLowerInvariant())) {
                        Add-AlignmentFinding -Severity "Medium" -Check "CloudAliasMissingOnPrem" -AffectedObject $sam `
                            -Attribute "proxyAddresses" -Value $address `
                            -Finding "Cloud address '$address' is absent from the AD object." `
                            -Recommendation "Adoption strips it. Add it on-prem as an smtp: entry (SMTP: if it is the primary) before enabling sync."
                    }
                }
            }
        }
        else {
            $renamed = $null
            if ($displayName) {
                $nameKey = $displayName.Trim().ToLowerInvariant()
                if ($cloudByName.ContainsKey($nameKey)) { $renamed = $cloudByName[$nameKey][0] }
            }

            if ($null -ne $renamed) {
                $cloudUpn = [string](Get-AkPropertyValue -InputObject $renamed -Name "UserPrincipalName" -Default "")
                Add-AlignmentFinding -Severity "High" -Check "RenamedInCloud" -AffectedObject $sam `
                    -Attribute "userPrincipalName" -Value "$upn -> $cloudUpn" `
                    -Finding "No cloud user holds '$upn', but '$displayName' exists in the cloud as '$cloudUpn'." `
                    -Recommendation "Syncing now creates a duplicate person. Change the AD UPN (and primary SMTP) to match the cloud value before widening the scope."
            }
            else {
                Add-AlignmentFinding -Severity "Medium" -Check "AdUserNotInCloud" -AffectedObject $sam `
                    -Attribute "userPrincipalName" -Value $upn `
                    -Finding "No cloud user matches '$upn'. Sync would create a new cloud account." `
                    -Recommendation "Intended for a genuinely new user. Otherwise keep the account out of the sync scope, or disable it if the person has left."
            }
        }

        foreach ($proxy in $proxies) {
            $text = [string]$proxy
            if ($text -notmatch "^[A-Za-z][A-Za-z0-9]*:") {
                Add-AlignmentFinding -Severity "Medium" -Check "MalformedProxyAddress" -AffectedObject $sam `
                    -Attribute "proxyAddresses" -Value $text `
                    -Finding "proxyAddresses entry '$text' has no scheme prefix." `
                    -Recommendation "Usually a shredded X.400 address from a semicolon-split import. Remove it; Entra rejects malformed entries."
                continue
            }
            if ($verified.Count -gt 0 -and $text -match "^(?i)smtp:") {
                $domain = Get-AddressDomain -Address $text.Substring(5)
                if ($domain -and ($verified -notcontains $domain) -and ($domain -notlike "*.onmicrosoft.com")) {
                    Add-AlignmentFinding -Severity "Medium" -Check "AdProxyOnUnverifiedDomain" -AffectedObject $sam `
                        -Attribute "proxyAddresses" -Value $text `
                        -Finding "Address domain '@$domain' is not verified in the tenant." `
                        -Recommendation "Entra silently drops addresses on unverified domains. Remove the entry, or verify the domain if it is still in use."
                }
            }
        }
    }

    # ------------------------------------------------------------------
    # Cloud -> AD
    # ------------------------------------------------------------------
    foreach ($cloud in @($CloudUser)) {
        $upn = [string](Get-AkPropertyValue -InputObject $cloud -Name "UserPrincipalName" -Default "")
        if ([string]::IsNullOrWhiteSpace($upn)) { continue }
        $upnKey = $upn.Trim().ToLowerInvariant()
        $suffix = Get-AddressDomain -Address $upn

        # onmicrosoft accounts (break-glass admins, service identities) and
        # guests are never provisioned into AD.
        if ($suffix -like "*.onmicrosoft.com") { continue }
        $userType = [string](Get-AkPropertyValue -InputObject $cloud -Name "UserType" -Default "Member")
        if ($userType -and $userType -ne "Member") { continue }
        if ($adUpnSet.ContainsKey($upnKey)) { continue }

        $displayName = [string](Get-AkPropertyValue -InputObject $cloud -Name "DisplayName" -Default "")

        $adTwin = $null
        if ($displayName) {
            $nameKey = $displayName.Trim().ToLowerInvariant()
            if ($adByName.ContainsKey($nameKey)) { $adTwin = $adByName[$nameKey] }
        }

        if ($null -ne $adTwin) {
            $twinUpn = [string](Get-AkPropertyValue -InputObject $adTwin -Name "UserPrincipalName" -Default "")
            $twinKey = $twinUpn.Trim().ToLowerInvariant()
            if ($twinUpn -and $cloudByUpn.ContainsKey($twinKey)) {
                # The AD account with this person's name already matched a
                # DIFFERENT cloud user, so the name exists in the cloud twice.
                Add-AlignmentFinding -Severity "High" -Check "AmbiguousNameMatch" -AffectedObject $upn `
                    -Attribute "displayName" -Value $displayName `
                    -Finding "Cloud user '$upn' has no AD account, but AD user '$twinUpn' with the same display name matched a different cloud user." `
                    -Recommendation "Either one person has two cloud accounts (delete or exclude one) or two people share a name (rename one for clarity). Resolve before provisioning."
                continue
            }
        }

        Add-AlignmentFinding -Severity "Info" -Check "CloudUserNotInAd" -AffectedObject $upn `
            -Attribute "userPrincipalName" -Value $displayName `
            -Finding "Cloud user has no AD account." `
            -Recommendation "Candidate for Sync-EntraUsersToAd.ps1 if the person needs shares or GPOs; otherwise nothing to do."
    }

    Add-AlignmentFinding -Severity "Info" -Check "MatchedPairs" -AffectedObject "(summary)" `
        -Value ([string]$matchedPairs) `
        -Finding "$matchedPairs AD user(s) match a cloud user by UPN and will soft-match on sync." `
        -Recommendation "No action. This is the adoption population."

    return ,@($findings.ToArray())
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
    "Test-AkIsWellKnownPrincipalName",
    "Select-AkPresentAttribute",
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
    "Test-AkKeepableUpnSuffix",
    "ConvertTo-AkBase64Url",
    "New-AkClientAssertion",
    "New-AkSamAccountName",
    "Get-AkEntraAttributeMap",
    "Test-AkEntraSyncCandidate",
    "Get-AkEntraAttributeDelta",
    "Get-AkEntraSyncPlan",
    "Get-AkPrimarySmtp",
    "Get-AkCsvColumnName",
    "Get-AkPrintbrmArgument",
    "Invoke-AkPrintbrm",
    "Update-AkProfwizConfig",
    "Initialize-AkGraphDependency",
    "Get-AkDirectoryAlignmentFinding"
)

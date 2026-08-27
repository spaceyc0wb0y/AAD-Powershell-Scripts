@{
    RootModule        = 'ADMigrationKit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b6d4a2f1-93c7-4a1e-8f52-2c7d5b0e4a19'
    Author            = 'Cesar Ricardo'
    CompanyName       = 'Adroit Technologies'
    Copyright         = '(c) Cesar Ricardo. All rights reserved.'
    Description       = 'Shared helpers for Active Directory export, cross-domain rebuild, security scanning, and Entra sync readiness scripts.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-AkPackageLayout',
        'Get-AkPackageItemPath',
        'Start-AkLog',
        'Stop-AkLog',
        'Write-AkLog',
        'Get-AkSafeName',
        'Assert-AkModule',
        'ConvertTo-AkDomainDn',
        'ConvertTo-AkTargetDn',
        'Get-AkParentDn',
        'Get-AkDnDepth',
        'Get-AkWellKnownRidMap',
        'Get-AkSidRid',
        'Test-AkIsBuiltInSid',
        'New-AkPassword',
        'Export-AkCsv',
        'Import-AkCsv',
        'New-AkPackageManifest',
        'Get-AkPackageManifest',
        'Get-AkPropertyValue',
        'ConvertTo-AkBoolean',
        'ConvertFrom-AkMultiValue',
        'ConvertTo-AkMultiValue',
        'ConvertFrom-AkGpLink',
        'Get-AkRdnValue',
        'Resolve-AkUpnTenantMatch',
        'Test-AkKeepableUpnSuffix'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags = @('ActiveDirectory', 'Migration', 'GroupPolicy', 'Entra', 'Security')
        }
    }
}

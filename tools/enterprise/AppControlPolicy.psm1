Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-ApprovedBasePolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ApprovedSha256
    )
    $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($hash -ne $ApprovedSha256) { throw 'Base policy does not match its approved SHA-256.' }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create((Resolve-Path -LiteralPath $Path).ProviderPath, $settings)
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    try { $document.Load($reader) } finally { $reader.Dispose() }
    $namespace = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespace.AddNamespace('si', 'urn:schemas-microsoft-com:sipolicy')
    $policyId = $document.SelectSingleNode('/si:SiPolicy/si:PolicyID', $namespace)
    $baseId = $document.SelectSingleNode('/si:SiPolicy/si:BasePolicyID', $namespace)
    if (-not $policyId -or -not $baseId -or $policyId.InnerText -ne $baseId.InnerText) {
        throw 'An existing multiple-policy-format base policy is required.'
    }
    $identifier = [Guid]::Empty
    if (-not [Guid]::TryParse($policyId.InnerText, [ref]$identifier)) { throw 'Invalid base policy identifier.' }
    $options = @($document.SelectNodes('/si:SiPolicy/si:Rules/si:Rule/si:Option', $namespace) | ForEach-Object { $_.InnerText })
    foreach ($required in 'Enabled:UMCI', 'Enabled:Allow Supplemental Policies', 'Enabled:Dynamic Code Security') {
        if ($required -notin $options) { throw "Base policy lacks $required." }
    }
    foreach ($broadTrust in 'Enabled:Managed Installer', 'Enabled:Intelligent Security Graph Authorization') {
        if ($broadTrust -in $options) { throw "Base policy contains broad trust option $broadTrust." }
    }
    foreach ($allow in $document.SelectNodes('/si:SiPolicy/si:FileRules/si:Allow', $namespace)) {
        if ($allow.HasAttribute('FilePath') -or -not $allow.HasAttribute('Hash')) {
            throw 'Base policy contains a broad non-hash file allow rule; review it separately.'
        }
    }
    [pscustomobject]@{
        PolicyId = '{' + $identifier.ToString().ToUpperInvariant() + '}'
        Sha256 = $hash
        AuditMode = ('Enabled:Audit Mode' -in $options)
    }
}

function Assert-HashOnlySupplement {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create((Resolve-Path -LiteralPath $Path).ProviderPath, $settings)
    $document = [Xml.XmlDocument]::new()
    $document.XmlResolver = $null
    try { $document.Load($reader) } finally { $reader.Dispose() }
    $namespace = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespace.AddNamespace('si', 'urn:schemas-microsoft-com:sipolicy')
    $allows = @($document.SelectNodes('/si:SiPolicy/si:FileRules/si:Allow', $namespace))
    if (-not $allows.Count) { throw 'The supplement has no executable hash rules.' }
    foreach ($allow in $allows) {
        if (-not $allow.HasAttribute('Hash') -or $allow.HasAttribute('FilePath') -or $allow.HasAttribute('FileName')) {
            throw 'The supplement contains an unexpected broad allow rule.'
        }
    }
    if ($document.SelectNodes('/si:SiPolicy/si:SigningScenarios/si:SigningScenario[@Value="12"]//si:AllowedSigner', $namespace).Count) {
        throw 'The supplement contains user-mode publisher trust instead of exact hashes.'
    }
}

Export-ModuleMember -Function Read-ApprovedBasePolicy, Assert-HashOnlySupplement

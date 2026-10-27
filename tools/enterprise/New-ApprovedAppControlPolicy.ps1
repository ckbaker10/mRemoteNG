#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReleaseDirectory,
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$BasePolicyPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ApprovedBasePolicySha256,
    [Parameter(Mandatory)][string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows ConfigCI tooling is required.' }
Import-Module (Join-Path $PSScriptRoot 'ReleaseManifest.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'AppControlPolicy.psm1') -Force
Import-Module ConfigCI -ErrorAction Stop
$manifest = Test-ReleaseManifest -ReleaseDirectory $ReleaseDirectory -ManifestPath $ManifestPath
$base = Read-ApprovedBasePolicy -Path $BasePolicyPath -ApprovedSha256 $ApprovedBasePolicySha256
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) { throw 'Use a new output directory for each policy generation.' }
$releaseRoot = (Resolve-Path -LiteralPath $ReleaseDirectory).ProviderPath.TrimEnd('\', '/')
if ($output.StartsWith($releaseRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Policy output must be outside the approved release directory.'
}
[IO.Directory]::CreateDirectory($output) | Out-Null
$xmlPath = Join-Path $output 'mRemoteNG.approved.xml'
New-CIPolicy -ScanPath $releaseRoot -UserPEs -Level Hash -MultiplePolicyFormat -FilePath $xmlPath | Out-Null
Set-CIPolicyIdInfo -FilePath $xmlPath -ResetPolicyID | Out-Null
Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName ('mRemoteNG approved ' + $manifest.SourceCommit.Substring(0, 12)) `
    -SupplementsBasePolicyID $base.PolicyId | Out-Null
Assert-HashOnlySupplement -Path $xmlPath
Test-ReleaseManifest -ReleaseDirectory $releaseRoot -ManifestPath $ManifestPath | Out-Null
$policy = [Xml.XmlDocument]::new()
$policy.XmlResolver = $null
$policy.Load($xmlPath)
$namespace = [Xml.XmlNamespaceManager]::new($policy.NameTable)
$namespace.AddNamespace('si', 'urn:schemas-microsoft-com:sipolicy')
$policyId = $policy.SelectSingleNode('/si:SiPolicy/si:PolicyID', $namespace).InnerText
$binaryPath = Join-Path $output ($policyId + '.cip')
ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binaryPath
$record = [ordered]@{
    SourceCommit = $manifest.SourceCommit
    ManifestSha256 = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
    BasePolicyId = $base.PolicyId
    BasePolicySha256 = $base.Sha256
    BaseAuditMode = $base.AuditMode
    SupplementalPolicyId = $policyId
    XmlSha256 = (Get-FileHash -LiteralPath $xmlPath -Algorithm SHA256).Hash
    BinarySha256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash
    DeploymentState = 'Generated only; not installed, signed or approved'
}
[IO.File]::WriteAllText((Join-Path $output 'generation.json'), ($record | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
Write-Output $binaryPath

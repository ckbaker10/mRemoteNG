#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReleaseDirectory,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][string]$OutputPath,
    [switch]$RequireValidSignatures
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReleaseManifest.psm1') -Force
$root = (Resolve-Path -LiteralPath $ReleaseDirectory).ProviderPath.TrimEnd('\', '/')
$output = [IO.Path]::GetFullPath($OutputPath)
if ($output.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Store the manifest outside the release directory to avoid a self-referential inventory.'
}
$files = @(Get-ReleaseFiles -ReleaseDirectory $root)
$rows = foreach ($file in $files) {
    $executable = [IO.Path]::GetExtension($file.FullPath) -in '.exe', '.dll', '.ocx', '.sys', '.ps1', '.psm1'
    $signatureStatus = 'NotApplicable'
    $thumbprint = $null
    if ($executable) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullPath
        $signatureStatus = [string]$signature.Status
        if ($signature.SignerCertificate) { $thumbprint = $signature.SignerCertificate.Thumbprint }
        if ($RequireValidSignatures -and $signatureStatus -ne 'Valid') {
            throw "A valid signature is required: $($file.RelativePath)"
        }
    }
    [pscustomobject][ordered]@{
        RelativePath = $file.RelativePath
        Length = $file.Length
        Sha256 = (Get-FileHash -LiteralPath $file.FullPath -Algorithm SHA256).Hash
        ExecutableComponent = $executable
        FileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullPath).FileVersion
        AuthenticodeStatus = $signatureStatus
        SignerThumbprint = $thumbprint
    }
}
$manifest = [pscustomobject][ordered]@{
    SchemaVersion = 1
    SourceCommit = $SourceCommit.ToLowerInvariant()
    GeneratedUtc = [DateTime]::UtcNow.ToString('o')
    InventoryEnvironment = [pscustomobject]@{
        OSVersion = [Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        ProcessBitness = [IntPtr]::Size * 8
    }
    HashAlgorithm = 'SHA256'
    HashPurpose = 'File inventory; not the Authenticode hashes used by App Control rules'
    Files = @($rows)
}
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output)) | Out-Null
$temporary = $output + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
try {
    [IO.File]::WriteAllText($temporary, ($manifest | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($output)) { [IO.File]::Replace($temporary, $output, $null) }
    else { [IO.File]::Move($temporary, $output) }
} finally {
    if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
}
Test-ReleaseManifest -ReleaseDirectory $root -ManifestPath $output | Out-Null
Write-Output $output

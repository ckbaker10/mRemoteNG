#requires -Version 5.1
# Standalone regression checks; no additional test modules are required.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReleaseManifest.psm1') -Force
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mrng-manifest-' + [Guid]::NewGuid().ToString('N'))
$release = Join-Path $temporary 'release'
$manifest = Join-Path $temporary 'manifest.json'
[IO.Directory]::CreateDirectory($release) | Out-Null
function Assert-Rejected([scriptblock]$Operation) {
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Expected manifest validation to reject this release.' }
}
try {
    $file = Join-Path $release 'synthetic.txt'
    [IO.File]::WriteAllText($file, 'approved')
    & (Join-Path $PSScriptRoot 'New-ReleaseManifest.ps1') -ReleaseDirectory $release `
        -SourceCommit ('a' * 40) -OutputPath $manifest | Out-Null
    Test-ReleaseManifest -ReleaseDirectory $release -ManifestPath $manifest | Out-Null
    $originalManifest = [IO.File]::ReadAllText($manifest)
    $invalid = $originalManifest | ConvertFrom-Json
    $invalid.Files[0].RelativePath = '../outside.txt'
    [IO.File]::WriteAllText($manifest, ($invalid | ConvertTo-Json -Depth 5))
    Assert-Rejected { Test-ReleaseManifest -ReleaseDirectory $release -ManifestPath $manifest }
    [IO.File]::WriteAllText($manifest, $originalManifest)
    [IO.File]::WriteAllText($file, 'modified')
    Assert-Rejected { Test-ReleaseManifest -ReleaseDirectory $release -ManifestPath $manifest }
    [IO.File]::WriteAllText($file, 'approved')
    [IO.File]::WriteAllText((Join-Path $release 'extra.txt'), 'unexpected')
    Assert-Rejected { Test-ReleaseManifest -ReleaseDirectory $release -ManifestPath $manifest }
    [IO.File]::Delete((Join-Path $release 'extra.txt'))
    [IO.File]::Delete($file)
    Assert-Rejected { Test-ReleaseManifest -ReleaseDirectory $release -ManifestPath $manifest }
    Write-Output 'PASS: approved, modified, added, missing and path-traversal release entries.'
} finally {
    if ([IO.Directory]::Exists($temporary)) { [IO.Directory]::Delete($temporary, $true) }
}

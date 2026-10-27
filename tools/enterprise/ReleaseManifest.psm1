Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ReleaseFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ReleaseDirectory)
    $resolved = (Resolve-Path -LiteralPath $ReleaseDirectory).ProviderPath
    $root = $resolved.TrimEnd('\', '/')
    if ($root -eq [IO.Path]::GetPathRoot($resolved).TrimEnd('\', '/')) {
        throw 'A dedicated release subdirectory is required; scanning a volume root is not supported.'
    }
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Release directory not found.' }
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Release roots must not be reparse points.'
    }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    $collected = [Collections.Generic.List[object]]::new()
    while ($pending.Count) {
        foreach ($entry in (Get-ChildItem -LiteralPath ($pending.Pop()) -Force)) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Release files and directories must not be reparse points.'
            }
            if ($entry.PSIsContainer) { $pending.Push($entry.FullName) }
            else { $collected.Add($entry) }
        }
    }
    $files = @($collected | Sort-Object FullName)
    if (-not $files.Count) { throw 'The release directory is empty.' }
    $seen = @{}
    foreach ($file in $files) {
        $relative = $file.FullName.Substring($root.Length + 1).Replace('\', '/')
        if ($seen.ContainsKey($relative)) { throw 'Release paths collide under Windows case-insensitive comparison.' }
        $seen[$relative] = $true
        [pscustomobject]@{
            RelativePath = $relative
            FullPath = $file.FullName
            Length = $file.Length
        }
    }
}

function Test-ReleaseManifest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReleaseDirectory,
        [Parameter(Mandatory)][string]$ManifestPath
    )
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    if ($manifest.SchemaVersion -ne 1 -or $manifest.HashAlgorithm -ne 'SHA256') {
        throw 'Unsupported release manifest format.'
    }
    $actual = @(Get-ReleaseFiles -ReleaseDirectory $ReleaseDirectory)
    $expected = @($manifest.Files)
    if ($actual.Count -ne $expected.Count) { throw 'Release file count differs from the manifest.' }
    $seen = @{}
    foreach ($entry in $expected) {
        $relative = [string]$entry.RelativePath
        if ($seen.ContainsKey($relative)) { throw 'Duplicate manifest path.' }
        $seen[$relative] = $true
        # Match the enumerated paths, rather than combining untrusted paths with a root.
        $matches = @($actual | Where-Object { $_.RelativePath -ceq $relative })
        if ($matches.Count -ne 1) { throw "Release path mismatch: $relative" }
        if ($matches[0].Length -ne $entry.Length) { throw "Release length mismatch: $relative" }
        $hash = (Get-FileHash -LiteralPath $matches[0].FullPath -Algorithm SHA256).Hash
        if ($hash -cne $entry.Sha256) { throw "Release hash mismatch: $relative" }
    }
    return $manifest
}

Export-ModuleMember -Function Get-ReleaseFiles, Test-ReleaseManifest

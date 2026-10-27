#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReleaseDirectory,
    [Parameter(Mandatory)][string]$ManifestPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReleaseManifest.psm1') -Force
$manifest = Test-ReleaseManifest -ReleaseDirectory $ReleaseDirectory -ManifestPath $ManifestPath
Write-Output "Verified $(@($manifest.Files).Count) files for source commit $($manifest.SourceCommit)."

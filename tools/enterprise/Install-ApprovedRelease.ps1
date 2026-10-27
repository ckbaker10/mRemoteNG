#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReleaseDirectory,
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][string]$Destination
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'ReleaseManifest.psm1') -Force
Test-ReleaseManifest -ReleaseDirectory $ReleaseDirectory -ManifestPath $ManifestPath | Out-Null
$target = [IO.Path]::GetFullPath($Destination)
$programFiles = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\')
if (-not $target.StartsWith($programFiles + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Install into a dedicated directory below Program Files.'
}
if (Test-Path -LiteralPath $target) { throw 'Destination already exists. Install a new version into a new directory.' }
$ancestor = [IO.Path]::GetDirectoryName($target)
while ($ancestor) {
    if (Test-Path -LiteralPath $ancestor) {
        if ((Get-Item -LiteralPath $ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Installation ancestors must not be reparse points.'
        }
    }
    $ancestor = [IO.Path]::GetDirectoryName($ancestor)
}
[IO.Directory]::CreateDirectory($target) | Out-Null
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$propagation = [Security.AccessControl.PropagationFlags]::None
$allow = [Security.AccessControl.AccessControlType]::Allow
$acl.SetOwner($administrators)
foreach ($identity in $administrators, $system) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', $inherit, $propagation, $allow))
}
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($users, 'ReadAndExecute', $inherit, $propagation, $allow))
Set-Acl -LiteralPath $target -AclObject $acl
foreach ($file in @(Get-ReleaseFiles -ReleaseDirectory $ReleaseDirectory)) {
    $destinationFile = Join-Path $target $file.RelativePath
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destinationFile)) | Out-Null
    [IO.File]::Copy($file.FullPath, $destinationFile, $false)
}
Test-ReleaseManifest -ReleaseDirectory $target -ManifestPath $ManifestPath | Out-Null
Write-Output $target

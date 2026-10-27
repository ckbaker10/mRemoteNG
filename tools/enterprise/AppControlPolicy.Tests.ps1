#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'AppControlPolicy.psm1') -Force
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mrng-policy-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporary) | Out-Null
$path = Join-Path $temporary 'synthetic.xml'
$identifier = '{11111111-2222-3333-4444-555555555555}'
$valid = @"
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy">
  <PolicyID>$identifier</PolicyID><BasePolicyID>$identifier</BasePolicyID>
  <Rules>
    <Rule><Option>Enabled:UMCI</Option></Rule>
    <Rule><Option>Enabled:Allow Supplemental Policies</Option></Rule>
    <Rule><Option>Enabled:Dynamic Code Security</Option></Rule>
  </Rules>
  <FileRules><Allow ID="ID_SYNTHETIC" Hash="$('A' * 64)" /></FileRules>
</SiPolicy>
"@
function Set-Fixture([string]$Content) {
    [IO.File]::WriteAllText($path, $Content)
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
function Assert-Rejected([scriptblock]$Operation) {
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Expected rejection of the unsafe policy.' }
}
try {
    $hash = Set-Fixture $valid
    $result = Read-ApprovedBasePolicy -Path $path -ApprovedSha256 $hash
    if ($result.PolicyId -ne $identifier) { throw 'Base policy identifier changed.' }
    Assert-HashOnlySupplement -Path $path
    Assert-Rejected { Read-ApprovedBasePolicy -Path $path -ApprovedSha256 ('0' * 64) }
    $hash = Set-Fixture ($valid.Replace('Enabled:UMCI', 'Enabled:Audit Mode'))
    Assert-Rejected { Read-ApprovedBasePolicy -Path $path -ApprovedSha256 $hash }
    $hash = Set-Fixture ($valid.Replace('Hash="' + ('A' * 64) + '"', 'FilePath="C:\*"'))
    Assert-Rejected { Read-ApprovedBasePolicy -Path $path -ApprovedSha256 $hash }
    Assert-Rejected { Assert-HashOnlySupplement -Path $path }
    $hash = Set-Fixture ($valid.Replace('Enabled:Dynamic Code Security', 'Enabled:Managed Installer'))
    Assert-Rejected { Read-ApprovedBasePolicy -Path $path -ApprovedSha256 $hash }
    $hash = Set-Fixture ('<!DOCTYPE SiPolicy [<!ENTITY test SYSTEM "file:///not-a-real-input">]>' + $valid)
    Assert-Rejected { Read-ApprovedBasePolicy -Path $path -ApprovedSha256 $hash }
    Write-Output 'PASS: approved policy, hash mismatch, missing hardening, broad trust and DTD rejection.'
} finally {
    [IO.Directory]::Delete($temporary, $true)
}

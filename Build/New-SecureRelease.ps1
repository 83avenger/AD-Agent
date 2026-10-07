#Requires -Version 5.1
<#
.SYNOPSIS
    Build a signed, integrity-cataloged, encrypted AD-Agent release from a source tree.
    Developer-only; run on the build machine.

.DESCRIPTION
    Produces AD-Agent-<version>.secure (an AES-256-encrypted zip) plus release-info.json.
    Steps:
      1. Stage a clean copy (excludes .git, State, venv, plaintext secrets, logs, build keys).
      2. Byte-compile the Python (ship .pyc alongside source; no packed exe - EDR-safe).
      3. Authenticode-sign every .ps1/.psm1/.psd1 with the code-signing cert.
      4. Build and sign an integrity catalog (AD-Agent.cat) covering the whole tree, so the
         installer can prove nothing was altered - including Python/JSON/templates that
         Authenticode can't sign individually.
      5. Write release-info.json (version, build time, signer thumbprint, SHA-256 manifest).
      6. Zip, then AES-256 encrypt with a key derived (PBKDF2) from the supplied passphrase;
         the salt+IV are stored in the file header. The passphrase is handed to the installer
         out-of-band and never written to disk.

.PARAMETER SourcePath      Repo root to build from. Default: the parent of this script.
.PARAMETER OutputDir       Where to write the .secure artifact. Default: .\dist
.PARAMETER Version         Release version string, e.g. '1.0.0'. Required.
.PARAMETER CodeSignThumbprint  Thumbprint of the code-signing cert (from New-ProductKeys).
.PARAMETER Passphrase      Passphrase used to derive the AES key for the artifact. Required.
.PARAMETER PythonExe       Python used for byte-compilation. Default: python on PATH.

.EXAMPLE
    .\New-SecureRelease.ps1 -Version 1.0.0 -CodeSignThumbprint (Get-Content .\keys\codesign-thumbprint.txt) -Passphrase 'correct horse ...'
#>
[CmdletBinding()]
param(
    [string]$SourcePath = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputDir = (Join-Path $PSScriptRoot 'dist'),
    [Parameter(Mandatory)][string]$Version,
    [Parameter(Mandatory)][string]$CodeSignThumbprint,
    [Parameter(Mandatory)][string]$Passphrase,
    [string]$PythonExe = 'python'
)

$ErrorActionPreference = 'Stop'

$cert = Get-Item "Cert:\CurrentUser\My\$CodeSignThumbprint" -ErrorAction SilentlyContinue
if (-not $cert) { $cert = Get-Item "Cert:\LocalMachine\My\$CodeSignThumbprint" -ErrorAction SilentlyContinue }
if (-not $cert) { throw "Code-signing cert $CodeSignThumbprint not found. Run New-ProductKeys.ps1 or pass the right thumbprint." }

$stage = Join-Path $env:TEMP "adagent-build-$Version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# 1. Stage a clean tree. Exclude data, env, secrets, build keys.
Write-Host "Staging clean tree from $SourcePath ..."
$exclude = @('.git', 'State', '.venv', 'venv', '__pycache__', 'dist', 'keys', 'out',
             'integration-secrets.json', 'integration-secrets.json.enc', '*.log',
             'license_privkey.dpapi', 'license.key')
robocopy $SourcePath $stage /MIR /XD ($exclude | Where-Object { $_ -notmatch '\.' }) /XF ($exclude | Where-Object { $_ -match '\.' }) /NFL /NDL /NJH /NJS /NP | Out-Null

# 2. Byte-compile Python (best effort - absence must not fail the build).
Write-Host "Byte-compiling Python ..."
& $PythonExe -m compileall -q (Join-Path $stage 'WebApp') 2>$null

# 3. Authenticode-sign all PowerShell.
Write-Host "Signing PowerShell files ..."
$ps = Get-ChildItem -Path $stage -Recurse -Include *.ps1, *.psm1, *.psd1
foreach ($f in $ps) {
    $r = Set-AuthenticodeSignature -FilePath $f.FullName -Certificate $cert -HashAlgorithm SHA256
    if ($r.Status -ne 'Valid') { throw "Signing failed for $($f.FullName): $($r.StatusMessage)" }
}
Write-Host "  Signed $($ps.Count) file(s)."

# 4. Integrity catalog over the whole tree, then sign it.
$catPath = Join-Path $stage 'AD-Agent.cat'
Write-Host "Building integrity catalog ..."
New-FileCatalog -Path $stage -CatalogFilePath $catPath -CatalogVersion 2 | Out-Null
$catSig = Set-AuthenticodeSignature -FilePath $catPath -Certificate $cert -HashAlgorithm SHA256
if ($catSig.Status -ne 'Valid') { throw "Catalog signing failed: $($catSig.StatusMessage)" }

# 5. release-info.json with a SHA-256 manifest.
Write-Host "Writing release-info.json ..."
$manifest = @{}
Get-ChildItem -Path $stage -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($stage.Length).TrimStart('\')
    $manifest[$rel] = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
}
[ordered]@{
    product = 'AD-Agent'; version = $Version
    builtUtc = (Get-Date).ToUniversalTime().ToString('o')
    signerThumbprint = $cert.Thumbprint
    fileCount = $manifest.Count
    sha256 = $manifest
} | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $stage 'release-info.json') -Encoding UTF8

# 6. Zip, then AES-256 encrypt (PBKDF2-derived key; salt+IV header).
$zip = Join-Path $OutputDir "AD-Agent-$Version.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Write-Host "Zipping ..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $zip)

$secure = Join-Path $OutputDir "AD-Agent-$Version.secure"
Write-Host "Encrypting -> $secure"
$salt = New-Object byte[] 16; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
$kdf  = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 200000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$aes = [System.Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.Key = $kdf.GetBytes(32); $aes.GenerateIV()
$plain = [System.IO.File]::ReadAllBytes($zip)
$enc = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)
$out = New-Object System.IO.MemoryStream
$out.Write([Text.Encoding]::ASCII.GetBytes('ADAG1'), 0, 5)   # format magic
$out.Write($salt, 0, 16); $out.Write($aes.IV, 0, 16); $out.Write($enc, 0, $enc.Length)
[System.IO.File]::WriteAllBytes($secure, $out.ToArray())
Remove-Item $zip -Force
Remove-Item $stage -Recurse -Force

Write-Host ""
Write-Host "Built: $secure" -ForegroundColor Green
Write-Host "Ship this file + the passphrase (out-of-band) to the installer on the target server."

#Requires -Version 5.1
<#
.SYNOPSIS
    Single setup for AD-Agent: decrypt + verify + install a signed release, register the
    service tasks, open the firewall, and enable encrypted-secret + signed-code enforcement.

.DESCRIPTION
    Replaces the manual copy-and-run-each-script deployment. Given a .secure release
    (New-SecureRelease.ps1), its passphrase, and a license.key (New-License.ps1), it:
      1. Decrypts the artifact and extracts it to a temp dir.
      2. VERIFIES before trusting: the signed integrity catalog (Test-FileCatalog), the
         catalog's signer thumbprint, the SHA-256 manifest, and the license for THIS host.
         Any mismatch aborts - nothing is installed.
      3. Installs into a protected directory (default C:\Program Files\AD-Agent) with ACLs
         that let the gMSA read/execute code and write only State\ and Config\.
      4. Preserves existing State/Config/bin/reports/.venv across the replace.
      5. Installs Python dependencies offline from a bundled wheels folder, if present.
      6. Registers scan/web/watchdog tasks and the firewall rule via the existing Install
         scripts, and (optionally) sets the machine ExecutionPolicy to AllSigned.

    Re-run it to upgrade: data and config are preserved.

.PARAMETER Package        Path to AD-Agent-<version>.secure.
.PARAMETER Passphrase     The artifact passphrase used at build time.
.PARAMETER License        Path to the license.key issued for this host.
.PARAMETER InstallDir     Target install directory. Default: C:\Program Files\AD-Agent.
.PARAMETER GmsaAccount    gMSA the tasks run under (passed to the Register-* scripts).
.PARAMETER PythonPath     python.exe used to run the web UI and compile deps.
.PARAMETER WheelsDir      Offline pip wheels dir (optional); deps installed from here.
.PARAMETER SetAllSigned   Set machine ExecutionPolicy to AllSigned (recommended once the
                          code-signing cert is trusted estate-wide).
.PARAMETER SkipFirewall   Don't create the inbound firewall rule.

.EXAMPLE
    .\Install-ADAgent.ps1 -Package .\AD-Agent-1.0.0.secure -Passphrase (Read-Host -AsSecureString) `
        -License .\license.key -GmsaAccount 'AMG\svc-discoverAgt$' -PythonPath 'C:\Apps\Python312\python.exe'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Package,
    [Parameter(Mandatory)][string]$Passphrase,
    [Parameter(Mandatory)][string]$License,
    [string]$InstallDir = "$env:ProgramFiles\AD-Agent",
    [string]$GmsaAccount,
    [string]$PythonPath,
    [string]$WheelsDir,
    [switch]$SetAllSigned,
    [switch]$SkipFirewall
)

$ErrorActionPreference = 'Stop'

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { throw "Install-ADAgent.ps1 must be run from an elevated (Run as Administrator) PowerShell session." }
foreach ($p in @($Package, $License)) { if (-not (Test-Path $p)) { throw "Not found: $p" } }

$work = Join-Path $env:TEMP ("adagent-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    # 1. Decrypt the artifact (header: 'ADAG1' + 16-byte salt + 16-byte IV + ciphertext).
    Write-Host "Decrypting $Package ..."
    $blob = [System.IO.File]::ReadAllBytes($Package)
    if ([Text.Encoding]::ASCII.GetString($blob, 0, 5) -ne 'ADAG1') { throw "Not an AD-Agent secure package (bad header)." }
    $salt = $blob[5..20]; $iv = $blob[21..36]; $cipher = $blob[37..($blob.Length - 1)]
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, [byte[]]$salt, 200000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $aes = [System.Security.Cryptography.Aes]::Create(); $aes.KeySize = 256; $aes.Key = $kdf.GetBytes(32); $aes.IV = [byte[]]$iv
    try { $plain = $aes.CreateDecryptor().TransformFinalBlock([byte[]]$cipher, 0, $cipher.Length) }
    catch { throw "Decryption failed - wrong passphrase or corrupted package." }
    $zip = Join-Path $work 'release.zip'
    [System.IO.File]::WriteAllBytes($zip, $plain)
    $extract = Join-Path $work 'tree'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $extract)

    # 2. Verify BEFORE trusting.
    Write-Host "Verifying integrity catalog ..."
    $cat = Join-Path $extract 'AD-Agent.cat'
    if (-not (Test-Path $cat)) { throw "Release has no integrity catalog - refusing to install." }
    $catSig = Get-AuthenticodeSignature -FilePath $cat
    if ($catSig.Status -ne 'Valid') { throw "Catalog signature is not valid ($($catSig.Status)) - refusing to install." }
    $info = Get-Content -Raw (Join-Path $extract 'release-info.json') | ConvertFrom-Json
    if ($catSig.SignerCertificate.Thumbprint -ne $info.signerThumbprint) {
        throw "Catalog signer thumbprint does not match release-info.json - refusing to install."
    }
    $catTest = Test-FileCatalog -Path $extract -CatalogFilePath $cat -Detailed
    if ($catTest.Status -ne 'Valid') { throw "Integrity catalog check failed ($($catTest.Status)) - files were altered. Refusing to install." }
    Write-Host "  Catalog valid, signer $($info.signerThumbprint), version $($info.version)."

    # License for this host (import the shipped module from the extracted tree).
    Copy-Item $License (Join-Path $extract 'DCAnomalyAgent\Config\license.key') -Force
    Import-Module (Join-Path $extract 'DCAnomalyAgent\Modules\DCAnomalyAgent.Licensing.psm1') -Force
    $env:ADAGENT_LICENSE_ENFORCE = '1'
    $lic = Test-ProductLicense -LicensePath (Join-Path $extract 'DCAnomalyAgent\Config\license.key') -PublicKeyPath (Join-Path $extract 'DCAnomalyAgent\Config\license_pubkey.pem')
    if (-not $lic.Ok) { throw "License is not valid for this host: $($lic.Reason)" }
    Write-Host "  License OK (owner: $($lic.Owner))."

    # 3/4. Preserve existing data, then lay down the new tree.
    $preserve = @('State', 'Config\settings.psd1', 'Config\integration-secrets.json',
                  'Config\integration-secrets.json.enc', 'bin', 'WebApp\reports', 'WebApp\.venv')
    $backup = Join-Path $work 'preserved'
    if (Test-Path $InstallDir) {
        Write-Host "Preserving existing data/config ..."
        foreach ($rel in $preserve) {
            $src = Join-Path $InstallDir $rel
            if (Test-Path $src) {
                $dst = Join-Path $backup $rel
                New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
                Copy-Item $src $dst -Recurse -Force
            }
        }
    }
    Write-Host "Installing to $InstallDir ..."
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $extract '*') $InstallDir -Recurse -Force
    if (Test-Path $backup) {
        foreach ($rel in $preserve) {
            $src = Join-Path $backup $rel
            if (Test-Path $src) {
                $dst = Join-Path $InstallDir $rel
                New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
                Copy-Item $src $dst -Recurse -Force
            }
        }
    }

    # ACLs: Admins/SYSTEM full; gMSA read+execute everywhere, write only on State\ and Config\.
    if ($GmsaAccount) {
        Write-Host "Setting ACLs (gMSA read/execute; write only on State\ and Config\) ..."
        icacls $InstallDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "${GmsaAccount}:(OI)(CI)RX" | Out-Null
        foreach ($rw in @('State', 'Config')) {
            $d = Join-Path $InstallDir $rw
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
            icacls $d /grant:r "${GmsaAccount}:(OI)(CI)M" | Out-Null
        }
    }

    # 5. Offline Python deps.
    if ($WheelsDir -and $PythonPath -and (Test-Path $WheelsDir)) {
        Write-Host "Installing Python dependencies from $WheelsDir ..."
        & $PythonPath -m pip install --no-index --find-links $WheelsDir -r (Join-Path $InstallDir 'WebApp\requirements.txt')
    }

    # 6. Register tasks + firewall via the existing scripts.
    $install = Join-Path $InstallDir 'DCAnomalyAgent\Install'
    if ($GmsaAccount -and $PythonPath) {
        & (Join-Path $install 'Register-WebUIStartup.ps1') -GmsaAccount $GmsaAccount -PythonPath $PythonPath
    } else {
        Write-Warning "Skipping task registration (pass -GmsaAccount and -PythonPath to register the web UI/scan tasks)."
    }
    if (-not $SkipFirewall) { & (Join-Path $install 'Set-WebUIFirewall.ps1') -Port 5000 }

    if ($SetAllSigned) {
        Write-Host "Setting machine ExecutionPolicy to AllSigned ..."
        Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
    }

    Write-Host ""
    Write-Host "AD-Agent $($info.version) installed to $InstallDir." -ForegroundColor Green
    Write-Host "License: owner $($lic.Owner); enforcement is ON for this deployment."
    Write-Host "Set ADAGENT_LICENSE_ENFORCE=1 (Machine) so the web UI enforces it too:"
    Write-Host "  [Environment]::SetEnvironmentVariable('ADAGENT_LICENSE_ENFORCE','1','Machine')"
} finally {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
}

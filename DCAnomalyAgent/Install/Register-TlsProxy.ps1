#Requires -Version 5.1
<#
.SYNOPSIS
    Registers the AD-Agent TLS proxy (WebApp\tls_proxy.py) as a Scheduled Task that runs at
    startup under the gMSA, terminating HTTPS for the web UI without IIS. Also opens the
    inbound firewall port.

.DESCRIPTION
    On a locked-down server where IIS + ARR + URL Rewrite won't install, this is the
    no-extra-software way to put the page on HTTPS with your CA certificate: a small
    stdlib Python TLS proxy (tls_proxy.py) listens on 443 and forwards to the Flask app on
    127.0.0.1:5000. It runs under the same gMSA as the web UI task, survives reboots, and
    restarts if it dies - same pattern as Register-WebUIStartup.ps1.

    It does NOT add authentication (IIS would have added Windows Auth). It adds TLS only;
    keep the plain app port (5000) restricted at the network firewall and add auth later if
    required. See docs/TLS-SETUP.md.

.PARAMETER GmsaAccount
    gMSA to run under - the same one the web UI task uses.
.PARAMETER PythonPath
    python.exe that runs tls_proxy.py.
.PARAMETER Pfx
    Path to a PFX exported from the LocalMachine store (needs the 'cryptography' package on
    the server). Mutually usable with -Cert/-Key instead.
.PARAMETER PfxPassword
    PFX password as a SecureString. Prompted if -Pfx is given without it.
.PARAMETER CertPem / -KeyPem
    PEM certificate + key files (stdlib only, no package needed). Use instead of -Pfx.
.PARAMETER ListenPort
    HTTPS port to listen on (default 443).
.PARAMETER BackendPort
    The Flask app's plain port (default 5000). Must match Register-WebUIStartup.ps1 -Port.
.PARAMETER TaskName
    Scheduled Task name.

.EXAMPLE
    # Export the CA cert to a PFX first:
    Export-PfxCertificate -Cert Cert:\LocalMachine\My\<thumb> -FilePath C:\Apps\AD-Agent\webui.pfx -Password (Read-Host -AsSecureString)
    .\Register-TlsProxy.ps1 -GmsaAccount 'AMG\svc-discoverAgt$' -PythonPath 'C:\Apps\Python312\python.exe' -Pfx 'C:\Apps\AD-Agent\webui.pfx'
#>
[CmdletBinding(DefaultParameterSetName = 'Pfx')]
param(
    [string]$GmsaAccount = 'CONTOSO\svc-discoverAgt$',
    [Parameter(Mandatory)][string]$PythonPath,
    [Parameter(ParameterSetName = 'Pfx', Mandatory)][string]$Pfx,
    [Parameter(ParameterSetName = 'Pfx')][System.Security.SecureString]$PfxPassword,
    [Parameter(ParameterSetName = 'Pem', Mandatory)][string]$CertPem,
    [Parameter(ParameterSetName = 'Pem', Mandatory)][string]$KeyPem,
    [int]$ListenPort = 443,
    [int]$BackendPort = 5000,
    [string]$TaskName = 'AD-Agent-TlsProxy'
)

$ErrorActionPreference = 'Stop'
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { throw "Run elevated - this registers a Scheduled Task and a firewall rule." }
if (-not (Test-Path $PythonPath)) { throw "PythonPath '$PythonPath' does not exist." }

# Join-Path (not Resolve-Path) so a missing file gives a clear message instead of the
# cryptic Resolve-Path "cannot find path" error - the usual cause is the server not having
# pulled the latest code yet.
$proxyScript = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'WebApp\tls_proxy.py'
if (-not (Test-Path $proxyScript)) {
    throw "tls_proxy.py not found at $proxyScript. This file ships in WebApp\ - update the server to the latest code first (git pull + Update-Deployment.ps1, or copy WebApp\tls_proxy.py into place), then re-run."
}
$webAppDir = Split-Path -Parent $proxyScript

# Build the argument list for the selected cert source.
$certArgs = ''
if ($PSCmdlet.ParameterSetName -eq 'Pfx') {
    if (-not (Test-Path $Pfx)) { throw "PFX '$Pfx' not found." }
    if (-not $PfxPassword) { $PfxPassword = Read-Host -AsSecureString -Prompt "PFX password" }
    # The task runs non-interactively, so the password has to be passed to the process. A
    # Scheduled Task's arguments are readable by admins/SYSTEM only (not SYSVOL), so this is
    # an acceptable exposure for an internal cert; use -CertPem/-KeyPem with an ACL'd key file
    # if you'd rather not have it in the task definition at all.
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
    $certArgs = "--pfx `"$Pfx`" --pfx-pass `"$plain`""
} else {
    foreach ($f in @($CertPem, $KeyPem)) { if (-not (Test-Path $f)) { throw "File not found: $f" } }
    $certArgs = "--cert `"$CertPem`" --key `"$KeyPem`""
}

$argument = "`"$proxyScript`" --listen-port $ListenPort --backend-port $BackendPort $certArgs"
$action = New-ScheduledTaskAction -Execute $PythonPath -Argument $argument -WorkingDirectory $webAppDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Write-Host "Task '$TaskName' exists - re-registering."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Terminates HTTPS for the AD-Agent web UI (tls_proxy.py) and forwards to the Flask app on 127.0.0.1:$BackendPort." | Out-Null

# Open the HTTPS port (reuse the firewall helper if present).
$fw = Join-Path $PSScriptRoot 'Set-WebUIFirewall.ps1'
if (Test-Path $fw) {
    try { & $fw -Port $ListenPort } catch { Write-Warning "Could not open TCP $ListenPort automatically: $_" }
} else {
    Write-Warning "Set-WebUIFirewall.ps1 not found - open inbound TCP $ListenPort manually."
}

Write-Host "`nTask '$TaskName' registered. Start it now:" -ForegroundColor Green
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "Then browse https://$($env:COMPUTERNAME):$ListenPort (or the FQDN on the cert)."
Write-Host ""
Write-Host "This adds TLS only, not authentication. Keep the plain app port ($BackendPort) restricted"
Write-Host "to endpoint VLANs at the network firewall. See docs/TLS-SETUP.md."

#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fronts the AD-Agent web UI with IIS doing TLS termination + Windows
    Authentication, closing the "no built-in auth, plain HTTP" gap called out
    in the security review (see ENTERPRISE-HARDENING-RUNBOOK.md).

.DESCRIPTION
    Today, anyone who can reach TCP 5000 can trigger scans/discovery, delete
    assets, and view every collected result (software inventories, compliance
    gaps, warranty data) - the Flask app itself has no login. This script
    doesn't change a line of the Flask app; it puts IIS in front of it as a
    reverse proxy so the browser talks to IIS over HTTPS with Windows
    Authentication enforced, and IIS forwards the request to the Flask app on
    localhost only. Combined with rebinding the web UI to 127.0.0.1 (see the
    -LockWebUIToLocalhost switch below), port 5000 stops being reachable from
    the network at all - only IIS is, and only to authenticated, authorized
    users.

    What this configures:
      1. IIS + Application Request Routing (ARR) + URL Rewrite (installed if
         missing).
      2. An IIS site bound to HTTPS on -Port (self-signed cert by default -
         see -CertThumbprint to use a real one from your CA).
      3. Windows Authentication enabled, Anonymous Authentication disabled.
      4. If -AllowedGroup is supplied, an authorization rule restricting
         access to that AD group only (e.g. 'AMG\AD-Agent-Analysts') -
         otherwise any authenticated domain user can reach it, same as today
         just no longer anonymous.
      5. A URL Rewrite reverse-proxy rule forwarding to
         http://127.0.0.1:<WebUIPort>, with the authenticated Windows
         username forwarded as an X-Remote-User header so app.py can log who
         did what (see Register-WebUIStartup's audit logging note).

.PARAMETER SiteName
    IIS site name to create.
.PARAMETER Port
    HTTPS port IIS listens on (what analysts actually browse to).
.PARAMETER WebUIPort
    Port the Flask/waitress process listens on internally. Must match
    Register-WebUIStartup.ps1's -Port.
.PARAMETER CertThumbprint
    Thumbprint of an existing certificate in the local machine store to bind.
    If omitted, a self-signed certificate is generated - fine for internal
    testing, but browsers will warn; get a real cert from your internal CA
    for production use.
.PARAMETER AllowedGroup
    AD group (DOMAIN\GroupName) to restrict access to. Strongly recommended -
    without it, every authenticated domain user can reach the tool.
.PARAMETER LockWebUIToLocalhost
    Also re-registers the AD-Agent-WebUI Scheduled Task with -BindHost
    127.0.0.1, so the Flask app is no longer reachable except through this
    IIS proxy. Requires Register-WebUIStartup.ps1 to already be registered
    (uses the same -GmsaAccount/-PythonPath it was set up with).

.EXAMPLE
    .\Register-IISReverseProxy.ps1 -AllowedGroup 'AMG\AD-Agent-Analysts' -LockWebUIToLocalhost

.NOTES
    Test in a lab/staging environment before running against Jump-Jeremy -
    this changes how the tool is reached (HTTPS + Windows Auth instead of
    plain HTTP) and IIS/ARR/URL Rewrite aren't installed by default. Confirm
    IIS itself isn't disallowed by your change-control process on an
    EDR-protected server before running.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$SiteName = 'AD-Agent',
    [int]$Port = 443,
    [int]$WebUIPort = 5000,
    [string]$CertThumbprint,
    [string]$AllowedGroup,
    [switch]$LockWebUIToLocalhost,
    [string]$GmsaAccount = 'CONTOSO\svc-discoverAgt$',
    [string]$PythonPath
)

Write-Host "== Step 1: IIS + ARR + URL Rewrite =="
$iisFeature = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
if (-not $iisFeature -or -not $iisFeature.Installed) {
    Install-WindowsFeature -Name Web-Server, Web-Windows-Auth -IncludeManagementTools
} elseif (-not (Get-WindowsFeature -Name Web-Windows-Auth).Installed) {
    Install-WindowsFeature -Name Web-Windows-Auth
}

$arrInstalled = Test-Path 'C:\Program Files\IIS\Application Request Routing'
$rewriteInstalled = Test-Path 'C:\Windows\System32\inetsrv\rewrite.dll'
if (-not $arrInstalled -or -not $rewriteInstalled) {
    throw @"
Application Request Routing and/or URL Rewrite aren't installed. Both are
Microsoft downloads, not Windows Features, so they can't be installed purely
via PowerShell cmdlets on an air-gapped/EDR-locked server without pre-staging
the MSIs:
  - URL Rewrite:  https://www.iis.net/downloads/microsoft/url-rewrite
  - ARR 3.0:      https://www.iis.net/downloads/microsoft/application-request-routing
Download both on a machine with internet access, copy the MSIs to this
server, install them (they don't require a reboot), then re-run this script.
"@
}

Import-Module WebAdministration -ErrorAction Stop

Write-Host "== Step 2: Certificate =="
if ($CertThumbprint) {
    $cert = Get-ChildItem "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { throw "Certificate with thumbprint $CertThumbprint not found in Cert:\LocalMachine\My." }
} else {
    Write-Warning "No -CertThumbprint supplied - generating a self-signed certificate. Browsers will show a warning until you replace this with a certificate from your internal CA."
    $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME, "$env:COMPUTERNAME.$env:USERDNSDOMAIN" `
        -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'AD-Agent reverse proxy'
}

Write-Host "== Step 3: IIS site =="
if (Test-Path "IIS:\Sites\$SiteName") {
    Write-Host "Site '$SiteName' already exists - removing before re-creating."
    Remove-Website -Name $SiteName
}
$sitePath = "C:\inetpub\$SiteName"
New-Item -ItemType Directory -Path $sitePath -Force | Out-Null
# web.config below is what actually does the reverse-proxying + user forwarding -
# the site just needs *a* physical path to satisfy IIS, it never serves files from it.
New-Website -Name $SiteName -Port $Port -PhysicalPath $sitePath -Ssl | Out-Null
New-WebBinding -Name $SiteName -Protocol https -Port $Port -SslFlags 0
(Get-WebBinding -Name $SiteName -Protocol https).AddSslCertificate($cert.Thumbprint, 'my')

Write-Host "== Step 4: Windows Authentication, anonymous disabled =="
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' `
    -Name Enabled -Value $false -PSPath "IIS:\Sites\$SiteName"
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' `
    -Name Enabled -Value $true -PSPath "IIS:\Sites\$SiteName"

if ($AllowedGroup) {
    Write-Host "== Step 5: Restricting access to '$AllowedGroup' =="
    Clear-WebConfiguration -Filter '/system.webServer/security/authorization' -PSPath "IIS:\Sites\$SiteName"
    Add-WebConfiguration -Filter '/system.webServer/security/authorization' -PSPath "IIS:\Sites\$SiteName" -Value @{
        accessType = 'Allow'; roles = $AllowedGroup
    }
} else {
    Write-Warning "No -AllowedGroup supplied - every authenticated domain user will be able to reach the tool (no longer anonymous, but not restricted to analysts either). Re-run with -AllowedGroup 'DOMAIN\GroupName' to fix this."
}

Write-Host "== Step 6: Reverse proxy rule (web.config) =="
$webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="AD-Agent reverse proxy" stopProcessing="true">
          <match url="(.*)" />
          <serverVariables>
            <set name="HTTP_X_REMOTE_USER" value="{LOGON_USER}" />
          </serverVariables>
          <action type="Rewrite" url="http://127.0.0.1:$WebUIPort/{R:1}" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@
Set-Content -Path (Join-Path $sitePath 'web.config') -Value $webConfig -Encoding UTF8

# Server variable set above must be allowlisted before URL Rewrite will forward it.
$allowedVarsPath = 'IIS:\'
if (-not (Get-WebConfiguration -Filter "/system.webServer/rewrite/allowedServerVariables/add[@name='HTTP_X_REMOTE_USER']" -PSPath $allowedVarsPath -ErrorAction SilentlyContinue)) {
    Add-WebConfiguration -Filter '/system.webServer/rewrite/allowedServerVariables' -PSPath $allowedVarsPath -Value @{ name = 'HTTP_X_REMOTE_USER' }
}

if ($LockWebUIToLocalhost) {
    Write-Host "== Step 7: Re-registering AD-Agent-WebUI bound to 127.0.0.1 =="
    if (-not $PythonPath) {
        throw "-LockWebUIToLocalhost requires -PythonPath (the same python.exe path used when Register-WebUIStartup.ps1 was first run)."
    }
    $registerScript = Join-Path $PSScriptRoot 'Register-WebUIStartup.ps1'
    & $registerScript -GmsaAccount $GmsaAccount -PythonPath $PythonPath -BindHost '127.0.0.1' -Port $WebUIPort
    Write-Host "Restart the task now so the new binding takes effect: Restart-ScheduledTask isn't a cmdlet, so:"
    Write-Host "  Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'"
}

Write-Host "`nDone. Site '$SiteName' is listening on https://$($env:COMPUTERNAME):$Port and proxying to http://127.0.0.1:$WebUIPort."
Write-Host "Point analysts at TCP/$Port on this proxy instead of TCP/$WebUIPort directly - firewall-request-ports.csv row 22 already covers this; once confirmed working, ask your network team to remove row 20 (direct TCP/$WebUIPort access)."
if (-not $CertThumbprint) {
    Write-Host "`nReminder: replace the self-signed certificate with one from your internal CA before rolling this out beyond a test." -ForegroundColor Yellow
}

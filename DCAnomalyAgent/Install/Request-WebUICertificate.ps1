#Requires -Version 5.1
<#
.SYNOPSIS
    Requests a web-server certificate for the AD-Agent jump host from the enterprise AD CS CA
    and prints its thumbprint, ready to hand to Register-IISReverseProxy.ps1 -CertThumbprint.

.DESCRIPTION
    Securing the browser-facing page means IIS binds a real certificate (not the self-signed
    default). This gets one from your internal CA for this host, so analysts browsing
    https://<jump> see no warning.

    It does NOT change how devices register - collector check-ins stay on plain http://<jump>:5000
    until you choose to move them. See docs/TLS-SETUP.md.

    Two paths:
      * Auto-enrollment (preferred): Get-Certificate against the CA using a published template.
      * Fallback: if auto-enrollment isn't available, it writes a ready-to-use certreq .inf and
        prints the certreq commands to request + install the cert manually.

.PARAMETER DnsName
    Names to put on the certificate. Defaults to this host's FQDN plus its short name (SAN), so
    the cert is valid whether analysts browse by short name or FQDN.
.PARAMETER Template
    AD CS certificate template to enrol against. 'WebServer' is the built-in default; your CA
    may publish a differently-named one (e.g. 'AMG Web Server') - pass it here.
.PARAMETER FriendlyName
    Friendly name stamped on the cert in the store.
.PARAMETER InfOnly
    Skip auto-enrollment and just emit the certreq .inf + instructions.

.EXAMPLE
    .\Request-WebUICertificate.ps1
    Enrol a web-server cert for this host from the CA and print its thumbprint.

.EXAMPLE
    .\Request-WebUICertificate.ps1 -Template 'AMG Web Server'
    Use a specifically-named template your CA publishes.
#>
[CmdletBinding()]
param(
    [string[]]$DnsName,
    [string]$Template = 'WebServer',
    [string]$FriendlyName = 'AD-Agent Web UI',
    [switch]$InfOnly
)

$ErrorActionPreference = 'Stop'

# Default names: FQDN first (that's the Subject/primary), short name as an additional SAN.
if (-not $DnsName) {
    $fqdn = "$env:COMPUTERNAME.$env:USERDNSDOMAIN".TrimEnd('.')
    if (-not $env:USERDNSDOMAIN) { $fqdn = $env:COMPUTERNAME }
    $DnsName = @($fqdn)
    if ($env:COMPUTERNAME -and ($DnsName -notcontains $env:COMPUTERNAME)) { $DnsName += $env:COMPUTERNAME }
}
$primary = $DnsName[0]

function Show-Next {
    param([string]$Thumbprint)
    Write-Host ""
    Write-Host "Certificate thumbprint: $Thumbprint" -ForegroundColor Green
    Write-Host "Bind it to the IIS reverse proxy (secures the page over HTTPS with your CA):"
    Write-Host "  .\Register-IISReverseProxy.ps1 -CertThumbprint $Thumbprint -AllowedGroup 'DOMAIN\AD-Agent-Analysts'"
    Write-Host ""
    Write-Host "Do NOT pass -LockWebUIToLocalhost yet - leaving it off keeps TCP 5000 open so devices"
    Write-Host "can keep registering over plain http://$primary`:5000 for now. See docs/TLS-SETUP.md."
}

if (-not $InfOnly) {
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) { throw "Run elevated - the certificate is placed in the LocalMachine store." }
    try {
        Write-Host "Requesting a '$Template' certificate for: $($DnsName -join ', ') ..."
        $result = Get-Certificate -Template $Template -DnsName $DnsName -CertStoreLocation 'Cert:\LocalMachine\My' -ErrorAction Stop
        if ($result.Status -eq 'Issued' -and $result.Certificate) {
            $cert = $result.Certificate
            if ($FriendlyName) { $cert.FriendlyName = $FriendlyName }
            Show-Next -Thumbprint $cert.Thumbprint
            return
        }
        if ($result.Status -eq 'Pending') {
            Write-Warning "The request is PENDING CA approval. Once a CA manager issues it, retrieve it with: certreq -retrieve <RequestId>; then bind the resulting thumbprint."
            return
        }
        Write-Warning "Enrollment returned status '$($result.Status)'. Falling back to a manual certreq request below."
    } catch {
        Write-Warning "Auto-enrollment failed ($($_.Exception.Message)). Falling back to a manual certreq request below."
    }
}

# --- Fallback: emit a certreq .inf + the commands to request/install manually ----------------
$sanLines = ($DnsName | ForEach-Object { "_continue_ = `"dns=$_&`"" }) -join "`r`n"
$inf = @"
[Version]
Signature = "`$Windows NT`$"

[NewRequest]
Subject = "CN=$primary"
KeySpec = 1
KeyLength = 2048
Exportable = FALSE
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
FriendlyName = "$FriendlyName"

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.5.5.7.3.1   ; Server Authentication

[Extensions]
2.5.29.17 = "{text}"
$sanLines

[RequestAttributes]
CertificateTemplate = $Template
"@

$infPath = Join-Path $env:TEMP 'adagent-webui-cert.inf'
$reqPath = Join-Path $env:TEMP 'adagent-webui-cert.req'
Set-Content -Path $infPath -Value $inf -Encoding ASCII

Write-Host ""
Write-Host "Wrote a certificate request template: $infPath" -ForegroundColor Cyan
Write-Host "Request, submit to the CA, and install, then bind the thumbprint:"
Write-Host ""
Write-Host "  certreq -new `"$infPath`" `"$reqPath`""
Write-Host "  certreq -submit -config `"<CAServer\CAName>`" `"$reqPath`" adagent-webui-cert.cer"
Write-Host "  certreq -accept adagent-webui-cert.cer"
Write-Host ""
Write-Host "Find the installed thumbprint with:"
Write-Host "  Get-ChildItem Cert:\LocalMachine\My | Where-Object { `$_.Subject -like '*$primary*' } | Select-Object Thumbprint, Subject"
Write-Host ""
Write-Host "Then: .\Register-IISReverseProxy.ps1 -CertThumbprint <thumb> -AllowedGroup 'DOMAIN\AD-Agent-Analysts'  (no -LockWebUIToLocalhost yet)."
Write-Host "Your CA must publish a Server-Authentication template the requester may enrol ('$Template')."

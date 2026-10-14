#Requires -Version 5.1
<#
.SYNOPSIS
    Puts a certificate from the machine store onto the AD-Agent TLS proxy in one step:
    checks it, writes cert.pem (with the CA chain) and key.pem, locks the key down,
    restarts the proxy and tests what it now serves.

.DESCRIPTION
    Replaces the manual sequence (export PFX -> OpenSSL -> build chain -> icacls ->
    restart). Each manual step went wrong at least once: joined commands, the wrong
    certificate picked, non-exportable keys, leaf-only cert.pem, files lost on update.
    The checks this does BEFORE touching the live files:

      * The name you browse (default: this host's FQDN) is in the certificate's Subject
        Alternative Name. Chrome/Edge ignore the Common Name, so a certificate issued to
        'CN=<short-name>' with no matching SAN shows "Not secure" for <host>.<domain>.
      * Not expired, has its private key, allowed for Server Authentication.
      * The private key is exportable (the proxy needs it as a file).
      * The new key matches the new certificate.

    Existing cert.pem/key.pem are backed up first and restored if anything fails.

    Needs OpenSSL for the key conversion (found on PATH, in C:\Program Files\OpenSSL-Win64,
    or Git for Windows), or pass -OpenSslPath.

.PARAMETER Thumbprint
    The certificate in Cert:\LocalMachine\My to install.
.PARAMETER Auto
    Pick automatically: the newest valid Server Authentication certificate whose names
    include -ExpectedName and whose key can be exported.
.PARAMETER ExpectedName
    The name analysts and endpoints use in the URL. Default: this computer's FQDN.
.PARAMETER OutDir
    Where cert.pem/key.pem live - must match the TLS proxy task's --cert/--key.
    Default: the deployment root (two levels above this script).
.PARAMETER TaskName
    The TLS proxy's scheduled task.
.PARAMETER GmsaAccount
    Account the proxy runs as (gets read access to key.pem). Default: read from the task.
.PARAMETER OpenSslPath
    Full path to openssl.exe if it isn't found automatically.
.PARAMETER SkipRestart
    Write the files but don't restart the proxy.

.EXAMPLE
    .\Install-WebUICertificate.ps1 -Thumbprint 0A1B2C...
.EXAMPLE
    .\Install-WebUICertificate.ps1 -Auto
#>
[CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
param(
    [Parameter(ParameterSetName = 'Thumbprint', Mandatory)][string]$Thumbprint,
    [Parameter(ParameterSetName = 'Auto', Mandatory)][switch]$Auto,
    [string]$ExpectedName,
    [string]$OutDir,
    [string]$TaskName = 'AD-Agent-TlsProxy',
    [string]$GmsaAccount,
    [string]$OpenSslPath,
    [switch]$SkipRestart
)

$ErrorActionPreference = 'Stop'
$ServerAuthOid = '1.3.6.1.5.5.7.3.1'

# --- Helpers (no side effects; unit-tested) ------------------------------------------

function Get-CertDnsNames {
    # SAN DNS entries. Windows formats them 'DNS Name=x', OpenSSL-based .NET 'DNS:x'.
    param([Parameter(Mandatory)]$Certificate)
    $san = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if (-not $san) { return @() }
    @([regex]::Matches($san.Format($false), '(?:DNS Name=|DNS:)\s*([^,\s]+)') | ForEach-Object { $_.Groups[1].Value })
}

function Test-NameCovered {
    # True when $Name is one of $Names, case-insensitively, or matches a one-label wildcard.
    param([string[]]$Names, [Parameter(Mandatory)][string]$Name)
    foreach ($n in $Names) {
        if ($n -ieq $Name) { return $true }
        if ($n.StartsWith('*.') -and $Name.Contains('.') -and
            $Name.Substring($Name.IndexOf('.')) -ieq $n.Substring(1)) { return $true }
    }
    return $false
}

function Test-ServerAuthUsage {
    # No EKU extension = any purpose; otherwise Server Authentication must be listed.
    param([Parameter(Mandatory)]$Certificate)
    $eku = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
    if (-not $eku) { return $true }
    return [bool]($eku.EnhancedKeyUsages | Where-Object { $_.Value -eq $ServerAuthOid })
}

function Get-CertProblems {
    # Everything wrong with using $Certificate for https://$Name. Empty = good to go.
    param([Parameter(Mandatory)]$Certificate, [Parameter(Mandatory)][string]$Name, [switch]$SkipKeyCheck)
    $problems = @()
    $names = @(Get-CertDnsNames $Certificate)
    if (-not (Test-NameCovered -Names $names -Name $Name)) {
        $has = if ($names) { $names -join ', ' } else { 'none - only the Common Name ' + $Certificate.Subject }
        $problems += "'$Name' is not in the certificate's Subject Alternative Name (it has: $has). Browsers ignore the Common Name, so this shows 'Not secure'. Request one with: .\Request-WebUICertificate.ps1 -ExportableKey"
    }
    if ($Certificate.NotAfter -lt (Get-Date)) { $problems += "Expired on $($Certificate.NotAfter)." }
    if ($Certificate.NotBefore -gt (Get-Date)) { $problems += "Not valid until $($Certificate.NotBefore)." }
    if (-not (Test-ServerAuthUsage $Certificate)) { $problems += "Not allowed for Server Authentication (wrong template)." }
    if (-not $SkipKeyCheck -and -not $Certificate.HasPrivateKey) { $problems += "No private key on this machine for this certificate." }
    $problems
}

function ConvertTo-PemChain {
    # Leaf first, then each CA certificate - the order TLS servers must send them.
    param([Parameter(Mandatory)][object[]]$Certificates)
    ($Certificates | ForEach-Object {
        "-----BEGIN CERTIFICATE-----`r`n" + [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks') + "`r`n-----END CERTIFICATE-----"
    }) -join "`r`n"
}

function Find-OpenSsl {
    param([string]$Explicit)
    $candidates = @()
    if ($Explicit) { $candidates += $Explicit }
    $onPath = Get-Command openssl -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($onPath) { $candidates += $onPath.Source }
    $candidates += @(
        'C:\Program Files\OpenSSL-Win64\bin\openssl.exe',
        'C:\Program Files\OpenSSL\bin\openssl.exe',
        'C:\Program Files\Git\usr\bin\openssl.exe',
        'C:\Program Files\Git\mingw64\bin\openssl.exe'
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    return $null
}

function Test-KeyMatchesCert {
    # Compare the RSA modulus of the certificate and the key.
    param([Parameter(Mandatory)][string]$OpenSsl, [Parameter(Mandatory)][string]$CertPem, [Parameter(Mandatory)][string]$KeyPem)
    $c = (& $OpenSsl x509 -noout -modulus -in $CertPem 2>$null) -join ''
    $k = (& $OpenSsl rsa -noout -modulus -in $KeyPem 2>$null) -join ''
    return ($c -and $k -and $c -eq $k)
}

function Export-KeyPemFromPfx {
    # PFX -> unencrypted PEM key. The password goes through an environment variable, not
    # the command line, so it never shows in a process listing. Retries with -legacy for
    # OpenSSL 3 reading an older PFX format.
    param([Parameter(Mandatory)][string]$OpenSsl, [Parameter(Mandatory)][string]$Pfx,
          [Parameter(Mandatory)][string]$Password, [Parameter(Mandatory)][string]$OutKey)
    $env:ADAGENT_PFX_PW = $Password
    try {
        foreach ($extra in @(@(), @('-legacy'))) {
            Remove-Item $OutKey -ErrorAction SilentlyContinue
            & $OpenSsl pkcs12 -in $Pfx -nocerts -nodes -passin env:ADAGENT_PFX_PW -out $OutKey @extra 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0 -and (Test-Path $OutKey) -and (Get-Content $OutKey -Raw) -match 'PRIVATE KEY') { return $true }
        }
        return $false
    } finally {
        Remove-Item Env:\ADAGENT_PFX_PW -ErrorAction SilentlyContinue
    }
}

function Test-ServedCertificate {
    # TLS handshake to the proxy, presenting $Name (SNI + name check) while connecting to
    # $ConnectTo - so it tests what browsers get for that name without depending on DNS.
    param([Parameter(Mandatory)][string]$Name, [int]$Port = 443, [string]$ConnectTo = '127.0.0.1', [int]$TimeoutMs = 8000)
    $state = @{ Errors = $null; Cert = $null; Chain = @() }
    $callback = {
        param($sender, $certificate, $chain, $policyErrors)
        $state.Errors = $policyErrors
        if ($certificate) { $state.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate }
        if ($chain) { $state.Chain = @($chain.ChainElements | ForEach-Object { $_.Certificate.Subject }) }
        return $true
    }.GetNewClosure()
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $tcp.ConnectAsync($ConnectTo, $Port)
        $done = $false
        try { $done = $connect.Wait($TimeoutMs) } catch { }
        if (-not $done -or -not $tcp.Connected) { return [pscustomobject]@{ Ok = $false; Detail = "Nothing answering on ${ConnectTo}:$Port - is the proxy running?" } }
        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $tcp.GetStream(), $false, ([System.Net.Security.RemoteCertificateValidationCallback]$callback)
        try { $ssl.AuthenticateAsClient($Name, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false) } finally { $ssl.Dispose() }
    } catch {
        $inner = $_.Exception; while ($inner.InnerException) { $inner = $inner.InnerException }
        return [pscustomobject]@{ Ok = $false; Detail = "TLS handshake failed: $($inner.Message)" }
    } finally {
        $tcp.Dispose()
    }
    $names = if ($state.Cert) { @(Get-CertDnsNames $state.Cert) } else { @() }
    $errors = [string]$state.Errors
    [pscustomobject]@{
        Ok         = ($errors -eq 'None')
        Thumbprint = if ($state.Cert) { $state.Cert.Thumbprint } else { $null }
        Names      = $names
        Chain      = $state.Chain
        Detail     = $errors
    }
}

# --- Main --------------------------------------------------------------------------
# Lets a test dot-source the helpers above without running anything below.
if ($env:ADAGENT_CERT_HELPERS_ONLY -eq '1') { return }

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { throw "Run elevated - this reads machine certificate keys, sets file permissions and restarts the TLS proxy task." }

if (-not $ExpectedName) {
    $ExpectedName = if ($env:USERDNSDOMAIN) { "$env:COMPUTERNAME.$env:USERDNSDOMAIN".ToLower() } else { $env:COMPUTERNAME }
}
if (-not $OutDir) { $OutDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
$certPath = Join-Path $OutDir 'cert.pem'
$keyPath = Join-Path $OutDir 'key.pem'

$ossl = Find-OpenSsl -Explicit $OpenSslPath
if (-not $ossl) { throw "OpenSSL not found. Install it, or pass -OpenSslPath 'C:\path\to\openssl.exe'." }
Write-Host "OpenSSL      : $ossl"
Write-Host "Expected name: $ExpectedName"
Write-Host "Output       : $certPath, $keyPath"

# 1. Pick the certificate --------------------------------------------------------
if ($Auto) {
    $candidates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey } |
        Where-Object { -not (Get-CertProblems -Certificate $_ -Name $ExpectedName) } |
        Sort-Object NotAfter -Descending)
    if (-not $candidates) {
        Write-Host "No certificate in Cert:\LocalMachine\My is usable for https://$ExpectedName :" -ForegroundColor Red
        Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
            Write-Host "  $($_.Thumbprint)  $($_.Subject)  expires $($_.NotAfter)"
            Get-CertProblems -Certificate $_ -Name $ExpectedName | ForEach-Object { Write-Host "      - $_" -ForegroundColor Yellow }
        }
        throw "Request a suitable certificate with: .\Request-WebUICertificate.ps1 -ExportableKey"
    }
} else {
    $t = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpper()
    $one = Get-Item "Cert:\LocalMachine\My\$t" -ErrorAction SilentlyContinue
    if (-not $one) { throw "No certificate with thumbprint $t in Cert:\LocalMachine\My." }
    $problems = @(Get-CertProblems -Certificate $one -Name $ExpectedName)
    if ($problems) {
        Write-Host "Certificate $t can't be used for https://$ExpectedName :" -ForegroundColor Red
        $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
        throw "Certificate check failed - nothing was changed."
    }
    $candidates = @($one)
}

# 2. Export (first candidate whose key is exportable) -----------------------------
$work = Join-Path $env:TEMP ("adagent-cert-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$backup = $null
try {
    $cert = $null
    $pfxPath = Join-Path $work 'export.pfx'
    $pw = [Convert]::ToBase64String((1..24 | ForEach-Object { [byte](Get-Random -Maximum 256) }))
    foreach ($c in $candidates) {
        try {
            Export-PfxCertificate -Cert $c -FilePath $pfxPath -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -ChainOption BuildChain -Force | Out-Null
            $cert = $c
            break
        } catch {
            Write-Host "  $($c.Thumbprint): key can't be exported ($($_.Exception.Message))" -ForegroundColor Yellow
        }
    }
    if (-not $cert) {
        throw "The private key isn't exportable. The TLS proxy needs the key as a file - request a certificate with an exportable key: .\Request-WebUICertificate.ps1 -ExportableKey (or tick 'Make private key exportable' in certlm.msc)."
    }
    Write-Host "Using        : $($cert.Thumbprint)  $($cert.Subject)  expires $($cert.NotAfter)" -ForegroundColor Green
    Write-Host "Names        : $((Get-CertDnsNames $cert) -join ', ')"

    # 3. New key + cert into the work folder, verified before anything live changes
    $newKey = Join-Path $work 'key.pem'
    $newCert = Join-Path $work 'cert.pem'
    if (-not (Export-KeyPemFromPfx -OpenSsl $ossl -Pfx $pfxPath -Password $pw -OutKey $newKey)) {
        throw "OpenSSL could not read the private key from the exported PFX."
    }
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    [void]$chain.Build($cert)
    $chainCerts = @($chain.ChainElements | ForEach-Object { $_.Certificate })
    if ($chainCerts.Count -lt 1) { $chainCerts = @($cert) }
    Set-Content -Path $newCert -Value (ConvertTo-PemChain -Certificates $chainCerts) -Encoding ascii
    Write-Host "Chain        : $(($chainCerts | ForEach-Object { $_.Subject }) -join '  ->  ')"
    if ($chainCerts.Count -lt 2) {
        Write-Warning "Only the server certificate was found - this machine doesn't have the issuing CA certificate, so clients may report a partial chain."
    }
    if (-not (Test-KeyMatchesCert -OpenSsl $ossl -CertPem $newCert -KeyPem $newKey)) {
        throw "The exported key does not match the certificate - nothing was changed."
    }

    # 4. Back up the live files, then swap in the new ones
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ((Test-Path $certPath) -or (Test-Path $keyPath)) {
        $backup = Join-Path $OutDir "tls-backup-$stamp"
        New-Item -ItemType Directory -Path $backup -Force | Out-Null
        foreach ($f in @($certPath, $keyPath)) { if (Test-Path $f) { Copy-Item $f $backup } }
        Write-Host "Backup       : $backup"
    }
    Copy-Item $newCert $certPath -Force
    Copy-Item $newKey $keyPath -Force

    # 5. Lock the key down to SYSTEM, Administrators and the account the proxy runs as
    if (-not $GmsaAccount) {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) { $GmsaAccount = $task.Principal.UserId }
    }
    $grants = @('SYSTEM:R', 'BUILTIN\Administrators:F')
    if ($GmsaAccount) { $grants += "${GmsaAccount}:R" }
    icacls $keyPath /inheritance:r /grant:r @grants | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "icacls returned $LASTEXITCODE - check the permissions on $keyPath." }
    Write-Host "Key access   : $($grants -join ', ')"
} catch {
    if ($backup) {
        foreach ($f in @('cert.pem', 'key.pem')) {
            $b = Join-Path $backup $f
            if (Test-Path $b) { Copy-Item $b (Join-Path $OutDir $f) -Force }
        }
        Write-Warning "Restored the previous cert.pem/key.pem from $backup."
    }
    throw
} finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}

# 6. Restart the proxy and test what it serves -------------------------------------
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$port = 443
if ($task) {
    $taskArgs = (@($task.Actions) | ForEach-Object { $_.Arguments }) -join ' '
    if ($taskArgs -match '--listen-port\s+(\d+)') { $port = [int]$Matches[1] }
    if ($taskArgs -notmatch [regex]::Escape($certPath) -or $taskArgs -notmatch [regex]::Escape($keyPath)) {
        Write-Warning "Task '$TaskName' doesn't point at $certPath / $keyPath. Re-register it: .\Register-TlsProxy.ps1 -CertPem '$certPath' -KeyPem '$keyPath' -GmsaAccount ... -PythonPath ..."
    }
} else {
    Write-Warning "Scheduled task '$TaskName' not found - register the proxy with Register-TlsProxy.ps1 -CertPem '$certPath' -KeyPem '$keyPath'."
}

if ($SkipRestart -or -not $task) {
    Write-Host "`nFiles written. Restart the proxy to use them: Stop-ScheduledTask '$TaskName'; Start-ScheduledTask '$TaskName'"
    return
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 5

$r = Test-ServedCertificate -Name $ExpectedName -Port $port
Write-Host ""
if ($r.Thumbprint -and $r.Thumbprint -ne $cert.Thumbprint) {
    Write-Warning "The proxy is serving $($r.Thumbprint), not the new certificate - it may not have restarted, or the task points at different files."
}
if ($r.Ok) {
    Write-Host "OK - https://$ExpectedName now serves a certificate this machine trusts." -ForegroundColor Green
    Write-Host "   Names: $($r.Names -join ', ')   Chain: $($r.Chain.Count) certificate(s)"
    Write-Host ""
    Write-Host "Next:"
    Write-Host "  1. Close every browser window, reopen https://$ExpectedName - expect the padlock."
    Write-Host "  2. Laptops: rebuild the Intune package with this exact name and re-upload it:"
    Write-Host "     .\Build-IntunePackage.ps1 -ServerUrl 'https://$ExpectedName' -Token '<COLLECTOR_TOKEN>' ..."
} else {
    Write-Host "The proxy answered but this machine does NOT accept its certificate for '$ExpectedName': $($r.Detail)" -ForegroundColor Red
    if ($r.Names) { Write-Host "   Served names: $($r.Names -join ', ')   Chain: $($r.Chain -join ' -> ')" }
    Write-Host "   Previous files are in: $backup"
}

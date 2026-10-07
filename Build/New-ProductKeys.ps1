#Requires -Version 5.1
<#
.SYNOPSIS
    One-time generation of the developer's product keys: an Authenticode code-signing
    certificate and an RSA license-signing keypair. Run on the BUILD machine only.

.DESCRIPTION
    AD-Agent ships as a signed, licensed product. Two keys, both held by the developer and
    kept on the build machine - never on a deployed server, which only ever receives the
    public halves:

      1. Code-signing certificate - signs every .ps1/.psm1 and the integrity catalog, so a
         deployed server running ExecutionPolicy AllSigned only executes developer-signed
         code and tampering is detectable. Prefer a cert issued by your AD CS CA; this script
         can also create a self-signed one as an interim.

      2. License RSA keypair - the private key signs each license.key; the product embeds
         only the public key (WebApp/license_pubkey.pem and the PS module's copy) and
         verifies licenses against it. Only licenses you sign are valid.

    The RSA private key is exported encrypted (DPAPI, current user on the build box) so it
    is not left in the clear. Keep a secure backup; losing it means re-keying the product
    (re-issuing licenses), not losing data.

.PARAMETER OutputDir
    Where to write the keys and the public artifacts. Default: a 'keys' folder beside this script.
.PARAMETER CodeSignSubject
    Subject for a self-signed code-signing cert if you don't supply -CodeSignThumbprint.
.PARAMETER CodeSignThumbprint
    Thumbprint of an existing code-signing cert (e.g. issued by AD CS) to use instead of
    generating a self-signed one.
.PARAMETER RsaKeySize
    License key size. 3072 by default.

.EXAMPLE
    .\New-ProductKeys.ps1
    Generate a self-signed code-signing cert and a 3072-bit license keypair.

.EXAMPLE
    .\New-ProductKeys.ps1 -CodeSignThumbprint 'AB12...'
    Use an existing (CA-issued) code-signing cert; just create the license keypair + exports.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $PSScriptRoot 'keys'),
    [string]$CodeSignSubject = 'CN=AD-Agent Code Signing',
    [string]$CodeSignThumbprint,
    [int]$RsaKeySize = 3072
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# --- Code-signing certificate ------------------------------------------------
if ($CodeSignThumbprint) {
    $cert = Get-Item "Cert:\CurrentUser\My\$CodeSignThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item "Cert:\LocalMachine\My\$CodeSignThumbprint" -ErrorAction SilentlyContinue }
    if (-not $cert) { throw "No code-signing cert with thumbprint $CodeSignThumbprint found in CurrentUser\My or LocalMachine\My." }
    Write-Host "Using existing code-signing cert: $($cert.Subject) [$($cert.Thumbprint)]"
} else {
    Write-Host "Generating a self-signed code-signing certificate ($CodeSignSubject)..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $CodeSignSubject `
        -KeyUsage DigitalSignature -KeyExportPolicy Exportable `
        -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(5)
    Write-Host "Created self-signed cert [$($cert.Thumbprint)]."
    Write-Host "For AllSigned to trust it estate-wide, distribute the public cert below to"
    Write-Host "Trusted Publishers (and Trusted Root if self-signed) via GPO."
}

# Export the PUBLIC code-signing cert for distribution (never the private key).
$pubCer = Join-Path $OutputDir 'codesign-public.cer'
Export-Certificate -Cert $cert -FilePath $pubCer -Force | Out-Null
Write-Host "Code-signing public cert -> $pubCer"
Set-Content -Path (Join-Path $OutputDir 'codesign-thumbprint.txt') -Value $cert.Thumbprint -Encoding ASCII

# --- License RSA keypair -----------------------------------------------------
Write-Host "Generating a $RsaKeySize-bit RSA license keypair..."
$rsa = [System.Security.Cryptography.RSA]::Create($RsaKeySize)

# Public key as SubjectPublicKeyInfo PEM - this is what the product embeds and verifies with.
$spki = $rsa.ExportSubjectPublicKeyInfo()
$pem = "-----BEGIN PUBLIC KEY-----`n" +
       ([Convert]::ToBase64String($spki, [Base64FormattingOptions]::InsertLineBreaks)) +
       "`n-----END PUBLIC KEY-----`n"
$pubPem = Join-Path $OutputDir 'license_pubkey.pem'
Set-Content -Path $pubPem -Value $pem -Encoding ASCII
Write-Host "License PUBLIC key -> $pubPem"
Write-Host "  Copy this to WebApp\license_pubkey.pem and DCAnomalyAgent\Config\license_pubkey.pem before building."

# Private key (PKCS#8), DPAPI-protected to the current user on this build box so it is not
# stored in the clear. New-License.ps1 reads it back.
$pkcs8 = $rsa.ExportPkcs8PrivateKey()
$protected = [System.Security.Cryptography.ProtectedData]::Protect(
    $pkcs8, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$privOut = Join-Path $OutputDir 'license_privkey.dpapi'
[System.IO.File]::WriteAllBytes($privOut, $protected)
Write-Host "License PRIVATE key (DPAPI-protected to you on this box) -> $privOut"
Write-Host ""
Write-Host "KEEP THE PRIVATE KEY AND ITS BACKUP SECURE. It never goes on a deployed server." -ForegroundColor Yellow

#Requires -Version 5.1
<#
.SYNOPSIS
    Issue a signed license.key for an AD-Agent deployment. Developer-only; run on the build
    machine where the license private key (from New-ProductKeys.ps1) lives.

.DESCRIPTION
    Writes a license.key: a JSON document {payload, signature} where the signature is RSA
    PKCS#1 v1.5 over SHA-256 of the canonical JSON of the payload, made with your license
    private key. The product verifies it with the embedded public key. Only licenses you
    sign are valid, so the product is "locked" to builds you license.

    Node-locking: pass -MachineId (the target server's MachineGuid) to bind the license to
    that one host, so a copied install will not run elsewhere without a new license. Get the
    target's id with:
        (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid

.PARAMETER Owner
    Who the license is issued to (shown in the product banner). Required.
.PARAMETER PrivateKeyPath
    The DPAPI-protected license private key from New-ProductKeys.ps1.
.PARAMETER OutFile
    Where to write license.key.
.PARAMETER MachineId
    Optional target MachineGuid to node-lock the license. Omit for an unbound license.
.PARAMETER ExpiresUtc
    Optional expiry (e.g. '2027-12-31'). Omit for a perpetual license. NOTE: enforcement is
    non-destructive - an expired license blocks new scans but never deletes data.
.PARAMETER Features
    Optional feature tags recorded in the payload (informational for now).

.EXAMPLE
    .\New-License.ps1 -Owner 'Acme SOC' -MachineId (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Owner,
    [string]$PrivateKeyPath = (Join-Path $PSScriptRoot 'keys\license_privkey.dpapi'),
    [string]$OutFile = (Join-Path $PSScriptRoot 'out\license.key'),
    [string]$MachineId,
    [string]$ExpiresUtc,
    [string[]]$Features = @('all')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $PrivateKeyPath)) { throw "License private key not found at $PrivateKeyPath. Run New-ProductKeys.ps1 first." }

# Recover the RSA private key from its DPAPI blob (current user, build box).
$protected = [System.IO.File]::ReadAllBytes($PrivateKeyPath)
$pkcs8 = [System.Security.Cryptography.ProtectedData]::Unprotect(
    $protected, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$rsa = [System.Security.Cryptography.RSA]::Create()
$rsa.ImportPkcs8PrivateKey($pkcs8, [ref]0)

$expiresValue = if ($ExpiresUtc) { ([datetime]$ExpiresUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }

# Payload keys MUST serialize the same way the verifier canonicalizes them (sorted keys,
# compact separators). Build the canonical JSON by hand to match Python's
# json.dumps(sort_keys=True, separators=(',',':')).
$payload = [ordered]@{
    expires  = $expiresValue
    features = $Features
    issued   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    machine  = if ($MachineId) { $MachineId.ToLower() } else { $null }
    owner    = $Owner
    product  = 'AD-Agent'
}

function ConvertTo-CanonicalJson {
    # Minimal canonical JSON (sorted keys, no spaces) matching the Python verifier for the
    # flat payload used here (string/null values + a string array for features).
    param([hashtable]$Map)
    $keys = $Map.Keys | Sort-Object
    $parts = foreach ($k in $keys) {
        $v = $Map[$k]
        $val =
            if ($null -eq $v) { 'null' }
            elseif ($v -is [System.Array]) { '[' + (($v | ForEach-Object { '"' + ($_ -replace '([\\"])','\$1') + '"' }) -join ',') + ']' }
            else { '"' + ("$v" -replace '([\\"])','\$1') + '"' }
        '"' + $k + '":' + $val
    }
    '{' + ($parts -join ',') + '}'
}

# $payload is [ordered] (a hashtable); pass as hashtable for canonicalization.
$canon = ConvertTo-CanonicalJson -Map $payload
$sigBytes = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($canon),
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$signature = [Convert]::ToBase64String($sigBytes)

$doc = [ordered]@{ payload = $payload; signature = $signature }
$outDir = Split-Path -Parent $OutFile
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$doc | ConvertTo-Json -Depth 5 | Set-Content -Path $OutFile -Encoding UTF8

Write-Host "License written: $OutFile"
Write-Host "  Owner:   $Owner"
Write-Host "  Machine: $(if ($MachineId) { $MachineId } else { '(unbound)' })"
Write-Host "  Expires: $(if ($expiresValue) { $expiresValue } else { '(perpetual)' })"
Write-Host "Install it with: Install-ADAgent.ps1 -License `"$OutFile`""

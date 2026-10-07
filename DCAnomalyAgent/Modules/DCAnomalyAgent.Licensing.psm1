#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies the AD-Agent product license for the scan scripts (the PowerShell side of
    WebApp/licensing.py). Non-destructive and default-off.

.DESCRIPTION
    Test-ProductLicense returns a status object {State; Ok; Reason; Owner; Expires}. It
    checks an RSA PKCS#1 v1.5 / SHA-256 signature over the canonical JSON of the license
    payload against the embedded public key, plus product, expiry and optional machine
    binding (MachineGuid node-lock).

    Enforcement is OFF unless the environment variable ADAGENT_LICENSE_ENFORCE=1 AND a
    public key is present. When off, Ok is always $true (the product runs unlocked). When on
    and the license is missing/invalid, the scan scripts exit WITHOUT touching any data -
    a licensed security tool must fail safe, never destructive.
#>

function ConvertTo-LicenseCanonicalJson {
    # MUST match Build\New-License.ps1 and WebApp/licensing.py (sorted keys, compact,
    # string/null/string-array values only).
    param([Parameter(Mandatory)]$Payload)
    $map = @{}
    foreach ($p in $Payload.PSObject.Properties) { $map[$p.Name] = $p.Value }
    $keys = $map.Keys | Sort-Object
    $parts = foreach ($k in $keys) {
        $v = $map[$k]
        $val =
            if ($null -eq $v) { 'null' }
            elseif ($v -is [System.Array] -or $v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                '[' + (($v | ForEach-Object { '"' + ($_ -replace '([\\"])', '\$1') + '"' }) -join ',') + ']'
            }
            else { '"' + ("$v" -replace '([\\"])', '\$1') + '"' }
        '"' + $k + '":' + $val
    }
    '{' + ($parts -join ',') + '}'
}

function Get-LicenseMachineId {
    try { return ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid).ToLower() }
    catch { return $env:COMPUTERNAME.ToLower() }
}

function Test-ProductLicense {
    [CmdletBinding()]
    param(
        [string]$LicensePath   = (Join-Path $PSScriptRoot '..\Config\license.key'),
        [string]$PublicKeyPath = (Join-Path $PSScriptRoot '..\Config\license_pubkey.pem')
    )

    $enforce = ($env:ADAGENT_LICENSE_ENFORCE -eq '1') -and (Test-Path $PublicKeyPath) -and ((Get-Item $PublicKeyPath).Length -gt 0)
    if (-not $enforce) {
        return [pscustomobject]@{ State = 'unenforced'; Ok = $true; Reason = 'License enforcement is off.'; Owner = $null; Expires = $null }
    }
    if (-not (Test-Path $LicensePath)) {
        return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = 'No license file installed.'; Owner = $null; Expires = $null }
    }

    try {
        $doc = Get-Content -Raw -Path $LicensePath | ConvertFrom-Json
        $payload = $doc.payload
        $sig = [Convert]::FromBase64String($doc.signature)
    } catch {
        return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = 'License file is unreadable.'; Owner = $null; Expires = $null }
    }

    $owner = $payload.owner; $expires = $payload.expires
    try {
        $pem = (Get-Content -Raw -Path $PublicKeyPath)
        $b64 = ($pem -replace '-----BEGIN PUBLIC KEY-----', '' -replace '-----END PUBLIC KEY-----', '' -replace '\s', '')
        $spki = [Convert]::FromBase64String($b64)
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportSubjectPublicKeyInfo($spki, [ref]0)
        $canon = [Text.Encoding]::UTF8.GetBytes((ConvertTo-LicenseCanonicalJson -Payload $payload))
        $ok = $rsa.VerifyData($canon, $sig,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch {
        return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = "Signature check error: $_"; Owner = $owner; Expires = $expires }
    }
    if (-not $ok)                { return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = 'License signature is not valid.'; Owner = $owner; Expires = $expires } }
    if ($payload.product -ne 'AD-Agent') { return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = 'License is not for this product.'; Owner = $owner; Expires = $expires } }
    if ($expires) {
        try { if ((Get-Date).ToUniversalTime() -gt ([datetime]$expires).ToUniversalTime()) {
            return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = "License expired on $expires."; Owner = $owner; Expires = $expires } } }
        catch { return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = 'License expiry is malformed.'; Owner = $owner; Expires = $expires } }
    }
    if ($payload.machine -and ($payload.machine.ToString().ToLower() -ne (Get-LicenseMachineId))) {
        return [pscustomobject]@{ State = 'invalid'; Ok = $false; Reason = 'License is bound to a different machine.'; Owner = $owner; Expires = $expires }
    }
    return [pscustomobject]@{ State = 'valid'; Ok = $true; Reason = 'Licensed.'; Owner = $owner; Expires = $expires }
}

function Assert-ProductLicense {
    <#
    .SYNOPSIS
        Throw (stopping the scan before any work) if enforcement is on and the license is
        invalid. No data is touched. Scan scripts call this at startup.
    #>
    [CmdletBinding()] param()
    $s = Test-ProductLicense
    if (-not $s.Ok) {
        throw "AD-Agent is not licensed to run on this host: $($s.Reason) No scan was performed; no data was changed."
    }
    return $s
}

Export-ModuleMember -Function Test-ProductLicense, Assert-ProductLicense, Get-LicenseMachineId, ConvertTo-LicenseCanonicalJson

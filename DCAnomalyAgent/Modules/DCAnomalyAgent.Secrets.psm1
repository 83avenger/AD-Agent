#Requires -Version 5.1
<#
.SYNOPSIS
    DPAPI (machine-scope) encryption for AD-Agent's integration secrets, matching
    WebApp/secrets_store.py so the PowerShell scripts and the web app read the same
    Config\integration-secrets.json.enc.

.DESCRIPTION
    .NET ProtectedData at LocalMachine scope uses the same underlying DPAPI (CryptProtectData
    with the machine flag, no extra entropy) as the Python ctypes implementation, so blobs
    written by one side decrypt on the other. Secrets are therefore never on disk in the
    clear, yet any identity on that one machine (the gMSA, an admin) can read them, while a
    copy taken off the box is useless.
#>

function Get-SecretsEncPath {
    param([string]$Path = (Join-Path $PSScriptRoot '..\Config\integration-secrets.json'))
    return "$Path.enc"
}

function Read-IntegrationSecrets {
    [CmdletBinding()]
    param([string]$Path = (Join-Path $PSScriptRoot '..\Config\integration-secrets.json'))
    $enc = Get-SecretsEncPath -Path $Path
    if (Test-Path $enc) {
        try {
            $blob = [System.IO.File]::ReadAllBytes($enc)
            $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $blob, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
            return ([Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json)
        } catch {
            Write-Warning "Could not decrypt $enc (blob from another machine?): $_"
        }
    }
    if (Test-Path $Path) {
        try { return (Get-Content -Raw -Path $Path | ConvertFrom-Json) } catch { }
    }
    return $null
}

function Write-IntegrationSecrets {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Data,
        [string]$Path = (Join-Path $PSScriptRoot '..\Config\integration-secrets.json')
    )
    $enc = Get-SecretsEncPath -Path $Path
    $dir = Split-Path -Parent $enc
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = ($Data | ConvertTo-Json -Depth 8)
    $blob = [System.Security.Cryptography.ProtectedData]::Protect(
        [Text.Encoding]::UTF8.GetBytes($json), $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [System.IO.File]::WriteAllBytes($enc, $blob)
    # Migrate away from any plaintext copy.
    if (Test-Path $Path) { try { Remove-Item $Path -Force } catch { } }
}

Export-ModuleMember -Function Read-IntegrationSecrets, Write-IntegrationSecrets, Get-SecretsEncPath

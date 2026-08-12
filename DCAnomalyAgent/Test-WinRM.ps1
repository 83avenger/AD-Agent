#Requires -Version 5.1
<#
.SYNOPSIS
    WinRM connectivity/troubleshooting test - the exact checks that have been run by hand
    (Test-TcpPort, Test-WSMan, Invoke-Command) to diagnose why a host has no software
    collected, packaged into one command with clear pass/fail per step and the real error
    text for whichever step fails.

.PARAMETER ComputerName
    One or more hosts to test. If omitted, tests every host in the Discovery inventory
    (State\asset-inventory.json) that was seen with WinRM open.

.PARAMETER JsonOutput
    Emit results as JSON on stdout (used by the web UI's WinRM Test page).

.EXAMPLE
    .\Test-WinRM.ps1 -ComputerName 'Jump-Jeremy.amg.local'
.EXAMPLE
    .\Test-WinRM.ps1
    # tests every Windows host Discovery has found so far
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$ConfigPath,
    [switch]$JsonOutput
)

$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'Config\settings.psd1' }
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Discovery.psm1" -Force

function Import-AgentConfig {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -Path $Path).Path
    $dir  = Split-Path -Parent $resolved
    $text = (Get-Content -Raw -Path $resolved).Replace('$PSScriptRoot', $dir)
    return (& ([scriptblock]::Create($text)))
}

if (-not $ComputerName) {
    $config = Import-AgentConfig -Path $ConfigPath
    $outDir = Split-Path -Path $config.LogPath -Parent
    $inventoryPath = Join-Path $outDir 'asset-inventory.json'
    if (Test-Path $inventoryPath) {
        $inventory = @(Get-Content -Raw -Path $inventoryPath | ConvertFrom-Json)
        $ComputerName = @($inventory | Where-Object {
            $_.AssetType -in @('Domain Controller', 'Server', 'Desktop', 'Laptop', 'Workstation') -or
            ($_.OpenPorts -and $_.OpenPorts -match 'WinRM')
        } | Select-Object -ExpandProperty Name)
    }
    if (-not $ComputerName) {
        Write-Host "No -ComputerName given and no Windows hosts found in the Discovery inventory. Run Run-Discovery.ps1 first, or pass -ComputerName explicitly."
        return
    }
}

$results = foreach ($h in $ComputerName) {
    $r = [ordered]@{
        ComputerName  = $h
        Tcp5985       = $false
        Tcp5986       = $false
        WsManOk       = $false
        WsManError    = $null
        InvokeOk      = $false
        InvokeIdentity = $null
        InvokeHostname = $null
        InvokeError   = $null
        OverallStatus = 'Unreachable'
    }

    $r.Tcp5985 = Test-TcpPort -ComputerName $h -Port 5985 -TimeoutMs 1500
    $r.Tcp5986 = Test-TcpPort -ComputerName $h -Port 5986 -TimeoutMs 1500

    if ($r.Tcp5985 -or $r.Tcp5986) {
        try {
            $null = Test-WSMan -ComputerName $h -ErrorAction Stop
            $r.WsManOk = $true
        } catch {
            $r.WsManError = $_.Exception.Message
        }

        try {
            $identity = Invoke-Command -ComputerName $h -ScriptBlock {
                [pscustomobject]@{
                    Identity = whoami
                    Hostname = hostname
                }
            } -ErrorAction Stop
            $r.InvokeOk = $true
            $r.InvokeIdentity = $identity.Identity
            $r.InvokeHostname = $identity.Hostname
        } catch {
            $r.InvokeError = $_.Exception.Message
        }
    }

    $r.OverallStatus =
        if ($r.InvokeOk) { 'OK - fully working' }
        elseif ($r.WsManOk) { 'WSMan reachable but Invoke-Command failed (see InvokeError - usually auth/permissions)' }
        elseif ($r.Tcp5985 -or $r.Tcp5986) { 'Port open but WSMan handshake failed (see WsManError)' }
        else { 'Port 5985/5986 not reachable - firewall, WinRM not enabled, or host down' }

    [pscustomobject]$r
}

if ($JsonOutput) {
    $results | ConvertTo-Json -Depth 4
    return
}

$results | Format-Table -AutoSize ComputerName, Tcp5985, Tcp5986, WsManOk, InvokeOk, OverallStatus | Out-String -Width 300 | Write-Host
foreach ($r in $results) {
    if ($r.WsManError -or $r.InvokeError) {
        Write-Host "`n--- $($r.ComputerName) ---"
        if ($r.WsManError)   { Write-Host "  WSMan error:  $($r.WsManError)" }
        if ($r.InvokeError)  { Write-Host "  Invoke error: $($r.InvokeError)" }
    }
}

return $results

#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Turns WinRM on locally on ONE endpoint, with the inbound rule scoped to the jump server
    (and any admin addresses you list) instead of the whole network.

.DESCRIPTION
    Does on the machine itself what New-WinRMGPO.ps1 does by policy:
      1. WinRM service -> Automatic, and started now (no reboot needed).
      2. Enable-PSRemoting -SkipNetworkProfileCheck: HTTP listener + session configurations,
         working on Public/Private networks too, not just Domain.
      3. One inbound rule 'AD-Agent WinRM-In' for TCP 5985, ALL profiles, RemoteAddress limited
         to -AllowedRemoteAddress.

    Enable-PSRemoting also enables the built-in 'Windows Remote Management (HTTP-In)' rules,
    which are open to any address. This script puts those back exactly as it found them, so
    the only new access it grants is the scoped rule.

    The same file is used three ways: run by hand on an endpoint, pushed by
    Invoke-RemoteEndpointSetup.ps1 (over WMI/DCOM when WinRM is still off), and embedded in the
    Intune script built by Intune\Build-IntunePackage.ps1.

.PARAMETER AllowedRemoteAddress
    Addresses allowed to reach WinRM: the jump server IP, plus optional admin workstation IPs,
    subnets (10.15.2.0/24) or ranges (10.15.2.10-10.15.2.20).
.PARAMETER LogPath
    Where to log what was done.

.EXAMPLE
    .\Enable-EndpointWinRM.ps1 -AllowedRemoteAddress 10.15.2.21
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string[]]$AllowedRemoteAddress,
    [string]$LogPath = "$env:ProgramData\AD-Agent\endpoint-setup.log"
)

$ErrorActionPreference = 'Stop'

function Write-SetupLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] [WinRM] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try {
        $dir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
    } catch { }
}

# A blank or 'Any' scope would quietly open WinRM to the whole network - the opposite of
# what this script is for.
$AllowedRemoteAddress = @($AllowedRemoteAddress | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not $AllowedRemoteAddress -or ($AllowedRemoteAddress | Where-Object { $_ -in @('*', 'Any') })) {
    throw "-AllowedRemoteAddress must list the jump server (and any admin) addresses - not blank, '*' or 'Any'."
}

try {
    Set-Service -Name WinRM -StartupType Automatic
    Start-Service -Name WinRM
    Write-SetupLog "WinRM service set to Automatic and started."

    # Remember the built-in rules' state so we can put it back after Enable-PSRemoting.
    $builtIn = @(Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled)

    Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null
    Write-SetupLog "PSRemoting enabled (listener + session configurations)."

    foreach ($r in $builtIn) {
        Set-NetFirewallRule -Name $r.Name -Enabled $r.Enabled -ErrorAction SilentlyContinue
    }

    $ruleName = 'ADAgent-WinRM-In'
    Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -Name $ruleName -DisplayName 'AD-Agent WinRM-In (TCP 5985)' `
        -Description 'Allows the AD-Agent jump server (and listed admin hosts) to reach WinRM.' `
        -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any `
        -RemoteAddress $AllowedRemoteAddress | Out-Null
    Write-SetupLog "Firewall rule '$ruleName' allows TCP 5985 from: $($AllowedRemoteAddress -join ', ') (all profiles)."

    $listener = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
        Where-Object { $_.Keys -contains 'Transport=HTTP' }
    if (-not $listener) { throw "No HTTP listener exists after Enable-PSRemoting." }
    Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
    Write-SetupLog "WinRM is listening and answering locally."
} catch {
    Write-SetupLog "Failed: $($_.Exception.Message)" 'ERROR'
    throw
}

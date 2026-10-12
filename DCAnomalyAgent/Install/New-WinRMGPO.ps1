#Requires -Version 5.1
<#
.SYNOPSIS
    Builds a WinRM GPO with all the settings it needs, so workstations actually open TCP
    5985 to the jump server. Run on a domain-joined admin box with RSAT Group Policy.

.DESCRIPTION
    A hand-built WinRM GPO usually misses one of the pieces below, and then endpoints still
    show 5985 CLOSED even though the GPO "applied". This sets all of them in one GPO:

      1. WinRM service -> Automatic (takes effect at the next boot).
      2. Listener policy: "Allow remote server management through WinRM" = Enabled with
         IPv4/IPv6 filter '*'. A BLANK filter is the classic trap: no listener is created.
         '*' only means "listen on every local address"; WHO can connect is limited by (3).
      3. An inbound firewall rule for TCP 5985 on ALL profiles (a Domain-only rule does
         nothing for a laptop on Wi-Fi/VPN), with Remote address limited to
         -AllowedRemoteAddress: the jump server, plus any admin hosts you name.

    Endpoints pull GPOs from the DC themselves, so this works even where the endpoint's
    firewall blocks RPC (the GPMC "Group Policy Update..." 0x800706ba errors) - they just pick
    it up at their next background refresh (~90 min) or reboot. A reboot is needed anyway for
    the service to start.

    Verify on an endpoint afterwards with Test-WinRMReadiness.ps1.

.PARAMETER TargetOU
    OU distinguished name(s) to link the GPO to.
.PARAMETER AllowedRemoteAddress
    Addresses allowed to reach WinRM: jump server IP (required), plus optional admin IPs,
    subnets (10.15.2.0/24) or ranges (10.15.2.10-10.15.2.20).
.PARAMETER GpoName
    GPO name. Created if absent, updated if present.

.EXAMPLE
    .\New-WinRMGPO.ps1 -TargetOU 'OU=Laptops,OU=Devices,DC=example,DC=local' `
        -AllowedRemoteAddress 10.15.2.21 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][string[]]$TargetOU,
    [Parameter(Mandatory)][string[]]$AllowedRemoteAddress,
    [string]$GpoName = 'AD-Agent-WinRM'
)

$ErrorActionPreference = 'Stop'

# --- Preconditions -----------------------------------------------------------
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { throw "Run this from an elevated PowerShell session (it edits GPOs)." }
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    throw "The RSAT GroupPolicy module is not installed. Install it (e.g. 'Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0') and re-run."
}
Import-Module GroupPolicy -ErrorAction Stop
Import-Module NetSecurity -ErrorAction Stop

$AllowedRemoteAddress = @($AllowedRemoteAddress | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if (-not $AllowedRemoteAddress -or ($AllowedRemoteAddress | Where-Object { $_ -in @('*', 'Any') })) {
    throw "-AllowedRemoteAddress must list the jump server (and any admin) addresses - not blank, '*' or 'Any'."
}

$domainDns = $env:USERDNSDOMAIN
if (-not $domainDns -and (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) { $domainDns = (Get-ADDomain).DNSRoot }
if (-not $domainDns) { throw "Could not determine the domain DNS name." }

# --- Create + link -----------------------------------------------------------
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    if ($PSCmdlet.ShouldProcess($GpoName, "Create GPO")) {
        $gpo = New-GPO -Name $GpoName -Comment "Enables WinRM on endpoints for the AD-Agent jump server (listener, service, scoped firewall rule)."
        Write-Host "Created GPO '$GpoName' {$($gpo.Id)}"
    }
} else {
    Write-Host "GPO '$GpoName' already exists {$($gpo.Id)} - updating it."
}
foreach ($ou in $TargetOU) {
    if ($PSCmdlet.ShouldProcess($ou, "Link GPO '$GpoName'")) {
        if (-not (Get-GPInheritance -Target $ou | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })) {
            New-GPLink -Name $GpoName -Target $ou -LinkEnabled Yes | Out-Null
            Write-Host "Linked '$GpoName' to $ou"
        } else {
            Write-Host "'$GpoName' already linked to $ou"
        }
    }
}

# --- 1. Service Automatic ----------------------------------------------------
# Written as a registry policy value. (The GUI equivalent is Security Settings > System
# Services; the effect on the endpoint is the same Start=2.)
if ($PSCmdlet.ShouldProcess($GpoName, "Set WinRM service to Automatic")) {
    Set-GPRegistryValue -Name $GpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM' `
        -ValueName 'Start' -Type DWord -Value 2 | Out-Null
    Write-Host "WinRM service: Automatic"
}

# --- 2. Listener policy ------------------------------------------------------
if ($PSCmdlet.ShouldProcess($GpoName, "Enable WinRM listener policy with filter '*'")) {
    $k = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    Set-GPRegistryValue -Name $GpoName -Key $k -ValueName 'AllowAutoConfig' -Type DWord -Value 1 | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key $k -ValueName 'IPv4Filter' -Type String -Value '*' | Out-Null
    Set-GPRegistryValue -Name $GpoName -Key $k -ValueName 'IPv6Filter' -Type String -Value '*' | Out-Null
    Write-Host "Listener policy: enabled, IPv4/IPv6 filter '*'"
}

# --- 3. Scoped firewall rule -------------------------------------------------
# -PolicyStore '<domain>\<GPO>' writes the rule into the GPO itself (Windows Defender Firewall
# with Advanced Security > Inbound Rules), the same as creating it in the GPMC editor.
$store = "$domainDns\$GpoName"
$ruleName = 'ADAgent-WinRM-In'
if ($PSCmdlet.ShouldProcess($store, "Add inbound TCP 5985 rule from $($AllowedRemoteAddress -join ', ')")) {
    Get-NetFirewallRule -PolicyStore $store -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -PolicyStore $store -Name $ruleName -DisplayName 'AD-Agent WinRM-In (TCP 5985)' `
        -Description 'Allows the AD-Agent jump server (and listed admin hosts) to reach WinRM.' `
        -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any `
        -RemoteAddress $AllowedRemoteAddress | Out-Null
    Write-Host "Firewall rule '$ruleName': TCP 5985 from $($AllowedRemoteAddress -join ', '), all profiles"
}

Write-Host ""
Write-Host "Done. On each endpoint the GPO lands at the next background refresh (~90 min) or reboot;" -ForegroundColor Green
Write-Host "the service only STARTS at boot, so reboot (or 'gpupdate /force' then 'Start-Service WinRM')."
Write-Host ""
Write-Host "Check one endpoint:   .\Test-WinRMReadiness.ps1 -GpoName '$GpoName'   (run on the endpoint)"
Write-Host "From the jump server: Test-NetConnection <endpoint> -Port 5985 ; Test-WSMan <endpoint>"
Write-Host ""
Write-Host "If you also have an older hand-made WinRM GPO linked to the same OU, unlink it so the two"
Write-Host "don't fight (e.g. one leaving the IPv4 filter blank)."
Write-Host "If CrowdStrike Falcon Firewall Management is on for these hosts, allow TCP 5985 from the"
Write-Host "jump server in the Falcon firewall policy too - it overrides Windows Firewall rules."

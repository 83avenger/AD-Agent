#Requires -Version 5.1
<#
.SYNOPSIS
    Run from an admin workstation: turns WinRM on and/or installs the push collector on
    endpoints remotely, using whatever channel each endpoint still allows, and reports the
    rest.

.DESCRIPTION
    For each target:
      1. Quick TCP probe of 5985 (WinRM), 135 (RPC/WMI) and 445 (SMB).
      2. 5985 open  -> use WinRM directly.
         135 open   -> start Enable-EndpointWinRM.ps1 on the endpoint over WMI/DCOM
                       (Win32_Process.Create), wait for 5985 to open, then use WinRM.
         neither    -> report "Blocked" - nothing remote can reach it.
      3. With WinRM up and -InstallCollector: send the collector + Install-PushCollector.ps1
         over the session and run the installer there (same tested code as the GPO/local path),
         which registers the two check-in tasks and does one test check-in.

    WHAT THIS CANNOT DO: being on the same VLAN does not get past the endpoint's own
    firewall. If an endpoint drops 5985 AND 135 (what GPMC's "RPC server is unavailable" means),
    no remote tool reaches it - use the GPO (New-WinRMGPO.ps1 / New-PushCollectorGPO.ps1), which
    the endpoint pulls from the DC itself, or Intune (Intune\README.md), which the endpoint
    pulls outbound from the cloud. Those hosts are listed as Blocked in the report.

    CREDENTIALS: run as (or pass -Credential for) an account that is local admin on the
    targets. A DOMAIN account in the local Administrators group works as-is. A LOCAL account
    (e.g. .\Administrator, LAPS) is stripped of admin rights over the network by remote UAC
    unless it is the built-in RID-500 Administrator or LocalAccountTokenFilterPolicy=1, and
    WinRM with a local account also needs the targets in this machine's TrustedHosts. The
    report says when that's the cause.

.PARAMETER ComputerName
    Target host names. (Names, not IPs - Kerberos needs names.)
.PARAMETER InputFile
    Text file with one host name per line (# comments allowed).
.PARAMETER SearchBase
    AD OU distinguished name - every enabled computer under it is a target (needs RSAT AD).
.PARAMETER Credential
    Admin credential for the targets. Defaults to the current user.
.PARAMETER EnableWinRM
    Turn WinRM on (scoped to -AllowedRemoteAddress) where it's off.
.PARAMETER AllowedRemoteAddress
    Addresses the endpoint's WinRM rule allows: the jump server IP AND this admin
    workstation's IP (or subnet), or this script can't use what it just enabled.
.PARAMETER InstallCollector
    Install the push collector tasks.
.PARAMETER ServerUrl
    Jump server URL for the collector, e.g. 'http://jump-host:5000'.
.PARAMETER Token
    The jump server's COLLECTOR_TOKEN.
.PARAMETER ReportPath
    CSV report path.
.PARAMETER WaitSeconds
    How long to wait for 5985 to open after starting the WMI step.

.EXAMPLE
    .\Invoke-RemoteEndpointSetup.ps1 -ComputerName AHD00997-LTP -EnableWinRM `
        -AllowedRemoteAddress 10.15.2.21,10.15.4.0/24 `
        -InstallCollector -ServerUrl 'http://jump-host:5000' -Token '<COLLECTOR_TOKEN>' -WhatIf

.EXAMPLE
    .\Invoke-RemoteEndpointSetup.ps1 -SearchBase 'OU=Laptops,DC=example,DC=local' -InstallCollector `
        -ServerUrl 'http://jump-host:5000' -Token '<COLLECTOR_TOKEN>'
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$ComputerName,
    [string]$InputFile,
    [string]$SearchBase,
    [pscredential]$Credential,
    [switch]$EnableWinRM,
    [string[]]$AllowedRemoteAddress,
    [switch]$InstallCollector,
    [string]$ServerUrl,
    [string]$Token,
    [string]$ReportPath = (Join-Path (Get-Location) ("endpoint-setup-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [int]$WaitSeconds = 45
)

$ErrorActionPreference = 'Stop'

# --- Inputs ------------------------------------------------------------------
if (-not $EnableWinRM -and -not $InstallCollector) { throw "Nothing to do - pass -EnableWinRM and/or -InstallCollector." }
if ($EnableWinRM -and -not $AllowedRemoteAddress) {
    throw "-EnableWinRM needs -AllowedRemoteAddress: the jump server IP AND this workstation's IP/subnet."
}
if ($InstallCollector -and (-not $ServerUrl -or -not $Token)) { throw "-InstallCollector needs -ServerUrl and -Token." }

$collectorDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'Collector'
$winrmScript = Join-Path $collectorDir 'Enable-EndpointWinRM.ps1'
$installerScript = Join-Path $collectorDir 'Install-PushCollector.ps1'
$collectorScript = Join-Path $collectorDir 'Send-InventoryCheckin.ps1'
foreach ($f in @($winrmScript, $installerScript, $collectorScript)) {
    if (-not (Test-Path $f)) { throw "Missing $f - run this from a full copy of the repo." }
}

$targets = [System.Collections.Generic.List[string]]::new()
foreach ($c in @($ComputerName)) { if ($c) { $targets.Add($c.Trim()) } }
if ($InputFile) {
    Get-Content $InputFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { $targets.Add($_) }
}
if ($SearchBase) {
    Import-Module ActiveDirectory -ErrorAction Stop
    Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true' | ForEach-Object { $targets.Add($_.Name) }
}
$targets = @($targets | Sort-Object -Unique)
if (-not $targets) { throw "No targets - use -ComputerName, -InputFile or -SearchBase." }

$credArg = @{}
if ($Credential) { $credArg.Credential = $Credential }

# Script text sent to endpoints. '#Requires' lines are stripped because the text runs as a
# script block on the far side, where they don't apply (the session is already elevated).
function Get-ScriptBody([string]$Path) {
    (Get-Content -Path $Path -Raw) -replace '(?m)^#Requires.*$', ''
}

# --- Helpers -----------------------------------------------------------------
function Test-Ports {
    param([string]$HostName, [int[]]$Ports = @(5985, 135, 445), [int]$TimeoutMs = 1500)
    # Probe all ports at once: a firewalled host otherwise costs one full timeout per port.
    $probes = foreach ($p in $Ports) {
        $client = [System.Net.Sockets.TcpClient]::new()
        [pscustomobject]@{ Port = $p; Client = $client; Task = $client.ConnectAsync($HostName, $p) }
    }
    try { [void][System.Threading.Tasks.Task]::WaitAll(@($probes.Task), $TimeoutMs) } catch { }
    $open = @{}
    foreach ($pr in $probes) {
        # A refused connection also "completes" - only RanToCompletion + Connected is open.
        $open[$pr.Port] = ($pr.Task.Status -eq 'RanToCompletion' -and $pr.Client.Connected)
        $pr.Client.Dispose()
    }
    $open
}

function Get-AuthHint([string]$Message) {
    if ($Message -match 'Access is denied|0x80070005|E_ACCESSDENIED') {
        return ' Access denied: the account is not admin on the target over the network. A local account needs RID-500 or LocalAccountTokenFilterPolicy=1; prefer a domain account in local Administrators.'
    }
    if ($Message -match 'TrustedHosts|Kerberos|cannot be authenticated|0x8009030e') {
        return ' Authentication: use the host NAME with a domain account (Kerberos), or add the target to TrustedHosts when using a local account.'
    }
    ''
}

function Start-WinRMOverWmi {
    param([string]$HostName)
    $body = Get-ScriptBody $winrmScript
    $addrList = ($AllowedRemoteAddress | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
    $wrapper = "& { $body } -AllowedRemoteAddress @($addrList)"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($wrapper))
    $cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc"
    if ($cmd.Length -gt 32000) { throw "Encoded WinRM step is $($cmd.Length) chars - over the Windows command-line limit." }

    $cim = New-CimSession -ComputerName $HostName -SessionOption (New-CimSessionOption -Protocol Dcom) @credArg -ErrorAction Stop
    try {
        $r = Invoke-CimMethod -CimSession $cim -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd } -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create returned $($r.ReturnValue) (2 = access denied)." }
    } finally {
        Remove-CimSession $cim -ErrorAction SilentlyContinue
    }
    # The process runs asynchronously on the endpoint - wait for the port to open.
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        if ((Test-Ports -HostName $HostName -Ports 5985)[5985]) { return $true }
    }
    $false
}

# --- Main loop ---------------------------------------------------------------
$report = [System.Collections.Generic.List[object]]::new()
$i = 0
foreach ($h in $targets) {
    $i++
    Write-Progress -Activity 'Endpoint setup' -Status $h -PercentComplete (100 * $i / $targets.Count)
    $row = [ordered]@{
        Host = $h; Resolved = ''; Port5985 = $false; Port135 = $false; Port445 = $false
        Method = ''; WinRM = ''; Collector = ''; Error = ''
    }
    try {
        try {
            $row.Resolved = (@([System.Net.Dns]::GetHostAddresses($h) | Where-Object AddressFamily -eq 'InterNetwork') | Select-Object -First 1).IPAddressToString
        } catch { throw "DNS: cannot resolve $h." }

        $ports = Test-Ports -HostName $h
        $row.Port5985 = $ports[5985]; $row.Port135 = $ports[135]; $row.Port445 = $ports[445]

        $winrmUp = $ports[5985]
        if ($winrmUp) {
            $row.Method = 'WinRM'
            $row.WinRM = 'Already open'
        } elseif ($EnableWinRM -and $ports[135]) {
            $row.Method = 'WMI/DCOM -> WinRM'
            if ($PSCmdlet.ShouldProcess($h, "Enable WinRM over WMI/DCOM (scoped to $($AllowedRemoteAddress -join ', '))")) {
                $winrmUp = Start-WinRMOverWmi -HostName $h
                $row.WinRM = if ($winrmUp) { 'Enabled' } else { "Started but 5985 not open after ${WaitSeconds}s - check $env:ProgramData\AD-Agent\endpoint-setup.log on the endpoint" }
            } else {
                $row.WinRM = 'WhatIf: would enable over WMI/DCOM'
            }
        } elseif ($ports[135]) {
            $row.Method = 'None'
            $row.WinRM = 'Closed (135 open - re-run with -EnableWinRM to turn it on over WMI)'
        } else {
            $row.Method = 'Blocked'
            $row.WinRM = 'Closed'
            throw 'Blocked: 5985 and 135 closed (host firewall or offline). Use GPO (New-WinRMGPO.ps1 / New-PushCollectorGPO.ps1) or Intune.'
        }

        if ($InstallCollector) {
            if (-not $winrmUp) {
                $row.Collector = 'Skipped - no WinRM'
            } elseif ($PSCmdlet.ShouldProcess($h, "Install push collector -> $ServerUrl")) {
                $s = New-PSSession -ComputerName $h @credArg -ErrorAction Stop
                try {
                    $out = Invoke-Command -Session $s -ErrorAction Stop -ArgumentList @(
                        (Get-ScriptBody $installerScript), (Get-Content $collectorScript -Raw), $ServerUrl, $Token
                    ) -ScriptBlock {
                        param($installerText, $collectorText, $url, $tok)
                        $stage = Join-Path $env:ProgramData 'AD-Agent\setup'
                        New-Item -ItemType Directory -Path $stage -Force | Out-Null
                        $src = Join-Path $stage 'Send-InventoryCheckin.ps1'
                        Set-Content -Path $src -Value $collectorText -Encoding UTF8
                        # Run the installer as a script block: no file on disk to be blocked by
                        # the endpoint's execution policy, same code as every other install path.
                        & ([scriptblock]::Create($installerText)) -ServerUrl $url -Token $tok -SourcePath $src *>&1 |
                            ForEach-Object { "$_" }
                    }
                    $text = ($out -join "`n")
                    $row.Collector = if ($text -match 'Check-in accepted') { 'Installed, check-in accepted' }
                                     elseif ($text -match 'Registered scheduled task') { 'Installed, check-in NOT confirmed - see collector.log on the endpoint' }
                                     else { 'Ran, no task registration seen' }
                    if ($row.Collector -notlike 'Installed, check-in accepted') {
                        $row.Error = (($out | Select-Object -Last 4) -join ' / ')
                    }
                } finally {
                    Remove-PSSession $s -ErrorAction SilentlyContinue
                }
            } else {
                $row.Collector = 'WhatIf: would install'
            }
        }
    } catch {
        $msg = $_.Exception.Message
        $row.Error = $msg + (Get-AuthHint $msg)
    }
    $report.Add([pscustomobject]$row)
    $color = if ($row.Error) { 'Yellow' } else { 'Green' }
    Write-Host ("{0,-20} {1,-18} WinRM: {2} | Collector: {3} {4}" -f $h, $row.Method, $row.WinRM, $row.Collector, $(if ($row.Error) { "| $($row.Error)" })) -ForegroundColor $color
}
Write-Progress -Activity 'Endpoint setup' -Completed

$report | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
$blocked = @($report | Where-Object Method -eq 'Blocked').Count
Write-Host ""
Write-Host "Report: $ReportPath"
Write-Host ("Targets: {0}  WinRM reachable/enabled: {1}  Collector installed: {2}  Blocked: {3}" -f `
    $report.Count,
    @($report | Where-Object { $_.WinRM -in @('Already open', 'Enabled') }).Count,
    @($report | Where-Object { $_.Collector -like 'Installed*' }).Count,
    $blocked)
if ($blocked) {
    Write-Host "Blocked hosts drop both WinRM and RPC at their own firewall - no remote tool reaches them." -ForegroundColor Yellow
    Write-Host "Cover them with the GPO (pulled from the DC) or Intune (pulled from the cloud) - see docs/WINRM-ENDPOINTS.md."
}

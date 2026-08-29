#Requires -Version 5.1
<#
.SYNOPSIS
    Push collector - runs ON an endpoint (laptop/workstation) and pushes its own
    inventory OUTBOUND to the AD-Agent jump server.

.DESCRIPTION
    The jump server's normal discovery reaches out to hosts over WinRM. That works
    for always-on, fixed-IP servers on approved VLANs; it does not work for roaming
    laptops, which is where every coverage gap has actually been:

      * they sit on VLANs the firewall won't allow inbound WinRM to
      * their IP changes with DHCP, so a scan target list goes stale immediately
      * they're asleep or off the network entirely when the scheduled scan runs

    This script inverts the direction. The endpoint collects its own inventory
    locally (no WinRM, no inbound rule, no credentials on the wire) and POSTs it to
    the jump server. Consequences worth knowing:

      * ONE outbound firewall rule (endpoint VLANs -> jump server) replaces inbound
        WinRM rules to every workstation VLAN
      * an IP change is irrelevant - the device identifies itself by hostname, and
        its current IP arrives as data
      * a laptop that was off for three weeks simply checks in when it comes back,
        and the Endpoints page shows it reappearing

    Deliberately self-contained: endpoints do NOT have the AD-Agent modules, so the
    chassis/software logic below is inlined rather than imported. It mirrors
    DCAnomalyAgent.SoftwareInventory.psm1's registry enumeration and chassis-type
    mapping so pushed data renders identically to WinRM-collected data.

    Deploy via GPO as a Scheduled Task running as SYSTEM - see
    Install\Deploy-PushCollector-GPO.md.

.PARAMETER ServerUrl
    Base URL of the AD-Agent web UI, e.g. 'https://jump-jeremy.amg.local'. The
    script appends /api/collector/checkin itself.
.PARAMETER Token
    Shared secret matching the jump server's COLLECTOR_TOKEN environment variable.
.PARAMETER SkipSoftware
    Presence-only check-in: hostname/IP/OS/user, no software enumeration. Much
    faster (no registry walk) - intended for the frequent "is it online" task, with
    a separate daily full run.
.PARAMETER TimeoutSec
    Per-attempt HTTP timeout.
.PARAMETER Retries
    Retry count for transient failures. A laptop that just woke up often has an
    adapter that isn't ready for a few seconds, so this retries with backoff rather
    than failing the whole check-in.
.PARAMETER LogPath
    Local log file on the endpoint. Defaults under ProgramData.

.EXAMPLE
    .\Send-InventoryCheckin.ps1 -ServerUrl 'https://jump-jeremy.amg.local' -Token 'xxxx'

.EXAMPLE
    .\Send-InventoryCheckin.ps1 -ServerUrl 'https://jump-jeremy.amg.local' -Token 'xxxx' -SkipSoftware
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [Parameter(Mandatory)][string]$Token,
    [switch]$SkipSoftware,
    [int]$TimeoutSec = 30,
    [int]$Retries = 3,
    [string]$LogPath = "$env:ProgramData\AD-Agent\collector.log"
)

$ErrorActionPreference = 'Stop'

function Write-CollectorLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $line
    try {
        $dir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
        # Keep the endpoint log from growing without bound - this runs every 30 min
        # on thousands of machines and nobody is out there rotating logs by hand.
        $f = Get-Item $LogPath -ErrorAction SilentlyContinue
        if ($f -and $f.Length -gt 1MB) {
            Set-Content -Path $LogPath -Value (Get-Content $LogPath -Tail 200) -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Chassis type codes, mirroring DCAnomalyAgent.SoftwareInventory.psm1.
$LaptopChassisTypes  = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
$DesktopChassisTypes = @(3, 4, 5, 6, 7, 13, 15, 16, 35, 36)
$ServerChassisTypes  = @(17, 23, 28)

function Get-LocalCategory {
    try {
        $codes = @((Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop).ChassisTypes)
        if ($codes | Where-Object { $_ -in $ServerChassisTypes })  { return 'Server' }
        if ($codes | Where-Object { $_ -in $LaptopChassisTypes })  { return 'Laptop' }
        if ($codes | Where-Object { $_ -in $DesktopChassisTypes }) { return 'Desktop' }
        return 'Workstation'
    } catch {
        return 'Workstation'
    }
}

function Get-PrimaryIPv4 {
    # The address on the interface that actually holds the default route - not the
    # first adapter found. On a laptop running Cloudflare WARP there are several
    # adapters up at once (physical NIC, WARP virtual, maybe a VM switch); the
    # default-route one is the address the jump server would realistically see.
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction Stop |
            Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
            Select-Object -First 1
        if ($cfg -and $cfg.IPv4Address) { return @($cfg.IPv4Address)[0].IPAddress }
    } catch { }
    try {
        return (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -First 1).IPAddress
    } catch { }
    return $null
}

function Get-ConsoleUser {
    # Runs as SYSTEM under the GPO scheduled task, so $env:USERNAME would be the
    # machine account - Win32_ComputerSystem.UserName is the actual signed-in user.
    try {
        $u = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($u) { return $u }
    } catch { }
    return $null
}

function Get-LocalSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = foreach ($path in $paths) {
        $arch = if ($path -match 'WOW6432Node') { '32-bit' } else { '64-bit' }
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
            ForEach-Object {
                [pscustomobject]@{
                    Name         = $_.DisplayName
                    Version      = "$($_.DisplayVersion)"
                    Publisher    = "$($_.Publisher)"
                    InstallDate  = "$($_.InstallDate)"
                    Architecture = $arch
                }
            }
    }
    # HKCU is deliberately NOT read here: as SYSTEM, HKCU is SYSTEM's own hive, not
    # the signed-in user's, so it would return nothing useful and imply per-user apps
    # were absent. Per-user installs are a known blind spot of running as SYSTEM.
    return @($items | Sort-Object Name, Version -Unique)
}

$hostname = $env:COMPUTERNAME
try {
    $fqdn = ([System.Net.Dns]::GetHostEntry($hostname)).HostName
} catch {
    $fqdn = $hostname
}

$os = try {
    $o = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    ("$($o.Caption) $($o.Version)").Trim()
} catch { $null }

$payload = [ordered]@{
    Name        = $fqdn
    IP          = Get-PrimaryIPv4
    AssetType   = Get-LocalCategory
    OS          = $os
    User        = Get-ConsoleUser
    CollectedAt = (Get-Date).ToUniversalTime().ToString('o')
    Software    = if ($SkipSoftware) { $null } else { Get-LocalSoftware }
}

$swCount = if ($payload.Software) { @($payload.Software).Count } else { 0 }
Write-CollectorLog "Collected: $fqdn ($($payload.IP)) $($payload.AssetType) - $swCount software item(s)."

$uri = "$($ServerUrl.TrimEnd('/'))/api/collector/checkin"
$body = $payload | ConvertTo-Json -Depth 4 -Compress

$sent = $false
for ($attempt = 1; $attempt -le $Retries; $attempt++) {
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
            -ContentType 'application/json' `
            -Headers @{ 'X-Collector-Token' = $Token } `
            -TimeoutSec $TimeoutSec
        Write-CollectorLog "Check-in accepted by $uri (key: $($resp.dedup_key))."
        $sent = $true
        break
    } catch {
        $msg = $_.Exception.Message
        if ($attempt -lt $Retries) {
            # Backoff: a laptop that just resumed often has an adapter that isn't
            # usable for a few seconds, and WARP may still be establishing its tunnel.
            $delay = [math]::Pow(2, $attempt) * 2
            Write-CollectorLog "Attempt $attempt/$Retries failed ($msg) - retrying in ${delay}s." 'WARN'
            Start-Sleep -Seconds $delay
        } else {
            Write-CollectorLog "Check-in FAILED after $Retries attempt(s): $msg" 'ERROR'
        }
    }
}

if (-not $sent) {
    # Non-zero exit so the Scheduled Task's LastTaskResult reflects the failure and
    # it's visible in Task Scheduler / any endpoint monitoring, rather than the task
    # silently reporting success while nothing ever reaches the jump server.
    exit 1
}
exit 0

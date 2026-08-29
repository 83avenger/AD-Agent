#Requires -Version 5.1
<#
.SYNOPSIS
    Pulls the WARP-enrolled device roster from Cloudflare Zero Trust and records it
    as check-ins, so laptops appear in the asset inventory without ever being
    reachable from this server.

.DESCRIPTION
    The WARP client is already installed on every laptop, so Cloudflare already
    knows which devices exist, what OS they run, who's signed in, and when each was
    last online. That is exactly the roster/presence data a jump-server-initiated
    scan cannot get for roaming devices - and it needs no new agent deployed.

    IMPORTANT - this does NOT collect installed software. Cloudflare has no
    software-inventory API; its device posture checks are assertions you define, not
    an enumeration. Devices synced from here will show up with OS, user, and
    last-seen but no software list until the push collector
    (Collector\Send-InventoryCheckin.ps1) reaches them. See
    Modules\DCAnomalyAgent.CloudflareDevices.psm1 for the full detail.

    Writes through the same /api/collector/checkin endpoint the push collector uses,
    so there is one tested write path into the asset store rather than two.

.PARAMETER ConfigPath
    settings.psd1. Reads Integrations.CloudflareZeroTrust (Enabled/ApiToken/AccountId).
.PARAMETER ServerUrl
    Base URL of the AD-Agent web UI. Defaults to localhost since this runs on the
    same server.
.PARAMETER Token
    COLLECTOR_TOKEN value. Defaults to the environment variable of that name.
.PARAMETER WhatIf
    Query Cloudflare and report what would be recorded, without writing anything.

.EXAMPLE
    .\Sync-CloudflareDevices.ps1

.EXAMPLE
    .\Sync-CloudflareDevices.ps1 -WhatIf
#>
[CmdletBinding(PositionalBinding = $false, SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath,
    [string]$ServerUrl = 'http://localhost:5000',
    [string]$Token = $env:COLLECTOR_TOKEN,
    [int]$TimeoutSec = 60
)

$ErrorActionPreference = 'Stop'

if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'Config\settings.psd1' }
if (-not (Test-Path $ConfigPath)) { throw "Config not found: $ConfigPath" }

Import-Module (Join-Path $PSScriptRoot 'Modules\DCAnomalyAgent.CloudflareDevices.psm1') -Force

$config = Import-PowerShellDataFile -Path $ConfigPath
$cf = $config.Integrations.CloudflareZeroTrust

if (-not $cf -or -not $cf.Enabled) {
    Write-Host "Cloudflare Zero Trust integration is disabled (Integrations.CloudflareZeroTrust.Enabled = `$false). Nothing to do."
    return
}
if (-not $cf.ApiToken -or -not $cf.AccountId) {
    throw "Integrations.CloudflareZeroTrust is enabled but ApiToken and/or AccountId is blank in $ConfigPath."
}

function Write-SyncLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try {
        $stateDir = Join-Path $PSScriptRoot 'State'
        if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
        Add-Content -Path (Join-Path $stateDir 'cloudflare-sync.log') -Value $line
    } catch { }
}

Write-SyncLog "Querying Cloudflare Zero Trust device roster..."
$devices = @(Get-CloudflareDevice -ApiToken $cf.ApiToken -AccountId $cf.AccountId -TimeoutSec $TimeoutSec)
Write-SyncLog "Cloudflare returned $($devices.Count) enrolled device(s)."

if (-not $devices) { return }

if ($WhatIfPreference) {
    Write-Host "`n-WhatIf: the following would be recorded (no writes performed):`n"
    $devices | Select-Object Name, IP, AssetType, OS, User, CollectedAt |
        Format-Table -AutoSize | Out-String -Width 300 | Write-Host
    return
}

if (-not $Token) {
    throw "No collector token available. Set the COLLECTOR_TOKEN environment variable (same value the web UI runs with) or pass -Token."
}

$uri = "$($ServerUrl.TrimEnd('/'))/api/collector/checkin"
$ok = 0
$failed = 0

foreach ($d in $devices) {
    $payload = [ordered]@{
        Name          = $d.Name
        IP            = $d.IP
        AssetType     = $d.AssetType
        OS            = $d.OS
        User          = $d.User
        CollectedAt   = $d.CollectedAt
        Source        = $d.Source
        CheckinSource = 'CloudflareWARP'
    }
    try {
        $null = Invoke-RestMethod -Uri $uri -Method Post -TimeoutSec $TimeoutSec `
            -Body ($payload | ConvertTo-Json -Depth 3 -Compress) `
            -ContentType 'application/json' `
            -Headers @{ 'X-Collector-Token' = $Token }
        $ok++
    } catch {
        $failed++
        Write-SyncLog "Failed to record '$($d.Name)': $($_.Exception.Message)" 'WARN'
    }
}

Write-SyncLog "Sync complete: $ok recorded, $failed failed."
Write-SyncLog "Note: Cloudflare supplies device identity/presence only - installed software still comes from the push collector or WinRM."

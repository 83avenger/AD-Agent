#Requires -Version 5.1
<#
.SYNOPSIS
    Self-healing watchdog for the AD-Agent web UI. Polls /healthz and restarts
    the AD-Agent-WebUI Scheduled Task if the process is unreachable, hung, or
    reporting a hard failure.

.DESCRIPTION
    Register-WebUIStartup.ps1's Scheduled Task already restarts the web UI if
    the process itself exits (-RestartCount/-RestartInterval), but that only
    catches a clean crash - it does nothing if the process is still alive but
    wedged (deadlocked, out of worker threads, DB file locked) and simply
    stops answering requests. This script is the piece that catches that case:
    it actually calls /healthz over HTTP, so a hang looks the same as a crash
    to it, and both get the same remediation - restart the task.

    Run this on a short interval (5 minutes recommended) via its own
    Scheduled Task - see the -Register switch below, or wire it up yourself
    with Register-ScheduledTask.

.PARAMETER Url
    The /healthz URL to poll.
.PARAMETER TaskName
    Name of the web UI Scheduled Task to restart on failure. Must match
    Register-WebUIStartup.ps1's -TaskName.
.PARAMETER TimeoutSec
    How long to wait for /healthz to respond before treating it as down.
.PARAMETER FailureThreshold
    Consecutive failed polls required before restarting - avoids restarting
    on a single transient blip (e.g. the process mid-restart already).
.PARAMETER LogPath
    Where to append watchdog activity. Defaults to State\watchdog.log next to
    the rest of AD-Agent's state.
.PARAMETER Register
    Instead of running a check, register *this script* as its own Scheduled
    Task on a recurring interval, then exit.
.PARAMETER IntervalMinutes
    Only used with -Register: how often the watchdog task itself runs.
.PARAMETER GmsaAccount
    Only used with -Register: identity to run the watchdog task under. Doesn't
    need to be the gMSA - restarting a Scheduled Task only needs local admin,
    not domain access - but defaults to the same gMSA for consistency.

.EXAMPLE
    .\Watch-WebUIHealth.ps1
    Runs a single health check/remediation pass - what the watchdog's own
    Scheduled Task actually invokes every few minutes.

.EXAMPLE
    .\Watch-WebUIHealth.ps1 -Register -GmsaAccount 'AMG\svc-discoverAgt$'
    One-time setup: registers this script to run every 5 minutes.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Url = 'http://localhost:5000/healthz',
    [string]$TaskName = 'AD-Agent-WebUI',
    [int]$TimeoutSec = 10,
    [int]$FailureThreshold = 2,
    [string]$LogPath,
    [switch]$Register,
    [int]$IntervalMinutes = 5,
    [string]$GmsaAccount = 'CONTOSO\svc-discoverAgt$'
)

if (-not $LogPath) {
    $LogPath = Join-Path (Resolve-Path "$PSScriptRoot\..\State") 'watchdog.log'
}

function Write-WatchdogLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try {
        $dir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line
    } catch {
        Write-Warning "Could not write to watchdog log '$LogPath': $_"
    }
}

if ($Register) {
    $watchdogScript = $MyInvocation.MyCommand.Path
    $psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { (Get-Command pwsh).Source } else { (Get-Command powershell).Source }

    $action  = New-ScheduledTaskAction -Execute $psExe `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$watchdogScript`" -Url `"$Url`" -TaskName `"$TaskName`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration ([TimeSpan]::MaxValue)
    $principal = New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    $watchdogTaskName = "$TaskName-Watchdog"
    $existing = Get-ScheduledTask -TaskName $watchdogTaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Task '$watchdogTaskName' already exists - unregistering old copy before re-registering."
        Unregister-ScheduledTask -TaskName $watchdogTaskName -Confirm:$false
    }
    Register-ScheduledTask -TaskName $watchdogTaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings `
        -Description "Polls $Url every $IntervalMinutes minute(s) and restarts '$TaskName' if it's down or hung."

    Write-Host "`nWatchdog task '$watchdogTaskName' registered - runs every $IntervalMinutes minute(s)."
    Write-Host "Start it immediately: Start-ScheduledTask -TaskName '$watchdogTaskName'"
    return
}

$stateFile = Join-Path (Split-Path -Path $LogPath -Parent) 'watchdog-state.json'
$consecutiveFailures = 0
if (Test-Path $stateFile) {
    try {
        $prior = Get-Content $stateFile -Raw | ConvertFrom-Json
        $consecutiveFailures = [int]$prior.ConsecutiveFailures
    } catch {
        $consecutiveFailures = 0
    }
}

$healthy = $false
$detail  = $null
try {
    $resp = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing
    $body = $resp.Content | ConvertFrom-Json
    if ($resp.StatusCode -eq 200 -and $body.status -ne 'fail') {
        $healthy = $true
        $detail  = "status=$($body.status)"
    } else {
        $detail = "HTTP $($resp.StatusCode), status=$($body.status)"
    }
} catch {
    $detail = "unreachable: $($_.Exception.Message)"
}

if ($healthy) {
    if ($consecutiveFailures -gt 0) {
        Write-WatchdogLog "Health check recovered ($detail) after $consecutiveFailures failed poll(s)."
    } else {
        Write-WatchdogLog "Health check OK ($detail)."
    }
    $consecutiveFailures = 0
} else {
    $consecutiveFailures++
    Write-WatchdogLog "Health check FAILED ($detail) - $consecutiveFailures/$FailureThreshold consecutive failure(s)." -Level 'WARN'

    if ($consecutiveFailures -ge $FailureThreshold) {
        Write-WatchdogLog "Failure threshold reached - restarting Scheduled Task '$TaskName'." -Level 'ERROR'
        try {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            if ($task.State -eq 'Running') {
                Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
            }
            Start-ScheduledTask -TaskName $TaskName
            Write-WatchdogLog "Restart command issued for '$TaskName'."
        } catch {
            Write-WatchdogLog "Failed to restart '$TaskName': $_" -Level 'ERROR'
        }
        $consecutiveFailures = 0
    }
}

@{ ConsecutiveFailures = $consecutiveFailures; LastCheck = (Get-Date -Format 'o') } |
    ConvertTo-Json | Set-Content -Path $stateFile

#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the push collector locally on ONE machine - for non-domain-joined
    servers, DMZ hosts, and anything else GPO can't reach.

.DESCRIPTION
    Deploy-PushCollector-GPO.md covers domain-joined endpoints, where a GPO does the
    work. Non-domain-joined servers have no GPO, no Kerberos and no gMSA, so nothing
    the jump server initiates can authenticate to them - Get-ADComputer never sees
    them, and WinRM has no domain identity to accept.

    The push collector doesn't care. It runs locally as SYSTEM and authenticates
    OUTBOUND with the shared token, so domain membership is irrelevant to it. The
    only thing missing was a way to install it without GPO - that's this script.

    Run it once on each non-domain host (or bake it into your build/golden image,
    or drive it from whatever config management you already have).

    WHAT THIS DOES AND DOESN'T COVER: it gives you discovery, presence/last-seen,
    OS, device category and full installed-software inventory - the same data a
    domain-joined endpoint pushes. It does NOT give you compliance or certificate
    scanning, because those run FROM the jump server over WinRM and still have no
    way to authenticate to a non-domain host. See COVERAGE-NON-DOMAIN.md.

.PARAMETER ServerUrl
    Base URL of the AD-Agent web UI, e.g. 'https://jump-jeremy.amg.local'.
.PARAMETER Token
    Value of the jump server's COLLECTOR_TOKEN.
.PARAMETER InstallPath
    Where the collector script is copied to.
.PARAMETER IntervalMinutes
    Presence check-in interval.
.PARAMETER FullInventoryAt
    Time of day for the daily full (software) inventory.
.PARAMETER SourcePath
    Path to Send-InventoryCheckin.ps1. Defaults to the copy next to this script.
.PARAMETER Uninstall
    Remove the tasks and installed files instead.

.EXAMPLE
    .\Install-PushCollector.ps1 -ServerUrl 'https://jump-jeremy.amg.local' -Token '<TOKEN>'

.EXAMPLE
    .\Install-PushCollector.ps1 -Uninstall
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$ServerUrl,
    [string]$Token,
    [string]$InstallPath = "$env:ProgramData\AD-Agent",
    [int]$IntervalMinutes = 30,
    [string]$FullInventoryAt = '13:00',
    [string]$SourcePath,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$presenceTask = 'AD-Agent Check-in'
$fullTask     = 'AD-Agent Full Inventory'

if ($Uninstall) {
    foreach ($name in @($presenceTask, $fullTask)) {
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
            Write-Host "Removed scheduled task '$name'."
        }
    }
    if (Test-Path $InstallPath) {
        # Leave collector.log behind deliberately - it's the only local record of what
        # this host reported, and is useful when troubleshooting after a removal.
        Remove-Item (Join-Path $InstallPath 'Send-InventoryCheckin.ps1') -Force -ErrorAction SilentlyContinue
        Write-Host "Removed collector script from $InstallPath (log retained)."
    }
    Write-Host "Uninstalled. This host will stop checking in; its existing asset record on the jump server is left intact."
    return
}

if (-not $ServerUrl) { throw "-ServerUrl is required (e.g. 'https://jump-jeremy.amg.local')." }
if (-not $Token)     { throw "-Token is required - use the same value as the jump server's COLLECTOR_TOKEN." }

if (-not $SourcePath) { $SourcePath = Join-Path $PSScriptRoot 'Send-InventoryCheckin.ps1' }
if (-not (Test-Path $SourcePath)) {
    throw "Collector script not found at '$SourcePath'. Copy Send-InventoryCheckin.ps1 alongside this installer, or pass -SourcePath."
}

if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
$target = Join-Path $InstallPath 'Send-InventoryCheckin.ps1'
Copy-Item -Path $SourcePath -Destination $target -Force
Write-Host "Installed collector to $target"

# SYSTEM works identically on a workgroup machine - no domain account needed anywhere
# in this path, which is the whole reason the collector suits non-domain hosts.
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

function Register-CollectorTask {
    param([string]$Name, [string]$Arguments, [object[]]$Triggers, [string]$Description)

    if (Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $Arguments
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $Triggers `
        -Principal $principal -Settings $settings -Description $Description -ErrorAction Stop | Out-Null
    Write-Host "Registered scheduled task '$Name'."
}

$baseArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$target`" -ServerUrl `"$ServerUrl`" -Token `"$Token`""

# Presence: repeat indefinitely. [TimeSpan]::MaxValue is NOT usable here - it doesn't fit
# the task XML duration schema and registration fails; an empty Duration alongside a set
# interval is how Task Scheduler expresses "forever".
$presenceTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(2) `
    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$presenceTrigger.Repetition.Duration = ""
$presenceTrigger.Repetition.StopAtDurationEnd = $false

# Also fire at startup so a server that was rebooted or powered off reports in promptly
# rather than waiting out the interval.
$startupTrigger = New-ScheduledTaskTrigger -AtStartup

Register-CollectorTask -Name $presenceTask `
    -Arguments "$baseArgs -SkipSoftware" `
    -Triggers @($presenceTrigger, $startupTrigger) `
    -Description "AD-Agent presence check-in every $IntervalMinutes minutes (no software enumeration)."

Register-CollectorTask -Name $fullTask `
    -Arguments $baseArgs `
    -Triggers @((New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($FullInventoryAt)))) `
    -Description 'AD-Agent full inventory including installed software, once daily.'

Write-Host "`nRunning one check-in now to verify..."
Start-ScheduledTask -TaskName $presenceTask
Start-Sleep -Seconds 12

$logPath = Join-Path $InstallPath 'collector.log'
if (Test-Path $logPath) {
    Write-Host "`n--- collector.log (last 10 lines) ---"
    Get-Content $logPath -Tail 10
    Write-Host "-------------------------------------"
    if ((Get-Content $logPath -Tail 10) -match 'Check-in accepted') {
        Write-Host "`nSUCCESS - this host is now reporting to $ServerUrl. It should appear on the Endpoints page." -ForegroundColor Green
    } else {
        Write-Warning "The task ran but no acceptance was logged. Check the log above - common causes: wrong token, the jump server's COLLECTOR_TOKEN not set, or no outbound route to $ServerUrl."
    }
} else {
    Write-Warning "No log written yet at $logPath. Task Scheduler may still be starting it - re-check in a minute with: Get-Content '$logPath' -Tail 10"
}

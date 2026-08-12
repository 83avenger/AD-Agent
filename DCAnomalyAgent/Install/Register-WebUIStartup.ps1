#Requires -Version 5.1
<#
.SYNOPSIS
    Registers a Scheduled Task that starts the AD-Agent web UI at system startup, running
    under the gMSA - so it survives reboots/RDP logoffs and, critically, so every WinRM
    call the web UI makes (discovery, software inventory, WinRM Test, scans triggered from
    the browser) uses the SAME identity as the scan Scheduled Tasks registered by
    Register-ScheduledTask.ps1.

.DESCRIPTION
    Fixes a real problem: running "python.exe start.py" interactively in an RDP session
    means the web UI's WinRM calls authenticate as whoever is logged into that session -
    not the gMSA - so a host can work fine when a domain admin tests it manually
    (Invoke-Command from their own session) yet still fail with Access Denied when the
    exact same check runs through the web UI, because the web UI process was a different
    identity the whole time. Running it as this Scheduled Task removes that inconsistency.

    This is a Scheduled Task, not a literal Windows Service - Windows Task Scheduler is
    the standard, no-extra-software way to run a gMSA-driven background process
    continuously (same mechanism already used for the scan tasks), and avoids introducing
    a new download (e.g. NSSM) that could hit the same EDR/installer blocking already
    worked around once for Python itself.

.PARAMETER GmsaAccount
    The gMSA identity to run under. Must already be installed on this server
    (Install-ADServiceAccount) and granted "Log on as a batch job" - see
    Register-ScheduledTask.ps1's header notes for the one-time AD-side setup.
.PARAMETER PythonPath
    Path to the Python executable used to run the web UI (the same one used to launch it
    interactively today, e.g. the embeddable-Python workaround path if EDR blocked the MSI).
.PARAMETER WebAppPath
    Path to WebApp\start.py. Defaults to the WebApp folder next to this script's DCAnomalyAgent.
.PARAMETER BindHost
    Interface to bind to. 0.0.0.0 so it's reachable from other machines, not just localhost.
.PARAMETER Port
    Port for the web UI (must match whatever firewall rule was requested for it).

.EXAMPLE
    .\Register-WebUIStartup.ps1 -GmsaAccount 'AMG\svc-discoverAgt$' -PythonPath 'C:\Apps\Python312\python.exe'
#>
[CmdletBinding()]
param(
    [string]$GmsaAccount = 'CONTOSO\svc-discoverAgt$',
    [Parameter(Mandatory)][string]$PythonPath,
    [string]$WebAppPath = (Resolve-Path "$PSScriptRoot\..\..\WebApp\start.py").Path,
    [string]$BindHost = '0.0.0.0',
    [int]$Port = 5000,
    [string]$TaskName = 'AD-Agent-WebUI'
)

if (-not (Test-Path $PythonPath)) {
    throw "PythonPath '$PythonPath' does not exist. Pass the exact python.exe used to run the web UI today."
}
if (-not (Test-Path $WebAppPath)) {
    throw "WebAppPath '$WebAppPath' does not exist. Pass -WebAppPath explicitly if start.py isn't in the default location."
}
$webAppDir = Split-Path -Path $WebAppPath -Parent

$action = New-ScheduledTaskAction -Execute $PythonPath `
    -Argument "start.py --prod --host $BindHost --port $Port" `
    -WorkingDirectory $webAppDir

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel Highest

# ExecutionTimeLimit defaults to a few days if unset, and Register-ScheduledTask.ps1's scan
# tasks intentionally cap at 1 hour - that would be fatal here since this task is meant to
# run continuously. Explicitly unlimited, plus auto-restart if the process ever dies.
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Task '$TaskName' already exists - unregistering old copy before re-registering."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description "Runs the AD-Agent web UI continuously under the gMSA identity, so its WinRM calls match the scan Scheduled Tasks."

Write-Host "`nTask '$TaskName' registered:"
Write-Host "  Runs as:  $GmsaAccount"
Write-Host "  Trigger:  At system startup, whether anyone is logged on or not"
Write-Host "  Command:  $PythonPath start.py --prod --host $BindHost --port $Port"
Write-Host "  Working:  $webAppDir"
Write-Host "`nIf a web UI is currently running interactively in an RDP session, stop it (Ctrl+C) now -"
Write-Host "otherwise both copies will try to bind port $Port and the new one will fail to start."
Write-Host "`nStart it immediately without waiting for a reboot:"
Write-Host "  Start-ScheduledTask -TaskName '$TaskName'"
Write-Host "`nCheck it's actually running:"
Write-Host "  Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"

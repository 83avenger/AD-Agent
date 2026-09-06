#Requires -Version 5.1
<#
.SYNOPSIS
    Reports whether each AD-Agent scheduled task actually ran, what it returned, and what
    its log says - the questions Task Scheduler's own UI answers badly or not at all.

.DESCRIPTION
    Task Scheduler shows "Running" for a task that finished hours ago but left an orphaned
    process, shows "Ready" for one that has never run once, and reports last-run results as
    raw hex that means nothing without a lookup. This pulls the same information into one
    readable table, translates the result codes, flags the states that actually indicate a
    problem, and shows the tail of the log each task writes - which is where the real
    reason for a bad run lives.

    Read-only: it inspects tasks and reads logs. It never starts, stops or changes a task.

.PARAMETER TaskPath
    Scheduled Task folder to look in. Defaults to the root folder, where the installer
    registers everything.

.PARAMETER Name
    Only report on tasks matching this wildcard (e.g. '*Discovery*').

.PARAMETER LogLines
    How many trailing log lines to show per task. Default 15, 0 to skip logs entirely.

.EXAMPLE
    .\Test-ScheduledTasks.ps1
    Full report on every AD-Agent task.

.EXAMPLE
    .\Test-ScheduledTasks.ps1 -Name '*Discovery*' -LogLines 40
    Just discovery, with more log context.
#>
[CmdletBinding()]
param(
    [string]$TaskPath = '\',
    [string]$Name = '*',
    [int]$LogLines = 15
)

$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $PSScriptRoot 'State'

# Task Scheduler reports last-run results as an unsigned 32-bit code. These are the ones
# that actually come up for these tasks; anything else is printed raw.
$resultCodes = @{
    0          = 'Success'
    1          = 'Incorrect function / the script threw'
    2          = 'File not found - check the -File path in the action'
    10         = 'The environment is incorrect'
    267009     = 'Task is currently running'
    267011     = 'Task has not yet run'
    267014     = 'Task was terminated by the user or by its execution time limit'
    2147750687 = 'An instance is already running (and the task is set to not run a new one)'
    2147942401 = 'Access denied - the run-as account cannot read the script or its folder'
    2147942402 = 'The system cannot find the file specified'
    2147943645 = 'The service is not available (task set to run only when the user is logged on)'
    3221225786 = 'The application terminated as a result of CTRL+C'
}

# Which log each task writes, so the report can show the real failure reason rather than
# just a return code. Matched on the task name.
$logForTask = @{
    'Discovery'         = 'discovery.log'
    'Certificates'      = 'scan.log'
    'Compliance'        = 'scan.log'
    'SoftwareInventory' = 'scan.log'
    'ZeroDay'           = 'scan.log'
    'Scan'              = 'scan.log'
    'Watchdog'          = 'watchdog.log'
}

$tasks = @(Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskName -like 'DCAnomalyAgent*' -or $_.TaskName -like 'AD-Agent*' } |
    Where-Object { $_.TaskName -like $Name } |
    Sort-Object TaskName)

if (-not $tasks) {
    Write-Warning "No AD-Agent scheduled tasks found in '$TaskPath' matching '$Name'. If the installer ran, check the folder in Task Scheduler - tasks may have been registered somewhere other than the root."
    return
}

Write-Host ''
Write-Host "AD-Agent scheduled tasks ($($tasks.Count))" -ForegroundColor Cyan
Write-Host ('=' * 78)

$problems = @()

foreach ($t in $tasks) {
    $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath
    $code = [uint32]$info.LastTaskResult
    $meaning = if ($resultCodes.ContainsKey([int64]$code)) { $resultCodes[[int64]$code] } else { "Unrecognised code 0x{0:X8}" -f $code }

    # "Never run" is the single most common cause of "the task is there but nothing
    # happens", and Task Scheduler displays it as an innocuous-looking date rather than
    # calling it out.
    $neverRan = (-not $info.LastRunTime) -or ($info.LastRunTime -lt (Get-Date '2000-01-01'))

    Write-Host ''
    Write-Host $t.TaskName -ForegroundColor White
    Write-Host ("  State          : {0}" -f $t.State)
    Write-Host ("  Last run       : {0}" -f $(if ($neverRan) { 'NEVER' } else { $info.LastRunTime }))
    Write-Host ("  Last result    : {0} ({1})" -f $code, $meaning)
    Write-Host ("  Next run       : {0}" -f $(if ($info.NextRunTime) { $info.NextRunTime } else { 'not scheduled' }))
    Write-Host ("  Missed runs    : {0}" -f $info.NumberOfMissedRuns)
    Write-Host ("  Run as         : {0}" -f $t.Principal.UserId)

    $action = @($t.Actions)[0]
    if ($action.Execute) {
        Write-Host ("  Action         : {0} {1}" -f $action.Execute, $action.Arguments)
        # A task pointing at a script that no longer exists is silent in the UI - it just
        # returns 2 forever. Extract the -File argument and check it.
        if ($action.Arguments -match '-File\s+"?([^"]+\.ps1)"?') {
            $scriptPath = $Matches[1]
            if (-not (Test-Path $scriptPath)) {
                Write-Host "  SCRIPT MISSING : $scriptPath" -ForegroundColor Red
                $problems += "$($t.TaskName): its script does not exist at $scriptPath"
            }
        }
    }

    if ($t.State -eq 'Disabled') {
        Write-Host '  -> DISABLED: this task will never fire until it is enabled.' -ForegroundColor Yellow
        $problems += "$($t.TaskName): disabled"
    }
    if ($neverRan -and $t.State -ne 'Disabled') {
        Write-Host '  -> Has never run.' -ForegroundColor Yellow
        $problems += "$($t.TaskName): has never run"
    }
    if ($t.State -eq 'Running') {
        $runningFor = if (-not $neverRan) { (Get-Date) - $info.LastRunTime } else { $null }
        if ($runningFor -and $runningFor.TotalHours -ge 2) {
            Write-Host ("  -> Running for {0:N1} hours - almost certainly stuck, not working." -f $runningFor.TotalHours) -ForegroundColor Red
            $problems += "$($t.TaskName): running for $([math]::Round($runningFor.TotalHours,1))h - likely hung"
        } else {
            Write-Host '  -> Currently running.' -ForegroundColor Cyan
        }
    }
    if ($code -ne 0 -and $code -ne 267009 -and $code -ne 267011) {
        Write-Host "  -> Last run did not succeed." -ForegroundColor Red
        $problems += "$($t.TaskName): last result $code ($meaning)"
    }

    if ($LogLines -gt 0) {
        $logName = $null
        foreach ($k in $logForTask.Keys) { if ($t.TaskName -like "*$k*") { $logName = $logForTask[$k]; break } }
        if ($logName) {
            $logPath = Join-Path $stateDir $logName
            if (Test-Path $logPath) {
                $age = (Get-Date) - (Get-Item $logPath).LastWriteTime
                Write-Host ("  Log            : {0} (last written {1:N1}h ago)" -f $logPath, $age.TotalHours)
                Write-Host "  --- last $LogLines line(s) ---" -ForegroundColor DarkGray
                Get-Content -Path $logPath -Tail $LogLines | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
            } else {
                Write-Host "  Log            : $logPath (does not exist - the task has produced no output at all)" -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ''
Write-Host ('=' * 78)
if ($problems) {
    Write-Host "Issues found ($($problems.Count)):" -ForegroundColor Yellow
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'Common fixes:'
    Write-Host '  Disabled task      : Enable-ScheduledTask -TaskName "<name>"'
    Write-Host '  Run one now        : Start-ScheduledTask -TaskName "<name>"   (then re-run this script)'
    Write-Host '  Stuck "Running"    : Stop-ScheduledTask -TaskName "<name>"'
    Write-Host '  Access denied (0x80070005) : the run-as account needs Read+Execute on the install folder,'
    Write-Host '                     and "Log on as a batch job" in local policy.'
    Write-Host '  Full history       : Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational -MaxEvents 50 |'
    Write-Host '                       Where-Object Message -like "*<name>*" | Format-List TimeCreated, Id, Message'
    Write-Host '                     (enable it first if empty: wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true)'
} else {
    Write-Host 'No issues found - every task is enabled, has run, and last returned success.' -ForegroundColor Green
}
Write-Host ''

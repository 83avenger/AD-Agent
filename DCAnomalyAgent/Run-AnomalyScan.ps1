#Requires -Version 5.1
<#
.SYNOPSIS
    Scans configured Domain Controllers for security anomalies and reports findings
    to Microsoft Teams and SharePoint.
.PARAMETER DryRun
    Skip Teams/SharePoint writes; print the anomaly list to the console instead.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\Config\settings.psd1",
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Collectors.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Detectors.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Baseline.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Reporting.psm1" -Force

$config = Import-PowerShellDataFile -Path $ConfigPath

function Write-ScanLog {
    param([string]$Message)
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $Message
    Write-Host $line
    $logDir = Split-Path -Path $config.LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $config.LogPath -Value $line
}

$endTime = Get-Date
$startTime = $endTime.AddHours(-$config.LookbackHours)
$allAnomalies = @()
$allSuccessfulLogons = @()

$baseline = Get-Baseline -StatePath $config.Baseline.StatePath
$knownGpoVersions = @{}
if ($baseline.ContainsKey('__gpoVersions')) {
    foreach ($entry in $baseline['__gpoVersions']) { $knownGpoVersions[$entry.Id] = $entry.Version }
}

foreach ($dc in $config.DomainControllers) {
    Write-ScanLog "Scanning $dc for window $startTime - $endTime"

    try {
        $failedLogons = Get-FailedLogonEvents -ComputerName $dc -StartTime $startTime -EndTime $endTime
        $allAnomalies += Find-FailedLogonAnomalies -FailedLogonEvents $failedLogons -BurstThreshold $config.FailedLogonBurstThreshold

        $successLogons = Get-SuccessfulLogonEvents -ComputerName $dc -StartTime $startTime -EndTime $endTime
        $allSuccessfulLogons += $successLogons

        $groupChanges = Get-PrivilegedGroupChangeEvents -ComputerName $dc -StartTime $startTime -EndTime $endTime -PrivilegedGroups $config.PrivilegedGroups
        $allAnomalies += Find-PrivilegedGroupAnomalies -GroupChangeEvents $groupChanges

        $newPrivAccounts = Get-NewPrivilegedAccounts -ComputerName $dc -StartTime $startTime -EndTime $endTime `
            -PrivilegedGroups $config.PrivilegedGroups -WindowHours $config.NewAccountToPrivilegedGroupWindowHours
        $allAnomalies += Find-NewPrivilegedAccountAnomalies -NewPrivilegedAccounts $newPrivAccounts

        $gpoResult = Get-GpoChangeEvents -ComputerName $dc -StartTime $startTime -EndTime $endTime -KnownGpoVersions $knownGpoVersions
        $allAnomalies += Find-GpoAnomalies -GpoResult $gpoResult
        foreach ($v in $gpoResult.CurrentVersions) { $knownGpoVersions[$v.Id] = $v.Version }
    } catch {
        Write-ScanLog "ERROR scanning $dc : $_"
    }
}

# Baseline (UEBA-lite) deviations
$baselineDeviations = Update-Baseline -Baseline $baseline -LogonEvents $allSuccessfulLogons `
    -MinObservationsBeforeFlagging $config.Baseline.MinObservationsBeforeFlagging
$allAnomalies += $baselineDeviations

$baseline['__gpoVersions'] = $knownGpoVersions.GetEnumerator() | ForEach-Object { @{ Id = $_.Key; Version = $_.Value } }
Save-Baseline -Baseline $baseline -StatePath $config.Baseline.StatePath

Write-ScanLog "Scan complete: $($allAnomalies.Count) anomaly/anomalies found."

if ($DryRun) {
    $allAnomalies | Format-Table -AutoSize
    return
}

if ($config.Reporting.Teams.Enabled) {
    Send-TeamsAlert -WebhookUrl $config.Reporting.Teams.WebhookUrl -Anomalies $allAnomalies
}

if ($config.Reporting.SharePoint.Enabled) {
    $itemsToLog = if ($config.Reporting.SharePoint.LogEveryScan) { $allAnomalies } else { $allAnomalies }
    Write-SharePointListItem -SharePointConfig $config.Reporting.SharePoint -Anomalies $itemsToLog
}

return $allAnomalies

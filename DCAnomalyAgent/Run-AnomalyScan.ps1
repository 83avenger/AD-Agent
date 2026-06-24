#Requires -Version 5.1
<#
.SYNOPSIS
    Scans configured Domain Controllers for security anomalies and (optionally) compliance
    gaps against NIST CSF, ISO 27001, and CIS Benchmarks. Reports to Teams and SharePoint.
.PARAMETER DryRun
    Skip Teams/SharePoint writes; print all findings to the console instead.
.PARAMETER ComplianceScan
    Run the compliance framework scan in addition to the regular anomaly scan.
    By default only the anomaly scan runs (suitable for the 3x/day schedule).
    Run compliance scan less frequently (e.g. daily/weekly) to reduce DC load.
.PARAMETER FrameworkFilter
    Optionally limit compliance check to one or more frameworks: CIS, NIST, ISO.
.PARAMETER SeverityFilter
    Optionally limit compliance check to specific severity levels: Critical, High, Medium, Low.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\Config\settings.psd1",
    [switch]$DryRun,
    [switch]$ComplianceScan,
    [string[]]$FrameworkFilter,
    [ValidateSet('Critical','High','Medium','Low')][string[]]$SeverityFilter
)

$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Collectors.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Detectors.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Baseline.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Reporting.psm1" -Force
if ($ComplianceScan) {
    Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Compliance.psm1" -Force
}

$config = Import-PowerShellDataFile -Path $ConfigPath
$scanTime = Get-Date

function Write-ScanLog {
    param([string]$Message)
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $Message
    Write-Host $line
    $logDir = Split-Path -Path $config.LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $config.LogPath -Value $line
}

# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY SCAN
# ─────────────────────────────────────────────────────────────────────────────
$endTime = $scanTime
$startTime = $endTime.AddHours(-$config.LookbackHours)
$allAnomalies = @()
$allSuccessfulLogons = @()

$baseline = Get-Baseline -StatePath $config.Baseline.StatePath
$knownGpoVersions = @{}
if ($baseline.ContainsKey('__gpoVersions')) {
    foreach ($entry in $baseline['__gpoVersions']) { $knownGpoVersions[$entry.Id] = $entry.Version }
}

foreach ($dc in $config.DomainControllers) {
    Write-ScanLog "Anomaly scan: $dc ($startTime — $endTime)"

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
        Write-ScanLog "ERROR (anomaly) on $dc : $_"
    }
}

$baselineDeviations = Update-Baseline -Baseline $baseline -LogonEvents $allSuccessfulLogons `
    -MinObservationsBeforeFlagging $config.Baseline.MinObservationsBeforeFlagging
$allAnomalies += $baselineDeviations

$baseline['__gpoVersions'] = $knownGpoVersions.GetEnumerator() | ForEach-Object { @{ Id = $_.Key; Version = $_.Value } }
Save-Baseline -Baseline $baseline -StatePath $config.Baseline.StatePath

Write-ScanLog "Anomaly scan complete: $($allAnomalies.Count) finding(s)."

if ($DryRun) {
    Write-Host "`n=== ANOMALIES ==="
    $allAnomalies | Format-Table -AutoSize
}

if (-not $DryRun -and $config.Reporting.Teams.Enabled -and $allAnomalies.Count -gt 0) {
    Send-TeamsAlert -WebhookUrl $config.Reporting.Teams.WebhookUrl -Anomalies $allAnomalies
}

if (-not $DryRun -and $config.Reporting.SharePoint.Enabled -and $allAnomalies.Count -gt 0) {
    Write-SharePointListItem -SharePointConfig $config.Reporting.SharePoint -Anomalies $allAnomalies
}

# ─────────────────────────────────────────────────────────────────────────────
# COMPLIANCE SCAN
# ─────────────────────────────────────────────────────────────────────────────
if ($ComplianceScan -and $config.Compliance.Enabled) {
    Write-ScanLog "Starting compliance scan..."

    $effectiveFrameworkFilter = if ($FrameworkFilter) { $FrameworkFilter } else { $config.Compliance.FrameworkFilter }
    $effectiveSeverityFilter  = if ($SeverityFilter)  { $SeverityFilter  } else { $config.Compliance.SeverityFilter  }

    $getControlsParams = @{ FrameworkPath = $config.Compliance.FrameworkPath }
    if ($effectiveFrameworkFilter) { $getControlsParams['FrameworkFilter'] = $effectiveFrameworkFilter }
    if ($effectiveSeverityFilter)  { $getControlsParams['SeverityFilter']  = $effectiveSeverityFilter  }

    $controls = Get-ComplianceControls @getControlsParams
    Write-ScanLog "Running $($controls.Count) compliance control(s) across $($config.DomainControllers.Count) DC(s)..."

    $scanResults = Invoke-ComplianceScan -DomainControllers $config.DomainControllers -Controls $controls
    $gaps        = Get-ComplianceGaps -ScanResults $scanResults
    $summary     = Get-ComplianceSummary -ScanResults $scanResults

    Write-ScanLog "Compliance scan complete: $($summary.Passed)/$($summary.TotalControls) passing ($($summary.ScorePct)%). Gaps: $($gaps.Count)."

    # Save markdown report to disk (always)
    $reportDir = Split-Path -Path $config.Compliance.ReportOutputPath -Parent
    if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
    Format-ComplianceReport -Summary $summary -Gaps $gaps -ScanTime $scanTime |
        Set-Content -Path $config.Compliance.ReportOutputPath -Encoding UTF8
    Write-ScanLog "Compliance report saved: $($config.Compliance.ReportOutputPath)"

    if ($DryRun) {
        Write-Host "`n=== COMPLIANCE GAPS ==="
        $gaps | Select-Object ControlId, Severity, Title, ComputerName, Actual | Format-Table -AutoSize
        Write-Host "`nOverall score: $($summary.ScorePct)%  ($($summary.Passed)/$($summary.TotalControls) controls passing)"
    } else {
        if ($config.Reporting.Teams.Enabled) {
            Send-TeamsComplianceReport -WebhookUrl $config.Reporting.Teams.WebhookUrl `
                -Summary $summary -Gaps $gaps
        }
        if ($config.Reporting.SharePoint.Enabled -and $gaps.Count -gt 0) {
            Write-SharePointComplianceItems -SharePointConfig $config.Reporting.SharePoint `
                -Gaps $gaps -ScanTime $scanTime
        }
    }

    return [pscustomobject]@{ Anomalies = $allAnomalies; ComplianceGaps = $gaps; Summary = $summary }
}

return $allAnomalies

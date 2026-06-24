#Requires -Version 5.1
<#
.SYNOPSIS
    Loads compliance controls from the framework database, runs each check against
    configured Domain Controllers, and returns a structured gap/recommendation report.

.DESCRIPTION
    Supported frameworks: CIS Benchmarks (Windows Server/AD), NIST CSF / SP 800-53, ISO 27001 Annex A.
    Controls are defined in Config/compliance-frameworks.psd1 and are fully extensible.
#>

function Get-ComplianceControls {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FrameworkPath,
        [string[]]$FrameworkFilter,
        [ValidateSet('Critical','High','Medium','Low')][string[]]$SeverityFilter
    )

    $data = Import-PowerShellDataFile -Path $FrameworkPath
    $controls = $data.Controls

    if ($FrameworkFilter) {
        $controls = $controls | Where-Object {
            $ctl = $_
            $FrameworkFilter | Where-Object { $ctl.Frameworks.Keys -contains $_ }
        }
    }

    if ($SeverityFilter) {
        $controls = $controls | Where-Object { $_.Severity -in $SeverityFilter }
    }

    return $controls
}

function Invoke-ComplianceScan {
    <#
    .SYNOPSIS
        Runs all loaded compliance controls against each DC and returns gap findings.
    .OUTPUTS
        Array of [pscustomobject] with: ControlId, Title, Severity, Frameworks,
        ComputerName, Pass, Actual, Expected, Remediation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$DomainControllers,
        [Parameter(Mandatory)][array]$Controls
    )

    $results = @()

    foreach ($dc in $DomainControllers) {
        foreach ($control in $Controls) {
            try {
                $checkResult = & $control.Check $dc
                $results += [pscustomobject]@{
                    ControlId    = $control.Id
                    Title        = $control.Title
                    Severity     = $control.Severity
                    Frameworks   = $control.Frameworks
                    ComputerName = $dc
                    Pass         = $checkResult.Pass
                    Actual       = $checkResult.Actual
                    Expected     = $control.Expected
                    Remediation  = $control.Remediation
                }
            } catch {
                $results += [pscustomobject]@{
                    ControlId    = $control.Id
                    Title        = $control.Title
                    Severity     = $control.Severity
                    Frameworks   = $control.Frameworks
                    ComputerName = $dc
                    Pass         = $false
                    Actual       = "ERROR: $_"
                    Expected     = $control.Expected
                    Remediation  = $control.Remediation
                }
            }
        }
    }

    return $results
}

function Get-ComplianceGaps {
    <#
    .SYNOPSIS
        Filters scan results to only the failing controls (the gaps).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][array]$ScanResults)

    $ScanResults | Where-Object { -not $_.Pass }
}

function Get-ComplianceSummary {
    <#
    .SYNOPSIS
        Returns a summary object: pass/fail counts per DC and per severity, plus an
        overall compliance score (percent of controls passing).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][array]$ScanResults)

    $total = $ScanResults.Count
    $passed = ($ScanResults | Where-Object { $_.Pass }).Count
    $failed = $total - $passed
    $score = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }

    $byDc = $ScanResults | Group-Object ComputerName | ForEach-Object {
        $dcTotal  = $_.Group.Count
        $dcPassed = ($_.Group | Where-Object { $_.Pass }).Count
        [pscustomobject]@{
            DC            = $_.Name
            Total         = $dcTotal
            Passed        = $dcPassed
            Failed        = $dcTotal - $dcPassed
            ScorePct      = [math]::Round(($dcPassed / $dcTotal) * 100, 1)
        }
    }

    $bySeverity = $ScanResults | Where-Object { -not $_.Pass } | Group-Object Severity | ForEach-Object {
        [pscustomobject]@{ Severity = $_.Name; GapCount = $_.Count }
    }

    [pscustomobject]@{
        TotalControls   = $total
        Passed          = $passed
        Failed          = $failed
        ScorePct        = $score
        ByDC            = $byDc
        GapsBySeverity  = $bySeverity
    }
}

function Format-ComplianceReport {
    <#
    .SYNOPSIS
        Renders a human-readable markdown compliance report to a string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][array]$Gaps,
        [datetime]$ScanTime = (Get-Date)
    )

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("# DC Compliance Gap Report")
    $null = $sb.AppendLine("**Scan time:** $ScanTime")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## Overall Score: $($Summary.ScorePct)%  ($($Summary.Passed)/$($Summary.TotalControls) controls passing)")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("### Results by Domain Controller")
    $null = $sb.AppendLine("| DC | Total | Passed | Failed | Score |")
    $null = $sb.AppendLine("|---|---|---|---|---|")
    foreach ($row in $Summary.ByDC) {
        $null = $sb.AppendLine("| $($row.DC) | $($row.Total) | $($row.Passed) | $($row.Failed) | $($row.ScorePct)% |")
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("### Gaps by Severity")
    foreach ($row in ($Summary.GapsBySeverity | Sort-Object @{e={
        switch ($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Low'{3} default{4} }
    }})) {
        $null = $sb.AppendLine("- **$($row.Severity)**: $($row.GapCount) gap(s)")
    }
    $null = $sb.AppendLine()

    if ($Gaps.Count -eq 0) {
        $null = $sb.AppendLine("**No gaps found. All controls are passing.**")
        return $sb.ToString()
    }

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("## Gaps and Remediation")
    $null = $sb.AppendLine()

    $sortOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    $sortedGaps = $Gaps | Sort-Object { $sortOrder[$_.Severity] }, ControlId

    foreach ($gap in $sortedGaps) {
        $frameworkLabels = ($gap.Frameworks.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ' | '
        $null = $sb.AppendLine("### [$($gap.Severity)] $($gap.ControlId) — $($gap.Title)")
        $null = $sb.AppendLine("**DC:** $($gap.ComputerName)  ")
        $null = $sb.AppendLine("**Frameworks:** $frameworkLabels  ")
        $null = $sb.AppendLine("**Expected:** $($gap.Expected)  ")
        $null = $sb.AppendLine("**Actual:** $($gap.Actual)  ")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("> **Remediation:** $($gap.Remediation)")
        $null = $sb.AppendLine()
    }

    return $sb.ToString()
}

Export-ModuleMember -Function Get-ComplianceControls, Invoke-ComplianceScan, `
    Get-ComplianceGaps, Get-ComplianceSummary, Format-ComplianceReport

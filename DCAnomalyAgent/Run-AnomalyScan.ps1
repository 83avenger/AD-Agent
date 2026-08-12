#Requires -Version 5.1
<#
.SYNOPSIS
    Scans configured Domain Controllers for security anomalies and (optionally) compliance
    gaps against NIST CSF, ISO 27001, and CIS Benchmarks. Reports to Teams, SharePoint, and email.
.PARAMETER DryRun
    Skip Teams/SharePoint/email writes; print all findings to the console instead.
.PARAMETER ComplianceScan
    Run the compliance framework scan in addition to the regular anomaly scan.
    By default only the anomaly scan runs (suitable for the 3x/day schedule).
    Run compliance scan less frequently (e.g. daily/weekly) to reduce DC load.
.PARAMETER ZeroDayScan
    Pull the CISA KEV catalog (and optionally NVD) and alert on newly-added CVEs that
    match the product watch list in Config/zeroday-products.psd1.
.PARAMETER SoftwareInventoryScan
    Enumerate installed software (name/version/publisher) on every configured Windows
    asset, categorize hosts as Desktop/Laptop/Server/Domain Controller, and optionally
    cross-reference installed versions against the zero-day watchlist.
.PARAMETER TestEmail
    Send a synthetic test email to verify SMTP configuration without running a real scan.
.PARAMETER FrameworkFilter
    Optionally limit compliance check to one or more frameworks: CIS, NIST, ISO.
.PARAMETER SeverityFilter
    Optionally limit compliance check to specific severity levels: Critical, High, Medium, Low.
.PARAMETER DomainControllerOverride
    Override the DC list from settings.psd1 (comma-separated). Used by the web UI.
.PARAMETER JsonOutput
    Emit all results as a single JSON object on stdout instead of human-readable output.
    Used by the web UI to consume results programmatically.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    # Left unset by default and resolved below (not here) - $PSScriptRoot is not reliably
    # populated while param() default values are evaluated in Windows PowerShell 5.1,
    # which silently produced a garbage path like "C:\Config\settings.psd1".
    [string]$ConfigPath,
    [switch]$DryRun,
    [switch]$ComplianceScan,
    [switch]$ZeroDayScan,
    [switch]$CertificateScan,
    [switch]$SoftwareInventoryScan,
    # Skip the event-log anomaly scan. Used by the compliance/zero-day/certificate
    # Scheduled Tasks so they don't each re-run (and re-report) the anomaly scan
    # that the dedicated anomaly task already covers 3x/day.
    [switch]$SkipAnomalyScan,
    [switch]$TestEmail,
    [string[]]$FrameworkFilter,
    [ValidateSet('Critical','High','Medium','Low')][string[]]$SeverityFilter,
    [string]$DomainControllerOverride,
    [switch]$JsonOutput,
    # Limit the compliance scan to specific asset types. Default: all configured types.
    [ValidateSet('DomainController','MemberServer','Workstation','Linux','WebApplication')][string[]]$AssetType,
    # Override the target host list for compliance (comma-separated). Requires -AssetType
    # with a single value so the right controls are selected. Used by the web UI.
    [string]$TargetHostsOverride
)

$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'Config\settings.psd1' }

function Import-AgentConfig {
    # Loads settings.psd1. Unlike Import-PowerShellDataFile (which evaluates in a
    # restricted mode that leaves $PSScriptRoot empty), this resolves the file's
    # $PSScriptRoot to its own directory so the relative paths in settings.psd1 work.
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -Path $Path).Path
    $dir  = Split-Path -Parent $resolved
    $text = (Get-Content -Raw -Path $resolved).Replace('$PSScriptRoot', $dir)
    return (& ([scriptblock]::Create($text)))
}

Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Collectors.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Detectors.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Baseline.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Reporting.psm1" -Force
if ($ComplianceScan) {
    Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Compliance.psm1" -Force
}
if ($ZeroDayScan -or ($config -and $config.ZeroDay -and $config.ZeroDay.Enabled)) {
    Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.ZeroDay.psm1" -Force
}

$config = Import-AgentConfig -Path $ConfigPath
$scanTime = Get-Date

# Asset types with Assets.<Type>.DiscoverFromInventory = $true pull their target list from
# here (Run-Discovery.ps1's output) instead of - or in addition to - a static Hosts list.
$discoveryInventoryPath = "$PSScriptRoot\State\asset-inventory.json"

# Re-check after config is loaded
if (-not (Get-Module DCAnomalyAgent.ZeroDay -ErrorAction SilentlyContinue)) {
    if ($ZeroDayScan -or ($config.ZeroDay -and $config.ZeroDay.Enabled)) {
        Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.ZeroDay.psm1" -Force
    }
}

# Certificate scan is a heavy infrastructure sweep, so - like the compliance scan -
# it runs only on explicit request (-CertificateScan or the dedicated Scheduled Task),
# gated by the Enabled master switch. It does NOT piggyback on every anomaly run.
# Needs its own module plus Compliance (for Get-AssetTargets host resolution).
$runCertScan = $CertificateScan -and (-not $config.Certificates -or $config.Certificates.Enabled)
if ($runCertScan) {
    Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Certificates.psm1" -Force
    if (-not (Get-Module DCAnomalyAgent.Compliance -ErrorAction SilentlyContinue)) {
        Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Compliance.psm1" -Force
    }
}

# Software inventory follows the same explicit-request pattern as compliance/certificates.
# Needs its own module plus Compliance (for Get-AssetTargets) and, if cross-referencing
# against the zero-day watchlist is enabled, the ZeroDay module too.
$runSoftwareInventory = $SoftwareInventoryScan -and (-not $config.SoftwareInventory -or $config.SoftwareInventory.Enabled)
if ($runSoftwareInventory) {
    Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.SoftwareInventory.psm1" -Force
    if (-not (Get-Module DCAnomalyAgent.Compliance -ErrorAction SilentlyContinue)) {
        Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Compliance.psm1" -Force
    }
    if ($config.SoftwareInventory.CrossReferenceZeroDay -and -not (Get-Module DCAnomalyAgent.ZeroDay -ErrorAction SilentlyContinue)) {
        Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.ZeroDay.psm1" -Force
    }
}

if ($DomainControllerOverride) {
    $config = $config.Clone()
    $config['DomainControllers'] = $DomainControllerOverride -split ',' | ForEach-Object { $_.Trim() }
}

function Write-ScanLog {
    param([string]$Message)
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $Message
    Write-Host $line
    $logDir = Split-Path -Path $config.LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $config.LogPath -Value $line
}

# -----------------------------------------------------------------------------
# TEST EMAIL (smoke test only - exits after sending)
# -----------------------------------------------------------------------------
if ($TestEmail) {
    $testAnomaly = [pscustomobject]@{
        Type        = 'TestAlert'
        Account     = 'test-account'
        ComputerName = 'dc01.contoso.com'
        TimeCreated = Get-Date
        Detail      = 'This is a test alert sent by Run-AnomalyScan.ps1 -TestEmail to verify SMTP configuration.'
        Severity    = 'Low'
    }
    Write-Host "Sending test email to: $($config.Reporting.Email.To -join ', ')"
    Send-EmailAlert -EmailConfig $config.Reporting.Email -Anomalies @($testAnomaly)
    Write-Host "Test email sent (check inbox and spam folder)."
    return
}

# -----------------------------------------------------------------------------
# ANOMALY SCAN
# -----------------------------------------------------------------------------
$allAnomalies = @()
if ($SkipAnomalyScan) {
    Write-ScanLog "Anomaly scan skipped (-SkipAnomalyScan)."
} else {
$endTime = $scanTime
$startTime = $endTime.AddHours(-$config.LookbackHours)
$allSuccessfulLogons = @()

$baseline = Get-Baseline -StatePath $config.Baseline.StatePath
$knownGpoVersions = @{}
if ($baseline.ContainsKey('__gpoVersions')) {
    # Defensive: skip any malformed/legacy entry rather than indexing with a null key.
    foreach ($entry in @($baseline['__gpoVersions'])) {
        if ($entry -and $entry.Id) { $knownGpoVersions[$entry.Id] = $entry.Version }
    }
}

foreach ($dc in $config.DomainControllers) {
    Write-ScanLog "Anomaly scan: $dc ($startTime - $endTime)"

    try {
        # @() wrapping matters: Get-WinEvent (inside each collector) returns $null - not an
        # empty array - when zero events match, which is the common/good case (e.g. no
        # failed logons). PowerShell unrolls that $null straight through the assignment, and
        # binding $null to a Mandatory [array] parameter below throws "Cannot bind argument
        # ... because it is null" - which used to abort the entire DC's scan on the very
        # first collector call, every time there was nothing to report.
        $failedLogons = @(Get-FailedLogonEvents -ComputerName $dc -StartTime $startTime -EndTime $endTime)
        $allAnomalies += Find-FailedLogonAnomalies -FailedLogonEvents $failedLogons -BurstThreshold $config.FailedLogonBurstThreshold

        $successLogons = @(Get-SuccessfulLogonEvents -ComputerName $dc -StartTime $startTime -EndTime $endTime)
        $allSuccessfulLogons += $successLogons

        $groupChanges = @(Get-PrivilegedGroupChangeEvents -ComputerName $dc -StartTime $startTime -EndTime $endTime -PrivilegedGroups $config.PrivilegedGroups)
        $allAnomalies += Find-PrivilegedGroupAnomalies -GroupChangeEvents $groupChanges

        $newPrivAccounts = @(Get-NewPrivilegedAccounts -ComputerName $dc -StartTime $startTime -EndTime $endTime `
            -PrivilegedGroups $config.PrivilegedGroups -WindowHours $config.NewAccountToPrivilegedGroupWindowHours)
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
    $allAnomalies | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
}

if (-not $DryRun -and $allAnomalies.Count -gt 0) {
    if ($config.Reporting.Teams.Enabled) {
        Send-TeamsAlert -WebhookUrl $config.Reporting.Teams.WebhookUrl -Anomalies $allAnomalies
    }
    if ($config.Reporting.SharePoint.Enabled) {
        Write-SharePointListItem -SharePointConfig $config.Reporting.SharePoint -Anomalies $allAnomalies
    }
    if ($config.Reporting.Email.Enabled) {
        Send-EmailAlert -EmailConfig $config.Reporting.Email -Anomalies $allAnomalies
    }
}
} # end anomaly scan (-not $SkipAnomalyScan)

# -----------------------------------------------------------------------------
# COMPLIANCE SCAN
# -----------------------------------------------------------------------------
$complianceGaps    = $null
$complianceSummary = $null
if ($ComplianceScan -and $config.Compliance.Enabled) {
    Write-ScanLog "Starting compliance scan..."

    $effectiveFrameworkFilter = if ($FrameworkFilter) { $FrameworkFilter } else { $config.Compliance.FrameworkFilter }
    $effectiveSeverityFilter  = if ($SeverityFilter)  { $SeverityFilter  } else { $config.Compliance.SeverityFilter  }

    # Which asset types to scan: -AssetType param, else all configured types.
    $assetTypesToScan = if ($AssetType) { $AssetType } else { @($config.Assets.Keys) }

    $scanResults = @()
    foreach ($at in $assetTypesToScan) {
        # Resolve targets for this asset type (override > config hosts > AD discovery > DC fallback)
        if ($TargetHostsOverride -and $AssetType.Count -eq 1) {
            $targets = $TargetHostsOverride -split ',' | ForEach-Object { $_.Trim() }
        } else {
            $assetCfg = $config.Assets[$at]
            if (-not $assetCfg) { Write-ScanLog "No asset config for '$at' - skipping."; continue }
            $targets = Get-AssetTargets -AssetType $at -AssetConfig $assetCfg `
                -FallbackHosts $config.DomainControllers -InventoryPath $discoveryInventoryPath
        }

        if (-not $targets) { Write-ScanLog "No targets resolved for '$at' - skipping."; continue }

        # Select only controls applicable to this asset type
        $getControlsParams = @{ FrameworkPath = $config.Compliance.FrameworkPath; AssetTypeFilter = $at }
        if ($effectiveFrameworkFilter) { $getControlsParams['FrameworkFilter'] = $effectiveFrameworkFilter }
        if ($effectiveSeverityFilter)  { $getControlsParams['SeverityFilter']  = $effectiveSeverityFilter  }
        $controls = Get-ComplianceControls @getControlsParams

        Write-ScanLog "[$at] Running $($controls.Count) control(s) across $(@($targets).Count) host(s)..."

        # Linux (and any SSH-based) asset types carry a connection context for their checks
        $invokeParams = @{ Targets = $targets; Controls = $controls; AssetType = $at }
        if ($config.Assets[$at] -and $config.Assets[$at].Ssh) {
            $invokeParams['Context'] = $config.Assets[$at].Ssh
        }
        $scanResults += Invoke-ComplianceScan @invokeParams
    }

    $gaps    = Get-ComplianceGaps -ScanResults $scanResults
    $summary = Get-ComplianceSummary -ScanResults $scanResults

    Write-ScanLog "Compliance scan complete: $($summary.Passed)/$($summary.TotalControls) passing ($($summary.ScorePct)%). Gaps: $($gaps.Count)."

    # Save markdown report to disk (always)
    $reportDir = Split-Path -Path $config.Compliance.ReportOutputPath -Parent
    if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
    Format-ComplianceReport -Summary $summary -Gaps $gaps -ScanTime $scanTime |
        Set-Content -Path $config.Compliance.ReportOutputPath -Encoding UTF8
    Write-ScanLog "Compliance report saved: $($config.Compliance.ReportOutputPath)"

    if ($DryRun) {
        Write-Host "`n=== COMPLIANCE GAPS ==="
        $gaps | Select-Object ControlId, Severity, Title, ComputerName, Actual | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
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
        if ($config.Reporting.Email.Enabled) {
            Send-EmailComplianceReport -EmailConfig $config.Reporting.Email `
                -Summary $summary -Gaps $gaps
        }
    }

    # Captured for the consolidated output at the end of the script.
    $complianceGaps    = $gaps
    $complianceSummary = $summary
}

# -----------------------------------------------------------------------------
# ZERO-DAY SCAN
# -----------------------------------------------------------------------------
$dashboardZeroDays = @()
$runZeroDay = $ZeroDayScan -or ($config.ZeroDay -and $config.ZeroDay.Enabled -and $config.ZeroDay.AlertOnNew)
if ($runZeroDay) {
    Write-ScanLog "Starting zero-day telemetry scan..."

    try {
        $zdMatches   = Get-ZeroDayMatches -Config $config.ZeroDay
        $newZeroDays = Update-ZeroDayBaseline -Matches $zdMatches -CacheDir $config.ZeroDay.CacheDir

        # Also surface any entries whose CISA due date falls within the configured window
        if ($config.ZeroDay.AlertDueDateDays -gt 0) {
            $dueSoon = $zdMatches | Where-Object {
                $_.DueDate -and ([datetime]$_.DueDate - (Get-Date)).TotalDays -le $config.ZeroDay.AlertDueDateDays `
                    -and ([datetime]$_.DueDate - (Get-Date)).TotalDays -ge 0
            }
            # Merge without duplicates
            $existingIds  = $newZeroDays | Select-Object -ExpandProperty CveId
            $newZeroDays += $dueSoon | Where-Object { $_.CveId -notin $existingIds }
        }

        $dashboardZeroDays = @($newZeroDays)
        Write-ScanLog "Zero-day scan complete: $($zdMatches.Count) total match(es), $($newZeroDays.Count) new/due-soon alert(s)."

        if ($DryRun) {
            Write-Host "`n=== ZERO-DAY MATCHES (new/due-soon) ==="
            $newZeroDays | Select-Object CveId, VendorProject, Product, DateAdded, DueDate, KnownRansomwareCampaignUse |
                Format-Table -AutoSize | Out-String -Width 300 | Write-Host
        } elseif ($newZeroDays.Count -gt 0) {
            if ($config.Reporting.Teams.Enabled) {
                Send-TeamsZeroDayAlert -WebhookUrl $config.Reporting.Teams.WebhookUrl -ZeroDays $newZeroDays
            }
            if ($config.Reporting.Email.Enabled) {
                Send-EmailZeroDayAlert -EmailConfig $config.Reporting.Email -ZeroDays $newZeroDays
            }
        }
    } catch {
        Write-ScanLog "ERROR (zero-day scan): $_"
    }
}

# -----------------------------------------------------------------------------
# CERTIFICATE EXPIRY SCAN
# -----------------------------------------------------------------------------
$expiringCerts = @()
if ($runCertScan) {
    Write-ScanLog "Starting certificate expiry scan..."
    $certCfg = $config.Certificates
    $thresholdDays = if ($certCfg.ThresholdDays) { $certCfg.ThresholdDays } else { 90 }
    $collected = @()

    # 1. Windows machine certificate stores across the configured asset types.
    foreach ($at in $certCfg.ScanAssetTypes) {
        $assetCfg = $config.Assets[$at]
        if (-not $assetCfg) { continue }
        try {
            $targets = Get-AssetTargets -AssetType $at -AssetConfig $assetCfg -FallbackHosts $config.DomainControllers -InventoryPath $discoveryInventoryPath
        } catch {
            Write-ScanLog "ERROR (cert: resolve $at targets): $_"; continue
        }
        foreach ($t in $targets) {
            try {
                $collected += Get-MachineCertificate -ComputerName $t -Stores $certCfg.MachineStores
            } catch {
                Write-ScanLog "ERROR (cert: machine store on $t): $_"
            }
        }
    }

    # 2. TLS endpoints: explicit config list + auto-derived (DC LDAPS, WebApplication 443).
    $endpoints = @()
    if ($certCfg.EndpointsPath -and (Test-Path $certCfg.EndpointsPath)) {
        try { $endpoints += (Import-PowerShellDataFile -Path $certCfg.EndpointsPath).Endpoints } catch {
            Write-ScanLog "ERROR (cert: load endpoints file): $_"
        }
    }
    if ($certCfg.ProbeDcLdaps) {
        foreach ($dc in $config.DomainControllers) { $endpoints += @{ Host = $dc; Port = 636; Name = 'DC LDAPS' } }
    }
    if ($certCfg.ProbeWebApps -and $config.Assets.WebApplication) {
        foreach ($w in $config.Assets.WebApplication.Hosts) {
            $h = $w -replace '^https?://' -replace '/.*$'
            $endpoints += @{ Host = $h; Port = 443; Name = 'WebApplication' }
        }
    }
    foreach ($ep in $endpoints) {
        if (-not $ep.Host) { continue }
        try {
            $collected += Get-EndpointCertificate -TargetHost $ep.Host -Port $ep.Port
        } catch {
            Write-ScanLog "ERROR (cert: TLS probe $($ep.Host):$($ep.Port)): $_"
        }
    }

    # 3. AD Certificate Services (optional).
    if ($certCfg.Adcs -and $certCfg.Adcs.Enabled -and $certCfg.Adcs.CaConfig) {
        try {
            $collected += Get-CaIssuedCertificate -CaConfig $certCfg.Adcs.CaConfig -ThresholdDays $thresholdDays
        } catch {
            Write-ScanLog "ERROR (cert: ADCS query): $_"
        }
    }

    $expiringCerts = Find-ExpiringCertificates -Certificates $collected -ThresholdDays $thresholdDays
    $expiringReal  = @($expiringCerts | Where-Object { $null -ne $_.DaysRemaining })
    Write-ScanLog "Certificate scan complete: $($expiringReal.Count) cert(s) expiring within $thresholdDays days."

    # Save markdown report to disk (always).
    if ($certCfg.ReportOutputPath) {
        $certReportDir = Split-Path -Path $certCfg.ReportOutputPath -Parent
        if (-not (Test-Path $certReportDir)) { New-Item -ItemType Directory -Path $certReportDir -Force | Out-Null }
        Format-CertificateReport -Findings $expiringCerts -ThresholdDays $thresholdDays -ScanTime $scanTime |
            Set-Content -Path $certCfg.ReportOutputPath -Encoding UTF8
        Write-ScanLog "Certificate report saved: $($certCfg.ReportOutputPath)"
    }

    if ($DryRun) {
        Write-Host "`n=== EXPIRING CERTIFICATES (within $thresholdDays days) ==="
        $expiringReal | Select-Object Severity, DaysRemaining, Subject, Sources, Locations | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
    } elseif ($expiringReal.Count -gt 0) {
        if ($config.Reporting.Teams.Enabled) {
            Send-TeamsCertificateReport -WebhookUrl $config.Reporting.Teams.WebhookUrl `
                -Certificates $expiringCerts -ThresholdDays $thresholdDays
        }
        if ($config.Reporting.Email.Enabled) {
            Send-EmailCertificateReport -EmailConfig $config.Reporting.Email `
                -Certificates $expiringCerts -ThresholdDays $thresholdDays
        }
        if ($config.Reporting.SharePoint.Enabled) {
            Write-SharePointCertificateItems -SharePointConfig $config.Reporting.SharePoint `
                -Certificates $expiringCerts -ScanTime $scanTime
        }
    }
}

# -----------------------------------------------------------------------------
# SOFTWARE INVENTORY SCAN
# -----------------------------------------------------------------------------
$softwareInventory  = @()
$vulnerableSoftware = @()
if ($runSoftwareInventory) {
    Write-ScanLog "Starting software inventory scan..."
    $swCfg = $config.SoftwareInventory
    $collected = @()

    foreach ($at in $swCfg.ScanAssetTypes) {
        $assetCfg = $config.Assets[$at]
        if (-not $assetCfg) { continue }
        try {
            $targets = Get-AssetTargets -AssetType $at -AssetConfig $assetCfg -FallbackHosts $config.DomainControllers -InventoryPath $discoveryInventoryPath
        } catch {
            Write-ScanLog "ERROR (software: resolve $at targets): $_"; continue
        }
        foreach ($t in $targets) {
            $category = Get-DeviceCategory -ComputerName $t -AssetType $at
            try {
                $collected += Get-InstalledSoftware -ComputerName $t -Category $category
            } catch {
                Write-ScanLog "ERROR (software: inventory on $t): $_"
            }
        }
    }

    $softwareInventory = $collected
    $installedOnly = @($softwareInventory | Where-Object { -not $_.Error })
    $hostCount = @($installedOnly | Select-Object -ExpandProperty ComputerName -Unique).Count
    Write-ScanLog "Software inventory complete: $($installedOnly.Count) record(s) across $hostCount host(s)."

    if ($swCfg.CrossReferenceZeroDay) {
        try {
            $zdForCrossRef = Get-ZeroDayMatches -Config $config.ZeroDay
            $vulnerableSoftware = Find-VulnerableInstalledSoftware -Inventory $softwareInventory -ZeroDayMatches $zdForCrossRef
            if ($vulnerableSoftware.Count -gt 0) {
                Write-ScanLog "Software inventory: $($vulnerableSoftware.Count) zero-day exposure hit(s) found in installed software."
            }
        } catch {
            Write-ScanLog "ERROR (software: zero-day cross-reference): $_"
        }
    }

    if ($swCfg.ReportOutputPath) {
        $swReportDir = Split-Path -Path $swCfg.ReportOutputPath -Parent
        if (-not (Test-Path $swReportDir)) { New-Item -ItemType Directory -Path $swReportDir -Force | Out-Null }
        Format-SoftwareInventoryReport -Inventory $softwareInventory -VulnerableHits $vulnerableSoftware -ScanTime $scanTime |
            Set-Content -Path $swCfg.ReportOutputPath -Encoding UTF8
        Write-ScanLog "Software inventory report saved: $($swCfg.ReportOutputPath)"
    }

    if ($DryRun) {
        Write-Host "`n=== SOFTWARE INVENTORY (top products) ==="
        $installedOnly | Group-Object Name | Sort-Object Count -Descending | Select-Object -First 15 Name, Count |
            Format-Table -AutoSize | Out-String -Width 300 | Write-Host
        if ($vulnerableSoftware.Count -gt 0) {
            Write-Host "`n=== ZERO-DAY EXPOSURE (installed software) ==="
            $vulnerableSoftware | Format-Table -AutoSize | Out-String -Width 300 | Write-Host
        }
    } elseif ($vulnerableSoftware.Count -gt 0) {
        if ($config.Reporting.Teams.Enabled) {
            Send-TeamsSoftwareExposureAlert -WebhookUrl $config.Reporting.Teams.WebhookUrl -VulnerableHits $vulnerableSoftware
        }
        if ($config.Reporting.Email.Enabled) {
            Send-EmailSoftwareExposureAlert -EmailConfig $config.Reporting.Email -VulnerableHits $vulnerableSoftware
        }
    }
}

# -----------------------------------------------------------------------------
# DASHBOARD SNAPSHOT (merged across scan types)
# Each scheduled task runs a single scan type, so we merge this run's sections
# into the persisted snapshot rather than overwriting - the rotating dashboard
# then shows every scan type even though they run in separate tasks.
# -----------------------------------------------------------------------------
try {
    $snapshotPath = if ($config.Dashboard -and $config.Dashboard.SnapshotPath) {
        $config.Dashboard.SnapshotPath
    } else {
        "$PSScriptRoot\State\latest-scan.json"
    }
    $snapDir = Split-Path -Path $snapshotPath -Parent
    if (-not (Test-Path $snapDir)) { New-Item -ItemType Directory -Path $snapDir -Force | Out-Null }

    $prev = $null
    if (Test-Path $snapshotPath) {
        try { $prev = Get-Content -Path $snapshotPath -Raw | ConvertFrom-Json } catch { $prev = $null }
    }
    $prevFresh = if ($prev -and $prev.Freshness) { $prev.Freshness } else { [pscustomobject]@{} }
    $nowIso = $scanTime.ToString('o')

    $ranAnomaly    = -not $SkipAnomalyScan
    $ranCompliance = $ComplianceScan -and $config.Compliance.Enabled
    $ranCert       = $runCertScan
    $ranZeroDay    = $runZeroDay
    $ranSoftware   = $runSoftwareInventory

    $snapshot = [ordered]@{
        ScanTime             = $nowIso
        Anomalies            = if ($ranAnomaly)    { @($allAnomalies) }   elseif ($prev) { @($prev.Anomalies) }            else { @() }
        ComplianceGaps       = if ($ranCompliance) { @($complianceGaps) } elseif ($prev) { @($prev.ComplianceGaps) }       else { @() }
        ComplianceSummary    = if ($ranCompliance) { $complianceSummary } elseif ($prev) { $prev.ComplianceSummary }        else { $null }
        ExpiringCertificates = if ($ranCert)       { @($expiringCerts) }  elseif ($prev) { @($prev.ExpiringCertificates) }  else { @() }
        ZeroDays             = if ($ranZeroDay)    { @($dashboardZeroDays) } elseif ($prev) { @($prev.ZeroDays) }           else { @() }
        SoftwareInventory    = if ($ranSoftware)   { @($softwareInventory) } elseif ($prev) { @($prev.SoftwareInventory) }  else { @() }
        VulnerableSoftware   = if ($ranSoftware)   { @($vulnerableSoftware) } elseif ($prev) { @($prev.VulnerableSoftware) } else { @() }
        Freshness            = [ordered]@{
            Anomalies    = if ($ranAnomaly)    { $nowIso } else { $prevFresh.Anomalies }
            Compliance   = if ($ranCompliance) { $nowIso } else { $prevFresh.Compliance }
            Certificates = if ($ranCert)       { $nowIso } else { $prevFresh.Certificates }
            ZeroDay      = if ($ranZeroDay)    { $nowIso } else { $prevFresh.ZeroDay }
            SoftwareInventory = if ($ranSoftware) { $nowIso } else { $prevFresh.SoftwareInventory }
        }
    }

    $snapshot | ConvertTo-Json -Depth 8 | Set-Content -Path $snapshotPath -Encoding UTF8
    Write-ScanLog "Dashboard snapshot updated: $snapshotPath"
} catch {
    Write-ScanLog "WARN (dashboard snapshot): $_"
}

# -----------------------------------------------------------------------------
# CONSOLIDATED OUTPUT
# -----------------------------------------------------------------------------
if ($JsonOutput) {
    $payload = [ordered]@{
        ScanTime  = $scanTime.ToString('o')
        Anomalies = $allAnomalies
    }
    if ($ComplianceScan -and $config.Compliance.Enabled) {
        $payload['ComplianceGaps']    = $complianceGaps
        $payload['ComplianceSummary'] = $complianceSummary
    }
    if ($runCertScan) {
        $payload['ExpiringCertificates'] = $expiringCerts
    }
    if ($runSoftwareInventory) {
        $payload['SoftwareInventory']  = $softwareInventory
        $payload['VulnerableSoftware'] = $vulnerableSoftware
    }
    $payload | ConvertTo-Json -Depth 8
    return
}

if (($ComplianceScan -and $config.Compliance.Enabled) -or $runCertScan -or $runSoftwareInventory) {
    return [pscustomobject]@{
        Anomalies            = $allAnomalies
        ComplianceGaps       = $complianceGaps
        Summary              = $complianceSummary
        ExpiringCertificates = $expiringCerts
        SoftwareInventory    = $softwareInventory
        VulnerableSoftware   = $vulnerableSoftware
    }
}

return $allAnomalies

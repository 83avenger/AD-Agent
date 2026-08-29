#Requires -Version 5.1
<#
.SYNOPSIS
    Registers a Windows Scheduled Task that runs Run-AnomalyScan.ps1 three times a day
    under a Group Managed Service Account (gMSA), so WinRM auth uses Kerberos with no
    stored passwords.

.NOTES
    One-time prerequisites (run by a domain admin, not by this script):
      1. Create the gMSA:
           New-ADServiceAccount -Name 'svc-discoverAgt' -DNSHostName 'svc-discoverAgt.contoso.com' `
               -PrincipalsAllowedToRetrieveManagedPassword 'MGMT-SERVER$'
      2. Install it on the management server:
           Install-ADServiceAccount -Identity 'svc-discoverAgt'
      3. Grant the gMSA "Log on as a batch job" on the management server (Local Security Policy
         or via GPO), and read access to the Security event log on each DC (add the gMSA to a
         security group that is a member of the built-in "Event Log Readers" group on each DC,
         e.g. via a domain GPO restricted-group setting).
      4. Register an Azure AD app for the SharePoint/Graph write path, grant it Sites.ReadWrite.All
         (application permission, admin consented), and install its auth certificate into a
         certificate store the gMSA can read (e.g. LocalMachine\My on the management server).
      5. Update DCAnomalyAgent/Config/settings.psd1 with the webhook URL, tenant/app/site/list IDs,
         and certificate thumbprint.
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$GmsaAccount = 'CONTOSO\svc-discoverAgt$',
    # Left unset by default and resolved below (not here) - $PSScriptRoot is not reliably
    # populated while param() default values are evaluated in Windows PowerShell 5.1.
    [string]$ScriptPath,
    [string]$DiscoveryScriptPath,
    [string]$CloudflareSyncScriptPath,
    [string]$TaskName = 'DCAnomalyAgent-Scan',
    [string[]]$TriggerTimes = @('06:00', '14:00', '22:00'),
    # Lightweight presence sweep (refreshes online/LastSeen status only, skips the slower
    # per-host software collection) - keeps the Assets/Discovery pages current throughout
    # the day without hammering every host with WinRM software-inventory calls that often.
    [string[]]$DiscoveryPresenceTimes = @('02:00', '06:00', '10:00', '14:00', '18:00', '22:00'),
    [string]$DiscoveryFullTime = '05:00'
)

if (-not $ScriptPath) { $ScriptPath = (Resolve-Path "$PSScriptRoot\..\Run-AnomalyScan.ps1").Path }
if (-not $DiscoveryScriptPath) { $DiscoveryScriptPath = (Resolve-Path "$PSScriptRoot\..\Run-Discovery.ps1").Path }
if (-not $CloudflareSyncScriptPath) {
    # Resolve-Path throws if absent; this task is optional so just note the path and let
    # the Test-Path guard further down skip registration cleanly.
    $CloudflareSyncScriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Sync-CloudflareDevices.ps1'
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

$triggers = $TriggerTimes | ForEach-Object {
    New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($_))
}

$principal = New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
# Discovery with -FromAD can enumerate thousands of computer objects (seen 4000+ in
# real deployments) and attempts a WinRM probe against each eligible one - a 1-hour cap
# risks the task getting killed mid-run. Longer ceiling, same "don't skip if missed" behavior.
$discoverySettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
    -Principal $principal -Settings $settings -Description 'Runs DC Anomaly Agent scan under gMSA identity'

Write-Host "Scheduled task '$TaskName' registered to run at: $($TriggerTimes -join ', ') under $GmsaAccount"

# -- Compliance scan task (runs once daily, separate from anomaly scan) --------
$complianceAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ComplianceScan -SkipAnomalyScan"

$complianceTrigger = New-ScheduledTaskTrigger -Daily -At '07:00'

Register-ScheduledTask -TaskName "$TaskName-Compliance" -Action $complianceAction `
    -Trigger $complianceTrigger -Principal $principal -Settings $settings `
    -Description 'Runs DC Anomaly Agent compliance scan (NIST/CIS/ISO) under gMSA identity'

Write-Host "Compliance task '$TaskName-Compliance' registered to run daily at 07:00 under $GmsaAccount"

# -- Zero-day telemetry task (runs once daily) ---------------------------------
$zeroDayAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -ZeroDayScan -SkipAnomalyScan"

$zeroDayTrigger = New-ScheduledTaskTrigger -Daily -At '08:00'

Register-ScheduledTask -TaskName "$TaskName-ZeroDay" -Action $zeroDayAction `
    -Trigger $zeroDayTrigger -Principal $principal -Settings $settings `
    -Description 'Pulls CISA KEV and NVD feeds and alerts on newly-added CVEs matching the watched product list'

Write-Host "Zero-day task '$TaskName-ZeroDay' registered to run daily at 08:00 under $GmsaAccount"

# -- Certificate expiry task (runs once daily) ---------------------------------
$certAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -CertificateScan -SkipAnomalyScan"

$certTrigger = New-ScheduledTaskTrigger -Daily -At '09:00'

Register-ScheduledTask -TaskName "$TaskName-Certificates" -Action $certAction `
    -Trigger $certTrigger -Principal $principal -Settings $settings `
    -Description 'Scans machine stores, TLS endpoints and the CA for certificates expiring within the configured threshold (default 90 days)'

Write-Host "Certificate task '$TaskName-Certificates' registered to run daily at 09:00 under $GmsaAccount"

# -- Software inventory task (runs once daily) ---------------------------------
$softwareAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -SoftwareInventoryScan -SkipAnomalyScan"

$softwareTrigger = New-ScheduledTaskTrigger -Daily -At '10:00'

Register-ScheduledTask -TaskName "$TaskName-SoftwareInventory" -Action $softwareAction `
    -Trigger $softwareTrigger -Principal $principal -Settings $settings `
    -Description 'Enumerates installed software on Windows assets, categorizes by device type, and cross-references against the zero-day watchlist'

Write-Host "Software inventory task '$TaskName-SoftwareInventory' registered to run daily at 10:00 under $GmsaAccount"

# -- Discovery presence sweep (runs several times daily, no software collection) ----
# Keeps AssetType/OpenPorts/LastSeen (online status, staleness) current on the
# Assets/Discovery pages. Uses whatever FromAD/Cidr/CloudflareWarpCidr is configured in
# settings.psd1's Discovery block (no switches passed = config-driven, same as running
# Run-Discovery.ps1 with no arguments).
$discoveryPresenceAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$DiscoveryScriptPath`" -SkipSoftwareInventory"

$discoveryPresenceTriggers = $DiscoveryPresenceTimes | ForEach-Object {
    New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($_))
}

Register-ScheduledTask -TaskName "$TaskName-Discovery" -Action $discoveryPresenceAction `
    -Trigger $discoveryPresenceTriggers -Principal $principal -Settings $discoverySettings `
    -Description 'Refreshes asset online/LastSeen status via AD + network discovery (no software collection - see -Discovery-Full for that)'

Write-Host "Discovery presence task '$TaskName-Discovery' registered to run at: $($DiscoveryPresenceTimes -join ', ') under $GmsaAccount"

# -- Discovery full pass (runs once daily, includes software inventory) ------------
$discoveryFullAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$DiscoveryScriptPath`""

$discoveryFullTrigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($DiscoveryFullTime))

Register-ScheduledTask -TaskName "$TaskName-Discovery-Full" -Action $discoveryFullAction `
    -Trigger $discoveryFullTrigger -Principal $principal -Settings $discoverySettings `
    -Description 'Full discovery pass: asset inventory, device categorization, and per-device software collection'

Write-Host "Discovery full-pass task '$TaskName-Discovery-Full' registered to run daily at $DiscoveryFullTime under $GmsaAccount"

# -- Cloudflare WARP device roster sync -------------------------------------------
# Only meaningful once Integrations.CloudflareZeroTrust is enabled AND credentials are
# saved (web UI Integrations page -> Config\integration-secrets.json); the script exits
# cleanly with a message otherwise, so registering it unconditionally is harmless.
#
# Hourly rather than a few times a day because this is the ONLY presence signal for a
# laptop that is off the corporate network - it's a cheap API call, not a scan, and it
# is what keeps a work-from-home device from drifting into "stale" while it is in fact
# online every day. It supplies identity/presence only; installed software still comes
# from the push collector or WinRM.
if (Test-Path $CloudflareSyncScriptPath) {
    $cloudflareAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$CloudflareSyncScriptPath`""

    $cloudflareTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(20) `
        -RepetitionInterval (New-TimeSpan -Hours 1)
    # See Watch-WebUIHealth.ps1: [TimeSpan]::MaxValue does not fit the task XML duration
    # schema and is rejected at registration. An empty Duration with a set interval is
    # how Task Scheduler expresses "repeat indefinitely".
    $cloudflareTrigger.Repetition.Duration = ""
    $cloudflareTrigger.Repetition.StopAtDurationEnd = $false

    $cloudflareSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

    Register-ScheduledTask -TaskName "$TaskName-CloudflareSync" -Action $cloudflareAction `
        -Trigger $cloudflareTrigger -Principal $principal -Settings $cloudflareSettings `
        -Description 'Pulls the Cloudflare WARP-enrolled device roster (identity/presence for off-network laptops; no software inventory - Cloudflare has no such API)' `
        -Force | Out-Null

    Write-Host "Cloudflare sync task '$TaskName-CloudflareSync' registered to run hourly under $GmsaAccount"
    Write-Host "  (no-op until Integrations.CloudflareZeroTrust.Enabled = `$true and credentials are saved on the web UI's Integrations page)"
} else {
    Write-Warning "Cloudflare sync script not found at '$CloudflareSyncScriptPath' - skipping that task."
}

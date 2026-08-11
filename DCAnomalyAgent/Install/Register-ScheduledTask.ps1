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
[CmdletBinding()]
param(
    [string]$GmsaAccount = 'CONTOSO\svc-discoverAgt$',
    # Left unset by default and resolved below (not here) - $PSScriptRoot is not reliably
    # populated while param() default values are evaluated in Windows PowerShell 5.1.
    [string]$ScriptPath,
    [string]$TaskName = 'DCAnomalyAgent-Scan',
    [string[]]$TriggerTimes = @('06:00', '14:00', '22:00')
)

if (-not $ScriptPath) { $ScriptPath = (Resolve-Path "$PSScriptRoot\..\Run-AnomalyScan.ps1").Path }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

$triggers = $TriggerTimes | ForEach-Object {
    New-ScheduledTaskTrigger -Daily -At ([datetime]::Parse($_))
}

$principal = New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

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

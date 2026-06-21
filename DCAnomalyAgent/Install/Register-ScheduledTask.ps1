#Requires -Version 5.1
<#
.SYNOPSIS
    Registers a Windows Scheduled Task that runs Run-AnomalyScan.ps1 three times a day
    under a Group Managed Service Account (gMSA), so WinRM auth uses Kerberos with no
    stored passwords.

.NOTES
    One-time prerequisites (run by a domain admin, not by this script):
      1. Create the gMSA:
           New-ADServiceAccount -Name 'svc-dcAnomalyAgent' -DNSHostName 'svc-dcAnomalyAgent.contoso.com' `
               -PrincipalsAllowedToRetrieveManagedPassword 'MGMT-SERVER$'
      2. Install it on the management server:
           Install-ADServiceAccount -Identity 'svc-dcAnomalyAgent'
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
    [string]$GmsaAccount = 'CONTOSO\svc-dcAnomalyAgent$',
    [string]$ScriptPath = (Resolve-Path "$PSScriptRoot\..\Run-AnomalyScan.ps1").Path,
    [string]$TaskName = 'DCAnomalyAgent-Scan',
    [string[]]$TriggerTimes = @('06:00', '14:00', '22:00')
)

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

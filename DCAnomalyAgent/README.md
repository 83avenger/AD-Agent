# DC Anomaly Agent

PowerShell tool that scans Domain Controllers 2-3 times a day for security
anomalies and reports findings to Microsoft Teams and a SharePoint list.

## What it detects

- Failed logon bursts and account lockouts (Event ID 4625, 4740)
- Privileged group membership changes (Domain Admins, Enterprise Admins, etc.)
- New accounts elevated to a privileged group shortly after creation
- GPO modifications and version changes
- Behavioral baseline deviations (UEBA-lite): unusual logon hour, unseen
  source host, first-ever logon to a given DC, all measured per account
  against a rolling baseline with a cold-start guard

## Layout

- `Run-AnomalyScan.ps1` — entry point, run manually or via Scheduled Task
- `Config/settings.psd1` — DC list, thresholds, Teams/SharePoint config (no secrets)
- `Modules/` — Collectors, Detectors, Baseline, Reporting
- `Install/Register-ScheduledTask.ps1` — registers the 3x/day Scheduled Task under a gMSA
- `Tests/` — Pester unit tests for detectors and baseline logic
- `State/` — runtime baseline + log file (gitignored)

## Setup

1. Edit `Config/settings.psd1`: set your DC hostnames, Teams webhook URL, and
   SharePoint/Graph app registration details (tenant/client ID, cert thumbprint,
   site/list IDs).
2. Follow the prerequisites documented at the top of
   `Install/Register-ScheduledTask.ps1` (gMSA creation, event log read access,
   Azure AD app registration for the SharePoint write path).
3. Run `Install/Register-ScheduledTask.ps1` on your management server to
   schedule the scan 3x/day.

## Testing

```powershell
# Unit tests (no DC required, uses synthetic event data)
Invoke-Pester -Path .\Tests

# Dry run against a real DC (prints findings, skips Teams/SharePoint writes)
.\Run-AnomalyScan.ps1 -DryRun
```

# DC Anomaly Agent

PowerShell tool that scans Domain Controllers 2-3 times a day for security
anomalies and reports findings to Microsoft Teams and a SharePoint list.

## What it detects

**Anomaly scan (3x/day):**
- Failed logon bursts and account lockouts (Event ID 4625, 4740)
- Privileged group membership changes (Domain Admins, Enterprise Admins, etc.)
- New accounts elevated to a privileged group shortly after creation
- GPO modifications and version changes
- Behavioral baseline deviations (UEBA-lite): unusual logon hour, unseen
  source host, first-ever logon to a given DC, all measured per account
  against a rolling baseline with a cold-start guard

**Compliance scan (daily, `-ComplianceScan`):**

| Control Area | Controls | Frameworks |
|---|---|---|
| Password Policy | Min length, complexity, max age, history, reversible encryption | CIS, NIST IA-5, ISO A.9.4.3 |
| Account Lockout | Threshold, duration | CIS, NIST AC-7, ISO A.9.4.2 |
| Audit Policy | Account logon, account mgmt, policy change, privilege use | CIS, NIST AU-2, ISO A.12.4.1 |
| Network Hardening | SMB signing, LDAP signing, NTLMv1 disabled, WinRM HTTPS | CIS, NIST SC-8, ISO A.13.2.1 |
| Privileged Access | DA membership count, built-in admin, guest account, service accounts in DA | CIS, NIST AC-6, ISO A.9.2.3 |
| Kerberos | Max ticket lifetime | CIS, NIST IA-5 |
| Domain / Forest | Functional level, FGPP, AD Recycle Bin | NIST CM-6, ISO A.12.6.1 |

## Layout

- `Run-AnomalyScan.ps1` — entry point; `-ComplianceScan` enables the compliance module, `-DryRun` skips reporting
- `Config/settings.psd1` — DC list, thresholds, Teams/SharePoint config (no secrets)
- `Config/compliance-frameworks.psd1` — compliance control database (add custom controls here)
- `Modules/DCAnomalyAgent.Collectors.psm1` — WinRM-based event log + AD collectors
- `Modules/DCAnomalyAgent.Detectors.psm1` — rule-based anomaly detectors
- `Modules/DCAnomalyAgent.Baseline.psm1` — rolling per-account UEBA baseline
- `Modules/DCAnomalyAgent.Compliance.psm1` — compliance control loader, scanner, gap analysis, report formatter
- `Modules/DCAnomalyAgent.Reporting.psm1` — Teams webhook + SharePoint (Graph) output for both anomalies and compliance gaps
- `Install/Register-ScheduledTask.ps1` — registers anomaly scan (3x/day) and compliance scan (1x/day) tasks under a gMSA
- `Tests/` — Pester unit tests (Detectors, Baseline, Compliance)
- `State/` — runtime baseline, log, compliance report markdown (gitignored)

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

# Dry run — anomaly scan only (prints findings, skips Teams/SharePoint writes)
.\Run-AnomalyScan.ps1 -DryRun

# Dry run — anomaly + compliance scan together
.\Run-AnomalyScan.ps1 -DryRun -ComplianceScan

# Compliance scan limited to Critical/High gaps across CIS controls only
.\Run-AnomalyScan.ps1 -ComplianceScan -FrameworkFilter CIS -SeverityFilter Critical,High
```

### Adding custom controls

Open `Config/compliance-frameworks.psd1` and append a new hashtable to the `Controls` array:

```powershell
@{
    Id          = 'CUSTOM-001'
    Title       = 'My custom check'
    Frameworks  = @{ CIS = 'n/a'; NIST = 'AC-2'; ISO = 'A.9.2.1' }
    Severity    = 'High'
    Check       = {
        param($ComputerName)
        $val = Invoke-Command -ComputerName $ComputerName -ScriptBlock { <# your check here #> }
        [pscustomobject]@{ Actual = $val; Pass = $val -eq $true }
    }
    Expected    = 'Describe what a passing state looks like'
    Remediation = 'Step-by-step fix instructions.'
}
```

No code changes required — the scanner picks it up automatically.

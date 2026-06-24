# AD-Agent

A PowerShell-based security monitoring and compliance platform for Active Directory environments. Runs 2–3 times per day against Domain Controllers via WinRM, detects anomalies and compliance gaps, and reports findings to Microsoft Teams and SharePoint. Includes a web UI for on-demand scans and PDF/CSV report generation.

---

## Features

| Capability | Detail |
|---|---|
| Anomaly detection | Failed logon bursts, account lockouts, privileged group changes, new accounts elevated to DA within X hours, GPO version drift |
| UEBA baseline | Per-user rolling logon-hour range, source host, and DC profiles; flags deviations after cold-start guard |
| Compliance scanning | CIS Benchmarks, NIST SP 800-53, ISO 27001 Annex A across DCs, member servers, workstations, and Linux hosts |
| Asset discovery | AD enumeration + TCP CIDR sweep; classifies and merges into a unified inventory |
| Reporting | Teams Adaptive Card alerts, SharePoint list items (Graph API), local markdown report, PDF/CSV download via web UI |
| Web UI | Flask app — choose scan type, frameworks, severities, target hosts; download PDF or CSV reports |

---

## Repository layout

```
AD-Agent/
├── DCAnomalyAgent/
│   ├── Run-AnomalyScan.ps1          # Scan entry point (anomaly + compliance)
│   ├── Run-Discovery.ps1            # Asset discovery entry point
│   ├── Config/
│   │   ├── settings.psd1            # All configuration (no secrets)
│   │   ├── compliance-frameworks.psd1   # DC/domain controls (CIS/NIST/ISO)
│   │   ├── compliance-endpoints.psd1    # Windows host controls (servers/workstations)
│   │   └── compliance-linux.psd1        # Linux/SSH controls
│   ├── Modules/
│   │   ├── DCAnomalyAgent.Collectors.psm1   # WinRM event log + AD collection
│   │   ├── DCAnomalyAgent.Detectors.psm1    # Rule-based anomaly detection
│   │   ├── DCAnomalyAgent.Baseline.psm1     # UEBA rolling baseline (JSON)
│   │   ├── DCAnomalyAgent.Reporting.psm1    # Teams + SharePoint output
│   │   ├── DCAnomalyAgent.Compliance.psm1   # Compliance engine
│   │   └── DCAnomalyAgent.Discovery.psm1    # Asset discovery (AD + network)
│   ├── Install/
│   │   └── Register-ScheduledTask.ps1   # Registers gMSA-run Scheduled Tasks
│   ├── Tests/
│   │   ├── Detectors.Tests.ps1
│   │   ├── Baseline.Tests.ps1
│   │   ├── Compliance.Tests.ps1
│   │   └── Discovery.Tests.ps1
│   ├── State/                        # Runtime state (gitignored)
│   ├── README.md                     # Scanner module reference
│   └── COMPLIANCE-OTHER-ASSETS.md   # Guide for member servers, workstations, Linux
├── WebApp/
│   ├── app.py                        # Flask application
│   ├── report_generator.py           # PDF (ReportLab) + CSV generation
│   ├── requirements.txt
│   └── templates/
│       ├── base.html
│       ├── index.html
│       └── results.html
├── DEPLOYMENT.md                     # Jump server installation guide
└── DEPLOYMENT-OFFLINE.md            # Air-gapped / no-internet deployment guide
```

---

## Quick start

### Prerequisites

- Windows Server 2016+ jump server (not the DC itself)
- PowerShell 5.1+ (7+ recommended for parallel discovery)
- WinRM reachable from the jump server to target hosts (TCP 5985/5986)
- gMSA with least-privilege rights on all targets (see [DEPLOYMENT-OFFLINE.md](DEPLOYMENT-OFFLINE.md))

### 1. Configure

Edit `DCAnomalyAgent/Config/settings.psd1`:

```powershell
DomainControllers = @('dc01.contoso.com','dc02.contoso.com')
```

Add Teams webhook URL and SharePoint app registration details (no secrets — cert thumbprint only).

### 2. Anomaly scan (dry run)

```powershell
cd DCAnomalyAgent
.\Run-AnomalyScan.ps1 -DryRun
```

### 3. Compliance scan

```powershell
# All asset types
.\Run-AnomalyScan.ps1 -ComplianceScan -DryRun

# Specific asset type and severity
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType MemberServer -SeverityFilter Critical,High

# Linux hosts
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType Linux
```

### 4. Asset discovery

```powershell
# From Active Directory
.\Run-Discovery.ps1 -FromAD

# Network sweep + AD, combined
.\Run-Discovery.ps1 -FromAD -Cidr '10.0.0.0/24','10.0.1.0/24'
```

Outputs `State/asset-inventory.json`, `asset-inventory.csv`, and a ready-to-paste `settings.psd1` snippet.

### 5. Web UI

```powershell
cd ..\WebApp
pip install -r requirements.txt
python app.py
# Browse to http://localhost:5000
```

---

## Supported asset types

| Asset type | Transport | Framework file | Notes |
|---|---|---|---|
| `DomainController` | WinRM (Kerberos) | `compliance-frameworks.psd1` | Password policy, audit, LDAP signing, Kerberos, AD Recycle Bin… |
| `MemberServer` | WinRM | `compliance-endpoints.psd1` | Local admins, LAPS, RDP NLA, Defender, SMBv1, patching, firewall |
| `Workstation` | WinRM | `compliance-endpoints.psd1` | Same as MemberServer + BitLocker |
| `Linux` | SSH (key-based) | `compliance-linux.psd1` | PermitRootLogin, PasswordAuth, auditd, SELinux/AppArmor, patch age |

---

## Compliance frameworks

| Framework | Coverage |
|---|---|
| CIS Benchmarks | Windows Server (DC + member server), Workstation, Distribution-Independent Linux |
| NIST SP 800-53 | Rev 5 control references on every check |
| ISO 27001 | Annex A references on every check |

All three frameworks are tagged on every control — filter by framework or severity at scan time:

```powershell
.\Run-AnomalyScan.ps1 -ComplianceScan -FrameworkFilter CIS -SeverityFilter Critical,High
```

---

## Scheduling

```powershell
cd DCAnomalyAgent\Install
.\Register-ScheduledTask.ps1 -GmsaAccount 'CONTOSO\svc-dcagent$'
```

Creates two Scheduled Tasks under the gMSA:

| Task | Schedule | Command |
|---|---|---|
| `DCAnomalyAgent-Scan` | 06:00, 14:00, 22:00 | Anomaly scan only |
| `DCAnomalyAgent-Scan-Compliance` | Daily 07:00 | Anomaly + full compliance scan |

---

## Security model

- **No stored credentials.** The gMSA's Kerberos ticket is used for all WinRM connections. The SharePoint/Graph cert is installed in the gMSA's certificate store; only the thumbprint is in config.
- **Least privilege.** The gMSA needs: Remote Management Users, Event Log Readers, Remote Registry read access, and `SeSecurityPrivilege` (for `auditpol /get`). No local admin required. See [DEPLOYMENT-OFFLINE.md](DEPLOYMENT-OFFLINE.md) for the full GPO configuration.
- **Linux scans run without root.** Controls use `sshd -T`, world-readable `/etc/login.defs`, and `systemctl is-active` — no sudo required unless you add custom privilege-requiring checks.
- **Baseline state** (`State/baseline.json`) and log files are gitignored and written only at runtime.

---

## Running tests

```powershell
cd DCAnomalyAgent
Invoke-Pester .\Tests\ -Output Detailed
```

Pester 5.x required. Tests mock WinRM and AD cmdlets — no live DC needed.

---

## Deployment guides

| Guide | When to use |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Jump server with internet access |
| [DEPLOYMENT-OFFLINE.md](DEPLOYMENT-OFFLINE.md) | Air-gapped / no-internet environment — includes all download URLs and full GPO least-privilege config |
| [DCAnomalyAgent/COMPLIANCE-OTHER-ASSETS.md](DCAnomalyAgent/COMPLIANCE-OTHER-ASSETS.md) | Extending compliance scans to member servers, workstations, and Linux hosts |

---

## Adding custom controls

Append to any `Config/compliance-*.psd1` file — no code changes needed. Example:

```powershell
@{
    Id          = 'EP-CUSTOM-001'
    Title       = 'Screen lock timeout <= 15 minutes'
    AppliesTo   = @('Workstation')
    Frameworks  = @{ CIS = 'CIS-L1 2.3.7.x'; NIST = 'AC-11'; ISO = 'A.11.2.8' }
    Severity    = 'Medium'
    Check       = {
        param($ComputerName)
        $v = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
        }
        [pscustomobject]@{ Actual = "$v sec"; Pass = $v -gt 0 -and $v -le 900 }
    }
    Expected    = 'InactivityTimeoutSecs between 1 and 900'
    Remediation = 'Set via GPO: Interactive logon: Machine inactivity limit = 900.'
}
```

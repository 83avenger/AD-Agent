# AD-Agent — Step-by-Step Implementation Guide

This is the complete, end-to-end guide to deploying AD-Agent from a clean Windows
jump server through to a running, scheduled, dashboard-backed security operations
platform. Follow the phases in order; each step lists the exact commands and the
verification to confirm it worked before moving on.

> **Companion docs:** [`DEPLOYMENT.md`](DEPLOYMENT.md) (short-form install),
> [`DEPLOYMENT-OFFLINE.md`](DEPLOYMENT-OFFLINE.md) (air-gapped + full GPO XML),
> [`README.md`](README.md) (feature reference),
> [`DCAnomalyAgent/COMPLIANCE-OTHER-ASSETS.md`](DCAnomalyAgent/COMPLIANCE-OTHER-ASSETS.md)
> (member servers / workstations / Linux). This guide ties them together into one
> ordered runbook.

---

## Contents

1. [Architecture recap](#1-architecture-recap)
2. [Phase 0 — Prerequisites & sizing](#phase-0--prerequisites--sizing)
3. [Phase 1 — Jump server base setup](#phase-1--jump-server-base-setup)
4. [Phase 2 — Deploy the code](#phase-2--deploy-the-code)
5. [Phase 3 — gMSA & least-privilege rights](#phase-3--gmsa--least-privilege-rights)
6. [Phase 4 — Core configuration (`settings.psd1`)](#phase-4--core-configuration-settingspsd1)
7. [Phase 5 — Reporting: Teams, Email, SharePoint](#phase-5--reporting-teams-email-sharepoint)
8. [Phase 6 — Anomaly scan bring-up](#phase-6--anomaly-scan-bring-up)
9. [Phase 7 — Compliance scanning (CIS/NIST/ISO/HIPAA/OWASP)](#phase-7--compliance-scanning)
10. [Phase 8 — Zero-day telemetry](#phase-8--zero-day-telemetry)
11. [Phase 9 — Certificate expiry scanning](#phase-9--certificate-expiry-scanning)
12. [Phase 10 — Asset discovery](#phase-10--asset-discovery)
13. [Phase 11 — Web UI & rotating dashboard](#phase-11--web-ui--rotating-dashboard)
14. [Phase 12 — Scheduled tasks](#phase-12--scheduled-tasks)
15. [Phase 13 — End-to-end validation](#phase-13--end-to-end-validation)
16. [Phase 14 — Operations & maintenance](#phase-14--operations--maintenance)
17. [Troubleshooting](#troubleshooting)
18. [Implementation checklist](#implementation-checklist)

---

## 1. Architecture recap

```
                          ┌─────────────────────────────────────────────┐
                          │  Jump / Management Server (Windows 2019+)    │
                          │                                              │
   Scheduled Tasks ──────▶│  Run-AnomalyScan.ps1  (runs as gMSA)         │
   (gMSA identity)        │    ├─ Collectors  ── WinRM/Kerberos ─────────┼──▶ DCs, member servers,
                          │    ├─ Detectors                              │    workstations
                          │    ├─ Compliance engine ── WinRM / SSH ──────┼──▶ Linux hosts (SSH)
                          │    ├─ Zero-day  ── HTTPS ────────────────────┼──▶ CISA KEV / NVD
                          │    ├─ Certificates ── WinRM / TLS / certutil ┼──▶ stores / endpoints / CA
                          │    └─ Reporting ── Teams / Graph / SMTP ─────┼──▶ Teams, SharePoint, email
                          │                                              │
                          │  State/latest-scan.json  ◀── merged snapshot │
                          │  WebApp (Flask + Waitress) ── /dashboard ────┼──▶ NOC wall display
                          └─────────────────────────────────────────────┘
```

Key principles you are implementing:

- **No stored passwords.** WinRM auth uses the gMSA's Kerberos ticket; Graph uses a
  certificate thumbprint only.
- **Least privilege.** The gMSA is *not* a local admin anywhere — rights are granted
  by GPO (Remote Management Users, Event Log Readers, Remote Registry, `SeSecurityPrivilege`).
- **One engine, many scan types.** Anomaly, compliance, zero-day, and certificate
  scans share collectors/reporting and each write into one dashboard snapshot.

---

## Phase 0 — Prerequisites & sizing

| Requirement | Detail |
|---|---|
| Jump server OS | Windows Server 2019 or 2022 (2016 works; 2019+ needed for the built-in OpenSSH client used by Linux checks) |
| PowerShell | 5.1 minimum; **7.x recommended** (parallel network discovery). Both can coexist |
| RAM / CPU | 4 vCPU / 8 GB is ample for a few hundred hosts |
| Domain join | Jump server must be domain-joined |
| Network | WinRM (TCP 5985/5986) to targets; 636 for DC LDAPS cert checks; 443/587/3389 to any TLS endpoints you probe; outbound HTTPS to `cisa.gov` + `services.nvd.nist.gov`; outbound HTTPS to `login.microsoftonline.com` + `graph.microsoft.com` if using SharePoint |
| Accounts you'll need | Domain Admin (one-time gMSA + GPO setup), an Azure AD app registration (only if using SharePoint), a Teams incoming webhook (optional), an SMTP relay (optional) |
| Python | 3.9+ only if you deploy the Web UI / dashboard |

**Decide up front** which capabilities you're turning on (anomaly is mandatory; the
rest are optional): Compliance, Zero-day, Certificates, Web UI/Dashboard, and which
reporting channels (Teams / Email / SharePoint). You can enable more later.

---

## Phase 1 — Jump server base setup

**Step 1.1 — Install PowerShell 7 (recommended).**
```powershell
winget install --id Microsoft.PowerShell -e
# Offline: download the MSI from https://github.com/PowerShell/PowerShell/releases and install
pwsh -v
```

**Step 1.2 — Set execution policy for the machine (scripts are unsigned locally).**
```powershell
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
```

**Step 1.3 — Confirm WinRM client works from the jump server to a DC.**
```powershell
Test-WSMan -ComputerName dc01.contoso.com
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock { $env:COMPUTERNAME }
```
If this fails, fix WinRM/Kerberos before continuing — every scan depends on it.

**Step 1.4 — Install the RSAT ActiveDirectory & GroupPolicy modules** (needed by some
collectors and AD discovery):
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

**Step 1.5 — (Linux checks only) Confirm the OpenSSH client is present.**
```powershell
Get-WindowsCapability -Online -Name OpenSSH.Client* | Select-Object Name, State
# If not Installed:
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
ssh -V
```

✅ **Verify Phase 1:** `pwsh -v` prints 7.x, `Test-WSMan` against a DC succeeds, and
`Get-ADDomainController -Filter *` returns your DCs.

---

## Phase 2 — Deploy the code

**Step 2.1 — Choose an install root.** This guide uses `C:\Apps\AD-Agent`.

**Step 2.2 — Get the files onto the server.**
```powershell
# Option A: git (internet-connected)
git clone https://github.com/83avenger/AD-Agent.git C:\Apps\AD-Agent

# Option B: air-gapped — copy the repo zip via approved media, then:
Expand-Archive .\AD-Agent.zip -DestinationPath C:\Apps\
```

**Step 2.3 — Confirm the layout.**
```powershell
Get-ChildItem C:\Apps\AD-Agent\DCAnomalyAgent -Recurse -Depth 1 |
    Select-Object FullName
```
You should see `Run-AnomalyScan.ps1`, `Run-Discovery.ps1`, `Config\`, `Modules\`,
`Install\`, `Tests\`.

**Step 2.4 — Unblock files copied from another machine** (removes the MOTW flag):
```powershell
Get-ChildItem C:\Apps\AD-Agent -Recurse | Unblock-File
```

**Step 2.5 — (Optional) Run the unit tests** to prove the modules load cleanly:
```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope AllUsers -Force   # if not present
cd C:\Apps\AD-Agent\DCAnomalyAgent
Invoke-Pester .\Tests\ -Output Detailed
```

✅ **Verify Phase 2:** Pester reports all tests passing (or at minimum, the modules
import with no errors).

---

## Phase 3 — gMSA & least-privilege rights

Run **Steps 3.1–3.4 as a Domain Admin**, once. (For the full GPO XML and an offline
walkthrough, see `DEPLOYMENT-OFFLINE.md`.)

**Step 3.1 — Ensure a KDS root key exists** (only needed once per forest):
```powershell
# If none exists yet (lab: effective immediately; prod already has one):
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
```

**Step 3.2 — Create the gMSA and allow the jump server to use it.**
```powershell
New-ADServiceAccount -Name 'svc-dcAgent' `
    -DNSHostName 'svc-dcAgent.contoso.com' `
    -PrincipalsAllowedToRetrieveManagedPassword 'JUMP01$'
```

**Step 3.3 — Install the gMSA on the jump server** (run on the jump server):
```powershell
Install-ADServiceAccount -Identity 'svc-dcAgent'
Test-ADServiceAccount -Identity 'svc-dcAgent'   # must return True
```

**Step 3.4 — Grant least-privilege rights via GPO.** Create/link a GPO to the OUs
containing your DCs, member servers, and workstations that grants the gMSA (via a
group, e.g. `GG-AD-Agent-Scanners`, that contains `svc-dcAgent$`):

| Right | Where | Why |
|---|---|---|
| Member of **Remote Management Users** | Restricted Groups / LGPO | WinRM access |
| Member of **Event Log Readers** | Restricted Groups | Read the Security log |
| **Remote Registry** service = Automatic + running | Services | Registry-based compliance checks |
| **Manage auditing and security log** (`SeSecurityPrivilege`) | User Rights Assignment | `auditpol /get` checks |
| **Log on as a batch job** | User Rights Assignment (jump server) | Run the Scheduled Task |

> For Linux targets there is no GPO — instead create an unprivileged SSH user and
> install the jump server's public key (Phase 9 / `COMPLIANCE-OTHER-ASSETS.md`).

✅ **Verify Phase 3:** After GPO has applied (`gpupdate /force` on a test target),
from the jump server run:
```powershell
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock {
    Get-WinEvent -LogName Security -MaxEvents 1
}
```
It should return an event without an access-denied error.

---

## Phase 4 — Core configuration (`settings.psd1`)

Edit `C:\Apps\AD-Agent\DCAnomalyAgent\Config\settings.psd1`. Work top to bottom.

**Step 4.1 — Domain controllers and lookback.**
```powershell
DomainControllers = @('dc01.contoso.com','dc02.contoso.com')
LookbackHours     = 9      # slightly larger than the 8h gap between anomaly runs
```

**Step 4.2 — Privileged groups & thresholds** — accept the defaults unless your
naming differs (e.g. localized group names):
```powershell
PrivilegedGroups = @('Domain Admins','Enterprise Admins','Schema Admins',
                     'Administrators','Account Operators','Backup Operators')
FailedLogonBurstThreshold = 5
```

**Step 4.3 — Assets block** — this drives compliance *and* certificate host
resolution. List hosts explicitly or set `DiscoverFromAD = $true`:
```powershell
Assets = @{
    DomainController = @{ Hosts = @();                            DiscoverFromAD = $true  }
    MemberServer     = @{ Hosts = @('app01.contoso.com','sql01'); DiscoverFromAD = $false }
    Workstation      = @{ Hosts = @();                            DiscoverFromAD = $false }
    Linux            = @{ Hosts = @('web01.contoso.com'); DiscoverFromAD = $false
                          Ssh = @{ User='svc-scan'; KeyPath="$PSScriptRoot\..\State\ssh\id_ed25519"; Port=22 } }
    WebApplication   = @{ Hosts = @('https://portal.contoso.com'); DiscoverFromAD = $false }
}
```

**Step 4.4 — Leave the framework list as-is** (all five files) unless you want to
scope down:
```powershell
FrameworkPath = @(
    "$PSScriptRoot\compliance-frameworks.psd1"   # DC/domain
    "$PSScriptRoot\compliance-endpoints.psd1"    # servers/workstations
    "$PSScriptRoot\compliance-linux.psd1"        # Linux (SSH)
    "$PSScriptRoot\compliance-hipaa.psd1"        # HIPAA Security Rule
    "$PSScriptRoot\compliance-owasp.psd1"        # OWASP Top 10 (WebApplication)
)
```

> **Do not put secrets in this file.** It holds hostnames, IDs, a cert *thumbprint*,
> and a webhook URL only. Passwords/keys live in the certificate store, the gMSA, or
> a SecureString export.

✅ **Verify Phase 4:** the file parses cleanly:
```powershell
Import-PowerShellDataFile C:\Apps\AD-Agent\DCAnomalyAgent\Config\settings.psd1 | Out-Null
'settings.psd1 OK'
```

---

## Phase 5 — Reporting: Teams, Email, SharePoint

Enable only the channels you use. All three fail independently — a broken channel
never aborts a scan.

### 5A — Microsoft Teams (simplest)

**Step 5A.1** — In Teams, create an **Incoming Webhook** on the target channel and
copy the URL.
**Step 5A.2** — Set it in config:
```powershell
Reporting = @{ Teams = @{ Enabled = $true; WebhookUrl = 'https://contoso.webhook.office.com/…' } }
```

### 5B — Email (SMTP)

**Step 5B.1** — Fill the `Reporting.Email` block:
```powershell
Email = @{
    Enabled = $true
    To = @('secops@contoso.com'); From = 'ad-agent@contoso.com'
    SmtpServer = 'smtp.contoso.com'; Port = 587; UseSsl = $true
    CredentialUser = ''; CredentialPassword = ''   # empty = anonymous relay
    MinSeverity = 'High'; SendOnNoFindings = $false
}
```
**Step 5B.2 — If your relay requires auth,** store the password as a SecureString
export (never plaintext) generated *as the gMSA/service context on this machine*:
```powershell
Read-Host 'SMTP password' -AsSecureString | ConvertFrom-SecureString
# paste the long string into CredentialPassword, and set CredentialUser
```
**Step 5B.3 — Smoke-test without running a scan:**
```powershell
cd C:\Apps\AD-Agent\DCAnomalyAgent
.\Run-AnomalyScan.ps1 -TestEmail
```
✅ A test message arrives in the `To` inbox.

### 5C — SharePoint (Microsoft Graph)

**Step 5C.1** — Register an Azure AD app; grant **Sites.ReadWrite.All** (application
permission, admin-consented). Create a **certificate**, upload the public key to the
app, and install the cert (with private key) into a store the gMSA can read
(`LocalMachine\My`).
**Step 5C.2** — Create three SharePoint lists (Anomalies, Compliance, Certificates)
and note their IDs.
**Step 5C.3** — Fill the block:
```powershell
SharePoint = @{
    Enabled = $true
    TenantId = '<guid>'; ClientId = '<guid>'; CertificateThumbprint = '<thumbprint>'
    SiteId = '<site-id>'
    ListId = '<anomaly-list-id>'
    ComplianceListId = '<compliance-list-id>'
    CertificateListId = '<certificate-list-id>'
}
```

✅ **Verify Phase 5:** `-TestEmail` succeeds (5B); a later real scan posts a card to
Teams (5A) and items to the lists (5C).

---

## Phase 6 — Anomaly scan bring-up

The anomaly scan is the mandatory core. Bring it up in **dry-run** first (no alerts
sent).

**Step 6.1 — Dry run:**
```powershell
cd C:\Apps\AD-Agent\DCAnomalyAgent
.\Run-AnomalyScan.ps1 -DryRun
```
Read the console table. On first run the UEBA baseline is empty (cold-start guard
suppresses deviations) — that's expected.

**Step 6.2 — Generate a test signal** (optional) — deliberately fail a few logons
against a lab DC, then re-run `-DryRun` and confirm a `FailedLogonBurst_*` finding.

**Step 6.3 — First live run** (sends to enabled channels):
```powershell
.\Run-AnomalyScan.ps1
```

**Step 6.4 — Confirm state was written:**
```powershell
Get-ChildItem .\State\   # baseline.json, scan.log, latest-scan.json
Get-Content .\State\scan.log -Tail 20
```

✅ **Verify Phase 6:** `baseline.json` exists and grows across runs; findings (if any)
appear in Teams/email/SharePoint.

---

## Phase 7 — Compliance scanning

**Step 7.1 — Dry-run all asset types:**
```powershell
.\Run-AnomalyScan.ps1 -ComplianceScan -DryRun
```

**Step 7.2 — Scope by asset type / framework / severity as needed:**
```powershell
# Member servers, only Critical+High
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType MemberServer -SeverityFilter Critical,High

# HIPAA audit prep across everything
.\Run-AnomalyScan.ps1 -ComplianceScan -FrameworkFilter HIPAA

# OWASP web posture (agentless, no creds) against specific URLs
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType WebApplication `
    -TargetHostsOverride 'https://portal.contoso.com,https://hr.contoso.com'
```

**Step 7.3 — Linux checks** — first create the SSH scan user + key (see
`COMPLIANCE-OTHER-ASSETS.md`), then:
```powershell
ssh-keygen -t ed25519 -f .\State\ssh\id_ed25519 -N '""'
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType Linux -DryRun
```

**Step 7.4 — Review the saved report:**
```powershell
Get-Content .\State\compliance-report.md
```

✅ **Verify Phase 7:** the markdown report lists gaps with framework citations and
remediation; a live run (no `-DryRun`) posts the scorecard to Teams/email.

---

## Phase 8 — Zero-day telemetry

**Step 8.1 — Tune the product watch list** (`Config\zeroday-products.psd1`) to your
estate:
```powershell
@{ Products = @('Microsoft Windows','Windows Server','Microsoft Active Directory','Kerberos')
   NvdApiKey = ''      # optional free key: nvd.nist.gov/developers/request-an-api-key
   MaxAgeDays = 30 }
```

**Step 8.2 — Dry run (fetches CISA KEV, prints matches):**
```powershell
.\Run-AnomalyScan.ps1 -ZeroDayScan -DryRun
```

**Step 8.3 — Confirm the feed cached and dedup works:**
```powershell
Test-Path .\State\kev-cache.json                # True after first run
.\Run-AnomalyScan.ps1 -ZeroDayScan -DryRun      # second run → 0 *new* alerts
```

**Step 8.4 — Air-gapped?** Set `ZeroDay.Offline = $true` in `settings.psd1` and copy a
freshly-downloaded KEV JSON to `.\State\kev-cache.json` on a schedule (the file lives
at `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).

✅ **Verify Phase 8:** first dry run lists matches; second run shows 0 new; a live run
alerts only on newly-added CVEs.

---

## Phase 9 — Certificate expiry scanning

Scans three sources and flags anything expiring within `ThresholdDays` (default 90).

**Step 9.1 — Confirm the `Certificates` config block** in `settings.psd1`:
```powershell
Certificates = @{
    Enabled = $true; ThresholdDays = 90
    ScanAssetTypes = @('DomainController','MemberServer','Workstation')
    MachineStores  = @('My','CA','WebHosting')
    EndpointsPath  = "$PSScriptRoot\certificate-endpoints.psd1"
    ProbeDcLdaps = $true; ProbeWebApps = $true
    Adcs = @{ Enabled = $false; CaConfig = 'CA01.contoso.com\Contoso-Issuing-CA' }
    ReportOutputPath = "$PSScriptRoot\..\State\certificate-report.md"
}
```

**Step 9.2 — Add extra TLS endpoints** (load balancers, appliances, non-Windows
services) in `Config\certificate-endpoints.psd1`:
```powershell
@{ Endpoints = @(
    @{ Host='vpn.contoso.com'; Port=443;  Name='VPN' }
    @{ Host='mail.contoso.com';Port=587;  Name='SMTP submission' }
) }
```

**Step 9.3 — (Optional) Enable the CA source** — set `Adcs.Enabled = $true` and a
valid `CaConfig`. The gMSA needs read access to the CA. Note `certutil` column names
vary by OS/locale; validate the output on your CA.

**Step 9.4 — Dry run:**
```powershell
.\Run-AnomalyScan.ps1 -CertificateScan -DryRun
Get-Content .\State\certificate-report.md
```

✅ **Verify Phase 9:** the report lists near-expiry certs with days-remaining and
severity; certs found in multiple places collapse into one row listing all locations;
unreachable endpoints show as collection errors, not crashes.

---

## Phase 10 — Asset discovery

Use this instead of hand-maintaining host lists.

**Step 10.1 — From Active Directory:**
```powershell
.\Run-Discovery.ps1 -FromAD
```
**Step 10.2 — Network sweep (finds non-domain / Linux / appliances):**
```powershell
.\Run-Discovery.ps1 -Cidr '10.0.0.0/24','10.0.1.0/24'
# Combined + de-duplicated:
.\Run-Discovery.ps1 -FromAD -Cidr '10.0.0.0/24'
```
**Step 10.3 — Fold results into config** — open
`.\State\discovered-assets.psd1.txt` and paste the generated block into the `Assets`
section of `settings.psd1`.

> The network sweep is an **active port probe** — get authorization before scanning
> ranges you don't own.

✅ **Verify Phase 10:** `State\asset-inventory.csv` lists hosts with a classification
(DomainController / MemberServer / Workstation / Linux / NetworkDevice).

---

## Phase 11 — Web UI & rotating dashboard

**Step 11.1 — Install Python 3.9+** (or use an existing install).

**Step 11.2 — Create a venv and install dependencies:**
```powershell
cd C:\Apps\AD-Agent\WebApp
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Air-gapped: pip download on an internet host, then
#   pip install --no-index --find-links .\wheels -r requirements.txt
```

**Step 11.3 — Run it (dev):**
```powershell
python app.py
# Browse http://localhost:5000  ·  Dashboard: http://localhost:5000/dashboard
```

**Step 11.4 — Run it as a service (prod)** with Waitress behind NSSM. `start.py --prod`
serves via Waitress (falls back to the dev server if waitress is missing):
```powershell
pip install waitress
nssm install AD-Agent-Web "C:\Apps\AD-Agent\WebApp\.venv\Scripts\python.exe" `
    "C:\Apps\AD-Agent\WebApp\start.py --prod --host 127.0.0.1 --port 5000"
nssm set AD-Agent-Web AppDirectory C:\Apps\AD-Agent\WebApp
nssm set AD-Agent-Web ObjectName 'CONTOSO\svc-dcAgent$' ''   # run as the gMSA
nssm start AD-Agent-Web
```
> Bind to `127.0.0.1` and front with an IIS/ARR reverse proxy for TLS + Windows auth
> (the app has no built-in authentication).

**Step 11.5 — Understand the dashboard data flow.** The dashboard reads
`DCAnomalyAgent\State\latest-scan.json`, which every scan *merges* into (each
scheduled task contributes its own section). Until a scan has run, the dashboard
shows a **DEMO DATA** badge with sample content.

**Step 11.6 — Point a wall display** at `/dashboard`. It rotates 4 screens every 13s;
`Space` pauses, `←`/`→` navigate, `F` fullscreen, hover pauses. It re-polls
`/api/dashboard` every 3 minutes.

> **Security:** the web app has no authentication of its own. Bind it to localhost or
> an internal-only interface and front it with a reverse proxy (IIS ARR) enforcing
> Windows auth / IP restrictions before exposing it to users.

✅ **Verify Phase 11:** `http://<jump>:5000/` loads the scan form; `/dashboard` rotates
through Overview → Compliance → Threats → Certificates; after a real scan the DEMO
badge disappears.

---

## Phase 12 — Scheduled tasks

**Step 12.1 — Register all tasks under the gMSA** (run as Domain Admin on the jump
server):
```powershell
cd C:\Apps\AD-Agent\DCAnomalyAgent\Install
.\Register-ScheduledTask.ps1 -GmsaAccount 'CONTOSO\svc-dcAgent$'
```

This creates:

| Task | Schedule | Arguments |
|---|---|---|
| `DCAnomalyAgent-Scan` | 06:00, 14:00, 22:00 | *(anomaly only)* |
| `DCAnomalyAgent-Scan-Compliance` | Daily 07:00 | `-ComplianceScan -SkipAnomalyScan` |
| `DCAnomalyAgent-Scan-ZeroDay` | Daily 08:00 | `-ZeroDayScan -SkipAnomalyScan` |
| `DCAnomalyAgent-Scan-Certificates` | Daily 09:00 | `-CertificateScan -SkipAnomalyScan` |

**Step 12.2 — Why `-SkipAnomalyScan`?** The three secondary tasks skip the event-log
anomaly scan so they don't re-run and re-report what the dedicated 3×/day task already
covers. Each still writes its own section into the dashboard snapshot.

**Step 12.3 — Trigger one task manually to confirm it runs as the gMSA:**
```powershell
Start-ScheduledTask -TaskName 'DCAnomalyAgent-Scan-Compliance'
Get-ScheduledTaskInfo -TaskName 'DCAnomalyAgent-Scan-Compliance'   # LastTaskResult should be 0
```

✅ **Verify Phase 12:** all four tasks show **Ready**; a manual run returns
`LastTaskResult = 0` and appends to `State\scan.log`.

---

## Phase 13 — End-to-end validation

Run this sequence and tick each item:

```powershell
cd C:\Apps\AD-Agent\DCAnomalyAgent
.\Run-AnomalyScan.ps1 -DryRun                                  # 1 anomaly engine
.\Run-AnomalyScan.ps1 -ComplianceScan -DryRun                 # 2 compliance engine
.\Run-AnomalyScan.ps1 -ZeroDayScan -DryRun                    # 3 zero-day feed
.\Run-AnomalyScan.ps1 -CertificateScan -DryRun                # 4 certificate scan
.\Run-AnomalyScan.ps1 -TestEmail                              # 5 email path
.\Run-AnomalyScan.ps1 -ComplianceScan                         # 6 live Teams/SharePoint
Get-Content .\State\latest-scan.json | ConvertFrom-Json | Format-List   # 7 snapshot merged
```

1. Anomaly table prints, `baseline.json` present.
2. Compliance gaps print with framework citations.
3. Zero-day matches print; `kev-cache.json` present.
4. Expiring certs print; `certificate-report.md` present.
5. Test email received.
6. Teams card + SharePoint items appear.
7. Snapshot contains **all** sections (Anomalies, ComplianceGaps/Summary,
   ExpiringCertificates, ZeroDays, Freshness).

Then open **`/dashboard`** and confirm all four screens show real (non-demo) data.

---

## Phase 14 — Operations & maintenance

| Cadence | Task |
|---|---|
| Daily | Glance at `/dashboard`; check Teams/email alerts |
| Weekly | Review `State\scan.log` for `ERROR`/`WARN`; confirm all 4 scheduled tasks `LastTaskResult = 0` |
| Monthly | Review compliance score trend; re-run discovery to catch new hosts; rotate the SSH scan key if used |
| Quarterly | Rotate the Graph auth certificate before expiry (AD-Agent will actually flag its *own* cert nearing expiry in Phase 9!); review privileged-group list and framework scope |
| As needed | Air-gapped: refresh `kev-cache.json`; add new TLS endpoints / custom controls |

**Log & state locations** (all under `DCAnomalyAgent\State\`, gitignored):
`scan.log`, `baseline.json`, `kev-cache.json`, `zeroday-baseline.json`,
`compliance-report.md`, `certificate-report.md`, `latest-scan.json`,
`asset-inventory.{json,csv}`.

**Adding custom checks** — append a control block to any `Config\compliance-*.psd1`
(pattern in `README.md` / `COMPLIANCE-OTHER-ASSETS.md`); no code changes needed.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Access is denied` from a collector | gMSA not in Event Log Readers / Remote Management Users on that host, or GPO not applied (`gpupdate /force`) |
| `Test-ADServiceAccount` returns False | Jump server not in `PrincipalsAllowedToRetrieveManagedPassword`; re-run `Install-ADServiceAccount` |
| Scheduled task `LastTaskResult` ≠ 0 | Missing "Log on as a batch job" for the gMSA; check `State\scan.log` and Task Scheduler history |
| WinRM "cannot process the request" | Kerberos/SPN issue — use FQDNs everywhere; confirm `Test-WSMan <fqdn>` |
| Teams card not posting | Webhook URL wrong/expired; test with a manual `Invoke-RestMethod` POST |
| SharePoint writes fail | Cert not readable by the gMSA, app lacks admin-consented `Sites.ReadWrite.All`, or wrong `SiteId/ListId` |
| Email fails | Relay requires auth (set `CredentialUser`/`CredentialPassword`) or blocks the `From`; test with `-TestEmail` |
| Zero-day fetch fails | Outbound HTTPS to `cisa.gov` blocked → use `Offline = $true` + cached JSON |
| Cert TLS probe always errors | Port blocked from the jump server, or service down — expected for unreachable hosts (recorded as collection errors) |
| ADCS returns nothing | `certutil` column names differ on your CA/OS/locale; validate `certutil -config <CA> -view` output manually |
| Dashboard stuck on DEMO DATA | No `State\latest-scan.json` yet (run any scan), or the web service can't read the State folder (path/permissions) |
| Dashboard shows one section only | Only one scan type has run — let the other scheduled tasks fire (the snapshot merges over time) |

---

## Implementation checklist

- [ ] **Phase 1** PowerShell 7, execution policy, WinRM to a DC verified, RSAT installed
- [ ] **Phase 2** Code deployed to `C:\Apps\AD-Agent`, files unblocked, Pester passing
- [ ] **Phase 3** gMSA created + installed (`Test-ADServiceAccount` = True), least-priv GPO applied
- [ ] **Phase 4** `settings.psd1` filled (DCs, Assets, frameworks) and parses
- [ ] **Phase 5** At least one reporting channel enabled and tested
- [ ] **Phase 6** Anomaly dry run + live run OK; baseline written
- [ ] **Phase 7** Compliance dry run OK across intended asset types (incl. Linux/Web if used)
- [ ] **Phase 8** Zero-day fetch + dedup verified (or offline cache in place)
- [ ] **Phase 9** Certificate scan OK; endpoints/CA configured as needed
- [ ] **Phase 10** Discovery run; inventory reviewed / folded into config
- [ ] **Phase 11** Web UI + `/dashboard` reachable and showing live data
- [ ] **Phase 12** All 4 scheduled tasks registered and returning `LastTaskResult = 0`
- [ ] **Phase 13** End-to-end validation sequence all green
- [ ] **Phase 14** Ops cadence agreed; log/state locations documented for the team
```

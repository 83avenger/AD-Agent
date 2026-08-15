# AD-Agent

A one-stop security services platform for Windows/AD environments, built in PowerShell. From a single jump server and a single gMSA it delivers anomaly detection, multi-framework compliance scanning (CIS, NIST, ISO 27001, HIPAA, OWASP), web application posture checks, asset discovery, and zero-day telemetry — with unified reporting to Microsoft Teams, SharePoint, and email, plus a web UI for on-demand scans and PDF/CSV reports.

## Security services at a glance

| Service | What it covers | Entry point |
|---|---|---|
| Threat detection | Failed-logon bursts, lockouts, privileged group changes, GPO drift, UEBA deviations | `Run-AnomalyScan.ps1` |
| Infrastructure compliance | CIS / NIST / ISO / HIPAA controls on DCs, servers, workstations, Linux | `Run-AnomalyScan.ps1 -ComplianceScan` |
| Web application posture | OWASP Top 10 header/TLS/cookie checks on HTTPS endpoints | `Run-AnomalyScan.ps1 -ComplianceScan -AssetType WebApplication` |
| Vulnerability intelligence | CISA KEV + NVD zero-day feed, deduplicated alerts | `Run-AnomalyScan.ps1 -ZeroDayScan` |
| Certificate expiry | Machine stores + TLS endpoints + Enterprise CA, flags certs expiring within 90 days | `Run-AnomalyScan.ps1 -CertificateScan` |
| Software & device inventory | Installed software (name/version/publisher) on every Windows asset, categorized Desktop/Laptop/Server/Domain Controller, cross-referenced against the zero-day watchlist | `Run-AnomalyScan.ps1 -SoftwareInventoryScan` (or folded into `Run-Discovery.ps1` — see below) |
| Asset inventory | AD + network discovery, Desktop/Laptop/Server/DC categorization, online/last-seen status, Cloudflare WARP remote-user range; consolidates across batched subnet scans | `Run-Discovery.ps1` |
| Extended integrations | SNMP (network devices), vendor warranty APIs (device age), MDM (kiosks/managed phones), Cloudflare Zero Trust — opt-in, keys managed from the web UI | `/integrations` (web UI) |
| Reporting & alerting | Teams, SharePoint, email, markdown, PDF/CSV | automatic / web UI |
| Live dashboard | Rotating NOC wall display cycling 6 screens across all scan types | `/dashboard` (web UI) |

---

## Features

| Capability | Detail |
|---|---|
| Anomaly detection | Failed logon bursts, account lockouts, privileged group changes, new accounts elevated to DA within X hours, GPO version drift |
| UEBA baseline | Per-user rolling logon-hour range, source host, and DC profiles; flags deviations after cold-start guard |
| Compliance scanning | CIS Benchmarks, NIST SP 800-53, ISO 27001 Annex A, HIPAA Security Rule, and OWASP Top 10 across DCs, member servers, workstations, Linux hosts, and web applications |
| Asset discovery | AD enumeration + TCP CIDR sweep, incl. a Cloudflare WARP/Zero Trust IP range for remote/home users; categorizes every Windows host as Desktop/Laptop/Server/Domain Controller; stamps a LastSeen timestamp per host for online/offline status; consolidates results across subnets scanned in separate batches instead of overwriting; folds in installed-software collection by default (`-SkipSoftwareInventory` to opt out for a fast first pass) |
| Reporting | Teams Adaptive Card alerts, SharePoint list items (Graph API), **email (SMTP)**, local markdown report, PDF/CSV download via web UI |
| Zero-day telemetry | Pulls CISA KEV catalog + NVD daily; alerts on newly-added CVEs matching your product watch list; deduplicates so each CVE fires only once |
| Certificate expiry | Scans Windows machine stores (WinRM), live TLS endpoints (socket probe), and an Enterprise CA; flags any certificate expiring within a configurable threshold (default 90 days) with severity by days-remaining |
| Software & device inventory | Enumerates installed software (registry Uninstall keys, 64-bit + WOW6432Node) on every configured Windows asset over WinRM; categorizes hosts as Desktop/Laptop (via chassis type) /Server/Domain Controller; optionally flags installed products matching an active CISA KEV/NVD CVE; click a device on the dashboard's Discovery screen to see its full installed-software list |
| Extended integrations | Optional, disabled by default: SNMP polling for Printers/Switches/APs/IP Phones/Cameras/Firewalls; Dell/HP/Lenovo warranty API lookups for device age; MDM (Intune/Jamf/Android Enterprise) for kiosks and managed phones off the LAN; Cloudflare Zero Trust API for richer WARP device identity. The web UI's Integrations page shows setup status and exactly what to request from which team; Vendor Warranty API keys are entered/saved there too, ahead of the integration actually going live |
| Web UI | Flask app — choose scan type, frameworks, severities, target hosts; download PDF or CSV reports |

---

## Repository layout

```
AD-Agent/
├── DCAnomalyAgent/
│   ├── Run-AnomalyScan.ps1          # Scan entry point (anomaly + compliance)
│   ├── Run-Discovery.ps1            # Asset discovery entry point (also folds in software inventory)
│   ├── Get-IntegrationStatus.ps1    # Reports SNMP/vendor-warranty/MDM/Cloudflare config status for the web UI
│   ├── Config/
│   │   ├── settings.psd1            # All configuration (no secrets)
│   │   ├── integration-secrets.json # Vendor API keys saved from the web UI (gitignored, created on first save)
│   │   ├── compliance-frameworks.psd1   # DC/domain controls (CIS/NIST/ISO)
│   │   ├── compliance-endpoints.psd1    # Windows host controls (servers/workstations)
│   │   ├── compliance-linux.psd1        # Linux/SSH controls
│   │   ├── compliance-hipaa.psd1        # HIPAA Security Rule technical safeguards
│   │   └── compliance-owasp.psd1        # OWASP Top 10 web application posture checks
│   ├── Modules/
│   │   ├── DCAnomalyAgent.Collectors.psm1   # WinRM event log + AD collection
│   │   ├── DCAnomalyAgent.Detectors.psm1    # Rule-based anomaly detection
│   │   ├── DCAnomalyAgent.Baseline.psm1     # UEBA rolling baseline (JSON)
│   │   ├── DCAnomalyAgent.Reporting.psm1    # Teams + SharePoint output
│   │   ├── DCAnomalyAgent.Compliance.psm1   # Compliance engine
│   │   ├── DCAnomalyAgent.Discovery.psm1    # Asset discovery (AD + network, incl. Cloudflare WARP)
│   │   ├── DCAnomalyAgent.ZeroDay.psm1      # CISA KEV + NVD zero-day telemetry
│   │   ├── DCAnomalyAgent.Certificates.psm1 # Certificate expiry scanning (stores/TLS/CA)
│   │   ├── DCAnomalyAgent.SoftwareInventory.psm1 # Installed software + device category inventory
│   │   └── DCAnomalyAgent.VendorWarranty.psm1    # Dell/HP/Lenovo warranty API lookups for device age
│   ├── Config/
│   │   ├── zeroday-products.psd1        # Vendor/product watch list for zero-day alerts
│   │   └── certificate-endpoints.psd1  # Extra TLS endpoints to probe for cert expiry
│   ├── Install/
│   │   └── Register-ScheduledTask.ps1   # Registers gMSA-run Scheduled Tasks (incl. zero-day)
│   ├── Tests/
│   │   ├── Detectors.Tests.ps1
│   │   ├── Baseline.Tests.ps1
│   │   ├── Compliance.Tests.ps1
│   │   ├── Discovery.Tests.ps1
│   │   ├── ZeroDay.Tests.ps1
│   │   ├── SoftwareInventory.Tests.ps1
│   │   └── Reporting.Email.Tests.ps1
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
│       ├── results.html
│       ├── dashboard.html            # Rotating NOC dashboard (6 screens, incl. Discovery)
│       ├── integrations.html         # Integration status + what-to-request-from-which-team
│       └── vendor_warranty.html      # Save Dell/HP/Lenovo API keys
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

# Scan subnets in batches over separate runs — results accumulate, they don't overwrite
.\Run-Discovery.ps1 -Cidr '10.15.2.0/24'
.\Run-Discovery.ps1 -Cidr '10.15.3.0/24'

# Also sweep the Cloudflare WARP range for remote/home users (tagged separately on the dashboard)
.\Run-Discovery.ps1 -Cidr '10.0.0.0/24' -CloudflareWarpCidr '100.96.0.0/12'

# Fast first pass: skip the per-host category probe and software collection
.\Run-Discovery.ps1 -Cidr '10.0.0.0/24' -SkipCategorize -SkipSoftwareInventory
```

Outputs `State/asset-inventory.json`, `asset-inventory.csv`, and a ready-to-paste `settings.psd1` snippet. Every Windows host is categorized as Desktop/Laptop/Server/Domain Controller, stamped with a `LastSeen` timestamp for online/offline status, and — by default — has its installed software collected and cross-referenced against the zero-day watchlist, so discovery alone covers what used to need a separate `-SoftwareInventoryScan` run. Pass `-Fresh` to discard prior results instead of merging.

### 5. Web UI

```powershell
cd ..\WebApp
pip install -r requirements.txt
python app.py
# Browse to http://localhost:5000  ·  Rotating dashboard at http://localhost:5000/dashboard
```

Running it this way (interactively, in an RDP session) ties every WinRM call the web UI makes
to whoever is logged into that session — which can behave differently than the gMSA-driven
scan Scheduled Tasks (a host can work when a domain admin tests it manually but still fail
through the web UI). For production, register it to run under the gMSA at startup instead:

```powershell
cd DCAnomalyAgent\Install
.\Register-WebUIStartup.ps1 -GmsaAccount 'CONTOSO\svc-discoverAgt$' -PythonPath 'C:\Apps\Python312\python.exe'
```

**Self-healing:** the web UI exposes `GET /healthz` (checks: state directory writable, SQLite
asset DB reachable, PowerShell available, disk space, staleness of the last scan/discovery run).
`Register-WebUIStartup.ps1`'s Scheduled Task already restarts the process if it crashes outright,
but that alone won't catch a *hung* process that's still running but no longer answering requests.
Register the watchdog to cover that case too - it polls `/healthz` and restarts the task if it's
down, hung, or reporting a hard failure two checks in a row:

```powershell
.\Watch-WebUIHealth.ps1 -Register -GmsaAccount 'CONTOSO\svc-discoverAgt$'
```

This registers a second Scheduled Task (`AD-Agent-WebUI-Watchdog`) that runs every 5 minutes and
logs its activity to `DCAnomalyAgent\State\watchdog.log`.

**Network scan accelerator (optional):** `Get-NetworkAsset`'s built-in PowerShell scanner works
fine, but `tools/netscan/` has a small Go rewrite of the same port-probe logic that's meaningfully
faster at scale and sidesteps a few real `ForEach-Object -Parallel` limitations this codebase hit
(no `-ArgumentList` support, module functions not crossing the runspace boundary). It's optional -
if Go isn't installed, skip this entirely and Discovery keeps using the PowerShell scanner as
before. To use it: install Go once (https://go.dev/dl/), then build the binary:

```powershell
cd tools\netscan
.\build.ps1
```

This drops `netscan.exe` into `DCAnomalyAgent\bin\`. `Get-NetworkAsset` checks for it
automatically on every Discovery run and uses it when present; if it's ever missing, fails to
run, or produces bad output, Discovery logs a warning and transparently falls back to the
PowerShell scanner - no configuration needed either way. Re-run `build.ps1` after pulling source
changes to `tools/netscan/`.

**Asset store backend (optional):** the discovered-assets store (`WebApp/assets_db.py`) defaults
to SQLite at `DCAnomalyAgent\State\assets.db` — no setup needed, and fine for a single server up
to a few thousand assets. If you outgrow that (3000+ assets, or multiple AD-Agent instances/sites
needing a shared view), point it at PostgreSQL instead:

```powershell
pip install psycopg2-binary
$env:ASSETS_DATABASE_URL = 'postgresql://ad_agent:secret@pgserver.contoso.com:5432/ad_agent'
```

Set that environment variable wherever the web UI's Scheduled Task runs (or in `start.py`'s
environment) and restart it — the table is created automatically on first connection. Leave the
variable unset and nothing changes; this is purely additive. Both backends use the exact same
dedup/upsert semantics (stable dedup key, IP→hostname promotion, never-delete-on-sync), so
switching doesn't change how deduplication behaves, only where the data lives.

**Authentication (recommended before exposing this beyond your own testing):** the web UI has no
built-in login — anyone who can reach its port can trigger scans, delete assets, and view
everything collected. `DCAnomalyAgent\Install\Register-IISReverseProxy.ps1` fronts it with IIS
doing TLS termination + Windows Authentication, restricted to an AD group of your choosing, and
forwards the authenticated username to the app so `WebApp\State\audit.log` records who ran what.
It doesn't change the Flask app itself - IIS proxies to it over localhost. See its `-AllowedGroup`
and `-LockWebUIToLocalhost` parameters, and test in a lab before running against a production
jump server:

```powershell
cd DCAnomalyAgent\Install
.\Register-IISReverseProxy.ps1 -AllowedGroup 'CONTOSO\AD-Agent-Analysts' `
    -LockWebUIToLocalhost -GmsaAccount 'CONTOSO\svc-discoverAgt$' -PythonPath 'C:\Apps\Python312\python.exe'
```

**Metrics export & comparisons (optional):** `GET /metrics` exports scan findings, compliance
score, discovery freshness, and AD-Agent's own `/healthz` checks in Prometheus format — point a
Prometheus scrape config at it and import `grafana/ad-agent-dashboard.json` (panels) and
`grafana/ad-agent-alerts.yml` (alert rules, `promtool check rules`-clean) for long-term trend
graphs and flexible alert routing on top of AD-Agent's own dashboard. See the **vs Prometheus**
page in the nav for the full breakdown of what's native vs. what needs this integration, and
**vs PDQ** for the inventory-tool comparison.

---

## Supported asset types

| Asset type | Transport | Framework file | Notes |
|---|---|---|---|
| `DomainController` | WinRM (Kerberos) | `compliance-frameworks.psd1` | Password policy, audit, LDAP signing, Kerberos, AD Recycle Bin… |
| `MemberServer` | WinRM | `compliance-endpoints.psd1` | Local admins, LAPS, RDP NLA, Defender, SMBv1, patching, firewall |
| `Workstation` | WinRM | `compliance-endpoints.psd1` | Same as MemberServer + BitLocker |
| `Linux` | SSH (key-based) | `compliance-linux.psd1` | PermitRootLogin, PasswordAuth, auditd, SELinux/AppArmor, patch age |
| `WebApplication` | HTTPS (agentless) | `compliance-owasp.psd1` | TLS versions, HSTS/CSP/nosniff/clickjacking headers, cookie flags, banner disclosure |

---

## Compliance frameworks

| Framework | Coverage |
|---|---|
| CIS Benchmarks | Windows Server (DC + member server), Workstation, Distribution-Independent Linux |
| NIST SP 800-53 | Rev 5 control references on every check |
| ISO 27001 | Annex A references on every check |
| HIPAA Security Rule | 45 CFR §164.312/§164.308 technical safeguards — access control, automatic logoff, encryption at rest, audit controls, transmission security (`compliance-hipaa.psd1`) |
| OWASP Top 10:2021 / ASVS v4 | Agentless HTTPS posture checks on web applications (`compliance-owasp.psd1`) |

Controls carry cross-references to multiple frameworks, so one scan serves several audits. Filter by framework or severity at scan time:

```powershell
.\Run-AnomalyScan.ps1 -ComplianceScan -FrameworkFilter CIS -SeverityFilter Critical,High

# HIPAA audit prep across all Windows + Linux assets
.\Run-AnomalyScan.ps1 -ComplianceScan -FrameworkFilter HIPAA

# OWASP posture check on your intranet apps (agentless, no credentials)
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType WebApplication -TargetHostsOverride 'https://portal.contoso.com,https://hr.contoso.com'
```

> The OWASP checks are passive posture checks (headers, TLS, cookies) probed from the jump server — not a DAST scanner. Pair with OWASP ZAP for active testing and feed results into the same SharePoint list.

---

## Email notifications

Enable SMTP email alerts alongside Teams by setting `Reporting.Email.Enabled = $true` in `Config/settings.psd1`:

```powershell
Email = @{
    Enabled    = $true
    To         = @('security-team@contoso.com')
    From       = 'dcagent@contoso.com'
    SmtpServer = 'smtp.contoso.com'
    Port       = 587
    UseSsl     = $true
    # Leave CredentialUser empty for unauthenticated SMTP relay
    CredentialUser     = ''
    CredentialPassword = ''   # ConvertFrom-SecureString export if auth needed
    MinSeverity        = 'High'
    SendOnNoFindings   = $false
}
```

Verify SMTP config without running a real scan:

```powershell
.\Run-AnomalyScan.ps1 -TestEmail
```

Three email functions fire automatically at the same points as Teams:
- Anomaly findings → alert email with findings table
- Compliance scan → scorecard + top-gap table
- Zero-day new CVEs → CVE list with product, due date, ransomware flag

---

## Zero-day telemetry

The zero-day module pulls the **CISA Known Exploited Vulnerabilities (KEV)** catalog (and optionally **NVD CVE API**) daily, cross-references against your product watch list, and alerts only on CVEs **newly added since the last run** — no repeat noise.

### Configure watched products (`Config/zeroday-products.psd1`)

```powershell
@{
    Products  = @('Microsoft Windows','Windows Server','Microsoft Active Directory','Kerberos')
    NvdApiKey = ''      # optional free key: nvd.nist.gov/developers/request-an-api-key
    MaxAgeDays = 30     # only surface entries added within N days (0 = all-time)
}
```

### Run

```powershell
# Zero-day scan only (dry run — no Teams/email, prints to console)
.\Run-AnomalyScan.ps1 -ZeroDayScan -DryRun

# Combined anomaly + zero-day scan
.\Run-AnomalyScan.ps1 -ZeroDayScan
```

Zero-day scanning also runs automatically when `ZeroDay.Enabled = $true` in settings (default).

### Air-gapped environments

Set `ZeroDay.Offline = $true` in settings. Pre-download the KEV JSON on an internet-connected machine and copy it to `State\kev-cache.json` on the jump server:

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

---

## Certificate expiry scanning

Scans three certificate sources and reports any certificate expiring within `ThresholdDays` (default 90), with severity by days-remaining (Critical ≤14, High ≤30, Medium ≤60, Low ≤90; already-expired = Critical):

1. **Windows machine stores** — `LocalMachine\My`, `CA`, `WebHosting` on every configured Windows asset, over WinRM. Trust-store noise (public/Microsoft roots) is filtered out so you see operational certs.
2. **TLS endpoints** — socket-probes live services and reads the presented server certificate. Auto-derives DC LDAPS (636) and WebApplication HTTPS (443) from the `Assets` block; add load balancers, appliances, and non-Windows services in `Config/certificate-endpoints.psd1`.
3. **AD Certificate Services** — optionally queries an Enterprise CA (`certutil`) for issued certs nearing expiry.

Identical certs found in multiple locations (same thumbprint) are collapsed into one finding listing every location. Unreachable hosts/ports record a collection error instead of aborting the scan.

### Configure (`Config/settings.psd1 → Certificates`)

```powershell
Certificates = @{
    Enabled        = $true
    ThresholdDays  = 90
    ScanAssetTypes = @('DomainController','MemberServer','Workstation')
    MachineStores  = @('My','CA','WebHosting')
    EndpointsPath  = "$PSScriptRoot\certificate-endpoints.psd1"
    ProbeDcLdaps   = $true      # auto-probe LDAPS 636 on every DC
    ProbeWebApps   = $true      # auto-probe HTTPS 443 on every WebApplication host
    Adcs = @{ Enabled = $false; CaConfig = 'CA01.contoso.com\Contoso-Issuing-CA' }
    ReportOutputPath = "$PSScriptRoot\..\State\certificate-report.md"
}
```

### Run

```powershell
# Dry run — prints the expiring-cert table, sends no alerts
.\Run-AnomalyScan.ps1 -CertificateScan -DryRun

# Full run — Teams / email / SharePoint alerts on findings
.\Run-AnomalyScan.ps1 -CertificateScan
```

Findings are reported to Teams, email, and a dedicated SharePoint list (`CertificateListId`), plus a markdown report at `State\certificate-report.md`. The web UI exposes it as a "🔐 Certificate Scan" option with a CSV/PDF download.

---

## Software & device inventory

Enumerates installed software on every configured Windows asset over WinRM (registry `Uninstall` keys, both native and `WOW6432Node` views — the standard no-extra-tooling approach), and classifies each host into a device category:

| AssetType (from asset discovery) | Category | How |
|---|---|---|
| `DomainController` | Domain Controller | passthrough |
| `MemberServer` | Server | passthrough |
| `Workstation` | **Desktop** or **Laptop** | `Win32_SystemEnclosure.ChassisTypes` over WinRM (falls back to `Workstation` if the chassis type is unrecognized or the query fails) |

If `CrossReferenceZeroDay` is enabled, installed product names are matched against the CISA KEV/NVD watchlist (`Config/zeroday-products.psd1`) so a host actually running a known-exploited version is flagged — not just alerted on abstractly.

### Configure (`Config/settings.psd1 → SoftwareInventory`)

```powershell
SoftwareInventory = @{
    Enabled               = $true
    ScanAssetTypes        = @('DomainController','MemberServer','Workstation')
    CrossReferenceZeroDay = $true
    ReportOutputPath      = "$PSScriptRoot\..\State\software-inventory-report.md"
}
```

### Run

```powershell
# Dry run — prints top installed products + any zero-day exposure, sends no alerts
.\Run-AnomalyScan.ps1 -SoftwareInventoryScan -DryRun

# Full run — Teams / email alerts only when installed software matches the zero-day watchlist
.\Run-AnomalyScan.ps1 -SoftwareInventoryScan
```

Results are written to `State\software-inventory-report.md` and merged into the dashboard snapshot. The web UI exposes it as a "💻 Software Inventory" option with a CSV download; zero-day exposure hits (if any) get their own table in both the web UI and the PDF report.

---

## Live rotating dashboard

A full-screen operations dashboard for a NOC/wall display, at **`/dashboard`** in the web UI. It auto-rotates through **6 screens** every 13 seconds:

1. **Executive Overview** — posture banner + KPI tiles (anomalies, compliance score, zero-day alerts, expiring certs, inventoried hosts) and an all-sources severity bar
2. **Network Discovery** — asset counts by type and by discovery source (on-prem vs. Cloudflare WARP), an online/last-seen status column, and a table of discovered hosts — click any row for its full installed-software list
3. **Compliance Posture** — score gauge, gaps by severity, top failing controls, per-asset breakdown
4. **Threats & Anomalies** — anomalies by type, recent anomalies, zero-day CVE watchlist (ransomware-flagged)
5. **Certificate Expiry** — severity split, soonest-to-expire countdown, count expiring < 30 days
6. **Software Inventory** — hosts by category (Desktop/Laptop/Server/Domain Controller), top installed products, zero-day exposure via installed software

Controls: `Space` pauses rotation, `←`/`→` navigate, `F` toggles fullscreen, `Esc` closes the device detail popup; hovering the stage pauses so operators can read. The page polls `/api/dashboard` every 3 minutes for fresh data.

**Data source.** Every scan run merges its results into `State/latest-scan.json` (configurable via `Dashboard.SnapshotPath`). Because each scheduled task runs a single scan type, the merge *preserves the other sections* — so the dashboard always shows all six areas even though anomaly, compliance, zero-day, certificate, discovery, and software-inventory scans run in separate tasks. The Discovery screen instead reads `State/asset-inventory.json` directly (accumulated by `Run-Discovery.ps1` across batched scans), so it updates independently of the shared snapshot. If no snapshot exists yet, the dashboard shows clearly-labelled demo data.

---

## Integrations

Agentless WinRM/TCP scanning only reaches Windows hosts and open-port network devices. The web UI's **`/integrations`** page documents what's needed to go further — SNMP for Printers/Switches/Access Points/IP Phones/Cameras/Firewalls, vendor warranty APIs (Dell/HP/Lenovo) for device age, MDM (Intune/Jamf/Android Enterprise) for kiosks and managed phones that a LAN scan can't reach by design, and the Cloudflare Zero Trust API as a richer alternative to today's WARP IP-range scan — plus exactly what to request from which team for each one. All are opt-in and disabled by default; nothing here is required for core scanning to work.

Vendor warranty API keys are entered and saved from **`/integrations/vendor-warranty`** ahead of the integration going live — they're written to `Config/integration-secrets.json` (gitignored, never `settings.psd1`), and the page never echoes a saved key back, only a masked indicator.

---

## Scheduling

```powershell
cd DCAnomalyAgent\Install
.\Register-ScheduledTask.ps1 -GmsaAccount 'CONTOSO\svc-discoverAgt$'
```

Creates these Scheduled Tasks under the gMSA:

| Task | Schedule | Command |
|---|---|---|
| `DCAnomalyAgent-Scan` | 06:00, 14:00, 22:00 | Anomaly scan only |
| `DCAnomalyAgent-Scan-Compliance` | Daily 07:00 | Compliance scan (`-SkipAnomalyScan`) |
| `DCAnomalyAgent-Scan-ZeroDay` | Daily 08:00 | Zero-day feed pull (`-SkipAnomalyScan`) |
| `DCAnomalyAgent-Scan-Certificates` | Daily 09:00 | Certificate expiry scan (`-SkipAnomalyScan`) |
| `DCAnomalyAgent-Scan-SoftwareInventory` | Daily 10:00 | Installed-software inventory + zero-day cross-reference (`-SkipAnomalyScan`) |
| `DCAnomalyAgent-Scan-Discovery` | 02:00, 06:00, 10:00, 14:00, 18:00, 22:00 | Lightweight presence sweep (`-SkipSoftwareInventory`) — keeps Online/Last Seen status current on the Assets/Discovery pages without a WinRM software pull on every host |
| `DCAnomalyAgent-Scan-Discovery-Full` | Daily 05:00 | Full discovery pass: asset inventory, device categorization, and per-device software collection |

> The compliance, zero-day, certificate, and software-inventory tasks pass **`-SkipAnomalyScan`** so they don't each re-run and re-report the event-log anomaly scan that the dedicated anomaly task already covers 3×/day. Each still contributes its section to the dashboard snapshot. The discovery presence task uses a 3-hour execution limit rather than 1 hour, since `-FromAD` can enumerate thousands of computer objects in a large domain.

---

## Security model

- **No stored credentials.** The gMSA's Kerberos ticket is used for all WinRM connections. The SharePoint/Graph cert is installed in the gMSA's certificate store; only the thumbprint is in config.
- **Least privilege.** The gMSA needs: Remote Management Users, Event Log Readers, Remote Registry read access, and `SeSecurityPrivilege` (for `auditpol /get`). No local admin required. See [DEPLOYMENT-OFFLINE.md](DEPLOYMENT-OFFLINE.md) for the full GPO configuration.
- **Linux scans run without root.** Controls use `sshd -T`, world-readable `/etc/login.defs`, and `systemctl is-active` — no sudo required unless you add custom privilege-requiring checks.
- **Baseline state** (`State/baseline.json`) and log files are gitignored and written only at runtime.
- **Integration secrets** (SNMP community/v3 credentials, Dell/HP/Lenovo API keys, MDM/Cloudflare tokens) live in `Config/integration-secrets.json`, gitignored and separate from `settings.psd1`, and are only ever entered via the web UI — never displayed back once saved, only shown as a masked indicator. The web UI itself has no built-in authentication (see the firewall guidance in [DEPLOYMENT-OFFLINE.md](DEPLOYMENT-OFFLINE.md)), so restrict network access to it accordingly.

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
| [IMPLEMENTATION-GUIDE.md](IMPLEMENTATION-GUIDE.md) | **Full step-by-step runbook** — phased deployment from a clean jump server to scheduled, dashboard-backed operations, with per-step verification |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Jump server with internet access |
| [DEPLOYMENT-OFFLINE.md](DEPLOYMENT-OFFLINE.md) | Air-gapped / no-internet environment — includes all download URLs, full GPO least-privilege config, the **network ports / cross-team prerequisites list**, and a **no-MSI Python fallback** for jump servers where CrowdStrike/EDR blocks the standard installer |
| [DCAnomalyAgent/COMPLIANCE-OTHER-ASSETS.md](DCAnomalyAgent/COMPLIANCE-OTHER-ASSETS.md) | Extending compliance scans to member servers, workstations, and Linux hosts |
| [firewall-request-ports.csv](firewall-request-ports.csv) | Ready-to-import firewall change request (S.No / Source IP / Destination IP / Service / Remarks) — the same table as `DEPLOYMENT-OFFLINE.md` Part 3.3 |

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

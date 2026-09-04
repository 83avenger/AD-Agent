# Master Deployment Guide — Full Solution

**Already deployed and continuing from an older build?** Use **`RUNBOOK-CONTINUE.md`** instead — it starts from a running instance and works forward.

**Start here for a fresh deployment.** The detail lives in seven other documents; this one is the running order, the
dependencies between stages, and the consolidated references (environment variables, scheduled
tasks, firewall) that are otherwise scattered.

Nothing below is required except Stage 1. Everything else is opt-in, degrades cleanly if
skipped, and can be deployed months apart.

---

## What the full solution is

| Layer | Components |
|---|---|
| **Core** | PowerShell scanner (anomaly, compliance, certificates, zero-day, software) + Flask web UI, on one jump server, agentless over WinRM as a gMSA |
| **Resilience** | `/healthz`, self-healing watchdog, background job queue |
| **Performance** | Go network-scan accelerator, optional PostgreSQL asset store |
| **Security** | IIS reverse proxy with Windows Auth + TLS, audit log |
| **Endpoint coverage** | Push collector (GPO for domain, local installer for non-domain), Cloudflare WARP roster sync |
| **Response** | SOAR playbooks, incidents, approval-gated AD actions |
| **Observability** | Prometheus `/metrics` + Grafana dashboard and alert rules |

---

## Before you start: things with lead time

These involve other teams and will gate you if left late. Raise them in week one:

| Ask | Team | Needed for |
|---|---|---|
| Create + install the gMSA, grant Event Log Readers / `SeSecurityPrivilege` via GPO | AD / Identity | Stage 1 — everything depends on it |
| Firewall rules (see consolidated table below) | Network | Stages 1, 6, 7 |
| An AD security group for analysts (e.g. `AD-Agent-Analysts`) | AD / Identity | Stage 5 |
| Internal CA certificate for the jump server | PKI | Stage 5 |
| URL Rewrite + ARR MSIs downloaded | — | Stage 5 (not fetchable on an air-gapped box) |
| Cloudflare API token, Zero Trust → Read + Account ID | Cloudflare admin | Stage 7 |
| Teams incoming webhook URL | Messaging | Stage 8 (optional) |
| Change window for the network discovery sweep | Change Mgmt | Stage 1 (it's an active port probe) |

---

## Running order

Dependencies are real where marked. Everything else can be reordered or skipped.

### Stage 1 — Core install *(required)*
Windows prerequisites, Python, code, `settings.psd1`, gMSA, WinRM verification, web UI as a
Scheduled Task, scan tasks.

📄 **`DEPLOYMENT.md`** §1–11 — or **`DEPLOYMENT-OFFLINE.md`** for an air-gapped server (it also
covers the EDR/Windows-Installer fallback if the Python MSI is blocked, which happened here).

> If you're using the offline guide, note its Parts 1–5 still describe the older NSSM service
> install. For a fresh build use `Register-WebUIStartup.ps1` (gMSA Scheduled Task) instead — no
> extra software to download, which suits a locked-down server better.

**Verify:** web UI loads, a manual scan returns findings, scheduled tasks registered.

---

### Stage 2 — Self-healing *(recommended; ~15 min, no risk)*
`/healthz` plus the watchdog that restarts the web UI when it crashes *or hangs*.

```powershell
cd DCAnomalyAgent\Install
.\Watch-WebUIHealth.ps1 -Register -GmsaAccount 'AMG\svc-discoverAgt$'
```
⚠ Must be run from an **elevated** PowerShell session.

📄 `ENTERPRISE-HARDENING-RUNBOOK.md` Phase 1 · `CHANGE-TICKET-PHASE-1-3.md`

---

### Stage 3 — Job queue *(no action)*
Scans stopped blocking web requests as of the `app.py` in Stage 1. Nothing to configure — listed
only so it isn't hunted for.

---

### Stage 4 — Scan accelerator *(optional)*
Go binary replacing the PowerShell port scanner.

```powershell
cd tools\netscan
.\build.ps1        # needs Go installed, or build elsewhere and copy netscan.exe
```
Falls back to the PowerShell scanner automatically if absent or broken.

📄 `ENTERPRISE-HARDENING-RUNBOOK.md` Phase 2

---

### Stage 5 — Authentication *(strongly recommended — and a prerequisite for Stage 8 live)*
IIS reverse proxy: Windows Auth + TLS, restricted to an AD group, web UI locked to localhost.

```powershell
.\Register-IISReverseProxy.ps1 -AllowedGroup 'AMG\AD-Agent-Analysts' `
    -LockWebUIToLocalhost -GmsaAccount 'AMG\svc-discoverAgt$' `
    -PythonPath 'C:\Apps\Python312\python.exe' -CertThumbprint '<thumbprint>'
```

**Until this is done the web UI has no authentication at all** — anyone who can reach the port
can trigger scans, delete assets and read every finding. Treat it as required before anyone
beyond you uses the tool.

📄 `ENTERPRISE-HARDENING-RUNBOOK.md` Phase 5

---

### Stage 6 — Endpoint push collector *(recommended if you have laptops)*
Endpoints push their own inventory outbound. Fixes roaming laptops, DHCP churn, and devices
asleep at scan time — and replaces the inbound-WinRM-per-VLAN firewall ask with one outbound rule.

1. Set `COLLECTOR_TOKEN`, `CORPORATE_NETWORKS`, `CORPORATE_DNS_SUFFIX`; restart the web UI
2. **Test on one machine by hand**
3. Domain-joined → GPO · non-domain → `Install-PushCollector.ps1` per host

📄 `DEPLOY-ENDPOINTS-CLOUDFLARE-SOAR.md` Stage 1 · `DCAnomalyAgent\Install\Deploy-PushCollector-GPO.md`
· `COVERAGE-NON-DOMAIN.md` (non-domain servers)

---

### Stage 7 — Cloudflare WARP sync *(optional)*
Device roster and presence for laptops off the corporate network, using the agent already
installed on them. Identity/presence only — Cloudflare has no software-inventory API.

📄 `DEPLOY-ENDPOINTS-CLOUDFLARE-SOAR.md` Stage 2

---

### Stage 8 — SOAR *(optional)*
Playbooks → incidents → approval-gated AD response.

- `SOAR_MODE=dryrun` is safe now. Run it for **at least a week** and review what it raises.
- **`SOAR_MODE=live` requires Stage 5 first.** The approve button changes production AD; without
  Windows Auth in front of it the audit trail records `unauthenticated@<ip>`, which is not an
  accountable record.
- Add your break-glass and service accounts to `$ProtectedIdentities` in
  `Invoke-SoarResponder.ps1` before enabling any destructive playbook.

📄 `DEPLOY-ENDPOINTS-CLOUDFLARE-SOAR.md` Stage 3

---

### Stage 9 — Postgres asset store *(only past SQLite's range)*
Only worth doing beyond a few thousand assets, or for multi-site/multi-instance. Set
`ASSETS_DATABASE_URL`, `pip install psycopg2-binary`, restart. Unset it to revert.

📄 `ENTERPRISE-HARDENING-RUNBOOK.md` Phase 4

---

### Stage 10 — Prometheus / Grafana *(optional)*
Point a scrape config at `/metrics`, import `grafana/ad-agent-dashboard.json` and
`grafana/ad-agent-alerts.yml`.

If Stage 5 is deployed, allowlist the Prometheus server's IP for `/metrics` specifically —
scrapers can't do interactive Windows Auth.

📄 `/prometheus-comparison` page in the UI · `README.md`

---

## Consolidated environment variables

All set on the jump server as **Machine** scope, then restart the web UI task:

```powershell
[Environment]::SetEnvironmentVariable('<NAME>', '<value>', 'Machine')
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

| Variable | Stage | Default if unset | Purpose |
|---|---|---|---|
| `FLASK_SECRET` | 1 | random per restart | Session signing. Set it, or sessions drop on every restart |
| `COLLECTOR_TOKEN` | 6 | **feature off (503)** | Shared secret for endpoint check-ins |
| `CORPORATE_NETWORKS` | 6 | location = `Unknown` | Internal CIDRs, comma-separated — splits office from home |
| `CORPORATE_DNS_SUFFIX` | 6 | name may flip-flop | Pins the corporate FQDN for roaming devices |
| `SOAR_MODE` | 8 | **`off`** | `off` \| `dryrun` \| `live` |
| `TEAMS_WEBHOOK_URL` | 8 | notify action fails | Teams webhook for SOAR notifications |
| `ASSETS_DATABASE_URL` | 9 | SQLite | Postgres connection string |
| `HOST` / `PORT` | 1 | `0.0.0.0` / `5000` | Web UI bind (set host to `127.0.0.1` after Stage 5) |

Every optional feature is **off by default** and says so in the UI rather than failing quietly.

---

## Scheduled task inventory

**On the jump server:**

| Task | Schedule | Stage |
|---|---|---|
| `AD-Agent-WebUI` | At startup (continuous) | 1 |
| `AD-Agent-WebUI-Watchdog` | Every 5 min | 2 |
| `DCAnomalyAgent-Scan` | 06:00, 14:00, 22:00 | 1 |
| `DCAnomalyAgent-Scan-Compliance` | Daily 07:00 | 1 |
| `DCAnomalyAgent-Scan-ZeroDay` | Daily 08:00 | 1 |
| `DCAnomalyAgent-Scan-Certificates` | Daily 09:00 | 1 |
| `DCAnomalyAgent-Scan-SoftwareInventory` | Daily 10:00 | 1 |
| `DCAnomalyAgent-Scan-Discovery` | 6×/day | 1 |
| `DCAnomalyAgent-Scan-Discovery-Full` | Daily 05:00 | 1 |
| `DCAnomalyAgent-Scan-CloudflareSync` | Hourly | 7 |

**On each endpoint** (GPO or local installer):

| Task | Schedule |
|---|---|
| `AD-Agent Check-in` | Every 30 min + at startup/logon/unlock |
| `AD-Agent Full Inventory` | Daily (a time laptops are actually on) |

---

## Firewall summary

Full table with placeholders: **`firewall-request-ports.csv`** (24 rows) — hand that to the
network team rather than retyping.

- **Rows 1–9** — core: jump server → DCs and member servers (WinRM, ADWS, LDAP/S, Kerberos, SMB). Required.
- **Rows 10–19** — optional outbound: Linux SSH, TLS endpoints, ADCS, KEV/NVD feeds, Graph, Teams, SMTP.
- **Row 20** — inbound TCP/5000 to the web UI. **Temporary**; remove once row 22 is live.
- **Row 21** — Postgres TCP/5432, only if the DB is on another host (Stage 9).
- **Row 22** — inbound TCP/443 to IIS (Stage 5). Supersedes row 20.
- **Row 23** — endpoints → jump server, outbound (Stage 6). **Replaces** inbound WinRM to laptop VLANs.
- **Row 24** — jump server → `api.cloudflare.com` (Stage 7).

---

## Final verification

| Check | Command / where |
|---|---|
| Web UI healthy | `/healthz` → `status: ok` |
| Watchdog live | `Get-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'` → Ready |
| Scans producing data | Dashboard shows findings; `State\scan.log` |
| Accelerator in use | `State\discovery.log` — no "falling back" warning |
| Auth enforced | Browsing `https://<server>` prompts for Windows credentials |
| Endpoints reporting | `/endpoints` lists devices; Location shows Office/Remote |
| No duplicate assets | A checked-in laptop appears once on `/assets` |
| Cloudflare syncing | `State\cloudflare-sync.log` → "Sync complete: N recorded" |
| SOAR safe | `/soar` — destructive actions show **awaiting approval**, never executed |
| Metrics scrapeable | `/metrics` returns text; Prometheus target `up` |
| Audit trail | `State\audit.log` shows real usernames, not `unauthenticated@` |

---

## Known gaps and cautions

Carried forward honestly rather than discovered later:

- **PowerShell scripts written late in the build have never been executed** — `Send-InventoryCheckin.ps1`,
  `Install-PushCollector.ps1`, `Invoke-SoarResponder.ps1`, `Sync-CloudflareDevices.ps1`. The
  environment they were written in had no PowerShell. Test each on one host / with `-WhatIf`
  before any fleet rollout or live enablement.
- **Non-domain servers get inventory only** — no compliance, certificate or anomaly scanning,
  because those run from the jump server over WinRM and there's no credential support. See
  `COVERAGE-NON-DOMAIN.md` for the three options.
- **The collector token is readable** by anyone who can read the GPO or is local admin on an
  endpoint. It's write-only (submit inventory, read nothing); Stage 5 Windows Auth removes the
  need for it.
- **Per-user installed software isn't captured** by the collector — it runs as SYSTEM, so `HKCU`
  is SYSTEM's hive. Machine-wide installs are captured normally.
- **Cloudflare presence is ~hourly**, not live, and carries no software inventory.
- **SQLite is single-writer.** Fine to a few thousand assets; Stage 9 exists for beyond that.

---

## Document map

| Document | Covers |
|---|---|
| `DEPLOYMENT.md` | Core install (§1–11) and the ongoing update procedure (§12) |
| `DEPLOYMENT-OFFLINE.md` | Air-gapped install, least-privilege gMSA/GPO detail, cross-team asks, offline updates |
| `ENTERPRISE-HARDENING-RUNBOOK.md` | Phases 1–5 with security review |
| `CHANGE-TICKET-PHASE-1-3.md` | Submittable change ticket for the low-risk batch |
| `DEPLOY-ENDPOINTS-CLOUDFLARE-SOAR.md` | Collector, Cloudflare, SOAR — staged |
| `Install\Deploy-PushCollector-GPO.md` | GPO rollout detail |
| `COVERAGE-NON-DOMAIN.md` | Non-domain servers: coverage matrix and onboarding |
| `IMPLEMENTATION-GUIDE.md` | How the scanner works internally |

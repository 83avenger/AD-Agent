# Deployment Guide — Jump Server Installation

This guide installs the **DC Anomaly Agent** (PowerShell scanner + Flask web UI)
on a Windows **jump/management server** that has WinRM access to your Domain
Controllers. Do **not** install this on a DC itself.

---

## 0. Prerequisites

A domain-joined Windows Server (2019/2022 recommended) with:

| Requirement | Why |
|---|---|
| RSAT ActiveDirectory PowerShell module | `Get-AD*` cmdlets used by collectors & compliance checks |
| WinRM connectivity to each DC (TCP 5985/5986) | Remote event log + AD queries |
| PowerShell 5.1+ (built-in) or PowerShell 7 | Runs the scanner |
| Python 3.10+ | Runs the web UI |
| A gMSA (or service account) | Credential-free Kerberos auth to DCs |
| Outbound HTTPS to Teams/Graph (optional) | Only if you enable Teams/SharePoint reporting |

---

## 1. Install Windows prerequisites

Open an **elevated PowerShell** prompt on the jump server.

```powershell
# RSAT AD PowerShell module (Windows Server)
Install-WindowsFeature RSAT-AD-PowerShell

# Verify the AD module loads
Import-Module ActiveDirectory
Get-Command Get-ADDefaultDomainPasswordPolicy
```

If this is Windows 10/11 acting as the jump host instead of a server:
```powershell
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

---

## 2. Install Python

Download Python 3.12 from <https://www.python.org/downloads/windows/> and
install with **"Add python.exe to PATH"** checked, or via winget:

```powershell
winget install -e --id Python.Python.3.12
```

Verify:
```powershell
python --version    # should print Python 3.1x.x
```

---

## 3. Get the code onto the server

```powershell
# Option A: git
git clone <your-repo-url> C:\Apps\AD-Agent

# Option B: copy the AD-Agent folder via your normal file-transfer method
```

Resulting layout:
```
C:\Apps\AD-Agent\
  DCAnomalyAgent\   <- PowerShell scanner
  WebApp\           <- Flask web UI
```

---

## 4. Install Python dependencies

```powershell
cd C:\Apps\AD-Agent\WebApp

# (Recommended) isolated virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install waitress      # production WSGI server
```

---

## 5. Configure the scanner

Edit `C:\Apps\AD-Agent\DCAnomalyAgent\Config\settings.psd1`:

- `DomainControllers` — your DC hostnames (the web UI can also override this per-scan)
- `Reporting.Teams.WebhookUrl` — Teams incoming webhook (or set `Enabled = $false`)
- `Reporting.SharePoint.*` — tenant/client/site/list IDs + cert thumbprint
  (or set `Enabled = $false`)

> The web UI works fine with Teams/SharePoint **disabled** — it generates
> PDF/CSV reports on demand regardless.

---

## 6. Set up the gMSA (credential-free DC access)

Run as a **Domain Admin** on a DC or admin workstation:

```powershell
# Create the gMSA, allowing this jump server to retrieve its password
New-ADServiceAccount -Name 'svc-discoverAgt' `
  -DNSHostName 'svc-discoverAgt.contoso.com' `
  -PrincipalsAllowedToRetrieveManagedPassword 'JUMPSERVER$'
```

On the **jump server** (elevated):
```powershell
Install-ADServiceAccount -Identity 'svc-discoverAgt'
Test-ADServiceAccount   -Identity 'svc-discoverAgt'   # must return True
```

Grant the gMSA **read access to the Security event log** on each DC — add it to
a group that is a member of the DC's built-in **Event Log Readers** group
(via a domain GPO restricted-group setting). Do **not** grant local admin on DCs.

---

## 7. Verify WinRM connectivity

From the jump server:
```powershell
Test-WSMan -ComputerName dc01.contoso.com

# End-to-end scanner smoke test (prints findings, no Teams/SharePoint writes)
cd C:\Apps\AD-Agent\DCAnomalyAgent
.\Run-AnomalyScan.ps1 -DryRun -ComplianceScan -DomainControllerOverride 'dc01.contoso.com'
```

If WinRM is blocked, enable it on the DCs (usually already on in a domain) and
confirm firewall rules allow 5985/5986 from the jump server.

---

## 8. First run of the web UI (interactive test)

```powershell
cd C:\Apps\AD-Agent\WebApp
.\.venv\Scripts\Activate.ps1
python start.py --prod --host 127.0.0.1 --port 5000
```

Browse to <http://127.0.0.1:5000>, enter a DC hostname, run a scan, and confirm
the PDF/CSV downloads work. Press `Ctrl+C` to stop.

> If PowerShell can't be found the app runs in **demo mode** with sample data —
> useful for validating the UI, but it means `pwsh`/`powershell` isn't on PATH.

---

## 9. Run the web UI as a Windows Service

So the UI survives reboots and logoffs. Use **NSSM** (Non-Sucking Service Manager):

```powershell
# Install NSSM
winget install -e --id NSSM.NSSM
# (or download from https://nssm.cc/download)

nssm install DCAnomalyWebUI "C:\Apps\AD-Agent\WebApp\.venv\Scripts\python.exe" `
    "C:\Apps\AD-Agent\WebApp\start.py --prod --host 127.0.0.1 --port 5000"

nssm set DCAnomalyWebUI AppDirectory "C:\Apps\AD-Agent\WebApp"

# Run the service under the gMSA so subprocess scans inherit Kerberos context
nssm set DCAnomalyWebUI ObjectName "CONTOSO\svc-discoverAgt$" ""

nssm start DCAnomalyWebUI
```

Check status: `nssm status DCAnomalyWebUI` (should be `SERVICE_RUNNING`).

---

## 10. Put HTTPS in front (recommended)

The Flask/waitress server is bound to `127.0.0.1` only. Front it with a reverse
proxy for TLS so credentials and reports never traverse the network in clear:

**Option A — IIS** (Install Web Server + URL Rewrite + ARR):
1. Create a site bound to `https://adagent.contoso.com:443` with a valid cert.
2. Add a reverse-proxy rule forwarding to `http://127.0.0.1:5000`.

**Option B — Caddy** (simplest):
```
adagent.contoso.com {
    reverse_proxy 127.0.0.1:5000
}
```

Restrict access to the site (Windows Auth / IP allow-list) so only your
security/IT team can reach it.

---

## 11. Schedule the unattended scans (separate from the UI)

The web UI is for **on-demand** scans. For the recurring 2–3x/day scans, register
the Scheduled Tasks under the same gMSA:

```powershell
cd C:\Apps\AD-Agent\DCAnomalyAgent\Install
.\Register-ScheduledTask.ps1
```

This creates:
- `DCAnomalyAgent-Scan` — anomaly scan 3x/day (06:00, 14:00, 22:00)
- `DCAnomalyAgent-Scan-Compliance` — compliance scan daily (07:00)

---

## 12. Updating the application

This is the repeatable procedure for pulling in any future update — not just the current
hardening batch. Same steps whether you're picking up a bug fix, a new feature, or one of the
optional phases described in `ENTERPRISE-HARDENING-RUNBOOK.md`.

### 12.1 Before you update

- [ ] Check what's currently deployed, so you have a known-good point to roll back to:
      ```powershell
      cd C:\Apps\AD-Agent
      git log -1 --oneline
      ```
      (If you deploy via file copy instead of git, keep a dated zip of the current
      `C:\Apps\AD-Agent` folder instead — same purpose.)
- [ ] Confirm no scan/discovery is actively running:
      ```powershell
      Get-ScheduledTask -TaskName 'DCAnomalyAgent-*' | Get-ScheduledTaskInfo | Where-Object State -eq 'Running'
      ```
      Recurring scans on their own schedule aren't affected by a web UI restart, but it's
      cleaner to avoid updating mid-scan.
- [ ] Note current `/healthz` output as a before/after baseline:
      ```powershell
      Invoke-WebRequest http://localhost:5000/healthz -UseBasicParsing | Select -Expand Content
      ```

### 12.2 Pull the update

```powershell
cd C:\Apps\AD-Agent
git fetch origin
git log HEAD..origin/<branch> --oneline   # preview what's changing before applying it
git pull origin <branch>
```

If you deploy via file copy (no git on the server), replace only the files that changed —
diff against your last-deployed copy, or just re-copy the whole tree if that's simpler for your
process. Either way, **never edit deployed files directly on the server** — always update via a
fresh pull/copy from the repo, so `git log` (or your zip archive) stays an honest record of
what's actually running.

### 12.3 Pick up dependency changes, if any

Check whether `WebApp/requirements.txt` changed in this update:
```powershell
git diff HEAD@{1} HEAD -- WebApp/requirements.txt
```
If it did:
```powershell
cd C:\Apps\AD-Agent\WebApp
.\.venv\Scripts\Activate.ps1   # if using a venv, per section 4
pip install -r requirements.txt
```
Most updates won't touch this — PowerShell script/module changes and Python code changes don't
need a dependency reinstall, only new third-party packages do.

### 12.4 Restart what needs restarting

| Component | Needs restart on update? | Command |
|---|---|---|
| Web UI (`app.py`, templates, `assets_db.py`) | Yes — Python doesn't hot-reload in `--prod` mode | `Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'` |
| Watchdog (`Watch-WebUIHealth.ps1`) | No — re-reads itself fresh on every scheduled fire | — |
| Scan/Discovery PowerShell scripts & modules | No — re-read fresh on every scheduled run, nothing persists in memory between runs | — |
| `settings.psd1` / other config | No — read fresh on every run/request | — |
| `tools/netscan/main.go` | Only if that specific file changed | `cd tools\netscan; .\build.ps1` |

In practice: **if `WebApp/` changed, restart the web UI task; otherwise you often don't need to
restart anything** — the next scheduled scan or the next request just picks up the new script/
config automatically.

### 12.5 Verify

```powershell
Invoke-WebRequest http://localhost:5000/healthz -UseBasicParsing | Select -Expand Content
```
Compare against your 12.1 baseline — `status` should still be `ok` (or the same `warn` reasons
as before, e.g. no scan run yet on a fresh install). Then exercise whatever the update actually
changed — run a test scan, check the page/feature that was fixed or added, etc. Type-checking
and a clean `/healthz` confirm the app didn't break; they don't confirm the specific feature
works — verify that by hand.

### 12.6 Rollback

```powershell
cd C:\Apps\AD-Agent
git log --oneline -5           # find the commit hash noted in 12.1
git checkout <previous-commit-hash>
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```
If you deployed via file copy, restore from the dated zip taken in 12.1 and restart the task the
same way. Either path gets you back to the exact prior state within a couple minutes.

---

## Quick reference

| Action | Command |
|---|---|
| Start web UI | `Start-ScheduledTask -TaskName 'AD-Agent-WebUI'` (see §9/Register-WebUIStartup.ps1) |
| Stop web UI | `Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'` |
| Update the application | See §12 — pull, restart web UI task if `WebApp/` changed, verify `/healthz` |
| Manual UI run (testing only) | `python start.py --prod` |
| CLI anomaly scan | `.\Run-AnomalyScan.ps1` |
| CLI compliance scan | `.\Run-AnomalyScan.ps1 -ComplianceScan` |
| Dry run (no reporting) | `.\Run-AnomalyScan.ps1 -DryRun -ComplianceScan` |
| Web UI logs | `C:\Apps\AD-Agent\DCAnomalyAgent\State\scan.log`, `watchdog.log`, `audit.log` |
| Web UI health | `Invoke-WebRequest http://localhost:5000/healthz -UseBasicParsing` |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| UI shows "Demo mode" banner | `pwsh`/`powershell` not on PATH for the service account — verify PATH / use full path |
| `Test-ADServiceAccount` returns False | gMSA not installed on this host or `PrincipalsAllowedToRetrieveManagedPassword` missing this server |
| Scan returns "Access denied" | gMSA lacks Event Log Readers / AD read rights on the DC |
| `Test-WSMan` fails | WinRM disabled or firewall blocking 5985/5986 |
| PDF/CSV empty | No findings in window, or scan errored — check `State\scan.log` |
| Scan times out (>5 min) | Too many DCs/controls per run — filter by framework/severity, or scan fewer DCs at once |

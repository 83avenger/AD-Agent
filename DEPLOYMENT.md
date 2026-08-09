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

## Quick reference

| Action | Command |
|---|---|
| Start service | `nssm start DCAnomalyWebUI` |
| Stop service | `nssm stop DCAnomalyWebUI` |
| Manual UI run | `python start.py --prod` |
| CLI anomaly scan | `.\Run-AnomalyScan.ps1` |
| CLI compliance scan | `.\Run-AnomalyScan.ps1 -ComplianceScan` |
| Dry run (no reporting) | `.\Run-AnomalyScan.ps1 -DryRun -ComplianceScan` |
| Web UI logs | `C:\Apps\AD-Agent\DCAnomalyAgent\State\scan.log` |

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

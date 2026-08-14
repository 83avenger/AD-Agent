# Enterprise Hardening Runbook — Self-Healing, Accelerator, Job Queue, Postgres

This runbook covers deploying the four enterprise-hardening changes made to AD-Agent, in order.
Each phase is additive and independently optional — stop after any step and the tool keeps
working exactly as it did before. A security review and firewall-impact summary are at the end.

---

## 0. Pull the latest code onto the jump server

```powershell
cd C:\Apps\AD-Agent        # wherever the repo lives on the server
git pull origin claude/optimistic-bohr-tnmeli
```

If you don't run git directly on the server, copy these changed/new files over instead:

```
WebApp/app.py
WebApp/assets_db.py                              (new)
WebApp/requirements.txt
WebApp/templates/job_wait.html                   (new)
DCAnomalyAgent/Install/Watch-WebUIHealth.ps1      (new)
DCAnomalyAgent/Modules/DCAnomalyAgent.Discovery.psm1
DCAnomalyAgent/Run-Discovery.ps1
DCAnomalyAgent/Config/settings.psd1
tools/netscan/                                    (new folder)
README.md
firewall-request-ports.csv
.gitignore
```

---

## Phase 1 — Self-healing (`/healthz` + watchdog)

**1.1** No extra code changes beyond the `app.py` sync above — `/healthz` is baked in.

**1.2** Restart the web UI so it picks up the new code:

```powershell
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-Sleep -Seconds 5
Get-ScheduledTask -TaskName 'AD-Agent-WebUI' | Get-ScheduledTaskInfo
```

**1.3** Verify the health endpoint:

```powershell
Invoke-WebRequest -Uri 'http://localhost:5000/healthz' -UseBasicParsing | Select -Expand Content
```
`200` = healthy/degraded, `503` = hard failure — read the `checks` object to see which check failed and why.

**1.4** Register the watchdog (one-time):

```powershell
cd DCAnomalyAgent\Install
.\Watch-WebUIHealth.ps1 -Register -GmsaAccount 'AMG\svc-discoverAgt$'
```

**1.5** Confirm it's running:

```powershell
Get-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'
Start-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'
Get-Content DCAnomalyAgent\State\watchdog.log -Tail 5
```
Expect a line like `Health check OK (status=ok).`

**1.6 (optional smoke test)** Stop the web UI task manually, wait ~10-15 minutes (two watchdog
cycles), and confirm it comes back up on its own — check `Get-ScheduledTask -TaskName
'AD-Agent-WebUI'` and the watchdog log for a restart line.

---

## Phase 2 — Go network-scan accelerator (optional)

**2.1** Install Go on the server (one-time): https://go.dev/dl/ — Windows amd64 MSI.

**2.2** Build the binary:

```powershell
cd tools\netscan
.\build.ps1
```
Drops `netscan.exe` into `DCAnomalyAgent\bin\`.

**2.3** Verify it works standalone:

```powershell
DCAnomalyAgent\bin\netscan.exe -cidr "127.0.0.1" -ports "WinRM=5985" -timeout-ms 500
```
Should print `[]` or a JSON array, not an error.

**2.4** Nothing else to configure — `Get-NetworkAsset` picks it up automatically on the next
Discovery run. Confirm:

```powershell
DCAnomalyAgent\Run-Discovery.ps1 -Cidr '10.0.0.0/28'
Get-Content DCAnomalyAgent\State\discovery.log -Tail 20
```
A `Write-Warning` about falling back to the PowerShell scanner means the binary path failed —
that's the self-healing fallback working as designed, not a bug; Discovery still completes.

**2.5** Re-run `build.ps1` any time `tools/netscan/main.go` changes in a future pull.

---

## Phase 3 — Non-blocking scan/discovery (job queue)

**3.1** No extra registration — this is purely `app.py` + `job_wait.html`, already live after
the Phase 1 restart.

**3.2** Verify from the browser: submit a Discovery or Scan. You should land on a "Running…"
page with a spinner that auto-redirects to results when done, instead of the browser hanging on
the POST.

**3.3** Verify concurrency: open two browser tabs, start a scan in one, confirm the
dashboard/assets pages in the other tab still load instantly while the scan runs.

---

## Phase 4 — PostgreSQL asset store (optional — only past SQLite's comfortable range)

Skip unless you're past a few thousand assets or standing up a second AD-Agent instance/site
that needs to share the inventory.

**4.1** Provision a Postgres database and a dedicated least-privilege login:

```sql
CREATE ROLE ad_agent LOGIN PASSWORD 'choose-a-strong-password';
CREATE DATABASE ad_agent OWNER ad_agent;
```

**4.2** Install the Python driver on the jump server:

```powershell
& 'C:\Apps\Python312\python.exe' -m pip install psycopg2-binary
```

**4.3** Set the connection string as a persistent machine environment variable (survives
reboots, picked up by the Scheduled Task):

```powershell
[Environment]::SetEnvironmentVariable(
  'ASSETS_DATABASE_URL',
  'postgresql://ad_agent:choose-a-strong-password@pgserver.contoso.com:5432/ad_agent?sslmode=require',
  'Machine'
)
```
Use `sslmode=require` (or `verify-full` if the Postgres server has a trusted cert) — see the
security notes below on why this matters for a cross-host connection.

**4.4** Restart the web UI task to pick up the new env var:

```powershell
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

**4.5** Verify it's using Postgres:

```powershell
Invoke-WebRequest -Uri 'http://localhost:5000/healthz' -UseBasicParsing | Select -Expand Content
```
Look for `"assets_db": {"status": "ok", "detail": "postgres"}`.

**4.6** Run a Discovery scan and confirm assets show up on `/assets` as before.

**4.7 (rollback)** Remove the env var and restart — falls straight back to the untouched SQLite
file:

```powershell
[Environment]::SetEnvironmentVariable('ASSETS_DATABASE_URL', $null, 'Machine')
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

---

## Phase 5 — Authentication (IIS reverse proxy + Windows Auth)

Built now, per your request — **not deployed automatically; run this when you're ready.** This
closes the biggest gap from the security review below: the web UI has no login today, so anyone
who can reach its port can trigger scans, delete assets, and see every collected result.

**5.1** Stage the IIS prerequisites the script can't fetch itself (no internet access assumed on
an EDR-locked server):
- [URL Rewrite](https://www.iis.net/downloads/microsoft/url-rewrite)
- [Application Request Routing 3.0](https://www.iis.net/downloads/microsoft/application-request-routing)

Download both on a machine with internet access, copy the MSIs to the server, install them (no
reboot required).

**5.2** Get a real certificate from your internal CA if you have one — the script can generate a
self-signed cert to test with, but browsers will warn on it. Note the thumbprint if you have a
real cert ready (`Get-ChildItem Cert:\LocalMachine\My`).

**5.3** Run the script — test in a lab/staging server first, since this changes how the tool is
reached (HTTPS + Windows Auth via IIS, instead of plain HTTP directly to the app):

```powershell
cd DCAnomalyAgent\Install
.\Register-IISReverseProxy.ps1 `
    -AllowedGroup 'AMG\AD-Agent-Analysts' `
    -LockWebUIToLocalhost `
    -GmsaAccount 'AMG\svc-discoverAgt$' `
    -PythonPath 'C:\Apps\Python312\python.exe' `
    -CertThumbprint '<thumbprint, or omit for self-signed>'
```

`-AllowedGroup` restricts access to that AD group (create it first if it doesn't exist yet -
`New-ADGroup 'AD-Agent-Analysts' -GroupScope Global`, add your analysts as members). Omitting it
still requires Windows auth but allows *any* authenticated domain user through - not what you
want long-term.

`-LockWebUIToLocalhost` re-registers the `AD-Agent-WebUI` task bound to `127.0.0.1` instead of
`0.0.0.0`, so port 5000 stops being reachable from the network entirely - only IIS (443) is.

**5.4** Restart the web UI task so the localhost-only binding takes effect:
```powershell
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

**5.5** Browse to `https://jump-jeremy.amg.local/` — you should get a Windows Authentication
prompt (or silent SSO if your browser/domain is configured for it), and be denied if you're not
in `-AllowedGroup`.

**5.6** Confirm the audit trail is working — trigger a scan or delete an asset, then:
```powershell
Get-Content DCAnomalyAgent\State\audit.log -Tail 5
```
Each line should show the real Windows username (e.g. `user=AMG\jsmith`), not
`unauthenticated@<ip>` — that fallback only appears for requests that bypass the IIS proxy
entirely, which shouldn't be possible once port 5000 is locked to localhost.

**5.7** Update your firewall request: analysts should now hit **TCP/443 on the jump server**
(IIS), not TCP/5000 directly. `firewall-request-ports.csv` row 20 has been updated to reflect
this - hand the updated file to your network team.

**5.8 (rollback)** If anything goes wrong, `Remove-Website -Name 'AD-Agent'` removes the IIS site,
and re-running `Register-WebUIStartup.ps1` with `-BindHost '0.0.0.0'` restores direct access to
port 5000 while you troubleshoot.

---

## Quick verification checklist

| Check | Command |
|---|---|
| Web UI healthy | `Invoke-WebRequest http://localhost:5000/healthz` → `status: ok` |
| Watchdog active | `Get-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'` → `Ready`/`Running` |
| netscan in use | `discovery.log` has no "falling back to PowerShell scanner" warning |
| Jobs non-blocking | Scan submission shows the spinner page, not a hung tab |
| Asset backend | `/healthz` → `checks.assets_db.detail` shows `sqlite` or `postgres` as expected |

---

## Security review

### Pre-existing, not introduced by this work — addressed by Phase 5 below
- **No authentication on the web UI.** `firewall-request-ports.csv` already documented this
  (`"no built-in auth"` on the port-5000 inbound rule). Anyone who can reach TCP 5000 can trigger
  scans/discovery, delete assets, and view every collected result — including installed software
  inventories, compliance gaps, and (if configured) vendor warranty API responses. This predates
  the four phases above. **`Register-IISReverseProxy.ps1` (Phase 5) fixes this** — IIS in front
  doing Windows Authentication restricted to an AD group, with the Flask app locked to
  localhost-only afterward. Built and ready; deploy it whenever you're ready to test it.
- **Traffic is plain HTTP**, not HTTPS. Phase 5's IIS proxy terminates TLS (self-signed by
  default, or a real cert from your internal CA via `-CertThumbprint`), so this is closed by the
  same step.
- **No audit trail of who did what.** Also closed by Phase 5: `app.py` now writes
  `DCAnomalyAgent\State\audit.log` on every scan submit, discovery submit, and asset delete,
  recording the Windows Authentication username IIS forwards via the `X-Remote-User` header. Before
  Phase 5 is deployed, or for any request that reaches the app directly, entries fall back to
  `unauthenticated@<ip>` — expected, since there's genuinely no verified identity yet.

### Reviewed as part of this work — no issues found
- **SQL injection**: every query in `assets_db.py` (both SQLite and Postgres paths) uses
  parameterized placeholders (`?` / `%s`), never string-formatted SQL. Verified by reading every
  query site.
- **Command injection**: `Invoke-NetscanBinary` and all other PowerShell invocations from
  `app.py` pass arguments as an array to `subprocess`/`&`, never through a shell string — no
  argument can break out into a second command.
- **Job queue (`/jobs/<id>`)**: job IDs are `uuid4().hex` (122 bits of randomness) — not
  practically guessable/enumerable. There's no per-user isolation, but that's consistent with the
  rest of the app having no auth at all; fixing the auth gap above covers this too.

### New attack surface introduced by these phases — mitigations already in place, plus notes
- **`tools/netscan/` (Go binary)**: takes only `-cidr`/`-ports`/`-timeout-ms`/`-source` as typed
  flags (no shell interpolation), scans the exact same port set your firewall change request
  already covers (see below), and is invoked with a hard timeout per port probe. Building it
  requires installing the Go toolchain on the server — if your EDR/change-control process would
  rather not have a compiler present on Jump-Jeremy, build `netscan.exe` on a separate machine
  and copy just the binary into `DCAnomalyAgent\bin\`; nothing about the build step needs to
  happen on the jump server itself.
- **PostgreSQL (`ASSETS_DATABASE_URL`)**: only relevant if you deploy Phase 4. Recommendations
  baked into the steps above: a dedicated least-privilege DB role (not a shared/admin account),
  `sslmode=require` on the connection string so credentials and asset data aren't sent in the
  clear across the network, and restricting the Postgres server's own firewall/`pg_hba.conf` to
  only accept connections from Jump-Jeremy's IP. If Postgres runs on the same server as the web
  UI (`localhost`), none of this cross-host risk applies and `sslmode` can be left at its default.
- **`/healthz` info disclosure**: unauthenticated today and returns internal detail strings (e.g.
  exception text, disk paths) on failure. Low severity — no credentials or scan data are ever
  included — but once Phase 5's IIS proxy is in front, `/healthz` is covered by Windows Auth too.
- **IIS reverse proxy itself (Phase 5)**: the URL Rewrite rule forwards the Windows-Auth-verified
  username via a custom `X-Remote-User` header, which only IIS can set on this path since the
  Flask app is locked to `127.0.0.1` afterward (`-LockWebUIToLocalhost`) — nothing else on the
  network can reach port 5000 directly to spoof that header. If you skip
  `-LockWebUIToLocalhost`, port 5000 stays reachable from the network and someone could bypass IIS
  entirely and set their own `X-Remote-User` header talking to Flask directly — so treat
  `-LockWebUIToLocalhost` as required, not optional, once you deploy Phase 5.

---

## Firewall impact — what's actually new

**Nothing for Phases 1-3.** They're all local to the jump server (loopback health checks, a local
binary, an in-process thread pool) and don't open or require any new ports.

| Phase | Source | Destination | Port | Reason |
|---|---|---|---|---|
| 4 (optional) | Jump server | Postgres server | TCP/5432 | Asset store queries, only if `ASSETS_DATABASE_URL` points at a remote host (loopback if Postgres runs on the jump server itself) |
| 5 (optional) | Analyst workstations | Jump server (IIS) | TCP/443 | Replaces direct TCP/5000 access once deployed — see below |

**Phase 5 changes an existing rule rather than adding one:** once deployed with
`-LockWebUIToLocalhost`, port 5000 is no longer reachable from the network at all — only IIS on
443 is. `firewall-request-ports.csv` row 20 has been updated to reflect analysts hitting 443
(IIS) instead of 5000 (Flask directly); no new port is opened, an existing one is effectively
replaced.

This has been added to `firewall-request-ports.csv` as row 21, marked optional/Phase-4-only, so
it's ready to hand to your network team alongside the existing list if and when you deploy
Postgres remotely.

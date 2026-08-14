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

### Pre-existing, not introduced by this work — flagging because it's the biggest gap
- **No authentication on the web UI.** `firewall-request-ports.csv` already documents this
  (`"no built-in auth"` on the port-5000 inbound rule). Anyone who can reach TCP 5000 can trigger
  scans/discovery, delete assets, and view every collected result — including installed software
  inventories, compliance gaps, and (if configured) vendor warranty API responses. This predates
  the four phases here and wasn't part of what was asked for, but given "I hope the entire
  solution is secure": **this is the one item worth prioritizing next.** Cheapest fix is fronting
  port 5000 with an IIS/nginx reverse proxy doing Windows-integrated or basic auth restricted to
  your analyst group, since the firewall doc already recommends fronting it with a reverse proxy.
- **Traffic is plain HTTP**, not HTTPS, both to the web UI and (originally) between browser and
  server. Same reverse-proxy step above should terminate TLS.

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
- **`/healthz` info disclosure**: it's unauthenticated (same as everything else) and returns
  internal detail strings (e.g. exception text, disk paths) on failure. Low severity — no
  credentials or scan data are ever included — but once you add the reverse-proxy auth layer
  above, `/healthz` gets covered by it too.

---

## Firewall impact — what's actually new

**Short answer: nothing, for Phases 1-3.** They're all local to the jump server (loopback health
checks, a local binary, an in-process thread pool) and don't open or require any new ports.

**Phase 4 (Postgres) is the only one with a firewall implication, and only if you host the
database on a separate server:**

| Source | Destination | Port | Reason |
|---|---|---|---|
| Jump server (Jump-Jeremy) | Postgres server | TCP/5432 | Asset store queries, if `ASSETS_DATABASE_URL` points at a remote host |

If Postgres runs on Jump-Jeremy itself (`localhost` in the connection string), this is a loopback
connection and needs no firewall change at all.

This has been added to `firewall-request-ports.csv` as row 21, marked optional/Phase-4-only, so
it's ready to hand to your network team alongside the existing list if and when you deploy
Postgres remotely.

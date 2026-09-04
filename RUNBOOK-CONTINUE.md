# Runbook — Continuing From the Current Deployment

Your deployed instance is running and reachable, but on an **older build**. This runbook takes it
from where it is now to fully current, then enables the remaining features in a safe order.

Work top to bottom. Each part is independently useful and safe to stop after.

---

## Part 0 — Confirm your baseline

The navigation bar tells you roughly which build is deployed. Your current UI shows:

> Assets · Software · WinRM Test · vs PDQ · Integrations · Live Dashboard

Three links are **missing** — `vs Prometheus`, `Endpoints` and `SOAR` — which places your build
before commit `b3927a6`. Everything from the Prometheus exporter onwards is not deployed.

Confirm precisely on the server:

```powershell
cd C:\AD-Agent
git log -1 --oneline          # what's actually checked out
git fetch origin
git log HEAD..origin/claude/optimistic-bohr-tnmeli --oneline   # what you're missing
```

Quick feature probes (each answers a yes/no about your build):

```powershell
Invoke-WebRequest http://localhost:5000/healthz   -UseBasicParsing   # 200/503 = Phase 1 present, 404 = not
Invoke-WebRequest http://localhost:5000/metrics   -UseBasicParsing   # 200 = Prometheus exporter present
Invoke-WebRequest http://localhost:5000/endpoints -UseBasicParsing   # 200 = collector build present
Get-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog' -ErrorAction SilentlyContinue  # watchdog registered?
Test-Path C:\AD-Agent\DCAnomalyAgent\bin\netscan.exe                 # Go accelerator built?
```

Record the answers — they tell you which parts below you can skip.

---

## Part 1 — Update the code *(do this first; ~10 minutes)*

This single step brings in everything: the Endpoints and SOAR pages, the Prometheus exporter, the
watchdog fixes, the certificate-scan crash fix, and all the deployment documentation.

### 1.1 Pre-checks

```powershell
cd C:\AD-Agent
git log -1 --oneline                                   # note this - your rollback point
Get-ScheduledTask -TaskName 'DCAnomalyAgent-*' | Get-ScheduledTaskInfo |
    Where-Object State -eq 'Running'                   # let any running scan finish
```

### 1.2 Stop, pull, restart

```powershell
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'

git pull origin claude/optimistic-bohr-tnmeli

Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-Sleep -Seconds 5
Invoke-WebRequest http://localhost:5000/healthz -UseBasicParsing | Select -Expand Content
```

Stopping first avoids a file-lock error on `app.py`.

### 1.3 Verify the update landed

Reload the web UI. The navigation bar should now read:

> Assets · **SOAR** · **Endpoints** · Software · WinRM Test · vs PDQ · **vs Prometheus** · Integrations · Live Dashboard

Then:

| Check | Expect |
|---|---|
| `/endpoints` | Loads, says the push collector is not enabled yet |
| `/soar` | Loads, says SOAR is disabled |
| `/metrics` | Returns Prometheus text |
| `/healthz` | `status: ok` (or the same warnings as before) |

The asset database migrates itself on first connection — new check-in columns and the
`checkin_days` table are added automatically. Existing rows are untouched.

### 1.4 Confirm the certificate fix

Your last scan crashed on `Find-ExpiringCertificates` with an `op_Addition` error. Re-run it:

```powershell
cd C:\AD-Agent\DCAnomalyAgent
.\Run-AnomalyScan.ps1 -CertificateScan -SkipAnomalyScan
```

It should now complete past "Starting certificate expiry scan..." instead of throwing.

### 1.5 Rollback if needed

```powershell
git checkout <commit noted in 1.1>
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

**Stop here if you just want the fixes.** Everything below is opt-in.

---

## Part 2 — Self-healing watchdog *(~10 minutes, no risk)*

Skip if `Get-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'` already returns a task.

```powershell
# ELEVATED PowerShell - registering a gMSA-principal task requires local admin
cd C:\AD-Agent\DCAnomalyAgent\Install
.\Watch-WebUIHealth.ps1 -Register -GmsaAccount 'AMG\svc-discoverAgt$'
Start-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'
Start-Sleep -Seconds 20
Get-Content C:\AD-Agent\DCAnomalyAgent\State\watchdog.log -Tail 5
```

Expect `Health check OK (status=ok).` If the web UI is down, you'll instead see a failure line and
a restart after two cycles — that's the feature working.

---

## Part 3 — Authentication *(schedule a window; do before Part 6 live)*

The web UI still has **no login** — anyone who can reach port 5000 can run scans, delete assets and
read every finding. This is the highest-value remaining item.

1. Stage the IIS prerequisites (not fetchable on a locked-down box):
   [URL Rewrite](https://www.iis.net/downloads/microsoft/url-rewrite) and
   [ARR 3.0](https://www.iis.net/downloads/microsoft/application-request-routing)
2. Create the analyst AD group, e.g. `AMG\AD-Agent-Analysts`
3. Obtain an internal CA certificate (or accept the self-signed one for a first test)

```powershell
cd C:\AD-Agent\DCAnomalyAgent\Install
.\Register-IISReverseProxy.ps1 -AllowedGroup 'AMG\AD-Agent-Analysts' `
    -LockWebUIToLocalhost -GmsaAccount 'AMG\svc-discoverAgt$' `
    -PythonPath 'C:\Apps\Python312\python.exe' -CertThumbprint '<thumbprint>'

Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

Then browse `https://jump-jeremy.amg.local` — expect a Windows Authentication prompt, and denial
if you're outside the group. Ask the network team to add row 22 (inbound 443) and drop row 20
(inbound 5000).

📄 `ENTERPRISE-HARDENING-RUNBOOK.md` Phase 5

---

## Part 4 — Endpoint push collector *(highest coverage gain)*

Solves the laptop problems directly: unreachable VLANs, DHCP churn, devices asleep at scan time.

### 4.1 Enable the endpoint

```powershell
$token = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
$token   # record this

[Environment]::SetEnvironmentVariable('COLLECTOR_TOKEN', $token, 'Machine')
[Environment]::SetEnvironmentVariable('CORPORATE_NETWORKS', '172.29.0.0/16,10.44.0.0/16', 'Machine')
[Environment]::SetEnvironmentVariable('CORPORATE_DNS_SUFFIX', 'amg.local', 'Machine')

Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

Replace the CIDRs with your real internal ranges — that's what separates office from home
check-ins. Verify (401 is the *correct* answer here):

```powershell
Invoke-WebRequest -Uri 'http://localhost:5000/api/collector/checkin' -Method POST -Body '{}' `
    -ContentType 'application/json' -Headers @{ 'X-Collector-Token' = 'wrong' } -UseBasicParsing
```

### 4.2 Test on ONE laptop before any rollout

⚠ `Send-InventoryCheckin.ps1` has never been executed anywhere. Prove it on one machine first.

```powershell
.\Send-InventoryCheckin.ps1 -ServerUrl 'http://jump-jeremy.amg.local:5000' -Token '<TOKEN>' -Verbose
Get-Content "$env:ProgramData\AD-Agent\collector.log" -Tail 5
```

Expect `Check-in accepted`. Then confirm on the server that it appears on `/endpoints` **and**
merged into its existing `/assets` row rather than creating a duplicate.

### 4.3 Roll out

- **Domain-joined:** GPO — `DCAnomalyAgent\Install\Deploy-PushCollector-GPO.md`
- **Non-domain servers:** `Install-PushCollector.ps1` per host — `COVERAGE-NON-DOMAIN.md`

Firewall row 23 (outbound only) replaces the inbound WinRM ask for laptop VLANs.

---

## Part 5 — Cloudflare WARP sync *(optional, ~30 minutes)*

Presence for laptops off the corporate network, using the agent already installed on them.

1. Cloudflare API token with **Zero Trust → Read**, plus Account ID
2. Save both on the web UI **Integrations** page (writes to the gitignored secrets file)
3. Set `Integrations.CloudflareZeroTrust.Enabled = $true` in `settings.psd1`
4. Dry run, then register the hourly task:

```powershell
cd C:\AD-Agent\DCAnomalyAgent
.\Sync-CloudflareDevices.ps1 -WhatIf         # queries Cloudflare, writes nothing

cd Install
.\Register-ScheduledTask.ps1 -GmsaAccount 'AMG\svc-discoverAgt$'
Start-ScheduledTask -TaskName 'DCAnomalyAgent-Scan-CloudflareSync'
Get-Content C:\AD-Agent\DCAnomalyAgent\State\cloudflare-sync.log -Tail 10
```

Firewall row 24. Identity and presence only — no software inventory, and roughly hourly, not live.

---

## Part 6 — SOAR *(dry-run now; live only after Part 3)*

```powershell
[Environment]::SetEnvironmentVariable('SOAR_MODE', 'dryrun', 'Machine')
[Environment]::SetEnvironmentVariable('TEAMS_WEBHOOK_URL', '<webhook>', 'Machine')
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

Open `/soar`. The preview shows what would fire against your current snapshot without writing
anything; **Run playbooks now** records incidents but still executes nothing.

**Leave it in dry-run for at least a week.** Review the incidents and ask whether you'd have been
happy for those to act automatically — that's the decision, not the config.

Before ever setting `live`:

- [ ] Part 3 complete (otherwise approvals are recorded as `unauthenticated@<ip>`)
- [ ] Your break-glass and service accounts added to `$ProtectedIdentities` in `Invoke-SoarResponder.ps1`
- [ ] Responder tested by hand: `.\Invoke-SoarResponder.ps1 -Action disable_ad_user -Identity 'test-user' -WhatIf`
- [ ] A non-gMSA account chosen to run destructive actions (the scanning gMSA is read-only by design)

---

## Part 7 — Optional extras

| Item | When | Reference |
|---|---|---|
| Go scan accelerator | Large subnet scans feel slow | `ENTERPRISE-HARDENING-RUNBOOK.md` Phase 2 |
| PostgreSQL store | Past a few thousand assets, or multi-site | Phase 4 |
| Prometheus + Grafana | You want long-term trends and alert routing | `/prometheus-comparison` in the UI |

---

## Suggested sequence

| When | Do |
|---|---|
| Today | Part 1 (update + verify), Part 2 (watchdog), Part 6 dry-run |
| This week | Part 4.1–4.2 (collector on one test laptop) |
| Next change window | Part 3 (authentication) |
| After that | Part 4.3 (GPO rollout), Part 5 (Cloudflare) |
| Once dry-run is trusted, and Part 3 done | Part 6 live |

Part 1 alone gets you three new pages and the certificate-scan fix, with a one-command rollback.
Everything after it is additive and independently reversible.

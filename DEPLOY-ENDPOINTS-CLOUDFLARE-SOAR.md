# Deployment — Push Collector, Cloudflare Sync, and SOAR

Covers the three features added after the Phase 1–5 hardening batch:

1. **Push collector** — endpoints push their own inventory outbound (`/endpoints` page)
2. **Cloudflare WARP sync** — device roster/presence for laptops off the corporate network
3. **SOAR** — playbook-driven incidents and approval-gated AD response (`/soar` page)

Stages 1 and 2 are independent and low risk. **Stage 3 has a hard prerequisite — read it before
starting.**

---

## ⚠ Read first: SOAR and authentication

The web UI still has **no built-in authentication**. That is tolerable for read-only dashboards
behind a firewall. It is **not** tolerable for the SOAR approval buttons: anyone who can reach
port 5000 could approve a `disable_ad_user` action against your directory.

**Therefore:**

- SOAR in `dryrun` is safe to run now — it executes nothing, so there is nothing to approve.
- **Do not set `SOAR_MODE=live` with any destructive playbook enabled until
  `Register-IISReverseProxy.ps1` (Phase 5) is deployed with `-AllowedGroup` and
  `-LockWebUIToLocalhost`.** That's what puts Windows Authentication in front of the approve
  button and records who approved what.

The audit trail records an approver name, but until Phase 5 is in place that name is
`unauthenticated@<ip>` — which is not an accountable record for a production AD change.

---

## Stage 0 — Sync the code and restart

```powershell
cd C:\AD-Agent
git pull origin claude/optimistic-bohr-tnmeli

Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-Sleep -Seconds 5
Invoke-WebRequest http://localhost:5000/healthz -UseBasicParsing | Select -Expand Content
```

New/changed files in this batch:
```
WebApp/app.py                 WebApp/soar.py                (new)
WebApp/assets_db.py           WebApp/templates/soar.html    (new)
WebApp/templates/endpoints.html (new)                       WebApp/templates/base.html
DCAnomalyAgent/Collector/Send-InventoryCheckin.ps1          (new)
DCAnomalyAgent/Sync-CloudflareDevices.ps1                   (new)
DCAnomalyAgent/Invoke-SoarResponder.ps1                     (new)
DCAnomalyAgent/Modules/DCAnomalyAgent.CloudflareDevices.psm1 (new)
DCAnomalyAgent/Config/playbooks.json                        (new)
DCAnomalyAgent/Install/Register-ScheduledTask.ps1
DCAnomalyAgent/Install/Deploy-PushCollector-GPO.md           (new)
```

The `assets.db` schema migrates itself on first connection (adds check-in columns and the
`checkin_days` table). Existing rows are untouched — verified against a copy of the original
schema with data in it.

**Verify:** `/endpoints` and `/soar` both load. `/endpoints` should say the push collector isn't
enabled yet; `/soar` should say SOAR is disabled. Both are the expected "off" states.

---

## Stage 1 — Push collector

### 1.1 Enable the endpoint

```powershell
$token = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
$token    # copy this

[Environment]::SetEnvironmentVariable('COLLECTOR_TOKEN', $token, 'Machine')
[Environment]::SetEnvironmentVariable('CORPORATE_NETWORKS', '172.29.0.0/16,10.44.0.0/16', 'Machine')
[Environment]::SetEnvironmentVariable('CORPORATE_DNS_SUFFIX', 'amg.local', 'Machine')

Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

Replace the CIDRs with your real internal ranges — that's what separates office check-ins from
home ones, and what makes "last seen in the office" meaningful.

**Verify** (401 is the correct answer — the endpoint is up and rejecting a bad token):
```powershell
Invoke-WebRequest -Uri 'http://localhost:5000/api/collector/checkin' -Method POST -Body '{}' `
    -ContentType 'application/json' -Headers @{ 'X-Collector-Token' = 'wrong' } -UseBasicParsing
```

### 1.2 Test on ONE machine before the GPO

Copy `Send-InventoryCheckin.ps1` to a test laptop and run it by hand:

```powershell
.\Send-InventoryCheckin.ps1 -ServerUrl 'http://jump-jeremy.amg.local:5000' -Token '<TOKEN>' -Verbose
Get-Content "$env:ProgramData\AD-Agent\collector.log" -Tail 5
```

Expect `Check-in accepted by ... (key: ...)`. Then confirm on the jump server that the device
appears on `/endpoints` **and** that it merged into its existing row on `/assets` rather than
creating a duplicate.

This script has not been executed anywhere yet — run it on one machine and read the log before
going near a GPO.

### 1.3 Roll out via GPO

Follow `DCAnomalyAgent\Install\Deploy-PushCollector-GPO.md` (steps 2–5): stage the script in
SYSVOL, create the two scheduled tasks (30-minute presence, daily full inventory), scoped to
laptop/workstation OUs — **not** the Domain Controllers OU.

### 1.4 Firewall

Row 23 of `firewall-request-ports.csv`: endpoint VLANs → jump server, outbound only. This
**replaces** the inbound WinRM/SMB ask for roaming laptop VLANs (rows 8–9).

---

## Stage 2 — Cloudflare WARP sync

### 2.1 Create a Cloudflare API token

In the Cloudflare Zero Trust dashboard: an API token with **Account → Zero Trust → Read**, plus
your Account ID.

### 2.2 Save the credentials

Enter them on the web UI's **Integrations** page so they're written to
`Config\integration-secrets.json` (gitignored). Then enable the integration in `settings.psd1`:

```powershell
# DCAnomalyAgent\Config\settings.psd1
CloudflareZeroTrust = @{
    Enabled  = $true
    ApiToken = ''      # leave blank - the secrets file is preferred
    AccountId = ''
}
```

### 2.3 Dry run first

```powershell
cd C:\AD-Agent\DCAnomalyAgent
.\Sync-CloudflareDevices.ps1 -WhatIf
```

This queries Cloudflare and prints the device roster it *would* record, writing nothing. Confirm
the hostnames look like your estate before proceeding.

### 2.4 Register the hourly task

```powershell
cd C:\AD-Agent\DCAnomalyAgent\Install
.\Register-ScheduledTask.ps1 -GmsaAccount 'AMG\svc-discoverAgt$'
```

This re-registers all scan tasks and adds `DCAnomalyAgent-Scan-CloudflareSync` (hourly). Then:

```powershell
Start-ScheduledTask -TaskName 'DCAnomalyAgent-Scan-CloudflareSync'
Get-Content C:\AD-Agent\DCAnomalyAgent\State\cloudflare-sync.log -Tail 10
```

**Firewall:** row 24 — jump server → `api.cloudflare.com` TCP/443.

**Expectation to set:** this gives device identity and presence only. Cloudflare has no
installed-software API, so those devices show OS/user/last-seen but no software list until the
push collector reaches them. Sync is hourly, so it's "online within roughly the last hour", not
a live view.

---

## Stage 3 — SOAR

### 3.1 Dry-run (safe to do now)

```powershell
[Environment]::SetEnvironmentVariable('SOAR_MODE', 'dryrun', 'Machine')
[Environment]::SetEnvironmentVariable('TEAMS_WEBHOOK_URL', '<your Teams webhook>', 'Machine')
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

Open `/soar`. The **Preview** panel shows what would fire against the current scan snapshot
without writing anything. Click **Run playbooks now** to record incidents (still executes
nothing in dry-run).

**Leave it here for at least a week.** Review the incidents it raises and ask: would I have been
happy for this to act automatically? That's the question that decides whether live mode is
appropriate at all.

### 3.2 Before ever going live

- [ ] Phase 5 (IIS reverse proxy + Windows Auth) deployed — see the warning at the top
- [ ] Edit `$ProtectedIdentities` in `Invoke-SoarResponder.ps1` to include **your** break-glass
      and critical service accounts. The shipped list (`Administrator`, `krbtgt`, `Guest`,
      `DefaultAccount`) is a floor, not a complete list for your environment.
- [ ] Decide which account runs destructive actions. The scanning gMSA is read-only and
      **cannot** perform them — that's deliberate. A separate, appropriately-scoped account is
      required if you enable them.
- [ ] Test the responder by hand against a disposable test account:
      ```powershell
      .\Invoke-SoarResponder.ps1 -Action disable_ad_user -Identity 'test-user' -WhatIf
      ```
      This script has never been executed. Run `-WhatIf` first, then once for real against a
      test account, and read `State\soar-responder.log`.

### 3.3 Live mode

```powershell
[Environment]::SetEnvironmentVariable('SOAR_MODE', 'live', 'Machine')
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

Safe actions (Teams notification, asset tagging) now execute automatically. AD-changing actions
still queue on `/soar` for approval — in every mode. Enable the two destructive example
playbooks in `playbooks.json` only when you're ready for that.

---

## Verification checklist

| Check | Where |
|---|---|
| Web UI healthy | `/healthz` → `status: ok` |
| Collector enabled | `/endpoints` no longer shows the "not enabled" banner |
| Check-ins arriving | `/endpoints` lists devices; `State\audit.log` has `collector_checkin` lines |
| Office/home split working | `/endpoints` Location column shows Office/Remote, not all Unknown |
| No duplicate assets | A checked-in laptop appears once on `/assets`, with a refreshed IP |
| Cloudflare syncing | `State\cloudflare-sync.log` shows "Sync complete: N recorded" |
| SOAR evaluating | `/soar` preview lists matches; incidents appear after "Run playbooks now" |
| SOAR safe | Destructive actions show as **awaiting approval**, never as executed |

---

## Rollback

Each stage is independent and reverts by unsetting one variable plus a restart:

```powershell
# Disable SOAR entirely
[Environment]::SetEnvironmentVariable('SOAR_MODE', $null, 'Machine')

# Disable push check-ins (endpoint returns 503; GPO tasks fail harmlessly and log locally)
[Environment]::SetEnvironmentVariable('COLLECTOR_TOKEN', $null, 'Machine')

# Disable Cloudflare sync
Disable-ScheduledTask -TaskName 'DCAnomalyAgent-Scan-CloudflareSync'

Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

To roll the code back entirely, see `DEPLOYMENT.md` §12.6. The schema additions are additive
(new nullable columns and a new table) so an older build reads the same database without error.

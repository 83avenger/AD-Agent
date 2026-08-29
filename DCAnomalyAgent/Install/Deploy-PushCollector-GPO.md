# Deploying the Push Collector via GPO

The push collector inverts discovery for endpoints: instead of the jump server reaching *in*
over WinRM, each endpoint collects its own inventory and POSTs it *out* to the jump server.

**Why this exists:** every coverage gap hit so far has been on roaming laptops — VLANs the
firewall won't allow inbound WinRM to, IPs that change several times a week, and devices asleep
or off-network when the scheduled scan runs. None of those are solvable by scanning harder.

**What it changes for the network team:** one **outbound** rule (endpoint VLANs → jump server)
replaces inbound WinRM/SMB rules to every workstation VLAN. That's a materially smaller ask than
the inbound-per-VLAN request.

Servers and DCs stay on agentless WinRM — they're static, always-on, already reachable, and
already have approved rules. Don't deploy this to them.

---

## 1. Generate a token and enable the endpoint

On the jump server, generate a random token:

```powershell
$token = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
$token   # copy this - you need it in step 3
```

Set it as a machine environment variable so the web UI's Scheduled Task inherits it, then
restart the web UI:

```powershell
[Environment]::SetEnvironmentVariable('COLLECTOR_TOKEN', $token, 'Machine')
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'; Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
```

Until `COLLECTOR_TOKEN` is set, `/api/collector/checkin` refuses every request with HTTP 503 —
the feature is off by default rather than silently accepting unauthenticated writes.

Verify it's live (401 = endpoint is up and rejecting a bad token, which is what you want):

```powershell
Invoke-WebRequest -Uri 'http://localhost:5000/api/collector/checkin' -Method POST `
    -Body '{}' -ContentType 'application/json' `
    -Headers @{ 'X-Collector-Token' = 'deliberately-wrong' } -UseBasicParsing
```

---

## 2. Stage the collector script where endpoints can read it

Copy `DCAnomalyAgent\Collector\Send-InventoryCheckin.ps1` to a location every domain computer can
read — SYSVOL is the usual choice since it already replicates to every DC:

```
\\amg.local\SYSVOL\amg.local\scripts\AD-Agent\Send-InventoryCheckin.ps1
```

---

## 3. Create the GPO

New GPO (e.g. `AD-Agent-PushCollector`), linked to the OU(s) containing laptops/workstations —
**not** the Domain Controllers OU.

`Computer Configuration > Preferences > Control Panel Settings > Scheduled Tasks`
→ New → **Scheduled Task (At least Windows 7)**

Create **two** tasks — a frequent lightweight presence check and one daily full inventory. The
software enumeration walks the registry, so running it every 30 minutes on every endpoint is
wasteful; presence is what you need often, software is what you need daily.

### Task A — presence check-in (frequent)

| Field | Value |
|---|---|
| Name | `AD-Agent Check-in` |
| Run as | `NT AUTHORITY\SYSTEM`, **Run with highest privileges** |
| Trigger | Daily, repeat every **30 minutes** indefinitely |
| Trigger | Also add: **At log on** and **On workstation unlock** — this is what makes a returning laptop appear promptly |
| Action | Start a program |
| Program | `powershell.exe` |
| Arguments | `-NoProfile -ExecutionPolicy Bypass -File "\\amg.local\SYSVOL\amg.local\scripts\AD-Agent\Send-InventoryCheckin.ps1" -ServerUrl "https://jump-jeremy.amg.local" -Token "<TOKEN>" -SkipSoftware` |

Under **Settings**, tick *Run task as soon as possible after a scheduled start is missed* — that's
what catches a laptop that was asleep at the scheduled time.

### Task B — full inventory (daily)

Same as above, except:

| Field | Value |
|---|---|
| Name | `AD-Agent Full Inventory` |
| Trigger | Daily at a time laptops are typically on (e.g. **13:00**, not 03:00 — laptops are shut) |
| Arguments | Same, but **without** `-SkipSoftware` |

---

## 4. Firewall

One outbound rule. Hand this to the network team in place of the inbound-per-VLAN request:

| Source | Destination | Port | Reason |
|---|---|---|---|
| Endpoint VLANs (laptops/workstations) | Jump server | TCP/443 (or 5000 pre-IIS) | Push collector check-in — outbound only, no inbound rule to endpoints required |

This row is also in `firewall-request-ports.csv` (row 23).

---

## 5. Verify

On a test endpoint, run the task manually and check the local log:

```powershell
Start-ScheduledTask -TaskName 'AD-Agent Check-in'
Get-Content "$env:ProgramData\AD-Agent\collector.log" -Tail 10
```

Expect `Check-in accepted by ... (key: ...)`. Then on the jump server, the device should appear
on the **Endpoints** page in the web UI, and its check-in should have merged into its existing
Assets row rather than creating a duplicate.

Failures are logged locally with the real error, and the task exits non-zero so
`LastTaskResult` in Task Scheduler reflects it rather than silently reporting success.

---

## Security notes — read before rolling out broadly

**The token is readable by domain users.** Scheduled Task arguments delivered by GPO live in
SYSVOL, which Authenticated Users can read by default, and are visible in the task definition on
the endpoint itself. Do not treat this token as a secret that only admins hold.

What that does and doesn't get an attacker who reads it:

- It is **write-only**: the endpoint accepts a check-in and returns a dedup key. It cannot be
  used to read the asset inventory, scan results, or anything else.
- Worst case is **bogus inventory** — fabricated devices or false software lists. Annoying and
  potentially misleading for compliance reporting, not a path into AD or the jump server. The
  payload only reaches the database through parameterized SQL.

Reasonable mitigations, in increasing order of effort:

1. **Tighten the SYSVOL folder ACL** on the script directory to `Domain Computers` + admins.
   This narrows who can read it, though machine accounts still can.
2. **Rotate periodically** — change `COLLECTOR_TOKEN` and the GPO value together, restart the web
   UI. Old tokens stop working immediately.
3. **Best: replace the shared token with Windows Authentication.** Once
   `Register-IISReverseProxy.ps1` (Phase 5) is deployed, IIS can authenticate the endpoint's own
   *machine account* via Kerberos, and the shared token becomes unnecessary. Each endpoint then
   proves its identity with a credential it already has and never exposes. If you're deploying
   both, do Phase 5 first and skip the token entirely.

**Per-user installed software is a known blind spot.** The task runs as SYSTEM, so `HKCU` is
SYSTEM's hive, not the signed-in user's. Applications installed per-user (some Chrome/Teams/Zoom
deployments) won't be enumerated. Machine-wide installs — the overwhelming majority in a managed
estate — are captured normally.

# Change Ticket — AD-Agent Reliability Update (Phases 1–3)

**Target system:** Jump-Jeremy (`amg.local`) — AD-Agent web UI + scan Scheduled Tasks
**Change type:** Standard / low-risk — no new inbound ports, no auth/protocol change, no new
external dependency required
**Rollback:** Trivial — see Rollback section. Every change here is additive with an existing
fallback path; nothing in this batch removes or replaces working functionality.

---

## 1. Summary

Three reliability improvements to the AD-Agent web UI, bundled as one change since they share
the same file sync and restart step:

| Phase | What | User-visible effect |
|---|---|---|
| 1 | Self-healing watchdog | None under normal operation — only kicks in if the web UI process hangs or crashes |
| 2 | Go network-scan accelerator (optional) | Discovery scans against large subnets complete faster |
| 3 | Non-blocking scan/discovery | Submitting a scan shows a live "running…" page instead of a hung browser tab; concurrent users no longer block each other |

**Explicitly out of scope for this ticket:** Phase 4 (PostgreSQL) and Phase 5 (IIS
authentication) — both are separate, higher-consideration changes tracked independently. Phase 5
in particular changes how the tool is reached and should go through its own change window; see
`ENTERPRISE-HARDENING-RUNBOOK.md` Phase 5 when ready for that one.

---

## 2. Why

- **Phase 1** closes a gap where the web UI's existing auto-restart (Scheduled Task
  `-RestartCount`) only catches a clean process crash, not a hang (process alive, no longer
  responding). A watchdog polling `/healthz` catches both.
- **Phase 2** addresses "our tool is generating other ports which is not allowed" and general
  scan-speed concerns raised earlier — a faster scanner reduces how long a large subnet scan
  ties up resources. Purely optional; skip if you'd rather not install Go on this server.
- **Phase 3** fixes a real concurrency problem: today, one person running a scan blocks the
  Flask worker thread for the full scan duration, which can make the dashboard sluggish for
  everyone else using the tool at the same time.

---

## 3. Pre-checks (do these first)

- [ ] Confirm no scan or discovery job is actively running (check the web UI, or
      `Get-ScheduledTask -TaskName 'DCAnomalyAgent-*' | Get-ScheduledTaskInfo` for `Running` state)
- [ ] Confirm current `AD-Agent-WebUI` task is healthy: `Get-ScheduledTask -TaskName 'AD-Agent-WebUI' | Get-ScheduledTaskInfo`
- [ ] Take note of current `/healthz` output for a before/after comparison:
      `Invoke-WebRequest http://localhost:5000/healthz -UseBasicParsing`
- [ ] (Phase 2 only, if doing it in this window) Confirm Go can be installed per your
      change-control process, or plan to build `netscan.exe` on a separate machine and copy
      just the binary over

**Maintenance window needed:** ~5 minutes of web UI downtime for the restart in step 2 below.
Scan/discovery Scheduled Tasks are unaffected and keep running on their normal schedule
regardless of web UI state.

---

## 4. Steps

### 4.1 Pull the code
```powershell
cd C:\Apps\AD-Agent
git pull origin claude/optimistic-bohr-tnmeli
```
Or copy these files if not using git directly on the server:
```
WebApp/app.py
WebApp/templates/job_wait.html                   (new)
DCAnomalyAgent/Install/Watch-WebUIHealth.ps1      (new)
tools/netscan/                                    (new folder - Phase 2 only)
```

### 4.2 Restart the web UI (picks up Phases 1 & 3 together)
```powershell
Stop-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-ScheduledTask -TaskName 'AD-Agent-WebUI'
Start-Sleep -Seconds 5
Get-ScheduledTask -TaskName 'AD-Agent-WebUI' | Get-ScheduledTaskInfo
```

### 4.3 Register the watchdog (Phase 1, one-time)
```powershell
cd DCAnomalyAgent\Install
.\Watch-WebUIHealth.ps1 -Register -GmsaAccount 'AMG\svc-discoverAgt$'
Start-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'
```

### 4.4 Build the scan accelerator (Phase 2, optional — skip if not doing Go this window)
```powershell
cd DCAnomalyAgent\Install\..\..\tools\netscan
.\build.ps1
```

---

## 5. Verification

| Check | Command | Expected |
|---|---|---|
| Web UI responding | `Invoke-WebRequest http://localhost:5000/healthz -UseBasicParsing` | HTTP 200, `"status": "ok"` (or `"warn"` if no scan has run yet — not a failure) |
| Watchdog registered | `Get-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog'` | `Ready` |
| Watchdog logging | `Get-Content DCAnomalyAgent\State\watchdog.log -Tail 5` | `Health check OK (status=ok).` |
| Job queue live | Submit a test scan/discovery from the browser | Lands on a "Running…" page with a spinner, auto-redirects to results |
| netscan in use (if built) | `Get-Content DCAnomalyAgent\State\discovery.log -Tail 20` after a Discovery run | No "falling back to PowerShell scanner" warning |

---

## 6. Rollback

Every change in this batch is additive — there is no data migration or destructive step to undo.

- **Web UI misbehaving after restart:** `git checkout <previous-commit> -- WebApp/app.py WebApp/templates/job_wait.html`, then repeat step 4.2. The previous synchronous behavior returns immediately.
- **Watchdog causing unwanted restarts:** `Unregister-ScheduledTask -TaskName 'AD-Agent-WebUI-Watchdog' -Confirm:$false` — the web UI itself is untouched, this only removes the polling task.
- **netscan causing scan issues:** delete or rename `DCAnomalyAgent\bin\netscan.exe` — `Get-NetworkAsset` falls back to the PowerShell scanner automatically on the next run, no config change needed.

No firewall changes are required or requested for this ticket — all three phases are local to
the jump server.

---

## 7. Sign-off

| Role | Name | Date |
|---|---|---|
| Requested by | | |
| Approved by | | |
| Deployed by | | |
| Verified by | | |

---

*Full technical detail, security review, and Phases 4–5 (Postgres, IIS auth) are in
`ENTERPRISE-HARDENING-RUNBOOK.md` in the same repo.*

# Covering Non-Domain-Joined Servers

Workgroup servers, DMZ hosts, appliances with a Windows OS, vendor-managed boxes, anything
built outside the domain. This documents what works, what doesn't, and the options for the gap.

---

## Why the normal path doesn't reach them

Everything the jump server initiates depends on domain identity:

| Mechanism | Why it fails on a non-domain host |
|---|---|
| `Get-ADComputer` discovery | The host has no AD computer object — it simply isn't there to enumerate |
| WinRM via gMSA | Kerberos needs a domain identity on both ends. There's no ticket to present |
| GPO deployment | GPO applies to domain members only |
| Remote Registry / CIM | Same authentication problem |

Confirmed in the code: there is currently **no `-Credential` support anywhere** — all 20 remote
call sites rely on ambient Kerberos from the gMSA.

---

## What already works today

**Network discovery finds them.** `Get-NetworkAsset` (and the Go accelerator) is a TCP port
scan — it doesn't authenticate to anything. A non-domain server on a scanned CIDR already shows
up in the inventory as `Windows`, with its open ports and last-seen.

So they aren't invisible. They're just shallow: a name, an IP, and a guess at the type.

---

## What closes most of the gap: the push collector

The push collector **doesn't care about domain membership.** It runs locally as SYSTEM and
authenticates outbound with the shared token — no Kerberos, no gMSA, no inbound rule. The only
thing that didn't work for non-domain hosts was the *deployment* method, since GPO can't reach
them.

`DCAnomalyAgent\Collector\Install-PushCollector.ps1` fixes that — run it once per host:

```powershell
.\Install-PushCollector.ps1 -ServerUrl 'https://jump-jeremy.amg.local' -Token '<COLLECTOR_TOKEN>'
```

It copies the collector locally, registers the same two scheduled tasks the GPO would have
(presence every 30 min plus at startup, full inventory daily), runs one check-in immediately and
prints the result so you know straight away whether it worked.

Good places to run it: your build/golden image, whatever config management already reaches these
hosts (Ansible, DSC, a run-once script), or by hand for a handful of servers.

Uninstall is `-Uninstall`.

---

## Coverage matrix — be clear-eyed about this

| Capability | Domain-joined | Non-domain + collector | Non-domain, scan only |
|---|---|---|---|
| Discovered / inventoried | ✅ | ✅ | ✅ |
| Online / last-seen | ✅ | ✅ | ✅ (only when reachable at scan time) |
| OS, device category | ✅ | ✅ | ⚠️ port-based guess |
| Installed software | ✅ | ✅ | ❌ |
| Zero-day / KEV cross-reference | ✅ | ✅ (follows from software) | ❌ |
| **Compliance scanning (CIS/NIST/ISO)** | ✅ | ❌ | ❌ |
| **Certificate store scanning** | ✅ | ❌ | ❌ |
| Anomaly detection (event logs) | ✅ | ❌ | ❌ |
| SOAR AD response actions | ✅ | n/a — no AD object to act on | n/a |

The collector gets you from "a name and an IP" to "full asset and software inventory". It does
**not** get you compliance, certificate or anomaly scanning, because those run *from* the jump
server over WinRM and still have nothing to authenticate with.

---

## Closing the compliance gap — three options

### Option A — credentialed WinRM

Add `-Credential` support and store a local admin credential per host (or one shared account).

- **Pros:** full parity, no endpoint install.
- **Cons:** you are storing local administrator credentials at rest for machines that are
  outside domain protections — often the *least* hardened hosts you own. Without an HTTPS WinRM
  listener on each target you're also sending NTLM over HTTP. Plus `TrustedHosts` entries on the
  jump server, and a credential rotation problem nobody will own.
- **Effort:** moderate. The framework helps more than expected — `Test-ComplianceControl` already
  passes an optional `$Context` hashtable to every check scriptblock, and the Linux/SSH path
  already uses it for connection details. A third transport is a natural extension rather than a
  rewrite. But each check that calls `Invoke-Command` internally has to honour it.

### Option B — extend the collector to run compliance checks locally *(recommended if you have more than a handful)*

The endpoint already runs code locally with SYSTEM rights. Have it evaluate the compliance
controls for itself and push the results, exactly as it pushes software today.

- **Pros:** no credentials stored anywhere, no inbound rules, no `TrustedHosts`, no NTLM. Works
  identically for domain-joined, non-domain, DMZ and roaming machines — it collapses several
  coverage problems into one mechanism. It's also where the tool is already heading.
- **Cons:** the control definitions have to run on the endpoint, so the check scriptblocks need
  to be executable locally and shipped to the host. Checks that inspect *domain* state (password
  policy, GPO, AD groups) are meaningless on a workgroup box anyway and would be filtered out —
  what remains is the host-level set (SMB signing, NTLMv1, RDP NLA, firewall, Defender, patch
  age, local admins, services), which is the majority of the non-DC controls.
- **Effort:** the largest of the three, but the only one that doesn't create a credential
  liability.

### Option C — accept inventory-only coverage

If non-domain servers are few, low-risk, or vendor-managed under someone else's compliance
regime, deploy the collector for inventory and explicitly scope them out of compliance
reporting. Record the decision so an auditor sees a deliberate exclusion rather than a blind
spot.

---

## Recommendation

1. **Now:** run `Install-PushCollector.ps1` on your non-domain servers. It's already built and
   tested against the same endpoint as the GPO path, needs no credentials, and takes them from
   near-zero to full inventory coverage.
2. **Then decide on compliance by population size.** A handful of vendor-managed boxes →
   Option C with a documented exclusion. A meaningful estate you're accountable for → Option B.
3. **Avoid Option A** unless something forces it. Storing local admin credentials for your least
   hardened hosts, on the server that scans your domain controllers, is a poor trade — and this
   engagement has already shown how much pain credential/auth mismatches cause here.

---

## Practical notes

- **Naming.** Workgroup machines are often built with generic names (`WIN-A3K9DL2`). Deduplication
  keys on the short hostname, so two hosts sharing a name would merge into one record. Give them
  distinct names before onboarding, or they'll silently collide.
- **Token distribution.** The same shared token is used, and on a non-domain host it sits in the
  scheduled task arguments readable by local admins. It is write-only (submit inventory, read
  nothing), but treat it as known-exposed and rotate it as a set.
- **Firewall.** Same rule as the GPO rollout — row 23, outbound from the host to the jump server.
  No inbound rule to these servers is needed, which is a genuine security improvement over
  opening WinRM into a DMZ.

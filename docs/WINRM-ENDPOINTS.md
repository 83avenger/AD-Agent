# WinRM on endpoints — why the GPO "applied" but 5985 is still closed, and the fixes

> **Step-by-step:** follow [`ENDPOINT-ROLLOUT-STEP-BY-STEP.md`](ENDPOINT-ROLLOUT-STEP-BY-STEP.md). This page is the background and reference.

The jump server scans endpoints over WinRM (TCP 5985). Laptops and desktops block inbound
WinRM by default, so it has to be turned on. There are three ways to do that, plus one that
avoids WinRM entirely:

| Method | Reaches endpoints whose firewall blocks everything inbound? | Off-network laptops? |
|---|---|---|
| **GPO** (`New-WinRMGPO.ps1`) | Yes — the endpoint pulls the GPO from the DC | Only when they're back on the network / VPN |
| **Intune** (`Intune\Build-IntunePackage.ps1`) | Yes — the endpoint pulls from the cloud | Yes |
| **From your admin laptop** (`Invoke-RemoteEndpointSetup.ps1`) | **No** — needs 5985 or 135 already open | No |
| **Push collector** (no WinRM at all) | Yes — outbound check-in only | Yes (via GPO startup script or Intune) |

**Being on the same VLAN doesn't get past the endpoint's own firewall.** If GPMC's
"Group Policy Update…" showed `0x800706ba` (RPC server unavailable) for a host, that host
drops RPC, so nothing remote — PsExec, WMI, schtasks, remote gpupdate — will reach it
either. Use GPO or Intune for those hosts.

---

## The four things a WinRM GPO needs

A hand-built GPO usually misses one of these:

1. **Service** — Windows Remote Management set to **Automatic**. It only *starts* at the
   next boot, so the endpoint needs a reboot (or `Start-Service WinRM`).
2. **Listener policy** — *Computer Configuration > Administrative Templates > Windows
   Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server
   management through WinRM* = **Enabled**, with **IPv4 filter = `*`** (and IPv6 = `*`).
   **A blank filter means no listener** — the most common mistake.
3. **Firewall rule** — inbound TCP 5985 allowed, on **all profiles**. A Domain-only rule
   does nothing for a laptop on Wi-Fi or VPN that Windows classes as Private or Public.
   Scope the **Remote address** to the jump server, not Any.
4. **The GPO actually applies** — the computer is in (or below) the linked OU, Security
   Filtering includes it (Domain Computers: Read + Apply), and there's no WMI filter
   excluding it.

Also check: **CrowdStrike Falcon Firewall Management**. If it's enabled for the host group,
its policy overrides Windows Firewall and GPO rules. Allow TCP 5985 from the jump server
in the Falcon firewall policy too.

## Step 1 — find out which piece is missing (on one affected endpoint)

Copy `DCAnomalyAgent\Install\Test-WinRMReadiness.ps1` to the endpoint, then run it in an
elevated prompt:

```powershell
.\Test-WinRMReadiness.ps1 -GpoName '<your WinRM GPO name>'
```

It prints PASS/FAIL for each piece above, plus the fix. It's read-only.

## Step 2 — fix it with a correct GPO

On an admin box with RSAT Group Policy:

```powershell
cd DCAnomalyAgent\Install
.\New-WinRMGPO.ps1 -TargetOU 'OU=Laptops,OU=Devices,DC=example,DC=local' `
    -AllowedRemoteAddress <jump-server-IP>,<your-admin-laptop-IP> -WhatIf   # drop -WhatIf to apply
```

This sets all of points 1–3 in one GPO (`AD-Agent-WinRM`) and links it. Unlink any older
hand-made WinRM GPO on the same OU so the two don't conflict. Reboot one test endpoint,
re-run `Test-WinRMReadiness.ps1` on it, then from the jump server:

```powershell
Test-NetConnection <endpoint> -Port 5985
Test-WSMan <endpoint>
```

## Step 3 (optional) — push it from your admin laptop to hosts that are reachable

You're local admin on the endpoints, so you can bootstrap the ones whose firewall still
lets 5985 or 135 through. On your laptop, from a full copy of the repo:

```powershell
cd DCAnomalyAgent\Install
.\Invoke-RemoteEndpointSetup.ps1 -ComputerName AHD00997-LTP `
    -EnableWinRM -AllowedRemoteAddress <jump-server-IP>,<your-laptop-IP> `
    -InstallCollector -ServerUrl 'http://<jump>:5000' -Token '<COLLECTOR_TOKEN>' -WhatIf
```

Drop `-WhatIf` to run it. Use `-InputFile hosts.txt` or `-SearchBase 'OU=...'` for many
hosts. For each host it:

- uses WinRM if 5985 is open;
- otherwise, if 135 is open, turns WinRM on over WMI (`Enable-EndpointWinRM.ps1`), then
  uses it;
- otherwise marks the host **Blocked**.

With `-InstallCollector` it then creates the two check-in tasks using the normal installer.
Results go to a CSV.

- Include **your laptop's IP** in `-AllowedRemoteAddress`, or the script can't use the
  WinRM it just turned on.
- **Account:** a domain account in the endpoints' local Administrators group works as-is.
  A *local* account (`.\Administrator`, LAPS) is blocked over the network by remote UAC
  unless it's the built-in RID-500 Administrator or `LocalAccountTokenFilterPolicy=1` is
  set. It also needs the targets in `TrustedHosts` for WinRM. The report says when this
  is the cause.

On a single endpoint you can also run the pieces by hand (elevated, on the endpoint):

```powershell
.\Enable-EndpointWinRM.ps1 -AllowedRemoteAddress <jump-server-IP>
.\Install-PushCollector.ps1 -ServerUrl 'http://<jump>:5000' -Token '<COLLECTOR_TOKEN>'
```

## Intune

If the devices are enrolled in Intune, it's the most reliable option for laptops — see
[`DCAnomalyAgent/Intune/README.md`](../DCAnomalyAgent/Intune/README.md).

## Do laptops need WinRM at all?

For inventory, no: the push collector sends presence, OS, device category and installed
software outbound, with no inbound access. WinRM is only needed for the checks that run
*from* the jump server (certificate scan, pentest/compliance checks). For roaming laptops,
the collector is usually enough. Keep WinRM for desktops and servers that stay on the
network.

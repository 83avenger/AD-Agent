# Endpoint rollout — step by step (GPO, Intune, or from your laptop)

This guide covers getting laptops and desktops **discovered** by AD-Agent. Each endpoint gets
the push-collector **check-in tasks**, and **WinRM** too if you want the jump server to scan it.
There are three ways to deliver this; pick one in Part 0.

Every step tells you:

- **Run on:** which machine. Most mistakes come from running a step on the wrong one.
- **Elevated:** whether PowerShell must be "Run as administrator".
- The command. **Run each code block on its own**, and don't join two commands on one line.
- What you should see, and what to do if you don't.

Placeholders you'll replace throughout:

| Placeholder | What to put |
|---|---|
| `<jump FQDN>` | The jump server's full name **exactly as it appears on its HTTPS certificate** (see 1.5). Not the IP: certificates don't list IPs, so an IP URL fails every check-in. |
| `<jump>` | Jump server name (for `Test-NetConnection` etc.) |
| `<jump-IP>` | Jump server IP address |
| `<your-laptop-IP>` | Your admin laptop's IP (only for the laptop route / WinRM) |
| `<COLLECTOR_TOKEN>` | The token printed in step 1.2 |
| `<Laptops OU DN>` | e.g. `OU=Laptops,OU=Devices,DC=example,DC=local` |

---

## Part 0 — Choose a route

| | **A. GPO** | **B. Intune** | **C. From your laptop** |
|---|---|---|---|
| Reaches endpoints whose firewall blocks all inbound? | Yes, because the endpoint pulls the GPO from the DC | Yes, because the endpoint pulls from the cloud | **No**: needs TCP 5985 or 135 already open on the endpoint |
| Reaches laptops at home / off-network? | Only once they're back on the LAN/VPN | **Yes** | No |
| Needs | RSAT Group Policy; a reboot per endpoint | Devices enrolled in Intune | Local admin on the endpoints |
| Speed | At next reboot | Next Intune sync (minutes to ~1 h) | Immediate |

**Recommendation:**
- **Intune** if the laptops are enrolled. It's the most reliable.
- **GPO** otherwise.
- **Your laptop** for an immediate push to hosts that are reachable right now. It reports
  the rest as *Blocked*, so you can cover those with A or B.

Laptops don't need WinRM just to be discovered. The check-in tasks send presence, OS, device
category and installed software outbound. Add WinRM only if you want the jump server's own
scans (Software / Pentest / certificates) to reach those hosts.

Whichever route you pick, do **Part 1** and **Part 2** first.

---

## Part 1 — Prerequisites (once)

### 1.1 Update the jump server to the latest code

**Run on:** Jump server · **Elevated:** yes

The new scripts (`Enable-EndpointWinRM.ps1`, `New-WinRMGPO.ps1`, `Invoke-RemoteEndpointSetup.ps1`,
`Test-WinRMReadiness.ps1`, `Intune\Build-IntunePackage.ps1`) must exist on the machines you'll
run them from.

```powershell
cd C:\AD-Agent
```
```powershell
git pull origin claude/optimistic-bohr-tnmeli
```
```powershell
.\DCAnomalyAgent\Install\Update-Deployment.ps1 -SourcePath C:\AD-Agent -TargetPath C:\Apps\AD-Agent
```

Replace `C:\AD-Agent` (your git clone) and `C:\Apps\AD-Agent` (the running deployment) if
yours differ. Add `-WhatIf` first to preview. If the server has no git, copy the repo folder
over instead of `git pull`.

**Check:** these must all print `True`:
```powershell
Test-Path C:\AD-Agent\DCAnomalyAgent\Collector\Install-PushCollector.ps1
```
```powershell
Test-Path C:\AD-Agent\DCAnomalyAgent\Collector\Enable-EndpointWinRM.ps1
```
```powershell
Test-Path C:\AD-Agent\DCAnomalyAgent\Install\Invoke-RemoteEndpointSetup.ps1
```
```powershell
Test-Path C:\AD-Agent\DCAnomalyAgent\Intune\Build-IntunePackage.ps1
```

### 1.2 Set the collector token

**Run on:** Jump server · **Elevated:** yes

```powershell
cd C:\AD-Agent\DCAnomalyAgent\Install
```
```powershell
.\Set-CollectorToken.ps1 -RestartWebUI
```

**You should see:** a long hex token printed. **Copy it.** This is `<COLLECTOR_TOKEN>`
everywhere below.

Don't set it with `[Environment]::SetEnvironmentVariable` by hand. Putting the token in the
*name* slot gives "name cannot contain equal character"; the script avoids that.

### 1.3 Check the check-in endpoint is live

**Run on:** Jump server · **Elevated:** no

```powershell
Invoke-WebRequest -Uri 'http://localhost:5000/api/collector/checkin' -Method POST -Body '{}' -ContentType 'application/json' -Headers @{ 'X-Collector-Token' = 'deliberately-wrong' } -UseBasicParsing
```

| Result | Meaning |
|---|---|
| **401 Unauthorized** | ✅ Correct. The endpoint is up and rejecting a wrong token. |
| 503 `collector endpoint disabled` | The token isn't set. Redo 1.2 (make sure `-RestartWebUI` ran). |
| Connection refused / timeout | The web UI isn't running. `Start-ScheduledTask -TaskName 'AD-Agent-WebUI'` |

### 1.4 Note the IP addresses

**Run on:** Jump server, then your admin laptop · **Elevated:** no

```powershell
ipconfig | Select-String 'IPv4'
```

Write down `<jump-IP>`, and `<your-laptop-IP>` if you'll use Route C or WinRM.

### 1.5 HTTPS on 443 and the network firewall

Endpoints check in over **HTTPS on TCP 443**, through the TLS proxy on the jump server. The
app's own port 5000 doesn't need to be open from endpoints.

1. **The TLS proxy must be running with the full certificate chain.** Follow
   [`TLS-SETUP.md`](TLS-SETUP.md) Option A (A0–A5). The chain matters: laptops reject a
   certificate when the server sends only its own certificate and not the issuing CA.
2. **Find `<jump FQDN>`.** Run on the jump server:
   ```powershell
   & 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe' x509 -noout -subject -ext subjectAltName -in C:\Apps\AD-Agent\cert.pem
   ```
   Use one of the `DNS:` names it lists.
3. **Firewall:** you need **endpoint VLANs → jump server TCP 443**. If you'll enable WinRM,
   also **`<jump-IP>` (and `<your-laptop-IP>`) → endpoint VLANs TCP 5985**.
4. **Test from one laptop** (as admin, Windows PowerShell). It must return JSON with no
   error:
   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
   ```
   ```powershell
   Invoke-RestMethod https://<jump FQDN>/healthz
   ```
   If this fails with a trust error, fix the certificate before rolling out (Part 7). Every
   check-in would fail the same way.

---

## Part 2 — Test on ONE endpoint first (by hand)

This proves the token, URL and firewall path work before you touch GPO or Intune. Do it on
one laptop, e.g. the one that showed 5985 CLOSED.

### 2.1 Copy two files onto the endpoint

**Run on:** the endpoint · **Elevated:** no

Copy these **two files into the same folder** on the endpoint (e.g. `C:\Temp\ADAgent`).
The installer looks for the collector right next to itself.

- `DCAnomalyAgent\Collector\Install-PushCollector.ps1`
- `DCAnomalyAgent\Collector\Send-InventoryCheckin.ps1`

### 2.2 Run the installer

**Run on:** the endpoint (**not** the jump server) · **Elevated:** yes

```powershell
cd C:\Temp\ADAgent
```
```powershell
.\Install-PushCollector.ps1 -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>'
```

Both `-ServerUrl` and `-Token` are required. Without them you get "-ServerUrl is required".

**You should see:**
- `Registered scheduled task 'AD-Agent Check-in'.`
- `Registered scheduled task 'AD-Agent Full Inventory'.`
- `SUCCESS - this host is now reporting to https://<jump FQDN>.`

If execution policy blocks the script, run it with
`powershell -ExecutionPolicy Bypass -File .\Install-PushCollector.ps1 -ServerUrl ... -Token ...`

### 2.3 Check on the jump server

**Run on:** your browser

Open `https://<jump FQDN>/endpoints`. The laptop is listed with a recent check-in. On the
**Assets** page its row is updated, with the device type in the **Category** column.

### 2.4 (Optional) Turn on WinRM on this endpoint

**Run on:** the endpoint · **Elevated:** yes

Copy `DCAnomalyAgent\Collector\Enable-EndpointWinRM.ps1` to the same folder, then:

```powershell
.\Enable-EndpointWinRM.ps1 -AllowedRemoteAddress <jump-IP>
```

This opens TCP 5985 **only** to the addresses you list, on all network profiles. To list
more addresses, separate them with commas: `-AllowedRemoteAddress <jump-IP>,<your-laptop-IP>`.

**Check from the jump server:**
```powershell
Test-NetConnection <endpoint-name> -Port 5985
```
```powershell
Test-WSMan <endpoint-name>
```

### 2.5 Undo (if needed)

**Run on:** the endpoint · **Elevated:** yes

```powershell
.\Install-PushCollector.ps1 -Uninstall
```

This removes both tasks. The log is kept, and so is the device's record on the jump server.

✅ When 2.2 shows SUCCESS and 2.3 shows the device, continue with your route.

---

## Part 3 — Route A: GPO

**Run on:** a domain-joined **admin box with RSAT Group Policy** (can be the jump server if
RSAT is installed) · **Elevated:** yes

If RSAT is missing:
```powershell
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

### 3.1 Create the push-collector GPO

```powershell
cd C:\AD-Agent\DCAnomalyAgent\Install
```

Preview first:
```powershell
.\New-PushCollectorGPO.ps1 -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>' -TargetOU '<Laptops OU DN>' -TightenAcl -WhatIf
```

Then run it for real (same line without `-WhatIf`):
```powershell
.\New-PushCollectorGPO.ps1 -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>' -TargetOU '<Laptops OU DN>' -TightenAcl
```

**You should see:** "Staged collector scripts to \\…\SYSVOL\…", "Created GPO
'AD-Agent-PushCollector'", "Linked … to <OU>". It refuses the Domain Controllers OU on purpose.

Start with a **small test OU** containing one or two machines, then widen it in 3.5.

### 3.2 (Optional) Create the WinRM GPO

Only if you want the jump server to scan these endpoints over WinRM.

```powershell
.\New-WinRMGPO.ps1 -TargetOU '<Laptops OU DN>' -AllowedRemoteAddress <jump-IP>,<your-laptop-IP> -WhatIf
```
```powershell
.\New-WinRMGPO.ps1 -TargetOU '<Laptops OU DN>' -AllowedRemoteAddress <jump-IP>,<your-laptop-IP>
```

This creates `AD-Agent-WinRM` with all three pieces WinRM needs:
- the service set to Automatic;
- the listener with IPv4/IPv6 filter `*`;
- an inbound 5985 rule on all profiles, limited to the addresses you gave.

**If you made a WinRM GPO by hand earlier, unlink it from this OU** (GPMC → the OU → right-click
the old GPO link → uncheck *Link Enabled*). Otherwise the two can conflict.

### 3.3 Apply on a test endpoint

**Run on:** the test endpoint · **Elevated:** yes

```powershell
gpupdate /force
```
```powershell
Restart-Computer
```

The reboot is required. The collector is installed by a *startup* script, and the WinRM
service only *starts* at boot.

**Don't use GPMC → right-click OU → "Group Policy Update…" to check this.** That button needs
inbound RPC to every endpoint. Laptops block it, which gives `0x800706ba` / `0x8007071a`.
Those errors don't mean the GPO is broken.

### 3.4 Verify

**Run on:** the test endpoint (after reboot) · **Elevated:** yes

```powershell
gpresult /scope computer /r
```
Expect **AD-Agent-PushCollector** (and **AD-Agent-WinRM** if you did 3.2) under *Applied
Group Policy Objects*.

```powershell
Get-ScheduledTask -TaskName 'AD-Agent*'
```
Expect two tasks.

```powershell
Get-Content "$env:ProgramData\AD-Agent\collector.log" -Tail 10
```
Expect `Check-in accepted`.

If you did 3.2, copy `DCAnomalyAgent\Install\Test-WinRMReadiness.ps1` to the endpoint and run:
```powershell
.\Test-WinRMReadiness.ps1
```
Expect all PASS. Any FAIL line prints its fix.

**Run on:** Jump server
```powershell
Test-NetConnection <endpoint-name> -Port 5985
```
```powershell
Test-WSMan <endpoint-name>
```
And the device appears on the **Endpoints** page.

### 3.5 Widen

Link the same GPO(s) to the full laptop/desktop OUs (re-run 3.1 / 3.2 with the bigger
`-TargetOU`, or link in GPMC). Endpoints pick it up at their next reboot.

---

## Part 4 — Route B: Intune

### 4.1 Confirm the devices are enrolled

**Run on:** one endpoint · **Elevated:** no

```powershell
dsregcmd /status
```
Look for `AzureAdJoined : YES` (hybrid-joined is fine). Also confirm the device is listed in
**Intune admin center → Devices → Windows**. If it isn't enrolled, use Route A.

### 4.2 Build the Intune scripts

**Run on:** jump server or your laptop (any machine with the repo) · **Elevated:** no

```powershell
cd C:\AD-Agent\DCAnomalyAgent\Intune
```

Collector only (recommended for laptops):
```powershell
.\Build-IntunePackage.ps1 -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>'
```

Collector + WinRM opened to the jump server only:
```powershell
.\Build-IntunePackage.ps1 -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>' -EnableWinRM -AllowedRemoteAddress <jump-IP>
```

**You should see:** two files written to `C:\AD-Agent\Build\out\intune\`:
- `Enable-ADAgentEndpoint.ps1` (~25–30 KB)
- `Detect-ADAgentEndpoint.ps1`

They contain the token, so don't email them around or commit them. `Build\out` is
git-ignored.

### 4.3 Create a test device group

**Run on:** Intune admin center (https://intune.microsoft.com)

1. **Groups → New group**
2. Group type: **Security**. Name: `AD-Agent Test Devices`. Membership type: **Assigned**.
3. **Members → Add members** → pick **one test device** (search by computer name; add the
   *device*, not the user).
4. **Create**.

### 4.4 Add the script. Choose ONE of these

#### Option 1 — Platform script (runs once per device)

1. **Devices → Scripts and remediations → Platform scripts → Add → Windows 10 and later**
2. **Basics:** Name `AD-Agent endpoint setup` → **Next**
3. **Script settings:**
   - Script location: upload `Enable-ADAgentEndpoint.ps1`
   - Run this script using the logged on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64 bit PowerShell Host: **Yes**
   → **Next**
4. **Assignments:** *Included groups* → **Add groups** → `AD-Agent Test Devices` → **Next**
5. **Review + add → Add**

#### Option 2 — Remediation (re-checks on a schedule and repairs; needs Windows Enterprise E3/E5 or equivalent)

1. **Devices → Scripts and remediations → Remediations → Create**
2. **Basics:** Name `AD-Agent endpoint setup` → **Next**
3. **Settings:**
   - Detection script file: upload `Detect-ADAgentEndpoint.ps1`
   - Remediation script file: upload `Enable-ADAgentEndpoint.ps1`
   - Run this script using the logged-on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes**
   → **Next**
4. **Scope tags:** leave default → **Next**
5. **Assignments:** add `AD-Agent Test Devices`, schedule **Daily** → **Next**
6. **Review + create → Create**

### 4.5 Make the device pick it up

**Run on:** the test endpoint

- **Settings → Accounts → Access work or school →** your work account **→ Info → Sync**, or
- Company Portal → **Settings → Sync**.

Platform scripts can take up to about an hour. Restarting the
**Microsoft Intune Management Extension** service speeds it up:
```powershell
Restart-Service IntuneManagementExtension
```
(elevated)

### 4.6 Verify

**Run on:** the test endpoint · **Elevated:** yes

```powershell
Get-Content "$env:ProgramData\AD-Agent\endpoint-setup.log" -Tail 20
```
Expect it to end with `Done.`

```powershell
Get-ScheduledTask -TaskName 'AD-Agent*'
```
Expect two tasks.

```powershell
Get-Content "$env:ProgramData\AD-Agent\collector.log" -Tail 10
```
Expect `Check-in accepted`.

**Run on:** Intune admin center. Open the script/remediation → **Device status**. Expect
*Succeeded* (Remediation: *Without issues* / *Issue fixed*).

**Run on:** your browser. The device is on the **Endpoints** page.

### 4.7 Widen

Change the assignment from `AD-Agent Test Devices` to your laptop/desktop device group.

### 4.8 After rotating the token

Re-run 4.2 with the new token, then in Intune open the script → **Properties → Script
settings → Edit** → upload the new file. A changed platform script runs again on every device.

---

## Part 5 — Route C: from your admin laptop

This works **only for endpoints that still accept TCP 5985 or 135**. It tells you which ones
those are. Being on the same VLAN doesn't get you past an endpoint's own firewall.

### 5.1 Prepare your laptop

**Run on:** your admin laptop · **Elevated:** yes

1. Get a copy of the repo on your laptop (git clone/pull of `claude/optimistic-bohr-tnmeli`,
   or copy the `C:\AD-Agent` folder from the jump server). You need the whole
   `DCAnomalyAgent` folder: the script loads files from `DCAnomalyAgent\Collector\`.
2. **Account:** sign in to your laptop (or pass `-Credential`) as a **domain account that is
   in the endpoints' local Administrators group**.
   A local account (e.g. `.\Administrator` or a LAPS account) is stripped of admin rights
   over the network unless it's the built-in RID-500 Administrator or the endpoint has
   `LocalAccountTokenFilterPolicy=1`. WinRM with a local account also needs the endpoints in
   your laptop's TrustedHosts. Use a domain account if you can.
3. Only if you'll target a whole OU (`-SearchBase`), install RSAT AD:
   ```powershell
   Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
   ```

### 5.2 Dry run on one host

```powershell
cd C:\AD-Agent\DCAnomalyAgent\Install
```
```powershell
.\Invoke-RemoteEndpointSetup.ps1 -ComputerName <endpoint-name> -EnableWinRM -AllowedRemoteAddress <jump-IP>,<your-laptop-IP> -InstallCollector -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>' -WhatIf
```

- Use the endpoint's **name**, not its IP.
- **Include `<your-laptop-IP>`** in `-AllowedRemoteAddress`, or the script can't use the
  WinRM it just enabled.
- Leave out `-EnableWinRM -AllowedRemoteAddress …` if you only want the check-in tasks. That
  only works on hosts where 5985 is already open.

**You should see:** one line per host showing which ports are open and what it *would* do.

### 5.3 Real run

The same command without `-WhatIf`:
```powershell
.\Invoke-RemoteEndpointSetup.ps1 -ComputerName <endpoint-name> -EnableWinRM -AllowedRemoteAddress <jump-IP>,<your-laptop-IP> -InstallCollector -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>'
```

For many hosts, use a text file with one name per line:
```powershell
.\Invoke-RemoteEndpointSetup.ps1 -InputFile C:\Temp\hosts.txt -EnableWinRM -AllowedRemoteAddress <jump-IP>,<your-laptop-IP> -InstallCollector -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>'
```

Or a whole OU:
```powershell
.\Invoke-RemoteEndpointSetup.ps1 -SearchBase '<Laptops OU DN>' -EnableWinRM -AllowedRemoteAddress <jump-IP>,<your-laptop-IP> -InstallCollector -ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>'
```

### 5.4 Read the report

A CSV named `endpoint-setup-<date>.csv` is written to the current folder.

| Column / value | Meaning | Next step |
|---|---|---|
| Method = `WinRM` | 5985 was already open | — |
| Method = `WMI/DCOM -> WinRM`, WinRM = `Enabled` | WinRM was off. The script turned it on over port 135. | — |
| WinRM = `Started but 5985 not open…` | The WMI step ran but the port didn't open | On the endpoint, read `C:\ProgramData\AD-Agent\endpoint-setup.log` |
| Method = `Blocked` | 5985 **and** 135 are closed (host firewall, or the host is off) | Use **Route A or B** for these hosts |
| Collector = `Installed, check-in accepted` | ✅ Done | — |
| Collector = `Installed, check-in NOT confirmed` | The tasks exist but the first check-in failed | See Part 7, "Tasks exist but no check-in" |
| Error contains `Access denied` | The account isn't admin on the endpoint over the network | See 5.1 step 2 |
| Error mentions `TrustedHosts` / `Kerberos` | Wrong name/IP or a local account | Use the host **name** and a domain account |

### 5.5 Verify

Same as 3.4: check the **Endpoints** page, and run `Test-WSMan <endpoint-name>` from the jump
server for hosts where WinRM was enabled.

---

## Part 6 — Confirm discovery worked (all routes)

**Run on:** your browser, at `https://<jump FQDN>`

1. **Endpoints** page: each rolled-out device shows a recent check-in. The presence task runs
   every 30 min and at startup; the full software inventory runs daily at 13:00.
2. **Assets** page: the device's row is updated (not duplicated), with **Category**
   (Laptop / Desktop / …) filled in.
3. If you set `CORPORATE_NETWORKS` on the jump server, check-ins are split into Office vs
   Remote.
4. For hosts where you enabled WinRM: run a **New Scan → Software Inventory** against one of
   them. It should now return data instead of "Port 5985/5986 not reachable".

---

## Part 7 — Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `-ServerUrl is required (e.g. …)` | The installer was run with no parameters | Add `-ServerUrl 'https://<jump FQDN>' -Token '<COLLECTOR_TOKEN>'` (2.2) |
| "Tasks were not created", but `collector.log` has a line every 30 minutes | The tasks **are** there; those lines are the tasks running | `Get-ScheduledTask 'AD-Agent*'`. In Task Scheduler, they're in the root of the Library (press F5 to refresh). |
| `collector.log`: `Could not establish trust relationship for the SSL/TLS secure channel` | The laptop rejects the jump server's HTTPS certificate | Read the **`TLS diagnosis:`** line logged just before it. It names one of three causes: (1) **URL host not on the certificate**: rebuild/redeploy with `https://<jump FQDN>` using a name on the cert (1.5 step 2), not the IP. (2) **Chain stops at the server certificate**: rebuild `cert.pem` with the chain ([TLS-SETUP](TLS-SETUP.md) A2) and restart `AD-Agent-TlsProxy`. (3) **Device doesn't have the root CA**: deploy the root to Trusted Root Certification Authorities (GPO, or Intune → Devices → Configuration → *Trusted certificate* profile). Then retest with 1.5 step 4. |
| `collector.log`: `Could not create SSL/TLS secure channel` | Old TLS settings on the device | The updated collector forces TLS 1.2. Rebuild and redeploy (Intune 4.2 + 4.8). |
| `Collector script not found at …` | `Send-InventoryCheckin.ps1` isn't in the same folder as the installer | Copy both files together (2.1), or add `-SourcePath <path>\Send-InventoryCheckin.ps1` |
| The jump server itself shows up as a new endpoint | The installer was run on the jump server | Run `.\Install-PushCollector.ps1 -Uninstall` on the jump server; run the installer **on the endpoint** |
| Check-in returns `503 collector endpoint disabled` | The token isn't set on the jump server | 1.2 with `-RestartWebUI` |
| Check-in returns `401` | The token on the endpoint doesn't match the jump server's | Use the exact token from 1.2. For GPO, re-run 3.1. For Intune, rebuild (4.8). |
| Scan shows `TCP 5985 / 5986 CLOSED`, WSMan FAIL | WinRM isn't on, or is blocked, on that endpoint | Run `Test-WinRMReadiness.ps1` on it. Usual causes: blank IPv4 filter in a hand-made GPO; service Automatic but no reboot yet; firewall rule only for the Domain profile while the laptop is on Wi-Fi/VPN; CrowdStrike Falcon firewall policy overriding Windows Firewall (allow TCP 5985 from `<jump-IP>` there). Fix with 3.2 + reboot. |
| GPMC "Group Policy Update…": `800706ba` RPC server is unavailable / `8007071a` RPC call cancelled | That button needs inbound RPC to each endpoint; laptops block it or are offline | Ignore it. Verify on the endpoint itself (3.3–3.4). The GPO still applies at the next refresh/reboot. |
| Intune script never runs | Not enrolled, assigned to a *user* group instead of a device group, or not synced yet | Check 4.1. Assign to a **device** group. Sync (4.5). Read `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log`. |
| `endpoint-setup.log` shows `Failed: …` | The script hit an error on the device | The message says what failed. Fix and re-sync; a Remediation retries automatically. |
| Route C: `Blocked` | The endpoint drops 5985 and 135 | Expected for many laptops. Use Route A or B. |
| Route C: `Access denied` | A local account filtered by remote UAC, or an account that isn't admin | Use a domain account in local Administrators (5.1) |
| Tasks exist but no `Check-in accepted` | The endpoint can't reach `https://<jump FQDN>`, or the token is wrong | On the endpoint, run `Test-NetConnection <jump FQDN> -Port 443`. False means a network firewall rule is missing, or the TLS proxy isn't running (1.5). Read `collector.log` for the real error. `Get-ScheduledTaskInfo -TaskName 'AD-Agent Check-in'` shows LastRunTime/LastTaskResult. |
| `Test-WinRMReadiness` all PASS but the jump server still sees 5985 closed | The block is between the two machines | Network firewall, or the jump server's IP isn't inside the rule's allowed addresses. Re-run 3.2 / 2.4 with the right `<jump-IP>`. |

---

## Part 8 — Undo / rollback

| To remove | Run on | Do |
|---|---|---|
| Check-in tasks on one endpoint | the endpoint (elevated) | `.\Install-PushCollector.ps1 -Uninstall` |
| WinRM rule on one endpoint | the endpoint (elevated) | `Remove-NetFirewallRule -Name 'ADAgent-WinRM-In'` |
| GPO rollout | admin box (GPMC) | Unlink or delete `AD-Agent-PushCollector` / `AD-Agent-WinRM`. Existing tasks stay until uninstalled. |
| Intune rollout | Intune admin center | Remove the assignment, or delete the script/remediation |
| Stop all check-ins at once | jump server (elevated) | `.\Set-CollectorToken.ps1 -Clear` (check-ins then get 503) |

---

Reference docs (background and detail): [`WINRM-ENDPOINTS.md`](WINRM-ENDPOINTS.md),
[`../DCAnomalyAgent/Intune/README.md`](../DCAnomalyAgent/Intune/README.md),
[`../DCAnomalyAgent/Install/Deploy-PushCollector-GPO.md`](../DCAnomalyAgent/Install/Deploy-PushCollector-GPO.md).

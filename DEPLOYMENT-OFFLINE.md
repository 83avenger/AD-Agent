# Offline Deployment Guide — Air-Gapped Windows Jump Server

## Overview

This guide covers three things:
1. **Offline installs** — every download URL and how to transfer files with no internet on the jump server
2. **Least-privilege service account** — exactly which rights the gMSA needs on each DC and how to grant them via GPO (no local admin required)
3. **Network ports & cross-team prerequisites** — the exact port list to hand to the Network team, and what to request from AD, PKI, Messaging, and other teams (Part 3)

---

## Part 1 — Downloads (on an internet-connected machine)

Do all downloads on a separate internet-connected machine, then copy to the jump server via USB, file share, or your internal software distribution tool.

---

### 1.1 Python 3.12 (Windows 64-bit installer)

Download page: `https://www.python.org/downloads/windows/`

Direct installer:
```
https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe
```

> Check `https://www.python.org/ftp/python/` for the latest 3.12.x release if a newer patch exists.

---

### 1.2 NSSM (Windows service wrapper)

Download page: `https://nssm.cc/download`

Direct zip:
```
https://nssm.cc/release/nssm-2.24.zip
```

Extract `nssm.exe` from `nssm-2.24\win64\nssm.exe` — that is the only file needed.

---

### 1.3 Git for Windows (needed only if cloning the repo — otherwise just copy the folder)

Download page: `https://git-scm.com/download/win`

Direct installer:
```
https://github.com/git-for-windows/git/releases/download/v2.49.0.windows.1/Git-2.49.0-64-bit.exe
```

> Check `https://github.com/git-for-windows/git/releases/latest` for the current version.

Skip Git entirely if you zip and copy the `AD-Agent` folder directly.

---

### 1.4 Python packages (offline wheel bundle)

On the internet-connected machine, run the following to download all wheels
including transitive dependencies as `.whl` files:

```powershell
# On internet-connected machine — run this once
mkdir C:\AD-Agent-Wheels
cd C:\AD-Agent-Wheels

pip download flask==3.1.0 reportlab==4.2.5 Werkzeug==3.1.3 waitress `
    --dest . `
    --platform win_amd64 `
    --python-version 312 `
    --only-binary=:all:
```

This produces a folder of `.whl` files you can copy to the jump server.

> If `pip download` complains about `--platform` needing binary-only, add `--only-binary=:all:`.
> If reportlab 4.x is unavailable as a wheel, grab 4.2.5 directly from PyPI:
> `https://pypi.org/project/reportlab/#files` — download `reportlab-4.2.5-cp312-cp312-win_amd64.whl`

**Complete list of packages you need (including dependencies):**
```
flask
Werkzeug
click
itsdangerous
Jinja2
MarkupSafe
reportlab
pillow          # reportlab image support
waitress
```

On the **jump server** (no internet), install from the wheel folder:

```powershell
cd C:\Apps\AD-Agent\WebApp

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install `
    --no-index `
    --find-links C:\AD-Agent-Wheels `
    flask reportlab waitress
```

---

### 1.5 Summary — what to copy to the jump server

```
C:\Transfer\
  python-3.12.10-amd64.exe
  nssm-2.24\
    win64\
      nssm.exe
  Git-2.49.0-64-bit.exe     (optional)
  AD-Agent-Wheels\
    *.whl                    (all downloaded wheels)
  AD-Agent\                  (the entire repo folder, zipped from your dev machine)
```

---

## Part 2 — Least-Privilege Service Account Configuration

The gMSA needs **five specific rights** on each DC. None of them require local admin.
All are granted via a single GPO scoped to the Domain Controllers OU.

---

### 2.1 Rights required and why

| Right | What it enables | How granted |
|---|---|---|
| Member of **Remote Management Users** | `Invoke-Command` / WinRM remoting | Restricted Groups GPO |
| Member of **Event Log Readers** | `Get-WinEvent` on the Security log (event IDs 4624/4625/4728/5136 etc.) | Restricted Groups GPO |
| **Manage auditing and security log** (`SeSecurityPrivilege`) | `auditpol /get` to read current audit policy settings | User Rights Assignment GPO |
| **Remote Registry** service reachable + read ACL on HKLM keys | Compliance checks that read registry values (SMB signing, LDAP signing, NTLMv1, WinRM listener) | Services GPO + Registry ACL GPO |
| Default **Authenticated Users** AD read | All `Get-AD*` cmdlets, `Get-GPO` | No action needed — domain accounts have this by default |

No local admin. No Domain Admin. No elevated AD permissions.

---

### 2.2 Create and install the gMSA

Run as **Domain Admin** on a DC:

```powershell
# Create the gMSA, restricting password retrieval to only the jump server
New-ADServiceAccount `
    -Name            'svc-dcAnomalyAgent' `
    -DNSHostName     'svc-dcAnomalyAgent.contoso.com' `
    -PrincipalsAllowedToRetrieveManagedPassword 'JUMPSERVER$'

# Verify it was created
Get-ADServiceAccount -Identity 'svc-dcAnomalyAgent'
```

On the **jump server** (elevated):

```powershell
Install-ADServiceAccount -Identity 'svc-dcAnomalyAgent'

# Must return True — if False, recheck PrincipalsAllowedToRetrieveManagedPassword
Test-ADServiceAccount -Identity 'svc-dcAnomalyAgent'
```

---

### 2.3 Grant all rights via GPO (one GPO, scoped to Domain Controllers OU)

Open **Group Policy Management Console (GPMC)** on a DC or admin workstation.

Create a new GPO: `DC-AnomalyAgent-ServiceAccount-Rights`
Link it to: `OU=Domain Controllers,DC=contoso,DC=com`

#### A — Add gMSA to Remote Management Users and Event Log Readers

**(Preferred: GPO Preferences — Local Users and Groups)**
`Computer Configuration > Preferences > Control Panel Settings > Local Users and Groups`

- Action: **Update**
- Group Name: **Remote Management Users (built-in)**
- Members: Add `CONTOSO\svc-dcAnomalyAgent$`
- Tick "Do not remove users from the group"

Repeat for **Event Log Readers (built-in)**.

**(Alternative: Restricted Groups — replaces membership)**
`Computer Configuration > Policies > Windows Settings > Security Settings > Restricted Groups`
Add group `Remote Management Users`, add `CONTOSO\svc-dcAnomalyAgent$` as a member.
Repeat for `Event Log Readers`.

> Preferences is safer as it doesn't remove other members.

---

#### B — Grant "Manage auditing and security log"

`Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment`

Policy: **Manage auditing and security log**
Add: `CONTOSO\svc-dcAnomalyAgent$`

> This is the `SeSecurityPrivilege` right — needed so `auditpol /get` works
> in the remote WinRM session without local admin.

---

#### C — Ensure Remote Registry service is running on DCs

`Computer Configuration > Policies > Windows Settings > Security Settings > System Services`

Service: **Remote Registry**
Startup: **Automatic**

The gMSA needs read access to the following registry keys for compliance checks:

| Registry Path | Check |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters` | SMB signing (NT-001) |
| `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` | LDAP signing (NT-002) |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | NTLMv1 level (NT-003) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener` | WinRM listener (NT-004) |

Grant read-only access via GPO Registry preference:

`Computer Configuration > Preferences > Windows Settings > Registry`

For each key above:
- Action: **Update**
- Hive: `HKEY_LOCAL_MACHINE`
- Path: `SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters`
- Permissions: Add `svc-dcAnomalyAgent$` with **Read** access

Repeat for the other three paths.

---

### 2.4 Force GPO update on DCs

```powershell
# From an admin workstation — forces immediate policy refresh on all DCs
$dcs = (Get-ADDomainController -Filter *).Name
foreach ($dc in $dcs) {
    Invoke-Command -ComputerName $dc -ScriptBlock { gpupdate /force }
}

# Verify the rights applied correctly on one DC
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock {
    # Should show svc-dcAnomalyAgent in both groups
    net localgroup "Remote Management Users"
    net localgroup "Event Log Readers"
}
```

---

### 2.5 Verify each permission end-to-end

Run these **as the gMSA** (or as a domain admin impersonating it) from the jump server:

```powershell
# Test 1: WinRM remoting works
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock { hostname }

# Test 2: Security event log readable
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock {
    Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } `
        -MaxEvents 1 -ErrorAction Stop
}

# Test 3: auditpol readable
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock {
    auditpol /get /subcategory:"Credential Validation" /r
}

# Test 4: Registry readable
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock {
    Get-ItemProperty `
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters' `
        -Name RequireSecuritySignature
}

# Test 5: AD queries work
Invoke-Command -ComputerName dc01.contoso.com -ScriptBlock {
    Get-ADDefaultDomainPasswordPolicy
}

# Full scanner smoke test
cd C:\Apps\AD-Agent\DCAnomalyAgent
.\Run-AnomalyScan.ps1 -DryRun -ComplianceScan -DomainControllerOverride 'dc01.contoso.com'
```

All five should return data — no "Access Denied" errors.

---

### 2.6 What happens with multiple DCs

The **same GPO** applies to all DCs in the Domain Controllers OU simultaneously.
The gMSA uses the same Kerberos identity against every DC — you grant rights once
via GPO and all DCs inherit them on the next GPO refresh (typically every 5 minutes
for DCs, or forced with `gpupdate /force`).

When the scanner runs it loops over `DomainControllers` in `settings.psd1` and
authenticates to each one independently using Kerberos — no passwords, no per-server
credential configuration needed.

---

### 2.7 What the gMSA can NOT do (by design)

- Cannot log on interactively or via RDP to DCs
- Cannot write to Active Directory (read-only)
- Cannot modify GPOs, restart services, or change any DC configuration
- Cannot read LSASS memory or SAM database
- Cannot elevate privileges

If a scan check fails with Access Denied, it means that specific check requires
more than these rights — the result is recorded as an error in the scan log, not
a crash, and the other checks continue.

---

## Part 3 — Network Ports & Cross-Team Prerequisites

Share this section with the **Network**, **Identity/AD**, **Firewall**, and
**Messaging/Collab** teams ahead of deployment — every port and account below
is required by a specific piece of the tool, cited by module/function so it can
be independently verified against the source if needed.

### 3.1 Port list for the Network team

All connections are **outbound from the jump server** — nothing needs to be
opened *inbound* to the jump server except optionally the Web UI port (3.1.G).

#### A — Jump server -> Domain Controllers (required)

| Port | Protocol | Direction | Purpose | Source |
|---|---|---|---|---|
| 5985/TCP | WinRM (HTTP) | Jump -> DC | `Invoke-Command` remoting for all event-log/registry/auditpol checks | `DCAnomalyAgent.Collectors.psm1`, all compliance `Check` blocks |
| 5986/TCP | WinRM (HTTPS) | Jump -> DC | Same as above, if the DC's WinRM listener is HTTPS-only | same |
| 9389/TCP | ADWS (AD Web Services) | Jump -> DC | `Get-ADDomainController`, `Get-ADComputer`, `Get-ADGroupMember` (asset discovery, compliance target resolution, privileged-group checks) | `DCAnomalyAgent.Compliance.psm1`, `DCAnomalyAgent.Collectors.psm1`, `DCAnomalyAgent.Discovery.psm1` |
| 389/TCP | LDAP | Jump -> DC | Fallback if ADWS (9389) is unreachable; also used by the asset-discovery network sweep to help classify a host as a DC | `DCAnomalyAgent.Discovery.psm1` |
| 636/TCP | LDAPS | Jump -> DC | Certificate-expiry scan probes this port directly on every DC (`ProbeDcLdaps`) | `DCAnomalyAgent.Certificates.psm1` (`Get-EndpointCertificate`), `Run-AnomalyScan.ps1` |
| 88/TCP+UDP | Kerberos | Jump -> DC | Authentication for the gMSA on every WinRM/ADWS/LDAP call above (implicit, not a scan target) | Windows Kerberos (SSO), also probed by asset discovery |
| 445/TCP | SMB | Jump -> DC/servers | Remote Registry reads (SMB signing, LDAP signing, NTLMv1, WinRM listener config); also probed by asset discovery | `DCAnomalyAgent.Certificates.psm1` machine-store checks, `DCAnomalyAgent.Discovery.psm1` |

#### B — Jump server -> Member servers & workstations (if scanning them)

| Port | Protocol | Purpose | Source |
|---|---|---|---|
| 5985/TCP (or 5986) | WinRM | Same `Invoke-Command` checks as DCs — local admins, LAPS, RDP NLA, firewall, Defender, SMBv1, patch age, services, machine cert stores | `DCAnomalyAgent.Compliance.psm1`, `DCAnomalyAgent.Certificates.psm1` |
| 445/TCP | SMB | Remote Registry reads | same |

#### C — Jump server -> Linux/Unix hosts (if scanning them)

| Port | Protocol | Purpose | Source |
|---|---|---|---|
| 22/TCP (configurable) | SSH | All Linux compliance checks (`ssh.exe`, key-based, `BatchMode=yes`) | `Config/settings.psd1 -> Assets.Linux.Ssh`, `compliance-linux.psd1` |

#### D — Jump server -> Web applications / TLS endpoints (certificate & OWASP scans)

| Port | Protocol | Purpose | Source |
|---|---|---|---|
| 443/TCP | HTTPS | OWASP posture checks (headers/TLS/cookies) on every `Assets.WebApplication` host; certificate-expiry probe on the same hosts (`ProbeWebApps`) | `compliance-owasp.psd1`, `DCAnomalyAgent.Certificates.psm1` |
| Custom (443/587/3389/etc.) | TLS | Any extra endpoints listed in `Config/certificate-endpoints.psd1` — load balancers, mail gateways, VPN/RDP appliances | `DCAnomalyAgent.Certificates.psm1` (`Get-EndpointCertificate`) |

> These are **read-only TLS handshakes** — the probe reads the presented server
> certificate and does not send any authenticated request or validate the trust
> chain. Coordinate with the owning team before adding a production endpoint.

#### E — Jump server -> Enterprise CA (only if `Certificates.Adcs.Enabled = $true`)

| Port | Protocol | Purpose | Source |
|---|---|---|---|
| 135/TCP + dynamic RPC (or DCOM-configured static port) | RPC/DCOM | `certutil -view` against the Issuing CA to list certs nearing expiry | `DCAnomalyAgent.Certificates.psm1` (`Get-CaIssuedCertificate`) |

> Off by default. Only request this from the PKI/Network team if you intend to
> enable ADCS-based certificate scanning; the machine-store and TLS-endpoint
> sources (A/B/D above) already cover the vast majority of certificates.

#### F — Jump server -> Internet (outbound HTTPS only, unless fully offline)

| Destination | Port | Purpose | Can be disabled? |
|---|---|---|---|
| `www.cisa.gov` | 443/TCP | CISA Known Exploited Vulnerabilities (KEV) feed | Yes — set `ZeroDay.Offline = $true` and pre-load `State\kev-cache.json` |
| `services.nvd.nist.gov` | 443/TCP | NVD CVE API v2 (secondary zero-day source) | Yes — leave `NvdApiKey` blank and/or block; KEV alone still functions |
| `login.microsoftonline.com` | 443/TCP | Azure AD OAuth token for Graph (SharePoint reporting) | Yes — set `Reporting.SharePoint.Enabled = $false` |
| `graph.microsoft.com` | 443/TCP | Writing anomaly/compliance/certificate items to SharePoint lists | Yes — same as above |
| Your Teams webhook domain (`*.webhook.office.com`) | 443/TCP | Teams incoming webhook alerts | Yes — set `Reporting.Teams.Enabled = $false` |
| Your SMTP relay | 587/TCP (or your relay's port) | Email alerts | Yes — set `Reporting.Email.Enabled = $false` |

On a fully air-gapped jump server, disable every row in this table and rely on
Teams/Email/SharePoint being unreachable (each fails independently without
aborting a scan) plus the offline KEV cache workflow in Part 1.

#### G — Web UI / Dashboard (inbound, optional)

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 5000/TCP (configurable via `--port`) | HTTP | Analyst workstation -> Jump server | Flask web UI + `/dashboard` rotating display |

> The app has **no built-in authentication**. Bind to `127.0.0.1` (as shown in
> Part 4) and front it with an internal reverse proxy (IIS/ARR) that enforces
> Windows auth or IP allow-listing before exposing it beyond the jump server
> itself. Do not expose 5000 directly to the network without a proxy in front.

### 3.2 Prerequisites from other teams

| Team | What to request | Why |
|---|---|---|
| **Active Directory / Identity** | Create the gMSA (`New-ADServiceAccount`), add it to a group granted **Remote Management Users** + **Event Log Readers** on the target OUs, grant `SeSecurityPrivilege` (Manage auditing and security log) via GPO — see Part 2 | Credential-free WinRM auth; least-privilege event log/audit reads |
| **Active Directory / Identity** | Confirm a **KDS root key** exists in the forest (`Get-KdsRootKey`); create one 10+ hours before gMSA creation if not (`Add-KdsRootKey`) | Required before any gMSA can be created in the forest |
| **Network / Firewall** | Open the ports in 3.1.A-C from the jump server to DCs, member servers, workstations, and any Linux hosts in scope | Core WinRM/SSH/LDAP/SMB scanning |
| **Network / Firewall** | Open 3.1.D to any TLS endpoints added to `certificate-endpoints.psd1` or `Assets.WebApplication` | Certificate expiry + OWASP posture checks |
| **Network / Firewall** | Open 3.1.F outbound HTTPS destinations, *or* confirm they should stay blocked (air-gapped mode) | Zero-day feeds, Teams, Graph/SharePoint, SMTP |
| **PKI / Certificate Services team** | Only if enabling ADCS scanning: grant the gMSA (or a delegated account) read access to run `certutil -view` against the Issuing CA, and open 3.1.E | Enterprise CA certificate inventory |
| **Messaging / Collaboration (Teams)** | Provide an Incoming Webhook URL for the target channel | `Reporting.Teams.WebhookUrl` |
| **Messaging / Collaboration (Exchange/SMTP)** | Provide an SMTP relay endpoint (host/port), and confirm whether the jump server's IP/hostname needs to be allow-listed for anonymous relay, or provide a mailbox + credential if auth is required | `Reporting.Email` |
| **M365 / SharePoint & Azure AD admin** | Register an Azure AD app (client credentials flow), grant it **Sites.ReadWrite.All** (application, admin-consented), issue a certificate for auth, and create/share the target SharePoint lists (Anomalies, Compliance, Certificates) with their List IDs | `Reporting.SharePoint` — see Part 2 equivalent app-registration steps in `DEPLOYMENT.md` |
| **Server/Endpoint team** | Ensure WinRM is enabled and listening (5985/5986) on all member servers/workstations in scope; confirm Remote Registry service is set to at least Manual/Trigger-start | Compliance + certificate machine-store scans on non-DC assets |
| **Linux/Unix team** | Create an unprivileged SSH scan account on each in-scope Linux host and install the jump server's public key in `~/.ssh/authorized_keys`; confirm `sshd` policy allows key-based, non-interactive login for that account | Linux compliance checks (`compliance-linux.psd1`) |
| **Security/GRC** | Confirm which frameworks apply (CIS/NIST/ISO/HIPAA/OWASP) and the desired `Certificates.ThresholdDays` / severity thresholds | Scopes `FrameworkFilter`/`SeverityFilter` and alerting noise |
| **Change Management** | Approve the network-discovery sweep window if `Run-Discovery.ps1 -Cidr` will be used — it is an **active TCP port probe** across the given ranges | `DCAnomalyAgent.Discovery.psm1` |

### 3.3 Firewall change request form

Fill in the `<...>` placeholders (jump server IP, actual DC/host IPs or subnets)
and hand this table to the Network team as-is. Rows marked *(optional)* only
apply if that feature is enabled in `settings.psd1` — see the Remarks column.

> A ready-to-import copy of this same table is at
> [`firewall-request-ports.csv`](firewall-request-ports.csv) in the repo root —
> open it directly in Excel/Google Sheets or attach it to the change ticket.

| S.No | Source IP | Source Description | Destination IP | Destination Description | Service (TCP/UDP) | Remarks/Reason |
|---|---|---|---|---|---|---|
| 1 | `<Jump Server IP>` | AD-Agent jump server | `<DC IPs/subnet>` | Domain Controllers | TCP/5985 | WinRM (HTTP) - Invoke-Command for event log, registry, auditpol checks |
| 2 | `<Jump Server IP>` | AD-Agent jump server | `<DC IPs/subnet>` | Domain Controllers | TCP/5986 | WinRM (HTTPS) - same as above if listener is HTTPS-only |
| 3 | `<Jump Server IP>` | AD-Agent jump server | `<DC IPs/subnet>` | Domain Controllers | TCP/9389 | ADWS - Get-ADDomainController / Get-ADComputer / Get-ADGroupMember |
| 4 | `<Jump Server IP>` | AD-Agent jump server | `<DC IPs/subnet>` | Domain Controllers | TCP/389 | LDAP - fallback if ADWS unreachable; asset discovery classification |
| 5 | `<Jump Server IP>` | AD-Agent jump server | `<DC IPs/subnet>` | Domain Controllers | TCP/636 | LDAPS - certificate-expiry probe on every DC (ProbeDcLdaps) |
| 6 | `<Jump Server IP>` | AD-Agent jump server | `<DC IPs/subnet>` | Domain Controllers | TCP+UDP/88 | Kerberos - gMSA authentication for all WinRM/ADWS/LDAP calls |
| 7 | `<Jump Server IP>` | AD-Agent jump server | `<DC IPs/subnet>` | Domain Controllers | TCP/445 | SMB - Remote Registry reads (SMB/LDAP signing, NTLMv1, WinRM config) |
| 8 | `<Jump Server IP>` | AD-Agent jump server | `<Member server/workstation IPs or subnet>` | Member servers & workstations | TCP/5985,5986 | WinRM - local admins, LAPS, RDP NLA, firewall, Defender, patch, cert store checks |
| 9 | `<Jump Server IP>` | AD-Agent jump server | `<Member server/workstation IPs or subnet>` | Member servers & workstations | TCP/445 | SMB - Remote Registry reads |
| 10 | `<Jump Server IP>` | AD-Agent jump server | `<Linux host IPs>` | Linux/Unix hosts *(optional)* | TCP/22 | SSH (key-based) - Linux compliance checks |
| 11 | `<Jump Server IP>` | AD-Agent jump server | `<Web app IPs/VIPs>` | Web applications / TLS endpoints *(optional)* | TCP/443 | HTTPS - OWASP posture checks + certificate-expiry probe |
| 12 | `<Jump Server IP>` | AD-Agent jump server | `<Custom endpoint IPs from certificate-endpoints.psd1>` | Load balancers, mail gateways, VPN/RDP appliances *(optional)* | TCP/custom (e.g. 443, 587, 3389) | Certificate-expiry probe only - read-only TLS handshake, no auth |
| 13 | `<Jump Server IP>` | AD-Agent jump server | `<Issuing CA IP>` | Enterprise CA *(optional - ADCS scanning)* | TCP/135 + dynamic RPC | certutil -view for CA-issued certificates nearing expiry |
| 14 | `<Jump Server IP>` | AD-Agent jump server | `www.cisa.gov` | CISA KEV feed *(optional)* | TCP/443 | Zero-day vulnerability feed; disable via ZeroDay.Offline = $true |
| 15 | `<Jump Server IP>` | AD-Agent jump server | `services.nvd.nist.gov` | NVD CVE API *(optional)* | TCP/443 | Secondary zero-day source; disable by leaving NvdApiKey blank/blocking |
| 16 | `<Jump Server IP>` | AD-Agent jump server | `login.microsoftonline.com` | Azure AD OAuth *(optional)* | TCP/443 | Token acquisition for Graph/SharePoint reporting |
| 17 | `<Jump Server IP>` | AD-Agent jump server | `graph.microsoft.com` | Microsoft Graph *(optional)* | TCP/443 | Writes anomaly/compliance/certificate items to SharePoint lists |
| 18 | `<Jump Server IP>` | AD-Agent jump server | `<tenant>.webhook.office.com` | Teams incoming webhook *(optional)* | TCP/443 | Teams alert delivery; disable via Reporting.Teams.Enabled = $false |
| 19 | `<Jump Server IP>` | AD-Agent jump server | `<SMTP relay IP/hostname>` | Email relay *(optional)* | TCP/587 (or relay's port) | Email alert delivery; disable via Reporting.Email.Enabled = $false |
| 20 | `<Analyst workstation IPs/subnet>` | Analysts viewing the dashboard *(optional, inbound)* | `<Jump Server IP>` | AD-Agent jump server | TCP/5000 | Web UI + rotating dashboard - front with a reverse proxy; no built-in auth |

> Rows 1-9 are the core requirement for any deployment. Rows 10-19 are
> outbound and only needed if that asset type/feature is in scope or enabled.
> Row 20 is the only inbound rule, and only if the Web UI is used from other
> workstations rather than accessed locally on the jump server.

---

## Part 4 — Complete offline installation sequence

Once all files are copied to `C:\Transfer\` on the jump server:

```powershell
# 1 — Python
C:\Transfer\python-3.12.10-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
# Open a new PowerShell window so PATH refreshes, then:
python --version

# 2 — Copy NSSM
Copy-Item C:\Transfer\nssm-2.24\win64\nssm.exe C:\Windows\System32\nssm.exe

# 3 — Unzip repo (if not using Git)
Expand-Archive C:\Transfer\AD-Agent.zip C:\Apps\AD-Agent

# 4 — Python venv + offline wheel install
cd C:\Apps\AD-Agent\WebApp
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --no-index --find-links C:\Transfer\AD-Agent-Wheels flask reportlab waitress

# 5 — Verify imports
python -c "import flask, reportlab, waitress; print('All packages OK')"

# 6 — Edit config
notepad C:\Apps\AD-Agent\DCAnomalyAgent\Config\settings.psd1

# 7 — Install the gMSA (Domain Admin already ran New-ADServiceAccount)
Install-ADServiceAccount -Identity 'svc-dcAnomalyAgent'
Test-ADServiceAccount   -Identity 'svc-dcAnomalyAgent'   # must return True

# 8 — Smoke test the scanner
cd C:\Apps\AD-Agent\DCAnomalyAgent
.\Run-AnomalyScan.ps1 -DryRun -DomainControllerOverride 'dc01.contoso.com'

# 9 — Interactive web UI test
cd C:\Apps\AD-Agent\WebApp
.\.venv\Scripts\Activate.ps1
python start.py --prod --host 127.0.0.1 --port 5000
# Browse http://127.0.0.1:5000 and verify scan + PDF/CSV download

# 10 — Install as Windows service under gMSA
nssm install DCAnomalyWebUI `
    "C:\Apps\AD-Agent\WebApp\.venv\Scripts\python.exe" `
    "C:\Apps\AD-Agent\WebApp\start.py --prod --host 127.0.0.1 --port 5000"
nssm set DCAnomalyWebUI AppDirectory "C:\Apps\AD-Agent\WebApp"
nssm set DCAnomalyWebUI ObjectName "CONTOSO\svc-dcAnomalyAgent$" ""
nssm start DCAnomalyWebUI

# 11 — Register scheduled scan tasks
cd C:\Apps\AD-Agent\DCAnomalyAgent\Install
.\Register-ScheduledTask.ps1
```

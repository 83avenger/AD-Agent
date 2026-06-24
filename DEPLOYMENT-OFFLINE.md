# Offline Deployment Guide — Air-Gapped Windows Jump Server

## Overview

This guide covers two things:
1. **Offline installs** — every download URL and how to transfer files with no internet on the jump server
2. **Least-privilege service account** — exactly which rights the gMSA needs on each DC and how to grant them via GPO (no local admin required)

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

## Part 3 — Complete offline installation sequence

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

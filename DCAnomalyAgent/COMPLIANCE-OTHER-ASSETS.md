# Compliance Checks on Other Assets (Member Servers & Workstations)

The compliance engine is asset-type aware. The same WinRM-based scanner that
checks Domain Controllers can check **member servers** and **workstations** —
it just runs a different set of controls per asset type.

## How it works

Each control declares which asset types it applies to via an `AppliesTo` array:

| Asset type | Transport | Controls run | File |
|---|---|---|---|
| `DomainController` | WinRM | Domain-wide + DC checks (password policy, DA membership, LDAP signing, AD Recycle Bin…) | `Config/compliance-frameworks.psd1` |
| `MemberServer` | WinRM | Host hardening (local admins, LAPS, RDP NLA, firewall, Defender, SMBv1, patching, services, log size) | `Config/compliance-endpoints.psd1` |
| `Workstation` | WinRM | Same host hardening **+ BitLocker** | `Config/compliance-endpoints.psd1` |
| `Linux` | **SSH** | SSH hardening, host firewall, auditd, SELinux/AppArmor, password aging, legacy services, patching | `Config/compliance-linux.psd1` |
| `WebApplication` | **HTTPS (agentless)** | OWASP Top 10 posture: TLS versions, security headers, cookie flags, banner disclosure | `Config/compliance-owasp.psd1` |

HIPAA Security Rule controls (`Config/compliance-hipaa.psd1`) span the Windows and
Linux asset types above — run them alone with `-FrameworkFilter HIPAA`.

Controls shared across all Windows hosts (firewall, SMBv1, RDP NLA, patch age,
log size) list multiple types in `AppliesTo`, so they run everywhere.

## What to run

### 1. Define your assets in `Config/settings.psd1`

```powershell
Assets = @{
    DomainController = @{ Hosts = @();                              DiscoverFromAD = $true  }
    MemberServer     = @{ Hosts = @('app01.contoso.com','sql01');   DiscoverFromAD = $false }
    Workstation      = @{ Hosts = @();                              DiscoverFromAD = $true  }
}
```

- `Hosts` — explicit list of hostnames
- `DiscoverFromAD = $true` — auto-enumerate from AD:
  - DomainController → `Get-ADDomainController -Filter *`
  - MemberServer → server-OS computers that aren't DCs
  - Workstation → client-OS Windows computers

### 2. Run the scan

```powershell
cd C:\Apps\AD-Agent\DCAnomalyAgent

# All asset types defined in config
.\Run-AnomalyScan.ps1 -ComplianceScan

# Only member servers
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType MemberServer

# Only workstations, Critical/High gaps
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType Workstation -SeverityFilter Critical,High

# Ad-hoc list of hosts (single asset type, no config edit)
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType MemberServer `
    -TargetHostsOverride 'web01.contoso.com,web02.contoso.com'

# Dry run (no Teams/SharePoint), see results in console
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType MemberServer -DryRun
```

Results, reports (PDF/CSV via the web UI), Teams and SharePoint output all work
the same as for DCs — each finding is tagged with its `AssetType`.

## Prerequisites on the target endpoints

The scanning service account (gMSA) needs the **same least-privilege rights** on
member servers and workstations that it has on DCs. Apply the GPO from
`DEPLOYMENT-OFFLINE.md` to the **Servers** and **Workstations** OUs as well:

- Member of **Remote Management Users** (WinRM)
- Member of **Event Log Readers** (event log checks)
- **Remote Registry** service running + read access to the checked keys
- WinRM enabled (TCP 5985/5986 reachable from the jump server)

> Workstations are often off, asleep, or on VPN. Expect some hosts to be
> unreachable; those controls record as errors (counted as gaps) rather than
> crashing the scan. Schedule workstation scans during business hours and treat
> coverage % as its own metric.

## Adding your own endpoint controls

Append to `Config/compliance-endpoints.psd1` — no code changes needed:

```powershell
@{
    Id          = 'EP-CUSTOM-001'
    Title       = 'Screen lock timeout <= 15 minutes'
    AppliesTo   = @('Workstation')
    Frameworks  = @{ CIS = 'CIS-L1 2.3.7.x'; NIST = 'AC-11'; ISO = 'A.11.2.8' }
    Severity    = 'Medium'
    Check       = {
        param($ComputerName)
        $v = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
        }
        [pscustomobject]@{ Actual = "$v sec"; Pass = $v -gt 0 -and $v -le 900 }
    }
    Expected    = 'InactivityTimeoutSecs between 1 and 900'
    Remediation = 'Set via GPO: Interactive logon: Machine inactivity limit = 900.'
}
```

## Linux / Unix assets (built-in, over SSH)

Linux is a first-class asset type. The checks run over **SSH** using the Windows
OpenSSH client (`ssh.exe`, included in Windows Server 2019+), with key-based,
non-interactive auth.

### Setup

1. **Create an unprivileged scan user** on each Linux host (e.g. `svc-scan`) and
   install the scanning server's public key in its `~/.ssh/authorized_keys`.
2. **Generate a key pair** on the jump server and store the private key where the
   gMSA can read it (referenced by `Assets.Linux.Ssh.KeyPath`):
   ```powershell
   ssh-keygen -t ed25519 -f C:\Apps\AD-Agent\DCAnomalyAgent\State\ssh\id_ed25519 -N '""'
   ```
3. The included controls favour world-readable config (`sshd -T`, `/etc/login.defs`)
   so **root/sudo is not required**. If you add checks needing privilege, grant
   `sudo NOPASSWD` for those specific read-only commands only.
4. Configure hosts in `settings.psd1`:
   ```powershell
   Linux = @{
       Hosts = @('web01.contoso.com','web02.contoso.com')
       Ssh   = @{ User = 'svc-scan'; KeyPath = '...\State\ssh\id_ed25519'; Port = 22 }
   }
   ```

### Run

```powershell
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType Linux
.\Run-AnomalyScan.ps1 -ComplianceScan -AssetType Linux -TargetHostsOverride 'db01,db02'
```

### Controls included (CIS Distribution-Independent Linux subset)

SSH PermitRootLogin / PasswordAuthentication, host firewall active
(ufw/firewalld/nftables), auditd running, SELinux/AppArmor enforcing,
PASS_MAX_DAYS, legacy services (telnet/rsh/ftp), pending security updates.
Add your own in `Config/compliance-linux.psd1` (same pattern, `AppliesTo = @('Linux')`,
Check receives `param($ComputerName, $Ctx)` with SSH details).

## Other non-Windows assets (network devices, appliances, cloud)

For asset classes this scanner can't reach directly, run a dedicated tool and feed
results into the same SharePoint list / reports for one pane of glass:

| Asset | Recommended approach |
|---|---|
| Network (Cisco/Palo/etc.) | CIS-CAT Pro, or vendor posture tools |
| Cloud (Azure/AWS) | Azure Policy / Defender for Cloud, AWS Config + Security Hub |
| Cross-platform, authoritative | CIS-CAT Pro Assessor (covers Windows, Linux, network devices) |

## Asset discovery

Don't hand-maintain host lists — discover them. `Run-Discovery.ps1` enumerates
assets from AD and/or a network scan, classifies them by OS/role, and writes an
inventory plus a ready-to-paste `Assets` snippet for `settings.psd1`.

```powershell
# From Active Directory (domain-joined hosts)
.\Run-Discovery.ps1 -FromAD

# Network scan — finds non-domain and Linux/appliance hosts too
.\Run-Discovery.ps1 -Cidr '10.0.0.0/24','10.0.1.0/24'

# Both, combined and de-duplicated
.\Run-Discovery.ps1 -FromAD -Cidr '10.0.0.0/24'
```

Outputs (in the `State` folder): `asset-inventory.json`, `asset-inventory.csv`,
and `discovered-assets.psd1.txt` (paste into `settings.psd1` → `Assets`).

**Classification:** Windows (445/5985/135 open or AD OS = Windows), Linux (22 open,
Windows ports closed), DomainController (LDAP+Kerberos+Windows, or AD PrimaryGroupID
516), NetworkDevice (SNMP/telnet only). AD discovery refines Windows role into
DomainController / MemberServer / Workstation. The network scan needs no agents but
should be authorized — it's an active port probe across your ranges.

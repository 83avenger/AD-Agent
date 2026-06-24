# Compliance Checks on Other Assets (Member Servers & Workstations)

The compliance engine is asset-type aware. The same WinRM-based scanner that
checks Domain Controllers can check **member servers** and **workstations** —
it just runs a different set of controls per asset type.

## How it works

Each control declares which asset types it applies to via an `AppliesTo` array:

| Asset type | Controls run | File |
|---|---|---|
| `DomainController` | Domain-wide + DC checks (password policy, DA membership, LDAP signing, AD Recycle Bin…) | `Config/compliance-frameworks.psd1` |
| `MemberServer` | Host hardening (local admins, LAPS, RDP NLA, firewall, Defender, SMBv1, patching, services, log size) | `Config/compliance-endpoints.psd1` |
| `Workstation` | Same host hardening **+ BitLocker** | `Config/compliance-endpoints.psd1` |

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

## Non-Windows assets (Linux, network devices, appliances)

This engine is WinRM/PowerShell-based, so it targets Windows only. For other
asset classes, point a dedicated tool at them and feed results into the same
SharePoint list / report if you want one pane of glass:

| Asset | Recommended approach |
|---|---|
| Linux/Unix | OpenSCAP with CIS/SCAP content, or Ansible CIS role |
| Network (Cisco/Palo/etc.) | CIS-CAT Pro, or vendor posture tools |
| Cloud (Azure/AWS) | Azure Policy / Defender for Cloud, AWS Config + Security Hub |
| Cross-platform, authoritative | CIS-CAT Pro Assessor (covers Windows, Linux, network devices) |

The PowerShell scanner here is best for Windows/AD; for a mixed estate, CIS-CAT
Pro is the natural complement and can export to the same kinds of reports.

# Intune deployment (WinRM + push collector)

Intune is the most reliable way to reach laptops: the device pulls its scripts **outbound**
from Intune over HTTPS, so its host firewall, blocked RPC, VLAN rules and being at home
don't matter. Devices must be enrolled in Intune (hybrid-joined / co-managed is fine).

## 1. Build the scripts

On any machine with a copy of the repo:

```powershell
cd DCAnomalyAgent\Intune
# Push collector only (recommended for laptops - no inbound access needed at all):
.\Build-IntunePackage.ps1 -ServerUrl 'http://<jump>:5000' -Token '<COLLECTOR_TOKEN>'

# Push collector + WinRM opened to the jump server only:
.\Build-IntunePackage.ps1 -ServerUrl 'http://<jump>:5000' -Token '<COLLECTOR_TOKEN>' `
    -EnableWinRM -AllowedRemoteAddress <jump-server-IP>
```

Output goes to `Build\out\intune\` (git-ignored - it contains the token):

| File | Use as |
|---|---|
| `Enable-ADAgentEndpoint.ps1` | Platform script, or the **remediation** script of a Remediation |
| `Detect-ADAgentEndpoint.ps1` | The **detection** script of a Remediation |

The scripts are self-contained: your settings plus the repo's own
`Enable-EndpointWinRM.ps1`, `Install-PushCollector.ps1` and `Send-InventoryCheckin.ps1`
embedded, so the device runs the same code as the GPO and manual paths. Rebuild after
changing those scripts or rotating the token.

## 2. Add to Intune

Intune admin center → **Devices → Scripts and remediations**. Use one of these:

**Platform scripts** (runs once per device; runs again only if you upload a new version)
- Script: `Enable-ADAgentEndpoint.ps1`
- Run this script using the logged on credentials: **No** (runs as SYSTEM)
- Enforce script signature check: **No** (unless you sign it)
- Run script in 64-bit PowerShell host: **Yes**
- Assign to a device group (test with one device first).

**Remediations** (self-healing on a schedule; needs Windows Enterprise E3/E5 or equivalent)
- Detection script: `Detect-ADAgentEndpoint.ps1`
- Remediation script: `Enable-ADAgentEndpoint.ps1`
- Run with logged-on credentials: **No**, 64-bit: **Yes**, schedule: daily.
- If a user deletes a task or the WinRM rule disappears, the next run puts it back.

Optional: instead of the script creating the WinRM firewall rule, you can use
**Endpoint security → Firewall → Microsoft Defender Firewall Rules** (inbound TCP 5985,
remote address = jump server IP). Build without `-EnableWinRM` in that case, or keep both -
they don't conflict.

## 3. Verify on the test device

- Company Portal → Settings → **Sync** (or wait for the next check-in; platform scripts can
  take up to about an hour).
- `C:\ProgramData\AD-Agent\endpoint-setup.log` - ends with `Done.`
- `Get-ScheduledTask 'AD-Agent*'` - two tasks.
- `C:\ProgramData\AD-Agent\collector.log` - `Check-in accepted`.
- The device appears on the jump server's **Endpoints** page.
- Intune agent log if the script never ran:
  `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log`.

#Requires -Version 5.1
<#
.SYNOPSIS
    Ensures the inbound Windows Firewall rule the AD-Agent web UI needs exists. Idempotent:
    safe to run on every deploy and from the watchdog.

.DESCRIPTION
    The web UI listens on TCP 5000 (bound to 0.0.0.0 by Register-WebUIStartup.ps1). If the
    inbound allow rule for that port is missing, the process is up and answers on localhost
    but every remote browser times out (a dropped SYN reads as ERR_TIMED_OUT, not
    "connection refused") - the classic "running but unreachable" state. A reboot that
    resets a non-persistent rule, or a domain GPO firewall refresh, can remove it.

    This script creates the rule if it is absent and reports if it is already present. It
    only needs elevation when it actually has to create the rule; a plain presence check
    (-CheckOnly) runs unprivileged, so the watchdog (which runs as the non-admin gMSA) can
    call it to DETECT the gap even when it cannot fix it.

    IMPORTANT (GPO): if the domain firewall policy is set to not merge local rules
    ("Apply local firewall rules: No"), a rule created here is overridden on the next GPO
    refresh and will vanish again. In that case the port must be opened in GPO by the
    network/AD team - see firewall-request-ports.csv. This script detects and reports that
    situation; it cannot override Group Policy.

.PARAMETER Port
    TCP port to allow inbound. Must match Register-WebUIStartup.ps1's -Port.
.PARAMETER Profile
    Firewall profile(s) the rule applies to. Domain by default (the estate is domain-joined).
.PARAMETER DisplayName
    Stable rule name used for both lookup and creation, so repeated runs never duplicate it.
.PARAMETER CheckOnly
    Only report whether the rule exists (exit 0 = present, exit 2 = missing). Never modifies
    anything, so it needs no elevation. Used by the watchdog.

.EXAMPLE
    .\Set-WebUIFirewall.ps1
    Ensure the inbound rule for TCP 5000 exists (creates it if missing; needs elevation).

.EXAMPLE
    .\Set-WebUIFirewall.ps1 -CheckOnly
    Just report presence - used by Watch-WebUIHealth.ps1.
#>
[CmdletBinding()]
param(
    [int]$Port = 5000,
    [string[]]$Profile = @('Domain'),
    [string]$DisplayName = 'AD-Agent WebUI (TCP 5000)',
    [switch]$CheckOnly
)

function Test-WebUIFirewallRule {
    <#
    .SYNOPSIS
        Returns $true if an enabled inbound allow rule for $Port exists. Matches on the
        port filter, not just the display name, so a rule created by hand or by the network
        team under a different name still counts as "present".
    #>
    param([int]$Port)
    try {
        $inbound = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop
        foreach ($rule in $inbound) {
            $pf = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            if ($pf -and $pf.Protocol -eq 'TCP' -and ($pf.LocalPort -contains "$Port" -or $pf.LocalPort -contains $Port)) {
                return $true
            }
        }
    } catch {
        Write-Warning "Could not enumerate firewall rules: $_"
    }
    return $false
}

$exists = Test-WebUIFirewallRule -Port $Port

if ($CheckOnly) {
    if ($exists) {
        Write-Host "Inbound allow rule for TCP $Port is present."
        exit 0
    }
    Write-Host "No inbound allow rule for TCP $Port - external clients cannot reach the web UI."
    exit 2
}

if ($exists) {
    Write-Host "Inbound allow rule for TCP $Port already present - nothing to do."
    return
}

# Creating a rule needs elevation - check only now, at the point we actually modify, so
# -CheckOnly stays usable by the non-admin gMSA (same pattern as Watch-WebUIHealth.ps1).
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    throw "Creating the firewall rule requires an elevated (Run as Administrator) PowerShell session. Re-open PowerShell as Administrator and re-run."
}

New-NetFirewallRule -DisplayName $DisplayName -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $Port -Profile ($Profile -join ',') `
    -Description "Allows analysts to reach the AD-Agent web UI on TCP $Port. Created by Set-WebUIFirewall.ps1." | Out-Null

if (Test-WebUIFirewallRule -Port $Port) {
    Write-Host "Created inbound allow rule '$DisplayName' for TCP $Port (profile: $($Profile -join ', '))."
    Write-Host "If this rule disappears after a while, domain GPO is overriding local firewall rules -"
    Write-Host "the port must then be opened in GPO by the network/AD team (see firewall-request-ports.csv)."
} else {
    Write-Warning "Rule creation reported success but the rule is not present - domain GPO may be blocking local rules. Request TCP $Port inbound via GPO (firewall-request-ports.csv)."
}

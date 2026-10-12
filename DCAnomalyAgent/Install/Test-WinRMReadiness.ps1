#Requires -Version 5.1
<#
.SYNOPSIS
    Run ON an endpoint where WinRM "should" be on (GPO/Intune) but the jump server sees TCP
    5985 closed. Checks each piece WinRM needs and says which one is missing and how to fix it.

.DESCRIPTION
    A WinRM GPO only works when all of these line up; a hand-built one usually misses one:
      1. The GPO actually applied to this computer.
      2. Listener policy: AllowAutoConfig = 1 AND a non-blank IPv4Filter/IPv6Filter. A blank
         filter is the classic trap - the policy is "enabled" but no listener is created.
      3. WinRM service Automatic AND running (a service set to Automatic by GPO only starts at
         the next boot).
      4. An HTTP listener exists and answers locally.
      5. An enabled inbound allow rule for TCP 5985 that covers the CURRENT network profile -
         a Domain-only rule does nothing on a laptop that's on Wi-Fi/VPN as Private/Public.
      6. No third-party firewall (e.g. CrowdStrike Falcon Firewall) overriding Windows Firewall.

    Read-only: changes nothing. Run elevated for the most complete answer (gpresult and some
    firewall details need it).

.PARAMETER GpoName
    Name of your WinRM GPO, to confirm it applied. Default matches New-WinRMGPO.ps1.

.EXAMPLE
    .\Test-WinRMReadiness.ps1
.EXAMPLE
    .\Test-WinRMReadiness.ps1 -GpoName 'Enable WinRM - Workstations'
#>
[CmdletBinding()]
param(
    [string]$GpoName = 'AD-Agent-WinRM'
)

$results = [System.Collections.Generic.List[object]]::new()
function Add-Check {
    param([string]$Check, [ValidateSet('PASS', 'FAIL', 'WARN', 'INFO')][string]$Status, [string]$Detail, [string]$Fix = '')
    $results.Add([pscustomobject]@{ Check = $Check; Status = $Status; Detail = $Detail; Fix = $Fix })
}

$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { Write-Warning "Not elevated - the GPO check may be incomplete. Re-run as administrator for the full picture." }

# --- 1. GPO applied ----------------------------------------------------------
try {
    $gp = (gpresult /scope computer /r 2>&1) -join "`n"
    # gpresult lists "Applied Group Policy Objects" first, then "The following GPOs were not
    # applied because they were filtered out" - which section the name is in is the answer.
    $parts = $gp -split 'The following GPOs were not applied'
    $nameRx = "(?m)^\s+$([regex]::Escape($GpoName))\s*$"
    if ($parts[0] -match $nameRx) {
        Add-Check 'GPO applied' 'PASS' "'$GpoName' is in this computer's Applied GPOs."
    } elseif ($parts.Count -gt 1 -and $parts[1] -match [regex]::Escape($GpoName)) {
        Add-Check 'GPO applied' 'FAIL' "'$GpoName' is listed under 'not applied' (filtered out)." `
            'Check the GPO''s Security Filtering (needs Domain Computers or this computer with Read + Apply), any WMI filter, and that the link is enabled.'
    } elseif ($gp -match 'Access is denied|ERROR') {
        Add-Check 'GPO applied' 'WARN' 'gpresult could not run (needs elevation).' 'Re-run this script as administrator.'
    } else {
        Add-Check 'GPO applied' 'FAIL' "'$GpoName' does not appear in gpresult at all." `
            'Confirm this computer object is in (or below) the OU the GPO is linked to, then run: gpupdate /force and reboot. (Use -GpoName if your GPO has a different name.)'
    }
} catch {
    Add-Check 'GPO applied' 'WARN' "gpresult failed: $($_.Exception.Message)"
}

# --- 2. Listener policy ------------------------------------------------------
$polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
$pol = Get-ItemProperty -Path $polKey -ErrorAction SilentlyContinue
if (-not $pol) {
    Add-Check 'Listener policy' 'INFO' 'No WinRM listener policy on this machine (fine if WinRM is enabled locally instead of by GPO).'
} else {
    if ($pol.AllowAutoConfig -ne 1) {
        Add-Check 'Listener policy' 'FAIL' "AllowAutoConfig = '$($pol.AllowAutoConfig)'." `
            'GPO: Computer Config > Admin Templates > Windows Components > Windows Remote Management > WinRM Service > "Allow remote server management through WinRM" = Enabled.'
    } elseif ([string]::IsNullOrWhiteSpace($pol.IPv4Filter) -and [string]::IsNullOrWhiteSpace($pol.IPv6Filter)) {
        Add-Check 'Listener policy' 'FAIL' 'AllowAutoConfig is on but IPv4Filter and IPv6Filter are BLANK - WinRM creates no listener.' `
            'In that same GPO setting, set IPv4 filter = * (and IPv6 filter = *). Access is limited by the firewall rule, not this filter.'
    } else {
        Add-Check 'Listener policy' 'PASS' "AllowAutoConfig = 1, IPv4Filter = '$($pol.IPv4Filter)', IPv6Filter = '$($pol.IPv6Filter)'."
    }
}

# --- 3. Service --------------------------------------------------------------
$svc = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if (-not $svc) {
    Add-Check 'WinRM service' 'FAIL' 'WinRM service not found.'
} else {
    $startType = (Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction SilentlyContinue).StartMode
    if ($svc.Status -eq 'Running' -and $startType -eq 'Auto') {
        Add-Check 'WinRM service' 'PASS' 'Running, Automatic.'
    } elseif ($svc.Status -ne 'Running' -and $startType -eq 'Auto') {
        Add-Check 'WinRM service' 'FAIL' 'Set to Automatic but NOT running - the GPO set it, but it only starts at boot.' `
            'Reboot, or run: Start-Service WinRM'
    } else {
        Add-Check 'WinRM service' 'FAIL' "Status = $($svc.Status), StartMode = $startType." `
            'GPO: Computer Config > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management) = Automatic. Then reboot.'
    }
}

# --- 4. Listener -------------------------------------------------------------
$listenerOk = $false
try {
    $listeners = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop)
    $http = $listeners | Where-Object { $_.Keys -contains 'Transport=HTTP' }
    if ($http) {
        $listenerOk = $true
        Add-Check 'HTTP listener' 'PASS' "Present ($(@($http).Count))."
    } else {
        Add-Check 'HTTP listener' 'FAIL' 'No HTTP listener.' 'Fix the listener policy above (blank filter is the usual cause), or run Enable-EndpointWinRM.ps1.'
    }
} catch {
    Add-Check 'HTTP listener' 'FAIL' "Cannot read listeners ($($_.Exception.Message)) - usually means the service isn't running." 'Fix the service check first.'
}
try {
    Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
    Add-Check 'Local WSMan answer' 'PASS' 'Test-WSMan localhost succeeded.'
} catch {
    Add-Check 'Local WSMan answer' 'FAIL' "Test-WSMan localhost failed: $($_.Exception.Message)"
}

# --- 5. Network profile vs firewall rules ------------------------------------
$profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)
$current = @($profiles | ForEach-Object { switch ([string]$_.NetworkCategory) { 'DomainAuthenticated' { 'Domain' } default { [string]$_ } } } | Select-Object -Unique)
Add-Check 'Network profile' 'INFO' ("Active: " + (($profiles | ForEach-Object { "$($_.InterfaceAlias) = $($_.NetworkCategory)" }) -join '; '))

$fwProfiles = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue
foreach ($p in $fwProfiles | Where-Object { $_.Name -in $current }) {
    if ($p.Enabled -and $p.DefaultInboundAction -eq 'Allow') {
        Add-Check "Firewall ($($p.Name))" 'INFO' 'Profile allows all inbound by default.'
    }
}

# Port filters first (one call), then the rules they belong to - far cheaper than asking every
# rule for its port filter. ActiveStore = the merged local + GPO rules actually enforced.
$portFilters = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.Protocol -eq 'TCP' -and @($_.LocalPort) -contains '5985' })
$rules = @($portFilters | Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and [string]$_.Enabled -eq 'True' })
if (-not $rules) {
    Add-Check 'Firewall rule 5985' 'FAIL' 'No enabled inbound allow rule for TCP 5985 is in effect.' `
        'Add one via GPO (New-WinRMGPO.ps1 does this, scoped to the jump server) or locally with Enable-EndpointWinRM.ps1.'
} else {
    $covering = @($rules | Where-Object {
        $rp = [string]$_.Profile
        $rp -eq 'Any' -or ($current | Where-Object { $rp -match $_ })
    })
    $summary = ($rules | ForEach-Object {
        $ra = ($_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress -join ','
        "$($_.DisplayName) [Profile=$($_.Profile); Remote=$ra; Source=$($_.PolicyStoreSourceType)]"
    }) -join ' | '
    if ($covering) {
        Add-Check 'Firewall rule 5985' 'PASS' "Rule(s) cover the current profile ($($current -join ',')): $summary" `
            'If the jump server still sees it closed, confirm the jump server IP is inside the rule''s Remote addresses.'
    } else {
        Add-Check 'Firewall rule 5985' 'FAIL' "Rules exist but NOT for the current profile ($($current -join ',')): $summary" `
            'Typical laptop case: a Domain-only rule while on Wi-Fi/VPN. Set the rule''s profile to All (New-WinRMGPO.ps1 does this).'
    }
}

# --- 6. Third-party firewall -------------------------------------------------
try {
    $fwProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct -ErrorAction Stop)
    $thirdParty = @($fwProducts | Where-Object { $_.displayName -notmatch 'Windows (Defender )?Firewall|Microsoft Defender' })
    if ($thirdParty) {
        Add-Check 'Third-party firewall' 'WARN' "Registered: $(($thirdParty.displayName) -join ', ')." `
            'This product may enforce its own rules over Windows Firewall/GPO - allow inbound TCP 5985 from the jump server in its policy.'
    } else {
        Add-Check 'Third-party firewall' 'PASS' 'None registered with Security Center.'
    }
} catch {
    Add-Check 'Third-party firewall' 'INFO' 'Security Center not available (normal on servers).'
}
if (Get-Service -Name CSAgent -ErrorAction SilentlyContinue) {
    Add-Check 'CrowdStrike Falcon' 'WARN' 'Falcon sensor present.' `
        'If Falcon Firewall Management is enabled for this host group, its policy overrides Windows Firewall/GPO rules - allow inbound TCP 5985 from the jump server there.'
}

# --- Output ------------------------------------------------------------------
Write-Host ""
foreach ($r in $results) {
    $color = switch ($r.Status) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'WARN' { 'Yellow' } default { 'Gray' } }
    Write-Host ("[{0}] {1}: {2}" -f $r.Status, $r.Check, $r.Detail) -ForegroundColor $color
    if ($r.Fix -and $r.Status -ne 'PASS') { Write-Host "       Fix: $($r.Fix)" }
}
$fails = @($results | Where-Object Status -eq 'FAIL')
Write-Host ""
if ($fails) {
    Write-Host "$($fails.Count) blocking problem(s). Fix them top-down - later checks often clear once earlier ones pass." -ForegroundColor Red
} else {
    Write-Host "Locally WinRM looks ready. If the jump server still sees 5985 closed, the block is on the path (network firewall) or in a third-party firewall policy." -ForegroundColor Green
    Write-Host "From the jump server: Test-NetConnection $env:COMPUTERNAME -Port 5985 ; Test-WSMan $env:COMPUTERNAME"
}

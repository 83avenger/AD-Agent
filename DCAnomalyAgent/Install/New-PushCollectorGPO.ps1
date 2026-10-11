#Requires -Version 5.1
<#
.SYNOPSIS
    Automates the GPO rollout of the AD-Agent push collector to laptop/workstation OUs. Run
    on a domain-joined admin box with the RSAT GroupPolicy module.

.DESCRIPTION
    Workstations usually drop inbound WinRM/SMB at their host firewall, so the jump server
    can't pull from them. The push collector inverts that: each endpoint checks in OUTBOUND,
    needing no inbound rule. This helper does what Deploy-PushCollector-GPO.md describes by
    hand:

      1. Stages the collector scripts to SYSVOL (replicated to every DC, readable by every
         domain computer).
      2. Creates/links a GPO to the OU(s) you name.
      3. Adds a Computer **Startup PowerShell script** that runs the existing, tested
         Install-PushCollector.ps1 on each endpoint at boot - which idempotently registers the
         two local scheduled tasks (presence every N min + at startup; full inventory daily).

    Reusing Install-PushCollector.ps1 (rather than hand-building Group Policy Preferences
    Scheduled-Task XML) means the endpoint-side logic is the same code already in use for
    non-domain hosts.

    PREREQUISITE: set COLLECTOR_TOKEN on the jump server first, or /api/collector/checkin
    fails closed with HTTP 503 "collector endpoint disabled":
        .\Set-CollectorToken.ps1 -RestartWebUI

.PARAMETER ServerUrl
    Base URL of the AD-Agent web UI, e.g. 'https://jump-host.example.local'.
.PARAMETER Token
    The jump server's COLLECTOR_TOKEN. Defaults to $env:COLLECTOR_TOKEN if set here.
.PARAMETER TargetOU
    One or more OU distinguished names to link the GPO to. MUST be workstation/laptop OUs -
    NOT the Domain Controllers OU (servers/DCs stay on agentless WinRM).
.PARAMETER GpoName
    GPO name. Created if absent.
.PARAMETER SysvolSubPath
    Folder under the domain SYSVOL scripts share to stage the collector into.
.PARAMETER IntervalMinutes
    Presence check-in interval passed to the installer.
.PARAMETER FullInventoryAt
    Daily full-inventory time passed to the installer.
.PARAMETER TightenAcl
    Restrict the staged SYSVOL folder to Domain Computers (read) + admins.

.EXAMPLE
    .\New-PushCollectorGPO.ps1 -ServerUrl 'https://jump-host.example.local' `
        -TargetOU 'OU=Laptops,OU=Devices,DC=example,DC=local' -TightenAcl
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [string]$Token = $env:COLLECTOR_TOKEN,
    [Parameter(Mandatory)][string[]]$TargetOU,
    [string]$GpoName = 'AD-Agent-PushCollector',
    [string]$SysvolSubPath = 'scripts\AD-Agent',
    [int]$IntervalMinutes = 30,
    [string]$FullInventoryAt = '13:00',
    [switch]$TightenAcl
)

$ErrorActionPreference = 'Stop'

# --- Preconditions -----------------------------------------------------------
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) { throw "Run this from an elevated PowerShell session (it edits SYSVOL and GPOs)." }
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    throw "The RSAT GroupPolicy module is not installed. Install it (e.g. 'Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0') and re-run."
}
Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if (-not $Token) { throw "No -Token given and COLLECTOR_TOKEN is not set in this session. Set it on the jump server with Set-CollectorToken.ps1, then pass it here." }

$dcOuPattern = 'OU=Domain Controllers,'
foreach ($ou in $TargetOU) {
    if ($ou -like "*$dcOuPattern*") {
        throw "Refusing to link to the Domain Controllers OU ($ou). Servers and DCs stay on agentless WinRM - deploy the collector only to laptop/workstation OUs."
    }
}

# --- Resolve domain / SYSVOL -------------------------------------------------
$domainDns = $env:USERDNSDOMAIN
if (-not $domainDns -and (Get-Command Get-ADDomain -ErrorAction SilentlyContinue)) { $domainDns = (Get-ADDomain).DNSRoot }
if (-not $domainDns) { throw "Could not determine the domain DNS name (USERDNSDOMAIN empty and ActiveDirectory module unavailable)." }

$sysvolDir = "\\$domainDns\SYSVOL\$domainDns\$SysvolSubPath"
$srcDir = $PSScriptRoot
$collectorSrc = Join-Path (Split-Path -Parent $srcDir) 'Collector\Send-InventoryCheckin.ps1'
$installerSrc = Join-Path (Split-Path -Parent $srcDir) 'Collector\Install-PushCollector.ps1'
foreach ($f in @($collectorSrc, $installerSrc)) {
    if (-not (Test-Path $f)) { throw "Source script not found: $f" }
}

# --- 1/2. Stage scripts to SYSVOL -------------------------------------------
if ($PSCmdlet.ShouldProcess($sysvolDir, "Stage collector scripts to SYSVOL")) {
    if (-not (Test-Path $sysvolDir)) { New-Item -ItemType Directory -Path $sysvolDir -Force | Out-Null }
    Copy-Item $collectorSrc (Join-Path $sysvolDir 'Send-InventoryCheckin.ps1') -Force
    Copy-Item $installerSrc (Join-Path $sysvolDir 'Install-PushCollector.ps1') -Force
    Write-Host "Staged collector scripts to $sysvolDir"

    if ($TightenAcl) {
        # Domain Computers need read (the startup script runs as SYSTEM = the machine account);
        # remove broad inherited access and grant only computers + admins + SYSTEM. Use the
        # NetBIOS domain for the group principals - icacls resolves those more reliably than FQDN.
        $nb = $env:USERDOMAIN
        icacls $sysvolDir /inheritance:r /grant:r `
            "$nb\Domain Computers:(OI)(CI)RX" `
            "BUILTIN\Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "$nb\Domain Admins:(OI)(CI)F" | Out-Null
        Write-Host "Tightened ACL on $sysvolDir to Domain Computers (read) + admins."
    }
}

# --- 3. Create + link the GPO ------------------------------------------------
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    if ($PSCmdlet.ShouldProcess($GpoName, "Create GPO")) {
        $gpo = New-GPO -Name $GpoName -Comment "Deploys the AD-Agent push collector (outbound check-in) to endpoints."
        Write-Host "Created GPO '$GpoName' {$($gpo.Id)}"
    }
} else {
    Write-Host "GPO '$GpoName' already exists {$($gpo.Id)} - updating it."
}
foreach ($ou in $TargetOU) {
    if ($PSCmdlet.ShouldProcess($ou, "Link GPO '$GpoName'")) {
        if (-not (Get-GPInheritance -Target $ou | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName })) {
            New-GPLink -Name $GpoName -Target $ou -LinkEnabled Yes | Out-Null
            Write-Host "Linked '$GpoName' to $ou"
        } else {
            Write-Host "'$GpoName' already linked to $ou"
        }
    }
}

# --- 4. Configure the Computer Startup PowerShell script ---------------------
# GPO startup scripts live in the GPO's SYSVOL Machine\Scripts area: the PowerShell startup
# entries are listed in psscripts.ini, and the Scripts client-side extension must be declared
# in gPCMachineExtensionNames so clients apply them. We point the entry at the installer staged
# above and pass the server URL + token as its parameters.
$gpoId = "{$($gpo.Id.ToString().ToUpper())}"
$policyRoot = "\\$domainDns\SYSVOL\$domainDns\Policies\$gpoId\Machine"
$scriptsDir = Join-Path $policyRoot 'Scripts\Startup'
$iniPath = Join-Path $policyRoot 'Scripts\psscripts.ini'
$installerSysvol = "\\$domainDns\SYSVOL\$domainDns\$SysvolSubPath\Install-PushCollector.ps1"
$collectorSysvol = "\\$domainDns\SYSVOL\$domainDns\$SysvolSubPath\Send-InventoryCheckin.ps1"
$cmdLine = "-NoProfile -ExecutionPolicy Bypass -File `"$installerSysvol`" -ServerUrl `"$ServerUrl`" -Token `"$Token`" -SourcePath `"$collectorSysvol`" -IntervalMinutes $IntervalMinutes -FullInventoryAt `"$FullInventoryAt`""

if ($PSCmdlet.ShouldProcess($iniPath, "Set Computer Startup PowerShell script")) {
    if (-not (Test-Path $scriptsDir)) { New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null }

    # psscripts.ini drives the PowerShell Startup/Shutdown lists. Write a single startup entry
    # (index 0) that runs powershell.exe with our command line. UTF-16LE + BOM is what the Group
    # Policy editor writes and what the client expects.
    $ini = @"
[Startup]
0CmdLine=powershell.exe
0Parameters=$cmdLine
[ScriptsConfig]
StartExecutePSFirst=true
"@
    $enc = New-Object System.Text.UnicodeEncoding($false, $true)   # UTF-16LE, with BOM
    [System.IO.File]::WriteAllText($iniPath, $ini, $enc)
    # Mark the ini hidden/system, as the GP editor does.
    (Get-Item $iniPath -Force).Attributes = 'Hidden,System,Archive'
    Write-Host "Wrote startup script entry to $iniPath"

    # Declare the Scripts CSE so clients actually run it. Format is a sorted, concatenated list
    # of [{CSE-GUID}{Tool-GUID}] pairs; Scripts CSE = {42B5FAAE-...}, tool = {40B6664F-...}.
    $scriptsCse = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    $gpoAdPath = "CN=$gpoId,CN=Policies,CN=System," + ((Get-ADDomain -ErrorAction Stop).DistinguishedName)
    if (Get-Command Get-ADObject -ErrorAction SilentlyContinue) {
        $existing = (Get-ADObject -Identity $gpoAdPath -Properties gPCMachineExtensionNames).gPCMachineExtensionNames
        if (-not $existing -or ($existing -notlike '*42B5FAAE-6536-11D2-AE5A-0000F87571E3*')) {
            $new = if ($existing) { $existing + $scriptsCse } else { $scriptsCse }
            Set-ADObject -Identity $gpoAdPath -Replace @{ gPCMachineExtensionNames = $new }
            Write-Host "Registered the Scripts client-side extension on the GPO."
        }
    } else {
        Write-Warning "ActiveDirectory module not available - set gPCMachineExtensionNames on the GPO manually (add $scriptsCse), or the startup script won't apply."
    }

    # Bump the GPO version so clients re-read it (increment the computer half of the version).
    try {
        $verObj = Get-ADObject -Identity $gpoAdPath -Properties versionNumber
        Set-ADObject -Identity $gpoAdPath -Replace @{ versionNumber = ([int]$verObj.versionNumber + 65536) }
    } catch { Write-Warning "Could not bump the GPO version automatically: $_. Run 'gpupdate /force' on a client to force re-apply, or re-save the GPO in GPMC." }
}

Write-Host ""
Write-Host "Done. GPO '$GpoName' deploys the push collector at endpoint startup." -ForegroundColor Green
Write-Host "Verify on a test endpoint in the target OU:"
Write-Host "  gpupdate /force   (then reboot, since it's a startup script)"
Write-Host "  Get-ScheduledTask -TaskName 'AD-Agent Check-in','AD-Agent Full Inventory'"
Write-Host "  Get-Content \$env:ProgramData\AD-Agent\collector.log -Tail 10"
Write-Host "Then the device should appear on the web UI's Endpoints page."
Write-Host ""
Write-Host "Reminder: if check-ins return HTTP 503 'collector endpoint disabled', COLLECTOR_TOKEN"
Write-Host "is not set on the jump server. Set it with Set-CollectorToken.ps1 -RestartWebUI."

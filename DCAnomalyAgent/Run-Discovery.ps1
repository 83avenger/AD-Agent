#Requires -Version 5.1
<#
.SYNOPSIS
    Discovers assets from Active Directory and/or a network scan, classifies them
    by OS/role, and writes an inventory (JSON + CSV + a ready-to-paste settings
    Assets snippet).

.PARAMETER FromAD
    Enumerate domain-joined computers from Active Directory.

.PARAMETER Cidr
    One or more CIDR ranges to network-scan (e.g. '10.0.0.0/24','10.0.1.0/24'), or a bare
    IP (e.g. '10.0.1.50') to scan just that one host. Picks up non-domain and non-Windows
    (Linux/appliance) hosts too.

.PARAMETER JsonOutput
    Emit the inventory as JSON on stdout (used by the web UI).

.PARAMETER Fresh
    Ignore any previously saved inventory at the output location and start clean.
    By default, each run is MERGED into the existing asset-inventory.json/csv at
    OutDir, so you can scan subnets in small batches (e.g. one /24 at a time) and
    the results accumulate in one place instead of overwriting each other. A host
    re-scanned in a later batch replaces its old entry; hosts not touched in this
    run are kept as-is from the prior scan(s).

.PARAMETER SkipCategorize
    Skip the Desktop/Laptop/Server/Domain Controller device-category probe (an
    extra WinRM call per Windows host) and leave AssetType as the coarser
    DomainController/MemberServer/Workstation/Windows discovery label. Use this
    for a faster first pass over a large range before WinRM/gMSA access is set up.

.PARAMETER CloudflareWarpCidr
    CIDR range(s) assigned to remote/home users connecting in via Cloudflare
    WARP/Zero Trust. Scanned exactly like -Cidr but tagged with
    Source = 'Cloudflare WARP' so those hosts are distinguishable from on-prem
    LAN devices on the Discovery dashboard. Falls back to
    Discovery.CloudflareWarpSubnets in settings.psd1 when omitted. Pulling
    device/user identity straight from the Cloudflare Zero Trust API instead of
    a port scan is a possible future enhancement, not implemented here.

.PARAMETER SkipSoftwareInventory
    Skip collecting installed software from newly-categorized Windows hosts.
    By default this runs as part of discovery (per-device software list, plus
    the same zero-day cross-reference used by -SoftwareInventoryScan), since
    discovery is meant to be the first scan run - use this to skip straight to
    just asset/category/online data on a fast first pass.

.EXAMPLE
    .\Run-Discovery.ps1 -FromAD
.EXAMPLE
    .\Run-Discovery.ps1 -Cidr '10.0.0.0/24','10.0.1.0/24'
.EXAMPLE
    .\Run-Discovery.ps1 -FromAD -Cidr '10.0.0.0/24'
.EXAMPLE
    # Scan in bunches on separate days; each run folds into the same inventory file.
    .\Run-Discovery.ps1 -Cidr '10.15.2.0/24'
    .\Run-Discovery.ps1 -Cidr '10.15.3.0/24'
.EXAMPLE
    .\Run-Discovery.ps1 -CloudflareWarpCidr '100.96.0.0/12'
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    # Left unset by default and resolved below (not here) - $PSScriptRoot is not reliably
    # populated while param() default values are evaluated in Windows PowerShell 5.1.
    [string]$ConfigPath,
    [switch]$FromAD,
    [string[]]$Cidr,
    [string[]]$CloudflareWarpCidr,
    [int]$TimeoutMs = 700,
    [switch]$JsonOutput,
    [switch]$Fresh,
    [switch]$SkipCategorize,
    [switch]$SkipSoftwareInventory
)

$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'Config\settings.psd1' }

# PowerShell's parameter binder does NOT aggregate multiple space-separated tokens into
# an array parameter when this script is invoked externally (e.g. Python's subprocess ->
# pwsh -File ... -Cidr val1 val2 val3) - only the first token binds, and the rest become
# unbindable stray arguments. The caller (WebApp/app.py) instead passes one comma-joined
# string per multi-value parameter; splitting here handles that case, and is a harmless
# no-op for normal array input (e.g. -Cidr 'a','b','c' from an interactive/CLI caller).
if ($Cidr) { $Cidr = @($Cidr | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
if ($CloudflareWarpCidr) { $CloudflareWarpCidr = @($CloudflareWarpCidr | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }

Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Discovery.psm1" -Force
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.SoftwareInventory.psm1" -Force

function Import-AgentConfig {
    # Resolves $PSScriptRoot in settings.psd1 to its own directory (Import-PowerShellDataFile
    # leaves it empty), so the relative paths in the config load correctly.
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -Path $Path).Path
    $dir  = Split-Path -Parent $resolved
    $text = (Get-Content -Raw -Path $resolved).Replace('$PSScriptRoot', $dir)
    return (& ([scriptblock]::Create($text)))
}

$config = Import-AgentConfig -Path $ConfigPath

function Write-DiscoveryLog {
    <#
    .SYNOPSIS
        Timestamped trace to both console and State\discovery.log, so you can see WHY a
        host was skipped/failed for categorization or software collection without needing
        -Verbose live (e.g. from the web UI, which doesn't surface console output).
    #>
    param([string]$Message, [ValidateSet('INFO', 'SKIP', 'ERROR')][string]$Level = 'INFO')
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    Write-Host $line
    try {
        $logDir = Split-Path -Path $config.LogPath -Parent
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        Add-Content -Path (Join-Path $logDir 'discovery.log') -Value $line
    } catch { }
}

# Fall back to configured Discovery settings if no switches passed
if (-not $FromAD -and -not $Cidr) {
    if ($config.Discovery) {
        $FromAD = [bool]$config.Discovery.FromAD
        $Cidr   = $config.Discovery.Subnets
    }
}
if (-not $CloudflareWarpCidr -and $config.Discovery -and $config.Discovery.CloudflareWarpSubnets) {
    $CloudflareWarpCidr = $config.Discovery.CloudflareWarpSubnets
}

$adAssets  = @()
$netAssets = @()

if ($FromAD) {
    Write-DiscoveryLog "Discovering from Active Directory..."
    $adAssets = @(Get-ADAsset -EnabledOnly)
    Write-DiscoveryLog "AD discovery found $($adAssets.Count) computer object(s)."
}

if ($Cidr) {
    Write-DiscoveryLog "Scanning network ranges: $($Cidr -join ', ')"
    $netAssets += @(Get-NetworkAsset -Cidr $Cidr -TimeoutMs $TimeoutMs)
    Write-DiscoveryLog "Network scan found $($netAssets.Count) live host(s) so far."
}

if ($CloudflareWarpCidr) {
    Write-DiscoveryLog "Scanning Cloudflare WARP range(s): $($CloudflareWarpCidr -join ', ')"
    $warpAssets = @(Get-NetworkAsset -Cidr $CloudflareWarpCidr -TimeoutMs $TimeoutMs -SourceLabel 'Cloudflare WARP')
    Write-DiscoveryLog "Cloudflare WARP scan found $($warpAssets.Count) live host(s)."
    $netAssets += $warpAssets
}

$newInventory = @(Merge-AssetInventory -AdAssets $adAssets -NetworkAssets $netAssets)

# Categorize every Windows asset into Desktop / Laptop / Server / Domain Controller.
# DomainController/MemberServer resolve without touching the host; Workstation/Windows
# need one extra WinRM call (Win32_SystemEnclosure) to tell Desktop from Laptop, so it's
# only attempted where WinRM was seen open during the scan (or the host came from AD,
# which doesn't record OpenPorts and is worth trying regardless).
if (-not $SkipCategorize) {
    Write-DiscoveryLog "Categorizing $($newInventory.Count) newly-discovered asset(s)..."
    foreach ($asset in $newInventory) {
        if ($asset.AssetType -notin @('DomainController', 'MemberServer', 'Workstation', 'Windows')) {
            Write-DiscoveryLog "SKIP categorize for $($asset.Name): AssetType '$($asset.AssetType)' is not a Windows type" -Level SKIP
            continue
        }
        $hasOpenPorts = $null -ne $asset.PSObject.Properties['OpenPorts']
        if ($hasOpenPorts -and $asset.OpenPorts -notmatch 'WinRM') {
            $note = "Not categorized: WinRM (5985/5986) was not seen open during the network scan (ports seen: $($asset.OpenPorts)). Category probe and software collection both need WinRM."
            Write-DiscoveryLog "SKIP categorize/software for $($asset.Name) ($($asset.IP)): WinRM not open (ports: $($asset.OpenPorts))" -Level SKIP
            $asset | Add-Member -NotePropertyName CollectionNote -NotePropertyValue $note -Force
            continue
        }
        Write-DiscoveryLog "Probing device category for $($asset.Name) over WinRM (this may take a few seconds)..."
        try {
            $before = $asset.AssetType
            $asset.AssetType = Get-DeviceCategory -ComputerName $asset.Name -AssetType $asset.AssetType
            Write-DiscoveryLog "Categorized $($asset.Name): $before -> $($asset.AssetType)"
        } catch {
            $note = "Category probe failed over WinRM: $_. Common causes: gMSA lacks Remote Management Users on this host, WinRM is open but not configured for this identity, or the host is genuinely unreachable."
            Write-DiscoveryLog "ERROR categorize $($asset.Name): $_" -Level ERROR
            $asset | Add-Member -NotePropertyName CollectionNote -NotePropertyValue $note -Force
        }
    }
}

# Software inventory as part of discovery: for every Windows host we could reach for
# categorization, also pull its installed-software list (per-device, for the dashboard
# drill-down) and cross-reference it against the zero-day watchlist, same as
# -SoftwareInventoryScan. Runs by default since discovery is meant to be the first scan.
$softwareInventory  = @()
$vulnerableSoftware = @()
if (-not $SkipSoftwareInventory) {
    $swTargets = @($newInventory | Where-Object { $_.AssetType -in @('Domain Controller', 'Server', 'Desktop', 'Laptop', 'Workstation') })
    Write-DiscoveryLog "Software inventory: $($swTargets.Count) Windows host(s) categorized and eligible for collection."
    foreach ($asset in $swTargets) {
        $hasOpenPorts = $null -ne $asset.PSObject.Properties['OpenPorts']
        if ($hasOpenPorts -and $asset.OpenPorts -notmatch 'WinRM') {
            Write-DiscoveryLog "SKIP software collection for $($asset.Name) ($($asset.IP)): WinRM not open (ports: $($asset.OpenPorts))" -Level SKIP
            if (-not $asset.PSObject.Properties['CollectionNote']) {
                $asset | Add-Member -NotePropertyName CollectionNote -NotePropertyValue "No software collected this run: WinRM (5985/5986) was not seen open during the network scan (ports seen: $($asset.OpenPorts)). Any software list shown is from an earlier successful scan, if one exists." -Force
            }
            continue
        }
        try {
            $sw = @(Get-InstalledSoftware -ComputerName $asset.Name -Category $asset.AssetType)
            $asset | Add-Member -NotePropertyName Software -NotePropertyValue $sw -Force
            $softwareInventory += $sw
            Write-DiscoveryLog "Software inventory: $($sw.Count) product(s) collected from $($asset.Name)."
        } catch {
            Write-DiscoveryLog "ERROR software collection on $($asset.Name): $_" -Level ERROR
            $asset | Add-Member -NotePropertyName CollectionNote -NotePropertyValue "Software collection failed over WinRM: $_. Common causes: gMSA lacks Remote Management Users on this host, WinRM listener not configured for this identity, firewall blocking 5985/5986 from the jump server, or the host is genuinely unreachable." -Force
        }
    }

    if ($softwareInventory.Count -gt 0 -and $config.SoftwareInventory -and $config.SoftwareInventory.CrossReferenceZeroDay) {
        try {
            Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.ZeroDay.psm1" -Force
            $zdForCrossRef = Get-ZeroDayMatches -Config $config.ZeroDay
            $vulnerableSoftware = @(Find-VulnerableInstalledSoftware -Inventory $softwareInventory -ZeroDayMatches $zdForCrossRef)
            if ($vulnerableSoftware.Count -gt 0) {
                Write-DiscoveryLog "Software inventory: $($vulnerableSoftware.Count) zero-day exposure hit(s) found."
            }
        } catch {
            Write-DiscoveryLog "ERROR zero-day cross-reference: $_" -Level ERROR
        }
    }

    if ($config.SoftwareInventory -and $config.SoftwareInventory.ReportOutputPath) {
        $swReportDir = Split-Path -Path $config.SoftwareInventory.ReportOutputPath -Parent
        if (-not (Test-Path $swReportDir)) { New-Item -ItemType Directory -Path $swReportDir -Force | Out-Null }
        Format-SoftwareInventoryReport -Inventory $softwareInventory -VulnerableHits $vulnerableSoftware -ScanTime (Get-Date) |
            Set-Content -Path $config.SoftwareInventory.ReportOutputPath -Encoding UTF8
    }
}

$outDir   = Split-Path -Path $config.LogPath -Parent
$jsonPath = Join-Path $outDir 'asset-inventory.json'

$priorAssets = @()
if (-not $Fresh -and (Test-Path $jsonPath)) {
    $priorAssets = @(Get-Content -Raw -Path $jsonPath | ConvertFrom-Json)
    Write-DiscoveryLog "Merging with existing inventory at $jsonPath ($($priorAssets.Count) prior asset(s))"
}

# Consolidate: prior scans first, then this run's results overwrite any matching host
# (by short name) so re-scanning a host refreshes its data, while hosts from earlier
# batches that weren't touched this run are kept - including their last-known LastSeen
# and Software, if this run didn't have the chance to refresh those itself (e.g. no WinRM
# reachability this pass, or -SkipSoftwareInventory).
$byKey = @{}
foreach ($p in $priorAssets) { $byKey[(($p.Name -split '\.')[0]).ToLower()] = $p }
foreach ($n in $newInventory) {
    $key = (($n.Name -split '\.')[0]).ToLower()
    if ($byKey.ContainsKey($key)) {
        $prior = $byKey[$key]
        if (-not $n.PSObject.Properties['LastSeen'] -or -not $n.LastSeen) {
            if ($prior.PSObject.Properties['LastSeen'] -and $prior.LastSeen) {
                $n | Add-Member -NotePropertyName LastSeen -NotePropertyValue $prior.LastSeen -Force
            }
        }
        if (-not $n.PSObject.Properties['Software'] -or -not $n.Software) {
            if ($prior.PSObject.Properties['Software'] -and $prior.Software) {
                $n | Add-Member -NotePropertyName Software -NotePropertyValue $prior.Software -Force
            }
        }
    }
    $byKey[$key] = $n
}
$inventory = @($byKey.Values | Sort-Object AssetType, Name)

$export = Export-AssetInventory -Inventory $inventory -OutputDir $outDir

# Merge the software-inventory section into the shared dashboard snapshot, preserving
# every other section (Anomalies/Compliance/Certificates/ZeroDay) exactly as Run-AnomalyScan
# leaves them - discovery only owns the SoftwareInventory/VulnerableSoftware keys.
try {
    $snapshotPath = if ($config.Dashboard -and $config.Dashboard.SnapshotPath) { $config.Dashboard.SnapshotPath } else { "$PSScriptRoot\State\latest-scan.json" }
    $snapDir = Split-Path -Path $snapshotPath -Parent
    if (-not (Test-Path $snapDir)) { New-Item -ItemType Directory -Path $snapDir -Force | Out-Null }

    $prev = $null
    if (Test-Path $snapshotPath) {
        try { $prev = Get-Content -Path $snapshotPath -Raw | ConvertFrom-Json } catch { $prev = $null }
    }
    $prevFresh = if ($prev -and $prev.Freshness) { $prev.Freshness } else { [pscustomobject]@{} }
    $nowIso = (Get-Date).ToString('o')
    $ranSoftware = -not $SkipSoftwareInventory

    $snapshot = [ordered]@{
        ScanTime             = if ($prev) { $prev.ScanTime } else { $nowIso }
        Anomalies            = if ($prev) { @($prev.Anomalies) } else { @() }
        ComplianceGaps       = if ($prev) { @($prev.ComplianceGaps) } else { @() }
        ComplianceSummary    = if ($prev) { $prev.ComplianceSummary } else { $null }
        ExpiringCertificates = if ($prev) { @($prev.ExpiringCertificates) } else { @() }
        ZeroDays             = if ($prev) { @($prev.ZeroDays) } else { @() }
        SoftwareInventory    = if ($ranSoftware) { @($softwareInventory) } elseif ($prev) { @($prev.SoftwareInventory) } else { @() }
        VulnerableSoftware   = if ($ranSoftware) { @($vulnerableSoftware) } elseif ($prev) { @($prev.VulnerableSoftware) } else { @() }
        Freshness            = [ordered]@{
            Anomalies         = $prevFresh.Anomalies
            Compliance        = $prevFresh.Compliance
            Certificates      = $prevFresh.Certificates
            ZeroDay           = $prevFresh.ZeroDay
            SoftwareInventory = if ($ranSoftware) { $nowIso } else { $prevFresh.SoftwareInventory }
        }
    }
    $snapshot | ConvertTo-Json -Depth 8 | Set-Content -Path $snapshotPath -Encoding UTF8
} catch {
    Write-DiscoveryLog "ERROR dashboard snapshot update: $_" -Level ERROR
}

if ($JsonOutput) {
    @{
        ScanTime  = (Get-Date).ToString('o')
        Count     = $inventory.Count
        Inventory = $inventory
    } | ConvertTo-Json -Depth 6
    return
}

Write-Host "`nThis run found $($newInventory.Count) asset(s); consolidated inventory now has $($inventory.Count) asset(s) total:`n"
$inventory | Group-Object AssetType | ForEach-Object {
    Write-Host ("  {0,-18} {1}" -f $_.Name, $_.Count)
}
Write-Host "`nInventory written to:"
Write-Host "  JSON:    $($export.Json)"
Write-Host "  CSV:     $($export.Csv)"
Write-Host "  Snippet: $($export.Psd1Snippet)  (paste into settings.psd1 Assets)"

if (-not $SkipSoftwareInventory) {
    $swHostCount = @($softwareInventory | Select-Object -ExpandProperty ComputerName -Unique).Count
    Write-Host "`nSoftware inventory: $($softwareInventory.Count) record(s) across $swHostCount host(s); $($vulnerableSoftware.Count) zero-day exposure hit(s)."
}

return $inventory

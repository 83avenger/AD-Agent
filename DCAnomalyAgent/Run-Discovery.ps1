#Requires -Version 5.1
<#
.SYNOPSIS
    Discovers assets from Active Directory and/or a network scan, classifies them
    by OS/role, and writes an inventory (JSON + CSV + a ready-to-paste settings
    Assets snippet).

.PARAMETER FromAD
    Enumerate domain-joined computers from Active Directory.

.PARAMETER Cidr
    One or more CIDR ranges to network-scan (e.g. '10.0.0.0/24','10.0.1.0/24').
    Picks up non-domain and non-Windows (Linux/appliance) hosts too.

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
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\Config\settings.psd1",
    [switch]$FromAD,
    [string[]]$Cidr,
    [int]$TimeoutMs = 700,
    [switch]$JsonOutput,
    [switch]$Fresh,
    [switch]$SkipCategorize
)

$ErrorActionPreference = 'Stop'
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

# Fall back to configured Discovery settings if no switches passed
if (-not $FromAD -and -not $Cidr) {
    if ($config.Discovery) {
        $FromAD = [bool]$config.Discovery.FromAD
        $Cidr   = $config.Discovery.Subnets
    }
}

$adAssets  = @()
$netAssets = @()

if ($FromAD) {
    Write-Verbose "Discovering from Active Directory..."
    $adAssets = @(Get-ADAsset -EnabledOnly)
}

if ($Cidr) {
    Write-Verbose "Scanning network ranges: $($Cidr -join ', ')"
    $netAssets = @(Get-NetworkAsset -Cidr $Cidr -TimeoutMs $TimeoutMs)
}

$newInventory = @(Merge-AssetInventory -AdAssets $adAssets -NetworkAssets $netAssets)

# Categorize every Windows asset into Desktop / Laptop / Server / Domain Controller.
# DomainController/MemberServer resolve without touching the host; Workstation/Windows
# need one extra WinRM call (Win32_SystemEnclosure) to tell Desktop from Laptop, so it's
# only attempted where WinRM was seen open during the scan (or the host came from AD,
# which doesn't record OpenPorts and is worth trying regardless).
if (-not $SkipCategorize) {
    foreach ($asset in $newInventory) {
        if ($asset.AssetType -notin @('DomainController', 'MemberServer', 'Workstation', 'Windows')) { continue }
        $hasOpenPorts = $null -ne $asset.PSObject.Properties['OpenPorts']
        if ($hasOpenPorts -and $asset.OpenPorts -notmatch 'WinRM') { continue }  # can't probe without WinRM
        try {
            $asset.AssetType = Get-DeviceCategory -ComputerName $asset.Name -AssetType $asset.AssetType
        } catch {
            # leave the coarser label on failure (WinRM unreachable, no gMSA access yet, etc.)
        }
    }
}

$outDir   = Split-Path -Path $config.LogPath -Parent
$jsonPath = Join-Path $outDir 'asset-inventory.json'

$priorAssets = @()
if (-not $Fresh -and (Test-Path $jsonPath)) {
    Write-Verbose "Merging with existing inventory at $jsonPath"
    $priorAssets = @(Get-Content -Raw -Path $jsonPath | ConvertFrom-Json)
}

# Consolidate: prior scans first, then this run's results overwrite any
# matching host (by short name) so re-scanning a host refreshes its data
# while hosts from earlier batches that weren't touched this run are kept.
$byKey = @{}
foreach ($p in $priorAssets) { $byKey[(($p.Name -split '\.')[0]).ToLower()] = $p }
foreach ($n in $newInventory) { $byKey[(($n.Name -split '\.')[0]).ToLower()] = $n }
$inventory = @($byKey.Values | Sort-Object AssetType, Name)

$export = Export-AssetInventory -Inventory $inventory -OutputDir $outDir

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

return $inventory

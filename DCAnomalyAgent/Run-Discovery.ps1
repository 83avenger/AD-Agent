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

.EXAMPLE
    .\Run-Discovery.ps1 -FromAD
.EXAMPLE
    .\Run-Discovery.ps1 -Cidr '10.0.0.0/24','10.0.1.0/24'
.EXAMPLE
    .\Run-Discovery.ps1 -FromAD -Cidr '10.0.0.0/24'
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\Config\settings.psd1",
    [switch]$FromAD,
    [string[]]$Cidr,
    [int]$TimeoutMs = 700,
    [switch]$JsonOutput
)

$ErrorActionPreference = 'Stop'
Import-Module "$PSScriptRoot\Modules\DCAnomalyAgent.Discovery.psm1" -Force

$config = Import-PowerShellDataFile -Path $ConfigPath

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

$inventory = @(Merge-AssetInventory -AdAssets $adAssets -NetworkAssets $netAssets)

$outDir = Split-Path -Path $config.LogPath -Parent
$export = Export-AssetInventory -Inventory $inventory -OutputDir $outDir

if ($JsonOutput) {
    @{
        ScanTime  = (Get-Date).ToString('o')
        Count     = $inventory.Count
        Inventory = $inventory
    } | ConvertTo-Json -Depth 6
    return
}

Write-Host "`nDiscovered $($inventory.Count) asset(s):`n"
$inventory | Group-Object AssetType | ForEach-Object {
    Write-Host ("  {0,-18} {1}" -f $_.Name, $_.Count)
}
Write-Host "`nInventory written to:"
Write-Host "  JSON:    $($export.Json)"
Write-Host "  CSV:     $($export.Csv)"
Write-Host "  Snippet: $($export.Psd1Snippet)  (paste into settings.psd1 Assets)"

return $inventory

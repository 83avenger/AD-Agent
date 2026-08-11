#Requires -Version 5.1
<#
.SYNOPSIS
    Reports which optional integrations (SNMP, vendor warranty APIs, MDM, Cloudflare
    Zero Trust) are configured in settings.psd1, without needing any of them to
    actually work yet. Used by the web UI's Integrations page.

.PARAMETER JsonOutput
    Emit the status as JSON on stdout (used by the web UI).
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\Config\settings.psd1",
    [switch]$JsonOutput
)

$ErrorActionPreference = 'Stop'

function Import-AgentConfig {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -Path $Path).Path
    $dir  = Split-Path -Parent $resolved
    $text = (Get-Content -Raw -Path $resolved).Replace('$PSScriptRoot', $dir)
    return (& ([scriptblock]::Create($text)))
}

function Test-NonEmpty($value) { -not [string]::IsNullOrWhiteSpace("$value") }

$config = Import-AgentConfig -Path $ConfigPath
$i = $config.Integrations

$snmp = $i.Snmp
$snmpConfigured = if ($snmp.Version -eq 'v3') {
    (Test-NonEmpty $snmp.V3.Username) -and (Test-NonEmpty $snmp.V3.AuthPassword)
} else {
    Test-NonEmpty $snmp.Community
}

$vw = $i.VendorWarranty
$vwStatus = [ordered]@{
    Dell   = (Test-NonEmpty $vw.Dell.ApiKey) -and (Test-NonEmpty $vw.Dell.ApiSecret)
    Hp     = Test-NonEmpty $vw.Hp.ApiKey
    Lenovo = Test-NonEmpty $vw.Lenovo.ApiKey
}

$mdm = $i.Mdm
$mdmConfigured = switch ($mdm.Provider) {
    'Intune'            { (Test-NonEmpty $mdm.Intune.TenantId) -and (Test-NonEmpty $mdm.Intune.ClientId) -and (Test-NonEmpty $mdm.Intune.ClientSecret) }
    'Jamf'              { (Test-NonEmpty $mdm.Jamf.Url) -and (Test-NonEmpty $mdm.Jamf.ClientId) -and (Test-NonEmpty $mdm.Jamf.ClientSecret) }
    'AndroidEnterprise' { (Test-NonEmpty $mdm.AndroidEnterprise.EnterpriseId) -and (Test-NonEmpty $mdm.AndroidEnterprise.ServiceAccountKeyPath) }
    default             { $false }
}

$cf = $i.CloudflareZeroTrust
$cfConfigured = (Test-NonEmpty $cf.ApiToken) -and (Test-NonEmpty $cf.AccountId)

$status = [ordered]@{
    GeneratedAt = (Get-Date).ToString('o')
    Snmp = [ordered]@{
        Enabled     = [bool]$snmp.Enabled
        Configured  = $snmpConfigured
        Version     = $snmp.Version
    }
    VendorWarranty = [ordered]@{
        Enabled     = [bool]$vw.Enabled
        Configured  = ($vwStatus.Values -contains $true)
        ByVendor    = $vwStatus
        AgeAlertYears = $vw.AgeAlertYears
    }
    Mdm = [ordered]@{
        Enabled     = [bool]$mdm.Enabled
        Configured  = $mdmConfigured
        Provider    = $mdm.Provider
    }
    CloudflareZeroTrust = [ordered]@{
        Enabled     = [bool]$cf.Enabled
        Configured  = $cfConfigured
    }
}

$outDir = Split-Path -Path $config.LogPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$statusPath = Join-Path $outDir 'integrations-status.json'
$status | ConvertTo-Json -Depth 6 | Set-Content -Path $statusPath -Encoding UTF8

if ($JsonOutput) {
    $status | ConvertTo-Json -Depth 6
    return
}

Write-Host "Integration status written to $statusPath"
$status | ConvertTo-Json -Depth 6 | Write-Host

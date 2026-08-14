#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the netscan accelerator binary and drops it where
    DCAnomalyAgent.Discovery.psm1 (Invoke-NetscanBinary) looks for it.

.DESCRIPTION
    Go itself isn't required at runtime - only to (re)build this binary after
    pulling source changes. If Go isn't installed on the server, Get-NetworkAsset
    just keeps using its built-in PowerShell scanner; nothing breaks.

.EXAMPLE
    .\build.ps1
#>
[CmdletBinding()]
param()

$go = Get-Command go -ErrorAction SilentlyContinue
if (-not $go) {
    throw "Go toolchain not found on PATH. Install it from https://go.dev/dl/ (or build netscan on another machine and copy the resulting netscan.exe into DCAnomalyAgent\bin\), then re-run this script."
}

$binDir = Join-Path $PSScriptRoot '..\..\DCAnomalyAgent\bin'
if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }

$outPath = Join-Path $binDir 'netscan.exe'
Push-Location $PSScriptRoot
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    & go build -o $outPath .
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
    Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
}

Write-Host "Built $outPath"
Write-Host "Get-NetworkAsset will use it automatically on the next Discovery run."

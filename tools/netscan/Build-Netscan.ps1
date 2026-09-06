#Requires -Version 5.1
<#
.SYNOPSIS
    Builds netscan.exe on this server and drops it where Run-Discovery.ps1 looks for it.

.DESCRIPTION
    netscan is an optional accelerator for the discovery port scan (see main.go). It is
    not a dependency: Run-Discovery.ps1 falls back to the PowerShell scanner when the
    binary isn't present, which is why this is a separate, explicit build step rather
    than something the installer does silently.

    Why bother: PowerShell 5.1 scans hosts one at a time. netscan scans them
    concurrently in one process, so a /24 that takes minutes in PowerShell finishes in
    seconds - and it needs no Go runtime on the machines being scanned, only on the one
    doing the building.

.PARAMETER GoExe
    Path to go.exe. Found on PATH by default.

.PARAMETER OutputPath
    Where to write netscan.exe. Defaults to DCAnomalyAgent\bin\netscan.exe - the ONLY
    path Invoke-NetscanBinary looks in. Building it next to main.go instead would leave
    discovery silently using the slow PowerShell scanner.

.EXAMPLE
    .\Build-Netscan.ps1
    Builds with the Go toolchain on PATH.

.EXAMPLE
    .\Build-Netscan.ps1 -GoExe 'C:\Program Files\Go\bin\go.exe'
    Builds with an explicitly-located Go, for a server where Go isn't on the system PATH.
#>
[CmdletBinding()]
param(
    [string]$GoExe,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$sourceDir = $PSScriptRoot
if (-not $OutputPath) {
    # Must match Invoke-NetscanBinary in DCAnomalyAgent.Discovery.psm1, which resolves
    # "$PSScriptRoot\..\bin\netscan.exe" from the Modules folder.
    $binDir = Join-Path (Split-Path -Parent (Split-Path -Parent $sourceDir)) 'DCAnomalyAgent\bin'
    if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Path $binDir -Force | Out-Null }
    $OutputPath = Join-Path $binDir 'netscan.exe'
}

if (-not $GoExe) {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw @"
Go is not installed or not on PATH.

Install it once on this server (nothing is needed on the hosts being scanned):
  winget install --id GoLang.Go --silent
or download the MSI from https://go.dev/dl/ and install it, then open a NEW PowerShell
window so PATH is refreshed. Then re-run this script.

If Go is installed but not on PATH, pass it explicitly:
  .\Build-Netscan.ps1 -GoExe 'C:\Program Files\Go\bin\go.exe'

Building is entirely optional - discovery works without netscan.exe, just slower.
"@
    }
    $GoExe = $cmd.Source
}

if (-not (Test-Path (Join-Path $sourceDir 'main.go'))) {
    throw "main.go not found in $sourceDir - run this script from the repo's tools\netscan folder."
}

Write-Host "Go:      $GoExe"
Write-Host "Source:  $sourceDir"
Write-Host "Output:  $OutputPath"
Write-Host ''

Push-Location $sourceDir
try {
    if (-not (Test-Path (Join-Path $sourceDir 'go.mod'))) {
        Write-Host 'Initialising go.mod...'
        & $GoExe mod init netscan 2>&1 | Write-Host
    }
    Write-Host 'Building...'
    # No external dependencies, so this needs no network access - useful on a jump
    # server whose egress is locked down.
    $env:CGO_ENABLED = '0'
    & $GoExe build -o $OutputPath .
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
}

if (-not (Test-Path $OutputPath)) { throw "Build reported success but $OutputPath does not exist." }

Write-Host ''
Write-Host "Built: $OutputPath ($([math]::Round((Get-Item $OutputPath).Length / 1MB, 1)) MB)" -ForegroundColor Green

# Prove it actually runs before declaring victory - a binary that builds but won't
# execute (blocked by AppLocker/WDAC, or an EDR quarantine) is worse than no binary,
# because discovery would fall back silently and you would never know why it's slow.
Write-Host ''
Write-Host 'Smoke test (scanning 127.0.0.1)...'
try {
    $out = & $OutputPath -cidr '127.0.0.1' -timeout-ms 300 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netscan.exe exited with code $LASTEXITCODE : $out" }
    $null = $out | ConvertFrom-Json
    Write-Host 'Smoke test passed - netscan.exe runs and emits valid JSON.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Discovery will now use it automatically. Nothing else to configure.'
} catch {
    Write-Warning @"
netscan.exe was built but did not run successfully: $_

If this is AppLocker/WDAC or your EDR (CrowdStrike) blocking an unsigned binary from a
user-writable path, either get the path allow-listed or leave the binary out - discovery
falls back to the PowerShell scanner on its own, so nothing breaks either way.
"@
}

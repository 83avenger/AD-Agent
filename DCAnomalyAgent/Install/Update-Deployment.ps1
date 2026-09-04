#Requires -Version 5.1
<#
.SYNOPSIS
    Safely replaces the entire AD-Agent code tree while preserving live data and
    configuration.

.DESCRIPTION
    Wholesale-replacing the deployment directory is the cleanest way to get a
    server current - especially after code has drifted or ended up in two places -
    but done naively it destroys everything the repository does not contain:

      State\*.db          the accumulated asset inventory (assets.db), including
                          first-seen history and endpoint check-ins
      State\*.json        dashboard snapshot, KEV cache, and the UEBA rolling
                          baseline - losing that resets anomaly detection to
                          cold-start and degrades it until it rebuilds
      State\*.log         scan, discovery, watchdog, audit and responder logs
      Config\             settings.psd1 holds YOUR domain controllers, subnets,
                          scan ports, webhook and certificate thumbprint. The
                          repository copy has CONTOSO placeholders.
                          integration-secrets.json holds saved API keys and is
                          gitignored - it exists nowhere else.
      bin\                netscan.exe, if built
      WebApp\reports\     generated PDF/CSV reports
      WebApp\.venv\       the Python virtual environment, if used

    This script takes a full backup, replaces the code, restores those paths, and
    then reports which configuration files changed in the new version so you can
    merge them deliberately rather than having them silently overwritten.

    Run it with -WhatIf first.

.PARAMETER SourcePath
    A fresh, current copy of the repository (clone or extracted archive).
.PARAMETER TargetPath
    The live deployment to replace. This is the directory your Scheduled Tasks
    actually run from - confirm with:
        (Get-ScheduledTask -TaskName 'DCAnomalyAgent-Scan').Actions.Arguments
.PARAMETER BackupRoot
    Where the pre-change backup is written. Defaults beside the target.
.PARAMETER WebUITaskName
    Web UI Scheduled Task, stopped during the replace and restarted afterwards.
.PARAMETER SkipBackup
    Skip the full backup. Not recommended; the backup is the only undo.

.EXAMPLE
    .\Update-Deployment.ps1 -SourcePath C:\AD-Agent -TargetPath C:\Apps\AD-Agent -WhatIf

.EXAMPLE
    .\Update-Deployment.ps1 -SourcePath C:\AD-Agent -TargetPath C:\Apps\AD-Agent
#>
[CmdletBinding(PositionalBinding = $false, SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$TargetPath,
    [string]$BackupRoot,
    [string]$WebUITaskName = 'AD-Agent-WebUI',
    [switch]$SkipBackup
)

$ErrorActionPreference = 'Stop'

# Paths carried across from the live deployment. Config is preserved WHOLESALE and
# never overwritten - a merge you make knowingly is far cheaper than discovering
# next week that your DC list reverted to placeholders.
$PreservePaths = @(
    'DCAnomalyAgent\State',
    'DCAnomalyAgent\Config',
    'DCAnomalyAgent\bin',
    'WebApp\reports',
    'WebApp\.venv'
)

function Write-Step { param([string]$m) Write-Host "`n== $m" -ForegroundColor Cyan }

if (-not (Test-Path $SourcePath)) { throw "SourcePath '$SourcePath' does not exist." }
if (-not (Test-Path $TargetPath)) { throw "TargetPath '$TargetPath' does not exist." }
if ((Resolve-Path $SourcePath).Path -eq (Resolve-Path $TargetPath).Path) {
    throw "SourcePath and TargetPath are the same directory."
}
if (-not (Test-Path (Join-Path $SourcePath 'DCAnomalyAgent'))) {
    throw "'$SourcePath' doesn't look like an AD-Agent tree (no DCAnomalyAgent folder)."
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $BackupRoot) { $BackupRoot = "$($TargetPath.TrimEnd('\'))-backup-$stamp" }
$preserveStage = Join-Path $env:TEMP "ad-agent-preserve-$stamp"

Write-Host "Source : $SourcePath"
Write-Host "Target : $TargetPath"
Write-Host "Backup : $(if ($SkipBackup) { '(skipped)' } else { $BackupRoot })"

# ---------------------------------------------------------------------------
Write-Step "1/7  Stopping the web UI"
$task = Get-ScheduledTask -TaskName $WebUITaskName -ErrorAction SilentlyContinue
if ($task) {
    if ($PSCmdlet.ShouldProcess($WebUITaskName, 'Stop scheduled task')) {
        Stop-ScheduledTask -TaskName $WebUITaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Write-Host "   stopped (files unlock)"
    }
} else {
    Write-Warning "   task '$WebUITaskName' not found - if the web UI runs another way, stop it now."
}

# ---------------------------------------------------------------------------
Write-Step "2/7  Full backup"
if ($SkipBackup) {
    Write-Warning "   -SkipBackup set. There is no undo if this goes wrong."
} elseif ($PSCmdlet.ShouldProcess($TargetPath, "Back up to $BackupRoot")) {
    robocopy $TargetPath $BackupRoot /E /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Backup failed (robocopy exit $LASTEXITCODE). Stopping before any destructive step." }
    Write-Host "   backed up to $BackupRoot"
}

# ---------------------------------------------------------------------------
Write-Step "3/7  Staging data and config to preserve"
$staged = @()
foreach ($rel in $PreservePaths) {
    $full = Join-Path $TargetPath $rel
    if (-not (Test-Path $full)) { Write-Host "   - $rel (not present, skipping)"; continue }
    $dest = Join-Path $preserveStage $rel
    if ($PSCmdlet.ShouldProcess($rel, 'Stage for preservation')) {
        New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
        robocopy $full $dest /E /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "Failed to stage '$rel' (robocopy exit $LASTEXITCODE). Stopping - nothing has been deleted yet." }
    }
    $staged += $rel
    Write-Host "   + $rel"
}

# ---------------------------------------------------------------------------
Write-Step "4/7  Replacing the code"
if ($PSCmdlet.ShouldProcess($TargetPath, 'Replace all code from source')) {
    # /MIR mirrors the source, removing files the new version no longer has - the
    # point of a full replace. Everything worth keeping is already staged in step 3;
    # .git is excluded so the target's own repo metadata (if any) isn't clobbered
    # by the source's.
    robocopy $SourcePath $TargetPath /MIR /R:1 /W:1 /NFL /NDL /NJH /NJS /XD '.git' | Out-Null
    if ($LASTEXITCODE -ge 8) {
        Write-Error "Replace failed (robocopy exit $LASTEXITCODE)."
        Write-Host "RESTORE FROM: $BackupRoot" -ForegroundColor Yellow
        throw "Aborted during replace."
    }
    Write-Host "   code replaced"
}

# ---------------------------------------------------------------------------
Write-Step "5/7  Restoring preserved data and config"
foreach ($rel in $staged) {
    $src = Join-Path $preserveStage $rel
    $dst = Join-Path $TargetPath $rel
    if ($PSCmdlet.ShouldProcess($rel, 'Restore')) {
        New-Item -ItemType Directory -Path $dst -Force | Out-Null
        robocopy $src $dst /E /R:1 /W:1 /NFL /NDL /NJH /NJS | Out-Null
        if ($LASTEXITCODE -ge 8) { Write-Warning "   restore of '$rel' reported exit $LASTEXITCODE - check it manually against $BackupRoot" }
    }
    Write-Host "   + $rel"
}

# ---------------------------------------------------------------------------
Write-Step "6/7  Configuration changes to review"
# Config was preserved wholesale, so any new settings in this release are NOT
# applied. Report the differences rather than deciding for the operator.
$srcConfig = Join-Path $SourcePath 'DCAnomalyAgent\Config'
$liveConfig = Join-Path $TargetPath 'DCAnomalyAgent\Config'
$diffs = @()
if (Test-Path $srcConfig) {
    foreach ($f in Get-ChildItem $srcConfig -File) {
        $live = Join-Path $liveConfig $f.Name
        if (-not (Test-Path $live)) {
            $diffs += "NEW  $($f.Name) - present in this release, not in your config"
        } else {
            $a = (Get-FileHash $f.FullName -Algorithm SHA256).Hash
            $b = (Get-FileHash $live      -Algorithm SHA256).Hash
            if ($a -ne $b) { $diffs += "DIFF $($f.Name) - your copy kept; release version differs" }
        }
    }
}
if ($diffs) {
    Write-Warning "   Your configuration was preserved, so these were NOT applied:"
    $diffs | ForEach-Object { Write-Host "     $_" -ForegroundColor Yellow }
    Write-Host "   Compare against: $srcConfig"
    Write-Host "   (A NEW file usually just needs copying across; a DIFF needs a manual merge.)"
} else {
    Write-Host "   no configuration differences"
}

# ---------------------------------------------------------------------------
Write-Step "7/7  Restarting and verifying"
if ($task -and $PSCmdlet.ShouldProcess($WebUITaskName, 'Start scheduled task')) {
    Start-ScheduledTask -TaskName $WebUITaskName
    Start-Sleep -Seconds 8
    try {
        $r = Invoke-WebRequest -Uri 'http://localhost:5000/healthz' -UseBasicParsing -TimeoutSec 15
        Write-Host "   /healthz responded HTTP $($r.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Warning "   /healthz did not respond: $($_.Exception.Message)"
        Write-Host "   If the web UI is bound to another port, or behind the IIS proxy, check it manually." -ForegroundColor Yellow
    }
}

Write-Host "`nDone." -ForegroundColor Green
if (-not $SkipBackup) { Write-Host "Backup retained at: $BackupRoot" }
Write-Host @"

Next:
  1. Confirm the asset inventory survived - the Assets page should show your
     existing hosts, not an empty list.
  2. Merge any configuration differences reported in step 6.
  3. Run one scan from the web UI and confirm it completes.
  4. Once satisfied, remove the old duplicate tree so updates can't land in the
     wrong place again, and re-register the watchdog from this deployment.
"@

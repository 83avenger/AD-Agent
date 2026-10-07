#Requires -Version 5.1
<#
.SYNOPSIS
    Sets (or clears) the COLLECTOR_TOKEN shared secret the push collectors use, in one safe
    step - no manual [Environment]::SetEnvironmentVariable argument juggling.

.DESCRIPTION
    Setting the token by hand is error-prone: SetEnvironmentVariable takes the NAME first,
    and pasting the token into the name slot fails with "Environment variable name cannot
    contain equal character" (base64 tokens end in '='). This helper removes that footgun -
    the variable name is a fixed literal here, so it can never be transposed with the value,
    and a generated token is lowercase hex (no '=', '+' or '/') so it is clean to copy,
    quote and place anywhere.

    The token is a SHARED SECRET: the same value must be set here (the jump server, which the
    web UI reads at startup) and handed to each collector via Install-PushCollector.ps1's
    -Token. See COVERAGE-NON-DOMAIN.md and DEPLOY-ENDPOINTS-CLOUDFLARE-SOAR.md.

.PARAMETER Token
    The token value to set. Omit it to generate a fresh 256-bit hex token.
.PARAMETER Scope
    Environment variable scope. Machine (default) so the gMSA-run web UI task sees it;
    Machine scope requires an elevated session.
.PARAMETER RestartWebUI
    After setting the token, restart the web UI Scheduled Task so the running process picks
    up the new value (a process only reads environment variables at startup).
.PARAMETER TaskName
    Web UI task to restart with -RestartWebUI. Matches Register-WebUIStartup.ps1.
.PARAMETER Clear
    Remove COLLECTOR_TOKEN instead of setting it (teardown). When the token is unset the
    web UI's /api/collector/checkin endpoint fails closed (503), rejecting all check-ins.

.EXAMPLE
    .\Set-CollectorToken.ps1 -RestartWebUI
    Generate a fresh token, set it at Machine scope, restart the UI, and print the token to
    copy to each collector.

.EXAMPLE
    .\Set-CollectorToken.ps1 -Token 'a1b2c3...'
    Set a specific (e.g. pre-shared) token value.

.EXAMPLE
    .\Set-CollectorToken.ps1 -Clear
    Remove the token (disables collector check-ins).
#>
[CmdletBinding(DefaultParameterSetName = 'Set')]
param(
    [Parameter(ParameterSetName = 'Set')][string]$Token,
    [ValidateSet('Machine', 'User', 'Process')][string]$Scope = 'Machine',
    [Parameter(ParameterSetName = 'Set')][switch]$RestartWebUI,
    [string]$TaskName = 'AD-Agent-WebUI',
    [Parameter(ParameterSetName = 'Clear')][switch]$Clear
)

$VarName = 'COLLECTOR_TOKEN'

# Machine (and User) scope writes to the registry; Machine requires elevation. Checked only
# for Machine so Process/User scope stays usable unprivileged (same conditional-elevation
# pattern as Set-WebUIFirewall.ps1 / Watch-WebUIHealth.ps1).
if ($Scope -eq 'Machine') {
    $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) {
        throw "Setting a Machine-scoped environment variable requires an elevated (Run as Administrator) PowerShell session. Re-open PowerShell as Administrator and re-run."
    }
}

if ($Clear) {
    [Environment]::SetEnvironmentVariable($VarName, $null, $Scope)
    $after = [Environment]::GetEnvironmentVariable($VarName, $Scope)
    if ([string]::IsNullOrEmpty($after)) {
        Write-Host "$VarName cleared at $Scope scope. Collector check-ins will now be rejected (503) until a token is set again."
        if ($RestartWebUI) { Write-Warning "-RestartWebUI is ignored with -Clear; restart the UI yourself if you want the change live immediately." }
    } else {
        Write-Warning "$VarName still has a value after clearing - check for another scope (it may be set at Machine AND User)."
    }
    return
}

if (-not $Token) {
    # 32 random bytes -> 64 hex chars. Hex avoids '=', '+', '/' entirely, so the value is
    # safe in the name/value slots, in shell quoting, and in the collector's -Token arg.
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $Token = -join ($bytes | ForEach-Object { '{0:x2}' -f $_ })
    Write-Host "Generated a new 256-bit token."
}

# Name is a fixed literal - the token can never land in the name argument by mistake.
[Environment]::SetEnvironmentVariable($VarName, $Token, $Scope)

$readback = [Environment]::GetEnvironmentVariable($VarName, $Scope)
if ($readback -ne $Token) {
    throw "Set $VarName but read-back did not match - the value was not stored correctly."
}

Write-Host ""
Write-Host "$VarName set at $Scope scope." -ForegroundColor Green
Write-Host "Token (shared secret - give this SAME value to each collector's -Token):"
Write-Host "  $Token"
Write-Host ""
Write-Host "A running process only reads environment variables at startup, so the web UI must"
Write-Host "restart to pick up the new value."

if ($RestartWebUI) {
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if ($task.State -eq 'Running') {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "Restarted '$TaskName' - the web UI is now running with the new token."
    } catch {
        Write-Warning "Could not restart '$TaskName' automatically: $_"
        Write-Warning "Restart it yourself: Stop-ScheduledTask -TaskName '$TaskName'; Start-ScheduledTask -TaskName '$TaskName'"
    }
} else {
    Write-Host "Restart it when ready:  Stop-ScheduledTask -TaskName '$TaskName'; Start-ScheduledTask -TaskName '$TaskName'"
}

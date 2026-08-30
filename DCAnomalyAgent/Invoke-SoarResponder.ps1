#Requires -Version 5.1
<#
.SYNOPSIS
    Executes a single SOAR response action against Active Directory.

.DESCRIPTION
    Called by WebApp/soar.py only after a human has APPROVED the action in the web
    UI. Nothing in the automation path reaches this script unattended - destructive
    actions queue for approval regardless of SOAR_MODE, by design.

    Kept deliberately small and single-purpose: one action per invocation, explicit
    parameters, no playbook logic. The orchestration lives in Python where it is
    unit-tested; this is the thin edge that actually touches AD, so the less it
    does the better.

    SAFETY BEHAVIOUR:
      * -WhatIf is supported on every action and does a full parameter/target
        resolution without mutating anything. Use it first.
      * Protected accounts (see $ProtectedIdentities) are refused outright. Locking
        yourself out of your own directory by automating a disable of a break-glass
        or service account is a real failure mode, so it is blocked here rather
        than trusted to playbook authoring.
      * Every invocation appends to State\soar-responder.log with the identity that
        ran it, the action, the target and the outcome.

    Requires the RSAT ActiveDirectory module and an account with rights to modify
    the target object. The gMSA used for scanning is deliberately read-only, so it
    CANNOT perform these actions - that is intentional. Point this at a separate,
    appropriately-scoped account if you enable destructive playbooks.

.PARAMETER Action
    disable_ad_user | disable_ad_computer | remove_from_privileged_group
.PARAMETER Identity
    sAMAccountName / DN of the target user or computer.
.PARAMETER Group
    Group name, for remove_from_privileged_group.
.PARAMETER Reason
    Free text recorded in the log and (for accounts) in the object's Description.

.EXAMPLE
    .\Invoke-SoarResponder.ps1 -Action disable_ad_user -Identity 'jdoe' -WhatIf

.EXAMPLE
    .\Invoke-SoarResponder.ps1 -Action remove_from_privileged_group -Identity 'jdoe' -Group 'Domain Admins' -Reason 'SOAR playbook'
#>
[CmdletBinding(PositionalBinding = $false, SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('disable_ad_user', 'disable_ad_computer', 'remove_from_privileged_group')]
    [string]$Action,

    [Parameter(Mandatory)][string]$Identity,
    [string]$Group,
    [string]$Reason = 'AD-Agent SOAR response',
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

if (-not $LogPath) { $LogPath = Join-Path $PSScriptRoot 'State\soar-responder.log' }

# Never automate against these, whatever a playbook says. Extend to match your
# environment's break-glass and critical service accounts BEFORE enabling any
# destructive playbook.
$ProtectedIdentities = @(
    'Administrator', 'krbtgt', 'Guest', 'DefaultAccount'
)

function Write-ResponderLog {
    param([string]$Message, [string]$Level = 'INFO')
    $who = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { 'unknown' }
    $line = "[{0}] [{1}] [{2}] {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $who, $Message
    Write-Host $line
    try {
        $dir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line
    } catch { }
}

if ($ProtectedIdentities -contains $Identity) {
    Write-ResponderLog "REFUSED $Action on protected identity '$Identity'." 'ERROR'
    throw "'$Identity' is in the protected list and will not be modified by automation. Act on it manually if genuinely required."
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-ResponderLog "ActiveDirectory module unavailable: $_" 'ERROR'
    throw "The ActiveDirectory PowerShell module is required. Install RSAT-AD-PowerShell."
}

Write-ResponderLog "Requested: $Action on '$Identity'$(if ($Group) { " (group: $Group)" }) - reason: $Reason"

switch ($Action) {

    'disable_ad_user' {
        $user = Get-ADUser -Identity $Identity -Properties Description -ErrorAction Stop
        if (-not $user.Enabled) {
            Write-ResponderLog "No-op: user '$Identity' is already disabled."
            break
        }
        if ($PSCmdlet.ShouldProcess($user.DistinguishedName, 'Disable AD user account')) {
            Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop
            $stamp = "[AD-Agent SOAR $(Get-Date -Format 'yyyy-MM-dd')] $Reason"
            try {
                Set-ADUser -Identity $user.DistinguishedName `
                    -Description (("$($user.Description) $stamp").Trim()) -ErrorAction Stop
            } catch {
                Write-ResponderLog "Disabled OK but could not stamp Description: $_" 'WARN'
            }
            Write-ResponderLog "Disabled user '$Identity' ($($user.DistinguishedName))."
        } else {
            Write-ResponderLog "WhatIf: would disable user '$Identity' ($($user.DistinguishedName))."
        }
    }

    'disable_ad_computer' {
        $name = $Identity -replace '\..*$', ''      # accept an FQDN, match on the short name
        $computer = Get-ADComputer -Identity $name -ErrorAction Stop
        if (-not $computer.Enabled) {
            Write-ResponderLog "No-op: computer '$name' is already disabled."
            break
        }
        if ($PSCmdlet.ShouldProcess($computer.DistinguishedName, 'Disable AD computer account')) {
            Disable-ADAccount -Identity $computer.DistinguishedName -ErrorAction Stop
            Write-ResponderLog "Disabled computer '$name' ($($computer.DistinguishedName))."
        } else {
            Write-ResponderLog "WhatIf: would disable computer '$name' ($($computer.DistinguishedName))."
        }
    }

    'remove_from_privileged_group' {
        if (-not $Group) { throw "remove_from_privileged_group requires -Group." }
        $groupObj = Get-ADGroup -Identity $Group -ErrorAction Stop
        $members = @(Get-ADGroupMember -Identity $groupObj -ErrorAction Stop)

        # Match on sAMAccountName or name so a playbook can pass either form.
        $target = $members | Where-Object {
            $_.SamAccountName -eq $Identity -or $_.Name -eq $Identity
        } | Select-Object -First 1

        if (-not $target) {
            Write-ResponderLog "No-op: '$Identity' is not a member of '$Group'."
            break
        }
        if ($PSCmdlet.ShouldProcess("$Identity in $Group", 'Remove from group')) {
            Remove-ADGroupMember -Identity $groupObj -Members $target -Confirm:$false -ErrorAction Stop
            Write-ResponderLog "Removed '$Identity' from '$Group'."
        } else {
            Write-ResponderLog "WhatIf: would remove '$Identity' from '$Group'."
        }
    }
}

Write-ResponderLog "Completed: $Action on '$Identity'."
exit 0

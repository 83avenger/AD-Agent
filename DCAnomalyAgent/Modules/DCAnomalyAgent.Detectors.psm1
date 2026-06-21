#Requires -Version 5.1

function Find-FailedLogonAnomalies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][array]$FailedLogonEvents,
        [Parameter(Mandatory)][int]$BurstThreshold
    )

    $anomalies = @()

    $lockouts = $FailedLogonEvents | Where-Object { $_.Id -eq 4740 }
    foreach ($lockout in $lockouts) {
        $anomalies += [pscustomobject]@{
            Type        = 'AccountLockout'
            Account     = $lockout.TargetAccount
            Detail      = "Account locked out on $($lockout.ComputerName)"
            TimeCreated = $lockout.TimeCreated
            ComputerName = $lockout.ComputerName
        }
    }

    $failures = $FailedLogonEvents | Where-Object { $_.Id -eq 4625 }

    $byAccount = $failures | Group-Object -Property TargetAccount
    foreach ($group in $byAccount) {
        if ($group.Count -ge $BurstThreshold) {
            $anomalies += [pscustomobject]@{
                Type        = 'FailedLogonBurst_Account'
                Account     = $group.Name
                Detail      = "$($group.Count) failed logons for account $($group.Name)"
                TimeCreated = ($group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                ComputerName = ($group.Group | Select-Object -First 1).ComputerName
            }
        }
    }

    $byAddress = $failures | Where-Object { $_.SourceAddress } | Group-Object -Property SourceAddress
    foreach ($group in $byAddress) {
        if ($group.Count -ge $BurstThreshold) {
            $anomalies += [pscustomobject]@{
                Type        = 'FailedLogonBurst_SourceAddress'
                Account     = $group.Group[0].SourceAddress
                Detail      = "$($group.Count) failed logons from source $($group.Name)"
                TimeCreated = ($group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
                ComputerName = ($group.Group | Select-Object -First 1).ComputerName
            }
        }
    }

    return $anomalies
}

function Find-PrivilegedGroupAnomalies {
    [CmdletBinding()]
    param([Parameter(Mandatory)][array]$GroupChangeEvents)

    $GroupChangeEvents | ForEach-Object {
        [pscustomobject]@{
            Type        = 'PrivilegedGroupMembershipChange'
            Account     = $_.MemberAccount
            Detail      = "Added to privileged group '$($_.GroupName)'"
            TimeCreated = $_.TimeCreated
            ComputerName = $_.ComputerName
        }
    }
}

function Find-NewPrivilegedAccountAnomalies {
    [CmdletBinding()]
    param([Parameter(Mandatory)][array]$NewPrivilegedAccounts)

    $NewPrivilegedAccounts | ForEach-Object {
        [pscustomobject]@{
            Type        = 'NewAccountElevatedToPrivilegedGroup'
            Account     = $_.AccountName
            Detail      = "New account added to '$($_.GroupName)' within window of creation"
            TimeCreated = $_.CreatedAt
            ComputerName = $_.ComputerName
        }
    }
}

function Find-GpoAnomalies {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$GpoResult)

    $anomalies = @()

    foreach ($change in $GpoResult.EventChanges) {
        $anomalies += [pscustomobject]@{
            Type        = 'GpoObjectModified'
            Account     = $null
            Detail      = 'Directory service change to a GPO object (Event 5136)'
            TimeCreated = $change.TimeCreated
            ComputerName = $change.ComputerName
        }
    }

    foreach ($change in $GpoResult.VersionChanges) {
        $anomalies += [pscustomobject]@{
            Type        = 'GpoVersionChanged'
            Account     = $null
            Detail      = "GPO '$($change.GpoName)' version changed from $($change.OldVersion) to $($change.NewVersion)"
            TimeCreated = Get-Date
            ComputerName = $null
        }
    }

    return $anomalies
}

Export-ModuleMember -Function Find-FailedLogonAnomalies, Find-PrivilegedGroupAnomalies, `
    Find-NewPrivilegedAccountAnomalies, Find-GpoAnomalies

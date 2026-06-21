#Requires -Version 5.1

function Get-FailedLogonEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime
    )

    $filter = @{
        LogName   = 'Security'
        Id        = 4625, 4740
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($filter)
        Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    } -ArgumentList $filter |
        Select-Object Id, TimeCreated, @{n = 'ComputerName'; e = { $ComputerName } }, Message, @{
            n = 'TargetAccount'; e = { ($_.Properties | Select-Object -Index 5).Value }
        }, @{ n = 'SourceAddress'; e = { ($_.Properties | Select-Object -Index 19).Value } }
}

function Get-SuccessfulLogonEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime
    )

    $filter = @{
        LogName   = 'Security'
        Id        = 4624
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($filter)
        Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    } -ArgumentList $filter |
        Select-Object Id, TimeCreated, @{n = 'ComputerName'; e = { $ComputerName } }, @{
            n = 'TargetAccount'; e = { ($_.Properties | Select-Object -Index 5).Value }
        }, @{ n = 'SourceAddress'; e = { ($_.Properties | Select-Object -Index 18).Value } }, @{
            n = 'LogonType'; e = { ($_.Properties | Select-Object -Index 8).Value }
        }
}

function Get-PrivilegedGroupChangeEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime,
        [Parameter(Mandatory)][string[]]$PrivilegedGroups
    )

    $filter = @{
        LogName   = 'Security'
        Id        = 4728, 4732, 4756
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($filter)
        Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    } -ArgumentList $filter |
        Select-Object Id, TimeCreated, @{n = 'ComputerName'; e = { $ComputerName } }, @{
            n = 'MemberAccount'; e = { ($_.Properties | Select-Object -Index 0).Value }
        }, @{ n = 'GroupName'; e = { ($_.Properties | Select-Object -Index 2).Value } } |
        Where-Object { $_.GroupName -in $PrivilegedGroups }
}

function Get-NewPrivilegedAccounts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime,
        [Parameter(Mandatory)][string[]]$PrivilegedGroups,
        [Parameter(Mandatory)][int]$WindowHours
    )

    $filter = @{
        LogName   = 'Security'
        Id        = 4720
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    $newAccounts = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($filter)
        Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
    } -ArgumentList $filter |
        Select-Object TimeCreated, @{
            n = 'AccountName'; e = { ($_.Properties | Select-Object -Index 0).Value }
        }

    $results = @()
    foreach ($group in $PrivilegedGroups) {
        $members = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($group)
            try { Get-ADGroupMember -Identity $group -ErrorAction Stop } catch { @() }
        } -ArgumentList $group

        foreach ($account in $newAccounts) {
            $isMember = $members | Where-Object { $_.SamAccountName -eq $account.AccountName }
            $withinWindow = ((Get-Date) - $account.TimeCreated).TotalHours -le $WindowHours
            if ($isMember -and $withinWindow) {
                $results += [pscustomobject]@{
                    ComputerName = $ComputerName
                    AccountName  = $account.AccountName
                    GroupName    = $group
                    CreatedAt    = $account.TimeCreated
                }
            }
        }
    }
    $results
}

function Get-GpoChangeEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][datetime]$StartTime,
        [Parameter(Mandatory)][datetime]$EndTime,
        [hashtable]$KnownGpoVersions = @{}
    )

    $filter = @{
        LogName   = 'Security'
        Id        = 5136
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    $eventChanges = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($filter)
        Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
            Where-Object { $_.Message -match 'CN=Policies' }
    } -ArgumentList $filter |
        Select-Object Id, TimeCreated, @{n = 'ComputerName'; e = { $ComputerName } }, Message

    $currentGpos = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        try { Get-GPO -All -ErrorAction Stop } catch { @() }
    } | Select-Object DisplayName, Id, @{n = 'Version'; e = { $_.User.DSVersion + $_.Computer.DSVersion } }

    $versionChanges = foreach ($gpo in $currentGpos) {
        $previous = $KnownGpoVersions[$gpo.Id.ToString()]
        if ($null -ne $previous -and $previous -ne $gpo.Version) {
            [pscustomobject]@{
                GpoName     = $gpo.DisplayName
                GpoId       = $gpo.Id.ToString()
                OldVersion  = $previous
                NewVersion  = $gpo.Version
            }
        }
    }

    [pscustomobject]@{
        EventChanges    = $eventChanges
        VersionChanges  = $versionChanges
        CurrentVersions = ($currentGpos | ForEach-Object {
            @{ Id = $_.Id.ToString(); Version = $_.Version }
        })
    }
}

Export-ModuleMember -Function Get-FailedLogonEvents, Get-SuccessfulLogonEvents, `
    Get-PrivilegedGroupChangeEvents, Get-NewPrivilegedAccounts, Get-GpoChangeEvents

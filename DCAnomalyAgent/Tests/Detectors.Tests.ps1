#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.Detectors.psm1" -Force
}

Describe 'Find-FailedLogonAnomalies' {
    It 'flags an account lockout' {
        $events = @([pscustomobject]@{ Id = 4740; TargetAccount = 'jdoe'; ComputerName = 'dc01'; TimeCreated = Get-Date })
        $result = Find-FailedLogonAnomalies -FailedLogonEvents $events -BurstThreshold 5
        $result.Type | Should -Contain 'AccountLockout'
    }

    It 'flags a failed logon burst for a single account at or above threshold' {
        $events = 1..5 | ForEach-Object {
            [pscustomobject]@{ Id = 4625; TargetAccount = 'jdoe'; ComputerName = 'dc01'; SourceAddress = "10.0.0.$_"; TimeCreated = Get-Date }
        }
        $result = Find-FailedLogonAnomalies -FailedLogonEvents $events -BurstThreshold 5
        $result.Type | Should -Contain 'FailedLogonBurst_Account'
    }

    It 'does not flag below threshold' {
        $events = 1..3 | ForEach-Object {
            [pscustomobject]@{ Id = 4625; TargetAccount = 'jdoe'; ComputerName = 'dc01'; SourceAddress = '10.0.0.1'; TimeCreated = Get-Date }
        }
        $result = Find-FailedLogonAnomalies -FailedLogonEvents $events -BurstThreshold 5
        $result | Should -BeNullOrEmpty
    }

    It 'flags a failed logon burst from a single source address across accounts' {
        $events = 1..5 | ForEach-Object {
            [pscustomobject]@{ Id = 4625; TargetAccount = "user$_"; ComputerName = 'dc01'; SourceAddress = '10.0.0.99'; TimeCreated = Get-Date }
        }
        $result = Find-FailedLogonAnomalies -FailedLogonEvents $events -BurstThreshold 5
        $result.Type | Should -Contain 'FailedLogonBurst_SourceAddress'
    }
}

Describe 'Find-PrivilegedGroupAnomalies' {
    It 'flags every privileged group membership change event' {
        $events = @([pscustomobject]@{ MemberAccount = 'jdoe'; GroupName = 'Domain Admins'; ComputerName = 'dc01'; TimeCreated = Get-Date })
        $result = Find-PrivilegedGroupAnomalies -GroupChangeEvents $events
        $result.Type | Should -Contain 'PrivilegedGroupMembershipChange'
    }
}

Describe 'Find-NewPrivilegedAccountAnomalies' {
    It 'flags new accounts elevated within the window' {
        $accounts = @([pscustomobject]@{ AccountName = 'newuser'; GroupName = 'Domain Admins'; ComputerName = 'dc01'; CreatedAt = Get-Date })
        $result = Find-NewPrivilegedAccountAnomalies -NewPrivilegedAccounts $accounts
        $result.Type | Should -Contain 'NewAccountElevatedToPrivilegedGroup'
    }
}

Describe 'Find-GpoAnomalies' {
    It 'flags GPO version changes' {
        $gpoResult = [pscustomobject]@{
            EventChanges   = @()
            VersionChanges = @([pscustomobject]@{ GpoName = 'Default Domain Policy'; GpoId = 'abc'; OldVersion = 1; NewVersion = 2 })
            CurrentVersions = @()
        }
        $result = Find-GpoAnomalies -GpoResult $gpoResult
        $result.Type | Should -Contain 'GpoVersionChanged'
    }

    It 'flags directory service modification events' {
        $gpoResult = [pscustomobject]@{
            EventChanges   = @([pscustomobject]@{ TimeCreated = Get-Date; ComputerName = 'dc01' })
            VersionChanges = @()
            CurrentVersions = @()
        }
        $result = Find-GpoAnomalies -GpoResult $gpoResult
        $result.Type | Should -Contain 'GpoObjectModified'
    }
}

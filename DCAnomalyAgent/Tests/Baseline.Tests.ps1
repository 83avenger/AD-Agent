#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.Baseline.psm1" -Force
}

Describe 'Update-Baseline' {
    It 'does not flag deviations during cold start (below MinObservationsBeforeFlagging)' {
        $baseline = @{}
        $events = 1..3 | ForEach-Object {
            [pscustomobject]@{ TargetAccount = 'jdoe'; TimeCreated = (Get-Date).Date.AddHours(9); SourceAddress = '10.0.0.1'; ComputerName = 'dc01' }
        }
        $result = Update-Baseline -Baseline $baseline -LogonEvents $events -MinObservationsBeforeFlagging 5
        $result | Should -BeNullOrEmpty
        $baseline['jdoe'].Observations | Should -Be 3
    }

    It 'flags an unusual logon hour once baseline is established' {
        $baseline = @{
            'jdoe' = @{ Hours = @(9); SourceHosts = @('10.0.0.1'); DomainControllers = @('dc01'); Observations = 10 }
        }
        $events = @([pscustomobject]@{ TargetAccount = 'jdoe'; TimeCreated = (Get-Date).Date.AddHours(3); SourceAddress = '10.0.0.1'; ComputerName = 'dc01' })
        $result = Update-Baseline -Baseline $baseline -LogonEvents $events -MinObservationsBeforeFlagging 5
        $result.Type | Should -Contain 'UnusualLogonHour'
    }

    It 'flags a logon from a never-before-seen source host' {
        $baseline = @{
            'jdoe' = @{ Hours = @(9); SourceHosts = @('10.0.0.1'); DomainControllers = @('dc01'); Observations = 10 }
        }
        $events = @([pscustomobject]@{ TargetAccount = 'jdoe'; TimeCreated = (Get-Date).Date.AddHours(9); SourceAddress = '10.0.0.250'; ComputerName = 'dc01' })
        $result = Update-Baseline -Baseline $baseline -LogonEvents $events -MinObservationsBeforeFlagging 5
        $result.Type | Should -Contain 'UnseenSourceHost'
    }

    It 'flags first-ever logon to a new domain controller' {
        $baseline = @{
            'jdoe' = @{ Hours = @(9); SourceHosts = @('10.0.0.1'); DomainControllers = @('dc01'); Observations = 10 }
        }
        $events = @([pscustomobject]@{ TargetAccount = 'jdoe'; TimeCreated = (Get-Date).Date.AddHours(9); SourceAddress = '10.0.0.1'; ComputerName = 'dc02' })
        $result = Update-Baseline -Baseline $baseline -LogonEvents $events -MinObservationsBeforeFlagging 5
        $result.Type | Should -Contain 'UnseenDomainController'
    }

    It 'ignores machine accounts (trailing $)' {
        $baseline = @{}
        $events = @([pscustomobject]@{ TargetAccount = 'DC01$'; TimeCreated = Get-Date; SourceAddress = '10.0.0.1'; ComputerName = 'dc01' })
        Update-Baseline -Baseline $baseline -LogonEvents $events -MinObservationsBeforeFlagging 5
        $baseline.ContainsKey('DC01$') | Should -Be $false
    }
}

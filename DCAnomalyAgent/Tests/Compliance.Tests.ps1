#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.Compliance.psm1" -Force
}

Describe 'Get-ComplianceControls' {
    It 'loads all controls from the framework file' {
        $controls = Get-ComplianceControls -FrameworkPath "$PSScriptRoot\..\Config\compliance-frameworks.psd1"
        $controls.Count | Should -BeGreaterThan 0
    }

    It 'each control has required fields' {
        $controls = Get-ComplianceControls -FrameworkPath "$PSScriptRoot\..\Config\compliance-frameworks.psd1"
        foreach ($c in $controls) {
            $c.Id         | Should -Not -BeNullOrEmpty
            $c.Title      | Should -Not -BeNullOrEmpty
            $c.Severity   | Should -BeIn @('Critical','High','Medium','Low')
            $c.Remediation| Should -Not -BeNullOrEmpty
            $c.Check      | Should -BeOfType [scriptblock]
        }
    }

    It 'filters by framework name' {
        $controls = Get-ComplianceControls -FrameworkPath "$PSScriptRoot\..\Config\compliance-frameworks.psd1" `
            -FrameworkFilter @('CIS')
        $controls | ForEach-Object { $_.Frameworks.Keys | Should -Contain 'CIS' }
    }

    It 'filters by severity' {
        $controls = Get-ComplianceControls -FrameworkPath "$PSScriptRoot\..\Config\compliance-frameworks.psd1" `
            -SeverityFilter @('Critical')
        $controls | ForEach-Object { $_.Severity | Should -Be 'Critical' }
    }
}

Describe 'Get-ComplianceControls AssetTypeFilter' {
    It 'returns only MemberServer-applicable controls from the endpoints file' {
        $controls = Get-ComplianceControls `
            -FrameworkPath "$PSScriptRoot\..\Config\compliance-endpoints.psd1" `
            -AssetTypeFilter 'MemberServer'
        $controls.Count | Should -BeGreaterThan 0
        foreach ($c in $controls) { $c.AppliesTo | Should -Contain 'MemberServer' }
    }

    It 'returns only Linux-applicable controls from the linux file' {
        $controls = Get-ComplianceControls `
            -FrameworkPath "$PSScriptRoot\..\Config\compliance-linux.psd1" `
            -AssetTypeFilter 'Linux'
        $controls.Count | Should -BeGreaterThan 0
        foreach ($c in $controls) { $c.AppliesTo | Should -Contain 'Linux' }
    }

    It 'returns Workstation-only controls (e.g. BitLocker) when filtering Workstation' {
        $controls = Get-ComplianceControls `
            -FrameworkPath "$PSScriptRoot\..\Config\compliance-endpoints.psd1" `
            -AssetTypeFilter 'Workstation'
        ($controls | Where-Object { $_.Id -eq 'EP-BL-001' }) | Should -Not -BeNullOrEmpty
    }

    It 'merges multiple framework files' {
        $controls = Get-ComplianceControls -FrameworkPath @(
            "$PSScriptRoot\..\Config\compliance-frameworks.psd1",
            "$PSScriptRoot\..\Config\compliance-endpoints.psd1"
        )
        $controls.Count | Should -BeGreaterThan 20
    }

    It 'treats controls with no AppliesTo as DomainController-only' {
        $controls = Get-ComplianceControls `
            -FrameworkPath "$PSScriptRoot\..\Config\compliance-frameworks.psd1" `
            -AssetTypeFilter 'Workstation'
        # The DC framework controls have no AppliesTo, so none should match Workstation
        $controls.Count | Should -Be 0
    }
}

Describe 'Invoke-ComplianceScan' {
    It 'tags results with the supplied AssetType' {
        $controls = @(@{
            Id = 'T'; Title = 'x'; Severity = 'Low'; Frameworks = @{ CIS = 'n/a' }
            Expected = 'y'; Remediation = 'z'
            Check = { param($t) [pscustomobject]@{ Pass = $true; Actual = 'ok' } }
        })
        $r = Invoke-ComplianceScan -Targets @('app01') -Controls $controls -AssetType 'MemberServer'
        $r[0].AssetType | Should -Be 'MemberServer'
    }

    It 'returns a result for each control-DC pair' {
        $controls = @(
            @{
                Id = 'TEST-001'; Title = 'Always Pass'; Severity = 'Low'
                Frameworks = @{ CIS = 'n/a' }; Expected = 'true'
                Remediation = 'none'
                Check = { param($dc) [pscustomobject]@{ Pass = $true; Actual = 'ok' } }
            }
            @{
                Id = 'TEST-002'; Title = 'Always Fail'; Severity = 'High'
                Frameworks = @{ CIS = 'n/a' }; Expected = 'something'
                Remediation = 'fix it'
                Check = { param($dc) [pscustomobject]@{ Pass = $false; Actual = 'bad' } }
            }
        )
        $results = Invoke-ComplianceScan -DomainControllers @('dc01','dc02') -Controls $controls
        $results.Count | Should -Be 4
    }

    It 'records errors as failing controls without throwing' {
        $controls = @(@{
            Id = 'TEST-ERR'; Title = 'Error Control'; Severity = 'Medium'
            Frameworks = @{ CIS = 'n/a' }; Expected = 'x'; Remediation = 'y'
            Check = { throw 'simulated error' }
        })
        { Invoke-ComplianceScan -DomainControllers @('dc01') -Controls $controls } | Should -Not -Throw
        $result = Invoke-ComplianceScan -DomainControllers @('dc01') -Controls $controls
        $result[0].Pass | Should -Be $false
        $result[0].Actual | Should -Match 'ERROR'
    }
}

Describe 'Get-ComplianceGaps' {
    It 'returns only failing controls' {
        $results = @(
            [pscustomobject]@{ Pass = $true;  ControlId = 'A' }
            [pscustomobject]@{ Pass = $false; ControlId = 'B' }
            [pscustomobject]@{ Pass = $false; ControlId = 'C' }
        )
        $gaps = Get-ComplianceGaps -ScanResults $results
        $gaps.Count | Should -Be 2
        $gaps.ControlId | Should -Not -Contain 'A'
    }
}

Describe 'Get-ComplianceSummary' {
    It 'computes score correctly' {
        $results = @(
            [pscustomobject]@{ Pass = $true;  ComputerName = 'dc01'; Severity = 'High' }
            [pscustomobject]@{ Pass = $true;  ComputerName = 'dc01'; Severity = 'Low'  }
            [pscustomobject]@{ Pass = $false; ComputerName = 'dc01'; Severity = 'Critical' }
            [pscustomobject]@{ Pass = $false; ComputerName = 'dc01'; Severity = 'High' }
        )
        $summary = Get-ComplianceSummary -ScanResults $results
        $summary.ScorePct     | Should -Be 50.0
        $summary.Passed       | Should -Be 2
        $summary.Failed       | Should -Be 2
        $summary.TotalControls| Should -Be 4
    }
}

Describe 'Format-ComplianceReport' {
    It 'generates a non-empty markdown string' {
        $summary = [pscustomobject]@{
            ScorePct = 75; Passed = 3; Failed = 1; TotalControls = 4
            ByDC = @([pscustomobject]@{ DC = 'dc01'; Total = 4; Passed = 3; Failed = 1; ScorePct = 75 })
            GapsBySeverity = @([pscustomobject]@{ Severity = 'High'; GapCount = 1 })
        }
        $gaps = @([pscustomobject]@{
            ControlId = 'PP-001'; Title = 'Test'; Severity = 'High'
            Frameworks = @{ CIS = 'CIS-L1 1.1.1' }
            ComputerName = 'dc01'; Actual = '8'; Expected = '>= 14'
            Remediation = 'Set minimum password length.'
        })
        $report = Format-ComplianceReport -Summary $summary -Gaps $gaps
        $report | Should -Match '# DC Compliance Report'
        $report | Should -Match 'PP-001'
        $report | Should -Match 'Remediation'
    }
}

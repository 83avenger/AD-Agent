#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.SoftwareInventory.psm1" -Force
}

Describe 'Get-DeviceCategory' {
    It 'passes DomainController straight through as "Domain Controller"' {
        Get-DeviceCategory -ComputerName 'dc01' -AssetType 'DomainController' | Should -Be 'Domain Controller'
    }

    It 'passes MemberServer straight through as "Server"' {
        Get-DeviceCategory -ComputerName 'sql01' -AssetType 'MemberServer' | Should -Be 'Server'
    }

    It 'passes an unrecognized asset type straight through unchanged' {
        Get-DeviceCategory -ComputerName 'lin01' -AssetType 'Linux' | Should -Be 'Linux'
    }

    It 'falls back to "Workstation" for a Workstation host when WinRM/chassis lookup fails' {
        # No live host to query -> Invoke-Command throws -> caught -> generic fallback
        Get-DeviceCategory -ComputerName 'unreachable-host.invalid' -AssetType 'Workstation' | Should -Be 'Workstation'
    }
}

Describe 'Find-VulnerableInstalledSoftware' {
    BeforeEach {
        $script:inv = @(
            [pscustomobject]@{ ComputerName = 'ws01'; Category = 'Laptop'; Name = 'Adobe Acrobat Reader DC'; Version = '23.001'; Publisher = 'Adobe'; InstallDate = ''; Architecture = '64-bit'; Error = $null }
            [pscustomobject]@{ ComputerName = 'ws02'; Category = 'Desktop'; Name = '7-Zip 19.00'; Version = '19.00'; Publisher = 'Igor Pavlov'; InstallDate = ''; Architecture = '64-bit'; Error = $null }
        )
        $script:zd = @(
            [pscustomobject]@{ CveId = 'CVE-2024-1111'; Product = 'Adobe Acrobat Reader'; VulnerabilityName = 'RCE'; KnownRansomwareCampaignUse = 'Unknown'; DueDate = '2026-01-01' }
        )
    }

    It 'matches installed software whose name contains the watchlist product string' {
        $hits = Find-VulnerableInstalledSoftware -Inventory $script:inv -ZeroDayMatches $script:zd
        $hits.Count | Should -Be 1
        $hits[0].ComputerName | Should -Be 'ws01'
        $hits[0].CveId | Should -Be 'CVE-2024-1111'
    }

    It 'returns an empty array (not null/throw) when the inventory is empty' {
        { Find-VulnerableInstalledSoftware -Inventory @() -ZeroDayMatches $script:zd } | Should -Not -Throw
        @(Find-VulnerableInstalledSoftware -Inventory @() -ZeroDayMatches $script:zd).Count | Should -Be 0
    }

    It 'returns an empty array (not null/throw) when there are no zero-day matches' {
        { Find-VulnerableInstalledSoftware -Inventory $script:inv -ZeroDayMatches @() } | Should -Not -Throw
        @(Find-VulnerableInstalledSoftware -Inventory $script:inv -ZeroDayMatches @()).Count | Should -Be 0
    }

    It 'does not match unrelated software' {
        $hits = Find-VulnerableInstalledSoftware -Inventory $script:inv -ZeroDayMatches $script:zd
        ($hits.ComputerName) | Should -Not -Contain 'ws02'
    }
}

Describe 'Format-SoftwareInventoryReport' {
    It 'renders category counts, top products, and a summary line' {
        $inv = @(
            [pscustomobject]@{ ComputerName = 'ws01'; Category = 'Laptop'; Name = 'Chrome'; Version = '120'; Publisher = 'Google'; InstallDate = ''; Architecture = '64-bit'; Error = $null }
            [pscustomobject]@{ ComputerName = 'ws02'; Category = 'Desktop'; Name = 'Chrome'; Version = '120'; Publisher = 'Google'; InstallDate = ''; Architecture = '64-bit'; Error = $null }
        )
        $report = Format-SoftwareInventoryReport -Inventory $inv -VulnerableHits @()
        $report | Should -Match '# Software Inventory Report'
        $report | Should -Match 'Laptop'
        $report | Should -Match 'Desktop'
        $report | Should -Match 'Chrome'
    }

    It 'lists collection errors separately without breaking the report' {
        $inv = @(
            [pscustomobject]@{ ComputerName = 'ws03'; Category = 'Server'; Name = $null; Version = $null; Publisher = $null; InstallDate = $null; Architecture = $null; Error = 'WinRM failed' }
        )
        $report = Format-SoftwareInventoryReport -Inventory $inv -VulnerableHits @()
        $report | Should -Match 'Collection issues'
        $report | Should -Match 'WinRM failed'
    }

    It 'includes a zero-day exposure section only when hits are present' {
        $hit = [pscustomobject]@{ ComputerName = 'ws01'; Category = 'Laptop'; SoftwareName = 'Adobe Acrobat Reader DC'; SoftwareVersion = '23.001'; CveId = 'CVE-2024-1111'; VulnerabilityName = 'RCE'; KnownRansomwareCampaignUse = 'Unknown'; DueDate = '2026-01-01' }
        $reportWith = Format-SoftwareInventoryReport -Inventory @() -VulnerableHits @($hit)
        $reportWith | Should -Match 'Zero-day exposure'
        $reportWithout = Format-SoftwareInventoryReport -Inventory @() -VulnerableHits @()
        $reportWithout | Should -Not -Match 'Zero-day exposure'
    }

    It 'handles a completely empty inventory without throwing' {
        { Format-SoftwareInventoryReport -Inventory @() -VulnerableHits @() } | Should -Not -Throw
    }
}

#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.Discovery.psm1" -Force
}

Describe 'Expand-Cidr' {
    It 'expands a /30 to 2 usable host addresses' {
        $ips = Expand-Cidr -Cidr '192.168.1.0/30'
        $ips.Count | Should -Be 2
        $ips | Should -Contain '192.168.1.1'
        $ips | Should -Contain '192.168.1.2'
    }

    It 'expands a /24 to 254 usable hosts' {
        (Expand-Cidr -Cidr '10.0.0.0/24').Count | Should -Be 254
    }

    It 'returns the single host for a /32' {
        $ips = Expand-Cidr -Cidr '10.0.0.5/32'
        $ips.Count | Should -Be 1
        $ips[0] | Should -Be '10.0.0.5'
    }

    It 'throws on an invalid CIDR' {
        { Expand-Cidr -Cidr 'not-a-cidr' } | Should -Throw
    }

    It 'rejects a prefix smaller than /16' {
        { Expand-Cidr -Cidr '10.0.0.0/8' } | Should -Throw
    }
}

Describe 'Merge-AssetInventory' {
    It 'prefers AD classification and annotates with network ports for shared hosts' {
        $ad  = @([pscustomobject]@{ Name = 'srv1.contoso.com'; AssetType = 'MemberServer'; Source = 'ActiveDirectory' })
        $net = @([pscustomobject]@{ Name = 'srv1'; AssetType = 'Windows'; OpenPorts = '445,5985'; Source = 'NetworkScan' })
        $merged = Merge-AssetInventory -AdAssets $ad -NetworkAssets $net
        $merged.Count | Should -Be 1
        $merged[0].AssetType | Should -Be 'MemberServer'   # AD wins
        $merged[0].OpenPorts | Should -Be '445,5985'        # annotated from network
        $merged[0].Source    | Should -Be 'AD+NetworkScan'
    }

    It 'keeps network-only hosts (non-domain / non-Windows)' {
        $ad  = @([pscustomobject]@{ Name = 'srv1.contoso.com'; AssetType = 'MemberServer'; Source = 'ActiveDirectory' })
        $net = @([pscustomobject]@{ Name = 'linux99'; AssetType = 'Linux'; OpenPorts = '22'; Source = 'NetworkScan' })
        $merged = Merge-AssetInventory -AdAssets $ad -NetworkAssets $net
        $merged.Count | Should -Be 2
        ($merged | Where-Object AssetType -eq 'Linux') | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-TcpPort' {
    It 'returns false quickly for a closed port' {
        # 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed unreachable
        Test-TcpPort -ComputerName '192.0.2.1' -Port 9 -TimeoutMs 300 | Should -Be $false
    }
}

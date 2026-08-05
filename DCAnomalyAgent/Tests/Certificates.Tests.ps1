#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.Certificates.psm1" -Force

    # Helper: build a collected-certificate object as the collectors would emit.
    function New-Cert {
        param(
            [string]$Source = 'MachineStore',
            [string]$ComputerName = 'host01',
            [string]$Location = 'Cert:\LocalMachine\My',
            [string]$Subject = 'CN=test',
            [string]$Thumbprint = 'AABBCC',
            [int]$DaysUntilExpiry = 30,
            [string]$ErrorText = $null
        )
        [pscustomobject]@{
            Source = $Source; ComputerName = $ComputerName; Location = $Location
            Subject = $Subject; Issuer = 'CN=Issuing CA'; Thumbprint = $Thumbprint
            NotBefore = (Get-Date).AddDays(-100)
            NotAfter  = (Get-Date).AddDays($DaysUntilExpiry)
            DnsNames = 'test.contoso.com'; FriendlyName = 'test'; HasPrivateKey = $true
            Error = $ErrorText
        }
    }
}

Describe 'Find-ExpiringCertificates threshold' {
    It 'includes a cert 89 days out and excludes one 91 days out (90-day threshold)' {
        $certs = @(
            (New-Cert -Thumbprint 'IN'  -DaysUntilExpiry 89),
            (New-Cert -Thumbprint 'OUT' -DaysUntilExpiry 91)
        )
        $f = Find-ExpiringCertificates -Certificates $certs -ThresholdDays 90
        $ids = $f | ForEach-Object { $_.Id }
        $ids | Should -Contain 'IN'
        $ids | Should -Not -Contain 'OUT'
    }

    It 'includes an already-expired certificate' {
        $certs = @( (New-Cert -Thumbprint 'DEAD' -DaysUntilExpiry -5) )
        $f = Find-ExpiringCertificates -Certificates $certs -ThresholdDays 90
        ($f | Where-Object Id -eq 'DEAD').DaysRemaining | Should -BeLessThan 0
    }

    It 'returns nothing when no certs are within the window' {
        $certs = @( (New-Cert -DaysUntilExpiry 200) )
        $f = Find-ExpiringCertificates -Certificates $certs -ThresholdDays 90
        @($f | Where-Object { $null -ne $_.DaysRemaining }).Count | Should -Be 0
    }
}

Describe 'Find-ExpiringCertificates severity tiers' {
    It 'assigns Critical at <=14 days, High at 15-30, Medium at 31-60, Low at 61-90' {
        $cases = @(
            @{ Days = 10; Sev = 'Critical' }
            @{ Days = 14; Sev = 'Critical' }
            @{ Days = 20; Sev = 'High' }
            @{ Days = 30; Sev = 'High' }
            @{ Days = 45; Sev = 'Medium' }
            @{ Days = 60; Sev = 'Medium' }
            @{ Days = 75; Sev = 'Low' }
            @{ Days = 90; Sev = 'Low' }
        )
        foreach ($c in $cases) {
            $cert = New-Cert -Thumbprint "T$($c.Days)" -DaysUntilExpiry $c.Days
            $f = Find-ExpiringCertificates -Certificates @($cert) -ThresholdDays 90
            ($f | Where-Object Id -eq "T$($c.Days)").Severity | Should -Be $c.Sev -Because "$($c.Days) days => $($c.Sev)"
        }
    }

    It 'treats an already-expired cert as Critical' {
        $f = Find-ExpiringCertificates -Certificates @((New-Cert -DaysUntilExpiry -30)) -ThresholdDays 90
        ($f | Where-Object { $null -ne $_.DaysRemaining }).Severity | Should -Be 'Critical'
    }
}

Describe 'Find-ExpiringCertificates de-duplication' {
    It 'collapses the same thumbprint from multiple sources into one finding listing all locations' {
        $certs = @(
            (New-Cert -Source 'MachineStore' -ComputerName 'dc01' -Location 'Cert:\LocalMachine\My' -Thumbprint 'SAME' -DaysUntilExpiry 20),
            (New-Cert -Source 'TlsEndpoint'  -ComputerName 'dc01' -Location 'dc01:636'            -Thumbprint 'SAME' -DaysUntilExpiry 20)
        )
        $result = Find-ExpiringCertificates -Certificates $certs -ThresholdDays 90
        $same = $result | Where-Object Id -eq 'SAME'
        @($same).Count | Should -Be 1
        $same.Sources   | Should -Match 'MachineStore'
        $same.Sources   | Should -Match 'TlsEndpoint'
        $same.Locations | Should -Match 'dc01:636'
    }
}

Describe 'Find-ExpiringCertificates error handling' {
    It 'surfaces collection errors as findings without throwing and does not miscount them as expiring' {
        $certs = @(
            (New-Cert -Thumbprint 'GOOD' -DaysUntilExpiry 10),
            (New-Cert -Thumbprint 'ERR'  -DaysUntilExpiry 10 -ErrorText 'WinRM failed')
        )
        { Find-ExpiringCertificates -Certificates $certs -ThresholdDays 90 } | Should -Not -Throw
        $result = Find-ExpiringCertificates -Certificates $certs -ThresholdDays 90
        $errFinding = $result | Where-Object { $_.CollectionErrors }
        $errFinding | Should -Not -BeNullOrEmpty
        $errFinding.CollectionErrors | Should -Match 'WinRM failed'
        # Error findings carry no DaysRemaining, so the "real" expiring count excludes them.
        @($result | Where-Object { $null -ne $_.DaysRemaining }).Count | Should -Be 1
    }

    It 'handles an empty certificate collection' {
        { Find-ExpiringCertificates -Certificates @() -ThresholdDays 90 } | Should -Not -Throw
    }
}

Describe 'Get-EndpointCertificate resilience' {
    It 'records an error object (not a throw) for an unreachable endpoint' {
        # 192.0.2.1 is TEST-NET-1 (RFC 5737) - guaranteed unreachable
        $r = Get-EndpointCertificate -TargetHost '192.0.2.1' -Port 9 -TimeoutMs 500
        $r.Source | Should -Be 'TlsEndpoint'
        $r.Error  | Should -Not -BeNullOrEmpty
    }
}

Describe 'Format-CertificateReport' {
    It 'renders a markdown report with a summary line' {
        $findings = Find-ExpiringCertificates -Certificates @((New-Cert -Subject 'CN=web01' -DaysUntilExpiry 12)) -ThresholdDays 90
        $md = Format-CertificateReport -Findings $findings -ThresholdDays 90
        $md | Should -Match '# Certificate Expiry Report'
        $md | Should -Match 'CN=web01'
    }

    It 'states clearly when nothing is expiring' {
        $md = Format-CertificateReport -Findings @() -ThresholdDays 90
        $md | Should -Match 'No certificates are expiring'
    }
}

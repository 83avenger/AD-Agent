#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.ZeroDay.psm1" -Force

    # Minimal config used by all tests
    $script:TestCacheDir = Join-Path $TestDrive 'State'
    New-Item -ItemType Directory -Path $script:TestCacheDir -Force | Out-Null

    $script:TestConfig = @{
        Enabled          = $true
        Offline          = $false
        ProductsPath     = "$PSScriptRoot\..\Config\zeroday-products.psd1"
        CacheDir         = $script:TestCacheDir
        AlertOnNew       = $true
        AlertDueDateDays = 7
    }

    # Synthetic KEV feed matching Windows
    $script:FakeKevResponse = @{
        vulnerabilities = @(
            @{
                cveID                      = 'CVE-2024-00001'
                vendorProject              = 'Microsoft'
                product                    = 'Windows Server'
                vulnerabilityName          = 'Fake RCE in Windows Server'
                dateAdded                  = (Get-Date).ToString('yyyy-MM-dd')
                dueDate                    = (Get-Date).AddDays(5).ToString('yyyy-MM-dd')
                requiredAction             = 'Apply vendor patch immediately.'
                shortDescription           = 'A critical RCE vulnerability.'
                knownRansomwareCampaignUse = 'Known'
                notes                      = ''
            }
            @{
                cveID                      = 'CVE-2024-00002'
                vendorProject              = 'Apache'
                product                    = 'Log4j'
                vulnerabilityName          = 'Log4Shell'
                dateAdded                  = (Get-Date).ToString('yyyy-MM-dd')
                dueDate                    = ''
                requiredAction             = 'Update.'
                shortDescription           = 'JNDI injection.'
                knownRansomwareCampaignUse = 'Unknown'
                notes                      = ''
            }
        )
    }
}

Describe 'Get-CisaKevFeed' {
    It 'falls back to cache when Offline = true' {
        $cacheFile = Join-Path $script:TestCacheDir 'kev-cache.json'
        $script:FakeKevResponse | ConvertTo-Json -Depth 10 | Set-Content $cacheFile -Encoding UTF8

        $cfg = $script:TestConfig.Clone(); $cfg.Offline = $true
        $result = Get-CisaKevFeed -Config $cfg
        $result.Count | Should -Be 2
    }

    It 'returns empty array and warns when offline and no cache exists' {
        $cfg = $script:TestConfig.Clone()
        $cfg.Offline  = $true
        $cfg.CacheDir = Join-Path $TestDrive 'nocache'
        New-Item -ItemType Directory -Path $cfg.CacheDir -Force | Out-Null

        $result = Get-CisaKevFeed -Config $cfg -WarningVariable w
        $result.Count | Should -Be 0
        $w | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-ZeroDayMatches' {
    It 'returns entries matching the watched product list' {
        # Write cache so no HTTP call is needed
        $cacheFile = Join-Path $script:TestCacheDir 'kev-cache.json'
        $script:FakeKevResponse | ConvertTo-Json -Depth 10 | Set-Content $cacheFile -Encoding UTF8

        $cfg = $script:TestConfig.Clone(); $cfg.Offline = $true
        $matches = Get-ZeroDayMatches -Config $cfg
        # CVE-2024-00001 matches 'Windows Server'; CVE-2024-00002 (Apache/Log4j) should not match
        $matches | Where-Object CveId -eq 'CVE-2024-00001' | Should -Not -BeNullOrEmpty
        $matches | Where-Object CveId -eq 'CVE-2024-00002' | Should -BeNullOrEmpty
    }

    It 'respects MaxAgeDays and excludes old entries' {
        $oldEntry = @{
            cveID = 'CVE-2020-00001'; vendorProject = 'Microsoft'; product = 'Windows Server'
            vulnerabilityName = 'Old vuln'; dateAdded = '2020-01-01'; dueDate = ''; requiredAction = 'Patch'
            shortDescription = 'Old.'; knownRansomwareCampaignUse = 'Unknown'; notes = ''
        }
        $feed = @{ vulnerabilities = @($oldEntry) }
        $cacheFile = Join-Path $script:TestCacheDir 'kev-cache.json'
        $feed | ConvertTo-Json -Depth 10 | Set-Content $cacheFile -Encoding UTF8

        # Import-PowerShellDataFile needs real file; use the actual products file but override MaxAgeDays via direct manipulation
        $cfg = $script:TestConfig.Clone(); $cfg.Offline = $true
        # The products file has MaxAgeDays = 30, so a 2020 entry must be excluded
        $matches = Get-ZeroDayMatches -Config $cfg
        $matches | Where-Object CveId -eq 'CVE-2020-00001' | Should -BeNullOrEmpty
    }
}

Describe 'Update-ZeroDayBaseline' {
    It 'returns all matches on first run (empty baseline)' {
        $matches = @(
            [pscustomobject]@{ CveId = 'CVE-2024-A'; VulnerabilityName = 'Test' }
            [pscustomobject]@{ CveId = 'CVE-2024-B'; VulnerabilityName = 'Test2' }
        )
        $cacheDir = Join-Path $TestDrive 'baseline-test1'
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
        $new = Update-ZeroDayBaseline -Matches $matches -CacheDir $cacheDir
        $new.Count | Should -Be 2
    }

    It 'returns only new entries on subsequent runs' {
        $matches = @(
            [pscustomobject]@{ CveId = 'CVE-2024-A'; VulnerabilityName = 'Test' }
            [pscustomobject]@{ CveId = 'CVE-2024-B'; VulnerabilityName = 'Test2' }
        )
        $cacheDir = Join-Path $TestDrive 'baseline-test2'
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null

        Update-ZeroDayBaseline -Matches $matches -CacheDir $cacheDir | Out-Null  # first run

        $more = $matches + @([pscustomobject]@{ CveId = 'CVE-2024-C'; VulnerabilityName = 'New' })
        $new = Update-ZeroDayBaseline -Matches $more -CacheDir $cacheDir
        $new.Count    | Should -Be 1
        $new[0].CveId | Should -Be 'CVE-2024-C'
    }

    It 'returns empty array when nothing is new' {
        $matches = @([pscustomobject]@{ CveId = 'CVE-2024-A'; VulnerabilityName = 'Test' })
        $cacheDir = Join-Path $TestDrive 'baseline-test3'
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
        Update-ZeroDayBaseline -Matches $matches -CacheDir $cacheDir | Out-Null
        $new = Update-ZeroDayBaseline -Matches $matches -CacheDir $cacheDir
        $new.Count | Should -Be 0
    }
}

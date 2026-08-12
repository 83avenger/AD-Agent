#Requires -Version 5.1

$KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
$NVD_URL  = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

function Get-CisaKevFeed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config
    )

    $cacheFile = Join-Path $Config.CacheDir 'kev-cache.json'

    if (-not $Config.Offline) {
        try {
            [System.Net.ServicePointManager]::SecurityProtocol =
                [System.Net.ServicePointManager]::SecurityProtocol -bor
                [System.Net.SecurityProtocolType]::Tls12

            $response = Invoke-RestMethod -Uri $KEV_URL -UseBasicParsing
            $response | ConvertTo-Json -Depth 10 |
                Set-Content -Path $cacheFile -Encoding UTF8
            return $response.vulnerabilities
        } catch {
            Write-Warning "Failed to fetch CISA KEV feed: $_. Falling back to cache."
        }
    }

    if (Test-Path $cacheFile) {
        $cached = Get-Content $cacheFile -Raw | ConvertFrom-Json
        return $cached.vulnerabilities
    }

    Write-Warning "No KEV cache found at '$cacheFile'. Run without -Offline first to populate it."
    return @()
}

function Get-NvdCveFeed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Products,
        [Parameter(Mandatory)][hashtable]$Config
    )

    if ($Config.Offline) { return @() }

    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor
        [System.Net.SecurityProtocolType]::Tls12

    $productsCfg = Import-PowerShellDataFile -Path $Config.ProductsPath
    $apiKey      = $productsCfg.NvdApiKey
    $headers     = if ($apiKey) { @{ apiKey = $apiKey } } else { @{} }

    # Respect NVD rate limits: 5 req/30 s (no key) or 50 req/30 s (with key).
    # We sleep 6 s between requests to stay safe without a key.
    $sleepMs = if ($apiKey) { 700 } else { 6100 }

    $results = @()
    foreach ($product in $Products) {
        try {
            $uri = "$NVD_URL`?keywordSearch=$([uri]::EscapeDataString($product))&resultsPerPage=20"
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -UseBasicParsing
            foreach ($item in $response.vulnerabilities) {
                $cve = $item.cve
                $results += [pscustomobject]@{
                    CveId              = $cve.id
                    VendorProject      = 'NVD'
                    Product            = $product
                    VulnerabilityName  = ($cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
                    DateAdded          = $cve.published
                    DueDate            = ''
                    RequiredAction     = 'Review NVD entry and apply vendor patch.'
                    ShortDescription   = ($cve.descriptions | Where-Object { $_.lang -eq 'en' } | Select-Object -First 1).value
                    KnownRansomwareCampaignUse = 'Unknown'
                    Source             = 'NVD'
                }
            }
        } catch {
            Write-Warning "NVD query failed for '$product': $_"
        }
        Start-Sleep -Milliseconds $sleepMs
    }
    return $results
}

function Get-ZeroDayMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config
    )

    $productsCfg = Import-PowerShellDataFile -Path $Config.ProductsPath
    $watchList   = $productsCfg.Products
    $maxAgeDays  = $productsCfg.MaxAgeDays

    $cutoff = if ($maxAgeDays -gt 0) { (Get-Date).AddDays(-$maxAgeDays) } else { [datetime]::MinValue }

    # --- CISA KEV ---
    $kevEntries = Get-CisaKevFeed -Config $Config
    $zdMatches  = @()

    foreach ($entry in $kevEntries) {
        $dateAdded = if ($entry.dateAdded) { [datetime]$entry.dateAdded } else { [datetime]::MinValue }
        if ($dateAdded -lt $cutoff) { continue }

        $text = "$($entry.vendorProject) $($entry.product)"
        $hit  = $watchList | Where-Object { $text -match [regex]::Escape($_) }
        if ($hit) {
            $zdMatches += [pscustomobject]@{
                CveId                      = $entry.cveID
                VendorProject              = $entry.vendorProject
                Product                    = $entry.product
                VulnerabilityName          = $entry.vulnerabilityName
                DateAdded                  = $entry.dateAdded
                DueDate                    = $entry.dueDate
                RequiredAction             = $entry.requiredAction
                ShortDescription           = $entry.shortDescription
                KnownRansomwareCampaignUse = $entry.knownRansomwareCampaignUse
                Source                     = 'CISA-KEV'
            }
        }
    }

    # --- NVD (secondary - only for products not already covered by KEV) ---
    $kevCveIds = $zdMatches | Select-Object -ExpandProperty CveId
    $nvdResults = Get-NvdCveFeed -Products $watchList -Config $Config
    foreach ($nvd in $nvdResults) {
        if ($nvd.CveId -notin $kevCveIds) {
            $zdMatches += $nvd
        }
    }

    # Unary comma preserves an empty array through return (PowerShell otherwise
    # unrolls @() to $null, which would break the caller when there are 0 matches).
    return ,$zdMatches
}

function Update-ZeroDayBaseline {
    [CmdletBinding()]
    param(
        # May be $null/empty when the feeds are unreachable or matched nothing.
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][array]$Matches,
        [Parameter(Mandatory)][string]$CacheDir
    )

    if (-not $Matches) { return @() }

    $baselineFile = Join-Path $CacheDir 'zeroday-baseline.json'
    $seenIds = @()

    if (Test-Path $baselineFile) {
        $seenIds = @(Get-Content $baselineFile -Raw | ConvertFrom-Json)
    }

    $newMatches = @($Matches | Where-Object { $_.CveId -notin $seenIds })

    if ($newMatches.Count -gt 0) {
        $allIds = @($seenIds) + @($newMatches | Select-Object -ExpandProperty CveId) | Select-Object -Unique
        $allIds | ConvertTo-Json | Set-Content -Path $baselineFile -Encoding UTF8
    }

    return ,$newMatches
}

Export-ModuleMember -Function Get-CisaKevFeed, Get-NvdCveFeed, Get-ZeroDayMatches, Update-ZeroDayBaseline

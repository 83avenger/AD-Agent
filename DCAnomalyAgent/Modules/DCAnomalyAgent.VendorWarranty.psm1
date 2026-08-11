#Requires -Version 5.1
<#
.SYNOPSIS
    Resolves a Windows host's BIOS serial number to its ship/purchase date via the
    Dell/HP/Lenovo warranty APIs, so device age can be reported without a separate CMDB.

.DESCRIPTION
    Keys are entered and saved from the web UI's Integrations > Vendor Warranty page
    (or by hand in Config/integration-secrets.json) rather than settings.psd1, so real
    API secrets never end up committed to source control - see Get-VendorWarrantySecrets.

    The three Invoke-WarrantyApi* functions call each vendor's published warranty/
    entitlement endpoint. None of this has been exercised against a live vendor account
    yet (no keys were available at authoring time) - the request shapes follow each
    vendor's published API docs as of 2026, but expect to adjust field names/auth flow
    once real credentials are in hand and you can test against them.
#>

function Get-VendorWarrantySecrets {
    <#
    .SYNOPSIS
        Loads vendor API keys from Config/integration-secrets.json (written by the web
        UI's "Vendor Warranty" settings page). Returns an all-empty shape if the file
        doesn't exist yet - nothing here is required for any other AD-Agent feature.
    #>
    [CmdletBinding()]
    param([string]$SecretsPath = "$PSScriptRoot\..\Config\integration-secrets.json")

    # Enabled/AgeAlertYears are $null here (not $false/4) so callers can tell "not set via
    # the web UI yet" apart from an explicit choice, and fall back to settings.psd1's value.
    $empty = [pscustomobject]@{
        Dell          = [pscustomobject]@{ ApiKey = ''; ApiSecret = '' }
        Hp            = [pscustomobject]@{ ApiKey = '' }
        Lenovo        = [pscustomobject]@{ ApiKey = '' }
        Enabled       = $null
        AgeAlertYears = $null
    }
    if (-not (Test-Path $SecretsPath)) { return $empty }
    try {
        $raw = Get-Content -Raw -Path $SecretsPath | ConvertFrom-Json
        if ($raw.VendorWarranty) { return $raw.VendorWarranty }
        return $empty
    } catch {
        Write-Verbose "Failed to read $SecretsPath - treating vendor warranty as unconfigured: $_"
        return $empty
    }
}

function Get-WarrantyInfo {
    <#
    .SYNOPSIS
        Looks up ship date / warranty end date for one serial number from the matching
        vendor API. Returns $null if that vendor isn't configured or the lookup fails -
        callers should treat a $null return as "age unknown", not an error.
    .PARAMETER Vendor
        'Dell' | 'Hp' | 'Lenovo' (matches Win32_ComputerSystem.Manufacturer once normalized -
        see Get-DeviceAge).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Dell', 'Hp', 'Lenovo')][string]$Vendor,
        [Parameter(Mandatory)][string]$SerialNumber,
        [pscustomobject]$Secrets
    )

    if (-not $Secrets) { $Secrets = Get-VendorWarrantySecrets }

    try {
        switch ($Vendor) {
            'Dell' {
                if (-not $Secrets.Dell.ApiKey -or -not $Secrets.Dell.ApiSecret) { return $null }
                # Dell TechDirect: OAuth2 client-credentials token, then the Asset Entitlement
                # (Warranty) API keyed by service tag. Adjust the token/entitlement URLs and
                # response field names once you have a real TechDirect account to verify against.
                $tokenResp = Invoke-RestMethod -Method Post -Uri 'https://apigtwb2c.us.dell.com/auth/oauth/v2/token' `
                    -Body @{ client_id = $Secrets.Dell.ApiKey; client_secret = $Secrets.Dell.ApiSecret; grant_type = 'client_credentials' } `
                    -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 15
                $entResp = Invoke-RestMethod -Method Get `
                    -Uri "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements?servicetags=$SerialNumber" `
                    -Headers @{ Authorization = "Bearer $($tokenResp.access_token)" } -TimeoutSec 15
                $asset = $entResp | Select-Object -First 1
                $ship  = if ($asset.shipDate) { [datetime]$asset.shipDate } else { $null }
                $end   = ($asset.entitlements | Sort-Object endDate -Descending | Select-Object -First 1).endDate
                return [pscustomobject]@{ SerialNumber = $SerialNumber; Vendor = 'Dell'; ShipDate = $ship; WarrantyEndDate = $end }
            }
            'Hp' {
                if (-not $Secrets.Hp.ApiKey) { return $null }
                # HP Warranty API (developers.hp.com) - subscription key in header, lookup by serial.
                $resp = Invoke-RestMethod -Method Get `
                    -Uri "https://api.hp.com/support-services/v1/warranty/products?serialNumber=$SerialNumber" `
                    -Headers @{ 'Ocp-Apim-Subscription-Key' = $Secrets.Hp.ApiKey } -TimeoutSec 15
                $asset = $resp.products | Select-Object -First 1
                $ship  = if ($asset.startDate) { [datetime]$asset.startDate } else { $null }
                return [pscustomobject]@{ SerialNumber = $SerialNumber; Vendor = 'Hp'; ShipDate = $ship; WarrantyEndDate = $asset.endDate }
            }
            'Lenovo' {
                if (-not $Secrets.Lenovo.ApiKey) { return $null }
                # Lenovo Support API (supportapi.lenovo.com) - API key as ClientID header.
                $resp = Invoke-RestMethod -Method Get `
                    -Uri "https://supportapi.lenovo.com/v2.5/warranty?Serial=$SerialNumber" `
                    -Headers @{ ClientID = $Secrets.Lenovo.ApiKey } -TimeoutSec 15
                $ship = if ($resp.Purchase_Date) { [datetime]$resp.Purchase_Date } else { $null }
                $end  = ($resp.Warranty | Sort-Object End -Descending | Select-Object -First 1).End
                return [pscustomobject]@{ SerialNumber = $SerialNumber; Vendor = 'Lenovo'; ShipDate = $ship; WarrantyEndDate = $end }
            }
        }
    } catch {
        Write-Verbose "Warranty lookup failed for $Vendor/$SerialNumber - $_"
        return $null
    }
}

function Get-DeviceAge {
    <#
    .SYNOPSIS
        For one Windows host: pulls BIOS serial + manufacturer over WinRM, looks up ship
        date via the matching vendor API, and returns age in years. Returns $null (not an
        error) if the vendor isn't configured, isn't Dell/HP/Lenovo, or WinRM fails.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscustomobject]$Secrets
    )

    if (-not $Secrets) { $Secrets = Get-VendorWarrantySecrets }

    try {
        $sys = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            [pscustomobject]@{
                Serial       = (Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber
                Manufacturer = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Manufacturer
            }
        }
    } catch {
        Write-Verbose "Get-DeviceAge: WinRM failed for $ComputerName - $_"
        return $null
    }

    $vendor = switch -Regex ($sys.Manufacturer) {
        'Dell'                { 'Dell'; break }
        'HP|Hewlett'           { 'Hp'; break }
        'Lenovo'               { 'Lenovo'; break }
        default                { $null }
    }
    if (-not $vendor -or -not $sys.Serial) { return $null }

    $warranty = Get-WarrantyInfo -Vendor $vendor -SerialNumber $sys.Serial -Secrets $Secrets
    if (-not $warranty -or -not $warranty.ShipDate) { return $null }

    $ageYears = [math]::Round(((Get-Date) - $warranty.ShipDate).TotalDays / 365.25, 1)
    [pscustomobject]@{
        ComputerName    = $ComputerName
        SerialNumber    = $sys.Serial
        Vendor          = $vendor
        ShipDate        = $warranty.ShipDate
        WarrantyEndDate = $warranty.WarrantyEndDate
        AgeYears        = $ageYears
    }
}

Export-ModuleMember -Function Get-VendorWarrantySecrets, Get-WarrantyInfo, Get-DeviceAge

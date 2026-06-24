#Requires -Version 5.1

function Send-TeamsAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebhookUrl,
        [Parameter(Mandatory)][array]$Anomalies
    )

    if (-not $Anomalies -or $Anomalies.Count -eq 0) { return }

    $facts = $Anomalies | ForEach-Object {
        @{
            title = "$($_.Type) - $($_.ComputerName)"
            value = "$($_.Detail) (Account: $($_.Account); $($_.TimeCreated))"
        }
    }

    $card = @{
        '@type'    = 'MessageCard'
        '@context' = 'http://schema.org/extensions'
        summary    = "DC Anomaly Scan: $($Anomalies.Count) finding(s)"
        themeColor = 'D9534F'
        title      = "Domain Controller Anomaly Scan - $($Anomalies.Count) finding(s)"
        sections   = @(@{ facts = $facts })
    }

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body ($card | ConvertTo-Json -Depth 6) -ContentType 'application/json'
    } catch {
        Write-Warning "Failed to send Teams alert: $_"
    }
}

function Get-GraphAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$CertificateThumbprint
    )

    $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction Stop
    }

    $now = [DateTimeOffset]::UtcNow
    $jwtHeader = @{ alg = 'RS256'; typ = 'JWT'; x5t = [Convert]::ToBase64String($cert.GetCertHash()) } | ConvertTo-Json -Compress
    $jwtPayload = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $ClientId
        sub = $ClientId
        jti = [guid]::NewGuid().ToString()
        nbf = $now.ToUnixTimeSeconds()
        exp = $now.AddMinutes(10).ToUnixTimeSeconds()
    } | ConvertTo-Json -Compress

    $b64 = { param($bytes) [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $headerEnc = & $b64 ([System.Text.Encoding]::UTF8.GetBytes($jwtHeader))
    $payloadEnc = & $b64 ([System.Text.Encoding]::UTF8.GetBytes($jwtPayload))
    $signInput = "$headerEnc.$payloadEnc"

    $rsa = $cert.GetRSAPrivateKey()
    $signature = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($signInput), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $signatureEnc = & $b64 $signature
    $clientAssertion = "$signInput.$signatureEnc"

    $body = @{
        client_id             = $ClientId
        scope                 = 'https://graph.microsoft.com/.default'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $clientAssertion
        grant_type            = 'client_credentials'
    }

    $response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method Post -Body $body
    return $response.access_token
}

function Write-SharePointListItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$SharePointConfig,
        [Parameter(Mandatory)][array]$Anomalies
    )

    if (-not $Anomalies -or $Anomalies.Count -eq 0) { return }

    try {
        $token = Get-GraphAccessToken -TenantId $SharePointConfig.TenantId -ClientId $SharePointConfig.ClientId `
            -CertificateThumbprint $SharePointConfig.CertificateThumbprint

        $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
        $uri = "https://graph.microsoft.com/v1.0/sites/$($SharePointConfig.SiteId)/lists/$($SharePointConfig.ListId)/items"

        foreach ($anomaly in $Anomalies) {
            $body = @{
                fields = @{
                    Title          = $anomaly.Type
                    Account        = $anomaly.Account
                    Detail         = $anomaly.Detail
                    ComputerName   = $anomaly.ComputerName
                    DetectedAt     = $anomaly.TimeCreated.ToString('o')
                }
            } | ConvertTo-Json -Depth 5

            Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body | Out-Null
        }
    } catch {
        Write-Warning "Failed to write SharePoint list item(s): $_"
    }
}

function Send-TeamsComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebhookUrl,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][array]$Gaps
    )

    $severityIcon = @{ Critical = '🔴'; High = '🟠'; Medium = '🟡'; Low = '🔵' }
    $topGaps = $Gaps | Sort-Object @{
        e = { @{ Critical = 0; High = 1; Medium = 2; Low = 3 }[$_.Severity] }
    } | Select-Object -First 10

    $facts = $topGaps | ForEach-Object {
        @{
            title = "$($severityIcon[$_.Severity]) [$($_.Severity)] $($_.ControlId) — $($_.Title)"
            value = "DC: $($_.ComputerName) | Actual: $($_.Actual)"
        }
    }

    if ($Gaps.Count -gt 10) {
        $facts += @{ title = '...'; value = "$($Gaps.Count - 10) more gap(s) in SharePoint report." }
    }

    $color = if ($Summary.ScorePct -ge 80) { '5CB85C' } elseif ($Summary.ScorePct -ge 60) { 'F0AD4E' } else { 'D9534F' }

    $card = @{
        '@type'    = 'MessageCard'
        '@context' = 'http://schema.org/extensions'
        summary    = "Compliance Scan: $($Summary.ScorePct)% ($($Summary.Failed) gap(s))"
        themeColor = $color
        title      = "DC Compliance Report — $($Summary.ScorePct)% passing ($($Summary.Passed)/$($Summary.TotalControls) controls)"
        sections   = @(
            @{
                activityTitle = "Gaps by severity: $(($Summary.GapsBySeverity | ForEach-Object { "$($_.Severity): $($_.GapCount)" }) -join ' | ')"
                facts         = $facts
            }
        )
    }

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body ($card | ConvertTo-Json -Depth 8) -ContentType 'application/json'
    } catch {
        Write-Warning "Failed to send Teams compliance report: $_"
    }
}

function Write-SharePointComplianceItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$SharePointConfig,
        [Parameter(Mandatory)][array]$Gaps,
        [datetime]$ScanTime = (Get-Date),
        [string]$ListId
    )

    if (-not $Gaps -or $Gaps.Count -eq 0) { return }

    $targetListId = if ($ListId) { $ListId } else { $SharePointConfig.ComplianceListId }
    if (-not $targetListId) {
        Write-Warning "No SharePoint list ID configured for compliance items (set SharePointConfig.ComplianceListId)."
        return
    }

    try {
        $token = Get-GraphAccessToken -TenantId $SharePointConfig.TenantId -ClientId $SharePointConfig.ClientId `
            -CertificateThumbprint $SharePointConfig.CertificateThumbprint

        $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
        $uri = "https://graph.microsoft.com/v1.0/sites/$($SharePointConfig.SiteId)/lists/$targetListId/items"

        foreach ($gap in $Gaps) {
            $frameworkLabels = ($gap.Frameworks.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join '; '
            $body = @{
                fields = @{
                    Title        = "$($gap.ControlId) — $($gap.Title)"
                    Severity     = $gap.Severity
                    Frameworks   = $frameworkLabels
                    ComputerName = $gap.ComputerName
                    Actual       = $gap.Actual
                    Expected     = $gap.Expected
                    Remediation  = $gap.Remediation
                    ScanTime     = $ScanTime.ToString('o')
                }
            } | ConvertTo-Json -Depth 5

            Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body | Out-Null
        }
    } catch {
        Write-Warning "Failed to write compliance items to SharePoint: $_"
    }
}

Export-ModuleMember -Function Send-TeamsAlert, Write-SharePointListItem, Get-GraphAccessToken, `
    Send-TeamsComplianceReport, Write-SharePointComplianceItems

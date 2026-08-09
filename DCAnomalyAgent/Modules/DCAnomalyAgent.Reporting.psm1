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

    $severityIcon = @{ Critical = '[C]'; High = '[H]'; Medium = '[M]'; Low = '[L]' }
    $topGaps = $Gaps | Sort-Object @{
        e = { @{ Critical = 0; High = 1; Medium = 2; Low = 3 }[$_.Severity] }
    } | Select-Object -First 10

    $facts = $topGaps | ForEach-Object {
        @{
            title = "$($severityIcon[$_.Severity]) [$($_.Severity)] $($_.ControlId) - $($_.Title)"
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
        title      = "DC Compliance Report - $($Summary.ScorePct)% passing ($($Summary.Passed)/$($Summary.TotalControls) controls)"
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
                    Title        = "$($gap.ControlId) - $($gap.Title)"
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


# --- Email helpers ------------------------------------------------------------

function _Get-EmailCredential {
    param([hashtable]$EmailConfig)
    if (-not $EmailConfig.CredentialUser) { return $null }
    $securePass = if ($EmailConfig.CredentialPassword) {
        $EmailConfig.CredentialPassword | ConvertTo-SecureString
    } else {
        New-Object System.Security.SecureString
    }
    return New-Object System.Management.Automation.PSCredential($EmailConfig.CredentialUser, $securePass)
}

function _Build-HtmlTable {
    param([array]$Rows, [string[]]$Columns)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table border="1" cellpadding="4" cellspacing="0" style="border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:13px">')
    [void]$sb.Append('<tr style="background:#1e3a5f;color:#fff">')
    foreach ($col in $Columns) { [void]$sb.Append("<th>$col</th>") }
    [void]$sb.Append('</tr>')
    $alt = $false
    foreach ($row in $Rows) {
        $bg = if ($alt) { '#f4f4f4' } else { '#ffffff' }
        [void]$sb.Append("<tr style=`"background:$bg`">")
        foreach ($col in $Columns) { [void]$sb.Append("<td>$([System.Net.WebUtility]::HtmlEncode($row.$col))</td>") }
        [void]$sb.Append('</tr>')
        $alt = -not $alt
    }
    [void]$sb.Append('</table>')
    return $sb.ToString()
}

$_SeverityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }

function Send-EmailAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$EmailConfig,
        [Parameter(Mandatory)][array]$Anomalies
    )

    if (-not $EmailConfig.Enabled -or -not $Anomalies) { return }

    try {
        $filtered = if ($EmailConfig.MinSeverity) {
            $minRank = $_SeverityOrder[$EmailConfig.MinSeverity]
            $Anomalies | Where-Object { ($_SeverityOrder[$_.Severity] -le $minRank) -or (-not $_.Severity) }
        } else { $Anomalies }

        if (-not $filtered -and -not $EmailConfig.SendOnNoFindings) { return }

        $table  = _Build-HtmlTable -Rows $filtered -Columns @('Type','Account','ComputerName','TimeCreated','Detail')
        $body   = "<h2>Domain Controller Anomaly Alert - $($Anomalies.Count) finding(s)</h2>$table"
        $cred   = _Get-EmailCredential -EmailConfig $EmailConfig

        $params = @{
            To         = $EmailConfig.To
            From       = $EmailConfig.From
            Subject    = "[AD-Agent] Anomaly Alert - $($Anomalies.Count) finding(s) - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
            Body       = $body
            BodyAsHtml = $true
            SmtpServer = $EmailConfig.SmtpServer
            Port       = $EmailConfig.Port
            UseSsl     = $EmailConfig.UseSsl
        }
        if ($cred) { $params['Credential'] = $cred }
        Send-MailMessage @params
    } catch {
        Write-Warning "Failed to send email alert: $_"
    }
}

function Send-EmailComplianceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$EmailConfig,
        [Parameter(Mandatory)][pscustomobject]$Summary,
        [Parameter(Mandatory)][array]$Gaps
    )

    if (-not $EmailConfig.Enabled) { return }
    if ($Gaps.Count -eq 0 -and -not $EmailConfig.SendOnNoFindings) { return }

    try {
        $scoreColor = if ($Summary.ScorePct -ge 80) { '#27ae60' } elseif ($Summary.ScorePct -ge 60) { '#f39c12' } else { '#c0392b' }
        $scoreCard  = "<p style=`"font-size:20px`">Compliance Score: <strong style=`"color:$scoreColor`">$($Summary.ScorePct)%</strong> &nbsp; ($($Summary.Passed)/$($Summary.TotalControls) controls passing, $($Gaps.Count) gap(s))</p>"

        $topGaps   = $Gaps | Sort-Object { $_SeverityOrder[$_.Severity] } | Select-Object -First 20
        $table     = _Build-HtmlTable -Rows $topGaps -Columns @('Severity','ControlId','Title','ComputerName','Actual','Remediation')
        $body      = "<h2>Compliance Scan Report - $(Get-Date -Format 'yyyy-MM-dd')</h2>$scoreCard$table"
        $cred      = _Get-EmailCredential -EmailConfig $EmailConfig

        $params = @{
            To         = $EmailConfig.To
            From       = $EmailConfig.From
            Subject    = "[AD-Agent] Compliance Report - $($Summary.ScorePct)% - $(Get-Date -Format 'yyyy-MM-dd')"
            Body       = $body
            BodyAsHtml = $true
            SmtpServer = $EmailConfig.SmtpServer
            Port       = $EmailConfig.Port
            UseSsl     = $EmailConfig.UseSsl
        }
        if ($cred) { $params['Credential'] = $cred }
        Send-MailMessage @params
    } catch {
        Write-Warning "Failed to send email compliance report: $_"
    }
}

function Send-TeamsZeroDayAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebhookUrl,
        [Parameter(Mandatory)][array]$ZeroDays
    )

    if (-not $ZeroDays -or $ZeroDays.Count -eq 0) { return }

    $facts = $ZeroDays | ForEach-Object {
        $ransomTag = if ($_.KnownRansomwareCampaignUse -eq 'Known') { ' [RANSOMWARE]' } else { '' }
        @{
            title = "$($_.CveId)$ransomTag - $($_.VulnerabilityName)"
            value = "Product: $($_.VendorProject) / $($_.Product) | Added: $($_.DateAdded) | Due: $($_.DueDate) | $($_.RequiredAction)"
        }
    }

    $card = @{
        '@type'    = 'MessageCard'
        '@context' = 'http://schema.org/extensions'
        summary    = "Zero-Day Alert: $($ZeroDays.Count) new CVE(s) match your environment"
        themeColor = 'C0392B'
        title      = "Zero-Day Alert - $($ZeroDays.Count) new CVE(s) match your environment"
        sections   = @(@{ activityTitle = 'Newly added to CISA KEV / NVD'; facts = $facts })
    }

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body ($card | ConvertTo-Json -Depth 8) -ContentType 'application/json'
    } catch {
        Write-Warning "Failed to send Teams zero-day alert: $_"
    }
}

function Send-EmailZeroDayAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$EmailConfig,
        [Parameter(Mandatory)][array]$ZeroDays
    )

    if (-not $EmailConfig.Enabled -or -not $ZeroDays) { return }

    try {
        $table  = _Build-HtmlTable -Rows $ZeroDays -Columns @('CveId','VendorProject','Product','VulnerabilityName','DateAdded','DueDate','KnownRansomwareCampaignUse','RequiredAction')
        $body   = "<h2 style=`"color:#c0392b`">Zero-Day Alert - $($ZeroDays.Count) new CVE(s) match your environment</h2>$table"
        $cred   = _Get-EmailCredential -EmailConfig $EmailConfig

        $params = @{
            To         = $EmailConfig.To
            From       = $EmailConfig.From
            Subject    = "[AD-Agent] Zero-Day Alert - $($ZeroDays.Count) new CVE(s) - $(Get-Date -Format 'yyyy-MM-dd')"
            Body       = $body
            BodyAsHtml = $true
            SmtpServer = $EmailConfig.SmtpServer
            Port       = $EmailConfig.Port
            UseSsl     = $EmailConfig.UseSsl
        }
        if ($cred) { $params['Credential'] = $cred }
        Send-MailMessage @params
    } catch {
        Write-Warning "Failed to send email zero-day alert: $_"
    }
}

function Send-TeamsCertificateReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebhookUrl,
        [Parameter(Mandatory)][array]$Certificates,
        [int]$ThresholdDays = 90
    )

    $real = $Certificates | Where-Object { $null -ne $_.DaysRemaining }
    if (-not $real -or $real.Count -eq 0) { return }

    $severityIcon = @{ Critical = '[C]'; High = '[H]'; Medium = '[M]'; Low = '[L]' }
    $top = $real | Sort-Object @{ e = { $_SeverityOrder[$_.Severity] } }, DaysRemaining | Select-Object -First 15

    $facts = $top | ForEach-Object {
        $days = if ($_.DaysRemaining -lt 0) { "EXPIRED $([math]::Abs($_.DaysRemaining))d ago" } else { "$($_.DaysRemaining)d left" }
        @{
            title = "$($severityIcon[$_.Severity]) [$($_.Severity)] $days - $($_.Subject)"
            value = "Issuer: $($_.Issuer) | $($_.Sources) | $($_.Locations)"
        }
    }
    if ($real.Count -gt 15) {
        $facts += @{ title = '...'; value = "$($real.Count - 15) more certificate(s) in the full report." }
    }

    $anyCritical = $real | Where-Object { $_.Severity -eq 'Critical' }
    $color = if ($anyCritical) { 'C0392B' } else { 'F0AD4E' }

    $card = @{
        '@type'    = 'MessageCard'
        '@context' = 'http://schema.org/extensions'
        summary    = "Certificate Expiry: $($real.Count) cert(s) expiring within $ThresholdDays days"
        themeColor = $color
        title      = "Certificate Expiry Report - $($real.Count) cert(s) expiring within $ThresholdDays days"
        sections   = @(@{ activityTitle = 'Sorted by urgency'; facts = $facts })
    }

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body ($card | ConvertTo-Json -Depth 8) -ContentType 'application/json'
    } catch {
        Write-Warning "Failed to send Teams certificate report: $_"
    }
}

function Send-EmailCertificateReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$EmailConfig,
        [Parameter(Mandatory)][array]$Certificates,
        [int]$ThresholdDays = 90
    )

    if (-not $EmailConfig.Enabled) { return }
    $real = $Certificates | Where-Object { $null -ne $_.DaysRemaining }
    if ((-not $real -or $real.Count -eq 0) -and -not $EmailConfig.SendOnNoFindings) { return }

    try {
        $rows = $real | Sort-Object @{ e = { $_SeverityOrder[$_.Severity] } }, DaysRemaining | ForEach-Object {
            [pscustomobject]@{
                Severity      = $_.Severity
                DaysRemaining = if ($_.DaysRemaining -lt 0) { "EXPIRED ($($_.DaysRemaining))" } else { $_.DaysRemaining }
                Subject       = $_.Subject
                Issuer        = $_.Issuer
                NotAfter      = $_.NotAfter
                Sources       = $_.Sources
                Locations     = $_.Locations
            }
        }
        $count = @($real).Count
        $table = _Build-HtmlTable -Rows $rows -Columns @('Severity','DaysRemaining','Subject','Issuer','NotAfter','Sources','Locations')
        $body  = "<h2 style=`"color:#c0392b`">Certificate Expiry Report - $count cert(s) expiring within $ThresholdDays days</h2>$table"
        $cred  = _Get-EmailCredential -EmailConfig $EmailConfig

        $params = @{
            To         = $EmailConfig.To
            From       = $EmailConfig.From
            Subject    = "[AD-Agent] Certificate Expiry - $count cert(s) within $ThresholdDays days - $(Get-Date -Format 'yyyy-MM-dd')"
            Body       = $body
            BodyAsHtml = $true
            SmtpServer = $EmailConfig.SmtpServer
            Port       = $EmailConfig.Port
            UseSsl     = $EmailConfig.UseSsl
        }
        if ($cred) { $params['Credential'] = $cred }
        Send-MailMessage @params
    } catch {
        Write-Warning "Failed to send email certificate report: $_"
    }
}

function Write-SharePointCertificateItems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$SharePointConfig,
        [Parameter(Mandatory)][array]$Certificates,
        [datetime]$ScanTime = (Get-Date)
    )

    $real = $Certificates | Where-Object { $null -ne $_.DaysRemaining }
    if (-not $real -or $real.Count -eq 0) { return }

    $targetListId = $SharePointConfig.CertificateListId
    if (-not $targetListId -or $targetListId -eq 'REPLACE_ME') {
        Write-Warning "No SharePoint list ID configured for certificate items (set SharePointConfig.CertificateListId)."
        return
    }

    try {
        $token = Get-GraphAccessToken -TenantId $SharePointConfig.TenantId -ClientId $SharePointConfig.ClientId `
            -CertificateThumbprint $SharePointConfig.CertificateThumbprint

        $headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
        $uri = "https://graph.microsoft.com/v1.0/sites/$($SharePointConfig.SiteId)/lists/$targetListId/items"

        foreach ($c in $real) {
            $body = @{
                fields = @{
                    Title         = $c.Subject
                    Severity      = $c.Severity
                    DaysRemaining = $c.DaysRemaining
                    NotAfter      = if ($c.NotAfter) { $c.NotAfter.ToString('o') } else { '' }
                    Issuer        = $c.Issuer
                    Sources       = $c.Sources
                    Locations     = $c.Locations
                    Thumbprint    = $c.Id
                    ScanTime      = $ScanTime.ToString('o')
                }
            } | ConvertTo-Json -Depth 5

            Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $body | Out-Null
        }
    } catch {
        Write-Warning "Failed to write certificate items to SharePoint: $_"
    }
}

function Send-TeamsSoftwareExposureAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WebhookUrl,
        [Parameter(Mandatory)][array]$VulnerableHits
    )

    if (-not $VulnerableHits -or $VulnerableHits.Count -eq 0) { return }

    $top = $VulnerableHits | Select-Object -First 15
    $facts = $top | ForEach-Object {
        $ransomTag = if ($_.KnownRansomwareCampaignUse -eq 'Known') { ' [RANSOMWARE]' } else { '' }
        @{
            title = "$($_.CveId)$ransomTag - $($_.SoftwareName) $($_.SoftwareVersion)"
            value = "Host: $($_.ComputerName) ($($_.Category)) | $($_.VulnerabilityName)"
        }
    }
    if ($VulnerableHits.Count -gt 15) {
        $facts += @{ title = '...'; value = "$($VulnerableHits.Count - 15) more exposure(s) in the full report." }
    }

    $card = @{
        '@type'    = 'MessageCard'
        '@context' = 'http://schema.org/extensions'
        summary    = "Software Inventory: $($VulnerableHits.Count) zero-day exposure(s) found"
        themeColor = 'C0392B'
        title      = "Zero-Day Exposure via Installed Software - $($VulnerableHits.Count) hit(s)"
        sections   = @(@{ activityTitle = 'Installed software matching the CISA KEV / NVD watchlist'; facts = $facts })
    }

    try {
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body ($card | ConvertTo-Json -Depth 8) -ContentType 'application/json'
    } catch {
        Write-Warning "Failed to send Teams software exposure alert: $_"
    }
}

function Send-EmailSoftwareExposureAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$EmailConfig,
        [Parameter(Mandatory)][array]$VulnerableHits
    )

    if (-not $EmailConfig.Enabled -or -not $VulnerableHits) { return }

    try {
        $table = _Build-HtmlTable -Rows $VulnerableHits -Columns @('ComputerName','Category','SoftwareName','SoftwareVersion','CveId','VulnerabilityName','KnownRansomwareCampaignUse')
        $body  = "<h2 style=`"color:#c0392b`">Zero-Day Exposure via Installed Software - $($VulnerableHits.Count) hit(s)</h2>$table"
        $cred  = _Get-EmailCredential -EmailConfig $EmailConfig

        $params = @{
            To         = $EmailConfig.To
            From       = $EmailConfig.From
            Subject    = "[AD-Agent] Software Zero-Day Exposure - $($VulnerableHits.Count) hit(s) - $(Get-Date -Format 'yyyy-MM-dd')"
            Body       = $body
            BodyAsHtml = $true
            SmtpServer = $EmailConfig.SmtpServer
            Port       = $EmailConfig.Port
            UseSsl     = $EmailConfig.UseSsl
        }
        if ($cred) { $params['Credential'] = $cred }
        Send-MailMessage @params
    } catch {
        Write-Warning "Failed to send email software exposure alert: $_"
    }
}

Export-ModuleMember -Function Send-TeamsAlert, Write-SharePointListItem, Get-GraphAccessToken, `
    Send-TeamsComplianceReport, Write-SharePointComplianceItems, `
    Send-EmailAlert, Send-EmailComplianceReport, `
    Send-TeamsZeroDayAlert, Send-EmailZeroDayAlert, `
    Send-TeamsCertificateReport, Send-EmailCertificateReport, Write-SharePointCertificateItems, `
    Send-TeamsSoftwareExposureAlert, Send-EmailSoftwareExposureAlert

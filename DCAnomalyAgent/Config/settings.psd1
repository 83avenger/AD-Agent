@{
    # Domain Controllers to scan via WinRM
    DomainControllers = @(
        'dc01.contoso.com'
        'dc02.contoso.com'
    )

    # Lookback window in hours. Should exceed the scan interval to tolerate missed runs.
    LookbackHours = 9

    # Well-known privileged group names to monitor for membership changes
    PrivilegedGroups = @(
        'Domain Admins'
        'Enterprise Admins'
        'Schema Admins'
        'Administrators'
        'Account Operators'
        'Backup Operators'
    )

    # Rule thresholds
    FailedLogonBurstThreshold = 5
    NewAccountToPrivilegedGroupWindowHours = 24

    # Baseline (UEBA-lite) settings
    Baseline = @{
        StatePath               = "$PSScriptRoot\..\State\baseline.json"
        MinObservationsBeforeFlagging = 5
        DecayFactor             = 0.9
    }

    # Reporting targets
    Reporting = @{
        Teams = @{
            Enabled    = $true
            WebhookUrl = 'https://contoso.webhook.office.com/REPLACE_ME'
        }
        SharePoint = @{
            Enabled  = $true
            TenantId = '00000000-0000-0000-0000-000000000000'
            ClientId = '00000000-0000-0000-0000-000000000000'
            # Certificate thumbprint for cert-based auth (cert must be installed in the
            # running gMSA's accessible certificate store). No secrets stored here.
            CertificateThumbprint = 'REPLACE_ME'
            SiteId   = 'REPLACE_ME'
            ListId   = 'REPLACE_ME'   # Anomaly events list
            ComplianceListId = 'REPLACE_ME'  # Compliance gap items list (separate list)
            # When false, only anomalies are written; when true, every scan run is logged.
            LogEveryScan = $false
        }
    }

    # Compliance scanning
    Compliance = @{
        Enabled          = $true
        FrameworkPath    = "$PSScriptRoot\compliance-frameworks.psd1"
        # Filter by framework name (e.g. 'CIS','NIST','ISO') or leave empty for all
        FrameworkFilter  = @()
        # Filter by severity or leave empty for all: 'Critical','High','Medium','Low'
        SeverityFilter   = @()
        # Path where the full markdown report is saved locally after each scan
        ReportOutputPath = "$PSScriptRoot\..\State\compliance-report.md"
    }

    LogPath = "$PSScriptRoot\..\State\scan.log"
}

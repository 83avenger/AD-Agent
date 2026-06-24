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
        # One or more framework files. The DC framework holds domain-wide + DC checks;
        # the endpoints framework holds host-level checks for member servers/workstations.
        FrameworkPath    = @(
            "$PSScriptRoot\compliance-frameworks.psd1"
            "$PSScriptRoot\compliance-endpoints.psd1"
            "$PSScriptRoot\compliance-linux.psd1"
        )
        # Filter by framework name (e.g. 'CIS','NIST','ISO') or leave empty for all
        FrameworkFilter  = @()
        # Filter by severity or leave empty for all: 'Critical','High','Medium','Low'
        SeverityFilter   = @()
        # Path where the full markdown report is saved locally after each scan
        ReportOutputPath = "$PSScriptRoot\..\State\compliance-report.md"
    }

    # Asset inventory — targets for compliance scanning by asset type.
    # Each AssetType runs only the controls whose AppliesTo includes that type.
    # You can list hosts explicitly, or set DiscoverFromAD = $true to auto-enumerate.
    Assets = @{
        DomainController = @{
            # Defaults to the DomainControllers list above when empty
            Hosts         = @()
            DiscoverFromAD = $true   # uses Get-ADDomainController -Filter *
        }
        MemberServer = @{
            Hosts         = @('app01.contoso.com','sql01.contoso.com')
            DiscoverFromAD = $false  # set $true to auto-enumerate server OS computers from AD
        }
        Workstation = @{
            Hosts         = @()
            DiscoverFromAD = $false  # set $true to auto-enumerate client OS computers from AD
        }
        Linux = @{
            Hosts         = @('web01.contoso.com','web02.contoso.com')
            DiscoverFromAD = $false  # most Linux hosts are found via network discovery, not AD
            # SSH connection context for Linux checks. Uses the Windows OpenSSH client.
            # Key-based, non-interactive auth; the key must be readable by the gMSA.
            Ssh = @{
                User    = 'svc-scan'
                KeyPath = "$PSScriptRoot\..\State\ssh\id_ed25519"
                Port    = 22
            }
        }
    }

    # Asset discovery (used by Run-Discovery.ps1 when no switches are passed)
    Discovery = @{
        FromAD  = $true
        Subnets = @()   # e.g. @('10.0.0.0/24','10.0.1.0/24') for network scanning
    }

    LogPath = "$PSScriptRoot\..\State\scan.log"
}

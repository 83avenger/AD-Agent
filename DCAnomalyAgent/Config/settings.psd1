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
        Email = @{
            Enabled           = $false
            To                = @('security-team@contoso.com')
            From              = 'dcagent@contoso.com'
            SmtpServer        = 'smtp.contoso.com'
            Port              = 587
            UseSsl            = $true
            # Leave CredentialUser empty to use an unauthenticated SMTP relay.
            # If auth is required, set CredentialUser and store the password as a
            # ConvertFrom-SecureString export (run once interactively as the gMSA):
            #   Read-Host -AsSecureString | ConvertFrom-SecureString
            # Paste the resulting string into CredentialPassword.
            CredentialUser     = ''
            CredentialPassword = ''
            # Minimum severity level to include in the email body (Critical/High/Medium/Low).
            MinSeverity        = 'High'
            # Set $true to send a summary email even when there are no findings.
            SendOnNoFindings   = $false
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
            "$PSScriptRoot\compliance-hipaa.psd1"
            "$PSScriptRoot\compliance-owasp.psd1"
        )
        # Filter by framework name (e.g. 'CIS','NIST','ISO','HIPAA','OWASP') or leave empty for all
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
        WebApplication = @{
            # HTTPS endpoints for OWASP posture checks — probed directly from the
            # jump server (headers/TLS/cookies), no agent or credentials needed.
            # Bare hostnames are probed as https://<host>.
            Hosts         = @('https://intranet.contoso.com')
            DiscoverFromAD = $false
        }
    }

    # Asset discovery (used by Run-Discovery.ps1 when no switches are passed)
    Discovery = @{
        FromAD  = $true
        Subnets = @()   # e.g. @('10.0.0.0/24','10.0.1.0/24') for network scanning
    }

    # Zero-day / CVE telemetry
    # Pulls the CISA Known Exploited Vulnerabilities (KEV) catalog daily and optionally
    # queries NVD for additional coverage. Alerts only on CVEs newly added since the last run.
    ZeroDay = @{
        Enabled          = $true
        # Set $true on air-gapped servers — reads State\kev-cache.json instead of fetching live.
        Offline          = $false
        ProductsPath     = "$PSScriptRoot\zeroday-products.psd1"
        CacheDir         = "$PSScriptRoot\..\State"
        # Alert when a new KEV entry matches a watched product.
        AlertOnNew       = $true
        # Also alert if a matching KEV entry has a CISA due date within N days (0 = disabled).
        AlertDueDateDays = 7
    }

    LogPath = "$PSScriptRoot\..\State\scan.log"
}

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
            CertificateListId = 'REPLACE_ME' # Expiring-certificate items list (separate list)
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

    # Asset inventory - targets for compliance scanning by asset type.
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
            # HTTPS endpoints for OWASP posture checks - probed directly from the
            # jump server (headers/TLS/cookies), no agent or credentials needed.
            # Bare hostnames are probed as https://<host>.
            Hosts         = @('https://intranet.contoso.com')
            DiscoverFromAD = $false
        }
    }

    # Asset discovery (used by Run-Discovery.ps1 when no switches are passed)
    Discovery = @{
        FromAD  = $true
        # Any mix of prefix sizes is fine (supported range: /16-/32). Replace these
        # placeholder examples with your real ranges, or leave @() to skip network
        # scanning and rely on AD-only discovery (FromAD above).
        Subnets = @(
            # '10.0.0.0/24'      # example: a full /24 (254 usable hosts)
            # '10.0.1.0/25'      # example: a /25 (126 usable hosts)
            # '10.0.1.128/25'    # example: the other half of that /24
            # '192.168.10.0/26'  # example: a smaller /26 (62 usable hosts)
        )
        # Cloudflare WARP/Zero Trust virtual IP range(s) assigned to remote/home users
        # connecting into the network. Scanned the same way as Subnets above, but tagged
        # with Source = 'Cloudflare WARP' so remote devices are distinguishable on the
        # Discovery dashboard from on-prem LAN hosts. Get the exact range from your
        # Cloudflare Zero Trust dashboard (Settings > WARP Client > Device settings profile
        # > Split Tunnels, or the tunnel's configured private network route).
        # A future enhancement can pull device/user identity directly from the Cloudflare
        # Zero Trust API instead of relying on a port scan; for now this just extends the
        # network scan to that range so those hosts show up like any other discovered asset.
        CloudflareWarpSubnets = @(
            # '100.96.0.0/12'  # example only - replace with your actual WARP-assigned range
        )
    }

    # Zero-day / CVE telemetry
    # Pulls the CISA Known Exploited Vulnerabilities (KEV) catalog daily and optionally
    # queries NVD for additional coverage. Alerts only on CVEs newly added since the last run.
    ZeroDay = @{
        Enabled          = $true
        # Set $true on air-gapped servers - reads State\kev-cache.json instead of fetching live.
        Offline          = $false
        ProductsPath     = "$PSScriptRoot\zeroday-products.psd1"
        CacheDir         = "$PSScriptRoot\..\State"
        # Alert when a new KEV entry matches a watched product.
        AlertOnNew       = $true
        # Also alert if a matching KEV entry has a CISA due date within N days (0 = disabled).
        AlertDueDateDays = 7
    }

    # Certificate expiry scanning
    # Scans Windows machine stores (WinRM), live TLS endpoints (socket probe), and
    # optionally an Enterprise CA, then reports any certificate expiring within
    # ThresholdDays. Reuses the Assets{} inventory for machine-store host resolution.
    Certificates = @{
        Enabled        = $true
        ThresholdDays  = 90
        # Windows asset types to sweep machine certificate stores on.
        ScanAssetTypes = @('DomainController', 'MemberServer', 'Workstation')
        MachineStores  = @('My', 'CA', 'WebHosting')
        # Extra TLS endpoints to probe (load balancers, appliances, non-Windows services).
        EndpointsPath  = "$PSScriptRoot\certificate-endpoints.psd1"
        # Auto-probe LDAPS (636) on every Domain Controller and HTTPS (443) on every
        # WebApplication host from the Assets block.
        ProbeDcLdaps   = $true
        ProbeWebApps   = $true
        # AD Certificate Services (optional - needs read access to the CA).
        Adcs = @{
            Enabled  = $false
            CaConfig = ''   # e.g. 'CA01.contoso.com\Contoso-Issuing-CA'
        }
        ReportOutputPath = "$PSScriptRoot\..\State\certificate-report.md"
    }

    # Installed-software inventory. Enumerates installed products (name/version/
    # publisher) on every configured Windows asset over WinRM, categorizes hosts as
    # Desktop/Laptop/Server/Domain Controller, and optionally cross-references
    # installed versions against the zero-day watchlist to flag actual exposure.
    SoftwareInventory = @{
        Enabled        = $true
        ScanAssetTypes = @('DomainController', 'MemberServer', 'Workstation')
        # Flag installed software matching a product in the CISA KEV / NVD watchlist
        # (Config/zeroday-products.psd1). Requires the ZeroDay module/feed.
        CrossReferenceZeroDay = $true
        ReportOutputPath = "$PSScriptRoot\..\State\software-inventory-report.md"
    }

    # Third-party integrations that extend discovery beyond what an agentless
    # WinRM/TCP scan alone can see. All disabled/empty until credentials are
    # supplied by the relevant team - see the web UI's Integrations page for what
    # to request from each team. None of these are required for core discovery,
    # compliance, anomaly, certificate, or software-inventory scanning to work.
    Integrations = @{
        # SNMP read-only polling of network-attached, non-Windows devices that
        # already show up in a network scan as NetworkDevice/Unknown (Printers,
        # Switches, Access Points, IP Phones, Cameras, Firewalls). Enables pulling
        # sysDescr/model/firmware instead of just "port 161 is open".
        Snmp = @{
            Enabled   = $false
            Version   = 'v2c'   # 'v2c' (community string) or 'v3' (per-device credentials)
            Community = ''      # v2c read-only community string
            V3 = @{
                Username     = ''
                AuthProtocol = 'SHA'
                AuthPassword = ''
                PrivProtocol = 'AES'
                PrivPassword = ''
            }
        }

        # Vendor warranty/asset APIs, used to resolve a Windows host's BIOS serial
        # number (already collectible over WinRM) to a ship/purchase date, so
        # device age can be reported without needing a separate CMDB.
        VendorWarranty = @{
            Enabled = $false
            # API keys (Dell TechDirect / HP Warranty / Lenovo Support) are entered and
            # saved separately, from the web UI's Integrations > Vendor Warranty page -
            # they're written to Config/integration-secrets.json (gitignored) instead of
            # here, so real secrets never end up committed to source control. See
            # Modules/DCAnomalyAgent.VendorWarranty.psm1 -> Get-VendorWarrantySecrets.
            AgeAlertYears = 4   # flag devices at/above this age once populated
        }

        # MDM-managed devices (kiosks/IoT-VLAN tablets, fully-managed Android
        # phones on Wi-Fi) are not reachable by our LAN/WinRM scan - only their
        # MDM's own API can enumerate and detail them.
        Mdm = @{
            Enabled  = $false
            Provider = ''   # 'Intune' | 'Jamf' | 'AndroidEnterprise'
            Intune = @{ TenantId = ''; ClientId = ''; ClientSecret = '' }
            Jamf   = @{ Url = ''; ClientId = ''; ClientSecret = '' }
            AndroidEnterprise = @{ EnterpriseId = ''; ServiceAccountKeyPath = '' }
        }

        # Cloudflare Zero Trust API - device/user identity for WARP-connected
        # remote users, as a richer alternative to just scanning the WARP IP
        # range (which Discovery already does). Documented future enhancement.
        CloudflareZeroTrust = @{
            Enabled  = $false
            ApiToken = ''
            AccountId = ''
        }
    }

    # Rotating dashboard snapshot. Every scan run merges its section(s) into this
    # file; the web UI dashboard reads it. Because each scheduled task runs one
    # scan type, the merge preserves the other sections from prior runs.
    Dashboard = @{
        SnapshotPath = "$PSScriptRoot\..\State\latest-scan.json"
    }

    LogPath = "$PSScriptRoot\..\State\scan.log"
}

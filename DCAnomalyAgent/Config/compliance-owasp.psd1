@{
    # ─────────────────────────────────────────────────────────────────────────
    # OWASP web application security controls (OWASP Top 10:2021 + ASVS v4).
    #
    # These target the 'WebApplication' asset type: HTTPS endpoints (intranet
    # portals, APIs, appliances) probed directly from the jump server — no agent,
    # no WinRM, no credentials. Targets are URLs or hostnames configured under
    # Assets.WebApplication.Hosts in settings.psd1; bare hostnames are probed
    # as https://<host>.
    #
    # This is passive posture checking (headers, TLS, cookies) — NOT a DAST
    # scanner. For active testing pair with OWASP ZAP and feed results into the
    # same SharePoint list.
    # ─────────────────────────────────────────────────────────────────────────
    Controls = @(

        # ── TRANSPORT — A02:2021 Cryptographic Failures ──────────────────────
        @{
            Id          = 'OW-TLS-001'
            Title       = 'Legacy TLS 1.0/1.1 Rejected by Server'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A02:2021'; ASVS = 'V9.1.3'; NIST = 'SC-8(1)'; ISO = 'A.13.2.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $target = $ComputerName -replace '^https?://' -replace '/.*$'
                $accepted = @()
                foreach ($proto in @([System.Security.Authentication.SslProtocols]::Tls, [System.Security.Authentication.SslProtocols]::Tls11)) {
                    $tcp = $null; $ssl = $null
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient($target, 443)
                        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
                        $ssl.AuthenticateAsClient($target, $null, $proto, $false)
                        $accepted += "$proto"
                    } catch { } finally {
                        if ($ssl) { $ssl.Dispose() }
                        if ($tcp) { $tcp.Dispose() }
                    }
                }
                [pscustomobject]@{
                    Actual = if ($accepted) { "Server accepted: $($accepted -join ', ')" } else { 'TLS 1.0/1.1 rejected' }
                    Pass   = $accepted.Count -eq 0
                }
            }
            Expected    = 'TLS 1.0 and 1.1 handshakes rejected; TLS 1.2+ only'
            Remediation = 'Disable TLS 1.0/1.1 on the web server or load balancer (IIS: SChannel registry; nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3).'
        }

        @{
            Id          = 'OW-RD-001'
            Title       = 'HTTP Redirects to HTTPS'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A02:2021'; ASVS = 'V9.1.1'; NIST = 'SC-8'; ISO = 'A.13.2.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $target = $ComputerName -replace '^https?://' -replace '/.*$'
                try {
                    $resp = Invoke-WebRequest -Uri "http://$target/" -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 15 -ErrorAction SilentlyContinue
                } catch { $resp = $_.Exception.Response }
                if (-not $resp) {
                    # Port 80 closed entirely also passes — HTTPS-only service
                    return [pscustomobject]@{ Actual = 'Port 80 unreachable (HTTPS-only)'; Pass = $true }
                }
                $code = [int]$resp.StatusCode
                $loc  = "$($resp.Headers['Location'])"
                [pscustomobject]@{
                    Actual = "HTTP $code, Location: $loc"
                    Pass   = ($code -ge 301 -and $code -le 308 -and $loc -like 'https://*')
                }
            }
            Expected    = 'Plain-HTTP requests answered with a 301/308 redirect to https://, or port 80 closed'
            Remediation = 'Configure a permanent redirect from HTTP to HTTPS at the web server or load balancer; do not serve content over plain HTTP.'
        }

        # ── SECURITY HEADERS — A05:2021 Security Misconfiguration ────────────
        @{
            Id          = 'OW-HDR-001'
            Title       = 'HSTS Header Present (Strict-Transport-Security)'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A05:2021'; ASVS = 'V14.4.5'; NIST = 'SC-8'; ISO = 'A.13.2.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $url = if ($ComputerName -match '^https?://') { $ComputerName } else { "https://$ComputerName" }
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
                $hsts = "$($resp.Headers['Strict-Transport-Security'])"
                [pscustomobject]@{ Actual = if ($hsts) { $hsts } else { 'Header missing' }; Pass = $hsts -match 'max-age=\d{4,}' }
            }
            Expected    = 'Strict-Transport-Security with max-age >= 1000 seconds (recommend 31536000)'
            Remediation = 'Add header Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses.'
        }

        @{
            Id          = 'OW-HDR-002'
            Title       = 'X-Content-Type-Options: nosniff'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A05:2021'; ASVS = 'V14.4.4'; NIST = 'SC-18'; ISO = 'A.14.1.2' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $url = if ($ComputerName -match '^https?://') { $ComputerName } else { "https://$ComputerName" }
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
                $v = "$($resp.Headers['X-Content-Type-Options'])"
                [pscustomobject]@{ Actual = if ($v) { $v } else { 'Header missing' }; Pass = $v -eq 'nosniff' }
            }
            Expected    = 'X-Content-Type-Options: nosniff on all responses'
            Remediation = 'Add the X-Content-Type-Options: nosniff response header at the web server or application level.'
        }

        @{
            Id          = 'OW-HDR-003'
            Title       = 'Content-Security-Policy Header Present'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A03:2021'; ASVS = 'V14.4.3'; NIST = 'SI-10'; ISO = 'A.14.1.2' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $url = if ($ComputerName -match '^https?://') { $ComputerName } else { "https://$ComputerName" }
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
                $csp = "$($resp.Headers['Content-Security-Policy'])"
                [pscustomobject]@{ Actual = if ($csp) { $csp.Substring(0, [math]::Min(120, $csp.Length)) } else { 'Header missing' }; Pass = [bool]$csp }
            }
            Expected    = 'A Content-Security-Policy header restricting script/style sources (XSS defence-in-depth)'
            Remediation = "Define a CSP starting from default-src 'self' and add sources as needed. Deploy in Content-Security-Policy-Report-Only mode first to find breakage."
        }

        @{
            Id          = 'OW-HDR-004'
            Title       = 'Clickjacking Protection (X-Frame-Options or frame-ancestors)'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A05:2021'; ASVS = 'V14.4.7'; NIST = 'SC-18'; ISO = 'A.14.1.2' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $url = if ($ComputerName -match '^https?://') { $ComputerName } else { "https://$ComputerName" }
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
                $xfo = "$($resp.Headers['X-Frame-Options'])"
                $csp = "$($resp.Headers['Content-Security-Policy'])"
                $ok  = ($xfo -match 'DENY|SAMEORIGIN') -or ($csp -match 'frame-ancestors')
                [pscustomobject]@{ Actual = "X-Frame-Options: $(if ($xfo) { $xfo } else { 'missing' }); CSP frame-ancestors: $($csp -match 'frame-ancestors')"; Pass = $ok }
            }
            Expected    = 'X-Frame-Options: DENY/SAMEORIGIN, or CSP frame-ancestors directive'
            Remediation = "Add X-Frame-Options: SAMEORIGIN, or (preferred) a CSP frame-ancestors 'self' directive."
        }

        # ── INFORMATION DISCLOSURE — A05:2021 ────────────────────────────────
        @{
            Id          = 'OW-INF-001'
            Title       = 'Server Version Not Disclosed in Response Headers'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A05:2021'; ASVS = 'V14.3.3'; NIST = 'CM-7'; ISO = 'A.12.6.1' }
            Severity    = 'Low'
            Check       = {
                param($ComputerName)
                $url = if ($ComputerName -match '^https?://') { $ComputerName } else { "https://$ComputerName" }
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
                $server  = "$($resp.Headers['Server'])"
                $powered = "$($resp.Headers['X-Powered-By'])"
                $leaky = ($server -match '\d') -or [bool]$powered
                [pscustomobject]@{ Actual = "Server: $(if ($server) { $server } else { 'none' }); X-Powered-By: $(if ($powered) { $powered } else { 'none' })"; Pass = -not $leaky }
            }
            Expected    = 'No version number in Server header; no X-Powered-By header'
            Remediation = 'Strip or genericize the Server header and remove X-Powered-By (IIS: removeServerHeader/requestFiltering; nginx: server_tokens off; Apache: ServerTokens Prod; PHP: expose_php=Off).'
        }

        # ── SESSION — A05/A07:2021 ───────────────────────────────────────────
        @{
            Id          = 'OW-CK-001'
            Title       = 'Cookies Set With Secure and HttpOnly Flags'
            AppliesTo   = @('WebApplication')
            Frameworks  = @{ OWASP = 'A05:2021'; ASVS = 'V3.4.1'; NIST = 'SC-23'; ISO = 'A.14.1.3' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $url = if ($ComputerName -match '^https?://') { $ComputerName } else { "https://$ComputerName" }
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
                $setCookies = @($resp.Headers['Set-Cookie'])
                if (-not $setCookies -or -not $setCookies[0]) {
                    return [pscustomobject]@{ Actual = 'No cookies set on landing page'; Pass = $true }
                }
                $bad = $setCookies | Where-Object { $_ -notmatch '(?i)secure' -or $_ -notmatch '(?i)httponly' }
                [pscustomobject]@{
                    Actual = "$(@($setCookies).Count) cookie(s); $(@($bad).Count) missing Secure/HttpOnly"
                    Pass   = @($bad).Count -eq 0
                }
            }
            Expected    = 'Every Set-Cookie carries both Secure and HttpOnly attributes'
            Remediation = 'Set Secure and HttpOnly (and SameSite=Lax/Strict) on all cookies in the application framework or via web server rewrite rules.'
        }
    )
}

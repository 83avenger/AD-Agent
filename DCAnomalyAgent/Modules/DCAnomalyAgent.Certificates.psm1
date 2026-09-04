#Requires -Version 5.1
<#
.SYNOPSIS
    Certificate expiry scanning. Collects certificates from three sources -
    Windows machine stores (over WinRM), live TLS endpoints (socket probe), and
    an AD Certificate Services / Enterprise CA (certutil) - then flags any that
    expire within a configurable threshold (default 90 days).

.DESCRIPTION
    Mirrors the collectors -> detector -> formatter shape of the anomaly and
    compliance modules. Every collector is resilient: an unreachable host, a
    closed port, or an inaccessible CA records an error object and keeps going,
    so a single failure never aborts the scan.

    Common certificate object shape returned by every collector:
        Source        MachineStore | TlsEndpoint | ADCS
        ComputerName  host the cert was found on / probed
        Location      store path or 'host:port' or CA config
        Subject, Issuer, Thumbprint
        NotBefore, NotAfter  [datetime]
        DnsNames      SAN entries (string, comma-joined)
        FriendlyName
        HasPrivateKey [bool] (machine store only; $null otherwise)
        Error         populated only on collection failure
#>

# Issuers we treat as trust-store noise rather than operational certs.
$script:RootIssuerNoise = @(
    'Microsoft Root'
    'Microsoft Authenticode'
    'Microsoft Time-Stamp'
    'Microsoft ECC'
    'Microsoft RSA Root'
    'DigiCert'
    'Baltimore CyberTrust'
    'VeriSign'
    'Thawte'
    'GlobalSign'
    'Go Daddy'
    'Entrust'
    'USERTrust'
    'AddTrust'
    'Sectigo'
    'ISRG Root'      # Let's Encrypt root/intermediate certs in the CA store
)

function Test-IsLocalCertHost {
    <#
    .SYNOPSIS
        Is this target the machine we're running on?
    .DESCRIPTION
        Calling Invoke-Command against your own FQDN fails Kerberos loopback
        authentication with "Access is denied" even for an elevated admin - a Windows
        quirk, not a permissions gap. DCAnomalyAgent.SoftwareInventory.psm1 solved this
        with Test-IsLocalComputer; the same predicate is duplicated here rather than
        imported so the certificate scan has no load-order dependency on the software
        inventory module (they run independently and either may be imported alone).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)

    $n = $ComputerName.Trim()
    if ($n -in @('localhost', '.', '127.0.0.1', '::1')) { return $true }
    if ($n -eq $env:COMPUTERNAME) { return $true }
    try {
        $entry = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME)
        $localFqdn = $entry.HostName
        if ($n -eq $localFqdn) { return $true }
        if ($n.Split('.')[0] -eq $localFqdn.Split('.')[0]) { return $true }
        # Targets often arrive as IP addresses (a discovery scan or a typed range
        # produces nothing else), and an IP never matches a name comparison. Worse,
        # WinRM refuses an IP target outright - "Default authentication may be used
        # with an IP address under the following conditions..." - so without this the
        # local host fails to report its own certificates purely because it was named
        # by address rather than by hostname.
        if ($entry.AddressList | Where-Object { $_.IPAddressToString -eq $n }) { return $true }
    } catch { }
    return $false
}

function Resolve-CertTargetName {
    <#
    .SYNOPSIS
        Turns an IP address into a resolvable host name for WinRM.
    .DESCRIPTION
        WinRM will not do Kerberos against a bare IP address; it fails with
        "Default authentication may be used with an IP address under the following
        conditions: the transport is HTTPS or the destination is in the TrustedHosts
        list". Reverse-resolving to the FQDN first makes the same target work with the
        authentication that is already configured, instead of asking every operator to
        edit TrustedHosts. Non-IP input, and IPs with no PTR record, are returned
        unchanged so behavior is never worse than before.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)

    $n = $ComputerName.Trim()
    $parsed = [System.Net.IPAddress]::None
    if (-not [System.Net.IPAddress]::TryParse($n, [ref]$parsed)) { return $n }
    try {
        $host_ = [System.Net.Dns]::GetHostEntry($n).HostName
        if ($host_ -and $host_ -ne $n) { return $host_ }
    } catch { }
    return $n
}

function Get-MachineCertificate {
    <#
    .SYNOPSIS
        Enumerates certificates from LocalMachine stores on a remote Windows host over WinRM.
    .PARAMETER Stores
        Store names under Cert:\LocalMachine to scan. Default: My, CA, WebHosting.
    .PARAMETER IncludeRoots
        Include well-known public/Microsoft trust-store certs (normally filtered out).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [string[]]$Stores = @('My', 'CA', 'WebHosting'),
        [switch]$IncludeRoots
    )

    # Collect the stores locally when the target IS this machine (see
    # Test-IsLocalCertHost) - otherwise the jump server can never report its own
    # certificates, which is exactly the host an operator checks first.
    $collectScript = {
            param($stores)
            foreach ($store in $stores) {
                $path = "Cert:\LocalMachine\$store"
                if (-not (Test-Path $path)) { continue }
                Get-ChildItem -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $sans = @()
                    try {
                        $ext = $_.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
                        if ($ext) { $sans = ($ext.Format($false) -split ',\s*') }
                    } catch { }
                    [pscustomobject]@{
                        StoreName     = $store
                        Subject       = $_.Subject
                        Issuer        = $_.Issuer
                        Thumbprint    = $_.Thumbprint
                        NotBefore     = $_.NotBefore
                        NotAfter      = $_.NotAfter
                        DnsNames      = ($sans -join ', ')
                        FriendlyName  = $_.FriendlyName
                        HasPrivateKey = $_.HasPrivateKey
                    }
                }
            }
    }

    try {
        $raw = if (Test-IsLocalCertHost -ComputerName $ComputerName) {
            & $collectScript $Stores
        } else {
            Invoke-Command -ComputerName (Resolve-CertTargetName -ComputerName $ComputerName) `
                -ScriptBlock $collectScript -ArgumentList (, $Stores)
        }
    } catch {
        return [pscustomobject]@{
            Source = 'MachineStore'; ComputerName = $ComputerName; Location = 'Cert:\LocalMachine'
            Subject = $null; Issuer = $null; Thumbprint = $null
            NotBefore = $null; NotAfter = $null; DnsNames = $null; FriendlyName = $null
            HasPrivateKey = $null; Error = "WinRM/collection failed: $_"
        }
    }

    $results = foreach ($c in $raw) {
        if (-not $IncludeRoots) {
            $issuer = "$($c.Issuer)"
            if ($script:RootIssuerNoise | Where-Object { $issuer -like "*$_*" }) { continue }
            # Skip self-signed roots (Subject == Issuer) unless they carry a private key (operational)
            if ($c.Subject -eq $c.Issuer -and -not $c.HasPrivateKey) { continue }
        }
        [pscustomobject]@{
            Source        = 'MachineStore'
            ComputerName  = $ComputerName
            Location      = "Cert:\LocalMachine\$($c.StoreName)"
            Subject       = $c.Subject
            Issuer        = $c.Issuer
            Thumbprint    = $c.Thumbprint
            NotBefore     = $c.NotBefore
            NotAfter      = $c.NotAfter
            DnsNames      = $c.DnsNames
            FriendlyName  = $c.FriendlyName
            HasPrivateKey = $c.HasPrivateKey
            Error         = $null
        }
    }
    return $results
}

function Get-EndpointCertificate {
    <#
    .SYNOPSIS
        Retrieves the server certificate presented by a TLS endpoint via socket probe.
    .DESCRIPTION
        Does NOT validate the trust chain - the callback accepts any cert so we can
        inspect even self-signed / expired certs. Reuses the SslStream pattern from
        the OWASP compliance control OW-TLS-001.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TargetHost,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 5000
    )

    $tcp = $null; $ssl = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            throw "connection timed out after ${TimeoutMs}ms"
        }
        $tcp.EndConnect($iar)

        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
        $ssl.AuthenticateAsClient($TargetHost)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)

        $sans = ''
        try {
            $ext = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
            if ($ext) { $sans = ($ext.Format($false) -split ',\s*') -join ', ' }
        } catch { }

        [pscustomobject]@{
            Source        = 'TlsEndpoint'
            ComputerName  = $TargetHost
            Location      = "${TargetHost}:${Port}"
            Subject       = $cert.Subject
            Issuer        = $cert.Issuer
            Thumbprint    = $cert.Thumbprint
            NotBefore     = $cert.NotBefore
            NotAfter      = $cert.NotAfter
            DnsNames      = $sans
            FriendlyName  = $cert.FriendlyName
            HasPrivateKey = $null
            Error         = $null
        }
    } catch {
        [pscustomobject]@{
            Source = 'TlsEndpoint'; ComputerName = $TargetHost; Location = "${TargetHost}:${Port}"
            Subject = $null; Issuer = $null; Thumbprint = $null
            NotBefore = $null; NotAfter = $null; DnsNames = $null; FriendlyName = $null
            HasPrivateKey = $null; Error = "TLS probe failed: $_"
        }
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

function Get-CaIssuedCertificate {
    <#
    .SYNOPSIS
        Queries an Enterprise CA for issued (Disposition=20) certificates expiring
        on or before the threshold date, via certutil.
    .PARAMETER CaConfig
        CA config string, e.g. 'CA01.contoso.com\Contoso-Issuing-CA'.
    .PARAMETER ThresholdDays
        Only return certs whose NotAfter is within this many days.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CaConfig,
        [int]$ThresholdDays = 90
    )

    $cutoff = (Get-Date).AddDays($ThresholdDays).ToString('MM/dd/yyyy')
    try {
        # Disposition 20 = issued. Restrict to certs expiring by the cutoff.
        $restrict = "NotAfter<=$cutoff,Disposition=20"
        $columns  = 'RequestID,CommonName,NotBefore,NotAfter,CertificateTemplate,SerialNumber'
        $out = & certutil -config $CaConfig -view -restrict $restrict -out $columns 2>&1
        if ($LASTEXITCODE -ne 0) { throw "certutil exited $LASTEXITCODE : $out" }

        # Parse certutil row output into records. Rows look like:  "  NotAfter: 1/2/2025 3:04 PM"
        $records = @()
        $current = @{}
        foreach ($line in $out) {
            if ($line -match '^\s*Row \d+:') {
                if ($current.Count) { $records += [pscustomobject]$current }
                $current = @{}
            } elseif ($line -match '^\s*([A-Za-z ]+):\s*(.+?)\s*$') {
                $key = ($matches[1].Trim() -replace '\s', '')
                $current[$key] = $matches[2].Trim() -replace '^"|"$', ''
            }
        }
        if ($current.Count) { $records += [pscustomobject]$current }

        # certutil displays friendly column names that differ from the -out field
        # names and vary by OS/locale, so resolve each value from several candidates.
        function _Field($rec, [string[]]$names) {
            foreach ($n in $names) { if ($rec.PSObject.Properties[$n] -and $rec.$n) { return $rec.$n } }
            return $null
        }

        foreach ($r in $records) {
            $naRaw = _Field $r @('CertificateExpirationDate', 'NotAfter')
            $nbRaw = _Field $r @('CertificateEffectiveDate', 'NotBefore')
            $cn    = _Field $r @('IssuedCommonName', 'CommonName')
            $tmpl  = _Field $r @('CertificateTemplate')
            $reqId = _Field $r @('RequestID')
            $serial = _Field $r @('SerialNumber')

            $na = $null; $nb = $null
            if ($naRaw) { [void][datetime]::TryParse($naRaw, [ref]$na) }
            if ($nbRaw) { [void][datetime]::TryParse($nbRaw, [ref]$nb) }

            [pscustomobject]@{
                Source        = 'ADCS'
                ComputerName  = $CaConfig
                Location      = "CA:$tmpl; ReqID $reqId"
                Subject       = if ($cn) { "CN=$cn" } else { '(unknown)' }
                Issuer        = $CaConfig
                Thumbprint    = $serial
                NotBefore     = $nb
                NotAfter      = $na
                DnsNames      = $null
                FriendlyName  = $tmpl
                HasPrivateKey = $null
                Error         = $null
            }
        }
    } catch {
        [pscustomobject]@{
            Source = 'ADCS'; ComputerName = $CaConfig; Location = $CaConfig
            Subject = $null; Issuer = $null; Thumbprint = $null
            NotBefore = $null; NotAfter = $null; DnsNames = $null; FriendlyName = $null
            HasPrivateKey = $null; Error = "CA query failed: $_"
        }
    }
}

function ConvertTo-CertificateInventory {
    <#
    .SYNOPSIS
        Returns EVERY collected certificate - expiring or not - as a flat inventory.
    .DESCRIPTION
        Find-ExpiringCertificates deliberately narrows to certificates inside the
        alert threshold, which is right for alerting but means a certificate valid
        until 2027 is collected and then discarded. That makes the question "does
        this host have a certificate at all, and which one?" unanswerable - exactly
        the question you have when confirming an IIS binding, tracking down which CA
        issued something, or proving coverage during an audit.

        Same input as Find-ExpiringCertificates, same thumbprint de-duplication, but
        no expiry filter. Adds a Status so the two views agree on what counts as
        expiring rather than each deciding separately.
    .OUTPUTS
        [pscustomobject]: Id (thumbprint), Subject, Issuer, NotBefore, NotAfter,
        DaysRemaining, Status, Severity, Sources, Locations, DnsNames, FriendlyName,
        ComputerName, HasPrivateKey
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][array]$Certificates,
        [int]$ThresholdDays = 90,
        [datetime]$Now = (Get-Date)
    )

    $valid = $Certificates | Where-Object { -not $_.Error -and $_.NotAfter }
    $grouped = $valid | Group-Object Thumbprint

    # @() so a single group doesn't collapse to a bare object - the same trap that
    # produced the op_Addition crash in Find-ExpiringCertificates.
    $inventory = @(foreach ($g in $grouped) {
        $first = $g.Group[0]
        $daysRemaining = [math]::Floor(($first.NotAfter - $Now).TotalDays)
        $status = if ($daysRemaining -lt 0) { 'Expired' }
                  elseif ($daysRemaining -le $ThresholdDays) { 'Expiring' }
                  else { 'Valid' }
        $severity = if ($daysRemaining -lt 0) { 'Critical' }
                    elseif ($daysRemaining -le 14) { 'Critical' }
                    elseif ($daysRemaining -le 30) { 'High' }
                    elseif ($daysRemaining -le 60) { 'Medium' }
                    else { 'Low' }

        [pscustomobject]@{
            Id            = $first.Thumbprint
            Subject       = $first.Subject
            Issuer        = $first.Issuer
            NotBefore     = $first.NotBefore
            NotAfter      = $first.NotAfter
            DaysRemaining = $daysRemaining
            Status        = $status
            Severity      = $severity
            FriendlyName  = $first.FriendlyName
            HasPrivateKey = $first.HasPrivateKey
            ComputerName  = (($g.Group | ForEach-Object { $_.ComputerName } | Where-Object { $_ } | Select-Object -Unique) -join ', ')
            Sources       = (($g.Group.Source | Select-Object -Unique) -join ', ')
            Locations     = (($g.Group | ForEach-Object { "$($_.ComputerName) [$($_.Location)]" } | Select-Object -Unique) -join '; ')
            DnsNames      = $first.DnsNames
        }
    })

    $statusOrder = @{ 'Expired' = 0; 'Expiring' = 1; 'Valid' = 2 }
    return @($inventory | Sort-Object @{ e = { $statusOrder[$_.Status] } }, DaysRemaining)
}

function Find-ExpiringCertificates {
    <#
    .SYNOPSIS
        Filters collected certificates to those expiring within ThresholdDays (or
        already expired), assigns a severity by days remaining, and de-duplicates
        the same certificate found in multiple locations by thumbprint.
    .OUTPUTS
        [pscustomobject] findings: Id (thumbprint), Subject, Issuer, NotAfter,
        DaysRemaining, Severity, Sources, Locations, DnsNames, CollectionErrors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Certificates,
        [int]$ThresholdDays = 90,
        [datetime]$Now = (Get-Date)
    )

    # Surface collection errors as their own findings so unreachable hosts are visible.
    $errors = $Certificates | Where-Object { $_.Error }
    $valid  = $Certificates | Where-Object { -not $_.Error -and $_.NotAfter }

    $limit = $Now.AddDays($ThresholdDays)
    $expiring = $valid | Where-Object { $_.NotAfter -le $limit }

    # Group identical certs (same thumbprint) discovered in multiple places.
    $grouped = $expiring | Group-Object Thumbprint

    # @() forces an array even when $grouped has exactly one element - otherwise
    # "$findings = foreach (...) {...}" collapses to a single unwrapped PSCustomObject,
    # and the "$findings += ..." below then fails trying to call the object's own
    # (nonexistent) + operator instead of PowerShell's array-append behavior.
    $findings = @(foreach ($g in $grouped) {
        $first = $g.Group[0]
        $daysRemaining = [math]::Floor(($first.NotAfter - $Now).TotalDays)
        $severity = if ($daysRemaining -lt 0) { 'Critical' }
                    elseif ($daysRemaining -le 14) { 'Critical' }
                    elseif ($daysRemaining -le 30) { 'High' }
                    elseif ($daysRemaining -le 60) { 'Medium' }
                    else { 'Low' }

        [pscustomobject]@{
            Id            = $first.Thumbprint
            Subject       = $first.Subject
            Issuer        = $first.Issuer
            NotAfter      = $first.NotAfter
            DaysRemaining = $daysRemaining
            Severity      = $severity
            Sources       = (($g.Group.Source | Select-Object -Unique) -join ', ')
            Locations     = (($g.Group | ForEach-Object { "$($_.ComputerName) [$($_.Location)]" } | Select-Object -Unique) -join '; ')
            DnsNames      = $first.DnsNames
            CollectionErrors = $null
        }
    })

    # Append collection errors as Low-severity informational findings.
    foreach ($e in $errors) {
        $findings += [pscustomobject]@{
            Id            = "ERR-$($e.ComputerName)-$($e.Location)"
            Subject       = '(collection error)'
            Issuer        = $null
            NotAfter      = $null
            DaysRemaining = $null
            Severity      = 'Low'
            Sources       = $e.Source
            Locations     = "$($e.ComputerName) [$($e.Location)]"
            DnsNames      = $null
            CollectionErrors = $e.Error
        }
    }

    $sortOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    return @($findings | Sort-Object @{ e = { $sortOrder[$_.Severity] } }, DaysRemaining)
}

function Format-CertificateReport {
    <#
    .SYNOPSIS
        Renders a markdown certificate-expiry report to a string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings,
        [int]$ThresholdDays = 90,
        [datetime]$ScanTime = (Get-Date)
    )

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# Certificate Expiry Report")
    $null = $sb.AppendLine("**Scan time:** $ScanTime  ")
    $null = $sb.AppendLine("**Threshold:** certificates expiring within $ThresholdDays day(s)")
    $null = $sb.AppendLine()

    $real = $Findings | Where-Object { $null -ne $_.DaysRemaining }
    $errs = $Findings | Where-Object { $_.CollectionErrors }

    if (-not $real -or $real.Count -eq 0) {
        $null = $sb.AppendLine("**No certificates are expiring within the threshold window.**")
    } else {
        $null = $sb.AppendLine("## $($real.Count) certificate(s) expiring within $ThresholdDays days")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Severity | Days Left | Subject | Issuer | Source(s) | Location(s) |")
        $null = $sb.AppendLine("|---|---|---|---|---|---|")
        foreach ($f in $real) {
            $days = if ($f.DaysRemaining -lt 0) { "EXPIRED ($($f.DaysRemaining))" } else { $f.DaysRemaining }
            $null = $sb.AppendLine("| $($f.Severity) | $days | $($f.Subject) | $($f.Issuer) | $($f.Sources) | $($f.Locations) |")
        }
        $null = $sb.AppendLine()
    }

    if ($errs -and $errs.Count -gt 0) {
        $null = $sb.AppendLine("## Collection issues ($($errs.Count))")
        foreach ($e in $errs) {
            $null = $sb.AppendLine("- **$($e.Locations)**: $($e.CollectionErrors)")
        }
    }

    return $sb.ToString()
}

Export-ModuleMember -Function Get-MachineCertificate, Test-IsLocalCertHost, `
    Resolve-CertTargetName, Get-EndpointCertificate, `
    Get-CaIssuedCertificate, Find-ExpiringCertificates, Format-CertificateReport, `
    ConvertTo-CertificateInventory

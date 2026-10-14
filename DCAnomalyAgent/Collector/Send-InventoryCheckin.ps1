#Requires -Version 5.1
<#
.SYNOPSIS
    Push collector - runs ON an endpoint (laptop/workstation) and pushes its own
    inventory OUTBOUND to the AD-Agent jump server.

.DESCRIPTION
    The jump server's normal discovery reaches out to hosts over WinRM. That works
    for always-on, fixed-IP servers on approved VLANs; it does not work for roaming
    laptops, which is where every coverage gap has actually been:

      * they sit on VLANs the firewall won't allow inbound WinRM to
      * their IP changes with DHCP, so a scan target list goes stale immediately
      * they're asleep or off the network entirely when the scheduled scan runs

    This script inverts the direction. The endpoint collects its own inventory
    locally (no WinRM, no inbound rule, no credentials on the wire) and POSTs it to
    the jump server. Consequences worth knowing:

      * ONE outbound firewall rule (endpoint VLANs -> jump server) replaces inbound
        WinRM rules to every workstation VLAN
      * an IP change is irrelevant - the device identifies itself by hostname, and
        its current IP arrives as data
      * a laptop that was off for three weeks simply checks in when it comes back,
        and the Endpoints page shows it reappearing

    Deliberately self-contained: endpoints do NOT have the AD-Agent modules, so the
    chassis/software logic below is inlined rather than imported. It mirrors
    DCAnomalyAgent.SoftwareInventory.psm1's registry enumeration and chassis-type
    mapping so pushed data renders identically to WinRM-collected data.

    Deploy via GPO as a Scheduled Task running as SYSTEM - see
    Install\Deploy-PushCollector-GPO.md.

.PARAMETER ServerUrl
    Base URL of the AD-Agent web UI, e.g. 'https://jump-jeremy.amg.local'. The
    script appends /api/collector/checkin itself.
.PARAMETER Token
    Shared secret matching the jump server's COLLECTOR_TOKEN environment variable.
.PARAMETER SkipSoftware
    Presence-only check-in: hostname/IP/OS/user, no software enumeration. Much
    faster (no registry walk) - intended for the frequent "is it online" task, with
    a separate daily full run.
.PARAMETER TimeoutSec
    Per-attempt HTTP timeout.
.PARAMETER Retries
    Retry count for transient failures. A laptop that just woke up often has an
    adapter that isn't ready for a few seconds, so this retries with backoff rather
    than failing the whole check-in.
.PARAMETER LogPath
    Local log file on the endpoint. Defaults under ProgramData.

.EXAMPLE
    .\Send-InventoryCheckin.ps1 -ServerUrl 'https://jump-jeremy.amg.local' -Token 'xxxx'

.EXAMPLE
    .\Send-InventoryCheckin.ps1 -ServerUrl 'https://jump-jeremy.amg.local' -Token 'xxxx' -SkipSoftware
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory)][string]$ServerUrl,
    [Parameter(Mandatory)][string]$Token,
    [switch]$SkipSoftware,
    [int]$TimeoutSec = 30,
    [int]$Retries = 3,
    [string]$LogPath = "$env:ProgramData\AD-Agent\collector.log"
)

$ErrorActionPreference = 'Stop'

function Write-CollectorLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $line
    try {
        $dir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
        # Keep the endpoint log from growing without bound - this runs every 30 min
        # on thousands of machines and nobody is out there rotating logs by hand.
        $f = Get-Item $LogPath -ErrorAction SilentlyContinue
        if ($f -and $f.Length -gt 1MB) {
            Set-Content -Path $LogPath -Value (Get-Content $LogPath -Tail 200) -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Chassis type codes, mirroring DCAnomalyAgent.SoftwareInventory.psm1.
$LaptopChassisTypes  = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
$DesktopChassisTypes = @(3, 4, 5, 6, 7, 13, 15, 16, 35, 36)
$ServerChassisTypes  = @(17, 23, 28)

function Get-LocalCategory {
    try {
        $codes = @((Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop).ChassisTypes)
        if ($codes | Where-Object { $_ -in $ServerChassisTypes })  { return 'Server' }
        if ($codes | Where-Object { $_ -in $LaptopChassisTypes })  { return 'Laptop' }
        if ($codes | Where-Object { $_ -in $DesktopChassisTypes }) { return 'Desktop' }
        return 'Workstation'
    } catch {
        return 'Workstation'
    }
}

function Get-PrimaryIPv4 {
    # The address on the interface that actually holds the default route - not the
    # first adapter found. On a laptop running Cloudflare WARP there are several
    # adapters up at once (physical NIC, WARP virtual, maybe a VM switch); the
    # default-route one is the address the jump server would realistically see.
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction Stop |
            Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } |
            Select-Object -First 1
        if ($cfg -and $cfg.IPv4Address) { return @($cfg.IPv4Address)[0].IPAddress }
    } catch { }
    try {
        return (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
            Select-Object -First 1).IPAddress
    } catch { }
    return $null
}

function Get-ConnectionInfo {
    # Which link this device is actually using: the up adapter holding the lowest-metric
    # IPv4 default route. When that's a VPN/tunnel adapter, report the physical link it
    # rides on too ('Wi-Fi (VPN)'). Kept identical in Send-InventoryCheckin.ps1 (which
    # must stay standalone) and DCAnomalyAgent.SoftwareInventory.psm1.
    function _ConnKind($a) {
        $text = "$($a.Name) $($a.InterfaceDescription)"
        $medium = [string]$a.PhysicalMediaType
        if ($medium -match 'Wireless WAN|WWAN' -or $text -match 'Mobile Broadband|Cellular|WWAN') { return 'Mobile' }
        if ($medium -match '802\.11' -or $text -match 'Wi-?Fi|Wireless|WLAN|802\.11') { return 'Wi-Fi' }
        if ($text -match 'VPN|WARP|AnyConnect|GlobalProtect|PANGP|Forti|TAP-Windows|WireGuard|Wintun|Zscaler|Pulse Secure|Juniper|NordLynx|OpenVPN|Check Point|SonicWall|Tunnel') { return 'VPN' }
        if ($medium -match '802\.3' -or $text -match 'Ethernet|GbE|Gigabit|LAN') { return 'LAN' }
        return 'Other'
    }
    try { $up = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }) } catch { return $null }
    if (-not $up) { return $null }
    $metric = @{}
    foreach ($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
        $ipIf = Get-NetIPInterface -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $m = [int]$r.RouteMetric + $(if ($ipIf) { [int]$ipIf.InterfaceMetric } else { 0 })
        if (-not $metric.ContainsKey($r.InterfaceIndex) -or $m -lt $metric[$r.InterfaceIndex]) { $metric[$r.InterfaceIndex] = $m }
    }
    $routed = @($up | Where-Object { $metric.ContainsKey($_.InterfaceIndex) } | Sort-Object { $metric[$_.InterfaceIndex] })
    $primary = if ($routed) { $routed[0] } else { $up[0] }
    $type = _ConnKind $primary
    $adapter = "$($primary.Name) ($($primary.InterfaceDescription))"
    if ($type -eq 'VPN') {
        $phys = @(@($routed) + @($up) | Where-Object {
            $_.InterfaceIndex -ne $primary.InterfaceIndex -and (_ConnKind $_) -in @('Wi-Fi', 'LAN', 'Mobile') } | Select-Object -First 1)
        if ($phys) {
            $type = "$(_ConnKind $phys[0]) (VPN)"
            $adapter = "$($phys[0].Name) ($($phys[0].InterfaceDescription)) via $($primary.InterfaceDescription)"
        }
    }
    [pscustomobject]@{ Type = $type; Adapter = $adapter }
}

function Get-ConsoleUser {
    # Runs as SYSTEM under the GPO scheduled task, so $env:USERNAME would be the
    # machine account - Win32_ComputerSystem.UserName is the actual signed-in user.
    try {
        $u = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).UserName
        if ($u) { return $u }
    } catch { }
    return $null
}

function Get-LocalSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $items = foreach ($path in $paths) {
        $arch = if ($path -match 'WOW6432Node') { '32-bit' } else { '64-bit' }
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
            ForEach-Object {
                [pscustomobject]@{
                    Name         = $_.DisplayName
                    Version      = "$($_.DisplayVersion)"
                    Publisher    = "$($_.Publisher)"
                    InstallDate  = "$($_.InstallDate)"
                    Architecture = $arch
                }
            }
    }
    # HKCU is deliberately NOT read here: as SYSTEM, HKCU is SYSTEM's own hive, not
    # the signed-in user's, so it would return nothing useful and imply per-user apps
    # were absent. Per-user installs are a known blind spot of running as SYSTEM.
    return @($items | Sort-Object Name, Version -Unique)
}

function Get-TlsDiagnosis {
    <#
    .SYNOPSIS
        After an HTTPS check-in fails on the certificate, work out WHY and say it in one line.
    .DESCRIPTION
        "Could not establish trust relationship for the SSL/TLS secure channel" covers three
        different problems with three different fixes: the URL host isn't on the
        certificate, the server doesn't send its intermediate CA, or this device doesn't
        trust the root CA. This repeats the TLS handshake on its own socket, records what
        Windows' own validation said (the callback sees the platform's verdict and chain),
        and turns that into a specific instruction. It's a probe only: the callback returns
        $true so the handshake completes, but nothing is ever sent over the connection, and
        the real check-in still fails closed.
    #>
    param([Parameter(Mandatory)][string]$Uri, [int]$TimeoutMs = 8000)

    try { $u = [Uri]$Uri } catch { return "TLS diagnosis: '$Uri' is not a valid URL." }
    if ($u.Scheme -ne 'https') { return $null }
    $target = $u.DnsSafeHost
    $port = if ($u.Port -gt 0) { $u.Port } else { 443 }

    # A hashtable is a reference type, so the closure below writes into this same object.
    $state = @{ Errors = $null; Cert = $null; Status = @(); Chain = @() }
    $callback = {
        param($sender, $certificate, $chain, $policyErrors)
        $state.Errors = $policyErrors
        if ($certificate) {
            $state.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certificate
        }
        if ($chain) {
            # Copy out now - the chain object isn't guaranteed to outlive the callback.
            $state.Status = @($chain.ChainStatus | ForEach-Object { [string]$_.Status })
            $state.Chain = @($chain.ChainElements | ForEach-Object { [pscustomobject]@{ Subject = $_.Certificate.Subject; Issuer = $_.Certificate.Issuer } })
        }
        return $true
    }.GetNewClosure()

    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $tcp.ConnectAsync($target, $port)
        $done = $false
        try { $done = $connect.Wait($TimeoutMs) } catch { }
        if (-not $done -or $connect.IsFaulted -or -not $tcp.Connected) {
            return "TLS diagnosis: cannot open TCP $port on '$target' - check DNS and the firewall path."
        }
        $ssl = New-Object System.Net.Security.SslStream -ArgumentList $tcp.GetStream(), $false, ([System.Net.Security.RemoteCertificateValidationCallback]$callback)
        try {
            $ssl.AuthenticateAsClient($target, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
        } finally {
            $ssl.Dispose()
        }
    } catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        return "TLS diagnosis: TLS 1.2 handshake with ${target}:$port failed ($($inner.Message)) - is the TLS proxy running and is this the HTTPS port?"
    } finally {
        $tcp.Dispose()
    }

    $cert = $state.Cert
    if (-not $cert) { return "TLS diagnosis: ${target}:$port presented no certificate." }

    # Names on the certificate: SAN DNS entries (Windows formats them 'DNS Name=x',
    # OpenSSL-based platforms 'DNS:x') plus the subject CN.
    $names = @()
    $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if ($san) {
        $names += [regex]::Matches($san.Format($false), '(?:DNS Name=|DNS:)\s*([^,\s]+)') | ForEach-Object { $_.Groups[1].Value }
    }
    $cn = [regex]::Match($cert.Subject, 'CN=([^,]+)')
    if ($cn.Success) { $names += $cn.Groups[1].Value.Trim() }
    $names = @($names | Select-Object -Unique)

    $errors = [string]$state.Errors
    $problems = @()
    if ($errors -match 'RemoteCertificateNameMismatch') {
        $problems += "URL host '$target' is not on the certificate (names: $($names -join ', ')) - set -ServerUrl to https://<one of those names>."
    }
    if ($errors -match 'RemoteCertificateChainErrors') {
        $status = @($state.Status)
        $chainList = @($state.Chain)
        $last = if ($chainList) { $chainList[-1] } else { $null }
        if ($status -contains 'PartialChain') {
            # Where the chain stops says what's missing: stopping at the leaf means no
            # intermediate was available; stopping at a CA cert means its issuer (the root)
            # isn't on this device.
            if ($chainList.Count -le 1) {
                $problems += "PartialChain - the chain stops at the server certificate: the server isn't sending its intermediate CA '$($cert.Issuer)' (export cert.pem with the full chain, leaf first), and this device doesn't have it either."
            } else {
                $problems += "PartialChain - the chain reaches '$($last.Subject)' but this device doesn't have its issuer, the root CA '$($last.Issuer)' - deploy that root to Trusted Root Certification Authorities (GPO or an Intune trusted certificate profile)."
            }
        }
        if ($status -contains 'UntrustedRoot') {
            $problems += "UntrustedRoot - this device doesn't trust the root CA '$($last.Subject)' - deploy it to Trusted Root Certification Authorities (GPO or an Intune trusted certificate profile)."
        }
        if ($status -contains 'NotTimeValid') {
            $problems += "NotTimeValid - the certificate is expired or not yet valid (valid $($cert.NotBefore) to $($cert.NotAfter)); also check this device's clock."
        }
        $other = @($status | Where-Object { $_ -notin @('PartialChain', 'UntrustedRoot', 'NotTimeValid', 'NoError') } | Select-Object -Unique)
        if ($other) { $problems += "Chain status: $($other -join ', ')." }
        if (-not $status) { $problems += "Certificate chain rejected (no further detail from the platform)." }
    }
    if ($errors -match 'RemoteCertificateNotAvailable') { $problems += "The server did not provide a certificate." }

    if (-not $problems) {
        return "TLS diagnosis: the certificate for '$target' (names: $($names -join ', ')) validates on this device - the failure is not the certificate."
    }
    return "TLS diagnosis: " + ($problems -join ' ')
}

$hostname = $env:COMPUTERNAME
try {
    $fqdn = ([System.Net.Dns]::GetHostEntry($hostname)).HostName
} catch {
    $fqdn = $hostname
}

$os = try {
    $o = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    ("$($o.Caption) $($o.Version)").Trim()
} catch { $null }

$payload = [ordered]@{
    Name        = $fqdn
    IP          = Get-PrimaryIPv4
    AssetType   = Get-LocalCategory
    OS          = $os
    User        = Get-ConsoleUser
    # Wi-Fi / LAN / VPN for the Assets and Endpoints pages. Never fails the check-in.
    ConnectionType    = $null
    ConnectionAdapter = $null
    CollectedAt = (Get-Date).ToUniversalTime().ToString('o')
    Software    = if ($SkipSoftware) { $null } else { Get-LocalSoftware }
}

try {
    $conn = Get-ConnectionInfo
    if ($conn) { $payload.ConnectionType = $conn.Type; $payload.ConnectionAdapter = $conn.Adapter }
} catch { }

$swCount = if ($payload.Software) { @($payload.Software).Count } else { 0 }
$via = if ($payload.ConnectionType) { " via $($payload.ConnectionType)" } else { '' }
Write-CollectorLog "Collected: $fqdn ($($payload.IP)) $($payload.AssetType)$via - $swCount software item(s)."

$uri = "$($ServerUrl.TrimEnd('/'))/api/collector/checkin"
$body = $payload | ConvertTo-Json -Depth 4 -Compress

# Windows PowerShell 5.1 on older .NET defaults can offer only SSL3/TLS 1.0, which the
# AD-Agent TLS proxy refuses (TLS 1.2 minimum). Add TLS 1.2 to whatever is configured -
# unless the machine is on SystemDefault (0), where the OS already negotiates 1.2+ and
# setting explicit flags would only rule out TLS 1.3.
try {
    $sp = [Net.ServicePointManager]::SecurityProtocol
    if ([int]$sp -ne 0 -and -not ($sp -band [Net.SecurityProtocolType]::Tls12)) {
        [Net.ServicePointManager]::SecurityProtocol = $sp -bor [Net.SecurityProtocolType]::Tls12
    }
} catch { }

$sent = $false
$tlsDiagnosed = $false
for ($attempt = 1; $attempt -le $Retries; $attempt++) {
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $body `
            -ContentType 'application/json' `
            -Headers @{ 'X-Collector-Token' = $Token } `
            -TimeoutSec $TimeoutSec
        Write-CollectorLog "Check-in accepted by $uri (key: $($resp.dedup_key))."
        $sent = $true
        break
    } catch {
        $msg = $_.Exception.Message
        # A certificate problem won't fix itself between retries - explain it once, then
        # carry on with the normal retry/fail path.
        if (-not $tlsDiagnosed -and $msg -match 'trust relationship|SSL|TLS|secure channel|certificate') {
            $tlsDiagnosed = $true
            $diag = Get-TlsDiagnosis -Uri $uri
            if ($diag) { Write-CollectorLog $diag 'ERROR' }
        }
        if ($attempt -lt $Retries) {
            # Backoff: a laptop that just resumed often has an adapter that isn't
            # usable for a few seconds, and WARP may still be establishing its tunnel.
            $delay = [math]::Pow(2, $attempt) * 2
            Write-CollectorLog "Attempt $attempt/$Retries failed ($msg) - retrying in ${delay}s." 'WARN'
            Start-Sleep -Seconds $delay
        } else {
            Write-CollectorLog "Check-in FAILED after $Retries attempt(s): $msg" 'ERROR'
        }
    }
}

if (-not $sent) {
    # Non-zero exit so the Scheduled Task's LastTaskResult reflects the failure and
    # it's visible in Task Scheduler / any endpoint monitoring, rather than the task
    # silently reporting success while nothing ever reaches the jump server.
    exit 1
}
exit 0

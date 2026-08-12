#Requires -Version 5.1
<#
.SYNOPSIS
    Asset discovery - enumerates hosts from Active Directory and/or by scanning the
    network, classifies them by OS/role, and emits an inventory suitable for feeding
    the compliance scanner's asset lists.

.DESCRIPTION
    Two discovery sources:
      1. Active Directory  (Get-ADAsset)      - authoritative for domain-joined hosts
      2. Network scan      (Get-NetworkAsset) - finds anything reachable, incl. non-domain
                                                 and non-Windows (Linux/appliances)

    Classification heuristics by open port / AD attribute:
      Windows  : TCP 135/445/5985 open, or AD OperatingSystem contains 'Windows'
      Linux    : TCP 22 open and Windows ports closed
      Network  : 161 (SNMP) / 23 (telnet) open, no 445/5985/22 -> likely appliance
    Role (Windows):
      DomainController : AD PrimaryGroupID 516, or LDAP/Kerberos ports (389/88) open
      MemberServer     : server OS
      Workstation      : client OS
#>

function Get-ADAsset {
    <#
    .SYNOPSIS
        Enumerate domain-joined computers from AD and classify them.
    #>
    [CmdletBinding()]
    param(
        [string]$SearchBase,
        [switch]$EnabledOnly
    )

    $params = @{ Filter = '*'; Properties = @('OperatingSystem','OperatingSystemVersion','PrimaryGroupID','DNSHostName','LastLogonDate','Enabled') }
    if ($SearchBase) { $params['SearchBase'] = $SearchBase }

    $dcSet = @{}
    try { (Get-ADDomainController -Filter *).ComputerObjectDN | ForEach-Object { $dcSet[$_] = $true } } catch {}

    Get-ADComputer @params | Where-Object { -not $EnabledOnly -or $_.Enabled } | ForEach-Object {
        $os = "$($_.OperatingSystem)"
        $assetType =
            if ($dcSet.ContainsKey($_.DistinguishedName) -or $_.PrimaryGroupID -eq 516) { 'DomainController' }
            elseif ($os -like '*Server*')  { 'MemberServer' }
            elseif ($os -like '*Linux*' -or $os -like '*Unix*') { 'Linux' }
            elseif ($os -like '*Windows*') { 'Workstation' }
            else { 'Unknown' }

        $hostName = if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name }
        [pscustomobject]@{
            Name          = $hostName
            AssetType     = $assetType
            OS            = $os
            OSVersion     = "$($_.OperatingSystemVersion)"
            Source        = 'ActiveDirectory'
            Enabled       = $_.Enabled
            LastLogonDate = $_.LastLogonDate
            DistinguishedName = $_.DistinguishedName
        }
    }
}

function Test-TcpPort {
    <#
    .SYNOPSIS
        Fast TCP port probe with a timeout (avoids Test-NetConnection's overhead).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 700
    )
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $async  = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $ok     = $async.AsyncWaitHandle.WaitOne($TimeoutMs)
        if ($ok -and $client.Connected) { $client.EndConnect($async); return $true }
        return $false
    } catch {
        return $false
    } finally {
        if ($client) { $client.Close() }
    }
}

function Expand-Cidr {
    <#
    .SYNOPSIS
        Expand a CIDR (e.g. 10.0.0.0/24) into individual host IPs. Supports /16-/32.
        A bare IP with no /prefix (e.g. 10.0.0.5) is treated as /32 - a single host.
        A hostname (anything that isn't IP/CIDR-shaped) is resolved via DNS to its
        current IP(s) at scan time - useful for targeting a specific device whose IP
        changes on every DHCP renewal (e.g. a laptop) instead of a fixed address that
        goes stale within days.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Cidr)

    if ($Cidr -match '^(\d{1,3}(?:\.\d{1,3}){3})$') {
        $Cidr = "$Cidr/32"
    }
    if ($Cidr -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        if ($Cidr -match '^\d') {
            throw "Invalid CIDR: $Cidr"   # looked like an IP/CIDR attempt but didn't parse - don't silently DNS-resolve digits
        }
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($Cidr) |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                ForEach-Object { $_.ToString() }
        } catch {
            throw "Could not resolve hostname '$Cidr' to an IP address: $_"
        }
        if (-not $resolved) { throw "Hostname '$Cidr' resolved to no IPv4 address." }
        return $resolved
    }
    $baseIp = $Matches[1]; $prefix = [int]$Matches[2]
    if ($prefix -lt 16 -or $prefix -gt 32) { throw "Prefix /$prefix out of supported range (/16-/32)." }

    $ipBytes  = [System.Net.IPAddress]::Parse($baseIp).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt    = [BitConverter]::ToUInt32($ipBytes, 0)
    $hostBits = 32 - $prefix
    $mask     = [uint32]((0xFFFFFFFFL -shl $hostBits) -band 0xFFFFFFFFL)
    $network  = $ipInt -band $mask
    $count    = [uint32]([math]::Pow(2, $hostBits))

    $first = if ($hostBits -gt 1) { 1 } else { 0 }
    $last  = if ($hostBits -gt 1) { $count - 2 } else { $count - 1 }

    for ($i = $first; $i -le $last; $i++) {
        $addr = $network + $i
        $b = [BitConverter]::GetBytes([uint32]$addr)
        [Array]::Reverse($b)
        ([System.Net.IPAddress]::new($b)).ToString()
    }
}

function Get-NetworkAsset {
    <#
    .SYNOPSIS
        Scan one or more CIDR ranges, find live hosts, and classify them by open port.
    .PARAMETER Cidr
        One or more CIDR ranges (e.g. '10.0.0.0/24').
    .PARAMETER ThrottleLimit
        Max parallel host probes (PowerShell 7+ uses ForEach-Object -Parallel; on 5.1
        it falls back to sequential).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Cidr,
        [int]$TimeoutMs = 700,
        [int]$ThrottleLimit = 64,
        # Tags every host found in this call, e.g. 'Cloudflare WARP' for remote/home
        # users connecting in via Zero Trust, vs the default on-prem 'NetworkScan'.
        [string]$SourceLabel = 'NetworkScan'
    )

    $ips = foreach ($c in $Cidr) { Expand-Cidr -Cidr $c }

    # NOTE: ForEach-Object -Parallel does not support -ArgumentList (that belongs to a
    # different parameter set) and its runspaces don't inherit module-scope functions, so
    # the parallel (PS7+) and sequential (PS5.1) probes are two self-contained scriptblocks
    # rather than one shared one passed in different ways.
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $ips | ForEach-Object -Parallel {
            $ip          = $_
            $TimeoutMs   = $using:TimeoutMs
            $SourceLabel = $using:SourceLabel

            function _port($h, $p, $t) {
                try {
                    $cl = [System.Net.Sockets.TcpClient]::new()
                    $a  = $cl.BeginConnect($h, $p, $null, $null)
                    $r  = $a.AsyncWaitHandle.WaitOne($t)
                    $open = $r -and $cl.Connected
                    if ($open) { $cl.EndConnect($a) }
                    $cl.Close()
                    return $open
                } catch { return $false }
            }

            $ports = @{
                SMB     = _port $ip 445  $TimeoutMs
                WinRM   = _port $ip 5985 $TimeoutMs
                RPC     = _port $ip 135  $TimeoutMs
                SSH     = _port $ip 22   $TimeoutMs
                LDAP    = _port $ip 389  $TimeoutMs
                Kerberos= _port $ip 88   $TimeoutMs
                SNMP    = _port $ip 161  $TimeoutMs
                Telnet  = _port $ip 23   $TimeoutMs
                HTTPS   = _port $ip 443  $TimeoutMs
            }

            if (-not ($ports.Values -contains $true)) { return }  # host appears dead

            $isWinHost = $ports.SMB -or $ports.WinRM -or $ports.RPC
            $assetType =
                if ($ports.LDAP -and $ports.Kerberos -and $isWinHost) { 'DomainController' }
                elseif ($isWinHost)        { 'Windows' }            # role refined later via AD/WinRM
                elseif ($ports.SSH)        { 'Linux' }
                elseif ($ports.SNMP -or $ports.Telnet) { 'NetworkDevice' }
                else                       { 'Unknown' }

            $name = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $ip }

            [pscustomobject]@{
                Name      = $name
                IP        = $ip
                AssetType = $assetType
                OpenPorts = ($ports.GetEnumerator() | Where-Object Value | ForEach-Object Key) -join ','
                Source    = $SourceLabel
                LastSeen  = (Get-Date).ToString('o')
            }
        } -ThrottleLimit $ThrottleLimit
    } else {
        foreach ($ip in $ips) {
            function _port($h, $p, $t) {
                try {
                    $cl = [System.Net.Sockets.TcpClient]::new()
                    $a  = $cl.BeginConnect($h, $p, $null, $null)
                    $r  = $a.AsyncWaitHandle.WaitOne($t)
                    $open = $r -and $cl.Connected
                    if ($open) { $cl.EndConnect($a) }
                    $cl.Close()
                    return $open
                } catch { return $false }
            }

            $ports = @{
                SMB     = _port $ip 445  $TimeoutMs
                WinRM   = _port $ip 5985 $TimeoutMs
                RPC     = _port $ip 135  $TimeoutMs
                SSH     = _port $ip 22   $TimeoutMs
                LDAP    = _port $ip 389  $TimeoutMs
                Kerberos= _port $ip 88   $TimeoutMs
                SNMP    = _port $ip 161  $TimeoutMs
                Telnet  = _port $ip 23   $TimeoutMs
                HTTPS   = _port $ip 443  $TimeoutMs
            }

            if (-not ($ports.Values -contains $true)) { continue }  # host appears dead

            $isWinHost = $ports.SMB -or $ports.WinRM -or $ports.RPC
            $assetType =
                if ($ports.LDAP -and $ports.Kerberos -and $isWinHost) { 'DomainController' }
                elseif ($isWinHost)        { 'Windows' }
                elseif ($ports.SSH)        { 'Linux' }
                elseif ($ports.SNMP -or $ports.Telnet) { 'NetworkDevice' }
                else                       { 'Unknown' }

            $name = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $ip }

            [pscustomobject]@{
                Name      = $name
                IP        = $ip
                AssetType = $assetType
                OpenPorts = ($ports.GetEnumerator() | Where-Object Value | ForEach-Object Key) -join ','
                Source    = $SourceLabel
                LastSeen  = (Get-Date).ToString('o')
            }
        }
    }
}

function Merge-AssetInventory {
    <#
    .SYNOPSIS
        Combine AD + network discovery, de-duplicate by name, and prefer AD's
        richer classification where both sources see the same host.
    #>
    [CmdletBinding()]
    param(
        [array]$AdAssets = @(),
        [array]$NetworkAssets = @()
    )

    $byName = @{}

    foreach ($a in $AdAssets) {
        $key = ($a.Name -split '\.')[0].ToLower()
        $byName[$key] = $a
    }
    foreach ($n in $NetworkAssets) {
        $key = ($n.Name -split '\.')[0].ToLower()
        if ($byName.ContainsKey($key)) {
            # AD already has it - annotate with discovered open ports and the live-response
            # timestamp from the network probe (AD membership alone doesn't prove reachability).
            $byName[$key] | Add-Member -NotePropertyName OpenPorts -NotePropertyValue $n.OpenPorts -Force
            $byName[$key] | Add-Member -NotePropertyName Source -NotePropertyValue "AD+$($n.Source)" -Force
            $byName[$key] | Add-Member -NotePropertyName LastSeen -NotePropertyValue $n.LastSeen -Force
        } else {
            $byName[$key] = $n   # network-only (non-domain / non-Windows)
        }
    }

    $byName.Values | Sort-Object AssetType, Name
}

function Export-AssetInventory {
    <#
    .SYNOPSIS
        Write the inventory to JSON and CSV, and emit ready-to-paste settings.psd1
        Assets blocks grouped by asset type.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Inventory,
        [Parameter(Mandatory)][string]$OutputDir
    )

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    $jsonPath = Join-Path $OutputDir 'asset-inventory.json'
    $csvPath  = Join-Path $OutputDir 'asset-inventory.csv'
    $psd1Path = Join-Path $OutputDir 'discovered-assets.psd1.txt'

    $Inventory | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding UTF8
    # Software is a nested per-host array (kept in the JSON for the dashboard's per-device
    # drill-down) and is intentionally left out of the flat CSV.
    $Inventory | Select-Object Name, IP, AssetType, OS, OpenPorts, Source, LastSeen |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    # Emit a settings.psd1-style Assets snippet
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('# Paste into settings.psd1 -> Assets (review before use)')
    $null = $sb.AppendLine('Assets = @{')
    foreach ($group in ($Inventory | Group-Object AssetType)) {
        $hosts = ($group.Group.Name | ForEach-Object { "'$_'" }) -join ','
        $null = $sb.AppendLine("    $($group.Name) = @{ Hosts = @($hosts); DiscoverFromAD = `$false }")
    }
    $null = $sb.AppendLine('}')
    $sb.ToString() | Set-Content -Path $psd1Path -Encoding UTF8

    [pscustomobject]@{ Json = $jsonPath; Csv = $csvPath; Psd1Snippet = $psd1Path; Count = $Inventory.Count }
}

Export-ModuleMember -Function Get-ADAsset, Get-NetworkAsset, Test-TcpPort, `
    Expand-Cidr, Merge-AssetInventory, Export-AssetInventory

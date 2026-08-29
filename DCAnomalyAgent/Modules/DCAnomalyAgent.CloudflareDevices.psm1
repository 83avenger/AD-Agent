#Requires -Version 5.1
<#
.SYNOPSIS
    Pulls the WARP-enrolled device roster from the Cloudflare Zero Trust API.

.DESCRIPTION
    WHAT THIS GIVES YOU, AND WHAT IT DOESN'T - read this before wiring it into
    anything, because the limit is not obvious from Cloudflare's marketing:

      YES - device roster:  every laptop with the WARP client enrolled, including
            ones that have never been reachable from the jump server. Hostname,
            OS + version, serial number, the enrolled user's email, WARP client
            version, and Cloudflare's own last_seen timestamp.

      NO  - installed software. There is no software-inventory endpoint. WARP's
            device posture checks are ASSERTIONS YOU DEFINE ("is CrowdStrike
            running?", "does file X exist?", "is registry key Y set?") - you cannot
            ask it to enumerate every installed program with versions. Anything
            needing a real software list (the zero-day/KEV cross-reference, the
            Software List page, licence questions) still needs the push collector
            or WinRM.

    So the useful split is: Cloudflare answers "which laptops exist and when was
    each last online" without deploying anything, because the agent is already
    installed everywhere. The push collector answers "what is installed on them".
    They complement each other; neither replaces the other.

    Requires a Cloudflare API token with Account > Zero Trust > Read (or the
    narrower Devices Read) permission, plus the Account ID. Both go in
    settings.psd1 under Integrations.CloudflareZeroTrust.
#>

Set-StrictMode -Version Latest

$script:CloudflareApiBase = 'https://api.cloudflare.com/client/v4'

function ConvertFrom-CloudflareDevice {
    <#
    .SYNOPSIS
        Maps one Cloudflare device record to AD-Agent's asset shape.
    .DESCRIPTION
        Split out from the HTTP call so the mapping is testable without a live
        API token or network access.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Device)

    if (-not $Device) { return $null }

    $name = $null
    foreach ($prop in @('name', 'hostname')) {
        if ($Device.PSObject.Properties.Name -contains $prop -and $Device.$prop) {
            $name = [string]$Device.$prop
            break
        }
    }
    if (-not $name) { return $null }   # unidentifiable - skip rather than emit a junk row

    $user = $null
    if ($Device.PSObject.Properties.Name -contains 'user' -and $Device.user) {
        if ($Device.user.PSObject.Properties.Name -contains 'email') { $user = [string]$Device.user.email }
    }

    # device_type is Cloudflare's platform string (windows/mac/linux/ios/android),
    # not a chassis class - it cannot distinguish a laptop from a desktop. Map it to
    # something honest rather than guessing 'Laptop' for every Windows device.
    $platform = if ($Device.PSObject.Properties.Name -contains 'device_type') { [string]$Device.device_type } else { '' }
    $assetType = switch -Regex ($platform) {
        '^(?i)windows' { 'Windows' }
        '^(?i)(mac|darwin)' { 'macOS' }
        '^(?i)linux'   { 'Linux' }
        '^(?i)ios'     { 'Mobile' }
        '^(?i)android' { 'Mobile' }
        default        { 'Unknown' }
    }

    $osParts = @()
    foreach ($prop in @('os_distro_name', 'os_version')) {
        if ($Device.PSObject.Properties.Name -contains $prop -and $Device.$prop) { $osParts += [string]$Device.$prop }
    }
    $os = if ($osParts) { ($osParts -join ' ').Trim() } elseif ($platform) { $platform } else { $null }

    $lastSeen = $null
    if ($Device.PSObject.Properties.Name -contains 'last_seen' -and $Device.last_seen) {
        try { $lastSeen = ([datetime]$Device.last_seen).ToUniversalTime().ToString('o') } catch { $lastSeen = $null }
    }

    $ip = if ($Device.PSObject.Properties.Name -contains 'ip' -and $Device.ip) { [string]$Device.ip } else { $null }

    [pscustomobject]@{
        Name          = $name
        IP            = $ip
        AssetType     = $assetType
        OS            = $os
        User          = $user
        CollectedAt   = $lastSeen
        Source        = 'Cloudflare WARP'
        CheckinSource = 'CloudflareWARP'
        # Deliberately no Software key: Cloudflare cannot supply one (see the module
        # header). Omitting it means a merge never clobbers real software inventory
        # collected by the push collector or WinRM with an empty list.
    }
}

function Get-CloudflareDevice {
    <#
    .SYNOPSIS
        Returns every WARP-enrolled device in the account, as AD-Agent asset objects.
    .PARAMETER ApiToken
        Cloudflare API token with Zero Trust / Devices read permission.
    .PARAMETER AccountId
        Cloudflare account ID.
    .PARAMETER PerPage
        Page size for the paginated API.
    .PARAMETER MaxPages
        Safety cap so a malformed pagination response can't loop forever.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ApiToken,
        [Parameter(Mandatory)][string]$AccountId,
        [int]$PerPage = 100,
        [int]$MaxPages = 100,
        [int]$TimeoutSec = 60
    )

    $headers = @{
        'Authorization' = "Bearer $ApiToken"
        'Content-Type'  = 'application/json'
    }

    $all = New-Object System.Collections.Generic.List[object]
    $page = 1

    while ($page -le $MaxPages) {
        $uri = "$script:CloudflareApiBase/accounts/$AccountId/devices?page=$page&per_page=$PerPage"
        try {
            $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec $TimeoutSec
        } catch {
            throw "Cloudflare device query failed (page $page): $($_.Exception.Message)"
        }

        if (-not $resp.success) {
            $errText = if ($resp.errors) { ($resp.errors | ForEach-Object { $_.message }) -join '; ' } else { 'unknown error' }
            throw "Cloudflare API returned success=false: $errText"
        }

        $batch = @($resp.result)
        foreach ($d in $batch) {
            # Cloudflare keeps soft-deleted device records; they'd otherwise resurrect
            # as live assets on every sync.
            if ($d.PSObject.Properties.Name -contains 'deleted' -and $d.deleted) { continue }
            $mapped = ConvertFrom-CloudflareDevice -Device $d
            if ($mapped) { $all.Add($mapped) }
        }

        if ($batch.Count -lt $PerPage) { break }   # last page
        $page++
    }

    return @($all)
}

Export-ModuleMember -Function Get-CloudflareDevice, ConvertFrom-CloudflareDevice

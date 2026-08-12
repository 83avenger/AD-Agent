#Requires -Version 5.1
<#
.SYNOPSIS
    Installed-software inventory for Windows assets. Enumerates every product in
    the registry Uninstall keys (64-bit + WOW6432Node) over WinRM, classifies the
    host into Desktop / Laptop / Server / Domain Controller, and can cross-reference
    installed versions against the zero-day watchlist (CISA KEV / NVD) to flag
    hosts running a known-exploited product.

.DESCRIPTION
    Category vs AssetType:
        AssetType (from Get-AssetTargets / asset discovery) tells us
        DomainController / MemberServer / Workstation. This module only needs to
        further split 'Workstation' into Desktop vs Laptop, using
        Win32_SystemEnclosure.ChassisTypes (no extra config, one more WinRM call).

    Software object shape returned by Get-InstalledSoftware:
        ComputerName, Category, Name, Version, Publisher, InstallDate,
        Architecture ('64-bit'|'32-bit'), Error (populated only on failure)
#>

# Chassis type codes -> category. Laptop-like values first.
# Reference: Win32_SystemEnclosure.ChassisTypes (DMTF/SMBIOS type codes).
$script:LaptopChassisTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
$script:DesktopChassisTypes = @(3, 4, 5, 6, 7, 13, 15, 16, 35, 36)
# Rack-mount / server chassis - catches server hardware discovered generically
# (e.g. via network scan) that wasn't already labeled MemberServer by AD/OS checks.
$script:ServerChassisTypes = @(17, 23, 28)

function Test-IsLocalComputer {
    <#
    .SYNOPSIS
        True when $ComputerName refers to the machine this code is already running on.
        Self-referential Kerberos WinRM (calling your own FQDN via Invoke-Command) is a
        well-known flaky scenario in Windows - loopback authentication can be denied even
        for an elevated admin, independent of any real group-membership/GPO configuration.
        Running the collection in-process instead of over WinRM sidesteps that entirely.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ComputerName)

    if ($ComputerName -in @('localhost', '.', '127.0.0.1', '::1')) { return $true }
    $short = $ComputerName.Split('.')[0]
    if ($short -ieq $env:COMPUTERNAME) { return $true }
    try {
        $fqdn = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
        if ($ComputerName -ieq $fqdn) { return $true }
    } catch { }
    return $false
}

function Get-DeviceCategory {
    <#
    .SYNOPSIS
        Resolves a host to Desktop / Laptop / Server / Domain Controller.
    .PARAMETER AssetType
        DomainController | MemberServer | Workstation | Windows (from asset discovery /
        Get-AssetTargets / network scan). Anything else passes straight through.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$AssetType
    )

    if ($AssetType -eq 'DomainController') { return 'Domain Controller' }
    if ($AssetType -eq 'MemberServer')     { return 'Server' }
    if ($AssetType -notin @('Workstation', 'Windows')) { return $AssetType }

    $chassisScript = { (Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction Stop).ChassisTypes }
    try {
        $chassis = if (Test-IsLocalComputer -ComputerName $ComputerName) {
            & $chassisScript
        } else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $chassisScript
        }
        $codes = @($chassis)
        if ($codes | Where-Object { $_ -in $script:ServerChassisTypes })  { return 'Server' }
        if ($codes | Where-Object { $_ -in $script:LaptopChassisTypes })  { return 'Laptop' }
        if ($codes | Where-Object { $_ -in $script:DesktopChassisTypes }) { return 'Desktop' }
        return 'Workstation'   # chassis type unrecognized/virtual - keep the generic label
    } catch {
        return 'Workstation'   # WinRM/WMI failure - don't block the inventory over this
    }
}

function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Enumerates installed software from the registry Uninstall keys on a remote
        Windows host over WinRM (both native and WOW6432Node views).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][string]$Category
    )

    $collectScript = {
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        foreach ($path in $paths) {
            $arch = if ($path -match 'WOW6432Node') { '32-bit' } else { '64-bit' }
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
                ForEach-Object {
                    [pscustomobject]@{
                        Name        = $_.DisplayName
                        Version     = "$($_.DisplayVersion)"
                        Publisher   = "$($_.Publisher)"
                        InstallDate = "$($_.InstallDate)"
                        Architecture = $arch
                    }
                }
        }
    }

    try {
        # Self-referential Kerberos WinRM (calling your own FQDN) can be denied even for
        # an elevated admin - a Windows loopback-authentication quirk, not a real
        # permissions gap. Collecting in-process for the local machine sidesteps it and
        # is also just faster (no remoting overhead) for the jump server's own inventory.
        $raw = if (Test-IsLocalComputer -ComputerName $ComputerName) {
            & $collectScript
        } else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $collectScript
        }
    } catch {
        return [pscustomobject]@{
            ComputerName = $ComputerName; Category = $Category
            Name = $null; Version = $null; Publisher = $null; InstallDate = $null
            Architecture = $null; Error = "WinRM/collection failed: $_"
        }
    }

    if (-not $raw) { return @() }

    # De-dup identical Name+Version+Architecture entries seen in multiple hives.
    $seen = @{}
    foreach ($r in $raw) {
        $key = "$($r.Name)|$($r.Version)|$($r.Architecture)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [pscustomobject]@{
            ComputerName = $ComputerName
            Category     = $Category
            Name         = $r.Name
            Version      = $r.Version
            Publisher    = $r.Publisher
            InstallDate  = $r.InstallDate
            Architecture = $r.Architecture
            Error        = $null
        }
    }
}

function Find-VulnerableInstalledSoftware {
    <#
    .SYNOPSIS
        Cross-references the installed-software inventory against zero-day watchlist
        matches (from DCAnomalyAgent.ZeroDay's Get-ZeroDayMatches output) by simple
        product-name substring matching.
    .OUTPUTS
        One row per (software, ZeroDay match) hit: ComputerName, Category,
        SoftwareName, SoftwareVersion, CveId, VulnerabilityName,
        KnownRansomwareCampaignUse, DueDate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Inventory,
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$ZeroDayMatches
    )

    if (-not $Inventory -or -not $ZeroDayMatches) { return @() }

    $installed = $Inventory | Where-Object { -not $_.Error -and $_.Name }
    $hits = foreach ($zd in $ZeroDayMatches) {
        $needle = "$($zd.Product)"
        if (-not $needle) { continue }
        foreach ($sw in $installed) {
            if ($sw.Name -like "*$needle*") {
                [pscustomobject]@{
                    ComputerName               = $sw.ComputerName
                    Category                   = $sw.Category
                    SoftwareName               = $sw.Name
                    SoftwareVersion            = $sw.Version
                    CveId                      = $zd.CveId
                    VulnerabilityName          = $zd.VulnerabilityName
                    KnownRansomwareCampaignUse = $zd.KnownRansomwareCampaignUse
                    DueDate                    = $zd.DueDate
                }
            }
        }
    }
    return @($hits)
}

function Format-SoftwareInventoryReport {
    <#
    .SYNOPSIS
        Renders a markdown software inventory summary: counts by category, top
        products by install count, and any zero-day cross-reference hits.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Inventory,
        [array]$VulnerableHits = @(),
        [datetime]$ScanTime = (Get-Date)
    )

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# Software Inventory Report")
    $null = $sb.AppendLine("**Scan time:** $ScanTime  ")

    $installed = $Inventory | Where-Object { -not $_.Error -and $_.Name }
    $errors    = $Inventory | Where-Object { $_.Error }
    $hosts     = @($installed | Select-Object -ExpandProperty ComputerName -Unique)

    $null = $sb.AppendLine("**Hosts inventoried:** $($hosts.Count)  ")
    $null = $sb.AppendLine("**Total installed-software records:** $($installed.Count)")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## By category")
    $null = $sb.AppendLine("| Category | Hosts |")
    $null = $sb.AppendLine("|---|---|")
    $uniqueHosts = $installed | Select-Object ComputerName, Category -Unique
    foreach ($g in ($uniqueHosts | Group-Object Category)) {
        $null = $sb.AppendLine("| $($g.Name) | $($g.Count) |")
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## Top installed products")
    $null = $sb.AppendLine("| Product | Host count |")
    $null = $sb.AppendLine("|---|---|")
    foreach ($g in ($installed | Group-Object Name | Sort-Object Count -Descending | Select-Object -First 20)) {
        $null = $sb.AppendLine("| $($g.Name) | $($g.Count) |")
    }
    $null = $sb.AppendLine()

    if ($VulnerableHits -and $VulnerableHits.Count -gt 0) {
        $null = $sb.AppendLine("## Zero-day exposure (installed software matching the watchlist)")
        $null = $sb.AppendLine("| Host | Category | Software | CVE | Vulnerability |")
        $null = $sb.AppendLine("|---|---|---|---|---|")
        foreach ($h in $VulnerableHits) {
            $null = $sb.AppendLine("| $($h.ComputerName) | $($h.Category) | $($h.SoftwareName) $($h.SoftwareVersion) | $($h.CveId) | $($h.VulnerabilityName) |")
        }
        $null = $sb.AppendLine()
    }

    if ($errors -and $errors.Count -gt 0) {
        $null = $sb.AppendLine("## Collection issues ($($errors.Count))")
        foreach ($e in $errors) {
            $null = $sb.AppendLine("- **$($e.ComputerName)**: $($e.Error)")
        }
    }

    return $sb.ToString()
}

Export-ModuleMember -Function Get-DeviceCategory, Get-InstalledSoftware, `
    Find-VulnerableInstalledSoftware, Format-SoftwareInventoryReport, Test-IsLocalComputer

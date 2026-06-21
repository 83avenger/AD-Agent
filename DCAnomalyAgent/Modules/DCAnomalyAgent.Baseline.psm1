#Requires -Version 5.1

function Get-Baseline {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$StatePath)

    if (Test-Path -Path $StatePath) {
        $raw = Get-Content -Path $StatePath -Raw | ConvertFrom-Json
        $baseline = @{}
        foreach ($prop in $raw.PSObject.Properties) {
            $baseline[$prop.Name] = @{
                Hours          = [int[]]$prop.Value.Hours
                SourceHosts    = [string[]]$prop.Value.SourceHosts
                DomainControllers = [string[]]$prop.Value.DomainControllers
                Observations   = [int]$prop.Value.Observations
            }
        }
        return $baseline
    }

    return @{}
}

function Save-Baseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Baseline,
        [Parameter(Mandatory)][string]$StatePath
    )

    $dir = Split-Path -Path $StatePath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $Baseline | ConvertTo-Json -Depth 5 | Set-Content -Path $StatePath -Encoding UTF8
}

function Update-Baseline {
    <#
        Folds successful logon events into the rolling per-account baseline and
        returns deviations flagged BEFORE the new observations are merged in,
        so a one-off anomalous event doesn't immediately mask itself.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Baseline,
        [Parameter(Mandatory)][array]$LogonEvents,
        [Parameter(Mandatory)][int]$MinObservationsBeforeFlagging
    )

    $deviations = @()

    foreach ($logon in $LogonEvents) {
        $account = $logon.TargetAccount
        if ([string]::IsNullOrWhiteSpace($account) -or $account -like '*$') { continue }

        if (-not $Baseline.ContainsKey($account)) {
            $Baseline[$account] = @{
                Hours              = @()
                SourceHosts        = @()
                DomainControllers  = @()
                Observations       = 0
            }
        }
        $profile = $Baseline[$account]
        $hour = $logon.TimeCreated.Hour

        if ($profile.Observations -ge $MinObservationsBeforeFlagging) {
            if ($profile.Hours -notcontains $hour) {
                $deviations += [pscustomobject]@{
                    Type        = 'UnusualLogonHour'
                    Account     = $account
                    Detail      = "Logon at hour $hour, outside learned hours: $($profile.Hours -join ',')"
                    TimeCreated = $logon.TimeCreated
                    ComputerName = $logon.ComputerName
                }
            }
            if ($logon.SourceAddress -and ($profile.SourceHosts -notcontains $logon.SourceAddress)) {
                $deviations += [pscustomobject]@{
                    Type        = 'UnseenSourceHost'
                    Account     = $account
                    Detail      = "Logon from new source host: $($logon.SourceAddress)"
                    TimeCreated = $logon.TimeCreated
                    ComputerName = $logon.ComputerName
                }
            }
            if ($profile.DomainControllers -notcontains $logon.ComputerName) {
                $deviations += [pscustomobject]@{
                    Type        = 'UnseenDomainController'
                    Account     = $account
                    Detail      = "First-ever logon to DC: $($logon.ComputerName)"
                    TimeCreated = $logon.TimeCreated
                    ComputerName = $logon.ComputerName
                }
            }
        }

        # Fold this observation into the baseline (rolling window, capped lists).
        $profile.Hours = @($profile.Hours + $hour | Select-Object -Unique | Select-Object -Last 24)
        if ($logon.SourceAddress) {
            $profile.SourceHosts = @($profile.SourceHosts + $logon.SourceAddress | Select-Object -Unique | Select-Object -Last 20)
        }
        $profile.DomainControllers = @($profile.DomainControllers + $logon.ComputerName | Select-Object -Unique)
        $profile.Observations += 1
        $Baseline[$account] = $profile
    }

    return $deviations
}

Export-ModuleMember -Function Get-Baseline, Save-Baseline, Update-Baseline

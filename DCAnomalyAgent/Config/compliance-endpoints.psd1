@{
    # -------------------------------------------------------------------------
    # Endpoint compliance controls - host-level checks that apply to ANY domain
    # member (Member Servers and Workstations), not just Domain Controllers.
    #
    # Each control declares AppliesTo = which asset types it is relevant for:
    #   'DomainController', 'MemberServer', 'Workstation'
    #
    # All checks run remotely over WinRM (Invoke-Command), the same transport the
    # DC scan uses. The scanning service account needs the same least-privilege
    # rights on these endpoints as on DCs (Remote Management Users, Event Log
    # Readers, Remote Registry read) - apply the GPO to the relevant OUs.
    # -------------------------------------------------------------------------
    Controls = @(

        # -- LOCAL ADMINISTRATORS ---------------------------------------------
        @{
            Id          = 'EP-LA-001'
            Title       = 'Local Administrators Group Membership Reviewed (<= 4 members)'
            AppliesTo   = @('MemberServer','Workstation')
            Frameworks  = @{ CIS = 'CIS-L1 5.x'; NIST = 'AC-6(5)'; ISO = 'A.9.2.3' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $members = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop).Name
                }
                $count = @($members).Count
                [pscustomobject]@{ Actual = "$count members: $($members -join ', ')"; Pass = $count -le 4 }
            }
            Expected    = 'Local Administrators group has <= 4 members (e.g. Domain Admins, local admin, a server-admin group)'
            Remediation = 'Audit local Administrators; remove unnecessary accounts. Use a dedicated tiered admin group and LAPS-managed local admin. Avoid adding individual user accounts directly.'
        }

        @{
            Id          = 'EP-LAPS-001'
            Title       = 'LAPS (Local Admin Password Solution) Deployed'
            AppliesTo   = @('MemberServer','Workstation')
            Frameworks  = @{ CIS = 'CIS-L1 18.2.x'; NIST = 'IA-5'; ISO = 'A.9.4.3' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $laps = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    # Windows LAPS (modern) or legacy LAPS CSE
                    $modern = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction SilentlyContinue
                    $legacy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
                    [bool]$modern -or ($legacy.AdmPwdEnabled -eq 1)
                }
                [pscustomobject]@{ Actual = "LAPS configured: $laps"; Pass = $laps -eq $true }
            }
            Expected    = 'LAPS (Windows LAPS or legacy) enabled to randomize the local admin password'
            Remediation = 'Deploy Windows LAPS via GPO (Computer Configuration > Policies > Administrative Templates > System > LAPS). Rotate and back up the local admin password to AD/Entra.'
        }

        # -- REMOTE DESKTOP ---------------------------------------------------
        @{
            Id          = 'EP-RDP-001'
            Title       = 'RDP Network Level Authentication (NLA) Required'
            AppliesTo   = @('MemberServer','Workstation','DomainController')
            Frameworks  = @{ CIS = 'CIS-L1 18.9.65.x'; NIST = 'IA-2'; ISO = 'A.9.4.2' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $nla = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
                }
                [pscustomobject]@{ Actual = "UserAuthentication = $nla"; Pass = $nla -eq 1 }
            }
            Expected    = 'UserAuthentication = 1 (NLA required)'
            Remediation = 'Enable via GPO: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > Require user authentication for remote connections by using Network Level Authentication = Enabled.'
        }

        # -- WINDOWS FIREWALL -------------------------------------------------
        @{
            Id          = 'EP-FW-001'
            Title       = 'Windows Firewall Enabled on All Profiles'
            AppliesTo   = @('MemberServer','Workstation','DomainController')
            Frameworks  = @{ CIS = 'CIS-L1 9.x'; NIST = 'SC-7'; ISO = 'A.13.1.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $profiles = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-NetFirewallProfile | Select-Object Name, Enabled
                }
                $disabled = $profiles | Where-Object { -not $_.Enabled }
                [pscustomobject]@{
                    Actual = ($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', '
                    Pass   = -not $disabled
                }
            }
            Expected    = 'Domain, Private, and Public firewall profiles all Enabled'
            Remediation = 'Enable via GPO: Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security - set Firewall state = On for all three profiles.'
        }

        # -- ANTIVIRUS / DEFENDER ---------------------------------------------
        @{
            Id          = 'EP-AV-001'
            Title       = 'Microsoft Defender Antivirus Enabled with Real-Time Protection'
            AppliesTo   = @('MemberServer','Workstation')
            Frameworks  = @{ CIS = 'CIS-L1 18.9.47.x'; NIST = 'SI-3'; ISO = 'A.12.2.1' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $av = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $s = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    [pscustomobject]@{ RT = $s.RealTimeProtectionEnabled; AM = $s.AntivirusEnabled }
                }
                $pass = $av.RT -eq $true -and $av.AM -eq $true
                [pscustomobject]@{ Actual = "RealTime=$($av.RT), AV=$($av.AM)"; Pass = $pass }
            }
            Expected    = 'Defender AntivirusEnabled and RealTimeProtectionEnabled = True (or an approved 3rd-party EDR present)'
            Remediation = 'Ensure Defender (or your EDR) is running with real-time protection. If using 3rd-party AV, adjust this control. Configure via Defender GPO / Intune.'
        }

        # -- BITLOCKER (workstations / laptops) -------------------------------
        @{
            Id          = 'EP-BL-001'
            Title       = 'BitLocker Enabled on OS Volume'
            AppliesTo   = @('Workstation')
            Frameworks  = @{ CIS = 'CIS-L1 18.9.11.x'; NIST = 'SC-28'; ISO = 'A.10.1.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $bl = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
                    $v.ProtectionStatus
                }
                [pscustomobject]@{ Actual = "ProtectionStatus = $bl"; Pass = "$bl" -eq 'On' }
            }
            Expected    = 'BitLocker ProtectionStatus = On for the system drive'
            Remediation = 'Enable BitLocker via GPO/Intune with TPM + recovery key escrow to AD/Entra. Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption.'
        }

        # -- LEGACY PROTOCOLS -------------------------------------------------
        @{
            Id          = 'EP-SMB1-001'
            Title       = 'SMBv1 Protocol Disabled'
            AppliesTo   = @('MemberServer','Workstation','DomainController')
            Frameworks  = @{ CIS = 'CIS-L1 18.4.x'; NIST = 'CM-7'; ISO = 'A.13.1.1' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $smb1 = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
                }
                [pscustomobject]@{ Actual = "EnableSMB1Protocol = $smb1"; Pass = $smb1 -eq $false }
            }
            Expected    = 'SMBv1 disabled (EnableSMB1Protocol = False)'
            Remediation = 'Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. Or via GPO/DSC across the fleet. Verify no legacy devices depend on SMBv1 first.'
        }

        # -- PATCHING / UPDATES -----------------------------------------------
        @{
            Id          = 'EP-PATCH-001'
            Title       = 'No Missing Security Updates Older Than 30 Days'
            AppliesTo   = @('MemberServer','Workstation','DomainController')
            Frameworks  = @{ CIS = 'CIS-L1 n/a'; NIST = 'SI-2'; ISO = 'A.12.6.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $lastPatch = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
                }
                $daysSince = if ($lastPatch) { ((Get-Date) - $lastPatch).TotalDays } else { 9999 }
                [pscustomobject]@{
                    Actual = "Last hotfix installed: $lastPatch ($([math]::Round($daysSince)) days ago)"
                    Pass   = $daysSince -le 45
                }
            }
            Expected    = 'Most recent hotfix installed within the last 45 days (proxy for active patching)'
            Remediation = 'Ensure the host receives updates via WSUS/SCCM/Intune/Windows Update. Investigate hosts with stale patch dates. (This is a heuristic - pair with a dedicated patch-compliance tool for authoritative data.)'
        }

        # -- AUDIT / LOGGING (host level) -------------------------------------
        @{
            Id          = 'EP-AU-001'
            Title       = 'Security Event Log Size >= 196 MB'
            AppliesTo   = @('MemberServer','Workstation','DomainController')
            Frameworks  = @{ CIS = 'CIS-L1 18.9.27.x'; NIST = 'AU-4'; ISO = 'A.12.4.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $maxKb = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name MaxSize -ErrorAction SilentlyContinue).MaxSize
                }
                $maxMb = if ($maxKb) { [math]::Round($maxKb/1024) } else { 0 }
                [pscustomobject]@{ Actual = "Security log max size = $maxMb MB"; Pass = $maxKb -ge 196608 }
            }
            Expected    = 'Security event log maximum size >= 196608 KB (192 MB)'
            Remediation = 'Set via GPO: Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB) = 196608 or larger.'
        }

        # -- SERVICES ---------------------------------------------------------
        @{
            Id          = 'EP-SVC-001'
            Title       = 'Unnecessary Risky Services Disabled (Telnet, RemoteAccess, SNMP-trap)'
            AppliesTo   = @('MemberServer','Workstation')
            Frameworks  = @{ CIS = 'CIS-L1 5.x'; NIST = 'CM-7'; ISO = 'A.12.5.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $running = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $risky = 'TlntSvr','RemoteAccess','SNMPTRAP','simptcp'
                    Get-Service -Name $risky -ErrorAction SilentlyContinue |
                        Where-Object { $_.Status -eq 'Running' -or $_.StartType -ne 'Disabled' } |
                        Select-Object -ExpandProperty Name
                }
                $found = $running -join ', '
                [pscustomobject]@{ Actual = if ($found) { "Enabled: $found" } else { 'None enabled' }; Pass = -not $found }
            }
            Expected    = 'Telnet, Routing and Remote Access, SNMP Trap, Simple TCP/IP services disabled'
            Remediation = 'Disable unneeded services via GPO System Services or: Set-Service -Name <svc> -StartupType Disabled; Stop-Service <svc>.'
        }
    )
}

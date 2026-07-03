@{
    # ─────────────────────────────────────────────────────────────────────────
    # HIPAA Security Rule compliance controls (45 CFR Part 164, Subpart C).
    #
    # Technical safeguards (§164.312) and selected administrative safeguards
    # (§164.308) that can be verified technically on Windows and Linux hosts.
    # Checks run over WinRM (Windows) or SSH (Linux) — same transports and
    # least-privilege rights as the other framework files.
    #
    # Each control carries a HIPAA citation plus NIST/ISO cross-references so a
    # single scan can serve multiple audits.
    # ─────────────────────────────────────────────────────────────────────────
    Controls = @(

        # ── ACCESS CONTROL — §164.312(a) ─────────────────────────────────────
        @{
            Id          = 'HI-AC-001'
            Title       = 'Built-in Guest Account Disabled'
            AppliesTo   = @('DomainController','MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.312(a)(1)'; NIST = 'AC-2'; ISO = 'A.9.2.1'; CIS = 'CIS-L1 2.3.1.2' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $enabled = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled
                }
                [pscustomobject]@{ Actual = "Guest enabled: $enabled"; Pass = $enabled -ne $true }
            }
            Expected    = 'Guest account disabled (no anonymous access path to systems that may hold ePHI)'
            Remediation = 'Disable via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Guest account status = Disabled.'
        }

        @{
            Id          = 'HI-AC-002'
            Title       = 'Automatic Logoff — Machine Inactivity Limit <= 15 Minutes'
            AppliesTo   = @('DomainController','MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.312(a)(2)(iii)'; NIST = 'AC-11'; ISO = 'A.11.2.8'; CIS = 'CIS-L1 2.3.7.x' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $secs = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction SilentlyContinue).InactivityTimeoutSecs
                }
                [pscustomobject]@{ Actual = "InactivityTimeoutSecs = $secs"; Pass = ($secs -gt 0 -and $secs -le 900) }
            }
            Expected    = 'InactivityTimeoutSecs between 1 and 900 (sessions lock automatically)'
            Remediation = 'Set via GPO: Security Options > Interactive logon: Machine inactivity limit = 900 seconds or less.'
        }

        @{
            Id          = 'HI-AC-003'
            Title       = 'Account Lockout Threshold Configured'
            AppliesTo   = @('MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.312(a)(1)'; NIST = 'AC-7'; ISO = 'A.9.4.2'; CIS = 'CIS-L1 1.2.2' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $threshold = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $line = (net accounts) | Where-Object { $_ -match 'Lockout threshold' }
                    if ($line -match '(\d+)') { [int]$Matches[1] } else { 0 }
                }
                [pscustomobject]@{ Actual = "Lockout threshold = $threshold"; Pass = ($threshold -gt 0 -and $threshold -le 10) }
            }
            Expected    = 'Effective lockout threshold between 1 and 10 failed attempts'
            Remediation = 'Set via domain GPO: Account Policies > Account Lockout Policy > Account lockout threshold = 5 (or organizational standard <= 10).'
        }

        # ── ENCRYPTION AT REST — §164.312(a)(2)(iv) ──────────────────────────
        @{
            Id          = 'HI-EN-001'
            Title       = 'Disk Encryption (BitLocker) on Systems That May Store ePHI'
            AppliesTo   = @('MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.312(a)(2)(iv)'; NIST = 'SC-28'; ISO = 'A.10.1.1'; CIS = 'CIS-L1 18.10.9.x' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $status = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $v = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue
                    if ($v) { $v.ProtectionStatus } else { 'NotAvailable' }
                }
                [pscustomobject]@{ Actual = "C: ProtectionStatus = $status"; Pass = "$status" -eq 'On' }
            }
            Expected    = 'BitLocker protection On for the OS volume'
            Remediation = 'Enable BitLocker with TPM protector via GPO/Intune; escrow recovery keys to AD (Computer Configuration > Administrative Templates > Windows Components > BitLocker Drive Encryption).'
        }

        # ── AUDIT CONTROLS — §164.312(b) ─────────────────────────────────────
        @{
            Id          = 'HI-AU-001'
            Title       = 'Security Event Log Size Supports Activity Review (>= 1 GB)'
            AppliesTo   = @('DomainController','MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.312(b)'; NIST = 'AU-4'; ISO = 'A.12.4.1'; CIS = 'CIS-L1 17.x' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $maxKb = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-WinEvent -ListLog Security).MaximumSizeInBytes / 1KB
                }
                [pscustomobject]@{ Actual = "Security log max = $([math]::Round($maxKb/1024)) MB"; Pass = $maxKb -ge 1048576 }
            }
            Expected    = 'Security log maximum size >= 1 GB so audit history survives review cycles'
            Remediation = 'Set via GPO: Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size = 1048576 KB or more.'
        }

        @{
            Id          = 'HI-AU-002'
            Title       = 'Logon/Logoff Auditing Enabled (Information System Activity Review)'
            AppliesTo   = @('DomainController','MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.308(a)(1)(ii)(D)'; NIST = 'AU-2'; ISO = 'A.12.4.1'; CIS = 'CIS-L1 17.5.x' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $out = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    auditpol /get /subcategory:'Logon' 2>$null
                }
                $configured = ($out -join ' ') -match 'Success and Failure|Success|Failure'
                $full = ($out -join ' ') -match 'Success and Failure'
                [pscustomobject]@{ Actual = if ($configured) { ($out | Where-Object { $_ -match 'Logon' }) -join '; ' } else { 'Not configured' }; Pass = $full }
            }
            Expected    = 'Audit Logon = Success and Failure'
            Remediation = 'Set via GPO: Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon = Success and Failure.'
        }

        # ── INTEGRITY — §164.312(c)(1) ───────────────────────────────────────
        @{
            Id          = 'HI-IN-001'
            Title       = 'SMBv1 Protocol Disabled'
            AppliesTo   = @('DomainController','MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.312(c)(1)'; NIST = 'SI-7'; ISO = 'A.13.1.3'; CIS = 'CIS-L1 18.3.x' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $smb1 = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-SmbServerConfiguration).EnableSMB1Protocol
                }
                [pscustomobject]@{ Actual = "EnableSMB1Protocol = $smb1"; Pass = $smb1 -eq $false }
            }
            Expected    = 'SMBv1 disabled (no unauthenticated tampering path for data in transit)'
            Remediation = 'Set-SmbServerConfiguration -EnableSMB1Protocol $false and remove the SMB1 feature (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).'
        }

        # ── TRANSMISSION SECURITY — §164.312(e)(1) ───────────────────────────
        @{
            Id          = 'HI-TS-001'
            Title       = 'SMB Signing Required (ePHI Integrity in Transit)'
            AppliesTo   = @('DomainController','MemberServer','Workstation')
            Frameworks  = @{ HIPAA = '164.312(e)(1)'; NIST = 'SC-8'; ISO = 'A.13.2.1'; CIS = 'CIS-L1 2.3.9.x' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $sign = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-SmbServerConfiguration).RequireSecuritySignature
                }
                [pscustomobject]@{ Actual = "RequireSecuritySignature = $sign"; Pass = $sign -eq $true }
            }
            Expected    = 'SMB server signing required'
            Remediation = 'Set via GPO: Security Options > Microsoft network server: Digitally sign communications (always) = Enabled.'
        }

        @{
            Id          = 'HI-TS-002'
            Title       = 'Legacy TLS 1.0/1.1 Server Protocols Disabled'
            AppliesTo   = @('DomainController','MemberServer')
            Frameworks  = @{ HIPAA = '164.312(e)(1)'; NIST = 'SC-8(1)'; ISO = 'A.13.2.1'; CIS = 'CIS-L1 18.x' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $legacy = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $bad = @()
                    foreach ($proto in 'TLS 1.0','TLS 1.1') {
                        $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto\Server"
                        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
                        # Missing key or Enabled != 0 means the OS default (often enabled) applies
                        if (-not $p -or $p.Enabled -ne 0) { $bad += $proto }
                    }
                    $bad -join ', '
                }
                [pscustomobject]@{
                    Actual = if ($legacy) { "Not explicitly disabled: $legacy" } else { 'TLS 1.0/1.1 disabled' }
                    Pass   = -not $legacy
                }
            }
            Expected    = 'SChannel server registry keys set: TLS 1.0 and 1.1 Enabled = 0'
            Remediation = 'Under HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols, set Server\Enabled=0 and Server\DisabledByDefault=1 for TLS 1.0 and TLS 1.1. Deploy via GPO registry preferences; reboot required.'
        }

        # ── LINUX — audit controls over SSH ──────────────────────────────────
        @{
            Id          = 'HI-LX-001'
            Title       = 'Linux Audit Daemon (auditd) Active for Activity Review'
            AppliesTo   = @('Linux')
            Frameworks  = @{ HIPAA = '164.312(b)'; NIST = 'AU-2'; ISO = 'A.12.4.1'; CIS = 'CIS-DIL 4.1.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName, $Ctx)
                $sshArgs = @('-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-p',"$($Ctx.Port)",'-i',"$($Ctx.KeyPath)","$($Ctx.User)@$ComputerName")
                $state = (& ssh.exe @sshArgs 'systemctl is-active auditd 2>/dev/null') -join ''
                [pscustomobject]@{ Actual = "auditd: $state"; Pass = $state -eq 'active' }
            }
            Expected    = 'auditd service active'
            Remediation = 'Install and enable auditd (apt/dnf install audit; systemctl enable --now auditd). Configure rules for authentication and file access events on ePHI paths.'
        }
    )
}

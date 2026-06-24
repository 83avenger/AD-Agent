@{
    # ─────────────────────────────────────────────────────────────────────────
    # Linux / Unix compliance controls — CIS Distribution Independent Linux
    # benchmark subset, mapped to NIST 800-53 and ISO 27001.
    #
    # Transport: SSH (not WinRM). Each Check receives a second argument $Ctx with
    # SSH connection details: @{ User; KeyPath; Port }. The Windows OpenSSH client
    # (ssh.exe) ships with Windows Server 2019+ and is used to run remote commands
    # with key-based, non-interactive auth (BatchMode=yes).
    #
    # Prereqs on each Linux host:
    #   - sshd running, key-based auth for the scan user
    #   - the scan user is unprivileged; checks that need root use sudo NOPASSWD
    #     for the specific read-only commands, OR rely on world-readable config.
    #     The controls below favour world-readable files to avoid needing sudo.
    # ─────────────────────────────────────────────────────────────────────────
    Controls = @(

        # ── SSH HARDENING ────────────────────────────────────────────────────
        @{
            Id          = 'LX-SSH-001'
            Title       = 'SSH PermitRootLogin Disabled'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 5.2.x'; NIST = 'AC-6(2)'; ISO = 'A.9.2.3' }
            Severity    = 'High'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=10 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "sshd -T 2>/dev/null | grep -i permitrootlogin || grep -Ei '^\s*PermitRootLogin' /etc/ssh/sshd_config"
                $val = ("$out").Trim()
                [pscustomobject]@{ Actual = $val; Pass = $val -match 'permitrootlogin\s+no' }
            }
            Expected    = 'PermitRootLogin no'
            Remediation = 'Set "PermitRootLogin no" in /etc/ssh/sshd_config and restart sshd. Use sudo from a named account instead of direct root login.'
        }

        @{
            Id          = 'LX-SSH-002'
            Title       = 'SSH Password Authentication Disabled (key-based only)'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 5.2.x'; NIST = 'IA-2'; ISO = 'A.9.4.2' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=10 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "sshd -T 2>/dev/null | grep -i passwordauthentication"
                $val = ("$out").Trim()
                [pscustomobject]@{ Actual = $val; Pass = $val -match 'passwordauthentication\s+no' }
            }
            Expected    = 'PasswordAuthentication no'
            Remediation = 'Set "PasswordAuthentication no" in /etc/ssh/sshd_config (ensure key-based access works first) and restart sshd.'
        }

        # ── FIREWALL ─────────────────────────────────────────────────────────
        @{
            Id          = 'LX-FW-001'
            Title       = 'Host Firewall Active (ufw / firewalld / nftables)'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 3.5.x'; NIST = 'SC-7'; ISO = 'A.13.1.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=10 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "systemctl is-active firewalld 2>/dev/null; systemctl is-active ufw 2>/dev/null; systemctl is-active nftables 2>/dev/null"
                $active = "$out" -match 'active'
                [pscustomobject]@{ Actual = ("$out").Trim() -replace '\s+',' '; Pass = $active }
            }
            Expected    = 'At least one host firewall service active'
            Remediation = 'Enable a host firewall: "systemctl enable --now firewalld" (RHEL) or "ufw enable" (Debian/Ubuntu) with a default-deny inbound policy.'
        }

        # ── AUDITING ─────────────────────────────────────────────────────────
        @{
            Id          = 'LX-AU-001'
            Title       = 'auditd Service Running'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 4.1.x'; NIST = 'AU-2'; ISO = 'A.12.4.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=10 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "systemctl is-active auditd 2>/dev/null"
                $val = ("$out").Trim()
                [pscustomobject]@{ Actual = "auditd: $val"; Pass = $val -eq 'active' }
            }
            Expected    = 'auditd service active'
            Remediation = 'Install and enable auditd: "yum install audit" / "apt install auditd", then "systemctl enable --now auditd".'
        }

        # ── MANDATORY ACCESS CONTROL ─────────────────────────────────────────
        @{
            Id          = 'LX-MAC-001'
            Title       = 'SELinux or AppArmor Enforcing'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 1.6.x'; NIST = 'AC-3'; ISO = 'A.9.4.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=10 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "getenforce 2>/dev/null; aa-status --enabled 2>/dev/null && echo apparmor-enabled"
                $val = ("$out").Trim() -replace '\s+',' '
                $pass = $val -match 'Enforcing' -or $val -match 'apparmor-enabled'
                [pscustomobject]@{ Actual = $val; Pass = $pass }
            }
            Expected    = 'SELinux Enforcing or AppArmor enabled'
            Remediation = 'Enable SELinux (set SELINUX=enforcing in /etc/selinux/config, relabel, reboot) or AppArmor ("systemctl enable --now apparmor").'
        }

        # ── PASSWORD POLICY ──────────────────────────────────────────────────
        @{
            Id          = 'LX-PW-001'
            Title       = 'Password Max Age <= 365 days (PASS_MAX_DAYS)'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 5.4.1.x'; NIST = 'IA-5(1)'; ISO = 'A.9.4.3' }
            Severity    = 'Low'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=10 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "grep -E '^PASS_MAX_DAYS' /etc/login.defs"
                $days = ([regex]::Match("$out", '\d+').Value)
                $ok = $days -and [int]$days -le 365 -and [int]$days -gt 0
                [pscustomobject]@{ Actual = ("$out").Trim(); Pass = [bool]$ok }
            }
            Expected    = 'PASS_MAX_DAYS between 1 and 365'
            Remediation = 'Set "PASS_MAX_DAYS 365" (or less) in /etc/login.defs and apply to existing users with chage.'
        }

        # ── LEGACY SERVICES ──────────────────────────────────────────────────
        @{
            Id          = 'LX-SVC-001'
            Title       = 'Legacy Insecure Services Not Installed (telnet, rsh, ftp)'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 2.x'; NIST = 'CM-7'; ISO = 'A.13.1.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=10 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "for s in telnet.socket rsh.socket vsftpd; do systemctl is-enabled \$s 2>/dev/null && echo \$s-enabled; done"
                $found = "$out" -match 'enabled'
                [pscustomobject]@{ Actual = if ($found) { ("$out").Trim() } else { 'None enabled' }; Pass = -not $found }
            }
            Expected    = 'telnet, rsh, ftp services not enabled'
            Remediation = 'Remove/disable legacy cleartext services: "systemctl disable --now telnet.socket rsh.socket vsftpd" and uninstall the packages.'
        }

        # ── PATCHING ─────────────────────────────────────────────────────────
        @{
            Id          = 'LX-PATCH-001'
            Title       = 'No Pending Security Updates'
            AppliesTo   = @('Linux')
            Frameworks  = @{ CIS = 'CIS-DIL 1.9'; NIST = 'SI-2'; ISO = 'A.12.6.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName, $Ctx)
                $out = & ssh -i $Ctx.KeyPath -p $Ctx.Port -o BatchMode=yes -o ConnectTimeout=15 `
                    -o StrictHostKeyChecking=accept-new "$($Ctx.User)@$ComputerName" `
                    "(yum -q updateinfo list security 2>/dev/null | grep -c Sec) || (apt-get -s upgrade 2>/dev/null | grep -ci '^Inst.*security')"
                $count = ([regex]::Match("$out", '\d+').Value)
                $ok = $count -ne '' -and [int]$count -eq 0
                [pscustomobject]@{ Actual = "Pending security updates: $count"; Pass = [bool]$ok }
            }
            Expected    = 'Zero pending security updates'
            Remediation = 'Apply security updates: "yum update --security" (RHEL) or "apt-get upgrade" (Debian/Ubuntu). Enable unattended-upgrades / dnf-automatic for ongoing patching.'
        }
    )
}

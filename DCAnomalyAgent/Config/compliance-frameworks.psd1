@{
    Controls = @(

        # -----------------------------------------------------------------
        # PASSWORD POLICY
        # -----------------------------------------------------------------
        @{
            Id          = 'PP-001'
            Title       = 'Minimum Password Length >= 14 characters'
            Frameworks  = @{
                CIS   = 'CIS-L1 1.1.1'
                NIST  = 'IA-5(1)(a)'
                ISO   = 'A.9.4.3'
            }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                [pscustomobject]@{ Actual = $policy.MinPasswordLength; Pass = $policy.MinPasswordLength -ge 14 }
            }
            Expected    = 'Minimum password length >= 14'
            Remediation = 'Set via Default Domain Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy > Minimum password length = 14 (or higher).'
        }

        @{
            Id          = 'PP-002'
            Title       = 'Password Complexity Enabled'
            Frameworks  = @{ CIS = 'CIS-L1 1.1.5'; NIST = 'IA-5(1)(a)'; ISO = 'A.9.4.3' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                [pscustomobject]@{ Actual = $policy.ComplexityEnabled; Pass = $policy.ComplexityEnabled -eq $true }
            }
            Expected    = 'ComplexityEnabled = True'
            Remediation = 'Enable via Default Domain Policy > Password Policy > Password must meet complexity requirements = Enabled.'
        }

        @{
            Id          = 'PP-003'
            Title       = 'Maximum Password Age <= 365 days'
            Frameworks  = @{ CIS = 'CIS-L1 1.1.2'; NIST = 'IA-5(1)(d)'; ISO = 'A.9.4.3' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                $days = $policy.MaxPasswordAge.TotalDays
                [pscustomobject]@{ Actual = "$days days"; Pass = $days -le 365 -and $days -gt 0 }
            }
            Expected    = 'MaxPasswordAge between 1 and 365 days'
            Remediation = 'Set Maximum password age <= 365 days in Default Domain Policy > Password Policy.'
        }

        @{
            Id          = 'PP-004'
            Title       = 'Password History Count >= 24'
            Frameworks  = @{ CIS = 'CIS-L1 1.1.4'; NIST = 'IA-5(1)(e)'; ISO = 'A.9.4.3' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                [pscustomobject]@{ Actual = $policy.PasswordHistoryCount; Pass = $policy.PasswordHistoryCount -ge 24 }
            }
            Expected    = 'PasswordHistoryCount >= 24'
            Remediation = 'Set Enforce password history = 24 or more in Default Domain Policy > Password Policy.'
        }

        @{
            Id          = 'PP-005'
            Title       = 'Reversible Encryption Disabled'
            Frameworks  = @{ CIS = 'CIS-L1 1.1.7'; NIST = 'SC-28'; ISO = 'A.10.1.1' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                [pscustomobject]@{ Actual = $policy.ReversibleEncryptionEnabled; Pass = $policy.ReversibleEncryptionEnabled -eq $false }
            }
            Expected    = 'ReversibleEncryptionEnabled = False'
            Remediation = 'Disable "Store passwords using reversible encryption" in Default Domain Policy > Password Policy immediately; enforce a password reset cycle afterwards.'
        }

        # -----------------------------------------------------------------
        # ACCOUNT LOCKOUT POLICY
        # -----------------------------------------------------------------
        @{
            Id          = 'AL-001'
            Title       = 'Account Lockout Threshold <= 10 attempts'
            Frameworks  = @{ CIS = 'CIS-L1 1.2.1'; NIST = 'AC-7'; ISO = 'A.9.4.2' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                $t = $policy.LockoutThreshold
                [pscustomobject]@{ Actual = $t; Pass = $t -gt 0 -and $t -le 10 }
            }
            Expected    = 'LockoutThreshold between 1 and 10'
            Remediation = 'Set Account lockout threshold = 5-10 in Default Domain Policy > Account Lockout Policy.'
        }

        @{
            Id          = 'AL-002'
            Title       = 'Lockout Duration >= 15 minutes'
            Frameworks  = @{ CIS = 'CIS-L1 1.2.2'; NIST = 'AC-7'; ISO = 'A.9.4.2' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                $mins = $policy.LockoutDuration.TotalMinutes
                [pscustomobject]@{ Actual = "$mins min"; Pass = $mins -ge 15 }
            }
            Expected    = 'LockoutDuration >= 15 minutes'
            Remediation = 'Set Account lockout duration >= 15 minutes in Default Domain Policy > Account Lockout Policy.'
        }

        # -----------------------------------------------------------------
        # AUDIT POLICY
        # -----------------------------------------------------------------
        @{
            Id          = 'AU-001'
            Title       = 'Audit Account Logon Events (Success + Failure)'
            Frameworks  = @{ CIS = 'CIS-L1 17.1.1'; NIST = 'AU-2'; ISO = 'A.12.4.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $raw = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    auditpol /get /subcategory:"Credential Validation" /r | ConvertFrom-Csv | Select-Object -Property 'Inclusion Setting'
                }
                $setting = $raw.'Inclusion Setting'
                [pscustomobject]@{ Actual = $setting; Pass = $setting -match 'Success and Failure' }
            }
            Expected    = 'Credential Validation: Success and Failure'
            Remediation = 'Configure via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > Account Logon > Credential Validation = Success and Failure.'
        }

        @{
            Id          = 'AU-002'
            Title       = 'Audit Account Management (Success + Failure)'
            Frameworks  = @{ CIS = 'CIS-L1 17.2.1'; NIST = 'AU-2'; ISO = 'A.12.4.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $raw = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    auditpol /get /subcategory:"User Account Management" /r | ConvertFrom-Csv | Select-Object -Property 'Inclusion Setting'
                }
                $setting = $raw.'Inclusion Setting'
                [pscustomobject]@{ Actual = $setting; Pass = $setting -match 'Success and Failure' }
            }
            Expected    = 'User Account Management: Success and Failure'
            Remediation = 'Configure via GPO: Advanced Audit Policy > Account Management > User Account Management = Success and Failure.'
        }

        @{
            Id          = 'AU-003'
            Title       = 'Audit Policy Change (Success + Failure)'
            Frameworks  = @{ CIS = 'CIS-L1 17.7.1'; NIST = 'AU-2'; ISO = 'A.12.4.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $raw = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    auditpol /get /subcategory:"Audit Policy Change" /r | ConvertFrom-Csv | Select-Object -Property 'Inclusion Setting'
                }
                $setting = $raw.'Inclusion Setting'
                [pscustomobject]@{ Actual = $setting; Pass = $setting -match 'Success and Failure' }
            }
            Expected    = 'Audit Policy Change: Success and Failure'
            Remediation = 'Configure via GPO: Advanced Audit Policy > Policy Change > Audit Policy Change = Success and Failure.'
        }

        @{
            Id          = 'AU-004'
            Title       = 'Audit Privilege Use (Success + Failure)'
            Frameworks  = @{ CIS = 'CIS-L1 17.8.1'; NIST = 'AU-2'; ISO = 'A.12.4.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $raw = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    auditpol /get /subcategory:"Sensitive Privilege Use" /r | ConvertFrom-Csv | Select-Object -Property 'Inclusion Setting'
                }
                $setting = $raw.'Inclusion Setting'
                [pscustomobject]@{ Actual = $setting; Pass = $setting -match 'Success and Failure' }
            }
            Expected    = 'Sensitive Privilege Use: Success and Failure'
            Remediation = 'Configure via GPO: Advanced Audit Policy > Privilege Use > Sensitive Privilege Use = Success and Failure.'
        }

        # -----------------------------------------------------------------
        # NETWORK / PROTOCOL HARDENING
        # -----------------------------------------------------------------
        @{
            Id          = 'NT-001'
            Title       = 'SMB Signing Required'
            Frameworks  = @{ CIS = 'CIS-L1 2.3.9.5'; NIST = 'SC-8'; ISO = 'A.13.2.1' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $val = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters' -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
                }
                [pscustomobject]@{ Actual = $val; Pass = $val -eq 1 }
            }
            Expected    = 'RequireSecuritySignature = 1'
            Remediation = 'Enable via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client: Digitally sign communications (always) = Enabled.'
        }

        @{
            Id          = 'NT-002'
            Title       = 'LDAP Signing Required'
            Frameworks  = @{ CIS = 'CIS-L1 2.3.9.8'; NIST = 'SC-8'; ISO = 'A.13.2.1' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $val = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue).LDAPServerIntegrity
                }
                [pscustomobject]@{ Actual = $val; Pass = $val -eq 2 }
            }
            Expected    = 'LDAPServerIntegrity = 2 (Require signing)'
            Remediation = 'Set via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements = Require signing.'
        }

        @{
            Id          = 'NT-003'
            Title       = 'NTLMv1 Authentication Disabled'
            Frameworks  = @{ CIS = 'CIS-L1 2.3.11.7'; NIST = 'IA-3'; ISO = 'A.9.4.2' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $val = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue).LmCompatibilityLevel
                }
                [pscustomobject]@{ Actual = $val; Pass = $val -ge 5 }
            }
            Expected    = 'LmCompatibilityLevel >= 5 (Send NTLMv2 responses only; refuse LM & NTLM)'
            Remediation = 'Set via GPO: Security Options > Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM. Verify no legacy clients break before enforcing.'
        }

        @{
            Id          = 'NT-004'
            Title       = 'WinRM Using HTTPS or Kerberos Encryption'
            Frameworks  = @{ CIS = 'CIS-L1 18.9.86.2'; NIST = 'SC-8'; ISO = 'A.13.2.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $listeners = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate
                }
                $httpsPresent = $listeners | Where-Object { $_.Transport -eq 'HTTPS' }
                [pscustomobject]@{ Actual = ($listeners.Transport -join ','); Pass = $null -ne $httpsPresent }
            }
            Expected    = 'HTTPS WinRM listener present'
            Remediation = 'Create a HTTPS listener: New-WSManInstance winrm/config/Listener -SelectorSet @{Transport="HTTPS"} -ValueSet @{CertificateThumbprint="<thumbprint>"}. Bind a valid server cert.'
        }

        # -----------------------------------------------------------------
        # PRIVILEGED ACCESS
        # -----------------------------------------------------------------
        @{
            Id          = 'PA-001'
            Title       = 'Domain Admins Group Has <= 5 Members'
            Frameworks  = @{ CIS = 'CIS-L1 2.2'; NIST = 'AC-6(5)'; ISO = 'A.9.2.3' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $members = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ADGroupMember -Identity 'Domain Admins' -Recursive).Count
                }
                [pscustomobject]@{ Actual = "$members members"; Pass = $members -le 5 }
            }
            Expected    = 'Domain Admins membership <= 5 accounts'
            Remediation = 'Audit Domain Admins; remove accounts that do not require persistent DA rights. Use JIT/PAM solutions (e.g. Microsoft Identity Manager, Entra ID PIM) for time-limited elevation instead of permanent membership.'
        }

        @{
            Id          = 'PA-002'
            Title       = 'Built-in Administrator Account Disabled or Renamed'
            Frameworks  = @{ CIS = 'CIS-L1 2.3.1.2'; NIST = 'AC-2'; ISO = 'A.9.2.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $acct = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-ADUser -Filter { SID -like '*-500' } -Properties Enabled, Name | Select-Object Name, Enabled
                }
                $pass = (-not $acct.Enabled) -or ($acct.Name -ne 'Administrator')
                [pscustomobject]@{ Actual = "Name=$($acct.Name), Enabled=$($acct.Enabled)"; Pass = $pass }
            }
            Expected    = 'Built-in Administrator (RID 500) disabled or renamed from default'
            Remediation = 'Disable: Disable-ADAccount -Identity Administrator. Or rename it via AD Users & Computers. Ensure a separate named admin account exists before disabling.'
        }

        @{
            Id          = 'PA-003'
            Title       = 'Guest Account Disabled'
            Frameworks  = @{ CIS = 'CIS-L1 2.3.1.5'; NIST = 'AC-2(3)'; ISO = 'A.9.2.1' }
            Severity    = 'High'
            Check       = {
                param($ComputerName)
                $acct = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-ADUser -Filter { SID -like '*-501' } -Properties Enabled | Select-Object Enabled
                }
                [pscustomobject]@{ Actual = "Enabled=$($acct.Enabled)"; Pass = $acct.Enabled -eq $false }
            }
            Expected    = 'Guest account (RID 501) disabled'
            Remediation = 'Disable-ADAccount -Identity Guest'
        }

        @{
            Id          = 'PA-004'
            Title       = 'No Service Accounts Are Members of Domain Admins'
            Frameworks  = @{ CIS = 'CIS-L2 4.2'; NIST = 'AC-6(5)'; ISO = 'A.9.2.3' }
            Severity    = 'Critical'
            Check       = {
                param($ComputerName)
                $members = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    Get-ADGroupMember -Identity 'Domain Admins' -Recursive |
                        Where-Object { $_.Name -match 'svc|service|sa[-_]' } |
                        Select-Object -ExpandProperty Name
                }
                $found = $members -join ', '
                [pscustomobject]@{ Actual = if ($found) { $found } else { 'None' }; Pass = -not $found }
            }
            Expected    = 'No accounts matching svc/service/sa- pattern in Domain Admins'
            Remediation = 'Remove service accounts from Domain Admins immediately. Grant only the minimum AD permissions required, scoped to the specific OU/object they need.'
        }

        # -----------------------------------------------------------------
        # KERBEROS
        # -----------------------------------------------------------------
        @{
            Id          = 'KB-001'
            Title       = 'Kerberos Max Ticket Lifetime <= 10 Hours'
            Frameworks  = @{ CIS = 'CIS-L1 5.1'; NIST = 'IA-5'; ISO = 'A.9.4.3' }
            Severity    = 'Low'
            Check       = {
                param($ComputerName)
                $policy = Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-ADDefaultDomainPasswordPolicy }
                $hours = (Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ADObject -SearchBase (Get-ADDomain).DistinguishedName -Filter { objectClass -eq 'domain' } -Properties kerberosMaxTicketAge).kerberosMaxTicketAge
                })
                if (-not $hours) { $hours = 10 }
                [pscustomobject]@{ Actual = "$hours hours"; Pass = $hours -le 10 }
            }
            Expected    = 'Max Kerberos ticket lifetime <= 10 hours'
            Remediation = 'Set via Default Domain Policy: Account Policies > Kerberos Policy > Maximum lifetime for user ticket = 10 hours or less.'
        }

        # -----------------------------------------------------------------
        # DOMAIN / FOREST
        # -----------------------------------------------------------------
        @{
            Id          = 'DF-001'
            Title       = 'Domain Functional Level >= Windows Server 2012 R2'
            Frameworks  = @{ CIS = 'CIS-L1 n/a'; NIST = 'CM-6'; ISO = 'A.12.6.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $level = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ADDomain).DomainMode
                }
                $acceptable = @('Windows2012R2Domain', 'Windows2016Domain', 'Windows2019Domain', 'Windows2022Domain', 'Windows2025Domain')
                [pscustomobject]@{ Actual = $level; Pass = $level -in $acceptable }
            }
            Expected    = 'DomainMode >= Windows2012R2Domain'
            Remediation = 'Raise the domain functional level once all DCs are upgraded: Set-ADDomainMode -Identity contoso.com -DomainMode Windows2016Domain. Requires all DCs to be on the target OS first.'
        }

        @{
            Id          = 'DF-002'
            Title       = 'Fine-Grained Password Policies in Use'
            Frameworks  = @{ CIS = 'CIS-L2 n/a'; NIST = 'IA-5'; ISO = 'A.9.4.3' }
            Severity    = 'Low'
            Check       = {
                param($ComputerName)
                $fgpp = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    (Get-ADFineGrainedPasswordPolicy -Filter *).Count
                }
                [pscustomobject]@{ Actual = "$fgpp FGPP policy/policies defined"; Pass = $fgpp -gt 0 }
            }
            Expected    = 'At least one Fine-Grained Password Policy defined'
            Remediation = 'Create FGPPs for privileged groups to enforce stricter password requirements than the default domain policy: New-ADFineGrainedPasswordPolicy -Name "PrivilegedAccounts-Policy" -Precedence 10 -MinPasswordLength 20 ...'
        }

        @{
            Id          = 'DF-003'
            Title       = 'AD Recycle Bin Enabled'
            Frameworks  = @{ CIS = 'CIS-L2 n/a'; NIST = 'CP-9'; ISO = 'A.12.3.1' }
            Severity    = 'Medium'
            Check       = {
                param($ComputerName)
                $enabled = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    $forest = Get-ADForest
                    $dn = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($forest.PartitionsContainer.Split(',')[1..99] -join ',')"
                    $obj = Get-ADObject $dn -Properties msDS-EnabledFeatureBL -ErrorAction SilentlyContinue
                    $obj.'msDS-EnabledFeatureBL' -ne $null
                }
                [pscustomobject]@{ Actual = $enabled; Pass = $enabled -eq $true }
            }
            Expected    = 'AD Recycle Bin = Enabled'
            Remediation = 'Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name'
        }
    )
}

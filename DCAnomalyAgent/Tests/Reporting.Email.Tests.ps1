#Requires -Modules Pester

BeforeAll {
    Import-Module "$PSScriptRoot\..\Modules\DCAnomalyAgent.Reporting.psm1" -Force

    $script:EmailConfig = @{
        Enabled           = $true
        To                = @('test@contoso.com')
        From              = 'dcagent@contoso.com'
        SmtpServer        = 'smtp.contoso.com'
        Port              = 587
        UseSsl            = $true
        CredentialUser    = ''
        CredentialPassword = ''
        MinSeverity       = 'High'
        SendOnNoFindings  = $false
    }

    $script:SampleAnomalies = @(
        [pscustomobject]@{
            Type='FailedLogonBurst_Account'; Account='jsmith'; ComputerName='dc01'
            TimeCreated=(Get-Date); Detail='10 failures in 1 hour'; Severity='High'
        }
    )

    $script:SampleSummary = [pscustomobject]@{
        ScorePct=75; Passed=3; Failed=1; TotalControls=4
        ByDC=@(); GapsBySeverity=@([pscustomobject]@{Severity='High';GapCount=1})
    }

    $script:SampleGaps = @(
        [pscustomobject]@{
            ControlId='PP-001'; Title='Min password length'; Severity='High'
            ComputerName='dc01'; Actual='8'; Expected='>= 14'
            Remediation='Set via GPO.'; Frameworks=@{CIS='CIS-L1 1.1.1'}
        }
    )

    $script:SampleZeroDays = @(
        [pscustomobject]@{
            CveId='CVE-2024-00001'; VendorProject='Microsoft'; Product='Windows Server'
            VulnerabilityName='Fake RCE'; DateAdded=(Get-Date -Format 'yyyy-MM-dd')
            DueDate=(Get-Date).AddDays(5).ToString('yyyy-MM-dd')
            RequiredAction='Patch immediately.'; KnownRansomwareCampaignUse='Known'; Source='CISA-KEV'
        }
    )
}

Describe 'Send-EmailAlert' {
    It 'calls Send-MailMessage when Enabled and anomalies present' {
        Mock Send-MailMessage {}
        Send-EmailAlert -EmailConfig $script:EmailConfig -Anomalies $script:SampleAnomalies
        Should -Invoke Send-MailMessage -Times 1 -Exactly
    }

    It 'does not call Send-MailMessage when Enabled = false' {
        Mock Send-MailMessage {}
        $cfg = $script:EmailConfig.Clone(); $cfg.Enabled = $false
        Send-EmailAlert -EmailConfig $cfg -Anomalies $script:SampleAnomalies
        Should -Invoke Send-MailMessage -Times 0
    }

    It 'does not throw when Send-MailMessage fails' {
        Mock Send-MailMessage { throw 'SMTP error' }
        { Send-EmailAlert -EmailConfig $script:EmailConfig -Anomalies $script:SampleAnomalies } |
            Should -Not -Throw
    }

    It 'does not send when anomalies are empty and SendOnNoFindings is false' {
        Mock Send-MailMessage {}
        Send-EmailAlert -EmailConfig $script:EmailConfig -Anomalies @()
        Should -Invoke Send-MailMessage -Times 0
    }

    It 'sends when anomalies are empty and SendOnNoFindings is true' {
        Mock Send-MailMessage {}
        $cfg = $script:EmailConfig.Clone(); $cfg.SendOnNoFindings = $true
        Send-EmailAlert -EmailConfig $cfg -Anomalies @()
        Should -Invoke Send-MailMessage -Times 1 -Exactly
    }
}

Describe 'Send-EmailComplianceReport' {
    It 'calls Send-MailMessage with compliance data' {
        Mock Send-MailMessage {}
        Send-EmailComplianceReport -EmailConfig $script:EmailConfig `
            -Summary $script:SampleSummary -Gaps $script:SampleGaps
        Should -Invoke Send-MailMessage -Times 1 -Exactly
    }

    It 'does not throw when SMTP fails' {
        Mock Send-MailMessage { throw 'connection refused' }
        { Send-EmailComplianceReport -EmailConfig $script:EmailConfig `
            -Summary $script:SampleSummary -Gaps $script:SampleGaps } |
            Should -Not -Throw
    }
}

Describe 'Send-TeamsZeroDayAlert' {
    It 'calls Invoke-RestMethod with zero-day card' {
        Mock Invoke-RestMethod {}
        Send-TeamsZeroDayAlert -WebhookUrl 'https://fake.webhook/' -ZeroDays $script:SampleZeroDays
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'does not call Invoke-RestMethod for empty zero-day list' {
        Mock Invoke-RestMethod {}
        Send-TeamsZeroDayAlert -WebhookUrl 'https://fake.webhook/' -ZeroDays @()
        Should -Invoke Invoke-RestMethod -Times 0
    }

    It 'does not throw when webhook fails' {
        Mock Invoke-RestMethod { throw 'timeout' }
        { Send-TeamsZeroDayAlert -WebhookUrl 'https://fake.webhook/' -ZeroDays $script:SampleZeroDays } |
            Should -Not -Throw
    }
}

Describe 'Send-EmailZeroDayAlert' {
    It 'calls Send-MailMessage with CVE data' {
        Mock Send-MailMessage {}
        Send-EmailZeroDayAlert -EmailConfig $script:EmailConfig -ZeroDays $script:SampleZeroDays
        Should -Invoke Send-MailMessage -Times 1 -Exactly
    }

    It 'does not throw when SMTP fails' {
        Mock Send-MailMessage { throw 'auth failure' }
        { Send-EmailZeroDayAlert -EmailConfig $script:EmailConfig -ZeroDays $script:SampleZeroDays } |
            Should -Not -Throw
    }
}

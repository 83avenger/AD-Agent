@{
    # Vendor/product strings to match against CISA KEV vendorProject and product fields.
    # Add any software your environment runs (case-insensitive substring match).
    Products = @(
        'Microsoft Windows'
        'Microsoft Active Directory'
        'Windows Server'
        'Microsoft Exchange'
        'Microsoft Office'
        'Microsoft Outlook'
        'Microsoft SharePoint'
        'Kerberos'
        'LDAP'
        'Remote Desktop'
        'SMB'
        'IIS'
        'Microsoft DNS'
        'Microsoft NTLM'
    )

    # Free NVD API key (optional - raises rate limit from 5 to 50 req/30 s).
    # Request at: https://nvd.nist.gov/developers/request-an-api-key
    NvdApiKey = ''

    # Only surface KEV entries added within this many days (0 = all-time).
    MaxAgeDays = 30
}

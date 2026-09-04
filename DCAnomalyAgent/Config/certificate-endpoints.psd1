@{
    # -------------------------------------------------------------------------
    # TLS endpoints to probe for certificate expiry, beyond the ones the scanner
    # auto-derives (LDAPS 636 on every DC, HTTPS 443 on every WebApplication host).
    #
    # Use this for load balancers, appliances, non-Windows services, and any
    # host:port whose certificate you want tracked but that the machine-store /
    # asset inventory doesn't already cover.
    #
    # Each entry: Host (FQDN or IP), Port, and an optional friendly Name.
    # The probe reads the presented server certificate only - it does not
    # validate the trust chain, so self-signed and already-expired certs are
    # still reported.
    # -------------------------------------------------------------------------
    # Empty by default. This list used to ship with contoso.com examples in it, which
    # every certificate scan then dutifully tried to reach - producing five guaranteed
    # collection failures on a fresh install and burying whatever real certificates were
    # found. Uncomment and edit the shapes below for your own endpoints.
    Endpoints = @(
        # @{ Host = 'portal.example.local'; Port = 443;  Name = 'Public portal (behind LB)' }
        # @{ Host = 'mail.example.local';   Port = 443;  Name = 'OWA' }
        # @{ Host = 'mail.example.local';   Port = 587;  Name = 'SMTP submission (STARTTLS)' }
        # @{ Host = 'vpn.example.local';    Port = 443;  Name = 'VPN appliance' }
        # @{ Host = 'rdgw.example.local';   Port = 3389; Name = 'RD Gateway' }
    )
}

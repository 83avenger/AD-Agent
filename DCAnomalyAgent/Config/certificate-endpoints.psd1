@{
    # ─────────────────────────────────────────────────────────────────────────
    # TLS endpoints to probe for certificate expiry, beyond the ones the scanner
    # auto-derives (LDAPS 636 on every DC, HTTPS 443 on every WebApplication host).
    #
    # Use this for load balancers, appliances, non-Windows services, and any
    # host:port whose certificate you want tracked but that the machine-store /
    # asset inventory doesn't already cover.
    #
    # Each entry: Host (FQDN or IP), Port, and an optional friendly Name.
    # The probe reads the presented server certificate only — it does not
    # validate the trust chain, so self-signed and already-expired certs are
    # still reported.
    # ─────────────────────────────────────────────────────────────────────────
    Endpoints = @(
        @{ Host = 'portal.contoso.com';   Port = 443;  Name = 'Public portal (behind LB)' }
        @{ Host = 'mail.contoso.com';     Port = 443;  Name = 'OWA' }
        @{ Host = 'mail.contoso.com';     Port = 587;  Name = 'SMTP submission (STARTTLS)' }
        @{ Host = 'vpn.contoso.com';      Port = 443;  Name = 'VPN appliance' }
        @{ Host = 'rdgw.contoso.com';     Port = 3389; Name = 'RD Gateway' }
    )
}

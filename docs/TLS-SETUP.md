# TLS setup — secure the page with your CA, register devices over plain for now

AD-Agent runs two channels, and they can use different security levels:

- **The page** (browser UI) — secure it over **HTTPS with your internal CA certificate**, via
  the IIS reverse proxy. Analysts browse `https://<jump>` with no warning and (optionally)
  Windows Authentication.
- **Device registration** (collector check-ins) — leave on **plain HTTP** (`http://<jump>:5000`)
  for the initial rollout; move it to HTTPS later with a one-line change.

The Flask app itself only ever serves plain HTTP on `localhost:5000`; something in front
provides the TLS. This is why a loopback self-test uses `http://localhost:5000` — that
traffic never leaves the box.

There are two ways to put TLS in front. Pick one:

- **Python TLS proxy (no IIS)** — recommended on a locked-down / air-gapped server where
  IIS + ARR + URL Rewrite won't install cleanly. Nothing but the Python you already have.
  TLS only (no Windows Auth). See **Option A** below.
- **IIS reverse proxy** — adds TLS *and* Windows Authentication, but needs IIS + the ARR and
  URL Rewrite MSIs staged offline. See **Option B** below.

---

## Option A — Python TLS proxy (no IIS)

### A1. Get a CA certificate and export it as a PFX

```powershell
cd DCAnomalyAgent\Install
.\Request-WebUICertificate.ps1        # enrols a web-server cert from your CA; prints the thumbprint
# Export it (with its private key) to a PFX the proxy can load:
Export-PfxCertificate -Cert Cert:\LocalMachine\My\<thumbprint> `
    -FilePath C:\Apps\AD-Agent\webui.pfx -Password (Read-Host -AsSecureString)
```

(If you already have PEM `cert`/`key` files, you can use those instead and skip the PFX —
the proxy and registrar both accept `-CertPem`/`-KeyPem`, which need no extra package.)

### A2. Register the proxy as a service

```powershell
.\Register-TlsProxy.ps1 -GmsaAccount 'AMG\svc-discoverAgt$' `
    -PythonPath 'C:\Apps\Python312\python.exe' -Pfx 'C:\Apps\AD-Agent\webui.pfx'
Start-ScheduledTask -TaskName 'AD-Agent-TlsProxy'
```

It runs `WebApp\tls_proxy.py` under the gMSA at startup, listening on 443 and forwarding to
the Flask app on 127.0.0.1:5000, and opens the inbound 443 rule. The `--pfx` path needs the
`cryptography` package on the server (`pip install cryptography`); the `-CertPem/-KeyPem`
path is pure stdlib and needs nothing.

### A3. Browse and register devices

- Analysts: `https://<jump>` (CA-trusted, no warning).
- Devices: keep registering at `http://<jump>:5000` for now (see below).

Then skip to **Firewall** and **Later** sections.

---

## Option B — IIS reverse proxy (adds Windows Auth)

```powershell
cd DCAnomalyAgent\Install
.\Request-WebUICertificate.ps1                 # or -Template 'Your Web Server Template'
```

It enrols a web-server cert from your AD CS CA (FQDN + short name) and prints the thumbprint. If
auto-enrollment isn't available it writes a `certreq` request and the commands to submit it.

### 2. Secure the page (IIS on 443, your CA cert) — keep 5000 open

```powershell
.\Register-IISReverseProxy.ps1 -CertThumbprint <thumb> -AllowedGroup 'DOMAIN\AD-Agent-Analysts'
```

**Do not** pass `-LockWebUIToLocalhost` yet — leaving it off is the "both" mode: IIS serves the
UI on 443/HTTPS while the app stays reachable on TCP 5000 for plain collector check-ins.

### 3. Register devices over plain (for now)

Point the collector at the plain URL:

```powershell
.\New-PushCollectorGPO.ps1 -ServerUrl 'http://<jump>:5000' -Token '<COLLECTOR_TOKEN>' `
    -TargetOU 'OU=Laptops,...' -TightenAcl
```

### 4. Firewall (important while 5000 is plain)

In "both" mode the UI is *also* reachable unauthenticated on 5000. Scope it:

| Rule | Source | Destination | Port |
|---|---|---|---|
| Analysts reach the UI | Analyst subnets | Jump server | TCP/443 |
| Devices register | Endpoint VLANs only | Jump server | TCP/5000 |

Restricting 5000 to the endpoint VLANs keeps the unauthenticated plain port off general-purpose
networks while devices still check in.

## Later: move registration to HTTPS and close 5000

1. Re-run the GPO helper with the HTTPS URL:
   `New-PushCollectorGPO.ps1 -ServerUrl 'https://<jump>' -Token '<token>' -TargetOU ...`
   (the IIS proxy already forwards `/api/collector/checkin` to the app).
2. Once all devices have switched, re-run the proxy with `-LockWebUIToLocalhost` (and
   `-PythonPath`) to rebind the app to 127.0.0.1 and close TCP 5000 entirely.
3. Remove the endpoint-VLAN → 5000 firewall rule; keep only 443.

At that point both the page and device registration are HTTPS, and nothing is reachable in the
clear.

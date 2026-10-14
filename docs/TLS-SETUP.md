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

Run every step on the **jump server**, in an **elevated** PowerShell, **one command per line**.

### A0. Make sure the proxy file is on the server

```powershell
Test-Path C:\Apps\AD-Agent\WebApp\tls_proxy.py
```

`False` → update the server first (`git pull` + `Update-Deployment.ps1`, see
`docs/ENDPOINT-ROLLOUT-STEP-BY-STEP.md` step 1.1).

### A1. Get a CA certificate and export it as a PFX

Two separate commands - don't put them on one line.

```powershell
cd C:\Apps\AD-Agent\DCAnomalyAgent\Install
```
```powershell
.\Request-WebUICertificate.ps1
```

It prints the certificate thumbprint. Then export it with its private key (it asks for a
password - remember it for A2):

```powershell
Export-PfxCertificate -Cert Cert:\LocalMachine\My\<thumbprint> -FilePath C:\Apps\AD-Agent\webui.pfx -Password (Read-Host -AsSecureString) -ChainOption BuildChain
```

`-ChainOption BuildChain` puts the issuing/intermediate CA in the PFX too - devices need
the server to send it (see A2).

### A2. Convert to PEM with OpenSSL (cert **with chain** + key)

The path has a space in it, so keep it in a variable and call it with `&`:

```powershell
$ossl = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
```

Server certificate, then the CA chain, then join them **leaf first**:

```powershell
& $ossl pkcs12 -in C:\Apps\AD-Agent\webui.pfx -clcerts -nokeys -out C:\Apps\AD-Agent\leaf.pem
```
```powershell
& $ossl pkcs12 -in C:\Apps\AD-Agent\webui.pfx -cacerts -nokeys -out C:\Apps\AD-Agent\chain.pem
```
```powershell
Get-Content C:\Apps\AD-Agent\leaf.pem, C:\Apps\AD-Agent\chain.pem | Set-Content C:\Apps\AD-Agent\cert.pem -Encoding ascii
```

Private key (unencrypted, which the proxy needs):

```powershell
& $ossl pkcs12 -in C:\Apps\AD-Agent\webui.pfx -nocerts -nodes -out C:\Apps\AD-Agent\key.pem
```

If any of these fails with "unsupported" / "RC2-40-CBC", add `-legacy` and rerun.

If `chain.pem` comes out empty (the PFX had no CA certs), export the issuing CA from the
store instead and use that as `chain.pem`:

```powershell
Get-ChildItem Cert:\LocalMachine\CA, Cert:\LocalMachine\Root | Where-Object Subject -eq (Get-Item Cert:\LocalMachine\My\<thumbprint>).Issuer | Select-Object -First 1 | ForEach-Object { "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----" } | Set-Content C:\Apps\AD-Agent\chain.pem -Encoding ascii
```

Check the key matches the certificate (the two hashes must be identical):

```powershell
& $ossl x509 -noout -modulus -in C:\Apps\AD-Agent\cert.pem | & $ossl md5
```
```powershell
& $ossl rsa -noout -modulus -in C:\Apps\AD-Agent\key.pem | & $ossl md5
```

Note the **names on the certificate** - devices must use one of them in their URL:

```powershell
& $ossl x509 -noout -subject -ext subjectAltName -in C:\Apps\AD-Agent\cert.pem
```

Lock the key down to SYSTEM, Administrators and the gMSA:

```powershell
icacls C:\Apps\AD-Agent\key.pem /inheritance:r /grant:r "SYSTEM:R" "BUILTIN\Administrators:F" 'DOMAIN\svc-discoverAgt$:R'
```

(No OpenSSL? Install the `cryptography` package offline - `pip download cryptography
--only-binary=:all: -d wheels` on a connected machine with the same Python, copy the folder,
then `python -m pip install --no-index --find-links <folder> cryptography` - and register with
`-Pfx` instead of `-CertPem/-KeyPem` in A3. The PowerShell 7 `ExportCertificatePem()` methods
do **not** exist in Windows PowerShell 5.1.)

### A3. Free port 443 if IIS has it

If IIS is installed it usually holds 443, and the proxy can't bind. Check:

```powershell
Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Get-Process -Id $_.OwningProcess } | Select-Object Id, ProcessName
```

`System` (PID 4) = IIS/http.sys. Stop and disable IIS (reversible):

```powershell
iisreset /stop
```
```powershell
Set-Service W3SVC -StartupType Disabled; Set-Service WAS -StartupType Disabled
```

### A4. Register and start the proxy

```powershell
.\Register-TlsProxy.ps1 -GmsaAccount 'DOMAIN\svc-discoverAgt$' -PythonPath 'C:\Apps\Python312\python.exe' -CertPem 'C:\Apps\AD-Agent\cert.pem' -KeyPem 'C:\Apps\AD-Agent\key.pem'
```
```powershell
Start-ScheduledTask -TaskName 'AD-Agent-TlsProxy'
```

It runs `WebApp\tls_proxy.py` under the gMSA at startup (443 → 127.0.0.1:5000) and opens the
inbound 443 rule. After changing `cert.pem`/`key.pem` later, just restart it:

```powershell
Stop-ScheduledTask -TaskName 'AD-Agent-TlsProxy'; Start-ScheduledTask -TaskName 'AD-Agent-TlsProxy'
```

### A5. Verify

On the server - the full chain must be served (look for **two or more** `s:`/`i:` pairs):

```powershell
"Q" | & $ossl s_client -connect localhost:443 -showcerts 2>$null | Select-String '^ *\d+ s:|^ *i:'
```

From a laptop (as admin, Windows PowerShell 5.1):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
```
```powershell
Invoke-RestMethod https://<FQDN-on-cert>/healthz
```

Returns JSON with no error = the laptop trusts the certificate. Analysts browse
`https://<FQDN-on-cert>`.

### A6. Point devices at HTTPS

Devices must use **`https://<FQDN-on-cert>`** - not the IP and not a name missing from the
certificate. Rebuild/redeploy the collector with that URL (Intune: `Build-IntunePackage.ps1
-ServerUrl 'https://<FQDN-on-cert>' ...` and re-upload; GPO: re-run `New-PushCollectorGPO.ps1`;
single host: re-run `Install-PushCollector.ps1`). The installers warn if you pass an IP.

### Troubleshooting Option A

| Symptom | Fix |
|---|---|
| `C:\Program : The term ... is not recognized` | Path with a space: use `$ossl = '...openssl.exe'` and `& $ossl ...` (A2) |
| `The specified network password is not correct` | Wrong / unset PFX password - enter the one used in A1 |
| `does not contain a method named 'ExportCertificatePem'` | That's PowerShell 7 only - use the OpenSSL steps (A2) |
| Proxy task runs but nothing listens on 443 | IIS holds 443 (A3), or run the proxy in the foreground to see the error: `C:\Apps\Python312\python.exe C:\Apps\AD-Agent\WebApp\tls_proxy.py --cert C:\Apps\AD-Agent\cert.pem --key C:\Apps\AD-Agent\key.pem` |
| Laptop `collector.log`: `Could not establish trust relationship for the SSL/TLS secure channel` | The next line, `TLS diagnosis: ...`, names the cause: **URL host not on the certificate** → use the FQDN on the cert (A6); **chain stops at the server certificate** → rebuild `cert.pem` with the chain (A2) and restart the proxy; **device doesn't have the root CA** → deploy the root to Trusted Root Certification Authorities (GPO, or an Intune *Trusted certificate* profile) |
| Browser warns about the name | Browse with a name listed by the `subjectAltName` check in A2 |

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

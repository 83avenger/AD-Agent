# AD-Agent secure build, signing & licensing

AD-Agent ships like a commercial product: the **developer holds the keys** and produces a
signed, encrypted release; the customer installs it with one setup; the product is **locked**
(only a developer-signed, optionally node-bound license runs it) and **tamper-evident**
(Authenticode + a signed integrity catalog). Secrets are **encrypted at rest** (DPAPI).

Enforcement is **non-destructive and default-off**: until you issue keys and turn it on,
nothing changes. When on, an unlicensed/expired/altered/wrong-host copy refuses to run *new*
scans and shows a banner, but keeps serving existing data and never deletes anything — a
security tool must fail safe.

> On a CrowdStrike estate we deliberately **do not** obfuscate source or ship packed exes
> (they trip EDR and break AllSigned). Protection = signing + integrity catalog + DPAPI +
> license, which are auditable and EDR-friendly.

## One-time, on the build machine

```powershell
cd Build
# 1. Developer keys: a code-signing cert (or reuse a CA-issued one) + a license keypair.
.\New-ProductKeys.ps1                 # or -CodeSignThumbprint <CA cert thumbprint>
# 2. Embed the license PUBLIC key into the product before building:
Copy-Item .\keys\license_pubkey.pem ..\WebApp\license_pubkey.pem
Copy-Item .\keys\license_pubkey.pem ..\DCAnomalyAgent\Config\license_pubkey.pem
# 3. Trust the code-signing cert estate-wide (GPO): push keys\codesign-public.cer to
#    Trusted Publishers (and Trusted Root if self-signed) so AllSigned accepts it.
```

Private keys never leave the build machine. The license private key is stored
DPAPI-protected to you; **back it up securely** — losing it means re-keying (re-issuing
licenses), not losing data.

## Each release

```powershell
cd Build
.\New-SecureRelease.ps1 -Version 1.0.0 `
    -CodeSignThumbprint (Get-Content .\keys\codesign-thumbprint.txt) `
    -Passphrase 'a strong build passphrase'
# -> dist\AD-Agent-1.0.0.secure  (+ release-info.json inside)
```

This signs every `.ps1/.psm1`, builds and signs `AD-Agent.cat`, writes a SHA-256 manifest,
then AES-256-encrypts the zip (PBKDF2 from the passphrase; salt+IV in the header).

## Per customer / deployment: issue a license

```powershell
# Node-lock to the target host (recommended). Get its id on that server:
#   (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
.\New-License.ps1 -Owner 'Acme SOC' -MachineId '<target MachineGuid>' `
    -ExpiresUtc '2027-12-31'      # omit for perpetual
# -> out\license.key
```

## On the target server: one setup

```powershell
cd DCAnomalyAgent\Install
.\Install-ADAgent.ps1 -Package .\AD-Agent-1.0.0.secure -Passphrase '<build passphrase>' `
    -License .\license.key -GmsaAccount 'AMG\svc-discoverAgt$' `
    -PythonPath 'C:\Apps\Python312\python.exe' -WheelsDir .\wheels -SetAllSigned
# Then enable enforcement for the web UI too:
[Environment]::SetEnvironmentVariable('ADAGENT_LICENSE_ENFORCE','1','Machine')
```

The installer decrypts, **verifies the catalog + signer + manifest + license for this host**,
installs to `C:\Program Files\AD-Agent` with hardened ACLs (gMSA read/execute; write only on
`State\`/`Config\`), preserves existing data/config, installs deps offline, and registers the
tasks + firewall. Any verification failure aborts the install.

## What "locked" means in practice
- **AllSigned** + the signed catalog → only your-signed scripts run; edits are rejected and
  surfaced by the watchdog's `Test-FileCatalog` check.
- **License** → only a license you signed runs new work; node-locking stops a copied install
  from running on another host.
- **Encrypted artifact** → the shipped `.secure` is useless without the build passphrase.
- **DPAPI secrets** → API keys/tokens are ciphertext on disk, bound to the machine.

None of this can lock the owner out of their own data: results live in `State\` and the
source in git; the controls protect the artifact, secrets, and integrity — they are not a
kill-switch.

## Rotation
- **Code-signing cert**: re-issue, re-push the public cert via GPO, rebuild. Old releases
  keep validating against the old cert until replaced.
- **License key**: `New-ProductKeys.ps1` makes a new keypair; re-embed the public key,
  rebuild, re-issue licenses. Do this if the private key is ever exposed.

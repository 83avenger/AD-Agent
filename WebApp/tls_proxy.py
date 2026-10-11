"""Tiny TLS-terminating reverse proxy for the AD-Agent web UI.

Why this exists: on a locked-down / air-gapped server, installing IIS + ARR + URL Rewrite
to put HTTPS in front of the app is heavy (missing feature source, two MSI downloads). This
does the one job that matters for "secure the page with our CA" - terminate TLS - with
nothing but the Python already installed:

    browser --HTTPS/443--> tls_proxy.py --plain HTTP--> 127.0.0.1:5000 (waitress app)

It is a transparent byte relay, not an HTTP parser: it accepts a TLS connection, opens a
plain socket to the backend, and shuttles bytes both ways. That keeps it simple and correct
for any HTTP/1.1 traffic the app serves (keep-alive, chunked, file downloads) without
re-implementing a proxy.

What it does NOT do: authentication. IIS added Windows Auth; this adds only TLS. Keep the
app's plain port (5000) restricted at the network firewall, and layer auth on later if needed.

Certificate input, either:
  --cert cert.pem --key key.pem         (stdlib only, no extra packages)
  --pfx webui.pfx [--pfx-pass ...]      (needs the 'cryptography' package; converts in-memory)

Export a PFX from the Windows store with the built-in cmdlet:
  Export-PfxCertificate -Cert Cert:\LocalMachine\My\<thumbprint> -FilePath webui.pfx `
      -Password (Read-Host -AsSecureString)
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import tempfile
import threading


def _context_from_pfx(pfx_path: str, pfx_pass: str | None) -> ssl.SSLContext:
    """Load a PKCS#12/PFX (cert + key, optional chain) and build an SSLContext from it.

    stdlib ssl can't read PFX, so this uses 'cryptography' to convert to PEM in memory,
    writes the PEM to short-lived 0600 temp files only long enough for load_cert_chain to
    read them, then deletes them."""
    try:
        from cryptography.hazmat.primitives.serialization import (
            BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat, pkcs12,
        )
    except ImportError:
        sys.exit("--pfx needs the 'cryptography' package. Install it (pip install cryptography) "
                 "or export PEM files and use --cert/--key instead.")
    data = open(pfx_path, "rb").read()
    pw = pfx_pass.encode() if pfx_pass else None
    key_obj, cert_obj, extra = pkcs12.load_key_and_certificates(data, pw)
    if not key_obj or not cert_obj:
        sys.exit("Could not load a key + certificate from the PFX (wrong password, or no private key).")

    tmp = tempfile.mkdtemp()
    cert_pem = os.path.join(tmp, "c.pem")
    key_pem = os.path.join(tmp, "k.pem")
    try:
        with open(cert_pem, "wb") as fh:
            fh.write(cert_obj.public_bytes(Encoding.PEM))
            for c in (extra or []):
                fh.write(c.public_bytes(Encoding.PEM))
        # Write the key with no passphrase (file is 0600 and deleted immediately after load).
        fd = os.open(key_pem, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key_obj.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_pem, key_pem)
        return ctx
    finally:
        for p in (cert_pem, key_pem):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(tmp)
        except OSError:
            pass


def build_context(args) -> ssl.SSLContext:
    if args.pfx:
        return _context_from_pfx(args.pfx, args.pfx_pass)
    if not (args.cert and args.key):
        sys.exit("Provide either --pfx, or both --cert and --key.")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    return ctx


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(chunk)
    except OSError:
        pass
    finally:
        # Half-close so the other direction can still drain, mirroring a normal connection end.
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(tls_conn: socket.socket, backend: tuple[str, int]) -> None:
    back = None
    try:
        back = socket.create_connection(backend, timeout=10)
    except OSError:
        try:
            tls_conn.close()
        except OSError:
            pass
        return
    t1 = threading.Thread(target=_pipe, args=(tls_conn, back), daemon=True)
    t2 = threading.Thread(target=_pipe, args=(back, tls_conn), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    for s in (tls_conn, back):
        try:
            s.close()
        except OSError:
            pass


def main() -> None:
    p = argparse.ArgumentParser(description="TLS reverse proxy for the AD-Agent web UI.")
    p.add_argument("--listen-host", default=os.environ.get("TLS_LISTEN_HOST", "0.0.0.0"))
    p.add_argument("--listen-port", type=int, default=int(os.environ.get("TLS_LISTEN_PORT", "443")))
    p.add_argument("--backend-host", default=os.environ.get("TLS_BACKEND_HOST", "127.0.0.1"))
    p.add_argument("--backend-port", type=int, default=int(os.environ.get("TLS_BACKEND_PORT", "5000")))
    p.add_argument("--cert", default=os.environ.get("TLS_CERT"))
    p.add_argument("--key", default=os.environ.get("TLS_KEY"))
    p.add_argument("--pfx", default=os.environ.get("TLS_PFX"))
    p.add_argument("--pfx-pass", default=os.environ.get("TLS_PFX_PASS"))
    args = p.parse_args()

    ctx = build_context(args)
    backend = (args.backend_host, args.backend_port)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(128)
    print(f"AD-Agent TLS proxy: https://{args.listen_host}:{args.listen_port} -> "
          f"http://{backend[0]}:{backend[1]}", flush=True)

    while True:
        try:
            raw, _addr = listener.accept()
        except OSError:
            continue
        try:
            tls_conn = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            # Bad handshake (scanner, plain-HTTP to the TLS port, etc.) - drop and keep serving.
            try:
                raw.close()
            except OSError:
                pass
            continue
        threading.Thread(target=_handle, args=(tls_conn, backend), daemon=True).start()


if __name__ == "__main__":
    main()

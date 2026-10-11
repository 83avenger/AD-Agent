"""Encrypted-at-rest storage for AD-Agent's integration secrets.

The vendor/API keys the Integrations page saves can be stored encrypted with Windows DPAPI
at **machine scope**, so no plaintext API keys sit on disk and the ciphertext is useless if
copied off the box. Encryption is **opt-in** (ADAGENT_ENCRYPT_SECRETS=1, which the secure
installer sets): the plain deployment keeps writing plaintext `integration-secrets.json`
exactly as before, so the two deployment methods stay cleanly separate. Reads always accept
either form, so switching is transparent.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
from ctypes import wintypes
from pathlib import Path

_IS_WINDOWS = sys.platform.startswith("win")
# CryptProtectData flag: key the blob to the machine, not the calling user, so the gMSA
# that writes it and an admin who reads it (different identities) both can.
_CRYPTPROTECT_LOCAL_MACHINE = 0x04


def is_encrypted() -> bool:
    """True when at-rest encryption is both available (Windows) and enabled. Encryption is
    opt-in via ADAGENT_ENCRYPT_SECRETS=1 (the secure installer sets it), so the plain
    deployment keeps writing plaintext exactly as before."""
    return _IS_WINDOWS and os.environ.get("ADAGENT_ENCRYPT_SECRETS", "0") == "1"


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> "_DATA_BLOB":
    buf = ctypes.create_string_buffer(data, len(data))
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: "_DATA_BLOB") -> bytes:
    out = ctypes.string_at(blob.pbData, blob.cbData)
    # The CryptoAPI allocated this with LocalAlloc; free it to avoid a leak.
    ctypes.windll.kernel32.LocalFree(blob.pbData)
    return out


def _dpapi_protect(plaintext: bytes) -> bytes:
    inb, outb = _blob(plaintext), _DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(inb), None, None, None, None, _CRYPTPROTECT_LOCAL_MACHINE, ctypes.byref(outb)
    ):
        raise OSError("CryptProtectData failed (DPAPI machine-scope encrypt).")
    return _blob_bytes(outb)


def _dpapi_unprotect(ciphertext: bytes) -> bytes:
    inb, outb = _blob(ciphertext), _DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(inb), None, None, None, None, _CRYPTPROTECT_LOCAL_MACHINE, ctypes.byref(outb)
    ):
        raise OSError("CryptUnprotectData failed (DPAPI decrypt) - blob from another machine?")
    return _blob_bytes(outb)


def _enc_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".enc")


def read_secrets(path: Path) -> dict:
    """Load the secrets dict. Prefers the encrypted `<path>.enc`, falls back to a legacy
    plaintext `<path>`, and returns {} if neither exists or anything goes wrong (a secrets
    read must never crash the page that needs it)."""
    enc = _enc_path(path)
    try:
        if enc.exists():
            raw = enc.read_bytes()
            data = _dpapi_unprotect(raw) if _IS_WINDOWS else raw
            return json.loads(data.decode("utf-8"))
    except Exception:
        pass
    try:
        if path.exists():
            with open(path, encoding="utf-8-sig") as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}


def write_secrets(path: Path, data: dict) -> None:
    """Persist the secrets dict. Encrypted when enabled (is_encrypted()), otherwise plaintext
    exactly as the old deployment wrote it. Either way, remove the other representation so the
    file just written is authoritative and no stale copy is read back."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2).encode("utf-8")
    enc = _enc_path(path)
    if is_encrypted():
        tmp = enc.with_suffix(enc.suffix + ".tmp")
        tmp.write_bytes(_dpapi_protect(payload))
        os.replace(tmp, enc)
        # Migrate away from any plaintext copy.
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass
    else:
        # Plain deployment (default) - plaintext, same path/format as before.
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload.decode("utf-8"))
        # Drop a stale encrypted copy so the plaintext is what gets read next time.
        try:
            if enc.exists():
                enc.unlink()
        except OSError:
            pass

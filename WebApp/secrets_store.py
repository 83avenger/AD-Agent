"""Encrypted-at-rest storage for AD-Agent's integration secrets.

The vendor/API keys the Integrations page saves used to live in plaintext
(Config/integration-secrets.json). This module keeps the same JSON shape but stores it
encrypted with Windows DPAPI at **machine scope**, so:

  * no plaintext API keys sit on disk, and
  * any account on that one machine (the web UI's gMSA and an admin alike) can read it,
    while the ciphertext is useless if the file is copied off the box.

DPAPI is called through stdlib ctypes - no pywin32 dependency. On a non-Windows host
(developer laptop / CI) there is no DPAPI, so the store transparently falls back to
plaintext and says so via `is_encrypted()`; production is Windows, where encryption is
always used. Reads accept a legacy plaintext file and the next write migrates it to the
encrypted form, deleting the plaintext.
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
    """True when real at-rest encryption is available (i.e. on Windows)."""
    return _IS_WINDOWS


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
    """Persist the secrets dict encrypted (Windows) or plaintext (dev). After a successful
    encrypted write, remove any legacy plaintext file so secrets don't linger in the clear."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2).encode("utf-8")
    if _IS_WINDOWS:
        enc = _enc_path(path)
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
        # Developer/CI fallback - no DPAPI available. Plaintext, same path as before.
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payload.decode("utf-8"))

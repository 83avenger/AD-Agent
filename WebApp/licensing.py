"""License verification for AD-Agent.

AD-Agent ships as a signed, licensed product: the developer holds an RSA private key and
issues a `license.key` (signed JSON); the product embeds only the matching **public** key
and verifies the license at runtime. A valid license is signature-correct, unexpired, and -
when node-locked - bound to this machine, so a copied build will not run elsewhere without
the developer issuing a new license.

Enforcement is deliberately **non-destructive and default-off**:

  * Off unless ADAGENT_LICENSE_ENFORCE=1 AND a real public key is embedded. This means
    pulling the code into an existing deployment changes nothing until the developer turns
    it on - it never silently blocks a running estate.
  * When on and the license is missing/invalid/expired/wrong-machine, the app blocks only
    *new* scan/discovery/pentest submissions and shows a licensing banner; it keeps serving
    existing data and /healthz, never deletes anything, never disables itself. A licensed
    security tool must fail safe, not blind the estate.

Signature scheme: RSA-2048+ PKCS#1 v1.5 over SHA-256 of the canonical JSON of the payload -
verifiable by Python `cryptography` and issuable by .NET RSA (PowerShell build side).
"""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

_APP_ROOT = Path(__file__).parent
PUBLIC_KEY_PATH = _APP_ROOT / "license_pubkey.pem"
LICENSE_PATH = _APP_ROOT.parent / "DCAnomalyAgent" / "Config" / "license.key"


def enforced() -> bool:
    """Enforcement is active only when explicitly enabled AND a usable public key is present.
    Either missing → unenforced, so the product runs unlocked (safe default)."""
    if os.environ.get("ADAGENT_LICENSE_ENFORCE", "0") != "1":
        return False
    try:
        return PUBLIC_KEY_PATH.exists() and PUBLIC_KEY_PATH.stat().st_size > 0
    except OSError:
        return False


def _machine_id() -> str:
    """Stable per-machine id for node-locking. Windows MachineGuid; hostname elsewhere (dev)."""
    if sys.platform.startswith("win"):
        try:
            import winreg  # noqa: PLC0415 - Windows-only, imported lazily
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return str(winreg.QueryValueEx(k, "MachineGuid")[0]).lower()
        except OSError:
            pass
    import socket
    return socket.gethostname().lower()


def _canonical(payload: dict) -> bytes:
    """Byte form the signature is computed over - must match the issuer (sorted keys,
    compact separators, UTF-8)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _verify_signature(payload: dict, signature_b64: str) -> bool:
    try:
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        # No crypto lib: cannot verify. Caller treats this as invalid when enforcing.
        return False
    try:
        pub = serialization.load_pem_public_key(PUBLIC_KEY_PATH.read_bytes())
        pub.verify(base64.b64decode(signature_b64), _canonical(payload),
                   padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def license_status() -> dict:
    """Return {'state','ok','reason','owner','expires'} describing the current license.

    state: 'unenforced' | 'valid' | 'invalid'. `ok` is True when the product may run new
    work (always True while unenforced)."""
    if not enforced():
        return {"state": "unenforced", "ok": True, "reason": "License enforcement is off.",
                "owner": None, "expires": None}

    if not LICENSE_PATH.exists():
        return {"state": "invalid", "ok": False, "reason": "No license file installed.",
                "owner": None, "expires": None}
    try:
        doc = json.loads(LICENSE_PATH.read_text(encoding="utf-8-sig"))
        payload, sig = doc["payload"], doc["signature"]
    except Exception:
        return {"state": "invalid", "ok": False, "reason": "License file is unreadable.",
                "owner": None, "expires": None}

    owner = payload.get("owner")
    expires = payload.get("expires")

    if not _verify_signature(payload, sig):
        return {"state": "invalid", "ok": False, "reason": "License signature is not valid.",
                "owner": owner, "expires": expires}
    if payload.get("product") != "AD-Agent":
        return {"state": "invalid", "ok": False, "reason": "License is not for this product.",
                "owner": owner, "expires": expires}
    if expires:
        try:
            exp = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return {"state": "invalid", "ok": False, "reason": f"License expired on {expires}.",
                        "owner": owner, "expires": expires}
        except ValueError:
            return {"state": "invalid", "ok": False, "reason": "License expiry is malformed.",
                    "owner": owner, "expires": expires}
    bound = payload.get("machine")
    if bound and str(bound).lower() != _machine_id():
        return {"state": "invalid", "ok": False,
                "reason": "License is bound to a different machine.",
                "owner": owner, "expires": expires}

    return {"state": "valid", "ok": True, "reason": "Licensed.", "owner": owner, "expires": expires}


def is_valid() -> bool:
    """True when new work is allowed (licensed, or enforcement off)."""
    return license_status()["ok"]

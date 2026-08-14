"""Asset inventory store - SQLite by default, PostgreSQL when configured.

SQLite (the original design) is fine up to a few thousand assets on a single
server, which is where this tool started. Past that - or once there's more
than one site/server wanting a shared view - a real client/server database
removes the single-writer-file constraint and lets multiple AD-Agent
instances (or read-only dashboards) hit the same store concurrently.

Set the ASSETS_DATABASE_URL environment variable to switch backends, e.g.:
    postgresql://ad_agent:secret@pgserver.contoso.com:5432/ad_agent

Leave it unset and nothing changes - SQLite at DCAnomalyAgent/State/assets.db,
exactly as before. Postgres additionally requires `pip install psycopg2-binary`
on this server; if ASSETS_DATABASE_URL is set but psycopg2 isn't installed,
this raises clearly at startup rather than silently falling back, since a
misconfigured production DB should fail loudly, not quietly disagree with
what the operator configured.
"""

import json
import os
from datetime import datetime
from pathlib import Path

BACKEND = "postgres" if os.environ.get("ASSETS_DATABASE_URL") else "sqlite"

if BACKEND == "postgres":
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError as exc:
        raise RuntimeError(
            "ASSETS_DATABASE_URL is set, but psycopg2 isn't installed. "
            "Run: pip install psycopg2-binary"
        ) from exc
else:
    import sqlite3


_SCHEMA_SQLITE = """
    CREATE TABLE IF NOT EXISTS assets (
        dedup_key       TEXT PRIMARY KEY,
        name            TEXT,
        ip              TEXT,
        asset_type      TEXT,
        os              TEXT,
        open_ports      TEXT,
        source          TEXT,
        last_seen       TEXT,
        collection_note TEXT,
        software_json   TEXT,
        first_seen      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )
"""

_SCHEMA_POSTGRES = """
    CREATE TABLE IF NOT EXISTS assets (
        dedup_key       TEXT PRIMARY KEY,
        name            TEXT,
        ip              TEXT,
        asset_type      TEXT,
        os              TEXT,
        open_ports      TEXT,
        source          TEXT,
        last_seen       TEXT,
        collection_note TEXT,
        software_json   TEXT,
        first_seen      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )
"""


def get_connection(state_dir: Path):
    """Opens a fresh connection per call - simplest way to be safe under
    waitress's threaded request handling without extra pooling/locking
    machinery at this scale. WAL mode (SQLite) / normal autocommit-off
    (Postgres) both let reads and writes overlap without blocking."""
    if BACKEND == "postgres":
        conn = psycopg2.connect(os.environ["ASSETS_DATABASE_URL"])
        with conn.cursor() as cur:
            cur.execute(_SCHEMA_POSTGRES)
        conn.commit()
        return conn

    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "assets.db"
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA_SQLITE)
    return conn


def dedup_key(asset: dict) -> str:
    """Stable identity for an asset: lowercased hostname when it's a real
    (resolved) name, falling back to IP for hosts DNS never resolved a name
    for. Matches the same short-name-first convention Run-Discovery.ps1's own
    consolidation already uses."""
    name = (asset.get("Name") or "").strip().lower()
    ip = (asset.get("IP") or "").strip().lower()
    if name and name != ip:
        return name.split(".")[0]
    return ip or name


def sync_assets(state_dir: Path, assets: list) -> None:
    """Upsert every asset from a JSON snapshot into the DB. Never deletes - a
    host missing from this particular snapshot (e.g. it wasn't in the
    subnet/zone just scanned) simply isn't touched, so it stays exactly as
    last known."""
    if not assets:
        return
    now = datetime.utcnow().isoformat()
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        for a in assets:
            key = dedup_key(a)
            if not key:
                continue
            software = a.get("Software")
            name = (a.get("Name") or "").strip().lower()
            ip = (a.get("IP") or "").strip().lower()
            row = (
                key, a.get("Name"), a.get("IP"), a.get("AssetType"), a.get("OS"),
                a.get("OpenPorts"), a.get("Source"), a.get("LastSeen"), a.get("CollectionNote"),
                json.dumps(software) if software else None, now, now,
            )
            if BACKEND == "postgres":
                # A host discovered first as a bare IP (no reverse DNS yet) that later
                # resolves a real hostname would otherwise keep two rows forever - one
                # keyed by the old IP, one by the new name. Retire the stale IP-keyed
                # row once a same-IP hostname record shows up.
                if name and name != ip and ip:
                    cur.execute("DELETE FROM assets WHERE dedup_key = %s AND dedup_key != %s", (ip, key))
                cur.execute("""
                    INSERT INTO assets (dedup_key, name, ip, asset_type, os, open_ports,
                        source, last_seen, collection_note, software_json, first_seen, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (dedup_key) DO UPDATE SET
                        name            = EXCLUDED.name,
                        ip              = EXCLUDED.ip,
                        asset_type      = EXCLUDED.asset_type,
                        os              = EXCLUDED.os,
                        open_ports      = EXCLUDED.open_ports,
                        source          = EXCLUDED.source,
                        last_seen       = COALESCE(EXCLUDED.last_seen, assets.last_seen),
                        collection_note = EXCLUDED.collection_note,
                        software_json   = COALESCE(EXCLUDED.software_json, assets.software_json),
                        updated_at      = EXCLUDED.updated_at
                """, row)
            else:
                if name and name != ip and ip:
                    cur.execute("DELETE FROM assets WHERE dedup_key = ? AND dedup_key != ?", (ip, key))
                cur.execute("""
                    INSERT INTO assets (dedup_key, name, ip, asset_type, os, open_ports,
                        source, last_seen, collection_note, software_json, first_seen, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(dedup_key) DO UPDATE SET
                        name            = excluded.name,
                        ip              = excluded.ip,
                        asset_type      = excluded.asset_type,
                        os              = excluded.os,
                        open_ports      = excluded.open_ports,
                        source          = excluded.source,
                        last_seen       = COALESCE(excluded.last_seen, assets.last_seen),
                        collection_note = excluded.collection_note,
                        software_json   = COALESCE(excluded.software_json, assets.software_json),
                        updated_at      = excluded.updated_at
                """, row)
        conn.commit()
    finally:
        conn.close()


def _row_to_asset(row) -> dict:
    get = row.__getitem__ if isinstance(row, (dict,)) else (lambda k: row[k])
    d = {
        "Name": get("name"), "IP": get("ip"), "AssetType": get("asset_type"),
        "OS": get("os"), "OpenPorts": get("open_ports"), "Source": get("source"),
        "LastSeen": get("last_seen"), "DedupKey": get("dedup_key"),
    }
    if get("collection_note"):
        d["CollectionNote"] = get("collection_note")
    if get("software_json"):
        try:
            d["Software"] = json.loads(get("software_json"))
        except (TypeError, ValueError):
            pass
    return d


def load_all_assets(state_dir: Path) -> list:
    conn = get_connection(state_dir)
    try:
        if BACKEND == "postgres":
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM assets ORDER BY asset_type, name")
            rows = cur.fetchall()
        else:
            rows = conn.execute("SELECT * FROM assets ORDER BY asset_type, name").fetchall()
        return [_row_to_asset(r) for r in rows]
    finally:
        conn.close()


def delete_asset(state_dir: Path, key: str) -> bool:
    """Manually remove one asset from the inventory (e.g. a decommissioned
    device or a stray duplicate). Returns True if a row was actually deleted."""
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        if BACKEND == "postgres":
            cur.execute("DELETE FROM assets WHERE dedup_key = %s", (key,))
        else:
            cur.execute("DELETE FROM assets WHERE dedup_key = ?", (key,))
        deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()


def check_health(state_dir: Path) -> None:
    """Raises if the store isn't reachable. Used by /healthz."""
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM assets")
        cur.fetchone()
    finally:
        conn.close()

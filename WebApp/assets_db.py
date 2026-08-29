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

# Columns added after the original schema shipped. CREATE TABLE IF NOT EXISTS does
# nothing to a table that already exists, so an assets.db already deployed on a jump
# server would keep the old shape forever without this - hence the ALTER TABLE
# migration in _migrate() below rather than just editing the CREATE statements.
# Name -> column type. Deliberately all nullable with no default: a row that predates
# check-ins simply has NULL here, which the UI renders as "never checked in".
_ADDED_COLUMNS = {
    "last_checkin":   "TEXT",   # when the device last pushed its own inventory to us
    "checkin_source": "TEXT",   # 'PushCollector' | 'CloudflareWARP'
    "checkin_user":   "TEXT",   # logged-on user (push collector) / WARP-enrolled user email
}


def _existing_columns(conn) -> set:
    if BACKEND == "postgres":
        cur = conn.cursor()
        cur.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'assets'"
        )
        return {r[0] for r in cur.fetchall()}
    return {r[1] for r in conn.execute("PRAGMA table_info(assets)").fetchall()}


def _migrate(conn) -> None:
    """Adds any missing _ADDED_COLUMNS to an existing assets table. Safe to run on
    every connection: it's a cheap catalog read, and a no-op once the columns exist."""
    have = _existing_columns(conn)
    missing = {c: t for c, t in _ADDED_COLUMNS.items() if c not in have}
    if not missing:
        return
    cur = conn.cursor()
    for col, coltype in missing.items():
        # Column names here are our own literals, never user input - no injection path.
        cur.execute(f"ALTER TABLE assets ADD COLUMN {col} {coltype}")
    conn.commit()


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
        _migrate(conn)
        return conn

    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "assets.db"
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    conn.execute(_SCHEMA_SQLITE)
    _migrate(conn)
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
    for col, key in (("last_checkin", "LastCheckin"),
                     ("checkin_source", "CheckinSource"),
                     ("checkin_user", "CheckinUser")):
        try:
            val = get(col)
        except (KeyError, IndexError):
            # Row came from a connection opened before _migrate() added the column
            # (shouldn't happen, but don't let it break the whole asset list).
            val = None
        if val:
            d[key] = val
    if get("software_json"):
        try:
            d["Software"] = json.loads(get("software_json"))
        except (TypeError, ValueError):
            pass
    return d


def record_checkin(state_dir: Path, payload: dict, checkin_source: str = "PushCollector") -> str:
    """Records one device-initiated check-in (the push collector running on the
    endpoint itself, or a Cloudflare WARP device pull) into the same assets table
    network discovery writes to, keyed by the same dedup key - so a laptop that was
    also network-scanned merges into one row instead of appearing twice.

    A check-in is proof the device is alive, so it advances last_seen as well as
    last_checkin. That's what makes the Online/Stale badges finally work for roaming
    laptops that a jump-server-initiated scan can never reach.

    Returns the dedup key written."""
    key = dedup_key(payload)
    if not key:
        raise ValueError("check-in payload has neither Name nor IP - cannot identify the device")

    now = datetime.utcnow().isoformat()
    # The device reports its own collection timestamp; fall back to server time if
    # absent or unparseable rather than trusting a clock-skewed endpoint blindly.
    seen = payload.get("CollectedAt") or now
    software = payload.get("Software")

    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        row = (
            key, payload.get("Name"), payload.get("IP"), payload.get("AssetType"),
            payload.get("OS"), payload.get("Source") or checkin_source, seen,
            json.dumps(software) if software else None,
            seen, checkin_source, payload.get("User"), now, now,
        )
        if BACKEND == "postgres":
            cur.execute("""
                INSERT INTO assets (dedup_key, name, ip, asset_type, os, source, last_seen,
                    software_json, last_checkin, checkin_source, checkin_user, first_seen, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (dedup_key) DO UPDATE SET
                    name           = COALESCE(EXCLUDED.name, assets.name),
                    ip             = COALESCE(EXCLUDED.ip, assets.ip),
                    asset_type     = COALESCE(EXCLUDED.asset_type, assets.asset_type),
                    os             = COALESCE(EXCLUDED.os, assets.os),
                    source         = COALESCE(EXCLUDED.source, assets.source),
                    last_seen      = COALESCE(EXCLUDED.last_seen, assets.last_seen),
                    software_json  = COALESCE(EXCLUDED.software_json, assets.software_json),
                    last_checkin   = EXCLUDED.last_checkin,
                    checkin_source = EXCLUDED.checkin_source,
                    checkin_user   = COALESCE(EXCLUDED.checkin_user, assets.checkin_user),
                    updated_at     = EXCLUDED.updated_at
            """, row)
        else:
            cur.execute("""
                INSERT INTO assets (dedup_key, name, ip, asset_type, os, source, last_seen,
                    software_json, last_checkin, checkin_source, checkin_user, first_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(dedup_key) DO UPDATE SET
                    name           = COALESCE(excluded.name, assets.name),
                    ip             = COALESCE(excluded.ip, assets.ip),
                    asset_type     = COALESCE(excluded.asset_type, assets.asset_type),
                    os             = COALESCE(excluded.os, assets.os),
                    source         = COALESCE(excluded.source, assets.source),
                    last_seen      = COALESCE(excluded.last_seen, assets.last_seen),
                    software_json  = COALESCE(excluded.software_json, assets.software_json),
                    last_checkin   = excluded.last_checkin,
                    checkin_source = excluded.checkin_source,
                    checkin_user   = COALESCE(excluded.checkin_user, assets.checkin_user),
                    updated_at     = excluded.updated_at
            """, row)
        conn.commit()
        return key
    finally:
        conn.close()


def load_recent_checkins(state_dir: Path, limit: int = 500) -> list:
    """Devices that have pushed a check-in, most recent first - the feed behind the
    Endpoints page. Excludes assets that have only ever been network-scanned."""
    conn = get_connection(state_dir)
    try:
        if BACKEND == "postgres":
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(
                "SELECT * FROM assets WHERE last_checkin IS NOT NULL "
                "ORDER BY last_checkin DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM assets WHERE last_checkin IS NOT NULL "
                "ORDER BY last_checkin DESC LIMIT ?", (limit,)).fetchall()
        return [_row_to_asset(r) for r in rows]
    finally:
        conn.close()


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

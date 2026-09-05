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
from datetime import datetime, timedelta
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
    # A laptop carried home every night checks in from the office by day and from home
    # by evening/weekend. Keeping only "last check-in" would mean each location's
    # timestamp erases the other's, so "when was this device last actually in the
    # office?" - the question that matters for physical audits, imaging and hands-on
    # work - becomes unanswerable. These keep both facts side by side.
    "last_office_checkin": "TEXT",
    "last_remote_checkin": "TEXT",
    "last_location":       "TEXT",   # 'Office' | 'Remote' | 'Unknown'
}

# Daily presence rollup. NOT one row per check-in: presence check-ins run every 30
# minutes, so 3000 laptops would write ~144k rows/day and the table would be useless
# within a month. One row per (device, day, location) collapses that to ~1-2 rows per
# device per day while still answering "how many days was this in the office" exactly.
_SCHEMA_CHECKIN_DAYS = """
    CREATE TABLE IF NOT EXISTS checkin_days (
        dedup_key     TEXT NOT NULL,
        day           TEXT NOT NULL,
        location      TEXT NOT NULL,
        first_seen_at TEXT NOT NULL,
        last_seen_at  TEXT NOT NULL,
        checkin_count INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (dedup_key, day, location)
    )
"""


# Certificates found by any scan, ever. Without this the Certificates page could only
# ever show the hosts in the most recent scan snapshot, so confirming one server's
# binding wiped the record of every other server - you would have to re-scan the whole
# estate every time to keep the page complete. Keyed by thumbprint (the certificate's
# own identity), with every place it has been seen merged into locations_json rather
# than overwritten, so the same wildcard cert on ten servers accumulates ten locations
# across ten separate scans.
_SCHEMA_CERTIFICATES = """
    CREATE TABLE IF NOT EXISTS certificates (
        thumbprint      TEXT PRIMARY KEY,
        subject         TEXT,
        issuer          TEXT,
        not_before      TEXT,
        not_after       TEXT,
        friendly_name   TEXT,
        dns_names       TEXT,
        has_private_key INTEGER,
        sources         TEXT,
        locations_json  TEXT,
        first_seen      TEXT NOT NULL,
        updated_at      TEXT NOT NULL
    )
"""

# Installed software, same reasoning as certificates: the scan snapshot only holds the
# hosts of the run that produced it, so a software inventory of ten laptops erased the
# previous ten. Keyed by (host, product, version) - version is part of the identity so an
# upgrade shows as the new version replacing nothing, and last_seen tells you whether the
# old one is genuinely still installed or just never re-scanned.
_SCHEMA_SOFTWARE = """
    CREATE TABLE IF NOT EXISTS software (
        sw_key       TEXT PRIMARY KEY,
        host         TEXT NOT NULL,
        category     TEXT,
        name         TEXT,
        version      TEXT,
        publisher    TEXT,
        architecture TEXT,
        install_date TEXT,
        source       TEXT,
        first_seen   TEXT NOT NULL,
        last_seen    TEXT NOT NULL
    )
"""

# Why a host has no software listed (WinRM error, or skipped because WinRM was never seen
# open). Keyed by host so a host that later collects successfully clears its own row.
_SCHEMA_SOFTWARE_ISSUES = """
    CREATE TABLE IF NOT EXISTS software_issues (
        host       TEXT PRIMARY KEY,
        reason     TEXT,
        first_seen TEXT NOT NULL,
        last_seen  TEXT NOT NULL
    )
"""

# Collection failures, keyed by target so a host that later succeeds replaces (and then
# clears) its own error rather than leaving a permanent scar on the page.
_SCHEMA_CERT_ERRORS = """
    CREATE TABLE IF NOT EXISTS cert_errors (
        target     TEXT PRIMARY KEY,
        source     TEXT,
        reason     TEXT,
        first_seen TEXT NOT NULL,
        last_seen  TEXT NOT NULL
    )
"""


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
    cur = conn.cursor()
    cur.execute(_SCHEMA_CHECKIN_DAYS)
    cur.execute(_SCHEMA_CERTIFICATES)
    cur.execute(_SCHEMA_CERT_ERRORS)
    cur.execute(_SCHEMA_SOFTWARE)
    cur.execute(_SCHEMA_SOFTWARE_ISSUES)

    have = _existing_columns(conn)
    missing = {c: t for c, t in _ADDED_COLUMNS.items() if c not in have}
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
                     ("checkin_user", "CheckinUser"),
                     ("last_office_checkin", "LastOfficeCheckin"),
                     ("last_remote_checkin", "LastRemoteCheckin"),
                     ("last_location", "LastLocation")):
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


def _preferred_name(existing: str | None, incoming: str | None, corp_suffix: str = "") -> str | None:
    """Picks the name to keep when a device reports itself from different networks.

    A laptop resolves its own FQDN via whatever DNS it currently has. In the office
    that's 'lap01.amg.local'; on a home router it's often 'lap01.lan', 'lap01.home',
    or just 'lap01'. The dedup key is the short name so it still merges correctly -
    but without this the DISPLAYED name would flip every time the laptop moved,
    which across 3000 assets is exactly the churn that makes an inventory feel
    untrustworthy. Prefer the corporate FQDN once we've ever seen one."""
    if not incoming:
        return existing
    if not existing:
        return incoming
    suffix = (corp_suffix or "").strip().lower().lstrip(".")
    if suffix:
        e_corp = existing.lower().endswith("." + suffix)
        i_corp = incoming.lower().endswith("." + suffix)
        if e_corp and not i_corp:
            return existing        # don't let 'lap01.lan' overwrite 'lap01.amg.local'
        if i_corp and not e_corp:
            return incoming
    # No corporate suffix configured (or both/neither match): prefer the more
    # qualified name, since an FQDN carries strictly more information than a label.
    if "." in existing and "." not in incoming:
        return existing
    return incoming


def _record_presence_day(cur, key: str, location: str, when_iso: str) -> None:
    """Upserts today's (device, location) presence row - see _SCHEMA_CHECKIN_DAYS."""
    day = when_iso[:10]
    if BACKEND == "postgres":
        cur.execute("""
            INSERT INTO checkin_days (dedup_key, day, location, first_seen_at, last_seen_at, checkin_count)
            VALUES (%s, %s, %s, %s, %s, 1)
            ON CONFLICT (dedup_key, day, location) DO UPDATE SET
                last_seen_at  = EXCLUDED.last_seen_at,
                checkin_count = checkin_days.checkin_count + 1
        """, (key, day, location, when_iso, when_iso))
    else:
        cur.execute("""
            INSERT INTO checkin_days (dedup_key, day, location, first_seen_at, last_seen_at, checkin_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(dedup_key, day, location) DO UPDATE SET
                last_seen_at  = excluded.last_seen_at,
                checkin_count = checkin_days.checkin_count + 1
        """, (key, day, location, when_iso, when_iso))


def presence_summary(state_dir: Path, days: int = 30) -> dict:
    """Per-device office/remote day counts over the last N days, for the Endpoints
    page. Returns {dedup_key: {'Office': n, 'Remote': n, 'last_office_day': 'YYYY-MM-DD'}}.

    Counts DAYS PRESENT, not check-ins - a laptop that sat in the office all day and
    one that connected for ten minutes both count as one office day, which is the
    honest granularity for 'how often is this device actually on site'."""
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        if BACKEND == "postgres":
            cur.execute("SELECT dedup_key, location, COUNT(*), MAX(day) FROM checkin_days "
                        "WHERE day >= %s GROUP BY dedup_key, location", (cutoff,))
        else:
            cur.execute("SELECT dedup_key, location, COUNT(*), MAX(day) FROM checkin_days "
                        "WHERE day >= ? GROUP BY dedup_key, location", (cutoff,))
        out: dict = {}
        for key, location, count, last_day in cur.fetchall():
            entry = out.setdefault(key, {"Office": 0, "Remote": 0, "Unknown": 0, "last_office_day": None})
            if location in entry:
                entry[location] = count
            if location == "Office":
                entry["last_office_day"] = last_day
        return out
    except Exception:
        return {}
    finally:
        conn.close()


def record_checkin(state_dir: Path, payload: dict, checkin_source: str = "PushCollector",
                   location: str = "Unknown", corp_dns_suffix: str = "") -> str:
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

    if location not in ("Office", "Remote", "Unknown"):
        location = "Unknown"
    # Only the matching location's column carries a timestamp; the other is NULL and
    # COALESCE below leaves the stored value alone. That's what lets a laptop check in
    # from home all weekend without erasing "last seen in the office on Friday".
    office_ts = seen if location == "Office" else None
    remote_ts = seen if location == "Remote" else None

    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()

        placeholder = "%s" if BACKEND == "postgres" else "?"
        cur.execute(f"SELECT name FROM assets WHERE dedup_key = {placeholder}", (key,))
        found = cur.fetchone()
        existing_name = found[0] if found else None
        name = _preferred_name(existing_name, payload.get("Name"), corp_dns_suffix)

        row = (
            key, name, payload.get("IP"), payload.get("AssetType"),
            payload.get("OS"), payload.get("Source") or checkin_source, seen,
            json.dumps(software) if software else None,
            seen, checkin_source, payload.get("User"),
            office_ts, remote_ts, location, now, now,
        )
        if BACKEND == "postgres":
            cur.execute("""
                INSERT INTO assets (dedup_key, name, ip, asset_type, os, source, last_seen,
                    software_json, last_checkin, checkin_source, checkin_user,
                    last_office_checkin, last_remote_checkin, last_location, first_seen, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    last_office_checkin = COALESCE(EXCLUDED.last_office_checkin, assets.last_office_checkin),
                    last_remote_checkin = COALESCE(EXCLUDED.last_remote_checkin, assets.last_remote_checkin),
                    last_location  = EXCLUDED.last_location,
                    updated_at     = EXCLUDED.updated_at
            """, row)
        else:
            cur.execute("""
                INSERT INTO assets (dedup_key, name, ip, asset_type, os, source, last_seen,
                    software_json, last_checkin, checkin_source, checkin_user,
                    last_office_checkin, last_remote_checkin, last_location, first_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    last_office_checkin = COALESCE(excluded.last_office_checkin, assets.last_office_checkin),
                    last_remote_checkin = COALESCE(excluded.last_remote_checkin, assets.last_remote_checkin),
                    last_location  = excluded.last_location,
                    updated_at     = excluded.updated_at
            """, row)

        _record_presence_day(cur, key, location, seen)
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


def _parse_locations(locations: str) -> dict:
    """'host [Cert:\\LocalMachine\\My]; host2 [host2:443]' -> {host: place}.

    PowerShell builds that string in Find-ExpiringCertificates/ConvertTo-CertificateInventory;
    splitting it back out is what lets the UI group certificates under the host they live
    on instead of showing one opaque line per certificate."""
    out = {}
    for part in (locations or "").split(";"):
        part = part.strip()
        if not part:
            continue
        if "[" in part:
            host, place = part.split("[", 1)
            out[host.strip() or "(unknown)"] = place.rstrip("]").strip()
        else:
            out[part] = ""
    return out


def sync_certificates(state_dir: Path, certs: list, errors: list, scan_time: str = "") -> None:
    """Merge one scan's certificate results into the permanent store.

    Never deletes a certificate: a host absent from this scan keeps everything already
    known about it. Locations are unioned, not replaced, so scanning server B does not
    erase the fact that the same certificate is also on server A."""
    now = datetime.utcnow().isoformat()
    seen_at = scan_time or now
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        ph = "%s" if BACKEND == "postgres" else "?"

        for c in certs or []:
            thumb = (c.get("Id") or c.get("Thumbprint") or "").strip().upper()
            if not thumb:
                continue
            locations = _parse_locations(c.get("Locations") or "")
            if not locations and c.get("ComputerName"):
                locations = {str(c["ComputerName"]).strip(): ""}
            incoming = {h: {"place": p, "last_seen": seen_at} for h, p in locations.items()}

            cur.execute(f"SELECT locations_json, sources FROM certificates WHERE thumbprint = {ph}", (thumb,))
            existing = cur.fetchone()
            sources = {s.strip() for s in (c.get("Sources") or "").split(",") if s.strip()}
            if existing:
                prior_locs = existing[0] if not isinstance(existing, dict) else existing["locations_json"]
                prior_src = existing[1] if not isinstance(existing, dict) else existing["sources"]
                try:
                    merged = json.loads(prior_locs) if prior_locs else {}
                except ValueError:
                    merged = {}
                merged.update(incoming)
                sources |= {s.strip() for s in (prior_src or "").split(",") if s.strip()}
            else:
                merged = incoming

            row = (
                c.get("Subject"), c.get("Issuer"), c.get("NotBefore"), c.get("NotAfter"),
                c.get("FriendlyName"), c.get("DnsNames"),
                1 if c.get("HasPrivateKey") else 0,
                ", ".join(sorted(sources)), json.dumps(merged), now,
            )
            if existing:
                cur.execute(f"""
                    UPDATE certificates SET subject={ph}, issuer={ph}, not_before={ph}, not_after={ph},
                        friendly_name={ph}, dns_names={ph}, has_private_key={ph}, sources={ph},
                        locations_json={ph}, updated_at={ph}
                    WHERE thumbprint={ph}
                """, row + (thumb,))
            else:
                cur.execute(f"""
                    INSERT INTO certificates (subject, issuer, not_before, not_after, friendly_name,
                        dns_names, has_private_key, sources, locations_json, updated_at,
                        thumbprint, first_seen)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                """, row + (thumb, now))

        # A target that just returned certificates is not failing any more - drop any
        # stale error row for it, otherwise the failures table never empties.
        for c in certs or []:
            for h in _parse_locations(c.get("Locations") or ""):
                cur.execute(f"DELETE FROM cert_errors WHERE target = {ph}", (h,))

        for e in errors or []:
            target = (e.get("ComputerName") or e.get("Locations") or "").split("[")[0].strip()
            if not target:
                continue
            reason = e.get("CollectionErrors") or e.get("Error") or "Unknown error"
            cur.execute(f"SELECT 1 FROM cert_errors WHERE target = {ph}", (target,))
            if cur.fetchone():
                cur.execute(
                    f"UPDATE cert_errors SET source={ph}, reason={ph}, last_seen={ph} WHERE target={ph}",
                    (e.get("Sources") or e.get("Source"), reason, now, target),
                )
            else:
                cur.execute(
                    f"INSERT INTO cert_errors (target, source, reason, first_seen, last_seen)"
                    f" VALUES ({ph}, {ph}, {ph}, {ph}, {ph})",
                    (target, e.get("Sources") or e.get("Source"), reason, now, now),
                )
        conn.commit()
    finally:
        conn.close()


CERT_ERROR_TTL_DAYS = 7


def load_all_certificates(state_dir: Path, error_ttl_days: int = CERT_ERROR_TTL_DAYS) -> tuple[list, list]:
    """Every certificate ever collected, plus the currently-failing targets.

    Error rows are pruned once nothing has re-reported them for error_ttl_days. A target
    that is removed from the config (a placeholder endpoint deleted, a decommissioned
    host) never succeeds and so would never clear itself - it would sit on the page as a
    permanent failure for something nobody is scanning any more."""
    conn = get_connection(state_dir)
    try:
        cutoff = (datetime.utcnow() - timedelta(days=error_ttl_days)).isoformat()
        cur0 = conn.cursor()
        cur0.execute(
            f"DELETE FROM cert_errors WHERE last_seen < {'%s' if BACKEND == 'postgres' else '?'}",
            (cutoff,),
        )
        conn.commit()
        if BACKEND == "postgres":
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM certificates")
            cert_rows = cur.fetchall()
            cur.execute("SELECT * FROM cert_errors")
            err_rows = cur.fetchall()
        else:
            cert_rows = conn.execute("SELECT * FROM certificates").fetchall()
            err_rows = conn.execute("SELECT * FROM cert_errors").fetchall()

        certs = []
        for r in cert_rows:
            get = (lambda k: r[k])
            try:
                locations = json.loads(get("locations_json") or "{}")
            except ValueError:
                locations = {}
            certs.append({
                "Id": get("thumbprint"),
                "Subject": get("subject"),
                "Issuer": get("issuer"),
                "NotBefore": get("not_before"),
                "NotAfter": get("not_after"),
                "FriendlyName": get("friendly_name"),
                "DnsNames": get("dns_names"),
                "HasPrivateKey": bool(get("has_private_key")),
                "Sources": get("sources"),
                "LocationMap": locations,
                "ComputerName": ", ".join(sorted(locations)),
                "Locations": "; ".join(f"{h} [{v.get('place','')}]" for h, v in sorted(locations.items())),
                "FirstSeen": get("first_seen"),
                "UpdatedAt": get("updated_at"),
            })
        errors = [{
            "ComputerName": r["target"], "Locations": r["target"],
            "Sources": r["source"], "CollectionErrors": r["reason"],
            "FirstSeen": r["first_seen"], "LastSeen": r["last_seen"],
        } for r in err_rows]
        return certs, errors
    finally:
        conn.close()


def delete_cert_error(state_dir: Path, target: str) -> bool:
    """Dismiss one collection failure by hand - for a target you have deliberately
    stopped scanning and don't want to wait out the TTL on."""
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        ph = "%s" if BACKEND == "postgres" else "?"
        cur.execute(f"DELETE FROM cert_errors WHERE target = {ph}", (target,))
        deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()


def delete_certificate(state_dir: Path, thumbprint: str) -> bool:
    """Remove one certificate from the permanent store (replaced cert, decommissioned
    host). Nothing else prunes this table, so there has to be a way to take a row out."""
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        ph = "%s" if BACKEND == "postgres" else "?"
        cur.execute(f"DELETE FROM certificates WHERE thumbprint = {ph}", (thumbprint.strip().upper(),))
        deleted = cur.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()


def _software_key(host: str, name: str, version: str) -> str:
    return "|".join(x.strip().lower() for x in (host or "", name or "", version or ""))


def sync_software(state_dir: Path, records: list, issues: list) -> None:
    """Merge one run's software inventory into the permanent store.

    Like certificates, nothing is deleted: a host that wasn't in this run keeps its last
    known inventory, stamped with when it was collected, rather than vanishing from the
    page until the next full sweep."""
    now = datetime.utcnow().isoformat()
    conn = get_connection(state_dir)
    try:
        cur = conn.cursor()
        ph = "%s" if BACKEND == "postgres" else "?"
        collected_hosts = set()

        for s in records or []:
            host = (s.get("ComputerName") or "").strip()
            name = (s.get("Name") or "").strip()
            if not host or not name:
                continue
            collected_hosts.add(host)
            key = _software_key(host, name, s.get("Version") or "")
            row = (
                host, s.get("Category"), name, s.get("Version"), s.get("Publisher"),
                s.get("Architecture"), s.get("InstallDate"), s.get("Source"), now,
            )
            cur.execute(f"SELECT 1 FROM software WHERE sw_key = {ph}", (key,))
            if cur.fetchone():
                cur.execute(f"""
                    UPDATE software SET host={ph}, category={ph}, name={ph}, version={ph},
                        publisher={ph}, architecture={ph}, install_date={ph}, source={ph},
                        last_seen={ph}
                    WHERE sw_key={ph}
                """, row + (key,))
            else:
                cur.execute(f"""
                    INSERT INTO software (host, category, name, version, publisher,
                        architecture, install_date, source, last_seen, sw_key, first_seen)
                    VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                """, row + (key, now))

        # A host that just returned software is not failing any more.
        for host in collected_hosts:
            cur.execute(f"DELETE FROM software_issues WHERE host = {ph}", (host,))

        for i in issues or []:
            host = (i.get("ComputerName") or "").strip()
            if not host or host in collected_hosts:
                continue
            cur.execute(f"SELECT 1 FROM software_issues WHERE host = {ph}", (host,))
            if cur.fetchone():
                cur.execute(f"UPDATE software_issues SET reason={ph}, last_seen={ph} WHERE host={ph}",
                            (i.get("Reason"), now, host))
            else:
                cur.execute(f"INSERT INTO software_issues (host, reason, first_seen, last_seen)"
                            f" VALUES ({ph}, {ph}, {ph}, {ph})", (host, i.get("Reason"), now, now))
        conn.commit()
    finally:
        conn.close()


def load_all_software(state_dir: Path) -> tuple[list, list]:
    """Every software record ever collected, plus the hosts currently failing to collect."""
    conn = get_connection(state_dir)
    try:
        if BACKEND == "postgres":
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT * FROM software ORDER BY host, name, version")
            sw_rows = cur.fetchall()
            cur.execute("SELECT * FROM software_issues ORDER BY host")
            issue_rows = cur.fetchall()
        else:
            sw_rows = conn.execute("SELECT * FROM software ORDER BY host, name, version").fetchall()
            issue_rows = conn.execute("SELECT * FROM software_issues ORDER BY host").fetchall()

        software = [{
            "ComputerName": r["host"], "Category": r["category"], "Name": r["name"],
            "Version": r["version"], "Publisher": r["publisher"],
            "Architecture": r["architecture"], "InstallDate": r["install_date"],
            "Source": r["source"], "FirstSeen": r["first_seen"], "LastSeen": r["last_seen"],
        } for r in sw_rows]
        issues = [{
            "ComputerName": r["host"], "Reason": r["reason"],
            "FirstSeen": r["first_seen"], "LastSeen": r["last_seen"],
        } for r in issue_rows]
        return software, issues
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

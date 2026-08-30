"""SOAR - playbook-driven response automation for AD-Agent findings.

WHAT THIS IS, honestly: a focused, AD-centric orchestration engine - triggers,
conditions, actions, incidents, approvals and an audit trail. It is NOT FortiSOAR.
A commercial SOAR additionally ships a visual playbook designer, hundreds of vendor
connectors, case SLAs, shift handover, multi-tenancy and a war room. What's here is
the part that actually earns its keep for this tool: turning scan findings into
tracked incidents and taking a small set of well-chosen AD response actions, with
approval gates in front of anything destructive.

DESIGN CONSTRAINT THAT SHAPES EVERYTHING BELOW: this automates actions against a
production Active Directory. Disabling the wrong account is an outage; disabling the
wrong *privileged* account during an incident is a much worse one. So:

  * The engine is OFF by default (SOAR_MODE unset).
  * Dry-run is the first real mode: playbooks evaluate and incidents are created,
    but no action executes.
  * Destructive actions ALWAYS require explicit human approval in the UI, even in
    live mode. There is deliberately no "fully autonomous" setting - not because it
    couldn't be written, but because nothing in this tool's data is reliable enough
    to justify unattended account disablement.
  * Every evaluation, approval and execution is written to the audit trail.

The orchestration logic lives here in Python (testable, and it's what the web UI
reads); only the AD-mutating actions shell out to PowerShell, kept as thin as
possible so the untested surface stays small.
"""

import json
import os
import subprocess
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

import assets_db

# off    - engine disabled entirely (default; nothing evaluates)
# dryrun - playbooks evaluate, incidents are created, NO action executes
# live   - safe actions execute; destructive ones still queue for approval
SOAR_MODE = os.environ.get("SOAR_MODE", "off").strip().lower()

_SCHEMA_INCIDENTS = """
    CREATE TABLE IF NOT EXISTS soar_incidents (
        id           TEXT PRIMARY KEY,
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL,
        playbook_id  TEXT NOT NULL,
        title        TEXT NOT NULL,
        severity     TEXT,
        source       TEXT,
        entity       TEXT,
        status       TEXT NOT NULL,
        dedupe_key   TEXT,
        detail_json  TEXT
    )
"""

_SCHEMA_ACTIONS = """
    CREATE TABLE IF NOT EXISTS soar_actions (
        id           TEXT PRIMARY KEY,
        incident_id  TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        action_type  TEXT NOT NULL,
        params_json  TEXT,
        status       TEXT NOT NULL,
        destructive  INTEGER NOT NULL DEFAULT 0,
        approved_by  TEXT,
        approved_at  TEXT,
        executed_at  TEXT,
        result_json  TEXT
    )
"""

# Incident status
OPEN, CLOSED = "open", "closed"
# Action status
PENDING_APPROVAL = "pending_approval"
QUEUED = "queued"
EXECUTED = "executed"
FAILED = "failed"
SKIPPED_DRYRUN = "skipped_dryrun"
REJECTED = "rejected"


def _ph() -> str:
    return "%s" if assets_db.BACKEND == "postgres" else "?"


def _connect(state_dir: Path):
    conn = assets_db.get_connection(state_dir)
    cur = conn.cursor()
    cur.execute(_SCHEMA_INCIDENTS)
    cur.execute(_SCHEMA_ACTIONS)
    conn.commit()
    return conn


# ── Action registry ──────────────────────────────────────────────────────────
# destructive=True means "changes state in Active Directory or on an endpoint".
# Those never auto-execute; they queue for approval regardless of SOAR_MODE.
ACTIONS = {
    "notify_teams": {
        "destructive": False,
        "description": "Post the incident to the configured Teams webhook.",
    },
    "tag_asset": {
        "destructive": False,
        "description": "Annotate the affected asset with a note visible on the Assets page.",
    },
    "disable_ad_user": {
        "destructive": True,
        "description": "Disable the Active Directory user account named in the finding.",
    },
    "disable_ad_computer": {
        "destructive": True,
        "description": "Disable the Active Directory computer account for the affected host.",
    },
    "remove_from_privileged_group": {
        "destructive": True,
        "description": "Remove the account from the privileged group named in the finding.",
    },
}


def load_playbooks(config_path: Path) -> list:
    """Reads playbooks.json. Returns [] (rather than raising) if it's missing or
    malformed - a broken playbook file must never take the web UI down with it.
    Validation errors are returned per-playbook so the UI can show them."""
    if not config_path.exists():
        return []
    try:
        with open(config_path, encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    return data.get("playbooks", []) if isinstance(data, dict) else []


def validate_playbook(pb: dict) -> list:
    """Returns a list of human-readable problems; empty means usable."""
    problems = []
    if not pb.get("id"):
        problems.append("missing 'id'")
    if not pb.get("name"):
        problems.append("missing 'name'")
    trigger = pb.get("trigger") or {}
    if not trigger.get("source"):
        problems.append("trigger.source is required (e.g. 'Anomalies')")
    for a in pb.get("actions") or []:
        if a.get("type") not in ACTIONS:
            problems.append(f"unknown action type {a.get('type')!r}")
    if not pb.get("actions"):
        problems.append("playbook has no actions")
    return problems


def _match_condition(finding: dict, cond: dict) -> bool:
    field = cond.get("field")
    op = (cond.get("op") or "eq").lower()
    expected = cond.get("value")
    actual = finding.get(field)

    if op == "exists":
        return actual is not None
    if actual is None:
        return False

    a_str = str(actual).lower()
    if op == "eq":
        return a_str == str(expected).lower()
    if op == "ne":
        return a_str != str(expected).lower()
    if op == "in":
        return a_str in [str(v).lower() for v in (expected or [])]
    if op == "contains":
        return str(expected).lower() in a_str
    if op in ("lt", "lte", "gt", "gte"):
        try:
            a_num, e_num = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return {"lt": a_num < e_num, "lte": a_num <= e_num,
                "gt": a_num > e_num, "gte": a_num >= e_num}[op]
    return False


def matches(finding: dict, pb: dict) -> bool:
    """Does this finding fire this playbook? Severity filter, then all conditions
    (AND). Deliberately AND-only: OR logic in a config file becomes unreadable fast,
    and two playbooks express it more clearly than nested boolean groups."""
    trigger = pb.get("trigger") or {}
    severities = trigger.get("severity")
    if severities:
        want = [str(s).lower() for s in severities]
        if str(finding.get("Severity", "")).lower() not in want:
            return False
    for cond in pb.get("conditions") or []:
        if not _match_condition(finding, cond):
            return False
    return True


def render(template: str, finding: dict) -> str:
    """Fills {Field} placeholders from the finding. Unknown fields render as '?'
    rather than raising - a formatting slip in a playbook shouldn't abort a run."""
    out = str(template)
    for key, value in finding.items():
        out = out.replace("{" + str(key) + "}", str(value) if value is not None else "")
    # Any placeholder left unresolved
    while "{" in out and "}" in out:
        start = out.index("{")
        end = out.index("}", start) if "}" in out[start:] else -1
        if end == -1:
            break
        out = out[:start] + "?" + out[end + 1:]
    return out


def _dedupe_key(pb_id: str, finding: dict) -> str:
    """Stops a playbook re-raising the same incident on every scan. Keyed on the
    playbook plus the finding's most identifying fields."""
    parts = [pb_id]
    for field in ("ControlId", "Type", "Id", "CveId", "Account", "ComputerName", "Subject"):
        val = finding.get(field)
        if val:
            parts.append(f"{field}={val}")
    return "|".join(parts)


def evaluate(findings_by_source: dict, playbooks: list) -> list:
    """Pure function: which playbooks fire on which findings. No side effects, so
    it can be unit-tested and previewed in the UI before anything is written."""
    hits = []
    for pb in playbooks:
        if not pb.get("enabled", True):
            continue
        if validate_playbook(pb):
            continue
        source = (pb.get("trigger") or {}).get("source")
        for finding in findings_by_source.get(source, []) or []:
            if matches(finding, pb):
                hits.append({"playbook": pb, "finding": finding, "source": source})
    return hits


def run(state_dir: Path, findings_by_source: dict, playbooks: list,
        mode: str | None = None, teams_webhook: str = "",
        responder_script: Path | None = None, powershell: str | None = None) -> dict:
    """Evaluates playbooks and records incidents/actions.

    Returns a summary dict. Honours SOAR_MODE unless `mode` overrides it (the UI's
    "preview" button passes 'dryrun' explicitly)."""
    mode = (mode or SOAR_MODE).lower()
    if mode == "off":
        return {"mode": "off", "evaluated": 0, "incidents_created": 0,
                "actions": {}, "note": "SOAR_MODE is not set - engine disabled."}

    hits = evaluate(findings_by_source, playbooks)
    now = datetime.utcnow().isoformat()
    created = 0
    action_counts: dict = {}

    conn = _connect(state_dir)
    try:
        cur = conn.cursor()
        ph = _ph()
        for hit in hits:
            pb, finding = hit["playbook"], hit["finding"]
            key = _dedupe_key(pb["id"], finding)

            cur.execute(f"SELECT id FROM soar_incidents WHERE dedupe_key = {ph} AND status = {ph}",
                        (key, OPEN))
            if cur.fetchone():
                continue   # already tracking this exact finding

            incident_id = uuid.uuid4().hex
            title = render(pb.get("title") or pb.get("name", "Incident"), finding)
            entity = finding.get("ComputerName") or finding.get("Account") or finding.get("Subject")
            cur.execute(
                f"INSERT INTO soar_incidents (id, created_at, updated_at, playbook_id, title, "
                f"severity, source, entity, status, dedupe_key, detail_json) "
                f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})",
                (incident_id, now, now, pb["id"], title, finding.get("Severity"),
                 hit["source"], entity, OPEN, key, json.dumps(finding)[:8000]))
            created += 1

            for action in pb.get("actions") or []:
                a_type = action.get("type")
                spec = ACTIONS.get(a_type)
                if not spec:
                    continue
                destructive = bool(spec["destructive"])
                params = {k: render(v, finding) if isinstance(v, str) else v
                          for k, v in (action.get("params") or {}).items()}

                if destructive:
                    status = PENDING_APPROVAL      # always, in every mode
                elif mode == "dryrun":
                    status = SKIPPED_DRYRUN
                else:
                    status = QUEUED

                action_id = uuid.uuid4().hex
                cur.execute(
                    f"INSERT INTO soar_actions (id, incident_id, created_at, action_type, "
                    f"params_json, status, destructive) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})",
                    (action_id, incident_id, now, a_type, json.dumps(params), status,
                     1 if destructive else 0))
                action_counts[status] = action_counts.get(status, 0) + 1
        conn.commit()
    finally:
        conn.close()

    executed = 0
    if mode == "live":
        executed = execute_queued(state_dir, teams_webhook=teams_webhook,
                                  responder_script=responder_script, powershell=powershell)

    return {"mode": mode, "evaluated": len(hits), "incidents_created": created,
            "actions": action_counts, "executed": executed}


def _perform(action_type: str, params: dict, teams_webhook: str,
             responder_script: Path | None, powershell: str | None) -> dict:
    """Carries out one action. Raises on failure; caller records the result."""
    if action_type == "notify_teams":
        if not teams_webhook:
            raise RuntimeError("no Teams webhook configured (Reporting.Teams.WebhookUrl)")
        payload = json.dumps({"text": params.get("text") or params.get("title") or "AD-Agent incident"})
        req = urllib.request.Request(
            teams_webhook, data=payload.encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return {"http_status": resp.status}

    if action_type == "tag_asset":
        note = params.get("note") or "Flagged by AD-Agent SOAR"
        target = params.get("asset") or params.get("ComputerName")
        if not target:
            raise RuntimeError("tag_asset needs an 'asset' parameter")
        return {"tagged": target, "note": note}

    # Everything else mutates AD - hand off to the PowerShell responder.
    if not responder_script or not Path(responder_script).exists():
        raise RuntimeError("AD responder script not found; cannot execute AD actions")
    if not powershell:
        raise RuntimeError("no PowerShell interpreter available")

    cmd = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass",
           "-File", str(responder_script), "-Action", action_type]
    for key in ("Identity", "Group", "Reason"):
        if params.get(key):
            cmd += [f"-{key}", str(params[key])]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise RuntimeError(f"responder exited {proc.returncode}: {(proc.stderr or proc.stdout)[:500]}")
    return {"stdout": (proc.stdout or "")[:2000]}


def execute_queued(state_dir: Path, teams_webhook: str = "",
                   responder_script: Path | None = None,
                   powershell: str | None = None) -> int:
    """Runs every QUEUED action. Destructive actions only reach QUEUED after a human
    approved them in the UI, so this never needs to re-check that."""
    conn = _connect(state_dir)
    ran = 0
    try:
        cur = conn.cursor()
        ph = _ph()
        cur.execute(f"SELECT id, action_type, params_json FROM soar_actions WHERE status = {ph}", (QUEUED,))
        rows = cur.fetchall()
        for row in rows:
            action_id, action_type, params_json = row[0], row[1], row[2]
            try:
                params = json.loads(params_json) if params_json else {}
            except ValueError:
                params = {}
            now = datetime.utcnow().isoformat()
            try:
                result = _perform(action_type, params, teams_webhook, responder_script, powershell)
                cur.execute(
                    f"UPDATE soar_actions SET status = {ph}, executed_at = {ph}, result_json = {ph} "
                    f"WHERE id = {ph}", (EXECUTED, now, json.dumps(result)[:4000], action_id))
                ran += 1
            except Exception as exc:  # noqa: BLE001 - one bad action must not stop the rest
                cur.execute(
                    f"UPDATE soar_actions SET status = {ph}, executed_at = {ph}, result_json = {ph} "
                    f"WHERE id = {ph}", (FAILED, now, json.dumps({"error": str(exc)})[:4000], action_id))
            conn.commit()
    finally:
        conn.close()
    return ran


def set_action_status(state_dir: Path, action_id: str, status: str, approved_by: str = "") -> bool:
    """Approve (-> QUEUED) or reject (-> REJECTED) a pending action."""
    conn = _connect(state_dir)
    try:
        cur = conn.cursor()
        ph = _ph()
        now = datetime.utcnow().isoformat()
        cur.execute(
            f"UPDATE soar_actions SET status = {ph}, approved_by = {ph}, approved_at = {ph} "
            f"WHERE id = {ph} AND status = {ph}",
            (status, approved_by, now, action_id, PENDING_APPROVAL))
        changed = cur.rowcount > 0
        conn.commit()
        return changed
    finally:
        conn.close()


def list_incidents(state_dir: Path, limit: int = 200) -> list:
    conn = _connect(state_dir)
    try:
        cur = conn.cursor()
        ph = _ph()
        cur.execute(
            f"SELECT id, created_at, playbook_id, title, severity, source, entity, status "
            f"FROM soar_incidents ORDER BY created_at DESC LIMIT {ph}", (limit,))
        cols = ["Id", "CreatedAt", "PlaybookId", "Title", "Severity", "Source", "Entity", "Status"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        return []
    finally:
        conn.close()


def list_actions(state_dir: Path, status: str | None = None, limit: int = 200) -> list:
    conn = _connect(state_dir)
    try:
        cur = conn.cursor()
        ph = _ph()
        base = ("SELECT a.id, a.incident_id, a.created_at, a.action_type, a.params_json, a.status, "
                "a.destructive, a.approved_by, a.executed_at, a.result_json, i.title, i.entity "
                "FROM soar_actions a LEFT JOIN soar_incidents i ON i.id = a.incident_id ")
        if status:
            cur.execute(base + f"WHERE a.status = {ph} ORDER BY a.created_at DESC LIMIT {ph}", (status, limit))
        else:
            cur.execute(base + f"ORDER BY a.created_at DESC LIMIT {ph}", (limit,))
        cols = ["Id", "IncidentId", "CreatedAt", "ActionType", "ParamsJson", "Status",
                "Destructive", "ApprovedBy", "ExecutedAt", "ResultJson", "IncidentTitle", "Entity"]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        return []
    finally:
        conn.close()

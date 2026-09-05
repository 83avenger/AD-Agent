"""DC Anomaly Agent — web UI.

Accepts scan sources, triggers the PowerShell scanner, and serves
PDF and CSV reports. Designed to run on the same management server
that executes the Scheduled Task.
"""

import hmac
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from report_generator import (
    generate_csv_anomalies,
    generate_csv_certificates,
    generate_csv_compliance,
    generate_csv_software,
    generate_pdf,
)
import assets_db
import soar

APP_ROOT      = Path(__file__).parent
PS_SCRIPT     = APP_ROOT.parent / "DCAnomalyAgent" / "Run-AnomalyScan.ps1"
DISCOVERY_SCRIPT = APP_ROOT.parent / "DCAnomalyAgent" / "Run-Discovery.ps1"
STATE_DIR     = APP_ROOT.parent / "DCAnomalyAgent" / "State"
# Passed explicitly as -ConfigPath on every PowerShell invocation below, rather than
# relying on each script's own default resolution - belt-and-braces against any argument
# mis-binding (a stray value landing on -ConfigPath instead of its intended parameter).
SETTINGS_PATH = APP_ROOT.parent / "DCAnomalyAgent" / "Config" / "settings.psd1"
SNAPSHOT_PATH = STATE_DIR / "latest-scan.json"
DISCOVERY_INVENTORY_PATH = STATE_DIR / "asset-inventory.json"
# Canonical, ever-growing asset store. Run-Discovery.ps1 still writes the JSON file above
# on every run (unchanged - no PowerShell-side dependency added); the web app upserts it
# into a real DB on load, keyed by a stable dedup key. Rows are only ever added/updated
# here, never deleted, so previously-discovered assets can't disappear regardless of what
# a given scan run's JSON snapshot does or doesn't contain - and at 3000+ assets, an
# indexed UPSERT scales far better than rewriting one flat JSON array. See assets_db.py -
# SQLite by default (DCAnomalyAgent/State/assets.db), or PostgreSQL if ASSETS_DATABASE_URL
# is set (for multi-site/multi-instance deployments past what one SQLite file handles).
INTEGRATIONS_STATUS_PATH = STATE_DIR / "integrations-status.json"
INTEGRATIONS_SCRIPT      = APP_ROOT.parent / "DCAnomalyAgent" / "Get-IntegrationStatus.ps1"
WINRM_TEST_SCRIPT        = APP_ROOT.parent / "DCAnomalyAgent" / "Test-WinRM.ps1"
PLAYBOOKS_PATH           = APP_ROOT.parent / "DCAnomalyAgent" / "Config" / "playbooks.json"
SOAR_RESPONDER_SCRIPT    = APP_ROOT.parent / "DCAnomalyAgent" / "Invoke-SoarResponder.ps1"
# Vendor API keys entered on the Vendor Warranty page live here, not in settings.psd1 or
# git - see DCAnomalyAgent/Modules/DCAnomalyAgent.VendorWarranty.psm1.
INTEGRATION_SECRETS_PATH = APP_ROOT.parent / "DCAnomalyAgent" / "Config" / "integration-secrets.json"
REPORTS_DIR   = APP_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))

AUDIT_LOG_PATH = STATE_DIR / "audit.log"


def _remote_user() -> str:
    """Identity of whoever made this request, if known. Register-IISReverseProxy.ps1
    forwards the Windows-Authentication-verified username as X-Remote-User once that
    proxy is deployed in front of the web UI; until then (or for anyone hitting the app
    directly) there's no auth at all, so this is best-effort, not a security control by
    itself - see the security review in ENTERPRISE-HARDENING-RUNBOOK.md."""
    return request.headers.get("X-Remote-User") or f"unauthenticated@{request.remote_addr}"


def _audit(action: str, detail: str = "") -> None:
    """Appends one line per state-changing action (scan/discovery submitted, asset
    deleted) so that once IIS auth is in front of this app, there's a record of who
    triggered what - not just that it happened."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        line = f"[{datetime.utcnow().isoformat()}Z] user={_remote_user()} action={action} {detail}".rstrip()
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass  # audit logging must never break the request it's logging


# ── Background job queue ────────────────────────────────────────────────────
# Scans/discovery runs shell out to PowerShell and can take minutes against
# many hosts. Running them synchronously inside a Flask request thread blocks
# that worker for the whole duration - fine for one person testing, but not
# for multiple people using the UI at once, and it leaves the browser with no
# feedback beyond a spinning tab for however long the PowerShell process
# takes. Jobs run on a small thread pool instead; the submitting request gets
# a job id back immediately and the UI polls /jobs/<id> for status.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="adagent-job")
_JOB_RETENTION_SEC = 3600  # finished jobs are kept this long so a late poll/refresh still works


def _submit_job(kind: str, fn, *args, **kwargs) -> str:
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {
            "kind": kind,
            "status": "running",
            "started_at": time.time(),
            "finished_at": None,
            "result": None,
            "error": None,
        }
        # Opportunistic cleanup of old finished jobs - keeps _jobs from growing
        # unbounded on a long-lived process without needing a separate timer.
        stale = [
            jid for jid, j in _jobs.items()
            if j["finished_at"] and (time.time() - j["finished_at"]) > _JOB_RETENTION_SEC
        ]
        for jid in stale:
            del _jobs[jid]

    def _run():
        try:
            result = fn(*args, **kwargs)
            with _jobs_lock:
                _jobs[job_id]["status"] = "done"
                _jobs[job_id]["result"] = result
                _jobs[job_id]["finished_at"] = time.time()
        except Exception as exc:  # noqa: BLE001 - report to the polling UI, don't crash the pool
            with _jobs_lock:
                _jobs[job_id]["status"] = "error"
                _jobs[job_id]["error"] = str(exc)
                _jobs[job_id]["finished_at"] = time.time()

    _executor.submit(_run)
    return job_id


def _get_job(job_id: str) -> dict | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _detect_powershell() -> str:
    for candidate in ("pwsh", "powershell"):
        try:
            subprocess.run([candidate, "-Version"], capture_output=True, timeout=5)
            return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return None


def _run_scan(
    domain_controllers: list[str],
    scan_types: list[str],
    frameworks: list[str],
    severities: list[str],
) -> tuple[dict | None, str]:
    """
    Invoke the PowerShell scanner and return (parsed_result, error_message).
    Returns (None, error) on failure.
    """
    pwsh = _detect_powershell()
    if not pwsh:
        return None, "PowerShell (pwsh/powershell) not found on PATH."

    dc_override = ",".join(domain_controllers)

    cmd = [
        pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(PS_SCRIPT),
        "-ConfigPath", str(SETTINGS_PATH),
        "-DomainControllerOverride", dc_override,
        "-JsonOutput",
    ]

    # -OnlySelectedScans makes the scanner honour this selection exactly. Without it,
    # settings.psd1's own enable flags act as an OR fallback, so picking just
    # "Certificate Scan" here still ran a full zero-day sweep. Scheduled tasks
    # deliberately don't pass it - unattended runs should stay config-driven.
    cmd.append("-OnlySelectedScans")

    if "compliance" in scan_types:
        cmd.append("-ComplianceScan")
    if "certificate" in scan_types:
        cmd.append("-CertificateScan")
    if "software" in scan_types:
        cmd.append("-SoftwareInventoryScan")
    if "zeroday" in scan_types:
        cmd.append("-ZeroDayScan")
    if "anomaly" not in scan_types:
        cmd.append("-SkipAnomalyScan")
    # A comma-joined single argument, not multiple space-separated ones: PowerShell's
    # parameter binder doesn't aggregate multiple tokens into an array when invoked
    # externally like this (only the first token binds) - the target scripts split
    # comma-joined values back into arrays themselves. See Run-Discovery.ps1's comment
    # on this for the full explanation.
    if frameworks:
        cmd += ["-FrameworkFilter", ",".join(frameworks)]
    if severities:
        cmd += ["-SeverityFilter", ",".join(severities)]

    # A flat 5-minute cap was fine for the handful of DCs this started with, but a
    # target range is now a legitimate input: 50 hosts collected one after another,
    # several of them unreachable and each burning WinRM's own connect timeout, does not
    # fit in 300s. Scale with the work actually requested rather than making everyone
    # wait for the worst case, and let a site with slower links raise the whole thing
    # via AD_AGENT_SCAN_TIMEOUT_SEC. The run itself is already on the job queue, so a
    # longer ceiling costs a browser nothing - it polls /jobs/<id> either way.
    timeout_sec = int(os.environ.get("AD_AGENT_SCAN_TIMEOUT_SEC") or 0) or min(
        7200, 300 + 30 * max(0, len(domain_controllers) - 1)
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=timeout_sec,
        )
        raw = result.stdout.strip()
        if not raw:
            err = result.stderr.strip() or "Scanner produced no output."
            return None, err

        # The PS script may emit warnings/verbose lines before the JSON — grab the last
        # contiguous JSON block (starts with '{' ends with '}').
        json_start = raw.find("{")
        json_end   = raw.rfind("}") + 1
        if json_start == -1:
            return None, f"No JSON in output.\n\nStdout:\n{raw}\n\nStderr:\n{result.stderr}"

        parsed = json.loads(raw[json_start:json_end])
        return parsed, ""

    except subprocess.TimeoutExpired:
        mins = timeout_sec / 60
        return None, (
            f"Scan timed out after {mins:.0f} minute(s) against {len(domain_controllers)} target(s). "
            "Unreachable hosts are the usual cause - each one costs WinRM's full connect timeout. "
            "Narrow the range, or raise AD_AGENT_SCAN_TIMEOUT_SEC on the web app service."
        )
    except json.JSONDecodeError as exc:
        return None, f"Failed to parse scanner output as JSON: {exc}\n\nRaw output:\n{raw[:2000]}"
    except Exception as exc:
        return None, str(exc)


def _run_discovery(
    from_ad: bool,
    cidr: list[str],
    cloudflare_warp_cidr: list[str],
    skip_categorize: bool,
    skip_software: bool,
) -> tuple[dict | None, str]:
    """
    Invoke Run-Discovery.ps1 directly — asset discovery + (by default) its folded-in
    software inventory, with no anomaly/compliance/certificate scanning at all. Targets
    are whatever AD/network scanning actually finds, not the static Assets.* host lists
    Run-AnomalyScan.ps1 uses (which is what silently fails on stale placeholder hosts).
    Returns (parsed_result, error_message); (None, error) on failure.
    """
    pwsh = _detect_powershell()
    if not pwsh:
        return None, "PowerShell (pwsh/powershell) not found on PATH."

    cmd = [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(DISCOVERY_SCRIPT),
           "-ConfigPath", str(SETTINGS_PATH), "-JsonOutput"]
    if from_ad:
        cmd.append("-FromAD")
    # Comma-joined single argument - see the -FrameworkFilter comment above for why.
    if cidr:
        cmd += ["-Cidr", ",".join(cidr)]
    if cloudflare_warp_cidr:
        cmd += ["-CloudflareWarpCidr", ",".join(cloudflare_warp_cidr)]
    if skip_categorize:
        cmd.append("-SkipCategorize")
    if skip_software:
        cmd.append("-SkipSoftwareInventory")

    # Scale with the size of the sweep rather than a flat 10 minutes: 100 addresses is a
    # perfectly ordinary ask and a fixed ceiling turned it into a failure that threw away
    # everything already found. AD_AGENT_DISCOVERY_TIMEOUT_SEC overrides it outright.
    address_count = 0
    for target in list(cidr) + list(cloudflare_warp_cidr):
        expanded, err = _expand_scan_targets(target)
        address_count += len(expanded) if not err else 1
    timeout_sec = int(os.environ.get("AD_AGENT_DISCOVERY_TIMEOUT_SEC") or 0) or min(
        10800, 600 + 6 * max(0, address_count - 1)
    )

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        raw = result.stdout.strip()
        if not raw:
            return None, result.stderr.strip() or "Discovery produced no output."
        json_start = raw.find("{")
        json_end = raw.rfind("}") + 1
        if json_start == -1:
            return None, f"No JSON in output.\n\nStdout:\n{raw}\n\nStderr:\n{result.stderr}"
        return json.loads(raw[json_start:json_end]), ""
    except subprocess.TimeoutExpired:
        return None, (
            f"Discovery timed out after {timeout_sec / 60:.0f} minute(s) across {address_count} address(es). "
            "Tick “Skip software inventory” for a faster sweep, narrow the range, or raise "
            "AD_AGENT_DISCOVERY_TIMEOUT_SEC on the web app service."
        )
    except json.JSONDecodeError as exc:
        return None, f"Failed to parse discovery output as JSON: {exc}\n\nRaw output:\n{raw[:2000]}"
    except Exception as exc:
        return None, str(exc)


def _mock_result(dcs: list[str]) -> dict:
    """Return synthetic scan data when PowerShell is unavailable (dev/demo mode)."""
    return {
        "ScanTime": datetime.utcnow().isoformat(),
        "Anomalies": [
            {"Type": "FailedLogonBurst_Account", "Account": "jdoe", "ComputerName": dcs[0] if dcs else "dc01",
             "TimeCreated": "2025-06-24T06:14:00", "Detail": "8 failed logons for account jdoe"},
            {"Type": "PrivilegedGroupMembershipChange", "Account": "svc-backup", "ComputerName": dcs[0] if dcs else "dc01",
             "TimeCreated": "2025-06-24T05:30:00", "Detail": "Added to privileged group 'Domain Admins'"},
            {"Type": "UnusualLogonHour", "Account": "asmith", "ComputerName": dcs[0] if dcs else "dc01",
             "TimeCreated": "2025-06-24T03:44:00", "Detail": "Logon at hour 3, outside learned hours: 8,9,10"},
        ],
        "ComplianceGaps": [
            {"ControlId": "PP-001", "Severity": "High", "Title": "Minimum Password Length >= 14 characters",
             "ComputerName": dcs[0] if dcs else "dc01", "Actual": "8", "Expected": "Minimum password length >= 14",
             "Frameworks": {"CIS": "CIS-L1 1.1.1", "NIST": "IA-5(1)(a)", "ISO": "A.9.4.3"},
             "Remediation": "Set via Default Domain Policy: Password Policy > Minimum password length = 14."},
            {"ControlId": "NT-001", "Severity": "Critical", "Title": "SMB Signing Required",
             "ComputerName": dcs[0] if dcs else "dc01", "Actual": "0", "Expected": "RequireSecuritySignature = 1",
             "Frameworks": {"CIS": "CIS-L1 2.3.9.5", "NIST": "SC-8", "ISO": "A.13.2.1"},
             "Remediation": "Enable via GPO: Security Options > Microsoft network client: Digitally sign communications (always) = Enabled."},
            {"ControlId": "PA-001", "Severity": "High", "Title": "Domain Admins Group Has <= 5 Members",
             "ComputerName": dcs[0] if dcs else "dc01", "Actual": "12 members", "Expected": "Domain Admins membership <= 5 accounts",
             "Frameworks": {"CIS": "CIS-L1 2.2", "NIST": "AC-6(5)", "ISO": "A.9.2.3"},
             "Remediation": "Audit Domain Admins; remove accounts that do not require persistent DA rights."},
        ],
        "ComplianceSummary": {
            "TotalControls": 20, "Passed": 17, "Failed": 3, "ScorePct": 85.0,
            "ByDC": [{"DC": dcs[0] if dcs else "dc01", "Total": 20, "Passed": 17, "Failed": 3, "ScorePct": 85.0}],
            "GapsBySeverity": [{"Severity": "Critical", "GapCount": 1}, {"Severity": "High", "GapCount": 2}],
        },
        "ExpiringCertificates": [
            {"Id": "A1B2C3", "Subject": "CN=portal.contoso.com", "Issuer": "CN=Contoso Issuing CA",
             "NotAfter": "2025-07-05T00:00:00", "DaysRemaining": 11, "Severity": "Critical",
             "Sources": "TlsEndpoint", "Locations": "portal.contoso.com [portal.contoso.com:443]",
             "DnsNames": "portal.contoso.com, www.contoso.com", "CollectionErrors": None},
            {"Id": "D4E5F6", "Subject": "CN=dc01.contoso.com", "Issuer": "CN=Contoso Issuing CA",
             "NotAfter": "2025-07-20T00:00:00", "DaysRemaining": 26, "Severity": "High",
             "Sources": "MachineStore, TlsEndpoint", "Locations": "dc01.contoso.com [Cert:\\LocalMachine\\My]; dc01.contoso.com [dc01.contoso.com:636]",
             "DnsNames": "dc01.contoso.com", "CollectionErrors": None},
            {"Id": "G7H8I9", "Subject": "CN=sql01.contoso.com", "Issuer": "CN=Contoso Issuing CA",
             "NotAfter": "2025-08-15T00:00:00", "DaysRemaining": 52, "Severity": "Medium",
             "Sources": "MachineStore", "Locations": "sql01.contoso.com [Cert:\\LocalMachine\\My]",
             "DnsNames": "sql01.contoso.com", "CollectionErrors": None},
        ],
        "ZeroDays": [
            {"CveId": "CVE-2025-21299", "VendorProject": "Microsoft", "Product": "Windows Kerberos",
             "VulnerabilityName": "Windows Kerberos Security Feature Bypass", "DateAdded": "2025-06-22",
             "DueDate": "2025-07-13", "RequiredAction": "Apply mitigations per vendor instructions.",
             "KnownRansomwareCampaignUse": "Known"},
            {"CveId": "CVE-2025-29824", "VendorProject": "Microsoft", "Product": "Windows CLFS Driver",
             "VulnerabilityName": "Windows Common Log File System Elevation of Privilege", "DateAdded": "2025-06-20",
             "DueDate": "2025-07-11", "RequiredAction": "Apply updates per vendor instructions.",
             "KnownRansomwareCampaignUse": "Unknown"},
        ],
        "SoftwareInventory": [
            {"ComputerName": "ws01.contoso.com", "Category": "Laptop", "Name": "Adobe Acrobat Reader DC",
             "Version": "23.001.20143", "Publisher": "Adobe Inc.", "InstallDate": "20250110", "Architecture": "64-bit", "Error": None},
            {"ComputerName": "ws02.contoso.com", "Category": "Desktop", "Name": "7-Zip 22.01",
             "Version": "22.01", "Publisher": "Igor Pavlov", "InstallDate": "20241203", "Architecture": "64-bit", "Error": None},
            {"ComputerName": "sql01.contoso.com", "Category": "Server", "Name": "Microsoft SQL Server 2019",
             "Version": "15.0.4261.1", "Publisher": "Microsoft Corporation", "InstallDate": "20230512", "Architecture": "64-bit", "Error": None},
            {"ComputerName": dcs[0] if dcs else "dc01", "Category": "Domain Controller", "Name": "Google Chrome",
             "Version": "120.0.6099.109", "Publisher": "Google LLC", "InstallDate": "20250601", "Architecture": "64-bit", "Error": None},
        ],
        "VulnerableSoftware": [
            {"ComputerName": "ws01.contoso.com", "Category": "Laptop", "SoftwareName": "Adobe Acrobat Reader DC",
             "SoftwareVersion": "23.001.20143", "CveId": "CVE-2025-21299", "VulnerabilityName": "Windows Kerberos Security Feature Bypass",
             "KnownRansomwareCampaignUse": "Known", "DueDate": "2025-07-13"},
        ],
        "Freshness": {
            "Anomalies": datetime.utcnow().isoformat(),
            "Compliance": datetime.utcnow().isoformat(),
            "Certificates": datetime.utcnow().isoformat(),
            "ZeroDay": datetime.utcnow().isoformat(),
            "SoftwareInventory": datetime.utcnow().isoformat(),
        },
        "_demo": True,
    }


def _load_snapshot() -> tuple[dict, bool]:
    """Return (snapshot_dict, is_demo). Falls back to mock data if no snapshot exists."""
    try:
        if SNAPSHOT_PATH.exists():
            # PowerShell Set-Content -Encoding UTF8 may write a BOM; utf-8-sig handles both.
            with open(SNAPSHOT_PATH, encoding="utf-8-sig") as fh:
                return json.load(fh), False
    except Exception:
        pass
    return _mock_result(["dc01.contoso.com"]), True


def _load_integration_status() -> dict:
    """Status of optional SNMP/vendor-warranty/MDM/Cloudflare integrations.
    Empty/unconfigured defaults if the status file hasn't been generated yet."""
    empty = {"Enabled": False, "Configured": False}
    default = {
        "GeneratedAt": None,
        "Snmp": dict(empty, Version="v2c"),
        "VendorWarranty": dict(empty, ByVendor={"Dell": False, "Hp": False, "Lenovo": False}, AgeAlertYears=4),
        "Mdm": dict(empty, Provider=""),
        "CloudflareZeroTrust": dict(empty),
    }
    try:
        if INTEGRATIONS_STATUS_PATH.exists():
            with open(INTEGRATIONS_STATUS_PATH, encoding="utf-8-sig") as fh:
                data = json.load(fh)
                default.update(data)
                return default
    except Exception:
        pass
    return default


def _load_vendor_warranty_secrets() -> dict:
    """Raw contents of integration-secrets.json's VendorWarranty block (never sent to the
    browser as-is — the form only ever shows masked placeholders for saved keys)."""
    default = {
        "Dell": {"ApiKey": "", "ApiSecret": ""},
        "Hp": {"ApiKey": ""},
        "Lenovo": {"ApiKey": ""},
        "Enabled": False,
        "AgeAlertYears": 4,
    }
    try:
        if INTEGRATION_SECRETS_PATH.exists():
            with open(INTEGRATION_SECRETS_PATH, encoding="utf-8-sig") as fh:
                data = json.load(fh)
                saved = data.get("VendorWarranty", {})
                default["Dell"].update(saved.get("Dell", {}))
                default["Hp"].update(saved.get("Hp", {}))
                default["Lenovo"].update(saved.get("Lenovo", {}))
                if "Enabled" in saved:
                    default["Enabled"] = saved["Enabled"]
                if "AgeAlertYears" in saved:
                    default["AgeAlertYears"] = saved["AgeAlertYears"]
    except Exception:
        pass
    return default


def _save_vendor_warranty_secrets(update: dict) -> None:
    """Merge `update` into integration-secrets.json's VendorWarranty block, preserving any
    other top-level sections the file may gain later and any field left blank in the form
    (blank means "keep what's already saved", not "clear it")."""
    data = {}
    if INTEGRATION_SECRETS_PATH.exists():
        try:
            with open(INTEGRATION_SECRETS_PATH, encoding="utf-8-sig") as fh:
                data = json.load(fh)
        except Exception:
            data = {}
    current = data.get("VendorWarranty", {})
    for section in ("Dell", "Hp", "Lenovo"):
        if section in update:
            merged = dict(current.get(section, {}))
            merged.update({k: v for k, v in update[section].items() if v})  # blank = keep existing
            current[section] = merged
    if "Enabled" in update:
        current["Enabled"] = update["Enabled"]
    if "AgeAlertYears" in update:
        current["AgeAlertYears"] = update["AgeAlertYears"]
    data["VendorWarranty"] = current
    INTEGRATION_SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(INTEGRATION_SECRETS_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


_last_synced_mtime: float | None = None  # module-level: avoids re-syncing an unchanged
# snapshot on every page view. Matters for manual deletes (below): if a deleted asset is
# still present in the CURRENT snapshot, re-running that same sync would just re-insert
# it right back. Only syncing when the file's mtime actually advances means a delete
# sticks until the next real scan runs - at which point, if the host is genuinely still
# alive, it reappearing is correct (that's a fresh discovery, not the old delete undone).


def _load_discovery_inventory() -> tuple[list, str | None]:
    """Return (assets, last_scan_iso) from the asset store (assets_db.py - SQLite or
    Postgres), syncing in whatever the latest Run-Discovery.ps1 JSON snapshot has first
    (only if it's changed since the last sync). Empty list if no discovery scan has ever
    run and the store has nothing yet."""
    global _last_synced_mtime
    last_scan = None
    try:
        if DISCOVERY_INVENTORY_PATH.exists():
            mtime = DISCOVERY_INVENTORY_PATH.stat().st_mtime
            last_scan = datetime.utcfromtimestamp(mtime).isoformat()
            if mtime != _last_synced_mtime:
                with open(DISCOVERY_INVENTORY_PATH, encoding="utf-8-sig") as fh:
                    raw = json.load(fh)
                    if isinstance(raw, dict):
                        raw = [raw]
                    assets_db.sync_assets(STATE_DIR, raw)
                _last_synced_mtime = mtime
    except Exception:
        pass

    try:
        return assets_db.load_all_assets(STATE_DIR), last_scan
    except Exception:
        return [], last_scan


def _delete_asset(dedup_key: str) -> bool:
    """Manually remove one asset from the inventory (e.g. a decommissioned device or a
    stray duplicate). Returns True if a row was actually deleted."""
    return assets_db.delete_asset(STATE_DIR, dedup_key)


ONLINE_THRESHOLD_MINUTES = 20


def _is_online(last_seen_iso: str | None) -> bool:
    """A host counts as online if it answered a probe within the last 20 minutes."""
    if not last_seen_iso:
        return False
    try:
        seen = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        now = datetime.now(seen.tzinfo) if seen.tzinfo else datetime.utcnow()
        return (now - seen).total_seconds() <= ONLINE_THRESHOLD_MINUTES * 60
    except Exception:
        return False


CERT_THRESHOLD_DAYS = 90   # mirrors Certificates.ThresholdDays in settings.psd1
STALE_THRESHOLD_DAYS = 14  # e.g. a laptop out on leave for 2-3 weeks
PRESENCE_WINDOW_DAYS = 30  # window for the Endpoints page's office/remote day counts


def _time_ago(last_seen_iso: str | None) -> str:
    """Human-readable age since LastSeen - 'never seen', '3h ago', '23d ago', etc.
    Distinct from _is_online: a device can be offline right now but seen recently
    (last night), or offline and stale (genuinely absent from the network for a while,
    e.g. someone on leave with their laptop off/at home)."""
    if not last_seen_iso:
        return "never seen"
    try:
        seen = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        now = datetime.now(seen.tzinfo) if seen.tzinfo else datetime.utcnow()
        delta = now - seen
        secs = delta.total_seconds()
        if secs < 0:
            return "just now"
        if secs < 3600:
            return f"{int(secs // 60)}m ago"
        if secs < 86400:
            return f"{int(secs // 3600)}h ago"
        return f"{int(secs // 86400)}d ago"
    except Exception:
        return "unknown"


def _is_stale(last_seen_iso: str | None) -> bool:
    """True when a device hasn't been seen in STALE_THRESHOLD_DAYS+ (or never)."""
    if not last_seen_iso:
        return True
    try:
        seen = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        now = datetime.now(seen.tzinfo) if seen.tzinfo else datetime.utcnow()
        return (now - seen).days >= STALE_THRESHOLD_DAYS
    except Exception:
        return True


def _sev_counts(items: list, key: str = "Severity") -> dict:
    out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for it in items:
        s = it.get(key, "Low")
        if s in out:
            out[s] += 1
    return out


def _dashboard_payload() -> dict:
    """Compute render-ready aggregates for the rotating dashboard from the snapshot."""
    data, demo = _load_snapshot()

    anomalies = data.get("Anomalies") or []
    gaps      = data.get("ComplianceGaps") or []
    summary   = data.get("ComplianceSummary") or {}
    certs     = [c for c in (data.get("ExpiringCertificates") or [])
                 if c.get("DaysRemaining") is not None]
    zerodays  = data.get("ZeroDays") or []
    software  = [s for s in (data.get("SoftwareInventory") or []) if not s.get("Error")]
    vuln_sw   = data.get("VulnerableSoftware") or []
    freshness = data.get("Freshness") or {}

    gap_sev  = _sev_counts(gaps)
    cert_sev = _sev_counts(certs)

    # Anomaly severity: use Severity when present, else treat as High.
    an_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in anomalies:
        s = a.get("Severity") if a.get("Severity") in an_sev else "High"
        an_sev[s] += 1

    # Zero-day severity: ransomware-linked = Critical, otherwise High.
    zd_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for z in zerodays:
        if str(z.get("KnownRansomwareCampaignUse", "")).lower() == "known":
            zd_sev["Critical"] += 1
        else:
            zd_sev["High"] += 1

    total_sev = {k: gap_sev[k] + cert_sev[k] + an_sev[k] + zd_sev[k] for k in gap_sev}
    score = summary.get("ScorePct")

    posture = "good"
    if total_sev["Critical"] > 0 or len(vuln_sw) > 0:
        posture = "critical"
    elif total_sev["High"] > 0 or (score is not None and score < 80):
        posture = "warn"

    # Anomalies grouped by type.
    an_types: dict = {}
    for a in anomalies:
        t = a.get("Type", "Unknown")
        an_types[t] = an_types.get(t, 0) + 1
    an_types_sorted = sorted(an_types.items(), key=lambda kv: -kv[1])

    def _csort(c):
        return (SEV_RANK.get(c.get("Severity", "Low"), 9), c.get("DaysRemaining", 9999))

    certs_sorted = sorted(certs, key=_csort)
    certs_under_30 = [c for c in certs if isinstance(c.get("DaysRemaining"), (int, float))
                      and c.get("DaysRemaining") < 30]
    gaps_sorted = sorted(gaps, key=lambda g: (SEV_RANK.get(g.get("Severity", "Low"), 9),
                                              g.get("ControlId", "")))

    # Software inventory aggregates.
    sw_hosts = {s.get("ComputerName") for s in software if s.get("ComputerName")}
    sw_by_category: dict = {}
    seen_host_category = set()
    for s in software:
        host, cat = s.get("ComputerName"), s.get("Category", "Unknown")
        key = (host, cat)
        if host and key not in seen_host_category:
            seen_host_category.add(key)
            sw_by_category[cat] = sw_by_category.get(cat, 0) + 1
    sw_products: dict = {}
    for s in software:
        name = s.get("Name")
        if name:
            sw_products[name] = sw_products.get(name, 0) + 1
    sw_top_products = sorted(sw_products.items(), key=lambda kv: -kv[1])[:8]

    # Discovery inventory (accumulated by Run-Discovery.ps1, independent of the scan snapshot).
    assets, disc_last_scan = _load_discovery_inventory()
    by_type: dict = {}
    for a in assets:
        t = a.get("AssetType", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1
    disc_by_type = sorted(by_type.items(), key=lambda kv: -kv[1])
    sources: dict = {}
    for a in assets:
        s = a.get("Source", "Unknown")
        sources[s] = sources.get(s, 0) + 1

    return {
        "demo": demo,
        "generated": datetime.utcnow().isoformat(),
        "freshness": freshness,
        "kpi": {
            "anomalies": len(anomalies),
            "compliance_score": score,
            "compliance_passed": summary.get("Passed", 0),
            "compliance_total": summary.get("TotalControls", 0),
            "zerodays": len(zerodays),
            "certs": len(certs),
            "certs_urgent": len(certs_under_30),
            "software_hosts": len(sw_hosts),
            "software_vulnerable": len(vuln_sw),
        },
        "posture": posture,
        "severity_totals": total_sev,
        "compliance": {
            "summary": summary,
            "gaps_by_severity": gap_sev,
            "top_gaps": gaps_sorted[:6],
            "by_dc": summary.get("ByDC", []),
        },
        "threats": {
            "anomaly_types": an_types_sorted[:6],
            "recent_anomalies": anomalies[:7],
            "zerodays": zerodays[:6],
        },
        "certificates": {
            "by_severity": cert_sev,
            "soonest": certs_sorted[:8],
            "urgent_count": len(certs_under_30),
        },
        "software": {
            "host_count": len(sw_hosts),
            "by_category": sw_by_category,
            "top_products": sw_top_products,
            "vulnerable": vuln_sw[:8],
            "vulnerable_count": len(vuln_sw),
        },
        "discovery": {
            "total": len(assets),
            "online": len([a for a in assets if _is_online(a.get("LastSeen"))]),
            "by_type": disc_by_type,
            "by_source": sorted(sources.items(), key=lambda kv: -kv[1]),
            "last_scan": disc_last_scan,
            # Software omitted here (fetched on demand via /api/discovery/asset/<name>)
            # to keep the polled dashboard payload small.
            "assets": [
                {k: v for k, v in a.items() if k != "Software"}
                for a in sorted(assets, key=lambda a: (a.get("AssetType", ""), a.get("Name", "")))[:40]
            ],
        },
    }


def _healthz_checks() -> dict:
    """Cheap, dependency-free self-checks a watchdog can poll without shelling
    out to PowerShell. Each check reports ok/warn/fail independently so a
    watchdog (or you, reading /healthz by hand) can tell exactly what's wrong
    rather than getting a single opaque up/down bit."""
    checks = {}

    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        probe = STATE_DIR / ".healthz-write-probe"
        probe.write_text(datetime.utcnow().isoformat())
        probe.unlink()
        checks["state_dir_writable"] = {"status": "ok"}
    except OSError as exc:
        checks["state_dir_writable"] = {"status": "fail", "detail": str(exc)}

    try:
        assets_db.check_health(STATE_DIR)
        checks["assets_db"] = {"status": "ok", "detail": assets_db.BACKEND}
    except Exception as exc:
        checks["assets_db"] = {"status": "fail", "detail": str(exc)}

    ps = _detect_powershell()
    checks["powershell"] = (
        {"status": "ok", "detail": ps} if ps else {"status": "fail", "detail": "neither pwsh nor powershell found on PATH"}
    )

    try:
        free_gb = os.statvfs(STATE_DIR).f_bavail * os.statvfs(STATE_DIR).f_frsize / (1024 ** 3) \
            if hasattr(os, "statvfs") else None
    except OSError:
        free_gb = None
    if free_gb is None:
        import shutil
        try:
            free_gb = shutil.disk_usage(STATE_DIR).free / (1024 ** 3)
        except OSError:
            free_gb = None
    if free_gb is None:
        checks["disk_space"] = {"status": "warn", "detail": "could not determine free space"}
    elif free_gb < 1:
        checks["disk_space"] = {"status": "fail", "detail": f"{free_gb:.2f} GB free"}
    elif free_gb < 5:
        checks["disk_space"] = {"status": "warn", "detail": f"{free_gb:.2f} GB free"}
    else:
        checks["disk_space"] = {"status": "ok", "detail": f"{free_gb:.2f} GB free"}

    def _age_hours(path: Path) -> float | None:
        try:
            return (datetime.utcnow().timestamp() - path.stat().st_mtime) / 3600
        except OSError:
            return None

    scan_age = _age_hours(SNAPSHOT_PATH)
    if scan_age is None:
        checks["last_scan"] = {"status": "warn", "detail": "no scan has run yet"}
    elif scan_age > 48:
        checks["last_scan"] = {"status": "warn", "detail": f"{scan_age:.1f}h since last scan"}
    else:
        checks["last_scan"] = {"status": "ok", "detail": f"{scan_age:.1f}h since last scan"}

    disc_age = _age_hours(DISCOVERY_INVENTORY_PATH)
    if disc_age is None:
        checks["last_discovery"] = {"status": "warn", "detail": "no discovery run has happened yet"}
    elif disc_age > 48:
        checks["last_discovery"] = {"status": "warn", "detail": f"{disc_age:.1f}h since last discovery"}
    else:
        checks["last_discovery"] = {"status": "ok", "detail": f"{disc_age:.1f}h since last discovery"}

    return checks


@app.route("/healthz")
def healthz():
    """Machine-readable liveness/readiness endpoint for a watchdog (see
    DCAnomalyAgent/Install/Watch-WebUIHealth.ps1) or any external monitor to
    poll. 200 = healthy or degraded-but-serving; 503 = a hard failure a
    watchdog should act on (restart the service). This intentionally never
    shells out to PowerShell itself, so it stays fast and reliable even if a
    PowerShell invocation elsewhere is hung."""
    checks = _healthz_checks()
    statuses = [c["status"] for c in checks.values()]
    if "fail" in statuses:
        overall = "fail"
    elif "warn" in statuses:
        overall = "warn"
    else:
        overall = "ok"
    body = {
        "status": overall,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": checks,
    }
    return jsonify(body), (503 if overall == "fail" else 200)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Full-screen rotating operations dashboard (for a NOC/wall display)."""
    return render_template("dashboard.html")


@app.route("/api/dashboard")
def api_dashboard():
    """JSON aggregates powering the rotating dashboard; polled periodically by the page."""
    return jsonify(_dashboard_payload())


def _prometheus_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _prom_metric(lines: list, name: str, mtype: str, help_text: str, samples: list) -> None:
    """Appends one metric family (HELP/TYPE header + samples) in Prometheus text
    exposition format. samples is a list of (labels_dict, value) tuples."""
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} {mtype}")
    for labels, value in samples:
        if labels:
            label_str = ",".join(f'{k}="{_prometheus_escape(v)}"' for k, v in labels.items())
            lines.append(f"{name}{{{label_str}}} {value}")
        else:
            lines.append(f"{name} {value}")


@app.route("/metrics")
def metrics():
    """Prometheus exposition-format endpoint - the AD-specific "checks" Prometheus itself
    has no notion of (compliance gaps, AD anomalies, cert expiry, KEV exposure, discovery
    freshness) turned into scrapeable time series. Point a Prometheus scrape config at this
    URL and the accompanying grafana/ad-agent-dashboard.json for ready-made panels/alerts -
    see /prometheus-comparison for the full writeup of why this exists alongside, not
    instead of, this app's own dashboard.

    Unauthenticated today, same as every other route - once Register-IISReverseProxy.ps1
    (Phase 5) is deployed, either put this behind it too or scope a separate unauthenticated
    path for just this route in the IIS config, since Prometheus scrapers don't do
    interactive Windows Authentication. A shared-secret query param or IP allowlist in IIS
    for the Prometheus server's own IP is the usual compromise."""
    payload = _dashboard_payload()
    lines: list = []

    _prom_metric(lines, "adagent_up", "gauge",
                 "Whether the AD-Agent web UI is up and this scrape succeeded (always 1 if reached).",
                 [({}, 1)])
    _prom_metric(lines, "adagent_demo_mode", "gauge",
                 "1 if the last scan snapshot is demo/mock data (no PowerShell available), 0 for a real scan.",
                 [({}, 1 if payload["demo"] else 0)])

    # Note: these are point-in-time snapshots re-evaluated from the last scan on every
    # scrape, not monotonically increasing counters - so per Prometheus naming convention
    # (https://prometheus.io/docs/practices/naming/) they're gauges without a "_total"
    # suffix, even though "total X findings" is how a human would phrase them. promtool
    # check metrics was run against this endpoint's actual output to confirm.
    kpi = payload["kpi"]
    _prom_metric(lines, "adagent_anomalies", "gauge", "AD anomalies found in the last scan.",
                 [({}, kpi["anomalies"])])
    _prom_metric(lines, "adagent_compliance_score_percent", "gauge",
                 "Overall compliance score (0-100) from the last scan.", [({}, kpi["compliance_score"])])
    _prom_metric(lines, "adagent_compliance_controls_passed", "gauge",
                 "Compliance controls passed in the last scan.", [({}, kpi["compliance_passed"])])
    _prom_metric(lines, "adagent_compliance_controls", "gauge",
                 "Compliance controls evaluated in the last scan.", [({}, kpi["compliance_total"])])
    _prom_metric(lines, "adagent_zerodays", "gauge",
                 "CISA KEV / zero-day matches against installed software.", [({}, kpi["zerodays"])])
    _prom_metric(lines, "adagent_certificates_expiring", "gauge",
                 "Certificates approaching expiry.", [({}, kpi["certs"])])
    _prom_metric(lines, "adagent_certificates_urgent", "gauge",
                 "Certificates expiring within 30 days.", [({}, kpi["certs_urgent"])])
    _prom_metric(lines, "adagent_software_hosts", "gauge",
                 "Hosts with software inventory collected.", [({}, kpi["software_hosts"])])
    _prom_metric(lines, "adagent_software_vulnerable", "gauge",
                 "Installed software matches against known-vulnerable versions.", [({}, kpi["software_vulnerable"])])

    _prom_metric(lines, "adagent_findings_by_severity", "gauge",
                 "Combined anomaly+compliance+cert+zero-day findings by severity.",
                 [({"severity": sev}, count) for sev, count in payload["severity_totals"].items()])
    _prom_metric(lines, "adagent_compliance_gaps_by_severity", "gauge",
                 "Compliance gaps by severity.",
                 [({"severity": sev}, count) for sev, count in payload["compliance"]["gaps_by_severity"].items()])
    _prom_metric(lines, "adagent_certificates_by_severity", "gauge",
                 "Expiring certificates by severity.",
                 [({"severity": sev}, count) for sev, count in payload["certificates"]["by_severity"].items()])

    disc = payload["discovery"]
    _prom_metric(lines, "adagent_discovery_assets", "gauge",
                 "Discovered assets by type.",
                 [({"asset_type": t}, count) for t, count in disc["by_type"]])
    _prom_metric(lines, "adagent_discovery_assets_online", "gauge",
                 "Discovered assets currently online (seen within the online threshold).",
                 [({}, disc["online"])])
    _prom_metric(lines, "adagent_discovery_assets_by_source", "gauge",
                 "Discovered assets by discovery source (AD, NetworkScan, Cloudflare WARP, ...).",
                 [({"source": s}, count) for s, count in disc["by_source"]])
    if disc["last_scan"]:
        try:
            ts = datetime.fromisoformat(disc["last_scan"]).timestamp()
            _prom_metric(lines, "adagent_discovery_last_scan_timestamp_seconds", "gauge",
                         "Unix timestamp of the last Discovery run - alert on this going stale rather than polling the UI.",
                         [({}, ts)])
        except ValueError:
            pass

    # Surfaces the exact same self-checks /healthz reports, as a 1/0 gauge per check -
    # lets a Prometheus alert rule fire on "adagent_health_check == 0" instead of parsing
    # JSON, and gives you the healthz history for free via Prometheus's own retention.
    health_checks = _healthz_checks()
    _prom_metric(lines, "adagent_health_check", "gauge",
                 "Per-check health status (1 = ok, 0.5 = warn, 0 = fail) - see /healthz for detail text.",
                 [({"check": name}, {"ok": 1, "warn": 0.5, "fail": 0}[c["status"]])
                  for name, c in health_checks.items()])

    body = "\n".join(lines) + "\n"
    return Response(body, content_type="text/plain; version=0.0.4; charset=utf-8")


def _corporate_networks() -> list:
    """Corporate CIDRs from the CORPORATE_NETWORKS environment variable, e.g.
    '172.29.0.0/16,10.44.0.0/16'. Set it alongside COLLECTOR_TOKEN on the server.

    An env var rather than settings.psd1 because that's a PowerShell data file this
    app can't parse - same reason ASSETS_DATABASE_URL and COLLECTOR_TOKEN live in the
    environment. Unset means every check-in is classified 'Unknown', which is honest:
    without knowing your ranges we cannot tell an office IP from a home one."""
    raw = os.environ.get("CORPORATE_NETWORKS", "")
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            app.logger.warning("Ignoring invalid CIDR in CORPORATE_NETWORKS: %r", part)
    return nets


def _classify_location(reported_ip: str | None, observed_ip: str | None) -> str:
    """Office vs Remote for one check-in.

    Laptops here go home every night and check in from both places, so a single
    "last seen" would keep flip-flopping and tell you nothing. Classifying each
    check-in lets both facts be kept side by side.

    Two IPs are available and they answer different questions: the DEVICE-REPORTED
    address is the laptop's own adapter (what it thinks it is), while the OBSERVED
    address is the socket this request actually arrived from. A laptop at home on
    WARP tunnels into the corporate network, so the observed address can look
    internal while the device is physically at a kitchen table - which is why the
    device-reported address is trusted first and the observed one is only a
    fallback. Neither is spoof-proof; this is inventory context, not a security
    control, and it is not used for any access decision."""
    nets = _corporate_networks()
    if not nets:
        return "Unknown"
    for candidate in (reported_ip, observed_ip):
        if not candidate:
            continue
        try:
            addr = ipaddress.ip_address(str(candidate).strip())
        except ValueError:
            continue
        if any(addr in n for n in nets):
            return "Office"
        return "Remote"   # first parseable address decides; don't fall through
    return "Unknown"


@app.route("/api/collector/checkin", methods=["POST"])
def collector_checkin():
    """Receives a push-collector check-in from an endpoint (see
    DCAnomalyAgent/Collector/Send-InventoryCheckin.ps1).

    Auth is a shared secret in X-Collector-Token, compared with hmac.compare_digest
    so a wrong token can't be recovered by timing the response. The token lives in
    the COLLECTOR_TOKEN environment variable; if it isn't set, this endpoint refuses
    every request rather than accepting unauthenticated writes - the feature is off
    until someone deliberately turns it on.

    Note this is a WRITE endpoint reachable from every endpoint VLAN, which is a
    wider exposure than the rest of the app: a leaked token lets someone submit
    bogus inventory (it cannot read anything back, and the payload only ever reaches
    the assets table via parameterized SQL). Treat the token as a real secret,
    deploy it via GPO Preferences rather than pasting it into a shared script, and
    rotate it by changing COLLECTOR_TOKEN plus the GPO value together."""
    expected = os.environ.get("COLLECTOR_TOKEN", "")
    if not expected:
        return jsonify({
            "error": "collector endpoint disabled",
            "detail": "Set the COLLECTOR_TOKEN environment variable on the AD-Agent "
                      "server to enable push check-ins.",
        }), 503

    presented = request.headers.get("X-Collector-Token", "")
    if not hmac.compare_digest(presented, expected):
        _audit("collector_checkin_denied", f"remote_addr={request.remote_addr}")
        return jsonify({"error": "unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "expected a JSON object body"}), 400

    # Sync-CloudflareDevices.ps1 posts through this same endpoint so there's one
    # tested write path, and labels its rows CloudflareWARP. Whitelisted rather than
    # free-text: an endpoint could otherwise write an arbitrary string into the
    # source column. Worst case even so is a mislabelled row - no privilege gain -
    # but a fixed set keeps the Endpoints page's grouping meaningful.
    source = payload.get("CheckinSource")
    if source not in ("PushCollector", "CloudflareWARP"):
        source = "PushCollector"

    location = _classify_location(payload.get("IP"), request.remote_addr)

    try:
        key = assets_db.record_checkin(
            STATE_DIR, payload, checkin_source=source, location=location,
            corp_dns_suffix=os.environ.get("CORPORATE_DNS_SUFFIX", ""),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001 - never leak a stack trace to an endpoint
        app.logger.exception("collector check-in failed")
        return jsonify({"error": "failed to record check-in", "detail": str(exc)}), 500

    sw = payload.get("Software")
    _audit("collector_checkin", f"key={key} ip={payload.get('IP')} loc={location} software={len(sw) if sw else 0}")
    return jsonify({"status": "ok", "dedup_key": key}), 200


@app.route("/api/discovery/asset/<path:name>")
def api_discovery_asset(name: str):
    """Full detail (incl. installed software) for one discovered device, read fresh
    from asset-inventory.json — the dashboard payload only carries a trimmed list."""
    assets, _ = _load_discovery_inventory()
    match = next((a for a in assets if str(a.get("Name", "")).lower() == name.lower()), None)
    if not match:
        return jsonify({"error": "not found"}), 404
    return jsonify(match)


@app.route("/integrations")
def integrations():
    """Status + setup requirements for optional SNMP/vendor-warranty/MDM/Cloudflare
    integrations that extend discovery beyond what agentless WinRM/TCP scanning sees."""
    return render_template("integrations.html", status=_load_integration_status())


@app.route("/integrations/refresh", methods=["POST"])
def integrations_refresh():
    """Re-run Get-IntegrationStatus.ps1 to pick up config changes, then redisplay."""
    pwsh = _detect_powershell()
    error = None
    if pwsh:
        try:
            subprocess.run(
                [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(INTEGRATIONS_SCRIPT),
                 "-ConfigPath", str(SETTINGS_PATH)],
                capture_output=True, text=True, timeout=30,
            )
        except Exception as exc:
            error = str(exc)
    else:
        error = "PowerShell (pwsh/powershell) not found on PATH."
    return render_template("integrations.html", status=_load_integration_status(), error=error)


@app.route("/integrations/vendor-warranty", methods=["GET", "POST"])
def vendor_warranty_settings():
    """Enter/save Dell/HP/Lenovo warranty API keys for later use, once each team hands
    them over — keys are written to integration-secrets.json (gitignored), never to
    settings.psd1 or the page itself (saved keys show as masked, not in plaintext)."""
    saved_msg = None
    if request.method == "POST":
        update = {
            "Dell": {
                "ApiKey": request.form.get("dell_api_key", "").strip(),
                "ApiSecret": request.form.get("dell_api_secret", "").strip(),
            },
            "Hp": {"ApiKey": request.form.get("hp_api_key", "").strip()},
            "Lenovo": {"ApiKey": request.form.get("lenovo_api_key", "").strip()},
            "Enabled": "enabled" in request.form,
        }
        try:
            update["AgeAlertYears"] = int(request.form.get("age_alert_years", "4"))
        except ValueError:
            update["AgeAlertYears"] = 4
        _save_vendor_warranty_secrets(update)
        saved_msg = "Saved. Keys left blank above were kept as previously saved (not cleared)."

    secrets = _load_vendor_warranty_secrets()
    masked = {
        "dell_api_key": bool(secrets["Dell"].get("ApiKey")),
        "dell_api_secret": bool(secrets["Dell"].get("ApiSecret")),
        "hp_api_key": bool(secrets["Hp"].get("ApiKey")),
        "lenovo_api_key": bool(secrets["Lenovo"].get("ApiKey")),
    }
    return render_template(
        "vendor_warranty.html",
        masked=masked,
        enabled=secrets["Enabled"],
        age_alert_years=secrets["AgeAlertYears"],
        saved_msg=saved_msg,
    )


@app.route("/winrm-test", methods=["GET", "POST"])
def winrm_test():
    """Run the same TCP/WSMan/Invoke-Command checks used to hand-diagnose WinRM issues
    (why a device has no software collected, etc.) from the browser instead of RDP+CLI."""
    results = None
    error = None
    hosts_input = ""

    if request.method == "POST":
        hosts_input = request.form.get("hosts", "").strip()
        hosts = [h.strip() for h in hosts_input.replace("\n", ",").split(",") if h.strip()]

        pwsh = _detect_powershell()
        if not pwsh:
            error = "PowerShell (pwsh/powershell) not found on PATH."
        else:
            cmd = [pwsh, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(WINRM_TEST_SCRIPT),
                   "-ConfigPath", str(SETTINGS_PATH), "-JsonOutput"]
            if hosts:
                cmd += ["-ComputerName", ",".join(hosts)]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                raw = proc.stdout.strip()
                if not raw:
                    error = proc.stderr.strip() or "No output from Test-WinRM.ps1."
                else:
                    json_start = raw.find("{") if raw.lstrip().startswith("{") else raw.find("[")
                    json_end = raw.rfind("}") + 1 if raw.lstrip().startswith("{") else raw.rfind("]") + 1
                    if json_start == -1:
                        error = f"No JSON in output.\n\nStdout:\n{raw}\n\nStderr:\n{proc.stderr}"
                    else:
                        parsed = json.loads(raw[json_start:json_end])
                        results = parsed if isinstance(parsed, list) else [parsed]
            except subprocess.TimeoutExpired:
                error = "WinRM test timed out (>2 minutes) — try fewer hosts at once."
            except json.JSONDecodeError as exc:
                error = f"Failed to parse output as JSON: {exc}\n\nRaw output:\n{raw[:2000]}"
            except Exception as exc:
                error = str(exc)

    return render_template("winrm_test.html", results=results, error=error, hosts_input=hosts_input)


# ── PDQ Inventory feature comparison ─────────────────────────────────────────
# Hand-maintained checklist, updated as features land. Status: "covered" | "partial" | "gap".
# This is intentionally scoped to PDQ Inventory's own feature set (discovery/hardware/
# software inventory) - compliance/anomaly/zero-day/certs are a separate "beyond PDQ"
# section since PDQ Inventory doesn't do security/compliance scanning at all.
PDQ_COMPARISON = [
    {"category": "Discovery & Scanning", "features": [
        {"feature": "Agentless scanning (no client install)", "status": "covered", "note": "WinRM, same agentless model as PDQ's WMI approach"},
        {"feature": "Active Directory discovery", "status": "covered", "note": "Run-Discovery.ps1 -FromAD"},
        {"feature": "Network / IP range (CIDR) scanning", "status": "covered", "note": "Mixed prefix sizes, /16-/32, single-IP too"},
        {"feature": "Scheduled recurring scans", "status": "covered", "note": "Windows Scheduled Tasks under the gMSA"},
        {"feature": "Remote/VPN device discovery", "status": "covered", "note": "Cloudflare WARP range scanning - PDQ has no equivalent out of the box"},
        {"feature": "CSV / manual host list import", "status": "gap", "note": None},
        {"feature": "Duplicate device detection & merge", "status": "gap", "note": None},
    ]},
    {"category": "Hardware Inventory", "features": [
        {"feature": "CPU / RAM / disk specs", "status": "gap", "note": "Next up"},
        {"feature": "BIOS / serial number / manufacturer / model", "status": "gap", "note": "Next up - feeds device age below"},
        {"feature": "Device age via warranty lookup", "status": "partial", "note": "Dell/HP/Lenovo API module built (Get-DeviceAge); not yet wired to a hardware collection pass or live-tested against real keys"},
        {"feature": "Monitor / peripheral inventory", "status": "gap", "note": "Not scannable for most peripherals - see Integrations page"},
        {"feature": "Network adapter / MAC inventory", "status": "gap", "note": None},
    ]},
    {"category": "Software Inventory", "features": [
        {"feature": "Installed software list per device", "status": "covered", "note": None},
        {"feature": "Version / publisher / install date", "status": "covered", "note": None},
        {"feature": "Fleet-wide software search", "status": "covered", "note": "Software List page"},
        {"feature": "License / install-count metering", "status": "gap", "note": None},
        {"feature": "Software change history over time", "status": "gap", "note": None},
    ]},
    {"category": "Categorization & Grouping", "features": [
        {"feature": "Device type categorization", "status": "covered", "note": "Desktop / Laptop / Server / Domain Controller via chassis probe"},
        {"feature": "Dynamic/smart groups (saved filters)", "status": "gap", "note": None},
        {"feature": "Manual tagging", "status": "gap", "note": None},
        {"feature": "OU-based grouping", "status": "partial", "note": "AD discovery works; no OU-specific grouping UI yet"},
    ]},
    {"category": "Status & Diagnostics", "features": [
        {"feature": "Online/offline & last-seen status", "status": "covered", "note": None},
        {"feature": "Connectivity/agent test tooling", "status": "covered", "note": "WinRM Test page - TCP/WSMan/Invoke-Command, per host"},
        {"feature": "Collection-failure diagnostics", "status": "covered", "note": "CollectionNote + discovery.log - PDQ's own troubleshooting is less transparent here"},
    ]},
    {"category": "Reporting & Dashboards", "features": [
        {"feature": "Central web dashboard", "status": "covered", "note": None},
        {"feature": "Per-device drill-down", "status": "covered", "note": None},
        {"feature": "CSV / PDF export", "status": "covered", "note": None},
        {"feature": "Custom report builder", "status": "gap", "note": None},
    ]},
    {"category": "Alerting & Automation", "features": [
        {"feature": "Email/Teams alerts on findings", "status": "covered", "note": None},
        {"feature": "Alert on risky software detected", "status": "covered", "note": "Zero-day/KEV cross-reference - PDQ has no equivalent"},
        {"feature": "Scriptable custom scanners", "status": "partial", "note": "Compliance-control framework is analogous but not a generic ad-hoc scanner UI"},
        {"feature": "Patch/software deployment", "status": "gap", "note": "Out of scope by design - detection tool, not a deployment tool (that's PDQ Deploy's job, not PDQ Inventory's)"},
    ]},
]

PDQ_EXCLUSIVES = [
    "CIS / NIST / ISO 27001 / HIPAA / OWASP compliance scanning",
    "AD security anomaly detection (UEBA-lite, privileged group changes, GPO drift)",
    "Certificate expiry monitoring (stores, TLS endpoints, Enterprise CA)",
    "CISA KEV / NVD zero-day exposure cross-referenced against installed software",
]


# ── Prometheus + Grafana comparison ──────────────────────────────────────────
# Different category than PDQ (generic metrics/dashboard platform vs. a purpose-built AD
# scanner), so this isn't a straight feature-parity checklist - it's "what does AD-Agent
# need Prometheus+Grafana for, and what does Prometheus+Grafana need AD-Agent for."
# "covered" here includes native AND covered-via-the-/metrics-integration - both are things
# you can actually do today, just through different UIs.
PROMETHEUS_COMPARISON = [
    {"category": "Metrics Collection & Time-Series", "features": [
        {"feature": "Point-in-time scan results", "status": "covered", "note": "Native - every scan snapshot"},
        {"feature": "Long-term metric history/retention", "status": "covered", "note": "Via /metrics - Prometheus's own TSDB retains scrape history AD-Agent doesn't store itself"},
        {"feature": "Ad-hoc querying across metrics (PromQL)", "status": "covered", "note": "Via /metrics - not something AD-Agent needs to build; Prometheus already does this well"},
        {"feature": "Correlating AD findings with infra metrics (CPU/disk/network)", "status": "partial", "note": "Possible if you also run node_exporter alongside and join in Grafana - AD-Agent itself doesn't collect infra metrics, by design"},
    ]},
    {"category": "Dashboards & Visualization", "features": [
        {"feature": "Prebuilt security posture dashboard", "status": "covered", "note": "Native rotating dashboard, no setup required"},
        {"feature": "Fully customizable drag-and-drop dashboards", "status": "covered", "note": "Via grafana/ad-agent-dashboard.json - Grafana's panel editor is far more flexible than anything worth building natively here"},
        {"feature": "Historical trend graphs (compliance score over months)", "status": "covered", "note": "Via /metrics + Grafana - AD-Agent's own dashboard only shows current state"},
        {"feature": "Per-device drill-down", "status": "covered", "note": "Native only - Prometheus metrics here are fleet-level aggregates, not built for per-device browsing"},
    ]},
    {"category": "Alerting", "features": [
        {"feature": "Email/Teams alerts on scan findings", "status": "covered", "note": "Native"},
        {"feature": "Flexible routing (PagerDuty, Slack, on-call schedules, dedup/silence)", "status": "covered", "note": "Via grafana/ad-agent-alerts.yml + Alertmanager - not something worth re-building when Alertmanager already does it well"},
        {"feature": "Alert on AD-Agent's own health (process down, hung, disk full)", "status": "covered", "note": "Native via the watchdog (Phase 1) AND via /metrics' adagent_health_check + the ADAgentHealthCheckFailing/ADAgentScrapeDown rules - belt and braces"},
    ]},
    {"category": "Deployment & Operations", "features": [
        {"feature": "Self-healing (auto-restart on crash/hang)", "status": "covered", "note": "Native - Watch-WebUIHealth.ps1 (Phase 1); Prometheus/Grafana have no equivalent built in either"},
        {"feature": "Zero-config single-binary/agent-based metrics", "status": "gap", "note": "Prometheus's exporter ecosystem (node_exporter, windows_exporter, etc.) is far more mature for generic infra metrics than anything AD-Agent should try to replicate"},
    ]},
]

PROMETHEUS_EXCLUSIVES = [
    "AD-specific security checks: privileged group changes, anomaly detection, GPO drift",
    "CIS / NIST / ISO 27001 / HIPAA / OWASP compliance scanning with pass/fail evidence",
    "Certificate expiry monitoring across stores, TLS endpoints, and Enterprise CA",
    "CISA KEV / NVD zero-day exposure cross-referenced against installed software",
    "Agentless AD/network discovery with dedup and staleness tracking",
]

PROMETHEUS_THEY_HAVE = [
    "A massive, mature exporter ecosystem for generic infra metrics (nothing AD-specific)",
    "Long-term time-series storage and PromQL - AD-Agent doesn't try to replace this, it feeds it",
    "Industry-standard alert routing/dedup/on-call via Alertmanager",
    "A dashboarding platform used far beyond security - infra, business metrics, everything",
]


@app.route("/prometheus-comparison")
def prometheus_comparison():
    counts = {"covered": 0, "partial": 0, "gap": 0}
    for cat in PROMETHEUS_COMPARISON:
        for item in cat["features"]:
            counts[item["status"]] += 1
    total = sum(counts.values())
    pct = round((counts["covered"] + 0.5 * counts["partial"]) / total * 100) if total else 0
    return render_template(
        "prometheus_comparison.html",
        categories=PROMETHEUS_COMPARISON,
        exclusives=PROMETHEUS_EXCLUSIVES,
        they_have=PROMETHEUS_THEY_HAVE,
        counts=counts,
        total=total,
        pct=pct,
    )


@app.route("/pdq-comparison")
def pdq_comparison():
    counts = {"covered": 0, "partial": 0, "gap": 0}
    for cat in PDQ_COMPARISON:
        for item in cat["features"]:
            counts[item["status"]] += 1
    total = sum(counts.values())
    pct = round((counts["covered"] + 0.5 * counts["partial"]) / total * 100) if total else 0
    return render_template(
        "pdq_comparison.html",
        categories=PDQ_COMPARISON,
        exclusives=PDQ_EXCLUSIVES,
        counts=counts,
        total=total,
        pct=pct,
    )


@app.route("/assets/delete", methods=["POST"])
def assets_delete():
    """Manual delete of one asset (decommissioned device, stray duplicate, etc.). Sticks
    until the next real Discovery scan re-finds that host, if it's genuinely still alive
    - see the _last_synced_mtime note on _load_discovery_inventory."""
    dedup_key = request.form.get("dedup_key", "").strip()
    if dedup_key:
        _delete_asset(dedup_key)
        _audit("asset_delete", f"dedup_key={dedup_key}")
    return redirect(url_for("assets_list"))


@app.route("/assets")
def assets_list():
    """Full, always-available table of every discovered asset (not the dashboard's
    NOC-display truncated-to-40 version) - searchable, with online/last-seen status."""
    assets, last_scan = _load_discovery_inventory()
    by_type: dict = {}
    by_source: dict = {}
    online_count = 0
    stale_count = 0
    for a in assets:
        by_type[a.get("AssetType", "Unknown")] = by_type.get(a.get("AssetType", "Unknown"), 0) + 1
        by_source[a.get("Source", "Unknown")] = by_source.get(a.get("Source", "Unknown"), 0) + 1
        if _is_online(a.get("LastSeen")):
            online_count += 1
        if _is_stale(a.get("LastSeen")):
            stale_count += 1

    return render_template(
        "assets.html",
        assets=sorted(assets, key=lambda a: (a.get("AssetType", ""), a.get("Name", ""))),
        total=len(assets),
        online_count=online_count,
        stale_count=stale_count,
        stale_days=STALE_THRESHOLD_DAYS,
        by_type=sorted(by_type.items(), key=lambda kv: -kv[1]),
        by_source=sorted(by_source.items(), key=lambda kv: -kv[1]),
        last_scan=last_scan,
        is_online=_is_online,
        is_stale=_is_stale,
        time_ago=_time_ago,
    )


def _findings_by_source() -> dict:
    """The latest scan snapshot, keyed the way playbook triggers reference it."""
    data, _ = _load_snapshot()
    return {
        "Anomalies":            data.get("Anomalies") or [],
        "ComplianceGaps":       data.get("ComplianceGaps") or [],
        "ExpiringCertificates": data.get("ExpiringCertificates") or [],
        "ZeroDays":             data.get("ZeroDays") or [],
        "VulnerableSoftware":   data.get("VulnerableSoftware") or [],
    }


@app.route("/soar")
def soar_page():
    """Incidents, pending approvals and action history for the response engine."""
    playbooks = soar.load_playbooks(PLAYBOOKS_PATH)
    problems = {pb.get("id", "?"): soar.validate_playbook(pb) for pb in playbooks}
    problems = {k: v for k, v in problems.items() if v}

    # Preview is always a dry evaluation - it shows what WOULD fire right now
    # without writing anything, so the page is safe to open at any time.
    preview = soar.evaluate(_findings_by_source(), playbooks)

    return render_template(
        "soar.html",
        mode=soar.SOAR_MODE,
        playbooks=playbooks,
        problems=problems,
        preview_count=len(preview),
        preview=preview[:25],
        incidents=soar.list_incidents(STATE_DIR),
        pending=soar.list_actions(STATE_DIR, status=soar.PENDING_APPROVAL),
        recent_actions=soar.list_actions(STATE_DIR)[:50],
        actions_registry=soar.ACTIONS,
        time_ago=_time_ago,
    )


@app.route("/soar/run", methods=["POST"])
def soar_run():
    if soar.SOAR_MODE == "off":
        return render_template("index.html",
                               error="SOAR is disabled. Set SOAR_MODE=dryrun (or live) and restart the web UI.")
    playbooks = soar.load_playbooks(PLAYBOOKS_PATH)
    summary = soar.run(
        STATE_DIR, _findings_by_source(), playbooks,
        teams_webhook=os.environ.get("TEAMS_WEBHOOK_URL", ""),
        responder_script=SOAR_RESPONDER_SCRIPT,
        powershell=_detect_powershell(),
    )
    _audit("soar_run", f"mode={summary.get('mode')} incidents={summary.get('incidents_created')}")
    return redirect(url_for("soar_page"))


@app.route("/soar/action/<action_id>/<decision>", methods=["POST"])
def soar_decide(action_id: str, decision: str):
    """Approve or reject a queued destructive action. Approval is the ONLY path by
    which an AD-mutating action ever runs - there is no autonomous mode."""
    if decision not in ("approve", "reject"):
        return "unknown decision", 400
    status = soar.QUEUED if decision == "approve" else soar.REJECTED
    changed = soar.set_action_status(STATE_DIR, action_id, status, approved_by=_remote_user())
    _audit(f"soar_action_{decision}", f"action_id={action_id} applied={changed}")

    if changed and decision == "approve" and soar.SOAR_MODE == "live":
        soar.execute_queued(
            STATE_DIR,
            teams_webhook=os.environ.get("TEAMS_WEBHOOK_URL", ""),
            responder_script=SOAR_RESPONDER_SCRIPT,
            powershell=_detect_powershell(),
        )
    return redirect(url_for("soar_page"))


@app.route("/endpoints")
def endpoints_list():
    """Live feed of devices that have pushed a check-in - laptops coming back online,
    newest first. This is the view that jump-server-initiated scanning could never
    produce for roaming devices: a laptop on an unreachable VLAN, behind DHCP churn,
    or asleep for three weeks simply appears here the moment it phones home."""
    try:
        endpoints = assets_db.load_recent_checkins(STATE_DIR)
    except Exception:
        endpoints = []

    now_online = [e for e in endpoints if _is_online(e.get("LastCheckin"))]

    # "Came online today" = first appearance or a return after a long silence is not
    # something a single timestamp can tell us, so this is simply "checked in within
    # the last 24h" - honest about what the data supports.
    day_ago = datetime.utcnow().timestamp() - 86400
    today = []
    for e in endpoints:
        try:
            if datetime.fromisoformat(str(e["LastCheckin"]).replace("Z", "")).timestamp() >= day_ago:
                today.append(e)
        except (ValueError, KeyError, TypeError):
            pass

    by_source: dict = {}
    by_location: dict = {}
    for e in endpoints:
        s = e.get("CheckinSource", "Unknown")
        by_source[s] = by_source.get(s, 0) + 1
        loc = e.get("LastLocation", "Unknown")
        by_location[loc] = by_location.get(loc, 0) + 1

    # Office/remote day counts over the last 30 days - the pattern view. A laptop
    # carried home nightly shows up as both, which is the point: neither number
    # overwrites the other the way a single "last seen" field would.
    presence = assets_db.presence_summary(STATE_DIR, days=PRESENCE_WINDOW_DAYS)

    return render_template(
        "endpoints.html",
        endpoints=endpoints,
        total=len(endpoints),
        online_count=len(now_online),
        today_count=len(today),
        by_source=sorted(by_source.items(), key=lambda kv: -kv[1]),
        by_location=sorted(by_location.items(), key=lambda kv: -kv[1]),
        presence=presence,
        presence_days=PRESENCE_WINDOW_DAYS,
        location_configured=bool(_corporate_networks()),
        collector_enabled=bool(os.environ.get("COLLECTOR_TOKEN")),
        is_online=_is_online,
        is_stale=_is_stale,
        time_ago=_time_ago,
    )


def _cert_expiry(not_after) -> tuple:
    """(datetime|None, days_remaining|None) for a NotAfter value.

    Days are recomputed on every page load rather than trusted from the scan snapshot:
    a certificate collected 40 days ago has 40 fewer days left than the scan recorded,
    and now that results persist across scans, a stored DaysRemaining would drift
    steadily further from the truth the longer a host went un-rescanned.
    """
    if not not_after:
        return None, None
    text = str(not_after)
    m = re.match(r"/Date\((-?\d+)", text)   # PowerShell's legacy JSON date shape
    try:
        if m:
            dt = datetime.utcfromtimestamp(int(m.group(1)) / 1000)
        else:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00").split("+")[0].strip())
    except (ValueError, OSError, OverflowError):
        return None, None
    return dt, (dt - datetime.utcnow()).days


@app.route("/certificates")
def certificates_list():
    """Every certificate ever found, expiring or not, across every scan.

    Results are merged into the permanent store (assets_db.sync_certificates) rather
    than read straight from the latest snapshot. A snapshot only holds the hosts of
    the run that produced it, so reading it directly meant scanning one server erased
    the record of every other one - you had to re-scan the whole estate to keep this
    page complete. Certificates now accumulate; a host absent from today's scan simply
    keeps what was last known about it, stamped with when that was.
    """
    data, demo = _load_snapshot()
    snap_certs = data.get("CertificateInventory") or []
    legacy = False
    if not snap_certs and data.get("ExpiringCertificates"):
        snap_certs = data.get("ExpiringCertificates") or []
        legacy = True

    # Find-ExpiringCertificates emits unreachable hosts as pseudo-findings with a
    # '(collection error)' subject and no NotAfter. They are failures to report, not
    # certificates: counting them or badging them "Expiring" claims a host has a
    # certificate about to lapse when nothing could be read from it at all.
    snap_errors = [
        c for c in snap_certs
        if c.get("CollectionErrors") or c.get("Subject") == "(collection error)"
    ]
    snap_real = [c for c in snap_certs if c not in snap_errors]

    if not demo:
        try:
            assets_db.sync_certificates(STATE_DIR, snap_real, snap_errors,
                                        scan_time=str(data.get("ScanTime") or ""))
        except Exception:
            pass  # a store problem must not blank the page; /healthz reports it

    if demo:
        certs, errors = snap_real, snap_errors
    else:
        try:
            certs, errors = assets_db.load_all_certificates(STATE_DIR)
        except Exception:
            certs, errors = snap_real, snap_errors

    counts = {"Expired": 0, "Expiring": 0, "Valid": 0, "Unknown": 0}
    by_issuer: dict = {}
    for c in certs:
        expiry, days = _cert_expiry(c.get("NotAfter"))
        if days is None:
            days = c.get("DaysRemaining")
        c["DaysRemaining"] = days
        if days is None:
            status = "Unknown"
        elif days < 0:
            status = "Expired"
        elif days <= CERT_THRESHOLD_DAYS:
            status = "Expiring"
        else:
            status = "Valid"
        c["Status"] = status
        counts[status] += 1
        issuer = (c.get("Issuer") or "Unknown").strip()
        by_issuer[issuer] = by_issuer.get(issuer, 0) + 1

    # Group by host so a server with six certificates is one expandable row rather than
    # six unrelated lines, and so "which hosts have nothing?" is answerable at a glance.
    hosts: dict = {}
    for c in certs:
        locs = c.get("LocationMap") or {h.strip(): {} for h in str(c.get("ComputerName") or "").split(",") if h.strip()}
        for host, meta in (locs or {"(unknown)": {}}).items():
            h = hosts.setdefault(host, {"host": host, "certs": [], "last_seen": None,
                                        "counts": {"Expired": 0, "Expiring": 0, "Valid": 0, "Unknown": 0}})
            entry = dict(c)
            entry["Place"] = (meta or {}).get("place", "")
            h["certs"].append(entry)
            h["counts"][c["Status"]] += 1
            seen = (meta or {}).get("last_seen")
            if seen and (h["last_seen"] is None or seen > h["last_seen"]):
                h["last_seen"] = seen
    for h in hosts.values():
        h["certs"].sort(key=lambda x: (x["DaysRemaining"] is None, x["DaysRemaining"]))
        h["worst"] = ("Expired" if h["counts"]["Expired"] else
                      "Expiring" if h["counts"]["Expiring"] else
                      "Valid" if h["counts"]["Valid"] else "Unknown")

    error_hosts = {(e.get("ComputerName") or "").split("[")[0].strip() for e in errors}
    host_rows = sorted(
        hosts.values(),
        key=lambda h: ({"Expired": 0, "Expiring": 1, "Unknown": 2, "Valid": 3}[h["worst"]], h["host"].lower()),
    )

    status_filter = request.args.get("status") or ""
    if status_filter in counts:
        host_rows = [h for h in host_rows if h["counts"][status_filter]]
    host_filter = (request.args.get("host") or "").strip().lower()
    if host_filter:
        host_rows = [h for h in host_rows if host_filter in h["host"].lower()]

    return render_template(
        "certificates.html",
        demo=demo,
        error_ttl_days=assets_db.CERT_ERROR_TTL_DAYS,
        certs=sorted(certs, key=lambda c: (c["DaysRemaining"] is None, c["DaysRemaining"])),
        host_rows=host_rows,
        errors=errors,
        error_hosts=error_hosts,
        total=len(certs),
        counts=counts,
        host_count=len(hosts | {h: None for h in error_hosts if h}),
        by_issuer=sorted(by_issuer.items(), key=lambda kv: -kv[1])[:12],
        threshold_days=CERT_THRESHOLD_DAYS,
        legacy_only=legacy and bool(certs),
        status_filter=status_filter,
        host_filter=request.args.get("host") or "",
    )


@app.route("/certificates/errors/clear", methods=["POST"])
def certificates_clear_error():
    """Dismiss one collection failure. Failures age out on their own after
    CERT_ERROR_TTL_DAYS, but a target you have just removed from the config shouldn't
    have to sit on the page for a week first."""
    target = (request.form.get("target") or "").strip()
    if target:
        _audit("cert_error_dismiss", f"target={target}")
        try:
            assets_db.delete_cert_error(STATE_DIR, target)
        except Exception:
            pass
    return redirect(url_for("certificates_list"))


@app.route("/software")
def software_list():
    """Every installed-software record collected so far, across every device and every run.

    Results merge into the permanent store rather than being read from the latest scan
    snapshot: a snapshot only holds the hosts of the run that produced it, so inventorying
    ten laptops used to erase the previous ten. A host absent from today's run keeps its
    last known inventory, stamped with when it was collected.
    """
    data, demo = _load_snapshot()
    all_sw = data.get("SoftwareInventory") or []
    snap_software = [s for s in all_sw if not s.get("Error")]
    vulnerable = data.get("VulnerableSoftware") or []

    snap_issues = [
        {"ComputerName": s.get("ComputerName"), "Reason": s.get("Error")}
        for s in all_sw if s.get("Error")
    ]
    assets, _ = _load_discovery_inventory()

    # Software pushed by the endpoint collector lives on the asset record, not in the
    # scan snapshot - a roaming laptop is never in a snapshot, because no scan from
    # this server can reach it. Merge those in so pushed inventory is visible here and
    # not just in the dashboard drill-down. Snapshot (WinRM-collected) data wins for a
    # host present in both, since that's the run this page's vulnerability
    # cross-reference was actually computed against.
    have_software_for = {s.get("ComputerName") for s in snap_software if s.get("ComputerName")}
    for a in assets:
        name = a.get("Name")
        pushed = a.get("Software")
        if not name or not pushed or name in have_software_for:
            continue
        for item in pushed:
            if not isinstance(item, dict):
                continue
            snap_software.append({
                "ComputerName": name,
                "Category":     a.get("AssetType") or "Unknown",
                "Name":         item.get("Name"),
                "Version":      item.get("Version"),
                "Publisher":    item.get("Publisher"),
                "InstallDate":  item.get("InstallDate"),
                "Source":       "PushCollector",
            })
        have_software_for.add(name)

    covered = {i["ComputerName"] for i in snap_issues} | have_software_for
    for a in assets:
        note = a.get("CollectionNote")
        name = a.get("Name")
        if note and name not in covered:
            snap_issues.append({"ComputerName": name, "Reason": note})
            covered.add(name)

    if demo:
        software, issues = snap_software, snap_issues
    else:
        try:
            assets_db.sync_software(STATE_DIR, snap_software, snap_issues)
            software, issues = assets_db.load_all_software(STATE_DIR)
        except Exception:
            # A store problem must not blank the page - fall back to this run's data.
            software, issues = snap_software, snap_issues

    vuln_hosts = {v.get("ComputerName") for v in vulnerable if v.get("ComputerName")}
    hosts: dict = {}
    for s in software:
        host = s.get("ComputerName") or "(unknown)"
        h = hosts.setdefault(host, {"host": host, "packages": [], "category": s.get("Category"),
                                    "last_seen": None, "sources": set()})
        h["packages"].append(s)
        if s.get("Source"):
            h["sources"].add(s["Source"])
        seen = s.get("LastSeen")
        if seen and (h["last_seen"] is None or seen > h["last_seen"]):
            h["last_seen"] = seen
    for h in hosts.values():
        h["packages"].sort(key=lambda x: ((x.get("Name") or "").lower(), x.get("Version") or ""))
        h["vulnerable"] = h["host"] in vuln_hosts
        h["sources"] = ", ".join(sorted(h["sources"])) or "-"

    # Vulnerable hosts first: the reason to open this page in a hurry is a zero-day hit.
    host_rows = sorted(hosts.values(), key=lambda h: (not h["vulnerable"], h["host"].lower()))

    host_filter = (request.args.get("host") or "").strip().lower()
    if host_filter:
        host_rows = [h for h in host_rows if host_filter in h["host"].lower()]
    if request.args.get("only") == "vulnerable":
        host_rows = [h for h in host_rows if h["vulnerable"]]

    return render_template(
        "software.html",
        demo=demo,
        software=software,
        host_rows=host_rows,
        vulnerable=vulnerable,
        issues=issues,
        host_count=len(hosts),
        only=request.args.get("only") or "",
        host_filter=request.args.get("host") or "",
    )


@app.route("/discovery/run", methods=["POST"])
def discovery_run():
    """Discovery-only run (+ software inventory by default): no anomaly, compliance,
    certificate, or zero-day scanning at all."""

    def _split(field: str) -> list[str]:
        raw = request.form.get(field, "").strip()
        return [x.strip() for x in raw.replace("\n", ",").split(",") if x.strip()]

    from_ad = "from_ad" in request.form
    cidr = _split("cidr")
    warp_cidr = _split("cloudflare_warp_cidr")
    skip_categorize = "skip_categorize" in request.form
    skip_software = "skip_software" in request.form

    if not from_ad and not cidr and not warp_cidr:
        return render_template("index.html", error="Discovery needs at least one target: check "
                                "“From Active Directory” or enter a CIDR range.")

    target_err = _validate_targets(cidr) or _validate_targets(warp_cidr)
    if target_err:
        return render_template("index.html", error=target_err)

    _audit("discovery_submit", f"from_ad={from_ad} cidr={cidr} warp_cidr={warp_cidr}")
    job_id = _submit_job(
        "discovery", _discovery_job, from_ad, cidr, warp_cidr, skip_categorize, skip_software
    )
    return render_template("job_wait.html", job_id=job_id, kind="discovery")


def _discovery_job(from_ad, cidr, warp_cidr, skip_categorize, skip_software) -> dict:
    """Runs on the job thread pool - see _submit_job. Must not touch the Flask
    session or request context (neither exist off the request thread)."""
    result, err = _run_discovery(from_ad, cidr, warp_cidr, skip_categorize, skip_software)
    if err:
        raise RuntimeError(err)
    return {"result": result}


# Scan targets can be typed the same way discovery targets are: a hostname, an IP, a
# CIDR, or an inclusive dash range. Expand-Cidr already understood ranges on the
# discovery side, so a range that worked in one box and was rejected in the other was
# purely an inconsistency between the two entry points, not a real limit.
_MAX_SCAN_TARGETS = 1024


def _validate_targets(targets: list[str]) -> str | None:
    """Reject malformed network targets before PowerShell ever sees them.

    Expand-Cidr throws on a bad target and takes the whole discovery run with it, and
    what surfaces in the browser is a PowerShell stack trace with the parse error buried
    in it. Checking here means an obvious typo is caught instantly and named plainly.
    """
    # Pre-pass for the classic typo: a comma typed where a dot belongs, e.g.
    # "10.15.2.150 - 10,15.2.250". That splits one range into two targets - a truncated
    # range and an orphan fragment - and both halves can look individually plausible
    # enough that the per-target error below names the wrong thing. Catch the pair.
    for i in range(len(targets) - 1):
        a, b = targets[i], targets[i + 1]
        if "-" in a and b[:1].isdigit() and b.count(".") < 3 and a[:1].isdigit():
            return (f"'{a}' and '{b}' look like one range split by a comma typed in place "
                    f"of a dot. Did you mean '{a}.{b}'?")

    for i, t in enumerate(targets):
        looks_numeric = t[:1].isdigit()
        if not looks_numeric:
            continue  # a hostname - DNS resolves it at scan time, nothing to validate here
        try:
            if "/" in t:
                ipaddress.ip_network(t, strict=False)
            elif "-" in t:
                lo_s, hi_s = (x.strip() for x in t.split("-", 1))
                if hi_s.isdigit() and lo_s.count(".") == 3:
                    hi_s = lo_s.rsplit(".", 1)[0] + "." + hi_s
                lo, hi = ipaddress.ip_address(lo_s), ipaddress.ip_address(hi_s)
                if hi < lo:
                    return f"Invalid range '{t}': the end address is lower than the start."
            else:
                ipaddress.ip_address(t)
        except ValueError:
            # The classic version of this: a comma typed where a dot belongs, e.g.
            # "10.15.2.150 - 10,15.2.250". The comma splits one range into two targets -
            # a truncated range and an orphan fragment - and whichever half fails is the
            # only one the error names, which reads as nonsense. Say what probably
            # happened instead.
            prev = targets[i - 1] if i else ""
            if prev and "-" in prev and t[:1].isdigit():
                return (f"'{t}' isn't a valid IP, CIDR or range. Did you mean "
                        f"'{prev}.{t}'? A comma typed in place of a dot splits one range "
                        "into two invalid targets.")
            return f"'{t}' isn't a valid IP, CIDR or range."
    return None


def _expand_scan_targets(raw: str) -> tuple[list[str], str | None]:
    """Split the targets box into individual hosts, expanding CIDRs and a-b ranges.

    Returns (targets, error). Hostnames pass through untouched - only things that
    actually parse as an address or network are expanded, so 'dc01.amg.local' is never
    mistaken for a malformed range.
    """
    out: list[str] = []
    for part in [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]:
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                out += [str(ip) for ip in net.hosts()] or [str(net.network_address)]
                continue
            if "-" in part and part.count("-") == 1:
                lo_s, hi_s = (x.strip() for x in part.split("-"))
                # A short form is convenient and unambiguous: 10.15.2.1-50.
                if hi_s.isdigit() and lo_s.count(".") == 3:
                    hi_s = lo_s.rsplit(".", 1)[0] + "." + hi_s
                lo, hi = ipaddress.ip_address(lo_s), ipaddress.ip_address(hi_s)
                if hi < lo:
                    return [], f"Invalid range '{part}': the end address is lower than the start."
                if int(hi) - int(lo) + 1 > _MAX_SCAN_TARGETS:
                    return [], (f"Range '{part}' covers {int(hi) - int(lo) + 1} addresses; "
                                f"the limit for a scan is {_MAX_SCAN_TARGETS}.")
                out += [str(ipaddress.ip_address(n)) for n in range(int(lo), int(hi) + 1)]
                continue
        except ValueError:
            # Not an address/network - a hostname that happens to contain '-' or '/'.
            pass
        out.append(part)

    if len(out) > _MAX_SCAN_TARGETS:
        return [], f"{len(out)} targets requested; the limit for a single scan is {_MAX_SCAN_TARGETS}."
    seen, uniq = set(), []
    for t in out:
        if t.lower() not in seen:
            seen.add(t.lower())
            uniq.append(t)
    return uniq, None


@app.route("/scan", methods=["POST"])
def scan():
    raw_dcs  = request.form.get("domain_controllers", "").strip()
    # Validate what was typed before expanding it, so the message names the entry as the
    # user wrote it rather than something derived from it.
    typed = [p.strip() for p in raw_dcs.replace("\n", ",").split(",") if p.strip()]
    target_err = _validate_targets(typed)
    if target_err:
        return render_template("index.html", error=target_err)
    dcs, target_err = _expand_scan_targets(raw_dcs)
    if target_err:
        return render_template("index.html", error=target_err)
    scan_types = request.form.getlist("scan_types")  # ["anomaly", "compliance"]
    frameworks = request.form.getlist("frameworks")   # ["CIS", "NIST", "ISO"]
    severities = request.form.getlist("severities")   # ["Critical", "High", ...]

    if not dcs:
        return render_template("index.html", error="Please enter at least one Domain Controller hostname.")

    if not scan_types:
        scan_types = ["anomaly"]

    _audit("scan_submit", f"dcs={dcs} scan_types={scan_types}")
    job_id = _submit_job("scan", _scan_job, dcs, scan_types, frameworks, severities)
    return render_template("job_wait.html", job_id=job_id, kind="scan")


def _scan_job(dcs, scan_types, frameworks, severities) -> dict:
    """Runs on the job thread pool - see _submit_job. Must not touch the Flask
    session or request context (neither exist off the request thread)."""
    pwsh = _detect_powershell()
    if not pwsh:
        result = _mock_result(dcs)
        demo = True
    else:
        result, err = _run_scan(dcs, scan_types, frameworks, severities)
        if result is None:
            raise RuntimeError(err or "unknown error")
        demo = False
    return {
        "result": result, "demo": demo, "dcs": dcs,
        "scan_types": scan_types, "frameworks": frameworks, "severities": severities,
    }


def _render_scan_result(data: dict):
    result     = data["result"]
    dcs        = data["dcs"]
    scan_types = data["scan_types"]
    frameworks = data["frameworks"]
    severities = data["severities"]
    demo       = data["demo"]

    # Persist in session so download endpoints can regenerate from it
    session["last_result"] = json.dumps(result)

    anomalies = result.get("Anomalies") or []
    gaps       = result.get("ComplianceGaps") or []
    summary    = result.get("ComplianceSummary") or {}
    certs      = result.get("ExpiringCertificates") or []
    software   = [s for s in (result.get("SoftwareInventory") or []) if not s.get("Error")]
    vuln_sw    = result.get("VulnerableSoftware") or []
    sev_rank   = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    return render_template(
        "results.html",
        scan_time  = result.get("ScanTime", ""),
        dcs        = dcs,
        anomalies  = anomalies,
        gaps       = sorted(gaps, key=lambda g: sev_rank.get(g.get("Severity","Low"), 9)),
        summary    = summary,
        certs      = sorted(
            [c for c in certs if c.get("DaysRemaining") is not None],
            key=lambda c: (sev_rank.get(c.get("Severity","Low"), 9), c.get("DaysRemaining", 9999)),
        ),
        software   = sorted(software, key=lambda s: (s.get("Category",""), s.get("ComputerName",""), s.get("Name",""))),
        vulnerable_software = vuln_sw,
        scan_types = scan_types,
        frameworks = frameworks,
        severities = severities,
        demo       = demo,
    )


def _render_discovery_result(data: dict):
    result = data["result"]
    by_type: dict = {}
    for a in (result.get("Inventory") or []):
        t = a.get("AssetType", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1
    return render_template(
        "index.html",
        discovery_summary={
            "count": result.get("Count", 0),
            "by_type": sorted(by_type.items(), key=lambda kv: -kv[1]),
        },
    )


@app.route("/jobs/<job_id>")
def job_status(job_id):
    """Polled by job_wait.html every couple seconds. Kept intentionally tiny -
    just enough for the UI to know whether to keep waiting, redirect to the
    result, or show an error."""
    job = _get_job(job_id)
    if not job:
        return jsonify({"status": "not_found"}), 404
    return jsonify({"status": job["status"], "kind": job["kind"], "error": job["error"]})


@app.route("/jobs/<job_id>/result")
def job_result(job_id):
    job = _get_job(job_id)
    if not job:
        return render_template("index.html", error="That job has expired or the server restarted. Please run the scan again."), 404
    if job["status"] == "running":
        return render_template("job_wait.html", job_id=job_id, kind=job["kind"])
    if job["status"] == "error":
        label = "Scan" if job["kind"] == "scan" else "Discovery"
        return render_template("index.html", error=f"{label} failed: {job['error']}")
    if job["kind"] == "scan":
        return _render_scan_result(job["result"])
    return _render_discovery_result(job["result"])


@app.route("/download/pdf")
def download_pdf():
    raw = session.get("last_result")
    if not raw:
        return "No scan result in session. Run a scan first.", 400
    result = json.loads(raw)
    pdf_bytes = generate_pdf(result)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=dc_report_{ts}.pdf"},
    )


@app.route("/download/csv/anomalies")
def download_csv_anomalies():
    raw = session.get("last_result")
    if not raw:
        return "No scan result in session. Run a scan first.", 400
    result = json.loads(raw)
    csv_str = generate_csv_anomalies(result)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=anomalies_{ts}.csv"},
    )


@app.route("/download/csv/compliance")
def download_csv_compliance():
    raw = session.get("last_result")
    if not raw:
        return "No scan result in session. Run a scan first.", 400
    result = json.loads(raw)
    csv_str = generate_csv_compliance(result)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=compliance_gaps_{ts}.csv"},
    )


@app.route("/download/csv/certificates")
def download_csv_certificates():
    raw = session.get("last_result")
    if not raw:
        return "No scan result in session. Run a scan first.", 400
    result = json.loads(raw)
    csv_str = generate_csv_certificates(result)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=expiring_certificates_{ts}.csv"},
    )


@app.route("/download/csv/software")
def download_csv_software():
    raw = session.get("last_result")
    if not raw:
        return "No scan result in session. Run a scan first.", 400
    result = json.loads(raw)
    csv_str = generate_csv_software(result)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=software_inventory_{ts}.csv"},
    )


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)

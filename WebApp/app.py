"""DC Anomaly Agent — web UI.

Accepts scan sources, triggers the PowerShell scanner, and serves
PDF and CSV reports. Designed to run on the same management server
that executes the Scheduled Task.
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
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
INTEGRATIONS_STATUS_PATH = STATE_DIR / "integrations-status.json"
INTEGRATIONS_SCRIPT      = APP_ROOT.parent / "DCAnomalyAgent" / "Get-IntegrationStatus.ps1"
WINRM_TEST_SCRIPT        = APP_ROOT.parent / "DCAnomalyAgent" / "Test-WinRM.ps1"
# Vendor API keys entered on the Vendor Warranty page live here, not in settings.psd1 or
# git - see DCAnomalyAgent/Modules/DCAnomalyAgent.VendorWarranty.psm1.
INTEGRATION_SECRETS_PATH = APP_ROOT.parent / "DCAnomalyAgent" / "Config" / "integration-secrets.json"
REPORTS_DIR   = APP_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))


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

    if "compliance" in scan_types:
        cmd.append("-ComplianceScan")
    if "certificate" in scan_types:
        cmd.append("-CertificateScan")
    if "software" in scan_types:
        cmd.append("-SoftwareInventoryScan")
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

    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True,
            timeout=300,
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
        return None, "Scan timed out (>5 minutes)."
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

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        raw = result.stdout.strip()
        if not raw:
            return None, result.stderr.strip() or "Discovery produced no output."
        json_start = raw.find("{")
        json_end = raw.rfind("}") + 1
        if json_start == -1:
            return None, f"No JSON in output.\n\nStdout:\n{raw}\n\nStderr:\n{result.stderr}"
        return json.loads(raw[json_start:json_end]), ""
    except subprocess.TimeoutExpired:
        return None, "Discovery timed out (>10 minutes) — try a smaller CIDR range or -SkipSoftwareInventory."
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


def _load_discovery_inventory() -> tuple[list, str | None]:
    """Return (assets, last_scan_iso). Empty list if no discovery scan has run yet."""
    try:
        if DISCOVERY_INVENTORY_PATH.exists():
            mtime = datetime.utcfromtimestamp(DISCOVERY_INVENTORY_PATH.stat().st_mtime).isoformat()
            with open(DISCOVERY_INVENTORY_PATH, encoding="utf-8-sig") as fh:
                assets = json.load(fh)
                if isinstance(assets, dict):
                    assets = [assets]
                return assets, mtime
    except Exception:
        pass
    return [], None


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


STALE_THRESHOLD_DAYS = 14  # e.g. a laptop out on leave for 2-3 weeks


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


@app.route("/software")
def software_list():
    """Standalone, always-available view of every collected software record across every
    device — not tied to a specific scan run, and not limited to clicking through devices
    one at a time on the dashboard. Also surfaces WHY a device has nothing collected yet
    (WinRM error, or skipped because WinRM wasn't seen open during discovery), pulling
    together both the shared scan snapshot and the live discovery inventory."""
    data, demo = _load_snapshot()
    all_sw = data.get("SoftwareInventory") or []
    software = [s for s in all_sw if not s.get("Error")]
    vulnerable = data.get("VulnerableSoftware") or []

    issues = [
        {"ComputerName": s.get("ComputerName"), "Reason": s.get("Error")}
        for s in all_sw if s.get("Error")
    ]
    assets, _ = _load_discovery_inventory()
    covered = {i["ComputerName"] for i in issues} | {s.get("ComputerName") for s in software}
    for a in assets:
        note = a.get("CollectionNote")
        name = a.get("Name")
        if note and name not in covered:
            issues.append({"ComputerName": name, "Reason": note})
            covered.add(name)

    return render_template(
        "software.html",
        demo=demo,
        software=software,
        vulnerable=vulnerable,
        issues=issues,
        host_count=len({s.get("ComputerName") for s in software if s.get("ComputerName")}),
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

    result, err = _run_discovery(from_ad, cidr, warp_cidr, skip_categorize, skip_software)
    if err:
        return render_template("index.html", error=f"Discovery failed: {err}")

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


@app.route("/scan", methods=["POST"])
def scan():
    raw_dcs  = request.form.get("domain_controllers", "").strip()
    dcs      = [d.strip() for d in raw_dcs.replace("\n", ",").split(",") if d.strip()]
    scan_types = request.form.getlist("scan_types")  # ["anomaly", "compliance"]
    frameworks = request.form.getlist("frameworks")   # ["CIS", "NIST", "ISO"]
    severities = request.form.getlist("severities")   # ["Critical", "High", ...]

    if not dcs:
        return render_template("index.html", error="Please enter at least one Domain Controller hostname.")

    if not scan_types:
        scan_types = ["anomaly"]

    pwsh = _detect_powershell()
    if not pwsh:
        result = _mock_result(dcs)
        demo = True
    else:
        result, err = _run_scan(dcs, scan_types, frameworks, severities)
        if result is None:
            return render_template("index.html", error=f"Scan failed: {err}", scan_config={
                "dcs": dcs, "scan_types": scan_types, "frameworks": frameworks, "severities": severities,
            })
        demo = False

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

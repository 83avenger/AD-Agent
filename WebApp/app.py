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
    generate_pdf,
)

APP_ROOT    = Path(__file__).parent
PS_SCRIPT   = APP_ROOT.parent / "DCAnomalyAgent" / "Run-AnomalyScan.ps1"
REPORTS_DIR = APP_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(24))


def _detect_powershell() -> str:
    for candidate in ("pwsh", "powershell"):
        try:
            subprocess.run([candidate, "-Version"], capture_output=True, timeout=5)
            return candidate
        except FileNotFoundError:
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
        "-DomainControllerOverride", dc_override,
        "-JsonOutput",
    ]

    if "compliance" in scan_types:
        cmd.append("-ComplianceScan")
    if "certificate" in scan_types:
        cmd.append("-CertificateScan")
    if frameworks:
        cmd += ["-FrameworkFilter"] + frameworks
    if severities:
        cmd += ["-SeverityFilter"] + severities

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
        "_demo": True,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


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


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)

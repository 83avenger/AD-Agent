"""PDF and CSV report generation for DC Anomaly Agent scan results."""

import csv
import io
import textwrap
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette ────────────────────────────────────────────────────────────
BRAND_DARK  = colors.HexColor("#1a2332")
BRAND_MID   = colors.HexColor("#2d4a6e")
BRAND_LIGHT = colors.HexColor("#e8f0fa")

SEV_COLORS = {
    "Critical": colors.HexColor("#c0392b"),
    "High":     colors.HexColor("#e67e22"),
    "Medium":   colors.HexColor("#f1c40f"),
    "Low":      colors.HexColor("#2980b9"),
}
SEV_TEXT = {
    "Critical": colors.white,
    "High":     colors.white,
    "Medium":   colors.HexColor("#222"),
    "Low":      colors.white,
}


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"],
                                fontSize=22, textColor=BRAND_DARK, spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", parent=base["Normal"],
                                   fontSize=11, textColor=BRAND_MID, spaceAfter=12),
        "h2": ParagraphStyle("h2", parent=base["Heading2"],
                              fontSize=13, textColor=BRAND_DARK, spaceBefore=14, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=9, leading=13),
        "small": ParagraphStyle("small", parent=base["Normal"], fontSize=8, textColor=colors.grey),
        "remediation": ParagraphStyle("rem", parent=base["Normal"], fontSize=8,
                                      leading=12, textColor=colors.HexColor("#333")),
        "center": ParagraphStyle("center", parent=base["Normal"], alignment=TA_CENTER, fontSize=9),
    }


def _sev_badge(severity: str, style) -> Paragraph:
    bg  = SEV_COLORS.get(severity, colors.grey).hexval()
    fg  = "white" if severity in ("Critical", "High", "Low") else "#222"
    txt = f'<font color="{fg}"><b> {severity} </b></font>'
    return Paragraph(f'<para backColor="{bg}" borderPadding="2">{txt}</para>', style["body"])


def _frameworks_str(frameworks) -> str:
    if isinstance(frameworks, dict):
        return " | ".join(f"{k}: {v}" for k, v in frameworks.items())
    return str(frameworks)


# ── PDF ───────────────────────────────────────────────────────────────────────

def generate_pdf(scan_result: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )
    s = _styles()
    story = []

    scan_time = scan_result.get("ScanTime", datetime.utcnow().isoformat())
    anomalies = scan_result.get("Anomalies") or []
    gaps       = scan_result.get("ComplianceGaps") or []
    summary    = scan_result.get("ComplianceSummary") or {}
    certs      = [c for c in (scan_result.get("ExpiringCertificates") or [])
                  if c.get("DaysRemaining") is not None]
    software   = [sw for sw in (scan_result.get("SoftwareInventory") or []) if not sw.get("Error")]
    vuln_sw    = scan_result.get("VulnerableSoftware") or []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("DC Anomaly &amp; Compliance Report", s["title"]))
    story.append(Paragraph(f"Scan time: {scan_time}", s["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=BRAND_DARK))
    story.append(Spacer(1, 0.4 * cm))

    # ── Executive summary boxes ───────────────────────────────────────────────
    score_pct = summary.get("ScorePct", "N/A")
    passed    = summary.get("Passed", 0)
    total     = summary.get("TotalControls", 0)
    summary_data = [
        ["Anomalies Found", "Compliance Score", "Controls Passed", "Controls Failed"],
        [
            str(len(anomalies)),
            f"{score_pct}%" if total else "—",
            str(passed) if total else "—",
            str(total - passed) if total else "—",
        ],
    ]
    summary_table = Table(summary_data, colWidths=[4.25 * cm] * 4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), BRAND_DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0), 9),
        ("BACKGROUND",  (0, 1), (-1, 1), BRAND_LIGHT),
        ("FONTSIZE",    (0, 1), (-1, 1), 18),
        ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [BRAND_DARK, BRAND_LIGHT]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.white),
        ("ROWHEIGHT",   (0, 0), (-1, -1), 26),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5 * cm))

    # ── Anomalies section ────────────────────────────────────────────────────
    story.append(Paragraph("Security Anomalies", s["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_MID))
    story.append(Spacer(1, 0.2 * cm))

    if not anomalies:
        story.append(Paragraph("No anomalies detected in this scan window.", s["body"]))
    else:
        headers = ["Type", "Account", "DC", "Detected At", "Detail"]
        rows = [headers]
        for a in anomalies:
            rows.append([
                Paragraph(str(a.get("Type", "")),        s["body"]),
                Paragraph(str(a.get("Account", "—")),    s["body"]),
                Paragraph(str(a.get("ComputerName", "")), s["body"]),
                Paragraph(str(a.get("TimeCreated", ""))[:19], s["small"]),
                Paragraph(textwrap.shorten(str(a.get("Detail", "")), 120), s["body"]),
            ])

        col_w = [3.8*cm, 2.8*cm, 3.0*cm, 3.0*cm, 4.5*cm]
        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), BRAND_MID),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE",     (0, 1), (-1, -1), 8),
        ]))
        story.append(tbl)

    story.append(Spacer(1, 0.6 * cm))

    # ── Compliance gaps section ───────────────────────────────────────────────
    story.append(Paragraph("Compliance Gaps", s["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_MID))
    story.append(Spacer(1, 0.2 * cm))

    if not gaps:
        story.append(Paragraph("No compliance gaps found — all controls are passing.", s["body"]))
    else:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_gaps = sorted(gaps, key=lambda g: (sev_order.get(g.get("Severity", "Low"), 9), g.get("ControlId", "")))

        headers = ["ID", "Severity", "Title", "DC", "Actual vs Expected", "Frameworks"]
        rows = [headers]
        for g in sorted_gaps:
            sev  = g.get("Severity", "Low")
            rows.append([
                Paragraph(str(g.get("ControlId", "")),   s["body"]),
                _sev_badge(sev, s),
                Paragraph(str(g.get("Title", "")),        s["body"]),
                Paragraph(str(g.get("ComputerName", "")), s["body"]),
                Paragraph(f'<b>Actual:</b> {g.get("Actual","")}<br/>'
                          f'<b>Expected:</b> {g.get("Expected","")}', s["small"]),
                Paragraph(_frameworks_str(g.get("Frameworks", {})), s["small"]),
            ])

        col_w = [1.5*cm, 1.8*cm, 4.5*cm, 2.5*cm, 4.0*cm, 2.8*cm]
        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), BRAND_MID),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)

        # Remediation detail pages
        story.append(Spacer(1, 0.8 * cm))
        story.append(Paragraph("Remediation Details", s["h2"]))
        story.append(HRFlowable(width="100%", thickness=1, color=BRAND_MID))
        story.append(Spacer(1, 0.2 * cm))

        for g in sorted_gaps:
            sev  = g.get("Severity", "Low")
            bg   = SEV_COLORS.get(sev, colors.grey)
            detail_data = [[
                Paragraph(f'<b>{g.get("ControlId")} — {g.get("Title")}</b>', s["body"]),
                _sev_badge(sev, s),
            ]]
            detail_tbl = Table(detail_data, colWidths=[14.5*cm, 2.5*cm])
            detail_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), BRAND_LIGHT),
                ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
            ]))
            story.append(detail_tbl)
            story.append(Paragraph(
                f'<b>DC:</b> {g.get("ComputerName","—")}  '
                f'<b>Frameworks:</b> {_frameworks_str(g.get("Frameworks", {}))}',
                s["small"],
            ))
            story.append(Paragraph(
                f'<b>Expected:</b> {g.get("Expected","")}  |  <b>Actual:</b> {g.get("Actual","")}',
                s["small"],
            ))
            story.append(Paragraph(
                f'<b>Remediation:</b> {g.get("Remediation", "")}',
                s["remediation"],
            ))
            story.append(Spacer(1, 0.3 * cm))

    # ── Expiring certificates section ─────────────────────────────────────────
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph("Expiring Certificates", s["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_MID))
    story.append(Spacer(1, 0.2 * cm))

    if not certs:
        story.append(Paragraph("No certificates are expiring within the threshold window.", s["body"]))
    else:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_certs = sorted(
            certs,
            key=lambda c: (sev_order.get(c.get("Severity", "Low"), 9), c.get("DaysRemaining", 9999)),
        )
        headers = ["Severity", "Days Left", "Subject", "Issuer", "Source(s)", "Location(s)"]
        rows = [headers]
        for c in sorted_certs:
            days = c.get("DaysRemaining", 0)
            days_str = f"EXPIRED ({days})" if isinstance(days, (int, float)) and days < 0 else str(days)
            rows.append([
                _sev_badge(c.get("Severity", "Low"), s),
                Paragraph(days_str, s["body"]),
                Paragraph(str(c.get("Subject", "")), s["small"]),
                Paragraph(str(c.get("Issuer", "")), s["small"]),
                Paragraph(str(c.get("Sources", "")), s["small"]),
                Paragraph(textwrap.shorten(str(c.get("Locations", "")), 90), s["small"]),
            ])
        col_w = [1.8*cm, 1.8*cm, 4.0*cm, 3.2*cm, 2.4*cm, 3.9*cm]
        tbl = Table(rows, colWidths=col_w, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), BRAND_MID),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tbl)

    # ── Software inventory section ───────────────────────────────────────────
    story.append(Spacer(1, 0.6 * cm))
    story.append(Paragraph("Software Inventory", s["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_MID))
    story.append(Spacer(1, 0.2 * cm))

    if not software:
        story.append(Paragraph("No software inventory data in this scan.", s["body"]))
    else:
        hosts = {sw.get("ComputerName") for sw in software if sw.get("ComputerName")}
        story.append(Paragraph(
            f"{len(hosts)} host(s) inventoried, {len(software)} installed-software record(s).",
            s["body"],
        ))
        story.append(Spacer(1, 0.2 * cm))

        if vuln_sw:
            story.append(Paragraph(
                f"<font color='#c0392b'><b>{len(vuln_sw)} zero-day exposure hit(s) found in installed software:</b></font>",
                s["body"],
            ))
            vheaders = ["Host", "Category", "Software", "CVE", "Vulnerability"]
            vrows = [vheaders]
            for h in vuln_sw:
                vrows.append([
                    Paragraph(str(h.get("ComputerName", "")), s["small"]),
                    Paragraph(str(h.get("Category", "")), s["small"]),
                    Paragraph(f"{h.get('SoftwareName','')} {h.get('SoftwareVersion','')}", s["small"]),
                    Paragraph(str(h.get("CveId", "")), s["small"]),
                    Paragraph(str(h.get("VulnerabilityName", "")), s["small"]),
                ])
            vtbl = Table(vrows, colWidths=[3.2*cm, 2.2*cm, 5.0*cm, 2.8*cm, 3.9*cm], repeatRows=1)
            vtbl.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#c0392b")),
                ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
                ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",     (0, 0), (-1, 0), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
                ("GRID",         (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(vtbl)
            story.append(Spacer(1, 0.4 * cm))

        prod_counts: dict = {}
        for sw in software:
            name = sw.get("Name")
            if name:
                prod_counts[name] = prod_counts.get(name, 0) + 1
        top_products = sorted(prod_counts.items(), key=lambda kv: -kv[1])[:15]

        story.append(Paragraph("Top installed products", s["body"]))
        pheaders = ["Product", "Host count"]
        prows = [pheaders] + [[Paragraph(name, s["small"]), Paragraph(str(count), s["small"])]
                               for name, count in top_products]
        ptbl = Table(prows, colWidths=[13.0*cm, 4.0*cm], repeatRows=1)
        ptbl.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0), BRAND_MID),
            ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
            ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_LIGHT]),
            ("GRID",         (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ptbl)

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Paragraph(
        f"Generated by DC Anomaly Agent  •  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        s["small"],
    ))

    doc.build(story)
    return buf.getvalue()


# ── CSV ───────────────────────────────────────────────────────────────────────

def generate_csv_anomalies(scan_result: dict) -> str:
    buf = io.StringIO()
    anomalies = scan_result.get("Anomalies") or []
    w = csv.DictWriter(buf, fieldnames=["Type", "Account", "ComputerName", "TimeCreated", "Detail"])
    w.writeheader()
    for a in anomalies:
        w.writerow({
            "Type":         a.get("Type", ""),
            "Account":      a.get("Account", ""),
            "ComputerName": a.get("ComputerName", ""),
            "TimeCreated":  str(a.get("TimeCreated", ""))[:19],
            "Detail":       a.get("Detail", ""),
        })
    return buf.getvalue()


def generate_csv_compliance(scan_result: dict) -> str:
    buf = io.StringIO()
    gaps = scan_result.get("ComplianceGaps") or []
    w = csv.DictWriter(buf, fieldnames=[
        "ControlId", "Severity", "Title", "ComputerName",
        "Actual", "Expected", "Frameworks_CIS", "Frameworks_NIST",
        "Frameworks_ISO", "Remediation",
    ])
    w.writeheader()
    for g in gaps:
        fw = g.get("Frameworks") or {}
        w.writerow({
            "ControlId":       g.get("ControlId", ""),
            "Severity":        g.get("Severity", ""),
            "Title":           g.get("Title", ""),
            "ComputerName":    g.get("ComputerName", ""),
            "Actual":          g.get("Actual", ""),
            "Expected":        g.get("Expected", ""),
            "Frameworks_CIS":  fw.get("CIS", ""),
            "Frameworks_NIST": fw.get("NIST", ""),
            "Frameworks_ISO":  fw.get("ISO", ""),
            "Remediation":     g.get("Remediation", ""),
        })
    return buf.getvalue()


def generate_csv_certificates(scan_result: dict) -> str:
    buf = io.StringIO()
    certs = [c for c in (scan_result.get("ExpiringCertificates") or [])
             if c.get("DaysRemaining") is not None]
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    certs = sorted(certs, key=lambda c: (sev_order.get(c.get("Severity", "Low"), 9),
                                         c.get("DaysRemaining", 9999)))
    w = csv.DictWriter(buf, fieldnames=[
        "Severity", "DaysRemaining", "NotAfter", "Subject", "Issuer",
        "Sources", "Locations", "DnsNames", "Thumbprint",
    ])
    w.writeheader()
    for c in certs:
        w.writerow({
            "Severity":      c.get("Severity", ""),
            "DaysRemaining": c.get("DaysRemaining", ""),
            "NotAfter":      str(c.get("NotAfter", ""))[:19],
            "Subject":       c.get("Subject", ""),
            "Issuer":        c.get("Issuer", ""),
            "Sources":       c.get("Sources", ""),
            "Locations":     c.get("Locations", ""),
            "DnsNames":      c.get("DnsNames", ""),
            "Thumbprint":    c.get("Id", ""),
        })
    return buf.getvalue()


def generate_csv_software(scan_result: dict) -> str:
    buf = io.StringIO()
    software = [s for s in (scan_result.get("SoftwareInventory") or []) if not s.get("Error")]
    software = sorted(software, key=lambda s: (s.get("Category", ""), s.get("ComputerName", ""), s.get("Name", "")))
    w = csv.DictWriter(buf, fieldnames=[
        "ComputerName", "Category", "Name", "Version", "Publisher", "InstallDate", "Architecture",
    ])
    w.writeheader()
    for s in software:
        w.writerow({
            "ComputerName": s.get("ComputerName", ""),
            "Category":     s.get("Category", ""),
            "Name":         s.get("Name", ""),
            "Version":      s.get("Version", ""),
            "Publisher":    s.get("Publisher", ""),
            "InstallDate":  s.get("InstallDate", ""),
            "Architecture": s.get("Architecture", ""),
        })
    return buf.getvalue()

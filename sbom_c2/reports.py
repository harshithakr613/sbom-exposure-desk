"""
Audit report generation  (Capstone 1, Phase 5 — Report Generator)

Produces a downloadable PDF of the prioritised remediation queue, formatted as
audit-trail evidence: what was found, how it was ranked, and why. The scoring
weights are printed alongside the findings so a reader can reconstruct any
ranking from the report alone, which is what makes it usable as evidence rather
than merely a listing.

ReportLab is used when installed. When it is not, the module falls back to
generating a self-contained HTML report that any browser prints to PDF, so the
feature degrades rather than disappearing.
"""

import datetime as dt
import html
import io

try:  # pragma: no cover - environment dependent
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle)
    BACKEND = "reportlab"
except Exception:  # pragma: no cover
    BACKEND = "html"

TIER_COLOURS = {
    "CRITICAL": "#B91C1C", "HIGH": "#C2410C",
    "MEDIUM": "#A16207", "LOW": "#4D7C0F",
}


def _timestamp():
    return dt.datetime.now(dt.timezone.utc).strftime("%d %B %Y, %H:%M UTC")


def build_report(findings, impact, organisation, weights, limit=50):
    """
    Render the report. Returns (bytes, media_type, filename).

    findings: the prioritised queue, highest business score first
    impact:   the output of impact.compute_impact
    weights:  the scoring weights, printed so rankings are reproducible
    """
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M")
    if BACKEND == "reportlab":
        return (_pdf(findings, impact, organisation, weights, limit),
                "application/pdf",
                "remediation-report-%s.pdf" % stamp)
    return (_html(findings, impact, organisation, weights, limit).encode(),
            "text/html",
            "remediation-report-%s.html" % stamp)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def _pdf(findings, impact, organisation, weights, limit):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        leftMargin=14 * mm, rightMargin=14 * mm,
        topMargin=14 * mm, bottomMargin=14 * mm,
        title="Business-Context-Aware Remediation Report")

    styles = getSampleStyleSheet()
    title = ParagraphStyle("t", parent=styles["Title"], fontSize=17, spaceAfter=4)
    sub = ParagraphStyle("s", parent=styles["Normal"], fontSize=9,
                         textColor=colors.HexColor("#555555"), spaceAfter=10)
    heading = ParagraphStyle("h", parent=styles["Heading2"], fontSize=11,
                             spaceBefore=10, spaceAfter=5)
    small = ParagraphStyle("sm", parent=styles["Normal"], fontSize=8,
                           textColor=colors.HexColor("#555555"))

    story = [
        Paragraph("Business-Context-Aware Remediation Report", title),
        Paragraph("Organisation: %s &nbsp;&nbsp;|&nbsp;&nbsp; Generated: %s"
                  % (html.escape(str(organisation)), _timestamp()), sub),
    ]

    ops = (impact or {}).get("operations", {})
    biz = (impact or {}).get("business", {})
    summary = [
        ["Open findings", ops.get("open", "-"),
         "Business risk open", biz.get("business_risk_open", "-")],
        ["Resolved", ops.get("resolved", "-"),
         "Business risk eliminated", biz.get("business_risk_eliminated", "-")],
        ["Fix rate", ops.get("fix_rate", "-"),
         "Processes protected", biz.get("processes_protected", "-")],
        ["Mean time to remediate (h)", ops.get("mttr_hours", "not yet measurable"),
         "Processes at risk", biz.get("processes_at_risk", "-")],
    ]
    table = Table(summary, colWidths=[58 * mm, 32 * mm, 62 * mm, 32 * mm])
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#555555")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor("#DDDDDD")),
    ]))
    story += [Paragraph("Summary", heading), table]

    story.append(Paragraph("Prioritised remediation queue", heading))
    rows = [["#", "Repository", "Business process", "CVE", "Component",
             "CVSS", "EPSS", "Crit.", "Score", "Tier"]]
    for i, f in enumerate(findings[:limit], 1):
        contributions = (f.get("explanation") or {}).get("contributions", {})
        rows.append([
            str(i),
            _clip(f.get("repository"), 26),
            _clip(f.get("business_process") or "unmapped", 24),
            _clip(f.get("cve_id") or f.get("advisory_id"), 17),
            _clip("%s %s" % (f.get("component") or "", f.get("version") or ""), 26),
            _fmt(contributions.get("cvss")),
            _fmt(contributions.get("epss")),
            _fmt(contributions.get("criticality")),
            _fmt(f.get("business_score")),
            f.get("tier") or "-",
        ])

    queue = Table(rows, repeatRows=1,
                  colWidths=[9 * mm, 40 * mm, 38 * mm, 30 * mm, 42 * mm,
                             15 * mm, 15 * mm, 15 * mm, 17 * mm, 22 * mm])
    style = [
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (5, 0), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E0E0E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, f in enumerate(findings[:limit], 1):
        colour = TIER_COLOURS.get(f.get("tier"))
        if colour:
            style.append(("TEXTCOLOR", (9, i), (9, i), colors.HexColor(colour)))
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i),
                          colors.HexColor("#FAFAFA")))
    queue.setStyle(TableStyle(style))
    story.append(queue)

    story += [
        Spacer(1, 8),
        Paragraph(
            "Scoring model: composite = (CVSS x %.2f) + (EPSS x %.2f) + "
            "(derived criticality x %.2f), multiplied by a compliance factor of "
            "1.0 plus 0.10 per regulatory regime, capped at 1.25. Criticality is "
            "derived from business process attributes recorded against each "
            "repository, not manually assigned. Columns CVSS, EPSS and Crit. "
            "show each factor's contribution to the final score, so any ranking "
            "in this report can be reconstructed independently."
            % (weights.get("cvss", 0.5), weights.get("epss", 0.3),
               weights.get("criticality", 0.2)), small),
        Spacer(1, 4),
        Paragraph(
            "Generated by the SBOM-Based Zero-Day Exposure Impact Analyzer. "
            "Prepared as audit-trail evidence aligned with ISO/IEC 27001 "
            "documentation practice and NIST SP 800-218.", small),
    ]

    doc.build(story)
    return buffer.getvalue()


def _clip(text, width):
    text = str(text or "")
    return text if len(text) <= width else text[: width - 1] + "\u2026"


def _fmt(value):
    return "-" if value is None else ("%.2f" % value)


# ---------------------------------------------------------------------------
# HTML fallback
# ---------------------------------------------------------------------------

def _html(findings, impact, organisation, weights, limit):
    ops = (impact or {}).get("operations", {})
    biz = (impact or {}).get("business", {})

    rows = []
    for i, f in enumerate(findings[:limit], 1):
        c = (f.get("explanation") or {}).get("contributions", {})
        rows.append(
            "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s %s</td>"
            "<td class=n>%s</td><td class=n>%s</td><td class=n>%s</td>"
            "<td class=n><b>%s</b></td><td style='color:%s'>%s</td></tr>" % (
                i, html.escape(str(f.get("repository") or "")),
                html.escape(str(f.get("business_process") or "unmapped")),
                html.escape(str(f.get("cve_id") or f.get("advisory_id") or "")),
                html.escape(str(f.get("component") or "")),
                html.escape(str(f.get("version") or "")),
                _fmt(c.get("cvss")), _fmt(c.get("epss")),
                _fmt(c.get("criticality")), _fmt(f.get("business_score")),
                TIER_COLOURS.get(f.get("tier"), "#333"),
                html.escape(str(f.get("tier") or "-"))))

    return """<!doctype html><meta charset=utf-8>
<title>Remediation Report</title>
<style>
body{font:13px/1.5 system-ui,sans-serif;margin:28px;color:#1a1a2e}
h1{font-size:20px;margin:0 0 2px}
.sub{color:#666;font-size:12px;margin-bottom:18px}
table{border-collapse:collapse;width:100%%;font-size:11.5px}
th{background:#1a1a2e;color:#fff;text-align:left;padding:6px}
td{border-bottom:1px solid #eee;padding:5px 6px}
td.n{text-align:right}
.kpi{display:flex;gap:26px;flex-wrap:wrap;margin-bottom:18px}
.kpi div{min-width:130px}
.kpi span{display:block;color:#666;font-size:11px}
.kpi b{font-size:17px}
footer{margin-top:16px;color:#666;font-size:11px}
@media print{body{margin:0}}
</style>
<h1>Business-Context-Aware Remediation Report</h1>
<div class=sub>Organisation: %s &nbsp;|&nbsp; Generated: %s</div>
<div class=kpi>
<div><span>Open findings</span><b>%s</b></div>
<div><span>Resolved</span><b>%s</b></div>
<div><span>Fix rate</span><b>%s</b></div>
<div><span>Mean time to remediate</span><b>%s</b></div>
<div><span>Business risk open</span><b>%s</b></div>
<div><span>Business risk eliminated</span><b>%s</b></div>
</div>
<table><tr><th>#</th><th>Repository</th><th>Business process</th><th>CVE</th>
<th>Component</th><th>CVSS</th><th>EPSS</th><th>Crit.</th><th>Score</th><th>Tier</th></tr>
%s</table>
<footer>Composite = (CVSS &times; %.2f) + (EPSS &times; %.2f) + (derived criticality
&times; %.2f), multiplied by a compliance factor of 1.0 plus 0.10 per regulatory
regime, capped at 1.25. Criticality is derived from recorded business process
attributes, not manually assigned. Print this page to PDF for filing.</footer>
""" % (html.escape(str(organisation)), _timestamp(),
       ops.get("open", "-"), ops.get("resolved", "-"),
       ops.get("fix_rate", "-"), ops.get("mttr_hours", "not yet measurable"),
       biz.get("business_risk_open", "-"), biz.get("business_risk_eliminated", "-"),
       "\n".join(rows), weights.get("cvss", 0.5), weights.get("epss", 0.3),
       weights.get("criticality", 0.2))

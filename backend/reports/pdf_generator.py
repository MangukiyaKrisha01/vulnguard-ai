"""
VulnGuard AI - PDF Report Generator
Builds a professional, multi-section PDF report for a completed scan.
"""
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#dc2626"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#64748b"),
}


def generate_pdf_report(scan, findings, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4,
                             topMargin=2 * cm, bottomMargin=2 * cm,
                             leftMargin=1.8 * cm, rightMargin=1.8 * cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=colors.HexColor("#0f172a"))
    h2 = ParagraphStyle("H2X", parent=styles["Heading2"], textColor=colors.HexColor("#1e293b"), spaceBefore=12)
    body = ParagraphStyle("BodyX", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("SmallX", parent=styles["BodyText"], fontSize=8, textColor=colors.grey)

    story = []

    story.append(Paragraph("VulnGuard AI — Vulnerability Assessment Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: {scan.target_url}", body))
    story.append(Paragraph(f"Scan ID: {scan.id} &nbsp;&nbsp;|&nbsp;&nbsp; Scan Type: {scan.scan_type} "
                            f"&nbsp;&nbsp;|&nbsp;&nbsp; Depth: {scan.scan_depth}", body))
    story.append(Paragraph(f"Started: {scan.started_at.strftime('%Y-%m-%d %H:%M UTC') if scan.started_at else 'N/A'} "
                            f"&nbsp;&nbsp;|&nbsp;&nbsp; Completed: "
                            f"{scan.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan.completed_at else 'N/A'}", body))
    story.append(Paragraph(f"Pages Crawled: {scan.pages_crawled}", body))
    story.append(Spacer(1, 14))

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2))
    counts = scan.severity_counts()
    summary_text = (
        f"This report documents the results of an automated OWASP Top-10-aligned vulnerability scan "
        f"performed against {scan.target_url}. The scan identified <b>{len(findings)}</b> total finding(s): "
        f"<b>{counts.get('Critical',0)} Critical</b>, <b>{counts.get('High',0)} High</b>, "
        f"<b>{counts.get('Medium',0)} Medium</b>, <b>{counts.get('Low',0)} Low</b>, and "
        f"<b>{counts.get('Informational',0)} Informational</b> severity issues. "
        f"Findings should be triaged starting with Critical and High severity items, validated manually, "
        f"and remediated according to the guidance provided per finding below."
    )
    story.append(Paragraph(summary_text, body))
    story.append(Spacer(1, 10))

    # Severity breakdown table
    sev_table_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in counts.items()]
    sev_table = Table(sev_table_data, colWidths=[8 * cm, 4 * cm])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
    ]))
    story.append(sev_table)
    story.append(PageBreak())

    # Vulnerability table (overview)
    story.append(Paragraph("Findings Overview", h2))
    overview_data = [["#", "Title", "Severity", "CVSS", "OWASP"]]
    for i, f in enumerate(findings, 1):
        overview_data.append([str(i), Paragraph(f.title, small), f.severity, str(f.cvss_score),
                               Paragraph(f.owasp_mapping, small)])
    overview_table = Table(overview_data, colWidths=[1 * cm, 6.5 * cm, 2.2 * cm, 1.5 * cm, 5.3 * cm], repeatRows=1)
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(overview_table)
    story.append(PageBreak())

    # Detailed findings
    story.append(Paragraph("Detailed Findings", h2))
    for i, f in enumerate(findings, 1):
        sev_color = SEVERITY_COLORS.get(f.severity, colors.grey)
        header_style = ParagraphStyle(f"FindingHeader{i}", parent=styles["Heading3"], textColor=sev_color)
        story.append(Paragraph(f"{i}. {f.title}  [{f.severity} — CVSS {f.cvss_score}]", header_style))
        story.append(Paragraph(f"<b>Affected URL:</b> {f.affected_url}", body))
        story.append(Paragraph(f"<b>OWASP Mapping:</b> {f.owasp_mapping}", body))
        story.append(Paragraph(f"<b>Description:</b> {f.description}", body))
        story.append(Paragraph(f"<b>Risk Explanation:</b> {f.risk_explanation}", body))
        story.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", body))
        if f.ai_insight:
            story.append(Paragraph(f"<b>AI Security Insight:</b> {f.ai_insight}", body))
        if f.evidence:
            story.append(Paragraph(f"<b>Evidence:</b> {f.evidence}", small))
        story.append(Spacer(1, 10))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Disclaimer: This report was generated by an automated scanning tool against a target explicitly "
        "authorized for security testing. Automated findings may include false positives and should be "
        "manually validated before remediation prioritization or disclosure.", small))
    story.append(Paragraph(f"Report generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} by VulnGuard AI",
                            small))

    doc.build(story)
    return output_path

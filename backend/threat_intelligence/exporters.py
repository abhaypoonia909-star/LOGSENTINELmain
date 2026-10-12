"""Export helpers that turn a report into JSON, CSV, or PDF bytes.

PDF generation degrades gracefully: if no PDF engine is installed, a plain-text
report is returned so the endpoint never fails hard.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any


def to_json_bytes(report: dict[str, Any]) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def to_csv_bytes(report: dict[str, Any]) -> bytes:
    """Serialize every export sheet into a single multi-section CSV."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    sheets = report.get("export", {}).get("csv_sheets", {})

    for name, sheet in sheets.items():
        writer.writerow([f"# {name.upper()}"])
        writer.writerow(sheet.get("columns", []))
        for row in sheet.get("rows", []):
            writer.writerow(row)
        writer.writerow([])  # blank separator between sections

    return buffer.getvalue().encode("utf-8")


def to_pdf_bytes(report: dict[str, Any]) -> bytes:
    """Render a simple PDF; fall back to text bytes if no engine is available."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        )
        from reportlab.lib import colors
    except ImportError:
        return _text_fallback(report)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="Threat Intelligence Report")
    styles = getSampleStyleSheet()
    story: list[Any] = [
        Paragraph("CyberShield AI — Threat Intelligence Report", styles["Title"]),
        Paragraph(f"Generated: {report.get('generated_at', 'N/A')}", styles["Normal"]),
        Spacer(1, 12),
    ]

    stats = report.get("statistics", {})
    story.append(Paragraph("Attack Statistics", styles["Heading2"]))
    stat_rows = [[k.replace("_", " ").title(), str(v)] for k, v in stats.items()]
    if stat_rows:
        table = Table([["Metric", "Value"], *stat_rows], hAlign="LEFT")
        table.setStyle(_table_style())
        story.append(table)
    story.append(Spacer(1, 12))

    for section_key, title in (
        ("mitre_attack", "MITRE ATT&CK Mapping"),
        ("owasp_top10", "OWASP Top 10 Mapping"),
    ):
        rows = report.get(section_key, [])
        if not rows:
            continue
        story.append(Paragraph(title, styles["Heading2"]))
        for row in rows:
            label = row.get("technique_id") or row.get("category_id", "")
            name = row.get("technique_name") or row.get("category", "")
            story.append(Paragraph(f"<b>{label}</b> — {name}", styles["Normal"]))
        story.append(Spacer(1, 12))

    doc.build(story)
    return buffer.getvalue()


def _table_style():
    from reportlab.lib import colors
    from reportlab.platypus import TableStyle
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2a44")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ])


def _text_fallback(report: dict[str, Any]) -> bytes:
    lines = ["CyberShield AI — Threat Intelligence Report",
             f"Generated: {report.get('generated_at', 'N/A')}", ""]
    stats = report.get("statistics", {})
    for key, value in stats.items():
        lines.append(f"{key.replace('_', ' ').title()}: {value}")
    return "\n".join(lines).encode("utf-8")
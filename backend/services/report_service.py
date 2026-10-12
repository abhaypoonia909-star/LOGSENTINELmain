import io
import json
from collections import Counter
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from config import Config
from services.attack_wise import build_attack_wise, summarize_attacks
from services.incident_correlation import correlate_incidents


class ReportService:
    """
    Enterprise Security Report Generator.

    Backward compatibility:
    - Preserves existing `build()` return signature: (report_dict, report_path)
    - Preserves existing keys used by API/front-end:
      analysis_id, summary, risk_score, threat_details, recommendations, analysis
    - Adds new report fields without removing old ones.
    """

    # MITRE ATT&CK mapping by threat category/pattern
    _MITRE_MAP = {
        "Brute Force": ["T1110 - Brute Force"],
        "Port Scan": ["T1046 - Network Service Discovery"],
        "Intrusion": ["T1190 - Exploit Public-Facing Application"],
        "Critical Event": ["T1068 - Exploitation for Privilege Escalation"],
        "Malware Indicator": ["T1105 - Ingress Tool Transfer", "T1059 - Command and Scripting Interpreter"],
        "SQL Injection": ["T1190 - Exploit Public-Facing Application"],
        "Cross-Site Scripting (XSS)": ["T1059.007 - JavaScript"],
        "Directory Traversal": ["T1005 - Data from Local System"],
        "Command Injection": ["T1059 - Command and Scripting Interpreter"],
        "Reverse Shell": ["T1059 - Command and Scripting Interpreter", "T1071 - Application Layer Protocol"],
        "Suspicious PowerShell": ["T1059.001 - PowerShell"],
        "Web Shell": ["T1505.003 - Web Shell"],
        "Privilege Escalation / Unauthorized Access": ["T1068 - Exploitation for Privilege Escalation"],
    }

    # OWASP Top 10 mapping by threat category/pattern
    _OWASP_MAP = {
        "Brute Force": ["A07:2021 - Identification and Authentication Failures"],
        "Port Scan": ["A05:2021 - Security Misconfiguration"],
        "Intrusion": ["A03:2021 - Injection", "A01:2021 - Broken Access Control"],
        "Critical Event": ["A04:2021 - Insecure Design"],
        "Malware Indicator": ["A08:2021 - Software and Data Integrity Failures"],
        "SQL Injection": ["A03:2021 - Injection"],
        "Cross-Site Scripting (XSS)": ["A03:2021 - Injection"],
        "Directory Traversal": ["A01:2021 - Broken Access Control"],
        "Command Injection": ["A03:2021 - Injection"],
        "Reverse Shell": ["A03:2021 - Injection"],
        "Suspicious PowerShell": ["A03:2021 - Injection"],
        "Web Shell": ["A03:2021 - Injection", "A08:2021 - Software and Data Integrity Failures"],
        "Privilege Escalation / Unauthorized Access": ["A01:2021 - Broken Access Control"],
    }

    def build(self, analysis_record, analysis_data: dict) -> tuple[dict[str, Any], str]:
        """
        Build full JSON report and persist it to reports/report_<analysis_id>.json.
        """
        threats = analysis_data.get("threats", []) or []
        confidence = self._derive_confidence(analysis_record, analysis_data)

        # Keep old recommendations logic and extend it with targeted advice.
        recommendations = self._build_recommendations(analysis_data, threats)

        # Existing summary payload kept intact.
        summary = {
            "filename": analysis_record.file.original_name,
            "risk_score": analysis_record.risk_score,
            "severity": analysis_record.severity,
            "threat_count": analysis_record.threat_count,
            "total_lines": analysis_record.total_lines,
        }

        # New enterprise sections
        threat_summary = self._build_threat_summary(threats)
        top_attacker_ips = self._top_attacker_ips(threats, analysis_data)
        mitre_mapping = self._build_mitre_mapping(threats)
        owasp_mapping = self._build_owasp_mapping(threats)
        executive_summary = self._build_executive_summary(summary, threat_summary, confidence)
        security_conclusion = self._build_security_conclusion(summary, confidence, threat_summary)

        report = {
            # ---- Backward-compatible fields (existing API contract) ----
            "analysis_id": analysis_record.id,
            "summary": summary,
            "risk_score": analysis_record.risk_score,
            "threat_details": threats,
            "recommendations": recommendations,
            "analysis": analysis_data,

            # ---- New professional sections (additive only) ----
            "executive_summary": executive_summary,
            "severity": analysis_record.severity,
            "confidence_score": confidence,
            "threat_summary": threat_summary,
            "top_attacker_ips": top_attacker_ips,
            "mitre_attack_mapping": mitre_mapping,
            "owasp_top_10_mapping": owasp_mapping,
            "security_conclusion": security_conclusion,
        }

        Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
        path = Config.REPORT_DIR / f"report_{analysis_record.id}.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return report, str(path)

    def build_preview(self, analysis_data: dict, filename: str, fmt: str) -> str:
        """
        Backward-compatible text preview used by current UI flows.
        Kept as plain text to avoid breaking existing frontend behavior.
        """
        lines = [
            "=" * 60,
            "LOGSENTINEL ANALYSIS REPORT",
            "=" * 60,
            f"File: {filename}",
            f"Format: {fmt}",
            f"Risk Score: {analysis_data.get('risk_score', 0)}/100",
            f"Severity: {str(analysis_data.get('severity', 'low')).upper()}",
            f"Confidence: {analysis_data.get('confidence', 65)}%",
            f"Threats: {len(analysis_data.get('threats', []))}",
            "",
            "RECOMMENDATIONS",
            "-" * 60,
        ]

        # Preserve existing preview structure
        for t in analysis_data.get("threats", [])[:20]:
            lines.append(
                f"- [{str(t.get('severity', '')).upper()}] "
                f"{t.get('category')}: "
                f"{t.get('message', t.get('description', ''))}"
            )

        if len(lines) == 10:
            lines.append("- No immediate action required. Continue monitoring.")

        lines.extend([
            "",
            "=" * 60,
            "End of Report",
        ])
        return "\n".join(lines)

    def build_pdf_bytes(self, analysis_record, analysis_data: dict) -> bytes:
        """Professional attack-wise PDF. Escapes untrusted log evidence."""
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            Preformatted,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        attack_wise = analysis_data.get("attack_wise")
        if not isinstance(attack_wise, dict) or "attacks" not in attack_wise:
            attack_wise = build_attack_wise(analysis_data)
        incidents_payload = analysis_data.get("incidents")
        if not isinstance(incidents_payload, dict) or "incidents" not in incidents_payload:
            incidents_payload = correlate_incidents(analysis_data)

        filename = "uploaded log"
        if getattr(analysis_record, "file", None) is not None:
            filename = str(analysis_record.file.original_name or filename)
        generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "LSTitle", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#0f172a"),
            spaceAfter=6, alignment=TA_LEFT,
        )
        h1 = ParagraphStyle(
            "LSH1", parent=styles["Heading1"], fontSize=13, textColor=colors.HexColor("#0f172a"),
            spaceBefore=14, spaceAfter=8,
        )
        h2 = ParagraphStyle(
            "LSH2", parent=styles["Heading2"], fontSize=11, textColor=colors.HexColor("#1e3a5f"),
            spaceBefore=10, spaceAfter=6,
        )
        body = ParagraphStyle(
            "LSBody", parent=styles["Normal"], fontSize=9, leading=13, alignment=TA_JUSTIFY,
        )
        meta = ParagraphStyle(
            "LSMeta", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#475569"),
        )
        evidence_style = ParagraphStyle(
            "LSEvidence", parent=styles["Code"], fontName="Courier", fontSize=7.5,
            leading=10, backColor=colors.HexColor("#f1f5f9"), borderPadding=4,
            textColor=colors.HexColor("#0f172a"),
        )

        def p(text: str, style=body) -> Paragraph:
            return Paragraph(xml_escape(str(text or "")), style)

        summary = attack_wise.get("summary")
        if not isinstance(summary, dict) or "rows" not in summary:
            summary = summarize_attacks(attack_wise)

        story: list[Any] = [
            Paragraph("LogSentinel Attack Summary Report", title_style),
            p(f"Generated {generated}  ·  File: {filename}", meta),
            Spacer(1, 8),
            Paragraph("Overall Summary", h1),
            p(
                f"Risk score {getattr(analysis_record, 'risk_score', analysis_data.get('risk_score', 0))}/100 "
                f"({str(getattr(analysis_record, 'severity', analysis_data.get('severity', 'unknown'))).upper()}). "
                f"Detected {summary.get('total_events', attack_wise.get('total_events', 0))} event(s) across "
                f"{summary.get('distinct_attack_types', attack_wise.get('distinct_attack_types', 0))} distinct attack type(s). "
                "Counts come from the LogSentinel detection engine. Missing IP addresses "
                "are shown as Not available — they are not invented."
            ),
            Spacer(1, 8),
            Paragraph("Attack Summary", h1),
        ]

        summary_rows = [["Attack Type", "Attempts", "Severity", "Source IP Address"]]
        for row in summary.get("rows") or []:
            summary_rows.append([
                p(str(row.get("attack_type") or "Unknown Attack")),
                str(row.get("attempts") or 0),
                p(str(row.get("severity") or "Not available").upper() if row.get("severity") else "Not available"),
                p(str(row.get("source_ip_display") or "Not available")),
            ])
        if len(summary_rows) == 1:
            summary_rows.append(["None", "0", "Not available", "Not available"])
        table = Table(summary_rows, colWidths=[150, 58, 72, 160])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 1), (1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(table)

        incidents = incidents_payload.get("incidents") or []
        incident_summary = incidents_payload.get("summary") or {}
        story.append(Spacer(1, 12))
        story.append(Paragraph("Incident Correlation Summary", h1))
        story.append(p(
            f"{incident_summary.get('total_incidents', 0)} investigation item(s), including "
            f"{incident_summary.get('possible_correlations', 0)} possible correlation(s), from "
            f"{incident_summary.get('confirmed_findings', 0)} confirmed detector finding(s). "
            f"{incident_summary.get('disclaimer', '')}"
        ))
        incident_rows = [["Incident", "Severity", "Risk", "Events", "Status"]]
        for incident in incidents:
            incident_rows.append([
                xml_escape(str(incident.get("incident_id") or "")),
                xml_escape(str(incident.get("severity") or "not present")),
                str(incident.get("risk_score") if incident.get("risk_score") is not None else "not present"),
                str(incident.get("event_count") or 0),
                xml_escape(str(incident.get("correlation_status") or "")),
            ])
        if len(incident_rows) == 1:
            incident_rows.append(["None", "—", "—", "0", "—"])
        incident_table = Table(incident_rows, colWidths=[72, 72, 52, 52, 150])
        incident_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(incident_table)

        for incident in incidents:
            story.append(Paragraph(
                xml_escape(
                    f"{incident.get('incident_id')} — {incident.get('title')} "
                    f"(risk {incident.get('risk_score')}/100)"
                ),
                h2,
            ))
            story.append(p(incident.get("assessment") or "No assessment available."))
            reasons = "; ".join(incident.get("correlation_reasons") or [])
            story.append(p(f"Correlation basis: {reasons or 'not present'}"))
            factors = "; ".join(
                f"{factor.get('factor')} (+{factor.get('points', 0)})"
                for factor in incident.get("risk_factors") or []
            )
            story.append(p(f"Risk factors: {factors or 'not present'}"))
            story.append(p("Incident timeline:"))
            for event in incident.get("timeline") or []:
                story.append(p(
                    f"{event.get('timestamp') or 'not present'} · "
                    f"{event.get('attack_name') or 'Unknown Attack'} · "
                    f"{event.get('severity') or 'not present'} · "
                    f"IP {event.get('source_ip') or 'not present'}"
                ))
                story.append(Preformatted(
                    xml_escape(event.get("evidence") or "not present"),
                    evidence_style,
                ))
            story.append(p("Investigation steps:"))
            for step in incident.get("investigation_steps") or []:
                story.append(p(f"• {step}"))
            story.append(p("Remediation recommendations:"))
            for recommendation in incident.get("recommendations") or []:
                story.append(p(f"• {recommendation}"))

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            title="LogSentinel Attack Summary Report",
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=16 * mm,
            bottomMargin=16 * mm,
        )
        # Keep streams uncompressed so reports remain searchable and testable.
        doc.pageCompression = 0
        doc.build(story)
        return buffer.getvalue()

    # ------------------------------------------------------------------
    # Helper functions
    # ------------------------------------------------------------------

    def _derive_confidence(self, analysis_record, analysis_data: dict) -> int:
        """
        Prefer analyzer-provided confidence; otherwise compute from signal strength.
        """
        provided = analysis_data.get("confidence")
        if isinstance(provided, (int, float)):
            return max(0, min(100, int(provided)))

        threat_count = int(getattr(analysis_record, "threat_count", 0) or 0)
        total_lines = int(getattr(analysis_record, "total_lines", 0) or 0)
        risk_score = int(getattr(analysis_record, "risk_score", 0) or 0)

        # Conservative heuristic confidence.
        detector_density = min(1.0, threat_count / max(total_lines, 1) * 100)
        confidence = int(min(100, 45 + (risk_score * 0.35) + (detector_density * 20)))
        return max(30, confidence)

    def _build_recommendations(self, analysis_data: dict, threats: list[dict]) -> list[str]:
        recommendations: list[str] = []

        # Preserve existing logic
        if analysis_data.get("brute_force", {}).get("flagged_ips"):
            recommendations.append("Block flagged IPs and enable fail2ban.")

        if analysis_data.get("intrusion", {}).get("event_count", 0) > 0:
            recommendations.append("Review WAF rules and sanitize user inputs.")

        if analysis_data.get("port_scan", {}).get("event_count", 0) > 0:
            recommendations.append("Restrict exposed ports and monitor reconnaissance traffic.")

        # Add targeted recommendations from threats
        for t in threats:
            rec = t.get("recommendation")
            if rec and rec not in recommendations:
                recommendations.append(rec)

        if not recommendations:
            recommendations.append("No immediate action required. Continue monitoring.")

        return recommendations[:12]

    def _build_threat_summary(self, threats: list[dict]) -> dict[str, Any]:
        by_severity = Counter(str(t.get("severity", "low")).lower() for t in threats)
        by_category = Counter(str(t.get("category", "Unknown")) for t in threats)

        return {
            "total_threats": len(threats),
            "severity_breakdown": {
                "critical": by_severity.get("critical", 0),
                "high": by_severity.get("high", 0),
                "medium": by_severity.get("medium", 0),
                "low": by_severity.get("low", 0),
            },
            "category_breakdown": dict(by_category),
        }

    def _top_attacker_ips(self, threats: list[dict], analysis_data: dict) -> list[dict[str, Any]]:
        ip_counter = Counter()

        # Count from flattened threat list
        for t in threats:
            ip = t.get("source_ip")
            if ip:
                ip_counter[str(ip)] += 1

        # Include brute-force IP counts if present
        for ip_info in analysis_data.get("brute_force", {}).get("flagged_ips", []):
            ip = ip_info.get("ip_address")
            attempts = int(ip_info.get("attempt_count", 1))
            if ip:
                ip_counter[str(ip)] += attempts

        return [{"ip": ip, "events": count} for ip, count in ip_counter.most_common(10)]

    def _build_mitre_mapping(self, threats: list[dict]) -> list[str]:
        mapped: set[str] = set()
        for t in threats:
            category = str(t.get("category", ""))
            title = str(t.get("title", ""))
            for key, tactics in self._MITRE_MAP.items():
                if key.lower() in category.lower() or key.lower() in title.lower():
                    mapped.update(tactics)
        return sorted(mapped)

    def _build_owasp_mapping(self, threats: list[dict]) -> list[str]:
        mapped: set[str] = set()
        for t in threats:
            # Prefer explicit owasp tag from analyzer if present
            explicit = t.get("owasp")
            if explicit:
                mapped.add(str(explicit))
                continue

            category = str(t.get("category", ""))
            title = str(t.get("title", ""))
            for key, entries in self._OWASP_MAP.items():
                if key.lower() in category.lower() or key.lower() in title.lower():
                    mapped.update(entries)
        return sorted(mapped)

    def _build_executive_summary(
        self,
        summary: dict[str, Any],
        threat_summary: dict[str, Any],
        confidence: int,
    ) -> str:
        return (
            f"Log file '{summary.get('filename')}' was analyzed with risk score "
            f"{summary.get('risk_score', 0)}/100 ({str(summary.get('severity', 'low')).upper()}). "
            f"Detected {threat_summary.get('total_threats', 0)} security events. "
            f"Assessment confidence is {confidence}%."
        )

    def _build_security_conclusion(
        self,
        summary: dict[str, Any],
        confidence: int,
        threat_summary: dict[str, Any],
    ) -> str:
        score = int(summary.get("risk_score", 0))
        sev = str(summary.get("severity", "low")).lower()
        critical_count = threat_summary.get("severity_breakdown", {}).get("critical", 0)

        if score >= 80 or sev == "critical" or critical_count > 0:
            return (
                "Critical security posture. Immediate incident response is recommended, "
                "including containment, threat hunting, and forensic evidence preservation."
            )
        if score >= 60 or sev == "high":
            return (
                "High risk posture. Prioritize remediation of identified attack paths and "
                "increase monitoring for lateral movement and persistence."
            )
        if score >= 40 or sev == "medium":
            return (
                "Moderate risk posture. Address exposed weaknesses and harden controls to "
                "prevent escalation."
            )
        return (
            "Low risk posture. No active critical threats observed, but continue continuous "
            "monitoring and periodic security validation."
        )
import json
from threat_intelligence.service import ThreatIntelligenceService
_threat_intel_service = ThreatIntelligenceService()
from datetime import datetime
from flask import Blueprint, request, jsonify, g
from config import Config
from models import db
from models.models import UploadedFile, Analysis, Threat, Report
from services.log_parser import LogParser
from services.log_analyzer import LogAnalyzer
from services.chart_service import ChartService
from services.report_service import ReportService
from services.ai_service import AIService
from services.incident_correlation import correlate_incidents
from utils.validators import validate_log_extension
from utils.security import save_upload
from utils.jwt_utils import require_jwt
from utils.transfer_encoding import TransferDecodeError, read_upload_bytes

analysis_bp = Blueprint("analysis", __name__)

def _persist_analysis(filename, stored_name, fmt, parser, result, charts, report_text):
    user_id = g.current_user["id"] if getattr(g, "current_user", None) else None

    file_row = UploadedFile(
        user_id=user_id,
        original_name=filename,
        stored_name=stored_name,
        file_format=fmt,
    )
    db.session.add(file_row)
    db.session.flush()

    analysis_row = Analysis(
        user_id=user_id,
        file_id=file_row.id,
        risk_score=result["risk_score"],
        severity=result["severity"],
        total_lines=result["stats"]["total_lines"],
        threat_count=len(result["threats"]),
        result_json=json.dumps(result),
    )
    db.session.add(analysis_row)
    db.session.flush()

    for t in result["threats"]:
        db.session.add(Threat(
            analysis_id=analysis_row.id,
            category=t["category"],
            severity=t["severity"],
            source_ip=t.get("source_ip"),
            message=t.get("message"),
            path=t.get("path"),
            timestamp=t.get("timestamp"),
        ))

    report_payload, json_path = ReportService().build(analysis_row, result)
    db.session.add(Report(
        analysis_id=analysis_row.id,
        summary=json.dumps(report_payload["summary"]),
        recommendations=json.dumps(report_payload["recommendations"]),
        json_path=json_path,
    ))
    db.session.commit()
    return analysis_row, report_text

@analysis_bp.post("/analyze")
@require_jwt
def analyze_log():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "Upload a file using form field 'file'."}), 400
    if not validate_log_extension(f.filename):
        return jsonify({"error": "Only .log, .txt, .json files are allowed."}), 400

    # The browser may base64-encode the file in transit so hosting firewalls do
    # not block logs that legitimately contain attack strings. The decoded size
    # is still held to MAX_CONTENT_LENGTH (existing 413 handler).
    try:
        raw = read_upload_bytes(f, max_bytes=Config.MAX_CONTENT_LENGTH)
    except TransferDecodeError as exc:
        return jsonify({"error": str(exc)}), 400
    if not raw.strip():
        return jsonify({"error": "Uploaded file is empty."}), 400

    content = raw.decode("utf-8", errors="replace")
    stored_name, _ = save_upload(f.filename, raw)

    parser = LogParser()
    df = parser.parse(content)

    # Run Log Analyzer
    result = LogAnalyzer(df).analyze()
    # Additive investigation view. Detector and attack-wise findings are not
    # changed, deleted, or deduplicated.
    result["incidents"] = correlate_incidents(result)

    # -----------------------------
    # AI Security Assistant
    # -----------------------------
    try:
        ai_service = AIService()
        result["ai_analysis"] = ai_service.analyze_security(result)
    except Exception as e:
        print("AIService Error:", e)

        result["ai_analysis"] = {
            "executive_ai_summary": "AI analysis unavailable.",
            "threat_explanation": "",
            "attack_chain_description": "",
            "business_impact": "",
            "recommended_actions": [],
            "mitre_attack_techniques": [],
            "owasp_top_10_mapping": [],
            "confidence_score": 0,
            "incident_priority": "P4 - Low",
            "next_investigation_steps": []
        }

    # -----------------------------
    # Threat Intelligence
    # -----------------------------
    try:
        parsed_events = df.to_dict(orient="records")
        threat_intelligence = _threat_intel_service.build_report(parsed_events)
        threat_intelligence.pop("export", None)
    except Exception as e:
        print("Threat Intelligence Error:", e)
        threat_intelligence = {
            "error": "Threat Intelligence unavailable."
        }

    # Existing services
    charts = ChartService().generate_all(result)
    report_text = ReportService().build_preview(
        result,
        f.filename,
        parser.format_detected
    )

    analysis_row, report_text = _persist_analysis(
        f.filename, stored_name, parser.format_detected, parser, result, charts, report_text
    )

    return jsonify({
        "analysis_id": analysis_row.id,
        "meta": {
            "filename": f.filename,
            "format": parser.format_detected,
            "total_lines": parser.total_lines,
            "parsed_lines": parser.parsed_lines,
            "analyzed_at": datetime.utcnow().isoformat(),
        },
        "analysis": result,
        "charts": charts,
        "report": report_text,
        "threat_intelligence": threat_intelligence,
    })
import io
import json
from flask import Blueprint, jsonify, send_file
from models.models import Analysis, Report
from services.attack_wise import build_attack_wise
from services.incident_correlation import correlate_incidents
from services.report_service import ReportService
from utils.jwt_utils import require_jwt, owns_or_admin

reports_bp = Blueprint("reports", __name__)

@reports_bp.get("/report/<int:analysis_id>")
@require_jwt
def get_report(analysis_id: int):
    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found."}), 404
    if not owns_or_admin(analysis.user_id):
        return jsonify({"error": "You do not have access to this analysis."}), 403

    data = json.loads(analysis.result_json)
    report = Report.query.filter_by(analysis_id=analysis_id).first()
    attack_wise = data.get("attack_wise") if isinstance(data, dict) else None
    if not isinstance(attack_wise, dict) or "attacks" not in attack_wise:
        attack_wise = build_attack_wise(data if isinstance(data, dict) else {})
    incidents = data.get("incidents") if isinstance(data, dict) else None
    if not isinstance(incidents, dict) or "incidents" not in incidents:
        incidents = correlate_incidents(data if isinstance(data, dict) else {})

    return jsonify({
        "analysis_id": analysis.id,
        "summary": json.loads(report.summary) if report else {},
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "threat_details": data.get("threats", []),
        "recommendations": json.loads(report.recommendations) if report else [],
        "analysis": data,
        "attack_wise": attack_wise,
        "incidents": incidents,
    })


@reports_bp.get("/report/<int:analysis_id>/pdf")
@require_jwt
def download_report_pdf(analysis_id: int):
    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found."}), 404
    if not owns_or_admin(analysis.user_id):
        return jsonify({"error": "You do not have access to this analysis."}), 403

    try:
        data = json.loads(analysis.result_json or "{}")
    except json.JSONDecodeError:
        return jsonify({"error": "Stored analysis could not be read."}), 500
    if not isinstance(data, dict):
        return jsonify({"error": "Stored analysis could not be read."}), 500

    try:
        pdf_bytes = ReportService().build_pdf_bytes(analysis, data)
    except Exception as exc:
        print("PDF report error:", exc, flush=True)
        return jsonify({"error": "The PDF report could not be generated."}), 500

    safe_name = f"logsentinel_attack_report_{analysis.id}.pdf"
    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=safe_name,
    )
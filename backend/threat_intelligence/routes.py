"""Flask Blueprint exposing Threat Intelligence endpoints.

All routes are new and namespaced under /api/threat-intel, so existing
endpoints are untouched. Register this blueprint from app.py.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request, Response

from .service import ThreatIntelligenceService
from . import exporters
from utils.jwt_utils import require_jwt

threat_intel_bp = Blueprint("threat_intel", __name__, url_prefix="/api/threat-intel")
_service = ThreatIntelligenceService()


def _extract_events(payload: dict | None) -> list[dict]:
    """Accept either {"events": [...]} or a raw list; default to empty."""
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        events = payload.get("events") or payload.get("logs") or payload.get("data")
        if isinstance(events, list):
            return events
    return []


@threat_intel_bp.route("/report", methods=["POST"])
@require_jwt
def report():
    """Build a full threat intelligence report from posted parsed events."""
    events = _extract_events(request.get_json(silent=True))
    report_data = _service.build_report(events)
    return jsonify(report_data), 200


@threat_intel_bp.route("/export/<fmt>", methods=["POST"])
@require_jwt
def export(fmt: str):
    """Export a report in json, csv, or pdf."""
    fmt = fmt.lower()
    if fmt not in {"json", "csv", "pdf"}:
        return jsonify({"error": "Unsupported format. Use json, csv, or pdf."}), 400

    events = _extract_events(request.get_json(silent=True))
    report_data = _service.build_report(events)

    if fmt == "json":
        data = exporters.to_json_bytes(report_data)
        mimetype, ext = "application/json", "json"
    elif fmt == "csv":
        data = exporters.to_csv_bytes(report_data)
        mimetype, ext = "text/csv", "csv"
    else:
        data = exporters.to_pdf_bytes(report_data)
        mimetype, ext = "application/pdf", "pdf"

    return Response(
        data,
        mimetype=mimetype,
        headers={
            "Content-Disposition": f"attachment; filename=threat_intel_report.{ext}"
        },
    )
import json
from datetime import datetime, timedelta

from flask import Blueprint, g, jsonify, request

from models.models import Analysis, SecurityAlert, SecurityEvent
from services.incident_correlation import correlate_incidents, correlate_security_records
from services.security_alerts import SecurityAlertService
from utils.jwt_utils import owns_or_admin, require_jwt
from utils.validators import sanitize_text

incidents_bp = Blueprint("incidents", __name__)
_SEVERITIES = {"low", "medium", "high", "critical"}


def _load(analysis_id: int):
    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return None, None, (jsonify({"error": "Analysis not found."}), 404)
    if not owns_or_admin(analysis.user_id):
        return None, None, (jsonify({"error": "You do not have access to this analysis."}), 403)
    try:
        data = json.loads(analysis.result_json or "{}")
    except (TypeError, json.JSONDecodeError):
        return None, None, (jsonify({"error": "Stored analysis could not be read."}), 500)
    if not isinstance(data, dict):
        return None, None, (jsonify({"error": "Stored analysis could not be read."}), 500)
    incidents = data.get("incidents")
    if not isinstance(incidents, dict) or "incidents" not in incidents:
        incidents = correlate_incidents(data)
    return analysis, incidents, None


def _filtered(items: list[dict]) -> tuple[list[dict] | None, str | None]:
    severity = sanitize_text(request.args.get("severity", ""), 20).lower()
    if severity and severity != "all" and severity not in _SEVERITIES:
        return None, "Invalid severity filter."
    category = sanitize_text(request.args.get("category", ""), 80).lower()
    source_ip = sanitize_text(request.args.get("ip", ""), 64)
    hours_raw = request.args.get("hours", "")
    requested_hours = None
    if hours_raw and hours_raw.lower() != "all":
        try:
            requested_hours = float(hours_raw)
            if requested_hours <= 0 or requested_hours > 24 * 365:
                raise ValueError
        except (TypeError, ValueError):
            return None, "Invalid time-range filter."

    parsed_stamps = []
    for incident in items:
        try:
            if incident.get("last_seen"):
                parsed_stamps.append(datetime.fromisoformat(incident["last_seen"]))
        except (TypeError, ValueError):
            continue
    cutoff = (
        max(parsed_stamps) - timedelta(hours=requested_hours)
        if requested_hours is not None and parsed_stamps
        else None
    )

    result = []
    for incident in items:
        if severity and severity != "all" and str(incident.get("severity", "")).lower() != severity:
            continue
        if category and category != "all":
            categories = [str(value).lower() for value in incident.get("categories") or []]
            if category not in categories:
                continue
        if source_ip:
            if source_ip not in (incident.get("source_ips") or []):
                continue
        if requested_hours is not None:
            stamp = incident.get("last_seen")
            try:
                parsed = datetime.fromisoformat(stamp) if stamp else None
            except (TypeError, ValueError):
                parsed = None
            # A missing timestamp cannot be assumed to fall inside a requested range.
            if parsed is None or cutoff is None or parsed < cutoff:
                continue
        result.append(incident)
    return result, None


@incidents_bp.get("/analysis/<int:analysis_id>/incidents")
@require_jwt
def list_incidents(analysis_id: int):
    _, payload, error = _load(analysis_id)
    if error:
        return error
    items, filter_error = _filtered(payload.get("incidents") or [])
    if filter_error:
        return jsonify({"error": filter_error}), 400
    return jsonify({
        "analysis_id": analysis_id,
        "summary": payload.get("summary") or {},
        "count": len(items),
        "incidents": items,
    })


@incidents_bp.get("/analysis/<int:analysis_id>/incidents/<incident_id>")
@require_jwt
def incident_detail(analysis_id: int, incident_id: str):
    _, payload, error = _load(analysis_id)
    if error:
        return error
    normalized = sanitize_text(incident_id, 30).upper()
    for incident in payload.get("incidents") or []:
        if str(incident.get("incident_id", "")).upper() == normalized:
            return jsonify({"analysis_id": analysis_id, "incident": incident})
    return jsonify({"error": "Incident not found."}), 404


@incidents_bp.get("/security-incidents")
@require_jwt
def security_incidents():
    """Correlate the classroom demo stream plus alerts the viewer may see.

    Shared demo: SecurityEvent rows with source='demo_login' are the public
    /api/demo/login classroom burst. They have no owner and are visible to
    every authenticated user so the guided demo stays consistent.

    Private: SecurityAlert visibility matches GET /api/alerts — demo_login
    alerts are shared; owner-scoped alerts stay with that user (admins see all).
    """
    try:
        limit = max(1, min(int(request.args.get("limit") or 500), 1000))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid limit."}), 400
    events = (
        SecurityEvent.query.filter(SecurityEvent.source == "demo_login")
        .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
        .limit(limit)
        .all()
    )
    viewer_id = g.current_user.get("id")
    viewer_admin = g.current_user.get("role") == "admin"
    alerts = (
        SecurityAlertService()
        ._visible_query(viewer_id, viewer_admin)
        .order_by(SecurityAlert.last_seen.desc())
        .limit(500)
        .all()
    )
    payload = correlate_security_records(events, alerts)
    items, filter_error = _filtered(payload.get("incidents") or [])
    if filter_error:
        return jsonify({"error": filter_error}), 400
    return jsonify({
        "summary": payload.get("summary") or {},
        "count": len(items),
        "incidents": items,
    })


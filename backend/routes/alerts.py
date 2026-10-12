from flask import Blueprint, jsonify, request, g

from services.security_alerts import ATTACK_TYPES, SecurityAlertService
from utils.jwt_utils import require_jwt
from utils.validators import sanitize_text

alerts_bp = Blueprint("alerts", __name__)

_ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}


def _parse_hours(raw) -> float | None:
    if raw is None or raw == "" or str(raw).lower() in ("all", "any"):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return value


@alerts_bp.get("/alerts")
@require_jwt
def list_alerts():
    severity = sanitize_text(request.args.get("severity", ""), 20).lower()
    if severity in ("", "all"):
        severity = None
    elif severity not in _ALLOWED_SEVERITY:
        return jsonify({"error": "Invalid severity filter."}), 400

    attack_type = sanitize_text(request.args.get("attack_type", ""), 40).lower()
    if attack_type in ("", "all"):
        attack_type = None
    elif attack_type not in ATTACK_TYPES:
        return jsonify({"error": "Invalid attack type filter."}), 400

    hours = _parse_hours(request.args.get("hours"))
    after_raw = request.args.get("after_id")
    after_id = None
    if after_raw:
        try:
            after_id = int(after_raw)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid after_id."}), 400

    try:
        limit = int(request.args.get("limit") or 50)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid limit."}), 400

    service = SecurityAlertService()
    viewer_id = g.current_user.get("id")
    viewer_admin = g.current_user.get("role") == "admin"
    alerts = service.list_alerts(
        severity=severity,
        attack_type=attack_type,
        hours=hours,
        after_id=after_id,
        limit=limit,
        viewer_user_id=viewer_id,
        viewer_is_admin=viewer_admin,
    )
    return jsonify({
        "alerts": alerts,
        "count": len(alerts),
        "summary": service.summary(viewer_user_id=viewer_id, viewer_is_admin=viewer_admin),
    })

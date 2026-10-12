import json

from flask import Blueprint, jsonify, g
from models.models import Analysis, UploadedFile, Threat
from sqlalchemy import func
from services.attack_wise import build_attack_wise, summarize_attacks
from services.security_alerts import SecurityAlertService
from utils.jwt_utils import require_jwt

dashboard_bp = Blueprint("dashboard", __name__)


def _parse_analysis_payload(analysis):
    if analysis is None or not analysis.result_json:
        return None
    try:
        payload = json.loads(analysis.result_json)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _incident_count_from_analysis(analysis):
    """Count stored investigation items from the last analysis only. Never invent."""
    payload = _parse_analysis_payload(analysis)
    if not payload:
        return 0
    incidents = payload.get("incidents")
    if not isinstance(incidents, dict):
        return 0
    summary = incidents.get("summary") or {}
    try:
        return int(summary.get("total_incidents") or 0)
    except (TypeError, ValueError):
        return 0


def _is_log_analysis(analysis):
    """True when the row is uploaded-log analysis, not a source-code scan."""
    if analysis is None:
        return False
    if analysis.file and getattr(analysis.file, "file_format", None) == "code":
        return False
    payload = _parse_analysis_payload(analysis)
    if not payload:
        return False
    attack_wise = payload.get("attack_wise")
    if isinstance(attack_wise, dict) and (attack_wise.get("attacks") or attack_wise.get("summary")):
        return True
    return "stats" in payload and "threats" in payload


def _latest_log_analysis(analysis_q):
    for analysis in analysis_q.order_by(Analysis.created_at.desc()).all():
        if _is_log_analysis(analysis):
            return analysis
    return None


def _distinct_attack_types_from_analysis(analysis):
    """Count named Attack Summary rows from the latest analysis.

    Uses the same summarize_attacks() aggregation as the Attack Summary table
    and PDF. Threat.category is a coarser detector layer (e.g. Intrusion) and
    must not be used for this label.
    """
    payload = _parse_analysis_payload(analysis)
    if not payload:
        return 0
    attack_wise = payload.get("attack_wise")
    if not isinstance(attack_wise, dict) or "attacks" not in attack_wise:
        attack_wise = build_attack_wise(payload)
    summary = attack_wise.get("summary")
    if not isinstance(summary, dict) or "rows" not in summary:
        summary = summarize_attacks(attack_wise)
    try:
        return int(summary.get("distinct_attack_types") or 0)
    except (TypeError, ValueError):
        return 0


@dashboard_bp.get("/dashboard")
@require_jwt
def dashboard():
    user_id = g.current_user["id"]
    is_admin = g.current_user.get("role") == "admin"

    # Admins keep the full, system-wide view. Normal users only ever see the
    # files and analyses that belong to them.
    file_q = UploadedFile.query if is_admin else UploadedFile.query.filter_by(user_id=user_id)
    analysis_q = Analysis.query if is_admin else Analysis.query.filter_by(user_id=user_id)

    total_logs = file_q.count()
    analyses = analysis_q.all()
    analysis_count = len(analyses)
    threat_count = sum(a.threat_count for a in analyses)
    avg_risk = int(sum(a.risk_score for a in analyses) / len(analyses)) if analyses else 0

    severity_breakdown = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for a in analyses:
        severity_breakdown[a.severity] = severity_breakdown.get(a.severity, 0) + 1

    analysis_ids = [a.id for a in analyses]
    last = analysis_q.order_by(Analysis.created_at.desc()).first()
    log_last = _latest_log_analysis(analysis_q)
    distinct_attack_types = _distinct_attack_types_from_analysis(log_last)

    threat_q = (
        Threat.query.with_entities(Threat.source_ip, func.count(Threat.id))
        .filter(Threat.source_ip.isnot(None))
    )
    if not is_admin:
        threat_q = threat_q.filter(
            Threat.analysis_id.in_(analysis_ids or [-1])
        )

    suspicious_ips = (
        threat_q.group_by(Threat.source_ip)
        .order_by(func.count(Threat.id).desc())
        .limit(10)
        .all()
    )

    last_analysis = None
    if last:
        last_analysis = {
            "analysis_id": last.id,
            "filename": last.file.original_name if last.file else None,
            "risk_score": last.risk_score,
            "severity": last.severity,
            "threat_count": last.threat_count,
            "created_at": last.created_at.isoformat() if last.created_at else None,
        }

    timeline = [{
        "analysis_id": a.id,
        "filename": a.file.original_name if a.file else None,
        "risk_score": a.risk_score,
        "severity": a.severity,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    } for a in analysis_q.order_by(Analysis.created_at.desc()).limit(20)]

    service = SecurityAlertService()
    viewer_admin = g.current_user.get("role") == "admin"
    alert_summary = service.summary(viewer_user_id=user_id, viewer_is_admin=viewer_admin)
    live_alerts = service.list_alerts(
        limit=5,
        viewer_user_id=user_id,
        viewer_is_admin=viewer_admin,
    )

    return jsonify({
        "total_logs": total_logs,
        "analysis_count": analysis_count,
        "threat_count": threat_count,
        "distinct_attack_types": int(distinct_attack_types),
        "active_alerts": int(alert_summary.get("total") or 0),
        "incident_count": _incident_count_from_analysis(log_last),
        "risk_score": avg_risk,
        "severity_breakdown": severity_breakdown,
        "suspicious_ips": [{"ip": ip, "count": count} for ip, count in suspicious_ips],
        "last_analysis": last_analysis,
        "timeline_events": timeline,
        "live_alerts": {
            "items": live_alerts,
            "summary": alert_summary,
        },
    })

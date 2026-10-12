import json
from flask import Blueprint, jsonify
from models.models import Analysis
from utils.jwt_utils import require_jwt, owns_or_admin

charts_bp = Blueprint("charts", __name__)

@charts_bp.get("/charts/<int:analysis_id>")
@require_jwt
def charts_data(analysis_id: int):
    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found."}), 404
    if not owns_or_admin(analysis.user_id):
        return jsonify({"error": "You do not have access to this analysis."}), 403

    data = json.loads(analysis.result_json)
    stats = data.get("stats", {})

    return jsonify({
        "threat_distribution": {
            "brute_force": len(data.get("brute_force", {}).get("flagged_ips", [])),
            "port_scan": data.get("port_scan", {}).get("event_count", 0),
            "intrusion": data.get("intrusion", {}).get("event_count", 0),
            "critical": data.get("critical_events", {}).get("event_count", 0),
            "malware": data.get("malware", {}).get("event_count", 0),
        },
        "hourly_activity": stats.get("hourly_dist", {}),
        "severity_statistics": {
            "overall_severity": data.get("severity"),
            "risk_score": data.get("risk_score"),
        },
        "attack_categories": [t.get("category") for t in data.get("threats", [])],
    })
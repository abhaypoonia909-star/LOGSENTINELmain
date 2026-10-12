"""Isolated demo-login endpoints. Production /api/login is not used here."""

from flask import Blueprint, jsonify, request

from config import Config
from services.security_alerts import (
    GENERIC_BLOCKED,
    GENERIC_FAIL,
    GENERIC_OK,
    SecurityAlertService,
    client_ip,
    inspect_input,
)
from utils.jwt_utils import require_jwt
from utils.validators import sanitize_text

demo_auth_bp = Blueprint("demo_auth", __name__)


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


@demo_auth_bp.get("/demo/status")
def demo_status():
    service = SecurityAlertService()
    ip = client_ip(request)
    blocked, until = service.is_demo_blocked(ip)
    return jsonify({
        "demo": True,
        "source_ip": ip,
        "blocked": blocked,
        "blocked_until": until.isoformat() if until else None,
        "threshold": service.threshold(),
        "window_seconds": service.window_seconds(),
        "poll_seconds": service.poll_seconds(),
        "mitigation_enabled": bool(Config.ALERT_DEMO_MITIGATION),
        "message": "This endpoint is a local demonstration. It does not authenticate real users.",
    })


@demo_auth_bp.post("/demo/login")
def demo_login():
    data = request.get_json(silent=True) or {}
    username = sanitize_text(data.get("username", ""), 256)
    password = data.get("password", "") or ""
    if len(password) > 256:
        password = password[:256]
    want_mitigation = _bool(data.get("mitigation"))
    service = SecurityAlertService()
    ip = client_ip(request)

    blocked, until = service.is_demo_blocked(ip)
    if blocked:
        service.record_event(
            source="demo_login",
            event_type="blocked_attempt",
            attack_name="Demo Login Blocked",
            category="Authentication",
            severity="high",
            source_ip=ip,
            username_preview=username[:80] if username else None,
            evidence="A demo-login attempt was rejected because this address is temporarily blocked.",
        )
        return jsonify({
            "ok": False,
            "blocked": True,
            "message": GENERIC_BLOCKED,
            "blocked_until": until.isoformat() if until else None,
        }), 429

    user_findings = inspect_input(username)
    password_findings = inspect_input(password)
    if user_findings or password_findings:
        service.handle_failed_login(
            ip=ip,
            username=username,
            source="demo_login",
            apply_demo_mitigation=False,
        )
        if password_findings:
            service.handle_suspicious_password(
                ip=ip,
                username=username,
                source="demo_login",
                findings=password_findings,
            )
        # Suspicious payloads never reach the credential check or a shell.
        return jsonify({"ok": False, "message": GENERIC_FAIL}), 401

    if service.demo_credentials_match(username, password):
        service.record_event(
            source="demo_login",
            event_type="demo_success",
            attack_name=None,
            category="Authentication",
            severity="low",
            source_ip=ip,
            username_preview=username[:80],
            evidence="Demo credentials accepted. Production authentication was not used.",
        )
        return jsonify({"ok": True, "message": GENERIC_OK})

    service.handle_failed_login(
        ip=ip,
        username=username,
        source="demo_login",
        apply_demo_mitigation=want_mitigation,
    )
    return jsonify({"ok": False, "message": GENERIC_FAIL}), 401


@demo_auth_bp.post("/demo/unblock")
@require_jwt
def demo_unblock():
    service = SecurityAlertService()
    ip = client_ip(request)
    cleared = service.clear_demo_block(ip)
    return jsonify({
        "ok": True,
        "cleared": cleared,
        "source_ip": ip,
        "message": "Demo block cleared for this address." if cleared else "No demo block was active.",
    })

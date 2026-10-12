"""Live security-event logging and alert generation.

Detection rules inspect untrusted input as text only. Nothing is executed.
Demo-login mitigation never applies to production authentication.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

import bcrypt
from flask import Request, request
from sqlalchemy import func

from config import Config
from models import db
from models.models import DemoAccount, DemoBlock, SecurityAlert, SecurityEvent
from utils.validators import sanitize_text

ATTACK_TYPES = {
    "brute_force": "Brute Force Attempt",
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "directory_traversal": "Directory Traversal",
}

_GENERIC_FAIL = "Invalid credentials."
_GENERIC_BLOCKED = "Demo login temporarily unavailable from this address."
_GENERIC_OK = "Demo login accepted. This account is isolated from production authentication."

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

_INPUT_RULES = [
    {
        "attack_type": "sql_injection",
        "attack_name": "SQL Injection",
        "category": "Injection",
        "severity": "high",
        "pattern": re.compile(
            r"(union\s+select|select\s+.+\s+from|drop\s+table|delete\s+from|"
            r"insert\s+into|or\s+1\s*=\s*1|'?\s*or\s+'?1'?\s*=\s*'?1|"
            r"sql\s*injection|;\s*--)",
            re.IGNORECASE,
        ),
    },
    {
        "attack_type": "xss",
        "attack_name": "Cross-Site Scripting (XSS)",
        "category": "Injection",
        "severity": "high",
        "pattern": re.compile(
            r"(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)",
            re.IGNORECASE,
        ),
    },
    {
        "attack_type": "directory_traversal",
        "attack_name": "Directory Traversal",
        "category": "Access Control",
        "severity": "high",
        "pattern": re.compile(
            r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|/windows/system32)",
            re.IGNORECASE,
        ),
    },
]


def client_ip(req: Request | None = None) -> str | None:
    """Use the peer address only. Do not trust X-Forwarded-For."""
    req = req if req is not None else request
    ip = (getattr(req, "remote_addr", None) or "").strip()
    if not ip or ip.lower() in ("unknown", "none"):
        return None
    return ip[:64]


def _now(now: datetime | None) -> datetime:
    return now or datetime.utcnow()


def _safe_preview(value: Any, limit: int = 80) -> str | None:
    text = _CTRL.sub("", str(value or "")).strip()
    if not text:
        return None
    return text[:limit]


def inspect_input(*parts: str) -> list[dict[str, str]]:
    """Return attack matches. Input is treated as inert text."""
    findings: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in parts:
        text = str(raw or "")
        if not text:
            continue
        for rule in _INPUT_RULES:
            if rule["attack_type"] in seen:
                continue
            if rule["pattern"].search(text):
                seen.add(rule["attack_type"])
                findings.append({
                    "attack_type": rule["attack_type"],
                    "attack_name": rule["attack_name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "evidence": (
                        f"Untrusted input matched the {rule['attack_name']} detector. "
                        "The payload was not executed."
                    ),
                })
    return findings


class SecurityAlertService:
    def threshold(self) -> int:
        return max(1, int(Config.ALERT_FAILED_LOGIN_THRESHOLD))

    def window_seconds(self) -> int:
        return max(1, int(Config.ALERT_FAILED_LOGIN_WINDOW_SECONDS))

    def poll_seconds(self) -> int:
        return max(2, int(Config.ALERT_POLL_SECONDS))

    def seed_demo_account(self) -> None:
        username = sanitize_text(Config.DEMO_LOGIN_USERNAME, 80)
        if not username:
            return
        existing = DemoAccount.query.filter(DemoAccount.username == username).first()
        if existing:
            return
        hashed = bcrypt.hashpw(Config.DEMO_LOGIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
        db.session.add(DemoAccount(username=username, password_hash=hashed))
        db.session.commit()

    def demo_credentials_match(self, username: str, password: str) -> bool:
        """Parameterized lookup against the isolated demo_accounts table."""
        clean = sanitize_text(username, 80)
        if not clean or not password:
            return False
        row = DemoAccount.query.filter(DemoAccount.username == clean).first()
        if not row:
            return False
        try:
            return bcrypt.checkpw(password.encode(), row.password_hash.encode())
        except ValueError:
            return False

    def is_demo_blocked(self, ip: str | None, now: datetime | None = None) -> tuple[bool, datetime | None]:
        if not ip:
            return False, None
        current = _now(now)
        row = DemoBlock.query.filter_by(source_ip=ip).first()
        if not row:
            return False, None
        if row.blocked_until <= current:
            db.session.delete(row)
            db.session.commit()
            return False, None
        return True, row.blocked_until

    def block_demo_ip(self, ip: str, reason: str, now: datetime | None = None) -> DemoBlock:
        current = _now(now)
        until = current + timedelta(seconds=max(1, int(Config.ALERT_DEMO_BLOCK_SECONDS)))
        row = DemoBlock.query.filter_by(source_ip=ip).first()
        if row:
            row.blocked_until = until
            row.reason = reason[:255]
        else:
            row = DemoBlock(source_ip=ip, blocked_until=until, reason=reason[:255])
            db.session.add(row)
        db.session.commit()
        return row

    def clear_demo_block(self, ip: str | None) -> bool:
        if not ip:
            return False
        row = DemoBlock.query.filter_by(source_ip=ip).first()
        if not row:
            return False
        db.session.delete(row)
        db.session.commit()
        return True

    def record_event(
        self,
        *,
        source: str,
        event_type: str,
        attack_name: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        source_ip: str | None = None,
        username_preview: str | None = None,
        evidence: str | None = None,
        now: datetime | None = None,
    ) -> SecurityEvent:
        event = SecurityEvent(
            source=source[:40],
            event_type=event_type[:40],
            attack_name=_safe_preview(attack_name, 120),
            category=_safe_preview(category, 80),
            severity=_safe_preview(severity, 20),
            source_ip=_safe_preview(source_ip, 64),
            username_preview=_safe_preview(username_preview, 80),
            evidence=_safe_preview(evidence, 500),
            created_at=_now(now),
        )
        db.session.add(event)
        db.session.commit()
        return event

    def failed_login_count(self, ip: str | None, now: datetime | None = None) -> int:
        if not ip:
            return 0
        current = _now(now)
        since = current - timedelta(seconds=self.window_seconds())
        return (
            SecurityEvent.query.filter(
                SecurityEvent.event_type == "failed_login",
                SecurityEvent.source_ip == ip,
                SecurityEvent.created_at >= since,
                SecurityEvent.created_at <= current,
            ).count()
        )

    def _upsert_alert(
        self,
        *,
        attack_type: str,
        attack_name: str,
        severity: str,
        source_ip: str | None,
        event_count: int,
        evidence: str | None,
        mitigated: bool = False,
        now: datetime | None = None,
        source: str = "demo_login",
        owner_user_id: int | None = None,
    ) -> SecurityAlert:
        current = _now(now)
        window_start = current - timedelta(seconds=self.window_seconds())
        query = SecurityAlert.query.filter(
            SecurityAlert.attack_type == attack_type,
            SecurityAlert.last_seen >= window_start,
        )
        if source_ip:
            query = query.filter(SecurityAlert.source_ip == source_ip)
        else:
            query = query.filter(SecurityAlert.source_ip.is_(None))
        alert = query.order_by(SecurityAlert.last_seen.desc()).first()
        if alert:
            alert.event_count = max(alert.event_count or 0, event_count)
            alert.last_seen = current
            if evidence:
                alert.evidence = evidence[:500]
            if mitigated:
                alert.mitigated = True
            if _severity_rank(severity) > _severity_rank(alert.severity):
                alert.severity = severity
            db.session.commit()
            return alert

        alert = SecurityAlert(
            attack_name=attack_name,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            event_count=event_count,
            evidence=_safe_preview(evidence, 500),
            first_seen=current,
            last_seen=current,
            mitigated=bool(mitigated),
            source=(source or "demo_login")[:40],
            owner_user_id=owner_user_id,
        )
        db.session.add(alert)
        db.session.commit()
        return alert

    def evaluate_brute_force(
        self,
        ip: str | None,
        evidence: str,
        now: datetime | None = None,
        apply_demo_mitigation: bool = False,
    ) -> SecurityAlert | None:
        count = self.failed_login_count(ip, now)
        if count < self.threshold():
            return None
        mitigated = False
        if apply_demo_mitigation and Config.ALERT_DEMO_MITIGATION and ip:
            self.block_demo_ip(ip, "Demo brute-force threshold reached", now)
            mitigated = True
        return self._upsert_alert(
            attack_type="brute_force",
            attack_name=ATTACK_TYPES["brute_force"],
            severity="high",
            source_ip=ip,
            event_count=count,
            evidence=evidence,
            mitigated=mitigated,
            now=now,
            source="demo_login",
        )

    def handle_failed_login(
        self,
        *,
        ip: str | None,
        username: str,
        source: str,
        now: datetime | None = None,
        apply_demo_mitigation: bool = False,
    ) -> dict[str, Any]:
        if source != "demo_login":
            return {"findings": [], "alerts": []}
        preview = _safe_preview(username, 80)
        findings = inspect_input(username)
        alerts: list[SecurityAlert] = []
        for finding in findings:
            self.record_event(
                source=source,
                event_type="suspicious_input",
                attack_name=finding["attack_name"],
                category=finding["category"],
                severity=finding["severity"],
                source_ip=ip,
                username_preview=preview,
                evidence=finding["evidence"],
                now=now,
            )
            alerts.append(self._upsert_alert(
                attack_type=finding["attack_type"],
                attack_name=finding["attack_name"],
                severity=finding["severity"],
                source_ip=ip,
                event_count=1,
                evidence=finding["evidence"],
                now=now,
                source="demo_login",
            ))

        evidence = f"Failed login recorded for username '{preview or 'not present'}'."
        self.record_event(
            source=source,
            event_type="failed_login",
            attack_name="Failed Login",
            category="Authentication",
            severity="medium",
            source_ip=ip,
            username_preview=preview,
            evidence=evidence,
            now=now,
        )
        brute = self.evaluate_brute_force(
            ip,
            f"{self.failed_login_count(ip, now)} failed login(s) from {ip or 'an unknown address'} "
            f"within {self.window_seconds()} seconds.",
            now=now,
            apply_demo_mitigation=apply_demo_mitigation,
        )
        if brute:
            alerts.append(brute)
        return {"findings": findings, "alerts": alerts}

    def handle_suspicious_password(
        self,
        *,
        ip: str | None,
        username: str,
        source: str,
        findings: list[dict[str, str]],
        now: datetime | None = None,
    ) -> list[SecurityAlert]:
        preview = _safe_preview(username, 80)
        alerts = []
        for finding in findings:
            self.record_event(
                source=source,
                event_type="suspicious_input",
                attack_name=finding["attack_name"],
                category=finding["category"],
                severity=finding["severity"],
                source_ip=ip,
                username_preview=preview,
                evidence=finding["evidence"] + " Detected in the password field; the value was not stored.",
                now=now,
            )
            alerts.append(self._upsert_alert(
                attack_type=finding["attack_type"],
                attack_name=finding["attack_name"],
                severity=finding["severity"],
                source_ip=ip,
                event_count=1,
                evidence=finding["evidence"],
                now=now,
                source="demo_login",
            ))
        return alerts

    def _visible_query(self, viewer_user_id: int | None = None, viewer_is_admin: bool = False):
        """Classroom demo alerts are shared; user-owned alerts stay private.

        Shared demo: rows with source='demo_login' are created by the public
        /api/demo/login burst. They have no owner so every signed-in evaluator
        sees the same Live Alerts after the guided demo. This is intentional.

        Private: any other source (including leftover production_login rows)
        is visible only to the owning user, or to an admin.
        """
        from sqlalchemy import or_
        query = SecurityAlert.query
        if viewer_is_admin:
            return query
        return query.filter(
            or_(
                SecurityAlert.source == "demo_login",
                SecurityAlert.owner_user_id == viewer_user_id,
            )
        )

    def list_alerts(
        self,
        *,
        severity: str | None = None,
        attack_type: str | None = None,
        hours: float | None = None,
        after_id: int | None = None,
        limit: int = 50,
        viewer_user_id: int | None = None,
        viewer_is_admin: bool = False,
    ) -> list[dict[str, Any]]:
        query = self._visible_query(viewer_user_id, viewer_is_admin)
        if severity:
            query = query.filter(func.lower(SecurityAlert.severity) == severity.lower())
        if attack_type:
            query = query.filter(SecurityAlert.attack_type == attack_type)
        if hours is not None and hours > 0:
            since = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(SecurityAlert.last_seen >= since)
        if after_id:
            query = query.filter(SecurityAlert.id > after_id)
        rows = (
            query.order_by(SecurityAlert.last_seen.desc(), SecurityAlert.id.desc())
            .limit(max(1, min(limit, 200)))
            .all()
        )
        seen: set[int] = set()
        unique = []
        for row in rows:
            if row.id in seen:
                continue
            seen.add(row.id)
            unique.append(self.serialize_alert(row))
        return unique

    def serialize_alert(self, alert: SecurityAlert) -> dict[str, Any]:
        return {
            "id": alert.id,
            "attack_name": alert.attack_name,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "source_ip": alert.source_ip or None,
            "event_count": alert.event_count,
            "evidence": alert.evidence,
            "first_seen": alert.first_seen.isoformat() if alert.first_seen else None,
            "last_seen": alert.last_seen.isoformat() if alert.last_seen else None,
            "timestamp": alert.last_seen.isoformat() if alert.last_seen else None,
            "mitigated": bool(alert.mitigated),
            "source": getattr(alert, "source", None) or "demo_login",
        }

    def summary(self, viewer_user_id: int | None = None, viewer_is_admin: bool = False) -> dict[str, Any]:
        query = self._visible_query(viewer_user_id, viewer_is_admin)
        total = query.count()
        high = query.filter(func.lower(SecurityAlert.severity) == "high").count()
        return {
            "total": total,
            "high": high,
            "threshold": self.threshold(),
            "window_seconds": self.window_seconds(),
            "poll_seconds": self.poll_seconds(),
            "transport": "polling",
        }


def _severity_rank(value: str | None) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(value or "").lower(), 0)


GENERIC_FAIL = _GENERIC_FAIL
GENERIC_BLOCKED = _GENERIC_BLOCKED
GENERIC_OK = _GENERIC_OK

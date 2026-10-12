"""Incident correlation, filtering, PDF, and authorization tests."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

DB_PATH = Path(tempfile.gettempdir()) / "logsentinel_incidents_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + DB_PATH.as_posix()
os.environ["JWT_SECRET"] = "incident-test-secret-32-bytes"
os.environ["SECRET_KEY"] = "incident-test-secret-32-bytes"
os.environ["AUTH_RATE_LIMIT"] = "5000/minute"
os.environ["RATE_LIMIT"] = "5000/minute"
os.environ["AI_PROVIDER"] = "local"
os.environ["INCIDENT_CORRELATION_WINDOW_SECONDS"] = "900"

from flask import Flask  # noqa: E402

from config import Config  # noqa: E402
from models import db  # noqa: E402
from models.models import Analysis, SecurityAlert, SecurityEvent, UploadedFile, ensure_user_schema  # noqa: E402
from routes.auth import auth_bp  # noqa: E402
from routes.incidents import incidents_bp  # noqa: E402
from services.attack_wise import build_attack_wise  # noqa: E402
from services.incident_correlation import correlate_incidents, correlate_security_records  # noqa: E402
from services.report_service import ReportService  # noqa: E402


def payload(threats):
    data = {"risk_score": 70, "severity": "high", "threats": threats}
    data["attack_wise"] = build_attack_wise(data)
    return data


def event(name, category, severity, ip, timestamp, evidence):
    return {
        "title": name,
        "category": category,
        "severity": severity,
        "source_ip": ip,
        "timestamp": timestamp,
        "evidence": evidence,
        "recommendation": "Validate and contain only after confirmation.",
    }


class CorrelationUnitTests(unittest.TestCase):
    def test_related_events_same_ip_inside_window(self):
        data = payload([
            event("SQL Injection", "Intrusion", "critical", "192.0.2.10",
                  "2026-01-01 12:00:00", "request OR 1=1"),
            event("Web Shell", "Intrusion", "critical", "192.0.2.10",
                  "2026-01-01 12:10:00", "GET /shell.php"),
        ])
        result = correlate_incidents(data, window_seconds=900)
        self.assertEqual(result["summary"]["total_incidents"], 1)
        incident = result["incidents"][0]
        self.assertEqual(incident["correlation_status"], "possible_correlation")
        self.assertEqual(incident["event_count"], 2)
        self.assertEqual(len(incident["timeline"]), 2)
        self.assertIn("does not establish", incident["assessment"])

    def test_unrelated_events_same_timestamp_not_correlated(self):
        data = payload([
            event("SQL Injection", "Intrusion", "critical", "192.0.2.10",
                  "2026-01-01 12:00:00", "first evidence"),
            event("SQL Injection", "Intrusion", "critical", "192.0.2.11",
                  "2026-01-01 12:00:00", "second evidence"),
        ])
        result = correlate_incidents(data)
        self.assertEqual(result["summary"]["total_incidents"], 2)
        self.assertEqual(result["summary"]["possible_correlations"], 0)

    def test_missing_fields_are_not_invented_or_loosely_correlated(self):
        data = payload([
            event("SQL Injection", "Intrusion", "high", None, None, "evidence A"),
            event("XSS", "Intrusion", "high", None, None, "evidence B"),
        ])
        result = correlate_incidents(data)
        self.assertEqual(result["summary"]["total_incidents"], 2)
        for incident in result["incidents"]:
            self.assertIsNone(incident["source_ip"])
            self.assertIsNone(incident["first_seen"])
            self.assertIsNone(incident["last_seen"])
            self.assertIsNone(incident["timeline"][0]["source_ip"])
            self.assertIsNone(incident["timeline"][0]["timestamp"])

    def test_duplicate_findings_are_preserved(self):
        twin = event("Directory Traversal", "Intrusion", "high", None, None, "../etc/passwd")
        data = payload([twin, dict(twin)])
        result = correlate_incidents(data)
        self.assertEqual(result["summary"]["confirmed_findings"], 2)
        self.assertEqual(result["summary"]["total_incidents"], 1)
        self.assertEqual(result["incidents"][0]["event_count"], 2)
        self.assertEqual(len(result["incidents"][0]["timeline"]), 2)

    def test_time_window_boundary_is_inclusive(self):
        first = event("SQL Injection", "Intrusion", "high", "192.0.2.20",
                      "2026-01-01 12:00:00", "A")
        at_boundary = event("XSS", "Intrusion", "high", "192.0.2.20",
                            "2026-01-01 12:15:00", "B")
        outside = event("XSS", "Intrusion", "high", "192.0.2.20",
                        "2026-01-01 12:15:01", "B")
        self.assertEqual(correlate_incidents(payload([first, at_boundary]), 900)["summary"]["total_incidents"], 1)
        self.assertEqual(correlate_incidents(payload([first, outside]), 900)["summary"]["total_incidents"], 2)

    def test_risk_score_and_factors_are_deterministic(self):
        data = payload([
            event("SQL Injection", "Intrusion", "critical", "192.0.2.30",
                  "2026-01-01 12:00:00", "A"),
            event("Web Shell", "Intrusion", "high", "192.0.2.30",
                  "2026-01-01 12:01:00", "B"),
        ])
        incident = correlate_incidents(data)["incidents"][0]
        self.assertEqual(incident["risk_score"], 86)
        self.assertEqual(sum(f["points"] for f in incident["risk_factors"]), 86)
        self.assertEqual(incident["severity"], "critical")

    def test_pdf_keeps_attack_wise_and_adds_incidents(self):
        data = payload([
            event("SQL Injection", "Intrusion", "critical", "192.0.2.40",
                  "2026-01-01 12:00:00", "GET /?id=1 OR 1=1"),
            event("Directory Traversal", "Intrusion", "high", "192.0.2.40",
                  "2026-01-01 12:02:00", "GET /../etc/passwd"),
        ])
        data["incidents"] = correlate_incidents(data)
        record = SimpleNamespace(
            id=9,
            risk_score=80,
            severity="critical",
            file=SimpleNamespace(original_name="incident-demo.log"),
        )
        pdf = ReportService().build_pdf_bytes(record, data)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertIn(b"Attack Summary", pdf)
        self.assertIn(b"Incident Correlation Summary", pdf)
        self.assertIn(b"INC-0001", pdf)

    def test_persisted_security_event_adapter_keeps_alert_references(self):
        first = SimpleNamespace(
            id=1, attack_name="SQL Injection", event_type="suspicious_input",
            category="Injection", severity="high", source_ip="192.0.2.70",
            evidence="matched SQLi text", created_at=__import__("datetime").datetime(2026, 1, 1, 12, 0),
        )
        second = SimpleNamespace(
            id=2, attack_name="Directory Traversal", event_type="suspicious_input",
            category="Access Control", severity="high", source_ip="192.0.2.70",
            evidence="matched traversal text", created_at=__import__("datetime").datetime(2026, 1, 1, 12, 5),
        )
        alert = SimpleNamespace(id=44, source_ip="192.0.2.70")
        result = correlate_security_records([first, second], [alert])
        self.assertEqual(result["summary"]["source"], "persisted_security_events")
        self.assertEqual(result["incidents"][0]["related_security_alert_ids"], [44])
        self.assertEqual(result["incidents"][0]["event_count"], 2)


def create_app():
    application = Flask(__name__)
    application.config.from_object(Config)
    db.init_app(application)
    application.register_blueprint(auth_bp, url_prefix="/api")
    application.register_blueprint(incidents_bp, url_prefix="/api")
    with application.app_context():
        db.create_all()
        ensure_user_schema()
    return application


app = create_app()


def auth(token):
    return {"Authorization": "Bearer " + token}


class IncidentAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.owner = cls.register("incowner", "incowner@example.com")
        cls.other = cls.register("incother", "incother@example.com")
        cls.analysis_id = cls.seed(cls.owner)

    @classmethod
    def register(cls, username, email):
        response = cls.client.post("/api/register", json={
            "username": username,
            "email": email,
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        })
        if response.status_code != 201:
            raise AssertionError(response.get_json())
        return response.get_json()["token"]

    @classmethod
    def seed(cls, token):
        user = cls.client.get("/api/me", headers=auth(token)).get_json()["user"]
        data = payload([
            event("SQL Injection", "Intrusion", "critical", "192.0.2.50",
                  "2026-01-01 12:00:00", "A"),
            event("XSS", "Intrusion", "high", "192.0.2.50",
                  "2026-01-01 12:05:00", "B"),
            event("Port Scan Activity", "Port Scan", "medium", "192.0.2.60",
                  "2026-01-01 14:00:00", "C"),
        ])
        data["incidents"] = correlate_incidents(data)
        with app.app_context():
            uploaded = UploadedFile(
                user_id=user["id"],
                original_name="incidents.log",
                stored_name="incidents-stored.log",
                file_format="text",
            )
            db.session.add(uploaded)
            db.session.flush()
            analysis = Analysis(
                user_id=user["id"],
                file_id=uploaded.id,
                risk_score=80,
                severity="critical",
                total_lines=3,
                threat_count=3,
                result_json=json.dumps(data),
            )
            db.session.add(analysis)
            db.session.commit()
            return analysis.id

    def test_list_and_detail_require_owner(self):
        path = f"/api/analysis/{self.analysis_id}/incidents"
        self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.get(path, headers=auth(self.other)).status_code, 403)
        owner = self.client.get(path, headers=auth(self.owner))
        self.assertEqual(owner.status_code, 200)
        self.assertEqual(owner.get_json()["count"], 2)
        incident_id = owner.get_json()["incidents"][0]["incident_id"]
        detail = self.client.get(f"{path}/{incident_id}", headers=auth(self.owner))
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.get_json()["incident"]["incident_id"], incident_id)

    def test_filters(self):
        base = f"/api/analysis/{self.analysis_id}/incidents"
        critical = self.client.get(base + "?severity=critical", headers=auth(self.owner))
        self.assertEqual(critical.status_code, 200)
        self.assertEqual(critical.get_json()["count"], 1)
        ip_filter = self.client.get(base + "?ip=192.0.2.60", headers=auth(self.owner))
        self.assertEqual(ip_filter.get_json()["count"], 1)
        category = self.client.get(base + "?category=intrusion", headers=auth(self.owner))
        self.assertEqual(category.get_json()["count"], 1)
        recent = self.client.get(base + "?hours=1", headers=auth(self.owner))
        self.assertEqual(recent.get_json()["count"], 1)
        invalid = self.client.get(base + "?severity=nope", headers=auth(self.owner))
        self.assertEqual(invalid.status_code, 400)

    def test_persisted_security_incidents_require_auth(self):
        self.assertEqual(self.client.get("/api/security-incidents").status_code, 401)
        with app.app_context():
            db.session.add(SecurityEvent(
                source="demo_login",
                event_type="suspicious_input",
                attack_name="SQL Injection",
                category="Injection",
                severity="high",
                source_ip="192.0.2.80",
                evidence="safe test evidence",
            ))
            db.session.add(SecurityAlert(
                attack_name="SQL Injection",
                attack_type="sql_injection",
                severity="high",
                source_ip="192.0.2.80",
                event_count=1,
                evidence="safe test evidence",
                source="demo_login",
            ))
            db.session.commit()
        response = self.client.get("/api/security-incidents", headers=auth(self.owner))
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.get_json()["count"], 1)
        shared = self.client.get("/api/security-incidents", headers=auth(self.other))
        self.assertEqual(shared.status_code, 200)
        self.assertGreaterEqual(shared.get_json()["count"], 1)

    def test_private_alert_is_hidden_from_security_incidents(self):
        owner = self.client.get("/api/me", headers=auth(self.owner)).get_json()["user"]
        with app.app_context():
            db.session.add(SecurityEvent(
                source="demo_login",
                event_type="failed_login",
                attack_name="Shared Demo Burst",
                category="Authentication",
                severity="high",
                source_ip="192.0.2.91",
                evidence="classroom demo burst",
            ))
            db.session.add(SecurityEvent(
                source="production_login",
                event_type="failed_login",
                attack_name="Private Login Event",
                category="Authentication",
                severity="high",
                source_ip="203.0.113.91",
                evidence="owner only event",
            ))
            alert = SecurityAlert(
                attack_name="Private Incident Alert",
                attack_type="sql_injection",
                severity="high",
                source_ip="192.0.2.91",
                event_count=1,
                evidence="owner only incident",
                source="production_login",
                owner_user_id=owner["id"],
            )
            db.session.add(alert)
            db.session.commit()
            private_id = alert.id
        owner_resp = self.client.get("/api/security-incidents", headers=auth(self.owner))
        other_resp = self.client.get("/api/security-incidents", headers=auth(self.other))
        self.assertEqual(owner_resp.status_code, 200)
        self.assertEqual(other_resp.status_code, 200)
        owner_ids = []
        for incident in owner_resp.get_json().get("incidents") or []:
            owner_ids.extend(incident.get("related_security_alert_ids") or [])
        other_ids = []
        for incident in other_resp.get_json().get("incidents") or []:
            other_ids.extend(incident.get("related_security_alert_ids") or [])
        self.assertIn(private_id, owner_ids)
        self.assertNotIn(private_id, other_ids)
        other_blob = json.dumps(other_resp.get_json())
        owner_blob = json.dumps(owner_resp.get_json())
        self.assertIn("Shared Demo Burst", owner_blob)
        self.assertIn("Shared Demo Burst", other_blob)
        self.assertNotIn("Private Login Event", owner_blob)
        self.assertNotIn("Private Login Event", other_blob)
        self.assertNotIn("Private Incident Alert", other_blob)
        self.assertNotIn("203.0.113.91", other_blob)


if __name__ == "__main__":
    unittest.main(verbosity=2)

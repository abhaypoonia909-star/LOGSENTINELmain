"""Live security-alert tests: thresholds, windows, IPs, input, auth, persistence."""
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(tempfile.gettempdir()) / "logsentinel_security_alerts_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + DB_PATH.as_posix()
os.environ["JWT_SECRET"] = "security-alerts-test-secret-32-bytes"
os.environ["SECRET_KEY"] = "security-alerts-test-secret-32-bytes"
os.environ["AUTH_RATE_LIMIT"] = "5000/minute"
os.environ["RATE_LIMIT"] = "5000/minute"
os.environ["DEMO_LOGIN_RATE_LIMIT"] = "5000/minute"
os.environ["AI_PROVIDER"] = "local"
os.environ["ALERT_FAILED_LOGIN_THRESHOLD"] = "5"
os.environ["ALERT_FAILED_LOGIN_WINDOW_SECONDS"] = "300"
os.environ["ALERT_DEMO_MITIGATION"] = "1"
os.environ["ALERT_DEMO_BLOCK_SECONDS"] = "120"
os.environ["DEMO_LOGIN_USERNAME"] = "demo"
os.environ["DEMO_LOGIN_PASSWORD"] = "Demo1234"

from flask import Flask  # noqa: E402

from config import Config  # noqa: E402
from models import db  # noqa: E402
from models.models import SecurityAlert, SecurityEvent, ensure_user_schema  # noqa: E402
from routes.alerts import alerts_bp  # noqa: E402
from routes.auth import auth_bp  # noqa: E402
from routes.dashboard import dashboard_bp  # noqa: E402
from routes.demo_auth import demo_auth_bp  # noqa: E402
from services.security_alerts import (  # noqa: E402
    GENERIC_FAIL,
    SecurityAlertService,
    inspect_input,
)


def create_test_app():
    application = Flask(__name__)
    application.config.from_object(Config)
    db.init_app(application)
    application.register_blueprint(auth_bp, url_prefix="/api")
    application.register_blueprint(demo_auth_bp, url_prefix="/api")
    application.register_blueprint(alerts_bp, url_prefix="/api")
    application.register_blueprint(dashboard_bp, url_prefix="/api")
    with application.app_context():
        db.create_all()
        ensure_user_schema()
        SecurityAlertService().seed_demo_account()
    return application


app = create_test_app()


def _auth(token):
    return {"Authorization": "Bearer " + token}


class InputInspectionTests(unittest.TestCase):
    def test_detects_sqli_xss_and_traversal(self):
        names = {f["attack_type"] for f in inspect_input("1 OR 1=1", "<script>alert(1)</script>", "../etc/passwd")}
        self.assertEqual(names, {"sql_injection", "xss", "directory_traversal"})

    def test_benign_values_are_not_alerts(self):
        self.assertEqual(inspect_input("alice", "Sentinel123", "demo"), [])
        self.assertEqual(inspect_input("O'Reilly", "password1"), [])


class ThresholdAndWindowTests(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.ctx = app.app_context()
        self.ctx.push()
        SecurityEvent.query.delete()
        SecurityAlert.query.delete()
        db.session.commit()
        self.service = SecurityAlertService()

    def tearDown(self):
        self.ctx.pop()

    def test_threshold_creates_high_alert(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        alert = None
        for _ in range(5):
            result = self.service.handle_failed_login(
                ip="192.0.2.10",
                username="attacker",
                source="demo_login",
                now=now,
            )
            alert = result["alerts"][-1] if result["alerts"] else None
        self.assertIsNotNone(alert)
        self.assertEqual(alert.attack_type, "brute_force")
        self.assertEqual(alert.severity, "high")
        self.assertEqual(alert.event_count, 5)
        self.assertEqual(SecurityAlert.query.filter_by(attack_type="brute_force").count(), 1)

    def test_four_failures_do_not_alert(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        for _ in range(4):
            self.service.handle_failed_login(
                ip="192.0.2.11", username="attacker", source="demo_login", now=now
            )
        self.assertEqual(SecurityAlert.query.filter_by(attack_type="brute_force").count(), 0)
        self.assertEqual(SecurityEvent.query.filter_by(event_type="failed_login").count(), 4)

    def test_time_window_excludes_old_failures(self):
        t1 = datetime(2026, 1, 1, 12, 0, 0)
        t2 = t1 + timedelta(seconds=301)
        for _ in range(4):
            self.service.handle_failed_login(
                ip="192.0.2.12", username="attacker", source="demo_login", now=t1
            )
        self.service.handle_failed_login(
            ip="192.0.2.12", username="attacker", source="demo_login", now=t2
        )
        self.assertEqual(SecurityAlert.query.filter_by(attack_type="brute_force").count(), 0)

    def test_different_ips_are_not_combined(self):
        now = datetime(2026, 1, 1, 12, 0, 0)
        for _ in range(4):
            self.service.handle_failed_login(
                ip="192.0.2.20", username="a", source="demo_login", now=now
            )
        for _ in range(5):
            self.service.handle_failed_login(
                ip="192.0.2.21", username="b", source="demo_login", now=now
            )
        alerts = SecurityAlert.query.filter_by(attack_type="brute_force").all()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "192.0.2.21")


class DemoEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        resp = cls.client.post("/api/register", json={
            "username": "alertuser",
            "email": "alertuser@example.com",
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        })
        cls.token = resp.get_json()["token"]

    def setUp(self):
        with app.app_context():
            SecurityEvent.query.delete()
            SecurityAlert.query.delete()
            db.session.commit()

    def _demo(self, username, password, ip="198.51.100.7", mitigation=False):
        return self.client.post(
            "/api/demo/login",
            json={"username": username, "password": password, "mitigation": mitigation},
            environ_base={"REMOTE_ADDR": ip},
            headers={"X-Forwarded-For": "203.0.113.9"},
        )

    def test_isolated_demo_login_four_then_five_threshold(self):
        """Clean test DB only. Four failures stay quiet; the fifth creates one brute-force alert."""
        ip = "203.0.113.201"
        with app.app_context():
            self.assertEqual(SecurityEvent.query.filter_by(source_ip=ip).count(), 0)
            self.assertEqual(SecurityAlert.query.filter_by(source_ip=ip).count(), 0)
            self.assertEqual(app.config["ALERT_FAILED_LOGIN_THRESHOLD"], 5)
            self.assertEqual(app.config["ALERT_FAILED_LOGIN_WINDOW_SECONDS"], 300)

        for _ in range(4):
            resp = self._demo("demo", "WrongPass1", ip=ip)
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.get_json()["message"], GENERIC_FAIL)
        with app.app_context():
            self.assertEqual(SecurityAlert.query.filter_by(attack_type="brute_force", source_ip=ip).count(), 0)
            self.assertEqual(SecurityEvent.query.filter_by(event_type="failed_login", source_ip=ip).count(), 4)

        fifth = self._demo("demo", "WrongPass1", ip=ip)
        self.assertEqual(fifth.status_code, 401)
        self.assertEqual(fifth.get_json()["message"], GENERIC_FAIL)
        with app.app_context():
            alerts = SecurityAlert.query.filter_by(attack_type="brute_force", source_ip=ip).all()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].event_count, 5)
            self.assertEqual(alerts[0].severity, "high")
            self.assertEqual(alerts[0].source, "demo_login")
            self.assertIsNone(alerts[0].owner_user_id)
            self.assertEqual(SecurityEvent.query.filter_by(event_type="failed_login", source_ip=ip).count(), 5)

    def test_demo_success_and_failure_messages(self):
        ok = self._demo("demo", "Demo1234")
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.get_json()["ok"])
        bad = self._demo("demo", "wrong")
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(bad.get_json()["message"], GENERIC_FAIL)

    def test_suspicious_inputs_are_generic_and_persisted(self):
        cases = [
            ("1 OR 1=1", "x", "sql_injection"),
            ("alice", "<script>alert(1)</script>", "xss"),
            ("../etc/passwd", "x", "directory_traversal"),
        ]
        for username, password, attack_type in cases:
            resp = self._demo(username, password, ip="198.51.100.8")
            self.assertEqual(resp.status_code, 401, attack_type)
            self.assertEqual(resp.get_json()["message"], GENERIC_FAIL)
        with app.app_context():
            types = {a.attack_type for a in SecurityAlert.query.all()}
            self.assertTrue({"sql_injection", "xss", "directory_traversal"} <= types)
            self.assertTrue(SecurityEvent.query.filter_by(event_type="suspicious_input").count() >= 3)

    def test_ignores_forwarded_ip_header(self):
        for _ in range(5):
            self._demo("demo", "wrong", ip="198.51.100.30")
        with app.app_context():
            alert = SecurityAlert.query.filter_by(attack_type="brute_force").first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.source_ip, "198.51.100.30")
            self.assertNotEqual(alert.source_ip, "203.0.113.9")

    def test_demo_mitigation_does_not_block_production_login(self):
        for _ in range(5):
            resp = self._demo("demo", "wrong", ip="198.51.100.40", mitigation=True)
        self.assertIn(resp.status_code, (401, 429))
        blocked = self._demo("demo", "wrong", ip="198.51.100.40", mitigation=True)
        self.assertEqual(blocked.status_code, 429)
        production = self.client.post(
            "/api/login",
            json={"email": "nobody@example.com", "password": "WrongPass1"},
            environ_base={"REMOTE_ADDR": "198.51.100.40"},
        )
        self.assertEqual(production.status_code, 401)
        self.assertEqual(production.get_json()["error"], "Invalid credentials.")

    def test_false_positive_username_does_not_create_injection_alert(self):
        resp = self._demo("alice", "Sentinel123", ip="198.51.100.50")
        self.assertEqual(resp.status_code, 401)
        with app.app_context():
            injection = SecurityAlert.query.filter(
                SecurityAlert.attack_type.in_(["sql_injection", "xss", "directory_traversal"])
            ).count()
            self.assertEqual(injection, 0)


class AuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        resp = cls.client.post("/api/register", json={
            "username": "alertauth",
            "email": "alertauth@example.com",
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        })
        cls.token = resp.get_json()["token"]

    def setUp(self):
        with app.app_context():
            SecurityEvent.query.delete()
            SecurityAlert.query.delete()
            db.session.commit()

    def test_alerts_require_auth(self):
        missing = self.client.get("/api/alerts")
        self.assertEqual(missing.status_code, 401)
        ok = self.client.get("/api/alerts", headers=_auth(self.token))
        self.assertEqual(ok.status_code, 200)
        self.assertIn("alerts", ok.get_json())

    def test_dashboard_includes_live_alerts(self):
        missing = self.client.get("/api/dashboard")
        self.assertEqual(missing.status_code, 401)
        ok = self.client.get("/api/dashboard", headers=_auth(self.token))
        self.assertEqual(ok.status_code, 200)
        self.assertIn("live_alerts", ok.get_json())
        self.assertIn("total_logs", ok.get_json())

    def test_dashboard_metrics_are_real_zeros_when_empty(self):
        data = self.client.get("/api/dashboard", headers=_auth(self.token)).get_json()
        for key in (
            "total_logs", "analysis_count", "threat_count",
            "distinct_attack_types", "active_alerts", "incident_count",
        ):
            self.assertIn(key, data)
            self.assertEqual(data[key], 0)
        self.assertIsNone(data.get("last_analysis"))

    def test_invalid_filter_rejected(self):
        resp = self.client.get("/api/alerts?severity=nope", headers=_auth(self.token))
        self.assertEqual(resp.status_code, 400)

    def test_unblock_requires_auth(self):
        self.assertEqual(self.client.post("/api/demo/unblock").status_code, 401)

    def test_repeated_polling_does_not_duplicate_alerts(self):
        for _ in range(5):
            self.client.post(
                "/api/demo/login",
                json={"username": "demo", "password": "wrong"},
                environ_base={"REMOTE_ADDR": "198.51.100.77"},
            )
        first = self.client.get("/api/alerts", headers=_auth(self.token))
        second = self.client.get("/api/alerts", headers=_auth(self.token))
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        ids1 = [item["id"] for item in first.get_json()["alerts"]]
        ids2 = [item["id"] for item in second.get_json()["alerts"]]
        self.assertEqual(ids1, ids2)
        self.assertEqual(len(ids1), len(set(ids1)))

    def test_production_login_failure_is_not_a_live_alert(self):
        before = self.client.get("/api/alerts", headers=_auth(self.token)).get_json()["count"]
        for _ in range(6):
            resp = self.client.post(
                "/api/login",
                json={"email": "nobody@example.com", "password": "WrongPass1"},
                environ_base={"REMOTE_ADDR": "198.51.100.88"},
            )
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.get_json()["error"], "Invalid credentials.")
        after = self.client.get("/api/alerts", headers=_auth(self.token)).get_json()
        self.assertEqual(after["count"], before)

    def test_demo_success_is_not_an_attack_alert(self):
        self.client.post(
            "/api/demo/login",
            json={"username": "demo", "password": "Demo1234"},
            environ_base={"REMOTE_ADDR": "198.51.100.89"},
        )
        with app.app_context():
            self.assertEqual(SecurityAlert.query.count(), 0)
            self.assertEqual(SecurityEvent.query.filter_by(event_type="demo_success").count(), 1)

    def test_uploaded_analysis_does_not_create_live_alerts(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)
        with app.app_context():
            before = SecurityAlert.query.count()
            LogAnalyzer(LogParser().parse(
                "2024-01-15 02:14:33 FAILED ssh root@192.168.1.100 - Failed password attempt\n"
                "2024-01-15 02:17:46 INFO apache: 10.0.0.99 GET /login.php?id=1 OR 1=1"
            )).analyze()
            self.assertEqual(SecurityAlert.query.count(), before)
        analysis_source = Path(__file__).resolve().parent.joinpath("routes", "analysis.py").read_text(encoding="utf-8")
        self.assertNotIn("SecurityAlertService", analysis_source)
        self.assertNotIn("handle_failed_login", analysis_source)

    def _other_token(self):
        other = self.client.post("/api/register", json={
            "username": "alertother",
            "email": "alertother@example.com",
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        })
        if other.status_code == 201:
            return other.get_json()["token"]
        login = self.client.post("/api/login", json={
            "email": "alertother@example.com",
            "password": "Sentinel123",
        })
        return login.get_json()["token"]

    def test_private_alert_is_hidden_from_other_users(self):
        other_token = self._other_token()
        me = self.client.get("/api/me", headers=_auth(self.token)).get_json()["user"]
        with app.app_context():
            db.session.add(SecurityAlert(
                attack_name="Private Alert",
                attack_type="sql_injection",
                severity="high",
                source_ip="192.0.2.55",
                event_count=1,
                evidence="owner only",
                source="production_login",
                owner_user_id=me["id"],
            ))
            db.session.commit()
        owner = self.client.get("/api/alerts?hours=all", headers=_auth(self.token))
        stranger = self.client.get("/api/alerts?hours=all", headers=_auth(other_token))
        owner_names = {item["attack_name"] for item in owner.get_json()["alerts"]}
        stranger_names = {item["attack_name"] for item in stranger.get_json()["alerts"]}
        self.assertIn("Private Alert", owner_names)
        self.assertNotIn("Private Alert", stranger_names)

        owner_dash = self.client.get("/api/dashboard", headers=_auth(self.token)).get_json()
        stranger_dash = self.client.get("/api/dashboard", headers=_auth(other_token)).get_json()
        owner_live = {item["attack_name"] for item in owner_dash["live_alerts"]["items"]}
        stranger_live = {item["attack_name"] for item in stranger_dash["live_alerts"]["items"]}
        self.assertIn("Private Alert", owner_live)
        self.assertNotIn("Private Alert", stranger_live)
        self.assertGreaterEqual(owner_dash["active_alerts"], 1)
        self.assertEqual(stranger_dash["active_alerts"], 0)

    def test_demo_login_alerts_are_shared_classroom_events(self):
        """Demo-login alerts have no owner and stay visible to every signed-in user."""
        for _ in range(5):
            self.client.post(
                "/api/demo/login",
                json={"username": "demo", "password": "wrong"},
                environ_base={"REMOTE_ADDR": "198.51.100.70"},
            )
        other_token = self._other_token()
        owner = self.client.get("/api/alerts?hours=all", headers=_auth(self.token))
        stranger = self.client.get("/api/alerts?hours=all", headers=_auth(other_token))
        owner_types = {item["attack_type"] for item in owner.get_json()["alerts"]}
        stranger_types = {item["attack_type"] for item in stranger.get_json()["alerts"]}
        self.assertIn("brute_force", owner_types)
        self.assertEqual(owner_types, stranger_types)
        owner_dash = self.client.get("/api/dashboard", headers=_auth(self.token)).get_json()
        stranger_dash = self.client.get("/api/dashboard", headers=_auth(other_token)).get_json()
        self.assertGreaterEqual(owner_dash["active_alerts"], 1)
        self.assertEqual(owner_dash["active_alerts"], stranger_dash["active_alerts"])

    def test_missing_ip_serializes_as_null(self):
        with app.app_context():
            service = SecurityAlertService()
            alert = service._upsert_alert(
                attack_type="xss",
                attack_name="Cross-Site Scripting (XSS)",
                severity="high",
                source_ip=None,
                event_count=1,
                evidence="Untrusted input matched the XSS detector.",
                source="demo_login",
            )
            payload = service.serialize_alert(alert)
            self.assertIsNone(payload["source_ip"])
            self.assertTrue(payload["timestamp"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

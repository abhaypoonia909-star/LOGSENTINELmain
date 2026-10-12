"""Attack-wise grouping, PDF report, and authorization tests."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

DB_PATH = Path(tempfile.gettempdir()) / "logsentinel_attack_wise_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + DB_PATH.as_posix()
os.environ["JWT_SECRET"] = "attack-wise-test-secret-32-bytes"
os.environ["SECRET_KEY"] = "attack-wise-test-secret-32-bytes"
os.environ["AUTH_RATE_LIMIT"] = "5000/minute"
os.environ["RATE_LIMIT"] = "5000/minute"
os.environ["AI_PROVIDER"] = "local"

from flask import Flask  # noqa: E402

from config import Config  # noqa: E402
from models import db  # noqa: E402
from models.models import Analysis, Threat, UploadedFile, ensure_user_schema  # noqa: E402
from routes.auth import auth_bp  # noqa: E402
from routes.dashboard import dashboard_bp  # noqa: E402
from routes.reports import reports_bp  # noqa: E402
from services.attack_wise import build_attack_wise, summarize_attacks  # noqa: E402
from services.report_service import ReportService  # noqa: E402


def create_test_app():
    application = Flask(__name__)
    application.config.from_object(Config)
    db.init_app(application)
    application.register_blueprint(auth_bp, url_prefix="/api")
    application.register_blueprint(reports_bp, url_prefix="/api")
    application.register_blueprint(dashboard_bp, url_prefix="/api")
    with application.app_context():
        db.create_all()
        ensure_user_schema()
    return application


app = create_test_app()
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "samples" / "multi_attack_demo.log"


def _auth(token):
    return {"Authorization": "Bearer " + token}


class AttackWiseUnitTests(unittest.TestCase):
    def test_groups_multiple_attack_types_separately(self):
        result = build_attack_wise({
            "threats": [
                {"title": "SQL Injection", "category": "Intrusion", "severity": "critical",
                 "source_ip": "10.0.0.99", "message": "GET /login.php?id=1 OR 1=1"},
                {"title": "Directory Traversal", "category": "Intrusion", "severity": "high",
                 "source_ip": "10.0.0.99", "message": "GET /../../../etc/passwd"},
                {"title": "Brute Force Attack", "category": "Brute Force", "severity": "high",
                 "source_ip": "192.168.1.100", "message": "Failed password"},
            ]
        })
        names = [a["attack_name"] for a in result["attacks"]]
        self.assertEqual(result["distinct_attack_types"], 3)
        self.assertEqual(result["total_events"], 3)
        self.assertEqual(names.count("SQL Injection"), 1)
        self.assertIn("Directory Traversal", names)
        self.assertIn("Brute Force Attack", names)
        sql = next(a for a in result["attacks"] if a["attack_name"] == "SQL Injection")
        self.assertEqual(sql["category"], "Intrusion")
        self.assertEqual(len(sql["events"]), 1)
        rows = {row["attack_type"]: row for row in result["summary"]["rows"]}
        self.assertEqual(rows["SQL Injection"]["severity"], "critical")
        self.assertEqual(rows["Brute Force Attack"]["severity"], "high")

    def test_preserves_duplicate_events(self):
        twin = {
            "title": "Port Scan Activity",
            "category": "Port Scan",
            "severity": "medium",
            "source_ip": "172.16.0.200",
            "evidence": "WARNING port_scan: Multiple ports probed",
        }
        result = build_attack_wise({"threats": [twin, dict(twin)]})
        self.assertEqual(result["distinct_attack_types"], 1)
        self.assertEqual(result["total_events"], 2)
        self.assertEqual(result["attacks"][0]["event_count"], 2)

    def test_missing_fields_are_none_not_invented(self):
        result = build_attack_wise({
            "threats": [{
                "title": "Port Scan Activity",
                "category": "Port Scan",
                "message": "scan detected",
            }]
        })
        event = result["attacks"][0]["events"][0]
        self.assertIsNone(event["source_ip"])
        self.assertIsNone(event["timestamp"])
        self.assertIsNone(event["severity"])
        self.assertIsNone(event["confidence"])
        self.assertEqual(event["evidence"], "scan detected")
        self.assertTrue(event["explanation"])

    def test_summary_counts_per_ip_and_marks_missing(self):
        result = build_attack_wise({
            "threats": [
                {"title": "SQL Injection", "category": "Intrusion", "source_ip": "203.0.113.60",
                 "message": "GET /login?id=1 OR 1=1"},
                {"title": "SQL Injection", "category": "Intrusion", "source_ip": "203.0.113.60",
                 "message": "GET /search?q=1 OR 1=1"},
                {"title": "SQL Injection", "category": "Intrusion", "source_ip": "203.0.113.70",
                 "message": "GET /x?id=1 OR 1=1"},
                {"title": "Brute Force Attack", "category": "Brute Force", "source_ip": "198.51.100.25",
                 "message": "5 failed logins", "attempt_count": 5},
                {"title": "Privilege Escalation / Unauthorized Access", "category": "Intrusion",
                 "message": "privilege escalation detected"},
            ]
        })
        rows = {row["attack_type"]: row for row in result["summary"]["rows"]}
        self.assertEqual(rows["SQL Injection"]["attempts"], 3)
        self.assertEqual(rows["SQL Injection"]["source_ip_display"], "203.0.113.60 (2); 203.0.113.70 (1)")
        self.assertEqual(rows["Brute Force Attack"]["attempts"], 5)
        self.assertEqual(rows["Brute Force Attack"]["source_ip_display"], "198.51.100.25")
        self.assertEqual(rows["Privilege Escalation / Unauthorized Access"]["attempts"], 1)
        self.assertEqual(rows["Privilege Escalation / Unauthorized Access"]["source_ip_display"], "Not available")

    def test_pdf_contains_sections_and_escaped_evidence(self):
        analysis_data = {
            "risk_score": 82,
            "severity": "critical",
            "threats": [{
                "title": "SQL Injection",
                "category": "Intrusion",
                "severity": "critical",
                "source_ip": "10.0.0.99",
                "timestamp": "2024-01-15 02:17:46",
                "evidence": "GET /x?q=<script>alert(1)</script>",
                "recommendation": "Use parameterized queries.",
            }],
        }
        analysis_data["attack_wise"] = build_attack_wise(analysis_data)
        record = SimpleNamespace(
            id=7,
            risk_score=82,
            severity="critical",
            file=SimpleNamespace(original_name="demo.log"),
        )
        pdf = ReportService().build_pdf_bytes(record, analysis_data)
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertGreater(len(pdf), 400)
        self.assertIn(b"Attack Summary", pdf)
        self.assertIn(b"SQL Injection", pdf)
        self.assertIn(b"10.0.0.99", pdf)
        self.assertNotIn(b"<script>alert(1)</script>", pdf)
        self.assertNotIn(b"Detailed Findings by Attack Type", pdf)
        self.assertNotIn(b"Why it matched", pdf)


class AttackWiseAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.owner = cls._register("awowner", "aw-owner@example.com")
        cls.other = cls._register("awother", "aw-other@example.com")
        cls.analysis_id = cls._seed(cls.owner)

    @classmethod
    def _register(cls, username, email):
        resp = cls.client.post("/api/register", json={
            "username": username,
            "email": email,
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        })
        if resp.status_code != 201:
            raise AssertionError(resp.get_json())
        return resp.get_json()["token"]

    @classmethod
    def _seed(cls, token):
        me = cls.client.get("/api/me", headers=_auth(token)).get_json()["user"]
        payload = {
            "risk_score": 70,
            "severity": "high",
            "threats": [{
                "title": "Brute Force Attack",
                "category": "Brute Force",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "evidence": "FAILED ssh root@192.168.1.100 - Failed password attempt",
            }],
        }
        payload["attack_wise"] = build_attack_wise(payload)
        with app.app_context():
            uploaded = UploadedFile(
                user_id=me["id"],
                original_name="demo.log",
                stored_name="demo-stored.log",
                file_format="syslog",
            )
            db.session.add(uploaded)
            db.session.flush()
            row = Analysis(
                user_id=me["id"],
                file_id=uploaded.id,
                risk_score=70,
                severity="high",
                total_lines=8,
                threat_count=1,
                result_json=json.dumps(payload),
            )
            db.session.add(row)
            db.session.commit()
            return row.id

    def test_pdf_requires_auth(self):
        missing = self.client.get("/api/report/%s/pdf" % self.analysis_id)
        self.assertEqual(missing.status_code, 401)

    def test_pdf_owner_ok_other_forbidden(self):
        owner = self.client.get(
            "/api/report/%s/pdf" % self.analysis_id,
            headers=_auth(self.owner),
        )
        self.assertEqual(owner.status_code, 200)
        self.assertEqual(owner.mimetype, "application/pdf")
        self.assertTrue(owner.data.startswith(b"%PDF"))

        other = self.client.get(
            "/api/report/%s/pdf" % self.analysis_id,
            headers=_auth(self.other),
        )
        self.assertEqual(other.status_code, 403)

        missing = self.client.get("/api/report/999999/pdf", headers=_auth(self.owner))
        self.assertEqual(missing.status_code, 404)

    def test_json_report_includes_attack_wise(self):
        resp = self.client.get(
            "/api/report/%s" % self.analysis_id,
            headers=_auth(self.owner),
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attack_wise", resp.get_json())
        self.assertGreaterEqual(resp.get_json()["attack_wise"]["distinct_attack_types"], 1)

    def test_dashboard_distinct_types_match_attack_summary(self):
        me = self.client.get("/api/me", headers=_auth(self.owner)).get_json()["user"]
        payload = {
            "risk_score": 80,
            "severity": "critical",
            "threats": [
                {"title": "SQL Injection", "category": "Intrusion", "severity": "critical",
                 "source_ip": "10.0.0.99", "evidence": "GET /login.php?id=1 OR 1=1"},
                {"title": "Directory Traversal", "category": "Intrusion", "severity": "high",
                 "source_ip": "10.0.0.99", "evidence": "GET /../../../etc/passwd"},
                {"title": "Web Shell", "category": "Intrusion", "severity": "critical",
                 "source_ip": "10.0.0.99", "evidence": "GET /shell.php"},
                {"title": "Brute Force Attack", "category": "Brute Force", "severity": "high",
                 "source_ip": "192.168.1.100", "evidence": "FAILED ssh root"},
            ],
        }
        payload["attack_wise"] = build_attack_wise(payload)
        expected = summarize_attacks(payload["attack_wise"])["distinct_attack_types"]
        with app.app_context():
            uploaded = UploadedFile(
                user_id=me["id"],
                original_name="metric-consistency.log",
                stored_name="metric-consistency-stored.log",
                file_format="text",
            )
            db.session.add(uploaded)
            db.session.flush()
            analysis = Analysis(
                user_id=me["id"],
                file_id=uploaded.id,
                risk_score=80,
                severity="critical",
                total_lines=4,
                threat_count=4,
                result_json=json.dumps(payload),
            )
            db.session.add(analysis)
            db.session.flush()
            for threat in payload["threats"]:
                db.session.add(Threat(
                    analysis_id=analysis.id,
                    category=threat["category"],
                    severity=threat["severity"],
                    source_ip=threat.get("source_ip"),
                    message=threat.get("evidence"),
                ))
            db.session.commit()
            from sqlalchemy import func
            stored_categories = (
                db.session.query(func.count(func.distinct(Threat.category)))
                .filter(Threat.analysis_id == analysis.id)
                .scalar()
            )
        dash = self.client.get("/api/dashboard", headers=_auth(self.owner))
        self.assertEqual(dash.status_code, 200)
        data = dash.get_json()
        self.assertEqual(expected, 4)
        self.assertEqual(stored_categories, 2)
        self.assertEqual(data["distinct_attack_types"], expected)
        self.assertEqual(data["last_analysis"]["filename"], "metric-consistency.log")
        self.assertNotEqual(data["distinct_attack_types"], stored_categories)

    def test_dashboard_skips_later_code_scan_for_attack_types(self):
        me = self.client.get("/api/me", headers=_auth(self.owner)).get_json()["user"]
        log_payload = {
            "risk_score": 70,
            "severity": "high",
            "stats": {"total_lines": 3},
            "threats": [
                {"title": "SQL Injection", "category": "Intrusion", "severity": "critical",
                 "source_ip": "10.0.0.99", "evidence": "GET /x?id=1 OR 1=1"},
                {"title": "Brute Force Attack", "category": "Brute Force", "severity": "high",
                 "source_ip": "192.168.1.100", "evidence": "FAILED ssh root"},
            ],
        }
        log_payload["attack_wise"] = build_attack_wise(log_payload)
        expected = summarize_attacks(log_payload["attack_wise"])["distinct_attack_types"]
        with app.app_context():
            log_file = UploadedFile(
                user_id=me["id"],
                original_name="latest-log.log",
                stored_name="latest-log-stored.log",
                file_format="text",
            )
            code_file = UploadedFile(
                user_id=me["id"],
                original_name="later-scan.py",
                stored_name="later-scan-stored.py",
                file_format="code",
            )
            db.session.add_all([log_file, code_file])
            db.session.flush()
            db.session.add(Analysis(
                user_id=me["id"],
                file_id=log_file.id,
                risk_score=70,
                severity="high",
                total_lines=3,
                threat_count=2,
                result_json=json.dumps(log_payload),
            ))
            db.session.flush()
            db.session.add(Analysis(
                user_id=me["id"],
                file_id=code_file.id,
                risk_score=10,
                severity="low",
                total_lines=20,
                threat_count=0,
                result_json=json.dumps({"scan": True, "findings": []}),
            ))
            db.session.commit()
        dash = self.client.get("/api/dashboard", headers=_auth(self.owner))
        self.assertEqual(dash.status_code, 200)
        data = dash.get_json()
        self.assertEqual(expected, 2)
        self.assertEqual(data["distinct_attack_types"], expected)
        self.assertNotEqual(data["distinct_attack_types"], 0)


class AttackWiseEngineTests(unittest.TestCase):
    def test_sample_log_detects_multiple_real_categories(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        content = SAMPLE_PATH.read_text(encoding="utf-8")
        parser = LogParser()
        df = parser.parse(content)
        result = LogAnalyzer(df).analyze()
        names = {a["attack_name"] for a in result["attack_wise"]["attacks"]}
        self.assertGreaterEqual(result["attack_wise"]["distinct_attack_types"], 3)
        self.assertTrue(
            {"Brute Force Attack", "Port Scan Activity"} <= names,
            "expected brute-force and port-scan groups, got %s" % sorted(names),
        )
        self.assertTrue(
            names & {"SQL Injection", "Directory Traversal", "Web Shell", "Cross-Site Scripting (XSS)"},
            "expected an intrusion category, got %s" % sorted(names),
        )
        for attack in result["attack_wise"]["attacks"]:
            for event in attack["events"]:
                if event["evidence"]:
                    self.assertIn(event["evidence"].strip(), content)
                if event["source_ip"]:
                    self.assertRegex(event["source_ip"], r"^\d{1,3}(\.\d{1,3}){3}$")
        summary = result["attack_wise"]["summary"]
        self.assertEqual(len(summary["rows"]), result["attack_wise"]["distinct_attack_types"])
        for row in summary["rows"]:
            self.assertGreater(row["attempts"], 0)
            self.assertTrue(row["source_ip_display"])

    def test_all_attack_types_log_summary_matches_findings(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        candidates = [
            Path(__file__).resolve().parents[1] / "samples" / "logsentinel_all_attack_types_test.log",
            Path(__file__).resolve().parent / "uploads" / "1dd01d7dc3_logsentinel_all_attack_types_test.log",
        ]
        path = next((item for item in candidates if item.exists()), None)
        if path is None:
            self.skipTest("logsentinel_all_attack_types_test.log not found")

        content = path.read_text(encoding="utf-8")
        result = LogAnalyzer(LogParser().parse(content)).analyze()
        summary = summarize_attacks(result["attack_wise"])
        rebuilt = {row["attack_type"]: row for row in summary["rows"]}
        for attack in result["attack_wise"]["attacks"]:
            row = rebuilt[attack["attack_name"]]
            expected_ips = []
            missing = 0
            expected_attempts = 0
            for event in attack["events"]:
                n = event.get("attempt_count") or 1
                if isinstance(event.get("message"), str) and event["message"].startswith("5 failed"):
                    n = event.get("attempt_count") or 5
                if event.get("attempt_count"):
                    n = int(event["attempt_count"])
                elif isinstance(event.get("message"), str) and event["message"][:1].isdigit() and "failed logins" in event["message"]:
                    n = int(event["message"].split()[0])
                else:
                    n = 1
                expected_attempts += n
                if event.get("source_ip"):
                    expected_ips.append(event["source_ip"])
                    self.assertIn(event["source_ip"], content)
                    self.assertIn(event["source_ip"], row["source_ip_display"])
                else:
                    missing += 1
            self.assertEqual(row["attempts"], expected_attempts)
            if not expected_ips:
                self.assertEqual(row["source_ip_display"], "Not available")

    def test_overlapping_privilege_and_critical_are_not_double_counted(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        content = "\n".join([
            "2024-01-15 05:45:22 CRITICAL security: privilege escalation detected uid 1000 to 0",
            "2024-01-15 05:46:00 CRITICAL kernel: segfault at 0x00 ip 0xdeadbeef",
            "2024-01-15 06:00:00 INFO cron: job completed with no error",
            "2024-01-15 06:01:00 INFO app: suspicious-looking comment only",
        ])
        result = LogAnalyzer(LogParser().parse(content)).analyze()
        names = [item["title"] for item in result["threats"]]
        self.assertIn("Privilege Escalation / Unauthorized Access", names)
        self.assertIn("Critical System Event", names)
        self.assertEqual(names.count("Privilege Escalation / Unauthorized Access"), 1)
        self.assertEqual(names.count("Critical System Event"), 1)
        summary_names = [row["attack_type"] for row in result["attack_wise"]["summary"]["rows"]]
        self.assertEqual(summary_names.count("Privilege Escalation / Unauthorized Access"), 1)
        self.assertEqual(summary_names.count("Critical System Event"), 1)

    def test_benign_lines_do_not_create_findings(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        content = "\n".join([
            "2024-01-15 03:00:01 INFO cron: (root) CMD (/usr/bin/updatedb)",
            "2024-01-15 04:00:00 INFO syslog: Log rotation completed",
            "user said the word attack in a comment",
            "this line mentions an error in documentation only if the word is isolated: note",
        ])
        result = LogAnalyzer(LogParser().parse(content)).analyze()
        self.assertEqual(result["threats"], [])
        self.assertEqual(result["attack_wise"]["summary"]["rows"], [])

    def test_log_brute_force_default_threshold_is_two_not_live_alert_five(self):
        try:
            from services.log_analyzer import LogAnalyzer, log_brute_force_threshold
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        saved = os.environ.get("BRUTE_FORCE_THRESHOLD")
        try:
            os.environ.pop("BRUTE_FORCE_THRESHOLD", None)
            self.assertEqual(log_brute_force_threshold(), 2)
            one = LogAnalyzer(LogParser().parse(
                "2026-10-12T12:00:00Z WARNING sshd 198.51.100.77 Failed password for guest\n"
            )).analyze()
            self.assertNotIn("Brute Force Attack", {t["title"] for t in one["threats"]})
            self.assertEqual(one["brute_force"]["threshold_used"], 2)
            self.assertEqual(one["brute_force"]["total_failed_logins"], 1)

            two = LogAnalyzer(LogParser().parse(
                "2026-10-12T12:00:00Z WARNING sshd 198.51.100.77 Failed password for guest\n"
                "2026-10-12T12:00:01Z WARNING sshd 198.51.100.77 Failed password for guest\n"
            )).analyze()
            self.assertIn("Brute Force Attack", {t["title"] for t in two["threats"]})
            self.assertEqual(two["brute_force"]["threshold_used"], 2)
            self.assertEqual(two["brute_force"]["flagged_ips"][0]["attempt_count"], 2)
        finally:
            if saved is None:
                os.environ.pop("BRUTE_FORCE_THRESHOLD", None)
            else:
                os.environ["BRUTE_FORCE_THRESHOLD"] = saved

    def test_log_brute_force_reads_env_without_changing_alert_threshold(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        saved = os.environ.get("BRUTE_FORCE_THRESHOLD")
        two_lines = (
            "2026-10-12T12:00:00Z WARNING sshd 198.51.100.78 Failed password for guest\n"
            "2026-10-12T12:00:01Z WARNING sshd 198.51.100.78 Failed password for guest\n"
        )
        try:
            os.environ["BRUTE_FORCE_THRESHOLD"] = "3"
            raised = LogAnalyzer(LogParser().parse(two_lines)).analyze()
            self.assertNotIn("Brute Force Attack", {t["title"] for t in raised["threats"]})
            self.assertEqual(raised["brute_force"]["threshold_used"], 3)

            three = LogAnalyzer(LogParser().parse(
                two_lines + "2026-10-12T12:00:02Z WARNING sshd 198.51.100.78 Failed password for guest\n"
            )).analyze()
            self.assertIn("Brute Force Attack", {t["title"] for t in three["threats"]})
            self.assertEqual(three["brute_force"]["threshold_used"], 3)
        finally:
            if saved is None:
                os.environ.pop("BRUTE_FORCE_THRESHOLD", None)
            else:
                os.environ["BRUTE_FORCE_THRESHOLD"] = saved

    def test_parser_does_not_print_each_line(self):
        try:
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/parser unavailable: %s" % exc)

        buf = io.StringIO()
        with redirect_stdout(buf):
            df = LogParser().parse(
                "2026-10-11T09:00:10Z WARNING 198.51.100.25 Failed password attempt\n"
            )
        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(df.iloc[0]["ip_address"], "198.51.100.25")

    def test_command_injection_matches_shell_exec_and_whoami(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        hit = LogAnalyzer(LogParser().parse(
            "2026-10-11T09:05:00Z WARNING app 203.0.113.63 shell_exec(user_input)\n"
        )).analyze()
        names = {a["attack_name"] for a in hit["attack_wise"]["attacks"]}
        self.assertIn("Command Injection", names)

        whoami = LogAnalyzer(LogParser().parse(
            "2026-10-11T09:05:00Z WARNING app 203.0.113.63 Command injection indicator in input: ; whoami\n"
        )).analyze()
        whoami_names = {a["attack_name"] for a in whoami["attack_wise"]["attacks"]}
        self.assertIn("Command Injection", whoami_names)
        self.assertEqual(whoami["threats"][0]["evidence"], (
            "2026-10-11T09:05:00Z WARNING app 203.0.113.63 Command injection indicator in input: ; whoami"
        ))

    def test_command_injection_pipe_subshell_backtick_and_encoded(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        cases = [
            "2026-10-12T10:00:05Z WARNING app 203.0.113.14 input: | whoami",
            "2026-10-12T10:00:06Z WARNING app 203.0.113.15 payload: $(whoami)",
            "2026-10-12T10:00:07Z WARNING app 203.0.113.16 payload: `whoami`",
            "2026-10-12T10:00:08Z WARNING app 203.0.113.17 input: %3B%20whoami",
            "2026-10-12T10:00:09Z WARNING app 203.0.113.18 input: %7C%20whoami",
        ]
        for line in cases:
            result = LogAnalyzer(LogParser().parse(line + "\n")).analyze()
            names = {a["attack_name"] for a in result["attack_wise"]["attacks"]}
            self.assertIn("Command Injection", names, msg=line)
            evidence = {t["title"]: t["evidence"] for t in result["threats"]}
            self.assertEqual(evidence["Command Injection"], line)

        filesystem = LogAnalyzer(LogParser().parse(
            "2026-10-12T10:00:21Z INFO fs 192.0.2.13 filesystem(check) completed successfully\n"
        )).analyze()
        self.assertEqual(filesystem["threats"], [])

        docs = LogAnalyzer(LogParser().parse(
            "2026-10-12T10:00:20Z INFO docs 192.0.2.12 whoami is documented in the admin guide\n"
        )).analyze()
        self.assertEqual(docs["threats"], [])

        system_call = LogAnalyzer(LogParser().parse(
            "2026-10-12T10:00:30Z WARNING app 203.0.113.40 system(user_input)\n"
        )).analyze()
        self.assertIn("Command Injection", {a["attack_name"] for a in system_call["attack_wise"]["attacks"]})

    def test_overlap_preserves_independent_command_and_traversal(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        line = "2026-10-11T09:05:00Z WARNING app 203.0.113.63 Command injection: ; cat /etc/passwd"
        result = LogAnalyzer(LogParser().parse(line + "\n")).analyze()
        names = {a["attack_name"] for a in result["attack_wise"]["attacks"]}
        self.assertIn("Command Injection", names)
        self.assertIn("Directory Traversal", names)
        summary = {row["attack_type"]: row["attempts"] for row in result["attack_wise"]["summary"]["rows"]}
        self.assertEqual(summary["Command Injection"], 1)
        self.assertEqual(summary["Directory Traversal"], 1)
        for threat in result["threats"]:
            if threat["title"] in ("Command Injection", "Directory Traversal"):
                self.assertEqual(threat["evidence"], line)

    def test_encoded_payloads_match_without_replacing_evidence(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        xss_line = "2026-10-11T09:03:10Z WARNING web 203.0.113.66 GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E"
        trav_line = "2026-10-11T09:04:10Z WARNING web 203.0.113.67 GET /..%2F..%2Fetc/passwd HTTP/1.1"
        sql_line = "2026-10-11T09:02:10Z WARNING web 203.0.113.68 GET /login?id=%27%20OR%201%3D1"
        result = LogAnalyzer(LogParser().parse("\n".join([xss_line, trav_line, sql_line]))).analyze()
        names = {a["attack_name"] for a in result["attack_wise"]["attacks"]}
        self.assertIn("Cross-Site Scripting (XSS)", names)
        self.assertIn("Directory Traversal", names)
        self.assertIn("SQL Injection", names)
        evidence = {t["title"]: t["evidence"] for t in result["threats"]}
        self.assertEqual(evidence["Cross-Site Scripting (XSS)"], xss_line)
        self.assertEqual(evidence["Directory Traversal"], trav_line)
        self.assertEqual(evidence["SQL Injection"], sql_line)
        self.assertIn("%3Cscript", evidence["Cross-Site Scripting (XSS)"])
        self.assertIn("..%2F", evidence["Directory Traversal"])

    def test_encoded_benign_and_duplicate_overlap_are_not_inflated(self):
        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        benign = LogAnalyzer(LogParser().parse(
            "2026-10-11T09:13:00Z INFO web 192.0.2.10 GET /health%20check HTTP/1.1 200\n"
            "user%20said%20the%20word%20attack%20in%20a%20comment\n"
        )).analyze()
        self.assertEqual(benign["threats"], [])

        dup = LogAnalyzer(LogParser().parse(
            "2026-10-11T09:05:00Z WARNING app 203.0.113.63 Command injection: ; cat /etc/passwd\n"
            "2026-10-11T09:05:00Z WARNING app 203.0.113.63 Command injection: ; cat /etc/passwd\n"
        )).analyze()
        summary = {row["attack_type"]: row["attempts"] for row in dup["attack_wise"]["summary"]["rows"]}
        self.assertEqual(summary.get("Command Injection"), 1)
        self.assertEqual(summary.get("Directory Traversal"), 1)

    def test_frontend_uses_compact_attack_summary(self):
        html = (Path(__file__).resolve().parents[1] / "forntend" / "index11.html").read_text(encoding="utf-8")
        self.assertIn("Attack Summary", html)
        self.assertIn("Source IP Address", html)
        self.assertIn("WARNING port scan:", html)
        self.assertNotIn("WARNING port_scan:", html)
        self.assertIn("scroll-padding-top: calc(var(--nav-h) + 12px)", html)
        self.assertIn("scroll-margin-top: calc(var(--nav-h) + 16px)", html)
        self.assertNotIn("Attack-Wise Analysis", html)
        self.assertNotIn("Why it matched", html)
        self.assertNotIn("Recommended remediation", html)

    def test_frontend_keeps_original_dark_background_and_theme_toggle(self):
        html = (Path(__file__).resolve().parents[1] / "forntend" / "index11.html").read_text(encoding="utf-8")
        self.assertIn("--bg:       #050810;", html)
        self.assertIn("repeating-linear-gradient(", html)
        self.assertIn('id="matrix-canvas"', html)
        self.assertIn('id="particle-canvas"', html)
        self.assertIn('class="hero-grid-overlay"', html)
        self.assertIn('class="hero-radial"', html)
        self.assertIn('id="themeToggle"', html)
        self.assertIn("ls_theme", html)
        self.assertIn('data-theme="dark"', html)
        self.assertIn("Switch to Light Mode", html)
        self.assertIn("theme-icon-moon", html)
        self.assertIn("theme-icon-sun", html)
        self.assertIn('html[data-theme="light"]', html)
        self.assertIn('<span class="word-log">LOG</span><span class="word-sentinel">SENTINEL</span>', html)
        hero = html.split('<h1 class="hero-title">', 1)[-1].split("</h1>", 1)[0]
        self.assertNotIn("word-tagline", hero)
        self.assertNotIn("Analyze uploaded logs", hero)
        self.assertNotIn("LogSentinel parses uploaded syslog", html)

    def test_removed_sections_and_top_source_ips_use_real_data(self):
        html = (Path(__file__).resolve().parents[1] / "forntend" / "index11.html").read_text(encoding="utf-8")
        self.assertNotIn('<h2 class="section-heading">Incident Investigation</h2>', html)
        self.assertNotIn('id="incident-details"', html)
        self.assertNotIn('id="incidents"', html)
        self.assertNotIn("Threat Intel Timeline", html)
        self.assertNotIn('id="tiTimelineFeed"', html)
        self.assertIn("Hi, I am SentinelAI.", html)
        self.assertNotIn("I do not invent scan results.", html)
        self.assertIn("collectTopSourceIps", html)
        self.assertIn("No source IP addresses were present in this analysis.", html)
        self.assertIn("cyber-holo", html)
        self.assertIn('class="cyber-stage"', html)

        try:
            from services.log_analyzer import LogAnalyzer
            from services.log_parser import LogParser
        except ImportError as exc:
            self.skipTest("pandas/analyzer unavailable: %s" % exc)

        root = Path(__file__).resolve().parents[1]
        multi = (root / "samples" / "multi_attack_demo.log").read_text(encoding="utf-8")
        multi_ips = LogAnalyzer(LogParser().parse(multi)).analyze()["stats"]["top_ips"]
        self.assertEqual(multi_ips.get("192.168.1.100"), 3)
        self.assertEqual(multi_ips.get("172.16.0.200"), 1)
        self.assertEqual(multi_ips.get("10.0.0.99"), 4)
        self.assertNotIn("nan", {str(k).lower() for k in multi_ips})
        self.assertTrue(all(str(k).count(".") == 3 for k in multi_ips))

        all_path = root / "backend" / "uploads" / "1e012fa667_logsentinel_all_attack_types_test.log"
        if all_path.exists():
            all_ips = LogAnalyzer(LogParser().parse(all_path.read_text(encoding="utf-8"))).analyze()["stats"]["top_ips"]
            self.assertIn("198.51.100.25", all_ips)
            self.assertGreaterEqual(all_ips["198.51.100.25"], 4)
            self.assertNotIn("nan", {str(k).lower() for k in all_ips})


if __name__ == "__main__":
    unittest.main(verbosity=2)

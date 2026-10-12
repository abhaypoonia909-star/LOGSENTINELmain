"""Source-code scanner tests: .txt uploads, ZIP, validation, and existing formats."""
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

DB_PATH = Path(tempfile.gettempdir()) / "logsentinel_code_scan_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + DB_PATH.as_posix()
os.environ["JWT_SECRET"] = "code-scan-test-secret-32-bytes-xx"
os.environ["SECRET_KEY"] = "code-scan-test-secret-32-bytes-xx"
os.environ["AUTH_RATE_LIMIT"] = "5000/minute"
os.environ["RATE_LIMIT"] = "5000/minute"
os.environ["AI_PROVIDER"] = "local"

from flask import Flask  # noqa: E402
from werkzeug.exceptions import RequestEntityTooLarge  # noqa: E402

from config import Config  # noqa: E402
from models import db  # noqa: E402
from models.models import ensure_user_schema  # noqa: E402
from routes.analysis import analysis_bp  # noqa: E402
from routes.auth import auth_bp  # noqa: E402
from routes.code_analysis import code_analysis_bp  # noqa: E402
from services.code_scanner import CodeScannerService  # noqa: E402
from utils.validators import decode_source_text  # noqa: E402


PY_SOURCE = b"import os\nos.system(input())\nprint('ok')\n"
JS_SOURCE = b"eval(userInput);\n"
TXT_SOURCE = (
    b"# saved as text, still source code\n"
    b"import os\n"
    b"os.system(input())\n"
)
TXT_LOG = (
    b"2024-01-15 02:14:33 FAILED ssh root@192.168.1.100 - Failed password attempt\n"
    b"2024-01-15 02:14:35 FAILED ssh root@192.168.1.100 - Failed password attempt\n"
    b"2024-01-15 02:14:37 FAILED ssh root@192.168.1.100 - Failed password attempt\n"
    b"2024-01-15 02:14:39 FAILED ssh root@192.168.1.100 - Failed password attempt\n"
    b"2024-01-15 02:14:41 FAILED ssh root@192.168.1.100 - Failed password attempt\n"
)
FRONTEND = Path(__file__).resolve().parents[1] / "forntend" / "index11.html"


def create_test_app():
    application = Flask(__name__)
    application.config.from_object(Config)
    db.init_app(application)
    application.register_blueprint(auth_bp, url_prefix="/api")
    application.register_blueprint(code_analysis_bp, url_prefix="/api")
    application.register_blueprint(analysis_bp, url_prefix="/api")

    @application.errorhandler(413)
    @application.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        limit = application.config.get("MAX_CONTENT_LENGTH") or (10 * 1024 * 1024)
        limit_mb = max(1, int(limit) // (1024 * 1024))
        return {"error": f"File exceeds the {limit_mb} MB upload limit."}, 413

    with application.app_context():
        db.create_all()
        ensure_user_schema()
    return application


app = create_test_app()


def _auth(token):
    return {"Authorization": "Bearer " + token}


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buf.getvalue()


class DecodeSourceTextTests(unittest.TestCase):
    def test_rejects_empty_and_binary(self):
        with self.assertRaises(ValueError) as empty:
            decode_source_text(b"")
        self.assertIn("empty", str(empty.exception).lower())
        with self.assertRaises(ValueError) as binary:
            decode_source_text(b"abc\x00def")
        self.assertIn("binary", str(binary.exception).lower())

    def test_rejects_invalid_utf8(self):
        with self.assertRaises(ValueError) as invalid:
            decode_source_text(b"\xff\xfe\xfa")
        self.assertIn("utf-8", str(invalid.exception).lower())

    def test_accepts_utf8(self):
        self.assertEqual(decode_source_text(b"os.system(input())\n"), "os.system(input())\n")


class PlaintextScannerTests(unittest.TestCase):
    def test_txt_reuses_python_rules_and_keeps_filename_and_line(self):
        result = CodeScannerService().scan_file(TXT_SOURCE.decode("utf-8"), "notes.txt")
        self.assertEqual(result["filename"], "notes.txt")
        self.assertGreaterEqual(result["vulnerability_count"], 1)
        command = next(
            item for item in result["vulnerabilities"]
            if "os.system" in (item.get("snippet") or "") or "os.system" in item["description"]
        )
        self.assertEqual(command["file"], "notes.txt")
        self.assertEqual(command["line"], 3)
        self.assertTrue(command.get("recommendation"))
        self.assertTrue(command.get("snippet"))


class CodeScanRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        signup = cls.client.post("/api/register", json={
            "username": "scanner",
            "email": "scanner@example.com",
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        })
        cls.token = signup.get_json()["token"]

    def _post_scan(self, payload, filename):
        return self.client.post(
            "/api/code-scan",
            headers=_auth(self.token),
            data={"file": (io.BytesIO(payload), filename)},
            content_type="multipart/form-data",
        )

    def test_txt_source_upload_returns_findings(self):
        resp = self._post_scan(TXT_SOURCE, "saved_script.txt")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        data = resp.get_json()
        self.assertEqual(data["filename"], "saved_script.txt")
        self.assertEqual(data["scan_type"], "code")
        self.assertGreaterEqual(data["vulnerability_count"], 1)
        hit = next(item for item in data["vulnerabilities"] if item["line"] == 3)
        self.assertEqual(hit["file"], "saved_script.txt")
        self.assertIn("os.system", hit["snippet"])
        self.assertTrue(hit["recommendation"])
        self.assertEqual(hit["match_kind"], "pattern_match")
        self.assertIn("subprocess", hit["suggested_fix"])
        self.assertTrue(hit["fix_explanation"])
        self.assertIn("3›", hit["context"])

    def test_txt_log_upload_goes_to_analyzer(self):
        with patch("routes.analysis.AIService") as mock_ai:
            mock_ai.return_value.analyze_security.return_value = {
                "executive_ai_summary": "stub",
            }
            resp = self.client.post(
                "/api/analyze",
                headers=_auth(self.token),
                data={"file": (io.BytesIO(TXT_LOG), "bruteforce.txt")},
                content_type="multipart/form-data",
            )
        self.assertEqual(resp.status_code, 200, resp.get_json())
        data = resp.get_json()
        self.assertEqual(data["meta"]["filename"], "bruteforce.txt")
        threats = data.get("analysis", {}).get("threats") or []
        self.assertGreater(len(threats), 0)
        self.assertNotIn("vulnerabilities", data)

    def test_zip_upload_still_scans_python(self):
        raw = _zip_bytes({"src/bad.py": PY_SOURCE, "readme.md": b"# docs\n"})
        resp = self._post_scan(raw, "bundle.zip")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        data = resp.get_json()
        self.assertEqual(data["filename"], "bundle.zip")
        self.assertIn("src/bad.py", data["scanned_files"])
        self.assertGreaterEqual(data["vulnerability_count"], 1)

    def test_zip_scans_inner_txt(self):
        raw = _zip_bytes({"notes.txt": TXT_SOURCE})
        resp = self._post_scan(raw, "notes.zip")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        files = resp.get_json()["scanned_files"]
        self.assertEqual(files, ["notes.txt"])
        self.assertGreaterEqual(resp.get_json()["vulnerability_count"], 1)

    def test_invalid_extension_rejected(self):
        resp = self._post_scan(b"print(1)\n", "payload.exe")
        self.assertEqual(resp.status_code, 400)
        self.assertIn(".txt", resp.get_json()["error"])
        self.assertIn("Unsupported", resp.get_json()["error"])

    def test_empty_file_rejected(self):
        empty = self._post_scan(b"", "empty.txt")
        self.assertEqual(empty.status_code, 400)
        self.assertIn("empty", empty.get_json()["error"].lower())
        whitespace = self._post_scan(b"  \n  ", "spaces.py")
        self.assertEqual(whitespace.status_code, 400)
        self.assertIn("empty", whitespace.get_json()["error"].lower())

    def test_oversized_file_returns_clear_413(self):
        previous = app.config.get("MAX_CONTENT_LENGTH")
        app.config["MAX_CONTENT_LENGTH"] = 2048
        try:
            resp = self._post_scan(b"os.system(input())\n" + (b"a" * 4000), "huge.py")
            self.assertEqual(resp.status_code, 413)
            body = resp.get_json() or {}
            self.assertIn("upload limit", (body.get("error") or "").lower())
        finally:
            app.config["MAX_CONTENT_LENGTH"] = previous

    def test_binary_txt_rejected(self):
        resp = self._post_scan(b"print(1)\x00\x00", "blob.txt")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("binary", resp.get_json()["error"].lower())

    def test_python_and_js_regression(self):
        py_resp = self._post_scan(PY_SOURCE, "bad.py")
        self.assertEqual(py_resp.status_code, 200, py_resp.get_json())
        self.assertGreaterEqual(py_resp.get_json()["vulnerability_count"], 1)
        self.assertEqual(py_resp.get_json()["filename"], "bad.py")

        js_resp = self._post_scan(JS_SOURCE, "bad.js")
        self.assertEqual(js_resp.status_code, 200, js_resp.get_json())
        self.assertGreaterEqual(js_resp.get_json()["vulnerability_count"], 1)
        self.assertEqual(js_resp.get_json()["filename"], "bad.js")

    def test_code_scan_requires_auth(self):
        resp = self.client.post(
            "/api/code-scan",
            data={"file": (io.BytesIO(PY_SOURCE), "bad.py")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 401)

    def test_frontend_accepts_txt_and_offers_choice(self):
        html = FRONTEND.read_text(encoding="utf-8")
        self.assertIn('id="codeScanInput" accept=".py,.js,.jsx,.ts,.tsx,.php,.html,.css,.txt,.zip,.java,.cs,.sql,.json,.yml,.yaml,.xml,.env,.ini,.config"', html)
        self.assertIn('name="txtIntent"', html)
        self.assertIn("Source Code Scan", html)
        self.assertIn("Security Log Analysis", html)
        self.assertIn("Log analysis remains 10 MB", html)
        self.assertIn("CODE_SCAN_MAX_UPLOAD_BYTES", html)
        self.assertIn("Nested ZIP files", html)
        self.assertIn("scanSourceFile", html)
        self.assertIn("File exceeds the code-scan upload limit.", html)
        self.assertIn("scan-warnings", html)
        self.assertIn("renderFindingCard", html)
        self.assertIn("Suggested Fix", html)
        self.assertIn("Copy Fixed Code", html)
        self.assertIn("Potential pattern match", html)
        self.assertIn("finding-card", html)
        self.assertIn("vuln-line-hit", html)

    def test_php_html_css_regression(self):
        php = self._post_scan(b"<?php mysql_query($q); ?>\n", "bad.php")
        self.assertEqual(php.status_code, 200, php.get_json())
        self.assertGreaterEqual(php.get_json()["vulnerability_count"], 1)
        html = self._post_scan(b"<script>eval(1)</script>\n", "bad.html")
        self.assertEqual(html.status_code, 200, html.get_json())
        css = self._post_scan(b"body { color: red; }\n", "ok.css")
        self.assertEqual(css.status_code, 200, css.get_json())

    def test_corrupted_zip_rejected(self):
        resp = self._post_scan(b"this is not a zip", "broken.zip")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("corrupted", resp.get_json()["error"].lower())

    def test_nested_folder_zip_is_scanned(self):
        raw = _zip_bytes({"src/app/bad.py": PY_SOURCE})
        resp = self._post_scan(raw, "nested.zip")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertIn("src/app/bad.py", resp.get_json()["scanned_files"])
        self.assertGreaterEqual(resp.get_json()["vulnerability_count"], 1)

    def test_nested_zip_is_not_scanned_and_is_warned(self):
        inner = _zip_bytes({"inner.py": PY_SOURCE})
        raw = _zip_bytes({"payload.zip": inner, "ok.py": PY_SOURCE})
        resp = self._post_scan(raw, "outer.zip")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        data = resp.get_json()
        self.assertIn("ok.py", data["scanned_files"])
        self.assertNotIn("payload.zip", data["scanned_files"])
        reasons = " ".join(item["reason"] for item in data["warnings"])
        self.assertIn("Nested ZIP files are not scanned", reasons)
        self.assertFalse(data["limits"]["nested_zips_scanned"])

    def test_oversized_zip_member_is_warned(self):
        huge = b"# " + (b"a" * 6000)
        raw = _zip_bytes({"huge.py": huge, "ok.py": PY_SOURCE})
        result = CodeScannerService().scan_zip(raw, "limits.zip", max_file_bytes=100)
        self.assertIn("ok.py", result["scanned_files"])
        self.assertNotIn("huge.py", result["scanned_files"])
        self.assertTrue(any("per-file limit" in item["reason"] and item["file"] == "huge.py" for item in result["warnings"]))

    def test_zip_file_count_limit_is_warned(self):
        raw = _zip_bytes({"one.py": PY_SOURCE, "two.py": PY_SOURCE})
        result = CodeScannerService().scan_zip(raw, "count.zip", max_files=1)
        self.assertEqual(result["scanned_files"], ["one.py"])
        self.assertTrue(any("file-count limit" in item["reason"] for item in result["warnings"]))

    def test_zip_extract_size_limit_is_warned(self):
        raw = _zip_bytes({"a.py": PY_SOURCE, "b.py": PY_SOURCE})
        result = CodeScannerService().scan_zip(raw, "extract.zip", max_extract_bytes=len(PY_SOURCE) + 2)
        self.assertEqual(result["scanned_files"], ["a.py"])
        self.assertTrue(any("extracted-size limit" in item["reason"] for item in result["warnings"]))

    def test_zip_path_traversal_is_warned(self):
        raw = _zip_bytes({"../evil.py": PY_SOURCE, "ok.py": PY_SOURCE})
        result = CodeScannerService().scan_zip(raw, "slip.zip")
        self.assertIn("ok.py", result["scanned_files"])
        self.assertTrue(any("Unsafe archive path" in item["reason"] for item in result["warnings"]))

    def test_code_report_owner_only(self):
        scan = self._post_scan(PY_SOURCE, "owned.py")
        self.assertEqual(scan.status_code, 200, scan.get_json())
        analysis_id = scan.get_json()["analysis_id"]
        other = self.client.post("/api/register", json={
            "username": "malloryscan",
            "email": "malloryscan@example.com",
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        }).get_json()["token"]
        forbidden = self.client.get("/api/code-report/%s" % analysis_id, headers=_auth(other))
        self.assertEqual(forbidden.status_code, 403)
        allowed = self.client.get("/api/code-report/%s" % analysis_id, headers=_auth(self.token))
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.get_json()["filename"], "owned.py")


class FindingEvidenceTests(unittest.TestCase):
    def _assert_evidence(self, source: str, finding: dict):
        lines = source.splitlines()
        idx = finding["line"] - 1
        self.assertGreaterEqual(idx, 0)
        self.assertLess(idx, len(lines))
        self.assertIn(f"{finding['line']:>4}›", finding["context"])
        if finding.get("redacted"):
            self.assertIn("***REDACTED***", finding["snippet"])
        else:
            self.assertEqual(finding["snippet"], lines[idx].strip())
            self.assertIn(lines[idx], finding["context"])
        self.assertEqual(finding["match_kind"], "pattern_match")
        self.assertTrue(finding.get("suggested_fix"))
        self.assertTrue(finding.get("fix_explanation"))
        self.assertTrue(finding.get("extra_steps"))
        self.assertIn("complete_fix", finding)

    def test_python_findings_keep_real_lines_and_suggest_fixes(self):
        source = (
            "import os\n"
            "def run():\n"
            "    os.system(input())\n"
            '    password = "hunter2x"\n'
            "    eval(payload)\n"
        )
        result = CodeScannerService().scan_file(source, "app.py")
        by_line = {}
        for item in result["vulnerabilities"]:
            by_line.setdefault(item["line"], item)
            self._assert_evidence(source, item)
            self.assertEqual(item["file"], "app.py")
            self.assertEqual(item["language"], "python")
        self.assertEqual(by_line[3]["snippet"], "os.system(input())")
        self.assertIn("subprocess.run", by_line[3]["suggested_fix"])
        self.assertFalse(by_line[3]["complete_fix"])
        self.assertIn("Minimal example", by_line[3]["suggested_fix"])
        self.assertTrue(by_line[3]["suggested_fix"].startswith("    "))
        self.assertTrue(by_line[4]["redacted"])
        self.assertIn("password", by_line[4]["snippet"].lower())
        self.assertIn("***REDACTED***", by_line[4]["snippet"])
        self.assertIn("os.environ", by_line[4]["suggested_fix"])
        self.assertIn("PASSWORD", by_line[4]["suggested_fix"])
        self.assertTrue(by_line[4]["complete_fix"])
        self.assertEqual(by_line[5]["snippet"], "eval(payload)")
        self.assertIn("literal_eval", by_line[5]["suggested_fix"])
        self.assertFalse(by_line[5]["complete_fix"])

    def test_javascript_innerhtml_and_eval(self):
        source = "eval(userInput);\nel.innerHTML = userInput;\n"
        result = CodeScannerService().scan_file(source, "app.js")
        self.assertGreaterEqual(result["vulnerability_count"], 2)
        eval_hit = next(item for item in result["vulnerabilities"] if item["line"] == 1)
        xss_hit = next(item for item in result["vulnerabilities"] if "innerHTML" in item["snippet"])
        self._assert_evidence(source, eval_hit)
        self._assert_evidence(source, xss_hit)
        self.assertEqual(eval_hit["language"], "javascript")
        self.assertIn("JSON.parse", eval_hit["suggested_fix"])
        self.assertFalse(eval_hit["complete_fix"])
        self.assertIn("textContent", xss_hit["suggested_fix"])
        self.assertTrue(xss_hit["complete_fix"])

    def test_php_echo_and_mysql_query(self):
        source = "<?php\necho $_GET['q'];\nmysql_query($q);\n"
        result = CodeScannerService().scan_file(source, "app.php")
        echo_hit = next(item for item in result["vulnerabilities"] if item["line"] == 2)
        sql_hit = next(item for item in result["vulnerabilities"] if item["line"] == 3)
        self._assert_evidence(source, echo_hit)
        self._assert_evidence(source, sql_hit)
        self.assertIn("htmlspecialchars", echo_hit["suggested_fix"])
        self.assertIn("$_GET['q']", echo_hit["suggested_fix"])
        self.assertIn("prepare", sql_hit["suggested_fix"])
        self.assertFalse(sql_hit["complete_fix"])

    def test_html_http_script_uses_https(self):
        source = '<script src="http://cdn.example/app.js"></script>\n'
        result = CodeScannerService().scan_file(source, "page.html")
        hit = next(
            item for item in result["vulnerabilities"]
            if "https://cdn.example/app.js" in (item.get("suggested_fix") or "")
        )
        self._assert_evidence(source, hit)
        self.assertEqual(hit["language"], "html")
        self.assertTrue(hit["complete_fix"])

    def test_clean_python_and_css_have_no_findings(self):
        py = CodeScannerService().scan_file("print('hello')\nvalue = 1 + 2\n", "ok.py")
        css = CodeScannerService().scan_file("body { color: red; }\n", "ok.css")
        self.assertEqual(py["vulnerability_count"], 0)
        self.assertEqual(py["vulnerabilities"], [])
        self.assertEqual(css["vulnerability_count"], 0)
        self.assertEqual(css["vulnerabilities"], [])

    def test_txt_source_gets_language_and_fix(self):
        source = TXT_SOURCE.decode("utf-8")
        result = CodeScannerService().scan_file(source, "notes.txt")
        hit = next(item for item in result["vulnerabilities"] if item["line"] == 3)
        self._assert_evidence(source, hit)
        self.assertEqual(hit["language"], "python")
        self.assertIn("subprocess", hit["suggested_fix"])

    def test_sql_injection_is_labelled_minimal(self):
        source = 'cursor.execute("SELECT * FROM t WHERE id=" + user_id)\n'
        result = CodeScannerService().scan_file(source, "query.py")
        hit = result["vulnerabilities"][0]
        self._assert_evidence(source, hit)
        self.assertIn("%s", hit["suggested_fix"])
        self.assertFalse(hit["complete_fix"])
        self.assertIn("Minimal example", hit["suggested_fix"])


if __name__ == "__main__":
    unittest.main(verbosity=2)

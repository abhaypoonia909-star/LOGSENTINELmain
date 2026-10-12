"""Large-project code-scan tests: ZIP limits, new languages, jobs, compare."""
import io
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

DB_PATH = Path(tempfile.gettempdir()) / "logsentinel_large_scan_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + DB_PATH.as_posix()
os.environ["JWT_SECRET"] = "large-scan-test-secret-32-bytes-xxx"
os.environ["SECRET_KEY"] = "large-scan-test-secret-32-bytes-xxx"
os.environ["AUTH_RATE_LIMIT"] = "5000/minute"
os.environ["RATE_LIMIT"] = "5000/minute"
os.environ["AI_PROVIDER"] = "local"

from flask import Flask  # noqa: E402
from werkzeug.exceptions import RequestEntityTooLarge  # noqa: E402

from config import Config  # noqa: E402
from models import db  # noqa: E402
from models.models import ensure_user_schema  # noqa: E402
from routes.auth import auth_bp  # noqa: E402
from routes.code_analysis import code_analysis_bp  # noqa: E402
from services.code_scanner import CodeScannerService  # noqa: E402

FRONTEND = Path(__file__).resolve().parents[1] / "forntend" / "index11.html"


def create_test_app():
    application = Flask(__name__)
    application.config.from_object(Config)
    db.init_app(application)
    application.register_blueprint(auth_bp, url_prefix="/api")
    application.register_blueprint(code_analysis_bp, url_prefix="/api")

    @application.errorhandler(413)
    @application.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        return {"error": "File exceeds the upload limit."}, 413

    with application.app_context():
        db.create_all()
        ensure_user_schema()
    return application


app = create_test_app()


def _auth(token):
    return {"Authorization": "Bearer " + token}


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buf.getvalue()


def sample_project() -> dict[str, bytes]:
    return {
        "src/app.py": (
            b"import os\n"
            b"def run():\n"
            b"    os.system(input())\n"
            b'    password = "hunter2x"\n'
        ),
        "src/clean.py": b"print('hello')\nvalue = 1 + 2\n",
        "web/app.js": b"eval(userInput);\nel.innerHTML = userInput;\n",
        "web/ok.js": b"const value = 1 + 2;\n",
        "web/app.ts": b"el.innerHTML = userInput;\n",
        "api/upload.php": b"<?php echo $_GET['q'];\nmysql_query($q);\n",
        "App.java": b'Runtime.getRuntime().exec(cmd);\nString q = "SELECT * FROM t WHERE id=" + id;\n',
        "Program.cs": b'Process.Start("cmd " + user);\n',
        "queries.sql": b"EXEC(@dynsql);\n",
        "config/appsettings.json": b'{"debug": true, "password": "hunter2x"}\n',
        "requirements.txt": b"flask==0.12.0\n",
        "nested/deep/util.py": b"import pickle\npickle.loads(blob)\n",
        "node_modules/leftpad/index.js": b"eval(1);\n",
        "readme.md": b"# docs\n",
        "notes.txt": b"os.system(input())\n",
    }


class LargeProjectScannerTests(unittest.TestCase):
    def test_sample_project_findings_and_skips(self):
        raw = _zip_bytes(sample_project())
        result = CodeScannerService().scan_zip(raw, "sample.zip")
        files = result["scanned_files"]
        self.assertIn("src/app.py", files)
        self.assertIn("nested/deep/util.py", files)
        self.assertIn("App.java", files)
        self.assertIn("Program.cs", files)
        self.assertIn("queries.sql", files)
        self.assertIn("web/app.ts", files)
        self.assertNotIn("node_modules/leftpad/index.js", files)
        self.assertGreaterEqual(result["stats"]["excluded_files_count"], 1)
        self.assertGreaterEqual(result["stats"]["unsupported_files_count"], 1)
        self.assertTrue(result["stats"]["scan_complete"])
        self.assertGreater(result["stats"]["lines_scanned"], 10)
        by_file = {item["file"]: item["snippet"] for item in result["vulnerabilities"]}
        self.assertIn("src/app.py", by_file)
        py = next(item for item in result["vulnerabilities"] if item["file"] == "src/app.py" and item["line"] == 3)
        self.assertEqual(py["snippet"], "os.system(input())")
        self.assertEqual(py["classification"], "suspected")
        secret = next(item for item in result["vulnerabilities"] if item["file"] == "src/app.py" and "password" in item["snippet"].lower())
        self.assertIn("***REDACTED***", secret["snippet"])
        self.assertTrue(any(item["file"] == "App.java" and "Command" in item["type"] for item in result["vulnerabilities"]))
        self.assertTrue(any(item["file"] == "Program.cs" for item in result["vulnerabilities"]))
        self.assertTrue(any(item["file"] == "queries.sql" for item in result["vulnerabilities"]))
        self.assertTrue(any(item["type"] == "Dependency Hint" for item in result["vulnerabilities"]))
        self.assertFalse(any(item["file"].startswith("node_modules/") for item in result["vulnerabilities"]))
        self.assertTrue(any("Unsupported" in item["reason"] for item in result["warnings"]))
        self.assertIn("src/clean.py", result["scanned_files"])
        self.assertFalse(any(item["file"] == "src/clean.py" for item in result["vulnerabilities"]))

    def test_larger_multi_file_project_counts(self):
        files = {f"pkg/mod_{index:03d}.py": f"print({index})\n".encode() for index in range(80)}
        files["pkg/mod_000.py"] = b"os.system(input())\n"
        files["pkg/mod_001.py"] = b"os.system(input() + 'x')\n"
        result = CodeScannerService().scan_zip(_zip_bytes(files), "many.zip")
        self.assertEqual(result["stats"]["scanned_files_count"], 80)
        self.assertEqual(result["stats"]["duplicate_files_count"], 0)
        self.assertGreaterEqual(result["vulnerability_count"], 2)
        self.assertEqual(len([item for item in result["vulnerabilities"] if item["type"] == "Command Injection"]), 2)

    def test_duplicate_content_is_not_rescanned(self):
        payload = b"os.system(input())\n"
        result = CodeScannerService().scan_zip(
            _zip_bytes({"a.py": payload, "copy/a.py": payload}),
            "dup.zip",
        )
        self.assertEqual(result["stats"]["scanned_files_count"], 1)
        self.assertEqual(result["stats"]["duplicate_files_count"], 1)
        self.assertEqual(result["vulnerability_count"], 1)

    def test_timeout_marks_incomplete(self):
        files = {f"f{index}.py": f"print({index})\n".encode() for index in range(20)}
        result = CodeScannerService().scan_zip(_zip_bytes(files), "slow.zip", max_duration_seconds=0)
        self.assertFalse(result["stats"]["scan_complete"])
        self.assertEqual(result["stats"]["stop_reason"], "duration_limit")
        self.assertTrue(any(item["category"] == "timeout" for item in result["warnings"]))

    def test_zip_bomb_ratio_skipped(self):
        raw = _zip_bytes({"bomb.py": b"a" * 200000})
        result = CodeScannerService().scan_zip(raw, "bomb.zip", max_file_bytes=400000, max_ratio=50)
        self.assertNotIn("bomb.py", result["scanned_files"])
        self.assertTrue(any("ZIP bomb" in item["reason"] or "Compression ratio" in item["reason"] for item in result["warnings"]))

    def test_symlink_skipped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            info = zipfile.ZipInfo("link.py")
            info.external_attr = 0o120777 << 16
            archive.writestr(info, b"os.system(input())\n")
            archive.writestr("ok.py", b"print(1)\n")
        result = CodeScannerService().scan_zip(buf.getvalue(), "link.zip")
        self.assertIn("ok.py", result["scanned_files"])
        self.assertNotIn("link.py", result["scanned_files"])
        self.assertTrue(any("Symbolic links" in item["reason"] for item in result["warnings"]))


class LargeProjectRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        signup = cls.client.post("/api/register", json={
            "username": "largeuser",
            "email": "largeuser@example.com",
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        })
        cls.token = signup.get_json()["token"]

    def _wait_job(self, job_id, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.client.get("/api/code-scan/jobs/" + job_id, headers=_auth(self.token))
            data = resp.get_json() or {}
            if data.get("status") in {"done", "failed", "timeout", "cancelled"}:
                return resp
            time.sleep(0.05)
        self.fail("job %s did not finish" % job_id)

    def test_limits_endpoint(self):
        resp = self.client.get("/api/code-scan/limits")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("max_upload_bytes", data)
        self.assertIn("log_upload_max_bytes", data)
        self.assertEqual(data["log_upload_max_bytes"], Config.MAX_CONTENT_LENGTH)
        self.assertNotEqual(data["max_upload_bytes"], data["log_upload_max_bytes"])
        self.assertIn(".java", data["supported_extensions"])

    def test_job_scan_and_owner_only(self):
        raw = _zip_bytes(sample_project())
        started = self.client.post(
            "/api/code-scan/jobs",
            headers=_auth(self.token),
            data={"file": (io.BytesIO(raw), "sample.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(started.status_code, 202, started.get_json())
        job_id = started.get_json()["job_id"]
        done = self._wait_job(job_id)
        body = done.get_json()
        self.assertEqual(body["status"], "done", body)
        self.assertGreaterEqual(body["result"]["vulnerability_count"], 1)
        other = self.client.post("/api/register", json={
            "username": "largeother",
            "email": "largeother@example.com",
            "password": "Sentinel123",
            "confirm_password": "Sentinel123",
        }).get_json()["token"]
        forbidden = self.client.get("/api/code-scan/jobs/" + job_id, headers=_auth(other))
        self.assertEqual(forbidden.status_code, 403)

    def test_cancel_job(self):
        files = {f"f{index}.py": ("print(%s)\n" % index).encode() for index in range(40)}
        started = self.client.post(
            "/api/code-scan/jobs",
            headers=_auth(self.token),
            data={"file": (io.BytesIO(_zip_bytes(files)), "cancel.zip")},
            content_type="multipart/form-data",
        )
        job_id = started.get_json()["job_id"]
        cancelled = self.client.post("/api/code-scan/jobs/%s/cancel" % job_id, headers=_auth(self.token))
        self.assertEqual(cancelled.status_code, 200)
        finished = self._wait_job(job_id)
        self.assertIn(finished.get_json()["status"], {"cancelled", "done"})

    def test_compare_suggested_fix(self):
        resp = self.client.post(
            "/api/code-scan/compare",
            headers=_auth(self.token),
            json={
                "language": "javascript",
                "filename": "app.js",
                "original": "el.innerHTML = userInput;",
                "suggested_fix": "el.textContent = userInput;",
            },
        )
        self.assertEqual(resp.status_code, 200, resp.get_json())
        data = resp.get_json()
        self.assertGreaterEqual(data["original_count"], 1)
        self.assertEqual(data["suggested_count"], 0)
        self.assertIn("does not prove", data["note"])

    def test_compare_requires_auth(self):
        resp = self.client.post("/api/code-scan/compare", json={"original": "x", "suggested_fix": "y"})
        self.assertEqual(resp.status_code, 401)

    def test_single_file_new_languages(self):
        java = self.client.post(
            "/api/code-scan",
            headers=_auth(self.token),
            data={"file": (io.BytesIO(b"Runtime.getRuntime().exec(cmd);\n"), "App.java")},
            content_type="multipart/form-data",
        )
        self.assertEqual(java.status_code, 200, java.get_json())
        self.assertGreaterEqual(java.get_json()["vulnerability_count"], 1)
        ts = self.client.post(
            "/api/code-scan",
            headers=_auth(self.token),
            data={"file": (io.BytesIO(b"el.innerHTML = userInput;\n"), "view.tsx")},
            content_type="multipart/form-data",
        )
        self.assertEqual(ts.status_code, 200)
        self.assertGreaterEqual(ts.get_json()["vulnerability_count"], 1)

    def test_frontend_has_progress_and_dashboard(self):
        html = FRONTEND.read_text(encoding="utf-8")
        self.assertIn("codeScanProgress", html)
        self.assertIn("code-scan/jobs", html)
        self.assertIn("Re-scan suggested fix", html)
        self.assertIn("scan-summary", html)
        self.assertIn("CODE_SCAN_MAX_UPLOAD_BYTES", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)

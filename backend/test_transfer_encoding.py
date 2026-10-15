"""Base64 upload transport: hosting WAF workaround for attack-laden logs and code.

Run alone (JWT isolation): python -m unittest test_transfer_encoding.py
"""
import base64
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

DB_PATH = Path(tempfile.gettempdir()) / "logsentinel_transfer_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()

os.environ["DATABASE_URL"] = "sqlite:///" + DB_PATH.as_posix()
os.environ["JWT_SECRET"] = "transfer-test-secret-32-bytes-xxxx"
os.environ["SECRET_KEY"] = "transfer-test-secret-32-bytes-xxxx"
os.environ["AUTH_RATE_LIMIT"] = "5000/minute"
os.environ["RATE_LIMIT"] = "5000/minute"
os.environ["AI_PROVIDER"] = "local"
os.environ.pop("LOGSENTINEL_ENV", None)
os.environ.pop("RENDER", None)

from app import app  # noqa: E402  (real create_app: budgets + 413 handler)
from config import Config  # noqa: E402
from utils.transfer_encoding import (  # noqa: E402
    TRANSFER_HEADER,
    base64_budget,
)

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "forntend" / "index11.html"
SAMPLE = ROOT / "samples" / "multi_attack_demo.log"

ATTACK_LOG = (
    b"2024-01-15 03:00:03 WARNING web 203.0.113.12 GET /../../etc/passwd HTTP/1.1 404\n"
    b"2024-01-15 03:00:01 WARNING web 203.0.113.10 GET /login?user=admin' OR '1'='1 HTTP/1.1 200\n"
    b"2024-01-15 03:00:02 WARNING web 203.0.113.11 GET /search?q=<script>alert(1)</script> HTTP/1.1 200\n"
    b"2024-01-15 03:12:44 FAILED ssh root@203.0.113.5 - Failed password\n"
    b"2024-01-15 03:12:45 FAILED ssh root@203.0.113.5 - Failed password\n"
)
VULN_PY = b"import os\nos.system(input())\nopen('../../etc/passwd').read()\n"


def _b64_upload(content: bytes, filename: str):
    return {"file": (io.BytesIO(base64.b64encode(content)), filename)}


def _raw_upload(content: bytes, filename: str):
    return {"file": (io.BytesIO(content), filename)}


class TransferEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        resp = cls.client.post("/api/register", json={
            "username": "transfer_user",
            "email": "transfer@example.com",
            "password": "Transfer123",
            "confirm_password": "Transfer123",
        })
        assert resp.status_code == 201, resp.get_json()
        cls.token = resp.get_json()["token"]
        cls.auth = {"Authorization": "Bearer " + cls.token}
        cls.auth_b64 = dict(cls.auth, **{TRANSFER_HEADER: "base64"})

    # ---- /api/analyze -------------------------------------------------
    def test_raw_upload_still_works_without_header(self):
        resp = self.client.post("/api/analyze", headers=self.auth,
                                data=_raw_upload(ATTACK_LOG, "raw.log"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertGreaterEqual(len(resp.get_json()["analysis"]["threats"]), 1)

    def test_base64_upload_decodes_and_matches_raw_detection(self):
        raw = self.client.post("/api/analyze", headers=self.auth,
                               data=_raw_upload(ATTACK_LOG, "a.log"),
                               content_type="multipart/form-data").get_json()
        enc_resp = self.client.post("/api/analyze", headers=self.auth_b64,
                                    data=_b64_upload(ATTACK_LOG, "a.log"),
                                    content_type="multipart/form-data")
        self.assertEqual(enc_resp.status_code, 200, enc_resp.get_json())
        enc = enc_resp.get_json()
        raw_cats = sorted(t["category"] for t in raw["analysis"]["threats"])
        enc_cats = sorted(t["category"] for t in enc["analysis"]["threats"])
        self.assertEqual(raw_cats, enc_cats)
        self.assertEqual(raw["analysis"]["risk_score"], enc["analysis"]["risk_score"])
        self.assertEqual(enc["meta"]["total_lines"], raw["meta"]["total_lines"])

    def test_repo_sample_round_trips_through_base64(self):
        """samples/multi_attack_demo.log is exactly the kind of upload the WAF blocked live."""
        content = SAMPLE.read_bytes()
        raw = self.client.post("/api/analyze", headers=self.auth,
                               data=_raw_upload(content, "multi_attack_demo.log"),
                               content_type="multipart/form-data").get_json()
        resp = self.client.post("/api/analyze", headers=self.auth_b64,
                                data=_b64_upload(content, "multi_attack_demo.log"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        enc = resp.get_json()
        self.assertGreaterEqual(len(enc["analysis"]["threats"]), 1)
        self.assertEqual(
            sorted(t["category"] for t in enc["analysis"]["threats"]),
            sorted(t["category"] for t in raw["analysis"]["threats"]),
        )
        self.assertEqual(enc["analysis"]["risk_score"], raw["analysis"]["risk_score"])

    def test_base64_header_still_requires_jwt(self):
        resp = self.client.post("/api/analyze", headers={TRANSFER_HEADER: "base64"},
                                data=_b64_upload(ATTACK_LOG, "a.log"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 401)

    def test_invalid_base64_is_a_400_not_a_crash(self):
        resp = self.client.post("/api/analyze", headers=self.auth_b64,
                                data=_raw_upload(b"this is not base64!!", "bad.log"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("transfer encoding", resp.get_json()["error"].lower())

    def test_empty_decoded_file_is_rejected(self):
        resp = self.client.post("/api/analyze", headers=self.auth_b64,
                                data=_b64_upload(b"   \n", "empty.log"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("empty", resp.get_json()["error"].lower())

    def test_decoded_size_is_still_capped_at_upload_limit(self):
        too_big = b"x" * (int(Config.MAX_CONTENT_LENGTH) + 10)
        resp = self.client.post("/api/analyze", headers=self.auth_b64,
                                data=_b64_upload(too_big, "big.log"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 413)
        self.assertIn("upload limit", resp.get_json()["error"])

    def test_request_budget_grows_only_for_base64_transfer(self):
        self.assertGreater(base64_budget(10), 13)
        with app.test_request_context("/api/analyze", method="POST",
                                      headers={TRANSFER_HEADER: "base64"}):
            app.preprocess_request()
            from flask import request
            self.assertEqual(request.max_content_length,
                             base64_budget(int(Config.MAX_CONTENT_LENGTH)))
        with app.test_request_context("/api/analyze", method="POST"):
            app.preprocess_request()
            from flask import request
            self.assertEqual(request.max_content_length, int(Config.MAX_CONTENT_LENGTH))

    # ---- /api/upload ----------------------------------------------------
    def test_upload_route_decodes_base64(self):
        resp = self.client.post("/api/upload", headers=self.auth_b64,
                                data=_b64_upload(ATTACK_LOG, "u.log"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 201, resp.get_json())
        self.assertEqual(resp.get_json()["size_bytes"], len(ATTACK_LOG))

    # ---- code scan ------------------------------------------------------
    def test_code_scan_decodes_base64_source(self):
        resp = self.client.post("/api/code-scan", headers=self.auth_b64,
                                data=_b64_upload(VULN_PY, "vuln.py"),
                                content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertGreaterEqual(resp.get_json()["vulnerability_count"], 1)

    def test_compare_accepts_base64_json_and_plain_json(self):
        payload = {
            "filename": "vuln.py", "language": "python",
            "original": "os.system(input())\n",
            "suggested_fix": "subprocess.run(['ls'], check=True)\n",
        }
        plain = self.client.post("/api/code-scan/compare", headers=self.auth, json=payload)
        self.assertEqual(plain.status_code, 200, plain.get_json())
        wrapped = self.client.post(
            "/api/code-scan/compare",
            headers=dict(self.auth_b64, **{"Content-Type": "text/plain;charset=UTF-8"}),
            data=base64.b64encode(json.dumps(payload).encode("utf-8")),
        )
        self.assertEqual(wrapped.status_code, 200, wrapped.get_json())
        self.assertEqual(wrapped.get_json()["original_count"], plain.get_json()["original_count"])

    # ---- frontend wiring -------------------------------------------------
    def test_frontend_sends_header_on_upload_and_compare_calls(self):
        html = FRONTEND.read_text(encoding="utf-8")
        self.assertIn("const LS_TRANSFER_HEADER = 'X-LogSentinel-Transfer'", html)
        self.assertIn("async function lsUploadRequest(", html)
        self.assertIn("lsUploadRequest(uploadSource, uploadName)", html)
        self.assertIn("backendUrl + '/analyze', { method: 'POST', body: upload.body, headers: upload.headers }", html)
        self.assertIn("'/code-scan/jobs', { method: 'POST', body: form, headers: upload.headers }", html)
        self.assertIn("'/code-scan', { method: 'POST', body: form, headers: upload.headers }", html)
        self.assertIn("lsJsonTransferRequest({", html)
        # Same-origin API base is unchanged: the browser uses the page's own host.
        self.assertIn("return location.origin + '/api';", html)
        # File input matches what Flask accepts.
        self.assertIn('accept=".log,.txt,.json"', html)
        self.assertNotIn("Max 50 MB", html)


if __name__ == "__main__":
    unittest.main()

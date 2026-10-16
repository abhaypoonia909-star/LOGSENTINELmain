"""Authenticated Ollama gateway + remote-mode OllamaClient. No real Ollama, no network.

Run alone: python -m unittest test_ollama_gateway.py
"""
import http.client
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

os.environ.setdefault("JWT_SECRET", "gateway-test-secret-32-bytes-xxxxxx")
os.environ.setdefault("SECRET_KEY", "gateway-test-secret-32-bytes-xxxxxx")

from services.ollama_client import (  # noqa: E402
    OllamaClient,
    OllamaConfigError,
    is_loopback_base_url,
)
from tools import ollama_gateway as gw  # noqa: E402

TOKEN = "unit-test-gateway-token-0123456789abcdefghij"
MODEL_LIST = {"models": [{"name": "llama3.2:1b"}]}


class FakeOllama(BaseHTTPRequestHandler):
    """Minimal stand-in for 127.0.0.1:11434."""
    seen: list = []

    def log_message(self, *a):
        return

    def do_GET(self):
        FakeOllama.seen.append(("GET", self.path, dict(self.headers)))
        body = json.dumps(MODEL_LIST).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        FakeOllama.seen.append(("POST", self.path, payload))
        if payload.get("model") == "missing:1b":
            body = b'{"error":"model \'missing:1b\' not found, try pulling it first"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for piece, done in (("Hel", False), ("lo", False), ("", True)):
            line = json.dumps({"message": {"role": "assistant", "content": piece}, "done": done}).encode() + b"\n"
            self.wfile.write(f"{len(line):x}\r\n".encode() + line + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")


def _get(url, token=None, method="GET", data=None, _retries=2):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    for attempt in range(_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read()
            except (ConnectionError, http.client.RemoteDisconnected):
                # Windows loopback race: server closed right after writing a small
                # rejection; the status line was received, body read aborted.
                if attempt == _retries:
                    return exc.code, b""
        except (ConnectionError, http.client.RemoteDisconnected):
            if attempt == _retries:
                raise
    raise AssertionError("unreachable")


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = ThreadingHTTPServer(("127.0.0.1", 0), FakeOllama)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()
        upstream_url = "http://127.0.0.1:%d" % cls.upstream.server_address[1]
        cls.server = gw.make_server(TOKEN, port=0, upstream=upstream_url, quiet=True)
        gw.serve_in_thread(cls.server)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()
        cls.upstream.shutdown(); cls.upstream.server_close()

    def setUp(self):
        FakeOllama.seen.clear()

    def test_missing_token_is_401_and_never_reaches_ollama(self):
        status, _ = _get(self.base + "/api/tags")
        self.assertEqual(status, 401)
        self.assertEqual(FakeOllama.seen, [])

    def test_wrong_token_is_401(self):
        status, _ = _get(self.base + "/api/tags", token="x" * len(TOKEN))
        self.assertEqual(status, 401)
        self.assertEqual(FakeOllama.seen, [])

    def test_tags_passthrough_with_token(self):
        status, body = _get(self.base + "/api/tags", token=TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), MODEL_LIST)
        # The gateway token is not forwarded to Ollama.
        self.assertNotIn("Authorization", FakeOllama.seen[0][2])

    def test_management_endpoints_are_blocked_even_with_token(self):
        for method, path in (("POST", "/api/pull"), ("DELETE", "/api/delete"), ("POST", "/api/create"),
                             ("POST", "/api/generate"), ("GET", "/api/ps"), ("GET", "/"), ("POST", "/api/tags")):
            status, _ = _get(self.base + path, token=TOKEN, method=method,
                             data=b"{}" if method in ("POST", "DELETE") else None)
            self.assertEqual(status, 404, f"{method} {path}")
        self.assertEqual(FakeOllama.seen, [])

    def test_chat_streams_ndjson_lines(self):
        payload = json.dumps({"model": "llama3.2:1b", "messages": [{"role": "user", "content": "hi"}],
                              "stream": True}).encode()
        status, body = _get(self.base + "/api/chat", token=TOKEN, method="POST", data=payload)
        self.assertEqual(status, 200)
        lines = [json.loads(l) for l in body.splitlines() if l.strip()]
        self.assertEqual("".join(l["message"]["content"] for l in lines), "Hello")
        self.assertTrue(lines[-1]["done"])

    def test_upstream_error_status_is_forwarded(self):
        payload = json.dumps({"model": "missing:1b", "messages": []}).encode()
        status, body = _get(self.base + "/api/chat", token=TOKEN, method="POST", data=payload)
        self.assertEqual(status, 404)
        self.assertIn(b"not found", body)

    def test_oversized_body_is_413(self):
        big = b'{"x":"' + b"a" * (gw.MAX_BODY_BYTES + 10) + b'"}'
        status, _ = _get(self.base + "/api/chat", token=TOKEN, method="POST", data=big)
        self.assertEqual(status, 413)
        self.assertEqual(FakeOllama.seen, [])

    def test_unreachable_ollama_is_502_not_a_crash(self):
        server = gw.make_server(TOKEN, port=0, upstream="http://127.0.0.1:1", quiet=True)
        gw.serve_in_thread(server)
        try:
            status, body = _get("http://127.0.0.1:%d/api/tags" % server.server_address[1], token=TOKEN)
        finally:
            server.shutdown(); server.server_close()
        self.assertEqual(status, 502)
        self.assertIn(b"not reachable", body)

    def test_rate_limit(self):
        server = gw.make_server(TOKEN, port=0, upstream=self.upstream and
                                "http://127.0.0.1:%d" % self.upstream.server_address[1],
                                rate_limit_per_minute=2, quiet=True)
        gw.serve_in_thread(server)
        url = "http://127.0.0.1:%d/api/tags" % server.server_address[1]
        try:
            codes = [_get(url, token=TOKEN)[0] for _ in range(3)]
        finally:
            server.shutdown(); server.server_close()
        self.assertEqual(codes, [200, 200, 429])

    def test_refuses_non_loopback_bind_and_short_token(self):
        with self.assertRaises(ValueError):
            gw.make_server(TOKEN, bind="0.0.0.0", port=0)
        with self.assertRaises(ValueError):
            gw.make_server("short", port=0)


class TokenFileTests(unittest.TestCase):
    def test_token_is_created_once_outside_repo_and_reused(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OLLAMA_AUTH_TOKEN", None)
            path = Path(tmp) / "LogSentinel" / "token.txt"
            first, created = gw.load_or_create_token(path)
            second, created_again = gw.load_or_create_token(path)
            self.assertTrue(created); self.assertFalse(created_again)
            self.assertEqual(first, second)
            self.assertGreaterEqual(len(first), gw.MIN_TOKEN_LENGTH)
            repo = Path(__file__).resolve().parents[1]
            self.assertNotIn(str(repo), str(gw.default_token_path()))

    def test_env_token_wins(self):
        with mock.patch.dict(os.environ, {"OLLAMA_AUTH_TOKEN": "env-token-value-long-enough-0123456789"}):
            token, created = gw.load_or_create_token(Path(tempfile.gettempdir()) / "unused.txt")
            self.assertEqual(token, "env-token-value-long-enough-0123456789")
            self.assertFalse(created)


class RemoteClientTests(unittest.TestCase):
    def test_loopback_detection(self):
        self.assertTrue(is_loopback_base_url("http://127.0.0.1:11434"))
        self.assertTrue(is_loopback_base_url("http://localhost:11434/"))
        self.assertFalse(is_loopback_base_url("https://abc.ngrok-free.app"))

    def test_local_client_sends_no_auth_header(self):
        client = OllamaClient("http://127.0.0.1:11434", auth_token="")
        headers = client._headers(json_body=False)
        self.assertNotIn("Authorization", headers)
        self.assertEqual(client._ping_timeout(), 5.0)

    def test_remote_client_sends_bearer_and_longer_ping_timeout(self):
        client = OllamaClient("https://abc.ngrok-free.app", timeout=60, auth_token="tok-123")
        headers = client._headers(json_body=True)
        self.assertEqual(headers["Authorization"], "Bearer tok-123")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(client._ping_timeout(), 15.0)

    def test_remote_client_reads_token_from_env(self):
        with mock.patch.dict(os.environ, {"OLLAMA_AUTH_TOKEN": "from-env"}):
            client = OllamaClient("https://abc.ngrok-free.app")
        self.assertEqual(client._headers(False)["Authorization"], "Bearer from-env")

    def test_remote_without_token_refuses(self):
        client = OllamaClient("https://abc.ngrok-free.app", auth_token="")
        with self.assertRaises(OllamaConfigError):
            client.installed_models()

    def test_remote_plain_http_refuses(self):
        client = OllamaClient("http://abc.ngrok-free.app", auth_token="tok")
        with self.assertRaises(OllamaConfigError) as ctx:
            client.installed_models()
        self.assertIn("https", str(ctx.exception))

    def test_gateway_401_becomes_clear_config_error(self):
        server = gw.make_server(TOKEN, port=0, upstream="http://127.0.0.1:1", quiet=True)
        gw.serve_in_thread(server)
        try:
            client = OllamaClient("http://127.0.0.1:%d" % server.server_address[1], auth_token="")
            # Loopback client -> no header sent -> gateway answers 401 -> mapped to OllamaConfigError.
            with self.assertRaises(OllamaConfigError) as ctx:
                client.installed_models()
        finally:
            server.shutdown(); server.server_close()
        self.assertIn("OLLAMA_AUTH_TOKEN", str(ctx.exception))

    def test_status_reports_remote_misconfiguration_without_local_setup_text(self):
        from services.ai_service import AIService
        with mock.patch.dict(os.environ, {"OLLAMA_BASE_URL": "https://abc.ngrok-free.app",
                                          "OLLAMA_AUTH_TOKEN": ""}):
            os.environ.pop("OLLAMA_AUTH_TOKEN", None)
            status = AIService().status()
        self.assertFalse(status["ready"])
        self.assertIn("OLLAMA_AUTH_TOKEN", status["message"])

    def test_find_ngrok_reuses_existing_binary_before_downloading(self):
        from tools import connect_ollama as co
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            exe = home / "Downloads" / "ngrok-v3-stable-windows-amd64" / ("ngrok.exe" if os.name == "nt" else "ngrok")
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"stub")
            with mock.patch.dict(os.environ, {"NGROK_EXE": ""}), \
                 mock.patch("shutil.which", return_value=None), \
                 mock.patch.object(Path, "home", return_value=home), \
                 mock.patch.object(co, "ngrok_dir", return_value=home / "nowhere"):
                self.assertEqual(co.find_ngrok(), str(exe))
            with mock.patch.dict(os.environ, {"NGROK_EXE": str(exe)}), \
                 mock.patch("shutil.which", return_value=None):
                self.assertEqual(co.find_ngrok(), str(exe))

    def test_connect_script_and_launcher_exist_and_never_target_11434_publicly(self):
        tools = Path(__file__).resolve().parent / "tools"
        script = (tools / "connect_ollama.py").read_text(encoding="utf-8")
        launcher = (tools / "connect_ollama.cmd").read_text(encoding="utf-8")
        wrapper = (tools.parent / "connect_ollama.cmd").read_text(encoding="utf-8")
        self.assertIn("tools\\connect_ollama.py", launcher)
        self.assertIn("tools\\connect_ollama.cmd", wrapper)
        self.assertIn('f"127.0.0.1:{args.port}"', script)   # ngrok targets the gateway port
        self.assertNotIn("11434\"", script.split("def main")[1])  # never the raw Ollama port
        self.assertIn("expected 401", script)                  # public no-token check is enforced


if __name__ == "__main__":
    unittest.main()

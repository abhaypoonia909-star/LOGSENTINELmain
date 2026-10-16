"""Authenticated loopback gateway in front of the laptop's Ollama.

Ollama (127.0.0.1:11434) has no authentication and exposes model-management
endpoints, so it must never be reachable from the internet. This gateway is
what the tunnel points at instead:

    tunnel ──▶ 127.0.0.1:11435 (this file) ──▶ 127.0.0.1:11434 (Ollama)

Rules enforced here, in order:
1. ``Authorization: Bearer <token>`` must match (constant-time compare) → else 401.
2. Only ``GET /api/tags`` and ``POST /api/chat`` are forwarded → everything else 404
   (no /api/pull, /api/delete, /api/create, /api/generate, /api/push ...).
3. Request bodies are capped (default 1 MB) and a simple requests-per-minute
   limit applies.
4. Responses stream back line by line (Ollama's NDJSON), so chat streaming works.

Standard library only. Logs method, path and status - never bodies or tokens.
Usage (normally started by tools/connect_ollama.py):
    python tools/ollama_gateway.py            # token from OLLAMA_AUTH_TOKEN or the token file
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_UPSTREAM = "http://127.0.0.1:11434"
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 11435
ALLOWED_ROUTES = frozenset({("GET", "/api/tags"), ("POST", "/api/chat")})
MAX_BODY_BYTES = 1_000_000
RATE_LIMIT_PER_MINUTE = 120
UPSTREAM_TIMEOUT = 300.0
MIN_TOKEN_LENGTH = 32


def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home())
    return Path(base) / "LogSentinel"


def default_token_path() -> Path:
    return app_data_dir() / "ollama_gateway_token.txt"


def load_or_create_token(path: Path | None = None) -> tuple[str, bool]:
    """Return (token, created). Stored outside the repository, never printed here."""
    env_token = (os.environ.get("OLLAMA_AUTH_TOKEN") or "").strip()
    if env_token:
        return env_token, False
    path = path or default_token_path()
    if path.is_file():
        existing = path.read_text(encoding="utf-8").strip()
        if len(existing) >= MIN_TOKEN_LENGTH:
            return existing, False
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(48)
    path.write_text(token + "\n", encoding="utf-8")
    return token, True


class _RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = max(1, int(per_minute))
        self._lock = threading.Lock()
        self._window_start = time.monotonic()
        self._count = 0

    def allow(self) -> bool:
        with self._lock:
            now = time.monotonic()
            if now - self._window_start >= 60.0:
                self._window_start = now
                self._count = 0
            if self._count >= self.per_minute:
                return False
            self._count += 1
            return True


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = "LogSentinelOllamaGateway/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # Set per server instance by make_server().
    token: str = ""
    upstream: str = DEFAULT_UPSTREAM
    limiter: _RateLimiter | None = None
    quiet: bool = False

    # ---- plumbing -----------------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: N802 - BaseHTTPRequestHandler API
        return  # we log explicitly in _done (no bodies, no headers)

    def _done(self, status: int) -> None:
        if not self.quiet:
            path = self.path.split("?", 1)[0]
            print(f"[gateway] {self.command} {path} -> {status}", flush=True)

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
        self._done(status)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization") or ""
        scheme, _, value = header.partition(" ")
        if scheme.lower() != "bearer" or not self.token:
            return False
        return hmac.compare_digest(value.strip(), self.token)

    # ---- verbs ------------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        self._handle("GET")

    def do_POST(self):  # noqa: N802
        self._handle("POST")

    def do_HEAD(self):  # noqa: N802
        self._send_json(404, {"error": "not found"})

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD

    # ---- core -------------------------------------------------------------------
    def _handle(self, method: str) -> None:
        path = self.path.split("?", 1)[0]
        # Consume (bounded) the request body first so every rejection below can be
        # read by the client instead of aborting the socket mid-response.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._drain(length)
            self._send_json(413, {"error": "request body too large"})
            return
        body = self.rfile.read(length) if length else None

        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return
        if (method, path) not in ALLOWED_ROUTES:
            self._send_json(404, {"error": "not found"})
            return
        if self.limiter is not None and not self.limiter.allow():
            self._send_json(429, {"error": "too many requests"})
            return

        upstream_headers = {"Accept": "application/json"}
        if body is not None:
            upstream_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.upstream.rstrip("/") + path, data=body, headers=upstream_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=UPSTREAM_TIMEOUT) as response:
                self._stream_response(response.status, response.headers.get("Content-Type"), response)
        except urllib.error.HTTPError as exc:
            payload = exc.read(MAX_BODY_BYTES)
            self._send_raw(exc.code, exc.headers.get("Content-Type") or "application/json", payload)
        except urllib.error.URLError:
            self._send_json(502, {"error": "Ollama is not reachable on the laptop (127.0.0.1:11434)."})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
        except Exception:  # noqa: BLE001 - never leak internals to the tunnel
            self._send_json(502, {"error": "gateway error"})

    def _drain(self, length: int, cap: int = 8 * MAX_BODY_BYTES) -> None:
        """Discard an oversized body (bounded) so the client can read our reply."""
        remaining = min(max(length, 0), cap)
        try:
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

    def _send_raw(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True
        self._done(status)

    def _stream_response(self, status: int, content_type: str | None, response) -> None:
        """Forward Ollama's NDJSON line by line using chunked transfer encoding."""
        self.send_response(status)
        self.send_header("Content-Type", content_type or "application/x-ndjson")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        for line in response:
            if not line:
                continue
            self.wfile.write(f"{len(line):x}\r\n".encode("ascii") + line + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        self.close_connection = True
        self._done(status)


def make_server(
    token: str,
    *,
    bind: str = DEFAULT_BIND,
    port: int = DEFAULT_PORT,
    upstream: str = DEFAULT_UPSTREAM,
    rate_limit_per_minute: int = RATE_LIMIT_PER_MINUTE,
    quiet: bool = False,
) -> ThreadingHTTPServer:
    if bind not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("The gateway must bind to a loopback address; the tunnel agent connects locally.")
    if len(token or "") < MIN_TOKEN_LENGTH:
        raise ValueError("Gateway token is too short.")

    class Handler(GatewayHandler):
        pass

    Handler.token = token
    Handler.upstream = upstream
    Handler.limiter = _RateLimiter(rate_limit_per_minute)
    Handler.quiet = quiet
    server = ThreadingHTTPServer((bind, port), Handler)
    server.daemon_threads = True
    return server


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, name="ollama-gateway", daemon=True)
    thread.start()
    return thread


def main(argv: list[str] | None = None) -> int:
    port = int(os.environ.get("OLLAMA_GATEWAY_PORT") or DEFAULT_PORT)
    token, created = load_or_create_token()
    server = make_server(token, port=port)
    print(f"[gateway] listening on http://127.0.0.1:{port} -> {DEFAULT_UPSTREAM} "
          f"(token {'created' if created else 'loaded'} from {default_token_path()})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

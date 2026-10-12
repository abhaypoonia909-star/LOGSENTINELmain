"""LogSentinel authentication test suite (temporary — safe to delete)."""
import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from check_runner import CheckRunner, refers_to_brute_force_activity

DB_PATH = Path(tempfile.gettempdir()) / "logsentinel_auth_test.db"
if DB_PATH.exists():
    DB_PATH.unlink()
os.environ["DATABASE_URL"] = "sqlite:///" + DB_PATH.as_posix()
os.environ.setdefault("AUTH_RATE_LIMIT", "5000/minute")
os.environ.setdefault("RATE_LIMIT", "5000/minute")
os.environ.setdefault("JWT_SECRET", "test-secret-for-suite")
os.environ.setdefault("ADMIN_EMAILS", "root@logsentinel.io")

import jwt as pyjwt
from app import app

runner = CheckRunner()


def check(name, cond, detail=""):
    return runner.check(name, cond, detail)


c = app.test_client()
SAMPLE = b"""2024-01-15 04:22:11 FAILED ssh user@192.168.1.200 - Failed password attempt
2024-01-15 04:22:13 FAILED ssh user@192.168.1.200 - Failed password attempt
2024-01-15 04:22:15 FAILED ssh user@192.168.1.200 - Failed password attempt
2024-01-15 04:22:17 FAILED ssh user@192.168.1.200 - Failed password attempt
2024-01-15 04:22:19 FAILED ssh user@192.168.1.200 - Failed password attempt
2024-01-15 05:45:22 CRITICAL security: privilege escalation detected uid 1000->0
2024-01-15 02:17:46 INFO apache: 10.0.0.99 - - [15/Jan/2024:02:17:46] "GET /login.php?id=1' OR 1=1-- HTTP/1.1" 500 512
"""


def hdr(tok):
    return {"Authorization": "Bearer " + tok}


print("\n=== REGISTRATION ===")
r = c.post("/api/register", json={"username": "analyst", "email": "analyst@example.com",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123"})
check("new user registration -> 201", r.status_code == 201, r.get_json())
body = r.get_json()
USER_TOKEN = body["token"]
check("register returns token + user, never a password hash",
      "token" in body and "password_hash" not in json.dumps(body), body)
check("register assigns 'user' role by default", body["user"]["role"] == "user", body)

r = c.post("/api/register", json={"username": "other", "email": "analyst@example.com",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123"})
check("duplicate email -> 409", r.status_code == 409, r.get_json())

r = c.post("/api/register", json={"username": "analyst", "email": "other@example.com",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123"})
check("duplicate username -> 409", r.status_code == 409, r.get_json())

r = c.post("/api/register", json={"username": "bob", "email": "not-an-email",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123"})
check("invalid email -> 400", r.status_code == 400, r.get_json())

r = c.post("/api/register", json={"username": "bob", "email": "bob@example.com",
                                  "password": "abc", "confirm_password": "abc"})
check("weak password (too short) -> 400", r.status_code == 400, r.get_json())

r = c.post("/api/register", json={"username": "bob", "email": "bob@example.com",
                                  "password": "abcdefghij", "confirm_password": "abcdefghij"})
check("weak password (no digit) -> 400", r.status_code == 400, r.get_json())

r = c.post("/api/register", json={"username": "bob", "email": "bob@example.com",
                                  "password": "Sentinel123", "confirm_password": "Sentinel999"})
check("password confirmation mismatch -> 400", r.status_code == 400, r.get_json())

r = c.post("/api/register", json={"username": "x", "email": "bob@example.com",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123"})
check("invalid username -> 400", r.status_code == 400, r.get_json())

r = c.post("/api/register", json={"username": "sneaky", "email": "sneaky@example.com",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123",
                                  "role": "admin"})
check("client-supplied role='admin' is ignored", r.get_json()["user"]["role"] == "user", r.get_json())

r = c.post("/api/register", json={"username": "root", "email": "root@logsentinel.io",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123"})
check("ADMIN_EMAILS grants admin role", r.get_json()["user"]["role"] == "admin", r.get_json())
ADMIN_TOKEN = r.get_json()["token"]

# password is hashed, not stored in plaintext
with app.app_context():
    from models.models import User
    u = User.query.filter_by(email="analyst@example.com").first()
    check("password stored as bcrypt hash, not plaintext",
          u.password_hash.startswith("$2") and "Sentinel123" not in u.password_hash)

print("\n=== LOGIN ===")
r = c.post("/api/login", json={"email": "analyst@example.com", "password": "Sentinel123"})
check("correct credentials (email) -> 200", r.status_code == 200, r.get_json())
USER_TOKEN = r.get_json()["token"]

r = c.post("/api/login", json={"username": "analyst", "password": "Sentinel123"})
check("correct credentials (username) -> 200", r.status_code == 200, r.get_json())

r = c.post("/api/login", json={"email": "analyst@example.com", "password": "WrongPass1"})
check("wrong password -> 401", r.status_code == 401, r.get_json())

r2 = c.post("/api/login", json={"email": "ghost@example.com", "password": "WrongPass1"})
check("non-existent user -> 401", r2.status_code == 401, r2.get_json())
check("no user enumeration (identical error for both)",
      r.get_json()["error"] == r2.get_json()["error"])

r = c.post("/api/login", json={})
check("empty credentials -> 400", r.status_code == 400, r.get_json())

print("\n=== AUTHENTICATION (JWT) ===")
r = c.get("/api/me", headers=hdr(USER_TOKEN))
check("valid JWT on /api/me -> 200", r.status_code == 200, r.get_json())

r = c.get("/api/me", headers=hdr("not.a.real.token"))
check("invalid JWT -> 401", r.status_code == 401, r.get_json())

expired = pyjwt.encode(
    {"sub": 1, "email": "analyst@example.com", "role": "user", "exp": int(time.time()) - 60},
    os.environ["JWT_SECRET"], algorithm="HS256")
r = c.get("/api/me", headers=hdr(expired))
check("expired JWT -> 401 'Token expired.'",
      r.status_code == 401 and "expired" in r.get_json()["error"].lower(), r.get_json())

forged = pyjwt.encode({"sub": 1, "email": "a@b.co", "role": "admin",
                       "exp": int(time.time()) + 999}, "wrong-secret", algorithm="HS256")
r = c.get("/api/me", headers=hdr(forged))
check("JWT signed with wrong secret -> 401", r.status_code == 401, r.get_json())

r = c.get("/api/me")
check("missing JWT -> 401", r.status_code == 401, r.get_json())

for path in ["/api/dashboard", "/api/report/1", "/api/charts/1", "/api/code-report/1"]:
    r = c.get(path)
    check("protected GET %s without auth -> 401" % path, r.status_code == 401, r.status_code)
for path in ["/api/upload", "/api/analyze", "/api/ai", "/api/code-scan",
             "/api/threat-intel/report", "/api/threat-intel/export/json"]:
    r = c.post(path)
    check("protected POST %s without auth -> 401" % path, r.status_code == 401, r.status_code)

print("\n=== PUBLIC ENDPOINTS STAY PUBLIC ===")
check("GET /api/health public", c.get("/api/health").status_code == 200)
check("GET /api index public", c.get("/api").status_code == 200)
check("POST /api/register public", c.post("/api/register", json={}).status_code == 400)
check("POST /api/login public", c.post("/api/login", json={}).status_code == 400)

print("\n=== AUTHORIZATION ===")
r = c.get("/api/admin/users", headers=hdr(USER_TOKEN))
check("normal user on admin endpoint -> 403", r.status_code == 403, r.get_json())

r = c.get("/api/admin/users", headers=hdr(ADMIN_TOKEN))
check("admin user on admin endpoint -> 200", r.status_code == 200, r.get_json())
check("admin listing never leaks password hashes",
      "password_hash" not in json.dumps(r.get_json()))

r = c.get("/api/admin/users")
check("admin endpoint without token -> 401", r.status_code == 401, r.status_code)

print("\n=== EXISTING FUNCTIONALITY (authenticated) ===")
r = c.post("/api/analyze", headers=hdr(USER_TOKEN),
           data={"file": (io.BytesIO(SAMPLE), "sample_threats.log")},
           content_type="multipart/form-data")
check("log upload + analysis -> 200", r.status_code == 200, r.get_json())
data = r.get_json() if r.status_code == 200 else {}
ANALYSIS_ID = data.get("analysis_id")
check("threat detection produced threats",
      len(data.get("analysis", {}).get("threats", [])) > 0,
      data.get("analysis", {}).get("threats"))
check("risk score present", isinstance(data.get("analysis", {}).get("risk_score"), int),
      data.get("analysis", {}).get("risk_score"))
check("charts present", "charts" in data and bool(data["charts"]), list(data.keys()))
check("report preview present", bool(data.get("report")), type(data.get("report")))
check("AI analysis present", "ai_analysis" in data.get("analysis", {}), list(data.get("analysis", {}).keys()))
check("threat intelligence present", "threat_intelligence" in data, list(data.keys()))

r = c.get("/api/dashboard", headers=hdr(USER_TOKEN))
d = r.get_json()
check("dashboard with auth -> 200", r.status_code == 200, d)
check("dashboard scoped to this user's data", d.get("total_logs", 0) >= 1 and
      any(e["analysis_id"] == ANALYSIS_ID for e in d.get("timeline_events", [])), d)

r = c.get("/api/report/%s" % ANALYSIS_ID, headers=hdr(USER_TOKEN))
check("owner can read own report -> 200", r.status_code == 200, r.get_json())

r = c.get("/api/charts/%s" % ANALYSIS_ID, headers=hdr(USER_TOKEN))
check("owner can read own charts -> 200", r.status_code == 200, r.get_json())

import routes.ai as ai_routes

class _AIMsg:
    content = "Brute-force attacks repeatedly guess credentials to gain access."

class _AIChoice:
    message = _AIMsg()

class _AIResp:
    choices = [_AIChoice()]

class _AIClient:
    class chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                return _AIResp()

ai_routes.ai._client = _AIClient()
r = c.post("/api/ai", headers=hdr(USER_TOKEN), json={"question": "what is a brute force attack"})
check("AI endpoint with auth -> 200", r.status_code == 200, r.get_json())
ai_body = r.get_json() if r.status_code == 200 else {}
check(
    "AI endpoint answer refers to brute-force activity",
    refers_to_brute_force_activity(ai_body.get("answer", "")),
    ai_body,
)

r = c.post("/api/upload", headers=hdr(USER_TOKEN),
           data={"file": (io.BytesIO(SAMPLE), "sample_threats.log")},
           content_type="multipart/form-data")
check("upload endpoint with auth -> 201", r.status_code == 201, r.get_json())

r = c.post("/api/code-scan", headers=hdr(USER_TOKEN),
           data={"file": (io.BytesIO(b"import os\nos.system(input())\n"), "bad.py")},
           content_type="multipart/form-data")
check("code scan with auth -> 200", r.status_code == 200, r.get_json())
CODE_ID = r.get_json().get("analysis_id")
r = c.get("/api/code-report/%s" % CODE_ID, headers=hdr(USER_TOKEN))
check("owner can read own code report -> 200", r.status_code == 200, r.status_code)

r = c.post("/api/threat-intel/report", headers=hdr(USER_TOKEN), json={"events": []})
check("threat-intel report with auth -> 200", r.status_code == 200, r.status_code)

print("\n=== CROSS-USER ISOLATION ===")
r = c.post("/api/register", json={"username": "mallory", "email": "mallory@example.com",
                                  "password": "Sentinel123", "confirm_password": "Sentinel123"})
OTHER_TOKEN = r.get_json()["token"]

r = c.get("/api/report/%s" % ANALYSIS_ID, headers=hdr(OTHER_TOKEN))
check("other user reading someone else's report -> 403", r.status_code == 403, r.get_json())
r = c.get("/api/charts/%s" % ANALYSIS_ID, headers=hdr(OTHER_TOKEN))
check("other user reading someone else's charts -> 403", r.status_code == 403, r.get_json())
r = c.get("/api/code-report/%s" % CODE_ID, headers=hdr(OTHER_TOKEN))
check("other user reading someone else's code report -> 403", r.status_code == 403, r.status_code)
r = c.get("/api/dashboard", headers=hdr(OTHER_TOKEN))
check("new user's dashboard is empty (no data leak)",
      r.get_json().get("total_logs") == 0 and r.get_json().get("timeline_events") == [],
      r.get_json())

r = c.get("/api/report/%s" % ANALYSIS_ID, headers=hdr(ADMIN_TOKEN))
check("admin can read any report -> 200", r.status_code == 200, r.status_code)

r = c.get("/api/report/999999", headers=hdr(USER_TOKEN))
check("missing analysis -> 404 (not 403 leak)", r.status_code == 404, r.status_code)

print("\n=== LOGOUT ===")
r = c.post("/api/logout", headers=hdr(USER_TOKEN))
check("logout with valid token -> 200", r.status_code == 200, r.get_json())
r = c.post("/api/logout")
check("logout without token -> 401", r.status_code == 401, r.status_code)
# after the client clears the token, protected calls carry no credentials
r = c.get("/api/dashboard")
check("protected endpoint after client clears token -> 401", r.status_code == 401, r.status_code)

print("\n=== CORS + RATE LIMITING PRESERVED ===")
r = c.get("/api/health", headers={"Origin": "https://logsentinel.vercel.app"})
check("CORS still allows cross-origin",
      r.headers.get("Access-Control-Allow-Origin") in ("*", "https://logsentinel.vercel.app"),
      dict(r.headers))
r = c.options("/api/analyze", headers={"Origin": "https://logsentinel.vercel.app",
                                       "Access-Control-Request-Method": "POST",
                                       "Access-Control-Request-Headers": "Authorization"})
check("CORS preflight allows Authorization header",
      r.status_code in (200, 204) and "authorization" in
      (r.headers.get("Access-Control-Allow-Headers") or "").lower(), dict(r.headers))
check("rate limiter still installed", hasattr(app, "extensions") and "limiter" in app.extensions)

raise SystemExit(runner.summarize())

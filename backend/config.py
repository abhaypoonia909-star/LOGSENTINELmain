import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

BASE_DIR = Path(__file__).resolve().parent
if load_dotenv is not None:
    # Later files fill in missing values. A real key in either file is used;
    # an empty OPENAI_API_KEY= line is ignored.
    load_dotenv(BASE_DIR.parent / ".env")
    load_dotenv(BASE_DIR / ".env", override=True)
    for _name in (
        "OPENAI_API_KEY",
        "OPENAI_MODEL",
        "OLLAMA_BASE_URL",
        "OLLAMA_MODEL",
        "DATABASE_URL",
        "JWT_SECRET",
    ):
        if os.environ.get(_name, "").strip() == "":
            os.environ.pop(_name, None)


def resolve_database_uri(raw: str | None = None) -> str:
    """SQLAlchemy URI. Empty/unset DATABASE_URL keeps local SQLite.

    Render/Heroku still emit postgres:// which SQLAlchemy 1.4+ rejects.
    That scheme is rewritten to postgresql://. sqlite:// is left unchanged.
    """
    value = (os.environ.get("DATABASE_URL") if raw is None else raw) or ""
    value = value.strip()
    if not value:
        return f"sqlite:///{BASE_DIR / 'logsentinel.db'}"
    if value.startswith("postgres://"):
        value = "postgresql://" + value[len("postgres://"):]
    return value


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "change-me-in-production"
    JWT_SECRET = os.environ.get("JWT_SECRET") or SECRET_KEY
    JWT_EXPIRY_HOURS = int(os.environ.get("JWT_EXPIRY_HOURS") or 24)

    SQLALCHEMY_DATABASE_URI = resolve_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_DIR = BASE_DIR / "uploads"
    REPORT_DIR = BASE_DIR / "reports"
    # Log-analyzer and generic uploads. Code scanning uses CODE_SCAN_* instead.
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_UPLOAD_MB", 10)) * 1024 * 1024
    RATE_LIMIT = os.environ.get("RATE_LIMIT", "60/minute")
    # Defaults sized for a Windows laptop with ~8 GB RAM. Raise via env vars.
    CODE_SCAN_MAX_UPLOAD_BYTES = int(
        os.environ.get("CODE_SCAN_MAX_UPLOAD_BYTES") or (50 * 1024 * 1024)
    )
    CODE_SCAN_MAX_FILE_BYTES = int(os.environ.get("CODE_SCAN_MAX_FILE_BYTES") or (1024 * 1024))
    CODE_SCAN_MAX_ZIP_FILES = int(os.environ.get("CODE_SCAN_MAX_ZIP_FILES") or 1500)
    CODE_SCAN_MAX_ZIP_EXTRACT_BYTES = int(
        os.environ.get("CODE_SCAN_MAX_ZIP_EXTRACT_BYTES") or (80 * 1024 * 1024)
    )
    CODE_SCAN_MAX_DURATION_SECONDS = int(os.environ.get("CODE_SCAN_MAX_DURATION_SECONDS") or 90)
    CODE_SCAN_MAX_CONCURRENT = int(os.environ.get("CODE_SCAN_MAX_CONCURRENT") or 1)
    CODE_SCAN_MAX_COMPRESSION_RATIO = int(os.environ.get("CODE_SCAN_MAX_COMPRESSION_RATIO") or 100)
    CODE_SCAN_JOB_TTL_SECONDS = int(os.environ.get("CODE_SCAN_JOB_TTL_SECONDS") or 1800)

    ALLOWED_LOG_EXT = {".log", ".txt", ".json"}
    # Uploaded-log analyzer (LogAnalyzer). Default 2 matches the historical
    # hardcoded detector. This is not the Live Alerts threshold.
    BRUTE_FORCE_THRESHOLD = int(os.environ.get("BRUTE_FORCE_THRESHOLD") or 2)

    # Live security alerts (demo-login + dashboard). Isolated from log-file analysis.
    ALERT_FAILED_LOGIN_THRESHOLD = int(os.environ.get("ALERT_FAILED_LOGIN_THRESHOLD") or 5)
    ALERT_FAILED_LOGIN_WINDOW_SECONDS = int(
        os.environ.get("ALERT_FAILED_LOGIN_WINDOW_SECONDS") or 300
    )
    ALERT_DEMO_MITIGATION = (os.environ.get("ALERT_DEMO_MITIGATION") or "1").strip().lower() not in (
        "0", "false", "no", "off"
    )
    ALERT_DEMO_BLOCK_SECONDS = int(os.environ.get("ALERT_DEMO_BLOCK_SECONDS") or 120)
    ALERT_POLL_SECONDS = int(os.environ.get("ALERT_POLL_SECONDS") or 5)
    DEMO_LOGIN_RATE_LIMIT = os.environ.get("DEMO_LOGIN_RATE_LIMIT", "30/minute")
    DEMO_LOGIN_USERNAME = (os.environ.get("DEMO_LOGIN_USERNAME") or "demo").strip() or "demo"
    DEMO_LOGIN_PASSWORD = os.environ.get("DEMO_LOGIN_PASSWORD") or "Demo1234"
    INCIDENT_CORRELATION_WINDOW_SECONDS = int(
        os.environ.get("INCIDENT_CORRELATION_WINDOW_SECONDS") or 900
    )

    # --- Authentication settings (added) ---------------------------------
    PASSWORD_MIN_LENGTH = int(os.environ.get("PASSWORD_MIN_LENGTH", 8))
    AUTH_RATE_LIMIT = os.environ.get("AUTH_RATE_LIMIT", "10/minute")
    # Model names only. Keys and URLs are read from the environment in AIService.
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
    AI_PROVIDER = (os.environ.get("AI_PROVIDER") or "ollama").strip().lower() or "ollama"
    OLLAMA_BASE_URL = (os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").strip()
    OLLAMA_MODEL = (os.environ.get("OLLAMA_MODEL") or "llama3.2:1b").strip() or "llama3.2:1b"
    # Chat timeout/options are applied at call time by utils.ollama_settings
    # (defaults: 60s, num_ctx 1024, num_predict 80, keep_alive 60m).
    OLLAMA_TIMEOUT_SECONDS = int(os.environ.get("OLLAMA_TIMEOUT_SECONDS") or 60)
    # Comma-separated list of emails that receive the "admin" role at signup.
    ADMIN_EMAILS = {
        e.strip().lower()
        for e in os.environ.get("ADMIN_EMAILS", "").split(",")
        if e.strip()
    }


# Loud startup warning instead of silently shipping the placeholder secret.
if not os.environ.get("SECRET_KEY") and not os.environ.get("JWT_SECRET"):
    print(
        "[LogSentinel][WARNING] SECRET_KEY / JWT_SECRET is not set - falling back to "
        "the development placeholder. Set SECRET_KEY in your Railway variables "
        "before serving real users, or every issued JWT is forgeable.",
        flush=True,
    )

_ai_provider = (os.environ.get("AI_PROVIDER") or "ollama").strip().lower() or "ollama"
if _ai_provider == "openai" and not os.environ.get("OPENAI_API_KEY", "").strip():
    print(
        "[LogSentinel][WARNING] AI_PROVIDER=openai but OPENAI_API_KEY is not set. "
        "POST /api/ai will return a configuration error until a key is set, "
        "or set AI_PROVIDER=ollama to use local inference.",
        flush=True,
    )
elif _ai_provider != "openai":
    print(
        "[LogSentinel] SentinelAI defaults to local Ollama. Install Ollama, run "
        "'ollama pull %s', and keep Ollama listening on %s. Chat does not call "
        "a cloud provider."
        % (
            (os.environ.get("OLLAMA_MODEL") or "llama3.2:1b").strip() or "llama3.2:1b",
            (os.environ.get("OLLAMA_BASE_URL") or "http://127.0.0.1:11434").strip()
            or "http://127.0.0.1:11434",
        ),
        flush=True,
    )
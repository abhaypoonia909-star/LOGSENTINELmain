import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "forntend"
from models import db
from models.models import User, UploadedFile, Analysis, Threat, Report, ensure_user_schema
from routes.auth import auth_bp
from routes.upload import upload_bp
from routes.analysis import analysis_bp
from routes.dashboard import dashboard_bp
from routes.reports import reports_bp
from routes.charts import charts_bp
from routes.ai import ai_bp
from routes.code_analysis import code_analysis_bp
from routes.alerts import alerts_bp
from routes.demo_auth import demo_auth_bp
from routes.incidents import incidents_bp
from services.security_alerts import SecurityAlertService
from threat_intelligence.routes import threat_intel_bp
from utils.runtime_secrets import assert_secure_secrets
from utils.transfer_encoding import base64_budget, transfer_is_base64


limiter = Limiter(key_func=get_remote_address)

def create_app():
    assert_secure_secrets()
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)
    limiter.init_app(app)
    limiter.default_limits = [Config.RATE_LIMIT]

    db.init_app(app)
    Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with app.app_context():
        db.create_all()
        ensure_user_schema()
        try:
            SecurityAlertService().seed_demo_account()
        except Exception as exc:
            print("demo account seed error:", exc, flush=True)

    app.register_blueprint(auth_bp, url_prefix="/api")
    # Tighter rate limit on the credential endpoints (brute-force defence).
    limiter.limit(Config.AUTH_RATE_LIMIT)(auth_bp)
    app.register_blueprint(demo_auth_bp, url_prefix="/api")
    limiter.limit(Config.DEMO_LOGIN_RATE_LIMIT)(demo_auth_bp)
    app.register_blueprint(alerts_bp, url_prefix="/api")
    app.register_blueprint(incidents_bp, url_prefix="/api")
    app.register_blueprint(upload_bp, url_prefix="/api")
    app.register_blueprint(analysis_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp, url_prefix="/api")
    app.register_blueprint(reports_bp, url_prefix="/api")
    app.register_blueprint(charts_bp, url_prefix="/api")
    app.register_blueprint(ai_bp, url_prefix="/api")
    app.register_blueprint(code_analysis_bp, url_prefix="/api")
    app.register_blueprint(threat_intel_bp)

    @app.before_request
    def _code_scan_upload_budget():
        """Code-scan routes use CODE_SCAN_MAX_UPLOAD_BYTES; log uploads stay at MAX_CONTENT_LENGTH.

        Base64-transported uploads (X-LogSentinel-Transfer: base64) are ~33%
        larger on the wire, so the request budget grows accordingly. The routes
        still enforce the original limit on the decoded bytes.
        """
        path = request.path or ""
        encoded = transfer_is_base64()
        if path.startswith("/api/code-scan"):
            limit = int(Config.CODE_SCAN_MAX_UPLOAD_BYTES)
            request.max_content_length = base64_budget(limit) if encoded else limit
        elif encoded and path in ("/api/analyze", "/api/upload"):
            request.max_content_length = base64_budget(int(Config.MAX_CONTENT_LENGTH))

    @app.get("/")
    def frontend_index():
        return send_from_directory(FRONTEND_DIR, "index11.html")

    @app.get("/demo-login")
    def demo_login_page():
        return send_from_directory(FRONTEND_DIR, "demo-login.html")

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "LogSentinel"})

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error):
        limit = app.config.get("MAX_CONTENT_LENGTH") or (10 * 1024 * 1024)
        limit_mb = max(1, int(limit) // (1024 * 1024))
        return jsonify({"error": f"File exceeds the {limit_mb} MB upload limit."}), 413

    @app.get("/api")
    def api_index():
        return jsonify({
            "service": "LogSentinel API",
            "base_url": "/api",
            "endpoints": [
                "POST /api/register",
                "POST /api/login",
                "GET  /api/me",
                "POST /api/logout",
                "POST /api/upload",
                "POST /api/analyze",
                "GET  /api/dashboard",
                "GET  /api/alerts",
                "GET  /api/analysis/<analysis_id>/incidents",
                "GET  /api/analysis/<analysis_id>/incidents/<incident_id>",
                "GET  /api/security-incidents",
                "GET  /api/demo/status",
                "POST /api/demo/login",
                "POST /api/demo/unblock",
                "GET  /api/report/<analysis_id>",
                "GET  /api/report/<analysis_id>/pdf",
                "GET  /api/charts/<analysis_id>",
                "POST /api/ai",
                "POST /api/ai/stream",
                "GET  /api/ai/status",
                "POST /api/code-scan",
                "GET  /api/code-scan/limits",
                "POST /api/code-scan/jobs",
                "GET  /api/code-scan/jobs/<job_id>",
                "POST /api/code-scan/jobs/<job_id>/cancel",
                "POST /api/code-scan/compare",
                "GET  /api/code-report/<analysis_id>",
                "GET  /api/health",
            ],
        })

    return app

app = create_app()

if __name__ == "__main__":
    debug = (os.environ.get("FLASK_DEBUG") or "").strip().lower() in {"1", "true", "yes"}
    host = (os.environ.get("FLASK_RUN_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.environ.get("PORT") or 5000)
    # Dev convenience only (python app.py): start the laptop's installed Ollama
    # on 127.0.0.1:11434 if it is not running. Skipped in production/gunicorn,
    # for non-loopback OLLAMA_BASE_URL, or with OLLAMA_AUTOSTART=0. With the
    # debug reloader, run it in the child process only.
    if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        from utils.ollama_bootstrap import start_background_bootstrap
        start_background_bootstrap()
    app.run(host=host, port=port, debug=debug)
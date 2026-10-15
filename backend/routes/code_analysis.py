"""Code-scan routes: sync scan, background jobs, limits, and fix compare."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, g

from config import Config
from models import db
from models.models import Analysis, Report, Threat, UploadedFile
from services.code_scan_jobs import job_store
from services.code_scanner import CodeScannerService
from utils.jwt_utils import require_jwt, owns_or_admin
from utils.security import save_upload
from utils.transfer_encoding import TransferDecodeError, read_upload_bytes, request_json_object
from utils.validators import decode_source_text

code_analysis_bp = Blueprint("code_analysis", __name__)
scanner = CodeScannerService()

ALLOWED = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".html", ".css", ".zip", ".txt",
    ".java", ".cs", ".sql", ".json", ".yml", ".yaml", ".xml", ".env", ".ini", ".config",
}

_COMPARE_EXT = {
    "python": ".py",
    "javascript": ".js",
    "php": ".php",
    "html": ".html",
    "css": ".css",
    "java": ".java",
    "csharp": ".cs",
    "sql": ".sql",
    "json": ".json",
    "yaml": ".yml",
    "xml": ".xml",
    "env": ".env",
    "ini": ".ini",
}


def code_scan_limits() -> dict:
    return {
        "max_upload_bytes": Config.CODE_SCAN_MAX_UPLOAD_BYTES,
        "max_file_bytes": Config.CODE_SCAN_MAX_FILE_BYTES,
        "max_zip_files": Config.CODE_SCAN_MAX_ZIP_FILES,
        "max_zip_extract_bytes": Config.CODE_SCAN_MAX_ZIP_EXTRACT_BYTES,
        "max_duration_seconds": Config.CODE_SCAN_MAX_DURATION_SECONDS,
        "max_concurrent": Config.CODE_SCAN_MAX_CONCURRENT,
        "max_compression_ratio": Config.CODE_SCAN_MAX_COMPRESSION_RATIO,
        "log_upload_max_bytes": Config.MAX_CONTENT_LENGTH,
        "supported_extensions": sorted(ALLOWED),
        "notes": (
            "Defaults target a Windows laptop with about 8 GB RAM. "
            "Adjust CODE_SCAN_MAX_* environment variables. "
            "Log analysis still uses MAX_UPLOAD_MB / MAX_CONTENT_LENGTH. "
            "Dependency hints use a tiny local list and are not CVE lookups."
        ),
    }


def _persist_code_scan(
    filename: str,
    stored_name: str,
    result: dict,
    size_bytes: int = 0,
    user_id: int | None = None,
) -> int:
    if user_id is None:
        user_id = g.current_user["id"] if getattr(g, "current_user", None) else None

    file_row = UploadedFile(
        user_id=user_id,
        original_name=filename,
        stored_name=stored_name,
        file_format="code",
        size_bytes=size_bytes,
    )
    db.session.add(file_row)
    db.session.flush()

    stored_path = Config.UPLOAD_DIR / stored_name
    total_lines = int((result.get("stats") or {}).get("lines_scanned") or 0)
    if not total_lines and stored_path.exists():
        with stored_path.open(errors="ignore") as handle:
            total_lines = sum(1 for _ in handle)

    analysis_row = Analysis(
        user_id=user_id,
        file_id=file_row.id,
        risk_score=result["risk_score"],
        severity=result["severity"].lower(),
        total_lines=total_lines,
        threat_count=result["vulnerability_count"],
        result_json=json.dumps(result),
    )
    db.session.add(analysis_row)
    db.session.flush()

    for vuln in result["vulnerabilities"][:400]:
        db.session.add(Threat(
            analysis_id=analysis_row.id,
            category=vuln["type"],
            severity=vuln["severity"].lower(),
            message=vuln["description"],
            path=f"{vuln['file']}:{vuln['line']}",
        ))

    report_payload = {
        "analysis_id": analysis_row.id,
        "summary": {
            "filename": filename,
            "risk_score": result["risk_score"],
            "severity": result["severity"],
            "vulnerability_count": result["vulnerability_count"],
            "stats": result.get("stats") or {},
        },
        "risk_score": result["risk_score"],
        "threat_details": result["vulnerabilities"],
        "recommendations": list({v["recommendation"] for v in result["vulnerabilities"]}) or [
            "No vulnerabilities detected. Continue secure coding practices."
        ],
    }
    report_path = Config.REPORT_DIR / f"code_report_{analysis_row.id}.json"
    Config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    db.session.add(Report(
        analysis_id=analysis_row.id,
        summary=json.dumps(report_payload["summary"]),
        recommendations=json.dumps(report_payload["recommendations"]),
        json_path=str(report_path),
    ))
    db.session.commit()
    return analysis_row.id


def _read_upload():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return None, None, None, (jsonify({"error": "No file uploaded. Use form field 'file'."}), 400)
    ext = Path(upload.filename).suffix.lower()
    if ext not in ALLOWED:
        return None, None, None, (jsonify({"error": f"Unsupported file type '{ext}'. Allowed: {sorted(ALLOWED)}"}), 400)
    # Base64 transport (see utils.transfer_encoding) keeps vulnerable source
    # files from being blocked by the hosting edge firewall. Size limits below
    # apply to the decoded bytes.
    try:
        raw = read_upload_bytes(upload)
    except TransferDecodeError as exc:
        return None, None, None, (jsonify({"error": str(exc)}), 400)
    if not raw or not raw.strip():
        return None, None, None, (jsonify({"error": "Uploaded file is empty."}), 400)
    if len(raw) > Config.CODE_SCAN_MAX_UPLOAD_BYTES:
        limit_mb = max(1, Config.CODE_SCAN_MAX_UPLOAD_BYTES // (1024 * 1024))
        return None, None, None, (jsonify({"error": f"File exceeds the {limit_mb} MB code-scan upload limit."}), 413)
    return upload, ext, raw, None


def _scan_bytes(raw: bytes, filename: str, ext: str, cancel_event=None, progress_cb=None) -> dict:
    if ext == ".zip":
        return scanner.scan_zip(
            raw,
            filename,
            cancel_event=cancel_event,
            progress_cb=progress_cb,
        )
    content = decode_source_text(raw)
    return scanner.scan_file(content, filename)


@code_analysis_bp.get("/code-scan/limits")
def code_scan_limits_view():
    return jsonify(code_scan_limits())


@code_analysis_bp.post("/code-scan")
@require_jwt
def code_scan():
    upload, ext, raw, error = _read_upload()
    if error:
        return error
    try:
        stored_name, _ = save_upload(upload.filename, raw)
        if ext == ".zip" and not job_store.acquire():
            return jsonify({
                "error": (
                    "A code scan is already running. Wait for it to finish or raise "
                    "CODE_SCAN_MAX_CONCURRENT."
                )
            }), 429
        try:
            result = _scan_bytes(raw, upload.filename, ext)
        finally:
            if ext == ".zip":
                job_store.release()
        analysis_id = _persist_code_scan(upload.filename, stored_name, result, size_bytes=len(raw))
        return jsonify({
            "analysis_id": analysis_id,
            "scan_type": "code",
            "scanned_at": datetime.utcnow().isoformat(),
            "report_url": f"/api/code-report/{analysis_id}",
            **result,
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Code scan failed: {exc}"}), 500


def _job_worker(app, job_id: str, raw: bytes, filename: str, ext: str, user_id: int, stored_name: str, size: int):
    with app.app_context():
        job = job_store.get(job_id)
        if not job:
            return
        if ext == ".zip" and not job_store.acquire():
            job["status"] = "failed"
            job["error"] = (
                "A code scan is already running. Wait for it to finish or raise "
                "CODE_SCAN_MAX_CONCURRENT."
            )
            return
        job["status"] = "running"

        def progress_cb(payload: dict) -> None:
            job["progress"] = payload

        try:
            result = _scan_bytes(raw, filename, ext, cancel_event=job["cancel"], progress_cb=progress_cb)
            analysis_id = _persist_code_scan(filename, stored_name, result, size_bytes=size, user_id=user_id)
            job["analysis_id"] = analysis_id
            job["result"] = {
                "analysis_id": analysis_id,
                "scan_type": "code",
                "scanned_at": datetime.utcnow().isoformat(),
                "report_url": f"/api/code-report/{analysis_id}",
                **result,
            }
            if job["cancel"].is_set():
                job["status"] = "cancelled"
            elif (result.get("stats") or {}).get("stop_reason") == "duration_limit":
                job["status"] = "timeout"
            else:
                job["status"] = "done"
        except Exception as exc:
            job["status"] = "failed"
            job["error"] = str(exc)
        finally:
            if ext == ".zip":
                job_store.release()


@code_analysis_bp.post("/code-scan/jobs")
@require_jwt
def start_code_scan_job():
    upload, ext, raw, error = _read_upload()
    if error:
        return error
    user_id = g.current_user["id"]
    stored_name, _ = save_upload(upload.filename, raw)
    public = job_store.create(user_id, upload.filename)
    app = current_app._get_current_object()
    job_store.start_thread(
        _job_worker,
        (app, public["job_id"], raw, upload.filename, ext, user_id, stored_name, len(raw)),
    )
    return jsonify(public), 202


@code_analysis_bp.get("/code-scan/jobs/<job_id>")
@require_jwt
def code_scan_job_status(job_id: str):
    job = job_store.get(job_id)
    if not job:
        return jsonify({"error": "Scan job not found."}), 404
    if not owns_or_admin(job["user_id"]):
        return jsonify({"error": "You do not have access to this scan job."}), 403
    return jsonify(job_store.public(job))


@code_analysis_bp.post("/code-scan/jobs/<job_id>/cancel")
@require_jwt
def cancel_code_scan_job(job_id: str):
    job = job_store.get(job_id)
    if not job:
        return jsonify({"error": "Scan job not found."}), 404
    if not owns_or_admin(job["user_id"]):
        return jsonify({"error": "You do not have access to this scan job."}), 403
    job_store.cancel(job_id)
    return jsonify(job_store.public(job))


@code_analysis_bp.post("/code-scan/compare")
@require_jwt
def compare_suggested_fix():
    try:
        body = request_json_object()
    except TransferDecodeError as exc:
        return jsonify({"error": str(exc)}), 400
    original = body.get("original")
    suggested = body.get("suggested_fix") or body.get("suggested")
    language = (body.get("language") or "text").lower()
    filename = body.get("filename") or f"snippet{_COMPARE_EXT.get(language, '.txt')}"
    if not isinstance(original, str) or not original.strip():
        return jsonify({"error": "original source snippet is required."}), 400
    if not isinstance(suggested, str) or not suggested.strip():
        return jsonify({"error": "suggested_fix is required."}), 400
    ext = Path(filename).suffix.lower() or _COMPARE_EXT.get(language, ".txt")
    before = scanner.scan_file(original, f"original{ext}")
    after = scanner.scan_file(suggested, f"suggested{ext}")
    return jsonify({
        "original_count": before["vulnerability_count"],
        "suggested_count": after["vulnerability_count"],
        "original_types": [item["type"] for item in before["vulnerabilities"]],
        "suggested_types": [item["type"] for item in after["vulnerabilities"]],
        "note": (
            "A finding disappearing after re-scanning a snippet does not prove the "
            "application is secure. The scanner was not executed against the full program."
        ),
    })


@code_analysis_bp.get("/code-report/<int:analysis_id>")
@require_jwt
def code_report(analysis_id: int):
    analysis = Analysis.query.get(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found."}), 404
    if not owns_or_admin(analysis.user_id):
        return jsonify({"error": "You do not have access to this analysis."}), 403
    return jsonify(json.loads(analysis.result_json))

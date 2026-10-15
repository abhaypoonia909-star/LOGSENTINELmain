from flask import Blueprint, request, jsonify, g
from config import Config
from models import db
from models.models import UploadedFile
from utils.validators import validate_log_extension
from utils.security import save_upload
from utils.jwt_utils import require_jwt
from utils.transfer_encoding import TransferDecodeError, read_upload_bytes

upload_bp = Blueprint("upload", __name__)

@upload_bp.post("/upload")
@require_jwt
def upload_file():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file uploaded. Use form field 'file'."}), 400
    if not validate_log_extension(f.filename):
        return jsonify({"error": "Only .log, .txt, .json files are allowed."}), 400

    try:
        raw = read_upload_bytes(f, max_bytes=Config.MAX_CONTENT_LENGTH)
    except TransferDecodeError as exc:
        return jsonify({"error": str(exc)}), 400
    if not raw.strip():
        return jsonify({"error": "Uploaded file is empty."}), 400

    stored_name, path = save_upload(f.filename, raw)
    record = UploadedFile(
        user_id=g.current_user["id"] if getattr(g, "current_user", None) else None,
        original_name=f.filename,
        stored_name=stored_name,
        size_bytes=len(raw),
    )
    db.session.add(record)
    db.session.commit()

    return jsonify({
        "file_id": record.id,
        "filename": record.original_name,
        "stored_as": stored_name,
        "size_bytes": record.size_bytes,
    }), 201

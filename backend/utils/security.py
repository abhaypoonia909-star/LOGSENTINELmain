import uuid
from pathlib import Path
from werkzeug.utils import secure_filename
from config import Config

def save_upload(filename: str, content: bytes) -> tuple[str, Path]:
    Config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe = secure_filename(filename) or "upload.log"
    stored = f"{uuid.uuid4().hex[:10]}_{safe}"
    path = Config.UPLOAD_DIR / stored
    path.write_bytes(content)
    return stored, path
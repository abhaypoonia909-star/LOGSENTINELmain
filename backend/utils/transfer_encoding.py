"""Optional base64 transport for uploads and code snippets.

Why this exists
---------------
LogSentinel uploads security logs and vulnerable source code. That content is
*supposed* to contain attack strings (``../../etc/passwd``, ``<script>``,
``' OR 1=1``). Hosting edge firewalls (Render's built-in Cloudflare WAF) inspect
request bodies and answer such uploads with an HTML ``403 Blocked`` page before
Flask ever runs, so the UI shows a bare ``HTTP 403``.

The browser therefore sends the *same* multipart ``file`` field, but with the
file bytes base64-encoded, and marks the request with
``X-LogSentinel-Transfer: base64``. Routes call :func:`read_upload_bytes` to get
the original bytes back. Requests without the header are handled exactly as
before, so existing API clients and tests keep working.

Nothing here touches authentication: ``require_jwt`` still runs first.
"""

from __future__ import annotations

import base64
import binascii
import json

from flask import request
from werkzeug.exceptions import RequestEntityTooLarge

TRANSFER_HEADER = "X-LogSentinel-Transfer"
BASE64_TRANSFER = "base64"


class TransferDecodeError(ValueError):
    """The request claimed base64 transfer but the body was not valid base64."""


def transfer_is_base64() -> bool:
    return (request.headers.get(TRANSFER_HEADER) or "").strip().lower() == BASE64_TRANSFER


def base64_budget(raw_limit: int) -> int:
    """Request-size budget that lets a ``raw_limit``-byte file arrive base64-encoded.

    Base64 grows data by 4/3; the extra 4 KiB covers multipart boundaries and
    headers. The *decoded* size is still checked against ``raw_limit``.
    """
    return int(raw_limit) * 4 // 3 + 4096


def read_upload_bytes(storage, max_bytes: int | None = None) -> bytes:
    """Return the real bytes of an uploaded file, decoding base64 transport if used.

    Raises :class:`TransferDecodeError` for a malformed base64 body and
    :class:`werkzeug.exceptions.RequestEntityTooLarge` when the decoded file is
    larger than ``max_bytes`` (so the app's existing 413 handler answers).
    """
    raw = storage.read()
    if transfer_is_base64():
        try:
            raw = base64.b64decode(b"".join(raw.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise TransferDecodeError(
                "Upload transfer encoding is invalid. Re-select the file and try again."
            ) from exc
    if max_bytes is not None and len(raw) > int(max_bytes):
        raise RequestEntityTooLarge()
    return raw


def request_json_object() -> dict:
    """JSON body as a dict, accepting a base64-wrapped JSON text when flagged.

    Mirrors ``request.get_json(silent=True) or {}`` for ordinary requests.
    """
    if not transfer_is_base64():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}
    try:
        decoded = base64.b64decode(b"".join(request.get_data().split()), validate=True)
        data = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise TransferDecodeError(
            "Request transfer encoding is invalid. Please retry."
        ) from exc
    return data if isinstance(data, dict) else {}

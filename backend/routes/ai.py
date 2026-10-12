import json

from flask import Blueprint, Response, request, jsonify, stream_with_context
from models.models import Analysis
from services.ai_service import AIService, AIServiceError
from utils.validators import sanitize_text
from utils.jwt_utils import require_jwt, owns_or_admin

ai_bp = Blueprint("ai", __name__)
ai = AIService()

_MAX_HISTORY = 8


@ai_bp.post("/ai")
@require_jwt
def ai_assistant():
    parsed = _parse_ai_request()
    if parsed[3] is not None:
        return parsed[3]
    question, history, analysis_data, _error = parsed

    try:
        result = ai.answer(question, analysis_data, history)
    except AIServiceError as exc:
        return jsonify({"error": exc.message}), exc.status_code
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    payload = {
        "question": question,
        "answer": result["answer"],
        "explanation": result["explanation"],
        "provider": result.get("provider", "ollama"),
        "used_analysis": bool(result.get("used_analysis")),
        "source": result.get("source", "model"),
        "risk": result["risk"],
        "prevention": result["prevention"],
    }
    if "ai_analysis" in result:
        payload["ai_analysis"] = result["ai_analysis"]
    return jsonify(payload)


@ai_bp.post("/ai/stream")
@require_jwt
def ai_assistant_stream():
    parsed = _parse_ai_request()
    if parsed[3] is not None:
        return parsed[3]
    question, history, analysis_data, _error = parsed

    def generate():
        try:
            for event in ai.stream_answer(question, analysis_data, history):
                yield "data: %s\n\n" % json.dumps(event)
        except AIServiceError as exc:
            yield "data: %s\n\n" % json.dumps({
                "event": "error",
                "error": exc.message,
                "status": exc.status_code,
            })
        except ValueError as exc:
            yield "data: %s\n\n" % json.dumps({
                "event": "error",
                "error": str(exc),
                "status": 400,
            })

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@ai_bp.get("/ai/status")
@require_jwt
def ai_status():
    return jsonify(ai.status())


def _parse_ai_request():
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return None, None, None, (jsonify({"error": "Request body must be a JSON object."}), 400)

    question = sanitize_text(str(data.get("question", "")), 2000)
    if not question:
        return None, None, None, (jsonify({"error": "Field 'question' is required."}), 400)

    try:
        history = _parse_history(data.get("messages"))
    except ValueError as exc:
        return None, None, None, (jsonify({"error": str(exc)}), 400)

    analysis_data = None
    if "analysis_id" in data and data.get("analysis_id") not in (None, ""):
        try:
            analysis_id = _parse_analysis_id(data.get("analysis_id"))
        except ValueError as exc:
            return None, None, None, (jsonify({"error": str(exc)}), 400)
        analysis_data, error = _authorized_analysis(analysis_id)
        if error:
            return None, None, None, error

    return question, history, analysis_data, None


def _parse_history(raw) -> list[dict]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("Field 'messages' must be a list.")
    if len(raw) > 20:
        raise ValueError("Field 'messages' is too long.")

    cleaned = []
    for item in raw[-_MAX_HISTORY:]:
        if not isinstance(item, dict):
            raise ValueError("Each message must be an object with role and content.")
        role = item.get("role")
        if role not in ("user", "assistant"):
            raise ValueError("Message role must be 'user' or 'assistant'.")
        content = sanitize_text(str(item.get("content") or ""), 2000)
        if content:
            cleaned.append({"role": role, "content": content})
    return cleaned


def _parse_analysis_id(value) -> int:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError("Field 'analysis_id' must be a positive integer.")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
    else:
        raise ValueError("Field 'analysis_id' must be a positive integer.")
    if parsed < 1:
        raise ValueError("Field 'analysis_id' must be a positive integer.")
    return parsed


def _authorized_analysis(analysis_id: int):
    row = Analysis.query.get(analysis_id)
    if not row:
        return None, (jsonify({"error": "Analysis not found."}), 404)
    if not owns_or_admin(row.user_id):
        return None, (jsonify({"error": "You do not have access to this analysis."}), 403)

    try:
        payload = json.loads(row.result_json or "{}")
    except json.JSONDecodeError:
        return None, (jsonify({"error": "Stored analysis could not be read."}), 500)
    if not isinstance(payload, dict):
        return None, (jsonify({"error": "Stored analysis could not be read."}), 500)

    authorized = dict(payload)
    filename = ""
    if row.file is not None and row.file.original_name:
        filename = str(row.file.original_name)
    if filename:
        authorized["filename"] = filename[:255]
    return authorized, None

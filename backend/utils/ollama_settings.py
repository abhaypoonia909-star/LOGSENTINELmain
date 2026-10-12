"""Runtime defaults for local Ollama. AIService reads these when env vars are unset.

Keep this module free of Flask/Config imports so tests can inspect defaults
without loading JWT secrets.
"""

from __future__ import annotations

import os
from typing import Any

DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2:1b"
DEFAULT_OLLAMA_TIMEOUT_SECONDS = 60
DEFAULT_OLLAMA_KEEP_ALIVE = "60m"
DEFAULT_OLLAMA_TEMPERATURE = 0.3
DEFAULT_OLLAMA_NUM_CTX = 1024
DEFAULT_OLLAMA_NUM_PREDICT = 80
DEFAULT_OLLAMA_NUM_PREDICT_SHORT = 48
DEFAULT_OLLAMA_NUM_PREDICT_ANALYSIS = 120
DEFAULT_OLLAMA_NUM_PREDICT_LONG = 512


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def ollama_runtime_settings() -> tuple[str, str, float, dict[str, Any]]:
    """Values actually sent to Ollama when environment variables are absent."""
    from services.ollama_client import normalize_base_url

    base_url = normalize_base_url(
        os.environ.get("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_BASE_URL
    )
    model = (os.environ.get("OLLAMA_MODEL") or DEFAULT_OLLAMA_MODEL).strip() or DEFAULT_OLLAMA_MODEL
    raw_timeout = (os.environ.get("OLLAMA_TIMEOUT_SECONDS") or str(DEFAULT_OLLAMA_TIMEOUT_SECONDS)).strip()
    try:
        timeout = float(raw_timeout)
    except ValueError:
        timeout = float(DEFAULT_OLLAMA_TIMEOUT_SECONDS)
    if timeout <= 0:
        timeout = float(DEFAULT_OLLAMA_TIMEOUT_SECONDS)
    keep_alive = (os.environ.get("OLLAMA_KEEP_ALIVE") or DEFAULT_OLLAMA_KEEP_ALIVE).strip() or DEFAULT_OLLAMA_KEEP_ALIVE
    try:
        temperature = float(os.environ.get("OLLAMA_TEMPERATURE") or DEFAULT_OLLAMA_TEMPERATURE)
    except ValueError:
        temperature = DEFAULT_OLLAMA_TEMPERATURE
    options = {
        "temperature": max(0.0, min(temperature, 1.0)),
        "num_ctx": _as_int(os.environ.get("OLLAMA_NUM_CTX") or DEFAULT_OLLAMA_NUM_CTX) or DEFAULT_OLLAMA_NUM_CTX,
        "num_predict": _as_int(os.environ.get("OLLAMA_NUM_PREDICT") or DEFAULT_OLLAMA_NUM_PREDICT) or DEFAULT_OLLAMA_NUM_PREDICT,
        "num_predict_short": _as_int(os.environ.get("OLLAMA_NUM_PREDICT_SHORT") or DEFAULT_OLLAMA_NUM_PREDICT_SHORT) or DEFAULT_OLLAMA_NUM_PREDICT_SHORT,
        "num_predict_analysis": _as_int(os.environ.get("OLLAMA_NUM_PREDICT_ANALYSIS") or DEFAULT_OLLAMA_NUM_PREDICT_ANALYSIS) or DEFAULT_OLLAMA_NUM_PREDICT_ANALYSIS,
        "num_predict_long": _as_int(os.environ.get("OLLAMA_NUM_PREDICT_LONG") or DEFAULT_OLLAMA_NUM_PREDICT_LONG) or DEFAULT_OLLAMA_NUM_PREDICT_LONG,
        "keep_alive": keep_alive,
    }
    return base_url, model, timeout, options

"""Refuse a known development signing secret when production is indicated."""

from __future__ import annotations

import os

PLACEHOLDER_SECRET = "change-me-in-production"
_PROD_VALUES = {"production", "prod"}


def is_production_environment() -> bool:
    for name in ("LOGSENTINEL_ENV", "FLASK_ENV", "RAILWAY_ENVIRONMENT"):
        value = (os.environ.get(name) or "").strip().lower()
        if value in _PROD_VALUES:
            return True
    # Render sets RENDER=true on every service. Treat that as production so a
    # forgotten LOGSENTINEL_ENV cannot start with the placeholder JWT.
    render_flag = (os.environ.get("RENDER") or "").strip().lower()
    if render_flag in {"true", "1", "yes"}:
        return True
    return False


def configured_signing_secret() -> str:
    jwt_secret = (os.environ.get("JWT_SECRET") or "").strip()
    secret_key = (os.environ.get("SECRET_KEY") or "").strip()
    return jwt_secret or secret_key


def signing_secret_is_insecure() -> bool:
    secret = configured_signing_secret()
    if not secret:
        return True
    if secret == PLACEHOLDER_SECRET:
        return True
    if len(secret) < 16:
        return True
    return False


def assert_secure_secrets() -> None:
    """Raise when production would otherwise sign JWTs with the placeholder."""
    if not is_production_environment():
        return
    if not signing_secret_is_insecure():
        return
    raise RuntimeError(
        "Production configuration refuses the development JWT/SECRET placeholder. "
        "Set JWT_SECRET (or SECRET_KEY) to a random value of at least 16 characters. "
        "The app will not start with change-me-in-production."
    )

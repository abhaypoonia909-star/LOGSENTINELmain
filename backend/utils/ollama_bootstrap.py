"""Development-only helper: make sure the laptop's own Ollama is running.

Used by ``python app.py`` (the local dev entry point) and nowhere else.
It never runs under gunicorn/Render, never downloads a model, never installs
anything, and never changes how Ollama binds: the installed ``ollama.exe`` is
started with its default loopback address (``127.0.0.1:11434``).

Sequence
--------
1. Skip unless SentinelAI uses Ollama, the base URL is loopback, we are not in
   production, and ``OLLAMA_AUTOSTART`` is not ``0``.
2. ``GET /api/tags`` - if Ollama already answers, only verify the model.
3. Otherwise find the installed ``ollama`` binary (PATH, then the per-user
   install folder), refuse if ``OLLAMA_HOST`` would bind a public address,
   and launch ``ollama serve`` detached with no console window.
4. Poll ``/api/tags`` until ready (``OLLAMA_AUTOSTART_WAIT_SECONDS``, default 45).
5. Confirm the configured model is installed; if not, print the exact
   ``ollama pull`` command instead of running it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

LOG_PREFIX = "[LogSentinel][Ollama]"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
DEFAULT_WAIT_SECONDS = 45.0  # a cold ollama.exe start measured ~25-30 s on an 8 GB laptop
_POLL_INTERVAL = 0.5


def _log(message: str) -> None:
    print(f"{LOG_PREFIX} {message}", flush=True)


def _env_flag_disabled(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in {"0", "false", "no", "off"}


def _is_loopback_url(base_url: str) -> bool:
    try:
        host = (urlparse(base_url).hostname or "").lower()
    except ValueError:
        return False
    return host in LOOPBACK_HOSTS


def _ollama_host_is_safe() -> bool:
    """True when OLLAMA_HOST is unset or points at a loopback address.

    Starting ``ollama serve`` with e.g. ``OLLAMA_HOST=0.0.0.0`` would expose the
    model API on the network, so the bootstrap refuses in that case.
    """
    raw = (os.environ.get("OLLAMA_HOST") or "").strip()
    if not raw:
        return True
    candidate = raw if "://" in raw else f"http://{raw}"
    return _is_loopback_url(candidate)


def find_ollama_executable() -> str | None:
    """Locate the already-installed Ollama binary. Never downloads anything."""
    found = shutil.which("ollama")
    if found:
        return found
    candidates = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Programs" / "Ollama" / "ollama.exe")
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(Path(program_files) / "Ollama" / "ollama.exe")
    for path in candidates:
        if path.is_file():
            return str(path)
    return None


def _default_launcher(executable: str) -> None:
    """Start ``ollama serve`` detached so closing Flask does not kill it."""
    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([executable, "serve"], **kwargs)


def _installed_models(client) -> list[str] | None:
    """Model names if Ollama answers, else None."""
    try:
        return list(client.installed_models())
    except Exception:
        return None


def _wait_seconds() -> float:
    raw = (os.environ.get("OLLAMA_AUTOSTART_WAIT_SECONDS") or "").strip()
    try:
        value = float(raw) if raw else DEFAULT_WAIT_SECONDS
    except ValueError:
        value = DEFAULT_WAIT_SECONDS
    return max(1.0, min(value, 120.0))


def ensure_local_ollama(
    *,
    client=None,
    launcher=None,
    find_executable=None,
    sleep=time.sleep,
    monotonic=time.monotonic,
) -> dict:
    """Run the bootstrap once. Returns a small status dict (also logged).

    ``status`` is one of: skipped, running, started, no_executable,
    start_failed, timeout. ``model_ready`` says whether the configured model is
    installed when Ollama answered.
    """
    from services.ai_service import _model_is_installed, _schedule_ollama_warmup
    from services.ollama_client import OllamaClient
    from utils.ollama_settings import ollama_runtime_settings
    from utils.runtime_secrets import is_production_environment

    provider = (os.environ.get("AI_PROVIDER") or "ollama").strip().lower() or "ollama"
    base_url, model, timeout, options = ollama_runtime_settings()

    if provider == "openai":
        return {"status": "skipped", "reason": "AI_PROVIDER=openai"}
    if is_production_environment():
        return {"status": "skipped", "reason": "production environment"}
    if _env_flag_disabled("OLLAMA_AUTOSTART"):
        return {"status": "skipped", "reason": "OLLAMA_AUTOSTART disabled"}
    if not _is_loopback_url(base_url):
        _log(f"OLLAMA_BASE_URL is not loopback ({base_url}); not starting a local server.")
        return {"status": "skipped", "reason": "remote base url"}

    client = client or OllamaClient(base_url, timeout)
    launcher = launcher or _default_launcher
    find_executable = find_executable or find_ollama_executable

    def _finish(status: str, names: list[str]) -> dict:
        ready = _model_is_installed(names, model)
        if ready:
            _log(f"ready at {base_url} with model {model}.")
            _schedule_ollama_warmup(client, model, str(options.get("keep_alive") or "60m"))
        else:
            _log(
                f"running at {base_url}, but model {model} is not installed. "
                f"Run once in a terminal: ollama pull {model}  (not done automatically)."
            )
        return {"status": status, "model_ready": ready, "base_url": base_url, "model": model}

    names = _installed_models(client)
    if names is not None:
        return _finish("running", names)

    if not _ollama_host_is_safe():
        _log("OLLAMA_HOST points at a non-loopback address; refusing to auto-start. Start Ollama yourself.")
        return {"status": "skipped", "reason": "unsafe OLLAMA_HOST"}

    executable = find_executable()
    if not executable:
        _log(
            f"not reachable at {base_url} and ollama.exe was not found. "
            "Start the Ollama app from the Start menu (SentinelAI stays unavailable until then)."
        )
        return {"status": "no_executable", "base_url": base_url, "model": model}

    _log(f"not running; starting the installed Ollama ({executable}) on {base_url} ...")
    try:
        launcher(executable)
    except Exception as exc:  # noqa: BLE001 - report and keep Flask running
        _log(f"could not start Ollama: {exc.__class__.__name__}. Start the Ollama app manually.")
        return {"status": "start_failed", "base_url": base_url, "model": model}

    deadline = monotonic() + _wait_seconds()
    while monotonic() < deadline:
        sleep(_POLL_INTERVAL)
        names = _installed_models(client)
        if names is not None:
            return _finish("started", names)

    _log(
        f"started Ollama but {base_url} did not answer within {int(_wait_seconds())}s. "
        "It may still be loading; SentinelAI will work once /api/ai/status reports ready."
    )
    return {"status": "timeout", "base_url": base_url, "model": model}


def start_background_bootstrap() -> threading.Thread:
    """Run ensure_local_ollama() without delaying Flask startup."""

    def _run() -> None:
        try:
            ensure_local_ollama()
        except Exception as exc:  # noqa: BLE001 - never crash the dev server
            _log(f"bootstrap skipped after error: {exc.__class__.__name__}")

    thread = threading.Thread(target=_run, name="ollama-bootstrap", daemon=True)
    thread.start()
    return thread

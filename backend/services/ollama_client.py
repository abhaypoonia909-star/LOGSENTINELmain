"""Ollama HTTP client. No cloud calls.

Default: the laptop's own Ollama on http://127.0.0.1:11434, no credentials.

Remote mode: when OLLAMA_BASE_URL is not a loopback address (e.g. the Render
deployment reaching the laptop through backend/tools/ollama_gateway.py behind a
tunnel), the client requires https:// and sends
``Authorization: Bearer $OLLAMA_AUTH_TOKEN``. It refuses to talk to a remote
Ollama without a token so the model API is never used unauthenticated.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin, urlparse

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
AUTH_TOKEN_ENV = "OLLAMA_AUTH_TOKEN"


class OllamaUnavailable(Exception):
    """Ollama is not running or the local URL could not be reached."""


class OllamaModelMissing(Exception):
    """The configured model is not installed in the local Ollama instance."""


class OllamaRequestError(Exception):
    """Ollama returned an empty or unexpected response."""


class OllamaConfigError(OllamaRequestError):
    """Remote OLLAMA_BASE_URL / OLLAMA_AUTH_TOKEN are misconfigured or rejected."""


def normalize_base_url(base_url: str) -> str:
    url = (base_url or "").strip().rstrip("/")
    return url or "http://127.0.0.1:11434"


def is_loopback_base_url(base_url: str) -> bool:
    try:
        host = (urlparse(normalize_base_url(base_url)).hostname or "").lower()
    except ValueError:
        return False
    return host in LOOPBACK_HOSTS


class OllamaClient:
    def __init__(self, base_url: str, timeout: float = 60.0, auth_token: str | None = None):
        self.base_url = normalize_base_url(base_url)
        self.timeout = max(5.0, float(timeout))
        self.remote = not is_loopback_base_url(self.base_url)
        token = auth_token if auth_token is not None else os.environ.get(AUTH_TOKEN_ENV, "")
        self.auth_token = (token or "").strip()

    def _headers(self, json_body: bool) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if json_body:
            headers["Content-Type"] = "application/json"
        if self.remote:
            if not self.base_url.lower().startswith("https://"):
                raise OllamaConfigError(
                    "OLLAMA_BASE_URL points at a non-local host but does not use https://. "
                    "Refusing to send the gateway token in clear text."
                )
            if not self.auth_token:
                raise OllamaConfigError(
                    "OLLAMA_BASE_URL points at a remote Ollama gateway but %s is not set." % AUTH_TOKEN_ENV
                )
            headers["Authorization"] = "Bearer " + self.auth_token
            # Free tunnel providers may show a browser interstitial; this marks a server call.
            headers["ngrok-skip-browser-warning"] = "1"
        return headers

    def _ping_timeout(self) -> float:
        # A tunnel round trip plus a cold /api/tags can exceed the 5 s local budget.
        return min(15.0 if self.remote else 5.0, self.timeout)

    @staticmethod
    def _rejected(exc: urllib.error.HTTPError) -> OllamaConfigError | None:
        if exc.code in (401, 403):
            return OllamaConfigError(
                "The remote Ollama gateway rejected the request (HTTP %d). "
                "Check that %s on this server matches the gateway token." % (exc.code, AUTH_TOKEN_ENV)
            )
        return None

    def _request(self, method: str, path: str, payload: dict | None = None, timeout: float | None = None) -> Any:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        data = None
        headers = self._headers(json_body=payload is not None)
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            rejected = self._rejected(exc)
            if rejected is not None:
                raise rejected from exc
            body = exc.read().decode("utf-8", errors="replace")
            text = body.lower()
            if exc.code == 404 or "not found" in text or "model" in text and "not found" in text:
                raise OllamaModelMissing(body or str(exc)) from exc
            raise OllamaRequestError(body or str(exc)) from exc
        except urllib.error.URLError as exc:
            raise OllamaUnavailable(str(exc.reason if getattr(exc, "reason", None) else exc)) from exc
        except TimeoutError as exc:
            raise TimeoutError("The local Ollama request timed out.") from exc

        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OllamaRequestError("Ollama returned a non-JSON response.") from exc

    def ping(self) -> dict[str, Any]:
        return self._request("GET", "/api/tags", timeout=self._ping_timeout())

    def installed_models(self) -> list[str]:
        payload = self.ping()
        models = payload.get("models") if isinstance(payload, dict) else None
        names = []
        if isinstance(models, list):
            for item in models:
                if isinstance(item, dict) and item.get("name"):
                    names.append(str(item["name"]))
        return names

    def _chat_payload(
        self,
        model: str,
        messages: list[dict[str, str]],
        options: dict[str, Any] | None,
        stream: bool,
    ) -> dict[str, Any]:
        tuned = {
            "temperature": 0.3,
            "num_ctx": 1024,
            "num_predict": 80,
        }
        keep_alive = "60m"
        if isinstance(options, dict):
            for key in ("temperature", "num_ctx", "num_predict"):
                if options.get(key) is not None:
                    tuned[key] = options[key]
            if options.get("keep_alive"):
                keep_alive = str(options["keep_alive"])
        return {
            "model": model,
            "messages": messages,
            "stream": bool(stream),
            "keep_alive": keep_alive,
            "options": tuned,
        }

    def _raise_model_error(self, payload: dict[str, Any] | None) -> None:
        if not isinstance(payload, dict) or not payload.get("error"):
            return
        error = str(payload["error"])
        if "not found" in error.lower() or "pull" in error.lower():
            raise OllamaModelMissing(error)
        raise OllamaRequestError(error)

    def chat(self, model: str, messages: list[dict[str, str]], options: dict[str, Any] | None = None) -> str:
        payload = self._chat_payload(model, messages, options, stream=False)
        try:
            data = self._request("POST", "/api/chat", payload)
        except OllamaRequestError as exc:
            text = str(exc).lower()
            if "not found" in text or "pull" in text:
                raise OllamaModelMissing(str(exc)) from exc
            raise

        self._raise_model_error(data if isinstance(data, dict) else None)
        message = data.get("message") if isinstance(data, dict) else None
        content = ""
        if isinstance(message, dict):
            content = str(message.get("content") or "")
        elif isinstance(data, dict):
            content = str(data.get("response") or "")
        text = content.strip()
        if not text:
            raise OllamaRequestError("Ollama returned an empty response.")
        return text

    def chat_stream(self, model: str, messages: list[dict[str, str]], options: dict[str, Any] | None = None):
        payload = self._chat_payload(model, messages, options, stream=True)
        url = urljoin(self.base_url + "/", "api/chat")
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(json_body=True),
            method="POST",
        )
        got_text = False
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                for raw in response:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise OllamaRequestError("Ollama returned a non-JSON stream chunk.") from exc
                    self._raise_model_error(data)
                    message = data.get("message") if isinstance(data, dict) else None
                    piece = ""
                    if isinstance(message, dict):
                        piece = str(message.get("content") or "")
                    elif isinstance(data, dict):
                        piece = str(data.get("response") or "")
                    if piece:
                        got_text = True
                        yield piece
                    if isinstance(data, dict) and data.get("done"):
                        break
        except urllib.error.HTTPError as exc:
            rejected = self._rejected(exc)
            if rejected is not None:
                raise rejected from exc
            body = exc.read().decode("utf-8", errors="replace")
            text = body.lower()
            if exc.code == 404 or "not found" in text:
                raise OllamaModelMissing(body or str(exc)) from exc
            raise OllamaRequestError(body or str(exc)) from exc
        except urllib.error.URLError as exc:
            raise OllamaUnavailable(str(exc.reason if getattr(exc, "reason", None) else exc)) from exc
        except TimeoutError as exc:
            raise TimeoutError("The local Ollama request timed out.") from exc
        if not got_text:
            raise OllamaRequestError("Ollama returned an empty response.")

    def warmup(self, model: str, keep_alive: str = "60m") -> None:
        """Keep the local model loaded. Does not send user or analysis text."""
        payload = self._chat_payload(
            model,
            [{"role": "user", "content": "ok"}],
            {
                "temperature": 0,
                "num_ctx": 256,
                "num_predict": 1,
                "keep_alive": keep_alive,
            },
            stream=False,
        )
        self._request("POST", "/api/chat", payload, timeout=min(20.0, self.timeout))

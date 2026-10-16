"""One command: securely connect this laptop's Ollama to the Render-hosted LogSentinel chat.

    backend\\tools\\connect_ollama.cmd          (Windows CMD)
    python tools/connect_ollama.py             (from backend/, any OS)

What it does, in order:
1. Makes sure the installed Ollama is running on 127.0.0.1:11434 with the
   configured model (reuses utils/ollama_bootstrap.py; never pulls a model).
2. Loads or creates the gateway token (stored outside the repo in
   %LOCALAPPDATA%\\LogSentinel\\ollama_gateway_token.txt). Shown once on
   creation, or with --show-token, so you can paste it into Render.
3. Finds ngrok (PATH or %LOCALAPPDATA%\\LogSentinel\\ngrok\\ngrok.exe). If it is
   missing, offers to download the official portable zip - no installer, no winget.
4. Asks once for your free ngrok authtoken and free static domain; stores the
   domain next to the token. (ngrok stores the authtoken in its own config.)
5. Starts the authenticated gateway on 127.0.0.1:11435 and the ngrok tunnel to it.
   Port 11434 is never exposed.
6. Self-tests through the public URL: no token -> 401, correct token -> model list.
7. Prints the two Render environment variables and stays connected until Ctrl+C.

Free tier only. Works while this window is open and the laptop is awake.
"""

from __future__ import annotations

import argparse
import getpass
import io
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from tools.ollama_gateway import (  # noqa: E402
    DEFAULT_PORT,
    app_data_dir,
    default_token_path,
    load_or_create_token,
    make_server,
    serve_in_thread,
)

NGROK_ZIP_URL = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip"
NGROK_LOCAL_API = "http://127.0.0.1:4040/api/tunnels"
RENDER_URL = "https://logsentinelmain.onrender.com"


def say(message: str = "") -> None:
    print(message, flush=True)


def ngrok_dir() -> Path:
    return app_data_dir() / "ngrok"


def domain_path() -> Path:
    return app_data_dir() / "ngrok_domain.txt"


# ---------------------------------------------------------------------------
# Step 1: Ollama
# ---------------------------------------------------------------------------
def ensure_ollama() -> tuple[str, str]:
    from utils.ollama_bootstrap import ensure_local_ollama
    from utils.ollama_settings import ollama_runtime_settings

    base_url, model, _timeout, _options = ollama_runtime_settings()
    result = ensure_local_ollama()
    status = result.get("status")
    if status in ("running", "started") and result.get("model_ready"):
        return base_url, model
    if status in ("running", "started"):
        say(f"Model {model} is not installed in Ollama. Run once:  ollama pull {model}")
    elif status == "skipped":
        say(f"Ollama bootstrap skipped ({result.get('reason')}). Start Ollama yourself and retry.")
    else:
        say("Ollama is not reachable on 127.0.0.1:11434. Start the Ollama app and retry.")
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Step 3: ngrok binary (portable)
# ---------------------------------------------------------------------------
def find_ngrok() -> str | None:
    """Reuse an ngrok binary that is already on this machine; download only as a last resort.

    Order: NGROK_EXE env var, PATH, %LOCALAPPDATA%\\LogSentinel\\ngrok, then the
    user's Downloads folder (zip extracted in place, e.g.
    Downloads\\ngrok-v3-stable-windows-amd64\\ngrok.exe).
    """
    exe_name = "ngrok.exe" if os.name == "nt" else "ngrok"
    explicit = (os.environ.get("NGROK_EXE") or "").strip().strip('"')
    if explicit and Path(explicit).is_file():
        return explicit
    found = shutil.which("ngrok")
    if found:
        return found
    candidates = [ngrok_dir() / exe_name]
    downloads = Path.home() / "Downloads"
    candidates.append(downloads / exe_name)
    if downloads.is_dir():
        for child in sorted(downloads.glob("ngrok*")):
            if child.is_dir():
                candidates.append(child / exe_name)
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def download_ngrok(assume_yes: bool = False) -> str:
    target_dir = ngrok_dir()
    say("ngrok was not found on this machine.")
    say(f"It can be downloaded as a portable zip (official ngrok URL, ~15 MB) into:\n  {target_dir}")
    if not assume_yes:
        answer = input("Download it now? [Y/n] ").strip().lower()
        if answer not in ("", "y", "yes"):
            raise SystemExit("ngrok is required for the tunnel. Aborted.")
    target_dir.mkdir(parents=True, exist_ok=True)
    say("Downloading ...")
    with urllib.request.urlopen(NGROK_ZIP_URL, timeout=120) as response:
        data = response.read()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [n for n in archive.namelist() if n.lower().endswith(("ngrok.exe", "ngrok"))]
        if not names:
            raise SystemExit("Downloaded archive did not contain ngrok.")
        archive.extract(names[0], target_dir)
    exe = target_dir / names[0]
    say(f"ngrok ready: {exe}")
    return str(exe)


def run_ngrok(exe: str, *args: str, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([exe, *args], capture_output=capture, text=True, timeout=60)


def ensure_authtoken(exe: str) -> None:
    check = run_ngrok(exe, "config", "check")
    if check.returncode == 0:
        return
    say("ngrok needs your free account authtoken (one time).")
    say("  1. Sign in / sign up free at https://dashboard.ngrok.com")
    say("  2. Copy the token from https://dashboard.ngrok.com/get-started/your-authtoken")
    token = getpass.getpass("Paste the authtoken (input hidden): ").strip()
    if not token:
        raise SystemExit("No authtoken entered. Aborted.")
    added = run_ngrok(exe, "config", "add-authtoken", token)
    if added.returncode != 0:
        raise SystemExit("ngrok rejected the authtoken: " + (added.stderr or added.stdout).strip())
    say("Authtoken saved by ngrok.")


def ensure_domain(cli_domain: str | None) -> str:
    def clean(value: str) -> str:
        value = value.lstrip("\ufeff").strip().lower()  # tolerate a BOM from Notepad/PowerShell
        for prefix in ("https://", "http://"):
            if value.startswith(prefix):
                value = value[len(prefix):]
        return value.strip("/")

    if cli_domain:
        domain = clean(cli_domain)
    elif domain_path().is_file():
        domain = clean(domain_path().read_text(encoding="utf-8"))
    else:
        say("ngrok needs your free static domain (one time).")
        say("  Create it at https://dashboard.ngrok.com/domains  ->  'New Domain' (free: 1 per account)")
        domain = clean(input("Static domain (e.g. your-name.ngrok-free.app): "))
    if "." not in domain or " " in domain:
        raise SystemExit(f"'{domain}' does not look like a hostname.")
    domain_path().parent.mkdir(parents=True, exist_ok=True)
    domain_path().write_text(domain + "\n", encoding="utf-8")
    return domain


# ---------------------------------------------------------------------------
# Step 5-6: gateway, tunnel, self-tests
# ---------------------------------------------------------------------------
def http_get(url: str, token: str | None, timeout: float = 20.0) -> tuple[int, bytes]:
    headers = {"Accept": "application/json", "ngrok-skip-browser-warning": "1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_for_tunnel(domain: str, process: subprocess.Popen, timeout: float = 40.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SystemExit(f"ngrok exited early (code {process.returncode}). See the [ngrok] lines above.")
        try:
            status, body = http_get(NGROK_LOCAL_API, None, timeout=3)
            if status == 200:
                for tunnel in json.loads(body.decode("utf-8")).get("tunnels", []):
                    public = str(tunnel.get("public_url") or "")
                    if domain in public and public.startswith("https://"):
                        return public
        except Exception:  # noqa: BLE001 - agent API not up yet
            pass
        time.sleep(1.0)
    raise SystemExit("ngrok did not report the tunnel within 40 s.")


def pump_output(process: subprocess.Popen) -> None:
    assert process.stdout is not None
    for line in process.stdout:
        text = line.rstrip()
        if text:
            say(f"[ngrok] {text}")


def self_test(public_url: str, token: str, model: str) -> None:
    status, _ = http_get(public_url + "/api/tags", None)
    if status != 401:
        raise SystemExit(f"SECURITY CHECK FAILED: request without token returned {status}, expected 401. Stopping.")
    say("  no token  -> 401 (gateway auth works)")
    status, body = http_get(public_url + "/api/tags", token)
    if status != 200:
        raise SystemExit(f"Public check failed: /api/tags with token returned {status}.")
    names = [m.get("name") for m in json.loads(body.decode("utf-8")).get("models", [])]
    if not any(str(n).lower().startswith(model.lower()) for n in names):
        raise SystemExit(f"Public check: Ollama answered but {model} is not in {names}.")
    say(f"  with token -> 200, model {model} visible through the tunnel")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Connect local Ollama to the Render-hosted LogSentinel chat.")
    parser.add_argument("--domain", help="ngrok static domain (saved for next time)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("OLLAMA_GATEWAY_PORT") or DEFAULT_PORT))
    parser.add_argument("--show-token", action="store_true", help="print the gateway token again")
    parser.add_argument("--yes", action="store_true", help="do not ask before downloading ngrok")
    args = parser.parse_args(argv)

    say("LogSentinel - connect local Ollama to Render")
    say("=" * 44)

    say("[1/5] Checking local Ollama ...")
    base_url, model = ensure_ollama()
    say(f"      Ollama OK at {base_url}, model {model}")

    say("[2/5] Gateway token ...")
    token, created = load_or_create_token()
    if created or args.show_token:
        say("      Copy this value into Render as OLLAMA_AUTH_TOKEN (shown only now / with --show-token):")
        say(f"      {token}")
    else:
        say(f"      Using the existing token stored at {default_token_path()} (run with --show-token to display it).")

    say("[3/5] ngrok ...")
    exe = find_ngrok() or download_ngrok(assume_yes=args.yes)
    ensure_authtoken(exe)
    domain = ensure_domain(args.domain)
    say(f"      Static domain: {domain}")

    say(f"[4/5] Starting gateway on 127.0.0.1:{args.port} (Ollama on 11434 stays local) ...")
    server = make_server(token, port=args.port, quiet=False)
    serve_in_thread(server)
    status, _ = http_get(f"http://127.0.0.1:{args.port}/api/tags", token, timeout=20)
    if status != 200:
        server.shutdown()
        raise SystemExit(f"Local gateway check failed with HTTP {status}.")

    say("      Starting tunnel ...")
    process = subprocess.Popen(
        [exe, "http", f"--url=https://{domain}", f"127.0.0.1:{args.port}", "--log=stdout", "--log-level=warn"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    threading.Thread(target=pump_output, args=(process,), daemon=True).start()
    try:
        public_url = wait_for_tunnel(domain, process)
        say(f"[5/5] Self-test through {public_url} ...")
        self_test(public_url, token, model)
        say("")
        say("CONNECTED. Render environment variables (Dashboard -> your service -> Environment):")
        say(f"  OLLAMA_BASE_URL   = {public_url}")
        say(f"  OLLAMA_AUTH_TOKEN = {'(the value printed above)' if (created or args.show_token) else '(token in ' + str(default_token_path()) + ')'}")
        say("  AI_PROVIDER       = ollama      OLLAMA_MODEL = " + model)
        say(f"Then open {RENDER_URL}, sign in, open SentinelAI: status should read 'Local - {model}'.")
        say("Keep this window open. Press Ctrl+C to disconnect.")
        while process.poll() is None:
            time.sleep(1.0)
        say(f"ngrok stopped (code {process.returncode}).")
        return 1
    except KeyboardInterrupt:
        say("\nDisconnecting ...")
        return 0
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())

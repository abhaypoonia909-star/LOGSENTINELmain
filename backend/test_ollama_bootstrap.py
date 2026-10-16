"""Dev-only Ollama autostart (utils/ollama_bootstrap.py). No real process is started.

Run alone: python -m unittest test_ollama_bootstrap.py
"""
import os
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("JWT_SECRET", "bootstrap-test-secret-32-bytes-xxxx")
os.environ.setdefault("SECRET_KEY", "bootstrap-test-secret-32-bytes-xxxx")
os.environ["AI_PROVIDER"] = "ollama"

from services.ollama_client import OllamaUnavailable  # noqa: E402
from utils import ollama_bootstrap as boot  # noqa: E402

ENV_NAMES = (
    "AI_PROVIDER", "OLLAMA_BASE_URL", "OLLAMA_MODEL", "OLLAMA_HOST",
    "OLLAMA_AUTOSTART", "OLLAMA_AUTOSTART_WAIT_SECONDS",
    "LOGSENTINEL_ENV", "FLASK_ENV", "RAILWAY_ENVIRONMENT", "RENDER",
)


class FakeClient:
    """Answers /api/tags only after `down_for` polls (None = never)."""

    def __init__(self, models=("llama3.2:1b",), down_for=0):
        self.models = list(models)
        self.down_for = down_for
        self.calls = 0

    def installed_models(self):
        self.calls += 1
        if self.down_for is None or self.calls <= self.down_for:
            raise OllamaUnavailable("connection refused")
        return list(self.models)

    def warmup(self, model, keep_alive="60m"):
        return None


class Clock:
    def __init__(self):
        self.now = 0.0

    def sleep(self, seconds):
        self.now += seconds

    def monotonic(self):
        return self.now


class OllamaBootstrapTests(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ENV_NAMES}
        for k in ENV_NAMES:
            os.environ.pop(k, None)
        os.environ["AI_PROVIDER"] = "ollama"
        self.launched = []
        self.launcher = lambda exe: self.launched.append(exe)
        self.find_exe = lambda: r"C:\Users\me\AppData\Local\Programs\Ollama\ollama.exe"
        self.clock = Clock()
        boot_mod = boot
        self._warmup = mock.patch("services.ai_service._schedule_ollama_warmup")
        self.warmup = self._warmup.start()
        self.boot_mod = boot_mod

    def tearDown(self):
        self._warmup.stop()
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _run(self, client, **kw):
        kw.setdefault("launcher", self.launcher)
        kw.setdefault("find_executable", self.find_exe)
        kw.setdefault("sleep", self.clock.sleep)
        kw.setdefault("monotonic", self.clock.monotonic)
        with mock.patch("builtins.print"):
            return boot.ensure_local_ollama(client=client, **kw)

    # ---- already running ---------------------------------------------------
    def test_running_with_model_does_not_launch_and_warms_up(self):
        client = FakeClient()
        result = self._run(client)
        self.assertEqual(result["status"], "running")
        self.assertTrue(result["model_ready"])
        self.assertEqual(result["base_url"], "http://127.0.0.1:11434")
        self.assertEqual(result["model"], "llama3.2:1b")
        self.assertEqual(self.launched, [])
        self.warmup.assert_called_once()

    def test_running_without_model_reports_pull_command_but_never_pulls(self):
        client = FakeClient(models=["qwen:0.5b"])
        with mock.patch("builtins.print") as printed:
            result = boot.ensure_local_ollama(client=client, launcher=self.launcher,
                                              find_executable=self.find_exe,
                                              sleep=self.clock.sleep, monotonic=self.clock.monotonic)
        self.assertEqual(result["status"], "running")
        self.assertFalse(result["model_ready"])
        self.assertEqual(self.launched, [])
        text = " ".join(str(c.args[0]) for c in printed.call_args_list)
        self.assertIn("ollama pull llama3.2:1b", text)
        self.assertIn("not done automatically", text)

    # ---- needs starting ----------------------------------------------------
    def test_not_running_starts_installed_binary_and_waits_until_ready(self):
        client = FakeClient(down_for=3)
        result = self._run(client)
        self.assertEqual(result["status"], "started")
        self.assertTrue(result["model_ready"])
        self.assertEqual(self.launched, [self.find_exe()])
        self.assertGreaterEqual(client.calls, 4)
        self.warmup.assert_called_once()

    def test_timeout_when_api_never_answers(self):
        os.environ["OLLAMA_AUTOSTART_WAIT_SECONDS"] = "3"
        client = FakeClient(down_for=None)
        result = self._run(client)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(len(self.launched), 1)
        self.assertLessEqual(self.clock.now, 3.6)

    def test_missing_executable_is_reported_not_installed(self):
        client = FakeClient(down_for=None)
        result = self._run(client, find_executable=lambda: None)
        self.assertEqual(result["status"], "no_executable")
        self.assertEqual(self.launched, [])

    def test_launcher_failure_does_not_raise(self):
        def boom(exe):
            raise OSError("access denied")
        client = FakeClient(down_for=None)
        result = self._run(client, launcher=boom)
        self.assertEqual(result["status"], "start_failed")

    # ---- safety skips --------------------------------------------------------
    def test_skipped_in_production_render(self):
        os.environ["RENDER"] = "true"
        client = FakeClient(down_for=None)
        result = self._run(client)
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.launched, [])
        self.assertEqual(client.calls, 0)

    def test_skipped_when_logsentinel_env_production(self):
        os.environ["LOGSENTINEL_ENV"] = "production"
        result = self._run(FakeClient(down_for=None))
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.launched, [])

    def test_skipped_for_remote_base_url(self):
        os.environ["OLLAMA_BASE_URL"] = "https://ollama.example.net"
        result = self._run(FakeClient(down_for=None))
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.launched, [])

    def test_skipped_when_disabled(self):
        os.environ["OLLAMA_AUTOSTART"] = "0"
        result = self._run(FakeClient(down_for=None))
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(self.launched, [])

    def test_skipped_for_openai_provider(self):
        os.environ["AI_PROVIDER"] = "openai"
        result = self._run(FakeClient(down_for=None))
        self.assertEqual(result["status"], "skipped")

    def test_refuses_to_start_when_ollama_host_is_public(self):
        os.environ["OLLAMA_HOST"] = "0.0.0.0:11434"
        result = self._run(FakeClient(down_for=None))
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "unsafe OLLAMA_HOST")
        self.assertEqual(self.launched, [])

    def test_loopback_ollama_host_is_allowed(self):
        os.environ["OLLAMA_HOST"] = "127.0.0.1:11434"
        result = self._run(FakeClient(down_for=1))
        self.assertEqual(result["status"], "started")

    # ---- helpers / wiring ------------------------------------------------------
    def test_loopback_detection(self):
        self.assertTrue(boot._is_loopback_url("http://127.0.0.1:11434"))
        self.assertTrue(boot._is_loopback_url("http://localhost:11434"))
        self.assertFalse(boot._is_loopback_url("http://192.168.1.5:11434"))
        self.assertFalse(boot._is_loopback_url("https://host.example"))

    def test_default_launcher_runs_serve_detached_without_window(self):
        with mock.patch("subprocess.Popen") as popen:
            boot._default_launcher(r"C:\x\ollama.exe")
        args, kwargs = popen.call_args
        self.assertEqual(args[0], [r"C:\x\ollama.exe", "serve"])
        self.assertIs(kwargs["stdout"], boot.subprocess.DEVNULL)
        if boot.sys.platform.startswith("win"):
            self.assertTrue(kwargs["creationflags"] & boot.subprocess.CREATE_NO_WINDOW)
            self.assertTrue(kwargs["creationflags"] & boot.subprocess.DETACHED_PROCESS)

    def test_app_wires_bootstrap_only_into_dev_main_block(self):
        source = (Path(__file__).resolve().parent / "app.py").read_text(encoding="utf-8")
        main_idx = source.index('if __name__ == "__main__":')
        self.assertIn("start_background_bootstrap()", source[main_idx:])
        self.assertNotIn("ollama_bootstrap", source[:main_idx])
        procfile = (Path(__file__).resolve().parent / "Procfile").read_text(encoding="utf-8")
        self.assertIn("gunicorn", procfile)  # Render never executes the __main__ block


if __name__ == "__main__":
    unittest.main()

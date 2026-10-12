"""Defaults and .env load order. Does not import Flask app."""
import os
import unittest
from pathlib import Path

from utils.ollama_settings import (
    DEFAULT_OLLAMA_KEEP_ALIVE,
    DEFAULT_OLLAMA_NUM_CTX,
    DEFAULT_OLLAMA_NUM_PREDICT,
    DEFAULT_OLLAMA_TIMEOUT_SECONDS,
    ollama_runtime_settings,
)


OLLAMA_ENV = (
    "OLLAMA_BASE_URL",
    "OLLAMA_MODEL",
    "OLLAMA_TIMEOUT_SECONDS",
    "OLLAMA_KEEP_ALIVE",
    "OLLAMA_TEMPERATURE",
    "OLLAMA_NUM_CTX",
    "OLLAMA_NUM_PREDICT",
    "OLLAMA_NUM_PREDICT_SHORT",
    "OLLAMA_NUM_PREDICT_ANALYSIS",
    "OLLAMA_NUM_PREDICT_LONG",
)


class OllamaDefaultTests(unittest.TestCase):
    def setUp(self):
        self._saved = {name: os.environ.get(name) for name in OLLAMA_ENV}
        for name in OLLAMA_ENV:
            os.environ.pop(name, None)

    def tearDown(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def test_runtime_defaults_when_env_is_unset(self):
        _base, model, timeout, options = ollama_runtime_settings()
        self.assertEqual(model, "llama3.2:1b")
        self.assertEqual(timeout, 60.0)
        self.assertEqual(options["num_ctx"], 1024)
        self.assertEqual(options["num_predict"], 80)
        self.assertEqual(options["keep_alive"], "60m")
        self.assertEqual(DEFAULT_OLLAMA_TIMEOUT_SECONDS, 60)
        self.assertEqual(DEFAULT_OLLAMA_NUM_CTX, 1024)
        self.assertEqual(DEFAULT_OLLAMA_NUM_PREDICT, 80)
        self.assertEqual(DEFAULT_OLLAMA_KEEP_ALIVE, "60m")

    def test_env_overrides_are_applied(self):
        os.environ["OLLAMA_TIMEOUT_SECONDS"] = "90"
        os.environ["OLLAMA_NUM_CTX"] = "768"
        os.environ["OLLAMA_KEEP_ALIVE"] = "30m"
        _base, _model, timeout, options = ollama_runtime_settings()
        self.assertEqual(timeout, 90.0)
        self.assertEqual(options["num_ctx"], 768)
        self.assertEqual(options["keep_alive"], "30m")


class EnvLoadOrderTests(unittest.TestCase):
    def test_config_loads_root_then_backend_override(self):
        text = (Path(__file__).resolve().parent / "config.py").read_text(encoding="utf-8")
        root = text.find('load_dotenv(BASE_DIR.parent / ".env")')
        backend = text.find('load_dotenv(BASE_DIR / ".env", override=True)')
        self.assertNotEqual(root, -1)
        self.assertNotEqual(backend, -1)
        self.assertLess(root, backend)

    def test_example_env_describes_the_same_order(self):
        example = (Path(__file__).resolve().parents[1] / ".env.example").read_text(encoding="utf-8")
        self.assertIn("project-root .env", example)
        self.assertIn("backend/.env", example)
        self.assertIn("override=True", example)
        self.assertIn("BRUTE_FORCE_THRESHOLD=2", example)
        self.assertIn("OLLAMA_NUM_CTX=1024", example)
        self.assertIn("OLLAMA_NUM_PREDICT=80", example)
        self.assertIn("OLLAMA_KEEP_ALIVE=60m", example)
        self.assertIn("OLLAMA_TIMEOUT_SECONDS=60", example)


class DatabaseUriTests(unittest.TestCase):
    def test_empty_and_unset_keep_local_sqlite(self):
        from config import BASE_DIR, resolve_database_uri

        expected = f"sqlite:///{BASE_DIR / 'logsentinel.db'}"
        self.assertEqual(resolve_database_uri(""), expected)
        self.assertEqual(resolve_database_uri("   "), expected)

    def test_render_postgres_scheme_is_rewritten(self):
        from config import resolve_database_uri

        raw = "postgres://user:pass@dpg-host/logsentinel"
        self.assertEqual(
            resolve_database_uri(raw),
            "postgresql://user:pass@dpg-host/logsentinel",
        )

    def test_postgresql_and_sqlite_urls_are_unchanged(self):
        from config import resolve_database_uri

        pg = "postgresql://user:pass@dpg-host/logsentinel?sslmode=require"
        self.assertEqual(resolve_database_uri(pg), pg)
        sqlite = "sqlite:///C:/tmp/logsentinel.db"
        self.assertEqual(resolve_database_uri(sqlite), sqlite)

    def test_procfile_and_postgres_driver_are_present(self):
        backend = Path(__file__).resolve().parent
        procfile = (backend / "Procfile").read_text(encoding="utf-8")
        self.assertIn(
            "gunicorn --bind 0.0.0.0:$PORT --workers 1 --timeout 120 app:app",
            procfile,
        )
        requirements = (backend / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("psycopg2-binary", requirements)
        self.assertIn("gunicorn", requirements)


class LogThresholdHelperTests(unittest.TestCase):
    def test_invalid_env_keeps_default_two(self):
        from services.log_analyzer import log_brute_force_threshold

        saved = os.environ.get("BRUTE_FORCE_THRESHOLD")
        try:
            os.environ["BRUTE_FORCE_THRESHOLD"] = "not-a-number"
            self.assertEqual(log_brute_force_threshold(), 2)
        finally:
            if saved is None:
                os.environ.pop("BRUTE_FORCE_THRESHOLD", None)
            else:
                os.environ["BRUTE_FORCE_THRESHOLD"] = saved


if __name__ == "__main__":
    unittest.main()

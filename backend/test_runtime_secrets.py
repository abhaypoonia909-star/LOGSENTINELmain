"""Production signing-secret refusal and safer Flask defaults."""
import os
import unittest
from pathlib import Path

from utils.runtime_secrets import (
    PLACEHOLDER_SECRET,
    assert_secure_secrets,
    configured_signing_secret,
    is_production_environment,
    signing_secret_is_insecure,
)


class RuntimeSecretsTests(unittest.TestCase):
    def setUp(self):
        self._saved = {
            name: os.environ.get(name)
            for name in (
                "LOGSENTINEL_ENV",
                "FLASK_ENV",
                "RAILWAY_ENVIRONMENT",
                "RENDER",
                "JWT_SECRET",
                "SECRET_KEY",
            )
        }

    def tearDown(self):
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def _clear_prod_flags(self):
        for name in ("LOGSENTINEL_ENV", "FLASK_ENV", "RAILWAY_ENVIRONMENT", "RENDER"):
            os.environ.pop(name, None)

    def test_local_demo_may_use_placeholder_with_warning_path_only(self):
        self._clear_prod_flags()
        os.environ.pop("JWT_SECRET", None)
        os.environ.pop("SECRET_KEY", None)
        self.assertFalse(is_production_environment())
        self.assertTrue(signing_secret_is_insecure())
        assert_secure_secrets()

    def test_production_refuses_missing_and_placeholder_secrets(self):
        os.environ["LOGSENTINEL_ENV"] = "production"
        os.environ.pop("JWT_SECRET", None)
        os.environ.pop("SECRET_KEY", None)
        self.assertTrue(is_production_environment())
        self.assertTrue(signing_secret_is_insecure())
        with self.assertRaises(RuntimeError) as ctx:
            assert_secure_secrets()
        self.assertIn("change-me-in-production", str(ctx.exception))

        os.environ["JWT_SECRET"] = PLACEHOLDER_SECRET
        with self.assertRaises(RuntimeError):
            assert_secure_secrets()

        os.environ["JWT_SECRET"] = "short-key"
        with self.assertRaises(RuntimeError):
            assert_secure_secrets()

    def test_production_accepts_a_long_random_secret(self):
        os.environ["LOGSENTINEL_ENV"] = "prod"
        os.environ["JWT_SECRET"] = "classroom-eval-secret-32b"
        self.assertFalse(signing_secret_is_insecure())
        self.assertEqual(configured_signing_secret(), "classroom-eval-secret-32b")
        assert_secure_secrets()

    def test_flask_env_and_railway_also_count_as_production(self):
        self._clear_prod_flags()
        os.environ["FLASK_ENV"] = "production"
        os.environ.pop("JWT_SECRET", None)
        os.environ.pop("SECRET_KEY", None)
        with self.assertRaises(RuntimeError):
            assert_secure_secrets()

        os.environ.pop("FLASK_ENV", None)
        os.environ["RAILWAY_ENVIRONMENT"] = "production"
        with self.assertRaises(RuntimeError):
            assert_secure_secrets()

    def test_render_true_refuses_placeholder_secret(self):
        self._clear_prod_flags()
        os.environ["RENDER"] = "true"
        os.environ.pop("JWT_SECRET", None)
        os.environ.pop("SECRET_KEY", None)
        self.assertTrue(is_production_environment())
        with self.assertRaises(RuntimeError):
            assert_secure_secrets()

        os.environ["JWT_SECRET"] = "classroom-eval-secret-32b"
        assert_secure_secrets()

    def test_app_run_defaults_are_localhost_without_debug(self):
        text = (Path(__file__).resolve().parent / "app.py").read_text(encoding="utf-8")
        self.assertIn("assert_secure_secrets()", text)
        self.assertNotIn('app.run(host="0.0.0.0", port=5000, debug=True)', text)
        self.assertIn('or "127.0.0.1"', text)
        self.assertIn("FLASK_DEBUG", text)
        self.assertIn("debug=debug", text)


if __name__ == "__main__":
    unittest.main()

"""Runner exit codes and brute-force answer matching. Does not import Flask."""
import io
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from check_runner import CheckRunner, normalize_answer_text, refers_to_brute_force_activity

BACKEND = Path(__file__).resolve().parent


def _run_fixture(script: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(BACKEND) + (os.pathsep + existing if existing else "")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "runner_fixture.py"
        path.write_text(script, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(path)],
            cwd=str(BACKEND),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )


class BruteForceAnswerTests(unittest.TestCase):
    def test_accepts_harmless_spelling_differences(self):
        positives = (
            "A brute force attack guesses passwords.",
            "Brute-force attacks repeatedly guess credentials.",
            "BRUTE_FORCE  attack  on  login",
            "A brute-force attempt cracks authentication.",
        )
        for answer in positives:
            self.assertTrue(refers_to_brute_force_activity(answer), msg=answer)

    def test_rejects_unrelated_or_empty_replies(self):
        negatives = (
            "",
            "Hello, how can I help you today?",
            "The brute force of the river flooded the bank.",
            "Force is used in physics.",
        )
        for answer in negatives:
            self.assertFalse(refers_to_brute_force_activity(answer), msg=answer)

    def test_normalize_collapses_hyphens_and_spaces(self):
        self.assertEqual(normalize_answer_text("Brute-Force"), "brute force")
        self.assertEqual(normalize_answer_text("  brute   force  "), "brute force")


class CheckRunnerExitTests(unittest.TestCase):
    def test_counts_are_reported_separately(self):
        runner = CheckRunner()
        runner.check("ok", True)
        runner.check("bad", False, "reason")
        runner.error("boom", "explode")
        runner.skip("later", "not run")
        buf = io.StringIO()
        code = runner.summarize(stream=buf)
        text = buf.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("PASSED: 1    FAILED: 1    ERRORS: 1    SKIPPED: 1", text)
        self.assertIn("FAILURES:", text)
        self.assertIn("ERRORS:", text)
        self.assertIn("SKIPPED:", text)

    def test_success_exits_zero_and_skip_is_not_failure(self):
        runner = CheckRunner()
        runner.check("ok", True)
        runner.skip("optional", "ollama not required here")
        self.assertEqual(runner.exit_code(), 0)
        self.assertEqual(len(runner.skipped), 1)

    def test_check_exception_is_error_not_pass(self):
        runner = CheckRunner()

        def boom():
            raise RuntimeError("cannot evaluate")

        self.assertFalse(runner.check("broken", boom))
        self.assertEqual(runner.passed, [])
        self.assertEqual(len(runner.errors), 1)
        self.assertEqual(runner.exit_code(), 1)

    def test_failing_fixture_process_exits_nonzero(self):
        script = textwrap.dedent(
            """
            from check_runner import CheckRunner
            runner = CheckRunner()
            runner.check("intentional fail", False, "safe fixture")
            raise SystemExit(runner.summarize())
            """
        )
        result = _run_fixture(script)
        self.assertEqual(result.returncode, 1, msg=result.stdout + result.stderr)
        self.assertIn("FAILED: 1", result.stdout)
        self.assertIn("intentional fail", result.stdout)

    def test_passing_fixture_process_exits_zero(self):
        script = textwrap.dedent(
            """
            from check_runner import CheckRunner
            runner = CheckRunner()
            runner.check("intentional pass", True)
            runner.skip("unused", "not a failure")
            raise SystemExit(runner.summarize())
            """
        )
        result = _run_fixture(script)
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)
        self.assertIn("PASSED: 1", result.stdout)
        self.assertIn("SKIPPED: 1", result.stdout)


if __name__ == "__main__":
    unittest.main()

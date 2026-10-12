"""Shared helpers for the custom test_auth runner.

This module is stdlib-only so runner tests can import it without Flask or Config.
"""

from __future__ import annotations

import re
import sys
from typing import Any

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_BRUTE_FORCE_CLUES = (
    "attack",
    "password",
    "credential",
    "login",
    "guess",
    "crack",
    "auth",
    "attempt",
)


def normalize_answer_text(text: str) -> str:
    """Lowercase and collapse punctuation, hyphens, and whitespace to spaces."""
    return " ".join(_NON_ALNUM.sub(" ", (text or "").lower()).split())


def refers_to_brute_force_activity(answer: str) -> bool:
    """True when the reply discusses brute-force activity, not one exact spelling.

    Accepts 'brute force', 'brute-force', 'Brute_Force', extra spaces, and
    similar harmless punctuation. Requires an attack/credential clue so a
    generic sentence is not treated as a pass.
    """
    normalized = normalize_answer_text(answer)
    if not normalized:
        return False
    collapsed = normalized.replace(" ", "")
    if "bruteforce" not in collapsed:
        return False
    return any(clue in collapsed for clue in _BRUTE_FORCE_CLUES)


class CheckRunner:
    """Record PASS / FAIL / ERROR / SKIP and choose a process exit code."""

    def __init__(self) -> None:
        self.passed: list[str] = []
        self.failed: list[tuple[str, str]] = []
        self.errors: list[tuple[str, str]] = []
        self.skipped: list[tuple[str, str]] = []

    def check(self, name: str, cond: Any, detail: Any = "") -> bool:
        try:
            ok = bool(cond() if callable(cond) else cond)
        except Exception as exc:
            self.error(name, exc)
            return False
        if ok:
            self.passed.append(name)
            print("  PASS  " + name)
            return True
        text = "" if detail in ("", None) else str(detail)
        self.failed.append((name, text))
        suffix = (" -> " + text) if text else ""
        print("  FAIL  " + name + suffix)
        return False

    def skip(self, name: str, reason: Any = "") -> None:
        text = "" if reason in ("", None) else str(reason)
        self.skipped.append((name, text))
        suffix = (" -> " + text) if text else ""
        print("  SKIP  " + name + suffix)

    def error(self, name: str, detail: Any = "") -> None:
        text = str(detail)
        self.errors.append((name, text))
        suffix = (" -> " + text) if text else ""
        print("  ERROR " + name + suffix)

    def exit_code(self) -> int:
        if self.failed or self.errors:
            return 1
        return 0

    def summarize(self, stream=None) -> int:
        out = stream or sys.stdout
        out.write(
            "\n"
            + "=" * 62
            + "\n"
            + "PASSED: %d    FAILED: %d    ERRORS: %d    SKIPPED: %d\n"
            % (len(self.passed), len(self.failed), len(self.errors), len(self.skipped))
        )
        if self.failed:
            out.write("FAILURES:\n")
            for name, detail in self.failed:
                line = "   - " + name
                if detail:
                    line += " -> " + detail
                out.write(line + "\n")
        if self.errors:
            out.write("ERRORS:\n")
            for name, detail in self.errors:
                line = "   - " + name
                if detail:
                    line += " -> " + detail
                out.write(line + "\n")
        if self.skipped:
            out.write("SKIPPED:\n")
            for name, reason in self.skipped:
                line = "   - " + name
                if reason:
                    line += " -> " + reason
                out.write(line + "\n")
        out.write("=" * 62 + "\n")
        return self.exit_code()

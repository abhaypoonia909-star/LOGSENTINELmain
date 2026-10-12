"""SQL script pattern scanner for dynamic-SQL anti-patterns."""

from __future__ import annotations

from services.sast_engine import apply_rules

RULES = [
    {
        "type": "SQL Injection",
        "pattern": r"(?i)\bEXEC(?:UTE)?\s*\(",
        "severity": "High",
        "description": "Dynamic EXEC/EXECUTE can run concatenated SQL.",
        "recommendation": "Use parameterized statements from the application instead of EXEC of a string.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
    {
        "type": "SQL Injection",
        "pattern": r"(?i)\bEXEC(?:UTE)?\s+@",
        "severity": "High",
        "description": "EXEC of a variable often means dynamically built SQL.",
        "recommendation": "Keep SQL static and pass values as parameters.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
    {
        "type": "SQL Injection",
        "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+",
        "severity": "Medium",
        "description": "SQL text appears concatenated with '+'.",
        "recommendation": "Use bind parameters; do not assemble statements from user text.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
]


class SQLScanner:
    def scan(self, content: str, filename: str = "unknown.sql"):
        return apply_rules(content, filename, RULES)

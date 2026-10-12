"""PHP source code vulnerability scanner."""

from __future__ import annotations

import re

from services.security_models import VulnerabilityFinding


RULES = [
    {
        "type": "SQL Injection",
        "pattern": r"\bmysql_query\s*\(",
        "severity": "Critical",
        "description": "Deprecated mysql_query() often used with unsafe concatenation.",
        "recommendation": "Use PDO or mysqli with prepared statements.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
    {
        "type": "Command Injection",
        "pattern": r"\bshell_exec\s*\(",
        "severity": "Critical",
        "description": "shell_exec() executes system commands.",
        "recommendation": "Avoid shell execution; use safe PHP APIs.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "Command Injection",
        "pattern": r"\b(exec|system|passthru|popen)\s*\(",
        "severity": "Critical",
        "description": "Dangerous command execution function detected.",
        "recommendation": "Remove shell calls or strictly validate input.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "Insecure Deserialization",
        "pattern": r"\bunserialize\s*\(",
        "severity": "Critical",
        "description": "unserialize() on untrusted data enables object injection.",
        "recommendation": "Use JSON; never unserialize user input.",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-502",
    },
    {
        "type": "SQL Injection",
        "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\$_(GET|POST|REQUEST)",
        "severity": "Critical",
        "description": "Direct superglobal used in SQL statement.",
        "recommendation": "Use prepared statements with bound parameters.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
    {
        "type": "SQL Injection",
        "pattern": r"(?i)(SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\.\s*\$",
        "severity": "Critical",
        "description": "SQL query built via string concatenation with variables.",
        "recommendation": "Use parameterized queries via PDO/mysqli.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "pattern": r"echo\s+\$_(GET|POST|REQUEST)",
        "severity": "High",
        "description": "User input echoed without encoding.",
        "recommendation": "Use htmlspecialchars() with ENT_QUOTES.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
    },
    {
        "type": "Path Traversal",
        "pattern": r"\b(include|require|include_once|require_once|fopen|file_get_contents)\s*\(?\s*\$_(GET|POST|REQUEST|FILES)",
        "severity": "Critical",
        "description": "A filesystem or include path is taken from a superglobal.",
        "recommendation": "Map request values to an allowlist of files.",
        "owasp": "A01:2021 – Broken Access Control",
        "cwe": "CWE-22",
    },
    {
        "type": "Insecure File Upload",
        "pattern": r"\bmove_uploaded_file\s*\(",
        "severity": "High",
        "description": "Uploaded file is moved; destination must not trust the client name.",
        "recommendation": "Generate a random stored name and allowlist MIME/extension.",
        "owasp": "A04:2021 – Insecure Design",
        "cwe": "CWE-434",
    },
    {
        "type": "SSRF",
        "pattern": r"\bfile_get_contents\s*\(\s*['\"]https?://",
        "severity": "Medium",
        "description": "Server-side HTTP fetch via file_get_contents.",
        "recommendation": "Allowlist destinations; do not concatenate request data into the URL.",
        "owasp": "A10:2021 – Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
    },
]


class PHPScanner:
    def scan(self, content: str, filename: str = "unknown.php") -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for rule in RULES:
                if re.search(rule["pattern"], line):
                    findings.append(VulnerabilityFinding(
                        line=line_no,
                        severity=rule["severity"],
                        type=rule["type"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        owasp=rule["owasp"],
                        cwe=rule["cwe"],
                        file=filename,
                        snippet=line.strip()[:200],
                    ))
        return findings
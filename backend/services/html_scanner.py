"""HTML template vulnerability scanner."""

from __future__ import annotations

import re

from services.security_models import VulnerabilityFinding


RULES = [
    {
        "type": "Cross-Site Scripting (XSS)",
        "pattern": r"<script[^>]*>.*?</script>",
        "severity": "Medium",
        "description": "Inline JavaScript block detected.",
        "recommendation": "Move scripts to external files and enforce CSP.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "pattern": r"\bon(click|load|error|mouseover)\s*=",
        "severity": "High",
        "description": "Inline event handler can enable XSS.",
        "recommendation": "Use addEventListener in external JS files.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
    },
    {
        "type": "Insecure Form",
        "pattern": r"<form[^>]+action\s*=\s*['\"]http://",
        "severity": "Medium",
        "description": "Form submits credentials over insecure HTTP.",
        "recommendation": "Use HTTPS action URLs for all forms.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-319",
    },
    {
        "type": "Insecure External Script",
        "pattern": r"<script[^>]+src\s*=\s*['\"]http://",
        "severity": "Medium",
        "description": "External script loaded over HTTP (MITM risk).",
        "recommendation": "Load scripts over HTTPS and use SRI hashes.",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-829",
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "pattern": r"javascript:",
        "severity": "High",
        "description": "javascript: URI scheme detected.",
        "recommendation": "Remove javascript: URIs; use safe event handlers.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
    },
]


class HTMLScanner:
    def scan(self, content: str, filename: str = "unknown.html"):
        findings: list[VulnerabilityFinding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for rule in RULES:
                if re.search(rule["pattern"], line, re.IGNORECASE):
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
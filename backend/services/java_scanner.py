"""Java source pattern scanner. Regex only; not a full compiler frontend."""

from __future__ import annotations

from services.sast_engine import apply_rules

RULES = [
    {
        "type": "Command Injection",
        "pattern": r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(",
        "severity": "Critical",
        "description": "Runtime.exec() runs an OS command.",
        "recommendation": "Use ProcessBuilder with a fixed argument list.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "Command Injection",
        "pattern": r"\bnew\s+ProcessBuilder\s*\([^)]*\+",
        "severity": "Critical",
        "description": "ProcessBuilder is constructed with string concatenation.",
        "recommendation": "Pass a constant executable and allowlisted arguments.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "SQL Injection",
        "pattern": r"(?i)(executeQuery|executeUpdate|createStatement|prepareStatement)\s*\([^)]*\+",
        "severity": "Critical",
        "description": "SQL is built with string concatenation.",
        "recommendation": "Use a PreparedStatement with placeholders.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
    {
        "type": "Insecure Deserialization",
        "pattern": r"\bObjectInputStream\b|\.readObject\s*\(",
        "severity": "Critical",
        "description": "Java object deserialization can instantiate unexpected classes.",
        "recommendation": "Do not deserialize untrusted bytes; prefer a constrained format.",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-502",
    },
    {
        "type": "Hardcoded Credentials",
        "pattern": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]",
        "severity": "High",
        "description": "Hardcoded password detected in Java source.",
        "recommendation": "Load secrets from the environment or a vault.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-798",
    },
    {
        "type": "Weak Cryptography",
        "pattern": r'(?i)getInstance\s*\(\s*"(MD5|SHA-1|DES|RC4)"',
        "severity": "Medium",
        "description": "A weak or deprecated cryptographic algorithm is requested.",
        "recommendation": "Use SHA-256 or AES-GCM as appropriate.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-327",
    },
    {
        "type": "Insecure Randomness",
        "pattern": r"(?i)(password|token|secret|otp|session).{0,40}new\s+Random\s*\(",
        "severity": "Medium",
        "description": "java.util.Random used near a security-sensitive name.",
        "recommendation": "Use SecureRandom for tokens and keys.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-330",
    },
    {
        "type": "Path Traversal",
        "pattern": r"\bnew\s+File\s*\([^)]*\+",
        "severity": "High",
        "description": "File path is concatenated, which may allow '..' segments.",
        "recommendation": "Resolve against a fixed directory and reject parent segments.",
        "owasp": "A01:2021 – Broken Access Control",
        "cwe": "CWE-22",
    },
]


class JavaScanner:
    def scan(self, content: str, filename: str = "unknown.java"):
        return apply_rules(content, filename, RULES)

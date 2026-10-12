"""C# source pattern scanner. Regex only; not Roslyn."""

from __future__ import annotations

from services.sast_engine import apply_rules

RULES = [
    {
        "type": "Command Injection",
        "pattern": r"\bProcess\.Start\s*\([^)]*\+",
        "severity": "Critical",
        "description": "Process.Start is called with a concatenated command string.",
        "recommendation": "Set FileName and Arguments separately with UseShellExecute = false.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
    },
    {
        "type": "SQL Injection",
        "pattern": r"(?i)(SqlCommand|ExecuteReader|ExecuteNonQuery)\s*\([^)]*\+",
        "severity": "Critical",
        "description": "SQL command text is concatenated.",
        "recommendation": "Use parameterized SqlCommand values.",
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
    },
    {
        "type": "Insecure Deserialization",
        "pattern": r"\bBinaryFormatter\b|\.Deserialize\s*\(",
        "severity": "Critical",
        "description": "BinaryFormatter / Deserialize can instantiate unexpected types.",
        "recommendation": "Use a constrained serializer such as System.Text.Json.",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "cwe": "CWE-502",
    },
    {
        "type": "Hardcoded Credentials",
        "pattern": r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]",
        "severity": "High",
        "description": "Hardcoded password detected in C# source.",
        "recommendation": "Load secrets from configuration that is not in source control.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-798",
    },
    {
        "type": "Insecure Randomness",
        "pattern": r"(?i)(password|token|secret|otp|session).{0,40}new\s+Random\s*\(",
        "severity": "Medium",
        "description": "System.Random used near a security-sensitive name.",
        "recommendation": "Use RandomNumberGenerator for tokens and keys.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-330",
    },
    {
        "type": "Path Traversal",
        "pattern": r"\bFile\.(ReadAllText|Open|WriteAllText|Copy)\s*\([^)]*\+",
        "severity": "High",
        "description": "File API path is concatenated.",
        "recommendation": "Resolve against a fixed root and reject '..' segments.",
        "owasp": "A01:2021 – Broken Access Control",
        "cwe": "CWE-22",
    },
]


class CSharpScanner:
    def scan(self, content: str, filename: str = "unknown.cs"):
        return apply_rules(content, filename, RULES)

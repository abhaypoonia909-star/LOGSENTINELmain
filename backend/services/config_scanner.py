"""Configuration and manifest pattern scanner. Not a CVE database."""

from __future__ import annotations

import json
import re
from pathlib import Path

from services.sast_engine import apply_rules
from services.security_models import VulnerabilityFinding

RULES = [
    {
        "type": "Hardcoded Credentials",
        "pattern": r"(?i)(password|passwd|pwd|secret|api[_-]?key|token|jwt_secret)\s*[:=]\s*['\"][^'\"]{3,}['\"]",
        "severity": "High",
        "description": "A secret-like value is embedded in a configuration file.",
        "recommendation": "Move secrets to the environment or a local secrets store.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-798",
    },
    {
        "type": "Security Misconfiguration",
        "pattern": r'(?i)("debug"\s*:\s*true|debug\s*[:=]\s*true|ASPNETCORE_ENVIRONMENT\s*[:=]\s*[\'"]Development)',
        "severity": "Medium",
        "description": "Debug or Development mode is enabled in configuration.",
        "recommendation": "Disable debug flags outside local development.",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-489",
    },
    {
        "type": "Security Misconfiguration",
        "pattern": r'(?i)(allow[_-]?origin|allowedorigins|cors).{0,40}[\'"]\*[\'"]',
        "severity": "Medium",
        "description": "CORS appears to allow any origin.",
        "recommendation": "List explicit trusted origins.",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-942",
    },
    {
        "type": "JWT Misconfiguration",
        "pattern": r"(?i)(verify_signature|validateissuer|validateaudience|requirehttpsmetadata)\s*[:=]\s*(false|0)",
        "severity": "High",
        "description": "A JWT or auth validation flag is disabled.",
        "recommendation": "Keep signature and issuer validation enabled in production.",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "cwe": "CWE-347",
    },
]

# Local hints only. Not a vulnerability database and not updated automatically.
_STALE_PY = {
    "django": ("2.0", "Django 1.x is past upstream support. This is a local version hint, not a CVE lookup."),
    "flask": ("1.0", "Flask 0.x is past upstream support. This is a local version hint, not a CVE lookup."),
}
_STALE_JS = {
    "jquery": ("3.0", "jQuery 1.x/2.x is a local outdated-package hint, not a CVE lookup."),
}


def _hint(filename: str, line: int, package: str, message: str) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        line=line,
        line_end=line,
        severity="Low",
        type="Dependency Hint",
        description=message,
        recommendation="Review the package against your own advisory source. LogSentinel does not query a CVE database.",
        owasp="A06:2021 – Vulnerable and Outdated Components",
        cwe="CWE-1104",
        file=filename,
        snippet=package[:200],
    )


def _python_requirement_hints(content: str, filename: str) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for line_no, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([0-9][0-9A-Za-z_.+]*)", line)
        if not match:
            continue
        name, version = match.group(1).lower(), match.group(2)
        ceiling = _STALE_PY.get(name)
        if not ceiling:
            continue
        def _nums(text: str) -> tuple[int, ...]:
            parts = [int(part) for part in re.findall(r"\d+", text)[:3]]
            return tuple((parts + [0, 0, 0])[:3])
        if _nums(version) < _nums(ceiling[0]):
            findings.append(_hint(filename, line_no, line, ceiling[1]))
    return findings


def _package_json_hints(content: str, filename: str) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return findings
    if not isinstance(data, dict):
        return findings
    deps = {}
    for key in ("dependencies", "devDependencies"):
        block = data.get(key) or {}
        if isinstance(block, dict):
            deps.update(block)
    for name, spec in deps.items():
        hint = _STALE_JS.get(str(name).lower())
        if not hint:
            continue
        text = str(spec)
        nums = [int(p) for p in re.findall(r"\d+", text)[:2]]
        if nums and nums[0] < int(hint[0].split(".")[0]):
            findings.append(_hint(filename, 1, f"{name}@{spec}", hint[1]))
    return findings


class ConfigScanner:
    def scan(self, content: str, filename: str = "unknown.json"):
        findings = apply_rules(content, filename, RULES)
        name = Path(filename).name.lower()
        if name == "requirements.txt":
            findings.extend(_python_requirement_hints(content, filename))
        if name == "package.json":
            findings.extend(_package_json_hints(content, filename))
        return findings

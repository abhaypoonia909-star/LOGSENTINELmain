"""Shared SAST helpers: rule application, classification, redaction, skip paths.

Existing language RULES stay the source of detections. This module does not
execute source code and does not contact external vulnerability databases.
"""

from __future__ import annotations

import hashlib
import re
import stat

from services.security_models import VulnerabilityFinding

UNTRUSTED_RE = re.compile(
    r"\binput\s*\(|\brequest\.|\breq\.|\bflask\.request|\$_(GET|POST|REQUEST|COOKIE|FILES)"
    r"|os\.environ|sys\.argv|location\.(hash|search|href)|document\.cookie"
    r"|document\.URL|searchParams|\.query(?:String)?\b|HttpContext|HttpServletRequest"
    r"|Console\.Read|getParameter\s*\(",
    re.I,
)

_SECRET_ASSIGN = re.compile(
    r"(?i)((?:password|passwd|pwd|api[_-]?key|secret[_-]?key|token|jwt_secret|secret_key)\s*[=:]\s*)"
    r"(['\"])([^'\"]{3,})\2"
)
_SECRET_JSON = re.compile(
    r'(?i)("(?:password|passwd|pwd|api[_-]?key|secret[_-]?key|token|jwt_secret|secret)"\s*:\s*")([^"]{3,})(")'
)

EXCLUDE_DIR_NAMES = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "vendor",
    ".idea",
    ".vs",
    "bin",
    "obj",
    "target",
}

IMPACT_BY_TYPE = {
    "SQL Injection": "An attacker may read or modify database contents.",
    "Cross-Site Scripting (XSS)": "An attacker may run script in another user's browser.",
    "DOM-based XSS": "An attacker may run script in another user's browser via the DOM.",
    "Code Injection": "An attacker may execute attacker-controlled program statements.",
    "Command Injection": "An attacker may run operating-system commands with the app's privileges.",
    "Insecure Deserialization": "An attacker may instantiate unexpected objects or run code during load.",
    "Hardcoded Credentials": "Anyone with the source (or a leak) can reuse the embedded secret.",
    "Hardcoded API Key": "Anyone with the source can call the related API as this application.",
    "Weak Cryptography": "Data protected by this algorithm may be recovered more easily than expected.",
    "Insecure Request": "Traffic or the request URL may be observed, altered, or redirected.",
    "Path Traversal": "An attacker may read or write files outside the intended directory.",
    "SSRF": "The server may be induced to request internal or unexpected URLs.",
    "Insecure File Upload": "Uploaded files may be stored or executed in an unsafe location.",
    "Insecure Randomness": "Security tokens generated this way may be predictable.",
    "Security Misconfiguration": "Debug, CORS, or auth settings may weaken isolation.",
    "Sensitive Data Exposure": "Secrets or tokens in source or client storage can be stolen.",
    "JWT Misconfiguration": "Tokens may be accepted without a valid signature or expiry check.",
    "Insecure YAML": "Loading untrusted YAML can construct unexpected objects.",
    "Dependency Hint": "A locally recognised outdated package name/version was listed. This is not a CVE lookup.",
    "Insecure Form": "Form data may be sent over an unencrypted connection.",
    "Insecure External Script": "A network attacker may replace the script in transit.",
}

_SECRET_TYPES = {
    "Hardcoded Credentials",
    "Hardcoded API Key",
    "Sensitive Data Exposure",
}


def path_is_excluded(relpath: str) -> bool:
    parts = [part.lower() for part in (relpath or "").replace("\\", "/").split("/") if part]
    return any(part in EXCLUDE_DIR_NAMES for part in parts[:-1])


def is_zip_symlink(info) -> bool:
    mode = (getattr(info, "external_attr", 0) >> 16) & 0xFFFF
    return bool(mode) and stat.S_ISLNK(mode)


def content_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify_from_context(source: str, line: int) -> tuple[str, str]:
    lines = source.splitlines()
    idx = max(int(line or 1) - 1, 0)
    start = max(0, idx - 2)
    end = min(len(lines), idx + 3)
    window = "\n".join(lines[start:end])
    if UNTRUSTED_RE.search(window):
        return "suspected", "medium"
    return "potential", "low"


def redact_text(text: str) -> tuple[str, bool]:
    if not text:
        return text, False
    updated, n1 = _SECRET_ASSIGN.subn(r"\1\2***REDACTED***\2", text)
    updated, n2 = _SECRET_JSON.subn(r"\1***REDACTED***\3", updated)
    return updated, (n1 + n2) > 0


def impact_for(kind: str) -> str:
    return IMPACT_BY_TYPE.get(kind, "Review this match; impact depends on how the code is reached.")


def apply_rules(
    content: str,
    filename: str,
    rules: list[dict],
    *,
    flags: int = 0,
) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for rule in rules:
            rule_flags = rule.get("flags", flags)
            if re.search(rule["pattern"], line, rule_flags):
                findings.append(
                    VulnerabilityFinding(
                        line=line_no,
                        line_end=line_no,
                        severity=rule["severity"],
                        type=rule["type"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        owasp=rule.get("owasp") or "",
                        cwe=rule.get("cwe") or "",
                        file=filename,
                        snippet=line.strip()[:200],
                    )
                )
    return findings


def finalize_finding(finding: VulnerabilityFinding, source: str) -> VulnerabilityFinding:
    classification, confidence = classify_from_context(source, finding.line)
    if finding.type in _SECRET_TYPES:
        classification, confidence = "suspected", "medium"
    finding.classification = classification
    finding.confidence = confidence
    finding.impact = finding.impact or impact_for(finding.type)
    snippet, red_s = redact_text(finding.snippet or "")
    context, red_c = redact_text(finding.context or "")
    finding.snippet = snippet
    finding.context = context
    finding.redacted = bool(red_s or finding.redacted)
    return finding

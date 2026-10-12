"""Attach real source context and language-appropriate suggested fixes to findings.

Detection rules are unchanged. Snippets and line numbers always come from the
uploaded file. Suggested code is an advisory example and is never executed.
"""

from __future__ import annotations

import re
from pathlib import Path

from services.sast_engine import finalize_finding
from services.security_models import VulnerabilityFinding

_LANG_BY_EXT = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".php": "php",
    ".html": "html",
    ".css": "css",
    ".java": "java",
    ".cs": "csharp",
    ".sql": "sql",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".xml": "xml",
    ".env": "env",
    ".ini": "ini",
    ".config": "xml",
}

_CONTEXT_RADIUS = 2


def language_for(filename: str, fallback: str = "") -> str:
    ext = Path(filename or "").suffix.lower()
    return _LANG_BY_EXT.get(ext) or fallback or "text"


def enrich_finding(finding: VulnerabilityFinding, source: str, language: str) -> VulnerabilityFinding:
    lines = source.splitlines()
    idx = int(finding.line or 0) - 1
    indent = ""
    if 0 <= idx < len(lines):
        actual = lines[idx]
        indent = re.match(r"^(\s*)", actual).group(1)
        finding.snippet = actual.strip()[:400]
        start = max(0, idx - _CONTEXT_RADIUS)
        end = min(len(lines), idx + _CONTEXT_RADIUS + 1)
        finding.context_start = start + 1
        finding.context = "\n".join(
            f"{i + 1:>4}{'›' if i == idx else ' '} {lines[i]}"
            for i in range(start, end)
        )
    finding.language = language or finding.language or language_for(finding.file)
    finding.match_kind = "pattern_match"
    suggested, explanation, extra, complete = suggest_fix(finding, indent)
    finding.suggested_fix = suggested
    finding.fix_explanation = explanation
    finding.extra_steps = extra
    finding.complete_fix = complete
    return finalize_finding(finding, source)


def suggest_fix(finding: VulnerabilityFinding, indent: str | None = None) -> tuple[str, str, str, bool]:
    lang = (finding.language or "").lower()
    snippet = finding.snippet or ""
    if indent is None:
        indent = re.match(r"^(\s*)", snippet).group(1) if snippet else ""
    kind = finding.type or ""

    if lang == "python":
        return _python_fix(kind, snippet, indent, finding)
    if lang == "javascript":
        return _javascript_fix(kind, snippet, indent, finding)
    if lang == "php":
        return _php_fix(kind, snippet, indent, finding)
    if lang == "html":
        return _html_fix(kind, snippet, indent, finding)
    if lang == "css":
        return _css_fix(kind, snippet, indent, finding)
    if lang == "java":
        return _java_fix(kind, snippet, indent, finding)
    if lang == "csharp":
        return _csharp_fix(kind, snippet, indent, finding)
    if lang == "sql":
        return _sql_fix(kind, snippet, indent, finding)
    return _generic_fix(kind, snippet, indent, finding)


def _python_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    if re.search(r"\bos\.system\s*\(", snippet):
        arg = _first_call_arg(snippet, r"os\.system")
        if _is_string_literal(arg):
            try:
                argv = __import__("ast").literal_eval(arg)
            except Exception:
                argv = None
            if isinstance(argv, str) and argv.strip() and " " not in argv.strip():
                fixed = f"{indent}subprocess.run([{arg}], check=True)"
                return (
                    fixed,
                    "Replaces os.system() with subprocess.run and a fixed argument list, so the shell is not invoked.",
                    "Add `import subprocess`. Review whether this command should run at all. This is a pattern-based suggestion, not a confirmed exploit.",
                    True,
                )
        fixed = (
            f"{indent}# Minimal example — not a drop-in replacement.\n"
            f"{indent}subprocess.run([executable, *validated_args], shell=False, check=True)"
        )
        return (
            fixed,
            "os.system() starts a shell. Pass a validated executable and argument list to subprocess.run with shell=False.",
            "Do not pass unsanitized input() or concatenated strings as the command. Define the intended executable and allowlisted arguments.",
            False,
        )
    if re.search(r"subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True", snippet):
        fixed = re.sub(r"shell\s*=\s*True", "shell=False", snippet, count=1)
        return (
            fixed,
            "Disables shell interpolation so metacharacters in arguments are not executed as commands.",
            "Convert a shell string into an argv list (for example ['ls', path]) before calling subprocess.",
            False,
        )
    if re.search(r"\beval\s*\(", snippet):
        arg = _first_call_arg(snippet, r"eval")
        fixed = f"{indent}value = ast.literal_eval({arg or 'payload'})"
        return (
            fixed,
            "ast.literal_eval parses Python literals only and does not execute statements.",
            "Add `import ast`. If the payload is JSON, use json.loads instead. Do not eval untrusted text.",
            False,
        )
    if re.search(r"\bexec\s*\(", snippet):
        return (
            f"{indent}# Minimal example — replace exec() with explicit logic for the intended behaviour.\n"
            f"{indent}# result = intended_function(validated_input)",
            "exec() runs arbitrary Python. There is not enough context here to rewrite the surrounding program safely.",
            "Identify what the executed string was supposed to do and implement that as normal code or a parser.",
            False,
        )
    if re.search(r"\bpickle\.loads\s*\(", snippet):
        arg = _first_call_arg(snippet, r"pickle\.loads")
        fixed = f"{indent}data = json.loads({arg or 'payload'})"
        return (
            fixed,
            "JSON cannot reconstruct arbitrary Python objects, unlike pickle.loads.",
            "Add `import json`. This only works if the payload is JSON. Rotate any secrets that were pickled.",
            False,
        )
    cred = re.search(
        r"(?i)^(\s*)((?:password|passwd|pwd|api[_-]?key|secret[_-]?key|token))\s*=\s*['\"][^'\"]+['\"]",
        snippet,
    )
    if cred:
        name = cred.group(2)
        env = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
        fixed = f"{indent}{name} = os.environ[{env!r}]"
        return (
            fixed,
            "Reads the secret from the process environment instead of storing it in source.",
            f"Add `import os`, set {env} outside the repository, and rotate the credential that was committed.",
            True,
        )
    if re.search(r"(?i)\b(md5|sha1)\b", snippet):
        algo = "md5" if re.search(r"(?i)\bmd5\b", snippet) else "sha1"
        if re.search(r"(?i)password|passwd|pwd|hash", snippet):
            fixed = (
                f"{indent}# Minimal example for password hashing — not a drop-in replacement.\n"
                f"{indent}hashed = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)"
            )
            extra = "Use a unique random salt per password. Prefer hashlib.scrypt, or a dedicated library such as argon2-cffi, over MD5/SHA-1."
        else:
            fixed = re.sub(r"(?i)\bmd5\b|\bsha1\b", "sha256", snippet, count=1)
            extra = "Confirm whether this digest is for integrity, caching, or passwords; SHA-256 is not a password KDF."
        return (
            fixed,
            f"Replaces the weak {algo.upper()} digest with a stronger hash for this use case.",
            extra,
            False,
        )
    if re.search(r"(?i)\b(DES|RC4)\b", snippet):
        return (
            f"{indent}# Minimal example — choose AES-GCM (or a TLS library) for the actual protocol.\n"
            f"{indent}from cryptography.hazmat.primitives.ciphers.aead import AESGCM",
            "DES and RC4 are obsolete. AES-GCM (or HTTPS/TLS) is the usual modern replacement.",
            "Do not invent a new protocol from this one line. Identify whether this is storage encryption or transport security.",
            False,
        )
    if "SQL" in kind or re.search(r"execute\s*\(", snippet):
        return (
            f"{indent}# Minimal example — not a drop-in replacement.\n"
            f"{indent}cursor.execute('SELECT * FROM items WHERE id = %s', (item_id,))",
            "Uses a bound parameter so user input cannot change the SQL structure.",
            "Replace the placeholder style (%s, ?, :name) with the one your driver expects. Map this onto the original query and identifiers.",
            False,
        )
    return _generic_fix(kind, snippet, indent, finding)


def _javascript_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    if re.search(r"\beval\s*\(", snippet):
        arg = _first_call_arg(snippet, r"eval")
        return (
            f"{indent}const value = JSON.parse({arg or 'payload'});",
            "JSON.parse does not execute JavaScript. eval() does.",
            "This only applies if the payload is JSON. If it is not, implement an explicit parser. Do not eval untrusted text.",
            False,
        )
    inner = re.search(r"^(\s*)(.+?)\.innerHTML\s*=\s*(.+)$", snippet)
    if inner:
        target, value = inner.group(2).strip(), inner.group(3).rstrip(";")
        return (
            f"{indent}{target}.textContent = {value};",
            "textContent inserts text, not HTML, so markup in the value is not executed as DOM.",
            "If you must render HTML, sanitize it with a vetted library such as DOMPurify. This is a pattern-based suggestion.",
            True,
        )
    if re.search(r"\bdocument\.write\s*\(", snippet):
        arg = _first_call_arg(snippet, r"document\.write")
        return (
            f"{indent}element.textContent = {arg or 'text'};",
            "Writes text into a known element instead of injecting markup through document.write.",
            "Choose the actual target element from the page. Avoid document.write after load.",
            False,
        )
    if re.search(r"localStorage\.(setItem|getItem)", snippet):
        return (
            f"{indent}// Store session tokens in a Secure + HttpOnly cookie set by the server.\n"
            f"{indent}// Example cookie flags: Secure; HttpOnly; SameSite=Strict",
            "JavaScript cannot read HttpOnly cookies, which reduces token theft via XSS.",
            "Change the authentication response on the server. Remove the token from localStorage after migrating.",
            False,
        )
    if re.search(r"fetch\s*\(\s*['\"]http://", snippet):
        fixed = snippet.replace("http://", "https://", 1)
        return (
            fixed,
            "HTTPS encrypts the request in transit.",
            "Confirm the endpoint supports TLS and pin or validate certificates in production as appropriate.",
            True,
        )
    if re.search(r"fetch\s*\(\s*[^)]*\+", snippet):
        return (
            f"{indent}const url = new URL('/api/resource', window.location.origin);\n"
            f"{indent}url.searchParams.set('id', String(id));\n"
            f"{indent}const response = await fetch(url);",
            "Builds the URL from a same-origin path and encoded parameters instead of concatenating untrusted strings.",
            "Allowlist the path. This is a minimal example; map it onto the original fetch arguments.",
            False,
        )
    return _generic_fix(kind, snippet, indent, finding)


def _php_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    if re.search(r"\bmysql_query\s*\(", snippet):
        return (
            f"{indent}$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n"
            f"{indent}$stmt->execute([$id]);",
            "A prepared statement keeps the query structure separate from the value.",
            "Switch from mysql_query to PDO or mysqli. This is a minimal example of the original query shape.",
            False,
        )
    if re.search(r"\b(shell_exec|exec|system|passthru|popen)\s*\(", snippet):
        return (
            f"{indent}// Minimal example — avoid shell execution.\n"
            f"{indent}// Use a PHP API for the intended task, or proc_open with a fixed argv array.",
            "These functions run OS commands. There is not enough context to reconstruct the intended command safely.",
            "If a binary must run, pass a constant executable path and an allowlisted argument list. Never concatenate request data into a command string.",
            False,
        )
    if re.search(r"\bunserialize\s*\(", snippet):
        arg = _first_call_arg(snippet, r"unserialize")
        return (
            f"{indent}$data = json_decode({arg or '$payload'}, true);",
            "json_decode cannot instantiate arbitrary PHP objects.",
            "Only works if the payload is JSON. Reject serialized objects from users.",
            False,
        )
    if re.search(r"echo\s+\$_(GET|POST|REQUEST)", snippet):
        source = re.search(r"\$_(GET|POST|REQUEST)\[[^\]]+\]|\$_(GET|POST|REQUEST)", snippet)
        expr = source.group(0) if source else "$_GET['q']"
        php_open = "<?php " if re.search(r"<\?php\b", snippet) else ""
        return (
            f"{indent}{php_open}echo htmlspecialchars({expr}, ENT_QUOTES, 'UTF-8');",
            "htmlspecialchars encodes HTML special characters so the value is displayed, not executed as markup.",
            "Keep ENT_QUOTES and UTF-8. This is a potential XSS pattern match, not a confirmed exploit.",
            True,
        )
    if "SQL" in kind:
        return (
            f"{indent}$stmt = $pdo->prepare('SELECT * FROM items WHERE name = :name');\n"
            f"{indent}$stmt->execute(['name' => $name]);",
            "Bound parameters prevent the value from changing the SQL statement.",
            "Rewrite the original concatenated query as a prepared statement. This example is not a drop-in copy of the original SQL.",
            False,
        )
    return _generic_fix(kind, snippet, indent, finding)


def _html_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    if re.search(r"\bon(click|load|error|mouseover)\s*=", snippet, re.I):
        return (
            f"{indent}<button type=\"button\" id=\"safe-action\">…</button>\n"
            f"{indent}<!-- In an external JS file: document.getElementById('safe-action').addEventListener('click', handler); -->",
            "Moves behaviour out of HTML attributes so injected attributes cannot run script as easily.",
            "Give the element a stable id and attach the listener in a .js file. This is a minimal example of the original markup.",
            False,
        )
    if re.search(r"<script[^>]*>", snippet, re.I) and "src=" not in snippet.lower():
        return (
            f"{indent}<script src=\"/static/app.js\" nonce=\"{{csp_nonce}}\"></script>",
            "External scripts can be constrained with Content-Security-Policy and a nonce.",
            "Move the inline script body into app.js. Enable a CSP that disallows unsafe-inline.",
            False,
        )
    if re.search(r"<script[^>]+src\s*=\s*['\"]http://", snippet, re.I):
        fixed = re.sub(r"http://", "https://", snippet, count=1, flags=re.I)
        return (
            fixed,
            "Loads the script over HTTPS so a network attacker cannot swap the file as easily.",
            "Add a Subresource Integrity hash when the script is third-party.",
            True,
        )
    if re.search(r"<form[^>]+action\s*=\s*['\"]http://", snippet, re.I):
        fixed = re.sub(r"http://", "https://", snippet, count=1, flags=re.I)
        return (
            fixed,
            "Submits the form over HTTPS so credentials are not sent in cleartext.",
            "Confirm the destination supports TLS.",
            True,
        )
    if re.search(r"javascript:", snippet, re.I):
        return (
            f"{indent}<a href=\"/safe-path\" id=\"safe-link\">Continue</a>",
            "Removes the javascript: URL, which executes script when followed.",
            "Use a real URL or a button plus addEventListener. This is a minimal example, not a reconstruction of the original href.",
            False,
        )
    return _generic_fix(kind, snippet, indent, finding)


def _java_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    if "SQL" in kind:
        return (
            f"{indent}// Minimal example — not a drop-in replacement.\n"
            f"{indent}PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE id = ?\");\n"
            f"{indent}ps.setString(1, id);",
            "A prepared statement keeps the SQL structure separate from the value.",
            "Rewrite the original concatenated query. This example is not a copy of the original SQL.",
            False,
        )
    if "Command" in kind:
        return (
            f"{indent}// Minimal example — avoid a shell string.\n"
            f"{indent}new ProcessBuilder(executable, validatedArg).start();",
            "ProcessBuilder with a fixed argument list does not invoke a shell.",
            "Do not concatenate request data into the command. This is a pattern match.",
            False,
        )
    if "Deserial" in kind:
        return (
            f"{indent}// Minimal example — prefer JSON or a constrained schema.\n"
            f"{indent}// ObjectMapper.readValue(bytes, AllowedType.class);",
            "Java deserialization of untrusted bytes can instantiate unexpected classes.",
            "Do not use ObjectInputStream on user data.",
            False,
        )
    return _generic_fix(kind, snippet, indent, finding)


def _csharp_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    if "SQL" in kind:
        return (
            f"{indent}// Minimal example — not a drop-in replacement.\n"
            f"{indent}using var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = @id\", conn);\n"
            f"{indent}cmd.Parameters.AddWithValue(\"@id\", id);",
            "Parameters keep values out of the SQL structure.",
            "Map this onto the original query text and connection.",
            False,
        )
    if "Command" in kind:
        return (
            f"{indent}// Minimal example — set FileName and Arguments separately.\n"
            f"{indent}Process.Start(new ProcessStartInfo {{ FileName = executable, ArgumentList = {{ arg }}, UseShellExecute = false }});",
            "Avoid building a single shell command string.",
            "Allowlist the executable. This is not a rewrite of the original process call.",
            False,
        )
    if "Deserial" in kind:
        return (
            f"{indent}// Minimal example — BinaryFormatter is obsolete.\n"
            f"{indent}// JsonSerializer.Deserialize<AllowedType>(json);",
            "BinaryFormatter can instantiate unexpected types from untrusted data.",
            "Use a constrained serializer. Do not deserialize user bytes with BinaryFormatter.",
            False,
        )
    return _generic_fix(kind, snippet, indent, finding)


def _sql_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    return (
        f"{indent}-- Minimal example — not a drop-in replacement.\n"
        f"{indent}-- Use a parameterized statement from the application:\n"
        f"{indent}-- SELECT col FROM t WHERE id = @id",
        "Dynamic SQL built from concatenated strings can change the statement.",
        "Keep SQL in the application with bound parameters. Do not EXEC unsanitized text.",
        False,
    )


def _css_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    if re.search(r"javascript:", snippet, re.I):
        return (
            f"{indent}/* Minimal example — do not use javascript: URLs in CSS. */\n"
            f"{indent}background-image: none;",
            "javascript: URLs in stylesheets can execute script in older browsers.",
            "Use a static image path or omit the property. This is a pattern match, not a confirmed exploit.",
            False,
        )
    if re.search(r"http://", snippet, re.I):
        fixed = re.sub(r"http://", "https://", snippet, count=1, flags=re.I)
        return (
            fixed,
            "Loads the stylesheet resource over HTTPS.",
            "Confirm the host supports TLS.",
            True,
        )
    return _generic_fix(kind, snippet, indent, finding)


def _generic_fix(kind: str, snippet: str, indent: str, finding: VulnerabilityFinding) -> tuple[str, str, str, bool]:
    rec = finding.recommendation or "Apply the documented remediation for this pattern."
    lang = (finding.language or "").lower()
    note = "Minimal example — not a drop-in replacement."
    if lang in {"javascript", "php"}:
        sample = (
            f"{indent}// {note}\n"
            f"{indent}// Original line: {snippet[:160]}\n"
            f"{indent}// Follow: {rec}"
        )
    elif lang in {"html", "css"}:
        sample = (
            f"{indent}<!-- {note} -->\n"
            f"{indent}<!-- Original: {esc_comment(snippet[:160])} -->\n"
            f"{indent}<!-- Follow: {esc_comment(rec)} -->"
        )
    else:
        sample = (
            f"{indent}# {note}\n"
            f"{indent}# Original line: {snippet[:160]}\n"
            f"{indent}# Follow: {rec}"
        )
    return (
        sample,
        rec,
        "There is not enough surrounding context to rewrite this line as complete production code. Treat this as a potential pattern match.",
        False,
    )


def esc_comment(text: str) -> str:
    return (text or "").replace("-->", "->")


def _first_call_arg(snippet: str, func_re: str) -> str:
    match = re.search(func_re + r"\s*\((.*)\)\s*;?\s*$", snippet)
    if not match:
        return ""
    args = match.group(1).strip()
    return args


def _is_string_literal(value: str) -> bool:
    value = (value or "").strip()
    return len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]

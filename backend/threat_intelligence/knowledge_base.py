"""Static knowledge bases for MITRE ATT&CK and OWASP mappings.

These dictionaries are the single source of truth for enrichment. Keeping them
declarative makes the mappings auditable and easy to extend without code changes.
"""

from __future__ import annotations

# Canonical attack labels -> MITRE technique metadata.
# The `signals` list contains lowercase substrings used to classify raw log
# events into a canonical attack type.
MITRE_TECHNIQUES: dict[str, dict] = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "severity": "High",
        "description": (
            "Adversaries attempt repeated authentication using guessed or "
            "sprayed credentials to gain account access."
        ),
        "detection_method": (
            "Correlate repeated failed logins from a single source or against a "
            "single account within a short window."
        ),
        "mitigation": (
            "Enforce MFA, account lockout thresholds, and rate limiting on "
            "authentication endpoints."
        ),
        "signals": ["brute force", "failed login", "authentication failure",
                    "invalid password", "password guess"],
    },
    "exploit_public_app": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "severity": "Critical",
        "description": (
            "Adversaries exploit a weakness in an Internet-facing host or "
            "service to gain initial access."
        ),
        "detection_method": (
            "Monitor for anomalous requests, known exploit signatures, and "
            "unexpected responses from public services."
        ),
        "mitigation": (
            "Patch promptly, deploy a WAF, and segment public-facing services."
        ),
        "signals": ["exploit", "cve-", "public facing", "rce", "deserialization"],
    },
    "command_scripting": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "severity": "High",
        "description": (
            "Adversaries abuse command and script interpreters such as PowerShell "
            "or Bash to execute commands."
        ),
        "detection_method": (
            "Inspect process creation logs for suspicious interpreter invocations "
            "and encoded command lines."
        ),
        "mitigation": (
            "Restrict PowerShell with Constrained Language Mode, enable script "
            "block logging, and apply application control."
        ),
        "signals": ["powershell", "cmd.exe", "/bin/sh", "bash -i",
                    "scripting", "encodedcommand"],
    },
    "sql_injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application (SQL Injection)",
        "tactic": "Initial Access",
        "severity": "Critical",
        "description": (
            "Adversaries inject SQL statements into application inputs to read or "
            "modify database contents."
        ),
        "detection_method": (
            "Detect SQL metacharacters, UNION/SELECT patterns, and tautologies in "
            "request parameters."
        ),
        "mitigation": (
            "Use parameterized queries, input validation, and a WAF; apply least "
            "privilege to database accounts."
        ),
        "signals": ["sql injection", "union select", "' or '1'='1", "sqlmap",
                    "or 1=1", "'--"],
    },
    "reverse_shell": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter (Reverse Shell)",
        "tactic": "Execution",
        "severity": "Critical",
        "description": (
            "Adversaries establish an outbound interactive shell to a "
            "controlled host for remote command execution."
        ),
        "detection_method": (
            "Flag outbound connections spawned by shell processes and known "
            "reverse-shell command patterns."
        ),
        "mitigation": (
            "Apply egress filtering, application control, and behavioral EDR "
            "detection."
        ),
        "signals": ["reverse shell", "nc -e", "bash -i >&", "/dev/tcp",
                    "meterpreter"],
    },
    "privilege_escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "severity": "Critical",
        "description": (
            "Adversaries exploit software vulnerabilities or misconfigurations to "
            "elevate privileges."
        ),
        "detection_method": (
            "Monitor for unexpected privilege grants, sudo abuse, and token "
            "manipulation events."
        ),
        "mitigation": (
            "Apply least privilege, patch aggressively, and monitor privileged "
            "group membership."
        ),
        "signals": ["privilege escalation", "sudo", "setuid", "token",
                    "elevation", "runas"],
    },
    "web_attack": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application (Web Attack)",
        "tactic": "Initial Access",
        "severity": "High",
        "description": (
            "Adversaries target web applications with XSS, path traversal, or "
            "similar payloads."
        ),
        "detection_method": (
            "Inspect requests for script tags, traversal sequences, and encoded "
            "payloads."
        ),
        "mitigation": (
            "Deploy a WAF, sanitize output, and validate input on the server."
        ),
        "signals": ["<script>", "xss", "../", "path traversal", "directory traversal"],
    },
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "severity": "Medium",
        "description": (
            "Adversaries enumerate open ports and services to plan further "
            "attacks."
        ),
        "detection_method": (
            "Detect many connection attempts across distinct ports from one "
            "source in a short window."
        ),
        "mitigation": (
            "Rate-limit connections, deploy IDS, and minimize exposed services."
        ),
        "signals": ["port scan", "nmap", "syn scan", "portscan"],
    },
    "malware": {
        "technique_id": "T1204",
        "technique_name": "User Execution (Malware)",
        "tactic": "Execution",
        "severity": "Critical",
        "description": (
            "Malicious files are delivered and executed on a host."
        ),
        "detection_method": (
            "Match file hashes against threat intel and monitor for known "
            "malware behavior."
        ),
        "mitigation": (
            "Deploy EDR, block known-bad hashes, and restrict execution paths."
        ),
        "signals": ["malware", "trojan", "ransomware", "virus", "malicious file"],
    },
}

# Canonical attack labels -> OWASP Top 10 (2021) category.
OWASP_MAPPING: dict[str, dict] = {
    "brute_force": {
        "category_id": "A07",
        "category": "Identification and Authentication Failures",
        "risk": "High",
        "description": (
            "Weaknesses in authentication allow credential stuffing and brute "
            "force attacks to succeed."
        ),
        "recommendation": (
            "Enforce MFA, strong password policy, and lockout after repeated "
            "failed attempts."
        ),
    },
    "sql_injection": {
        "category_id": "A03",
        "category": "Injection",
        "risk": "Critical",
        "description": (
            "Untrusted data is interpreted as part of a command or query, "
            "enabling SQL injection."
        ),
        "recommendation": (
            "Use parameterized queries and ORM safe APIs; validate and escape "
            "all input."
        ),
    },
    "web_attack": {
        "category_id": "A03",
        "category": "Injection",
        "risk": "High",
        "description": (
            "Cross-site scripting and related injection flaws allow attacker "
            "controlled content to execute."
        ),
        "recommendation": (
            "Apply context-aware output encoding, CSP headers, and input "
            "validation."
        ),
    },
    "exploit_public_app": {
        "category_id": "A05",
        "category": "Security Misconfiguration",
        "risk": "Critical",
        "description": (
            "Missing hardening or unpatched components expose public-facing "
            "services to exploitation."
        ),
        "recommendation": (
            "Harden configurations, remove unused features, and maintain a "
            "patch cadence."
        ),
    },
    "privilege_escalation": {
        "category_id": "A01",
        "category": "Broken Access Control",
        "risk": "Critical",
        "description": (
            "Access control gaps allow users to act beyond their intended "
            "permissions."
        ),
        "recommendation": (
            "Enforce least privilege, deny by default, and validate authorization "
            "server-side."
        ),
    },
    "reverse_shell": {
        "category_id": "A05",
        "category": "Security Misconfiguration",
        "risk": "Critical",
        "description": (
            "Excessive egress and weak host controls permit interactive remote "
            "shells."
        ),
        "recommendation": (
            "Restrict outbound traffic, apply application control, and monitor "
            "process behavior."
        ),
    },
    "command_scripting": {
        "category_id": "A05",
        "category": "Security Misconfiguration",
        "risk": "High",
        "description": (
            "Overly permissive interpreter access enables arbitrary command "
            "execution."
        ),
        "recommendation": (
            "Restrict interpreters, enable logging, and apply allow-listing."
        ),
    },
    "malware": {
        "category_id": "A08",
        "category": "Software and Data Integrity Failures",
        "risk": "Critical",
        "description": (
            "Unverified code or updates allow malicious payloads to run."
        ),
        "recommendation": (
            "Verify integrity of code and updates; deploy EDR and allow-listing."
        ),
    },
    "port_scan": {
        "category_id": "A09",
        "category": "Security Logging and Monitoring Failures",
        "risk": "Medium",
        "description": (
            "Insufficient monitoring lets reconnaissance activity go undetected."
        ),
        "recommendation": (
            "Enable network monitoring, alerting, and IDS coverage."
        ),
    },
    "exploit_crypto": {
        "category_id": "A02",
        "category": "Cryptographic Failures",
        "risk": "High",
        "description": (
            "Weak or missing cryptography exposes sensitive data in transit or "
            "at rest."
        ),
        "recommendation": (
            "Use strong TLS, encrypt sensitive data, and rotate keys."
        ),
    },
}

# Severity ordering used for sorting and statistics.
SEVERITY_RANK: dict[str, int] = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}
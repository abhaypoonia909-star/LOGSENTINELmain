"""
CyberShield AI Enterprise Edition — Log Analysis Engine
Upgraded threat detection with weighted risk scoring.
Backward-compatible with LogSentinel frontend JSON shape.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import unquote_plus

import pandas as pd

from services.attack_wise import build_attack_wise, explain_match


def normalize_for_detection(text: str, limit: int = 8000) -> str:
    """Decode URL encodings for matching only. Never executes the text."""
    decoded = str(text or "")[:limit]
    for _ in range(2):
        nxt = unquote_plus(decoded, errors="replace")
        if nxt == decoded:
            break
        decoded = nxt[:limit]
    return decoded.lower()

# ── Thresholds & weights ─────────────────────────────────────────────────────
# Log-file analyzer only. Live Alerts use Config.ALERT_FAILED_LOGIN_THRESHOLD
# (default 5) and a 300s window. Those are a different detector.
DEFAULT_LOG_BRUTE_FORCE_THRESHOLD = 2
BRUTE_FORCE_THRESHOLD = DEFAULT_LOG_BRUTE_FORCE_THRESHOLD


def log_brute_force_threshold() -> int:
    """Failed-login count per IP that flags Brute Force in uploaded logs.

    Reads BRUTE_FORCE_THRESHOLD at call time so tests can override it.
    Unset / invalid values keep the historical default of 2.
    """
    raw = os.environ.get("BRUTE_FORCE_THRESHOLD")
    if raw is None or str(raw).strip() == "":
        return DEFAULT_LOG_BRUTE_FORCE_THRESHOLD
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_LOG_BRUTE_FORCE_THRESHOLD

# Weighted severity points (Task 3)
SEVERITY_WEIGHTS = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
}

# ── Port scan keywords (compiled once) ───────────────────────────────────────
PORT_SCAN_KEYWORDS = [
    "port scan", "portscan", "nmap", "masscan", "syn flood",
    "scan detected", "connection sweep", "reconnaissance",
]
_PORT_SCAN_RE = re.compile(
    "|".join(re.escape(k) for k in PORT_SCAN_KEYWORDS),
    re.IGNORECASE,
)

# ── Intrusion rules: (name, severity, regex, owasp, cwe, recommendation) ─────
# Compiled once at import time (Task 2 / Task 8)
INTRUSION_RULES: list[dict[str, Any]] = [
    # SQL Injection
    {
        "name": "SQL Injection",
        "severity": "critical",
        "pattern": re.compile(
            r"(union\s+select|select\s+.+\s+from|drop\s+table|delete\s+from|"
            r"insert\s+into|or\s+1\s*=\s*1|'?\s*or\s+'?1'?\s*=\s*'?1|"
            r"sql\s*injection|;\s*--)",
            re.IGNORECASE,
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
        "recommendation": "Block the source IP and review parameterized query usage on the target app.",
    },
    # XSS
    {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "high",
        "pattern": re.compile(
            r"(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)",
            re.IGNORECASE,
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
        "recommendation": "Encode output and deploy Content-Security-Policy headers.",
    },
    # Directory Traversal
    {
        "name": "Directory Traversal",
        "severity": "high",
        "pattern": re.compile(
            r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|/windows/system32)",
            re.IGNORECASE,
        ),
        "owasp": "A01:2021 – Broken Access Control",
        "cwe": "CWE-22",
        "recommendation": "Normalize paths, reject traversal sequences, and restrict file system access.",
    },
    # Command Injection
    {
        "name": "Command Injection",
        "severity": "critical",
        "pattern": re.compile(
            r"(cmd=|shell_exec|/\s*bin\s*/\s*sh|/\s*bin\s*/\s*bash|"
            r"\bsystem\s*\(|passthru\s*\(|;\s*cat\s|/bin/nc|"
            r"[;&|]\s*(whoami|id|uname)\b|"
            r"`\s*(whoami|id|uname)\s*`|"
            r"\$\(\s*(whoami|id|uname)\s*\))",
            re.IGNORECASE,
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "recommendation": "Never pass user input to shell commands; use safe APIs with argument lists.",
    },
    # PowerShell
    {
        "name": "Suspicious PowerShell",
        "severity": "high",
        "pattern": re.compile(
            r"(powershell|pwsh|-enc(?:odedcommand)?|invoke-expression|"
            r"iex\s*\(|downloadstring|frombase64string)",
            re.IGNORECASE,
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-78",
        "recommendation": "Investigate host for script execution; enable PowerShell logging and AMSI.",
    },
    # Reverse Shell
    {
        "name": "Reverse Shell",
        "severity": "critical",
        "pattern": re.compile(
            r"(reverse\s*shell|bash\s+-i|/dev/tcp/|nc\s+-e|ncat\s+|socat\s+|"
            r"mkfifo\s+/tmp)",
            re.IGNORECASE,
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-77",
        "recommendation": "Isolate the host immediately and capture network connections for forensics.",
    },
    # Web Shell
    {
        "name": "Web Shell",
        "severity": "critical",
        "pattern": re.compile(
            r"(shell\.php|cmd\.php|c99\.php|r57\.php|webshell|"
            r"wso\.php|b374k|eval\s*\(\s*\$_(GET|POST|REQUEST))",
            re.IGNORECASE,
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-94",
        "recommendation": "Remove webshell files, rotate credentials, and audit web-writable directories.",
    },
    # Privilege Escalation / Unauthorized Access
    {
        "name": "Privilege Escalation / Unauthorized Access",
        "severity": "critical",
        "pattern": re.compile(
            r"(privilege\s*escalation|unauthorized|permission\s*denied|"
            r"access\s*denied|uid\s*\d+\s*->\s*0|sudo:\s*AUTHENTICATION FAILURE|"
            r"setuid|become\s+root)",
            re.IGNORECASE,
        ),
        "owasp": "A01:2021 – Broken Access Control",
        "cwe": "CWE-269",
        "recommendation": "Review privileged account activity and enforce least privilege.",
    },
]

# Combined intrusion regex for fast pre-filter (single pass)
_INTRUSION_COMBINED_RE = re.compile(
    "|".join(f"(?:{rule['pattern'].pattern})" for rule in INTRUSION_RULES),
    re.IGNORECASE,
)

# ── Malware rules (Task 5) ───────────────────────────────────────────────────
MALWARE_RULES: list[dict[str, Any]] = [
    {"name": "Trojan", "severity": "critical", "pattern": re.compile(r"\btrojan\b", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Quarantine the host and run full AV/EDR scan."},
    {"name": "Virus", "severity": "critical", "pattern": re.compile(r"\bvirus\b", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Isolate infected systems and restore from clean backups."},
    {"name": "Worm", "severity": "critical", "pattern": re.compile(r"\bworm\b", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Segment the network and patch the propagation vector."},
    {"name": "Rootkit", "severity": "critical", "pattern": re.compile(r"\brootkit\b", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Boot from trusted media and perform offline rootkit analysis."},
    {"name": "Backdoor", "severity": "critical", "pattern": re.compile(r"\bbackdoor\b", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Hunt for persistence mechanisms and rotate all credentials."},
    {"name": "CoinHive Miner", "severity": "high", "pattern": re.compile(r"coinhive|cryptonight|minero", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Remove miner scripts and block mining pool domains."},
    {"name": "XMRig Miner", "severity": "high", "pattern": re.compile(r"xmrig|stratum\+tcp|monero", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Kill mining processes and inspect cron/startup persistence."},
    {"name": "Reverse Shell Payload", "severity": "critical",
     "pattern": re.compile(r"reverse\s*shell|/dev/tcp/|nc\s+-e", re.I),
     "owasp": "A03:2021 – Injection", "cwe": "CWE-77",
     "recommendation": "Block outbound C2 channels and forensic the compromised host."},
    {"name": "Base64 Payload", "severity": "medium",
     "pattern": re.compile(r"(base64\s*payload|frombase64string|atob\s*\(|b64decode)", re.I),
     "owasp": "A03:2021 – Injection", "cwe": "CWE-94",
     "recommendation": "Decode and inspect the payload in a sandbox."},
    {"name": "PowerShell Malware", "severity": "high",
     "pattern": re.compile(r"powershell\s+-enc|invoke-expression|iex\s*\(", re.I),
     "owasp": "A03:2021 – Injection", "cwe": "CWE-78",
     "recommendation": "Enable script block logging and review execution history."},
    {"name": "Web Shell Malware", "severity": "critical",
     "pattern": re.compile(r"webshell|c99\.php|r57\.php|b374k|wso\.php", re.I),
     "owasp": "A03:2021 – Injection", "cwe": "CWE-94",
     "recommendation": "Delete webshell artifacts and harden web upload paths."},
    {"name": "Ransomware", "severity": "critical",
     "pattern": re.compile(r"ransomware|\.locked|\.encrypted|wanna\s?cry|lockbit|encrypt(ed|ion)\s+notice", re.I),
     "owasp": "A08:2021 – Software and Data Integrity Failures", "cwe": "CWE-506",
     "recommendation": "Disconnect from network; do not pay; restore from offline backups."},
]

_MALWARE_COMBINED_RE = re.compile(
    "|".join(f"(?:{r['pattern'].pattern})" for r in MALWARE_RULES),
    re.IGNORECASE,
)

# ── Critical system keywords ─────────────────────────────────────────────────
CRITICAL_KEYWORDS = [
    "kernel panic", "oom kill", "out of memory",
    "segfault", "disk full", "hardware error", "fatal error", "system crash",
]
_CRITICAL_RE = re.compile(
    "|".join(re.escape(k) for k in CRITICAL_KEYWORDS),
    re.IGNORECASE,
)


class LogAnalyzer:
    """Enterprise log threat analyzer — preserves LogSentinel response contract."""

    def __init__(self, df: pd.DataFrame):
        # Defensive copy so caller data is never mutated
        self.df = df.copy() if df is not None else pd.DataFrame()
        # Pre-build searchable text column once (performance)
        self._haystack = self._build_haystack()

    # ── Public entry point ───────────────────────────────────────────────────
    def analyze(self) -> dict:
        stats = self._stats()
        bf = self._brute_force()
        ps = self._port_scan()
        intr = self._intrusion()
        crit = self._critical()
        malware = self._malware_hits()

        # Weighted risk + confidence (Task 3) — adds fields, keeps risk_score/severity
        risk_score, severity, confidence = self._weighted_risk(
            stats, bf, ps, intr, crit, malware
        )

        threats = self._flatten_threats(bf, ps, intr, crit, malware)

        payload = {
            # ── Existing frontend fields (DO NOT RENAME) ──
            "stats": stats,
            "brute_force": bf,
            "port_scan": ps,
            "intrusion": intr,
            "critical_events": crit,
            "malware": malware,
            "risk_score": risk_score,
            "severity": severity,
            "threats": threats,
            # ── New additive fields only ──
            "confidence": confidence,
        }
        payload["attack_wise"] = build_attack_wise(payload)
        return payload

    # ── Haystack builder (safe for missing columns) ──────────────────────────
    def _build_haystack(self) -> pd.Series:
        """Combine message + path into one searchable series. Never fails on missing cols."""
        n = len(self.df)
        if n == 0:
            return pd.Series(dtype=str)

        message = (
            self.df["message"].fillna("").astype(str)
            if "message" in self.df.columns
            else pd.Series([""] * n, index=self.df.index)
        )
        path = (
            self.df["path"].fillna("").astype(str)
            if "path" in self.df.columns
            else pd.Series([""] * n, index=self.df.index)
        )
        raw = (
            self.df["raw"].fillna("").astype(str)
            if "raw" in self.df.columns
            else pd.Series([""] * n, index=self.df.index)
        )
        return (message + " " + path + " " + raw).map(normalize_for_detection)

    def _row_evidence(self, row) -> str:
        """Exact original line when the parser stored it. Never invents text."""
        for key in ("raw", "message"):
            if key in self.df.columns:
                text = str(row.get(key) or "").strip()
                if text.lower() not in ("", "nan", "none"):
                    return text[:4000]
        return ""

    def _row_timestamp(self, row) -> str:
        if "timestamp" not in self.df.columns:
            return ""
        ts = row.get("timestamp")
        if ts is None or (isinstance(ts, float) and pd.isna(ts)):
            return ""
        text = str(ts).strip()
        return "" if text.lower() in ("nan", "none") else text

    # ── Improved _matching (Task 2) ──────────────────────────────────────────
    def _matching(
        self,
        compiled_re: re.Pattern,
        *,
        limit: int = 50,
        rule_meta: dict | None = None,
    ) -> list[dict]:
        """
        Match a pre-compiled regex against the haystack.
        - Compiles once (caller passes compiled pattern)
        - Case-insensitive (haystack is lowercased; patterns use IGNORECASE)
        - Safe if message/path/ip columns are missing
        - Returns event dicts compatible with frontend tables
        """
        if self.df.empty or self._haystack.empty:
            return []

        try:
            mask = self._haystack.str.contains(compiled_re, na=False, regex=True)
        except Exception:
            return []

        if not mask.any():
            return []

        matched = self.df.loc[mask].head(limit)
        events: list[dict] = []

        for _, row in matched.iterrows():
            ip_val = row.get("ip_address") if "ip_address" in self.df.columns else None
            if ip_val is not None and (pd.isna(ip_val) or str(ip_val).lower() in ("nan", "none", "")):
                ip_val = None

            path_val = ""
            if "path" in self.df.columns:
                path_val = str(row.get("path") or "")[:200]
                if path_val.lower() in ("nan", "none"):
                    path_val = ""

            msg_val = ""
            if "message" in self.df.columns:
                msg_val = str(row.get("message") or "")[:200]
            elif "raw" in self.df.columns:
                msg_val = str(row.get("raw") or "")[:200]

            ts_val = ""
            if "timestamp" in self.df.columns:
                ts = row.get("timestamp")
                ts_val = "" if ts is None or (isinstance(ts, float) and pd.isna(ts)) else str(ts)

            # Frontend-compatible event shape
            event = {
                "ip": None if ip_val is None else str(ip_val),
                "path": path_val,
                "message": msg_val,
                "timestamp": ts_val,
                "evidence": self._row_evidence(row),
            }

            # Optional enrichment for threat objects (additive)
            if rule_meta:
                event["rule_name"] = rule_meta.get("name")
                event["rule_severity"] = rule_meta.get("severity")
                event["owasp"] = rule_meta.get("owasp")
                event["cwe"] = rule_meta.get("cwe")
                event["recommendation"] = rule_meta.get("recommendation")

            events.append(event)

        return events

    # ── Stats (unchanged contract) ───────────────────────────────────────────
    def _stats(self) -> dict:
        df = self.df
        total = len(df)
        if total == 0:
            return {
                "total_lines": 0, "error_count": 0, "warning_count": 0,
                "critical_count": 0, "hourly_dist": {}, "hourly": [0] * 24,
                "level_dist": {}, "status_dist": {}, "top_ips": {},
            }

        errors = int(df["is_error"].sum()) if "is_error" in df.columns else 0
        warnings = int(df["is_warning"].sum()) if "is_warning" in df.columns else 0
        criticals = int(df["is_critical"].sum()) if "is_critical" in df.columns else 0

        hourly_dist: dict[str, int] = {}
        if "hour" in df.columns:
            counts = df["hour"].dropna().value_counts().sort_index()
            hourly_dist = {str(int(k)): int(v) for k, v in counts.items()}

        hourly = [0] * 24
        for h, c in hourly_dist.items():
            try:
                hourly[int(h)] = int(c)
            except ValueError:
                pass

        level_dist = {}
        if "level" in df.columns:
            level_dist = {
                str(k): int(v)
                for k, v in df["level"].fillna("INFO").value_counts().items()
            }

        status_dist = {}
        if "status_code" in df.columns:
            status_dist = {
                str(k): int(v)
                for k, v in df["status_code"].dropna().value_counts().head(10).items()
            }

        top_ips = {}
        if "ip_address" in df.columns:
            top_ips = {
                str(k): int(v)
                for k, v in df["ip_address"].dropna().value_counts().head(10).items()
            }

        return {
            "total_lines": total,
            "error_count": errors,
            "warning_count": warnings,
            "critical_count": criticals,
            "hourly_dist": hourly_dist,
            "hourly": hourly,
            "level_dist": level_dist,
            "status_dist": status_dist,
            "top_ips": top_ips,
        }

    # ── Brute force ──────────────────────────────────────────────────────────
    def _brute_force(self) -> dict:
        threshold = log_brute_force_threshold()
        empty = {
            "flagged_ips": [],
            "total_failed_logins": 0,
            "threshold_used": threshold,
        }
        if self.df.empty or "is_failed_login" not in self.df.columns:
            return empty
        if "ip_address" not in self.df.columns:
            # Still count failed logins even without IP
            failed_count = int(self.df["is_failed_login"].sum())
            return {
                "flagged_ips": [],
                "total_failed_logins": failed_count,
                "threshold_used": threshold,
            }

        failed = self.df[self.df["is_failed_login"] & self.df["ip_address"].notna()]
        if failed.empty:
            return empty

        grouped = failed.groupby("ip_address").size().reset_index(name="attempt_count")
        flagged = grouped[grouped["attempt_count"] >= threshold]
        flagged = flagged.sort_values("attempt_count", ascending=False)

        flagged_ips = []
        for r in flagged.itertuples(index=False):
            ip_rows = failed[failed["ip_address"] == r.ip_address]
            first = ip_rows.iloc[0]
            flagged_ips.append({
                "ip_address": str(r.ip_address),
                "attempt_count": int(r.attempt_count),
                "evidence": self._row_evidence(first),
                "timestamp": self._row_timestamp(first),
            })

        return {
            "flagged_ips": flagged_ips,
            "total_failed_logins": int(len(failed)),
            "threshold_used": threshold,
        }

    # ── Port scan ────────────────────────────────────────────────────────────
    def _port_scan(self) -> dict:
        events = self._matching(_PORT_SCAN_RE, rule_meta={
            "name": "Port Scan",
            "severity": "medium",
            "owasp": "A05:2021 – Security Misconfiguration",
            "cwe": "CWE-200",
            "recommendation": "Block scanning IPs and reduce public service exposure.",
        })
        return {"events": events, "event_count": len(events)}

    # ── Intrusion (Task 6) — single pre-filter then per-rule classify ────────
    def _intrusion(self) -> dict:
        if self.df.empty:
            return {"events": [], "event_count": 0}

        # Fast path: only rows that match ANY intrusion pattern
        try:
            candidates = self._haystack.str.contains(_INTRUSION_COMBINED_RE, na=False)
        except Exception:
            return {"events": [], "event_count": 0}

        if not candidates.any():
            return {"events": [], "event_count": 0}

        # Classify each candidate against individual rules
        seen: set[tuple] = set()
        unique: list[dict] = []

        candidate_df = self.df.loc[candidates]
        candidate_hay = self._haystack.loc[candidates]

        for idx, row in candidate_df.iterrows():
            text = candidate_hay.at[idx] if idx in candidate_hay.index else ""
            matched_rules = [rule for rule in INTRUSION_RULES if rule["pattern"].search(text)]
            if not matched_rules:
                continue

            ip_val = row.get("ip_address") if "ip_address" in self.df.columns else None
            if ip_val is not None and (pd.isna(ip_val) or str(ip_val).lower() in ("nan", "none", "")):
                ip_val = None

            msg = str(row.get("message", "") or "")[:200] if "message" in self.df.columns else ""
            path = str(row.get("path", "") or "")[:200] if "path" in self.df.columns else ""
            if path.lower() in ("nan", "none"):
                path = ""
            ts = ""
            if "timestamp" in self.df.columns:
                t = row.get("timestamp")
                ts = "" if t is None or (isinstance(t, float) and pd.isna(t)) else str(t)

            for matched_rule in matched_rules:
                key = (None if ip_val is None else str(ip_val), msg or path, matched_rule["name"])
                if key in seen:
                    continue
                seen.add(key)

                unique.append({
                    "ip": None if ip_val is None else str(ip_val),
                    "path": path,
                    "message": msg,
                    "timestamp": ts,
                    "evidence": self._row_evidence(row),
                    # Additive enrichment
                    "rule_name": matched_rule["name"],
                    "rule_severity": matched_rule["severity"],
                    "owasp": matched_rule["owasp"],
                    "cwe": matched_rule["cwe"],
                    "recommendation": matched_rule["recommendation"],
                })

                if len(unique) >= 50:
                    break
            if len(unique) >= 50:
                break

        return {"events": unique, "event_count": len(unique)}

    def _finding_key(self, event: dict) -> tuple[str, str, str]:
        evidence = str(event.get("evidence") or event.get("message") or event.get("path") or "").strip()
        ip = str(event.get("ip") or event.get("source_ip") or "").strip()
        ts = str(event.get("timestamp") or "").strip()
        return (evidence, ip, ts)

    # ── Critical events ──────────────────────────────────────────────────────
    def _critical(self) -> dict:
        if self.df.empty:
            return {"events": [], "event_count": 0}

        # Only the dedicated critical-system keywords. The parser's is_critical
        # flag is a level hint (the word "critical") and must not create extra
        # detections on its own. Privilege-escalation lines are intrusion findings.
        msg_mask = self._haystack.str.contains(_CRITICAL_RE, na=False)
        flagged = self.df.loc[msg_mask]

        events = []
        for _, row in flagged.head(50).iterrows():
            level = "CRITICAL"
            if "level" in self.df.columns:
                level = str(row.get("level") or "CRITICAL")
            msg = ""
            if "message" in self.df.columns:
                msg = str(row.get("message") or "")[:300]
            ts = ""
            if "timestamp" in self.df.columns:
                t = row.get("timestamp")
                ts = "" if t is None or (isinstance(t, float) and pd.isna(t)) else str(t)
            ip_val = row.get("ip_address") if "ip_address" in self.df.columns else None
            if ip_val is not None and (pd.isna(ip_val) or str(ip_val).lower() in ("nan", "none", "")):
                ip_val = None
            events.append({
                "level": level,
                "message": msg,
                "timestamp": ts,
                "ip": None if ip_val is None else str(ip_val),
                "evidence": self._row_evidence(row),
            })

        return {"events": events, "event_count": len(events)}

    # ── Malware (Task 5) ─────────────────────────────────────────────────────
    def _malware_hits(self) -> dict:
        if self.df.empty:
            return {"events": [], "event_count": 0}

        try:
            candidates = self._haystack.str.contains(_MALWARE_COMBINED_RE, na=False)
        except Exception:
            return {"events": [], "event_count": 0}

        if not candidates.any():
            return {"events": [], "event_count": 0}

        seen: set[tuple] = set()
        events: list[dict] = []
        candidate_df = self.df.loc[candidates]
        candidate_hay = self._haystack.loc[candidates]

        for idx, row in candidate_df.iterrows():
            text = candidate_hay.at[idx] if idx in candidate_hay.index else ""
            matched = None
            for rule in MALWARE_RULES:
                if rule["pattern"].search(text):
                    matched = rule
                    break
            if not matched:
                continue

            ip_val = row.get("ip_address") if "ip_address" in self.df.columns else None
            if ip_val is not None and (pd.isna(ip_val) or str(ip_val).lower() in ("nan", "none", "")):
                ip_val = None
            msg = str(row.get("message", "") or "")[:200] if "message" in self.df.columns else ""
            ts = ""
            if "timestamp" in self.df.columns:
                t = row.get("timestamp")
                ts = "" if t is None or (isinstance(t, float) and pd.isna(t)) else str(t)

            key = (None if ip_val is None else str(ip_val), msg, matched["name"])
            if key in seen:
                continue
            seen.add(key)

            events.append({
                "ip": None if ip_val is None else str(ip_val),
                "path": "",
                "message": msg,
                "timestamp": ts,
                "evidence": self._row_evidence(row),
                "rule_name": matched["name"],
                "rule_severity": matched["severity"],
                "owasp": matched["owasp"],
                "cwe": matched["cwe"],
                "recommendation": matched["recommendation"],
            })
            if len(events) >= 50:
                break

        return {"events": events, "event_count": len(events)}

    # ── Weighted risk score (Task 3) ─────────────────────────────────────────
    def _weighted_risk(self, stats, bf, ps, intr, crit, malware) -> tuple[int, str, int]:
        """
        Returns (risk_score 0-100, severity, confidence 0-100).
        Uses severity weights: Critical=15, High=10, Medium=5, Low=2.
        """
        points = 0

        # Brute force IPs → High each (capped)
        points += min(len(bf.get("flagged_ips", [])) * SEVERITY_WEIGHTS["high"], 40)

        # Port scan events → Medium
        points += min(ps.get("event_count", 0) * SEVERITY_WEIGHTS["medium"], 20)

        # Intrusion — use per-event severity when available
        for e in intr.get("events", []):
            sev = (e.get("rule_severity") or "high").lower()
            points += SEVERITY_WEIGHTS.get(sev, SEVERITY_WEIGHTS["high"])
        points = min(points, points)  # no-op placeholder; cap applied at end

        # Cap intrusion contribution
        # (recalculate intrusion portion with cap)
        # Simpler: recompute total cleanly below

        points = 0
        points += min(len(bf.get("flagged_ips", [])) * SEVERITY_WEIGHTS["high"], 40)
        points += min(ps.get("event_count", 0) * SEVERITY_WEIGHTS["medium"], 20)

        intr_pts = sum(
            SEVERITY_WEIGHTS.get((e.get("rule_severity") or "high").lower(), 10)
            for e in intr.get("events", [])
        )
        points += min(intr_pts, 35)

        points += min(crit.get("event_count", 0) * SEVERITY_WEIGHTS["critical"], 30)

        mal_pts = sum(
            SEVERITY_WEIGHTS.get((e.get("rule_severity") or "critical").lower(), 15)
            for e in malware.get("events", [])
        )
        points += min(mal_pts, 30)

        # Error volume contribution (low weight)
        total = max(stats.get("total_lines", 1), 1)
        err_ratio = stats.get("error_count", 0) / total
        points += min(int(err_ratio * 30), 5)

        risk_score = min(int(points), 100)
        severity = self._severity(risk_score)

        # Confidence: higher when more detectors fire and more lines parsed
        detectors_hit = sum([
            1 if bf.get("flagged_ips") else 0,
            1 if ps.get("event_count", 0) else 0,
            1 if intr.get("event_count", 0) else 0,
            1 if crit.get("event_count", 0) else 0,
            1 if malware.get("event_count", 0) else 0,
        ])
        volume_factor = min(stats.get("total_lines", 0) / 50, 1.0)  # saturate at 50 lines
        confidence = int(min(40 + detectors_hit * 10 + volume_factor * 20, 100))

        return risk_score, severity, confidence

    def _severity(self, score: int) -> str:
        # Keep lowercase values expected by existing frontend/dashboard
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    # ── Threat objects (Task 4) — additive fields on each threat ─────────────
    def _flatten_threats(self, bf, ps, intr, crit, malware) -> list[dict]:
        threats: list[dict] = []
        seen_keys: set[tuple[str, str, str]] = set()

        def _remember(event: dict) -> None:
            key = self._finding_key(event)
            if any(key):
                seen_keys.add(key)

        for ip in bf.get("flagged_ips", []):
            title = "Brute Force Attack"
            item = {
                "category": "Brute Force",
                "severity": "high",
                "source_ip": ip["ip_address"],
                "message": f"{ip['attempt_count']} failed logins",
                "attempt_count": int(ip["attempt_count"]),
                "title": title,
                "description": f"IP {ip['ip_address']} exceeded failed-login threshold with {ip['attempt_count']} attempts.",
                "timestamp": ip.get("timestamp") or "",
                "evidence": ip.get("evidence") or "",
                "explanation": explain_match(title, "Brute Force"),
                "recommendation": "Block the IP at the firewall and enable account lockout / fail2ban.",
                "owasp": "A07:2021 – Identification and Authentication Failures",
                "cwe": "CWE-307",
            }
            threats.append(item)
            _remember(item)

        for e in ps.get("events", []):
            title = "Port Scan Activity"
            item = {
                "category": "Port Scan",
                "severity": "medium",
                "source_ip": str(e.get("ip") or ""),
                "message": e.get("message"),
                "title": title,
                "description": e.get("message") or "Port scan indicators detected in logs.",
                "timestamp": e.get("timestamp") or "",
                "evidence": e.get("evidence") or e.get("message") or "",
                "explanation": explain_match(title, "Port Scan"),
                "recommendation": e.get("recommendation") or "Block scanning IPs and harden exposed services.",
                "owasp": e.get("owasp") or "A05:2021 – Security Misconfiguration",
                "cwe": e.get("cwe") or "CWE-200",
            }
            threats.append(item)
            _remember(item)

        for e in intr.get("events", []):
            title = e.get("rule_name") or "Intrusion"
            item = {
                "category": "Intrusion",
                "severity": (e.get("rule_severity") or "high").lower(),
                "source_ip": str(e.get("ip") or ""),
                "message": e.get("path") or e.get("message"),
                "title": title,
                "description": e.get("message") or e.get("path") or title,
                "timestamp": e.get("timestamp") or "",
                "evidence": e.get("evidence") or e.get("message") or e.get("path") or "",
                "explanation": explain_match(title, "Intrusion"),
                "recommendation": e.get("recommendation") or "Investigate and block the source.",
                "owasp": e.get("owasp") or "A03:2021 – Injection",
                "cwe": e.get("cwe") or "CWE-74",
            }
            threats.append(item)
            _remember(item)

        for e in malware.get("events", []):
            if self._finding_key(e) in seen_keys:
                continue
            title = e.get("rule_name") or "Malware Indicator"
            item = {
                "category": "Malware Indicator",
                "severity": (e.get("rule_severity") or "critical").lower(),
                "source_ip": str(e.get("ip") or ""),
                "message": e.get("message"),
                "title": title,
                "description": e.get("message") or title,
                "timestamp": e.get("timestamp") or "",
                "evidence": e.get("evidence") or e.get("message") or "",
                "explanation": explain_match(title, "Malware Indicator"),
                "recommendation": e.get("recommendation") or "Quarantine and run full malware scan.",
                "owasp": e.get("owasp") or "A08:2021 – Software and Data Integrity Failures",
                "cwe": e.get("cwe") or "CWE-506",
            }
            threats.append(item)
            _remember(item)

        for e in crit.get("events", []):
            if self._finding_key(e) in seen_keys:
                continue
            title = "Critical System Event"
            item = {
                "category": "Critical Event",
                "severity": "critical",
                "source_ip": str(e.get("ip") or ""),
                "message": e.get("message"),
                "title": title,
                "description": e.get("message") or "Critical system event detected.",
                "timestamp": e.get("timestamp") or "",
                "evidence": e.get("evidence") or e.get("message") or "",
                "explanation": explain_match(title, "Critical Event"),
                "recommendation": "Escalate to on-call / SOC and preserve forensic evidence.",
                "owasp": "A04:2021 – Insecure Design",
                "cwe": "CWE-754",
            }
            threats.append(item)
            _remember(item)

        return threats
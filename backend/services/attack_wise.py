"""Group LogAnalyzer findings by attack type. Does not run detection."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

_TS_PREFIX = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)

_EXPLANATIONS = {
    "Brute Force Attack": (
        "This source exceeded the failed-login threshold used by the brute-force detector."
    ),
    "Port Scan Activity": (
        "The log line matched port-scan or reconnaissance keywords used by the detector."
    ),
    "SQL Injection": (
        "The request matched a SQL injection detection rule (query fragments such as "
        "UNION SELECT or OR 1=1)."
    ),
    "Cross-Site Scripting (XSS)": (
        "The request matched a cross-site scripting detection rule."
    ),
    "Directory Traversal": (
        "The path matched a directory-traversal detection rule (parent-directory sequences)."
    ),
    "Command Injection": (
        "The request matched a command-injection detection rule."
    ),
    "Reverse Shell": (
        "The log line matched a reverse-shell indicator used by the detector."
    ),
    "Suspicious PowerShell": (
        "The log line matched a suspicious PowerShell execution rule."
    ),
    "Web Shell": (
        "The request matched a web-shell probe or artifact rule."
    ),
    "Privilege Escalation / Unauthorized Access": (
        "The log line matched a privilege-escalation or unauthorized-access rule."
    ),
    "Critical System Event": (
        "The line was marked critical by level or matched a critical-system keyword."
    ),
    "Malware Indicator": (
        "The line matched a malware-indicator rule in the detection engine."
    ),
}

_CATEGORY_FALLBACK = {
    "Brute Force": "Failed-login volume from this source crossed the detector threshold.",
    "Port Scan": "Reconnaissance or port-scan keywords were present in the log line.",
    "Intrusion": "The line matched an intrusion detection rule.",
    "Critical Event": "The detector classified this as a critical system event.",
    "Malware Indicator": "The line matched a malware detection rule.",
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def explain_match(title: str, category: str) -> str:
    title = (title or "").strip()
    category = (category or "").strip()
    if title in _EXPLANATIONS:
        return _EXPLANATIONS[title]
    if category in _CATEGORY_FALLBACK:
        return _CATEGORY_FALLBACK[category]
    return "The detection engine matched this line with an existing rule."


def _blank_to_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in ("", "none", "nan", "null", "?"):
        return None
    return text


def _evidence(threat: dict) -> str | None:
    for key in ("evidence", "raw", "message", "path", "description"):
        text = _blank_to_none(threat.get(key))
        if text:
            return text[:4000]
    return None


def _timestamp_from_evidence(evidence: str | None) -> str | None:
    """Use a leading timestamp already in the original line. Do not invent one."""
    if not evidence:
        return None
    match = _TS_PREFIX.match(evidence.strip())
    return match.group(1) if match else None


def _normalize_event(threat: dict) -> dict[str, Any]:
    title = _blank_to_none(threat.get("title") or threat.get("rule_name")) or "Unknown Attack"
    category = _blank_to_none(threat.get("category")) or "Unknown"
    severity = _blank_to_none(threat.get("severity"))
    confidence = threat.get("confidence")
    if isinstance(confidence, (int, float)):
        confidence = max(0, min(100, int(confidence)))
    else:
        confidence = None
    evidence = _evidence(threat)
    attempt_count = threat.get("attempt_count")
    if not isinstance(attempt_count, (int, float)) or int(attempt_count) <= 0:
        attempt_count = None
    else:
        attempt_count = int(attempt_count)

    return {
        "attack_name": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "source_ip": _blank_to_none(threat.get("source_ip") or threat.get("ip")),
        "timestamp": _blank_to_none(threat.get("timestamp")) or _timestamp_from_evidence(evidence),
        "evidence": evidence,
        "message": _blank_to_none(threat.get("message")),
        "attempt_count": attempt_count,
        "explanation": _blank_to_none(threat.get("explanation")) or explain_match(title, category),
        "recommendation": _blank_to_none(threat.get("recommendation")),
    }


def build_attack_wise(analysis_data: dict | None) -> dict[str, Any]:
    """Group flattened threats by attack name + category. Preserves every event."""
    analysis_data = analysis_data if isinstance(analysis_data, dict) else {}
    raw_threats = analysis_data.get("threats") or []
    if not isinstance(raw_threats, list):
        raw_threats = []

    groups: OrderedDict[tuple[str, str], list[dict]] = OrderedDict()
    for item in raw_threats:
        if not isinstance(item, dict):
            continue
        event = _normalize_event(item)
        key = (event["attack_name"], event["category"])
        groups.setdefault(key, []).append(event)

    attacks = []
    for (name, category), events in groups.items():
        ranks = [_SEVERITY_RANK.get(str(e.get("severity") or "").lower(), 0) for e in events]
        worst = "low"
        if ranks:
            top = max(ranks)
            for label, rank in _SEVERITY_RANK.items():
                if rank == top:
                    worst = label
                    break
        attacks.append({
            "attack_name": name,
            "category": category,
            "event_count": len(events),
            "severity": worst if any(e.get("severity") for e in events) else None,
            "events": events,
        })

    grouped = {
        "total_events": sum(a["event_count"] for a in attacks),
        "distinct_attack_types": len(attacks),
        "attacks": attacks,
    }
    grouped["summary"] = summarize_attacks(grouped)
    return grouped


UNAVAILABLE_IP = "Not available"
_FAILED_LOGIN_ATTEMPTS = re.compile(r"^(\d+)\s+failed logins\b", re.IGNORECASE)


def _event_attempts(event: dict) -> int:
    """Use the finding's own attempt count when the detector recorded one."""
    raw = event.get("attempt_count") if isinstance(event, dict) else None
    if isinstance(raw, (int, float)) and int(raw) > 0:
        return int(raw)
    message = str((event or {}).get("message") or "")
    match = _FAILED_LOGIN_ATTEMPTS.match(message.strip())
    if match:
        return max(1, int(match.group(1)))
    return 1


def _format_source_ips(ip_counts: OrderedDict[str, int], missing: int) -> str:
    parts: list[str] = []
    show_counts = len(ip_counts) + (1 if missing else 0) > 1
    for ip, count in ip_counts.items():
        parts.append(f"{ip} ({count})" if show_counts else ip)
    if missing:
        parts.append(f"{UNAVAILABLE_IP} ({missing})" if show_counts else UNAVAILABLE_IP)
    return "; ".join(parts) if parts else UNAVAILABLE_IP


def _event_fingerprint(event: dict) -> tuple[str, str, str]:
    evidence = str(event.get("evidence") or event.get("message") or "").strip()
    ip = str(_blank_to_none(event.get("source_ip")) or "")
    ts = str(_blank_to_none(event.get("timestamp")) or "")
    return (evidence, ip, ts)


def summarize_attacks(attack_wise: dict | None) -> dict[str, Any]:
    """Compact one-row-per-attack-type view. Does not run detection."""
    payload = attack_wise if isinstance(attack_wise, dict) else {}
    attacks = [item for item in (payload.get("attacks") or []) if isinstance(item, dict)]
    specific_prints: set[tuple[str, str, str]] = set()
    for attack in attacks:
        name = _blank_to_none(attack.get("attack_name")) or "Unknown Attack"
        if name == "Critical System Event":
            continue
        for event in attack.get("events") or []:
            if isinstance(event, dict):
                specific_prints.add(_event_fingerprint(event))

    merged: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for attack in attacks:
        name = _blank_to_none(attack.get("attack_name")) or "Unknown Attack"
        bucket = merged.setdefault(name, {
            "ip_counts": OrderedDict(),
            "missing": 0,
            "severity_rank": 0,
        })
        contributed = False
        for event in attack.get("events") or []:
            if not isinstance(event, dict):
                continue
            if name == "Critical System Event" and _event_fingerprint(event) in specific_prints:
                continue
            contributed = True
            attempts = _event_attempts(event)
            ip = _blank_to_none(event.get("source_ip"))
            if ip:
                bucket["ip_counts"][ip] = bucket["ip_counts"].get(ip, 0) + attempts
            else:
                bucket["missing"] += attempts
            rank = _SEVERITY_RANK.get(str(event.get("severity") or "").lower(), 0)
            if rank > bucket["severity_rank"]:
                bucket["severity_rank"] = rank
        if not contributed:
            fallback = attack.get("event_count")
            if isinstance(fallback, (int, float)) and int(fallback) > 0:
                bucket["missing"] += int(fallback)
            rank = _SEVERITY_RANK.get(str(attack.get("severity") or "").lower(), 0)
            if rank > bucket["severity_rank"]:
                bucket["severity_rank"] = rank

    rows: list[dict[str, Any]] = []
    for name, bucket in merged.items():
        ip_counts = bucket["ip_counts"]
        missing = bucket["missing"]
        if not ip_counts and not missing:
            continue
        sources = [{"ip": ip, "attempts": count} for ip, count in ip_counts.items()]
        if missing:
            sources.append({"ip": None, "attempts": missing})
        worst = None
        for label, rank in _SEVERITY_RANK.items():
            if rank == bucket["severity_rank"] and rank > 0:
                worst = label
                break
        rows.append({
            "attack_type": name,
            "attempts": sum(item["attempts"] for item in sources),
            "severity": worst,
            "source_ips": sources,
            "source_ip_display": _format_source_ips(ip_counts, missing),
        })
    return {
        "total_events": sum(row["attempts"] for row in rows),
        "distinct_attack_types": len(rows),
        "rows": rows,
    }

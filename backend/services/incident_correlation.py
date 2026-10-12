"""Additive incident correlation over existing attack-wise findings.

This module never changes or removes detector output. It groups copied event
views into possible incidents and labels the distinction between a confirmed
rule match and a possible relationship between multiple matches.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from config import Config
from services.attack_wise import build_attack_wise

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_BASE = {"low": 10, "medium": 25, "high": 45, "critical": 65}
_SPACE = re.compile(r"\s+")

INVESTIGATION_STEPS = [
    "Validate each original log line against the source system and surrounding logs.",
    "Confirm whether the source IP is expected, shared, proxied, or associated with automation.",
    "Review authentication, web, endpoint, and network telemetry around the incident window.",
    "Check whether any suspicious request succeeded; a rule match alone does not prove compromise.",
    "Preserve relevant logs and document analyst conclusions before containment changes.",
]

REMEDIATIONS = {
    "Brute Force": "Apply account lockout or rate limiting and review successful logins from the source.",
    "Port Scan": "Restrict exposed services and monitor the source for follow-on access attempts.",
    "Intrusion": "Validate input handling, review WAF logs, and patch the affected application path.",
    "Critical Event": "Escalate for host triage and preserve forensic evidence.",
    "Malware Indicator": "Isolate affected assets only after validation and run approved EDR investigation.",
    "Injection": "Use parameterized queries and context-appropriate output encoding.",
    "Access Control": "Normalize paths and enforce least-privilege file access.",
    "Authentication": "Review authentication controls, sessions, and account activity.",
}


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in ("", "none", "nan", "null", "?") else text


def _parse_timestamp(value: Any) -> datetime | None:
    text = _text(value)
    if not text:
        return None
    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
        ):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _fingerprint(event: dict[str, Any]) -> str:
    evidence = _SPACE.sub(" ", (_text(event.get("evidence")) or "").lower())
    material = "|".join([
        (_text(event.get("attack_name")) or "").lower(),
        (_text(event.get("category")) or "").lower(),
        evidence,
    ])
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:20]


def _event_view(event: dict[str, Any], sequence: int) -> dict[str, Any]:
    return {
        "event_id": sequence,
        "attack_name": _text(event.get("attack_name")) or "Unknown Attack",
        "category": _text(event.get("category")) or "Unknown",
        "severity": _text(event.get("severity")),
        "confidence": event.get("confidence") if isinstance(event.get("confidence"), (int, float)) else None,
        "source_ip": _text(event.get("source_ip")),
        "timestamp": _text(event.get("timestamp")),
        "evidence": _text(event.get("evidence")),
        "explanation": _text(event.get("explanation")),
        "recommendation": _text(event.get("recommendation")),
        "finding_status": "confirmed_detection",
        "_parsed_time": _parse_timestamp(event.get("timestamp")),
        "_fingerprint": _fingerprint(event),
    }


def _risk(events: list[dict[str, Any]]) -> tuple[int, str, list[dict[str, Any]]]:
    severities = [
        str(event.get("severity") or "low").lower()
        for event in events
    ]
    worst = max(severities, key=lambda item: _SEVERITY_RANK.get(item, 0), default="low")
    base = _SEVERITY_BASE.get(worst, 10)
    volume = min(max(len(events) - 1, 0) * 4, 16)
    types = len({event["attack_name"] for event in events})
    diversity = min(max(types - 1, 0) * 7, 14)
    ip_signal = 5 if any(event.get("source_ip") for event in events) else 0
    known_times = [event["_parsed_time"] for event in events if event["_parsed_time"]]
    time_signal = 5 if len(known_times) >= 2 else 0
    score = min(base + volume + diversity + ip_signal + time_signal, 100)
    factors = [
        {"factor": f"Highest finding severity: {worst}", "points": base},
        {"factor": f"Event volume: {len(events)} preserved finding(s)", "points": volume},
        {"factor": f"Attack diversity: {types} distinct type(s)", "points": diversity},
        {"factor": "Shared source IP available" if ip_signal else "No source IP signal available", "points": ip_signal},
        {"factor": "Time proximity validated" if time_signal else "Insufficient timestamps for a time-proximity factor", "points": time_signal},
    ]
    return score, worst, factors


def _remediations(events: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for event in events:
        recommendation = _text(event.get("recommendation"))
        if recommendation and recommendation not in values:
            values.append(recommendation)
        category = event.get("category")
        fallback = REMEDIATIONS.get(str(category))
        if fallback and fallback not in values:
            values.append(fallback)
    if not values:
        values.append("Validate the finding and continue monitoring; do not assume compromise.")
    return values[:8]


def _build_incident(events: list[dict[str, Any]], index: int, reasons: list[str]) -> dict[str, Any]:
    events = sorted(
        events,
        key=lambda event: (
            event["_parsed_time"] is None,
            event["_parsed_time"] or datetime.max,
            event["event_id"],
        ),
    )
    score, severity, factors = _risk(events)
    known_times = [event["_parsed_time"] for event in events if event["_parsed_time"]]
    ips = sorted({event["source_ip"] for event in events if event.get("source_ip")})
    categories = sorted({event["category"] for event in events})
    attack_types = sorted({event["attack_name"] for event in events})
    public_events = [
        {key: value for key, value in event.items() if not key.startswith("_")}
        for event in events
    ]
    return {
        "incident_id": f"INC-{index:04d}",
        "title": attack_types[0] if len(attack_types) == 1 else f"Possible related activity: {', '.join(attack_types[:3])}",
        "correlation_status": "possible_correlation" if len(events) > 1 else "single_detection",
        "assessment": (
            "These confirmed rule matches may be related based on the listed correlation factors. "
            "This does not establish that a compromise occurred."
            if len(events) > 1
            else "This is a confirmed detector match. No relationship to another event is asserted."
        ),
        "severity": severity,
        "risk_score": score,
        "risk_factors": factors,
        "event_count": len(events),
        "distinct_attack_types": len(attack_types),
        "attack_types": attack_types,
        "categories": categories,
        "source_ips": ips,
        "source_ip": ips[0] if len(ips) == 1 else None,
        "first_seen": min(known_times).isoformat() if known_times else None,
        "last_seen": max(known_times).isoformat() if known_times else None,
        "correlation_reasons": reasons,
        "timeline": public_events,
        "investigation_steps": list(INVESTIGATION_STEPS),
        "recommendations": _remediations(events),
    }


def correlate_incidents(
    analysis_data: dict | None,
    window_seconds: int | None = None,
) -> dict[str, Any]:
    """Build incidents without mutating or de-duplicating original findings."""
    data = analysis_data if isinstance(analysis_data, dict) else {}
    attack_wise = data.get("attack_wise")
    if not isinstance(attack_wise, dict) or "attacks" not in attack_wise:
        attack_wise = build_attack_wise(data)
    window = max(1, int(window_seconds or Config.INCIDENT_CORRELATION_WINDOW_SECONDS))

    events: list[dict[str, Any]] = []
    sequence = 1
    for attack in attack_wise.get("attacks") or []:
        for raw_event in attack.get("events") or []:
            if isinstance(raw_event, dict):
                events.append(_event_view(raw_event, sequence))
                sequence += 1

    grouped: list[tuple[list[dict[str, Any]], list[str]]] = []
    used: set[int] = set()

    # Strongest relationship: same known source IP plus time proximity.
    by_ip: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event.get("source_ip") and event["_parsed_time"]:
            by_ip[event["source_ip"]].append(event)
    for ip, ip_events in by_ip.items():
        ordered = sorted(ip_events, key=lambda event: event["_parsed_time"])
        cluster: list[dict[str, Any]] = []
        for event in ordered:
            if cluster and (event["_parsed_time"] - cluster[-1]["_parsed_time"]).total_seconds() > window:
                if len(cluster) > 1:
                    grouped.append((cluster, [f"Same source IP {ip}", f"Events occurred within {window} seconds"]))
                    used.update(item["event_id"] for item in cluster)
                cluster = []
            cluster.append(event)
        if len(cluster) > 1:
            grouped.append((cluster, [f"Same source IP {ip}", f"Events occurred within {window} seconds"]))
            used.update(item["event_id"] for item in cluster)

    # When time is unavailable, only exact same-type/evidence duplicates are
    # possibly related. Similar timestamps alone are never sufficient.
    by_fingerprint: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["event_id"] not in used:
            by_fingerprint[event["_fingerprint"]].append(event)
    for duplicate_events in by_fingerprint.values():
        known_ips = {event["source_ip"] for event in duplicate_events if event.get("source_ip")}
        if len(duplicate_events) > 1 and len(known_ips) <= 1:
            grouped.append((
                duplicate_events,
                ["Exact attack type and evidence fingerprint match", "Timestamp or source-IP evidence was insufficient"],
            ))
            used.update(item["event_id"] for item in duplicate_events)

    # Every ungrouped finding remains visible as its own investigation item.
    for event in events:
        if event["event_id"] not in used:
            grouped.append(([event], ["No sufficiently strong relationship to another finding"]))

    incidents = [
        _build_incident(group_events, index, reasons)
        for index, (group_events, reasons) in enumerate(grouped, start=1)
    ]
    incidents.sort(key=lambda incident: (-incident["risk_score"], incident["incident_id"]))
    # IDs remain stable after risk ordering.
    for index, incident in enumerate(incidents, start=1):
        incident["incident_id"] = f"INC-{index:04d}"

    return {
        "summary": {
            "total_incidents": len(incidents),
            "possible_correlations": sum(
                1 for incident in incidents if incident["correlation_status"] == "possible_correlation"
            ),
            "confirmed_findings": len(events),
            "correlation_window_seconds": window,
            "disclaimer": (
                "Incident groupings are investigative hypotheses. Confirmed detections are rule matches; "
                "neither alone proves successful exploitation or compromise."
            ),
        },
        "incidents": incidents,
    }


def correlate_security_records(
    security_events: list[Any],
    security_alerts: list[Any] | None = None,
    window_seconds: int | None = None,
) -> dict[str, Any]:
    """Adapt persisted SecurityEvent/SecurityAlert rows to the same incident view.

    SecurityEvent rows remain authoritative and untouched. SecurityAlert IDs are
    attached only as references when their source IP overlaps an incident.
    """
    threats = []
    for row in security_events or []:
        getter = row.get if isinstance(row, dict) else lambda key, default=None: getattr(row, key, default)
        created_at = getter("created_at")
        threats.append({
            "title": getter("attack_name") or getter("event_type") or "Security Event",
            "category": getter("category") or "Security Event",
            "severity": getter("severity"),
            "source_ip": getter("source_ip"),
            "timestamp": created_at.isoformat() if isinstance(created_at, datetime) else _text(created_at),
            "evidence": getter("evidence"),
            "explanation": "This is a persisted LogSentinel security event.",
            "recommendation": REMEDIATIONS.get(str(getter("category") or "")),
        })
    data = {"threats": threats}
    data["attack_wise"] = build_attack_wise(data)
    result = correlate_incidents(data, window_seconds)

    alerts = security_alerts or []
    for incident in result["incidents"]:
        source_ips = set(incident.get("source_ips") or [])
        related = []
        for alert in alerts:
            getter = alert.get if isinstance(alert, dict) else lambda key, default=None: getattr(alert, key, default)
            if getter("source_ip") and getter("source_ip") in source_ips:
                related.append(getter("id"))
        incident["related_security_alert_ids"] = [value for value in related if value is not None]
    result["summary"]["source"] = "persisted_security_events"
    return result


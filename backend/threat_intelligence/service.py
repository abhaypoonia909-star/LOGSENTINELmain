"""Core Threat Intelligence service.

Consumes already-parsed log events (the same structures the existing Log Parser
produces) and returns enriched threat intelligence. This class performs no I/O
and mutates no external state, making it safe to call from any existing endpoint.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from typing import Any, Iterable

from .knowledge_base import (
    MITRE_TECHNIQUES,
    OWASP_MAPPING,
    SEVERITY_RANK,
)


class ThreatIntelligenceService:
    """Builds a Threat Intelligence report from parsed log events.

    The service is intentionally tolerant of heterogeneous event shapes so it
    can run against the existing parser output without requiring changes to it.
    """

    # Fields checked (in order) when extracting values from an event dict.
    _MESSAGE_KEYS = ("message", "raw", "log", "description", "event", "detail")
    _IP_KEYS = ("ip", "source_ip", "src_ip", "client_ip", "remote_addr", "attacker_ip", "ip_address")
    _TIME_KEYS = ("timestamp", "time", "datetime", "@timestamp", "date")
    _SEVERITY_KEYS = ("severity", "level", "priority")
    _STATUS_KEYS = ("status", "action", "outcome", "result")

    def build_report(self, events: Iterable[dict[str, Any]]) -> dict[str, Any]:
        """Return the complete Threat Intelligence report.

        Args:
            events: Iterable of parsed log event dictionaries.

        Returns:
            A JSON-serializable dict containing all dashboard sections plus an
            `export` block prepared for PDF/JSON/CSV rendering.
        """
        normalized = [self._normalize(e) for e in events if isinstance(e, dict)]
        classified = [e for e in normalized if e["attack_type"] is not None]

        mitre = self._build_mitre(classified)
        owasp = self._build_owasp(classified)
        timeline = self._build_timeline(classified)
        statistics = self._build_statistics(classified)
        recommendations = self._build_recommendations(classified)

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "mitre_attack": mitre,
            "owasp_top10": owasp,
            "timeline": timeline,
            "statistics": statistics,
            "recommendations": recommendations,
            "export": self._build_export_payload(
                mitre, owasp, timeline, statistics, recommendations
            ),
        }

    # ---- Normalization -------------------------------------------------

    def _first(self, event: dict, keys: tuple[str, ...], default: Any = None) -> Any:
        for key in keys:
            value = event.get(key)
            # Treat None, empty string, and pandas NaN (value != value) as missing.
            if value is None or value == "" or (isinstance(value, float) and value != value):
                continue
            return value
        return default

    def _normalize(self, event: dict[str, Any]) -> dict[str, Any]:
        """Reduce an arbitrary event dict to a canonical internal shape."""
        message = str(self._first(event, self._MESSAGE_KEYS, "") or "")
        # Fall back to scanning the whole event when no message field exists.
        haystack = message.lower() if message else " ".join(
            str(v) for v in event.values()
        ).lower()

        attack_type = self._classify(haystack)
        technique = MITRE_TECHNIQUES.get(attack_type, {}) if attack_type else {}

        event_severity = self._normalize_severity(
            self._first(event, self._SEVERITY_KEYS)
        )
        technique_severity = technique.get("severity") if technique else None
        # When the event carries no explicit severity (or only the generic
        # "Info" default that upstream parsers assign to every line), prefer the
        # classified technique's severity so Statistics/Timeline reflect the real
        # threat level instead of collapsing everything to "Info".
        if event_severity and event_severity != "Info":
            severity = event_severity
        else:
            severity = technique_severity or event_severity or "Info"

        timestamp = self._first(event, self._TIME_KEYS)
        if timestamp is None:
            timestamp = self._extract_timestamp(message) or "N/A"

        return {
            "attack_type": attack_type,
            "attack_name": technique.get("technique_name", "Unknown"),
            "message": message,
            "ip": self._first(event, self._IP_KEYS, "N/A"),
            "timestamp": timestamp,
            "severity": severity,
            "status": str(self._first(event, self._STATUS_KEYS, "Detected")),
        }

    # Syslog ("Jun 11 10:15:21") and ISO ("2024-06-11T10:15:21") timestamps.
    _TS_PATTERNS = (
        re.compile(
            r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
        ),
        re.compile(
            r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
        ),
    )

    def _extract_timestamp(self, message: str) -> str | None:
        """Best-effort timestamp extraction from a raw log line.

        Only used when the event has no explicit timestamp field; never
        overrides a real one. Returns None when nothing matches.
        """
        if not message:
            return None
        for pattern in self._TS_PATTERNS:
            match = pattern.search(message)
            if match:
                return match.group(0)
        return None

    def _classify(self, haystack: str) -> str | None:
        """Match an event against known attack signals; return canonical label."""
        if not haystack:
            return None
        for attack_type, meta in MITRE_TECHNIQUES.items():
            for signal in meta["signals"]:
                if signal in haystack:
                    return attack_type
        return None

    @staticmethod
    def _normalize_severity(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip().lower()
        mapping = {
            "critical": "Critical", "crit": "Critical", "emergency": "Critical",
            "high": "High", "error": "High", "alert": "High",
            "medium": "Medium", "warning": "Medium", "warn": "Medium",
            "low": "Low", "notice": "Low",
            "info": "Info", "informational": "Info", "debug": "Info",
        }
        return mapping.get(text)

    # ---- Feature 1: MITRE ATT&CK ---------------------------------------

    def _build_mitre(self, events: list[dict]) -> list[dict]:
        seen: dict[str, dict] = {}
        for event in events:
            attack_type = event["attack_type"]
            meta = MITRE_TECHNIQUES[attack_type]
            key = meta["technique_id"] + meta["technique_name"]
            if key not in seen:
                seen[key] = {
                    "technique_id": meta["technique_id"],
                    "technique_name": meta["technique_name"],
                    "tactic": meta["tactic"],
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "detection_method": meta["detection_method"],
                    "mitigation": meta["mitigation"],
                    "occurrences": 0,
                }
            seen[key]["occurrences"] += 1
        return sorted(
            seen.values(),
            key=lambda r: (SEVERITY_RANK.get(r["severity"], 0), r["occurrences"]),
            reverse=True,
        )

    # ---- Feature 2: OWASP Top 10 ---------------------------------------

    def _build_owasp(self, events: list[dict]) -> list[dict]:
        seen: dict[str, dict] = {}
        for event in events:
            mapping = OWASP_MAPPING.get(event["attack_type"])
            if not mapping:
                continue
            key = mapping["category_id"]
            if key not in seen:
                seen[key] = {
                    "category_id": mapping["category_id"],
                    "category": mapping["category"],
                    "risk": mapping["risk"],
                    "description": mapping["description"],
                    "recommendation": mapping["recommendation"],
                    "occurrences": 0,
                }
            seen[key]["occurrences"] += 1
        return sorted(seen.values(), key=lambda r: r["category_id"])

    # ---- Feature 3: Threat Timeline ------------------------------------

    def _build_timeline(self, events: list[dict]) -> list[dict]:
        timeline = [
            {
                "time": event["timestamp"],
                "attack": event["attack_name"],
                "severity": event["severity"],
                "ip": event["ip"],
                "status": event["status"],
            }
            for event in events
        ]
        # Best-effort chronological sort; falls back to insertion order.
        return sorted(timeline, key=lambda r: str(r["time"]))

    # ---- Feature 4: Attack Statistics ----------------------------------

    def _build_statistics(self, events: list[dict]) -> dict[str, Any]:
        severity_counter: Counter = Counter(e["severity"] for e in events)
        attack_counter: Counter = Counter(e["attack_name"] for e in events)
        ip_counter: Counter = Counter(
            e["ip"] for e in events if e["ip"] not in (None, "N/A")
        )

        most_common_attack = (
            attack_counter.most_common(1)[0][0] if attack_counter else "None"
        )
        top_attacker_ip = (
            ip_counter.most_common(1)[0][0] if ip_counter else "None"
        )

        total = len(events)
        critical = severity_counter.get("Critical", 0)
        high = severity_counter.get("High", 0)

        # Simple qualitative trend based on critical/high concentration.
        if total == 0:
            trend = "Stable"
        elif (critical + high) / total >= 0.5:
            trend = "Escalating"
        elif (critical + high) / total >= 0.2:
            trend = "Elevated"
        else:
            trend = "Stable"

        return {
            "total_threats": total,
            "critical": critical,
            "high": high,
            "medium": severity_counter.get("Medium", 0),
            "low": severity_counter.get("Low", 0),
            "threat_trend": trend,
            "most_common_attack": most_common_attack,
            "top_attacker_ip": top_attacker_ip,
        }

    # ---- Feature 5: Recommendations ------------------------------------

    # Attack-type -> ordered list of concrete recommendations.
    _RECOMMENDATIONS: dict[str, list[str]] = {
        "brute_force": ["Enable MFA", "Monitor failed logins",
                        "Enforce account lockout policy"],
        "sql_injection": ["Enable WAF", "Use parameterized queries",
                          "Restrict database privileges"],
        "web_attack": ["Enable WAF", "Apply Content Security Policy",
                       "Sanitize user input"],
        "exploit_public_app": ["Patch vulnerable software", "Enable WAF",
                               "Segment public-facing services"],
        "privilege_escalation": ["Apply least privilege",
                                 "Patch vulnerable software",
                                 "Monitor privileged accounts"],
        "reverse_shell": ["Block malicious IP", "Apply egress filtering",
                          "Deploy EDR"],
        "command_scripting": ["Restrict PowerShell", "Enable script block logging",
                              "Apply application control"],
        "port_scan": ["Update Firewall Rules", "Enable IDS",
                      "Rate-limit connections"],
        "malware": ["Deploy EDR", "Block malicious IP",
                    "Block known-bad file hashes"],
    }

    def _build_recommendations(self, events: list[dict]) -> list[dict]:
        detected_types = {e["attack_type"] for e in events}
        # Preserve severity ordering: higher-severity attacks first.
        ordered_types = sorted(
            detected_types,
            key=lambda t: SEVERITY_RANK.get(
                MITRE_TECHNIQUES[t]["severity"], 0
            ),
            reverse=True,
        )
        seen: set[str] = set()
        recommendations: list[dict] = []
        for attack_type in ordered_types:
            for rec in self._RECOMMENDATIONS.get(attack_type, []):
                if rec in seen:
                    continue
                seen.add(rec)
                recommendations.append({
                    "action": rec,
                    "priority": MITRE_TECHNIQUES[attack_type]["severity"],
                    "related_attack": MITRE_TECHNIQUES[attack_type]["technique_name"],
                })
        return recommendations

    # ---- Feature 6: Export payload -------------------------------------

    def _build_export_payload(
        self,
        mitre: list[dict],
        owasp: list[dict],
        timeline: list[dict],
        statistics: dict,
        recommendations: list[dict],
    ) -> dict[str, Any]:
        """Prepare flat, export-friendly structures for PDF/JSON/CSV."""
        return {
            "formats": ["pdf", "json", "csv"],
            "csv_sheets": {
                "mitre_attack": {
                    "columns": ["technique_id", "technique_name", "tactic",
                                "severity", "occurrences", "detection_method",
                                "mitigation"],
                    "rows": [
                        [r["technique_id"], r["technique_name"], r["tactic"],
                         r["severity"], r["occurrences"], r["detection_method"],
                         r["mitigation"]]
                        for r in mitre
                    ],
                },
                "owasp_top10": {
                    "columns": ["category_id", "category", "risk",
                                "occurrences", "recommendation"],
                    "rows": [
                        [r["category_id"], r["category"], r["risk"],
                         r["occurrences"], r["recommendation"]]
                        for r in owasp
                    ],
                },
                "timeline": {
                    "columns": ["time", "attack", "severity", "ip", "status"],
                    "rows": [
                        [r["time"], r["attack"], r["severity"], r["ip"],
                         r["status"]]
                        for r in timeline
                    ],
                },
                "recommendations": {
                    "columns": ["priority", "action", "related_attack"],
                    "rows": [
                        [r["priority"], r["action"], r["related_attack"]]
                        for r in recommendations
                    ],
                },
            },
            "statistics": statistics,
        }
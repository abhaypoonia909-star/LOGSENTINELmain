"""Score LogAnalyzer output against a labeled synthetic dataset.

This module does not register Flask routes and does not change detection rules.
Overlapping findings on one line are scored as independent (line, attack) pairs.
Unsupported labels are reported separately and never counted as successful detections.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

DATASET_PATH = Path(__file__).resolve().parent / "synthetic_dataset.jsonl"


def load_dataset(path: Path | None = None) -> list[dict[str, Any]]:
    target = path or DATASET_PATH
    cases: list[dict[str, Any]] = []
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cases.append(json.loads(line))
    return cases


def _case_lines(case: dict[str, Any]) -> list[str]:
    if case.get("kind") == "group":
        return [str(item) for item in (case.get("lines") or []) if str(item).strip()]
    line = str(case.get("line") or "").strip()
    return [line] if line else []


def _titles_by_evidence(result: dict[str, Any]) -> dict[str, set[str]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for threat in result.get("threats") or []:
        if not isinstance(threat, dict):
            continue
        evidence = str(threat.get("evidence") or "").strip()
        title = str(threat.get("title") or "").strip()
        if evidence and title:
            grouped[evidence].add(title)
    return grouped


def _brute_force_ips(result: dict[str, Any]) -> set[str]:
    ips: set[str] = set()
    for threat in result.get("threats") or []:
        if not isinstance(threat, dict):
            continue
        if str(threat.get("title") or "") != "Brute Force Attack":
            continue
        ip = str(threat.get("source_ip") or "").strip()
        if ip:
            ips.add(ip)
    return ips


def _safe_div(num: float, den: float) -> float:
    if den <= 0:
        return 0.0
    return num / den


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fpr = _safe_div(fp, fp + tn)
    return {
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


def evaluate(dataset_path: Path | None = None) -> dict[str, Any]:
    from services.log_analyzer import LogAnalyzer
    from services.log_parser import LogParser

    cases = load_dataset(dataset_path)
    log_lines: list[str] = []
    for case in cases:
        log_lines.extend(_case_lines(case))
    parsed = LogParser().parse("\n".join(log_lines) + "\n")
    result = LogAnalyzer(parsed).analyze()
    by_evidence = _titles_by_evidence(result)
    brute_ips = _brute_force_ips(result)

    tp = fp = tn = fn = 0
    details: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []
    per_attack: Counter[str] = Counter()

    for case in cases:
        case_id = str(case.get("id") or "")
        expected = [str(name) for name in (case.get("expected") or [])]
        supported = bool(case.get("supported", True))
        kind = str(case.get("kind") or "line")

        if kind == "group":
            predicted = []
            match_ip = str(case.get("match_ip") or "").strip()
            if match_ip and match_ip in brute_ips:
                predicted = ["Brute Force Attack"]
            extra = [name for name in predicted if name not in expected]
            missing = [name for name in expected if name not in predicted]
            if not supported:
                unsupported.append({
                    "id": case_id,
                    "expected": expected,
                    "predicted": predicted,
                    "status": "unexpected_detection" if predicted else "unsupported_miss",
                })
                continue
            if expected and not missing and not extra:
                tp += 1
                per_attack[expected[0]] += 1
                status = "TP"
            elif expected and missing:
                fn += 1
                status = "FN"
            elif extra:
                fp += len(extra)
                status = "FP"
            else:
                tn += 1
                status = "TN"
            details.append({
                "id": case_id,
                "kind": kind,
                "expected": expected,
                "predicted": predicted,
                "status": status,
            })
            continue

        line = str(case.get("line") or "").strip()
        predicted = sorted(by_evidence.get(line, set()))
        if not supported:
            if any(name in predicted for name in expected):
                status = "unexpected_detection"
            elif predicted:
                status = "unsupported_other_match"
            else:
                status = "unsupported_miss"
            unsupported.append({
                "id": case_id,
                "expected": expected,
                "predicted": predicted,
                "status": status,
            })
            continue

        if not expected:
            if not predicted:
                tn += 1
                status = "TN"
            else:
                fp += len(predicted)
                status = "FP"
        else:
            hits = [name for name in expected if name in predicted]
            misses = [name for name in expected if name not in predicted]
            extras = [name for name in predicted if name not in expected]
            tp += len(hits)
            fn += len(misses)
            fp += len(extras)
            for name in hits:
                per_attack[name] += 1
            if extras and misses:
                status = "MIXED"
            elif extras:
                status = "FP"
            elif misses:
                status = "FN"
            else:
                status = "TP"

        details.append({
            "id": case_id,
            "kind": kind,
            "expected": expected,
            "predicted": predicted,
            "status": status,
        })

    metrics = _metrics(tp, fp, tn, fn)
    return {
        "overlap_rule": (
            "Each (original evidence line, attack title) pair is scored once. "
            "A line with two independent detections can contribute two TPs. "
            "Brute Force is scored as one group finding per source IP, using the "
            "first failed-login row as stored evidence. Unsupported labels are "
            "excluded from TP/FP/TN/FN and are never counted as successful detections."
        ),
        "dataset_path": str(dataset_path or DATASET_PATH),
        "supported_cases": len(details),
        "unsupported_cases": len(unsupported),
        "metrics": metrics,
        "true_positives_by_attack": dict(per_attack),
        "cases": details,
        "unsupported": unsupported,
        "detector_titles": sorted({
            title for titles in by_evidence.values() for title in titles
        } | ({"Brute Force Attack"} if brute_ips else set())),
    }


def main() -> None:
    report = evaluate()
    print(json.dumps(report["metrics"], indent=2))
    print("unsupported:", json.dumps(report["unsupported"], indent=2))
    print("overlap_rule:", report["overlap_rule"])


if __name__ == "__main__":
    main()

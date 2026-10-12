"""
LogSentinel code scanner orchestrator.
Routes files to language scanners, walks ZIP members in memory, scores risk.
"""

from __future__ import annotations

import io
import time
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from config import Config
from services.code_fix_advisor import enrich_finding, language_for
from services.config_scanner import ConfigScanner
from services.csharp_scanner import CSharpScanner
from services.html_scanner import HTMLScanner
from services.java_scanner import JavaScanner
from services.js_scanner import JavaScriptScanner
from services.php_scanner import PHPScanner
from services.python_scanner import PythonScanner
from services.sast_engine import content_digest, is_zip_symlink, path_is_excluded
from services.sql_scanner import SQLScanner
from utils.validators import decode_source_text

SEVERITY_WEIGHTS = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 2,
}

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".html", ".css", ".txt",
    ".java", ".cs", ".sql", ".json", ".yml", ".yaml", ".xml", ".env", ".ini", ".config",
}

CONFIG_NAMES = {"requirements.txt", "package.json", "appsettings.json", "web.config", ".env"}


def _safe_archive_name(name: str) -> str | None:
    """Return a relative archive path, or None if it could escape an extract root."""
    raw = (name or "").replace("\\", "/").strip()
    if not raw or raw.endswith("/"):
        return None
    if raw.startswith("/") or raw.startswith("//"):
        return None
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    if ":" in parts[0]:
        return None
    return "/".join(parts)


def _warn(file: str, reason: str, category: str) -> dict:
    return {"file": file, "reason": reason, "category": category}


@dataclass
class VulnerabilityFinding:
    line: int
    severity: str
    type: str
    description: str
    recommendation: str
    owasp: str
    cwe: str
    file: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class CodeScannerService:
    def __init__(self) -> None:
        python = PythonScanner()
        javascript = JavaScriptScanner()
        php = PHPScanner()
        html = HTMLScanner()
        config = ConfigScanner()
        self._scanners = {
            ".py": python,
            ".js": javascript,
            ".jsx": javascript,
            ".ts": javascript,
            ".tsx": javascript,
            ".php": php,
            ".html": html,
            ".css": html,
            ".java": JavaScanner(),
            ".cs": CSharpScanner(),
            ".sql": SQLScanner(),
            ".json": config,
            ".yml": config,
            ".yaml": config,
            ".xml": config,
            ".env": config,
            ".ini": config,
            ".config": config,
        }
        self._plaintext_scanners = [
            ("python", python),
            ("javascript", javascript),
            ("php", php),
            ("html", html),
        ]
        self._config = config

    def scan_file(self, content: str, filename: str) -> dict:
        started = time.perf_counter()
        ext = Path(filename).suffix.lower()
        findings = self._scan_content(content, filename, ext)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return self._build_result(
            filename,
            findings,
            scanned_files=[filename],
            warnings=[],
            stats={
                "eligible_files": 1,
                "scanned_files_count": 1,
                "skipped_files_count": 0,
                "excluded_files_count": 0,
                "failed_files_count": 0,
                "unsupported_files_count": 0,
                "duplicate_files_count": 0,
                "lines_scanned": len(content.splitlines()),
                "scan_complete": True,
                "stop_reason": None,
                "elapsed_ms": elapsed_ms,
            },
            elapsed_ms=elapsed_ms,
        )

    def scan_zip(
        self,
        raw: bytes,
        zip_name: str,
        *,
        max_file_bytes: int | None = None,
        max_files: int | None = None,
        max_extract_bytes: int | None = None,
        max_duration_seconds: int | None = None,
        max_ratio: int | None = None,
        cancel_event=None,
        progress_cb=None,
    ) -> dict:
        max_file_bytes = int(max_file_bytes if max_file_bytes is not None else Config.CODE_SCAN_MAX_FILE_BYTES)
        max_files = int(max_files if max_files is not None else Config.CODE_SCAN_MAX_ZIP_FILES)
        max_extract_bytes = int(
            max_extract_bytes if max_extract_bytes is not None else Config.CODE_SCAN_MAX_ZIP_EXTRACT_BYTES
        )
        max_duration = int(
            max_duration_seconds if max_duration_seconds is not None else Config.CODE_SCAN_MAX_DURATION_SECONDS
        )
        max_ratio = int(max_ratio if max_ratio is not None else Config.CODE_SCAN_MAX_COMPRESSION_RATIO)
        started = time.perf_counter()
        deadline = started + max(0, max_duration)

        findings = []
        scanned_files: list[str] = []
        warnings: list[dict] = []
        extracted = 0
        extract_limit_hit = False
        file_limit_hit = False
        timed_out = False
        cancelled = False
        excluded = 0
        failed = 0
        skipped = 0
        unsupported = 0
        duplicates = 0
        lines_scanned = 0
        seen_digests: dict[str, str] = {}
        eligible = 0

        def emit(stage: str, current: str = "") -> None:
            if not progress_cb:
                return
            progress_cb({
                "stage": stage,
                "current_file": current,
                "eligible": eligible,
                "scanned": len(scanned_files),
                "skipped": skipped,
                "elapsed_ms": int((time.perf_counter() - started) * 1000),
            })

        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = [info for info in archive.infolist() if not info.is_dir()]
                emit("indexing")
                for info in members:
                    if cancel_event is not None and cancel_event.is_set():
                        cancelled = True
                        break
                    if time.perf_counter() > deadline:
                        timed_out = True
                        break

                    displayed = info.filename
                    safe_name = _safe_archive_name(info.filename)
                    if safe_name is None:
                        skipped += 1
                        warnings.append(_warn(
                            displayed,
                            "Unsafe archive path was skipped (path traversal or absolute path).",
                            "skipped",
                        ))
                        continue
                    if is_zip_symlink(info):
                        skipped += 1
                        warnings.append(_warn(displayed, "Symbolic links inside archives are not followed.", "skipped"))
                        continue
                    if path_is_excluded(safe_name):
                        excluded += 1
                        warnings.append(_warn(
                            displayed,
                            "Excluded directory (vendor/build/VCS). Not inspected.",
                            "excluded",
                        ))
                        continue

                    ext = Path(safe_name).suffix.lower()
                    name = Path(safe_name).name.lower()
                    if ext == ".zip":
                        skipped += 1
                        warnings.append(_warn(displayed, "Nested ZIP files are not scanned.", "skipped"))
                        continue
                    if ext not in SCANNABLE_EXTENSIONS and name not in CONFIG_NAMES:
                        unsupported += 1
                        if unsupported <= 15:
                            warnings.append(_warn(
                                displayed,
                                f"Unsupported file type '{ext or name}'. Not inspected.",
                                "unsupported",
                            ))
                        continue

                    eligible += 1
                    if extract_limit_hit:
                        skipped += 1
                        warnings.append(_warn(
                            displayed,
                            (
                                f"Archive exceeded the total extracted-size limit of {max_extract_bytes} bytes. "
                                "Split the project or raise CODE_SCAN_MAX_ZIP_EXTRACT_BYTES."
                            ),
                            "skipped",
                        ))
                        continue
                    if file_limit_hit or len(scanned_files) >= max_files:
                        file_limit_hit = True
                        skipped += 1
                        warnings.append(_warn(
                            displayed,
                            (
                                f"Archive exceeded the file-count limit of {max_files} scanned files. "
                                "Exclude node_modules/venv or raise CODE_SCAN_MAX_ZIP_FILES."
                            ),
                            "skipped",
                        ))
                        continue

                    claimed = max(int(info.file_size or 0), 0)
                    compressed = max(int(getattr(info, "compress_size", 0) or 0), 0)
                    if claimed > max_file_bytes:
                        skipped += 1
                        warnings.append(_warn(
                            displayed,
                            f"File exceeds the per-file limit of {max_file_bytes} bytes.",
                            "skipped",
                        ))
                        continue
                    if compressed and claimed and claimed / compressed > max_ratio and claimed > 65536:
                        skipped += 1
                        warnings.append(_warn(
                            displayed,
                            (
                                f"Compression ratio exceeded {max_ratio}:1 (possible ZIP bomb). "
                                "Member was not expanded."
                            ),
                            "skipped",
                        ))
                        continue
                    if extracted + claimed > max_extract_bytes:
                        extract_limit_hit = True
                        skipped += 1
                        warnings.append(_warn(
                            displayed,
                            (
                                f"Archive exceeded the total extracted-size limit of {max_extract_bytes} bytes. "
                                "Split the project or raise CODE_SCAN_MAX_ZIP_EXTRACT_BYTES."
                            ),
                            "skipped",
                        ))
                        continue

                    emit("scanning", displayed)
                    try:
                        with archive.open(info) as handle:
                            data = handle.read(max_file_bytes + 1)
                    except Exception:
                        failed += 1
                        warnings.append(_warn(displayed, "Archive member could not be read.", "failed"))
                        continue
                    if len(data) > max_file_bytes:
                        skipped += 1
                        warnings.append(_warn(
                            displayed,
                            f"File exceeds the per-file limit of {max_file_bytes} bytes.",
                            "skipped",
                        ))
                        continue
                    extracted += len(data)
                    digest = content_digest(data)
                    prior = seen_digests.get(digest)
                    if prior:
                        duplicates += 1
                        warnings.append(_warn(
                            displayed,
                            f"Duplicate content of {prior}; not scanned again in this job.",
                            "duplicate",
                        ))
                        continue
                    try:
                        content = decode_source_text(data)
                    except ValueError as exc:
                        failed += 1
                        warnings.append(_warn(displayed, str(exc), "failed"))
                        continue
                    seen_digests[digest] = displayed
                    scanned_files.append(displayed)
                    lines_scanned += len(content.splitlines())
                    findings.extend(self._scan_content(content, displayed, ext or Path(name).suffix.lower()))
                    del data, content
        except zipfile.BadZipFile as exc:
            raise ValueError("Invalid or corrupted ZIP archive.") from exc

        if timed_out:
            warnings.append(_warn(
                zip_name,
                (
                    f"Scan stopped after the duration limit of {max_duration} seconds. "
                    "Later members were not inspected. Split the archive or raise "
                    "CODE_SCAN_MAX_DURATION_SECONDS."
                ),
                "timeout",
            ))
        if cancelled:
            warnings.append(_warn(zip_name, "Scan was cancelled. Remaining members were not inspected.", "cancelled"))

        if not scanned_files and not warnings:
            raise ValueError(
                "ZIP contains no scannable source files "
                "(.py, .js, .ts, .php, .html, .css, .java, .cs, .sql, .json, .yml, .txt, …)."
            )

        stop_reason = None
        scan_complete = not (file_limit_hit or extract_limit_hit or timed_out or cancelled)
        if cancelled:
            stop_reason = "cancelled"
        elif timed_out:
            stop_reason = "duration_limit"
        elif file_limit_hit:
            stop_reason = "file_count_limit"
        elif extract_limit_hit:
            stop_reason = "extract_size_limit"

        elapsed_ms = int((time.perf_counter() - started) * 1000)
        emit("finalizing")
        return self._build_result(
            zip_name,
            findings,
            scanned_files=scanned_files,
            warnings=warnings,
            limits={
                "max_upload_bytes": Config.CODE_SCAN_MAX_UPLOAD_BYTES,
                "max_file_bytes": max_file_bytes,
                "max_zip_files": max_files,
                "max_zip_extract_bytes": max_extract_bytes,
                "max_duration_seconds": max_duration,
                "max_concurrent": Config.CODE_SCAN_MAX_CONCURRENT,
                "max_compression_ratio": max_ratio,
                "nested_zips_scanned": False,
                "log_upload_max_bytes": Config.MAX_CONTENT_LENGTH,
            },
            stats={
                "eligible_files": eligible,
                "scanned_files_count": len(scanned_files),
                "skipped_files_count": skipped,
                "excluded_files_count": excluded,
                "failed_files_count": failed,
                "unsupported_files_count": unsupported,
                "duplicate_files_count": duplicates,
                "lines_scanned": lines_scanned,
                "scan_complete": scan_complete,
                "stop_reason": stop_reason,
                "elapsed_ms": elapsed_ms,
            },
            elapsed_ms=elapsed_ms,
        )

    def _scan_content(self, content: str, filename: str, ext: str) -> list:
        name = Path(filename).name.lower()
        extra = []
        if ext == ".txt":
            findings = self._scan_plaintext(content, filename)
            if name in CONFIG_NAMES:
                extra = self._config.scan(content, filename)
        else:
            scanner = self._scanners.get(ext)
            if not scanner:
                findings = []
            else:
                findings = scanner.scan(content, filename)
                lang = language_for(filename)
                for finding in findings:
                    finding.language = lang
            if name in CONFIG_NAMES and ext not in {".json", ".yml", ".yaml", ".xml", ".env", ".ini", ".config"}:
                extra = self._config.scan(content, filename)
        merged = findings + extra
        seen: set[tuple] = set()
        unique = []
        for item in merged:
            key = (item.file, item.line, item.type, item.description)
            if key in seen:
                continue
            seen.add(key)
            unique.append(enrich_finding(item, content, item.language or language_for(filename)))
        return unique

    def _scan_plaintext(self, content: str, filename: str) -> list:
        """Run the original language scanners on a .txt source file and merge unique hits."""
        findings = []
        seen: set[tuple] = set()
        for lang, scanner in self._plaintext_scanners:
            for finding in scanner.scan(content, filename):
                key = (finding.line, finding.type, finding.description, finding.snippet)
                if key in seen:
                    continue
                seen.add(key)
                finding.language = lang
                findings.append(finding)
        findings.sort(key=lambda item: (item.line, item.type))
        return findings

    def _build_result(
        self,
        filename: str,
        findings,
        scanned_files: list[str] | None = None,
        warnings: list[dict] | None = None,
        limits: dict | None = None,
        stats: dict | None = None,
        elapsed_ms: int = 0,
    ) -> dict:
        risk_score = self._calculate_score(findings)
        severity = self._overall_severity(risk_score)
        breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        by_type: dict[str, int] = {}
        by_file: dict[str, dict] = {}
        for item in findings:
            breakdown[item.severity] = breakdown.get(item.severity, 0) + 1
            by_type[item.type] = by_type.get(item.type, 0) + 1
            bucket = by_file.setdefault(
                item.file,
                {"file": item.file, "count": 0, "severity_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}},
            )
            bucket["count"] += 1
            bucket["severity_breakdown"][item.severity] = bucket["severity_breakdown"].get(item.severity, 0) + 1

        default_limits = {
            "max_upload_bytes": Config.CODE_SCAN_MAX_UPLOAD_BYTES,
            "max_file_bytes": Config.CODE_SCAN_MAX_FILE_BYTES,
            "max_zip_files": Config.CODE_SCAN_MAX_ZIP_FILES,
            "max_zip_extract_bytes": Config.CODE_SCAN_MAX_ZIP_EXTRACT_BYTES,
            "max_duration_seconds": Config.CODE_SCAN_MAX_DURATION_SECONDS,
            "max_concurrent": Config.CODE_SCAN_MAX_CONCURRENT,
            "max_compression_ratio": Config.CODE_SCAN_MAX_COMPRESSION_RATIO,
            "nested_zips_scanned": False,
            "log_upload_max_bytes": Config.MAX_CONTENT_LENGTH,
        }
        default_stats = {
            "eligible_files": 1 if scanned_files is None else len(scanned_files or []),
            "scanned_files_count": 1 if scanned_files is None else len(scanned_files or []),
            "skipped_files_count": 0,
            "excluded_files_count": 0,
            "failed_files_count": 0,
            "unsupported_files_count": 0,
            "duplicate_files_count": 0,
            "lines_scanned": 0,
            "scan_complete": True,
            "stop_reason": None,
            "elapsed_ms": elapsed_ms,
        }
        return {
            "filename": filename,
            "risk_score": risk_score,
            "severity": severity,
            "vulnerability_count": len(findings),
            "severity_breakdown": breakdown,
            "by_type": by_type,
            "by_file": list(by_file.values()),
            "scanned_files": [filename] if scanned_files is None else scanned_files,
            "warnings": warnings or [],
            "limits": limits or default_limits,
            "stats": stats or default_stats,
            "vulnerabilities": [item.to_dict() for item in findings],
        }

    def _calculate_score(self, findings) -> int:
        total = sum(SEVERITY_WEIGHTS.get(item.severity, 2) for item in findings)
        return min(total, 100)

    def _overall_severity(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

"""In-process code-scan jobs. No Redis, no cloud queue."""

from __future__ import annotations

import threading
import time
import uuid
from typing import Callable

from config import Config


class CodeScanJobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, dict] = {}
        self._running = 0

    def acquire(self) -> bool:
        with self._lock:
            if self._running >= max(1, Config.CODE_SCAN_MAX_CONCURRENT):
                return False
            self._running += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._running = max(0, self._running - 1)

    def create(self, user_id: int, filename: str) -> dict:
        self._purge_locked()
        job_id = uuid.uuid4().hex
        job = {
            "id": job_id,
            "user_id": user_id,
            "filename": filename,
            "status": "queued",
            "progress": {
                "stage": "queued",
                "current_file": "",
                "eligible": 0,
                "scanned": 0,
                "skipped": 0,
                "elapsed_ms": 0,
            },
            "result": None,
            "error": None,
            "analysis_id": None,
            "created": time.time(),
            "cancel": threading.Event(),
        }
        with self._lock:
            self._jobs[job_id] = job
        return self.public(job)

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            self._purge_locked()
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if not job:
            return False
        job["cancel"].set()
        return True

    def public(self, job: dict) -> dict:
        return {
            "job_id": job["id"],
            "filename": job["filename"],
            "status": job["status"],
            "progress": job["progress"],
            "error": job["error"],
            "analysis_id": job["analysis_id"],
            "result": job["result"] if job["status"] == "done" else None,
        }

    def start_thread(self, target: Callable, args: tuple) -> None:
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()

    def _purge_locked(self) -> None:
        ttl = max(60, Config.CODE_SCAN_JOB_TTL_SECONDS)
        now = time.time()
        expired = [key for key, job in self._jobs.items() if now - job["created"] > ttl]
        for key in expired:
            self._jobs.pop(key, None)


job_store = CodeScanJobStore()

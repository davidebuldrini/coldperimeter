"""Run scans in a background thread and expose their progress."""

from __future__ import annotations

import threading
import uuid
from typing import Any

from ..models import ScanResult
from ..service import STAGES, ScanCancelled, ScanRequest, apply_checklist, run_scan

MAX_MESSAGES = 200


class Job:
    """One scan, running or finished."""

    def __init__(self, result: ScanResult | None = None) -> None:
        self.id = uuid.uuid4().hex
        self.status = "done" if result else "running"
        self.error: str | None = None
        self.result = result
        self.messages: list[str] = []
        self.stages: dict[str, dict[str, Any]] = {
            stage: {"status": "done" if result else "pending", "done": 0, "total": 0}
            for stage in STAGES
        }
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._pending_answers: dict[str, str] | None = None

    # -- progress ----------------------------------------------------------

    def _on_progress(
        self, stage: str, message: str, done: int | None, total: int | None
    ) -> None:
        with self._lock:
            if message:
                self.messages.append(message)
                del self.messages[:-MAX_MESSAGES]
            if stage not in self.stages:
                return
            # Stages run in order: everything before the current one is over.
            for earlier in STAGES[: STAGES.index(stage)]:
                self.stages[earlier]["status"] = "done"
            entry = self.stages[stage]
            if done is not None and total is not None:
                entry["done"], entry["total"] = done, total
                entry["status"] = "done" if done >= total else "running"
            elif entry["status"] == "pending":
                entry["status"] = "running"

    # -- lifecycle ---------------------------------------------------------

    def start(self, request: ScanRequest) -> None:
        threading.Thread(target=self._run, args=(request,), daemon=True).start()

    def _run(self, request: ScanRequest) -> None:
        try:
            result = run_scan(request, self._on_progress, self._cancel)
        except ScanCancelled:
            with self._lock:
                self.status = "cancelled"
            return
        except Exception as exc:  # report any failure to the interface
            with self._lock:
                self.status = "failed"
                self.error = str(exc) or type(exc).__name__
            return
        with self._lock:
            if self._pending_answers is not None:
                apply_checklist(result, self._pending_answers)
            self.result = result
            for entry in self.stages.values():
                entry["status"] = "done"
            self.status = "done"

    def cancel(self) -> None:
        self._cancel.set()

    def set_checklist(self, answers: dict[str, str]) -> None:
        """Accept answers at any time; they are applied once results exist."""
        with self._lock:
            if self.result is not None:
                apply_checklist(self.result, answers)
            else:
                self._pending_answers = dict(answers)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "error": self.error,
                "stages": {name: dict(entry) for name, entry in self.stages.items()},
                "messages": list(self.messages[-8:]),
            }


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def running(self) -> Job | None:
        return next((j for j in self._jobs.values() if j.status == "running"), None)

    def start(self, request: ScanRequest) -> Job:
        job = Job()
        self._jobs[job.id] = job
        job.start(request)
        return job

    def add_finished(self, result: ScanResult) -> Job:
        job = Job(result)
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

from __future__ import annotations

import contextlib
import multiprocessing
from multiprocessing.managers import SyncManager
import queue
import threading
import time
from typing import Any, Dict, List, Tuple

from .config import settings
from .jobs import Job, JobStatus
from .policy_engine import rate_limiter, validate_job, validate_plugin
from .storage import append_evidence


class Orchestrator:
    """Simple in-memory orchestrator with a SyncManager Queue for workers.

    Production deployments should replace this with Redis/RabbitMQ and a
    persistent job store.
    """

    def __init__(self) -> None:
        self.jobs: Dict[str, Job] = {}
        self.killed_jobs: set[str] = set()
        self._lock = threading.Lock()
        self.manager: SyncManager | None = None
        self.task_queue: Any = None

    def start_manager(self) -> None:
        if self.manager is not None:
            return

        class _Mgr(SyncManager):
            pass

        _Mgr.register("get_queue")

        def _make_queue() -> multiprocessing.Queue:
            return multiprocessing.Queue()

        _Mgr.register("get_queue", callable=_make_queue)
        self.manager = _Mgr(
            address=(settings.queue_manager_host, settings.queue_manager_port),
            authkey=settings.queue_manager_authkey.encode("utf-8"),
        )
        self.manager.start()
        self.task_queue = self.manager.get_queue()

    def submit_job(self, job: Job) -> Tuple[bool, str]:
        ok, msg = validate_job(job)
        if not ok:
            return False, msg

        with self._lock:
            self.jobs[job.id] = job
            job.status = JobStatus.queued
            job.progress = 0.01
            append_evidence(job.id, "job_created", {"target": job.target, "mode": job.mode})
        # Enqueue task
        payload = {
            "job_id": job.id,
            "target": job.target,
            "scope": job.scope,
            "mode": job.mode,
            "manifest": job.manifest,
        }
        self.task_queue.put(payload)
        return True, job.id

    def mark_running(self, job_id: str) -> None:
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.status = JobStatus.running
            job.progress = max(job.progress, 0.1)
            job.log("worker started")

    def update_progress(self, job_id: str, progress: float, message: str | None = None) -> None:
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.progress = max(job.progress, min(0.99, progress))
            if message:
                job.log(message)

    def add_finding(self, job_id: str, finding: Dict[str, Any]) -> None:
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.findings.append(finding)

    def complete_job(self, job_id: str) -> None:
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.status = JobStatus.completed
            job.progress = 1.0
            job.log("completed")

    def fail_job(self, job_id: str, error: str) -> None:
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job.status = JobStatus.failed
            job.progress = 1.0
            job.log(f"failed: {error}")

    def kill_job(self, job_id: str) -> bool:
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            self.killed_jobs.add(job_id)
            job.status = JobStatus.killed
            job.progress = 1.0
            job.log("killed by operator")
        return True

    def approve_active(self, job_id: str) -> bool:
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            job.approved_active = True
            job.log("active mode approved")
            return True

    def get_status(self, job_id: str) -> Dict[str, Any] | None:
        with self._lock:
            job = self.jobs.get(job_id)
            return job.model_dump() if job else None


orchestrator = Orchestrator()


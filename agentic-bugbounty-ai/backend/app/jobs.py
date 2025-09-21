from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class JobMode(str, Enum):
    passive = "passive"
    active = "active"


class JobStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    killed = "killed"


class ScanRequest(BaseModel):
    target: str
    scope: List[str]
    manifest: Dict[str, Any]
    mode: JobMode = JobMode.passive
    integrations: Dict[str, Any] | None = None
    max_rate: float | None = None


class Job(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    scope: List[str]
    manifest: Dict[str, Any]
    mode: JobMode = JobMode.passive
    approved_active: bool = False
    status: JobStatus = JobStatus.queued
    created_at: float = Field(default_factory=lambda: time.time())
    updated_at: float = Field(default_factory=lambda: time.time())
    progress: float = 0.0
    logs: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    result_paths: Dict[str, str] = Field(default_factory=dict)
    integrations: Dict[str, Any] | None = None
    max_rate: float | None = None

    def log(self, message: str) -> None:
        self.logs.append(message)
        self.updated_at = time.time()


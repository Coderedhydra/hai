from __future__ import annotations

import threading
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import settings
from .jobs import Job, ScanRequest
from .ollama_integration import list_local_models
from .orchestrator import orchestrator
from .policy_engine import rate_limiter


app = FastAPI(title="Agentic Bug Bounty AI", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.on_event("startup")
def _startup() -> None:
    orchestrator.start_manager()


class ScanResponse(BaseModel):
    job_id: str


@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest) -> ScanResponse:
    # Enforce default passive; active requires manifest consent and later approval
    job = Job(
        target=req.target,
        scope=req.scope,
        manifest=req.manifest,
        mode=req.mode,
        integrations=req.integrations,
        max_rate=req.max_rate,
    )
    ok, msg = orchestrator.submit_job(job)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return ScanResponse(job_id=msg)


@app.get("/api/v1/scan/{job_id}/status")
async def scan_status(job_id: str) -> Dict[str, Any]:
    status = orchestrator.get_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="job not found")
    return status


class ApprovalRequest(BaseModel):
    manifest: Dict[str, Any]


@app.post("/api/v1/scan/{job_id}/approve-active")
async def approve_active(job_id: str, approval: ApprovalRequest, x_operator_token: str = Header(None)) -> Dict[str, Any]:  # noqa: N803
    if x_operator_token != settings.operator_token:
        raise HTTPException(status_code=403, detail="invalid operator token")
    # Job must exist
    status = orchestrator.get_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="job not found")
    # Manifest must match job manifest's signature; re-validate is handled in policy on next dispatch
    ok = orchestrator.approve_active(job_id)
    if not ok:
        raise HTTPException(status_code=400, detail="unable to approve")
    return {"status": "ok"}


@app.post("/api/v1/kill/{job_id}")
async def kill_job(job_id: str, x_operator_token: str = Header(None)) -> Dict[str, Any]:  # noqa: N803
    if x_operator_token != settings.operator_token:
        raise HTTPException(status_code=403, detail="invalid operator token")
    ok = orchestrator.kill_job(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="job not found")
    return {"status": "killed"}


@app.get("/api/v1/models")
async def get_models() -> Dict[str, Any]:
    return {"models": list_local_models()}


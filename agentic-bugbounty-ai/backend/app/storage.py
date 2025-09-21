from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any, Dict

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


_write_lock = threading.Lock()


def _get_fernet() -> Fernet | None:
    key = settings.evidence_encryption_key
    if not key:
        return None
    try:
        return Fernet(key.encode("ascii") if not key.startswith("gAAAA") else key)
    except Exception:  # noqa: BLE001
        return None


def _append_line(path: str, line: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _write_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def _compute_hmac(payload: bytes) -> str:
    key = settings.evidence_hmac_key.encode("utf-8")
    mac = hmac.new(key, payload, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def append_evidence(job_id: str, record_type: str, data: Dict[str, Any]) -> str:
    """Append an immutable evidence record to the job log.

    Returns the evidence reference (filename:line_number) for reports.
    """
    ts = time.time()
    payload = {"type": record_type, "ts": ts, "data": data}
    fernet = _get_fernet()
    if fernet is not None:
        try:
            serialized = json.dumps(payload["data"], sort_keys=True, separators=(",", ":")).encode("utf-8")
            encrypted = fernet.encrypt(serialized)
            payload["data"] = {"encrypted": encrypted.decode("ascii")}
        except Exception:  # noqa: BLE001
            # If encryption fails, fall back to plaintext but still record
            pass
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = _compute_hmac(canonical)
    record = {"payload": payload, "hmac": sig}
    line = json.dumps(record, separators=(",", ":"))
    path = os.path.join(settings.evidence_dir, f"job_{job_id}.jsonl")

    # Determine line number by counting existing lines (inefficient but ok for starter)
    line_no = 1
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line_no, _ in enumerate(f, start=1):
                pass
        line_no += 1
    _append_line(path, line)
    return f"{os.path.basename(path)}:{line_no}"


def create_report_files(job_id: str, report_json: dict, report_md: str) -> dict:
    os.makedirs(settings.reports_dir, exist_ok=True)
    json_path = os.path.join(settings.reports_dir, f"job_{job_id}.json")
    md_path = os.path.join(settings.reports_dir, f"job_{job_id}.md")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_json, f, indent=2, sort_keys=True)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(report_md)
    return {"json": json_path, "md": md_path}


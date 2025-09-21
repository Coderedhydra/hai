from __future__ import annotations

import importlib
import os
import sys
import time
from multiprocessing.managers import SyncManager
from typing import Any, Dict

# Adjust path for container execution
CURRENT_DIR = os.path.dirname(os.path.dirname(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

from app.config import settings
from app.orchestrator import orchestrator
from app.policy_engine import validate_plugin
from app.storage import append_evidence


def load_plugin(name: str):
    mod = importlib.import_module(f"app.plugins.{name}")
    return mod


def run_task(task: Dict[str, Any]) -> None:
    job_id = task["job_id"]
    orchestrator.mark_running(job_id)
    target = task["target"]
    manifest = task["manifest"]
    scope = task["scope"]

    append_evidence(job_id, "task_received", {"target": target})

    # Plugin plan for starter: run crawler then header_checker
    for plugin_name in ["crawler", "header_checker"]:
        try:
            plugin = load_plugin(plugin_name)
            ok, msg = validate_plugin(
                orchestrator.jobs[job_id], getattr(plugin, "metadata", {"name": plugin_name})
            )
            if not ok:
                append_evidence(job_id, "plugin_skipped", {"name": plugin_name, "reason": msg})
                continue
            orchestrator.update_progress(job_id, 0.2 if plugin_name == "crawler" else 0.6, f"running {plugin_name}")
            result = plugin.run({"target": target, "manifest": manifest, "scope": scope})
            # Store finding(s)
            if isinstance(result, dict):
                result = [result]
            for finding in result or []:
                # Ensure safe shape
                finding.setdefault("severity", "info")
                finding.setdefault("confidence", 0.5)
                ref = append_evidence(job_id, "finding", finding)
                finding["evidence_ref"] = ref
                orchestrator.add_finding(job_id, finding)
        except Exception as exc:  # noqa: BLE001
            append_evidence(job_id, "plugin_error", {"name": plugin_name, "error": str(exc)})
    orchestrator.complete_job(job_id)


def main() -> None:
    class _Mgr(SyncManager):
        pass

    _Mgr.register("get_queue")
    mgr = _Mgr(
        address=(settings.queue_manager_host, settings.queue_manager_port),
        authkey=settings.queue_manager_authkey.encode("utf-8"),
    )
    mgr.connect()
    q = mgr.get_queue()

    while True:
        try:
            task = q.get(timeout=1.0)
        except Exception:
            time.sleep(0.1)
            continue
        run_task(task)


if __name__ == "__main__":
    main()


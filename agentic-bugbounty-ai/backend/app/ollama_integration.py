from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import httpx


@dataclass
class OllamaModel:
    name: str
    modified_at: float


def _ollama_binary_path() -> str | None:
    return shutil.which("ollama")


def list_local_models() -> List[Dict[str, Any]]:
    """Return a deterministic list of local models.

    Attempts to call `ollama list --json`. If not available, returns a stub list
    for development.
    """
    bin_path = _ollama_binary_path()
    models: List[OllamaModel] = []
    if bin_path:
        try:
            out = subprocess.check_output([bin_path, "list", "--json"], text=True)
            payload = json.loads(out)
            for entry in payload.get("models", []):
                name = entry.get("name") or entry.get("model") or "unknown"
                modified_at = entry.get("modified_at") or time.time()
                if isinstance(modified_at, str):
                    try:
                        modified_at = float(modified_at)
                    except Exception:  # noqa: BLE001
                        modified_at = time.time()
                models.append(OllamaModel(name=name, modified_at=float(modified_at)))
        except Exception:
            # Fall back to simulator if listing fails
            models = [
                OllamaModel(name="llama3.1:8b", modified_at=1_700_000_000.0),
                OllamaModel(name="mistral:7b", modified_at=1_700_000_100.0),
            ]
    else:
        # Simulator mode
        models = [
            OllamaModel(name="llama3.1:8b", modified_at=1_700_000_000.0),
            OllamaModel(name="mistral:7b", modified_at=1_700_000_100.0),
        ]

    # Deterministic ordering: name asc, then modified_at asc
    models_sorted = sorted(models, key=lambda m: (m.name.lower(), m.modified_at))
    return [{"name": m.name, "modified_at": m.modified_at} for m in models_sorted]


async def run_local_model(model: str, prompt: str, json_mode: bool = True, timeout: float = 60.0) -> Dict[str, Any]:
    """Send a prompt to a local Ollama model.

    If Ollama is not installed or reachable, returns a simulator response with
    a safe, structured JSON.
    """
    if not _ollama_binary_path():
        # Simulator response
        return {
            "model": model,
            "response": {
                "summary": "simulated response",
                "hypotheses": [
                    {"title": "Missing HSTS", "confidence": 0.6, "remediation": "Add Strict-Transport-Security header."}
                ],
            },
            "simulated": True,
        }

    # Ollama HTTP API default: http://localhost:11434
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    endpoint = f"{base_url.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        # Hint to get JSON-like output. Real models may need more guidance.
        "format": "json" if json_mode else None,
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            res = await client.post(endpoint, json=payload)
            res.raise_for_status()
            data = res.json()
            if isinstance(data, dict) and data.get("response"):
                try:
                    # Ollama may return JSON string in 'response'
                    parsed = json.loads(data["response"]) if isinstance(data["response"], str) else data["response"]
                except Exception:  # noqa: BLE001
                    parsed = {"text": data.get("response")}
                return {"model": model, "response": parsed, "simulated": False}
            return {"model": model, "response": data, "simulated": False}
        except Exception:
            # Fallback simulator
            return {
                "model": model,
                "response": {
                    "summary": "fallback simulated response",
                    "hypotheses": [
                        {"title": "Missing CSP", "confidence": 0.5, "remediation": "Add strong Content-Security-Policy."}
                    ],
                },
                "simulated": True,
            }


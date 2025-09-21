from __future__ import annotations

import os
import re
from typing import Any, Dict

from anthropic import Anthropic, APIStatusError

from .config import settings


REDACTION_RE = re.compile(r"(?i)(bearer\s+[a-z0-9\-_.]+|api[_-]?key\s*[=:]\s*\S+|secret\s*[:=]\s*\S+)")


def redact(text: str) -> str:
    return REDACTION_RE.sub("[REDACTED]", text)


async def call_claude(role: str, prompt: str, model: str = "claude-3-5-haiku-20241022", max_tokens: int = 1000) -> Dict[str, Any]:
    """Call Anthropic Claude safely via the gateway.

    - Requires CLAUDE_API_KEY env var. Raw key is never logged or returned.
    - Prompts are redacted before audit.
    - If key is missing or call fails, returns a stub response.
    """
    api_key = settings.claude_api_key
    if not api_key:
        return {
            "model": model,
            "role": role,
            "response": {"summary": "gateway disabled", "triage": []},
            "disabled": True,
        }

    client = Anthropic(api_key=api_key)
    safe_prompt = redact(prompt)
    try:
        resp = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": safe_prompt}],
        )
        content = "".join([b.text for b in resp.content if hasattr(b, "text")])
        return {
            "model": model,
            "role": role,
            "response": {"text": content},
            "disabled": False,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "model": model,
            "role": role,
            "response": {"error": str(exc), "summary": "stubbed failure"},
            "disabled": False,
        }


from __future__ import annotations

import re
import threading
import time
from typing import Dict, Tuple

from .auth_manifest import verify_manifest
from .config import settings
from .jobs import Job


class _TokenBucket:
    def __init__(self, rate_per_sec: float, capacity: float | None = None) -> None:
        self.rate = max(rate_per_sec, 0.0001)
        self.capacity = capacity or self.rate
        self.tokens = self.capacity
        self.updated_at = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, amount: float = 1.0) -> Tuple[bool, float]:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.updated_at
            self.updated_at = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True, 0.0
            deficit = amount - self.tokens
            wait = deficit / self.rate
            return False, wait


class RateLimiter:
    def __init__(self) -> None:
        self.global_bucket = _TokenBucket(settings.global_rps, capacity=settings.global_rps)
        self.per_target_buckets: Dict[str, _TokenBucket] = {}
        self.lock = threading.Lock()

    def check(self, target: str) -> Tuple[bool, float]:
        ok_g, wait_g = self.global_bucket.consume(1.0)
        if not ok_g:
            return False, wait_g
        with self.lock:
            bucket = self.per_target_buckets.get(target)
            if bucket is None:
                rate = settings.per_target_rps
                bucket = _TokenBucket(rate, capacity=rate)
                self.per_target_buckets[target] = bucket
        ok_t, wait_t = bucket.consume(1.0)
        if not ok_t:
            return False, max(wait_t, settings.backoff_seconds)
        return True, 0.0


rate_limiter = RateLimiter()


SAFE_PLUGIN_ALLOWLIST = {"crawler", "header_checker"}


def _host_in_scope(target: str, scope_list: list[str]) -> bool:
    """Very simple scope match: exact host or suffix match if scope starts with a dot."""
    # Extract host
    host_match = re.match(r"^[a-z]+://([^/]+)", target)
    host = host_match.group(1) if host_match else target
    for entry in scope_list:
        entry = entry.strip()
        if not entry:
            continue
        if entry.startswith(".") and (host.endswith(entry) or host == entry.lstrip(".")):
            return True
        if host == entry:
            return True
    return False


def validate_job(job: Job) -> Tuple[bool, str]:
    ok, msg = verify_manifest(job.manifest)
    if not ok:
        return False, f"manifest invalid: {msg}"

    scope = job.manifest.get("target_scope", job.scope)
    if not _host_in_scope(job.target, scope):
        return False, "target not in authorized scope"

    # Mode enforcement
    if job.mode == "active":
        if not job.manifest.get("active_consent", False):
            return False, "active mode requested but manifest active_consent is false"
        if not job.approved_active:
            return False, "active mode requested but operator approval missing"

    # Allowed plugins
    allowed_plugins = set(job.manifest.get("allowed_plugins", list(SAFE_PLUGIN_ALLOWLIST)))
    disallowed = allowed_plugins - SAFE_PLUGIN_ALLOWLIST
    if disallowed:
        # Only allow known safe plugins in starter repo
        return False, f"disallowed plugins requested: {sorted(disallowed)}"

    return True, "ok"


def validate_plugin(job: Job, plugin_meta: dict) -> Tuple[bool, str]:
    # HTTP methods allowed
    http_methods = plugin_meta.get("http_methods", ["GET"]) or ["GET"]
    for method in http_methods:
        if method.upper() not in settings.allowed_http_methods:
            return False, f"HTTP method not allowed by policy: {method}"

    # Plugin must be in safe allowlist and allowed by manifest
    name = plugin_meta.get("name")
    if name not in SAFE_PLUGIN_ALLOWLIST:
        return False, f"plugin not allowed: {name}"
    allowed_plugins = set(job.manifest.get("allowed_plugins", list(SAFE_PLUGIN_ALLOWLIST)))
    if name not in allowed_plugins:
        return False, f"plugin {name} not allowed by manifest"

    # Active checks enforcement: all starter plugins are passive
    if not plugin_meta.get("safe_default", True) and job.mode == "active":
        # In this starter repo, we simply block non-safe_default
        return False, f"plugin {name} not marked safe_default"

    return True, "ok"


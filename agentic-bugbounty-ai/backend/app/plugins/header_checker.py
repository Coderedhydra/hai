from __future__ import annotations

"""
Header checker plugin (safe). Performs a single GET to the target and evaluates
security-related headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
and cookie flags where available. Non-destructive.
"""

from typing import Any, Dict, List

import httpx

metadata = {
    "name": "header_checker",
    "safe_default": True,
    "required_manifest_scopes": ["web"],
    "http_methods": ["GET"],
}


def run(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    target = context["target"]
    findings: List[Dict[str, Any]] = []
    try:
        res = httpx.get(target, timeout=10.0, follow_redirects=True)
        headers = {k.lower(): v for k, v in res.headers.items()}
        # CSP
        if "content-security-policy" not in headers:
            findings.append(
                {
                    "title": "Missing Content-Security-Policy",
                    "severity": "medium",
                    "confidence": 0.7,
                    "remediation": "Add a strict CSP limiting script, style, and frame sources.",
                }
            )
        # HSTS
        if "strict-transport-security" not in headers and target.startswith("https://"):
            findings.append(
                {
                    "title": "Missing Strict-Transport-Security",
                    "severity": "medium",
                    "confidence": 0.7,
                    "remediation": "Enable HSTS with includeSubDomains and preload where appropriate.",
                }
            )
        # Frame options
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append(
                {
                    "title": "Missing clickjacking protection",
                    "severity": "low",
                    "confidence": 0.6,
                    "remediation": "Add X-Frame-Options or a CSP frame-ancestors directive.",
                }
            )
        # MIME sniffing
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(
                {
                    "title": "Missing X-Content-Type-Options: nosniff",
                    "severity": "low",
                    "confidence": 0.6,
                    "remediation": "Set X-Content-Type-Options to nosniff.",
                }
            )
        # Basic cookie flags indicators (not reading cookies from JS; server-set headers only)
        set_cookie = headers.get("set-cookie", "")
        if set_cookie and ("secure" not in set_cookie.lower() or "httponly" not in set_cookie.lower()):
            findings.append(
                {
                    "title": "Set-Cookie lacks Secure and/or HttpOnly",
                    "severity": "low",
                    "confidence": 0.6,
                    "remediation": "Ensure cookies are set with Secure and HttpOnly flags.",
                }
            )
    except Exception as exc:  # noqa: BLE001
        findings.append({"title": "Header check failed", "severity": "info", "confidence": 0.3, "error": str(exc)})
    return findings


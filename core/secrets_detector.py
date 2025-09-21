#!/usr/bin/env python3
"""
Secrets Detector
================

Detect API keys and sensitive tokens in text/content and local files.
"""

import re
from typing import List, Dict


class SecretsDetector:
    """Detect common API keys and secrets via regex heuristics."""

    def __init__(self):
        # Curated patterns with conservative matching to reduce false positives
        self.patterns = [
            # AWS Access Key ID (AKIA...)
            (r"\bAKIA[0-9A-Z]{16}\b", "AWS Access Key ID", True),
            # AWS Secret Access Key (40 base64 chars)
            (r"\b(?<![A-Za-z0-9+/=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])\b", "AWS Secret Access Key", True),
            # Google API Key (AIza...)
            (r"\bAIza[0-9A-Za-z\-_]{35}\b", "Google API Key", True),
            # GitHub Personal Access Token (ghp_)
            (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub Personal Access Token", True),
            # Slack token
            (r"\bxox[baprs]-[A-Za-z0-9\-]{10,48}\b", "Slack Token", True),
            # Stripe secret keys
            (r"\bsk_(live|test)_[A-Za-z0-9]{24,}\b", "Stripe Secret Key", True),
            # OpenAI API key
            (r"\bsk-[A-Za-z0-9]{32,}\b", "OpenAI API Key", True),
            # Generic bearer token
            (r"\bBearer\s+[A-Za-z0-9\-\.\_~\+\/=]{20,}\b", "Bearer Token", False),
            # Private key headers
            (r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----", "Private Key", True),
        ]

    def find_in_text(self, text: str) -> List[Dict[str, object]]:
        findings: List[Dict[str, object]] = []
        if not text:
            return findings
        for pattern, name, high_risk in self.patterns:
            for m in re.finditer(pattern, text):
                snippet = self._extract_snippet(text, m.start(), m.end())
                findings.append({
                    'type': name,
                    'match': m.group(0),
                    'index': m.start(),
                    'context': snippet,
                    'confidence': 0.9 if high_risk else 0.7,
                    'high_risk': high_risk
                })
        return findings

    def _extract_snippet(self, text: str, start: int, end: int, radius: int = 80) -> str:
        s = max(0, start - radius)
        e = min(len(text), end + radius)
        return text[s:e]


#!/usr/bin/env python3
"""
Code and Web Search Integration
===============================

Provides simple local repository scanning and optional web search scraping
to detect secrets exposure in external sources and code.
"""

import os
import re
from typing import List, Dict

from .secrets_detector import SecretsDetector


class LocalRepoScanner:
    """Scan local repository files for secrets using regex detectors."""

    def __init__(self, root_path: str = '.'):
        self.root_path = root_path
        self.detector = SecretsDetector()
        self._ignore_dirs = {'.git', 'node_modules', '.venv', '__pycache__', 'dist', 'build', '.next', '.cache'}
        self._text_ext = {
            '.py', '.js', '.ts', '.tsx', '.jsx', '.json', '.yml', '.yaml', '.ini', '.env', '.toml', '.md', '.txt', '.html', '.css', '.sql', '.sh', '.cfg'
        }

    def scan(self, max_file_size: int = 2000000) -> List[Dict[str, object]]:
        findings: List[Dict[str, object]] = []
        for dirpath, dirnames, filenames in os.walk(self.root_path):
            dirnames[:] = [d for d in dirnames if d not in self._ignore_dirs]
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext and ext not in self._text_ext:
                    continue
                fpath = os.path.join(dirpath, filename)
                try:
                    if os.path.getsize(fpath) > max_file_size:
                        continue
                    with open(fpath, 'r', errors='ignore') as f:
                        content = f.read()
                    file_findings = self.detector.find_in_text(content)
                    for fnd in file_findings:
                        fnd['file'] = fpath
                    findings.extend(file_findings)
                except Exception:
                    continue
        return findings


class SimpleWebSearcher:
    """Very basic web search using DuckDuckGo HTML (no API keys)."""

    def __init__(self):
        try:
            import requests  # type: ignore
            self.requests = requests
        except Exception:
            self.requests = None

    def search(self, query: str, limit: int = 5) -> List[str]:
        if not self.requests:
            return []
        try:
            resp = self.requests.get(
                'https://duckduckgo.com/html/',
                params={'q': query}, timeout=10
            )
            urls = re.findall(r'href=\"(https?://[^\"]+)\"', resp.text)
            seen = set()
            results = []
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    results.append(u)
                if len(results) >= limit:
                    break
            return results
        except Exception:
            return []


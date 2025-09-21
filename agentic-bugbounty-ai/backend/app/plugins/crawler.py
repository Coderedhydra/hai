from __future__ import annotations

"""
Passive crawler plugin (safe). Uses only GET requests to fetch pages and extract links.
No destructive actions. Playwright is optional; fallback to httpx + simple HTML parsing.
"""

import asyncio
import re
from typing import Any, Dict, List, Set

import httpx

metadata = {
    "name": "crawler",
    "safe_default": True,
    "required_manifest_scopes": ["web"],
    "http_methods": ["GET"],
}


async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[str, str | None]:
    try:
        res = await client.get(url, timeout=10.0, follow_redirects=True)
        content_type = res.headers.get("content-type", "")
        if "text/html" in content_type:
            return url, res.text[:200000]
        return url, None
    except Exception:  # noqa: BLE001
        return url, None


def _extract_links(base: str, html: str) -> List[str]:
    # Simple regex-based extraction for starter purposes
    links = re.findall(r"href=\"(.*?)\"", html, flags=re.IGNORECASE)
    absolute: List[str] = []
    for link in links:
        if link.startswith("http://") or link.startswith("https://"):
            absolute.append(link)
        elif link.startswith("/"):
            # Build absolute from base
            m = re.match(r"^(https?://[^/]+)", base)
            if m:
                absolute.append(m.group(1) + link)
    return list(dict.fromkeys(absolute))


def run(context: Dict[str, Any]) -> List[Dict[str, Any]]:
    target = context["target"]

    async def crawl(start_url: str) -> Dict[str, Any]:
        seen: Set[str] = set()
        to_visit: List[str] = [start_url]
        out: List[str] = []
        async with httpx.AsyncClient() as client:
            while to_visit and len(out) < 50:  # cap for starter
                batch = []
                while to_visit and len(batch) < 5:
                    url = to_visit.pop(0)
                    if url in seen:
                        continue
                    seen.add(url)
                    batch.append(url)
                results = await asyncio.gather(*[_fetch(client, u) for u in batch])
                for url, html in results:
                    out.append(url)
                    if html:
                        links = _extract_links(url, html)
                        for l in links:
                            if l not in seen and l.startswith("http") and l.split("/")[2] == start_url.split("/")[2]:
                                to_visit.append(l)
        return {"start": start_url, "endpoints": out}

    crawl_result = asyncio.run(crawl(target))
    return [
        {
            "title": "Passive crawl completed",
            "severity": "info",
            "confidence": 0.8,
            "data": crawl_result,
        }
    ]


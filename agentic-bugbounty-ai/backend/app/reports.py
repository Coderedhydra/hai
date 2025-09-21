from __future__ import annotations

from typing import Any, Dict, List


def generate_report(job_id: str, target: str, findings: List[Dict[str, Any]], model_provenance: List[Dict[str, str]] | None = None) -> tuple[dict, str]:
    """Generate JSON and Markdown reports.

    This starter keeps reports simple and non-destructive. Findings should be
    safe observations (e.g., headers missing) with confidence estimates.
    """
    model_provenance = model_provenance or []
    summary = {
        "job_id": job_id,
        "target": target,
        "findings_count": len(findings),
    }
    report_json = {
        "summary": summary,
        "findings": findings,
        "model_provenance": model_provenance,
        "sections": {
            "executive_summary": f"Scan of {target} completed. {len(findings)} safe findings recorded.",
            "remediation_guidance": "Review each finding and apply standard hardening: secure headers, strong CSP, HSTS, cookie flags, and least privilege. Validate inputs server-side and add monitoring for anomalies.",
        },
    }

    lines: List[str] = []
    lines.append(f"# Report for job {job_id}\n")
    lines.append(f"Target: {target}\n")
    lines.append("## Executive Summary\n")
    lines.append(report_json["sections"]["executive_summary"] + "\n\n")
    lines.append("## Findings\n")
    if not findings:
        lines.append("No findings recorded.\n")
    for idx, f in enumerate(findings, start=1):
        lines.append(f"- [{idx}] {f.get('title','Untitled')} (severity: {f.get('severity','info')}, confidence: {f.get('confidence', 0):.2f})\n")
        if f.get("evidence_ref"):
            lines.append(f"  Evidence: {f['evidence_ref']}\n")
        if f.get("remediation"):
            lines.append(f"  Remediation: {f['remediation']}\n")
    lines.append("\n## Model Provenance\n")
    for mp in model_provenance:
        lines.append(f"- {mp.get('role')}: {mp.get('model')}\n")

    return report_json, "\n".join(lines)


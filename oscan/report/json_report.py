"""SIEM-friendly JSON report."""

from __future__ import annotations

import json
import time
from typing import List

from ..core.finding import Finding
from ..core.scoring import ScanSummary


def build(target: str, profile: str, summary: ScanSummary, findings: List[Finding], meta: dict | None = None) -> dict:
    return {
        "tool": "oscan",
        "version": "0.1.0",
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "target": target,
        "profile": profile,
        "summary": {
            "risk_score": summary.risk_score,
            "grade": summary.grade,
            "time_to_compromise": summary.time_to_compromise,
            "counts": summary.counts,
            "total_findings": summary.total_findings,
        },
        "meta": meta or {},
        "findings": [f.to_dict() for f in findings],
    }


def write(path: str, report: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

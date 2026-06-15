"""Aggregate findings into a Risk Score (0-100) and a Time-To-Compromise band.

Modelled on the NetzSchild UX: a single number plus a plain-language estimate
of how quickly the worst issue could realistically be exploited.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .finding import Finding, Severity

_TTC_BY_WORST = {
    Severity.CRITICAL: "minutes to hours",
    Severity.HIGH: "hours to days",
    Severity.MEDIUM: "days to weeks",
    Severity.LOW: "weeks or more",
}


@dataclass
class ScanSummary:
    risk_score: int  # 0 (clean) .. 100 (worst)
    grade: str  # A .. F
    time_to_compromise: str
    counts: dict  # severity name -> count (excluding Info)
    total_findings: int


def _grade(score: int) -> str:
    if score == 0:
        return "A"
    if score < 15:
        return "B"
    if score < 35:
        return "C"
    if score < 60:
        return "D"
    return "F"


def summarize(findings: list[Finding]) -> ScanSummary:
    real = [f for f in findings if f.severity is not Severity.INFO]
    score = min(100, sum(f.severity.weight for f in real))
    counts = Counter(f.severity.value for f in real)

    worst = min((f.severity for f in real), key=lambda s: s.rank, default=None)
    ttc = _TTC_BY_WORST.get(worst, "no obvious quick path found") if worst else "no issues found"

    return ScanSummary(
        risk_score=score,
        grade=_grade(score),
        time_to_compromise=ttc,
        counts=dict(counts),
        total_findings=len(real),
    )

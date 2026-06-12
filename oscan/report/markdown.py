"""Human-readable Markdown report."""

from __future__ import annotations

import time
from typing import List

from ..core.finding import Finding, Severity
from ..core.scoring import ScanSummary

_EMOJI = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "✅",
}


def build(target: str, profile: str, summary: ScanSummary, findings: List[Finding]) -> str:
    lines: list[str] = []
    lines.append(f"# oscan report — {target}")
    lines.append("")
    lines.append(f"- **Scanned:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"- **Profile:** {profile}")
    lines.append(f"- **Risk Score:** {summary.risk_score}/100 (grade {summary.grade})")
    lines.append(f"- **Estimated time-to-compromise:** {summary.time_to_compromise}")
    counts = ", ".join(f"{k}: {v}" for k, v in summary.counts.items()) or "none"
    lines.append(f"- **Findings by severity:** {counts}")
    lines.append("")

    issues = [f for f in findings if f.severity is not Severity.INFO]
    issues.sort(key=lambda f: f.severity.rank)

    if issues:
        lines.append("## Findings")
        lines.append("")
        for f in issues:
            lines.append(f"### {_EMOJI[f.severity]} [{f.severity.value}] {f.id} — {f.title}")
            if f.location:
                lines.append(f"- **Where:** {f.location}")
            if f.evidence:
                lines.append(f"- **Evidence:** {f.evidence}")
            if f.why:
                lines.append(f"- **Why it matters:** {f.why}")
            if f.fix:
                lines.append(f"- **Fix:** {f.fix}")
            if f.enrichment:
                lines.append(f"- **Plain language:** {f.enrichment}")
            if f.references:
                lines.append(f"- **References:** {', '.join(f.references)}")
            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No issues found at this profile. Consider running a higher profile or adding defense-in-depth.")
        lines.append("")

    passed = [f for f in findings if f.severity is Severity.INFO]
    if passed:
        lines.append("## Controls in place / observations")
        lines.append("")
        for f in passed:
            note = f" — {f.evidence}" if f.evidence else ""
            lines.append(f"- ✅ {f.id}: {f.title}{note}")
        lines.append("")

    return "\n".join(lines)


def write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)

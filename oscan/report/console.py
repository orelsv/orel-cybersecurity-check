"""Rich console output: a summary panel plus a findings table."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.finding import Finding, Severity
from ..core.scoring import ScanSummary

_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "green",
}
_GRADE_COLOR = {"A": "bold green", "B": "green", "C": "yellow", "D": "orange1", "F": "bold red"}


def render(
    console: Console, target: str, profile: str, summary: ScanSummary, findings: list[Finding]
) -> None:
    gcol = _GRADE_COLOR.get(summary.grade, "white")
    header = Text()
    header.append(f"Target: {target}\n")
    header.append(f"Profile: {profile}\n")
    header.append("Risk Score: ")
    header.append(f"{summary.risk_score}/100", style=gcol)
    header.append("   Grade: ")
    header.append(summary.grade, style=gcol)
    header.append(f"\nEstimated time-to-compromise: {summary.time_to_compromise}")
    console.print(Panel(header, title="oscan", border_style=gcol))

    issues = sorted(
        (f for f in findings if f.severity is not Severity.INFO), key=lambda f: f.severity.rank
    )
    if not issues:
        console.print("[green]No issues found at this profile.[/green]")
    else:
        table = Table(show_lines=False, expand=True)
        table.add_column("Sev", no_wrap=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Where", overflow="fold")
        for f in issues:
            table.add_row(
                Text(f.severity.value, style=_COLOR[f.severity]),
                f.id,
                f.title,
                f.location or "",
            )
        console.print(table)

    passed = [f for f in findings if f.severity is Severity.INFO]
    if passed:
        console.print(
            f"[green]✓ {len(passed)} controls in place / observations[/green] (see full report for details)"
        )

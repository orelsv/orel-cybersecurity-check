"""The single shape every check produces: a Finding.

Detection logic lives in the checks and is fully deterministic. A Finding
records WHAT was found, WHY it matters, and HOW to fix it - the optional
LLM layer only fills `enrichment`, never the severity or the evidence.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Ordered severity with a scoring weight and a sort rank."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def weight(self) -> int:
        """Contribution to the Risk Score (0-100, higher = worse)."""
        return {
            "Critical": 40,
            "High": 20,
            "Medium": 8,
            "Low": 3,
            "Info": 0,
        }[self.value]

    @property
    def rank(self) -> int:
        """Sort order: 0 = most severe first."""
        return ["Critical", "High", "Medium", "Low", "Info"].index(self.value)


@dataclass
class Finding:
    """A single issue (or, when severity is INFO, an observation / passed check)."""

    id: str                       # stable check id, e.g. "HDR-001"
    title: str                    # short human title
    severity: Severity
    category: str                 # e.g. "Transport & headers", "GDPR"
    why: str = ""                 # one-sentence real attack/impact scenario
    fix: str = ""                 # concrete remediation
    evidence: str = ""            # what was observed (redacted, no secrets)
    location: str = ""            # url / header / file:line
    references: list[str] = field(default_factory=list)
    enrichment: str = ""          # optional plain-language note from the LLM layer

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "why": self.why,
            "fix": self.fix,
            "evidence": self.evidence,
            "location": self.location,
            "references": list(self.references),
        }
        if self.enrichment:
            d["enrichment"] = self.enrichment
        return d


def passed(id: str, title: str, category: str, evidence: str = "", location: str = "") -> Finding:
    """Helper for a positive observation (a control that IS in place)."""
    return Finding(
        id=id,
        title=title,
        severity=Severity.INFO,
        category=category,
        evidence=evidence,
        location=location,
    )

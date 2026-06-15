"""The scan target and the context object handed to every check."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Target:
    """What we are scanning: a live URL, a local repo path, or both."""

    url: str | None = None
    repo: str | None = None

    @property
    def label(self) -> str:
        return self.url or self.repo or "<none>"


@dataclass
class ScanContext:
    """Shared state passed to checks. Checks read from here and may use the
    cached HTTP client; they never mutate global state."""

    target: Target
    http: Any = None  # oscan.core.http.HttpClient (lazy import)
    profile: str = "passive"
    intrusive_allowed: bool = False
    options: dict = field(default_factory=dict)
    cache: dict = field(default_factory=dict)

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

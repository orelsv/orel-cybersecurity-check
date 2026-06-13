"""Check registry: decorate a function with @check and it becomes part of a
scan. Each spec declares the minimum profile at which it runs and what it
needs (a live url, a local repo, or either)."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Callable, List

from .context import ScanContext
from .finding import Finding, Severity
from .safety import profile_rank

CheckFn = Callable[[ScanContext], List[Finding]]


@dataclass
class CheckSpec:
    func: CheckFn
    name: str
    profile: str = "passive"     # minimum profile to run this check
    requires: str = "url"        # "url" | "repo" | "any"


_REGISTRY: List[CheckSpec] = []

# Check modules to import so their @check decorators register. Kept explicit
# for deterministic ordering and so registration failures are obvious.
_CHECK_MODULES = [
    "oscan.checks.transport",
    "oscan.checks.headers",
    "oscan.checks.cookies",
    "oscan.checks.exposure",
    "oscan.checks.secrets_git",
    "oscan.checks.gdpr",
    "oscan.checks.cors",
    "oscan.checks.api",
    "oscan.checks.injection",
    "oscan.checks.auth",
    "oscan.checks.dos_resilience",
]


def check(name: str, *, profile: str = "passive", requires: str = "url") -> Callable[[CheckFn], CheckFn]:
    def deco(func: CheckFn) -> CheckFn:
        _REGISTRY.append(CheckSpec(func, name, profile, requires))
        return func
    return deco


def load_checks() -> None:
    """Import all check modules once so the registry is populated."""
    for mod in _CHECK_MODULES:
        try:
            importlib.import_module(mod)
        except Exception:
            # A missing optional check module must not break the whole scan.
            continue


def checks_for_profile(profile: str) -> List[CheckSpec]:
    limit = profile_rank(profile)
    return [c for c in _REGISTRY if profile_rank(c.profile) <= limit]


def _applicable(spec: CheckSpec, ctx: ScanContext) -> bool:
    if spec.requires == "url":
        return bool(ctx.target.url)
    if spec.requires == "repo":
        return bool(ctx.target.repo)
    return bool(ctx.target.url or ctx.target.repo)


def run_checks(ctx: ScanContext, profile: str) -> List[Finding]:
    """Run every applicable check for the profile. A crash in one check is
    captured as an Info finding rather than aborting the scan."""
    load_checks()
    findings: List[Finding] = []
    for spec in checks_for_profile(profile):
        if not _applicable(spec, ctx):
            continue
        try:
            result = spec.func(ctx) or []
            findings.extend(result)
        except Exception as exc:  # noqa: BLE001 - resilience over strictness
            findings.append(Finding(
                id="ENGINE-ERR",
                title=f"Check '{spec.name}' failed to run",
                severity=Severity.INFO,
                category="Engine",
                evidence=f"{type(exc).__name__}: {exc}",
            ))
    return findings

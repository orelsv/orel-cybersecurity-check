"""Authorization gate, scope allowlist, and audit logging.

This module is the reason the tool is a *self-assessment* tool and not an
attack tool. Intrusive checks (the `active` profile) cannot run unless the
caller explicitly asserts authorization, the target is in scope, and the
action is recorded in an audit log.

Design notes:
- `passive` / `standard` profiles only observe (GET requests, header/cookie
  inspection). They need no gate.
- `active` adds non-destructive probes (injection markers, an auth-lockout
  check, a small DoS-resilience burst). It is gated here.
- There is deliberately no DDoS flood and no password cracker anywhere in the
  codebase; "active" verifies that *defenses exist*, it does not attack.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

PROFILES = ("passive", "standard", "active")
_PROFILE_ORDER = {"passive": 0, "standard": 1, "active": 2}

# Profiles at or above this level perform intrusive (non-destructive) probing.
INTRUSIVE_FROM = "active"

# Obvious third-party hosts we refuse to actively probe even with the flag set,
# to make accidental misuse against someone else's property harder.
_BLOCKED_ACTIVE_HOSTS = {
    "google.com",
    "www.google.com",
    "facebook.com",
    "www.facebook.com",
    "microsoft.com",
    "login.microsoftonline.com",
    "github.com",
    "amazon.com",
    "apple.com",
    "cloudflare.com",
    "openai.com",
    "anthropic.com",
}


class AuthorizationError(Exception):
    """Raised when an intrusive scan is requested without proper authorization."""


class ScopeError(Exception):
    """Raised when a target is not covered by the provided scope allowlist."""


def profile_rank(profile: str) -> int:
    try:
        return _PROFILE_ORDER[profile]
    except KeyError as err:
        raise ValueError(f"unknown profile {profile!r}; choose one of {PROFILES}") from err


def is_intrusive(profile: str) -> bool:
    return profile_rank(profile) >= _PROFILE_ORDER[INTRUSIVE_FROM]


def _host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}", scheme="https")
    return (parsed.hostname or "").lower()


def scope_allows(target: str, scope: Iterable[str]) -> bool:
    """A target is allowed if its host equals or is a subdomain of a scope entry."""
    host = _host(target)
    if not host:
        return False
    for entry in scope:
        entry = entry.strip().lower().lstrip("*.")
        if not entry:
            continue
        if host == entry or host.endswith("." + entry):
            return True
    return False


def _state_dir() -> Path:
    override = os.environ.get("OSCAN_STATE_DIR")
    base = Path(override) if override else Path.home() / ".oscan"
    base.mkdir(parents=True, exist_ok=True)
    return base


def write_audit(profile: str, targets: list[str], extra: dict | None = None) -> Path:
    """Append a JSON line recording who ran what, when. Returns the log path."""
    log = _state_dir() / "audit.log"
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "profile": profile,
        "targets": list(targets),
        "user": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
    }
    if extra:
        entry.update(extra)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return log


@dataclass
class AuthDecision:
    """Result of the gate: whether intrusive checks may run, and why/why not."""

    intrusive_allowed: bool
    profile: str
    reason: str = ""
    audit_path: Path | None = None


def authorize(
    profile: str,
    *,
    authorized: bool,
    targets: list[str],
    scope: list[str] | None = None,
    confirm: Callable[[], bool] | None = None,
) -> AuthDecision:
    """Decide whether an intrusive scan may proceed.

    Non-intrusive profiles always pass. Intrusive profiles require ALL of:
      1. `authorized` is True  (the --i-am-authorized flag)
      2. every target is in scope (if a scope allowlist was supplied) and not a
         known third-party host
      3. an explicit confirmation (the `confirm` callback returns True)
    On success the action is recorded via `write_audit`.

    Raises AuthorizationError or ScopeError on refusal.
    """
    if not is_intrusive(profile):
        return AuthDecision(
            intrusive_allowed=False,
            profile=profile,
            reason="non-intrusive profile; observation only",
        )

    if not authorized:
        raise AuthorizationError(
            "The 'active' profile performs intrusive (non-destructive) probing. "
            "Re-run with --i-am-authorized to assert you own the target or have "
            "written permission to test it."
        )

    for target in targets:
        host = _host(target)
        if host in _BLOCKED_ACTIVE_HOSTS:
            raise ScopeError(
                f"Refusing to actively probe third-party host {host!r}. "
                "Active scanning is only for assets you own or are authorized to test."
            )
        if scope is not None and not scope_allows(target, scope):
            raise ScopeError(
                f"Target {target!r} is not covered by the scope allowlist. "
                "Add its host to the --scope file to authorize it explicitly."
            )

    if confirm is not None and not confirm():
        raise AuthorizationError("Active scan declined at the confirmation prompt.")

    audit = write_audit(profile, targets, extra={"scope": scope or []})
    return AuthDecision(
        intrusive_allowed=True,
        profile=profile,
        reason="authorized, in scope, confirmed",
        audit_path=audit,
    )

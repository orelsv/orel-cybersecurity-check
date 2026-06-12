"""The safety gate is the backbone of this tool being a *self-assessment*
scanner. These tests prove intrusive scans cannot run without authorization."""

import json

import pytest

from oscan.core.safety import (
    AuthorizationError,
    ScopeError,
    authorize,
    is_intrusive,
    scope_allows,
    write_audit,
)


def test_passive_and_standard_are_not_intrusive():
    assert not is_intrusive("passive")
    assert not is_intrusive("standard")
    assert is_intrusive("active")


def test_passive_needs_no_authorization():
    decision = authorize("passive", authorized=False, targets=["https://example.com"])
    assert decision.intrusive_allowed is False  # observation only, but allowed to run


def test_active_without_flag_is_blocked():
    with pytest.raises(AuthorizationError):
        authorize("active", authorized=False, targets=["https://mysite.example"])


def test_active_blocks_known_third_party_even_with_flag():
    with pytest.raises(ScopeError):
        authorize(
            "active",
            authorized=True,
            targets=["https://www.google.com"],
            confirm=lambda: True,
        )


def test_active_enforces_scope_allowlist():
    with pytest.raises(ScopeError):
        authorize(
            "active",
            authorized=True,
            targets=["https://not-in-scope.example"],
            scope=["mysite.example"],
            confirm=lambda: True,
        )


def test_active_blocked_when_confirmation_declined():
    with pytest.raises(AuthorizationError):
        authorize(
            "active",
            authorized=True,
            targets=["https://mysite.example"],
            confirm=lambda: False,
        )


def test_active_succeeds_and_writes_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("OSCAN_STATE_DIR", str(tmp_path))
    decision = authorize(
        "active",
        authorized=True,
        targets=["https://mysite.example"],
        scope=["mysite.example"],
        confirm=lambda: True,
    )
    assert decision.intrusive_allowed is True
    assert decision.audit_path.exists()

    line = decision.audit_path.read_text(encoding="utf-8").strip().splitlines()[-1]
    entry = json.loads(line)
    assert entry["profile"] == "active"
    assert entry["targets"] == ["https://mysite.example"]


def test_scope_allows_subdomains():
    assert scope_allows("https://api.mysite.example/x", ["mysite.example"])
    assert scope_allows("https://mysite.example", ["*.mysite.example"])
    assert not scope_allows("https://evil.example", ["mysite.example"])


def test_write_audit_appends(tmp_path, monkeypatch):
    monkeypatch.setenv("OSCAN_STATE_DIR", str(tmp_path))
    write_audit("passive", ["https://a.example"])
    path = write_audit("passive", ["https://b.example"])
    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 2

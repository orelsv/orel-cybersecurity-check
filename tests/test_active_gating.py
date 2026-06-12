"""Active checks must be inert unless the context says intrusive is allowed,
and must degrade gracefully when there is nothing to test."""

from conftest import make_ctx

from oscan.checks.injection import check_injection
from oscan.checks.auth import check_admin_endpoints, check_login_lockout
from oscan.checks.dos_resilience import check_dos_burst
from oscan.core.finding import Severity


def test_injection_inert_without_intrusive_flag():
    ctx = make_ctx("https://mysite.example/search?q=hi", [], text="<html></html>")
    ctx.intrusive_allowed = False
    assert check_injection(ctx) == []


def test_admin_endpoints_inert_without_intrusive_flag():
    ctx = make_ctx("https://mysite.example", [], text="<html></html>")
    ctx.intrusive_allowed = False
    assert check_admin_endpoints(ctx) == []


def test_dos_burst_inert_without_intrusive_flag():
    ctx = make_ctx("https://mysite.example", [], text="")
    ctx.intrusive_allowed = False
    assert check_dos_burst(ctx) == []


def test_injection_reports_no_points_gracefully():
    ctx = make_ctx("https://mysite.example", [], text="<html><body>no links</body></html>")
    ctx.intrusive_allowed = True
    findings = check_injection(ctx)
    assert len(findings) == 1
    assert findings[0].id == "INJ-000"
    assert findings[0].severity is Severity.INFO


def test_login_lockout_skips_without_credentials():
    ctx = make_ctx("https://mysite.example", [], text="")
    ctx.intrusive_allowed = True
    findings = check_login_lockout(ctx)
    assert findings[0].id == "AUTH-LOCK-000"
    assert findings[0].severity is Severity.INFO

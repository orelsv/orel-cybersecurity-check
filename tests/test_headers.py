from conftest import make_ctx

from oscan.checks.headers import check_security_headers
from oscan.core.finding import Severity


def real_ids(findings):
    return {f.id for f in findings if f.severity is not Severity.INFO}


def test_missing_headers_are_flagged():
    ctx = make_ctx("https://mysite.example", [("content-type", "text/html")])
    flagged = real_ids(check_security_headers(ctx))
    assert {"HDR-001", "HDR-002", "HDR-003", "HDR-004", "HDR-005"} <= flagged


def test_present_headers_pass():
    headers = [
        ("strict-transport-security", "max-age=63072000; includeSubDomains"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("content-security-policy", "default-src 'self'"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
    ]
    ctx = make_ctx("https://mysite.example", headers)
    assert real_ids(check_security_headers(ctx)) == set()


def test_csp_frame_ancestors_counts_as_clickjacking_protection():
    headers = [("content-security-policy", "default-src 'self'; frame-ancestors 'none'")]
    ctx = make_ctx("https://mysite.example", headers)
    assert "HDR-003" not in real_ids(check_security_headers(ctx))


def test_version_disclosure_flagged():
    ctx = make_ctx("https://mysite.example", [("server", "nginx/1.18.0")])
    assert "HDR-006" in real_ids(check_security_headers(ctx))

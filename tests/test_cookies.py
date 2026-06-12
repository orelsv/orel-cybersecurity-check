from conftest import make_ctx

from oscan.checks.cookies import check_cookies, _parse_set_cookie
from oscan.core.finding import Severity


def ids(findings):
    return {f.id for f in findings}


def test_parse_set_cookie_flags():
    c = _parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    assert c["name"] == "sid"
    assert c["secure"] and c["httponly"]
    assert c["samesite"] == "lax"


def test_insecure_cookie_flagged_high():
    ctx = make_ctx("https://mysite.example", [("set-cookie", "sid=abc; Path=/")])
    findings = check_cookies(ctx)
    by_id = {f.id: f for f in findings}
    assert by_id["COOKIE-001"].severity is Severity.HIGH   # missing Secure
    assert "COOKIE-002" in by_id                            # missing HttpOnly
    assert "COOKIE-003" in by_id                            # weak SameSite


def test_well_configured_cookie_has_no_issues():
    ctx = make_ctx(
        "https://mysite.example",
        [("set-cookie", "sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict")],
    )
    findings = check_cookies(ctx)
    real = [f for f in findings if f.severity is not Severity.INFO]
    assert real == []


def test_token_in_url_flagged():
    ctx = make_ctx("https://mysite.example/cb?access_token=xyz", [])
    findings = check_cookies(ctx)
    assert "TOKEN-001" in ids(findings)


def test_jwt_in_cookie_noted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdef"
    ctx = make_ctx("https://mysite.example", [("set-cookie", f"t={jwt}; Secure; HttpOnly; SameSite=Lax")])
    findings = check_cookies(ctx)
    assert "COOKIE-004" in ids(findings)

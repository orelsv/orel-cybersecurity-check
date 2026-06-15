import base64
import json

from conftest import make_ctx

from oscan.checks.auth import check_jwt


def _b64(d: dict) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=")
    return raw.decode()


def _token(header: dict, payload: dict, sig: str = "c2ln") -> str:
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


def ids(findings):
    return {f.id for f in findings}


def test_hmac_alg_flagged():
    tok = _token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
    ctx = make_ctx("https://x.example", [("set-cookie", f"t={tok}; Secure; HttpOnly")])
    got = ids(check_jwt(ctx))
    assert "JWT-004" in got  # symmetric HMAC -> alg-confusion risk
    assert "JWT-001" not in got  # not alg=none


def test_empty_signature_flagged():
    tok = _token({"alg": "HS256"}, {"sub": "1", "exp": 9999999999}, sig="")
    ctx = make_ctx("https://x.example", [("set-cookie", f"t={tok}; Secure; HttpOnly")])
    assert "JWT-005" in ids(check_jwt(ctx))


def test_alg_none_still_flagged():
    tok = _token({"alg": "none"}, {"sub": "1", "exp": 9999999999}, sig="")
    ctx = make_ctx("https://x.example", [("set-cookie", f"t={tok}; Secure; HttpOnly")])
    got = ids(check_jwt(ctx))
    assert "JWT-001" in got
    assert "JWT-005" not in got  # alg=none is reported as JWT-001, not empty-sig


def test_rs256_no_hmac_finding():
    tok = _token({"alg": "RS256"}, {"sub": "1", "exp": 9999999999})
    ctx = make_ctx("https://x.example", [("set-cookie", f"t={tok}; Secure; HttpOnly")])
    assert "JWT-004" not in ids(check_jwt(ctx))

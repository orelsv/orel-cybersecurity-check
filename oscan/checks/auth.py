"""Auth hardening checks.

- JWT hygiene (standard): decode (never verify) any JWT in cookies and flag
  alg=none / missing expiry / sensitive claims.
- Admin endpoint exposure (active): GET a few well-known admin/debug paths and
  report ones that answer without authentication.
- Login lockout (active): the *reframed* "brute force" — a hard-capped number
  of failed logins against an account YOU supply, purely to confirm that
  rate-limiting / lockout / CAPTCHA kicks in. It is not a password cracker.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "Auth hardening"
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_SENSITIVE_CLAIMS = {"password", "passwd", "secret", "ssn", "credit_card", "cvv"}
_LOCKOUT_HINTS = re.compile(r"(too many|locked|temporarily disabled|try again later|captcha|rate.?limit)", re.I)
_ADMIN_PATHS = ["admin", "admin/", "api/admin", "api/debug", "debug", "actuator", "actuator/env",
                "api/users", "wp-admin/", "phpmyadmin/"]
_MAX_LOGIN_ATTEMPTS = 8


def _b64url(part: str) -> dict:
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad))


@check("jwt", profile="standard", requires="url")
def check_jwt(ctx: ScanContext) -> list[Finding]:
    resp = ctx.http.get_cached(ctx.target.url)
    raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    findings: list[Finding] = []
    for raw in raw_cookies:
        m = _JWT_RE.search(raw)
        if not m:
            continue
        token = m.group(0)
        try:
            header = _b64url(token.split(".")[0])
            payload = _b64url(token.split(".")[1])
        except Exception:
            continue
        if str(header.get("alg", "")).lower() == "none":
            findings.append(Finding(
                id="JWT-001", title="JWT uses alg=none (unsigned)",
                severity=Severity.CRITICAL, category=CATEGORY, location=ctx.target.url,
                why="An unsigned JWT can be forged by anyone, allowing trivial account/role takeover.",
                fix="Reject alg=none; require a strong signing algorithm (e.g. RS256/EdDSA) and verify it.",
            ))
        if "exp" not in payload:
            findings.append(Finding(
                id="JWT-002", title="JWT has no expiry (exp) claim",
                severity=Severity.MEDIUM, category=CATEGORY, location=ctx.target.url,
                why="A token that never expires stays valid forever if stolen.",
                fix="Add a short 'exp' claim and refresh tokens server-side.",
            ))
        leaked = _SENSITIVE_CLAIMS & {str(k).lower() for k in payload}
        if leaked:
            findings.append(Finding(
                id="JWT-003", title="JWT carries sensitive claims",
                severity=Severity.HIGH, category=CATEGORY, location=ctx.target.url,
                evidence=f"Claims: {', '.join(sorted(leaked))}",
                why="JWT payloads are only base64 (not encrypted); anyone can read these values.",
                fix="Never put secrets/PII in a JWT payload; keep only an opaque user id.",
            ))

        alg = str(header.get("alg", "")).upper()
        parts = token.split(".")
        sig = parts[2] if len(parts) > 2 else ""
        if alg.startswith("HS"):
            findings.append(Finding(
                id="JWT-004", title=f"JWT signed with symmetric HMAC ({alg})",
                severity=Severity.MEDIUM, category=CATEGORY, location=ctx.target.url,
                why="HMAC keys are shared secrets: a leaked/weak secret forges any token, and servers "
                    "that accept multiple algorithms are open to RS256→HS256 confusion (the public key is "
                    "used as the HMAC secret).",
                fix="Prefer asymmetric signing (RS256/EdDSA); pin one expected algorithm and reject all others; "
                    "use a long, random HMAC secret if HMAC is required.",
                references=["https://portswigger.net/web-security/jwt/algorithm-confusion"],
            ))
        if not sig and alg != "NONE":
            findings.append(Finding(
                id="JWT-005", title="JWT has an empty signature",
                severity=Severity.HIGH, category=CATEGORY, location=ctx.target.url,
                why="A token whose signature segment is empty is effectively unsigned and can be tampered with.",
                fix="Ensure tokens are signed and the server verifies the signature before trusting claims.",
            ))
    return findings


@check("admin_endpoints", profile="active", requires="url")
def check_admin_endpoints(ctx: ScanContext) -> list[Finding]:
    if not ctx.intrusive_allowed:
        return []
    base = ctx.target.url if ctx.target.url.endswith("/") else ctx.target.url + "/"
    findings: list[Finding] = []
    for path in _ADMIN_PATHS:
        url = urljoin(base, path)
        try:
            resp = ctx.http.get(url, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        body = (resp.text or "")[:5000]
        low = body.lower()
        has_login = "password" in low and "<input" in low
        looks_admin = any(k in low for k in ("dashboard", "admin panel", "users", "actuator")) or low.strip().startswith("{")
        if looks_admin and not has_login:
            findings.append(Finding(
                id="AUTH-001", title=f"Admin/debug endpoint reachable without auth: /{path}",
                severity=Severity.HIGH, category=CATEGORY, location=url,
                evidence=f"HTTP 200, no login required ({len(body)} bytes)",
                why="An unauthenticated admin/debug endpoint can leak data or allow privileged actions.",
                fix="Require authentication and authorization on all admin/debug/management routes; disable debug in prod.",
            ))
    if not findings:
        findings.append(passed("AUTH-001", "No unauthenticated admin/debug endpoints found", CATEGORY,
                               location=ctx.target.url))
    return findings


@check("login_lockout", profile="active", requires="url")
def check_login_lockout(ctx: ScanContext) -> list[Finding]:
    """Verify a login endpoint rate-limits / locks out repeated failures.

    Requires the user to supply their OWN test account via options:
    login_url, login_user, login_userfield, login_passfield.
    """
    if not ctx.intrusive_allowed:
        return []
    login_url = ctx.option("login_url")
    user = ctx.option("login_user")
    if not login_url or not user:
        return [Finding(
            id="AUTH-LOCK-000", title="Login lockout test skipped (no credentials supplied)",
            severity=Severity.INFO, category=CATEGORY, location=ctx.target.url,
            evidence="Provide --login-url and --login-user (your own test account) to run this check.",
            fix="Re-run with --login-url/--login-user to verify lockout exists. oscan never cracks passwords; "
                "it sends a few failed logins to confirm the defense triggers.",
        )]

    userfield = ctx.option("login_userfield", "username")
    passfield = ctx.option("login_passfield", "password")
    attempts = min(ctx.option("login_attempts", 6), _MAX_LOGIN_ATTEMPTS)

    defended = False
    statuses = []
    for i in range(attempts):
        data = {userfield: user, passfield: f"wrong-oscan-{i}-{'x'*6}"}
        try:
            resp = ctx.http.post(login_url, data=data, follow_redirects=False)
        except Exception:
            break
        statuses.append(resp.status_code)
        if resp.status_code in (429, 423) or _LOCKOUT_HINTS.search((resp.text or "")[:2000]):
            defended = True
            break

    if defended:
        return [passed("AUTH-LOCK-001", "Login rate-limiting / lockout triggered", CATEGORY,
                       location=login_url, evidence=f"Defense engaged after {len(statuses)} attempts")]
    return [Finding(
        id="AUTH-LOCK-001", title="No login rate-limiting / lockout observed",
        severity=Severity.MEDIUM, category=CATEGORY, location=login_url,
        evidence=f"{len(statuses)} failed logins, no 429/lockout (statuses: {statuses})",
        why="Without lockout or rate-limiting, attackers can brute-force or credential-stuff the login at will.",
        fix="Add rate-limiting, exponential backoff, account lockout, and/or CAPTCHA after a few failures; "
            "consider MFA.",
        references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
    )]

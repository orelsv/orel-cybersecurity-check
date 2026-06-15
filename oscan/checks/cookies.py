"""Cookie & token hygiene.

Grounded in the It's Always Phishing lab: a session cookie IS a bearer token.
If it lacks Secure/HttpOnly/SameSite, or if a token rides in a URL, stealing a
session becomes trivial.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "Cookies & tokens"
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{2,}")
_TOKEN_KEYS = {
    "token",
    "access_token",
    "id_token",
    "auth",
    "apikey",
    "api_key",
    "session",
    "sessionid",
    "sid",
    "jwt",
    "key",
    "secret",
    "password",
}


def _parse_set_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
    samesite = ""
    for p in parts[1:]:
        if p.lower().startswith("samesite="):
            samesite = p.split("=", 1)[1].strip().lower()
    return {
        "name": name,
        "secure": "secure" in attrs,
        "httponly": "httponly" in attrs,
        "samesite": samesite,
        "value": parts[0].split("=", 1)[1] if "=" in parts[0] else "",
    }


@check("cookies", profile="passive", requires="url")
def check_cookies(ctx: ScanContext) -> list[Finding]:
    resp = ctx.http.get_cached(ctx.target.url)
    url = str(resp.url)
    is_https = url.startswith("https://")
    raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    findings: list[Finding] = []

    if not raw_cookies:
        findings.append(
            passed("COOKIE-000", "No cookies set on the home page", CATEGORY, location=url)
        )

    for raw in raw_cookies:
        c = _parse_set_cookie(raw)
        loc = f"{url} (Set-Cookie: {c['name']})"

        if is_https and not c["secure"]:
            findings.append(
                Finding(
                    id="COOKIE-001",
                    title=f"Cookie '{c['name']}' missing Secure flag",
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    location=loc,
                    why="Without Secure, the cookie is sent over any plaintext request and can be captured on the network.",
                    fix="Add the Secure attribute to every cookie on an HTTPS site.",
                )
            )
        if not c["httponly"]:
            findings.append(
                Finding(
                    id="COOKIE-002",
                    title=f"Cookie '{c['name']}' missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    location=loc,
                    why="Without HttpOnly, any XSS on the page can read the cookie and hijack the session.",
                    fix="Add HttpOnly to session/auth cookies so JavaScript cannot read them.",
                )
            )
        if c["samesite"] in ("", "none"):
            findings.append(
                Finding(
                    id="COOKIE-003",
                    title=f"Cookie '{c['name']}' has weak SameSite ({c['samesite'] or 'unset'})",
                    severity=Severity.LOW,
                    category=CATEGORY,
                    location=loc,
                    why="A missing or None SameSite allows the cookie to ride cross-site requests, enabling CSRF.",
                    fix="Set SameSite=Lax (or Strict for sensitive cookies); use None only with Secure and a clear reason.",
                )
            )
        if _JWT_RE.search(c["value"]):
            findings.append(
                Finding(
                    id="COOKIE-004",
                    title=f"JWT stored in cookie '{c['name']}'",
                    severity=Severity.INFO,
                    category=CATEGORY,
                    location=loc,
                    evidence="JWT-shaped value detected (redacted)",
                    why="A JWT in a cookie is a bearer token; if the cookie is stealable, so is the identity.",
                    fix="Ensure the cookie is Secure + HttpOnly + SameSite, the JWT is short-lived, and consider token binding.",
                )
            )

    # Tokens in the URL (request target + final redirected URL).
    for candidate in {ctx.target.url, url}:
        q = parse_qs(urlparse(candidate).query)
        leaked = [k for k in q if k.lower() in _TOKEN_KEYS]
        if leaked or _JWT_RE.search(candidate):
            findings.append(
                Finding(
                    id="TOKEN-001",
                    title="Token or credential present in URL",
                    severity=Severity.HIGH,
                    category=CATEGORY,
                    location=candidate.split("?")[0],
                    evidence=f"Suspicious query keys: {', '.join(leaked) or 'JWT in path'}",
                    why="URLs are logged by servers, proxies and browser history, and leak via the Referer header.",
                    fix="Never put tokens in URLs; use Authorization headers or Secure+HttpOnly cookies.",
                )
            )
            break

    return findings

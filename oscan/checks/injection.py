"""Injection probes (active profile, non-destructive).

We only ever send *detection markers*: a reflected string to spot XSS, a single
quote / boolean pair to spot SQL handling, a traversal marker, and a redirect
marker. There are no destructive payloads (no DROP, no stacked queries) and the
shared HTTP throttle keeps the request rate gentle.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "Injection & input"
_MAX_POINTS = 6

_SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|mysqli?_|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|"
    r"unclosed quotation mark|quoted string not properly terminated|"
    r"Microsoft OLE DB Provider for SQL Server|Warning: pg_)",
    re.I,
)


def _split(url: str):
    p = urlparse(url)
    return p, dict(parse_qsl(p.query))


def _with_params(parsed, params: dict) -> str:
    from urllib.parse import urlencode
    return urlunparse(parsed._replace(query=urlencode(params)))


def _targets_with_params(ctx: ScanContext) -> list[str]:
    out: list[str] = []
    if urlparse(ctx.target.url).query:
        out.append(ctx.target.url)
    try:
        home = ctx.http.get_cached(ctx.target.url)
        base_host = urlparse(str(home.url)).hostname
        soup = BeautifulSoup(home.text or "", "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href")
            if not href:
                continue
            absu = urljoin(str(home.url), href)
            p = urlparse(absu)
            if p.hostname == base_host and p.query and absu not in out:
                out.append(absu)
            if len(out) >= _MAX_POINTS:
                break
    except Exception:
        pass
    return out[:_MAX_POINTS]


@check("injection", profile="active", requires="url")
def check_injection(ctx: ScanContext) -> list[Finding]:
    if not ctx.intrusive_allowed:
        return []
    points = _targets_with_params(ctx)
    if not points:
        return [Finding(
            id="INJ-000", title="No parameterized endpoints found to test",
            severity=Severity.INFO, category=CATEGORY, location=ctx.target.url,
            evidence="Active injection probes need URLs with query parameters; none were discovered.",
            fix="Point oscan at a specific endpoint with parameters (e.g. /search?q=...) to test injection.",
        )]

    findings: list[Finding] = []
    for url in points:
        parsed, params = _split(url)
        for name in list(params.keys()):
            findings.extend(_probe_param(ctx, parsed, params, name))
    if not findings:
        findings.append(passed("INJ-001", "No reflected XSS / SQL error signatures detected", CATEGORY,
                               location=ctx.target.url))
    return findings


def _probe_param(ctx: ScanContext, parsed, params: dict, name: str) -> list[Finding]:
    findings: list[Finding] = []
    where = f"{parsed.path or '/'}?{name}="

    # 1. Reflected XSS — benign marker with meaningful characters.
    marker = "oscan" + secrets.token_hex(3)
    xss_payload = f'{marker}\'"<b>'
    p = dict(params); p[name] = xss_payload
    try:
        body = ctx.http.get(_with_params(parsed, p)).text or ""
        if f'{marker}\'"<b>' in body or f'{marker}"<b>' in body:
            findings.append(Finding(
                id="INJ-XSS", title=f"Reflected input not encoded (possible XSS) in '{name}'",
                severity=Severity.HIGH, category=CATEGORY, location=where,
                evidence="Marker reflected with raw < and \" characters",
                why="Unencoded reflection of user input lets an attacker run JavaScript in your users' browsers.",
                fix="Context-encode all output (HTML escape), and add a Content-Security-Policy as defense-in-depth.",
                references=["https://owasp.org/www-community/attacks/xss/"],
            ))
    except Exception:
        pass

    # 2. SQL error-based — a single quote.
    p = dict(params); p[name] = params[name] + "'"
    try:
        body = ctx.http.get(_with_params(parsed, p)).text or ""
        if _SQL_ERRORS.search(body):
            findings.append(Finding(
                id="INJ-SQL", title=f"SQL error triggered by quote in '{name}' (possible SQL injection)",
                severity=Severity.CRITICAL, category=CATEGORY, location=where,
                evidence="Database error message returned after injecting a single quote",
                why="If a single quote reaches the database, an attacker can likely read or modify all data.",
                fix="Use parameterized queries / prepared statements; never build SQL by string concatenation.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            ))
    except Exception:
        pass

    # 3. Path traversal marker.
    p = dict(params); p[name] = "../../../../etc/passwd"
    try:
        body = ctx.http.get(_with_params(parsed, p)).text or ""
        if re.search(r"root:.*:0:0:", body):
            findings.append(Finding(
                id="INJ-LFI", title=f"Path traversal in '{name}' (file disclosure)",
                severity=Severity.CRITICAL, category=CATEGORY, location=where,
                evidence="/etc/passwd contents returned",
                why="An attacker can read arbitrary files from the server, including secrets and source.",
                fix="Never pass user input to file paths; use allowlists and canonicalize paths.",
            ))
    except Exception:
        pass

    # 4. Open redirect marker (only for redirect-ish params).
    if name.lower() in ("next", "url", "redirect", "return", "returnurl", "dest", "continue"):
        p = dict(params); p[name] = "https://oscan-redirect.example/"
        try:
            resp = ctx.http.get(_with_params(parsed, p), follow_redirects=False)
            loc = resp.headers.get("location", "")
            if loc.startswith("https://oscan-redirect.example"):
                findings.append(Finding(
                    id="INJ-REDIR", title=f"Open redirect via '{name}'",
                    severity=Severity.MEDIUM, category=CATEGORY, location=where,
                    evidence=f"Redirected to attacker-controlled URL: {loc}",
                    why="Open redirects are used in phishing to lend your domain's trust to a malicious link.",
                    fix="Allowlist redirect targets or use relative paths only.",
                ))
        except Exception:
            pass

    return findings

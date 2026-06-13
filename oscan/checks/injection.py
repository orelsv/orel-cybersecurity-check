"""Injection probes (active profile, non-destructive).

We only ever send *detection markers*: a reflected string to spot XSS, a single
quote / boolean pair to spot SQL handling, a read-only time-delay payload to spot
blind SQLi, a traversal marker, and a redirect marker. There are no destructive
payloads (no DROP, no stacked writes) and the shared HTTP throttle keeps the
request rate gentle.
"""

from __future__ import annotations

import re
import secrets
import time
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "Injection & input"
_MAX_POINTS = 6
# Time-based blind SQLi is slow (each probe waits out a server-side sleep), so
# only run it on the first few injection points.
_TIMING_MAX_POINTS = 3

_SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|mysqli?_|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|"
    r"unclosed quotation mark|quoted string not properly terminated|"
    r"Microsoft OLE DB Provider for SQL Server|Warning: pg_)",
    re.I,
)
_NOSQL_ERRORS = re.compile(
    r"(MongoError|MongoServerError|Mongoose|CastError|BSONError|"
    r"unexpected token.*in JSON|E11000|couchdb|unknown operator)",
    re.I,
)
# Params whose value is likely fetched server-side (SSRF surface).
_SSRF_PARAMS = {"url", "uri", "link", "src", "source", "dest", "target", "callback",
                "webhook", "image", "img", "fetch", "proxy", "to", "feed", "u"}
# Signatures of cloud instance-metadata responses (SSRF confirmation).
_METADATA_RE = re.compile(r"(ami-id|instance-id|iam/security-credentials|"
                          r"computeMetadata|meta-data/|access_key)", re.I)


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
    for i, url in enumerate(points):
        parsed, params = _split(url)
        for name in list(params.keys()):
            findings.extend(_probe_param(ctx, parsed, params, name,
                                         do_timing=(i < _TIMING_MAX_POINTS)))
    if not findings:
        findings.append(passed("INJ-001", "No reflected XSS / SQL error signatures detected", CATEGORY,
                               location=ctx.target.url))
    return findings


def _time_payloads(orig: str, delay) -> list[str]:
    """Read-only time-delay payloads (MySQL / PostgreSQL). No data is written."""
    return [
        f"{orig}' AND SLEEP({delay})-- -",
        f"{orig}'; SELECT pg_sleep({delay})-- -",
        f"{orig}'||(SELECT pg_sleep({delay}))||'",
    ]


def _probe_param(ctx: ScanContext, parsed, params: dict, name: str, do_timing: bool = False) -> list[Finding]:
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

    # 2b. NoSQL injection — error-based (Mongo/Mongoose/CouchDB signatures).
    p = dict(params); p[name] = params[name] + '\'"\\{'
    try:
        body = ctx.http.get(_with_params(parsed, p)).text or ""
        if _NOSQL_ERRORS.search(body):
            findings.append(Finding(
                id="INJ-NOSQL", title=f"NoSQL error triggered in '{name}' (possible NoSQL injection)",
                severity=Severity.CRITICAL, category=CATEGORY, location=where,
                evidence="NoSQL database error returned after injecting operator characters",
                why="Unsanitized input reaching a NoSQL query (e.g. Mongo) lets an attacker bypass auth or read data.",
                fix="Validate/cast input types, reject query operators ($ne/$gt/$where) in user data, use an ODM safely.",
                references=["https://owasp.org/www-community/Injection_Flaws"],
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

    # 5. SSRF — only for URL-like params; check for cloud-metadata leakage.
    if name.lower() in _SSRF_PARAMS:
        for probe in ("http://169.254.169.254/latest/meta-data/",
                      "http://metadata.google.internal/computeMetadata/v1/"):
            p = dict(params); p[name] = probe
            try:
                body = ctx.http.get(_with_params(parsed, p)).text or ""
            except Exception:
                continue
            if _METADATA_RE.search(body):
                findings.append(Finding(
                    id="INJ-SSRF", title=f"Server-Side Request Forgery via '{name}'",
                    severity=Severity.CRITICAL, category=CATEGORY, location=where,
                    evidence="Cloud instance-metadata content was returned through the parameter",
                    why="The server fetches attacker-supplied URLs, exposing internal services and cloud "
                        "credentials (e.g. the metadata endpoint).",
                    fix="Allowlist outbound hosts, block link-local/internal ranges, and disable unused URL fetching.",
                    references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                ))
                break

    # 6. Time-based blind SQLi — read-only delay, no error message needed.
    if do_timing:
        findings.extend(_probe_time_based(ctx, parsed, params, name, where))

    return findings


def _probe_time_based(ctx: ScanContext, parsed, params: dict, name: str, where: str) -> list[Finding]:
    """Detect blind SQLi by injecting a server-side sleep and measuring the delay.

    Read-only: the payloads only call SLEEP/pg_sleep, never modify data. Gentle:
    one baseline request plus a few delay probes, capped to a few endpoints.
    """
    delay = float(ctx.option("sqli_delay", 3.0))
    threshold = float(ctx.option("sqli_threshold", 2.5))

    try:
        t0 = time.monotonic()
        ctx.http.get(_with_params(parsed, dict(params)))
        baseline = time.monotonic() - t0
    except Exception:
        return []
    # If the normal response is already slower than our delay, timing is unreliable.
    if baseline >= delay:
        return []

    for payload in _time_payloads(params[name], delay):
        p = dict(params); p[name] = payload
        try:
            t0 = time.monotonic()
            ctx.http.get(_with_params(parsed, p))
            elapsed = time.monotonic() - t0
        except Exception:
            continue
        if elapsed - baseline >= threshold:
            return [Finding(
                id="INJ-SQL-TIME", title=f"Time-based blind SQL injection in '{name}'",
                severity=Severity.CRITICAL, category=CATEGORY, location=where,
                evidence=f"Injected sleep({delay}) delayed the response by {elapsed - baseline:.1f}s",
                why="A SLEEP payload that reaches the database means an attacker can read or modify "
                    "all data even when no error or output is visible (blind injection).",
                fix="Use parameterized queries / prepared statements; never build SQL by string concatenation.",
                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
            )]
    return []

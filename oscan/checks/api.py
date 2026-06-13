"""API security checks (OWASP API Top 10 flavoured).

Conservative, low-false-positive, GET-only probes:
- Exposed API documentation / specs / GraphQL introspection (attack-surface map).
- Excessive data exposure: sensitive field names in JSON responses.
- Verbose errors / stack traces leaking internals.

Object-level authorization (BOLA) and mass assignment need two accounts or
state-changing writes to confirm safely, so we flag them as a manual follow-up
(see API-009) rather than probe them blindly.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "API security"

_SENSITIVE_KEY = re.compile(
    r'"(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|'
    r'ssn|social_security|credit_card|card_number|cvv|private_key|password_hash)"\s*:',
    re.I,
)
_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|Werkzeug Debugger|Whitelabel Error Page|"
    r"at [\w.$]+\([\w.]+\.java:\d+\)|System\.\w+Exception|"
    r'"stack"\s*:\s*"|org\.springframework|django\.|node_modules)',
    re.I,
)

_DOC_PROBES = [
    ("swagger.json", lambda t: '"swagger"' in t or '"openapi"' in t),
    ("openapi.json", lambda t: '"openapi"' in t or '"swagger"' in t),
    ("v2/api-docs", lambda t: '"swagger"' in t),
    ("api-docs", lambda t: '"openapi"' in t or '"swagger"' in t),
    ("swagger-ui.html", lambda t: "swagger-ui" in t.lower()),
]


def _looks_json(resp) -> bool:
    ct = ""
    for k, v in resp.headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
    if "json" in ct:
        return True
    body = (resp.text or "").lstrip()[:1]
    return body in ("{", "[")


@check("api_docs", profile="standard", requires="url")
def check_api_docs(ctx: ScanContext) -> list[Finding]:
    base = ctx.target.url if ctx.target.url.endswith("/") else ctx.target.url + "/"
    findings: list[Finding] = []

    for path, valid in _DOC_PROBES:
        url = urljoin(base, path)
        try:
            resp = ctx.http.get(url, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 200 and valid(resp.text or ""):
            findings.append(Finding(
                id="API-001", title=f"Exposed API documentation: /{path}",
                severity=Severity.MEDIUM, category=CATEGORY, location=url,
                evidence="OpenAPI/Swagger spec is publicly reachable",
                why="A public API spec hands an attacker the full list of endpoints, parameters, and auth schemes.",
                fix="Restrict API docs to internal/authenticated access in production.",
            ))

    # GraphQL introspection via GET.
    gql = urljoin(base, "graphql")
    try:
        resp = ctx.http.get(gql, params={"query": "{__schema{types{name}}}"}, follow_redirects=False)
        if resp.status_code == 200 and "__schema" in (resp.text or ""):
            findings.append(Finding(
                id="API-002", title="GraphQL introspection enabled",
                severity=Severity.MEDIUM, category=CATEGORY, location=gql,
                evidence="__schema returned via introspection query",
                why="Introspection exposes the entire GraphQL schema, easing targeted attacks.",
                fix="Disable introspection in production or require authentication for it.",
            ))
    except Exception:
        pass

    if not findings:
        findings.append(passed("API-001", "No exposed API docs / GraphQL introspection found", CATEGORY,
                               location=ctx.target.url))
    return findings


@check("api_excessive_data", profile="standard", requires="url")
def check_excessive_data(ctx: ScanContext) -> list[Finding]:
    try:
        resp = ctx.http.get_cached(ctx.target.url)
    except Exception:
        return []
    if not _looks_json(resp):
        return []
    m = _SENSITIVE_KEY.search(resp.text or "")
    if m:
        return [Finding(
            id="API-003", title="Excessive data exposure in JSON response",
            severity=Severity.HIGH, category=CATEGORY, location=str(resp.url),
            evidence=f"Sensitive field exposed: {m.group(1)}",
            why="The API returns sensitive fields (e.g. password hashes, tokens, PII) the client never needs.",
            fix="Return only the fields the client requires; filter sensitive properties server-side, not in the UI.",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
        )]
    return []


@check("api_verbose_errors", profile="standard", requires="url")
def check_verbose_errors(ctx: ScanContext) -> list[Finding]:
    base = ctx.target.url if ctx.target.url.endswith("/") else ctx.target.url + "/"
    url = urljoin(base, "oscan-nonexistent-%27%22%00")
    try:
        resp = ctx.http.get(url, follow_redirects=False)
    except Exception:
        return []
    if _STACK_TRACE.search((resp.text or "")[:8000]):
        return [Finding(
            id="API-004", title="Verbose error / stack trace disclosure",
            severity=Severity.MEDIUM, category=CATEGORY, location=url,
            evidence="Server returned a stack trace / debug error page",
            why="Stack traces leak framework versions, file paths, and internal logic useful to an attacker.",
            fix="Disable debug mode in production; return generic error pages and log details server-side.",
        )]
    return []

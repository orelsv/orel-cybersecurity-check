"""CORS misconfiguration check.

Sends a request with a foreign `Origin` and inspects the
`Access-Control-Allow-*` response headers. A server that reflects an arbitrary
origin (or uses `*`) together with credentials lets any site read authenticated
responses on behalf of the victim.
"""

from __future__ import annotations

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "CORS"
_EVIL_ORIGIN = "https://oscan-evil.example"


@check("cors", profile="standard", requires="url")
def check_cors(ctx: ScanContext) -> list[Finding]:
    try:
        resp = ctx.http.get(ctx.target.url, headers={"Origin": _EVIL_ORIGIN}, follow_redirects=True)
    except Exception:
        return []
    h = {k.lower(): v for k, v in resp.headers.items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    url = str(resp.url)

    if not acao:
        return [
            passed(
                "CORS-001", "No permissive CORS headers on the home page", CATEGORY, location=url
            )
        ]

    # Reflecting an arbitrary origin (or null) with credentials is the dangerous case.
    if acao == _EVIL_ORIGIN or acao == "null":
        sev = Severity.HIGH if acac == "true" else Severity.MEDIUM
        return [
            Finding(
                id="CORS-001",
                title="CORS reflects an arbitrary Origin",
                severity=sev,
                category=CATEGORY,
                location=url,
                evidence=f"Access-Control-Allow-Origin: {acao}"
                + (" + Allow-Credentials: true" if acac == "true" else ""),
                why="Any website can read this site's responses on behalf of a logged-in user - "
                "with credentials enabled, that means stealing private data.",
                fix="Allowlist trusted origins explicitly; never reflect the request Origin; "
                "don't combine a wildcard/reflected origin with Allow-Credentials: true.",
                references=["https://developer.mozilla.org/docs/Web/HTTP/CORS"],
            )
        ]

    if acao == "*" and acac == "true":
        return [
            Finding(
                id="CORS-002",
                title="CORS wildcard with credentials",
                severity=Severity.HIGH,
                category=CATEGORY,
                location=url,
                evidence="Access-Control-Allow-Origin: * with Allow-Credentials: true",
                why="A wildcard origin combined with credentials exposes authenticated responses to any site.",
                fix="Use an explicit origin allowlist when credentials are allowed; never pair '*' with credentials.",
            )
        ]

    return [
        passed(
            "CORS-001",
            f"CORS present but not reflecting foreign origins ({acao})",
            CATEGORY,
            location=url,
        )
    ]

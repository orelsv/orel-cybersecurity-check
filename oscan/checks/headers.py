"""Security response-header checks (the LearningSteps Lockdown hardening list)."""

from __future__ import annotations

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "Security headers"


def _home(ctx: ScanContext):
    return ctx.http.get_cached(ctx.target.url)


@check("security_headers", profile="passive", requires="url")
def check_security_headers(ctx: ScanContext) -> list[Finding]:
    resp = _home(ctx)
    h = {k.lower(): v for k, v in resp.headers.items()}
    url = str(resp.url)
    findings: list[Finding] = []

    def need(header, fid, title, severity, why, fix, refs=None):
        if header in h:
            findings.append(
                passed(fid, f"{title} present", CATEGORY, evidence=h[header][:120], location=url)
            )
        else:
            findings.append(
                Finding(
                    id=fid,
                    title=f"Missing {title}",
                    severity=severity,
                    category=CATEGORY,
                    location=url,
                    why=why,
                    fix=fix,
                    references=refs or [],
                )
            )

    is_https = url.startswith("https://")
    if is_https:
        need(
            "strict-transport-security",
            "HDR-001",
            "HSTS (Strict-Transport-Security)",
            Severity.MEDIUM,
            "Without HSTS, a single plaintext request can be intercepted and the user downgraded to HTTP.",
            "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains",
            ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"],
        )

    need(
        "x-content-type-options",
        "HDR-002",
        "X-Content-Type-Options",
        Severity.LOW,
        "Browsers may MIME-sniff responses and execute content as a different type, enabling some XSS.",
        "Add: X-Content-Type-Options: nosniff",
    )

    # Clickjacking: either X-Frame-Options OR a CSP frame-ancestors directive.
    csp = h.get("content-security-policy", "")
    if "x-frame-options" in h or "frame-ancestors" in csp.lower():
        findings.append(
            passed("HDR-003", "Clickjacking protection present", CATEGORY, location=url)
        )
    else:
        findings.append(
            Finding(
                id="HDR-003",
                title="No clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                location=url,
                why="The page can be embedded in a hidden iframe and used for clickjacking against your users.",
                fix="Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors none' directive.",
            )
        )

    need(
        "content-security-policy",
        "HDR-004",
        "Content-Security-Policy",
        Severity.MEDIUM,
        "Without a CSP, injected scripts run with no restriction, turning any XSS into full account takeover.",
        "Add a Content-Security-Policy starting from 'default-src self' and tighten from there.",
        ["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
    )

    need(
        "referrer-policy",
        "HDR-005",
        "Referrer-Policy",
        Severity.LOW,
        "Full URLs (possibly with tokens) may leak to third-party sites via the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
    )

    # Version disclosure.
    disclosed = []
    for hdr in ("server", "x-powered-by"):
        val = h.get(hdr, "")
        if val and any(ch.isdigit() for ch in val):
            disclosed.append(f"{hdr}: {val}")
    if disclosed:
        findings.append(
            Finding(
                id="HDR-006",
                title="Software version disclosure",
                severity=Severity.LOW,
                category=CATEGORY,
                location=url,
                evidence="; ".join(disclosed),
                why="Exposing exact versions lets attackers look up known CVEs for your stack.",
                fix="Hide version banners (e.g. Nginx 'server_tokens off', remove X-Powered-By).",
            )
        )

    return findings

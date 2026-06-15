"""Transport-layer checks: TLS version, certificate validity, HTTP->HTTPS."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.http import tls_info
from ..core.registry import check

CATEGORY = "Transport & TLS"
_WEAK_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


@check("tls", profile="passive", requires="url")
def check_tls(ctx: ScanContext) -> list[Finding]:
    url = ctx.target.url
    parsed = urlparse(url)
    findings: list[Finding] = []

    if parsed.scheme != "https":
        findings.append(
            Finding(
                id="TLS-000",
                title="Site served over plaintext HTTP",
                severity=Severity.HIGH,
                category=CATEGORY,
                location=url,
                why="All traffic, including credentials and session cookies, travels unencrypted and can be read or modified on the path.",
                fix="Serve the site over HTTPS only and redirect HTTP to HTTPS. Use a free certificate via Let's Encrypt / certbot.",
                references=["https://letsencrypt.org/"],
            )
        )
        return findings

    info = tls_info(url)
    if info.error:
        findings.append(
            Finding(
                id="TLS-001",
                title="TLS connection / certificate problem",
                severity=Severity.HIGH,
                category=CATEGORY,
                location=url,
                evidence=info.error,
                why="A failing or untrusted certificate lets attackers impersonate the site or trains users to click through warnings.",
                fix="Install a valid certificate from a trusted CA and ensure the full chain is served.",
            )
        )
        return findings

    if info.version in _WEAK_TLS:
        findings.append(
            Finding(
                id="TLS-002",
                title=f"Weak TLS protocol negotiated ({info.version})",
                severity=Severity.HIGH,
                category=CATEGORY,
                location=url,
                evidence=f"Negotiated {info.version}",
                why="TLS 1.0/1.1 have known weaknesses and are deprecated; modern attackers can downgrade and attack them.",
                fix="Disable TLS 1.0/1.1 at the server/load balancer and allow only TLS 1.2+.",
                references=["https://datatracker.ietf.org/doc/rfc8996/"],
            )
        )
    else:
        findings.append(
            passed("TLS-002", f"Modern TLS in use ({info.version})", CATEGORY, location=url)
        )

    # Certificate expiry window.
    if info.not_after:
        try:
            exp = datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
            days = (exp - datetime.now(UTC)).days
            if days < 0:
                findings.append(
                    Finding(
                        id="TLS-003",
                        title="TLS certificate expired",
                        severity=Severity.HIGH,
                        category=CATEGORY,
                        location=url,
                        evidence=f"Expired {abs(days)} days ago ({info.not_after})",
                        why="Browsers block expired certificates; users see a full-page security warning.",
                        fix="Renew the certificate and automate renewal (certbot timer / managed cert).",
                    )
                )
            elif days < 15:
                findings.append(
                    Finding(
                        id="TLS-004",
                        title="TLS certificate expiring soon",
                        severity=Severity.MEDIUM,
                        category=CATEGORY,
                        location=url,
                        evidence=f"Expires in {days} days ({info.not_after})",
                        why="An expiring certificate will soon trigger browser warnings and outages.",
                        fix="Renew now and verify auto-renewal is configured.",
                    )
                )
        except ValueError:
            pass

    return findings


@check("http_redirect", profile="passive", requires="url")
def check_http_redirect(ctx: ScanContext) -> list[Finding]:
    """If the site is HTTPS, confirm the HTTP version redirects to it."""
    parsed = urlparse(ctx.target.url)
    if parsed.scheme != "https":
        return []
    http_url = ctx.target.url.replace("https://", "http://", 1)
    try:
        resp = ctx.http.get(http_url, follow_redirects=False)
    except Exception:
        # No HTTP listener at all is fine (HTTPS-only).
        return [passed("TLS-005", "No plaintext HTTP listener", CATEGORY, location=http_url)]

    location = resp.headers.get("location", "")
    if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
        return [passed("TLS-005", "HTTP redirects to HTTPS", CATEGORY, location=http_url)]
    return [
        Finding(
            id="TLS-005",
            title="HTTP does not redirect to HTTPS",
            severity=Severity.MEDIUM,
            category=CATEGORY,
            location=http_url,
            evidence=f"HTTP returned {resp.status_code}, Location={location or '(none)'}",
            why="Users who type the bare domain stay on plaintext HTTP, exposing their session to interception.",
            fix="Add a permanent redirect from all HTTP requests to the HTTPS equivalent, then enable HSTS.",
        )
    ]

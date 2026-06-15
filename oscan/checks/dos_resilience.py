"""DoS-resilience checks - NOT a DDoS tool.

The goal is to confirm that *defenses exist*: rate-limiting headers / a WAF / a
CDN, and that a short, hard-capped burst of requests starts getting throttled
(HTTP 429/503). There is deliberately no flooding capability here; the burst is
capped at a few dozen requests and is gated behind the authorization flag.
"""

from __future__ import annotations

import httpx

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.http import DEFAULT_UA
from ..core.registry import check

CATEGORY = "DoS resilience"
_HARD_CAP = 50

_RATE_HEADERS = ("retry-after", "ratelimit-limit", "ratelimit-remaining", "x-ratelimit-limit")
_WAF_CDN_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-amz-cf-id": "AWS CloudFront",
    "x-cdn": "CDN",
    "server": None,
}
_WAF_SERVER_TOKENS = ("cloudflare", "akamai", "sucuri", "imperva", "incapsula", "awselb")


@check("rate_limit_headers", profile="standard", requires="url")
def check_rate_limit_headers(ctx: ScanContext) -> list[Finding]:
    resp = ctx.http.get_cached(ctx.target.url)
    h = {k.lower(): v for k, v in resp.headers.items()}
    detected = []

    if any(rh in h for rh in _RATE_HEADERS):
        detected.append("rate-limit headers")
    for hdr, name in _WAF_CDN_HEADERS.items():
        if hdr in h:
            if name:
                detected.append(name)
            elif hdr == "server" and any(tok in h["server"].lower() for tok in _WAF_SERVER_TOKENS):
                detected.append(h["server"])

    if detected:
        return [
            passed(
                "DOS-001",
                f"Edge protection / rate-limiting present ({', '.join(sorted(set(detected)))})",
                CATEGORY,
                location=ctx.target.url,
            )
        ]
    return [
        Finding(
            id="DOS-001",
            title="No WAF / CDN / rate-limit headers detected",
            severity=Severity.LOW,
            category=CATEGORY,
            location=ctx.target.url,
            why="With no edge protection or visible rate-limiting, the app is more exposed to abuse and volumetric attacks.",
            fix="Put the app behind a CDN/WAF (e.g. Cloudflare) and add application-level rate-limiting.",
        )
    ]


@check("dos_burst", profile="active", requires="url")
def check_dos_burst(ctx: ScanContext) -> list[Finding]:
    """Send a small, hard-capped burst to see whether throttling engages."""
    if not ctx.intrusive_allowed:
        return []
    n = min(int(ctx.option("dos_burst", 30)), _HARD_CAP)
    throttled = False
    seen_statuses = []
    try:
        with httpx.Client(
            timeout=5.0, follow_redirects=False, headers={"User-Agent": DEFAULT_UA}
        ) as client:
            for _ in range(n):
                try:
                    r = client.get(ctx.target.url)
                except Exception:
                    break
                seen_statuses.append(r.status_code)
                if r.status_code in (429, 503):
                    throttled = True
                    break
    except Exception as exc:  # noqa: BLE001
        return [
            Finding(
                id="DOS-002",
                title="DoS-resilience burst could not run",
                severity=Severity.INFO,
                category=CATEGORY,
                evidence=str(exc),
                location=ctx.target.url,
            )
        ]

    if throttled:
        return [
            passed(
                "DOS-002",
                "Server throttled the request burst (rate-limiting works)",
                CATEGORY,
                location=ctx.target.url,
                evidence=f"Got HTTP 429/503 after {len(seen_statuses)} requests",
            )
        ]
    return [
        Finding(
            id="DOS-002",
            title="No throttling under a light request burst",
            severity=Severity.MEDIUM,
            category=CATEGORY,
            location=ctx.target.url,
            evidence=f"{len(seen_statuses)} rapid requests, no 429/503 returned",
            why="If a tiny burst is not rate-limited, the endpoint is cheap to abuse (credential stuffing, scraping, DoS).",
            fix="Add per-IP / per-account rate-limiting and a WAF; return 429 with Retry-After when limits are exceeded.",
        )
    ]

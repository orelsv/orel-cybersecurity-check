"""GDPR / privacy checks - all passive (just reading the served page).

These are heuristics, not legal advice: they flag the patterns that most often
make an EU site non-compliant (tracking before consent, no consent banner, no
privacy policy, third-party data transfers, PII over HTTP, Google-hosted fonts).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "GDPR & privacy"

_CONSENT_HINTS = ("cookieconsent", "cookiebot", "onetrust", "usercentrics", "cookie-law",
                  "cookieyes", "termly", "klaro", "tarteaucitron", "gdpr", "consent")
_PRIVACY_HINTS = ("privacy", "datenschutz", "privacidad", "confidentialité", "privacy-policy",
                  "polityka-prywatnosci", "integritetspolicy")
_TRACKERS = {
    "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google DoubleClick", "facebook.net": "Meta Pixel",
    "connect.facebook.net": "Meta Pixel", "hotjar.com": "Hotjar", "clarity.ms": "Microsoft Clarity",
    "segment.com": "Segment", "mixpanel.com": "Mixpanel", "fullstory.com": "FullStory",
}
_GOOGLE_FONTS = ("fonts.googleapis.com", "fonts.gstatic.com")
_TRACKING_COOKIE = re.compile(r"^(_ga|_gid|_gat|_fbp|_gcl|IDE|NID|_hj|ajs_)", re.I)


def _registrable(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


@check("gdpr", profile="passive", requires="url")
def check_gdpr(ctx: ScanContext) -> list[Finding]:
    resp = ctx.http.get_cached(ctx.target.url)
    html = resp.text or ""
    final_url = str(resp.url)
    base_host = urlparse(final_url).hostname or ""
    base_reg = _registrable(base_host)
    soup = BeautifulSoup(html, "html.parser")
    lower = html.lower()
    findings: list[Finding] = []

    # Consent banner present?
    has_consent = any(h in lower for h in _CONSENT_HINTS)

    # Cookies set on first load (no consent yet).
    raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    tracking_cookies = [c.split("=", 1)[0].strip() for c in raw_cookies
                        if _TRACKING_COOKIE.match(c.split("=", 1)[0].strip())]
    if tracking_cookies and not has_consent:
        findings.append(Finding(
            id="GDPR-001", title="Tracking cookies set before consent",
            severity=Severity.HIGH, category=CATEGORY, location=final_url,
            evidence=f"Cookies: {', '.join(tracking_cookies)}",
            why="Setting non-essential/tracking cookies before the user consents violates GDPR/ePrivacy.",
            fix="Block analytics/tracking until the user opts in via a consent banner.",
            references=["https://gdpr.eu/cookies/"],
        ))

    # Third-party trackers and Google Fonts.
    third_party_hosts = set()
    tracker_hits = set()
    google_fonts = False
    for tag, attr in (("script", "src"), ("img", "src"), ("iframe", "src"),
                      ("link", "href"), ("source", "src")):
        for el in soup.find_all(tag):
            val = el.get(attr)
            if not val:
                continue
            absurl = urljoin(final_url, val)
            host = urlparse(absurl).hostname or ""
            if not host:
                continue
            if _registrable(host) != base_reg:
                third_party_hosts.add(host)
            for dom, name in _TRACKERS.items():
                if host.endswith(dom):
                    tracker_hits.add(name)
            if any(host.endswith(g) for g in _GOOGLE_FONTS):
                google_fonts = True

    if tracker_hits:
        sev = Severity.HIGH if not has_consent else Severity.MEDIUM
        findings.append(Finding(
            id="GDPR-002", title="Third-party trackers loaded",
            severity=sev, category=CATEGORY, location=final_url,
            evidence=", ".join(sorted(tracker_hits)),
            why=("Trackers send visitor data (incl. IP) to third parties; without prior consent this breaches GDPR."
                 if not has_consent else "Trackers process personal data; ensure they only run after consent and are in your privacy policy."),
            fix="Load trackers only after consent; document them; consider self-hosted, privacy-friendly analytics.",
        ))

    if google_fonts:
        findings.append(Finding(
            id="GDPR-003", title="Google Fonts loaded from Google servers",
            severity=Severity.LOW, category=CATEGORY, location=final_url,
            evidence="fonts.googleapis.com / fonts.gstatic.com referenced",
            why="German courts have ruled that dynamically loading Google Fonts transfers the visitor's IP to Google without consent.",
            fix="Self-host the fonts (download and serve locally) to avoid the transfer.",
            references=["https://www.heise.de/news/Datenschutz-Google-Fonts-Abmahnungen-7178459.html"],
        ))

    # Consent banner missing while cookies/trackers present.
    if (raw_cookies or tracker_hits) and not has_consent:
        findings.append(Finding(
            id="GDPR-004", title="No cookie-consent mechanism detected",
            severity=Severity.MEDIUM, category=CATEGORY, location=final_url,
            why="If you set non-essential cookies or run trackers, EU law requires a prior-consent banner.",
            fix="Add a consent banner that blocks non-essential cookies/scripts until the user opts in.",
        ))
    elif has_consent:
        findings.append(passed("GDPR-004", "Consent mechanism detected", CATEGORY, location=final_url))

    # Privacy policy link.
    has_privacy = any(h in (a.get("href", "") + " " + a.get_text()).lower()
                      for a in soup.find_all("a") for h in _PRIVACY_HINTS)
    if not has_privacy:
        findings.append(Finding(
            id="GDPR-005", title="No privacy policy link found",
            severity=Severity.MEDIUM, category=CATEGORY, location=final_url,
            why="GDPR requires a clear, accessible privacy notice; a missing one is a common compliance gap.",
            fix="Add a linked privacy policy describing what data you collect, why, and visitor rights.",
        ))
    else:
        findings.append(passed("GDPR-005", "Privacy policy link present", CATEGORY, location=final_url))

    # PII forms over HTTP.
    if final_url.startswith("http://"):
        for form in soup.find_all("form"):
            inputs = {(i.get("type") or "text").lower() for i in form.find_all("input")}
            if {"password", "email", "tel"} & inputs:
                findings.append(Finding(
                    id="GDPR-006", title="Form collecting personal data over HTTP",
                    severity=Severity.HIGH, category=CATEGORY, location=final_url,
                    why="Personal data (email/password/phone) submitted over plaintext HTTP can be intercepted.",
                    fix="Serve the page and form endpoint over HTTPS only.",
                ))
                break

    return findings

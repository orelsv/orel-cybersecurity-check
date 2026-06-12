"""Detect sensitive files/endpoints accidentally exposed on a live target.

Every probe is a plain GET to a well-known path and the *content* is validated
(not just the status code) because SPAs love to return 200 for everything.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "Exposed files & endpoints"


def _looks_html(text: str) -> bool:
    head = text[:200].lower()
    return "<!doctype html" in head or "<html" in head


# (path, validator(text)->bool, id, title, severity, why, fix)
_PROBES = [
    (".git/HEAD", lambda t: t.strip().startswith("ref:"),
     "EXP-001", "Exposed .git directory", Severity.CRITICAL,
     "A reachable .git lets anyone download the full source history, including any secrets ever committed.",
     "Block access to /.git at the web server, or deploy build artifacts only (never the .git folder)."),
    (".git/config", lambda t: "[core]" in t,
     "EXP-001", "Exposed .git/config", Severity.CRITICAL,
     "The .git directory is reachable, exposing source code and history.",
     "Deny /.git in the web server config and redeploy without the repo."),
    (".env", lambda t: not _looks_html(t) and re.search(r"^[A-Z0-9_]+=", t, re.M) is not None,
     "EXP-002", "Exposed .env file", Severity.CRITICAL,
     "The environment file typically holds database passwords, API keys and secrets in plaintext.",
     "Remove .env from the web root, deny access to dotfiles, and rotate any exposed secrets."),
    (".env.local", lambda t: not _looks_html(t) and re.search(r"^[A-Z0-9_]+=", t, re.M) is not None,
     "EXP-002", "Exposed .env.local file", Severity.CRITICAL,
     "Local env files often contain real credentials.",
     "Remove it from the web root and deny dotfile access; rotate exposed secrets."),
    ("config.json", lambda t: not _looks_html(t) and ("password" in t.lower() or "secret" in t.lower() or "apikey" in t.lower()),
     "EXP-003", "Exposed config file with secrets", Severity.HIGH,
     "A reachable config file is leaking credentials or keys.",
     "Move config out of the web root and serve only what is needed."),
    ("backup.zip", lambda t: not _looks_html(t),
     "EXP-004", "Exposed backup archive", Severity.HIGH,
     "Backups frequently contain source, databases and secrets.",
     "Delete backups from the web root and store them in private storage."),
    ("phpinfo.php", lambda t: "phpinfo()" in t or "PHP Version" in t,
     "EXP-005", "Exposed phpinfo() page", Severity.MEDIUM,
     "phpinfo reveals full server configuration and paths useful to an attacker.",
     "Delete phpinfo files from production."),
    ("server-status", lambda t: "Apache Server Status" in t,
     "EXP-006", "Exposed Apache server-status", Severity.MEDIUM,
     "server-status leaks live request data and internal IPs.",
     "Restrict /server-status to localhost or disable mod_status."),
]


@check("exposure", profile="passive", requires="url")
def check_exposure(ctx: ScanContext) -> list[Finding]:
    base = ctx.target.url if ctx.target.url.endswith("/") else ctx.target.url + "/"
    findings: list[Finding] = []
    any_hit = False

    for path, valid, fid, title, sev, why, fix in _PROBES:
        url = urljoin(base, path)
        try:
            resp = ctx.http.get(url, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 200:
            text = resp.text if hasattr(resp, "text") else ""
            try:
                if valid(text):
                    any_hit = True
                    findings.append(Finding(
                        id=fid, title=title, severity=sev, category=CATEGORY, location=url,
                        evidence=f"HTTP 200, content matched ({len(text)} bytes)",
                        why=why, fix=fix,
                    ))
            except Exception:
                continue

    # Source map exposure referenced from the home page.
    try:
        home = ctx.http.get_cached(ctx.target.url)
        if "sourceMappingURL" in (home.text or "")[:200000]:
            findings.append(Finding(
                id="EXP-007", title="JavaScript source maps exposed",
                severity=Severity.LOW, category=CATEGORY, location=ctx.target.url,
                evidence="sourceMappingURL reference found in served assets",
                why="Source maps reveal your original (unminified) source code and sometimes comments/secrets.",
                fix="Do not deploy .map files to production, or restrict access to them.",
            ))
    except Exception:
        pass

    if not any_hit and not findings:
        findings.append(passed("EXP-001", "No common sensitive files exposed", CATEGORY, location=ctx.target.url))
    return findings

"""oscan command-line interface.

    oscan https://mysite.example                 # passive (safe, default)
    oscan https://mysite.example --profile active --i-am-authorized
    oscan --repo ./my-project                    # local git/secret scan
    oscan https://mysite.example --json out.json --md out.md
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from . import __version__
from .core.context import ScanContext, Target
from .core.http import HttpClient
from .core.registry import run_checks
from .core.safety import (
    AuthorizationError,
    ScopeError,
    authorize,
    is_intrusive,
)
from .core.scoring import summarize
from .report import console as console_report
from .report import json_report, markdown


def _normalize_url(value: str) -> str:
    if "://" not in value:
        return "https://" + value
    return value


def _looks_like_url(value: str) -> bool:
    if "://" in value:
        return True
    # bare host like example.com (a dot, no path/space, not an existing path)
    return "." in value and "/" not in value and not Path(value).exists()


def _load_scope(path: str | None) -> list[str] | None:
    if not path:
        return None
    import yaml
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if isinstance(data, dict):
        return [str(x) for x in data.get("scope", [])]
    if isinstance(data, list):
        return [str(x) for x in data]
    return None


def _confirm_active(console: Console, targets: list[str], assume_yes: bool) -> bool:
    if assume_yes:
        return True
    console.print(
        "[bold yellow]ACTIVE profile[/bold yellow] sends non-destructive probes "
        "(injection markers, an auth-lockout check, a small rate-limit burst)."
    )
    console.print(f"Targets: {', '.join(targets)}")
    console.print("Only proceed for assets you own or are explicitly authorized to test.")
    try:
        answer = input("Type 'yes' to confirm authorization: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oscan",
        description="Authorized self-assessment scanner for web apps/sites (vulnerabilities + GDPR).",
    )
    p.add_argument("target", nargs="?", help="URL (https://...) or a local repo path to scan")
    p.add_argument("--repo", help="local repository path to scan for secrets/git leaks")
    p.add_argument("--profile", choices=["passive", "standard", "active"], default="passive",
                   help="passive (default, observe only) | standard | active (intrusive, gated)")
    p.add_argument("--scope", help="YAML allowlist of hosts permitted for active scanning")
    p.add_argument("--i-am-authorized", action="store_true", dest="authorized",
                   help="assert you own or are authorized to test the target (required for active)")
    p.add_argument("--yes", action="store_true", help="skip the interactive active-scan confirmation")
    p.add_argument("--json", dest="json_path", help="write JSON report to this path")
    p.add_argument("--md", dest="md_path", help="write Markdown report to this path")
    p.add_argument("--no-enrich", action="store_true", help="disable optional Claude plain-language enrichment")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates (testing only)")
    p.add_argument("--min-interval", type=float, default=0.3, help="seconds between requests (throttle)")
    p.add_argument("--dos-burst", type=int, default=30, help="request count for the DoS-resilience check (hard-capped at 50)")
    # Login lockout check (active) — supply your OWN test account.
    p.add_argument("--login-url", help="login form POST URL (enables the lockout check)")
    p.add_argument("--login-user", help="username/email of YOUR test account for the lockout check")
    p.add_argument("--login-userfield", default="username", help="form field name for the username (default: username)")
    p.add_argument("--login-passfield", default="password", help="form field name for the password (default: password)")
    p.add_argument("--version", action="version", version=f"oscan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()

    url = None
    repo = args.repo
    if args.target:
        if _looks_like_url(args.target):
            url = _normalize_url(args.target)
        elif Path(args.target).exists():
            repo = args.target
        else:
            url = _normalize_url(args.target)

    if not url and not repo:
        console.print("[red]Provide a URL or a --repo path.[/red] See --help.")
        return 2

    targets = [t for t in (url,) if t]
    scope = _load_scope(args.scope)

    # Safety gate (only meaningful for the active profile).
    if is_intrusive(args.profile):
        try:
            authorize(
                args.profile,
                authorized=args.authorized,
                targets=targets or [repo or "local"],
                scope=scope,
                confirm=lambda: _confirm_active(console, targets, args.yes),
            )
        except (AuthorizationError, ScopeError) as exc:
            console.print(f"[red]Refused:[/red] {exc}")
            return 3

    http = HttpClient(min_interval=args.min_interval, verify=not args.insecure) if url else None
    ctx = ScanContext(
        target=Target(url=url, repo=repo),
        http=http,
        profile=args.profile,
        intrusive_allowed=is_intrusive(args.profile),
        options={
            "dos_burst": min(args.dos_burst, 50),
            "login_url": args.login_url,
            "login_user": args.login_user,
            "login_userfield": args.login_userfield,
            "login_passfield": args.login_passfield,
        },
    )

    try:
        findings = run_checks(ctx, args.profile)
    finally:
        if http:
            http.close()

    # Optional Claude enrichment (no-op without the package or an API key).
    if not args.no_enrich:
        try:
            from .report import enrich
            enrich.enrich_findings(findings)
        except Exception:
            pass

    summary = summarize(findings)
    label = url or repo
    console_report.render(console, label, args.profile, summary, findings)

    if args.json_path:
        meta = {"requests_sent": http.request_count if http else 0}
        json_report.write(args.json_path, json_report.build(label, args.profile, summary, findings, meta))
        console.print(f"[dim]JSON report → {args.json_path}[/dim]")
    if args.md_path:
        markdown.write(args.md_path, markdown.build(label, args.profile, summary, findings))
        console.print(f"[dim]Markdown report → {args.md_path}[/dim]")

    return 0


if __name__ == "__main__":
    sys.exit(main())

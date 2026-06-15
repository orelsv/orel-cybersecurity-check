"""Secret-leak scanning of a local repository.

The headline case (and an explicit ask): a secret committed and later deleted
still lives in git history. We scan the full history, not just the working tree.

Strategy:
  1. If `gitleaks` is installed, use it (it scans all commits by default).
  2. Otherwise fall back to a built-in regex scan over the working tree and a
     capped slice of `git log -p` history.
Either way we also check that .gitignore covers the usual secret files.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..core.context import ScanContext
from ..core.finding import Finding, Severity, passed
from ..core.registry import check

CATEGORY = "Secrets & git leakage"

# High-confidence secret patterns for the built-in fallback.
_PATTERNS = {
    "AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "Azure storage key": re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    "Generic assignment": re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{12,}"
    ),
}
_CRITICAL_RULES = ("private", "aws", "azure", "gcp", "google", "rsa", "pgp")
_HISTORY_BYTE_CAP = 5_000_000  # don't read more than ~5 MB of git history

# Inline markers that tell oscan (as gitleaks/detect-secrets do) to ignore a
# known or deliberately-fake secret on that line - the allowlist convention.
_ALLOW_MARKERS = ("gitleaks:allow", "pragma: allowlist secret", "oscan:allow")


def _redact(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}...{secret[-2:]} ({len(secret)} chars)"


def _severity_for(rule: str) -> Severity:
    rule_l = rule.lower()
    return Severity.CRITICAL if any(k in rule_l for k in _CRITICAL_RULES) else Severity.HIGH


def _is_git_repo(repo: Path) -> bool:
    return (repo / ".git").exists()


def _run_gitleaks(repo: Path) -> list[Finding]:
    mode = "git" if _is_git_repo(repo) else "dir"
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        report_path = tf.name
    try:
        subprocess.run(
            [
                "gitleaks",
                mode,
                str(repo),
                "--report-format",
                "json",
                "--report-path",
                report_path,
                "--no-banner",
                "--redact",
            ],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=str(repo),  # so gitleaks honors the repo's own .gitleaksignore
        )
        data = json.loads(Path(report_path).read_text(encoding="utf-8") or "[]")
    except Exception as exc:  # noqa: BLE001
        return [
            Finding(
                id="SECRET-ERR",
                title="gitleaks run failed",
                severity=Severity.INFO,
                category=CATEGORY,
                evidence=str(exc),
            )
        ]
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass

    findings: list[Finding] = []
    seen = set()
    for item in data:
        rule = item.get("RuleID", "secret")
        file = item.get("File", "")
        commit = (item.get("Commit") or "")[:10]
        key = (rule, file, commit, item.get("StartLine"))
        if key in seen:
            continue
        seen.add(key)
        in_history = bool(commit)
        where = f"{file}" + (f" @ commit {commit}" if commit else "")
        findings.append(
            Finding(
                id="SECRET-001",
                title=f"Secret detected: {item.get('Description', rule)}",
                severity=_severity_for(rule),
                category=CATEGORY,
                location=where,
                evidence=item.get("Match", "")[:80] or _redact(item.get("Secret", "")),
                why=(
                    "This secret is in git history; even if deleted from the latest commit it "
                    "is still recoverable by anyone with the repo."
                    if in_history
                    else "A live secret in the repo can be used directly by anyone who reads the code."
                ),
                fix="Rotate/revoke the secret now (history rewrite alone is not enough), then store it "
                "in environment variables or a secrets manager (e.g. Azure Key Vault) and add it to .gitignore.",
                references=["https://docs.github.com/code-security/secret-scanning"],
            )
        )
    if not findings:
        findings.append(
            passed("SECRET-001", "No secrets detected by gitleaks", CATEGORY, location=str(repo))
        )
    return findings


def _scan_text(text: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if any(marker in line for marker in _ALLOW_MARKERS):
            continue  # allowlisted line (e.g. a known test fixture)
        for name, pat in _PATTERNS.items():
            if name in seen:
                continue
            m = pat.search(line)
            if m:
                hits.append((name, _redact(m.group(0))))
                seen.add(name)
        if len(seen) == len(_PATTERNS):
            break
    return hits


def _run_builtin(repo: Path) -> list[Finding]:
    findings: list[Finding] = []

    # Working tree (tracked-ish text files, size-limited).
    for path in repo.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.stat().st_size > 1_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, redacted in _scan_text(text):
            findings.append(
                Finding(
                    id="SECRET-002",
                    title=f"Possible secret in working tree: {name}",
                    severity=_severity_for(name),
                    category=CATEGORY,
                    location=str(path.relative_to(repo)),
                    evidence=redacted,
                    why="A secret committed to the repo can be used by anyone who reads the code.",
                    fix="Remove it, rotate the secret, move it to env/secrets manager, and add the file to .gitignore.",
                )
            )

    # History (capped) - find secrets that may have been deleted but persist in commits.
    if _is_git_repo(repo):
        try:
            proc = subprocess.Popen(
                ["git", "-C", str(repo), "log", "-p", "--all", "--no-color"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            buf = proc.stdout.read(_HISTORY_BYTE_CAP) if proc.stdout else ""
            proc.kill()
            history_hits = dict(_scan_text(buf))
            for name, redacted in history_hits.items():
                findings.append(
                    Finding(
                        id="SECRET-003",
                        title=f"Possible secret in git history: {name}",
                        severity=_severity_for(name),
                        category=CATEGORY,
                        location=f"{repo} (git history)",
                        evidence=redacted,
                        why="Secrets in history are recoverable from any clone even after deletion from the latest commit.",
                        fix="Rotate the secret immediately, then scrub history (git filter-repo) and force-push.",
                    )
                )
        except Exception:  # noqa: BLE001
            pass

    if not findings:
        findings.append(
            passed(
                "SECRET-002",
                "No high-confidence secrets found (built-in scan)",
                CATEGORY,
                location=str(repo),
            )
        )
    return findings


@check("secrets", profile="passive", requires="repo")
def check_secrets(ctx: ScanContext) -> list[Finding]:
    repo = Path(ctx.target.repo)
    if not repo.exists():
        return [
            Finding(
                id="SECRET-000",
                title="Repo path not found",
                severity=Severity.INFO,
                category=CATEGORY,
                evidence=str(repo),
            )
        ]
    if shutil.which("gitleaks"):
        return _run_gitleaks(repo)
    return _run_builtin(repo)


@check("gitignore", profile="passive", requires="repo")
def check_gitignore(ctx: ScanContext) -> list[Finding]:
    repo = Path(ctx.target.repo)
    gi = repo / ".gitignore"
    expected = [".env", "*.key", "*.pem"]
    if not gi.exists():
        return [
            Finding(
                id="GIT-IGNORE-001",
                title="No .gitignore file",
                severity=Severity.LOW,
                category=CATEGORY,
                location=str(repo),
                why="Without .gitignore it is easy to accidentally commit .env files, keys, and credentials.",
                fix="Add a .gitignore covering .env, *.key, *.pem, and other secret/build artifacts.",
            )
        ]
    content = gi.read_text(encoding="utf-8", errors="ignore")
    missing = [pat for pat in expected if pat not in content]
    if missing:
        return [
            Finding(
                id="GIT-IGNORE-002",
                title=".gitignore missing common secret patterns",
                severity=Severity.LOW,
                category=CATEGORY,
                location=str(gi),
                evidence=f"Not ignored: {', '.join(missing)}",
                why="Files matching these patterns can be committed by accident and leak credentials.",
                fix=f"Add these lines to .gitignore: {', '.join(missing)}",
            )
        ]
    return [
        passed(
            "GIT-IGNORE-001", ".gitignore covers common secret patterns", CATEGORY, location=str(gi)
        )
    ]

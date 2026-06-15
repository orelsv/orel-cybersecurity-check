"""Prove the repo scanner finds a secret that was committed and then deleted -
i.e. it lives only in git history, not the working tree."""

import subprocess

import pytest

from oscan.checks.secrets_git import check_gitignore, check_secrets
from oscan.core.context import ScanContext, Target
from oscan.core.finding import Severity

# Deliberately fake credentials, written to a temp repo to prove the scanner
# detects them. The trailing `# gitleaks:allow` stops the scanner from flagging
# its own fixture in this source file - this is the allowlist feature, dogfooded.
_SECRET_CONTENT = 'DB_PASSWORD = "Sup3rSecretP@ssw0rd123"\napi_key = "abcd1234efgh5678ijkl9012mnop"\n'  # gitleaks:allow


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def repo_with_deleted_secret(tmp_path):
    repo = tmp_path / "proj"
    repo.mkdir()
    _git(repo, "init", "-q")
    secret_file = repo / "app.conf"
    secret_file.write_text(_SECRET_CONTENT)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "add config")
    secret_file.unlink()  # delete the secret from the working tree
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "remove config")
    return repo


def test_finds_secret_in_history(repo_with_deleted_secret):
    ctx = ScanContext(target=Target(repo=str(repo_with_deleted_secret)))
    findings = check_secrets(ctx)
    serious = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert serious, f"expected a secret finding, got {[f.title for f in findings]}"


def test_gitignore_missing_patterns_flagged(tmp_path):
    (tmp_path / ".gitignore").write_text("node_modules/\n")
    ctx = ScanContext(target=Target(repo=str(tmp_path)))
    findings = check_gitignore(ctx)
    assert any(f.id == "GIT-IGNORE-002" for f in findings)


def test_gitignore_complete_passes(tmp_path):
    (tmp_path / ".gitignore").write_text(".env\n*.key\n*.pem\n")
    ctx = ScanContext(target=Target(repo=str(tmp_path)))
    findings = check_gitignore(ctx)
    assert all(f.severity is Severity.INFO for f in findings)


def test_inline_allow_marker_suppresses():
    from oscan.checks.secrets_git import _scan_text

    flagged = 'api_key = "abcd1234efgh5678ijkl9012mnop"'  # gitleaks:allow
    assert _scan_text(flagged), "control: a bare fake key should be detected"
    assert not _scan_text(flagged + "  # gitleaks:allow"), "allow marker should suppress"

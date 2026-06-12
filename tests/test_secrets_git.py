"""Prove the repo scanner finds a secret that was committed and then deleted —
i.e. it lives only in git history, not the working tree."""

import subprocess

import pytest

from oscan.checks.secrets_git import check_secrets, check_gitignore
from oscan.core.context import ScanContext, Target
from oscan.core.finding import Severity

# A secret in the form gitleaks reliably flags (generic-api-key) and that the
# built-in fallback also matches (Generic assignment pattern).
_SECRET_CONTENT = (
    'DB_PASSWORD = "Sup3rSecretP@ssw0rd123"\n'
    'api_key = "abcd1234efgh5678ijkl9012mnop"\n'
)


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True, capture_output=True, text=True,
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

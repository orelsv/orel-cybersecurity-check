"""--repo accepts a remote git URL: oscan clones it to a temp dir and scans it."""

import shutil
import subprocess

from rich.console import Console

from oscan.checks.secrets_git import check_secrets
from oscan.cli import _clone_repo, _is_remote_repo
from oscan.core.context import ScanContext, Target
from oscan.core.finding import Severity


def test_is_remote_repo_detection(tmp_path):
    assert _is_remote_repo("https://github.com/o/r")
    assert _is_remote_repo("git@github.com:o/r.git")
    assert _is_remote_repo("ssh://git@host/o/r.git")
    assert not _is_remote_repo(str(tmp_path))  # an existing local path
    assert not _is_remote_repo("./does/not/exist")  # local-looking, no URL scheme


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def test_clone_and_scan_finds_secret(tmp_path):
    # A source repo with a committed secret, scanned the way a remote URL would be.
    src = tmp_path / "src"
    src.mkdir()
    _git(src, "init", "-q")
    (src / "app.conf").write_text('api_key = "abcd1234efgh5678ijkl9012mnop"\n')  # gitleaks:allow
    _git(src, "add", "-A")
    _git(src, "commit", "-q", "-m", "add config")

    dest = _clone_repo(str(src), Console())
    try:
        assert dest, "cloning a local source repo should succeed"
        findings = check_secrets(ScanContext(target=Target(repo=dest)))
        assert any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    finally:
        if dest:
            shutil.rmtree(dest, ignore_errors=True)

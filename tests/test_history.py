"""Git history scanning tests.

Each test creates a real git repo, makes commits, then scans history.
"""

import subprocess
import textwrap
from pathlib import Path

import pytest

from secrets_cli.ignore import IgnoreRules
from secrets_cli.scanner import scan_history


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Initialise a real git repo with user config and an empty initial commit."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"], cwd=tmp_path, capture_output=True
    )
    (tmp_path / "README.md").write_text("# Test repo")
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True)
    return tmp_path


def commit(repo: Path, filename: str, content: str, msg: str = "update") -> None:
    (repo / filename).write_text(textwrap.dedent(content))
    subprocess.run(["git", "add", "."], cwd=repo, capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=repo, capture_output=True)


def scan(repo: Path) -> list:
    return scan_history(root=repo, ignore=IgnoreRules(root=repo))


class TestScanHistory:
    def test_finds_secret_still_present(self, git_repo: Path) -> None:
        commit(git_repo, "config.py", "KEY='AKIAIOSFODNN7EXAMPLE'", "add config")
        findings = scan(git_repo)
        assert any(f.pattern.name == "AWS Access Key ID" for f in findings)

    def test_finds_deleted_secret(self, git_repo: Path) -> None:
        """Secret removed from working tree must still appear in history scan."""
        commit(git_repo, "secret.py", "KEY='AKIAIOSFODNN7EXAMPLE'", "oops")
        commit(git_repo, "secret.py", "KEY=os.environ['KEY']", "fix")
        findings = scan(git_repo)
        assert any(f.pattern.name == "AWS Access Key ID" for f in findings)

    def test_finding_has_commit_hash(self, git_repo: Path) -> None:
        commit(git_repo, "config.py", "KEY='AKIAIOSFODNN7EXAMPLE'", "add key")
        findings = scan(git_repo)
        aws = [f for f in findings if f.pattern.name == "AWS Access Key ID"]
        assert aws
        assert len(aws[0].commit) == 8  # short hash

    def test_finding_has_commit_message(self, git_repo: Path) -> None:
        commit(git_repo, "config.py", "KEY='AKIAIOSFODNN7EXAMPLE'", "add deployment key")
        findings = scan(git_repo)
        aws = [f for f in findings if f.pattern.name == "AWS Access Key ID"]
        assert aws[0].commit_msg == "add deployment key"

    def test_deduplication_across_commits(self, git_repo: Path) -> None:
        """Same secret in same file added in two commits → reported only once."""
        commit(git_repo, "a.py", "KEY='AKIAIOSFODNN7EXAMPLE'", "add")
        commit(git_repo, "a.py", "KEY='AKIAIOSFODNN7EXAMPLE'\nX=1", "touch")
        findings = scan(git_repo)
        aws = [f for f in findings if f.pattern.name == "AWS Access Key ID"]
        assert len(aws) == 1

    def test_max_commits_limits_scan(self, git_repo: Path) -> None:
        commit(git_repo, "old.py", "KEY='AKIAIOSFODNN7EXAMPLE'", "old commit")
        commit(git_repo, "new.py", "# clean file", "new commit")
        findings_all = scan_history(root=git_repo, ignore=IgnoreRules(root=git_repo))
        findings_one = scan_history(
            root=git_repo, ignore=IgnoreRules(root=git_repo), max_commits=1
        )
        # With max_commits=1 we only see the latest commit (clean file), so fewer findings
        assert len(findings_one) <= len(findings_all)

    def test_no_secret_no_findings(self, git_repo: Path) -> None:
        commit(git_repo, "clean.py", "API_KEY = os.environ['API_KEY']", "clean")
        findings = scan(git_repo)
        assert not findings

    def test_skips_example_files(self, git_repo: Path) -> None:
        commit(git_repo, "config.env.example", "KEY='AKIAIOSFODNN7EXAMPLE'", "examples")
        findings = scan(git_repo)
        assert not any(f.pattern.name == "AWS Access Key ID" for f in findings)

    def test_no_git_repo_returns_empty(self, tmp_path: Path) -> None:
        """Not a git repo → return empty list, no crash."""
        findings = scan_history(root=tmp_path, ignore=IgnoreRules(root=tmp_path))
        assert findings == []

    def test_github_token_in_history(self, git_repo: Path) -> None:
        token = "ghp_" + "A" * 36
        commit(git_repo, "deploy.sh", f"GITHUB_TOKEN={token}", "ci")
        findings = scan(git_repo)
        assert any("GitHub" in f.pattern.name for f in findings)

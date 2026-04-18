import textwrap
from pathlib import Path

import pytest

from secrets_cli.ignore import IgnoreRules
from secrets_cli.scanner import scan_path


@pytest.fixture
def tmp_repo(tmp_path):
    """Create a minimal temp directory with .git so IgnoreRules works."""
    (tmp_path / ".git").mkdir()
    return tmp_path


def write_file(root: Path, name: str, content: str) -> Path:
    p = root / name
    p.write_text(textwrap.dedent(content))
    return p


def scan(root: Path) -> list:
    ignore = IgnoreRules(root=root)
    return scan_path(root=root, ignore=ignore)


class TestScanPath:
    def test_finds_aws_key(self, tmp_repo):
        write_file(tmp_repo, "config.py", "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        assert any(f.pattern.name == "AWS Access Key ID" for f in findings)

    def test_finds_github_token(self, tmp_repo):
        token = "ghp_" + "A" * 36
        write_file(tmp_repo, "deploy.sh", f"GITHUB_TOKEN={token}")
        findings = scan(tmp_repo)
        assert any("GitHub" in f.pattern.name for f in findings)

    def test_finds_private_key(self, tmp_repo):
        write_file(tmp_repo, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----")
        findings = scan(tmp_repo)
        assert any("Private Key" in f.pattern.name for f in findings)

    def test_nosecrets_inline_suppresses(self, tmp_repo):
        write_file(tmp_repo, "test_config.py", "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'  # nosecrets")
        findings = scan(tmp_repo)
        assert not findings

    def test_skips_binary_file(self, tmp_repo):
        p = tmp_repo / "binary.bin"
        p.write_bytes(b"\x00AKIAIOSFODNN7EXAMPLE")
        findings = scan(tmp_repo)
        assert not findings

    def test_skips_example_suffix(self, tmp_repo):
        write_file(tmp_repo, "config.env.example", "API_KEY=AKIAIOSFODNN7EXAMPLE")
        findings = scan(tmp_repo)
        assert not findings

    def test_skips_git_directory(self, tmp_repo):
        git_file = tmp_repo / ".git" / "config"
        git_file.write_text("API_KEY=AKIAIOSFODNN7EXAMPLE")
        findings = scan(tmp_repo)
        assert not findings

    def test_no_findings_on_clean_file(self, tmp_repo):
        write_file(tmp_repo, "clean.py", 'API_KEY = os.environ["API_KEY"]')
        findings = scan(tmp_repo)
        assert not findings

    def test_deduplication(self, tmp_repo):
        # Same secret on two lines → should appear twice (different lines)
        content = "KEY='AKIAIOSFODNN7EXAMPLE'\nKEY='AKIAIOSFODNN7EXAMPLE'"
        write_file(tmp_repo, "dup.py", content)
        findings = scan(tmp_repo)
        # Dedup is per file+pattern+raw, but different lines are same raw → deduplicated
        aws_findings = [f for f in findings if f.pattern.name == "AWS Access Key ID"]
        assert len(aws_findings) == 1

    def test_secretsignore_file(self, tmp_repo):
        write_file(tmp_repo, "legacy.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        (tmp_repo / ".secretsignore").write_text("legacy.py\n")
        findings = scan(tmp_repo)
        assert not findings

    def test_high_severity_first(self, tmp_repo):
        write_file(tmp_repo, "a.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        stripe_key = "sk_test_" + "x" * 24
        write_file(tmp_repo, "b.py", f"STRIPE_KEY='{stripe_key}'")
        findings = scan(tmp_repo)
        from secrets_cli.reporter import SEVERITY_ORDER
        severities = [SEVERITY_ORDER[f.pattern.severity] for f in findings]
        assert severities == sorted(severities)


class TestRedaction:
    def test_redacted_shows_prefix_and_suffix(self, tmp_repo):
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        aws = [f for f in findings if f.pattern.name == "AWS Access Key ID"][0]
        assert aws.redacted.startswith("AKIA")
        assert aws.redacted.endswith("IPLE") or "****" in aws.redacted

    def test_raw_never_equals_redacted_for_long_secrets(self, tmp_repo):
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        aws = [f for f in findings if f.pattern.name == "AWS Access Key ID"][0]
        assert aws.raw != aws.redacted

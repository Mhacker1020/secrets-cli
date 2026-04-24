"""Baseline management tests."""

import json
import textwrap
from pathlib import Path

import pytest

from secrets_cli.baseline import (
    BASELINE_FILE,
    create_baseline,
    filter_baseline,
    load_baseline,
)
from secrets_cli.ignore import IgnoreRules
from secrets_cli.scanner import scan_path


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    return tmp_path


def write_file(root: Path, name: str, content: str) -> Path:
    p = root / name
    p.write_text(textwrap.dedent(content))
    return p


def scan(root: Path) -> list:
    return scan_path(root=root, ignore=IgnoreRules(root=root))


class TestCreateBaseline:
    def test_writes_json_file(self, tmp_repo: Path) -> None:
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        out = tmp_repo / BASELINE_FILE
        create_baseline(findings, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["version"] == 1
        assert data["count"] == len(findings)

    def test_no_raw_secrets_in_file(self, tmp_repo: Path) -> None:
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        out = tmp_repo / BASELINE_FILE
        create_baseline(findings, out)
        content = out.read_text()
        assert "AKIAIOSFODNN7EXAMPLE" not in content

    def test_fingerprint_is_sha256(self, tmp_repo: Path) -> None:
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        out = tmp_repo / BASELINE_FILE
        create_baseline(findings, out)
        data = json.loads(out.read_text())
        fp = data["findings"][0]["fingerprint"]
        assert fp.startswith("sha256:")
        assert len(fp) == 71  # "sha256:" + 64 hex chars

    def test_empty_findings(self, tmp_repo: Path) -> None:
        out = tmp_repo / BASELINE_FILE
        create_baseline([], out)
        data = json.loads(out.read_text())
        assert data["count"] == 0
        assert data["findings"] == []


class TestLoadBaseline:
    def test_returns_empty_set_when_missing(self, tmp_repo: Path) -> None:
        assert load_baseline(tmp_repo / "nonexistent.json") == set()

    def test_loads_fingerprints(self, tmp_repo: Path) -> None:
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        out = tmp_repo / BASELINE_FILE
        create_baseline(findings, out)
        loaded = load_baseline(out)
        assert len(loaded) == len(findings)
        assert all(fp.startswith("sha256:") for fp in loaded)

    def test_returns_empty_on_corrupt_json(self, tmp_repo: Path) -> None:
        bad = tmp_repo / BASELINE_FILE
        bad.write_text("not json")
        assert load_baseline(bad) == set()


class TestFilterBaseline:
    def test_suppresses_baselined_finding(self, tmp_repo: Path) -> None:
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        out = tmp_repo / BASELINE_FILE
        create_baseline(findings, out)
        baseline = load_baseline(out)
        assert filter_baseline(findings, baseline) == []

    def test_passes_new_finding(self, tmp_repo: Path) -> None:
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        out = tmp_repo / BASELINE_FILE
        create_baseline(findings, out)
        baseline = load_baseline(out)

        # New finding in a different file → not suppressed
        write_file(tmp_repo, "b.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        new_findings = scan(tmp_repo)
        result = filter_baseline(new_findings, baseline)
        # b.py finding should pass (different file → different fingerprint)
        assert any("b.py" in str(f.file) for f in result)

    def test_empty_baseline_passes_everything(self, tmp_repo: Path) -> None:
        write_file(tmp_repo, "k.py", "KEY='AKIAIOSFODNN7EXAMPLE'")
        findings = scan(tmp_repo)
        assert filter_baseline(findings, set()) == findings

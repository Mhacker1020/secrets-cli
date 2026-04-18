"""
Core scanner — walks files and applies patterns.

Two modes:
  - scan_path(path):   walk a directory or single file
  - scan_staged(root): scan only git-staged content (reads from git index)
"""

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .entropy import is_high_entropy
from .ignore import IgnoreRules
from .patterns import PATTERNS, Pattern


@dataclass
class Finding:
    file: Path
    line: int
    pattern: Pattern
    redacted: str   # shown to user: first 4 + **** + last 4
    raw: str        # used only for deduplication, never printed


def _redact(value: str) -> str:
    """Show first 4 and last 4 chars, mask the middle."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _scan_lines(
    file: Path,
    lines: list[str],
    ignore: IgnoreRules,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for lineno, line in enumerate(lines, start=1):
        if ignore.is_suppressed_line(line):
            continue
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                raw = match.group(1) if match.lastindex else match.group(0)
                if not raw or len(raw) < 8:
                    continue
                if pattern.entropy_check and not is_high_entropy(raw, pattern.entropy_charset):
                    continue
                dedup_key = f"{file}:{pattern.name}:{raw}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    Finding(
                        file=file,
                        line=lineno,
                        pattern=pattern,
                        redacted=_redact(raw),
                        raw=raw,
                    )
                )
    return findings


def scan_path(root: Path, ignore: IgnoreRules) -> list[Finding]:
    """Scan a directory tree or a single file."""
    findings: list[Finding] = []

    paths = [root] if root.is_file() else sorted(root.rglob("*"))
    for path in paths:
        if not path.is_file():
            continue
        if ignore.is_ignored(path):
            continue
        if ignore.is_binary(path):
            continue
        if ignore.is_oversized(path):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        findings.extend(_scan_lines(path, lines, ignore))

    return findings


def scan_staged(root: Path, ignore: IgnoreRules) -> list[Finding]:
    """
    Scan only git-staged files using 'git show :<path>' to read the staged content.
    This is what the pre-commit hook uses — it sees exactly what will be committed.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    findings: list[Finding] = []
    for rel_path in result.stdout.strip().splitlines():
        if not rel_path:
            continue
        path = root / rel_path
        if ignore.is_ignored(path):
            continue

        # Read staged content from git index (not working tree)
        try:
            content_result = subprocess.run(
                ["git", "show", f":{rel_path}"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        if content_result.returncode != 0:
            continue

        content = content_result.stdout
        if "\x00" in content:  # binary
            continue

        lines = content.splitlines()
        findings.extend(_scan_lines(path, lines, ignore))

    return findings

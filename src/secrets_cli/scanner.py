"""
Core scanner — walks files and applies patterns.

Three modes:
  - scan_path(path):    walk a directory or single file
  - scan_staged(root):  scan only git-staged content (reads from git index)
  - scan_history(root): scan entire git commit history (added lines only)
"""

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .entropy import is_high_entropy
from .ignore import IgnoreRules
from .patterns import PATTERNS, Pattern


@dataclass
class Finding:
    file: Path
    line: int
    pattern: Pattern
    redacted: str    # shown to user: first 4 + **** + last 4
    raw: str         # used only for deduplication, never printed
    commit: str = field(default="")       # short hash (history mode only)
    commit_msg: str = field(default="")   # first line of commit message


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _scan_lines(
    file: Path,
    lines: list[str],
    ignore: IgnoreRules,
    seen: set[str] | None = None,
    commit: str = "",
    commit_msg: str = "",
) -> list[Finding]:
    findings: list[Finding] = []
    if seen is None:
        seen = set()

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
                        commit=commit,
                        commit_msg=commit_msg,
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
    Scan only git-staged files using 'git show :<path>' to read staged content.
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
        if "\x00" in content:
            continue

        lines = content.splitlines()
        findings.extend(_scan_lines(path, lines, ignore))

    return findings


def scan_history(
    root: Path,
    ignore: IgnoreRules,
    max_commits: int = 0,
) -> list[Finding]:
    """
    Scan the entire git commit history for secrets in added lines.

    Reads only lines introduced ('+') in each commit's diff so that
    deleted secrets are still found even if no longer in the working tree.
    Deduplicates globally: same secret in same file reported once.
    """
    try:
        log_result = subprocess.run(
            ["git", "log", "--all", "--reverse", "--format=%H %s"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if log_result.returncode != 0:
        return []

    commit_lines = [c for c in log_result.stdout.strip().splitlines() if c]
    if max_commits:
        commit_lines = commit_lines[-max_commits:]

    findings: list[Finding] = []
    seen: set[str] = set()   # global dedup across all commits

    for commit_line in commit_lines:
        parts = commit_line.split(" ", 1)
        commit_hash = parts[0]
        commit_msg = parts[1] if len(parts) > 1 else ""
        short_hash = commit_hash[:8]

        try:
            diff_result = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "--root", "-r", "-p", commit_hash],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
                errors="replace",
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        if diff_result.returncode != 0:
            continue

        current_file: Path | None = None
        current_line = 0

        for diff_line in diff_result.stdout.splitlines():
            if diff_line.startswith("+++ b/"):
                current_file = root / diff_line[6:]
                current_line = 0
            elif diff_line.startswith("@@ "):
                m = re.search(r"\+(\d+)", diff_line)
                if m:
                    current_line = int(m.group(1)) - 1
            elif diff_line.startswith("+") and not diff_line.startswith("+++"):
                current_line += 1
                if current_file is None or ignore.is_ignored(current_file):
                    continue
                content = diff_line[1:]
                new = _scan_lines(
                    current_file,
                    [content],
                    ignore,
                    seen=seen,
                    commit=short_hash,
                    commit_msg=commit_msg,
                )
                findings.extend(new)
            elif not diff_line.startswith("-"):
                current_line += 1

    return findings

"""
.secretsignore parser — gitignore-style path exclusions.

Supports:
  - Exact filenames:   config.py
  - Wildcards:         tests/fixtures/*
  - Directory prefix:  tests/
  - Negation:          !important.py  (override previous ignore)
  - Comments:          # this is a comment
  - Inline nosecrets:  # nosecrets  (on the same line as the secret)
"""

import fnmatch
from pathlib import Path

INLINE_SUPPRESS = "nosecrets"
IGNORE_FILENAME = ".secretsignore"

# Files/dirs always skipped regardless of .secretsignore
ALWAYS_SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".eggs", "*.egg-info",
    ".mypy_cache", ".ruff_cache", ".pytest_cache",
}

ALWAYS_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".wasm",
    ".pyc", ".pyo", ".class",
    ".lock",  # lockfiles contain hashes, not secrets
    ".sum",
}

# Filenames that commonly contain example/test secrets — skip by default
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tpl")


class IgnoreRules:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._rules: list[tuple[bool, str]] = []  # (negated, pattern)
        self._load()

    def _load(self) -> None:
        ignore_file = self.root / IGNORE_FILENAME
        if not ignore_file.exists():
            return
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            pattern = line[1:] if negated else line
            self._rules.append((negated, pattern))

    def is_ignored(self, path: Path) -> bool:
        try:
            rel = path.relative_to(self.root).as_posix()
        except ValueError:
            rel = path.name  # file outside root — match only by filename

        # Check always-skip dirs
        for part in path.parts:
            if part in ALWAYS_SKIP_DIRS:
                return True

        # Check always-skip extensions
        if path.suffix.lower() in ALWAYS_SKIP_EXTENSIONS:
            return True

        # Check example suffixes (e.g. .env.example)
        name_lower = path.name.lower()
        if any(name_lower.endswith(s) for s in EXAMPLE_SUFFIXES):
            return True

        # Apply .secretsignore rules (last matching rule wins)
        ignored = False
        for negated, pattern in self._rules:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern):
                ignored = not negated
        return ignored

    def is_suppressed_line(self, line: str) -> bool:
        return INLINE_SUPPRESS in line.lower()

    def is_binary(self, path: Path) -> bool:
        try:
            chunk = path.read_bytes()[:8192]
            return b"\x00" in chunk
        except OSError:
            return True

    def is_oversized(self, path: Path, max_bytes: int = 1_048_576) -> bool:
        try:
            return path.stat().st_size > max_bytes
        except OSError:
            return True

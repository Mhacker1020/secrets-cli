"""Git pre-commit hook installer/uninstaller."""

import os
import stat
from pathlib import Path

HOOK_SCRIPT = """\
#!/bin/sh
# Installed by secrets-cli — do not edit manually
secrets scan --staged --no-color
exit $?
"""

HOOK_PATH_RELATIVE = ".git/hooks/pre-commit"


def _find_git_root(start: Path) -> Path | None:
    current = start.resolve()
    while True:
        if (current / ".git").is_dir():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def install(cwd: Path) -> None:
    root = _find_git_root(cwd)
    if root is None:
        raise RuntimeError("Not inside a git repository.")

    hook = root / HOOK_PATH_RELATIVE
    hooks_dir = hook.parent
    hooks_dir.mkdir(parents=True, exist_ok=True)

    if hook.exists():
        existing = hook.read_text()
        if "secrets-cli" in existing:
            print(f"Hook already installed at {hook}")
            return
        # Append to existing hook instead of overwriting
        updated = existing.rstrip("\n") + "\n\n" + HOOK_SCRIPT.strip() + "\n"
        hook.write_text(updated)
        print(f"Appended secrets-cli to existing hook at {hook}")
    else:
        hook.write_text(HOOK_SCRIPT)

    # Make executable
    current_mode = os.stat(hook).st_mode
    hook.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"✓ Pre-commit hook installed at {hook}")
    print("  secrets scan --staged will run before every commit.")


def uninstall(cwd: Path) -> None:
    root = _find_git_root(cwd)
    if root is None:
        raise RuntimeError("Not inside a git repository.")

    hook = root / HOOK_PATH_RELATIVE
    if not hook.exists():
        print("No pre-commit hook found.")
        return

    content = hook.read_text()
    if "secrets-cli" not in content:
        print("secrets-cli hook not found in pre-commit hook.")
        return

    # Remove only the secrets-cli block, preserve the rest
    lines = content.splitlines(keepends=True)
    cleaned = [
        line for line in lines
        if "secrets-cli" not in line and "secrets scan" not in line
    ]
    result = "".join(cleaned).strip()

    if result in ("#!/bin/sh", ""):
        hook.unlink()
        print(f"✓ Pre-commit hook removed from {hook}")
    else:
        hook.write_text(result + "\n")
        print(f"✓ secrets-cli block removed from {hook} (other hooks preserved)")

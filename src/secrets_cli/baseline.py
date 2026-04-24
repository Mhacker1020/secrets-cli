"""
Baseline management — suppress known/accepted findings from future scans.

The baseline stores SHA-256 fingerprints of each finding (file + pattern + raw),
so the file is safe to commit: it never contains the actual secrets.

Workflow:
  1. secrets baseline          → write .nosecrets-baseline.json
  2. secrets scan --baseline   → skip baseline findings, report only new ones
  3. Team commits baseline file → everyone gets the same suppression list
"""

import hashlib
import json
from pathlib import Path

from .scanner import Finding

BASELINE_FILE = ".nosecrets-baseline.json"


def _fingerprint(f: Finding) -> str:
    key = f"{f.file.as_posix()}:{f.pattern.name}:{f.raw}"
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()


def create_baseline(findings: list[Finding], path: Path) -> None:
    """Serialise findings as a baseline. Raw secrets are never stored."""
    entries = [
        {
            "file": f.file.as_posix(),
            "pattern": f.pattern.name,
            "fingerprint": _fingerprint(f),
        }
        for f in findings
    ]
    data: dict[str, object] = {
        "version": 1,
        "count": len(entries),
        "findings": entries,
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> set[str]:
    """Return the set of fingerprints stored in a baseline file."""
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {e["fingerprint"] for e in data.get("findings", [])}
    except (json.JSONDecodeError, KeyError, OSError):
        return set()


def filter_baseline(findings: list[Finding], baseline: set[str]) -> list[Finding]:
    """Remove findings whose fingerprint is already in the baseline."""
    return [f for f in findings if _fingerprint(f) not in baseline]

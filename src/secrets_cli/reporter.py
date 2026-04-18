"""Terminal reporter — ANSI colors, no external deps."""

import json
import sys
from pathlib import Path

from .scanner import Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[93m",  # bright yellow
    "MEDIUM":   "\033[94m",  # bright blue
    "INFO":     "\033[96m",  # bright cyan
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
    "GREEN":    "\033[92m",
}


def _c(color: str, text: str, no_color: bool = False) -> str:
    if no_color or not sys.stdout.isatty():
        return text
    return f"{COLORS[color]}{text}{COLORS['RESET']}"


def print_findings(findings: list[Finding], no_color: bool = False) -> None:
    if not findings:
        print(_c("GREEN", "✓ No secrets detected.", no_color))
        return

    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.pattern.severity, 9), str(f.file), f.line))

    print()
    for f in sorted_findings:
        sev = f.pattern.severity
        sev_label = _c(sev, f"[{sev}]", no_color)
        bold = COLORS["BOLD"] if not no_color else ""
        reset = COLORS["RESET"] if not no_color else ""

        print(f"  {sev_label}  {bold}{f.file}:{f.line}{reset}")
        print(f"         {_c('DIM', f.pattern.name, no_color)}: {f.redacted}")
        print()

    _print_summary(findings, no_color)


def _print_summary(findings: list[Finding], no_color: bool) -> None:
    from collections import Counter
    counts = Counter(f.pattern.severity for f in findings)

    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        if counts[sev]:
            parts.append(_c(sev, f"{counts[sev]} {sev}", no_color))

    total = len(findings)
    print(_c("BOLD", f"  Found {total} potential secret(s): ", no_color) + ", ".join(parts))
    print()
    print(_c("DIM", "  To suppress a finding:", no_color))
    print(_c("DIM", "    Inline:  add  # nosecrets  at end of line", no_color))
    print(_c("DIM", "    Global:  add path to .secretsignore", no_color))
    print()


def print_json(findings: list[Finding], cwd: Path) -> None:
    output = []
    for f in findings:
        try:
            rel = f.file.relative_to(cwd).as_posix()
        except ValueError:
            rel = str(f.file)
        output.append({
            "file": rel,
            "line": f.line,
            "name": f.pattern.name,
            "severity": f.pattern.severity,
            "match": f.redacted,
            "description": f.pattern.description,
        })
    print(json.dumps(output, indent=2))

"""Terminal reporter — ANSI colors, no external deps."""

import json
import sys
from pathlib import Path

from . import __version__
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

    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.pattern.severity, 9), str(f.file), f.line),
    )

    print()
    for f in sorted_findings:
        sev = f.pattern.severity
        sev_label = _c(sev, f"[{sev}]", no_color)
        bold = COLORS["BOLD"] if not no_color else ""
        reset = COLORS["RESET"] if not no_color else ""

        if f.commit:
            location = f"{f.file} (commit {f.commit}: {f.commit_msg[:60]})"
        else:
            location = f"{f.file}:{f.line}"

        print(f"  {sev_label}  {bold}{location}{reset}")
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
    print(_c("DIM", "    Inline:   add  # nosecrets  at end of line", no_color))
    print(_c("DIM", "    Baseline: secrets baseline  (suppress all current findings)", no_color))
    print(_c("DIM", "    Global:   add path to .secretsignore", no_color))
    print()


def print_json(findings: list[Finding], cwd: Path) -> None:
    output = []
    for f in findings:
        try:
            rel = f.file.relative_to(cwd).as_posix()
        except ValueError:
            rel = str(f.file)
        entry: dict[str, object] = {
            "file": rel,
            "line": f.line,
            "name": f.pattern.name,
            "severity": f.pattern.severity,
            "match": f.redacted,
            "description": f.pattern.description,
        }
        if f.commit:
            entry["commit"] = f.commit
            entry["commit_msg"] = f.commit_msg
        output.append(entry)
    print(json.dumps(output, indent=2))


def print_sarif(findings: list[Finding], cwd: Path) -> None:
    """Output SARIF 2.1.0 — consumed by GitHub Advanced Security for inline PR annotations."""
    rules: dict[str, dict[str, object]] = {}
    for f in findings:
        rid = _sarif_rule_id(f.pattern.name)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.pattern.name.replace(" ", "").replace("(", "").replace(")", ""),
                "shortDescription": {"text": f.pattern.description},
                "defaultConfiguration": {"level": _sarif_level(f.pattern.severity)},
                "properties": {"tags": ["security", "secrets"]},
            }

    results = []
    for f in findings:
        try:
            rel = f.file.relative_to(cwd).as_posix()
        except ValueError:
            rel = str(f.file)
        msg = f"{f.pattern.description}: {f.redacted}"
        if f.commit:
            msg += f" (introduced in {f.commit})"
        results.append({
            "ruleId": _sarif_rule_id(f.pattern.name),
            "level": _sarif_level(f.pattern.severity),
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(f.line, 1)},
                }
            }],
        })

    sarif: dict[str, object] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "nosecrets",
                    "version": __version__,
                    "informationUri": "https://github.com/Mhacker1020/secrets-cli",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    print(json.dumps(sarif, indent=2))


def _sarif_rule_id(pattern_name: str) -> str:
    return (
        pattern_name.upper()
        .replace(" ", "_")
        .replace("(", "").replace(")", "")
        .replace("/", "_").replace("-", "_")
    )


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "INFO": "note"}.get(
        severity, "warning"
    )

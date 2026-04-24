"""secrets-cli — main entry point."""

import argparse
import sys
from pathlib import Path

from .baseline import BASELINE_FILE, create_baseline, filter_baseline, load_baseline
from .hooks.precommit import install as hook_install
from .hooks.precommit import uninstall as hook_uninstall
from .ignore import IgnoreRules
from .reporter import print_findings, print_json, print_sarif
from .scanner import scan_history, scan_path, scan_staged

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets",
        description="Scan for hardcoded secrets before they reach your repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secrets scan                       Scan current directory
  secrets scan src/                  Scan a specific path
  secrets scan --staged              Scan only git-staged files (pre-commit)
  secrets scan --history             Scan entire git commit history
  secrets scan --history --max-commits 50
  secrets scan --format sarif        SARIF output (GitHub Advanced Security)
  secrets scan --format json         JSON output (CI / automation)
  secrets scan --baseline            Skip findings already in baseline file
  secrets scan --severity high       Only report HIGH and above
  secrets baseline                   Write current findings to baseline file
  secrets init                       Install git pre-commit hook
  secrets uninstall                  Remove git pre-commit hook
        """,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # ── scan ──
    scan = subparsers.add_parser("scan", help="Scan for secrets")
    scan.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory)",
    )
    scan.add_argument(
        "--staged",
        action="store_true",
        help="Scan only git-staged files",
    )
    scan.add_argument(
        "--history",
        action="store_true",
        help="Scan entire git commit history (added lines only)",
    )
    scan.add_argument(
        "--max-commits",
        type=int,
        default=0,
        metavar="N",
        help="Limit history scan to last N commits (default: all)",
    )
    scan.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan.add_argument(
        "--json",
        action="store_true",
        help=argparse.SUPPRESS,  # kept for backward compat
    )
    scan.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )
    scan.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "info"],
        default="medium",
        help="Minimum severity to report (default: medium)",
    )
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "info"],
        default="high",
        help="Exit code 1 if findings at or above this severity (default: high)",
    )
    scan.add_argument(
        "--baseline",
        action="store_true",
        help=f"Skip findings already in {BASELINE_FILE}",
    )

    # ── baseline ──
    bl = subparsers.add_parser(
        "baseline",
        help=f"Write current findings to {BASELINE_FILE} (suppress them in future scans)",
    )
    bl.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (default: current directory)",
    )
    bl.add_argument(
        "--output",
        default=BASELINE_FILE,
        metavar="FILE",
        help=f"Baseline file to write (default: {BASELINE_FILE})",
    )

    # ── init ──
    subparsers.add_parser("init", help="Install git pre-commit hook")

    # ── uninstall ──
    subparsers.add_parser("uninstall", help="Remove git pre-commit hook")

    return parser


def _severity_passes(severity: str, min_severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 9) <= SEVERITY_ORDER.get(min_severity.upper(), 9)


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    cwd = Path.cwd()

    # ── init / uninstall ──
    if args.command == "init":
        try:
            hook_install(cwd)
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == "uninstall":
        try:
            hook_uninstall(cwd)
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # ── baseline (write) ──
    if args.command == "baseline":
        target = Path(args.path).resolve()
        if not target.exists():
            print(f"Error: path does not exist: {target}", file=sys.stderr)
            sys.exit(1)
        ignore = IgnoreRules(root=cwd)
        findings = scan_path(root=target, ignore=ignore)
        out_path = Path(args.output)
        create_baseline(findings, out_path)
        print(f"Baseline written: {out_path} ({len(findings)} finding(s) suppressed)")
        return

    # ── scan ──
    target = Path(args.path).resolve()
    ignore = IgnoreRules(root=cwd)

    if args.history:
        findings = scan_history(root=cwd, ignore=ignore, max_commits=args.max_commits)
    elif args.staged:
        findings = scan_staged(root=cwd, ignore=ignore)
    else:
        if not target.exists():
            print(f"Error: path does not exist: {target}", file=sys.stderr)
            sys.exit(1)
        findings = scan_path(root=target, ignore=ignore)

    # Filter by minimum severity
    min_sev = args.severity.upper()
    findings = [f for f in findings if _severity_passes(f.pattern.severity, min_sev)]

    # Apply baseline filter
    if args.baseline:
        baseline = load_baseline(cwd / BASELINE_FILE)
        before = len(findings)
        findings = filter_baseline(findings, baseline)
        suppressed = before - len(findings)
        if suppressed:
            print(f"  [{suppressed} finding(s) suppressed by baseline]", file=sys.stderr)

    # Resolve output format (--json is legacy alias for --format json)
    fmt = "json" if args.json else args.format

    if fmt == "json":
        print_json(findings, cwd)
    elif fmt == "sarif":
        print_sarif(findings, cwd)
    else:
        print_findings(findings, no_color=args.no_color)

    # Exit code
    fail_on = args.fail_on.upper()
    should_fail = any(_severity_passes(f.pattern.severity, fail_on) for f in findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()

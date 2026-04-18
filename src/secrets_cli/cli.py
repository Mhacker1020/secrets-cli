"""secrets-cli — main entry point."""

import argparse
import sys
from pathlib import Path

from .hooks.precommit import install as hook_install
from .hooks.precommit import uninstall as hook_uninstall
from .ignore import IgnoreRules
from .reporter import print_findings, print_json
from .scanner import scan_path, scan_staged

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets",
        description="Scan for hardcoded secrets before they reach your repository.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  secrets scan                  Scan current directory
  secrets scan src/             Scan a specific path
  secrets scan --staged         Scan only git-staged files (pre-commit)
  secrets scan --json           JSON output (for CI / automation)
  secrets scan --severity high  Only report HIGH and above
  secrets init                  Install git pre-commit hook
  secrets uninstall             Remove pre-commit hook
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
        "--json",
        action="store_true",
        help="Output findings as JSON",
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

    # ── scan ──
    target = Path(args.path).resolve()
    ignore = IgnoreRules(root=cwd)

    if args.staged:
        findings = scan_staged(root=cwd, ignore=ignore)
    else:
        if not target.exists():
            print(f"Error: path does not exist: {target}", file=sys.stderr)
            sys.exit(1)
        findings = scan_path(root=target, ignore=ignore)

    # Filter by minimum severity
    min_sev = args.severity.upper()
    findings = [f for f in findings if _severity_passes(f.pattern.severity, min_sev)]

    if args.json:
        print_json(findings, cwd)
    else:
        print_findings(findings, no_color=args.no_color)

    # Exit code
    fail_on = args.fail_on.upper()
    should_fail = any(_severity_passes(f.pattern.severity, fail_on) for f in findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()

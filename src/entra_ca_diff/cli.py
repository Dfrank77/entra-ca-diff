"""Command line entry point."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .loader import PolicyLoadError, load_policies
from .report import RENDERERS, to_markdown
from .rules import compare_sets

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="entra-ca-diff",
        description="Compare two sets of Entra ID Conditional Access policies and flag "
                    "changes that reduce coverage or enforcement.",
    )
    parser.add_argument("baseline", help="Baseline policy JSON file or folder (what's live now)")
    parser.add_argument("proposed", help="Proposed policy JSON file or folder (the change)")
    parser.add_argument("--format", choices=sorted(RENDERERS), default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", help="Write the report to this file instead of stdout")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "never"], default="high",
                        help="Exit 1 if any finding is at or above this severity (default: high)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        baseline = load_policies(args.baseline)
        proposed = load_policies(args.proposed)
    except PolicyLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    compared = len(set(baseline.policies) | set(proposed.policies))
    if compared == 0:
        print("error: no Conditional Access policies found in either input", file=sys.stderr)
        return EXIT_ERROR

    for skipped in baseline.skipped + proposed.skipped:
        print(f"note: skipped {skipped} (not a Conditional Access policy)", file=sys.stderr)

    findings = compare_sets(baseline.policies, proposed.policies)
    report = RENDERERS[args.format](findings, compared)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report if report.endswith("\n") else report + "\n")
    else:
        print(report)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(to_markdown(findings, compared))

    if args.fail_on != "never" and any(f.at_least(args.fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

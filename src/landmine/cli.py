"""Command-line parsing and output routing."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from landmine import __version__
from landmine.analyzers.why import analyze_why
from landmine.git import GitError, GitTimeout
from landmine.renderers import render_json, render_markdown
from landmine.source import TargetError, parse_target


def _positive_float(value: str) -> float:
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def _add_shared_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--base")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=_positive_float, default=15.0)
    parser.add_argument("--max-files", type=_positive_int, default=1000)
    parser.add_argument("--max-commits", type=_positive_int, default=5000)
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="landmine", description="Discover hidden code-change risk"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    why = subparsers.add_parser("why", help="recover historical evidence for a target")
    why.add_argument("target")
    why.add_argument("--history-depth", type=_positive_int, default=50)
    why.add_argument("--follow-renames", action=argparse.BooleanOptionalAction, default=True)
    _add_shared_options(why)

    assumptions = subparsers.add_parser("assumptions", help="find hidden constraints (Phase 2)")
    assumptions.add_argument("target")
    _add_shared_options(assumptions)

    blast = subparsers.add_parser("blast", help="trace change impact (Phase 3)")
    blast.add_argument("change")
    blast.add_argument("--target")
    _add_shared_options(blast)

    defuse = subparsers.add_parser("defuse", help="build a safe change plan (Phase 4)")
    defuse.add_argument("target")
    defuse.add_argument("--goal", required=True)
    _add_shared_options(defuse)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "why":
        parser.error(f"{args.command} is visible in the CLI but is not implemented in Phase 0/1")
    try:
        target = parse_target(args.target)
        result = analyze_why(
            repo=args.repo,
            target=target,
            timeout=args.timeout,
            history_depth=min(args.history_depth, args.max_commits),
        )
    except TargetError as exc:
        parser.error(str(exc))
    except GitTimeout as exc:
        print(f"landmine: {exc}", file=sys.stderr)
        return 1
    except GitError as exc:
        print(f"landmine: {exc}", file=sys.stderr)
        return 3

    rendered = render_json(result) if args.format == "json" else render_markdown(result)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 1 if result.analysis_status.value == "partial" else 0

"""Command-line parsing and output routing."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from landmine import __version__
from landmine.analyzers.assumptions import analyze_assumptions
from landmine.analyzers.blast import analyze_blast
from landmine.analyzers.defuse import analyze_defuse
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


def _confidence(value: str) -> float:
    number = float(value)
    if not 0.0 <= number <= 1.0:
        raise argparse.ArgumentTypeError("must be between zero and one")
    return number


def _add_shared_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="repository to analyze")
    parser.add_argument("--base", help="reserved for a future comparison base; currently ignored")
    parser.add_argument(
        "--format", choices=("markdown", "json"), default="markdown", help="output format"
    )
    parser.add_argument("--output", type=Path, help="write output to this file")
    parser.add_argument("--timeout", type=_positive_float, default=15.0, help="analysis budget")
    parser.add_argument("--max-files", type=_positive_int, default=1000, help="file scan limit")
    parser.add_argument(
        "--max-commits",
        type=_positive_int,
        default=5000,
        help="Git history limit where supported",
    )
    parser.add_argument(
        "--include", action="append", default=[], help="reserved; currently ignored"
    )
    parser.add_argument(
        "--exclude", action="append", default=[], help="reserved; currently ignored"
    )
    parser.add_argument("--no-color", action="store_true", help="accepted; output is always plain")
    parser.add_argument("--verbose", action="store_true", help="reserved; currently ignored")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="landmine", description="Discover hidden code-change risk"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    why = subparsers.add_parser("why", help="recover historical evidence for a target")
    why.add_argument("target")
    why.add_argument("--history-depth", type=_positive_int, default=50, help="commit scan limit")
    why.add_argument(
        "--follow-renames",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="accepted for compatibility; rename following is always enabled",
    )
    _add_shared_options(why)

    assumptions = subparsers.add_parser("assumptions", help="find hidden constraints")
    assumptions.add_argument("target")
    assumptions.add_argument(
        "--category",
        choices=(
            "data",
            "environment",
            "external_contract",
            "ordering",
            "filesystem",
            "time",
        ),
        default=None,
    )
    assumptions.add_argument(
        "--min-confidence", type=_confidence, default=0.0, help="minimum finding confidence"
    )
    _add_shared_options(assumptions)

    blast = subparsers.add_parser("blast", help="trace direct Python change impact")
    blast.add_argument("change")
    blast.add_argument("--target", help="path, path:line-range, or symbol:name")
    blast.add_argument("--depth", type=_positive_int, default=1, help="only depth 1 is supported")
    _add_shared_options(blast)

    defuse = subparsers.add_parser("defuse", help="propose a non-executing safe change plan")
    defuse.add_argument("target", nargs="?")
    defuse.add_argument("--goal", help="required non-empty change objective")
    defuse.add_argument("--from-result", type=Path, help="reserved; currently returns failed")
    _add_shared_options(defuse)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        target = parse_target(args.target) if args.target is not None else None
        if args.command == "defuse":
            result = analyze_defuse(
                repo=args.repo,
                target=target,
                goal=args.goal,
                from_result=args.from_result,
                timeout=args.timeout,
                max_files=args.max_files,
                history_depth=args.max_commits,
            )
        elif args.command == "blast":
            result = analyze_blast(
                repo=args.repo,
                change=args.change,
                target=target,
                depth=args.depth,
                timeout=args.timeout,
                max_files=args.max_files,
            )
        elif args.command == "why":
            assert target is not None
            result = analyze_why(
                repo=args.repo,
                target=target,
                timeout=args.timeout,
                history_depth=min(args.history_depth, args.max_commits),
                max_files=args.max_files,
            )
        else:
            assert target is not None
            result = analyze_assumptions(
                repo=args.repo,
                target=target,
                category=args.category,
                min_confidence=args.min_confidence,
                timeout=args.timeout,
                max_files=args.max_files,
            )
    except TargetError as exc:
        parser.error(str(exc))
    except ValueError as exc:
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
    if result.error is not None:
        return 2
    return 1 if result.analysis_status.value == "partial" else 0

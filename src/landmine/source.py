"""Safe parsing and repository-relative resolution of analysis targets."""

from __future__ import annotations

import re
from pathlib import Path

from landmine.domain import Target


class TargetError(ValueError):
    """Raised when a target is malformed or escapes the repository."""


_LINE_SUFFIX = re.compile(r"^(?P<path>.+):(?P<start>[1-9]\d*)(?:-(?P<end>[1-9]\d*))?$")
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:$-]*$")


def parse_target(value: str) -> Target:
    """Parse path, path:line, path:start-end, or symbol:name syntax."""
    if value.startswith("symbol:"):
        symbol = value[7:]
        if not _SYMBOL.fullmatch(symbol):
            raise TargetError("symbol target must contain a non-empty identifier")
        return Target(symbol=symbol)

    match = _LINE_SUFFIX.match(value)
    if match:
        start = int(match.group("start"))
        end = int(match.group("end") or start)
        if end < start:
            raise TargetError("target line range end must be greater than or equal to start")
        return Target(path=match.group("path"), start_line=start, end_line=end)
    if not value or value.endswith(":"):
        raise TargetError("target must be path, path:line, or path:start-end")
    return Target(path=value)


def resolve_path_target(target: Target, repository_root: Path) -> Target:
    """Resolve a path target without permitting traversal or symlink escape."""
    if target.path is None:
        raise TargetError("symbol targets are not supported by this bounded why slice")
    root = repository_root.resolve()
    supplied = Path(target.path)
    candidate = supplied if supplied.is_absolute() else root / supplied
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise TargetError(f"target path does not exist: {target.path}") from exc
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise TargetError("target path resolves outside the repository") from exc
    if not resolved.is_file():
        raise TargetError("target path must identify a regular file")
    return Target(
        path=relative.as_posix(),
        start_line=target.start_line,
        end_line=target.end_line,
        symbol=target.symbol,
    )


def resolve_line_range(target: Target, repository_root: Path) -> Target:
    """Fill a path-only target with its bounded full-file line range."""
    if target.path is None:
        raise TargetError("target has no path")
    path = repository_root / Path(target.path)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            count = sum(1 for _ in handle)
    except OSError as exc:
        raise TargetError(f"cannot read target path: {target.path}") from exc
    if count == 0:
        raise TargetError("target file is empty")
    start = target.start_line or 1
    end = target.end_line or count
    if start > count or end > count:
        raise TargetError(f"target line range exceeds file length ({count})")
    return Target(path=target.path, start_line=start, end_line=end)

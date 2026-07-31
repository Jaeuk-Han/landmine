"""Safe parsing and repository-relative resolution of analysis targets."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from landmine.domain import SymbolCandidate, Target
from landmine.evidence import safe_excerpt


class TargetError(ValueError):
    """Raised when a target is malformed or escapes the repository."""


class SymbolResolutionError(TargetError):
    """A symbol could not be resolved safely to exactly one source location."""

    def __init__(
        self,
        *,
        code: str,
        message: str,
        symbol: str,
        candidates: tuple[SymbolCandidate, ...] = (),
        files_scanned: int = 0,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.symbol = symbol
        self.candidates = candidates
        self.files_scanned = files_scanned


_LINE_SUFFIX = re.compile(r"^(?P<path>.+):(?P<start>[1-9]\d*)(?:-(?P<end>[1-9]\d*))?$")
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:$-]*$")
_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".next",
        "build",
        "dist",
        "generated",
        "node_modules",
        "out",
        "vendor",
    }
)
_LOCK_FILES = frozenset(
    {
        "bun.lock",
        "composer.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "uv.lock",
        "yarn.lock",
    }
)
DEFAULT_MAX_SYMBOL_FILE_BYTES = 1_000_000


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
    return Target(
        path=target.path,
        start_line=start,
        end_line=end,
        symbol=target.symbol,
    )


def _is_excluded_path(path: str) -> bool:
    parts = tuple(part.lower() for part in path.split("/"))
    name = parts[-1]
    return (
        any(part in _EXCLUDED_DIRECTORIES for part in parts[:-1])
        or name in _LOCK_FILES
        or ".generated." in name
        or name.endswith((".generated", "_generated.py", "_generated.ts", "_generated.js"))
    )


def _definition_patterns(symbol: str, suffix: str) -> tuple[re.Pattern[str], ...]:
    escaped = re.escape(symbol)
    if suffix in _PYTHON_SUFFIXES:
        return (
            re.compile(rf"^\s*(?:async\s+)?def\s+{escaped}(?![A-Za-z0-9_$])"),
            re.compile(rf"^\s*class\s+{escaped}(?![A-Za-z0-9_$])"),
            re.compile(rf"^\s*{escaped}\s*(?::[^=]+)?="),
        )
    if suffix in _JS_SUFFIXES:
        prefix = r"^\s*(?:export\s+)?(?:default\s+)?"
        return (
            re.compile(
                prefix
                + r"(?:async\s+)?(?:function|class|interface|type|enum|namespace)\s+"
                + rf"{escaped}(?![A-Za-z0-9_$])"
            ),
            re.compile(prefix + rf"(?:const|let|var)\s+{escaped}(?![A-Za-z0-9_$])"),
        )
    return ()


def _candidate_sort_key(candidate: SymbolCandidate) -> tuple[int, str, int]:
    return (
        0 if candidate.match_kind == "definition" else 1,
        candidate.path,
        candidate.line,
    )


def _search_symbol_candidates(
    symbol: str,
    repository_root: Path,
    tracked_paths: Sequence[str],
    *,
    max_files: int,
    max_file_bytes: int,
    deadline: float | None,
    monotonic: Callable[[], float],
) -> tuple[tuple[SymbolCandidate, ...], int, bool]:
    root = repository_root.resolve()
    candidates: list[SymbolCandidate] = []
    files_scanned = 0
    truncated = False
    exact_reference = re.compile(rf"(?<![A-Za-z0-9_$]){re.escape(symbol)}(?![A-Za-z0-9_$])")

    normalized_paths = sorted({path.replace("\\", "/") for path in tracked_paths})
    for relative in normalized_paths:
        if _is_excluded_path(relative):
            continue
        if files_scanned >= max_files or (deadline is not None and monotonic() >= deadline):
            truncated = True
            break
        candidate_path = root.joinpath(*relative.split("/"))
        try:
            resolved = candidate_path.resolve(strict=True)
            resolved.relative_to(root)
            if not resolved.is_file():
                continue
            files_scanned += 1
            if resolved.stat().st_size > max_file_bytes:
                continue
            content = resolved.read_bytes()
        except (OSError, ValueError):
            continue
        if b"\0" in content[:8192]:
            continue
        text = content.decode("utf-8", errors="replace")
        definitions = _definition_patterns(symbol, resolved.suffix.lower())
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not exact_reference.search(line):
                continue
            match_kind = (
                "definition"
                if any(pattern.search(line) for pattern in definitions)
                else "reference"
            )
            candidates.append(
                SymbolCandidate(
                    path=relative,
                    line=line_number,
                    matching_text=safe_excerpt(line.strip(), max_lines=1, max_chars=500),
                    match_kind=match_kind,
                )
            )
    return tuple(sorted(candidates, key=_candidate_sort_key)), files_scanned, truncated


def discover_symbol_candidates(
    symbol: str,
    repository_root: Path,
    tracked_paths: Sequence[str],
    *,
    max_files: int,
    max_file_bytes: int = DEFAULT_MAX_SYMBOL_FILE_BYTES,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> tuple[SymbolCandidate, ...]:
    """Discover bounded exact lexical matches in deterministic order."""
    candidates, files_scanned, truncated = _search_symbol_candidates(
        symbol,
        repository_root,
        tracked_paths,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        deadline=deadline,
        monotonic=monotonic,
    )
    if truncated:
        raise SymbolResolutionError(
            code="symbol_search_budget_exhausted",
            message=(
                f"Symbol search for {symbol!r} reached the file or time budget; "
                "increase --max-files or --timeout."
            ),
            symbol=symbol,
            candidates=candidates,
            files_scanned=files_scanned,
        )
    return candidates


def resolve_symbol_target(
    target: Target,
    repository_root: Path,
    tracked_paths: Sequence[str],
    *,
    max_files: int,
    max_file_bytes: int = DEFAULT_MAX_SYMBOL_FILE_BYTES,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> Target:
    """Resolve one preferred symbol candidate or report deterministic alternatives."""
    if target.symbol is None:
        raise TargetError("symbol target has no symbol name")
    candidates = discover_symbol_candidates(
        target.symbol,
        repository_root,
        tracked_paths,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        deadline=deadline,
        monotonic=monotonic,
    )
    definitions = tuple(
        candidate for candidate in candidates if candidate.match_kind == "definition"
    )
    preferred = definitions or candidates
    if not preferred:
        raise SymbolResolutionError(
            code="symbol_not_found",
            message=(
                f"No exact lexical match was found for symbol {target.symbol!r}. "
                "Check the spelling or use a path:line target."
            ),
            symbol=target.symbol,
        )
    if len(preferred) > 1:
        raise SymbolResolutionError(
            code="ambiguous_symbol",
            message=(
                f"Symbol {target.symbol!r} has {len(preferred)} preferred candidates; "
                "select one with path:line."
            ),
            symbol=target.symbol,
            candidates=candidates,
        )
    selected = preferred[0]
    return Target(
        path=selected.path,
        start_line=selected.line,
        end_line=selected.line,
        symbol=target.symbol,
    )

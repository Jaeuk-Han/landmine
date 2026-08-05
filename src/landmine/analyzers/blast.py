"""Bounded Python direct-impact analysis for ``landmine blast``."""

from __future__ import annotations

import ast
import hashlib
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from landmine.domain import (
    AnalysisStatus,
    BlastAnalysis,
    BlastImpact,
    BlastImpactStatus,
    BlastSubject,
    ClaimStatus,
    ErrorDetail,
    Evidence,
    Finding,
    Impact,
    Limitation,
    Metrics,
    RepositoryState,
    Result,
    SymbolCandidate,
    Target,
)
from landmine.evidence import make_evidence
from landmine.git import RepositorySnapshot, list_tracked_files, preflight
from landmine.scoring import score_blast
from landmine.source import (
    SymbolResolutionError,
    discover_symbol_candidates,
    resolve_line_range,
    resolve_path_target,
)

Clock = Callable[[], datetime]
MAX_SOURCE_BYTES = 1_000_000
_EXCLUDED_PARTS = frozenset(
    {".git", ".next", "build", "dist", "generated", "node_modules", "out", "vendor"}
)
_NOT_EVALUATED = (
    "git_cochange",
    "second_hop",
    "behavioral_impact",
    "operational_impact",
)


@dataclass(frozen=True)
class _ImportBinding:
    kind: str
    local_name: str
    line: int
    module: str
    imported_name: str | None = None
    scope_start: int | None = None
    scope_end: int | None = None


@dataclass(frozen=True)
class _Reference:
    local_name: str
    line: int
    column: int
    excerpt: str
    binding_line: int | None = None
    binding_name: str | None = None
    start_column: int | None = None
    end_column: int | None = None


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(clock: Clock) -> str:
    return clock().astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _target_dict(target: Target | None) -> dict[str, object] | None:
    if target is None:
        return None
    return {
        "path": target.path,
        "start_line": target.start_line,
        "end_line": target.end_line,
        "symbol": target.symbol,
    }


def _is_test_path(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    return name.endswith(".py") and (
        any(part in {"test", "tests"} for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _eligible_python_path(path: str) -> bool:
    parts = path.lower().split("/")
    return (
        path.lower().endswith((".py", ".pyi"))
        and not any(part in _EXCLUDED_PARTS for part in parts[:-1])
        and ".generated." not in parts[-1]
        and not parts[-1].endswith("_generated.py")
    )


def _read_source(root: Path, relative: str) -> str | None:
    candidate = root.joinpath(*relative.split("/"))
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.stat().st_size > MAX_SOURCE_BYTES:
            return None
        content = resolved.read_bytes()
    except (OSError, ValueError):
        return None
    if b"\0" in content[:8192]:
        return None
    return content.decode("utf-8", errors="replace")


def _source_line(source: str, line: int) -> str:
    lines = source.splitlines()
    return lines[line - 1] if 1 <= line <= len(lines) else ""


def _module_name(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized.startswith("src/"):
        normalized = normalized[4:]
    if normalized.endswith(".pyi"):
        normalized = normalized[:-4]
    elif normalized.endswith(".py"):
        normalized = normalized[:-3]
    parts = normalized.split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(part for part in parts if part)


def _resolve_import_from(node: ast.ImportFrom, current_module: str) -> str:
    if node.level == 0:
        return node.module or ""
    package = current_module.split(".")[:-1]
    keep = max(0, len(package) - node.level + 1)
    prefix = package[:keep]
    if node.module:
        prefix.extend(node.module.split("."))
    return ".".join(prefix)


def _containing_subject(tree: ast.Module, target: Target) -> BlastSubject:
    assert target.path is not None
    start = target.start_line or 1
    end = target.end_line or start
    named = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.lineno <= start
        and (node.end_lineno or node.lineno) >= end
    ]
    if target.symbol is not None:
        exact = [node for node in named if node.name == target.symbol]
        if exact:
            node = min(exact, key=lambda item: (item.end_lineno or item.lineno) - item.lineno)
            return BlastSubject(target.path, node.lineno, node.end_lineno or node.lineno, node.name)
    if target.start_line is not None and named:
        node = min(named, key=lambda item: (item.end_lineno or item.lineno) - item.lineno)
        return BlastSubject(target.path, node.lineno, node.end_lineno or node.lineno, node.name)
    return BlastSubject(target.path, start, end, target.symbol)


def _is_module_definition(source: str, symbol: str, line: int) -> bool:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == symbol and node.lineno == line:
                return True
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(target, ast.Name) and target.id == symbol and target.lineno == line
                for target in targets
            ):
                return True
    return False


def _resolve_blast_symbol(
    target: Target,
    root: Path,
    tracked: Sequence[str],
    *,
    max_files: int,
    deadline: float,
    monotonic: Callable[[], float],
) -> Target:
    assert target.symbol is not None
    candidates = discover_symbol_candidates(
        target.symbol,
        root,
        tracked,
        max_files=max_files,
        deadline=deadline,
        monotonic=monotonic,
    )
    definitions: list[SymbolCandidate] = []
    for candidate in candidates:
        if candidate.match_kind != "definition":
            continue
        if not candidate.path.endswith((".py", ".pyi")):
            definitions.append(candidate)
            continue
        source = _read_source(root, candidate.path)
        if source is not None and _is_module_definition(source, target.symbol, candidate.line):
            definitions.append(candidate)
    preferred = definitions or [
        candidate for candidate in candidates if candidate.match_kind == "reference"
    ]
    if not preferred:
        raise SymbolResolutionError(
            code="symbol_not_found",
            message=(
                f"No exact lexical match was found for symbol {target.symbol!r}. "
                "Check the spelling or use a path:line target."
            ),
            symbol=target.symbol,
            candidates=candidates,
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


def _subject_label(subject: BlastSubject) -> str:
    if subject.symbol:
        return f"{subject.symbol} definition at {subject.path}:{subject.start_line}"
    return f"module {subject.path}"


def _byte_offset_to_character_column(line: str, offset: int) -> int | None:
    if offset < 0:
        return None
    encoded = line.encode("utf-8")
    if offset > len(encoded):
        return None
    try:
        prefix = encoded[:offset].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return len(prefix) + 1


def _node_character_columns(line: str, node: ast.AST) -> tuple[int | None, int | None]:
    start_offset = getattr(node, "col_offset", None)
    end_offset = getattr(node, "end_col_offset", None)
    line_number = getattr(node, "lineno", None)
    end_line_number = getattr(node, "end_lineno", None)
    if (
        not isinstance(start_offset, int)
        or not isinstance(end_offset, int)
        or line_number != end_line_number
    ):
        return None, None
    start_column = _byte_offset_to_character_column(line, start_offset)
    end_column = _byte_offset_to_character_column(line, end_offset)
    if start_column is None or end_column is None or end_column < start_column:
        return None, None
    return start_column, end_column


def _reference_from_node(
    *,
    local_name: str,
    node: ast.Name | ast.Attribute,
    source: str,
    binding_line: int | None = None,
    binding_name: str | None = None,
) -> _Reference:
    excerpt = _source_line(source, node.lineno)
    start_column, end_column = _node_character_columns(excerpt, node)
    return _Reference(
        local_name=local_name,
        line=node.lineno,
        column=node.col_offset,
        excerpt=excerpt,
        binding_line=binding_line,
        binding_name=binding_name,
        start_column=start_column,
        end_column=end_column,
    )


def _column_locator(reference: _Reference) -> dict[str, int]:
    if reference.start_column is None or reference.end_column is None:
        return {}
    return {
        "start_column": reference.start_column,
        "end_column": reference.end_column,
    }


def _impact_id(
    impact_type: str,
    path: str,
    line: int,
    end_line: int,
    symbol: str | None,
    evidence_ids: Sequence[str],
    start_column: int | None = None,
    end_column: int | None = None,
) -> str:
    parts = [
        impact_type,
        path,
        str(line),
        str(end_line),
        symbol or "",
        ",".join(sorted(evidence_ids)),
    ]
    if start_column is not None and end_column is not None:
        parts.extend((str(start_column), str(end_column)))
    material = "\0".join(parts)
    return f"impact_{hashlib.sha256(material.encode()).hexdigest()[:12]}"


def _make_impact(
    *,
    impact_type: str,
    path: str,
    line: int,
    end_line: int | None = None,
    symbol: str | None,
    confidence: float,
    evidence_ids: Sequence[str],
    path_from_target: Sequence[str],
    reason: str,
    limitations: Sequence[str] = (),
    start_column: int | None = None,
    end_column: int | None = None,
) -> BlastImpact:
    ordered_evidence = tuple(sorted(set(evidence_ids)))
    resolved_end_line = end_line or line
    return BlastImpact(
        id=_impact_id(
            impact_type,
            path,
            line,
            resolved_end_line,
            symbol,
            ordered_evidence,
            start_column,
            end_column,
        ),
        impact_type=impact_type,
        path=path,
        start_line=line,
        end_line=resolved_end_line,
        symbol=symbol,
        status=BlastImpactStatus.DIRECT,
        confidence=confidence,
        evidence_ids=ordered_evidence,
        path_from_target=tuple(path_from_target),
        reason=reason,
        limitations=tuple(sorted(set(limitations))),
        start_column=start_column,
        end_column=end_column,
    )


def _reference_bindings(
    tree: ast.Module,
    *,
    current_module: str,
    target_module: str,
    target_symbol: str | None,
) -> tuple[tuple[_ImportBinding, ...], tuple[int, ...], tuple[str, ...]]:
    bindings: list[_ImportBinding] = []
    wildcard_lines: list[int] = []
    unresolved: list[str] = []
    parent, _, child = target_module.rpartition(".")
    parents = _parent_map(tree)

    def function_scope(node: ast.AST) -> tuple[int | None, int | None]:
        current = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.AsyncFunctionDef, ast.FunctionDef)):
                return current.lineno, current.end_lineno or current.lineno
        return None, None

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == target_module:
                    bindings.append(
                        _ImportBinding(
                            "module",
                            alias.asname or alias.name,
                            node.lineno,
                            target_module,
                        )
                    )
                elif target_symbol is not None and target_module.startswith(f"{alias.name}."):
                    remaining_module = target_module[len(alias.name) + 1 :]
                    local_prefix = alias.asname or alias.name
                    scope_start, scope_end = function_scope(node)
                    bindings.append(
                        _ImportBinding(
                            "package_symbol",
                            f"{local_prefix}.{remaining_module}",
                            node.lineno,
                            target_module,
                            scope_start=scope_start,
                            scope_end=scope_end,
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module = _resolve_import_from(node, current_module)
            for alias in node.names:
                if alias.name == "*" and module == target_module:
                    wildcard_lines.append(node.lineno)
                    continue
                if module == target_module:
                    if target_symbol is not None and alias.name == target_symbol:
                        bindings.append(
                            _ImportBinding(
                                "symbol",
                                alias.asname or alias.name,
                                node.lineno,
                                module,
                                alias.name,
                            )
                        )
                    elif target_symbol is None:
                        bindings.append(
                            _ImportBinding(
                                "member",
                                alias.asname or alias.name,
                                node.lineno,
                                module,
                                alias.name,
                            )
                        )
                elif module == parent and alias.name == child:
                    bindings.append(
                        _ImportBinding(
                            "module" if target_symbol is None else "module_symbol",
                            alias.asname or alias.name,
                            node.lineno,
                            target_module,
                        )
                    )
        elif isinstance(node, ast.Call):
            function = node.func
            is_dynamic = (
                isinstance(function, ast.Attribute)
                and isinstance(function.value, ast.Name)
                and function.value.id == "importlib"
                and function.attr == "import_module"
            )
            if (
                is_dynamic
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == target_module
            ):
                unresolved.append("dynamic_import")
    return (
        tuple(sorted(bindings, key=lambda item: (item.line, item.kind, item.local_name))),
        tuple(sorted(set(wildcard_lines))),
        tuple(sorted(set(unresolved))),
    )


def _function_local_names(tree: ast.Module) -> dict[ast.AST, set[str]]:
    result: dict[ast.AST, set[str]] = {}
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        names = {
            node.id
            for node in ast.walk(function)
            if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
        }
        names.update(argument.arg for argument in function.args.args)
        names.update(argument.arg for argument in function.args.kwonlyargs)
        if function.args.vararg:
            names.add(function.args.vararg.arg)
        if function.args.kwarg:
            names.add(function.args.kwarg.arg)
        result[function] = names
    return result


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _shadowed(
    node: ast.AST,
    name: str,
    parents: dict[ast.AST, ast.AST],
    locals_by_function: dict[ast.AST, set[str]],
) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if current in locals_by_function:
            return name in locals_by_function[current]
    return False


def _find_references(
    tree: ast.Module,
    source: str,
    bindings: Sequence[_ImportBinding],
    target_symbol: str | None,
) -> tuple[_Reference, ...]:
    parents = _parent_map(tree)
    locals_by_function = _function_local_names(tree)
    references: list[_Reference] = []

    def dotted_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = dotted_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else None
        return None

    module_rebindings: dict[str, list[int]] = {}
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        targets: Sequence[ast.AST] = (
            statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
        )
        for target_node in targets:
            for node in ast.walk(target_node):
                if isinstance(node, ast.Name):
                    module_rebindings.setdefault(node.id, []).append(node.lineno)

    for binding in bindings:
        binding_root = binding.local_name.split(".")[0]
        for node in ast.walk(tree):
            if binding.kind in {"symbol", "member"} and isinstance(node, ast.Name):
                if (
                    isinstance(node.ctx, ast.Load)
                    and node.id == binding.local_name
                    and node.lineno != binding.line
                    and not _shadowed(node, binding.local_name, parents, locals_by_function)
                    and not any(
                        binding.line < line <= node.lineno
                        for line in module_rebindings.get(binding_root, ())
                    )
                ):
                    references.append(
                        _reference_from_node(
                            local_name=binding.local_name,
                            node=node,
                            source=source,
                            binding_line=binding.line,
                            binding_name=binding.local_name,
                        )
                    )
            elif binding.kind in {
                "module",
                "module_symbol",
                "package_symbol",
            } and isinstance(node, ast.Attribute):
                if dotted_name(node.value) != binding.local_name:
                    continue
                root_name = binding.local_name.split(".")[0]
                if _shadowed(node, root_name, parents, locals_by_function):
                    continue
                if any(
                    binding.line < line <= node.lineno
                    for line in module_rebindings.get(root_name, ())
                ):
                    continue
                if target_symbol is not None and node.attr != target_symbol:
                    continue
                if binding.kind == "package_symbol":
                    if (
                        binding.scope_start is not None
                        and binding.scope_end is not None
                        and not binding.scope_start <= node.lineno <= binding.scope_end
                    ):
                        continue
                    parent = parents.get(node)
                    if not isinstance(parent, ast.Call) or parent.func is not node:
                        continue
                    if node.lineno <= binding.line:
                        continue
                references.append(
                    _reference_from_node(
                        local_name=node.attr,
                        node=node,
                        source=source,
                        binding_line=binding.line,
                        binding_name=binding.local_name,
                    )
                )
    return tuple(
        sorted(
            {
                (item.local_name, item.line, item.column, item.excerpt): item for item in references
            }.values(),
            key=lambda item: (item.line, item.column, item.local_name),
        )
    )


def _find_same_module_references(
    tree: ast.Module,
    source: str,
    symbol: str,
) -> tuple[_Reference, ...]:
    parents = _parent_map(tree)
    locals_by_function = _function_local_names(tree)
    references = [
        _reference_from_node(local_name=symbol, node=node, source=source)
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id == symbol
        and not _shadowed(node, symbol, parents, locals_by_function)
    ]
    return tuple(
        sorted(
            references,
            key=lambda item: (item.line, item.column, item.local_name),
        )
    )


def _candidate_test(
    path: str,
    tree: ast.Module,
    subject: BlastSubject,
    *,
    imports_target: bool = False,
) -> bool:
    if not _is_test_path(path):
        return False
    module_stem = Path(subject.path).stem.casefold()
    test_stem = Path(path).stem.casefold()
    if test_stem in {f"test_{module_stem}", f"{module_stem}_test"}:
        return True
    if subject.symbol is not None and any(
        (isinstance(node, ast.Name) and node.id == subject.symbol)
        or (isinstance(node, ast.Attribute) and node.attr == subject.symbol)
        for node in ast.walk(tree)
    ):
        return True
    return imports_target


def _error_result(
    *,
    repository: RepositoryState,
    observed_at: str,
    started: float,
    monotonic: Callable[[], float],
    change: str,
    target: Target | None,
    code: str,
    message: str,
    candidates: tuple[SymbolCandidate, ...] = (),
) -> Result:
    material = f"blast\0{repository.head}\0{change}\0{_target_dict(target)}\0{code}"
    return Result(
        schema_version="landmine.result.v1",
        analysis_id=f"lm_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
        analysis_status=AnalysisStatus.FAILED,
        command="blast",
        generated_at=observed_at,
        repository=repository,
        request={"target": _target_dict(target), "change": change, "goal": None, "depth": 1},
        summary=message,
        risk=score_blast(
            dependent_file_count=0,
            reference_site_count=0,
            direct_test_count=0,
            candidate_test_count=0,
            publicly_exported=False,
            importing_package_count=0,
            uncertainty_signals=("unresolved_import",),
        ),
        findings=(),
        evidence=(),
        limitations=(Limitation("unresolved_target", message, (str(_target_dict(target)),)),),
        metrics=Metrics(
            elapsed_ms=max(0, round((monotonic() - started) * 1000)),
            files_scanned=0,
            commits_scanned=0,
            evidence_count=0,
        ),
        error=ErrorDetail(code=code, message=message, candidates=candidates),
    )


def analyze_blast(
    *,
    repo: Path,
    change: str,
    target: Target | None,
    timeout: float = 15.0,
    max_files: int = 1000,
    depth: int = 1,
    clock: Clock = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
    snapshot: RepositorySnapshot | None = None,
) -> Result:
    """Analyze proven Python direct imports and references without executing source."""
    started = monotonic()
    observed_at = _timestamp(clock)
    repository, runner = (
        (snapshot.state, snapshot.runner)
        if snapshot is not None
        else preflight(repo, timeout=timeout)
    )
    root = runner.cwd.resolve()
    if target is None:
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            change=change,
            target=None,
            code="target_required",
            message="blast requires --target; provide a path, path:line, or symbol:name.",
        )
    if depth != 1:
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            change=change,
            target=target,
            code="unsupported_depth",
            message="This blast slice supports only --depth 1.",
        )
    tracked = list_tracked_files(runner)
    deadline = started + timeout
    try:
        resolved = (
            _resolve_blast_symbol(
                target,
                root,
                tracked,
                max_files=max_files,
                deadline=deadline,
                monotonic=monotonic,
            )
            if target.symbol is not None
            else resolve_path_target(target, root)
        )
        resolved = resolve_line_range(resolved, root)
    except SymbolResolutionError as exc:
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            change=change,
            target=target,
            code=exc.code,
            message=str(exc),
            candidates=exc.candidates,
        )

    limitations: list[Limitation] = []
    if not resolved.path or not resolved.path.lower().endswith((".py", ".pyi")):
        assert resolved.path is not None
        subject = BlastSubject(
            resolved.path,
            resolved.start_line or 1,
            resolved.end_line or resolved.start_line or 1,
            resolved.symbol,
        )
        limitations.append(
            Limitation(
                "unsupported_language",
                "The first blast vertical slice supports Python targets only.",
                (resolved.path,),
            )
        )
        return _result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            change=change,
            resolved=resolved,
            subject=subject,
            impacts=(),
            evidence=(),
            limitations=tuple(limitations),
            candidate_tests=(),
            files_scanned=0,
            status=AnalysisStatus.PARTIAL,
            publicly_exported=False,
        )

    source = _read_source(root, resolved.path)
    if source is None:
        raise ValueError(f"cannot read Python target: {resolved.path}")
    try:
        target_tree = ast.parse(source, filename=resolved.path)
    except SyntaxError:
        subject = BlastSubject(
            resolved.path,
            resolved.start_line or 1,
            resolved.end_line or resolved.start_line or 1,
            resolved.symbol,
        )
        limitations.append(
            Limitation(
                "provider_failure", "The Python target could not be parsed.", (resolved.path,)
            )
        )
        return _result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            change=change,
            resolved=resolved,
            subject=subject,
            impacts=(),
            evidence=(),
            limitations=tuple(limitations),
            candidate_tests=(),
            files_scanned=1,
            status=AnalysisStatus.PARTIAL,
            publicly_exported=False,
        )

    subject = (
        BlastSubject(
            resolved.path,
            resolved.start_line or 1,
            resolved.end_line or resolved.start_line or 1,
            None,
        )
        if target.symbol is None and target.start_line is None
        else _containing_subject(target_tree, resolved)
    )
    if target.start_line is not None and resolved.symbol is None and subject.symbol is None:
        limitations.append(
            Limitation(
                "file_level_fallback",
                "No containing named definition was found; analysis fell back to the file module.",
                (resolved.path,),
            )
        )

    evidence_by_id = {}
    definition_excerpt = "\n".join(
        source.splitlines()[subject.start_line - 1 : min(subject.end_line, subject.start_line + 11)]
    )
    definition = make_evidence(
        kind="definition",
        locator={
            "path": subject.path,
            "start_line": subject.start_line,
            "end_line": subject.end_line,
            "relationship": "blast target definition",
        },
        excerpt=definition_excerpt,
        observed_at=observed_at,
        command=None,
    )
    evidence_by_id[definition.id] = definition
    impacts: list[BlastImpact] = [
        _make_impact(
            impact_type="definition",
            path=subject.path,
            line=subject.start_line,
            end_line=subject.end_line,
            symbol=subject.symbol,
            confidence=0.99,
            evidence_ids=(definition.id,),
            path_from_target=(
                _subject_label(subject),
                f"defined at {subject.path}:{subject.start_line}",
            ),
            reason="The selected target resolves to this Python definition or module.",
        )
    ]
    if subject.symbol is not None:
        for local_reference in _find_same_module_references(target_tree, source, subject.symbol):
            local_evidence = make_evidence(
                kind="reference",
                locator={
                    "path": subject.path,
                    "start_line": local_reference.line,
                    "end_line": local_reference.line,
                    **_column_locator(local_reference),
                    "relationship": "same-module target definition reference",
                },
                excerpt=local_reference.excerpt,
                observed_at=observed_at,
                command=None,
            )
            evidence_by_id[local_evidence.id] = local_evidence
            impacts.append(
                _make_impact(
                    impact_type="reference",
                    path=subject.path,
                    line=local_reference.line,
                    symbol=subject.symbol,
                    confidence=0.92,
                    evidence_ids=(definition.id, local_evidence.id),
                    path_from_target=(
                        _subject_label(subject),
                        f"referenced in the same module at {subject.path}:{local_reference.line}",
                    ),
                    reason="The reference resolves to the target definition in the same module.",
                    start_column=local_reference.start_column,
                    end_column=local_reference.end_column,
                )
            )
    target_module = _module_name(subject.path)
    candidate_tests: set[str] = set()
    files_scanned = 0
    truncated = False
    publicly_exported = False

    for path in sorted(set(tracked)):
        if path == subject.path or not _eligible_python_path(path):
            continue
        if files_scanned >= max_files or monotonic() >= deadline:
            truncated = True
            break
        files_scanned += 1
        candidate_source = _read_source(root, path)
        if candidate_source is None:
            continue
        try:
            tree = ast.parse(candidate_source, filename=path)
        except SyntaxError:
            continue
        current_module = _module_name(path)
        bindings, wildcard_lines, unresolved = _reference_bindings(
            tree,
            current_module=current_module,
            target_module=target_module,
            target_symbol=subject.symbol,
        )
        imports_target = bool(
            any(binding.kind != "package_symbol" for binding in bindings)
            or wildcard_lines
            or unresolved
        )
        for line in wildcard_lines:
            limitations.append(
                Limitation(
                    "wildcard_import",
                    "A wildcard import may expose the target, but its binding is unresolved.",
                    (f"{path}:{line}",),
                )
            )
        if unresolved:
            limitations.append(
                Limitation(
                    "dynamic_import",
                    "A dynamic import mentions the target module and was not executed.",
                    (path,),
                )
            )
        references = _find_references(tree, candidate_source, bindings, subject.symbol)
        proven_module_symbol_bindings = {
            (reference.binding_line, reference.binding_name)
            for reference in references
            if reference.binding_line is not None and reference.binding_name is not None
        }
        bindings = tuple(
            binding
            for binding in bindings
            if binding.kind not in {"module_symbol", "package_symbol"}
            or (binding.line, binding.local_name) in proven_module_symbol_bindings
        )
        if not bindings:
            if _candidate_test(
                path,
                tree,
                subject,
                imports_target=imports_target,
            ):
                candidate_tests.add(path)
            continue

        import_evidence_ids: list[str] = []
        for binding in bindings:
            import_evidence = make_evidence(
                kind="import",
                locator={
                    "path": path,
                    "start_line": binding.line,
                    "end_line": binding.line,
                    "relationship": f"imports {target_module}",
                },
                excerpt=_source_line(candidate_source, binding.line),
                observed_at=observed_at,
                command=None,
            )
            evidence_by_id[import_evidence.id] = import_evidence
            import_evidence_ids.append(import_evidence.id)

        if _is_test_path(path):
            if not references:
                candidate_tests.add(path)
                continue
            for reference in references:
                reference_evidence = make_evidence(
                    kind="test_reference",
                    locator={
                        "path": path,
                        "start_line": reference.line,
                        "end_line": reference.line,
                        **_column_locator(reference),
                        "relationship": "test imports and references blast target",
                    },
                    excerpt=reference.excerpt,
                    observed_at=observed_at,
                    command=None,
                )
                evidence_by_id[reference_evidence.id] = reference_evidence
                impacts.append(
                    _make_impact(
                        impact_type="test",
                        path=path,
                        line=reference.line,
                        symbol=reference.local_name,
                        confidence=0.94,
                        evidence_ids=(*import_evidence_ids, reference_evidence.id),
                        path_from_target=(
                            _subject_label(subject),
                            f"imported by {path}:{bindings[0].line}",
                            f"referenced by test at {path}:{reference.line}",
                        ),
                        reason=(
                            "The test has a proven target import and reference; its existence "
                            "does not establish behavioral coverage."
                        ),
                        start_column=reference.start_column,
                        end_column=reference.end_column,
                    )
                )
            continue

        for binding, evidence_id in zip(bindings, import_evidence_ids, strict=True):
            impacts.append(
                _make_impact(
                    impact_type="importer",
                    path=path,
                    line=binding.line,
                    symbol=binding.local_name,
                    confidence=0.96,
                    evidence_ids=(evidence_id,),
                    path_from_target=(
                        _subject_label(subject),
                        f"imported by {path}:{binding.line}",
                    ),
                    reason="The module directly imports the selected target module or symbol.",
                )
            )
        for reference in references:
            reference_evidence = make_evidence(
                kind="reference",
                locator={
                    "path": path,
                    "start_line": reference.line,
                    "end_line": reference.line,
                    **_column_locator(reference),
                    "relationship": "proven imported target reference",
                },
                excerpt=reference.excerpt,
                observed_at=observed_at,
                command=None,
            )
            evidence_by_id[reference_evidence.id] = reference_evidence
            impacts.append(
                _make_impact(
                    impact_type="reference",
                    path=path,
                    line=reference.line,
                    symbol=reference.local_name,
                    confidence=0.94,
                    evidence_ids=(*import_evidence_ids, reference_evidence.id),
                    path_from_target=(
                        _subject_label(subject),
                        f"imported by {path}:{bindings[0].line}",
                        f"referenced at {path}:{reference.line}",
                    ),
                    reason="The reference resolves through a proven Python import binding.",
                    start_column=reference.start_column,
                    end_column=reference.end_column,
                )
            )
        if path.endswith("/__init__.py") and bindings:
            publicly_exported = True

    if truncated:
        limitations.append(
            Limitation(
                "budget_exhausted",
                "Direct-impact traversal reached the configured file or timeout budget.",
                (subject.path,),
            )
        )
    return _result(
        repository=repository,
        observed_at=observed_at,
        started=started,
        monotonic=monotonic,
        change=change,
        resolved=resolved,
        subject=subject,
        impacts=tuple(impacts),
        evidence=tuple(evidence_by_id.values()),
        limitations=tuple(limitations),
        candidate_tests=tuple(sorted(candidate_tests)),
        files_scanned=files_scanned + 1,
        status=AnalysisStatus.PARTIAL if limitations or truncated else AnalysisStatus.COMPLETE,
        publicly_exported=publicly_exported,
    )


def _result(
    *,
    repository: RepositoryState,
    observed_at: str,
    started: float,
    monotonic: Callable[[], float],
    change: str,
    resolved: Target,
    subject: BlastSubject,
    impacts: Sequence[BlastImpact],
    evidence: Sequence[Evidence],
    limitations: Sequence[Limitation],
    candidate_tests: Sequence[str],
    files_scanned: int,
    status: AnalysisStatus,
    publicly_exported: bool,
) -> Result:
    ordered_impacts = tuple(
        sorted(
            impacts,
            key=lambda item: (
                {"definition": 0, "importer": 1, "reference": 2, "test": 3}.get(
                    item.impact_type, 9
                ),
                item.path,
                item.start_line,
                item.start_column or 0,
                item.end_column or 0,
                item.id,
            ),
        )
    )
    ordered_evidence = tuple(
        sorted(
            evidence,
            key=lambda item: (
                item.kind,
                str(item.locator.get("path", "")),
                int(item.locator.get("start_line", 0)),
                item.id,
            ),
        )
    )
    direct_tests = {item.path for item in ordered_impacts if item.impact_type == "test"}
    dependent_files = {
        item.path
        for item in ordered_impacts
        if item.path != subject.path and item.impact_type != "test"
    }
    reference_count = sum(item.impact_type in {"reference", "test"} for item in ordered_impacts)
    packages = {_module_name(path).split(".")[0] for path in dependent_files if _module_name(path)}
    uncertainty_signals = tuple(
        sorted(
            {
                (
                    "unsupported_dynamic_import"
                    if item.code in {"dynamic_import", "wildcard_import"}
                    else "traversal_budget_exhausted"
                    if item.code == "budget_exhausted"
                    else "file_level_fallback"
                    if item.code == "file_level_fallback"
                    else "unsupported_language"
                    if item.code == "unsupported_language"
                    else "unresolved_import"
                )
                for item in limitations
            }
        )
    )
    risk = score_blast(
        dependent_file_count=len(dependent_files),
        reference_site_count=reference_count,
        direct_test_count=len(direct_tests),
        candidate_test_count=len(candidate_tests),
        publicly_exported=publicly_exported,
        importing_package_count=len(packages),
        uncertainty_signals=uncertainty_signals,
    )
    blast_analysis = BlastAnalysis(
        scope="direct",
        supported_depth=1,
        subject=subject,
        impact_count=len(ordered_impacts),
        direct_test_count=len(direct_tests),
        candidate_test_count=len(candidate_tests),
        candidate_tests=tuple(sorted(set(candidate_tests))),
        not_evaluated=_NOT_EVALUATED,
    )
    findings = tuple(
        Finding(
            id=f"finding_{item.id[7:]}",
            type="direct_impact",
            title=f"Direct {item.impact_type}: {item.path}",
            claim=item.reason,
            status=ClaimStatus.VERIFIED
            if item.status is BlastImpactStatus.DIRECT
            else ClaimStatus.INFERRED,
            confidence=item.confidence,
            evidence_ids=item.evidence_ids,
            impact=Impact.DIRECT,
            tags=("blast", item.impact_type),
        )
        for item in ordered_impacts
    )
    analysis_material = (
        f"blast\0{repository.head}\0{change}\0{subject.path}\0{subject.symbol}\0"
        + ",".join(item.id for item in ordered_impacts)
    )
    return Result(
        schema_version="landmine.result.v1",
        analysis_id=f"lm_{hashlib.sha256(analysis_material.encode()).hexdigest()[:12]}",
        analysis_status=status,
        command="blast",
        generated_at=observed_at,
        repository=repository,
        request={
            "target": _target_dict(resolved),
            "change": change,
            "goal": None,
            "depth": 1,
        },
        summary=(
            f"Found {len(ordered_impacts)} direct impact(s), {len(direct_tests)} direct "
            f"test file(s), and {len(candidate_tests)} candidate test file(s)."
        ),
        risk=risk,
        findings=findings,
        evidence=ordered_evidence,
        limitations=tuple(
            sorted(
                set(limitations),
                key=lambda item: (item.code, item.affected, item.message),
            )
        ),
        metrics=Metrics(
            elapsed_ms=max(0, round((monotonic() - started) * 1000)),
            files_scanned=files_scanned,
            commits_scanned=0,
            evidence_count=len(ordered_evidence),
        ),
        blast_analysis=blast_analysis,
        impacts=ordered_impacts,
    )

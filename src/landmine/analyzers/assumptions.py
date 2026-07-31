"""Bounded orchestration for deterministic assumption detectors."""

from __future__ import annotations

import ast
import hashlib
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from landmine.assumptions import AnalysisContext, AssumptionCandidate
from landmine.detectors.python_non_empty_collection import PythonNonEmptyCollectionDetector
from landmine.domain import (
    AnalysisStatus,
    AssumptionAnalysis,
    AssumptionCategory,
    AssumptionDetail,
    ClaimStatus,
    ErrorDetail,
    Finding,
    Impact,
    Limitation,
    Metrics,
    ProtectionStatus,
    RepositoryState,
    Result,
    Target,
)
from landmine.evidence import make_evidence
from landmine.git import list_tracked_files, preflight
from landmine.scoring import score_assumptions
from landmine.source import (
    SymbolResolutionError,
    resolve_line_range,
    resolve_path_target,
    resolve_symbol_target,
)
from landmine.test_protection import TestProtectionMatch, analyze_python_test_source

Clock = Callable[[], datetime]
MAX_SOURCE_BYTES = 1_000_000
_DETECTOR = PythonNonEmptyCollectionDetector()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(clock: Clock) -> str:
    return clock().astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _target_dict(target: Target) -> dict[str, object]:
    return {
        "path": target.path,
        "start_line": target.start_line,
        "end_line": target.end_line,
        "symbol": target.symbol,
    }


def _no_evidence_finding(*, filtered: bool = False) -> Finding:
    detail = (
        "The active detector found no supported signal at or above the minimum confidence; "
        "the absence of other assumptions was not established."
        if filtered
        else "The active detector found no supported non-empty collection signal; "
        "the absence of other assumptions was not established."
    )
    return Finding(
        id="finding_no_assumption_evidence",
        type="no_assumption_evidence",
        title="No supported detector signal found",
        claim=detail,
        status=ClaimStatus.UNKNOWN,
        confidence=0.0,
        evidence_ids=(),
        impact=Impact.UNKNOWN,
        tags=("assumptions", "no-evidence"),
    )


def _is_test_path(path: str) -> bool:
    lowered = path.lower()
    parts = lowered.split("/")
    name = parts[-1]
    return (
        lowered.endswith(".py")
        and (
            any(part in {"test", "tests"} for part in parts[:-1])
            or name.startswith("test_")
            or name.endswith("_test.py")
        )
        and not any(part in {".git", "build", "dist", "generated", "vendor"} for part in parts[:-1])
        and ".generated." not in name
    )


def _read_bounded_text(root: Path, relative: str) -> str | None:
    path = root.joinpath(*relative.split("/"))
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.stat().st_size > MAX_SOURCE_BYTES:
            return None
        content = resolved.read_bytes()
    except (OSError, ValueError):
        return None
    if b"\0" in content[:8192]:
        return None
    return content.decode("utf-8", errors="replace")


def _discover_test_protection(
    *,
    root: Path,
    tracked_paths: Sequence[str],
    scopes: set[str],
    max_files: int,
    deadline: float,
    monotonic: Callable[[], float],
) -> tuple[tuple[TestProtectionMatch, ...], int, bool, bool]:
    matches: list[TestProtectionMatch] = []
    scanned = 0
    truncated = False
    parse_failure = False
    if not scopes:
        return (), scanned, truncated, parse_failure
    for path in sorted(set(tracked_paths)):
        if not _is_test_path(path):
            continue
        if scanned >= max_files or monotonic() >= deadline:
            truncated = True
            break
        scanned += 1
        source = _read_bounded_text(root, path)
        if source is None:
            continue
        try:
            matches.extend(analyze_python_test_source(path, source, scopes))
        except SyntaxError:
            parse_failure = True
    combined: dict[tuple[str, str], TestProtectionMatch] = {}
    for match in matches:
        key = (match.path, match.scope)
        existing = combined.get(key)
        if existing is None or (match.empty_input and not existing.empty_input):
            combined[key] = match
    return (
        tuple(
            sorted(
                combined.values(),
                key=lambda item: (item.path, item.scope, item.line, not item.empty_input),
            )
        ),
        scanned,
        truncated,
        parse_failure,
    )


def _symbol_definition_range(tree: ast.Module, target: Target) -> Target:
    if target.symbol is None or target.start_line is None:
        return target
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == target.symbol
            and node.lineno == target.start_line
        ):
            return Target(
                path=target.path,
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
                symbol=target.symbol,
            )
    return target


def _error_result(
    *,
    repository: RepositoryState,
    observed_at: str,
    started: float,
    monotonic: Callable[[], float],
    exc: SymbolResolutionError,
) -> Result:
    material = f"assumptions\0{repository.head}\0symbol:{exc.symbol}\0{exc.code}\0" + ",".join(
        f"{candidate.match_kind}:{candidate.path}:{candidate.line}" for candidate in exc.candidates
    )
    limitation = Limitation(
        code="unresolved_target",
        message=str(exc),
        affected=(f"symbol:{exc.symbol}",),
    )
    return Result(
        schema_version="landmine.result.v1",
        analysis_id=f"lm_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
        analysis_status=AnalysisStatus.FAILED,
        command="assumptions",
        generated_at=observed_at,
        repository=repository,
        request={
            "target": _target_dict(Target(symbol=exc.symbol)),
            "change": None,
            "goal": None,
            "category": "data",
            "min_confidence": 0.0,
        },
        summary=str(exc),
        risk=score_assumptions(
            finding_count=0,
            protected_count=0,
            unknown_protection_count=0,
            limitation_count=1,
        ),
        findings=(),
        evidence=(),
        limitations=(limitation,),
        metrics=Metrics(
            elapsed_ms=max(0, round((monotonic() - started) * 1000)),
            files_scanned=exc.files_scanned,
            commits_scanned=0,
            evidence_count=0,
        ),
        error=ErrorDetail(code=exc.code, message=str(exc), candidates=exc.candidates),
        assumption_analysis=AssumptionAnalysis(
            detectors_run=(_DETECTOR.detector_id,),
            categories_scanned=(AssumptionCategory.DATA,),
            suppression_count=0,
        ),
    )


def analyze_assumptions(
    *,
    repo: Path,
    target: Target,
    category: str = "data",
    min_confidence: float = 0.0,
    timeout: float = 15.0,
    max_files: int = 1000,
    clock: Clock = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Result:
    """Analyze one Python target with the bounded data-cardinality detector."""
    if category != AssumptionCategory.DATA.value:
        raise ValueError(
            f"assumption category {category!r} is not implemented; use --category data"
        )
    started = monotonic()
    repository, runner = preflight(repo, timeout=timeout)
    root = runner.cwd
    observed_at = _timestamp(clock)
    tracked_paths = list_tracked_files(runner)
    try:
        if target.symbol is not None and target.path is None:
            target = resolve_symbol_target(
                target,
                root,
                tracked_paths,
                max_files=max_files,
                deadline=started + timeout,
                monotonic=monotonic,
            )
        resolved_path = resolve_path_target(target, root)
        resolved = resolve_line_range(resolved_path, root)
    except SymbolResolutionError as exc:
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            exc=exc,
        )
    assert resolved.path is not None
    assert resolved.start_line is not None
    assert resolved.end_line is not None
    target_path = resolved.path

    limitations: list[Limitation] = []
    source = _read_bounded_text(root, target_path)
    tree: ast.Module | None = None
    if not target_path.lower().endswith((".py", ".pyi")):
        limitations.append(
            Limitation(
                code="unsupported_language",
                message=(
                    "The active assumptions detector supports Python source only; "
                    "no detector finding was produced."
                ),
                affected=(target_path,),
            )
        )
    elif source is None:
        limitations.append(
            Limitation(
                code="binary_or_generated",
                message=(
                    "The target is binary, oversized, unreadable, "
                    "or outside the bounded source set."
                ),
                affected=(target_path,),
            )
        )
    else:
        try:
            tree = ast.parse(source, filename=target_path)
            resolved = _symbol_definition_range(tree, resolved)
        except SyntaxError as exc:
            limitations.append(
                Limitation(
                    code="provider_failure",
                    message=(
                        f"Python AST parsing failed at line {exc.lineno or 'unknown'}; "
                        "no detector finding was produced."
                    ),
                    affected=(target_path,),
                )
            )

    assert resolved.path is not None
    assert resolved.start_line is not None
    assert resolved.end_line is not None
    raw_candidates: list[AssumptionCandidate] = []
    if source is not None and tree is not None:
        raw_candidates = _DETECTOR.detect(
            AnalysisContext(
                path=resolved.path,
                source=source,
                start_line=resolved.start_line,
                end_line=resolved.end_line,
            )
        )
    suppressed = [item for item in raw_candidates if item.suppression_reason is not None]
    active = [item for item in raw_candidates if item.suppression_reason is None]
    scopes = {item.scope for item in active if item.scope is not None}
    test_matches, test_files_scanned, test_truncated, test_parse_failure = (
        _discover_test_protection(
            root=root,
            tracked_paths=tracked_paths,
            scopes=scopes,
            max_files=max_files,
            deadline=started + timeout,
            monotonic=monotonic,
        )
    )
    if test_truncated:
        limitations.append(
            Limitation(
                code="budget_exhausted",
                message="Related-test discovery reached the file or time budget.",
                affected=(resolved.path,),
            )
        )
    if test_parse_failure:
        limitations.append(
            Limitation(
                code="provider_failure",
                message="At least one candidate Python test file could not be parsed.",
                affected=(resolved.path,),
            )
        )

    evidence_by_id = {}
    matches_by_scope: dict[str, list[TestProtectionMatch]] = {}
    for match in test_matches:
        matches_by_scope.setdefault(match.scope, []).append(match)
        test_item = make_evidence(
            kind="test",
            locator={
                "path": match.path,
                "line": match.line,
                "target_scope": match.scope,
                "explicit_empty_input": match.empty_input,
            },
            excerpt=match.matching_text,
            observed_at=observed_at,
            command=None,
        )
        evidence_by_id[test_item.id] = test_item

    findings: list[Finding] = []
    protected_count = 0
    unknown_count = 0
    filtered_count = 0
    source_lines = source.splitlines() if source is not None else []
    for candidate in active:
        if candidate.confidence < min_confidence:
            filtered_count += 1
            continue
        line_excerpt = (
            source_lines[candidate.line - 1].strip()
            if 0 < candidate.line <= len(source_lines)
            else ""
        )
        source_item = make_evidence(
            kind="source",
            locator={
                "path": candidate.path,
                "line": candidate.line,
                "end_line": candidate.end_line,
                "detector_id": candidate.detector_id,
                "signal": candidate.observed_signal,
            },
            excerpt=line_excerpt,
            observed_at=observed_at,
            command=None,
        )
        evidence_by_id[source_item.id] = source_item
        related = matches_by_scope.get(candidate.scope or "", [])
        candidate_tests = tuple(sorted({item.path for item in related}))
        explicit_empty = any(item.empty_input for item in related)
        if explicit_empty:
            protection = ProtectionStatus.PROTECTED
            protected_count += 1
            uncertainty = (
                "An explicit empty-input call was found in a candidate test; "
                "the test was not executed."
            )
        elif related or test_truncated or test_parse_failure or candidate.scope is None:
            protection = ProtectionStatus.UNKNOWN
            unknown_count += 1
            uncertainty = (
                "Candidate tests were found, but no explicit empty-input call was proven."
                if related
                else "Test protection could not be determined within the available evidence."
            )
        else:
            protection = ProtectionStatus.UNPROTECTED
            uncertainty = "No candidate test reference was found in the bounded test search."
        test_ids = [
            item.id
            for item in evidence_by_id.values()
            if item.kind == "test" and item.locator.get("target_scope") == candidate.scope
        ]
        finding_material = (
            f"{candidate.detector_id}\0{candidate.path}\0{candidate.line}\0"
            f"{candidate.column}\0{candidate.observed_signal}\0{candidate.variable}"
        )
        findings.append(
            Finding(
                id=f"finding_{hashlib.sha256(finding_material.encode()).hexdigest()[:12]}",
                type="assumption",
                title="Unchecked collection cardinality",
                claim=candidate.claim,
                status=ClaimStatus.INFERRED,
                confidence=min(candidate.confidence, candidate.confidence_ceiling),
                evidence_ids=tuple(sorted({source_item.id, *test_ids})),
                impact=Impact.BEHAVIORAL,
                tags=("assumption", "data", candidate.detector_id),
                assumption=AssumptionDetail(
                    detector_id=candidate.detector_id,
                    category=candidate.category,
                    observed_signal=candidate.observed_signal,
                    violation_scenario=candidate.violation_scenario,
                    consequence=candidate.consequence,
                    confidence_ceiling=candidate.confidence_ceiling,
                    protection=protection,
                    candidate_tests=candidate_tests,
                    uncertainty=uncertainty,
                    scope=candidate.scope,
                ),
            )
        )

    findings.sort(
        key=lambda item: (
            next(
                (
                    int(evidence_by_id[evidence_id].locator.get("line", 0))
                    for evidence_id in item.evidence_ids
                    if evidence_by_id[evidence_id].kind == "source"
                ),
                0,
            ),
            item.id,
        )
    )
    if not findings:
        findings.append(_no_evidence_finding(filtered=filtered_count > 0))

    evidence = tuple(
        sorted(
            evidence_by_id.values(),
            key=lambda item: (
                item.kind,
                str(item.locator.get("path", "")),
                int(item.locator.get("line", 0)),
                item.id,
            ),
        )
    )
    status = AnalysisStatus.PARTIAL if limitations else AnalysisStatus.COMPLETE
    actual_findings = [item for item in findings if item.type == "assumption"]
    if actual_findings:
        summary = (
            f"Found {len(actual_findings)} supported non-empty collection signal(s) "
            f"with {_DETECTOR.detector_id}; suppressed {len(suppressed)} guarded or "
            "statically safe candidate(s)."
        )
    elif filtered_count:
        summary = (
            "The active detector found no supported signal at or above the minimum confidence; "
            f"{filtered_count} candidate(s) were filtered and {len(suppressed)} suppressed."
        )
    else:
        summary = (
            "The active detector found no supported non-empty collection signal; "
            f"{len(suppressed)} candidate(s) were suppressed. "
            "The absence of other assumptions was not established."
        )
    risk = score_assumptions(
        finding_count=len(actual_findings),
        protected_count=protected_count,
        unknown_protection_count=unknown_count,
        limitation_count=len(limitations),
    )
    material = (
        f"assumptions\0{repository.head}\0{resolved.path}\0{resolved.start_line}\0"
        f"{resolved.end_line}\0data\0{min_confidence:g}\0" + ",".join(item.id for item in evidence)
    )
    return Result(
        schema_version="landmine.result.v1",
        analysis_id=f"lm_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
        analysis_status=status,
        command="assumptions",
        generated_at=observed_at,
        repository=repository,
        request={
            "target": _target_dict(resolved),
            "change": None,
            "goal": None,
            "category": category,
            "min_confidence": min_confidence,
        },
        summary=summary,
        risk=risk,
        findings=tuple(findings),
        evidence=evidence,
        limitations=tuple(limitations),
        metrics=Metrics(
            elapsed_ms=max(0, round((monotonic() - started) * 1000)),
            files_scanned=1 + test_files_scanned,
            commits_scanned=0,
            evidence_count=len(evidence),
        ),
        assumption_analysis=AssumptionAnalysis(
            detectors_run=(_DETECTOR.detector_id,),
            categories_scanned=(AssumptionCategory.DATA,),
            suppression_count=len(suppressed),
        ),
    )

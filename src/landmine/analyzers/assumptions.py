"""Bounded orchestration for deterministic assumption detectors."""

from __future__ import annotations

import ast
import hashlib
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from landmine.assumptions import AnalysisContext, AssumptionCandidate, AssumptionDetector
from landmine.detectors.python_arbitrary_set_selection import (
    PythonArbitrarySetSelectionDetector,
)
from landmine.detectors.python_cwd_relative_file_access import (
    PythonCwdRelativeFileAccessDetector,
)
from landmine.detectors.python_non_empty_collection import PythonNonEmptyCollectionDetector
from landmine.detectors.python_required_environment_variable import (
    PythonRequiredEnvironmentVariableDetector,
)
from landmine.detectors.python_required_mapping_key import PythonRequiredMappingKeyDetector
from landmine.detectors.python_required_response_field import (
    PythonRequiredResponseFieldDetector,
)
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
_DETECTORS: tuple[AssumptionDetector, ...] = (
    PythonNonEmptyCollectionDetector(),
    PythonRequiredMappingKeyDetector(),
    PythonRequiredEnvironmentVariableDetector(),
    PythonRequiredResponseFieldDetector(),
    PythonArbitrarySetSelectionDetector(),
    PythonCwdRelativeFileAccessDetector(),
)


def _selected_detectors(category: str | None) -> tuple[AssumptionDetector, ...]:
    if category is None:
        return _DETECTORS
    try:
        selected_category = AssumptionCategory(category)
    except ValueError as exc:
        supported = ", ".join(item.value for item in AssumptionCategory)
        raise ValueError(
            f"assumption category {category!r} is not implemented; use one of: {supported}"
        ) from exc
    return tuple(detector for detector in _DETECTORS if detector.category is selected_category)


def _detector_categories(
    detectors: Sequence[AssumptionDetector],
) -> tuple[AssumptionCategory, ...]:
    return tuple(dict.fromkeys(detector.category for detector in detectors))


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


def _no_evidence_finding(
    *,
    filtered: bool = False,
    category_label: str = "data",
) -> Finding:
    detail = (
        "The active detector found no supported signal at or above the minimum confidence; "
        "the absence of other assumptions was not established."
        if filtered
        else f"The active detectors found no supported {category_label}-assumption signal; "
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
    return (
        tuple(
            sorted(
                set(matches),
                key=lambda item: (
                    item.path,
                    item.scope,
                    item.line,
                    not item.empty_input,
                    item.mapping_keys is None,
                    item.mapping_keys or (),
                    not item.expects_key_error,
                    item.removed_environment_variables,
                    tuple((mock.library, mock.method, mock.fields) for mock in item.response_mocks),
                    not item.changed_working_directory,
                ),
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
    category: str | None,
    detectors: Sequence[AssumptionDetector],
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
            "category": category,
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
            detectors_run=tuple(detector.detector_id for detector in detectors),
            categories_scanned=_detector_categories(detectors),
            suppression_count=0,
        ),
    )


def analyze_assumptions(
    *,
    repo: Path,
    target: Target,
    category: str | None = None,
    min_confidence: float = 0.0,
    timeout: float = 15.0,
    max_files: int = 1000,
    clock: Clock = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Result:
    """Analyze one Python target with the selected registered detectors."""
    detectors = _selected_detectors(category)
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
            category=category,
            detectors=detectors,
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
        context = AnalysisContext(
            path=resolved.path,
            source=source,
            start_line=resolved.start_line,
            end_line=resolved.end_line,
        )
        for detector in detectors:
            raw_candidates.extend(detector.detect(context))
    limited_candidates = [item for item in raw_candidates if item.limitation_reason is not None]
    if limited_candidates:
        affected = tuple(sorted({f"{item.path}:{item.line}" for item in limited_candidates}))
        limitations.append(
            Limitation(
                code="provider_failure",
                message=(
                    "At least one required mapping-key base expression could not be "
                    "normalized; no finding was produced for that access."
                ),
                affected=affected,
            )
        )
    suppressed = [
        item
        for item in raw_candidates
        if item.suppression_reason is not None and item.limitation_reason is None
    ]
    active = [
        item
        for item in raw_candidates
        if item.suppression_reason is None and item.limitation_reason is None
    ]
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
                **(
                    {"mapping_keys": list(match.mapping_keys)}
                    if match.mapping_keys is not None
                    else {}
                ),
                **({"changed_working_directory": True} if match.changed_working_directory else {}),
                **({"expects_key_error": True} if match.expects_key_error else {}),
                **(
                    {"removed_environment_variables": list(match.removed_environment_variables)}
                    if match.removed_environment_variables
                    else {}
                ),
                **(
                    {
                        "response_mocks": [
                            {
                                "library": mock.library,
                                "method": mock.method,
                                "fields": list(mock.fields),
                            }
                            for mock in match.response_mocks
                        ]
                    }
                    if match.response_mocks
                    else {}
                ),
            },
            excerpt=match.matching_text,
            observed_at=observed_at,
            command=None,
        )
        evidence_by_id[test_item.id] = test_item

    findings: list[Finding] = []
    finding_sort_keys: dict[str, tuple[int, str, int, int, str]] = {}
    detector_order = {detector.detector_id: index for index, detector in enumerate(_DETECTORS)}
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
                "column": candidate.column,
                "detector_id": candidate.detector_id,
                "signal": candidate.observed_signal,
                **(
                    {
                        "base_expression": candidate.variable,
                        "required_key": candidate.required_key,
                        **(
                            {
                                "http_library": candidate.http_library,
                                "http_method": candidate.http_method,
                            }
                            if candidate.http_library is not None
                            and candidate.http_method is not None
                            else {}
                        ),
                    }
                    if candidate.required_key is not None
                    else {}
                ),
                **(
                    {
                        "base_expression": candidate.variable,
                        "selection_operation": candidate.selection_operation,
                    }
                    if candidate.selection_operation is not None
                    else {}
                ),
                **(
                    {
                        "path_literal": candidate.path_literal,
                        "access_operation": candidate.access_operation,
                        "api_binding": candidate.api_binding,
                    }
                    if candidate.path_literal is not None
                    and candidate.access_operation is not None
                    and candidate.api_binding is not None
                    else {}
                ),
            },
            excerpt=line_excerpt,
            observed_at=observed_at,
            command=None,
        )
        evidence_by_id[source_item.id] = source_item
        provenance_ids: list[str] = []
        for observation in candidate.provenance:
            provenance_excerpt = (
                source_lines[observation.line - 1].strip()
                if 0 < observation.line <= len(source_lines)
                else ""
            )
            provenance_item = make_evidence(
                kind="source",
                locator={
                    "path": candidate.path,
                    "line": observation.line,
                    "end_line": observation.end_line,
                    "detector_id": candidate.detector_id,
                    "provenance_role": observation.role,
                    **(
                        {
                            "http_library": candidate.http_library,
                            "http_method": candidate.http_method,
                        }
                        if candidate.http_library is not None and candidate.http_method is not None
                        else {}
                    ),
                    **(
                        {"set_expression": observation.expression}
                        if candidate.selection_operation is not None
                        else {}
                    ),
                    **(
                        {"path_expression": observation.expression}
                        if candidate.path_literal is not None
                        else {}
                    ),
                },
                excerpt=provenance_excerpt,
                observed_at=observed_at,
                command=None,
            )
            evidence_by_id[provenance_item.id] = provenance_item
            provenance_ids.append(provenance_item.id)
        related = matches_by_scope.get(candidate.scope or "", [])
        candidate_tests = tuple(sorted({item.path for item in related}))
        environment_protection = candidate.detector_id == "python.required-environment-variable"
        mapping_protection = candidate.detector_id == "python.required-mapping-key"
        response_protection = candidate.detector_id == "python.required-response-field"
        ordering_protection = candidate.detector_id == "python.arbitrary-set-selection"
        filesystem_protection = candidate.detector_id == "python.cwd-relative-file-access"
        explicit_missing_key = any(
            item.mapping_keys is not None and candidate.required_key not in item.mapping_keys
            for item in related
        )
        key_error_characterization = any(
            item.mapping_keys is not None
            and candidate.required_key not in item.mapping_keys
            and item.expects_key_error
            for item in related
        )
        explicit_missing_environment = any(
            candidate.required_key in item.removed_environment_variables for item in related
        )
        environment_key_error_characterization = any(
            candidate.required_key in item.removed_environment_variables and item.expects_key_error
            for item in related
        )
        matching_response_mocks = [
            mock
            for item in related
            for mock in item.response_mocks
            if mock.library == candidate.http_library and mock.method == candidate.http_method
        ]
        explicit_missing_response_field = any(
            candidate.required_key not in mock.fields for mock in matching_response_mocks
        )
        response_key_error_characterization = any(
            item.expects_key_error
            and any(
                mock.library == candidate.http_library
                and mock.method == candidate.http_method
                and candidate.required_key not in mock.fields
                for mock in item.response_mocks
            )
            for item in related
        )
        cwd_characterized = any(item.changed_working_directory for item in related)
        if ordering_protection:
            explicit_edge_case = False
        elif filesystem_protection:
            explicit_edge_case = cwd_characterized
        elif response_protection:
            explicit_edge_case = explicit_missing_response_field
        elif environment_protection:
            explicit_edge_case = explicit_missing_environment
        elif mapping_protection:
            explicit_edge_case = explicit_missing_key
        else:
            explicit_edge_case = any(item.empty_input for item in related)
        if ordering_protection:
            protection = ProtectionStatus.UNKNOWN
            unknown_count += 1
            uncertainty = (
                (candidate.uncertainty_note + " ") if candidate.uncertainty_note is not None else ""
            ) + (
                "A related test does not prove deterministic set ordering."
                if related
                else (
                    "Static analysis cannot establish deterministic set ordering; "
                    "no multi-seed execution was performed."
                )
            )
        elif explicit_edge_case:
            protection = ProtectionStatus.PROTECTED
            protected_count += 1
            if filesystem_protection:
                uncertainty = (
                    (
                        candidate.uncertainty_note + " "
                        if candidate.uncertainty_note is not None
                        else ""
                    )
                    + "The working-directory-dependent behavior is explicitly "
                    "characterized with monkeypatch.chdir(...); protection does not "
                    "establish safety from every working directory."
                )
            elif response_protection:
                uncertainty = (
                    "The missing-field external response behavior is explicitly "
                    "characterized with a proven HTTP mock; "
                    + (
                        "a KeyError characterization is present. "
                        if response_key_error_characterization
                        else ""
                    )
                    + "Protection does not imply that production code handles schema drift."
                )
            elif environment_protection:
                uncertainty = (
                    "A missing-variable behavior is explicitly tested with "
                    "monkeypatch.delenv(..., raising=False); "
                    + (
                        "a KeyError characterization is present. "
                        if environment_key_error_characterization
                        else ""
                    )
                    + "Protection does not imply that production code handles the exception."
                )
            elif mapping_protection:
                uncertainty = (
                    "A missing-key behavior is explicitly tested with a mapping literal; "
                    + (
                        "a KeyError characterization is present. "
                        if key_error_characterization
                        else ""
                    )
                    + "Protection does not imply that production code handles the exception."
                )
            else:
                uncertainty = (
                    "An explicit empty-input call was found in a candidate test; "
                    "the test was not executed."
                )
        elif related or test_truncated or test_parse_failure or candidate.scope is None:
            protection = ProtectionStatus.UNKNOWN
            unknown_count += 1
            if related and filesystem_protection:
                uncertainty = (
                    (
                        candidate.uncertainty_note + " "
                        if candidate.uncertainty_note is not None
                        else ""
                    )
                    + "Candidate tests were found, but no direct monkeypatch.chdir(...) "
                    "setup was proven."
                )
            elif related and response_protection:
                uncertainty = (
                    "Candidate tests were found, but no proven HTTP mock omitted "
                    "the required response field."
                )
            elif related and environment_protection:
                uncertainty = (
                    "Candidate tests were found, but no explicit missing-variable setup "
                    "with monkeypatch.delenv(..., raising=False) was proven."
                )
            elif related and mapping_protection:
                uncertainty = (
                    "Candidate tests were found, but no explicit missing-key mapping was proven."
                )
            elif related:
                uncertainty = (
                    "Candidate tests were found, but no explicit empty-input call was proven."
                )
            else:
                uncertainty = (
                    "Test protection could not be determined within the available evidence."
                )
        else:
            protection = ProtectionStatus.UNPROTECTED
            uncertainty = (
                candidate.uncertainty_note + " "
                if filesystem_protection and candidate.uncertainty_note is not None
                else ""
            ) + "No candidate test reference was found in the bounded test search."
        test_ids = [
            item.id
            for item in evidence_by_id.values()
            if item.kind == "test" and item.locator.get("target_scope") == candidate.scope
        ]
        finding_material = (
            f"{candidate.detector_id}\0{candidate.path}\0{candidate.line}\0"
            f"{candidate.column}\0{candidate.observed_signal}\0{candidate.variable}\0"
            f"{candidate.required_key or ''}\0{candidate.selection_operation or ''}"
            f"\0{candidate.path_literal or ''}\0{candidate.access_operation or ''}"
        )
        if filesystem_protection:
            title = "CWD-relative file access"
        elif ordering_protection:
            title = "Arbitrary set element selection"
        elif response_protection:
            title = "Unchecked required response field"
        elif environment_protection:
            title = "Unchecked required environment variable"
        elif mapping_protection:
            title = "Unchecked required mapping key"
        else:
            title = "Unchecked collection cardinality"
        finding_id = f"finding_{hashlib.sha256(finding_material.encode()).hexdigest()[:12]}"
        findings.append(
            Finding(
                id=finding_id,
                type="assumption",
                title=title,
                claim=candidate.claim,
                status=ClaimStatus.INFERRED,
                confidence=min(candidate.confidence, candidate.confidence_ceiling),
                evidence_ids=tuple(sorted({source_item.id, *provenance_ids, *test_ids})),
                impact=Impact.BEHAVIORAL,
                tags=("assumption", candidate.category.value, candidate.detector_id),
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
                    base_expression=(
                        candidate.variable
                        if candidate.required_key is not None
                        or candidate.selection_operation is not None
                        or candidate.path_literal is not None
                        else None
                    ),
                    required_key=candidate.required_key,
                    http_library=candidate.http_library,
                    http_method=candidate.http_method,
                    selection_operation=candidate.selection_operation,
                    suggested_alternatives=candidate.suggested_alternatives,
                    path_literal=candidate.path_literal,
                    access_operation=candidate.access_operation,
                    api_binding=candidate.api_binding,
                    path_anchor=candidate.path_anchor,
                ),
            )
        )
        finding_sort_keys[finding_id] = (
            detector_order.get(candidate.detector_id, 999),
            candidate.path,
            candidate.line,
            candidate.column,
            finding_id,
        )

    findings.sort(key=lambda item: finding_sort_keys[item.id])
    if not findings:
        findings.append(
            _no_evidence_finding(
                filtered=filtered_count > 0,
                category_label=category or "registered",
            )
        )

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
        active_detector_ids = {
            item.assumption.detector_id for item in actual_findings if item.assumption is not None
        }
        if active_detector_ids == {"python.non-empty-collection"}:
            summary = (
                f"Found {len(actual_findings)} supported non-empty collection signal(s) "
                "with python.non-empty-collection; "
                f"suppressed {len(suppressed)} guarded or statically safe candidate(s)."
            )
        elif active_detector_ids == {"python.required-mapping-key"}:
            summary = (
                f"Found {len(actual_findings)} supported required mapping-key signal(s) "
                "with python.required-mapping-key; "
                f"suppressed {len(suppressed)} guarded or statically safe candidate(s)."
            )
        elif active_detector_ids == {"python.required-environment-variable"}:
            summary = (
                f"Found {len(actual_findings)} supported required environment-variable "
                "signal(s) with python.required-environment-variable; "
                f"suppressed {len(suppressed)} guarded or statically safe candidate(s)."
            )
        elif active_detector_ids == {"python.required-response-field"}:
            summary = (
                f"Found {len(actual_findings)} supported required response-field "
                "signal(s) with python.required-response-field; "
                f"suppressed {len(suppressed)} guarded or handled candidate(s)."
            )
        elif active_detector_ids == {"python.arbitrary-set-selection"}:
            summary = (
                f"Found {len(actual_findings)} supported arbitrary set-selection "
                "signal(s) with python.arbitrary-set-selection; "
                f"suppressed {len(suppressed)} statically deterministic candidate(s)."
            )
        elif active_detector_ids == {"python.cwd-relative-file-access"}:
            summary = (
                f"Found {len(actual_findings)} supported CWD-relative file-access "
                "signal(s) with python.cwd-relative-file-access; "
                f"suppressed {len(suppressed)} explicitly anchored candidate(s)."
            )
        else:
            summary = (
                f"Found {len(actual_findings)} supported assumption signal(s) "
                f"across {len(active_detector_ids)} detector(s); "
                f"suppressed {len(suppressed)} guarded or statically safe candidate(s)."
            )
    elif filtered_count:
        summary = (
            "The active detector found no supported signal at or above the minimum confidence; "
            f"{filtered_count} candidate(s) were filtered and {len(suppressed)} suppressed."
        )
    else:
        summary = (
            f"The active detectors found no supported {category or 'registered'}-assumption "
            "signal; "
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
        f"{resolved.end_line}\0{category or 'all'}\0{min_confidence:g}\0"
        + ",".join(item.id for item in evidence)
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
            detectors_run=tuple(detector.detector_id for detector in detectors),
            categories_scanned=_detector_categories(detectors),
            suppression_count=len(suppressed),
        ),
    )

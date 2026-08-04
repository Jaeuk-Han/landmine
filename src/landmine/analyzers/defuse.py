"""Deterministic, read-only safe-change planning from prerequisite analyses."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from landmine.analyzers.assumptions import analyze_assumptions
from landmine.analyzers.blast import analyze_blast
from landmine.analyzers.why import analyze_why
from landmine.domain import (
    AnalysisStatus,
    AssumptionDetail,
    ClaimStatus,
    DefuseAnalysis,
    ErrorDetail,
    Evidence,
    Finding,
    Limitation,
    Metrics,
    Plan,
    PlanItem,
    PlanItemStatus,
    PrerequisiteSummary,
    ProtectionStatus,
    RepositoryState,
    Result,
    SymbolCandidate,
    Target,
)
from landmine.git import RepositorySnapshot, list_tracked_files, preflight
from landmine.scoring import score_defuse
from landmine.source import (
    SymbolResolutionError,
    resolve_line_range,
    resolve_path_target,
    resolve_symbol_target,
)

Clock = Callable[[], datetime]


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


def _plan_item(
    *,
    kind: str,
    description: str,
    status: PlanItemStatus = PlanItemStatus.PROPOSED,
    evidence_ids: Sequence[str] = (),
    finding_ids: Sequence[str] = (),
    target_paths: Sequence[str] = (),
    command_args: Sequence[str] = (),
) -> PlanItem:
    normalized_evidence = tuple(sorted(set(evidence_ids)))
    normalized_findings = tuple(sorted(set(finding_ids)))
    normalized_paths = tuple(sorted(set(target_paths)))
    material = "\0".join(
        (
            kind,
            description,
            status.value,
            ",".join(normalized_evidence),
            ",".join(normalized_findings),
            ",".join(normalized_paths),
            "\0".join(command_args),
        )
    )
    return PlanItem(
        id=f"plan_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
        kind=kind,
        description=description,
        status=status,
        evidence_ids=normalized_evidence,
        related_finding_ids=normalized_findings,
        target_paths=normalized_paths,
        command_args=tuple(command_args),
    )


def _target_label(target: Target) -> str:
    if target.symbol:
        return f"`{target.symbol}`"
    assert target.path is not None
    if target.start_line is None:
        return f"`{target.path}`"
    return f"`{target.path}:{target.start_line}-{target.end_line or target.start_line}`"


def assumption_test_description(detail: AssumptionDetail, target_label: str) -> str:
    """Map detector metadata to a deterministic characterization specification."""
    detector = detail.detector_id
    if detector == "python.non-empty-collection":
        description = (
            f"Exercise {target_label} with an empty collection and record the intended behavior."
        )
    elif detector == "python.required-mapping-key":
        key = repr(detail.required_key) if detail.required_key is not None else "an unknown key"
        description = f"Exercise {target_label} with {key} omitted from the input mapping."
    elif detector == "python.required-environment-variable":
        name = (
            f"`{detail.required_key}`"
            if detail.required_key is not None
            else "the required environment variable"
        )
        description = f"Exercise {target_label} with {name} absent from the environment."
    elif detector == "python.required-response-field":
        field = repr(detail.required_key) if detail.required_key is not None else "an unknown field"
        description = (
            f"Exercise {target_label} with {field} omitted from the external JSON response."
        )
    elif detector == "python.arbitrary-set-selection":
        description = (
            f"Exercise {target_label} with a multi-element set and define an explicit "
            "selection rule."
        )
    elif detector == "python.cwd-relative-file-access":
        description = f"Exercise {target_label} from a different working directory."
    elif detector == "python.wall-clock-elapsed-time":
        description = f"Exercise {target_label} with backward and forward wall-clock adjustments."
    else:
        description = (
            f"Characterize the unresolved violation scenario for {target_label}; "
            "detector metadata is insufficient for a more specific input."
        )
    protection = (
        "Existing characterization evidence found."
        if detail.protection is ProtectionStatus.PROTECTED
        else "Characterization gap."
    )
    return f"{description} {protection}"


def _merge_evidence(results: Sequence[Result]) -> tuple[Evidence, ...]:
    by_id: dict[str, Evidence] = {}
    for result in results:
        for evidence in result.evidence:
            existing = by_id.get(evidence.id)
            if existing is None or existing == evidence:
                by_id[evidence.id] = evidence
                continue
            material = f"{result.command}\0{evidence.id}\0{evidence.excerpt_sha256}"
            replacement = Evidence(
                id=f"ev_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
                kind=evidence.kind,
                locator=evidence.locator,
                excerpt_sha256=evidence.excerpt_sha256,
                observed_at=evidence.observed_at,
                excerpt=evidence.excerpt,
                command=evidence.command,
            )
            by_id[replacement.id] = replacement
    return tuple(
        sorted(
            by_id.values(),
            key=lambda item: (
                item.kind,
                str(item.locator.get("path", "")),
                int(item.locator.get("start_line", 0)),
                item.id,
            ),
        )
    )


def _merge_findings(results: Sequence[Result]) -> tuple[Finding, ...]:
    by_id: dict[str, Finding] = {}
    for result in results:
        for finding in result.findings:
            existing = by_id.get(finding.id)
            if existing is None or existing == finding:
                by_id[finding.id] = finding
                continue
            material = f"{result.command}\0{finding.id}\0{finding.claim}"
            replacement = Finding(
                id=f"finding_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
                type=finding.type,
                title=finding.title,
                claim=finding.claim,
                status=finding.status,
                confidence=finding.confidence,
                evidence_ids=finding.evidence_ids,
                impact=finding.impact,
                tags=finding.tags,
                assumption=finding.assumption,
            )
            by_id[replacement.id] = replacement
    return tuple(
        sorted(
            by_id.values(),
            key=lambda item: (item.type, item.title, item.id),
        )
    )


def _repository_stable(snapshot: RepositorySnapshot) -> bool:
    runner = snapshot.runner
    head = runner.run(["rev-parse", "HEAD"]).stdout.strip()
    worktree_status = runner.run(["status", "--porcelain=v1", "--untracked-files=normal"]).stdout
    return head == snapshot.state.head and worktree_status == snapshot.worktree_status


def _has_pytest_configuration(root: Path, tracked: Sequence[str]) -> bool:
    if "pyproject.toml" not in tracked:
        return False
    path = root / "pyproject.toml"
    try:
        if path.stat().st_size > 1_000_000:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "[tool.pytest" in text


def _error_result(
    *,
    repository: RepositoryState,
    observed_at: str,
    started: float,
    monotonic: Callable[[], float],
    target: Target | None,
    goal: str | None,
    code: str,
    message: str,
    candidates: tuple[SymbolCandidate, ...] = (),
) -> Result:
    material = f"defuse\0{repository.head}\0{_target_dict(target)}\0{goal}\0{code}"
    return Result(
        schema_version="landmine.result.v1",
        analysis_id=f"lm_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
        analysis_status=AnalysisStatus.FAILED,
        command="defuse",
        generated_at=observed_at,
        repository=repository,
        request={"target": _target_dict(target), "change": None, "goal": goal},
        summary=message,
        risk=score_defuse(()),
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


def analyze_defuse(
    *,
    repo: Path,
    target: Target | None,
    goal: str | None,
    timeout: float = 15.0,
    max_files: int = 1000,
    history_depth: int = 50,
    from_result: Path | None = None,
    clock: Clock = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Result:
    """Compose prerequisite evidence into a plan without editing or executing tests."""
    started = monotonic()
    observed_at = _timestamp(clock)
    repository, runner = preflight(repo, timeout=timeout)
    worktree_status = runner.run(["status", "--porcelain=v1", "--untracked-files=normal"]).stdout
    snapshot = RepositorySnapshot(repository, runner, worktree_status)
    if target is None:
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            target=None,
            goal=goal,
            code="target_required",
            message="defuse requires TARGET; provide a path, path:line, or symbol:name.",
        )
    if goal is None or not goal.strip():
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            target=target,
            goal=goal,
            code="goal_required",
            message="defuse requires --goal with a non-empty change objective.",
        )
    if from_result is not None:
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            target=target,
            goal=goal,
            code="unsupported_from_result",
            message="--from-result is not supported by this defuse vertical slice.",
        )

    tracked = list_tracked_files(runner)
    try:
        if target.symbol is not None and target.path is None:
            target = resolve_symbol_target(
                target,
                runner.cwd,
                tracked,
                max_files=max_files,
                deadline=started + timeout,
                monotonic=monotonic,
            )
        resolved = resolve_line_range(resolve_path_target(target, runner.cwd), runner.cwd)
    except SymbolResolutionError as exc:
        return _error_result(
            repository=repository,
            observed_at=observed_at,
            started=started,
            monotonic=monotonic,
            target=target,
            goal=goal,
            code=exc.code,
            message=str(exc),
            candidates=exc.candidates,
        )

    def remaining() -> float:
        return max(0.001, timeout - max(0.0, monotonic() - started))

    why = analyze_why(
        repo=repo,
        target=resolved,
        timeout=remaining(),
        history_depth=history_depth,
        max_files=max_files,
        clock=clock,
        monotonic=monotonic,
        snapshot=snapshot,
    )
    assumptions = analyze_assumptions(
        repo=repo,
        target=resolved,
        timeout=remaining(),
        max_files=max_files,
        clock=clock,
        monotonic=monotonic,
        snapshot=snapshot,
    )
    blast = analyze_blast(
        repo=repo,
        change=goal,
        target=resolved,
        timeout=remaining(),
        max_files=max_files,
        clock=clock,
        monotonic=monotonic,
        snapshot=snapshot,
    )
    prerequisites = (why, assumptions, blast)
    evidence = _merge_evidence(prerequisites)
    findings = _merge_findings(prerequisites)
    stable = _repository_stable(snapshot)
    limitations = list(
        {
            (item.code, item.message, item.affected): item
            for result in prerequisites
            for item in result.limitations
            if item.code != "bounded_method"
        }.values()
    )
    if repository.dirty:
        limitations.append(
            Limitation(
                "dirty_worktree",
                "The repository had uncommitted changes when the plan snapshot was captured.",
                (resolved.path or "",),
            )
        )
    if not stable:
        limitations.append(
            Limitation(
                "repository_state_changed",
                "HEAD or worktree state changed during prerequisite analysis.",
                (resolved.path or "",),
            )
        )

    plan = _synthesize_plan(
        resolved=resolved,
        repository=repository,
        why=why,
        assumptions=assumptions,
        blast=blast,
        limitations=limitations,
        tracked=tracked,
        root=runner.cwd,
    )
    usable = bool(evidence or findings or blast.impacts)
    any_incomplete = any(
        result.analysis_status is not AnalysisStatus.COMPLETE for result in prerequisites
    )
    status = (
        AnalysisStatus.FAILED
        if not usable
        else AnalysisStatus.PARTIAL
        if any_incomplete or limitations or not stable or repository.dirty
        else AnalysisStatus.COMPLETE
    )
    risk = score_defuse(tuple((result.command, result.risk) for result in prerequisites))
    prerequisite_summary = tuple(
        PrerequisiteSummary(
            command=result.command,
            analysis_id=result.analysis_id,
            status=result.analysis_status,
            risk_score=result.risk.score,
            finding_count=len(result.findings),
            evidence_count=len(result.evidence),
        )
        for result in prerequisites
    )
    material = f"defuse\0{repository.head}\0{goal}\0{_target_dict(resolved)}\0" + ",".join(
        item.id for item in (*plan.preconditions, *plan.tests, *plan.steps)
    )
    return Result(
        schema_version="landmine.result.v1",
        analysis_id=f"lm_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
        analysis_status=status,
        command="defuse",
        generated_at=observed_at,
        repository=repository,
        request={"target": _target_dict(resolved), "change": None, "goal": goal},
        summary=(
            f"Proposed a non-executing safe-change plan from {len(prerequisites)} "
            f"prerequisite analyses and {len(evidence)} unique evidence item(s)."
        ),
        risk=risk,
        findings=findings,
        evidence=evidence,
        plan=plan,
        limitations=tuple(
            sorted(
                set(limitations),
                key=lambda item: (item.code, item.affected, item.message),
            )
        ),
        metrics=Metrics(
            elapsed_ms=max(0, round((monotonic() - started) * 1000)),
            files_scanned=sum(result.metrics.files_scanned for result in prerequisites),
            commits_scanned=max(
                (result.metrics.commits_scanned for result in prerequisites), default=0
            ),
            evidence_count=len(evidence),
        ),
        defuse_analysis=DefuseAnalysis(
            prerequisites=prerequisite_summary,
            snapshot_head=repository.head,
            snapshot_dirty=repository.dirty,
            repository_state_stable=stable,
        ),
    )


def _synthesize_plan(
    *,
    resolved: Target,
    repository: RepositoryState,
    why: Result,
    assumptions: Result,
    blast: Result,
    limitations: Sequence[Limitation],
    tracked: Sequence[str],
    root: Path,
) -> Plan:
    label = _target_label(resolved)
    preconditions: list[PlanItem] = []
    tests: list[PlanItem] = []
    steps: list[PlanItem] = []
    verification: list[PlanItem] = []
    rollback: list[PlanItem] = []
    unknowns: list[PlanItem] = []

    evidence_by_id = {item.id: item for item in why.evidence}
    historical = [
        finding
        for finding in why.findings
        if finding.type == "historical_intent"
        and finding.status in {ClaimStatus.VERIFIED, ClaimStatus.INFERRED}
        and any(
            evidence_by_id.get(evidence_id) is not None
            and evidence_by_id[evidence_id].kind in {"git_diff", "git_blame", "test"}
            for evidence_id in finding.evidence_ids
        )
    ]
    for finding in historical:
        preconditions.append(
            _plan_item(
                kind="precondition",
                description=(
                    f"Preserve or explicitly replace the historical constraint associated "
                    f"with {finding.title}."
                ),
                evidence_ids=finding.evidence_ids,
                finding_ids=(finding.id,),
                target_paths=(resolved.path or "",),
            )
        )
    if repository.dirty:
        preconditions.append(
            _plan_item(
                kind="precondition",
                description=(
                    "Separate or preserve existing uncommitted changes before applying the plan."
                ),
                status=PlanItemStatus.BLOCKED,
                target_paths=(resolved.path or "",),
            )
        )
    if limitations:
        preconditions.append(
            _plan_item(
                kind="precondition",
                description=(
                    "Resolve the unknown impact surface before treating this plan as complete."
                ),
                status=PlanItemStatus.BLOCKED,
                target_paths=(resolved.path or "",),
            )
        )

    seen_test_specs: set[tuple[str, str, str | None]] = set()
    for finding in assumptions.findings:
        detail = finding.assumption
        if detail is None:
            continue
        key = (detail.detector_id, detail.violation_scenario, detail.scope)
        if key in seen_test_specs:
            continue
        seen_test_specs.add(key)
        tests.append(
            _plan_item(
                kind="test",
                description=assumption_test_description(detail, label),
                evidence_ids=finding.evidence_ids,
                finding_ids=(finding.id,),
                target_paths=(resolved.path or "",),
            )
        )
    if not tests:
        tests.append(
            _plan_item(
                kind="test",
                description=(
                    f"Add characterization coverage for {label} before modifying the target; "
                    "no supported assumption-specific input was found."
                ),
                status=PlanItemStatus.BLOCKED,
                target_paths=(resolved.path or "",),
            )
        )

    direct_tests = sorted({impact.path for impact in blast.impacts if impact.impact_type == "test"})
    candidate_tests = (
        blast.blast_analysis.candidate_tests if blast.blast_analysis is not None else ()
    )
    for path in direct_tests:
        evidence_ids = tuple(
            evidence_id
            for impact in blast.impacts
            if impact.impact_type == "test" and impact.path == path
            for evidence_id in impact.evidence_ids
        )
        verification.append(
            _plan_item(
                kind="verification",
                description=f"Run the proven direct test at `{path}` with Python pytest.",
                evidence_ids=evidence_ids,
                target_paths=(path,),
                command_args=("python", "-m", "pytest", path),
            )
        )
    if not direct_tests:
        tests.append(
            _plan_item(
                kind="test",
                description=(
                    "No direct test was found; add characterization coverage before modifying "
                    "the target."
                ),
                status=PlanItemStatus.BLOCKED,
                target_paths=(resolved.path or "",),
            )
        )
    for path in candidate_tests:
        unknowns.append(
            _plan_item(
                kind="unknown",
                description=(
                    f"Review candidate test `{path}` manually; naming or text evidence does "
                    "not prove direct coverage."
                ),
                status=PlanItemStatus.NOT_EVALUATED,
                target_paths=(path,),
            )
        )

    code_paths = sorted(
        {
            resolved.path or "",
            *(
                impact.path
                for impact in blast.impacts
                if impact.impact_type in {"definition", "importer", "reference"}
                and not impact.path.startswith(("test/", "tests/"))
            ),
        }
        - {""}
    )
    if limitations:
        steps.append(
            _plan_item(
                kind="step",
                description="Confirm the direct-impact scope after resolving blocked unknowns.",
                status=PlanItemStatus.BLOCKED,
                target_paths=code_paths,
            )
        )
    steps.extend(
        [
            _plan_item(
                kind="step",
                description="Resolve blocked or unknown preconditions.",
                status=(PlanItemStatus.BLOCKED if preconditions else PlanItemStatus.PROPOSED),
                target_paths=(resolved.path or "",),
            ),
            _plan_item(
                kind="step",
                description="Add or confirm the proposed characterization tests.",
                target_paths=(resolved.path or "",),
            ),
            _plan_item(
                kind="step",
                description=(
                    "Modify only the resolved target and proven direct dependents when required; "
                    "do not include unrelated refactoring."
                ),
                target_paths=code_paths,
            ),
            _plan_item(
                kind="step",
                description="Run the proposed direct-test verification commands.",
                target_paths=direct_tests,
            ),
            _plan_item(
                kind="step",
                description="Run the repository's broader test suite.",
            ),
            _plan_item(
                kind="step",
                description="Re-run landmine blast for the resulting diff.",
                command_args=(
                    "landmine",
                    "blast",
                    "review resulting diff",
                    "--target",
                    (f"symbol:{resolved.symbol}" if resolved.symbol else resolved.path or ""),
                ),
                target_paths=(resolved.path or "",),
            ),
        ]
    )
    public_export = "public_export" in blast.risk.components["coupling"].signals
    if public_export:
        steps.insert(
            3,
            _plan_item(
                kind="step",
                description=(
                    "Review compatibility for the proven public export before modification."
                ),
                target_paths=(resolved.path or "",),
            ),
        )

    if _has_pytest_configuration(root, tracked):
        verification.append(
            _plan_item(
                kind="verification",
                description="Run the repository pytest suite configured by pyproject.toml.",
                target_paths=(),
                command_args=("python", "-m", "pytest"),
            )
        )
    else:
        verification.append(
            _plan_item(
                kind="verification",
                description="Run the repository's documented full test command.",
            )
        )
    verification.append(
        _plan_item(
            kind="verification",
            description="Re-run direct blast analysis after the implementation is reviewed.",
            command_args=(
                "landmine",
                "blast",
                "review resulting diff",
                "--target",
                f"symbol:{resolved.symbol}" if resolved.symbol else resolved.path or "",
            ),
            target_paths=(resolved.path or "",),
        )
    )

    if direct_tests:
        rollback.append(
            _plan_item(
                kind="rollback_trigger",
                description=(
                    "If a direct test fails, stop the change and restore the last known-good "
                    "revision using the repository's normal review process."
                ),
                target_paths=direct_tests,
            )
        )
    if any(
        finding.assumption is not None
        and finding.assumption.protection is ProtectionStatus.PROTECTED
        for finding in assumptions.findings
    ):
        rollback.append(
            _plan_item(
                kind="rollback_trigger",
                description=(
                    "If previously characterized assumption behavior changes unexpectedly, "
                    "stop and restore the last known-good revision through normal review."
                ),
            )
        )
    if historical:
        rollback.append(
            _plan_item(
                kind="rollback_trigger",
                description=(
                    "If a historical regression test fails, stop the change and restore the "
                    "last known-good revision using the repository's normal review process."
                ),
                evidence_ids=tuple(
                    evidence_id for finding in historical for evidence_id in finding.evidence_ids
                ),
                finding_ids=tuple(finding.id for finding in historical),
            )
        )
    rollback.extend(
        [
            _plan_item(
                kind="rollback_trigger",
                description=(
                    "If the direct impact set expands beyond analyzed paths, stop and repeat "
                    "impact analysis before continuing."
                ),
                target_paths=code_paths,
            ),
            _plan_item(
                kind="rollback_trigger",
                description=(
                    "If analysis becomes partial because of a new dynamic or unknown dependency, "
                    "stop and resolve the unknown surface."
                ),
            ),
            _plan_item(
                kind="rollback_trigger",
                description=(
                    "If repository state changes during implementation, stop and re-establish "
                    "the reviewed repository snapshot."
                ),
            ),
        ]
    )
    if public_export:
        rollback.append(
            _plan_item(
                kind="rollback_trigger",
                description=(
                    "If the public API or export changes unexpectedly, stop and perform a "
                    "compatibility review."
                ),
            )
        )
    for limitation in sorted(limitations, key=lambda item: (item.code, item.affected)):
        unknowns.append(
            _plan_item(
                kind="unknown",
                description=f"{limitation.code}: {limitation.message}",
                status=PlanItemStatus.NOT_EVALUATED,
                target_paths=limitation.affected,
            )
        )

    return Plan(
        preconditions=tuple(preconditions),
        tests=tuple(tests),
        steps=tuple(steps),
        verification=tuple(verification),
        rollback_triggers=tuple(rollback),
        unknowns=tuple(unknowns),
    )

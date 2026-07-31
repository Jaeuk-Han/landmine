"""Git-backed historical evidence analysis for path targets."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from landmine.domain import (
    AnalysisStatus,
    ClaimStatus,
    ErrorDetail,
    Finding,
    Impact,
    Limitation,
    Metrics,
    Result,
    Target,
)
from landmine.evidence import make_evidence
from landmine.git import GitRunner, list_tracked_files, preflight
from landmine.scoring import score_why
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


def _blamed_commits(output: str) -> tuple[str, ...]:
    commits: set[str] = set()
    for line in output.splitlines():
        token = line.split(" ", 1)[0].lstrip("^")
        if len(token) == 40 and all(character in "0123456789abcdef" for character in token):
            commits.add(token)
    return tuple(sorted(commits))


def _commit_summary_and_paths(runner: GitRunner, commit: str) -> tuple[str, tuple[str, ...]]:
    output = runner.run(
        ["show", "--format=%H%x00%s", "--name-only", "--find-renames", commit]
    ).stdout
    lines = output.splitlines()
    header = lines[0] if lines else commit
    _, _, summary = header.partition("\x00")
    paths = tuple(sorted({line.strip().replace("\\", "/") for line in lines[1:] if line.strip()}))
    return summary, paths


def analyze_why(
    *,
    repo: Path,
    target: Target,
    timeout: float = 15.0,
    history_depth: int = 50,
    max_files: int = 1000,
    clock: Clock = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> Result:
    """Analyze a target using bounded blame, show, and follow-history evidence."""
    started = monotonic()
    repository, runner = preflight(repo, timeout=timeout)
    root = runner.cwd
    observed_at = _timestamp(clock)
    try:
        if target.symbol is not None and target.path is None:
            target = resolve_symbol_target(
                target,
                root,
                list_tracked_files(runner),
                max_files=max_files,
                deadline=started + timeout,
                monotonic=monotonic,
            )
        resolved = resolve_line_range(resolve_path_target(target, root), root)
    except SymbolResolutionError as exc:
        limitations = [
            Limitation(
                code="unresolved_target",
                message=str(exc),
                affected=(f"symbol:{exc.symbol}",),
            )
        ]
        if repository.shallow:
            limitations.append(
                Limitation(
                    code="shallow_history",
                    message="Repository history is shallow.",
                    affected=(f"symbol:{exc.symbol}",),
                )
            )
        material = f"why\0{repository.head}\0symbol:{exc.symbol}\0{exc.code}\0" + ",".join(
            f"{candidate.match_kind}:{candidate.path}:{candidate.line}"
            for candidate in exc.candidates
        )
        return Result(
            schema_version="landmine.result.v1",
            analysis_id=f"lm_{hashlib.sha256(material.encode()).hexdigest()[:12]}",
            analysis_status=AnalysisStatus.FAILED,
            command="why",
            generated_at=observed_at,
            repository=repository,
            request={
                "target": {
                    "path": None,
                    "start_line": None,
                    "end_line": None,
                    "symbol": exc.symbol,
                },
                "change": None,
                "goal": None,
            },
            summary=str(exc),
            risk=score_why(
                commit_count=0,
                related_test_count=0,
                shallow=repository.shallow,
            ),
            findings=(),
            evidence=(),
            limitations=tuple(limitations),
            metrics=Metrics(
                elapsed_ms=max(0, round((monotonic() - started) * 1000)),
                files_scanned=exc.files_scanned,
                commits_scanned=0,
                evidence_count=0,
            ),
            error=ErrorDetail(
                code=exc.code,
                message=str(exc),
                candidates=exc.candidates,
            ),
        )
    assert resolved.path is not None
    assert resolved.start_line is not None
    assert resolved.end_line is not None

    blame_args = [
        "blame",
        "--line-porcelain",
        "-L",
        f"{resolved.start_line},{resolved.end_line}",
        "--",
        resolved.path,
    ]
    blame = runner.run(blame_args)
    commits = _blamed_commits(blame.stdout)
    evidence_by_id = {}
    blame_evidence = make_evidence(
        kind="git_blame",
        locator={
            "path": resolved.path,
            "start_line": resolved.start_line,
            "end_line": resolved.end_line,
            "commits": list(commits),
        },
        excerpt="\n".join(line[1:] for line in blame.stdout.splitlines() if line.startswith("\t")),
        observed_at=observed_at,
        command="git blame --line-porcelain -L <range> -- <path>",
    )
    evidence_by_id[blame_evidence.id] = blame_evidence

    commit_evidence_ids: list[str] = []
    related_test_ids: list[str] = []
    related_test_paths: set[str] = set()
    for commit in commits:
        summary, paths = _commit_summary_and_paths(runner, commit)
        item = make_evidence(
            kind="git_commit",
            locator={"commit": commit, "paths": list(paths)},
            excerpt=summary,
            observed_at=observed_at,
            command="git show --format=<fields> --name-only --find-renames <commit>",
        )
        evidence_by_id[item.id] = item
        commit_evidence_ids.append(item.id)
        for path in paths:
            lowered = path.lower()
            if (
                lowered.startswith("test")
                or "/test" in lowered
                or lowered.endswith(("_test.py", ".spec.ts", ".test.ts"))
            ):
                test_item = make_evidence(
                    kind="test",
                    locator={"commit": commit, "path": path},
                    excerpt=f"Related test changed in the blamed commit: {path}",
                    observed_at=observed_at,
                    command="git show --name-only <commit>",
                )
                evidence_by_id[test_item.id] = test_item
                related_test_ids.append(test_item.id)
                related_test_paths.add(path)

    log = runner.run(
        [
            "log",
            "--follow",
            f"--max-count={max(1, history_depth)}",
            "--format=%H%x00%s",
            "--name-status",
            "--",
            resolved.path,
        ]
    )
    log_item = make_evidence(
        kind="git_diff",
        locator={"path": resolved.path, "follow_renames": True},
        excerpt=log.stdout,
        observed_at=observed_at,
        command="git log --follow --format=<fields> --name-status -- <path>",
    )
    evidence_by_id[log_item.id] = log_item

    primary_ids = tuple(sorted({blame_evidence.id, *commit_evidence_ids}))
    if commits:
        historical = Finding(
            id="finding_historical_intent",
            type="historical_intent",
            title="Historical introduction evidence",
            claim=(
                "The selected lines are linked by blame to "
                f"{len(commits)} commit(s); commit text is reported only as untrusted evidence."
            ),
            status=ClaimStatus.VERIFIED,
            confidence=0.9,
            impact=Impact.BEHAVIORAL,
            evidence_ids=primary_ids,
            tags=("history",),
        )
    else:
        historical = Finding(
            id="finding_historical_intent",
            type="historical_intent",
            title="Historical intent is unresolved",
            claim="No commit could be recovered for the selected lines.",
            status=ClaimStatus.UNKNOWN,
            confidence=0.2,
            impact=Impact.UNKNOWN,
            evidence_ids=(blame_evidence.id,),
            tags=("history",),
        )
    current = Finding(
        id="finding_current_relevance",
        type="current_relevance",
        title="Selected lines remain present",
        claim=(
            f"The analyzed range {resolved.path}:{resolved.start_line}-"
            f"{resolved.end_line} exists at HEAD."
        ),
        status=ClaimStatus.VERIFIED,
        confidence=0.95,
        impact=Impact.DIRECT,
        evidence_ids=(blame_evidence.id,),
        tags=("current",),
    )
    protection_ids = tuple(sorted({*primary_ids, *related_test_ids}))
    removal = Finding(
        id="finding_removal_risk",
        type="removal_risk",
        title="Change protection evidence",
        claim=(
            f"{len(related_test_paths)} related test file(s) changed with blamed commits."
            if related_test_paths
            else "No related test changed with the blamed commits; absence was not proven."
        ),
        status=ClaimStatus.INFERRED if protection_ids else ClaimStatus.UNKNOWN,
        confidence=0.7 if related_test_paths else 0.45,
        impact=Impact.BEHAVIORAL if related_test_paths else Impact.UNKNOWN,
        evidence_ids=protection_ids or (blame_evidence.id,),
        tags=("tests", "change-risk"),
    )

    limitations = [
        Limitation(
            code="unsupported_language",
            message="No semantic language adapter was used; evidence is Git- and path-based.",
            affected=(resolved.path,),
        )
    ]
    if repository.shallow:
        limitations.append(
            Limitation(
                code="shallow_history",
                message="Repository history is shallow; earlier evidence may be unavailable.",
                affected=(resolved.path,),
            )
        )
    if blame.truncated or log.truncated:
        limitations.append(
            Limitation(
                code="budget_exhausted",
                message="Git output reached the configured size limit.",
                affected=(resolved.path,),
            )
        )
    status = (
        AnalysisStatus.PARTIAL
        if repository.shallow or blame.truncated or log.truncated
        else AnalysisStatus.COMPLETE
    )
    evidence = tuple(
        sorted(
            evidence_by_id.values(),
            key=lambda item: (
                item.kind,
                str(item.locator.get("path", "")),
                int(item.locator.get("start_line", 0)),
                item.id,
            ),
        )
    )
    risk = score_why(
        commit_count=len(commits),
        related_test_count=len(related_test_paths),
        shallow=repository.shallow,
    )
    analysis_material = (
        f"why\0{repository.head}\0{resolved.path}\0{resolved.start_line}\0"
        f"{resolved.end_line}\0{','.join(item.id for item in evidence)}"
    )
    analysis_id = f"lm_{hashlib.sha256(analysis_material.encode()).hexdigest()[:12]}"
    elapsed_ms = max(0, round((monotonic() - started) * 1000))
    return Result(
        schema_version="landmine.result.v1",
        analysis_id=analysis_id,
        analysis_status=status,
        command="why",
        generated_at=observed_at,
        repository=repository,
        request={
            "target": {
                "path": resolved.path,
                "start_line": resolved.start_line,
                "end_line": resolved.end_line,
                "symbol": resolved.symbol,
            },
            "change": None,
            "goal": None,
        },
        summary=(
            f"Recovered {len(commits)} blamed commit(s) and "
            f"{len(related_test_paths)} related test file(s) for {resolved.path}."
        ),
        risk=risk,
        findings=(historical, current, removal),
        evidence=evidence,
        limitations=tuple(limitations),
        metrics=Metrics(
            elapsed_ms=elapsed_ms,
            files_scanned=1 + len(related_test_paths),
            commits_scanned=len(commits),
            evidence_count=len(evidence),
        ),
    )

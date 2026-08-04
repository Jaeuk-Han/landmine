"""Git-backed historical evidence analysis for path targets."""

from __future__ import annotations

import ast
import hashlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from landmine.domain import (
    AnalysisStatus,
    ClaimStatus,
    ErrorDetail,
    EvolutionCommit,
    Finding,
    Impact,
    Limitation,
    Metrics,
    Result,
    Target,
)
from landmine.evidence import make_evidence, safe_excerpt
from landmine.git import (
    GitError,
    GitRunner,
    GitTimeout,
    LineLogRecord,
    RepositorySnapshot,
    line_log,
    list_tracked_files,
    parse_line_log,
    preflight,
)
from landmine.scoring import score_why
from landmine.source import (
    SymbolResolutionError,
    resolve_line_range,
    resolve_path_target,
    resolve_symbol_target,
)

Clock = Callable[[], datetime]
ZERO_OID = "0" * 40


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(clock: Clock) -> str:
    return clock().astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _is_commit_oid(value: str) -> bool:
    return (
        len(value) == 40
        and value != ZERO_OID
        and all(character in "0123456789abcdef" for character in value)
    )


def _blame_commit_sets(output: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    attributed: set[str] = set()
    previous: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            token = fields[0].lstrip("^")
            if fields[1].isdigit() and fields[2].isdigit() and _is_commit_oid(token):
                attributed.add(token)
        if len(fields) >= 2 and fields[0] == "previous" and _is_commit_oid(fields[1]):
            previous.add(fields[1])
    return tuple(sorted(attributed)), tuple(sorted(previous))


def _blamed_commits(output: str) -> tuple[str, ...]:
    attributed, previous = _blame_commit_sets(output)
    return attributed or previous


def _commit_summary_and_paths(runner: GitRunner, commit: str) -> tuple[str, tuple[str, ...]]:
    if not _is_commit_oid(commit):
        raise GitError("Refusing to inspect a non-commit blame placeholder")
    output = runner.run(
        ["show", "--format=%H%x00%s", "--name-only", "--find-renames", commit]
    ).stdout
    lines = output.splitlines()
    header = lines[0] if lines else commit
    _, _, summary = header.partition("\x00")
    paths = tuple(sorted({line.strip().replace("\\", "/") for line in lines[1:] if line.strip()}))
    return summary, paths


def _head_symbol_range(runner: GitRunner, target: Target) -> Target:
    if (
        target.symbol is None
        or target.path is None
        or not target.path.endswith(".py")
        or target.start_line is None
        or target.end_line != target.start_line
    ):
        return target
    source = runner.run(["show", f"HEAD:{target.path}"], check=False)
    if source.returncode != 0 or source.truncated:
        return target
    try:
        tree = ast.parse(source.stdout)
    except SyntaxError:
        return target
    matches = tuple(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
        and node.name == target.symbol
        and node.end_lineno is not None
    )
    selected = next(
        (node for node in matches if node.lineno == target.start_line),
        matches[0] if len(matches) == 1 else None,
    )
    if selected is None:
        return target
    return Target(
        path=target.path,
        start_line=selected.lineno,
        end_line=selected.end_lineno,
        symbol=target.symbol,
    )


def analyze_why(
    *,
    repo: Path,
    target: Target,
    timeout: float = 15.0,
    history_depth: int = 50,
    max_files: int = 1000,
    clock: Clock = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
    snapshot: RepositorySnapshot | None = None,
) -> Result:
    """Analyze a target using bounded blame, show, and follow-history evidence."""
    started = monotonic()
    repository, runner = (
        (snapshot.state, snapshot.runner)
        if snapshot is not None
        else preflight(repo, timeout=timeout)
    )
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
        resolved = _head_symbol_range(runner, resolved)
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
        "HEAD",
        "--",
        resolved.path,
    ]
    blame = runner.run(blame_args)
    attributed_commits, previous_commits = _blame_commit_sets(blame.stdout)
    commits = attributed_commits or previous_commits
    blame_fallback_limitation = (
        Limitation(
            code="provider_failure",
            message=(
                "git blame returned only uncommitted placeholders; valid previous-commit "
                "metadata and line evolution were used as fallback."
            ),
            affected=(resolved.path,),
        )
        if not attributed_commits and previous_commits
        else None
    )
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
        command="git blame --line-porcelain -L <range> HEAD -- <path>",
    )
    evidence_by_id[blame_evidence.id] = blame_evidence

    line_records: tuple[LineLogRecord, ...] = ()
    line_history_limitation: Limitation | None = None
    try:
        line_output = line_log(
            runner,
            path=resolved.path,
            start_line=resolved.start_line,
            end_line=resolved.end_line,
            max_commits=history_depth,
        )
        if line_output.returncode != 0:
            line_history_limitation = Limitation(
                code="provider_failure",
                message="git log -L failed; git log --follow evidence was used as fallback.",
                affected=(resolved.path,),
            )
        elif line_output.truncated:
            line_history_limitation = Limitation(
                code="budget_exhausted",
                message="git log -L reached the configured output-size limit.",
                affected=(resolved.path,),
            )
        else:
            line_records = parse_line_log(line_output.stdout)
            if not line_records:
                line_history_limitation = Limitation(
                    code="provider_failure",
                    message=(
                        "git log -L returned no parseable evolution; "
                        "git log --follow evidence was used as fallback."
                    ),
                    affected=(resolved.path,),
                )
            elif not set(attributed_commits).issubset({record.commit for record in line_records}):
                line_records = ()
                line_history_limitation = Limitation(
                    code="provider_failure",
                    message=(
                        "git log -L did not cover the blamed commit, possibly due to a rename; "
                        "git log --follow evidence was used as fallback."
                    ),
                    affected=(resolved.path,),
                )
    except GitTimeout:
        line_history_limitation = Limitation(
            code="budget_exhausted",
            message="git log -L timed out; git log --follow evidence was used as fallback.",
            affected=(resolved.path,),
        )

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

    commit_evidence_by_sha: dict[str, str] = {}
    evolution_diff_by_sha: dict[str, str] = {}
    tests_by_commit: dict[str, list[str]] = {}
    related_test_ids: list[str] = []
    related_test_paths: set[str] = set()
    commits_to_inspect = tuple(
        sorted(
            commit
            for commit in {*commits, *(record.commit for record in line_records)}
            if _is_commit_oid(commit)
        )
    )
    for record in line_records:
        diff_item = make_evidence(
            kind="git_diff",
            locator={
                "commit": record.commit,
                "path": resolved.path,
                "start_line": resolved.start_line,
                "end_line": resolved.end_line,
                "timestamp": record.timestamp,
                "line_evolution": True,
            },
            excerpt=record.diff,
            observed_at=observed_at,
            command="git log --format=<fields> --patch -L <range>:<path>",
        )
        evidence_by_id[diff_item.id] = diff_item
        evolution_diff_by_sha[record.commit] = diff_item.id

    for commit in commits_to_inspect:
        summary, paths = _commit_summary_and_paths(runner, commit)
        item = make_evidence(
            kind="git_commit",
            locator={"commit": commit, "paths": list(paths)},
            excerpt=summary,
            observed_at=observed_at,
            command="git show --format=<fields> --name-only --find-renames <commit>",
        )
        evidence_by_id[item.id] = item
        commit_evidence_by_sha[commit] = item.id
        tests_by_commit[commit] = []
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
                tests_by_commit[commit].append(test_item.id)

    primary_commit: str | None = None
    if line_records:
        corroborated = tuple(
            record
            for record in line_records
            if evolution_diff_by_sha.get(record.commit) and tests_by_commit.get(record.commit)
        )
        primary_commit = corroborated[0].commit if corroborated else line_records[0].commit

    evolution: list[EvolutionCommit] = []
    for index, record in enumerate(line_records):
        roles: list[str] = []
        if record.commit == primary_commit:
            roles.append("introduction")
        if index == len(line_records) - 1:
            roles.append("latest")
        if not roles:
            roles.append("intermediate")
        entry_evidence = {
            commit_evidence_by_sha[record.commit],
            evolution_diff_by_sha[record.commit],
            *tests_by_commit.get(record.commit, ()),
        }
        evolution.append(
            EvolutionCommit(
                commit=record.commit,
                timestamp=record.timestamp,
                subject=safe_excerpt(record.subject, max_lines=1, max_chars=500),
                path=resolved.path,
                start_line=resolved.start_line,
                end_line=resolved.end_line,
                roles=tuple(roles),
                evidence_ids=tuple(sorted(entry_evidence)),
            )
        )

    if primary_commit is not None:
        primary_ids = {
            commit_evidence_by_sha[primary_commit],
            evolution_diff_by_sha[primary_commit],
            *tests_by_commit.get(primary_commit, ()),
        }
        corroborated_intent = bool(tests_by_commit.get(primary_commit))
        historical = Finding(
            id="finding_historical_intent",
            type="historical_intent",
            title="Historical introduction evidence",
            claim=(
                f"Commit {primary_commit} is the earliest line-evolution change "
                + (
                    "corroborated by a source diff and regression-test change."
                    if corroborated_intent
                    else "with source-diff evidence; no same-commit regression test was found."
                )
            ),
            status=(ClaimStatus.VERIFIED if corroborated_intent else ClaimStatus.INFERRED),
            confidence=0.9 if corroborated_intent else 0.65,
            impact=Impact.BEHAVIORAL,
            evidence_ids=tuple(sorted(primary_ids)),
            tags=("history",),
        )
    elif commits:
        fallback_ids = {
            blame_evidence.id,
            *(commit_evidence_by_sha[commit] for commit in commits),
        }
        historical = Finding(
            id="finding_historical_intent",
            type="historical_intent",
            title="Historical introduction evidence is inferred",
            claim=(
                "Line evolution was unavailable; blame and follow-history evidence "
                "identify only the current attribution."
            ),
            status=ClaimStatus.INFERRED,
            confidence=0.6,
            impact=Impact.BEHAVIORAL,
            evidence_ids=tuple(sorted(fallback_ids)),
            tags=("history", "fallback"),
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
    latest_ids = {blame_evidence.id}
    if evolution:
        latest_ids.update(evolution[-1].evidence_ids)
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
        evidence_ids=tuple(sorted(latest_ids)),
        tags=("current",),
    )
    protection_ids = tuple(
        sorted(
            {
                blame_evidence.id,
                *commit_evidence_by_sha.values(),
                *related_test_ids,
            }
        )
    )
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
    if line_history_limitation is not None:
        limitations.append(line_history_limitation)
    if blame_fallback_limitation is not None:
        limitations.append(blame_fallback_limitation)
    if repository.dirty:
        limitations.append(
            Limitation(
                code="dirty_worktree_head_history",
                message=(
                    "Historical attribution is based on HEAD; uncommitted worktree content "
                    "was not represented as a historical commit."
                ),
                affected=(resolved.path,),
            )
        )
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
        if (
            repository.shallow
            or repository.dirty
            or blame.truncated
            or log.truncated
            or line_history_limitation is not None
            or blame_fallback_limitation is not None
        )
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
        commit_count=len(commits_to_inspect),
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
            f"Recovered {len(evolution)} line-evolution commit(s) and "
            f"{len(related_test_paths)} related test file(s) for {resolved.path}."
        ),
        risk=risk,
        findings=(historical, current, removal),
        evidence=evidence,
        limitations=tuple(limitations),
        metrics=Metrics(
            elapsed_ms=elapsed_ms,
            files_scanned=1 + len(related_test_paths),
            commits_scanned=len(commits_to_inspect),
            evidence_count=len(evidence),
        ),
        evolution=tuple(evolution),
    )

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

import landmine.analyzers.defuse as defuse_module
from landmine.analyzers.assumptions import analyze_assumptions
from landmine.analyzers.blast import analyze_blast
from landmine.analyzers.defuse import (
    analyze_defuse,
    assumption_test_description,
)
from landmine.analyzers.why import analyze_why
from landmine.cli import main
from landmine.domain import (
    AnalysisStatus,
    AssumptionCategory,
    AssumptionDetail,
    ProtectionStatus,
    Target,
)
from landmine.renderers import render_json, render_markdown, result_dict
from tests.conftest import GitFixture, defuse_plan, repository_digest


def fixed_clock() -> datetime:
    return datetime(2024, 1, 1, tzinfo=UTC)


@pytest.fixture(scope="module")
def defuse_repository(tmp_path_factory: pytest.TempPathFactory) -> GitFixture:
    fixture = GitFixture(tmp_path_factory.mktemp("defuse-repository") / "repository")
    fixture.initialize()
    return defuse_plan.__wrapped__(fixture)


@pytest.fixture(scope="module")
def defuse_result(defuse_repository: GitFixture):
    return analyze_defuse(
        repo=defuse_repository.root,
        target=Target(symbol="select_route"),
        goal="support empty upstream results",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )


def _items(result) -> tuple:
    return (
        *result.plan.preconditions,
        *result.plan.tests,
        *result.plan.steps,
        *result.plan.verification,
        *result.plan.rollback_triggers,
        *result.plan.unknowns,
    )


def test_assumptions_method_coverage_does_not_make_defuse_incomplete(
    defuse_result,
) -> None:
    assert all(item.code != "bounded_method" for item in defuse_result.limitations)
    assert defuse_result.defuse_analysis is not None
    assumptions = next(
        item
        for item in defuse_result.defuse_analysis.prerequisites
        if item.command == "assumptions"
    )
    assert assumptions.status is AnalysisStatus.COMPLETE


def _detail(
    detector_id: str,
    *,
    category: AssumptionCategory,
    key: str | None = None,
    protection: ProtectionStatus = ProtectionStatus.UNPROTECTED,
) -> AssumptionDetail:
    return AssumptionDetail(
        detector_id=detector_id,
        category=category,
        observed_signal="signal",
        violation_scenario="violation",
        consequence="consequence",
        confidence_ceiling=0.79,
        protection=protection,
        required_key=key,
    )


def test_defuse_requires_target(
    defuse_repository: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "defuse",
                "--goal",
                "change behavior",
                "--repo",
                str(defuse_repository.root),
                "--format",
                "json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "target_required"


def test_defuse_requires_goal(
    defuse_repository: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "defuse",
                "symbol:select_route",
                "--repo",
                str(defuse_repository.root),
                "--format",
                "json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "goal_required"


def test_defuse_reuses_ambiguous_symbol_error(
    git_fixture: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    git_fixture.commit(
        "duplicate",
        "duplicate",
        {"src/a.py": "class Duplicate:\n    pass\n", "src/b.py": "class Duplicate:\n    pass\n"},
    )
    assert (
        main(
            [
                "defuse",
                "symbol:Duplicate",
                "--goal",
                "change duplicate",
                "--repo",
                str(git_fixture.root),
                "--format",
                "json",
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["code"] == "ambiguous_symbol"
    assert len(payload["error"]["candidates"]) == 2


def test_defuse_rejects_from_result(
    defuse_repository: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "defuse",
                "symbol:select_route",
                "--goal",
                "change route",
                "--from-result",
                "prior.json",
                "--repo",
                str(defuse_repository.root),
                "--format",
                "json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "unsupported_from_result"


def test_defuse_runs_why_assumptions_and_blast(defuse_result) -> None:
    assert defuse_result.defuse_analysis is not None
    assert [item.command for item in defuse_result.defuse_analysis.prerequisites] == [
        "why",
        "assumptions",
        "blast",
    ]


def test_defuse_uses_single_repository_snapshot(
    defuse_repository: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0
    original = defuse_module.preflight

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(defuse_module, "preflight", counted)
    result = analyze_defuse(
        repo=defuse_repository.root,
        target=Target(symbol="select_route"),
        goal="change route",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert calls == 1
    assert result.defuse_analysis is not None
    assert result.defuse_analysis.repository_state_stable


def test_defuse_aggregates_partial_status(defuse_result) -> None:
    assert defuse_result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "dynamic_import" for item in defuse_result.limitations)


def test_defuse_unsupported_language_is_partial(git_fixture: GitFixture) -> None:
    git_fixture.commit("typescript", "typescript", {"src/value.ts": "export const value = 1;\n"})
    result = analyze_defuse(
        repo=git_fixture.root,
        target=Target(path="src/value.ts"),
        goal="change value",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "unsupported_language" for item in result.limitations)


def test_repository_state_change_prevents_complete(
    defuse_plan: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = defuse_module.analyze_why

    def changing(**kwargs):
        result = original(**kwargs)
        (defuse_plan.root / "state-changed.txt").write_text("changed\n", encoding="utf-8")
        return result

    monkeypatch.setattr(defuse_module, "analyze_why", changing)
    result = analyze_defuse(
        repo=defuse_plan.root,
        target=Target(symbol="select_route"),
        goal="change route",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "repository_state_changed" for item in result.limitations)
    assert result.defuse_analysis is not None
    assert not result.defuse_analysis.repository_state_stable


def test_defuse_fails_without_usable_evidence(
    git_fixture: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    git_fixture.commit("empty", "empty", {"src/empty.py": "\n"})
    repository, _ = defuse_module.preflight(git_fixture.root)
    empty = defuse_module._error_result(
        repository=repository,
        observed_at="2024-01-01T00:00:00Z",
        started=100.0,
        monotonic=lambda: 100.0,
        target=Target(path="src/empty.py"),
        goal="change empty",
        code="symbol_not_found",
        message="no evidence",
    )
    monkeypatch.setattr(defuse_module, "analyze_why", lambda **kwargs: empty)
    monkeypatch.setattr(defuse_module, "analyze_assumptions", lambda **kwargs: empty)
    monkeypatch.setattr(defuse_module, "analyze_blast", lambda **kwargs: empty)
    result = analyze_defuse(
        repo=git_fixture.root,
        target=Target(path="src/empty.py"),
        goal="change empty",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert result.analysis_status is AnalysisStatus.FAILED


def test_defuse_deduplicates_evidence(defuse_result) -> None:
    ids = [item.id for item in defuse_result.evidence]
    assert len(ids) == len(set(ids))


def test_defuse_deduplicates_findings(defuse_result) -> None:
    ids = [item.id for item in defuse_result.findings]
    assert len(ids) == len(set(ids))


def test_historical_constraint_becomes_precondition(defuse_result) -> None:
    assert any(
        "historical constraint" in item.description
        and item.evidence_ids
        and item.related_finding_ids
        for item in defuse_result.plan.preconditions
    )


def test_dirty_worktree_becomes_precondition(defuse_plan: GitFixture) -> None:
    path = defuse_plan.root / "src/landmine_fixture/routing.py"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    result = analyze_defuse(
        repo=defuse_plan.root,
        target=Target(symbol="select_route"),
        goal="change route",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert any("uncommitted changes" in item.description for item in result.plan.preconditions)


def test_partial_analysis_creates_blocked_precondition(defuse_result) -> None:
    assert any(
        item.status.value == "blocked" and "unknown impact surface" in item.description
        for item in defuse_result.plan.preconditions
    )


def test_collection_assumption_creates_test_spec(defuse_result) -> None:
    assert any("empty collection" in item.description for item in defuse_result.plan.tests)


def test_mapping_key_assumption_creates_test_spec(defuse_result) -> None:
    assert any("'status' omitted" in item.description for item in defuse_result.plan.tests)


def test_environment_assumption_creates_test_spec() -> None:
    text = assumption_test_description(
        _detail(
            "python.required-environment-variable",
            category=AssumptionCategory.ENVIRONMENT,
            key="DATABASE_URL",
        ),
        "`load_config`",
    )
    assert "`DATABASE_URL` absent" in text


def test_response_field_assumption_creates_test_spec() -> None:
    text = assumption_test_description(
        _detail(
            "python.required-response-field",
            category=AssumptionCategory.EXTERNAL_CONTRACT,
            key="user_id",
        ),
        "`load_user`",
    )
    assert "'user_id' omitted from the external JSON response" in text


def test_ordering_assumption_creates_test_spec() -> None:
    text = assumption_test_description(
        _detail(
            "python.arbitrary-set-selection",
            category=AssumptionCategory.ORDERING,
        ),
        "`choose`",
    )
    assert "multi-element set" in text


def test_filesystem_assumption_creates_test_spec() -> None:
    text = assumption_test_description(
        _detail(
            "python.cwd-relative-file-access",
            category=AssumptionCategory.FILESYSTEM,
        ),
        "`load`",
    )
    assert "different working directory" in text


def test_time_assumption_creates_test_spec() -> None:
    text = assumption_test_description(
        _detail(
            "python.wall-clock-elapsed-time",
            category=AssumptionCategory.TIME,
        ),
        "`elapsed`",
    )
    assert "backward and forward wall-clock adjustments" in text


def test_protected_finding_remains_in_test_plan() -> None:
    text = assumption_test_description(
        _detail(
            "python.required-mapping-key",
            category=AssumptionCategory.DATA,
            key="id",
            protection=ProtectionStatus.PROTECTED,
        ),
        "`parse`",
    )
    assert "Existing characterization evidence found" in text


def test_direct_test_creates_proposed_pytest_command(defuse_result) -> None:
    assert any(
        item.command_args == ("python", "-m", "pytest", "tests/test_routing.py")
        for item in defuse_result.plan.verification
    )


def test_candidate_test_does_not_create_command(defuse_result) -> None:
    assert not any(
        "tests/test_candidate.py" in item.command_args for item in defuse_result.plan.verification
    )
    assert any(
        "tests/test_candidate.py" in item.description for item in defuse_result.plan.unknowns
    )


def test_goal_text_is_never_inserted_into_command(defuse_repository: GitFixture) -> None:
    goal = '"; python -c "raise SystemExit"; #'
    result = analyze_defuse(
        repo=defuse_repository.root,
        target=Target(symbol="select_route"),
        goal=goal,
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert all(goal not in argument for item in _items(result) for argument in item.command_args)


def test_steps_are_deterministically_ordered(defuse_result) -> None:
    first = [item.id for item in defuse_result.plan.steps]
    second = [item.id for item in defuse_result.plan.steps]
    assert first == second
    assert "scope" in defuse_result.plan.steps[0].description


def test_steps_use_only_proven_impact_paths(defuse_result) -> None:
    modification = next(
        item for item in defuse_result.plan.steps if item.description.startswith("Modify only")
    )
    assert set(modification.target_paths) == {
        "src/landmine_fixture/app.py",
        "src/landmine_fixture/routing.py",
    }


def test_public_export_adds_compatibility_review(defuse_plan: GitFixture) -> None:
    (defuse_plan.root / "src/landmine_fixture/__init__.py").write_text(
        "from landmine_fixture.routing import select_route\n", encoding="utf-8"
    )
    result = analyze_defuse(
        repo=defuse_plan.root,
        target=Target(symbol="select_route"),
        goal="change export",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert any("compatibility" in item.description for item in result.plan.steps)


def test_partial_blast_blocks_scope_confirmation(defuse_result) -> None:
    assert defuse_result.plan.steps[0].status.value == "blocked"
    assert "scope" in defuse_result.plan.steps[0].description


def test_direct_test_failure_is_rollback_trigger(defuse_result) -> None:
    assert any(
        "direct test fails" in item.description for item in defuse_result.plan.rollback_triggers
    )


def test_historical_regression_is_rollback_trigger(defuse_result) -> None:
    assert any(
        "historical regression test fails" in item.description
        for item in defuse_result.plan.rollback_triggers
    )


def test_unknown_expansion_is_rollback_trigger(defuse_result) -> None:
    assert any(
        "impact set expands" in item.description for item in defuse_result.plan.rollback_triggers
    )


def test_no_plan_item_claims_execution(defuse_result) -> None:
    assert {item.status.value for item in _items(defuse_result)} <= {
        "proposed",
        "blocked",
        "not_evaluated",
    }
    assert not any(
        word in item.status.value
        for item in _items(defuse_result)
        for word in ("executed", "passed")
    )


def test_defuse_risk_uses_prerequisite_scores(defuse_result) -> None:
    assert defuse_result.defuse_analysis is not None
    assert defuse_result.risk.score == max(
        item.risk_score for item in defuse_result.defuse_analysis.prerequisites
    )
    assert all(
        component.signals[0].startswith("source:")
        for component in defuse_result.risk.components.values()
    )


def test_defuse_json_matches_v1_schema(defuse_result) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = json.loads(render_json(defuse_result))
    schema = json.loads(
        (Path(__file__).parents[2] / "schemas/result-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_defuse_json_is_deterministic(defuse_result) -> None:
    assert render_json(defuse_result) == render_json(defuse_result)


def test_defuse_markdown_contains_all_sections(defuse_result) -> None:
    output = render_markdown(defuse_result)
    for section in (
        "Summary",
        "Overall risk",
        "Target and goal",
        "Preconditions",
        "Characterization tests",
        "Safe modification steps",
        "Proposed verification",
        "Rollback triggers",
        "Unknowns and limitations",
        "Analysis metadata",
    ):
        assert f"## {section}" in output


def test_defuse_does_not_execute_tests(
    defuse_repository: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    original = subprocess.run

    def recording(command, *args, **kwargs):
        calls.append([str(item) for item in command])
        return original(command, *args, **kwargs)

    monkeypatch.setattr("landmine.git.subprocess.run", recording)
    analyze_defuse(
        repo=defuse_repository.root,
        target=Target(symbol="select_route"),
        goal="change route",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert calls
    assert all("pytest" not in command for command in calls)


def test_defuse_does_not_modify_repository(defuse_repository: GitFixture) -> None:
    before = repository_digest(defuse_repository.root)
    analyze_defuse(
        repo=defuse_repository.root,
        target=Target(symbol="select_route"),
        goal="change route",
        clock=fixed_clock,
        monotonic=lambda: 100.0,
    )
    assert repository_digest(defuse_repository.root) == before


def test_existing_command_outputs_are_unchanged(defuse_repository: GitFixture) -> None:
    target = Target(path="src/landmine_fixture/routing.py", start_line=1, end_line=1)
    results = (
        analyze_why(
            repo=defuse_repository.root,
            target=target,
            clock=fixed_clock,
            monotonic=lambda: 100.0,
        ),
        analyze_assumptions(
            repo=defuse_repository.root,
            target=target,
            clock=fixed_clock,
            monotonic=lambda: 100.0,
        ),
        analyze_blast(
            repo=defuse_repository.root,
            change="change route",
            target=target,
            clock=fixed_clock,
            monotonic=lambda: 100.0,
        ),
    )
    for result in results:
        payload = result_dict(result)
        assert "defuse_analysis" not in payload
        assert "unknowns" not in payload["plan"]

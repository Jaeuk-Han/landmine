from __future__ import annotations

from datetime import UTC, datetime

from landmine.analyzers.why import analyze_why
from landmine.domain import AnalysisStatus, ClaimStatus, Target
from landmine.git import GitOutput, GitRunner, GitTimeout
from landmine.renderers import render_json, render_markdown
from tests.conftest import GitFixture, repository_digest

FIXED_TIME = datetime(2026, 7, 31, 9, 0, tzinfo=UTC)


def analyze(fixture: GitFixture, target: Target | None = None):
    return analyze_why(
        repo=fixture.root,
        target=target or Target(path="src/routing.py", start_line=5, end_line=6),
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def test_why_tracks_line_modified_by_later_commit(
    line_modified_after_guard: GitFixture,
) -> None:
    result = analyze(line_modified_after_guard)
    assert [item.commit for item in result.evolution] == [
        line_modified_after_guard.commits["introduce_guard"],
        line_modified_after_guard.commits["refactor_guard"],
    ]
    assert result.evolution[0].roles == ("introduction",)
    assert result.evolution[-1].roles == ("latest",)


def test_why_preserves_original_guard_intent(
    line_modified_after_guard: GitFixture,
) -> None:
    result = analyze(line_modified_after_guard)
    historical = next(item for item in result.findings if item.type == "historical_intent")
    assert historical.status is ClaimStatus.VERIFIED
    guard_commit = line_modified_after_guard.commits["introduce_guard"]
    guard_evidence = {
        evidence.id
        for evidence in result.evidence
        if evidence.locator.get("commit") == guard_commit
    }
    assert guard_evidence
    assert set(historical.evidence_ids).issubset(guard_evidence)


def test_why_links_regression_test_to_guard_commit(
    line_modified_after_guard: GitFixture,
) -> None:
    result = analyze(line_modified_after_guard)
    guard = result.evolution[0]
    tests = {
        item.id
        for item in result.evidence
        if item.kind == "test"
        and item.locator.get("commit") == line_modified_after_guard.commits["introduce_guard"]
        and item.locator.get("path") == "tests/test_routing.py"
    }
    assert tests
    assert tests.issubset(set(guard.evidence_ids))


def test_line_evolution_orders_commits_oldest_to_newest(
    line_modified_after_guard: GitFixture,
) -> None:
    result = analyze(line_modified_after_guard)
    assert [item.timestamp for item in result.evolution] == sorted(
        item.timestamp for item in result.evolution
    )


def test_formatting_commit_is_not_primary_intent(
    line_modified_after_guard: GitFixture,
) -> None:
    result = analyze(line_modified_after_guard)
    formatting = line_modified_after_guard.commits["format_unrelated"]
    historical = next(item for item in result.findings if item.type == "historical_intent")
    primary_commits = {
        item.locator.get("commit") for item in result.evidence if item.id in historical.evidence_ids
    }
    assert formatting not in primary_commits
    assert formatting not in {item.commit for item in result.evolution}


def test_log_l_failure_falls_back_to_follow_history(
    line_modified_after_guard: GitFixture, monkeypatch
) -> None:
    original = GitRunner.run

    def fail_log_l(self, arguments, *, check=True):
        if arguments[:1] == ["log"] and "-L" in arguments:
            return GitOutput("", "forced log -L failure", 128)
        return original(self, arguments, check=check)

    monkeypatch.setattr(GitRunner, "run", fail_log_l)
    result = analyze(line_modified_after_guard)
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "provider_failure" for item in result.limitations)
    assert any(
        item.kind == "git_diff" and item.locator.get("follow_renames") is True
        for item in result.evidence
    )
    historical = next(item for item in result.findings if item.type == "historical_intent")
    assert historical.status is ClaimStatus.INFERRED


def test_log_l_timeout_returns_partial_result(
    line_modified_after_guard: GitFixture, monkeypatch
) -> None:
    original = GitRunner.run

    def timeout_log_l(self, arguments, *, check=True):
        if arguments[:1] == ["log"] and "-L" in arguments:
            raise GitTimeout("forced log -L timeout")
        return original(self, arguments, check=check)

    monkeypatch.setattr(GitRunner, "run", timeout_log_l)
    result = analyze(line_modified_after_guard)
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "budget_exhausted" for item in result.limitations)
    assert result.evolution == ()


def test_symbol_target_uses_resolved_line_history(
    line_modified_after_guard: GitFixture,
) -> None:
    result = analyze(
        line_modified_after_guard,
        Target(symbol="HospitalFallback"),
    )
    assert result.request["target"]["path"] == "src/routing.py"
    assert result.request["target"]["start_line"] == 1
    assert [item.commit for item in result.evolution] == [
        line_modified_after_guard.commits["introduce_guard"],
        line_modified_after_guard.commits["refactor_guard"],
    ]


def test_line_evolution_json_is_deterministic(
    line_modified_after_guard: GitFixture,
) -> None:
    assert render_json(analyze(line_modified_after_guard)) == render_json(
        analyze(line_modified_after_guard)
    )


def test_line_evolution_does_not_mutate_repository(
    line_modified_after_guard: GitFixture,
) -> None:
    before = repository_digest(line_modified_after_guard.root)
    result = analyze(line_modified_after_guard)
    after = repository_digest(line_modified_after_guard.root)
    assert result.evolution
    assert after == before


def test_markdown_includes_concise_evolution_timeline(
    line_modified_after_guard: GitFixture,
) -> None:
    markdown = render_markdown(analyze(line_modified_after_guard))
    assert "## Evolution timeline" in markdown
    assert markdown.index("introduction") < markdown.index("latest")
    markdown.encode("cp949")

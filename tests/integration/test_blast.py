from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from landmine.analyzers.assumptions import analyze_assumptions
from landmine.analyzers.blast import analyze_blast
from landmine.analyzers.why import analyze_why
from landmine.cli import main
from landmine.domain import AnalysisStatus, Target
from landmine.renderers import render_json, result_dict
from tests.conftest import GitFixture, repository_digest


def _symbol_result(fixture: GitFixture, **kwargs: object):
    return analyze_blast(
        repo=fixture.root,
        change="change HospitalFallback behavior",
        target=Target(symbol="HospitalFallback"),
        clock=lambda: datetime(2024, 1, 1, tzinfo=UTC),
        monotonic=lambda: 100.0,
        **kwargs,
    )


def _impact_paths(result) -> set[str]:
    return {impact.path for impact in result.impacts}


def test_blast_requires_explicit_target(
    direct_blast: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(["blast", "describe only", "--repo", str(direct_blast.root), "--format", "json"]) == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["analysis_status"] == "failed"
    assert payload["error"]["code"] == "target_required"


def test_blast_accepts_symbol_target(direct_blast: GitFixture) -> None:
    result = _symbol_result(direct_blast)
    assert result.blast_analysis is not None
    assert result.blast_analysis.subject.symbol == "HospitalFallback"


def test_blast_accepts_file_target(direct_blast: GitFixture) -> None:
    result = analyze_blast(
        repo=direct_blast.root,
        change="rename module",
        target=Target(path="src/landmine_fixture/fallback.py"),
        monotonic=lambda: 100.0,
    )
    assert result.blast_analysis is not None
    assert result.blast_analysis.subject.symbol is None
    assert "src/landmine_fixture/router.py" in _impact_paths(result)


def test_blast_accepts_line_range_target(direct_blast: GitFixture) -> None:
    result = analyze_blast(
        repo=direct_blast.root,
        change="change route",
        target=Target(path="src/landmine_fixture/fallback.py", start_line=4, end_line=4),
        monotonic=lambda: 100.0,
    )
    assert result.blast_analysis is not None
    assert result.blast_analysis.subject.symbol == "HospitalFallback"


def test_blast_reuses_ambiguous_symbol_error(
    git_fixture: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    git_fixture.commit(
        "ambiguous",
        "ambiguous",
        {"src/a.py": "class Duplicate:\n    pass\n", "src/b.py": "class Duplicate:\n    pass\n"},
    )
    assert (
        main(
            [
                "blast",
                "change duplicate",
                "--target",
                "symbol:Duplicate",
                "--repo",
                str(git_fixture.root),
                "--format",
                "json",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "ambiguous_symbol"


def test_blast_resolves_containing_symbol(direct_blast: GitFixture) -> None:
    result = analyze_blast(
        repo=direct_blast.root,
        change="change route",
        target=Target(path="src/landmine_fixture/fallback.py", start_line=5, end_line=5),
        monotonic=lambda: 100.0,
    )
    assert result.blast_analysis is not None
    assert result.blast_analysis.subject.symbol == "route"


def test_line_without_symbol_falls_back_to_file(direct_blast: GitFixture) -> None:
    result = analyze_blast(
        repo=direct_blast.root,
        change="change reason",
        target=Target(path="src/landmine_fixture/fallback.py", start_line=1, end_line=1),
        monotonic=lambda: 100.0,
    )
    assert result.blast_analysis is not None
    assert result.blast_analysis.subject.symbol is None
    assert any(item.code == "file_level_fallback" for item in result.limitations)


def test_finds_direct_from_import_reference(direct_blast: GitFixture) -> None:
    result = _symbol_result(direct_blast)
    assert any(
        impact.path == "src/landmine_fixture/router.py" and impact.impact_type == "reference"
        for impact in result.impacts
    )


def test_finds_aliased_symbol_reference(direct_blast: GitFixture) -> None:
    result = _symbol_result(direct_blast)
    router = [item for item in result.impacts if item.path.endswith("router.py")]
    assert any(item.symbol == "Fallback" for item in router)


def test_finds_qualified_module_reference(direct_blast: GitFixture) -> None:
    result = _symbol_result(direct_blast)
    assert any(
        item.path.endswith("api.py") and item.impact_type == "reference" for item in result.impacts
    )


def test_finds_direct_module_importer(direct_blast: GitFixture) -> None:
    result = analyze_blast(
        repo=direct_blast.root,
        change="rename module",
        target=Target(path="src/landmine_fixture/fallback.py"),
        monotonic=lambda: 100.0,
    )
    assert any(item.impact_type == "importer" for item in result.impacts)


@pytest.mark.parametrize(
    "excluded",
    [
        "src/landmine_fixture/unrelated.py",
        "src/landmine_fixture/dynamic.py",
        "src/landmine_fixture/second_hop.py",
    ],
)
def test_non_direct_paths_are_excluded(direct_blast: GitFixture, excluded: str) -> None:
    assert excluded not in _impact_paths(_symbol_result(direct_blast))


def test_does_not_match_shadowed_local_name(direct_blast: GitFixture) -> None:
    assert "src/landmine_fixture/unrelated.py" not in _impact_paths(_symbol_result(direct_blast))


def test_does_not_promote_getattr_reference(direct_blast: GitFixture) -> None:
    assert "src/landmine_fixture/dynamic.py" not in _impact_paths(_symbol_result(direct_blast))


def test_wildcard_import_returns_limitation(direct_blast: GitFixture) -> None:
    assert any(item.code == "wildcard_import" for item in _symbol_result(direct_blast).limitations)


def test_dynamic_import_returns_limitation(direct_blast: GitFixture) -> None:
    assert any(item.code == "dynamic_import" for item in _symbol_result(direct_blast).limitations)


def test_finds_direct_test_reference(direct_blast: GitFixture) -> None:
    assert any(
        item.path == "tests/test_router.py" and item.impact_type == "test"
        for item in _symbol_result(direct_blast).impacts
    )


def test_candidate_test_is_not_direct_impact(direct_blast: GitFixture) -> None:
    result = _symbol_result(direct_blast)
    assert "tests/test_candidate.py" not in _impact_paths(result)
    assert result.blast_analysis is not None
    assert "tests/test_candidate.py" in result.blast_analysis.candidate_tests


def test_second_hop_is_not_included(direct_blast: GitFixture) -> None:
    assert "src/landmine_fixture/second_hop.py" not in _impact_paths(_symbol_result(direct_blast))


def test_each_impact_has_evidence(direct_blast: GitFixture) -> None:
    result = _symbol_result(direct_blast)
    evidence_ids = {item.id for item in result.evidence}
    assert all(
        impact.evidence_ids and set(impact.evidence_ids) <= evidence_ids
        for impact in result.impacts
    )


def test_each_impact_has_path_from_target(direct_blast: GitFixture) -> None:
    assert all(len(item.path_from_target) >= 2 for item in _symbol_result(direct_blast).impacts)


def test_coupling_score_is_deterministic(direct_blast: GitFixture) -> None:
    first = _symbol_result(direct_blast).risk.components["coupling"]
    second = _symbol_result(direct_blast).risk.components["coupling"]
    assert first == second
    assert first.value > 0


def test_direct_test_reduces_test_gap_component(direct_blast: GitFixture) -> None:
    assert _symbol_result(direct_blast).risk.components["test_gap"].value == 10


def test_missing_tests_increases_test_gap_component(git_fixture: GitFixture) -> None:
    git_fixture.commit(
        "leaf",
        "leaf",
        {
            "src/pkg/__init__.py": "",
            "src/pkg/leaf.py": "class Leaf:\n    pass\n",
            "src/pkg/use.py": "from pkg.leaf import Leaf\nvalue = Leaf()\n",
        },
    )
    result = analyze_blast(
        repo=git_fixture.root,
        change="change leaf",
        target=Target(symbol="Leaf"),
        monotonic=lambda: 100.0,
    )
    assert result.risk.components["test_gap"].value == 80


def test_unanalyzed_components_are_not_presented_as_safe(direct_blast: GitFixture) -> None:
    result = _symbol_result(direct_blast)
    for name in ("history", "contract_surface", "operational"):
        assert "not_evaluated" in result.risk.components[name].signals
    assert result.blast_analysis is not None
    assert "git_cochange" in result.blast_analysis.not_evaluated


def test_unsupported_language_returns_partial(git_fixture: GitFixture) -> None:
    git_fixture.commit("ts", "ts", {"src/value.ts": "export const value = 1;\n"})
    result = analyze_blast(
        repo=git_fixture.root,
        change="change value",
        target=Target(path="src/value.ts"),
        monotonic=lambda: 100.0,
    )
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "unsupported_language" for item in result.limitations)


def test_blast_json_matches_v1_schema(direct_blast: GitFixture) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    payload = json.loads(render_json(_symbol_result(direct_blast)))
    schema = json.loads(
        (Path(__file__).parents[2] / "schemas/result-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_blast_json_is_deterministic(direct_blast: GitFixture) -> None:
    assert render_json(_symbol_result(direct_blast)) == render_json(_symbol_result(direct_blast))


def test_blast_markdown_lists_direct_impacts(
    direct_blast: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "blast",
                "change HospitalFallback behavior",
                "--target",
                "symbol:HospitalFallback",
                "--repo",
                str(direct_blast.root),
            ]
        )
        == 1
    )
    output = capsys.readouterr().out
    assert "## Direct impacts" in output
    assert "src/landmine_fixture/router.py" in output


def test_change_description_is_treated_as_data(direct_blast: GitFixture, tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    result = analyze_blast(
        repo=direct_blast.root,
        change=f'"; New-Item {marker}; #',
        target=Target(symbol="HospitalFallback"),
        monotonic=lambda: 100.0,
    )
    assert result.request["change"].endswith("; #")
    assert not marker.exists()


def test_blast_respects_max_files(direct_blast: GitFixture) -> None:
    result = analyze_blast(
        repo=direct_blast.root,
        change="change fallback",
        target=Target(path="src/landmine_fixture/fallback.py"),
        max_files=1,
        monotonic=lambda: 100.0,
    )
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "budget_exhausted" for item in result.limitations)


def test_blast_timeout_returns_partial(direct_blast: GitFixture) -> None:
    ticks = iter([0.0, 2.0, 2.0, 2.0])
    result = analyze_blast(
        repo=direct_blast.root,
        change="change HospitalFallback",
        target=Target(path="src/landmine_fixture/fallback.py"),
        timeout=1.0,
        monotonic=lambda: next(ticks, 2.0),
    )
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "budget_exhausted" for item in result.limitations)


def test_blast_does_not_mutate_repository(direct_blast: GitFixture) -> None:
    before = repository_digest(direct_blast.root)
    result = _symbol_result(direct_blast)
    assert result.impacts
    assert repository_digest(direct_blast.root) == before


def test_existing_why_and_assumptions_outputs_are_unchanged(
    direct_blast: GitFixture,
) -> None:
    why_payload = result_dict(
        analyze_why(
            repo=direct_blast.root,
            target=Target(path="src/landmine_fixture/fallback.py", start_line=4, end_line=4),
            clock=lambda: datetime(2024, 1, 1, tzinfo=UTC),
            monotonic=lambda: 100.0,
        )
    )
    assumptions_payload = result_dict(
        analyze_assumptions(
            repo=direct_blast.root,
            target=Target(path="src/landmine_fixture/fallback.py"),
            clock=lambda: datetime(2024, 1, 1, tzinfo=UTC),
            monotonic=lambda: 100.0,
        )
    )
    for payload in (why_payload, assumptions_payload):
        assert "blast_analysis" not in payload
        assert "impacts" not in payload

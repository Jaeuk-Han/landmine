from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from landmine.analyzers.assumptions import analyze_assumptions
from landmine.cli import main
from landmine.domain import AnalysisStatus, ClaimStatus, ProtectionStatus, Target
from landmine.renderers import render_json, render_markdown, result_dict
from tests.conftest import GitFixture, repository_digest

FIXED_TIME = datetime(2026, 7, 31, 9, 0, tzinfo=UTC)


def analyze(
    fixture: GitFixture,
    target: Target | None = None,
    *,
    min_confidence: float = 0.0,
):
    return analyze_assumptions(
        repo=fixture.root,
        target=target or Target(path="src/processor.py"),
        category="data",
        min_confidence=min_confidence,
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def assumption_findings(result):
    return [finding for finding in result.findings if finding.type == "assumption"]


def test_assumptions_cli_accepts_path(
    hidden_cardinality: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["assumptions", "src/processor.py", "--repo", str(hidden_cardinality.root)]) == 0
    assert "# Landmine: assumptions" in capsys.readouterr().out


def test_assumptions_cli_accepts_line_range(
    hidden_cardinality: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "assumptions",
                "src/processor.py:1-2",
                "--repo",
                str(hidden_cardinality.root),
                "--format",
                "json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert len([item for item in payload["findings"] if item["type"] == "assumption"]) == 1
    assert payload["request"]["target"]["start_line"] == 1
    assert payload["request"]["target"]["end_line"] == 2


def test_assumptions_cli_accepts_symbol(
    hidden_cardinality: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        main(
            [
                "assumptions",
                "symbol:process_unsafe",
                "--repo",
                str(hidden_cardinality.root),
                "--format",
                "json",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["request"]["target"]["symbol"] == "process_unsafe"
    assert len([item for item in payload["findings"] if item["type"] == "assumption"]) == 1


def test_unimplemented_assumption_category_returns_exit_code_2() -> None:
    with pytest.raises(SystemExit) as raised:
        main(["assumptions", "src/example.py", "--category", "ordering"])
    assert raised.value.code == 2


def test_finding_is_inferred_without_runtime_evidence(
    hidden_cardinality: GitFixture,
) -> None:
    findings = assumption_findings(analyze(hidden_cardinality))
    assert findings
    assert all(finding.status is ClaimStatus.INFERRED for finding in findings)
    assert all(finding.assumption is not None for finding in findings)
    assert all(finding.confidence <= finding.assumption.confidence_ceiling for finding in findings)


def test_candidate_test_does_not_imply_protected(hidden_cardinality: GitFixture) -> None:
    finding = next(
        item
        for item in assumption_findings(analyze(hidden_cardinality))
        if item.assumption is not None and item.assumption.scope == "process_unsafe"
    )
    assert finding.assumption is not None
    assert finding.assumption.candidate_tests == ("tests/test_processor.py",)
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN


def test_empty_input_test_can_mark_protected(git_fixture: GitFixture) -> None:
    git_fixture.commit(
        "protected",
        "Add empty-input characterization",
        {
            "src/example.py": "def first(items):\n    return items[0]\n",
            "tests/test_example.py": (
                "import pytest\n"
                "from example import first\n"
                "\n"
                "def test_empty_input_is_rejected():\n"
                "    with pytest.raises(IndexError):\n"
                "        first([])\n"
            ),
        },
    )
    finding = assumption_findings(analyze(git_fixture, Target(path="src/example.py")))[0]
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED


def test_unsupported_language_returns_partial_limitation(git_fixture: GitFixture) -> None:
    git_fixture.commit("typescript", "Add TS", {"src/example.ts": "const first = items[0];\n"})
    result = analyze(git_fixture, Target(path="src/example.ts"))
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "unsupported_language" for item in result.limitations)
    assert not assumption_findings(result)


def test_python_syntax_error_returns_partial_limitation(git_fixture: GitFixture) -> None:
    git_fixture.commit("invalid", "Add invalid Python", {"src/broken.py": "def broken(:\n"})
    result = analyze(git_fixture, Target(path="src/broken.py"))
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "provider_failure" for item in result.limitations)
    assert not assumption_findings(result)


def test_no_finding_output_is_calibrated(git_fixture: GitFixture) -> None:
    git_fixture.commit(
        "safe", "Add safe code", {"src/safe.py": "def size(items):\n    return len(items)\n"}
    )
    result = analyze(git_fixture, Target(path="src/safe.py"))
    assert not assumption_findings(result)
    assert "found no supported" in result.summary.lower()
    assert "no assumptions exist" not in render_markdown(result).lower()
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == ("python.non-empty-collection",)


def test_min_confidence_filters_findings(hidden_cardinality: GitFixture) -> None:
    result = analyze(hidden_cardinality, min_confidence=0.99)
    assert not assumption_findings(result)
    assert "minimum confidence" in result.summary.lower()


def test_assumption_json_is_deterministic(hidden_cardinality: GitFixture) -> None:
    assert render_json(analyze(hidden_cardinality)) == render_json(analyze(hidden_cardinality))


def test_assumption_markdown_references_evidence(hidden_cardinality: GitFixture) -> None:
    result = analyze(hidden_cardinality)
    markdown = render_markdown(result)
    for finding in assumption_findings(result):
        assert finding.evidence_ids
        assert all(evidence_id in markdown for evidence_id in finding.evidence_ids)
    assert "Protection:" in markdown


def test_assumption_json_matches_v1_schema(hidden_cardinality: GitFixture) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        result_dict(analyze(hidden_cardinality))
    )


def test_assumption_analysis_does_not_mutate_repository(
    hidden_cardinality: GitFixture,
) -> None:
    before = repository_digest(hidden_cardinality.root)
    analyze(hidden_cardinality)
    after = repository_digest(hidden_cardinality.root)
    assert after == before

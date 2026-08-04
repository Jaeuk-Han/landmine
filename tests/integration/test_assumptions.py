from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

import landmine.analyzers.assumptions as assumptions_module
from landmine.analyzers.assumptions import analyze_assumptions
from landmine.analyzers.blast import analyze_blast
from landmine.analyzers.why import analyze_why
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
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == ()
    assert result.assumption_analysis.categories_scanned == ()
    assert result.assumption_analysis.coverage.status == "incomplete"


def test_python_syntax_error_returns_partial_limitation(git_fixture: GitFixture) -> None:
    git_fixture.commit("invalid", "Add invalid Python", {"src/broken.py": "def broken(:\n"})
    result = analyze(git_fixture, Target(path="src/broken.py"))
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(item.code == "provider_failure" for item in result.limitations)
    assert not assumption_findings(result)
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == ()
    assert result.assumption_analysis.coverage.status == "incomplete"


def test_no_finding_output_is_calibrated(git_fixture: GitFixture) -> None:
    git_fixture.commit(
        "safe", "Add safe code", {"src/safe.py": "def size(items):\n    return len(items)\n"}
    )
    result = analyze(git_fixture, Target(path="src/safe.py"))
    assert not assumption_findings(result)
    assert "found no supported" in result.summary.lower()
    assert "no assumptions exist" not in render_markdown(result).lower()
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
    )
    coverage = result.assumption_analysis.coverage
    assert result.analysis_status is AnalysisStatus.COMPLETE
    assert coverage.status == "bounded"
    assert coverage.requested_category == "data"
    assert coverage.target_scope == "file"
    assert coverage.runtime_execution is False
    assert coverage.risk_basis == "signals observed by evaluated detectors only"
    assert coverage.not_established == (
        "absence of unsupported assumption types",
        "runtime behavior or safety",
        "external library behavior",
        "interprocedural behavior",
    )
    assert any(item.code == "bounded_method" for item in result.limitations)
    markdown = render_markdown(result).lower()
    assert "0 candidate(s) were suppressed" in markdown
    assert "runtime execution: not performed" in markdown
    assert "no risk" not in markdown
    assert "fully covered" not in markdown
    assert "is safe" not in markdown


def test_finding_result_reports_bounded_detector_signal_risk(
    hidden_cardinality: GitFixture,
) -> None:
    result = analyze(hidden_cardinality)
    assert assumption_findings(result)
    assert result.analysis_status is AnalysisStatus.COMPLETE
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.coverage.status == "bounded"
    assert "signals observed by the evaluated detectors" in render_markdown(result)


def test_line_range_coverage_records_requested_scope(hidden_cardinality: GitFixture) -> None:
    result = analyze(
        hidden_cardinality,
        Target(path="src/processor.py", start_line=1, end_line=2),
    )
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.coverage.target_scope == "line_range"


def test_symbol_coverage_records_requested_scope(hidden_cardinality: GitFixture) -> None:
    result = analyze(hidden_cardinality, Target(symbol="process_unsafe"))
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.coverage.target_scope == "symbol"


def test_budget_exhaustion_keeps_executed_detectors_and_marks_coverage_incomplete(
    hidden_cardinality: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        assumptions_module,
        "_discover_test_protection",
        lambda **_kwargs: ((), 0, True, False),
    )
    result = analyze(hidden_cardinality)
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
    )
    assert result.assumption_analysis.coverage.status == "incomplete"
    assert any(item.code == "budget_exhausted" for item in result.limitations)


def test_detector_failure_is_structured_and_not_recorded_as_executed(
    git_fixture: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingDetector:
        detector_id = "python.test-failure"
        category = assumptions_module.AssumptionCategory.DATA

        def detect(self, _context):
            raise RuntimeError("raw provider detail")

    git_fixture.commit(
        "source",
        "Add source",
        {"src/example.py": "def example(value):\n    return value\n"},
    )
    monkeypatch.setattr(assumptions_module, "_DETECTORS", (FailingDetector(),))
    result = analyze(git_fixture, Target(path="src/example.py"))
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == ()
    assert result.assumption_analysis.coverage.status == "incomplete"
    assert any(item.code == "provider_failure" for item in result.limitations)
    assert "raw provider detail" not in render_json(result)
    assert "raw provider detail" not in render_markdown(result)


def test_coverage_ordering_and_markdown_json_semantics_are_deterministic(
    hidden_cardinality: GitFixture,
) -> None:
    first = analyze(hidden_cardinality)
    second = analyze(hidden_cardinality)
    assert render_json(first) == render_json(second)
    assert first.assumption_analysis is not None
    payload = result_dict(first)["assumption_analysis"]
    markdown = render_markdown(first)
    for detector_id in payload["detectors_run"]:
        assert f"`{detector_id}`" in markdown
    for item in payload["coverage"]["not_established"]:
        assert item in markdown


def test_v1_schema_still_accepts_payload_without_optional_coverage(
    hidden_cardinality: GitFixture,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    payload = result_dict(analyze(hidden_cardinality))
    payload["assumption_analysis"].pop("coverage")
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_assumption_coverage_is_not_added_to_why_or_blast(
    hidden_cardinality: GitFixture,
) -> None:
    why = analyze_why(
        repo=hidden_cardinality.root,
        target=Target(path="src/processor.py"),
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )
    blast = analyze_blast(
        repo=hidden_cardinality.root,
        change="bounded detector reporting",
        target=Target(path="src/processor.py"),
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )
    assert "assumption_analysis" not in result_dict(why)
    assert "assumption_analysis" not in result_dict(blast)


def test_min_confidence_filters_findings(hidden_cardinality: GitFixture) -> None:
    result = analyze(hidden_cardinality, min_confidence=0.99)
    assert not assumption_findings(result)
    assert "minimum confidence" in result.summary.lower()


def test_assumption_json_is_deterministic(hidden_cardinality: GitFixture) -> None:
    assert render_json(analyze(hidden_cardinality)) == render_json(analyze(hidden_cardinality))


def test_non_empty_collection_json_omits_mapping_only_fields(
    hidden_cardinality: GitFixture,
) -> None:
    payload = result_dict(analyze(hidden_cardinality))
    details = [
        item["assumption"]
        for item in payload["findings"]
        if item.get("assumption", {}).get("detector_id") == "python.non-empty-collection"
    ]
    assert details
    assert all("base_expression" not in item and "required_key" not in item for item in details)


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

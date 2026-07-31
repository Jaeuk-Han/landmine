from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from landmine.analyzers.assumptions import analyze_assumptions
from landmine.domain import ClaimStatus, ProtectionStatus, Target
from landmine.renderers import render_json, render_markdown, result_dict
from tests.conftest import GitFixture, repository_digest

FIXED_TIME = datetime(2026, 7, 31, 9, 0, tzinfo=UTC)
DETECTOR_ID = "python.required-environment-variable"


def analyze(
    fixture: GitFixture,
    target: Target | None = None,
    *,
    category: str | None = None,
):
    return analyze_assumptions(
        repo=fixture.root,
        target=target or Target(path="src/config.py"),
        category=category,
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def environment_findings(result):
    return [
        item
        for item in result.findings
        if item.assumption is not None and item.assumption.detector_id == DETECTOR_ID
    ]


def finding_for_scope(result, scope: str):
    return next(
        item
        for item in environment_findings(result)
        if item.assumption is not None and item.assumption.scope == scope
    )


def test_setenv_test_does_not_mark_missing_behavior_protected(
    hidden_environment_variable: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_environment_variable), "required_os_environ")
    assert finding.assumption is not None
    assert finding.assumption.candidate_tests == ("tests/test_config.py",)
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN


def test_delenv_test_marks_missing_behavior_protected(
    hidden_environment_variable: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_environment_variable), "required_aliased_os")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "missing-variable behavior is explicitly tested" in finding.assumption.uncertainty


def test_delenv_pytest_raises_is_characterization(
    hidden_environment_variable: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_environment_variable), "required_imported_environ")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "KeyError characterization" in finding.assumption.uncertainty


def test_environment_finding_is_at_most_inferred(
    hidden_environment_variable: GitFixture,
) -> None:
    findings = environment_findings(analyze(hidden_environment_variable))
    assert findings
    assert all(item.status is ClaimStatus.INFERRED for item in findings)
    assert all(
        item.assumption is not None
        and item.confidence <= item.assumption.confidence_ceiling <= 0.79
        for item in findings
    )


def test_environment_category_runs_only_environment_detector(
    hidden_environment_variable: GitFixture,
) -> None:
    result = analyze(hidden_environment_variable, category="environment")
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (DETECTOR_ID,)
    assert {item.assumption.detector_id for item in environment_findings(result)} == {DETECTOR_ID}


def test_data_category_excludes_environment_detector(
    hidden_environment_variable: GitFixture,
) -> None:
    result = analyze(hidden_environment_variable, category="data")
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
    )
    assert not environment_findings(result)
    assert all(
        item.assumption is None or item.assumption.detector_id != DETECTOR_ID
        for item in result.findings
    )


def test_default_category_runs_all_detectors(
    hidden_environment_variable: GitFixture,
) -> None:
    result = analyze(hidden_environment_variable)
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
        DETECTOR_ID,
        "python.required-response-field",
        "python.arbitrary-set-selection",
        "python.cwd-relative-file-access",
    )


def test_environment_json_is_deterministic(
    hidden_environment_variable: GitFixture,
) -> None:
    assert render_json(analyze(hidden_environment_variable)) == render_json(
        analyze(hidden_environment_variable)
    )


def test_environment_json_matches_v1_schema(
    hidden_environment_variable: GitFixture,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(result_dict(analyze(hidden_environment_variable)))


def test_environment_markdown_references_evidence(
    hidden_environment_variable: GitFixture,
) -> None:
    result = analyze(hidden_environment_variable)
    markdown = render_markdown(result)
    for finding in environment_findings(result):
        assert all(item in markdown for item in finding.evidence_ids)
    assert "protected = missing-variable behavior is explicitly tested" in markdown


def test_environment_symbol_scope_is_respected(
    hidden_environment_variable: GitFixture,
) -> None:
    result = analyze(
        hidden_environment_variable,
        Target(symbol="required_aliased_environ"),
    )
    findings = environment_findings(result)
    assert len(findings) == 1
    assert findings[0].assumption is not None
    assert findings[0].assumption.scope == "required_aliased_environ"


def test_environment_analysis_does_not_mutate_repository(
    hidden_environment_variable: GitFixture,
) -> None:
    before = repository_digest(hidden_environment_variable.root)
    analyze(hidden_environment_variable)
    after = repository_digest(hidden_environment_variable.root)
    assert after == before

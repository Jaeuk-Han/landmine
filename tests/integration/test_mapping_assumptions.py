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
DETECTOR_ID = "python.required-mapping-key"


def analyze(fixture: GitFixture, target: Target | None = None):
    return analyze_assumptions(
        repo=fixture.root,
        target=target or Target(path="src/parser.py"),
        category="data",
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def mapping_findings(result):
    return [
        item
        for item in result.findings
        if item.assumption is not None and item.assumption.detector_id == DETECTOR_ID
    ]


def finding_for_scope(result, scope: str):
    return next(
        item
        for item in mapping_findings(result)
        if item.assumption is not None and item.assumption.scope == scope
    )


def test_missing_key_test_marks_protected(hidden_mapping_key: GitFixture) -> None:
    finding = finding_for_scope(analyze(hidden_mapping_key), "truthy_mapping_guard")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "missing-key behavior is explicitly tested" in finding.assumption.uncertainty


def test_pytest_raises_key_error_is_characterization(hidden_mapping_key: GitFixture) -> None:
    finding = finding_for_scope(analyze(hidden_mapping_key), "get_then_direct_access")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "KeyError characterization" in finding.assumption.uncertainty


def test_candidate_test_does_not_imply_protected(hidden_mapping_key: GitFixture) -> None:
    finding = finding_for_scope(analyze(hidden_mapping_key), "unsafe_access")
    assert finding.assumption is not None
    assert finding.assumption.candidate_tests == ("tests/test_parser.py",)
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN


def test_mapping_key_finding_is_at_most_inferred(hidden_mapping_key: GitFixture) -> None:
    findings = mapping_findings(analyze(hidden_mapping_key))
    assert findings
    assert all(item.status is ClaimStatus.INFERRED for item in findings)
    assert all(
        item.assumption is not None
        and item.confidence <= item.assumption.confidence_ceiling <= 0.79
        for item in findings
    )


def test_detector_order_is_deterministic(hidden_mapping_key: GitFixture) -> None:
    result = analyze(hidden_mapping_key)
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
    )


def test_mapping_key_json_is_deterministic(hidden_mapping_key: GitFixture) -> None:
    assert render_json(analyze(hidden_mapping_key)) == render_json(analyze(hidden_mapping_key))


def test_mapping_key_json_matches_v1_schema(hidden_mapping_key: GitFixture) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        result_dict(analyze(hidden_mapping_key))
    )


def test_mapping_key_markdown_references_evidence(hidden_mapping_key: GitFixture) -> None:
    result = analyze(hidden_mapping_key)
    markdown = render_markdown(result)
    for finding in mapping_findings(result):
        assert all(item in markdown for item in finding.evidence_ids)
    assert "protected = missing-key behavior is explicitly tested" in markdown


def test_line_range_filters_mapping_findings(hidden_mapping_key: GitFixture) -> None:
    result = analyze(
        hidden_mapping_key,
        Target(path="src/parser.py", start_line=1, end_line=2),
    )
    findings = mapping_findings(result)
    assert len(findings) == 1
    assert findings[0].assumption is not None
    assert findings[0].assumption.scope == "unsafe_access"


def test_symbol_scope_filters_mapping_findings(hidden_mapping_key: GitFixture) -> None:
    result = analyze(hidden_mapping_key, Target(symbol="wrong_key_guard"))
    findings = mapping_findings(result)
    assert len(findings) == 1
    assert findings[0].assumption is not None
    assert findings[0].assumption.scope == "wrong_key_guard"


def test_mapping_detector_does_not_mutate_repository(hidden_mapping_key: GitFixture) -> None:
    before = repository_digest(hidden_mapping_key.root)
    analyze(hidden_mapping_key)
    after = repository_digest(hidden_mapping_key.root)
    assert after == before

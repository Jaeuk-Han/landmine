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
DETECTOR_ID = "python.wall-clock-elapsed-time"


def analyze(
    fixture: GitFixture,
    target: Target | None = None,
    *,
    category: str | None = None,
):
    return analyze_assumptions(
        repo=fixture.root,
        target=target or Target(path="src/timeout_logic.py"),
        category=category,
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def time_findings(result):
    return [
        item
        for item in result.findings
        if item.assumption is not None and item.assumption.detector_id == DETECTOR_ID
    ]


def finding_for_scope(result, scope: str):
    return next(
        item
        for item in time_findings(result)
        if item.assumption is not None and item.assumption.scope == scope
    )


def test_fixed_clock_mock_does_not_mark_jump_behavior_protected(
    hidden_time: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_time), "time_ns_duration")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN


def test_backward_clock_mock_can_characterize_behavior(
    hidden_time: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_time), "returned_duration")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "backward" in finding.assumption.uncertainty


def test_forward_clock_mock_can_characterize_behavior(
    hidden_time: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_time), "deadline_if")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "forward" in finding.assumption.uncertainty


def test_unproven_mock_does_not_mark_protected(hidden_time: GitFixture) -> None:
    finding = finding_for_scope(analyze(hidden_time), "imported_time_alias")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN


def test_time_finding_is_at_most_inferred(hidden_time: GitFixture) -> None:
    findings = time_findings(analyze(hidden_time))
    assert findings
    assert all(item.status is ClaimStatus.INFERRED for item in findings)
    assert all(
        item.assumption is not None
        and item.confidence <= item.assumption.confidence_ceiling <= 0.79
        for item in findings
    )


def test_time_category_runs_only_time_detector(hidden_time: GitFixture) -> None:
    result = analyze(hidden_time, category="time")
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (DETECTOR_ID,)
    assert all(
        item.assumption is None or item.assumption.detector_id == DETECTOR_ID
        for item in result.findings
    )


def test_default_category_runs_all_seven_detectors(hidden_time: GitFixture) -> None:
    result = analyze(hidden_time)
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
        "python.required-environment-variable",
        "python.required-response-field",
        "python.arbitrary-set-selection",
        "python.cwd-relative-file-access",
        DETECTOR_ID,
    )


def test_time_json_is_deterministic(hidden_time: GitFixture) -> None:
    assert render_json(analyze(hidden_time)) == render_json(analyze(hidden_time))


def test_time_json_matches_v1_schema(hidden_time: GitFixture) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(result_dict(analyze(hidden_time)))


def test_time_markdown_links_clock_provenance(hidden_time: GitFixture) -> None:
    result = analyze(hidden_time, Target(symbol="time_duration"))
    finding = time_findings(result)[0]
    markdown = render_markdown(result)
    assert all(item in markdown for item in finding.evidence_ids)
    assert any(
        item.locator.get("provenance_role") == "clock_call"
        for item in result.evidence
        if item.id in finding.evidence_ids
    )
    assert "Suggested monotonic alternatives" in markdown


def test_time_symbol_scope_is_respected(hidden_time: GitFixture) -> None:
    result = analyze(hidden_time, Target(symbol="deadline_loop"))
    findings = time_findings(result)
    assert len(findings) == 1
    assert findings[0].assumption is not None
    assert findings[0].assumption.scope == "deadline_loop"


def test_time_detector_does_not_mutate_repository(hidden_time: GitFixture) -> None:
    before = repository_digest(hidden_time.root)
    analyze(hidden_time)
    after = repository_digest(hidden_time.root)
    assert after == before

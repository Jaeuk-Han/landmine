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
DETECTOR_ID = "python.arbitrary-set-selection"


def analyze(
    fixture: GitFixture,
    target: Target | None = None,
    *,
    category: str | None = None,
):
    return analyze_assumptions(
        repo=fixture.root,
        target=target or Target(path="src/selector.py"),
        category=category,
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def ordering_findings(result):
    return [
        item
        for item in result.findings
        if item.assumption is not None and item.assumption.detector_id == DETECTOR_ID
    ]


def finding_for_scope(result, scope: str):
    return next(
        item
        for item in ordering_findings(result)
        if item.assumption is not None and item.assumption.scope == scope
    )


def test_related_test_does_not_mark_ordering_protected(
    hidden_ordering: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_ordering), "typed_set_next_iter")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN
    assert (
        "A related test does not prove deterministic set ordering."
        in finding.assumption.uncertainty
    )


def test_ordering_finding_is_at_most_inferred(hidden_ordering: GitFixture) -> None:
    findings = ordering_findings(analyze(hidden_ordering))
    assert findings
    assert all(item.status is ClaimStatus.INFERRED for item in findings)
    assert all(
        item.assumption is not None
        and item.confidence <= item.assumption.confidence_ceiling <= 0.79
        for item in findings
    )


def test_ordering_category_runs_only_ordering_detector(
    hidden_ordering: GitFixture,
) -> None:
    result = analyze(hidden_ordering, category="ordering")
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (DETECTOR_ID,)
    assert all(
        item.assumption is None or item.assumption.detector_id == DETECTOR_ID
        for item in result.findings
    )


def test_default_category_runs_all_seven_detectors(
    hidden_ordering: GitFixture,
) -> None:
    result = analyze(hidden_ordering)
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
        "python.required-environment-variable",
        "python.required-response-field",
        DETECTOR_ID,
        "python.cwd-relative-file-access",
        "python.wall-clock-elapsed-time",
    )


def test_ordering_json_is_deterministic(hidden_ordering: GitFixture) -> None:
    assert render_json(analyze(hidden_ordering)) == render_json(analyze(hidden_ordering))


def test_ordering_json_matches_v1_schema(hidden_ordering: GitFixture) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(result_dict(analyze(hidden_ordering)))


def test_ordering_markdown_links_provenance(hidden_ordering: GitFixture) -> None:
    result = analyze(hidden_ordering, Target(symbol="constructed_set_list_index"))
    finding = ordering_findings(result)[0]
    markdown = render_markdown(result)
    assert all(item in markdown for item in finding.evidence_ids)
    assert any(
        item.locator.get("provenance_role") == "set_construction"
        for item in result.evidence
        if item.id in finding.evidence_ids
    )
    assert "Suggested deterministic alternatives" in markdown


def test_ordering_symbol_scope_is_respected(hidden_ordering: GitFixture) -> None:
    result = analyze(hidden_ordering, Target(symbol="set_pop"))
    findings = ordering_findings(result)
    assert len(findings) == 1
    assert findings[0].assumption is not None
    assert findings[0].assumption.scope == "set_pop"


def test_ordering_detector_does_not_mutate_repository(
    hidden_ordering: GitFixture,
) -> None:
    before = repository_digest(hidden_ordering.root)
    analyze(hidden_ordering)
    after = repository_digest(hidden_ordering.root)
    assert after == before

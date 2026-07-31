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
DETECTOR_ID = "python.required-response-field"


def analyze(
    fixture: GitFixture,
    target: Target | None = None,
    *,
    category: str | None = None,
):
    return analyze_assumptions(
        repo=fixture.root,
        target=target or Target(path="src/client.py"),
        category=category,
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def response_findings(result):
    return [
        item
        for item in result.findings
        if item.assumption is not None and item.assumption.detector_id == DETECTOR_ID
    ]


def finding_for_scope(result, scope: str):
    return next(
        item
        for item in response_findings(result)
        if item.assumption is not None and item.assumption.scope == scope
    )


def test_missing_field_mock_marks_protected(
    hidden_external_contract: GitFixture,
) -> None:
    finding = finding_for_scope(
        analyze(hidden_external_contract),
        "requests_payload_assignment",
    )
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "missing-field external response behavior" in finding.assumption.uncertainty


def test_present_field_mock_does_not_mark_missing_behavior_protected(
    hidden_external_contract: GitFixture,
) -> None:
    finding = finding_for_scope(
        analyze(hidden_external_contract),
        "requests_direct_json_access",
    )
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN


def test_unproven_mock_does_not_mark_protected(
    hidden_external_contract: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_external_contract), "httpx_direct")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN


def test_missing_field_pytest_raises_is_characterization(
    hidden_external_contract: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_external_contract), "requests_alias")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "KeyError characterization" in finding.assumption.uncertainty


def test_response_field_finding_is_at_most_inferred(
    hidden_external_contract: GitFixture,
) -> None:
    findings = response_findings(analyze(hidden_external_contract))
    assert findings
    assert all(item.status is ClaimStatus.INFERRED for item in findings)
    assert all(
        item.assumption is not None
        and item.confidence <= item.assumption.confidence_ceiling <= 0.79
        for item in findings
    )


def test_external_contract_category_runs_only_response_detector(
    hidden_external_contract: GitFixture,
) -> None:
    result = analyze(hidden_external_contract, category="external_contract")
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (DETECTOR_ID,)
    assert all(
        item.assumption is None or item.assumption.detector_id == DETECTOR_ID
        for item in result.findings
    )


def test_default_category_runs_all_four_detectors(
    hidden_external_contract: GitFixture,
) -> None:
    result = analyze(hidden_external_contract)
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
        "python.required-environment-variable",
        DETECTOR_ID,
    )


def test_response_field_json_is_deterministic(
    hidden_external_contract: GitFixture,
) -> None:
    assert render_json(analyze(hidden_external_contract)) == render_json(
        analyze(hidden_external_contract)
    )


def test_response_field_json_matches_v1_schema(
    hidden_external_contract: GitFixture,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(result_dict(analyze(hidden_external_contract)))


def test_response_field_markdown_links_provenance_evidence(
    hidden_external_contract: GitFixture,
) -> None:
    result = analyze(
        hidden_external_contract,
        Target(symbol="requests_payload_assignment"),
    )
    finding = response_findings(result)[0]
    markdown = render_markdown(result)
    assert all(item in markdown for item in finding.evidence_ids)
    provenance_roles = {
        item.locator.get("provenance_role")
        for item in result.evidence
        if item.id in finding.evidence_ids
    }
    assert {"http_call", "json_conversion"} <= provenance_roles
    assert (
        "protected = missing-field external response behavior is explicitly characterized"
        in markdown
    )


def test_response_symbol_scope_is_respected(
    hidden_external_contract: GitFixture,
) -> None:
    result = analyze(
        hidden_external_contract,
        Target(symbol="httpx_alias"),
    )
    findings = response_findings(result)
    assert len(findings) == 1
    assert findings[0].assumption is not None
    assert findings[0].assumption.scope == "httpx_alias"


def test_response_detector_does_not_mutate_repository(
    hidden_external_contract: GitFixture,
) -> None:
    before = repository_digest(hidden_external_contract.root)
    analyze(hidden_external_contract)
    after = repository_digest(hidden_external_contract.root)
    assert after == before

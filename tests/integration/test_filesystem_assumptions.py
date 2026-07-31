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
DETECTOR_ID = "python.cwd-relative-file-access"


def analyze(
    fixture: GitFixture,
    target: Target | None = None,
    *,
    category: str | None = None,
):
    return analyze_assumptions(
        repo=fixture.root,
        target=target or Target(path="src/config_loader.py"),
        category=category,
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def filesystem_findings(result):
    return [
        item
        for item in result.findings
        if item.assumption is not None and item.assumption.detector_id == DETECTOR_ID
    ]


def finding_for_scope(result, scope: str):
    return next(
        item
        for item in filesystem_findings(result)
        if item.assumption is not None and item.assumption.scope == scope
    )


def test_chdir_test_can_characterize_cwd_behavior(
    hidden_filesystem: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_filesystem), "builtin_open_relative")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.PROTECTED
    assert "working-directory-dependent behavior" in finding.assumption.uncertainty


def test_related_test_without_chdir_is_not_protected(
    hidden_filesystem: GitFixture,
) -> None:
    finding = finding_for_scope(analyze(hidden_filesystem), "pathlib_direct_read")
    assert finding.assumption is not None
    assert finding.assumption.protection is ProtectionStatus.UNKNOWN
    assert "monkeypatch.chdir" in finding.assumption.uncertainty


def test_filesystem_finding_is_at_most_inferred(
    hidden_filesystem: GitFixture,
) -> None:
    findings = filesystem_findings(analyze(hidden_filesystem))
    assert findings
    assert all(item.status is ClaimStatus.INFERRED for item in findings)
    assert all(
        item.assumption is not None
        and item.confidence <= item.assumption.confidence_ceiling <= 0.79
        for item in findings
    )


def test_filesystem_category_runs_only_filesystem_detector(
    hidden_filesystem: GitFixture,
) -> None:
    result = analyze(hidden_filesystem, category="filesystem")
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (DETECTOR_ID,)
    assert all(
        item.assumption is None or item.assumption.detector_id == DETECTOR_ID
        for item in result.findings
    )


def test_default_category_runs_all_six_detectors(
    hidden_filesystem: GitFixture,
) -> None:
    result = analyze(hidden_filesystem)
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.detectors_run == (
        "python.non-empty-collection",
        "python.required-mapping-key",
        "python.required-environment-variable",
        "python.required-response-field",
        "python.arbitrary-set-selection",
        DETECTOR_ID,
    )


def test_filesystem_json_is_deterministic(hidden_filesystem: GitFixture) -> None:
    assert render_json(analyze(hidden_filesystem)) == render_json(analyze(hidden_filesystem))


def test_filesystem_json_matches_v1_schema(hidden_filesystem: GitFixture) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(result_dict(analyze(hidden_filesystem)))


def test_filesystem_markdown_links_path_evidence(
    hidden_filesystem: GitFixture,
) -> None:
    result = analyze(hidden_filesystem, Target(symbol="assigned_relative_path"))
    finding = filesystem_findings(result)[0]
    markdown = render_markdown(result)
    assert all(item in markdown for item in finding.evidence_ids)
    assert any(
        item.locator.get("provenance_role") == "path_construction"
        for item in result.evidence
        if item.id in finding.evidence_ids
    )
    assert "Suggested explicit anchors" in markdown


def test_filesystem_symbol_scope_is_respected(
    hidden_filesystem: GitFixture,
) -> None:
    result = analyze(hidden_filesystem, Target(symbol="pathlib_module_alias"))
    findings = filesystem_findings(result)
    assert len(findings) == 1
    assert findings[0].assumption is not None
    assert findings[0].assumption.scope == "pathlib_module_alias"


def test_filesystem_detector_does_not_mutate_repository(
    hidden_filesystem: GitFixture,
) -> None:
    before = repository_digest(hidden_filesystem.root)
    analyze(hidden_filesystem)
    after = repository_digest(hidden_filesystem.root)
    assert after == before

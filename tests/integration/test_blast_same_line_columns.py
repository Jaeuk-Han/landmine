from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from landmine.analyzers.blast import analyze_blast
from landmine.domain import Target
from landmine.renderers import render_json, render_markdown, result_dict
from tests.conftest import GitFixture, repository_digest


@pytest.fixture
def same_line_calls(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "same_line_calls",
        "Add repeated target call occurrences",
        {
            "src/pkg/__init__.py": "",
            "src/pkg/mod.py": (
                "def target(value):\n    return value\n\n\ndef other(value):\n    return value\n"
            ),
            "tests/test_same_line.py": (
                "from pkg.mod import target\n\n\ndef test_same_line():\n"
                "    assert target(1) == target(1)\n"
            ),
            "tests/test_alias.py": (
                "from pkg.mod import target as alias\n\n\ndef test_alias():\n"
                "    assert alias(1) == alias(1)\n"
            ),
            "tests/test_different_lines.py": (
                "from pkg.mod import target\n\n\ndef test_different_lines():\n"
                "    first = target(1)\n    second = target(2)\n    assert first == second\n"
            ),
            "tests/test_unicode.py": (
                "from pkg.mod import target\n\n\ndef test_unicode():\n"
                '    assert "한글" and target(1)\n'
            ),
            "tests/test_nested.py": (
                "from pkg.mod import target\n\n\ndef test_nested():\n    assert target(target(1))\n"
            ),
            "tests/test_other_symbol.py": (
                "from pkg.mod import other, target\n\n\ndef test_other_symbol():\n"
                "    assert target(1) == other(1) == target(2)\n"
            ),
        },
    )
    return git_fixture


def result_for(fixture: GitFixture):
    return analyze_blast(
        repo=fixture.root,
        change="change repeated target calls",
        target=Target(symbol="target"),
        clock=lambda: datetime(2026, 8, 4, tzinfo=UTC),
        monotonic=lambda: 100.0,
    )


def test_same_line_calls_have_distinct_character_columns_and_ids(
    same_line_calls: GitFixture,
) -> None:
    result = result_for(same_line_calls)
    impacts = [item for item in result.impacts if item.path == "tests/test_same_line.py"]

    assert [(item.start_line, item.start_column, item.end_column) for item in impacts] == [
        (5, 12, 18),
        (5, 25, 31),
    ]
    assert len({item.id for item in impacts}) == 2
    evidence = {item.id: item for item in result.evidence}
    occurrence_evidence_ids = {
        next(
            evidence[evidence_id].id
            for evidence_id in impact.evidence_ids
            if "start_column" in evidence[evidence_id].locator
        )
        for impact in impacts
    }
    assert len(occurrence_evidence_ids) == 2


def test_alias_different_line_nested_and_other_symbol_occurrences(
    same_line_calls: GitFixture,
) -> None:
    result = result_for(same_line_calls)
    by_path = {
        path: [item for item in result.impacts if item.path == path]
        for path in (
            "tests/test_alias.py",
            "tests/test_different_lines.py",
            "tests/test_nested.py",
            "tests/test_other_symbol.py",
        )
    }

    assert [(item.start_column, item.end_column) for item in by_path["tests/test_alias.py"]] == [
        (12, 17),
        (24, 29),
    ]
    assert [item.start_line for item in by_path["tests/test_different_lines.py"]] == [5, 6]
    assert [(item.start_column, item.end_column) for item in by_path["tests/test_nested.py"]] == [
        (12, 18),
        (19, 25),
    ]
    assert [
        (item.start_column, item.end_column) for item in by_path["tests/test_other_symbol.py"]
    ] == [
        (12, 18),
        (37, 43),
    ]
    assert all(item.symbol == "target" for item in by_path["tests/test_other_symbol.py"])


def test_unicode_prefix_uses_character_not_byte_column(same_line_calls: GitFixture) -> None:
    result = result_for(same_line_calls)
    impact = next(item for item in result.impacts if item.path == "tests/test_unicode.py")

    assert (impact.start_column, impact.end_column) == (21, 27)


def test_occurrence_order_and_json_are_deterministic(same_line_calls: GitFixture) -> None:
    first = result_for(same_line_calls)
    second = result_for(same_line_calls)

    assert render_json(first) == render_json(second)
    test_locations = [
        (item.path, item.start_line, item.start_column)
        for item in first.impacts
        if item.impact_type == "test"
    ]
    assert test_locations == sorted(test_locations)


def test_markdown_and_evidence_locators_match_json(same_line_calls: GitFixture) -> None:
    result = result_for(same_line_calls)
    payload = result_dict(result)
    markdown = render_markdown(result)
    evidence = {item["id"]: item for item in payload["evidence"]}

    for impact in payload["impacts"]:
        if impact["impact_type"] not in {"reference", "test"}:
            continue
        location = f"{impact['path']}:{impact['start_line']}:{impact['start_column']}"
        assert location in markdown
        occurrence = next(
            evidence[evidence_id]["locator"]
            for evidence_id in impact["evidence_ids"]
            if "start_column" in evidence[evidence_id]["locator"]
        )
        assert occurrence["start_column"] == impact["start_column"]
        assert occurrence["end_column"] == impact["end_column"]


def test_v1_schema_accepts_new_and_legacy_columnless_payloads(
    same_line_calls: GitFixture,
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).parents[2] / "schemas" / "result-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.Draft202012Validator(schema)
    payload = result_dict(result_for(same_line_calls))
    validator.validate(payload)

    for impact in payload["impacts"]:
        impact.pop("start_column", None)
        impact.pop("end_column", None)
    for item in payload["evidence"]:
        item["locator"].pop("start_column", None)
        item["locator"].pop("end_column", None)
    validator.validate(payload)


def test_same_line_analysis_preserves_candidates_and_repository(
    same_line_calls: GitFixture,
) -> None:
    before = repository_digest(same_line_calls.root)
    result = result_for(same_line_calls)

    assert result.blast_analysis is not None
    assert result.blast_analysis.candidate_test_count == 0
    assert repository_digest(same_line_calls.root) == before

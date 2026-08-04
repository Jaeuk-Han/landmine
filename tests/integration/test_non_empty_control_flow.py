from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from landmine.analyzers.assumptions import analyze_assumptions
from landmine.domain import Target
from landmine.renderers import render_json, render_markdown
from tests.conftest import GitFixture, repository_digest

FIXED_TIME = datetime(2026, 8, 4, tzinfo=UTC)


@pytest.fixture
def non_empty_control_flow(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "control_flow",
        "Add bounded collection control flow",
        {
            "src/control_flow.py": (
                "def fold_lines(text):\n"
                "    out = []\n"
                "    for raw in text.splitlines():\n"
                "        if not raw.strip():\n"
                "            continue\n"
                "        line = raw.rstrip()\n"
                "        if not out or line.startswith('-'):\n"
                "            out.append(line)\n"
                "            continue\n"
                "        prev = out[-1]\n"
                "        if prev[-1].isdigit():\n"
                "            out.append(line)\n"
                "            continue\n"
                "        out[-1] = prev + ' ' + line.strip()\n"
                "    return out\n"
                "\n"
                "\n"
                "def walk(alg, condition):\n"
                "    children = alg['children']\n"
                "    return condition or (children and children[0][0])\n"
            )
        },
    )
    return git_fixture


def _analyze(fixture: GitFixture, symbol: str):
    return analyze_assumptions(
        repo=fixture.root,
        target=Target(symbol=symbol),
        category="data",
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def _non_empty_variables(result) -> list[str]:
    return [
        finding.claim.split("`", 2)[1]
        for finding in result.findings
        if finding.assumption is not None
        and finding.assumption.detector_id == "python.non-empty-collection"
    ]


def test_fold_lines_control_flow_is_suppressed_with_output_parity(
    non_empty_control_flow: GitFixture,
) -> None:
    result = _analyze(non_empty_control_flow, "fold_lines")
    payload = json.loads(render_json(result))
    markdown = render_markdown(result)

    assert _non_empty_variables(result) == []
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.suppression_count == 2
    assert payload["assumption_analysis"]["suppression_count"] == 2
    assert payload["summary"] == result.summary
    assert result.summary in markdown


def test_walk_short_circuit_suppresses_only_proven_collection(
    non_empty_control_flow: GitFixture,
) -> None:
    result = _analyze(non_empty_control_flow, "walk")

    assert _non_empty_variables(result) == ["children[0]"]
    assert result.assumption_analysis is not None
    assert result.assumption_analysis.suppression_count == 1
    assert any(
        finding.assumption is not None
        and finding.assumption.detector_id == "python.required-mapping-key"
        and finding.assumption.base_expression == "alg"
        for finding in result.findings
    )


def test_control_flow_output_is_deterministic(
    non_empty_control_flow: GitFixture,
) -> None:
    assert render_json(_analyze(non_empty_control_flow, "fold_lines")) == render_json(
        _analyze(non_empty_control_flow, "fold_lines")
    )


def test_control_flow_analysis_does_not_mutate_repository(
    non_empty_control_flow: GitFixture,
) -> None:
    before = repository_digest(non_empty_control_flow.root)

    _analyze(non_empty_control_flow, "fold_lines")
    _analyze(non_empty_control_flow, "walk")

    assert repository_digest(non_empty_control_flow.root) == before

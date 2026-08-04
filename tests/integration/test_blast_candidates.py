from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from landmine.analyzers.blast import analyze_blast
from landmine.domain import Target
from landmine.renderers import render_json, render_markdown
from tests.conftest import GitFixture, repository_digest


@pytest.fixture
def candidate_signals(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "candidate_signals",
        "Add structural candidate signals",
        {
            "src/pkg/__init__.py": "",
            "src/pkg/render.py": "def _first_text(value):\n    return value\n",
            "tests/test_render.py": "def test_aligned():\n    assert True\n",
            "tests/render_test.py": "def test_aligned_suffix():\n    assert True\n",
            "tests/test_name.py": ("def test_name(value):\n    return _first_text(value)\n"),
            "tests/test_attribute.py": (
                "def test_attribute(subject):\n    return subject._first_text()\n"
            ),
            "tests/test_import_only.py": (
                "from pkg import render\n\n\ndef test_import_only():\n    assert render\n"
            ),
            "tests/test_wildcard.py": (
                "from pkg.render import *\n\n\ndef test_wildcard():\n    assert True\n"
            ),
            "tests/test_dynamic.py": (
                "import importlib\n\n\ndef test_dynamic():\n"
                '    assert importlib.import_module("pkg.render")\n'
            ),
            "tests/test_direct.py": (
                "from pkg.render import _first_text\n\n\ndef test_direct():\n"
                "    assert _first_text('value') == 'value'\n"
            ),
            "tests/test_comment.py": "# _first_text render\ndef test_comment():\n    assert True\n",
            "tests/test_docstring.py": (
                'def test_docstring():\n    """_first_text render"""\n    assert True\n'
            ),
            "tests/test_string.py": ('def test_string():\n    assert "_first_text render"\n'),
            "tests/test_render_report.py": (
                "def test_render_report():\n    return render_report()\n"
            ),
            "tests/test_symbol_substring.py": (
                "def test_symbol_substring():\n    return get_first_text()\n"
            ),
        },
    )
    return git_fixture


def result_for(fixture: GitFixture):
    return analyze_blast(
        repo=fixture.root,
        change="change first rendered text handling",
        target=Target(symbol="_first_text"),
        clock=lambda: datetime(2026, 8, 4, tzinfo=UTC),
        monotonic=lambda: 100.0,
    )


def test_structural_candidates_are_precise_and_deterministic(
    candidate_signals: GitFixture,
) -> None:
    first = result_for(candidate_signals)
    second = result_for(candidate_signals)
    assert first.blast_analysis is not None
    assert first.blast_analysis.candidate_tests == (
        "tests/render_test.py",
        "tests/test_attribute.py",
        "tests/test_dynamic.py",
        "tests/test_import_only.py",
        "tests/test_name.py",
        "tests/test_render.py",
        "tests/test_wildcard.py",
    )
    assert first.blast_analysis.candidate_tests == second.blast_analysis.candidate_tests


def test_weak_signals_are_not_candidates(candidate_signals: GitFixture) -> None:
    result = result_for(candidate_signals)
    assert result.blast_analysis is not None
    assert set(result.blast_analysis.candidate_tests).isdisjoint(
        {
            "tests/test_comment.py",
            "tests/test_docstring.py",
            "tests/test_string.py",
            "tests/test_render_report.py",
            "tests/test_symbol_substring.py",
        }
    )


def test_proven_direct_test_is_not_candidate(candidate_signals: GitFixture) -> None:
    result = result_for(candidate_signals)
    assert result.blast_analysis is not None
    assert "tests/test_direct.py" not in result.blast_analysis.candidate_tests
    assert any(
        impact.path == "tests/test_direct.py" and impact.impact_type == "test"
        for impact in result.impacts
    )


def test_import_only_candidate_and_unresolved_import_limitations_are_preserved(
    candidate_signals: GitFixture,
) -> None:
    result = result_for(candidate_signals)
    assert result.blast_analysis is not None
    assert "tests/test_import_only.py" in result.blast_analysis.candidate_tests
    assert any(item.code == "wildcard_import" for item in result.limitations)
    assert any(item.code == "dynamic_import" for item in result.limitations)


def test_candidate_markdown_json_semantics_match(candidate_signals: GitFixture) -> None:
    result = result_for(candidate_signals)
    payload = json.loads(render_json(result))
    markdown = render_markdown(result)
    candidates = payload["blast_analysis"]["candidate_tests"]

    assert payload["blast_analysis"]["candidate_test_count"] == len(candidates)
    for path in candidates:
        assert f"- Candidate test: {path}" in markdown


def test_candidate_analysis_does_not_mutate_repository(candidate_signals: GitFixture) -> None:
    before = repository_digest(candidate_signals.root)
    result_for(candidate_signals)
    assert repository_digest(candidate_signals.root) == before

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from landmine.analyzers.defuse import analyze_defuse
from landmine.analyzers.why import analyze_why
from landmine.domain import AnalysisStatus, Target
from landmine.renderers import render_json, render_markdown, result_dict
from tests.conftest import GitFixture, repository_digest

FIXED_TIME = datetime(2026, 8, 5, 9, 0, tzinfo=UTC)
CLASS_PATH = "src/widget.py"


@pytest.fixture
def class_history(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "introduction",
        "Introduce Widget",
        {
            CLASS_PATH: (
                "@registered\n"
                "class Widget:\n"
                '    """Initial widget."""\n'
                '    mode = "safe"\n'
                "\n"
                "    def run(self):\n"
                '        return "initial"\n'
            )
        },
    )
    git_fixture.commit(
        "body_change",
        "Change Widget method body",
        {
            CLASS_PATH: (
                "@registered\n"
                "class Widget:\n"
                '    """Initial widget."""\n'
                '    mode = "safe"\n'
                "\n"
                "    def run(self):\n"
                '        return "revised"\n'
            )
        },
    )
    git_fixture.commit(
        "new_method",
        "Add Widget stop method",
        {
            CLASS_PATH: (
                "@registered\n"
                "class Widget:\n"
                '    """Initial widget."""\n'
                '    mode = "safe"\n'
                "\n"
                "    def run(self):\n"
                '        return "revised"\n'
                "\n"
                "    def stop(self):\n"
                "        return None\n"
            )
        },
    )
    git_fixture.commit(
        "attribute_change",
        "Clarify Widget mode",
        {
            CLASS_PATH: (
                "@registered\n"
                "class Widget:\n"
                '    """Current widget."""\n'
                '    mode = "strict"\n'
                "\n"
                "    def run(self):\n"
                '        return "revised"\n'
                "\n"
                "    def stop(self):\n"
                "        return None\n"
            )
        },
    )
    git_fixture.commit(
        "outside_change",
        "Change unrelated module",
        {"src/unrelated.py": "value = 2\n"},
    )
    return git_fixture


def analyze(fixture: GitFixture, *, history_depth: int = 50):
    return analyze_why(
        repo=fixture.root,
        target=Target(symbol="Widget"),
        history_depth=history_depth,
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def test_class_symbol_uses_decorated_full_head_ast_range_and_body_history(
    class_history: GitFixture,
) -> None:
    before = repository_digest(class_history.root)
    result = analyze(class_history)

    assert result.request["target"] == {
        "path": CLASS_PATH,
        "start_line": 1,
        "end_line": 10,
        "symbol": "Widget",
    }
    assert [item.commit for item in result.evolution] == [
        class_history.commits["introduction"],
        class_history.commits["body_change"],
        class_history.commits["new_method"],
        class_history.commits["attribute_change"],
    ]
    assert result.evolution[0].roles == ("introduction",)
    assert result.evolution[-1].roles == ("latest",)
    assert class_history.commits["outside_change"] not in {item.commit for item in result.evolution}
    assert result.analysis_status is AnalysisStatus.COMPLETE
    assert repository_digest(class_history.root) == before


def test_class_history_rendering_is_deterministic_and_semantically_aligned(
    class_history: GitFixture,
) -> None:
    first = analyze(class_history)
    second = analyze(class_history)
    markdown = render_markdown(first)

    assert render_json(first) == render_json(second)
    assert "Status: complete" in markdown
    assert "src/widget.py:1-10" in markdown
    for evolution in first.evolution:
        assert evolution.commit[:12] in markdown


def test_class_history_depth_truncation_is_partial_and_not_introduction(
    class_history: GitFixture,
) -> None:
    result = analyze(class_history, history_depth=2)

    assert result.analysis_status is AnalysisStatus.PARTIAL
    limitation = next(item for item in result.limitations if item.code == "budget_exhausted")
    assert "history depth" in limitation.message
    assert len(result.evolution) == 2
    assert all("introduction" not in item.roles for item in result.evolution)
    assert result.evolution[-1].roles == ("latest",)


def test_function_symbol_scope_remains_full_body(class_history: GitFixture) -> None:
    result = analyze_why(
        repo=class_history.root,
        target=Target(symbol="run"),
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )

    assert result.request["target"] == {
        "path": CLASS_PATH,
        "start_line": 6,
        "end_line": 7,
        "symbol": "run",
    }


def test_defuse_inherits_class_history_without_execution_or_mutation(
    class_history: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = repository_digest(class_history.root)
    calls: list[list[str]] = []
    original = subprocess.run

    def recording(command, *args, **kwargs):
        calls.append([str(item) for item in command])
        return original(command, *args, **kwargs)

    monkeypatch.setattr("landmine.git.subprocess.run", recording)
    result = analyze_defuse(
        repo=class_history.root,
        target=Target(symbol="Widget"),
        goal="make a narrow Widget behavior change",
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )

    historical_commits = {
        item.locator.get("commit")
        for item in result.evidence
        if item.locator.get("line_evolution") is True
    }
    assert class_history.commits["body_change"] in historical_commits
    assert class_history.commits["attribute_change"] in historical_commits
    assert any(item.locator.get("end_line") == 10 for item in result.evidence)
    assert calls
    assert all("pytest" not in command for command in calls)
    assert repository_digest(class_history.root) == before


def test_class_history_json_remains_schema_valid(class_history: GitFixture) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    project_schema = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(project_schema.read_text(encoding="utf-8"))

    jsonschema.Draft202012Validator(schema).validate(result_dict(analyze(class_history)))

from __future__ import annotations

import json
from pathlib import Path

import pytest

from landmine.analyzers.why import analyze_why
from landmine.cli import main
from landmine.domain import AnalysisStatus, Target
from landmine.renderers import result_dict
from tests.conftest import GitFixture, repository_digest


def add_unique_symbol(fixture: GitFixture) -> None:
    fixture.commit(
        "symbol",
        "Add hospital fallback",
        {
            "src/routing.py": (
                'class HospitalFallback:\n    def route(self):\n        return "fallback"\n'
            ),
            "src/use_routing.py": (
                "from routing import HospitalFallback\nfallback = HospitalFallback()\n"
            ),
        },
    )


def add_ambiguous_symbol(fixture: GitFixture) -> None:
    fixture.commit(
        "ambiguous",
        "Add duplicate fallbacks",
        {
            "src/a.py": "class HospitalFallback:\n    pass\n",
            "src/b.ts": "export class HospitalFallback {}\n",
            "src/use.ts": "const fallback = new HospitalFallback();\n",
        },
    )


def test_symbol_why_connects_single_candidate_to_pipeline(
    git_fixture: GitFixture,
) -> None:
    add_unique_symbol(git_fixture)
    result = analyze_why(
        repo=git_fixture.root,
        target=Target(symbol="HospitalFallback"),
        monotonic=lambda: 100.0,
    )
    assert result.analysis_status is AnalysisStatus.COMPLETE
    assert result.error is None
    assert result.request["target"] == {
        "path": "src/routing.py",
        "start_line": 1,
        "end_line": 3,
        "symbol": "HospitalFallback",
    }
    assert any(item.kind == "git_blame" for item in result.evidence)


def test_ambiguous_symbol_lists_stable_candidates(
    git_fixture: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    add_ambiguous_symbol(git_fixture)
    arguments = [
        "why",
        "symbol:HospitalFallback",
        "--repo",
        str(git_fixture.root),
        "--format",
        "json",
    ]
    assert main(arguments) == 2
    first = json.loads(capsys.readouterr().out)
    assert main(arguments) == 2
    second = json.loads(capsys.readouterr().out)
    assert first["error"]["candidates"] == second["error"]["candidates"]
    assert [
        (candidate["match_kind"], candidate["path"], candidate["line"])
        for candidate in first["error"]["candidates"]
    ] == [
        ("definition", "src/a.py", 1),
        ("definition", "src/b.ts", 1),
        ("reference", "src/use.ts", 1),
    ]


def test_missing_symbol_returns_exit_code_2(
    git_fixture: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    git_fixture.commit("initial", "Initial", {"src/routing.py": "value = 1\n"})
    exit_code = main(
        [
            "why",
            "symbol:HospitalFallback",
            "--repo",
            str(git_fixture.root),
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == 2
    assert "symbol_not_found" in output
    assert "path:line" in output


def test_symbol_json_error_contains_candidates(
    git_fixture: GitFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    add_ambiguous_symbol(git_fixture)
    exit_code = main(
        [
            "why",
            "symbol:HospitalFallback",
            "--repo",
            str(git_fixture.root),
            "--format",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert payload["schema_version"] == "landmine.result.v1"
    assert payload["analysis_status"] == "failed"
    assert payload["error"]["code"] == "ambiguous_symbol"
    assert payload["error"]["candidates"][0] == {
        "line": 1,
        "match_kind": "definition",
        "matching_text": "class HospitalFallback:",
        "path": "src/a.py",
    }

    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        payload
    )


def test_symbol_resolution_does_not_mutate_repository(
    git_fixture: GitFixture,
) -> None:
    add_unique_symbol(git_fixture)
    before = repository_digest(git_fixture.root)
    result = analyze_why(
        repo=git_fixture.root,
        target=Target(symbol="HospitalFallback"),
        monotonic=lambda: 100.0,
    )
    after = repository_digest(git_fixture.root)
    assert result_dict(result)["request"]["target"]["symbol"] == "HospitalFallback"
    assert after == before

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from landmine.analyzers.blast import analyze_blast
from landmine.analyzers.defuse import analyze_defuse
from landmine.domain import AnalysisStatus, Target
from landmine.renderers import render_json, render_markdown, result_dict
from tests.conftest import GitFixture, repository_digest

FIXED_TIME = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)


@pytest.fixture
def package_submodule_calls(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "package_submodule_calls",
        "Add package submodule call forms",
        {
            "src/pkg/__init__.py": "",
            "src/pkg/testing.py": "class Target:\n    pass\n",
            "src/pkg/other.py": "class Other:\n    pass\n",
            "src/package_call.py": (
                "import pkg\n\n\ndef build():\n    return pkg.testing.Target()\n"
            ),
            "src/package_alias_call.py": (
                "import pkg as p\n\n\ndef build():\n    return p.testing.Target()\n"
            ),
            "tests/test_full_module.py": (
                "import pkg.testing\n\n\ndef test_target():\n    pkg.testing.Target()\n"
            ),
            "tests/test_module_alias.py": (
                "import pkg.testing as pt\n\n\ndef test_target():\n    pt.Target()\n"
            ),
            "tests/test_from_package.py": (
                "from pkg import testing\n\n\ndef test_target():\n    testing.Target()\n"
            ),
            "tests/test_from_module.py": (
                "from pkg.testing import Target\n\n\ndef test_target():\n    Target()\n"
            ),
            "tests/test_package_call.py": (
                "import pkg\n\n\ndef test_target():\n    pkg.testing.Target()\n"
            ),
            "tests/test_package_alias_call.py": (
                "import pkg as p\n\n\ndef test_target():\n    p.testing.Target()\n"
            ),
            "tests/test_local_import.py": (
                "def test_target():\n    import pkg\n    pkg.testing.Target()\n"
            ),
            "tests/test_local_import_leak.py": (
                "def bind_package():\n    import pkg\n\n\n"
                "def test_not_bound():\n    pkg.testing.Target()\n"
            ),
            "tests/test_same_line.py": (
                "import pkg\n\n\ndef test_target():\n"
                "    pkg.testing.Target(); pkg.testing.Target()\n"
            ),
            "tests/test_wrong_submodule.py": (
                "import pkg\n\n\ndef test_wrong():\n    pkg.other.Target()\n"
            ),
            "tests/test_wrong_symbol.py": (
                "import pkg\n\n\ndef test_wrong():\n    pkg.testing.OtherTarget()\n"
            ),
            "tests/test_unused_package.py": "import pkg\n",
            "tests/test_rebound_package.py": (
                "import pkg\n\npkg = replacement\npkg.testing.Target()\n"
            ),
            "tests/test_parameter_shadow.py": (
                "import pkg\n\n\ndef test_shadow(pkg):\n    pkg.testing.Target()\n"
            ),
            "tests/test_import_after_call.py": "pkg.testing.Target()\nimport pkg\n",
            "tests/test_noise.py": (
                '"""pkg.testing.Target()"""\n'
                "# pkg.testing.Target()\n"
                'text = "pkg.testing.Target()"\n'
            ),
            "tests/test_non_call.py": "import pkg\nvalue = pkg.testing.Target\n",
            "tests/test_getattr.py": ("import pkg\nvalue = getattr(pkg.testing, 'Target')()\n"),
            "tests/test_dynamic.py": (
                "import importlib\n"
                "module = importlib.import_module('pkg.testing')\n"
                "module.Target()\n"
            ),
            "tests/test_wildcard.py": "from pkg.testing import *\nTarget()\n",
            "tests/test_testing.py": "def test_unrelated():\n    assert True\n",
        },
    )
    return git_fixture


def analyze(fixture: GitFixture):
    return analyze_blast(
        repo=fixture.root,
        change="make a narrow Target change",
        target=Target(symbol="Target"),
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def direct_locations(result) -> set[tuple[str, str, int]]:
    return {
        (impact.impact_type, impact.path, impact.start_line)
        for impact in result.impacts
        if impact.impact_type in {"reference", "test"}
    }


def test_imported_package_prefix_and_alias_calls_are_direct(
    package_submodule_calls: GitFixture,
) -> None:
    result = analyze(package_submodule_calls)
    locations = direct_locations(result)

    assert ("reference", "src/package_call.py", 5) in locations
    assert ("reference", "src/package_alias_call.py", 5) in locations
    assert ("test", "tests/test_package_call.py", 5) in locations
    assert ("test", "tests/test_package_alias_call.py", 5) in locations
    assert ("test", "tests/test_local_import.py", 3) in locations
    assert result.blast_analysis is not None
    assert result.blast_analysis.direct_test_count == 8


def test_existing_module_and_symbol_binding_forms_remain_direct(
    package_submodule_calls: GitFixture,
) -> None:
    locations = direct_locations(analyze(package_submodule_calls))

    assert {
        ("test", "tests/test_full_module.py", 5),
        ("test", "tests/test_module_alias.py", 5),
        ("test", "tests/test_from_package.py", 5),
        ("test", "tests/test_from_module.py", 5),
    }.issubset(locations)


def test_package_chain_false_positives_are_not_direct(
    package_submodule_calls: GitFixture,
) -> None:
    direct_paths = {path for _, path, _ in direct_locations(analyze(package_submodule_calls))}

    assert direct_paths.isdisjoint(
        {
            "tests/test_wrong_submodule.py",
            "tests/test_wrong_symbol.py",
            "tests/test_unused_package.py",
            "tests/test_rebound_package.py",
            "tests/test_parameter_shadow.py",
            "tests/test_import_after_call.py",
            "tests/test_local_import_leak.py",
            "tests/test_noise.py",
            "tests/test_non_call.py",
            "tests/test_getattr.py",
            "tests/test_dynamic.py",
            "tests/test_wildcard.py",
            "tests/test_testing.py",
        }
    )


def test_package_chain_candidates_and_unresolved_cases_remain_bounded(
    package_submodule_calls: GitFixture,
) -> None:
    result = analyze(package_submodule_calls)
    assert result.blast_analysis is not None

    candidates = set(result.blast_analysis.candidate_tests)
    assert candidates == {
        "tests/test_dynamic.py",
        "tests/test_import_after_call.py",
        "tests/test_local_import_leak.py",
        "tests/test_non_call.py",
        "tests/test_parameter_shadow.py",
        "tests/test_rebound_package.py",
        "tests/test_testing.py",
        "tests/test_wildcard.py",
        "tests/test_wrong_submodule.py",
    }
    assert candidates.isdisjoint(
        {
            "tests/test_getattr.py",
            "tests/test_unused_package.py",
            "tests/test_wrong_symbol.py",
        }
    )
    assert any(item.code == "dynamic_import" for item in result.limitations)
    assert any(item.code == "wildcard_import" for item in result.limitations)


def test_same_line_package_calls_keep_distinct_columns_and_ids(
    package_submodule_calls: GitFixture,
) -> None:
    impacts = [
        item
        for item in analyze(package_submodule_calls).impacts
        if item.path == "tests/test_same_line.py" and item.impact_type == "test"
    ]

    assert len(impacts) == 2
    assert [item.start_column for item in impacts] == [5, 27]
    assert len({item.id for item in impacts}) == 2


def test_package_chain_output_is_deterministic_schema_valid_and_aligned(
    package_submodule_calls: GitFixture,
) -> None:
    first = analyze(package_submodule_calls)
    second = analyze(package_submodule_calls)
    payload = result_dict(first)
    markdown = render_markdown(first)

    assert render_json(first) == render_json(second)
    assert "Direct test: tests/test_package_call.py:5" in markdown
    assert payload["analysis_status"] == "partial"
    assert "Status: partial" in markdown
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_package_chain_analysis_is_read_only(package_submodule_calls: GitFixture) -> None:
    before = repository_digest(package_submodule_calls.root)
    analyze(package_submodule_calls)
    assert repository_digest(package_submodule_calls.root) == before


def test_defuse_inherits_package_chain_blast_without_execution(
    package_submodule_calls: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = repository_digest(package_submodule_calls.root)
    calls: list[list[str]] = []
    original = subprocess.run

    def recording(command, *args, **kwargs):
        calls.append([str(item) for item in command])
        return original(command, *args, **kwargs)

    monkeypatch.setattr("landmine.git.subprocess.run", recording)
    result = analyze_defuse(
        repo=package_submodule_calls.root,
        target=Target(symbol="Target"),
        goal="make a narrow Target change",
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )

    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert any(
        item.kind == "test_reference" and item.locator.get("path") == "tests/test_package_call.py"
        for item in result.evidence
    )
    assert calls
    assert all("pytest" not in command for command in calls)
    assert repository_digest(package_submodule_calls.root) == before

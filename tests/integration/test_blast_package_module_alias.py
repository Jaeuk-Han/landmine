from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from landmine.analyzers.blast import analyze_blast
from landmine.domain import Target
from landmine.renderers import render_json, render_markdown
from tests.conftest import GitFixture, repository_digest


@pytest.fixture
def package_module_alias(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "package_module_alias",
        "Add package module alias callers",
        {
            "src/pkg/__init__.py": "",
            "src/pkg/mod.py": "def target():\n    return 'target'\n",
            "src/pkg/other.py": "def other_symbol():\n    return 'other'\n",
            "src/prod_alias.py": (
                "from pkg import mod as alias\n\n\ndef call_target():\n    return alias.target()\n"
            ),
            "src/prod_plain.py": (
                "from pkg import mod\n\n\ndef call_target():\n    return mod.target()\n"
            ),
            "src/prod_wrong_symbol.py": (
                "from pkg import mod as alias\n\n\n"
                "def call_other():\n"
                "    return alias.other_symbol()\n"
            ),
            "src/prod_wrong_module.py": (
                "from pkg import other as alias\n\n\n"
                "def call_target():\n"
                "    return alias.target()\n"
            ),
            "src/prod_rebound.py": (
                "from pkg import mod as alias\n\nalias = replacement\nvalue = alias.target()\n"
            ),
            "src/prod_unused.py": "from pkg import mod as alias\n",
            "tests/test_alias.py": (
                "from pkg import mod as alias\n\n\n"
                "def test_target():\n"
                "    assert alias.target() == 'target'\n"
            ),
            "tests/test_plain.py": (
                "from pkg import mod\n\n\ndef test_target():\n    assert mod.target() == 'target'\n"
            ),
            "tests/test_wrong_symbol.py": (
                "from pkg import mod as alias\n\n\n"
                "def test_other():\n"
                "    assert alias.other_symbol() == 'other'\n"
            ),
            "tests/test_wrong_module.py": (
                "from pkg import other as alias\n\n\n"
                "def test_target():\n"
                "    assert alias.target() == 'target'\n"
            ),
            "tests/test_rebound.py": (
                "from pkg import mod as alias\n\n"
                "alias = replacement\n"
                "assert alias.target() == 'target'\n"
            ),
            "tests/test_unused.py": "from pkg import mod as alias\n",
            "tests/test_direct_symbol.py": (
                "from pkg.mod import target as direct_target\n\n\n"
                "def test_target():\n"
                "    assert direct_target() == 'target'\n"
            ),
        },
    )
    return git_fixture


def _result(fixture: GitFixture):
    return analyze_blast(
        repo=fixture.root,
        change="Narrow target behavior",
        target=Target(symbol="target"),
        clock=lambda: datetime(2026, 8, 4, tzinfo=UTC),
        monotonic=lambda: 100.0,
    )


def _direct_locations(result) -> set[tuple[str, str, int]]:
    return {(impact.impact_type, impact.path, impact.start_line) for impact in result.impacts}


def test_package_module_alias_and_plain_import_are_direct_references(
    package_module_alias: GitFixture,
) -> None:
    result = _result(package_module_alias)
    locations = _direct_locations(result)

    assert ("reference", "src/prod_alias.py", 5) in locations
    assert ("reference", "src/prod_plain.py", 5) in locations
    assert ("test", "tests/test_alias.py", 5) in locations
    assert ("test", "tests/test_plain.py", 5) in locations
    assert result.blast_analysis is not None
    assert result.blast_analysis.direct_test_count == 3

    import_locations = {
        (item.locator.get("path"), item.locator.get("start_line"))
        for item in result.evidence
        if item.kind == "import"
    }
    assert ("src/prod_alias.py", 1) in import_locations
    assert ("src/prod_plain.py", 1) in import_locations
    reference_locations = {
        (item.locator.get("path"), item.locator.get("start_line"))
        for item in result.evidence
        if item.kind in {"reference", "test_reference"}
    }
    assert ("src/prod_alias.py", 5) in reference_locations
    assert ("src/prod_plain.py", 5) in reference_locations
    assert ("tests/test_alias.py", 5) in reference_locations
    assert ("tests/test_plain.py", 5) in reference_locations


def test_package_module_alias_false_positives_are_not_direct_impacts(
    package_module_alias: GitFixture,
) -> None:
    direct_paths = {impact.path for impact in _result(package_module_alias).impacts}

    assert direct_paths.isdisjoint(
        {
            "src/prod_wrong_symbol.py",
            "src/prod_wrong_module.py",
            "src/prod_rebound.py",
            "src/prod_unused.py",
            "tests/test_wrong_symbol.py",
            "tests/test_wrong_module.py",
            "tests/test_rebound.py",
            "tests/test_unused.py",
        }
    )


def test_existing_direct_symbol_import_remains_direct(
    package_module_alias: GitFixture,
) -> None:
    result = _result(package_module_alias)

    assert ("test", "tests/test_direct_symbol.py", 5) in _direct_locations(result)


def test_package_module_alias_output_is_deterministic_and_semantically_aligned(
    package_module_alias: GitFixture,
) -> None:
    first = _result(package_module_alias)
    second = _result(package_module_alias)
    payload = json.loads(render_json(first))
    markdown = render_markdown(first)

    assert render_json(first) == render_json(second)
    direct_tests = [
        (item["path"], item["start_line"])
        for item in payload["impacts"]
        if item["impact_type"] == "test"
    ]
    assert direct_tests == [
        ("tests/test_alias.py", 5),
        ("tests/test_direct_symbol.py", 5),
        ("tests/test_plain.py", 5),
    ]
    for path, line in direct_tests:
        assert f"- Direct test: {path}:{line}" in markdown
    assert "3 direct test file(s)" in markdown


def test_package_module_alias_analysis_does_not_mutate_repository(
    package_module_alias: GitFixture,
) -> None:
    before = repository_digest(package_module_alias.root)

    _result(package_module_alias)

    assert repository_digest(package_module_alias.root) == before

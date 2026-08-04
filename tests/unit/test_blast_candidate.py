from __future__ import annotations

import ast

import pytest

from landmine.analyzers.blast import _candidate_test
from landmine.domain import BlastSubject

SUBJECT = BlastSubject(
    path="src/pkg/render.py",
    start_line=1,
    end_line=2,
    symbol="_first_text",
)


def candidate(path: str, source: str, *, imports_target: bool = False) -> bool:
    return _candidate_test(
        path,
        ast.parse(source),
        SUBJECT,
        imports_target=imports_target,
    )


@pytest.mark.parametrize("path", ["tests/test_render.py", "tests/render_test.py"])
def test_exact_module_aligned_filename_is_candidate(path: str) -> None:
    assert candidate(path, "def test_unrelated():\n    assert True\n")


def test_exact_private_symbol_name_is_candidate() -> None:
    assert candidate("tests/test_name.py", "def test_name(value):\n    return _first_text(value)\n")


def test_exact_private_symbol_attribute_is_candidate() -> None:
    assert candidate(
        "tests/test_attribute.py",
        "def test_attribute(subject):\n    return subject._first_text()\n",
    )


@pytest.mark.parametrize(
    "source",
    [
        "# _first_text render\ndef test_comment():\n    assert True\n",
        'def test_docstring():\n    """_first_text render"""\n    assert True\n',
        'def test_string():\n    assert "_first_text render"\n',
        "def test_module_substring():\n    return render_report()\n",
        "def test_symbol_substring():\n    return get_first_text()\n",
        "def test_private_symbol_suffix():\n    return _first_text_value()\n",
    ],
)
def test_weak_text_and_identifier_substrings_are_not_candidates(source: str) -> None:
    assert not candidate("tests/test_unrelated.py", source)


def test_unrelated_filename_substring_is_not_candidate() -> None:
    assert not candidate("tests/test_render_report.py", "def test_report():\n    assert True\n")


def test_exact_target_import_signal_is_candidate() -> None:
    assert candidate(
        "tests/test_import_only.py",
        "def test_imported_module():\n    assert True\n",
        imports_target=True,
    )

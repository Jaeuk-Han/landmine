from __future__ import annotations

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_non_empty_collection import PythonNonEmptyCollectionDetector


def detect(source: str):
    context = AnalysisContext(
        path="src/example.py",
        source=source,
        start_line=1,
        end_line=max(1, len(source.splitlines())),
    )
    return PythonNonEmptyCollectionDetector().detect(context)


def active(source: str):
    return [candidate for candidate in detect(source) if candidate.suppression_reason is None]


def suppressed(source: str):
    return [candidate for candidate in detect(source) if candidate.suppression_reason is not None]


def test_detects_unchecked_zero_index() -> None:
    candidate = active("def first(items):\n    return items[0]\n")[0]
    assert candidate.observed_signal == "zero_index"
    assert candidate.variable == "items"
    assert candidate.consequence == "IndexError"


def test_detects_unchecked_negative_index() -> None:
    candidate = active("def last(items):\n    return items[-1]\n")[0]
    assert candidate.observed_signal == "negative_index"
    assert candidate.variable == "items"


def test_detects_next_iter_without_guard() -> None:
    candidate = active("def first(items):\n    return next(iter(items))\n")[0]
    assert candidate.observed_signal == "next_iter"
    assert candidate.consequence == "StopIteration"


def test_detects_fixed_length_unpacking() -> None:
    candidate = active("def split(values):\n    head, tail = values\n    return head\n")[0]
    assert candidate.observed_signal == "fixed_length_unpack"
    assert candidate.variable == "values"
    assert candidate.consequence == "ValueError during unpacking"


def test_suppresses_truthy_guard() -> None:
    candidates = detect("def first(items):\n    if items:\n        return items[0]\n")
    assert not active("def first(items):\n    if items:\n        return items[0]\n")
    assert candidates[0].suppression_reason == "truthy_guard"


def test_suppresses_positive_length_guard() -> None:
    source = "def first(items):\n    if len(items) > 0:\n        return items[0]\n"
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "positive_length_guard"


def test_suppresses_early_return_guard() -> None:
    source = "def first(items):\n    if not items:\n        return None\n    return items[0]\n"
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_guard"


def test_suppresses_early_raise_guard() -> None:
    source = (
        "def first(items):\n"
        "    if not items:\n"
        '        raise ValueError("items required")\n'
        "    return items[0]\n"
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_guard"


def test_ignores_non_empty_literal() -> None:
    candidates = detect("def first():\n    return [1, 2, 3][0]\n")
    assert not active("def first():\n    return [1, 2, 3][0]\n")
    assert candidates[0].suppression_reason == "statically_non_empty"


def test_ignores_statically_non_empty_assignment() -> None:
    source = "def first():\n    items = [create_default()]\n    return items[0]\n"
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "statically_non_empty"

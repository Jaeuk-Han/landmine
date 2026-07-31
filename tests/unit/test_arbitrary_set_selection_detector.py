from __future__ import annotations

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_arbitrary_set_selection import (
    PythonArbitrarySetSelectionDetector,
)
from landmine.detectors.python_non_empty_collection import PythonNonEmptyCollectionDetector


def context(source: str) -> AnalysisContext:
    return AnalysisContext(
        path="src/selector.py",
        source=source,
        start_line=1,
        end_line=max(1, len(source.splitlines())),
    )


def detect(source: str):
    return PythonArbitrarySetSelectionDetector().detect(context(source))


def active(source: str):
    return [item for item in detect(source) if item.suppression_reason is None]


def test_detects_next_iter_on_typed_set() -> None:
    candidate = active("def choose(values: set[str]):\n    return next(iter(values))\n")[0]
    assert candidate.variable == "values"
    assert candidate.selection_operation == "next_iter"
    assert candidate.category.value == "ordering"


def test_detects_typing_set_annotation() -> None:
    candidates = active(
        "from typing import Set\ndef choose(values: Set[str]):\n    return next(iter(values))\n"
    )
    assert len(candidates) == 1


def test_detects_list_index_on_constructed_set() -> None:
    candidate = active("def choose(items):\n    values = set(items)\n    return list(values)[0]\n")[
        0
    ]
    assert candidate.selection_operation == "list_index_zero"


def test_detects_tuple_index_on_set_comprehension() -> None:
    candidate = active(
        "def choose(items):\n    values = {item for item in items}\n    return tuple(values)[0]\n"
    )[0]
    assert candidate.selection_operation == "tuple_index_zero"


def test_detects_first_return_from_set_loop() -> None:
    candidate = active(
        "def choose(values: set[str]):\n    for value in values:\n        return value\n"
    )[0]
    assert candidate.selection_operation == "for_first_return"


def test_detects_set_pop() -> None:
    candidate = active("def choose(values: set[str]):\n    return values.pop()\n")[0]
    assert candidate.selection_operation == "set_pop"
    assert "mutates" in candidate.consequence


def test_tracks_simple_set_alias() -> None:
    candidate = active(
        "def choose(items):\n"
        "    values = set(items)\n"
        "    aliases = values\n"
        "    return next(iter(aliases))\n"
    )[0]
    assert candidate.variable == "aliases"
    assert [item.role for item in candidate.provenance] == [
        "set_construction",
        "set_alias",
    ]


def test_rebinding_invalidates_set_provenance() -> None:
    assert (
        detect(
            "def choose(items):\n"
            "    values = set(items)\n"
            "    values = list(items)\n"
            "    return next(iter(values))\n"
        )
        == []
    )


def test_does_not_infer_untyped_iterable_as_set() -> None:
    assert detect("def choose(values):\n    return next(iter(values))\n") == []


def test_does_not_infer_custom_factory_as_set() -> None:
    assert (
        detect(
            "def choose(items):\n"
            "    values = custom_set_factory(items)\n"
            "    return next(iter(values))\n"
        )
        == []
    )


def test_does_not_confuse_dict_literal_with_set() -> None:
    assert (
        detect('def choose():\n    values = {"key": "value"}\n    return next(iter(values))\n')
        == []
    )


def test_ignores_single_element_set_literal() -> None:
    assert detect('def choose():\n    return next(iter({"only"}))\n') == []


def test_truthy_guard_does_not_suppress_ordering() -> None:
    source = "def choose(values: set[str]):\n    if values:\n        return next(iter(values))\n"
    assert len(active(source)) == 1


def test_non_empty_assert_does_not_suppress_ordering() -> None:
    source = "def choose(values: set[str]):\n    assert values\n    return values.pop()\n"
    assert len(active(source)) == 1


def test_sorted_selection_is_not_flagged() -> None:
    assert detect("def choose(values: set[str]):\n    return sorted(values)[0]\n") == []


def test_min_selection_is_not_flagged() -> None:
    assert detect("def choose(values: set[str]):\n    return min(values)\n") == []


def test_max_selection_is_not_flagged() -> None:
    assert detect("def choose(values: set[str]):\n    return max(values)\n") == []


def test_custom_key_tie_risk_is_not_silently_suppressed() -> None:
    candidate = active(
        "def choose(values: set[str], priority):\n    return sorted(values, key=priority)[0]\n"
    )[0]
    assert candidate.selection_operation == "sorted_custom_key_index"
    assert candidate.confidence < 0.7
    assert candidate.uncertainty_note is not None
    assert "ties" in candidate.uncertainty_note


def test_next_iter_can_emit_cardinality_and_ordering_findings() -> None:
    analysis_context = context("def choose(values: set[str]):\n    return next(iter(values))\n")
    detector_ids = {
        item.detector_id
        for detector in (
            PythonNonEmptyCollectionDetector(),
            PythonArbitrarySetSelectionDetector(),
        )
        for item in detector.detect(analysis_context)
        if item.suppression_reason is None
    }
    assert detector_ids == {
        "python.non-empty-collection",
        "python.arbitrary-set-selection",
    }


def test_nested_ast_does_not_duplicate_ordering_finding() -> None:
    candidates = active("def choose(items):\n    values = set(items)\n    return list(values)[0]\n")
    assert len(candidates) == 1

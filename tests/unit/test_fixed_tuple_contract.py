from __future__ import annotations

import pytest

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_non_empty_collection import (
    PythonNonEmptyCollectionDetector,
)

FIXED_TUPLE_REASON = (
    "The inner access is covered by an explicit fixed-length tuple element contract."
)


def detect(source: str):
    return PythonNonEmptyCollectionDetector().detect(
        AnalysisContext(
            path="src/example.py",
            source=source,
            start_line=1,
            end_line=max(1, len(source.splitlines())),
        )
    )


def active_variables(source: str) -> list[str]:
    return [item.variable for item in detect(source) if item.suppression_reason is None]


def fixed_tuple_suppressions(source: str):
    return [item for item in detect(source) if item.suppression_reason == FIXED_TUPLE_REASON]


def source_for(
    annotation: str,
    expression: str = "helper()",
    access: str = "items and items[0][0]",
    *,
    imports: str = "",
) -> str:
    return (
        imports
        + f"def helper() -> {annotation}:\n"
        + "    return []\n\n"
        + "def use(condition=True, index=0):\n"
        + f"    items = {expression}\n"
        + f"    return {access}\n"
    )


def test_direct_fixed_tuple_helper_suppresses_inner_access_only() -> None:
    candidates = detect(source_for("list[tuple[int, str]]"))

    assert [(item.variable, item.suppression_reason) for item in candidates] == [
        ("items", "short_circuit_guard"),
        ("items[0]", FIXED_TUPLE_REASON),
    ]


def test_conditional_empty_list_preserves_fixed_tuple_provenance() -> None:
    source = source_for(
        "list[tuple[int, str]]",
        "helper() if condition else []",
    )

    assert active_variables(source) == []
    assert len(fixed_tuple_suppressions(source)) == 1


def test_conditional_non_list_empty_branch_is_not_supported() -> None:
    source = source_for(
        "list[tuple[int, str]]",
        "helper() if condition else ()",
    )

    assert "items[0]" in active_variables(source)


@pytest.mark.parametrize("index", ["0", "1", "-1", "-2"])
def test_all_in_range_fixed_tuple_indexes_are_suppressed(index: str) -> None:
    source = source_for(
        "list[tuple[int, str]]",
        access=f"items and items[0][{index}]",
    )

    assert active_variables(source) == []
    assert len(fixed_tuple_suppressions(source)) == 1


def test_arity_three_accepts_its_last_index() -> None:
    source = source_for(
        "list[tuple[int, str, bytes]]",
        access="items and items[0][2]",
    )

    assert active_variables(source) == []
    assert len(fixed_tuple_suppressions(source)) == 1


def test_unguarded_outer_collection_remains_active() -> None:
    source = source_for("list[tuple[int, str]]", access="items[0][0]")

    assert active_variables(source) == ["items"]
    assert [item.variable for item in fixed_tuple_suppressions(source)] == ["items[0]"]


@pytest.mark.parametrize(
    "annotation",
    [
        "list[list[int]]",
        "list[tuple[int, ...]]",
        "Sequence[tuple[int, str]]",
        "Any",
        "Custom[tuple[int, str]]",
        "Alias",
        "'list[tuple[int, str]]'",
        "list[tuple[int, str]] | None",
    ],
)
def test_unproven_or_non_fixed_annotations_do_not_suppress(annotation: str) -> None:
    source = source_for(annotation)

    assert "items[0]" in active_variables(source)
    assert fixed_tuple_suppressions(source) == []


@pytest.mark.parametrize(
    ("imports", "annotation"),
    [
        ("import typing\n\n", "typing.List[typing.Tuple[int, str]]"),
        ("import typing as t\n\n", "t.List[t.Tuple[int, str]]"),
        ("from typing import List as L, Tuple as T\n\n", "L[T[int, str]]"),
    ],
)
def test_proven_typing_imports_and_aliases_are_supported(imports: str, annotation: str) -> None:
    source = source_for(annotation, imports=imports)

    assert active_variables(source) == []
    assert len(fixed_tuple_suppressions(source)) == 1


def test_unimported_typing_names_are_not_treated_as_proven() -> None:
    source = source_for("typing.List[typing.Tuple[int, str]]")

    assert "items[0]" in active_variables(source)


@pytest.mark.parametrize(
    "body",
    [
        "    helper = replacement\n    items = helper()\n",
        "    items = helper()\n    items = replacement\n",
        "    items = helper()\n    mutate(items)\n",
        "    items = helper()\n    alias = items\n    alias.clear()\n",
        "    items = helper()\n    items[0] = replacement\n",
    ],
)
def test_rebinding_reassignment_and_mutation_invalidate_provenance(body: str) -> None:
    source = (
        "def helper() -> list[tuple[int, str]]:\n"
        "    return []\n\n"
        "def use(replacement):\n"
        f"{body}"
        "    return items and items[0][0]\n"
    )

    assert "items[0]" in active_variables(source)
    assert fixed_tuple_suppressions(source) == []


def test_parameter_shadowing_prevents_helper_provenance() -> None:
    source = (
        "def helper() -> list[tuple[int, str]]:\n"
        "    return []\n\n"
        "def use(helper):\n"
        "    items = helper()\n"
        "    return items and items[0][0]\n"
    )

    assert "items[0]" in active_variables(source)


def test_imported_and_attribute_helpers_are_not_same_module_direct_calls() -> None:
    source = (
        "from package import helper\n\n"
        "def use():\n"
        "    imported = helper()\n"
        "    dynamic = module.helper()\n"
        "    return (imported and imported[0][0], dynamic and dynamic[0][0])\n"
    )

    assert active_variables(source) == ["imported[0]", "dynamic[0]"]


def test_async_helper_is_not_treated_as_a_direct_list_result() -> None:
    source = (
        "async def helper() -> list[tuple[int, str]]:\n"
        "    return []\n\n"
        "def use():\n"
        "    items = helper()\n"
        "    return items and items[0][0]\n"
    )

    assert "items[0]" in active_variables(source)


@pytest.mark.parametrize("index", ["index", "0:1", "2", "-3"])
def test_dynamic_slice_and_out_of_range_indexes_are_not_contract_suppressed(
    index: str,
) -> None:
    source = source_for(
        "list[tuple[int, str]]",
        access=f"items and items[0][{index}]",
    )

    assert fixed_tuple_suppressions(source) == []


def test_module_level_helper_rebinding_prevents_provenance() -> None:
    source = (
        "def helper() -> list[tuple[int, str]]:\n"
        "    return []\n\n"
        "helper = replacement\n\n"
        "def use():\n"
        "    items = helper()\n"
        "    return items and items[0][0]\n"
    )

    assert "items[0]" in active_variables(source)


def test_existing_literal_tuple_and_short_circuit_behavior_is_unchanged() -> None:
    source = (
        "def use(items):\n"
        "    literal = [(1, 2)][0][0]\n"
        "    guarded = items and items[0]\n"
        "    return literal, guarded\n"
    )

    assert active_variables(source) == ["[(1, 2)][0]"]
    assert [(item.variable, item.suppression_reason) for item in detect(source)] == [
        ("[(1, 2)]", "statically_non_empty"),
        ("[(1, 2)][0]", None),
        ("items", "short_circuit_guard"),
    ]


def test_candidate_order_and_suppression_are_deterministic() -> None:
    source = source_for("list[tuple[int, str]]")

    assert detect(source) == detect(source)

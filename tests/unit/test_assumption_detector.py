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


def test_suppresses_terminating_continue_guard() -> None:
    source = (
        "def first(groups):\n"
        "    for items in groups:\n"
        "        if not items:\n"
        "            continue\n"
        "        return items[0]\n"
    )

    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_guard"


def test_suppresses_terminating_break_guard_only_inside_loop_body() -> None:
    source = (
        "def first(groups):\n"
        "    for items in groups:\n"
        "        if not items:\n"
        "            break\n"
        "        value = items[0]\n"
        "    return items[0]\n"
    )

    candidates = detect(source)

    assert [(item.line, item.suppression_reason) for item in candidates] == [
        (5, "early_exit_guard"),
        (6, None),
    ]


def test_suppresses_or_guard_when_terminating_branch_implies_non_empty() -> None:
    source = (
        "def first(groups, condition):\n"
        "    for items in groups:\n"
        "        if not items or condition:\n"
        "            continue\n"
        "        return items[0]\n"
    )

    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_guard"


def test_non_terminating_negative_guard_keeps_finding() -> None:
    source = "def first(items):\n    if not items:\n        pass\n    return items[0]\n"

    assert active(source)[0].variable == "items"


def test_collection_mutation_after_guard_keeps_finding() -> None:
    source = (
        "def first(groups):\n"
        "    for items in groups:\n"
        "        if not items:\n"
        "            continue\n"
        "        items.clear()\n"
        "        return items[0]\n"
    )

    assert active(source)[0].variable == "items"


def test_conditional_reassignment_after_guard_keeps_finding() -> None:
    source = (
        "def first(items, condition):\n"
        "    if not items:\n"
        "        return None\n"
        "    if condition:\n"
        "        items = []\n"
        "    return items[0]\n"
    )

    assert active(source)[0].variable == "items"


def test_alias_mutation_after_guard_keeps_finding() -> None:
    source = (
        "def first(items):\n"
        "    alias = items\n"
        "    if not items:\n"
        "        return None\n"
        "    alias.clear()\n"
        "    return items[0]\n"
    )

    assert active(source)[0].variable == "items"


def test_suppresses_same_collection_in_and_rhs() -> None:
    source = "def first(items):\n    return items and items[0]\n"

    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "short_circuit_guard"


def test_suppresses_same_collection_nested_in_and_rhs() -> None:
    source = (
        "def first(condition, items):\n    return condition or (items and predicate(items[0]))\n"
    )

    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "short_circuit_guard"


def test_or_does_not_protect_rhs_access() -> None:
    source = "def first(items):\n    return items or items[0]\n"

    assert active(source)[0].variable == "items"


def test_negative_and_guard_does_not_protect_rhs_access() -> None:
    source = "def first(items):\n    return not items and items[0]\n"

    assert active(source)[0].variable == "items"


def test_guard_for_other_collection_does_not_protect_access() -> None:
    source = "def first(items, other):\n    return items and other[0]\n"

    assert active(source)[0].variable == "other"


def test_predicate_call_does_not_protect_another_collection() -> None:
    source = "def first(items, other):\n    return predicate(items) and other[0]\n"

    assert active(source)[0].variable == "other"


def test_suppresses_fold_lines_element_provenance() -> None:
    source = (
        "def fold_lines(text):\n"
        "    out = []\n"
        "    for raw in text.splitlines():\n"
        "        if not raw.strip():\n"
        "            continue\n"
        "        line = raw.rstrip()\n"
        "        if not out or predicate(line):\n"
        "            out.append(line)\n"
        "            continue\n"
        "        prev = out[-1]\n"
        "        if prev[-1].isdigit():\n"
        "            out.append(line)\n"
        "            continue\n"
        "        out[-1] = prev + line.strip()\n"
        "    return out\n"
    )

    candidates = detect(source)

    assert not active(source)
    assert [(item.variable, item.suppression_reason) for item in candidates] == [
        ("out", "early_exit_guard"),
        ("prev", "nonempty_element_provenance"),
    ]


def test_maybe_empty_appended_element_keeps_derived_finding() -> None:
    source = (
        "def last(maybe_empty):\n"
        "    items = []\n"
        "    items.append(maybe_empty)\n"
        "    value = items[-1]\n"
        "    return value[-1]\n"
    )

    assert [(item.variable, item.suppression_reason) for item in detect(source)] == [
        ("items", "statically_non_empty"),
        ("value", None),
    ]


def test_non_terminating_strip_guard_keeps_string_finding() -> None:
    source = (
        "def last(raw):\n"
        "    if not raw.strip():\n"
        "        pass\n"
        "    line = raw.rstrip()\n"
        "    return line[-1]\n"
    )

    assert active(source)[0].variable == "line"


def test_reassigned_derived_element_keeps_finding() -> None:
    source = (
        "def last(text, replacement):\n"
        "    out = []\n"
        "    for raw in text.splitlines():\n"
        "        if not raw.strip():\n"
        "            continue\n"
        "        line = raw.rstrip()\n"
        "        out.append(line)\n"
        "        prev = out[-1]\n"
        "        prev = replacement\n"
        "        return prev[-1]\n"
    )

    candidates = detect(source)

    assert candidates[-1].variable == "prev"
    assert candidates[-1].suppression_reason is None


def test_nested_subscript_only_suppresses_proven_collection() -> None:
    source = (
        "def first(condition, children):\n    return condition or (children and children[0][0])\n"
    )

    candidates = detect(source)

    assert [(item.variable, item.suppression_reason) for item in candidates] == [
        ("children", "short_circuit_guard"),
        ("children[0]", None),
    ]


def test_control_flow_finding_order_is_deterministic() -> None:
    source = (
        "def first(items, other):\n"
        "    left = items and items[0]\n"
        "    right = other or other[-1]\n"
        "    return left, right\n"
    )

    assert detect(source) == detect(source)

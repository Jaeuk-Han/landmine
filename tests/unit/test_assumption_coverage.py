from __future__ import annotations

import pytest

from landmine.analyzers.assumptions import _coverage, _target_scope
from landmine.domain import Target


def test_bounded_coverage_is_deterministic_and_limits_risk_interpretation() -> None:
    coverage = _coverage(status="bounded", category=None, target_scope="symbol")

    assert coverage.status == "bounded"
    assert coverage.requested_category == "all"
    assert coverage.runtime_execution is False
    assert coverage.risk_basis == "signals observed by evaluated detectors only"
    assert coverage.not_established == (
        "absence of unsupported assumption types",
        "runtime behavior or safety",
        "external library behavior",
        "interprocedural behavior",
    )


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (Target(path="src/example.py"), "file"),
        (Target(path="src/example.py", start_line=2, end_line=4), "line_range"),
        (Target(symbol="example"), "symbol"),
    ],
)
def test_requested_target_scope_is_preserved(target: Target, expected: str) -> None:
    assert _target_scope(target) == expected

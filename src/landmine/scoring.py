"""Deterministic risk scoring over explicit signals."""

from __future__ import annotations

from landmine.domain import Risk, ScoreComponent

_WEIGHTS = {
    "coupling": 0.25,
    "history": 0.20,
    "test_gap": 0.20,
    "contract_surface": 0.15,
    "operational": 0.10,
    "uncertainty": 0.10,
}


def score_why(*, commit_count: int, related_test_count: int, shallow: bool) -> Risk:
    """Score the bounded why evidence without deriving values from prose."""
    values = {
        "coupling": min(48, related_test_count * 8),
        "history": min(100, commit_count * 8),
        "test_gap": 10 if related_test_count else 80,
        "contract_surface": 0,
        "operational": 0,
        "uncertainty": min(100, 15 + (35 if shallow else 0)),
    }
    signals = {
        "coupling": ("related_tests",) if related_test_count else (),
        "history": ("target_commits",) if commit_count else (),
        "test_gap": ("related_test_found",) if related_test_count else ("missing_related_test",),
        "contract_surface": (),
        "operational": (),
        "uncertainty": ("unsupported_language",) + (("shallow_history",) if shallow else ()),
    }
    components = {
        name: ScoreComponent(values[name], weight, signals[name])
        for name, weight in _WEIGHTS.items()
    }
    total = round(sum(component.value * component.weight for component in components.values()))
    if total >= 75:
        grade = "critical"
    elif total >= 50:
        grade = "high"
    elif total >= 25:
        grade = "moderate"
    else:
        grade = "low"
    return Risk(score=total, grade=grade, components=components)


def score_assumptions(
    *,
    finding_count: int,
    protected_count: int,
    unknown_protection_count: int,
    limitation_count: int,
) -> Risk:
    """Score explicit assumption signals without treating missing data as safety."""
    unprotected_count = max(0, finding_count - protected_count - unknown_protection_count)
    values = {
        "coupling": 0,
        "history": 0,
        "test_gap": (
            80
            if unprotected_count
            else 55
            if unknown_protection_count
            else 10
            if protected_count
            else 30
        ),
        "contract_surface": min(100, finding_count * 15),
        "operational": 0,
        "uncertainty": min(100, 20 + limitation_count * 15),
    }
    signals = {
        "coupling": (),
        "history": (),
        "test_gap": (
            ("unprotected_assumption",)
            if unprotected_count
            else ("unknown_test_protection",)
            if unknown_protection_count
            else ("explicit_empty_input_test",)
            if protected_count
            else ("no_detector_signal",)
        ),
        "contract_surface": ("data_cardinality_assumption",) if finding_count else (),
        "operational": (),
        "uncertainty": ("static_analysis_only",)
        + (("analysis_limitation",) if limitation_count else ()),
    }
    components = {
        name: ScoreComponent(values[name], weight, signals[name])
        for name, weight in _WEIGHTS.items()
    }
    total = round(sum(component.value * component.weight for component in components.values()))
    if total >= 75:
        grade = "critical"
    elif total >= 50:
        grade = "high"
    elif total >= 25:
        grade = "moderate"
    else:
        grade = "low"
    return Risk(score=total, grade=grade, components=components)

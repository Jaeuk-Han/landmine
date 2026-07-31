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

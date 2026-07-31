"""Detector contracts and immutable candidates for assumption analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from landmine.domain import AssumptionCategory


@dataclass(frozen=True)
class AnalysisContext:
    path: str
    source: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class ProvenanceObservation:
    role: str
    line: int
    end_line: int
    column: int
    expression: str


@dataclass(frozen=True)
class AssumptionCandidate:
    detector_id: str
    category: AssumptionCategory
    path: str
    line: int
    end_line: int
    column: int
    observed_signal: str
    variable: str
    claim: str
    violation_scenario: str
    consequence: str
    confidence: float
    confidence_ceiling: float
    scope: str | None = None
    suppression_reason: str | None = None
    required_key: str | None = None
    limitation_reason: str | None = None
    http_library: str | None = None
    http_method: str | None = None
    provenance: tuple[ProvenanceObservation, ...] = ()
    selection_operation: str | None = None
    suggested_alternatives: tuple[str, ...] = ()
    uncertainty_note: str | None = None


class AssumptionDetector(Protocol):
    detector_id: str
    category: AssumptionCategory

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        """Return deterministic active and explicitly suppressed candidates."""
        ...

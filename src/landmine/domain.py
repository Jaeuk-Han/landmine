"""Immutable domain objects for the stable v1 result contract."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AnalysisStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class ClaimStatus(StrEnum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class Impact(StrEnum):
    DIRECT = "direct"
    BEHAVIORAL = "behavioral"
    OPERATIONAL = "operational"
    UNKNOWN = "unknown"


class AssumptionCategory(StrEnum):
    DATA = "data"


class ProtectionStatus(StrEnum):
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Target:
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    symbol: str | None = None


@dataclass(frozen=True)
class SymbolCandidate:
    path: str
    line: int
    matching_text: str
    match_kind: str


@dataclass(frozen=True)
class ErrorDetail:
    code: str
    message: str
    candidates: tuple[SymbolCandidate, ...] = ()


@dataclass(frozen=True)
class EvolutionCommit:
    commit: str
    timestamp: str
    subject: str
    path: str
    start_line: int
    end_line: int
    roles: tuple[str, ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class AssumptionDetail:
    detector_id: str
    category: AssumptionCategory
    observed_signal: str
    violation_scenario: str
    consequence: str
    confidence_ceiling: float
    protection: ProtectionStatus
    candidate_tests: tuple[str, ...] = ()
    uncertainty: str | None = None
    scope: str | None = None
    base_expression: str | None = None
    required_key: str | None = None


@dataclass(frozen=True)
class AssumptionAnalysis:
    detectors_run: tuple[str, ...]
    categories_scanned: tuple[AssumptionCategory, ...]
    suppression_count: int


@dataclass(frozen=True)
class RepositoryState:
    root: str
    head: str
    dirty: bool
    shallow: bool
    base: str | None = None


@dataclass(frozen=True)
class Evidence:
    id: str
    kind: str
    locator: dict[str, Any]
    excerpt_sha256: str
    observed_at: str
    excerpt: str | None = None
    command: str | None = None


@dataclass(frozen=True)
class Finding:
    id: str
    type: str
    title: str
    claim: str
    status: ClaimStatus
    confidence: float
    evidence_ids: tuple[str, ...]
    impact: Impact = Impact.UNKNOWN
    tags: tuple[str, ...] = ()
    assumption: AssumptionDetail | None = None


@dataclass(frozen=True)
class ScoreComponent:
    value: int
    weight: float
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class Risk:
    score: int
    grade: str
    components: dict[str, ScoreComponent]


@dataclass(frozen=True)
class Limitation:
    code: str
    message: str
    affected: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    preconditions: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()
    steps: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    rollback_triggers: tuple[str, ...] = ()


@dataclass(frozen=True)
class Metrics:
    elapsed_ms: int
    files_scanned: int
    commits_scanned: int
    evidence_count: int


@dataclass(frozen=True)
class Result:
    schema_version: str
    analysis_id: str
    analysis_status: AnalysisStatus
    command: str
    generated_at: str
    repository: RepositoryState
    request: dict[str, Any]
    summary: str
    risk: Risk
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    plan: Plan = field(default_factory=Plan)
    limitations: tuple[Limitation, ...] = ()
    metrics: Metrics = field(default_factory=lambda: Metrics(0, 0, 0, 0))
    error: ErrorDetail | None = None
    evolution: tuple[EvolutionCommit, ...] = ()
    assumption_analysis: AssumptionAnalysis | None = None

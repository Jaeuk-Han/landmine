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
    ENVIRONMENT = "environment"
    EXTERNAL_CONTRACT = "external_contract"
    ORDERING = "ordering"
    FILESYSTEM = "filesystem"
    TIME = "time"


class ProtectionStatus(StrEnum):
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    UNKNOWN = "unknown"


class BlastImpactStatus(StrEnum):
    DIRECT = "direct"
    INFERRED = "inferred"


class PlanItemStatus(StrEnum):
    PROPOSED = "proposed"
    BLOCKED = "blocked"
    NOT_EVALUATED = "not_evaluated"


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
    http_library: str | None = None
    http_method: str | None = None
    selection_operation: str | None = None
    suggested_alternatives: tuple[str, ...] = ()
    path_literal: str | None = None
    access_operation: str | None = None
    api_binding: str | None = None
    path_anchor: str | None = None
    clock_source: str | None = None
    clock_unit: str | None = None
    time_operation: str | None = None


@dataclass(frozen=True)
class AssumptionCoverage:
    status: str
    requested_category: str
    target_scope: str
    method: str
    runtime_execution: bool
    risk_basis: str
    not_established: tuple[str, ...]


@dataclass(frozen=True)
class AssumptionAnalysis:
    detectors_run: tuple[str, ...]
    categories_scanned: tuple[AssumptionCategory, ...]
    suppression_count: int
    coverage: AssumptionCoverage | None = None


@dataclass(frozen=True)
class BlastSubject:
    path: str
    start_line: int
    end_line: int
    symbol: str | None = None


@dataclass(frozen=True)
class BlastImpact:
    id: str
    impact_type: str
    path: str
    start_line: int
    end_line: int
    symbol: str | None
    status: BlastImpactStatus
    confidence: float
    evidence_ids: tuple[str, ...]
    path_from_target: tuple[str, ...]
    reason: str
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class BlastAnalysis:
    scope: str
    supported_depth: int
    subject: BlastSubject
    impact_count: int
    direct_test_count: int
    candidate_test_count: int
    candidate_tests: tuple[str, ...]
    not_evaluated: tuple[str, ...]


@dataclass(frozen=True)
class PrerequisiteSummary:
    command: str
    analysis_id: str
    status: AnalysisStatus
    risk_score: int
    finding_count: int
    evidence_count: int


@dataclass(frozen=True)
class DefuseAnalysis:
    prerequisites: tuple[PrerequisiteSummary, ...]
    snapshot_head: str
    snapshot_dirty: bool
    repository_state_stable: bool


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
class PlanItem:
    id: str
    kind: str
    description: str
    status: PlanItemStatus
    evidence_ids: tuple[str, ...] = ()
    related_finding_ids: tuple[str, ...] = ()
    target_paths: tuple[str, ...] = ()
    command_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class Plan:
    preconditions: tuple[PlanItem, ...] = ()
    tests: tuple[PlanItem, ...] = ()
    steps: tuple[PlanItem, ...] = ()
    verification: tuple[PlanItem, ...] = ()
    rollback_triggers: tuple[PlanItem, ...] = ()
    unknowns: tuple[PlanItem, ...] = ()


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
    blast_analysis: BlastAnalysis | None = None
    impacts: tuple[BlastImpact, ...] = ()
    defuse_analysis: DefuseAnalysis | None = None

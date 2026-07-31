"""Stable JSON and readable Markdown renderers."""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from typing import Any

from landmine.domain import Result


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {
            field.name: _primitive(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, dict):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_primitive(item) for item in value]
    return value


def result_dict(result: Result) -> dict[str, Any]:
    """Return the explicit primitive representation of a result."""
    value = _primitive(result)
    if not isinstance(value, dict):
        raise TypeError("result serialization did not produce an object")
    if value.get("error") is None:
        del value["error"]
    if not value.get("evolution"):
        del value["evolution"]
    if value.get("assumption_analysis") is None:
        del value["assumption_analysis"]
    for finding in value.get("findings", []):
        if finding.get("assumption") is None:
            del finding["assumption"]
        else:
            assumption = finding["assumption"]
            if assumption.get("base_expression") is None:
                del assumption["base_expression"]
            if assumption.get("required_key") is None:
                del assumption["required_key"]
    return value


def render_json(result: Result) -> str:
    """Serialize canonical v1 JSON."""
    return json.dumps(result_dict(result), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render_markdown(result: Result) -> str:
    """Render the v1 section order without discovering or changing evidence."""
    if result.error is not None:
        lines = [
            f"# Landmine: {result.command}",
            "",
            "## Error",
            "",
            f"`{result.error.code}`: {result.error.message}",
            "",
            "## Candidates",
            "",
        ]
        if result.error.candidates:
            for candidate in result.error.candidates:
                lines.append(
                    f"- [{candidate.match_kind}] {candidate.path}:{candidate.line} "
                    f"{candidate.matching_text!r}"
                )
        else:
            lines.append("- No candidates found.")
        lines.append("")
        return "\n".join(lines)
    lines = [
        f"# Landmine: {result.command}",
        "",
        "## Summary",
        "",
        result.summary,
        "",
        "## Risk",
        "",
        f"- Score: {result.risk.score}/100 ({result.risk.grade})",
        "",
        "## Findings",
        "",
    ]
    for finding in result.findings:
        evidence = ", ".join(finding.evidence_ids) or "none"
        lines.extend(
            [
                f"### {finding.title}",
                "",
                f"- Status: {finding.status.value} ({finding.confidence:.2f})",
                f"- Claim: {finding.claim}",
                f"- Evidence: {evidence}",
            ]
        )
        if finding.assumption is not None:
            detail = finding.assumption
            candidate_tests = ", ".join(detail.candidate_tests) or "none"
            lines.extend(
                [
                    f"- Detector: `{detail.detector_id}`",
                    f"- Category: {detail.category.value}",
                    f"- Signal: {detail.observed_signal}",
                    *(
                        [
                            f"- Base expression: `{detail.base_expression}`",
                            f"- Required key: {detail.required_key!r}",
                        ]
                        if detail.required_key is not None
                        else []
                    ),
                    f"- Violation: {detail.violation_scenario}",
                    f"- Consequence: {detail.consequence}",
                    f"- Confidence ceiling: {detail.confidence_ceiling:.2f}",
                    f"- Protection: {detail.protection.value}",
                    f"- Candidate tests: {candidate_tests}",
                    f"- Uncertainty: {detail.uncertainty or 'none recorded'}",
                ]
            )
            if detail.detector_id == "python.required-mapping-key":
                lines.append(
                    "- Protection meaning: protected = missing-key behavior is explicitly "
                    "tested; production exception handling is not implied."
                )
        lines.append("")
    if result.evolution:
        lines.extend(["## Evolution timeline", ""])
        for entry in result.evolution:
            roles = ", ".join(entry.roles)
            lines.append(
                f"- `{entry.timestamp}` `{entry.commit[:12]}` ({roles}) "
                f"{entry.path}:{entry.start_line}-{entry.end_line} - "
                f"subject (untrusted): {entry.subject!r}"
            )
        lines.append("")
    if result.assumption_analysis is not None:
        lines.extend(
            [
                "## Detector coverage",
                "",
                "- Detectors run: "
                + ", ".join(f"`{item}`" for item in result.assumption_analysis.detectors_run),
                "- Categories scanned: "
                + ", ".join(item.value for item in result.assumption_analysis.categories_scanned),
                f"- Suppression count: {result.assumption_analysis.suppression_count}",
                "",
            ]
        )
    lines.extend(["## Evidence", ""])
    for item in result.evidence:
        locator = ", ".join(f"{key}={value}" for key, value in sorted(item.locator.items()))
        lines.append(f"- `{item.id}` [{item.kind}] {locator}")
        if item.excerpt:
            lines.append(f"  - Excerpt (untrusted data): {item.excerpt!r}")
    lines.extend(["", "## Limitations", ""])
    if result.limitations:
        for limitation in result.limitations:
            lines.append(f"- `{limitation.code}`: {limitation.message}")
    else:
        lines.append("- None recorded.")
    lines.extend(
        [
            "",
            "## Analysis metadata",
            "",
            f"- Status: {result.analysis_status.value}",
            f"- HEAD: `{result.repository.head}`",
            f"- Dirty worktree: {str(result.repository.dirty).lower()}",
            f"- Shallow repository: {str(result.repository.shallow).lower()}",
            f"- Evidence count: {result.metrics.evidence_count}",
            "",
        ]
    )
    return "\n".join(lines)

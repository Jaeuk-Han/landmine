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
    if value.get("blast_analysis") is None:
        del value["blast_analysis"]
    if result.command != "blast":
        del value["impacts"]
    for finding in value.get("findings", []):
        if finding.get("assumption") is None:
            del finding["assumption"]
        else:
            assumption = finding["assumption"]
            if assumption.get("base_expression") is None:
                del assumption["base_expression"]
            if assumption.get("required_key") is None:
                del assumption["required_key"]
            if assumption.get("http_library") is None:
                del assumption["http_library"]
            if assumption.get("http_method") is None:
                del assumption["http_method"]
            if assumption.get("selection_operation") is None:
                del assumption["selection_operation"]
            if not assumption.get("suggested_alternatives"):
                del assumption["suggested_alternatives"]
            if assumption.get("path_literal") is None:
                del assumption["path_literal"]
            if assumption.get("access_operation") is None:
                del assumption["access_operation"]
            if assumption.get("api_binding") is None:
                del assumption["api_binding"]
            if assumption.get("path_anchor") is None:
                del assumption["path_anchor"]
            if assumption.get("clock_source") is None:
                del assumption["clock_source"]
            if assumption.get("clock_unit") is None:
                del assumption["clock_unit"]
            if assumption.get("time_operation") is None:
                del assumption["time_operation"]
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
    if result.command == "blast":
        return _render_blast_markdown(result)
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
                    *(
                        [
                            f"- HTTP library: `{detail.http_library}`",
                            f"- HTTP method: `{detail.http_method}`",
                        ]
                        if detail.http_library is not None and detail.http_method is not None
                        else []
                    ),
                    *(
                        [f"- Selection operation: `{detail.selection_operation}`"]
                        if detail.selection_operation is not None
                        else []
                    ),
                    *(
                        [
                            f"- Relative path: `{detail.path_literal}`",
                            f"- Access operation: `{detail.access_operation}`",
                            f"- API binding: `{detail.api_binding}`",
                        ]
                        if detail.path_literal is not None
                        and detail.access_operation is not None
                        and detail.api_binding is not None
                        else []
                    ),
                    *(
                        [
                            f"- Clock source: `{detail.clock_source}`",
                            f"- Clock unit: `{detail.clock_unit}`",
                            f"- Time operation: `{detail.time_operation}`",
                        ]
                        if detail.clock_source is not None
                        and detail.clock_unit is not None
                        and detail.time_operation is not None
                        else []
                    ),
                    f"- Violation: {detail.violation_scenario}",
                    f"- Consequence: {detail.consequence}",
                    f"- Confidence ceiling: {detail.confidence_ceiling:.2f}",
                    f"- Protection: {detail.protection.value}",
                    f"- Candidate tests: {candidate_tests}",
                    f"- Uncertainty: {detail.uncertainty or 'none recorded'}",
                    *(
                        [
                            (
                                "- Suggested explicit anchors: "
                                if detail.detector_id == "python.cwd-relative-file-access"
                                else (
                                    "- Suggested monotonic alternatives: "
                                    if detail.detector_id == "python.wall-clock-elapsed-time"
                                    else "- Suggested deterministic alternatives: "
                                )
                            )
                            + ", ".join(
                                f"`{alternative}`" for alternative in detail.suggested_alternatives
                            ),
                            (
                                "- Alternative note: choose only an option whose semantics "
                                "match the application; Landmine does not infer that rule."
                            ),
                        ]
                        if detail.suggested_alternatives
                        else []
                    ),
                ]
            )
            if detail.detector_id == "python.required-mapping-key":
                lines.append(
                    "- Protection meaning: protected = missing-key behavior is explicitly "
                    "tested; production exception handling is not implied."
                )
            elif detail.detector_id == "python.required-environment-variable":
                lines.append(
                    "- Protection meaning: protected = missing-variable behavior is "
                    "explicitly tested; production exception handling is not implied."
                )
            elif detail.detector_id == "python.required-response-field":
                lines.append(
                    "- Protection meaning: protected = missing-field external response "
                    "behavior is explicitly characterized; production schema-drift "
                    "handling is not implied."
                )
            elif detail.detector_id == "python.cwd-relative-file-access":
                lines.append(
                    "- Protection meaning: protected = working-directory-dependent "
                    "behavior is explicitly characterized; safety from arbitrary working "
                    "directories is not implied."
                )
            elif detail.detector_id == "python.wall-clock-elapsed-time":
                lines.append(
                    "- Protection meaning: protected = wall-clock adjustment behavior "
                    "is explicitly characterized; safe production handling is not implied."
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


def _render_blast_markdown(result: Result) -> str:
    analysis = result.blast_analysis
    if analysis is None:
        raise ValueError("successful blast result requires blast_analysis")
    subject = analysis.subject
    target_label = f"{subject.path}:{subject.start_line}-{subject.end_line}" + (
        f" (`{subject.symbol}`)" if subject.symbol else ""
    )
    lines = [
        "# Landmine: blast",
        "",
        "## Summary",
        "",
        result.summary,
        "",
        "## Risk",
        "",
        f"- Score: {result.risk.score}/100 ({result.risk.grade})",
    ]
    for name, component in result.risk.components.items():
        signals = ", ".join(component.signals) or "none"
        lines.append(f"- {name}: {component.value} (signals: {signals})")
    lines.extend(["", "## Target", "", f"- {target_label}", "", "## Direct impacts", ""])
    non_tests = [item for item in result.impacts if item.impact_type != "test"]
    if non_tests:
        for impact in non_tests:
            evidence = ", ".join(impact.evidence_ids)
            path = " → ".join(impact.path_from_target)
            lines.extend(
                [
                    f"### {impact.impact_type}: {impact.path}:{impact.start_line}",
                    "",
                    f"- Status: {impact.status.value} ({impact.confidence:.2f})",
                    f"- Reason: {impact.reason}",
                    f"- Path: {path}",
                    f"- Evidence: {evidence}",
                    "",
                ]
            )
    else:
        lines.extend(["- No proven direct impacts were found.", ""])
    lines.extend(["## Related tests", ""])
    direct_tests = [item for item in result.impacts if item.impact_type == "test"]
    if direct_tests:
        for impact in direct_tests:
            lines.append(
                f"- Direct test: {impact.path}:{impact.start_line} "
                f"(evidence: {', '.join(impact.evidence_ids)})"
            )
        lines.append(
            "- A direct test import/reference does not by itself establish behavioral coverage."
        )
    else:
        lines.append("- No direct test import/reference was found.")
    for path in analysis.candidate_tests:
        lines.append(f"- Candidate test: {path} (naming/text signal only; not a direct impact).")
    lines.extend(["", "## Unknown surfaces", ""])
    for surface in analysis.not_evaluated:
        lines.append(f"- `{surface}`: not evaluated")
    lines.extend(["", "## Evidence", ""])
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
            f"- Scope: {analysis.scope}",
            f"- Supported depth: {analysis.supported_depth}",
            f"- HEAD: `{result.repository.head}`",
            f"- Dirty worktree: {str(result.repository.dirty).lower()}",
            f"- Shallow repository: {str(result.repository.shallow).lower()}",
            f"- Files scanned: {result.metrics.files_scanned}",
            f"- Evidence count: {result.metrics.evidence_count}",
            "",
        ]
    )
    return "\n".join(lines)

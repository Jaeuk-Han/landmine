"""Deterministic evidence construction and safe excerpt handling."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from landmine.domain import Evidence

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*)(\S+)"),
    re.compile(r"(?i)((?:api[_-]?key|token|password|secret)\s*[=:]\s*)(\S+)"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.S),
)


def safe_excerpt(value: str, *, max_lines: int = 12, max_chars: int = 2000) -> str:
    """Cap and redact untrusted repository text while retaining evidence value."""
    excerpt = "\n".join(value.splitlines()[:max_lines])[:max_chars]
    for pattern in _SECRET_PATTERNS:
        excerpt = pattern.sub(
            lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]",
            excerpt,
        )
    return excerpt


def make_evidence(
    *,
    kind: str,
    locator: dict[str, Any],
    excerpt: str,
    observed_at: str,
    command: str | None,
) -> Evidence:
    """Create an evidence item whose ID is stable across runs."""
    normalized_excerpt = safe_excerpt(excerpt).strip()
    locator_json = json.dumps(locator, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    excerpt_sha = hashlib.sha256(normalized_excerpt.encode("utf-8")).hexdigest()
    digest = hashlib.sha256(f"{kind}\0{locator_json}\0{normalized_excerpt}".encode()).hexdigest()
    return Evidence(
        id=f"ev_{digest[:12]}",
        kind=kind,
        locator=locator,
        excerpt_sha256=excerpt_sha,
        observed_at=observed_at,
        excerpt=normalized_excerpt or None,
        command=command,
    )

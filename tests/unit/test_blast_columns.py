from __future__ import annotations

import ast

import pytest

from landmine.analyzers.blast import _node_character_columns
from landmine.domain import BlastImpact, BlastImpactStatus


def test_ast_utf8_byte_offsets_are_converted_to_unicode_character_columns() -> None:
    line = '    assert "한글" and target(1)'
    tree = ast.parse("def test_unicode():\n" + line + "\n")
    target = next(
        node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "target"
    )

    assert target.col_offset + 1 != 21
    assert _node_character_columns(line, target) == (21, 27)


def test_invalid_utf8_boundary_returns_no_column_range() -> None:
    line = "한target"
    node = ast.Name(id="target", ctx=ast.Load())
    node.col_offset = 1
    node.end_col_offset = 3
    node.lineno = 1
    node.end_lineno = 1

    assert _node_character_columns(line, node) == (None, None)


def test_blast_impact_rejects_inverted_column_range() -> None:
    with pytest.raises(ValueError, match="end_column"):
        BlastImpact(
            id="impact_000000000000",
            impact_type="test",
            path="tests/test_example.py",
            start_line=1,
            end_line=1,
            symbol="target",
            status=BlastImpactStatus.DIRECT,
            confidence=0.9,
            evidence_ids=(),
            path_from_target=(),
            reason="test",
            start_column=8,
            end_column=4,
        )

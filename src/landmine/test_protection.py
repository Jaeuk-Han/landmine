"""Conservative Python test-reference and empty-input discovery."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class TestProtectionMatch:
    path: str
    scope: str
    line: int
    matching_text: str
    empty_input: bool


def _called_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_empty_expression(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)):
        values = node.elts if not isinstance(node, ast.Dict) else node.keys
        return not values
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"list", "tuple", "set", "dict"}
        and not node.args
        and not node.keywords
    )


class _TestVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source_lines: list[str], scopes: set[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.scopes = scopes
        self.empty_names: set[str] = set()
        self.matches: list[TestProtectionMatch] = []

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        previous = self.empty_names
        self.empty_names = set()
        for statement in node.body:
            self.visit(statement)
        self.empty_names = previous

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        if _is_empty_expression(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.empty_names.add(target.id)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            if isinstance(node.target, ast.Name) and _is_empty_expression(node.value):
                self.empty_names.add(node.target.id)

    def visit_Call(self, node: ast.Call) -> None:
        scope = _called_name(node.func)
        if scope in self.scopes:
            empty_input = any(
                _is_empty_expression(argument)
                or (isinstance(argument, ast.Name) and argument.id in self.empty_names)
                for argument in node.args
            )
            text = self.source_lines[node.lineno - 1].strip() if self.source_lines else ""
            self.matches.append(
                TestProtectionMatch(
                    path=self.path,
                    scope=scope,
                    line=node.lineno,
                    matching_text=text,
                    empty_input=empty_input,
                )
            )
        self.generic_visit(node)


def analyze_python_test_source(
    path: str,
    source: str,
    scopes: set[str],
) -> tuple[TestProtectionMatch, ...]:
    """Find exact target calls and distinguish explicit empty-input calls."""
    tree = ast.parse(source, filename=path)
    visitor = _TestVisitor(path, source.splitlines(), scopes)
    visitor.visit(tree)
    combined: dict[tuple[str, str], TestProtectionMatch] = {}
    for match in visitor.matches:
        key = (match.path, match.scope)
        existing = combined.get(key)
        if existing is None or (match.empty_input and not existing.empty_input):
            combined[key] = match
    return tuple(
        sorted(
            combined.values(),
            key=lambda item: (item.path, item.scope, item.line, not item.empty_input),
        )
    )

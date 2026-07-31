"""Python AST detector for unchecked required mapping-key access."""

from __future__ import annotations

import ast
import json

from landmine.assumptions import AnalysisContext, AssumptionCandidate
from landmine.domain import AssumptionCategory

Guarantee = tuple[str, str]


def _literal_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _quoted_key(key: str) -> str:
    return json.dumps(key, ensure_ascii=False)


def _normalize_base(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _normalize_base(node.value)
        return f"{parent}.{node.attr}" if parent is not None else None
    if isinstance(node, ast.Subscript):
        parent = _normalize_base(node.value)
        key = _literal_key(node.slice)
        if parent is not None and key is not None:
            return f"{parent}[{_quoted_key(key)}]"
    return None


def _membership(node: ast.AST) -> tuple[Guarantee, bool] | None:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    key = _literal_key(node.left)
    base = _normalize_base(node.comparators[0])
    if key is None or base is None:
        return None
    operator = node.ops[0]
    if isinstance(operator, ast.In):
        return (base, key), True
    if isinstance(operator, ast.NotIn):
        return (base, key), False
    return None


def _definitely_exits(statements: list[ast.stmt]) -> bool:
    return bool(statements) and isinstance(statements[-1], (ast.Return, ast.Raise))


def _binding_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for item in node.elts:
            names.update(_binding_names(item))
        return names
    if isinstance(node, ast.Starred):
        return _binding_names(node.value)
    return set()


def _dict_literal_keys(node: ast.AST) -> tuple[str, ...] | None:
    if not isinstance(node, ast.Dict) or any(key is None for key in node.keys):
        return None
    keys: list[str] = []
    for key_node in node.keys:
        if key_node is None:
            return None
        key = _literal_key(key_node)
        if key is None:
            return None
        keys.append(key)
    return tuple(sorted(set(keys)))


def _catches_key_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return False
    if isinstance(handler.type, ast.Name):
        return handler.type.id == "KeyError"
    if isinstance(handler.type, ast.Tuple):
        return any(
            isinstance(item, ast.Name) and item.id == "KeyError" for item in handler.type.elts
        )
    return False


def _invalidate_name(guarantees: dict[Guarantee, str], name: str) -> None:
    prefixes = (f"{name}.", f"{name}[")
    for guarantee in tuple(guarantees):
        base, _ = guarantee
        if base == name or base.startswith(prefixes):
            del guarantees[guarantee]


class _ExpressionScanner(ast.NodeVisitor):
    def __init__(
        self,
        analyzer: _MappingAnalyzer,
        *,
        guarantees: dict[Guarantee, str],
        scope: str | None,
        handled_key_error: bool,
    ) -> None:
        self.analyzer = analyzer
        self.guarantees = guarantees
        self.scope = scope
        self.handled_key_error = handled_key_error

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Subscript(self, node: ast.Subscript) -> None:
        key = _literal_key(node.slice)
        if key is not None and isinstance(node.ctx, ast.Load):
            base = _normalize_base(node.value)
            if base is None:
                self.analyzer.add_candidate(
                    node,
                    base=ast.dump(node.value, annotate_fields=True, include_attributes=False),
                    key=key,
                    scope=self.scope,
                    suppression_reason="unsupported_base_expression",
                    limitation_reason=(
                        "required mapping-key base expression could not be normalized"
                    ),
                )
            else:
                suppression = self.guarantees.get((base, key))
                if suppression is None and self.handled_key_error:
                    suppression = "handled_key_error"
                self.analyzer.add_candidate(
                    node,
                    base=base,
                    key=key,
                    scope=self.scope,
                    suppression_reason=suppression,
                )
        self.generic_visit(node)


class _MappingAnalyzer:
    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.candidates: dict[tuple[str, int, int, str, str], AssumptionCandidate] = {}

    def add_candidate(
        self,
        node: ast.expr,
        *,
        base: str,
        key: str,
        scope: str | None,
        suppression_reason: str | None,
        limitation_reason: str | None = None,
    ) -> None:
        line = node.lineno
        end_line = node.end_lineno or line
        if line > self.context.end_line or end_line < self.context.start_line:
            return
        identity = (self.context.path, line, node.col_offset, base, key)
        self.candidates[identity] = AssumptionCandidate(
            detector_id=PythonRequiredMappingKeyDetector.detector_id,
            category=PythonRequiredMappingKeyDetector.category,
            path=self.context.path,
            line=line,
            end_line=end_line,
            column=node.col_offset,
            observed_signal="required_mapping_key",
            variable=base,
            claim=f"`{base}` is assumed to contain the key {_quoted_key(key)}.",
            violation_scenario=f"The key {_quoted_key(key)} is absent.",
            consequence="KeyError before the requested operation completes.",
            confidence=0.74,
            confidence_ceiling=0.79,
            scope=scope,
            suppression_reason=suppression_reason,
            required_key=key,
            limitation_reason=limitation_reason,
        )

    def scan_expression(
        self,
        node: ast.AST | None,
        *,
        guarantees: dict[Guarantee, str],
        scope: str | None,
        handled_key_error: bool,
    ) -> None:
        if node is not None:
            _ExpressionScanner(
                self,
                guarantees=guarantees,
                scope=scope,
                handled_key_error=handled_key_error,
            ).visit(node)

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        guarantees: dict[Guarantee, str] | None = None,
        scope: str | None = None,
        handled_key_error: bool = False,
    ) -> None:
        current = dict(guarantees or {})
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_block(statement.body, scope=statement.name)
                continue
            if isinstance(statement, ast.ClassDef):
                self.scan_block(statement.body, scope=statement.name)
                continue
            if isinstance(statement, ast.If):
                self.scan_expression(
                    statement.test,
                    guarantees=current,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                membership = _membership(statement.test)
                body_guarantees = dict(current)
                else_guarantees = dict(current)
                if membership is not None:
                    guarantee, present = membership
                    if present:
                        body_guarantees[guarantee] = "membership_guard"
                    else:
                        else_guarantees[guarantee] = "membership_guard"
                self.scan_block(
                    statement.body,
                    guarantees=body_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                self.scan_block(
                    statement.orelse,
                    guarantees=else_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                if (
                    membership is not None
                    and not membership[1]
                    and _definitely_exits(statement.body)
                ):
                    current[membership[0]] = "early_exit_missing_key_guard"
                continue
            if isinstance(statement, ast.Assert):
                self.scan_expression(
                    statement.test,
                    guarantees=current,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                membership = _membership(statement.test)
                if membership is not None and membership[1]:
                    current[membership[0]] = "membership_assertion"
                if statement.msg is not None:
                    self.scan_expression(
                        statement.msg,
                        guarantees=current,
                        scope=scope,
                        handled_key_error=handled_key_error,
                    )
                continue
            if isinstance(statement, ast.Try):
                catches = any(_catches_key_error(handler) for handler in statement.handlers)
                self.scan_block(
                    statement.body,
                    guarantees=dict(current),
                    scope=scope,
                    handled_key_error=handled_key_error or catches,
                )
                for handler in statement.handlers:
                    self.scan_block(
                        handler.body,
                        guarantees=dict(current),
                        scope=scope,
                        handled_key_error=handled_key_error,
                    )
                self.scan_block(
                    statement.orelse,
                    guarantees=dict(current),
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                self.scan_block(
                    statement.finalbody,
                    guarantees=dict(current),
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                self.scan_expression(
                    value,
                    guarantees=current,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                for target in targets:
                    if isinstance(target, ast.Subscript):
                        base = _normalize_base(target.value)
                        key = _literal_key(target.slice)
                        self.scan_expression(
                            target.value,
                            guarantees=current,
                            scope=scope,
                            handled_key_error=handled_key_error,
                        )
                        if base is not None and key is not None:
                            current[(base, key)] = "prior_key_assignment"
                assigned = set().union(*(_binding_names(target) for target in targets))
                for name in assigned:
                    _invalidate_name(current, name)
                if len(targets) == 1 and isinstance(targets[0], ast.Name) and value is not None:
                    literal_keys = _dict_literal_keys(value)
                    if literal_keys is not None:
                        for key in literal_keys:
                            current[(targets[0].id, key)] = "known_mapping_literal"
                continue
            expressions: list[ast.expr | None] = []
            if isinstance(statement, (ast.Expr, ast.Return)):
                expressions = [statement.value]
            elif isinstance(statement, ast.Raise):
                expressions = [statement.exc, statement.cause]
            elif isinstance(statement, ast.AugAssign):
                expressions = [statement.target, statement.value]
            else:
                for _, value in ast.iter_fields(statement):
                    if isinstance(value, ast.expr):
                        expressions.append(value)
            for expression in expressions:
                self.scan_expression(
                    expression,
                    guarantees=current,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
            for nested in (
                getattr(statement, "body", []),
                getattr(statement, "orelse", []),
                getattr(statement, "finalbody", []),
            ):
                if nested:
                    self.scan_block(
                        nested,
                        guarantees=dict(current),
                        scope=scope,
                        handled_key_error=handled_key_error,
                    )


class PythonRequiredMappingKeyDetector:
    detector_id = "python.required-mapping-key"
    category = AssumptionCategory.DATA

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        tree = ast.parse(context.source, filename=context.path)
        analyzer = _MappingAnalyzer(context)
        analyzer.scan_block(tree.body)
        return [
            analyzer.candidates[key]
            for key in sorted(
                analyzer.candidates,
                key=lambda item: (item[0], item[1], item[2], item[3], item[4]),
            )
        ]

"""Python AST detector for unchecked collection cardinality assumptions."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from landmine.assumptions import AnalysisContext, AssumptionCandidate
from landmine.domain import AssumptionCategory


def _name(node: ast.AST) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _is_non_empty_literal(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return bool(node.elts)
    if isinstance(node, ast.Dict):
        return bool(node.keys)
    return (
        isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and bool(node.value)
    )


def _index_kind(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and node.value == 0:
        return "zero_index"
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and node.operand.value == 1
    ):
        return "negative_index"
    return None


def _positive_guard(node: ast.AST) -> tuple[str, str] | None:
    if isinstance(node, ast.Name):
        return node.id, "truthy_guard"
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    call = node.left
    if (
        not isinstance(call, ast.Call)
        or not isinstance(call.func, ast.Name)
        or call.func.id != "len"
        or len(call.args) != 1
    ):
        return None
    variable = _name(call.args[0])
    comparator = node.comparators[0]
    if variable is None or not isinstance(comparator, ast.Constant):
        return None
    value = comparator.value
    operator = node.ops[0]
    if (isinstance(operator, ast.Gt) and value == 0) or (
        isinstance(operator, ast.GtE) and value == 1
    ):
        return variable, "positive_length_guard"
    return None


def _negative_guard(node: ast.AST) -> str | None:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _name(node.operand)
    return None


def _definitely_exits(statements: list[ast.stmt]) -> bool:
    return bool(statements) and isinstance(statements[-1], (ast.Return, ast.Raise))


def _assigned_names(targets: Iterable[ast.AST]) -> set[str]:
    names: set[str] = set()
    for target in targets:
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.add(node.id)
    return names


class _ExpressionScanner(ast.NodeVisitor):
    def __init__(
        self,
        analyzer: _AstAnalyzer,
        *,
        protected: dict[str, str],
        known_nonempty: set[str],
        scope: str | None,
    ) -> None:
        self.analyzer = analyzer
        self.protected = protected
        self.known_nonempty = known_nonempty
        self.scope = scope

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Subscript(self, node: ast.Subscript) -> None:
        signal = _index_kind(node.slice)
        if signal is not None:
            variable = _name(node.value) or ast.unparse(node.value)
            suppression = None
            if _is_non_empty_literal(node.value) or (
                isinstance(node.value, ast.Name) and node.value.id in self.known_nonempty
            ):
                suppression = "statically_non_empty"
            elif isinstance(node.value, ast.Name):
                suppression = self.protected.get(node.value.id)
            self.analyzer.add_candidate(
                node,
                signal=signal,
                variable=variable,
                consequence="IndexError",
                scope=self.scope,
                suppression_reason=suppression,
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "next"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Call)
            and isinstance(node.args[0].func, ast.Name)
            and node.args[0].func.id == "iter"
            and len(node.args[0].args) == 1
        ):
            collection = node.args[0].args[0]
            variable = _name(collection) or ast.unparse(collection)
            suppression = None
            if _is_non_empty_literal(collection) or (
                isinstance(collection, ast.Name) and collection.id in self.known_nonempty
            ):
                suppression = "statically_non_empty"
            elif isinstance(collection, ast.Name):
                suppression = self.protected.get(collection.id)
            self.analyzer.add_candidate(
                node,
                signal="next_iter",
                variable=variable,
                consequence="StopIteration",
                scope=self.scope,
                suppression_reason=suppression,
            )
        self.generic_visit(node)


class _AstAnalyzer:
    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.candidates: list[AssumptionCandidate] = []

    def add_candidate(
        self,
        node: ast.expr | ast.stmt,
        *,
        signal: str,
        variable: str,
        consequence: str,
        scope: str | None,
        suppression_reason: str | None,
        exact_length: int | None = None,
    ) -> None:
        line = node.lineno
        end_line = getattr(node, "end_lineno", line) or line
        if line > self.context.end_line or end_line < self.context.start_line:
            return
        if exact_length is None:
            claim = f"The collection `{variable}` is assumed to contain at least one element."
            violation = f"`{variable}` is empty."
        else:
            claim = (
                f"The collection `{variable}` is assumed to contain exactly "
                f"{exact_length} elements."
            )
            violation = f"`{variable}` is empty or has a different cardinality."
        self.candidates.append(
            AssumptionCandidate(
                detector_id=PythonNonEmptyCollectionDetector.detector_id,
                category=PythonNonEmptyCollectionDetector.category,
                path=self.context.path,
                line=line,
                end_line=end_line,
                column=node.col_offset,
                observed_signal=signal,
                variable=variable,
                claim=claim,
                violation_scenario=violation,
                consequence=consequence,
                confidence=0.72 if signal in {"zero_index", "negative_index"} else 0.68,
                confidence_ceiling=0.79,
                scope=scope,
                suppression_reason=suppression_reason,
            )
        )

    def scan_expression(
        self,
        node: ast.AST | None,
        *,
        protected: dict[str, str],
        known_nonempty: set[str],
        scope: str | None,
    ) -> None:
        if node is not None:
            _ExpressionScanner(
                self,
                protected=protected,
                known_nonempty=known_nonempty,
                scope=scope,
            ).visit(node)

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        protected: dict[str, str] | None = None,
        known_nonempty: set[str] | None = None,
        scope: str | None = None,
    ) -> None:
        current_protected = dict(protected or {})
        current_nonempty = set(known_nonempty or ())
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
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    scope=scope,
                )
                positive = _positive_guard(statement.test)
                negative = _negative_guard(statement.test)
                body_protected = dict(current_protected)
                else_protected = dict(current_protected)
                if positive is not None:
                    body_protected[positive[0]] = positive[1]
                if negative is not None:
                    else_protected[negative] = "truthy_guard"
                self.scan_block(
                    statement.body,
                    protected=body_protected,
                    known_nonempty=set(current_nonempty),
                    scope=scope,
                )
                self.scan_block(
                    statement.orelse,
                    protected=else_protected,
                    known_nonempty=set(current_nonempty),
                    scope=scope,
                )
                if negative is not None and _definitely_exits(statement.body):
                    current_protected[negative] = "early_exit_guard"
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                if (
                    isinstance(statement, ast.Assign)
                    and len(statement.targets) == 1
                    and isinstance(statement.targets[0], (ast.Tuple, ast.List))
                    and not any(isinstance(item, ast.Starred) for item in statement.targets[0].elts)
                ):
                    variable = _name(value) if value is not None else None
                    if variable is not None:
                        suppression = current_protected.get(variable)
                        self.add_candidate(
                            statement,
                            signal="fixed_length_unpack",
                            variable=variable,
                            consequence="ValueError during unpacking",
                            scope=scope,
                            suppression_reason=suppression,
                            exact_length=len(statement.targets[0].elts),
                        )
                self.scan_expression(
                    value,
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    scope=scope,
                )
                assigned = _assigned_names(targets)
                current_nonempty.difference_update(assigned)
                current_protected = {
                    name: reason
                    for name, reason in current_protected.items()
                    if name not in assigned
                }
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and value is not None
                    and _is_non_empty_literal(value)
                ):
                    current_nonempty.add(targets[0].id)
                continue
            expressions: list[ast.expr | None]
            if isinstance(statement, ast.Expr):
                expressions = [statement.value]
            elif isinstance(statement, (ast.Return, ast.Raise)):
                expressions = [
                    statement.value if isinstance(statement, ast.Return) else statement.exc
                ]
            elif isinstance(statement, ast.AugAssign):
                expressions = [statement.target, statement.value]
            else:
                expressions = []
                for _, value in ast.iter_fields(statement):
                    if isinstance(value, ast.expr):
                        expressions.append(value)
            for expression in expressions:
                self.scan_expression(
                    expression,
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    scope=scope,
                )
            for nested in (
                getattr(statement, "body", []),
                getattr(statement, "orelse", []),
                getattr(statement, "finalbody", []),
            ):
                if nested:
                    self.scan_block(
                        nested,
                        protected=dict(current_protected),
                        known_nonempty=set(current_nonempty),
                        scope=scope,
                    )


class PythonNonEmptyCollectionDetector:
    detector_id = "python.non-empty-collection"
    category = AssumptionCategory.DATA

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        tree = ast.parse(context.source, filename=context.path)
        analyzer = _AstAnalyzer(context)
        analyzer.scan_block(tree.body)
        return sorted(
            analyzer.candidates,
            key=lambda item: (
                item.path,
                item.line,
                item.column,
                item.observed_signal,
                item.variable,
            ),
        )

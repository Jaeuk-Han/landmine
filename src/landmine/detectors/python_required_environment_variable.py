"""Python AST detector for required process environment variables."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from landmine.assumptions import AnalysisContext, AssumptionCandidate
from landmine.domain import AssumptionCategory

AccessIdentity = tuple[int, int, str]


def _literal_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
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


def _argument_names(arguments: ast.arguments) -> set[str]:
    return {
        argument.arg
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            *([arguments.vararg] if arguments.vararg is not None else []),
            *([arguments.kwarg] if arguments.kwarg is not None else []),
        )
    }


@dataclass
class _Bindings:
    os_modules: set[str]
    environ_names: set[str]

    def copy(self) -> _Bindings:
        return _Bindings(set(self.os_modules), set(self.environ_names))

    def invalidate(self, names: set[str]) -> None:
        self.os_modules.difference_update(names)
        self.environ_names.difference_update(names)


def _is_environment_base(node: ast.AST, bindings: _Bindings) -> bool:
    if isinstance(node, ast.Name):
        return node.id in bindings.environ_names
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id in bindings.os_modules
    )


def _membership(
    node: ast.AST,
    bindings: _Bindings,
) -> tuple[str, bool] | None:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    key = _literal_key(node.left)
    if key is None or not _is_environment_base(node.comparators[0], bindings):
        return None
    if isinstance(node.ops[0], ast.In):
        return key, True
    if isinstance(node.ops[0], ast.NotIn):
        return key, False
    return None


class _ExpressionScanner(ast.NodeVisitor):
    def __init__(
        self,
        analyzer: _EnvironmentAnalyzer,
        *,
        bindings: _Bindings,
        guarantees: dict[str, str],
        scope: str | None,
    ) -> None:
        self.analyzer = analyzer
        self.bindings = bindings
        self.guarantees = guarantees
        self.scope = scope

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Subscript(self, node: ast.Subscript) -> None:
        key = _literal_key(node.slice)
        if (
            key is not None
            and isinstance(node.ctx, ast.Load)
            and _is_environment_base(node.value, self.bindings)
        ):
            self.analyzer.add_candidate(
                node,
                key=key,
                scope=self.scope,
                suppression_reason=self.guarantees.get(key),
            )
        self.generic_visit(node)


class _EnvironmentAnalyzer:
    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.candidates: dict[tuple[str, int, int, str], AssumptionCandidate] = {}

    def add_candidate(
        self,
        node: ast.expr,
        *,
        key: str,
        scope: str | None,
        suppression_reason: str | None,
    ) -> None:
        line = node.lineno
        end_line = node.end_lineno or line
        if line > self.context.end_line or end_line < self.context.start_line:
            return
        identity = (self.context.path, line, node.col_offset, key)
        self.candidates[identity] = AssumptionCandidate(
            detector_id=PythonRequiredEnvironmentVariableDetector.detector_id,
            category=PythonRequiredEnvironmentVariableDetector.category,
            path=self.context.path,
            line=line,
            end_line=end_line,
            column=node.col_offset,
            observed_signal="required_environment_variable",
            variable="os.environ",
            claim=f"The environment is assumed to define `{key}`.",
            violation_scenario=f"`{key}` is missing from the process environment.",
            consequence=("Configuration loading raises KeyError before the operation starts."),
            confidence=0.76,
            confidence_ceiling=0.79,
            scope=scope,
            suppression_reason=suppression_reason,
            required_key=key,
        )

    def scan_expression(
        self,
        node: ast.AST | None,
        *,
        bindings: _Bindings,
        guarantees: dict[str, str],
        scope: str | None,
    ) -> None:
        if node is not None:
            _ExpressionScanner(
                self,
                bindings=bindings,
                guarantees=guarantees,
                scope=scope,
            ).visit(node)

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        bindings: _Bindings | None = None,
        guarantees: dict[str, str] | None = None,
        scope: str | None = None,
    ) -> None:
        current_bindings = bindings.copy() if bindings is not None else _Bindings(set(), set())
        current_guarantees = dict(guarantees or {})
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local_name = alias.asname or alias.name.split(".", 1)[0]
                    current_bindings.invalidate({local_name})
                    if alias.name == "os":
                        current_bindings.os_modules.add(local_name)
                continue
            if isinstance(statement, ast.ImportFrom):
                for alias in statement.names:
                    local_name = alias.asname or alias.name
                    current_bindings.invalidate({local_name})
                    if statement.module == "os" and alias.name == "environ":
                        current_bindings.environ_names.add(local_name)
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_bindings = current_bindings.copy()
                function_bindings.invalidate(_argument_names(statement.args))
                self.scan_block(
                    statement.body,
                    bindings=function_bindings,
                    scope=statement.name,
                )
                continue
            if isinstance(statement, ast.ClassDef):
                self.scan_block(
                    statement.body,
                    bindings=current_bindings,
                    scope=statement.name,
                )
                continue
            if isinstance(statement, ast.If):
                self.scan_expression(
                    statement.test,
                    bindings=current_bindings,
                    guarantees=current_guarantees,
                    scope=scope,
                )
                membership = _membership(statement.test, current_bindings)
                body_guarantees = dict(current_guarantees)
                else_guarantees = dict(current_guarantees)
                if membership is not None:
                    key, present = membership
                    if present:
                        body_guarantees[key] = "membership_guard"
                    else:
                        else_guarantees[key] = "membership_guard"
                self.scan_block(
                    statement.body,
                    bindings=current_bindings,
                    guarantees=body_guarantees,
                    scope=scope,
                )
                self.scan_block(
                    statement.orelse,
                    bindings=current_bindings,
                    guarantees=else_guarantees,
                    scope=scope,
                )
                if (
                    membership is not None
                    and not membership[1]
                    and _definitely_exits(statement.body)
                ):
                    current_guarantees[membership[0]] = "early_exit_missing_key_guard"
                continue
            if isinstance(statement, ast.Assert):
                self.scan_expression(
                    statement.test,
                    bindings=current_bindings,
                    guarantees=current_guarantees,
                    scope=scope,
                )
                membership = _membership(statement.test, current_bindings)
                if membership is not None and membership[1]:
                    current_guarantees[membership[0]] = "membership_assertion"
                self.scan_expression(
                    statement.msg,
                    bindings=current_bindings,
                    guarantees=current_guarantees,
                    scope=scope,
                )
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                self.scan_expression(
                    value,
                    bindings=current_bindings,
                    guarantees=current_guarantees,
                    scope=scope,
                )
                for target in targets:
                    if isinstance(target, ast.Subscript) and _is_environment_base(
                        target.value, current_bindings
                    ):
                        assigned_key = _literal_key(target.slice)
                        if assigned_key is not None:
                            current_guarantees[assigned_key] = "prior_environment_assignment"
                    self.scan_expression(
                        target.value if isinstance(target, ast.Subscript) else None,
                        bindings=current_bindings,
                        guarantees=current_guarantees,
                        scope=scope,
                    )
                assigned = set().union(*(_binding_names(target) for target in targets))
                current_bindings.invalidate(assigned)
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
                    bindings=current_bindings,
                    guarantees=current_guarantees,
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
                        bindings=current_bindings,
                        guarantees=current_guarantees,
                        scope=scope,
                    )


class PythonRequiredEnvironmentVariableDetector:
    detector_id = "python.required-environment-variable"
    category = AssumptionCategory.ENVIRONMENT

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        tree = ast.parse(context.source, filename=context.path)
        analyzer = _EnvironmentAnalyzer(context)
        analyzer.scan_block(tree.body)
        return [
            analyzer.candidates[key]
            for key in sorted(
                analyzer.candidates,
                key=lambda item: (item[0], item[1], item[2], item[3]),
            )
        ]


def owned_environment_accesses(context: AnalysisContext) -> frozenset[AccessIdentity]:
    """Classify accesses owned by the specialized detector, including suppressions."""
    return frozenset(
        (candidate.line, candidate.column, candidate.required_key)
        for candidate in PythonRequiredEnvironmentVariableDetector().detect(context)
        if candidate.required_key is not None
    )

"""Python AST detector for required fields in proven HTTP JSON responses."""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass

from landmine.assumptions import (
    AnalysisContext,
    AssumptionCandidate,
    ProvenanceObservation,
)
from landmine.domain import AssumptionCategory

AccessIdentity = tuple[int, int, str]
Guarantee = tuple[str, str]
_HTTP_LIBRARIES = frozenset({"requests", "httpx"})
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "request"})


def _literal_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _quoted_key(key: str) -> str:
    return json.dumps(key, ensure_ascii=False)


def _unwrap_await(node: ast.AST) -> ast.AST:
    return node.value if isinstance(node, ast.Await) else node


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


def _normalize_expression(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _normalize_expression(node.value)
        return f"{parent}.{node.attr}" if parent is not None else None
    if isinstance(node, ast.Call):
        function = _normalize_expression(node.func)
        if function is not None and not node.args and not node.keywords:
            return f"{function}()"
        return None
    if isinstance(node, ast.Subscript):
        parent = _normalize_expression(node.value)
        key = _literal_key(node.slice)
        if parent is not None and key is not None:
            return f"{parent}[{_quoted_key(key)}]"
    return None


def _expression_text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return ast.dump(node, annotate_fields=True, include_attributes=False)


@dataclass(frozen=True)
class _HttpOrigin:
    library: str
    method: str
    call: ProvenanceObservation


@dataclass(frozen=True)
class _JsonValue:
    origin: _HttpOrigin
    expression: str
    provenance: tuple[ProvenanceObservation, ...]


@dataclass
class _State:
    http_modules: dict[str, str]
    responses: dict[str, _HttpOrigin]
    json_values: dict[str, _JsonValue]

    def copy(self, *, include_values: bool = True) -> _State:
        return _State(
            dict(self.http_modules),
            dict(self.responses) if include_values else {},
            dict(self.json_values) if include_values else {},
        )

    def invalidate(self, names: set[str]) -> None:
        for name in names:
            self.http_modules.pop(name, None)
            self.responses.pop(name, None)
            self.json_values.pop(name, None)


def _http_call(node: ast.AST, state: _State) -> _HttpOrigin | None:
    unwrapped = _unwrap_await(node)
    if (
        not isinstance(unwrapped, ast.Call)
        or not isinstance(unwrapped.func, ast.Attribute)
        or not isinstance(unwrapped.func.value, ast.Name)
        or unwrapped.func.attr not in _HTTP_METHODS
    ):
        return None
    library = state.http_modules.get(unwrapped.func.value.id)
    if library is None:
        return None
    return _HttpOrigin(
        library=library,
        method=unwrapped.func.attr,
        call=ProvenanceObservation(
            role="http_call",
            line=unwrapped.lineno,
            end_line=unwrapped.end_lineno or unwrapped.lineno,
            column=unwrapped.col_offset,
            expression=_expression_text(unwrapped),
        ),
    )


def _json_value(node: ast.AST, state: _State) -> _JsonValue | None:
    unwrapped = _unwrap_await(node)
    if isinstance(unwrapped, ast.Name):
        return state.json_values.get(unwrapped.id)
    if (
        isinstance(unwrapped, ast.Call)
        and isinstance(unwrapped.func, ast.Attribute)
        and unwrapped.func.attr == "json"
        and not unwrapped.args
        and not unwrapped.keywords
        and isinstance(unwrapped.func.value, ast.Name)
    ):
        origin = state.responses.get(unwrapped.func.value.id)
        if origin is None:
            return None
        expression = _normalize_expression(unwrapped)
        if expression is None:
            return None
        conversion = ProvenanceObservation(
            role="json_conversion",
            line=unwrapped.lineno,
            end_line=unwrapped.end_lineno or unwrapped.lineno,
            column=unwrapped.col_offset,
            expression=_expression_text(unwrapped),
        )
        return _JsonValue(
            origin=origin,
            expression=expression,
            provenance=(origin.call, conversion),
        )
    if isinstance(unwrapped, ast.Subscript) and _literal_key(unwrapped.slice) is not None:
        parent = _json_value(unwrapped.value, state)
        expression = _normalize_expression(unwrapped)
        if parent is not None and expression is not None:
            return _JsonValue(
                origin=parent.origin,
                expression=expression,
                provenance=parent.provenance,
            )
    return None


def _membership(
    node: ast.AST,
    state: _State,
) -> tuple[Guarantee, bool] | None:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    key = _literal_key(node.left)
    value = _json_value(node.comparators[0], state)
    base = _normalize_expression(node.comparators[0])
    if key is None or value is None or base is None:
        return None
    if isinstance(node.ops[0], ast.In):
        return (base, key), True
    if isinstance(node.ops[0], ast.NotIn):
        return (base, key), False
    return None


class _ExpressionScanner(ast.NodeVisitor):
    def __init__(
        self,
        analyzer: _ResponseAnalyzer,
        *,
        state: _State,
        guarantees: dict[Guarantee, str],
        scope: str | None,
        handled_key_error: bool,
    ) -> None:
        self.analyzer = analyzer
        self.state = state
        self.guarantees = guarantees
        self.scope = scope
        self.handled_key_error = handled_key_error

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Subscript(self, node: ast.Subscript) -> None:
        key = _literal_key(node.slice)
        value = _json_value(node.value, self.state)
        base = _normalize_expression(node.value)
        if (
            key is not None
            and value is not None
            and base is not None
            and isinstance(node.ctx, ast.Load)
        ):
            suppression = self.guarantees.get((base, key))
            if suppression is None and self.handled_key_error:
                suppression = "handled_key_error"
            self.analyzer.add_candidate(
                node,
                value=value,
                base=base,
                key=key,
                scope=self.scope,
                suppression_reason=suppression,
            )
        self.generic_visit(node)


class _ResponseAnalyzer:
    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.candidates: dict[
            tuple[str, int, int, str, str],
            AssumptionCandidate,
        ] = {}

    def add_candidate(
        self,
        node: ast.expr,
        *,
        value: _JsonValue,
        base: str,
        key: str,
        scope: str | None,
        suppression_reason: str | None,
    ) -> None:
        line = node.lineno
        end_line = node.end_lineno or line
        if line > self.context.end_line or end_line < self.context.start_line:
            return
        identity = (self.context.path, line, node.col_offset, base, key)
        self.candidates[identity] = AssumptionCandidate(
            detector_id=PythonRequiredResponseFieldDetector.detector_id,
            category=PythonRequiredResponseFieldDetector.category,
            path=self.context.path,
            line=line,
            end_line=end_line,
            column=node.col_offset,
            observed_signal="required_response_field",
            variable=base,
            claim=(f"The external JSON response is assumed to contain {_quoted_key(key)}."),
            violation_scenario=(f"The remote response omits or renames {_quoted_key(key)}."),
            consequence=("The consumer raises KeyError after a successful HTTP response."),
            confidence=0.77,
            confidence_ceiling=0.79,
            scope=scope,
            suppression_reason=suppression_reason,
            required_key=key,
            http_library=value.origin.library,
            http_method=value.origin.method,
            provenance=value.provenance,
        )

    def scan_expression(
        self,
        node: ast.AST | None,
        *,
        state: _State,
        guarantees: dict[Guarantee, str],
        scope: str | None,
        handled_key_error: bool,
    ) -> None:
        if node is not None:
            _ExpressionScanner(
                self,
                state=state,
                guarantees=guarantees,
                scope=scope,
                handled_key_error=handled_key_error,
            ).visit(node)

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        state: _State | None = None,
        guarantees: dict[Guarantee, str] | None = None,
        scope: str | None = None,
        handled_key_error: bool = False,
        allow_new_provenance: bool = True,
    ) -> None:
        current_state = (
            state.copy()
            if state is not None
            else _State(http_modules={}, responses={}, json_values={})
        )
        current_guarantees = dict(guarantees or {})
        for statement in statements:
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    local_name = alias.asname or alias.name.split(".", 1)[0]
                    current_state.invalidate({local_name})
                    if allow_new_provenance and alias.name in _HTTP_LIBRARIES:
                        current_state.http_modules[local_name] = alias.name
                continue
            if isinstance(statement, ast.ImportFrom):
                for alias in statement.names:
                    current_state.invalidate({alias.asname or alias.name})
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_state = current_state.copy(include_values=False)
                function_state.invalidate(_argument_names(statement.args))
                self.scan_block(
                    statement.body,
                    state=function_state,
                    scope=statement.name,
                )
                continue
            if isinstance(statement, ast.ClassDef):
                self.scan_block(
                    statement.body,
                    state=current_state.copy(include_values=False),
                    scope=statement.name,
                )
                continue
            if isinstance(statement, ast.If):
                self.scan_expression(
                    statement.test,
                    state=current_state,
                    guarantees=current_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                membership = _membership(statement.test, current_state)
                body_guarantees = dict(current_guarantees)
                else_guarantees = dict(current_guarantees)
                if membership is not None:
                    guarantee, present = membership
                    if present:
                        body_guarantees[guarantee] = "membership_guard"
                    else:
                        else_guarantees[guarantee] = "membership_guard"
                self.scan_block(
                    statement.body,
                    state=current_state,
                    guarantees=body_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                    allow_new_provenance=False,
                )
                self.scan_block(
                    statement.orelse,
                    state=current_state,
                    guarantees=else_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                    allow_new_provenance=False,
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
                    state=current_state,
                    guarantees=current_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                membership = _membership(statement.test, current_state)
                if membership is not None and membership[1]:
                    current_guarantees[membership[0]] = "membership_assertion"
                self.scan_expression(
                    statement.msg,
                    state=current_state,
                    guarantees=current_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                continue
            if isinstance(statement, ast.Try):
                catches = any(_catches_key_error(handler) for handler in statement.handlers)
                self.scan_block(
                    statement.body,
                    state=current_state,
                    guarantees=current_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error or catches,
                    allow_new_provenance=False,
                )
                for handler in statement.handlers:
                    self.scan_block(
                        handler.body,
                        state=current_state,
                        guarantees=current_guarantees,
                        scope=scope,
                        handled_key_error=handled_key_error,
                        allow_new_provenance=False,
                    )
                self.scan_block(
                    statement.orelse,
                    state=current_state,
                    guarantees=current_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                    allow_new_provenance=False,
                )
                self.scan_block(
                    statement.finalbody,
                    state=current_state,
                    guarantees=current_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                    allow_new_provenance=False,
                )
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                self.scan_expression(
                    value,
                    state=current_state,
                    guarantees=current_guarantees,
                    scope=scope,
                    handled_key_error=handled_key_error,
                )
                http_origin = _http_call(value, current_state) if value is not None else None
                json_value = _json_value(value, current_state) if value is not None else None
                assigned_names = set().union(*(_binding_names(target) for target in targets))
                current_state.invalidate(assigned_names)
                if allow_new_provenance and len(targets) == 1 and isinstance(targets[0], ast.Name):
                    name = targets[0].id
                    if http_origin is not None:
                        current_state.responses[name] = http_origin
                    elif json_value is not None:
                        current_state.json_values[name] = _JsonValue(
                            origin=json_value.origin,
                            expression=name,
                            provenance=json_value.provenance,
                        )
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
                    state=current_state,
                    guarantees=current_guarantees,
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
                        state=current_state,
                        guarantees=current_guarantees,
                        scope=scope,
                        handled_key_error=handled_key_error,
                        allow_new_provenance=False,
                    )


class PythonRequiredResponseFieldDetector:
    detector_id = "python.required-response-field"
    category = AssumptionCategory.EXTERNAL_CONTRACT

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        tree = ast.parse(context.source, filename=context.path)
        analyzer = _ResponseAnalyzer(context)
        analyzer.scan_block(tree.body)
        return [
            analyzer.candidates[key]
            for key in sorted(
                analyzer.candidates,
                key=lambda item: (item[0], item[1], item[2], item[3], item[4]),
            )
        ]


def owned_response_field_accesses(
    context: AnalysisContext,
) -> frozenset[AccessIdentity]:
    """Return accesses exclusively owned by proven external JSON provenance."""
    return frozenset(
        (candidate.line, candidate.column, candidate.required_key)
        for candidate in PythonRequiredResponseFieldDetector().detect(context)
        if candidate.required_key is not None
    )

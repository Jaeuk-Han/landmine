"""Python AST detector for selection that depends on set iteration order."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from landmine.assumptions import (
    AnalysisContext,
    AssumptionCandidate,
    ProvenanceObservation,
)
from landmine.domain import AssumptionCategory


@dataclass(frozen=True)
class _SetValue:
    expression: str
    provenance: tuple[ProvenanceObservation, ...]
    known_size: int | None = None


def _observation(role: str, node: ast.AST, expression: str) -> ProvenanceObservation:
    line = getattr(node, "lineno", 1)
    return ProvenanceObservation(
        role=role,
        line=line,
        end_line=getattr(node, "end_lineno", None) or line,
        column=getattr(node, "col_offset", 0),
        expression=expression,
    )


def _annotation_name(node: ast.AST) -> tuple[str, ast.AST]:
    if isinstance(node, ast.Subscript):
        return _annotation_name(node.value)
    if isinstance(node, ast.Name):
        return node.id, node
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}", node
    return "", node


def _bound_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return set().union(*(_bound_names(item) for item in node.elts))
    if isinstance(node, ast.Starred):
        return _bound_names(node.value)
    return set()


class _Analyzer:
    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.typing_set_names: set[str] = set()
        self.typing_module_names: set[str] = set()
        self.shadowed_builtins: set[str] = set()
        self.candidates: dict[tuple[int, int, str, str], AssumptionCandidate] = {}

    def _is_set_annotation(self, node: ast.AST) -> bool:
        name, _ = _annotation_name(node)
        return (
            (name == "set" and "set" not in self.shadowed_builtins)
            or name in self.typing_set_names
            or (
                "." in name
                and name.split(".", 1)[0] in self.typing_module_names
                and name.split(".", 1)[1] == "Set"
            )
        )

    def _set_expression(self, node: ast.AST, values: dict[str, _SetValue]) -> _SetValue | None:
        if isinstance(node, ast.Name):
            return values.get(node.id)
        if isinstance(node, ast.Set):
            expression = ast.unparse(node)
            return _SetValue(
                expression=expression,
                provenance=(_observation("set_construction", node, expression),),
                known_size=len(node.elts),
            )
        if isinstance(node, ast.SetComp):
            expression = ast.unparse(node)
            return _SetValue(
                expression=expression,
                provenance=(_observation("set_construction", node, expression),),
            )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "set"
            and "set" not in self.shadowed_builtins
        ):
            expression = ast.unparse(node)
            return _SetValue(
                expression=expression,
                provenance=(_observation("set_construction", node, expression),),
                known_size=0 if not node.args and not node.keywords else None,
            )
        return None

    def _in_target(self, node: ast.AST) -> bool:
        line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", None) or line
        return line <= self.context.end_line and end_line >= self.context.start_line

    def _add(
        self,
        node: ast.expr,
        set_value: _SetValue,
        *,
        operation: str,
        scope: str | None,
        confidence: float = 0.75,
        uncertainty_note: str | None = None,
    ) -> None:
        if not self._in_target(node) or set_value.known_size == 1:
            return
        expression = set_value.expression
        consequence = "A different element is selected without an explicit selection rule."
        if operation == "set_pop":
            consequence += " The selection also mutates the set by removing that element."
        identity = (node.lineno, node.col_offset, operation, expression)
        self.candidates[identity] = AssumptionCandidate(
            detector_id=PythonArbitrarySetSelectionDetector.detector_id,
            category=PythonArbitrarySetSelectionDetector.category,
            path=self.context.path,
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            column=node.col_offset,
            observed_signal="set_iteration_selection",
            variable=expression,
            claim=(
                f"The code assumes iteration over `{expression}` produces an acceptable "
                "first element."
            ),
            violation_scenario=(
                "Set iteration order changes across runtime, hash seed, Python version, "
                "or input composition."
            ),
            consequence=consequence,
            confidence=confidence,
            confidence_ceiling=0.79,
            scope=scope,
            provenance=set_value.provenance,
            selection_operation=operation,
            suggested_alternatives=(
                f"sorted({expression})[0]",
                f"min({expression})",
                f"max({expression})",
                "explicit selection key",
            ),
            uncertainty_note=uncertainty_note,
        )

    def _scan_expression(
        self, node: ast.AST | None, values: dict[str, _SetValue], scope: str | None
    ) -> None:
        if node is None:
            return

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "next"
            and "next" not in self.shadowed_builtins
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Call)
            and isinstance(node.args[0].func, ast.Name)
            and node.args[0].func.id == "iter"
            and "iter" not in self.shadowed_builtins
            and len(node.args[0].args) == 1
        ):
            set_value = self._set_expression(node.args[0].args[0], values)
            if set_value is not None:
                self._add(node, set_value, operation="next_iter", scope=scope)
                return

        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value == 0
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and len(node.value.args) >= 1
        ):
            function_name = node.value.func.id
            set_value = self._set_expression(node.value.args[0], values)
            if (
                function_name in {"list", "tuple"}
                and function_name not in self.shadowed_builtins
                and set_value is not None
            ):
                self._add(
                    node,
                    set_value,
                    operation=f"{function_name}_index_zero",
                    scope=scope,
                )
                return
            if (
                function_name == "sorted"
                and "sorted" not in self.shadowed_builtins
                and set_value is not None
                and any(keyword.arg == "key" for keyword in node.value.keywords)
            ):
                self._add(
                    node,
                    set_value,
                    operation="sorted_custom_key_index",
                    scope=scope,
                    confidence=0.62,
                    uncertainty_note=(
                        "A custom selection key may leave ties; tied values can still inherit "
                        "set iteration order."
                    ),
                )
                return

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "pop"
            and not node.args
            and not node.keywords
        ):
            set_value = self._set_expression(node.func.value, values)
            if set_value is not None:
                self._add(node, set_value, operation="set_pop", scope=scope)
                return

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"min", "max"}
            and node.func.id not in self.shadowed_builtins
            and node.args
            and any(keyword.arg == "key" for keyword in node.keywords)
        ):
            set_value = self._set_expression(node.args[0], values)
            if set_value is not None:
                self._add(
                    node,
                    set_value,
                    operation=f"{node.func.id}_custom_key",
                    scope=scope,
                    confidence=0.62,
                    uncertainty_note=(
                        "A custom selection key may leave ties; tied values can still inherit "
                        "set iteration order."
                    ),
                )
                return

        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.comprehension, ast.Store)):
                self._scan_expression(child, values, scope)

    def _function_values(
        self, statement: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> dict[str, _SetValue]:
        values: dict[str, _SetValue] = {}
        arguments = (
            list(statement.args.posonlyargs)
            + list(statement.args.args)
            + list(statement.args.kwonlyargs)
        )
        if statement.args.vararg is not None:
            arguments.append(statement.args.vararg)
        if statement.args.kwarg is not None:
            arguments.append(statement.args.kwarg)
        for argument in arguments:
            if argument.annotation is not None and self._is_set_annotation(argument.annotation):
                values[argument.arg] = _SetValue(
                    expression=argument.arg,
                    provenance=(
                        _observation("set_annotation", argument, ast.unparse(argument.annotation)),
                    ),
                )
        return values

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        values: dict[str, _SetValue] | None = None,
        scope: str | None = None,
    ) -> None:
        current = dict(values or {})
        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_block(
                    statement.body,
                    values=self._function_values(statement),
                    scope=statement.name,
                )
                continue
            if isinstance(statement, ast.ClassDef):
                self.scan_block(statement.body, scope=statement.name)
                continue
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                self._handle_import(statement)
                continue
            if isinstance(statement, ast.For):
                self._scan_expression(statement.iter, current, scope)
                set_value = self._set_expression(statement.iter, current)
                if (
                    set_value is not None
                    and statement.body
                    and isinstance(statement.body[0], ast.Return)
                    and isinstance(statement.body[0].value, ast.Name)
                    and statement.body[0].value.id in _bound_names(statement.target)
                ):
                    self._add(
                        statement.body[0].value,
                        set_value,
                        operation="for_first_return",
                        scope=scope,
                    )
                nested_values = dict(current)
                for name in _bound_names(statement.target):
                    nested_values.pop(name, None)
                self.scan_block(statement.body, values=nested_values, scope=scope)
                self.scan_block(statement.orelse, values=dict(current), scope=scope)
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                self._scan_expression(value, current, scope)
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                proven = self._set_expression(value, current) if value is not None else None
                for target in targets:
                    for name in _bound_names(target):
                        current.pop(name, None)
                        self._invalidate_import_or_builtin(name)
                if len(targets) == 1 and isinstance(targets[0], ast.Name):
                    target = targets[0]
                    if proven is not None:
                        provenance = proven.provenance
                        if isinstance(value, ast.Name):
                            provenance += (
                                _observation("set_alias", statement, f"{target.id} = {value.id}"),
                            )
                        current[target.id] = _SetValue(
                            expression=target.id,
                            provenance=provenance,
                            known_size=proven.known_size,
                        )
                    elif (
                        isinstance(statement, ast.AnnAssign)
                        and statement.annotation is not None
                        and self._is_set_annotation(statement.annotation)
                    ):
                        current[target.id] = _SetValue(
                            expression=target.id,
                            provenance=(
                                _observation(
                                    "set_annotation",
                                    statement,
                                    ast.unparse(statement.annotation),
                                ),
                            ),
                        )
                continue
            if isinstance(statement, ast.If):
                self._scan_expression(statement.test, current, scope)
                self.scan_block(statement.body, values=dict(current), scope=scope)
                self.scan_block(statement.orelse, values=dict(current), scope=scope)
                continue
            if isinstance(statement, ast.Assert):
                self._scan_expression(statement.test, current, scope)
                self._scan_expression(statement.msg, current, scope)
                continue
            expressions: list[ast.AST | None] = []
            if isinstance(statement, (ast.Expr, ast.Return)):
                expressions.append(statement.value)
            elif isinstance(statement, ast.Raise):
                expressions.extend((statement.exc, statement.cause))
            else:
                for _, value in ast.iter_fields(statement):
                    if isinstance(value, ast.expr):
                        expressions.append(value)
            for expression in expressions:
                self._scan_expression(expression, current, scope)
            for nested_name in ("body", "orelse", "finalbody"):
                nested = getattr(statement, nested_name, [])
                if nested:
                    self.scan_block(nested, values=dict(current), scope=scope)

    def _invalidate_import_or_builtin(self, name: str) -> None:
        self.typing_set_names.discard(name)
        self.typing_module_names.discard(name)
        if name in {"set", "list", "tuple", "sorted", "min", "max", "iter", "next"}:
            self.shadowed_builtins.add(name)

    def _handle_import(self, statement: ast.Import | ast.ImportFrom) -> None:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                self._invalidate_import_or_builtin(bound)
                if alias.name == "typing":
                    self.typing_module_names.add(bound)
            return
        if statement.module == "typing":
            for alias in statement.names:
                bound = alias.asname or alias.name
                self._invalidate_import_or_builtin(bound)
                if alias.name == "Set":
                    self.typing_set_names.add(bound)


class PythonArbitrarySetSelectionDetector:
    detector_id = "python.arbitrary-set-selection"
    category = AssumptionCategory.ORDERING

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        tree = ast.parse(context.source, filename=context.path)
        analyzer = _Analyzer(context)
        analyzer.scan_block(tree.body)
        return [
            analyzer.candidates[key]
            for key in sorted(
                analyzer.candidates,
                key=lambda item: (item[0], item[1], item[2], item[3]),
            )
        ]

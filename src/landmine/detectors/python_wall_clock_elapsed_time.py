"""Python AST detector for elapsed-time logic based on the system wall clock."""

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
class _ClockSpec:
    domain: str
    unit: str
    source: str


@dataclass(frozen=True)
class _TemporalValue:
    kind: str
    domain: str
    unit: str
    source: str
    provenance: tuple[ProvenanceObservation, ...]


@dataclass
class _Bindings:
    time_modules: set[str]
    clock_functions: dict[str, _ClockSpec]

    def copy(self) -> _Bindings:
        return _Bindings(set(self.time_modules), dict(self.clock_functions))

    def invalidate(self, names: set[str]) -> None:
        self.time_modules.difference_update(names)
        for name in names:
            self.clock_functions.pop(name, None)


_CLOCK_METHODS = {
    "time": _ClockSpec("wall", "seconds", "time.time"),
    "time_ns": _ClockSpec("wall", "nanoseconds", "time.time_ns"),
    "monotonic": _ClockSpec("monotonic", "seconds", "time.monotonic"),
    "monotonic_ns": _ClockSpec("monotonic", "nanoseconds", "time.monotonic_ns"),
    "perf_counter": _ClockSpec("monotonic", "seconds", "time.perf_counter"),
}


def _observation(role: str, node: ast.AST, expression: str) -> ProvenanceObservation:
    line = getattr(node, "lineno", 1)
    return ProvenanceObservation(
        role=role,
        line=line,
        end_line=getattr(node, "end_lineno", None) or line,
        column=getattr(node, "col_offset", 0),
        expression=expression,
    )


def _bound_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for item in node.elts:
            names.update(_bound_names(item))
        return names
    if isinstance(node, ast.Starred):
        return _bound_names(node.value)
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


class _TimeAnalyzer:
    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.candidates: dict[tuple[int, int, str, str], AssumptionCandidate] = {}

    def _in_target(self, node: ast.AST) -> bool:
        line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", None) or line
        return line <= self.context.end_line and end_line >= self.context.start_line

    def _direct_clock_call(
        self,
        node: ast.AST,
        bindings: _Bindings,
    ) -> _TemporalValue | None:
        if not isinstance(node, ast.Call) or node.args or node.keywords:
            return None
        spec: _ClockSpec | None = None
        if isinstance(node.func, ast.Name):
            spec = bindings.clock_functions.get(node.func.id)
        elif (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in bindings.time_modules
        ):
            spec = _CLOCK_METHODS.get(node.func.attr)
        if spec is None:
            return None
        return _TemporalValue(
            kind="instant",
            domain=spec.domain,
            unit=spec.unit,
            source=spec.source,
            provenance=(_observation("clock_call", node, ast.unparse(node)),),
        )

    def _temporal_value(
        self,
        node: ast.AST,
        *,
        bindings: _Bindings,
        values: dict[str, _TemporalValue],
    ) -> _TemporalValue | None:
        if isinstance(node, ast.Name):
            return values.get(node.id)
        direct = self._direct_clock_call(node, bindings)
        if direct is not None:
            return direct
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._temporal_value(node.left, bindings=bindings, values=values)
            right = self._temporal_value(node.right, bindings=bindings, values=values)
            instant = (
                left
                if left is not None and right is None
                else right
                if right is not None and left is None
                else None
            )
            if instant is not None and instant.kind == "instant":
                return _TemporalValue(
                    kind="deadline",
                    domain=instant.domain,
                    unit=instant.unit,
                    source=instant.source,
                    provenance=instant.provenance
                    + (_observation("deadline_construction", node, ast.unparse(node)),),
                )
        return None

    def _add_candidate(
        self,
        node: ast.expr,
        *,
        operation: str,
        first: _TemporalValue,
        second: _TemporalValue,
        scope: str | None,
    ) -> None:
        if not self._in_target(node):
            return
        mixed = first.domain != second.domain or first.unit != second.unit
        if first.domain != "wall" and second.domain != "wall":
            return
        sources = tuple(sorted({first.source, second.source}))
        source = sources[0] if len(sources) == 1 else " + ".join(sources)
        unit = first.unit if first.unit == second.unit else "mixed"
        signal = "mixed_clock_domain" if mixed else "wall_clock_elapsed_time"
        uncertainty = (
            "The expression uses mixed clock domains or units; subtracting or comparing their "
            "values has no reliable elapsed-time meaning."
            if mixed
            else None
        )
        identity = (node.lineno, node.col_offset, operation, source)
        self.candidates[identity] = AssumptionCandidate(
            detector_id=PythonWallClockElapsedTimeDetector.detector_id,
            category=PythonWallClockElapsedTimeDetector.category,
            path=self.context.path,
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            column=node.col_offset,
            observed_signal=signal,
            variable=source,
            claim="Elapsed-time logic assumes the system wall clock advances monotonically.",
            violation_scenario=(
                "NTP synchronization, manual clock changes, VM clock correction, or "
                "system resume moves the wall clock backward or forward."
            ),
            consequence=(
                "Timeouts may expire too early, too late, or produce a negative duration."
            ),
            confidence=0.63 if mixed else 0.76,
            confidence_ceiling=0.79,
            scope=scope,
            provenance=first.provenance + second.provenance,
            suggested_alternatives=(
                "time.monotonic()",
                "time.monotonic_ns()",
                "time.perf_counter()",
                "inject a monotonic clock dependency",
            ),
            uncertainty_note=uncertainty,
            clock_source=source,
            clock_unit=unit,
            time_operation=operation,
        )

    def _scan_expression(
        self,
        node: ast.AST | None,
        *,
        bindings: _Bindings,
        values: dict[str, _TemporalValue],
        scope: str | None,
    ) -> None:
        if node is None:
            return
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            left = self._temporal_value(node.left, bindings=bindings, values=values)
            right = self._temporal_value(node.right, bindings=bindings, values=values)
            if left is not None and right is not None:
                self._add_candidate(
                    node,
                    operation="duration",
                    first=left,
                    second=right,
                    scope=scope,
                )
                return
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            left = self._temporal_value(node.left, bindings=bindings, values=values)
            right = self._temporal_value(
                node.comparators[0],
                bindings=bindings,
                values=values,
            )
            if (
                left is not None
                and right is not None
                and {left.kind, right.kind} == {"instant", "deadline"}
            ):
                self._add_candidate(
                    node,
                    operation="deadline",
                    first=left,
                    second=right,
                    scope=scope,
                )
                return
        for child in ast.iter_child_nodes(node):
            self._scan_expression(
                child,
                bindings=bindings,
                values=values,
                scope=scope,
            )

    def _handle_import(self, node: ast.Import | ast.ImportFrom, bindings: _Bindings) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                bindings.invalidate({bound})
                if alias.name == "time":
                    bindings.time_modules.add(bound)
            return
        if node.module == "time":
            for alias in node.names:
                bound = alias.asname or alias.name
                bindings.invalidate({bound})
                spec = _CLOCK_METHODS.get(alias.name)
                if spec is not None:
                    bindings.clock_functions[bound] = spec

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        bindings: _Bindings | None = None,
        values: dict[str, _TemporalValue] | None = None,
        scope: str | None = None,
        track_assignments: bool = True,
    ) -> None:
        current_bindings = bindings.copy() if bindings is not None else _Bindings(set(), {})
        current_values = dict(values or {})
        for statement in statements:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                self._handle_import(statement, current_bindings)
                continue
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                current_bindings.invalidate({statement.name})
                function_bindings = current_bindings.copy()
                function_bindings.invalidate(_argument_names(statement.args))
                self.scan_block(
                    statement.body,
                    bindings=function_bindings,
                    scope=statement.name,
                )
                continue
            if isinstance(statement, ast.ClassDef):
                current_bindings.invalidate({statement.name})
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value = statement.value
                self._scan_expression(
                    value,
                    bindings=current_bindings,
                    values=current_values,
                    scope=scope,
                )
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                temporal = (
                    self._temporal_value(
                        value,
                        bindings=current_bindings,
                        values=current_values,
                    )
                    if value is not None
                    else None
                )
                names = set().union(*(_bound_names(target) for target in targets))
                current_bindings.invalidate(names)
                for name in names:
                    current_values.pop(name, None)
                if (
                    track_assignments
                    and len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and temporal is not None
                ):
                    current_values[targets[0].id] = temporal
                continue
            if isinstance(statement, ast.If):
                self._scan_expression(
                    statement.test,
                    bindings=current_bindings,
                    values=current_values,
                    scope=scope,
                )
                self.scan_block(
                    statement.body,
                    bindings=current_bindings,
                    values=current_values,
                    scope=scope,
                    track_assignments=False,
                )
                self.scan_block(
                    statement.orelse,
                    bindings=current_bindings,
                    values=current_values,
                    scope=scope,
                    track_assignments=False,
                )
                continue
            expressions: list[ast.AST | None] = []
            if isinstance(statement, (ast.Expr, ast.Return)):
                expressions.append(statement.value)
            elif isinstance(statement, ast.Raise):
                expressions.extend((statement.exc, statement.cause))
            elif isinstance(statement, ast.Assert):
                expressions.extend((statement.test, statement.msg))
            else:
                for _, value in ast.iter_fields(statement):
                    if isinstance(value, ast.expr):
                        expressions.append(value)
            for expression in expressions:
                self._scan_expression(
                    expression,
                    bindings=current_bindings,
                    values=current_values,
                    scope=scope,
                )
            for nested_name in ("body", "orelse", "finalbody"):
                nested = getattr(statement, nested_name, [])
                if nested:
                    self.scan_block(
                        nested,
                        bindings=current_bindings,
                        values=current_values,
                        scope=scope,
                        track_assignments=False,
                    )


class PythonWallClockElapsedTimeDetector:
    detector_id = "python.wall-clock-elapsed-time"
    category = AssumptionCategory.TIME

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        tree = ast.parse(context.source, filename=context.path)
        analyzer = _TimeAnalyzer(context)
        analyzer.scan_block(tree.body)
        return [
            analyzer.candidates[key]
            for key in sorted(
                analyzer.candidates,
                key=lambda item: (item[0], item[1], item[2], item[3]),
            )
        ]

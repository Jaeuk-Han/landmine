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


def _strip_call_name(node: ast.AST) -> str | None:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "strip"
        and not node.args
        and not node.keywords
    ):
        return _name(node.func.value)
    return None


def _false_path_facts(node: ast.AST) -> tuple[set[str], set[str]]:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        variable = _name(node.operand)
        if variable is not None:
            return {variable}, set()
        stripped = _strip_call_name(node.operand)
        if stripped is not None:
            return set(), {stripped}
        return set(), set()
    if isinstance(node, ast.BoolOp) and node.values:
        facts = [_false_path_facts(value) for value in node.values]
        if isinstance(node.op, ast.Or):
            return (
                set().union(*(collections for collections, _ in facts)),
                set().union(*(strings for _, strings in facts)),
            )
        collections = set(facts[0][0])
        strings = set(facts[0][1])
        for next_collections, next_strings in facts[1:]:
            collections.intersection_update(next_collections)
            strings.intersection_update(next_strings)
        return collections, strings
    return set(), set()


def _truthy_nonempty_names(node: ast.AST) -> set[str]:
    positive = _positive_guard(node)
    if positive is not None:
        return {positive[0]}
    if isinstance(node, ast.BoolOp) and node.values:
        facts = [_truthy_nonempty_names(value) for value in node.values]
        if isinstance(node.op, ast.And):
            return set().union(*facts)
        names = set(facts[0])
        for next_names in facts[1:]:
            names.intersection_update(next_names)
        return names
    return set()


def _definitely_exits(statements: list[ast.stmt], *, in_loop: bool) -> bool:
    if not statements:
        return False
    terminal = statements[-1]
    return isinstance(terminal, (ast.Return, ast.Raise)) or (
        in_loop and isinstance(terminal, (ast.Break, ast.Continue))
    )


def _assigned_names(targets: Iterable[ast.AST]) -> set[str]:
    names: set[str] = set()
    for target in targets:
        if isinstance(target, ast.Name):
            names.add(target.id)
        elif isinstance(target, (ast.List, ast.Tuple)):
            names.update(_assigned_names(target.elts))
    return names


def _empty_collection_literal(node: ast.AST) -> bool:
    return isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict)) and not _is_non_empty_literal(
        node
    )


def _proven_nonblank_string(node: ast.AST, known_nonblank: set[str]) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(node.value.strip())
    if isinstance(node, ast.Name):
        return node.id in known_nonblank
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"rstrip", "strip"}
        and not node.args
        and not node.keywords
        and isinstance(node.func.value, ast.Name)
    ):
        return node.func.value.id in known_nonblank
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _proven_nonblank_string(node.left, known_nonblank) or _proven_nonblank_string(
            node.right, known_nonblank
        )
    return False


_MUTATING_METHODS = frozenset(
    {"append", "clear", "extend", "insert", "pop", "remove", "__delitem__", "__setitem__"}
)


class _MutationCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def _targets(self, targets: Iterable[ast.AST]) -> None:
        self.names.update(_assigned_names(targets))
        for target in targets:
            if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                self.names.add(target.value.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._targets(node.targets)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._targets((node.target,))
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._targets((node.target,))
        self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr in _MUTATING_METHODS
        ):
            self.names.add(node.func.value.id)
        self.generic_visit(node)


def _mutated_names(statements: list[ast.stmt]) -> set[str]:
    collector = _MutationCollector()
    for statement in statements:
        collector.visit(statement)
    return collector.names


class _ExpressionScanner(ast.NodeVisitor):
    def __init__(
        self,
        analyzer: _AstAnalyzer,
        *,
        protected: dict[str, str],
        known_nonempty: dict[str, str],
        scope: str | None,
    ) -> None:
        self.analyzer = analyzer
        self.protected = protected
        self.known_nonempty = known_nonempty
        self.scope = scope

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        if isinstance(node.op, ast.And):
            protected = dict(self.protected)
            for value in node.values:
                _ExpressionScanner(
                    self.analyzer,
                    protected=protected,
                    known_nonempty=self.known_nonempty,
                    scope=self.scope,
                ).visit(value)
                for name in _truthy_nonempty_names(value):
                    protected[name] = "short_circuit_guard"
            return
        for value in node.values:
            _ExpressionScanner(
                self.analyzer,
                protected=dict(self.protected),
                known_nonempty=self.known_nonempty,
                scope=self.scope,
            ).visit(value)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        signal = _index_kind(node.slice)
        if signal is not None:
            variable = _name(node.value) or ast.unparse(node.value)
            suppression = None
            if _is_non_empty_literal(node.value):
                suppression = "statically_non_empty"
            elif isinstance(node.value, ast.Name):
                suppression = self.known_nonempty.get(node.value.id) or self.protected.get(
                    node.value.id
                )
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
            if _is_non_empty_literal(collection):
                suppression = "statically_non_empty"
            elif isinstance(collection, ast.Name):
                suppression = self.known_nonempty.get(collection.id) or self.protected.get(
                    collection.id
                )
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
        known_nonempty: dict[str, str],
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
        known_nonempty: dict[str, str] | None = None,
        known_nonblank: set[str] | None = None,
        safe_string_elements: set[str] | None = None,
        aliases: dict[str, str] | None = None,
        scope: str | None = None,
        in_loop: bool = False,
    ) -> None:
        current_protected = dict(protected or {})
        current_nonempty = dict(known_nonempty or {})
        current_nonblank = set(known_nonblank or ())
        current_safe_elements = set(safe_string_elements or ())
        current_aliases = dict(aliases or {})

        def invalidate(names: set[str]) -> None:
            canonical_names = {current_aliases.get(name, name) for name in names}
            affected = set(names) | canonical_names
            affected.update(
                alias
                for alias, canonical in current_aliases.items()
                if canonical in canonical_names
            )
            for name in affected:
                current_nonempty.pop(name, None)
                current_protected.pop(name, None)
                current_nonblank.discard(name)
                current_safe_elements.discard(name)
            current_aliases_copy = dict(current_aliases)
            for alias, canonical in current_aliases_copy.items():
                if alias in affected or canonical in canonical_names:
                    current_aliases.pop(alias, None)

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
                    known_nonempty=dict(current_nonempty),
                    known_nonblank=set(current_nonblank),
                    safe_string_elements=set(current_safe_elements),
                    aliases=dict(current_aliases),
                    scope=scope,
                    in_loop=in_loop,
                )
                self.scan_block(
                    statement.orelse,
                    protected=else_protected,
                    known_nonempty=dict(current_nonempty),
                    known_nonblank=set(current_nonblank),
                    safe_string_elements=set(current_safe_elements),
                    aliases=dict(current_aliases),
                    scope=scope,
                    in_loop=in_loop,
                )
                body_exits = _definitely_exits(statement.body, in_loop=in_loop)
                else_exits = _definitely_exits(statement.orelse, in_loop=in_loop)
                if body_exits:
                    false_nonempty, false_nonblank = _false_path_facts(statement.test)
                    for variable in false_nonempty:
                        current_protected[variable] = "early_exit_guard"
                    current_nonblank.update(false_nonblank)
                branch_mutations: set[str] = set()
                if not body_exits:
                    branch_mutations.update(_mutated_names(statement.body))
                if statement.orelse and not else_exits:
                    branch_mutations.update(_mutated_names(statement.orelse))
                invalidate(branch_mutations)
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                self.scan_expression(
                    statement.iter,
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    scope=scope,
                )
                loop_nonempty = dict(current_nonempty)
                loop_nonblank = set(current_nonblank)
                loop_safe_elements = set(current_safe_elements)
                loop_aliases = dict(current_aliases)
                assigned = _assigned_names((statement.target,))
                for name in assigned:
                    loop_nonempty.pop(name, None)
                    loop_nonblank.discard(name)
                    loop_safe_elements.discard(name)
                    loop_aliases.pop(name, None)
                self.scan_block(
                    statement.body,
                    protected={
                        name: reason
                        for name, reason in current_protected.items()
                        if name not in assigned
                    },
                    known_nonempty=loop_nonempty,
                    known_nonblank=loop_nonblank,
                    safe_string_elements=loop_safe_elements,
                    aliases=loop_aliases,
                    scope=scope,
                    in_loop=True,
                )
                self.scan_block(
                    statement.orelse,
                    protected=dict(current_protected),
                    known_nonempty=dict(current_nonempty),
                    known_nonblank=set(current_nonblank),
                    safe_string_elements=set(current_safe_elements),
                    aliases=dict(current_aliases),
                    scope=scope,
                    in_loop=in_loop,
                )
                continue
            if isinstance(statement, ast.While):
                self.scan_expression(
                    statement.test,
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    scope=scope,
                )
                self.scan_block(
                    statement.body,
                    protected=dict(current_protected),
                    known_nonempty=dict(current_nonempty),
                    known_nonblank=set(current_nonblank),
                    safe_string_elements=set(current_safe_elements),
                    aliases=dict(current_aliases),
                    scope=scope,
                    in_loop=True,
                )
                self.scan_block(
                    statement.orelse,
                    protected=dict(current_protected),
                    known_nonempty=dict(current_nonempty),
                    known_nonblank=set(current_nonblank),
                    safe_string_elements=set(current_safe_elements),
                    aliases=dict(current_aliases),
                    scope=scope,
                    in_loop=in_loop,
                )
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
                    unpacked_variable = _name(value) if value is not None else None
                    if unpacked_variable is not None:
                        suppression = current_protected.get(unpacked_variable)
                        self.add_candidate(
                            statement,
                            signal="fixed_length_unpack",
                            variable=unpacked_variable,
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
                assigned_alias: tuple[str, str] | None = None
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and isinstance(value, ast.Name)
                ):
                    assigned_alias = (
                        targets[0].id,
                        current_aliases.get(value.id, value.id),
                    )
                assignment_nonempty: dict[str, str] = {}
                assignment_nonblank: set[str] = set()
                if len(targets) == 1 and isinstance(targets[0], ast.Name) and value is not None:
                    target_name = targets[0].id
                    if _is_non_empty_literal(value):
                        assignment_nonempty[target_name] = "statically_non_empty"
                    if _proven_nonblank_string(value, current_nonblank):
                        assignment_nonempty[target_name] = "nonempty_string_provenance"
                        assignment_nonblank.add(target_name)
                    if (
                        isinstance(value, ast.Subscript)
                        and _index_kind(value.slice) is not None
                        and isinstance(value.value, ast.Name)
                        and value.value.id in current_safe_elements
                        and (
                            value.value.id in current_nonempty
                            or value.value.id in current_protected
                        )
                    ):
                        assignment_nonempty[target_name] = "nonempty_element_provenance"
                        assignment_nonblank.add(target_name)
                invalidate(assigned)
                if assigned_alias is not None and assigned_alias[0] != assigned_alias[1]:
                    current_aliases[assigned_alias[0]] = assigned_alias[1]
                current_nonempty.update(assignment_nonempty)
                current_nonblank.update(assignment_nonblank)
                if (
                    len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and value is not None
                    and _empty_collection_literal(value)
                ):
                    current_safe_elements.add(targets[0].id)
                for target in targets:
                    if not isinstance(target, ast.Subscript) or not isinstance(
                        target.value, ast.Name
                    ):
                        continue
                    collection = target.value.id
                    if value is None or not _proven_nonblank_string(value, current_nonblank):
                        current_safe_elements.discard(collection)
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
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute)
                and isinstance(statement.value.func.value, ast.Name)
            ):
                call = statement.value
                function = call.func
                assert isinstance(function, ast.Attribute)
                assert isinstance(function.value, ast.Name)
                local_collection = function.value.id
                collection = current_aliases.get(local_collection, local_collection)
                method = function.attr
                if method == "append" and len(call.args) == 1 and not call.keywords:
                    current_nonempty[collection] = "statically_non_empty"
                    if not _proven_nonblank_string(call.args[0], current_nonblank):
                        current_safe_elements.discard(collection)
                elif method == "clear" or method in {
                    "extend",
                    "insert",
                    "pop",
                    "remove",
                    "__delitem__",
                    "__setitem__",
                }:
                    invalidate({local_collection})
            for nested in (
                getattr(statement, "body", []),
                getattr(statement, "orelse", []),
                getattr(statement, "finalbody", []),
            ):
                if nested:
                    self.scan_block(
                        nested,
                        protected=dict(current_protected),
                        known_nonempty=dict(current_nonempty),
                        known_nonblank=set(current_nonblank),
                        safe_string_elements=set(current_safe_elements),
                        aliases=dict(current_aliases),
                        scope=scope,
                        in_loop=in_loop,
                    )
            if isinstance(statement, (ast.Return, ast.Raise)) or (
                in_loop and isinstance(statement, (ast.Break, ast.Continue))
            ):
                break


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

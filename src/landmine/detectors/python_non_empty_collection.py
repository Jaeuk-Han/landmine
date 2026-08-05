"""Python AST detector for unchecked collection cardinality assumptions."""

from __future__ import annotations

import ast
from collections.abc import Iterable

from landmine.assumptions import AnalysisContext, AssumptionCandidate
from landmine.domain import AssumptionCategory


def _name(node: ast.AST) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


def _root_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Starred):
        return _root_name(node.value)
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return _root_name(node.value)
    return None


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


def _literal_integer_index(node: ast.AST) -> int | None:
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, int)
        and not isinstance(node.value, bool)
    ):
        return node.value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
        and not isinstance(node.operand.value, bool)
    ):
        return -node.operand.value
    return None


_FIXED_TUPLE_SUPPRESSION = (
    "The inner access is covered by an explicit fixed-length tuple element contract."
)


def _bound_names(statement: ast.stmt) -> set[str]:
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {statement.name}
    if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        return _assigned_names(targets)
    if isinstance(statement, (ast.Import, ast.ImportFrom)):
        names: set[str] = set()
        for alias in statement.names:
            if alias.name == "*":
                continue
            names.add(alias.asname or alias.name.split(".", 1)[0])
        return names
    return set()


def _annotation_generic_name(
    node: ast.AST,
    *,
    builtin_name: str,
    typing_name: str,
    typing_modules: set[str],
    typing_aliases: set[str],
    builtin_available: bool,
) -> bool:
    if isinstance(node, ast.Name):
        return (builtin_available and node.id == builtin_name) or node.id in typing_aliases
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in typing_modules
        and node.attr == typing_name
    )


def _fixed_tuple_arity(
    annotation: ast.AST | None,
    *,
    typing_modules: set[str],
    list_aliases: set[str],
    tuple_aliases: set[str],
    builtin_list_available: bool,
    builtin_tuple_available: bool,
) -> int | None:
    if not isinstance(annotation, ast.Subscript):
        return None
    if not _annotation_generic_name(
        annotation.value,
        builtin_name="list",
        typing_name="List",
        typing_modules=typing_modules,
        typing_aliases=list_aliases,
        builtin_available=builtin_list_available,
    ):
        return None
    element = annotation.slice
    if not isinstance(element, ast.Subscript) or not _annotation_generic_name(
        element.value,
        builtin_name="tuple",
        typing_name="Tuple",
        typing_modules=typing_modules,
        typing_aliases=tuple_aliases,
        builtin_available=builtin_tuple_available,
    ):
        return None
    arguments = element.slice.elts if isinstance(element.slice, ast.Tuple) else [element.slice]
    if len(arguments) not in {2, 3} or any(
        isinstance(argument, ast.Constant) and argument.value is Ellipsis for argument in arguments
    ):
        return None
    return len(arguments)


def _module_fixed_tuple_helpers(tree: ast.Module) -> dict[str, int]:
    bindings: dict[str, list[ast.stmt]] = {}
    for statement in tree.body:
        for name in _bound_names(statement):
            bindings.setdefault(name, []).append(statement)

    typing_modules: set[str] = set()
    list_aliases: set[str] = set()
    tuple_aliases: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.name != "typing":
                    continue
                local_name = alias.asname or "typing"
                if bindings.get(local_name) == [statement]:
                    typing_modules.add(local_name)
        elif isinstance(statement, ast.ImportFrom) and statement.module == "typing":
            for alias in statement.names:
                local_name = alias.asname or alias.name
                if bindings.get(local_name) != [statement]:
                    continue
                if alias.name == "List":
                    list_aliases.add(local_name)
                elif alias.name == "Tuple":
                    tuple_aliases.add(local_name)

    helpers: dict[str, int] = {}
    for statement in tree.body:
        if not isinstance(statement, ast.FunctionDef):
            continue
        if statement.decorator_list or bindings.get(statement.name) != [statement]:
            continue
        arity = _fixed_tuple_arity(
            statement.returns,
            typing_modules=typing_modules,
            list_aliases=list_aliases,
            tuple_aliases=tuple_aliases,
            builtin_list_available="list" not in bindings,
            builtin_tuple_available="tuple" not in bindings,
        )
        if arity is not None:
            helpers[statement.name] = arity
    return helpers


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


def _empty_list_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.List) and not node.elts


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


class _LocalBindingCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.names.add(alias.asname or alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.names.add(alias.asname or alias.name)


def _function_local_bindings(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    collector = _LocalBindingCollector()
    for statement in node.body:
        collector.visit(statement)
    arguments = (
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    )
    collector.names.update(argument.arg for argument in arguments)
    if node.args.vararg is not None:
        collector.names.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        collector.names.add(node.args.kwarg.arg)
    return collector.names


class _PotentialMutationCollector(ast.NodeVisitor):
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

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id == "len":
            self.generic_visit(node)
            return
        if isinstance(node.func, ast.Attribute):
            receiver = _root_name(node.func.value)
            if receiver is not None:
                self.names.add(receiver)
        for argument in node.args:
            name = _root_name(argument)
            if name is not None:
                self.names.add(name)
        for keyword in node.keywords:
            name = _root_name(keyword.value)
            if name is not None:
                self.names.add(name)
        self.generic_visit(node)


def _potentially_mutated_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    collector = _PotentialMutationCollector()
    collector.visit(node)
    return collector.names


def _potentially_mutated_names_in(statements: list[ast.stmt]) -> set[str]:
    names: set[str] = set()
    for statement in statements:
        names.update(_potentially_mutated_names(statement))
    return names


class _ExpressionScanner(ast.NodeVisitor):
    def __init__(
        self,
        analyzer: _AstAnalyzer,
        *,
        protected: dict[str, str],
        known_nonempty: dict[str, str],
        fixed_tuple_elements: dict[str, int],
        scope: str | None,
    ) -> None:
        self.analyzer = analyzer
        self.protected = protected
        self.known_nonempty = known_nonempty
        self.fixed_tuple_elements = fixed_tuple_elements
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
                    fixed_tuple_elements=self.fixed_tuple_elements,
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
                fixed_tuple_elements=self.fixed_tuple_elements,
                scope=self.scope,
            ).visit(value)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        signal = _index_kind(node.slice)
        fixed_tuple_suppression = False
        if (
            isinstance(node.value, ast.Subscript)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id in self.fixed_tuple_elements
        ):
            index = _literal_integer_index(node.slice)
            arity = self.fixed_tuple_elements[node.value.value.id]
            fixed_tuple_suppression = index is not None and -arity <= index < arity
            if fixed_tuple_suppression and signal is None:
                signal = "fixed_tuple_index"
        if signal is not None:
            variable = _name(node.value) or ast.unparse(node.value)
            suppression = _FIXED_TUPLE_SUPPRESSION if fixed_tuple_suppression else None
            if suppression is None and _is_non_empty_literal(node.value):
                suppression = "statically_non_empty"
            elif suppression is None and isinstance(node.value, ast.Name):
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
    def __init__(self, context: AnalysisContext, *, fixed_tuple_helpers: dict[str, int]) -> None:
        self.context = context
        self.candidates: list[AssumptionCandidate] = []
        self.fixed_tuple_helpers = fixed_tuple_helpers

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
        fixed_tuple_elements: dict[str, int],
        aliases: dict[str, str],
        scope: str | None,
    ) -> None:
        if node is not None:
            possibly_mutated = {
                aliases.get(name, name) for name in _potentially_mutated_names(node)
            }
            _ExpressionScanner(
                self,
                protected=protected,
                known_nonempty=known_nonempty,
                fixed_tuple_elements={
                    name: arity
                    for name, arity in fixed_tuple_elements.items()
                    if name not in possibly_mutated
                },
                scope=scope,
            ).visit(node)

    def fixed_tuple_assignment_arity(
        self,
        node: ast.AST,
        *,
        blocked_helpers: set[str],
    ) -> int | None:
        call = node
        if isinstance(node, ast.IfExp):
            if _empty_list_literal(node.body):
                call = node.orelse
            elif _empty_list_literal(node.orelse):
                call = node.body
            else:
                return None
        if (
            not isinstance(call, ast.Call)
            or not isinstance(call.func, ast.Name)
            or call.func.id in blocked_helpers
        ):
            return None
        return self.fixed_tuple_helpers.get(call.func.id)

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        protected: dict[str, str] | None = None,
        known_nonempty: dict[str, str] | None = None,
        known_nonblank: set[str] | None = None,
        safe_string_elements: set[str] | None = None,
        aliases: dict[str, str] | None = None,
        fixed_tuple_elements: dict[str, int] | None = None,
        blocked_helpers: set[str] | None = None,
        allow_fixed_tuple_contracts: bool = False,
        scope: str | None = None,
        in_loop: bool = False,
    ) -> None:
        current_protected = dict(protected or {})
        current_nonempty = dict(known_nonempty or {})
        current_nonblank = set(known_nonblank or ())
        current_safe_elements = set(safe_string_elements or ())
        current_aliases = dict(aliases or {})
        current_fixed_tuple_elements = dict(fixed_tuple_elements or {})
        current_blocked_helpers = set(blocked_helpers or ())

        def invalidate_fixed(names: set[str]) -> None:
            canonical_names = {current_aliases.get(name, name) for name in names}
            for name in canonical_names:
                current_fixed_tuple_elements.pop(name, None)

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
                current_fixed_tuple_elements.pop(name, None)
            current_aliases_copy = dict(current_aliases)
            for alias, canonical in current_aliases_copy.items():
                if alias in affected or canonical in canonical_names:
                    current_aliases.pop(alias, None)

        for statement in statements:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scan_block(
                    statement.body,
                    blocked_helpers=_function_local_bindings(statement),
                    allow_fixed_tuple_contracts=True,
                    scope=statement.name,
                )
                continue
            if isinstance(statement, ast.ClassDef):
                self.scan_block(statement.body, scope=statement.name)
                continue
            if isinstance(statement, ast.If):
                self.scan_expression(
                    statement.test,
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    fixed_tuple_elements=current_fixed_tuple_elements,
                    aliases=current_aliases,
                    scope=scope,
                )
                invalidate_fixed(_potentially_mutated_names(statement.test))
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
                    fixed_tuple_elements=dict(current_fixed_tuple_elements),
                    blocked_helpers=current_blocked_helpers,
                    allow_fixed_tuple_contracts=allow_fixed_tuple_contracts,
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
                    fixed_tuple_elements=dict(current_fixed_tuple_elements),
                    blocked_helpers=current_blocked_helpers,
                    allow_fixed_tuple_contracts=allow_fixed_tuple_contracts,
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
                invalidate_fixed(
                    _potentially_mutated_names_in(statement.body)
                    | _potentially_mutated_names_in(statement.orelse)
                )
                continue
            if isinstance(statement, (ast.For, ast.AsyncFor)):
                self.scan_expression(
                    statement.iter,
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    fixed_tuple_elements=current_fixed_tuple_elements,
                    aliases=current_aliases,
                    scope=scope,
                )
                invalidate_fixed(_potentially_mutated_names(statement.iter))
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
                    fixed_tuple_elements=dict(current_fixed_tuple_elements),
                    blocked_helpers=current_blocked_helpers,
                    allow_fixed_tuple_contracts=allow_fixed_tuple_contracts,
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
                    fixed_tuple_elements=dict(current_fixed_tuple_elements),
                    blocked_helpers=current_blocked_helpers,
                    allow_fixed_tuple_contracts=allow_fixed_tuple_contracts,
                    scope=scope,
                    in_loop=in_loop,
                )
                invalidate_fixed(
                    _mutated_names(statement.body)
                    | _mutated_names(statement.orelse)
                    | _potentially_mutated_names_in(statement.body)
                    | _potentially_mutated_names_in(statement.orelse)
                )
                continue
            if isinstance(statement, ast.While):
                self.scan_expression(
                    statement.test,
                    protected=current_protected,
                    known_nonempty=current_nonempty,
                    fixed_tuple_elements=current_fixed_tuple_elements,
                    aliases=current_aliases,
                    scope=scope,
                )
                invalidate_fixed(_potentially_mutated_names(statement.test))
                self.scan_block(
                    statement.body,
                    protected=dict(current_protected),
                    known_nonempty=dict(current_nonempty),
                    known_nonblank=set(current_nonblank),
                    safe_string_elements=set(current_safe_elements),
                    aliases=dict(current_aliases),
                    fixed_tuple_elements=dict(current_fixed_tuple_elements),
                    blocked_helpers=current_blocked_helpers,
                    allow_fixed_tuple_contracts=allow_fixed_tuple_contracts,
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
                    fixed_tuple_elements=dict(current_fixed_tuple_elements),
                    blocked_helpers=current_blocked_helpers,
                    allow_fixed_tuple_contracts=allow_fixed_tuple_contracts,
                    scope=scope,
                    in_loop=in_loop,
                )
                invalidate_fixed(
                    _mutated_names(statement.body)
                    | _mutated_names(statement.orelse)
                    | _potentially_mutated_names_in(statement.body)
                    | _potentially_mutated_names_in(statement.orelse)
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
                    fixed_tuple_elements=current_fixed_tuple_elements,
                    aliases=current_aliases,
                    scope=scope,
                )
                assigned = _assigned_names(targets)
                assigned_fixed_tuple: tuple[str, int] | None = None
                if (
                    allow_fixed_tuple_contracts
                    and len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and value is not None
                ):
                    arity = self.fixed_tuple_assignment_arity(
                        value,
                        blocked_helpers=current_blocked_helpers,
                    )
                    if arity is not None:
                        assigned_fixed_tuple = (targets[0].id, arity)
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
                invalidate_fixed(_potentially_mutated_names(value))
                invalidate_fixed(
                    {
                        target.value.id
                        for target in targets
                        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                    }
                )
                if assigned_alias is not None and assigned_alias[0] != assigned_alias[1]:
                    current_aliases[assigned_alias[0]] = assigned_alias[1]
                if assigned_fixed_tuple is not None:
                    current_fixed_tuple_elements[assigned_fixed_tuple[0]] = assigned_fixed_tuple[1]
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
                    fixed_tuple_elements=current_fixed_tuple_elements,
                    aliases=current_aliases,
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
            invalidate_fixed(_potentially_mutated_names(statement))
            invalidate_fixed(_mutated_names([statement]))
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
                        fixed_tuple_elements=dict(current_fixed_tuple_elements),
                        blocked_helpers=current_blocked_helpers,
                        allow_fixed_tuple_contracts=allow_fixed_tuple_contracts,
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
        analyzer = _AstAnalyzer(
            context,
            fixed_tuple_helpers=_module_fixed_tuple_helpers(tree),
        )
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

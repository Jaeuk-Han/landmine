"""Python AST detector for file access resolved relative to the process CWD."""

from __future__ import annotations

import ast
import ntpath
import posixpath
from dataclasses import dataclass

from landmine.assumptions import (
    AnalysisContext,
    AssumptionCandidate,
    ProvenanceObservation,
)
from landmine.domain import AssumptionCategory

_PATH_OPERATIONS = {
    "open",
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "touch",
    "unlink",
    "stat",
    "iterdir",
    "mkdir",
    "rename",
    "replace",
}


@dataclass(frozen=True)
class _PathValue:
    path: str
    api_binding: str
    provenance: tuple[ProvenanceObservation, ...]
    anchor: str | None = None


@dataclass
class _Bindings:
    path_classes: set[str]
    pathlib_modules: set[str]
    importlib_modules: set[str]
    resource_modules: set[str]
    os_modules: set[str]
    builtin_open: bool = True

    def copy(self) -> _Bindings:
        return _Bindings(
            set(self.path_classes),
            set(self.pathlib_modules),
            set(self.importlib_modules),
            set(self.resource_modules),
            set(self.os_modules),
            self.builtin_open,
        )

    def invalidate(self, names: set[str]) -> None:
        self.path_classes.difference_update(names)
        self.pathlib_modules.difference_update(names)
        self.importlib_modules.difference_update(names)
        self.resource_modules.difference_update(names)
        self.os_modules.difference_update(names)
        if "open" in names:
            self.builtin_open = False


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


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_absolute(path: str) -> bool:
    return posixpath.isabs(path) or ntpath.isabs(path)


def _normalize_relative(path: str) -> str:
    normalized = posixpath.normpath(path.replace("\\", "/"))
    return "." if normalized == "" else normalized


def _path_constructor_name(node: ast.AST, bindings: _Bindings) -> str | None:
    if isinstance(node, ast.Name) and node.id in bindings.path_classes:
        return node.id
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "Path"
        and isinstance(node.value, ast.Name)
        and node.value.id in bindings.pathlib_modules
    ):
        return f"{node.value.id}.Path"
    return None


def _path_class_method(
    node: ast.AST,
    bindings: _Bindings,
) -> tuple[str, str] | None:
    if not isinstance(node, ast.Attribute):
        return None
    constructor = _path_constructor_name(node.value, bindings)
    if constructor is None:
        return None
    return constructor, node.attr


def _is_dunder_file(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "__file__"


def _is_os_path_attribute(
    node: ast.AST,
    *,
    bindings: _Bindings,
    name: str,
) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == name
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "path"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id in bindings.os_modules
    )


def _is_file_dirname(node: ast.AST, bindings: _Bindings) -> bool:
    return (
        isinstance(node, ast.Call)
        and _is_os_path_attribute(node.func, bindings=bindings, name="dirname")
        and len(node.args) == 1
        and _is_dunder_file(node.args[0])
    )


def _resource_files_binding(node: ast.AST, bindings: _Bindings) -> str | None:
    if not isinstance(node, ast.Attribute) or node.attr != "files":
        return None
    if isinstance(node.value, ast.Name) and node.value.id in bindings.resource_modules:
        return node.value.id
    if (
        isinstance(node.value, ast.Attribute)
        and node.value.attr == "resources"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id in bindings.importlib_modules
    ):
        return f"{node.value.value.id}.resources"
    return None


class _FilesystemAnalyzer:
    def __init__(self, context: AnalysisContext) -> None:
        self.context = context
        self.candidates: dict[tuple[int, int, str, str], AssumptionCandidate] = {}

    def _in_target(self, node: ast.AST) -> bool:
        line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", None) or line
        return line <= self.context.end_line and end_line >= self.context.start_line

    def _path_value(
        self,
        node: ast.AST,
        *,
        bindings: _Bindings,
        paths: dict[str, _PathValue],
    ) -> _PathValue | None:
        if isinstance(node, ast.Name):
            return paths.get(node.id)
        if isinstance(node, ast.Attribute) and node.attr == "parent":
            return self._path_value(node.value, bindings=bindings, paths=paths)
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "resolve"
                and not node.args
                and not node.keywords
            ):
                return self._path_value(node.func.value, bindings=bindings, paths=paths)
            class_method = _path_class_method(node.func, bindings)
            if class_method is not None and not node.args and not node.keywords:
                constructor, method = class_method
                if method in {"cwd", "home"}:
                    anchor = "explicit_cwd_anchor" if method == "cwd" else "home_anchor"
                    return _PathValue(
                        path=f"<{anchor}>",
                        api_binding=f"{constructor}.{method}",
                        provenance=(_observation(anchor, node, ast.unparse(node)),),
                        anchor=anchor,
                    )
            resource_binding = _resource_files_binding(node.func, bindings)
            if resource_binding is not None and node.args:
                return _PathValue(
                    path="<package_resource_anchor>",
                    api_binding=f"{resource_binding}.files",
                    provenance=(_observation("package_resource_anchor", node, ast.unparse(node)),),
                    anchor="package_resource_anchor",
                )
            path_constructor = _path_constructor_name(node.func, bindings)
            if path_constructor is not None and len(node.args) == 1 and not node.keywords:
                literal = _literal_string(node.args[0])
                if literal is not None:
                    if _is_absolute(literal):
                        return None
                    normalized = _normalize_relative(literal)
                    return _PathValue(
                        path=normalized,
                        api_binding="pathlib.Path",
                        provenance=(_observation("path_construction", node, ast.unparse(node)),),
                    )
                if _is_dunder_file(node.args[0]):
                    return _PathValue(
                        path="<file_relative_anchor>",
                        api_binding="pathlib.Path",
                        provenance=(_observation("file_relative_anchor", node, ast.unparse(node)),),
                        anchor="file_relative_anchor",
                    )
            if (
                _is_os_path_attribute(node.func, bindings=bindings, name="join")
                and len(node.args) >= 2
                and _is_file_dirname(node.args[0], bindings)
                and all(_literal_string(argument) is not None for argument in node.args[1:])
            ):
                segments = [_literal_string(argument) for argument in node.args[1:]]
                return _PathValue(
                    path="/".join(segment for segment in segments if segment is not None),
                    api_binding="os.path.join",
                    provenance=(_observation("file_relative_anchor", node, ast.unparse(node)),),
                    anchor="file_relative_anchor",
                )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            base = self._path_value(node.left, bindings=bindings, paths=paths)
            segment = _literal_string(node.right)
            if base is not None and segment is not None and not _is_absolute(segment):
                joined = (
                    _normalize_relative(f"{base.path}/{segment}")
                    if base.anchor is None
                    else f"{base.path}/{_normalize_relative(segment)}"
                )
                return _PathValue(
                    path=joined,
                    api_binding=base.api_binding,
                    provenance=base.provenance
                    + (_observation("literal_path_join", node, ast.unparse(node)),),
                    anchor=base.anchor,
                )
        return None

    def _add_candidate(
        self,
        node: ast.Call,
        path_value: _PathValue,
        *,
        operation: str,
        api_binding: str,
        scope: str | None,
        handled_file_not_found: bool,
    ) -> None:
        if not self._in_target(node):
            return
        suppression_reason = path_value.anchor
        uncertainty_parts: list[str] = []
        if path_value.path == "~" or path_value.path.startswith("~/"):
            uncertainty_parts.append(
                "A leading tilde is not automatically expanded by open or pathlib.Path "
                "and remains relative to the process working directory."
            )
        if handled_file_not_found:
            uncertainty_parts.append(
                "FileNotFoundError may be handled, but the working-directory resolution "
                "dependency remains."
            )
        identity = (node.lineno, node.col_offset, operation, path_value.path)
        self.candidates[identity] = AssumptionCandidate(
            detector_id=PythonCwdRelativeFileAccessDetector.detector_id,
            category=PythonCwdRelativeFileAccessDetector.category,
            path=self.context.path,
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            column=node.col_offset,
            observed_signal="cwd_relative_file_access",
            variable=path_value.path,
            claim=(f"The process working directory is assumed to contain `{path_value.path}`."),
            violation_scenario="The application starts from a different working directory.",
            consequence=("The file resolves to a different location or raises FileNotFoundError."),
            confidence=0.76,
            confidence_ceiling=0.79,
            scope=scope,
            suppression_reason=suppression_reason,
            provenance=path_value.provenance,
            suggested_alternatives=(
                "anchor to Path(__file__).resolve().parent",
                "accept a path through configuration or function input",
                "use importlib.resources for packaged data",
                "document and validate the required working directory",
            ),
            uncertainty_note=" ".join(uncertainty_parts) or None,
            path_literal=path_value.path,
            access_operation=operation,
            api_binding=api_binding,
            path_anchor=path_value.anchor,
        )

    def _scan_expression(
        self,
        node: ast.AST | None,
        *,
        bindings: _Bindings,
        paths: dict[str, _PathValue],
        scope: str | None,
        handled_file_not_found: bool,
    ) -> None:
        if node is None:
            return
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "open"
                and bindings.builtin_open
                and node.args
            ):
                literal = _literal_string(node.args[0])
                path_value = (
                    None
                    if literal is not None and _is_absolute(literal)
                    else (
                        _PathValue(
                            path=_normalize_relative(literal),
                            api_binding="builtins.open",
                            provenance=(_observation("path_literal", node.args[0], literal),),
                        )
                        if literal is not None
                        else self._path_value(node.args[0], bindings=bindings, paths=paths)
                    )
                )
                if path_value is not None:
                    self._add_candidate(
                        node,
                        path_value,
                        operation="open",
                        api_binding="builtins.open",
                        scope=scope,
                        handled_file_not_found=handled_file_not_found,
                    )
                    return
            if isinstance(node.func, ast.Attribute) and node.func.attr in _PATH_OPERATIONS:
                path_value = self._path_value(node.func.value, bindings=bindings, paths=paths)
                if path_value is not None:
                    self._add_candidate(
                        node,
                        path_value,
                        operation=node.func.attr,
                        api_binding="pathlib.Path",
                        scope=scope,
                        handled_file_not_found=handled_file_not_found,
                    )
                    return
        for child in ast.iter_child_nodes(node):
            self._scan_expression(
                child,
                bindings=bindings,
                paths=paths,
                scope=scope,
                handled_file_not_found=handled_file_not_found,
            )

    def _handle_import(self, node: ast.Import | ast.ImportFrom, bindings: _Bindings) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".", 1)[0]
                bindings.invalidate({bound})
                if alias.name == "pathlib":
                    bindings.pathlib_modules.add(bound)
                elif alias.name == "os":
                    bindings.os_modules.add(bound)
                elif alias.name == "importlib" or alias.name == "importlib.resources":
                    bindings.importlib_modules.add(bound)
                if alias.name == "importlib.resources" and alias.asname is not None:
                    bindings.resource_modules.add(bound)
            return
        if node.module == "pathlib":
            for alias in node.names:
                bound = alias.asname or alias.name
                bindings.invalidate({bound})
                if alias.name == "Path":
                    bindings.path_classes.add(bound)
        elif node.module == "importlib":
            for alias in node.names:
                bound = alias.asname or alias.name
                bindings.invalidate({bound})
                if alias.name == "resources":
                    bindings.resource_modules.add(bound)

    def scan_block(
        self,
        statements: list[ast.stmt],
        *,
        bindings: _Bindings | None = None,
        paths: dict[str, _PathValue] | None = None,
        scope: str | None = None,
        handled_file_not_found: bool = False,
        track_assignments: bool = True,
    ) -> None:
        current_bindings = (
            bindings.copy()
            if bindings is not None
            else _Bindings(set(), set(), set(), set(), set())
        )
        current_paths = dict(paths or {})
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
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=handled_file_not_found,
                )
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                path_value = (
                    self._path_value(value, bindings=current_bindings, paths=current_paths)
                    if value is not None
                    else None
                )
                names = set().union(*(_bound_names(target) for target in targets))
                current_bindings.invalidate(names)
                for name in names:
                    current_paths.pop(name, None)
                if (
                    track_assignments
                    and len(targets) == 1
                    and isinstance(targets[0], ast.Name)
                    and path_value is not None
                ):
                    current_paths[targets[0].id] = path_value
                continue
            if isinstance(statement, ast.Try):
                catches_file_not_found = any(
                    isinstance(handler.type, ast.Name) and handler.type.id == "FileNotFoundError"
                    for handler in statement.handlers
                )
                self.scan_block(
                    statement.body,
                    bindings=current_bindings,
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=(handled_file_not_found or catches_file_not_found),
                )
                for handler in statement.handlers:
                    self.scan_block(
                        handler.body,
                        bindings=current_bindings,
                        paths=current_paths,
                        scope=scope,
                        handled_file_not_found=handled_file_not_found,
                    )
                self.scan_block(
                    statement.orelse,
                    bindings=current_bindings,
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=handled_file_not_found,
                )
                self.scan_block(
                    statement.finalbody,
                    bindings=current_bindings,
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=handled_file_not_found,
                )
                continue
            if isinstance(statement, ast.If):
                self._scan_expression(
                    statement.test,
                    bindings=current_bindings,
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=handled_file_not_found,
                )
                self.scan_block(
                    statement.body,
                    bindings=current_bindings,
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=handled_file_not_found,
                    track_assignments=False,
                )
                self.scan_block(
                    statement.orelse,
                    bindings=current_bindings,
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=handled_file_not_found,
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
                    paths=current_paths,
                    scope=scope,
                    handled_file_not_found=handled_file_not_found,
                )
            for nested_name in ("body", "orelse", "finalbody"):
                nested = getattr(statement, nested_name, [])
                if nested:
                    self.scan_block(
                        nested,
                        bindings=current_bindings,
                        paths=current_paths,
                        scope=scope,
                        handled_file_not_found=handled_file_not_found,
                        track_assignments=False,
                    )


class PythonCwdRelativeFileAccessDetector:
    detector_id = "python.cwd-relative-file-access"
    category = AssumptionCategory.FILESYSTEM

    def detect(self, context: AnalysisContext) -> list[AssumptionCandidate]:
        tree = ast.parse(context.source, filename=context.path)
        analyzer = _FilesystemAnalyzer(context)
        analyzer.scan_block(tree.body)
        return [
            analyzer.candidates[key]
            for key in sorted(
                analyzer.candidates,
                key=lambda item: (item[0], item[1], item[2], item[3]),
            )
        ]

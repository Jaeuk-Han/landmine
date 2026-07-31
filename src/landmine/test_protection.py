"""Conservative Python test-reference and empty-input discovery."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class ResponseMock:
    library: str
    method: str
    fields: tuple[str, ...]


@dataclass(frozen=True)
class TestProtectionMatch:
    path: str
    scope: str
    line: int
    matching_text: str
    empty_input: bool
    mapping_keys: tuple[str, ...] | None = None
    expects_key_error: bool = False
    removed_environment_variables: tuple[str, ...] = ()
    response_mocks: tuple[ResponseMock, ...] = ()


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


def _mapping_literal_keys(node: ast.AST) -> tuple[str, ...] | None:
    if not isinstance(node, ast.Dict) or any(key is None for key in node.keys):
        return None
    return tuple(
        sorted(
            {
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
        )
    )


def _is_pytest_raises_key_error(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
        and node.func.attr == "raises"
        and bool(node.args)
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "KeyError"
    )


def _proven_patch_target(node: ast.AST) -> tuple[str, str] | None:
    if (
        not isinstance(node, ast.Call)
        or not isinstance(node.func, ast.Attribute)
        or node.func.attr != "patch"
        or not isinstance(node.func.value, ast.Name)
        or node.func.value.id != "mocker"
        or not node.args
        or not isinstance(node.args[0], ast.Constant)
        or not isinstance(node.args[0].value, str)
    ):
        return None
    parts = node.args[0].value.split(".")
    if (
        len(parts) == 2
        and parts[0] in {"requests", "httpx"}
        and parts[1] in {"get", "post", "put", "patch", "delete", "request"}
    ):
        return parts[0], parts[1]
    return None


def _mock_json_return_root(node: ast.AST) -> str | None:
    attributes: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        attributes.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name) and tuple(reversed(attributes)) == (
        "return_value",
        "json",
        "return_value",
    ):
        return current.id
    return None


class _TestVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source_lines: list[str], scopes: set[str]) -> None:
        self.path = path
        self.source_lines = source_lines
        self.scopes = scopes
        self.empty_names: set[str] = set()
        self.mapping_names: dict[str, tuple[str, ...]] = {}
        self.removed_environment_variables: set[str] = set()
        self.proven_http_mocks: dict[str, tuple[str, str]] = {}
        self.response_mock_fields: dict[str, tuple[str, ...]] = {}
        self.expects_key_error = False
        self.matches: list[TestProtectionMatch] = []

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        previous = self.empty_names
        previous_mappings = self.mapping_names
        previous_removed_environment = self.removed_environment_variables
        previous_http_mocks = self.proven_http_mocks
        previous_response_fields = self.response_mock_fields
        self.empty_names = set()
        self.mapping_names = {}
        self.removed_environment_variables = set()
        self.proven_http_mocks = {}
        self.response_mock_fields = {}
        for statement in node.body:
            self.visit(statement)
        self.empty_names = previous
        self.mapping_names = previous_mappings
        self.removed_environment_variables = previous_removed_environment
        self.proven_http_mocks = previous_http_mocks
        self.response_mock_fields = previous_response_fields

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        mapping_keys = _mapping_literal_keys(node.value)
        patch_target = _proven_patch_target(node.value)
        for target in node.targets:
            mock_root = _mock_json_return_root(target)
            if (
                mock_root is not None
                and mock_root in self.proven_http_mocks
                and mapping_keys is not None
            ):
                self.response_mock_fields[mock_root] = mapping_keys
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.empty_names.discard(target.id)
                self.mapping_names.pop(target.id, None)
                self.proven_http_mocks.pop(target.id, None)
                self.response_mock_fields.pop(target.id, None)
                if _is_empty_expression(node.value):
                    self.empty_names.add(target.id)
                if mapping_keys is not None:
                    self.mapping_names[target.id] = mapping_keys
                if patch_target is not None:
                    self.proven_http_mocks[target.id] = patch_target

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            if isinstance(node.target, ast.Name):
                self.empty_names.discard(node.target.id)
                self.mapping_names.pop(node.target.id, None)
                if _is_empty_expression(node.value):
                    self.empty_names.add(node.target.id)
                mapping_keys = _mapping_literal_keys(node.value)
                if mapping_keys is not None:
                    self.mapping_names[node.target.id] = mapping_keys

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
        previous = self.expects_key_error
        self.expects_key_error = previous or any(
            _is_pytest_raises_key_error(item.context_expr) for item in node.items
        )
        for statement in node.body:
            self.visit(statement)
        self.expects_key_error = previous

    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "monkeypatch"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            environment_variable = node.args[0].value
            if node.func.attr == "delenv" and any(
                keyword.arg == "raising"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            ):
                self.removed_environment_variables.add(environment_variable)
            elif node.func.attr == "setenv":
                self.removed_environment_variables.discard(environment_variable)
        scope = _called_name(node.func)
        if scope in self.scopes:
            mapping_keys = None
            for argument in node.args:
                direct_keys = _mapping_literal_keys(argument)
                if direct_keys is not None:
                    mapping_keys = direct_keys
                    break
                if isinstance(argument, ast.Name) and argument.id in self.mapping_names:
                    mapping_keys = self.mapping_names[argument.id]
                    break
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
                    mapping_keys=mapping_keys,
                    expects_key_error=self.expects_key_error,
                    removed_environment_variables=tuple(sorted(self.removed_environment_variables)),
                    response_mocks=tuple(
                        sorted(
                            (
                                ResponseMock(
                                    library=library,
                                    method=method,
                                    fields=self.response_mock_fields[name],
                                )
                                for name, (library, method) in self.proven_http_mocks.items()
                                if name in self.response_mock_fields
                            ),
                            key=lambda item: (
                                item.library,
                                item.method,
                                item.fields,
                            ),
                        )
                    ),
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
    return tuple(
        sorted(
            set(visitor.matches),
            key=lambda item: (
                item.path,
                item.scope,
                item.line,
                not item.empty_input,
                item.mapping_keys is None,
                item.mapping_keys or (),
                not item.expects_key_error,
                item.removed_environment_variables,
                tuple((mock.library, mock.method, mock.fields) for mock in item.response_mocks),
            ),
        )
    )

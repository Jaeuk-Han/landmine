"""Deterministic temporary Git repositories used by integration tests."""

from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest


@dataclass
class GitFixture:
    root: Path
    commit_index: int = 0
    commits: dict[str, str] = field(default_factory=dict)

    def _run(self, arguments: list[str]) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Fixture Author",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture Committer",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        completed = subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            shell=False,
        )
        if completed.returncode:
            raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout.decode("utf-8", errors="replace").strip()

    def initialize(self) -> None:
        self.root.mkdir(parents=True)
        self._run(["init", "-b", "main"])

    def commit(
        self,
        tag: str,
        message: str,
        files: Mapping[str, str],
        *,
        remove: tuple[str, ...] = (),
    ) -> str:
        for relative, content in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        for relative in remove:
            path = self.root / relative
            if path.exists():
                path.unlink()
        self._run(["add", "--all"])
        moment = datetime(2024, 1, 1, tzinfo=UTC) + timedelta(minutes=self.commit_index)
        timestamp = moment.strftime("%Y-%m-%dT%H:%M:%S+0000")
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Fixture Author",
                "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                "GIT_COMMITTER_NAME": "Fixture Committer",
                "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                "GIT_AUTHOR_DATE": timestamp,
                "GIT_COMMITTER_DATE": timestamp,
                "GIT_CONFIG_NOSYSTEM": "1",
                "LC_ALL": "C",
            }
        )
        completed = subprocess.run(
            ["git", "commit", "--no-gpg-sign", "-m", message],
            cwd=self.root,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            shell=False,
        )
        if completed.returncode:
            raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))
        commit = self._run(["rev-parse", "HEAD"])
        self.commits[tag] = commit
        self.commit_index += 1
        return commit

    def rename(self, tag: str, old: str, new: str, message: str) -> str:
        destination = self.root / new
        destination.parent.mkdir(parents=True, exist_ok=True)
        (self.root / old).replace(destination)
        return self.commit(tag, message, {})


@pytest.fixture
def git_fixture(tmp_path: Path) -> GitFixture:
    fixture = GitFixture(tmp_path / "repository")
    fixture.initialize()
    return fixture


@pytest.fixture
def guard_after_incident(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add route selection",
        {
            "src/routing.py": ("def select_route(results):\n    return results[0]\n"),
            "tests/test_smoke.py": "def test_smoke():\n    assert True\n",
        },
    )
    git_fixture.commit(
        "introduce_guard",
        "Handle empty upstream response with fallback",
        {
            "src/routing.py": (
                "def select_route(results):\n"
                "    if not results:\n"
                '        return "fallback"\n'
                "    return results[0]\n"
            ),
            "tests/test_routing.py": (
                "from routing import select_route\n\n"
                "def test_empty_response_uses_fallback():\n"
                '    assert select_route([]) == "fallback"\n'
            ),
        },
    )
    return git_fixture


@pytest.fixture
def line_modified_after_guard(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial_behavior",
        "Add unsafe route selection",
        {
            "src/routing.py": (
                'def select_route(results):\n    label = "route"\n    return results[0]\n'
            )
        },
    )
    git_fixture.commit(
        "introduce_guard",
        "Guard empty route results after incident",
        {
            "src/routing.py": (
                'HospitalFallback = "fallback"\n'
                "\n"
                "def select_route(results):\n"
                '    label = "route"\n'
                "    if not results:\n"
                "        return HospitalFallback\n"
                "    return results[0]\n"
            ),
            "tests/test_routing.py": (
                "from routing import select_route\n\n"
                "def test_empty_results_use_fallback():\n"
                '    assert select_route([]) == "fallback"\n'
            ),
        },
    )
    git_fixture.commit(
        "refactor_guard",
        "Rename route result variable",
        {
            "src/routing.py": (
                'HospitalFallback: str = "fallback"\n'
                "\n"
                "def select_route(routes):\n"
                '    label = "route"\n'
                "    if not routes:\n"
                "        return HospitalFallback\n"
                "    return routes[0]\n"
            )
        },
    )
    git_fixture.commit(
        "format_unrelated",
        "Normalize unrelated label quoting",
        {
            "src/routing.py": (
                'HospitalFallback: str = "fallback"\n'
                "\n"
                "def select_route(routes):\n"
                "    label = 'route'\n"
                "    if not routes:\n"
                "        return HospitalFallback\n"
                "    return routes[0]\n"
            )
        },
    )
    return git_fixture


@pytest.fixture
def hidden_cardinality(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add processor cardinality behavior",
        {
            "src/processor.py": (
                "def process_unsafe(items):\n"
                "    return items[0]\n"
                "\n"
                "\n"
                "def process_guarded(items):\n"
                "    if not items:\n"
                "        return None\n"
                "    return items[0]\n"
                "\n"
                "\n"
                "def process_literal():\n"
                "    return [1, 2][0]\n"
                "\n"
                "\n"
                "def process_unpack(values):\n"
                "    head, tail = values\n"
                "    return head, tail\n"
            ),
            "tests/test_processor.py": (
                "from processor import process_guarded, process_unsafe\n"
                "\n"
                "\n"
                "def test_process_unsafe_with_values():\n"
                "    assert process_unsafe([1]) == 1\n"
                "\n"
                "\n"
                "def test_process_guarded_with_empty_input():\n"
                "    assert process_guarded([]) is None\n"
            ),
        },
    )
    return git_fixture


@pytest.fixture
def hidden_mapping_key(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add mapping key behavior",
        {
            "src/parser.py": (
                "def unsafe_access(payload):\n"
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def membership_guarded(payload):\n"
                '    if "user_id" in payload:\n'
                '        return payload["user_id"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def early_return_guarded(payload):\n"
                '    if "user_id" not in payload:\n'
                "        return None\n"
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def early_raise_guarded(payload):\n"
                '    if "user_id" not in payload:\n'
                '        raise ValueError("user_id required")\n'
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def assert_guarded(payload):\n"
                '    assert "user_id" in payload\n'
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def assigned_before_access(payload):\n"
                '    payload["user_id"] = create_id()\n'
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def literal_mapping():\n"
                '    payload = {"user_id": "known"}\n'
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def try_except_handled(payload):\n"
                "    try:\n"
                '        return payload["user_id"]\n'
                "    except KeyError:\n"
                "        return None\n"
                "\n"
                "\n"
                "def wrong_key_guard(payload):\n"
                '    if "other_key" in payload:\n'
                '        return payload["user_id"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def truthy_mapping_guard(payload):\n"
                "    if payload:\n"
                '        return payload["user_id"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def get_then_direct_access(payload):\n"
                '    payload.get("user_id")\n'
                '    return payload["user_id"]\n'
            ),
            "tests/test_parser.py": (
                "import pytest\n"
                "from parser import (\n"
                "    get_then_direct_access,\n"
                "    membership_guarded,\n"
                "    truthy_mapping_guard,\n"
                "    unsafe_access,\n"
                ")\n"
                "\n"
                "\n"
                "def test_unsafe_access_with_required_key():\n"
                '    assert unsafe_access({"user_id": 7}) == 7\n'
                "\n"
                "\n"
                "def test_membership_guarded_missing_key():\n"
                "    assert membership_guarded({}) is None\n"
                "\n"
                "\n"
                "def test_truthy_mapping_missing_key():\n"
                "    assert truthy_mapping_guard({}) is None\n"
                "\n"
                "\n"
                "def test_direct_access_characterizes_key_error():\n"
                "    with pytest.raises(KeyError):\n"
                "        get_then_direct_access({})\n"
            ),
        },
    )
    return git_fixture


@pytest.fixture
def hidden_environment_variable(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add environment configuration behavior",
        {
            "src/config.py": (
                "import os\n"
                "import os as operating_system\n"
                "from os import environ\n"
                "from os import environ as env\n"
                "\n"
                "\n"
                "def required_os_environ():\n"
                '    return os.environ["DATABASE_URL"]\n'
                "\n"
                "\n"
                "def required_aliased_os():\n"
                '    return operating_system.environ["API_TOKEN"]\n'
                "\n"
                "\n"
                "def required_imported_environ():\n"
                '    return environ["SECRET_KEY"]\n'
                "\n"
                "\n"
                "def required_aliased_environ():\n"
                '    return env["REGION"]\n'
                "\n"
                "\n"
                "def membership_guarded():\n"
                '    if "DATABASE_URL" in os.environ:\n'
                '        return os.environ["DATABASE_URL"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def early_return_guarded():\n"
                '    if "DATABASE_URL" not in os.environ:\n'
                "        return None\n"
                '    return os.environ["DATABASE_URL"]\n'
                "\n"
                "\n"
                "def early_raise_guarded():\n"
                '    if "DATABASE_URL" not in os.environ:\n'
                '        raise RuntimeError("required")\n'
                '    return os.environ["DATABASE_URL"]\n'
                "\n"
                "\n"
                "def assert_guarded():\n"
                '    assert "DATABASE_URL" in os.environ\n'
                '    return os.environ["DATABASE_URL"]\n'
                "\n"
                "\n"
                "def assigned_before_access():\n"
                '    os.environ["DATABASE_URL"] = "sqlite://"\n'
                '    return os.environ["DATABASE_URL"]\n'
                "\n"
                "\n"
                "def get_with_no_default():\n"
                '    return os.environ.get("DATABASE_URL")\n'
                "\n"
                "\n"
                "def getenv_with_default():\n"
                '    return os.getenv("DATABASE_URL", "sqlite://")\n'
                "\n"
                "\n"
                "def dynamic_key(key):\n"
                "    return os.environ[key]\n"
                "\n"
                "\n"
                "def custom_environ_mapping(custom_mapping):\n"
                "    environ = custom_mapping\n"
                '    return environ["CUSTOM_KEY"]\n'
                "\n"
                "\n"
                "def wrong_key_guard():\n"
                '    if "OTHER_KEY" in os.environ:\n'
                '        return os.environ["DATABASE_URL"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def truthy_environment_guard():\n"
                "    if os.environ:\n"
                '        return os.environ["DATABASE_URL"]\n'
                "    return None\n"
            ),
            "tests/test_config.py": (
                "import pytest\n"
                "\n"
                "from config import (\n"
                "    required_aliased_os,\n"
                "    required_imported_environ,\n"
                "    required_os_environ,\n"
                ")\n"
                "\n"
                "\n"
                "def test_required_os_environ_when_set(monkeypatch):\n"
                '    monkeypatch.setenv("DATABASE_URL", "sqlite://")\n'
                "    assert required_os_environ()\n"
                "\n"
                "\n"
                "def test_required_aliased_os_when_missing(monkeypatch):\n"
                '    monkeypatch.delenv("API_TOKEN", raising=False)\n'
                "    required_aliased_os()\n"
                "\n"
                "\n"
                "def test_required_imported_environ_characterizes_key_error(monkeypatch):\n"
                '    monkeypatch.delenv("SECRET_KEY", raising=False)\n'
                "    with pytest.raises(KeyError):\n"
                "        required_imported_environ()\n"
            ),
        },
    )
    return git_fixture


@pytest.fixture
def hidden_external_contract(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add external response consumers",
        {
            "src/client.py": (
                "import requests\n"
                "import requests as http\n"
                "import httpx\n"
                "import httpx as client\n"
                "\n"
                "\n"
                "def requests_direct_json_access(url):\n"
                "    response = requests.get(url)\n"
                '    return response.json()["user_id"]\n'
                "\n"
                "\n"
                "def requests_payload_assignment(url):\n"
                "    response = requests.post(url)\n"
                "    payload = response.json()\n"
                '    return payload["status"]\n'
                "\n"
                "\n"
                "def requests_alias(url):\n"
                "    response = http.put(url)\n"
                '    return response.json()["result"]\n'
                "\n"
                "\n"
                "def httpx_direct(url):\n"
                "    response = httpx.patch(url)\n"
                '    return response.json()["version"]\n'
                "\n"
                "\n"
                "def httpx_alias(url):\n"
                '    response = client.request("GET", url)\n'
                '    return response.json()["state"]\n'
                "\n"
                "\n"
                "def nested_response_field(url):\n"
                "    response = requests.get(url)\n"
                "    payload = response.json()\n"
                '    return payload["user"]["id"]\n'
                "\n"
                "\n"
                "def membership_guarded(url):\n"
                "    response = requests.get(url)\n"
                "    payload = response.json()\n"
                '    if "user_id" in payload:\n'
                '        return payload["user_id"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def early_return_guarded(url):\n"
                "    response = requests.get(url)\n"
                "    payload = response.json()\n"
                '    if "user_id" not in payload:\n'
                "        return None\n"
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def early_raise_guarded(url):\n"
                "    response = requests.get(url)\n"
                "    payload = response.json()\n"
                '    if "user_id" not in payload:\n'
                '        raise RuntimeError("contract field required")\n'
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def key_error_handled(url):\n"
                "    response = requests.get(url)\n"
                "    try:\n"
                '        return response.json()["user_id"]\n'
                "    except KeyError:\n"
                "        return None\n"
                "\n"
                "\n"
                "def raise_for_status_only(url):\n"
                "    response = requests.get(url)\n"
                "    response.raise_for_status()\n"
                '    return response.json()["user_id"]\n'
                "\n"
                "\n"
                "def status_code_guard_only(url):\n"
                "    response = requests.get(url)\n"
                "    if response.status_code == 200:\n"
                '        return response.json()["user_id"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def truthy_payload_guard(url):\n"
                "    response = requests.get(url)\n"
                "    payload = response.json()\n"
                "    if payload:\n"
                '        return payload["user_id"]\n'
                "    return None\n"
                "\n"
                "\n"
                "def payload_get_then_direct_access(url):\n"
                "    response = requests.get(url)\n"
                "    payload = response.json()\n"
                '    payload.get("user_id")\n'
                '    return payload["user_id"]\n'
                "\n"
                "\n"
                "def local_service_response(local_service):\n"
                "    response = local_service.get()\n"
                '    return response.json()["user_id"]\n'
                "\n"
                "\n"
                "def function_parameter_response(response):\n"
                '    return response.json()["user_id"]\n'
                "\n"
                "\n"
                "def rebound_requests_name(url, custom_client):\n"
                "    requests = custom_client\n"
                "    response = requests.get(url)\n"
                '    return response.json()["user_id"]\n'
                "\n"
                "\n"
                "def dynamic_field_key(url, key):\n"
                "    response = requests.get(url)\n"
                "    return response.json()[key]\n"
            ),
            "tests/test_client.py": (
                "import pytest\n"
                "\n"
                "from client import (\n"
                "    httpx_direct,\n"
                "    requests_alias,\n"
                "    requests_direct_json_access,\n"
                "    requests_payload_assignment,\n"
                ")\n"
                "\n"
                "\n"
                "def test_present_response_field(mocker):\n"
                '    mock_get = mocker.patch("requests.get")\n'
                '    mock_get.return_value.json.return_value = {"user_id": "known"}\n'
                '    requests_direct_json_access("https://example.invalid")\n'
                "\n"
                "\n"
                "def test_missing_response_field(mocker):\n"
                '    mock_post = mocker.patch("requests.post")\n'
                "    mock_post.return_value.json.return_value = {}\n"
                '    requests_payload_assignment("https://example.invalid")\n'
                "\n"
                "\n"
                "def test_other_response_field_characterizes_key_error(mocker):\n"
                '    mock_put = mocker.patch("requests.put")\n'
                '    mock_put.return_value.json.return_value = {"other": 1}\n'
                "    with pytest.raises(KeyError):\n"
                '        requests_alias("https://example.invalid")\n'
                "\n"
                "\n"
                "def test_unproven_similar_mock(mock_get):\n"
                "    mock_get.return_value.json.return_value = {}\n"
                '    httpx_direct("https://example.invalid")\n'
            ),
        },
    )
    return git_fixture


@pytest.fixture
def hidden_ordering(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add set selection behavior",
        {
            "src/selector.py": (
                "from typing import Set\n"
                "\n"
                "\n"
                "def typed_set_next_iter(values: set[str]):\n"
                "    return next(iter(values))\n"
                "\n"
                "\n"
                "def typing_set_annotation(values: Set[str]):\n"
                "    return next(iter(values))\n"
                "\n"
                "\n"
                "def constructed_set_list_index(candidates):\n"
                "    values = set(candidates)\n"
                "    return list(values)[0]\n"
                "\n"
                "\n"
                "def set_comprehension_tuple_index(items):\n"
                "    values = {item for item in items}\n"
                "    return tuple(values)[0]\n"
                "\n"
                "\n"
                "def simple_set_alias(items):\n"
                "    values = set(items)\n"
                "    aliases = values\n"
                "    return next(iter(aliases))\n"
                "\n"
                "\n"
                "def rebound_set_variable(items):\n"
                "    values = set(items)\n"
                "    values = list(items)\n"
                "    return next(iter(values))\n"
                "\n"
                "\n"
                "def untyped_iterable(values):\n"
                "    return next(iter(values))\n"
                "\n"
                "\n"
                "def custom_factory(items):\n"
                "    values = custom_set_factory(items)\n"
                "    return next(iter(values))\n"
                "\n"
                "\n"
                "def dict_literal():\n"
                '    values = {"key": "value"}\n'
                "    return next(iter(values))\n"
                "\n"
                "\n"
                "def single_element_set():\n"
                '    return next(iter({"only"}))\n'
                "\n"
                "\n"
                "def guarded_but_arbitrary(values: set[str]):\n"
                "    if values:\n"
                "        return next(iter(values))\n"
                "    return None\n"
                "\n"
                "\n"
                "def asserted_but_arbitrary(values: set[str]):\n"
                "    assert values\n"
                "    return values.pop()\n"
                "\n"
                "\n"
                "def set_pop(values: set[str]):\n"
                "    return values.pop()\n"
                "\n"
                "\n"
                "def for_loop_first_return(values: set[str]):\n"
                "    for value in values:\n"
                "        return value\n"
                '    raise ValueError("empty")\n'
                "\n"
                "\n"
                "def sorted_selection(values: set[str]):\n"
                "    return sorted(values)[0]\n"
                "\n"
                "\n"
                "def min_selection(values: set[str]):\n"
                "    return min(values)\n"
                "\n"
                "\n"
                "def max_selection(values: set[str]):\n"
                "    return max(values)\n"
                "\n"
                "\n"
                "def sorted_custom_key(values: set[str], priority):\n"
                "    return sorted(values, key=priority)[0]\n"
            ),
            "tests/test_selector.py": (
                "from selector import (\n"
                "    constructed_set_list_index,\n"
                "    typed_set_next_iter,\n"
                ")\n"
                "\n"
                "\n"
                "def test_typed_set_selection():\n"
                '    assert typed_set_next_iter({"a", "b"}) in {"a", "b"}\n'
                "\n"
                "\n"
                "def test_constructed_set_selection():\n"
                '    assert constructed_set_list_index(["a"]) == "a"\n'
            ),
        },
    )
    return git_fixture


@pytest.fixture
def hidden_filesystem(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add configuration file loading behavior",
        {
            "src/config_loader.py": (
                "import importlib.resources\n"
                "import os\n"
                "import pathlib as pl\n"
                "from pathlib import Path\n"
                "from pathlib import Path as FilePath\n"
                "\n"
                "\n"
                "def builtin_open_relative():\n"
                '    return open("config/settings.json").read()\n'
                "\n"
                "\n"
                "def builtin_open_absolute_posix():\n"
                '    return open("/etc/app/config.json").read()\n'
                "\n"
                "\n"
                "def builtin_open_absolute_windows():\n"
                '    return open("C:\\\\app\\\\config.json").read()\n'
                "\n"
                "\n"
                "def builtin_open_unc():\n"
                '    return open(r"\\\\server\\share\\config.json").read()\n'
                "\n"
                "\n"
                "def rebound_builtin_open():\n"
                "    open = custom_loader\n"
                '    return open("config.json")\n'
                "\n"
                "\n"
                "def pathlib_direct_read():\n"
                '    return Path("config.yaml").read_text()\n'
                "\n"
                "\n"
                "def pathlib_module_alias():\n"
                '    return pl.Path("payload.bin").read_bytes()\n'
                "\n"
                "\n"
                "def pathlib_import_alias(data):\n"
                '    return FilePath("output.txt").write_text(data)\n'
                "\n"
                "\n"
                "def assigned_relative_path():\n"
                '    config_path = Path("config.json")\n'
                "    return config_path.read_text()\n"
                "\n"
                "\n"
                "def joined_literal_segments():\n"
                '    base = Path("config")\n'
                '    settings = base / "settings.json"\n'
                "    return settings.read_text()\n"
                "\n"
                "\n"
                "def dynamic_segment(name):\n"
                '    path = Path("config") / name\n'
                "    return path.read_text()\n"
                "\n"
                "\n"
                "def function_parameter_path(path):\n"
                "    return path.read_text()\n"
                "\n"
                "\n"
                "class CustomPath:\n"
                "    def __init__(self, value):\n"
                "        self.value = value\n"
                "\n"
                "    def read_text(self):\n"
                "        return self.value\n"
                "\n"
                "\n"
                "def custom_path_class():\n"
                '    return CustomPath("config.json").read_text()\n'
                "\n"
                "\n"
                "def file_relative_anchor():\n"
                '    return (Path(__file__).parent / "config.json").read_text()\n'
                "\n"
                "\n"
                "def resolved_file_relative_anchor():\n"
                '    return (Path(__file__).resolve().parent / "config.json").read_text()\n'
                "\n"
                "\n"
                "def explicit_cwd_anchor():\n"
                '    return (Path.cwd() / "config.json").read_text()\n'
                "\n"
                "\n"
                "def home_anchor():\n"
                '    return (Path.home() / ".config" / "app.json").read_text()\n'
                "\n"
                "\n"
                "def package_resource_anchor():\n"
                '    return (importlib.resources.files("package") / "config.json").read_text()\n'
                "\n"
                "\n"
                "def dirname_file_anchor():\n"
                '    return open(os.path.join(os.path.dirname(__file__), "config.json")).read()\n'
                "\n"
                "\n"
                "def exists_guarded_relative():\n"
                '    path = Path("config.json")\n'
                "    if path.exists():\n"
                "        return path.read_text()\n"
                "    return None\n"
                "\n"
                "\n"
                "def file_not_found_handled_relative():\n"
                "    try:\n"
                '        return open("config.json").read()\n'
                "    except FileNotFoundError:\n"
                "        return None\n"
                "\n"
                "\n"
                "def tilde_relative_path():\n"
                '    return Path("~/config.json").read_text()\n'
                "\n"
                "\n"
                "def path_constructed_without_access():\n"
                '    return Path("config.json")\n'
            ),
            "tests/test_config_loader.py": (
                "from config_loader import (\n"
                "    builtin_open_relative,\n"
                "    pathlib_direct_read,\n"
                ")\n"
                "\n"
                "\n"
                "def test_builtin_open_relative(monkeypatch, tmp_path):\n"
                "    monkeypatch.chdir(tmp_path)\n"
                "    builtin_open_relative()\n"
                "\n"
                "\n"
                "def test_pathlib_direct_read():\n"
                "    pathlib_direct_read()\n"
            ),
        },
    )
    return git_fixture


@pytest.fixture
def hidden_time(git_fixture: GitFixture) -> GitFixture:
    git_fixture.commit(
        "initial",
        "Add timeout and elapsed time logic",
        {
            "src/timeout_logic.py": (
                "import logging\n"
                "import time\n"
                "import time as clock_module\n"
                "from time import monotonic as monotonic_clock\n"
                "from time import time as wall_time\n"
                "\n"
                "logger = logging.getLogger(__name__)\n"
                "\n"
                "\n"
                "def time_duration():\n"
                "    start = time.time()\n"
                "    return time.time() - start\n"
                "\n"
                "\n"
                "def time_ns_duration():\n"
                "    start = time.time_ns()\n"
                "    return time.time_ns() - start\n"
                "\n"
                "\n"
                "def imported_time_alias():\n"
                "    start = wall_time()\n"
                "    return wall_time() - start\n"
                "\n"
                "\n"
                "def module_alias():\n"
                "    start = clock_module.time()\n"
                "    return clock_module.time() - start\n"
                "\n"
                "\n"
                "def returned_duration():\n"
                "    start = time.time()\n"
                "    perform_work()\n"
                "    return time.time() - start\n"
                "\n"
                "\n"
                "def deadline_if(timeout):\n"
                "    deadline = time.time() + timeout\n"
                "    if time.time() >= deadline:\n"
                "        return False\n"
                "    return True\n"
                "\n"
                "\n"
                "def deadline_loop(timeout):\n"
                "    deadline = wall_time() + timeout\n"
                "    while wall_time() < deadline:\n"
                "        poll()\n"
                "\n"
                "\n"
                "def timestamp_only():\n"
                "    created_at = time.time()\n"
                "    return created_at\n"
                "\n"
                "\n"
                "def logged_timestamp():\n"
                '    logger.info("created at %s", time.time())\n'
                "\n"
                "\n"
                "def monotonic_duration():\n"
                "    start = time.monotonic()\n"
                "    return time.monotonic() - start\n"
                "\n"
                "\n"
                "def monotonic_ns_duration():\n"
                "    start = time.monotonic_ns()\n"
                "    return time.monotonic_ns() - start\n"
                "\n"
                "\n"
                "def perf_counter_duration():\n"
                "    start = time.perf_counter()\n"
                "    return time.perf_counter() - start\n"
                "\n"
                "\n"
                "def mixed_clock_domains():\n"
                "    start = time.time()\n"
                "    return monotonic_clock() - start\n"
                "\n"
                "\n"
                "def rebound_start():\n"
                "    start = time.time()\n"
                "    start = load_timestamp()\n"
                "    return time.time() - start\n"
                "\n"
                "\n"
                "def rebound_time_module():\n"
                "    time = custom_clock\n"
                "    start = time.time()\n"
                "    return time.time() - start\n"
                "\n"
                "\n"
                "def dynamic_clock_parameter(clock):\n"
                "    start = clock.time()\n"
                "    return clock.time() - start\n"
                "\n"
                "\n"
                "def helper_returned_start():\n"
                "    start = load_start_time()\n"
                "    return time.time() - start\n"
            ),
            "tests/test_timeout_logic.py": (
                "from timeout_logic import (\n"
                "    deadline_if,\n"
                "    imported_time_alias,\n"
                "    returned_duration,\n"
                "    time_duration,\n"
                "    time_ns_duration,\n"
                ")\n"
                "\n"
                "\n"
                "def test_ordinary_timeout():\n"
                "    assert time_duration() >= 0\n"
                "\n"
                "\n"
                "def test_fixed_clock(mocker):\n"
                '    mocker.patch("time.time_ns", return_value=100)\n'
                "    time_ns_duration()\n"
                "\n"
                "\n"
                "def test_backward_clock(mocker):\n"
                '    mocker.patch("time.time", side_effect=[100.0, 90.0])\n'
                "    returned_duration()\n"
                "\n"
                "\n"
                "def test_forward_clock(mocker):\n"
                '    mocker.patch("time.time", side_effect=[100.0, 10000.0])\n'
                "    deadline_if(5)\n"
                "\n"
                "\n"
                "def test_unproven_mock(fake_mocker):\n"
                '    fake_mocker.patch("time.time", side_effect=[100.0, 90.0])\n'
                "    imported_time_alias()\n"
            ),
        },
    )
    return git_fixture


def repository_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if relative.startswith(".git/logs/"):
            continue
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()

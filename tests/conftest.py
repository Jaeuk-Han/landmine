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

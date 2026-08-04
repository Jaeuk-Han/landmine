from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime, timedelta

import pytest

from landmine.analyzers.defuse import analyze_defuse
from landmine.analyzers.why import analyze_why
from landmine.domain import AnalysisStatus, Target
from landmine.git import GitOutput, GitRunner
from tests.conftest import GitFixture, repository_digest

ZERO_OID = "0" * 40
FIXED_TIME = datetime(2026, 8, 4, tzinfo=UTC)


def _commit_lf(
    fixture: GitFixture,
    tag: str,
    message: str,
    files: dict[str, str],
) -> str:
    for relative, content in files.items():
        path = fixture.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
    moment = datetime(2024, 1, 1, tzinfo=UTC) + timedelta(minutes=fixture.commit_index)
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
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    for arguments in (
        ["git", "-c", "core.autocrlf=true", "add", "--all"],
        ["git", "-c", "core.autocrlf=true", "commit", "--no-gpg-sign", "-m", message],
    ):
        completed = subprocess.run(
            arguments,
            cwd=fixture.root,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            shell=False,
        )
        if completed.returncode:
            raise RuntimeError(completed.stderr.decode("utf-8", errors="replace"))
    commit = fixture._run(["rev-parse", "HEAD"])
    fixture.commits[tag] = commit
    fixture.commit_index += 1
    return commit


@pytest.fixture
def crlf_history(git_fixture: GitFixture) -> GitFixture:
    _commit_lf(
        git_fixture,
        "introduction",
        "Introduce response parsing",
        {
            "src/parser.py": (
                "def parse_response(text: str):\n    import yaml\n    return yaml.safe_load(text)\n"
            )
        },
    )
    _commit_lf(
        git_fixture,
        "repair",
        "Retry malformed YAML after a bounded escape repair",
        {
            "src/parser.py": (
                "def repair_yaml(text: str) -> str:\n"
                "    return text.replace(r'\\%', '%')\n"
                "\n"
                "\n"
                "def parse_response(text: str):\n"
                "    import yaml\n"
                "    try:\n"
                "        return yaml.safe_load(text)\n"
                "    except yaml.YAMLError:\n"
                "        return yaml.safe_load(repair_yaml(text))\n"
            ),
            "tests/test_parser.py": (
                "from parser import parse_response\n"
                "\n"
                "\n"
                "def test_invalid_escape_is_repaired():\n"
                "    assert parse_response(r'value: 94\\%') == {'value': '94%'}\n"
            ),
        },
    )
    committed = subprocess.run(
        ["git", "show", "HEAD:src/parser.py"],
        cwd=git_fixture.root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    ).stdout
    assert b"\r\n" not in committed
    system_config = git_fixture.root.parent / "system.gitconfig"
    system_config.write_text("[core]\n\tautocrlf = true\n", encoding="utf-8", newline="\n")
    checkout = git_fixture.root.parent / "checkout"
    checkout_environment = os.environ.copy()
    checkout_environment.pop("GIT_CONFIG_NOSYSTEM", None)
    checkout_environment["GIT_CONFIG_SYSTEM"] = str(system_config)
    subprocess.run(
        ["git", "clone", "--quiet", "--no-local", str(git_fixture.root), str(checkout)],
        cwd=git_fixture.root.parent,
        env=checkout_environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    )
    fixture = GitFixture(
        checkout,
        commit_index=git_fixture.commit_index,
        commits=dict(git_fixture.commits),
    )
    path = fixture.root / "src/parser.py"
    clean = subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=fixture.root,
        env=checkout_environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        shell=False,
    ).stdout
    assert clean == b""
    assert b"\r\n" in path.read_bytes()
    return fixture


def _analyze_why(fixture: GitFixture):
    return analyze_why(
        repo=fixture.root,
        target=Target(symbol="parse_response"),
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )


def test_historical_blame_uses_explicit_head(
    crlf_history: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    original = GitRunner.run

    def recording(self, arguments, *, check=True):
        calls.append(list(arguments))
        return original(self, arguments, check=check)

    monkeypatch.setattr(GitRunner, "run", recording)
    _analyze_why(crlf_history)
    blame = next(arguments for arguments in calls if arguments[:1] == ["blame"])
    assert blame == [
        "blame",
        "--line-porcelain",
        "-L",
        "5,10",
        "HEAD",
        "--",
        "src/parser.py",
    ]


def test_zero_oid_blame_falls_back_without_showing_placeholder(
    crlf_history: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = GitRunner.run
    shows: list[str] = []
    head = crlf_history.commits["repair"]
    zero_blame = GitOutput(
        stdout=(
            f"{ZERO_OID} 5 5 1\n"
            "author Not Committed Yet\n"
            f"previous {head} src/parser.py\n"
            "filename src/parser.py\n"
            "\tdef parse_response(text: str):\n"
        ),
        stderr="",
        returncode=0,
    )

    def forced_zero(self, arguments, *, check=True):
        if arguments[:1] == ["blame"]:
            return zero_blame
        if arguments[:1] == ["show"]:
            shows.append(arguments[-1])
        return original(self, arguments, check=check)

    monkeypatch.setattr(GitRunner, "run", forced_zero)
    result = _analyze_why(crlf_history)

    assert ZERO_OID not in shows
    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert {item.commit for item in result.evolution} == {
        crlf_history.commits["introduction"],
        crlf_history.commits["repair"],
    }
    assert any(item.code == "provider_failure" for item in result.limitations)


def test_crlf_history_recovers_real_commits_without_mutation(crlf_history: GitFixture) -> None:
    before = repository_digest(crlf_history.root)
    result = _analyze_why(crlf_history)

    assert result.analysis_status is AnalysisStatus.PARTIAL
    assert [item.commit for item in result.evolution] == [
        crlf_history.commits["introduction"],
        crlf_history.commits["repair"],
    ]
    assert all(item.commit != ZERO_OID for item in result.evolution)
    assert any(item.code == "dirty_worktree_head_history" for item in result.limitations)
    assert repository_digest(crlf_history.root) == before


def test_defuse_uses_crlf_history_without_execution_or_mutation(
    crlf_history: GitFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = repository_digest(crlf_history.root)
    calls: list[list[str]] = []
    original = subprocess.run

    def recording(command, *args, **kwargs):
        calls.append([str(item) for item in command])
        return original(command, *args, **kwargs)

    monkeypatch.setattr("landmine.git.subprocess.run", recording)
    result = analyze_defuse(
        repo=crlf_history.root,
        target=Target(symbol="parse_response"),
        goal="make malformed YAML recovery safer without changing valid outputs",
        clock=lambda: FIXED_TIME,
        monotonic=lambda: 100.0,
    )

    assert result.analysis_status is not AnalysisStatus.FAILED
    assert result.defuse_analysis is not None
    why = next(item for item in result.defuse_analysis.prerequisites if item.command == "why")
    assert why.status is not AnalysisStatus.FAILED
    assert result.plan.tests
    assert result.plan.steps
    assert result.plan.verification
    assert calls
    assert all("pytest" not in command for command in calls)
    assert repository_digest(crlf_history.root) == before

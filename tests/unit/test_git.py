from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from landmine.git import (
    DIFF_MACHINERY_SAFETY_OPTIONS,
    GitError,
    GitRunner,
    line_log,
    parse_line_log,
)


def test_git_runner_uses_argument_array(tmp_path: Path) -> None:
    runner = GitRunner(tmp_path)
    completed = CompletedProcess(args=[], returncode=0, stdout=b"ok\n", stderr=b"")
    with patch("landmine.git.subprocess.run", return_value=completed) as run:
        output = runner.run(["rev-parse", "HEAD"])
    positional = run.call_args.args
    keywords = run.call_args.kwargs
    assert isinstance(positional[0], list)
    assert positional[0][-2:] == ["rev-parse", "HEAD"]
    assert keywords["shell"] is False
    assert output.stdout == "ok\n"


def test_git_runner_rejects_non_allowlisted_command(tmp_path: Path) -> None:
    with pytest.raises(GitError, match="allowlist"):
        GitRunner(tmp_path).run(["checkout", "main"])


def test_git_runner_truncates_output(tmp_path: Path) -> None:
    completed = CompletedProcess(args=[], returncode=0, stdout=b"123456", stderr=b"abcdef")
    with patch("landmine.git.subprocess.run", return_value=completed):
        output = GitRunner(tmp_path, max_output_bytes=8).run(["status"])
    assert output.truncated is True
    assert len(output.stdout.encode()) + len(output.stderr.encode()) == 8


def test_log_l_uses_argument_array(tmp_path: Path) -> None:
    runner = GitRunner(tmp_path)
    completed = CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
    with patch("landmine.git.subprocess.run", return_value=completed) as run:
        line_log(
            runner,
            path="src/routing.py",
            start_line=5,
            end_line=6,
            max_commits=50,
        )
    command = run.call_args.args[0]
    assert isinstance(command, list)
    log_index = command.index("log")
    assert command[log_index + 1 : log_index + 3] == list(DIFF_MACHINERY_SAFETY_OPTIONS)
    assert "-L" in command
    assert "5,6:src/routing.py" in command
    assert "HEAD" in command
    assert run.call_args.kwargs["shell"] is False


@pytest.mark.parametrize("subcommand", ["log", "show", "diff"])
def test_diff_machinery_commands_disable_textconv_and_external_diff(
    tmp_path: Path, subcommand: str
) -> None:
    completed = CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
    with patch("landmine.git.subprocess.run", return_value=completed) as run:
        GitRunner(tmp_path).run([subcommand, "HEAD"])
    command = run.call_args.args[0]
    subcommand_index = command.index(subcommand)
    assert command[subcommand_index + 1 : subcommand_index + 3] == list(
        DIFF_MACHINERY_SAFETY_OPTIONS
    )


@pytest.mark.parametrize("subcommand", ["rev-parse", "status", "ls-files"])
def test_non_diff_commands_do_not_receive_diff_machinery_options(
    tmp_path: Path, subcommand: str
) -> None:
    completed = CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
    with patch("landmine.git.subprocess.run", return_value=completed) as run:
        GitRunner(tmp_path).run([subcommand])
    command = run.call_args.args[0]
    assert all(option not in command for option in DIFF_MACHINERY_SAFETY_OPTIONS)


def test_parse_line_log_ignores_zero_oid_record() -> None:
    output = "\x1e" + "0" * 40 + "\x1f2026-08-04T00:00:00Z\x1fplaceholder\npatch"

    assert parse_line_log(output) == ()

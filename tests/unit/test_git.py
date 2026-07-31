from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from landmine.git import GitError, GitRunner, line_log


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
    assert "-L" in command
    assert "5,6:src/routing.py" in command
    assert run.call_args.kwargs["shell"] is False

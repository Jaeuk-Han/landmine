"""Bounded, read-only Git access used by all analyzers."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from landmine.domain import RepositoryState
from landmine.evidence import safe_excerpt

SAFE_GIT_COMMANDS = frozenset(
    {
        "rev-parse",
        "status",
        "blame",
        "log",
        "show",
        "diff",
        "grep",
        "ls-files",
        "ls-tree",
        "merge-base",
    }
)
DIFF_MACHINERY_COMMANDS = frozenset({"diff", "log", "show"})
DIFF_MACHINERY_SAFETY_OPTIONS = ("--no-textconv", "--no-ext-diff")


class GitError(RuntimeError):
    """A safe Git query failed."""


class GitTimeout(GitError):
    """A Git query exceeded its timeout."""


@dataclass(frozen=True)
class GitOutput:
    stdout: str
    stderr: str
    returncode: int
    truncated: bool = False


@dataclass(frozen=True)
class LineLogRecord:
    commit: str
    timestamp: str
    subject: str
    diff: str


@dataclass(frozen=True)
class RepositorySnapshot:
    state: RepositoryState
    runner: GitRunner
    worktree_status: str = ""


class GitRunner:
    """Run allowlisted Git queries with argument arrays and no shell."""

    def __init__(
        self,
        cwd: Path,
        *,
        timeout: float = 15.0,
        max_output_bytes: int = 2_000_000,
        executable: str = "git",
    ) -> None:
        self.cwd = cwd
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.executable = executable

    def run(self, arguments: Sequence[str], *, check: bool = True) -> GitOutput:
        if not arguments or arguments[0] not in SAFE_GIT_COMMANDS:
            raise GitError("Git command is not on the read-only allowlist")
        safe_arguments = (
            [arguments[0], *DIFF_MACHINERY_SAFETY_OPTIONS, *arguments[1:]]
            if arguments[0] in DIFF_MACHINERY_COMMANDS
            else list(arguments)
        )
        command = [
            self.executable,
            "--no-pager",
            "-c",
            "core.pager=cat",
            "-c",
            "color.ui=false",
            "-c",
            "core.fsmonitor=false",
            *safe_arguments,
        ]
        environment = os.environ.copy()
        for name in (
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_COMMON_DIR",
            "GIT_CONFIG",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_PARAMETERS",
            "GIT_DIR",
            "GIT_EXTERNAL_DIFF",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_WORK_TREE",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_PAGER": "cat",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        try:
            completed = subprocess.run(
                command,
                cwd=self.cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.timeout,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GitTimeout(f"Git query exceeded {self.timeout:g} seconds") from exc
        except OSError as exc:
            raise GitError(f"Git is unavailable: {exc}") from exc

        stdout_bytes = completed.stdout
        stderr_bytes = completed.stderr
        truncated = len(stdout_bytes) + len(stderr_bytes) > self.max_output_bytes
        remaining = self.max_output_bytes
        stdout_bytes = stdout_bytes[:remaining]
        remaining -= len(stdout_bytes)
        stderr_bytes = stderr_bytes[:remaining]
        result = GitOutput(
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            returncode=completed.returncode,
            truncated=truncated,
        )
        if check and result.returncode != 0:
            diagnostic = result.stderr.strip().splitlines()[:1]
            detail = (
                safe_excerpt(diagnostic[0], max_lines=1, max_chars=500)
                if diagnostic
                else "no diagnostic"
            )
            raise GitError(f"Git {arguments[0]} failed ({result.returncode}): {detail}")
        return result


def preflight(path: Path, *, timeout: float = 15.0) -> tuple[RepositoryState, GitRunner]:
    """Resolve repository state using only read-only Git commands."""
    initial = GitRunner(path, timeout=timeout)
    root_text = initial.run(["rev-parse", "--show-toplevel"]).stdout.strip()
    if not root_text:
        raise GitError("Git did not return a repository root")
    root = Path(root_text).resolve()
    runner = GitRunner(root, timeout=timeout)
    head = runner.run(["rev-parse", "HEAD"]).stdout.strip()
    dirty = bool(runner.run(["status", "--porcelain=v1", "--untracked-files=normal"]).stdout)
    shallow_text = runner.run(["rev-parse", "--is-shallow-repository"]).stdout.strip()
    return (
        RepositoryState(
            root=".",
            head=head,
            dirty=dirty,
            shallow=shallow_text == "true",
        ),
        runner,
    )


def list_tracked_files(runner: GitRunner) -> tuple[str, ...]:
    """List tracked paths without shell expansion or filesystem traversal."""
    output = runner.run(["ls-files", "-z", "--"])
    if output.truncated:
        raise GitError("tracked file listing reached the configured output-size limit")
    return tuple(sorted({path.replace("\\", "/") for path in output.stdout.split("\0") if path}))


def line_log(
    runner: GitRunner,
    *,
    path: str,
    start_line: int,
    end_line: int,
    max_commits: int,
) -> GitOutput:
    """Query line evolution with one argument-array invocation."""
    return runner.run(
        [
            "log",
            f"--max-count={max(1, max_commits)}",
            "--format=%x1e%H%x1f%aI%x1f%s",
            "--patch",
            "-L",
            f"{start_line},{end_line}:{path}",
        ],
        check=False,
    )


def parse_line_log(output: str) -> tuple[LineLogRecord, ...]:
    """Parse custom-delimited ``git log -L`` output oldest-first."""
    records: list[LineLogRecord] = []
    for block in output.split("\x1e"):
        block = block.lstrip("\r\n")
        if not block:
            continue
        header, separator, diff = block.partition("\n")
        fields = header.rstrip("\r").split("\x1f", 2)
        if not separator or len(fields) != 3:
            continue
        commit, timestamp, subject = fields
        if (
            len(commit) != 40
            or commit == "0" * 40
            or any(character not in "0123456789abcdef" for character in commit)
        ):
            continue
        records.append(
            LineLogRecord(
                commit=commit,
                timestamp=timestamp,
                subject=subject,
                diff=diff.strip(),
            )
        )
    records.reverse()
    return tuple(records)

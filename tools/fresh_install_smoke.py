"""Install the built wheel offline and smoke-test the installed CLI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path

EXPECTED_VERSION = "0.1.0a1"


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command!r}\n{completed.stderr}"
        )
    return completed


def _git(arguments: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    return _run(["git", *arguments], cwd=cwd, env=env).stdout


def _snapshot(root: Path, env: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for arguments in (
        ["rev-parse", "HEAD"],
        ["show-ref"],
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        ["diff", "--binary"],
        ["diff", "--cached", "--binary"],
    ):
        digest.update(_git(arguments, cwd=root, env=env).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _create_fixture(root: Path, env: dict[str, str]) -> None:
    root.mkdir()
    _git(["init", "-b", "main"], cwd=root, env=env)
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src" / "sample.py").write_text(
        "import os\n\n\ndef select_route(items):\n"
        '    token = os.environ["ROUTE_TOKEN"]\n'
        "    return items[0] if token else items[0]\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_sample.py").write_text(
        "from src.sample import select_route\n\n\n"
        "def test_route():\n    assert select_route([1]) == 1\n",
        encoding="utf-8",
    )
    _git(["add", "--all"], cwd=root, env=env)
    _git(["commit", "--no-gpg-sign", "-m", "Add guarded route selection"], cwd=root, env=env)


def smoke(dist: Path, schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise SystemExit("jsonschema is required by this verification script") from exc

    wheels = sorted(dist.resolve().glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("expected exactly one wheel")
    expected_wheel = f"landmine-{EXPECTED_VERSION}-py3-none-any.whl"
    if wheels[0].name != expected_wheel:
        raise SystemExit(f"expected {expected_wheel}, found {wheels[0].name}")
    schema = json.loads(schema_path.resolve().read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="landmine-release-") as temporary:
        temp = Path(temporary)
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.update(
            {
                "GIT_AUTHOR_NAME": "Release Fixture",
                "GIT_AUTHOR_EMAIL": "release@example.invalid",
                "GIT_COMMITTER_NAME": "Release Fixture",
                "GIT_COMMITTER_EMAIL": "release@example.invalid",
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        virtualenv = temp / "venv"
        venv.EnvBuilder(with_pip=True).create(virtualenv)
        scripts = virtualenv / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        console = scripts / ("landmine.exe" if os.name == "nt" else "landmine")
        _run(
            [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])],
            cwd=temp,
            env=environment,
        )

        help_result = _run([str(console), "--help"], cwd=temp, env=environment)
        version_result = _run([str(console), "--version"], cwd=temp, env=environment)
        if not all(
            name in help_result.stdout for name in ("why", "assumptions", "blast", "defuse")
        ):
            raise SystemExit("installed console help does not list all commands")
        if version_result.stdout.strip() != f"landmine {EXPECTED_VERSION}":
            raise SystemExit("installed console version is unexpected")

        fixture = temp / "fixture"
        _create_fixture(fixture, environment)
        before = _snapshot(fixture, environment)
        commands = {
            "why": ["why", "src/sample.py:4"],
            "assumptions": ["assumptions", "symbol:select_route"],
            "blast": ["blast", "change route behavior", "--target", "symbol:select_route"],
            "defuse": [
                "defuse",
                "symbol:select_route",
                "--goal",
                "support empty route inputs",
            ],
        }
        statuses: dict[str, int] = {}
        for name, arguments in commands.items():
            markdown = subprocess.run(
                [str(console), *arguments, "--repo", str(fixture)],
                cwd=temp,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
            )
            if markdown.returncode not in (0, 1) or not markdown.stdout.startswith("# Landmine"):
                raise RuntimeError(f"{name} Markdown smoke failed: {markdown.stderr}")
            structured = subprocess.run(
                [str(console), *arguments, "--repo", str(fixture), "--format", "json"],
                cwd=temp,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
            )
            if structured.returncode not in (0, 1):
                raise RuntimeError(f"{name} JSON smoke failed: {structured.stderr}")
            payload = json.loads(structured.stdout)
            jsonschema.Draft202012Validator(
                schema, format_checker=jsonschema.FormatChecker()
            ).validate(payload)
            if payload["command"] != name or payload["analysis_status"] == "failed":
                raise RuntimeError(f"{name} returned an unexpected result")
            statuses[name] = structured.returncode
        after = _snapshot(fixture, environment)
        if before != after:
            raise RuntimeError("installed CLI changed HEAD, refs, index, or worktree")
        print("installed console:", version_result.stdout.strip())
        print("smoke exit codes:", json.dumps(statuses, sort_keys=True))
        print("schema: landmine.result.v1 (all four commands)")
        print("repository state: unchanged")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    args = parser.parse_args()
    smoke(args.dist, args.schema)


if __name__ == "__main__":
    main()

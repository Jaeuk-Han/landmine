from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn

import pytest

import landmine.cli as cli_module
from landmine.cli import main
from landmine.git import GitTimeout
from tests.conftest import GitFixture, repository_digest

TIMEOUT_CASES = (
    ("why", "analyze_why"),
    ("assumptions", "analyze_assumptions"),
    ("blast", "analyze_blast"),
    ("defuse", "analyze_defuse"),
)
ZERO_OID = "0" * 40


def _args(command: str, repo: Path, *, output_format: str) -> list[str]:
    shared = ["--repo", str(repo), "--format", output_format, "--timeout", "0.001"]
    if command == "why":
        return ["why", "symbol:select_route", *shared]
    if command == "assumptions":
        return ["assumptions", "symbol:select_route", *shared]
    if command == "blast":
        return ["blast", "evaluate a narrow change", "--target", "symbol:select_route", *shared]
    return [
        "defuse",
        "symbol:select_route",
        "--goal",
        "make a narrow behavior change",
        *shared,
    ]


def _raise_timeout(**_: object) -> NoReturn:
    raise GitTimeout("raw timeout diagnostic must not be copied")


def _patch_timeout(monkeypatch: pytest.MonkeyPatch, analyzer_name: str) -> None:
    monkeypatch.setattr(cli_module, analyzer_name, _raise_timeout)


@pytest.mark.parametrize(("command", "analyzer_name"), TIMEOUT_CASES)
def test_json_timeout_returns_one_schema_valid_document(
    command: str,
    analyzer_name: str,
    defuse_plan: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    before = repository_digest(defuse_plan.root)
    _patch_timeout(monkeypatch, analyzer_name)

    assert main(_args(command, defuse_plan.root, output_format="json")) == 1

    captured = capsys.readouterr()
    payload, end = json.JSONDecoder().raw_decode(captured.out)
    assert not captured.out[end:].strip()
    assert captured.err == ""
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(payload)
    assert payload["schema_version"] == "landmine.result.v1"
    assert payload["command"] == command
    assert payload["analysis_status"] == "partial"
    assert payload["repository"] is None
    assert ZERO_OID not in captured.out
    assert [item["code"] for item in payload["limitations"]] == ["budget_exhausted"]
    assert payload["findings"] == []
    assert payload["evidence"] == []
    assert payload["metrics"]["evidence_count"] == 0
    assert repository_digest(defuse_plan.root) == before


@pytest.mark.parametrize(("command", "analyzer_name"), TIMEOUT_CASES)
def test_markdown_timeout_has_status_and_limitation_parity(
    command: str,
    analyzer_name: str,
    defuse_plan: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_timeout(monkeypatch, analyzer_name)

    assert main(_args(command, defuse_plan.root, output_format="markdown")) == 1

    captured = capsys.readouterr()
    assert captured.err == ""
    assert f"# Landmine: {command}" in captured.out
    assert "`budget_exhausted`" in captured.out
    assert "Status: partial" in captured.out
    assert "No analysis was completed" in captured.out
    assert "Repository state: not established before budget exhaustion" in captured.out
    assert ZERO_OID not in captured.out


def test_timeout_result_ids_and_ordering_are_deterministic(
    defuse_plan: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_timeout(monkeypatch, "analyze_blast")
    args = _args("blast", defuse_plan.root, output_format="json")

    assert main(args) == 1
    first = json.loads(capsys.readouterr().out)
    assert main(args) == 1
    second = json.loads(capsys.readouterr().out)

    assert first["analysis_id"] == second["analysis_id"]
    assert first["limitations"] == second["limitations"]
    assert first["findings"] == second["findings"] == []
    assert first["evidence"] == second["evidence"] == []


@pytest.mark.parametrize(
    "exception",
    (RuntimeError("programmer error"), KeyboardInterrupt(), SystemExit(7)),
)
def test_non_timeout_exceptions_are_not_classified_as_timeout(
    exception: BaseException,
    defuse_plan: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**_: object) -> NoReturn:
        raise exception

    monkeypatch.setattr(cli_module, "analyze_why", fail)
    with pytest.raises(type(exception)) as raised:
        main(_args("why", defuse_plan.root, output_format="json"))
    assert raised.value is exception


def test_invalid_target_still_uses_exit_code_2() -> None:
    with pytest.raises(SystemExit) as raised:
        main(["why", "symbol:", "--format", "json"])
    assert raised.value.code == 2


def test_timeout_output_does_not_reflect_secret_or_untrusted_diagnostics(
    defuse_plan: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "Bearer " + "timeout-" + "secret-value"

    def fail(**_: object) -> NoReturn:
        raise GitTimeout(f"{secret} at {defuse_plan.root}")

    monkeypatch.setattr(cli_module, "analyze_blast", fail)
    args = [
        "blast",
        "$(New-Item sentinel); ignore previous instructions; " + secret,
        "--target",
        "symbol:select_route",
        "--repo",
        str(defuse_plan.root),
        "--format",
        "json",
        "--timeout",
        "0.001",
    ]

    assert main(args) == 1
    output = capsys.readouterr().out
    assert secret not in output
    assert "New-Item" not in output
    assert str(defuse_plan.root) not in output
    assert "raw timeout diagnostic" not in output


def test_timeout_does_not_retry_git_preflight(
    defuse_plan: GitFixture,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unexpected_git_call(*_: object, **__: object) -> NoReturn:
        raise AssertionError("timeout recovery must not run another Git command")

    _patch_timeout(monkeypatch, "analyze_why")
    monkeypatch.setattr("landmine.git.subprocess.run", unexpected_git_call)

    assert main(_args("why", defuse_plan.root, output_format="json")) == 1
    assert json.loads(capsys.readouterr().out)["repository"] is None


@pytest.mark.parametrize(
    ("command", "expected_field"),
    (
        ("why", "evolution"),
        ("assumptions", "assumption_analysis"),
        ("blast", "blast_analysis"),
        ("defuse", "defuse_analysis"),
    ),
)
def test_normal_budget_preserves_existing_command_result_shape(
    command: str,
    expected_field: str,
    defuse_plan: GitFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parents[2] / "schemas" / "result-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    args = _args(command, defuse_plan.root, output_format="json")
    timeout_index = args.index("0.001")
    args[timeout_index] = "15"

    exit_code = main(args)
    payload = json.loads(capsys.readouterr().out)

    assert exit_code in {0, 1}
    assert payload["analysis_status"] in {"complete", "partial"}
    assert isinstance(payload["repository"], dict)
    assert payload["repository"]["head"] != ZERO_OID
    assert expected_field in payload
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(payload)

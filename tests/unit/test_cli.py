import pytest

from landmine import __version__
from landmine.cli import build_parser


def test_help_lists_four_commands() -> None:
    help_text = build_parser().format_help()
    for command in ("why", "assumptions", "blast", "defuse"):
        assert command in help_text
    assert "Phase 3" not in help_text
    assert "Phase 4" not in help_text


def test_help_labels_reserved_options() -> None:
    parser = build_parser()
    assumptions = next(action for action in parser._actions if action.dest == "command").choices[
        "assumptions"
    ]
    help_text = assumptions.format_help()
    assert "--base" in help_text and "currently ignored" in help_text
    assert "Git history limit where supported" in help_text


def test_version_uses_package_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"landmine {__version__}"

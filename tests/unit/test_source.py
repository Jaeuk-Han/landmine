from pathlib import Path

import pytest

from landmine.domain import Target
from landmine.source import TargetError, parse_target, resolve_path_target


def test_parse_path_target() -> None:
    assert parse_target("src/example.py") == Target(path="src/example.py")


def test_parse_path_line_target() -> None:
    assert parse_target("src/example.py:10") == Target(
        path="src/example.py", start_line=10, end_line=10
    )


def test_parse_path_line_range_target() -> None:
    assert parse_target("src/example.py:10-20") == Target(
        path="src/example.py", start_line=10, end_line=20
    )


def test_parse_windows_absolute_path_line_target() -> None:
    target = parse_target(r"C:\work\example.py:10-20")
    assert target.path == r"C:\work\example.py"
    assert target.start_line == 10
    assert target.end_line == 20


def test_reject_reversed_line_range() -> None:
    with pytest.raises(TargetError):
        parse_target("src/example.py:20-10")


def test_resolve_rejects_path_outside_repository(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("pass\n", encoding="utf-8")
    with pytest.raises(TargetError, match="outside"):
        resolve_path_target(Target(path=str(outside)), root)

from __future__ import annotations

from landmine.analyzers.why import _blamed_commits


def test_blamed_commits_excludes_zero_oid_and_uses_previous_commit() -> None:
    previous = "a" * 40
    output = (
        "0000000000000000000000000000000000000000 10 10 1\n"
        "author Not Committed Yet\n"
        f"previous {previous} path/to/file.py\n"
        "filename path/to/file.py\n"
        "\treturn value\n"
    )

    assert _blamed_commits(output) == (previous,)


def test_blamed_commits_prefers_attributed_commits_over_previous_metadata() -> None:
    attributed = "b" * 40
    previous = "a" * 40
    output = (
        f"{attributed} 10 10 1\n"
        f"previous {previous} path/to/file.py\n"
        "filename path/to/file.py\n"
        "\treturn value\n"
    )

    assert _blamed_commits(output) == (attributed,)

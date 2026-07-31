from pathlib import Path

import pytest

from landmine.domain import SymbolCandidate, Target
from landmine.source import (
    SymbolResolutionError,
    discover_symbol_candidates,
    resolve_symbol_target,
)


def write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_symbol_resolver_finds_python_definition(tmp_path: Path) -> None:
    write(tmp_path, "src/routing.py", "class HospitalFallback:\n    pass\n")
    candidates = discover_symbol_candidates(
        "HospitalFallback", tmp_path, ("src/routing.py",), max_files=10
    )
    assert candidates == (
        SymbolCandidate(
            path="src/routing.py",
            line=1,
            matching_text="class HospitalFallback:",
            match_kind="definition",
        ),
    )


def test_symbol_resolver_finds_typescript_definition(tmp_path: Path) -> None:
    write(
        tmp_path,
        "src/routing.ts",
        "export class HospitalFallback {\n  route() {}\n}\n",
    )
    candidates = discover_symbol_candidates(
        "HospitalFallback", tmp_path, ("src/routing.ts",), max_files=10
    )
    assert candidates[0].match_kind == "definition"
    assert candidates[0].path == "src/routing.ts"
    assert candidates[0].line == 1


def test_symbol_resolver_prefers_definition_over_reference(tmp_path: Path) -> None:
    write(tmp_path, "a_reference.py", "value = HospitalFallback()\n")
    write(tmp_path, "z_definition.py", "class HospitalFallback:\n    pass\n")
    candidates = discover_symbol_candidates(
        "HospitalFallback",
        tmp_path,
        ("a_reference.py", "z_definition.py"),
        max_files=10,
    )
    assert [candidate.match_kind for candidate in candidates] == [
        "definition",
        "reference",
    ]
    resolved = resolve_symbol_target(
        Target(symbol="HospitalFallback"),
        tmp_path,
        ("a_reference.py", "z_definition.py"),
        max_files=10,
    )
    assert resolved == Target(
        path="z_definition.py",
        start_line=1,
        end_line=1,
        symbol="HospitalFallback",
    )


def test_symbol_resolver_returns_single_candidate(tmp_path: Path) -> None:
    write(tmp_path, "src/only.js", "const HospitalFallback = () => null;\n")
    resolved = resolve_symbol_target(
        Target(symbol="HospitalFallback"),
        tmp_path,
        ("src/only.js",),
        max_files=10,
    )
    assert resolved.path == "src/only.js"
    assert resolved.start_line == 1
    assert resolved.symbol == "HospitalFallback"


def test_symbol_resolver_rejects_ambiguous_symbol(tmp_path: Path) -> None:
    write(tmp_path, "src/a.py", "class HospitalFallback:\n    pass\n")
    write(tmp_path, "src/b.ts", "export class HospitalFallback {}\n")
    with pytest.raises(SymbolResolutionError) as caught:
        resolve_symbol_target(
            Target(symbol="HospitalFallback"),
            tmp_path,
            ("src/b.ts", "src/a.py"),
            max_files=10,
        )
    assert caught.value.code == "ambiguous_symbol"
    assert [candidate.path for candidate in caught.value.candidates[:2]] == [
        "src/a.py",
        "src/b.ts",
    ]


def test_symbol_search_excludes_generated_and_vendor_files(tmp_path: Path) -> None:
    paths = (
        "vendor/library.py",
        "build/output.ts",
        "src/client.generated.ts",
        "src/real.py",
    )
    for path in paths:
        write(tmp_path, path, "class HospitalFallback:\n    pass\n")
    candidates = discover_symbol_candidates("HospitalFallback", tmp_path, paths, max_files=10)
    assert [candidate.path for candidate in candidates] == ["src/real.py"]


def test_symbol_search_handles_unicode_path(tmp_path: Path) -> None:
    write(tmp_path, "src/경로.py", "class HospitalFallback:\n    pass\n")
    candidates = discover_symbol_candidates(
        "HospitalFallback", tmp_path, ("src\\경로.py",), max_files=10
    )
    assert candidates[0].path == "src/경로.py"


def test_symbol_search_respects_file_budget(tmp_path: Path) -> None:
    write(tmp_path, "src/a.py", "unrelated = True\n")
    write(tmp_path, "src/b.py", "class HospitalFallback:\n    pass\n")
    with pytest.raises(SymbolResolutionError) as caught:
        discover_symbol_candidates(
            "HospitalFallback",
            tmp_path,
            ("src/a.py", "src/b.py"),
            max_files=1,
        )
    assert caught.value.code == "symbol_search_budget_exhausted"


def test_symbol_search_skips_binary_and_oversized_files(tmp_path: Path) -> None:
    binary = tmp_path / "src/binary.py"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"class HospitalFallback:\0\n")
    write(tmp_path, "src/large.py", "class HospitalFallback:\n" + ("x" * 100))
    candidates = discover_symbol_candidates(
        "HospitalFallback",
        tmp_path,
        ("src/binary.py", "src/large.py"),
        max_files=10,
        max_file_bytes=50,
    )
    assert candidates == ()

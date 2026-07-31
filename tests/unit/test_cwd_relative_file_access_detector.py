from __future__ import annotations

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_cwd_relative_file_access import (
    PythonCwdRelativeFileAccessDetector,
)


def context(source: str) -> AnalysisContext:
    return AnalysisContext(
        path="src/config_loader.py",
        source=source,
        start_line=1,
        end_line=max(1, len(source.splitlines())),
    )


def detect(source: str):
    return PythonCwdRelativeFileAccessDetector().detect(context(source))


def active(source: str):
    return [item for item in detect(source) if item.suppression_reason is None]


def test_detects_builtin_open_relative_path() -> None:
    candidate = active('def load():\n    return open("config/settings.json")\n')[0]
    assert candidate.path_literal == "config/settings.json"
    assert candidate.access_operation == "open"
    assert candidate.api_binding == "builtins.open"


def test_detects_pathlib_read_relative_path() -> None:
    candidate = active(
        'from pathlib import Path\ndef load():\n    return Path("config.json").read_text()\n'
    )[0]
    assert candidate.path_literal == "config.json"
    assert candidate.access_operation == "read_text"
    assert candidate.api_binding == "pathlib.Path"


def test_detects_pathlib_alias() -> None:
    assert (
        len(
            active(
                "import pathlib as pl\n"
                'def load():\n    return pl.Path("config.json").read_bytes()\n'
            )
        )
        == 1
    )


def test_detects_imported_path_alias() -> None:
    assert (
        len(
            active(
                "from pathlib import Path as FilePath\n"
                'def load():\n    return FilePath("config.json").stat()\n'
            )
        )
        == 1
    )


def test_tracks_assigned_relative_path() -> None:
    candidate = active(
        "from pathlib import Path\n"
        'def load():\n    path = Path("config.json")\n    return path.read_text()\n'
    )[0]
    assert [item.role for item in candidate.provenance] == ["path_construction"]


def test_tracks_literal_path_join() -> None:
    candidate = active(
        "from pathlib import Path\n"
        'def load():\n    base = Path("config")\n'
        '    settings = base / "settings.json"\n    return settings.read_text()\n'
    )[0]
    assert candidate.path_literal == "config/settings.json"
    assert [item.role for item in candidate.provenance] == [
        "path_construction",
        "literal_path_join",
    ]


def test_rebinding_invalidates_builtin_open() -> None:
    assert detect('def load():\n    open = custom_loader\n    return open("config.json")\n') == []


def test_does_not_infer_custom_path_class() -> None:
    assert detect('def load():\n    return Path("config.json").read_text()\n') == []


def test_does_not_infer_function_parameter_path() -> None:
    assert detect("def load(path):\n    return path.read_text()\n") == []


def test_ignores_path_construction_without_access() -> None:
    assert detect('from pathlib import Path\ndef load():\n    return Path("config.json")\n') == []


def test_ignores_posix_absolute_path() -> None:
    assert detect('def load():\n    return open("/etc/app/config.json")\n') == []


def test_ignores_windows_drive_absolute_path() -> None:
    assert detect('def load():\n    return open("C:\\\\app\\\\config.json")\n') == []
    assert detect('def load():\n    return open("C:/app/config.json")\n') == []


def test_ignores_windows_unc_path() -> None:
    assert detect('def load():\n    return open(r"\\\\server\\share\\config.json")\n') == []


def test_tilde_path_reports_cwd_semantics() -> None:
    candidate = active(
        'from pathlib import Path\ndef load():\n    return Path("~/config.json").read_text()\n'
    )[0]
    assert candidate.path_literal == "~/config.json"
    assert candidate.uncertainty_note is not None
    assert "not automatically expanded" in candidate.uncertainty_note


def test_file_relative_anchor_is_not_flagged() -> None:
    assert (
        active(
            "from pathlib import Path\n"
            'def load():\n    return (Path(__file__).parent / "config.json").read_text()\n'
        )
        == []
    )


def test_resolved_file_relative_anchor_is_not_flagged() -> None:
    assert (
        active(
            "from pathlib import Path\n"
            "def load():\n"
            '    return (Path(__file__).resolve().parent / "config.json").read_text()\n'
        )
        == []
    )


def test_explicit_cwd_anchor_is_not_flagged() -> None:
    candidates = detect(
        "from pathlib import Path\n"
        'def load():\n    return (Path.cwd() / "config.json").read_text()\n'
    )
    assert len(candidates) == 1
    assert candidates[0].suppression_reason == "explicit_cwd_anchor"


def test_home_anchor_is_not_flagged() -> None:
    assert (
        active(
            "from pathlib import Path\n"
            'def load():\n    return (Path.home() / ".config" / "app.json").read_text()\n'
        )
        == []
    )


def test_package_resource_anchor_is_not_flagged() -> None:
    candidates = detect(
        "import importlib.resources\n"
        "def load():\n"
        '    return (importlib.resources.files("pkg") / "config.json").read_text()\n'
    )
    assert len(candidates) == 1
    assert candidates[0].suppression_reason == "package_resource_anchor"


def test_dirname_file_anchor_is_not_flagged() -> None:
    candidates = detect(
        "import os\n"
        "def load():\n"
        '    return open(os.path.join(os.path.dirname(__file__), "config.json"))\n'
    )
    assert len(candidates) == 1
    assert candidates[0].suppression_reason == "file_relative_anchor"


def test_exists_guard_does_not_hide_cwd_assumption() -> None:
    source = (
        "from pathlib import Path\n"
        'def load():\n    path = Path("config.json")\n'
        "    if path.exists():\n        return path.read_text()\n"
    )
    assert len(active(source)) == 1


def test_file_not_found_handler_does_not_hide_cwd_assumption() -> None:
    source = (
        "def load():\n"
        "    try:\n"
        '        return open("config.json")\n'
        "    except FileNotFoundError:\n"
        "        return None\n"
    )
    assert len(active(source)) == 1

from __future__ import annotations

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_required_environment_variable import (
    PythonRequiredEnvironmentVariableDetector,
)
from landmine.detectors.python_required_mapping_key import PythonRequiredMappingKeyDetector


def context(source: str) -> AnalysisContext:
    return AnalysisContext(
        path="src/config.py",
        source=source,
        start_line=1,
        end_line=max(1, len(source.splitlines())),
    )


def detect(source: str):
    return PythonRequiredEnvironmentVariableDetector().detect(context(source))


def active(source: str):
    return [item for item in detect(source) if item.suppression_reason is None]


def suppressed(source: str):
    return [item for item in detect(source) if item.suppression_reason is not None]


def test_detects_os_environ_literal_key() -> None:
    candidate = active('import os\nvalue = os.environ["DATABASE_URL"]\n')[0]
    assert candidate.required_key == "DATABASE_URL"
    assert candidate.variable == "os.environ"
    assert candidate.observed_signal == "required_environment_variable"


def test_detects_aliased_os_import() -> None:
    candidates = active(
        'import os as operating_system\nvalue = operating_system.environ["API_TOKEN"]\n'
    )
    assert [item.required_key for item in candidates] == ["API_TOKEN"]


def test_detects_imported_environ() -> None:
    candidates = active('from os import environ\nvalue = environ["SECRET_KEY"]\n')
    assert [item.required_key for item in candidates] == ["SECRET_KEY"]


def test_detects_aliased_environ_import() -> None:
    candidates = active('from os import environ as env\nvalue = env["SECRET_KEY"]\n')
    assert [item.required_key for item in candidates] == ["SECRET_KEY"]


def test_does_not_classify_custom_environ_mapping() -> None:
    assert detect('environ = custom_mapping\nvalue = environ["KEY"]\n') == []
    assert (
        detect('from os import environ\nenviron = custom_mapping\nvalue = environ["KEY"]\n') == []
    )


def test_ignores_dynamic_environment_key() -> None:
    assert detect("import os\nvalue = os.environ[dynamic_key]\n") == []


def test_ignores_environ_get() -> None:
    assert detect('import os\nvalue = os.environ.get("DATABASE_URL")\n') == []


def test_ignores_os_getenv() -> None:
    assert detect('import os\nvalue = os.getenv("DATABASE_URL")\n') == []


def test_suppresses_environment_membership_guard() -> None:
    source = (
        "import os\n"
        "def load():\n"
        '    if "DATABASE_URL" in os.environ:\n'
        '        return os.environ["DATABASE_URL"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "membership_guard"


def test_suppresses_environment_early_return() -> None:
    source = (
        "import os\n"
        "def load():\n"
        '    if "DATABASE_URL" not in os.environ:\n'
        "        return None\n"
        '    return os.environ["DATABASE_URL"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_missing_key_guard"


def test_suppresses_environment_early_raise() -> None:
    source = (
        "import os\n"
        "def load():\n"
        '    if "DATABASE_URL" not in os.environ:\n'
        '        raise RuntimeError("required")\n'
        '    return os.environ["DATABASE_URL"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_missing_key_guard"


def test_suppresses_environment_assertion() -> None:
    source = (
        "import os\n"
        "def load():\n"
        '    assert "DATABASE_URL" in os.environ\n'
        '    return os.environ["DATABASE_URL"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "membership_assertion"


def test_suppresses_prior_environment_assignment() -> None:
    source = (
        "import os\n"
        "def load():\n"
        '    os.environ["DATABASE_URL"] = "sqlite://"\n'
        '    return os.environ["DATABASE_URL"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "prior_environment_assignment"


def test_truthy_environment_guard_does_not_suppress() -> None:
    source = (
        'import os\ndef load():\n    if os.environ:\n        return os.environ["DATABASE_URL"]\n'
    )
    assert len(active(source)) == 1


def test_wrong_environment_key_guard_does_not_suppress() -> None:
    source = (
        "import os\n"
        "def load():\n"
        '    if "OTHER_KEY" in os.environ:\n'
        '        return os.environ["DATABASE_URL"]\n'
    )
    assert len(active(source)) == 1


def test_environment_access_is_not_duplicated_as_mapping_key() -> None:
    analysis_context = context('import os\nvalue = os.environ["DATABASE_URL"]\n')
    environment = PythonRequiredEnvironmentVariableDetector().detect(analysis_context)
    mapping = PythonRequiredMappingKeyDetector().detect(analysis_context)
    assert [item.detector_id for item in environment + mapping] == [
        "python.required-environment-variable"
    ]


def test_overlap_resolution_is_order_independent() -> None:
    analysis_context = context('import os\nvalue = os.environ["DATABASE_URL"]\n')
    detectors = [
        PythonRequiredEnvironmentVariableDetector(),
        PythonRequiredMappingKeyDetector(),
    ]
    forward = [
        item.detector_id
        for detector in detectors
        for item in detector.detect(analysis_context)
        if item.suppression_reason is None
    ]
    reverse = [
        item.detector_id
        for detector in reversed(detectors)
        for item in detector.detect(analysis_context)
        if item.suppression_reason is None
    ]
    assert sorted(forward) == sorted(reverse) == ["python.required-environment-variable"]

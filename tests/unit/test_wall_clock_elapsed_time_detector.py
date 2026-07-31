from __future__ import annotations

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_wall_clock_elapsed_time import (
    PythonWallClockElapsedTimeDetector,
)


def context(source: str) -> AnalysisContext:
    return AnalysisContext(
        path="src/timeout_logic.py",
        source=source,
        start_line=1,
        end_line=max(1, len(source.splitlines())),
    )


def detect(source: str):
    return PythonWallClockElapsedTimeDetector().detect(context(source))


def active(source: str):
    return [item for item in detect(source) if item.suppression_reason is None]


def test_detects_time_duration_subtraction() -> None:
    candidate = active(
        "import time\ndef elapsed():\n    start = time.time()\n    return time.time() - start\n"
    )[0]
    assert candidate.clock_source == "time.time"
    assert candidate.clock_unit == "seconds"
    assert candidate.time_operation == "duration"


def test_detects_time_ns_duration_subtraction() -> None:
    candidate = active(
        "import time\n"
        "def elapsed():\n"
        "    start = time.time_ns()\n"
        "    return time.time_ns() - start\n"
    )[0]
    assert candidate.clock_source == "time.time_ns"
    assert candidate.clock_unit == "nanoseconds"


def test_detects_imported_time_alias() -> None:
    assert (
        len(
            active(
                "from time import time as wall_time\n"
                "def elapsed():\n"
                "    start = wall_time()\n"
                "    return wall_time() - start\n"
            )
        )
        == 1
    )


def test_detects_time_module_alias() -> None:
    assert (
        len(
            active(
                "import time as clock\n"
                "def elapsed():\n"
                "    start = clock.time()\n"
                "    return clock.time() - start\n"
            )
        )
        == 1
    )


def test_detects_returned_wall_clock_duration() -> None:
    assert (
        len(
            active(
                "import time\n"
                "def elapsed():\n"
                "    start = time.time()\n"
                "    work()\n"
                "    return time.time() - start\n"
            )
        )
        == 1
    )


def test_detects_wall_clock_deadline_if() -> None:
    candidate = active(
        "import time\n"
        "def wait(timeout):\n"
        "    deadline = time.time() + timeout\n"
        "    if time.time() >= deadline:\n"
        "        return False\n"
    )[0]
    assert candidate.time_operation == "deadline"


def test_detects_wall_clock_deadline_loop() -> None:
    candidate = active(
        "from time import time\n"
        "def wait(timeout):\n"
        "    deadline = time() + timeout\n"
        "    while time() < deadline:\n"
        "        poll()\n"
    )[0]
    assert candidate.time_operation == "deadline"


def test_ignores_timestamp_assignment() -> None:
    assert detect("import time\ncreated_at = time.time()\n") == []


def test_ignores_logged_timestamp() -> None:
    assert detect('import time\nlogger.info("created %s", time.time())\n') == []


def test_ignores_monotonic_duration() -> None:
    assert (
        detect(
            "import time\n"
            "def elapsed():\n"
            "    start = time.monotonic()\n"
            "    return time.monotonic() - start\n"
        )
        == []
    )


def test_ignores_monotonic_ns_duration() -> None:
    assert (
        detect(
            "import time\n"
            "def elapsed():\n"
            "    start = time.monotonic_ns()\n"
            "    return time.monotonic_ns() - start\n"
        )
        == []
    )


def test_ignores_perf_counter_duration() -> None:
    assert (
        detect(
            "import time\n"
            "def elapsed():\n"
            "    start = time.perf_counter()\n"
            "    return time.perf_counter() - start\n"
        )
        == []
    )


def test_mixed_clock_domain_is_not_marked_safe() -> None:
    candidate = active(
        "import time\n"
        "def elapsed():\n"
        "    start = time.time()\n"
        "    return time.monotonic() - start\n"
    )[0]
    assert candidate.observed_signal == "mixed_clock_domain"
    assert candidate.uncertainty_note is not None
    assert "mixed clock domains" in candidate.uncertainty_note


def test_rebinding_invalidates_start_provenance() -> None:
    assert (
        detect(
            "import time\n"
            "def elapsed():\n"
            "    start = time.time()\n"
            "    start = load_timestamp()\n"
            "    return time.time() - start\n"
        )
        == []
    )


def test_rebinding_invalidates_time_module() -> None:
    assert (
        detect(
            "import time\n"
            "def elapsed():\n"
            "    time = custom_clock\n"
            "    start = time.time()\n"
            "    return time.time() - start\n"
        )
        == []
    )


def test_does_not_infer_dynamic_clock_parameter() -> None:
    assert (
        detect("def elapsed(clock):\n    start = clock.time()\n    return clock.time() - start\n")
        == []
    )


def test_does_not_follow_helper_returned_timestamp() -> None:
    assert (
        detect(
            "import time\n"
            "def elapsed():\n"
            "    start = load_start()\n"
            "    return time.time() - start\n"
        )
        == []
    )

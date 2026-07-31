from __future__ import annotations

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_required_mapping_key import PythonRequiredMappingKeyDetector


def detect(source: str):
    return PythonRequiredMappingKeyDetector().detect(
        AnalysisContext(
            path="src/example.py",
            source=source,
            start_line=1,
            end_line=max(1, len(source.splitlines())),
        )
    )


def active(source: str):
    return [item for item in detect(source) if item.suppression_reason is None]


def suppressed(source: str):
    return [item for item in detect(source) if item.suppression_reason is not None]


def test_detects_required_literal_mapping_key() -> None:
    candidate = active('def parse(payload):\n    return payload["user_id"]\n')[0]
    assert candidate.variable == "payload"
    assert candidate.required_key == "user_id"
    assert candidate.observed_signal == "required_mapping_key"


def test_detects_attribute_mapping_key() -> None:
    candidate = active('def parse(response):\n    return response.data["status"]\n')[0]
    assert candidate.variable == "response.data"
    assert candidate.required_key == "status"


def test_detects_nested_mapping_keys_without_duplicates() -> None:
    candidates = active('def parse(payload):\n    return payload["user"]["id"]\n')
    assert [(item.variable, item.required_key) for item in candidates] == [
        ("payload", "user"),
        ('payload["user"]', "id"),
    ]


def test_ignores_numeric_index() -> None:
    assert detect("def first(items):\n    return items[0]\n") == []


def test_ignores_get_and_setdefault() -> None:
    source = (
        "def parse(payload):\n"
        '    payload.get("user_id")\n'
        '    return payload.setdefault("status", "new")\n'
    )
    assert detect(source) == []


def test_suppresses_membership_guard() -> None:
    source = (
        'def parse(payload):\n    if "user_id" in payload:\n        return payload["user_id"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "membership_guard"


def test_suppresses_early_return_missing_key_guard() -> None:
    source = (
        "def parse(payload):\n"
        '    if "user_id" not in payload:\n'
        "        return None\n"
        '    return payload["user_id"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_missing_key_guard"


def test_suppresses_early_raise_missing_key_guard() -> None:
    source = (
        "def parse(payload):\n"
        '    if "user_id" not in payload:\n'
        '        raise ValueError("required")\n'
        '    return payload["user_id"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_missing_key_guard"


def test_suppresses_membership_assertion() -> None:
    source = 'def parse(payload):\n    assert "user_id" in payload\n    return payload["user_id"]\n'
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "membership_assertion"


def test_suppresses_prior_key_assignment() -> None:
    source = (
        'def parse(payload):\n    payload["user_id"] = create_id()\n    return payload["user_id"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "prior_key_assignment"


def test_suppresses_known_mapping_literal() -> None:
    source = 'def parse():\n    payload = {"user_id": "known"}\n    return payload["user_id"]\n'
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "known_mapping_literal"


def test_suppresses_handled_key_error() -> None:
    source = (
        "def parse(payload):\n"
        "    try:\n"
        '        return payload["user_id"]\n'
        "    except KeyError:\n"
        "        return None\n"
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "handled_key_error"


def test_truthy_mapping_guard_does_not_suppress() -> None:
    source = 'def parse(payload):\n    if payload:\n        return payload["user_id"]\n'
    assert len(active(source)) == 1


def test_unrelated_key_guard_does_not_suppress() -> None:
    source = 'def parse(payload):\n    if "other" in payload:\n        return payload["user_id"]\n'
    assert len(active(source)) == 1


def test_get_without_control_flow_does_not_suppress() -> None:
    source = 'def parse(payload):\n    payload.get("user_id")\n    return payload["user_id"]\n'
    assert len(active(source)) == 1

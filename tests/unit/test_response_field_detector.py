from __future__ import annotations

from landmine.assumptions import AnalysisContext
from landmine.detectors.python_required_mapping_key import PythonRequiredMappingKeyDetector
from landmine.detectors.python_required_response_field import (
    PythonRequiredResponseFieldDetector,
)


def context(source: str) -> AnalysisContext:
    return AnalysisContext(
        path="src/client.py",
        source=source,
        start_line=1,
        end_line=max(1, len(source.splitlines())),
    )


def detect(source: str):
    return PythonRequiredResponseFieldDetector().detect(context(source))


def active(source: str):
    return [item for item in detect(source) if item.suppression_reason is None]


def suppressed(source: str):
    return [item for item in detect(source) if item.suppression_reason is not None]


def test_detects_requests_json_required_field() -> None:
    candidate = active(
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        '    return response.json()["user_id"]\n'
    )[0]
    assert candidate.required_key == "user_id"
    assert candidate.http_library == "requests"
    assert candidate.http_method == "get"


def test_detects_requests_alias() -> None:
    candidate = active(
        "import requests as http\n"
        "def load(url):\n"
        "    response = http.post(url)\n"
        '    return response.json()["status"]\n'
    )[0]
    assert (candidate.http_library, candidate.http_method) == ("requests", "post")


def test_detects_httpx_json_required_field() -> None:
    candidate = active(
        "import httpx\n"
        "def load(url):\n"
        "    response = httpx.get(url)\n"
        '    return response.json()["status"]\n'
    )[0]
    assert (candidate.http_library, candidate.http_method) == ("httpx", "get")


def test_detects_httpx_alias() -> None:
    candidate = active(
        "import httpx as client\n"
        "def load(url):\n"
        '    response = client.request("GET", url)\n'
        '    return response.json()["status"]\n'
    )[0]
    assert (candidate.http_library, candidate.http_method) == ("httpx", "request")


def test_tracks_payload_assignment() -> None:
    candidate = active(
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    payload = response.json()\n"
        '    return payload["field"]\n'
    )[0]
    assert candidate.variable == "payload"
    assert [item.role for item in candidate.provenance] == [
        "http_call",
        "json_conversion",
    ]


def test_tracks_direct_json_subscript() -> None:
    candidate = active(
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        '    return response.json()["field"]\n'
    )[0]
    assert candidate.variable == "response.json()"


def test_tracks_nested_response_fields() -> None:
    candidates = active(
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    payload = response.json()\n"
        '    return payload["user"]["id"]\n'
    )
    assert [(item.variable, item.required_key) for item in candidates] == [
        ("payload", "user"),
        ('payload["user"]', "id"),
    ]


def test_does_not_infer_from_response_variable_name() -> None:
    assert (
        detect('def load(response):\n    payload = response.json()\n    return payload["field"]\n')
        == []
    )


def test_does_not_infer_from_function_parameter() -> None:
    assert detect('def load(response):\n    return response.json()["field"]\n') == []


def test_does_not_infer_from_local_service_get() -> None:
    assert (
        detect(
            "def load(local_service):\n"
            "    response = local_service.get()\n"
            '    return response.json()["field"]\n'
        )
        == []
    )


def test_rebound_http_library_invalidates_provenance() -> None:
    assert (
        detect(
            "import requests\n"
            "def load(url, custom_client):\n"
            "    requests = custom_client\n"
            "    response = requests.get(url)\n"
            '    return response.json()["field"]\n'
        )
        == []
    )


def test_ignores_dynamic_response_field() -> None:
    assert (
        detect(
            "import requests\n"
            "def load(url, key):\n"
            "    response = requests.get(url)\n"
            "    return response.json()[key]\n"
        )
        == []
    )


def test_suppresses_response_membership_guard() -> None:
    source = (
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    payload = response.json()\n"
        '    if "field" in payload:\n'
        '        return payload["field"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "membership_guard"


def test_suppresses_response_early_return() -> None:
    source = (
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    payload = response.json()\n"
        '    if "field" not in payload:\n'
        "        return None\n"
        '    return payload["field"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_missing_key_guard"


def test_suppresses_response_early_raise() -> None:
    source = (
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    payload = response.json()\n"
        '    if "field" not in payload:\n'
        '        raise RuntimeError("required")\n'
        '    return payload["field"]\n'
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "early_exit_missing_key_guard"


def test_suppresses_handled_key_error() -> None:
    source = (
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    try:\n"
        '        return response.json()["field"]\n'
        "    except KeyError:\n"
        "        return None\n"
    )
    assert not active(source)
    assert suppressed(source)[0].suppression_reason == "handled_key_error"


def test_raise_for_status_does_not_suppress_field_assumption() -> None:
    source = (
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    response.raise_for_status()\n"
        '    return response.json()["field"]\n'
    )
    assert len(active(source)) == 1


def test_status_code_guard_does_not_suppress_field_assumption() -> None:
    source = (
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    if response.status_code == 200:\n"
        '        return response.json()["field"]\n'
    )
    assert len(active(source)) == 1


def test_truthy_payload_guard_does_not_suppress() -> None:
    source = (
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        "    payload = response.json()\n"
        "    if payload:\n"
        '        return payload["field"]\n'
    )
    assert len(active(source)) == 1


def test_response_field_is_not_duplicated_as_mapping_key() -> None:
    analysis_context = context(
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        '    return response.json()["field"]\n'
    )
    response = PythonRequiredResponseFieldDetector().detect(analysis_context)
    mapping = PythonRequiredMappingKeyDetector().detect(analysis_context)
    assert [item.detector_id for item in response + mapping] == ["python.required-response-field"]


def test_response_ownership_is_order_independent() -> None:
    analysis_context = context(
        "import requests\n"
        "def load(url):\n"
        "    response = requests.get(url)\n"
        '    return response.json()["field"]\n'
    )
    detectors = [
        PythonRequiredResponseFieldDetector(),
        PythonRequiredMappingKeyDetector(),
    ]
    forward = sorted(
        item.detector_id
        for detector in detectors
        for item in detector.detect(analysis_context)
        if item.suppression_reason is None
    )
    reverse = sorted(
        item.detector_id
        for detector in reversed(detectors)
        for item in detector.detect(analysis_context)
        if item.suppression_reason is None
    )
    assert forward == reverse == ["python.required-response-field"]

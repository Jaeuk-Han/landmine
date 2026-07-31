from landmine.test_protection import analyze_python_test_source


def test_non_empty_candidate_test_is_not_protection() -> None:
    matches = analyze_python_test_source(
        "tests/test_example.py",
        "def test_first():\n    assert first([1]) == 1\n",
        {"first"},
    )
    assert [(item.scope, item.empty_input) for item in matches] == [("first", False)]


def test_direct_empty_literal_marks_protection() -> None:
    matches = analyze_python_test_source(
        "tests/test_example.py",
        "def test_first_empty():\n    first([])\n",
        {"first"},
    )
    assert [(item.scope, item.empty_input) for item in matches] == [("first", True)]


def test_empty_local_passed_to_target_marks_protection() -> None:
    matches = analyze_python_test_source(
        "tests/test_example.py",
        "def test_first_empty():\n    items = []\n    first(items)\n",
        {"first"},
    )
    assert [(item.scope, item.empty_input) for item in matches] == [("first", True)]

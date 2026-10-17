from __future__ import annotations

import ast

import pytest

from factoryline.intent_quality import (
    IntentFinding,
    IntentQualityError,
    assess,
    findings_as_dict,
    normalize,
    require_clear,
)


def test_normalize_and_findings_as_dict_preserve_text_and_emit_stable_diagnostics():
    assert normalize("  A reviewer\n checks   the receipt. ") == (
        "A reviewer checks the receipt."
    )
    assert normalize(None) == ""

    findings = findings_as_dict("Make it better", field="acceptance")

    assert findings == [
        {
            "code": "INTENT_VAGUE_LANGUAGE",
            "message": "acceptance contains vague phrase: make_it_better",
        },
        {
            "code": "INTENT_NO_ACTION",
            "message": "acceptance does not state an observable action or state transition",
        },
    ]
    assert IntentFinding("INTENT_NO_ACTION", "missing action").as_dict() == {
        "code": "INTENT_NO_ACTION",
        "message": "missing action",
    }


def test_intent_quality_accepts_concrete_action_and_observation() -> None:
    text, findings = assess(
        "A reviewer can create a hash-bound receipt.",
        field="intent",
        require_observable=True,
    )
    assert text == "A reviewer can create a hash-bound receipt."
    assert findings == []


@pytest.mark.parametrize(
    "value, field, observable, code",
    [
        ("Make it better", "intent", False, "INTENT_VAGUE_LANGUAGE"),
        ("TODO", "intent", False, "INTENT_PLACEHOLDER"),
        ("Fine", "intent", False, "INTENT_NO_ACTION"),
        ("Do something", "acceptance", True, "INTENT_VAGUE_LANGUAGE"),
        ("The task runs", "acceptance", True, "INTENT_NOT_OBSERVABLE"),
    ],
)
def test_intent_quality_rejects_unverifiable_language(
    value: str, field: str, observable: bool, code: str
) -> None:
    with pytest.raises(IntentQualityError, match=code):
        require_clear(value, field=field, require_observable=observable)


@pytest.mark.parametrize(
    ("import_statement", "call_expression", "expected"),
    [
        (
            "import unittest.mock\n",
            "unittest.mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "import unittest.mock as mock\n",
            "mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "from unittest import mock\n",
            "mock.MagicMock()",
            "unittest.mock.MagicMock",
        ),
        (
            "from unittest.mock import MagicMock as Mock\n",
            "Mock()",
            "unittest.mock.MagicMock",
        ),
        (
            "import xml.etree.ElementTree\n",
            "xml.etree.ElementTree.fromstring(data)",
            "xml.etree.ElementTree.fromstring",
        ),
        ("import pickle\n", "pickle.loads(data)", "pickle.loads"),
        (
            "import pickle as serializer\n",
            "serializer.loads(data)",
            "pickle.loads",
        ),
    ],
)
def test_import_aliases_follow_python_binding_semantics(
    import_statement: str, call_expression: str, expected: str
) -> None:
    from factoryline.review_audits import (
        _module_security_aliases,
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(import_statement + f"def test_case():\n    {call_expression}\n")
    scope = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_case"
    )
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases(_module_security_aliases(tree), scope)

    assert _normalized_call_name(call, aliases) == expected


@pytest.mark.parametrize(
    ("import_statement", "binding", "call_expression"),
    [
        (
            "import unittest.mock\n",
            "unittest",
            "unittest.mock.MagicMock()",
        ),
        (
            "import unittest.mock as mock\n",
            "mock",
            "mock.MagicMock()",
        ),
        (
            "from unittest import mock\n",
            "mock",
            "mock.MagicMock()",
        ),
    ],
)
def test_import_aliases_are_invalidated_by_local_rebinding(
    import_statement: str, binding: str, call_expression: str
) -> None:
    from factoryline.review_audits import (
        _module_security_aliases,
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(
        import_statement
        + f"def test_case():\n    {binding} = replacement\n    {call_expression}\n"
    )
    scope = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "test_case"
    )
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases(_module_security_aliases(tree), scope)

    assert binding not in aliases
    assert _normalized_call_name(call, aliases) == call_expression.removesuffix("()")


def test_local_dotted_import_rebinds_the_top_level_package_after_shadowing() -> None:
    from factoryline.review_audits import (
        _normalized_call_name,
        _scope_security_aliases,
    )

    tree = ast.parse(
        "def test_case():\n"
        "    unittest = replacement\n"
        "    import unittest.mock\n"
        "    unittest.mock.MagicMock()\n"
    )
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    aliases = _scope_security_aliases({}, scope)

    assert aliases["unittest"] == "unittest"
    assert _normalized_call_name(call, aliases) == "unittest.mock.MagicMock"

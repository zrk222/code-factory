from __future__ import annotations

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

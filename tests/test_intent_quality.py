from __future__ import annotations

import pytest

from factoryline.intent_quality import IntentQualityError, assess, require_clear


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
def test_intent_quality_rejects_unverifiable_language(value: str, field: str, observable: bool, code: str) -> None:
    with pytest.raises(IntentQualityError, match=code):
        require_clear(value, field=field, require_observable=observable)

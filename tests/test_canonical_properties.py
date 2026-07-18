from __future__ import annotations

import json
import math

from hypothesis import given, strategies as st
import pytest

from factoryline.enterprise_receipts import EnterpriseReceiptError, canonical_json


UNICODE_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=80)
JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**50), max_value=10**50),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    UNICODE_TEXT,
)
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(UNICODE_TEXT, children, max_size=8),
    ),
    max_leaves=30,
)


@given(JSON_VALUES)
def test_canonical_json_round_trip_is_byte_identical(value: object) -> None:
    first = canonical_json(value)
    parsed = json.loads(first)

    assert canonical_json(parsed) == first


@given(st.dictionaries(UNICODE_TEXT, JSON_VALUES, max_size=12))
def test_canonical_json_ignores_dictionary_insertion_order(value: dict[str, object]) -> None:
    reversed_value = dict(reversed(list(value.items())))

    assert canonical_json(value) == canonical_json(reversed_value)


@pytest.mark.parametrize(
    "value",
    [
        {"value": math.nan},
        {"value": math.inf},
        {"value": -math.inf},
        {"value": "\ud800"},
        {"value": object()},
    ],
)
def test_canonical_json_classifies_unsupported_values(value: object) -> None:
    with pytest.raises(EnterpriseReceiptError) as error:
        canonical_json(value)

    assert error.value.code == "E_INVALID_PAYLOAD"


@pytest.mark.parametrize(
    "value",
    [
        {"emoji": "🧪🔐"},
        {"combining": "e\u0301"},
        {"separators": "\u2028\u2029"},
        {"nul": "\u0000"},
    ],
)
def test_canonical_json_preserves_supported_unicode(value: object) -> None:
    encoded = canonical_json(value)

    assert canonical_json(json.loads(encoded)) == encoded

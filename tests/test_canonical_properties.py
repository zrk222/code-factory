from __future__ import annotations

import json
import math
import string

from hypothesis import HealthCheck, given, settings, strategies as st
import pytest

from factoryline.enterprise_receipts import EnterpriseReceiptError, canonical_json


UNICODE_TEXT = st.text(
    alphabet=string.ascii_letters + string.digits + " -_./", max_size=24
)
JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**12), max_value=10**12),
    st.floats(
        min_value=-1_000_000.0,
        max_value=1_000_000.0,
        allow_nan=False,
        allow_infinity=False,
        width=32,
    ),
    UNICODE_TEXT,
)
JSON_VALUES = st.recursive(
    JSON_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(UNICODE_TEXT, children, max_size=3),
    ),
    max_leaves=4,
)


@given(JSON_VALUES)
@settings(suppress_health_check=[HealthCheck.too_slow])
def test_canonical_json_round_trip_is_byte_identical(value: object) -> None:
    first = canonical_json(value)
    parsed = json.loads(first)

    assert canonical_json(parsed) == first


@given(st.dictionaries(UNICODE_TEXT, JSON_VALUES, max_size=12))
def test_canonical_json_ignores_dictionary_insertion_order(
    value: dict[str, object],
) -> None:
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


@pytest.mark.parametrize(
    "module_name",
    [
        "agentic_control",
        "agui",
        "appforge_mobile_evidence",
        "appforge_oracle",
        "appforge_submission_assurance",
        "audit_trace",
        "blueprint",
        "continuous_proof",
        "first_lap",
        "full_stack_ux_harness",
        "full_stack_ux_spec",
        "gauntlet",
        "intake_grill",
        "jetbrains_handshake",
        "junie_review",
        "junie_taxonomy",
        "learning_loop",
        "proof_review_workflow",
        "release_contract",
        "repair_sandbox",
        "repo_coordination",
        "service_boundaries",
        "verifier_plane",
    ],
)
def test_shared_canonical_preserves_bytes_errors_and_deletes_duplicate_bodies(
    module_name,
):
    import ast
    import importlib
    import inspect
    from factoryline import canonical_json_bytes

    module = importlib.import_module("factoryline." + module_name)
    assert module._canonical is canonical_json_bytes
    tree = ast.parse(inspect.getsource(module))
    assert not any(
        isinstance(n, ast.FunctionDef) and n.name == "_canonical" for n in tree.body
    )
    values = [
        None,
        True,
        0,
        -0.0,
        {"z": [1, None, False], "a": "é🧪"},
        {"\u2028": "\u0000"},
    ]
    for value in values:
        expected = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        assert module._canonical(value) == expected
    for value in [math.nan, math.inf, -math.inf, object(), "\ud800"]:
        try:
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (ValueError, TypeError, UnicodeError) as original:
            with pytest.raises(type(original)):
                module._canonical(value)
        else:
            pytest.fail("negative control unexpectedly serialized")

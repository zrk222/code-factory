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


@pytest.mark.parametrize(
    "module_name, profile, parameter",
    [
        ("adoption", "unicode", "value"),
        ("agent_license", "unicode", "value"),
        ("appforge_device_reality", "unicode", "value"),
        ("appforge_eas", "unicode", "value"),
        ("appforge_fastlane_capture", "unicode", "value"),
        ("appforge_native_surface", "unicode", "value"),
        ("appforge_quality_audit", "unicode", "value"),
        ("appforge_release_rehearsal", "unicode", "value"),
        ("appforge_storefront_story", "unicode", "value"),
        ("appforge_store_media", "unicode", "value"),
        ("appforge_submission_integrity", "unicode", "v"),
        ("appforge_surface_matrix", "unicode", "value"),
        ("audit_taxonomy", "strict", "value"),
        ("capability_packs", "ascii", "value"),
        ("change_review", "unicode", "value"),
        ("codex_metadata", "unicode", "value"),
        ("continuous_controls", "unicode", "value"),
        ("counterexample", "unicode", "value"),
        ("developer_memory", "unicode", "value"),
        ("e2e_proof", "unicode", "value"),
        ("evidence_frontier", "unicode", "value"),
        ("gauntlet_draft", "unicode", "value"),
        ("github_assurance_dossier", "unicode", "value"),
        ("github_plan_proof_review", "unicode", "value"),
        ("github_proof_review", "unicode", "value"),
        ("graph_authorization", "unicode", "value"),
        ("graph_forensics", "unicode", "value"),
        ("graph_ops", "unicode", "value"),
        ("graph_portfolio", "ascii", "value"),
        ("guardrails", "unicode", "value"),
        ("index_continuity", "unicode", "value"),
        ("intent_ledger", "unicode", "value"),
        ("journey_proof", "unicode", "value"),
        ("judgment", "ascii", "value"),
        ("loop_passport", "unicode", "value"),
        ("mcp_mrt", "unicode", "value"),
        ("migration", "ascii", "value"),
        ("oracle_firewall", "unicode", "value"),
        ("plan_proof_review", "unicode", "value"),
        ("prd_grill", "unicode", "value"),
        ("product_missions", "unicode", "value"),
        ("proof", "ascii", "payload"),
        ("proofsearch", "unicode", "value"),
        ("proof_continuity_ledger", "unicode", "value"),
        ("proof_delta_telemetry", "unicode", "value"),
        ("proof_reuse", "ascii", "value"),
        ("reality_check", "unicode", "value"),
        ("release_candidate", "strict", "value"),
        ("resilience", "unicode", "value"),
        ("revenueforge", "unicode", "value"),
        ("revenue_evidence", "unicode", "value"),
        ("revenue_integrity", "unicode", "value"),
        ("run_admission", "ascii", "value"),
        ("saas_proof", "unicode", "value"),
        ("semantic_authority", "unicode", "value"),
        ("session_recorder", "unicode", "value"),
        ("signal_loop", "ascii", "value"),
        ("team_pilot", "unicode", "value"),
    ],
)
def test_remaining_shared_encoder_keeps_byte_error_and_keyword_contract(
    module_name, profile, parameter
):
    import ast
    import importlib
    import inspect
    import factoryline

    module = importlib.import_module("factoryline." + module_name)
    helpers = {
        "strict": factoryline.canonical_json_bytes,
        "unicode": factoryline.canonical_json_compat_bytes,
        "ascii": factoryline.canonical_ascii_json_compat_bytes,
    }
    encoders = [
        n
        for n in ast.parse(inspect.getsource(module)).body
        if isinstance(n, ast.FunctionDef) and n.name == "_canonical"
    ]
    if parameter == "value":
        assert module._canonical is helpers[profile]
        assert encoders == []
    else:
        assert module._canonical_encode is helpers[profile]
        assert len(encoders) == 1 and len(encoders[0].body) == 1
        assert isinstance(encoders[0].body[0], ast.Return)
        assert ast.unparse(encoders[0].body[0].value.func) == "_canonical_encode"
    options = {
        "ensure_ascii": profile == "ascii",
        "sort_keys": True,
        "separators": (",", ":"),
        "allow_nan": profile != "strict",
    }
    values = [
        None,
        True,
        -0.0,
        {"z": [1, None], "a": "é🧪"},
        "\u2028\u0000",
        math.nan,
        math.inf,
        -math.inf,
        object(),
        "\ud800",
        {1: "a", "b": "c"},
    ]
    for value in values:
        try:
            expected = json.dumps(value, **options).encode("utf-8")
        except (ValueError, TypeError, UnicodeError) as original:
            with pytest.raises(type(original)):
                module._canonical(value)
            with pytest.raises(type(original)):
                module._canonical(**{parameter: value})
        else:
            assert module._canonical(value) == expected
            assert module._canonical(**{parameter: value}) == expected

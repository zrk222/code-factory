from __future__ import annotations

import json

import pytest

from factoryline.runtime_audit_common import (
    MAX_ARTIFACT_BYTES,
    RuntimeAuditError,
    exact_keys,
    lane_result,
    parse_json_bytes,
    read_stable_json,
    reject_secret_material,
    require_bool,
    require_digest,
    require_int,
    require_number,
    require_str,
    require_unique_strings,
)


def _error_code(error: pytest.ExceptionInfo[RuntimeAuditError]) -> str:
    return error.value.code


def test_exact_keys_accepts_declared_fields_and_ignores_only_verdict_labels():
    exact_keys(
        {"id": "case-1", "mode": "strict", "passed": True},
        {"id"},
        {"mode"},
    )

    with pytest.raises(RuntimeAuditError) as missing:
        exact_keys({"mode": "strict"}, {"id"})
    assert _error_code(missing) == "E_ARTIFACT_FIELDS"

    with pytest.raises(RuntimeAuditError) as unknown:
        exact_keys({"id": "case-1", "authority": "approve"}, {"id"})
    assert _error_code(unknown) == "E_ARTIFACT_FIELDS"

    with pytest.raises(RuntimeAuditError) as wrong_type:
        exact_keys([("id", "case-1")], {"id"})  # type: ignore[arg-type]
    assert _error_code(wrong_type) == "E_ARTIFACT_FIELDS"


@pytest.mark.parametrize(
    ("value", "minimum", "maximum"),
    [("x", 1, 1), (" evidence ", 1, 10)],
)
def test_require_str_accepts_printable_strings_at_declared_bounds(
    value: str, minimum: int, maximum: int
):
    assert require_str(value, "label", minimum=minimum, maximum=maximum) == value


@pytest.mark.parametrize("value", [None, 5, "", "  ", "a\nb"])
def test_require_str_rejects_wrong_type_blank_and_control_text(value: object):
    with pytest.raises(RuntimeAuditError) as error:
        require_str(value, "label", maximum=4)
    assert _error_code(error) == "E_FIELD"


def test_require_digest_accepts_canonical_sha256_and_rejects_noncanonical_values():
    digest = "a" * 64
    assert require_digest(digest, "sha256") == digest
    for invalid in ("A" * 64, "a" * 63, "g" * 64, 123):
        with pytest.raises(RuntimeAuditError) as error:
            require_digest(invalid, "sha256")
        assert _error_code(error) == "E_DIGEST"


def test_require_bool_refuses_integer_truthiness_and_strings():
    assert require_bool(False, "enabled") is False
    with pytest.raises(RuntimeAuditError) as error:
        require_bool(1, "enabled")
    assert _error_code(error) == "E_FIELD"


def test_require_int_enforces_inclusive_range_without_accepting_bool():
    assert require_int(3, "attempts", minimum=1, maximum=3) == 3
    for invalid in (True, 0, 4, 3.0, "3"):
        with pytest.raises(RuntimeAuditError) as error:
            require_int(invalid, "attempts", minimum=1, maximum=3)
        assert _error_code(error) == "E_FIELD"


def test_require_number_accepts_finite_values_and_rejects_bool_nan_and_floor():
    assert require_number(2, "ratio", minimum=1.5) == 2.0
    for invalid in (True, float("nan"), float("inf"), 1.4, "2"):
        with pytest.raises(RuntimeAuditError) as error:
            require_number(invalid, "ratio", minimum=1.5)
        assert _error_code(error) == "E_FIELD"


def test_require_unique_strings_preserves_values_and_rejects_duplicate_or_invalid_items():
    assert require_unique_strings(["alpha", "beta"], "ids", minimum=1, maximum=2) == [
        "alpha",
        "beta",
    ]
    for invalid in (["alpha", "alpha"], ["alpha", ""], [], ["a", "b", "c"]):
        with pytest.raises(RuntimeAuditError) as error:
            require_unique_strings(invalid, "ids", minimum=1, maximum=2)
        assert _error_code(error) in {"E_FIELD", "E_DUPLICATE_ID"}


def test_reject_secret_material_checks_nested_keys_depth_numbers_and_string_size():
    reject_secret_material({"audit": [{"finding": "bounded"}]})
    for value, expected_code in (
        ({"audit": {"token": "hidden"}}, "E_SECRET_MATERIAL"),
        ({"audit": float("nan")}, "E_NONFINITE"),
        ({"audit": "x" * 5}, "E_FIELD_SIZE"),
    ):
        with pytest.raises(RuntimeAuditError) as error:
            reject_secret_material(value, max_string_length=4)
        assert _error_code(error) == expected_code

    nested: object = "leaf"
    for _ in range(34):
        nested = [nested]
    with pytest.raises(RuntimeAuditError) as error:
        reject_secret_material(nested)
    assert _error_code(error) == "E_ARTIFACT_DEPTH"


def test_parse_json_bytes_accepts_safe_object_and_rejects_ambiguous_or_unsafe_json():
    parsed = parse_json_bytes(b'{"id":"audit-1","count":2}')
    assert parsed == {"id": "audit-1", "count": 2}

    invalid_documents = (
        (b'{"id":1,"id":2}', "E_DUPLICATE_FIELD"),
        (b"[]", "E_ARTIFACT_JSON"),
        (b"{", "E_ARTIFACT_JSON"),
        (b'{"token":"hidden"}', "E_SECRET_MATERIAL"),
        (b"\xff", "E_ARTIFACT_JSON"),
        (b"{}" + b" " * MAX_ARTIFACT_BYTES, "E_ARTIFACT_SIZE"),
    )
    for raw, expected_code in invalid_documents:
        with pytest.raises(RuntimeAuditError) as error:
            parse_json_bytes(raw)
        assert _error_code(error) == expected_code


def test_read_stable_json_returns_exact_bytes_digest_and_rejects_missing_file(tmp_path):
    raw = json.dumps({"schema": "factory.audit.v1"}, separators=(",", ":")).encode()
    artifact = tmp_path / "receipt.json"
    artifact.write_bytes(raw)

    parsed, digest = read_stable_json(artifact)
    assert parsed == {"schema": "factory.audit.v1"}
    assert digest == __import__("hashlib").sha256(raw).hexdigest()

    with pytest.raises(RuntimeAuditError) as error:
        read_stable_json(tmp_path / "missing.json")
    assert _error_code(error) == "E_ARTIFACT_MISSING"


def test_lane_result_only_emits_closed_states_and_keeps_advisory_details():
    result = lane_result(
        "security", "FAIL", "UNSAFE_INPUT", "review the finding", details={"count": 1}
    )
    assert result == {
        "lane": "security",
        "state": "FAIL",
        "finding": "UNSAFE_INPUT",
        "consequence": "review the finding",
        "details": {"count": 1},
    }

    with pytest.raises(RuntimeAuditError) as error:
        lane_result("security", "APPROVED", "NONE", "not an authority")
    assert _error_code(error) == "E_STATE"

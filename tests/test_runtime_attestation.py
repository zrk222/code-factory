from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import base64
from types import CodeType
import pytest
from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.runtime_attestation import (
    PAYLOAD_TYPE,
    SCHEMA,
    TEST_ORACLE_PAYLOAD_TYPE,
    TEST_ORACLE_PAYLOAD_TYPE_V2,
    TEST_ORACLE_PAYLOAD_TYPE_V3,
    TEST_ORACLE_SCHEMA,
    TEST_ORACLE_SCHEMA_V2,
    TEST_ORACLE_SCHEMA_V3,
    TEST_ORACLE_VERIFICATION_SCHEMA_V3,
    TEST_ORACLE_VERIFICATION_SCHEMA_V2,
    RuntimeAttestationError,
    capture_supervised_attestation,
    runtime_boundary_decision,
    validate_runtime_attestation,
    verify_signed_test_oracles,
    verify_signed_runtime_attestation,
)
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes
import io
import os
import py_compile
import sys
import threading
from factoryline.runtime_audit_process import (
    _drain_stream,
    _stop,
    create_bounded_temp_directory,
    remove_bounded_temp_directory,
    run_bounded_command,
    validate_production_mutation_process,
)
from factoryline.runtime_audit_runner import (
    capture_local_production_mutation,
    run_runtime_audit_plan,
)
from factoryline.runtime_audit_contract import verify_runtime_audit_plan
from test_runtime_audit_contract import D, signed_plan


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _independent_payload(*, now: datetime | None = None) -> dict:
    issued = now or datetime.now(timezone.utc)
    executable = _digest("hardened-runner")
    payload = {
        "schema": SCHEMA,
        "attestation_id": "boundary-001",
        "candidate_sha256": _digest("candidate"),
        "plan_sha256": _digest("plan"),
        "environment_sha256": _digest("environment"),
        "run_nonce": "nonce-001",
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(hours=1)).isoformat(),
        "requested_isolation": "hardened_vm",
        "collector": {
            "id": "vm-collector",
            "version": "1",
            "role": "external_collector",
            "backend": "hardened_vm",
            "executable_sha256": executable,
        },
        "observations": {
            "shell": False,
            "stdin": "devnull",
            "stdout_capture": "hashed_pipe",
            "stderr_capture": "hashed_pipe",
            "environment_policy": "minimal_allowlist",
            "platform": "linux",
            "python_version": "3.12",
            "executable_sha256": executable,
            "workspace_environment_sha256": _digest("environment"),
            "cleanup_confirmed": True,
            "memory_peak_bytes": 128,
            "latency_ms": 4,
        },
        "isolation": {
            "backend": "hardened_vm",
            "state": "VERIFIED",
            "proof": True,
            "claim_boundary": "External collector supplied signed VM boundary evidence; application correctness remains unproven.",
        },
        "authority": "none",
    }
    payload["attestation_sha256"] = sha256_bytes(canonical_bytes(payload))
    return payload


def test_local_capture_is_explicitly_supervised_only(tmp_path: Path):
    attestation = capture_supervised_attestation(
        attestation_id="local-001",
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
    )
    result = runtime_boundary_decision(
        attestation,
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
        requested_isolation="supervised_subprocess",
    )
    assert result["state"] == "SUPERVISED_ONLY"
    blocked = runtime_boundary_decision(
        attestation,
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
        requested_isolation="isolated_worker",
    )
    assert (
        blocked["state"] == "BLOCKED" and blocked["finding"] == "E_ISOLATION_UNPROVEN"
    )


def test_boundary_rejects_shell_executable_drift_and_stale_observations():
    payload = _independent_payload()
    payload["observations"]["shell"] = True
    payload["attestation_sha256"] = sha256_bytes(
        canonical_bytes(
            {
                key: value
                for key, value in payload.items()
                if key != "attestation_sha256"
            }
        )
    )
    with pytest.raises(RuntimeAttestationError, match="E_SHELL_ENABLED"):
        validate_runtime_attestation(payload)

    payload = _independent_payload()
    payload["observations"]["executable_sha256"] = _digest("different")
    payload["attestation_sha256"] = sha256_bytes(
        canonical_bytes(
            {
                key: value
                for key, value in payload.items()
                if key != "attestation_sha256"
            }
        )
    )
    with pytest.raises(RuntimeAttestationError, match="E_ATTESTATION_BINDING"):
        validate_runtime_attestation(payload)

    stale = _independent_payload(now=datetime.now(timezone.utc) - timedelta(hours=2))
    with pytest.raises(RuntimeAttestationError, match="E_ATTESTATION_FRESHNESS"):
        validate_runtime_attestation(stale)


def test_boundary_missing_or_tampered_evidence_blocks_without_authority():
    missing = runtime_boundary_decision(
        None,
        candidate_sha256=_digest("candidate"),
        plan_sha256=_digest("plan"),
        environment_sha256=_digest("environment"),
        requested_isolation="hardened_vm",
    )
    assert (
        missing["state"] == "BLOCKED"
        and missing["finding"] == "E_RUNTIME_ATTESTATION_MISSING"
    )
    payload = _independent_payload()
    payload["attestation_sha256"] = _digest("tampered")
    decision = runtime_boundary_decision(
        payload,
        candidate_sha256=payload["candidate_sha256"],
        plan_sha256=payload["plan_sha256"],
        environment_sha256=payload["environment_sha256"],
        requested_isolation="hardened_vm",
    )
    assert (
        decision["state"] == "BLOCKED"
        and decision["finding"] == "E_ATTESTATION_SELF_HASH"
    )


def test_signed_external_boundary_verifies_offline(tmp_path: Path):
    keys = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="boundary-key",
        identity="collector@example",
        issuer="local",
    )
    payload = _independent_payload()
    envelope = sign_payload(
        payload,
        payload_type=PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt = tmp_path / "boundary.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    result = verify_signed_runtime_attestation(
        receipt,
        Path(keys["trust_root"]),
        candidate_sha256=payload["candidate_sha256"],
        plan_sha256=payload["plan_sha256"],
        environment_sha256=payload["environment_sha256"],
    )
    assert result["state"] == "VERIFIED"
    assert result["requested_isolation"] == "hardened_vm"
    assert result["authority"] == "none" and result["release_approval"] is False
    assert len(result["verification_sha256"]) == 64


def _oracle_payload(*, now: datetime | None = None) -> dict:
    issued = now or datetime.now(timezone.utc)
    case = "tests/test_example.py::test_example[case-1]"
    return {
        "schema": TEST_ORACLE_SCHEMA,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(hours=1)).isoformat(),
        "source_manifest_sha256": _digest("manifest"),
        "environment_sha256": _digest("oracle-environment"),
        "authority": "none",
        "tests": [
            {
                "path": "tests/test_example.py",
                "line": 12,
                "symbol": "test_example",
                "test_sha256": _digest("test source"),
                "baseline": {
                    "status": "PASS",
                    "phase": "call",
                    "collection_complete": True,
                    "case_ids": [case],
                    "report_sha256": _digest("baseline report"),
                },
                "mutation": {
                    "source_path": "factoryline/example.py",
                    "source_sha256": _digest("original source"),
                    "mutant_sha256": _digest("mutated source"),
                    "status": "FAIL",
                    "phase": "call",
                    "case_ids": [case],
                    "failure_kind": "assertion",
                    "report_sha256": _digest("mutation report"),
                },
            }
        ],
    }


def _oracle_payload_v2(*, now: datetime | None = None) -> dict:
    payload = _oracle_payload(now=now)
    payload["schema"] = TEST_ORACLE_SCHEMA_V2
    test = payload["tests"][0]
    case_id = test["baseline"]["case_ids"][0]
    test_source = {
        "case_id": case_id,
        "phase": "call",
        "source_path": test["path"],
        "module_name": "tests.test_example",
        "source_sha256": test["test_sha256"],
        "observation_kind": "executed_frame",
    }
    target_source = {
        "case_id": case_id,
        "phase": "call",
        "source_path": test["mutation"]["source_path"],
        "module_name": "factoryline.example",
        "source_sha256": test["mutation"]["source_sha256"],
        "observation_kind": "executed_frame",
    }
    test["baseline"]["module_origins"] = [test_source, target_source]
    test["mutation"]["module_origins"] = [
        test_source,
        {**target_source, "source_sha256": test["mutation"]["mutant_sha256"]},
    ]
    return payload


def _oracle_payload_v3(*, now: datetime | None = None) -> dict:
    payload = _oracle_payload_v2(now=now)
    payload["schema"] = TEST_ORACLE_SCHEMA_V3
    test = payload["tests"][0]
    case_id = test["baseline"]["case_ids"][0]
    callback = "test_example.<locals>.callback"
    assertion = {
        "case_id": case_id,
        "source_path": test["path"],
        "source_sha256": test["test_sha256"],
        "callback_qualname": callback,
        "line": 10,
        "assertion_kind": "assert",
        "hits": 1,
    }
    manifest_sha = _digest("[]")
    for run_name in ("baseline", "mutation"):
        run = test[run_name]
        run["setup_status"] = "PASS"
        run["teardown_status"] = "PASS"
        run["collection_catalog"] = {
            "status": "PASS",
            "phase": "collection",
            "complete": True,
            "scope": "test_function",
            "source_path": test["path"],
            "source_sha256": test["test_sha256"],
            "config_manifest": [],
            "config_manifest_sha256": manifest_sha,
            "config_identity": "pytest-default",
            "report_sha256": _digest(f"{run_name} collection report"),
            "case_ids": list(run["case_ids"]),
        }
        run["assertion_observations"] = [
            {
                **assertion,
                "outcome": "PASS" if run_name == "baseline" else "FAIL",
                "failure_visible": run_name == "mutation",
            }
        ]
        for origin in run["module_origins"]:
            if origin["source_path"] == test["path"]:
                origin["frame_qualname"] = "test_example"
            else:
                origin["frame_qualname"] = "product_call"
        run["module_origins"].append(
            {
                "case_id": case_id,
                "phase": "call",
                "source_path": test["path"],
                "module_name": "tests.test_example",
                "source_sha256": test["test_sha256"],
                "observation_kind": "executed_frame",
                "frame_qualname": callback,
            }
        )
    test["baseline"]["module_origins"][0]["frame_qualname"] = "test_example"
    test["mutation"]["module_origins"][0]["frame_qualname"] = "test_example"
    return payload


def _signed_oracle(tmp_path: Path, payload: dict | None = None):
    keys = generate_key_material(
        out_dir=tmp_path / "oracle-keys",
        keyid="oracle-key",
        identity="oracle@example",
        issuer="local",
    )
    trust_path = Path(keys["trust_root"])
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["keys"][0]["roles"] = ["oracle-verifier"]
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    payload = payload or _oracle_payload()
    envelope = sign_payload(
        payload,
        payload_type=(
            TEST_ORACLE_PAYLOAD_TYPE_V2
            if payload["schema"] == TEST_ORACLE_SCHEMA_V2
            else TEST_ORACLE_PAYLOAD_TYPE_V3
            if payload["schema"] == TEST_ORACLE_SCHEMA_V3
            else TEST_ORACLE_PAYLOAD_TYPE
        ),
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt_path = tmp_path / "test-oracle.json"
    receipt_path.write_text(json.dumps(envelope), encoding="utf-8")
    return receipt_path, trust_path, trust, payload


def _verify_oracle(
    receipt_path: Path,
    trust_path: Path,
    payload: dict,
    *,
    now=None,
    source_manifest_sha256=None,
    environment_sha256=None,
):
    trust_sha = sha256_bytes(trust_path.read_bytes())
    return verify_signed_test_oracles(
        receipt_path,
        trust_path,
        trust_root_sha256=trust_sha,
        source_manifest_sha256=source_manifest_sha256
        or payload["source_manifest_sha256"],
        environment_sha256=environment_sha256 or payload["environment_sha256"],
        now=now,
    )


def test_signed_test_oracle_verifies_bounded_signer_claim(tmp_path: Path):
    now = datetime.now(timezone.utc)
    payload = _oracle_payload(now=now)
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    result = _verify_oracle(receipt, trust, payload, now=now + timedelta(minutes=1))

    assert result["state"] == "VERIFIED"
    assert result["authority"] == "none"
    assert result["tests"][0]["baseline"]["collection_complete"] is True
    assert result["signature"]["role"] == "oracle-verifier"
    assert len(result["receipt_sha256"]) == 64
    assert "not established" in result["claim_boundary"]


def test_signed_test_oracle_v2_requires_bound_executed_origins(tmp_path: Path):
    now = datetime.now(timezone.utc)
    payload = _oracle_payload_v2(now=now)
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    result = _verify_oracle(receipt, trust, payload, now=now + timedelta(minutes=1))

    assert result["state"] == "VERIFIED"
    assert result["schema"] == TEST_ORACLE_VERIFICATION_SCHEMA_V2
    assert result["authority"] == "none"
    assert (
        result["tests"][0]["baseline"]["module_origins"]
        == payload["tests"][0]["baseline"]["module_origins"]
    )


def test_signed_test_oracle_v2_allows_consistent_module_aliases(tmp_path: Path):
    payload = _oracle_payload_v2()
    target = payload["tests"][0]["baseline"]["module_origins"][1]
    payload["tests"][0]["baseline"]["module_origins"].append(
        {
            **target,
            "module_name": "factoryline.alias",
            "observation_kind": "imported_module",
        }
    )
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    result = _verify_oracle(receipt, trust, payload)

    assert result["state"] == "VERIFIED"


def test_signed_test_oracle_v3_verifies_collection_and_assertion_observations(
    tmp_path: Path,
):
    payload = _oracle_payload_v3()
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    result = _verify_oracle(receipt, trust, payload)

    assert result["state"] == "VERIFIED"
    assert result["schema"] == TEST_ORACLE_VERIFICATION_SCHEMA_V3
    assert result["tests"][0]["baseline"]["collection_catalog"]["case_ids"]
    assert (
        result["tests"][0]["mutation"]["assertion_observations"][0]["failure_visible"]
        is True
    )


def _compiled_frame_qualname(source: str, code_name: str) -> str | None:
    root = compile(source, "frame_qualname_fixture.py", "exec")
    if code_name == "<module>":
        return getattr(root, "co_qualname", None)
    pending = [root]
    while pending:
        code = pending.pop()
        if code.co_name == code_name:
            return getattr(code, "co_qualname", None)
        pending.extend(item for item in code.co_consts if isinstance(item, CodeType))
    return None


def _append_test_frame(payload: dict, qualname: str) -> None:
    test = payload["tests"][0]
    for run_name in ("baseline", "mutation"):
        definition = next(
            row
            for row in test[run_name]["module_origins"]
            if row["source_path"] == test["path"]
            and row["frame_qualname"] == "test_example"
        )
        test[run_name]["module_origins"].append(
            {**definition, "frame_qualname": qualname}
        )


@pytest.mark.parametrize(
    ("source", "code_name", "legacy_qualname"),
    [
        (
            "def outer():\n return [x for x in ()]\n",
            "<listcomp>",
            "outer.<locals>.<listcomp>",
        ),
        (
            "def outer():\n return {x for x in ()}\n",
            "<setcomp>",
            "outer.<locals>.<setcomp>",
        ),
        (
            "def outer():\n return {x: x for x in ()}\n",
            "<dictcomp>",
            "outer.<locals>.<dictcomp>",
        ),
        (
            "def outer():\n return (x for x in ())\n",
            "<genexpr>",
            "outer.<locals>.<genexpr>",
        ),
        (
            "def outer():\n return lambda: None\n",
            "<lambda>",
            "outer.<locals>.<lambda>",
        ),
        ("value = 1\n", "<module>", "<module>"),
    ],
)
def test_v3_frame_origins_accept_compiler_and_legacy_qualnames(
    source: str, code_name: str, legacy_qualname: str
):
    import factoryline.runtime_attestation as oracle

    emitted_qualname = _compiled_frame_qualname(source, code_name)
    assert code_name in legacy_qualname
    if emitted_qualname is not None:
        assert emitted_qualname == legacy_qualname
    payload = _oracle_payload_v3()
    _append_test_frame(payload, legacy_qualname)
    normalized = oracle._oracle_payload(
        payload,
        source_manifest_sha256=payload["source_manifest_sha256"],
        environment_sha256=payload["environment_sha256"],
        now=datetime.now(timezone.utc),
    )["tests"][0]["baseline"]["module_origins"]
    assert normalized[0]["frame_qualname"] == "test_example"
    assert any(row["frame_qualname"] == legacy_qualname for row in normalized)


@pytest.mark.parametrize(
    "qualname",
    [
        "<bogus>",
        "outer.<listcomp",
        "outer.<localsx>.f",
        "outer.<>",
        "outer.<module>",
        "<module>.f",
        "outer.<listcomp>.<module>",
    ],
)
def test_v3_frame_origins_reject_unknown_or_malformed_special_tokens(qualname: str):
    import factoryline.runtime_attestation as oracle

    payload = _oracle_payload_v3()
    _append_test_frame(payload, qualname)
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_ORIGIN"):
        oracle._oracle_payload(
            payload,
            source_manifest_sha256=payload["source_manifest_sha256"],
            environment_sha256=payload["environment_sha256"],
            now=datetime.now(timezone.utc),
        )


def test_v3_callback_assertion_qualnames_still_reject_compiler_tokens():
    import factoryline.runtime_attestation as oracle

    payload = _oracle_payload_v3()
    for run_name in ("baseline", "mutation"):
        payload["tests"][0][run_name]["assertion_observations"][0][
            "callback_qualname"
        ] = "test_example.<locals>.<listcomp>"
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_ASSERTION"):
        oracle._oracle_payload(
            payload,
            source_manifest_sha256=payload["source_manifest_sha256"],
            environment_sha256=payload["environment_sha256"],
            now=datetime.now(timezone.utc),
        )


def test_signed_test_oracle_v3_rejects_wrong_dsse_payload_type(tmp_path: Path):
    keys = generate_key_material(
        out_dir=tmp_path / "oracle-keys",
        keyid="oracle-key",
        identity="oracle@example",
        issuer="local",
    )
    trust_path = Path(keys["trust_root"])
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["keys"][0]["roles"] = ["oracle-verifier"]
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    payload = _oracle_payload_v3()
    envelope = sign_payload(
        payload,
        payload_type=TEST_ORACLE_PAYLOAD_TYPE_V2,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt = tmp_path / "wrong-v3-payload-type.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(RuntimeAttestationError, match="E_PAYLOAD_TYPE_MISMATCH"):
        _verify_oracle(receipt, trust_path, payload)


def _oracle_assertion_observation_rows(test: dict, count: int) -> list[dict]:
    return [
        {
            "case_id": test["baseline"]["case_ids"][0],
            "source_path": test["path"],
            "source_sha256": test["test_sha256"],
            "callback_qualname": f"test_example.<locals>.callback_{index}",
            "line": 10,
            "assertion_kind": "assert",
            "hits": 1,
            "outcome": "PASS",
            "failure_visible": False,
        }
        for index in range(count)
    ]


def test_oracle_assertion_record_limit_boundary_is_accepted():
    from factoryline.runtime_attestation import _oracle_assertion_observations

    test = _oracle_payload_v3()["tests"][0]
    observations = _oracle_assertion_observation_rows(test, 8192)

    result = _oracle_assertion_observations(
        observations,
        field="baseline.assertion_observations",
        case_ids=test["baseline"]["case_ids"],
        test_path=test["path"],
        test_sha=test["test_sha256"],
        outcome="PASS",
        failure_visible=False,
    )

    assert len(result) == 8192


def test_oracle_assertion_record_limit_is_enforced():
    payload = _oracle_payload_v3()
    from factoryline.runtime_attestation import _oracle_assertion_observations

    test = payload["tests"][0]
    observations = _oracle_assertion_observation_rows(test, 8193)

    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_ASSERTION"):
        _oracle_assertion_observations(
            observations,
            field="baseline.assertion_observations",
            case_ids=test["baseline"]["case_ids"],
            test_path=test["path"],
            test_sha=test["test_sha256"],
            outcome="PASS",
            failure_visible=False,
        )


def test_signed_test_oracle_v3_accepts_subset_of_complete_collection_for_partial_use(
    tmp_path: Path,
):
    payload = _oracle_payload_v3()
    test = payload["tests"][0]
    test["baseline"]["collection_catalog"]["case_ids"].append(
        "tests/test_example.py::test_example[case-2]"
    )
    test["mutation"]["collection_catalog"]["case_ids"].append(
        "tests/test_example.py::test_example[case-2]"
    )
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    result = _verify_oracle(receipt, trust, payload)

    assert result["state"] == "VERIFIED"
    assert len(result["tests"][0]["baseline"]["case_ids"]) == 1
    assert len(result["tests"][0]["baseline"]["collection_catalog"]["case_ids"]) == 2


def test_signed_test_oracle_v2_rejects_v3_collection_fields(tmp_path: Path):
    payload = _oracle_payload_v2()
    payload["tests"][0]["baseline"]["collection_catalog"] = {}
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_SCHEMA"):
        _verify_oracle(receipt, trust, payload)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda p: p["tests"][0]["baseline"]["collection_catalog"].update(
                config_identity="manifest"
            ),
            "E_ORACLE_COLLECTION",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(setup_status="FAIL"),
            "E_ORACLE_MUTATION",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["assertion_observations"][0].update(
                source_sha256=_digest("changed test source")
            ),
            "E_ORACLE_ASSERTION",
        ),
        (
            lambda p: p["tests"][0]["mutation"]["assertion_observations"][0].update(
                failure_visible=False
            ),
            "E_ORACLE_ASSERTION",
        ),
        (
            lambda p: p["tests"][0]["mutation"]["module_origins"].pop(1),
            "E_ORACLE_ORIGIN",
        ),
    ],
)
def test_signed_test_oracle_v3_rejects_incomplete_callback_claims(
    tmp_path: Path, mutate, code: str
):
    payload = _oracle_payload_v3()
    mutate(payload)
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match=code):
        _verify_oracle(receipt, trust, payload)


def test_signed_test_oracle_v2_requires_origins_for_each_selected_case(
    tmp_path: Path,
):
    payload = _oracle_payload_v2()
    test = payload["tests"][0]
    first_case = test["baseline"]["case_ids"][0]
    second_case = "tests/test_example.py::test_example[case-2]"
    for run in ("baseline", "mutation"):
        test[run]["case_ids"].append(second_case)
        second_case_origins = [
            {**origin, "case_id": second_case} for origin in test[run]["module_origins"]
        ]
        test[run]["module_origins"].extend(second_case_origins)
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    result = _verify_oracle(receipt, trust, payload)

    assert result["tests"][0]["baseline"]["case_ids"] == [first_case, second_case]
    assert {
        origin["case_id"] for origin in result["tests"][0]["mutation"]["module_origins"]
    } == {first_case, second_case}


def test_signed_test_oracle_v2_rejects_origins_missing_for_one_case(tmp_path: Path):
    payload = _oracle_payload_v2()
    second_case = "tests/test_example.py::test_example[case-2]"
    test = payload["tests"][0]
    for run in ("baseline", "mutation"):
        test[run]["case_ids"].append(second_case)
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_ORIGIN"):
        _verify_oracle(receipt, trust, payload)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"][1].update(
                observation_kind="imported_module"
            ),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["mutation"]["module_origins"].pop(),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"][0].update(
                source_sha256=_digest("changed test source")
            ),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["mutation"]["module_origins"][1].update(
                case_id="tests/test_other.py::test_other"
            ),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"][1].update(
                source_path="C:/src/example.py"
            ),
            "E_ORACLE_PATH",
        ),
        (
            lambda p: p["tests"][0]["baseline"].update(status="UNKNOWN"),
            "E_ORACLE_BASELINE",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"].append(
                dict(p["tests"][0]["baseline"]["module_origins"][0])
            ),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"].append(
                {
                    **p["tests"][0]["baseline"]["module_origins"][0],
                    "observation_kind": "imported_module",
                    "source_sha256": _digest("conflicting import digest"),
                }
            ),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"].append(
                {
                    **p["tests"][0]["baseline"]["module_origins"][1],
                    "module_name": "factoryline.alias",
                    "observation_kind": "imported_module",
                    "source_sha256": _digest("conflicting alias digest"),
                }
            ),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"].append(
                {
                    **p["tests"][0]["baseline"]["module_origins"][1],
                    "source_path": "factoryline/alias.py",
                    "observation_kind": "imported_module",
                }
            ),
            "E_ORACLE_ORIGIN",
        ),
        (
            lambda p: p["tests"][0]["baseline"]["module_origins"][0].update(
                phase="setup"
            ),
            "E_ORACLE_ORIGIN",
        ),
    ],
)
def test_signed_test_oracle_v2_rejects_unproven_origins(
    tmp_path: Path, mutate, code: str
):
    payload = _oracle_payload_v2()
    mutate(payload)
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match=code):
        _verify_oracle(receipt, trust, payload)


def test_signed_test_oracle_v1_does_not_accept_v2_origin_fields(tmp_path: Path):
    payload = _oracle_payload()
    payload["tests"][0]["baseline"]["module_origins"] = []
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_SCHEMA"):
        _verify_oracle(receipt, trust, payload)


def test_signed_test_oracle_v2_rejects_wrong_dsse_payload_type(tmp_path: Path):
    keys = generate_key_material(
        out_dir=tmp_path / "oracle-keys",
        keyid="oracle-key",
        identity="oracle@example",
        issuer="local",
    )
    trust_path = Path(keys["trust_root"])
    trust = json.loads(trust_path.read_text(encoding="utf-8"))
    trust["keys"][0]["roles"] = ["oracle-verifier"]
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    payload = _oracle_payload_v2()
    envelope = sign_payload(
        payload,
        payload_type=TEST_ORACLE_PAYLOAD_TYPE,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt = tmp_path / "wrong-payload-type.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(RuntimeAttestationError):
        _verify_oracle(receipt, trust_path, payload)


def test_signed_test_oracle_rejects_non_string_schema(tmp_path: Path):
    payload = _oracle_payload()
    payload["schema"] = [TEST_ORACLE_SCHEMA]
    receipt, trust, _, _ = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_SCHEMA"):
        _verify_oracle(receipt, trust, payload)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (lambda p: p.update(authority="release"), "E_ORACLE_SCHEMA"),
        (
            lambda p: p["tests"][0]["baseline"].update(collection_complete=False),
            "E_ORACLE_BASELINE",
        ),
        (
            lambda p: p["tests"][0]["baseline"].update(phase="setup"),
            "E_ORACLE_BASELINE",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(phase="teardown"),
            "E_ORACLE_MUTATION",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(failure_kind="timeout"),
            "E_ORACLE_MUTATION",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(
                case_ids=["tests/test_other.py::test_other"]
            ),
            "E_ORACLE_CASES",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(
                mutant_sha256=p["tests"][0]["mutation"]["source_sha256"]
            ),
            "E_ORACLE_MUTATION",
        ),
        (
            lambda p: p["tests"][0]["mutation"].update(
                source_path="tests/test_example.py"
            ),
            "E_ORACLE_PATH",
        ),
        (
            lambda p: p["tests"][0].update(path="../tests/test_example.py"),
            "E_ORACLE_PATH",
        ),
    ],
)
def test_signed_test_oracle_rejects_invalid_claims(tmp_path: Path, change, code):
    payload = _oracle_payload()
    change(payload)
    receipt, trust, _, payload = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match=code):
        _verify_oracle(receipt, trust, payload)


@pytest.mark.parametrize("field", ["source_manifest_sha256", "environment_sha256"])
def test_signed_test_oracle_rejects_wrong_expected_binding(tmp_path: Path, field: str):
    payload = _oracle_payload()
    receipt, trust, _, payload = _signed_oracle(tmp_path, payload)
    kwargs = {field: _digest("wrong expected binding")}

    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_BINDING"):
        _verify_oracle(receipt, trust, payload, **kwargs)


@pytest.mark.parametrize(
    ("issued_delta", "validity", "code"),
    [
        (timedelta(minutes=1), timedelta(hours=1), "E_ORACLE_FRESHNESS"),
        (-timedelta(hours=2), timedelta(hours=1), "E_ORACLE_FRESHNESS"),
        (timedelta(), timedelta(hours=25), "E_ORACLE_FRESHNESS"),
    ],
)
def test_signed_test_oracle_rejects_stale_or_long_lived_payload(
    tmp_path: Path, issued_delta, validity, code
):
    now = datetime.now(timezone.utc)
    payload = _oracle_payload(now=now + issued_delta)
    payload["expires_at"] = (now + issued_delta + validity).isoformat()
    receipt, trust, _, payload = _signed_oracle(tmp_path, payload)

    with pytest.raises(RuntimeAttestationError, match=code):
        _verify_oracle(receipt, trust, payload, now=now)


def test_signed_test_oracle_rejects_missing_role_revocation_and_pin_mismatch(
    tmp_path: Path,
):
    receipt, trust_path, trust, payload = _signed_oracle(tmp_path)
    trust["keys"][0]["roles"] = []
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_KEY_ROLE_MISMATCH"):
        _verify_oracle(receipt, trust_path, payload)

    trust["keys"][0]["roles"] = ["oracle-verifier"]
    trust["keys"][0]["revoked"] = True
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_KEY"):
        _verify_oracle(receipt, trust_path, payload)

    trust["keys"][0].pop("revoked")
    trust["keys"].append(dict(trust["keys"][0]))
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_KEY"):
        _verify_oracle(receipt, trust_path, payload)

    trust["keys"].pop()
    trust_path.write_text(json.dumps(trust), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError, match="E_TRUST_ROOT_PIN"):
        verify_signed_test_oracles(
            receipt,
            trust_path,
            trust_root_sha256=_digest("wrong trust"),
            source_manifest_sha256=payload["source_manifest_sha256"],
            environment_sha256=payload["environment_sha256"],
        )


def test_signed_test_oracle_rejects_duplicate_json_and_tampered_signature(
    tmp_path: Path,
):
    receipt, trust, _, payload = _signed_oracle(tmp_path)
    raw = receipt.read_text(encoding="utf-8")
    receipt.write_text(
        raw.replace('"schema":', '"schema":"duplicate","schema":', 1), encoding="utf-8"
    )
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_JSON"):
        _verify_oracle(receipt, trust, payload)

    receipt, trust, _, payload = _signed_oracle(tmp_path / "tampered")
    envelope = json.loads(receipt.read_text(encoding="utf-8"))
    envelope["payload"] = base64.urlsafe_b64encode(b"{}").decode("ascii").rstrip("=")
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(RuntimeAttestationError):
        _verify_oracle(receipt, trust, payload)


def test_signed_test_oracle_rechecks_receipt_and_trust_bytes(
    tmp_path: Path, monkeypatch
):
    import factoryline.runtime_attestation as runtime_attestation

    receipt, trust, _, payload = _signed_oracle(tmp_path)
    original_verify = runtime_attestation.verify_signed_document

    def verify_then_drift(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        receipt.write_text("{}", encoding="utf-8")
        return result

    monkeypatch.setattr(
        runtime_attestation, "verify_signed_document", verify_then_drift
    )
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_DRIFT"):
        _verify_oracle(receipt, trust, payload)


def test_signed_test_oracle_rejects_oversized_receipt(tmp_path: Path):
    receipt, trust, _, payload = _signed_oracle(tmp_path)
    receipt.write_bytes(b" " * (1_048_577))
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_SIZE"):
        _verify_oracle(receipt, trust, payload)


def test_test_oracle_private_helpers_enforce_contracts(tmp_path: Path):
    import factoryline.runtime_attestation as oracle

    with pytest.raises(RuntimeAttestationError, match="E_TEST"):
        oracle._oracle_fail("E_TEST", "expected")
    path = tmp_path / "small.json"
    path.write_text('{"ok":true}', encoding="utf-8")
    assert oracle._oracle_read(path, "test") == b'{"ok":true}'
    assert oracle._oracle_json(b'{"ok":true}', "test") == {"ok": True}
    for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
        with pytest.raises(RuntimeAttestationError, match="E_ORACLE_JSON"):
            oracle._oracle_json(raw, "test")
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_SCHEMA"):
        oracle._oracle_exact({"x": 1, "extra": 2}, {"x"}, "test")
    assert (
        oracle._oracle_relative_py("src/mod.py", "source", test_source=False)
        == "src/mod.py"
    )
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_PATH"):
        oracle._oracle_relative_py("../test.py", "source", test_source=True)
    cases = oracle._oracle_case_ids(
        ["tests/test_x.py::Suite::test_x[param]"], "cases", "tests/test_x.py", "test_x"
    )
    assert cases == ["tests/test_x.py::Suite::test_x[param]"]
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_CASES"):
        oracle._oracle_case_ids(
            ["tests/test_y.py::test_y"], "cases", "tests/test_x.py", "test_x"
        )
    with pytest.raises(RuntimeAttestationError, match="E_ORACLE_ORIGIN"):
        oracle._oracle_origins(
            [{}] * (oracle.MAX_TEST_ORACLE_ORIGINS_PER_RUN + 1),
            field="origins",
            case_ids=["tests/test_example.py::test_example[case-1]"],
            test_path="tests/test_example.py",
            test_sha=_digest("test source"),
            source_path="factoryline/example.py",
            source_sha=_digest("original source"),
        )
    payload = _oracle_payload()
    assert oracle._oracle_test(payload["tests"][0])["mutation"]["status"] == "FAIL"
    normalized = oracle._oracle_payload(
        payload,
        source_manifest_sha256=payload["source_manifest_sha256"],
        environment_sha256=payload["environment_sha256"],
        now=datetime.now(timezone.utc),
    )
    assert normalized["authority"] == "none"
    receipt, trust_path, _, _ = _signed_oracle(tmp_path / "envelope", payload)
    envelope, _ = oracle._verify_oracle_envelope(
        receipt.read_bytes(), trust_path.read_bytes()
    )
    assert envelope["schema"] == TEST_ORACLE_SCHEMA


def test_runner_uses_exact_argv_separate_artifacts_and_no_worktree_home(tmp_path):
    writer = tmp_path / "writer.py"
    writer.write_text(
        "import json,sys; json.dump({'schema':'fixture','mode':sys.argv[1]},open(sys.argv[2],'w'))\n",
        encoding="utf-8",
    )
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 5,
        "target_argv": [sys.executable, str(writer), "target", "{artifact}"],
        "known_bad_argv": [sys.executable, str(writer), "known_bad", "{artifact}"],
    }
    result = run_runtime_audit_plan({"lanes": [lane]}, tmp_path, tmp_path / "out")
    execution = result["executions"][0]
    assert execution["target"]["artifact"]["mode"] == "target"
    assert execution["known_bad"]["artifact"]["mode"] == "known_bad"
    assert (
        execution["target"]["artifact_sha256"]
        != execution["known_bad"]["artifact_sha256"]
    )
    homes = list((tmp_path / "out").rglob("runtime-home"))
    assert len(homes) == 2
    assert all(
        path.is_dir() and path.is_relative_to(tmp_path / "out") for path in homes
    )
    target_artifact = (
        tmp_path / result["run_root"] / "lane" / "target" / "artifact.json"
    )
    known_bad_artifact = (
        tmp_path / result["run_root"] / "lane" / "known_bad" / "artifact.json"
    )
    assert target_artifact.is_file()
    assert known_bad_artifact.is_file()
    assert target_artifact != known_bad_artifact
    assert not (tmp_path / "runtime-home").exists()


def test_runner_supports_bounded_parallel_lanes_with_isolated_scratch(
    tmp_path, monkeypatch
):
    plan_path, trust, trust_sha, _ = signed_plan(
        tmp_path,
        execution_policy={
            "max_parallelism": 2,
            "non_mutating": True,
            "resource_safe": True,
        },
    )
    verified = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    calls = []
    active = 0
    peak_active = 0
    lock = threading.Lock()
    overlap = threading.Barrier(2, timeout=5)

    def fake_leg(lane, command_name, argv_key, run_root, workspace):
        nonlocal active, peak_active
        command_root = run_root / lane["id"] / command_name
        command_root.mkdir(parents=True, exist_ok=False)
        with lock:
            active += 1
            peak_active = max(peak_active, active)
            calls.append((lane["id"], command_name, command_root))
        try:
            overlap.wait()
            return {"artifact": {"ok": True}}
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr("factoryline.runtime_audit_runner._run_one_guarded", fake_leg)
    plan = verified["plan"]
    result = run_runtime_audit_plan(
        plan,
        tmp_path,
        tmp_path / "out",
        plan_sha256=verified["payload_sha256"],
        max_parallelism=2,
        execution_admission=verified["execution_admission"],
    )
    assert result["execution_policy"]["max_parallelism"] == 2
    assert [item["id"] for item in result["executions"]] == [
        item["id"] for item in plan["lanes"]
    ]
    expected = {
        (lane["id"], leg) for lane in plan["lanes"] for leg in ("target", "known_bad")
    }
    assert {(lane_id, leg) for lane_id, leg, _ in calls} == expected
    assert len(calls) == len(expected)
    assert peak_active == 2
    scratch = [path for _, _, path in calls]
    assert len(set(scratch)) == len(expected)
    assert all(
        path.is_dir() and path.is_relative_to(tmp_path / "out") for path in scratch
    )


def test_parallel_runner_requires_signed_policy_before_launch(tmp_path):
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 1,
        "target_argv": [sys.executable, "-c", "raise SystemExit(9)", "{artifact}"],
        "known_bad_argv": [sys.executable, "-c", "raise SystemExit(9)", "{artifact}"],
    }
    from factoryline.runtime_audit_common import RuntimeAuditError

    with pytest.raises(RuntimeAuditError, match="E_PARALLELISM_POLICY"):
        run_runtime_audit_plan(
            {"lanes": [lane]}, tmp_path, tmp_path / "out", max_parallelism=2
        )
    assert not list((tmp_path / "out").glob("run-*"))


def test_parallel_prelaunch_source_growth_reads_only_signed_budget_plus_one(
    tmp_path, monkeypatch
):
    from factoryline.runtime_audit_common import RuntimeAuditError

    plan_path, trust, trust_sha, _ = signed_plan(
        tmp_path,
        execution_policy={
            "max_parallelism": 2,
            "non_mutating": True,
            "resource_safe": True,
        },
    )
    verified = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    source = tmp_path / "candidate.txt"
    source.write_bytes(b"g" * 4096)
    calls = []
    original_open = Path.open

    class CountingStream:
        def __init__(self, stream):
            self.stream = stream

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            block = self.stream.read(size)
            calls.append(len(block))
            return block

    def counting_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        return CountingStream(stream) if path == source else stream

    monkeypatch.setattr(Path, "open", counting_open)

    with pytest.raises(RuntimeAuditError, match="E_SOURCE_SIZE"):
        run_runtime_audit_plan(
            verified["plan"],
            tmp_path,
            tmp_path / "out",
            plan_sha256=verified["payload_sha256"],
            max_parallelism=2,
            execution_admission=verified["execution_admission"],
        )
    assert sum(calls) == len(b"candidate") + 1
    assert not list((tmp_path / "out").glob("run-*"))


def test_parallel_runner_rejects_unsafe_or_over_limit_policy(tmp_path):
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 1,
        "target_argv": [sys.executable, "-c", "pass", "{artifact}"],
        "known_bad_argv": [sys.executable, "-c", "pass", "{artifact}"],
    }
    from factoryline.runtime_audit_common import RuntimeAuditError

    for policy in (
        {"max_parallelism": 2, "non_mutating": False, "resource_safe": True},
        {"max_parallelism": 2, "non_mutating": True, "resource_safe": False},
        {"max_parallelism": 1, "non_mutating": True, "resource_safe": True},
    ):
        with pytest.raises(RuntimeAuditError, match="E_PARALLELISM_POLICY"):
            run_runtime_audit_plan(
                {"lanes": [lane], "execution_policy": policy},
                tmp_path,
                tmp_path / "out",
                max_parallelism=2,
            )


@pytest.mark.parametrize(
    "mutation", ["lane", "source", "source_bytes", "environment", "policy"]
)
def test_parallel_runner_rejects_plan_changed_after_admission(tmp_path, mutation):
    from factoryline.runtime_audit_common import RuntimeAuditError

    plan_path, trust, trust_sha, plan = signed_plan(
        tmp_path,
        execution_policy={
            "max_parallelism": 2,
            "non_mutating": True,
            "resource_safe": True,
        },
    )
    verified = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    admission = verified["execution_admission"]
    if mutation == "lane":
        plan["lanes"][0]["timeout_seconds"] = 2
    elif mutation == "source":
        plan["sources"][0]["sha256"] = "b" * 64
    elif mutation == "source_bytes":
        (tmp_path / "candidate.txt").write_bytes(b"changed")
    elif mutation == "environment":
        plan["environment"]["digest"] = "f" * 64
    else:
        plan["execution_policy"]["max_parallelism"] = 3
    with pytest.raises(RuntimeAuditError, match="E_PARALLELISM_POLICY"):
        run_runtime_audit_plan(
            plan,
            tmp_path,
            tmp_path / "out",
            plan_sha256=verified["payload_sha256"],
            max_parallelism=2,
            execution_admission=admission,
        )
    assert not list((tmp_path / "out").glob("run-*"))


def test_missing_artifact_error_does_not_disclose_absolute_path(tmp_path):
    lane = {
        "id": "lane",
        "kind": "stateful_invariant",
        "timeout_seconds": 5,
        "target_argv": [sys.executable, "-c", "pass", "{artifact}"],
        "known_bad_argv": [sys.executable, "-c", "pass", "{artifact}"],
    }
    result = run_runtime_audit_plan({"lanes": [lane]}, tmp_path, tmp_path / "out")

    decoded = json.loads(json.dumps(result))

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    assert all(str(tmp_path) not in item for item in strings(decoded))
    assert decoded["run_root"].startswith("out/run-")
    assert not Path(decoded["run_root"]).is_absolute()
    assert str(tmp_path) not in decoded["run_root"]
    for leg in decoded["executions"][0].values():
        if isinstance(leg, dict):
            assert str(tmp_path) not in str(leg.get("artifact_error"))
    assert result["executions"][0]["target"]["artifact_error"] == {
        "code": "E_ARTIFACT_MISSING"
    }


def test_supervisor_times_out_and_hashes_output_without_retaining_it(tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    result = run_bounded_command(
        [sys.executable, "-c", "import time; print('safe'); time.sleep(2)"],
        tmp_path,
        1,
        scratch,
    )
    assert result["timed_out"] is True
    assert result["cleanup_confirmed"] is True
    assert result["timeout_seconds"] == 1
    assert result["duration_ms"] >= 1
    assert result["termination_reason"] == "timeout"
    assert "safe" not in json.dumps(result)


def _mutation_project(root, *, parameterized=False):
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\npython_files = ['test_*.py']\n",
        encoding="utf-8",
    )
    production = root / "app.py"
    production.write_text("def value():\n    return 1\n", encoding="utf-8")
    test = root / "test_app.py"
    decorator = (
        "@__import__('pytest').mark.parametrize('value', [1, 1], ids=['a', 'b'])\n"
        if parameterized
        else ""
    )
    expected = "value" if parameterized else "1"
    test.write_text(
        "import app\n"
        + decorator
        + f"def test_value({'' if not parameterized else 'value'}):\n    assert app.value() == {expected}\n",
        encoding="utf-8",
    )
    return test, 4 if parameterized else 3


def _mutation_mtime_writer(mutant_bytes, mutation_stats, original_write_bytes):
    def write_mutant_with_original_mtime(path, data):
        if path.name == "app.py" and data == mutant_bytes and path.is_file():
            before = path.stat()
            written = original_write_bytes(path, data)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            after = path.stat()
            mutation_stats.update(
                before_size=before.st_size,
                after_size=after.st_size,
                before_mtime_ns=before.st_mtime_ns,
                after_mtime_ns=after.st_mtime_ns,
            )
            return written
        return original_write_bytes(path, data)

    return write_mutant_with_original_mtime


def _capture_diagnostic_record(value):
    return value if isinstance(value, dict) else {}


def _capture_diagnostic_equal(left, right):
    if not isinstance(left, str) or not left:
        return None
    if not isinstance(right, str) or not right:
        return None
    return left == right


def _capture_diagnostic_catalog_match(baseline_cases, mutant_cases):
    valid_catalogs = (
        isinstance(baseline_cases, list)
        and bool(baseline_cases)
        and all(isinstance(case, str) and case for case in baseline_cases)
        and isinstance(mutant_cases, list)
        and bool(mutant_cases)
        and all(isinstance(case, str) and case for case in mutant_cases)
    )
    return baseline_cases == mutant_cases if valid_catalogs else None


def _capture_diagnostic_phase(payload, phase, expected_cases):
    trial = _capture_diagnostic_record(payload.get(phase))
    process = _capture_diagnostic_record(trial.get("process"))
    observation = _capture_diagnostic_record(payload.get(f"{phase}_observation"))
    hits = _capture_diagnostic_record(observation.get("case_hits"))
    return {
        "process_exit": process.get("exit_code"),
        "process_timed_out": process.get("timed_out"),
        "process_cleanup_confirmed": process.get("cleanup_confirmed"),
        "observation_exit": observation.get("exit_code"),
        "origin_status": observation.get("origin_status"),
        "collection_incomplete": observation.get("collection_incomplete"),
        "case_hits": {case: hits.get(case) for case in expected_cases},
    }


def _capture_diagnostic_summary(result, expected_cases):
    payload = _capture_diagnostic_record(result)
    baseline_observation = _capture_diagnostic_record(
        payload.get("baseline_observation")
    )
    mutant_observation = _capture_diagnostic_record(payload.get("mutant_observation"))
    cleanup = _capture_diagnostic_record(payload.get("cleanup"))
    source_unchanged = payload.get("source_unchanged")
    if not isinstance(source_unchanged, bool):
        source_unchanged = None
    cleanup_removed = cleanup.get("removed")
    if not isinstance(cleanup_removed, bool):
        cleanup_removed = None
    return {
        "baseline": _capture_diagnostic_phase(payload, "baseline", expected_cases),
        "mutant": _capture_diagnostic_phase(payload, "mutant", expected_cases),
        "baseline_raw_context_stable": _capture_diagnostic_equal(
            baseline_observation.get("runtime_context_before"),
            baseline_observation.get("runtime_context_after"),
        ),
        "mutant_raw_context_stable": _capture_diagnostic_equal(
            mutant_observation.get("runtime_context_before"),
            mutant_observation.get("runtime_context_after"),
        ),
        "normalized_context_matches": _capture_diagnostic_equal(
            baseline_observation.get("runtime_context_normalized_before"),
            mutant_observation.get("runtime_context_normalized_before"),
        ),
        "source_unchanged": source_unchanged,
        "case_catalog_matches": _capture_diagnostic_catalog_match(
            baseline_observation.get("collected"), mutant_observation.get("collected")
        ),
        "capture_cleanup_removed": cleanup_removed,
    }


def test_capture_diagnostic_summary_marks_missing_observations_unknown():
    summary = _capture_diagnostic_summary(
        {
            "baseline": None,
            "mutant": {},
            "baseline_observation": None,
            "mutant_observation": None,
            "cleanup": None,
        },
        ["test_app.py::test_value[a]", "test_app.py::test_value[b]"],
    )

    assert summary["baseline"]["process_exit"] is None
    assert summary["baseline"]["case_hits"] == {
        "test_app.py::test_value[a]": None,
        "test_app.py::test_value[b]": None,
    }
    assert summary["baseline_raw_context_stable"] is None
    assert summary["mutant_raw_context_stable"] is None
    assert summary["normalized_context_matches"] is None
    assert summary["case_catalog_matches"] is None


def test_capture_diagnostic_summary_reports_bound_gate_facts():
    cases = ["test_app.py::test_value[a]", "test_app.py::test_value[b]"]
    observation = {
        "exit_code": 0,
        "origin_status": "BOUND",
        "collection_incomplete": False,
        "collected": cases,
        "case_hits": dict.fromkeys(cases, 1),
        "runtime_context_before": "raw-context",
        "runtime_context_after": "raw-context",
        "runtime_context_normalized_before": "normalized-context",
    }
    result = {
        "baseline": {
            "process": {"exit_code": 0, "timed_out": False, "cleanup_confirmed": True}
        },
        "mutant": {
            "process": {"exit_code": 0, "timed_out": False, "cleanup_confirmed": True}
        },
        "baseline_observation": observation,
        "mutant_observation": {
            **observation,
            "runtime_context_before": "other-raw-context",
            "runtime_context_after": "other-raw-context",
        },
        "source_unchanged": True,
        "cleanup": {"removed": True},
    }

    summary = _capture_diagnostic_summary(result, cases)

    assert summary["baseline"]["process_exit"] == 0
    assert summary["baseline"]["process_timed_out"] is False
    assert summary["baseline"]["process_cleanup_confirmed"] is True
    assert summary["baseline"]["observation_exit"] == 0
    assert summary["baseline"]["origin_status"] == "BOUND"
    assert summary["baseline"]["collection_incomplete"] is False
    assert summary["baseline"]["case_hits"] == dict.fromkeys(cases, 1)
    assert summary["baseline_raw_context_stable"] is True
    assert summary["mutant_raw_context_stable"] is True
    assert summary["normalized_context_matches"] is True
    assert summary["source_unchanged"] is True
    assert summary["case_catalog_matches"] is True
    assert summary["capture_cleanup_removed"] is True


def test_local_production_mutation_capture_records_real_all_case_failure(tmp_path):
    test, assertion_line = _mutation_project(tmp_path, parameterized=True)
    original_test = test.read_bytes()
    original_source = (tmp_path / "app.py").read_bytes()
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-one",
        timeout_seconds=30,
    )

    _assert_local_candidate_envelope(result)
    _assert_local_candidate_test(result, test, assertion_line)
    _assert_local_capture_bindings(
        result, test, original_test, original_source, tmp_path
    )
    _assert_local_capture_observations(result, tmp_path)
    _assert_saved_local_candidate(result, tmp_path)
    _assert_local_candidate_negative_controls(result)


def _assert_local_candidate_envelope(result):
    projection = result["v3_candidate_projection"]
    assert result["schema"] == "factory.local-production-mutation-capture.v1"
    assert projection["schema"] == "factory.local-production-mutation-v3-candidate.v1"
    assert projection["oracle_schema"] == "factory.test-oracle-attestation.v3"
    assert projection["status"] == "CANDIDATE", projection["missing_evidence"]
    assert projection["signature_status"] == "UNSIGNED"
    assert projection["observer_integrity"] == "IN_PROCESS_NOT_ATTESTED"
    assert projection["authority"] == "none"
    assert projection["trust_admission"] == "NOT_PERFORMED"
    assert projection["attestation_envelope"] is None


def _assert_local_candidate_test(result, test, assertion_line):
    candidate_test = result["v3_candidate_projection"]["test_candidate"]
    assert (
        candidate_test["line"]
        == test.read_text().splitlines().index("def test_value(value):") + 1
    )
    assert candidate_test["symbol"] == "test_value"
    assert candidate_test["baseline"]["case_ids"] == [
        "test_app.py::test_value[a]",
        "test_app.py::test_value[b]",
    ]
    assert {
        row["line"] for row in candidate_test["baseline"]["assertion_observations"]
    } == {assertion_line}


def _assert_local_capture_bindings(
    result, test, original_test, original_source, tmp_path
):
    from hashlib import sha256

    expected_cases = ["test_app.py::test_value[a]", "test_app.py::test_value[b]"]
    diagnostics = _capture_diagnostic_summary(result, expected_cases)
    assert result["status"] == "OBSERVED", json.dumps(diagnostics, sort_keys=True)
    assert result["signature_status"] == "UNSIGNED"
    assert result["authority"] == "none"
    assert result["source_unchanged"] is True
    assert test.read_bytes() == original_test
    assert (tmp_path / "app.py").read_bytes() == original_source
    assert (
        result["production_mutation"]["original_sha256"]
        == sha256(original_source).hexdigest()
    )
    assert result["baseline_observation"]["collected"] == expected_cases


def _assert_local_capture_observations(result, tmp_path):
    baseline, mutant = result["baseline_observation"], result["mutant_observation"]
    assert baseline["runtime_context_before"] == baseline["runtime_context_after"]
    assert (
        baseline["runtime_context_normalized_before"]
        == mutant["runtime_context_normalized_before"]
    )
    for trial in (result["baseline"], result["mutant"]):
        identity = trial["execution_identity"]
        assert identity["command_template"].startswith("python -B -c ")
        assert identity["argument_roles"][-1] == "observation-output"
        assert len(identity["argv_sha256"]) == len(identity["interpreter_sha256"]) == 64
        assert identity["interpreter_version"]
        assert str(tmp_path) not in json.dumps(identity)
    _assert_local_assertion_observations(result)


def _assert_local_assertion_observations(result):
    mutant = result["mutant_observation"]
    for name in ("baseline_observation", "mutant_observation"):
        observation = result[name]
        assert observation["collection_incomplete"] is False
        assert observation["collection_report_sha256"]
        assert {row["hits"] for row in observation["assertion_observations"]} == {1}
    assert all(
        row["outcome"] == "FAIL" and row["failure_visible"] is True
        for row in mutant["assertion_observations"]
    )


def _assert_saved_local_candidate(result, tmp_path):
    projection = result["v3_candidate_projection"]
    assert result["cleanup"]["removed"] is True
    saved = json.loads((tmp_path / ".factory/capture-one/capture.json").read_text())
    assert saved["schema"] == "factory.local-production-mutation-capture.v1"
    assert saved["v3_candidate_projection"] == projection
    assert saved["signature_status"] == "UNSIGNED"
    assert str(tmp_path) not in json.dumps(saved)


def _assert_local_candidate_negative_controls(result):
    from copy import deepcopy
    from factoryline.runtime_audit_runner import (
        project_local_production_mutation_v3_candidate,
    )

    cases = []
    missing_definition = deepcopy(result)
    del missing_definition["selection"]["test_definition_line"]
    cases.append(missing_definition)
    tampered_manifest = deepcopy(result)
    tampered_manifest["source_manifest"][0]["sha256"] = "0" * 64
    cases.append(tampered_manifest)
    missing_config = deepcopy(result)
    missing_config["collection_config"]["config"] = {"state": "missing"}
    cases.append(missing_config)
    missing_runtime = deepcopy(result)
    del missing_runtime["baseline"]["execution_identity"]["interpreter_sha256"]
    cases.append(missing_runtime)
    missing_origin = deepcopy(result)
    missing_origin["baseline_observation"]["executed_modules"] = [
        row
        for row in missing_origin["baseline_observation"]["executed_modules"]
        if row.get("path") != "app.py"
    ]
    cases.append(missing_origin)
    tampered_checker = deepcopy(result)
    tampered_checker["mutant_observation"]["tool_sha256"] = "bad"
    cases.append(tampered_checker)
    assert all(
        project_local_production_mutation_v3_candidate(item)["status"] == "INCOMPLETE"
        for item in cases
    )


def _refresh_candidate_manifest_digests(capture):
    from hashlib import sha256

    capture["source_manifest"].sort(key=lambda row: row["path"])
    pairs = [[row["path"], row["sha256"]] for row in capture["source_manifest"]]
    capture["source_manifest_sha256"] = sha256(
        json.dumps(pairs, separators=(",", ":")).encode()
    ).hexdigest()
    manifest = dict(pairs)
    for name in ("baseline", "mutant"):
        executed = dict(manifest)
        if name == "mutant":
            mutation = capture["production_mutation"]
            executed[mutation["path"]] = mutation["mutant_sha256"]
        capture[f"{name}_observation"]["executed_source_manifest_sha256"] = sha256(
            json.dumps(executed, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def test_native_v3_candidate_binds_full_config_and_each_case_definition(tmp_path):
    from copy import deepcopy
    from hashlib import sha256
    from factoryline.runtime_audit_runner import (
        project_local_production_mutation_v3_candidate,
    )

    test, assertion_line = _mutation_project(tmp_path, parameterized=True)
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = test_*.py\n", encoding="utf-8"
    )
    (tmp_path / "conftest.py").write_text("pytest_plugins = []\n", encoding="utf-8")
    capture = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/native-v3-full-config",
        timeout_seconds=30,
    )
    projection = capture["v3_candidate_projection"]
    assert projection["status"] == "CANDIDATE", projection["missing_evidence"]
    baseline = projection["test_candidate"]["baseline"]["collection_catalog"]
    mutant = projection["test_candidate"]["mutation"]["collection_catalog"]
    expected = [
        {
            "path": "conftest.py",
            "sha256": sha256((tmp_path / "conftest.py").read_bytes()).hexdigest(),
        },
        {
            "path": "pytest.ini",
            "sha256": sha256((tmp_path / "pytest.ini").read_bytes()).hexdigest(),
        },
    ]
    assert baseline["config_manifest"] == mutant["config_manifest"] == expected
    assert baseline["config_manifest_sha256"] == mutant["config_manifest_sha256"]

    escaped = deepcopy(capture)
    escaped["source_manifest"].append({"path": "../unused.py", "sha256": "a" * 64})
    _refresh_candidate_manifest_digests(escaped)
    assert (
        project_local_production_mutation_v3_candidate(escaped)["status"]
        == "INCOMPLETE"
    )

    swapped = deepcopy(capture)
    for name in ("baseline_observation", "mutant_observation"):
        for row in swapped[name]["executed_modules"]:
            if (
                row.get("nodeid") == "test_app.py::test_value[b]"
                and row.get("frame_qualname") == "test_value"
            ):
                row["frame_qualname"] = "helper"
    assert (
        project_local_production_mutation_v3_candidate(swapped)["status"]
        == "INCOMPLETE"
    )

    omitted = deepcopy(capture)
    omitted["collection_config"]["manifest"] = [
        row
        for row in omitted["collection_config"]["manifest"]
        if row["path"] != "conftest.py"
    ]
    omitted["collection_config"]["identity_sha256"] = sha256(
        json.dumps(
            omitted["collection_config"]["manifest"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    assert (
        project_local_production_mutation_v3_candidate(omitted)["status"]
        == "INCOMPLETE"
    )


def test_local_production_mutation_avoids_same_timestamp_bytecode_cache(
    tmp_path, monkeypatch
):
    test, assertion_line = _mutation_project(tmp_path)
    production = tmp_path / "app.py"
    py_compile.compile(str(production), doraise=True)
    assert list((tmp_path / "__pycache__").glob("app.*.pyc"))
    original_write_bytes = Path.write_bytes
    mutant_bytes = production.read_bytes().replace(b"return 1", b"return 0", 1)
    mutation_stats = {}
    writer = _mutation_mtime_writer(mutant_bytes, mutation_stats, original_write_bytes)
    monkeypatch.setattr(Path, "write_bytes", writer)
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-timestamp-cache",
        timeout_seconds=30,
    )

    assert mutation_stats["before_size"] == mutation_stats["after_size"]
    assert mutation_stats["before_mtime_ns"] == mutation_stats["after_mtime_ns"]
    assert result["status"] == "OBSERVED"
    assert result["baseline"]["execution_identity"]["command_template"].startswith(
        "python -B -c "
    )
    assert all(
        row["outcome"] == "FAIL" and row["failure_visible"] is True
        for row in result["mutant_observation"]["assertion_observations"]
    )


def test_local_production_mutation_rejects_unrelated_assertion_failure(tmp_path):
    test, _ = _mutation_project(tmp_path)
    test.write_text(
        "import app\n"
        "def test_value():\n"
        "    assert app.value() == 1\n"
        "    assert app.other() == 1\n",
        encoding="utf-8",
    )
    production = tmp_path / "app.py"
    production.write_text(
        "def value():\n    return 1\n\ndef other():\n    return 1  # other\n",
        encoding="utf-8",
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        3,
        "app.py",
        "other",
        "return 1  # other",
        "return 0",
        ".factory/capture-unrelated",
        timeout_seconds=30,
    )

    assert result["status"] == "INCOMPLETE"
    observation = result["mutant_observation"]
    assert observation["case_hits"]["test_app.py::test_value"] == 1
    assert observation["assertion_observations"] == [
        {
            "case_id": "test_app.py::test_value",
            "callback_qualname": "test_value",
            "line": 3,
            "assertion_kind": "assert",
            "hits": 1,
            "outcome": "FAIL",
            "failure_visible": False,
        }
    ]


def test_local_production_mutation_capture_rejects_unbound_patch(tmp_path):
    from factoryline.runtime_audit_common import RuntimeAuditError

    _, assertion_line = _mutation_project(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_MUTATION_INPUT"):
        capture_local_production_mutation(
            tmp_path,
            "test_app.py::test_value",
            assertion_line,
            "app.py",
            "value",
            "return 3",
            "return 0",
            ".factory/capture-invalid",
            timeout_seconds=10,
        )
    assert not (tmp_path / ".factory/capture-invalid").exists()


def test_local_production_mutation_capture_rejects_duplicate_patch_bytes(tmp_path):
    from factoryline.runtime_audit_common import RuntimeAuditError

    _, assertion_line = _mutation_project(tmp_path)
    (tmp_path / "app.py").write_text(
        "def value():\n    return 1\n\ndef other():\n    return 1\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeAuditError, match="E_MUTATION_INPUT"):
        capture_local_production_mutation(
            tmp_path,
            "test_app.py::test_value",
            assertion_line,
            "app.py",
            "value",
            "return 1",
            "return 0",
            ".factory/capture-invalid",
            timeout_seconds=10,
        )
    assert not (tmp_path / ".factory/capture-invalid").exists()


def test_local_production_mutation_does_not_credit_assertion_error_from_production(
    tmp_path,
):
    test, assertion_line = _mutation_project(tmp_path)
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "raise AssertionError('from production')",
        ".factory/capture-production-assertion",
        timeout_seconds=30,
    )
    observation = result["mutant_observation"]
    assert result["status"] == "INCOMPLETE"
    assert observation["assertion_observations"][0]["hits"] == 1
    assert observation["assertion_observations"][0]["failure_visible"] is False


def test_local_production_mutation_keeps_pytest_deselection_incomplete(tmp_path):
    test, assertion_line = _mutation_project(tmp_path, parameterized=True)
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\npython_files = ['test_*.py']\naddopts = '-k b'\n",
        encoding="utf-8",
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-deselected",
        timeout_seconds=30,
    )
    assert result["status"] == "INCOMPLETE"
    assert result["baseline_observation"]["collection_incomplete"] is True
    saved = json.loads(
        (tmp_path / ".factory/capture-deselected/capture.json").read_text()
    )
    assert saved["status"] == "INCOMPLETE"
    assert saved["baseline_observation"]["collection_incomplete"] is True


def test_production_mutation_requires_identical_case_catalogs():
    from factoryline.runtime_audit_process import same_mutation_case_catalogs

    baseline = {"data": {"collected": ["test_app.py::test_value[a]"]}}
    mutant = {"data": {"collected": ["test_app.py::test_value[b]"]}}
    assert not same_mutation_case_catalogs(baseline, mutant)
    mutant["data"]["collected"] = baseline["data"]["collected"]
    assert same_mutation_case_catalogs(baseline, mutant)


def test_local_production_mutation_config_drift_is_incomplete(tmp_path):
    test, assertion_line = _mutation_project(tmp_path)
    test.write_text(
        "from pathlib import Path\n"
        "import app\n"
        "def test_value():\n"
        "    Path('pyproject.toml').write_text('[tool.pytest.ini_options]\\n', encoding='utf-8')\n"
        "    assert app.value() == 1\n",
        encoding="utf-8",
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        5,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-config-drift",
        timeout_seconds=30,
    )
    assert result["status"] == "INCOMPLETE"
    saved = json.loads(
        (tmp_path / ".factory/capture-config-drift/capture.json").read_text()
    )
    assert saved["status"] == "INCOMPLETE"
    assert saved["baseline_observation"] is not None


def test_local_production_mutation_rejects_target_symlink_after_baseline(
    tmp_path, monkeypatch
):
    import os

    import factoryline.runtime_audit_runner as runner

    test, assertion_line = _mutation_project(tmp_path)
    original = tmp_path / "app.py"
    original_bytes = original.read_bytes()
    run_trial = runner._run_local_mutation_trial

    def replace_copy_target_after_baseline(*args, **kwargs):
        result = run_trial(*args, **kwargs)
        if args[7] == "baseline":
            copied_target = args[0] / "app.py"
            copied_target.unlink()
            try:
                os.symlink(original, copied_target)
            except OSError as exc:
                pytest.skip(f"symlink unavailable for CAP06 control: {exc}")
        return result

    monkeypatch.setattr(
        runner, "_run_local_mutation_trial", replace_copy_target_after_baseline
    )
    result = capture_local_production_mutation(
        tmp_path,
        "test_app.py::test_value",
        assertion_line,
        "app.py",
        "value",
        "return 1",
        "return 0",
        ".factory/capture-linked-target",
        timeout_seconds=30,
    )
    assert result["status"] == "INCOMPLETE"
    assert original.read_bytes() == original_bytes


def test_supervisor_times_out_before_a_late_child_exit_is_polled(monkeypatch):
    from factoryline.runtime_audit_process import _wait_for_exit_or_limit

    class Child:
        def __init__(self):
            self.wait_calls = 0
            self.exit_code = None

        def wait(self, timeout):
            self.wait_calls += 1
            if self.wait_calls == 2:
                # Exit races the deadline: the bounded wait reports timeout,
                # then the supervisor observes the child's exit.
                self.exit_code = 0
            raise __import__("subprocess").TimeoutExpired("late", timeout)

    clock = iter((10.0, 10.5, 10.99, 11.01))
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.time.monotonic", lambda: next(clock)
    )
    child = Child()

    assert _wait_for_exit_or_limit(child, 1, threading.Event()) is True
    assert child.wait_calls == 2
    assert child.exit_code == 0


def test_supervisor_deadline_includes_launch_and_stream_setup(monkeypatch, tmp_path):
    class Child:
        returncode = 0

    monkeypatch.setattr("factoryline.runtime_audit_process._launch", lambda *a: Child())
    monkeypatch.setattr(
        "factoryline.runtime_audit_process._start_stream_readers",
        lambda *a: [],
    )
    monkeypatch.setattr(
        "factoryline.runtime_audit_process._await_cleanup", lambda *a: (True, True)
    )
    monkeypatch.setattr(
        "factoryline.runtime_audit_process._cleanup_is_confirmed",
        lambda *a: True,
    )
    clock = iter((10.0, 10.0, 11.01, 11.02))
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.time.monotonic", lambda: next(clock)
    )

    result = run_bounded_command(
        [sys.executable, "-c", "pass"], tmp_path, 1, tmp_path / "scratch"
    )

    assert result["timed_out"] is True
    assert result["duration_ms"] == 1020
    assert result["exit_code"] == 0


def test_windows_cleanup_timeout_is_contained(monkeypatch):
    class Child:
        pid = 42

        def poll(self):
            return None

        def kill(self):
            return None

    monkeypatch.setattr("factoryline.runtime_audit_process.os.name", "nt")
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            __import__("subprocess").TimeoutExpired("taskkill", 10)
        ),
    )
    assert _stop(Child()) is False


def test_windows_cleanup_failure_is_not_reported_as_confirmed(monkeypatch):
    class Child:
        pid = 42

        def poll(self):
            return None

        def kill(self):
            return None

    class FailedTaskkill:
        returncode = 1

    monkeypatch.setattr("factoryline.runtime_audit_process.os.name", "nt")
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.subprocess.run",
        lambda *args, **kwargs: FailedTaskkill(),
    )
    assert _stop(Child()) is False


def test_stream_drainer_hashes_and_counts_without_retaining_payload():
    streams: dict[str, tuple[str, int]] = {}
    _drain_stream("stdout", io.BytesIO(b"receipt-only"), threading.Event(), streams)
    digest, size = streams["stdout"]
    assert size == len(b"receipt-only")
    assert len(digest) == 64


def test_validate_production_mutation_source_binds_complete_named_function():
    from factoryline.runtime_audit_common import (
        RuntimeAuditError,
        validate_production_mutation_source,
    )

    source = b"def value():\n    return 1\n"
    assert validate_production_mutation_source(source, "value", b"return 1") == (
        2,
        "value",
    )
    with pytest.raises(RuntimeAuditError, match="E_MUTATION_INPUT"):
        validate_production_mutation_source(source, "other", b"return 1")


def test_validate_production_mutation_collection_requires_exact_complete_catalog():
    from factoryline.runtime_audit_common import (
        validate_production_mutation_collection,
    )

    observation = {
        "collection_incomplete": False,
        "collected": ["test_app.py::test_value[a]", "test_app.py::test_value[b]"],
        "collection_reports": [
            {"outcome": "passed", "failed": False, "skipped": False},
            {"outcome": "passed", "failed": False, "skipped": False},
        ],
    }
    assert validate_production_mutation_collection(
        observation, "test_app.py::test_value"
    )
    observation["collection_incomplete"] = True
    assert not validate_production_mutation_collection(
        observation, "test_app.py::test_value"
    )


def test_validate_production_mutation_trial_requires_hit_and_visible_failure():
    from factoryline.runtime_audit_common import validate_production_mutation_trial

    case = "test_app.py::test_value"
    observation = {
        "collection_incomplete": False,
        "collected": [case],
        "collection_reports": [
            {"outcome": "passed", "failed": False, "skipped": False}
        ],
        "reports": [
            {"nodeid": case, "phase": phase, "outcome": outcome, "xfail": False}
            for phase, outcome in (
                ("setup", "passed"),
                ("call", "failed"),
                ("teardown", "passed"),
            )
        ],
        "assertion_observations": [
            {
                "case_id": case,
                "line": 3,
                "hits": 1,
                "outcome": "FAIL",
                "failure_visible": True,
            }
        ],
    }
    assert validate_production_mutation_trial(
        observation, "test_app.py::test_value", 3, "failed", True
    )
    observation["assertion_observations"][0]["failure_visible"] = False
    assert not validate_production_mutation_trial(
        observation, "test_app.py::test_value", 3, "failed", True
    )


def test_validate_production_mutation_origins_requires_per_case_source_frames(
    tmp_path,
):
    from hashlib import sha256

    from factoryline.runtime_audit_common import validate_production_mutation_origins

    test_path = tmp_path / "test_app.py"
    production_path = tmp_path / "app.py"
    test_path.write_bytes(b"def test_value(): pass\n")
    production_path.write_bytes(b"def value(): return 1\n")
    case = "test_app.py::test_value"
    manifest = {
        "test_app.py": sha256(test_path.read_bytes()).hexdigest(),
        "app.py": sha256(production_path.read_bytes()).hexdigest(),
    }
    rows = [
        {
            "path": path,
            "origin": path,
            "nodeid": case,
            "phase": "call",
            "observation_kind": "executed_frame",
            "source_sha256": digest,
            "status": "BOUND",
        }
        for path, digest in manifest.items()
    ]
    observation = {
        "origin_status": "BOUND",
        "origin_limit_exceeded": False,
        "collected": [case],
        "executed_modules": rows,
    }
    assert validate_production_mutation_origins(
        observation, tmp_path, manifest, production_path
    )
    rows[0]["observation_kind"] = "imported_module"
    assert not validate_production_mutation_origins(
        observation, tmp_path, manifest, production_path
    )
    observation["executed_modules"] = [None]
    assert not validate_production_mutation_origins(
        observation, tmp_path, manifest, production_path
    )


def test_validate_production_mutation_process_requires_confirmed_supervision():
    facts = {
        "timed_out": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "launch_error": False,
        "exit_code": 1,
    }
    assert validate_production_mutation_process(facts)
    facts["cleanup_confirmed"] = False
    assert not validate_production_mutation_process(facts)


def test_bounded_file_hash_rejects_oversized_input(tmp_path):
    from factoryline.runtime_audit_process import bounded_file_sha256

    path = tmp_path / "small.bin"
    path.write_bytes(b"123")
    assert len(bounded_file_sha256(path, 3)) == 64
    with pytest.raises(ValueError, match="size limit"):
        bounded_file_sha256(path, 2)


def test_tree_and_target_path_helpers_reject_escape_and_accept_regular_files(tmp_path):
    from factoryline.runtime_audit_process import (
        new_output_path_inside,
        path_chain_has_no_links,
        regular_target_within,
        tree_has_no_links_or_reparse_points,
    )

    root = tmp_path / "root"
    root.mkdir()
    source = root / "source.py"
    source.write_text("x = 1\n", encoding="utf-8")
    assert tree_has_no_links_or_reparse_points(root)
    assert regular_target_within(root, source)
    assert path_chain_has_no_links(root, root / ".factory/output.json")
    assert not path_chain_has_no_links(root, tmp_path / "outside")
    assert (
        new_output_path_inside(root, Path(".factory/output"))
        == root / ".factory/output"
    )
    with pytest.raises(ValueError, match="escapes"):
        new_output_path_inside(root, tmp_path / "outside")


def test_bounded_temp_directory_stays_under_system_parent_and_is_removed():
    parent, root = create_bounded_temp_directory("cf-capture-test-")
    try:
        assert root.parent == parent
        assert root.is_dir()
    finally:
        assert remove_bounded_temp_directory(root, parent, "cf-capture-test-")
    assert not root.exists()


def test_mutation_trial_observed_rejects_context_drift_with_bound_phase_evidence(
    tmp_path,
):
    import hashlib

    from factoryline.runtime_audit_process import mutation_trial_observed

    root = tmp_path.resolve()
    test_path = root / "test_app.py"
    target = root / "app.py"
    test_path.write_bytes(b"def test_value():\n    pass\n")
    target.write_bytes(b"def value():\n    return 1\n")
    case = "test_app.py::test_value"
    manifest = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (test_path, target)
    }
    observation = {
        "collection_incomplete": False,
        "collection_reports": [
            {"outcome": "passed", "failed": False, "skipped": False}
        ],
        "collected": [case],
        "reports": [
            {"nodeid": case, "phase": phase, "outcome": outcome, "xfail": False}
            for phase, outcome in (
                ("setup", "passed"),
                ("call", "failed"),
                ("teardown", "passed"),
            )
        ],
        "assertion_observations": [
            {
                "case_id": case,
                "line": 3,
                "hits": 1,
                "outcome": "FAIL",
                "failure_visible": True,
            }
        ],
        "origin_status": "BOUND",
        "origin_limit_exceeded": False,
        "executed_modules": [
            {
                "path": name,
                "origin": name,
                "nodeid": case,
                "phase": "call",
                "observation_kind": "executed_frame",
                "source_sha256": digest,
                "status": "BOUND",
            }
            for name, digest in manifest.items()
        ],
        "runtime_context_before": "raw-context",
        "runtime_context_after": "raw-context",
        "runtime_context_normalized_before": "normalized-context",
        "runtime_context_normalized_after": "normalized-context",
    }
    trial = {
        "process": {
            "timed_out": False,
            "output_limit_exceeded": False,
            "cleanup_confirmed": True,
            "launch_error": False,
            "exit_code": 1,
        },
        "data": observation,
    }
    prepared = {"selector": case, "line": 3}

    assert mutation_trial_observed(
        trial, prepared, root, target, manifest, "failed", True
    )
    observation["runtime_context_after"] = "changed-context"
    assert not mutation_trial_observed(
        trial, prepared, root, target, manifest, "failed", True
    )

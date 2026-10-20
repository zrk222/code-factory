"""Source-only finite-input admission must reject mutable capture origins."""

import pytest
from test_runtime_audit_integrity import _json_enum_graph
import ast
import hashlib
import json
from factoryline.provenance import finite_template_binding, finite_template_witness
from factoryline.review_integrity import _fixed_primitive_binding
from datetime import datetime, timedelta, timezone
from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.independent_execution import (
    ExecutionAttestationError,
    PAYLOAD_TYPE,
    SCHEMA,
    validate_execution_attestation,
    verify_signed_execution_attestation,
)

_CAPTURE = (
    "import pytest\nfrom common import VALUES\n"
    "@pytest.mark.parametrize('field', sorted(VALUES))\n"
    "def test_generated(field):\n"
    "    exec(f'async def test_fn({field}: int) -> None: pass', {}, {})\n"
)


def test_canonical_capture_has_source_only_proof(tmp_path):
    graph = _json_enum_graph(
        tmp_path,
        test_source=_CAPTURE,
        client_source="",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert graph.snapshot_complete
    assert len(graph.finite_template_inputs()) == 1


@pytest.mark.parametrize(
    "prefix",
    [
        "from builtins import globals as ns\nns()['sorted'] = altered_sort\n",
        "def poison():\n    globals()['sorted'] = altered_sort\npoison()\n",
        "def poison():\n    globals()['sorted'] = altered_sort\nalias = poison\nalias()\n",
    ],
)
def test_namespace_capture_mutations_keep_input_unknown(tmp_path, prefix):
    graph = _json_enum_graph(
        tmp_path,
        test_source=prefix + _CAPTURE,
        client_source="",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert not graph.finite_template_inputs()


def test_collection_hooks_keep_input_unknown(tmp_path):
    graph = _json_enum_graph(
        tmp_path,
        test_source=_CAPTURE,
        client_source="def pytest_collection_modifyitems(items): pass\n",
        enum_source="VALUES = {'request', 'socket'}\n",
    )
    assert not graph.finite_template_inputs()


"""Envelope integrity tests; real native-source admission is measured separately."""


def _seal(facts):
    facts = {key: value for key, value in facts.items() if key != "proof_facts_sha256"}
    facts["proof_facts_sha256"] = hashlib.sha256(
        json.dumps(facts, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return facts


def _packet(tmp_path):
    code = (
        "@pytest.mark.parametrize('field', sorted(VALUES))\n"
        "def test_generated(field):\n"
        "    exec(f'async def test_fn({field}: int): pass', {}, {})\n"
    ).encode()
    domain = b"VALUES = {'request', 'socket'}\n"
    raw = {
        tmp_path / "tests/test_generated.py": code,
        tmp_path / "constants.py": domain,
    }
    rows = [
        {
            "path": path.relative_to(tmp_path).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for path, data in raw.items()
    ]
    bindings = {row["path"]: row["sha256"] for row in rows}
    tree = ast.parse(code)
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "exec"
    )

    def span(node):
        return [
            node.lineno,
            node.col_offset,
            node.end_lineno,
            node.end_col_offset,
        ]

    facts = {
        "schema": "factory.finite-template-input.v1",
        "disposition": "PROVEN_FINITE_TEMPLATE_INPUT",
        "scope_profile": "pytest-collection-finite-parameter",
        "hypothesis": "ARGUMENT_CODE_INJECTION",
        "input_effect": "FINITE_SOURCE_TEMPLATE_INPUT",
        "runtime_assurance": "INCOMPLETE",
        "execution_effects": "UNASSESSED",
        "target_execution": "not_performed",
        "source_path": "tests/test_generated.py",
        "source_sha256": bindings["tests/test_generated.py"],
        "capture_path": "tests/test_generated.py",
        "capture_sha256": bindings["tests/test_generated.py"],
        "capture_span": span(tree.body[0].decorator_list[0]),
        "domain_path": "constants.py",
        "domain_sha256": bindings["constants.py"],
        "domain_span": span(ast.parse(domain).body[0].value),
        "call_span": span(call),
        "template_span": span(call.args[0]),
        "template_sha256": hashlib.sha256(ast.dump(call.args[0]).encode()).hexdigest(),
        "domain_size": 2,
        "program_hashes": [
            hashlib.sha256(name.encode()).hexdigest() for name in ("request", "socket")
        ],
        "workspace_sources_sha256": hashlib.sha256(
            json.dumps(sorted(bindings.items()), separators=(",", ":")).encode()
        ).hexdigest(),
    }
    finding = {
        "path": "tests/test_generated.py",
        "code": "SECURITY_DYNAMIC_EXECUTION",
        "line": call.lineno,
        "column": call.col_offset,
        "facts": _seal(facts),
    }
    return finding, rows, bindings, call, raw


@pytest.mark.parametrize("changed", ["constants.py", "tests/test_generated.py"])
def test_finite_input_envelope_is_dispatched_and_source_bound(tmp_path, changed):
    finding, rows, bindings, call, raw = _packet(tmp_path)
    assert finite_template_binding(finding, rows, bindings)
    assert _fixed_primitive_binding(finding, rows, bindings)
    profile = {"finite_template_inputs": {"3:4": finding["facts"]}}
    assert (
        finite_template_witness(finding["path"], call, "exec", tmp_path, raw, profile)
        == finding["facts"]
    )
    raw[tmp_path / changed] += b"# stale source snapshot\n"
    assert not finite_template_witness(
        finding["path"], call, "exec", tmp_path, raw, profile
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("runtime_assurance", "COMPLETE"),
        ("execution_effects", "SAFE"),
        ("hypothesis", "SOFTWARE_CORRECT"),
        ("target_execution", "performed"),
        ("domain_size", True),
        ("domain_size", 65),
        ("program_hashes", []),
        ("program_hashes", ["not-a-hash", "not-a-hash"]),
        ("capture_path", "elsewhere.py"),
        ("domain_sha256", "0" * 64),
        ("source_sha256", "0" * 64),
        ("capture_sha256", "0" * 64),
        ("call_span", [4, 4, 4, 8]),
        ("template_span", [2, 0, 2, 8]),
        ("capture_span", [4, 0, 4, 8]),
        ("domain_span", [0, 0, 0, 1]),
        ("workspace_sources_sha256", "0" * 64),
        ("template_sha256", "invalid"),
    ],
)
def test_resealed_invalid_finite_input_is_not_admitted(tmp_path, field, value):
    finding, rows, bindings, _, _ = _packet(tmp_path)
    finding["facts"] = _seal({**finding["facts"], field: value})
    assert not finite_template_binding(finding, rows, bindings)
    assert not _fixed_primitive_binding(finding, rows, bindings)


def test_finite_input_rejects_unsealed_changes_and_duplicate_source_identity(tmp_path):
    finding, rows, bindings, _, _ = _packet(tmp_path)
    finding["facts"]["domain_size"] = 1
    assert not finite_template_binding(finding, rows, bindings)
    finding, rows, bindings, _, _ = _packet(tmp_path)
    assert not finite_template_binding(finding, rows + [rows[0]], bindings)


def test_native_finite_wrapper_rejects_stale_span_and_malformed_ledger(tmp_path):
    finding, _, _, call, raw = _packet(tmp_path)
    facts = {**finding["facts"], "call_span": [4, 0, 4, 20]}
    for ledger in ({"3:4": facts}, []):
        assert not finite_template_witness(
            finding["path"],
            call,
            "exec",
            tmp_path,
            raw,
            {"finite_template_inputs": ledger},
        )


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _payload(**overrides):
    now = datetime.now(timezone.utc)
    value = {
        "schema": SCHEMA,
        "attestation_id": "att-001",
        "candidate_sha256": _digest("a"),
        "plan_sha256": _digest("b"),
        "run_nonce": "nonce-001",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "assurance_level": "isolated_worker",
        "runner": {
            "id": "runner-1",
            "version": "1.0.0",
            "platform": "linux",
            "backend": "isolated_worker",
            "executable_sha256": _digest("c"),
        },
        "observations": {
            "target_artifact_sha256": _digest("d"),
            "known_bad_artifact_sha256": _digest("e"),
            "target_stdout_sha256": _digest("f"),
            "target_stderr_sha256": None,
            "cleanup_confirmed": True,
            "memory_peak_bytes": 128,
            "latency_ms": 7,
        },
        "authority": "none",
    }
    value.update(overrides)
    return value


def test_valid_attestation_normalizes_and_has_no_authority():
    result = validate_execution_attestation(_payload())
    assert result["schema"] == SCHEMA
    assert result["observations"]["memory_peak_bytes"] == 128
    assert result["authority"] == "none"


def test_supervised_local_is_rejected_for_independent_lane():
    payload = _payload(assurance_level="supervised_local")
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_ASSURANCE"):
        validate_execution_attestation(payload)


def test_independent_assurance_rejects_local_backend():
    payload = _payload()
    payload["runner"] = {**payload["runner"], "backend": "local_supervised"}
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_BACKEND"):
        validate_execution_attestation(payload)


def test_binding_cleanup_expiry_replay_and_unknown_fields_fail_closed():
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_BINDING"):
        validate_execution_attestation(_payload(), candidate_sha256=_digest("z"))
    incomplete = _payload()
    incomplete["observations"]["cleanup_confirmed"] = False
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_INCOMPLETE"):
        validate_execution_attestation(incomplete)
    with pytest.raises(ExecutionAttestationError, match="E_ATTESTATION_REPLAY"):
        validate_execution_attestation(_payload(), seen_nonces=["nonce-001"])
    unknown = _payload()
    unknown["unexpected"] = True
    with pytest.raises(ExecutionAttestationError, match="E_ARTIFACT_FIELDS"):
        validate_execution_attestation(unknown)


def test_signed_attestation_verifies_against_local_trust_root(tmp_path):
    keys = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="runner-key",
        identity="runner@example",
        issuer="local",
    )
    payload = _payload()
    envelope = sign_payload(
        payload,
        payload_type=PAYLOAD_TYPE,
        private_key_path=keys["private_key"],
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
    )
    receipt = tmp_path / "attestation.json"
    receipt.write_text(json.dumps(envelope), encoding="utf-8")
    result = verify_signed_execution_attestation(
        receipt,
        keys["trust_root"],
        candidate_sha256=payload["candidate_sha256"],
        plan_sha256=payload["plan_sha256"],
    )
    assert result["state"] == "VERIFIED"
    assert result["release_approval"] is False
    other_root = tmp_path / "other-trust-root.json"
    other_root.write_text(
        json.dumps({"schema": "factory.trust.root.v1", "version": 1, "keys": []}),
        encoding="utf-8",
    )
    with pytest.raises(ExecutionAttestationError, match="E_UNKNOWN_KEY"):
        verify_signed_execution_attestation(receipt, other_root)

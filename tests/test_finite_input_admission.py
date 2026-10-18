"""Envelope integrity tests; real native-source admission is measured separately."""

import ast
import hashlib
import json

import pytest

from factoryline.provenance import finite_template_binding, finite_template_witness
from factoryline.review_integrity import _fixed_primitive_binding


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

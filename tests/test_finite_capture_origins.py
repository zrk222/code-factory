"""Source-only finite-input admission must reject mutable capture origins."""

from factoryline import finite_capture as finite
from factoryline import review_audits
from factoryline import review_integrity
from factoryline import runtime_audit_integrity as runtime

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


def test_shell_operation_witness_reconstructs_supported_command_and_rejects_shell_syntax():
    source = b"import os\nos.system('upx --best app')\n"
    tree = ast.parse(source)
    call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    span = [call.lineno, call.col_offset, call.end_lineno, call.end_col_offset]
    witness = finite.closed_shell_operation_witness(
        source, "build.py", span, "os.system"
    )
    assert witness["operation_role"] == "executable_packing"
    assert witness["target_execution"] == "not_performed"
    unsafe = b"import os\nos.system('upx --best app; evil')\n"
    unsafe_call = next(
        node for node in ast.walk(ast.parse(unsafe)) if isinstance(node, ast.Call)
    )
    unsafe_span = [
        unsafe_call.lineno,
        unsafe_call.col_offset,
        unsafe_call.end_lineno,
        unsafe_call.end_col_offset,
    ]
    assert (
        finite.closed_shell_operation_witness(
            unsafe, "build.py", unsafe_span, "os.system"
        )
        == {}
    )


def test_closed_shell_workspace_hashes_clean_inventory_and_rejects_provider_shadow():
    clean = {"app.py": b"import os\nos.system('upx --best app')\n"}
    digest = finite.closed_shell_workspace(clean, "os")
    assert isinstance(digest, str) and len(digest) == 64
    assert digest == finite.closed_shell_workspace(clean, "os")
    assert (
        finite.closed_shell_workspace({"os.py": b"def system(x): pass\n"}, "os") is None
    )


def test_finite_scope_binding_and_blocked_prefixes_preserve_semantics():
    tree = ast.parse("def run(secret):\n    secret = None\n")
    args = next(node for node in ast.walk(tree) if isinstance(node, ast.arg))
    stores = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    ]
    assert finite.finite_scope_binding_candidate(args, {"secret"})
    assert finite.finite_scope_binding_candidate(stores[0], {"secret"})
    assert not finite.finite_scope_binding_candidate(stores[0], {"other"})
    prefixes = finite.finite_blocked_provider_prefixes(
        {("test.py", "client")}, {"test.py": {"client": "provider.api.client"}}
    )
    assert prefixes == {"provider", "provider.api", "provider.api.client"}


def test_finite_template_program_hashes_only_fixed_async_function_grammar():
    template = (
        ast.parse('f"async def run({parameter}) -> None:\\n    pass\\n"').body[0].value
    )
    result = finite.finite_template_program_hashes(
        template, "parameter", ["user_id", "tenant_id"]
    )
    assert result is not None
    skeleton_hash, rows = result
    assert len(skeleton_hash) == 64
    assert len(rows) == 2 and all(len(digest) == 64 for digest in rows)
    assert finite.finite_template_program_hashes(template, "other", ["user_id"]) is None


def test_shell_call_catalog_and_source_bound_finding_keep_safe_effect_unassessed(
    tmp_path,
):
    calls = finite.shell_execution_calls()
    assert {"os.system", "subprocess.run", "subprocess.Popen"}.issubset(calls)
    raw = b"import os\nos.system('upx --best app')\n"
    root = tmp_path
    path = root / "build.py"
    path.write_bytes(raw)
    module = ast.parse(raw)
    module._security_source_context = (root, {path: raw})
    module._oracle_source_sha256 = __import__("hashlib").sha256(raw).hexdigest()
    call = next(node for node in ast.walk(module) if isinstance(node, ast.Call))
    call._security_lexical_scope = module
    finding = finite.closed_shell_finding("os.system", "build.py", call)
    assert finding["code"] == "SECURITY_OS_COMMAND"
    assert finding["facts"]["operation_role"] == "executable_packing"
    assert finding["facts"]["target_execution"] == "not_performed"
    assert finite.closed_shell_finding("subprocess.run", "build.py", call) is None


def test_finite_domain_reference_rules_distinguish_capture_membership_and_tail():
    tree = ast.parse("selected = sorted(domain)\nvalid = value in domain\n")
    capture = next(node for node in ast.walk(tree) if isinstance(node, ast.Call))
    captured_name = capture.args[0]
    references = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == "domain"
    ]
    membership_use = references[-1]
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    assert finite.finite_domain_reference_allowed(
        "tests/test.py",
        captured_name,
        (),
        "tests/test.py",
        captured_name,
        capture,
        parents,
    )
    assert finite.finite_domain_reference_allowed(
        "tests/test.py",
        membership_use,
        (),
        "tests/test.py",
        captured_name,
        capture,
        parents,
    )
    assert not finite.finite_domain_reference_allowed(
        "tests/test.py",
        membership_use,
        ("child",),
        "tests/test.py",
        captured_name,
        capture,
        parents,
    )


def test_finite_provider_attribute_write_index_detects_alias_mutation():
    tree = ast.parse("client.token = replacement\n")
    nodes = list(ast.walk(tree))
    aliases = {"client": "provider.api.client"}
    writes = finite.finite_provider_attribute_write_index(nodes, aliases, review_audits)
    assert ("provider.api.client", "token") in writes
    assert (
        finite.finite_provider_attribute_write_index([], aliases, review_audits)
        == set()
    )


def test_finite_template_capture_shape_accepts_only_sorted_parametrize_capture():
    source = "@pytest.mark.parametrize('program', sorted(programs))\ndef test_program(program):\n    assert program\n"
    function = ast.parse(source).body[0]
    shape = finite.finite_template_capture_shape(
        function, {"pytest": "pytest"}, review_audits, review_integrity
    )
    assert shape[0] == "program"
    assert isinstance(shape[1], ast.Call) and shape[1].func.id == "sorted"
    wrong = ast.parse(source.replace("sorted(programs)", "programs")).body[0]
    assert (
        finite.finite_template_capture_shape(
            wrong, {"pytest": "pytest"}, review_audits, review_integrity
        )
        is None
    )


def _pickle_origin(source, aliases=None):
    module = ast.parse(source)
    runtime._conditional_provider_parents(module)
    aliases = aliases or {"pickle": "pickle"}
    load_name = next(iter(aliases.values())) + ".loads"
    loads = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and review_audits._normalized_call_name(node, aliases) == load_name
    ]
    assert len(loads) == 1
    return runtime.closed_local_pickle_origin(
        loads[0], load_name, aliases, review_audits
    )


@pytest.mark.parametrize(
    "roundtrip, kind, protocol",
    [
        (
            "result = pickle.loads(pickle.dumps(obj))",
            "nested",
            {"kind": "default", "source": "omitted"},
        ),
        (
            "packed = pickle.dumps(obj, protocol=4)\nresult = pickle.loads(packed)",
            "named_payload",
            {"kind": "integer", "value": 4, "source": "keyword_literal"},
        ),
        (
            "packed = pickle.dumps(obj, None)\nresult = pickle.loads(packed)",
            "named_payload",
            {"kind": "default", "source": "explicit_none"},
        ),
    ],
)
def test_pickle_origin_normalizes_native_nested_and_named_roundtrips(
    roundtrip, kind, protocol
):
    source = f"import pickle\ndef run(obj):\n    {roundtrip.replace(chr(10), chr(10) + '    ')}\n"
    origin = _pickle_origin(source)
    assert origin is not None
    assert origin["status"] == "LOCAL_DIRECT_DUMPS_LOADS_ORIGIN"
    assert origin["origin_kind"] == kind
    assert origin["protocol"] == protocol
    assert isinstance(origin["dump_call"], ast.Call)
    assert isinstance(origin["object_expression"], ast.Name)


@pytest.mark.parametrize(
    "body",
    [
        "packed = pickle.dumps(obj)\nalias = packed\nresult = pickle.loads(packed)",
        "packed = pickle.dumps(obj)\n"
        "packed += b'changed'\n"
        "result = pickle.loads(packed)",
        "packed = pickle.dumps(obj)\n"
        "packed = replacement\n"
        "result = pickle.loads(packed)",
        "global packed\npacked = pickle.dumps(obj)\nresult = pickle.loads(packed)",
    ],
)
def test_pickle_named_origin_rejects_payload_alias_mutation_and_global_escape(body):
    source = "import pickle\ndef run(obj):\n    " + body.replace("\n", "\n    ") + "\n"
    assert _pickle_origin(source) is None


def test_pickle_nested_origin_is_separate_from_reconstruction_effect_proof():
    source = (
        "import pickle\n"
        "def run():\n"
        "    result = pickle.loads(pickle.dumps(make_unknown()))\n"
    )
    origin = _pickle_origin(source)
    assert origin is not None
    assert origin["object_expression"].func.id == "make_unknown"
    module = ast.parse(source)
    runtime._conditional_provider_parents(module)
    loads = next(
        node
        for node in ast.walk(module)
        if isinstance(node, ast.Call)
        and review_audits._normalized_call_name(node, {"pickle": "pickle"})
        == "pickle.loads"
    )
    assert (
        runtime.closed_local_pickle_flow(
            loads, "pickle.loads", {"pickle": "pickle"}, review_audits
        )
        is None
    )


def test_pickle_origin_keeps_import_identity_and_rejects_local_serializer_rebinding():
    source = (
        "import pickle as serializer\n"
        "def run(obj):\n"
        "    result = serializer.loads(serializer.dumps(obj))\n"
    )
    origin = _pickle_origin(source, {"serializer": "pickle"})
    assert origin is not None and origin["origin_kind"] == "nested"
    rebound = source.replace(
        "    result =",
        "    serializer = replacement\n    result =",
    )
    assert _pickle_origin(rebound, {"serializer": "pickle"}) is None


def test_pickle_origin_rejects_non_native_serializer_namespace():
    source = "import json\ndef run(obj):\n    result = json.loads(json.dumps(obj))\n"
    assert _pickle_origin(source, {"json": "json"}) is None


@pytest.mark.parametrize(
    "extra_source, expected_count",
    [
        ("", 1),
        ("import zlib as compression\ndef unrelated(compression):\n    pass\n", 1),
        ("def unrelated():\n    observe(LocalError)\n", 1),
        (
            "def poison():\n    alias = LocalError\n    alias.__init__ = replacement\n",
            0,
        ),
        ("pickle.loads = replacement\n", 0),
    ],
)
def test_pickle_typed_v3_reuses_protocol_loop_origin_after_model_selection(
    tmp_path, extra_source, expected_count, monkeypatch
):
    from factoryline.finite_capture import provider_analysis_profile

    runtime_base = {
        "implementation": "cpython",
        "version": "3.11.9",
        "executable_sha256": "1" * 64,
        "pickle_source_sha256": "2" * 64,
        "pickle_implementation_sha256": "3" * 64,
    }
    runtime_v3 = {
        **runtime_base,
        "enum_source_sha256": "4" * 64,
        "typing_source_sha256": "5" * 64,
        "python_runtime_sha256": "6" * 64,
    }
    monkeypatch.setattr(
        finite, "_provider_runtime_identity", lambda: dict(runtime_base)
    )
    monkeypatch.setattr(
        finite, "provider_runtime_identity_v3", lambda: dict(runtime_v3)
    )

    provider_source = (
        "from enum import IntEnum\n"
        "class LocalError(Exception):\n"
        "    def __init__(self, message=None):\n"
        "        super().__init__(message)\n"
        "        self.message = message\n"
        "class WireCode(IntEnum):\n"
        "    PROTOCOL_ERROR = 7\n"
    ).encode()
    package_source = ("from .errors import LocalError, WireCode\n").encode()
    caller_source = (
        "import pickle\n"
        "from package import LocalError, WireCode\n"
        "def test_closed_record():\n"
        "    err = LocalError(WireCode.PROTOCOL_ERROR)\n"
        "    err.foo = 'bar'\n"
        "    for proto in range(pickle.HIGHEST_PROTOCOL + 1):\n"
        "        packed = pickle.dumps(err, proto)\n"
        "        result = pickle.loads(packed)\n"
        "        assert result.foo == 'bar'\n"
    ).encode() + extra_source.encode()
    sources = {
        "package/errors.py": provider_source,
        "package/__init__.py": package_source,
        "test_roundtrip.py": caller_source,
    }
    error_tree = ast.parse(provider_source)
    classes = [node for node in error_tree.body if isinstance(node, ast.ClassDef)]
    contract = {
        "schema": "factory.provider-contract.v1",
        "model": {"id": "typed-pickle-reconstruction-v3", "version": 3},
        "runtime": finite.provider_runtime_identity_v3(),
        "artifacts": {
            path: hashlib.sha256(value).hexdigest()
            for path, value in sources.items()
            if path != "test_roundtrip.py"
        },
        "export": {"path": "package/__init__.py", "symbol": "LocalError"},
        "classes": [
            {
                "path": "package/errors.py",
                "name": cls.name,
                "class_ast_sha256": hashlib.sha256(
                    ast.dump(cls, include_attributes=False).encode()
                ).hexdigest(),
                "constructor_ast_sha256": next(
                    (
                        hashlib.sha256(
                            ast.dump(item, include_attributes=False).encode()
                        ).hexdigest()
                        for item in cls.body
                        if isinstance(item, ast.FunctionDef) and item.name == "__init__"
                    ),
                    None,
                ),
            }
            for cls in classes
        ],
        "assumptions": list(finite._PROVIDER_ASSUMPTIONS),
    }
    for path, value in sources.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
    profile = provider_analysis_profile("trusted-dependencies-v2", (contract,))
    report = review_audits.security_scan(
        tmp_path,
        cache_enabled=False,
        analysis_profile="trusted-dependencies-v2",
        provider_contracts=tuple(profile["contracts"]),
    )
    witnesses = [
        row
        for row in report.get("primitive_observations", [])
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(witnesses) == expected_count
    if not expected_count:
        assert any(
            row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
            for row in report["findings"]
        )
        return
    witness = witnesses[0]["facts"]["provider_witness"]
    assert witness["selected_model_sha256"]
    assert witness["protocol"]["same_iteration"] is True


@pytest.mark.parametrize(
    "body, observed",
    [
        ("    return pickle.loads(pickle.dumps(value))\n", True),
        ("    blob = pickle.dumps(value)\n    return pickle.loads(blob)\n", True),
        (
            "    for p in range(2):\n        blob = pickle.dumps(value, p)\n        result = pickle.loads(blob)\n"
            "    for p in range(2):\n        blob = pickle.dumps(value, p)\n        result = pickle.loads(blob)\n",
            True,
        ),
        (
            "    global blob\n    blob = pickle.dumps(value)\n    return pickle.loads(blob)\n",
            False,
        ),
        (
            "    blob = pickle.dumps(value)\n    blob += supplied\n    return pickle.loads(blob)\n",
            False,
        ),
        (
            "    blob = pickle.dumps(value)\n    leak(blob)\n    return pickle.loads(blob)\n",
            False,
        ),
        ("    return pickle.loads(supplied)\n", False),
    ],
)
def test_pickle_family_byte_origin_is_type_independent_and_not_a_safety_decision(
    body, observed
):
    from factoryline import runtime_audit_integrity as runtime

    tree = ast.parse("import pickle\ndef work(value, supplied=None):\n" + body)
    runtime._conditional_provider_parents(tree)
    loads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and review_audits._normalized_call_name(node, {"pickle": "pickle"})
        == "pickle.loads"
    ]
    for load in loads:
        origin = runtime.local_pickle_byte_origin(
            load, "pickle.loads", {"pickle": "pickle"}, review_audits
        )
        assert (origin is not None) is observed
        if origin:
            assert origin["reconstruction_effects"] == "UNASSESSED"
            assert origin["negative_security_decision"] is False


def test_pickle_family_origin_observation_keeps_dangerous_reducer_diagnostic(tmp_path):
    source = (
        "import pickle\nclass Payload:\n"
        "    def __reduce__(self):\n        return eval, ('controlled_expression',)\n"
        "def work():\n    return pickle.loads(pickle.dumps(Payload()))\n"
    )
    (tmp_path / "consumer.py").write_text(source, encoding="utf-8")
    report = review_audits.security_scan(tmp_path, cache_enabled=False)
    findings = [
        row
        for row in report["findings"]
        if row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert len(findings) == 1
    (ledger,) = [
        row
        for row in report["finding_tier_report"]["ledger"]
        if row["raw_finding"]["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
    ]
    assert ledger["raw_finding"] == findings[0]
    assert ledger["tier"] == "NEEDS_CONTEXT"
    assert ledger["byte_origin_observation"]["negative_security_decision"] is False
    assert ledger["byte_origin_observation"]["reconstruction_effects"] == "UNASSESSED"
    assert not any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in report.get("primitive_observations", [])
    )


def _pickle_role_report(root, source, extra=None, policy="source-role-v1"):
    path = root / "tests" / "test_roundtrip.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    for name, value in (extra or {}).items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")
    with review_audits._security_only_scan_context(True):
        return review_audits.security_scan(
            root, cache_enabled=False, defect_policy=policy
        )


_PICKLE_ROLE_TEST = "import pickle\ndef test_roundtrip():\n    result = pickle.loads(pickle.dumps(object()))\n    assert result\n"


def test_pickle_role_review_preserves_raw_and_reseals(tmp_path):
    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    (review,) = report["context_reviews"]
    assert not report["findings"]
    (raw,) = report["finding_tier_report"]["ledger"]
    assert raw["raw_finding"] == review
    assert raw["source_role_review"]["safe_reconstruction"] is False
    assert raw["source_role_review"]["reconstruction_effects"] == "UNASSESSED"
    assert report["state"] == "REVIEW_REQUIRED"
    assert report["defect_policy_decision"]["clean"] is False
    again = review_audits._seal_security_scan(report.copy())
    assert again["context_reviews"] == [review]
    assert again["audit_sha256"] == report["audit_sha256"]
    assert "_primitive_source_bytes" not in again


@pytest.mark.parametrize("policy", ["legacy-v1", "trusted-core-v1"])
def test_pickle_role_policy_switch_restores_diagnostics(tmp_path, policy):
    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    (original,) = report["context_reviews"]
    report["selected_defect_policy"] = policy
    changed = review_audits._seal_security_scan(report)
    assert original in changed["findings"]
    assert not changed.get("context_reviews")
    assert all(
        "source_role_review" not in row
        for row in changed["finding_tier_report"]["ledger"]
    )


@pytest.mark.parametrize(
    "source,extra",
    [
        (
            "import pickle\ndef test_external(blob):\n    assert pickle.loads(blob)\n",
            {},
        ),
        (_PICKLE_ROLE_TEST.replace("def test_roundtrip", "def handler"), {}),
        (
            _PICKLE_ROLE_TEST.replace(
                "import pickle", "import pickle\npickle.loads = supplied"
            ),
            {},
        ),
        (_PICKLE_ROLE_TEST, {"app.py": "import tests.test_roundtrip\n"}),
        (_PICKLE_ROLE_TEST, {"app.py": "from .tests import test_roundtrip\n"}),
        (
            "import pytest\nimport pickle\nclass Handler:\n    def test_roundtrip(self):\n        assert pickle.loads(pickle.dumps(object()))\n",
            {},
        ),
        (
            "import pickle\n__test__ = False\ndef test_roundtrip():\n    assert pickle.loads(pickle.dumps(object()))\n",
            {},
        ),
        (
            "import pickle\nclass TestRoundtrip:\n    def __init__(self): pass\n    def test_roundtrip(self):\n        assert pickle.loads(pickle.dumps(object()))\n",
            {},
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "model.py": 'import requests\nclass Payload:\n    def __getstate__(self):\n        requests.get("https://example.invalid")\n        return {}\n'
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "model.py": 'def run(value):\n    return eval(value)\nclass Payload:\n    def __reduce__(self):\n        return run, ("x",)\n'
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {"mutation.py": "import pickle\npickle.loads = attacker\n"},
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "mutation.py": 'import builtins, pickle\nbuiltins.setattr(pickle, "loads", attacker)\n'
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "mutation.py": "import pickle\nprovider = pickle\nprovider.loads = attacker\n"
            },
        ),
        (
            _PICKLE_ROLE_TEST,
            {
                "mutation.py": 'import pickle\npickle.__dict__.update({"loads": attacker})\n'
            },
        ),
        (_PICKLE_ROLE_TEST, {"pickle.py": "def loads(value): return value\n"}),
        (
            _PICKLE_ROLE_TEST
            + '\nfrom helper import restore\nclass Payload:\n    def __reduce__(self): return restore, ("x",)\n',
            {"helper.py": "def restore(value): return eval(value)\n"},
        ),
    ],
)
def test_pickle_role_counterevidence_keeps_alert(tmp_path, source, extra):
    report = _pickle_role_report(tmp_path, source, extra)
    assert not report.get("context_reviews")
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in report["findings"]
    )


def test_pickle_role_stale_capture_restores_alert(tmp_path):
    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    report["_primitive_source_bytes"] = {}
    changed = review_audits._seal_security_scan(report)
    assert not changed["context_reviews"]
    assert changed["defect_policy_decision"]["state"] == "BLOCKED"
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION" for row in changed["findings"]
    )


def test_pickle_role_forged_severity_cannot_qualify(tmp_path):
    from factoryline import primitive_observation_binding as primitive

    report = _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    original = report["context_reviews"][0]
    finding = dict(
        original, severity="CRITICAL" if original["severity"] != "CRITICAL" else "INFO"
    )
    inventory = primitive._pickle_role_inventory(
        {"tests/test_roundtrip.py": _PICKLE_ROLE_TEST.encode()}
    )
    assert primitive._pickle_test_role_witness(finding, inventory) is None


def test_pickle_role_cli_receipt_and_text(tmp_path, capsys):
    from factoryline.cli import main

    _pickle_role_report(tmp_path, _PICKLE_ROLE_TEST)
    (tmp_path / ".factory").mkdir(exist_ok=True)
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    argv = [
        "audit",
        "security",
        "--root",
        str(tmp_path),
        "--defect-policy",
        "source-role-v1",
    ]
    assert main([*argv, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["context_reviews"]) == 1
    assert report["defect_policy_decision"]["clean"] is False
    receipt = json.loads(
        (tmp_path / ".factory/security-scan/latest.json").read_text(encoding="utf-8")
    )
    assert receipt["report"]["context_reviews"] == report["context_reviews"]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert "NEEDS_CONTEXT reviews: 1" in output
    assert "No clean security result" in output
    assert main([*argv, "--full-repository", "--json"]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "E_DEFECT_POLICY_SCOPE"


@pytest.mark.parametrize(
    "base,extra,qualified",
    [
        ("unittest.TestCase", {}, True),
        (
            "ConnectingCase",
            {
                "tests/helper.py": "import unittest\nclass ConnectingCase(unittest.TestCase): pass\n"
            },
            True,
        ),
        (
            "ConnectingCase",
            {
                "tests/helper.py": "import types, unittest\nclass ConnectingCase(unittest.TestCase): pass\ndef f():\n    types = []\n"
            },
            True,
        ),
        (
            "ConnectingCase",
            {
                "tests/helper.py": "import unittest\nunittest = supplied\nclass ConnectingCase(unittest.TestCase): pass\n"
            },
            False,
        ),
        ("ConnectingCase", {}, False),
        ("unittest.TestCase", {"unittest.py": "class TestCase: pass\n"}, False),
        ("ConnectingCase", {"tests/helper.py": "class ConnectingCase: pass\n"}, False),
    ],
)
def test_pickle_role_unittest_ancestry_is_source_bound(
    tmp_path, base, extra, qualified
):
    source = (
        "import unittest\nimport pickle\nfrom .helper import ConnectingCase\n"
        f"class CursorChecks({base}):\n"
        "    def test_roundtrip(self):\n"
        "        result = pickle.loads(pickle.dumps(object()))\n"
        "        self.assertTrue(result)\n"
    )
    report = _pickle_role_report(tmp_path, source, extra)
    assert bool(report.get("context_reviews")) is qualified
    assert bool(report["findings"]) is not qualified


_PICKLE_PIPE_WORKER = """import pickle
import subprocess
import sys
from runtime import open_process, BufferedByteReceiveStream
async def launch():
    command = [sys.executable, "-u", "-m", __name__]
    process = await open_process(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    buffered = BufferedByteReceiveStream(process.stdout)
    async def communicate():
        payload = await buffered.receive_exactly(10)
        return pickle.loads(payload)
    return await communicate()
def worker():
    stdin = sys.stdin
    value = pickle.load(stdin.buffer)
    encoded = pickle.dumps(value)
    return encoded
if __name__ == "__main__":
    worker()
"""


@pytest.mark.parametrize(
    "source,qualified",
    [
        (_PICKLE_PIPE_WORKER, True),
        (
            _PICKLE_PIPE_WORKER.replace(
                'sys.executable, "-u", "-m", __name__', '"remote-program"'
            ),
            False,
        ),
        (_PICKLE_PIPE_WORKER.replace("stdin=subprocess.PIPE", "stdin=external"), False),
        (
            _PICKLE_PIPE_WORKER.replace(
                "    buffered = BufferedByteReceiveStream(process.stdout)",
                "    buffered = external",
            ),
            False,
        ),
        (
            _PICKLE_PIPE_WORKER.replace(
                "    stdin = sys.stdin", "    stdin = external"
            ),
            False,
        ),
    ],
)
def test_pickle_role_worker_protocol_requires_source_bindings(
    tmp_path, source, qualified
):
    (tmp_path / "worker.py").write_text(source, encoding="utf-8")
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v1"
        )
    reviews = report.get("context_reviews", [])
    if qualified:
        assert len(reviews) == 2
        assert not report["findings"]
        assert all(
            row["source_role_review"]["safe_reconstruction"] is False
            for row in report["finding_tier_report"]["ledger"]
        )
    else:
        assert report["findings"]
    assert len(report["findings"]) + len(reviews) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "ConnectingCase = object",
        "unittest.TestCase = object",
        'setattr(unittest, "TestCase", object)',
    ],
)
def test_pickle_role_rebound_testcase_cannot_qualify(tmp_path, mutation):
    source = (
        "import unittest\nimport pickle\nclass ConnectingCase(unittest.TestCase): pass\n"
        + mutation
        + "\nclass CursorChecks(ConnectingCase):\n"
        "    def test_roundtrip(self):\n"
        "        self.assertTrue(pickle.loads(pickle.dumps(object())))\n"
    )
    report = _pickle_role_report(tmp_path, source)
    assert not report.get("context_reviews")
    assert report["findings"]


@pytest.mark.parametrize(
    "source,expected_reviews",
    [
        (
            _PICKLE_PIPE_WORKER
            + "\nasync def external_read(buffered):\n    payload = await buffered.receive_exactly(10)\n    return pickle.loads(payload)\n",
            2,
        ),
        (
            _PICKLE_PIPE_WORKER.replace(
                "        return pickle.loads(payload)",
                "        payload = external\n        return pickle.loads(payload)",
            ),
            1,
        ),
    ],
)
def test_pickle_role_ipc_does_not_launder_external_receiver_or_rebound_bytes(
    tmp_path, source, expected_reviews
):
    (tmp_path / "worker.py").write_text(source, encoding="utf-8")
    with review_audits._security_only_scan_context(True):
        report = review_audits.security_scan(
            tmp_path, cache_enabled=False, defect_policy="source-role-v1"
        )
    assert len(report["context_reviews"]) == expected_reviews
    assert any(row["facts"].get("call") == "pickle.loads" for row in report["findings"])

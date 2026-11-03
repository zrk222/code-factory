"""Coordinator boundaries; mocked rows test admission, not source-flow accuracy."""

import ast
from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from factoryline import audit_action_refs
from factoryline import credential_endpoint_admission as admission
from factoryline.credential_endpoint_admission import endpoint_binding

ENDPOINT = "https://appleid.apple.com/auth/token"


def _case(tmp_path, monkeypatch, overrides=None):
    admission._WORKSPACES.clear()
    path = tmp_path / "client.py"
    raw = f"class Client:\n    ACCESS_TOKEN_URL = {ENDPOINT!r}\n".encode()
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    tree._oracle_source_sha256 = digest
    tree._security_source_context = (tmp_path, {path: raw})
    node = tree.body[0].body[0]
    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "client.py",
        "line": node.lineno,
        "column": node.col_offset,
        "severity": "CRITICAL",
        "message": "original heuristic",
        "facts": {"name": "ACCESS_TOKEN_URL"},
    }
    row = {
        "declaration": {
            "source_sha256": digest,
            "path": "client.py",
            "member": "ACCESS_TOKEN_URL",
            "line": node.lineno,
            "column": node.col_offset,
            "value_sha256": hashlib.sha256(ENDPOINT.encode()).hexdigest(),
        },
        "profile": "DECLARED_CLASS_MAY_FLOW",
        "url_witnesses": [{"path": "client.py", "line": 2}],
        "known_auth_uses": [],
        "linked_unknown_uses": [],
        "value_use_audit": {
            "state": "COMPLETE",
            "profile": admission.USE_AUDIT_PROFILE,
        },
        **(overrides or {}),
    }
    monkeypatch.setattr(
        admission, "_derive", lambda *args: {("client.py", 2, "ACCESS_TOKEN_URL"): row}
    )
    integrity = SimpleNamespace(_security_module_scope=lambda _: tree)
    return node, finding, row, tree, integrity


def test_coordinator_mints_bound_local_marker_without_changing_priority(
    tmp_path, monkeypatch
):
    node, finding, _, tree, integrity = _case(tmp_path, monkeypatch)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    digest = tree._oracle_source_sha256
    assert endpoint_binding(
        finding, [{"path": "client.py", "sha256": digest}], {"client.py": digest}
    )
    assert finding["severity"] == "CRITICAL"
    assert finding["message"] == "original heuristic"


@pytest.mark.parametrize(
    "overrides",
    [
        {"value_use_audit": {}},
        {"value_use_audit": {"state": "INCOMPLETE", "profile": "partial"}},
        {"value_use_audit": {"state": "COMPLETE", "profile": "unknown_profile"}},
        {"known_auth_uses": [{"slot": "password"}]},
        {"linked_unknown_uses": [{"reason": "unresolved_receiver"}]},
        {"url_witnesses": []},
    ],
)
def test_missing_or_conflicting_source_proof_preserves_original_alert(
    tmp_path, monkeypatch, overrides
):
    node, finding, _, _, integrity = _case(tmp_path, monkeypatch, overrides)
    before = deepcopy(finding)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding == before


def test_source_mutation_invalidates_workspace_projection(tmp_path, monkeypatch):
    node, finding, _, tree, integrity = _case(tmp_path, monkeypatch)
    source_root, sources = tree._security_source_context
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert len(admission._WORKSPACES) == 1
    sources[source_root / "new.py"] = b"new_consumer = None\n"
    finding["facts"] = {"name": "ACCESS_TOKEN_URL"}
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert len(admission._WORKSPACES) == 2
    assert len(finding["facts"]._attestation[2]) == 2


def test_mismatched_declaration_cannot_receive_native_marker(tmp_path, monkeypatch):
    node, finding, row, _, integrity = _case(tmp_path, monkeypatch)
    row["declaration"]["line"] = 20
    before = deepcopy(finding)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding == before


def test_retained_source_changed_under_current_tree_is_rejected(tmp_path, monkeypatch):
    node, finding, _, tree, integrity = _case(tmp_path, monkeypatch)
    root, sources = tree._security_source_context
    sources[root / "client.py"] += b"ACCESS_TOKEN_URL = replacement\n"
    before = deepcopy(finding)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding == before


def test_changed_derivation_cannot_reuse_prior_complete_row(tmp_path, monkeypatch):
    node, finding, _, _, integrity = _case(tmp_path, monkeypatch)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding["facts"].get("disposition") == "ENDPOINT_DECLARATION_ROLE_PROVEN"
    finding["facts"] = {"name": "ACCESS_TOKEN_URL"}
    monkeypatch.setattr(admission, "_derive", lambda *args: {})
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    assert finding["facts"] == {"name": "ACCESS_TOKEN_URL"}
    assert len(admission._WORKSPACES) == 2


@pytest.mark.parametrize("cache_enabled", [False, True])
def test_real_scanner_partition_uses_current_coordinator(
    tmp_path, monkeypatch, cache_enabled
):
    from factoryline.review_audits import security_scan

    _, _, _, tree, _ = _case(tmp_path, monkeypatch)
    root, sources = tree._security_source_context
    for path, raw in sources.items():
        path.write_bytes(raw)
    for _ in range(2):
        result = security_scan(root, cache_enabled=cache_enabled)
        assert result["finding_conservation"]["state"] == "PASS"
        assert not [
            f for f in result["findings"] if f["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        observations = [
            f
            for f in result.get("primitive_observations", [])
            if f["code"] == "SECURITY_HARDCODED_SECRET"
        ]
        assert len(observations) == 1
        assert observations[0]["severity"] == "CRITICAL"
        assert observations[0]["facts"]["credential_safety"] == "UNASSESSED"


def _seal_core():
    first = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "client.py",
        "line": 2,
        "column": 4,
        "severity": "CRITICAL",
    }
    second = {
        "code": "SECURITY_SQL_INJECTION",
        "path": "client.py",
        "line": 8,
        "column": 0,
        "severity": "HIGH",
    }
    return {
        "state": "FINDINGS",
        "action_summary": "Two source findings require review.",
        "findings": [first],
        "context_reviews": [second],
        "primitive_observations": [],
        "finding_tier_report": {
            "ledger": [
                {"raw_finding": first, "tier": "NEEDS_CONTEXT"},
                {"raw_finding": second, "tier": "NEEDS_CONTEXT"},
            ]
        },
        "_primitive_source_bytes": {"client.py": b"private captured source"},
    }


def _seal_audit(partition):
    action_calls = []

    def remediation(candidate, finding, **kwargs):
        action_calls.append(finding)
        return audit_action_refs.audit_remediation_packet(
            candidate,
            finding,
            kwargs.get("source_bound_security_precondition"),
        )

    audit = SimpleNamespace(
        integrity=SimpleNamespace(partition_proven_primitive_observations=partition),
        _security_scan_report_candidate_payload=(
            audit_action_refs._security_scan_report_candidate_payload
        ),
        audit_remediation_packet=remediation,
    )
    return audit, action_calls


@pytest.mark.parametrize("failure_point", ["prepare", "partition", "policy"])
def test_security_scan_seal_failure_is_transactional_and_retryable(
    monkeypatch, failure_point
):
    core = _seal_core()
    before = deepcopy(core)
    audit, _ = _seal_audit(lambda *_: None)

    def fail_prepare(working, prior):
        original_prepare(working, prior)
        working["partial_prepare"] = True
        raise RuntimeError("injected preparation failure")

    def fail_partition(working, *_):
        working["findings"].append({"code": "SECURITY_PARTIAL"})
        raise RuntimeError("injected partition failure")

    def fail_policy(_audit, working, *_):
        working["finding_tier_report"]["ledger"].append({"partial": True})
        raise RuntimeError("injected policy failure")

    original_prepare = audit_action_refs._prepare_security_scan_sources
    with monkeypatch.context() as patcher:
        patcher.setattr(
            audit_action_refs, "_security_scan_verification_state", lambda *_: None
        )
        patcher.setattr(
            audit_action_refs, "_apply_security_scan_configuration", lambda *_: None
        )
        if failure_point == "prepare":
            patcher.setattr(
                audit_action_refs, "_prepare_security_scan_sources", fail_prepare
            )
        elif failure_point == "partition":
            audit.integrity.partition_proven_primitive_observations = fail_partition
        else:
            patcher.setattr(
                audit_action_refs, "_apply_security_scan_policy", fail_policy
            )
        with pytest.raises(RuntimeError, match="injected"):
            audit_action_refs.seal_security_scan(audit, core)

    assert core == before

    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", lambda *_: None
    )
    audit.integrity.partition_proven_primitive_observations = lambda *_: None
    first = audit_action_refs.seal_security_scan(audit, core)
    first_actions = deepcopy(first["agent_actions"])
    second = audit_action_refs.seal_security_scan(audit, first)
    assert [row["code"] for row in second["findings"]] == [
        "SECURITY_HARDCODED_SECRET",
        "SECURITY_SQL_INJECTION",
    ]
    assert second["agent_actions"] == first_actions
    assert len(second["agent_actions"]) == 2
    assert second["finding_conservation"]["state"] == "PASS"


def test_security_scan_known_native_surface_mismatch_cannot_fallback_to_handoff(
    monkeypatch,
):
    from factoryline import primitive_observation_binding as primitive

    core = _seal_core()
    core["selected_defect_policy"] = "trusted-core-v1"
    first = deepcopy(core["findings"][0])
    second = deepcopy(core["context_reviews"][0])
    forged = {
        "code": "SECURITY_FORGED",
        "path": "client.py",
        "line": 12,
        "column": 0,
        "severity": "HIGH",
    }
    core["context_reviews"].append(forged)
    core["finding_tier_report"]["ledger"].append(
        {"raw_finding": deepcopy(forged), "tier": "NEEDS_CONTEXT"}
    )
    core["defect_policy_decision"] = {
        "state": "CLEAN",
        "exit_code": 0,
        "passed": True,
        "clean": True,
    }
    audit, action_calls = _seal_audit(lambda *_: None)
    monkeypatch.setattr(
        audit_action_refs,
        "_security_scan_verification_state",
        lambda *_: ((None,), (), None, ()),
    )
    monkeypatch.setattr(
        primitive,
        "_trusted_core_native_security_rows",
        lambda *_: [first, second],
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", lambda *_: None
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["state"] == "BLOCKED"
    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["native_rows"] == "MISMATCH"
    assert result["finding_conservation"]["native_surface_mismatch"] is True
    assert result["finding_conservation"]["baseline_raw_diagnostics"] == [
        first,
        second,
        forged,
    ]
    assert result["agent_actions"] == []
    assert action_calls == []
    assert result["defect_policy_decision"]["exit_code"] == 2
    assert result["defect_policy_decision"]["passed"] is False
    assert result["defect_policy_decision"]["clean"] is False


def test_security_scan_native_reverification_change_cannot_fallback_to_handoff(
    monkeypatch,
):
    from factoryline import primitive_observation_binding as primitive

    core = _seal_core()
    core["selected_defect_policy"] = "trusted-core-v1"
    native_rows = [deepcopy(core["findings"][0]), deepcopy(core["context_reviews"][0])]
    audit, action_calls = _seal_audit(lambda *_: None)
    calls = 0

    def verification_state(*_):
        nonlocal calls
        calls += 1
        generation = "verified" if calls == 1 else "changed"
        return ((generation,), (), None, ())

    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", verification_state
    )
    monkeypatch.setattr(
        primitive,
        "_trusted_core_native_security_rows",
        lambda *_: native_rows,
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", lambda *_: None
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["state"] == "BLOCKED"
    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["native_rows"] == "INVALIDATED"
    assert result["finding_conservation"]["native_verification_state_changed"] is True
    assert result["finding_conservation"]["expected_security_rows"] == 2
    assert result["agent_actions"] == []
    assert action_calls == []


def test_security_scan_conserves_exact_rejected_proof_transform(monkeypatch):
    from factoryline import primitive_observation_binding as primitive

    core = _seal_core()
    finding = core["findings"][0]
    finding["facts"] = {
        "name": "TEST_SECRET",
        "disposition": "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE",
    }
    core["finding_tier_report"]["ledger"][0]["raw_finding"] = deepcopy(finding)
    audit, _ = _seal_audit(lambda *_: None)

    def reject_proof(_audit, working, *_):
        working["findings"][0] = primitive.rejected_primitive_proof(
            working["findings"][0]
        )

    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", reject_proof
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["finding_conservation"]["state"] == "PASS"
    assert result["finding_conservation"]["physical_matches_expected"] is True
    assert result["finding_conservation"]["ledger_matches_expected"] is True
    assert (
        result["findings"][0]["facts"]["proof_rejection"] == "SOURCE_BINDING_MISMATCH"
    )


def test_security_scan_does_not_spend_one_raw_row_twice(monkeypatch):
    from factoryline import primitive_observation_binding as primitive

    core = _seal_core()
    first = core["findings"][0]
    first["facts"] = {"disposition": "PROVEN_LOCAL_CRYPTO_TEST_PRIMITIVE"}
    core["finding_tier_report"]["ledger"][0]["raw_finding"] = deepcopy(first)
    original = deepcopy(first)
    audit, action_calls = _seal_audit(lambda *_: None)

    def duplicate_one_row(_audit, working, *_):
        rejected = primitive.rejected_primitive_proof(original)
        working["findings"] = [deepcopy(original), rejected]

    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs,
        "_apply_security_scan_configuration",
        duplicate_one_row,
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["state"] == "BLOCKED"
    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["physical_matches_expected"] is False
    assert result["finding_conservation"]["ledger_matches_expected"] is True
    assert result["agent_actions"] == []
    assert action_calls == []


@pytest.mark.parametrize("field", ["message", "end_column", "facts"])
def test_security_scan_conservation_rejects_raw_payload_mutation(monkeypatch, field):
    core = _seal_core()
    finding = core["findings"][0]
    finding.update(
        message="original diagnostic",
        end_line=2,
        end_column=14,
        facts={"name": "ORIGINAL_SECRET", "literal": "retained"},
    )
    core["finding_tier_report"]["ledger"][0]["raw_finding"] = deepcopy(finding)
    audit, action_calls = _seal_audit(lambda *_: None)

    def mutate_payload(_audit, working, *_):
        if field == "facts":
            working["findings"][0]["facts"]["name"] = "CHANGED_SECRET"
        else:
            working["findings"][0][field] = "changed diagnostic"

    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", mutate_payload
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["state"] == "BLOCKED"
    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["ledger_matches_expected"] is True
    assert result["agent_actions"] == []
    assert action_calls == []


def test_security_scan_conservation_covers_nonsecurity_families(monkeypatch):
    core = _seal_core()
    diagnostic = {
        "code": "QUALITY_UNKNOWN_TEST_ORACLE",
        "path": "tests/test_client.py",
        "line": 4,
        "column": 0,
        "severity": "MEDIUM",
        "message": "Oracle state is unknown.",
    }
    core["findings"].append(diagnostic)
    core["finding_tier_report"]["ledger"].append(
        {"raw_finding": deepcopy(diagnostic), "tier": "NEEDS_CONTEXT"}
    )
    audit, action_calls = _seal_audit(lambda *_: None)

    def drop_quality(_audit, working, *_):
        working["findings"].pop()

    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", drop_quality
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["state"] == "BLOCKED"
    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["baseline_raw_diagnostics"][-1] == diagnostic
    assert result["agent_actions"] == []
    assert action_calls == []


@pytest.mark.parametrize(
    ("surface", "mutation"),
    [
        ("physical", "drop"),
        ("physical", "duplicate"),
        ("ledger", "drop"),
        ("ledger", "duplicate"),
    ],
)
def test_security_scan_postpolicy_conservation_blocks_and_preserves_diagnostics(
    monkeypatch, surface, mutation
):
    from factoryline import primitive_observation_binding as primitive

    core = _seal_core()
    core["selected_defect_policy"] = "trusted-core-v1"
    first, second = deepcopy(core["findings"][0]), deepcopy(core["context_reviews"][0])
    native_rows = [first, second]
    core["defect_policy_decision"] = {
        "state": "CLEAN",
        "exit_code": 0,
        "passed": True,
        "clean": True,
    }
    audit, action_calls = _seal_audit(lambda *_: None)
    verified_state = ((None,), (), None, ())
    monkeypatch.setattr(
        audit_action_refs,
        "_security_scan_verification_state",
        lambda *_: verified_state,
    )
    monkeypatch.setattr(
        primitive,
        "_trusted_core_native_security_rows",
        lambda *_: native_rows,
    )

    def corrupt_policy(_audit, working, *_):
        working["defect_policy_decision"].update(
            state="CLEAN", exit_code=0, passed=True, clean=True
        )
        if surface == "physical":
            if mutation == "drop":
                working["findings"].pop()
            else:
                working["findings"].append(deepcopy(first))
        elif mutation == "drop":
            working["finding_tier_report"]["ledger"].pop()
        else:
            working["finding_tier_report"]["ledger"].append(
                {"raw_finding": deepcopy(first), "tier": "SUPPORTED_DEFECT"}
            )

    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", corrupt_policy
    )
    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["state"] == "BLOCKED"
    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["native_rows"] == "VERIFIED"
    assert result["finding_conservation"]["baseline_raw_diagnostics"] == [
        first,
        second,
    ]
    assert result["agent_actions"] == []
    assert action_calls == []
    assert result["defect_policy_decision"]["state"] == "BLOCKED"
    assert result["defect_policy_decision"]["exit_code"] == 2
    assert result["defect_policy_decision"]["passed"] is False
    assert result["defect_policy_decision"]["clean"] is False
    assert "no repair actions were emitted" in result["action_summary"]


def test_security_scan_keeps_raw_duplicate_but_emits_one_handoff_action():
    core = _seal_core()
    first = deepcopy(core["findings"][0])
    core["findings"] = [first, deepcopy(first)]
    core["context_reviews"] = []
    core["finding_tier_report"]["ledger"] = [
        {"raw_finding": deepcopy(first), "tier": "NEEDS_CONTEXT"},
        {"raw_finding": deepcopy(first), "tier": "NEEDS_CONTEXT"},
    ]
    audit, action_calls = _seal_audit(lambda *_: None)

    result = audit_action_refs.seal_security_scan(audit, core)

    assert len(result["findings"]) == 2
    assert len(result["finding_tier_report"]["ledger"]) == 2
    assert result["finding_conservation"]["state"] == "PASS"
    assert len(result["agent_actions"]) == 1
    assert len(action_calls) == 1


@pytest.mark.parametrize(
    "corruption",
    [
        "none",
        "missing",
        "wrong_candidate",
        "wrong_finding",
        "duplicate",
        "mutate_input",
    ],
)
def test_security_scan_rejects_unbound_remediation_packets(monkeypatch, corruption):
    core = _seal_core()
    expected_findings = deepcopy(core["findings"] + core["context_reviews"])
    audit, _ = _seal_audit(lambda *_: None)
    builder = audit.audit_remediation_packet
    packets = []
    calls = 0

    def corrupt_builder(candidate, finding, **kwargs):
        nonlocal calls
        calls += 1
        if corruption == "none":
            return None
        if corruption == "missing" and calls == 2:
            return None
        if corruption == "duplicate" and packets:
            return deepcopy(packets[0])
        if corruption == "mutate_input":
            finding["message"] = "builder mutation must not escape"
        packet = builder(candidate, finding, **kwargs)
        if corruption == "wrong_candidate":
            packet["candidate_sha256"] = "f" * 64
        elif corruption == "wrong_finding":
            packet["finding_context"]["message"] = "different finding"
        packets.append(deepcopy(packet))
        return packet

    audit.audit_remediation_packet = corrupt_builder
    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", lambda *_: None
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["state"] == "BLOCKED"
    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["failure_code"] == (
        "SECURITY_ACTION_HANDOFF_INVALID"
    )
    assert (
        result["finding_conservation"]["baseline_raw_diagnostics"] == expected_findings
    )
    assert result["agent_actions"] == []
    assert [row["code"] for row in result["findings"]] == [
        row["code"] for row in expected_findings
    ]


def test_security_scan_duplicate_supported_ledger_row_blocks_without_filtering(
    monkeypatch,
):
    core = _seal_core()
    core["selected_defect_policy"] = "trusted-core-v1"
    core["defect_policy_decision"] = {
        "state": "CLEAN",
        "exit_code": 0,
        "passed": True,
        "clean": True,
    }
    first = deepcopy(core["findings"][0])
    core["findings"].append(deepcopy(first))
    core["finding_tier_report"]["ledger"][0]["tier"] = "SUPPORTED_DEFECT"
    core["finding_tier_report"]["ledger"].append(
        {"raw_finding": deepcopy(first), "tier": "SUPPORTED_DEFECT"}
    )
    audit, action_calls = _seal_audit(lambda *_: None)
    monkeypatch.setattr(
        audit_action_refs, "_security_scan_verification_state", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_policy", lambda *_: None
    )
    monkeypatch.setattr(
        audit_action_refs, "_apply_security_scan_configuration", lambda *_: None
    )

    result = audit_action_refs.seal_security_scan(audit, core)

    assert result["finding_conservation"]["state"] == "FAILED"
    assert result["finding_conservation"]["handoff_failure"] == (
        "AMBIGUOUS_SUPPORTED_LEDGER_ROW"
    )
    assert result["state"] == "BLOCKED"
    assert result["defect_policy_decision"]["exit_code"] == 2
    assert result["defect_policy_decision"]["clean"] is False
    assert len(result["findings"]) == 3
    assert result["agent_actions"] == []
    assert action_calls == []


def test_seal_action_builder_cannot_mutate_source_witness():
    finding = {
        "code": "SECURITY_HARDCODED_SECRET",
        "path": "client.py",
        "line": 3,
        "column": 4,
        "severity": "CRITICAL",
    }
    candidate = "a" * 64
    source_sha256 = "b" * 64
    precondition = {
        "schema": "factory.security.precondition.v1",
        "state": "observed",
    }
    identity_sha256 = hashlib.sha256(
        audit_action_refs._canonical(
            {
                "path": "client.py",
                "source_sha256": source_sha256,
                "code": finding["code"],
                "line": finding["line"],
                "column": finding["column"],
                "original_severity": finding["severity"],
                "raw_finding": finding,
            }
        )
    ).hexdigest()
    witness = {
        "source_path": "client.py",
        "source_sha256": source_sha256,
        "finding_identity_sha256": identity_sha256,
        "precondition_sha256": hashlib.sha256(
            audit_action_refs._canonical(precondition)
        ).hexdigest(),
        "precondition": deepcopy(precondition),
    }
    original_witness = deepcopy(witness)
    builder = audit_action_refs.audit_remediation_packet

    def mutate_witness(candidate_sha256, raw_finding, **kwargs):
        packet = builder(candidate_sha256, raw_finding, **kwargs)
        kwargs["source_bound_security_precondition"]["precondition"]["state"] = (
            "mutated"
        )
        return packet

    audit = SimpleNamespace(audit_remediation_packet=mutate_witness)
    actions, failure = audit_action_refs._security_scan_seal_actions(
        audit,
        candidate,
        [finding],
        {audit_action_refs._canonical(finding): witness},
        False,
    )

    assert failure is None
    assert witness == original_witness
    assert actions[0]["security_precondition_evidence"]["precondition"] == precondition


def test_security_scan_failure_keeps_original_private_capture_and_endpoint_marker(
    tmp_path, monkeypatch
):
    node, finding, _, _, integrity = _case(tmp_path, monkeypatch)
    admission.annotate_endpoint_findings("client.py", node, [finding], integrity)
    facts = finding["facts"]
    attestation = facts._attestation
    core = _seal_core()
    core["findings"][0]["facts"] = facts
    report = audit_action_refs._SourceBoundSecurityReport(core)
    captured = (("client.py", b"private captured source"),)
    report._captured_sources = captured
    audit, _ = _seal_audit(lambda *_: None)

    def fail_policy(_audit, working, *_):
        working["action_summary"] = "partial policy mutation"
        raise RuntimeError("injected policy failure")

    with monkeypatch.context() as patcher:
        patcher.setattr(
            audit_action_refs, "_security_scan_verification_state", lambda *_: None
        )
        patcher.setattr(
            audit_action_refs, "_apply_security_scan_configuration", lambda *_: None
        )
        patcher.setattr(audit_action_refs, "_apply_security_scan_policy", fail_policy)
        with pytest.raises(RuntimeError, match="injected policy failure"):
            audit_action_refs.seal_security_scan(audit, report)

    assert report._captured_sources is captured
    assert report["findings"][0]["facts"] is facts
    assert facts._attestation == attestation


def test_transactional_scanner_keeps_endpoint_proof_source_bound_not_serialized(
    tmp_path, monkeypatch
):
    from factoryline.credential_endpoint_admission import endpoint_binding
    from factoryline.review_audits import security_scan

    _, _, _, tree, _ = _case(tmp_path, monkeypatch)
    root, sources = tree._security_source_context
    for path, raw in sources.items():
        path.write_bytes(raw)
    result = security_scan(root, defect_policy="trusted-core-v1")
    observation = next(
        row
        for row in result["primitive_observations"]
        if row["code"] == "SECURITY_HARDCODED_SECRET"
    )
    bindings = {row["path"]: row["sha256"] for row in result["sources"]}
    captured = dict(result._captured_sources)

    assert result["finding_conservation"]["state"] == "PASS"
    assert endpoint_binding(
        observation, result["sources"], bindings, source_bytes=captured
    )
    serialized = json.loads(json.dumps(observation))
    assert not endpoint_binding(serialized, result["sources"], bindings)


def test_precision257_endpoint_helper_inventory_and_catalog_digest_are_content_bound(
    monkeypatch,
):
    from factoryline import credential_endpoint_admission as endpoint

    catalog_helpers = endpoint.catalog_callable_helpers()
    validation = endpoint.validation_helpers()
    evidence = endpoint.endpoint_evidence_helpers()
    assert {item.__name__ for item in catalog_helpers if callable(item)} == {
        "urlsplit",
        "_unique_object",
        "_public_https",
        "endpoint_metadata",
        "matches_endpoint_declaration",
        "_catalog_digest",
        "_entry",
        "_reviewed_entry",
        "_declaration",
        "_read",
        "_catalog_bytes",
        "catalog_content_digest",
        "endpoint_publications",
        "endpoint_publication",
    }
    validation_names = {
        item.__name__
        for item in validation
        if callable(item) and getattr(item, "__module__", None) == endpoint.__name__
    }
    assert {
        "operative_signing_default_evidence",
        "_flask_credential_authority_for_key",
        "_flask_login_session_authority_witness",
        "_flask_credential_authority_witness",
        "_request_client_origin",
        "_direct_httpx_fixture",
        "_closed_fixture_decorator",
        "_client_uses_closed",
        "_cookie_write",
        "_tuple_httpx_fixture",
        "_fixture_app_uses_only_client",
        "factory_fixture_consumer_status",
        "_factory_fixture_uses",
        "_factory_fixture_consumer_result",
        "_single_factory_fixture_call",
        "public_json_assertion",
        "_json_assertion_operands",
        "_json_detail_name",
        "_json_cast_response",
        "_json_response_name",
        "_json_response_request",
        "_assertion_values",
        "_public_expected_value",
        "_public_enum_member",
        "router_factory_call_published",
        "_router_factory_call_published",
        "_fixture_returns_factory",
        "_factory_fixture_consumers",
        "_fixture_app_consumers_closed",
        "_fixture_app_consumers_closed_uncached",
        "_app_route_lookups_closed",
        "_include_router_options",
        "_route_lookup_only",
        "_local_name_uses",
        "_memo",
        "_app_fixture_consumer_status",
        "validation_helpers",
    } <= validation_names
    assert endpoint.tuple_httpx_fixture in validation
    assert endpoint.request_client_origin in validation
    from factoryline.credential_role_method_use_getter_audit import (
        CapturedOriginProjection,
    )

    owners = (
        endpoint._OperativeCredentialOrigin,
        endpoint._CredentialHandlerIndex,
        CapturedOriginProjection,
    )
    required_methods = {
        f"{owner.__qualname__}.{name}"
        for owner in owners
        for name, value in vars(owner).items()
        if callable(value)
    }
    assert required_methods <= {item.__qualname__ for item in validation}
    assert {
        "_endpoint_evidence_digest",
        "_identity",
        "_NativeEndpointFacts",
        "mint_endpoint_facts",
        "endpoint_binding",
        "_endpoint_claim_profile_matches",
        "_endpoint_attestation_matches",
    } == {item.__name__ for item in evidence if callable(item)}
    catalog = endpoint._catalog_bytes()
    assert catalog is not None
    assert endpoint.catalog_content_digest() == endpoint._catalog_digest(catalog)
    monkeypatch.setattr(endpoint, "_catalog_bytes", lambda: None)
    assert endpoint.catalog_content_digest() == "MISSING"
    finding = {
        "code": "E",
        "path": "a.py",
        "line": 1,
        "column": 0,
        "severity": "HIGH",
        "message": "x",
    }
    digest = endpoint._endpoint_evidence_digest({"a": 1})
    assert digest == endpoint._endpoint_evidence_digest({"a": 1})
    assert digest != endpoint._endpoint_evidence_digest({"a": 2})
    assert endpoint._identity(finding) == ("E", "a.py", 1, 0, "HIGH", "x")
    assert (
        endpoint.factory_fixture_consumer_status(
            None, "x", "fixture", "source", ast.parse("pass").body[0], True, True
        )
        is None
    )


def test_precision257_fixture_consumer_status_classifies_supported_and_unsupported_calls():
    import ast
    from types import SimpleNamespace
    from factoryline.credential_endpoint_admission import (
        factory_fixture_consumer_status,
    )

    def graph_for(source):
        tree = ast.parse(source)
        fixture, caller = tree.body
        parents = {
            id(child): node
            for node in ast.walk(tree)
            for child in ast.iter_child_nodes(node)
        }
        graph = SimpleNamespace(
            parents=parents,
            _is_pytest_fixture=lambda *_: True,
            _walk=lambda node: ast.walk(node),
            _nearest_fixture=lambda _source, name, _caller: (
                "tests/test_api.py",
                fixture,
            )
            if name == fixture.name
            else None,
        )
        return graph, fixture, caller

    path = "tests/test_api.py"
    graph, fixture, caller = graph_for(
        "def client_fixture():\n    pass\ndef consumer(client_fixture):\n    return client_fixture()"
    )
    assert (
        factory_fixture_consumer_status(
            graph, path, fixture, path, caller, lambda *_: True, lambda *_: True
        )
        is True
    )
    graph, fixture, caller = graph_for(
        "def client_fixture():\n    pass\ndef consumer(client_fixture):\n    return client_fixture"
    )
    assert (
        factory_fixture_consumer_status(
            graph, path, fixture, path, caller, lambda *_: False, lambda *_: True
        )
        is False
    )


@pytest.mark.parametrize(
    ("namespace", "setting"),
    [
        ("django.conf.settings", "FEATURE_ENABLED"),
        ("core.settings", "FEATURE_ENABLED"),
        ("core.settings", "configured"),
    ],
)
def test_django_sequence_branch_projects_selected_settings_literal(namespace, setting):
    handler = object.__new__(admission._CredentialHandlerIndex)
    handler.django_settings = ast.parse(f"{setting} = False")
    handler.django_settings_module = "core.settings"
    handler._django_guard_dependencies = {}
    handler.canonical = lambda _path, node: (
        namespace + "." + node.attr
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "settings"
        else None
    )
    visited = []
    handler._django_sequence_statements = (
        lambda _path, statements, _values, _accepted: (
            visited.append(statements) or True
        )
    )
    statement = ast.parse(
        f"if not settings.{setting}:\n    pass\nelse:\n    blocked = True"
    ).body[0]
    accepted = set()

    assert handler._django_sequence_branch("urls.py", statement, {}, accepted)
    assert visited == [statement.body]
    assert id(statement.orelse[0].targets[0]) in accepted
    assignment = handler.django_settings.body[0]
    assert handler._django_guard_dependencies == {(setting, assignment): None}


@pytest.mark.parametrize(
    ("settings_source", "guard", "namespace"),
    [
        ("", "settings.FEATURE_ENABLED", "django.conf.settings"),
        (
            "FEATURE_ENABLED = os.getenv('FEATURE_ENABLED')",
            "settings.FEATURE_ENABLED",
            "django.conf.settings",
        ),
        (
            "FEATURE_ENABLED = True\nFEATURE_ENABLED = False",
            "settings.FEATURE_ENABLED",
            "django.conf.settings",
        ),
        (
            "if DEBUG:\n    FEATURE_ENABLED = True",
            "settings.FEATURE_ENABLED",
            "django.conf.settings",
        ),
        ("configured = False", "settings.configured", "django.conf.settings"),
        (
            'MEDIA_URL = "media/"',
            "settings.MEDIA_URL == '/media/'",
            "django.conf.settings",
        ),
        ("FEATURE_ENABLED = False", "settings.FEATURE_ENABLED", "other.settings"),
        ("FEATURE_ENABLED = False", "settings.FEATURE_ENABLED", None),
    ],
)
def test_django_sequence_branch_leaves_unclosed_settings_unknown(
    settings_source, guard, namespace
):
    handler = object.__new__(admission._CredentialHandlerIndex)
    handler.django_settings = ast.parse(settings_source)
    handler.django_settings_module = "core.settings"
    handler._django_guard_dependencies = {}
    handler.canonical = lambda _path, node: (
        namespace + "." + node.attr
        if namespace is not None
        and isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "settings"
        else None
    )
    handler._django_sequence_statements = lambda *_args: pytest.fail(
        "unknown guard must not select either branch"
    )
    statement = ast.parse(f"if {guard}:\n    pass\nelse:\n    pass").body[0]

    assert not handler._django_sequence_branch("urls.py", statement, {}, set())
    assert not handler._django_guard_dependencies


@pytest.mark.parametrize(
    "settings_source",
    ["", "DEBUG = True\nDEBUG = False"],
)
def test_django_sequence_branch_keeps_debug_default_and_last_literal(settings_source):
    handler = object.__new__(admission._CredentialHandlerIndex)
    handler.django_settings = ast.parse(settings_source)
    handler.django_settings_module = "core.settings"
    handler._django_guard_dependencies = {}
    handler.canonical = lambda _path, node: (
        "django.conf.settings.DEBUG"
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "settings"
        else None
    )
    visited = []
    handler._django_sequence_statements = (
        lambda _path, statements, _values, _accepted: (
            visited.append(statements) or True
        )
    )
    statement = ast.parse("if settings.DEBUG:\n    pass\nelse:\n    pass").body[0]

    assert handler._django_sequence_branch("urls.py", statement, {}, set())
    assert visited == [statement.orelse]


def test_django_reference_reuses_source_span_for_relative_path():
    from pathlib import Path
    from factoryline.credential_role_constructor_provider import SourceSnapshotIndex

    path = Path("settings.py")
    raw = b"FEATURE_ENABLED = False\n"
    tree = ast.parse(raw)
    digest = hashlib.sha256(raw).hexdigest()
    index = SourceSnapshotIndex(Path("."), {path: tree}, {path: raw}, {path: digest})
    handler = object.__new__(admission._CredentialHandlerIndex)
    handler.index = index

    assert handler._django_reference(path, tree.body[0]) == {
        "path": "settings.py",
        "sha256": digest,
        "span": [1, 0, 1, 23],
    }


def test_django_sequence_rejects_large_guard_before_provider_projection():
    handler = object.__new__(admission._CredentialHandlerIndex)
    handler.canonical = lambda *_: pytest.fail("guard budget must precede projection")
    statement = ast.parse(
        "if " + " or ".join(["settings.FLAG"] * 200) + ":\n    pass"
    ).body[0]
    assert not handler._django_sequence_branch("urls.py", statement, {}, set())


def test_django_selected_consumer_materializes_guard_roots(monkeypatch):
    from factoryline import semantic_credential_sensor as sensor
    from pathlib import Path
    from types import SimpleNamespace

    settings_path, url_path, view_path = map(
        Path, ("core/settings.py", "core/urls.py", "images/views.py")
    )
    trees = {path: ast.parse("pass") for path in (settings_path, url_path, view_path)}
    index = SimpleNamespace(
        snapshots=trees,
        inventory={path: "0" * 64 for path in trees},
        validate=lambda _path: True,
    )
    context = {"index": index, "aliases": {path: {} for path in trees}}
    roots_by_tree = {}

    monkeypatch.setattr(
        sensor, "_security_builtin_identity_closed", lambda *_a, **_k: True
    )
    monkeypatch.setattr(sensor, "_provider_identity_uncertain", lambda *_a, **_k: False)
    monkeypatch.setattr(sensor, "_signing_provider_clear", lambda *_a, **_k: True)

    def provider_reads(tree, _aliases, _framework, roots, _nodes, **_kwargs):
        roots_by_tree[id(tree)] = tuple(roots)
        return set()

    monkeypatch.setattr(
        sensor,
        "_signing_provider_reads",
        provider_reads,
    )

    assert admission._django_selected_consumers_closed(
        context,
        settings_path,
        {"FEATURE_ENABLED"},
        set(),
        {url_path, view_path},
        iter(("FEATURE_ENABLED",)),
    )
    expected = "django.conf.settings.FEATURE_ENABLED"
    assert all(
        expected in roots_by_tree[id(trees[path])] for path in (url_path, view_path)
    )

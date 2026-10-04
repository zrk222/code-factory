from __future__ import annotations
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import pytest
from factoryline.enterprise_enforcement import (
    EnterpriseEnforcementError,
    authorize_enterprise_action,
    canonical_json,
    enterprise_enforcement_projection,
    record_enterprise_decision,
    validate_enforcement_policy,
    validate_workload_identity,
    verify_enterprise_decision,
    verify_enforcement_policy,
    verify_workload_identity,
    sign_enforcement_policy,
    sign_workload_identity,
    sign_workload_revocations,
)
from factoryline.enterprise_receipts import generate_key_material
from factoryline.enterprise_runner_admission import (
    EnterpriseRunnerAdmissionError,
    prepare_runner_admission,
    runner_admission_projection,
    verify_runner_admission_packet,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.semantic_authority import (
    _now,
    seal_authority_lease,
    seal_semantic_handoff,
)
from factoryline.audit_trace import build_audit_trace, verify_audit_trace
from factoryline.control_plane import ControlPlaneError, EvidenceStore, Principal
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from factoryline.appforge_mobile_evidence import verify_mobile_evidence_receipt
from factoryline.appforge_quality_audit import quality_audit_projection
from factoryline.assurance import policy_mutations
from factoryline.capability_packs import pack_payload, sign_pack
from factoryline.counterexample import (
    CounterexampleError,
    validate_counterexample_source,
)
from factoryline.e2e_proof import run_supervised_command
from factoryline.first_lap import (
    verify_activation_receipt,
    verify_promoted_incident_gates,
)
from factoryline.github_proof_review import (
    GitHubProofReviewError,
    validate_github_proof_review_payload,
)
from factoryline.guardrails import GuardrailError, validate_guardrail_manifest
from factoryline.oracle_firewall import (
    OracleFirewallError,
    admission_oracle_decision,
    oracle_incidents_for_agent,
)
from factoryline.plan_proof_review import (
    PlanProofReviewError,
    validate_plan_proof_review,
)
from factoryline.repair_sandbox import (
    RepairSandboxError,
    validate_repair_scope_envelope,
)
from factoryline.runtime_audit_common import RuntimeAuditError
from factoryline.runtime_audit_integrity import validate_receipt_decision
from factoryline.runtime_audit_policy import validate_lane_policy
from factoryline.supply_chain import SupplyChainError, validate_attestation

AGENT = {
    "schema": "factory.agent-identity.v1",
    "subject": "enterprise-worker",
    "provider": "local",
    "model": "model-a",
}


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _keys(root: Path) -> dict:
    return generate_key_material(
        out_dir=root / "keys",
        keyid="enterprise-ci",
        identity="https://example.test/workflows/proof",
        issuer="https://issuer.example.test",
    )


def _semantic_binding(root: Path) -> dict:
    intent = root / "intent.md"
    intent.write_text(
        "A restore must never create a second purchase.", encoding="utf-8"
    )
    planner = {
        "schema": "factory.agent-identity.v1",
        "subject": "planner",
        "provider": "local",
        "model": "model-a",
    }
    handoff = capture_intent_handoff(
        root,
        intent,
        planner,
        "intake",
        Path(".factory/oracles/handoffs/enterprise.json"),
    )
    contract_input = _write(
        root / "contract-input.json",
        {
            "schema": "factory.oracle-contract-input.v1",
            "id": "enterprise-restore",
            "version": 1,
            "approved_by": "Owner",
            "approval_rationale": "Bind restore safety before a worker tests it.",
            "scope_paths": ["."],
            "handoff": handoff["path"],
            "sources": [],
            "requirements": [
                {
                    "id": "restore",
                    "statement": "Restore requires an entitlement.",
                    "origin": "human_confirmed",
                    "effect": "blocking",
                    "source_id": "original-intent",
                    "critical": True,
                }
            ],
            "forbidden_behaviors": [
                {
                    "id": "charge",
                    "statement": "Restore never purchases.",
                    "origin": "human_confirmed",
                    "effect": "blocking",
                    "source_id": "original-intent",
                    "critical": True,
                }
            ],
            "gates": [
                {
                    "id": "evidence",
                    "statement": "Evidence exists.",
                    "origin": "human_confirmed",
                    "effect": "blocking",
                    "source_id": "original-intent",
                    "critical": True,
                    "comparison": "present",
                    "value": True,
                }
            ],
            "exceptions": [
                {
                    "id": "offline",
                    "statement": "Offline evidence is advisory only.",
                    "origin": "human_confirmed",
                    "effect": "advisory",
                    "source_id": "original-intent",
                    "critical": False,
                }
            ],
            "negative_cases": [
                {
                    "id": "expired",
                    "statement": "Expired access is denied.",
                    "origin": "human_confirmed",
                    "effect": "blocking",
                    "source_id": "original-intent",
                    "critical": True,
                }
            ],
            "invariants": [
                {
                    "id": "candidate",
                    "statement": "Evidence binds the candidate.",
                    "origin": "trusted_source",
                    "effect": "blocking",
                    "source_id": "original-intent",
                    "critical": True,
                }
            ],
            "tests": [
                {
                    "id": "restore-test",
                    "statement": "The negative case fails.",
                    "origin": "human_confirmed",
                    "effect": "blocking",
                    "source_id": "original-intent",
                    "critical": True,
                    "path": "tests/test_restore.py",
                }
            ],
        },
    )
    contract = (
        root
        / seal_oracle_contract(
            root,
            contract_input,
            Path(".factory/oracles/contracts/enterprise-restore.json"),
        )["path"]
    )
    semantic_input = _write(
        root / "semantic-input.json",
        {
            "schema": "factory.semantic-handoff-input.v1",
            "id": "enterprise-proof",
            "oracle_contract": contract.relative_to(root).as_posix(),
            "sender": planner,
            "receiver": AGENT,
            "performative": "REQUEST",
            "goal": "Test the restore safety contract.",
            "context_urn": "urn:factory:enterprise-restore:v1",
            "context_source_id": "original-intent",
            "scope_paths": ["tests"],
            "allowed_actions": ["test"],
            "sensitivities": [],
            "epistemic": {
                "known": [
                    {
                        "id": "intent",
                        "statement": "The sealed intent forbids a second purchase.",
                        "source_id": "original-intent",
                    }
                ],
                "unknown": [
                    {
                        "id": "provider",
                        "statement": "Live provider state is unavailable.",
                        "impact": "Do not claim production behavior.",
                        "blocking": False,
                    }
                ],
                "uncertain": [
                    {
                        "id": "parity",
                        "statement": "Sandbox parity is uncertain.",
                        "impact": "Runtime evidence remains required.",
                    }
                ],
                "capability_limits": ["No provider or release access."],
            },
        },
    )
    semantic = (
        root
        / seal_semantic_handoff(
            root,
            semantic_input,
            Path(".factory/semantic-authority/handoffs/enterprise.json"),
        )["path"]
    )
    lease_input = _write(
        root / "lease-input.json",
        {
            "schema": "factory.authority-lease-input.v1",
            "id": "enterprise-worker",
            "handoff": semantic.relative_to(root).as_posix(),
            "delegatee": AGENT,
            "scope_paths": ["tests"],
            "allowed_actions": ["test"],
            "expires_at": (_now() + timedelta(minutes=20))
            .isoformat()
            .replace("+00:00", "Z"),
            "approval_origin": "human_confirmed",
            "approved_by": "Owner",
            "rationale": "Bound enterprise test admission.",
        },
    )
    lease = (
        root
        / seal_authority_lease(
            root,
            lease_input,
            Path(".factory/semantic-authority/leases/enterprise.json"),
        )["path"]
    )
    lease_value = json.loads(lease.read_text(encoding="utf-8"))
    return {
        "lease_path": lease.relative_to(root).as_posix(),
        "lease_sha256": lease_value["lease_sha256"],
        "action_id": "enterprise-restore-test",
        "action": "test",
        "context_urn": "urn:factory:enterprise-restore:v1",
    }


def _materials(
    root: Path, *, require_semantic_lease: bool = True
) -> tuple[dict, Path, Path, dict]:
    keys = _keys(root)
    starts = _now()
    identity = {
        "schema": "factory.workload-identity.v1",
        "tenant_id": "tenant-a",
        "workload_id": "proof-runner",
        "subject": "repo:example/app",
        "audience": "factoryline.enterprise",
        "issued_at": starts.isoformat().replace("+00:00", "Z"),
        "expires_at": (starts + timedelta(minutes=30))
        .isoformat()
        .replace("+00:00", "Z"),
        "agent": AGENT,
        "allowed_action_classes": ["test"],
    }
    policy = {
        "schema": "factory.enforcement-policy.v1",
        "policy_id": "repo-proof",
        "version": "1",
        "tenant_id": "tenant-a",
        "audience": "factoryline.enterprise",
        "allowed_action_classes": ["test"],
        "allowed_scope_paths": ["tests"],
        "require_semantic_lease": require_semantic_lease,
    }
    identity_path, policy_path = root / "identity.dsse.json", root / "policy.dsse.json"
    sign_workload_identity(
        identity,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
        out=identity_path,
    )
    sign_enforcement_policy(
        policy,
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
        out=policy_path,
    )
    request = {
        "tenant_id": "tenant-a",
        "workload_id": "proof-runner",
        "subject": "repo:example/app",
        "audience": "factoryline.enterprise",
        "action_id": "enterprise-restore-test",
        "action_class": "test",
        "scope_paths": ["tests"],
        "oracle_contract_sha256": "a" * 64,
    }
    return keys, identity_path, policy_path, request


def test_workload_identity_validation_enforces_lifetime_and_normalizes_identity():
    issued_at = _now()
    payload = {
        "schema": "factory.workload-identity.v1",
        "tenant_id": "tenant-a",
        "workload_id": "proof-runner",
        "subject": "repo:example/app",
        "audience": "factoryline.enterprise",
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued_at + timedelta(minutes=30))
        .isoformat()
        .replace("+00:00", "Z"),
        "agent": AGENT,
        "allowed_action_classes": ["test"],
    }

    normalized = validate_workload_identity(payload)

    assert normalized["allowed_action_classes"] == ["test"]
    assert normalized["agent"]["subject"] == AGENT["subject"]
    too_long_lived = {
        **payload,
        "expires_at": (issued_at + timedelta(hours=25))
        .isoformat()
        .replace("+00:00", "Z"),
    }
    with pytest.raises(EnterpriseEnforcementError, match="within 24 hours"):
        validate_workload_identity(too_long_lived)


def test_enforcement_policy_validation_requires_boolean_and_safe_scope():
    payload = {
        "schema": "factory.enforcement-policy.v1",
        "policy_id": "repo-proof",
        "version": "1",
        "tenant_id": "tenant-a",
        "audience": "factoryline.enterprise",
        "allowed_action_classes": ["test"],
        "allowed_scope_paths": ["tests"],
        "require_semantic_lease": True,
    }

    normalized = validate_enforcement_policy(payload)

    assert normalized["allowed_scope_paths"] == ["tests"]
    assert normalized["require_semantic_lease"] is True
    with pytest.raises(EnterpriseEnforcementError, match="must be boolean"):
        validate_enforcement_policy({**payload, "require_semantic_lease": 1})
    with pytest.raises(EnterpriseEnforcementError):
        validate_enforcement_policy({**payload, "allowed_scope_paths": ["../outside"]})


def test_signed_identity_and_policy_verifiers_check_trust_and_expiry(tmp_path: Path):
    keys, identity, policy, _ = _materials(tmp_path)

    checked_identity = verify_workload_identity(
        identity, trust_root_path=Path(keys["trust_root"])
    )
    checked_policy = verify_enforcement_policy(
        policy, trust_root_path=Path(keys["trust_root"])
    )

    assert checked_identity["identity"]["tenant_id"] == "tenant-a"
    assert checked_identity["signature"]["keyid"] == keys["keyid"]
    assert checked_identity["verification"] == "offline_dsse_ed25519"
    assert checked_policy["policy"]["allowed_action_classes"] == ["test"]
    assert checked_policy["signature"]["keyid"] == keys["keyid"]
    assert checked_policy["verification"] == "offline_dsse_ed25519"
    with pytest.raises(EnterpriseEnforcementError, match="expired"):
        verify_workload_identity(
            identity,
            trust_root_path=Path(keys["trust_root"]),
            now=_now() + timedelta(hours=1),
        )


def test_enterprise_reference_admits_only_exact_signed_identity_policy_and_lease(
    tmp_path: Path,
) -> None:
    keys, identity, policy, request = _materials(tmp_path)
    request["semantic_authority"] = _semantic_binding(tmp_path)
    decision = authorize_enterprise_action(
        tmp_path,
        request,
        workload_identity_path=identity,
        policy_path=policy,
        trust_root_path=Path(keys["trust_root"]),
    )
    assert decision["marker"] == "ENTERPRISE_PEP_REFERENCE_ADMITTED"
    assert decision["admitted"] is True
    assert decision["semantic_authority_status"] == "VERIFIED"
    assert all(value is False for value in decision["authority"].values())
    assert "did not execute a tool" in decision["claim_boundary"]


def test_enterprise_reference_rejects_cross_tenant_scope_and_lease_absence(
    tmp_path: Path,
) -> None:
    keys, identity, policy, request = _materials(tmp_path)
    with pytest.raises(EnterpriseEnforcementError, match="E_SEMANTIC_LEASE_REQUIRED"):
        authorize_enterprise_action(
            tmp_path,
            request,
            workload_identity_path=identity,
            policy_path=policy,
            trust_root_path=Path(keys["trust_root"]),
        )
    request["semantic_authority"] = _semantic_binding(tmp_path)
    request["tenant_id"] = "other"
    with pytest.raises(EnterpriseEnforcementError, match="E_WORKLOAD_BINDING"):
        authorize_enterprise_action(
            tmp_path,
            request,
            workload_identity_path=identity,
            policy_path=policy,
            trust_root_path=Path(keys["trust_root"]),
        )
    request["tenant_id"] = "tenant-a"
    request["scope_paths"] = ["src"]
    with pytest.raises(EnterpriseEnforcementError, match="E_SCOPE_ESCAPE"):
        authorize_enterprise_action(
            tmp_path,
            request,
            workload_identity_path=identity,
            policy_path=policy,
            trust_root_path=Path(keys["trust_root"]),
        )


def test_workload_revocation_and_decision_replay_fail_closed(tmp_path: Path) -> None:
    keys, identity, policy, request = _materials(tmp_path)
    request["semantic_authority"] = _semantic_binding(tmp_path)
    recorded = record_enterprise_decision(
        tmp_path,
        request,
        Path(".factory/enterprise-enforcement/decisions/first.json"),
        workload_identity_path=identity,
        policy_path=policy,
        trust_root_path=Path(keys["trust_root"]),
    )
    assert recorded["path"].endswith("first.json")
    with pytest.raises(EnterpriseEnforcementError, match="E_ENFORCEMENT_REPLAY"):
        record_enterprise_decision(
            tmp_path,
            request,
            Path(".factory/enterprise-enforcement/decisions/replay.json"),
            workload_identity_path=identity,
            policy_path=policy,
            trust_root_path=Path(keys["trust_root"]),
        )
    projection = enterprise_enforcement_projection(tmp_path)
    assert projection["admitted_count"] == 1
    revocations = tmp_path / "workload-revocations.dsse.json"
    sign_workload_revocations(
        [
            {
                "tenant_id": "tenant-a",
                "workload_id": "proof-runner",
                "subject": "repo:example/app",
                "revoked_at": (_now() - timedelta(minutes=1))
                .isoformat()
                .replace("+00:00", "Z"),
                "reason": "compromised",
            }
        ],
        private_key_path=Path(keys["private_key"]),
        keyid=keys["keyid"],
        identity=keys["identity"],
        issuer=keys["issuer"],
        out=revocations,
    )
    with pytest.raises(EnterpriseEnforcementError, match="E_WORKLOAD_REVOKED"):
        authorize_enterprise_action(
            tmp_path,
            request,
            workload_identity_path=identity,
            policy_path=policy,
            trust_root_path=Path(keys["trust_root"]),
            revocations_path=revocations,
        )


def test_decision_reauthorizes_signed_inputs_after_a_recomputed_local_hash(
    tmp_path: Path,
) -> None:
    keys, identity, policy, request = _materials(tmp_path)
    request["semantic_authority"] = _semantic_binding(tmp_path)
    recorded = record_enterprise_decision(
        tmp_path,
        request,
        Path(".factory/enterprise-enforcement/decisions/reauthorize.json"),
        workload_identity_path=identity,
        policy_path=policy,
        trust_root_path=Path(keys["trust_root"]),
    )
    source = tmp_path / recorded["path"]
    forged = json.loads(source.read_text(encoding="utf-8"))
    forged["request"]["action_class"] = "deploy"
    unsigned = {key: value for key, value in forged.items() if key != "decision_sha256"}
    forged["decision_sha256"] = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    source.write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(EnterpriseEnforcementError, match="E_ACTION_UNGRANTED"):
        verify_enterprise_decision(tmp_path, source)


def test_enterprise_cli_seals_and_records_reference_decision(
    tmp_path: Path, capsys
) -> None:
    from factoryline.cli import main

    keys, _, _, request = _materials(tmp_path, require_semantic_lease=False)
    request_path = _write(tmp_path / "request.json", request)
    issued_at = _now()
    identity_payload = _write(
        tmp_path / "identity.json",
        {
            "schema": "factory.workload-identity.v1",
            "tenant_id": "tenant-a",
            "workload_id": "proof-runner",
            "subject": "repo:example/app",
            "audience": "factoryline.enterprise",
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (issued_at + timedelta(minutes=15))
            .isoformat()
            .replace("+00:00", "Z"),
            "agent": AGENT,
            "allowed_action_classes": ["test"],
        },
    )
    policy_payload = _write(
        tmp_path / "policy.json",
        {
            "schema": "factory.enforcement-policy.v1",
            "policy_id": "repo-proof",
            "version": "1",
            "tenant_id": "tenant-a",
            "audience": "factoryline.enterprise",
            "allowed_action_classes": ["test"],
            "allowed_scope_paths": ["tests"],
            "require_semantic_lease": False,
        },
    )
    identity_out, policy_out = (
        tmp_path / "cli-identity.dsse.json",
        tmp_path / "cli-policy.dsse.json",
    )
    common = [
        "--private-key",
        keys["private_key"],
        "--keyid",
        keys["keyid"],
        "--identity",
        keys["identity"],
        "--issuer",
        keys["issuer"],
    ]
    assert (
        main(
            [
                "enterprise",
                "workload-identity-seal",
                str(identity_payload),
                *common,
                "--out",
                str(identity_out),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "enterprise",
                "enforcement-policy-seal",
                str(policy_payload),
                *common,
                "--out",
                str(policy_out),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "enterprise",
                "authorize",
                str(request_path),
                "--root",
                str(tmp_path),
                "--workload-identity",
                str(identity_out),
                "--policy",
                str(policy_out),
                "--trust-root",
                keys["trust_root"],
                "--out",
                ".factory/enterprise-enforcement/decisions/cli.json",
            ]
        )
        == 0
    )
    assert '"admitted": true' in capsys.readouterr().out


def test_runner_packet_binds_exact_admitted_decision_scope_and_argv(
    tmp_path: Path,
) -> None:
    keys, identity, policy, request = _materials(tmp_path)
    request["semantic_authority"] = _semantic_binding(tmp_path)
    recorded = record_enterprise_decision(
        tmp_path,
        request,
        Path(".factory/enterprise-enforcement/decisions/runner.json"),
        workload_identity_path=identity,
        policy_path=policy,
        trust_root_path=Path(keys["trust_root"]),
    )
    manifest = _write(
        tmp_path / "runner.json",
        {
            "schema": "factory.runner-admission-input.v1",
            "id": "restore-run",
            "decision": recorded["path"],
            "run_id": "run-001",
            "action_class": "test",
            "scope_paths": ["tests"],
            "argv": ["python", "-m", "pytest", "-q", "tests/test_restore.py"],
        },
    )
    packet = prepare_runner_admission(
        tmp_path,
        manifest,
        Path(".factory/enterprise-enforcement/runner-admissions/restore.json"),
    )
    assert packet["marker"] == "RUNNER_ADMISSION_PACKET_SEALED"
    assert packet["authority"]["execution"] is False
    assert packet["admission_expires_at"] == recorded["workload_identity"]["expires_at"]
    verified = verify_runner_admission_packet(tmp_path, Path(packet["path"]))
    assert verified["decision_sha256"] == recorded["decision_sha256"]
    assert verified["admission_expires_at"] == packet["admission_expires_at"]
    projection = runner_admission_projection(tmp_path)
    assert projection["verified_count"] == 1
    assert projection["fresh_count"] == 1
    assert projection["expired_count"] == 0
    assert all(value is False for value in projection["authority"].values())
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["enterprise_runner_verified_count"] == 1
    assert "enterprise_runner_admission" in {node["kind"] for node in snapshot["nodes"]}
    bad = _write(
        tmp_path / "bad-runner.json",
        {**json.loads(manifest.read_text(encoding="utf-8")), "scope_paths": ["src"]},
    )
    with pytest.raises(EnterpriseRunnerAdmissionError, match="E_RUNNER_SCOPE_MISMATCH"):
        prepare_runner_admission(
            tmp_path,
            bad,
            Path(".factory/enterprise-enforcement/runner-admissions/bad.json"),
        )


def test_runner_packet_fails_closed_when_identity_derived_admission_expires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import factoryline.enterprise_runner_admission as runner_module

    keys, identity, policy, request = _materials(tmp_path)
    request["semantic_authority"] = _semantic_binding(tmp_path)
    recorded = record_enterprise_decision(
        tmp_path,
        request,
        Path(".factory/enterprise-enforcement/decisions/freshness.json"),
        workload_identity_path=identity,
        policy_path=policy,
        trust_root_path=Path(keys["trust_root"]),
    )
    manifest = _write(
        tmp_path / "runner-freshness.json",
        {
            "schema": "factory.runner-admission-input.v1",
            "id": "freshness-run",
            "decision": recorded["path"],
            "run_id": "run-freshness",
            "action_class": "test",
            "scope_paths": ["tests"],
            "argv": ["python", "-m", "pytest", "-q"],
        },
    )
    packet = prepare_runner_admission(
        tmp_path,
        manifest,
        Path(".factory/enterprise-enforcement/runner-admissions/freshness.json"),
    )
    expired_now = _now() + timedelta(hours=2)
    with pytest.raises(
        EnterpriseRunnerAdmissionError, match="E_RUNNER_ADMISSION_EXPIRED"
    ):
        verify_runner_admission_packet(tmp_path, Path(packet["path"]), now=expired_now)
    monkeypatch.setattr(runner_module, "_now", lambda: expired_now)
    projection = runner_admission_projection(tmp_path)
    assert projection["verified_count"] == 0
    assert projection["fresh_count"] == 0
    assert projection["expired_count"] == 1
    assert projection["invalid_count"] == 0


def test_runner_packet_refuses_missing_or_changed_identity_expiry(
    tmp_path: Path,
) -> None:
    keys, identity, policy, request = _materials(tmp_path)
    request["semantic_authority"] = _semantic_binding(tmp_path)
    recorded = record_enterprise_decision(
        tmp_path,
        request,
        Path(".factory/enterprise-enforcement/decisions/expiry-binding.json"),
        workload_identity_path=identity,
        policy_path=policy,
        trust_root_path=Path(keys["trust_root"]),
    )
    manifest = _write(
        tmp_path / "runner-expiry-binding.json",
        {
            "schema": "factory.runner-admission-input.v1",
            "id": "expiry-binding",
            "decision": recorded["path"],
            "run_id": "run-expiry-binding",
            "action_class": "test",
            "scope_paths": ["tests"],
            "argv": ["python", "-m", "pytest", "-q"],
        },
    )
    packet = prepare_runner_admission(
        tmp_path,
        manifest,
        Path(".factory/enterprise-enforcement/runner-admissions/expiry-binding.json"),
    )
    path = tmp_path / packet["path"]
    value = json.loads(path.read_text(encoding="utf-8"))
    for changed, code in [
        ({"admission_expires_at": None}, "E_RUNNER_FRESHNESS_MISSING"),
        (
            {"admission_expires_at": "2030-01-01T00:00:00Z"},
            "E_RUNNER_FRESHNESS_MISMATCH",
        ),
    ]:
        candidate = {**value, **changed}
        unsigned = dict(candidate)
        unsigned.pop("packet_sha256", None)
        candidate["packet_sha256"] = hashlib.sha256(
            canonical_json(unsigned)
        ).hexdigest()
        path.write_text(json.dumps(candidate), encoding="utf-8")
        with pytest.raises(EnterpriseRunnerAdmissionError, match=code):
            verify_runner_admission_packet(tmp_path, Path(packet["path"]))


def test_runner_packet_refuses_action_shell_overwrite_and_path_escape(
    tmp_path: Path,
) -> None:
    from factoryline.cli import main

    keys, identity, policy, request = _materials(tmp_path)
    request["semantic_authority"] = _semantic_binding(tmp_path)
    recorded = record_enterprise_decision(
        tmp_path,
        request,
        Path(".factory/enterprise-enforcement/decisions/runner-refusal.json"),
        workload_identity_path=identity,
        policy_path=policy,
        trust_root_path=Path(keys["trust_root"]),
    )
    payload = {
        "schema": "factory.runner-admission-input.v1",
        "id": "refusal-run",
        "decision": recorded["path"],
        "run_id": "run-002",
        "action_class": "test",
        "scope_paths": ["tests"],
        "argv": ["python", "-m", "pytest", "-q"],
    }
    manifest = _write(tmp_path / "runner-refusal.json", payload)
    for changed, code in [
        ({"action_class": "repair"}, "E_RUNNER_ACTION_MISMATCH"),
        ({"argv": ["python", "&&", "pytest"]}, "E_RUNNER_COMMAND_INVALID"),
    ]:
        candidate = _write(tmp_path / f"{code}.json", {**payload, **changed})
        with pytest.raises(EnterpriseRunnerAdmissionError, match=code):
            prepare_runner_admission(
                tmp_path,
                candidate,
                Path(f".factory/enterprise-enforcement/runner-admissions/{code}.json"),
            )
    out = Path(".factory/enterprise-enforcement/runner-admissions/once.json")
    prepare_runner_admission(tmp_path, manifest, out)
    with pytest.raises(
        EnterpriseRunnerAdmissionError, match="E_RUNNER_ADMISSION_IMMUTABLE"
    ):
        prepare_runner_admission(tmp_path, manifest, out)
    with pytest.raises(EnterpriseRunnerAdmissionError, match="E_RUNNER_ADMISSION_PATH"):
        prepare_runner_admission(tmp_path, manifest, Path("runner-outside.json"))
    assert (
        main(
            [
                "enterprise",
                "runner-admission-seal",
                str(manifest),
                "--root",
                str(tmp_path),
                "--out",
                ".factory/enterprise-enforcement/runner-admissions/cli.json",
            ]
        )
        == 0
    )
    (
        tmp_path
        / ".factory"
        / "enterprise-enforcement"
        / "runner-admissions"
        / "malformed.json"
    ).write_text("{}", encoding="utf-8")
    assert runner_admission_projection(tmp_path)["invalid_count"] == 1


# Consolidated tests from tests/security_penetration/test_tenant_isolation.py


_REPO = Path(__file__).resolve().parents[1]
_TEST_PATH = "tests/test_enterprise_enforcement.py"
_SOURCE_PATHS = [
    "factoryline/audit_trace.py",
    "factoryline/control_plane.py",
    _TEST_PATH,
]


def _evidence(tenant: str) -> dict[str, str]:
    return {
        "schema": "factory.receipt.v2",
        "tenant_id": tenant,
        "subject_digest": "a" * 64,
        "policy_sha256": "b" * 64,
        "verdict": "VERIFIED",
        "stage": "compile",
    }


def _input_ref(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_cross_tenant_role_operation_matrix_is_denied_and_traced(
    tmp_path: Path, record_property: pytest.FixtureRequest
) -> None:
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    tenant_a = Principal("owner-a", "tenant-a", ("operator",))
    tenant_b_operator = Principal("owner-b", "tenant-b", ("operator",))
    evidence_a = store.put(tenant_a, _evidence("tenant-a"), evidence_id="a-record")
    evidence_b = store.put(
        tenant_b_operator, _evidence("tenant-b"), evidence_id="b-record"
    )
    request = store.request_approval(
        tenant_a, "tenant-a", evidence_a["evidence_id"], "boundary matrix"
    )
    rows: list[tuple[str, str, str]] = []

    for role in ("viewer", "operator", "approver"):
        principal = Principal(f"{role}-b", "tenant-b", (role,))
        attempts = {
            "read": lambda: store.get(principal, "tenant-a", evidence_a["evidence_id"]),
            "list": lambda: store.list(principal, "tenant-a"),
            "write": lambda: store.put(
                principal, _evidence("tenant-a"), evidence_id=f"cross-{role}"
            ),
            "approval_decide": lambda: store.decide_approval(
                principal,
                "tenant-a",
                request["approval_id"],
                "approved",
                "cross-tenant attempt",
            ),
        }
        for operation, attempt in attempts.items():
            with pytest.raises(ControlPlaneError) as denied:
                attempt()
            assert denied.value.code in {"E_TENANT_BOUNDARY", "E_ACTION_DENIED"}
            rows.append((role, operation, denied.value.code))

    assert len(rows) == 12
    assert [item["evidence_id"] for item in store.list(tenant_a, "tenant-a")] == [
        evidence_a["evidence_id"]
    ]
    assert [
        item["evidence_id"] for item in store.list(tenant_b_operator, "tenant-b")
    ] == [evidence_b["evidence_id"]]
    assert (
        store.get_approval(
            Principal("approver-a", "tenant-a", ("approver",)),
            "tenant-a",
            request["approval_id"],
        )["status"]
        == "pending"
    )

    trace = build_audit_trace(
        _REPO,
        changed_paths=_SOURCE_PATHS,
        lane_states={
            "authorization_tenant_isolation": "PASS",
        },
        steps=[
            {
                "step_id": f"{role}-{operation}",
                "input": _input_ref(f"{role}:{operation}:{code}"),
                "guard": "TENANT_ROLE_AUTHORIZATION",
                "decision": "DENY_CROSS_TENANT",
                "state": "PASS",
                "source_paths": ["factoryline/control_plane.py", _TEST_PATH],
            }
            for role, operation, code in rows
        ],
    )
    assert verify_audit_trace(trace) == {"valid": True, "errors": []}
    assert len(trace["steps"]) == 12
    assert all("tenant" not in step["input"] for step in trace["steps"])
    record_property("factoryline_audit_trace_id", trace["trace_id"])
    record_property("factoryline_audit_trace", json.dumps(trace, sort_keys=True))


# Consolidated tests from tests/test_attribution_security.py
"""Behavior-focused tests for security and admission APIs with weak attribution."""


def test_runtime_receipt_decision_rejects_incomplete_lanes() -> None:
    with pytest.raises(RuntimeAuditError) as error:
        validate_receipt_decision({})

    assert error.value.code == "E_RECEIPT_LANES"


def test_lane_policy_rejects_unknown_kind_before_execution() -> None:
    with pytest.raises(RuntimeAuditError) as error:
        validate_lane_policy("unrecognized", {})

    assert error.value.code == "E_LANES"


def test_counterexample_source_requires_exact_schema() -> None:
    with pytest.raises(CounterexampleError) as error:
        validate_counterexample_source({"schema": "wrong", "requirements": []})

    assert error.value.code == "COUNTEREXAMPLE_SOURCE_INVALID"


def test_guardrail_manifest_rejects_missing_scope_and_identity() -> None:
    with pytest.raises(GuardrailError) as error:
        validate_guardrail_manifest({"schema": "factory.guardrails.v1"})

    assert error.value.code == "GUARDRAIL_MANIFEST_INVALID"


def test_repair_scope_envelope_rejects_unsealed_empty_scope() -> None:
    with pytest.raises(RepairSandboxError) as error:
        validate_repair_scope_envelope({})

    assert error.value.code == "REPAIR_SCOPE_INVALID"
    assert "scope is missing required fields" in str(error.value)


def test_github_proof_review_payload_rejects_unbound_delivery_fields() -> None:
    with pytest.raises(GitHubProofReviewError) as error:
        validate_github_proof_review_payload({})

    assert error.value.code == "GITHUB_PROOF_REVIEW_INPUT_INVALID"


def test_plan_proof_review_requires_canonical_schema() -> None:
    with pytest.raises(PlanProofReviewError) as error:
        validate_plan_proof_review({"schema": "untrusted"})

    assert error.value.code == "PLAN_TO_PROOF_REVIEW_INVALID"


def test_oracle_incident_projection_is_empty_for_unmatched_identity(
    tmp_path: Path,
) -> None:
    result = oracle_incidents_for_agent(
        tmp_path,
        {"subject": "agent:reviewer", "identity_sha256": "a" * 64},
    )

    assert result == []


def test_oracle_admission_pauses_when_contract_is_missing(tmp_path: Path) -> None:
    with pytest.raises(OracleFirewallError) as error:
        admission_oracle_decision(
            tmp_path, tmp_path / "missing-contract.json", "supervised", []
        )

    assert error.value.code == "ORACLE_ADMISSION_PAUSED"


def test_promoted_incident_gate_reports_verified_empty_state_without_authority(
    tmp_path: Path,
) -> None:
    result = verify_promoted_incident_gates(tmp_path)

    assert result["state"] == "VERIFIED"
    assert result["verified"] == []
    assert result["invalid"] == []
    assert result["authority"] == "none"


def test_activation_receipt_fails_closed_when_absent(tmp_path: Path) -> None:
    result = verify_activation_receipt(tmp_path)

    assert result["state"] == "BLOCKED"
    assert result["code"] == "E_FIRST_LAP_ACTIVATION_MISSING"
    assert result["authority"] == "none"


def test_policy_mutations_cover_delete_and_boolean_inversion() -> None:
    mutations = policy_mutations({"rules": [{"id": "tenant-check", "enabled": True}]})

    assert {item["mutation"]["kind"] for item in mutations} == {"delete", "invert"}
    assert {item["mutation"]["rule_id"] for item in mutations} == {"tenant-check"}


def test_supply_chain_attestation_rejects_incomplete_manifest(tmp_path: Path) -> None:
    with pytest.raises(SupplyChainError) as error:
        validate_attestation(tmp_path, {})

    assert error.value.code == "E_FIELDS"


def test_capability_pack_payload_hashes_pack_files(tmp_path: Path) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir()
    manifest_path = pack_root / "pack.yaml"
    manifest_path.write_text(
        json.dumps({"id": "sample", "version": "1.2.3"}), encoding="utf-8"
    )

    payload = pack_payload(pack_root)

    assert payload["schema"] == "factory.capability_pack.payload.v1"
    assert payload["pack_id"] == "sample"
    assert payload["version"] == "1.2.3"
    assert (
        payload["files"]["pack.yaml"]
        == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    )


def test_capability_pack_signing_writes_dsse_for_canonical_payload(
    tmp_path: Path,
) -> None:
    pack_root = tmp_path / "pack"
    pack_root.mkdir()
    (pack_root / "pack.yaml").write_text(
        json.dumps({"id": "signed-sample", "version": "2.0.0"}), encoding="utf-8"
    )
    private_key_path = tmp_path / "signing-key.pem"
    private_key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    result = sign_pack(
        pack_root,
        private_key_path,
        keyid="test-key",
        identity="test-suite",
        issuer="local-test",
    )

    envelope_path = pack_root / "pack.signature.json"
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    assert Path(result["path"]) == envelope_path.resolve()
    assert (
        result["payload_sha256"]
        == hashlib.sha256(
            json.dumps(
                pack_payload(pack_root), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()
    )
    assert envelope["payloadType"] == "application/vnd.factory.capability-pack.v1+json"
    assert envelope["signatures"][0]["keyid"] == "test-key"


def test_mobile_evidence_verifier_reports_missing_receipt_for_review(
    tmp_path: Path,
) -> None:
    result = verify_mobile_evidence_receipt(tmp_path, tmp_path / "missing.json")

    assert result["ok"] is False
    assert result["marker"] == "APPFORGE_MOBILE_EVIDENCE_REVIEW_REQUIRED"
    assert result["reason"] == "input must be a regular workspace file"


def test_supervised_command_returns_exit_and_output_digests(tmp_path: Path) -> None:
    result = run_supervised_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('supervised-ok')"],
        cwd=tmp_path,
        timeout_seconds=5,
    )

    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert result["launch_error"] is False
    assert result["stdout_sha256"] == hashlib.sha256(b"supervised-ok").hexdigest()
    assert result["stderr_sha256"] == hashlib.sha256(b"").hexdigest()


def test_quality_audit_projection_returns_empty_read_only_state(tmp_path: Path) -> None:
    result = quality_audit_projection(tmp_path)

    assert result["marker"] == "APPFORGE_QUALITY_AUDIT_READ_ONLY"
    assert result["current_count"] == 0
    assert result["invalid_count"] == 0
    assert result["latest"] is None
    assert all(value is False for value in result["authority"].values())

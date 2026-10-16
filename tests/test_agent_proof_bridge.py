from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

import pytest

from factoryline.agent_proof_bridge import (
    BOUND_MARKER,
    MCP_MARKER,
    AgentProofBridgeError,
    agent_handoff_brief,
    agent_proof_projection,
    import_external_review_claims,
    import_agent_proof,
    _external_predicate_identity,
    provider_template,
    verify_agent_proof,
    _mark_external_case_outcome_conflicts,
)
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.oracle_firewall import capture_intent_handoff, seal_oracle_contract
from factoryline.semantic_authority import seal_authority_lease, seal_semantic_handoff
from test_intake_admission import _intake


AGENT = {
    "schema": "factory.agent-identity.v1",
    "subject": "portable-worker",
    "provider": "declared",
    "model": "declared-model",
}


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _contract(root: Path) -> Path:
    existing = root / ".factory" / "oracles" / "contracts" / "bridge-checkout.json"
    if existing.is_file():
        return existing
    intent = root / "briefs" / "intent.md"
    source = root / "src" / "checkout.py"
    intent.parent.mkdir(parents=True, exist_ok=True)
    source.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text(
        "Checkout completes valid orders and never exposes private account data.\n",
        encoding="utf-8",
    )
    source.write_text(
        "def checkout(order):\n    return bool(order)\n", encoding="utf-8", newline="\n"
    )
    handoff = capture_intent_handoff(
        root,
        intent,
        AGENT,
        "bridge-intake",
        Path(".factory/oracles/handoffs/bridge-intake.json"),
    )
    payload = {
        "schema": "factory.oracle-contract-input.v1",
        "id": "bridge-checkout",
        "version": 1,
        "approved_by": "Release Owner",
        "approval_rationale": "Original intent and negative boundary reviewed.",
        "scope_paths": ["src"],
        "handoff": handoff["path"],
        "sources": [],
        "requirements": [
            {
                "id": "complete",
                "statement": "Valid checkout completes.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "forbidden_behaviors": [
            {
                "id": "private",
                "statement": "Private account data is never exposed.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "gates": [
            {
                "id": "quality",
                "statement": "Quality reaches approved threshold.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "comparison": "gte",
                "value": 95,
            }
        ],
        "exceptions": [
            {
                "id": "offline",
                "statement": "Offline evidence remains advisory until review.",
                "origin": "human_confirmed",
                "effect": "advisory",
                "source_id": "original-intent",
                "critical": False,
            }
        ],
        "negative_cases": [
            {
                "id": "bad-order",
                "statement": "Invalid order does not complete.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "invariants": [
            {
                "id": "scope",
                "statement": "Only sealed scope changes.",
                "origin": "trusted_source",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
            }
        ],
        "tests": [
            {
                "id": "checkout-test",
                "statement": "Rejected-order path is tested.",
                "origin": "human_confirmed",
                "effect": "blocking",
                "source_id": "original-intent",
                "critical": True,
                "path": "tests/test_checkout.py",
            }
        ],
    }
    return (
        root
        / seal_oracle_contract(
            root,
            _write(root / "oracle-input.json", payload),
            Path(".factory/oracles/contracts/bridge-checkout.json"),
        )["path"]
    )


def _workflow() -> dict[str, object]:
    nodes = [
        {"id": "plan", "kind": "planner"},
        {"id": "build", "kind": "worker"},
        {"id": "verify", "kind": "validator"},
    ]
    edges = [{"from": "plan", "to": "build"}, {"from": "build", "to": "verify"}]
    return {
        "id": "portable-checkout",
        "definition_sha256": _digest("definition"),
        "topology_sha256": _sha(
            {
                "nodes": sorted(nodes, key=lambda item: item["id"]),
                "edges": sorted(edges, key=lambda item: (item["from"], item["to"])),
            }
        ),
        "nodes": nodes,
        "edges": edges,
    }


def _profile(provider: str) -> dict[str, object]:
    value: dict[str, object] = {
        "session_id": "session-1",
        "runtime_sha256": _digest("runtime"),
        "tool_manifest_sha256": _digest("tools"),
    }
    if provider == "eve":
        value.update(
            {
                "workflow_id": "eve-flow",
                "checkpoint_id": "checkpoint-1",
                "checkpoint_sha256": _digest("checkpoint-1"),
                "deployment_commit_sha": "a" * 40,
            }
        )
    elif provider == "junie":
        value.update(
            {
                "mission_sha256": _digest("mission"),
                "action_policy_sha256": _digest("actions"),
                "change_list_sha256": _digest("change-list"),
            }
        )
    elif provider == "grok_build":
        value.update(
            {
                "stream_sha256": _digest("stream"),
                "mode": "headless",
                "permission_policy_sha256": _digest("policy"),
            }
        )
    elif provider == "coderabbit":
        value.update(
            {
                "review_output_sha256": _digest("review-jsonl"),
                "review_mode": "agent",
                "base_commit_sha": "b" * 40,
                "head_commit_sha": "c" * 40,
                "finding_count": 2,
            }
        )
    elif provider == "devin":
        value.update(
            {
                "task_sha256": _digest("task"),
                "result_sha256": _digest("result"),
                "base_commit_sha": "d" * 40,
                "head_commit_sha": "e" * 40,
                "permission_profile_sha256": _digest("permissions"),
            }
        )
    return value


def _envelope(
    root: Path, *, provider: str = "eve", run_id: str = "run-1", surface: str = "visual"
) -> dict[str, object]:
    contract = _contract(root)
    value = json.loads(contract.read_text(encoding="utf-8"))
    before, after = (
        root / ".factory" / "evidence" / f"{run_id}-before.txt",
        root / ".factory" / "evidence" / f"{run_id}-after.txt",
    )
    before.parent.mkdir(parents=True, exist_ok=True)
    before.write_text("before\n", encoding="utf-8")
    after.write_text("after\n", encoding="utf-8")
    return {
        "schema": "factory.agent-proof-envelope.v1",
        "envelope_id": f"envelope-{run_id}",
        "provider": provider,
        "run_id": run_id,
        "status": "completed",
        "agent": AGENT,
        "autonomy": "supervised",
        "isolation": "declared_worktree",
        "scope_paths": ["src"],
        "surface": surface,
        "oracle": {
            "contract_path": contract.relative_to(root).as_posix(),
            "contract_sha256": value["contract_sha256"],
        },
        "workflow": _workflow(),
        "source_preconditions": [
            {
                "path": "src/checkout.py",
                "sha256": _digest("def checkout(order):\n    return bool(order)\n"),
            }
        ],
        "evidence_pairs": [
            {
                "id": "before-after",
                "kind": "visual" if surface == "visual" else "logic",
                "before_path": before.relative_to(root).as_posix(),
                "after_path": after.relative_to(root).as_posix(),
                "before_sha256": hashlib.sha256(before.read_bytes()).hexdigest(),
                "after_sha256": hashlib.sha256(after.read_bytes()).hexdigest(),
                "claim_sha256": _digest("claim"),
            }
        ],
        "provider_receipt": _profile(provider),
    }


def _import(
    root: Path, envelope: dict[str, object], filename: str = "envelope.json"
) -> dict[str, object]:
    source = _write(root / filename, envelope)
    return import_agent_proof(root, source.relative_to(root))


def _semantic_binding(root: Path, suffix: str = "bridge") -> dict[str, str]:
    contract = _contract(root)
    contract_value = json.loads(contract.read_text(encoding="utf-8"))
    handoff_input = _write(
        root / "semantic-handoff-input.json",
        {
            "schema": "factory.semantic-handoff-input.v1",
            "id": "bridge-handoff",
            "oracle_contract": contract.relative_to(root).as_posix(),
            "sender": AGENT,
            "receiver": AGENT,
            "performative": "REQUEST",
            "goal": "Inspect the exact checkout evidence envelope.",
            "context_urn": "urn:factory:checkout:v1",
            "context_source_id": "original-intent",
            "scope_paths": ["src"],
            "allowed_actions": ["inspect"],
            "epistemic": {
                "known": [
                    {
                        "id": "intent",
                        "statement": "The source-bound contract forbids private-data exposure.",
                        "source_id": "original-intent",
                    }
                ],
                "unknown": [
                    {
                        "id": "provider",
                        "statement": "Provider runtime state is not in the local receipt.",
                        "impact": "No provider claim.",
                        "blocking": False,
                    }
                ],
                "uncertain": [
                    {
                        "id": "sandbox",
                        "statement": "Declared isolation is not verified sandbox proof.",
                        "impact": "Keep runtime proof separate.",
                    }
                ],
                "capability_limits": [
                    "This local envelope reader cannot call the provider or release code."
                ],
            },
        },
    )
    handoff = seal_semantic_handoff(
        root, handoff_input, Path(f".factory/semantic-authority/handoffs/{suffix}.json")
    )
    lease_input = _write(
        root / "semantic-lease-input.json",
        {
            "schema": "factory.authority-lease-input.v1",
            "id": "bridge-lease",
            "handoff": handoff["path"],
            "delegatee": AGENT,
            "scope_paths": ["src"],
            "allowed_actions": ["inspect"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30))
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "approval_origin": "human_confirmed",
            "approved_by": "Release Owner",
            "rationale": "Bound evidence intake only.",
        },
    )
    lease = seal_authority_lease(
        root, lease_input, Path(f".factory/semantic-authority/leases/{suffix}.json")
    )
    assert (
        lease["handoff"]["oracle_contract_sha256"] == contract_value["contract_sha256"]
    )
    return {
        "lease_path": lease["path"],
        "lease_sha256": lease["lease_sha256"],
        "action_id": "inspect-envelope",
        "action": "inspect",
        "context_urn": "urn:factory:checkout:v1",
    }


@pytest.mark.parametrize(
    "provider", ["eve", "junie", "grok_build", "coderabbit", "devin", "generic"]
)
def test_profiles_bind_hash_only_portable_evidence(
    provider: str, tmp_path: Path
) -> None:
    receipt = _import(tmp_path, _envelope(tmp_path, provider=provider))
    assert receipt["marker"] == BOUND_MARKER
    assert receipt["provider"] == provider
    assert all(value is False for value in receipt["authority"].values())
    assert verify_agent_proof(tmp_path, Path(receipt["path"]))["ok"] is True
    projection = agent_proof_projection(tmp_path)
    assert projection["marker"] == MCP_MARKER
    assert projection["providers"][provider] == 1


def test_bridge_can_require_an_authoritative_intake_binding(tmp_path: Path) -> None:
    intake_path, _ = _intake(tmp_path, scope=["src"])
    intake = json.loads(intake_path.read_text(encoding="utf-8"))
    envelope = _envelope(tmp_path, provider="junie", run_id="intake-bound")
    envelope["intake_parameters"] = {
        "path": intake_path.relative_to(tmp_path).as_posix(),
        "parameter_sha256": intake["parameter_sha256"],
    }

    receipt = _import(tmp_path, envelope, "intake-bound.json")

    assert (
        receipt["intake_parameters"]["parameter_sha256"] == intake["parameter_sha256"]
    )
    assert verify_agent_proof(tmp_path, Path(receipt["path"]))["ok"] is True


def test_bridge_rejects_advisory_intake_binding(tmp_path: Path) -> None:
    intake_path, _ = _intake(tmp_path, scope=["src"], advisory=True)
    intake = json.loads(intake_path.read_text(encoding="utf-8"))
    envelope = _envelope(tmp_path, provider="junie", run_id="advisory-intake")
    envelope["intake_parameters"] = {
        "path": intake_path.relative_to(tmp_path).as_posix(),
        "parameter_sha256": intake["parameter_sha256"],
    }

    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope, "advisory-intake.json")
    assert raised.value.code == "E_INTAKE_BINDING_ADVISORY"


def test_graph_ops_projects_agent_bridge_as_read_only_handoff_evidence(
    tmp_path: Path,
) -> None:
    _import(tmp_path, _envelope(tmp_path, provider="junie"))

    snapshot = graph_ops_snapshot(tmp_path)

    assert snapshot["agent_proof_bridge"]["bound_count"] == 1
    assert snapshot["facts"]["agent_bridge_bound_count"] == 1
    assert "GRAPH_OPS_AGENT_PROOF_BRIDGE_READ_ONLY" in snapshot["markers"]
    kinds = {node["kind"] for node in snapshot["nodes"]}
    assert {
        "agent_contract",
        "agent_provider",
        "agent_workflow",
        "agent_run",
        "agent_evidence",
    } <= kinds
    assert all(
        node["facts"]["authority"]["execution"] is False
        for node in snapshot["nodes"]
        if node["kind"].startswith("agent_")
    )


def test_agent_bridge_can_bind_imported_evidence_to_an_active_semantic_lease(
    tmp_path: Path,
) -> None:
    envelope = _envelope(tmp_path, provider="junie")
    envelope["semantic_authority"] = _semantic_binding(tmp_path)
    receipt = _import(tmp_path, envelope)
    assert receipt["semantic_authority"]["bound"] is True
    assert agent_proof_projection(tmp_path)["semantic_authority_bound_count"] == 1

    invalid = _envelope(tmp_path, provider="junie", run_id="invalid")
    binding = _semantic_binding(tmp_path, "invalid")
    binding["action"] = "repair"
    invalid["semantic_authority"] = binding
    with pytest.raises(AgentProofBridgeError) as rejected:
        _import(tmp_path, invalid, "invalid-semantic.json")
    assert rejected.value.code == "E_AGENT_BRIDGE_SEMANTIC_AUTHORITY"


def test_agent_bridge_rejects_a_receipt_when_its_semantic_lease_is_expired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path, provider="junie")
    envelope["semantic_authority"] = _semantic_binding(tmp_path)
    receipt = _import(tmp_path, envelope)
    assert verify_agent_proof(tmp_path, Path(receipt["path"]))["ok"] is True
    import factoryline.semantic_authority as semantic_module

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    monkeypatch.setattr(semantic_module, "_now", lambda: future)
    checked = verify_agent_proof(tmp_path, Path(receipt["path"]))
    assert checked["ok"] is False
    assert checked["reason"] == "semantic_authority_stale"


def test_bridge_fails_closed_for_private_content_scope_and_visual_proof_gaps(
    tmp_path: Path,
) -> None:
    envelope = _envelope(tmp_path)
    envelope["raw_prompt"] = "not allowed"
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_PRIVATE_FIELD"

    envelope = _envelope(tmp_path)
    envelope["scope_paths"] = ["admin"]
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_SCOPE_ESCAPE"

    envelope = _envelope(tmp_path)
    envelope["evidence_pairs"][0]["kind"] = "logic"
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED"
    assert not (tmp_path / ".factory" / "agent-bridges").exists()


def test_bridge_rejects_missing_or_hash_mismatched_before_after_artifacts(
    tmp_path: Path,
) -> None:
    envelope = _envelope(tmp_path)
    envelope["evidence_pairs"][0]["after_path"] = "evidence/missing.png"
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED"

    envelope = _envelope(tmp_path, run_id="changed")
    (tmp_path / envelope["evidence_pairs"][0]["after_path"]).write_text(
        "tampered\n", encoding="utf-8"
    )
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, envelope)
    assert raised.value.code == "E_AGENT_BRIDGE_EVIDENCE_UNVERIFIED"


def test_eve_resume_requires_exact_provider_checkpoint_and_oracle_binding(
    tmp_path: Path,
) -> None:
    first = _import(
        tmp_path, _envelope(tmp_path, provider="eve", run_id="run-1"), "first.json"
    )
    resumed = _envelope(tmp_path, provider="eve", run_id="run-2")
    profile = resumed["provider_receipt"]
    resumed["resume"] = {
        "prior_receipt": first["path"],
        "prior_run_id": "run-1",
        "checkpoint_id": profile["checkpoint_id"],
        "checkpoint_sha256": profile["checkpoint_sha256"],
        "provider_receipt_sha256": _sha(first["provider_receipt"]),
    }
    receipt = _import(tmp_path, resumed, "resumed.json")
    assert receipt["resume"]["recovery_action"] == "human_reviewed_fork"

    divergent = copy.deepcopy(resumed)
    divergent["run_id"] = "run-3"
    divergent["envelope_id"] = "envelope-run-3"
    divergent["resume"]["checkpoint_sha256"] = _digest("other")
    with pytest.raises(AgentProofBridgeError) as raised:
        _import(tmp_path, divergent, "divergent.json")
    assert raised.value.code == "E_AGENT_BRIDGE_RESUME_DIVERGENCE"


def test_templates_are_secret_free_and_no_provider_runtime_dependency() -> None:
    for provider in ("eve", "junie", "grok_build", "coderabbit", "devin", "generic"):
        template = provider_template(provider)
        assert template["provider"] == provider
        assert all(value is False for value in template["authority"].values())
    source = (
        Path(__file__).parents[1] / "factoryline" / "agent_proof_bridge.py"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "import subprocess",
        "import requests",
        "import httpx",
        "import socket",
    ):
        assert forbidden not in source


def test_handoff_brief_replays_sealed_intent_for_worker_and_human_without_authority(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    brief = agent_handoff_brief(tmp_path, contract.relative_to(tmp_path))

    assert brief["marker"] == "AGENT_HANDOFF_BRIEF_READ_ONLY"
    assert (
        brief["contract"]["contract_sha256"]
        == json.loads(contract.read_text(encoding="utf-8"))["contract_sha256"]
    )
    assert brief["intended_outcomes"][0]["id"] == "complete"
    assert brief["forbidden_outcomes"][0]["id"] == "private"
    assert brief["negative_cases"][0]["id"] == "bad-order"
    assert all(value is False for value in brief["authority"].values())


@pytest.mark.parametrize("provider", ["CodeRabbit", "Devin", "Blitzy"])
def test_local_review_claims_preserve_provenance_and_only_normalize_claims(
    tmp_path: Path, provider: str
) -> None:
    source = tmp_path / "src" / "checkout.py"
    source.parent.mkdir()
    source.write_text("def checkout(): return True\n", encoding="utf-8")
    source_sha = _digest(source.read_text(encoding="utf-8"))
    repeated = {
        "source_path": "src/checkout.py",
        "source_sha256": source_sha,
        "rule": "RISK-1",
        "statement": "Checkout omits a required guard.",
        "claim_type": "unsupported_prose",
        "case_binding": None,
        "evidence_refs": [{"path": "evidence/fake.json", "sha256": "a" * 64}],
    }
    report = _write(
        tmp_path / "review.json",
        {
            "schema": "factory.external-review-claims.input.v1",
            "provider": provider,
            "claims": [
                {
                    **repeated,
                    "external_id": "issue-a",
                    "claimed_disposition": "confirmed",
                },
                {
                    **repeated,
                    "external_id": "issue-b",
                    "claimed_disposition": "rejected",
                },
            ],
        },
    )
    receipt = import_external_review_claims(
        report.relative_to(tmp_path).as_posix(), tmp_path, "normalized.json"
    )

    assert receipt["provider"] == provider.casefold()
    assert receipt["provider_label"] == provider
    assert receipt["provider_identity"] == "declared label only; not authenticated"
    assert (
        receipt["report"]["sha256"] == hashlib.sha256(report.read_bytes()).hexdigest()
    )
    assert len(receipt["findings"]) == 1
    finding = receipt["findings"][0]
    assert finding["disposition"] == "unverified"
    assert finding["disagreement"] is True
    assert finding["claimed_dispositions"] == ["confirmed", "rejected"]
    assert {row["external_id"] for row in finding["occurrences"]} == {
        "issue-a",
        "issue-b",
    }
    assert all(row["disposition"] == "unverified" for row in finding["occurrences"])
    assert all(
        row["claimed_evidence_refs"][0]["sha256"] == "a" * 64
        for row in finding["occurrences"]
    )
    assert (tmp_path / "normalized.json").is_file()
    existing = tmp_path / "preserve.json"
    existing.write_bytes(b"existing evidence\n")
    with pytest.raises(AgentProofBridgeError, match="new workspace file"):
        import_external_review_claims(
            report.relative_to(tmp_path).as_posix(),
            tmp_path,
            existing.relative_to(tmp_path).as_posix(),
        )
    assert existing.read_bytes() == b"existing evidence\n"


def test_local_review_claims_enforce_report_and_item_limits(tmp_path: Path) -> None:
    report = _write(
        tmp_path / "too-many.json",
        {
            "schema": "factory.external-review-claims.input.v1",
            "provider": "Blitzy",
            "claims": [{}] * 65,
        },
    )
    with pytest.raises(AgentProofBridgeError, match="0-64 entries"):
        import_external_review_claims(
            report.relative_to(tmp_path).as_posix(), tmp_path, "normalized.json"
        )
    large_report = tmp_path / "large.json"
    large_report.write_bytes(b" " * (1_048_577))
    with pytest.raises(AgentProofBridgeError, match="exceeds 1 MiB"):
        import_external_review_claims("large.json", tmp_path, "normalized.json")


def test_case_outcome_conflicts_link_only_the_same_native_case() -> None:
    def finding(
        finding_id: str, case_id: str, outcome: str, mission_sha256: str = "a" * 64
    ) -> dict[str, object]:
        return {
            "finding_id": finding_id,
            "case_predicate": {
                "mission_id": "mission-1",
                "mission_sha256": mission_sha256,
                "candidate_sha256": "b" * 64,
                "criterion_id": "gate:unit",
                "case_id": case_id,
                "polarity": "positive",
                "observed_outcome": outcome,
            },
            "case_outcome_disagreement": False,
        }

    reproduced = finding(
        "reproduced", "case-1", "baseline_assertion_pass_mutant_assertion_fail"
    )
    contradicted = finding(
        "contradicted", "case-1", "baseline_assertion_pass_mutant_assertion_pass"
    )
    separate_case = finding(
        "separate-case", "case-2", "baseline_assertion_pass_mutant_assertion_pass"
    )
    separate_revision = finding(
        "separate-revision",
        "case-1",
        "baseline_assertion_pass_mutant_assertion_pass",
        mission_sha256="c" * 64,
    )
    identity = _external_predicate_identity(
        {
            "claim_type": "declared_case_outcome",
            "case_binding": reproduced["case_predicate"],
        }
    )

    findings = _mark_external_case_outcome_conflicts(
        [reproduced, contradicted, separate_case, separate_revision]
    )

    assert findings[0]["case_outcome_disagreement"] is True
    assert findings[0]["case_outcome_conflicts_with"] == ["contradicted"]
    assert findings[1]["case_outcome_disagreement"] is True
    assert findings[1]["case_outcome_conflicts_with"] == ["reproduced"]
    assert identity["mission_sha256"] == "a" * 64
    assert all(
        row["case_outcome_disagreement"] is False
        and row.get("case_outcome_conflicts_with", []) == []
        for row in findings[2:]
    )


def test_local_review_claim_verdict_binds_a_current_native_case(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from factoryline import product_missions
    from factoryline.product_missions import (
        close_mission,
        compile_product_prd,
        create_mission,
    )
    from factoryline.pytest_readiness import (
        _challenge_source_inventory,
        main as probe_main,
    )
    from test_product_missions import (
        _local_mutation_daily_contract,
        _validation_for,
    )

    root = tmp_path / "workspace"
    root.mkdir()
    prd = root / "PRD.md"
    prd.write_text(
        "# Record Service\n\n## Actors\n- Record service: serializes records.\n\n"
        "## Outcomes\n- Produce a stable record.\n\n## Jobs and pains\n"
        "- Job: serialize a record.\n\n## Journeys and business rules\n"
        "- Journey: serialize a record with identity, state, and trace.\n"
        "- Business rule: identity and trace remain stable.\n\n"
        "## Data ownership and trust boundaries\n- Data ownership: service.\n"
        "- Trust boundary: record input remains local.\n\n"
        "## External effects and approvals\n- External effect: none.\n- Approval: none.\n\n"
        "## Success events\n- record_serialized.\n\n## Requirements\n"
        "- REQ-RECORD: The service shall return a record with a stable identity.\n\n"
        "## Acceptance\nScenario: Serialize a stable record\n"
        "  Given a signal record\n  When the service serializes it\n"
        "  Then identity, state, and trace are present\n",
        encoding="utf-8",
    )
    graph = compile_product_prd(prd, root, project="record-service")
    slices = product_missions.plan_value_slices(Path(graph["path"]), root, 1)
    mission = create_mission(
        Path(slices["path"]), slices["slices"][0]["id"], root, "owner"
    )
    production = root / "app.py"
    test_file = root / "test_app.py"
    production.write_text(
        'def value():\n    return {"record_id": "signal-17", "state": "ready", "trace": "trace-1"}\n\n'
        "def healthy_control():\n    return True\n",
        encoding="utf-8",
    )
    assertions = {
        "requirement:REQ-RECORD": 'assert app.value()["record_id"] == "signal-17"',
        "acceptance:AC-001": 'assert app.value() == {"record_id": "signal-17", "state": "ready", "trace": "trace-1"}',
        "gate:unit": 'assert isinstance(app.value(), dict) and set(app.value()) == {"record_id", "state", "trace"} and app.value()["record_id"] == "signal-17"',
        "gate:requirement-mutation": 'assert app.value()["state"] == "ready"',
        "gate:receipt-trace": 'assert app.value()["trace"] == "trace-1"',
    }
    lines = ["import app", ""]
    selectors = []
    for index, criterion in enumerate(mission["completion_contract"]["criteria"]):
        target_name, control_name = f"test_target_{index}", f"test_control_{index}"
        target_line = len(lines) + 2
        lines.extend(
            [f"def {target_name}():", f"    {assertions[criterion['id']]}", ""]
        )
        control_line = len(lines) + 2
        lines.extend([f"def {control_name}():", "    assert app.healthy_control()", ""])
        selectors.append(
            (criterion["id"], target_name, target_line, control_name, control_line)
        )
    test_file.write_text("\n".join(lines), encoding="utf-8")
    source_map = _challenge_source_inventory(root)
    source_rows = [
        {"path": key, "sha256": value} for key, value in sorted(source_map.items())
    ]
    candidate_sha = product_missions._sha_bytes(
        product_missions._canonical(source_rows)
    )
    input_paths = ["app.py", "test_app.py"]
    input_sha = product_missions._sha_bytes(
        product_missions._canonical(
            [{"path": path, "sha256": source_map[path]} for path in input_paths]
        )
    )
    daily = _local_mutation_daily_contract(
        mission, source_rows, candidate_sha, input_paths, input_sha
    )
    daily_path = root / "daily.json"
    daily_path.write_text(json.dumps(daily), encoding="utf-8")
    for index, (criterion, target, target_line, control, control_line) in enumerate(
        selectors
    ):
        rc = probe_main(
            [
                "--root",
                str(root),
                "--kind",
                "production-mutation",
                "--nodeid",
                f"test_app.py::{target}",
                "--line",
                str(target_line),
                "--production-path",
                "app.py",
                "--production-symbol",
                "value",
                "--mutation-before",
                'return {"record_id": "signal-17", "state": "ready", "trace": "trace-1"}',
                "--mutation-after",
                'return {"record_id": "signal-0", "state": "broken", "trace": "trace-0"}',
                "--evidence",
                f".factory/local-capture/case-{index}",
                "--mission-path",
                mission["path"],
                "--daily-contract",
                str(daily_path),
                "--criterion-id",
                criterion,
                "--target-case-id",
                f"{criterion}:positive",
                "--control-nodeid",
                f"test_app.py::{control}",
                "--control-line",
                str(control_line),
                "--control-case-id",
                f"{criterion}:negative",
                "--timeout",
                "20",
                "--python",
                sys.executable,
            ]
        )
        captured = capsys.readouterr().out
        assert rc == 0, captured
        assert json.loads(captured)["status"] == "OBSERVED"
    validation_evidence = _write(root / "validation.json", {"passed": True})
    validation = _validation_for(mission, "worker", "verifier", validation_evidence)
    current_daily = json.loads(daily_path.read_text(encoding="utf-8"))
    criteria_by_id = {row["criterion_id"]: row for row in current_daily["criteria"]}
    for row in validation["criteria"]:
        positive = next(
            case
            for case in criteria_by_id[row["id"]]["cases"]
            if case["polarity"] == "positive"
        )
        row["evidence"] = [str(root / positive["evidence"]["path"])]
    validation["daily_verification"] = current_daily
    validation_path = _write(root / "validation-with-cases.json", validation)
    completion = close_mission(Path(mission["path"]), validation_path, root)
    completion_path = Path(completion["path"])
    verified = product_missions.verify_mission_completion(completion_path)
    assert verified["complete"] is True
    case = next(
        row
        for row in verified["daily_verification"]["criteria"]
        if row["criterion_id"] == "gate:unit"
    )["cases"][0]
    source_sha = hashlib.sha256(production.read_bytes()).hexdigest()
    binding = {
        "completion_path": completion_path.relative_to(root).as_posix(),
        "completion_sha256": hashlib.sha256(completion_path.read_bytes()).hexdigest(),
        "mission_id": mission["id"],
        "mission_sha256": next(
            row["native_gate_observation"]["mission_sha256"]
            for row in verified["daily_verification"]["criteria"]
            if row["criterion_id"] == "gate:unit"
        ),
        "candidate_sha256": candidate_sha,
        "criterion_id": "gate:unit",
        "case_id": case["case_id"],
        "polarity": case["polarity"],
        "observed_outcome": case["observed_outcome"],
    }
    claims = []
    for external_id, statement, outcome in (
        ("matched", "Unit case outcome is recorded.", case["observed_outcome"]),
        (
            "mismatched",
            "A conflicting case outcome was reported.",
            "baseline_assertion_pass_mutant_assertion_pass",
        ),
        ("stale", "A stale completion must remain unknown.", case["observed_outcome"]),
        (
            "arbitrary-hash",
            "A supplied arbitrary hash is not proof.",
            case["observed_outcome"],
        ),
        ("prose", "The checkout is generally safe.", None),
        (
            "same-prose-matched-case",
            "The checkout is generally safe.",
            case["observed_outcome"],
        ),
        (
            "same-prose-other-case",
            "The checkout is generally safe.",
            case["observed_outcome"],
        ),
    ):
        claims.append(
            {
                "external_id": external_id,
                "source_path": "app.py",
                "source_sha256": source_sha,
                "rule": "RISK-CASE",
                "statement": statement,
                "claimed_disposition": "supported",
                "claim_type": "declared_case_outcome"
                if outcome is not None
                else "prose",
                "case_binding": {**binding, "observed_outcome": outcome}
                if outcome is not None
                else None,
                "evidence_refs": (
                    [{"path": "evidence/opaque.json", "sha256": "b" * 64}]
                    if external_id == "arbitrary-hash"
                    else []
                ),
            }
        )
    next(claim for claim in claims if claim["external_id"] == "same-prose-other-case")[
        "case_binding"
    ]["case_id"] = "different-native-case"
    next(claim for claim in claims if claim["external_id"] == "stale")["case_binding"][
        "completion_sha256"
    ] = "c" * 64
    report = _write(
        root / "review.json",
        {
            "schema": "factory.external-review-claims.input.v1",
            "provider": "Devin",
            "claims": claims,
        },
    )
    completion_bytes = completion_path.read_bytes()
    with pytest.raises(AgentProofBridgeError, match="new workspace file"):
        import_external_review_claims(
            report.relative_to(root).as_posix(),
            root,
            completion_path.relative_to(root).as_posix(),
        )
    assert completion_path.read_bytes() == completion_bytes
    assert (
        product_missions.verify_mission_completion(completion_path)["complete"] is True
    )
    receipt = import_external_review_claims(
        report.relative_to(root).as_posix(), root, "normalized.json"
    )
    statuses = {row["statement"]: row["disposition"] for row in receipt["findings"]}
    assert statuses["Unit case outcome is recorded."] == "unverified"
    assert statuses["A conflicting case outcome was reported."] == "unverified"
    assert statuses["A stale completion must remain unknown."] == "unverified"
    assert statuses["A supplied arbitrary hash is not proof."] == "unverified"
    assert statuses["The checkout is generally safe."] == "unverified"
    general = [
        row
        for row in receipt["findings"]
        if row["statement"] == "The checkout is generally safe."
    ]
    assert len(general) == 3
    prose_only = next(row for row in general if row["case_predicate"] is None)
    assert prose_only["disposition"] == "unverified"
    matched_case = next(
        row
        for row in general
        if row["case_predicate"] is not None
        and row["case_predicate"]["case_id"] == case["case_id"]
    )
    assert matched_case["disposition"] == "unverified"
    assert matched_case["occurrences"][0]["disposition"] == "unverified"
    assert (
        matched_case["occurrences"][0]["case_outcome_assessment"]["disposition"]
        == "reproduced"
    )
    assert matched_case["case_predicate"] == {
        "mission_id": mission["id"],
        "mission_sha256": binding["mission_sha256"],
        "candidate_sha256": candidate_sha,
        "criterion_id": "gate:unit",
        "case_id": case["case_id"],
        "polarity": case["polarity"],
        "observed_outcome": case["observed_outcome"],
    }
    mismatch = next(
        row
        for row in receipt["findings"]
        if row["statement"] == "A conflicting case outcome was reported."
    )
    assert (
        mismatch["occurrences"][0]["case_outcome_assessment"]["disposition"]
        == "contradicted"
    )
    other_case = next(
        row
        for row in general
        if row["case_predicate"] is not None
        if row["case_predicate"]["case_id"] == "different-native-case"
    )
    assert other_case["disagreement"] is False
    assert other_case["occurrences"][0]["case_outcome_assessment"]["disposition"] == (
        "unverified"
    )

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from factoryline.agent_license import derive_license
from factoryline.oracle_firewall import (
    OracleFirewallError,
    capture_intent_handoff,
    compare_oracle_contracts,
    compile_oracle_challenge,
    initialize_oracle_firewall,
    oracle_firewall_projection,
    record_oracle_incident,
    seal_oracle_contract,
    verify_intent_handoff,
    verify_oracle_challenge_result,
    verify_oracle_contract,
)


AGENT = {"schema": "factory.agent-identity.v1", "subject": "worker-alpha", "provider": "local", "model": "model-a"}


@pytest.mark.parametrize("mutation", ["gates", "provenance", "sources", "duplicate", "original", "groups"])
def test_rehashed_contract_must_still_obey_constructor_rules(tmp_path, mutation):
    from factoryline.oracle_firewall import _hash_receipt
    path = _contract(tmp_path)
    payload = json.loads(path.read_text())
    if mutation == "gates": payload["rules"]["gates"] = []
    elif mutation == "provenance": payload["rules"]["gates"][0]["origin"] = "agent_proposed"
    elif mutation == "sources": payload["sources"] = []
    elif mutation == "duplicate": payload["sources"].append(dict(payload["sources"][0]))
    elif mutation == "original": payload["sources"][0]["id"] = "replacement"
    else: payload["rules"].pop("tests")
    payload.pop("contract_sha256")
    _write(path, _hash_receipt(payload, "contract_sha256"))
    assert verify_oracle_contract(tmp_path, path)["ok"] is False


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    return path


def _handoff(root: Path) -> Path:
    intent = root / "briefs" / "original-intent.md"
    intent.parent.mkdir(parents=True, exist_ok=True)
    intent.write_text("Users must be able to restore a subscription without a new purchase.\n", encoding="utf-8")
    result = capture_intent_handoff(root, intent, AGENT, "ios-intake", Path(".factory/oracles/handoffs/ios-intake.json"))
    return root / result["path"]


def _input(root: Path, handoff: Path, *, threshold: int = 95, include_negative: bool = True, exception_effect: str = "advisory") -> Path:
    rules = {
        "requirements": [{"id": "restore", "statement": "Restore succeeds for an entitled account.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "forbidden_behaviors": [{"id": "double-charge", "statement": "A restore must not create another charge.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "gates": [{"id": "restore-rate", "statement": "Restore evidence rate is at least the approved floor.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "comparison": "gte", "value": threshold}],
        "exceptions": [{"id": "offline-note", "statement": "Offline handling remains advisory until a named decision is recorded.", "origin": "human_confirmed", "effect": exception_effect, "source_id": "original-intent", "critical": False}],
        "negative_cases": ([{"id": "expired-entitlement", "statement": "An expired entitlement must not restore paid access.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}] if include_negative else [{"id": "new-negative", "statement": "A new non-equivalent negative case cannot replace the required case.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True}]),
        "invariants": [{"id": "candidate-bound", "statement": "Evidence must bind to the exact submitted candidate.", "origin": "trusted_source", "effect": "blocking", "source_id": "original-intent", "critical": True}],
        "tests": [{"id": "restore-flow", "statement": "The restore flow must fail when implementation accepts expired access.", "origin": "human_confirmed", "effect": "blocking", "source_id": "original-intent", "critical": True, "path": "tests/test_restore.py"}],
    }
    payload = {"schema": "factory.oracle-contract-input.v1", "id": "ios-restore", "version": 1, "approved_by": "Release Owner", "approval_rationale": "The product owner reviewed the original intent and the strict restore safety boundary.", "scope_paths": ["."], "handoff": handoff.relative_to(root).as_posix(), "sources": [], **rules}
    return _write(root / "oracle-input.json", payload)


def _contract(root: Path, *, out: str = ".factory/oracles/contracts/original.json", **kwargs: object) -> Path:
    handoff = _handoff(root)
    source = _input(root, handoff, **kwargs)
    return root / seal_oracle_contract(root, source, Path(out))["path"]


def test_handoff_or_contract_seals_exact_original_intent_and_rejects_agent_authority(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    verified = verify_oracle_contract(tmp_path, contract)
    handoff = verify_intent_handoff(tmp_path, tmp_path / ".factory/oracles/handoffs/ios-intake.json")

    assert handoff["ok"] is True
    assert verified["ok"] is True
    assert verified["contract"]["handoff"]["original_intent"]["sha256"] == hashlib.sha256((tmp_path / "briefs/original-intent.md").read_bytes()).hexdigest()

    source = _input(tmp_path, tmp_path / ".factory/oracles/handoffs/ios-intake.json")
    candidate = json.loads(source.read_text(encoding="utf-8"))
    candidate["gates"][0]["origin"] = "agent_proposed"
    _write(source, candidate)
    with pytest.raises(OracleFirewallError) as raised:
        seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/agent-gate.json"))
    assert raised.value.code == "ORACLE_PROVENANCE_INVALID"


def test_drift_blocks_threshold_lowering_and_removed_negative_case_with_source_justification(tmp_path: Path) -> None:
    prior = _contract(tmp_path, out=".factory/oracles/contracts/prior.json")
    handoff = tmp_path / ".factory/oracles/handoffs/ios-intake.json"
    source = _input(tmp_path, handoff, threshold=90, include_negative=False)
    candidate = tmp_path / seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/candidate.json"))["path"]
    drift = compare_oracle_contracts(tmp_path, prior, candidate, Path(".factory/oracles/drifts/latest.json"))

    assert drift["marker"] == "E_ORACLE_WEAKENING"
    assert drift["verdict"] == "BLOCKED"
    assert {item["code"] for item in drift["findings"]} >= {"threshold_lowered", "negative_case_removed"}
    assert all(item["justification"]["approved_by"] == "Release Owner" for item in drift["findings"])


def test_drift_requires_review_for_same_id_semantic_rewrites_for_every_blocking_rule_class(tmp_path: Path) -> None:
    prior = _contract(tmp_path, out=".factory/oracles/contracts/prior.json")
    source = _input(tmp_path, tmp_path / ".factory/oracles/handoffs/ios-intake.json")
    candidate_input = json.loads(source.read_text(encoding="utf-8"))
    candidate_input["requirements"][0]["statement"] = "Restore may fail for an entitled account."
    candidate_input["forbidden_behaviors"][0]["statement"] = "A restore may create another charge."
    candidate_input["invariants"][0]["statement"] = "Evidence may bind to a different candidate."
    candidate_input["gates"][0]["statement"] = "Restore evidence is optional."
    _write(source, candidate_input)
    candidate = tmp_path / seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/candidate.json"))["path"]

    drift = compare_oracle_contracts(tmp_path, prior, candidate)

    rewritten = [item for item in drift["findings"] if item["code"] == "blocking_rule_rewritten"]
    assert drift["marker"] == "ORACLE_DRIFT_REVIEW_REQUIRED"
    assert drift["verdict"] == "REVIEW_REQUIRED"
    assert {item["group"] for item in rewritten} >= {"requirements", "forbidden_behaviors", "invariants", "gates"}
    assert all("statement" in item["changed_fields"] for item in rewritten)


def test_added_blocking_rule_requires_review_and_never_clears(tmp_path: Path) -> None:
    prior = _contract(tmp_path, out=".factory/oracles/contracts/prior.json")
    source = _input(tmp_path, tmp_path / ".factory/oracles/handoffs/ios-intake.json")
    candidate_input = json.loads(source.read_text(encoding="utf-8"))
    candidate_input["requirements"].append({
        "id": "receipt-retention",
        "statement": "The final receipt must remain available for audit.",
        "origin": "human_confirmed",
        "effect": "blocking",
        "source_id": "original-intent",
        "critical": True,
    })
    _write(source, candidate_input)
    candidate = tmp_path / seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/candidate.json"))["path"]

    drift = compare_oracle_contracts(tmp_path, prior, candidate)

    assert drift["marker"] == "ORACLE_DRIFT_REVIEW_REQUIRED"
    assert drift["verdict"] == "REVIEW_REQUIRED"
    assert drift["reason"] == "semantic_change_requires_review"
    assert drift["weakening_findings"] == []
    added = [item for item in drift["review_findings"] if item["code"] == "blocking_rule_added"]
    assert len(added) == 1
    assert added[0]["before"] is None
    assert added[0]["group"] == "requirements"
    assert added[0]["rule_id"] == "receipt-retention"
    assert added[0]["after"]["statement"] == "The final receipt must remain available for audit."


def test_advisory_removal_or_rewrite_requires_review_and_never_clears(tmp_path: Path) -> None:
    handoff = _handoff(tmp_path)
    source = _input(tmp_path, handoff)
    prior_input = json.loads(source.read_text(encoding="utf-8"))
    prior_input["requirements"].append({"id": "advisory-note", "statement": "A non-blocking operator note remains visible.", "origin": "human_confirmed", "effect": "advisory", "source_id": "original-intent", "critical": False})
    _write(source, prior_input)
    prior = tmp_path / seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/prior.json"))["path"]
    candidate_input = json.loads(source.read_text(encoding="utf-8"))
    candidate_input["requirements"] = [item for item in candidate_input["requirements"] if item["id"] != "advisory-note"]
    _write(source, candidate_input)
    removed = tmp_path / seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/removed.json"))["path"]
    removal = compare_oracle_contracts(tmp_path, prior, removed)
    assert removal["verdict"] == "REVIEW_REQUIRED"
    assert any(item["code"] == "advisory_rule_removed" for item in removal["review_findings"])

    candidate_input = prior_input
    candidate_input["requirements"][-1]["statement"] = "The operator note changes and must be reviewed."
    _write(source, candidate_input)
    rewritten = tmp_path / seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/rewritten.json"))["path"]
    rewrite = compare_oracle_contracts(tmp_path, prior, rewritten)
    assert rewrite["verdict"] == "REVIEW_REQUIRED"
    assert any(item["code"] == "blocking_rule_rewritten" for item in rewrite["review_findings"])


def test_shadow_oracle_challenge_is_implementation_targeted_and_fails_on_survivor(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    plan = compile_oracle_challenge(tmp_path, contract, Path(".factory/oracles/challenges/restore.json"))
    result = _write(tmp_path / "challenge-result.json", {"schema": "factory.oracle-challenge-result.v1", "challenge_sha256": plan["challenge_sha256"], "worker_subject": "worker-alpha", "verifier_subject": "verifier-beta", "target": "implementation", "cases": [{"id": item["id"], "outcome": "survived" if index == 0 else "killed"} for index, item in enumerate(plan["cases"])]})

    checked = verify_oracle_challenge_result(tmp_path, tmp_path / plan["path"], result)

    assert checked["ok"] is False
    assert checked["marker"] == "ORACLE_CHALLENGE_FAILED"
    assert checked["surviving_cases"]
    gate = next(item for item in plan["cases"] if item["id"] == "gates:restore-rate")
    assert [item["relation"] for item in gate["boundary_cases"]] == ["below", "at", "above"]


def test_shadow_oracle_challenge_rejects_a_stale_plan_even_when_every_case_is_killed(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    plan = compile_oracle_challenge(tmp_path, contract, Path(".factory/oracles/challenges/restore.json"))
    result = _write(tmp_path / "challenge-result.json", {"schema": "factory.oracle-challenge-result.v1", "challenge_sha256": plan["challenge_sha256"], "worker_subject": "worker-alpha", "verifier_subject": "verifier-beta", "target": "implementation", "cases": [{"id": item["id"], "outcome": "killed"} for item in plan["cases"]]})
    sealed = json.loads(contract.read_text(encoding="utf-8"))
    captured = tmp_path / sealed["handoff"]["original_intent"]["captured_path"]
    captured.write_text("A changed bound source invalidates the previously sealed contract.\n", encoding="utf-8")

    checked = verify_oracle_challenge_result(tmp_path, tmp_path / plan["path"], result)

    assert checked["ok"] is False
    assert checked["marker"] == "ORACLE_CHALLENGE_FAILED"
    assert checked["reason"] == "challenge_plan_invalid_or_stale"


def test_oracle_incident_demotes_declared_agent_and_projects_read_only_status(tmp_path: Path) -> None:
    prior = _contract(tmp_path, out=".factory/oracles/contracts/prior.json")
    handoff = tmp_path / ".factory/oracles/handoffs/ios-intake.json"
    candidate = tmp_path / seal_oracle_contract(tmp_path, _input(tmp_path, handoff, threshold=90), Path(".factory/oracles/contracts/candidate.json"))["path"]
    drift = compare_oracle_contracts(tmp_path, prior, candidate, Path(".factory/oracles/drifts/blocked.json"))
    incident = record_oracle_incident(tmp_path, AGENT, prior, tmp_path / drift["path"])
    license_value = derive_license(tmp_path, AGENT)
    projection = oracle_firewall_projection(tmp_path)

    assert incident["marker"] == "ORACLE_AUTONOMY_DEMOTED"
    assert license_value["tier"] == "human_controlled"
    assert license_value["reason"] == "ORACLE_WEAKENING_DEMOTION"
    assert projection["blocked_drift_count"] == 1
    assert all(value is False for value in projection["authority"].values())


def test_oracle_incident_rejects_stale_or_unrelated_drift_without_demotion(tmp_path: Path) -> None:
    prior = _contract(tmp_path, out=".factory/oracles/contracts/prior.json")
    source = _input(tmp_path, tmp_path / ".factory/oracles/handoffs/ios-intake.json", threshold=90)
    candidate = tmp_path / seal_oracle_contract(tmp_path, source, Path(".factory/oracles/contracts/candidate.json"))["path"]
    drift = compare_oracle_contracts(tmp_path, prior, candidate, Path(".factory/oracles/drifts/blocked.json"))
    before = derive_license(tmp_path, AGENT)
    incidents = tmp_path / ".factory/oracles/incidents"
    before_incidents = sorted(incidents.glob("*.json")) if incidents.exists() else []

    with pytest.raises(OracleFirewallError) as unrelated:
        record_oracle_incident(tmp_path, AGENT, candidate, tmp_path / drift["path"])
    assert unrelated.value.code == "ORACLE_INCIDENT_INVALID"
    assert derive_license(tmp_path, AGENT)["tier"] == before["tier"]
    assert (sorted(incidents.glob("*.json")) if incidents.exists() else []) == before_incidents

    stale = _write(tmp_path / ".factory/oracles/drifts/stale.json", {
        "schema": "factory.oracle-drift.v1",
        "marker": "E_ORACLE_WEAKENING",
        "verdict": "BLOCKED",
        "reason": "contract_invalid_or_stale",
        "contracts": {"prior": {"path": "x", "contract_sha256": "0" * 64}, "candidate": {"path": "y", "contract_sha256": "1" * 64}},
        "findings": [],
        "verification": {"prior": "source_changed"},
        "authority": {"execution": False, "approval": False, "repair": False, "merge": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False},
        "claim_boundary": "Synthetic stale local comparison for refusal coverage.",
    })
    stale_payload = json.loads(stale.read_text(encoding="utf-8"))
    stale_payload["drift_sha256"] = hashlib.sha256(json.dumps(stale_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    _write(stale, stale_payload)
    with pytest.raises(OracleFirewallError) as stale_rejection:
        record_oracle_incident(tmp_path, AGENT, prior, stale)
    assert stale_rejection.value.code == "ORACLE_INCIDENT_INVALID"
    assert derive_license(tmp_path, AGENT)["tier"] == before["tier"]
    assert (sorted(incidents.glob("*.json")) if incidents.exists() else []) == before_incidents


def test_full_init_creates_deliberately_incomplete_appforge_authority_workspace(tmp_path: Path) -> None:
    source = tmp_path / "original.md"
    source.write_text("The user wants accessible subscription restore and a clear review path.", encoding="utf-8")

    result = initialize_oracle_firewall(tmp_path, Path(".factory/oracles/init/ios"), source, AGENT, "ios-release", ["."], appforge=True)
    workspace = tmp_path / ".factory/oracles/init/ios"

    assert result["marker"] == "ORACLE_FIREWALL_INIT_READY"
    assert json.loads((workspace / "oracle-contract-input.json").read_text(encoding="utf-8"))["requirements"] == []
    assert (workspace / "appforge-policy-authority-template.json").is_file()
    assert "does not approve" in (workspace / "NEXT_STEPS.md").read_text(encoding="utf-8")

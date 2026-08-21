from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.judgment import (
    CAPSULE_SCHEMA,
    CAPSULE_V2_SCHEMA,
    CHANGE_PROFILE_SCHEMA,
    PROOF_RECEIPT_SCHEMA,
    JudgmentError,
    judgment_status,
    promote_capsule,
    propose_capsule,
    reconsider_capsule,
    safety_case,
)


def _candidate(capsule_id: str = "billing-negative-proof", supersedes: str | None = None) -> dict:
    return {
        "schema": CAPSULE_SCHEMA,
        "id": capsule_id,
        "title": "Cancelled accounts never receive a new invoice",
        "summary": "The cancellation path preserves the no-new-invoice invariant.",
        "scope_paths": ["app/billing.py"],
        "rationale_refs": ["adr/0001-failure-aware-assembly.md"],
        "evidence_refs": ["tests/test_billing.py"],
        "proof_obligations": [{"id": "cancelled-invoice-negative", "description": "A cancelled account invoice attempt must fail."}],
        "owner": "Lin",
        "review_by": "2027-01-01",
        "supersedes": supersedes,
    }


def _v2_candidate(capsule_id: str = "billing-concurrency-contract", *, review_by: str = "2027-01-01") -> dict:
    return {
        **_candidate(capsule_id),
        "schema": CAPSULE_V2_SCHEMA,
        "category": "architecture",
        "change_kinds": ["concurrency"],
        "attention_floor": "domain",
        "enforcement_level": "proof",
        "incident_refs": ["incidents/billing-race.md"],
        "review_by": review_by,
    }


def _files(root: Path) -> dict[str, bytes]:
    return {item.relative_to(root).as_posix(): item.read_bytes() for item in root.rglob("*") if item.is_file()}


def _active(root: Path, capsule_id: str = "billing-negative-proof") -> dict:
    propose_capsule(root, _candidate(capsule_id), proposed_by="Ada", at="2026-08-21T12:00:00Z")
    return promote_capsule(root, capsule_id, promoted_by="Lin", reason="Independent review accepted the explicit invariant.", at="2026-08-21T12:01:00Z")


def _receipt(root: Path, *, capsule_id: str = "billing-negative-proof", obligation_id: str = "cancelled-invoice-negative") -> Path:
    evidence = root / "tests" / "billing-result.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("negative test passed\n", encoding="utf-8")
    core = {
        "schema": PROOF_RECEIPT_SCHEMA,
        "capsule_id": capsule_id,
        "obligation_id": obligation_id,
        "verdict": "verified",
        "evidence": [{"path": "tests/billing-result.txt", "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}],
    }
    payload = {**core, "receipt_sha256": hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()}
    result = root / "proofs" / "billing.receipt.json"
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text(json.dumps(payload), encoding="utf-8")
    return result


def _change_profile(root: Path, changed: list[dict[str, object]], name: str = "change-profile.json") -> Path:
    normalized = sorted(
        [{"path": str(item["path"]), "change_kinds": sorted(str(kind) for kind in item["change_kinds"])} for item in changed],
        key=lambda item: item["path"],
    )
    core = {"schema": CHANGE_PROFILE_SCHEMA, "changed": normalized}
    payload = {
        **core,
        "profile_sha256": hashlib.sha256(
            json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        ).hexdigest(),
    }
    path = root / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_proposal_requires_independent_promotion_and_is_tracked(tmp_path: Path) -> None:
    proposal = propose_capsule(tmp_path, _candidate(), proposed_by="Ada", at="2026-08-21T12:00:00Z")
    before = _files(tmp_path)
    with pytest.raises(JudgmentError) as exc:
        promote_capsule(tmp_path, "billing-negative-proof", promoted_by="Ada", reason="self", at="2026-08-21T12:01:00Z")
    assert exc.value.code == "JUDGMENT_PROMOTION_INDEPENDENCE_REQUIRED"
    assert _files(tmp_path) == before
    promoted = promote_capsule(tmp_path, "billing-negative-proof", promoted_by="Lin", reason="Independent review.", at="2026-08-21T12:02:00Z")
    assert proposal["capsule"]["lifecycle"]["state"] == "proposed"
    assert promoted["capsule"]["lifecycle"]["state"] == "active"
    assert promoted["capsule"]["lifecycle"]["promoted_by"] == "Lin"
    assert judgment_status(tmp_path, today=date(2026, 8, 21))["counts"] == {"total": 1, "active": 1, "proposed": 0, "review_due": 0}


def test_reconsideration_keeps_active_capsule_until_successor_is_independently_promoted(tmp_path: Path) -> None:
    _active(tmp_path)
    successor = _candidate("billing-replacement", supersedes="billing-negative-proof")
    propose_capsule(tmp_path, successor, proposed_by="Mira", at="2026-08-21T12:10:00Z")
    reconsidered = reconsider_capsule(tmp_path, "billing-negative-proof", "billing-replacement", requested_by="Lin", reason="The boundary changed.", at="2026-08-21T12:11:00Z")
    assert reconsidered["capsule"]["lifecycle"]["state"] == "active"
    promoted = promote_capsule(tmp_path, "billing-replacement", promoted_by="Ravi", reason="Independent successor approval.", at="2026-08-21T12:12:00Z")
    state = {row["id"]: row["state"] for row in judgment_status(tmp_path)["capsules"]}
    assert promoted["capsule"]["lifecycle"]["state"] == "active"
    assert state == {"billing-negative-proof": "superseded", "billing-replacement": "active"}


def test_safety_case_is_read_only_red_for_missing_obligation_and_green_is_explicitly_unclassified(tmp_path: Path) -> None:
    _active(tmp_path)
    before = _files(tmp_path)
    blocked = safety_case(tmp_path, changed=["app/billing.py"], as_of=date(2026, 8, 21))
    unclassified = safety_case(tmp_path, changed=["docs/notes.md"], as_of=date(2026, 8, 21))
    assert blocked["route"] == "RED"
    assert blocked["missing_obligations"] == [{"capsule_id": "billing-negative-proof", "obligation_id": "cancelled-invoice-negative", "owner": "Lin"}]
    assert unclassified["route"] == "GREEN"
    assert "routine_unclassified" in unclassified["review_reasons"]
    assert unclassified["unclassified_changed_paths"] == ["docs/notes.md"]
    assert all(value is False for value in blocked["authority"].values())
    assert _files(tmp_path) == before


def test_safety_case_validates_exact_hash_bound_receipt_and_marks_owner_review(tmp_path: Path) -> None:
    _active(tmp_path)
    receipt = _receipt(tmp_path)
    result = safety_case(tmp_path, changed=["app/billing.py"], proof_receipts=[receipt], as_of=date(2026, 8, 21))
    assert result["route"] == "AMBER"
    assert result["required_reviewers"] == ["Lin"]
    assert result["matching_capsules"][0]["obligations"][0]["state"] == "bound"
    evidence = tmp_path / "tests" / "billing-result.txt"
    evidence.write_text("tampered\n", encoding="utf-8")
    invalid = safety_case(tmp_path, changed=["app/billing.py"], proof_receipts=[receipt], as_of=date(2026, 8, 21))
    assert invalid["route"] == "RED"
    assert invalid["receipt_errors"][0]["code"] == "JUDGMENT_PROOF_RECEIPT_INVALID"


def test_tampered_store_fails_closed_without_fallback(tmp_path: Path) -> None:
    _active(tmp_path)
    store = tmp_path / "judgment" / "capsules.json"
    store.write_text("{}", encoding="utf-8")
    result = safety_case(tmp_path, changed=["app/billing.py"], as_of=date(2026, 8, 21))
    assert result["route"] == "BLACK"
    assert result["markers"] == ["JUDGMENT_CAPSULE_INVALID", "JUDGMENT_SAFETY_CASE_READ_ONLY"]


def test_cli_emits_machine_readable_proposal_promotion_and_no_execution_safety_case(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps(_candidate()), encoding="utf-8")
    assert main(["judgment", "propose", str(candidate), "--root", str(tmp_path), "--proposed-by", "Ada", "--json"]) == 0
    proposed = json.loads(capsys.readouterr().out)
    assert proposed["marker"] == "JUDGMENT_CAPSULE_PROPOSED"
    assert main(["judgment", "promote", "billing-negative-proof", "--root", str(tmp_path), "--promoted-by", "Lin", "--reason", "Independent review.", "--json"]) == 0
    active = json.loads(capsys.readouterr().out)
    assert active["marker"] == "JUDGMENT_CAPSULE_ACTIVE"
    before = _files(tmp_path)
    assert main(["judgment", "safety-case", "--root", str(tmp_path), "--changed", "app/billing.py", "--json"]) == 1
    safety = json.loads(capsys.readouterr().out)
    assert safety["route"] == "RED"
    assert all(value is False for value in safety["authority"].values())
    assert _files(tmp_path) == before


def test_graph_ops_projects_human_tracked_judgment_without_granting_execution(tmp_path: Path) -> None:
    _active(tmp_path)
    before = _files(tmp_path)
    graph = graph_ops_snapshot(tmp_path)
    after = _files(tmp_path)
    assert graph["judgment"]["active_count"] == 1
    assert graph["facts"]["judgment_active_count"] == 1
    assert "GRAPH_OPS_JUDGMENT_CAPSULES_READ_ONLY" in graph["markers"]
    capsule = next(node for node in graph["nodes"] if node["kind"] == "judgment_capsule")
    assert capsule["facts"]["owner"] == "Lin"
    assert capsule["facts"]["proof_obligation_count"] == 1
    assert capsule["facts"]["execution"] is False
    assert all(value is False for value in capsule["facts"]["authority"].values())
    assert before == after


def test_declared_change_profile_routes_attention_and_novelty_without_source_inference(tmp_path: Path) -> None:
    candidate = _v2_candidate()
    propose_capsule(tmp_path, candidate, proposed_by="Ada", at="2026-08-21T12:00:00Z")
    promote_capsule(tmp_path, candidate["id"], promoted_by="Lin", reason="Independent review.", at="2026-08-21T12:01:00Z")
    receipt = _receipt(tmp_path, capsule_id=candidate["id"])
    profile = _change_profile(tmp_path, [{"path": "app/billing.py", "change_kinds": ["concurrency", "architecture-boundary"]}])

    result = safety_case(
        tmp_path,
        changed=["app/billing.py"],
        proof_receipts=[receipt],
        change_profile=profile,
        as_of=date(2026, 8, 21),
    )

    assert result["route"] == "AMBER"
    assert result["attention"] == "architecture"
    assert result["profile"]["state"] == "valid"
    assert result["novelty"] == {
        "known_change_kinds": [{"path": "app/billing.py", "kind": "concurrency", "capsule_ids": [candidate["id"]]}],
        "novel_change_kinds": [{"path": "app/billing.py", "kind": "architecture-boundary", "reason": "no_matching_active_capsule_declares_kind"}],
        "unclassified_changed_paths": [],
    }
    assert result["drift"] == [{"capsule_id": candidate["id"], "state": "declared_proof_bound"}]
    assert result["facts"]["source_semantics_inferred"] is False
    assert any(question["id"] == "decision-app-billing.py-architecture-boundary" for question in result["human_questions"])


def test_invalid_change_profile_is_explicit_and_never_replaced_by_inference(tmp_path: Path) -> None:
    candidate = _v2_candidate()
    propose_capsule(tmp_path, candidate, proposed_by="Ada", at="2026-08-21T12:00:00Z")
    promote_capsule(tmp_path, candidate["id"], promoted_by="Lin", reason="Independent review.", at="2026-08-21T12:01:00Z")
    receipt = _receipt(tmp_path, capsule_id=candidate["id"])
    profile = _change_profile(tmp_path, [{"path": "app/billing.py", "change_kinds": ["concurrency"]}])
    payload = json.loads(profile.read_text(encoding="utf-8"))
    payload["profile_sha256"] = "0" * 64
    profile.write_text(json.dumps(payload), encoding="utf-8")

    result = safety_case(tmp_path, changed=["app/billing.py"], proof_receipts=[receipt], change_profile=profile, as_of=date(2026, 8, 21))

    assert result["route"] == "AMBER"
    assert result["profile"]["state"] == "invalid"
    assert result["profile"]["error"]["code"] == "JUDGMENT_CHANGE_PROFILE_INVALID"
    assert result["facts"]["source_semantics_inferred"] is False


def test_review_due_v2_capsule_exposes_drift_and_named_human_question(tmp_path: Path) -> None:
    candidate = _v2_candidate(review_by="2026-08-01")
    propose_capsule(tmp_path, candidate, proposed_by="Ada", at="2026-08-21T12:00:00Z")
    promote_capsule(tmp_path, candidate["id"], promoted_by="Lin", reason="Independent review.", at="2026-08-21T12:01:00Z")
    receipt = _receipt(tmp_path, capsule_id=candidate["id"])

    result = safety_case(tmp_path, changed=["app/billing.py"], proof_receipts=[receipt], as_of=date(2026, 8, 21))

    assert result["attention"] == "specialist"
    assert result["drift"] == [{"capsule_id": candidate["id"], "state": "review_due"}]
    assert any(question["id"] == f"review-{candidate['id']}" for question in result["human_questions"])

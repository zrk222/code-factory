from __future__ import annotations
import hashlib
import json
from pathlib import Path
import pytest
from factoryline.first_lap import (
    FirstLapError,
    classify_failure,
    initialize_first_lap,
    promote_incident,
    record_incident,
    verify_activation,
    verify_holdout_boundary,
    verify_observed_first_lap,
    verify_verifier_calibration,
)
from factoryline.grill_engine import (
    answer_question,
    confirm_grill,
    next_question,
    start_grill,
)
from datetime import date
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
from factoryline.policy_compiler import (
    PolicyCompileError,
    compile_policy,
    write_compiled_policy,
)
from factoryline.product_missions import (
    ProductMissionError,
    analyze_product_text,
    compile_product_text,
)
from factoryline.prd_grill import grill_prd, verify_prd_grill
import sys
from factoryline.reality_check import (
    RealityCheckError,
    inspect_reality_intent,
    run_reality_check,
    validate_reality_check_manifest,
    validate_reality_check_receipt,
    write_reality_check_artifacts,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _events():
    return [
        {"phase": phase, "evidence_sha256": "a" * 64}
        for phase in (
            "intake",
            "candidate_binding",
            "validation",
            "failure_handling",
            "cleanup",
            "handoff",
        )
    ]


def test_first_lap_init_writes_plain_language_files_and_receipt(tmp_path: Path):
    result = initialize_first_lap(
        tmp_path,
        mission="Ship a safe change",
        journeys=["Create an account", "Recover a failed request"],
        holdouts=["A revoked session is rejected"],
    )
    assert (tmp_path / "MISSION.md").is_file()
    assert (tmp_path / "END-TO-END.md").is_file()
    assert (tmp_path / ".factory" / "holdouts" / "HOLDOUT.md").is_file()
    assert result["marker"] == "FIRST_LAP_FILES_READY"
    assert result["artifacts"][0]["sha256"] == _sha(tmp_path / "MISSION.md")


def test_first_lap_does_not_overwrite_existing_files(tmp_path: Path):
    (tmp_path / "MISSION.md").write_text("owner content\n", encoding="utf-8")
    initialize_first_lap(tmp_path)
    assert (tmp_path / "MISSION.md").read_text(encoding="utf-8") == "owner content\n"
    with pytest.raises(FirstLapError, match="receipt already exists"):
        initialize_first_lap(tmp_path)


def test_calibration_requires_three_point_oracle():
    result = verify_verifier_calibration(
        tmp_path := Path("."),
        {
            "approved_candidate": "pass",
            "defective_candidate": "fail",
            "wrong_candidate": "inconclusive",
        },
    )
    assert result["state"] == "CALIBRATED"
    blocked = verify_verifier_calibration(
        tmp_path,
        {
            "approved_candidate": "pass",
            "defective_candidate": "pass",
            "wrong_candidate": "inconclusive",
        },
    )
    assert blocked["code"] == "E_CALIBRATION_FAILED"


def test_incident_promotion_chain_is_complete(tmp_path: Path):
    incident = {
        "incident_id": "publish-timeout",
        "failure_code": "E_PROVIDER_TIMEOUT",
        "invariant": "a timeout is never reported as published",
        "reproducer": "run upload with a dropped connection",
        "mutation": "replace timeout classification with success",
        "owner": "release-team",
    }
    recorded = record_incident(tmp_path, incident)
    assert recorded["status"] == "PROMOTION_READY"
    promoted = promote_incident(tmp_path, incident)
    assert promoted["marker"] == "INCIDENT_PROMOTED_TO_GATE"
    assert (
        json.loads((tmp_path / promoted["path"]).read_text(encoding="utf-8"))["gate"][
            "required"
        ]
        is True
    )


def test_incident_duplicate_and_missing_fields_fail_closed(tmp_path: Path):
    incident = {
        "incident_id": "x",
        "failure_code": "E_X",
        "invariant": "never lie",
        "reproducer": "steps",
        "mutation": "mutant",
        "owner": "owner",
    }
    record_incident(tmp_path, incident)
    with pytest.raises(FirstLapError, match="already recorded"):
        record_incident(tmp_path, incident)
    with pytest.raises(FirstLapError, match="full chain"):
        promote_incident(tmp_path, {"incident_id": "bad"})


def test_holdout_boundary_accepts_verifier_only_file_and_rejects_access(tmp_path: Path):
    holdout = tmp_path / ".factory" / "holdouts" / "HOLDOUT.md"
    holdout.parent.mkdir(parents=True)
    holdout.write_text("secret scenario\n", encoding="utf-8")
    verified = verify_holdout_boundary(
        tmp_path,
        {
            "path": ".factory/holdouts/HOLDOUT.md",
            "sha256": _sha(holdout),
            "builder_accessed_paths": [],
        },
    )
    assert verified["state"] == "VERIFIED"
    blocked = verify_holdout_boundary(
        tmp_path,
        {
            "path": str(holdout),
            "sha256": _sha(holdout),
            "builder_accessed_paths": [".factory/holdouts/HOLDOUT.md"],
        },
    )
    assert blocked["code"] == "E_HOLDOUT_BUILDER_ACCESS"


def test_observed_first_lap_requires_exact_order_and_evidence():
    assert verify_observed_first_lap(_events())["state"] == "OBSERVED"
    assert (
        verify_observed_first_lap(list(reversed(_events())))["code"]
        == "E_FIRST_LAP_SEQUENCE"
    )
    missing = _events()
    missing[2]["evidence_sha256"] = "bad"
    assert verify_observed_first_lap(missing)["code"] == "E_FIRST_LAP_EVIDENCE"


def test_only_transient_provider_failure_is_retryable():
    assert (
        classify_failure(
            "transient_provider_failure", provider="openvsx", retry_after_seconds=10
        )["retry_allowed"]
        is True
    )
    for kind in (
        "definitive_product_failure",
        "unverifiable_candidate_identity",
        "stale_evidence",
        "environment_setup_failure",
    ):
        assert classify_failure(kind)["retry_allowed"] is False
        assert (
            classify_failure(kind, retry_after_seconds=10)["retry_after_seconds"]
            is None
        )


def test_activation_requires_all_three_controls():
    calibration = verify_verifier_calibration(
        Path("."),
        {
            "approved_candidate": "pass",
            "defective_candidate": "fail",
            "wrong_candidate": "blocked",
        },
    )
    observed = verify_observed_first_lap(_events())
    blocked = verify_activation(
        Path("."),
        calibration=calibration,
        holdout={"state": "BLOCKED"},
        observed=observed,
    )
    assert blocked["state"] == "BLOCKED"
    holdout = {"state": "VERIFIED", "boundary_sha256": "b" * 64}
    ready = verify_activation(
        Path("."), calibration=calibration, holdout=holdout, observed=observed
    )
    assert ready["state"] == "READY"


def test_grill_is_one_question_at_a_time_and_requires_confirmation(
    tmp_path: Path,
) -> None:
    source = tmp_path / "PRD.md"
    source.write_text("A bounded audit workflow for a developer.", encoding="utf-8")
    started = start_grill(tmp_path, "audit-slice", source)
    assert started["next"]["id"] == "intent"
    assert next_question(tmp_path, "audit-slice")["status"] == "QUESTION_REQUIRED"
    for question in started["questions"]:
        if question["required"]:
            answer_question(
                tmp_path,
                "audit-slice",
                question["id"],
                f"Human answer for {question['id']}",
                answered_by="owner",
            )
    assert next_question(tmp_path, "audit-slice")["status"] == "CONFIRMATION_REQUIRED"
    confirmed = confirm_grill(tmp_path, "audit-slice", approved_by="owner")
    assert confirmed["status"] == "confirmed"
    assert confirmed["confirmation_sha256"]
    assert next_question(tmp_path, "audit-slice")["status"] == "COMPLETE"


def _candidate(
    capsule_id: str = "billing-negative-proof", supersedes: str | None = None
) -> dict:
    return {
        "schema": CAPSULE_SCHEMA,
        "id": capsule_id,
        "title": "Cancelled accounts never receive a new invoice",
        "summary": "The cancellation path preserves the no-new-invoice invariant.",
        "scope_paths": ["app/billing.py"],
        "rationale_refs": ["adr/0001-failure-aware-assembly.md"],
        "evidence_refs": ["tests/test_billing.py"],
        "proof_obligations": [
            {
                "id": "cancelled-invoice-negative",
                "description": "A cancelled account invoice attempt must fail.",
            }
        ],
        "owner": "Lin",
        "review_by": "2027-01-01",
        "supersedes": supersedes,
    }


def _v2_candidate(
    capsule_id: str = "billing-concurrency-contract", *, review_by: str = "2027-01-01"
) -> dict:
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
    return {
        item.relative_to(root).as_posix(): item.read_bytes()
        for item in root.rglob("*")
        if item.is_file()
    }


def _active(root: Path, capsule_id: str = "billing-negative-proof") -> dict:
    propose_capsule(
        root, _candidate(capsule_id), proposed_by="Ada", at="2026-08-21T12:00:00Z"
    )
    return promote_capsule(
        root,
        capsule_id,
        promoted_by="Lin",
        reason="Independent review accepted the explicit invariant.",
        at="2026-08-21T12:01:00Z",
    )


def _receipt(
    root: Path,
    *,
    capsule_id: str = "billing-negative-proof",
    obligation_id: str = "cancelled-invoice-negative",
) -> Path:
    evidence = root / "tests" / "billing-result.txt"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text("negative test passed\n", encoding="utf-8")
    core = {
        "schema": PROOF_RECEIPT_SCHEMA,
        "capsule_id": capsule_id,
        "obligation_id": obligation_id,
        "verdict": "verified",
        "evidence": [
            {
                "path": "tests/billing-result.txt",
                "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
            }
        ],
    }
    payload = {
        **core,
        "receipt_sha256": hashlib.sha256(
            json.dumps(
                core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest(),
    }
    result = root / "proofs" / "billing.receipt.json"
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_text(json.dumps(payload), encoding="utf-8")
    return result


def _change_profile(
    root: Path, changed: list[dict[str, object]], name: str = "change-profile.json"
) -> Path:
    normalized = sorted(
        [
            {
                "path": str(item["path"]),
                "change_kinds": sorted(str(kind) for kind in item["change_kinds"]),
            }
            for item in changed
        ],
        key=lambda item: item["path"],
    )
    core = {"schema": CHANGE_PROFILE_SCHEMA, "changed": normalized}
    payload = {
        **core,
        "profile_sha256": hashlib.sha256(
            json.dumps(
                core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest(),
    }
    path = root / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_proposal_requires_independent_promotion_and_is_tracked(tmp_path: Path) -> None:
    proposal = propose_capsule(
        tmp_path, _candidate(), proposed_by="Ada", at="2026-08-21T12:00:00Z"
    )
    before = _files(tmp_path)
    with pytest.raises(JudgmentError) as exc:
        promote_capsule(
            tmp_path,
            "billing-negative-proof",
            promoted_by="Ada",
            reason="self",
            at="2026-08-21T12:01:00Z",
        )
    assert exc.value.code == "JUDGMENT_PROMOTION_INDEPENDENCE_REQUIRED"
    assert _files(tmp_path) == before
    promoted = promote_capsule(
        tmp_path,
        "billing-negative-proof",
        promoted_by="Lin",
        reason="Independent review.",
        at="2026-08-21T12:02:00Z",
    )
    assert proposal["capsule"]["lifecycle"]["state"] == "proposed"
    assert promoted["capsule"]["lifecycle"]["state"] == "active"
    assert promoted["capsule"]["lifecycle"]["promoted_by"] == "Lin"
    assert judgment_status(tmp_path, today=date(2026, 8, 21))["counts"] == {
        "total": 1,
        "active": 1,
        "proposed": 0,
        "review_due": 0,
    }


def test_reconsideration_keeps_active_capsule_until_successor_is_independently_promoted(
    tmp_path: Path,
) -> None:
    _active(tmp_path)
    successor = _candidate("billing-replacement", supersedes="billing-negative-proof")
    propose_capsule(tmp_path, successor, proposed_by="Mira", at="2026-08-21T12:10:00Z")
    reconsidered = reconsider_capsule(
        tmp_path,
        "billing-negative-proof",
        "billing-replacement",
        requested_by="Lin",
        reason="The boundary changed.",
        at="2026-08-21T12:11:00Z",
    )
    assert reconsidered["capsule"]["lifecycle"]["state"] == "active"
    promoted = promote_capsule(
        tmp_path,
        "billing-replacement",
        promoted_by="Ravi",
        reason="Independent successor approval.",
        at="2026-08-21T12:12:00Z",
    )
    state = {row["id"]: row["state"] for row in judgment_status(tmp_path)["capsules"]}
    assert promoted["capsule"]["lifecycle"]["state"] == "active"
    assert state == {
        "billing-negative-proof": "superseded",
        "billing-replacement": "active",
    }


def test_safety_case_is_read_only_red_for_missing_obligation_and_green_is_explicitly_unclassified(
    tmp_path: Path,
) -> None:
    _active(tmp_path)
    before = _files(tmp_path)
    blocked = safety_case(tmp_path, changed=["app/billing.py"], as_of=date(2026, 8, 21))
    unclassified = safety_case(
        tmp_path, changed=["docs/notes.md"], as_of=date(2026, 8, 21)
    )
    assert blocked["route"] == "RED"
    assert blocked["missing_obligations"] == [
        {
            "capsule_id": "billing-negative-proof",
            "obligation_id": "cancelled-invoice-negative",
            "owner": "Lin",
        }
    ]
    assert unclassified["route"] == "GREEN"
    assert "routine_unclassified" in unclassified["review_reasons"]
    assert unclassified["unclassified_changed_paths"] == ["docs/notes.md"]
    assert all(value is False for value in blocked["authority"].values())
    assert _files(tmp_path) == before


def test_safety_case_validates_exact_hash_bound_receipt_and_marks_owner_review(
    tmp_path: Path,
) -> None:
    _active(tmp_path)
    receipt = _receipt(tmp_path)
    result = safety_case(
        tmp_path,
        changed=["app/billing.py"],
        proof_receipts=[receipt],
        as_of=date(2026, 8, 21),
    )
    assert result["route"] == "AMBER"
    assert result["required_reviewers"] == ["Lin"]
    assert result["matching_capsules"][0]["obligations"][0]["state"] == "bound"
    evidence = tmp_path / "tests" / "billing-result.txt"
    evidence.write_text("tampered\n", encoding="utf-8")
    invalid = safety_case(
        tmp_path,
        changed=["app/billing.py"],
        proof_receipts=[receipt],
        as_of=date(2026, 8, 21),
    )
    assert invalid["route"] == "RED"
    assert invalid["receipt_errors"][0]["code"] == "JUDGMENT_PROOF_RECEIPT_INVALID"


def test_tampered_store_fails_closed_without_fallback(tmp_path: Path) -> None:
    _active(tmp_path)
    store = tmp_path / "judgment" / "capsules.json"
    store.write_text("{}", encoding="utf-8")
    result = safety_case(tmp_path, changed=["app/billing.py"], as_of=date(2026, 8, 21))
    assert result["route"] == "BLACK"
    assert result["markers"] == [
        "JUDGMENT_CAPSULE_INVALID",
        "JUDGMENT_SAFETY_CASE_READ_ONLY",
    ]


def test_cli_emits_machine_readable_proposal_promotion_and_no_execution_safety_case(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate = tmp_path / "candidate.json"
    candidate.write_text(json.dumps(_candidate()), encoding="utf-8")
    assert (
        main(
            [
                "judgment",
                "propose",
                str(candidate),
                "--root",
                str(tmp_path),
                "--proposed-by",
                "Ada",
                "--json",
            ]
        )
        == 0
    )
    proposed = json.loads(capsys.readouterr().out)
    assert proposed["marker"] == "JUDGMENT_CAPSULE_PROPOSED"
    assert (
        main(
            [
                "judgment",
                "promote",
                "billing-negative-proof",
                "--root",
                str(tmp_path),
                "--promoted-by",
                "Lin",
                "--reason",
                "Independent review.",
                "--json",
            ]
        )
        == 0
    )
    active = json.loads(capsys.readouterr().out)
    assert active["marker"] == "JUDGMENT_CAPSULE_ACTIVE"
    before = _files(tmp_path)
    assert (
        main(
            [
                "judgment",
                "safety-case",
                "--root",
                str(tmp_path),
                "--changed",
                "app/billing.py",
                "--json",
            ]
        )
        == 1
    )
    safety = json.loads(capsys.readouterr().out)
    assert safety["route"] == "RED"
    assert all(value is False for value in safety["authority"].values())
    assert _files(tmp_path) == before


def test_graph_ops_projects_human_tracked_judgment_without_granting_execution(
    tmp_path: Path,
) -> None:
    _active(tmp_path)
    before = _files(tmp_path)
    graph = graph_ops_snapshot(tmp_path)
    after = _files(tmp_path)
    assert graph["judgment"]["active_count"] == 1
    assert graph["facts"]["judgment_active_count"] == 1
    assert "GRAPH_OPS_JUDGMENT_CAPSULES_READ_ONLY" in graph["markers"]
    capsule = next(
        node for node in graph["nodes"] if node["kind"] == "judgment_capsule"
    )
    assert capsule["facts"]["owner"] == "Lin"
    assert capsule["facts"]["proof_obligation_count"] == 1
    assert capsule["facts"]["execution"] is False
    assert all(value is False for value in capsule["facts"]["authority"].values())
    assert before == after


def test_declared_change_profile_routes_attention_and_novelty_without_source_inference(
    tmp_path: Path,
) -> None:
    candidate = _v2_candidate()
    propose_capsule(tmp_path, candidate, proposed_by="Ada", at="2026-08-21T12:00:00Z")
    promote_capsule(
        tmp_path,
        candidate["id"],
        promoted_by="Lin",
        reason="Independent review.",
        at="2026-08-21T12:01:00Z",
    )
    receipt = _receipt(tmp_path, capsule_id=candidate["id"])
    profile = _change_profile(
        tmp_path,
        [
            {
                "path": "app/billing.py",
                "change_kinds": ["concurrency", "architecture-boundary"],
            }
        ],
    )

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
        "known_change_kinds": [
            {
                "path": "app/billing.py",
                "kind": "concurrency",
                "capsule_ids": [candidate["id"]],
            }
        ],
        "novel_change_kinds": [
            {
                "path": "app/billing.py",
                "kind": "architecture-boundary",
                "reason": "no_matching_active_capsule_declares_kind",
            }
        ],
        "unclassified_changed_paths": [],
    }
    assert result["drift"] == [
        {"capsule_id": candidate["id"], "state": "declared_proof_bound"}
    ]
    assert result["facts"]["source_semantics_inferred"] is False
    assert any(
        question["id"] == "decision-app-billing.py-architecture-boundary"
        for question in result["human_questions"]
    )


def test_invalid_change_profile_is_explicit_and_never_replaced_by_inference(
    tmp_path: Path,
) -> None:
    candidate = _v2_candidate()
    propose_capsule(tmp_path, candidate, proposed_by="Ada", at="2026-08-21T12:00:00Z")
    promote_capsule(
        tmp_path,
        candidate["id"],
        promoted_by="Lin",
        reason="Independent review.",
        at="2026-08-21T12:01:00Z",
    )
    receipt = _receipt(tmp_path, capsule_id=candidate["id"])
    profile = _change_profile(
        tmp_path, [{"path": "app/billing.py", "change_kinds": ["concurrency"]}]
    )
    payload = json.loads(profile.read_text(encoding="utf-8"))
    payload["profile_sha256"] = "0" * 64
    profile.write_text(json.dumps(payload), encoding="utf-8")

    result = safety_case(
        tmp_path,
        changed=["app/billing.py"],
        proof_receipts=[receipt],
        change_profile=profile,
        as_of=date(2026, 8, 21),
    )

    assert result["route"] == "AMBER"
    assert result["profile"]["state"] == "invalid"
    assert result["profile"]["error"]["code"] == "JUDGMENT_CHANGE_PROFILE_INVALID"
    assert result["facts"]["source_semantics_inferred"] is False


def test_review_due_v2_capsule_exposes_drift_and_named_human_question(
    tmp_path: Path,
) -> None:
    candidate = _v2_candidate(review_by="2026-08-01")
    propose_capsule(tmp_path, candidate, proposed_by="Ada", at="2026-08-21T12:00:00Z")
    promote_capsule(
        tmp_path,
        candidate["id"],
        promoted_by="Lin",
        reason="Independent review.",
        at="2026-08-21T12:01:00Z",
    )
    receipt = _receipt(tmp_path, capsule_id=candidate["id"])

    result = safety_case(
        tmp_path,
        changed=["app/billing.py"],
        proof_receipts=[receipt],
        as_of=date(2026, 8, 21),
    )

    assert result["attention"] == "specialist"
    assert result["drift"] == [{"capsule_id": candidate["id"], "state": "review_due"}]
    assert any(
        question["id"] == f"review-{candidate['id']}"
        for question in result["human_questions"]
    )


def _policy() -> dict:
    return {
        "schema": "factory.policy.v1",
        "risk": {
            "default": "supervised",
            "require_human_approval_for": ["production-deploy", "security"],
        },
        "quality": {
            "require_hollow_tests": True,
            "require_hollow_validators": True,
            "min_goldens": 1,
            "max_complexity_delta": 10,
        },
        "tokens": {"require_meter": True, "max_estimated_cost_usd": 5.0},
        "design": {"purpose_profile": "developer", "require_prestige_audit": True},
        "release": {
            "require_clean_install": True,
            "require_license": True,
            "require_ci": True,
        },
    }


def test_compiler_is_key_order_invariant_and_hash_bound(tmp_path: Path):
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(json.dumps(_policy(), indent=2), encoding="utf-8")
    reordered = {
        "release": _policy()["release"],
        "design": _policy()["design"],
        "schema": "factory.policy.v1",
        "tokens": _policy()["tokens"],
        "quality": _policy()["quality"],
        "risk": _policy()["risk"],
    }
    second.write_text(json.dumps(reordered, indent=2), encoding="utf-8")

    left = compile_policy(tmp_path, first)
    right = compile_policy(tmp_path, second)

    assert left["status"] == "COMPILED"
    assert left["policy_sha256"] == right["policy_sha256"]
    assert left["manifest_sha256"] == right["manifest_sha256"]
    assert [item["id"] for item in left["checks"]] == sorted(
        item["id"] for item in left["checks"]
    )
    assert {
        item["action_class"] for item in left["human_gates"] if "action_class" in item
    } == {"production-deploy", "security"}
    assert left["authority"] == {
        "execute": False,
        "merge": False,
        "deploy": False,
        "release": False,
        "billing": False,
    }


def test_unknown_rules_are_visible_and_fail_closed(tmp_path: Path):
    path = tmp_path / "policy.json"
    payload = _policy()
    payload["quality"]["require_magic"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = compile_policy(tmp_path, path)

    assert result["status"] == "REVIEW_REQUIRED"
    assert {item["path"] for item in result["review_required"]} == {
        "quality.require_magic"
    }


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("quality", {"require_hollow_tests": "yes"}),
        ("risk", {"default": "magic"}),
        ("tokens", {"max_estimated_cost_usd": -1}),
    ],
)
def test_malformed_rules_are_visible(tmp_path: Path, path: str, value: dict):
    policy = {"schema": "factory.policy.v1", path: value}
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    result = compile_policy(tmp_path, policy_path)

    assert result["status"] == "REVIEW_REQUIRED"
    assert result["review_required"]


def test_wrong_schema_and_workspace_escape_are_rejected(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "factory.policy.v0"}), encoding="utf-8")
    with pytest.raises(PolicyCompileError, match="schema"):
        compile_policy(tmp_path, bad)
    with pytest.raises(PolicyCompileError, match="inside the workspace"):
        compile_policy(tmp_path, Path("..") / "outside.json")


def test_write_and_cli_emit_the_same_manifest(tmp_path: Path, capsys):
    policy_path = tmp_path / "factory.policy.json"
    out = tmp_path / ".factory" / "ops" / "policy-checks.json"
    policy_path.write_text(json.dumps(_policy()), encoding="utf-8")

    expected = write_compiled_policy(tmp_path, policy_path, out)
    assert out.exists()
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["manifest_sha256"] == expected["manifest_sha256"]
    assert written["marker"] == "POLICY_CLI_WRITTEN"

    assert (
        main(
            ["ops", "policy", "factory.policy.json", "--root", str(tmp_path), "--json"]
        )
        == 0
    )
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["status"] == "COMPILED"
    assert emitted["policy_sha256"] == expected["policy_sha256"]


THIN_PRD = "# Draft\n\nA useful idea without a product contract.\n"

COMPLETE_PRD = """# Signal Desk

## Actors
- Operator: reviews customer signals.

## Outcomes
- Reduce signal triage time below five minutes.

## Journeys and business rules
- Journey: an operator captures a signal, reviews its priority reason, then exports an audit report.
- Business rule: private signals require an authenticated operator.

## Data ownership and trust boundaries
- Data ownership: the workspace owner controls retention, export, and deletion.
- Trust boundary: signal content stays inside the selected workspace.

## External effects and approvals
- External effect: exporting a report writes a user-selected local file.
- Approval: publishing, deployment, credentials, and external messages require a human owner.

## Success events
- signal_review_completed within five minutes.

## Requirements
- REQ-DASH: The operator must see prioritized signals and their reasons.

## Experience states
- Loading: show progress without moving the dashboard layout.
- Empty: explain how to connect the first signal source.
- Error: preserve the last safe view and offer retry.
- Success: confirm the completed action.
- Permission: explain which role is required.
- Offline: preserve read-only cached signals.
- Recovery: resume the interrupted action without duplication.
- Accessibility: expose names, roles, focus order, and keyboard operation.

## Acceptance
Scenario: Review the most important signal
  Given an authenticated operator with prioritized signals
  When the operator opens the dashboard
  Then the highest-priority signal is visible with its reason
"""


def test_prd_grill_writes_a_bounded_frontier_without_mutating_source(
    tmp_path: Path,
) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")

    result = grill_prd(prd, tmp_path, mode="quick")

    assert prd.read_text(encoding="utf-8") == THIN_PRD
    assert result["status"] == "needs_input"
    assert len(result["questions"]) == 3
    assert [question["id"] for question in result["questions"]] == [
        "Q-REQUIREMENTS",
        "Q-ACTORS",
        "Q-OUTCOMES",
    ]
    deferred = {question["id"]: question for question in result["deferred_questions"]}
    assert deferred["Q-ACCEPTANCE"]["deferred_by"] == ["Q-REQUIREMENTS"]
    assert deferred["Q-JOURNEY"]["deferred_by"] == ["Q-ACTORS"]
    assert deferred["Q-SUCCESS-EVENT"]["deferred_by"] == ["Q-OUTCOMES"]
    assert result["authority"] == {
        "implementation": "not_authorized",
        "external_effects": "not_authorized",
    }
    assert (
        Path(result["markdown"]).read_text(encoding="utf-8").count("**Answer:**") == 3
    )
    assert verify_prd_grill(Path(result["path"]))["valid"] is True

    replay = grill_prd(prd, tmp_path, mode="quick")
    assert replay["idempotent"] is True
    assert replay["generated_at"] == result["generated_at"]


def test_prd_grill_confirms_only_a_complete_reviewed_contract(tmp_path: Path) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(COMPLETE_PRD, encoding="utf-8")

    analysis = analyze_product_text(COMPLETE_PRD, source_name="PRD.md")
    assert analysis["gaps"] == []
    assert not (tmp_path / ".factory" / "products").exists()

    result = grill_prd(prd, tmp_path, mode="deep", confirm=True)

    assert result["status"] == "confirmed"
    assert result["questions"] == []
    assert "PRD_GRILL_SHARED_UNDERSTANDING_CONFIRMED" in result["markers"]


def test_compile_product_text_still_writes_the_reviewable_product_graph(
    tmp_path: Path,
) -> None:
    graph = compile_product_text(COMPLETE_PRD, root=tmp_path, source_name="PRD.md")

    assert graph["schema"] == "factory.product_graph.v1"
    assert Path(graph["path"]).is_file()


def test_prd_grill_refuses_confirmation_while_decisions_remain(tmp_path: Path) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")

    with pytest.raises(ProductMissionError, match="PRD_GRILL_UNRESOLVED"):
        grill_prd(prd, tmp_path, confirm=True)
    assert not (tmp_path / ".factory" / "prd-grills").exists()


def test_prd_grill_cli_is_machine_readable_and_verifiable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")

    assert main(["prd", "grill", str(prd), "--root", str(tmp_path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert main(["prd", "verify", result["path"], "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["marker"] == "PRD_GRILL_VERIFIED"


def test_prd_grill_rejects_invalid_source_without_artifacts(tmp_path: Path) -> None:
    broken = tmp_path / "broken.md"
    broken.write_bytes(b"\xff")

    with pytest.raises(ProductMissionError, match="PRD_ENCODING_INVALID"):
        grill_prd(broken, tmp_path)
    assert not (tmp_path / ".factory" / "prd-grills").exists()


def test_beginner_interview_has_one_next_decision_and_no_implicit_approval(tmp_path):
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")
    result = grill_prd(prd, tmp_path, mode="deep")
    interview = result["interview"]
    assert interview["next_question_id"] == result["questions"][0]["id"]
    assert interview["decision_owner"] == "user"
    assert "Never treat silence as acceptance" in interview["answer_handling"]
    assert interview["unresolved_gap_codes"] == [
        gap["code"] for gap in result["observed_gaps"]
    ]
    assert "Q-JOURNEY" not in [q["id"] for q in result["questions"]]
    assert "EARS" not in result["questions"][0]["recommendation"]
    assert verify_prd_grill(Path(result["path"]))["valid"]


def test_confirmed_interview_does_not_claim_development_evidence(tmp_path):
    prd = tmp_path / "PRD.md"
    prd.write_text(COMPLETE_PRD, encoding="utf-8")
    result = grill_prd(prd, tmp_path, mode="deep", confirm=True)
    assert result["interview"]["next_question_id"] is None
    assert result["interview"]["unresolved_gap_codes"] == []
    assert "not proof" in result["interview"]["readiness"]
    assert result["authority"]["implementation"] == "not_authorized"


def test_answered_prd_recomputes_next_question_and_preserves_prior_source(tmp_path):
    prd = tmp_path / "PRD.md"
    prd.write_text(THIN_PRD, encoding="utf-8")
    before = grill_prd(prd, tmp_path, mode="deep")
    prd.write_text(COMPLETE_PRD, encoding="utf-8")
    after = grill_prd(prd, tmp_path, mode="deep")
    assert after["source"]["sha256"] != before["source"]["sha256"]
    assert after["status"] == "ready_for_confirmation"
    assert after["interview"]["next_question_id"] is None
    assert Path(before["source_copy"]).read_text(encoding="utf-8") == THIN_PRD
    assert verify_prd_grill(Path(before["path"]))["valid"]


def test_generated_junie_guidance_contains_beginner_native_prd_route():
    from factoryline.junie_taxonomy import _guidance, _junie_proof_agent_bytes

    guidance = _guidance().decode("utf-8")
    assert "factory prd grill PRD.md" in guidance
    assert "one ready question at a time" in guidance
    assert "never accept silence as approval" in guidance
    assert "## Beginner app-building" not in _junie_proof_agent_bytes().decode()


def _e2e() -> dict[str, object]:
    return {
        "schema": "factory.e2e_proof_manifest.v1",
        "id": "approval-flow-e2e",
        "approval": {"state": "approved", "approved_by": "reviewer"},
        "working_directory": ".",
        "timeout_seconds": 10,
        "network_egress": "not_granted",
        "positive": {
            "argv": [
                sys.executable,
                "-c",
                "from pathlib import Path; Path('proof.txt').write_text('approved')",
            ]
        },
        "negative": {"argv": [sys.executable, "-c", "import sys; sys.exit(1)"]},
        "artifact_paths": ["proof.txt"],
    }


def _reality() -> dict[str, object]:
    return {
        "schema": "factory.reality-check-manifest.v1",
        "id": "approval-flow",
        "approval": {"state": "approved", "approved_by": "reviewer"},
        "behavior": {
            "promise": "A manager can approve a request.",
            "happy_path": "Approved request is recorded.",
            "failure_case": "A non-manager cannot approve.",
        },
        "intent_assertions": [
            {
                "id": "manager-can-approve",
                "statement": "Manager approval is recorded.",
                "evidence": "positive",
            },
            {
                "id": "non-manager-blocked",
                "statement": "Non-manager approval is rejected.",
                "evidence": "negative",
            },
        ],
        "e2e_manifest": "approval.e2e.json",
    }


def _write(root: Path, *, negative: list[str] | None = None) -> Path:
    e2e = _e2e()
    if negative is not None:
        e2e["negative"] = {"argv": negative}
    (root / "approval.e2e.json").write_text(json.dumps(e2e), encoding="utf-8")
    manifest = root / "approval.reality.json"
    manifest.write_text(json.dumps(_reality()), encoding="utf-8")
    return manifest


def test_validate_reality_check_manifest_requires_approved_behavior_contract(
    tmp_path: Path,
) -> None:
    manifest = _write(tmp_path)
    validated = validate_reality_check_manifest(tmp_path, manifest)
    assert validated["id"] == "approval-flow"
    assert validated["e2e_manifest"]["path"] == "approval.e2e.json"


def test_reality_check_rejects_unresolved_behavior_intent(tmp_path: Path) -> None:
    manifest = _write(tmp_path)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["behavior"]["promise"] = "Make it better."
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RealityCheckError) as exc:
        validate_reality_check_manifest(tmp_path, manifest)
    assert exc.value.code == "REALITY_CHECK_INTENT_UNCLEAR"


def test_inspect_reality_intent_reports_deep_positive_and_negative_coverage_without_execution(
    tmp_path: Path,
) -> None:
    inspection = inspect_reality_intent(tmp_path, _write(tmp_path))
    assert inspection["marker"] == "REALITY_INTENT_CONTRACT_READY"
    assert inspection["execution"] is False
    assert inspection["positive_assertion_ids"] == ["manager-can-approve"]
    assert inspection["negative_assertion_ids"] == ["non-manager-blocked"]


def test_reality_check_binds_a_behavior_to_proof_by_sabotage_and_writes_public_artifacts(
    tmp_path: Path,
) -> None:
    receipt = run_reality_check(tmp_path, _write(tmp_path))
    assert receipt["marker"] == "REALITY_CHECK_VERIFIED"
    assert receipt["ok"] is True
    assert (
        receipt["manifest"]["behavior"]["failure_case"]
        == "A non-manager cannot approve."
    )
    assert receipt["e2e_receipt"]["marker"] == "E2E_PROOF_PASS"
    assert all(item["verified"] for item in receipt["intent_verification"])
    assert all(
        value is False
        for key, value in receipt["authority"].items()
        if key not in {"execution", "test_execution"}
    )
    assert validate_reality_check_receipt(receipt) is receipt
    paths = write_reality_check_artifacts(receipt, tmp_path / "packet")
    assert all(Path(path).is_file() for path in paths.values())


def test_reality_check_reports_hollow_negative_and_tamper_fails_closed(
    tmp_path: Path,
) -> None:
    receipt = run_reality_check(
        tmp_path, _write(tmp_path, negative=[sys.executable, "-c", "pass"])
    )
    assert (receipt["marker"], receipt["ok"]) == ("REALITY_CHECK_HOLLOW", False)
    receipt["manifest"]["behavior"]["promise"] = "tampered"
    with pytest.raises(RealityCheckError, match="SHA-256"):
        validate_reality_check_receipt(receipt)


def test_reality_check_cli_returns_zero_only_for_verified_behavior(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _write(tmp_path)
    assert (
        main(
            [
                "reality",
                "inspect",
                "--root",
                str(tmp_path),
                "--manifest",
                manifest.name,
                "--json",
            ]
        )
        == 0
    )
    assert (
        json.loads(capsys.readouterr().out)["marker"] == "REALITY_INTENT_CONTRACT_READY"
    )
    assert (
        main(
            [
                "reality",
                "verify",
                "--root",
                str(tmp_path),
                "--manifest",
                manifest.name,
                "--json",
            ]
        )
        == 0
    )
    assert (
        json.loads(capsys.readouterr().out)["receipt"]["marker"]
        == "REALITY_CHECK_VERIFIED"
    )
    _write(tmp_path, negative=[sys.executable, "-c", "pass"])
    assert (
        main(
            [
                "reality",
                "verify",
                "--root",
                str(tmp_path),
                "--manifest",
                manifest.name,
                "--json",
            ]
        )
        == 1
    )
    assert (
        json.loads(capsys.readouterr().out)["receipt"]["marker"]
        == "REALITY_CHECK_HOLLOW"
    )


def test_reality_check_rejects_unapproved_contract_without_executing(
    tmp_path: Path,
) -> None:
    manifest = _write(tmp_path)
    value = _reality()
    value["approval"] = {"state": "pending", "approved_by": "reviewer"}
    manifest.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(RealityCheckError, match="approved"):
        run_reality_check(tmp_path, manifest)

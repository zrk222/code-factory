from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.learning_loop import (
    LearningLoopError,
    OBSERVER_GATE_PAYLOAD_TYPE,
    OBSERVER_GATES,
    build_fresh_worker_packet,
    diagnose_forensic_rejection,
    init_learning_task,
    plan_learning_experiment,
    promote_instruction_candidate,
    propose_instruction_candidate,
    restore_instruction_promotion,
    seal_forensic_rejection_packet,
    validate_forensic_rejection_packet,
    validate_instruction_candidate,
)
from factoryline.enterprise_receipts import generate_key_material, sign_payload


MILESTONES = [
    {
        "id": "spec",
        "criteria": [
            {"id": "requirements", "statement": "Requirements are executable."}
        ],
    },
    {
        "id": "runtime",
        "criteria": [{"id": "smoke", "statement": "Runtime smoke passes."}],
    },
]

OBSERVER_MILESTONES = [
    {
        "id": "skill-repair",
        "criteria": [
            {"id": key, "statement": f"Run and bind {key}."}
            for key in (
                "forensic-replay",
                "holdout-regression",
                "false-positive-control",
                "specialty-ai-review",
            )
        ],
    }
]


def _observer_candidate(tmp_path: Path):
    evidence = tmp_path / "rejection.json"
    evidence.write_text('{"mutation":"survived"}\n', encoding="utf-8")
    candidate_sha = "a" * 64
    source_sha = "b" * 64
    packet = seal_forensic_rejection_packet(
        tmp_path,
        {
            "schema": "factory.forensic-rejection.v1",
            "candidate_sha256": candidate_sha,
            "source_sha256": source_sha,
            "failure_class": "mutation_survivor",
            "failure_id": "mutant-survived-01",
            "failed_mutation_seeds": [
                {
                    "id": "mutant-01",
                    "seed_sha256": "c" * 64,
                    "expected": "test failure",
                    "observed": "test pass",
                    "evidence_id": "mutation-run",
                }
            ],
            "policy_breaches": [],
            "counterfactual_profiles": [],
            "review_corrections": [],
            "validator_versions": [{"name": "factory", "version": "0.47.0"}],
            "evidence_bindings": [
                {
                    "id": "mutation-run",
                    "kind": "mutation-test",
                    "path": str(evidence),
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                }
            ],
            "unknowns": [],
        },
    )
    packet_path = tmp_path / "forensic.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    task = init_learning_task(
        tmp_path, "observer", "owner", "Harden worker test skills", OBSERVER_MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text(
        json.dumps({"candidate_sha256": candidate_sha, "source_sha256": source_sha}),
        encoding="utf-8",
    )
    candidate = propose_instruction_candidate(
        Path(task["path"]),
        tmp_path,
        "skill-repair",
        "observer-agent",
        outcome,
        [
            {
                "dimension": "d6_output_processing",
                "instruction": "Assert the mutated state is rejected.",
            }
        ],
        forensic_packet_path=packet_path,
    )
    return task, candidate, packet_path, packet


def _observer_gate_evidence(
    tmp_path: Path,
    packet: dict,
    *,
    signed: bool = True,
    runner_role: str = "observer-gate-runner",
):
    trust_dir = tmp_path.parent / f"{tmp_path.name}-observer-trust"
    runner = generate_key_material(
        out_dir=trust_dir / "runner",
        keyid="audit-runner",
        identity="factory-audit:runner",
        issuer="https://audit.example",
    )
    reviewer = generate_key_material(
        out_dir=trust_dir / "reviewer",
        keyid="specialty-reviewer",
        identity="specialty-ai:cf-reviewer",
        issuer="https://review.example",
    )
    trust_root = trust_dir / "trust-root.json"
    trust_root.write_text(
        json.dumps(
            {
                "schema": "factory.trust.root.v1",
                "version": 1,
                "keys": [
                    {
                        "keyid": key["keyid"],
                        "algorithm": "ed25519",
                        "public_key": Path(key["public_key"])
                        .read_text(encoding="ascii")
                        .strip(),
                        "identity": key["identity"],
                        "issuer": key["issuer"],
                        "roles": [
                            runner_role if key is runner else "specialty-ai-reviewer"
                        ],
                    }
                    for key in (runner, reviewer)
                ],
            }
        ),
        encoding="utf-8",
    )
    results = []
    for gate in sorted(OBSERVER_GATES):
        is_review = gate == "specialty-ai-review"
        payload = {
            "schema": (
                "factory.specialty-ai-review.v1"
                if is_review
                else "factory.observer-replay.v1"
            ),
            "candidate_sha256": packet["candidate_sha256"],
            "forensic_packet_sha256": packet["packet_sha256"],
        }
        if is_review:
            payload.update(
                {
                    "reviewer_agent": "specialty-ai:cf-reviewer",
                    "verdict": "APPROVE",
                    "findings": [],
                }
            )
        else:
            payload.update({"check_id": gate, "result": "PASS"})
        key = reviewer if is_review else runner
        evidence = payload
        if signed:
            evidence = sign_payload(
                payload,
                payload_type=OBSERVER_GATE_PAYLOAD_TYPE,
                private_key_path=Path(key["private_key"]),
                keyid=key["keyid"],
                identity=key["identity"],
                issuer=key["issuer"],
            )
        path = tmp_path / f"{gate}.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        results.append({"id": gate, "passed": True, "evidence": [str(path)]})
    return results, trust_root


def _candidate(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text('{"requirements": "passed"}\n', encoding="utf-8")
    candidate = propose_instruction_candidate(
        Path(task["path"]),
        tmp_path,
        "spec",
        "worker-1",
        outcome,
        [
            {
                "dimension": "d6_output_processing",
                "instruction": "Run the strict requirement mutation gate before implementation.",
            }
        ],
    )
    evidence = tmp_path / "strict.json"
    evidence.write_text('{"valid": true}\n', encoding="utf-8")
    return task, candidate, evidence


def test_fresh_packet_excludes_prior_reasoning_and_worker_outputs(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    packet = build_fresh_worker_packet(Path(task["path"]), "spec", "worker-2")
    assert packet["context"] == {
        "fresh": True,
        "prior_reasoning": [],
        "prior_worker_outputs": [],
    }
    assert packet["instructions"] == []
    assert packet["authority"]["promote_instructions"] is False


def test_candidate_cannot_self_validate(tmp_path: Path):
    _task, candidate, evidence = _candidate(tmp_path)
    results = [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
    with pytest.raises(LearningLoopError, match="VALIDATOR_IDENTITY_DISTINCT"):
        validate_instruction_candidate(
            Path(candidate["path"]), tmp_path, "worker-1", results
        )


def test_validation_requires_exact_complete_criteria(tmp_path: Path):
    _task, candidate, _evidence = _candidate(tmp_path)
    with pytest.raises(LearningLoopError, match="MILESTONE_VALIDATION_INCOMPLETE"):
        validate_instruction_candidate(
            Path(candidate["path"]), tmp_path, "validator", []
        )


def test_human_promotes_validated_candidate_to_aku_and_next_milestone(tmp_path: Path):
    task, candidate, evidence = _candidate(tmp_path)
    results = [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
    validation = validate_instruction_candidate(
        Path(candidate["path"]), tmp_path, "validator", results
    )
    promotion = promote_instruction_candidate(Path(validation["path"]), "owner")
    assert promotion["aku"]["procedure"] == candidate["instructions"]
    assert promotion["aku"]["metadata"]["control_dimensions"] == [
        "d6_output_processing"
    ]
    assert promotion["aku"]["governance"]["autonomy"] == "supervised"
    assert "HUMAN_PROMOTION_BOUND" in promotion["markers"]

    refined_packet = build_fresh_worker_packet(Path(task["path"]), "spec", "worker-2")
    assert refined_packet["instructions"] == candidate["instructions"]
    assert (
        refined_packet["harness_adaptation"]["d6_output_processing"]
        == candidate["instructions"]
    )
    assert refined_packet["context"]["prior_worker_outputs"] == []

    packet = build_fresh_worker_packet(Path(task["path"]), "runtime", "worker-2")
    assert packet["milestone"]["id"] == "runtime"
    assert packet["context"]["prior_reasoning"] == []


def test_promotion_history_is_immutable_and_owner_can_restore_prior_version(
    tmp_path: Path, capsys
):
    task, candidate, evidence = _candidate(tmp_path)
    validation = validate_instruction_candidate(
        Path(candidate["path"]),
        tmp_path,
        "validator-1",
        [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}],
    )
    first = promote_instruction_candidate(Path(validation["path"]), "owner")

    outcome2 = tmp_path / "outcome-v2.json"
    outcome2.write_text('{"requirements": "revised"}\n', encoding="utf-8")
    candidate2 = propose_instruction_candidate(
        Path(task["path"]),
        tmp_path,
        "spec",
        "worker-2",
        outcome2,
        [
            {
                "dimension": "d6_output_processing",
                "instruction": "Assert both accepted and rejected boundary cases.",
            }
        ],
    )
    evidence2 = tmp_path / "strict-v2.json"
    evidence2.write_text('{"valid": true, "boundaries": true}\n', encoding="utf-8")
    validation2 = validate_instruction_candidate(
        Path(candidate2["path"]),
        tmp_path,
        "validator-2",
        [{"id": "requirements", "passed": True, "evidence": [str(evidence2)]}],
    )
    second = promote_instruction_candidate(
        Path(validation2["path"]), "owner", force=True
    )
    history = (
        Path(second["path"]).parent
        / "history"
        / (f"spec-{first['promotion_sha256'][:16]}.json")
    )
    assert (
        json.loads(history.read_text(encoding="utf-8"))["promotion_sha256"]
        == first["promotion_sha256"]
    )

    with pytest.raises(LearningLoopError, match="OWNER_MISMATCH"):
        restore_instruction_promotion(
            Path(task["path"]), "different-owner", first["promotion_sha256"]
        )
    assert (
        main(
            [
                "learning",
                "promote",
                "--restore",
                first["promotion_sha256"],
                "--task",
                task["path"],
                "--owner",
                "owner",
                "--json",
            ]
        )
        == 0
    )
    restored = json.loads(capsys.readouterr().out)
    assert restored["restored"] is True
    assert restored["promotion_sha256"] == first["promotion_sha256"]
    active = json.loads(Path(restored["path"]).read_text(encoding="utf-8"))
    assert active["promotion_sha256"] == first["promotion_sha256"]
    assert restored["rollback"]["from_promotion_sha256"] == second["promotion_sha256"]
    assert restored["rollback"]["to_promotion_sha256"] == first["promotion_sha256"]
    assert (
        build_fresh_worker_packet(Path(task["path"]), "spec", "worker-after-rollback")[
            "instruction_version"
        ]
        == 1
    )


def test_rollback_rejects_unknown_promotion_hash(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    with pytest.raises(LearningLoopError, match="PROMOTION_HISTORY_NOT_FOUND"):
        restore_instruction_promotion(Path(task["path"]), "owner", "a" * 64)


def test_candidate_rejects_unclassified_harness_edit(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text("{}\n", encoding="utf-8")
    with pytest.raises(LearningLoopError, match="INSTRUCTION_CANDIDATE_INVALID"):
        propose_instruction_candidate(
            Path(task["path"]),
            tmp_path,
            "spec",
            "worker",
            outcome,
            [{"dimension": "prompt_magic", "instruction": "Try harder."}],
        )


def test_forensic_observer_binds_packet_replay_specialty_review_and_deferred_skill(
    tmp_path: Path,
):
    task, candidate, packet_path, packet = _observer_candidate(tmp_path)
    verified = validate_forensic_rejection_packet(tmp_path, packet_path)
    diagnosis = diagnose_forensic_rejection(verified)
    assert diagnosis["cause"] == "weak_oracle_or_assertion"
    assert diagnosis["confidence"] == "hypothesis_requires_replay"
    assert candidate["forensic_rejection"]["packet_sha256"] == packet["packet_sha256"]

    results, trust_root = _observer_gate_evidence(tmp_path, packet)

    validation = validate_instruction_candidate(
        Path(candidate["path"]),
        tmp_path,
        "specialty-ai:cf-reviewer",
        results,
        observer_trust_root=trust_root,
    )
    promotion = promote_instruction_candidate(Path(validation["path"]), "owner")
    packet = build_fresh_worker_packet(
        Path(task["path"]), "skill-repair", "worker-next"
    )
    assert (
        promotion["aku"]["metadata"]["provenance"]["forensic_packet_sha256"]
        == verified["packet_sha256"]
    )
    assert packet["instruction_version"] == 1
    assert packet["instructions"] == candidate["instructions"]


def test_forensic_observer_rejects_unsigned_gate_receipts(tmp_path: Path):
    _, candidate, _, packet = _observer_candidate(tmp_path)
    results, trust_root = _observer_gate_evidence(tmp_path, packet, signed=False)
    with pytest.raises(LearningLoopError, match="OBSERVER_SIGNATURE_INVALID"):
        validate_instruction_candidate(
            Path(candidate["path"]),
            tmp_path,
            "specialty-ai:cf-reviewer",
            results,
            observer_trust_root=trust_root,
        )


def test_forensic_observer_rejects_trusted_key_without_gate_role(tmp_path: Path):
    _, candidate, _, packet = _observer_candidate(tmp_path)
    results, trust_root = _observer_gate_evidence(
        tmp_path, packet, runner_role="worker"
    )
    with pytest.raises(LearningLoopError, match="OBSERVER_SIGNATURE_INVALID"):
        validate_instruction_candidate(
            Path(candidate["path"]),
            tmp_path,
            "specialty-ai:cf-reviewer",
            results,
            observer_trust_root=trust_root,
        )


def test_forensic_observer_requires_trust_root_outside_candidate_workspace(
    tmp_path: Path,
):
    _, candidate, _, packet = _observer_candidate(tmp_path)
    results, _ = _observer_gate_evidence(tmp_path, packet)
    in_workspace = tmp_path / "untrusted-root.json"
    in_workspace.write_text("{}", encoding="utf-8")
    with pytest.raises(LearningLoopError, match="OBSERVER_TRUST_ROOT_IN_WORKSPACE"):
        validate_instruction_candidate(
            Path(candidate["path"]),
            tmp_path,
            "specialty-ai:cf-reviewer",
            results,
            observer_trust_root=in_workspace,
        )


def test_forensic_observer_rejects_missing_gates_and_mismatched_outcome(tmp_path: Path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}\n", encoding="utf-8")
    packet = seal_forensic_rejection_packet(
        tmp_path,
        {
            "schema": "factory.forensic-rejection.v1",
            "candidate_sha256": "a" * 64,
            "source_sha256": "b" * 64,
            "failure_class": "policy_breach",
            "failure_id": "complexity",
            "failed_mutation_seeds": [],
            "policy_breaches": [
                {
                    "id": "breach",
                    "rule_id": "complexity-10",
                    "severity": "high",
                    "evidence_id": "audit",
                }
            ],
            "counterfactual_profiles": [],
            "review_corrections": [],
            "validator_versions": [{"name": "forge", "version": "1"}],
            "evidence_bindings": [
                {
                    "id": "audit",
                    "kind": "audit",
                    "path": str(evidence),
                    "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                }
            ],
            "unknowns": [],
        },
    )
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet), encoding="utf-8")
    task = init_learning_task(
        tmp_path, "observer", "owner", "Fix complexity", MILESTONES
    )
    outcome = tmp_path / "outcome.json"
    outcome.write_text(
        json.dumps({"candidate_sha256": "a" * 64, "source_sha256": "b" * 64}),
        encoding="utf-8",
    )
    with pytest.raises(LearningLoopError, match="OBSERVER_GATES_INCOMPLETE"):
        propose_instruction_candidate(
            Path(task["path"]),
            tmp_path,
            "spec",
            "observer",
            outcome,
            [{"dimension": "d4_orchestration", "instruction": "Split decisions."}],
            forensic_packet_path=packet_path,
        )


def test_asha_experiment_is_correctness_first_and_has_no_execution_authority(
    tmp_path: Path,
):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    plan = plan_learning_experiment(
        Path(task["path"]),
        {
            "d1_context_assembly": ["compact", "retrieval"],
            "d4_orchestration": ["plan-execute", "plan-refine"],
        },
        variant="asha",
        max_resource=50,
        grace_period=5,
        reduction_factor=3,
    )
    assert plan["scheduler"]["asynchronous"] is True
    assert plan["objective"]["primary"] == {
        "metric": "correctness",
        "mode": "max",
        "required": True,
        "range": [0.0, 1.0],
    }
    assert plan["authority"] == {
        "execute": False,
        "read_credentials": False,
        "train": False,
        "promote": False,
    }


def test_experiment_rejects_unknown_dimensions_and_unbounded_budget(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    with pytest.raises(LearningLoopError, match="SEARCH_SPACE_INVALID"):
        plan_learning_experiment(Path(task["path"]), {"prompt_magic": [True]})
    with pytest.raises(LearningLoopError, match="SEARCH_BUDGET_INVALID"):
        plan_learning_experiment(
            Path(task["path"]),
            {"d1_context_assembly": ["compact"]},
            max_concurrent=1001,
        )


def test_milestone_order_is_fail_closed(tmp_path: Path):
    task = init_learning_task(
        tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES
    )
    with pytest.raises(LearningLoopError, match="MILESTONE_ORDER_BLOCKED"):
        build_fresh_worker_packet(Path(task["path"]), "runtime", "worker-2")


def test_promotion_rechecks_evidence_hashes(tmp_path: Path):
    _task, candidate, evidence = _candidate(tmp_path)
    validation = validate_instruction_candidate(
        Path(candidate["path"]),
        tmp_path,
        "validator",
        [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}],
    )
    evidence.write_text('{"valid": false}\n', encoding="utf-8")
    with pytest.raises(LearningLoopError, match="HASH_INVALID"):
        promote_instruction_candidate(Path(validation["path"]), "owner")


def test_cli_runs_complete_learning_lane(tmp_path: Path, capsys):
    milestones = tmp_path / "milestones.json"
    milestones.write_text(json.dumps(MILESTONES), encoding="utf-8")
    assert (
        main(
            [
                "learning",
                "init",
                "checkout",
                "--root",
                str(tmp_path),
                "--owner",
                "owner",
                "--objective",
                "Ship verified checkout",
                "--milestones",
                str(milestones),
                "--json",
            ]
        )
        == 0
    )
    task = json.loads(capsys.readouterr().out)

    outcome = tmp_path / "outcome.json"
    outcome.write_text('{"requirements": "passed"}\n', encoding="utf-8")
    instructions = tmp_path / "instructions.json"
    instructions.write_text(
        json.dumps(
            [
                {
                    "dimension": "d6_output_processing",
                    "instruction": "Run strict validation.",
                }
            ]
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "learning",
                "propose",
                task["path"],
                "--root",
                str(tmp_path),
                "--milestone",
                "spec",
                "--worker",
                "worker",
                "--outcome",
                str(outcome),
                "--instructions",
                str(instructions),
                "--json",
            ]
        )
        == 0
    )
    candidate = json.loads(capsys.readouterr().out)

    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    results = tmp_path / "results.json"
    results.write_text(
        json.dumps(
            [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
        ),
        encoding="utf-8",
    )
    assert (
        main(
            [
                "learning",
                "validate",
                candidate["path"],
                "--root",
                str(tmp_path),
                "--validator",
                "validator",
                "--results",
                str(results),
                "--json",
            ]
        )
        == 0
    )
    validation = json.loads(capsys.readouterr().out)
    assert (
        main(["learning", "promote", validation["path"], "--owner", "owner", "--json"])
        == 0
    )
    promotion = json.loads(capsys.readouterr().out)
    assert promotion["aku"]["procedure"] == ["Run strict validation."]

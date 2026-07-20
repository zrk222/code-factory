from __future__ import annotations

import json
from pathlib import Path

import pytest

from factoryline.cli import main
from factoryline.learning_loop import (
    LearningLoopError,
    build_fresh_worker_packet,
    init_learning_task,
    plan_learning_experiment,
    promote_instruction_candidate,
    propose_instruction_candidate,
    validate_instruction_candidate,
)


MILESTONES = [
    {"id": "spec", "criteria": [{"id": "requirements", "statement": "Requirements are executable."}]},
    {"id": "runtime", "criteria": [{"id": "smoke", "statement": "Runtime smoke passes."}]},
]


def _candidate(tmp_path: Path):
    task = init_learning_task(tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES)
    outcome = tmp_path / "outcome.json"
    outcome.write_text('{"requirements": "passed"}\n', encoding="utf-8")
    candidate = propose_instruction_candidate(
        Path(task["path"]), tmp_path, "spec", "worker-1", outcome,
        [{"dimension": "d6_output_processing", "instruction": "Run the strict requirement mutation gate before implementation."}],
    )
    evidence = tmp_path / "strict.json"
    evidence.write_text('{"valid": true}\n', encoding="utf-8")
    return task, candidate, evidence


def test_fresh_packet_excludes_prior_reasoning_and_worker_outputs(tmp_path: Path):
    task = init_learning_task(tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES)
    packet = build_fresh_worker_packet(Path(task["path"]), "spec", "worker-2")
    assert packet["context"] == {"fresh": True, "prior_reasoning": [], "prior_worker_outputs": []}
    assert packet["instructions"] == []
    assert packet["authority"]["promote_instructions"] is False


def test_candidate_cannot_self_validate(tmp_path: Path):
    _task, candidate, evidence = _candidate(tmp_path)
    results = [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
    with pytest.raises(LearningLoopError, match="VALIDATOR_IDENTITY_DISTINCT"):
        validate_instruction_candidate(Path(candidate["path"]), tmp_path, "worker-1", results)


def test_validation_requires_exact_complete_criteria(tmp_path: Path):
    _task, candidate, _evidence = _candidate(tmp_path)
    with pytest.raises(LearningLoopError, match="MILESTONE_VALIDATION_INCOMPLETE"):
        validate_instruction_candidate(Path(candidate["path"]), tmp_path, "validator", [])


def test_human_promotes_validated_candidate_to_aku_and_next_milestone(tmp_path: Path):
    task, candidate, evidence = _candidate(tmp_path)
    results = [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]
    validation = validate_instruction_candidate(Path(candidate["path"]), tmp_path, "validator", results)
    promotion = promote_instruction_candidate(Path(validation["path"]), "owner")
    assert promotion["aku"]["procedure"] == candidate["instructions"]
    assert promotion["aku"]["metadata"]["control_dimensions"] == ["d6_output_processing"]
    assert promotion["aku"]["governance"]["autonomy"] == "supervised"
    assert "HUMAN_PROMOTION_BOUND" in promotion["markers"]

    refined_packet = build_fresh_worker_packet(Path(task["path"]), "spec", "worker-2")
    assert refined_packet["instructions"] == candidate["instructions"]
    assert refined_packet["harness_adaptation"]["d6_output_processing"] == candidate["instructions"]
    assert refined_packet["context"]["prior_worker_outputs"] == []

    packet = build_fresh_worker_packet(Path(task["path"]), "runtime", "worker-2")
    assert packet["milestone"]["id"] == "runtime"
    assert packet["context"]["prior_reasoning"] == []


def test_candidate_rejects_unclassified_harness_edit(tmp_path: Path):
    task = init_learning_task(tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES)
    outcome = tmp_path / "outcome.json"
    outcome.write_text("{}\n", encoding="utf-8")
    with pytest.raises(LearningLoopError, match="INSTRUCTION_CANDIDATE_INVALID"):
        propose_instruction_candidate(
            Path(task["path"]), tmp_path, "spec", "worker", outcome,
            [{"dimension": "prompt_magic", "instruction": "Try harder."}],
        )


def test_asha_experiment_is_correctness_first_and_has_no_execution_authority(tmp_path: Path):
    task = init_learning_task(tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES)
    plan = plan_learning_experiment(
        Path(task["path"]),
        {
            "d1_context_assembly": ["compact", "retrieval"],
            "d4_orchestration": ["plan-execute", "plan-refine"],
        },
        variant="asha", max_resource=50, grace_period=5, reduction_factor=3,
    )
    assert plan["scheduler"]["asynchronous"] is True
    assert plan["objective"]["primary"] == {"metric": "correctness", "mode": "max", "required": True, "range": [0.0, 1.0]}
    assert plan["authority"] == {"execute": False, "read_credentials": False, "train": False, "promote": False}


def test_experiment_rejects_unknown_dimensions_and_unbounded_budget(tmp_path: Path):
    task = init_learning_task(tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES)
    with pytest.raises(LearningLoopError, match="SEARCH_SPACE_INVALID"):
        plan_learning_experiment(Path(task["path"]), {"prompt_magic": [True]})
    with pytest.raises(LearningLoopError, match="SEARCH_BUDGET_INVALID"):
        plan_learning_experiment(Path(task["path"]), {"d1_context_assembly": ["compact"]}, max_concurrent=1001)


def test_milestone_order_is_fail_closed(tmp_path: Path):
    task = init_learning_task(tmp_path, "checkout", "owner", "Ship verified checkout", MILESTONES)
    with pytest.raises(LearningLoopError, match="MILESTONE_ORDER_BLOCKED"):
        build_fresh_worker_packet(Path(task["path"]), "runtime", "worker-2")


def test_promotion_rechecks_evidence_hashes(tmp_path: Path):
    _task, candidate, evidence = _candidate(tmp_path)
    validation = validate_instruction_candidate(
        Path(candidate["path"]), tmp_path, "validator",
        [{"id": "requirements", "passed": True, "evidence": [str(evidence)]}],
    )
    evidence.write_text('{"valid": false}\n', encoding="utf-8")
    with pytest.raises(LearningLoopError, match="HASH_INVALID"):
        promote_instruction_candidate(Path(validation["path"]), "owner")


def test_cli_runs_complete_learning_lane(tmp_path: Path, capsys):
    milestones = tmp_path / "milestones.json"
    milestones.write_text(json.dumps(MILESTONES), encoding="utf-8")
    assert main([
        "learning", "init", "checkout", "--root", str(tmp_path), "--owner", "owner",
        "--objective", "Ship verified checkout", "--milestones", str(milestones), "--json",
    ]) == 0
    task = json.loads(capsys.readouterr().out)

    outcome = tmp_path / "outcome.json"
    outcome.write_text('{"requirements": "passed"}\n', encoding="utf-8")
    instructions = tmp_path / "instructions.json"
    instructions.write_text(json.dumps([{"dimension": "d6_output_processing", "instruction": "Run strict validation."}]), encoding="utf-8")
    assert main([
        "learning", "propose", task["path"], "--root", str(tmp_path), "--milestone", "spec",
        "--worker", "worker", "--outcome", str(outcome), "--instructions", str(instructions), "--json",
    ]) == 0
    candidate = json.loads(capsys.readouterr().out)

    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"passed": true}\n', encoding="utf-8")
    results = tmp_path / "results.json"
    results.write_text(json.dumps([{"id": "requirements", "passed": True, "evidence": [str(evidence)]}]), encoding="utf-8")
    assert main([
        "learning", "validate", candidate["path"], "--root", str(tmp_path),
        "--validator", "validator", "--results", str(results), "--json",
    ]) == 0
    validation = json.loads(capsys.readouterr().out)
    assert main(["learning", "promote", validation["path"], "--owner", "owner", "--json"]) == 0
    promotion = json.loads(capsys.readouterr().out)
    assert promotion["aku"]["procedure"] == ["Run strict validation."]

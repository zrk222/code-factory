"""Fail-closed six-lane runtime assurance decision and human projection."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    lane_result,
    guarded_lane_evaluator,
    read_stable_json,
    sha256_bytes,
)
from .runtime_audit_compatibility import evaluate_compatibility
from .runtime_audit_contract import LANES, verify_runtime_audit_plan
from .runtime_audit_migration import evaluate_migration
from .runtime_audit_performance import evaluate_performance
from .runtime_audit_recovery import evaluate_recovery
from .runtime_audit_runner import run_runtime_audit_plan
from .runtime_audit_stateful import evaluate_stateful
from .runtime_audit_tenant import evaluate_tenant
from .runtime_audit_integrity import (
    index_executions,
    repair_guidance,
    validate_receipt_decision,
)
from .runtime_attestation import runtime_boundary_decision
from .audit_action_refs import audit_remediation_packet

Evaluator = Callable[..., dict[str, Any]]
EVALUATORS: dict[str, Evaluator] = {
    "stateful_invariant": evaluate_stateful,
    "tenant_isolation": evaluate_tenant,
    "failure_recovery": evaluate_recovery,
    "consumer_compatibility": evaluate_compatibility,
    "migration_integrity": evaluate_migration,
    "performance_regression": evaluate_performance,
}
QUESTIONS = {
    "stateful_invariant": "Do approved business invariants survive generated action sequences?",
    "tenant_isolation": "Do real owner and denied requests preserve tenant and authorization boundaries?",
    "failure_recovery": "Do retries, concurrency and injected faults recover without duplicate or lost effects?",
    "consumer_compatibility": "Does the candidate still satisfy every signed consumer interaction?",
    "migration_integrity": "Can representative data migrate without drift, loss, broken readers or unproven recovery?",
    "performance_regression": "Does equivalent load preserve latency, error, capacity and memory/resource recovery limits?",
}
REMEDIATIONS = {
    "stateful_invariant": "Fix the failing transition or invariant, then rerun the signed state-machine pair.",
    "tenant_isolation": "Enforce server-derived tenant context for every affected data path, then rerun the signed matrix.",
    "failure_recovery": "Repair idempotency, atomicity or cleanup and rerun the exact fault schedule.",
    "consumer_compatibility": "Restore the missing consumer behavior or version the contract before rerunning verification.",
    "migration_integrity": "Use an expand-contract or corrective migration and repeat the isolated rehearsal and recovery.",
    "performance_regression": "Remove the regression or obtain a separately approved threshold change, then repeat equivalent load.",
}
SCOPE = "Evidence covers only the signed sources, commands, fixtures, environment digest and observed run; human release approval remains external."
NATIVE_ENGINES = {"hypothesis", "toxiproxy", "pact_verifier", "flyway", "k6"}
REPAIR_PRIORITY = {
    "tenant_isolation": 0,
    "migration_integrity": 1,
    "failure_recovery": 2,
    "consumer_compatibility": 3,
    "stateful_invariant": 4,
    "performance_regression": 5,
}
COMPOUND_SIGNALS = (
    ({"tenant_isolation", "failure_recovery"}, "retry_boundary_isolation_risk"),
    (
        {"migration_integrity", "consumer_compatibility"},
        "rolling_upgrade_consumer_risk",
    ),
    ({"performance_regression", "failure_recovery"}, "load_amplified_recovery_risk"),
    ({"stateful_invariant", "failure_recovery"}, "sequence_replay_side_effect_risk"),
)


def _fact_index(
    *,
    decision: str,
    candidate_sha256: str,
    mesh: dict[str, Any],
    lanes: list[dict[str, Any]],
    quality: list[dict[str, str]],
    repair_count: int,
) -> dict[str, Any]:
    """Build a sorted, typed, secret-free KV projection for local IDE and agent queries."""
    values: list[dict[str, Any]] = [
        {"key": "audit.decision", "type": "enum", "value": decision},
        {"key": "audit.candidate_sha256", "type": "sha256", "value": candidate_sha256},
        {
            "key": "mesh.scenario_sha256",
            "type": "sha256",
            "value": mesh["scenario_sha256"],
        },
        {"key": "repair.count", "type": "integer", "value": repair_count},
    ]
    grade_by_lane = {item["lane"]: item["grade"] for item in quality}
    for lane in lanes:
        prefix = f"lane.{lane['lane']}"
        values.extend(
            [
                {"key": f"{prefix}.state", "type": "enum", "value": lane["state"]},
                {"key": f"{prefix}.finding", "type": "code", "value": lane["finding"]},
                {
                    "key": f"{prefix}.evidence_sha256",
                    "type": "sha256_or_null",
                    "value": lane["evidence_digest"],
                },
                {
                    "key": f"{prefix}.quality",
                    "type": "enum",
                    "value": grade_by_lane[lane["lane"]],
                },
            ]
        )
    values.sort(key=lambda item: item["key"])
    projection = {
        "schema": "factory.runtime-audit-kv.v1",
        "mutable": False,
        "values": values,
    }
    projection["kv_sha256"] = sha256_bytes(canonical_bytes(projection))
    return projection


def _expected_termination_reason(facts: dict[str, Any]) -> str:
    for field, reason in (
        ("cancelled", "cancelled"),
        ("timed_out", "timeout"),
        ("output_limit_exceeded", "output_limit"),
        ("launch_error", "launch_error"),
    ):
        if facts.get(field) is True:
            return reason
    return "process_exit"


def _command_terminal(
    kind: str,
    execution: Any,
    negative: bool,
    expected_timeout_seconds: int,
) -> dict[str, Any] | None:
    if not isinstance(execution, dict):
        return lane_result(
            kind,
            "INCOMPLETE",
            "RUNTIME_AUDIT_COMMAND_EVIDENCE_MISSING",
            "A bounded command execution record is missing.",
        )
    facts = execution.get("execution")
    if not isinstance(facts, dict):
        return lane_result(
            kind,
            "INCOMPLETE",
            "RUNTIME_AUDIT_COMMAND_EVIDENCE_MISSING",
            "The command execution facts are missing or malformed.",
        )
    required_facts = {
        "timed_out",
        "launch_error",
        "output_limit_exceeded",
        "cleanup_confirmed",
        "exit_code",
        "timeout_seconds",
        "duration_ms",
        "termination_reason",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
    }
    if (
        not required_facts.issubset(facts)
        or execution.get("timeout_seconds") != expected_timeout_seconds
        or facts.get("timeout_seconds") != expected_timeout_seconds
        or isinstance(facts.get("duration_ms"), bool)
        or not isinstance(facts.get("duration_ms"), int)
        or facts["duration_ms"] < 0
        or (
            facts.get("termination_reason") == "process_exit"
            and facts["duration_ms"] > expected_timeout_seconds * 1000
        )
        or facts.get("termination_reason")
        not in {"process_exit", "timeout", "output_limit", "cancelled", "launch_error"}
        or facts.get("termination_reason") != _expected_termination_reason(facts)
        or (
            facts.get("exit_code") is not None
            and (
                isinstance(facts.get("exit_code"), bool)
                or not isinstance(facts.get("exit_code"), int)
            )
        )
        or (
            facts.get("termination_reason") == "process_exit"
            and facts.get("exit_code") is None
        )
        or ("cancelled" in facts and type(facts["cancelled"]) is not bool)
        or any(
            type(facts.get(key)) is not bool
            for key in (
                "timed_out",
                "launch_error",
                "output_limit_exceeded",
                "cleanup_confirmed",
            )
        )
        or any(
            isinstance(facts.get(key), bool)
            or not isinstance(facts.get(key), int)
            or facts[key] < 0
            for key in ("stdout_bytes", "stderr_bytes")
        )
        or any(
            not isinstance(facts.get(key), str)
            or re.fullmatch(r"[0-9a-f]{64}", facts[key]) is None
            for key in ("stdout_sha256", "stderr_sha256")
        )
        or not isinstance(execution.get("artifact_error"), (dict, type(None)))
        or (
            isinstance(execution.get("artifact_error"), dict)
            and (
                set(execution["artifact_error"]) != {"code"}
                or not isinstance(execution["artifact_error"].get("code"), str)
                or re.fullmatch(r"[A-Z0-9_]{1,64}", execution["artifact_error"]["code"])
                is None
            )
        )
    ):
        return lane_result(
            kind,
            "INCOMPLETE",
            "RUNTIME_AUDIT_TRACE_INCONSISTENT",
            "The command trace is incomplete or contradicts its signed timeout and terminal state.",
        )
    if facts.get("cancelled") or facts.get("termination_reason") == "cancelled":
        return lane_result(
            kind,
            "INCOMPLETE",
            "RUNTIME_AUDIT_CANCELLED",
            "The signed audit command was cancelled before a complete observation.",
            details={"duration_ms": facts.get("duration_ms")},
        )
    if facts["timed_out"]:
        return lane_result(
            kind,
            "INCOMPLETE",
            "RUNTIME_AUDIT_TIMEOUT",
            "The signed audit command did not complete within its approved bound.",
            details={
                "duration_ms": facts.get("duration_ms"),
                "timeout_seconds": facts.get("timeout_seconds"),
                "termination_reason": facts.get("termination_reason"),
            },
        )
    if facts["launch_error"]:
        return lane_result(
            kind,
            "INCOMPLETE",
            "INCOMPLETE_TOOLING",
            "The signed audit engine could not be launched.",
        )
    if facts.get("output_limit_exceeded") or not facts.get("cleanup_confirmed", False):
        return lane_result(
            kind,
            "INCOMPLETE",
            "RUNTIME_AUDIT_PROCESS_UNBOUNDED",
            "The command exceeded bounded output or its process streams did not close.",
        )
    if execution.get("artifact_error"):
        return lane_result(
            kind,
            "INCOMPLETE",
            execution["artifact_error"]["code"],
            "The command did not produce stable bounded JSON evidence.",
            details={"code": execution["artifact_error"]["code"]},
        )
    return _command_exit_result(kind, facts.get("exit_code"), negative)


def _command_exit_result(
    kind: str, exit_code: int | None, negative: bool
) -> dict[str, Any] | None:
    if not negative and exit_code != 0:
        return lane_result(
            kind,
            "FAIL",
            "RUNTIME_AUDIT_TARGET_FAILED",
            "The candidate audit command failed before producing a passing observation.",
            details={"exit_code": exit_code},
        )
    if negative and exit_code == 0:
        return lane_result(
            kind,
            "FAIL",
            "HOLLOW_RUNTIME_AUDIT",
            "The known-bad control survived the audit command.",
        )
    return None


def _evaluate_artifact(
    lane: dict[str, Any], execution: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate one candidate or known-bad artifact against the shared mesh."""
    kind = lane["kind"]
    artifact = execution.get("artifact") if isinstance(execution, dict) else None
    if not isinstance(artifact, dict):
        return lane_result(
            kind,
            "INCOMPLETE",
            "RUNTIME_AUDIT_ARTIFACT_MISSING",
            "The completed command did not provide a valid observation artifact.",
        )
    scenario_sha256 = plan["counterfactual_mesh"]["scenario_sha256"]
    if artifact.get("scenario_sha256") != scenario_sha256:
        return lane_result(
            kind,
            "INCOMPLETE",
            "CROSS_LANE_SCENARIO_MISMATCH",
            "The artifact was not run against the approved shared counterfactual scenario.",
        )
    normalized = dict(artifact)
    normalized.pop("scenario_sha256")
    try:
        return guarded_lane_evaluator(kind)(EVALUATORS[kind])(
            normalized,
            lane["config"],
            engine=lane["engine"],
            engine_version=lane["engine_version"],
        )
    except Exception as exc:
        error_code = getattr(exc, "code", "E_ARTIFACT_INVALID")
        if (
            not isinstance(error_code, str)
            or re.fullmatch(r"[A-Z0-9_]{1,64}", error_code) is None
        ):
            error_code = "E_ARTIFACT_INVALID"
        return lane_result(
            kind,
            "INCOMPLETE",
            error_code,
            "The audit artifact could not be evaluated deterministically.",
            details={"error_code": error_code},
        )


def _evaluate_target(
    lane: dict[str, Any], execution: dict[str, Any] | None, plan: dict[str, Any]
) -> dict[str, Any]:
    if execution is None or execution.get("kind") != lane["kind"]:
        return lane_result(
            lane["kind"],
            "INCOMPLETE",
            "RUNTIME_AUDIT_EXECUTION_MISSING",
            "This signed lane has no matching execution evidence.",
        )
    target = execution.get("target")
    terminal = _command_terminal(lane["kind"], target, False, lane["timeout_seconds"])
    if terminal is not None:
        return terminal
    return terminal or _evaluate_artifact(lane, target, plan)


def _evaluate_known_bad(
    lane: dict[str, Any], execution: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any] | None:
    known_bad = execution.get("known_bad")
    terminal = _command_terminal(lane["kind"], known_bad, True, lane["timeout_seconds"])
    if terminal is not None:
        return terminal
    negative = _evaluate_artifact(lane, known_bad, plan)
    if negative["state"] == "INCOMPLETE":
        return negative
    if (
        negative["state"] != "FAIL"
        or negative["finding"] != lane["expected_negative_code"]
    ):
        return lane_result(
            lane["kind"],
            "FAIL",
            "HOLLOW_RUNTIME_AUDIT",
            "The known-bad control did not trigger its signed expected finding.",
            details={
                "expected": lane["expected_negative_code"],
                "observed": negative["finding"],
                "observed_state": negative["state"],
            },
        )
    return None


def _decorate_lane(
    lane: dict[str, Any], execution: dict[str, Any] | None, result: dict[str, Any]
) -> dict[str, Any]:
    target = execution.get("target") if execution else None
    if not isinstance(target, dict):
        target = {}
    known_bad = execution.get("known_bad") if execution else None
    if not isinstance(known_bad, dict):
        known_bad = {}
    target_facts = target.get("execution")
    if not isinstance(target_facts, dict):
        target_facts = {}
    known_bad_facts = known_bad.get("execution")
    if not isinstance(known_bad_facts, dict):
        known_bad_facts = {}

    def trace(command_facts: dict[str, Any]) -> dict[str, Any]:
        return {
            key: command_facts.get(key)
            for key in (
                "timeout_seconds",
                "duration_ms",
                "termination_reason",
                "exit_code",
                "timed_out",
                "cancelled",
                "output_limit_exceeded",
                "cleanup_confirmed",
                "stdout_sha256",
                "stdout_bytes",
                "stderr_sha256",
                "stderr_bytes",
            )
        }

    result.update(
        {
            "id": lane["id"],
            "question": QUESTIONS[lane["kind"]],
            "evidence_digest": target.get("artifact_sha256"),
            "evidence": {
                "target_artifact_sha256": target.get("artifact_sha256"),
                "target_normalized_sha256": target.get("normalized_artifact_sha256"),
                "known_bad_artifact_sha256": known_bad.get("artifact_sha256"),
                "target_stdout_sha256": target_facts.get("stdout_sha256"),
                "target_stderr_sha256": target_facts.get("stderr_sha256"),
                "known_bad_stdout_sha256": known_bad_facts.get("stdout_sha256"),
                "known_bad_stderr_sha256": known_bad_facts.get("stderr_sha256"),
                "command_trace": {
                    "target": trace(target_facts),
                    "known_bad": trace(known_bad_facts),
                },
            },
            "replay": {
                "argv": list(lane["target_argv"]),
                "timeout_seconds": lane["timeout_seconds"],
            },
            "remediation": REMEDIATIONS[lane["kind"]],
            "scope_limitation": SCOPE,
        }
    )
    result["repair_guidance"] = repair_guidance(result, lane)
    return result


def _evaluate_lane(
    lane: dict[str, Any], execution: dict[str, Any] | None, plan: dict[str, Any]
) -> dict[str, Any]:
    result = _evaluate_target(lane, execution, plan)
    if execution is not None and execution.get("kind") == lane["kind"]:
        negative_result = _evaluate_known_bad(lane, execution, plan)
        if negative_result is not None:
            result = negative_result
    return _decorate_lane(lane, execution, result)


def _boundary_for_plan(
    plan: dict[str, Any], executions: dict[str, Any]
) -> dict[str, Any] | None:
    boundary = plan.get("runtime_boundary")
    if not isinstance(boundary, dict):
        return None
    return runtime_boundary_decision(
        executions.get("runtime_boundary"),
        candidate_sha256=plan["candidate_sha256"],
        plan_sha256=executions.get("plan_sha256")
        or sha256_bytes(canonical_bytes(plan)),
        environment_sha256=plan["environment"]["digest"],
        requested_isolation=boundary["requested_isolation"],
    )


def evaluate_runtime_audit(
    plan: dict[str, Any], executions: dict[str, Any], workspace_root: Path
) -> dict[str, Any]:
    """Join six computed lanes, their known-bad controls, cross-lane scenario, quality, and repair order."""
    del (
        workspace_root
    )  # source binding was already verified; evaluation has no filesystem authority.
    by_id = index_executions(plan, executions)
    lanes: list[dict[str, Any]] = []
    for lane in plan["lanes"]:
        execution = by_id.get(lane["id"])
        lanes.append(_evaluate_lane(lane, execution, plan))
    states = {item["state"] for item in lanes}
    boundary_result = _boundary_for_plan(plan, executions)
    boundary_ok = boundary_result is None or boundary_result["state"] in {
        "PASS",
        "SUPERVISED_ONLY",
    }
    decision = (
        "READY_FOR_HUMAN_REVIEW"
        if len(lanes) == 6 and states == {"PASS"} and boundary_ok
        else "BLOCKED"
    )
    affected = {item["lane"] for item in lanes if item["state"] != "PASS"}
    repair_queue = [
        {
            "order": index + 1,
            "lane": item["lane"],
            "finding": item["finding"],
            "consequence": item["consequence"],
            "remediation": item["remediation"],
            "evidence_digest": item["evidence_digest"],
        }
        for index, item in enumerate(
            sorted(
                (item for item in lanes if item["state"] != "PASS"),
                key=lambda item: REPAIR_PRIORITY[item["lane"]],
            )
        )
    ]
    compound = [name for required, name in COMPOUND_SIGNALS if required <= affected]
    quality = [
        {
            "lane": lane["kind"],
            "engine": lane["engine"],
            "grade": "native_engine"
            if lane["engine"] in NATIVE_ENGINES
            else "approved_adapter",
        }
        for lane in plan["lanes"]
    ]
    facts = _fact_index(
        decision=decision,
        candidate_sha256=plan["candidate_sha256"],
        mesh=plan["counterfactual_mesh"],
        lanes=lanes,
        quality=quality,
        repair_count=len(repair_queue),
    )
    receipt = {
        "schema": "factory.runtime-audit-receipt.v1",
        "plan_id": plan["id"],
        "candidate_sha256": plan["candidate_sha256"],
        "decision": decision,
        "lanes": sorted(lanes, key=lambda item: LANES.index(item["lane"])),
        "authority": "none",
        "release_approval": False,
        "scope_limitation": SCOPE,
        "cross_lane_assurance": {
            "scenario_id": plan["counterfactual_mesh"]["id"],
            "scenario_sha256": plan["counterfactual_mesh"]["scenario_sha256"],
            "relations": plan["counterfactual_mesh"]["relations"],
            "origin": plan["counterfactual_mesh"]["origin"],
            "evidence_quality": quality,
            "compound_review_signals": compound,
            "signal_boundary": "Deterministic co-occurrence routing only; signals do not prove causation.",
        },
        "repair_queue": repair_queue,
        "agent_actions": [
            audit_remediation_packet(plan["candidate_sha256"], item)
            for item in repair_queue
        ],
        "fact_index": facts,
    }
    if boundary_result is not None:
        receipt["runtime_boundary"] = boundary_result
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    return receipt


def execute_runtime_audit(
    plan_path: Path,
    trust_root_path: Path,
    trust_root_sha256: str,
    workspace_root: Path,
    environment_digest: str,
    output_root: Path,
    *,
    require_intake: bool = False,
) -> dict[str, Any]:
    """Verify, execute, reverify, evaluate, and persist one signed runtime assurance plan."""
    verification = verify_runtime_audit_plan(
        plan_path,
        trust_root_path,
        trust_root_sha256,
        workspace_root,
        environment_digest,
        require_intake=require_intake,
    )
    execution = run_runtime_audit_plan(
        verification["plan"],
        workspace_root,
        output_root,
        plan_sha256=verification["payload_sha256"],
    )
    post_verification = verify_runtime_audit_plan(
        plan_path,
        trust_root_path,
        trust_root_sha256,
        workspace_root,
        environment_digest,
        require_intake=require_intake,
    )
    if post_verification["payload_sha256"] != verification["payload_sha256"]:
        raise RuntimeAuditError("E_PLAN_CHANGED", "plan changed during execution")
    receipt = evaluate_runtime_audit(verification["plan"], execution, workspace_root)
    receipt["plan_payload_sha256"] = verification["payload_sha256"]
    if verification.get("intake_parameters") is not None:
        receipt["intake_parameters"] = verification["intake_parameters"]
    receipt.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    receipt_path = (
        Path(workspace_root).resolve()
        / execution["run_root"]
        / "runtime-audit-receipt.json"
    )
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "verification": verification,
        "post_verification": post_verification,
        "execution": execution,
        "receipt": receipt,
        "receipt_path": receipt_path.relative_to(
            Path(workspace_root).resolve()
        ).as_posix(),
    }


def runtime_audit_status(root: Path | str) -> dict[str, Any]:
    """Return the newest stable self-hash-verified runtime audit receipt without executing any audit."""
    workspace = Path(root).resolve()
    try:
        receipt_paths = sorted(
            (workspace / ".factory" / "runtime-audits").glob(
                "run-*/runtime-audit-receipt.json"
            ),
            key=lambda path: path.stat().st_mtime_ns,
            reverse=True,
        )
        if not receipt_paths:
            return {
                "schema": "factory.runtime-audit-status.v1",
                "state": "NOT_RUN",
                "lanes": [],
                "authority": "none",
            }
        receipt, _ = read_stable_json(receipt_paths[0])
        if receipt.get("schema") != "factory.runtime-audit-receipt.v1":
            raise ValueError("unknown receipt schema")
        claimed = receipt.pop("receipt_sha256")
        actual = sha256_bytes(canonical_bytes(receipt))
        receipt["receipt_sha256"] = claimed
        if claimed != actual:
            raise ValueError("receipt digest mismatch")
        validate_receipt_decision(receipt)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return {
            "schema": "factory.runtime-audit-status.v1",
            "state": "INCOMPLETE",
            "lanes": [],
            "authority": "none",
        }
    return {
        "schema": "factory.runtime-audit-status.v1",
        "state": receipt.get("decision", "INCOMPLETE"),
        "receipt_path": str(receipt_paths[0]),
        "receipt_sha256": receipt.get("receipt_sha256"),
        "candidate_sha256": receipt.get("candidate_sha256"),
        "agent_actions": receipt.get("agent_actions", []),
        "lanes": receipt.get("lanes", []),
        "runtime_boundary": receipt.get("runtime_boundary"),
        "authority": "none",
    }

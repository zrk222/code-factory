"""Fail-closed six-lane runtime assurance decision and human projection."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .runtime_audit_common import RuntimeAuditError, canonical_bytes, lane_result, read_stable_json, sha256_bytes
from .runtime_audit_compatibility import evaluate_compatibility
from .runtime_audit_contract import LANES, verify_runtime_audit_plan
from .runtime_audit_migration import evaluate_migration
from .runtime_audit_performance import evaluate_performance
from .runtime_audit_recovery import evaluate_recovery
from .runtime_audit_runner import run_runtime_audit_plan
from .runtime_audit_stateful import evaluate_stateful
from .runtime_audit_tenant import evaluate_tenant
from .runtime_audit_integrity import index_executions, repair_guidance, validate_receipt_decision

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
    ({"migration_integrity", "consumer_compatibility"}, "rolling_upgrade_consumer_risk"),
    ({"performance_regression", "failure_recovery"}, "load_amplified_recovery_risk"),
    ({"stateful_invariant", "failure_recovery"}, "sequence_replay_side_effect_risk"),
)


def _fact_index(
    *, decision: str, candidate_sha256: str, mesh: dict[str, Any], lanes: list[dict[str, Any]], quality: list[dict[str, str]], repair_count: int
) -> dict[str, Any]:
    """Build a sorted, typed, secret-free KV projection for local IDE and agent queries."""
    values: list[dict[str, Any]] = [
        {"key": "audit.decision", "type": "enum", "value": decision},
        {"key": "audit.candidate_sha256", "type": "sha256", "value": candidate_sha256},
        {"key": "mesh.scenario_sha256", "type": "sha256", "value": mesh["scenario_sha256"]},
        {"key": "repair.count", "type": "integer", "value": repair_count},
    ]
    grade_by_lane = {item["lane"]: item["grade"] for item in quality}
    for lane in lanes:
        prefix = f"lane.{lane['lane']}"
        values.extend([
            {"key": f"{prefix}.state", "type": "enum", "value": lane["state"]},
            {"key": f"{prefix}.finding", "type": "code", "value": lane["finding"]},
            {"key": f"{prefix}.evidence_sha256", "type": "sha256_or_null", "value": lane["evidence_digest"]},
            {"key": f"{prefix}.quality", "type": "enum", "value": grade_by_lane[lane["lane"]]},
        ])
    values.sort(key=lambda item: item["key"])
    projection = {"schema": "factory.runtime-audit-kv.v1", "mutable": False, "values": values}
    projection["kv_sha256"] = sha256_bytes(canonical_bytes(projection))
    return projection


def _command_terminal(kind: str, execution: dict[str, Any], negative: bool) -> dict[str, Any] | None:
    facts = execution["execution"]
    if facts["timed_out"]:
        return lane_result(kind, "INCOMPLETE", "RUNTIME_AUDIT_TIMEOUT", "The signed audit command did not complete within its approved bound.")
    if facts["launch_error"]:
        return lane_result(kind, "INCOMPLETE", "INCOMPLETE_TOOLING", "The signed audit engine could not be launched.")
    if facts.get("output_limit_exceeded") or not facts.get("cleanup_confirmed", False):
        return lane_result(kind, "INCOMPLETE", "RUNTIME_AUDIT_PROCESS_UNBOUNDED", "The command exceeded bounded output or its process streams did not close.")
    if execution["artifact_error"]:
        return lane_result(kind, "INCOMPLETE", execution["artifact_error"]["code"], "The command did not produce stable bounded JSON evidence.", details=execution["artifact_error"])
    if not negative and facts["exit_code"] != 0:
        return lane_result(kind, "FAIL", "RUNTIME_AUDIT_TARGET_FAILED", "The candidate audit command failed before producing a passing observation.", details={"exit_code": facts["exit_code"]})
    if negative and facts["exit_code"] == 0:
        return lane_result(kind, "FAIL", "HOLLOW_RUNTIME_AUDIT", "The known-bad control survived the audit command.")
    return None


def evaluate_runtime_audit(plan: dict[str, Any], executions: dict[str, Any], workspace_root: Path) -> dict[str, Any]:
    """Join six computed lanes, their known-bad controls, cross-lane scenario, quality, and repair order."""
    del workspace_root  # source binding was already verified; evaluation has no filesystem authority.
    by_id = index_executions(plan, executions)
    lanes: list[dict[str, Any]] = []
    for lane in plan["lanes"]:
        kind = lane["kind"]
        execution = by_id.get(lane["id"])
        result: dict[str, Any]
        if execution is None or execution.get("kind") != kind:
            result = lane_result(kind, "INCOMPLETE", "RUNTIME_AUDIT_EXECUTION_MISSING", "This signed lane has no matching execution evidence.")
        else:
            result = _command_terminal(kind, execution["target"], False) or {}
            if not result:
                target_artifact = execution["target"]["artifact"]
                if target_artifact.get("scenario_sha256") != plan["counterfactual_mesh"]["scenario_sha256"]:
                    result = lane_result(kind, "INCOMPLETE", "CROSS_LANE_SCENARIO_MISMATCH", "The lane was not run against the approved shared counterfactual scenario.")
                else:
                    target_artifact = dict(target_artifact)
                    target_artifact.pop("scenario_sha256")
                try:
                    if not result:
                        result = EVALUATORS[kind](target_artifact, lane["config"], engine=lane["engine"], engine_version=lane["engine_version"])
                except (RuntimeAuditError, KeyError, TypeError, ValueError) as exc:
                    result = lane_result(kind, "INCOMPLETE", getattr(exc, "code", "E_ARTIFACT_INVALID"), "The target artifact could not be evaluated deterministically.", details={"message": str(exc)})
            negative_terminal = _command_terminal(kind, execution["known_bad"], True)
            if negative_terminal is not None:
                result = negative_terminal
            else:
                try:
                    negative_artifact = execution["known_bad"]["artifact"]
                    if negative_artifact.get("scenario_sha256") != plan["counterfactual_mesh"]["scenario_sha256"]:
                        negative_result = lane_result(kind, "INCOMPLETE", "CROSS_LANE_SCENARIO_MISMATCH", "The known-bad control used a different scenario.")
                    else:
                        negative_artifact = dict(negative_artifact)
                        negative_artifact.pop("scenario_sha256")
                        negative_result = EVALUATORS[kind](negative_artifact, lane["config"], engine=lane["engine"], engine_version=lane["engine_version"])
                except (RuntimeAuditError, KeyError, TypeError, ValueError) as exc:
                    negative_result = lane_result(kind, "INCOMPLETE", getattr(exc, "code", "E_ARTIFACT_INVALID"), "The known-bad artifact could not be evaluated deterministically.")
                if negative_result["state"] != "FAIL" or negative_result["finding"] != lane["expected_negative_code"]:
                    result = lane_result(kind, "FAIL", "HOLLOW_RUNTIME_AUDIT", "The known-bad control did not trigger its signed expected finding.", details={"expected": lane["expected_negative_code"], "observed": negative_result["finding"], "observed_state": negative_result["state"]})
        target = execution.get("target", {}) if execution else {}
        result.update({
            "id": lane["id"],
            "question": QUESTIONS[kind],
            "evidence_digest": target.get("artifact_sha256"),
            "evidence": {
                "target_artifact_sha256": target.get("artifact_sha256"),
                "target_normalized_sha256": target.get("normalized_artifact_sha256"),
                "known_bad_artifact_sha256": execution.get("known_bad", {}).get("artifact_sha256") if execution else None,
                "target_stdout_sha256": target.get("execution", {}).get("stdout_sha256"),
                "target_stderr_sha256": target.get("execution", {}).get("stderr_sha256"),
            },
            "replay": {"argv": list(lane["target_argv"]), "timeout_seconds": lane["timeout_seconds"]},
            "remediation": REMEDIATIONS[kind],
            "scope_limitation": SCOPE,
        })
        result["repair_guidance"] = repair_guidance(result, lane)
        lanes.append(result)
    states = {item["state"] for item in lanes}
    decision = "READY_FOR_HUMAN_REVIEW" if len(lanes) == 6 and states == {"PASS"} else "BLOCKED"
    affected = {item["lane"] for item in lanes if item["state"] != "PASS"}
    repair_queue = [
        {"order": index + 1, "lane": item["lane"], "finding": item["finding"], "consequence": item["consequence"], "remediation": item["remediation"], "evidence_digest": item["evidence_digest"]}
        for index, item in enumerate(sorted((item for item in lanes if item["state"] != "PASS"), key=lambda item: REPAIR_PRIORITY[item["lane"]]))
    ]
    compound = [name for required, name in COMPOUND_SIGNALS if required <= affected]
    quality = [{"lane": lane["kind"], "engine": lane["engine"], "grade": "native_engine" if lane["engine"] in NATIVE_ENGINES else "approved_adapter"} for lane in plan["lanes"]]
    facts = _fact_index(decision=decision, candidate_sha256=plan["candidate_sha256"], mesh=plan["counterfactual_mesh"], lanes=lanes, quality=quality, repair_count=len(repair_queue))
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
        "fact_index": facts,
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    return receipt


def execute_runtime_audit(
    plan_path: Path,
    trust_root_path: Path,
    trust_root_sha256: str,
    workspace_root: Path,
    environment_digest: str,
    output_root: Path,
) -> dict[str, Any]:
    """Verify, execute, reverify, evaluate, and persist one signed runtime assurance plan."""
    verification = verify_runtime_audit_plan(plan_path, trust_root_path, trust_root_sha256, workspace_root, environment_digest)
    execution = run_runtime_audit_plan(verification["plan"], workspace_root, output_root)
    post_verification = verify_runtime_audit_plan(plan_path, trust_root_path, trust_root_sha256, workspace_root, environment_digest)
    if post_verification["payload_sha256"] != verification["payload_sha256"]:
        raise RuntimeAuditError("E_PLAN_CHANGED", "plan changed during execution")
    receipt = evaluate_runtime_audit(verification["plan"], execution, workspace_root)
    receipt["plan_payload_sha256"] = verification["payload_sha256"]
    receipt.pop("receipt_sha256", None)
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    receipt_path = Path(execution["run_root"]) / "runtime-audit-receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"verification": verification, "post_verification": post_verification, "execution": execution, "receipt": receipt, "receipt_path": str(receipt_path)}


def runtime_audit_status(root: Path | str) -> dict[str, Any]:
    """Return the newest stable self-hash-verified runtime audit receipt without executing any audit."""
    workspace = Path(root).resolve()
    receipt_paths = sorted((workspace / ".factory" / "runtime-audits").glob("run-*/runtime-audit-receipt.json"), key=lambda path: path.stat().st_mtime_ns, reverse=True)
    if not receipt_paths:
        return {"schema": "factory.runtime-audit-status.v1", "state": "NOT_RUN", "lanes": [], "authority": "none"}
    try:
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
        return {"schema": "factory.runtime-audit-status.v1", "state": "INCOMPLETE", "lanes": [], "authority": "none"}
    return {"schema": "factory.runtime-audit-status.v1", "state": receipt.get("decision", "INCOMPLETE"), "receipt_path": str(receipt_paths[0]), "receipt_sha256": receipt.get("receipt_sha256"), "lanes": receipt.get("lanes", []), "authority": "none"}

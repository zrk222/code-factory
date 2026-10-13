"""One-command reproduce, repair, and regression handoff.

This is an orchestration layer over the existing senior assurance contracts.
The coding agent may propose a candidate elsewhere; CF proves the supplied
original failure, repair, and negative controls in fresh temporary workspaces.
Applying a patch and release decisions remain human-owned.
"""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from .runtime_audit_common import canonical_bytes
from .senior_assurance import SeniorAssuranceError, compare_repair, failure_brief


SCHEMA = "factory.fix-workflow.v1"
INTERVENTION_SCHEMA = "factory.behavioral-intervention-summary.v1"
BRANCH_COMPARISON_SCHEMA = "factory.repair-branch-comparison.v1"
BRANCH_COMPARISON_RECEIPT_SCHEMA = "factory.repair-branch-comparison-receipt.v1"
MAX_REPAIR_BRANCHES = 8


class FixWorkflowError(ValueError):
    """Stable fix-workflow input error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _sha(value: object) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _original_result(comparison: dict[str, Any]) -> dict[str, Any] | None:
    original = comparison.get("original")
    return original if isinstance(original, dict) else None


def _failure_brief(
    comparison: dict[str, Any], original: dict[str, Any] | None
) -> dict[str, Any] | None:
    if original is not None and comparison.get("state") == "FAIL":
        return failure_brief(original, receipt_sha256=original.get("receipt_sha256"))
    return None


def _next_action(comparison: dict[str, Any], execute: bool) -> str:
    if comparison.get("state") == "PASS":
        return "Human review may apply the candidate patch; CF does not apply or release it."
    if execute:
        return "Inspect the failure brief and repair evidence, then revise the candidate or contract."
    return "Run with --execute to reproduce the original failure and test the repair with negative controls."


def _reproduction(original: dict[str, Any] | None, execute: bool) -> dict[str, Any]:
    observed = bool(original and original.get("state") == "PASS") if execute else None
    return {
        "required": True,
        "observed": observed,
        "receipt_sha256": original.get("receipt_sha256") if original else None,
    }


def _repair_summary(comparison: dict[str, Any]) -> dict[str, Any]:
    repaired = comparison.get("repaired")
    candidate_receipt = (
        repaired.get("receipt_sha256") if isinstance(repaired, dict) else None
    )
    return {
        "candidate_receipt_sha256": candidate_receipt,
        "regression_checks": comparison.get("regression_checks"),
    }


def _negative_controls(comparison: dict[str, Any], execute: bool) -> dict[str, Any]:
    controls = comparison.get("negative_controls", [])
    regression_checks = comparison.get("regression_checks") or {}
    return {
        "required": comparison.get("negative_controls_required", len(controls)),
        "preserved": regression_checks.get("negative_controls_fail")
        if execute
        else None,
    }


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _unsupported_intervention_run(
    role: str, reason: str, *, process_executed: bool
) -> dict[str, Any]:
    return {
        "role": role,
        "status": "UNSUPPORTED",
        "process_executed": process_executed,
        "observed": False,
        "reason": reason,
    }


def _replay_hashes_valid(run: dict[str, Any]) -> bool:
    digest_fields = (
        "receipt_sha256",
        "source_sha256",
        "argv_sha256",
        "dependencies_sha256",
        "policy_sha256",
        "stdout_sha256",
        "stderr_sha256",
    )
    return all(_is_digest(run.get(field)) for field in digest_fields)


def _replay_outcome(
    run: dict[str, Any],
) -> tuple[int, int, bool, bool, str | None, str] | None:
    expected = run.get("expected_exit")
    actual = run.get("observed_exit")
    timed_out = run.get("timed_out")
    cleanup = run.get("cleanup")
    failure_reason = run.get("failure_reason")
    state = run.get("state")
    if (
        not isinstance(expected, int)
        or isinstance(expected, bool)
        or not isinstance(actual, int)
        or isinstance(actual, bool)
        or not isinstance(timed_out, bool)
        or not isinstance(cleanup, bool)
        or (failure_reason is not None and not isinstance(failure_reason, str))
        or state not in {"PASS", "FAIL"}
    ):
        return None
    return expected, actual, timed_out, cleanup, failure_reason, state


def _intervention_run_status(
    expected: int,
    actual: int,
    timed_out: bool,
    cleanup: bool,
    failure_reason: str | None,
    state: str,
) -> str:
    if timed_out or not cleanup:
        return "INCOMPLETE"
    if failure_reason is None and state == "PASS" and actual == expected:
        return "OBSERVED"
    mismatch = f"EXIT_MISMATCH:expected={expected}:observed={actual}"
    if failure_reason == mismatch and state == "FAIL" and actual != expected:
        return "OBSERVED"
    return "INCOMPLETE"


def _intervention_run(run: object, role: str, execute: bool) -> dict[str, Any]:
    if not execute:
        return {
            "role": role,
            "status": "NOT_EXECUTED",
            "process_executed": False,
            "observed": False,
        }
    if not isinstance(run, dict) or run.get("executed") is not True:
        return _unsupported_intervention_run(
            role,
            "comparison did not supply an executed replay receipt",
            process_executed=False,
        )
    if not _replay_hashes_valid(run):
        return _unsupported_intervention_run(
            role,
            "replay receipt is missing required hash bindings",
            process_executed=True,
        )
    outcome = _replay_outcome(run)
    if outcome is None:
        return _unsupported_intervention_run(
            role,
            "replay receipt lacks typed process outcome facts",
            process_executed=True,
        )
    expected, actual, timed_out, cleanup, failure_reason, state = outcome
    status = _intervention_run_status(
        expected, actual, timed_out, cleanup, failure_reason, state
    )
    return {
        "role": role,
        "status": status,
        "process_executed": True,
        "observed": status == "OBSERVED",
        "receipt_sha256": run["receipt_sha256"],
        "source_sha256": run["source_sha256"],
        "argv_sha256": run["argv_sha256"],
        "dependencies_sha256": run["dependencies_sha256"],
        "policy_sha256": run["policy_sha256"],
        "stdout_sha256": run["stdout_sha256"],
        "stderr_sha256": run["stderr_sha256"],
        "expected_exit": expected,
        "observed_exit": actual,
        "expected_outcome_observed": status == "OBSERVED" and actual == expected,
        "timed_out": timed_out,
        "cleanup_confirmed": cleanup,
        "failure_reason": failure_reason,
    }


def _intervention_counts(rows: list[dict[str, Any]], required: int) -> dict[str, int]:
    return {
        "required": required,
        "receipts_present": len(rows),
        "executed": sum(row.get("process_executed") is True for row in rows),
        "observed": sum(row.get("status") == "OBSERVED" for row in rows),
        "expected_failures_preserved": sum(
            row.get("status") == "OBSERVED"
            and row.get("expected_exit", 0) != 0
            and row.get("expected_outcome_observed") is True
            for row in rows
        ),
        "unexpected_outcomes": sum(
            row.get("status") == "OBSERVED"
            and row.get("expected_outcome_observed") is False
            for row in rows
        ),
        "incomplete": sum(row.get("status") == "INCOMPLETE" for row in rows),
        "unsupported": sum(row.get("status") == "UNSUPPORTED" for row in rows),
    }


def _behavioral_intervention(
    comparison: dict[str, Any], manifest: dict[str, Any], execute: bool
) -> dict[str, Any]:
    original = _intervention_run(comparison.get("original"), "original", execute)
    repaired = _intervention_run(comparison.get("repaired"), "repaired", execute)
    controls = [
        _intervention_run(item, f"negative_control_{index}", execute)
        for index, item in enumerate(comparison.get("negative_controls", []), start=1)
    ]
    rows = [original, repaired, *controls]
    required_controls = comparison.get("negative_controls_required", len(controls))
    if not isinstance(required_controls, int) or isinstance(required_controls, bool):
        required_controls = len(controls)
    status = _intervention_status(execute, controls, required_controls, rows)
    return {
        "schema": INTERVENTION_SCHEMA,
        "status": status,
        "comparison_receipt_sha256": comparison.get("receipt_sha256"),
        "input_manifest_sha256": _sha(manifest),
        "contract_sha256": comparison.get("contract_sha256"),
        "method": "bounded source-candidate replay comparison",
        "what_broke": (
            "REPRODUCED_EXPECTED_FAILURE"
            if original.get("expected_outcome_observed")
            and original.get("expected_exit", 0) != 0
            else "NOT_CONFIRMED"
        ),
        "what_restored": (
            "RESTORED_EXPECTED_SUCCESS"
            if repaired.get("expected_outcome_observed")
            and repaired.get("expected_exit") == 0
            else "NOT_CONFIRMED"
        ),
        "original": original,
        "repaired": repaired,
        "negative_controls": controls,
        "negative_control_counts": _intervention_counts(controls, required_controls),
        "claim_boundary": [
            "Describes only supplied bounded process replays and their hash-bound outcomes.",
            "Not detection-accuracy evidence, causal mechanism proof, or activation patching.",
            "Does not clear findings or apply, approve, merge, publish, or deploy a repair.",
        ],
    }


def _intervention_status(
    execute: bool,
    controls: list[dict[str, Any]],
    required_controls: int,
    rows: list[dict[str, Any]],
) -> str:
    if not execute:
        return "NOT_EXECUTED"
    if len(controls) != required_controls:
        return "UNSUPPORTED"
    if any(row["status"] == "INCOMPLETE" for row in rows):
        return "INCOMPLETE"
    if any(row["status"] == "UNSUPPORTED" for row in rows):
        return "UNSUPPORTED"
    return "OBSERVED"


def _branch_inputs(root: Path, value: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "comparison_id", "contract_sha256", "original", "negative_controls", "branches"
    }:
        raise FixWorkflowError("E_BRANCH_FIELDS", "branch comparison has missing or unknown fields")
    if value.get("schema") != BRANCH_COMPARISON_SCHEMA:
        raise FixWorkflowError("E_BRANCH_SCHEMA", "unsupported branch comparison schema")
    if not isinstance(value.get("comparison_id"), str) or not value["comparison_id"].strip() or len(value["comparison_id"]) > 64:
        raise FixWorkflowError("E_BRANCH_ID", "comparison_id must be a short non-empty string")
    if not _is_digest(value.get("contract_sha256")):
        raise FixWorkflowError("E_BRANCH_CONTRACT", "contract_sha256 must be lowercase SHA-256")
    branches = value.get("branches")
    if not isinstance(branches, list) or not 1 <= len(branches) <= MAX_REPAIR_BRANCHES:
        raise FixWorkflowError("E_BRANCH_LIMIT", f"branches must contain 1..{MAX_REPAIR_BRANCHES} candidates")
    ids = []
    for row in branches:
        if not isinstance(row, dict) or set(row) != {"branch_id", "candidate"}:
            raise FixWorkflowError("E_BRANCH_FIELDS", "each branch requires only branch_id and candidate")
        identifier = row.get("branch_id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 64 or not identifier[0].isalnum() or any(not (c.isalnum() or c in "._-") for c in identifier):
            raise FixWorkflowError("E_BRANCH_ID", "branch_id must use letters, digits, dot, underscore, or hyphen")
        ids.append(identifier)
    if len(set(ids)) != len(ids):
        raise FixWorkflowError("E_BRANCH_DUPLICATE", "branch_id values must be unique")
    base = {
        "schema": "factory.repair-comparison.v1",
        "comparison_id": value["comparison_id"],
        "contract_sha256": value["contract_sha256"],
        "buggy": value["original"],
        "negative_controls": value["negative_controls"],
    }
    return base, branches


def _branch_repair_manifest(base: dict[str, Any], branch: dict[str, Any]) -> dict[str, Any]:
    return {
        **base,
        "comparison_id": f"{base['comparison_id']}-{branch['branch_id']}",
        "fixed": branch["candidate"],
    }


def _branch_binding(base: dict[str, Any]) -> dict[str, Any]:
    return {
        "contract_sha256": base["contract_sha256"],
        "original_manifest_sha256": _sha(base["buggy"]),
        "negative_control_manifest_sha256": [_sha(item) for item in base["negative_controls"]],
    }


def _branch_row(
    branch: dict[str, Any],
    repair: dict[str, Any],
    binding: dict[str, Any],
    comparison: dict[str, Any],
    *,
    execute: bool,
) -> dict[str, Any]:
    intervention = _behavioral_intervention(comparison, repair, execute)
    status = "PLAN_ONLY" if not execute else (
        "OBSERVED" if intervention["status"] == "OBSERVED" else "INCOMPLETE"
    )
    return {
        "branch_id": branch["branch_id"],
        "candidate_manifest_sha256": _sha(branch["candidate"]),
        "shared_binding_sha256": _sha(binding),
        "status": status,
        "comparison_state": comparison.get("state"),
        "behavioral_intervention": intervention,
        "raw_comparison": comparison,
        "comparison_manifest_sha256": _sha(repair),
    }


def _preflight_repair_branches(
    workspace: Path, base: dict[str, Any], branches: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]]:
    prepared = []
    for branch in branches:
        repair = _branch_repair_manifest(base, branch)
        try:
            plan = compare_repair(workspace, repair, execute=False)
        except SeniorAssuranceError as exc:
            raise FixWorkflowError(exc.code, exc.message) from exc
        prepared.append((branch, repair, plan))
    return prepared


def _compare_repair_branches(
    workspace: Path,
    prepared: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]],
    binding: dict[str, Any],
    *,
    execute: bool,
) -> list[dict[str, Any]]:
    results = []
    for branch, repair, plan in prepared:
        comparison = plan
        if execute:
            try:
                comparison = compare_repair(workspace, repair, execute=True)
            except SeniorAssuranceError as exc:
                comparison = {
                    "state": "INCOMPLETE",
                    "executed": False,
                    "error_code": exc.code,
                    "error": "Replay execution did not produce a complete comparison.",
                }
        results.append(_branch_row(branch, repair, binding, comparison, execute=execute))
    return results


def _branch_batch_state(execute: bool, results: list[dict[str, Any]]) -> str:
    if not execute:
        return "PLAN_ONLY"
    complete = all(
        row["status"] == "OBSERVED" and row["raw_comparison"].get("executed") is True
        for row in results
    )
    return "COMPARED" if complete else "INCOMPLETE"


def run_repair_branch_comparison(
    root: Path, manifest: dict[str, Any], *, execute: bool = False, out: Path | None = None
) -> dict[str, Any]:
    """Compare up to eight repair candidates under one exact contract and baseline."""
    workspace = Path(root).resolve()
    base, branches = _branch_inputs(workspace, manifest)
    binding = _branch_binding(base)
    prepared = _preflight_repair_branches(workspace, base, branches)
    results = _compare_repair_branches(workspace, prepared, binding, execute=execute)
    core = {
        "schema": BRANCH_COMPARISON_RECEIPT_SCHEMA,
        "marker": "REPAIR_BRANCH_COMPARISON_ADVISORY",
        "comparison_id": manifest["comparison_id"],
        "contract_sha256": manifest["contract_sha256"],
        "mode": "execute" if execute else "plan",
        "state": _branch_batch_state(execute, results),
        "branch_count": len(results),
        "shared_binding": binding,
        "shared_binding_sha256": _sha(binding),
        "branches": results,
        "candidate_selection": None,
        "promotion": "NONE",
        "application": "NONE",
        "release_approval": False,
        "authority": "none",
        "claim_boundary": "Each candidate is compared independently against the same original failure and controls in fresh replay workspaces. Raw outcomes are preserved; no winner is chosen, ranked, promoted, applied, or approved.",
    }
    result = {**core, "receipt_sha256": _sha(core)}
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_bytes(result) + b"\n")
    return result


def run_fix_workflow(
    root: Path,
    repair_manifest: dict[str, Any],
    *,
    execute: bool = False,
    out: Path | None = None,
) -> dict[str, Any]:
    """Run or plan the complete fix handoff around a repair comparison manifest."""
    if isinstance(repair_manifest, dict) and repair_manifest.get("schema") == BRANCH_COMPARISON_SCHEMA:
        return run_repair_branch_comparison(
            root, repair_manifest, execute=execute, out=out
        )
    try:
        comparison = compare_repair(
            Path(root).resolve(), repair_manifest, execute=execute
        )
    except SeniorAssuranceError as exc:
        raise FixWorkflowError(exc.code, exc.message) from exc
    original = _original_result(comparison)
    core = {
        "schema": SCHEMA,
        "marker": "FIX_WORKFLOW_RECEIPT",
        "fix_id": comparison.get("comparison_id"),
        "contract_sha256": comparison.get("contract_sha256"),
        "mode": "execute" if execute else "plan",
        "state": comparison.get("state"),
        "reproduction": _reproduction(original, execute),
        "repair": _repair_summary(comparison),
        "negative_controls": _negative_controls(comparison, execute),
        "behavioral_intervention": _behavioral_intervention(
            comparison, repair_manifest, execute
        ),
        "failure_brief": _failure_brief(comparison, original),
        "findings": comparison.get("findings", []),
        "next_action": _next_action(comparison, execute),
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Coordinates bounded reproduction and repair evidence; it never applies patches, approves, merges, publishes, deploys, signs, or uses credentials.",
    }
    result = {**core, "receipt_sha256": _sha(core)}
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_bytes(result) + b"\n")
    return result


def load_fix_json(path: Path) -> dict[str, Any]:
    """Load one bounded repair-comparison manifest from JSON."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FixWorkflowError("E_FIX_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise FixWorkflowError("E_FIX_JSON", "JSON must be an object")
    return value

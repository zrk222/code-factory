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


class FixWorkflowError(ValueError):
    """Stable fix-workflow input error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _sha(value: object) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def run_fix_workflow(
    root: Path,
    repair_manifest: dict[str, Any],
    *,
    execute: bool = False,
    out: Path | None = None,
) -> dict[str, Any]:
    """Run or plan the complete fix handoff around a repair comparison manifest."""
    try:
        comparison = compare_repair(
            Path(root).resolve(), repair_manifest, execute=execute
        )
    except SeniorAssuranceError as exc:
        raise FixWorkflowError(exc.code, exc.message) from exc
    original = (
        comparison.get("original")
        if isinstance(comparison.get("original"), dict)
        else None
    )
    brief = None
    if original is not None and comparison.get("state") == "FAIL":
        brief = failure_brief(original, receipt_sha256=original.get("receipt_sha256"))
    if comparison.get("state") == "PASS":
        next_action = "Human review may apply the candidate patch; CF does not apply or release it."
    elif execute:
        next_action = "Inspect the failure brief and repair evidence, then revise the candidate or contract."
    else:
        next_action = "Run with --execute to reproduce the original failure and test the repair with negative controls."
    core = {
        "schema": SCHEMA,
        "marker": "FIX_WORKFLOW_RECEIPT",
        "fix_id": comparison.get("comparison_id"),
        "contract_sha256": comparison.get("contract_sha256"),
        "mode": "execute" if execute else "plan",
        "state": comparison.get("state"),
        "reproduction": {
            "required": True,
            "observed": bool(original and original.get("state") == "PASS")
            if execute
            else None,
            "receipt_sha256": original.get("receipt_sha256") if original else None,
        },
        "repair": {
            "candidate_receipt_sha256": (comparison.get("repaired") or {}).get(
                "receipt_sha256"
            )
            if isinstance(comparison.get("repaired"), dict)
            else None,
            "regression_checks": comparison.get("regression_checks"),
        },
        "negative_controls": {
            "required": comparison.get(
                "negative_controls_required",
                len(comparison.get("negative_controls", [])),
            ),
            "preserved": (comparison.get("regression_checks") or {}).get(
                "negative_controls_fail"
            )
            if execute
            else None,
        },
        "failure_brief": brief,
        "findings": comparison.get("findings", []),
        "next_action": next_action,
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

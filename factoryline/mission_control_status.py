"""Read-only shared control plane for human review and connected agents.

This is intentionally separate from :mod:`factoryline.control_plane`, which is
the tenant-scoped evidence store.  It only summarizes hash-bound local facts;
it cannot approve, execute, repair, merge, publish, or access credentials.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .lifecycle_ledger import lifecycle_projection
from .operations_control import operations_control_projection
from .oracle_firewall import oracle_firewall_projection
from .repair_loop import repair_loop_projection
from .protocol_enums import MissionControlState


SCHEMA = "factory.mission-control-status.v1"
AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


def mission_control_status(root: Path) -> dict[str, Any]:
    """Summarize local evidence gates without creating a hidden control path."""
    workspace = Path(root).resolve()
    oracle = oracle_firewall_projection(workspace)
    operations = operations_control_projection(workspace)
    lifecycle = lifecycle_projection(workspace)
    repairs = repair_loop_projection(workspace)
    blockers = {
        "oracle_invalid": int(oracle.get("invalid_count", 0)),
        "oracle_weakening": int(oracle.get("blocked_drift_count", 0)),
        "operations_blocked": int(operations.get("blocked_count", 0)),
        "operations_invalid": int(operations.get("invalid_count", 0)),
        "lifecycle_invalid": int(lifecycle.get("invalid_count", 0)),
        "repair_invalid": int(repairs.get("invalid_count", 0)),
    }
    blocked = any(blockers.values())
    human_required = (
        blocked
        or int(lifecycle.get("review_required_count", 0)) > 0
        or int(repairs.get("receipt_count", 0)) > 0
    )
    state = (
        MissionControlState.BLOCKED.value
        if blocked
        else MissionControlState.REVIEW_REQUIRED.value
        if human_required
        else MissionControlState.EVIDENCE_MISSING.value
    )
    return {
        "schema": SCHEMA,
        "marker": "MISSION_CONTROL_READ_ONLY",
        "state": state,
        "human_control_plane": {
            "state": state,
            "review_required": human_required,
            "can_approve_here": False,
            "next_action": (
                "repair_evidence_chain"
                if blocked
                else "named_human_review"
                if human_required
                else "seal_intent_and_collect_local_evidence"
            ),
        },
        "agent_control_plane": {
            "state": MissionControlState.SUPERVISED_ONLY.value,
            "may_read": [
                "sealed_oracle_contract",
                "operations_receipt",
                "session_trace",
                "repair_loop_packet",
            ],
            "may_not": [
                "alter_intent",
                "weaken_threshold",
                "authorize_repair",
                "merge",
                "publish",
                "deploy",
                "access_credentials",
            ],
            "handoff_rule": (
                "A connected agent must present local hash-bound facts; missing or changed facts "
                "return to named human review."
            ),
        },
        "blockers": blockers,
        "evidence": {
            "oracle": oracle,
            "operations": operations,
            "lifecycle": lifecycle,
            "repair_loops": repairs,
        },
        "authority": dict(AUTHORITY),
        "claim_boundary": (
            "This is a read-only coordination view. It does not create approval, execute an agent, "
            "repair code, alter Git, or perform any provider action."
        ),
    }

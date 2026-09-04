"""Read-only shared control plane for human review and connected agents.

This is intentionally separate from :mod:`factoryline.control_plane`, which is
the tenant-scoped evidence store.  It only summarizes hash-bound local facts;
it cannot approve, execute, repair, merge, publish, or access credentials.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import hashlib
import json
import time

from .lifecycle_ledger import lifecycle_projection
from .operations_control import operations_control_projection
from .oracle_firewall import oracle_firewall_projection
from .repair_loop import repair_loop_projection
from .runtime_audit import runtime_audit_status
from .deep_audit import deep_audit_status
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


def _collect_evidence(root: Path, spans: list | None = None) -> dict[str, Any]:
    readers = (
        ("oracle", oracle_firewall_projection),
        ("operations", operations_control_projection),
        ("lifecycle", lifecycle_projection),
        ("repair_loops", repair_loop_projection),
        ("runtime_assurance", runtime_audit_status),
        ("deep_audit", deep_audit_status),
    )
    evidence = {}
    for name, reader in readers:
        started = time.perf_counter_ns()
        evidence[name] = reader(root)
        elapsed = time.perf_counter_ns() - started
        if spans is not None:
            spans.append({"name": name, "elapsed_ns": elapsed,
                          "output_sha256": _fingerprint(evidence[name])})
    return evidence


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def mission_control_profile(root: Path) -> dict[str, Any]:
    """Measure local evidence readers without exporting their bodies or authorizing any action."""
    spans: list[dict[str, Any]] = []
    _collect_evidence(Path(root).resolve(), spans)
    identities = [{"name": span["name"], "output_sha256": span["output_sha256"]}
                  for span in spans]
    return {
        "schema": "factory.mission-control-profile.v1",
        "spans": spans,
        "reader_elapsed_ns": sum(span["elapsed_ns"] for span in spans),
        "evidence_sha256": _fingerprint(identities),
        "authority": dict(AUTHORITY),
        "claim_boundary": "Local reader timings only; not an atomic filesystem snapshot, approval, signature or end-to-end speedup.",
    }


def mission_control_status(root: Path) -> dict[str, Any]:
    """Summarize local evidence gates without creating a hidden control path."""
    workspace = Path(root).resolve()
    evidence = _collect_evidence(workspace)
    oracle = evidence["oracle"]
    operations = evidence["operations"]
    lifecycle = evidence["lifecycle"]
    repairs = evidence["repair_loops"]
    runtime = evidence["runtime_assurance"]
    blockers = {
        "oracle_invalid": int(oracle.get("invalid_count", 0)),
        "oracle_weakening": int(oracle.get("blocked_drift_count", 0)),
        "operations_blocked": int(operations.get("blocked_count", 0)),
        "operations_invalid": int(operations.get("invalid_count", 0)),
        "lifecycle_invalid": int(lifecycle.get("invalid_count", 0)),
        "repair_invalid": int(repairs.get("invalid_count", 0)),
        "runtime_assurance_blocked": int(runtime.get("state") in {"BLOCKED", "INCOMPLETE"}),
        "deep_audit_blocked": int(evidence["deep_audit"].get("state") in {"BLOCKED", "INCOMPLETE"}),
    }
    blocked = any(blockers.values())
    human_required = (
        blocked
        or evidence["deep_audit"].get("state") == "READY_FOR_HUMAN_REVIEW"
        or runtime.get("state") == "READY_FOR_HUMAN_REVIEW"
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
                "runtime_assurance_receipt",
                "deep_audit_receipt",
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
        "evidence": evidence,
        "authority": dict(AUTHORITY),
        "claim_boundary": (
            "This is a read-only coordination view. It does not create approval, execute an agent, "
            "repair code, alter Git, or perform any provider action."
        ),
    }

"""Pure MCP2-style Multi-Round Trip release-gate projections.

The transport remains stateless and authority-free. The input-required leg
describes what a human must decide; the completed leg returns only a local,
hash-bound acknowledgement and never performs provider release work.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


class McpMrtError(ValueError):
    """Fail-closed validation error for the stateless MRT boundary."""

    def __init__(self, message: str, marker: str = "MCP2_RELEASE_GATE_INPUT_REJECTED") -> None:
        super().__init__(message)
        self.marker = marker


_MCP2_DECISIONS = ("APPROVE_RELEASE", "REJECT_RELEASE", "REQUEST_REPAIR_RETRY")
_MCP2_STATUSES = {
    "APPROVE_RELEASE": "RELEASE_APPROVED",
    "REJECT_RELEASE": "RELEASE_REJECTED",
    "REQUEST_REPAIR_RETRY": "RETRY_DISPATCHED",
}


def _require_mcp2_string(value: Any, name: str, *, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise McpMrtError(f"{name} must be a non-empty string")
    if len(value) > max_length:
        raise McpMrtError(f"{name} exceeds the {max_length}-character limit")
    return value.strip()


def _mcp2_failed_lanes(blockers: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Project only explicitly lane-labelled blockers; never infer coverage."""
    findings: list[dict[str, str]] = []
    for blocker in blockers:
        lane = blocker.get("lane")
        if not isinstance(lane, str) or not lane.strip():
            continue
        rejection = blocker.get("rejectionCondition", blocker.get("rule_id", blocker.get("code", "UNKNOWN_RULE")))
        digest = blocker.get("evidenceDigest", blocker.get("evidence_digest", ""))
        severity = str(blocker.get("riskSeverity", blocker.get("risk_severity", blocker.get("severity", "HIGH")))).upper()
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = "HIGH"
        findings.append({
            "lane": lane,
            "rejectionCondition": str(rejection),
            "evidenceDigest": str(digest),
            "riskSeverity": severity,
        })
    return findings


def release_gate_completed(
    card: dict[str, Any],
    human_input: Any,
    *,
    tool_call_id: str | None = None,
    proof_card_hash: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic local receipt for a validated human decision.

    This is the safe second leg of the stateless MRT interaction. It binds the
    decision to the exact proof-card challenge and fails closed on debt or
    binding mismatches. It never persists state or performs a release action.
    """
    challenge = release_gate_input_required(card)
    expected_tool_call_id = challenge["toolCallId"]
    expected_proof_card_hash = challenge["context"]["proofCardHash"]
    if not isinstance(human_input, dict):
        raise McpMrtError("human_input must be an object")
    allowed = {"decision", "reviewerIdentity", "reviewerNotes", "acknowledgedProofDebt"}
    unknown = sorted(set(human_input) - allowed)
    if unknown:
        raise McpMrtError(f"human_input contains unsupported fields: {', '.join(unknown)}")
    decision = human_input.get("decision")
    if decision not in _MCP2_DECISIONS:
        raise McpMrtError("decision must be APPROVE_RELEASE, REJECT_RELEASE, or REQUEST_REPAIR_RETRY")
    reviewer = _require_mcp2_string(human_input.get("reviewerIdentity"), "reviewerIdentity", max_length=256)
    notes_value = human_input.get("reviewerNotes", "")
    if notes_value is None:
        notes_value = ""
    if not isinstance(notes_value, str) or len(notes_value) > 4000:
        raise McpMrtError("reviewerNotes must be a string of at most 4000 characters")
    acknowledged_value = human_input.get("acknowledgedProofDebt", [])
    if not isinstance(acknowledged_value, list) or len(acknowledged_value) > 50:
        raise McpMrtError("acknowledgedProofDebt must be an array of at most 50 strings")
    acknowledged = [_require_mcp2_string(item, "acknowledgedProofDebt item", max_length=256) for item in acknowledged_value]
    if len(set(acknowledged)) != len(acknowledged):
        raise McpMrtError("acknowledgedProofDebt must not contain duplicates")
    # MRT is stateless: the second leg must carry both bindings from the
    # original challenge.
    if tool_call_id is None or proof_card_hash is None:
        raise McpMrtError(
            "tool_call_id and proof_card_hash are required for the stateless second leg",
            "MCP2_RELEASE_GATE_BINDING_MISMATCH",
        )
    if tool_call_id != expected_tool_call_id:
        raise McpMrtError("toolCallId does not match the proof-card challenge", "MCP2_RELEASE_GATE_BINDING_MISMATCH")
    if proof_card_hash != expected_proof_card_hash:
        raise McpMrtError("proofCardHash does not match the proof-card contents", "MCP2_RELEASE_GATE_BINDING_MISMATCH")
    debt = challenge["context"].get("proofDebt", [])
    if not isinstance(debt, list):
        debt = []
    missing_debt = [str(item) for item in debt if str(item) not in acknowledged]
    if decision == "APPROVE_RELEASE" and missing_debt:
        raise McpMrtError(
            "APPROVE_RELEASE requires acknowledgement of every unresolved proof-debt code: " + ", ".join(missing_debt),
            "MCP2_RELEASE_DEBT_UNACKNOWLEDGED",
        )
    receipt_input = {
        "toolCallId": expected_tool_call_id,
        "proofCardHash": expected_proof_card_hash,
        "decision": decision,
        "reviewerIdentity": reviewer,
        "reviewerNotes": notes_value.strip(),
        "acknowledgedProofDebt": acknowledged,
    }
    receipt_hash = "sha256:" + _sha(receipt_input)
    return {
        "type": "completed",
        "toolCallId": expected_tool_call_id,
        "status": _MCP2_STATUSES[decision],
        "receiptHash": receipt_hash,
        "summary": (
            f"Human decision {decision} permanently sealed by {reviewer} for local review; "
            "external release remains unobserved."
        ),
        "authority": {key: False for key in (
            "execution", "approval", "publication", "deployment", "signing", "messaging", "credential", "connector"
        )},
        "claim_boundary": (
            "Completed local human-decision receipt only; this digest does not approve, merge, publish, deploy, "
            "sign, or authorize a provider action, and no server-side session or receipt file was retained."
        ),
        "proofCardHash": expected_proof_card_hash,
        "acknowledgedProofDebt": acknowledged,
    }


def evaluate_release_gate(
    card: dict[str, Any],
    human_input: Any = None,
    *,
    tool_call_id: str | None = None,
    proof_card_hash: str | None = None,
) -> dict[str, Any]:
    """Evaluate either stateless MRT leg without retaining server state."""
    if human_input is None:
        return release_gate_input_required(card)
    return release_gate_completed(
        card,
        human_input,
        tool_call_id=tool_call_id,
        proof_card_hash=proof_card_hash,
    )


def release_gate_input_required(card: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic, authority-free `input_required` envelope."""
    feature = str(card.get("feature", "unknown"))
    blockers = [item for item in card.get("blockers", []) if isinstance(item, dict)]
    debt = [str(item.get("code", "LOCAL_RELEASE_NOT_READY")) for item in blockers]
    proof_card = {
        "feature": feature,
        "state": str(card.get("state", "UNKNOWN")),
        "classification": str(card.get("classification", "unknown")),
        "blockers": blockers,
        "next_action": card.get("next_action", {}),
    }
    proof_card_hash = "sha256:" + _sha(proof_card)
    tool_call_id = "release-gate:" + _sha({"feature": feature, "proof_card_hash": proof_card_hash})[:32]
    return {
        "type": "input_required",
        "toolCallId": tool_call_id,
        "prompt": (
            "A human reviewer must choose a release decision after inspecting the bound local proof card; "
            f"{len(blockers)} failed audit lane(s) are reported. This request does not record or apply that decision."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "decision": {"type": "string", "enum": ["APPROVE_RELEASE", "REJECT_RELEASE", "REQUEST_REPAIR_RETRY"]},
                "reviewerIdentity": {"type": "string", "minLength": 1},
                "reviewerNotes": {"type": "string"},
                "acknowledgedProofDebt": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["decision", "reviewerIdentity"],
            "additionalProperties": False,
        },
        "context": {
            "proofCardHash": proof_card_hash,
            "hasUnresolvedProofDebt": bool(debt),
            "failedLanes": _mcp2_failed_lanes(blockers),
            "proofDebt": debt,
            "nextFactDerivedAction": str(card.get("next_action", {}).get("action", "review_local_release_evidence")),
            "state": str(card.get("state", "UNKNOWN")),
        },
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "messaging": False,
            "credential": False,
            "connector": False,
        },
        "claim_boundary": "MCP2-style input_required projection only; the connection may close and a later client request may carry user input, but this local server does not retain state, process approval, dispatch a retry, or emit a completed release receipt.",
    }

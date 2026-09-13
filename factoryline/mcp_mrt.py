"""Pure MCP2-style Multi-Round Trip release-gate projection.

The projection is intentionally input-only: it describes what a human would
need to decide, but never accepts, records, or dispatches that decision.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Any


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


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
        "prompt": "A human reviewer must choose a release decision after inspecting the bound local proof card; this request does not record or apply that decision.",
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
            "failedLanes": [],
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

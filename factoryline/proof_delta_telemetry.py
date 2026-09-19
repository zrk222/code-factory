"""Pure Graph Ops projection for verified Proof-Delta halt telemetry.

This module only hashes already-verified inputs. It does not read files, run
commands, or grant any authority; Graph Ops owns the read-only node projection.
"""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any


_AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def build_proof_delta_telemetry(
    verification: dict[str, Any], proof_delta_sha256: str
) -> dict[str, Any]:
    """Build a deterministic, authority-free telemetry record for one verified delta."""
    prior = verification["prior_candidate"]["candidate"]
    repair = verification["repair_candidate"]["candidate"]
    repair_evidence = verification["repair_candidate"].get("evidence", [])
    new_evidence = verification.get("new_evidence", [])
    candidate_unchanged = repair["diff_sha256"] == prior["diff_sha256"]
    evidence_unchanged = not bool(new_evidence)
    halted = not verification["eligible"]
    blocker_type = "STALE_EVIDENCE_OR_UNCHANGED_CANDIDATE" if halted else "NONE"
    proof_debt = (
        [
            f"Unresolved criterion: {verification['criterion_id']}",
            "Fresh hash-bound evidence gain is required before admitting a subsequent candidate",
        ]
        if halted
        else []
    )
    next_action = (
        "supply_modified_candidate_and_fresh_evidence: require an agent or human developer to provide a modified implementation candidate and new hash-bound evidence before admitting a subsequent candidate."
        if halted
        else "admit_named_owner_and_independent_validator: require named owner admission and independent validator review before relying on the changed candidate."
    )
    evidence_digest = "sha256:" + _sha({"repair": repair_evidence, "new": new_evidence})
    base = {
        "schema": "factory.graph-ops.proof-delta-telemetry.v1",
        "nodeId": "proof_delta_guard",
        "status": "NO_GAIN_HALT" if halted else "REPAIR_ADMITTED",
        "blocker": {
            "type": blocker_type,
            "candidateHash": repair["diff_sha256"],
            "priorCandidateHash": prior["diff_sha256"],
            "repairCandidateHash": repair["diff_sha256"],
            "evidenceDigest": evidence_digest,
            "candidateUnchanged": candidate_unchanged,
            "evidenceUnchanged": evidence_unchanged,
            "haltReason": verification["reason"],
        },
        "proofDebt": proof_debt,
        "nextFactDerivedAction": next_action,
        "criterionId": verification["criterion_id"],
        "missionId": verification["mission_id"],
        "proofDeltaSha256": proof_delta_sha256,
        "authority": dict(_AUTHORITY),
        "execution": False,
    }
    return {**base, "telemetrySha256": _sha(base)}

"""Privacy-plane primitives: Merkle disclosure plus honest optional adapters."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Iterable

from .control_plane import canonical_json, sha256


PRIVACY_SCHEMA = "factory.privacy.v1"


class PrivacyError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _leaf(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PrivacyError("E_LEAF_REQUIRED", "Merkle leaves must be non-empty strings")
    return value.strip()


def _parent(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("ascii")).hexdigest()


def merkle_root(leaves: Iterable[str]) -> str:
    """Compute a deterministic Merkle root for ordered disclosure values."""
    values = sorted({_leaf(value) for value in leaves})
    if not values:
        raise PrivacyError("E_EMPTY_MERKLE", "Merkle commitment needs at least one leaf")
    level = values
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            right = level[index + 1] if index + 1 < len(level) else level[index]
            next_level.append(_parent(level[index], right))
        level = next_level
    return level[0]


def merkle_disclosure(leaves: Iterable[str], disclosed: str) -> dict[str, Any]:
    """Build a Merkle inclusion disclosure for one value or fail if it is absent."""
    values = sorted({_leaf(value) for value in leaves})
    disclosed = _leaf(disclosed)
    if disclosed not in values:
        raise PrivacyError("E_LEAF_NOT_FOUND", "disclosed leaf is not in commitment")
    index = values.index(disclosed)
    proof: list[dict[str, str]] = []
    level = values
    cursor = index
    while len(level) > 1:
        sibling_index = cursor - 1 if cursor % 2 else cursor + 1
        if sibling_index >= len(level):
            sibling_index = cursor
        proof.append({"position": "left" if cursor % 2 else "right", "digest": level[sibling_index]})
        next_level = []
        for offset in range(0, len(level), 2):
            right = level[offset + 1] if offset + 1 < len(level) else level[offset]
            next_level.append(_parent(level[offset], right))
        level = next_level
        cursor //= 2
    result = {
        "schema": "factory.merkle.disclosure.v1",
        "root": level[0],
        "leaf": disclosed,
        "proof": proof,
        "disclosure": "one-leaf-plus-path",
    }
    result["disclosure_sha256"] = sha256(canonical_json(result))
    return result


def verify_merkle_disclosure(disclosure: dict[str, Any]) -> bool:
    """Verify a Merkle disclosure without accepting malformed proof directions."""
    current = _leaf(disclosure.get("leaf"))
    for step in disclosure.get("proof", []):
        sibling = _leaf(step.get("digest"))
        current = _parent(sibling, current) if step.get("position") == "left" else _parent(current, sibling)
    return current == disclosure.get("root")


def bbs_status() -> dict[str, Any]:
    """Report the bounded status of optional BBS selective-disclosure support."""
    try:
        __import__("bbs")
    except ImportError:
        return {
            "schema": "factory.bbs.status.v1",
            "available": False,
            "verdict": "UNAVAILABLE",
            "error": {"code": "E_BBS_UNAVAILABLE", "message": "install and configure a reviewed BBS backend before issuing credentials"},
        }
    return {"schema": "factory.bbs.status.v1", "available": True, "verdict": "BACKEND_PRESENT"}


def issue_bbs_credential(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Refuse unavailable BBS issuance with an explicit, stable privacy error."""
    status = bbs_status()
    if not status["available"]:
        raise PrivacyError(status["error"]["code"], status["error"]["message"])
    raise PrivacyError("E_BBS_REVIEW_REQUIRED", "BBS backend is present but issuance requires a reviewed integration")


def zkvm_pilot_status() -> dict[str, Any]:
    """Report the non-production status and constraints of the zkVM pilot."""
    try:
        __import__("factory_zkvm_backend")
    except ImportError:
        return {
            "schema": "factory.zkvm.pilot.v1",
            "available": False,
            "verdict": "UNAVAILABLE",
            "error": {"code": "E_ZKVM_UNAVAILABLE", "message": "zkVM pilot backend is not installed"},
        }
    return {"schema": "factory.zkvm.pilot.v1", "available": True, "verdict": "BACKEND_PRESENT"}


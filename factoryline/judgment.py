from __future__ import annotations

"""Human-governed engineering decisions and deterministic Change Safety Cases.

The module deliberately has no model, network, subprocess, VCS, or execution
surface.  Capsules are repository-tracked JSON so a team can review the
decision alongside the code.  A separate person must promote a proposal; a
Safety Case only describes supplied, hash-bound evidence declarations.
"""

from copy import deepcopy
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any


STORE_SCHEMA = "factory.judgment.store.v1"
CAPSULE_SCHEMA = "factory.judgment.capsule.v1"
CAPSULE_V2_SCHEMA = "factory.judgment.capsule.v2"
PROOF_RECEIPT_SCHEMA = "factory.judgment.proof-receipt.v1"
SAFETY_CASE_SCHEMA = "factory.judgment.safety-case.v1"
CHANGE_PROFILE_SCHEMA = "factory.judgment.change-profile.v1"
MAX_TEXT = 320
MAX_ITEMS = 64
_ID = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CATEGORIES = frozenset({"architecture", "reliability", "security", "data", "performance", "operations", "contract", "incident"})
_CHANGE_KINDS = frozenset({"architecture-boundary", "schema-change", "public-api", "concurrency", "authentication", "data-deletion", "external-dependency", "migration", "shared-state", "rollback", "incident-recurrence"})
_ATTENTION = ("routine", "domain", "specialist", "architecture")
_ENFORCEMENT_LEVELS = frozenset({"context", "detection", "assertion", "proof"})

AUTHORITY = {
    "model": False,
    "test_execution": False,
    "source_write": False,
    "vcs_write": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential_access": False,
    "connector_access": False,
}


class JudgmentError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value: object, field: str, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not (result := value.strip()):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must be a non-empty string")
    if len(result) > maximum:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} exceeds {maximum} characters")
    return result


def _identifier(value: object, field: str) -> str:
    result = _text(value, field, maximum=64)
    if not _ID.fullmatch(result):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must use lowercase letters, numbers, and hyphens")
    return result


def _relative(value: object, field: str) -> str:
    result = _text(value, field, maximum=240).replace("\\", "/").removeprefix("./").rstrip("/")
    if not result or result.startswith("/") or result.startswith("../") or "/../" in result or "*" in result:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must be a workspace-relative non-glob path")
    return result


def _strings(value: object, field: str, *, minimum: int = 0, maximum: int = MAX_ITEMS) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must contain {minimum} through {maximum} values")
    values = [_text(item, field) for item in value]
    if len(set(values)) != len(values):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must not contain duplicates")
    return values


def _date(value: object, field: str) -> str:
    result = _text(value, field, maximum=10)
    try:
        return date.fromisoformat(result).isoformat()
    except ValueError as exc:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must be an ISO-8601 date") from exc


def _timestamp(value: object, field: str) -> str:
    result = _text(value, field, maximum=32)
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _exact_keys(value: object, allowed: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != allowed:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"{field} has unsupported or missing fields")
    return value


def _obligations(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ITEMS:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "proof_obligations must contain 1 through 64 obligations")
    output: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        row = _exact_keys(item, {"id", "description"}, "proof_obligation")
        obligation_id = _identifier(row["id"], "proof_obligation.id")
        if obligation_id in seen:
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "proof_obligation.id must be unique")
        seen.add(obligation_id)
        output.append({"id": obligation_id, "description": _text(row["description"], "proof_obligation.description")})
    return output


def _capsule_core(value: object) -> dict[str, Any]:
    base_keys = {
        "schema", "id", "title", "summary", "scope_paths", "rationale_refs", "evidence_refs",
        "proof_obligations", "owner", "review_by", "supersedes",
    }
    if not isinstance(value, dict) or value.get("schema") not in {CAPSULE_SCHEMA, CAPSULE_V2_SCHEMA}:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"capsule schema must equal {CAPSULE_SCHEMA} or {CAPSULE_V2_SCHEMA}")
    is_v2 = value["schema"] == CAPSULE_V2_SCHEMA
    v2_keys = {"category", "change_kinds", "attention_floor", "enforcement_level", "incident_refs"}
    row = _exact_keys(value, base_keys | (v2_keys if is_v2 else set()), "capsule proposal")
    supersedes = row["supersedes"]
    if supersedes is not None:
        supersedes = _identifier(supersedes, "supersedes")
    paths = [_relative(item, "scope_paths") for item in row["scope_paths"]] if isinstance(row["scope_paths"], list) else []
    if not 1 <= len(paths) <= MAX_ITEMS or len(set(paths)) != len(paths):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "scope_paths must contain unique workspace-relative paths")
    core = {
        "schema": row["schema"],
        "id": _identifier(row["id"], "id"),
        "title": _text(row["title"], "title"),
        "summary": _text(row["summary"], "summary"),
        "scope_paths": sorted(paths),
        "rationale_refs": _strings(row["rationale_refs"], "rationale_refs", minimum=1),
        "evidence_refs": _strings(row["evidence_refs"], "evidence_refs", minimum=0),
        "proof_obligations": _obligations(row["proof_obligations"]),
        "owner": _text(row["owner"], "owner", maximum=120),
        "review_by": _date(row["review_by"], "review_by"),
        "supersedes": supersedes,
    }
    if is_v2:
        category = _identifier(row["category"], "category")
        if category not in _CATEGORIES:
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "category is not a declared Capsule category")
        kinds = [_identifier(item, "change_kinds") for item in _strings(row["change_kinds"], "change_kinds", minimum=1)]
        if any(item not in _CHANGE_KINDS for item in kinds):
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "change_kinds contains an unsupported declared kind")
        attention = _identifier(row["attention_floor"], "attention_floor")
        if attention not in _ATTENTION[1:]:
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "attention_floor must be domain, specialist, or architecture")
        level = _identifier(row["enforcement_level"], "enforcement_level")
        if level not in _ENFORCEMENT_LEVELS:
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "enforcement_level must be context, detection, assertion, or proof")
        core.update({
            "category": category,
            "change_kinds": sorted(kinds),
            "attention_floor": attention,
            "enforcement_level": level,
            "incident_refs": _strings(row["incident_refs"], "incident_refs", minimum=0),
        })
    return core


def _capsule_metadata(core: dict[str, Any]) -> dict[str, Any]:
    """Return V2 routing metadata without rewriting or rehashing a V1 Capsule."""
    if core["schema"] == CAPSULE_V2_SCHEMA:
        return {
            "category": core["category"],
            "change_kinds": core["change_kinds"],
            "attention_floor": core["attention_floor"],
            "enforcement_level": core["enforcement_level"],
            "incident_refs": core["incident_refs"],
        }
    return {
        "category": "unclassified",
        "change_kinds": [],
        "attention_floor": "domain",
        "enforcement_level": "context",
        "incident_refs": [],
    }


def _capsule_digest(core: dict[str, Any], lifecycle: dict[str, Any]) -> str:
    return _sha({"core": core, "lifecycle": lifecycle})


def _normalized_capsule(value: object) -> dict[str, Any]:
    row = _exact_keys(value, {
        "core", "lifecycle", "capsule_sha256",
    }, "stored capsule")
    core = _capsule_core(row["core"])
    lifecycle = _exact_keys(row["lifecycle"], {
        "state", "proposed_by", "proposed_at", "promoted_by", "promoted_at", "successor_proposal_id",
    }, "capsule.lifecycle")
    state = lifecycle["state"]
    if state not in {"proposed", "active", "superseded"}:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "capsule.lifecycle.state is invalid")
    normalized_lifecycle: dict[str, Any] = {
        "state": state,
        "proposed_by": _text(lifecycle["proposed_by"], "proposed_by", maximum=120),
        "proposed_at": _timestamp(lifecycle["proposed_at"], "proposed_at"),
        "promoted_by": None,
        "promoted_at": None,
        "successor_proposal_id": None,
    }
    if state in {"active", "superseded"}:
        normalized_lifecycle["promoted_by"] = _text(lifecycle["promoted_by"], "promoted_by", maximum=120)
        normalized_lifecycle["promoted_at"] = _timestamp(lifecycle["promoted_at"], "promoted_at")
    elif lifecycle["promoted_by"] is not None or lifecycle["promoted_at"] is not None:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "proposed Capsule cannot have promotion facts")
    if lifecycle["successor_proposal_id"] is not None:
        normalized_lifecycle["successor_proposal_id"] = _identifier(lifecycle["successor_proposal_id"], "successor_proposal_id")
    expected = _capsule_digest(core, normalized_lifecycle)
    if row["capsule_sha256"] != expected:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "capsule_sha256 does not match declared Capsule facts")
    return {"core": core, "lifecycle": normalized_lifecycle, "capsule_sha256": expected}


def _event(value: object) -> dict[str, str]:
    row = _exact_keys(value, {"action", "capsule_id", "actor", "at", "reason", "event_sha256"}, "audit event")
    core = {
        "action": _identifier(row["action"], "audit.action"),
        "capsule_id": _identifier(row["capsule_id"], "audit.capsule_id"),
        "actor": _text(row["actor"], "audit.actor", maximum=120),
        "at": _timestamp(row["at"], "audit.at"),
        "reason": _text(row["reason"], "audit.reason"),
    }
    if row["event_sha256"] != _sha(core):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "audit event hash does not match declared facts")
    return {**core, "event_sha256": _sha(core)}


def _empty_store() -> dict[str, Any]:
    return {"schema": STORE_SCHEMA, "capsules": [], "audit": []}


def _store_path(root: Path) -> Path:
    return Path(root).resolve() / "judgment" / "capsules.json"


def _store(value: object) -> dict[str, Any]:
    row = _exact_keys(value, {"schema", "capsules", "audit"}, "Capsule store")
    if row["schema"] != STORE_SCHEMA or not isinstance(row["capsules"], list) or not isinstance(row["audit"], list):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "Capsule store schema is invalid")
    if len(row["capsules"]) > MAX_ITEMS or len(row["audit"]) > MAX_ITEMS * 4:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "Capsule store exceeds bounded size")
    capsules = [_normalized_capsule(item) for item in row["capsules"]]
    ids = [item["core"]["id"] for item in capsules]
    if len(set(ids)) != len(ids):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "Capsule IDs must be unique")
    references = {item["core"]["id"]: item for item in capsules}
    for capsule in capsules:
        predecessor = capsule["core"]["supersedes"]
        if predecessor is not None and predecessor not in references:
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "supersedes must reference a stored Capsule")
        successor = capsule["lifecycle"]["successor_proposal_id"]
        if successor is not None and successor not in references:
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "successor_proposal_id must reference a stored Capsule")
    return {"schema": STORE_SCHEMA, "capsules": sorted(capsules, key=lambda item: item["core"]["id"]), "audit": [_event(item) for item in row["audit"]]}


def _read_store(root: Path, *, require: bool = False) -> tuple[dict[str, Any], Path | None]:
    path = _store_path(root)
    if not path.exists():
        if require:
            raise JudgmentError("JUDGMENT_CAPSULE_NOT_FOUND", "no Judgment Capsule store exists")
        return _empty_store(), None
    try:
        return _store(json.loads(path.read_text(encoding="utf-8"))), path
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, JudgmentError) as exc:
        if isinstance(exc, JudgmentError):
            raise
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "Capsule store is unreadable") from exc


def _atomic_store(path: Path, store: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(store, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)
    return path.as_posix()


def _write_event(store: dict[str, Any], *, action: str, capsule_id: str, actor: str, reason: str, at: str) -> None:
    core = {"action": action, "capsule_id": capsule_id, "actor": actor, "at": at, "reason": reason}
    store["audit"].append({**core, "event_sha256": _sha(core)})


def _render_capsule(core: dict[str, Any], lifecycle: dict[str, Any]) -> dict[str, Any]:
    return {"core": core, "lifecycle": lifecycle, "capsule_sha256": _capsule_digest(core, lifecycle)}


def propose_capsule(root: Path, candidate: object, *, proposed_by: str, at: str | None = None) -> dict[str, Any]:
    """Store a human-proposed Capsule. A proposal has no Change Safety Case authority."""
    workspace = Path(root).resolve()
    actor = _text(proposed_by, "proposed_by", maximum=120)
    core = _capsule_core(candidate)
    store, _ = _read_store(workspace)
    if any(item["core"]["id"] == core["id"] for item in store["capsules"]):
        raise JudgmentError("JUDGMENT_CAPSULE_EXISTS", "Capsule ID already exists")
    if core["supersedes"] is not None:
        predecessor = next((item for item in store["capsules"] if item["core"]["id"] == core["supersedes"]), None)
        if predecessor is None or predecessor["lifecycle"]["state"] != "active":
            raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "supersedes must reference an active Capsule")
    timestamp = _timestamp(at or _now(), "proposed_at")
    lifecycle = {"state": "proposed", "proposed_by": actor, "proposed_at": timestamp, "promoted_by": None, "promoted_at": None, "successor_proposal_id": None}
    capsule = _render_capsule(core, lifecycle)
    store["capsules"].append(capsule)
    store["capsules"].sort(key=lambda item: item["core"]["id"])
    _write_event(store, action="proposed", capsule_id=core["id"], actor=actor, reason="Named human proposal; no active policy authority.", at=timestamp)
    path = _atomic_store(_store_path(workspace), store)
    return {"schema": "factory.judgment.proposal.v1", "marker": "JUDGMENT_CAPSULE_PROPOSED", "path": str(Path(path).relative_to(workspace)), "capsule": capsule, "authority": {**AUTHORITY, "capsule_store_write": True}, "scope_limits": ["A proposal does not affect Change Safety Cases until independent human promotion."]}


def promote_capsule(root: Path, capsule_id: str, *, promoted_by: str, reason: str, at: str | None = None) -> dict[str, Any]:
    """Activate a proposal only when a different named human promotes it."""
    workspace = Path(root).resolve()
    target_id = _identifier(capsule_id, "capsule_id")
    actor = _text(promoted_by, "promoted_by", maximum=120)
    rationale = _text(reason, "reason")
    store, _ = _read_store(workspace, require=True)
    target = next((item for item in store["capsules"] if item["core"]["id"] == target_id), None)
    if target is None or target["lifecycle"]["state"] != "proposed":
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "only an existing proposed Capsule may be promoted")
    if target["lifecycle"]["proposed_by"] == actor:
        raise JudgmentError("JUDGMENT_PROMOTION_INDEPENDENCE_REQUIRED", "the proposing human cannot promote the same Capsule")
    timestamp = _timestamp(at or _now(), "promoted_at")
    target["lifecycle"] = {**target["lifecycle"], "state": "active", "promoted_by": actor, "promoted_at": timestamp}
    target["capsule_sha256"] = _capsule_digest(target["core"], target["lifecycle"])
    predecessor_id = target["core"]["supersedes"]
    if predecessor_id is not None:
        predecessor = next(item for item in store["capsules"] if item["core"]["id"] == predecessor_id)
        predecessor["lifecycle"] = {**predecessor["lifecycle"], "state": "superseded", "successor_proposal_id": target_id}
        predecessor["capsule_sha256"] = _capsule_digest(predecessor["core"], predecessor["lifecycle"])
        _write_event(store, action="superseded", capsule_id=predecessor_id, actor=actor, reason=f"Successor {target_id} independently promoted.", at=timestamp)
    _write_event(store, action="promoted", capsule_id=target_id, actor=actor, reason=rationale, at=timestamp)
    path = _atomic_store(_store_path(workspace), store)
    return {"schema": "factory.judgment.promotion.v1", "marker": "JUDGMENT_CAPSULE_ACTIVE", "path": str(Path(path).relative_to(workspace)), "capsule": target, "authority": {**AUTHORITY, "capsule_store_write": True}, "scope_limits": ["Promotion changes only the tracked Capsule state; it does not approve a change, run a proof, or authorize execution."]}


def reconsider_capsule(root: Path, capsule_id: str, successor_proposal_id: str, *, requested_by: str, reason: str, at: str | None = None) -> dict[str, Any]:
    """Record a named reconsideration while keeping the active decision in force."""
    workspace = Path(root).resolve()
    target_id = _identifier(capsule_id, "capsule_id")
    successor_id = _identifier(successor_proposal_id, "successor_proposal_id")
    actor = _text(requested_by, "requested_by", maximum=120)
    rationale = _text(reason, "reason")
    store, _ = _read_store(workspace, require=True)
    target = next((item for item in store["capsules"] if item["core"]["id"] == target_id), None)
    successor = next((item for item in store["capsules"] if item["core"]["id"] == successor_id), None)
    if target is None or target["lifecycle"]["state"] != "active":
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "only an active Capsule may be reconsidered")
    if successor is None or successor["lifecycle"]["state"] != "proposed" or successor["core"]["supersedes"] != target_id:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "successor must be a proposed Capsule that declares supersedes")
    timestamp = _timestamp(at or _now(), "reconsidered_at")
    target["lifecycle"] = {**target["lifecycle"], "successor_proposal_id": successor_id}
    target["capsule_sha256"] = _capsule_digest(target["core"], target["lifecycle"])
    _write_event(store, action="reconsidered", capsule_id=target_id, actor=actor, reason=rationale, at=timestamp)
    path = _atomic_store(_store_path(workspace), store)
    return {"schema": "factory.judgment.reconsideration.v1", "marker": "JUDGMENT_CAPSULE_RECONSIDERATION_RECORDED", "path": str(Path(path).relative_to(workspace)), "capsule": target, "authority": {**AUTHORITY, "capsule_store_write": True}, "scope_limits": ["Reconsideration does not disable, waive, or replace the active Capsule."]}


def _path_matches(scope: str, changed: str) -> bool:
    return changed == scope or changed.startswith(scope + "/")


def _changed_paths(values: list[str]) -> list[str]:
    if not values:
        raise JudgmentError("JUDGMENT_CHANGED_PATH_REQUIRED", "at least one explicit changed path is required")
    return sorted({_relative(value, "changed path") for value in values})


def _under_root(root: Path, supplied: Path) -> tuple[Path, str]:
    candidate = supplied if supplied.is_absolute() else root / supplied
    try:
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", "proof receipt must be an existing workspace-contained file") from exc
    return resolved, relative.as_posix()


def _change_profile(root: Path, supplied: Path | None, changed_paths: list[str]) -> dict[str, Any]:
    """Load only a human-supplied, hash-bound change classification profile.

    A bad profile never causes source inspection or changes a valid Capsule
    route; it is returned as an explicit unavailable/invalid fact instead.
    """
    if supplied is None:
        return {
            "state": "unavailable",
            "path": None,
            "profile_sha256": None,
            "entries": [],
            "error": None,
            "source_semantics_inferred": False,
        }
    try:
        path, relative = _under_root(root, Path(supplied))
        row = json.loads(path.read_text(encoding="utf-8"))
        value = _exact_keys(row, {"schema", "changed", "profile_sha256"}, "change profile")
        if value["schema"] != CHANGE_PROFILE_SCHEMA:
            raise JudgmentError("JUDGMENT_CHANGE_PROFILE_INVALID", f"change profile schema must equal {CHANGE_PROFILE_SCHEMA}")
        if not isinstance(value["changed"], list) or not 1 <= len(value["changed"]) <= MAX_ITEMS:
            raise JudgmentError("JUDGMENT_CHANGE_PROFILE_INVALID", "change profile changed must contain 1 through 64 entries")
        entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in value["changed"]:
            entry = _exact_keys(item, {"path", "change_kinds"}, "change profile entry")
            entry_path = _relative(entry["path"], "change profile path")
            if entry_path in seen:
                raise JudgmentError("JUDGMENT_CHANGE_PROFILE_INVALID", "change profile paths must be unique")
            seen.add(entry_path)
            kinds = [_identifier(kind, "change profile change_kinds") for kind in _strings(entry["change_kinds"], "change profile change_kinds", minimum=1)]
            if any(kind not in _CHANGE_KINDS for kind in kinds):
                raise JudgmentError("JUDGMENT_CHANGE_PROFILE_INVALID", "change profile contains an unsupported declared kind")
            entries.append({"path": entry_path, "change_kinds": sorted(kinds)})
        entries.sort(key=lambda item: item["path"])
        core = {"schema": CHANGE_PROFILE_SCHEMA, "changed": entries}
        if value["profile_sha256"] != _sha(core):
            raise JudgmentError("JUDGMENT_CHANGE_PROFILE_INVALID", "change profile hash does not match declared facts")
        if [item["path"] for item in entries] != changed_paths:
            raise JudgmentError("JUDGMENT_CHANGE_PROFILE_INVALID", "change profile paths must exactly equal explicit changed paths")
        return {
            "state": "valid",
            "path": relative,
            "profile_sha256": value["profile_sha256"],
            "entries": entries,
            "error": None,
            "source_semantics_inferred": False,
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, JudgmentError) as exc:
        code = exc.code if isinstance(exc, JudgmentError) else "JUDGMENT_CHANGE_PROFILE_INVALID"
        return {
            "state": "invalid",
            "path": str(supplied).replace("\\", "/"),
            "profile_sha256": None,
            "entries": [],
            "error": {"code": code, "message": str(exc)},
            "source_semantics_inferred": False,
        }


def _proof_receipt(root: Path, supplied: Path) -> dict[str, Any]:
    path, relative = _under_root(root, supplied)
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", f"proof receipt {relative} is unreadable JSON") from exc
    allowed = {"schema", "capsule_id", "obligation_id", "verdict", "evidence", "receipt_sha256"}
    value = _exact_keys(row, allowed, "proof receipt")
    if value["schema"] != PROOF_RECEIPT_SCHEMA or value["verdict"] != "verified":
        raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", f"proof receipt {relative} has an unsupported schema or verdict")
    core = {
        "schema": PROOF_RECEIPT_SCHEMA,
        "capsule_id": _identifier(value["capsule_id"], "proof receipt capsule_id"),
        "obligation_id": _identifier(value["obligation_id"], "proof receipt obligation_id"),
        "verdict": "verified",
        "evidence": [],
    }
    if not isinstance(value["evidence"], list) or not value["evidence"] or len(value["evidence"]) > MAX_ITEMS:
        raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", f"proof receipt {relative} must bind one or more evidence files")
    for evidence in value["evidence"]:
        item = _exact_keys(evidence, {"path", "sha256"}, "proof receipt evidence")
        evidence_path, evidence_relative = _under_root(root, Path(_relative(item["path"], "proof receipt evidence.path")))
        digest = item["sha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", "proof receipt evidence.sha256 is invalid")
        actual = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
        if actual != digest:
            raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", f"proof receipt evidence hash does not match {evidence_relative}")
        core["evidence"].append({"path": evidence_relative, "sha256": digest})
    core["evidence"].sort(key=lambda item: item["path"])
    if value["receipt_sha256"] != _sha(core):
        raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", f"proof receipt {relative} hash does not match declared facts")
    return {**core, "receipt_sha256": value["receipt_sha256"], "path": relative}


def _receipts(root: Path, values: list[Path] | None) -> tuple[dict[tuple[str, str], dict[str, Any]], list[dict[str, str]]]:
    output: dict[tuple[str, str], dict[str, Any]] = {}
    errors: list[dict[str, str]] = []
    for value in values or []:
        try:
            receipt = _proof_receipt(root, Path(value))
            key = (receipt["capsule_id"], receipt["obligation_id"])
            if key in output:
                raise JudgmentError("JUDGMENT_PROOF_RECEIPT_INVALID", "duplicate proof receipt binding")
            output[key] = receipt
        except JudgmentError as exc:
            errors.append({"code": exc.code, "message": str(exc), "path": str(value).replace("\\", "/")})
    return output, sorted(errors, key=lambda item: (item["path"], item["code"]))


def judgment_status(root: Path, *, today: date | None = None) -> dict[str, Any]:
    """Read a Capsule store without writing or inferring a policy from other data."""
    workspace = Path(root).resolve()
    observed = today or date.today()
    try:
        store, path = _read_store(workspace)
    except JudgmentError as exc:
        return {
            "schema": "factory.judgment.status.v1", "marker": "JUDGMENT_CAPSULE_INVALID", "state": "invalid", "path": "judgment/capsules.json",
            "capsules": [], "errors": [{"code": exc.code, "message": str(exc)}], "authority": AUTHORITY,
        }
    rows = []
    for capsule in store["capsules"]:
        core, lifecycle = capsule["core"], capsule["lifecycle"]
        metadata = _capsule_metadata(core)
        rows.append({
            "id": core["id"], "title": core["title"], "state": lifecycle["state"], "owner": core["owner"],
            "scope_paths": core["scope_paths"], "review_by": core["review_by"], "review_due": lifecycle["state"] == "active" and date.fromisoformat(core["review_by"]) < observed,
            "successor_proposal_id": lifecycle["successor_proposal_id"], "capsule_sha256": capsule["capsule_sha256"],
            "proof_obligation_count": len(core["proof_obligations"]), "schema": core["schema"], **metadata,
        })
    return {
        "schema": "factory.judgment.status.v1", "marker": "JUDGMENT_CAPSULE_STATUS_READ_ONLY", "state": "empty" if path is None else "valid",
        "path": path.relative_to(workspace).as_posix() if path else "judgment/capsules.json", "as_of": observed.isoformat(), "capsules": rows,
        "counts": {"total": len(rows), "active": sum(item["state"] == "active" for item in rows), "proposed": sum(item["state"] == "proposed" for item in rows), "review_due": sum(item["review_due"] for item in rows)},
        "errors": [], "authority": AUTHORITY,
        "scope_limits": ["Status reads only tracked Capsule records. It does not infer, promote, waive, or apply a decision."],
    }


def _attention_max(*values: str) -> str:
    rank = {name: index for index, name in enumerate(_ATTENTION)}
    return max(values, key=lambda item: rank[item])


def safety_case(
    root: Path,
    *,
    changed: list[str],
    proof_receipts: list[Path] | None = None,
    change_profile: Path | None = None,
    as_of: date | None = None,
) -> dict[str, Any]:
    """Compile a deterministic, declared-facts-only Change Safety Case."""
    workspace = Path(root).resolve()
    changed_paths = _changed_paths(changed)
    observed = as_of or date.today()
    try:
        store, path = _read_store(workspace)
    except JudgmentError as exc:
        core = {
            "schema": SAFETY_CASE_SCHEMA, "marker": "JUDGMENT_SAFETY_CASE_INVALID", "markers": ["JUDGMENT_CAPSULE_INVALID", "JUDGMENT_SAFETY_CASE_READ_ONLY"],
            "route": "BLACK", "attention": "architecture", "attention_reasons": ["invalid_capsule_store"], "review_reasons": ["invalid_capsule_store"],
            "changed_paths": changed_paths, "matching_capsules": [], "unclassified_changed_paths": changed_paths, "missing_obligations": [], "required_reviewers": [],
            "receipt_errors": [{"code": exc.code, "message": str(exc)}], "profile": {"state": "unavailable", "path": None, "profile_sha256": None, "entries": [], "error": None, "source_semantics_inferred": False},
            "novelty": {"known_change_kinds": [], "novel_change_kinds": [], "unclassified_changed_paths": changed_paths}, "drift": [],
            "human_questions": [{"id": "repair-capsule-store", "kind": "store_invalid", "question": "Repair the tracked Judgment Capsule store before routing this change."}],
            "facts": {"store_valid": False, "profile_state": "unavailable", "matching_active_capsule_count": 0, "has_no_matching_active_capsule": True, "missing_obligation_count": 0, "unclassified_path_count": len(changed_paths), "novel_kind_count": 0, "has_novel_architecture_boundary": False, "review_due_count": 0, "reconsideration_pending_count": 0, "source_semantics_inferred": False},
            "store_path": "judgment/capsules.json", "as_of": observed.isoformat(), "authority": AUTHORITY,
            "scope_limits": ["The invalid store was not replaced by an older or inferred Capsule.", "This result is not an approval, execution, or release decision."],
        }
        return {**core, "safety_case_sha256": _sha(core)}
    receipts, receipt_errors = _receipts(workspace, proof_receipts)
    profile = _change_profile(workspace, change_profile, changed_paths)
    matching: list[dict[str, Any]] = []
    matched_paths: set[str] = set()
    missing: list[dict[str, str]] = []
    reviewers: set[str] = set()
    for capsule in store["capsules"]:
        capsule_core, lifecycle = capsule["core"], capsule["lifecycle"]
        if lifecycle["state"] != "active":
            continue
        paths = [item for item in changed_paths if any(_path_matches(scope, item) for scope in capsule_core["scope_paths"])]
        if not paths:
            continue
        matched_paths.update(paths)
        reviewers.add(capsule_core["owner"])
        obligations = []
        capsule_missing = False
        for obligation in capsule_core["proof_obligations"]:
            receipt = receipts.get((capsule_core["id"], obligation["id"]))
            entry: dict[str, Any] = {"id": obligation["id"], "description": obligation["description"], "state": "bound" if receipt else "missing"}
            if receipt:
                entry["receipt_path"] = receipt["path"]
                entry["receipt_sha256"] = receipt["receipt_sha256"]
            else:
                capsule_missing = True
                missing.append({"capsule_id": capsule_core["id"], "obligation_id": obligation["id"], "owner": capsule_core["owner"]})
            obligations.append(entry)
        metadata = _capsule_metadata(capsule_core)
        review_due = date.fromisoformat(capsule_core["review_by"]) < observed
        if capsule_missing:
            drift_state = "proof_missing"
        elif lifecycle["successor_proposal_id"] is not None:
            drift_state = "reconsideration_pending"
        elif review_due:
            drift_state = "review_due"
        else:
            drift_state = "declared_proof_bound"
        matching.append({
            "id": capsule_core["id"], "title": capsule_core["title"], "owner": capsule_core["owner"], "matched_paths": paths,
            "review_by": capsule_core["review_by"], "review_due": review_due, "successor_proposal_id": lifecycle["successor_proposal_id"],
            "capsule_sha256": capsule["capsule_sha256"], "obligations": obligations, "drift_state": drift_state, **metadata,
        })
    matching.sort(key=lambda item: item["id"])
    missing.sort(key=lambda item: (item["capsule_id"], item["obligation_id"]))
    unclassified = sorted(item for item in changed_paths if item not in matched_paths)
    known_kinds: list[dict[str, Any]] = []
    novel_kinds: list[dict[str, str]] = []
    if profile["state"] == "valid":
        for entry in profile["entries"]:
            relevant = [capsule for capsule in matching if entry["path"] in capsule["matched_paths"]]
            for kind in entry["change_kinds"]:
                capsule_ids = sorted(capsule["id"] for capsule in relevant if kind in capsule["change_kinds"])
                if capsule_ids:
                    known_kinds.append({"path": entry["path"], "kind": kind, "capsule_ids": capsule_ids})
                else:
                    novel_kinds.append({"path": entry["path"], "kind": kind, "reason": "no_matching_active_capsule_declares_kind"})
    has_novel_architecture_boundary = any(item["kind"] == "architecture-boundary" for item in novel_kinds)
    if matching and (missing or receipt_errors):
        route, reasons = "RED", ["missing_declared_obligation_receipts"]
    elif matching:
        route, reasons = "AMBER", ["named_owner_review_required"]
    else:
        route, reasons = "GREEN", ["routine_unclassified", "no_active_capsule_matches"]
    if receipt_errors:
        reasons.append("supplied_receipt_invalid_or_unbound")
    if profile["state"] == "invalid":
        reasons.append("declared_change_profile_invalid")
    attention = "routine"
    attention_reasons: set[str] = set()
    if matching:
        attention = _attention_max(*(item["attention_floor"] for item in matching))
        attention_reasons.add("matching_capsule_attention_floor")
    if missing or receipt_errors:
        attention = _attention_max(attention, "specialist")
        attention_reasons.add("missing_or_invalid_declared_proof")
    if any(item["drift_state"] in {"review_due", "reconsideration_pending"} for item in matching):
        attention = _attention_max(attention, "specialist")
        attention_reasons.add("decision_drift_requires_reconsideration")
    if unclassified:
        attention = _attention_max(attention, "specialist")
        attention_reasons.add("unclassified_changed_path")
    if novel_kinds:
        attention = _attention_max(attention, "specialist")
        attention_reasons.add("novel_declared_change_kind")
    if has_novel_architecture_boundary:
        attention = "architecture"
        attention_reasons.add("novel_architecture_boundary")
    drift = [{"capsule_id": item["id"], "state": item["drift_state"]} for item in matching]
    human_questions: list[dict[str, str]] = []
    for item in missing:
        human_questions.append({"id": f"proof-{item['capsule_id']}-{item['obligation_id']}", "kind": "missing_proof", "capsule_id": item["capsule_id"], "question": f"Provide or reconsider declared proof obligation {item['obligation_id']} for Capsule {item['capsule_id']}."})
    for item in matching:
        if item["drift_state"] == "review_due":
            human_questions.append({"id": f"review-{item['id']}", "kind": "review_due", "capsule_id": item["id"], "question": f"Does Capsule {item['id']} remain current for its stated scope?"})
        elif item["drift_state"] == "reconsideration_pending":
            human_questions.append({"id": f"reconsider-{item['id']}", "kind": "reconsideration_pending", "capsule_id": item["id"], "question": f"Should successor proposal {item['successor_proposal_id']} be independently promoted for Capsule {item['id']}?"})
    for item in novel_kinds:
        if item["kind"] == "architecture-boundary":
            human_questions.append({"id": f"decision-{item['path'].replace('/', '-')}-{item['kind']}", "kind": "named_decision_required", "path": item["path"], "question": f"Which named Judgment Capsule governs the declared architecture-boundary change at {item['path']}?"})
    human_questions.sort(key=lambda item: item["id"])
    facts = {
        "store_valid": True,
        "profile_state": profile["state"],
        "matching_active_capsule_count": len(matching),
        "has_no_matching_active_capsule": not bool(matching),
        "missing_obligation_count": len(missing),
        "unclassified_path_count": len(unclassified),
        "novel_kind_count": len(novel_kinds),
        "has_novel_architecture_boundary": has_novel_architecture_boundary,
        "review_due_count": sum(item["drift_state"] == "review_due" for item in matching),
        "reconsideration_pending_count": sum(item["drift_state"] == "reconsideration_pending" for item in matching),
        "source_semantics_inferred": False,
    }
    core = {
        "schema": SAFETY_CASE_SCHEMA, "marker": "JUDGMENT_SAFETY_CASE_READ_ONLY", "markers": ["JUDGMENT_SAFETY_CASE_READ_ONLY", "JUDGMENT_NO_EXECUTION"],
        "route": route, "attention": attention, "attention_reasons": sorted(attention_reasons), "review_reasons": sorted(set(reasons)),
        "changed_paths": changed_paths, "matching_capsules": matching, "unclassified_changed_paths": unclassified, "missing_obligations": missing,
        "required_reviewers": sorted(reviewers), "receipt_errors": receipt_errors, "profile": profile,
        "novelty": {"known_change_kinds": known_kinds, "novel_change_kinds": novel_kinds, "unclassified_changed_paths": unclassified},
        "drift": drift, "human_questions": human_questions, "facts": facts,
        "store_path": path.relative_to(workspace).as_posix() if path else "judgment/capsules.json", "as_of": observed.isoformat(), "authority": AUTHORITY,
        "scope_limits": [
            "A GREEN route means no active tracked Capsule matched; it is not safety, approval, production readiness, or release authority.",
            "Change kinds are only supplied profile facts; FactoryLine did not inspect source semantics, git history, tickets, chat, or model output.",
            "A bound receipt proves only its validated declared file hashes and verdict fields; FactoryLine did not execute the test.",
            "The Safety Case does not write source, tests, VCS, Capsule state, CI, Marketplace, or external services.",
        ],
    }
    return {**core, "safety_case_sha256": _sha(core)}


def judgment_projection(root: Path, *, today: date | None = None) -> dict[str, Any]:
    """Return bounded active/proposed Capsule facts for Graph Ops without writes."""
    status = judgment_status(root, today=today)
    return {
        "status": status["state"], "path": status["path"], "count": status.get("counts", {}).get("total", 0),
        "active_count": status.get("counts", {}).get("active", 0), "proposed_count": status.get("counts", {}).get("proposed", 0),
        "review_due_count": status.get("counts", {}).get("review_due", 0), "capsules": status["capsules"],
        "errors": status["errors"], "authority": AUTHORITY,
    }

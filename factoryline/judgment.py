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
PROOF_RECEIPT_SCHEMA = "factory.judgment.proof-receipt.v1"
SAFETY_CASE_SCHEMA = "factory.judgment.safety-case.v1"
MAX_TEXT = 320
MAX_ITEMS = 64
_ID = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

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
    row = _exact_keys(value, {
        "schema", "id", "title", "summary", "scope_paths", "rationale_refs", "evidence_refs",
        "proof_obligations", "owner", "review_by", "supersedes",
    }, "capsule proposal")
    if row["schema"] != CAPSULE_SCHEMA:
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", f"capsule schema must equal {CAPSULE_SCHEMA}")
    supersedes = row["supersedes"]
    if supersedes is not None:
        supersedes = _identifier(supersedes, "supersedes")
    paths = [_relative(item, "scope_paths") for item in row["scope_paths"]] if isinstance(row["scope_paths"], list) else []
    if not 1 <= len(paths) <= MAX_ITEMS or len(set(paths)) != len(paths):
        raise JudgmentError("JUDGMENT_CAPSULE_INVALID", "scope_paths must contain unique workspace-relative paths")
    return {
        "schema": CAPSULE_SCHEMA,
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
        rows.append({
            "id": core["id"], "title": core["title"], "state": lifecycle["state"], "owner": core["owner"],
            "scope_paths": core["scope_paths"], "review_by": core["review_by"], "review_due": lifecycle["state"] == "active" and date.fromisoformat(core["review_by"]) < observed,
            "successor_proposal_id": lifecycle["successor_proposal_id"], "capsule_sha256": capsule["capsule_sha256"],
        })
    return {
        "schema": "factory.judgment.status.v1", "marker": "JUDGMENT_CAPSULE_STATUS_READ_ONLY", "state": "empty" if path is None else "valid",
        "path": path.relative_to(workspace).as_posix() if path else "judgment/capsules.json", "as_of": observed.isoformat(), "capsules": rows,
        "counts": {"total": len(rows), "active": sum(item["state"] == "active" for item in rows), "proposed": sum(item["state"] == "proposed" for item in rows), "review_due": sum(item["review_due"] for item in rows)},
        "errors": [], "authority": AUTHORITY,
        "scope_limits": ["Status reads only tracked Capsule records. It does not infer, promote, waive, or apply a decision."],
    }


def safety_case(root: Path, *, changed: list[str], proof_receipts: list[Path] | None = None, as_of: date | None = None) -> dict[str, Any]:
    """Compile deterministic review routing from explicit paths and proof declarations."""
    workspace = Path(root).resolve()
    changed_paths = _changed_paths(changed)
    observed = as_of or date.today()
    try:
        store, path = _read_store(workspace)
    except JudgmentError as exc:
        core = {
            "schema": SAFETY_CASE_SCHEMA, "marker": "JUDGMENT_SAFETY_CASE_INVALID", "markers": ["JUDGMENT_CAPSULE_INVALID", "JUDGMENT_SAFETY_CASE_READ_ONLY"],
            "route": "BLACK", "changed_paths": changed_paths, "matching_capsules": [], "unclassified_changed_paths": changed_paths,
            "missing_obligations": [], "required_reviewers": [], "receipt_errors": [{"code": exc.code, "message": str(exc)}],
            "store_path": "judgment/capsules.json", "as_of": observed.isoformat(), "authority": AUTHORITY,
            "scope_limits": ["The invalid store was not replaced by an older or inferred Capsule."],
        }
        return {**core, "safety_case_sha256": _sha(core)}
    receipts, receipt_errors = _receipts(workspace, proof_receipts)
    matching: list[dict[str, Any]] = []
    matched_paths: set[str] = set()
    missing: list[dict[str, str]] = []
    reviewers: set[str] = set()
    for capsule in store["capsules"]:
        core, lifecycle = capsule["core"], capsule["lifecycle"]
        if lifecycle["state"] != "active":
            continue
        paths = [item for item in changed_paths if any(_path_matches(scope, item) for scope in core["scope_paths"])]
        if not paths:
            continue
        matched_paths.update(paths)
        reviewers.add(core["owner"])
        obligations = []
        for obligation in core["proof_obligations"]:
            receipt = receipts.get((core["id"], obligation["id"]))
            entry: dict[str, Any] = {"id": obligation["id"], "description": obligation["description"], "state": "bound" if receipt else "missing"}
            if receipt:
                entry["receipt_path"] = receipt["path"]
                entry["receipt_sha256"] = receipt["receipt_sha256"]
            else:
                missing.append({"capsule_id": core["id"], "obligation_id": obligation["id"], "owner": core["owner"]})
            obligations.append(entry)
        matching.append({
            "id": core["id"], "title": core["title"], "owner": core["owner"], "matched_paths": paths,
            "review_by": core["review_by"], "review_due": date.fromisoformat(core["review_by"]) < observed,
            "capsule_sha256": capsule["capsule_sha256"], "obligations": obligations,
        })
    unclassified = [item for item in changed_paths if item not in matched_paths]
    if matching and missing:
        route, reasons = "RED", ["missing_declared_obligation_receipts"]
    elif matching:
        route, reasons = "AMBER", ["named_owner_review_required"]
    else:
        route, reasons = "GREEN", ["routine_unclassified", "no_active_capsule_matches"]
    if receipt_errors:
        reasons.append("supplied_receipt_invalid_or_unbound")
        if matching:
            route = "RED"
    core = {
        "schema": SAFETY_CASE_SCHEMA, "marker": "JUDGMENT_SAFETY_CASE_READ_ONLY", "markers": ["JUDGMENT_SAFETY_CASE_READ_ONLY", "JUDGMENT_NO_EXECUTION"],
        "route": route, "review_reasons": reasons, "changed_paths": changed_paths, "matching_capsules": matching,
        "unclassified_changed_paths": unclassified, "missing_obligations": missing, "required_reviewers": sorted(reviewers),
        "receipt_errors": receipt_errors, "store_path": path.relative_to(workspace).as_posix() if path else "judgment/capsules.json",
        "as_of": observed.isoformat(), "authority": AUTHORITY,
        "scope_limits": [
            "A GREEN route means no active tracked Capsule matched; it is not safety, approval, production readiness, or release authority.",
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

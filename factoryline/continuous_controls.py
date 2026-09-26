"""Deterministic, evidence-first policy controls for Code Factory.

The module deliberately coordinates policy and receipts; it never executes a
declared command or grants release authority.  All records are canonical JSON
so a reviewer can reproduce every digest locally.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


PACK_SCHEMA = "factory.policy-pack.v1"
EVALUATION_SCHEMA = "factory.control-evaluation.v1"
EXCEPTION_SCHEMA = "factory.control-exception.v1"
DOSSIER_SCHEMA = "factory.control-dossier.v1"
FLEET_SCHEMA = "factory.control-fleet.v1"
CONTROL_PROVENANCE = {
    "human_confirmed",
    "trusted_source",
    "observed_production",
    "agent_proposed",
}
ENFORCING_PROVENANCE = {"human_confirmed", "trusted_source"}
EVENT_KINDS = {"working_tree", "merge", "agent_action", "deployment"}
SEVERITIES = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")


class ControlsError(ValueError):
    """Stable, machine-readable failure for a policy or evidence boundary."""

    def __init__(self, code: str, message: str, *, details: Any = None):
        super().__init__(message)
        self.code = code
        self.details = details


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except (TypeError, ValueError) as exc:
        raise ControlsError(
            "E_INVALID_TIME", f"invalid UTC timestamp: {value!r}"
        ) from exc


def _rooted(root: Path, value: str | Path) -> Path:
    workspace = Path(root).resolve()
    candidate = (
        (workspace / Path(value)).resolve()
        if not Path(value).is_absolute()
        else Path(value).resolve()
    )
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise ControlsError(
            "E_PATH_ESCAPE", f"path escapes workspace: {value}"
        ) from exc
    return candidate


def _rel(root: Path, path: Path) -> str:
    return path.resolve().relative_to(Path(root).resolve()).as_posix()


def _require(condition: bool, code: str, message: str, *, details: Any = None) -> None:
    if not condition:
        raise ControlsError(code, message, details=details)


def _hash_field(value: Any, field: str) -> None:
    _require(
        isinstance(value, str) and SHA256.fullmatch(value),
        "E_INVALID_HASH",
        f"{field} must be a SHA-256 digest",
    )


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ControlsError("E_SOURCE_MISSING", f"missing JSON source: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ControlsError(
            "E_INVALID_JSON", f"invalid JSON source: {path}: {exc.msg}"
        ) from exc
    _require(
        isinstance(value, dict),
        "E_INVALID_JSON",
        f"JSON root must be an object: {path}",
    )
    return value


def _write_json(path: Path, value: dict[str, Any], *, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise ControlsError(
            "E_OUTPUT_EXISTS", f"refusing to overwrite existing record: {path}"
        )
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(_canonical(value) + b"\n")
    tmp.replace(path)


def _provenance(value: Any, fallback: str | None = None) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    kind = raw.get("kind", fallback)
    _require(
        kind in CONTROL_PROVENANCE,
        "E_INVALID_PROVENANCE",
        "provenance kind is not recognised",
    )
    source = raw.get("source", "")
    source_hash = raw.get("source_sha256", "")
    _require(
        isinstance(source, str) and source.strip(),
        "E_INVALID_PROVENANCE",
        "provenance source is required",
    )
    _hash_field(source_hash, "provenance.source_sha256")
    return {"kind": kind, "source": source, "source_sha256": source_hash}


def _approval(raw: Any, *, author: str) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    approver = str(raw.get("approver", "")).strip()
    decision = raw.get("decision")
    approved_at = raw.get("approved_at")
    if not approver or decision != "approved" or not approved_at:
        return None
    _require(
        approver != author,
        "E_SOD_VIOLATION",
        "policy author and approver must be different people",
    )
    _parse_time(approved_at)
    digest = raw.get("approval_sha256", "")
    _hash_field(digest, "approval.approval_sha256")
    return {
        "approver": approver,
        "decision": decision,
        "approved_at": approved_at,
        "approval_sha256": digest,
    }


def _validate_control(raw: Any, inherited_kind: str, *, pack_id: str) -> dict[str, Any]:
    _require(
        isinstance(raw, dict),
        "E_INVALID_CONTROL",
        f"control in {pack_id} must be an object",
    )
    control_id = str(raw.get("id", "")).strip()
    _require(bool(control_id), "E_INVALID_CONTROL", "control id is required")
    title = str(raw.get("title", control_id)).strip()
    forbidden = str(raw.get("forbidden_behavior", "")).strip()
    _require(
        bool(forbidden),
        "E_INVALID_CONTROL",
        f"{control_id} must declare forbidden_behavior",
    )
    gate = raw.get("gate")
    test = raw.get("test")
    _require(
        isinstance(gate, dict) and gate.get("kind") and gate.get("id", control_id),
        "E_INVALID_CONTROL",
        f"{control_id} gate is required",
    )
    _require(
        isinstance(test, dict) and test.get("kind") and test.get("id", control_id),
        "E_INVALID_CONTROL",
        f"{control_id} test is required",
    )
    evidence = raw.get("required_evidence", [])
    _require(
        isinstance(evidence, list)
        and all(isinstance(item, str) and item for item in evidence),
        "E_INVALID_CONTROL",
        f"{control_id} required_evidence must be strings",
    )
    severity = str(raw.get("severity", "HIGH")).upper()
    _require(
        severity in SEVERITIES, "E_INVALID_CONTROL", f"{control_id} severity is invalid"
    )
    provenance = _provenance(raw.get("provenance"), inherited_kind)
    return {
        "id": control_id,
        "title": title,
        "description": str(raw.get("description", "")).strip(),
        "forbidden_behavior": forbidden,
        "gate": gate,
        "test": test,
        "required_evidence": list(evidence),
        "severity": severity,
        "provenance": provenance,
        "remediation": str(
            raw.get("remediation", f"Supply fresh evidence for {control_id}")
        ).strip(),
    }


def _semantic_control(control: dict[str, Any]) -> dict[str, Any]:
    return {
        key: control.get(key)
        for key in (
            "id",
            "forbidden_behavior",
            "gate",
            "test",
            "required_evidence",
            "severity",
        )
    }


def _threshold(gate: dict[str, Any]) -> dict[str, Any] | None:
    value = gate.get("threshold")
    return (
        value
        if isinstance(value, dict) and "operator" in value and "value" in value
        else None
    )


def _threshold_weakens(old: dict[str, Any], new: dict[str, Any]) -> bool:
    previous, candidate = _threshold(old), _threshold(new)
    if previous is None and candidate is None:
        return False
    if not _compatible_thresholds(previous, candidate):
        return True
    return _numeric_threshold_weakens(previous, candidate)


def _compatible_thresholds(
    previous: dict[str, Any] | None, candidate: dict[str, Any] | None
) -> bool:
    return (
        previous is not None
        and candidate is not None
        and previous.get("operator") == candidate.get("operator")
    )


def _numeric_threshold_weakens(
    previous: dict[str, Any], candidate: dict[str, Any]
) -> bool:
    try:
        left, right = float(previous["value"]), float(candidate["value"])
    except (TypeError, ValueError):
        return previous != candidate
    operator = previous["operator"]
    return (
        (operator in {"lte", "lt"} and right > left)
        or (operator in {"gte", "gt"} and right < left)
        or (operator == "eq" and right != left)
    )


def _weakening(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if SEVERITIES[new["severity"]] < SEVERITIES[old["severity"]]:
        findings.append("severity lowered")
    if len(new["required_evidence"]) < len(old["required_evidence"]):
        findings.append("required evidence removed")
    if _threshold_weakens(old["gate"], new["gate"]):
        findings.append("gate threshold widened or changed")
    if old["forbidden_behavior"] != new["forbidden_behavior"]:
        findings.append("forbidden behavior changed")
    if old["gate"] != new["gate"] and not _threshold_weakens(old["gate"], new["gate"]):
        findings.append("gate changed")
    if old["test"] != new["test"]:
        findings.append("test changed")
    return findings


def _pack_status(provenance: dict[str, Any], approval: dict[str, Any] | None) -> str:
    return (
        "ENFORCED"
        if provenance["kind"] in ENFORCING_PROVENANCE and approval
        else "ADVISORY"
    )


def _policy_header(
    raw: dict[str, Any], path: str
) -> tuple[str, str, dict[str, Any], str, dict[str, Any] | None]:
    _require(
        raw.get("schema") == PACK_SCHEMA,
        "E_INVALID_PACK",
        f"{path} must use {PACK_SCHEMA}",
    )
    pack_id, version = (
        str(raw.get("pack_id", "")).strip(),
        str(raw.get("version", "")).strip(),
    )
    _require(pack_id and version, "E_INVALID_PACK", "pack_id and version are required")
    provenance = _provenance(raw.get("provenance"))
    author = str((raw.get("authorship") or {}).get("author", "")).strip()
    _require(author, "E_INVALID_PACK", "authorship.author is required")
    approval = (
        _approval(raw.get("approval"), author=author)
        if provenance["kind"] in ENFORCING_PROVENANCE
        else None
    )
    return pack_id, version, provenance, author, approval


def _policy_local_controls(
    raw: dict[str, Any], provenance: dict[str, Any], pack_id: str
) -> list[dict[str, Any]]:
    values = raw.get("controls", [])
    _require(
        isinstance(values, list) and len(values) <= 500,
        "E_INVALID_PACK",
        "controls must be a list of at most 500",
    )
    controls = [
        _validate_control(item, provenance["kind"], pack_id=pack_id) for item in values
    ]
    ids = [item["id"] for item in controls]
    _require(len(ids) == len(set(ids)), "E_INVALID_PACK", "control ids must be unique")
    return controls


def _parent_reference(raw: Any) -> tuple[str, str]:
    _require(isinstance(raw, dict), "E_INVALID_PARENT", "parent must be an object")
    path, expected = (
        str(raw.get("path", "")).strip(),
        str(raw.get("sha256", "")).strip(),
    )
    _require(
        path and expected, "E_INVALID_PARENT", "parent path and sha256 are required"
    )
    _hash_field(expected, "parent.sha256")
    return path, expected


def _load_bound_parent(
    workspace: Path,
    source: Path,
    path: str,
    expected: str,
    seen: tuple[str, ...],
    depth: int,
) -> tuple[dict[str, Any], Path]:
    parent_file = _rooted(workspace, (source.parent / path).resolve())
    parent = load_policy_pack(
        workspace,
        _rel(workspace, parent_file),
        _seen=seen + (source.as_posix(),),
        _depth=depth + 1,
    )
    actual = _sha_bytes(parent_file.read_bytes())
    _require(
        actual == expected,
        "E_PARENT_HASH_MISMATCH",
        f"parent hash mismatch for {path}",
        details={"expected": expected, "actual": actual},
    )
    return parent, parent_file


def _parent_control_map(
    parent: dict[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    merged, inherited = {}, []
    if parent:
        for item in parent["controls"]:
            merged[item["id"]] = item
            inherited.append(item["id"])
    return merged, inherited


def _policy_parent(
    workspace: Path,
    source: Path,
    raw: dict[str, Any],
    seen: tuple[str, ...],
    depth: int,
) -> tuple[dict[str, Any] | None, dict[str, dict[str, Any]], list[str]]:
    parent_raw = raw.get("parent")
    if parent_raw is None:
        return None, {}, []
    path, expected = _parent_reference(parent_raw)
    parent, _ = _load_bound_parent(workspace, source, path, expected, seen, depth)
    merged, inherited = _parent_control_map(parent)
    return parent, merged, inherited


def _merge_policy_controls(
    controls: list[dict[str, Any]], merged: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    for item in controls:
        previous = merged.get(item["id"])
        if previous:
            _reject_weakening(previous, item)
        merged[item["id"]] = item
    return merged


def _reject_weakening(previous: dict[str, Any], candidate: dict[str, Any]) -> None:
    issues = _weakening(previous, candidate)
    if not issues:
        return
    code = (
        "E_CONTROL_WEAKENING"
        if any("removed" not in issue for issue in issues)
        else "E_CONTROL_DELETED"
    )
    raise ControlsError(
        code,
        f"{candidate['id']} cannot weaken inherited control: {', '.join(issues)}",
        details={"control_id": candidate["id"], "changes": issues},
    )


def _validate_parent_removals(
    raw: dict[str, Any], parent_raw: Any, inherited: list[str]
) -> None:
    if parent_raw is None:
        _require(
            not raw.get("remove_controls"),
            "E_CONTROL_DELETED",
            "remove_controls requires an inherited parent",
        )
        return
    removals = raw.get("remove_controls", [])
    _require(
        isinstance(removals, list), "E_INVALID_PACK", "remove_controls must be a list"
    )
    deleted = sorted(set(str(item) for item in removals) & set(inherited))
    _require(
        not deleted,
        "E_CONTROL_DELETED",
        f"inherited controls cannot be deleted: {', '.join(deleted)}",
        details={"control_ids": deleted},
    )


def _validate_inherited_retention(
    inherited: list[str], merged: dict[str, dict[str, Any]]
) -> None:
    _require(
        set(inherited).issubset(set(merged)),
        "E_CONTROL_DELETED",
        "an inherited control was deleted",
    )


def _policy_pack_result(
    workspace: Path,
    source: Path,
    pack_id: str,
    version: str,
    provenance: dict[str, Any],
    author: str,
    approval: dict[str, Any] | None,
    parent: dict[str, Any] | None,
    inherited: list[str],
    controls: list[dict[str, Any]],
    raw: dict[str, Any],
) -> dict[str, Any]:
    raw_digest = _sha_bytes(source.read_bytes())
    effective = {
        "schema": PACK_SCHEMA,
        "pack_id": pack_id,
        "version": version,
        "controls": controls,
    }
    return {
        "schema": PACK_SCHEMA,
        "pack_id": pack_id,
        "version": version,
        "path": _rel(workspace, source),
        "policy_sha256": raw_digest,
        "effective_sha256": _sha(effective),
        "provenance": provenance,
        "authorship": {"author": author},
        "approval": approval,
        "status": _pack_status(provenance, approval),
        "parent": {
            "path": parent["path"],
            "effective_sha256": parent["effective_sha256"],
        }
        if parent
        else None,
        "inherited_control_ids": inherited,
        "controls": controls,
        "exception_policy": {
            "max_ttl_days": int(
                (raw.get("exception_policy") or {}).get("max_ttl_days", 30)
            )
        },
    }


def load_policy_pack(
    root: Path | str = ".",
    path: str = "controls/policy-pack.json",
    *,
    _seen: tuple[str, ...] = (),
    _depth: int = 0,
) -> dict[str, Any]:
    """Resolve a policy pack and all parents, rejecting unsafe mutations."""
    workspace = Path(root).resolve()
    source = _rooted(workspace, path)
    key = source.as_posix()
    _require(_depth <= 8, "E_INHERITANCE_DEPTH", "policy inheritance exceeds depth 8")
    _require(
        key not in _seen, "E_INHERITANCE_CYCLE", f"policy inheritance cycle at {path}"
    )
    raw = _load_json(source)
    pack_id, version, provenance, author, approval = _policy_header(raw, path)
    local_controls = _policy_local_controls(raw, provenance, pack_id)
    parent_raw = raw.get("parent")
    parent, merged, inherited = _policy_parent(workspace, source, raw, _seen, _depth)
    _validate_parent_removals(raw, parent_raw, inherited)
    merged = _merge_policy_controls(local_controls, merged)
    _validate_inherited_retention(inherited, merged)
    effective_controls = [merged[item] for item in sorted(merged)]
    return _policy_pack_result(
        workspace,
        source,
        pack_id,
        version,
        provenance,
        author,
        approval,
        parent,
        inherited,
        effective_controls,
        raw,
    )


def _receipt(root: Path, path: str) -> dict[str, Any]:
    candidate = _rooted(root, path)
    raw = _load_json(candidate)
    expected = raw.get("receipt_sha256") or raw.get("evidence_sha256")
    _hash_field(expected, "receipt_sha256")
    actual = _sha_bytes(candidate.read_bytes())
    # Runners may seal either the complete immutable file or the canonical
    # payload with the digest field removed (the latter avoids a self-hash
    # paradox).  Accept only those two deterministic forms.
    payload = dict(raw)
    payload.pop("receipt_sha256", None)
    payload.pop("evidence_sha256", None)
    detached = _sha(payload)
    _require(
        expected in {actual, detached},
        "E_EVIDENCE_HASH_MISMATCH",
        f"evidence hash mismatch: {path}",
        details={"expected": expected, "actual": actual, "detached": detached},
    )
    _require(
        isinstance(raw.get("control_id"), str) and raw["control_id"],
        "E_INVALID_EVIDENCE",
        f"receipt lacks control_id: {path}",
    )
    _require(
        raw.get("verdict") in {"PASS", "PASSED", "VERIFIED"},
        "E_EVIDENCE_NOT_PASS",
        f"receipt is not a passing proof: {path}",
    )
    return {"path": _rel(root, candidate), "sha256": actual, **raw}


def _exception_files(root: Path, paths: Iterable[str]) -> dict[str, dict[str, Any]]:
    active: dict[str, dict[str, Any]] = {}
    now = _now()
    for path in paths:
        candidate = _rooted(root, path)
        raw = _load_json(candidate)
        _require(
            raw.get("schema") == EXCEPTION_SCHEMA,
            "E_INVALID_EXCEPTION",
            f"{path} is not an exception",
        )
        _require(
            raw.get("control_id") and raw.get("status") == "ACTIVE",
            "E_INVALID_EXCEPTION",
            f"invalid exception: {path}",
        )
        expires = _parse_time(str(raw.get("expires_at", "")))
        if expires <= now:
            active[str(raw["control_id"])] = {
                "expired": True,
                "path": _rel(root, candidate),
                **raw,
            }
            continue
        evidence = _rooted(root, str(raw.get("evidence_path", "")))
        _require(
            evidence.is_file(),
            "E_EXCEPTION_EVIDENCE_MISSING",
            f"exception evidence missing: {evidence}",
        )
        _require(
            raw.get("evidence_sha256") == _sha_bytes(evidence.read_bytes()),
            "E_EXCEPTION_EVIDENCE_MISMATCH",
            f"exception evidence changed: {path}",
        )
        active[str(raw["control_id"])] = {
            "expired": False,
            "path": _rel(root, candidate),
            **raw,
        }
    return active


def create_exception(
    root: Path | str,
    policy_path: str,
    control_id: str,
    *,
    owner: str,
    reason: str,
    scope: str,
    ttl_days: int,
    evidence_path: str,
    author: str,
    approver: str,
    out: str | None = None,
) -> dict[str, Any]:
    """Create an explicit, bounded, separately approved exception record."""
    workspace = Path(root).resolve()
    pack = load_policy_pack(workspace, policy_path)
    control = next(
        (item for item in pack["controls"] if item["id"] == control_id), None
    )
    _require(control is not None, "E_UNKNOWN_CONTROL", f"unknown control: {control_id}")
    _require(
        pack["status"] == "ENFORCED",
        "E_EXCEPTION_UNAUTHORIZED",
        "exceptions require an enforced policy pack",
    )
    _require(
        author.strip() and approver.strip() and author.strip() != approver.strip(),
        "E_SOD_VIOLATION",
        "exception author and approver must be different",
    )
    max_ttl = int(pack["exception_policy"].get("max_ttl_days", 30))
    _require(
        1 <= int(ttl_days) <= max_ttl,
        "E_EXCEPTION_TTL",
        f"exception TTL must be 1..{max_ttl} days",
    )
    _require(
        owner.strip() and reason.strip() and scope.strip(),
        "E_INVALID_EXCEPTION",
        "owner, reason, and scope are required",
    )
    evidence = _rooted(workspace, evidence_path)
    _require(
        evidence.is_file(),
        "E_EXCEPTION_EVIDENCE_MISSING",
        f"exception evidence missing: {evidence_path}",
    )
    issued = _now()
    value = {
        "schema": EXCEPTION_SCHEMA,
        "exception_id": f"exc-{_sha({'control_id': control_id, 'issued_at': _iso(issued)})[:16]}",
        "control_id": control_id,
        "owner": owner.strip(),
        "reason": reason.strip(),
        "scope": scope.strip(),
        "issued_at": _iso(issued),
        "expires_at": _iso(issued + timedelta(days=int(ttl_days))),
        "evidence_path": _rel(workspace, evidence),
        "evidence_sha256": _sha_bytes(evidence.read_bytes()),
        "authorship": {"author": author.strip()},
        "approval": {
            "approver": approver.strip(),
            "decision": "approved",
            "approved_at": _iso(issued),
            "approval_sha256": _sha(
                {
                    "control_id": control_id,
                    "approver": approver,
                    "issued_at": _iso(issued),
                }
            ),
        },
        "status": "ACTIVE",
    }
    if out:
        target = _rooted(workspace, out)
        _write_json(target, value)
        value["path"] = _rel(workspace, target)
    return value


def _control_event(event: dict[str, Any] | None) -> dict[str, Any]:
    value = {
        "kind": "working_tree",
        "actor": "local",
        "commit": None,
        "changed_paths": [],
    }
    if event:
        value.update(event)
    _require(
        value["kind"] in EVENT_KINDS,
        "E_INVALID_EVENT",
        f"event kind must be one of {sorted(EVENT_KINDS)}",
    )
    _require(
        isinstance(value.get("changed_paths", []), list),
        "E_INVALID_EVENT",
        "changed_paths must be a list",
    )
    return value


def _control_evidence(
    workspace: Path, evidence_paths: Iterable[str]
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    receipts, errors = {}, []
    for path in evidence_paths:
        try:
            item = _receipt(workspace, path)
            receipts[item["control_id"]] = item
        except ControlsError as exc:
            errors.append({"path": path, "code": exc.code, "message": str(exc)})
    return receipts, errors


def _policy_drift(
    baseline: dict[str, Any] | None, pack: dict[str, Any], event: dict[str, Any]
) -> list[dict[str, Any]]:
    findings = []
    if not baseline:
        return findings
    if baseline.get("effective_sha256") != pack["effective_sha256"]:
        findings.append(
            {
                "code": "E_POLICY_DRIFT",
                "before": baseline.get("effective_sha256"),
                "after": pack["effective_sha256"],
                "event": event["kind"],
            }
        )
    if (
        baseline.get("policy_sha256")
        and baseline.get("policy_sha256") != pack["policy_sha256"]
    ):
        findings.append(
            {
                "code": "E_POLICY_SOURCE_DRIFT",
                "before": baseline.get("policy_sha256"),
                "after": pack["policy_sha256"],
            }
        )
    return findings


def _control_entry(
    control: dict[str, Any],
    pack: dict[str, Any],
    receipts: dict[str, dict[str, Any]],
    exceptions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    cid, provenance = control["id"], control["provenance"]
    enforced = (
        pack["status"] == "ENFORCED" and provenance["kind"] in ENFORCING_PROVENANCE
    )
    entry = {
        "id": cid,
        "title": control["title"],
        "severity": control["severity"],
        "provenance": provenance,
        "enforced": enforced,
        "required_evidence": control["required_evidence"],
        "remediation": control["remediation"],
        "forbidden_behavior": control["forbidden_behavior"],
        "gate": control["gate"],
        "test": control["test"],
    }
    exception = exceptions.get(cid)
    if exception and exception.get("expired"):
        entry.update(
            status="BLOCKED",
            blocker={"code": "E_EXCEPTION_EXPIRED", "message": "exception has expired"},
        )
    elif exception:
        entry.update(
            status="EXEMPT",
            exception_id=exception["exception_id"],
            exception_scope=exception["scope"],
        )
    elif cid in receipts:
        entry.update(status="PASSED", receipt=receipts[cid])
    elif enforced:
        entry.update(
            status="MISSING_EVIDENCE",
            blocker={
                "code": "E_MISSING_EVIDENCE",
                "message": "a fresh independent receipt is required",
            },
        )
    else:
        entry.update(
            status="ADVISORY", advisory_reason="provenance or approval is not blocking"
        )
    return entry


def _control_entries(
    pack: dict[str, Any],
    receipts: dict[str, dict[str, Any]],
    exceptions: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        _control_entry(control, pack, receipts, exceptions)
        for control in pack["controls"]
    ]


def _apply_evidence_drift(
    controls: list[dict[str, Any]],
    drift_findings: list[dict[str, Any]],
    pack: dict[str, Any],
) -> None:
    if not drift_findings or pack["status"] != "ENFORCED":
        return
    for item in controls:
        if item["status"] == "PASSED":
            item["status"] = "BLOCKED"
            item["blocker"] = {
                "code": item.get("blocker", {}).get("code", "E_POLICY_DRIFT"),
                "message": "policy or evidence drift must be reviewed",
            }


def _control_coverage_and_action(
    controls: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    blockers = [
        item for item in controls if item["status"] in {"BLOCKED", "MISSING_EVIDENCE"}
    ]
    coverage = {
        "total": len(controls),
        "enforced": sum(item["enforced"] for item in controls),
        "passed": sum(item["status"] == "PASSED" for item in controls),
        "exempt": sum(item["status"] == "EXEMPT" for item in controls),
        "advisory": sum(item["status"] == "ADVISORY" for item in controls),
        "blocked": len(blockers),
    }
    first = sorted(blockers, key=lambda item: item["id"])[0] if blockers else None
    action = _control_next_action(first)
    return blockers, coverage, action


def _control_next_action(first: dict[str, Any] | None) -> dict[str, Any]:
    if first is None:
        return {
            "action": "review_human_release",
            "reason": "all enforced controls have fresh evidence",
        }
    return {
        "action": f"provide_evidence:{first['id']}",
        "reason": first.get("blocker", {}).get("message", first["remediation"]),
        "control_id": first["id"],
        "remediation": first["remediation"],
    }


def _control_evaluation_payload(
    pack: dict[str, Any],
    event: dict[str, Any],
    controls: list[dict[str, Any]],
    coverage: dict[str, int],
    blockers: list[dict[str, Any]],
    drift_findings: list[dict[str, Any]],
    next_action: dict[str, Any],
    repo_id: str | None,
) -> dict[str, Any]:
    return {
        "schema": EVALUATION_SCHEMA,
        "evaluation_id": f"eval-{_sha({'policy': pack['effective_sha256'], 'event': event, 'controls': [(item['id'], item['status']) for item in controls]})[:16]}",
        "repo_id": repo_id,
        "policy": {
            key: pack[key]
            for key in (
                "path",
                "pack_id",
                "version",
                "policy_sha256",
                "effective_sha256",
                "provenance",
                "status",
                "inherited_control_ids",
            )
        },
        "event": event,
        "controls": controls,
        "coverage": coverage,
        "drift": {
            "state": "BLOCKED"
            if blockers
            else ("DRIFT" if drift_findings else "CLEAR"),
            "findings": drift_findings,
        },
        "next_action": next_action,
        "decision": "REVIEW_REQUIRED"
        if blockers or drift_findings
        else "READY_FOR_HUMAN_REVIEW",
        "authority": {
            "release": False,
            "merge": False,
            "deploy": False,
            "credentials": False,
        },
        "evaluated_at": _iso(_now()),
    }


def evaluate_controls(
    root: Path | str = ".",
    policy_path: str = "controls/policy-pack.json",
    *,
    evidence_paths: Iterable[str] = (),
    baseline: dict[str, Any] | None = None,
    event: dict[str, Any] | None = None,
    exception_paths: Iterable[str] = (),
    repo_id: str | None = None,
) -> dict[str, Any]:
    """Evaluate policy controls against immutable receipts without executing code."""
    workspace = Path(root).resolve()
    pack = load_policy_pack(workspace, policy_path)
    event_value = _control_event(event)
    receipts, evidence_errors = _control_evidence(workspace, evidence_paths)
    exceptions = _exception_files(workspace, exception_paths)
    drift_findings = _policy_drift(baseline, pack, event_value)
    controls = _control_entries(pack, receipts, exceptions)
    drift_findings.extend(evidence_errors)
    _apply_evidence_drift(controls, drift_findings, pack)
    blockers, coverage, next_action = _control_coverage_and_action(controls)
    evaluation = _control_evaluation_payload(
        pack,
        event_value,
        controls,
        coverage,
        blockers,
        drift_findings,
        next_action,
        repo_id,
    )
    evaluation["evaluation_sha256"] = _sha(evaluation)
    return evaluation


def write_control_evaluation(
    root: Path | str, evaluation: dict[str, Any], out: str | None = None
) -> dict[str, Any]:
    """Persist one immutable evaluation receipt below the workspace controls ledger."""
    workspace = Path(root).resolve()
    target = _rooted(
        workspace,
        out
        or f".factory/controls/evaluations/{evaluation['evaluation_sha256'][:16]}.json",
    )
    _write_json(target, evaluation)
    return {
        "path": _rel(workspace, target),
        "sha256": _sha_bytes(target.read_bytes()),
        **evaluation,
    }


def build_control_graph(evaluation: dict[str, Any]) -> dict[str, Any]:
    """Build the ordered intent-to-decision Graph Ops chain for an evaluation."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    intent = f"intent:{evaluation['policy']['effective_sha256']}"
    decision = f"decision:{evaluation['evaluation_id']}"
    nodes.append(
        {
            "id": intent,
            "kind": "intent",
            "label": f"Policy {evaluation['policy']['pack_id']}",
            "sha256": evaluation["policy"]["effective_sha256"],
        }
    )
    nodes.append({"id": decision, "kind": "decision", "label": evaluation["decision"]})
    for item in evaluation["controls"]:
        cid = item["id"]
        control = f"control:{cid}"
        forbidden = f"forbidden:{cid}"
        gate = f"gate:{cid}"
        test = f"test:{cid}"
        receipt_digest = item.get("receipt", {}).get("sha256")
        receipt = (
            f"receipt:{receipt_digest}" if receipt_digest else f"receipt:{cid}:missing"
        )
        nodes.extend(
            [
                {
                    "id": control,
                    "kind": "control",
                    "label": item["title"],
                    "status": item["status"],
                    "provenance": item["provenance"],
                },
                {
                    "id": forbidden,
                    "kind": "forbidden_behavior",
                    "label": item["forbidden_behavior"],
                },
                {"id": gate, "kind": "gate", "label": str(item["gate"].get("id", cid))},
                {"id": test, "kind": "test", "label": str(item["test"].get("id", cid))},
                {
                    "id": receipt,
                    "kind": "receipt",
                    "label": "evidence" if item.get("receipt") else "missing",
                },
            ]
        )
        for source, target, relation in (
            (intent, control, "defines"),
            (control, forbidden, "forbids"),
            (forbidden, gate, "guards"),
            (gate, test, "challenged_by"),
            (test, receipt, "evidenced_by"),
            (receipt, decision, "decides"),
        ):
            edges.append({"source": source, "target": target, "relation": relation})
    graph = {"nodes": nodes, "edges": edges}
    graph["graph_sha256"] = _sha(graph)
    return graph


def render_controls_review(evaluation: dict[str, Any]) -> str:
    """Render a concise, deterministic Markdown review with one remediation."""
    lines = [
        "# Code Factory Continuous Controls",
        "",
        f"Decision: **{evaluation['decision']}**",
        f"Policy: `{evaluation['policy']['pack_id']}@{evaluation['policy']['version']}` (`{evaluation['policy']['effective_sha256']}`)",
        f"Event: `{evaluation['event']['kind']}`",
        "",
        "## Coverage",
        f"`{evaluation['coverage']['passed']}` passed · `{evaluation['coverage']['exempt']}` exempt · `{evaluation['coverage']['advisory']}` advisory · `{evaluation['coverage']['blocked']}` blocked",
        "",
        "## Controls",
        "| Control | Status | Provenance | Next action |",
        "|---|---|---|---|",
    ]
    for item in evaluation["controls"]:
        lines.append(
            f"| `{item['id']}` {item['title']} | **{item['status']}** | `{item['provenance']['kind']}` | {item['remediation']} |"
        )
    lines.extend(
        [
            "",
            "## One next action",
            f"**{evaluation['next_action']['action']}** — {evaluation['next_action']['reason']}",
            "",
            "## Graph Ops chain",
            "`intent → control → forbidden behavior → gate → test → receipt → decision`",
            "",
            "## Drift",
            f"`{evaluation['drift']['state']}` ({len(evaluation['drift']['findings'])} finding(s))",
            "",
            "_This packet is evidence for human review; it never authorizes release, merge, deployment, or credentials._",
        ]
    )
    return "\n".join(lines) + "\n"


def _mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart TD"]
    for node in graph["nodes"]:
        label = str(node.get("label", node["id"])).replace('"', "'")[:160]
        lines.append(f'    {node["id"].replace(":", "_")}["{label}"]')
    for edge in graph["edges"]:
        lines.append(
            f"    {edge['source'].replace(':', '_')} -->|{edge['relation']}| {edge['target'].replace(':', '_')}"
        )
    return "\n".join(lines) + "\n"


def write_controls_dossier(
    root: Path | str,
    evaluation: dict[str, Any],
    out_dir: str = ".factory/controls/dossiers",
) -> dict[str, Any]:
    """Write JSON, Markdown, and Mermaid evidence artifacts for human review."""
    workspace = Path(root).resolve()
    graph = build_control_graph(evaluation)
    base = _rooted(workspace, out_dir) / evaluation["evaluation_id"]
    base.mkdir(parents=True, exist_ok=True)
    payload = {"schema": DOSSIER_SCHEMA, "evaluation": evaluation, "graph": graph}
    _write_json(base / "dossier.json", payload)
    (base / "review.md").write_text(
        render_controls_review(evaluation), encoding="utf-8"
    )
    (base / "graph.mmd").write_text(_mermaid(graph), encoding="utf-8")
    return {
        "directory": _rel(workspace, base),
        "json": _rel(workspace, base / "dossier.json"),
        "markdown": _rel(workspace, base / "review.md"),
        "mermaid": _rel(workspace, base / "graph.mmd"),
        "dossier_sha256": _sha_bytes((base / "dossier.json").read_bytes()),
    }


def fleet_coverage(
    root: Path | str, fleet_path: str = "controls/fleet.json"
) -> dict[str, Any]:
    """Report inherited policy coverage and missing baseline controls by repository."""
    workspace = Path(root).resolve()
    raw = _load_json(_rooted(workspace, fleet_path))
    _require(
        raw.get("schema") == FLEET_SCHEMA,
        "E_INVALID_FLEET",
        f"fleet must use {FLEET_SCHEMA}",
    )
    repos = raw.get("repositories", [])
    _require(
        isinstance(repos, list) and len(repos) <= 500,
        "E_INVALID_FLEET",
        "repositories must be a list of at most 500",
    )
    baseline = set(raw.get("baseline_controls", []))
    entries = []
    for item in repos:
        _require(
            isinstance(item, dict)
            and item.get("id")
            and item.get("path")
            and item.get("policy"),
            "E_INVALID_FLEET",
            "each repository needs id, path, and policy",
        )
        repo_root = _rooted(workspace, str(item["path"]))
        pack = load_policy_pack(repo_root, str(item["policy"]))
        ids = {control["id"] for control in pack["controls"]}
        entries.append(
            {
                "id": item["id"],
                "path": _rel(workspace, repo_root),
                "policy": pack["path"],
                "status": pack["status"],
                "control_count": len(ids),
                "enforced_count": sum(
                    control["provenance"]["kind"] in ENFORCING_PROVENANCE
                    and pack["status"] == "ENFORCED"
                    for control in pack["controls"]
                ),
                "missing_baseline": sorted(baseline - ids),
            }
        )
    return {
        "schema": FLEET_SCHEMA,
        "baseline_controls": sorted(baseline),
        "repositories": entries,
        "coverage_sha256": _sha(entries),
    }


def verify_control_evaluation(root: Path | str, path: str) -> dict[str, Any]:
    """Verify the content digest of a stored controls evaluation receipt."""
    workspace = Path(root).resolve()
    value = _load_json(_rooted(workspace, path))
    claimed = value.pop("evaluation_sha256", None)
    _require(
        claimed and claimed == _sha(value),
        "E_EVALUATION_HASH_MISMATCH",
        "evaluation digest does not match payload",
    )
    value["evaluation_sha256"] = claimed
    return {"verified": True, "evaluation_sha256": claimed, "path": path}


def continuous_controls_projection(root: Path | str = ".") -> dict[str, Any]:
    """Read-only bounded projection for Graph Ops and IDE mission control."""
    workspace = Path(root).resolve()
    directory = workspace / ".factory" / "controls" / "evaluations"
    records: list[dict[str, Any]] = []
    if directory.is_dir():
        for candidate in sorted(directory.glob("*.json"))[:500]:
            try:
                value = _load_json(candidate)
                claimed = value.get("evaluation_sha256")
                clone = dict(value)
                clone.pop("evaluation_sha256", None)
                valid = bool(claimed and claimed == _sha(clone))
                records.append(
                    {
                        "path": _rel(workspace, candidate),
                        "evaluation_id": value.get("evaluation_id"),
                        "decision": value.get("decision"),
                        "drift": value.get("drift", {}).get("state"),
                        "coverage": value.get("coverage", {}),
                        "evaluated_at": value.get("evaluated_at"),
                        "hash_valid": valid,
                    }
                )
            except ControlsError:
                records.append(
                    {
                        "path": _rel(workspace, candidate),
                        "hash_valid": False,
                        "decision": "INVALID",
                    }
                )
    records.sort(
        key=lambda item: (
            str(item.get("evaluated_at") or ""),
            str(item.get("path") or ""),
        )
    )
    latest = records[-1] if records else None
    return {
        "schema": "factory.continuous-controls-projection.v1",
        "evaluation_count": len(records),
        "invalid_count": sum(not item.get("hash_valid") for item in records),
        "latest": latest,
        "evaluations": records,
        "read_only": True,
    }


__all__ = [
    "ControlsError",
    "load_policy_pack",
    "evaluate_controls",
    "create_exception",
    "write_control_evaluation",
    "build_control_graph",
    "render_controls_review",
    "write_controls_dossier",
    "fleet_coverage",
    "verify_control_evaluation",
    "continuous_controls_projection",
    "PACK_SCHEMA",
    "EVALUATION_SCHEMA",
    "EXCEPTION_SCHEMA",
    "DOSSIER_SCHEMA",
    "FLEET_SCHEMA",
]

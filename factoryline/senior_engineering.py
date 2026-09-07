"""Read-only projection for the 0.46.3 senior-engineering receipts.

The projection is intentionally narrower than the four CLI adapters: it reads
only bounded JSON receipts already written below ``.factory/senior`` and
recomputes their local integrity hashes.  It never executes a replay, reuses a
proof, or grants release authority.  Graph Ops can therefore show the state of
the new controls without turning the visual surface into another gate runner.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .runtime_audit_common import canonical_bytes


ROOT_RELATIVE = Path(".factory") / "senior"
MAX_RECEIPTS = 256
MAX_BYTES = 1_048_576
_SCHEMAS = {
    "factory.execution-attestation.v1",
    "factory.execution-attestation-verification.v1",
    "factory.defect-benchmark-receipt.v1",
    "factory.incremental-plan.v1",
    "factory.incremental-shadow.v1",
    "factory.replay-receipt.v1",
    "factory.repair-comparison.v1",
    "factory.evidence-reuse.v1",
    "factory.failure-brief.v1",
}


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _integrity(value: dict[str, Any]) -> tuple[bool, str | None]:
    """Return local self-hash status for receipts that define one."""
    schema = value.get("schema")
    if schema == "factory.defect-benchmark-receipt.v1":
        supplied = value.get("receipt_sha256")
        core = {key: item for key, item in value.items() if key != "receipt_sha256"}
        expected = _digest(core)
    elif schema == "factory.incremental-plan.v1":
        supplied = value.get("plan_sha256")
        core = {key: item for key, item in value.items() if key != "plan_sha256"}
        expected = _digest(core)
    elif schema == "factory.incremental-shadow.v1":
        supplied = value.get("receipt_sha256")
        core = {key: item for key, item in value.items() if key != "receipt_sha256"}
        expected = _digest(core)
    elif schema in {"factory.replay-receipt.v1", "factory.repair-comparison.v1", "factory.evidence-reuse.v1"}:
        supplied = value.get("receipt_sha256")
        core = {key: item for key, item in value.items() if key != "receipt_sha256"}
        expected = _digest(core)
    elif schema == "factory.failure-brief.v1":
        supplied = value.get("brief_sha256")
        core = {key: item for key, item in value.items() if key != "brief_sha256"}
        expected = _digest(core)
    else:
        return True, None
    if not isinstance(supplied, str):
        return False, "SELF_HASH_MISSING"
    if supplied != expected:
        return False, "SELF_HASH_MISMATCH"
    return True, supplied


def _status(value: dict[str, Any], schema: str, valid: bool) -> str:
    if not valid:
        return "INVALID"
    if schema == "factory.execution-attestation-verification.v1":
        return str(value.get("state", "UNKNOWN"))
    if schema == "factory.defect-benchmark-receipt.v1":
        return str(value.get("decision", "UNKNOWN"))
    if schema == "factory.incremental-plan.v1":
        counts = value.get("counts")
        return "BLOCKED" if isinstance(counts, dict) and counts.get("BLOCK", 0) else "PLANNED"
    if schema == "factory.incremental-shadow.v1":
        return "EQUIVALENT" if value.get("shadow_equivalent") is True else "MISMATCH"
    if schema == "factory.replay-receipt.v1":
        return str(value.get("state", "UNKNOWN"))
    if schema == "factory.repair-comparison.v1":
        return str(value.get("state", "UNKNOWN"))
    if schema == "factory.evidence-reuse.v1":
        counts = value.get("counts")
        return "BLOCKED" if isinstance(counts, dict) and counts.get("BLOCK", 0) else "PLANNED"
    if schema == "factory.failure-brief.v1":
        return str(value.get("state", "UNKNOWN"))
    return "PLANNED"


def _summarize(path: Path, root: Path, value: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    schema = value.get("schema")
    if schema not in _SCHEMAS:
        return ({"path": _relative(root, path), "schema": schema if isinstance(schema, str) else None, "status": "UNRECOGNIZED", "error": "SCHEMA_UNRECOGNIZED"}, False)
    if value.get("authority") != "none":
        return ({"path": _relative(root, path), "schema": schema, "status": "INVALID", "error": "AUTHORITY_NOT_NONE", "authority": value.get("authority")}, False)
    integrity_ok, digest = _integrity(value)
    status = _status(value, schema, integrity_ok)
    valid = integrity_ok and status not in {"UNKNOWN", "INVALID"}
    item: dict[str, Any] = {
        "path": _relative(root, path),
        "schema": schema,
        "status": status,
        "valid": valid,
        "authority": value.get("authority", "none"),
    }
    if digest:
        item["receipt_sha256"] = digest
    if not integrity_ok:
        item["error"] = "SELF_HASH_MISMATCH" if value.get("receipt_sha256") or value.get("plan_sha256") else "SELF_HASH_MISSING"
    if schema == "factory.execution-attestation.v1":
        item["attestation_id"] = value.get("attestation_id")
        item["assurance_level"] = value.get("assurance_level")
    elif schema == "factory.execution-attestation-verification.v1":
        item["attestation_id"] = value.get("attestation_id")
        item["assurance_level"] = value.get("assurance_level")
    elif schema == "factory.defect-benchmark-receipt.v1":
        item["benchmark_id"] = (value.get("benchmark") or {}).get("benchmark_id") if isinstance(value.get("benchmark"), dict) else None
    elif schema == "factory.incremental-plan.v1":
        item["plan_id"] = value.get("plan_id")
        item["counts"] = value.get("counts") if isinstance(value.get("counts"), dict) else {}
    elif schema == "factory.incremental-shadow.v1":
        item["shadow_equivalent"] = value.get("shadow_equivalent") is True
    elif schema == "factory.replay-receipt.v1":
        item["replay_id"] = value.get("replay_id")
        item["executed"] = value.get("executed") is True
    elif schema == "factory.repair-comparison.v1":
        item["comparison_id"] = value.get("comparison_id")
        item["executed"] = value.get("executed") is True
    elif schema == "factory.evidence-reuse.v1":
        item["request_id"] = value.get("request_id")
        item["counts"] = value.get("counts") if isinstance(value.get("counts"), dict) else {}
    elif schema == "factory.failure-brief.v1":
        item["state"] = value.get("state")
        item["finding_count"] = len(value.get("what_broke", [])) if isinstance(value.get("what_broke"), list) else 0
    return item, valid


def senior_engineering_projection(root: Path) -> dict[str, Any]:
    """Project bounded senior receipts with explicit review-only semantics."""
    workspace = Path(root).resolve()
    directory = workspace / ROOT_RELATIVE
    receipts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    if directory.is_symlink():
        errors.append({"path": ROOT_RELATIVE.as_posix(), "code": "SYMLINK_REFUSED"})
        paths = []
    else:
        paths = sorted(directory.glob("*.json")) if directory.is_dir() else []
    if len(paths) > MAX_RECEIPTS:
        errors.append({"path": ROOT_RELATIVE.as_posix(), "code": "RECEIPT_LIMIT"})
        paths = paths[:MAX_RECEIPTS]
    for path in paths:
        relative = _relative(workspace, path)
        if path.is_symlink():
            errors.append({"path": relative, "code": "SYMLINK_REFUSED"})
            continue
        try:
            if path.stat().st_size > MAX_BYTES:
                errors.append({"path": relative, "code": "SOURCE_TOO_LARGE"})
                continue
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            errors.append({"path": relative, "code": "SOURCE_UNREADABLE"})
            continue
        if not isinstance(value, dict):
            errors.append({"path": relative, "code": "SOURCE_NOT_OBJECT"})
            continue
        item, valid = _summarize(path, workspace, value)
        receipts.append(item)
        if not valid:
            errors.append({"path": relative, "code": item.get("error", "REVIEW_REQUIRED")})

    counts = {
        "receipt_count": len(receipts),
        "invalid_count": sum(not item.get("valid", False) for item in receipts),
        "verified_count": sum(item.get("schema") in {"factory.execution-attestation-verification.v1", "factory.defect-benchmark-receipt.v1", "factory.replay-receipt.v1", "factory.repair-comparison.v1", "factory.evidence-reuse.v1", "factory.failure-brief.v1"} and item.get("valid") is True for item in receipts),
        "blocked_count": sum(item.get("status") in {"BLOCKED", "MISMATCH", "INVALID"} for item in receipts),
        "run_count": sum(item.get("schema") == "factory.incremental-plan.v1" and item.get("counts", {}).get("RUN", 0) > 0 for item in receipts),
        "reuse_count": sum(item.get("schema") == "factory.incremental-plan.v1" and item.get("counts", {}).get("REUSE", 0) > 0 for item in receipts),
        "shadow_mismatch_count": sum(item.get("schema") == "factory.incremental-shadow.v1" and item.get("status") == "MISMATCH" for item in receipts),
        "authority_false": True,
    }
    return {
        "schema": "factory.senior-engineering-projection.v1",
        "marker": "SENIOR_ENGINEERING_READ_ONLY",
        **counts,
        "claim_boundary": "Projects supplied senior-engineering receipts; does not execute tests, verify external runners, or grant release authority.",
        "authority": {"execution": False, "approval": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False},
        "receipts": sorted(receipts, key=lambda item: item["path"]),
        "errors": sorted(errors, key=lambda item: (item["path"], item["code"])),
    }

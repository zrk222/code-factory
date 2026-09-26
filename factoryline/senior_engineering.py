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
    "factory.runtime-boundary-attestation.v1",
    "factory.runtime-boundary-verification.v1",
    "factory.supply-chain-receipt.v1",
    "factory.supply-chain-verification.v1",
    "factory.defect-benchmark-receipt.v1",
    "factory.incremental-plan.v1",
    "factory.incremental-shadow.v1",
    "factory.replay-receipt.v1",
    "factory.repair-comparison.v1",
    "factory.evidence-reuse.v1",
    "factory.failure-brief.v1",
}

_HASH_FIELDS = {
    "factory.defect-benchmark-receipt.v1": "receipt_sha256",
    "factory.incremental-plan.v1": "plan_sha256",
    "factory.incremental-shadow.v1": "receipt_sha256",
    "factory.replay-receipt.v1": "receipt_sha256",
    "factory.repair-comparison.v1": "receipt_sha256",
    "factory.evidence-reuse.v1": "receipt_sha256",
    "factory.failure-brief.v1": "brief_sha256",
    "factory.runtime-boundary-attestation.v1": "attestation_sha256",
    "factory.runtime-boundary-verification.v1": "verification_sha256",
    "factory.supply-chain-receipt.v1": "receipt_sha256",
    "factory.supply-chain-verification.v1": "verification_sha256",
}

_STATE_FIELDS = {
    "factory.execution-attestation-verification.v1": "state",
    "factory.runtime-boundary-verification.v1": "state",
    "factory.supply-chain-verification.v1": "state",
    "factory.replay-receipt.v1": "state",
    "factory.repair-comparison.v1": "state",
    "factory.failure-brief.v1": "state",
}

_DECISION_FIELDS = {
    "factory.defect-benchmark-receipt.v1": "decision",
}

_OUTPUT_HASH_FIELDS = {
    "factory.runtime-boundary-attestation.v1": "attestation_sha256",
    "factory.runtime-boundary-verification.v1": "verification_sha256",
}


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _integrity(value: dict[str, Any]) -> tuple[bool, str | None]:
    """Return local self-hash status for receipts that define one."""
    field = _HASH_FIELDS.get(value.get("schema"))
    if field is None:
        return True, None
    supplied = value.get(field)
    core = {key: item for key, item in value.items() if key != field}
    expected = _digest(core)
    if not isinstance(supplied, str):
        return False, "SELF_HASH_MISSING"
    if supplied != expected:
        return False, "SELF_HASH_MISMATCH"
    return True, supplied


def _status_for_state(value: dict[str, Any], schema: str) -> str | None:
    field = _STATE_FIELDS.get(schema)
    return str(value.get(field, "UNKNOWN")) if field is not None else None


def _status_for_decision(value: dict[str, Any], schema: str) -> str | None:
    if schema == "factory.supply-chain-receipt.v1":
        return "PASS" if value.get("decision") == "PASS" else "BLOCKED"
    field = _DECISION_FIELDS.get(schema)
    return str(value.get(field, "UNKNOWN")) if field is not None else None


def _status_for_isolation(value: dict[str, Any], schema: str) -> str | None:
    if schema != "factory.runtime-boundary-attestation.v1":
        return None
    isolation = value.get("isolation")
    return (
        str(isolation.get("state", "UNKNOWN"))
        if isinstance(isolation, dict)
        else "UNKNOWN"
    )


def _status_for_counts(value: dict[str, Any], schema: str) -> str | None:
    if schema not in {
        "factory.incremental-plan.v1",
        "factory.evidence-reuse.v1",
    }:
        return None
    counts = value.get("counts")
    return (
        "BLOCKED" if isinstance(counts, dict) and counts.get("BLOCK", 0) else "PLANNED"
    )


def _status(value: dict[str, Any], schema: str, valid: bool) -> str:
    if not valid:
        return "INVALID"
    if schema == "factory.incremental-shadow.v1":
        return "EQUIVALENT" if value.get("shadow_equivalent") is True else "MISMATCH"
    for resolver in (
        _status_for_state,
        _status_for_decision,
        _status_for_isolation,
        _status_for_counts,
    ):
        status = resolver(value, schema)
        if status is not None:
            return status
    return "PLANNED"


def _unrecognized_summary(
    path: Path, root: Path, schema: object
) -> tuple[dict[str, Any], bool]:
    return (
        {
            "path": _relative(root, path),
            "schema": schema if isinstance(schema, str) else None,
            "status": "UNRECOGNIZED",
            "error": "SCHEMA_UNRECOGNIZED",
        },
        False,
    )


def _unauthorized_summary(
    path: Path, root: Path, schema: str, value: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    return (
        {
            "path": _relative(root, path),
            "schema": schema,
            "status": "INVALID",
            "error": "AUTHORITY_NOT_NONE",
            "authority": value.get("authority"),
        },
        False,
    )


def _base_summary(
    path: Path, root: Path, value: dict[str, Any], schema: str
) -> tuple[dict[str, Any], bool, str | None, bool]:
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
    return item, valid, digest, integrity_ok


def _add_integrity_fields(
    item: dict[str, Any],
    value: dict[str, Any],
    schema: str,
    digest: str | None,
    integrity_ok: bool,
) -> None:
    if digest:
        field = _OUTPUT_HASH_FIELDS.get(schema, "receipt_sha256")
        item[field] = digest
    if integrity_ok:
        return
    field = _HASH_FIELDS.get(schema, "receipt_sha256")
    item["error"] = "SELF_HASH_MISMATCH" if value.get(field) else "SELF_HASH_MISSING"


def _add_execution_attestation_fields(
    item: dict[str, Any], value: dict[str, Any], schema: str
) -> None:
    if schema not in {
        "factory.execution-attestation.v1",
        "factory.execution-attestation-verification.v1",
    }:
        return
    item["attestation_id"] = value.get("attestation_id")
    item["assurance_level"] = value.get("assurance_level")


def _add_runtime_boundary_fields(
    item: dict[str, Any], value: dict[str, Any], schema: str
) -> None:
    if schema == "factory.runtime-boundary-attestation.v1":
        item["attestation_id"] = value.get("attestation_id")
        item["requested_isolation"] = value.get("requested_isolation")
        isolation = value.get("isolation")
        item["observed_backend"] = (
            isolation.get("backend") if isinstance(isolation, dict) else None
        )
    elif schema == "factory.runtime-boundary-verification.v1":
        item["attestation_id"] = value.get("attestation_id")
        item["requested_isolation"] = value.get("requested_isolation")
        item["observed_backend"] = value.get("observed_backend")


def _add_supply_chain_fields(
    item: dict[str, Any], value: dict[str, Any], schema: str
) -> None:
    if schema == "factory.supply-chain-receipt.v1":
        item["attestation_id"] = value.get("attestation_id")
        item["candidate_sha256"] = value.get("candidate_sha256")
        facts = value.get("facts")
        item["artifact_count"] = (
            facts.get("artifact_count") if isinstance(facts, dict) else None
        )
        unresolved = facts.get("unresolved") if isinstance(facts, dict) else None
        item["unresolved_high"] = (
            unresolved.get("high") if isinstance(unresolved, dict) else None
        )
    elif schema == "factory.supply-chain-verification.v1":
        item["attestation_id"] = value.get("attestation_id")
        item["candidate_sha256"] = value.get("candidate_sha256")
        item["collector"] = value.get("collector")


def _add_benchmark_fields(
    item: dict[str, Any], value: dict[str, Any], schema: str
) -> None:
    if schema != "factory.defect-benchmark-receipt.v1":
        return
    benchmark = value.get("benchmark")
    item["benchmark_id"] = (
        benchmark.get("benchmark_id") if isinstance(benchmark, dict) else None
    )


def _add_incremental_fields(
    item: dict[str, Any], value: dict[str, Any], schema: str
) -> None:
    if schema == "factory.incremental-plan.v1":
        item["plan_id"] = value.get("plan_id")
        counts = value.get("counts")
        item["counts"] = counts if isinstance(counts, dict) else {}
    elif schema == "factory.incremental-shadow.v1":
        item["shadow_equivalent"] = value.get("shadow_equivalent") is True


def _add_replay_fields(
    item: dict[str, Any], value: dict[str, Any], schema: str
) -> None:
    if schema == "factory.replay-receipt.v1":
        item["replay_id"] = value.get("replay_id")
        item["executed"] = value.get("executed") is True
    elif schema == "factory.repair-comparison.v1":
        item["comparison_id"] = value.get("comparison_id")
        item["executed"] = value.get("executed") is True


def _add_reuse_fields(item: dict[str, Any], value: dict[str, Any], schema: str) -> None:
    if schema != "factory.evidence-reuse.v1":
        return
    item["request_id"] = value.get("request_id")
    counts = value.get("counts")
    item["counts"] = counts if isinstance(counts, dict) else {}


def _add_failure_brief_fields(
    item: dict[str, Any], value: dict[str, Any], schema: str
) -> None:
    if schema != "factory.failure-brief.v1":
        return
    item["state"] = value.get("state")
    findings = value.get("what_broke", [])
    item["finding_count"] = len(findings) if isinstance(findings, list) else 0


def _summarize(
    path: Path, root: Path, value: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    schema = value.get("schema")
    if schema not in _SCHEMAS:
        return _unrecognized_summary(path, root, schema)
    if value.get("authority") != "none":
        return _unauthorized_summary(path, root, schema, value)
    item, valid, digest, integrity_ok = _base_summary(path, root, value, schema)
    _add_integrity_fields(item, value, schema, digest, integrity_ok)
    _add_execution_attestation_fields(item, value, schema)
    _add_runtime_boundary_fields(item, value, schema)
    _add_supply_chain_fields(item, value, schema)
    _add_benchmark_fields(item, value, schema)
    _add_incremental_fields(item, value, schema)
    _add_replay_fields(item, value, schema)
    _add_reuse_fields(item, value, schema)
    _add_failure_brief_fields(item, value, schema)
    return item, valid


def _receipt_paths(workspace: Path, errors: list[dict[str, str]]) -> list[Path]:
    directory = workspace / ROOT_RELATIVE
    if directory.is_symlink():
        errors.append({"path": ROOT_RELATIVE.as_posix(), "code": "SYMLINK_REFUSED"})
        paths = []
    else:
        paths = sorted(directory.glob("*.json")) if directory.is_dir() else []
    if len(paths) > MAX_RECEIPTS:
        errors.append({"path": ROOT_RELATIVE.as_posix(), "code": "RECEIPT_LIMIT"})
        paths = paths[:MAX_RECEIPTS]
    return paths


def _read_receipt(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if path.is_symlink():
        return None, "SYMLINK_REFUSED"
    try:
        if path.stat().st_size > MAX_BYTES:
            return None, "SOURCE_TOO_LARGE"
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "SOURCE_UNREADABLE"
    if not isinstance(value, dict):
        return None, "SOURCE_NOT_OBJECT"
    return value, None


def _collect_receipts(
    paths: list[Path], workspace: Path
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    receipts: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for path in paths:
        relative = _relative(workspace, path)
        value, error = _read_receipt(path)
        if error is not None or value is None:
            errors.append({"path": relative, "code": error or "SOURCE_NOT_OBJECT"})
            continue
        item, valid = _summarize(path, workspace, value)
        receipts.append(item)
        if not valid:
            errors.append(
                {"path": relative, "code": item.get("error", "REVIEW_REQUIRED")}
            )
    return receipts, errors


def _verified_count(receipts: list[dict[str, Any]]) -> int:
    verified_schemas = {
        "factory.execution-attestation-verification.v1",
        "factory.runtime-boundary-verification.v1",
        "factory.supply-chain-receipt.v1",
        "factory.supply-chain-verification.v1",
        "factory.defect-benchmark-receipt.v1",
        "factory.replay-receipt.v1",
        "factory.repair-comparison.v1",
        "factory.evidence-reuse.v1",
        "factory.failure-brief.v1",
    }
    return sum(
        item.get("schema") in verified_schemas and item.get("valid") is True
        for item in receipts
    )


def _incremental_counts(receipts: list[dict[str, Any]]) -> tuple[int, int]:
    plans = [
        item for item in receipts if item.get("schema") == "factory.incremental-plan.v1"
    ]
    run_count = sum(item.get("counts", {}).get("RUN", 0) > 0 for item in plans)
    reuse_count = sum(item.get("counts", {}).get("REUSE", 0) > 0 for item in plans)
    return run_count, reuse_count


def _projection_counts(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    run_count, reuse_count = _incremental_counts(receipts)
    return {
        "receipt_count": len(receipts),
        "invalid_count": sum(not item.get("valid", False) for item in receipts),
        "verified_count": _verified_count(receipts),
        "blocked_count": sum(
            item.get("status") in {"BLOCKED", "MISMATCH", "INVALID"}
            for item in receipts
        ),
        "run_count": run_count,
        "reuse_count": reuse_count,
        "shadow_mismatch_count": sum(
            item.get("schema") == "factory.incremental-shadow.v1"
            and item.get("status") == "MISMATCH"
            for item in receipts
        ),
        "authority_false": True,
    }


def senior_engineering_projection(root: Path) -> dict[str, Any]:
    """Project bounded senior receipts with explicit review-only semantics."""
    workspace = Path(root).resolve()
    errors: list[dict[str, str]] = []
    paths = _receipt_paths(workspace, errors)
    receipts, receipt_errors = _collect_receipts(paths, workspace)
    errors.extend(receipt_errors)
    counts = _projection_counts(receipts)
    return {
        "schema": "factory.senior-engineering-projection.v1",
        "marker": "SENIOR_ENGINEERING_READ_ONLY",
        **counts,
        "claim_boundary": "Projects supplied senior-engineering receipts; does not execute tests, verify external runners, or grant release authority.",
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
        "receipts": sorted(receipts, key=lambda item: item["path"]),
        "errors": sorted(errors, key=lambda item: (item["path"], item["code"])),
    }

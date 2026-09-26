"""Fail closed on vague AppForge capture requirements and weak evidence classes."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .appforge_evidence_kit import _read_candidate
from .revenueforge import AUTHORITY, RevenueForgeError

CONTRACT_SCHEMA = "factory.appforge.submission-integrity-contract.v1"
RECEIPT_SCHEMA = "factory.appforge.submission-integrity-receipt.v1"
MAX_BYTES = 1_048_576
_SET_RULES = {"iphone": 10, "ipad_13": 3}


def _canonical(v: object) -> bytes:
    return json.dumps(
        v, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _sha(v: object) -> str:
    return hashlib.sha256(_canonical(v)).hexdigest()


def _file_sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _local(root: Path, path: Path, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_PATH_REJECTED",
            "paths must remain inside the workspace",
        ) from exc
    if exists and not target.is_file():
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_INPUT_UNAVAILABLE",
            "input must be a regular workspace file",
        )
    return target


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_INPUT_TOO_LARGE", "input exceeds 1 MiB"
        )
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_INPUT_INVALID", "input must be JSON"
        ) from exc
    if not isinstance(value, dict):
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_INPUT_INVALID", "input must be an object"
        )
    return value, source


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _finding(code: str, message: str, repair: str) -> dict[str, str]:
    return {"code": code, "message": message, "repair": repair}


_CONTRACT_KEYS = {"schema", "candidate", "requirements", "approval"}
_REQUIREMENT_KEYS = {
    "id",
    "device",
    "journey",
    "state",
    "entrypoint",
    "steps",
    "evidence_class",
    "layout_assertions",
}
_CAPTURE_KEYS = {
    "requirement_id",
    "device",
    "evidence_class",
    "path",
    "sha256",
}


def _validate_contract_binding(
    candidate: dict[str, Any], contract: dict[str, Any]
) -> None:
    if (
        set(contract) != _CONTRACT_KEYS
        or contract.get("schema") != CONTRACT_SCHEMA
        or contract.get("candidate") != candidate
    ):
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_CONTRACT_INVALID",
            "contract must bind the exact candidate and contain only schema, candidate, requirements, and approval",
        )


def _validated_approval(contract: dict[str, Any]) -> dict[str, Any]:
    approval = contract.get("approval")
    if (
        not isinstance(approval, dict)
        or approval.get("origin") not in {"human_confirmed", "trusted_source"}
        or not isinstance(approval.get("source"), str)
        or not approval["source"].strip()
    ):
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_AUTHORITY_MISSING",
            "coverage requirements need a human_confirmed or trusted_source approval with a bounded source",
        )
    return approval


def _loose_requirement(findings: list[dict[str, str]]) -> None:
    findings.append(
        _finding(
            "E_REQUIREMENT_LOOSE",
            "Each requirement needs an id, device, journey, state, entrypoint, steps, evidence class, and layout assertions.",
            "Name the missing user-visible state and the exact path that reaches it; do not infer it from a marketing image.",
        )
    )


def _requirement_identity(
    row: dict[str, Any], seen: set[str], findings: list[dict[str, str]]
) -> tuple[str, str] | None:
    rid = str(row.get("id", "")).strip()
    device = str(row.get("device", "")).strip()
    if not rid or rid in seen or device not in _SET_RULES:
        findings.append(
            _finding(
                "E_REQUIREMENT_LOOSE",
                "Requirement id must be unique and device must be iphone or ipad_13.",
                "Replace the ambiguous requirement with one uniquely named capture for the approved device family.",
            )
        )
        return None
    seen.add(rid)
    return rid, device


def _requirement_steps_are_explicit(row: dict[str, Any]) -> bool:
    steps = row.get("steps")
    return (
        all(
            isinstance(row.get(field), str) and bool(row[field].strip())
            for field in ("journey", "state", "entrypoint")
        )
        and isinstance(steps, list)
        and bool(steps)
        and all(isinstance(step, str) and step.strip() for step in steps)
    )


def _requirement_detail_findings(
    row: dict[str, Any], rid: str, device: str, findings: list[dict[str, str]]
) -> None:
    if not _requirement_steps_are_explicit(row):
        findings.append(
            _finding(
                "E_REQUIREMENT_LOOSE",
                f"{rid} lacks a reviewable journey, state, entrypoint, or capture steps.",
                f"Specify the exact user journey, visible state, entry route, and ordered steps for {rid}.",
            )
        )
    if row.get("evidence_class") != "native_signed_build":
        findings.append(
            _finding(
                "E_COLLATERAL_EVIDENCE_REJECTED",
                f"{rid} is not classified as native_signed_build evidence.",
                "Keep web previews and marketing collateral advisory; collect this capture from the candidate-bound signed native build.",
            )
        )
    assertions = row.get("layout_assertions")
    if device == "ipad_13" and (
        not isinstance(assertions, list) or "desktop_class_layout" not in assertions
    ):
        findings.append(
            _finding(
                "E_TABLET_LAYOUT_UNPROVEN",
                f"{rid} lacks the desktop_class_layout assertion.",
                "Add an explicit iPad 13-inch desktop-class layout assertion tied to the visible state.",
            )
        )


def _normalized_requirement(
    row: object, seen: set[str], findings: list[dict[str, str]]
) -> dict[str, Any] | None:
    if not isinstance(row, dict) or set(row) != _REQUIREMENT_KEYS:
        _loose_requirement(findings)
        return None
    identity = _requirement_identity(row, seen, findings)
    if identity is None:
        return None
    rid, device = identity
    _requirement_detail_findings(row, rid, device, findings)
    return {
        "id": rid,
        "device": device,
        "journey": row.get("journey"),
        "state": row.get("state"),
        "entrypoint": row.get("entrypoint"),
        "steps": row.get("steps"),
        "evidence_class": row.get("evidence_class"),
        "layout_assertions": row.get("layout_assertions"),
    }


def _normalize_requirements(
    rows: list[object], findings: list[dict[str, str]]
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for row in rows:
        item = _normalized_requirement(row, seen, findings)
        if item is not None:
            normalized.append(item)
    return normalized


def _coverage_findings(
    normalized: list[dict[str, Any]], findings: list[dict[str, str]]
) -> dict[str, dict[str, int]]:
    coverage: dict[str, dict[str, int]] = {}
    for device, required in _SET_RULES.items():
        actual = sum(1 for item in normalized if item["device"] == device)
        coverage[device] = {"required": required, "actual": actual}
        if actual != required:
            findings.append(
                _finding(
                    "E_CAPTURE_COVERAGE_MISSING",
                    f"{device} has {actual} named captures; the approved contract requires exactly {required}.",
                    f"Add or remove named {device} requirements until exactly {required} states are specified and independently reviewable.",
                )
            )
    return coverage


def _submission_receipt(
    workspace: Path,
    candidate: dict[str, Any],
    candidate_source: Path,
    contract_source: Path,
    approval: dict[str, Any],
    normalized: list[dict[str, Any]],
    coverage: dict[str, dict[str, int]],
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_SUBMISSION_INTEGRITY_READY"
        if not findings
        else "APPFORGE_SUBMISSION_INTEGRITY_BLOCKED",
        "ok": not findings,
        "action_summary": "Fail closed on vague AppForge screenshot requirements and weak evidence classes; return the smallest deterministic repair for every missing requirement without creating media or operating Apple systems.",
        "candidate": candidate,
        "sources": {
            "candidate": {
                "path": candidate_source.relative_to(workspace).as_posix(),
                "sha256": _file_sha(candidate_source),
            },
            "contract": {
                "path": contract_source.relative_to(workspace).as_posix(),
                "sha256": _file_sha(contract_source),
            },
        },
        "approval": approval,
        "requirements": normalized,
        "coverage": coverage,
        "findings": findings,
        "repair_plan": [item["repair"] for item in findings],
        "authority": {
            **AUTHORITY,
            "execution": False,
            "media_generation": False,
            "device_access": False,
            "apple_access": False,
            "app_review_submit": False,
            "apple_approval_claim": False,
        },
        "claim_boundary": "A local requirement-integrity receipt only. READY means requirements are explicit and candidate-bound, not that images depict the required state or that a native build, device, TestFlight, App Review, or Apple approval exists.",
    }
    return {**core, "receipt_sha256": _sha(core)}


def _validated_submission(
    root: Path, candidate_path: Path, contract_path: Path
) -> dict[str, Any]:
    """Validate a user-approved 10+3 capture contract; never creates or trusts media."""
    workspace = Path(root).resolve()
    candidate, candidate_source = _read_candidate(workspace, candidate_path)
    contract, source = _read(workspace, contract_path)
    _validate_contract_binding(candidate, contract)
    approval = _validated_approval(contract)
    rows = contract.get("requirements")
    if not isinstance(rows, list) or not rows:
        raise RevenueForgeError(
            "APPFORGE_SUBMISSION_INTEGRITY_CONTRACT_INVALID",
            "requirements must be a non-empty list",
        )
    findings: list[dict[str, str]] = []
    normalized = _normalize_requirements(rows, findings)
    coverage = _coverage_findings(normalized, findings)
    return _submission_receipt(
        workspace,
        candidate,
        candidate_source,
        source,
        approval,
        normalized,
        coverage,
        findings,
    )


def verify_submission_integrity(
    root: Path, candidate_path: Path, contract_path: Path, out_path: Path
) -> dict[str, Any]:
    """Validate current source requirements and persist their local receipt."""
    workspace = Path(root).resolve()
    receipt = _validated_submission(workspace, candidate_path, contract_path)
    target = _local(workspace, out_path, False)
    _atomic(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def _revalidate_integrity(workspace: Path, integrity: dict[str, Any]) -> None:
    """A matching local hash does not establish constructor validity or freshness."""
    try:
        sources = integrity["sources"]
        current = _validated_submission(
            workspace,
            Path(sources["candidate"]["path"]),
            Path(sources["contract"]["path"]),
        )
    except (KeyError, TypeError, ValueError, OSError, RevenueForgeError) as exc:
        raise RevenueForgeError(
            "APPFORGE_CAPTURE_RECONCILIATION_INTEGRITY_INVALID",
            "original candidate and contract must remain available and valid",
        ) from exc
    if current != integrity or current.get("ok") is not True:
        raise RevenueForgeError(
            "APPFORGE_CAPTURE_RECONCILIATION_INTEGRITY_INVALID",
            "receipt must match freshly validated candidate and contract requirements",
        )


def submission_integrity_projection(root: Path) -> dict[str, Any]:
    """Project hash-valid local submission-integrity receipts without accessing Apple systems."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    base = workspace / ".factory" / "appforge"
    if base.exists():
        for path in sorted(base.rglob("*submission-integrity*.json"))[:100]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(value, dict):
                    invalid.append(path.relative_to(workspace).as_posix())
                    continue
                supplied = value.get("receipt_sha256")
                if (
                    value.get("schema") == RECEIPT_SCHEMA
                    and isinstance(supplied, str)
                    and _sha({k: v for k, v in value.items() if k != "receipt_sha256"})
                    == supplied
                ):
                    current.append(
                        {
                            "path": path.relative_to(workspace).as_posix(),
                            "marker": value.get("marker"),
                            "receipt_sha256": supplied,
                            "coverage": value.get("coverage"),
                            "finding_count": len(value.get("findings", [])),
                        }
                    )
                else:
                    invalid.append(path.relative_to(workspace).as_posix())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
                invalid.append(path.relative_to(workspace).as_posix())
    return {
        "schema": "factory.appforge.submission-integrity-projection.v1",
        "marker": "APPFORGE_SUBMISSION_INTEGRITY_READ_ONLY",
        "current_count": len(current),
        "invalid_count": len(invalid),
        "latest": current[-1] if current else None,
        "invalid": invalid,
        "authority": {
            **AUTHORITY,
            "execution": False,
            "apple_access": False,
            "apple_approval_claim": False,
        },
        "claim_boundary": "Read-only local requirement-integrity status; not a capture, device, TestFlight, App Review, or Apple approval result.",
    }


def _validate_integrity_receipt(integrity: dict[str, Any]) -> None:
    valid_hash = integrity.get("receipt_sha256") == _sha(
        {key: value for key, value in integrity.items() if key != "receipt_sha256"}
    )
    is_ready = (
        integrity.get("schema") == RECEIPT_SCHEMA
        and integrity.get("marker") == "APPFORGE_SUBMISSION_INTEGRITY_READY"
        and valid_hash
    )
    if not is_ready:
        raise RevenueForgeError(
            "APPFORGE_CAPTURE_RECONCILIATION_INTEGRITY_INVALID",
            "requires a hash-valid ready submission-integrity receipt",
        )


def _validate_evidence_binding(
    integrity: dict[str, Any], evidence: dict[str, Any]
) -> list[dict[str, Any]]:
    if (
        set(evidence) != {"candidate", "captures"}
        or evidence["candidate"] != integrity["candidate"]
        or not isinstance(evidence["captures"], list)
    ):
        raise RevenueForgeError(
            "APPFORGE_CAPTURE_RECONCILIATION_EVIDENCE_INVALID",
            "evidence must bind the exact candidate and declare captures",
        )
    return evidence["captures"]


def _capture_hash_matches(workspace: Path, item: dict[str, Any]) -> bool:
    try:
        path = _local(workspace, Path(item["path"]))
        return isinstance(item["sha256"], str) and item["sha256"] == _file_sha(path)
    except (RevenueForgeError, OSError, TypeError, ValueError):
        return False


def _capture_identity_matches(
    item: dict[str, Any], required: dict[str, dict[str, Any]], seen: set[str]
) -> bool:
    rid = item["requirement_id"]
    if not isinstance(rid, str):
        return False
    expected = required.get(rid)
    return (
        expected is not None
        and rid not in seen
        and item["device"] == expected.get("device")
        and item["evidence_class"] == "native_signed_build"
    )


def _capture_evidence_findings(
    item: object,
    required: dict[str, dict[str, Any]],
    workspace: Path,
    seen: set[str],
    findings: list[dict[str, str]],
) -> None:
    if not isinstance(item, dict) or set(item) != _CAPTURE_KEYS:
        findings.append(
            _finding(
                "E_CAPTURE_EVIDENCE_LOOSE",
                "Capture evidence is missing required identity, device, class, or hash fields.",
                "Record one candidate-bound native capture with its requirement id, device, workspace path, and SHA-256.",
            )
        )
        return
    rid = item["requirement_id"]
    if not _capture_identity_matches(item, required, seen):
        findings.append(
            _finding(
                "E_CAPTURE_EVIDENCE_MISMATCH",
                f"Capture {rid} is duplicate, unknown, wrong-device, or not native signed-build evidence.",
                "Replace it with one unique file mapped to the exact sealed requirement.",
            )
        )
        return
    if not _capture_hash_matches(workspace, item):
        findings.append(
            _finding(
                "E_CAPTURE_EVIDENCE_HASH_INVALID",
                f"Capture {rid} is unavailable or hash-mismatched.",
                "Re-export the actual candidate-bound capture and record its current SHA-256.",
            )
        )
        return
    seen.add(rid)


def _missing_capture_findings(
    required: dict[str, dict[str, Any]], seen: set[str], findings: list[dict[str, str]]
) -> None:
    for rid in sorted(set(required) - seen):
        findings.append(
            _finding(
                "E_CAPTURE_EVIDENCE_MISSING",
                f"No valid capture evidence exists for {rid}.",
                f"Collect the sealed native-build capture for {rid}; do not substitute collateral.",
            )
        )


def _reconcile_capture_rows(
    captures: list[dict[str, Any]],
    integrity: dict[str, Any],
    workspace: Path,
) -> list[dict[str, str]]:
    required = {item["id"]: item for item in integrity["requirements"]}
    seen: set[str] = set()
    findings: list[dict[str, str]] = []
    for item in captures:
        _capture_evidence_findings(item, required, workspace, seen, findings)
    _missing_capture_findings(required, seen, findings)
    return findings


def _capture_reconciliation_receipt(
    workspace: Path,
    integrity: dict[str, Any],
    integrity_source: Path,
    evidence_source: Path,
    findings: list[dict[str, str]],
    out_path: Path,
) -> dict[str, Any]:
    core = {
        "schema": "factory.appforge.capture-reconciliation-receipt.v1",
        "marker": "APPFORGE_CAPTURE_RECONCILIATION_READY"
        if not findings
        else "APPFORGE_CAPTURE_RECONCILIATION_BLOCKED",
        "ok": not findings,
        "action_summary": "Reconcile actual local candidate-bound capture files to sealed requirements and return exact repairs without generating media or accessing Apple.",
        "candidate": integrity["candidate"],
        "integrity_receipt_sha256": integrity["receipt_sha256"],
        "sources": {
            "integrity": {
                "path": integrity_source.relative_to(workspace).as_posix(),
                "sha256": _file_sha(integrity_source),
            },
            "evidence": {
                "path": evidence_source.relative_to(workspace).as_posix(),
                "sha256": _file_sha(evidence_source),
            },
        },
        "finding_count": len(findings),
        "findings": findings,
        "repair_plan": [item["repair"] for item in findings],
        "authority": {
            **AUTHORITY,
            "execution": False,
            "media_generation": False,
            "device_access": False,
            "apple_access": False,
            "apple_approval_claim": False,
        },
        "claim_boundary": "File identity, candidate binding, and hash reconciliation only. It cannot determine what pixels depict, prove device execution, or establish TestFlight, App Review, or Apple approval.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    target = _local(workspace, out_path, False)
    _atomic(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def reconcile_capture_evidence(
    root: Path, integrity_path: Path, evidence_path: Path, out_path: Path
) -> dict[str, Any]:
    """Compare actual local files with sealed capture requirements; never judges pixels."""
    workspace = Path(root).resolve()
    integrity, integrity_source = _read(workspace, integrity_path)
    evidence, evidence_source = _read(workspace, evidence_path)
    _validate_integrity_receipt(integrity)
    _revalidate_integrity(workspace, integrity)
    captures = _validate_evidence_binding(integrity, evidence)
    findings = _reconcile_capture_rows(captures, integrity, workspace)
    return _capture_reconciliation_receipt(
        workspace, integrity, integrity_source, evidence_source, findings, out_path
    )

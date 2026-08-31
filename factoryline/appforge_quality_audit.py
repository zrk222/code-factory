"""Strict, evidence-bound iOS experience and full-stack quality audit.

This is deliberately an evidence verifier, not an AI aesthetic scorer. It
requires an exact candidate, named reviewer confirmation that user design input
was considered, and hash-bound artifacts for each strict design, accessibility,
and runtime lane. Unknown or not-applicable-without-review blocks the receipt.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
import hashlib
import json
import os
import tempfile

from .revenueforge import AUTHORITY, RevenueForgeError


CONTRACT_SCHEMA = "factory.appforge.quality-audit-contract.v1"
EVIDENCE_SCHEMA = "factory.appforge.quality-audit-evidence.v1"
RECEIPT_SCHEMA = "factory.appforge.quality-audit-receipt.v1"
MAX_BYTES = 1_048_576
CANDIDATE_KEYS = ("bundle_identifier", "version", "build_number", "source_commit")
DESIGN_CHECKS = (
    "device_specific_layout",
    "visual_hierarchy",
    "typography_and_readability",
    "color_semantics_and_contrast",
    "loading_empty_error_states",
    "touch_targets_and_gesture_alternatives",
    "dark_mode_and_dynamic_type",
    "reduced_motion_and_feedback",
    "accessibility_common_task_matrix",
    "ipad_adaptive_layout",
)
STACK_CHECKS = (
    "signed_archive_and_clean_build",
    "unit_and_integration_tests",
    "ui_automation",
    "physical_device_smoke",
    "backend_review_environment",
    "authentication_and_authorization",
    "network_failure_recovery",
    "privacy_sdk_and_processor_inventory",
    "performance_budget",
    "observability_and_rollback",
    "dependency_and_secret_scan",
)
CONDITIONAL_CHECKS = ("purchase_and_restore",)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, field: str, *, limit: int = 500) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_QUALITY_AUDIT_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise RevenueForgeError("APPFORGE_QUALITY_AUDIT_INVALID", f"{field} must be a SHA-256 hex digest")
    return result


def _candidate(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RevenueForgeError("APPFORGE_QUALITY_CANDIDATE_INVALID", f"{field} must be an object")
    return {key: _text(value.get(key), f"{field}.{key}", limit=200) for key in CANDIDATE_KEYS}


def _timestamp(value: object, field: str) -> str:
    result = _text(value, field, limit=60)
    try:
        datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_QUALITY_AUDIT_INVALID", f"{field} must be RFC3339") from exc
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = root.resolve()
    resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_QUALITY_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not resolved.is_file():
        raise RevenueForgeError("APPFORGE_QUALITY_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return resolved


def _read_json(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_QUALITY_INPUT_TOO_LARGE", "input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_QUALITY_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RevenueForgeError("APPFORGE_QUALITY_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _requirements(contract: dict[str, Any]) -> tuple[dict[str, dict[str, str]], list[dict[str, str]]]:
    classifications = contract.get("conditional")
    if not isinstance(classifications, dict):
        raise RevenueForgeError("APPFORGE_QUALITY_CONDITIONAL_UNREVIEWED", "conditional must classify each conditional check")
    required = {item: {"kind": "design"} for item in DESIGN_CHECKS}
    required.update({item: {"kind": "stack"} for item in STACK_CHECKS})
    skipped: list[dict[str, str]] = []
    for item in CONDITIONAL_CHECKS:
        classification = classifications.get(item)
        if not isinstance(classification, dict) or classification.get("status") not in {"required", "not_applicable"}:
            raise RevenueForgeError("APPFORGE_QUALITY_CONDITIONAL_UNREVIEWED", f"conditional.{item} must be reviewed")
        reviewer = _text(classification.get("reviewed_by"), f"conditional.{item}.reviewed_by")
        rationale = _text(classification.get("rationale"), f"conditional.{item}.rationale")
        if len(rationale) < 20:
            raise RevenueForgeError("APPFORGE_QUALITY_CONDITIONAL_UNREVIEWED", f"conditional.{item}.rationale must contain at least 20 characters")
        if classification["status"] == "required":
            required[item] = {"kind": "conditional"}
        else:
            skipped.append({"id": item, "reviewed_by": reviewer, "rationale": rationale})
    return required, skipped


def verify_quality_audit(root: Path, contract_path: Path, evidence_path: Path, out_path: Path) -> dict[str, Any]:
    """Verify strict candidate-bound design, accessibility, and full-stack evidence."""
    workspace = Path(root).resolve()
    contract, contract_source = _read_json(workspace, contract_path, CONTRACT_SCHEMA)
    evidence, evidence_source = _read_json(workspace, evidence_path, EVIDENCE_SCHEMA)
    expected = _candidate(contract.get("candidate"), "contract.candidate")
    observed = _candidate(evidence.get("candidate"), "evidence.candidate")
    intent = _digest(contract.get("user_design_input_sha256"), "contract.user_design_input_sha256")
    required, skipped = _requirements(contract)
    findings: list[dict[str, str]] = []
    if observed != expected:
        findings.append({"code": "APPFORGE_QUALITY_CANDIDATE_MISMATCH", "detail": "quality evidence is not bound to the reviewed candidate"})
    if _digest(evidence.get("user_design_input_sha256"), "evidence.user_design_input_sha256") != intent:
        findings.append({"code": "APPFORGE_QUALITY_USER_INTENT_MISMATCH", "detail": "quality evidence is not bound to the confirmed user design input"})
    review = evidence.get("design_review")
    if not isinstance(review, dict) or review.get("user_design_input_considered") is not True:
        findings.append({"code": "APPFORGE_QUALITY_USER_DESIGN_UNCONFIRMED", "detail": "a named reviewer must confirm that the supplied user design input was considered"})
        review_summary = None
    else:
        review_summary = {"reviewed_by": _text(review.get("reviewed_by"), "design_review.reviewed_by"), "reviewed_at": _timestamp(review.get("reviewed_at"), "design_review.reviewed_at"), "user_design_input_considered": True, "storyboard_sha256": _digest(review.get("storyboard_sha256"), "design_review.storyboard_sha256")}
    supplied = evidence.get("checks")
    if not isinstance(supplied, list) or len(supplied) > 100:
        raise RevenueForgeError("APPFORGE_QUALITY_EVIDENCE_INVALID", "checks must contain at most 100 objects")
    passed: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in supplied:
        if not isinstance(item, dict):
            findings.append({"code": "APPFORGE_QUALITY_CHECK_INVALID", "detail": "every check must be an object"})
            continue
        check_id = str(item.get("id") or "").strip()
        if check_id not in required:
            findings.append({"code": "APPFORGE_QUALITY_CHECK_UNRECOGNIZED", "detail": f"{check_id or 'unnamed'} is not required by this contract"})
            continue
        if check_id in seen:
            findings.append({"code": "APPFORGE_QUALITY_CHECK_DUPLICATE", "detail": f"{check_id} appears more than once"})
            continue
        seen.add(check_id)
        if item.get("status") != "passed":
            findings.append({"code": "APPFORGE_QUALITY_CHECK_UNPROVEN", "detail": f"{check_id} is not passed"})
            continue
        try:
            artifact = _local(workspace, Path(_text(item.get("artifact_path"), f"checks.{check_id}.artifact_path", limit=700)))
            digest = _digest(item.get("artifact_sha256"), f"checks.{check_id}.artifact_sha256")
            if hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
                raise RevenueForgeError("APPFORGE_QUALITY_ARTIFACT_HASH_MISMATCH", f"{check_id} artifact does not match declared SHA-256")
            passed.append({"id": check_id, "kind": required[check_id]["kind"], "artifact_path": artifact.relative_to(workspace).as_posix(), "artifact_sha256": digest, "performed_by": _text(item.get("performed_by"), f"checks.{check_id}.performed_by"), "performed_at": _timestamp(item.get("performed_at"), f"checks.{check_id}.performed_at")})
        except RevenueForgeError as error:
            findings.append({"code": getattr(error, "code", "APPFORGE_QUALITY_EVIDENCE_INVALID"), "detail": str(error)})
    for check_id in required:
        if check_id not in seen:
            findings.append({"code": "APPFORGE_QUALITY_CHECK_MISSING", "detail": f"{check_id} has no passed, hash-bound evidence"})
    destination = _local(workspace, out_path, exists=False)
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_QUALITY_AUDIT_READY" if not findings else "APPFORGE_QUALITY_AUDIT_BLOCKED",
        "ok": not findings,
        "action_summary": "Verify exact-candidate user-design review, strict iOS experience/accessibility checks, and full-stack release evidence; never infer a visual result, run a device, upload, submit, or claim Apple approval.",
        "candidate": expected,
        "user_design_input_sha256": intent,
        "contract_sha256": hashlib.sha256(contract_source.read_bytes()).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_source.read_bytes()).hexdigest(),
        "design_review": review_summary,
        "checks_passed": sorted(passed, key=lambda item: item["id"]),
        "not_applicable": skipped,
        "findings": findings,
        "authority": {**AUTHORITY, "device_execution": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "hash-bound supplied local artifacts only; not a substitute for physical-device assistive-technology testing, backend uptime verification, App Store Connect state, Apple policy certification, submission, or approval.",
    }
    core["receipt_sha256"] = _sha(core)
    _atomic(destination, core)
    return {**core, "path": destination.relative_to(workspace).as_posix()}


def quality_audit_projection(root: Path) -> dict[str, Any]:
    """Read only hash-valid quality-audit receipts without granting release authority."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("quality-audit*.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            supplied = value.pop("receipt_sha256", None)
            valid = value.get("schema") == RECEIPT_SCHEMA and isinstance(supplied, str) and _sha(value) == supplied
            if valid:
                current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "ok": value.get("ok"), "receipt_sha256": supplied})
            else:
                invalid.append(path.relative_to(workspace).as_posix())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.quality-audit-projection.v1", "marker": "APPFORGE_QUALITY_AUDIT_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": AUTHORITY, "claim_boundary": "hash-verified local quality audit status only; not a visual certification, physical-device result, or App Review approval."}

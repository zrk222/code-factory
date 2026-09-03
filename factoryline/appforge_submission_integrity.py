"""Fail closed on vague AppForge capture requirements and weak evidence classes."""
from __future__ import annotations

import hashlib, json, os, tempfile
from pathlib import Path
from typing import Any

from .appforge_evidence_kit import _read_candidate
from .revenueforge import AUTHORITY, RevenueForgeError

CONTRACT_SCHEMA = "factory.appforge.submission-integrity-contract.v1"
RECEIPT_SCHEMA = "factory.appforge.submission-integrity-receipt.v1"
MAX_BYTES = 1_048_576
_SET_RULES = {"iphone": 10, "ipad_13": 3}

def _canonical(v: object) -> bytes: return json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
def _sha(v: object) -> str: return hashlib.sha256(_canonical(v)).hexdigest()
def _file_sha(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()

def _local(root: Path, path: Path, exists: bool = True) -> Path:
    workspace = Path(root).resolve(); target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try: target.relative_to(workspace)
    except ValueError as exc: raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file(): raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target

def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES: raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_INPUT_TOO_LARGE", "input exceeds 1 MiB")
    try: value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_INPUT_INVALID", "input must be JSON") from exc
    if not isinstance(value, dict): raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_INPUT_INVALID", "input must be an object")
    return value, source

def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True); fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle: json.dump(payload, handle, indent=2, sort_keys=True); handle.write("\n")
        os.replace(temp, path)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def _finding(code: str, message: str, repair: str) -> dict[str, str]: return {"code": code, "message": message, "repair": repair}

def verify_submission_integrity(root: Path, candidate_path: Path, contract_path: Path, out_path: Path) -> dict[str, Any]:
    """Validate a user-approved 10+3 capture contract; never creates or trusts media."""
    workspace = Path(root).resolve(); candidate, candidate_source = _read_candidate(workspace, candidate_path); contract, source = _read(workspace, contract_path)
    expected = {"schema", "candidate", "requirements", "approval"}
    if set(contract) != expected or contract.get("schema") != CONTRACT_SCHEMA or contract.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_CONTRACT_INVALID", "contract must bind the exact candidate and contain only schema, candidate, requirements, and approval")
    approval = contract.get("approval")
    if not isinstance(approval, dict) or approval.get("origin") not in {"human_confirmed", "trusted_source"} or not isinstance(approval.get("source"), str) or not approval["source"].strip():
        raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_AUTHORITY_MISSING", "coverage requirements need a human_confirmed or trusted_source approval with a bounded source")
    rows = contract.get("requirements"); findings: list[dict[str, str]] = []; normalized: list[dict[str, Any]] = []
    if not isinstance(rows, list) or not rows: raise RevenueForgeError("APPFORGE_SUBMISSION_INTEGRITY_CONTRACT_INVALID", "requirements must be a non-empty list")
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "device", "journey", "state", "entrypoint", "steps", "evidence_class", "layout_assertions"}:
            findings.append(_finding("E_REQUIREMENT_LOOSE", "Each requirement needs an id, device, journey, state, entrypoint, steps, evidence class, and layout assertions.", "Name the missing user-visible state and the exact path that reaches it; do not infer it from a marketing image.")); continue
        rid = str(row.get("id", "")).strip(); device = str(row.get("device", "")).strip(); steps = row.get("steps"); assertions = row.get("layout_assertions")
        if not rid or rid in seen or device not in _SET_RULES: findings.append(_finding("E_REQUIREMENT_LOOSE", "Requirement id must be unique and device must be iphone or ipad_13.", "Replace the ambiguous requirement with one uniquely named capture for the approved device family.")); continue
        seen.add(rid)
        if any(not isinstance(row.get(field), str) or not row[field].strip() for field in ("journey", "state", "entrypoint")) or not isinstance(steps, list) or not steps or not all(isinstance(step, str) and step.strip() for step in steps): findings.append(_finding("E_REQUIREMENT_LOOSE", f"{rid} lacks a reviewable journey, state, entrypoint, or capture steps.", f"Specify the exact user journey, visible state, entry route, and ordered steps for {rid}."))
        if row.get("evidence_class") != "native_signed_build": findings.append(_finding("E_COLLATERAL_EVIDENCE_REJECTED", f"{rid} is not classified as native_signed_build evidence.", "Keep web previews and marketing collateral advisory; collect this capture from the candidate-bound signed native build."))
        if device == "ipad_13" and (not isinstance(assertions, list) or "desktop_class_layout" not in assertions): findings.append(_finding("E_TABLET_LAYOUT_UNPROVEN", f"{rid} lacks the desktop_class_layout assertion.", "Add an explicit iPad 13-inch desktop-class layout assertion tied to the visible state."))
        normalized.append({"id": rid, "device": device, "journey": row.get("journey"), "state": row.get("state"), "entrypoint": row.get("entrypoint"), "steps": steps, "evidence_class": row.get("evidence_class"), "layout_assertions": assertions})
    for device, required in _SET_RULES.items():
        actual = sum(1 for item in normalized if item["device"] == device)
        if actual != required: findings.append(_finding("E_CAPTURE_COVERAGE_MISSING", f"{device} has {actual} named captures; the approved contract requires exactly {required}.", f"Add or remove named {device} requirements until exactly {required} states are specified and independently reviewable."))
    core: dict[str, Any] = {"schema": RECEIPT_SCHEMA, "marker": "APPFORGE_SUBMISSION_INTEGRITY_READY" if not findings else "APPFORGE_SUBMISSION_INTEGRITY_BLOCKED", "ok": not findings, "action_summary": "Fail closed on vague AppForge screenshot requirements and weak evidence classes; return the smallest deterministic repair for every missing requirement without creating media or operating Apple systems.", "candidate": candidate, "sources": {"candidate": {"path": candidate_source.relative_to(workspace).as_posix(), "sha256": _file_sha(candidate_source)}, "contract": {"path": source.relative_to(workspace).as_posix(), "sha256": _file_sha(source)}}, "approval": approval, "requirements": normalized, "coverage": {device: {"required": required, "actual": sum(1 for item in normalized if item["device"] == device)} for device, required in _SET_RULES.items()}, "findings": findings, "repair_plan": [item["repair"] for item in findings], "authority": {**AUTHORITY, "execution": False, "media_generation": False, "device_access": False, "apple_access": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "A local requirement-integrity receipt only. READY means requirements are explicit and candidate-bound, not that images depict the required state or that a native build, device, TestFlight, App Review, or Apple approval exists."}
    receipt = {**core, "receipt_sha256": _sha(core)}; target = _local(workspace, out_path, False); _atomic(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}

def submission_integrity_projection(root: Path) -> dict[str, Any]:
    workspace = Path(root).resolve(); current: list[dict[str, Any]] = []; invalid: list[str] = []; base = workspace / ".factory" / "appforge"
    if base.exists():
        for path in sorted(base.rglob("*submission-integrity*.json"))[:100]:
            try:
                value = json.loads(path.read_text(encoding="utf-8")); supplied = value.get("receipt_sha256")
                if isinstance(value, dict) and value.get("schema") == RECEIPT_SCHEMA and isinstance(supplied, str) and _sha({k: v for k, v in value.items() if k != "receipt_sha256"}) == supplied: current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "receipt_sha256": supplied, "coverage": value.get("coverage"), "finding_count": len(value.get("findings", []))})
                else: invalid.append(path.relative_to(workspace).as_posix())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError): invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.submission-integrity-projection.v1", "marker": "APPFORGE_SUBMISSION_INTEGRITY_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**AUTHORITY, "execution": False, "apple_access": False, "apple_approval_claim": False}, "claim_boundary": "Read-only local requirement-integrity status; not a capture, device, TestFlight, App Review, or Apple approval result."}

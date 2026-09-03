"""Sealed-intent, supervised device evidence gate for AppForge.

The gate deliberately separates *capture transport* from *release authority*.
It can validate evidence collected with a real device, manually or through a
declared Phone Harness adapter, but it never starts a device session, uses
credentials, invokes a harness, uploads to Apple, or interprets a screenshot
with an LLM.  A device observation only counts when it is bound to a sealed
Oracle intent contract and named human supervision.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .appforge_oracle import AUTHORITY_SCHEMA as ORACLE_AUTHORITY_SCHEMA
from .appforge_oracle import verify_appforge_oracle_authority
from .oracle_firewall import AUTHORITY_ORIGINS, verify_oracle_contract
from .revenueforge import AUTHORITY, RevenueForgeError


ENVELOPE_SCHEMA = "factory.appforge.device-reality-intent-envelope.v1"
EVIDENCE_SCHEMA = "factory.appforge.device-reality-evidence.v1"
RECEIPT_SCHEMA = "factory.appforge.device-reality-receipt.v1"
MAX_BYTES = 1_048_576
MAX_CAPTURE_BYTES = 25 * 1_048_576
CANDIDATE_KEYS = ("bundle_identifier", "version", "build_number", "source_commit")
ALLOWED_TRANSPORTS = frozenset({"manual_physical_device", "phone_harness"})


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(value: object, field: str, *, limit: int = 500) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(char not in "0123456789abcdef" for char in result):
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_INVALID", f"{field} must be a SHA-256 hex digest")
    return result


def _candidate(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_CANDIDATE_INVALID", f"{field} must be an object")
    return {key: _text(value.get(key), f"{field}.{key}", limit=200) for key in CANDIDATE_KEYS}


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write_new(root: Path, path: Path, payload: dict[str, Any]) -> Path:
    target = _local(root, path, exists=False)
    if target.exists():
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_OUTPUT_EXISTS", "destination already exists; sealed artifacts are immutable")
    _atomic_json(target, payload)
    return target


def _valid_hash_seal(value: object, schema: str, field: str) -> bool:
    if not isinstance(value, dict) or value.get("schema") != schema:
        return False
    supplied = value.get(field)
    return isinstance(supplied, str) and len(supplied) == 64 and _sha({key: item for key, item in value.items() if key != field}) == supplied


def _rules(contract: dict[str, Any]) -> list[dict[str, str]]:
    selected: list[dict[str, str]] = []
    for group in ("requirements", "forbidden_behaviors", "gates", "negative_cases", "invariants", "tests"):
        for item in contract.get("rules", {}).get(group, []):
            if item.get("effect") in {"blocking", "release"} and item.get("origin") in AUTHORITY_ORIGINS:
                selected.append({"group": group, "id": str(item["id"]), "statement": str(item["statement"]), "source_id": str(item["source_id"]), "origin": str(item["origin"])})
    if not selected:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_ORACLE_UNAUTHORIZED", "sealed Oracle contract has no human-confirmed or trusted blocking obligations")
    return selected


def _journeys(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 30:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_JOURNEYS_INVALID", "required_journeys must contain 1 through 30 approved journeys")
    result: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise RevenueForgeError("APPFORGE_DEVICE_REALITY_JOURNEYS_INVALID", f"required_journeys[{index}] must be an object")
        result.append({
            "id": _text(item.get("id"), f"required_journeys[{index}].id", limit=96),
            "expected_outcome": _text(item.get("expected_outcome"), f"required_journeys[{index}].expected_outcome"),
            "forbidden_outcome": _text(item.get("forbidden_outcome"), f"required_journeys[{index}].forbidden_outcome"),
        })
    if len({item["id"] for item in result}) != len(result):
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_JOURNEYS_INVALID", "required journey ids must be unique")
    return result


def create_device_reality_intent_envelope(
    root: Path,
    oracle_authority_path: Path,
    design_input_path: Path,
    required_journeys: object,
    allowed_transports: object,
    out_path: Path,
) -> dict[str, Any]:
    """Create an immutable AppForge Device Reality envelope from sealed intent authority."""
    workspace = Path(root).resolve()
    authority_raw, authority_source = _read(workspace, oracle_authority_path, ORACLE_AUTHORITY_SCHEMA)
    candidate = _candidate(authority_raw.get("candidate"), "authority.candidate")
    derived = verify_appforge_oracle_authority(workspace, oracle_authority_path, candidate=candidate)
    if not derived.get("ok"):
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_ORACLE_BLOCKED", "Oracle authority must be current before sealing device intent")
    contract_path = authority_raw.get("contract_path")
    if not isinstance(contract_path, str) or not contract_path.strip():
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_ORACLE_INVALID", "authority.contract_path is required")
    contract_result = verify_oracle_contract(workspace, Path(contract_path))
    if not contract_result.get("ok"):
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_ORACLE_BLOCKED", "sealed Oracle contract is not current")
    design_source = _local(workspace, design_input_path)
    if design_source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_INPUT_TOO_LARGE", "design input exceeds 1 MiB")
    journeys = _journeys(required_journeys)
    if not isinstance(allowed_transports, list) or not allowed_transports:
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_TRANSPORT_INVALID", "allowed_transports must contain an approved capture transport")
    transports = sorted({_text(item, "allowed_transports", limit=64) for item in allowed_transports})
    if any(item not in ALLOWED_TRANSPORTS for item in transports):
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_TRANSPORT_INVALID", "allowed_transports contains an unsupported capture transport")
    core: dict[str, Any] = {
        "schema": ENVELOPE_SCHEMA,
        "marker": "APPFORGE_DEVICE_REALITY_INTENT_SEALED",
        "candidate": candidate,
        "user_design_input": {"path": design_source.relative_to(workspace).as_posix(), "sha256": _file_sha(design_source)},
        "oracle_authority": {"path": authority_source.relative_to(workspace).as_posix(), "sha256": _file_sha(authority_source), "receipt_sha256": derived["receipt_sha256"]},
        "oracle_contract": {"path": contract_result["path"], "contract_sha256": contract_result["contract"]["contract_sha256"]},
        "approved_by": _text(authority_raw.get("human_reviewer"), "authority.human_reviewer", limit=160),
        "required_journeys": journeys,
        "allowed_transports": transports,
        "obligations": _rules(contract_result["contract"]),
        "authority": {**AUTHORITY, "device_control": False, "capture_execution": False, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Hash-sealed local intent envelope only. It does not operate a device, prove screenshot semantics, access credentials, contact Apple, submit a build, or guarantee approval.",
    }
    envelope = {**core, "envelope_sha256": _sha(core)}
    destination = _write_new(workspace, out_path, envelope)
    return {**envelope, "path": destination.relative_to(workspace).as_posix()}


def _evidence_capture(root: Path, item: object, index: int, allowed: dict[str, dict[str, str]], transport: str) -> tuple[dict[str, str] | None, dict[str, str] | None]:
    if not isinstance(item, dict):
        return None, {"code": "APPFORGE_DEVICE_REALITY_CAPTURE_INVALID", "detail": f"captures[{index}] must be an object"}
    journey = str(item.get("journey") or "").strip()
    if journey not in allowed:
        return None, {"code": "APPFORGE_DEVICE_REALITY_JOURNEY_UNAUTHORIZED", "detail": f"captures[{index}] is not a sealed required journey"}
    if item.get("transport") != transport:
        return None, {"code": "APPFORGE_DEVICE_REALITY_TRANSPORT_MISMATCH", "detail": f"captures[{index}] transport does not match supervised evidence transport"}
    try:
        path = _local(root, Path(_text(item.get("path"), f"captures[{index}].path", limit=512)))
        if path.stat().st_size > MAX_CAPTURE_BYTES:
            raise RevenueForgeError("APPFORGE_DEVICE_REALITY_CAPTURE_TOO_LARGE", "capture exceeds 25 MiB")
        supplied = _digest(item.get("sha256"), f"captures[{index}].sha256")
    except RevenueForgeError as error:
        return None, {"code": error.code, "detail": str(error)}
    if _file_sha(path) != supplied:
        return None, {"code": "APPFORGE_DEVICE_REALITY_CAPTURE_HASH_MISMATCH", "detail": f"captures[{index}] does not match its supplied digest"}
    expected = allowed[journey]
    if item.get("expected_outcome") != expected["expected_outcome"] or item.get("forbidden_outcome") != expected["forbidden_outcome"]:
        return None, {"code": "APPFORGE_DEVICE_REALITY_OBSERVATION_UNBOUND", "detail": f"captures[{index}] does not preserve the sealed expected and forbidden outcomes"}
    if item.get("outcome") != "passed":
        return None, {"code": "APPFORGE_DEVICE_REALITY_OBSERVATION_FAILED", "detail": f"captures[{index}] is not a human-confirmed passing observation"}
    try:
        return {"journey": journey, "path": path.relative_to(root).as_posix(), "sha256": supplied, "expected_outcome": expected["expected_outcome"], "forbidden_outcome": expected["forbidden_outcome"]}, None
    except ValueError:
        return None, {"code": "APPFORGE_DEVICE_REALITY_PATH_REJECTED", "detail": f"captures[{index}] escapes workspace"}


def _binding_findings(envelope: dict[str, Any], evidence: dict[str, Any], candidate: dict[str, str]) -> list[dict[str, str]]:
    checks = (
        (_candidate(evidence.get("candidate"), "evidence.candidate") == candidate, "APPFORGE_DEVICE_REALITY_CANDIDATE_MISMATCH", "device evidence is not bound to the sealed candidate"),
        (evidence.get("intent_envelope_sha256") == envelope["envelope_sha256"], "APPFORGE_DEVICE_REALITY_INTENT_MISMATCH", "device evidence does not name the sealed intent envelope"),
        (evidence.get("user_design_input_sha256") == envelope["user_design_input"]["sha256"], "APPFORGE_DEVICE_REALITY_DESIGN_MISMATCH", "device evidence is not bound to the reviewed user design input"),
    )
    return [{"code": code, "detail": detail} for passed, code, detail in checks if not passed]


def _supervision_and_transport(envelope: dict[str, Any], evidence: dict[str, Any]) -> tuple[dict[str, Any] | None, str, list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    supervision = evidence.get("supervision")
    approved = isinstance(supervision, dict) and supervision.get("approved_by") == envelope["approved_by"] and supervision.get("human_present") is True and bool(str(supervision.get("approved_at") or "").strip())
    if not approved:
        findings.append({"code": "APPFORGE_DEVICE_REALITY_SUPERVISION_REQUIRED", "detail": "a named envelope approver must confirm supervised device observation"})
    transport = evidence.get("transport")
    kind = str(transport.get("kind") or "").strip() if isinstance(transport, dict) else ""
    authorized = isinstance(transport, dict) and kind in envelope["allowed_transports"] and transport.get("user_authorized") is True
    if not isinstance(transport, dict):
        findings.append({"code": "APPFORGE_DEVICE_REALITY_TRANSPORT_INVALID", "detail": "evidence.transport must declare an approved capture transport"})
    elif not authorized:
        findings.append({"code": "APPFORGE_DEVICE_REALITY_TRANSPORT_UNAUTHORIZED", "detail": "capture transport is not sealed and explicitly user-authorized"})
    return supervision if isinstance(supervision, dict) else None, kind, findings


def _capture_evidence(workspace: Path, envelope: dict[str, Any], evidence: dict[str, Any], transport: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    allowed = {item["id"]: item for item in envelope["required_journeys"]}
    raw_captures = evidence.get("captures")
    if not isinstance(raw_captures, list):
        return [], [{"code": "APPFORGE_DEVICE_REALITY_CAPTURE_INVALID", "detail": "captures must be an array"}]
    captures: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    for index, item in enumerate(raw_captures):
        capture, finding = _evidence_capture(workspace, item, index, allowed, transport)
        if finding:
            findings.append(finding)
        elif capture:
            captures.append(capture)
    ids = [item["journey"] for item in captures]
    if set(ids) != set(allowed) or len(ids) != len(set(ids)):
        findings.append({"code": "APPFORGE_DEVICE_REALITY_JOURNEYS_INCOMPLETE", "detail": "every sealed journey must have exactly one passing, hash-valid capture"})
    return captures, findings


def verify_device_reality(root: Path, envelope_path: Path, evidence_path: Path, out_path: Path) -> dict[str, Any]:
    """Fail closed unless supervised captures preserve a sealed AppForge intent envelope."""
    workspace = Path(root).resolve()
    envelope, envelope_source = _read(workspace, envelope_path, ENVELOPE_SCHEMA)
    if not _valid_hash_seal(envelope, ENVELOPE_SCHEMA, "envelope_sha256"):
        raise RevenueForgeError("APPFORGE_DEVICE_REALITY_ENVELOPE_TAMPERED", "intent envelope hash is invalid")
    evidence, evidence_source = _read(workspace, evidence_path, EVIDENCE_SCHEMA)
    candidate = _candidate(envelope.get("candidate"), "envelope.candidate")
    findings = _binding_findings(envelope, evidence, candidate)
    supervision, transport_kind, authority_findings = _supervision_and_transport(envelope, evidence)
    captures, capture_findings = _capture_evidence(workspace, envelope, evidence, transport_kind)
    findings.extend(authority_findings)
    findings.extend(capture_findings)
    ready = not findings
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_DEVICE_REALITY_READY" if ready else "APPFORGE_DEVICE_REALITY_BLOCKED",
        "ok": ready,
        "action_summary": "Verify user-supervised, hash-valid device captures against one sealed intent envelope, exact candidate, approved journeys, forbidden outcomes, user-design digest, and capture transport without operating a device or contacting Apple.",
        "candidate": candidate,
        "intent_envelope": {"path": envelope_source.relative_to(workspace).as_posix(), "envelope_sha256": envelope["envelope_sha256"]},
        "evidence_source": {"path": evidence_source.relative_to(workspace).as_posix(), "sha256": _file_sha(evidence_source)},
        "transport": {"kind": transport_kind, "observed_by_human": bool(isinstance(supervision, dict) and supervision.get("human_present") is True)},
        "captures": captures,
        "findings": findings,
        "authority": {**AUTHORITY, "device_control": False, "capture_execution": False, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Local hash-and-metadata validation only. It does not run Phone Harness or another device tool, authenticate a real device, inspect screenshot semantics, prove all device behavior, submit to Apple, or guarantee App Review approval.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    destination = _write_new(workspace, out_path, receipt)
    return {**receipt, "path": destination.relative_to(workspace).as_posix()}


def device_reality_projection(root: Path) -> dict[str, Any]:
    """Read hash-valid Device Reality receipts without touching a device or candidate."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    base = workspace / ".factory" / "appforge"
    if base.exists():
        for path in sorted(base.rglob("*device-reality*.json"))[:100]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if _valid_hash_seal(value, RECEIPT_SCHEMA, "receipt_sha256"):
                    current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "ok": value.get("ok"), "candidate": value.get("candidate"), "receipt_sha256": value.get("receipt_sha256")})
                elif value.get("schema") == RECEIPT_SCHEMA:
                    invalid.append(path.relative_to(workspace).as_posix())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.device-reality-projection.v1", "marker": "APPFORGE_DEVICE_REALITY_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**AUTHORITY, "device_control": False, "capture_execution": False, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "Read-only local receipt status; not device control, a device test, Apple submission, or Apple approval."}

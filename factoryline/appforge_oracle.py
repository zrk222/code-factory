"""Candidate-bound authority bridge between AppForge and Oracle Firewall.

AppForge evaluates iOS readiness evidence.  This bridge prevents a builder or
agent from silently rewriting the policy, user-intent, or release-gate inputs
that define that evaluation.  It is local and cannot contact Apple.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .oracle_firewall import AUTHORITY as ORACLE_AUTHORITY, AUTHORITY_ORIGINS, verify_oracle_contract
from .revenueforge import RevenueForgeError


AUTHORITY_SCHEMA = "factory.appforge.oracle-authority.v1"
RECEIPT_SCHEMA = "factory.appforge.oracle-authority-receipt.v1"
MAX_BYTES = 1_048_576
CANDIDATE_KEYS = ("bundle_identifier", "version", "build_number", "source_commit")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: object, field: str, *, limit: int = 500) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_ORACLE_AUTHORITY_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _candidate(value: object, field: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RevenueForgeError("APPFORGE_ORACLE_CANDIDATE_INVALID", f"{field} must be an object")
    return {key: _text(value.get(key), f"{field}.{key}", limit=200) for key in CANDIDATE_KEYS}


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_ORACLE_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise RevenueForgeError("APPFORGE_ORACLE_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_ORACLE_INPUT_TOO_LARGE", "input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_ORACLE_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != AUTHORITY_SCHEMA:
        raise RevenueForgeError("APPFORGE_ORACLE_SCHEMA_REJECTED", f"expected {AUTHORITY_SCHEMA}")
    return value, source


def _atomic(path: Path, payload: dict[str, Any]) -> None:
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


def _policy_sources(value: object, contract: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if not isinstance(value, list) or not value:
        return [], [{"code": "APPFORGE_ORACLE_POLICY_SOURCE_MISSING", "detail": "at least one named human-confirmed or trusted policy source is required"}]
    bound = {item.get("id"): item for item in contract.get("sources", []) if isinstance(item, dict)}
    accepted: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            findings.append({"code": "APPFORGE_ORACLE_POLICY_SOURCE_INVALID", "detail": f"policy_sources[{index}] must be an object"})
            continue
        source_id = str(item.get("source_id") or "").strip()
        source = bound.get(source_id)
        if source is None:
            findings.append({"code": "APPFORGE_ORACLE_POLICY_SOURCE_UNBOUND", "detail": f"policy_sources[{index}] is not in the sealed Oracle Contract"})
            continue
        if source.get("origin") not in AUTHORITY_ORIGINS:
            findings.append({"code": "APPFORGE_ORACLE_POLICY_SOURCE_ADVISORY", "detail": f"policy_sources[{index}] is not human-confirmed or trusted"})
            continue
        accepted.append({"source_id": source_id, "path": str(source.get("path")), "sha256": str(source.get("sha256")), "origin": str(source.get("origin"))})
    if len({item["source_id"] for item in accepted}) != len(accepted):
        findings.append({"code": "APPFORGE_ORACLE_POLICY_SOURCE_DUPLICATE", "detail": "policy source ids must be unique"})
    return accepted, findings


def _gate_findings(contract: dict[str, Any]) -> list[dict[str, str]]:
    """Require authoritative obligations in every release-relevant rule group."""
    findings = []
    for group in ("requirements", "forbidden_behaviors", "gates", "negative_cases", "invariants", "tests"):
        if not any(item.get("effect") in {"blocking", "release"} and item.get("origin") in AUTHORITY_ORIGINS for item in contract["rules"].get(group, [])):
            findings.append({"code": "APPFORGE_ORACLE_GATE_UNAUTHORIZED", "detail": f"sealed contract has no human or trusted {group} gate"})
    return findings


def verify_appforge_oracle_authority(root: Path, authority_path: Path, *, candidate: dict[str, str] | None = None, out: Path | None = None) -> dict[str, Any]:
    """Verify that a candidate's AppForge gates have source-bound authority."""
    workspace = Path(root).resolve()
    authority, source = _read(workspace, authority_path)
    expected = _candidate(authority.get("candidate"), "authority.candidate")
    findings: list[dict[str, str]] = []
    if candidate is not None and expected != candidate:
        findings.append({"code": "APPFORGE_ORACLE_CANDIDATE_MISMATCH", "detail": "authority candidate does not match the submission candidate"})
    reviewer = _text(authority.get("human_reviewer"), "human_reviewer", limit=160)
    raw_contract = authority.get("contract_path")
    if not isinstance(raw_contract, str) or not raw_contract.strip():
        raise RevenueForgeError("APPFORGE_ORACLE_CONTRACT_MISSING", "contract_path is required")
    contract_result = verify_oracle_contract(workspace, Path(raw_contract))
    if not contract_result["ok"]:
        findings.append({"code": "APPFORGE_ORACLE_CONTRACT_INVALID", "detail": f"sealed Oracle Contract is not current: {contract_result.get('reason')}"})
        contract: dict[str, Any] = {"rules": {}, "sources": []}
    else:
        contract = contract_result["contract"]
    policies, policy_findings = _policy_sources(authority.get("policy_sources"), contract)
    findings.extend(policy_findings)
    if contract_result.get("ok"):
        findings.extend(_gate_findings(contract))
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_ORACLE_AUTHORITY_READY" if not findings else "APPFORGE_ORACLE_AUTHORITY_BLOCKED",
        "ok": not findings,
        "action_summary": "Bind an exact AppForge candidate to source-backed user intent, policy evidence, forbidden outcomes, gates, tests, and a named human reviewer before a final local dossier can treat those gates as authoritative.",
        "candidate": expected,
        "authority_source": source.relative_to(workspace).as_posix(),
        "authority_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "oracle_contract": {"path": contract_result.get("path"), "contract_sha256": contract.get("contract_sha256")},
        "policy_sources": policies,
        "human_reviewer": reviewer,
        "findings": findings,
        "authority": {**ORACLE_AUTHORITY, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Local provenance validation only. It does not verify Apple policy interpretation, run a device, submit a build, contact Apple, or guarantee approval.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    if out is not None:
        target = _local(workspace, Path(out), exists=False)
        if target.exists():
            raise RevenueForgeError("APPFORGE_ORACLE_OUTPUT_EXISTS", "authority receipt destination already exists")
        _atomic(target, receipt)
        return {**receipt, "path": target.relative_to(workspace).as_posix()}
    return receipt


def _projected_authority(workspace: Path, path: Path) -> dict[str, Any]:
    """Check shape, local digest and source freshness before exposing readiness."""
    source = _local(workspace, path)
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("authority receipt exceeds byte limit")
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("authority receipt must be an object")
    supplied = value.get("receipt_sha256")
    core = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if value.get("schema") != RECEIPT_SCHEMA or not isinstance(supplied, str) or _sha(core) != supplied:
        raise ValueError("invalid authority receipt digest or schema")
    if value.get("ok") is True or value.get("marker") == "APPFORGE_ORACLE_AUTHORITY_READY":
        fresh = verify_appforge_oracle_authority(workspace, Path(value["authority_source"]))
        if fresh != value or fresh.get("ok") is not True:
            raise ValueError("authority receipt is not current")
    return {"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "ok": value.get("ok"), "candidate": value.get("candidate"), "receipt_sha256": supplied}


def appforge_oracle_projection(root: Path) -> dict[str, Any]:
    """Read hash-valid AppForge authority receipts without changing release state."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("*oracle-authority*.json"))[:100]:
        try:
            current.append(_projected_authority(workspace, path))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, KeyError, RevenueForgeError):
            invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.oracle-authority-projection.v1", "marker": "APPFORGE_ORACLE_AUTHORITY_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**ORACLE_AUTHORITY, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "Hash-verified local authority status only; not a policy certification, App Store Connect state, TestFlight state, submission, or Apple approval."}

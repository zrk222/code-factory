"""Local release-contract binding for the six-module control plane.

The contract deliberately composes the existing Oracle Firewall rather than
inventing a second source of truth.  It binds a release decision to the exact
feature, current Oracle contract, and required stage set.  Hash sealing detects
local changes; signer identity still requires the enterprise receipt path.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .oracle_firewall import verify_oracle_contract


SCHEMA = "factory.release-contract.v1"
MAX_BYTES = 1_048_576
CORE_STAGE_IDS = frozenset({
    "specline:strict", "specline:verify-validators", "specline:gate-spec", "specline:tasks", "specline:gate-plan",
    "forgeline:architect", "forgeline:review", "forgeline:arch-gate", "forgeline:verify-tests", "forgeline:smoke", "forgeline:ship",
    "prestige:score", "hsf:compile",
})
EXTERNAL_STAGE_IDS = frozenset({"appforge:mobile-evidence"})


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _inside(root: Path, path: Path) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("release contract paths must remain inside the workspace") from exc
    if not target.is_file():
        raise ValueError("release contract input is unavailable")
    return target


def verify_release_contract(root: Path, feature: str, path: Path, required_stages: set[str]) -> dict[str, Any]:
    """Verify a sealed local policy and its current Oracle binding."""
    workspace = Path(root).resolve()
    try:
        source = _inside(workspace, path)
        if source.stat().st_size > MAX_BYTES:
            raise ValueError("release contract exceeds 1 MiB")
        value = json.loads(source.read_text(encoding="utf-8-sig"))
        required = {"schema", "feature", "oracle_contract", "oracle_contract_sha256", "required_stages", "approved_by", "policy_digest"}
        allowed = required | {"evidence", "candidate"}
        if not isinstance(value, dict) or not required.issubset(value) or set(value) - allowed or value.get("schema") != SCHEMA:
            raise ValueError("release contract has an invalid schema or field set")
        if value.get("feature") != feature or not isinstance(value.get("approved_by"), str) or not value["approved_by"].strip():
            raise ValueError("release contract feature or approver is invalid")
        declared = value.get("required_stages")
        if not isinstance(declared, list) or len(declared) != len(set(declared)) or not all(isinstance(item, str) and item in (CORE_STAGE_IDS | EXTERNAL_STAGE_IDS) for item in declared):
            raise ValueError("release contract required_stages is invalid")
        declared_set = set(declared)
        if not required_stages.issubset(declared_set):
            missing = sorted(required_stages - declared_set)
            return {"ok": False, "marker": "RELEASE_CONTRACT_INCOMPLETE", "reason": "required_stages_missing", "missing": missing}
        supplied = value.get("policy_digest")
        candidate = value.get("candidate")
        if candidate is not None:
            if not isinstance(candidate, dict) or not {"source_version", "source_commit"}.issubset(candidate) or set(candidate) - {"source_version", "source_commit", "artifact_versions"}:
                raise ValueError("release contract candidate binding is invalid")
            if not isinstance(candidate.get("source_version"), str) or not candidate["source_version"].strip():
                raise ValueError("release contract candidate source_version is invalid")
            if not isinstance(candidate.get("source_commit"), str) or not re.fullmatch(r"[0-9a-f]{40,64}", candidate["source_commit"]):
                raise ValueError("release contract candidate source_commit is invalid")
            artifact_versions = candidate.get("artifact_versions")
            if artifact_versions is not None:
                if not isinstance(artifact_versions, dict) or set(artifact_versions) - {"python", "vscode", "intellij"}:
                    raise ValueError("release contract candidate artifact_versions is invalid")
                if not artifact_versions or not all(isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value.strip()) for value in artifact_versions.values()):
                    raise ValueError("release contract candidate artifact_versions must contain semantic versions")
        core = {key: item for key, item in value.items() if key != "policy_digest"}
        if not isinstance(supplied, str) or supplied != _sha(core):
            return {"ok": False, "marker": "RELEASE_CONTRACT_INVALID", "reason": "policy_digest_mismatch"}
        oracle_path = _inside(workspace, Path(str(value["oracle_contract"])))
        oracle = verify_oracle_contract(workspace, oracle_path)
        if not oracle.get("ok"):
            return {"ok": False, "marker": "RELEASE_CONTRACT_ORACLE_BLOCKED", "reason": str(oracle.get("reason", "oracle_invalid"))}
        actual = oracle["contract"].get("contract_sha256")
        if value.get("oracle_contract_sha256") != actual:
            return {"ok": False, "marker": "RELEASE_CONTRACT_ORACLE_BLOCKED", "reason": "oracle_contract_sha256_mismatch"}
        evidence = value.get("evidence", {})
        if not isinstance(evidence, dict) or set(evidence) - EXTERNAL_STAGE_IDS:
            return {"ok": False, "marker": "RELEASE_CONTRACT_EVIDENCE_INVALID", "reason": "evidence must map only supported external stages"}
        if "appforge:mobile-evidence" in declared_set:
            evidence_path = evidence.get("appforge:mobile-evidence")
            if not isinstance(evidence_path, str) or not evidence_path.strip():
                return {"ok": False, "marker": "RELEASE_CONTRACT_EVIDENCE_REQUIRED", "reason": "appforge:mobile-evidence requires a receipt path"}
            from .appforge_mobile_evidence import verify_mobile_evidence_receipt
            mobile = verify_mobile_evidence_receipt(workspace, Path(evidence_path))
            if not mobile.get("ok"):
                return {"ok": False, "marker": "RELEASE_CONTRACT_EVIDENCE_BLOCKED", "reason": str(mobile.get("reason", "mobile evidence is not current"))}
        elif evidence:
            return {"ok": False, "marker": "RELEASE_CONTRACT_EVIDENCE_INVALID", "reason": "evidence is supplied for an undeclared external stage"}
        return {"ok": True, "marker": "RELEASE_CONTRACT_VALID", "path": source.relative_to(workspace).as_posix(), "approved_by": value["approved_by"].strip(), "oracle_contract_sha256": actual, "policy_digest": supplied, "required_stages": sorted(declared_set), "evidence": evidence, "claim_boundary": "Hash-bound local policy and current Oracle/source evidence verification only; not authenticated human identity, a signature, deployment, publication, or approval."}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return {"ok": False, "marker": "RELEASE_CONTRACT_INVALID", "reason": str(exc)[:240]}


def release_readiness_projection(root: Path) -> dict[str, Any]:
    """Project every local release contract through the same strict verifier.

    This is the read-only Mission/MCP surface.  It never treats a contract's
    ``approved_by`` text as identity and never reports a provider or store
    approval; any malformed or unobserved contract makes the aggregate review
    required rather than allowing an older green row to remain authoritative.
    """
    workspace = Path(root).resolve()
    directory = workspace / ".factory" / "release-contracts"
    try:
        paths = sorted(directory.glob("*.json"), key=lambda item: item.name)
    except OSError:
        paths = []
    truncated = len(paths) > 100
    if truncated:
        paths = paths[-100:]
    records: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    for path in paths:
        try:
            if path.stat().st_size > MAX_BYTES:
                raise ValueError("release contract exceeds 1 MiB")
            value = json.loads(path.read_text(encoding="utf-8-sig"))
            feature = value.get("feature") if isinstance(value, dict) else None
            if not isinstance(feature, str) or not feature.strip():
                raise ValueError("release contract feature is missing")
            required = set(value.get("required_stages", [])) if isinstance(value, dict) and isinstance(value.get("required_stages"), list) else set()
            from .verification import verify_feature
            result = verify_feature(workspace, feature, strict_release=True, release_contract_path=path)
            records.append({"path": path.relative_to(workspace).as_posix(), "feature": feature, "ok": result.get("release_ready") is True, "marker": result.get("release_contract", {}).get("marker"), "blocker_count": len(result.get("blockers", [])), "next_action": result.get("next_action")})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            invalid.append({"path": path.relative_to(workspace).as_posix(), "reason": str(exc)[:240]})
    if truncated:
        invalid.append({"path": ".factory/release-contracts/", "reason": "contract scan exceeded 100 files"})
    return {"schema": "factory.release-readiness-projection.v1", "marker": "RELEASE_READINESS_REVIEW_REQUIRED" if invalid else "RELEASE_READINESS_READ_ONLY", "contract_count": len(records), "ready_count": sum(1 for item in records if item["ok"]), "invalid_count": len(invalid), "truncated": truncated, "latest": records[-1] if records and not invalid else None, "contracts": records[-20:], "invalid": invalid, "authority": {"execution": False, "approval": False, "release": False, "publication": False, "deployment": False, "credential_access": False}, "claim_boundary": "Read-only local strict-gate projection; it does not authenticate approvers or prove signing, deployment, publication, provider processing, or approval."}

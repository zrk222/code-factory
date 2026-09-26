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
CORE_STAGE_IDS = frozenset(
    {
        "specline:strict",
        "specline:verify-validators",
        "specline:gate-spec",
        "specline:tasks",
        "specline:gate-plan",
        "forgeline:architect",
        "forgeline:review",
        "forgeline:arch-gate",
        "forgeline:verify-tests",
        "forgeline:smoke",
        "forgeline:ship",
        "prestige:score",
        "hsf:compile",
    }
)
EXTERNAL_STAGE_IDS = frozenset({"appforge:mobile-evidence"})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _inside(root: Path, path: Path) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(
            "release contract paths must remain inside the workspace"
        ) from exc
    if not target.is_file():
        raise ValueError("release contract input is unavailable")
    return target


def _valid_contract_shape(value: Any, required: set[str], allowed: set[str]) -> bool:
    if not isinstance(value, dict):
        return False
    return (
        required.issubset(value)
        and not (set(value) - allowed)
        and value.get("schema") == SCHEMA
    )


def _valid_stages(declared: Any) -> bool:
    if not isinstance(declared, list):
        return False
    if len(declared) != len(set(declared)):
        return False
    return all(
        isinstance(item, str) and item in (CORE_STAGE_IDS | EXTERNAL_STAGE_IDS)
        for item in declared
    )


def _contract_fields(value: Any, feature: str, required_stages: set[str]):
    required = {
        "schema",
        "feature",
        "oracle_contract",
        "oracle_contract_sha256",
        "required_stages",
        "approved_by",
        "policy_digest",
    }
    allowed = required | {"evidence", "candidate"}
    if not _valid_contract_shape(value, required, allowed):
        raise ValueError("release contract has an invalid schema or field set")
    if (
        value.get("feature") != feature
        or not isinstance(value.get("approved_by"), str)
        or not value["approved_by"].strip()
    ):
        raise ValueError("release contract feature or approver is invalid")
    declared = value.get("required_stages")
    if not _valid_stages(declared):
        raise ValueError("release contract required_stages is invalid")
    declared_set = set(declared)
    missing = sorted(required_stages - declared_set)
    if missing:
        return None, {
            "ok": False,
            "marker": "RELEASE_CONTRACT_INCOMPLETE",
            "reason": "required_stages_missing",
            "missing": missing,
        }
    return declared_set, None


def _validate_artifact_versions(versions: Any) -> None:
    if versions is not None:
        valid_keys = {"python", "vscode", "intellij"}
        if not isinstance(versions, dict) or set(versions) - valid_keys:
            raise ValueError("release contract candidate artifact_versions is invalid")
        valid_versions = versions and all(
            isinstance(item, str) and re.fullmatch(r"\d+\.\d+\.\d+", item.strip())
            for item in versions.values()
        )
        if not valid_versions:
            raise ValueError(
                "release contract candidate artifact_versions must contain semantic versions"
            )


def _validate_candidate(candidate: Any) -> None:
    if candidate is None:
        return
    allowed = {"source_version", "source_commit", "artifact_versions"}
    if (
        not isinstance(candidate, dict)
        or not {"source_version", "source_commit"}.issubset(candidate)
        or set(candidate) - allowed
    ):
        raise ValueError("release contract candidate binding is invalid")
    version = candidate.get("source_version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("release contract candidate source_version is invalid")
    commit = candidate.get("source_commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("release contract candidate source_commit is invalid")
    _validate_artifact_versions(candidate.get("artifact_versions"))


def _oracle_binding(workspace: Path, value: dict[str, Any]):
    supplied = value.get("policy_digest")
    core = {key: item for key, item in value.items() if key != "policy_digest"}
    if not isinstance(supplied, str) or supplied != _sha(core):
        return None, {
            "ok": False,
            "marker": "RELEASE_CONTRACT_INVALID",
            "reason": "policy_digest_mismatch",
        }
    oracle_path = _inside(workspace, Path(str(value["oracle_contract"])))
    oracle = verify_oracle_contract(workspace, oracle_path)
    if not oracle.get("ok"):
        return None, {
            "ok": False,
            "marker": "RELEASE_CONTRACT_ORACLE_BLOCKED",
            "reason": str(oracle.get("reason", "oracle_invalid")),
        }
    actual = oracle["contract"].get("contract_sha256")
    if value.get("oracle_contract_sha256") != actual:
        return None, {
            "ok": False,
            "marker": "RELEASE_CONTRACT_ORACLE_BLOCKED",
            "reason": "oracle_contract_sha256_mismatch",
        }
    return (actual, supplied), None


def _external_evidence(workspace: Path, declared: set[str], evidence: Any):
    if not isinstance(evidence, dict) or set(evidence) - EXTERNAL_STAGE_IDS:
        return None, {
            "ok": False,
            "marker": "RELEASE_CONTRACT_EVIDENCE_INVALID",
            "reason": "evidence must map only supported external stages",
        }
    if "appforge:mobile-evidence" not in declared:
        if evidence:
            return None, {
                "ok": False,
                "marker": "RELEASE_CONTRACT_EVIDENCE_INVALID",
                "reason": "evidence is supplied for an undeclared external stage",
            }
        return evidence, None
    path = evidence.get("appforge:mobile-evidence")
    if not isinstance(path, str) or not path.strip():
        return None, {
            "ok": False,
            "marker": "RELEASE_CONTRACT_EVIDENCE_REQUIRED",
            "reason": "appforge:mobile-evidence requires a receipt path",
        }
    from .appforge_mobile_evidence import verify_mobile_evidence_receipt

    mobile = verify_mobile_evidence_receipt(workspace, Path(path))
    if not mobile.get("ok"):
        return None, {
            "ok": False,
            "marker": "RELEASE_CONTRACT_EVIDENCE_BLOCKED",
            "reason": str(mobile.get("reason", "mobile evidence is not current")),
        }
    return evidence, None


def verify_release_contract(
    root: Path, feature: str, path: Path, required_stages: set[str]
) -> dict[str, Any]:
    """Verify a sealed local policy and its current Oracle binding."""
    workspace = Path(root).resolve()
    try:
        source = _inside(workspace, path)
        if source.stat().st_size > MAX_BYTES:
            raise ValueError("release contract exceeds 1 MiB")
        value = json.loads(source.read_text(encoding="utf-8-sig"))
        declared_set, result = _contract_fields(value, feature, required_stages)
        if result:
            return result
        _validate_candidate(value.get("candidate"))
        binding, result = _oracle_binding(workspace, value)
        if result:
            return result
        actual, supplied = binding
        evidence, result = _external_evidence(
            workspace, declared_set, value.get("evidence", {})
        )
        if result:
            return result
        return {
            "ok": True,
            "marker": "RELEASE_CONTRACT_VALID",
            "path": source.relative_to(workspace).as_posix(),
            "approved_by": value["approved_by"].strip(),
            "oracle_contract_sha256": actual,
            "policy_digest": supplied,
            "required_stages": sorted(declared_set),
            "evidence": evidence,
            "claim_boundary": "Hash-bound local policy and current Oracle/source evidence verification only; not authenticated human identity, a signature, deployment, publication, or approval.",
        }
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        return {
            "ok": False,
            "marker": "RELEASE_CONTRACT_INVALID",
            "reason": str(exc)[:240],
        }


def _project_contract(workspace: Path, path: Path):
    try:
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("release contract exceeds 1 MiB")
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        feature = value.get("feature") if isinstance(value, dict) else None
        if not isinstance(feature, str) or not feature.strip():
            raise ValueError("release contract feature is missing")
        from .verification import verify_feature

        result = verify_feature(
            workspace, feature, strict_release=True, release_contract_path=path
        )
        return {
            "path": path.relative_to(workspace).as_posix(),
            "feature": feature,
            "ok": result.get("release_ready") is True,
            "marker": result.get("release_contract", {}).get("marker"),
            "blocker_count": len(result.get("blockers", [])),
            "next_action": result.get("next_action"),
        }, None
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        return None, {
            "path": path.relative_to(workspace).as_posix(),
            "reason": str(exc)[:240],
        }


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
        record, error = _project_contract(workspace, path)
        if record:
            records.append(record)
        if error:
            invalid.append(error)
    if truncated:
        invalid.append(
            {
                "path": ".factory/release-contracts/",
                "reason": "contract scan exceeded 100 files",
            }
        )
    return {
        "schema": "factory.release-readiness-projection.v1",
        "marker": "RELEASE_READINESS_REVIEW_REQUIRED"
        if invalid
        else "RELEASE_READINESS_READ_ONLY",
        "contract_count": len(records),
        "ready_count": sum(1 for item in records if item["ok"]),
        "invalid_count": len(invalid),
        "truncated": truncated,
        "latest": records[-1] if records and not invalid else None,
        "contracts": records[-20:],
        "invalid": invalid,
        "authority": {
            "execution": False,
            "approval": False,
            "release": False,
            "publication": False,
            "deployment": False,
            "credential_access": False,
        },
        "claim_boundary": "Read-only local strict-gate projection; it does not authenticate approvers or prove signing, deployment, publication, provider processing, or approval.",
    }

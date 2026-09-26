"""Three fail-closed senior-review controls: intent/diff, freshness, and policy ownership."""

from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from .revenueforge import AUTHORITY, RevenueForgeError


def _sha(v: object) -> str:
    return hashlib.sha256(
        json.dumps(v, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _read(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    p = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        p.relative_to(root)
    except ValueError as e:
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_PATH_REJECTED", "paths must remain inside the workspace"
        ) from e
    try:
        v = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_INPUT_INVALID", "inputs must be JSON objects"
        ) from e
    if not isinstance(v, dict):
        raise RevenueForgeError(
            "REVIEW_INTEGRITY_INPUT_INVALID", "inputs must be JSON objects"
        )
    return v, p


def _write(root: Path, path: Path, core: dict[str, Any]) -> dict[str, Any]:
    target = path.resolve() if path.is_absolute() else (root / path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    result = {**core, "receipt_sha256": _sha(core)}
    fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".receipt.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return {**result, "path": target.relative_to(root).as_posix()}


def _base(
    kind: str, ok: bool, findings: list[str], sources: dict[str, str]
) -> dict[str, Any]:
    return {
        "schema": f"factory.review-integrity.{kind}-receipt.v1",
        "marker": f"REVIEW_{kind.upper()}_READY"
        if ok
        else f"REVIEW_{kind.upper()}_BLOCKED",
        "ok": ok,
        "findings": findings,
        "sources": sources,
        "authority": {
            **AUTHORITY,
            "execution": False,
            "release": False,
            "policy_override": False,
        },
        "claim_boundary": "Local deterministic metadata validation only; not semantic code understanding, environment execution, signature verification, or release approval.",
    }


def _instant(value: object) -> datetime | None:
    """Parse a timezone-aware ISO-8601 instant or return None for ambiguous timestamp input."""
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _validate_intent_contract(contract: dict[str, Any]) -> None:
    if (
        set(contract) != {"schema", "approved_paths", "forbidden_terms", "approval"}
        or contract.get("schema") != "factory.intent-diff-contract.v1"
        or not isinstance(contract.get("approved_paths"), list)
    ):
        raise RevenueForgeError(
            "INTENT_DIFF_CONTRACT_INVALID",
            "contract needs approved_paths, forbidden_terms, and human/trusted approval",
        )


def _validate_diff_manifest(manifest: dict[str, Any]) -> None:
    if (
        set(manifest)
        != {"schema", "base_sha", "head_sha", "changed_paths", "added_text"}
        or manifest.get("schema") != "factory.diff-manifest.v1"
        or not isinstance(manifest.get("changed_paths"), list)
        or not isinstance(manifest.get("added_text"), str)
    ):
        raise RevenueForgeError(
            "INTENT_DIFF_MANIFEST_INVALID", "diff manifest must be explicit and bounded"
        )


def _intent_authority_findings(contract: dict[str, Any]) -> list[str]:
    approval = contract["approval"]
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        return ["E_INTENT_AUTHORITY_MISSING"]
    return []


def _scope_allows_path(path: object, approved_paths: list[Any]) -> bool:
    if not isinstance(path, str):
        return False
    return any(
        scope == "." or path == scope or path.startswith(scope.rstrip("/") + "/")
        for scope in approved_paths
    )


def _intent_scope_findings(
    contract: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    findings: list[str] = []
    for path in manifest["changed_paths"]:
        if not _scope_allows_path(path, contract["approved_paths"]):
            findings.append("E_INTENT_SCOPE_DRIFT:" + str(path))
    return findings


def _forbidden_term_findings(
    contract: dict[str, Any], manifest: dict[str, Any]
) -> list[str]:
    added_text = manifest["added_text"].lower()
    return [
        "E_INTENT_FORBIDDEN_BEHAVIOR:" + term
        for term in contract.get("forbidden_terms", [])
        if isinstance(term, str) and term and term.lower() in added_text
    ]


def _intent_diff_core(
    root: Path,
    contract_path: Path,
    diff_path: Path,
    contract: dict[str, Any],
    manifest: dict[str, Any],
    findings: list[str],
) -> dict[str, Any]:
    core = _base(
        "intent_diff",
        not findings,
        findings,
        {
            "contract": contract_path.relative_to(root).as_posix(),
            "diff": diff_path.relative_to(root).as_posix(),
        },
    )
    core.update(
        {
            "action_summary": "Compare a declared diff against human-approved scope and forbidden behaviors before review promotion.",
            "base_sha": manifest["base_sha"],
            "head_sha": manifest["head_sha"],
            "repair_plan": [
                "Remove or separately approve the out-of-scope path or forbidden behavior."
                for _ in findings
            ],
        }
    )
    return core


def verify_intent_diff(
    root: Path, contract_path: Path, diff_path: Path, out: Path
) -> dict[str, Any]:
    """Fail closed when a declared change exceeds approved intent or forbidden behavior."""
    root = Path(root).resolve()
    c, cp = _read(root, contract_path)
    d, dp = _read(root, diff_path)
    _validate_intent_contract(c)
    find = _intent_authority_findings(c)
    _validate_diff_manifest(d)
    find.extend(_intent_scope_findings(c, d))
    find.extend(_forbidden_term_findings(c, d))
    core = _intent_diff_core(root, cp, dp, c, d, find)
    return _write(root, out, core)


def _validate_freshness_manifest(manifest: dict[str, Any]) -> None:
    if (
        set(manifest)
        != {"schema", "current_commit", "environment_sha256", "now", "receipts"}
        or manifest.get("schema") != "factory.receipt-freshness-manifest.v1"
        or not isinstance(manifest.get("receipts"), list)
    ):
        raise RevenueForgeError(
            "RECEIPT_FRESHNESS_MANIFEST_INVALID",
            "manifest needs current commit, environment digest, time, and receipts",
        )


def _freshness_metadata_valid(receipt: object) -> bool:
    return isinstance(receipt, dict) and set(receipt) == {
        "id",
        "commit",
        "environment_sha256",
        "expires_at",
        "nonce",
    }


def _freshness_expired(receipt: dict[str, Any], manifest: dict[str, Any]) -> bool:
    expires_at, manifest_now = (
        _instant(receipt["expires_at"]),
        _instant(manifest["now"]),
    )
    current_now = datetime.now(timezone.utc)
    reference_now = (
        max(current_now, manifest_now) if manifest_now is not None else current_now
    )
    return (
        not isinstance(receipt["nonce"], str)
        or not receipt["nonce"]
        or expires_at is None
        or manifest_now is None
        or expires_at <= reference_now
    )


def _freshness_receipt_findings(
    receipt: object, manifest: dict[str, Any], seen: set[Any]
) -> list[str]:
    if not _freshness_metadata_valid(receipt):
        return ["E_RECEIPT_METADATA_LOOSE"]
    if receipt["id"] in seen:
        return ["E_RECEIPT_REPLAY:" + str(receipt["id"])]
    seen.add(receipt["id"])
    findings = []
    if receipt["commit"] != manifest["current_commit"]:
        findings.append("E_RECEIPT_STALE_COMMIT:" + str(receipt["id"]))
    if receipt["environment_sha256"] != manifest["environment_sha256"]:
        findings.append("E_RECEIPT_ENVIRONMENT_DRIFT:" + str(receipt["id"]))
    if _freshness_expired(receipt, manifest):
        findings.append("E_RECEIPT_EXPIRED:" + str(receipt["id"]))
    return findings


def _freshness_core(
    root: Path, path: Path, manifest: dict[str, Any], findings: list[str]
) -> dict[str, Any]:
    core = _base(
        "freshness",
        not findings,
        findings,
        {"manifest": path.relative_to(root).as_posix()},
    )
    core.update(
        {
            "action_summary": "Reject stale, replayed, expired, or environment-mismatched release-critical receipts.",
            "receipt_count": len(manifest["receipts"]),
            "repair_plan": [
                "Re-run the exact gate for the current commit and environment with a new expiry and nonce."
                for _ in findings
            ],
        }
    )
    return core


def verify_receipt_freshness(
    root: Path, manifest_path: Path, out: Path
) -> dict[str, Any]:
    """Reject release receipts that are stale, replayed, expired, or environment mismatched."""
    root = Path(root).resolve()
    manifest, source = _read(root, manifest_path)
    _validate_freshness_manifest(manifest)
    seen: set[Any] = set()
    findings = []
    for receipt in manifest["receipts"]:
        findings.extend(_freshness_receipt_findings(receipt, manifest, seen))
    core = _freshness_core(root, source, manifest, findings)
    return _write(root, out, core)


def _validate_policy_pack(pack: dict[str, Any]) -> None:
    if (
        set(pack) != {"schema", "owner", "version", "approval", "rules"}
        or pack.get("schema") != "factory.team-policy-pack.v1"
        or not isinstance(pack.get("rules"), list)
    ):
        raise RevenueForgeError(
            "TEAM_POLICY_PACK_INVALID", "pack needs human-owned versioned rules"
        )


def _policy_identity_findings(pack: dict[str, Any]) -> list[str]:
    valid = (
        isinstance(pack.get("owner"), str)
        and bool(pack["owner"].strip())
        and isinstance(pack.get("version"), str)
        and bool(pack["version"].strip())
    )
    return [] if valid else ["E_POLICY_OWNER_OR_VERSION_MISSING"]


def _policy_approval_findings(pack: dict[str, Any]) -> list[str]:
    approval = pack.get("approval")
    if not isinstance(approval, dict) or approval.get("origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        return ["E_POLICY_AGENT_OWNED"]
    return []


def _policy_rule_valid(rule: object) -> bool:
    return (
        isinstance(rule, dict)
        and set(rule) == {"id", "requirement", "gate"}
        and all(isinstance(rule[key], str) and rule[key] for key in rule)
    )


def _policy_rule_findings(pack: dict[str, Any]) -> list[str]:
    rules = pack["rules"]
    if not rules or not all(_policy_rule_valid(rule) for rule in rules):
        return ["E_POLICY_RULE_LOOSE"]
    return []


def _policy_core(
    root: Path, path: Path, pack: dict[str, Any], findings: list[str]
) -> dict[str, Any]:
    core = _base(
        "policy_pack",
        not findings,
        findings,
        {"pack": path.relative_to(root).as_posix()},
    )
    core.update(
        {
            "action_summary": "Verify a human-owned, versioned team policy pack before it is selected as a review baseline.",
            "owner": pack.get("owner"),
            "version": pack.get("version"),
            "rule_count": len(pack["rules"]),
            "repair_plan": [
                "Have the designated human/trusted owner approve explicit rule-to-gate mappings."
                for _ in findings
            ],
        }
    )
    return core


def verify_policy_pack(root: Path, pack_path: Path, out: Path) -> dict[str, Any]:
    """Verify that a selected team policy pack is explicit, versioned, and human owned."""
    root = Path(root).resolve()
    p, pp = _read(root, pack_path)
    _validate_policy_pack(p)
    find = _policy_identity_findings(p)
    find.extend(_policy_approval_findings(p))
    find.extend(_policy_rule_findings(p))
    core = _policy_core(root, pp, p, find)
    return _write(root, out, core)

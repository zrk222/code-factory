"""Bounded, proof-gated repair-loop packets for exact failures and consequences.

The module never attempts a repair.  It binds a human-reviewable failure,
candidate, consequence assessment, and independent re-check inputs so an agent
cannot silently convert repeated guesses into an approved outcome.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .oracle_firewall import OracleFirewallError, verify_oracle_contract
from .protocol_enums import RepairConsequence, RepairSeverity


MANIFEST_SCHEMA = "factory.repair-loop-manifest.v1"
RECEIPT_SCHEMA = "factory.repair-loop-receipt.v1"
PROJECTION_SCHEMA = "factory.repair-loop-projection.v1"
RECEIPT_DIR = Path(".factory/repair-loops")
MAX_BYTES = 1_048_576
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_SEVERITIES = RepairSeverity.values()
_CONSEQUENCES = RepairConsequence.values()
AUTHORITY = {"execution": False, "approval": False, "repair": False, "merge": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False}


class RepairLoopError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "input must be canonical JSON") from exc


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", f"{label} must be a safe identifier")
    return value


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", f"{label} must be a lowercase SHA-256")
    return value


def _path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", f"{label} must be a workspace-relative path")
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise RepairLoopError("E_REPAIR_LOOP_PATH", f"{label} escapes the workspace")
    return path.as_posix().rstrip("/") or "."


def _inside(root: Path, relative: str, *, required: bool = False) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise RepairLoopError("E_REPAIR_LOOP_PATH", "path escapes the workspace") from exc
    if required and not target.is_file():
        raise RepairLoopError("E_REPAIR_LOOP_EVIDENCE", f"required evidence is unavailable: {relative}")
    return target


def _bound_file(root: Path, value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", f"{label} must contain exact path and sha256")
    relative, expected = _path(value["path"], f"{label}.path"), _hash(value["sha256"], f"{label}.sha256")
    actual = _file_sha(_inside(root, relative, required=True))
    if actual != expected:
        raise RepairLoopError("E_REPAIR_LOOP_EVIDENCE", f"{label} does not match local bytes")
    return {"path": relative, "sha256": expected}


def _read_manifest(root: Path, source: Path) -> tuple[dict[str, Any], str]:
    try:
        relative = source.resolve().relative_to(root).as_posix() if source.is_absolute() else _path(str(source), "manifest")
    except ValueError as exc:
        raise RepairLoopError("E_REPAIR_LOOP_PATH", "manifest escapes the workspace") from exc
    path = _inside(root, relative, required=True)
    if path.stat().st_size > MAX_BYTES:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "manifest exceeds the 1 MiB limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "manifest must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "manifest must be an object")
    return value, relative


def _manifest(root: Path, source: Path) -> dict[str, Any]:
    value, relative = _read_manifest(root, source)
    fields = {"schema", "id", "oracle", "issue", "consequences", "reproduction", "repair", "independent_recheck", "human_review"}
    if set(value) != fields or value.get("schema") != MANIFEST_SCHEMA:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", f"manifest must use exact {MANIFEST_SCHEMA} fields")
    oracle = value["oracle"]
    if not isinstance(oracle, dict) or set(oracle) != {"contract_path", "contract_sha256"}:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "oracle fields must be exact")
    contract_path, contract_sha = _path(oracle["contract_path"], "oracle.contract_path"), _hash(oracle["contract_sha256"], "oracle.contract_sha256")
    try:
        verified = verify_oracle_contract(root, Path(contract_path))
    except OracleFirewallError as exc:
        raise RepairLoopError("E_REPAIR_LOOP_ORACLE", str(exc)) from exc
    if not verified.get("ok") or verified.get("contract", {}).get("contract_sha256") != contract_sha:
        raise RepairLoopError("E_REPAIR_LOOP_ORACLE", "repair loop must bind the current sealed Oracle Contract")
    issue = value["issue"]
    if not isinstance(issue, dict) or set(issue) != {"failure_code", "summary", "affected_obligations"} or not isinstance(issue["failure_code"], str) or not issue["failure_code"].startswith("E_") or not isinstance(issue["summary"], str) or not issue["summary"].strip() or len(issue["summary"]) > 280 or not isinstance(issue["affected_obligations"], list) or not 1 <= len(issue["affected_obligations"]) <= 32:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "issue must name an E_ failure, concise summary, and 1-32 obligations")
    obligations = sorted({_id(item, "issue.affected_obligations") for item in issue["affected_obligations"]})
    if len(obligations) != len(issue["affected_obligations"]):
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "issue.affected_obligations must be unique")
    consequences = value["consequences"]
    if not isinstance(consequences, list) or not 1 <= len(consequences) <= 16:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "consequences must contain 1-16 items")
    normalized_consequences: list[dict[str, str]] = []
    for index, item in enumerate(consequences):
        if not isinstance(item, dict) or set(item) != {"kind", "severity", "rationale"} or item["kind"] not in _CONSEQUENCES or item["severity"] not in _SEVERITIES or not isinstance(item["rationale"], str) or not item["rationale"].strip() or len(item["rationale"]) > 280:
            raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", f"consequences[{index}] is invalid")
        normalized_consequences.append({"kind": item["kind"], "severity": item["severity"], "rationale": item["rationale"].strip()})
    reproduction = _bound_file(root, value["reproduction"], "reproduction")
    repair = value["repair"]
    if not isinstance(repair, dict) or set(repair) != {"candidate", "allowed_paths"} or not isinstance(repair["allowed_paths"], list) or not 1 <= len(repair["allowed_paths"]) <= 64:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "repair must bind a candidate and 1-64 allowed paths")
    allowed_paths = sorted({_path(item, "repair.allowed_paths") for item in repair["allowed_paths"]})
    if len(allowed_paths) != len(repair["allowed_paths"]):
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "repair.allowed_paths must be unique")
    independent = value["independent_recheck"]
    if not isinstance(independent, dict) or set(independent) != {"challenge_plan", "positive_receipt", "negative_receipt"}:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "independent_recheck fields must be exact")
    human = value["human_review"]
    if not isinstance(human, dict) or set(human) != {"required", "reviewer"} or human["required"] is not True:
        raise RepairLoopError("E_REPAIR_LOOP_SCHEMA", "human_review.required must remain true")
    return {"id": _id(value["id"], "id"), "oracle": {"contract_path": contract_path, "contract_sha256": contract_sha}, "issue": {"failure_code": issue["failure_code"], "summary": issue["summary"].strip(), "affected_obligations": obligations}, "consequences": sorted(normalized_consequences, key=lambda item: (item["severity"], item["kind"], item["rationale"])), "reproduction": reproduction, "repair": {"candidate": _bound_file(root, repair["candidate"], "repair.candidate"), "allowed_paths": allowed_paths}, "independent_recheck": {"challenge_plan": _bound_file(root, independent["challenge_plan"], "independent_recheck.challenge_plan"), "positive_receipt": _bound_file(root, independent["positive_receipt"], "independent_recheck.positive_receipt"), "negative_receipt": _bound_file(root, independent["negative_receipt"], "independent_recheck.negative_receipt")}, "human_review": {"required": True, "reviewer": _id(human["reviewer"], "human_review.reviewer")}, "source_path": relative, "source_sha256": _file_sha(_inside(root, relative, required=True))}


def assess_repair_loop(root: Path, manifest_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Bind one failure, consequence assessment, candidate, and independent re-check packet."""
    workspace = Path(root).resolve()
    manifest = _manifest(workspace, manifest_path)
    core = {"schema": RECEIPT_SCHEMA, "marker": "REPAIR_LOOP_READY", **manifest, "authority": dict(AUTHORITY), "scope_limits": ["The consequence list is a human-authored risk assessment, not a prediction or severity guarantee.", "This receipt never runs the candidate, repairs code, calls a model, merges a change, or approves a decision."], "created_at": _now()}
    receipt = {**core, "receipt_sha256": _sha(core)}
    default = (RECEIPT_DIR / f"{manifest['id']}-{receipt['receipt_sha256'][:12]}.json").as_posix()
    relative = _path(str(out) if out else default, "output")
    if not relative.startswith(RECEIPT_DIR.as_posix() + "/"):
        raise RepairLoopError("E_REPAIR_LOOP_PATH", "output must be beneath .factory/repair-loops")
    target = _inside(workspace, relative)
    if target.exists():
        raise RepairLoopError("E_REPAIR_LOOP_EXISTS", "repair-loop receipt is immutable; choose a new output")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {**receipt, "path": relative}


def repair_loop_projection(root: Path) -> dict[str, Any]:
    """Project only structurally valid local repair packets for human review."""
    workspace, receipts, invalid = Path(root).resolve(), [], []
    directory = workspace / RECEIPT_DIR
    if directory.is_dir():
        for path in sorted(directory.glob("*.json"))[:500]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                core = {key: value[key] for key in value if key != "receipt_sha256"}
                if value.get("schema") != RECEIPT_SCHEMA or value.get("receipt_sha256") != _sha(core):
                    raise ValueError("invalid receipt")
                receipts.append({"id": value["id"], "path": path.relative_to(workspace).as_posix(), "receipt_sha256": value["receipt_sha256"], "failure_code": value["issue"]["failure_code"], "consequence_count": len(value["consequences"]), "highest_severity": max((item["severity"] for item in value["consequences"]), key=lambda item: ("low", "medium", "high", "critical").index(item)), "reviewer": value["human_review"]["reviewer"], "oracle_contract_sha256": value["oracle"]["contract_sha256"]})
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                invalid.append(path.relative_to(workspace).as_posix())
    receipts.sort(key=lambda item: (item["id"], item["receipt_sha256"]))
    return {"schema": PROJECTION_SCHEMA, "marker": "REPAIR_LOOP_READ_ONLY", "receipt_count": len(receipts), "invalid_count": len(invalid), "latest": receipts[-1] if receipts else None, "receipts": receipts[-50:], "invalid": invalid[:100], "authority": dict(AUTHORITY), "claim_boundary": "Read-only local repair-loop facts. No repair, model, provider, approval, merge, release, or external communication action ran."}


def repair_loop_template() -> dict[str, Any]:
    """Return a secret-free proof-gated repair-loop manifest template."""
    return {"schema": "factory.repair-loop-template.v1", "manifest_schema": MANIFEST_SCHEMA, "authority": dict(AUTHORITY), "claim_boundary": "Template only. It does not diagnose a real issue, run a repair, or approve a change.", "manifest": {"schema": MANIFEST_SCHEMA, "id": "replace-with-repair-loop-id", "oracle": {"contract_path": ".factory/oracles/contracts/current.json", "contract_sha256": "replace-with-lowercase-sha256"}, "issue": {"failure_code": "E_REPLACE_WITH_EXACT_FAILURE", "summary": "replace-with-observed-symptom", "affected_obligations": ["replace-with-obligation-id"]}, "consequences": [{"kind": "user_experience", "severity": "medium", "rationale": "replace-with-human-reviewed-consequence"}], "reproduction": {"path": ".factory/e2e/observed-failure.json", "sha256": "replace-with-lowercase-sha256"}, "repair": {"candidate": {"path": ".factory/repair-candidates/candidate.patch", "sha256": "replace-with-lowercase-sha256"}, "allowed_paths": ["src"]}, "independent_recheck": {"challenge_plan": {"path": ".factory/oracles/challenges/current.json", "sha256": "replace-with-lowercase-sha256"}, "positive_receipt": {"path": ".factory/proofs/positive.json", "sha256": "replace-with-lowercase-sha256"}, "negative_receipt": {"path": ".factory/proofs/negative.json", "sha256": "replace-with-lowercase-sha256"}}, "human_review": {"required": True, "reviewer": "replace-with-named-reviewer"}}}

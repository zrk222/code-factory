"""Hash-bound proof continuity across intent, gates, evidence, and observations.

The ledger is intentionally a local evidence boundary.  It can seal a named
human/trusted-source Oracle chain and record later evidence which confirms,
contradicts, or leaves that chain inconclusive.  It cannot run tests, change
code, contact a provider, or decide that a release is approved.
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

from .oracle_firewall import AUTHORITY, OracleFirewallError, verify_oracle_contract


CONTRACT_INPUT_SCHEMA = "factory.proof-continuity-contract-input.v1"
CONTRACT_SCHEMA = "factory.proof-continuity-contract.v1"
OBSERVATION_INPUT_SCHEMA = "factory.proof-continuity-observation-input.v1"
OBSERVATION_SCHEMA = "factory.proof-continuity-observation.v1"
PROJECTION_SCHEMA = "factory.proof-continuity-projection.v1"
MAX_BYTES = 1_048_576
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,95}")
_PROVENANCE = {"human_confirmed", "trusted_source"}
_EVIDENCE_KINDS = {"gate", "test", "challenge", "device", "storefront", "capture", "release", "runtime"}
_HASH_FIELDS = {"receipt_sha256", "contract_sha256", "challenge_sha256", "drift_sha256", "handoff_sha256"}


class ProofContinuityError(ValueError):
    """Stable local refusal for the proof-continuity boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value: object, field: str, limit: int = 800) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise ProofContinuityError("PROOF_CONTINUITY_INPUT_INVALID", f"{field} must be a non-empty string up to {limit} characters")
    return result


def _id(value: object, field: str) -> str:
    result = _text(value, field, 96)
    if not _IDENTIFIER.fullmatch(result):
        raise ProofContinuityError("PROOF_CONTINUITY_INPUT_INVALID", f"{field} must match {_IDENTIFIER.pattern}")
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise ProofContinuityError("PROOF_CONTINUITY_PATH_OUT_OF_SCOPE", "all paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise ProofContinuityError("PROOF_CONTINUITY_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read_json(root: Path, path: Path, schema: str | None = None) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise ProofContinuityError("PROOF_CONTINUITY_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofContinuityError("PROOF_CONTINUITY_INPUT_INVALID", "input must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or (schema is not None and value.get("schema") != schema):
        raise ProofContinuityError("PROOF_CONTINUITY_SCHEMA_REJECTED", f"expected {schema}" if schema else "input must be an object")
    return value, source


def _valid(value: object, schema: str, digest_field: str) -> bool:
    if not isinstance(value, dict) or value.get("schema") != schema:
        return False
    supplied = value.get(digest_field)
    return isinstance(supplied, str) and len(supplied) == 64 and _sha({key: item for key, item in value.items() if key != digest_field}) == supplied


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


def _write_new(root: Path, out: Path, payload: dict[str, Any]) -> Path:
    target = _local(root, out, exists=False)
    if target.exists():
        raise ProofContinuityError("PROOF_CONTINUITY_OUTPUT_EXISTS", "destination already exists; evidence receipts are immutable")
    _atomic(target, payload)
    return target


def _subject(value: object) -> dict[str, str]:
    """Validate a repository-level audit subject, not an AppForge candidate."""
    if not isinstance(value, dict) or set(value) != {"repository", "revision", "scope"}:
        raise ProofContinuityError("PROOF_CONTINUITY_SUBJECT_INVALID", "subject must contain only repository, revision, and scope")
    subject = {key: _text(value.get(key), f"subject.{key}", 512 if key == "scope" else 160) for key in sorted(value)}
    if not re.fullmatch(r"[0-9a-fA-F]{7,64}", subject["revision"]):
        raise ProofContinuityError("PROOF_CONTINUITY_SUBJECT_INVALID", "subject.revision must be a Git-like hexadecimal revision")
    scope = Path(subject["scope"].replace("\\", "/"))
    if scope.is_absolute() or ".." in scope.parts:
        raise ProofContinuityError("PROOF_CONTINUITY_SUBJECT_INVALID", "subject.scope must be a workspace-relative scope")
    subject["scope"] = scope.as_posix().rstrip("/") or "."
    return subject


def _evidence(root: Path, value: object, index: int, subject: dict[str, str]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"id", "kind", "path", "schema", "marker", "sha_field"}:
        raise ProofContinuityError("PROOF_CONTINUITY_EVIDENCE_INVALID", "each evidence reference must contain id, kind, path, schema, marker, and sha_field")
    evidence_id = _id(value.get("id"), f"evidence[{index}].id")
    kind = _text(value.get("kind"), f"evidence[{index}].kind", 40)
    if kind not in _EVIDENCE_KINDS:
        raise ProofContinuityError("PROOF_CONTINUITY_EVIDENCE_INVALID", "evidence kind is unsupported")
    schema = _text(value.get("schema"), f"evidence[{index}].schema", 160)
    marker = _text(value.get("marker"), f"evidence[{index}].marker", 160)
    digest_field = _text(value.get("sha_field"), f"evidence[{index}].sha_field", 40)
    if digest_field not in _HASH_FIELDS:
        raise ProofContinuityError("PROOF_CONTINUITY_EVIDENCE_INVALID", "evidence sha_field is unsupported")
    source, path = _read_json(root, Path(_text(value.get("path"), f"evidence[{index}].path", 512)), schema)
    if source.get("marker") != marker or not _valid(source, schema, digest_field):
        raise ProofContinuityError("PROOF_CONTINUITY_EVIDENCE_INVALID", "evidence must match its declared schema, marker, and local hash seal")
    declared_candidate = source.get("candidate")
    if isinstance(declared_candidate, dict) and isinstance(declared_candidate.get("source_commit"), str) and declared_candidate["source_commit"].lower() != subject["revision"].lower():
        raise ProofContinuityError("PROOF_CONTINUITY_EVIDENCE_REVISION_MISMATCH", "candidate-bound evidence must name the exact sealed repository revision")
    return {"id": evidence_id, "kind": kind, "path": path.relative_to(Path(root).resolve()).as_posix(), "schema": schema, "marker": marker, "sha_field": digest_field, "sha256": _file_sha(path), "receipt_sha256": str(source[digest_field])}


def _rule_maps(oracle: dict[str, Any]) -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, dict[str, Any]]]:
    rules = oracle.get("rules")
    sources = oracle.get("sources")
    if not isinstance(rules, dict) or not isinstance(sources, list):
        raise ProofContinuityError("PROOF_CONTINUITY_ORACLE_INVALID", "sealed oracle is missing its rule or source map")
    grouped = {group: {str(item.get("id")): item for item in rules.get(group, []) if isinstance(item, dict) and item.get("id")} for group in ("requirements", "forbidden_behaviors", "gates", "tests")}
    source_map = {str(item.get("id")): item for item in sources if isinstance(item, dict) and item.get("id")}
    if any(not items for items in grouped.values()) or not source_map:
        raise ProofContinuityError("PROOF_CONTINUITY_ORACLE_INVALID", "sealed oracle must contain source-bound requirements, forbidden behaviors, gates, and tests")
    return grouped, source_map


def _obligations(value: object, grouped: dict[str, dict[str, dict[str, Any]]], sources: dict[str, dict[str, Any]], evidence: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value or len(value) > 128:
        raise ProofContinuityError("PROOF_CONTINUITY_CHAIN_INVALID", "obligations must contain 1 through 128 source-to-evidence chains")
    expected = {"id", "source_id", "requirement_id", "forbidden_behavior_id", "gate_id", "test_id", "evidence_id"}
    rows: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict) or set(raw) != expected:
            raise ProofContinuityError("PROOF_CONTINUITY_CHAIN_INVALID", "every obligation must have the complete source-to-evidence chain")
        row = {key: _id(raw.get(key), f"obligations[{index}].{key}") for key in expected}
        bindings = (("source_id", sources), ("requirement_id", grouped["requirements"]), ("forbidden_behavior_id", grouped["forbidden_behaviors"]), ("gate_id", grouped["gates"]), ("test_id", grouped["tests"]), ("evidence_id", evidence))
        if any(row[key] not in available for key, available in bindings):
            raise ProofContinuityError("PROOF_CONTINUITY_CHAIN_INVALID", "obligation references an unavailable source, rule, or evidence receipt")
        source = sources[row["source_id"]]
        rules = (grouped["requirements"][row["requirement_id"]], grouped["forbidden_behaviors"][row["forbidden_behavior_id"]], grouped["gates"][row["gate_id"]], grouped["tests"][row["test_id"]])
        if source.get("origin") not in _PROVENANCE or any(rule.get("source_id") != row["source_id"] or rule.get("origin") not in _PROVENANCE or rule.get("effect") not in {"blocking", "release"} for rule in rules):
            raise ProofContinuityError("PROOF_CONTINUITY_PROVENANCE_INVALID", "only human-confirmed or trusted-source blocking/release rules may enter the continuity chain")
        rows.append(row)
    if len({item["id"] for item in rows}) != len(rows):
        raise ProofContinuityError("PROOF_CONTINUITY_CHAIN_INVALID", "obligation identifiers must be unique")
    for field, group in (("requirement_id", "requirements"), ("forbidden_behavior_id", "forbidden_behaviors"), ("gate_id", "gates"), ("test_id", "tests")):
        needed = {rule_id for rule_id, rule in grouped[group].items() if rule.get("critical") and rule.get("effect") in {"blocking", "release"}}
        found = {row[field] for row in rows}
        if not needed <= found:
            raise ProofContinuityError("PROOF_CONTINUITY_CHAIN_INCOMPLETE", f"every critical {group} rule must appear in an obligation chain")
    return sorted(rows, key=lambda item: item["id"])


def seal_proof_continuity(root: Path, input_path: Path, out: Path) -> dict[str, Any]:
    """Seal a cross-phase proof chain; it is not a test, release, or approval."""
    workspace = Path(root).resolve()
    raw, source = _read_json(workspace, input_path, CONTRACT_INPUT_SCHEMA)
    expected = {"schema", "id", "subject", "oracle_contract", "evidence", "obligations", "approved_by", "approval_rationale", "autonomy"}
    if set(raw) != expected:
        raise ProofContinuityError("PROOF_CONTINUITY_INPUT_INVALID", "contract input contains unsupported or missing fields")
    contract_id = _id(raw.get("id"), "id")
    subject = _subject(raw.get("subject"))
    approved_by = _text(raw.get("approved_by"), "approved_by", 160)
    rationale = _text(raw.get("approval_rationale"), "approval_rationale")
    if raw.get("autonomy") not in {"human_controlled", "supervised"}:
        raise ProofContinuityError("PROOF_CONTINUITY_AUTHORITY_INVALID", "autonomy must be human_controlled or supervised; autonomous continuity is not self-approved")
    verified = verify_oracle_contract(workspace, Path(_text(raw.get("oracle_contract"), "oracle_contract", 512)))
    if not verified.get("ok"):
        raise ProofContinuityError("PROOF_CONTINUITY_ORACLE_INVALID", f"oracle contract is not current: {verified.get('reason')}")
    oracle = verified["contract"]
    grouped, sources = _rule_maps(oracle)
    supplied = raw.get("evidence")
    if not isinstance(supplied, list) or not supplied or len(supplied) > 32:
        raise ProofContinuityError("PROOF_CONTINUITY_EVIDENCE_INVALID", "evidence must contain 1 through 32 bound receipts")
    evidence_rows = [_evidence(workspace, item, index, subject) for index, item in enumerate(supplied)]
    if len({item["id"] for item in evidence_rows}) != len(evidence_rows):
        raise ProofContinuityError("PROOF_CONTINUITY_EVIDENCE_INVALID", "evidence identifiers must be unique")
    evidence = {item["id"]: item for item in evidence_rows}
    obligations = _obligations(raw.get("obligations"), grouped, sources, evidence)
    core: dict[str, Any] = {
        "schema": CONTRACT_SCHEMA,
        "marker": "PROOF_CONTINUITY_SEALED",
        "id": contract_id,
        "sealed_at": _now(),
        "subject": subject,
        "approved_by": approved_by,
        "approval_rationale": rationale,
        "autonomy": {"mode": raw["autonomy"], "self_amendment": False, "automatic_release": False},
        "oracle": {"path": verified["path"], "contract_sha256": oracle["contract_sha256"], "original_intent_sha256": oracle["handoff"]["original_intent"]["sha256"], "handoff_sha256": oracle["handoff"]["handoff_sha256"]},
        "sources": [{"id": source_id, "origin": sources[source_id].get("origin"), "path": sources[source_id].get("path"), "sha256": sources[source_id].get("sha256")} for source_id in sorted({row["source_id"] for row in obligations})],
        "evidence": evidence_rows,
        "obligations": obligations,
        "input_sha256": _file_sha(source),
        "action_summary": "Seal the reviewed source-to-obligation-to-forbidden-behavior-to-gate-to-test-to-evidence chain for one exact repository revision; later contradictory evidence reopens it instead of silently preserving a ready state.",
        "authority": {**AUTHORITY, "execution": False, "code_mutation": False, "test_execution": False, "release": False, "publication": False, "autonomy_promotion": False},
        "claim_boundary": "Local hash-bound senior-engineering audit lineage only. It does not run or authenticate a test, challenge, device, provider, store, release, or post-release observation; it never substitutes for human approval.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    destination = _write_new(workspace, out, receipt)
    return {**receipt, "path": destination.relative_to(workspace).as_posix()}


def _contract_receipt(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    contract, source = _read_json(root, path, CONTRACT_SCHEMA)
    if not _valid(contract, CONTRACT_SCHEMA, "receipt_sha256") or contract.get("marker") != "PROOF_CONTINUITY_SEALED":
        raise ProofContinuityError("PROOF_CONTINUITY_CONTRACT_INVALID", "continuity contract must be hash-valid and sealed")
    return contract, source


def _validated_observation(root: Path, contract: dict[str, Any], observation_path: Path) -> tuple[dict[str, Any], dict[str, Any], Path]:
    raw, source = _read_json(root, observation_path, OBSERVATION_INPUT_SCHEMA)
    expected = {"schema", "id", "contract_sha256", "obligation_id", "outcome", "kind", "evidence_path", "evidence_sha256", "observed_at", "reviewed_by", "consequence"}
    if set(raw) != expected or raw.get("contract_sha256") != contract.get("receipt_sha256"):
        raise ProofContinuityError("PROOF_CONTINUITY_OBSERVATION_INVALID", "observation must have the exact shape and bind the exact proof-continuity receipt")
    obligation_id = _id(raw.get("obligation_id"), "observation.obligation_id")
    obligation = next((item for item in contract.get("obligations", []) if isinstance(item, dict) and item.get("id") == obligation_id), None)
    if obligation is None:
        raise ProofContinuityError("PROOF_CONTINUITY_OBSERVATION_INVALID", "observation names an unknown sealed obligation")
    outcome = _text(raw.get("outcome"), "observation.outcome", 20)
    kind = _text(raw.get("kind"), "observation.kind", 40)
    if outcome not in {"confirmed", "contradicted", "inconclusive"} or kind not in _EVIDENCE_KINDS:
        raise ProofContinuityError("PROOF_CONTINUITY_OBSERVATION_INVALID", "observation outcome or kind is unsupported")
    evidence_path = _local(root, Path(_text(raw.get("evidence_path"), "observation.evidence_path", 512)))
    if raw.get("evidence_sha256") != _file_sha(evidence_path):
        raise ProofContinuityError("PROOF_CONTINUITY_OBSERVATION_EVIDENCE_STALE", "observation evidence_sha256 must bind exact local evidence bytes")
    observed_at = _text(raw.get("observed_at"), "observation.observed_at", 40)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", observed_at):
        raise ProofContinuityError("PROOF_CONTINUITY_OBSERVATION_INVALID", "observed_at must be an RFC3339 UTC second timestamp")
    return {"id": _id(raw.get("id"), "observation.id"), "obligation_id": obligation_id, "outcome": outcome, "kind": kind, "evidence_path": evidence_path, "evidence_sha256": str(raw["evidence_sha256"]), "observed_at": observed_at, "reviewed_by": _text(raw.get("reviewed_by"), "observation.reviewed_by", 160), "consequence": _text(raw.get("consequence"), "observation.consequence")}, obligation, source


def _observation_state(outcome: str, autonomy: str) -> tuple[str, str, dict[str, Any]]:
    if outcome == "contradicted":
        return "E_PROOF_CONTINUITY_REOPENED", "BLOCKED", {"open": True, "failure_class": "proof_continuity_contradiction", "required_next_action": "named_human_review", "autonomy_mode": "supervised"}
    if outcome == "confirmed":
        return "PROOF_CONTINUITY_OBSERVATION_CONFIRMED", "CURRENT", {"open": False, "failure_class": None, "required_next_action": None, "autonomy_mode": autonomy}
    return "PROOF_CONTINUITY_REVIEW_REQUIRED", "REVIEW_REQUIRED", {"open": False, "failure_class": None, "required_next_action": "named_human_review", "autonomy_mode": autonomy}


def record_proof_continuity_observation(root: Path, contract_path: Path, observation_path: Path, out: Path) -> dict[str, Any]:
    """Record a sealed later observation and fail closed on contradiction."""
    workspace = Path(root).resolve()
    contract, contract_source = _contract_receipt(workspace, contract_path)
    observation, obligation, _ = _validated_observation(workspace, contract, observation_path)
    source = next((item for item in contract.get("sources", []) if isinstance(item, dict) and item.get("id") == obligation["source_id"]), {})
    marker, verdict, incident = _observation_state(observation["outcome"], contract["autonomy"]["mode"])
    core: dict[str, Any] = {
        "schema": OBSERVATION_SCHEMA,
        "marker": marker,
        "verdict": verdict,
        "recorded_at": _now(),
        "observation_id": observation["id"],
        "subject": contract["subject"],
        "contract": {"path": contract_source.relative_to(workspace).as_posix(), "receipt_sha256": contract["receipt_sha256"], "oracle_contract_sha256": contract["oracle"]["contract_sha256"]},
        "observation": {"outcome": observation["outcome"], "kind": observation["kind"], "evidence_path": observation["evidence_path"].relative_to(workspace).as_posix(), "evidence_sha256": observation["evidence_sha256"], "observed_at": observation["observed_at"], "reviewed_by": observation["reviewed_by"], "consequence": observation["consequence"]},
        "causal_chain": {"source": source, "obligation_id": observation["obligation_id"], "requirement_id": obligation["requirement_id"], "forbidden_behavior_id": obligation["forbidden_behavior_id"], "gate_id": obligation["gate_id"], "test_id": obligation["test_id"], "evidence_id": obligation["evidence_id"], "decision": verdict},
        "incident": incident,
        "action_summary": "Record later evidence against one sealed obligation; a contradiction opens a local incident and requires supervised human review rather than preserving a previous ready claim.",
        "authority": {**AUTHORITY, "execution": False, "code_mutation": False, "test_execution": False, "release": False, "publication": False, "autonomy_promotion": False},
        "claim_boundary": "Local observation binding only. A contradiction does not mutate code, revoke a real-world credential, contact a provider, or prove the external observation; a named human decides any recovery or release action.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    destination = _write_new(workspace, out, receipt)
    return {**receipt, "path": destination.relative_to(workspace).as_posix()}


def _projection_item(workspace: Path, path: Path, schema: str) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return None
    required_marker = "PROOF_CONTINUITY_SEALED" if schema == CONTRACT_SCHEMA else None
    if not _valid(value, schema, "receipt_sha256") or (required_marker is not None and value.get("marker") != required_marker):
        return None
    oracle = value.get("oracle") if isinstance(value.get("oracle"), dict) else {}
    contract = value.get("contract") if isinstance(value.get("contract"), dict) else {}
    incident = value.get("incident") if isinstance(value.get("incident"), dict) else {}
    return {"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "receipt_sha256": value.get("receipt_sha256"), "id": value.get("id") or value.get("observation_id"), "subject": value.get("subject"), "verdict": value.get("verdict"), "oracle_contract_sha256": oracle.get("contract_sha256") or contract.get("oracle_contract_sha256"), "contract_receipt_sha256": contract.get("receipt_sha256"), "incident_open": bool(incident.get("open"))}


def _read_projection_directory(workspace: Path, directory: str, schema: str) -> tuple[list[dict[str, Any]], list[str]]:
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "proof-continuity" / directory).glob("*.json"))[:200]:
        item = _projection_item(workspace, path, schema)
        if item is None:
            invalid.append(path.relative_to(workspace).as_posix())
        else:
            current.append(item)
    return current, invalid


def proof_continuity_projection(root: Path) -> dict[str, Any]:
    """Read sealed continuity contracts and observation incidents without side effects."""
    workspace = Path(root).resolve()
    contracts, contract_invalid = _read_projection_directory(workspace, "contracts", CONTRACT_SCHEMA)
    observations, observation_invalid = _read_projection_directory(workspace, "observations", OBSERVATION_SCHEMA)
    invalid = contract_invalid + observation_invalid
    reopened = [item for item in observations if item.get("incident_open")]
    contract_ids = {item["receipt_sha256"] for item in contracts if isinstance(item.get("receipt_sha256"), str)}
    active = [item for item in contracts if item.get("receipt_sha256") not in {obs.get("contract_receipt_sha256") for obs in reopened}]
    return {"schema": PROJECTION_SCHEMA, "marker": "PROOF_CONTINUITY_READ_ONLY", "contract_count": len(contracts), "active_contract_count": len(active), "observation_count": len(observations), "reopened_count": len(reopened), "invalid_count": len(invalid), "latest_contract": contracts[-1] if contracts else None, "latest_observation": observations[-1] if observations else None, "contracts": contracts[-20:], "observations": observations[-20:], "reopened": reopened[-20:], "orphan_observation_count": len([item for item in observations if item.get("contract_receipt_sha256") not in contract_ids]), "invalid": invalid[:100], "authority": {**AUTHORITY, "execution": False, "code_mutation": False, "release": False, "autonomy_promotion": False}, "claim_boundary": "Read-only local continuity status. It does not run evidence collection, modify a candidate, revoke real credentials, or approve recovery or release."}

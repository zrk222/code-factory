"""Supervised proof-of-survival batches and offline-verifiable Survival Cards.

The Gauntlet does not invent a test command from a natural-language promise.
It compiles only the explicit local E2E manifests a promise owner supplies,
requires a separate named admission before it executes them, and makes every
non-surviving or unproven case visible in its public card.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import html
import json
import os
from pathlib import Path
import re
from typing import Any

from .continuity import ContinuityError, ContinuityPrincipal, recall_continuity_metadata_read_only
from .e2e_proof import E2EProofError, public_e2e_proof_receipt, validate_e2e_proof_manifest, validate_e2e_proof_receipt, verify_e2e_proof
from .intent_quality import IntentQualityError, require_clear
from .reality_check import RealityCheckError, validate_reality_check_manifest


GAUNTLET_SOURCE_SCHEMA = "factory.gauntlet-source.v1"
GAUNTLET_PROPOSAL_SCHEMA = "factory.gauntlet-proposal.v1"
GAUNTLET_ADMISSION_SCHEMA = "factory.gauntlet-admission.v1"
SURVIVAL_CARD_SCHEMA = "factory.survival-card.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_COMPOUND_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,193}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_COMMIT = re.compile(r"^[a-f0-9]{40,64}$")
_RISK_TAGS = frozenset({"boundary", "authorization", "idempotency", "temporal", "state", "validation"})
_MUTATIONS = {
    "boundary": "outside_declared_boundary",
    "authorization": "missing_or_wrong_authority",
    "idempotency": "duplicate_effect_or_request",
    "temporal": "reordered_or_delayed_event",
    "state": "stale_or_conflicting_state",
    "validation": "invalid_or_missing_input",
}
MAX_PROMISES = 24
MAX_CASES = 48
MAX_CONTINUITY_RECORDS = 12
MAX_TOTAL_TIMEOUT_SECONDS = 3_600
_PLANNING_AUTHORITY = {
    "execution": False, "test_execution": False, "approval": False,
    "repair": False, "merge": False, "publication": False, "deployment": False,
    "signing": False, "messaging": False, "credential": False, "connector": False,
}
_RUN_AUTHORITY = {
    "execution": True, "test_execution": True, "approval": False,
    "source_write": False, "repair": False, "merge": False, "publication": False, "deployment": False,
    "signing": False, "messaging": False, "credential": False, "connector": False,
}


class GauntletError(ValueError):
    """Stable Gauntlet input, admission, and card error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", f"{field} must be RFC3339 text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", f"{field} must be RFC3339 text") from exc
    if parsed.tzinfo is None:
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _inside(root: Path, value: Path, field: str, *, exists: bool = True) -> tuple[Path, str]:
    candidate = Path(value)
    candidate = candidate if candidate.is_absolute() else root / candidate
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise GauntletError("GAUNTLET_PATH_INVALID", f"{field} must remain inside the workspace") from exc
    if exists and not resolved.is_file():
        raise GauntletError("GAUNTLET_INPUT_UNREADABLE", f"{field} must name a readable workspace file")
    return resolved, relative


def _text(value: object, field: str, *, identifier: bool = False, limit: int = 600) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} must be a non-empty string of at most {limit} characters")
    result = value.strip()
    if identifier and not _ID.fullmatch(result):
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} has an unsupported identifier")
    return result


def _clear_intent(value: str, field: str) -> str:
    """Keep unresolved Gauntlet promises from becoming proof obligations."""
    try:
        require_clear(value, field=field, require_action=True)
    except IntentQualityError as exc:
        raise GauntletError("GAUNTLET_INTENT_UNCLEAR", f"{field}: {exc.message}") from exc
    return value


def _compound_identifier(value: object, field: str) -> str:
    """Validate one promise/case id without truncating either declared id."""
    result = _text(value, field, limit=194)
    if not _COMPOUND_ID.fullmatch(result):
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} has an unsupported compound identifier")
    return result


def _load_json(root: Path, path: Path, field: str) -> tuple[dict[str, Any], Path, str, str]:
    resolved, relative = _inside(root, path, field)
    try:
        raw = resolved.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GauntletError("GAUNTLET_INPUT_INVALID", f"{field} must be UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GauntletError("GAUNTLET_INPUT_INVALID", f"{field} must contain one JSON object")
    return value, resolved, relative, sha256(raw).hexdigest()


def _relative_text(root: Path, value: object, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} must be a non-empty workspace-relative path")
    supplied = Path(value.replace("\\", "/"))
    if supplied.is_absolute() or ".." in supplied.parts:
        raise GauntletError("GAUNTLET_PATH_INVALID", f"{field} must remain workspace relative")
    _inside(root, root / supplied, field)
    return supplied


def _risk_tags(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= len(_RISK_TAGS):
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} must contain 1 through {len(_RISK_TAGS)} taxonomy tags")
    if any(not isinstance(tag, str) or tag not in _RISK_TAGS for tag in value) or len(set(value)) != len(value):
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} must contain unique supported taxonomy tags")
    return sorted(value)


def _string_list(value: object, field: str, *, maximum: int, identifier: bool = False) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} must contain 1 through {maximum} entries")
    result = [_text(item, f"{field} entry", identifier=identifier, limit=240) for item in value]
    if len(set(result)) != len(result):
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"{field} entries must be unique")
    return sorted(result)


def _continuity_binding(root: Path, value: object) -> dict[str, Any] | None:
    """Read only pre-verified continuity metadata; never recall memory content."""
    if value is None:
        return None
    required = {"db", "tenant_id", "purpose_ref", "scope_ref", "principal", "record_ids"}
    if not isinstance(value, dict) or set(value) != required:
        raise GauntletError("GAUNTLET_CONTINUITY_INVALID", "continuity must contain exactly db, tenant_id, purpose_ref, scope_ref, principal, and record_ids")
    db_path = _relative_text(root, value.get("db"), "continuity.db")
    tenant_id = _text(value.get("tenant_id"), "continuity.tenant_id", limit=160)
    purpose_ref = _text(value.get("purpose_ref"), "continuity.purpose_ref", limit=200)
    scope_ref = _text(value.get("scope_ref"), "continuity.scope_ref", limit=240)
    principal_raw = value.get("principal")
    if not isinstance(principal_raw, dict) or set(principal_raw) != {"subject", "roles", "purposes"}:
        raise GauntletError("GAUNTLET_CONTINUITY_INVALID", "continuity.principal must contain subject, roles, and purposes")
    record_ids = _string_list(value.get("record_ids"), "continuity.record_ids", maximum=MAX_CONTINUITY_RECORDS, identifier=True)
    try:
        principal = ContinuityPrincipal(
            subject=_text(principal_raw.get("subject"), "continuity.principal.subject", limit=160),
            tenant_id=tenant_id,
            roles=tuple(_string_list(principal_raw.get("roles"), "continuity.principal.roles", maximum=8, identifier=True)),
            purposes=tuple(_string_list(principal_raw.get("purposes"), "continuity.principal.purposes", maximum=12)),
        )
        recalled = recall_continuity_metadata_read_only(
            root / db_path, principal, tenant_id, purpose_ref=purpose_ref, scope_ref=scope_ref,
        )
    except ContinuityError as exc:
        raise GauntletError("GAUNTLET_CONTINUITY_UNAVAILABLE", f"verified continuity metadata is unavailable: {exc.code}") from exc
    records_by_id = {entry["record_id"]: entry for entry in recalled["records"]}
    if any(record_id not in records_by_id for record_id in record_ids):
        raise GauntletError("GAUNTLET_CONTINUITY_STALE", "every selected continuity record must be verified, unexpired, and exact-scope authorized")
    records = [{
        "record_id_sha256": _sha({"record_id": record_id}),
        "record_type": records_by_id[record_id]["record_type"],
        "memory_ref_sha256": records_by_id[record_id]["memory_ref_sha256"],
        "purpose_ref": records_by_id[record_id]["purpose_ref"],
        "scope_ref_sha256": records_by_id[record_id]["scope_ref_sha256"],
        "evidence_sha256": records_by_id[record_id]["evidence_sha256"],
        "record_sha256": records_by_id[record_id]["record_sha256"],
        "expires_at": records_by_id[record_id]["expires_at"],
    } for record_id in record_ids]
    core = {
        "marker": "GAUNTLET_CONTINUITY_METADATA_BOUND",
        "tenant_id_sha256": _sha({"tenant_id": tenant_id}),
        "purpose_ref": purpose_ref,
        "scope_ref_sha256": recalled["scope_ref_sha256"],
        "records": records,
    }
    return {**core, "binding_sha256": _sha(core)}


def _validate_continuity_binding(value: object, label: str) -> None:
    if value is None:
        return
    fields = {"marker", "tenant_id_sha256", "purpose_ref", "scope_ref_sha256", "records", "binding_sha256"}
    if not isinstance(value, dict) or set(value) != fields or value.get("marker") != "GAUNTLET_CONTINUITY_METADATA_BOUND":
        raise GauntletError("GAUNTLET_PROPOSAL_INVALID", f"{label} continuity binding is invalid")
    core = {key: value[key] for key in fields - {"binding_sha256"}}
    for field in ("tenant_id_sha256", "scope_ref_sha256", "binding_sha256"):
        if not isinstance(value.get(field), str) or not _SHA.fullmatch(value[field]):
            raise GauntletError("GAUNTLET_PROPOSAL_INVALID", f"{label} continuity binding is invalid")
    if value["binding_sha256"] != _sha(core):
        raise GauntletError("GAUNTLET_PROPOSAL_TAMPERED", f"{label} continuity binding SHA-256 does not match")
    _text(value.get("purpose_ref"), f"{label} continuity purpose", limit=200)
    records = value.get("records")
    record_fields = {"record_id_sha256", "record_type", "memory_ref_sha256", "purpose_ref", "scope_ref_sha256", "evidence_sha256", "record_sha256", "expires_at"}
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_CONTINUITY_RECORDS:
        raise GauntletError("GAUNTLET_PROPOSAL_INVALID", f"{label} continuity records are invalid")
    record_hashes: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != record_fields:
            raise GauntletError("GAUNTLET_PROPOSAL_INVALID", f"{label} continuity record is invalid")
        for field in ("record_id_sha256", "memory_ref_sha256", "scope_ref_sha256", "evidence_sha256", "record_sha256"):
            if not isinstance(record.get(field), str) or not _SHA.fullmatch(record[field]):
                raise GauntletError("GAUNTLET_PROPOSAL_INVALID", f"{label} continuity record is invalid")
        _text(record.get("record_type"), f"{label} continuity record type", limit=40)
        _text(record.get("purpose_ref"), f"{label} continuity record purpose", limit=200)
        _timestamp(record.get("expires_at"), f"{label} continuity record expiry")
        record_hashes.add(record["record_id_sha256"])
    if len(record_hashes) != len(records):
        raise GauntletError("GAUNTLET_PROPOSAL_INVALID", f"{label} continuity record ids must be unique")


def _source(root: Path, source_path: Path) -> tuple[dict[str, Any], Path, str, str]:
    source, path, relative, digest = _load_json(root, source_path, "source")
    required = {"schema", "id", "promises"}
    if not required.issubset(source) or set(source) - (required | {"continuity"}) or source.get("schema") != GAUNTLET_SOURCE_SCHEMA:
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"source must contain schema, id, promises, and optional continuity for {GAUNTLET_SOURCE_SCHEMA}")
    promises = source.get("promises")
    if not isinstance(promises, list) or not 1 <= len(promises) <= MAX_PROMISES:
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"promises must contain 1 through {MAX_PROMISES} entries")
    normalized: list[dict[str, Any]] = []
    promise_ids: set[str] = set()
    case_ids: set[str] = set()
    for index, item in enumerate(promises):
        if not isinstance(item, dict) or set(item) != {"id", "statement", "reality_manifest", "sabotage_cases"}:
            raise GauntletError("GAUNTLET_SOURCE_INVALID", f"promises[{index}] must contain exactly id, statement, reality_manifest, and sabotage_cases")
        promise_id = _text(item.get("id"), f"promises[{index}].id", identifier=True)
        if promise_id in promise_ids:
            raise GauntletError("GAUNTLET_SOURCE_INVALID", "promise ids must be unique")
        promise_ids.add(promise_id)
        cases = item.get("sabotage_cases")
        if not isinstance(cases, list) or not 1 <= len(cases) <= len(_RISK_TAGS):
            raise GauntletError("GAUNTLET_SOURCE_INVALID", f"promises[{index}].sabotage_cases must contain 1 through {len(_RISK_TAGS)} entries")
        normalized_cases: list[dict[str, Any]] = []
        for case_index, case in enumerate(cases):
            if not isinstance(case, dict) or set(case) != {"id", "risk_tag", "summary", "e2e_manifest"}:
                raise GauntletError("GAUNTLET_SOURCE_INVALID", f"promises[{index}].sabotage_cases[{case_index}] must contain exactly id, risk_tag, summary, and e2e_manifest")
            case_id = _text(case.get("id"), f"promises[{index}].sabotage_cases[{case_index}].id", identifier=True)
            compound_case_id = f"{promise_id}--{case_id}"
            _compound_identifier(compound_case_id, f"promises[{index}].sabotage_cases[{case_index}].compound_id")
            if compound_case_id in case_ids:
                raise GauntletError("GAUNTLET_SOURCE_INVALID", "promise/case ids must be unique")
            case_ids.add(compound_case_id)
            risk_tag = case.get("risk_tag")
            if risk_tag not in _RISK_TAGS:
                raise GauntletError("GAUNTLET_SOURCE_INVALID", f"promises[{index}].sabotage_cases[{case_index}].risk_tag is unsupported")
            normalized_cases.append({
                "id": case_id,
                "risk_tag": risk_tag,
                "summary": _text(case.get("summary"), f"promises[{index}].sabotage_cases[{case_index}].summary"),
                "e2e_manifest": _relative_text(root, case.get("e2e_manifest"), f"promises[{index}].sabotage_cases[{case_index}].e2e_manifest").as_posix(),
            })
        statement = _text(item.get("statement"), f"promises[{index}].statement")
        normalized.append({
            "id": promise_id,
            "statement": _clear_intent(statement, f"promises[{index}].statement"),
            "reality_manifest": _relative_text(root, item.get("reality_manifest"), f"promises[{index}].reality_manifest").as_posix(),
            "sabotage_cases": sorted(normalized_cases, key=lambda entry: entry["id"]),
        })
    if len(case_ids) > MAX_CASES:
        raise GauntletError("GAUNTLET_SOURCE_INVALID", f"the source may contain at most {MAX_CASES} sabotage cases")
    return {
        "schema": GAUNTLET_SOURCE_SCHEMA,
        "id": _text(source.get("id"), "id", identifier=True),
        "promises": sorted(normalized, key=lambda entry: entry["id"]),
        "continuity": _continuity_binding(root, source.get("continuity")),
    }, path, relative, digest


def _proposal_core(root: Path, source_path: Path) -> dict[str, Any]:
    source, _path, source_relative, source_digest = _source(root, source_path)
    proposals: list[dict[str, Any]] = []
    total_timeout = 0
    for promise in source["promises"]:
        try:
            reality = validate_reality_check_manifest(root, root / promise["reality_manifest"])
        except RealityCheckError as exc:
            raise GauntletError(exc.code, str(exc)) from exc
        for case in promise["sabotage_cases"]:
            try:
                e2e = validate_e2e_proof_manifest(root, root / case["e2e_manifest"])
            except E2EProofError as exc:
                raise GauntletError(exc.code, str(exc)) from exc
            total_timeout += e2e["timeout_seconds"]
            proposals.append({
                "id": f"{promise['id']}--{case['id']}",
                "promise": {"id": promise["id"], "statement": promise["statement"]},
                "reality": {
                    "path": promise["reality_manifest"], "sha256": reality["manifest_sha256"],
                    "promise": reality["behavior"]["promise"], "failure_case": reality["behavior"]["failure_case"],
                },
                "sabotage": {"id": case["id"], "risk_tag": case["risk_tag"], "mutation": _MUTATIONS[case["risk_tag"]], "summary": case["summary"]},
                "e2e": {
                    "path": case["e2e_manifest"], "sha256": e2e["manifest_sha256"], "id": e2e["id"],
                    "approved_by": e2e["approval"]["approved_by"], "timeout_seconds": e2e["timeout_seconds"],
                    "positive_argv": e2e["positive"]["argv"], "negative_argv": e2e["negative"]["argv"],
                },
            })
    if total_timeout > MAX_TOTAL_TIMEOUT_SECONDS:
        raise GauntletError("GAUNTLET_BUDGET_EXCEEDED", f"declared E2E timeouts exceed {MAX_TOTAL_TIMEOUT_SECONDS} seconds")
    return {
        "schema": GAUNTLET_PROPOSAL_SCHEMA,
        "marker": "GAUNTLET_PROPOSAL_COMPILED",
        "source": {"path": source_relative, "sha256": source_digest, "id": source["id"]},
        "continuity": source["continuity"],
        "proposals": sorted(proposals, key=lambda entry: entry["id"]),
        "facts": {"promise_count": len(source["promises"]), "case_count": len(proposals), "declared_timeout_seconds": total_timeout, "risk_tags": sorted({entry["sabotage"]["risk_tag"] for entry in proposals})},
        "authority": dict(_PLANNING_AUTHORITY),
        "scope_limits": [
            "A proposal is an inspectable plan over human-written local E2E argv pairs; it does not generate a command from prose.",
            "Compiling or verifying a proposal does not execute a command, admit a batch, repair source, or claim a promise holds.",
        ],
    }


def compile_gauntlet_proposal(root: Path, source_path: Path) -> dict[str, Any]:
    """Compile declared sabotage cases without executing any command."""
    workspace = Path(root).resolve()
    core = _proposal_core(workspace, source_path)
    return {**core, "proposal_sha256": _sha(core)}


def _proposal(root: Path, proposal_path: Path) -> tuple[dict[str, Any], Path, str]:
    value, resolved, relative, _digest = _load_json(root, proposal_path, "proposal")
    required = {"schema", "marker", "source", "continuity", "proposals", "facts", "authority", "scope_limits", "proposal_sha256"}
    if set(value) != required or value.get("schema") != GAUNTLET_PROPOSAL_SCHEMA or value.get("marker") != "GAUNTLET_PROPOSAL_COMPILED":
        raise GauntletError("GAUNTLET_PROPOSAL_INVALID", "proposal has an unsupported schema or fields")
    core = {key: value[key] for key in required - {"proposal_sha256"}}
    if not isinstance(value.get("proposal_sha256"), str) or not _SHA.fullmatch(value["proposal_sha256"]) or value["proposal_sha256"] != _sha(core):
        raise GauntletError("GAUNTLET_PROPOSAL_TAMPERED", "proposal SHA-256 does not match")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {"path", "sha256", "id"} or not isinstance(source.get("sha256"), str) or not _SHA.fullmatch(source["sha256"]):
        raise GauntletError("GAUNTLET_PROPOSAL_INVALID", "proposal source binding is invalid")
    _validate_continuity_binding(value.get("continuity"), "proposal")
    return value, resolved, relative


def verify_gauntlet_proposal(root: Path, proposal_path: Path) -> dict[str, Any]:
    """Fail closed when any declared source, intent, or E2E command binding drifted."""
    workspace = Path(root).resolve()
    value, _resolved, relative = _proposal(workspace, proposal_path)
    try:
        current = compile_gauntlet_proposal(workspace, workspace / value["source"]["path"])
    except GauntletError as exc:
        return {"schema": GAUNTLET_PROPOSAL_SCHEMA, "marker": "GAUNTLET_PROPOSAL_STALE", "ok": False, "proposal_path": relative, "reason": exc.code}
    expected = {key: value[key] for key in value}
    if current != expected:
        return {"schema": GAUNTLET_PROPOSAL_SCHEMA, "marker": "GAUNTLET_PROPOSAL_STALE", "ok": False, "proposal_path": relative, "reason": "source_or_e2e_binding_changed"}
    return {"schema": GAUNTLET_PROPOSAL_SCHEMA, "marker": "GAUNTLET_PROPOSAL_VERIFIED", "ok": True, "proposal_path": relative, "proposal_sha256": value["proposal_sha256"], "facts": value["facts"], "authority": dict(_PLANNING_AUTHORITY)}


def _atomic(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = _canonical(payload) + b"\n"
    if path.exists():
        if path.read_bytes() == content:
            return path
        raise GauntletError("GAUNTLET_ARTIFACT_EXISTS", f"a different artifact already exists at {path}")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(content)
    os.replace(temporary, path)
    return path


def write_gauntlet_proposal(root: Path, proposal: dict[str, Any], out: Path | None = None) -> Path:
    """Write a proposal under an explicit or canonical local artifact path."""
    workspace = Path(root).resolve()
    if not isinstance(proposal, dict) or proposal.get("schema") != GAUNTLET_PROPOSAL_SCHEMA:
        raise GauntletError("GAUNTLET_PROPOSAL_INVALID", "a compiled Gauntlet proposal is required")
    source = proposal.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("id"), str) or not isinstance(proposal.get("proposal_sha256"), str):
        raise GauntletError("GAUNTLET_PROPOSAL_INVALID", "proposal source or digest is invalid")
    target = Path(out) if out is not None else workspace / ".factory" / "gauntlets" / source["id"] / f"{proposal['proposal_sha256']}.proposal.json"
    resolved, _relative_path = _inside(workspace, target, "proposal output", exists=False)
    return _atomic(resolved, proposal)


def _admission_core(proposal: dict[str, Any], proposal_relative: str, approved_by: str, rationale: str, expires_at: datetime) -> dict[str, Any]:
    now = _now()
    return {
        "schema": GAUNTLET_ADMISSION_SCHEMA,
        "marker": "GAUNTLET_ADMISSION_SEALED",
        "proposal": {"path": proposal_relative, "sha256": proposal["proposal_sha256"], "source_id": proposal["source"]["id"]},
        "approved_by": approved_by,
        "rationale": rationale,
        "issued_at": _iso(now),
        "expires_at": _iso(expires_at),
        "authority": dict(_PLANNING_AUTHORITY),
        "scope_limits": [
            "Admission authorizes at most one separately requested local Gauntlet run for the exact current proposal.",
            "Admission does not execute a command, repair code, merge, publish, deploy, sign, send a message, access credentials, or call a connector.",
        ],
    }


def admit_gauntlet(root: Path, proposal_path: Path, *, approved_by: str, rationale: str, confirmation: str, valid_for_minutes: int = 30, out: Path | None = None) -> dict[str, Any]:
    """Seal a single named, expiry-bound admission without running the proposal."""
    workspace = Path(root).resolve()
    verification = verify_gauntlet_proposal(workspace, proposal_path)
    if not verification["ok"]:
        raise GauntletError("GAUNTLET_PROPOSAL_STALE", "current source and E2E bindings must verify before admission")
    proposal, _path, relative = _proposal(workspace, proposal_path)
    owner = _text(approved_by, "approved_by")
    reason = _text(rationale, "rationale")
    if confirmation != f"ADMIT {proposal['source']['id']}":
        raise GauntletError("GAUNTLET_CONFIRMATION_REQUIRED", f"confirmation must be exactly ADMIT {proposal['source']['id']}")
    if isinstance(valid_for_minutes, bool) or not isinstance(valid_for_minutes, int) or not 1 <= valid_for_minutes <= 60:
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", "valid_for_minutes must be an integer from 1 through 60")
    core = _admission_core(proposal, relative, owner, reason, _now() + timedelta(minutes=valid_for_minutes))
    admission = {**core, "admission_sha256": _sha(core)}
    target = Path(out) if out is not None else workspace / ".factory" / "gauntlets" / proposal["source"]["id"] / f"{admission['admission_sha256']}.admission.json"
    path, _ = _inside(workspace, target, "admission output", exists=False)
    _atomic(path, admission)
    return {**admission, "path": str(path)}


def _admission(root: Path, admission_path: Path) -> tuple[dict[str, Any], Path, str]:
    value, resolved, relative, _digest = _load_json(root, admission_path, "admission")
    required = {"schema", "marker", "proposal", "approved_by", "rationale", "issued_at", "expires_at", "authority", "scope_limits", "admission_sha256"}
    if set(value) != required or value.get("schema") != GAUNTLET_ADMISSION_SCHEMA or value.get("marker") != "GAUNTLET_ADMISSION_SEALED":
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", "admission has an unsupported schema or fields")
    core = {key: value[key] for key in required - {"admission_sha256"}}
    if not isinstance(value.get("admission_sha256"), str) or not _SHA.fullmatch(value["admission_sha256"]) or value["admission_sha256"] != _sha(core):
        raise GauntletError("GAUNTLET_ADMISSION_TAMPERED", "admission SHA-256 does not match")
    if value.get("authority") != _PLANNING_AUTHORITY:
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", "admission authority boundary changed")
    proposal = value.get("proposal")
    if not isinstance(proposal, dict) or set(proposal) != {"path", "sha256", "source_id"} or not isinstance(proposal.get("sha256"), str) or not _SHA.fullmatch(proposal["sha256"]):
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", "admission proposal binding is invalid")
    _text(value.get("approved_by"), "approved_by")
    _text(value.get("rationale"), "rationale")
    issued_at, expires_at = _timestamp(value.get("issued_at"), "issued_at"), _timestamp(value.get("expires_at"), "expires_at")
    if expires_at <= issued_at or expires_at > issued_at + timedelta(minutes=60):
        raise GauntletError("GAUNTLET_ADMISSION_INVALID", "admission expiry must be after issue and at most sixty minutes later")
    return value, resolved, relative


def verify_gauntlet_admission(root: Path, admission_path: Path, proposal_path: Path | None = None) -> dict[str, Any]:
    """Verify a named admission is intact, current, matched, and unexpired."""
    workspace = Path(root).resolve()
    admission, _path, relative = _admission(workspace, admission_path)
    bound_proposal = Path(admission["proposal"]["path"])
    if proposal_path is not None:
        requested, requested_relative = _inside(workspace, proposal_path, "proposal")
        if requested_relative != admission["proposal"]["path"]:
            return {"schema": GAUNTLET_ADMISSION_SCHEMA, "marker": "GAUNTLET_ADMISSION_MISMATCH", "ok": False, "admission_path": relative}
        bound_proposal = requested
    verification = verify_gauntlet_proposal(workspace, bound_proposal)
    if not verification["ok"] or verification.get("proposal_sha256") != admission["proposal"]["sha256"]:
        return {"schema": GAUNTLET_ADMISSION_SCHEMA, "marker": "GAUNTLET_ADMISSION_STALE", "ok": False, "admission_path": relative}
    if _timestamp(admission["expires_at"], "expires_at") <= _now():
        return {"schema": GAUNTLET_ADMISSION_SCHEMA, "marker": "GAUNTLET_ADMISSION_EXPIRED", "ok": False, "admission_path": relative}
    return {"schema": GAUNTLET_ADMISSION_SCHEMA, "marker": "GAUNTLET_ADMISSION_VERIFIED", "ok": True, "admission_path": relative, "admission_sha256": admission["admission_sha256"], "proposal_sha256": admission["proposal"]["sha256"], "approved_by": admission["approved_by"], "expires_at": admission["expires_at"], "authority": dict(_PLANNING_AUTHORITY)}


def _git_directory(root: Path) -> Path | None:
    """Locate a local Git directory through metadata reads only."""
    dot_git = root / ".git"
    if dot_git.is_dir():
        return dot_git
    try:
        line = dot_git.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not line.startswith("gitdir: "):
        return None
    location = Path(line.removeprefix("gitdir: ").strip())
    location = location if location.is_absolute() else root / location
    return location.resolve() if location.is_dir() else None


def _packed_ref(git_dir: Path, ref: str) -> str | None:
    try:
        for line in (git_dir / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("#", "^")):
                commit, name = line.split(" ", 1)
                if name == ref:
                    return commit
    except (OSError, ValueError):
        return None
    return None


def _commit(root: Path) -> dict[str, str]:
    git_dir = _git_directory(root)
    if git_dir is None:
        return {"state": "unavailable"}
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return {"state": "unavailable"}
    commit = head
    if head.startswith("ref: "):
        ref = head.removeprefix("ref: ").strip()
        if not ref or Path(ref).is_absolute() or ".." in Path(ref).parts:
            return {"state": "unavailable"}
        try:
            commit = (git_dir / ref).read_text(encoding="utf-8").strip()
        except OSError:
            commit = _packed_ref(git_dir, ref) or ""
    commit = commit.lower()
    return {"state": "bound", "commit": commit} if _COMMIT.fullmatch(commit) else {"state": "unavailable"}


def _case_outcome(proposal: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    public = public_e2e_proof_receipt(receipt)
    if public["marker"] == "E2E_PROOF_PASS":
        status = "survived"
    elif public["marker"] == "HOLLOW_E2E_TEST":
        status = "hollow"
    else:
        status = "blocked"
    return {"proposal_id": proposal["id"], "promise": proposal["promise"], "reality": proposal["reality"], "sabotage": proposal["sabotage"], "e2e": {"path": proposal["e2e"]["path"], "sha256": proposal["e2e"]["sha256"], "id": proposal["e2e"]["id"]}, "status": status, "e2e_receipt": public}


def _card_marker(outcomes: list[dict[str, Any]]) -> tuple[str, bool]:
    statuses = {entry["status"] for entry in outcomes}
    if "hollow" in statuses:
        return "GAUNTLET_HOLLOW", False
    if "blocked" in statuses:
        return "GAUNTLET_BLOCKED", False
    return "GAUNTLET_SURVIVED", True


def _card_markdown(card: dict[str, Any]) -> str:
    summary = card["summary"]
    return "\n".join([
        "# Code Factory Survival Card", "", f"- Card: `{card['card_id']}`", f"- Result: `{card['marker']}`",
        f"- Survived: `{summary['survived_count']}/{summary['case_count']}`", f"- Hollow: `{summary['hollow_count']}`",
        f"- Blocked: `{summary['blocked_count']}`", f"- Unproven promises: `{summary['unproven_promise_count']}`",
        f"- Card SHA-256: `{card['card_sha256']}`", "", "**Do not trust the badge alone — verify the card.**", "",
        "This card proves only the recorded caller-approved local E2E command outcomes. It does not certify production readiness, security, coverage, quality, performance, release readiness, or a deployment.", "",
    ])


def _card_svg(card: dict[str, Any]) -> str:
    summary = card["summary"]
    color = "#177245" if card["ok"] else "#a74713" if card["marker"] == "GAUNTLET_HOLLOW" else "#a17b12"
    title = "SURVIVED" if card["ok"] else "HOLLOW CHECK" if card["marker"] == "GAUNTLET_HOLLOW" else "BLOCKED"
    lines = [title, f"{summary['survived_count']}/{summary['case_count']} declared sabotages survived", f"{summary['unproven_promise_count']} promise(s) unproven", f"verify: factory gauntlet card verify <card>"]
    text = "".join(f'<text x="36" y="{74 + index * 31}" fill="#eff8f1" font-family="Arial, sans-serif" font-size="{28 if index == 0 else 18}" font-weight="{700 if index == 0 else 400}">{html.escape(line)}</text>' for index, line in enumerate(lines))
    return f'<svg xmlns="http://www.w3.org/2000/svg" width="840" height="240" viewBox="0 0 840 240" role="img" aria-label="Code Factory Survival Card {html.escape(title)}"><rect width="840" height="240" rx="24" fill="#0b1721"/><rect width="12" height="240" rx="6" fill="{color}"/>{text}</svg>\n'


def _card_core(proposal: dict[str, Any], proposal_relative: str, admission: dict[str, Any], admission_relative: str, outcomes: list[dict[str, Any]], root: Path) -> dict[str, Any]:
    marker, ok = _card_marker(outcomes)
    unproven = sorted({outcome["promise"]["id"] for outcome in outcomes if outcome["status"] != "survived"})
    return {
        "schema": SURVIVAL_CARD_SCHEMA,
        "marker": marker,
        "ok": ok,
        "card_id": f"card-{proposal['proposal_sha256'][:24]}",
        "source": proposal["source"],
        "continuity": proposal["continuity"],
        "proposal": {"path": proposal_relative, "sha256": proposal["proposal_sha256"]},
        "admission": {"path": admission_relative, "sha256": admission["admission_sha256"], "approved_by": admission["approved_by"]},
        "commit": _commit(root),
        "outcomes": outcomes,
        "summary": {
            "case_count": len(outcomes), "survived_count": sum(item["status"] == "survived" for item in outcomes),
            "hollow_count": sum(item["status"] == "hollow" for item in outcomes), "blocked_count": sum(item["status"] == "blocked" for item in outcomes),
            "unproven_promise_count": len(unproven),
        },
        "unproven_promises": unproven,
        "authority": dict(_RUN_AUTHORITY),
        "scope_limits": [
            "The Gauntlet executes only declared caller-approved local E2E argv pairs through the existing shell=False gate.",
            "A card records only the supplied command outcomes; it does not establish production readiness, security, coverage, quality, performance, or a release decision.",
            "The Gauntlet cannot repair, approve, merge, publish, deploy, sign, message, access credentials, or call a connector.",
        ],
    }


def _card_from_core(core: dict[str, Any]) -> dict[str, Any]:
    card = {**core, "card_sha256": _sha(core)}
    card["card_markdown"] = _card_markdown(card)
    card["card_svg"] = _card_svg(card)
    return card


def _card_path(root: Path, card: dict[str, Any], out: Path | None) -> Path:
    target = Path(out) if out is not None else root / ".factory" / "gauntlets" / card["source"]["id"] / f"{card['card_sha256']}.card.json"
    path, _ = _inside(root, target, "card output", exists=False)
    return path


def _admission_already_consumed(root: Path, admission_sha256: str) -> bool:
    for path in (root / ".factory" / "gauntlets").glob("*/*.card.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and isinstance(value.get("admission"), dict) and value["admission"].get("sha256") == admission_sha256:
            return True
    return False


def _claim_admission(root: Path, source_id: str, admission_sha256: str) -> Path:
    """Atomically reserve an approved batch so it cannot be executed twice concurrently."""
    directory = root / ".factory" / "gauntlets" / source_id
    directory.mkdir(parents=True, exist_ok=True)
    lock = directory / f"{admission_sha256}.run.lock"
    try:
        with lock.open("x", encoding="utf-8") as handle:
            handle.write(admission_sha256 + "\n")
    except FileExistsError as exc:
        raise GauntletError("GAUNTLET_ADMISSION_CONSUMED", "this admission has already reserved or completed its one allowed run") from exc
    return lock


def run_gauntlet(root: Path, proposal_path: Path, admission_path: Path | None, out: Path | None = None) -> dict[str, Any]:
    """Run one current, human-admitted batch and write its public Survival Card."""
    workspace = Path(root).resolve()
    proposal_verification = verify_gauntlet_proposal(workspace, proposal_path)
    if not proposal_verification["ok"]:
        raise GauntletError("GAUNTLET_PROPOSAL_STALE", "the source and declared E2E bindings must verify before execution")
    if admission_path is None:
        raise GauntletError("GAUNTLET_ADMISSION_REQUIRED", "a current named admission receipt is required before execution")
    admission_verification = verify_gauntlet_admission(workspace, admission_path, proposal_path)
    if not admission_verification["ok"]:
        raise GauntletError(admission_verification["marker"], "a current, unexpired admission receipt is required before execution")
    proposal, _proposal_resolved, proposal_relative = _proposal(workspace, proposal_path)
    admission, _admission_resolved, admission_relative = _admission(workspace, admission_path)
    if _admission_already_consumed(workspace, admission["admission_sha256"]):
        raise GauntletError("GAUNTLET_ADMISSION_CONSUMED", "this admission has already completed its one allowed run")
    lock = _claim_admission(workspace, proposal["source"]["id"], admission["admission_sha256"])
    try:
        outcomes: list[dict[str, Any]] = []
        for entry in proposal["proposals"]:
            try:
                receipt = verify_e2e_proof(workspace, workspace / entry["e2e"]["path"])
            except E2EProofError as exc:
                raise GauntletError(exc.code, str(exc)) from exc
            outcomes.append(_case_outcome(entry, receipt))
        card = _card_from_core(_card_core(proposal, proposal_relative, admission, admission_relative, outcomes, workspace))
        path = _card_path(workspace, card, out)
        _atomic(path, card)
        artifacts = write_survival_card_artifacts(card, path.parent)
    except Exception:
        lock.unlink(missing_ok=True)
        raise
    return {"card": card, "path": str(path), "artifacts": artifacts}


def _load_card(card_path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(card_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GauntletError("SURVIVAL_CARD_INVALID", f"card must be readable UTF-8 JSON: {exc}") from exc
    return validate_survival_card(value)


_CARD_FIELDS = {"schema", "marker", "ok", "card_id", "source", "continuity", "proposal", "admission", "commit", "outcomes", "summary", "unproven_promises", "authority", "scope_limits", "card_sha256", "card_markdown", "card_svg"}


def _hash_binding(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise GauntletError("SURVIVAL_CARD_INVALID", f"card {label} binding is invalid")
    digest = value.get("sha256")
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise GauntletError("SURVIVAL_CARD_INVALID", f"card {label} binding is invalid")
    return value


def _validate_card_bindings(card: dict[str, Any]) -> None:
    source = _hash_binding(card.get("source"), {"path", "sha256", "id"}, "source")
    _text(source.get("id"), "card source id", identifier=True)
    _validate_continuity_binding(card.get("continuity"), "card")
    _hash_binding(card.get("proposal"), {"path", "sha256"}, "proposal")
    admission = _hash_binding(card.get("admission"), {"path", "sha256", "approved_by"}, "admission")
    _text(admission.get("approved_by"), "card admission approved_by")


def _validate_commit_binding(value: object) -> None:
    if not isinstance(value, dict):
        raise GauntletError("SURVIVAL_CARD_INVALID", "card commit binding is invalid")
    if value.get("state") == "unavailable" and set(value) == {"state"}:
        return
    if value.get("state") == "bound" and set(value) == {"state", "commit"} and isinstance(value.get("commit"), str) and _COMMIT.fullmatch(value["commit"]):
        return
    raise GauntletError("SURVIVAL_CARD_INVALID", "card commit binding is invalid")


def _validate_card_envelope(card: object) -> dict[str, Any]:
    if not isinstance(card, dict) or set(card) != _CARD_FIELDS or card.get("schema") != SURVIVAL_CARD_SCHEMA:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card has an unsupported schema or fields")
    core = {key: card[key] for key in _CARD_FIELDS - {"card_sha256", "card_markdown", "card_svg"}}
    if not isinstance(card.get("card_sha256"), str) or not _SHA.fullmatch(card["card_sha256"]) or card["card_sha256"] != _sha(core):
        raise GauntletError("SURVIVAL_CARD_INVALID", "card SHA-256 does not match")
    if card.get("authority") != _RUN_AUTHORITY:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card authority boundary changed")
    _text(card.get("card_id"), "card_id", identifier=True)
    _validate_card_bindings(card)
    _validate_commit_binding(card.get("commit"))
    return card


def _validate_outcome(outcome: object) -> tuple[str, str]:
    fields = {"proposal_id", "promise", "reality", "sabotage", "e2e", "status", "e2e_receipt"}
    if not isinstance(outcome, dict) or set(outcome) != fields:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcome has unsupported fields")
    proposal_id = _compound_identifier(outcome.get("proposal_id"), "outcome proposal_id")
    promise = outcome.get("promise")
    if not isinstance(promise, dict) or set(promise) != {"id", "statement"}:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcome promise is invalid")
    promise_id = _text(promise.get("id"), "outcome promise id", identifier=True)
    promise_statement = _clear_intent(_text(promise.get("statement"), "outcome promise statement"), "outcome promise statement")
    if not proposal_id.startswith(f"{promise_id}--"):
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcome promise id is not bound to its proposal id")
    reality = _hash_binding(outcome.get("reality"), {"path", "sha256", "promise", "failure_case"}, "outcome Reality Check")
    if reality["promise"] != promise_statement:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcome promise differs from its Reality Check promise")
    _clear_intent(reality["promise"], "outcome Reality Check promise")
    _clear_intent(reality["failure_case"], "outcome Reality Check failure_case")
    sabotage = outcome.get("sabotage")
    if not isinstance(sabotage, dict) or set(sabotage) != {"id", "risk_tag", "mutation", "summary"} or sabotage.get("risk_tag") not in _RISK_TAGS or sabotage.get("mutation") != _MUTATIONS[sabotage["risk_tag"]]:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcome sabotage is invalid")
    _text(sabotage.get("id"), "outcome sabotage id", identifier=True)
    _text(sabotage.get("summary"), "outcome sabotage summary")
    e2e = _hash_binding(outcome.get("e2e"), {"path", "sha256", "id"}, "outcome E2E")
    _text(e2e.get("id"), "outcome E2E id", identifier=True)
    try:
        receipt = validate_e2e_proof_receipt(outcome.get("e2e_receipt"))
    except E2EProofError as exc:
        raise GauntletError("SURVIVAL_CARD_INVALID", str(exc)) from exc
    status = "survived" if receipt["marker"] == "E2E_PROOF_PASS" else "hollow" if receipt["marker"] == "HOLLOW_E2E_TEST" else "blocked"
    if outcome.get("status") != status or receipt["manifest"]["manifest_sha256"] != e2e["sha256"] or receipt["manifest"]["id"] != e2e["id"]:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcome does not match its E2E receipt")
    return proposal_id, status


def _validated_outcomes(card: dict[str, Any]) -> list[str]:
    outcomes = card.get("outcomes")
    if not isinstance(outcomes, list) or not outcomes or len(outcomes) > MAX_CASES:
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcomes must contain 1 through the case limit")
    validated = [_validate_outcome(outcome) for outcome in outcomes]
    if len({proposal_id for proposal_id, _status in validated}) != len(validated):
        raise GauntletError("SURVIVAL_CARD_INVALID", "card outcome proposal ids must be unique")
    return [status for _proposal_id, status in validated]


def _validate_card_summary(card: dict[str, Any], statuses: list[str]) -> None:
    outcomes = card["outcomes"]
    marker, ok = _card_marker(outcomes)
    unproven = sorted({entry["promise"]["id"] for entry in outcomes if entry["status"] != "survived"})
    summary = {"case_count": len(outcomes), "survived_count": statuses.count("survived"), "hollow_count": statuses.count("hollow"), "blocked_count": statuses.count("blocked"), "unproven_promise_count": len(unproven)}
    if (card.get("marker"), card.get("ok"), card.get("summary"), card.get("unproven_promises")) != (marker, ok, summary, unproven):
        raise GauntletError("SURVIVAL_CARD_INVALID", "card result summary does not match outcomes")


def _validate_card_views(card: dict[str, Any]) -> None:
    if card.get("card_markdown") != _card_markdown(card) or card.get("card_svg") != _card_svg(card):
        raise GauntletError("SURVIVAL_CARD_INVALID", "card views do not match card facts")


def validate_survival_card(value: object) -> dict[str, Any]:
    """Verify card semantics, canonical bytes, deterministic views, and embedded E2E receipts."""
    card = _validate_card_envelope(value)
    statuses = _validated_outcomes(card)
    _validate_card_summary(card, statuses)
    _validate_card_views(card)
    return card


def write_survival_card_artifacts(card: dict[str, Any], out_dir: Path) -> dict[str, str]:
    """Render deterministic JSON, Markdown, and SVG views for one verified card."""
    card = validate_survival_card(card)
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"survival-card-{card['card_sha256'][:12]}"
    paths = {"json": destination / f"{stem}.json", "markdown": destination / f"{stem}.md", "svg": destination / f"{stem}.svg"}
    for name, path in paths.items():
        content = _canonical(card) + b"\n" if name == "json" else card["card_markdown"].encode("utf-8") if name == "markdown" else card["card_svg"].encode("utf-8")
        if path.exists() and path.read_bytes() != content:
            raise GauntletError("GAUNTLET_ARTIFACT_EXISTS", f"a different card artifact already exists at {path}")
        if not path.exists():
            temporary = path.with_name(f".{path.name}.tmp")
            temporary.write_bytes(content)
            os.replace(temporary, path)
    return {name: str(path) for name, path in paths.items()}


def verify_survival_card(card_path: Path, *, envelope_path: Path | None = None, trust_root_path: Path | None = None) -> dict[str, Any]:
    """Verify a card locally and, when supplied, its exact offline DSSE binding."""
    card = _load_card(card_path)
    result: dict[str, Any] = {"schema": SURVIVAL_CARD_SCHEMA, "marker": "SURVIVAL_CARD_VERIFIED", "ok": True, "card_sha256": card["card_sha256"], "signature": "not_supplied"}
    if (envelope_path is None) != (trust_root_path is None):
        raise GauntletError("SURVIVAL_CARD_SIGNATURE_INPUT_INVALID", "supply both envelope_path and trust_root_path or neither")
    if envelope_path is not None and trust_root_path is not None:
        try:
            from .enterprise_receipts import EnterpriseReceiptError, verify_receipt_v2
            signed = verify_receipt_v2(Path(envelope_path), Path(trust_root_path))
        except (ImportError, OSError, EnterpriseReceiptError) as exc:
            raise GauntletError("SURVIVAL_CARD_SIGNATURE_INVALID", str(exc)) from exc
        envelope = json.loads(Path(envelope_path).read_text(encoding="utf-8"))
        import base64
        payload_bytes = base64.urlsafe_b64decode((envelope["payload"] + "=" * (-len(envelope["payload"]) % 4)).encode("ascii"))
        payload = json.loads(payload_bytes.decode("utf-8"))
        if payload.get("subject_sha256") != card["card_sha256"]:
            raise GauntletError("SURVIVAL_CARD_SIGNATURE_INVALID", "Receipt v2 subject_sha256 does not bind this card")
        result["signature"] = {"verdict": signed["verdict"], "verification": signed["verification"], "identity": signed["identity"], "issuer": signed["issuer"]}
    return result


def seal_survival_card(card_path: Path, *, private_key_path: Path, keyid: str, identity: str, issuer: str, tenant_id: str, out: Path) -> dict[str, Any]:
    """Create an optional DSSE Receipt v2 that binds exactly one existing card."""
    card = _load_card(card_path)
    try:
        from .enterprise_receipts import EnterpriseReceiptError, seal_receipt_v2
        payload = {
            "schema": "factory.receipt.v2", "module": "gauntlet", "stage": "survival-card",
            "feature": card["card_id"], "ok": card["ok"], "tenant_id": _text(tenant_id, "tenant_id", identifier=True),
            "run_id": card["card_sha256"][:32], "ts": _iso(_now()), "subject_sha256": card["card_sha256"],
        }
        envelope = seal_receipt_v2(payload, Path(private_key_path), _text(keyid, "keyid", identifier=True), _text(identity, "identity"), _text(issuer, "issuer"), Path(out))
    except (ImportError, OSError, EnterpriseReceiptError) as exc:
        raise GauntletError("SURVIVAL_CARD_SIGNING_FAILED", str(exc)) from exc
    return {"schema": SURVIVAL_CARD_SCHEMA, "marker": "SURVIVAL_CARD_SEALED", "card_sha256": card["card_sha256"], "path": str(Path(out).resolve()), "payload_sha256": envelope["payload_sha256"], "authority": {"signing": True, "publication": False, "deployment": False, "messaging": False, "credential": False, "connector": False}}


def challenge_survival_card(card_path: Path) -> dict[str, Any]:
    """Prove the verifier rejects a changed summary without mutating the original card."""
    card = _load_card(card_path)
    mutant = json.loads(json.dumps(card))
    mutant["summary"]["survived_count"] = mutant["summary"]["survived_count"] + 1
    try:
        validate_survival_card(mutant)
    except GauntletError:
        return {"schema": SURVIVAL_CARD_SCHEMA, "marker": "GAUNTLET_CARD_MUTATION_REJECTED", "ok": True, "card_sha256": card["card_sha256"], "mutations": 1}
    return {"schema": SURVIVAL_CARD_SCHEMA, "marker": "HOLLOW_SURVIVAL_CARD_VERIFIER", "ok": False, "card_sha256": card["card_sha256"], "mutations": 1}


def _continuity_status(binding: dict[str, Any] | None) -> dict[str, Any]:
    if binding is None:
        return {"bound": False, "marker": "GAUNTLET_CONTINUITY_NOT_BOUND", "record_count": 0}
    return {
        "bound": True,
        "marker": binding["marker"],
        "record_count": len(binding["records"]),
        "binding_sha256": binding["binding_sha256"],
    }


def gauntlet_status(root: Path, source_id: str | None = None) -> dict[str, Any]:
    """Read bounded current Survival Card facts without running or verifying a command."""
    workspace = Path(root).resolve()
    if source_id is not None:
        _text(source_id, "source_id", identifier=True)
    entries: list[dict[str, Any]] = []
    for path in sorted((workspace / ".factory" / "gauntlets").glob("*/*.card.json")):
        try:
            card = _load_card(path)
        except GauntletError as exc:
            entries.append({"path": path.relative_to(workspace).as_posix(), "valid": False, "marker": exc.code})
            continue
        if source_id is not None and card["source"]["id"] != source_id:
            continue
        entries.append({"path": path.relative_to(workspace).as_posix(), "valid": True, "source_id": card["source"]["id"], "marker": card["marker"], "card_sha256": card["card_sha256"], "summary": card["summary"], "continuity": _continuity_status(card["continuity"]), "commit": card["commit"]})
    return {"schema": SURVIVAL_CARD_SCHEMA, "marker": "GAUNTLET_STATUS_READ_ONLY", "source_id": source_id, "entries": entries, "authority": dict(_PLANNING_AUTHORITY), "scope_limits": ["Status is a local projection. It does not execute, admit, sign, repair, or promote a Gauntlet result."]}

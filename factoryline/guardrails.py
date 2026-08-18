"""Continuity-backed guardrail evaluation without memory-content retrieval."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .continuity import ContinuityError, ContinuityPrincipal, _is_expired, recall_continuity_metadata_read_only


GUARDRAIL_MANIFEST_SCHEMA = "factory.guardrail-manifest.v1"
GUARDRAIL_EVALUATION_SCHEMA = "factory.guardrail-evaluation.v1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_RISK_TAGS = frozenset({"boundary", "authorization", "idempotency", "temporal", "state", "validation"})


class GuardrailError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _text(value: object, field: str, *, limit: int = 160, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"{field} must be a non-empty string of at most {limit} characters")
    result = value.strip()
    if identifier and not _IDENTIFIER.fullmatch(result):
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"{field} has an unsupported identifier")
    return result


def _path(value: object, field: str) -> str:
    result = _text(value, field, limit=240)
    raw = result.replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) or ".." in raw.split("/"):
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"{field} must be a workspace-relative prefix")
    return raw.rstrip("/") or "."


def _validate_guardrail(item: object, index: int, seen: set[str]) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != {"id", "record_id", "path_prefixes", "required_risk_tags"}:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"guardrails[{index}] must contain exactly id, record_id, path_prefixes, and required_risk_tags")
    identifier = _text(item.get("id"), f"guardrails[{index}].id", limit=96, identifier=True)
    if identifier in seen:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", "guardrail ids must be unique")
    seen.add(identifier)
    prefixes = item.get("path_prefixes")
    if not isinstance(prefixes, list) or not 1 <= len(prefixes) <= 16:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"guardrails[{index}].path_prefixes must contain 1 through 16 entries")
    tags = item.get("required_risk_tags")
    if not isinstance(tags, list) or not 1 <= len(tags) <= 6:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"guardrails[{index}].required_risk_tags must contain supported tags")
    if any(not isinstance(tag, str) or tag not in _RISK_TAGS for tag in tags):
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"guardrails[{index}].required_risk_tags must contain supported tags")
    return {
        "id": identifier,
        "record_id": _text(item.get("record_id"), f"guardrails[{index}].record_id", limit=96, identifier=True),
        "path_prefixes": sorted({_path(path, f"guardrails[{index}].path_prefixes") for path in prefixes}),
        "required_risk_tags": sorted(set(tags)),
    }


def validate_guardrail_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema", "id", "tenant_id", "purpose", "scope", "guardrails"}:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", "manifest must contain exactly schema, id, tenant_id, purpose, scope, and guardrails")
    if value.get("schema") != GUARDRAIL_MANIFEST_SCHEMA:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", f"schema must be {GUARDRAIL_MANIFEST_SCHEMA}")
    guardrails = value.get("guardrails")
    if not isinstance(guardrails, list) or not 1 <= len(guardrails) <= 64:
        raise GuardrailError("GUARDRAIL_MANIFEST_INVALID", "guardrails must contain 1 through 64 entries")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(guardrails):
        normalized.append(_validate_guardrail(item, index, seen))
    return {"schema": GUARDRAIL_MANIFEST_SCHEMA, "id": _text(value.get("id"), "id", limit=96, identifier=True), "tenant_id": _text(value.get("tenant_id"), "tenant_id"), "purpose": _text(value.get("purpose"), "purpose"), "scope": _text(value.get("scope"), "scope", limit=240), "guardrails": sorted(normalized, key=lambda item: item["id"])}


def _load(path: Path) -> tuple[dict[str, Any], str]:
    try:
        raw = Path(path).read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuardrailError("GUARDRAIL_MANIFEST_UNREADABLE", f"manifest cannot be read as UTF-8 JSON: {exc}") from exc
    return validate_guardrail_manifest(value), sha256(raw).hexdigest()


def _match(prefix: str, path: str) -> bool:
    return prefix == "." or path == prefix or path.startswith(prefix + "/")


def _changed_paths(value: object) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        raise GuardrailError("GUARDRAIL_PATHS_INVALID", "changed_paths must contain 1 through 256 workspace-relative paths")
    return sorted({_path(path, "changed_paths") for path in value})


def _recalled_records(manifest: dict[str, Any], db_path: Path, principal: ContinuityPrincipal) -> dict[str, dict[str, Any]]:
    try:
        recalled = recall_continuity_metadata_read_only(
            Path(db_path), principal, manifest["tenant_id"], purpose_ref=manifest["purpose"], scope_ref=manifest["scope"],
        )
    except ContinuityError as exc:
        code = "GUARDRAIL_CONTINUITY_UNAVAILABLE" if exc.code == "E_CONTINUITY_UNAVAILABLE" else exc.code
        raise GuardrailError(code, str(exc)) from exc
    return {record["record_id"]: record for record in recalled["records"]}


def _guardrail_row(guardrail: dict[str, Any], paths: list[str], records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    record = records.get(guardrail["record_id"])
    matched_paths = [path for path in paths if any(_match(prefix, path) for prefix in guardrail["path_prefixes"])]
    eligible = record is not None and record.get("status") == "verified" and not _is_expired(str(record.get("expires_at", "")))
    status = "active" if eligible and matched_paths else "inactive" if eligible else "withheld"
    provenance = None if record is None else {"record_id": record["record_id"], "record_type": record["record_type"], "evidence_sha256": record["evidence_sha256"], "expires_at": record["expires_at"], "promotion": "independently_promoted"}
    return {"id": guardrail["id"], "status": status, "matched_paths": matched_paths, "required_risk_tags": guardrail["required_risk_tags"], "record": provenance, "withheld_reason": None if eligible else "GUARDRAIL_WITHHELD"}


def evaluate_guardrails(manifest_path: Path, db_path: Path, principal: ContinuityPrincipal, *, changed_paths: list[str]) -> dict[str, Any]:
    manifest, manifest_sha256 = _load(manifest_path)
    paths = _changed_paths(changed_paths)
    if principal.tenant_id != manifest["tenant_id"]:
        raise GuardrailError("GUARDRAIL_TENANT_BOUNDARY", "principal tenant must match guardrail manifest tenant")
    # This uses a SQLite read-only URI and selects no memory-reference or
    # summary column, so evaluation cannot initialize, migrate, or expose the
    # continuity ledger.
    records = _recalled_records(manifest, db_path, principal)
    rows = [_guardrail_row(guardrail, paths, records) for guardrail in manifest["guardrails"]]
    core = {"schema": GUARDRAIL_EVALUATION_SCHEMA, "marker": "GUARDRAIL_EVALUATED", "manifest": {"id": manifest["id"], "sha256": manifest_sha256}, "changed_paths": paths, "guardrails": rows, "facts": {"active_count": sum(row["status"] == "active" for row in rows), "withheld_count": sum(row["status"] == "withheld" for row in rows)}, "authority": {"memory_content": False, "source_write": False, "execution": False, "promotion": False, "approval": False}, "scope_limits": ["Evaluation reads only independently promoted continuity metadata.", "Memory references and summaries are not returned."]}
    return {**core, "evaluation_sha256": _sha(core)}


def verify_guardrail_evaluation(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != GUARDRAIL_EVALUATION_SCHEMA:
        raise GuardrailError("GUARDRAIL_EVALUATION_INVALID", f"evaluation must use {GUARDRAIL_EVALUATION_SCHEMA}")
    supplied = value.get("evaluation_sha256")
    core = {key: item for key, item in value.items() if key != "evaluation_sha256"}
    if not isinstance(supplied, str) or supplied != _sha(core):
        raise GuardrailError("GUARDRAIL_EVALUATION_TAMPERED", "evaluation hash does not match")
    if any("summary" in json.dumps(row) or "memory_ref" in json.dumps(row) for row in value.get("guardrails", [])):
        raise GuardrailError("GUARDRAIL_REDACTION_FAILED", "evaluation exposed prohibited continuity content")
    return value

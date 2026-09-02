"""Local, fail-closed authority records for Code Factory decision gates.

Oracle Firewall makes the definition of done an inspectable input instead of
an agent-owned by-product.  It only reads and writes bounded workspace
artifacts.  It never runs a harness, changes a candidate, contacts a provider,
or grants an external permission.
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

from .agent_license import normalize_agent_identity
from .protocol_enums import AuthorityOrigin, RuleEffect


HANDOFF_SCHEMA = "factory.intent-handoff.v1"
CONTRACT_INPUT_SCHEMA = "factory.oracle-contract-input.v1"
CONTRACT_SCHEMA = "factory.oracle-contract.v1"
DRIFT_SCHEMA = "factory.oracle-drift.v1"
CHALLENGE_SCHEMA = "factory.oracle-challenge.v1"
CHALLENGE_RESULT_SCHEMA = "factory.oracle-challenge-result.v1"
INCIDENT_SCHEMA = "factory.oracle-incident.v1"
PROJECTION_SCHEMA = "factory.oracle-firewall-projection.v1"
MAX_BYTES = 1_048_576
ORIGINS = AuthorityOrigin.values()
AUTHORITY_ORIGINS = frozenset({AuthorityOrigin.HUMAN_CONFIRMED.value, AuthorityOrigin.TRUSTED_SOURCE.value})
EFFECTS = RuleEffect.values()
RULE_GROUPS = ("requirements", "forbidden_behaviors", "gates", "exceptions", "negative_cases", "invariants", "tests")
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,95}$")
AUTHORITY = {
    "execution": False, "approval": False, "repair": False, "merge": False,
    "publication": False, "deployment": False, "signing": False, "messaging": False,
    "credential": False, "connector": False,
}


class OracleFirewallError(ValueError):
    """Stable local failure with a code suitable for receipts and adapters."""

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


def _text(value: object, field: str, *, limit: int = 800) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise OracleFirewallError("ORACLE_INPUT_INVALID", f"{field} must be a non-empty string up to {limit} characters")
    return result


def _identifier(value: object, field: str) -> str:
    result = _text(value, field, limit=96)
    if not IDENTIFIER.fullmatch(result):
        raise OracleFirewallError("ORACLE_INPUT_INVALID", f"{field} must match {IDENTIFIER.pattern}")
    return result


def _inside(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise OracleFirewallError("ORACLE_PATH_OUT_OF_SCOPE", "all paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise OracleFirewallError("ORACLE_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _relative(root: Path, path: Path) -> str:
    return _inside(root, path).relative_to(Path(root).resolve()).as_posix()


def _read_json(root: Path, path: Path, schema: str | None = None) -> tuple[dict[str, Any], Path]:
    source = _inside(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise OracleFirewallError("ORACLE_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OracleFirewallError("ORACLE_INPUT_INVALID", "input must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or (schema is not None and value.get("schema") != schema):
        raise OracleFirewallError("ORACLE_SCHEMA_REJECTED", f"expected {schema}" if schema else "input must be an object")
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


def _hash_receipt(core: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(core)
    result[field] = _sha(core)
    return result


def _valid_receipt(value: object, schema: str, digest_field: str) -> bool:
    if not isinstance(value, dict) or value.get("schema") != schema:
        return False
    supplied = value.get(digest_field)
    if not isinstance(supplied, str) or len(supplied) != 64:
        return False
    return _sha({key: item for key, item in value.items() if key != digest_field}) == supplied


def _write_new(root: Path, path: Path, payload: dict[str, Any], *, digest_field: str) -> Path:
    target = _inside(root, path, exists=False)
    if target.exists():
        raise OracleFirewallError("ORACLE_OUTPUT_EXISTS", "destination already exists; choose a new immutable artifact path")
    _atomic_json(target, payload)
    return target


def _source_binding(root: Path, source: object, *, index: int) -> dict[str, str]:
    if not isinstance(source, dict):
        raise OracleFirewallError("ORACLE_SOURCE_INVALID", "every source must be an object")
    source_id = _identifier(source.get("id"), f"sources[{index}].id")
    origin = _text(source.get("origin"), f"sources[{index}].origin", limit=64)
    if origin not in ORIGINS:
        raise OracleFirewallError("ORACLE_PROVENANCE_INVALID", f"sources[{index}].origin is unsupported")
    raw = source.get("path")
    if not isinstance(raw, str) or not raw.strip():
        raise OracleFirewallError("ORACLE_SOURCE_INVALID", f"sources[{index}].path is required")
    path = _inside(root, Path(raw))
    return {"id": source_id, "origin": origin, "path": path.relative_to(Path(root).resolve()).as_posix(), "sha256": _file_sha(path)}


def _rule(value: object, group: str, index: int, sources: dict[str, dict[str, str]]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OracleFirewallError("ORACLE_RULE_INVALID", f"{group}[{index}] must be an object")
    rule_id = _identifier(value.get("id"), f"{group}[{index}].id")
    statement = _text(value.get("statement"), f"{group}[{index}].statement")
    origin = _text(value.get("origin"), f"{group}[{index}].origin", limit=64)
    effect = _text(value.get("effect"), f"{group}[{index}].effect", limit=64)
    source_id = _identifier(value.get("source_id"), f"{group}[{index}].source_id")
    if origin not in ORIGINS:
        raise OracleFirewallError("ORACLE_PROVENANCE_INVALID", f"{group}[{index}] has unsupported origin")
    if effect not in EFFECTS:
        raise OracleFirewallError("ORACLE_EFFECT_INVALID", f"{group}[{index}] has unsupported effect")
    if source_id not in sources:
        raise OracleFirewallError("ORACLE_SOURCE_UNBOUND", f"{group}[{index}] names an unavailable source")
    if origin in {"agent_proposed", "observed_production"} and effect != "advisory":
        raise OracleFirewallError("ORACLE_PROVENANCE_INVALID", f"{group}[{index}] may only be advisory for {origin}")
    if effect in {"blocking", "release"} and origin not in AUTHORITY_ORIGINS:
        raise OracleFirewallError("ORACLE_PROVENANCE_INVALID", f"{group}[{index}] lacks human or trusted authority")
    critical = value.get("critical")
    if not isinstance(critical, bool):
        raise OracleFirewallError("ORACLE_RULE_INVALID", f"{group}[{index}].critical must be boolean")
    result: dict[str, Any] = {"id": rule_id, "statement": statement, "origin": origin, "effect": effect, "source_id": source_id, "critical": critical}
    if group == "gates":
        comparator = _text(value.get("comparison"), f"{group}[{index}].comparison", limit=32)
        if comparator not in {"gte", "lte", "equals", "present"}:
            raise OracleFirewallError("ORACLE_GATE_INVALID", f"{group}[{index}].comparison is unsupported")
        if comparator == "present":
            if value.get("value") is not True:
                raise OracleFirewallError("ORACLE_GATE_INVALID", f"{group}[{index}].value must be true for present")
        elif isinstance(value.get("value"), bool) or not isinstance(value.get("value"), (str, int, float)):
            raise OracleFirewallError("ORACLE_GATE_INVALID", f"{group}[{index}].value must be scalar")
        result.update({"comparison": comparator, "value": value.get("value")})
    if group == "tests":
        test_path = value.get("path")
        if not isinstance(test_path, str) or not test_path.strip():
            raise OracleFirewallError("ORACLE_RULE_INVALID", f"{group}[{index}].path is required")
        safe = Path(test_path.replace("\\", "/"))
        if safe.is_absolute() or ".." in safe.parts:
            raise OracleFirewallError("ORACLE_PATH_OUT_OF_SCOPE", f"{group}[{index}].path must be workspace relative")
        result["path"] = safe.as_posix()
    return result


def _rules(value: object, group: str, sources: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 128:
        raise OracleFirewallError("ORACLE_RULE_INVALID", f"{group} must contain 1 through 128 rules")
    result = [_rule(item, group, index, sources) for index, item in enumerate(value)]
    if len({item["id"] for item in result}) != len(result):
        raise OracleFirewallError("ORACLE_RULE_INVALID", f"{group} rule identifiers must be unique")
    return result


def capture_intent_handoff(root: Path, source_path: Path, agent: object, handoff_id: str, out: Path | None = None) -> dict[str, Any]:
    """Capture exact supplied intent bytes before a worker starts a candidate."""
    workspace = Path(root).resolve()
    source = _inside(workspace, Path(source_path))
    raw = source.read_bytes()
    if not raw or len(raw) > MAX_BYTES:
        raise OracleFirewallError("ORACLE_HANDOFF_INPUT_INVALID", "original intent must contain 1 byte through 1 MiB")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OracleFirewallError("ORACLE_HANDOFF_INPUT_INVALID", "original intent must be UTF-8 text") from exc
    identifier = _identifier(handoff_id, "handoff_id")
    identity = normalize_agent_identity(agent, "agent")
    digest = hashlib.sha256(raw).hexdigest()
    stored = workspace / ".factory" / "oracles" / "handoffs" / "sources" / f"{digest}.txt"
    if stored.exists() and stored.read_bytes() != raw:
        raise OracleFirewallError("ORACLE_HANDOFF_COLLISION", "existing original-intent snapshot has different bytes")
    if not stored.exists():
        stored.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{stored.name}.", suffix=".tmp", dir=str(stored.parent))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
            os.replace(temporary, stored)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    core = {
        "schema": HANDOFF_SCHEMA,
        "marker": "ORACLE_HANDOFF_CAPTURED",
        "handoff_id": identifier,
        "captured_at": _now(),
        "handoff_agent": identity,
        "original_intent": {
            "provided_path": source.relative_to(workspace).as_posix(),
            "captured_path": stored.relative_to(workspace).as_posix(),
            "sha256": digest,
            "bytes": len(raw),
        },
        "authority": dict(AUTHORITY),
        "claim_boundary": "Local capture of declared original-intent bytes. The receipt proves stored bytes and declared handoff identity, not a real-world identity or the truthfulness of that declaration.",
    }
    receipt = _hash_receipt(core, "handoff_sha256")
    destination = Path(out) if out is not None else workspace / ".factory" / "oracles" / "handoffs" / f"{identifier}.json"
    path = _write_new(workspace, destination, receipt, digest_field="handoff_sha256")
    return {**receipt, "path": path.relative_to(workspace).as_posix()}


def verify_intent_handoff(root: Path, handoff_path: Path) -> dict[str, Any]:
    """Verify the immutable original-intent snapshot and return only local integrity facts."""
    workspace = Path(root).resolve()
    try:
        value, source = _read_json(workspace, Path(handoff_path), HANDOFF_SCHEMA)
        if not _valid_receipt(value, HANDOFF_SCHEMA, "handoff_sha256"):
            return {"ok": False, "marker": "ORACLE_HANDOFF_INVALID", "reason": "handoff_sha256_mismatch", "authority": dict(AUTHORITY)}
        original = value.get("original_intent")
        if not isinstance(original, dict):
            return {"ok": False, "marker": "ORACLE_HANDOFF_INVALID", "reason": "original_intent_missing", "authority": dict(AUTHORITY)}
        stored = _inside(workspace, Path(_text(original.get("captured_path"), "original_intent.captured_path")))
        if _file_sha(stored) != _text(original.get("sha256"), "original_intent.sha256", limit=64):
            return {"ok": False, "marker": "ORACLE_HANDOFF_INVALID", "reason": "original_intent_sha256_mismatch", "authority": dict(AUTHORITY)}
        return {"ok": True, "marker": "ORACLE_HANDOFF_VALID", "handoff": value, "path": source.relative_to(workspace).as_posix(), "authority": dict(AUTHORITY)}
    except OracleFirewallError as exc:
        return {"ok": False, "marker": "ORACLE_HANDOFF_INVALID", "reason": exc.code, "authority": dict(AUTHORITY)}


def _contract_sources(root: Path, value: dict[str, Any]) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    handoff_raw = value.get("handoff")
    if not isinstance(handoff_raw, str) or not handoff_raw.strip():
        raise OracleFirewallError("ORACLE_HANDOFF_REQUIRED", "handoff must reference a captured original-intent receipt")
    handoff_result = verify_intent_handoff(root, Path(handoff_raw))
    if not handoff_result["ok"]:
        raise OracleFirewallError("ORACLE_HANDOFF_INVALID", f"handoff is not valid: {handoff_result['reason']}")
    handoff = handoff_result["handoff"]
    handoff_source = {"id": "original-intent", "origin": "human_confirmed", "path": handoff_result["path"], "sha256": _file_sha(_inside(root, Path(handoff_result["path"])))}
    raw_sources = value.get("sources", [])
    if not isinstance(raw_sources, list) or len(raw_sources) > 64:
        raise OracleFirewallError("ORACLE_SOURCE_INVALID", "sources must contain at most 64 objects")
    sources = {"original-intent": handoff_source}
    for index, item in enumerate(raw_sources):
        binding = _source_binding(root, item, index=index)
        if binding["id"] in sources:
            raise OracleFirewallError("ORACLE_SOURCE_INVALID", "source identifiers must be unique and may not replace original-intent")
        sources[binding["id"]] = binding
    return sources, handoff


def seal_oracle_contract(root: Path, input_path: Path, out: Path) -> dict[str, Any]:
    """Seal a versioned hash contract from named sources before candidate work."""
    workspace = Path(root).resolve()
    candidate, source = _read_json(workspace, Path(input_path), CONTRACT_INPUT_SCHEMA)
    contract_id = _identifier(candidate.get("id"), "id")
    version = candidate.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1 or version > 100_000:
        raise OracleFirewallError("ORACLE_INPUT_INVALID", "version must be an integer between 1 and 100000")
    approved_by = _text(candidate.get("approved_by"), "approved_by", limit=160)
    approval_rationale = _text(candidate.get("approval_rationale"), "approval_rationale", limit=1000)
    if len(approval_rationale) < 20:
        raise OracleFirewallError("ORACLE_INPUT_INVALID", "approval_rationale must explain the named approval in at least 20 characters")
    raw_scope = candidate.get("scope_paths")
    if not isinstance(raw_scope, list) or not raw_scope or len(raw_scope) > 64:
        raise OracleFirewallError("ORACLE_SCOPE_INVALID", "scope_paths must contain 1 through 64 workspace-relative paths")
    scope_paths: list[str] = []
    for raw in raw_scope:
        if not isinstance(raw, str) or not raw.strip():
            raise OracleFirewallError("ORACLE_SCOPE_INVALID", "scope path must be non-empty")
        path = Path(raw.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise OracleFirewallError("ORACLE_SCOPE_INVALID", "scope paths must be workspace relative")
        scope_paths.append(path.as_posix().rstrip("/") or ".")
    if len(set(scope_paths)) != len(scope_paths):
        raise OracleFirewallError("ORACLE_SCOPE_INVALID", "scope paths must be unique")
    sources, handoff = _contract_sources(workspace, candidate)
    rules = {group: _rules(candidate.get(group), group, sources) for group in RULE_GROUPS}
    for group in ("requirements", "forbidden_behaviors", "gates", "negative_cases", "invariants", "tests"):
        if not any(item["effect"] != "advisory" for item in rules[group]):
            raise OracleFirewallError("ORACLE_AUTHORITY_REQUIRED", f"{group} needs at least one human or trusted blocking/release rule")
    core: dict[str, Any] = {
        "schema": CONTRACT_SCHEMA,
        "marker": "ORACLE_CONTRACT_SEALED",
        "id": contract_id,
        "version": version,
        "sealed_at": _now(),
        "approved_by": approved_by,
        "approval_rationale": approval_rationale,
        "input_sha256": _file_sha(source),
        "scope_paths": sorted(scope_paths),
        "handoff": {
            "path": _relative(workspace, Path(candidate["handoff"])),
            "handoff_sha256": handoff["handoff_sha256"],
            "original_intent": dict(handoff["original_intent"]),
            "handoff_agent": dict(handoff["handoff_agent"]),
        },
        "sources": [sources[key] for key in sorted(sources)],
        "rules": rules,
        "signature": {"state": "hash_sealed", "claim_boundary": "A local SHA-256 seal detects content change. It is not an external signer identity proof without a separately verified receipt signature."},
        "authority": dict(AUTHORITY),
        "claim_boundary": "Local provenance and contract integrity only. It does not prove identity, source trust, implementation correctness, a human decision, or release approval.",
    }
    sealed = _hash_receipt(core, "contract_sha256")
    path = _write_new(workspace, Path(out), sealed, digest_field="contract_sha256")
    return {**sealed, "path": path.relative_to(workspace).as_posix()}


def _verify_sources(root: Path, contract: dict[str, Any]) -> list[dict[str, str]]:
    stale: list[dict[str, str]] = []
    source_list = contract.get("sources")
    if not isinstance(source_list, list):
        return [{"id": "sources", "reason": "missing"}]
    for source in source_list:
        if not isinstance(source, dict):
            stale.append({"id": "unknown", "reason": "invalid"})
            continue
        source_id = str(source.get("id") or "unknown")
        try:
            path = _inside(root, Path(_text(source.get("path"), "source.path")))
            if _file_sha(path) != _text(source.get("sha256"), "source.sha256", limit=64):
                stale.append({"id": source_id, "reason": "sha256_mismatch"})
        except OracleFirewallError as exc:
            stale.append({"id": source_id, "reason": exc.code})
    return stale


def verify_oracle_contract(root: Path, contract_path: Path) -> dict[str, Any]:
    """Verify the contract digest, original handoff, and every bound source."""
    workspace = Path(root).resolve()
    try:
        contract, source = _read_json(workspace, Path(contract_path), CONTRACT_SCHEMA)
        if not _valid_receipt(contract, CONTRACT_SCHEMA, "contract_sha256"):
            return {"ok": False, "marker": "ORACLE_CONTRACT_INVALID", "reason": "contract_sha256_mismatch", "authority": dict(AUTHORITY)}
        handoff = contract.get("handoff")
        if not isinstance(handoff, dict):
            return {"ok": False, "marker": "ORACLE_CONTRACT_INVALID", "reason": "handoff_missing", "authority": dict(AUTHORITY)}
        handoff_result = verify_intent_handoff(workspace, Path(_text(handoff.get("path"), "handoff.path")))
        if not handoff_result["ok"] or handoff_result["handoff"].get("handoff_sha256") != handoff.get("handoff_sha256"):
            return {"ok": False, "marker": "ORACLE_CONTRACT_INVALID", "reason": "handoff_binding_invalid", "authority": dict(AUTHORITY)}
        stale = _verify_sources(workspace, contract)
        if stale:
            return {"ok": False, "marker": "ORACLE_CONTRACT_SOURCE_STALE", "reason": "bound_source_changed", "stale_sources": stale, "contract": contract, "path": source.relative_to(workspace).as_posix(), "authority": dict(AUTHORITY)}
        return {"ok": True, "marker": "ORACLE_CONTRACT_VALID", "contract": contract, "path": source.relative_to(workspace).as_posix(), "authority": dict(AUTHORITY)}
    except OracleFirewallError as exc:
        return {"ok": False, "marker": "ORACLE_CONTRACT_INVALID", "reason": exc.code, "authority": dict(AUTHORITY)}


def _source_justification(contract: dict[str, Any], rule: dict[str, Any] | None) -> dict[str, Any]:
    source_id = rule.get("source_id") if isinstance(rule, dict) else None
    source = next((item for item in contract.get("sources", []) if isinstance(item, dict) and item.get("id") == source_id), None)
    return {
        "approved_by": contract.get("approved_by"),
        "approval_rationale": contract.get("approval_rationale"),
        "source_id": source_id,
        "source": source,
        "rule_origin": rule.get("origin") if isinstance(rule, dict) else None,
    }


def _weakening(previous: dict[str, Any], candidate: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    before = previous.get("rules", {})
    after = candidate.get("rules", {})
    for group in RULE_GROUPS:
        prior_rules = {item["id"]: item for item in before.get(group, []) if isinstance(item, dict)}
        candidate_rules = {item["id"]: item for item in after.get(group, []) if isinstance(item, dict)}
        for rule_id, prior in prior_rules.items():
            if prior.get("effect") == "advisory":
                continue
            later = candidate_rules.get(rule_id)
            if later is None:
                code = "negative_case_removed" if group == "negative_cases" else "required_rule_removed"
                findings.append({"code": code, "group": group, "rule_id": rule_id, "before": prior, "after": None, "justification": _source_justification(candidate, None)})
                continue
            if later.get("effect") == "advisory" and prior.get("effect") != "advisory":
                findings.append({"code": "gate_effect_relaxed", "group": group, "rule_id": rule_id, "before": prior, "after": later, "justification": _source_justification(candidate, later)})
            if prior.get("origin") in AUTHORITY_ORIGINS and later.get("origin") not in AUTHORITY_ORIGINS:
                findings.append({"code": "provenance_downgraded", "group": group, "rule_id": rule_id, "before": prior, "after": later, "justification": _source_justification(candidate, later)})
            if group in {"negative_cases", "tests"} and (prior.get("statement") != later.get("statement") or prior.get("path") != later.get("path")):
                findings.append({"code": "negative_proof_rewritten" if group == "negative_cases" else "test_rewritten", "group": group, "rule_id": rule_id, "before": prior, "after": later, "justification": _source_justification(candidate, later)})
            if group == "gates":
                prior_value, later_value = prior.get("value"), later.get("value")
                comparison = prior.get("comparison")
                if comparison == "gte" and isinstance(prior_value, (int, float)) and isinstance(later_value, (int, float)) and later_value < prior_value:
                    findings.append({"code": "threshold_lowered", "group": group, "rule_id": rule_id, "before": prior, "after": later, "justification": _source_justification(candidate, later)})
                if comparison == "lte" and isinstance(prior_value, (int, float)) and isinstance(later_value, (int, float)) and later_value > prior_value:
                    findings.append({"code": "tolerance_widened", "group": group, "rule_id": rule_id, "before": prior, "after": later, "justification": _source_justification(candidate, later)})
                if comparison != later.get("comparison") or (comparison == "equals" and prior_value != later_value):
                    findings.append({"code": "gate_semantics_changed", "group": group, "rule_id": rule_id, "before": prior, "after": later, "justification": _source_justification(candidate, later)})
        if group == "exceptions":
            for rule_id, later in candidate_rules.items():
                if rule_id not in prior_rules and later.get("effect") != "advisory":
                    findings.append({"code": "exception_added", "group": group, "rule_id": rule_id, "before": None, "after": later, "justification": _source_justification(candidate, later)})
    return findings


def compare_oracle_contracts(root: Path, prior_path: Path, candidate_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Report semantic oracle weakening; the report itself changes no authority."""
    workspace = Path(root).resolve()
    prior_result = verify_oracle_contract(workspace, Path(prior_path))
    candidate_result = verify_oracle_contract(workspace, Path(candidate_path))
    if not prior_result["ok"] or not candidate_result["ok"]:
        reason = {"prior": prior_result.get("reason"), "candidate": candidate_result.get("reason")}
        core = {"schema": DRIFT_SCHEMA, "marker": "E_ORACLE_WEAKENING", "verdict": "BLOCKED", "reason": "contract_invalid_or_stale", "contracts": {"prior": str(prior_path), "candidate": str(candidate_path)}, "findings": [], "verification": reason, "authority": dict(AUTHORITY), "claim_boundary": "A blocked local comparison requires human review; it does not decide the successor contract."}
    else:
        findings = _weakening(prior_result["contract"], candidate_result["contract"])
        core = {"schema": DRIFT_SCHEMA, "marker": "E_ORACLE_WEAKENING" if findings else "ORACLE_DRIFT_CLEAR", "verdict": "BLOCKED" if findings else "CLEAR", "reason": "semantic_weakening" if findings else "no_detected_weakening", "contracts": {"prior": {"path": prior_result["path"], "contract_sha256": prior_result["contract"]["contract_sha256"]}, "candidate": {"path": candidate_result["path"], "contract_sha256": candidate_result["contract"]["contract_sha256"]}}, "findings": findings, "authority": dict(AUTHORITY), "claim_boundary": "The report detects declared contract weakening. A named reviewer must decide whether to retain or replace the baseline through a separately sealed contract."}
    receipt = _hash_receipt(core, "drift_sha256")
    if out is not None:
        path = _write_new(workspace, Path(out), receipt, digest_field="drift_sha256")
        return {**receipt, "path": path.relative_to(workspace).as_posix()}
    return receipt


def compile_oracle_challenge(root: Path, contract_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Compile independent implementation-targeted counterfactual work."""
    workspace = Path(root).resolve()
    verified = verify_oracle_contract(workspace, Path(contract_path))
    if not verified["ok"]:
        raise OracleFirewallError("ORACLE_CHALLENGE_BLOCKED", f"contract is not eligible: {verified['reason']}")
    contract = verified["contract"]
    mutation = {
        "requirements": "invert_required_outcome_in_implementation",
        "forbidden_behaviors": "enable_forbidden_behavior_in_implementation",
        "gates": "cross_declared_gate_boundary_in_implementation",
        "negative_cases": "accept_declared_negative_case_in_implementation",
        "invariants": "violate_invariant_in_implementation",
        "tests": "mutate_implementation_so_declared_test_must_fail",
    }
    def boundary_cases(rule: dict[str, Any]) -> list[dict[str, Any]]:
        """Describe exact gate edges for an independent implementation lane.

        These are instructions for the independently declared verifier, not an
        executable mutation and never a request to rewrite the test oracle.
        """
        if rule.get("comparison") == "present":
            return [{"relation": "present", "value": True}, {"relation": "missing", "value": False}]
        value = rule.get("value")
        if rule.get("comparison") in {"gte", "lte"} and isinstance(value, (int, float)) and not isinstance(value, bool):
            step = 1 if isinstance(value, int) else max(abs(value) * 0.01, 0.001)
            return [
                {"relation": "below", "value": value - step},
                {"relation": "at", "value": value},
                {"relation": "above", "value": value + step},
            ]
        if rule.get("comparison") == "equals":
            return [{"relation": "equal", "value": value}, {"relation": "not_equal", "value": None}]
        return []

    cases: list[dict[str, Any]] = []
    for group in ("requirements", "forbidden_behaviors", "gates", "negative_cases", "invariants", "tests"):
        for rule in contract["rules"][group]:
            if rule["critical"]:
                cases.append({"id": f"{group}:{rule['id']}", "group": group, "rule_id": rule["id"], "target": "implementation", "mutation": mutation[group], "source_id": rule["source_id"], "expected": "killed", "boundary_cases": boundary_cases(rule)})
    if not cases:
        raise OracleFirewallError("ORACLE_CHALLENGE_BLOCKED", "contract declares no critical implementation challenge")
    core = {"schema": CHALLENGE_SCHEMA, "marker": "ORACLE_CHALLENGE_COMPILED", "contract": {"path": verified["path"], "contract_sha256": contract["contract_sha256"]}, "cases": sorted(cases, key=lambda item: item["id"]), "independence": {"worker_may_not_select_cases": True, "verifier_may_not_edit_contract": True, "verifier_may_not_edit_candidate": True, "target": "implementation"}, "authority": dict(AUTHORITY), "claim_boundary": "A local challenge plan. It defines independent implementation-targeted evidence to collect and does not mutate code or tests."}
    receipt = _hash_receipt(core, "challenge_sha256")
    if out is not None:
        path = _write_new(workspace, Path(out), receipt, digest_field="challenge_sha256")
        return {**receipt, "path": path.relative_to(workspace).as_posix()}
    return receipt


def verify_oracle_challenge_result(root: Path, plan_path: Path, result_path: Path) -> dict[str, Any]:
    """Verify that an independent context challenged implementation rather than tests."""
    workspace = Path(root).resolve()
    plan, plan_source = _read_json(workspace, Path(plan_path), CHALLENGE_SCHEMA)
    result, result_source = _read_json(workspace, Path(result_path), CHALLENGE_RESULT_SCHEMA)
    if not _valid_receipt(plan, CHALLENGE_SCHEMA, "challenge_sha256"):
        return {"ok": False, "marker": "ORACLE_CHALLENGE_FAILED", "reason": "challenge_sha256_mismatch", "authority": dict(AUTHORITY)}
    if result.get("challenge_sha256") != plan.get("challenge_sha256"):
        return {"ok": False, "marker": "ORACLE_CHALLENGE_FAILED", "reason": "challenge_binding_mismatch", "authority": dict(AUTHORITY)}
    worker = _text(result.get("worker_subject"), "worker_subject", limit=160)
    verifier = _text(result.get("verifier_subject"), "verifier_subject", limit=160)
    if worker == verifier:
        return {"ok": False, "marker": "ORACLE_CHALLENGE_FAILED", "reason": "independence_subject_collision", "authority": dict(AUTHORITY)}
    if result.get("target") != "implementation":
        return {"ok": False, "marker": "ORACLE_CHALLENGE_FAILED", "reason": "challenge_target_is_not_implementation", "authority": dict(AUTHORITY)}
    supplied = result.get("cases")
    if not isinstance(supplied, list):
        return {"ok": False, "marker": "ORACLE_CHALLENGE_FAILED", "reason": "cases_missing", "authority": dict(AUTHORITY)}
    expected = {item["id"] for item in plan.get("cases", []) if isinstance(item, dict)}
    observed: dict[str, str] = {}
    for item in supplied:
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("outcome") in {"killed", "survived"}:
            observed[item["id"]] = item["outcome"]
    missing = sorted(expected - set(observed))
    survivors = sorted(identifier for identifier, outcome in observed.items() if identifier in expected and outcome == "survived")
    ok = not missing and not survivors and set(observed) == expected
    return {"schema": CHALLENGE_RESULT_SCHEMA, "ok": ok, "marker": "ORACLE_CHALLENGE_VERIFIED" if ok else "ORACLE_CHALLENGE_FAILED", "plan_path": plan_source.relative_to(workspace).as_posix(), "result_path": result_source.relative_to(workspace).as_posix(), "worker_subject": worker, "verifier_subject": verifier, "missing_cases": missing, "surviving_cases": survivors, "authority": dict(AUTHORITY), "claim_boundary": "Receipt syntax and declared independence only; it is not proof that the independent verifier identity or underlying execution was authentic."}


def record_oracle_incident(root: Path, agent: object, contract_path: Path, drift_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Record a local demotion fact when a hash-valid weakening report is blocked."""
    workspace = Path(root).resolve()
    identity = normalize_agent_identity(agent, "agent")
    contract_result = verify_oracle_contract(workspace, Path(contract_path))
    if not contract_result["ok"]:
        raise OracleFirewallError("ORACLE_INCIDENT_BLOCKED", "incident contract must verify before it can identify the affected agent")
    drift, source = _read_json(workspace, Path(drift_path), DRIFT_SCHEMA)
    if not _valid_receipt(drift, DRIFT_SCHEMA, "drift_sha256") or drift.get("marker") != "E_ORACLE_WEAKENING" or drift.get("verdict") != "BLOCKED":
        raise OracleFirewallError("ORACLE_INCIDENT_INVALID", "incident requires a hash-valid blocked weakening report")
    core = {"schema": INCIDENT_SCHEMA, "marker": "ORACLE_AUTONOMY_DEMOTED", "recorded_at": _now(), "agent": identity, "contract_sha256": contract_result["contract"]["contract_sha256"], "drift_path": source.relative_to(workspace).as_posix(), "drift_sha256": drift["drift_sha256"], "failure_class": "oracle_weakening", "tier": "human_controlled", "requalification_clean_runs": 5, "authority": dict(AUTHORITY), "claim_boundary": "Local demotion evidence only. It does not establish real-world agent identity or grant an automatic future promotion."}
    receipt = _hash_receipt(core, "incident_sha256")
    destination = Path(out) if out is not None else workspace / ".factory" / "oracles" / "incidents" / f"{identity['subject'].replace('/', '_')}-{receipt['incident_sha256'][:12]}.json"
    path = _write_new(workspace, destination, receipt, digest_field="incident_sha256")
    return {**receipt, "path": path.relative_to(workspace).as_posix()}


def oracle_incidents_for_agent(root: Path, identity: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only hash-valid local incidents matching one declared agent identity."""
    workspace = Path(root).resolve()
    subject = identity.get("subject") if isinstance(identity, dict) else None
    digest = identity.get("identity_sha256") if isinstance(identity, dict) else None
    current: list[dict[str, Any]] = []
    for path in sorted((workspace / ".factory" / "oracles" / "incidents").glob("*.json"))[:200]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if _valid_receipt(value, INCIDENT_SCHEMA, "incident_sha256") and value.get("agent", {}).get("subject") == subject and value.get("agent", {}).get("identity_sha256") == digest:
                current.append({**value, "path": path.relative_to(workspace).as_posix()})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            continue
    return current


def admission_oracle_decision(root: Path, contract_path: Path, requested_autonomy: str, request_paths: list[str]) -> dict[str, Any]:
    """Check the pre-run contract binding used by an external admission packet."""
    verified = verify_oracle_contract(root, Path(contract_path))
    if not verified["ok"]:
        raise OracleFirewallError("ORACLE_ADMISSION_PAUSED", f"oracle contract is not current: {verified['reason']}")
    contract = verified["contract"]
    unresolved = [item for group in contract["rules"].values() for item in group if item.get("origin") == "agent_proposed" and item.get("effect") == "advisory"]
    if requested_autonomy == "autonomous" and unresolved:
        raise OracleFirewallError("ORACLE_ADMISSION_PAUSED", "autonomous work requires human or trusted disposition of every agent-proposed rule")
    scope = contract["scope_paths"]
    for path in request_paths:
        if not any(item == "." or path == item or path.startswith(item.rstrip("/") + "/") for item in scope):
            raise OracleFirewallError("ORACLE_SCOPE_ESCAPE", "admission path is outside the sealed oracle contract")
    return {"marker": "ORACLE_ADMISSION_READY", "contract_path": verified["path"], "contract_sha256": contract["contract_sha256"], "requested_autonomy": requested_autonomy, "scope_paths": scope, "advisory_proposal_count": len(unresolved), "authority": dict(AUTHORITY)}


def initialize_oracle_firewall(root: Path, out_dir: Path, source_path: Path, agent: object, contract_id: str, scope_paths: list[str], *, appforge: bool = False) -> dict[str, Any]:
    """Create an intentionally incomplete, source-bound operator workspace.

    The initializer captures original bytes but does not create an approving
    contract.  The named human must still supply each obligation, forbidden
    behavior, gate value, and source-backed approval before sealing.
    """
    workspace = Path(root).resolve()
    destination = _inside(workspace, Path(out_dir), exists=False)
    if destination.exists():
        raise OracleFirewallError("ORACLE_INIT_OUTPUT_EXISTS", "init destination already exists; choose a new empty directory")
    identifier = _identifier(contract_id, "contract_id")
    safe_scope: list[str] = []
    for item in scope_paths:
        path = Path(_text(item, "scope_path").replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise OracleFirewallError("ORACLE_SCOPE_INVALID", "scope paths must be workspace relative")
        safe_scope.append(path.as_posix().rstrip("/") or ".")
    if not safe_scope or len(set(safe_scope)) != len(safe_scope):
        raise OracleFirewallError("ORACLE_SCOPE_INVALID", "scope paths must be non-empty and unique")
    destination.mkdir(parents=True, exist_ok=False)
    handoff = capture_intent_handoff(workspace, Path(source_path), agent, f"{identifier}-handoff", destination / "handoff.json")
    contract_template = {
        "schema": CONTRACT_INPUT_SCHEMA,
        "id": identifier,
        "version": 1,
        "approved_by": "REPLACE_WITH_NAMED_HUMAN",
        "approval_rationale": "REPLACE_WITH_A_SOURCE_BACKED_EXPLANATION_OF_WHY_THE_ORACLE_IS_CORRECT",
        "scope_paths": safe_scope,
        "handoff": handoff["path"],
        "sources": [],
        "requirements": [],
        "forbidden_behaviors": [],
        "gates": [],
        "exceptions": [],
        "negative_cases": [],
        "invariants": [],
        "tests": [],
    }
    challenge_template = {
        "schema": CHALLENGE_RESULT_SCHEMA,
        "challenge_sha256": "REPLACE_WITH_COMPILED_CHALLENGE_SHA256",
        "worker_subject": "REPLACE_WITH_WORKER_SUBJECT",
        "verifier_subject": "REPLACE_WITH_INDEPENDENT_VERIFIER_SUBJECT",
        "target": "implementation",
        "cases": [],
    }
    _atomic_json(destination / "oracle-contract-input.json", contract_template)
    _atomic_json(destination / "independent-challenge-result.json", challenge_template)
    lines = [
        "# Oracle Firewall: next safe actions",
        "",
        "1. Keep `handoff.json` immutable. It is the byte-for-byte original intent source.",
        "2. Add only named human-confirmed or trusted-source blocking/release rules to `oracle-contract-input.json`.",
        "3. Record every agent-proposed or observed-production rule as advisory until a human promotes it with a named source.",
        "4. Seal the contract: `factory oracle seal --root . --input <this-folder>/oracle-contract-input.json --out .factory/oracles/contracts/<id>.json`.",
        "5. Compile a separate implementation-targeted challenge and have a verifier context report every case.",
        "6. Review the Source -> obligation -> forbidden behavior -> gate -> test -> evidence -> decision chain in Graph Ops before any external run.",
        "",
        "Boundary: this workspace does not approve, mutate a candidate, invoke a verifier, access credentials, or release anything.",
    ]
    if appforge:
        _atomic_json(destination / "appforge-policy-authority-template.json", {
            "schema": "factory.appforge.oracle-authority.v1",
            "contract_path": "REPLACE_WITH_SEALED_ORACLE_CONTRACT_PATH",
            "candidate": {"bundle_identifier": "REPLACE", "version": "REPLACE", "build_number": "REPLACE", "source_commit": "REPLACE"},
            "policy_sources": [],
            "human_reviewer": "REPLACE_WITH_NAMED_RELEASE_OWNER",
            "claim_boundary": "Template only; it is not App Review evidence, TestFlight state, submission, certification, or approval.",
        })
        lines.append("7. For AppForge, bind the exact candidate plus policy sources through the Oracle Authority template before the submission dossier can be marked authority-complete.")
    (destination / "NEXT_STEPS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    core = {"schema": "factory.oracle-firewall-init-receipt.v1", "marker": "ORACLE_FIREWALL_INIT_READY", "created_at": _now(), "contract_id": identifier, "handoff_path": handoff["path"], "scope_paths": sorted(safe_scope), "appforge_template": appforge, "action_summary": "Capture exact original intent and create deliberately incomplete provenance, challenge, and AppForge authority templates for a named human to complete.", "authority": dict(AUTHORITY), "claim_boundary": "Local setup only; no gate is approved or evaluated, no agent run starts, and no provider or store action occurs."}
    receipt = _hash_receipt(core, "receipt_sha256")
    _atomic_json(destination / "oracle-firewall-init-receipt.json", receipt)
    return {**receipt, "path": (destination / "oracle-firewall-init-receipt.json").relative_to(workspace).as_posix()}


def oracle_firewall_projection(root: Path) -> dict[str, Any]:
    """Read hash-valid Oracle artifacts for Graph Ops, MCP, and IDE presentation."""
    workspace = Path(root).resolve()
    contracts: list[dict[str, Any]] = []
    drifts: list[dict[str, Any]] = []
    challenges: list[dict[str, Any]] = []
    incidents: list[dict[str, Any]] = []
    invalid: list[str] = []
    for directory, schema, digest, collection in (("contracts", CONTRACT_SCHEMA, "contract_sha256", contracts), ("drifts", DRIFT_SCHEMA, "drift_sha256", drifts), ("challenges", CHALLENGE_SCHEMA, "challenge_sha256", challenges), ("incidents", INCIDENT_SCHEMA, "incident_sha256", incidents)):
        for path in sorted((workspace / ".factory" / "oracles" / directory).glob("*.json"))[:200]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if _valid_receipt(value, schema, digest):
                    collection.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "sha256": value.get(digest), "id": value.get("id"), "verdict": value.get("verdict"), "contract_sha256": value.get("contract_sha256")})
                else:
                    invalid.append(path.relative_to(workspace).as_posix())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                invalid.append(path.relative_to(workspace).as_posix())
    blocked = [item for item in drifts if item.get("verdict") == "BLOCKED"]
    return {"schema": PROJECTION_SCHEMA, "marker": "ORACLE_FIREWALL_READ_ONLY", "contract_count": len(contracts), "drift_count": len(drifts), "blocked_drift_count": len(blocked), "challenge_count": len(challenges), "incident_count": len(incidents), "invalid_count": len(invalid), "latest_contract": contracts[-1] if contracts else None, "blocked_drifts": blocked[-20:], "contracts": contracts[-20:], "challenges": challenges[-20:], "incidents": incidents[-20:], "invalid": invalid[:100], "authority": dict(AUTHORITY), "claim_boundary": "Read-only local artifact projection. It does not approve a contract, run a challenge, alter a candidate, or authorize release work."}

"""Externally signed, expiring authority contracts for deep audit evidence intake."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path

from .deep_audit_io import LIMIT, bound_bytes, digest, relative_path, strict_json
from .enterprise_receipts import verify_signed_document
from .runtime_audit_common import RuntimeAuditError, require_bool, require_digest, require_int, require_str, sha256_bytes

PLAN_TYPE = "application/vnd.factory.deep-audit-plan.v1+json"
PLAN_SCHEMA = "factory.deep-audit-plan.v1"
CATEGORIES = {"security", "memory", "concurrency", "error_handling", "correctness", "maintainability", "dependency"}


def _keys(value: object, keys: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys.split()):
        raise RuntimeAuditError("E_PLAN_FIELDS", "missing or unknown contract fields")
    return value


def _items(value: object, maximum: int) -> list:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        raise RuntimeAuditError("E_PLAN_FIELDS", "contract collection outside bounds")
    return value


def _unique(values: list) -> None:
    if len(set(values)) != len(values):
        raise RuntimeAuditError("E_DUPLICATE_ID", "duplicate contract identity")


def _time(value: object) -> datetime:
    text = require_str(value, "time", maximum=40)
    try:
        result = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeAuditError("E_TIME", "invalid timestamp") from exc
    if result.tzinfo is None:
        raise RuntimeAuditError("E_TIME", "timestamp needs timezone")
    return result.astimezone(timezone.utc)


def _sources(root: Path, plan: dict) -> dict:
    sources = _items(plan["sources"], 128)
    identities = []
    output = {}
    for source in sources:
        _keys(source, "path sha256 bytes")
        path = relative_path(source["path"])
        identities.append(path.casefold())
        raw = bound_bytes(root, source)
        if len(raw) != require_int(source["bytes"], "bytes", minimum=0, maximum=LIMIT):
            raise RuntimeAuditError("E_SOURCE_DRIFT", "source size mismatch")
        output[path] = source["sha256"]
    _unique(identities)
    expected = digest(sorted(sources, key=lambda source: source["path"]))
    if require_digest(plan["candidate_sha256"], "candidate_sha256") != expected:
        raise RuntimeAuditError("E_CANDIDATE_DRIFT", "candidate manifest hash mismatch")
    return output


def _analyzers(root: Path, value: object) -> list:
    analyzers = _items(value, 8)
    paths, hashes, ids, tools = [], [], [], []
    for item in analyzers:
        _keys(item, "id driver version report canary_report")
        for field in ("id", "driver", "version"):
            require_str(item[field], field)
        ids.append(item["id"])
        tools.append((item["driver"], item["version"]))
        for field in ("report", "canary_report"):
            binding = _keys(item[field], "path sha256")
            paths.append(relative_path(binding["path"]).casefold())
            hashes.append(require_digest(binding["sha256"], field))
            bound_bytes(root, binding)
    for values in (paths, hashes, ids, tools):
        _unique(values)
    return analyzers


def _rules(value: object, analyzer_ids: set) -> list:
    rules = _items(value, 256)
    aliases, ids = [], []
    for rule in rules:
        _keys(rule, "id obligation_id category aliases severity max_new max_total min_trace_steps require_source_sink allowed_suppressions origin remediation consequence")
        for field in ("id", "obligation_id", "remediation", "consequence"):
            require_str(rule[field], field, maximum=512)
        ids.append(rule["id"])
        if require_str(rule["origin"], "origin") not in {"human_confirmed", "trusted_source"}:
            raise RuntimeAuditError("E_RULE_AUTHORITY", "observations and agent proposals cannot authorize gates")
        if require_str(rule["category"], "category") not in CATEGORIES or require_str(rule["severity"], "severity") not in {"critical", "high", "medium", "low"}:
            raise RuntimeAuditError("E_RULE_POLICY", "unsupported category or severity")
        for key in ("max_new", "max_total"):
            require_int(rule[key], key, minimum=0, maximum=20_000)
        require_int(rule["min_trace_steps"], "min_trace_steps", minimum=0, maximum=128)
        require_bool(rule["require_source_sink"], "require_source_sink")
        suppressions = rule["allowed_suppressions"]
        if not isinstance(suppressions, list) or len(suppressions) > 128:
            raise RuntimeAuditError("E_RULE_POLICY", "suppression list exceeds bounds")
        _unique([require_digest(item, "suppression") for item in suppressions])
        for alias in _items(rule["aliases"], 8):
            _keys(alias, "analyzer_id rule_id")
            require_str(alias["rule_id"], "rule_id")
            if require_str(alias["analyzer_id"], "analyzer_id") not in analyzer_ids:
                raise RuntimeAuditError("E_RULE_POLICY", "unknown analyzer reference")
            aliases.append((alias["analyzer_id"], alias["rule_id"]))
    _unique(ids)
    _unique(aliases)
    return rules


def _canaries(value: object, rules: list, analyzer_ids: set) -> list:
    canaries = _items(value, 128)
    aliases = {(alias["analyzer_id"], alias["rule_id"]) for rule in rules for alias in rule["aliases"]}
    ids, identities = [], []
    covered = set()
    for item in canaries:
        _keys(item, "id analyzer_id rule_id fingerprint_sha256")
        ids.append(require_str(item["id"], "id"))
        key = (require_str(item["analyzer_id"], "analyzer_id"), require_str(item["rule_id"], "rule_id"))
        if key not in aliases:
            raise RuntimeAuditError("E_CANARY_POLICY", "canary does not reference an approved alias")
        identities.append((*key, require_digest(item["fingerprint_sha256"], "fingerprint_sha256")))
        covered.add(item["analyzer_id"])
    _unique(ids)
    _unique(identities)
    if covered != analyzer_ids:
        raise RuntimeAuditError("E_CANARY_POLICY", "each analyzer needs a canary")
    return canaries


def _read(path: Path) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    strict_json(raw)
    return raw


def verify_deep_audit_plan(path: Path, trust_root_path: Path, trust_root_sha256: str, workspace_root: Path) -> dict:
    """Verify external signature, trust pin, authority, expiry and all source/report bindings without executing analyzers."""
    raw, trust = _read(path), _read(trust_root_path)
    if sha256_bytes(trust) != require_digest(trust_root_sha256, "trust pin"):
        raise RuntimeAuditError("E_TRUST_ROOT_DRIFT", "trust root differs from operator pin")
    envelope = strict_json(raw)
    try:
        encoded = envelope["payload"]
        parsed = strict_json(base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeAuditError("E_PAYLOAD", "invalid signed payload") from exc
    verified = verify_signed_document(path, payload_type=PLAN_TYPE, schema=PLAN_SCHEMA, trust_root_path=trust_root_path)
    plan = verified["payload"]
    if plan != parsed:
        raise RuntimeAuditError("E_INPUT_CHANGED", "signed payload changed")
    _keys(plan, "schema id candidate_sha256 issued_at expires_at sources analyzers rules canaries")
    require_str(plan["id"], "id", maximum=128)
    issued, expires = _time(plan["issued_at"]), _time(plan["expires_at"])
    now = datetime.now(timezone.utc)
    if not issued <= now < expires or not 0 < (expires-issued).total_seconds() <= 86_400:
        raise RuntimeAuditError("E_PLAN_EXPIRED", "plan must be current and valid for at most 24 hours")
    root = Path(workspace_root).resolve()
    sources = _sources(root, plan)
    analyzers = _analyzers(root, plan["analyzers"])
    analyzer_ids = {item["id"] for item in analyzers}
    rules = _rules(plan["rules"], analyzer_ids)
    canaries = _canaries(plan["canaries"], rules, analyzer_ids)
    _analyzers(root, plan["analyzers"])
    if _read(path) != raw or _read(trust_root_path) != trust or _sources(root, plan) != sources:
        raise RuntimeAuditError("E_INPUT_CHANGED", "contract changed during verification")
    identities = [{key: item[key] for key in ("id", "driver", "version")} for item in analyzers]
    return {"plan": plan, "plan_sha256": sha256_bytes(raw), "source_hashes": sources,
            "ruleset_sha256": digest({"analyzers": identities, "rules": rules, "canaries": canaries}),
            "canary_set_sha256": digest(canaries), "authority": "none"}

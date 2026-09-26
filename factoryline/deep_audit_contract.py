"""Externally signed, expiring authority contracts for deep audit evidence intake."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from pathlib import Path

from .deep_audit_io import LIMIT, bound_bytes, digest, relative_path, strict_json
from .enterprise_receipts import verify_signed_document
from .runtime_audit_common import (
    RuntimeAuditError,
    require_bool,
    require_digest,
    require_int,
    require_str,
    sha256_bytes,
)

PLAN_TYPE = "application/vnd.factory.deep-audit-plan.v1+json"
PLAN_SCHEMA = "factory.deep-audit-plan.v1"
CATEGORIES = {
    "security",
    "memory",
    "concurrency",
    "error_handling",
    "correctness",
    "maintainability",
    "dependency",
}


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


def _validate_rule(rule: dict, analyzer_ids: set) -> tuple[str, list[tuple[str, str]]]:
    _keys(
        rule,
        "id obligation_id category aliases severity max_new max_total min_trace_steps require_source_sink allowed_suppressions origin remediation consequence",
    )
    for field in ("id", "obligation_id", "remediation", "consequence"):
        require_str(rule[field], field, maximum=512)
    if require_str(rule["origin"], "origin") not in {
        "human_confirmed",
        "trusted_source",
    }:
        raise RuntimeAuditError(
            "E_RULE_AUTHORITY",
            "observations and agent proposals cannot authorize gates",
        )
    if require_str(rule["category"], "category") not in CATEGORIES or require_str(
        rule["severity"], "severity"
    ) not in {"critical", "high", "medium", "low"}:
        raise RuntimeAuditError("E_RULE_POLICY", "unsupported category or severity")
    for key in ("max_new", "max_total"):
        require_int(rule[key], key, minimum=0, maximum=20_000)
    require_int(rule["min_trace_steps"], "min_trace_steps", minimum=0, maximum=128)
    require_bool(rule["require_source_sink"], "require_source_sink")
    suppressions = rule["allowed_suppressions"]
    if not isinstance(suppressions, list) or len(suppressions) > 128:
        raise RuntimeAuditError("E_RULE_POLICY", "suppression list exceeds bounds")
    _unique([require_digest(item, "suppression") for item in suppressions])
    aliases = []
    for alias in _items(rule["aliases"], 8):
        _keys(alias, "analyzer_id rule_id")
        require_str(alias["rule_id"], "rule_id")
        if require_str(alias["analyzer_id"], "analyzer_id") not in analyzer_ids:
            raise RuntimeAuditError("E_RULE_POLICY", "unknown analyzer reference")
        aliases.append((alias["analyzer_id"], alias["rule_id"]))
    return rule["id"], aliases


def _rules(value: object, analyzer_ids: set) -> list:
    rules = _items(value, 256)
    aliases, ids = [], []
    for rule in rules:
        rule_id, rule_aliases = _validate_rule(rule, analyzer_ids)
        ids.append(rule_id)
        aliases.extend(rule_aliases)
    _unique(ids)
    _unique(aliases)
    return rules


def _canaries(value: object, rules: list, analyzer_ids: set) -> list:
    canaries = _items(value, 128)
    aliases = {
        (alias["analyzer_id"], alias["rule_id"])
        for rule in rules
        for alias in rule["aliases"]
    }
    ids, identities = [], []
    covered = set()
    for item in canaries:
        _keys(item, "id analyzer_id rule_id fingerprint_sha256")
        ids.append(require_str(item["id"], "id"))
        key = (
            require_str(item["analyzer_id"], "analyzer_id"),
            require_str(item["rule_id"], "rule_id"),
        )
        if key not in aliases:
            raise RuntimeAuditError(
                "E_CANARY_POLICY", "canary does not reference an approved alias"
            )
        identities.append(
            (*key, require_digest(item["fingerprint_sha256"], "fingerprint_sha256"))
        )
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


def _verified_plan_payload(
    path: Path, trust_root_path: Path, trust: bytes, raw: bytes
) -> dict:
    envelope = strict_json(raw)
    try:
        encoded = envelope["payload"]
        parsed = strict_json(
            base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeAuditError("E_PAYLOAD", "invalid signed payload") from exc
    verified = verify_signed_document(
        path,
        payload_type=PLAN_TYPE,
        schema=PLAN_SCHEMA,
        trust_root_path=trust_root_path,
    )
    signer = verified["signature"]["keyid"]
    keys = [
        key for key in strict_json(trust).get("keys", []) if key.get("keyid") == signer
    ]
    if len(keys) != 1 or keys[0].get("revoked") or keys[0].get("revoked_at"):
        raise RuntimeAuditError(
            "E_PLAN_SIGNER_REVOKED", "plan signer is ambiguous or revoked"
        )
    plan = verified["payload"]
    if plan != parsed:
        raise RuntimeAuditError("E_INPUT_CHANGED", "signed payload changed")
    return plan


def verify_deep_audit_plan(
    path: Path, trust_root_path: Path, trust_root_sha256: str, workspace_root: Path
) -> dict:
    """Verify external signature, trust pin, authority, expiry and all source/report bindings without executing analyzers."""
    raw, trust = _read(path), _read(trust_root_path)
    if sha256_bytes(trust) != require_digest(trust_root_sha256, "trust pin"):
        raise RuntimeAuditError(
            "E_TRUST_ROOT_DRIFT", "trust root differs from operator pin"
        )
    plan = _verified_plan_payload(path, trust_root_path, trust, raw)
    _keys(
        plan,
        "schema id candidate_sha256 issued_at expires_at sources analyzers rules canaries",
    )
    require_str(plan["id"], "id", maximum=128)
    issued, expires = _time(plan["issued_at"]), _time(plan["expires_at"])
    now = datetime.now(timezone.utc)
    if (
        not issued <= now < expires
        or not 0 < (expires - issued).total_seconds() <= 86_400
    ):
        raise RuntimeAuditError(
            "E_PLAN_EXPIRED", "plan must be current and valid for at most 24 hours"
        )
    root = Path(workspace_root).resolve()
    sources = _sources(root, plan)
    analyzers = _analyzers(root, plan["analyzers"])
    analyzer_ids = {item["id"] for item in analyzers}
    rules = _rules(plan["rules"], analyzer_ids)
    canaries = _canaries(plan["canaries"], rules, analyzer_ids)
    _analyzers(root, plan["analyzers"])
    if (
        _read(path) != raw
        or _read(trust_root_path) != trust
        or _sources(root, plan) != sources
    ):
        raise RuntimeAuditError(
            "E_INPUT_CHANGED", "contract changed during verification"
        )
    identities = [
        {key: item[key] for key in ("id", "driver", "version")} for item in analyzers
    ]
    return {
        "plan": plan,
        "plan_sha256": sha256_bytes(raw),
        "source_hashes": sources,
        "ruleset_sha256": digest(
            {"analyzers": identities, "rules": rules, "canaries": canaries}
        ),
        "canary_set_sha256": digest(canaries),
        "authority": "none",
    }


EXECUTION_ENGINES = {
    "codeql",
    "semgrep",
    "syft",
    "osv",
    "gitleaks",
    "trivy",
    "zap",
    "atheris",
    "jazzer",
    "runtime",
}
EXECUTION_FAMILIES = {
    "static",
    "dependencies",
    "secrets",
    "configuration",
    "runtime",
    "fuzz",
}
ENGINE_FAMILIES = {
    "codeql": "static",
    "semgrep": "static",
    "syft": "dependencies",
    "osv": "dependencies",
    "gitleaks": "secrets",
    "trivy": "configuration",
    "zap": "runtime",
    "runtime": "runtime",
    "atheris": "fuzz",
    "jazzer": "fuzz",
}


def _validate_lane_identity(lane: dict) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", require_str(lane["id"], "lane.id")):
        raise RuntimeAuditError("E_EXECUTION_LANE", "invalid lane identity")
    if (
        not isinstance(lane["engine"], str)
        or ENGINE_FAMILIES.get(lane["engine"]) != lane["family"]
    ):
        raise RuntimeAuditError("E_EXECUTION_ENGINE", "unregistered engine or family")


def _validate_lane_image(lane: dict) -> None:
    image = require_str(lane["image"], "image", maximum=256)
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:-]*@sha256:[a-f0-9]{64}", image):
        raise RuntimeAuditError(
            "E_IMAGE_PIN", "container image must have an immutable SHA-256 pin"
        )


def _validate_lane_argv(lane: dict) -> None:
    argv = lane["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise RuntimeAuditError("E_EXECUTION_ARGV", "expected bounded container argv")
    for arg in argv:
        text = require_str(arg, "argv", maximum=2048)
        if any(ord(char) < 32 for char in text):
            raise RuntimeAuditError("E_EXECUTION_ARGV", "control characters in argv")


def _validate_lane_reports(lane: dict) -> None:
    for field in ("report", "coverage", "challenge_report"):
        relative_path(lane[field])
    if len({lane[field] for field in ("report", "coverage", "challenge_report")}) != 3:
        raise RuntimeAuditError("E_EXECUTION_REPORT", "report paths must be distinct")


def _validate_lane_languages(lane: dict) -> None:
    if not isinstance(lane["languages"], list) or not 1 <= len(lane["languages"]) <= 32:
        raise RuntimeAuditError(
            "E_EXECUTION_COVERAGE", "unique declared languages required"
        )
    for language in lane["languages"]:
        require_str(language, "language", maximum=40)
    _unique(lane["languages"])


def _validate_lane_mode(lane: dict) -> None:
    require_str(lane["mode"], "mode", maximum=64)
    if lane["family"] == "static" and lane["mode"] != "interprocedural-full":
        raise RuntimeAuditError(
            "E_ANALYSIS_MODE",
            "full-depth static analysis requires interprocedural full scan",
        )
    if lane["argv"] != [
        "/opt/factory/bin/audit-adapter",
        lane["engine"],
        "--mode",
        lane["mode"],
    ]:
        raise RuntimeAuditError(
            "E_ADAPTER_TEMPLATE",
            "only the versioned audit-adapter entrypoint is permitted",
        )


def _validate_lane_limits(lane: dict) -> None:
    require_str(lane["tool_version"], "tool_version", maximum=128)
    require_digest(lane["ruleset_sha256"], "ruleset_sha256")
    require_int(lane["timeout_seconds"], "timeout_seconds", minimum=1, maximum=3600)
    require_int(lane["memory_mib"], "memory_mib", minimum=64, maximum=32768)


def _execution_lane(lane: dict) -> None:
    _keys(
        lane,
        "id engine family image argv report coverage challenge_report languages mode timeout_seconds memory_mib tool_version ruleset_sha256",
    )
    _validate_lane_identity(lane)
    _validate_lane_image(lane)
    _validate_lane_argv(lane)
    _validate_lane_reports(lane)
    _validate_lane_languages(lane)
    _validate_lane_mode(lane)
    _validate_lane_limits(lane)


def _validate_execution_identity(plan: dict) -> None:
    for field in ("candidate_sha256", "trust_root_sha256"):
        require_digest(plan[field], field)
    for field in (
        "implementer_id",
        "implementer_keyid",
        "reviewer_identity",
        "reviewer_keyid",
        "coordinator_identity",
        "coordinator_keyid",
    ):
        require_str(plan[field], field, maximum=256)
    if plan["implementer_id"] == plan["reviewer_identity"]:
        raise RuntimeAuditError(
            "E_REVIEWER_INDEPENDENCE", "reviewer identity must differ from implementer"
        )
    _unique(
        [
            plan[key]
            for key in ("implementer_keyid", "reviewer_keyid", "coordinator_keyid")
        ]
    )
    _unique(
        [
            plan[key]
            for key in ("implementer_id", "reviewer_identity", "coordinator_identity")
        ]
    )


def _execution_lanes(value: object) -> list[dict]:
    lanes = _items(value, 32)
    for lane in lanes:
        _execution_lane(lane)
    _unique([lane["id"] for lane in lanes])
    families = {lane["family"] for lane in lanes}
    if families != EXECUTION_FAMILIES:
        raise RuntimeAuditError(
            "E_EXECUTION_SCOPE", "all six full-depth analysis families must be declared"
        )
    return lanes


def _obligation_engine(obligation: dict, lanes: list[dict]) -> None:
    if not any(
        lane["engine"] == obligation["engine"]
        and lane["family"] == obligation["family"]
        for lane in lanes
    ):
        raise RuntimeAuditError(
            "E_OBLIGATION_ENGINE", "obligation must bind a declared engine/family"
        )
    if obligation["family"] not in EXECUTION_FAMILIES:
        raise RuntimeAuditError("E_OBLIGATION_FAMILY", "unknown obligation family")


def _obligation_paths(obligation: dict) -> None:
    for field in ("paths", "requirements"):
        for path in _items(obligation[field], 50000):
            relative_path(path)
        _unique(obligation[field])


def _validate_challenge(challenge: dict) -> None:
    _keys(
        challenge,
        "kind fixture_path fixture_sha256 expected_report_sha256 expected_exit_code",
    )
    relative_path(challenge["fixture_path"])
    require_digest(challenge["fixture_sha256"], "fixture_sha256")
    require_digest(challenge["expected_report_sha256"], "expected_report_sha256")
    require_int(
        challenge["expected_exit_code"],
        "expected_exit_code",
        minimum=0,
        maximum=255,
    )


def _challenge_identity(challenges: list[dict]) -> None:
    positive = next(item for item in challenges if item["kind"] == "positive")
    mutation = next(item for item in challenges if item["kind"] == "mutation")
    negative = next(item for item in challenges if item["kind"] == "negative")
    if (
        positive["fixture_sha256"] != mutation["fixture_sha256"]
        or positive["fixture_sha256"] == negative["fixture_sha256"]
        or len({item["expected_report_sha256"] for item in challenges}) != 3
    ):
        raise RuntimeAuditError(
            "E_HOLLOW_CHALLENGE",
            "disabled-control mutation must produce different report evidence",
        )


def _obligation_challenges(value: object) -> None:
    challenges = _items(value, 3)
    if any(not isinstance(item, dict) for item in challenges) or {
        item.get("kind") for item in challenges
    } != {"positive", "negative", "mutation"}:
        raise RuntimeAuditError(
            "E_CHALLENGE_SCOPE",
            "positive, negative and mutation challenges required",
        )
    for challenge in challenges:
        _validate_challenge(challenge)
    _challenge_identity(challenges)


def _validate_obligation(obligation: dict, lanes: list[dict]) -> None:
    _keys(
        obligation,
        "id engine family detector_rule_id paths requirements remediation challenges",
    )
    require_str(obligation["id"], "obligation.id", maximum=128)
    require_str(obligation["detector_rule_id"], "detector_rule_id", maximum=256)
    _obligation_engine(obligation, lanes)
    _obligation_paths(obligation)
    require_str(obligation["remediation"], "remediation", maximum=2048)
    _obligation_challenges(obligation["challenges"])


def _execution_obligations(value: object, lanes: list[dict]) -> None:
    obligations = _items(value, 4096)
    for obligation in obligations:
        _validate_obligation(obligation, lanes)
    _unique([item["id"] for item in obligations])
    if {item["family"] for item in obligations} != EXECUTION_FAMILIES:
        raise RuntimeAuditError(
            "E_OBLIGATION_SCOPE", "each analysis family requires explicit obligations"
        )


def load_execution_manifest(path: Path, expected_sha256: str) -> dict:
    """Validate the exact operator-selected execution plan; never discover it implicitly."""
    raw = _read(Path(path))
    if sha256_bytes(raw) != require_digest(expected_sha256, "manifest pin"):
        raise RuntimeAuditError(
            "E_EXECUTION_PIN", "manifest differs from the operator pin"
        )
    plan = strict_json(raw)
    _keys(
        plan,
        "schema candidate_sha256 implementer_id implementer_keyid reviewer_identity reviewer_keyid coordinator_identity coordinator_keyid trust_root_sha256 lanes obligations",
    )
    if plan["schema"] != "factory.deep-execution.v1":
        raise RuntimeAuditError("E_EXECUTION_SCHEMA", "unexpected execution schema")
    _validate_execution_identity(plan)
    lanes = _execution_lanes(plan["lanes"])
    _execution_obligations(plan["obligations"], lanes)
    return plan

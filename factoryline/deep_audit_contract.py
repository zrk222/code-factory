"""Externally signed, expiring authority contracts for deep audit evidence intake."""

from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlencode

from .deep_audit_io import (
    LIMIT,
    _osv_suppression_bytes,
    bound_bytes,
    digest,
    relative_path,
    strict_json,
)
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
V2_NATIVE_ROLES = {
    "codeql": {"sarif_report", "query_inventory"},
    "semgrep": {"sarif_report", "rule_inventory"},
    "trivy": {"sarif_report", "policy_inventory"},
    "osv": {"osv_json_report", "advisory_db_identity"},
    "gitleaks": {"sarif_report", "gitleaks_rule_ledger"},
    "runtime": {"junit_xml", "coverage_json"},
    "atheris": {"fuzz_result", "corpus_manifest"},
    "jazzer": {"fuzz_result", "corpus_manifest"},
    "zap": {"zap_report"},
    "syft": {"sbom_json"},
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
    if not re.fullmatch(
        r"(?:[a-zA-Z0-9][a-zA-Z0-9._/:-]*@)?sha256:[a-f0-9]{64}", image
    ):
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
    full_static = lane["mode"] == "interprocedural-full"
    semgrep_supplemental = (
        lane["engine"] == "semgrep"
        and lane["family"] == "static"
        and lane["mode"] == "pattern-limited"
    )
    if lane["family"] == "static" and not (full_static or semgrep_supplemental):
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


def _execution_lane(
    lane: dict, version: int = 1, inventory: dict | None = None
) -> None:
    if not isinstance(lane, dict):
        raise RuntimeAuditError("E_EXECUTION_LANE", "lane object required")
    lane_fields = _execution_lane_fields(lane, version)
    if set(lane) != lane_fields:
        raise RuntimeAuditError("E_EXECUTION_LANE", "missing or unknown lane fields")
    _keys(lane, " ".join(sorted(lane_fields)))
    _validate_lane_identity(lane)
    _validate_lane_image(lane)
    _validate_lane_argv(lane)
    _validate_lane_reports(lane)
    _validate_lane_languages(lane)
    _validate_lane_mode(lane)
    _validate_lane_limits(lane)
    if version == 2:
        _validate_v2_lane(lane, inventory)
    if version == 1:
        _validate_legacy_gitleaks_lane(lane)


def _validate_legacy_gitleaks_lane(lane: dict) -> None:
    if lane["engine"] != "gitleaks" or "rule_ids" not in lane:
        return
    rule_ids = _items(lane["rule_ids"], 4096)
    for rule_id in rule_ids:
        require_str(rule_id, "rule_id", maximum=256)
    _unique(rule_ids)
    mutations = lane.get("mutation_config_sha256")
    if mutations is not None:
        if not isinstance(mutations, dict) or set(mutations) != set(rule_ids):
            raise RuntimeAuditError(
                "E_EXECUTION_LANE", "exact per-rule mutation config hashes required"
            )
        for rule_id in rule_ids:
            require_digest(mutations[rule_id], "mutation_config_sha256")


def _execution_lane_fields(lane: dict, version: int) -> set[str]:
    fields = set(
        "id engine family image argv report coverage challenge_report languages mode timeout_seconds memory_mib tool_version ruleset_sha256".split()
    )
    if version == 2:
        fields.add("native_artifact_roles")
        if lane.get("engine") != "syft":
            fields.update({"rule_ids", "mutation_config_sha256"})
        if lane.get("engine") in {"trivy", "osv"} and "native_policy" in lane:
            fields.add("native_policy")
        if lane.get("engine") == "zap" and "native_target" in lane:
            fields.add("native_target")
    if lane.get("engine") == "gitleaks" and "rule_ids" in lane:
        fields.add("rule_ids")
        if "mutation_config_sha256" in lane:
            fields.add("mutation_config_sha256")
    return fields


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


def _validate_v2_lane(lane: dict, inventory: dict | None = None) -> None:
    _validate_v2_roles(lane)
    if lane["engine"] == "zap" and "native_target" in lane:
        _validate_zap_target(lane["native_target"], inventory)
    if lane["engine"] == "syft":
        return
    _validate_v2_rule_inventory(lane)
    if "native_policy" in lane:
        if lane["engine"] == "osv":
            _validate_v2_osv_policy(lane)
        else:
            _validate_v2_trivy_policy(lane)


def _validate_v2_trivy_policy(lane: dict) -> None:
    policy = lane["native_policy"]
    if lane["engine"] != "trivy" or not isinstance(policy, dict):
        raise RuntimeAuditError("E_NATIVE_POLICY", "native policy is Trivy-only")
    if set(policy) != {"config_sha256", "baseline_ignore_sha256"}:
        raise RuntimeAuditError("E_NATIVE_POLICY", "invalid Trivy policy identity")
    require_digest(policy["config_sha256"], "native_policy.config_sha256")
    require_digest(
        policy["baseline_ignore_sha256"], "native_policy.baseline_ignore_sha256"
    )


def _osv_aliases(value: object, detector: str) -> list[str]:
    aliases = _items(value, 64)
    for alias in aliases:
        text = require_str(alias, "OSV advisory identity", maximum=256)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", text) is None:
            raise RuntimeAuditError("E_OSV_TARGET", "invalid advisory identity")
    _unique(aliases)
    if aliases != sorted(aliases) or detector not in aliases:
        raise RuntimeAuditError("E_OSV_TARGET", "sorted target aliases required")
    return aliases


def _validate_v2_osv_policy(lane: dict) -> None:
    policy = _keys(
        lane["native_policy"],
        "database_path database_sha256 baseline_config_sha256 advisory_aliases",
    )
    if lane["mode"] != "offline-pypi-snapshot" or policy["database_path"] != (
        "/opt/factory/osv-db/osv-scanner/PyPI/all.zip"
    ):
        raise RuntimeAuditError(
            "E_NATIVE_POLICY", "pinned offline PyPI database required"
        )
    if (
        require_digest(policy["database_sha256"], "database_sha256")
        != lane["ruleset_sha256"]
    ):
        raise RuntimeAuditError("E_NATIVE_POLICY", "OSV database ruleset differs")
    if require_digest(policy["baseline_config_sha256"], "baseline_config_sha256") != (
        sha256_bytes(b"\n")
    ):
        raise RuntimeAuditError(
            "E_NATIVE_POLICY", "OSV baseline must be exactly one LF"
        )
    _validate_osv_policy_targets(lane, policy["advisory_aliases"])


def _validate_osv_policy_targets(lane: dict, targets: object) -> None:
    rules = lane["rule_ids"]
    if not isinstance(targets, dict) or set(targets) != set(rules):
        raise RuntimeAuditError("E_OSV_TARGET", "exact per-target alias sets required")
    seen = set()
    for detector in rules:
        aliases = _osv_aliases(targets[detector], detector)
        if seen.intersection(aliases):
            raise RuntimeAuditError("E_OSV_TARGET", "advisory target families overlap")
        seen.update(aliases)
        expected = sha256_bytes(_osv_suppression_bytes(aliases))
        if lane["mutation_config_sha256"].get(detector) != expected:
            raise RuntimeAuditError("E_OSV_TARGET", "exact suppression digest differs")


def _validate_v2_roles(lane: dict) -> None:
    roles = lane["native_artifact_roles"]
    expected = V2_NATIVE_ROLES.get(lane["engine"])
    if (
        expected is None
        or not isinstance(roles, list)
        or any(not isinstance(role, str) for role in roles)
        or roles != sorted(expected)
    ):
        raise RuntimeAuditError(
            "E_NATIVE_ROLE", "signed native artifact roles differ from engine"
        )


def _validate_v2_rule_inventory(lane: dict) -> None:
    rule_ids = _items(lane["rule_ids"], 4096)
    for rule_id in rule_ids:
        require_str(rule_id, "rule_id", maximum=256)
        if lane["engine"] == "zap" and (
            re.fullmatch(r"[1-9][0-9]{0,9}", rule_id) is None
            or int(rule_id) > 2147483647
        ):
            raise RuntimeAuditError(
                "E_EXECUTION_LANE", "ZAP rule IDs must be canonical positive integers"
            )
    _unique(rule_ids)
    if rule_ids != sorted(rule_ids):
        raise RuntimeAuditError("E_EXECUTION_LANE", "rule inventory must be sorted")
    mutations = lane["mutation_config_sha256"]
    if not isinstance(mutations, dict) or set(mutations) != set(rule_ids):
        raise RuntimeAuditError(
            "E_EXECUTION_LANE", "exact per-rule mutation config hashes required"
        )
    for rule_id in rule_ids:
        require_digest(mutations[rule_id], "mutation_config_sha256")


def _validate_zap_target(target: dict, inventory: dict | None = None) -> None:
    """Validate the signed ZAP app target, exact routes, and optional source inventory binding."""
    _validate_zap_target_fields(target)
    if target["schema"] != "factory.zap-target.v1":
        raise RuntimeAuditError("E_ZAP_TARGET", "unsupported target schema")
    _validate_lane_image({"image": target["image"]})
    argv = target["argv"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise RuntimeAuditError("E_ZAP_TARGET", "bounded target argv required")
    for argument in argv:
        text = require_str(argument, "target argv", maximum=2048)
        if any(ord(char) < 32 for char in text):
            raise RuntimeAuditError("E_ZAP_TARGET", "control characters in target argv")
    if not PurePosixPath(argv[0]).is_absolute():
        raise RuntimeAuditError("E_ZAP_TARGET", "absolute target executable required")
    require_int(target["port"], "target port", minimum=1, maximum=65535)
    _zap_path(target["readiness_path"])
    routes = _items(target["routes"], 128)
    identities = []
    inventory_sources = (
        _zap_inventory_sources(inventory) if inventory is not None else None
    )
    for route in routes:
        _validate_zap_route(route, inventory_sources)
        identities.append(route["id"])
    _unique(identities)
    if identities != sorted(identities):
        raise RuntimeAuditError("E_ZAP_TARGET", "routes must be sorted by ID")
    if "source_trace" in target:
        _validate_zap_source_trace(target["source_trace"], argv, routes)


def _validate_zap_target_fields(target: object) -> None:
    """Allow only the base target fields and the opt-in trace field."""
    fields = {"schema", "image", "argv", "port", "readiness_path", "routes"}
    if not isinstance(target, dict):
        raise RuntimeAuditError("E_ZAP_TARGET", "target fields differ")
    if "source_trace" in target:
        fields.add("source_trace")
    if set(target) != fields:
        raise RuntimeAuditError("E_ZAP_TARGET", "target fields differ")


def _validate_zap_source_trace(config: object, argv: list, routes: list) -> None:
    """Validate the opt-in Python HTTP trace contract without asserting its truth."""
    fields = {"schema", "provider", "max_events"}
    if not isinstance(config, dict) or set(config) != fields:
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "trace config fields differ")
    if (
        config["schema"] != "factory.zap-source-trace.config.v1"
        or config["provider"] != "python-stdlib-http.v1"
    ):
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "unsupported trace provider")
    require_int(config["max_events"], "max_events", minimum=1, maximum=50_000)

    executable = PurePosixPath(argv[0])
    if (
        not executable.is_absolute()
        or str(executable) != argv[0]
        or any(part in {".", ".."} for part in executable.parts)
        or re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable.name) is None
        or len(argv) < 2
    ):
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "Python script argv required")
    script = argv[1]
    if not script.startswith("/src/"):
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "script must be under /src")
    try:
        source_path = relative_path(script.removeprefix("/src/"))
    except RuntimeAuditError as error:
        raise RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "canonical Python source required"
        ) from error
    if script != "/src/" + source_path or not source_path.endswith(".py"):
        raise RuntimeAuditError(
            "E_ZAP_SOURCE_TRACE", "canonical Python source required"
        )
    bound_sources = {path for route in routes for path in route["source_bindings"]}
    if source_path not in bound_sources:
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "trace script is not route-bound")
    identities = [(route["method"], route["path"]) for route in routes]
    if len(identities) != len(set(identities)):
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "duplicate HTTP route identity")


def _zap_inventory_sources(inventory: dict) -> dict[str, str]:
    if not isinstance(inventory, dict) or not isinstance(inventory.get("files"), list):
        raise RuntimeAuditError("E_ZAP_TARGET_SOURCE", "candidate inventory required")
    sources = {}
    for item in inventory["files"]:
        if not isinstance(item, dict) or not {"path", "sha256"} <= set(item):
            raise RuntimeAuditError(
                "E_ZAP_TARGET_SOURCE", "invalid candidate source row"
            )
        path = relative_path(item["path"])
        source_sha = require_digest(item["sha256"], "candidate source digest")
        if path in sources:
            raise RuntimeAuditError("E_ZAP_TARGET_SOURCE", "duplicate candidate source")
        sources[path] = source_sha
    return sources


def _validate_zap_route(route: dict, inventory_sources: dict[str, str] | None) -> None:
    fields = {"id", "method", "path", "query", "source_bindings"}
    if not isinstance(route, dict) or set(route) != fields:
        raise RuntimeAuditError("E_ZAP_ROUTE", "route fields differ")
    route_id = require_str(route["id"], "route ID", maximum=64)
    if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", route_id) is None:
        raise RuntimeAuditError("E_ZAP_ROUTE", "invalid route ID")
    if route["method"] != "GET":
        raise RuntimeAuditError("E_ZAP_ROUTE", "only GET routes are supported")
    _zap_path(route["path"])
    _validate_zap_query(route["query"])
    _validate_zap_source_bindings(route["source_bindings"], inventory_sources)


def _validate_zap_query(query: object) -> None:
    if not isinstance(query, dict) or len(query) > 32:
        raise RuntimeAuditError("E_ZAP_ROUTE", "bounded query object required")
    if list(query) != sorted(query):
        raise RuntimeAuditError("E_ZAP_ROUTE", "query keys must be sorted")
    for key, value in query.items():
        if (
            not isinstance(key, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,63}", key) is None
        ):
            raise RuntimeAuditError("E_ZAP_ROUTE", "invalid query key")
        require_str(value, "query value", maximum=256)


def _validate_zap_source_bindings(
    bindings: object, inventory_sources: dict[str, str] | None
) -> None:
    if not isinstance(bindings, dict) or not bindings:
        raise RuntimeAuditError(
            "E_ZAP_TARGET_SOURCE", "nonempty source bindings required"
        )
    if list(bindings) != sorted(bindings):
        raise RuntimeAuditError("E_ZAP_TARGET_SOURCE", "source bindings must be sorted")
    for path, source_sha in bindings.items():
        path = relative_path(path)
        source_sha = require_digest(source_sha, "route source digest")
        if inventory_sources is not None and inventory_sources.get(path) != source_sha:
            raise RuntimeAuditError(
                "E_ZAP_TARGET_SOURCE", "route source differs from inventory"
            )


def _zap_path(value: object) -> str:
    path = require_str(value, "ZAP path", maximum=512)
    if (
        not path.startswith("/")
        or not path.isascii()
        or re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@/-]*", path) is None
        or "//" in path
        or any(part in {".", ".."} for part in path.split("/")[1:])
    ):
        raise RuntimeAuditError(
            "E_ZAP_PATH", "noncanonical absolute ASCII path required"
        )
    return path


def _zap_target_url(target: dict, route: dict | None = None) -> str:
    """Build a URL using only the fixed internal target alias and validated route fields."""
    _validate_zap_target(target)
    base = f"http://factory-target:{target['port']}"
    if route is None:
        return base + target["readiness_path"]
    _validate_zap_route(route, None)
    if route not in target["routes"]:
        raise RuntimeAuditError("E_ZAP_ROUTE", "route is not in the signed target")
    query = urlencode(route["query"])
    return base + route["path"] + (f"?{query}" if query else "")


def _execution_lanes(
    value: object, version: int, inventory: dict | None = None
) -> list[dict]:
    lanes = _items(value, 32)
    for lane in lanes:
        _execution_lane(lane, version, inventory)
    _unique([lane["id"] for lane in lanes])
    families = {lane["family"] for lane in lanes}
    if families != EXECUTION_FAMILIES:
        raise RuntimeAuditError(
            "E_EXECUTION_SCOPE", "all six full-depth analysis families must be declared"
        )
    if not any(
        lane["family"] == "static" and lane["mode"] == "interprocedural-full"
        for lane in lanes
    ):
        raise RuntimeAuditError(
            "E_EXECUTION_DEPTH",
            "at least one full interprocedural static lane is required",
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


def _validate_v2_fixture_manifest(challenge: dict) -> None:
    manifest = challenge["fixture_manifest"]
    if not isinstance(manifest, dict) or not 1 <= len(manifest) <= 64:
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "fixture manifest outside bounds"
        )
    normalized = {}
    for path, source_sha in manifest.items():
        normalized[relative_path(path)] = require_digest(
            source_sha, "fixture source digest"
        )
    if list(manifest) != sorted(manifest) or normalized != manifest:
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "fixture manifest must be canonical and sorted"
        )
    if manifest.get(challenge["fixture_path"]) != challenge["fixture_sha256"]:
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "fixture anchor differs from source manifest"
        )
    if digest(manifest) != require_digest(
        challenge["fixture_manifest_sha256"], "fixture_manifest_sha256"
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "fixture manifest digest differs"
        )


def _validate_challenge(challenge: dict, version: int) -> None:
    fields = (
        "kind fixture_path fixture_sha256 expected_report_sha256 expected_exit_code"
    )
    if version == 2:
        fields += " fixture_manifest fixture_manifest_sha256"
        if "zap_route_id" in challenge:
            fields += " zap_route_id"
        if "zap_target" in challenge:
            fields += " zap_target"
    _keys(challenge, fields)
    relative_path(challenge["fixture_path"])
    require_digest(challenge["fixture_sha256"], "fixture_sha256")
    require_digest(challenge["expected_report_sha256"], "expected_report_sha256")
    require_int(
        challenge["expected_exit_code"],
        "expected_exit_code",
        minimum=0,
        maximum=255,
    )
    if version == 2:
        _validate_v2_fixture_manifest(challenge)


def _challenge_identity(challenges: list[dict], version: int) -> None:
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
    if version == 2 and positive["fixture_manifest"] != mutation["fixture_manifest"]:
        raise RuntimeAuditError(
            "E_HOLLOW_CHALLENGE", "mutation must bind the exact positive fixture tree"
        )
    if version == 2 and "zap_route_id" in positive:
        if positive["zap_route_id"] != mutation.get("zap_route_id") or positive.get(
            "zap_target"
        ) != mutation.get("zap_target"):
            raise RuntimeAuditError(
                "E_HOLLOW_CHALLENGE", "mutation must bind the exact positive route"
            )


def _obligation_challenges(value: object, version: int) -> None:
    challenges = _items(value, 3)
    if any(not isinstance(item, dict) for item in challenges) or {
        item.get("kind") for item in challenges
    } != {"positive", "negative", "mutation"}:
        raise RuntimeAuditError(
            "E_CHALLENGE_SCOPE",
            "positive, negative and mutation challenges required",
        )
    for challenge in challenges:
        _validate_challenge(challenge, version)
    _challenge_identity(challenges, version)


def _validate_obligation(obligation: dict, lanes: list[dict], version: int) -> None:
    fields = (
        "id engine family detector_rule_id paths requirements remediation challenges"
    )
    if (
        version == 2
        and isinstance(obligation, dict)
        and obligation.get("engine") == "osv"
        and "osv_target" in obligation
    ):
        fields += " osv_target"
    _keys(obligation, fields)
    require_str(obligation["id"], "obligation.id", maximum=128)
    require_str(obligation["detector_rule_id"], "detector_rule_id", maximum=256)
    _obligation_engine(obligation, lanes)
    if version == 2:
        _validate_v2_obligation(obligation, lanes)
    _obligation_paths(obligation)
    require_str(obligation["remediation"], "remediation", maximum=2048)
    _obligation_challenges(obligation["challenges"], version)
    if version == 2 and obligation.get("engine") == "zap":
        has_control = any(
            "zap_target" in item or "zap_route_id" in item
            for item in obligation["challenges"]
        )
        if has_control:
            lane = next(
                item
                for item in lanes
                if item["engine"] == "zap" and item["family"] == obligation["family"]
            )
            _validate_zap_control_obligation(obligation, lane)
    elif version == 2 and any(
        "zap_target" in item or "zap_route_id" in item
        for item in obligation["challenges"]
    ):
        raise RuntimeAuditError(
            "E_ZAP_CONTROL", "signed ZAP controls require a ZAP obligation"
        )


def _validate_v2_obligation(obligation: dict, lanes: list[dict]) -> None:
    if obligation["engine"] == "syft":
        raise RuntimeAuditError(
            "E_CHALLENGE_ENGINE", "Syft inventory is not a detector challenge"
        )
    lane = next(
        item
        for item in lanes
        if item["engine"] == obligation["engine"]
        and item["family"] == obligation["family"]
    )
    if obligation["detector_rule_id"] not in lane["rule_ids"]:
        raise RuntimeAuditError(
            "E_CHALLENGE_RULE", "detector rule is absent from signed inventory"
        )
    if lane["engine"] == "osv":
        _validate_osv_obligation(obligation, lane)


def _validate_zap_control_obligation(obligation: dict, lane: dict) -> None:
    """Bind signed ZAP controls to exact app routes and fixture trees."""
    native_target = lane.get("native_target")
    challenges = obligation["challenges"]
    controls_enabled = any(
        "zap_target" in challenge or "zap_route_id" in challenge
        for challenge in challenges
    )
    if not controls_enabled:
        return
    if not isinstance(native_target, dict) or any(
        "zap_target" not in challenge or "zap_route_id" not in challenge
        for challenge in challenges
    ):
        raise RuntimeAuditError(
            "E_ZAP_CONTROL", "all three challenge controls are required"
        )
    for challenge in challenges:
        target = challenge["zap_target"]
        _validate_zap_target(target)
        if target["image"] != native_target["image"]:
            raise RuntimeAuditError(
                "E_ZAP_CONTROL", "control target must use the lane's pinned app image"
            )
        route_id = require_str(
            challenge.get("zap_route_id"), "zap_route_id", maximum=64
        )
        route = _zap_route_by_id(target, route_id)
        if challenge["fixture_manifest"] != route["source_bindings"]:
            raise RuntimeAuditError(
                "E_ZAP_CONTROL", "fixture manifest differs from signed route sources"
            )
        fixture_manifest = challenge["fixture_manifest"]
        for declared_route in target["routes"]:
            if any(
                fixture_manifest.get(path) != source_sha
                for path, source_sha in declared_route["source_bindings"].items()
            ):
                raise RuntimeAuditError(
                    "E_ZAP_CONTROL", "target route source is outside fixture manifest"
                )


def _zap_route_by_id(target: dict, route_id: str) -> dict:
    """Select one exact route from a validated signed ZAP target."""
    routes = [route for route in target["routes"] if route["id"] == route_id]
    if len(routes) != 1:
        raise RuntimeAuditError("E_ZAP_CONTROL", "route ID is absent or ambiguous")
    return routes[0]


def zap_signed_controls(
    lane: dict, obligations: list[dict], source_root: Path | None = None
) -> dict[str, dict]:
    """Return per-rule signed controls, optionally hashing fixture files."""
    if lane.get("engine") != "zap" or "native_target" not in lane:
        raise RuntimeAuditError("E_ZAP_CONTROL", "signed ZAP target lane required")
    _validate_zap_target(lane["native_target"])
    controls = {}
    for obligation in obligations:
        if (
            obligation.get("engine") != "zap"
            or obligation.get("family") != lane["family"]
        ):
            continue
        rule_id, control = _zap_control_entry(obligation, lane, source_root)
        if rule_id in controls:
            raise RuntimeAuditError("E_ZAP_CONTROL", "duplicate rule control")
        controls[rule_id] = control
    if set(controls) != set(lane["rule_ids"]):
        raise RuntimeAuditError(
            "E_ZAP_CONTROL", "exactly one control per enabled rule required"
        )
    return controls


def _zap_control_entry(obligation, lane, source_root):
    rule_id = obligation.get("detector_rule_id")
    if rule_id not in lane["rule_ids"]:
        raise RuntimeAuditError(
            "E_ZAP_CONTROL", "control rule is outside lane inventory"
        )
    if not any("zap_target" in item for item in obligation.get("challenges", [])):
        raise RuntimeAuditError("E_ZAP_CONTROL", "signed rule control is missing")
    _validate_zap_control_obligation(obligation, lane)
    challenges = obligation.get("challenges")
    if not isinstance(challenges, list) or {
        item.get("kind") for item in challenges if isinstance(item, dict)
    } != {"positive", "negative", "mutation"}:
        raise RuntimeAuditError("E_ZAP_CONTROL", "complete signed control set required")
    if source_root is not None:
        _verify_zap_control_sources(challenges, source_root)
    return rule_id, {"challenges": {item["kind"]: item for item in challenges}}


def _verify_zap_control_sources(challenges, source_root):
    for challenge in challenges:
        for path, source_sha in challenge["fixture_manifest"].items():
            bound_bytes(Path(source_root), {"path": path, "sha256": source_sha})


def _zap_control_obligations(
    lane: dict, obligations: list[dict], snapshot: Path | None = None
) -> list[dict]:
    """Return signed ZAP controls in lane rule order after fixture verification."""
    selected = zap_signed_controls(lane, obligations, snapshot)
    by_rule = {
        item["detector_rule_id"]: item
        for item in obligations
        if item.get("engine") == "zap" and item.get("family") == lane["family"]
    }
    return [by_rule[rule_id] for rule_id in lane["rule_ids"] if rule_id in selected]


def _validate_osv_obligation(obligation: dict, lane: dict) -> None:
    policy = lane.get("native_policy")
    target = obligation.get("osv_target")
    if policy is None and target is None:
        return
    if policy is None or target is None:
        raise RuntimeAuditError("E_OSV_TARGET", "OSV policy and target must be paired")
    target = _keys(target, "package ecosystem vulnerable_version fixed_version aliases")
    name = require_str(target["package"], "OSV package", maximum=256)
    if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is None:
        raise RuntimeAuditError("E_OSV_TARGET", "normalized PyPI package required")
    if target["ecosystem"] != "PyPI":
        raise RuntimeAuditError("E_OSV_TARGET", "only PyPI controls are supported")
    for field in ("vulnerable_version", "fixed_version"):
        value = require_str(target[field], field, maximum=128)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.!+_-]{0,127}", value) is None:
            raise RuntimeAuditError("E_OSV_TARGET", "literal package version required")
    if target["vulnerable_version"] == target["fixed_version"]:
        raise RuntimeAuditError(
            "E_OSV_TARGET", "distinct vulnerable/fixed versions required"
        )
    detector = obligation["detector_rule_id"]
    aliases = _osv_aliases(target["aliases"], detector)
    if aliases != policy["advisory_aliases"][detector]:
        raise RuntimeAuditError("E_OSV_TARGET", "obligation aliases differ from policy")


def _execution_obligations(value: object, lanes: list[dict], version: int) -> None:
    obligations = _items(value, 4096)
    for obligation in obligations:
        _validate_obligation(obligation, lanes, version)
    _unique([item["id"] for item in obligations])
    if {item["family"] for item in obligations} != EXECUTION_FAMILIES:
        raise RuntimeAuditError(
            "E_OBLIGATION_SCOPE", "each analysis family requires explicit obligations"
        )


def load_execution_manifest(
    path: Path, expected_sha256: str, inventory: dict | None = None
) -> dict:
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
    versions = {"factory.deep-execution.v1": 1, "factory.deep-execution.v2": 2}
    version = versions.get(plan.get("schema"))
    if version is None:
        raise RuntimeAuditError("E_EXECUTION_SCHEMA", "unexpected execution schema")
    _validate_execution_identity(plan)
    lanes = _execution_lanes(plan["lanes"], version, inventory)
    _execution_obligations(plan["obligations"], lanes, version)
    return plan

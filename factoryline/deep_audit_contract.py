"""Externally signed, expiring authority contracts for deep audit evidence intake."""

from __future__ import annotations

from . import deep_audit_io as _deep_audit_io
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


def _adapter_profile(profile: dict, lane: dict) -> list[dict]:
    """Commands come from the immutable image, never from scanned repository text."""
    expected = {
        "schema",
        "engine",
        "mode",
        "tool_version",
        "ruleset_sha256",
        "commands",
    }
    if set(profile) != expected or profile["schema"] != "factory.adapter-profile.v1":
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "invalid image-bundled profile"
        )
    for key in ("engine", "mode", "tool_version", "ruleset_sha256"):
        if profile[key] != lane.get(key):
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_PROFILE", "profile differs from signed lane"
            )
    commands = profile["commands"]
    if not isinstance(commands, list) or not 1 <= len(commands) <= 64:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "bounded command list required"
        )
    for command in commands:
        _deep_audit_io._adapter_command_shape(command)
    return commands


def _adapter_command_shape(command: dict) -> None:
    if not isinstance(command, dict) or set(command) != {"argv", "accepted_exit_codes"}:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "invalid command fields"
        )
    _deep_audit_io._adapter_argv_shape(command["argv"])
    _deep_audit_io._adapter_exit_shape(command["accepted_exit_codes"])


def _adapter_argv_shape(argv):
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "bounded argv required"
        )
    for arg in argv:
        _deep_audit_io.require_str(arg, "adapter argument", maximum=2048)
    if not _deep_audit_io.Path(argv[0]).is_absolute():
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "absolute executable path required"
        )


def _adapter_exit_shape(exits):
    if not isinstance(exits, list) or not 1 <= len(exits) <= 16:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "bounded exit codes required"
        )
    if any(type(code) is not int or not 0 <= code <= 255 for code in exits):
        raise _deep_audit_io.RuntimeAuditError("E_ADAPTER_PROFILE", "invalid exit code")


def _adapter_sources(source: _deep_audit_io.Path, inventory: dict) -> None:
    files = inventory.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 50_000:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_INPUT", "bounded inventory required"
        )
    names = set()
    for item in files:
        if not isinstance(item, dict) or item.get("path") in names:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_INPUT", "unique source bindings required"
            )
        path = _deep_audit_io.relative_path(item.get("path"))
        names.add(path)
        _deep_audit_io.bound_bytes(source, {"path": path, "sha256": item.get("sha256")})
    actual = _deep_audit_io._adapter_source_files(source)
    if actual != names:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_INPUT", "source file set differs from inventory"
        )


def _adapter_source_files(source):
    if source.is_symlink() or not source.is_dir():
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_INPUT", "source root must be a real directory"
        )
    pending = [source]
    names = set()
    entries = 0
    while pending:
        directory = pending.pop()
        with _deep_audit_io.os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > 100_000:
                    raise _deep_audit_io.RuntimeAuditError(
                        "E_ADAPTER_INPUT", "source tree exceeds entry budget"
                    )
                if entry.is_symlink():
                    raise _deep_audit_io.RuntimeAuditError(
                        "E_ADAPTER_INPUT", "source links are unsupported"
                    )
                if entry.is_dir(follow_symlinks=False):
                    pending.append(_deep_audit_io.Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise _deep_audit_io.RuntimeAuditError(
                        "E_ADAPTER_INPUT", "special source entries are unsupported"
                    )
                relative = (
                    _deep_audit_io.Path(entry.path).relative_to(source).as_posix()
                )
                names.add(_deep_audit_io.relative_path(relative))
    return names


def _adapter_commands(
    commands: list[dict],
    lane: dict,
    source: _deep_audit_io.Path,
    scratch: _deep_audit_io.Path,
) -> list[dict]:
    from .runtime_audit_process import run_bounded_command

    timeout = lane.get("timeout_seconds")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_INPUT", "bounded signed timeout required"
        )
    deadline = _deep_audit_io.time.monotonic() + timeout
    invocations = []
    for index, command in enumerate(commands):
        remaining = int(deadline - _deep_audit_io.time.monotonic())
        if remaining <= 0:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "adapter deadline exhausted"
            )
        directory = scratch / str(index)
        directory.mkdir()
        invocations.append(
            _deep_audit_io._adapter_invocation(
                run_bounded_command,
                command,
                lane,
                source,
                directory,
                remaining,
                deadline,
            )
        )
    return invocations


def _adapter_invocation(runner, command, lane, source, directory, remaining, deadline):
    argv = [
        value.replace("{factory_ledger}", str(directory / "rule-ledger.json"))
        for value in command["argv"]
    ]
    stderr_path = _deep_audit_io._gitleaks_stderr_path(directory, lane)
    facts = runner(argv, source, remaining, directory, stderr_path=stderr_path)
    if _deep_audit_io._adapter_command_failed(
        facts, command["accepted_exit_codes"], deadline
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_COMMAND", "native command did not complete"
        )
    invocation = {
        "argv_sha256": _deep_audit_io.digest(command["argv"]),
        "execution": facts,
    }
    _deep_audit_io._attach_gitleaks_ledger(invocation, command, directory)
    if stderr_path is not None:
        invocation["native_scanned_bytes"] = _deep_audit_io._gitleaks_scanned_bytes(
            stderr_path.read_bytes(), lane["tool_version"]
        )
    return invocation


def _json_size_upper_bound(value):
    """Conservatively estimate canonical JSON bytes without materializing them."""
    total = 0
    pending = [value]
    while pending:
        total += _deep_audit_io._json_value_size(pending.pop(), pending)
    return total


def _json_value_size(item, pending):
    if isinstance(item, dict):
        pending.extend(item.values())
        for key in item:
            if not isinstance(key, str):
                raise _deep_audit_io.RuntimeAuditError(
                    "E_NATIVE_BUNDLE_SIZE", "JSON key is not text"
                )
        return (
            2
            + max(0, len(item) - 1)
            + sum(_deep_audit_io._json_string_size(key) for key in item)
        )
    if isinstance(item, (list, tuple)):
        pending.extend(item)
        return 2 + max(0, len(item) - 1)
    if isinstance(item, str):
        return _deep_audit_io._json_string_size(item)
    if item is None or isinstance(item, bool):
        return 5
    if isinstance(item, int):
        return len(str(item))
    if isinstance(item, float):
        return 32
    raise _deep_audit_io.RuntimeAuditError(
        "E_NATIVE_BUNDLE_SIZE", "unsupported JSON value"
    )


def _json_string_size(value):
    size = 2
    for char in value:
        codepoint = ord(char)
        if char in {'"', "\\", "\b", "\t", "\n", "\f", "\r"}:
            size += 2
        elif codepoint < 32:
            size += 6
        else:
            size += len(char.encode("utf-8"))
    return size


def _native_budget_error(code, sources, rules, estimate, limit):
    pairs = sources * rules
    raise _deep_audit_io.RuntimeAuditError(
        code,
        f"native budget requires {sources} sources x {rules} rules "
        f"({pairs} rows); estimated {estimate} bytes exceeds {limit}",
    )


def _gitleaks_coverage_preflight(
    execution, report, inventory, lane, challenges, obligations
):
    source_count = sum(
        item["language"] in lane["languages"] for item in inventory["files"]
    )
    rule_count = len(lane["rule_ids"])
    pairs = source_count * rule_count
    per_pair = 768 + (
        max(
            (
                _deep_audit_io._json_string_size(item["path"]) - 2
                for item in inventory["files"]
            ),
            default=0,
        )
        + max(
            (
                _deep_audit_io._json_string_size(rule_id) - 2
                for rule_id in lane["rule_ids"]
            ),
            default=0,
        )
    )
    fixed = (
        len(execution["ledger_json"].encode("utf-8"))
        + _deep_audit_io._json_size_upper_bound(inventory["files"])
        + _deep_audit_io._json_size_upper_bound(execution["invocations"])
        + _deep_audit_io._json_size_upper_bound(execution["version_probe"])
        + _deep_audit_io._json_size_upper_bound(execution["rule_inventory"])
        + _deep_audit_io._json_size_upper_bound(report)
        + _deep_audit_io._json_size_upper_bound(challenges)
        + _deep_audit_io._json_size_upper_bound(obligations)
        + 4096
    )
    estimate = fixed + pairs * per_pair
    if pairs > 200_000 or estimate > _deep_audit_io.NATIVE_COVERAGE_LIMIT:
        _deep_audit_io._native_budget_error(
            "E_GITLEAKS_LEDGER_SIZE",
            source_count,
            rule_count,
            estimate,
            _deep_audit_io.NATIVE_COVERAGE_LIMIT,
        )


def _bounded_json_bytes(value, limit, code, sources=0, rules=0):
    estimate = _deep_audit_io._json_size_upper_bound(value)
    if estimate > limit:
        _deep_audit_io._native_budget_error(code, sources, rules, estimate, limit)
    raw = _deep_audit_io.canonical_bytes(value)
    if len(raw) > limit:
        _deep_audit_io._native_budget_error(code, sources, rules, len(raw), limit)
    return raw


def _adapter_command_failed(facts, accepted_exit_codes, deadline):
    if any(
        facts[key] for key in ("timed_out", "launch_error", "output_limit_exceeded")
    ):
        return True
    if not facts["cleanup_confirmed"] or facts["exit_code"] not in accepted_exit_codes:
        return True
    return _deep_audit_io.time.monotonic() > deadline


def _adapter_contract_parts(contract: dict) -> tuple[dict, dict]:
    """Validate shared input identity before executing either worker format."""
    keys = {"schema", "run_id", "manifest_sha256", "inventory", "lane", "obligations"}
    if (
        not isinstance(contract, dict)
        or set(contract) != keys
        or contract["schema"] != "factory.deep-adapter-input.v1"
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_INPUT", "invalid adapter contract"
        )
    _deep_audit_io.require_str(contract["run_id"], "run_id", maximum=64)
    _deep_audit_io.require_digest(contract["manifest_sha256"], "manifest_sha256")
    inventory, lane = contract["inventory"], contract["lane"]
    if not isinstance(inventory, dict) or not isinstance(lane, dict):
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_INPUT", "inventory and lane objects required"
        )
    _deep_audit_io.require_digest(inventory.get("candidate_sha256"), "candidate_sha256")
    return inventory, lane


def _adapter_output_paths(
    lane: dict, output: _deep_audit_io.Path, *, create_parents: bool = False
) -> list[str]:
    """Reject stale or aliased artifacts before any native tool is started."""
    paths = [
        _deep_audit_io.relative_path(lane[key])
        for key in ("report", "coverage", "challenge_report")
    ]
    if len(set(paths)) != 3:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_INPUT", "distinct artifact paths required"
        )
    for path in paths:
        target = output / path
        if target.exists() or target.is_symlink():
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_STALE", "preexisting output rejected"
            )
        if create_parents:
            target.parent.mkdir(parents=True, exist_ok=True)
    return paths


def execute_adapter_profile(
    profile: dict,
    contract: dict,
    source: _deep_audit_io.Path,
    output: _deep_audit_io.Path,
) -> dict:
    """Join actual native artifacts; never synthesize coverage or challenge success."""
    inventory, lane = _deep_audit_io._adapter_contract_parts(contract)
    commands = _deep_audit_io._adapter_profile(profile, lane)
    _deep_audit_io._adapter_sources(source, inventory)
    report_paths = _deep_audit_io._adapter_output_paths(
        lane, _deep_audit_io.Path(output)
    )
    with _deep_audit_io.tempfile.TemporaryDirectory(
        prefix="factory-adapter-"
    ) as temporary:
        invocations = _deep_audit_io._adapter_commands(
            commands, lane, _deep_audit_io.Path(source), _deep_audit_io.Path(temporary)
        )
    artifacts = {}
    for path in sorted(report_paths):
        artifact = _deep_audit_io.local_file(output, path)
        with artifact.open("rb") as stream:
            artifacts[path] = _deep_audit_io.strict_json(
                stream.read(_deep_audit_io.LIMIT + 1)
            )
    coverage = artifacts[lane["coverage"]]
    coverage["native_coverage_sha256"] = _deep_audit_io.digest(coverage)
    coverage["native_invocations"] = invocations
    coverage["invocation_sha256"] = _deep_audit_io.digest(invocations)
    _deep_audit_io._adapter_sources(source, inventory)
    return {
        "schema": "factory.deep-worker.v1",
        "run_id": contract["run_id"],
        "candidate_sha256": inventory["candidate_sha256"],
        "artifacts": artifacts,
    }


def _native_profile(profile: dict, lane: dict) -> None:
    expected = {
        "schema",
        "engine",
        "mode",
        "tool_version",
        "ruleset_sha256",
        "commands",
        "version_argv",
        "report_format",
    }
    if set(profile) != expected or profile["schema"] != "factory.native-profile.v1":
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "invalid native profile"
        )
    projected = {
        key: value
        for key, value in profile.items()
        if key not in {"version_argv", "report_format"}
    }
    projected["schema"] = "factory.adapter-profile.v1"
    _deep_audit_io._adapter_profile(projected, lane)
    _deep_audit_io._adapter_command_shape(
        {"argv": profile["version_argv"], "accepted_exit_codes": [0]}
    )
    formats = {
        "codeql": {"sarif"},
        "semgrep": {"sarif"},
        "gitleaks": {"sarif"},
        "trivy": {"sarif"},
        "osv": {"osv-json"},
        "syft": {"syft-json"},
        "runtime": {"runtime-json", "coverage-json", "runtime-junit"},
        "atheris": {"runtime-json"},
        "jazzer": {"runtime-json"},
        "zap": {"runtime-json"},
    }
    if profile["report_format"] not in formats.get(profile["engine"], set()):
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_PROFILE", "unsupported native report"
        )
    if profile["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        if len(profile["commands"]) != 1:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_PROFILE", "runtime requires one bounded command"
            )
        if lane.get("native_artifact_roles") != ["coverage_json", "junit_xml"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_PROFILE", "runtime artifact roles differ"
            )
        if not isinstance(lane.get("rule_ids"), list) or not lane["rule_ids"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_ADAPTER_PROFILE", "runtime rule inventory required"
            )


def _native_version(
    profile: dict,
    source: _deep_audit_io.Path,
    scratch: _deep_audit_io.Path,
    timeout: int,
) -> dict:
    from .runtime_audit_process import run_bounded_command
    import re

    capture = scratch / "version.txt"
    facts = run_bounded_command(
        profile["version_argv"], source, timeout, scratch, stdout_path=capture
    )
    if (
        facts["exit_code"] != 0
        or facts["timed_out"]
        or facts["launch_error"]
        or facts["output_limit_exceeded"]
        or not facts["cleanup_confirmed"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TOOLCHAIN_PROBE", "native version probe failed"
        )
    text = capture.read_text(encoding="utf-8")
    pattern = r"(?<![\w.])v?" + re.escape(profile["tool_version"]) + r"(?![\w.])"
    if not re.search(pattern, text):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TOOLCHAIN_DRIFT", "native version differs"
        )
    return facts


def _native_argv(commands: list, bindings: dict) -> list:
    result = []
    for command in commands:
        argv = []
        for value in command["argv"]:
            for name, bound in bindings.items():
                value = value.replace("{" + name + "}", str(bound))
            argv.append(value)
        _deep_audit_io._adapter_command_shape(
            {"argv": argv, "accepted_exit_codes": command["accepted_exit_codes"]}
        )
        result.append(
            {"argv": argv, "accepted_exit_codes": command["accepted_exit_codes"]}
        )
    return result


def _gitleaks_rule_inventory(config: bytes, lane: dict) -> dict:
    """Bind the signed rule IDs to the exact TOML consumed by the pinned worker."""
    actual = _deep_audit_io._gitleaks_rule_ids(config)
    expected = lane.get("rule_ids")
    if not isinstance(expected, list) or not expected:
        return {"state": "UNAVAILABLE", "rule_ids": [], "sha256": None}
    if _deep_audit_io.sha256_bytes(config) != lane["ruleset_sha256"]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_RULESET", "pinned ruleset bytes differ"
        )
    if len(actual) != len(set(actual)) or set(actual) != set(expected):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_RULESET", "enabled rule inventory differs"
        )
    identity = {"ruleset_sha256": lane["ruleset_sha256"], "rule_ids": sorted(actual)}
    return {
        "state": "VERIFIED",
        "rule_ids": sorted(actual),
        "sha256": _deep_audit_io.digest(identity),
    }


def _gitleaks_rule_ids(config: bytes) -> list[str]:
    toml = _deep_audit_io._toml_parser()

    try:
        rules = toml.loads(config.decode("utf-8"))["rules"]
        actual = [item["id"] for item in rules]
    except (UnicodeError, KeyError, TypeError, toml.TOMLDecodeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_RULESET", "pinned ruleset is malformed"
        ) from exc
    if not all(isinstance(rule_id, str) and rule_id for rule_id in actual):
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_RULESET", "enabled rule inventory differs"
        )
    return actual


def _gitleaks_disable_rule(config: bytes, detector_rule_id: str) -> bytes:
    import re

    toml = _deep_audit_io._toml_parser()

    starts = [
        item.start()
        for item in re.finditer(rb"(?m)^\[\[rules\]\][\t ]*(?:\r?\n|$)", config)
    ]
    if not starts:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_MUTATION", "rules section missing"
        )
    chunks = [config[: starts[0]]]
    removed = 0
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(config)
        chunk = config[start:end]
        try:
            rule_id = toml.loads(chunk.decode("utf-8"))["rules"][0]["id"]
        except (
            UnicodeError,
            KeyError,
            IndexError,
            TypeError,
            toml.TOMLDecodeError,
        ) as exc:
            raise _deep_audit_io.RuntimeAuditError(
                "E_GITLEAKS_MUTATION", "rule block malformed"
            ) from exc
        if rule_id == detector_rule_id:
            removed += 1
        else:
            chunks.append(chunk)
    mutated = b"".join(chunks)
    original_ids = _deep_audit_io._gitleaks_rule_ids(config)
    expected = [rule_id for rule_id in original_ids if rule_id != detector_rule_id]
    if removed != 1 or _deep_audit_io._gitleaks_rule_ids(mutated) != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_GITLEAKS_MUTATION", "mutation must disable one rule"
        )
    return mutated


def _toml_parser():
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError as exc:
            raise _deep_audit_io.RuntimeAuditError(
                "E_GITLEAKS_RULESET", "TOML parser is unavailable"
            ) from exc
    return tomllib


def _gitleaks_mutation_valid(
    baseline: bytes, effective: bytes, detector_rule_id: str
) -> bool:
    try:
        return (
            _deep_audit_io._gitleaks_disable_rule(baseline, detector_rule_id)
            == effective
        )
    except _deep_audit_io.RuntimeAuditError:
        return False


def _fuzz_execution_contract(contract, source):
    if source == _deep_audit_io.Path("/src"):
        return contract
    bindings = {item["path"]: item for item in contract["inventory"]["files"]}
    names = _deep_audit_io._adapter_source_files(source)
    if not names or not names <= bindings.keys():
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "fixture source is not inventoried"
        )
    inventory = {
        **contract["inventory"],
        "files": [bindings[name] for name in sorted(names)],
    }
    _deep_audit_io._adapter_sources(source, inventory)
    return {**contract, "inventory": inventory}


def _fuzz_profile_preflight(profile, lane):
    if lane["engine"] != "atheris":
        return None
    path = _deep_audit_io.Path("/opt/factory/rules/fuzz-control.json")
    raw = path.read_bytes()
    if _deep_audit_io.sha256_bytes(raw) != profile[
        "ruleset_sha256"
    ] or _deep_audit_io._fuzz_control_ids(raw) != ["FUZZ_EXCEPTION"]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_FUZZ_CONTROL", "pinned baseline fuzz rule required"
        )
    return path


def _native_profile_challenges(profile, contract, source, lane, execution, started):
    challenges = {"schema": "factory.deep-challenges.v1", "observations": []}
    covered_obligations = []
    if lane["engine"] == "gitleaks":
        challenges, covered_obligations = _deep_audit_io._gitleaks_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "trivy":
        challenges, covered_obligations = _deep_audit_io._trivy_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "semgrep" and "native_artifact_roles" in lane:
        challenges, covered_obligations = _deep_audit_io._semgrep_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        challenges, covered_obligations = _deep_audit_io._runtime_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "codeql" and "native_artifact_roles" in lane:
        challenges, covered_obligations = _deep_audit_io._codeql_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "osv" and "native_policy" in lane:
        challenges, covered_obligations = _deep_audit_io._osv_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "atheris" and "native_artifact_roles" in lane:
        challenges, covered_obligations = _deep_audit_io._atheris_challenges(
            profile, contract, source, lane, execution, started
        )
    return challenges, covered_obligations


def _osv_config_rule_ids(raw, lane):
    policy = lane.get("native_policy", {})
    rules = lane.get("rule_ids", [])
    if raw == b"\n":
        return list(rules)
    for rule, aliases in policy.get("advisory_aliases", {}).items():
        if raw == _deep_audit_io._osv_suppression_bytes(aliases):
            return [item for item in rules if item != rule]
    raise _deep_audit_io.RuntimeAuditError(
        "E_OSV_POLICY", "unapproved suppression config"
    )


def _osv_mutation_valid(baseline, effective, rule_id, lane):
    try:
        policy = lane["native_policy"]
        aliases = policy["advisory_aliases"][rule_id]
        return (
            baseline == b"\n"
            and effective == _deep_audit_io._osv_suppression_bytes(aliases)
            and _deep_audit_io.sha256_bytes(effective)
            == lane["mutation_config_sha256"][rule_id]
        )
    except (KeyError, _deep_audit_io.RuntimeAuditError, TypeError, ValueError):
        return False


def _osv_profile_preflight(profile, lane):
    if (lane.get("engine"), lane.get("mode")) != (
        "osv",
        "offline-pypi-snapshot",
    ):
        return
    try:
        policy = _deep_audit_io.local_file(
            _deep_audit_io.Path("/opt/factory/rules"), "osv-scanner.toml"
        ).read_bytes()
    except (OSError, _deep_audit_io.RuntimeAuditError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_POLICY", "trusted OSV configuration unavailable"
        ) from exc
    _deep_audit_io._osv_policy_inputs(profile, policy)


def _osv_policy_inputs(profile, policy_bytes):
    expected = {
        "argv": [
            "/opt/factory/bin/osv-offline",
            "scan",
            "source",
            "-r",
            "{source}",
            "--config",
            "/opt/factory/rules/osv-scanner.toml",
            "--offline",
            "--offline-vulnerabilities",
            "--allow-no-lockfiles",
            "--all-packages",
            "--format",
            "json",
            "--output",
            "{report}",
        ],
        "accepted_exit_codes": [0, 1],
    }
    if profile.get("commands") != [expected] or policy_bytes != b"\n":
        raise _deep_audit_io.RuntimeAuditError(
            "E_OSV_POLICY", "baseline requires the trusted empty OSV configuration"
        )


def _osv_expected_policy(lane, obligation, kind):
    if kind != "mutation":
        return b"\n"
    aliases = lane["native_policy"]["advisory_aliases"][obligation["detector_rule_id"]]
    return _deep_audit_io._osv_suppression_bytes(aliases)


def _trivy_policy_inputs(config, ignore, lane):
    policy = lane.get("native_policy")
    if policy is None:
        return
    if _deep_audit_io.sha256_bytes(config) != policy.get(
        "config_sha256"
    ) or _deep_audit_io.sha256_bytes(ignore) != policy.get("baseline_ignore_sha256"):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_POLICY", "pinned Trivy policy bytes differ"
        )
    if _deep_audit_io._trivy_ignore_ids(ignore):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_POLICY", "baseline ignorefile must be empty"
        )


def _trivy_ignore_ids(config):
    try:
        text = config.decode("ascii")
    except (AttributeError, UnicodeDecodeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_POLICY", "Trivy ignorefile is malformed"
        ) from exc
    ids = text.splitlines()
    if not text.strip():
        return []
    if ids != sorted(set(ids)) or any(
        _deep_audit_io._trivy_rule_id_valid(item) is False for item in ids
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_POLICY", "Trivy ignore IDs are invalid"
        )
    return ids


def _trivy_rule_id_valid(rule_id):
    import re

    return (
        isinstance(rule_id, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", rule_id) is not None
    )


def _trivy_mutation(ignore, rule_id):
    if _deep_audit_io._trivy_ignore_ids(ignore):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_MUTATION", "baseline ignorefile is not empty"
        )
    if not _deep_audit_io._trivy_rule_id_valid(rule_id):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_MUTATION", "unsupported Trivy check ID"
        )
    return f"{rule_id}\n".encode("ascii")


def _trivy_mutation_valid(baseline, effective, rule_id):
    try:
        return _deep_audit_io._trivy_mutation(baseline, rule_id) == effective
    except (_deep_audit_io.RuntimeAuditError, ValueError, TypeError):
        return False


def _trivy_json_argv(sarif_argv, output_path):
    result = list(sarif_argv)
    try:
        format_index = result.index("--format") + 1
        output_index = result.index("--output") + 1
        if result[format_index] != "sarif":
            raise ValueError
        result[format_index] = "json"
        result[output_index] = str(output_path)
        result.insert(result.index("config") + 1, "--include-non-failures")
    except (ValueError, IndexError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_PROFILE", "pinned Trivy command differs"
        ) from exc
    return result


def _trivy_expected_ids(lane, disabled_rule_id):
    ids = lane.get("rule_ids")
    if not isinstance(ids, list) or not ids or ids != sorted(set(ids)):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_RULES", "signed Trivy check inventory is missing"
        )
    if disabled_rule_id is not None:
        if disabled_rule_id not in ids:
            raise _deep_audit_io.RuntimeAuditError(
                "E_TRIVY_MUTATION", "target is not a signed Trivy check"
            )
        ids = [item for item in ids if item != disabled_rule_id]
    return ids


def _trivy_matrix_ids(matrix, expected_ids):
    observed_ids = set().union(*(set(rows) for rows in matrix.values()))
    if observed_ids != set(expected_ids):
        raise _deep_audit_io.RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "signed Trivy check IDs differ"
        )


def _semgrep_rule_sources(rule, sources):
    languages = rule.get("languages")
    if (
        not isinstance(languages, list)
        or not languages
        or not set(languages) <= {"python", "javascript", "typescript", "php"}
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "unsupported pinned rule languages"
        )
    return {
        path
        for path in sources
        if _deep_audit_io.source_language(path, b"") in languages
        and not ("php" in languages and path.lower().endswith(".blade.php"))
    }


def _semgrep_scanned_sources(native, sources, lane):
    if (
        not isinstance(native, dict)
        or native.get("version") != lane["tool_version"]
        or native.get("errors") != []
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "native report failed or version drifted"
        )
    paths = native.get("paths", {}).get("scanned")
    if not isinstance(paths, list) or len(paths) > 64:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "bounded native scanned paths required"
        )
    observed = [_deep_audit_io._native_source_path(path, sources) for path in paths]
    if len(set(observed)) != len(observed):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "duplicate native source execution"
        )
    return set(observed)


def _codeql_query_preflight(profile, source, scratch, remaining, *, engine="codeql"):
    if engine != "codeql":
        return None
    if remaining < 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "query resolution deadline exhausted"
        )
    commands = profile.get("commands")
    if not isinstance(commands, list) or len(commands) < 2:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "analyze command required"
        )
    command = commands[1]
    argv = command.get("argv") if isinstance(command, dict) else None
    if not isinstance(argv, list) or len(argv) < 5:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "bounded analyze argv required"
        )
    if argv[1:3] != ["database", "analyze"] or not isinstance(argv[4], str):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "native analyze suite required"
        )
    return _deep_audit_io.resolve_codeql_query_inventory(
        argv[0], _deep_audit_io.Path(argv[4]), source, scratch, remaining
    )


def _codeql_suite_bytes(suite):
    with suite.open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576 or suite.is_symlink():
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "bounded regular suite required"
        )
    return raw


def resolve_codeql_query_inventory(codeql, suite, source, scratch, timeout):
    """Record native suite resolution and query bytes, not query execution coverage."""
    from .runtime_audit_process import run_bounded_command

    timeout = _deep_audit_io.require_int(
        timeout, "query resolution timeout", minimum=1, maximum=3600
    )
    suite = _deep_audit_io.local_file(
        _deep_audit_io.Path(suite).parent, _deep_audit_io.Path(suite).name
    )
    suite_raw = _deep_audit_io._codeql_suite_bytes(suite)
    run_root = _deep_audit_io.Path(scratch) / (
        "query-resolution-" + _deep_audit_io.uuid.uuid4().hex
    )
    run_root.mkdir()
    capture = run_root / "queries.json"
    argv = [str(codeql), "resolve", "queries", "--format=json", "--", str(suite)]
    deadline = _deep_audit_io.time.monotonic() + timeout
    facts = run_bounded_command(argv, source, timeout, run_root, stdout_path=capture)
    if _deep_audit_io._adapter_command_failed(facts, [0], deadline):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "native query resolution failed"
        )
    with capture.open("rb") as stream:
        raw = stream.read(1_048_577)
    if (
        len(raw) > 1_048_576
        or _deep_audit_io.sha256_bytes(raw) != facts["stdout_sha256"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "query resolution output differs"
        )
    try:
        paths = _deep_audit_io.json.loads(raw, parse_constant=_deep_audit_io._finite)
    except (ValueError, RecursionError, UnicodeError) as error:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "invalid query resolution JSON"
        ) from error
    queries = _deep_audit_io._codeql_resolved_queries(paths)
    if _deep_audit_io._codeql_suite_bytes(suite) != suite_raw:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "suite changed during resolution"
        )
    return dict(
        schema="factory.codeql-query-inventory.v1",
        suite_sha256=_deep_audit_io.sha256_bytes(suite_raw),
        queries=queries,
        query_ids=_deep_audit_io._codeql_query_ids(queries),
        query_inventory_sha256=_deep_audit_io.digest(queries),
        argv=argv,
        argv_sha256=_deep_audit_io.digest(argv),
        execution=facts,
        raw_resolution_sha256=_deep_audit_io.sha256_bytes(raw),
        claim_boundary="Native suite selection and query content identity only; not execution or source coverage",
    )


def _codeql_resolved_queries(paths):
    if not isinstance(paths, list) or not 1 <= len(paths) <= 1024:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "bounded nonempty query list required"
        )
    queries, total = {}, 0
    root = _deep_audit_io.Path("/opt/codeql/codeql/qlpacks")
    for value in paths:
        _deep_audit_io.require_str(value, "resolved query", maximum=2048)
        path = _deep_audit_io.Path(value)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_INVENTORY", "query is outside pinned packs"
            ) from error
        _deep_audit_io.relative_path(relative)
        if path.suffix != ".ql" or relative in queries:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_INVENTORY", "duplicate or non-query path"
            )
        with _deep_audit_io.local_file(root, relative).open("rb") as stream:
            raw = stream.read(1_048_577)
        total += len(raw)
        if len(raw) > 1_048_576 or total > 8_388_608:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_INVENTORY", "query content budget exceeded"
            )
        queries[relative] = _deep_audit_io.sha256_bytes(raw)
    return dict(sorted(queries.items()))


def verify_codeql_query_isolation(baseline, mutated, target_query):
    """Require exactly one removed query and unchanged nonempty sentinel inventory."""
    _deep_audit_io.relative_path(target_query)
    for inventory in (baseline, mutated):
        if not isinstance(inventory, dict) or not inventory:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_MUTATION", "query inventory required"
            )
        for path, seal in inventory.items():
            _deep_audit_io.relative_path(path)
            _deep_audit_io.require_digest(seal, "query content hash")
    expected = {path: seal for path, seal in baseline.items() if path != target_query}
    if target_query not in baseline or not expected or mutated != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_MUTATION", "mutation must remove only target query"
        )
    return dict(
        disabled_query=target_query,
        remaining_query_inventory_sha256=_deep_audit_io.digest(mutated),
    )


def _codeql_query_ids(queries):
    import re

    identifiers = {}
    root = _deep_audit_io.Path("/opt/codeql/codeql/qlpacks")
    for path, expected in queries.items():
        with _deep_audit_io.local_file(root, path).open("rb") as stream:
            raw = stream.read(1_048_577)
        if _deep_audit_io.sha256_bytes(raw) != expected:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_INVENTORY", "query changed during metadata read"
            )
        text = raw.decode("utf-8")
        ids = re.findall(r"(?m)^\s*\*\s*@id\s+([^\s]+)\s*$", text)
        if len(ids) != 1 or ids[0] in identifiers:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_INVENTORY", "unique native query ID required"
            )
        _deep_audit_io.require_str(ids[0], "native query ID", maximum=256)
        identifiers[ids[0]] = path
    return dict(sorted(identifiers.items()))


def _codeql_selection_shape(inventory):
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema") != "factory.codeql-query-inventory.v1"
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "native query inventory required"
        )
    queries, identifiers = inventory.get("queries"), inventory.get("query_ids")
    if not isinstance(queries, dict) or not 1 <= len(queries) <= 1024:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "bounded query map required"
        )
    for path, seal in queries.items():
        _deep_audit_io.relative_path(path)
        _deep_audit_io.require_digest(seal, "query content hash")
        if not path.startswith("codeql/") or not path.endswith(".ql"):
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_INVENTORY", "pinned query path required"
            )
    _deep_audit_io._codeql_selection_ids(identifiers, queries)
    _deep_audit_io.require_digest(inventory.get("suite_sha256"), "suite hash")
    if inventory.get("query_inventory_sha256") != _deep_audit_io.digest(queries):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "query inventory hash differs"
        )
    return queries, identifiers


def _codeql_selection_ids(identifiers, queries):
    if not isinstance(identifiers, dict) or len(identifiers) != len(queries):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "complete query ID map required"
        )
    for rule_id, path in identifiers.items():
        _deep_audit_io.require_str(rule_id, "native query ID", maximum=256)
        _deep_audit_io.relative_path(path)
    if set(identifiers.values()) != set(queries):
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "one-to-one query ID mapping required"
        )


def verify_codeql_query_selection(inventory, *, baseline=None, disabled_rule_id=None):
    """Validate selected query identity against a baseline, without claiming execution."""
    queries, identifiers = _deep_audit_io._codeql_selection_shape(inventory)
    if baseline is None:
        if disabled_rule_id is not None:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_MUTATION", "baseline required for mutation"
            )
        return
    original, original_ids = _deep_audit_io._codeql_selection_shape(baseline)
    if disabled_rule_id is not None:
        if disabled_rule_id not in original_ids:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_MUTATION", "target query ID absent"
            )
        _deep_audit_io.verify_codeql_query_isolation(
            original, queries, original_ids[disabled_rule_id]
        )
        expected_ids = {
            key: value for key, value in original_ids.items() if key != disabled_rule_id
        }
    else:
        expected_ids = original_ids
        if queries != original or inventory["suite_sha256"] != baseline["suite_sha256"]:
            raise _deep_audit_io.RuntimeAuditError(
                "E_CODEQL_INVENTORY", "baseline query selection differs"
            )
    if identifiers != expected_ids:
        raise _deep_audit_io.RuntimeAuditError(
            "E_CODEQL_INVENTORY", "query ID binding differs"
        )


def _semgrep_rule_ids(config):
    import yaml

    try:
        rules = yaml.safe_load(config)["rules"]
    except (yaml.YAMLError, KeyError, TypeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "invalid Semgrep rules"
        ) from exc
    if not isinstance(rules, list) or not 1 <= len(rules) <= 64:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "bounded Semgrep rules required"
        )
    ids = [
        _deep_audit_io.require_str(rule.get("id"), "rule id", maximum=256)
        for rule in rules
        if isinstance(rule, dict)
    ]
    if len(ids) != len(rules) or len(set(ids)) != len(ids):
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_RULESET", "invalid Semgrep rule IDs"
        )
    return sorted(ids)


def _semgrep_mutation_file(case, baseline, lane, obligation):
    mutation = _deep_audit_io._semgrep_disable_rule(
        baseline, obligation["detector_rule_id"]
    )
    expected = lane.get("mutation_config_sha256", {}).get(
        obligation["detector_rule_id"]
    )
    if _deep_audit_io.sha256_bytes(mutation) != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_MUTATION", "signed target removal differs"
        )
    path = case / "mutation.yml"
    path.write_bytes(mutation)
    return path


def _semgrep_disable_rule(config, rule_id):
    import yaml

    try:
        document = yaml.safe_load(config)
        rules = document["rules"]
    except (yaml.YAMLError, KeyError, TypeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_MUTATION", "pinned ruleset malformed"
        ) from exc
    before = _deep_audit_io._semgrep_rule_ids(config)
    if before.count(rule_id) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_MUTATION", "target rule not unique"
        )
    document["rules"] = [item for item in rules if item.get("id") != rule_id]
    mutated = yaml.safe_dump(document, sort_keys=True).encode("utf-8")
    expected = [item for item in before if item != rule_id]
    if _deep_audit_io._semgrep_rule_ids(mutated) != expected:
        raise _deep_audit_io.RuntimeAuditError(
            "E_SEMGREP_MUTATION", "mutation removed extra rules"
        )
    return mutated


def _semgrep_mutation_valid(baseline, effective, rule_id):
    try:
        return _deep_audit_io._semgrep_disable_rule(baseline, rule_id) == effective
    except _deep_audit_io.RuntimeAuditError:
        return False


def _runtime_ruleset_preflight(lane):
    config_path = _deep_audit_io.Path("/opt/factory/rules/runtime-control.toml")
    _deep_audit_io._runtime_rule_inventory(config_path.read_bytes(), lane)


def _runtime_rule_ids(config):
    toml = _deep_audit_io._toml_parser()
    try:
        value = toml.loads(config.decode("utf-8"))
        selectors = value["selectors"]
        if selectors != {"RUNTIME_TEST_FAILURE": "factory_runtime_failure"}:
            raise ValueError
        rules = value.get("rules", [])
        actual = [item["id"] for item in rules]
    except (UnicodeError, KeyError, TypeError, ValueError, toml.TOMLDecodeError) as exc:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_RULESET", "runtime controls are malformed"
        ) from exc
    if actual not in ([], ["RUNTIME_TEST_FAILURE"]):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_RULESET", "runtime rule inventory differs"
        )
    return actual


def _runtime_rule_inventory(config, lane):
    actual = _deep_audit_io._runtime_rule_ids(config)
    if (
        _deep_audit_io.sha256_bytes(config) != lane.get("ruleset_sha256")
        or lane.get("rule_ids") != ["RUNTIME_TEST_FAILURE"]
        or actual != lane["rule_ids"]
    ):
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_RULESET", "pinned runtime controls differ"
        )
    return {
        "state": "VERIFIED",
        "rule_ids": actual,
        "sha256": _deep_audit_io.digest(actual),
    }


def _runtime_mutation_valid(baseline, effective, rule_id):
    return (
        rule_id == "RUNTIME_TEST_FAILURE"
        and _deep_audit_io._runtime_disable_rule(baseline, rule_id) == effective
        and _deep_audit_io._runtime_rule_ids(effective) == []
    )


def _runtime_disable_rule(config, rule_id):
    import re

    if rule_id != "RUNTIME_TEST_FAILURE" or _deep_audit_io._runtime_rule_ids(
        config
    ) != [rule_id]:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_MUTATION", "exact runtime rule required"
        )
    starts = [
        item.start()
        for item in re.finditer(rb"(?m)^\[\[rules\]\][\t ]*(?:\r?\n|$)", config)
    ]
    if len(starts) != 1:
        raise _deep_audit_io.RuntimeAuditError(
            "E_RUNTIME_MUTATION", "one runtime rule block required"
        )
    return config[: starts[0]]

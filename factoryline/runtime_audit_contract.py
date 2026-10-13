"""Verification of externally signed six-lane runtime audit plans."""

from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import os
import re
import stat
from pathlib import PureWindowsPath
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

from .enterprise_receipts import EnterpriseReceiptError, verify_signed_document
from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    exact_keys,
    require_digest,
    require_int,
    require_str,
    require_bool,
    sha256_bytes,
    read_stable_json,
    parse_json_bytes,
)
from .runtime_audit_policy import ENGINES, validate_lane_policy
from .runtime_attestation import ISOLATION_MODES
from .intake_parameters import verify_intake_binding

MAX_RUNTIME_SOURCE_BYTES = 100_000_000


def _hash_regular_file_bounded(path: Path, maximum_bytes: int) -> tuple[str, int]:
    """Hash a lexical regular file with a strict byte budget and stable identity."""
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or not 0 <= maximum_bytes <= MAX_RUNTIME_SOURCE_BYTES
    ):
        raise RuntimeAuditError("E_SOURCE_SIZE", "source byte budget is invalid")
    lexical = Path(path)
    if lexical.is_symlink():
        raise RuntimeAuditError("E_SOURCE_TYPE", "source must not be a symlink")
    before = lexical.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(before.st_mode)
        or getattr(before, "st_file_attributes", 0) & 0x400
    ):
        raise RuntimeAuditError("E_SOURCE_TYPE", "source must be a regular file")
    digest = hashlib.sha256()
    count = 0
    with lexical.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or _file_identity(opened) != _file_identity(
            before
        ):
            raise RuntimeAuditError(
                "E_SOURCE_CHANGED", "source identity changed before read"
            )
        while count <= maximum_bytes:
            block = stream.read(min(1024 * 1024, maximum_bytes + 1 - count))
            if not block:
                break
            count += len(block)
            digest.update(block)
        after = os.fstat(stream.fileno())
    final = lexical.stat(follow_symlinks=False)
    if _file_identity(before) != _file_identity(after) or _file_identity(
        after
    ) != _file_identity(final):
        raise RuntimeAuditError(
            "E_SOURCE_CHANGED", "source identity changed during read"
        )
    if count > maximum_bytes:
        raise RuntimeAuditError("E_SOURCE_SIZE", "source exceeds its byte budget")
    return digest.hexdigest(), count


def _file_identity(info) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


PLAN_TYPE = "application/vnd.factory.runtime-audit-plan.v1+json"
PLAN_SCHEMA = "factory.runtime-audit-plan.v1"
LANES = (
    "stateful_invariant",
    "tenant_isolation",
    "failure_recovery",
    "consumer_compatibility",
    "migration_integrity",
    "performance_regression",
)
MESH_RELATIONS = {
    "same_business_operation",
    "same_tenant_boundary",
    "same_consumer_contract",
    "same_data_shape",
    "same_runtime_environment",
}
AUTHORITATIVE_ORIGINS = {"human_confirmed", "trusted_source", "observed_production"}


def _time(value: object, field: str) -> datetime:
    text = require_str(value, field, maximum=40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeAuditError("E_TIME", f"invalid {field}") from exc
    if parsed.tzinfo is None:
        raise RuntimeAuditError("E_TIME", f"{field} needs a timezone")
    return parsed.astimezone(timezone.utc)


def _relative_file(root: Path, relative: object, field: str) -> Path:
    text = require_str(relative, field, maximum=512)
    if (
        Path(text).is_absolute()
        or PureWindowsPath(text).drive
        or ".." in text.replace("\\", "/").split("/")
        or ":" in text
    ):
        raise RuntimeAuditError("E_PATH_ESCAPE", text)
    lexical = root / text
    cursor = root
    for part in text.replace("\\", "/").split("/"):
        cursor = cursor / part
        try:
            info = cursor.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimeAuditError("E_SOURCE_MISSING", text) from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError(
                "E_SOURCE_TYPE", "source path must not contain a reparse point"
            )
    candidate = lexical.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise RuntimeAuditError("E_PATH_ESCAPE", text) from exc
    if not candidate.is_file():
        raise RuntimeAuditError("E_SOURCE_MISSING", text)
    return lexical


def _argv(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise RuntimeAuditError("E_ARGV", f"{field} must contain 1..64 arguments")
    result = [require_str(item, f"{field}[]", maximum=1024) for item in value]
    if sum(item == "{artifact}" for item in result) != 1:
        raise RuntimeAuditError(
            "E_ARGV", f"{field} must contain one exact {{artifact}} token"
        )
    if result[0] == "{artifact}" or any(
        "{artifact}" in item and item != "{artifact}" for item in result
    ):
        raise RuntimeAuditError(
            "E_ARGV",
            "artifact placeholder must be one standalone non-executable argument",
        )
    if Path(result[0]).name.lower() in {
        "sh",
        "bash",
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
    } or result[0].lower().endswith((".bat", ".cmd")):
        raise RuntimeAuditError("E_ARGV", "shell command wrappers are not permitted")
    return result


def _loopback(origin: str) -> bool:
    parsed = urlparse(origin)
    return parsed.scheme in {"http", "https"} and parsed.hostname in {
        "127.0.0.1",
        "localhost",
        "::1",
    }


def _plan_environment(plan, environment_digest):
    environment = plan["environment"]
    if not isinstance(environment, dict):
        raise RuntimeAuditError("E_ENVIRONMENT", "environment must be an object")
    exact_keys(environment, {"kind", "digest", "origins"})
    if environment["kind"] not in {"local_test", "isolated_test"}:
        raise RuntimeAuditError("E_ENVIRONMENT", "unsupported environment kind")
    digest = require_digest(environment["digest"], "environment.digest")
    if digest != require_digest(environment_digest, "environment_digest"):
        raise RuntimeAuditError(
            "E_ENVIRONMENT_DRIFT",
            "runtime environment digest differs from the signed plan",
        )
    origins = environment["origins"]
    if (
        not isinstance(origins, list)
        or not 0 <= len(origins) <= 32
        or not all(isinstance(item, str) for item in origins)
    ):
        raise RuntimeAuditError("E_ENVIRONMENT", "origins must contain 0..32 strings")
    if environment["kind"] == "local_test" and any(
        not _loopback(item) for item in origins
    ):
        raise RuntimeAuditError(
            "E_NONLOCAL_TARGET", "local_test permits loopback HTTP origins only"
        )
    _plan_origins(origins)
    if len(set(origins)) != len(origins):
        raise RuntimeAuditError("E_DUPLICATE_ID", "duplicate origins")

    return digest


def _plan_origins(origins):
    for origin in origins:
        parsed = urlparse(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise RuntimeAuditError(
                "E_ENVIRONMENT", "origins must be credential-free HTTP(S) origins"
            )


def _plan_boundary(plan):
    # This optional block is the only way a signed plan can request a runtime
    # boundary.  Older six-lane plans remain wire-compatible; new strict plans
    # must make the requested assurance explicit before execution starts.
    boundary = plan.get("runtime_boundary")
    if boundary is not None:
        if not isinstance(boundary, dict):
            raise RuntimeAuditError(
                "E_RUNTIME_BOUNDARY", "runtime_boundary must be an object"
            )
        exact_keys(boundary, {"requested_isolation", "attestation_required"})
        if boundary["requested_isolation"] not in ISOLATION_MODES:
            raise RuntimeAuditError(
                "E_RUNTIME_BOUNDARY", "unsupported requested isolation"
            )
        require_bool(
            boundary["attestation_required"], "runtime_boundary.attestation_required"
        )
        if boundary["attestation_required"] is not True:
            raise RuntimeAuditError(
                "E_RUNTIME_BOUNDARY",
                "runtime boundary evidence must be required explicitly",
            )
        if (
            boundary["requested_isolation"] in {"isolated_worker", "hardened_vm"}
            and boundary["attestation_required"] is not True
        ):
            raise RuntimeAuditError(
                "E_RUNTIME_BOUNDARY", "independent isolation requires an attestation"
            )


def _plan_execution_policy(plan):
    policy = plan.get("execution_policy")
    if policy is None:
        return {"max_parallelism": 1, "non_mutating": False, "resource_safe": False}
    if not isinstance(policy, dict):
        raise RuntimeAuditError(
            "E_EXECUTION_POLICY", "execution_policy must be an object"
        )
    exact_keys(policy, {"max_parallelism", "non_mutating", "resource_safe"})
    maximum = require_int(
        policy["max_parallelism"],
        "execution_policy.max_parallelism",
        minimum=1,
        maximum=8,
    )
    non_mutating = require_bool(policy["non_mutating"], "execution_policy.non_mutating")
    resource_safe = require_bool(
        policy["resource_safe"], "execution_policy.resource_safe"
    )
    if maximum > 1 and not (non_mutating and resource_safe):
        raise RuntimeAuditError(
            "E_EXECUTION_POLICY",
            "parallel execution requires non_mutating and resource_safe declarations",
        )
    return {
        "max_parallelism": maximum,
        "non_mutating": non_mutating,
        "resource_safe": resource_safe,
    }


def _plan_sources(plan, root):
    sources = plan["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 128:
        raise RuntimeAuditError("E_SOURCES", "sources must contain 1..128 bindings")
    source_ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            raise RuntimeAuditError("E_SOURCES", "source binding must be an object")
        exact_keys(source, {"path", "sha256", "bytes"})
        relative = require_str(source["path"], "sources.path", maximum=512)
        if relative in source_ids:
            raise RuntimeAuditError("E_DUPLICATE_ID", relative)
        source_ids.add(relative)
        source_path = _relative_file(root, relative, "sources.path")
        declared_bytes = require_int(
            source["bytes"],
            "sources.bytes",
            minimum=0,
            maximum=MAX_RUNTIME_SOURCE_BYTES,
        )
        actual_digest, actual_bytes = _hash_regular_file_bounded(
            source_path, declared_bytes
        )
        if actual_bytes != declared_bytes:
            raise RuntimeAuditError("E_SOURCE_DRIFT", relative)
        if actual_digest != require_digest(source["sha256"], "sources.sha256"):
            raise RuntimeAuditError("E_SOURCE_DRIFT", relative)
    if plan["candidate_sha256"] != sha256_bytes(
        canonical_bytes(sorted(sources, key=lambda s: s["path"]))
    ):
        raise RuntimeAuditError(
            "E_CANDIDATE_BINDING",
            "candidate digest must bind the sorted source manifest",
        )

    return sources


def _plan_mesh(plan):
    mesh = plan["counterfactual_mesh"]
    if not isinstance(mesh, dict):
        raise RuntimeAuditError(
            "E_COUNTERFACTUAL_MESH", "counterfactual_mesh must be an object"
        )
    exact_keys(mesh, {"id", "scenario_sha256", "relations", "origin"})
    require_str(mesh["id"], "counterfactual_mesh.id", maximum=128)
    require_digest(mesh["scenario_sha256"], "counterfactual_mesh.scenario_sha256")
    relations = mesh["relations"]
    if (
        not isinstance(relations, list)
        or not 2 <= len(relations) <= len(MESH_RELATIONS)
        or len(set(relations)) != len(relations)
        or any(item not in MESH_RELATIONS for item in relations)
    ):
        raise RuntimeAuditError(
            "E_COUNTERFACTUAL_MESH", "mesh needs 2..5 distinct supported relations"
        )
    if mesh["origin"] not in AUTHORITATIVE_ORIGINS:
        raise RuntimeAuditError(
            "E_COUNTERFACTUAL_AUTHORITY",
            "agent-proposed mesh scenarios cannot release work",
        )


def _plan_lanes(plan):
    lanes = plan["lanes"]
    if not isinstance(lanes, list) or len(lanes) != 6:
        raise RuntimeAuditError("E_LANES", "exactly six lanes are required")
    seen_ids: set[str] = set()
    seen_kinds: set[str] = set()
    for lane in lanes:
        if not isinstance(lane, dict):
            raise RuntimeAuditError("E_LANE", "lane must be an object")
        exact_keys(
            lane,
            {
                "id",
                "kind",
                "engine",
                "engine_version",
                "timeout_seconds",
                "target_argv",
                "known_bad_argv",
                "expected_negative_code",
                "config",
            },
        )
        lane_id = require_str(lane["id"], "lane.id", maximum=128)
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", lane_id):
            raise RuntimeAuditError(
                "E_LANE_ID", "lane IDs must be safe lowercase path segments"
            )
        kind = require_str(lane["kind"], "lane.kind", maximum=64)
        if lane_id in seen_ids or kind in seen_kinds:
            raise RuntimeAuditError("E_DUPLICATE_ID", lane_id)
        seen_ids.add(lane_id)
        seen_kinds.add(kind)
        _plan_lane_engine(lane, kind)
    if seen_kinds != set(LANES):
        raise RuntimeAuditError("E_LANES", f"required lane kinds are {list(LANES)}")
    return lanes


def _plan_lane_engine(lane, kind):
    if require_str(lane["engine"], "lane.engine", maximum=80) not in ENGINES.get(
        kind, set()
    ):
        raise RuntimeAuditError("E_ENGINE", "engine is not supported for the lane")
    require_str(lane["engine_version"], "lane.engine_version", maximum=80)
    require_int(lane["timeout_seconds"], "lane.timeout_seconds", minimum=1, maximum=300)
    _argv(lane["target_argv"], "lane.target_argv")
    _argv(lane["known_bad_argv"], "lane.known_bad_argv")
    require_str(
        lane["expected_negative_code"], "lane.expected_negative_code", maximum=128
    )
    if not isinstance(lane["config"], dict):
        raise RuntimeAuditError("E_LANE", "lane config must be an object")
    validate_lane_policy(kind, lane["config"])
    if lane["target_argv"] == lane["known_bad_argv"]:
        raise RuntimeAuditError(
            "E_NEGATIVE_CONTROL", "target and known-bad commands must be distinct"
        )


def _plan_intake(plan, root, sources, lanes, require_intake):
    intake_binding = plan.get("intake_parameters")
    if intake_binding is None:
        if require_intake:
            raise RuntimeAuditError(
                "E_INTAKE_BINDING_REQUIRED",
                "strict runtime admission requires a signed intake_parameters binding",
            )
    else:
        if not isinstance(intake_binding, dict):
            raise RuntimeAuditError(
                "E_INTAKE_BINDING_INVALID", "intake_parameters must be an object"
            )
        exact_keys(intake_binding, {"path", "parameter_sha256", "external_effects"})
        binding_path = require_str(
            intake_binding["path"], "intake_parameters.path", maximum=512
        )
        if (
            Path(binding_path).is_absolute()
            or PureWindowsPath(binding_path).drive
            or ".." in binding_path.replace("\\", "/").split("/")
        ):
            raise RuntimeAuditError(
                "E_INTAKE_BINDING_INVALID",
                "intake_parameters.path must remain workspace-relative",
            )
        binding_digest = require_digest(
            intake_binding["parameter_sha256"], "intake_parameters.parameter_sha256"
        )
        effects = require_str(
            intake_binding["external_effects"],
            "intake_parameters.external_effects",
            maximum=32,
        )
        if effects not in {"local_only", "human_controlled"}:
            raise RuntimeAuditError(
                "E_INTAKE_BINDING_INVALID",
                "intake_parameters.external_effects is unsupported",
            )
        scope_paths = [item["path"] for item in sources]
        max_wall = sum(item["timeout_seconds"] for item in lanes)
        binding = verify_intake_binding(
            root,
            Path(binding_path),
            scope_paths=scope_paths,
            required_lanes=list(LANES),
            budgets={"max_wall_seconds": max_wall},
            external_effects=effects,
            expires_at=plan["expires_at"],
            binding_sha256=binding_digest,
        )
        if not binding.get("ok"):
            first = (
                binding.get("errors")
                or [
                    {
                        "code": "E_INTAKE_PARAMETER_DRIFT",
                        "detail": "intake binding failed",
                    }
                ]
            )[0]
            raise RuntimeAuditError(
                str(first.get("code", "E_INTAKE_PARAMETER_DRIFT")),
                str(first.get("detail", "intake binding failed")),
            )
    return intake_binding


def _plan_lifetime(plan, now):
    exact_keys(
        plan,
        {
            "schema",
            "id",
            "candidate_sha256",
            "issued_at",
            "expires_at",
            "environment",
            "sources",
            "lanes",
            "counterfactual_mesh",
        },
        optional={"runtime_boundary", "intake_parameters", "execution_policy"},
    )
    require_str(plan["id"], "id", maximum=128)
    require_digest(plan["candidate_sha256"], "candidate_sha256")
    issued = _time(plan["issued_at"], "issued_at")
    expires = _time(plan["expires_at"], "expires_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if issued > current:
        raise RuntimeAuditError("E_FUTURE_PLAN", "issued_at is in the future")
    if expires <= current or (expires - issued).total_seconds() > 86_400:
        raise RuntimeAuditError(
            "E_PLAN_EXPIRED", "plan is expired or valid for more than 24 hours"
        )


def verify_runtime_audit_plan(
    path: Path,
    trust_root_path: Path,
    trust_root_sha256: str,
    workspace_root: Path,
    environment_digest: str,
    *,
    now: datetime | None = None,
    require_intake: bool = False,
) -> dict[str, Any]:
    """Verify a signed, expiring six-lane plan, its trust pin, sources, scenario, and environment binding."""
    root = Path(workspace_root).resolve()
    trust_path = Path(trust_root_path).resolve()
    expected_trust = require_digest(trust_root_sha256, "trust_root_sha256")
    _, trust_digest = read_stable_json(trust_path)
    if trust_digest != expected_trust:
        raise RuntimeAuditError(
            "E_TRUST_ROOT_DRIFT", "trust-root bytes do not match the operator pin"
        )
    envelope, envelope_digest = read_stable_json(
        Path(path), max_string_length=1_048_576
    )
    try:
        encoded = envelope["payload"]
        raw_payload = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        parsed_payload = parse_json_bytes(raw_payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeAuditError("E_PAYLOAD", "invalid strict signed payload") from exc
    try:
        verified = verify_signed_document(
            Path(path),
            payload_type=PLAN_TYPE,
            schema=PLAN_SCHEMA,
            trust_root_path=trust_path,
        )
    except (EnterpriseReceiptError, OSError) as exc:
        raise RuntimeAuditError(getattr(exc, "code", "E_SIGNATURE"), str(exc)) from exc
    plan = verified["payload"]
    if (
        plan != parsed_payload
        or read_stable_json(trust_path)[1] != trust_digest
        or read_stable_json(Path(path), max_string_length=1_048_576)[1]
        != envelope_digest
    ):
        raise RuntimeAuditError(
            "E_INPUT_CHANGED", "signed inputs changed while verifying"
        )
    _plan_lifetime(plan, now)
    execution_policy = _plan_execution_policy(plan)
    digest = _plan_environment(plan, environment_digest)
    _plan_boundary(plan)
    sources = _plan_sources(plan, root)
    _plan_mesh(plan)
    lanes = _plan_lanes(plan)
    intake_binding = _plan_intake(plan, root, sources, lanes, require_intake)
    source_manifest_sha256 = sha256_bytes(
        canonical_bytes(sorted(sources, key=lambda item: item["path"]))
    )
    return {
        "schema": "factory.runtime-audit-plan-verification.v1",
        "verification": verified["verification"],
        "payload_sha256": verified["payload_sha256"],
        "source_manifest_sha256": sha256_bytes(
            canonical_bytes(sorted(sources, key=lambda item: item["path"]))
        ),
        "trust_root_sha256": expected_trust,
        "environment_digest": digest,
        "plan": plan,
        "execution_policy": execution_policy,
        "execution_admission": {
            "payload_sha256": verified["payload_sha256"],
            "plan_canonical_sha256": sha256_bytes(canonical_bytes(plan)),
            "source_manifest_sha256": source_manifest_sha256,
            "environment_sha256": digest,
            "max_parallelism": execution_policy["max_parallelism"],
            "non_mutating": execution_policy["non_mutating"],
            "resource_safe": execution_policy["resource_safe"],
        },
        "intake_parameters": intake_binding,
        "authority": "none",
    }

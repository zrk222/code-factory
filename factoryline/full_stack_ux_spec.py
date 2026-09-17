"""Strict, provider-neutral validation for the Full-Stack UX Harness SSAT.

The repository's checked-in ``full-stack-ux-harness-v1.ssat.yaml`` predates the
mobile evidence contract.  This adapter accepts that established SSAT shape and
the explicit ``code-factory.io/v1alpha1`` shape from the public integration
blueprint, then emits one canonical, hash-bound receipt.  It validates contract
structure only; it never executes Xcode, Gradle, Fastlane, a device cloud, or a
store provider.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import tempfile
from typing import Any

import yaml


SPEC_SCHEMA = "factory.full-stack-ux-harness.spec.v1"
RECEIPT_SCHEMA = "factory.full-stack-ux-harness.spec-receipt.v1"
DIRECT_API_VERSION = "code-factory.io/v1alpha1"
DIRECT_KIND = "FullStackUXHarness"
LEGACY_FEATURE = "full-stack-ux-harness-v1"
MAX_BYTES = 1_048_576
MAX_ITEMS = 64
SHA256_RE = re.compile(r"^(?:sha256:)?[0-9a-fA-F]{64}$")

MOBILE_CATEGORIES = (
    "visual_media",
    "privacy_to_listing",
    "release_chain",
    "design_system",
    "production_signal",
    "android_parity",
)

MOBILE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "visual_media": (
        "snapshot",
        "device_frames",
        "layout",
        "contrast",
        "accessibility",
        "store_assets",
    ),
    "privacy_to_listing": (
        "permissions",
        "privacy_manifest",
        "tracking_disclosure",
        "entitlements",
        "runtime_network",
        "listing_metadata",
    ),
    "release_chain": (
        "build",
        "signing",
        "upload",
        "processing",
        "tester_group",
        "tester_invitation",
        "review_submission",
        "store_decision",
    ),
    "design_system": (
        "design_system_conformance",
        "hierarchy_rules",
        "user_design_input",
    ),
    "production_signal": ("crash_free_rate", "anr_rate", "hang_rate", "startup_ms"),
    "android_parity": (
        "build",
        "tests",
        "adaptive_layout",
        "accessibility",
        "r8_permissions",
        "play_metadata",
    ),
}

LEGACY_REQUIREMENTS = frozenset(
    {
        "REQ_HARNESS_CLOSED_SET",
        "REQ_HARNESS_PROVENANCE",
        "REQ_HARNESS_HUMAN_BOUNDARY",
        "REQ_HARNESS_ROUTING",
    }
)


class FullStackUXSpecError(ValueError):
    """Stable fail-closed error for an unavailable or unsafe SSAT source."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class _UniqueKeyLoader(yaml.SafeLoader):
    """PyYAML loader that refuses ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise FullStackUXSpecError(
                "E_UX_SPEC_DUPLICATE_KEY", f"duplicate YAML key: {key}"
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(
        value if isinstance(value, bytes) else _canonical(value)
    ).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: object, field: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise FullStackUXSpecError(
            "E_UX_SPEC_FIELD_INVALID", f"{field} must be a non-empty bounded string"
        )
    return value.strip()


def _mapping(
    value: object, field: str, expected: set[str], *, optional: set[str] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FullStackUXSpecError("E_UX_SPEC_SCHEMA", f"{field} must be an object")
    optional = optional or set()
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected - optional)
    if missing or unexpected:
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA",
            f"{field} keys invalid; missing={missing}, unexpected={unexpected}",
        )
    return value


def _bool(value: object, field: str, *, default: bool | None = None) -> bool:
    if value is None and default is not None:
        return default
    if not isinstance(value, bool):
        raise FullStackUXSpecError(
            "E_UX_SPEC_FIELD_INVALID", f"{field} must be boolean"
        )
    return value


def _sha256(value: object, field: str) -> str:
    result = _text(value, field, limit=71)
    if not SHA256_RE.fullmatch(result):
        raise FullStackUXSpecError(
            "E_UX_SPEC_HASH_INVALID", f"{field} must be a SHA-256 digest"
        )
    return result.lower()


def _relative_path(root: Path, value: object, field: str) -> str:
    raw = _text(value, field, limit=512)
    relative = Path(raw)
    if relative.is_absolute() or PureWindowsPath(raw).drive or ".." in relative.parts:
        raise FullStackUXSpecError(
            "E_UX_SPEC_PATH_REJECTED", f"{field} must stay inside the workspace"
        )
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise FullStackUXSpecError(
            "E_UX_SPEC_PATH_REJECTED", f"{field} escapes the workspace"
        ) from exc
    return relative.as_posix()


def _safe_source(root: Path, spec_path: Path) -> tuple[dict[str, Any], Path, bytes]:
    workspace = Path(root).resolve()
    source = spec_path if spec_path.is_absolute() else workspace / spec_path
    source = source.resolve()
    try:
        source.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXSpecError(
            "E_UX_SPEC_PATH_REJECTED", "specification must stay inside the workspace"
        ) from exc
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise FullStackUXSpecError(
            "E_UX_SPEC_INPUT_UNAVAILABLE",
            f"cannot read specification: {source.relative_to(workspace).as_posix()}",
        ) from exc
    if not data or len(data) > MAX_BYTES:
        raise FullStackUXSpecError(
            "E_UX_SPEC_INPUT_SIZE", f"specification must contain 1 to {MAX_BYTES} bytes"
        )
    try:
        value = yaml.load(data.decode("utf-8-sig"), Loader=_UniqueKeyLoader)
    except FullStackUXSpecError:
        raise
    except (UnicodeError, yaml.YAMLError) as exc:
        raise FullStackUXSpecError(
            "E_UX_SPEC_YAML", "specification must be valid UTF-8 YAML"
        ) from exc
    if not isinstance(value, dict):
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", "specification must be a mapping"
        )
    return value, source, data


def _categories(*, source: str) -> list[dict[str, Any]]:
    return [
        {
            "category": category,
            "required_evidence": list(MOBILE_REQUIREMENTS[category]),
            "source": source,
        }
        for category in MOBILE_CATEGORIES
    ]


def _direct_normalize(
    root: Path, value: dict[str, Any], spec_name: str
) -> dict[str, Any]:
    _mapping(
        value,
        "specification",
        {"apiVersion", "kind", "metadata", "harnessConfig", "triageRules"},
    )
    if (
        value.get("apiVersion") != DIRECT_API_VERSION
        or value.get("kind") != DIRECT_KIND
    ):
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA",
            f"apiVersion/kind must be {DIRECT_API_VERSION}/{DIRECT_KIND}",
        )
    metadata = _mapping(
        value["metadata"],
        "metadata",
        {"name", "targetAppId", "version"},
        optional={"specFile"},
    )
    name = _text(metadata.get("name"), "metadata.name", limit=128)
    target = _text(metadata.get("targetAppId"), "metadata.targetAppId", limit=256)
    version = _text(metadata.get("version"), "metadata.version", limit=64)
    spec_file = _text(
        metadata.get("specFile", spec_name), "metadata.specFile", limit=256
    )

    config = _mapping(
        value["harnessConfig"],
        "harnessConfig",
        {
            "visualMedia",
            "privacyToListing",
            "releaseChain",
            "designSystem",
            "productionSignal",
            "androidParity",
        },
    )
    visual = _mapping(
        config["visualMedia"],
        "harnessConfig.visualMedia",
        {"storyboardManifest", "screenshotPaths"},
        optional={"requireIpadMedia"},
    )
    screenshot_paths = visual.get("screenshotPaths")
    if (
        not isinstance(screenshot_paths, list)
        or not 1 <= len(screenshot_paths) <= MAX_ITEMS
    ):
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA",
            "harnessConfig.visualMedia.screenshotPaths must contain 1-64 paths",
        )
    visual_norm = {
        "storyboardManifest": _relative_path(
            root,
            visual.get("storyboardManifest"),
            "harnessConfig.visualMedia.storyboardManifest",
        ),
        "requireIpadMedia": _bool(
            visual.get("requireIpadMedia"),
            "harnessConfig.visualMedia.requireIpadMedia",
            default=True,
        ),
        "screenshotPaths": [
            _relative_path(root, path, "harnessConfig.visualMedia.screenshotPaths")
            for path in screenshot_paths
        ],
    }

    privacy = _mapping(
        config["privacyToListing"],
        "harnessConfig.privacyToListing",
        {"declaredPermissions", "appStorePrivacyLabelHash"},
    )
    permissions = privacy.get("declaredPermissions")
    if (
        not isinstance(permissions, list)
        or not 1 <= len(permissions) <= MAX_ITEMS
        or not all(isinstance(item, str) and item.strip() for item in permissions)
    ):
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", "declaredPermissions must contain 1-64 strings"
        )
    privacy_norm = {
        "declaredPermissions": sorted(set(item.strip() for item in permissions)),
        "appStorePrivacyLabelHash": _sha256(
            privacy.get("appStorePrivacyLabelHash"),
            "harnessConfig.privacyToListing.appStorePrivacyLabelHash",
        ),
    }

    release = _mapping(
        config["releaseChain"],
        "harnessConfig.releaseChain",
        {"xcodeSigningVerified"},
        optional={"fastlaneReceiptPath", "easPreflightPassed"},
    )
    release_norm: dict[str, Any] = {
        "xcodeSigningVerified": _bool(
            release.get("xcodeSigningVerified"),
            "harnessConfig.releaseChain.xcodeSigningVerified",
        ),
        "easPreflightPassed": _bool(
            release.get("easPreflightPassed"),
            "harnessConfig.releaseChain.easPreflightPassed",
            default=False,
        ),
    }
    if release.get("fastlaneReceiptPath") is not None:
        release_norm["fastlaneReceiptPath"] = _relative_path(
            root,
            release["fastlaneReceiptPath"],
            "harnessConfig.releaseChain.fastlaneReceiptPath",
        )

    design = _mapping(
        config["designSystem"],
        "harnessConfig.designSystem",
        {"designTokensHash", "hierarchyRulesVerified"},
    )
    design_norm = {
        "designTokensHash": _sha256(
            design.get("designTokensHash"),
            "harnessConfig.designSystem.designTokensHash",
        ),
        "hierarchyRulesVerified": _bool(
            design.get("hierarchyRulesVerified"),
            "harnessConfig.designSystem.hierarchyRulesVerified",
        ),
    }
    signal = _mapping(
        config["productionSignal"],
        "harnessConfig.productionSignal",
        {"telemetryProvider", "crashReportingVerified"},
    )
    signal_norm = {
        "telemetryProvider": _text(
            signal.get("telemetryProvider"),
            "harnessConfig.productionSignal.telemetryProvider",
            limit=128,
        ),
        "crashReportingVerified": _bool(
            signal.get("crashReportingVerified"),
            "harnessConfig.productionSignal.crashReportingVerified",
        ),
    }
    android = _mapping(
        config["androidParity"],
        "harnessConfig.androidParity",
        {"gradleBuildVariant", "adbDeviceLogsHash"},
    )
    android_norm = {
        "gradleBuildVariant": _text(
            android.get("gradleBuildVariant"),
            "harnessConfig.androidParity.gradleBuildVariant",
            limit=128,
        ),
        "adbDeviceLogsHash": _sha256(
            android.get("adbDeviceLogsHash"),
            "harnessConfig.androidParity.adbDeviceLogsHash",
        ),
    }

    raw_triage = value["triageRules"]
    if not isinstance(raw_triage, list) or not 1 <= len(raw_triage) <= MAX_ITEMS:
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", "triageRules must contain 1-64 rules"
        )
    triage: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_triage):
        row = _mapping(
            item,
            f"triageRules[{index}]",
            {"ruleId", "category", "severity", "failureMessage"},
        )
        rule_id = _text(row.get("ruleId"), f"triageRules[{index}].ruleId", limit=128)
        if rule_id in seen:
            raise FullStackUXSpecError(
                "E_UX_SPEC_SCHEMA", f"duplicate triage rule: {rule_id}"
            )
        seen.add(rule_id)
        category = _text(
            row.get("category"), f"triageRules[{index}].category", limit=64
        )
        if category not in MOBILE_CATEGORIES:
            raise FullStackUXSpecError(
                "E_UX_SPEC_SCHEMA", f"triageRules[{index}].category is unsupported"
            )
        severity = _text(
            row.get("severity"), f"triageRules[{index}].severity", limit=16
        )
        if severity not in {"BLOCKER", "WARNING", "INFO"}:
            raise FullStackUXSpecError(
                "E_UX_SPEC_SCHEMA", f"triageRules[{index}].severity is unsupported"
            )
        triage.append(
            {
                "ruleId": rule_id,
                "category": category,
                "severity": severity,
                "failureMessage": _text(
                    row.get("failureMessage"),
                    f"triageRules[{index}].failureMessage",
                    limit=512,
                ),
            }
        )

    return {
        "apiVersion": DIRECT_API_VERSION,
        "kind": DIRECT_KIND,
        "metadata": {
            "name": name,
            "specFile": spec_file,
            "targetAppId": target,
            "version": version,
        },
        "harnessConfig": {
            "visualMedia": visual_norm,
            "privacyToListing": privacy_norm,
            "releaseChain": release_norm,
            "designSystem": design_norm,
            "productionSignal": signal_norm,
            "androidParity": android_norm,
        },
        "triageRules": sorted(triage, key=lambda item: item["ruleId"]),
        "mobileCategories": _categories(source="explicit_harness_config"),
    }


def _legacy_normalize(value: dict[str, Any], spec_name: str) -> dict[str, Any]:
    _mapping(
        value, "legacy SSAT", {"feature", "version", "intent", "requirements", "gates"}
    )
    if value.get("feature") != LEGACY_FEATURE:
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", f"feature must be {LEGACY_FEATURE}"
        )
    version = _text(value.get("version"), "version", limit=32)
    _text(value.get("intent"), "intent", limit=2048)
    requirements = value.get("requirements")
    if not isinstance(requirements, list) or len(requirements) != len(
        LEGACY_REQUIREMENTS
    ):
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", "legacy SSAT must contain exactly four requirements"
        )
    normalized_requirements: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(requirements):
        row = _mapping(
            item, f"requirements[{index}]", {"id", "description", "invariant", "checks"}
        )
        identifier = _text(row.get("id"), f"requirements[{index}].id", limit=128)
        if identifier in seen or identifier not in LEGACY_REQUIREMENTS:
            raise FullStackUXSpecError(
                "E_UX_SPEC_SCHEMA",
                "legacy SSAT requirement identifiers must be unique and closed",
            )
        seen.add(identifier)
        checks = row.get("checks")
        if (
            not isinstance(checks, list)
            or not 1 <= len(checks) <= MAX_ITEMS
            or not all(isinstance(check, str) and check.strip() for check in checks)
        ):
            raise FullStackUXSpecError(
                "E_UX_SPEC_SCHEMA",
                f"requirements[{index}].checks must be a string list",
            )
        normalized_requirements.append(
            {
                "id": identifier,
                "description": _text(
                    row.get("description"),
                    f"requirements[{index}].description",
                    limit=2048,
                ),
                "invariant": _text(
                    row.get("invariant"), f"requirements[{index}].invariant", limit=128
                ),
                "checks": sorted(set(check.strip() for check in checks)),
            }
        )
    if seen != LEGACY_REQUIREMENTS:
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", "legacy SSAT is missing a closed requirement"
        )
    gates = value.get("gates")
    if not isinstance(gates, list) or not 1 <= len(gates) <= MAX_ITEMS:
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", "gates must contain 1-64 entries"
        )
    normalized_gates: list[dict[str, str]] = []
    for index, item in enumerate(gates):
        row = _mapping(item, f"gates[{index}]", {"type", "command"})
        gate_type = _text(row.get("type"), f"gates[{index}].type", limit=32)
        if gate_type not in {"test", "smoke"}:
            raise FullStackUXSpecError(
                "E_UX_SPEC_SCHEMA", f"gates[{index}].type must be test or smoke"
            )
        normalized_gates.append(
            {
                "type": gate_type,
                "command": _text(
                    row.get("command"), f"gates[{index}].command", limit=512
                ),
            }
        )
    if {gate["type"] for gate in normalized_gates} != {"test", "smoke"}:
        raise FullStackUXSpecError(
            "E_UX_SPEC_SCHEMA", "legacy SSAT needs both test and smoke gates"
        )
    return {
        "apiVersion": DIRECT_API_VERSION,
        "kind": DIRECT_KIND,
        "metadata": {
            "name": LEGACY_FEATURE,
            "specFile": spec_name,
            "targetAppId": "not-declared",
            "version": version,
        },
        "legacy": {
            "feature": LEGACY_FEATURE,
            "intent": value["intent"].strip(),
            "requirements": sorted(
                normalized_requirements, key=lambda item: item["id"]
            ),
            "gates": sorted(normalized_gates, key=lambda item: item["type"]),
        },
        "mobileCategories": _categories(source="derived_from_legacy_harness"),
    }


def _normalize(root: Path, value: dict[str, Any], spec_name: str) -> dict[str, Any]:
    if value.get("apiVersion") is not None or value.get("kind") is not None:
        return _direct_normalize(root, value, spec_name)
    return _legacy_normalize(value, spec_name)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _output_path(root: Path, out: Path | None, source: Path) -> Path:
    workspace = Path(root).resolve()
    destination = (
        out
        if out is not None
        else Path(".factory") / "quality-harness" / f"{source.stem}.spec-receipt.json"
    )
    destination = destination if destination.is_absolute() else workspace / destination
    destination = destination.resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise FullStackUXSpecError(
            "E_UX_SPEC_OUTPUT_PATH", "receipt must stay inside the workspace"
        ) from exc
    if destination == source:
        raise FullStackUXSpecError(
            "E_UX_SPEC_OUTPUT_PATH", "receipt destination must differ from source"
        )
    if destination.exists():
        raise FullStackUXSpecError(
            "E_UX_SPEC_OUTPUT_EXISTS",
            "spec receipt is immutable; choose a new output path",
        )
    return destination


def _core_from_receipt(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: item
        for key, item in value.items()
        if key not in {"receipt_sha256", "generated_at"}
    }


def validate_ux_harness_spec(
    root: Path, spec_path: Path, *, out: Path | None = None
) -> dict[str, Any]:
    """Validate one SSAT/YAML contract and write an immutable local receipt."""
    workspace = Path(root).resolve()
    raw, source, data = _safe_source(workspace, Path(spec_path))
    findings: list[dict[str, str]] = []
    normalized: dict[str, Any] | None = None
    try:
        normalized = _normalize(workspace, raw, source.name)
    except FullStackUXSpecError as exc:
        findings.append({"code": exc.code, "detail": exc.message})
    core = {
        "schema": RECEIPT_SCHEMA,
        "marker": "FULL_STACK_UX_HARNESS_SPEC_VALIDATED"
        if not findings
        else "FULL_STACK_UX_HARNESS_SPEC_BLOCKED",
        "ok": not findings,
        "action_summary": "Validate the Full-Stack UX Harness contract, reject ambiguous or unsafe YAML, and map six mobile evidence categories to one local receipt without executing tools or providers.",
        "source": {
            "path": source.relative_to(workspace).as_posix(),
            "sha256": _sha(data),
            "bytes": len(data),
        },
        "normalized_spec": normalized,
        "mobile_categories": normalized.get("mobileCategories", [])
        if normalized
        else [],
        "findings": findings,
        "authority": {
            "execution": False,
            "provider_access": False,
            "device_access": False,
            "source_modification": False,
            "approval": False,
            "deployment": False,
            "publication": False,
            "credential_access": False,
        },
        "claim_boundary": "Contract structure and source binding only. A validated SSAT does not prove mobile behavior, accessibility, privacy compliance, signing, TestFlight, store submission, or store approval; run the named native evidence producers and preserve human release authority.",
    }
    receipt = {**core, "receipt_sha256": _sha(core), "generated_at": _now()}
    destination = _output_path(workspace, out, source)
    _atomic_json(destination, receipt)
    return {**receipt, "path": destination.relative_to(workspace).as_posix()}


def verify_ux_harness_spec_receipt(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Replay a spec receipt against its current source and self-digest."""
    workspace = Path(root).resolve()
    try:
        receipt_source = Path(receipt_path)
        receipt_source = (
            receipt_source
            if receipt_source.is_absolute()
            else workspace / receipt_source
        )
        receipt_source = receipt_source.resolve()
        receipt_source.relative_to(workspace)
        if receipt_source.stat().st_size > MAX_BYTES:
            raise FullStackUXSpecError(
                "E_UX_SPEC_RECEIPT_INVALID", "receipt exceeds 1 MiB"
            )
        value = json.loads(receipt_source.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict) or value.get("schema") != RECEIPT_SCHEMA:
            raise FullStackUXSpecError(
                "E_UX_SPEC_RECEIPT_INVALID", "receipt schema is invalid"
            )
        supplied = value.get("receipt_sha256")
        if not isinstance(supplied, str) or supplied != _sha(_core_from_receipt(value)):
            raise FullStackUXSpecError(
                "E_UX_SPEC_RECEIPT_INVALID", "receipt digest is invalid"
            )
        if (
            value.get("ok") is not True
            or value.get("marker") != "FULL_STACK_UX_HARNESS_SPEC_VALIDATED"
        ):
            raise FullStackUXSpecError(
                "E_UX_SPEC_NOT_VALIDATED", "receipt is not a validated contract"
            )
        source_info = value.get("source")
        if (
            not isinstance(source_info, dict)
            or not isinstance(source_info.get("path"), str)
            or not isinstance(source_info.get("sha256"), str)
        ):
            raise FullStackUXSpecError(
                "E_UX_SPEC_RECEIPT_INVALID", "source binding is missing"
            )
        raw, source, data = _safe_source(workspace, Path(source_info["path"]))
        if _sha(data) != source_info["sha256"]:
            raise FullStackUXSpecError(
                "E_UX_SPEC_STALE", "specification source changed"
            )
        normalized = _normalize(workspace, raw, source.name)
        if (
            normalized != value.get("normalized_spec")
            or source.relative_to(workspace).as_posix() != source_info["path"]
        ):
            raise FullStackUXSpecError(
                "E_UX_SPEC_STALE", "replayed specification differs from receipt"
            )
        return {
            "ok": True,
            "marker": value["marker"],
            "receipt_sha256": supplied,
            "source": source_info["path"],
        }
    except (
        FullStackUXSpecError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        return {
            "ok": False,
            "marker": "FULL_STACK_UX_HARNESS_SPEC_REVIEW_REQUIRED",
            "reason": str(exc)[:240],
        }

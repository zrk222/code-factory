"""Provider-neutral mobile evidence normalization and release-readiness gate.

This module accepts only hash-bound, workspace-local exports.  It deliberately
does not execute Xcode, Gradle, ADB, Fastlane, a device cloud, a telemetry
vendor, or either store console.  It turns their supplied evidence into one
candidate-bound receipt while preserving unobserved external state as a block
or an explicit ``not_attempted`` release stage.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any

from .appforge_evidence_kit import _read_candidate
from .revenueforge import AUTHORITY, RevenueForgeError


CONTRACT_SCHEMA = "factory.appforge.mobile-evidence-contract.v1"
EVIDENCE_SCHEMA = "factory.appforge.mobile-evidence-input.v1"
RECEIPT_SCHEMA = "factory.appforge.mobile-evidence-receipt.v1"
MAX_BYTES = 1_048_576
PLATFORMS = frozenset({"ios", "android"})
TOOLS = frozenset(
    {
        "xcodebuild",
        "xctest",
        "android_gradle",
        "adb",
        "fastlane",
        "device_cloud",
        "crashlytics",
        "sentry",
        "metrickit",
        "android_vitals",
    }
)
CHECKS = frozenset(
    {
        "build",
        "tests",
        "snapshot",
        "device_frames",
        "layout",
        "contrast",
        "accessibility",
        "store_assets",
        "permissions",
        "privacy_manifest",
        "tracking_disclosure",
        "entitlements",
        "runtime_network",
        "listing_metadata",
        "design_system_conformance",
        "adaptive_layout",
        "r8_permissions",
        "play_metadata",
    }
)
RELEASE_STAGES = (
    "build",
    "signing",
    "upload",
    "processing",
    "tester_group",
    "tester_invitation",
    "review_submission",
    "store_decision",
)
STAGE_STATES = frozenset(
    {"not_attempted", "observed", "passed", "failed", "not_applicable"}
)
METRICS = ("crash_free_rate", "anr_rate", "hang_rate", "startup_ms")
PASS = "passed"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _text(value: object, field: str, *, limit: int = 512) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_INVALID",
            f"{field} must be a non-empty bounded string",
        )
    return value.strip()


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_INVALID", f"{field} must be a lowercase SHA-256"
        )
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_PATH_REJECTED",
            "paths must remain inside the workspace",
        ) from exc
    if exists and not target.is_file():
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_INPUT_UNAVAILABLE",
            "input must be a regular workspace file",
        )
    return target


def _read(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB"
        )
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_INPUT_INVALID", "input must be valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_SCHEMA_REJECTED", f"expected {schema}"
        )
    return value, source


def _atomic(path: Path, payload: dict[str, Any]) -> None:
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


def _validate_contract_identity(
    value: dict[str, Any], candidate: dict[str, str]
) -> None:
    fields = {
        "schema",
        "candidate",
        "platforms",
        "user_design_input_sha256",
        "required_checks",
        "production_thresholds",
    }
    if set(value) != fields or value.get("candidate") != candidate:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID",
            "contract must have exact fields and bind the exact candidate",
        )


def _contract_platforms(value: dict[str, Any]) -> list[str]:
    platforms = value.get("platforms")
    if (
        not isinstance(platforms, list)
        or not platforms
        or len(platforms) != len(set(platforms))
        or set(platforms) - PLATFORMS
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID",
            "platforms must be a unique non-empty ios/android list",
        )
    return sorted(platforms)


def _validate_required_checks(value: dict[str, Any]) -> None:
    required = value.get("required_checks")
    if (
        not isinstance(required, dict)
        or set(required) != CHECKS
        or any(required.get(key) is not True for key in CHECKS)
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID",
            "every named mobile proof check must be explicitly required",
        )


def _numeric_thresholds(thresholds: dict[str, Any]) -> dict[str, float]:
    numeric: dict[str, float] = {}
    for key, raw in thresholds.items():
        if (
            isinstance(raw, bool)
            or not isinstance(raw, (int, float))
            or not math.isfinite(float(raw))
        ):
            raise RevenueForgeError(
                "APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID", f"{key} must be numeric"
            )
        numeric[key] = float(raw)
    return numeric


def _contract_thresholds(value: dict[str, Any]) -> dict[str, float]:
    thresholds = value.get("production_thresholds")
    if not isinstance(thresholds, dict) or set(thresholds) != {
        "crash_free_rate_min",
        "anr_rate_max",
        "hang_rate_max",
        "startup_ms_max",
    }:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID",
            "production thresholds must use the fixed metric fields",
        )
    numeric = _numeric_thresholds(thresholds)
    if not 0 <= numeric["crash_free_rate_min"] <= 100 or any(
        numeric[key] < 0 for key in ("anr_rate_max", "hang_rate_max", "startup_ms_max")
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID",
            "production thresholds contain an invalid range",
        )
    return numeric


def _contract(value: dict[str, Any], candidate: dict[str, str]) -> dict[str, Any]:
    _validate_contract_identity(value, candidate)
    platforms = _contract_platforms(value)
    _validate_required_checks(value)
    numeric = _contract_thresholds(value)
    return {
        "candidate": candidate,
        "platforms": platforms,
        "user_design_input_sha256": _digest(
            value["user_design_input_sha256"], "user_design_input_sha256"
        ),
        "required_checks": sorted(CHECKS),
        "production_thresholds": numeric,
    }


def _report_source(
    root: Path, item: dict[str, Any], index: int
) -> tuple[str, Path, str]:
    tool = _text(item["tool"], f"reports[{index}].tool", limit=64)
    if tool not in TOOLS:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_TOOL_REJECTED", "tool is unsupported"
        )
    path = _local(
        root, Path(_text(item["source_path"], f"reports[{index}].source_path"))
    )
    supplied = _digest(item["source_sha256"], f"reports[{index}].source_sha256")
    if _file_sha(path) != supplied:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_SOURCE_STALE",
            "source report does not match its supplied digest",
        )
    return tool, path, supplied


def _report_platforms(value: object) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) != len(set(value))
        or set(value) - PLATFORMS
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID",
            "report platforms are invalid",
        )
    return sorted(value)


def _report_checks(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) - CHECKS
        or any(
            status not in {PASS, "failed", "not_observed", "not_applicable"}
            for status in value.values()
        )
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID", "report checks are invalid"
        )
    return dict(sorted(value.items()))


def _report_stages(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != set(RELEASE_STAGES)
        or any(status not in STAGE_STATES for status in value.values())
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID", "release stages are invalid"
        )
    return {key: value[key] for key in RELEASE_STAGES}


def _report_signals(value: object) -> dict[str, float]:
    if (
        not isinstance(value, dict)
        or set(value) - set(METRICS)
        or any(
            isinstance(signal, bool)
            or not isinstance(signal, (int, float))
            or not math.isfinite(float(signal))
            for signal in value.values()
        )
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID",
            "production signals are invalid",
        )
    return {key: float(signal) for key, signal in sorted(value.items())}


def _normalize_report(root: Path, item: dict[str, Any], index: int) -> dict[str, Any]:
    tool, path, supplied = _report_source(root, item, index)
    return {
        "tool": tool,
        "source_path": path.relative_to(root).as_posix(),
        "source_sha256": supplied,
        "platforms": _report_platforms(item["platforms"]),
        "checks": _report_checks(item["checks"]),
        "release_stages": _report_stages(item["release_stages"]),
        "production_signals": _report_signals(item["production_signals"]),
    }


def _report(
    root: Path, item: object, candidate: dict[str, str], index: int
) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    fields = {
        "tool",
        "source_path",
        "source_sha256",
        "platforms",
        "checks",
        "release_stages",
        "production_signals",
    }
    if not isinstance(item, dict) or set(item) != fields:
        return None, [
            {
                "code": "APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID",
                "detail": f"reports[{index}] must have exact fields",
            }
        ]
    try:
        return _normalize_report(root, item, index), findings
    except RevenueForgeError as exc:
        findings.append({"code": exc.code, "detail": str(exc)})
        return None, findings


def _required_evidence(platforms: list[str]) -> dict[str, set[str]]:
    gates = {
        "visual_truth": {
            "snapshot",
            "device_frames",
            "layout",
            "contrast",
            "accessibility",
            "store_assets",
        },
        "privacy_store_consistency": {
            "permissions",
            "privacy_manifest",
            "tracking_disclosure",
            "entitlements",
            "runtime_network",
            "listing_metadata",
        },
        "design_system_conformance": {"design_system_conformance"},
    }
    if "ios" in platforms:
        gates["ios_native"] = {"build", "tests", "accessibility"}
    if "android" in platforms:
        gates["android_parity"] = {
            "build",
            "tests",
            "adaptive_layout",
            "accessibility",
            "r8_permissions",
            "play_metadata",
        }
    return gates


def _validate_reports(
    contract: dict[str, Any], evidence: dict[str, Any], root: Path
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    if (
        set(evidence) != {"schema", "candidate", "contract_sha256", "reports"}
        or evidence.get("candidate") != contract["candidate"]
    ):
        return [], [
            {
                "code": "APPFORGE_MOBILE_EVIDENCE_BINDING_INVALID",
                "detail": "evidence must bind the exact candidate and fixed fields",
            }
        ]
    supplied = _digest(evidence.get("contract_sha256"), "evidence.contract_sha256")
    if supplied != contract["contract_sha256"]:
        findings.append(
            {
                "code": "APPFORGE_MOBILE_EVIDENCE_CONTRACT_MISMATCH",
                "detail": "evidence names a different mobile evidence contract",
            }
        )
    raw_reports = evidence.get("reports")
    if not isinstance(raw_reports, list) or not raw_reports or len(raw_reports) > 32:
        return [], findings + [
            {
                "code": "APPFORGE_MOBILE_EVIDENCE_REPORTS_MISSING",
                "detail": "evidence must contain 1-32 source-bound reports",
            }
        ]
    reports: list[dict[str, Any]] = []
    for index, item in enumerate(raw_reports):
        report, errors = _report(root, item, contract["candidate"], index)
        findings.extend(errors)
        if report:
            reports.append(report)
    return reports, findings


def _platform_checks(
    reports: list[dict[str, Any]], platform: str
) -> dict[str, set[str]]:
    """Return every observed status for each check on one declared platform."""
    observed: dict[str, set[str]] = {}
    for report in reports:
        if platform not in report["platforms"]:
            continue
        for check, status in report["checks"].items():
            observed.setdefault(check, set()).add(status)
    return observed


def _platform_gate_findings(
    platform: str, observed: dict[str, set[str]]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for check, statuses in sorted(observed.items()):
        if "failed" in statuses:
            findings.append(
                {
                    "code": "APPFORGE_MOBILE_EVIDENCE_CHECK_FAILED",
                    "detail": f"{platform}:{check} has failed evidence",
                }
            )
        if PASS in statuses and "failed" in statuses:
            findings.append(
                {
                    "code": "APPFORGE_MOBILE_EVIDENCE_CHECK_CONFLICT",
                    "detail": f"{platform}:{check} has conflicting passed and failed evidence",
                }
            )
    for gate, required in _required_evidence([platform]).items():
        missing = sorted(
            check for check in required if PASS not in observed.get(check, set())
        )
        if missing:
            findings.append(
                {
                    "code": "APPFORGE_MOBILE_EVIDENCE_GATE_INCOMPLETE",
                    "detail": f"{platform}:{gate} lacks passed evidence for: {', '.join(missing)}",
                }
            )
    return findings


def _tool_findings(
    platform: str, reports: list[dict[str, Any]]
) -> list[dict[str, str]]:
    tools = {report["tool"] for report in reports if platform in report["platforms"]}
    findings: list[dict[str, str]] = []
    requirements = (
        (
            platform == "ios" and not tools & {"xcodebuild", "xctest"},
            "APPFORGE_MOBILE_EVIDENCE_IOS_TOOL_MISSING",
            "iOS readiness needs an xcodebuild or XCTest source report",
        ),
        (
            platform == "android" and not tools & {"android_gradle", "adb"},
            "APPFORGE_MOBILE_EVIDENCE_ANDROID_TOOL_MISSING",
            "Android readiness needs an Android Gradle or ADB source report",
        ),
        (
            not tools & {"fastlane", "device_cloud"},
            "APPFORGE_MOBILE_EVIDENCE_VISUAL_TRANSPORT_MISSING",
            f"{platform} visual truth needs a Fastlane or device-cloud source report",
        ),
    )
    for missing, code, detail in requirements:
        if missing:
            findings.append({"code": code, "detail": detail})
    return findings


def _stage_findings(
    platform: str, reports: list[dict[str, Any]]
) -> list[dict[str, str]]:
    observed: dict[str, set[str]] = {stage: set() for stage in RELEASE_STAGES}
    for report in reports:
        if platform in report["platforms"]:
            for stage, status in report["release_stages"].items():
                observed[stage].add(status)
    findings: list[dict[str, str]] = []
    for stage in ("build", "signing"):
        statuses = observed[stage]
        if PASS not in statuses or "failed" in statuses:
            findings.append(
                {
                    "code": "APPFORGE_MOBILE_EVIDENCE_RELEASE_CHAIN_INCOMPLETE",
                    "detail": f"{platform} release stage {stage} is absent, not passed, or failed",
                }
            )
    for stage, statuses in observed.items():
        if "failed" in statuses:
            findings.append(
                {
                    "code": "APPFORGE_MOBILE_EVIDENCE_RELEASE_CHAIN_FAILED",
                    "detail": f"{platform} release stage {stage} is failed",
                }
            )
    return findings


def _production_signals(
    reports: list[dict[str, Any]],
) -> dict[str, dict[str, list[float]]]:
    platforms = {platform for report in reports for platform in report["platforms"]}
    signals = {platform: {metric: [] for metric in METRICS} for platform in platforms}
    for report in reports:
        for platform in report["platforms"]:
            if platform in signals:
                for metric, value in report["production_signals"].items():
                    signals[platform][metric].append(value)
    return signals


def _production_findings(
    contract: dict[str, Any], reports: list[dict[str, Any]]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    signals_by_platform = _production_signals(reports)
    thresholds = contract["production_thresholds"]
    comparisons = {
        "crash_free_rate": (min, thresholds["crash_free_rate_min"], "below"),
        "anr_rate": (max, thresholds["anr_rate_max"], "above"),
        "hang_rate": (max, thresholds["hang_rate_max"], "above"),
        "startup_ms": (max, thresholds["startup_ms_max"], "above"),
    }
    for platform in contract["platforms"]:
        for metric, (aggregate, limit, direction) in comparisons.items():
            values = signals_by_platform.get(platform, {}).get(metric, [])
            if not values:
                findings.append(
                    {
                        "code": "APPFORGE_MOBILE_EVIDENCE_PRODUCTION_SIGNAL_MISSING",
                        "detail": f"{platform} production signal {metric} is missing",
                    }
                )
            elif _signal_regressed(aggregate(values), limit, direction):
                findings.append(
                    {
                        "code": "APPFORGE_MOBILE_EVIDENCE_PRODUCTION_REGRESSION",
                        "detail": f"{platform} production signal {metric} is {direction} its sealed threshold",
                    }
                )
    return findings


def _signal_regressed(value: float, limit: float, direction: str) -> bool:
    if direction == "below":
        return value < limit
    return value > limit


def _findings(
    contract: dict[str, Any], reports: list[dict[str, Any]]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for platform in contract["platforms"]:
        observed = _platform_checks(reports, platform)
        findings.extend(_platform_gate_findings(platform, observed))
        findings.extend(_tool_findings(platform, reports))
        findings.extend(_stage_findings(platform, reports))
    findings.extend(_production_findings(contract, reports))
    return findings


def verify_mobile_evidence(
    root: Path,
    candidate_path: Path,
    contract_path: Path,
    evidence_path: Path,
    out_path: Path,
) -> dict[str, Any]:
    """Normalize source-bound mobile evidence into one deterministic readiness receipt."""
    workspace = Path(root).resolve()
    candidate, candidate_source = _read_candidate(workspace, candidate_path)
    raw_contract, contract_source = _read(workspace, contract_path, CONTRACT_SCHEMA)
    contract = _contract(raw_contract, candidate)
    contract["contract_sha256"] = _file_sha(contract_source)
    evidence, evidence_source = _read(workspace, evidence_path, EVIDENCE_SCHEMA)
    reports, findings = _validate_reports(contract, evidence, workspace)
    findings.extend(_findings(contract, reports))
    findings.sort(key=lambda item: (item["code"], item["detail"]))
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_MOBILE_EVIDENCE_READY"
        if not findings
        else "APPFORGE_MOBILE_EVIDENCE_BLOCKED",
        "ok": not findings,
        "action_summary": "Normalize hash-bound iOS and Android tool reports into one candidate-bound mobile evidence receipt covering visual truth, privacy-to-store consistency, release-chain state, design conformance, production signals, and Android parity without executing a tool or accessing a provider.",
        "candidate": candidate,
        "candidate_source": {
            "path": candidate_source.relative_to(workspace).as_posix(),
            "sha256": _file_sha(candidate_source),
        },
        "contract": {
            "path": contract_source.relative_to(workspace).as_posix(),
            "sha256": contract["contract_sha256"],
            "platforms": contract["platforms"],
            "user_design_input_sha256": contract["user_design_input_sha256"],
            "production_thresholds": contract["production_thresholds"],
        },
        "evidence_source": {
            "path": evidence_source.relative_to(workspace).as_posix(),
            "sha256": _file_sha(evidence_source),
        },
        "reports": reports,
        "findings": findings,
        "release_chain_states": {
            stage: sorted({report["release_stages"][stage] for report in reports})
            for stage in RELEASE_STAGES
        },
        "authority": {
            **AUTHORITY,
            "execution": False,
            "device_access": False,
            "provider_access": False,
            "store_write": False,
            "app_review_submit": False,
            "approval_claim": False,
        },
        "claim_boundary": "Local structural and hash validation only. Report contents remain supplied evidence; this receipt does not execute Xcode, XCTest, Gradle, ADB, Fastlane, a device cloud, Crashlytics, Sentry, MetricKit, Android Vitals, App Store Connect, or Play Console, and it does not prove runtime behavior, external state, submission, policy certification, or store approval.",
    }
    result = {**core, "receipt_sha256": _sha(core)}
    destination = _local(workspace, out_path, exists=False)
    if destination.exists():
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_OUTPUT_EXISTS",
            "output receipt is immutable; choose a new path",
        )
    _atomic(destination, result)
    return {**result, "path": destination.relative_to(workspace).as_posix()}


def _read_mobile_receipt(workspace: Path, receipt_path: Path) -> dict[str, Any]:
    source = _local(workspace, receipt_path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_RECEIPT_INVALID", "receipt exceeds 1 MiB"
        )
    value = json.loads(source.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or value.get("schema") != RECEIPT_SCHEMA:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_RECEIPT_INVALID", "receipt schema is invalid"
        )
    return value


def _receipt_digest(value: dict[str, Any]) -> str:
    supplied = value.get("receipt_sha256")
    payload = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if (
        not isinstance(supplied, str)
        or len(supplied) != 64
        or _sha(payload) != supplied
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_RECEIPT_INVALID", "receipt digest is invalid"
        )
    return supplied


def _require_ready_receipt(value: dict[str, Any]) -> None:
    if (
        value.get("marker") != "APPFORGE_MOBILE_EVIDENCE_READY"
        or value.get("ok") is not True
    ):
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_NOT_READY",
            "receipt is not a ready mobile-evidence result",
        )


def _source_binding(info: object, label: str) -> tuple[Path, str]:
    detail = f"{label} source binding is missing"
    if (
        not isinstance(info, dict)
        or not isinstance(info.get("path"), str)
        or not isinstance(info.get("sha256"), str)
    ):
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_RECEIPT_INVALID", detail)
    return Path(info["path"]), info["sha256"]


def _bound_candidate(workspace: Path, info: object, expected: object) -> dict[str, str]:
    path, digest = _source_binding(info, "candidate")
    candidate, source = _read_candidate(workspace, path)
    if candidate != expected or _file_sha(source) != digest:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_RECEIPT_STALE", "candidate source changed"
        )
    return candidate


def _bound_contract(
    workspace: Path, info: object, candidate: dict[str, str]
) -> dict[str, Any]:
    path, digest = _source_binding(info, "contract")
    raw, source = _read(workspace, path, CONTRACT_SCHEMA)
    if _file_sha(source) != digest:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_RECEIPT_STALE", "mobile contract changed"
        )
    contract = _contract(raw, candidate)
    contract["contract_sha256"] = _file_sha(source)
    return contract


def _bound_evidence(workspace: Path, info: object) -> tuple[dict[str, Any], Path]:
    path, digest = _source_binding(info, "evidence")
    evidence, source = _read(workspace, path, EVIDENCE_SCHEMA)
    if _file_sha(source) != digest:
        raise RevenueForgeError(
            "APPFORGE_MOBILE_EVIDENCE_RECEIPT_STALE", "evidence input changed"
        )
    return evidence, source


def _mobile_receipt_success(supplied: str, candidate: dict[str, str]) -> dict[str, Any]:
    return {
        "ok": True,
        "marker": "APPFORGE_MOBILE_EVIDENCE_READY",
        "receipt_sha256": supplied,
        "candidate": candidate,
    }


def _mobile_receipt_review(exc: Exception) -> dict[str, Any]:
    return {
        "ok": False,
        "marker": "APPFORGE_MOBILE_EVIDENCE_REVIEW_REQUIRED",
        "reason": str(exc)[:240],
    }


def _rank_mobile_receipts(
    workspace: Path,
) -> tuple[list[tuple[int, Path]], bool, list[str]]:
    candidates = list(
        (workspace / ".factory" / "appforge").rglob("*mobile-evidence*.json")
    )
    truncated = len(candidates) > 1_000
    ranked: list[tuple[int, Path]] = []
    invalid: list[str] = []
    for path in candidates[:1_000]:
        try:
            ranked.append((path.stat().st_mtime_ns, path))
        except OSError:
            invalid.append(path.relative_to(workspace).as_posix())
    return ranked, truncated, invalid


def _project_mobile_receipt(workspace: Path, path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("mobile evidence receipt exceeds 1 MiB")
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("mobile evidence receipt must be an object")
        verified = verify_mobile_evidence_receipt(workspace, path)
        if not verified.get("ok"):
            return None
        return {
            "path": path.relative_to(workspace).as_posix(),
            "marker": value.get("marker"),
            "ok": value.get("ok"),
            "candidate": value.get("candidate"),
            "receipt_sha256": value.get("receipt_sha256"),
            "finding_count": len(value.get("findings", [])),
        }
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
        RevenueForgeError,
    ):
        return None


def _projection_marker(truncated: bool, invalid: list[str]) -> str:
    if truncated or invalid:
        return "APPFORGE_MOBILE_EVIDENCE_REVIEW_REQUIRED"
    return "APPFORGE_MOBILE_EVIDENCE_READ_ONLY"


def verify_mobile_evidence_receipt(root: Path, receipt_path: Path) -> dict[str, Any]:
    """Replay a mobile receipt against its candidate, contract, and sources.

    A self-hash alone only proves that a JSON blob was edited consistently.  A
    release projection must also prove that the referenced inputs still exist,
    still hash to the values recorded at capture time, and still produce the
    same findings when the deterministic validators are rerun.
    """
    workspace = Path(root).resolve()
    try:
        value = _read_mobile_receipt(workspace, receipt_path)
        supplied = _receipt_digest(value)
        _require_ready_receipt(value)
        candidate = _bound_candidate(
            workspace, value.get("candidate_source"), value.get("candidate")
        )
        contract = _bound_contract(workspace, value.get("contract"), candidate)
        evidence, _source = _bound_evidence(workspace, value.get("evidence_source"))
        reports, findings = _validate_reports(contract, evidence, workspace)
        findings.extend(_findings(contract, reports))
        findings.sort(key=lambda item: (item["code"], item["detail"]))
        if findings or reports != value.get("reports"):
            raise RevenueForgeError(
                "APPFORGE_MOBILE_EVIDENCE_RECEIPT_STALE",
                "replayed evidence differs from the sealed receipt",
            )
        return _mobile_receipt_success(supplied, candidate)
    except (
        RevenueForgeError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        return _mobile_receipt_review(exc)


def mobile_evidence_projection(root: Path) -> dict[str, Any]:
    """Read valid mobile evidence receipts without invoking tools or providers."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    ranked, truncated, invalid = _rank_mobile_receipts(workspace)
    # A projection is a current-state UI, not an archive browser.  Select the
    # 100 newest stable files by observed filesystem time, then read them. A
    # file vanishing during selection is recorded as invalid instead of
    # crashing the whole projection.
    for _mtime, path in sorted(ranked, key=lambda item: (item[0], item[1].as_posix()))[
        -100:
    ]:
        projected = _project_mobile_receipt(workspace, path)
        if projected is None:
            invalid.append(path.relative_to(workspace).as_posix())
        else:
            current.append(projected)
    if truncated:
        invalid.append(".factory/appforge/<scan-truncated>")
    # Any malformed/newer stale receipt invalidates the aggregate view; do not
    # surface an older READY value that could be mistaken for current state.
    latest = current[-1] if current and not invalid and not truncated else None
    marker = _projection_marker(truncated, invalid)
    return {
        "schema": "factory.appforge.mobile-evidence-projection.v1",
        "marker": marker,
        "current_count": len(current),
        "invalid_count": len(invalid),
        "truncated": truncated,
        "latest": latest,
        "invalid": invalid,
        "authority": {
            **AUTHORITY,
            "execution": False,
            "device_access": False,
            "provider_access": False,
            "store_write": False,
            "app_review_submit": False,
            "approval_claim": False,
        },
        "claim_boundary": "Read-only local mobile evidence status; not tool execution, a device test, a provider-state readback, submission, or approval.",
    }

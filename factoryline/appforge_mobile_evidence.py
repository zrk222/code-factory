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
TOOLS = frozenset({
    "xcodebuild", "xctest", "android_gradle", "adb", "fastlane", "device_cloud",
    "crashlytics", "sentry", "metrickit", "android_vitals",
})
CHECKS = frozenset({
    "build", "tests", "snapshot", "device_frames", "layout", "contrast", "accessibility",
    "store_assets", "permissions", "privacy_manifest", "tracking_disclosure", "entitlements",
    "runtime_network", "listing_metadata", "design_system_conformance", "adaptive_layout",
    "r8_permissions", "play_metadata",
})
RELEASE_STAGES = (
    "build", "signing", "upload", "processing", "tester_group", "tester_invitation",
    "review_submission", "store_decision",
)
STAGE_STATES = frozenset({"not_attempted", "observed", "passed", "failed", "not_applicable"})
METRICS = ("crash_free_rate", "anr_rate", "hang_rate", "startup_ms")
PASS = "passed"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


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
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_INVALID", f"{field} must be a non-empty bounded string")
    return value.strip()


def _digest(value: object, field: str) -> str:
    result = _text(value, field, limit=64).lower()
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_INVALID", f"{field} must be a lowercase SHA-256")
    return result


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_INPUT_INVALID", "input must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _contract(value: dict[str, Any], candidate: dict[str, str]) -> dict[str, Any]:
    fields = {"schema", "candidate", "platforms", "user_design_input_sha256", "required_checks", "production_thresholds"}
    if set(value) != fields or value.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID", "contract must have exact fields and bind the exact candidate")
    platforms = value.get("platforms")
    if not isinstance(platforms, list) or not platforms or len(platforms) != len(set(platforms)) or set(platforms) - PLATFORMS:
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID", "platforms must be a unique non-empty ios/android list")
    required = value.get("required_checks")
    if not isinstance(required, dict) or set(required) != CHECKS or any(required.get(key) is not True for key in CHECKS):
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID", "every named mobile proof check must be explicitly required")
    thresholds = value.get("production_thresholds")
    if not isinstance(thresholds, dict) or set(thresholds) != {"crash_free_rate_min", "anr_rate_max", "hang_rate_max", "startup_ms_max"}:
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID", "production thresholds must use the fixed metric fields")
    numeric: dict[str, float] = {}
    for key, raw in thresholds.items():
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID", f"{key} must be numeric")
        numeric[key] = float(raw)
    if not 0 <= numeric["crash_free_rate_min"] <= 100 or any(numeric[key] < 0 for key in ("anr_rate_max", "hang_rate_max", "startup_ms_max")):
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_CONTRACT_INVALID", "production thresholds contain an invalid range")
    return {"candidate": candidate, "platforms": sorted(platforms), "user_design_input_sha256": _digest(value["user_design_input_sha256"], "user_design_input_sha256"), "required_checks": sorted(CHECKS), "production_thresholds": numeric}


def _report(root: Path, item: object, candidate: dict[str, str], index: int) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    fields = {"tool", "source_path", "source_sha256", "platforms", "checks", "release_stages", "production_signals"}
    if not isinstance(item, dict) or set(item) != fields:
        return None, [{"code": "APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID", "detail": f"reports[{index}] must have exact fields"}]
    try:
        tool = _text(item["tool"], f"reports[{index}].tool", limit=64)
        if tool not in TOOLS:
            raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_TOOL_REJECTED", "tool is unsupported")
        path = _local(root, Path(_text(item["source_path"], f"reports[{index}].source_path")))
        supplied = _digest(item["source_sha256"], f"reports[{index}].source_sha256")
        if _file_sha(path) != supplied:
            raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_SOURCE_STALE", "source report does not match its supplied digest")
        platforms = item["platforms"]
        if not isinstance(platforms, list) or not platforms or len(platforms) != len(set(platforms)) or set(platforms) - PLATFORMS:
            raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID", "report platforms are invalid")
        checks = item["checks"]
        if not isinstance(checks, dict) or set(checks) - CHECKS or any(value not in {PASS, "failed", "not_observed", "not_applicable"} for value in checks.values()):
            raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID", "report checks are invalid")
        stages = item["release_stages"]
        if not isinstance(stages, dict) or set(stages) != set(RELEASE_STAGES) or any(value not in STAGE_STATES for value in stages.values()):
            raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID", "release stages are invalid")
        signals = item["production_signals"]
        if not isinstance(signals, dict) or set(signals) - set(METRICS) or any(isinstance(value, bool) or not isinstance(value, (int, float)) for value in signals.values()):
            raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_REPORT_INVALID", "production signals are invalid")
        return {"tool": tool, "source_path": path.relative_to(root).as_posix(), "source_sha256": supplied, "platforms": sorted(platforms), "checks": dict(sorted(checks.items())), "release_stages": {key: stages[key] for key in RELEASE_STAGES}, "production_signals": {key: float(value) for key, value in sorted(signals.items())}}, findings
    except RevenueForgeError as exc:
        findings.append({"code": exc.code, "detail": str(exc)})
        return None, findings


def _required_evidence(platforms: list[str]) -> dict[str, set[str]]:
    gates = {
        "visual_truth": {"snapshot", "device_frames", "layout", "contrast", "accessibility", "store_assets"},
        "privacy_store_consistency": {"permissions", "privacy_manifest", "tracking_disclosure", "entitlements", "runtime_network", "listing_metadata"},
        "design_system_conformance": {"design_system_conformance"},
    }
    if "ios" in platforms:
        gates["ios_native"] = {"build", "tests", "accessibility"}
    if "android" in platforms:
        gates["android_parity"] = {"build", "tests", "adaptive_layout", "accessibility", "r8_permissions", "play_metadata"}
    return gates


def _validate_reports(contract: dict[str, Any], evidence: dict[str, Any], root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    findings: list[dict[str, str]] = []
    if set(evidence) != {"schema", "candidate", "contract_sha256", "reports"} or evidence.get("candidate") != contract["candidate"]:
        return [], [{"code": "APPFORGE_MOBILE_EVIDENCE_BINDING_INVALID", "detail": "evidence must bind the exact candidate and fixed fields"}]
    supplied = _digest(evidence.get("contract_sha256"), "evidence.contract_sha256")
    if supplied != contract["contract_sha256"]:
        findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_CONTRACT_MISMATCH", "detail": "evidence names a different mobile evidence contract"})
    raw_reports = evidence.get("reports")
    if not isinstance(raw_reports, list) or not raw_reports or len(raw_reports) > 32:
        return [], findings + [{"code": "APPFORGE_MOBILE_EVIDENCE_REPORTS_MISSING", "detail": "evidence must contain 1-32 source-bound reports"}]
    reports: list[dict[str, Any]] = []
    for index, item in enumerate(raw_reports):
        report, errors = _report(root, item, contract["candidate"], index)
        findings.extend(errors)
        if report:
            reports.append(report)
    return reports, findings


def _findings(contract: dict[str, Any], reports: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    passed = {check for report in reports for check, status in report["checks"].items() if status == PASS}
    for gate, required in _required_evidence(contract["platforms"]).items():
        missing = sorted(required - passed)
        if missing:
            findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_GATE_INCOMPLETE", "detail": f"{gate} lacks passed evidence for: {', '.join(missing)}"})
    tools = {report["tool"] for report in reports}
    if "ios" in contract["platforms"] and not tools & {"xcodebuild", "xctest"}:
        findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_IOS_TOOL_MISSING", "detail": "iOS readiness needs an xcodebuild or XCTest source report"})
    if "android" in contract["platforms"] and not tools & {"android_gradle", "adb"}:
        findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_ANDROID_TOOL_MISSING", "detail": "Android readiness needs an Android Gradle or ADB source report"})
    if not tools & {"fastlane", "device_cloud"}:
        findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_VISUAL_TRANSPORT_MISSING", "detail": "visual truth needs a Fastlane or device-cloud source report"})
    observed_stages: dict[str, set[str]] = {stage: set() for stage in RELEASE_STAGES}
    for report in reports:
        for stage, status in report["release_stages"].items():
            observed_stages[stage].add(status)
    for stage, statuses in observed_stages.items():
        if not statuses or "failed" in statuses:
            findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_RELEASE_CHAIN_INCOMPLETE", "detail": f"release stage {stage} is absent or failed"})
    signals: dict[str, list[float]] = {metric: [] for metric in METRICS}
    for report in reports:
        for metric, value in report["production_signals"].items():
            signals[metric].append(value)
    thresholds = contract["production_thresholds"]
    comparisons = {
        "crash_free_rate": (min, thresholds["crash_free_rate_min"], "below"),
        "anr_rate": (max, thresholds["anr_rate_max"], "above"),
        "hang_rate": (max, thresholds["hang_rate_max"], "above"),
        "startup_ms": (max, thresholds["startup_ms_max"], "above"),
    }
    for metric, (aggregate, limit, direction) in comparisons.items():
        if not signals[metric]:
            findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_PRODUCTION_SIGNAL_MISSING", "detail": f"production signal {metric} is missing"})
        elif (aggregate(signals[metric]) < limit if direction == "below" else aggregate(signals[metric]) > limit):
            findings.append({"code": "APPFORGE_MOBILE_EVIDENCE_PRODUCTION_REGRESSION", "detail": f"production signal {metric} is {direction} its sealed threshold"})
    return findings


def verify_mobile_evidence(root: Path, candidate_path: Path, contract_path: Path, evidence_path: Path, out_path: Path) -> dict[str, Any]:
    """Normalize source-bound mobile evidence into one deterministic readiness receipt."""
    workspace = Path(root).resolve()
    candidate, _ = _read_candidate(workspace, candidate_path)
    raw_contract, contract_source = _read(workspace, contract_path, CONTRACT_SCHEMA)
    contract = _contract(raw_contract, candidate)
    contract["contract_sha256"] = _file_sha(contract_source)
    evidence, evidence_source = _read(workspace, evidence_path, EVIDENCE_SCHEMA)
    reports, findings = _validate_reports(contract, evidence, workspace)
    findings.extend(_findings(contract, reports))
    findings.sort(key=lambda item: (item["code"], item["detail"]))
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_MOBILE_EVIDENCE_READY" if not findings else "APPFORGE_MOBILE_EVIDENCE_BLOCKED",
        "ok": not findings,
        "action_summary": "Normalize hash-bound iOS and Android tool reports into one candidate-bound mobile evidence receipt covering visual truth, privacy-to-store consistency, release-chain state, design conformance, production signals, and Android parity without executing a tool or accessing a provider.",
        "candidate": candidate,
        "contract": {"path": contract_source.relative_to(workspace).as_posix(), "sha256": contract["contract_sha256"], "platforms": contract["platforms"], "user_design_input_sha256": contract["user_design_input_sha256"], "production_thresholds": contract["production_thresholds"]},
        "evidence_source": {"path": evidence_source.relative_to(workspace).as_posix(), "sha256": _file_sha(evidence_source)},
        "reports": reports,
        "findings": findings,
        "release_chain_states": {stage: sorted({report["release_stages"][stage] for report in reports}) for stage in RELEASE_STAGES},
        "authority": {**AUTHORITY, "execution": False, "device_access": False, "provider_access": False, "store_write": False, "app_review_submit": False, "approval_claim": False},
        "claim_boundary": "Local structural and hash validation only. Report contents remain supplied evidence; this receipt does not execute Xcode, XCTest, Gradle, ADB, Fastlane, a device cloud, Crashlytics, Sentry, MetricKit, Android Vitals, App Store Connect, or Play Console, and it does not prove runtime behavior, external state, submission, policy certification, or store approval.",
    }
    result = {**core, "receipt_sha256": _sha(core)}
    destination = _local(workspace, out_path, exists=False)
    if destination.exists():
        raise RevenueForgeError("APPFORGE_MOBILE_EVIDENCE_OUTPUT_EXISTS", "output receipt is immutable; choose a new path")
    _atomic(destination, result)
    return {**result, "path": destination.relative_to(workspace).as_posix()}


def mobile_evidence_projection(root: Path) -> dict[str, Any]:
    """Read valid mobile evidence receipts without invoking tools or providers."""
    workspace = Path(root).resolve(); current: list[dict[str, Any]] = []; invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("*mobile-evidence*.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            valid = value.get("schema") == RECEIPT_SCHEMA and isinstance(value.get("receipt_sha256"), str) and _sha({key: item for key, item in value.items() if key != "receipt_sha256"}) == value["receipt_sha256"]
            if valid:
                current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "ok": value.get("ok"), "candidate": value.get("candidate"), "receipt_sha256": value.get("receipt_sha256"), "finding_count": len(value.get("findings", []))})
            else:
                invalid.append(path.relative_to(workspace).as_posix())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.mobile-evidence-projection.v1", "marker": "APPFORGE_MOBILE_EVIDENCE_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**AUTHORITY, "execution": False, "device_access": False, "provider_access": False, "store_write": False, "app_review_submit": False, "approval_claim": False}, "claim_boundary": "Read-only local mobile evidence status; not tool execution, a device test, a provider-state readback, submission, or approval."}

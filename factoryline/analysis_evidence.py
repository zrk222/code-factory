"""Vendor-neutral, deterministic SARIF evidence adapter.

The adapter reads a user-selected local SARIF artifact. It never starts an
analyzer, contacts a vendor, modifies source, or treats a report as approval.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import unquote, urlparse


SCHEMA = "factory.analysis-evidence.v1"
MAX_ARTIFACT_BYTES = 10_000_000
SUPPORTED_PROVIDERS = ("qodana", "sonarqube")
_PROVIDER_NAMES = {
    "qodana": ("qodana",),
    "sonarqube": ("sonarqube", "sonarlint", "sonar"),
}


class AnalysisEvidenceError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _workspace(root: Path) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise AnalysisEvidenceError("ANALYSIS_ROOT_INVALID", "root must be an existing directory")
    return workspace


def _local_file(workspace: Path, value: Path) -> Path:
    candidate = Path(value)
    candidate = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise AnalysisEvidenceError("ANALYSIS_PATH_REJECTED", "analysis evidence must stay inside the workspace") from exc
    if not candidate.is_file() or candidate.stat().st_size > MAX_ARTIFACT_BYTES:
        raise AnalysisEvidenceError("ANALYSIS_ARTIFACT_INVALID", f"analysis evidence must be a regular file no larger than {MAX_ARTIFACT_BYTES} bytes")
    return candidate


def _driver_names(payload: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for run in payload.get("runs", []):
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        name = driver.get("name") if isinstance(driver, dict) else None
        if isinstance(name, str) and name.strip():
            names.append(name.strip())
    return sorted(set(names), key=str.casefold)


def _detected_provider(names: list[str]) -> str | None:
    detected: set[str] = set()
    for name in names:
        lowered = name.casefold()
        for provider, aliases in _PROVIDER_NAMES.items():
            if any(alias in lowered for alias in aliases):
                detected.add(provider)
    if len(detected) > 1:
        raise AnalysisEvidenceError("ANALYSIS_PROVIDER_AMBIGUOUS", "SARIF tool drivers identify more than one supported provider")
    return next(iter(detected), None)


def _provider(requested: str, names: list[str]) -> str:
    value = requested.strip().lower() if isinstance(requested, str) else ""
    if value not in {"auto", *SUPPORTED_PROVIDERS}:
        raise AnalysisEvidenceError("ANALYSIS_PROVIDER_UNSUPPORTED", "analysis provider must be auto, qodana, or sonarqube")
    detected = _detected_provider(names)
    if value == "auto":
        if detected is None:
            raise AnalysisEvidenceError("ANALYSIS_PROVIDER_UNVERIFIED", "auto detection requires a Qodana or SonarQube SARIF tool driver name")
        return detected
    if detected is not None and detected != value:
        raise AnalysisEvidenceError("ANALYSIS_PROVIDER_MISMATCH", f"requested {value} but SARIF tool driver identifies {detected}")
    return value


def _safe_uri(uri: object) -> str | None:
    if not isinstance(uri, str) or not uri.strip():
        return None
    decoded = unquote(uri.strip()).replace("\\", "/")
    parsed = urlparse(decoded)
    if parsed.scheme or parsed.netloc or decoded.startswith("/") or re.match(r"^[A-Za-z]:/", decoded):
        return None
    normalized = decoded.removeprefix("./").rstrip("/")
    if not normalized or any(part in {"", ".."} for part in normalized.split("/")):
        return None
    return normalized


def parse_analysis_sarif(root: Path, sarif_path: Path, *, provider: str = "auto") -> dict[str, Any]:
    """Normalize bounded Qodana or SonarQube SARIF facts without executing it."""
    workspace = _workspace(root)
    path = _local_file(workspace, sarif_path)
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "analysis evidence must contain UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("version") != "2.1.0" or not isinstance(payload.get("runs"), list) or not payload["runs"]:
        raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "analysis evidence must be a SARIF 2.1.0 object with at least one run")
    names = _driver_names(payload)
    resolved_provider = _provider(provider, names)
    findings: list[dict[str, Any]] = []
    execution: list[bool] = []
    for run in payload["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
            raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "every SARIF run must contain a results array when present")
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list):
            raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "SARIF invocations must be an array")
        for invocation in invocations:
            if isinstance(invocation, dict) and isinstance(invocation.get("executionSuccessful"), bool):
                execution.append(invocation["executionSuccessful"])
        for result in run.get("results", []):
            if not isinstance(result, dict):
                raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "SARIF results must be objects")
            rule = result.get("ruleId")
            if not isinstance(rule, str) or not rule.strip() or len(rule) > 200:
                raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "each SARIF result must contain a bounded ruleId")
            level = result.get("level", "warning")
            if level not in {"error", "warning", "note", "none"}:
                raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "SARIF result level is unsupported")
            baseline = result.get("baselineState", "unbaselined")
            if baseline not in {"new", "unchanged", "absent", "updated", "unbaselined"}:
                raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "SARIF baselineState is unsupported")
            locations: list[str] = []
            raw_locations = result.get("locations", [])
            if not isinstance(raw_locations, list):
                raise AnalysisEvidenceError("ANALYSIS_SARIF_INVALID", "SARIF result locations must be an array")
            for location in raw_locations:
                try:
                    uri = location["physicalLocation"]["artifactLocation"]["uri"]
                except (KeyError, TypeError):
                    continue
                safe = _safe_uri(uri)
                if safe is not None:
                    locations.append(safe)
            findings.append({"rule_id": rule.strip(), "level": level, "baseline_state": baseline, "paths": sorted(set(locations))[:20]})
    counts = {key: 0 for key in ("error", "warning", "note", "none", "new", "unchanged", "absent", "updated", "unbaselined")}
    for finding in findings:
        counts[finding["level"]] += 1
        counts[finding["baseline_state"]] += 1
    core = {
        "schema": SCHEMA,
        "marker": "ANALYSIS_EVIDENCE_NORMALIZED",
        "provider": resolved_provider,
        "tool_driver_names": names,
        "path": path.relative_to(workspace).as_posix(),
        "file_sha256": sha256(raw).hexdigest(),
        "execution_successful": False if False in execution else True if execution else None,
        "counts": counts,
        "findings": sorted(findings, key=lambda item: (item["baseline_state"], item["level"], item["rule_id"], item["paths"])),
        "authority": {"analyzer_execute": False, "source_modify": False, "network": False, "approval": False},
        "claim_boundary": "supplied local SARIF facts only; not analyzer execution, vendor certification, absence of defects, or release approval",
    }
    core["evidence_sha256"] = sha256(json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return core

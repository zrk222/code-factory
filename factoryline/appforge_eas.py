"""Credential-free EAS handoff preflight for an AppForge iOS candidate.

This module checks only a local ``eas.json`` profile and binds the resulting
handoff packet to one release candidate.  It never reads Expo, Apple, or CI
credentials; builds, TestFlight upload, App Store Connect submission, and
Apple approval remain separate user-authorized actions.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .appforge_evidence_kit import CANDIDATE_SCHEMA, _read_candidate
from .revenueforge import AUTHORITY, RevenueForgeError


PREFLIGHT_SCHEMA = "factory.appforge.eas-preflight.v1"
RECEIPT_SCHEMA = "factory.appforge.eas-preflight-receipt.v1"
MAX_BYTES = 1_048_576
SENSITIVE_KEYS = {"token", "password", "privatekey", "private_key", "clientsecret", "client_secret", "apikey", "api_key"}


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_EAS_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise RevenueForgeError("APPFORGE_EAS_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _text(value: object, field: str, *, limit: int = 120) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_EAS_PROFILE_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _read_eas_config(root: Path, path: Path) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_EAS_INPUT_TOO_LARGE", "eas.json exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_EAS_INPUT_INVALID", "eas.json must be valid JSON") from exc
    if not isinstance(value, dict):
        raise RevenueForgeError("APPFORGE_EAS_INPUT_INVALID", "eas.json must be a JSON object")
    return value, source


def _secret_findings(value: object, prefix: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).replace("-", "").lower()
            location = f"{prefix}.{key}" if prefix else str(key)
            if normalized in SENSITIVE_KEYS or "token" in normalized or "password" in normalized or "secret" in normalized:
                findings.append(location)
            findings.extend(_secret_findings(item, location))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_secret_findings(item, f"{prefix}[{index}]"))
    return findings


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


def verify_eas_preflight(
    root: Path,
    candidate_path: Path,
    eas_config_path: Path,
    build_profile: str,
    submit_profile: str,
    *,
    out: Path | None = None,
) -> dict[str, Any]:
    """Validate a candidate-bound EAS handoff without invoking Expo or Apple."""
    workspace = Path(root).resolve()
    candidate, candidate_source = _read_candidate(workspace, candidate_path)
    config, source = _read_eas_config(workspace, eas_config_path)
    build_name = _text(build_profile, "build_profile")
    submit_name = _text(submit_profile, "submit_profile")
    findings: list[dict[str, str]] = []
    secret_paths = _secret_findings(config)
    if secret_paths:
        findings.append({"code": "APPFORGE_EAS_SECRET_IN_CONFIG", "detail": "credential-like keys are forbidden in eas.json: " + ", ".join(secret_paths)})
    build = config.get("build")
    if not isinstance(build, dict) or not isinstance(build.get(build_name), dict):
        findings.append({"code": "APPFORGE_EAS_BUILD_PROFILE_MISSING", "detail": f"build.{build_name} is required"})
    submit = config.get("submit")
    submit_entry = submit.get(submit_name) if isinstance(submit, dict) else None
    ios = submit_entry.get("ios") if isinstance(submit_entry, dict) else None
    asc_app_id = ios.get("ascAppId") if isinstance(ios, dict) else None
    if not isinstance(asc_app_id, (str, int)) or not str(asc_app_id).strip().isdigit():
        findings.append({"code": "APPFORGE_EAS_ASC_APP_ID_MISSING", "detail": f"submit.{submit_name}.ios.ascAppId must be a numeric App Store Connect app id"})
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_EAS_PREFLIGHT_READY" if not findings else "APPFORGE_EAS_PREFLIGHT_BLOCKED",
        "ok": not findings,
        "action_summary": "Check that one exact release candidate has named local EAS build and iOS submission profiles while deliberately keeping credentials, builds, uploads, submission, and approval outside Code Factory.",
        "candidate": candidate,
        "candidate_source": candidate_source.relative_to(workspace).as_posix(),
        "candidate_source_sha256": hashlib.sha256(candidate_source.read_bytes()).hexdigest(),
        "eas_config": {"path": source.relative_to(workspace).as_posix(), "sha256": hashlib.sha256(source.read_bytes()).hexdigest()},
        "profiles": {"build": build_name, "submit": submit_name, "asc_app_id": str(asc_app_id).strip() if not findings and asc_app_id is not None else None},
        "findings": findings,
        "human_handoff": [
            "Run the reviewed EAS build profile from the developer's own authenticated environment.",
            "Inspect the completed build and candidate binding before choosing a submit action.",
            "Authorize any EAS submit or App Store Connect action separately; this receipt is not that authorization.",
        ],
        "authority": {**AUTHORITY, "credential_access": False, "eas_build_execute": False, "testflight_upload": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Local EAS configuration preflight only. It does not read environment variables or credential files, invoke EAS, create a build, upload to TestFlight, submit to App Review, inspect App Store Connect, or guarantee Apple approval.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    if out is not None:
        target = _local(workspace, Path(out), exists=False)
        if target.exists():
            raise RevenueForgeError("APPFORGE_EAS_OUTPUT_EXISTS", "preflight receipt destination already exists")
        _atomic_json(target, receipt)
        return {**receipt, "path": target.relative_to(workspace).as_posix()}
    return receipt


def appforge_eas_projection(root: Path) -> dict[str, Any]:
    """Read hash-valid local EAS preflight receipts without changing release state."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    for path in sorted((workspace / ".factory" / "appforge").rglob("*eas-preflight*.json"))[:100]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            supplied = value.pop("receipt_sha256", None)
            if value.get("schema") == RECEIPT_SCHEMA and isinstance(supplied, str) and _sha(value) == supplied:
                current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "ok": value.get("ok"), "candidate": value.get("candidate"), "profiles": value.get("profiles"), "receipt_sha256": supplied})
            else:
                invalid.append(path.relative_to(workspace).as_posix())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            invalid.append(path.relative_to(workspace).as_posix())
    return {
        "schema": "factory.appforge.eas-preflight-projection.v1",
        "marker": "APPFORGE_EAS_PREFLIGHT_READ_ONLY",
        "current_count": len(current),
        "invalid_count": len(invalid),
        "latest": current[-1] if current else None,
        "invalid": invalid,
        "authority": {**AUTHORITY, "credential_access": False, "eas_build_execute": False, "testflight_upload": False, "app_store_connect_write": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Hash-verified local EAS profile status only; not an EAS execution, TestFlight state, App Store Connect state, App Review submission, or Apple approval.",
    }

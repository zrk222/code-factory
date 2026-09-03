"""Non-executing Fastlane/ASC/Cider/Swiftlane/Zealot release rehearsal for AppForge.

This borrows the useful operational discipline of release lanes, declarative
manifest binding, and staged provider validation without importing a client or
granting it authority.
It seals a local handoff plan; a separately authenticated human must still run
any provider command and verify every external state directly with that
provider.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .appforge_evidence_kit import _read_candidate
from .appforge_submission_assurance import RECEIPT_SCHEMA as ASSURANCE_SCHEMA
from .revenueforge import AUTHORITY, RevenueForgeError


PROFILE_SCHEMA = "factory.appforge.release-automation-profile.v1"
RECEIPT_SCHEMA = "factory.appforge.release-rehearsal-receipt.v1"
ZEALOT_MANIFEST_SCHEMA = "factory.appforge.beta-distribution-manifest.v1"
MAX_BYTES = 1_048_576
PROVIDERS = frozenset({"fastlane", "asc_cli", "cider", "swiftlane", "zealot"})
CHANNELS = frozenset({"testflight_internal", "testflight_external", "app_store", "beta_distribution"})
STAGES = (
    "local_readiness", "archive_export", "upload", "provider_processing",
    "tester_group_assignment", "tester_invitation_readback",
    "external_beta_review_submission", "app_review_submission", "app_review_decision",
)
SECRET_HINTS = ("token", "password", "secret", "private_key", "privatekey", "api_key", "apikey", "credential")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _local(root: Path, path: Path, *, exists: bool = True) -> Path:
    workspace = Path(root).resolve()
    target = path.resolve() if path.is_absolute() else (workspace / path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError as exc:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PATH_REJECTED", "paths must remain inside the workspace") from exc
    if exists and not target.is_file():
        raise RevenueForgeError("APPFORGE_REHEARSAL_INPUT_UNAVAILABLE", "input must be a regular workspace file")
    return target


def _read_json(root: Path, path: Path, schema: str) -> tuple[dict[str, Any], Path]:
    source = _local(root, path)
    if source.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_REHEARSAL_INPUT_TOO_LARGE", "JSON input exceeds 1 MiB")
    try:
        value = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_REHEARSAL_INPUT_INVALID", "input must be valid JSON") from exc
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise RevenueForgeError("APPFORGE_REHEARSAL_SCHEMA_REJECTED", f"expected {schema}")
    return value, source


def _text(value: object, field: str, *, limit: int = 160) -> str:
    result = str(value or "").strip()
    if not result or len(result) > limit:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROFILE_INVALID", f"{field} must be a non-empty bounded string")
    return result


def _sealed(value: object, schema: str) -> bool:
    if not isinstance(value, dict) or value.get("schema") != schema:
        return False
    supplied = value.get("receipt_sha256")
    return isinstance(supplied, str) and len(supplied) == 64 and _sha({key: item for key, item in value.items() if key != "receipt_sha256"}) == supplied


def _secret_keys(value: object, prefix: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).replace("-", "_").lower()
            path = f"{prefix}.{key}" if prefix else str(key)
            if any(hint in normalized for hint in SECRET_HINTS):
                findings.append(path)
            findings.extend(_secret_keys(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_secret_keys(item, f"{prefix}[{index}]"))
    return findings


def _cider_manifest(root: Path, config: dict[str, Any]) -> dict[str, str]:
    if set(config) != {"manifest_path"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Cider provider_config may contain only manifest_path")
    declared = _text(config.get("manifest_path"), "provider_config.manifest_path", limit=512)
    path = _local(root, Path(declared))
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Cider manifest_path must reference a YAML file")
    if path.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_REHEARSAL_INPUT_TOO_LARGE", "Cider manifest exceeds 1 MiB")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_REHEARSAL_INPUT_INVALID", "Cider manifest must be UTF-8 text") from exc
    if re.search(r"(?im)^\s*[^#\n]*(?:token|password|secret|private[_-]?key|api[_-]?key|credential)[^:\n]*:", text):
        raise RevenueForgeError("APPFORGE_REHEARSAL_SECRET_IN_PROFILE", "Cider manifest must not contain credential-like keys")
    return {"manifest_path": path.relative_to(root).as_posix(), "manifest_sha256": _file_sha(path)}


def _swiftlane_workflow(root: Path, config: dict[str, Any]) -> dict[str, Any]:
    if set(config) != {"workflow_path"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Swiftlane provider_config may contain only workflow_path")
    declared = _text(config.get("workflow_path"), "provider_config.workflow_path", limit=512)
    path = _local(root, Path(declared))
    if path.suffix.lower() != ".swift":
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Swiftlane workflow_path must reference a Swift file")
    if path.stat().st_size > MAX_BYTES:
        raise RevenueForgeError("APPFORGE_REHEARSAL_INPUT_TOO_LARGE", "Swiftlane workflow exceeds 1 MiB")
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise RevenueForgeError("APPFORGE_REHEARSAL_INPUT_INVALID", "Swiftlane workflow must be UTF-8 text") from exc
    steps = {
        "build": "Build(" in text,
        "test": "Test(" in text,
        "archive": "Archive(" in text,
        "export_archive": "ExportArchive(" in text,
    }
    if "Workflow(" not in text or not all(steps.values()):
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Swiftlane workflow must visibly declare Workflow, Build, Test, Archive, and ExportArchive stages")
    return {
        "workflow_path": path.relative_to(root).as_posix(),
        "workflow_sha256": _file_sha(path),
        "declared_source_steps": steps,
        "source_presence_only": True,
    }


def _zealot_manifest(root: Path, config: dict[str, Any], candidate: dict[str, str]) -> dict[str, str]:
    if set(config) != {"manifest_path"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Zealot provider_config may contain only manifest_path")
    declared = _text(config.get("manifest_path"), "provider_config.manifest_path", limit=512)
    manifest, path = _read_json(root, Path(declared), ZEALOT_MANIFEST_SCHEMA)
    if _secret_keys(manifest):
        raise RevenueForgeError("APPFORGE_REHEARSAL_SECRET_IN_PROFILE", "beta-distribution manifest must not include credential-like keys")
    if set(manifest) != {"schema", "candidate", "platform", "artifact", "distribution"} or manifest.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_REHEARSAL_CANDIDATE_MISMATCH", "beta-distribution manifest must bind exactly the release candidate")
    platform = _text(manifest.get("platform"), "platform", limit=16)
    if platform not in {"ios", "android", "macos", "windows", "linux"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "beta-distribution platform is unsupported")
    artifact = manifest.get("artifact")
    distribution = manifest.get("distribution")
    if not isinstance(artifact, dict) or set(artifact) != {"sha256"} or not isinstance(distribution, dict) or set(distribution) != {"channel", "audience_ref"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "beta-distribution manifest has an invalid artifact or audience declaration")
    artifact_sha = _text(artifact.get("sha256"), "artifact.sha256", limit=64)
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha):
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "artifact.sha256 must be 64 lowercase hexadecimal characters")
    return {
        "manifest_path": path.relative_to(root).as_posix(),
        "manifest_sha256": _file_sha(path),
        "platform": platform,
        "artifact_sha256": artifact_sha,
        "distribution_channel": _text(distribution.get("channel"), "distribution.channel"),
        "audience_ref": _text(distribution.get("audience_ref"), "distribution.audience_ref"),
    }


def _profile(root: Path, profile: dict[str, Any], candidate: dict[str, str]) -> dict[str, Any]:
    if _secret_keys(profile):
        raise RevenueForgeError("APPFORGE_REHEARSAL_SECRET_IN_PROFILE", "automation profile must not include credential-like keys")
    if set(profile) != {"schema", "candidate", "provider", "release_channel", "provider_config"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROFILE_INVALID", "automation profile has unsupported fields")
    if profile.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_REHEARSAL_CANDIDATE_MISMATCH", "automation profile candidate must exactly match the release candidate")
    provider = _text(profile.get("provider"), "provider", limit=32)
    if provider not in PROVIDERS:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_REJECTED", "provider must be fastlane, asc_cli, cider, swiftlane, or zealot")
    channel = _text(profile.get("release_channel"), "release_channel", limit=32)
    if channel not in CHANNELS:
        raise RevenueForgeError("APPFORGE_REHEARSAL_CHANNEL_INVALID", "release_channel is unsupported")
    config = profile.get("provider_config")
    if not isinstance(config, dict):
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "provider_config must be an object")
    if provider == "fastlane":
        if set(config) != {"lane"}:
            raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Fastlane provider_config may contain only lane")
        lane = _text(config.get("lane"), "provider_config.lane", limit=80)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", lane):
            raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "Fastlane lane must be alphanumeric with underscores")
        return {"provider": provider, "release_channel": channel, "lane": lane}
    if provider == "cider":
        return {"provider": provider, "release_channel": channel, **_cider_manifest(root, config)}
    if provider == "swiftlane":
        return {"provider": provider, "release_channel": channel, **_swiftlane_workflow(root, config)}
    if provider == "zealot":
        if channel != "beta_distribution":
            raise RevenueForgeError("APPFORGE_REHEARSAL_CHANNEL_INVALID", "Zealot rehearsal requires beta_distribution channel")
        return {"provider": provider, "release_channel": channel, **_zealot_manifest(root, config, candidate)}
    if set(config) != {"app_store_connect_app_id"}:
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "ASC CLI provider_config may contain only app_store_connect_app_id")
    app_id = _text(config.get("app_store_connect_app_id"), "provider_config.app_store_connect_app_id", limit=20)
    if not app_id.isdecimal():
        raise RevenueForgeError("APPFORGE_REHEARSAL_PROVIDER_INVALID", "App Store Connect app id must be decimal")
    return {"provider": provider, "release_channel": channel, "app_store_connect_app_id": app_id}


def _matrix(channel: str) -> list[dict[str, str]]:
    statuses = {stage: "not_attempted" for stage in STAGES}
    statuses["local_readiness"] = "ready"
    if channel == "testflight_internal":
        statuses["external_beta_review_submission"] = "not_applicable"
        statuses["app_review_submission"] = "not_applicable"
        statuses["app_review_decision"] = "not_applicable"
    elif channel == "testflight_external":
        statuses["app_review_submission"] = "not_applicable"
        statuses["app_review_decision"] = "not_applicable"
    elif channel == "app_store":
        for stage in ("tester_group_assignment", "tester_invitation_readback", "external_beta_review_submission"):
            statuses[stage] = "not_applicable"
    else:
        for stage in ("external_beta_review_submission", "app_review_submission", "app_review_decision"):
            statuses[stage] = "not_applicable"
    return [{"stage": stage, "status": statuses[stage]} for stage in STAGES]


def _validate_matrix(matrix: list[dict[str, str]], channel: str) -> None:
    """Fail closed if a future change blurs an external provider-state boundary."""
    if len(matrix) != len(STAGES) or [item.get("stage") for item in matrix] != list(STAGES):
        raise RevenueForgeError("APPFORGE_REHEARSAL_STATE_INVALID", "release rehearsal must contain the fixed ordered state matrix")
    statuses = {str(item["stage"]): item.get("status") for item in matrix}
    if statuses["local_readiness"] != "ready":
        raise RevenueForgeError("APPFORGE_REHEARSAL_STATE_INVALID", "local readiness must be ready")
    if any(status == "ready" for stage, status in statuses.items() if stage != "local_readiness"):
        raise RevenueForgeError("APPFORGE_REHEARSAL_STATE_INVALID", "external provider stages cannot be marked ready by a local rehearsal")
    expected_not_applicable = {
        "testflight_internal": {"external_beta_review_submission", "app_review_submission", "app_review_decision"},
        "testflight_external": {"app_review_submission", "app_review_decision"},
        "app_store": {"tester_group_assignment", "tester_invitation_readback", "external_beta_review_submission"},
        "beta_distribution": {"external_beta_review_submission", "app_review_submission", "app_review_decision"},
    }[channel]
    actual_not_applicable = {stage for stage, status in statuses.items() if status == "not_applicable"}
    if actual_not_applicable != expected_not_applicable:
        raise RevenueForgeError("APPFORGE_REHEARSAL_CHANNEL_INVALID", "release channel does not preserve its required provider-state boundaries")


def _handoff(provider: dict[str, Any]) -> list[str]:
    if provider["provider"] == "fastlane":
        return [
            f"Review the declared Fastlane lane `{provider['lane']}` in the project Fastfile before any manual execution.",
            "In the authenticated release environment, separately verify the exact archive/export artifact, upload result, processing state, and tester or review state.",
        ]
    if provider["provider"] == "cider":
        return [
            f"Review the sealed Cider YAML manifest `{provider['manifest_path']}` at SHA-256 `{provider['manifest_sha256']}` before any manual execution.",
            "In the separately authenticated environment, use Cider's own documented validation and submission controls, then read back every provider state from App Store Connect.",
        ]
    if provider["provider"] == "swiftlane":
        return [
            f"Review the sealed Swiftlane workflow `{provider['workflow_path']}` at SHA-256 `{provider['workflow_sha256']}` and confirm the declared source stages before any manual execution.",
            "Use a separately authenticated macOS/Xcode environment for any Swiftlane action, then read back archive/export, upload, processing, tester delivery, and review states from their authoritative systems.",
        ]
    if provider["provider"] == "zealot":
        return [
            f"Review the sealed beta-distribution manifest `{provider['manifest_path']}` at SHA-256 `{provider['manifest_sha256']}` for its exact {provider['platform']} artifact, channel, and audience reference before any manual provider action.",
            "In the separately authenticated distribution environment, confirm the artifact, group assignment, invitation, and actual recipient read-back as separate provider facts.",
        ]
    return [
        f"In the authenticated App Store Connect CLI environment, review strict validation and a dry-run staging plan for app id `{provider['app_store_connect_app_id']}` before any submit action.",
        "After any manual provider action, read back the distinct upload, processing, tester delivery, and review states from App Store Connect.",
    ]


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


def create_release_rehearsal(root: Path, candidate_path: Path, assurance_path: Path, profile_path: Path, out_path: Path) -> dict[str, Any]:
    """Seal a provider-neutral release handoff without invoking any release tool."""
    workspace = Path(root).resolve()
    candidate, candidate_source = _read_candidate(workspace, candidate_path)
    assurance, assurance_source = _read_json(workspace, assurance_path, ASSURANCE_SCHEMA)
    if not _sealed(assurance, ASSURANCE_SCHEMA):
        raise RevenueForgeError("APPFORGE_REHEARSAL_ASSURANCE_TAMPERED", "submission assurance receipt is not hash-valid")
    if assurance.get("ok") is not True or assurance.get("candidate") != candidate:
        raise RevenueForgeError("APPFORGE_REHEARSAL_ASSURANCE_BLOCKED", "submission assurance must be ready and bound to the exact candidate")
    profile, profile_source = _read_json(workspace, profile_path, PROFILE_SCHEMA)
    provider = _profile(workspace, profile, candidate)
    matrix = _matrix(provider["release_channel"])
    _validate_matrix(matrix, provider["release_channel"])
    core: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "marker": "APPFORGE_RELEASE_REHEARSAL_READY",
        "ok": True,
        "action_summary": "Seal a non-executing Fastlane, App Store Connect CLI, Cider, Swiftlane, or Zealot release rehearsal that preserves the difference between local readiness, upload, processing, beta delivery, review submission, and Apple decision.",
        "candidate": candidate,
        "sources": {
            "candidate": {"path": candidate_source.relative_to(workspace).as_posix(), "sha256": _file_sha(candidate_source)},
            "submission_assurance": {"path": assurance_source.relative_to(workspace).as_posix(), "sha256": _file_sha(assurance_source), "receipt_sha256": assurance["receipt_sha256"]},
            "automation_profile": {"path": profile_source.relative_to(workspace).as_posix(), "sha256": _file_sha(profile_source)},
        },
        "provider": provider,
        "state_matrix": matrix,
        "stage_count": len(matrix),
        "external_ready_count": 0,
        "human_handoff": _handoff(provider),
        "authority": {**AUTHORITY, "execution": False, "credential_access": False, "network": False, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False},
        "claim_boundary": "Local rehearsal only. It does not parse or run a Fastfile, invoke ASC CLI, parse or run Cider YAML, run a Swiftlane workflow, invoke Zealot, access credentials, archive, sign, upload, wait for processing, assign testers, invite testers, submit beta review or App Review, poll Apple, or guarantee approval. Swift source step presence and beta-distribution manifest facts are not execution or delivery evidence. Every external state requires authenticated provider read-back.",
    }
    receipt = {**core, "receipt_sha256": _sha(core)}
    target = _local(workspace, out_path, exists=False)
    if target.exists():
        raise RevenueForgeError("APPFORGE_REHEARSAL_OUTPUT_EXISTS", "sealed rehearsal destination already exists")
    _atomic_json(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def release_rehearsal_projection(root: Path) -> dict[str, Any]:
    """Read bounded, hash-valid rehearsals without inspecting provider state."""
    workspace = Path(root).resolve()
    current: list[dict[str, Any]] = []
    invalid: list[str] = []
    base = workspace / ".factory" / "appforge"
    if base.exists():
        for path in sorted(base.rglob("*release-rehearsal*.json"))[:100]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if _sealed(value, RECEIPT_SCHEMA):
                    current.append({"path": path.relative_to(workspace).as_posix(), "marker": value.get("marker"), "candidate": value.get("candidate"), "provider": value.get("provider"), "receipt_sha256": value.get("receipt_sha256")})
                elif value.get("schema") == RECEIPT_SCHEMA:
                    invalid.append(path.relative_to(workspace).as_posix())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": "factory.appforge.release-rehearsal-projection.v1", "marker": "APPFORGE_RELEASE_REHEARSAL_READ_ONLY", "current_count": len(current), "invalid_count": len(invalid), "latest": current[-1] if current else None, "invalid": invalid, "authority": {**AUTHORITY, "execution": False, "credential_access": False, "network": False, "app_store_connect_write": False, "testflight_upload": False, "app_review_submit": False, "apple_approval_claim": False}, "claim_boundary": "Read-only local rehearsal status; not Fastlane/ASC execution, provider state, TestFlight delivery, App Review submission, or Apple approval."}

"""Fail-closed supply-chain and reproducible-release evidence.

This module binds the release candidate to the exact source, lockfiles, SBOM,
VEX, licence policy and independently repeated build outputs.  It deliberately
does not grant signing, release, publication or deployment authority: a local
receipt is evidence for review, not an approval token.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tarfile
from typing import Any
import zipfile

from .enterprise_receipts import EnterpriseReceiptError, verify_signed_document
from .runtime_audit_common import (
    canonical_bytes,
    require_bool,
    require_digest,
    require_int,
    require_str,
)


ATTESTATION_SCHEMA = "factory.supply-chain-attestation.v1"
RECEIPT_SCHEMA = "factory.supply-chain-receipt.v1"
VERIFICATION_SCHEMA = "factory.supply-chain-verification.v1"
PAYLOAD_TYPE = "application/vnd.factory.supply-chain-attestation.v1+json"
MAX_FILES = 2048
MAX_COMPONENTS = 4096
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
ARTIFACT_SUFFIXES = (".whl", ".tar.gz", ".vsix", ".zip", ".tgz")
VEX_STATUSES = frozenset({"not_affected", "affected", "fixed", "under_investigation"})
SEVERITIES = frozenset({"critical", "high", "medium", "low"})
LICENSE_STATUSES = frozenset({"allowed", "denied", "unknown"})
COLLECTOR_ROLES = frozenset(
    {
        "local_evaluator",
        "independent_builder",
        "independent_security_scanner",
        "release_attestor",
    }
)


class SupplyChainError(ValueError):
    """A stable, reviewable fail-closed supply-chain error."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    try:
        return canonical_bytes(value)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SupplyChainError("E_CANONICAL", str(exc)) from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_digest(path: Path) -> tuple[str, int]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SupplyChainError("E_FILE_READ", f"cannot read {path}: {exc}") from exc
    return hashlib.sha256(data).hexdigest(), len(data)


def _inside(root: Path, supplied: str | Path, label: str) -> tuple[Path, str]:
    workspace = Path(root).resolve()
    raw = str(supplied).replace("\\", "/")
    absolute = raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw) is not None
    if not raw.strip() or "\x00" in raw:
        raise SupplyChainError(
            "E_PATH_BOUNDARY", f"{label} must be a relative workspace path"
        )
    if absolute and not label.endswith("output"):
        raise SupplyChainError(
            "E_PATH_BOUNDARY", f"{label} must be a relative workspace path"
        )
    candidate = Path(raw).resolve() if absolute else (workspace / Path(raw)).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise SupplyChainError(
            "E_PATH_BOUNDARY", f"{label} escapes the workspace"
        ) from exc
    relative = candidate.relative_to(workspace).as_posix()
    if relative == "." or any(part == ".." for part in Path(raw).parts):
        raise SupplyChainError("E_PATH_BOUNDARY", f"{label} contains traversal")
    return candidate, relative


def _descriptor(
    root: Path, value: Any, label: str, *, suffixes: tuple[str, ...] = ()
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}:
        raise SupplyChainError(
            "E_DESCRIPTOR_FIELDS",
            f"{label} must contain exactly path, sha256 and bytes",
        )
    path, relative = _inside(root, value["path"], label)
    if path.is_symlink() or not path.is_file():
        raise SupplyChainError(
            "E_FILE_BOUNDARY", f"{label} is missing or a symlink: {relative}"
        )
    actual_digest, actual_bytes = _file_digest(path)
    supplied_digest = require_digest(value["sha256"], f"{label}.sha256")
    supplied_bytes = require_int(
        value["bytes"], f"{label}.bytes", minimum=0, maximum=MAX_ARCHIVE_BYTES
    )
    if actual_digest != supplied_digest:
        raise SupplyChainError(
            "E_FILE_DIGEST", f"{relative} digest does not match its descriptor"
        )
    if actual_bytes != supplied_bytes:
        raise SupplyChainError(
            "E_FILE_SIZE", f"{relative} byte count does not match its descriptor"
        )
    if suffixes and not relative.lower().endswith(suffixes):
        raise SupplyChainError(
            "E_ARTIFACT_SUFFIX", f"{relative} is not an allowed release artifact"
        )
    return {"path": relative, "sha256": actual_digest, "bytes": actual_bytes}


def _list_descriptors(
    root: Path, value: Any, label: str, *, minimum: int, suffixes: tuple[str, ...] = ()
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not minimum <= len(value) <= MAX_FILES:
        raise SupplyChainError(
            "E_DESCRIPTOR_LIST",
            f"{label} must contain {minimum}..{MAX_FILES} descriptors",
        )
    rows = [
        _descriptor(root, item, f"{label}[{index}]", suffixes=suffixes)
        for index, item in enumerate(value)
    ]
    paths = [row["path"] for row in rows]
    if len(paths) != len(set(paths)):
        raise SupplyChainError("E_DUPLICATE_PATH", f"{label} contains duplicate paths")
    return sorted(rows, key=lambda row: row["path"])


def _read_json(root: Path, descriptor: dict[str, Any], label: str) -> dict[str, Any]:
    path = root / descriptor["path"]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError(
            "E_JSON_ARTIFACT", f"{label} is not readable JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise SupplyChainError("E_JSON_ARTIFACT", f"{label} must be a JSON object")
    return value


def _timestamp(value: Any, field: str) -> datetime:
    text = require_str(value, field, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SupplyChainError("E_TIMESTAMP", f"{field} is not RFC3339") from exc
    if parsed.tzinfo is None:
        raise SupplyChainError("E_TIMESTAMP", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _assert_exact(
    value: Any, required: set[str], label: str, optional: set[str] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SupplyChainError("E_FIELDS", f"{label} must be an object")
    optional = optional or set()
    if set(value) - required - optional or required - set(value):
        raise SupplyChainError("E_FIELDS", f"{label} has missing or unknown fields")
    return value


def _scan_archive(path: Path) -> list[tuple[str, bytes]]:
    lowered = path.name.lower()
    if not lowered.endswith(ARTIFACT_SUFFIXES):
        return []
    try:
        if lowered.endswith((".whl", ".vsix", ".zip")):
            return _scan_zip_archive(path)
        return _scan_tar_archive(path)
    except SupplyChainError:
        raise
    except (OSError, EOFError, tarfile.TarError, zipfile.BadZipFile) as exc:
        raise SupplyChainError(
            "E_ARCHIVE_INVALID", f"{path.name} cannot be inspected: {exc}"
        ) from exc


def _safe_archive_member_name(raw_name: str) -> str:
    name = raw_name.replace("\\", "/")
    if name.startswith("/") or any(part in {"", ".", ".."} for part in name.split("/")):
        raise SupplyChainError("E_ARCHIVE_PATH", f"unsafe archive member {name}")
    return name


def _scan_zip_archive(path: Path) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(path) as archive:
        total = 0
        for info in archive.infolist():
            name = _safe_archive_member_name(info.filename)
            if info.is_dir():
                continue
            total += info.file_size
            if total > MAX_ARCHIVE_BYTES:
                raise SupplyChainError(
                    "E_ARCHIVE_SIZE",
                    f"archive contents exceed {MAX_ARCHIVE_BYTES} bytes",
                )
            members.append((name, archive.read(info)))
    return members


def _scan_tar_archive(path: Path) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with tarfile.open(path, mode="r:*") as archive:
        total = 0
        for info in archive.getmembers():
            name = _safe_archive_member_name(info.name)
            if not info.isfile():
                continue
            total += info.size
            if total > MAX_ARCHIVE_BYTES:
                raise SupplyChainError(
                    "E_ARCHIVE_SIZE",
                    f"archive contents exceed {MAX_ARCHIVE_BYTES} bytes",
                )
            stream = archive.extractfile(info)
            members.append((name, stream.read() if stream is not None else b""))
    return members


_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"(?:ghp_|github_pat_|pypi-|vsce[_-]?pat)[A-Za-z0-9_\-]{8,}"),
)


def _scan_artifact_secrets(
    root: Path, artifacts: list[dict[str, Any]]
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    for descriptor in artifacts:
        path = root / descriptor["path"]
        raw = path.read_bytes()
        for pattern in _SECRET_PATTERNS:
            if pattern.search(raw):
                findings.append(
                    {
                        "path": descriptor["path"],
                        "location": "archive-bytes",
                        "pattern": pattern.pattern.decode("ascii", "ignore"),
                    }
                )
        for member, content in _scan_archive(path):
            for pattern in _SECRET_PATTERNS:
                if pattern.search(content):
                    findings.append(
                        {
                            "path": descriptor["path"],
                            "location": member,
                            "pattern": pattern.pattern.decode("ascii", "ignore"),
                        }
                    )
    if findings:
        raise SupplyChainError(
            "E_SECRET_IN_ARTIFACT",
            f"secret-shaped material found in {findings[0]['path']}",
        )
    return {"artifact_count": len(artifacts), "secret_findings": 0}


def _validate_source_manifest(root: Path, value: Any) -> tuple[dict[str, Any], str]:
    source = _assert_exact(value, {"sha256", "files"}, "source_manifest")
    files = _list_descriptors(root, source["files"], "source_manifest.files", minimum=1)
    calculated = _digest(files)
    declared = require_digest(source["sha256"], "source_manifest.sha256")
    if declared != calculated:
        raise SupplyChainError(
            "E_SOURCE_MANIFEST_DIGEST",
            "source manifest digest does not match sorted file descriptors",
        )
    return {"sha256": declared, "files": files}, declared


def _validate_sbom(root: Path, descriptor: dict[str, Any]) -> dict[str, Any]:
    value = _read_json(root, descriptor, "sbom")
    if value.get("schema") != "factory.sbom.cyclonedx.v1":
        raise SupplyChainError(
            "E_SBOM_SCHEMA", "SBOM is not a Factory CycloneDX artifact"
        )
    supplied = require_digest(value.get("bom_sha256"), "sbom.bom_sha256")
    core = {key: item for key, item in value.items() if key != "bom_sha256"}
    if supplied != _digest(core):
        raise SupplyChainError("E_SBOM_DIGEST", "SBOM content digest is invalid")
    components = value.get("components")
    if not isinstance(components, list) or len(components) > MAX_COMPONENTS:
        raise SupplyChainError(
            "E_SBOM_COMPONENTS", "SBOM components are missing or too large"
        )
    return {
        "path": descriptor["path"],
        "sha256": descriptor["sha256"],
        "component_count": len(components),
        "bom_sha256": supplied,
    }


def _validate_vex(
    root: Path, descriptor: dict[str, Any], now: datetime
) -> tuple[dict[str, Any], dict[str, int], list[tuple[str, str, str]]]:
    value = _read_json(root, descriptor, "vex")
    if value.get("schema") != "factory.vex.v1":
        raise SupplyChainError("E_VEX_SCHEMA", "VEX is not a Factory VEX artifact")
    supplied = require_digest(value.get("vex_sha256"), "vex.vex_sha256")
    core = {key: item for key, item in value.items() if key != "vex_sha256"}
    if supplied != _digest(core):
        raise SupplyChainError("E_VEX_DIGEST", "VEX content digest is invalid")
    entries = value.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_COMPONENTS:
        raise SupplyChainError("E_VEX_ENTRIES", "VEX entries are missing or too large")
    unresolved = {severity: 0 for severity in SEVERITIES}
    unresolved_items: list[tuple[str, str, str]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SupplyChainError("E_VEX_ENTRY", f"VEX entry {index} is not an object")
        vulnerability = require_str(
            entry.get("vulnerability"), f"vex.entries[{index}].vulnerability"
        )
        require_str(entry.get("component"), f"vex.entries[{index}].component")
        status = require_str(entry.get("status"), f"vex.entries[{index}].status")
        if status not in VEX_STATUSES:
            raise SupplyChainError("E_VEX_STATUS", f"unsupported VEX status: {status}")
        if status not in {"affected", "under_investigation"}:
            continue
        severity = entry.get("severity")
        if severity not in SEVERITIES:
            raise SupplyChainError(
                "E_VEX_SEVERITY_UNKNOWN",
                f"unresolved {vulnerability} has no approved severity",
            )
        unresolved[severity] += 1
        unresolved_items.append((vulnerability, entry["component"], severity))
    return (
        {
            "path": descriptor["path"],
            "sha256": descriptor["sha256"],
            "entry_count": len(entries),
            "vex_sha256": supplied,
        },
        unresolved,
        unresolved_items,
    )


def _validate_policy(
    root: Path,
    value: Any,
    now: datetime,
    unresolved: dict[str, int],
    unresolved_items: list[tuple[str, str, str]],
) -> dict[str, Any]:
    policy = _assert_exact(value, {"max_unresolved", "exceptions"}, "vex_policy")
    thresholds = _assert_exact(
        policy["max_unresolved"], set(SEVERITIES), "vex_policy.max_unresolved"
    )
    normalized_thresholds: dict[str, int] = {}
    for severity in SEVERITIES:
        normalized_thresholds[severity] = require_int(
            thresholds[severity],
            f"max_unresolved.{severity}",
            minimum=0,
            maximum=MAX_COMPONENTS,
        )
    exceptions = policy["exceptions"]
    if not isinstance(exceptions, list) or len(exceptions) > MAX_COMPONENTS:
        raise SupplyChainError(
            "E_EXCEPTION_POLICY", "VEX exceptions are missing or too large"
        )
    exception_keys = _validated_vex_exceptions(exceptions, now, unresolved_items)
    effective = dict(unresolved)
    for _, _, severity in exception_keys:
        effective[severity] -= 1
    _validate_vulnerability_thresholds(effective, normalized_thresholds)
    return {
        "max_unresolved": normalized_thresholds,
        "exception_count": len(exceptions),
        "excepted_count": len(exception_keys),
        "unresolved_after_exceptions": effective,
    }


def _validated_vex_exceptions(
    exceptions: list[Any],
    now: datetime,
    unresolved_items: list[tuple[str, str, str]],
) -> set[tuple[str, str, str]]:
    unresolved_keys = set(unresolved_items)
    unresolved_key_counts = {
        key: unresolved_items.count(key) for key in unresolved_keys
    }
    exception_keys: set[tuple[str, str, str]] = set()
    for index, exception in enumerate(exceptions):
        _validate_vex_exception(
            exception,
            index,
            now,
            unresolved_keys,
            unresolved_key_counts,
            exception_keys,
        )
    return exception_keys


def _validate_vex_exception(
    exception: Any,
    index: int,
    now: datetime,
    unresolved_keys: set[tuple[str, str, str]],
    unresolved_key_counts: dict[tuple[str, str, str], int],
    exception_keys: set[tuple[str, str, str]],
) -> None:
    item = _assert_exact(
        exception,
        {"id", "vulnerability", "component", "severity", "expires_at", "reason"},
        f"vex_policy.exceptions[{index}]",
    )
    exception_id = require_str(item["id"], f"exception[{index}].id")
    vulnerability = require_str(
        item["vulnerability"], f"exception[{index}].vulnerability"
    )
    component = require_str(item["component"], f"exception[{index}].component")
    if item["severity"] not in SEVERITIES:
        raise SupplyChainError(
            "E_VEX_SEVERITY_UNKNOWN",
            f"exception {exception_id} has unsupported severity",
        )
    severity = item["severity"]
    if _timestamp(item["expires_at"], f"exception[{index}].expires_at") <= now:
        raise SupplyChainError(
            "E_EXCEPTION_EXPIRED", f"VEX exception {exception_id} is expired"
        )
    require_str(item["reason"], f"exception[{index}].reason", maximum=1024)
    key = (vulnerability, component, severity)
    _validate_vex_exception_match(
        key, exception_id, unresolved_keys, unresolved_key_counts, exception_keys
    )
    exception_keys.add(key)


def _validate_vex_exception_match(
    key: tuple[str, str, str],
    exception_id: str,
    unresolved_keys: set[tuple[str, str, str]],
    unresolved_key_counts: dict[tuple[str, str, str], int],
    exception_keys: set[tuple[str, str, str]],
) -> None:
    if key in exception_keys:
        raise SupplyChainError(
            "E_EXCEPTION_DUPLICATE",
            f"VEX exception {exception_id} duplicates an existing exception",
        )
    if key not in unresolved_keys:
        raise SupplyChainError(
            "E_EXCEPTION_UNMATCHED",
            f"VEX exception {exception_id} does not match an unresolved finding",
        )
    if unresolved_key_counts[key] != 1:
        raise SupplyChainError(
            "E_EXCEPTION_AMBIGUOUS",
            f"VEX exception {exception_id} matches multiple unresolved findings",
        )


def _validate_vulnerability_thresholds(
    effective: dict[str, int], normalized_thresholds: dict[str, int]
) -> None:
    for severity in SEVERITIES:
        if effective[severity] > normalized_thresholds[severity]:
            raise SupplyChainError(
                "E_VULNERABILITY_THRESHOLD",
                f"{severity} unresolved count exceeds policy after exceptions",
            )


def _validate_licenses(value: Any, now: datetime) -> dict[str, Any]:
    policy = _assert_exact(
        value, {"policy_sha256", "entries", "exceptions"}, "licenses"
    )
    policy_digest = require_digest(policy["policy_sha256"], "licenses.policy_sha256")
    entries = policy["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_COMPONENTS:
        raise SupplyChainError("E_LICENSE_ENTRIES", "license entries must be present")
    exceptions = policy["exceptions"]
    if not isinstance(exceptions, list) or len(exceptions) > MAX_COMPONENTS:
        raise SupplyChainError("E_LICENSE_EXCEPTIONS", "license exceptions are invalid")
    active = _active_license_exceptions(exceptions, now)
    denied = _count_unapproved_licenses(entries, active)
    return {
        "policy_sha256": policy_digest,
        "entry_count": len(entries),
        "exception_count": len(exceptions),
        "unapproved_count": denied,
    }


def _active_license_exceptions(
    exceptions: list[Any], now: datetime
) -> set[tuple[str, str]]:
    active: set[tuple[str, str]] = set()
    for index, item in enumerate(exceptions):
        row = _assert_exact(
            item,
            {"id", "component", "license", "expires_at", "reason"},
            f"licenses.exceptions[{index}]",
        )
        active.add(
            (
                require_str(row["component"], "license exception component"),
                require_str(row["license"], "license exception license"),
            )
        )
        if (
            _timestamp(row["expires_at"], f"license exception[{index}].expires_at")
            <= now
        ):
            raise SupplyChainError(
                "E_EXCEPTION_EXPIRED", f"license exception {row['id']} is expired"
            )
        require_str(row["reason"], "license exception reason", maximum=1024)
    return active


def _count_unapproved_licenses(entries: list[Any], active: set[tuple[str, str]]) -> int:
    denied = 0
    for index, item in enumerate(entries):
        row = _assert_exact(
            item, {"component", "license", "status"}, f"licenses.entries[{index}]"
        )
        component = require_str(row["component"], "license component")
        license_name = require_str(row["license"], "license name")
        status = require_str(row["status"], "license status")
        if status not in LICENSE_STATUSES:
            raise SupplyChainError(
                "E_LICENSE_POLICY", f"unsupported license status {status}"
            )
        if status in {"denied", "unknown"}:
            denied += 1
            if (component, license_name) not in active:
                raise SupplyChainError(
                    "E_LICENSE_POLICY", f"{component} has unapproved {status} license"
                )
    return denied


def _validate_build(root: Path, value: Any, now: datetime) -> dict[str, Any]:
    build = _assert_exact(
        value,
        {
            "builder_id",
            "builder_version",
            "toolchain_sha256",
            "command_sha256",
            "clean_environment",
            "reproducible",
            "rebuilds",
        },
        "build",
    )
    require_str(build["builder_id"], "build.builder_id")
    require_str(build["builder_version"], "build.builder_version")
    require_digest(build["toolchain_sha256"], "build.toolchain_sha256")
    require_digest(build["command_sha256"], "build.command_sha256")
    if not require_bool(
        build["clean_environment"], "build.clean_environment"
    ) or not require_bool(build["reproducible"], "build.reproducible"):
        raise SupplyChainError(
            "E_REPRO_BUILD_UNPROVEN",
            "clean_environment and reproducible must both be true",
        )
    rebuilds = build["rebuilds"]
    if not isinstance(rebuilds, list) or not 2 <= len(rebuilds) <= 4:
        raise SupplyChainError(
            "E_REPRO_BUILD_COUNT", "two to four independent rebuilds are required"
        )
    normalized: list[dict[str, Any]] = []
    for index, rebuild in enumerate(rebuilds):
        row = _assert_exact(rebuild, {"id", "artifacts"}, f"build.rebuilds[{index}]")
        rebuild_id = require_str(row["id"], f"rebuild[{index}].id")
        artifacts = _list_descriptors(
            root,
            row["artifacts"],
            f"build.rebuilds[{index}].artifacts",
            minimum=1,
            suffixes=ARTIFACT_SUFFIXES,
        )
        normalized.append({"id": rebuild_id, "artifacts": artifacts})
    if len({item["id"] for item in normalized}) != len(normalized):
        raise SupplyChainError("E_REPRO_BUILD_ID", "rebuild identifiers must be unique")
    baseline = {(item["path"], item["sha256"]) for item in normalized[0]["artifacts"]}
    for item in normalized[1:]:
        current = {
            (artifact["path"], artifact["sha256"]) for artifact in item["artifacts"]
        }
        if current != baseline:
            raise SupplyChainError(
                "E_REPRO_BUILD_DRIFT",
                f"rebuild {item['id']} differs from the first build",
            )
    return {
        "builder_id": build["builder_id"],
        "builder_version": build["builder_version"],
        "rebuild_count": len(normalized),
        "artifact_count": len(baseline),
        "artifacts": [
            dict(path=path, sha256=digest) for path, digest in sorted(baseline)
        ],
    }


def _validate_collector(value: Any, *, require_external: bool) -> dict[str, str]:
    collector = _assert_exact(value, {"id", "role", "backend"}, "collector")
    collector_id = require_str(collector["id"], "collector.id")
    role = require_str(collector["role"], "collector.role")
    backend = require_str(collector["backend"], "collector.backend")
    if role not in COLLECTOR_ROLES:
        raise SupplyChainError("E_COLLECTOR_ROLE", f"unsupported collector role {role}")
    if require_external and (role == "local_evaluator" or backend == "local"):
        raise SupplyChainError(
            "E_COLLECTOR_INDEPENDENCE",
            "signed verification requires a non-local collector",
        )
    return {"id": collector_id, "role": role, "backend": backend}


def _validate_attestation_header(value: dict[str, Any], now: datetime) -> None:
    if value["schema"] != ATTESTATION_SCHEMA:
        raise SupplyChainError("E_SCHEMA", f"expected {ATTESTATION_SCHEMA}")
    require_str(value["attestation_id"], "attestation_id")
    issued = _timestamp(value["issued_at"], "issued_at")
    expires = _timestamp(value["expires_at"], "expires_at")
    if (
        issued > now
        or expires <= now
        or expires <= issued
        or (expires - issued).total_seconds() > 86_400
    ):
        raise SupplyChainError(
            "E_ATTESTATION_WINDOW",
            "attestation must be current and valid for at most 24 hours",
        )
    if value["authority"] != "none" or value["release_approval"] is not False:
        raise SupplyChainError(
            "E_AUTHORITY", "supply-chain evidence cannot grant release authority"
        )


def validate_attestation(
    root: Path,
    manifest: dict[str, Any],
    *,
    candidate_sha256: str | None = None,
    now: datetime | None = None,
    require_external: bool = False,
) -> dict[str, Any]:
    """Validate a manifest and every referenced file without executing builds."""
    workspace = Path(root).resolve()
    required = {
        "schema",
        "attestation_id",
        "candidate_sha256",
        "source_manifest",
        "lockfiles",
        "sbom",
        "vex",
        "vex_policy",
        "licenses",
        "build",
        "collector",
        "issued_at",
        "expires_at",
        "authority",
        "release_approval",
    }
    value = _assert_exact(manifest, required, "attestation")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    _validate_attestation_header(value, current)
    source, source_digest = _validate_source_manifest(
        workspace, value["source_manifest"]
    )
    candidate = require_digest(value["candidate_sha256"], "candidate_sha256")
    if candidate != source_digest or (
        candidate_sha256 is not None and candidate_sha256 != candidate
    ):
        raise SupplyChainError(
            "E_CANDIDATE_BINDING",
            "candidate digest is not bound to the source manifest",
        )
    lockfiles = _list_descriptors(workspace, value["lockfiles"], "lockfiles", minimum=1)
    sbom_descriptor = _descriptor(workspace, value["sbom"], "sbom")
    sbom = _validate_sbom(workspace, sbom_descriptor)
    vex_descriptor = _descriptor(workspace, value["vex"], "vex")
    vex, unresolved, unresolved_items = _validate_vex(
        workspace, vex_descriptor, current
    )
    vex_policy = _validate_policy(
        workspace, value["vex_policy"], current, unresolved, unresolved_items
    )
    licenses = _validate_licenses(value["licenses"], current)
    build = _validate_build(workspace, value["build"], current)
    artifacts = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "bytes": next(
                (
                    a["bytes"]
                    for a in value["build"]["rebuilds"][0]["artifacts"]
                    if a.get("path") == item["path"]
                ),
                0,
            ),
        }
        for item in build["artifacts"]
    ]
    secret_scan = _scan_artifact_secrets(workspace, artifacts)
    collector = _validate_collector(
        value["collector"], require_external=require_external
    )
    return {
        "attestation_id": value["attestation_id"],
        "candidate_sha256": candidate,
        "source_manifest": source,
        "lockfiles": lockfiles,
        "sbom": sbom,
        "vex": vex,
        "vex_policy": vex_policy,
        "licenses": licenses,
        "build": build,
        "collector": collector,
        "facts": {
            "unresolved": unresolved,
            "unresolved_after_exceptions": vex_policy["unresolved_after_exceptions"],
            "excepted_count": vex_policy["excepted_count"],
            "lockfile_count": len(lockfiles),
            "component_count": sbom["component_count"],
            "vex_entry_count": vex["entry_count"],
            "artifact_count": build["artifact_count"],
            **secret_scan,
        },
    }


def _receipt(core: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema": RECEIPT_SCHEMA,
        "marker": "SUPPLY_CHAIN_RECEIPT",
        **core,
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Evidence-only supply-chain checks; no signing, release, publication, deployment, or approval authority.",
    }
    body["receipt_sha256"] = _digest(body)
    return body


def evaluate_supply_chain(
    root: Path,
    manifest: dict[str, Any],
    *,
    candidate_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a self-hashed PASS/BLOCKED receipt and never raise for bad input."""
    try:
        normalized = validate_attestation(
            Path(root), manifest, candidate_sha256=candidate_sha256, now=now
        )
        checks = [
            {
                "id": "SOURCE_MANIFEST_BOUND",
                "passed": True,
                "evidence": normalized["candidate_sha256"],
            },
            {
                "id": "LOCKFILES_BOUND",
                "passed": True,
                "evidence": f"{len(normalized['lockfiles'])} lockfile(s)",
            },
            {
                "id": "SBOM_BOUND",
                "passed": True,
                "evidence": normalized["sbom"]["bom_sha256"],
            },
            {
                "id": "VEX_POLICY_BOUND",
                "passed": True,
                "evidence": normalized["vex"]["vex_sha256"],
            },
            {
                "id": "LICENSE_POLICY_BOUND",
                "passed": True,
                "evidence": normalized["licenses"]["policy_sha256"],
            },
            {
                "id": "REPRODUCIBLE_BUILDS",
                "passed": True,
                "evidence": f"{normalized['build']['rebuild_count']} identical rebuilds",
            },
            {
                "id": "ARTIFACT_SECRET_SCAN",
                "passed": True,
                "evidence": "no secret-shaped material",
            },
        ]
        return _receipt(
            {
                "decision": "PASS",
                "candidate_sha256": normalized["candidate_sha256"],
                "manifest_sha256": _digest(manifest),
                "checks": checks,
                "blockers": [],
                "collector": normalized["collector"],
                "facts": normalized["facts"],
            }
        )
    except SupplyChainError as exc:
        return _receipt(
            {
                "decision": "BLOCKED",
                "candidate_sha256": candidate_sha256,
                "manifest_sha256": _digest(manifest)
                if isinstance(manifest, dict)
                else None,
                "checks": [],
                "blockers": [{"code": exc.code, "detail": exc.message}],
                "collector": manifest.get("collector")
                if isinstance(manifest, dict)
                else None,
                "facts": {},
            }
        )


def write_supply_chain_receipt(
    root: Path,
    manifest: dict[str, Any] | Path,
    out: Path,
    *,
    candidate_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate and atomically persist a local supply-chain receipt."""
    workspace = Path(root).resolve()
    value = (
        json.loads(Path(manifest).read_text(encoding="utf-8"))
        if isinstance(manifest, Path)
        else manifest
    )
    result = evaluate_supply_chain(
        workspace, value, candidate_sha256=candidate_sha256, now=now
    )
    destination, _ = _inside(workspace, out, "supply-chain receipt output")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {**result, "path": destination.relative_to(workspace).as_posix()}
    payload["receipt_sha256"] = _digest(
        {key: item for key, item in payload.items() if key != "receipt_sha256"}
    )
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return payload


def verify_signed_supply_chain_attestation(
    path: Path,
    trust_root_path: Path,
    root: Path,
    *,
    candidate_sha256: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify an externally collected DSSE attestation and keep release authority false."""
    try:
        result = verify_signed_document(
            Path(path),
            payload_type=PAYLOAD_TYPE,
            schema=ATTESTATION_SCHEMA,
            trust_root_path=Path(trust_root_path),
        )
        normalized = validate_attestation(
            Path(root),
            result["payload"],
            candidate_sha256=candidate_sha256,
            now=now,
            require_external=True,
        )
    except (EnterpriseReceiptError, SupplyChainError) as exc:
        code = getattr(exc, "code", "E_SIGNED_ATTESTATION")
        raise SupplyChainError(code, str(exc)) from exc
    body = {
        "schema": VERIFICATION_SCHEMA,
        "state": "VERIFIED",
        "attestation_id": normalized["attestation_id"],
        "candidate_sha256": normalized["candidate_sha256"],
        "payload_sha256": result["payload_sha256"],
        "verification": result["verification"],
        "collector": normalized["collector"],
        "facts": normalized["facts"],
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Signature verifies evidence only; it does not grant release authority.",
    }
    body["verification_sha256"] = _digest(body)
    return body


def supply_chain_status(root: Path) -> dict[str, Any]:
    """Read the newest local receipt without executing any gate."""
    workspace = Path(root).resolve()
    path = workspace / ".factory" / "supply-chain" / "supply-chain-receipt.json"
    if not path.is_file() or path.is_symlink():
        return {
            "schema": RECEIPT_SCHEMA,
            "state": "MISSING",
            "decision": "NOT_REQUESTED",
            "receipt_sha256": None,
            "claim_boundary": "No local supply-chain receipt was present; no conclusion about release readiness.",
        }
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        supplied = value.get("receipt_sha256")
        expected = _digest(
            {key: item for key, item in value.items() if key != "receipt_sha256"}
        )
        if supplied != expected or value.get("schema") != RECEIPT_SCHEMA:
            return {
                "schema": RECEIPT_SCHEMA,
                "state": "INCOMPLETE",
                "decision": value.get("decision"),
                "receipt_sha256": supplied,
                "error": "SELF_HASH_MISMATCH",
                "claim_boundary": "Receipt integrity is invalid; no readiness conclusion.",
            }
        return {
            "schema": RECEIPT_SCHEMA,
            "state": "PASS" if value.get("decision") == "PASS" else "BLOCKED",
            "decision": value.get("decision"),
            "receipt_sha256": supplied,
            "blockers": value.get("blockers", []),
            "facts": value.get("facts", {}),
            "claim_boundary": value.get("claim_boundary"),
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {
            "schema": RECEIPT_SCHEMA,
            "state": "INCOMPLETE",
            "decision": None,
            "receipt_sha256": None,
            "error": "SOURCE_UNREADABLE",
            "claim_boundary": "Receipt could not be read; no readiness conclusion.",
        }


__all__ = [
    "ATTESTATION_SCHEMA",
    "RECEIPT_SCHEMA",
    "VERIFICATION_SCHEMA",
    "PAYLOAD_TYPE",
    "SupplyChainError",
    "validate_attestation",
    "evaluate_supply_chain",
    "write_supply_chain_receipt",
    "verify_signed_supply_chain_attestation",
    "supply_chain_status",
]

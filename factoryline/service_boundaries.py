"""Language-neutral service-layer boundary checks for reviewable agent changes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any


MANIFEST_SCHEMA = "factory.service-boundary-manifest.v1"
REPORT_SCHEMA = "factory.service-boundary-report.v1"
MAX_BYTES = 512_000
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class ServiceBoundaryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


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


def _path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA", f"{label} must be a workspace-relative path"
        )
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_PATH", f"{label} escapes the workspace"
        )
    return path.as_posix().rstrip("/") or "."


def _paths(value: object, label: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= 128:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA", f"{label} must contain {minimum}-128 paths"
        )
    result = sorted({_path(item, label) for item in value})
    if len(result) != len(value):
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA", f"{label} must be unique"
        )
    return result


def _under(prefixes: list[str], path: str) -> bool:
    return any(
        prefix == "." or path == prefix or path.startswith(prefix.rstrip("/") + "/")
        for prefix in prefixes
    )


def _inside(root: Path, relative: str) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_PATH", "path escapes the workspace"
        ) from exc
    if not target.is_file():
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_PATH", f"changed file is unavailable: {relative}"
        )
    return target


def _manifest_relative_path(root: Path, source: Path) -> str:
    try:
        return (
            source.resolve().relative_to(root).as_posix()
            if source.is_absolute()
            else _path(str(source), "manifest")
        )
    except ValueError as exc:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_PATH", "manifest escapes the workspace"
        ) from exc


def _load_manifest_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA", "manifest must be UTF-8 JSON"
        ) from exc


def _manifest_object(value: object) -> dict[str, Any]:
    fields = {
        "schema",
        "id",
        "actions_paths",
        "services_paths",
        "adapters_paths",
        "core_paths",
        "forbidden_literals",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema") != MANIFEST_SCHEMA
    ):
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA",
            f"manifest must use exact {MANIFEST_SCHEMA} fields",
        )
    return value


def _manifest_id(value: dict[str, Any]) -> str:
    identifier = value["id"]
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA", "id must be a safe identifier"
        )
    return identifier


def _manifest_zones(value: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "actions": _paths(value["actions_paths"], "actions_paths"),
        "services": _paths(value["services_paths"], "services_paths"),
        "adapters": _paths(value["adapters_paths"], "adapters_paths"),
        "core": _paths(value["core_paths"], "core_paths"),
    }


def _zone_pair_overlaps(first: list[str], second: list[str]) -> bool:
    return any(_under(second, path) for path in first) or any(
        _under(first, path) for path in second
    )


def _validate_zone_overlaps(zones: dict[str, list[str]]) -> None:
    names = list(zones)
    for index, name in enumerate(names):
        for other in names[index + 1 :]:
            if _zone_pair_overlaps(zones[name], zones[other]):
                raise ServiceBoundaryError(
                    "E_SERVICE_BOUNDARY_SCHEMA",
                    f"{name} and {other} path zones must not overlap",
                )


def _manifest_literal_valid(item: object) -> bool:
    return (
        isinstance(item, dict)
        and set(item) == {"zone", "literal"}
        and item["zone"] in {"actions", "services", "adapters", "core"}
        and isinstance(item["literal"], str)
        and bool(item["literal"].strip())
        and len(item["literal"]) <= 128
    )


def _manifest_forbidden_literals(value: dict[str, Any]) -> list[dict[str, str]]:
    literals = value["forbidden_literals"]
    if not isinstance(literals, list) or len(literals) > 64:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA",
            "forbidden_literals must contain at most 64 entries",
        )
    normalized = []
    for index, item in enumerate(literals):
        if not _manifest_literal_valid(item):
            raise ServiceBoundaryError(
                "E_SERVICE_BOUNDARY_SCHEMA", f"forbidden_literals[{index}] is invalid"
            )
        normalized.append({"zone": item["zone"], "literal": item["literal"]})
    return sorted(normalized, key=lambda item: (item["zone"], item["literal"]))


def _manifest(root: Path, source: Path) -> tuple[dict[str, Any], str]:
    relative = _manifest_relative_path(root, source)
    path = _inside(root, relative)
    value = _manifest_object(_load_manifest_json(path))
    identifier = _manifest_id(value)
    zones = _manifest_zones(value)
    _validate_zone_overlaps(zones)
    literals = _manifest_forbidden_literals(value)
    return {
        "id": identifier,
        "zones": zones,
        "forbidden_literals": literals,
        "path": relative,
    }, hashlib.sha256(path.read_bytes()).hexdigest()


def _changed_paths(changed: list[str]) -> list[str]:
    normalized = sorted({_path(item, "changed path") for item in changed})
    if not normalized or len(normalized) > 256:
        raise ServiceBoundaryError(
            "E_SERVICE_BOUNDARY_SCHEMA", "changed must contain 1-256 unique paths"
        )
    return normalized


def _classify_zone(manifest: dict[str, Any], relative: str) -> str | None:
    matches = [
        name
        for name, prefixes in manifest["zones"].items()
        if _under(prefixes, relative)
    ]
    return matches[0] if len(matches) == 1 else None


def _unclassified_finding(relative: str) -> dict[str, str]:
    return {
        "code": "SERVICE_BOUNDARY_UNCLASSIFIED",
        "path": relative,
        "severity": "blocking",
        "message": "Changed source is not assigned to actions, services, adapters, or core.",
    }


def _source_text(path: Path) -> tuple[str, bool]:
    text = (
        path.read_text(encoding="utf-8", errors="replace")
        if path.stat().st_size <= MAX_BYTES
        else ""
    )
    return text, not text and path.stat().st_size > MAX_BYTES


def _oversized_finding(relative: str) -> dict[str, str]:
    return {
        "code": "SERVICE_BOUNDARY_SOURCE_TOO_LARGE",
        "path": relative,
        "severity": "blocking",
        "message": "Changed source exceeds the scan limit.",
    }


def _literal_findings(
    rules: list[dict[str, str]], zone: str, text: str, relative: str
) -> list[dict[str, str]]:
    findings = []
    for rule in rules:
        if rule["zone"] == zone and rule["literal"] in text:
            findings.append(
                {
                    "code": "SERVICE_BOUNDARY_LITERAL",
                    "path": relative,
                    "severity": "blocking",
                    "literal": rule["literal"],
                    "message": "A declared prohibited direct dependency is present in this architecture zone.",
                }
            )
    return findings


def _inspect_changed_path(
    workspace: Path, manifest: dict[str, Any], relative: str
) -> tuple[dict[str, str | None], list[dict[str, str]]]:
    path = _inside(workspace, relative)
    zone = _classify_zone(manifest, relative)
    if zone is None:
        return {"path": relative, "zone": None}, [_unclassified_finding(relative)]
    text, oversized = _source_text(path)
    findings = [_oversized_finding(relative)] if oversized else []
    findings.extend(
        _literal_findings(manifest["forbidden_literals"], zone, text, relative)
    )
    return {"path": relative, "zone": zone}, findings


def _service_boundary_report(
    manifest: dict[str, Any],
    manifest_sha: str,
    classifications: list[dict[str, str | None]],
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    blockers = [item for item in findings if item["severity"] == "blocking"]
    core_changed = [item["path"] for item in classifications if item["zone"] == "core"]
    core = {
        "schema": REPORT_SCHEMA,
        "marker": "SERVICE_BOUNDARY_READY"
        if not blockers
        else "SERVICE_BOUNDARY_BLOCKED",
        "manifest": {
            "id": manifest["id"],
            "path": manifest["path"],
            "sha256": manifest_sha,
        },
        "classifications": classifications,
        "findings": findings,
        "core_changed": core_changed,
        "next_action": {
            "action": "classify_or_move_change"
            if blockers
            else "review_service_boundary_packet",
            "reason": "Every changed file has a declared layer and no declared prohibited direct dependency was found."
            if not blockers
            else "Resolve unclassified paths, oversized scans, or declared prohibited dependencies before treating the change as reviewable.",
        },
        "authority": dict(AUTHORITY),
        "scope_limits": [
            "This is deterministic text and path analysis, not a semantic type checker or proof that a service is behaviorally correct.",
            "It does not execute code, move files, create a worktree, invoke an agent, or merge a change.",
        ],
    }
    return {**core, "report_sha256": _sha(core)}


def check_service_boundaries(
    root: Path, manifest_path: Path, changed: list[str]
) -> dict[str, Any]:
    """Classify changed files and report declared architecture boundary violations."""
    workspace = Path(root).resolve()
    manifest, manifest_sha = _manifest(workspace, manifest_path)
    normalized = _changed_paths(changed)
    findings = []
    classifications = []
    for relative in normalized:
        classification, path_findings = _inspect_changed_path(
            workspace, manifest, relative
        )
        findings.extend(path_findings)
        classifications.append(classification)
    return _service_boundary_report(manifest, manifest_sha, classifications, findings)


def service_boundary_template() -> dict[str, Any]:
    """Return a secret-free actions, services, adapters, and core boundary template."""
    return {
        "schema": "factory.service-boundary-template.v1",
        "manifest_schema": MANIFEST_SCHEMA,
        "authority": dict(AUTHORITY),
        "claim_boundary": "Template only. It does not rewrite architecture, install a linter, or infer domain boundaries.",
        "manifest": {
            "schema": MANIFEST_SCHEMA,
            "id": "replace-with-boundary-id",
            "actions_paths": ["src/actions"],
            "services_paths": ["src/services"],
            "adapters_paths": ["src/adapters"],
            "core_paths": ["src/core"],
            "forbidden_literals": [{"zone": "actions", "literal": "direct-db-client"}],
        },
    }

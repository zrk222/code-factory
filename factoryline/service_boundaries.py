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
    "execution": False, "approval": False, "repair": False, "merge": False,
    "publication": False, "deployment": False, "signing": False,
    "messaging": False, "credential": False, "connector": False,
}


class ServiceBoundaryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", f"{label} must be a workspace-relative path")
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_PATH", f"{label} escapes the workspace")
    return path.as_posix().rstrip("/") or "."


def _paths(value: object, label: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= 128:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", f"{label} must contain {minimum}-128 paths")
    result = sorted({_path(item, label) for item in value})
    if len(result) != len(value):
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", f"{label} must be unique")
    return result


def _under(prefixes: list[str], path: str) -> bool:
    return any(prefix == "." or path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


def _inside(root: Path, relative: str) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_PATH", "path escapes the workspace") from exc
    if not target.is_file():
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_PATH", f"changed file is unavailable: {relative}")
    return target


def _manifest(root: Path, source: Path) -> tuple[dict[str, Any], str]:
    try:
        relative = source.resolve().relative_to(root).as_posix() if source.is_absolute() else _path(str(source), "manifest")
    except ValueError as exc:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_PATH", "manifest escapes the workspace") from exc
    path = _inside(root, relative)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", "manifest must be UTF-8 JSON") from exc
    fields = {"schema", "id", "actions_paths", "services_paths", "adapters_paths", "core_paths", "forbidden_literals"}
    if not isinstance(value, dict) or set(value) != fields or value.get("schema") != MANIFEST_SCHEMA:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", f"manifest must use exact {MANIFEST_SCHEMA} fields")
    if not isinstance(value["id"], str) or not _ID.fullmatch(value["id"]):
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", "id must be a safe identifier")
    zones = {"actions": _paths(value["actions_paths"], "actions_paths"), "services": _paths(value["services_paths"], "services_paths"), "adapters": _paths(value["adapters_paths"], "adapters_paths"), "core": _paths(value["core_paths"], "core_paths")}
    names = list(zones)
    for index, name in enumerate(names):
        for other in names[index + 1:]:
            if any(_under(zones[other], path) for path in zones[name]) or any(_under(zones[name], path) for path in zones[other]):
                raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", f"{name} and {other} path zones must not overlap")
    literals = value["forbidden_literals"]
    if not isinstance(literals, list) or len(literals) > 64:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", "forbidden_literals must contain at most 64 entries")
    normalized = []
    for index, item in enumerate(literals):
        if not isinstance(item, dict) or set(item) != {"zone", "literal"} or item["zone"] not in {"actions", "services", "adapters", "core"} or not isinstance(item["literal"], str) or not item["literal"].strip() or len(item["literal"]) > 128:
            raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", f"forbidden_literals[{index}] is invalid")
        normalized.append({"zone": item["zone"], "literal": item["literal"]})
    return {"id": value["id"], "zones": zones, "forbidden_literals": sorted(normalized, key=lambda item: (item["zone"], item["literal"])), "path": relative}, hashlib.sha256(path.read_bytes()).hexdigest()


def check_service_boundaries(root: Path, manifest_path: Path, changed: list[str]) -> dict[str, Any]:
    """Classify changed files and report declared architecture boundary violations."""
    workspace = Path(root).resolve()
    manifest, manifest_sha = _manifest(workspace, manifest_path)
    normalized = sorted({_path(item, "changed path") for item in changed})
    if not normalized or len(normalized) > 256:
        raise ServiceBoundaryError("E_SERVICE_BOUNDARY_SCHEMA", "changed must contain 1-256 unique paths")
    findings = []
    classifications = []
    for relative in normalized:
        path = _inside(workspace, relative)
        matches = [name for name, prefixes in manifest["zones"].items() if _under(prefixes, relative)]
        zone = matches[0] if len(matches) == 1 else None
        if zone is None:
            findings.append({"code": "SERVICE_BOUNDARY_UNCLASSIFIED", "path": relative, "severity": "blocking", "message": "Changed source is not assigned to actions, services, adapters, or core."})
            classifications.append({"path": relative, "zone": None})
            continue
        text = path.read_text(encoding="utf-8", errors="replace") if path.stat().st_size <= MAX_BYTES else ""
        if not text and path.stat().st_size > MAX_BYTES:
            findings.append({"code": "SERVICE_BOUNDARY_SOURCE_TOO_LARGE", "path": relative, "severity": "blocking", "message": "Changed source exceeds the scan limit."})
        for rule in manifest["forbidden_literals"]:
            if rule["zone"] == zone and rule["literal"] in text:
                findings.append({"code": "SERVICE_BOUNDARY_LITERAL", "path": relative, "severity": "blocking", "literal": rule["literal"], "message": "A declared prohibited direct dependency is present in this architecture zone."})
        classifications.append({"path": relative, "zone": zone})
    blockers = [item for item in findings if item["severity"] == "blocking"]
    core_changed = [item["path"] for item in classifications if item["zone"] == "core"]
    core = {"schema": REPORT_SCHEMA, "marker": "SERVICE_BOUNDARY_READY" if not blockers else "SERVICE_BOUNDARY_BLOCKED", "manifest": {"id": manifest["id"], "path": manifest["path"], "sha256": manifest_sha}, "classifications": classifications, "findings": findings, "core_changed": core_changed, "next_action": {"action": "classify_or_move_change" if blockers else "review_service_boundary_packet", "reason": "Every changed file has a declared layer and no declared prohibited direct dependency was found." if not blockers else "Resolve unclassified paths, oversized scans, or declared prohibited dependencies before treating the change as reviewable."}, "authority": dict(AUTHORITY), "scope_limits": ["This is deterministic text and path analysis, not a semantic type checker or proof that a service is behaviorally correct.", "It does not execute code, move files, create a worktree, invoke an agent, or merge a change."]}
    return {**core, "report_sha256": _sha(core)}


def service_boundary_template() -> dict[str, Any]:
    """Return a secret-free actions, services, adapters, and core boundary template."""
    return {"schema": "factory.service-boundary-template.v1", "manifest_schema": MANIFEST_SCHEMA, "authority": dict(AUTHORITY), "claim_boundary": "Template only. It does not rewrite architecture, install a linter, or infer domain boundaries.", "manifest": {"schema": MANIFEST_SCHEMA, "id": "replace-with-boundary-id", "actions_paths": ["src/actions"], "services_paths": ["src/services"], "adapters_paths": ["src/adapters"], "core_paths": ["src/core"], "forbidden_literals": [{"zone": "actions", "literal": "direct-db-client"}]}}

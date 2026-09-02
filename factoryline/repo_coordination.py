"""Read-only, pinned-head coordination plans for several local repositories."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any


MANIFEST_SCHEMA = "factory.repo-coordination-manifest.v1"
PLAN_SCHEMA = "factory.repo-coordination-plan.v1"
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_SHA = re.compile(r"^[0-9a-f]{40,64}$")
AUTHORITY = {"execution": False, "approval": False, "repair": False, "merge": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False}


class RepoCoordinationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", f"{label} must be a workspace-relative path")
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise RepoCoordinationError("E_REPO_COORDINATION_PATH", f"{label} escapes the workspace")
    return path.as_posix().rstrip("/") or "."


def _inside(root: Path, relative: str) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise RepoCoordinationError("E_REPO_COORDINATION_PATH", "path escapes the workspace") from exc
    if not target.is_dir():
        raise RepoCoordinationError("E_REPO_COORDINATION_PATH", f"repository is unavailable: {relative}")
    return target


def _git(root: Path, *args: str) -> str:
    run = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if run.returncode:
        raise RepoCoordinationError("E_REPO_COORDINATION_GIT", run.stderr.strip() or "git inspection failed")
    return run.stdout.strip()


def _manifest(root: Path, source: Path) -> dict[str, Any]:
    try:
        relative = source.resolve().relative_to(root).as_posix() if source.is_absolute() else _path(str(source), "manifest")
    except ValueError as exc:
        raise RepoCoordinationError("E_REPO_COORDINATION_PATH", "manifest escapes the workspace") from exc
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
        value = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", "manifest must be readable UTF-8 JSON below the workspace") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "id", "repositories"} or value.get("schema") != MANIFEST_SCHEMA:
        raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", f"manifest must use exact {MANIFEST_SCHEMA} fields")
    if not isinstance(value["id"], str) or not _ID.fullmatch(value["id"]):
        raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", "id must be a safe identifier")
    rows = value["repositories"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", "repositories must contain 1-32 entries")
    result = []
    ids = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"id", "path", "expected_head_sha", "depends_on"}:
            raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", f"repositories[{index}] fields must be exact")
        identifier = row["id"]
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or identifier in ids:
            raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", "repository ids must be safe and unique")
        ids.add(identifier)
        expected = row["expected_head_sha"]
        if not isinstance(expected, str) or not _SHA.fullmatch(expected):
            raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", "expected_head_sha must be a 40-64 lowercase Git hash")
        dependencies = row["depends_on"]
        if not isinstance(dependencies, list) or len(dependencies) > 31 or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in dependencies) or len(set(dependencies)) != len(dependencies):
            raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", "depends_on must contain unique safe ids")
        result.append({"id": identifier, "path": _path(row["path"], "repository.path"), "expected_head_sha": expected, "depends_on": sorted(dependencies)})
    for row in result:
        if row["id"] in row["depends_on"] or any(dependency not in ids for dependency in row["depends_on"]):
            raise RepoCoordinationError("E_REPO_COORDINATION_SCHEMA", "dependencies must name a different declared repository")
    return {"id": value["id"], "path": relative, "repositories": sorted(result, key=lambda item: item["id"])}


def coordinate_repositories(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Derive a pinned, topologically ordered local repository review sequence."""
    workspace = Path(root).resolve()
    manifest = _manifest(workspace, manifest_path)
    pending = {row["id"]: row for row in manifest["repositories"]}
    ordered: list[dict[str, Any]] = []
    findings = []
    while pending:
        ready = [row for row in pending.values() if all(dependency not in pending for dependency in row["depends_on"])]
        if not ready:
            findings.append({"code": "REPO_COORDINATION_CYCLE", "severity": "blocking", "message": "Repository dependencies contain a cycle; no sequential plan is safe."})
            break
        for row in sorted(ready, key=lambda item: item["id"]):
            repo = _inside(workspace, row["path"])
            actual = _git(repo, "rev-parse", "HEAD")
            if _git(repo, "rev-parse", "--is-inside-work-tree") != "true":
                raise RepoCoordinationError("E_REPO_COORDINATION_GIT", f"{row['id']} is not a Git worktree")
            status = "ready" if actual == row["expected_head_sha"] else "blocked"
            if status == "blocked":
                findings.append({"code": "REPO_COORDINATION_HEAD_DRIFT", "severity": "blocking", "repository": row["id"], "expected_head_sha": row["expected_head_sha"], "observed_head_sha": actual, "message": "Pinned repository head differs; refresh human-reviewed coordination before sequential work."})
            ordered.append({"sequence": len(ordered) + 1, **row, "observed_head_sha": actual, "status": status})
            del pending[row["id"]]
    blockers = [item for item in findings if item["severity"] == "blocking"]
    core = {"schema": PLAN_SCHEMA, "marker": "REPO_COORDINATION_READY" if not blockers else "REPO_COORDINATION_BLOCKED", "manifest": {"id": manifest["id"], "path": manifest["path"], "sha256": _sha(manifest)}, "sequence": ordered, "findings": findings, "authority": dict(AUTHORITY), "claim_boundary": "Read-only local Git inspection. The plan never checks out, pulls, pushes, merges, rebases, creates worktrees, starts agents, or changes a repository."}
    return {**core, "plan_sha256": _sha(core)}


def repo_coordination_template() -> dict[str, Any]:
    """Return a secret-free manifest template for multi-repository dependency review."""
    return {"schema": "factory.repo-coordination-template.v1", "manifest_schema": MANIFEST_SCHEMA, "authority": dict(AUTHORITY), "claim_boundary": "Template only. It creates no cross-repository action or connection.", "manifest": {"schema": MANIFEST_SCHEMA, "id": "replace-with-coordination-id", "repositories": [{"id": "foundation", "path": "repos/foundation", "expected_head_sha": "replace-with-40-or-64-char-lowercase-git-hash", "depends_on": []}, {"id": "application", "path": "repos/application", "expected_head_sha": "replace-with-40-or-64-char-lowercase-git-hash", "depends_on": ["foundation"]}]}}

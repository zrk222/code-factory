"""Local, structural continuity evidence for JetBrains index investigations.

This module compares project *structure*, not IDE internals.  It never calls an
IDE API, asks a remote service, reads source contents into its reports, changes
settings, invalidates caches, or predicts indexing duration.  A changed
baseline is a human review signal only.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .workspace_advisor import WorkspaceAdvisorError, inspect_workspace


INDEX_CONTINUITY_SCHEMA = "factory.index_continuity.v1"
INDEX_CONTINUITY_BASELINE_SCHEMA = "factory.index_continuity_baseline.v1"
INDEX_CONTINUITY_MARKER = "INDEX_CONTINUITY_LOCAL_STRUCTURAL_ONLY"
MAX_STRUCTURAL_FILE_BYTES = 8 * 1024 * 1024
_STRUCTURAL_PATTERNS = (
    "pyproject.toml", "poetry.lock", "uv.lock", "requirements*.txt",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "gradle.properties", "pom.xml", "go.mod", "go.sum", "Cargo.toml",
    "Cargo.lock", "*.sln", "*.csproj", "*.fsproj",
)
_SOURCE_ROOTS = {"src", "lib", "app", "apps", "packages", "modules", "test", "tests"}


class IndexContinuityError(ValueError):
    """Stable refusal from the local continuity guard."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _workspace(root: Path | str) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise IndexContinuityError("INDEX_CONTINUITY_ROOT_INVALID", "workspace root must be an existing directory")
    return workspace


def _inside(root: Path, path: Path | str) -> Path:
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise IndexContinuityError("INDEX_CONTINUITY_PATH_OUTSIDE_ROOT", "path must stay inside the workspace root") from exc
    return resolved


def _structural_files(workspace: Path) -> list[dict[str, object]]:
    candidates: dict[str, Path] = {}
    for pattern in _STRUCTURAL_PATTERNS:
        for path in workspace.glob(pattern):
            if path.is_file() and not path.is_symlink():
                candidates[path.relative_to(workspace).as_posix()] = path
    entries: list[dict[str, object]] = []
    for relative, path in sorted(candidates.items()):
        size = path.stat().st_size
        entry: dict[str, object] = {"path": relative, "bytes": size}
        if size <= MAX_STRUCTURAL_FILE_BYTES:
            entry["sha256"] = _sha_file(path)
            entry["state"] = "hashed"
        else:
            entry["state"] = "too_large"
            entry["boundary"] = f"Skipped content hash above {MAX_STRUCTURAL_FILE_BYTES} bytes."
        entries.append(entry)
    return entries


def _source_roots(workspace: Path) -> list[str]:
    return sorted(
        child.name for child in workspace.iterdir()
        if child.is_dir() and not child.is_symlink() and child.name.lower() in _SOURCE_ROOTS
    )


def _managed_topology(advice: Mapping[str, object]) -> list[dict[str, object]]:
    raw = advice.get("managed_directory_summary")
    if not isinstance(raw, list):
        return []
    entries = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        path, category = item.get("path"), item.get("category")
        files, size = item.get("files"), item.get("bytes")
        if isinstance(path, str) and isinstance(category, str) and isinstance(files, int) and isinstance(size, int):
            entries.append({"path": path, "category": category, "files": files, "bytes": size})
    return sorted(entries, key=lambda item: (str(item["path"]), str(item["category"])))


def _baseline_core(payload: Mapping[str, object]) -> dict[str, object]:
    return {
        "workspace": payload["workspace"],
        "structural_files": payload["structural_files"],
        "source_roots": payload["source_roots"],
        "managed_topology": payload["managed_topology"],
    }


def capture_continuity_baseline(root: Path | str) -> dict[str, object]:
    """Capture bounded local structure without writing anything."""
    workspace = _workspace(root)
    try:
        advice = inspect_workspace(workspace)
    except WorkspaceAdvisorError as exc:
        raise IndexContinuityError(exc.code, str(exc)) from exc
    observed_workspace = advice["workspace"]
    payload: dict[str, object] = {
        "schema": INDEX_CONTINUITY_BASELINE_SCHEMA,
        "marker": INDEX_CONTINUITY_MARKER,
        "markers": [
            INDEX_CONTINUITY_MARKER,
            "INDEX_CONTINUITY_BASELINE_CAPTURED",
            "INDEX_CONTINUITY_NO_IDE_API",
            "INDEX_CONTINUITY_NO_WRITE_DEFAULT",
            "INDEX_CONTINUITY_NO_DURATION_PREDICTION",
        ],
        "workspace": {
            "name": observed_workspace["name"],
            "path_classification": observed_workspace["path_classification"],
            "ecosystems": observed_workspace["ecosystems"],
        },
        "structural_files": _structural_files(workspace),
        "source_roots": _source_roots(workspace),
        "managed_topology": _managed_topology(advice),
        "limitations": [
            "This baseline captures local project structure only; it does not inspect an IDE index, caches, plugins, CPU, heap, or UI responsiveness.",
            "A structural change is a review signal, not proof that an index is corrupt or that reindexing will solve a problem.",
            "File contents are never stored in the baseline; named structural files are represented by size and optional SHA-256 only.",
        ],
        "authority": {
            "ide_settings": False, "cache_mutation": False, "indexing_mutation": False,
            "network": False, "credential": False, "publication": False, "deployment": False,
        },
    }
    payload["baseline_sha256"] = sha256(_canonical(_baseline_core(payload))).hexdigest()
    return payload


def _atomic_json(path: Path, payload: Mapping[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_continuity_baseline(baseline: Mapping[str, object], root: Path | str, out: Path | str) -> str:
    """Persist one verified structural baseline at an explicit local JSON path."""
    workspace = _workspace(root)
    if baseline.get("schema") != INDEX_CONTINUITY_BASELINE_SCHEMA:
        raise IndexContinuityError("INDEX_CONTINUITY_BASELINE_INVALID", "baseline has an unexpected schema")
    path = _inside(workspace, out)
    if path.suffix.lower() != ".json":
        raise IndexContinuityError("INDEX_CONTINUITY_BASELINE_PATH_INVALID", "baseline output must be a .json file")
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json(path, baseline)
    return path.relative_to(workspace).as_posix()


def _load_baseline(root: Path, path: Path | str) -> dict[str, object]:
    resolved = _inside(root, path)
    if not resolved.is_file():
        raise IndexContinuityError("INDEX_CONTINUITY_BASELINE_MISSING", "baseline must be an existing workspace-contained JSON file")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IndexContinuityError("INDEX_CONTINUITY_BASELINE_UNREADABLE", "baseline must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("schema") != INDEX_CONTINUITY_BASELINE_SCHEMA:
        raise IndexContinuityError("INDEX_CONTINUITY_BASELINE_INVALID", "baseline has an unexpected schema")
    expected = payload.get("baseline_sha256")
    if not isinstance(expected, str) or expected != sha256(_canonical(_baseline_core(payload))).hexdigest():
        raise IndexContinuityError("INDEX_CONTINUITY_BASELINE_TAMPERED", "baseline digest does not match its structural content")
    return payload


def _by_path(entries: object) -> dict[str, Mapping[str, object]]:
    if not isinstance(entries, list):
        return {}
    return {item["path"]: item for item in entries if isinstance(item, Mapping) and isinstance(item.get("path"), str)}


def _changed_files(before: object, after: object) -> list[dict[str, object]]:
    old, new = _by_path(before), _by_path(after)
    changes: list[dict[str, object]] = []
    for path in sorted(set(old) | set(new)):
        prior, current = old.get(path), new.get(path)
        if prior is None:
            changes.append({"path": path, "change": "added"})
        elif current is None:
            changes.append({"path": path, "change": "removed"})
        elif prior != current:
            changes.append({"path": path, "change": "changed"})
    return changes


def _change(label: str, before: object, after: object) -> dict[str, object] | None:
    if before == after:
        return None
    return {"kind": label, "before": before, "after": after}


def compare_continuity(root: Path | str, baseline_path: Path | str) -> dict[str, object]:
    """Compare a verified local baseline with current local project structure."""
    workspace = _workspace(root)
    before = _load_baseline(workspace, baseline_path)
    current = capture_continuity_baseline(workspace)
    changes: list[dict[str, object]] = []
    files = _changed_files(before["structural_files"], current["structural_files"])
    if files:
        changes.append({"kind": "structural_files", "files": files})
    for label in ("workspace", "source_roots", "managed_topology"):
        value = _change(label, before[label], current[label])
        if value is not None:
            changes.append(value)
    broad = bool(files) or any(change["kind"] in {"workspace", "source_roots"} for change in changes)
    scope = "broad_reanalysis" if broad else "targeted_reanalysis" if changes else "stable"
    recommendations = {
        "stable": "No observed structural drift. Keep investigating the runtime symptom with IDE Health if it persists.",
        "targeted_reanalysis": "Review the named managed-directory change and project-model visibility before manually changing an IDE setting.",
        "broad_reanalysis": "Review the named structural drift and let the IDE's supported project-model flow complete before considering manual cache recovery.",
    }
    report: dict[str, object] = {
        "schema": INDEX_CONTINUITY_SCHEMA,
        "marker": INDEX_CONTINUITY_MARKER,
        "markers": [
            INDEX_CONTINUITY_MARKER,
            "INDEX_CONTINUITY_BASELINE_VERIFIED",
            f"INDEX_CONTINUITY_SCOPE_{scope.upper()}",
            "INDEX_CONTINUITY_NO_IDE_MUTATION",
            "INDEX_CONTINUITY_NO_DURATION_PREDICTION",
        ],
        "baseline": {
            "path": _inside(workspace, baseline_path).relative_to(workspace).as_posix(),
            "baseline_sha256": before["baseline_sha256"],
        },
        "review_scope": scope,
        "changes": changes,
        "recommendation": recommendations[scope],
        "limitations": [
            "The report compares local project structure only. It neither reads nor repairs the JetBrains index.",
            "No reindexing duration, performance improvement, or root cause is predicted from this result.",
            "FactoryLine does not invalidate caches, change plugins, or alter IDE project settings.",
        ],
        "authority": current["authority"],
    }
    report["comparison_sha256"] = sha256(_canonical({key: report[key] for key in ("baseline", "review_scope", "changes")})).hexdigest()
    return report

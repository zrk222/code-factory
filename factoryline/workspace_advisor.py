"""Bounded, local-only workspace shape and remote-preflight advice.

This module deliberately observes filesystem facts only.  It does not query an
IDE, alter heap settings, invalidate caches, toggle inspections, connect to a
remote host, or infer that a workspace is slow.  Those boundaries make the
result safe to invoke from an IDE action or a read-only MCP tool.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
import platform as platform_module
from typing import Mapping


WORKSPACE_ADVISOR_SCHEMA = "factory.workspace_advisor.v1"
WORKSPACE_ADVISOR_MARKER = "WORKSPACE_ADVISOR_LOCAL_READ_ONLY"
MAX_FILES = 20_000
MAX_LARGE_FILES = 20
MAX_TOP_LEVEL_DIRECTORIES = 20
_SKIP_DIRECTORY_NAMES = {".git"}
_GENERATED_DIRECTORY_NAMES = {"build", "dist", "out", "target", ".next", ".nuxt", "coverage"}
_DEPENDENCY_DIRECTORY_NAMES = {"node_modules", ".venv", "venv", "vendor", ".gradle", ".m2"}
_IDE_DIRECTORY_NAMES = {".idea", ".fleet"}
_MANIFESTS = {
    "pyproject.toml": "python",
    "package.json": "node",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle",
    "pom.xml": "maven",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "*.sln": "dotnet",
}


class WorkspaceAdvisorError(ValueError):
    """A stable refusal from the local workspace advisor."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _path_classification(raw_path: str, system: str, environ: Mapping[str, str]) -> str:
    """Classify only the path/runtime relationship, never probe a remote host."""
    normalized = raw_path.replace("/", "\\").lower()
    if normalized.startswith("\\\\wsl$\\") or normalized.startswith("\\\\wsl.localhost\\"):
        return "wsl_unc"
    if normalized.startswith("\\\\"):
        return "windows_unc"
    if system.lower() == "linux" and ("WSL_DISTRO_NAME" in environ or "microsoft" in environ.get("WSL_INTEROP", "").lower()):
        return "linux_wsl"
    if system.lower() == "windows":
        return "windows_local"
    if system.lower() in {"linux", "darwin"}:
        return "local_posix"
    return "unknown"


def _top_level(relative: Path) -> str:
    return relative.parts[0] if relative.parts else "."


def _category_for_top_level(name: str) -> str:
    lowered = name.lower()
    if lowered in _GENERATED_DIRECTORY_NAMES:
        return "generated"
    if lowered in _DEPENDENCY_DIRECTORY_NAMES:
        return "dependencies"
    if lowered in _IDE_DIRECTORY_NAMES:
        return "ide_metadata"
    return "project"


def _manifest_signals(root: Path) -> list[str]:
    signals: set[str] = set()
    for name, ecosystem in _MANIFESTS.items():
        if name.startswith("*."):
            if any(root.glob(name)):
                signals.add(ecosystem)
        elif (root / name).is_file():
            signals.add(ecosystem)
    return sorted(signals)


def _recommendations(
    *,
    file_count: int,
    scan_limited: bool,
    managed_directory_summary: list[dict[str, object]],
    path_classification: str,
) -> list[dict[str, object]]:
    recommendations: list[dict[str, object]] = []
    generated = [item for item in managed_directory_summary if item["category"] == "generated" and int(item["bytes"]) > 0]
    dependencies = [item for item in managed_directory_summary if item["category"] == "dependencies" and int(item["bytes"]) > 0]
    if generated:
        recommendations.append({
            "id": "review_generated_directories",
            "priority": "high",
            "state": "review",
            "evidence": [item["path"] for item in generated],
            "action": "Review these generated output directories in the IDE's project-exclusion settings before changing anything.",
            "boundary": "FactoryLine will not alter indexing, inspections, project files, or IDE settings.",
        })
    if dependencies:
        recommendations.append({
            "id": "review_dependency_directory_visibility",
            "priority": "medium",
            "state": "review",
            "evidence": [item["path"] for item in dependencies],
            "action": "Confirm dependency directories are managed by the project model and are not duplicated as ordinary source roots.",
            "boundary": "FactoryLine does not disable plugins or change dependency/index settings.",
        })
    if file_count >= 5_000 or scan_limited:
        recommendations.append({
            "id": "evaluate_shared_indexes",
            "priority": "medium",
            "state": "evaluate",
            "evidence": [f"files_scanned={file_count}", f"scan_limited={str(scan_limited).lower()}"],
            "action": "For a team workspace, evaluate JetBrains Shared Indexes with the JetBrains-supported setup for your IDE and build system.",
            "boundary": "This is a manual evaluation path; FactoryLine does not generate, download, or configure shared indexes.",
        })
    if path_classification in {"wsl_unc", "linux_wsl", "windows_unc"}:
        recommendations.append({
            "id": "remote_path_preflight",
            "priority": "high" if path_classification == "wsl_unc" else "medium",
            "state": "review",
            "evidence": [f"workspace_path_classification={path_classification}"],
            "action": "Verify that the IDE, runtime, build tools, and container/WSL path mappings use the same workspace boundary before a remote run.",
            "boundary": "FactoryLine does not connect to WSL, Gateway, Docker, SSH, or remote development hosts.",
        })
    if not recommendations:
        recommendations.append({
            "id": "no_high_signal_advice",
            "priority": "info",
            "state": "observed",
            "evidence": ["No generated/dependency directory or remote-path heuristic crossed the advisor threshold."],
            "action": "Use the measured workspace shape as a starting point if you investigate an IDE performance report.",
            "boundary": "This result is not an IDE freeze, heap, GC, or indexing diagnosis.",
        })
    return recommendations


@dataclass
class _ScanState:
    scanned_files: int = 0
    scanned_bytes: int = 0
    unreadable_entries: int = 0
    skipped_symlinks: int = 0
    top_level: dict[str, dict[str, object]] = field(default_factory=dict)
    managed_directories: dict[str, dict[str, object]] = field(default_factory=dict)
    large_files: list[tuple[int, str]] = field(default_factory=list)


def _safe_directories(current: Path, directory_names: list[str], state: _ScanState) -> list[str]:
    safe_directories: list[str] = []
    for directory_name in sorted(directory_names):
        if directory_name in _SKIP_DIRECTORY_NAMES:
            continue
        try:
            is_symlink = (current / directory_name).is_symlink()
        except OSError:
            state.unreadable_entries += 1
            continue
        if is_symlink:
            state.skipped_symlinks += 1
            continue
        safe_directories.append(directory_name)
    return safe_directories


def _update_directory_summary(
    summary: dict[str, dict[str, object]], path: str, category: str, size: int,
) -> None:
    item = summary.setdefault(path, {"path": path, "category": category, "files": 0, "bytes": 0})
    item["files"] = int(item["files"]) + 1
    item["bytes"] = int(item["bytes"]) + size


def _managed_ancestor(relative: Path) -> tuple[str, str] | None:
    for index, segment in enumerate(relative.parts[:-1]):
        category = _category_for_top_level(segment)
        if category in {"generated", "dependencies", "ide_metadata"}:
            return Path(*relative.parts[:index + 1]).as_posix(), category
    return None


def _observe_file(candidate: Path, workspace: Path, state: _ScanState) -> None:
    try:
        if candidate.is_symlink():
            state.skipped_symlinks += 1
            return
        stat = candidate.stat()
        if not candidate.is_file():
            return
    except OSError:
        state.unreadable_entries += 1
        return
    relative = candidate.relative_to(workspace)
    top_level = _top_level(relative)
    _update_directory_summary(
        state.top_level, top_level, _category_for_top_level(top_level), stat.st_size,
    )
    managed = _managed_ancestor(relative)
    if managed is not None:
        _update_directory_summary(state.managed_directories, *managed, stat.st_size)
    state.scanned_files += 1
    state.scanned_bytes += stat.st_size
    state.large_files.append((stat.st_size, relative.as_posix()))


def _scan_workspace(workspace: Path, max_files: int) -> tuple[_ScanState, bool]:
    state = _ScanState()
    for current_root, directory_names, file_names in os.walk(
        workspace, topdown=True, followlinks=False, onerror=lambda _error: None,
    ):
        directory_names[:] = _safe_directories(Path(current_root), directory_names, state)
        for file_name in sorted(file_names):
            if state.scanned_files >= max_files:
                return state, True
            _observe_file(Path(current_root) / file_name, workspace, state)
    return state, state.scanned_files >= max_files


def inspect_workspace(
    root: Path | str,
    *,
    platform_name: str | None = None,
    environ: Mapping[str, str] | None = None,
    max_files: int = MAX_FILES,
) -> dict[str, object]:
    """Return deterministic, bounded local facts without writing to the workspace."""
    if max_files < 1:
        raise WorkspaceAdvisorError("WORKSPACE_ADVISOR_LIMIT_INVALID", "max_files must be positive")
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise WorkspaceAdvisorError("WORKSPACE_ROOT_INVALID", "workspace root must be an existing directory")
    runtime_platform = platform_name or platform_module.system()
    environment = dict(environ) if environ is not None else dict(os.environ)
    path_classification = _path_classification(str(workspace), runtime_platform, environment)
    state, scan_limited = _scan_workspace(workspace, max_files)
    directories = sorted(
        state.top_level.values(), key=lambda item: (-int(item["bytes"]), str(item["path"]))
    )[:MAX_TOP_LEVEL_DIRECTORIES]
    managed_summary = sorted(
        state.managed_directories.values(), key=lambda item: (-int(item["bytes"]), str(item["path"]))
    )[:MAX_TOP_LEVEL_DIRECTORIES]
    large_files = sorted(state.large_files, key=lambda item: (-item[0], item[1]))[:MAX_LARGE_FILES]
    payload: dict[str, object] = {
        "schema": WORKSPACE_ADVISOR_SCHEMA,
        "marker": WORKSPACE_ADVISOR_MARKER,
        "markers": [
            WORKSPACE_ADVISOR_MARKER,
            "WORKSPACE_ADVISOR_SCHEMA_BOUND",
            "WORKSPACE_ADVISOR_NO_WRITE_DEFAULT",
            "WORKSPACE_ADVISOR_SCAN_BOUNDED",
            "WORKSPACE_ADVISOR_FACTS_MEASURED",
            "WORKSPACE_ADVISOR_REVIEW_PATHS",
            "WORKSPACE_ADVISOR_ZERO_AUTHORITY",
            "WORKSPACE_ADVISOR_NO_IDE_MUTATION",
            "WORKSPACE_ADVISOR_NO_REMOTE_CONNECTION",
            "WORKSPACE_ADVISOR_NOT_PERFORMANCE_DIAGNOSIS",
        ],
        "authority": {
            "execution": False,
            "ide_settings": False,
            "cache_mutation": False,
            "indexing_mutation": False,
            "remote_connection": False,
            "credential": False,
            "publication": False,
            "deployment": False,
        },
        "workspace": {
            "name": workspace.name,
            "platform": runtime_platform.lower(),
            "path_classification": path_classification,
            "ecosystems": _manifest_signals(workspace),
        },
        "scan": {
            "max_files": max_files,
            "files_scanned": state.scanned_files,
            "bytes_scanned": state.scanned_bytes,
            "scan_limited": scan_limited,
            "unreadable_entries": state.unreadable_entries,
            "skipped_symlinks": state.skipped_symlinks,
            "git_directory_skipped": True,
        },
        "directory_summary": directories,
        "managed_directory_summary": managed_summary,
        "large_files": [{"path": path, "bytes": size} for size, path in large_files],
        "limitations": [
            "Filesystem shape is measured; CPU, heap, garbage collection, IDE freeze, and indexing timing are not measured.",
            "Remote/WSL state is classified from the local path and runtime only; no remote connection is attempted.",
            "Recommendations are manual review paths, not automatic remediation.",
        ],
    }
    payload["recommendations"] = _recommendations(
        file_count=state.scanned_files,
        scan_limited=scan_limited,
        managed_directory_summary=managed_summary,
        path_classification=path_classification,
    )
    digest_source = dict(payload)
    payload["advice_sha256"] = sha256(_canonical(digest_source).encode("utf-8")).hexdigest()
    return payload


def _require_child(root: Path, candidate: Path | str) -> Path:
    resolved = Path(candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise WorkspaceAdvisorError("WORKSPACE_ADVISOR_OUTPUT_OUTSIDE_ROOT", "artifact directory must stay inside the workspace root") from exc
    return resolved


def _markdown(report: Mapping[str, object]) -> str:
    workspace = report["workspace"]
    scan = report["scan"]
    lines = [
        "# FactoryLine Workspace Load Advisor",
        "",
        "Measured local workspace shape and remote/WSL preflight. This is not an IDE performance diagnosis and changes no IDE settings.",
        "",
        "## Observed workspace",
        "",
        f"- Name: `{workspace['name']}`",
        f"- Path classification: `{workspace['path_classification']}`",
        f"- Files scanned: `{scan['files_scanned']}`",
        f"- Bytes scanned: `{scan['bytes_scanned']}`",
        f"- Scan limited: `{scan['scan_limited']}`",
        "",
        "## Manual review paths",
        "",
    ]
    for item in report["recommendations"]:
        lines.extend([f"### {item['id']}", "", f"{item['action']}", "", f"Boundary: {item['boundary']}", ""])
    lines.extend(["## Boundaries", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def _mermaid(report: Mapping[str, object]) -> str:
    workspace = report["workspace"]
    lines = ["flowchart LR", f'  workspace["{workspace["name"]}: {workspace["path_classification"]}"]']
    for index, item in enumerate(report["recommendations"], start=1):
        node = f"review{index}"
        lines.append(f'  {node}["{item["id"]}: {item["state"]}"]')
        lines.append(f"  workspace --> {node}")
    lines.append('  boundary["Manual review only; no IDE or remote mutation"]')
    for index, _item in enumerate(report["recommendations"], start=1):
        lines.append(f"  review{index} --> boundary")
    return "\n".join(lines) + "\n"


def write_workspace_advisor_artifacts(
    report: Mapping[str, object], root: Path | str, out_dir: Path | str,
) -> dict[str, str]:
    """Write explicit local artifacts only after the caller chooses an output directory."""
    workspace = Path(root).resolve()
    if report.get("schema") != WORKSPACE_ADVISOR_SCHEMA:
        raise WorkspaceAdvisorError("WORKSPACE_ADVISOR_REPORT_INVALID", "report has an unexpected schema")
    target = _require_child(workspace, out_dir)
    target.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": target / "workspace-advisor.json",
        "markdown": target / "workspace-advisor.md",
        "mermaid": target / "workspace-advisor.mmd",
    }
    paths["json"].write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["markdown"].write_text(_markdown(report), encoding="utf-8")
    paths["mermaid"].write_text(_mermaid(report), encoding="utf-8")
    return {name: path.relative_to(workspace).as_posix() for name, path in paths.items()}

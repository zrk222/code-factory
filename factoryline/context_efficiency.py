"""Deterministic, bounded context packets for fast agent hand-offs.

The packet is a read-only view of already-authorized local sources.  It is not a
gate, an approval token, or an instruction to execute anything.  Sources are
content-addressed and re-checked before use; cache reuse is exact and the token
figure is explicitly an estimate (four UTF-8 bytes per token), never a usage
claim.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil
from pathlib import Path
from statistics import median
from typing import Any

REQUEST_SCHEMA = "factory.context-efficiency-request.v1"
PACKET_SCHEMA = "factory.context-efficiency-packet.v1"
VERIFICATION_SCHEMA = "factory.context-efficiency-verification.v1"
STATUS_SCHEMA = "factory.context-efficiency-status.v1"
SELECTION_SCHEMA = "factory.context-efficiency-selection.v1"
EXPERIMENT_SCHEMA = "factory.context-efficiency-paired.v1"
SHARD_CANDIDATE_SCHEMA = "factory.context-shard-candidate.v1"
SHARD_REVIEW_SCHEMA = "factory.context-shard-review.v1"
MODULE_VERSION = "1"


def database_workspace_context(
    root: Path, python_sources: dict, read_source, python_inventory: list | None = None
) -> dict:
    """Capture static database context through the scanner's safe source reader."""
    return _database_workspace_context(
        root, python_sources, read_source, python_inventory
    )


def _database_workspace_context(
    root, python_sources, read_source, python_inventory=None, oracle_snapshots=None
):
    """Build the JSON projection without exposing parser trees to callers."""
    from .intent_quality import database_structure

    paths, gaps = _database_sql_paths(root)
    python_gaps = _database_python_inventory_gaps(python_inventory, python_sources)
    gaps.extend(python_gaps)
    database_signals = bool(paths) or any(
        any(name in raw for name in (b"sqlalchemy", b"sqlite3", b"psycopg", b"alembic"))
        for raw in python_sources.values()
    )
    selected = (
        {path.relative_to(root).as_posix(): raw for path, raw in python_sources.items()}
        if database_signals
        else {}
    )
    config, config_binding = _database_configuration(root, read_source, gaps)
    bindings = [config_binding] if config_binding else []
    bindings.extend(_database_sql_sources(root, paths, read_source, selected, gaps))
    if not selected or any("limit" in gap for gap in gaps):
        result = {
            "status": "NOT_APPLICABLE",
            "gaps": [],
            "tables": [],
            "queries": [],
            "operations": [],
            "source_manifest": [],
        }
    else:
        if oracle_snapshots is None:
            result = database_structure(
                selected,
                config.get("dialect", "postgres"),
                migration_order=config.get("migration_order"),
            )
        else:
            from .intent_quality import _database_structure

            trees = {
                path.relative_to(root).as_posix(): tree
                for path, raw in python_sources.items()
                if isinstance((tree := oracle_snapshots.get(path)), ast.Module)
                and getattr(tree, "_oracle_source_sha256", None)
                == hashlib.sha256(raw).hexdigest()
            }
            result = _database_structure(
                selected,
                config.get("dialect", "postgres"),
                config.get("migration_order"),
                trees,
            )
        if "dialect" not in config:
            gaps.append("database_dialect_confirmation_required")
    result["gaps"] = sorted(set(result["gaps"] + gaps))
    if result["gaps"]:
        result["status"] = "INCOMPLETE"
    result["discovery"] = _database_context_discovery(
        root, paths, gaps, python_gaps, python_inventory, selected, database_signals
    )
    result["configuration_sources"] = bindings
    result.pop("graph_digest", None)
    result["graph_digest"] = _sha(result)
    result["_bindings"] = bindings
    return result


def _database_workspace_context_from_oracle(
    root, python_sources, read_source, python_inventory, oracle_snapshots
):
    """Use fresh scanner trees only during their owning synchronous invocation."""
    return _database_workspace_context(
        root, python_sources, read_source, python_inventory, oracle_snapshots
    )


def _database_sql_sources(root, paths, read_source, selected, gaps):
    from .runtime_audit_common import RuntimeAuditError

    bindings, sql_bytes = [], 0
    for relative in paths:
        try:
            raw = read_source(root, relative)
            if len(raw) > 1_000_000:
                gaps.append("database_source_size_limit:" + relative)
                continue
            sql_bytes += len(raw)
            if sql_bytes > 16_000_000:
                gaps.append("database_total_source_limit")
                break
            selected[relative] = raw
            bindings.append(
                {
                    "path": relative,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                }
            )
        except (OSError, RuntimeAuditError):
            gaps.append("database_source_unreadable:" + relative)
    return bindings


def _database_context_discovery(
    root, paths, gaps, python_gaps, python_inventory, selected, database_signals
):
    return {
        "sql_files": len(paths),
        "paths": paths,
        "configuration_present": (root / "factory.database.json").exists()
        or (root / "factory.database.json").is_symlink(),
        "inventory_complete": not any(
            "discovery" in gap or "limit" in gap for gap in gaps
        )
        and not python_gaps,
        "python_sources_complete": not python_gaps,
        "python_sources_discovered": len(python_inventory or []),
        "python_sources_selected": sum(
            path.lower().endswith(".py") for path in selected
        ),
        "source_selection": "all_retained_python_when_database_signaled"
        if database_signals
        else "not_applicable",
    }


def _database_python_inventory_gaps(python_inventory, python_sources):
    if python_inventory is None:
        return ["database_python_inventory_unverified"]
    gaps = []
    for item in python_inventory:
        path = item.get("path", "")
        state = item.get("state")
        if state != "read":
            gaps.append(f"database_python_source_{state or 'unverified'}:{path}")
        elif not item.get("retained"):
            gaps.append(f"database_python_source_retention_limit:{path}")
    return gaps


def _database_sql_paths(root: Path) -> tuple[list[str], list[str]]:
    ignored = {
        ".git",
        ".factory",
        ".venv",
        "venv",
        "build",
        "dist",
        "tmp",
        "vendor",
        "site-packages",
        "__pycache__",
        "node_modules",
    }
    paths, gaps, entries = [], [], 0
    for directory, dirs, names in os.walk(
        root,
        followlinks=False,
        onerror=lambda _error: gaps.append("database_discovery_unreadable_directory"),
    ):
        entries += len(dirs) + len(names)
        if entries > 50_000:
            gaps.append("database_discovery_entry_limit")
            break
        dirs[:] = _database_directories(
            directory, [name for name in sorted(dirs) if name not in ignored], gaps
        )
        paths.extend(
            (Path(directory) / name).relative_to(root).as_posix()
            for name in sorted(names)
            if name.lower().endswith(".sql")
        )
        if len(paths) > 256:
            gaps.append("database_input_limit")
            return sorted(paths[:257]), gaps
    return sorted(paths), gaps


def _database_directories(directory, names, gaps):
    allowed = []
    for name in names:
        try:
            child = Path(directory) / name
            if (
                child.is_symlink()
                or getattr(child.lstat(), "st_file_attributes", 0) & 0x400
            ):
                gaps.append("database_discovery_linked_directory")
            else:
                allowed.append(name)
        except OSError:
            gaps.append("database_discovery_unreadable_directory")
    return allowed


def verify_database_context(root: Path, context: dict, error_type):
    """Reject new/deleted SQL inputs or configuration after context capture."""
    paths, gaps = _database_sql_paths(root)
    config = root / "factory.database.json"
    discovery = context["discovery"]
    if (
        paths != discovery["paths"]
        or bool(config.exists() or config.is_symlink())
        != discovery["configuration_present"]
        or (gaps and discovery["inventory_complete"])
    ):
        raise error_type("Database source inventory changed during scan")


def _database_configuration(
    root: Path, read_source, gaps: list
) -> tuple[dict, dict | None]:
    from .runtime_audit_common import RuntimeAuditError

    name = "factory.database.json"
    path = root / name
    if not path.exists() and not path.is_symlink():
        return {}, None
    try:
        raw = read_source(root, name)
        binding = {
            "path": name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        if len(raw) > 16_384:
            raise ValueError("configuration byte limit")
        config = json.loads(raw, object_pairs_hook=_database_json_pairs)
        if (
            not isinstance(config, dict)
            or not {"schema", "dialect"}
            <= set(config)
            <= {"schema", "dialect", "migration_order"}
            or config["schema"] != "factory.database-context-config.v1"
            or not isinstance(config["dialect"], str)
            or config["dialect"] not in {"postgres", "sqlite"}
        ):
            raise ValueError("configuration fields")
        order = config.get("migration_order")
        if order is not None and (
            not isinstance(order, list)
            or len(order) > 256
            or any(not isinstance(item, str) for item in order)
        ):
            raise ValueError("migration order fields")
        return config, binding
    except (OSError, RuntimeAuditError, ValueError, UnicodeError):
        gaps.append("database_configuration_invalid")
        return {}, locals().get("binding")


def _database_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate database configuration field")
        result[key] = value
    return result


MAX_SOURCES = 128
MAX_CHANGED_PATHS = 128
MAX_CACHE_FILES = 100
MAX_USAGE_ROWS = MAX_CACHE_FILES * 10
_USAGE_LOCK = threading.Lock()
MAX_CANDIDATES = 64
MAX_SELECTED_SOURCES = 64
MAX_EXPERIMENT_SAMPLES = 100
MAX_EXPERIMENT_HISTORY = 20
MAX_SHARD_CLAIMS = 64
MAX_SHARD_RECORDS = 256
MAX_SHARD_LOCATOR_BYTES = 16_384
MAX_SHARD_ARTIFACT_BYTES = 65_536
MAX_AST_NODES = 20_000
MAX_AST_SOURCE_BYTES = 65_536
MAX_SOURCE_BYTES = 1_048_576
MIN_TOKENS = 256
MAX_TOKENS = 12_000
MIN_FILE_TOKENS = 32
MAX_FILE_TOKENS = 2_000
_SECRET_NAME = re.compile(
    r"(?:^|[._-])(secret|token|password|passwd|credential|credentials|private[-_]?key|api[-_]?key)(?:$|[._-])|(?:^|[/\\])\.env(?:\.[^/\\]*)?$|(?:^|[/\\])(?:id_rsa|id_ed25519|known_hosts|credentials\.json|service[-_]?account[^/\\]*|kubeconfig)$",
    re.I,
)
_SECRET_BYTES = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?:ghp_|github_pat_|pypi-|vsce[_-]?pat)[A-Za-z0-9_-]{8,}"),
    re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(rb"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(
        rb"(?:sk-(?:live|proj|ant|test)-|xox[baprs]-|ya29\.)[A-Za-z0-9._-]{12,}"
    ),
)
_REDACT = (
    re.compile(
        r"(?i)(\b(?:token|password|passwd|secret|(?:[a-z0-9]+_)?api[_-]?key|authorization)\s*[:=]\s*)([^\s,;]+)"
    ),
    re.compile(r"(?i)(\b(?:bearer)\s+)([^\s]+)"),
)


class ContextEfficiencyError(ValueError):
    """Stable fail-closed error raised for malformed or changed context."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ContextEfficiencyError(
            "E_CANONICAL", "value is not canonical JSON"
        ) from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_text(value: Any, field: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ContextEfficiencyError(
            "E_FIELD",
            f"{field} must be a non-empty printable string of at most {maximum} characters",
        )
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ContextEfficiencyError(
            "E_DIGEST", f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ContextEfficiencyError(
            "E_FIELD", f"{field} must be an integer in {minimum}..{maximum}"
        )
    return value


def _reject_secret_keys(value: Any, path: str = "request", depth: int = 0) -> None:
    if depth > 16:
        raise ContextEfficiencyError("E_DEPTH", "request nesting exceeds 16")
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_NAME.search(str(key)):
                raise ContextEfficiencyError(
                    "E_SECRET_MATERIAL", f"secret-shaped field at {path}.{key}"
                )
            _reject_secret_keys(child, f"{path}.{key}", depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}[{index}]", depth + 1)


def _relative_path(root: Path, raw: Any, field: str) -> tuple[Path, str]:
    value = _safe_text(raw, field, 512).replace("\\", "/")
    candidate_raw = Path(value)
    if candidate_raw.is_absolute() or re.match(r"^[A-Za-z]:/", value):
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} must be relative to the workspace"
        )
    if any(part in {"", ".", ".."} for part in candidate_raw.parts):
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} contains traversal or empty components"
        )
    workspace = _validated_root(root)
    candidate = workspace.joinpath(candidate_raw)
    ancestor = workspace
    for part in candidate_raw.parts:
        ancestor = ancestor / part
        if ancestor.is_symlink():
            raise ContextEfficiencyError(
                "E_PATH_LINK", f"{field} may not traverse a symlink"
            )
    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} escapes the workspace"
        ) from exc
    if candidate.is_symlink() or resolved.is_symlink():
        raise ContextEfficiencyError("E_PATH_LINK", f"{field} may not be a symlink")
    return resolved, resolved.relative_to(workspace).as_posix()


def _stable_file(path: Path) -> tuple[bytes, str, dict[str, int]]:
    try:
        before = path.stat()
        if not path.is_file() or path.is_symlink() or before.st_size > MAX_SOURCE_BYTES:
            raise ContextEfficiencyError(
                "E_SOURCE_BOUNDARY",
                f"source is missing, a symlink, or exceeds {MAX_SOURCE_BYTES} bytes",
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    raise ContextEfficiencyError(
                        "E_SOURCE_BOUNDARY",
                        f"source exceeds {MAX_SOURCE_BYTES} bytes while reading",
                    )
                digest.update(chunk)
                chunks.append(chunk)
        after = path.stat()
    except ContextEfficiencyError:
        raise
    except OSError as exc:
        raise ContextEfficiencyError(
            "E_SOURCE_READ", f"cannot read source: {path}"
        ) from exc
    identity_before = {
        "size": int(before.st_size),
        "mtime_ns": int(before.st_mtime_ns),
        "ino": int(getattr(before, "st_ino", 0)),
    }
    identity_after = {
        "size": int(after.st_size),
        "mtime_ns": int(after.st_mtime_ns),
        "ino": int(getattr(after, "st_ino", 0)),
    }
    if identity_before != identity_after:
        raise ContextEfficiencyError(
            "E_SOURCE_CHANGED", f"source changed while reading: {path}"
        )
    raw = b"".join(chunks)
    return raw, digest.hexdigest(), identity_before


def _validate_request_fields(request: Any) -> None:
    if not isinstance(request, dict):
        raise ContextEfficiencyError(
            "E_REQUEST_FIELDS", "request has missing or unknown fields"
        )
    _reject_secret_keys(request)
    if set(request) != {
        "schema",
        "mission_id",
        "contract_digest",
        "changed_paths",
        "sources",
        "max_tokens",
        "per_file_tokens",
    }:
        raise ContextEfficiencyError(
            "E_REQUEST_FIELDS", "request has missing or unknown fields"
        )
    if request["schema"] != REQUEST_SCHEMA:
        raise ContextEfficiencyError("E_SCHEMA", "unsupported request schema")


def _normalize_changed_paths(root: Path, raw_paths: Any) -> list[str]:
    changed: list[str] = []
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= MAX_CHANGED_PATHS:
        raise ContextEfficiencyError(
            "E_FIELD", f"changed_paths must contain 1..{MAX_CHANGED_PATHS} paths"
        )
    for index, item in enumerate(raw_paths):
        _, relative = _relative_path(root, item, f"changed_paths[{index}]")
        if relative in changed:
            raise ContextEfficiencyError(
                "E_DUPLICATE_PATH", f"duplicate changed path: {relative}"
            )
        changed.append(relative)
    return changed


def _normalize_request_sources(root: Path, raw_sources: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_sources, list) or not 1 <= len(raw_sources) <= MAX_SOURCES:
        raise ContextEfficiencyError(
            "E_FIELD", f"sources must contain 1..{MAX_SOURCES} entries"
        )
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw_sources):
        if not isinstance(entry, dict) or set(entry) != {"path", "role", "priority"}:
            raise ContextEfficiencyError(
                "E_SOURCE_FIELDS", f"sources[{index}] has missing or unknown fields"
            )
        _, relative = _relative_path(root, entry["path"], f"sources[{index}].path")
        if relative in seen:
            raise ContextEfficiencyError(
                "E_DUPLICATE_PATH", f"duplicate source path: {relative}"
            )
        seen.add(relative)
        sources.append(
            {
                "path": relative,
                "role": _safe_text(entry["role"], f"sources[{index}].role", 80),
                "priority": _bounded_int(
                    entry["priority"], f"sources[{index}].priority", 0, 100
                ),
            }
        )
    sources.sort(key=lambda item: (-item["priority"], item["role"], item["path"]))
    return sources


def select_context_request(
    root: Path, manifest: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Rank only explicitly supplied candidates; never scan the workspace."""
    request, selection, _ = _select_context_request(root, manifest)
    return request, selection


def _select_context_request(
    root: Path, manifest: Any
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    task, changed, candidates, required, required_roles, max_sources = (
        _selection_inputs(root, manifest)
    )
    task_terms = set(re.findall(r"[a-z0-9]+", task.lower()))
    rows = [
        _score_candidate(root, item, index, task_terms, changed, required)
        for index, item in enumerate(candidates)
    ]
    if len({row["path"] for row in rows}) != len(rows):
        raise ContextEfficiencyError("E_DUPLICATE_PATH", "duplicate candidate path")
    if not required.issubset({row["path"] for row in rows}):
        raise ContextEfficiencyError(
            "E_REQUIRED_EVIDENCE", "required path is absent from candidates"
        )
    rows.sort(key=lambda row: (-row["score"], row["path"]))
    role_required = _required_role_paths(rows, required_roles)
    required.update(role_required)
    _order_selection_rows(rows, changed, required)
    selected = rows[:max_sources]
    if any(row["required"] for row in rows[len(selected) :]):
        raise ContextEfficiencyError(
            "E_REQUIRED_EVIDENCE", "max_sources would omit required evidence"
        )
    request, selection = _selection_outputs(
        root, manifest, task, changed, rows, selected, required, required_roles
    )
    return request, selection, rows


def _selection_inputs(
    root: Path, manifest: Any
) -> tuple[str, list[str], list[Any], set[str], list[str], int]:
    fields = {
        "schema",
        "task",
        "mission_id",
        "contract_digest",
        "changed_paths",
        "candidates",
        "required_paths",
        "required_evidence_roles",
        "max_sources",
        "max_tokens",
        "per_file_tokens",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != fields
        or manifest.get("schema") != SELECTION_SCHEMA
    ):
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "selection manifest has missing or unknown fields"
        )
    task = _safe_text(manifest["task"], "task", 2000)
    changed = _normalize_changed_paths(root, manifest["changed_paths"])
    candidates = manifest["candidates"]
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= MAX_CANDIDATES:
        raise ContextEfficiencyError(
            "E_FIELD", f"candidates must contain 1..{MAX_CANDIDATES} entries"
        )
    max_sources = _bounded_int(
        manifest["max_sources"], "max_sources", 1, MAX_SELECTED_SOURCES
    )
    required_raw = manifest["required_paths"]
    if not isinstance(required_raw, list) or len(required_raw) > MAX_CANDIDATES:
        raise ContextEfficiencyError("E_FIELD", "required_paths must be a bounded list")
    required = {
        _relative_path(root, item, "required_paths[]")[1] for item in required_raw
    }
    required_roles = manifest["required_evidence_roles"]
    if not isinstance(required_roles, list) or len(required_roles) > 16:
        raise ContextEfficiencyError(
            "E_FIELD", "required_evidence_roles must be a bounded list"
        )
    required_roles = sorted(
        {
            _safe_text(role, "required_evidence_roles[]", 80).lower()
            for role in required_roles
        }
    )
    return task, changed, candidates, required, required_roles, max_sources


def _score_candidate(
    root: Path,
    item: Any,
    index: int,
    task_terms: set[str],
    changed: list[str],
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(item, dict) or set(item) != {"path", "role"}:
        raise ContextEfficiencyError(
            "E_CANDIDATE_FIELDS", f"candidates[{index}] must contain path and role"
        )
    _, path = _relative_path(root, item["path"], f"candidates[{index}].path")
    role = _safe_text(item["role"], f"candidates[{index}].role", 80)
    raw, digest, identity = _stable_file(root / path)
    try:
        source_text = raw.decode("utf-8")
    except UnicodeDecodeError:
        source_text = ""
    if _SECRET_NAME.search(path) or any(
        pattern.search(raw) for pattern in _SECRET_BYTES
    ):
        source_text = ""
    path_terms = set(re.findall(r"[a-z0-9]+", path.lower()))
    role_terms = set(re.findall(r"[a-z0-9]+", role.lower()))
    content_terms = set(re.findall(r"[a-z0-9]+", source_text.lower()))
    matched_terms = sorted(task_terms & (path_terms | role_terms | content_terms))[:32]
    score = (
        len(task_terms & path_terms) * 10
        + len(task_terms & role_terms) * 3
        + len(task_terms & content_terms) * 2
        + (20 if path in changed else 0)
    )
    return {
        "path": path,
        "role": role,
        "score": score,
        "priority": 0,
        "stage": 3,
        "required": path in required,
        "sha256": digest,
        "identity": identity,
        "matched_terms": matched_terms,
        "why_selected": "",
        "raw": raw,
        "structure": _structural_evidence(path, raw),
    }


class _EvidenceVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.visited = 0
        self.identifiers: set[str] = set()
        self.definitions: list[dict[str, Any]] = []
        self.imports: set[str] = set()
        self.calls: set[str] = set()

    def _count_node(self) -> None:
        self.visited += 1
        if self.visited > MAX_AST_NODES:
            raise ContextEfficiencyError(
                "E_AST_BOUNDARY", "source structure exceeds node limit"
            )

    def _add_bounded(self, target: set[str], value: str) -> None:
        if len(target) >= 2048 and value not in target:
            raise ContextEfficiencyError(
                "E_AST_BOUNDARY", "source identifiers exceed collection limit"
            )
        target.add(value)

    def generic_visit(self, node: ast.AST) -> None:
        """Collect bounded identifiers while traversing syntax without execution."""
        self._count_node()
        if isinstance(node, ast.Name):
            self._add_bounded(self.identifiers, node.id)
        super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Record function definition ranges and visit their bounded syntax tree."""
        self.definitions.append(
            {
                "name": node.name,
                "kind": "function",
                "start": node.lineno,
                "end": node.end_lineno or node.lineno,
            }
        )
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Record class definition ranges and visit their bounded syntax tree."""
        self.definitions.append(
            {
                "name": node.name,
                "kind": "class",
                "start": node.lineno,
                "end": node.end_lineno or node.lineno,
            }
        )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Collect bounded direct module imports from this syntax node."""
        self._count_node()
        for item in node.names:
            self._add_bounded(self.imports, item.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Collect bounded relative or absolute imports from this syntax node."""
        self._count_node()
        self._add_bounded(self.imports, "." * node.level + (node.module or ""))
        for item in node.names:
            self._add_bounded(self.imports, item.name)

    def visit_Call(self, node: ast.Call) -> None:
        """Collect bounded syntactic call names without resolving their targets."""
        name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else ""
        )
        if name:
            self._add_bounded(self.calls, name)
        self.generic_visit(node)


def _structural_evidence(path: str, raw: bytes) -> dict[str, Any]:
    if path.lower().endswith(".sql"):
        return _database_structural_evidence(path, raw)
    if (
        not path.endswith(".py")
        or _SECRET_NAME.search(path)
        or any(pattern.search(raw) for pattern in _SECRET_BYTES)
        or len(raw) > MAX_AST_SOURCE_BYTES
    ):
        return {
            "status": "PARSE_LIMIT"
            if path.endswith(".py") and len(raw) > MAX_AST_SOURCE_BYTES
            else "NOT_PARSED",
            "definitions": [],
            "imports": [],
            "calls": [],
            "identifiers": [],
        }
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=path)
        visitor = _EvidenceVisitor()
        visitor.visit(tree)
    except (SyntaxError, UnicodeError, RecursionError, ContextEfficiencyError):
        return {
            "status": "PARSE_LIMIT_OR_ERROR",
            "definitions": [],
            "imports": [],
            "calls": [],
            "identifiers": [],
        }
    return {
        "status": "SYNTACTIC_ONLY",
        "node_count": visitor.visited,
        "definitions": sorted(
            visitor.definitions, key=lambda row: (row["start"], row["name"])
        )[:256],
        "imports": sorted(visitor.imports)[:256],
        "calls": sorted(visitor.calls)[:256],
        "identifiers": sorted(
            visitor.identifiers | _database_identifier_hints(path, raw)
        )[:512],
    }


def _database_identifier_hints(path: str, raw: bytes) -> set[str]:
    if not path.lower().endswith(".sql") and b"sqlalchemy" not in raw:
        return set()
    from .intent_quality import database_structure

    graph = database_structure({path: raw}, "postgres")
    return {table["name"] for table in graph["tables"]}


def _database_structural_evidence(path: str, raw: bytes) -> dict[str, Any]:
    empty = {
        "status": "NOT_PARSED",
        "definitions": [],
        "imports": [],
        "calls": [],
        "identifiers": [],
    }
    if (
        _SECRET_NAME.search(path)
        or any(pattern.search(raw) for pattern in _SECRET_BYTES)
        or len(raw) > MAX_AST_SOURCE_BYTES
    ):
        return empty
    from .intent_quality import database_structure

    graph = database_structure({path: raw}, "postgres")
    return {
        **empty,
        "status": "DATABASE_STATIC_ONLY"
        if graph["status"] == "COMPLETE"
        else "PARSE_LIMIT_OR_ERROR",
        "identifiers": sorted(table["name"] for table in graph["tables"])[:512],
    }


def _required_role_paths(
    rows: list[dict[str, Any]], required_roles: list[str]
) -> set[str]:
    available = {row["role"].lower() for row in rows}
    missing = sorted(set(required_roles) - available)
    if missing:
        raise ContextEfficiencyError(
            "E_REQUIRED_EVIDENCE",
            "missing candidate evidence roles: " + ", ".join(missing),
        )
    return {
        next(row["path"] for row in rows if row["role"].lower() == role)
        for role in required_roles
    }


def _order_selection_rows(
    rows: list[dict[str, Any]], changed: list[str], required: set[str]
) -> None:
    for row in rows:
        row["required"] = row["path"] in required
        row["stage"] = (
            0
            if row["required"]
            else 1
            if row["path"] in changed
            else 2
            if row["score"]
            else 3
        )
        row["priority"] = (
            100
            if row["stage"] == 0
            else 80 + min(row["score"], 19)
            if row["stage"] == 1
            else 50 + min(row["score"], 29)
            if row["stage"] == 2
            else 0
        )
        row["why_selected"] = (
            "required_evidence"
            if row["required"]
            else "changed_path"
            if row["path"] in changed
            else "task_terms:" + ",".join(row["matched_terms"])
            if row["matched_terms"]
            else "bounded_fallback"
        )
    rows.sort(key=lambda row: (row["stage"], -row["score"], row["path"]))


def _selection_outputs(
    root: Path,
    manifest: dict[str, Any],
    task: str,
    changed: list[str],
    rows: list[dict[str, Any]],
    selected: list[dict[str, Any]],
    required: set[str],
    required_roles: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    request = {
        "schema": REQUEST_SCHEMA,
        "mission_id": manifest["mission_id"],
        "contract_digest": manifest["contract_digest"],
        "changed_paths": changed,
        "sources": [
            {"path": row["path"], "role": row["role"], "priority": row["priority"]}
            for row in selected
        ],
        "max_tokens": manifest["max_tokens"],
        "per_file_tokens": manifest["per_file_tokens"],
    }
    selection = {
        "schema": SELECTION_SCHEMA,
        "task_sha256": hashlib.sha256(task.encode("utf-8")).hexdigest(),
        "candidate_count": len(rows),
        "candidates": [
            {
                "path": row["path"],
                "role": row["role"],
                "sha256": row["sha256"],
                "identity": row["identity"],
                "score": row["score"],
                "matched_terms": row["matched_terms"],
                "structure": row["structure"],
                "related_paths": _related_candidate_paths(row, rows),
            }
            for row in rows
        ],
        "selected": [
            {
                "path": row["path"],
                "score": row["score"],
                "stage": row["stage"],
                "required": row["required"],
                "why_selected": row["why_selected"],
            }
            for row in selected
        ],
        "omitted": [
            {
                "path": row["path"],
                "role": row["role"],
                "sha256": row["sha256"],
                "reason": "lower_task_relevance",
                "score": row["score"],
            }
            for row in rows[len(selected) :]
        ],
        "required_paths": sorted(required),
        "required_evidence_roles": required_roles,
        "present_evidence_roles": sorted({row["role"].lower() for row in selected}),
        "missing_evidence_roles": sorted(
            set(required_roles) - {row["role"].lower() for row in selected}
        ),
        "ranking": "UNVERIFIED_HEURISTIC_task_terms_path_and_declared_role_v1",
    }
    return request, selection


def _related_candidate_paths(
    candidate: dict[str, Any], rows: list[dict[str, Any]]
) -> list[str]:
    names = set(candidate["structure"].get("identifiers", []))
    if not names:
        return []
    related = []
    for row in rows:
        if row["path"] == candidate["path"]:
            continue
        overlap = names & set(row["structure"].get("identifiers", []))
        if overlap:
            related.append((len(overlap), row["path"]))
    return [
        path for _, path in sorted(related, key=lambda item: (-item[0], item[1]))[:16]
    ]


def _validate_request(root: Path, request: Any) -> dict[str, Any]:
    _validate_request_fields(request)
    mission_id = _safe_text(request["mission_id"], "mission_id", 120)
    contract_digest = _digest(request["contract_digest"], "contract_digest")
    changed = _normalize_changed_paths(root, request["changed_paths"])
    sources = _normalize_request_sources(root, request["sources"])
    return {
        "schema": REQUEST_SCHEMA,
        "mission_id": mission_id,
        "contract_digest": contract_digest,
        "changed_paths": sorted(changed),
        "sources": sources,
        "max_tokens": _bounded_int(
            request["max_tokens"], "max_tokens", MIN_TOKENS, MAX_TOKENS
        ),
        "per_file_tokens": _bounded_int(
            request["per_file_tokens"],
            "per_file_tokens",
            MIN_FILE_TOKENS,
            MAX_FILE_TOKENS,
        ),
    }


def _redact(text: str) -> str:
    for pattern in _REDACT:
        text = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]", text)
    return text


def _selection(
    raw: bytes,
    per_file_tokens: int,
    remaining_bytes: int,
    *,
    sensitive_name: bool = False,
) -> tuple[str | None, str, int, int]:
    budget = max(0, min(per_file_tokens * 4, remaining_bytes))
    if not raw or budget == 0:
        return None, "digest_only", 0, len(raw)
    if sensitive_name or any(pattern.search(raw) for pattern in _SECRET_BYTES):
        return None, "digest_only", 0, len(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "digest_only", 0, len(raw)
    if len(raw) <= budget:
        selected = _redact(text)
        selected_bytes = len(selected.encode("utf-8"))
        if selected_bytes <= budget:
            return selected, "full", selected_bytes, max(0, len(raw) - selected_bytes)
        selected = selected.encode("utf-8")[:budget].decode("utf-8", "ignore")
        selected_bytes = len(selected.encode("utf-8"))
        return selected, "head_tail", selected_bytes, max(0, len(raw) - selected_bytes)
    # Keep both the beginning (intent/configuration) and the end (results/errors)
    # so a compact packet remains useful without pretending to be complete.
    half = max(1, budget // 2)
    head = raw[:half].decode("utf-8", "ignore")
    tail = raw[-half:].decode("utf-8", "ignore")
    selected = _redact(head) + "\n…[context omitted]…\n" + _redact(tail)
    selected_bytes = len(selected.encode("utf-8"))
    if selected_bytes > budget:
        selected = selected.encode("utf-8")[:budget].decode("utf-8", "ignore")
        selected_bytes = len(selected.encode("utf-8"))
    return selected, "head_tail", selected_bytes, max(0, len(raw) - selected_bytes)


def _packet_digest(packet: dict[str, Any]) -> str:
    body = {key: value for key, value in packet.items() if key != "packet_sha256"}
    return _sha(body)


def _cache_dir(root: Path) -> Path:
    return Path(root) / ".factory" / "context-efficiency"


def _validated_root(root: Path) -> Path:
    lexical = Path(root).absolute()
    if _has_reparse_ancestor(lexical):
        raise ContextEfficiencyError(
            "E_PATH_LINK", "workspace path traverses a reparse point"
        )
    return lexical.resolve()


def _record_cache_hit(root: Path, cache_key: str) -> bool:
    """Record bounded operational telemetry outside immutable packet bytes."""
    path = _cache_dir(root) / "usage.sqlite3"
    try:
        raw_root = Path(root).absolute()
        if _has_reparse_ancestor(raw_root):
            return False
        workspace = raw_root.resolve()
        factory_dir = workspace / ".factory"
        cache_dir = _cache_dir(workspace)
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, path):
            return False
        cache_dir.mkdir(parents=True, exist_ok=True)
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, path):
            return False
        with _USAGE_LOCK, sqlite3.connect(path, timeout=2) as database:
            database.execute("PRAGMA max_page_count=256")
            database.execute(
                "CREATE TABLE IF NOT EXISTS cache_usage ("
                "cache_key TEXT PRIMARY KEY, hits INTEGER NOT NULL CHECK(hits >= 0))"
            )
            database.execute("BEGIN IMMEDIATE")
            exists = database.execute(
                "SELECT 1 FROM cache_usage WHERE cache_key = ?", (cache_key,)
            ).fetchone()
            if (
                exists
                or database.execute("SELECT COUNT(*) FROM cache_usage").fetchone()[0]
                < MAX_USAGE_ROWS
            ):
                database.execute(
                    "INSERT INTO cache_usage(cache_key, hits) VALUES (?, 1) "
                    "ON CONFLICT(cache_key) DO UPDATE SET hits = hits + 1",
                    (cache_key,),
                )
                return True
            return False
    except sqlite3.Error:
        # Cache correctness does not depend on optional status telemetry.
        return False
    except (OSError, OverflowError, ValueError):
        return False


def _mark_cache_usage_unknown(root: Path) -> None:
    raw_root = Path(root).absolute()
    if _has_reparse_ancestor(raw_root):
        return
    workspace = raw_root.resolve()
    factory_dir = workspace / ".factory"
    cache_dir = _cache_dir(workspace)
    marker = cache_dir / "usage-incomplete"
    if _unsafe_cache_path(workspace, factory_dir, cache_dir, marker):
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        marker.write_text("cache usage telemetry is incomplete\n", encoding="utf-8")
    except OSError:
        return


def _unsafe_cache_path(
    workspace: Path, factory_dir: Path, cache_dir: Path, database: Path
) -> bool:
    for path in (workspace, factory_dir, cache_dir, database):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            return True
        try:
            if path.exists():
                info = path.lstat()
                attributes = getattr(info, "st_file_attributes", 0)
                if stat.S_ISLNK(info.st_mode) or attributes & getattr(
                    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                ):
                    return True
            path.resolve(strict=False).relative_to(workspace)
        except (OSError, ValueError):
            return True
        if path.exists() and path.is_file() and path.stat().st_size > 1_000_000:
            return True
    return False


def _has_reparse_ancestor(path: Path) -> bool:
    for ancestor in (path, *path.parents):
        try:
            if stat.S_ISLNK(ancestor.lstat().st_mode):
                return True
            attributes = getattr(ancestor.lstat(), "st_file_attributes", 0)
            if attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                return True
        except FileNotFoundError:
            continue
        except OSError:
            return True
    return False


def _cache_hit_count(root: Path, cache_key: str) -> int | None:
    raw_root = Path(root).absolute()
    if _has_reparse_ancestor(raw_root):
        return None
    workspace = raw_root.resolve()
    factory_dir = workspace / ".factory"
    cache_dir = _cache_dir(workspace)
    path = cache_dir / "usage.sqlite3"
    try:
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, path):
            return None
        if not path.exists():
            return None
        incomplete = cache_dir / "usage-incomplete"
        if _unsafe_cache_path(workspace, factory_dir, cache_dir, incomplete):
            return None
        if incomplete.exists():
            return None
        uri = path.resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=2) as database:
            row = database.execute(
                "SELECT hits FROM cache_usage WHERE cache_key = ?", (cache_key,)
            ).fetchone()
        if row is None:
            return None
        hits = row[0]
        if (
            isinstance(hits, bool)
            or not isinstance(hits, int)
            or not 0 <= hits <= 2**31 - 1
        ):
            return None
        return hits
    except sqlite3.Error:
        return None
    except (OSError, OverflowError, ValueError):
        return None


def _read_bounded(path: Path, limit: int = 1_000_000) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ContextEfficiencyError("E_INPUT_BOUNDARY", f"input exceeds {limit} bytes")
    return raw


def _read_source_rows(
    workspace: Path, normalized: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    source_digests: list[dict[str, Any]] = []
    for source in normalized["sources"]:
        path = workspace / source["path"]
        raw, digest, identity = _stable_file(path)
        source_digests.append(
            {"path": source["path"], "sha256": digest, "identity": identity}
        )
        rows.append(
            {"source": source, "raw": raw, "sha256": digest, "identity": identity}
        )
    return rows, source_digests


def _load_cached_packet(
    cache_path: Path,
    request: dict[str, Any],
    rows: list[dict[str, Any]],
    selection: dict[str, Any] | None,
) -> dict[str, Any] | None:
    try:
        cached = json.loads(_read_bounded(cache_path).decode("utf-8"))
        if (
            not isinstance(cached, dict)
            or cached.get("schema") != PACKET_SCHEMA
            or _packet_digest(cached) != cached.get("packet_sha256")
            or cached.get("request") != request
            or cached.get("selection") != selection
        ):
            return None
        packet_sources = _validate_source_rows(
            cached.get("sources"), request["sources"]
        )
        _validate_packet_cache(cached, request, _source_identity_rows(packet_sources))
        _validate_packet_snapshot(cached, request, rows, packet_sources)
        return cached
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ContextEfficiencyError,
        TypeError,
        ValueError,
    ):
        return None


def _write_packet(path: Path, packet: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(packet, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _assemble_packet(
    normalized: dict[str, Any],
    rows: list[dict[str, Any]],
    cache_key: str,
    cache_path: Path,
    selection: dict[str, Any] | None = None,
) -> dict[str, Any]:
    max_bytes = normalized["max_tokens"] * 4
    remaining = max_bytes
    selected_rows: list[dict[str, Any]] = []
    total_source_bytes = 0
    selected_bytes = 0
    truncated = 0
    digest_only = 0
    for row in rows:
        raw = row["raw"]
        total_source_bytes += len(raw)
        excerpt, inclusion, used, omitted = _selection(
            raw,
            normalized["per_file_tokens"],
            remaining,
            sensitive_name=bool(_SECRET_NAME.search(row["source"]["path"])),
        )
        remaining -= used
        selected_bytes += used
        truncated += int(inclusion == "head_tail")
        digest_only += int(inclusion == "digest_only")
        item: dict[str, Any] = {
            "path": row["source"]["path"],
            "role": row["source"]["role"],
            "priority": row["source"]["priority"],
            "source_sha256": row["sha256"],
            "source_bytes": len(raw),
            "selected_bytes": used,
            "omitted_bytes": omitted,
            "inclusion": inclusion,
            "identity": row["identity"],
        }
        if selection is not None:
            selected_metadata = next(
                selected
                for selected in selection["selected"]
                if selected["path"] == row["source"]["path"]
            )
            item["stage"] = selected_metadata["stage"]
            item["why_selected"] = selected_metadata["why_selected"]
            candidate_metadata = next(
                candidate
                for candidate in selection["candidates"]
                if candidate["path"] == row["source"]["path"]
            )
            item["structural_evidence"] = candidate_metadata["structure"]
        if excerpt is not None:
            item["excerpt"] = excerpt
        selected_rows.append(item)
    if selection is not None:
        required = set(selection["required_paths"])
        missing = [
            row["path"]
            for row in selected_rows
            if row["path"] in required and row["inclusion"] != "full"
        ]
        if missing:
            raise ContextEfficiencyError(
                "E_REQUIRED_EVIDENCE",
                "required sources must be fully included: " + ", ".join(missing),
            )
    packet: dict[str, Any] = {
        "schema": PACKET_SCHEMA,
        "module_version": MODULE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "request": normalized,
        "sources": selected_rows,
        "selection": selection,
        "budget": {
            "max_tokens": normalized["max_tokens"],
            "max_bytes": max_bytes,
            "estimated_tokens": ceil(selected_bytes / 4),
            "selected_bytes": selected_bytes,
            "source_bytes": total_source_bytes,
            "omitted_bytes": max(0, total_source_bytes - selected_bytes),
            "decision": "TRUNCATED"
            if truncated or digest_only or selected_bytes < total_source_bytes
            else "WITHIN_BUDGET",
            "truncated_files": truncated,
            "digest_only_files": digest_only,
            "token_quality": "estimated_from_utf8_bytes_not_provider_usage",
            "progression": [
                {
                    "stage": stage,
                    "selected_sources": sum(
                        row.get("stage") == stage for row in selected_rows
                    ),
                    "selected_bytes": sum(
                        row["selected_bytes"]
                        for row in selected_rows
                        if row.get("stage") == stage
                    ),
                    "meaning": (
                        "required"
                        if stage == 0
                        else "changed"
                        if stage == 1
                        else "task_relevant"
                        if stage == 2
                        else "bounded_fallback"
                    ),
                }
                for stage in range(4)
            ]
            if selection is not None
            else [],
        },
        "cache": {
            "key": cache_key,
            "hit": False,
            "path": cache_path.relative_to(cache_path.parents[2]).as_posix(),
        },
        "authority": {
            "execution": False,
            "approval": False,
            "repair": False,
            "publication": False,
            "credential": False,
        },
        "claim_boundary": "Read-only bounded context selection. Token counts are estimates; this packet does not authorize execution, approval, repair, merge, publication, deployment, or credential access.",
    }
    packet["packet_sha256"] = _packet_digest(packet)
    return packet


def build_context_packet(
    root: Path,
    request: dict[str, Any],
    out: Path | None = None,
    *,
    selection: dict[str, Any] | None = None,
    source_snapshot: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build or exactly reuse one bounded packet; never executes a source."""
    workspace = _validated_root(root)
    normalized = _validate_request(workspace, request)
    if source_snapshot is None:
        rows, source_digests = _read_source_rows(workspace, normalized)
    else:
        rows, source_digests = _rows_from_selection_snapshot(
            normalized, selection, source_snapshot
        )
    cache_key = _sha(
        {
            "module_version": MODULE_VERSION,
            "request": normalized,
            "sources": source_digests,
            "selection": selection,
        }
    )
    cache_path = _cache_dir(workspace) / f"{cache_key}.json"
    if cache_path.is_file():
        cached = _load_cached_packet(cache_path, normalized, rows, selection)
        if cached is not None:
            telemetry_recorded = _record_cache_hit(workspace, cache_key)
            if not telemetry_recorded:
                _mark_cache_usage_unknown(workspace)
            result = deepcopy(cached)
            result["cache"] = {
                **result.get("cache", {}),
                "hit": True,
                "usage_count": _cache_hit_count(workspace, cache_key)
                if telemetry_recorded
                else None,
            }
            result["packet_sha256"] = _packet_digest(result)
            if out is not None:
                _write_packet(Path(out), result)
            return result
    packet = _assemble_packet(normalized, rows, cache_key, cache_path, selection)
    _write_packet(cache_path, packet)
    if out is not None:
        _write_packet(Path(out), packet)
    return packet


def build_selected_context_packet(
    root: Path, manifest: Any, out: Path | None = None
) -> dict[str, Any]:
    """Rank declared evidence candidates and build from their stable source snapshots."""
    request, selection, candidates = _select_context_request(root, manifest)
    return build_context_packet(
        root,
        request,
        out,
        selection=selection,
        source_snapshot=candidates,
    )


def _rows_from_selection_snapshot(
    request: dict[str, Any],
    selection: dict[str, Any] | None,
    candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if selection is None:
        raise ContextEfficiencyError("E_SELECTION_FIELDS", "selection is required")
    candidates_by_path = {row["path"]: row for row in candidates}
    rows = []
    digests = []
    for source in request["sources"]:
        candidate = candidates_by_path.get(source["path"])
        if candidate is None or candidate["role"] != source["role"]:
            raise ContextEfficiencyError(
                "E_SELECTION_FIELDS", "selected source is not in snapshot"
            )
        raw = candidate["raw"]
        rows.append(
            {
                "source": source,
                "raw": raw,
                "sha256": candidate["sha256"],
                "identity": candidate["identity"],
            }
        )
        digests.append(
            {
                "path": source["path"],
                "sha256": candidate["sha256"],
                "identity": candidate["identity"],
            }
        )
    return rows, digests


def _metric(value: Any, field: str, *, maximum: float = 1_000_000) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContextEfficiencyError("E_EXPERIMENT_METRIC", f"{field} must be numeric")
    result = float(value)
    if not 0 <= result <= maximum:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_METRIC", f"{field} is outside bounds"
        )
    return result


def _experiment_header(observation: Any) -> tuple[str, list[Any]]:
    fields = {
        "schema",
        "task_sha256",
        "revision_sha256",
        "model_id",
        "tools_sha256",
        "budget_sha256",
        "rubric_sha256",
        "cost_unit",
        "evidence_level",
        "samples",
    }
    if not isinstance(observation, dict) or set(observation) != fields:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_FIELDS", "paired observation has missing or unknown fields"
        )
    if (
        observation["schema"] != EXPERIMENT_SCHEMA
        or observation["evidence_level"] != "operator_supplied_unverified"
    ):
        raise ContextEfficiencyError(
            "E_EXPERIMENT_SCHEMA", "unsupported experiment schema or evidence level"
        )
    if observation["cost_unit"] not in {"USD", "not_recorded"}:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_METRIC", "cost_unit must be USD or not_recorded"
        )
    for key in (
        "task_sha256",
        "revision_sha256",
        "tools_sha256",
        "budget_sha256",
        "rubric_sha256",
    ):
        _digest(observation[key], key)
    samples = observation["samples"]
    if not isinstance(samples, list) or not 1 <= len(samples) <= MAX_EXPERIMENT_SAMPLES:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_SAMPLES", "samples must contain 1..100 paired observations"
        )
    return _safe_text(observation["model_id"], "model_id", 160), samples


def _arm_measurement(
    row: Any, arm: str
) -> tuple[float, float, float | None, float | None]:
    optional = {"phases_seconds", "quality", "cost", "tokens"}
    if (
        not isinstance(row, dict)
        or set(row) - optional
        or not {"phases_seconds", "quality"}.issubset(row)
    ):
        raise ContextEfficiencyError(
            "E_EXPERIMENT_SAMPLE", f"{arm} sample requires phase timings and quality"
        )
    phases = row["phases_seconds"]
    names = {"context_gathering", "coding", "repair"}
    if not isinstance(phases, dict) or set(phases) != names:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_PHASES",
            "all context_gathering, coding, and repair timings are required",
        )
    seconds = sum(_metric(phases[name], f"{arm}.{name}") for name in names)
    quality = _metric(row["quality"], f"{arm}.quality", maximum=100)
    cost = _metric(row["cost"], f"{arm}.cost") if "cost" in row else None
    tokens = _metric(row["tokens"], f"{arm}.tokens") if "tokens" in row else None
    return seconds, quality, cost, tokens


def _collect_experiment_metrics(
    samples: list[Any],
) -> dict[str, dict[str, list[float]]]:
    metrics = {
        name: {arm: [] for arm in ("baseline", "context")}
        for name in ("seconds", "quality", "cost", "tokens")
    }
    seen: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or set(sample) != {"id", "baseline", "context"}:
            raise ContextEfficiencyError(
                "E_EXPERIMENT_SAMPLE", f"samples[{index}] is malformed"
            )
        sample_id = _safe_text(sample["id"], f"samples[{index}].id", 120)
        if sample_id in seen:
            raise ContextEfficiencyError(
                "E_EXPERIMENT_SAMPLE", "sample ids must be unique"
            )
        seen.add(sample_id)
        for arm in ("baseline", "context"):
            seconds, quality, cost, tokens = _arm_measurement(sample[arm], arm)
            for key, value in (
                ("seconds", seconds),
                ("quality", quality),
                ("cost", cost),
                ("tokens", tokens),
            ):
                if value is not None:
                    metrics[key][arm].append(value)
        for key in ("cost", "tokens"):
            if (key in sample["baseline"]) != (key in sample["context"]):
                raise ContextEfficiencyError(
                    "E_EXPERIMENT_METRIC",
                    f"{key} must be measured for both arms or neither",
                )
    return metrics


def _experiment_projection(
    observation: dict[str, Any],
    model: str,
    samples: list[Any],
    metrics: dict[str, dict[str, list[float]]],
) -> dict[str, Any]:
    if (
        median(metrics["seconds"]["baseline"]) <= 0
        or median(metrics["seconds"]["context"]) <= 0
    ):
        raise ContextEfficiencyError(
            "E_EXPERIMENT_METRIC", "median elapsed time must be positive"
        )
    count = len(samples)
    for key in ("cost", "tokens"):
        values = metrics[key]["baseline"]
        if values and len(values) != count:
            raise ContextEfficiencyError(
                "E_EXPERIMENT_METRIC", f"{key} must be present in every pair or omitted"
            )
    has_cost = bool(metrics["cost"]["baseline"])
    if has_cost != (observation["cost_unit"] == "USD"):
        raise ContextEfficiencyError(
            "E_EXPERIMENT_METRIC", "cost_unit does not match cost observations"
        )
    baseline_time = median(metrics["seconds"]["baseline"])
    context_time = median(metrics["seconds"]["context"])
    baseline_quality = median(metrics["quality"]["baseline"])
    context_quality = median(metrics["quality"]["context"])
    reduction = 1 - context_time / baseline_time
    nonregressed = context_quality >= baseline_quality
    sufficient = count >= 3
    cost = metrics["cost"]
    tokens = metrics["tokens"]
    return {
        "schema": "factory.context-efficiency-experiment-result.v1",
        "state": "TARGET_MET"
        if sufficient and reduction >= 0.5 and nonregressed
        else "TARGET_NOT_MET"
        if sufficient
        else "INSUFFICIENT_SAMPLES",
        "evidence_level": "operator_supplied_unverified",
        "model_id": model,
        "paired_sample_count": count,
        "baseline_median_seconds": baseline_time,
        "context_median_seconds": context_time,
        "observed_latency_reduction": reduction,
        "quality_nonregression": nonregressed,
        "baseline_median_quality": baseline_quality,
        "context_median_quality": context_quality,
        "observed_cost_delta": median(cost["context"]) - median(cost["baseline"])
        if cost["baseline"]
        else None,
        "observed_cost_delta_unit": "USD" if cost["baseline"] else None,
        "observed_token_delta": median(tokens["context"]) - median(tokens["baseline"])
        if tokens["baseline"]
        else None,
        "observed_token_delta_unit": "tokens" if tokens["baseline"] else None,
        "claim_boundary": "Operator-supplied observations are not independently verified. Result applies only to this paired sample set; it is not a global performance claim.",
    }


def evaluate_context_experiment(observation: Any) -> dict[str, Any]:
    """Evaluate operator-supplied paired observations; never execute a model."""
    model, samples = _experiment_header(observation)
    return _experiment_projection(
        observation, model, samples, _collect_experiment_metrics(samples)
    )


def _read_experiment_history(path: Path) -> list[dict[str, Any]]:
    try:
        stored = json.loads(_read_bounded(path).decode("utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError, json.JSONDecodeError, ContextEfficiencyError) as exc:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_STORE", "stored experiment history cannot be read"
        ) from exc
    if (
        not isinstance(stored, dict)
        or stored.get("schema") != "factory.context-efficiency-experiments.v1"
    ):
        raise ContextEfficiencyError(
            "E_EXPERIMENT_STORE", "stored experiment history is malformed"
        )
    entries = stored.get("results")
    if not isinstance(entries, list) or len(entries) > MAX_EXPERIMENT_HISTORY:
        raise ContextEfficiencyError(
            "E_EXPERIMENT_STORE", "stored experiment history is malformed"
        )
    history = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "observation",
            "observation_sha256",
            "result",
        }:
            raise ContextEfficiencyError(
                "E_EXPERIMENT_STORE", "stored experiment record is malformed"
            )
        if _sha(entry["observation"]) != entry["observation_sha256"]:
            raise ContextEfficiencyError(
                "E_EXPERIMENT_STORE", "stored observation hash does not match"
            )
        result = evaluate_context_experiment(entry["observation"])
        if entry["result"] != result:
            raise ContextEfficiencyError(
                "E_EXPERIMENT_STORE", "stored aggregate does not match observations"
            )
        history.append(result)
    return history


def record_context_experiment(root: Path, observation: Any) -> dict[str, Any]:
    """Validate and store operator-supplied paired observations as unverified evidence."""
    result = evaluate_context_experiment(observation)
    directory = _cache_dir(Path(root).resolve())
    path = directory / "experiment.json"
    _read_experiment_history(path)
    # Keep records in the file; history is used as a bounded sanity check only.
    entries: list[dict[str, Any]] = []
    if path.is_file():
        stored = json.loads(_read_bounded(path).decode("utf-8"))
        entries = stored["results"]
    directory.mkdir(parents=True, exist_ok=True)
    entry = {
        "observation": observation,
        "observation_sha256": _sha(observation),
        "result": result,
    }
    payload = {
        "schema": "factory.context-efficiency-experiments.v1",
        "results": [*entries[-(MAX_EXPERIMENT_HISTORY - 1) :], entry],
    }
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return result


def _validate_source_row_binding(
    row: Any, expected: dict[str, Any], allowed: set[str]
) -> None:
    if (
        not isinstance(row, dict)
        or set(row) - allowed
        or row.get("path") != expected["path"]
        or row.get("role") != expected["role"]
        or row.get("priority") != expected["priority"]
    ):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source row is not bound to the request"
        )


def _validate_source_row_accounting(row: dict[str, Any]) -> None:
    if row.get("inclusion") not in {"full", "head_tail", "digest_only"}:
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source inclusion is invalid"
        )
    sizes = ("source_bytes", "selected_bytes", "omitted_bytes")
    if any(not isinstance(row.get(field), int) for field in sizes):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source byte accounting is invalid"
        )
    if (
        row["selected_bytes"] < 0
        or row["selected_bytes"] > row["source_bytes"]
        or row["omitted_bytes"] != row["source_bytes"] - row["selected_bytes"]
    ):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source byte accounting is invalid"
        )


def _validate_source_rows(
    packet_sources: Any, expected_sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not isinstance(packet_sources, list) or len(packet_sources) != len(
        expected_sources
    ):
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "packet source rows do not match the request"
        )
    allowed = {
        "path",
        "role",
        "priority",
        "source_sha256",
        "source_bytes",
        "selected_bytes",
        "omitted_bytes",
        "inclusion",
        "identity",
        "stage",
        "why_selected",
        "excerpt",
        "structural_evidence",
    }
    for row, expected in zip(packet_sources, expected_sources):
        _validate_source_row_binding(row, expected, allowed)
        _validate_source_row_accounting(row)
    return packet_sources


def _validate_packet_snapshot(
    packet: dict[str, Any],
    request: dict[str, Any],
    rows: list[dict[str, Any]],
    packet_sources: list[dict[str, Any]],
) -> None:
    if packet.get("request") != request:
        raise ContextEfficiencyError(
            "E_REQUEST_MISMATCH", "packet request is not normalized"
        )
    expected_sources = []
    by_path = {row["source"]["path"]: row for row in rows}
    for source in request["sources"]:
        row = by_path[source["path"]]
        expected_sources.append(
            {
                "path": source["path"],
                "sha256": row["sha256"],
                "identity": row["identity"],
            }
        )
    if _source_identity_rows(packet_sources) != expected_sources:
        raise ContextEfficiencyError(
            "E_SOURCE_ROWS", "cached source identity does not match snapshot"
        )
    remaining = request["max_tokens"] * 4
    for source, item in zip(request["sources"], packet_sources):
        raw = by_path[source["path"]]["raw"]
        excerpt, inclusion, selected, omitted = _selection(
            raw,
            request["per_file_tokens"],
            remaining,
            sensitive_name=bool(_SECRET_NAME.search(source["path"])),
        )
        remaining -= selected
        if (
            item["source_bytes"] != len(raw)
            or item["selected_bytes"] != selected
            or item["omitted_bytes"] != omitted
            or item["inclusion"] != inclusion
            or ("excerpt" in item) != (excerpt is not None)
            or item.get("excerpt") != excerpt
        ):
            raise ContextEfficiencyError(
                "E_EXCERPT_MISMATCH",
                f"cached excerpt does not match source: {source['path']}",
            )
    _verify_packet_budget(packet)


def _source_identity_rows(
    packet_sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "path": item["path"],
            "sha256": item["source_sha256"],
            "identity": item["identity"],
        }
        for item in packet_sources
    ]


def _validate_packet_cache(
    packet: dict[str, Any],
    request: dict[str, Any],
    source_identities: list[dict[str, Any]],
) -> None:
    cache = packet.get("cache")
    expected_key = _sha(
        {
            "module_version": MODULE_VERSION,
            "request": request,
            "sources": source_identities,
            "selection": packet.get("selection"),
        }
    )
    if not isinstance(cache, dict) or cache.get("key") != expected_key:
        raise ContextEfficiencyError(
            "E_CACHE_KEY", "cache key does not match request and source identities"
        )


def _verify_selection_evidence(
    workspace: Path, selection: Any, packet_sources: list[dict[str, Any]]
) -> None:
    if selection is None:
        return
    expected_keys = {
        "schema",
        "task_sha256",
        "candidate_count",
        "candidates",
        "selected",
        "omitted",
        "required_paths",
        "required_evidence_roles",
        "present_evidence_roles",
        "missing_evidence_roles",
        "ranking",
    }
    if not isinstance(selection, dict) or set(selection) != expected_keys:
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "selection metadata has missing or unknown fields"
        )
    candidates, selected, omitted = _selection_rows(selection)
    candidate_paths = _verify_candidates(workspace, candidates)
    _verify_selection_partition(
        selection, candidates, selected, omitted, packet_sources, candidate_paths
    )


def _selection_rows(
    selection: dict[str, Any],
) -> tuple[list[Any], list[Any], list[Any]]:
    candidates = selection.get("candidates")
    selected = selection.get("selected")
    omitted = selection.get("omitted")
    if (
        not isinstance(candidates, list)
        or not 1 <= len(candidates) <= MAX_CANDIDATES
        or not isinstance(selected, list)
        or not isinstance(omitted, list)
        or len(candidates) != len(selected) + len(omitted)
    ):
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "candidate evidence rows are malformed"
        )
    if selection.get("candidate_count") != len(candidates):
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "candidate count does not match rows"
        )
    return candidates, selected, omitted


def _verify_candidates(workspace: Path, candidates: list[Any]) -> set[str]:
    candidate_paths: set[str] = set()
    for row in candidates:
        if not isinstance(row, dict) or set(row) != {
            "path",
            "role",
            "sha256",
            "identity",
            "score",
            "matched_terms",
            "structure",
            "related_paths",
        }:
            raise ContextEfficiencyError(
                "E_SELECTION_FIELDS", "candidate evidence row is malformed"
            )
        path, relative = _relative_path(
            workspace, row["path"], "selection.candidates.path"
        )
        if (
            relative in candidate_paths
            or _digest(row["sha256"], "selection.candidates.sha256") != row["sha256"]
        ):
            raise ContextEfficiencyError(
                "E_SELECTION_FIELDS", "candidate evidence identity is invalid"
            )
        candidate_paths.add(relative)
        _validate_structure(row["structure"])
        if not isinstance(row["related_paths"], list) or len(row["related_paths"]) > 16:
            raise ContextEfficiencyError(
                "E_SELECTION_FIELDS", "related candidate list is malformed"
            )
        raw, digest, identity = _stable_file(path)
        structural = _structural_evidence(relative, raw)
        if (
            digest != row["sha256"]
            or identity != row["identity"]
            or structural != row["structure"]
        ):
            raise ContextEfficiencyError(
                "E_SELECTION_DRIFT", f"candidate changed: {relative}"
            )
    return candidate_paths


def _verify_selection_partition(
    selection: dict[str, Any],
    candidates: list[Any],
    selected: list[Any],
    omitted: list[Any],
    packet_sources: list[dict[str, Any]],
    candidate_paths: set[str],
) -> None:
    source_paths = {row["path"] for row in packet_sources}
    selected_paths = {row.get("path") for row in selected if isinstance(row, dict)}
    omitted_paths = {row.get("path") for row in omitted if isinstance(row, dict)}
    if (
        selected_paths != source_paths
        or selected_paths & omitted_paths
        or selected_paths | omitted_paths != candidate_paths
    ):
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "selected, omitted, and candidate paths do not match"
        )
    _validate_selection_rows(selected, omitted)
    candidate_by_path = {row["path"]: row for row in candidates}
    packet_by_path = {row["path"]: row for row in packet_sources}
    _validate_selected_bindings(selected, candidate_by_path, packet_by_path)
    omitted_by_path = {row.get("path"): row for row in omitted if isinstance(row, dict)}
    for path, row in omitted_by_path.items():
        if (
            path not in candidate_by_path
            or row.get("sha256") != candidate_by_path[path]["sha256"]
        ):
            raise ContextEfficiencyError(
                "E_SELECTION_FIELDS",
                "omitted source is not bound to candidate evidence",
            )
    candidate_rows = list(candidate_by_path.values())
    for row in candidates:
        if row["related_paths"] != _related_candidate_paths(row, candidate_rows):
            raise ContextEfficiencyError(
                "E_SELECTION_FIELDS", "related candidate references do not match"
            )
    _verify_required_selection(selection, packet_sources, selected_paths)


def _validate_selection_rows(selected: list[Any], omitted: list[Any]) -> None:
    if any(
        not isinstance(row, dict)
        or row.get("stage") not in {0, 1, 2, 3}
        or not isinstance(row.get("why_selected"), str)
        for row in selected
    ):
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "selection rationale is malformed"
        )
    if any(
        not isinstance(row, dict)
        or set(row) != {"path", "role", "sha256", "reason", "score"}
        for row in omitted
    ):
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "omitted candidate evidence is malformed"
        )


def _validate_selected_bindings(
    selected: list[Any],
    candidate_by_path: dict[str, Any],
    packet_by_path: dict[str, Any],
) -> None:
    for row in selected:
        candidate = candidate_by_path[row["path"]]
        source = packet_by_path[row["path"]]
        if (
            candidate["sha256"] != source["source_sha256"]
            or candidate["role"] != source["role"]
        ):
            raise ContextEfficiencyError(
                "E_SELECTION_FIELDS",
                "selected source is not bound to candidate evidence",
            )


def _verify_required_selection(
    selection: dict[str, Any],
    packet_sources: list[dict[str, Any]],
    selected_paths: set[str],
) -> None:
    required = selection.get("required_paths")
    missing_roles = selection.get("missing_evidence_roles")
    required_roles = selection.get("required_evidence_roles")
    full_roles = {
        row["role"].lower() for row in packet_sources if row["inclusion"] == "full"
    }
    if (
        not isinstance(required, list)
        or not set(required).issubset(selected_paths)
        or not isinstance(missing_roles, list)
        or missing_roles
        or not isinstance(required_roles, list)
        or not set(required_roles).issubset(full_roles)
        or selection.get("present_evidence_roles")
        != sorted({row["role"].lower() for row in packet_sources})
    ):
        raise ContextEfficiencyError(
            "E_REQUIRED_EVIDENCE", "required paths or evidence roles are missing"
        )


def _validate_structure(value: Any) -> None:
    if not isinstance(value, dict) or value.get("status") not in {
        "SYNTACTIC_ONLY",
        "NOT_PARSED",
        "PARSE_LIMIT",
        "PARSE_LIMIT_OR_ERROR",
        "DATABASE_STATIC_ONLY",
    }:
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "structural evidence is malformed"
        )
    common = {"status", "definitions", "imports", "calls", "identifiers"}
    expected = (
        common | {"node_count"} if value["status"] == "SYNTACTIC_ONLY" else common
    )
    if set(value) != expected:
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "structural evidence fields are malformed"
        )
    if value["status"] == "SYNTACTIC_ONLY" and (
        type(value["node_count"]) is not int
        or not 1 <= value["node_count"] <= MAX_AST_NODES
    ):
        raise ContextEfficiencyError(
            "E_SELECTION_FIELDS", "structural node count is invalid"
        )


def _verify_packet_header(
    workspace: Path, packet: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if packet.get("schema") != PACKET_SCHEMA or packet.get(
        "packet_sha256"
    ) != _packet_digest(packet):
        raise ContextEfficiencyError(
            "E_PACKET_DIGEST", "packet schema or digest is invalid"
        )
    request = _validate_request(workspace, packet.get("request"))
    packet_sources = _validate_source_rows(packet.get("sources"), request["sources"])
    selection = packet.get("selection")
    if selection is not None:
        selected = selection.get("selected") if isinstance(selection, dict) else None
        required_paths = (
            selection.get("required_paths") if isinstance(selection, dict) else None
        )
        requested_paths = {row["path"] for row in packet_sources}
        required_by_priority = {
            row["path"] for row in packet_sources if row["priority"] == 100
        }
        if (
            not isinstance(selection, dict)
            or selection.get("schema") != SELECTION_SCHEMA
            or not isinstance(selection.get("task_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", selection["task_sha256"]) is None
            or not isinstance(selected, list)
            or {row.get("path") for row in selected if isinstance(row, dict)}
            != requested_paths
            or not isinstance(required_paths, list)
            or set(required_paths) != required_by_priority
            or any(
                not isinstance(row, dict) or row.get("stage") not in {0, 1, 2, 3}
                for row in selected
            )
            or any(
                row["path"] in required_paths and row["inclusion"] != "full"
                for row in packet_sources
            )
        ):
            raise ContextEfficiencyError(
                "E_REQUIRED_EVIDENCE",
                "required context evidence is missing or truncated",
            )
        _verify_selection_evidence(workspace, selection, packet_sources)
    source_identities = _source_identity_rows(packet_sources)
    _validate_packet_cache(packet, request, source_identities)
    return request, packet_sources


def _verify_packet_sources(
    workspace: Path, packet_sources: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = []
    for item in packet_sources:
        source_path, relative = _relative_path(
            workspace, item.get("path"), "packet.sources.path"
        )
        raw, digest, identity = _stable_file(source_path)
        if (
            relative != item.get("path")
            or digest != item.get("source_sha256")
            or identity != item.get("identity")
            or len(raw) != item.get("source_bytes")
        ):
            raise ContextEfficiencyError(
                "E_SOURCE_DRIFT", f"source changed: {relative}"
            )
        rows.append(
            {
                "source": {
                    "path": relative,
                    "role": item["role"],
                    "priority": item["priority"],
                },
                "raw": raw,
                "sha256": digest,
                "identity": identity,
            }
        )
    return rows


def _verify_packet_budget(packet: dict[str, Any]) -> None:
    budget = packet.get("budget")
    if (
        not isinstance(budget, dict)
        or budget.get("selected_bytes", -1) > budget.get("max_bytes", -2)
        or budget.get("token_quality") != "estimated_from_utf8_bytes_not_provider_usage"
    ):
        raise ContextEfficiencyError("E_BUDGET", "packet budget is invalid")


def verify_context_packet(root: Path, packet_path: Path) -> dict[str, Any]:
    """Verify packet identity and every selected source without executing it."""
    workspace = _validated_root(root)
    path = (
        Path(packet_path)
        if Path(packet_path).is_absolute()
        else workspace / packet_path
    )
    try:
        packet = json.loads(_read_bounded(path).decode("utf-8"))
        if not isinstance(packet, dict):
            raise ContextEfficiencyError("E_SCHEMA", "packet must be an object")
        request, packet_sources = _verify_packet_header(workspace, packet)
        source_rows = _verify_packet_sources(workspace, packet_sources)
        _validate_packet_snapshot(
            packet,
            request,
            source_rows,
            packet_sources,
        )
        return {
            "schema": VERIFICATION_SCHEMA,
            "state": "READY",
            "valid": True,
            "packet_sha256": packet["packet_sha256"],
            "source_count": len(source_rows),
            "cache_key": packet["cache"]["key"],
            "claim_boundary": "Packet and source digests match; this is read-only evidence and estimated token accounting, not an approval or usage receipt.",
        }
    except (
        ContextEfficiencyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
    ) as exc:
        return {
            "schema": VERIFICATION_SCHEMA,
            "state": "BLOCKED",
            "valid": False,
            "code": getattr(exc, "code", "E_PACKET_READ"),
            "message": getattr(exc, "message", str(exc)),
            "claim_boundary": "Verification failed closed; no execution or approval authority is granted.",
        }


def _shard_digest(value: dict[str, Any], field: str) -> str:
    body = {key: item for key, item in value.items() if key != field}
    return _sha(body)


def _shard_artifact_path(root: Path, kind: str, digest: str) -> tuple[Path, str]:
    workspace = _validated_root(root)
    relative = f".factory/context-efficiency/shards/{kind}/{digest}.json"
    path, normalized = _shard_relative_path(workspace, relative, "shard artifact")
    return path, normalized


def _shard_relative_path(root: Path, raw: Any, field: str) -> tuple[Path, str]:
    lexical_root = Path(root).absolute()
    if _has_reparse_ancestor(lexical_root):
        raise ContextEfficiencyError(
            "E_PATH_LINK", "workspace path traverses a reparse point"
        )
    value = _safe_text(raw, field, 512).replace("\\", "/")
    candidate = Path(value)
    if (
        candidate.is_absolute()
        or re.match(r"^[A-Za-z]:/", value)
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ContextEfficiencyError(
            "E_PATH_BOUNDARY", f"{field} must stay within workspace"
        )
    lexical = lexical_root.joinpath(candidate)
    if _has_reparse_ancestor(lexical):
        raise ContextEfficiencyError(
            "E_PATH_LINK", f"{field} may not traverse a reparse point"
        )
    return _relative_path(lexical_root, value, field)


def _write_immutable_shard(path: Path, artifact: dict[str, Any]) -> None:
    raw = _canonical(artifact) + b"\n"
    if len(raw) > MAX_SHARD_ARTIFACT_BYTES:
        raise ContextEfficiencyError(
            "E_SHARD_BOUNDARY", "shard artifact exceeds size limit"
        )
    try:
        if _has_reparse_ancestor(path):
            raise ContextEfficiencyError(
                "E_PATH_LINK", "shard artifact path traverses a reparse point"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        if _has_reparse_ancestor(path):
            raise ContextEfficiencyError(
                "E_PATH_LINK", "shard artifact path traverses a reparse point"
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if _read_bounded(path, MAX_SHARD_ARTIFACT_BYTES) != raw:
            raise ContextEfficiencyError(
                "E_SHARD_COLLISION", "immutable shard path contains different bytes"
            )
    except OSError as exc:
        raise ContextEfficiencyError(
            "E_SHARD_WRITE", "cannot write immutable shard artifact"
        ) from exc


def _shard_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ContextEfficiencyError(
            "E_SHARD_EXPIRY", f"{field} must be a UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContextEfficiencyError(
            "E_SHARD_EXPIRY", f"{field} must be a UTC timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ContextEfficiencyError(
            "E_SHARD_EXPIRY", f"{field} must include UTC timezone"
        )
    return parsed.astimezone(timezone.utc)


def _shard_now(now: Any = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, datetime) and now.tzinfo is not None:
        return now.astimezone(timezone.utc)
    raise ContextEfficiencyError("E_SHARD_TIME", "now must be timezone-aware")


def _shard_source_rows(
    root: Path, packet: dict[str, Any]
) -> dict[str, tuple[bytes, str]]:
    rows: dict[str, tuple[bytes, str]] = {}
    for source in packet.get("sources", []):
        if not isinstance(source, dict) or source.get("inclusion") != "full":
            continue
        path, relative = _shard_relative_path(root, source.get("path"), "packet source")
        if _SECRET_NAME.search(relative):
            continue
        raw, digest, _ = _stable_file(path)
        if digest != source.get("source_sha256") or any(
            pattern.search(raw) for pattern in _SECRET_BYTES
        ):
            continue
        rows[relative] = (raw, digest)
    return rows


def _shard_locator(
    root: Path, raw_locator: Any, sources: dict[str, tuple[bytes, str]]
) -> dict[str, Any]:
    fields = {"path", "start_byte", "end_byte"}
    if not isinstance(raw_locator, dict) or set(raw_locator) != fields:
        raise ContextEfficiencyError(
            "E_SHARD_LOCATOR", "locator must contain path and byte bounds"
        )
    path, relative = _shard_relative_path(root, raw_locator["path"], "locator.path")
    del path
    source = sources.get(relative)
    if source is None:
        raise ContextEfficiencyError(
            "E_SHARD_LOCATOR", "locator must refer to a full, safe packet source"
        )
    raw, digest = source
    start = _bounded_int(raw_locator["start_byte"], "locator.start_byte", 0, len(raw))
    end = _bounded_int(raw_locator["end_byte"], "locator.end_byte", 1, len(raw))
    if end <= start or end - start > MAX_SHARD_LOCATOR_BYTES:
        raise ContextEfficiencyError(
            "E_SHARD_LOCATOR", "locator span is empty or exceeds limit"
        )
    span = raw[start:end]
    try:
        span.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContextEfficiencyError(
            "E_SHARD_LOCATOR", "locator must align to UTF-8 boundaries"
        ) from exc
    return {
        "path": relative,
        "raw_source_sha256": digest,
        "start_byte": start,
        "end_byte": end,
        "span_sha256": hashlib.sha256(span).hexdigest(),
    }


def _verify_shard_locator(root: Path, locator: Any) -> bool:
    try:
        if not isinstance(locator, dict) or set(locator) != {
            "path",
            "raw_source_sha256",
            "start_byte",
            "end_byte",
            "span_sha256",
        }:
            return False
        path, relative = _shard_relative_path(
            root, locator["path"], "shard locator.path"
        )
        if relative != locator["path"] or _SECRET_NAME.search(relative):
            return False
        raw, digest, _ = _stable_file(path)
        start = _bounded_int(locator["start_byte"], "locator.start_byte", 0, len(raw))
        end = _bounded_int(locator["end_byte"], "locator.end_byte", 1, len(raw))
        if end <= start or end - start > MAX_SHARD_LOCATOR_BYTES:
            return False
        span = raw[start:end]
        span.decode("utf-8")
        return (
            not any(pattern.search(raw) for pattern in _SECRET_BYTES)
            and digest == locator["raw_source_sha256"]
            and hashlib.sha256(span).hexdigest() == locator["span_sha256"]
        )
    except (ContextEfficiencyError, OSError, UnicodeError, TypeError, KeyError):
        return False


def _normalize_shard_claims(
    root: Path, claims: Any, sources: dict[str, tuple[bytes, str]]
) -> list[dict[str, Any]]:
    if not isinstance(claims, list) or not 1 <= len(claims) <= MAX_SHARD_CLAIMS:
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "claims must contain 1..64 entries"
        )
    normalized = []
    for index, claim in enumerate(claims):
        if not isinstance(claim, dict) or set(claim) != {"key", "value", "locators"}:
            raise ContextEfficiencyError(
                "E_SHARD_FIELDS", f"claims[{index}] has invalid fields"
            )
        key = _safe_text(claim["key"], f"claims[{index}].key", 160).strip()
        value = claim["value"]
        if not isinstance(value, (str, int, float, bool, list, dict)) or value is None:
            raise ContextEfficiencyError(
                "E_SHARD_FIELDS", f"claims[{index}].value must be bounded JSON"
            )
        _reject_secret_keys({"value": value}, f"claims[{index}]")
        value_bytes = _canonical(value)
        if len(value_bytes) > MAX_SHARD_LOCATOR_BYTES or any(
            pattern.search(value_bytes) for pattern in _SECRET_BYTES
        ):
            raise ContextEfficiencyError(
                "E_SHARD_BOUNDARY", f"claims[{index}].value exceeds limit"
            )
        locators = claim["locators"]
        if (
            not isinstance(locators, list)
            or not 1 <= len(locators) <= MAX_SHARD_RECORDS
        ):
            raise ContextEfficiencyError(
                "E_SHARD_LOCATOR", f"claims[{index}] requires source locators"
            )
        normalized.append(
            {
                "key": key,
                "value": value,
                "locators": [
                    _shard_locator(root, locator, sources) for locator in locators
                ],
            }
        )
    return normalized


def _normalize_shard_retention(
    root: Path, retained_records: Any, sources: dict[str, tuple[bytes, str]]
) -> dict[str, list[dict[str, Any]]]:
    categories = {"correction", "failure", "approval", "unresolved_action"}
    if not isinstance(retained_records, dict) or set(retained_records) != categories:
        raise ContextEfficiencyError(
            "E_SHARD_RETENTION", "all four retained-record categories are required"
        )
    retained = {}
    count = 0
    for category in sorted(categories):
        records = retained_records[category]
        if not isinstance(records, list):
            raise ContextEfficiencyError(
                "E_SHARD_RETENTION", f"{category} must be a locator list"
            )
        count += len(records)
        retained[category] = [
            _shard_locator(root, locator, sources) for locator in records
        ]
    if count > MAX_SHARD_RECORDS:
        raise ContextEfficiencyError(
            "E_SHARD_BOUNDARY", "retained records exceed limit"
        )
    return retained


def _candidate_source_state(
    workspace: Path, artifact: dict[str, Any], packet_path: Path
) -> str:
    verified = verify_context_packet(workspace, packet_path)
    if not verified.get("valid") or verified.get("packet_sha256") != artifact.get(
        "packet", {}
    ).get("packet_sha256"):
        return "STALE"
    try:
        packet = json.loads(_read_bounded(packet_path).decode("utf-8"))
        sources = _shard_source_rows(workspace, packet)
        locators = [
            item
            for claim in artifact.get("claims", [])
            if isinstance(claim, dict)
            for item in claim.get("locators", [])
        ]
        locators.extend(
            item
            for records in artifact.get("retained_records", {}).values()
            if isinstance(records, list)
            for item in records
        )
        if not all(_verify_shard_locator(workspace, item) for item in locators):
            return "STALE"
        if any(
            item.get("path") not in sources
            for item in locators
            if isinstance(item, dict)
        ):
            return "STALE"
        return "CANDIDATE"
    except (
        ContextEfficiencyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        AttributeError,
    ):
        return "STALE"


def _stored_shard_matches(workspace: Path, relative: str, body: dict[str, Any]) -> bool:
    try:
        path, _ = _shard_relative_path(workspace, relative, "shard artifact path")
        return _read_bounded(path, MAX_SHARD_ARTIFACT_BYTES) == _canonical(body) + b"\n"
    except (ContextEfficiencyError, OSError):
        return False


def _accepted_shard_conflict(
    workspace: Path,
    artifact: dict[str, Any],
    digest: str,
    claims: Any,
    accepted: Any,
    now: datetime | None,
) -> dict[str, str] | None:
    if not isinstance(accepted, (list, tuple)):
        return None
    current = {
        (str(item.get("key", "")).strip().casefold(), _canonical(item.get("value")))
        for item in claims
        if isinstance(item, dict)
    }
    for pair in accepted[:MAX_SHARD_RECORDS]:
        if not isinstance(pair, dict) or set(pair) != {"candidate", "review"}:
            continue
        other, review = pair["candidate"], pair["review"]
        if not _is_reviewed_accepted_shard(workspace, artifact, other, review, now):
            continue
        for old in other.get("claims", []):
            if not isinstance(old, dict):
                continue
            key, value = (
                str(old.get("key", "")).strip().casefold(),
                _canonical(old.get("value")),
            )
            if any(
                current_key == key and current_value != value
                for current_key, current_value in current
            ):
                return {
                    "candidate_sha256": digest,
                    "accepted_candidate_sha256": other.get("candidate_sha256"),
                    "key": key,
                    "basis": "same type and normalized key with different canonical values",
                }
    return None


def _is_reviewed_accepted_shard(
    workspace: Path,
    current: dict[str, Any],
    other: Any,
    review: Any,
    now: datetime | None,
) -> bool:
    if not isinstance(other, dict) or other.get("shard_type") != current.get(
        "shard_type"
    ):
        return False
    body = {key: value for key, value in other.items() if key != "artifact_path"}
    if other.get("candidate_sha256") != _shard_digest(body, "candidate_sha256"):
        return False
    if not isinstance(other.get("artifact_path"), str) or not _stored_shard_matches(
        workspace, other["artifact_path"], body
    ):
        return False
    try:
        if not validate_context_shard_candidate(workspace, other, now=now)["valid"]:
            return False
    except ContextEfficiencyError:
        return False
    if not isinstance(review, dict):
        return False
    review_body = {
        key: value for key, value in review.items() if key != "artifact_path"
    }
    return (
        review.get("schema") == SHARD_REVIEW_SCHEMA
        and review.get("decision") == "accept"
        and review.get("state") == "CALLER_REVIEWED_ACCEPTED"
        and review.get("reviewer_identity_authenticated") is False
        and review.get("candidate_sha256") == other.get("candidate_sha256")
        and review.get("review_sha256") == _shard_digest(review_body, "review_sha256")
        and isinstance(review.get("artifact_path"), str)
        and _stored_shard_matches(workspace, review["artifact_path"], review_body)
    )


def build_context_shard_candidate(
    root: Path,
    packet_path: Path,
    shard_type: str,
    claims: Any,
    retained_records: Any,
    expires_at: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Persist a source-bound candidate shard; this never accepts or activates it."""
    if shard_type not in {"rule", "fact", "code_map"}:
        raise ContextEfficiencyError(
            "E_SHARD_TYPE", "shard_type must be rule, fact, or code_map"
        )
    workspace = _validated_root(root)
    packet_path_value, packet_relative = _shard_relative_path(
        workspace,
        Path(packet_path).absolute().relative_to(workspace).as_posix()
        if Path(packet_path).is_absolute()
        else str(packet_path),
        "packet_path",
    )
    verified = verify_context_packet(workspace, packet_path_value)
    if not verified.get("valid"):
        raise ContextEfficiencyError(
            "E_SHARD_PACKET", "source packet failed verification"
        )
    packet = json.loads(_read_bounded(packet_path_value).decode("utf-8"))
    sources = _shard_source_rows(workspace, packet)
    normalized_claims = _normalize_shard_claims(workspace, claims, sources)
    retained = _normalize_shard_retention(workspace, retained_records, sources)
    current = _shard_now(now)
    expiry = _shard_datetime(expires_at, "expires_at")
    if not current < expiry <= current.replace(year=current.year + 1):
        raise ContextEfficiencyError(
            "E_SHARD_EXPIRY", "expiry must be within the next year"
        )
    artifact = {
        "schema": SHARD_CANDIDATE_SCHEMA,
        "state": "CANDIDATE",
        "review_status": "UNREVIEWED",
        "shard_type": shard_type,
        "packet": {"path": packet_relative, "packet_sha256": verified["packet_sha256"]},
        "claims": normalized_claims,
        "retained_records": retained,
        "retention_inventory_status": "CALLER_DECLARED",
        "expires_at": expiry.isoformat().replace("+00:00", "Z"),
        "provenance_boundary": "Hashes and locators bind caller-proposed content to local source bytes; they do not establish truth or completeness.",
    }
    artifact["candidate_sha256"] = _shard_digest(artifact, "candidate_sha256")
    artifact_path, relative = _shard_artifact_path(
        workspace, "candidates", artifact["candidate_sha256"]
    )
    _write_immutable_shard(artifact_path, artifact)
    return {**artifact, "artifact_path": relative}


def _load_shard_candidate(
    workspace: Path, candidate: Any
) -> tuple[dict[str, Any], str | None]:
    if isinstance(candidate, (str, Path)):
        path, relative = _shard_relative_path(
            workspace, str(candidate), "candidate path"
        )
        try:
            artifact = json.loads(
                _read_bounded(path, MAX_SHARD_ARTIFACT_BYTES).decode("utf-8")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ContextEfficiencyError(
                "E_SHARD_READ", "candidate artifact cannot be read"
            ) from exc
    elif isinstance(candidate, dict):
        artifact = {
            key: value for key, value in candidate.items() if key != "artifact_path"
        }
        relative = artifact.get("artifact_path")
    else:
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "candidate must be an artifact or relative path"
        )
    if not isinstance(artifact, dict):
        raise ContextEfficiencyError("E_SHARD_FIELDS", "candidate must be an object")
    return artifact, relative


def _validate_shard_claim_structure(claim: Any) -> None:
    if not isinstance(claim, dict) or set(claim) != {"key", "value", "locators"}:
        raise ContextEfficiencyError("E_SHARD_FIELDS", "candidate claim is invalid")
    _safe_text(claim["key"], "claim.key", 160)
    if (
        not isinstance(claim["value"], (str, int, float, bool, list, dict))
        or claim["value"] is None
    ):
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "candidate claim value is invalid"
        )
    _reject_secret_keys({"value": claim["value"]}, "candidate.claim")
    value_bytes = _canonical(claim["value"])
    if len(value_bytes) > MAX_SHARD_LOCATOR_BYTES or any(
        pattern.search(value_bytes) for pattern in _SECRET_BYTES
    ):
        raise ContextEfficiencyError(
            "E_SHARD_BOUNDARY", "candidate claim value exceeds limit"
        )
    if not isinstance(claim["locators"], list) or not claim["locators"]:
        raise ContextEfficiencyError(
            "E_SHARD_LOCATOR", "candidate claim requires locators"
        )


def _validate_shard_structure(artifact: dict[str, Any]) -> None:
    fields = {
        "schema",
        "state",
        "review_status",
        "shard_type",
        "packet",
        "claims",
        "retained_records",
        "retention_inventory_status",
        "expires_at",
        "provenance_boundary",
        "candidate_sha256",
    }
    if set(artifact) != fields or artifact.get("shard_type") not in {
        "rule",
        "fact",
        "code_map",
    }:
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "candidate has invalid fields or type"
        )
    if (
        artifact.get("review_status") != "UNREVIEWED"
        or artifact.get("retention_inventory_status") != "CALLER_DECLARED"
    ):
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "candidate review or retention state is invalid"
        )
    claims = artifact.get("claims")
    if not isinstance(claims, list) or not 1 <= len(claims) <= MAX_SHARD_CLAIMS:
        raise ContextEfficiencyError("E_SHARD_FIELDS", "candidate claims are invalid")
    for claim in claims:
        _validate_shard_claim_structure(claim)
    categories = {"correction", "failure", "approval", "unresolved_action"}
    retained = artifact.get("retained_records")
    if not isinstance(retained, dict) or set(retained) != categories:
        raise ContextEfficiencyError(
            "E_SHARD_RETENTION", "candidate retention categories are invalid"
        )
    if any(not isinstance(records, list) for records in retained.values()):
        raise ContextEfficiencyError(
            "E_SHARD_RETENTION", "candidate retained records are invalid"
        )
    if sum(len(records) for records in retained.values()) > MAX_SHARD_RECORDS:
        raise ContextEfficiencyError(
            "E_SHARD_BOUNDARY", "candidate retained records exceed limit"
        )


def _validated_shard_reference(
    workspace: Path, artifact: dict[str, Any]
) -> tuple[str, Path, str]:
    if (
        artifact.get("schema") != SHARD_CANDIDATE_SCHEMA
        or artifact.get("state") != "CANDIDATE"
    ):
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "candidate schema or state is invalid"
        )
    _validate_shard_structure(artifact)
    digest = artifact.get("candidate_sha256")
    if not isinstance(digest, str) or digest != _shard_digest(
        artifact, "candidate_sha256"
    ):
        raise ContextEfficiencyError("E_SHARD_DIGEST", "candidate digest is invalid")
    packet = artifact.get("packet")
    if not isinstance(packet, dict) or set(packet) != {"path", "packet_sha256"}:
        raise ContextEfficiencyError(
            "E_SHARD_FIELDS", "candidate packet reference is invalid"
        )
    path, relative = _shard_relative_path(workspace, packet["path"], "packet.path")
    return digest, path, relative


def validate_context_shard_candidate(
    root: Path,
    candidate: Any,
    *,
    accepted_shards: Any = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-read and validate candidate provenance, freshness, expiry and conflicts."""
    workspace = _validated_root(root)
    artifact, relative = _load_shard_candidate(workspace, candidate)
    digest, packet_path, packet_relative = _validated_shard_reference(
        workspace, artifact
    )
    state = _candidate_source_state(workspace, artifact, packet_path)
    if state != "STALE" and _shard_now(now) >= _shard_datetime(
        artifact.get("expires_at"), "expires_at"
    ):
        state = "EXPIRED"
    claims = artifact.get("claims", [])
    if not isinstance(claims, list) or len(claims) > MAX_SHARD_CLAIMS:
        state = "BLOCKED"
    elif not isinstance(accepted_shards, (list, tuple)):
        state = "BLOCKED"
    elif len(accepted_shards) > MAX_SHARD_RECORDS:
        state = "BLOCKED"
    contradiction = _accepted_shard_conflict(
        workspace, artifact, digest, claims, accepted_shards, now
    )
    if contradiction and state == "CANDIDATE":
        state = "CONTRADICTED"
    return {
        "schema": SHARD_CANDIDATE_SCHEMA,
        "state": state,
        "valid": state == "CANDIDATE",
        "candidate_sha256": digest,
        "artifact_path": relative,
        "packet_path": packet_relative,
        "claim_count": len(claims) if isinstance(claims, list) else None,
        "retention_inventory_status": artifact.get("retention_inventory_status"),
        "contradiction": contradiction,
        "review_status": artifact.get("review_status", "UNREVIEWED"),
        "claim_boundary": "Structural hash/provenance validation only; no memory activation, semantic truth, or completeness claim.",
    }


def review_context_shard_candidate(
    root: Path,
    candidate: dict[str, Any],
    decision: str,
    reviewer_id: str,
    review_basis: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Write a separate explicit caller-review event; reviewer identity is unauthenticated."""
    validation = validate_context_shard_candidate(root, candidate, now=now)
    if not validation["valid"]:
        raise ContextEfficiencyError(
            "E_SHARD_NOT_REVIEWABLE", f"candidate state is {validation['state']}"
        )
    if decision not in {"accept", "reject", "defer"}:
        raise ContextEfficiencyError(
            "E_SHARD_REVIEW", "decision must be accept, reject, or defer"
        )
    reviewer = _safe_text(reviewer_id, "reviewer_id", 160)
    basis = _safe_text(review_basis, "review_basis", 1000)
    artifact = {
        key: value for key, value in candidate.items() if key != "artifact_path"
    }
    event = {
        "schema": SHARD_REVIEW_SCHEMA,
        "state": "CALLER_REVIEWED_ACCEPTED"
        if decision == "accept"
        else "CALLER_REVIEWED_REJECTED"
        if decision == "reject"
        else "CALLER_REVIEWED_DEFERRED",
        "decision": decision,
        "candidate_sha256": artifact["candidate_sha256"],
        "reviewer_id": reviewer,
        "reviewer_identity_authenticated": False,
        "review_basis": basis,
        "reviewed_at": _shard_now(now).isoformat().replace("+00:00", "Z"),
        "activation": "NONE",
    }
    event["review_sha256"] = _shard_digest(event, "review_sha256")
    path, relative = _shard_artifact_path(root, "reviews", event["review_sha256"])
    _write_immutable_shard(path, event)
    return {**event, "artifact_path": relative}


def context_efficiency_status(root: Path) -> dict[str, Any]:
    """Fast bounded status projection over cached packets (no source reread)."""
    workspace = _validated_root(root)
    directory = _cache_dir(workspace)
    packet_stats = _collect_packet_status(workspace, directory)
    experiment, experiment_blocked = _load_latest_experiment(directory)
    invalid = packet_stats["invalid_count"] + int(experiment_blocked)
    state = "BLOCKED" if invalid else "READY" if packet_stats["rows"] else "MISSING"
    return _status_projection(
        packet_stats, experiment, experiment_blocked, state, invalid
    )


def _collect_packet_status(workspace: Path, directory: Path) -> dict[str, Any]:
    files = (
        sorted(
            path for path in directory.glob("*.json") if path.name != "experiment.json"
        )[:MAX_CACHE_FILES]
        if directory.is_dir()
        else []
    )
    rows: list[dict[str, Any]] = []
    invalid = 0
    cache_hits: int | None = 0
    estimated_tokens = 0
    selection_count = 0
    missing_selection_evidence = 0
    structural_file_count = 0
    evidence_roles: set[str] = set()
    for path in files:
        try:
            packet = json.loads(_read_bounded(path).decode("utf-8"))
            valid = (
                isinstance(packet, dict)
                and packet.get("schema") == PACKET_SCHEMA
                and packet.get("packet_sha256") == _packet_digest(packet)
            )
            if not valid:
                invalid += 1
                continue
            budget = packet.get("budget", {})
            estimated_tokens += int(budget.get("estimated_tokens", 0))
            packet_hits = _cache_hit_count(
                workspace, packet.get("cache", {}).get("key", "")
            )
            if packet_hits is None:
                cache_hits = None
            elif cache_hits is not None:
                cache_hits += packet_hits
            selection_count += int(isinstance(packet.get("selection"), dict))
            if isinstance(packet.get("selection"), dict):
                candidates = packet["selection"].get("candidates", [])
                structural_file_count += sum(
                    isinstance(row, dict)
                    and isinstance(row.get("structure"), dict)
                    and row["structure"].get("status") == "SYNTACTIC_ONLY"
                    for row in candidates
                )
                evidence_roles.update(
                    row.get("role", "")
                    for row in candidates
                    if isinstance(row, dict) and isinstance(row.get("role"), str)
                )
                missing_selection_evidence += len(
                    packet["selection"].get("missing_evidence_roles", [])
                )
            rows.append(
                {
                    "path": path.relative_to(workspace).as_posix(),
                    "packet_sha256": packet["packet_sha256"],
                    "state": "READY",
                    "estimated_tokens": budget.get("estimated_tokens", 0),
                    "source_count": len(packet.get("sources", [])),
                }
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError):
            invalid += 1
    return {
        "rows": rows,
        "invalid_count": invalid,
        "cache_hits": cache_hits,
        "estimated_tokens": estimated_tokens,
        "selection_count": selection_count,
        "missing_selection_evidence": missing_selection_evidence,
        "structural_file_count": structural_file_count,
        "evidence_role_count": len(evidence_roles),
    }


def _load_latest_experiment(directory: Path) -> tuple[dict[str, Any] | None, bool]:
    try:
        experiment_history = _read_experiment_history(directory / "experiment.json")
        return (experiment_history[-1] if experiment_history else None), False
    except ContextEfficiencyError:
        return None, True


def _status_projection(
    stats: dict[str, Any],
    experiment: dict[str, Any] | None,
    experiment_blocked: bool,
    state: str,
    invalid: int,
) -> dict[str, Any]:
    selection_count = stats["selection_count"]
    missing_roles = stats["missing_selection_evidence"]
    return {
        "schema": STATUS_SCHEMA,
        "state": state,
        "marker": "CONTEXT_EFFICIENCY_READ_ONLY",
        "packet_count": len(stats["rows"]),
        "invalid_count": invalid,
        "cache_hits": stats["cache_hits"],
        "cache_hits_semantics": "recorded_lower_bound",
        "cache_usage_completeness": "UNKNOWN",
        "estimated_tokens": stats["estimated_tokens"],
        "packets": stats["rows"],
        "source_selection_status": "CACHED_METADATA_UNVERIFIED"
        if selection_count
        else "MISSING",
        "source_evidence_status": "UNVERIFIED",
        "structural_evidence_status": "CACHED_METADATA_ONLY"
        if selection_count
        else "MISSING",
        "deep_evidence_file_count": stats["structural_file_count"],
        "evidence_role_count": stats["evidence_role_count"],
        "missing_evidence_role_count": missing_roles,
        "reusable_packet_count": None,
        "stale_packet_count": None,
        "missing_evidence_count": invalid + missing_roles + int(experiment is None),
        "experiment_status": "BLOCKED"
        if experiment_blocked
        else experiment.get("state", "MISSING_EVIDENCE")
        if experiment
        else "MISSING_EVIDENCE",
        "experiment_quality_status": "NONREGRESSED"
        if experiment and experiment.get("quality_nonregression") is True
        else "REGRESSED"
        if experiment
        else "UNKNOWN",
        "experiment_freshness": "UNVERIFIED" if experiment else "MISSING",
        "quality_nonregression": experiment.get("quality_nonregression")
        if experiment
        else None,
        "paired_sample_count": experiment.get("paired_sample_count", 0)
        if experiment
        else 0,
        "observed_latency_reduction": experiment.get("observed_latency_reduction")
        if experiment
        else None,
        "observed_cost_delta": experiment.get("observed_cost_delta")
        if experiment
        else None,
        "observed_cost_delta_unit": experiment.get("observed_cost_delta_unit")
        if experiment
        else None,
        "observed_token_delta": experiment.get("observed_token_delta")
        if experiment
        else None,
        "observed_token_delta_unit": experiment.get("observed_token_delta_unit")
        if experiment
        else None,
        "experiment_evidence_level": experiment.get("evidence_level")
        if experiment
        else None,
        "claim_boundary": "Bounded cache metadata only; estimated token counts are not provider usage or guaranteed savings, and no source is executed or approved.",
        "authority": {
            "execution": False,
            "approval": False,
            "repair": False,
            "publication": False,
            "credential": False,
        },
    }

"""Bounded content-addressed receipt indexing and retention planning."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from collections import OrderedDict
from functools import partial
from itertools import chain
from threading import RLock
from typing import Any, Iterable


SCHEMA = "factory.receipt-index.v1"
DEFAULT_HOT_DAYS = 30
DEFAULT_MAX_FILES = 2000
_INDEX_RELATIVE = Path(".factory") / "ops" / "receipt-index.json"
_PATH_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_PATH_CACHE_LOCK = RLock()
_PATH_CACHE_ROOTS = 16


def _sha_bytes(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 64), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _payload_digest(payload: dict[str, Any]) -> str:
    body = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _directory_snapshot(
    root: Path,
    *,
    max_directories: int = 20000,
    under_prefixes: tuple[str, ...] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Capture directory mtimes so cached receipt paths detect additions and removals."""
    workspace = Path(root).resolve()
    rows: list[dict[str, Any]] = []
    truncated = False
    relatives = under_prefixes or ("receipts", ".factory", "traces")
    for relative in relatives:
        base = workspace / relative
        directories = _watched_directories(workspace, base)
        for directory in directories:
            if directory.is_symlink():
                continue
            try:
                stat = directory.stat()
                name = directory.relative_to(workspace).as_posix()
            except OSError:
                continue
            rows.append({"path": name, "mtime_ns": int(stat.st_mtime_ns)})
            if len(rows) >= max_directories:
                truncated = True
                break
        if truncated:
            break
    rows.sort(key=lambda item: item["path"])
    return rows, truncated


def _watched_directories(workspace: Path, base: Path):
    if base.is_dir():
        return chain((base,), (item for item in base.rglob("*") if item.is_dir()))
    parent = base.parent
    while parent != workspace and not parent.is_dir():
        parent = parent.parent
    return (parent,)


def _candidate_file(path: Path, workspace: Path, exclusions: set[str], suffixes):
    if path.is_symlink() or not path.is_file():
        return False
    if path.suffix.lower() not in {".json", ".jsonl"}:
        return False
    if suffixes is not None and path.suffix.lower() not in suffixes:
        return False
    if path.name == "receipt-index.json":
        return False
    return path.relative_to(workspace).as_posix() not in exclusions


def _candidate_paths(
    root: Path,
    *,
    max_scan_files: int,
    exclude_paths: set[str] | None = None,
    under_prefixes: tuple[str, ...] | None = None,
    suffixes: set[str] | None = None,
) -> tuple[list[Path], bool]:
    workspace = Path(root).resolve()
    exclusions = exclude_paths or set()
    paths: list[Path] = []
    truncated = False
    directories = (
        [workspace / relative for relative in under_prefixes]
        if under_prefixes is not None
        else [workspace / "receipts", workspace / ".factory", workspace / "traces"]
    )
    for directory in directories:
        if directory.is_symlink():
            continue
        if directory.is_dir():
            for path in directory.rglob("*"):
                if _candidate_file(path, workspace, exclusions, suffixes):
                    paths.append(path)
                    if len(paths) >= max_scan_files:
                        truncated = True
                        return sorted(set(paths)), truncated
    return sorted(set(paths)), truncated


def _validate_index_limits(hot_days, max_files, max_scan_files):
    if isinstance(hot_days, bool) or not isinstance(hot_days, int) or hot_days < 0:
        raise ValueError("hot_days must be a non-negative integer")
    return _validate_path_limits(max_files, max_scan_files)


def _index_entries(workspace, paths, cutoff):
    entries: list[dict[str, Any]] = []
    duplicate_groups: dict[str, list[str]] = {}
    for path in paths:
        try:
            stat = path.stat()
            digest = _sha_bytes(path)
        except OSError:
            continue
        relative = path.relative_to(workspace).as_posix()
        modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        entries.append(
            {
                "path": relative,
                "bytes": int(stat.st_size),
                "mtime_ns": int(stat.st_mtime_ns),
                "sha256": digest,
                "modified_at": modified.isoformat(),
                "temperature": "hot" if modified >= cutoff else "cold",
            }
        )
        duplicate_groups.setdefault(digest, []).append(relative)
    entries.sort(
        key=lambda item: (
            item["temperature"] == "hot",
            item["modified_at"],
            item["path"],
        ),
        reverse=True,
    )
    duplicates = {
        key: value for key, value in duplicate_groups.items() if len(value) > 1
    }
    return entries, duplicates


def build_receipt_index(
    root: Path,
    *,
    hot_days: int = DEFAULT_HOT_DAYS,
    max_files: int = DEFAULT_MAX_FILES,
    max_scan_files: int | None = None,
    _exclude_paths: set[str] | None = None,
) -> dict[str, Any]:
    """Build an index and retention plan without deleting or moving evidence."""
    max_scan_files = _validate_index_limits(hot_days, max_files, max_scan_files)
    workspace = Path(root).resolve()
    cutoff = datetime.now(timezone.utc) - timedelta(days=hot_days)
    candidate_paths, scan_truncated = _candidate_paths(
        workspace,
        max_scan_files=max_scan_files,
        exclude_paths=_exclude_paths,
    )
    entries, duplicate_groups = _index_entries(workspace, candidate_paths, cutoff)
    over_limit = max(0, len(entries) - max_files)
    directories, directory_scan_truncated = _directory_snapshot(workspace)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root_bound": True,
        "policy": {
            "hot_days": hot_days,
            "max_files": max_files,
            "max_scan_files": max_scan_files,
            "action": "plan_only",
        },
        "counts": {
            "files": len(entries),
            "hot": sum(item["temperature"] == "hot" for item in entries),
            "cold": sum(item["temperature"] == "cold" for item in entries),
            "over_limit": over_limit,
            "duplicate_groups": len(duplicate_groups),
            "scan_truncated": scan_truncated,
            "directory_scan_truncated": directory_scan_truncated,
        },
        "duplicates": duplicate_groups,
        "retention_plan": {
            "archive_candidates": [item["path"] for item in entries[max_files:]],
            "dedupe_candidates": [paths[1:] for paths in duplicate_groups.values()],
            "mutation": False,
        },
        "entries": entries,
        "directory_snapshot": directories,
        "claim_boundary": "Index and retention plan only; evidence is never deleted or moved by this operation.",
    }


def write_receipt_index(
    root: Path,
    out: Path | None = None,
    *,
    hot_days: int = DEFAULT_HOT_DAYS,
    max_files: int = DEFAULT_MAX_FILES,
    max_scan_files: int | None = None,
) -> dict[str, Any]:
    """Write a deterministic, plan-only receipt index and return its hash-bound payload."""
    destination = (
        Path(out) if out is not None else Path(root).resolve() / _INDEX_RELATIVE
    )
    destination = (
        destination if destination.is_absolute() else Path(root).resolve() / destination
    )
    workspace = Path(root).resolve()
    destination = destination.resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(
            "receipt index output must remain inside the workspace"
        ) from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Create the directory entry before capturing directory mtimes; subsequent
    # in-place updates keep the snapshot valid while the index itself is excluded.
    if not destination.exists():
        destination.write_text("", encoding="utf-8")
    result = build_receipt_index(
        workspace,
        hot_days=hot_days,
        max_files=max_files,
        max_scan_files=max_scan_files,
        _exclude_paths={destination.relative_to(workspace).as_posix()},
    )
    result["index_sha256"] = _payload_digest(result)
    destination.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {**result, "path": destination.relative_to(Path(root).resolve()).as_posix()}


def _snapshot_matches(
    root: Path, payload: dict[str, Any], *, validate_file_metadata: bool = True
) -> bool:
    """Check indexed paths and directory state; optionally validate every file stat."""
    counts = payload.get("counts")
    entries = payload.get("entries")
    directories = payload.get("directory_snapshot")
    if (
        not isinstance(counts, dict)
        or counts.get("scan_truncated") is True
        or counts.get("directory_scan_truncated") is True
        or not isinstance(entries, list)
        or not isinstance(directories, list)
    ):
        return False
    workspace = Path(root).resolve()
    return all(_directory_row_matches(workspace, row) for row in directories) and all(
        _file_row_matches(workspace, row, validate_file_metadata) for row in entries
    )


def _safe_relative(raw):
    if not isinstance(raw, str):
        return None
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path


def _directory_row_matches(workspace, row):
    if not isinstance(row, dict) or set(row) != {"path", "mtime_ns"}:
        return False
    path = _safe_relative(row.get("path"))
    if path is None:
        return False
    candidate = workspace / path
    try:
        candidate.relative_to(workspace)
        return (
            candidate.is_dir() and int(candidate.stat().st_mtime_ns) == row["mtime_ns"]
        )
    except (OSError, TypeError, ValueError):
        return False


def _file_row_matches(workspace, row, validate_file_metadata):
    if not isinstance(row, dict):
        return False
    path = _safe_relative(row.get("path"))
    if path is None or path.name == "receipt-index.json":
        return False
    if not validate_file_metadata:
        return True
    candidate = (workspace / path).resolve()
    try:
        candidate.relative_to(workspace)
        stat = candidate.stat()
    except (OSError, ValueError):
        return False
    return (
        candidate.is_file()
        and int(stat.st_size) == row.get("bytes")
        and int(stat.st_mtime_ns) == row.get("mtime_ns")
    )


def _indexed_payload(
    root: Path, *, validate_file_metadata: bool = True
) -> dict[str, Any] | None:
    path = Path(root).resolve() / _INDEX_RELATIVE
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        return None
    supplied = value.get("index_sha256")
    core = {key: item for key, item in value.items() if key != "index_sha256"}
    if not isinstance(supplied, str) or supplied != _payload_digest(core):
        return None
    return (
        value
        if _snapshot_matches(
            Path(root), value, validate_file_metadata=validate_file_metadata
        )
        else None
    )


def _validate_path_limits(max_files: int, max_scan_files: int | None) -> int:
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files < 1:
        raise ValueError("max_files must be a positive integer")
    scan_limit = (
        max(max_files * 4, max_files) if max_scan_files is None else max_scan_files
    )
    if (
        isinstance(scan_limit, bool)
        or not isinstance(scan_limit, int)
        or scan_limit < max_files
    ):
        raise ValueError("max_scan_files must be an integer at least max_files")
    return scan_limit


def _normalize_suffix_filter(suffixes: set[str] | None) -> set[str] | None:
    if suffixes is None:
        return None
    valid = isinstance(suffixes, set) and all(
        isinstance(item, str) and item.startswith(".") and len(item) <= 16
        for item in suffixes
    )
    if not valid:
        raise ValueError("suffixes must be a set of dotted extensions")
    return {item.lower() for item in suffixes}


def _normalize_prefix_filter(workspace: Path, under) -> tuple[str, ...] | None:
    if under is None:
        return None
    raw_prefixes = [under] if isinstance(under, (Path, str)) else list(under)
    normalized = []
    for raw in raw_prefixes:
        raw_path = Path(raw)
        if raw_path.is_absolute() or ".." in raw_path.parts:
            raise ValueError("under must contain safe workspace-relative directories")
        prefix = (workspace / raw_path).resolve()
        try:
            prefix.relative_to(workspace)
        except ValueError as exc:
            raise ValueError("under must remain inside the workspace") from exc
        normalized.append(prefix.relative_to(workspace).as_posix().rstrip("/"))
    if not normalized:
        raise ValueError("under must not be empty")
    return tuple(normalized)


def _select_entries(entries, max_files, suffixes, prefixes):
    output = []
    for item in entries:
        relative = item.get("path")
        if not isinstance(relative, str):
            continue
        if suffixes is not None and Path(relative).suffix.lower() not in suffixes:
            continue
        if prefixes is not None and not any(
            relative.startswith(prefix + "/") for prefix in prefixes
        ):
            continue
        output.append(item)
    return output[:max_files]


def _cache_key(workspace, suffixes, prefixes):
    return "|".join(
        (
            str(workspace),
            ",".join(sorted(suffixes or set())),
            ",".join(prefixes or ()),
        )
    )


def _stat_entries(workspace, candidates):
    entries = []
    for candidate in candidates:
        try:
            stat = candidate.stat()
        except OSError:
            continue
        entries.append(
            {
                "path": candidate.relative_to(workspace).as_posix(),
                "bytes": int(stat.st_size),
                "mtime_ns": int(stat.st_mtime_ns),
            }
        )
    entries.sort(key=lambda item: (item["mtime_ns"], item["path"]), reverse=True)
    return entries


def _cache_receipt_paths(key, workspace, validate_file_metadata, select):
    with _PATH_CACHE_LOCK:
        cached = _PATH_CACHE.get(key)
        if cached is None or not _snapshot_matches(
            workspace, cached, validate_file_metadata=validate_file_metadata
        ):
            return None
        _PATH_CACHE.move_to_end(key)
        return [workspace / item["path"] for item in select(cached["entries"])]


def _store_path_snapshot(key, snapshot):
    if (
        snapshot["counts"]["scan_truncated"]
        or snapshot["counts"]["directory_scan_truncated"]
    ):
        return
    _PATH_CACHE[key] = snapshot
    _PATH_CACHE.move_to_end(key)
    while len(_PATH_CACHE) > _PATH_CACHE_ROOTS:
        _PATH_CACHE.popitem(last=False)


def _scan_receipt_paths(workspace, max_scan_files, suffixes, prefixes, key):
    with _PATH_CACHE_LOCK:
        candidates, truncated = _candidate_paths(
            workspace,
            max_scan_files=max_scan_files,
            under_prefixes=prefixes,
            suffixes=suffixes,
        )
        entries = _stat_entries(workspace, candidates)
        directories, directory_truncated = _directory_snapshot(
            workspace, under_prefixes=prefixes
        )
        snapshot = {
            "counts": {
                "scan_truncated": truncated,
                "directory_scan_truncated": directory_truncated,
            },
            "entries": entries,
            "directory_snapshot": directories,
        }
        _store_path_snapshot(key, snapshot)
        return entries


def indexed_receipt_paths(
    root: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_scan_files: int | None = None,
    suffixes: set[str] | None = None,
    under: Path | str | Iterable[Path | str] | None = None,
    validate_file_metadata: bool = True,
) -> list[Path]:
    """Return newest local receipt paths, reusing a validated index or stat cache.

    A stale or incomplete index is never trusted. The fallback scan is bounded;
    this helper does not write an index or alter evidence.

    ``validate_file_metadata=False`` is for full inventory consumers that read
    and content-hash every returned file and do not use index mtime ordering.
    It still validates path safety and directory membership, which detects
    additions/removals without statting every file.
    """
    workspace = Path(root).resolve()
    max_scan_files = _validate_path_limits(max_files, max_scan_files)
    normalized_suffixes = _normalize_suffix_filter(suffixes)
    relative_prefixes = _normalize_prefix_filter(workspace, under)
    if not isinstance(validate_file_metadata, bool):
        raise ValueError("validate_file_metadata must be a boolean")
    select = partial(
        _select_entries,
        max_files=max_files,
        suffixes=normalized_suffixes,
        prefixes=relative_prefixes,
    )
    indexed = _indexed_payload(workspace, validate_file_metadata=validate_file_metadata)
    if indexed is not None:
        return [workspace / item["path"] for item in select(indexed["entries"])]
    key = _cache_key(workspace, normalized_suffixes, relative_prefixes)
    cached = _cache_receipt_paths(key, workspace, validate_file_metadata, select)
    if cached is not None:
        return cached
    entries = _scan_receipt_paths(
        workspace, max_scan_files, normalized_suffixes, relative_prefixes, key
    )
    return [workspace / item["path"] for item in select(entries)]

"""Bounded content-addressed receipt indexing and retention planning."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA = "factory.receipt-index.v1"
DEFAULT_HOT_DAYS = 30
DEFAULT_MAX_FILES = 2000


def _sha_bytes(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 64), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_paths(root: Path, *, max_scan_files: int) -> tuple[list[Path], bool]:
    workspace = Path(root).resolve()
    paths: list[Path] = []
    truncated = False
    for directory in (workspace / "receipts", workspace / ".factory"):
        if directory.is_dir():
            for path in directory.rglob("*"):
                if path.is_file() and path.suffix.lower() in {".json", ".jsonl"}:
                    paths.append(path)
                    if len(paths) >= max_scan_files:
                        truncated = True
                        return sorted(set(paths)), truncated
    return sorted(set(paths)), truncated


def build_receipt_index(
    root: Path, *, hot_days: int = DEFAULT_HOT_DAYS, max_files: int = DEFAULT_MAX_FILES,
    max_scan_files: int | None = None,
) -> dict[str, Any]:
    """Build an index and retention plan without deleting or moving evidence."""
    if isinstance(hot_days, bool) or not isinstance(hot_days, int) or hot_days < 0:
        raise ValueError("hot_days must be a non-negative integer")
    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files < 1:
        raise ValueError("max_files must be a positive integer")
    if max_scan_files is None:
        max_scan_files = max(max_files * 4, max_files)
    if isinstance(max_scan_files, bool) or not isinstance(max_scan_files, int) or max_scan_files < max_files:
        raise ValueError("max_scan_files must be an integer at least max_files")
    workspace = Path(root).resolve()
    cutoff = datetime.now(timezone.utc) - timedelta(days=hot_days)
    entries: list[dict[str, Any]] = []
    duplicate_groups: dict[str, list[str]] = {}
    candidate_paths, scan_truncated = _candidate_paths(workspace, max_scan_files=max_scan_files)
    for path in candidate_paths:
        try:
            stat = path.stat()
            digest = _sha_bytes(path)
        except OSError:
            continue
        relative = path.relative_to(workspace).as_posix()
        modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        entry = {
            "path": relative,
            "bytes": int(stat.st_size),
            "sha256": digest,
            "modified_at": modified.isoformat(),
            "temperature": "hot" if modified >= cutoff else "cold",
        }
        entries.append(entry)
        duplicate_groups.setdefault(digest, []).append(relative)
    entries.sort(
        key=lambda item: (
            item["temperature"] == "hot",
            item["modified_at"],
            item["path"],
        ),
        reverse=True,
    )
    over_limit = max(0, len(entries) - max_files)
    duplicate_groups = {
        digest: paths for digest, paths in duplicate_groups.items() if len(paths) > 1
    }
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root_bound": True,
        "policy": {"hot_days": hot_days, "max_files": max_files, "max_scan_files": max_scan_files, "action": "plan_only"},
        "counts": {
            "files": len(entries),
            "hot": sum(item["temperature"] == "hot" for item in entries),
            "cold": sum(item["temperature"] == "cold" for item in entries),
            "over_limit": over_limit,
            "duplicate_groups": len(duplicate_groups),
            "scan_truncated": scan_truncated,
        },
        "duplicates": duplicate_groups,
        "retention_plan": {
            "archive_candidates": [item["path"] for item in entries[max_files:]],
            "dedupe_candidates": [paths[1:] for paths in duplicate_groups.values()],
            "mutation": False,
        },
        "entries": entries,
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
    result = build_receipt_index(root, hot_days=hot_days, max_files=max_files, max_scan_files=max_scan_files)
    destination = (
        Path(out)
        if out is not None
        else Path(root).resolve() / ".factory" / "ops" / "receipt-index.json"
    )
    destination = (
        destination if destination.is_absolute() else Path(root).resolve() / destination
    )
    workspace = Path(root).resolve()
    try:
        destination.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("receipt index output must remain inside the workspace") from exc
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {**result, "path": destination.relative_to(Path(root).resolve()).as_posix()}

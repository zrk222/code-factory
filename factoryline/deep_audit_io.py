"""Bounded local input primitives for non-authoritative deep analysis evidence."""

from __future__ import annotations

import json
import os
import subprocess
import stat
import uuid
import tempfile
import time
from collections import Counter
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote

from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    require_digest,
    require_str,
    sha256_bytes,
)

LIMIT = 10_000_000


def digest(value: object) -> str:
    """Fingerprint normalized JSON using the existing canonical receipt encoding without assigning any authority."""
    return sha256_bytes(canonical_bytes(value))


def relative_path(value: object) -> str:
    """Require a canonical workspace path, rejecting ambiguous URI, Windows and traversal spellings."""
    text = require_str(value, "path", maximum=512)
    parts = text.split("/")
    forbidden = ("\\", ":", "?", "#")
    if any(char in text for char in forbidden) or unquote(text) != text:
        raise RuntimeAuditError("E_PATH_ESCAPE", "noncanonical path")
    if any(
        ord(char) < 32
        or 0x7F <= ord(char) <= 0x9F
        or char
        in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200b\u200c\u200d\ufeff"
        for char in text
    ):
        raise RuntimeAuditError("E_PATH_ESCAPE", "control characters in path")
    if PureWindowsPath(text).drive or any(part in {"", ".", ".."} for part in parts):
        raise RuntimeAuditError("E_PATH_ESCAPE", "path must be workspace-relative")
    if any(
        part.endswith((" ", ".")) or PureWindowsPath(part).is_reserved()
        for part in parts
    ):
        raise RuntimeAuditError("E_PATH_ESCAPE", "ambiguous Windows path")
    return text


def local_file(root: Path, value: object) -> Path:
    """Resolve one regular workspace file while rejecting symlinks and Windows reparse points throughout."""
    root = Path(root).resolve()
    candidate = root
    for part in relative_path(value).split("/"):
        candidate = candidate / part
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise RuntimeAuditError(
                "E_SOURCE_MISSING", "regular file required"
            ) from exc
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError("E_PATH_ESCAPE", "linked evidence is not supported")
    candidate.resolve().relative_to(root)
    if not candidate.is_file():
        raise RuntimeAuditError("E_SOURCE_MISSING", "regular file required")
    return candidate


def bound_bytes(root: Path, binding: dict) -> bytes:
    """Read at most the evidence byte budget and verify its caller-supplied SHA-256 binding."""
    expected = require_digest(binding["sha256"], "sha256")
    path = local_file(root, binding["path"])
    with path.open("rb") as stream:
        before = path.stat()
        raw = stream.read(LIMIT + 1)
        after = path.stat()
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_REPORT_SIZE", "evidence exceeds byte budget")
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise RuntimeAuditError("E_INPUT_CHANGED", "evidence changed during read")
    if sha256_bytes(raw) != expected:
        raise RuntimeAuditError("E_REPORT_DRIFT", "evidence hash mismatch")
    return raw


def _object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeAuditError("E_DUPLICATE_FIELD", "duplicate JSON key")
        result[key] = value
    return result


def _finite(value: str) -> None:
    raise RuntimeAuditError("E_NONFINITE", "non-finite JSON number")


def strict_json(raw: bytes) -> dict:
    """Decode bounded JSON, rejecting duplicate fields, nonfinite values and excessive parser recursion."""
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_REPORT_SIZE", "JSON exceeds byte budget")
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_finite)
        canonical_bytes(value)  # Reject exponent overflow such as 1e999, too.
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, RuntimeAuditError):
            raise
        raise RuntimeAuditError("E_REPORT_JSON", "invalid bounded JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_REPORT_JSON", "object required")
    return value


# Execution inventory is a separate versioned contract; v1 signed intake keeps
# its original bounds and semantics.
INVENTORY_LIMIT = 50_000
SOURCE_LIMIT = 16 * 1024 * 1024
SNAPSHOT_LIMIT = 1024 * 1024 * 1024
LANGUAGES = {
    "python": ".py .pyi",
    "javascript": ".js .jsx .mjs .cjs",
    "typescript": ".ts .tsx .mts .cts",
    "java": ".java",
    "kotlin": ".kt .kts",
    "go": ".go",
    "rust": ".rs",
    "swift": ".swift",
    "c": ".c .h",
    "cpp": ".cpp .cc .cxx .hpp",
    "csharp": ".cs",
    "ruby": ".rb",
    "php": ".php",
    "shell": ".sh .bash .zsh",
    "powershell": ".ps1 .psm1 .psd1",
    "web": ".html .htm .vue .svelte .css .scss",
    "configuration": ".json .jsonc .yml .yaml .toml .ini .cfg .xml .gradle .tf .tfvars .properties",
    "dependency": ".lock .sum",
    "notebook": ".ipynb",
    "data": ".md .rst .txt .adoc .csv .tsv .png .jpg .jpeg .gif .ico .webp .pdf .woff .woff2 .ttf .mp4 .wav .mp3",
    "document-code": ".svg",
}


def _git_names(root: Path, tracked: bool, *, ignored: bool = False) -> set[str]:
    from .runtime_audit_process import run_bounded_command

    with tempfile.TemporaryDirectory(prefix="factory-inventory-") as scratch:
        output = Path(scratch) / "paths"
        argv = ["git", "-c", "core.fsmonitor=false", "ls-files", "-z"]
        argv += ["--cached"] if tracked else ["--others", "--exclude-standard"]
        if ignored:
            argv += ["--ignored"]
        facts = run_bounded_command(argv, root, 30, Path(scratch), stdout_path=output)
        if (
            facts["exit_code"] != 0
            or facts["output_limit_exceeded"]
            or not facts["cleanup_confirmed"]
        ):
            raise RuntimeAuditError(
                "E_INVENTORY_LIMIT", "Git inventory failed or exceeded bounds"
            )
        return set(output.read_bytes().decode("utf-8", errors="strict").split("\0")) - {
            ""
        }


def _git_paths(root: Path) -> list[str]:
    tracked, untracked = _git_names(root, True), _git_names(root, False)
    # Generated state is excluded only when untracked. Tracked files never vanish.
    generated = {name for name in untracked if name.startswith(".factory/deep-runs/")}
    return sorted(tracked | (untracked - generated))


def source_language(name: str, raw: bytes) -> str:
    """Classify inputs without treating unknown executable formats as covered."""
    suffix = Path(name).suffix.lower()
    base = Path(name).name.lower()
    if base in {"dockerfile", "makefile", "justfile", "procfile"}:
        return "configuration"
    if base in {
        "requirements.txt",
        "poetry.lock",
        "uv.lock",
        "package-lock.json",
        "yarn.lock",
        "go.sum",
        "cargo.lock",
    }:
        return "dependency"
    if raw.startswith(b"#!"):
        first = raw.split(b"\n", 1)[0].lower()
        for language, marker in (
            ("python", b"python"),
            ("javascript", b"node"),
            ("shell", b"sh"),
        ):
            if marker in first:
                return language
        return "unknown"
    for language, suffixes in LANGUAGES.items():
        if suffix in suffixes.split():
            return language
    if base in {
        "license",
        "notice",
        "authors",
        "codeowners",
        ".gitignore",
        ".gitattributes",
        ".dockerignore",
        ".editorconfig",
    }:
        return "data"
    return "unknown"


def _source_bytes(root: Path, name: str) -> tuple[bytes, int]:
    source = local_file(root, name)
    with source.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(SOURCE_LIMIT + 1)
        after = os.fstat(stream.fileno())
    current = local_file(root, name).stat()

    def identity(value):
        return value.st_ino, value.st_size, value.st_mtime_ns

    if identity(before) != identity(after) or identity(after) != identity(current):
        raise RuntimeAuditError("E_INPUT_CHANGED", "source changed during inventory")
    if len(raw) > SOURCE_LIMIT:
        raise RuntimeAuditError("E_SOURCE_SIZE", "source exceeds file byte budget")
    return raw, stat.S_IMODE(before.st_mode)


def inventory_candidate(root: Path, snapshot: Path | None = None) -> dict:
    """Account for tracked/dirty/untracked inputs; optionally copy a private snapshot."""
    root = Path(root).resolve()
    files, gaps, seen, total = [], [], set(), 0
    if snapshot is not None:
        snapshot = Path(snapshot).absolute()
        for component in (snapshot, *snapshot.parents):
            info = component.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400
            ):
                raise RuntimeAuditError(
                    "E_SNAPSHOT_PATH", "snapshot ancestors must not be linked"
                )
        if (
            snapshot.is_symlink()
            or getattr(snapshot.lstat(), "st_file_attributes", 0) & 0x400
            or any(snapshot.iterdir())
        ):
            raise RuntimeAuditError(
                "E_SNAPSHOT_PATH", "snapshot must be a fresh empty regular directory"
            )
        snapshot = snapshot.resolve()
        if snapshot == root or root in snapshot.parents:
            raise RuntimeAuditError(
                "E_SNAPSHOT_PATH", "snapshot must be outside the source tree"
            )
    ignored = []
    try:
        paths = _git_paths(root)
        ignored = sorted(
            name
            for name in _git_names(root, False, ignored=True)
            if not name.startswith(".factory/deep-runs/")
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, RuntimeAuditError):
        paths = []
        gaps.append(
            {
                "code": "GIT_INVENTORY_FAILED",
                "path": ".",
                "action": "Restore a readable Git worktree and rerun inventory.",
            }
        )
    for name in ignored:
        gaps.append(
            {
                "code": "IGNORED_INPUT_SCOPE",
                "path": name,
                "action": "Move non-product caches outside the audited checkout; include every build/runtime input as tracked or nonignored source.",
            }
        )
    candidates = paths
    if not candidates:
        gaps.append(
            {
                "code": "EMPTY_CANDIDATE",
                "path": ".",
                "action": "Include the product source before requesting a depth assessment.",
            }
        )
    if len(candidates) > INVENTORY_LIMIT:
        gaps.append(
            {
                "code": "INVENTORY_LIMIT",
                "path": ".",
                "action": "Partition the declared product into explicitly bound targets; inventory was truncated.",
            }
        )
    for name in candidates[:INVENTORY_LIMIT]:
        item = {"path": name, "sha256": None, "bytes": None, "language": "unknown"}
        try:
            relative_path(name)
            if name.startswith(".factory/deep-runs/"):
                raise RuntimeAuditError(
                    "E_RESERVED_SOURCE", "tracked source collides with audit state"
                )
            if name.casefold() in seen:
                raise RuntimeAuditError(
                    "E_CASE_COLLISION", "case-colliding source paths"
                )
            seen.add(name.casefold())
            if total >= SNAPSHOT_LIMIT:
                raise RuntimeAuditError(
                    "E_SNAPSHOT_SIZE", "snapshot total budget exhausted"
                )
            raw, mode = _source_bytes(root, name)
            total += len(raw)
            if total > SNAPSHOT_LIMIT:
                raise RuntimeAuditError(
                    "E_SNAPSHOT_SIZE", "snapshot exceeds total byte budget"
                )
            item.update(
                sha256=sha256_bytes(raw),
                bytes=len(raw),
                mode=mode,
                language=source_language(name, raw),
            )
            if snapshot is not None:
                target = Path(snapshot) / name
                current = snapshot
                for part in relative_path(name).split("/")[:-1]:
                    current /= part
                    current.mkdir(exist_ok=True)
                    info = current.lstat()
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & 0x400
                    ):
                        raise RuntimeAuditError(
                            "E_SNAPSHOT_PATH", "linked snapshot parent"
                        )
                with target.open("xb") as stream:
                    stream.write(raw)
                target.chmod(mode)
                if sha256_bytes(target.read_bytes()) != item["sha256"]:
                    raise RuntimeAuditError(
                        "E_SNAPSHOT_DRIFT", "snapshot copy differs from captured source"
                    )
            if item["language"] == "unknown":
                gaps.append(
                    {
                        "code": "UNCLASSIFIED_INPUT",
                        "path": name,
                        "action": "Assign and validate a supported analyzer for this input; do not silently exclude it.",
                    }
                )
        except (OSError, ValueError, RuntimeAuditError) as exc:
            gaps.append(
                {
                    "code": getattr(exc, "code", "SOURCE_UNREADABLE"),
                    "path": name,
                    "action": "Restore regular readable source inside the worktree, then rerun inventory.",
                }
            )
        files.append(item)
    try:
        if paths != _git_paths(root):
            gaps.append(
                {
                    "code": "INVENTORY_DRIFT",
                    "path": ".",
                    "action": "Retry against an immutable source snapshot.",
                }
            )
        if ignored != sorted(
            name
            for name in _git_names(root, False, ignored=True)
            if not name.startswith(".factory/deep-runs/")
        ):
            gaps.append(
                {
                    "code": "IGNORED_SCOPE_DRIFT",
                    "path": ".",
                    "action": "Retry against stable source and ignored-input scope.",
                }
            )
        for item in files:
            if item["sha256"] is not None:
                raw, mode = _source_bytes(root, item["path"])
                if sha256_bytes(raw) != item["sha256"] or mode != item.get("mode"):
                    gaps.append(
                        {
                            "code": "SOURCE_DRIFT",
                            "path": item["path"],
                            "action": "Stop concurrent edits and recapture the candidate.",
                        }
                    )
    except (OSError, subprocess.SubprocessError, UnicodeError, RuntimeAuditError):
        gaps.append(
            {
                "code": "INVENTORY_RECHECK_FAILED",
                "path": ".",
                "action": "Restore Git inventory access and rerun.",
            }
        )
    return {
        "schema": "factory.deep-inventory.v1",
        "state": "INCOMPLETE" if gaps else "COMPLETE",
        "candidate_sha256": digest(files),
        "files": files,
        "gaps": gaps,
        "discovered_paths": len(candidates),
        "accounted_paths": len(files),
        "languages": dict(sorted(Counter(item["language"] for item in files).items())),
        "ignored_paths": ignored,
        "scope": "tracked and nonignored untracked inputs; ignored paths are explicit gaps",
        "reserved_output_boundary": {
            "path": ".factory/deep-runs/",
            "reason": "Only untracked coordinator state is excluded; tracked collisions block and the snapshot never includes this directory.",
        },
        "authority": "none",
    }


def run_directory(root: Path, run_id: str, *, create: bool = False) -> Path:
    """Keep execution state within a regular, non-linked private directory."""
    if len(run_id) != 32 or any(char not in "0123456789abcdef" for char in run_id):
        raise RuntimeAuditError(
            "E_RUN_ID", "run ID must be 32 lowercase hex characters"
        )
    current = Path(root).resolve()
    for part in (".factory", "deep-runs", run_id):
        current /= part
        if create:
            current.mkdir(mode=0o700, exist_ok=True)
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeAuditError("E_RUN_PATH", "run state must not contain links")
    return current


def write_run_json(directory: Path, name: str, value: dict) -> None:
    """Atomically replace a local state artifact; hashes are integrity, not identity."""
    target = Path(directory) / relative_path(name)
    if "/" in name:
        raise RuntimeAuditError("E_RUN_PATH", "state name must be a basename")
    if target.exists() or target.is_symlink():
        local_file(directory, name)
    body = {**value, "sha256": digest(value)}
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(canonical_bytes(body))
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(5):
            try:
                os.replace(temporary, target)
                break
            except PermissionError:
                # Windows indexers may transiently hold the destination open.
                if os.name != "nt" or attempt == 4:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        temporary.unlink(missing_ok=True)


def read_run_json(directory: Path, name: str) -> dict:
    """Read bounded local run evidence and verify its integrity digest."""
    source = local_file(directory, name)
    with source.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    value = strict_json(raw)
    expected = value.pop("sha256", None)
    if expected != digest(value):
        raise RuntimeAuditError("E_RUN_INTEGRITY", "run state digest mismatch")
    return value

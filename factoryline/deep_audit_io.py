"""Bounded local input primitives for non-authoritative deep analysis evidence."""

from __future__ import annotations

import hashlib  # noqa: F401
import importlib
import json
import os
import platform
import re  # noqa: F401
import subprocess
import sys
import stat
import threading  # noqa: F401
import uuid
import tempfile
import time
import tokenize  # noqa: F401
from collections import Counter
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote

from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    exact_keys,  # noqa: F401
    require_digest,
    require_int,  # noqa: F401
    require_str,
    sha256_bytes,
)

LIMIT = 10_000_000
NATIVE_COVERAGE_LIMIT = 8 * 1024 * 1024
NATIVE_LEDGER_LIMIT = NATIVE_COVERAGE_LIMIT
NATIVE_SOURCE_MAP_LIMIT = NATIVE_COVERAGE_LIMIT
NATIVE_ACCOUNTING_LIMIT = NATIVE_COVERAGE_LIMIT


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
_GENERATED_FACTORY_PREFIXES = (
    ".factory/deep-runs/",
    ".factory/review-evidence/",
    ".factory/scopes/",
    ".factory/repair-approvals/",
    ".factory/repair-attempts/",
)


def _generated_factory_path(name: str) -> bool:
    return (
        name == ".factory/candidate.diff"
        or name.startswith(_GENERATED_FACTORY_PREFIXES)
        or re.fullmatch(r"\.factory/ops/lifecycle/[0-9a-f]{32}\.json", name) is not None
    )


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
    generated = {name for name in untracked if _generated_factory_path(name)}
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


def _prepare_snapshot(root: Path, snapshot: Path | None) -> Path | None:
    if snapshot is None:
        return None
    snapshot = Path(snapshot).absolute()
    for component in (snapshot, *snapshot.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
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
    return snapshot


def _candidate_paths(root: Path, gaps: list[dict]) -> tuple[list[str], list[str]]:
    try:
        paths = _git_paths(root)
        ignored = sorted(
            name
            for name in _git_names(root, False, ignored=True)
            if not _generated_factory_path(name)
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, RuntimeAuditError):
        paths, ignored = [], []
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
    if not paths:
        gaps.append(
            {
                "code": "EMPTY_CANDIDATE",
                "path": ".",
                "action": "Include the product source before requesting a depth assessment.",
            }
        )
    if len(paths) > INVENTORY_LIMIT:
        gaps.append(
            {
                "code": "INVENTORY_LIMIT",
                "path": ".",
                "action": "Partition the declared product into explicitly bound targets; inventory was truncated.",
            }
        )
    return paths, ignored


def _capture_inventory_source(
    root: Path, name: str, seen: set[str], total: list[int]
) -> tuple[dict, bytes, int]:
    relative_path(name)
    if _generated_factory_path(name):
        raise RuntimeAuditError(
            "E_RESERVED_SOURCE",
            "tracked source collides with generated FactoryLine state",
        )
    if name.casefold() in seen:
        raise RuntimeAuditError("E_CASE_COLLISION", "case-colliding source paths")
    seen.add(name.casefold())
    if total[0] >= SNAPSHOT_LIMIT:
        raise RuntimeAuditError("E_SNAPSHOT_SIZE", "snapshot total budget exhausted")
    raw, mode = _source_bytes(root, name)
    total[0] += len(raw)
    if total[0] > SNAPSHOT_LIMIT:
        raise RuntimeAuditError("E_SNAPSHOT_SIZE", "snapshot exceeds total byte budget")
    item = {
        "path": name,
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
        "mode": mode,
        "language": source_language(name, raw),
    }
    return item, raw, mode


def _copy_snapshot_file(
    snapshot: Path, name: str, raw: bytes, mode: int, expected_digest: str
) -> None:
    target = snapshot / name
    current = snapshot
    for part in relative_path(name).split("/")[:-1]:
        current /= part
        current.mkdir(exist_ok=True)
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeAuditError("E_SNAPSHOT_PATH", "linked snapshot parent")
    with target.open("xb") as stream:
        stream.write(raw)
    target.chmod(mode)
    if sha256_bytes(target.read_bytes()) != expected_digest:
        raise RuntimeAuditError(
            "E_SNAPSHOT_DRIFT", "snapshot copy differs from captured source"
        )


def _inventory_candidate_file(
    root: Path,
    name: str,
    seen: set[str],
    total: list[int],
    snapshot: Path | None,
    gaps: list[dict],
) -> dict:
    item = {"path": name, "sha256": None, "bytes": None, "language": "unknown"}
    try:
        captured, raw, mode = _capture_inventory_source(root, name, seen, total)
        item.update(captured)
        if snapshot is not None:
            _copy_snapshot_file(snapshot, name, raw, mode, item["sha256"])
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
    return item


def _ignored_names(root: Path) -> list[str]:
    return sorted(
        name
        for name in _git_names(root, False, ignored=True)
        if not _generated_factory_path(name)
    )


def _verify_source_files(root: Path, files: list[dict], gaps: list[dict]) -> None:
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


def _verify_inventory_stability(
    root: Path,
    paths: list[str],
    ignored: list[str],
    files: list[dict],
    gaps: list[dict],
) -> None:
    try:
        if paths != _git_paths(root):
            gaps.append(
                {
                    "code": "INVENTORY_DRIFT",
                    "path": ".",
                    "action": "Retry against an immutable source snapshot.",
                }
            )
        if ignored != _ignored_names(root):
            gaps.append(
                {
                    "code": "IGNORED_SCOPE_DRIFT",
                    "path": ".",
                    "action": "Retry against stable source and ignored-input scope.",
                }
            )
        _verify_source_files(root, files, gaps)
    except (OSError, subprocess.SubprocessError, UnicodeError, RuntimeAuditError):
        gaps.append(
            {
                "code": "INVENTORY_RECHECK_FAILED",
                "path": ".",
                "action": "Restore Git inventory access and rerun.",
            }
        )


def _inventory_result(
    paths: list[str], files: list[dict], gaps: list[dict], ignored: list[str]
) -> dict:
    return {
        "schema": "factory.deep-inventory.v1",
        "state": "INCOMPLETE" if gaps else "COMPLETE",
        "candidate_sha256": digest(files),
        "files": files,
        "gaps": gaps,
        "discovered_paths": len(paths),
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


def inventory_candidate(root: Path, snapshot: Path | None = None) -> dict:
    """Account for tracked/dirty/untracked inputs; optionally copy a private snapshot."""
    root = Path(root).resolve()
    snapshot = _prepare_snapshot(root, snapshot)
    files, gaps, seen, total = [], [], set(), [0]
    paths, ignored = _candidate_paths(root, gaps)
    for name in paths[:INVENTORY_LIMIT]:
        files.append(_inventory_candidate_file(root, name, seen, total, snapshot, gaps))
    _verify_inventory_stability(root, paths, ignored, files, gaps)
    return _inventory_result(paths, files, gaps, ignored)


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


FULL_REPOSITORY_SCAN_SCHEMA = "factory.full-repository-scan.v1"
FULL_REPOSITORY_CHECKPOINT_SCHEMA = "factory.full-repository-scan-checkpoint.v1"
FULL_REPOSITORY_BATCH_LIMIT = 460
FULL_REPOSITORY_CONTEXT_PROFILE = "workspace-v2"
FULL_REPOSITORY_CONTEXT_SCHEMA = "factory.full-repository-context.v2"
FULL_REPOSITORY_CONTEXT_SCAN_SCHEMA = "factory.full-repository-scan.workspace-v2"
FULL_REPOSITORY_CONTEXT_CHECKPOINT_SCHEMA = (
    "factory.full-repository-checkpoint.workspace-v2"
)
FULL_REPOSITORY_CONTEXT_RUN_ID = "f2110000000000000000000000000002"
FULL_REPOSITORY_CONTEXT_DEADLINE_SECONDS = 180
_FULL_REPOSITORY_RUN_ID = "f2110000000000000000000000000001"
_FULL_REPOSITORY_GLOBAL_CONSUMER_CLOSURE_VERIFIED = False
_FULL_REPOSITORY_TRUSTED_CHECKPOINT: tuple[str, str, str] | None = None
_FULL_REPOSITORY_SCANNER_HELPER_EPOCH = 1


def _full_repository_scanner_identity() -> str:
    """Bind results to the installed native package, helper epoch and runtime."""
    from . import review_audits

    package = Path(review_audits.__file__).parent
    parts = []
    for source in sorted(package.rglob("*")):
        if "__pycache__" in source.parts:
            continue
        try:
            linked = (
                source.is_symlink()
                or getattr(source.lstat(), "st_file_attributes", 0) & 0x400
            )
        except OSError as exc:
            raise RuntimeAuditError(
                "SCANNER_DRIFT", "scanner package entry is unreadable"
            ) from exc
        if linked:
            raise RuntimeAuditError(
                "SCANNER_DRIFT", "scanner package contains a linked file"
            )
        if not source.is_file():
            continue
        parts.append(_full_repository_scanner_file_identity(package, source))
    return digest(
        {
            "package_files": parts,
            "runtime": {
                "implementation": platform.python_implementation(),
                "version": platform.python_version(),
                "dependencies": _full_repository_runtime_dependencies(),
            },
            "helper_epoch": _FULL_REPOSITORY_SCANNER_HELPER_EPOCH,
        }
    )


def _full_repository_scanner_file_identity(package: Path, source: Path) -> dict:
    try:
        with source.open("rb") as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(LIMIT + 1)
            after = os.fstat(stream.fileno())
        current = source.stat()
    except OSError as exc:
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "scanner package file is unreadable"
        ) from exc
    if not (
        _full_repository_stat_identity(before)
        == _full_repository_stat_identity(after)
        == _full_repository_stat_identity(current)
        and len(raw) == current.st_size
    ):
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "scanner package changed during identity read"
        )
    if len(raw) > LIMIT:
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "scanner package file exceeds identity limit"
        )
    return {
        "path": source.relative_to(package).as_posix(),
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
    }


def _full_repository_runtime_dependencies() -> dict[str, str | None]:
    from importlib.metadata import PackageNotFoundError, version

    packages = ("cryptography", "httpx", "PyYAML", "sqlglot", "pytest")
    versions = {}
    for package in packages:
        try:
            versions[package] = version(package)
        except PackageNotFoundError:
            versions[package] = None
    return versions


def _full_repository_configuration(root: Path, audit) -> tuple[set[str], dict]:
    """Bind presence and exact bytes of every native pytest config candidate."""
    patterns, collection = audit._pytest_collection_config(root)
    candidates = (
        "pytest.toml",
        ".pytest.toml",
        "pytest.ini",
        ".pytest.ini",
        "pyproject.toml",
        "tox.ini",
        "setup.cfg",
    )
    bindings = [
        _full_repository_configuration_binding(root, name) for name in candidates
    ]
    return set(patterns), {"selected": collection, "candidates": bindings}


def _full_repository_profile_configuration(root: Path, audit, context_profile):
    try:
        patterns, frame = _full_repository_configuration(root, audit)
        return patterns, frame, False
    except audit.ReviewAuditError:
        if context_profile != FULL_REPOSITORY_CONTEXT_PROFILE:
            raise
        candidates = (
            "pytest.toml",
            ".pytest.toml",
            "pytest.ini",
            ".pytest.ini",
            "pyproject.toml",
            "tox.ini",
            "setup.cfg",
        )
        return (
            set(audit._TEST_FILE_PATTERNS),
            {
                "selected": {"path": None, "state": "unsupported"},
                "candidates": [
                    _full_repository_configuration_binding(root, name)
                    for name in candidates
                ],
            },
            True,
        )


def _full_repository_configuration_binding(root: Path, name: str) -> dict:
    """Bind exact candidate bytes without following links or accepting read drift."""
    try:
        path = local_file(root, name)
    except RuntimeAuditError as exc:
        if exc.code == "E_SOURCE_MISSING":
            return {"path": name, "state": "absent"}
        try:
            info = (root / name).lstat()
            raw = (
                os.readlink(root / name).encode("utf-8", errors="surrogatepass")
                if stat.S_ISLNK(info.st_mode)
                else b""
            )
        except OSError:
            info, raw = None, b""
        return {
            "path": name,
            "state": "unreadable",
            "sha256": sha256_bytes(raw),
            "bytes": info.st_size if info else None,
        }
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    current = local_file(root, name).stat()
    if not (
        _full_repository_stat_identity(before)
        == _full_repository_stat_identity(after)
        == _full_repository_stat_identity(current)
        and len(raw) == current.st_size
    ):
        raise RuntimeAuditError(
            "SOURCE_DRIFT", f"configuration changed during identity read: {name}"
        )
    if len(raw) > LIMIT:
        raise RuntimeAuditError(
            "E_CONFIG_SIZE", f"configuration identity exceeds {LIMIT} bytes: {name}"
        )
    return {
        "path": name,
        "state": "read",
        "sha256": sha256_bytes(raw),
        "bytes": len(raw),
    }


def _full_repository_stat_identity(info) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _full_repository_runtime_epoch(root: Path, configuration: str, audit) -> str:
    """Bind only the in-process cache shortcut to live native helper objects."""
    from .context_efficiency import _scan_security_source

    helpers = (
        _scan_security_source,
        audit._security_source_files,
        audit._security_source_bytes,
        audit._security_scan_tree,
        audit._pytest_collection_config,
        audit._oracle_import_source,
        audit.contracts.bound_snapshots,
        audit._oracle_tree_fingerprint,
    )
    # Owned profile helpers retain their live binding in the resume-cache identity.
    from . import runtime_audit_integrity as workspace_engine

    full_repository_workspace_scan_batch = (
        workspace_engine.full_repository_workspace_scan_batch
    )

    profile_helpers = (
        tuple(
            helper
            for name, helper in sorted(globals().items())
            if name.startswith("_full_repository_") and callable(helper)
        )
        + tuple(
            helper
            for name, helper in sorted(vars(workspace_engine).items())
            if name.startswith("_full_repository_workspace_") and callable(helper)
        )
        + (
            full_repository_workspace_scan_batch,
            _validate_full_repository_checkpoint,
            full_repository_scan,
            run_directory,
            read_run_json,
            write_run_json,
            local_file,
            digest,
            canonical_bytes,
        )
    )
    return digest(
        {
            "native_cache_epoch": audit._oracle_context_cache_key(
                root, [], {"configuration_sha256": configuration}
            ),
            "full_profile_helpers": [
                (id(helper), id(getattr(helper, "__code__", None)))
                for helper in helpers
            ],
            "profile_helpers": [
                (id(helper), id(getattr(helper, "__code__", None)))
                for helper in profile_helpers
            ],
        }
    )


def _full_repository_inventory(root: Path, files: list[Path]) -> list[dict]:
    return [_full_repository_inventory_row(root, path) for path in files]


def _full_repository_inventory_row(root: Path, path: Path) -> dict:
    """Account for one path without following links or hiding concurrent edits."""
    name = path.relative_to(root).as_posix()
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raw = os.readlink(path).encode("utf-8", errors="surrogatepass")
            return {
                "path": name,
                "state": "unreadable",
                "sha256": sha256_bytes(raw),
                "bytes": info.st_size,
            }
        return _full_repository_regular_inventory_row(root, name)
    except RuntimeAuditError as exc:
        if exc.code == "E_INPUT_CHANGED":
            raise RuntimeAuditError(
                "SOURCE_DRIFT", "source changed during inventory"
            ) from exc
        return _full_repository_unreadable_row(path, name)
    except (OSError, ValueError):
        return _full_repository_unreadable_row(path, name)


def _full_repository_regular_inventory_row(root: Path, name: str) -> dict:
    """Hash one bounded-memory regular source and compare its open-file identity."""
    source = local_file(root, name)
    hasher, size = hashlib.sha256(), 0
    with source.open("rb") as stream:
        before = os.fstat(stream.fileno())
        while chunk := stream.read(64 * 1024):
            hasher.update(chunk)
            size += len(chunk)
        after = os.fstat(stream.fileno())
    current = local_file(root, name).stat()

    def identity(item):
        return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns

    if (
        identity(before) != identity(after)
        or identity(after) != identity(current)
        or size != current.st_size
    ):
        raise RuntimeAuditError("E_INPUT_CHANGED", "source changed during inventory")
    return {
        "path": name,
        "state": "oversized" if size > 1_000_000 else "ready",
        "sha256": hasher.hexdigest(),
        "bytes": size,
    }


def _full_repository_unreadable_row(path: Path, name: str) -> dict:
    try:
        size = path.lstat().st_size
    except OSError:
        size = None
    return {"path": name, "state": "unreadable", "sha256": None, "bytes": size}


def _full_repository_primary(
    root: Path,
    path: Path,
    source: dict,
    patterns: set[str],
    audit,
    eligible: dict[Path, Path],
    scan_result=None,
) -> dict:
    binding, findings, status, tree = scan_result or _full_repository_native_scan(
        root, path, source, patterns, audit
    )
    if (
        source["state"] == "ready"
        and status in {"audited", "syntax_error"}
        and (binding is None or binding.get("sha256") != source["sha256"])
    ):
        raise RuntimeAuditError("SOURCE_DRIFT", "source bytes changed after inventory")
    dependencies = _full_repository_dependency_summary(
        root, path, tree, status, audit, eligible
    )
    return {
        "path": source["path"],
        "input_sha256": source["sha256"],
        "input_state": source["state"],
        "bytes": binding["bytes"] if binding else source["bytes"],
        "status": status,
        "findings": findings,
        "dependencies": dependencies,
    }


def _full_repository_native_scan(
    root: Path, path: Path, source: dict, patterns: set[str], audit
):
    """Invoke the native single-source engine with no partial-workspace context."""
    from .context_efficiency import _scan_security_source

    tree = None
    try:
        data = audit._security_source_bytes(root, source["path"])
        if len(data) <= audit.MAX_BYTES:
            try:
                tree = audit._measure_parse(audit.ast.parse, data, root, path)
            except (SyntaxError, UnicodeError, RecursionError):
                pass
        fingerprint = audit._oracle_tree_fingerprint(tree) if tree is not None else None
        binding, findings, status = _scan_security_source(
            root, path, (), {}, None, patterns, data, tree, fingerprint
        )
    except (OSError, UnicodeError, ValueError, RuntimeAuditError):
        binding, findings, status = _scan_security_source(
            root, path, (), {}, None, patterns, None
        )
    except RecursionError:
        binding, findings, status = None, [], "unsupported"
    return binding, findings, status, tree


def _full_repository_dependency_summary(
    root: Path, path: Path, tree, status, audit, eligible
):
    empty = {"state": "unavailable", "edges": [], "unresolved_relative_imports": []}
    if status != "audited" or tree is None:
        return empty
    edges, unresolved = [], []
    try:
        for node in audit.ast.walk(tree):
            if isinstance(node, (audit.ast.Import, audit.ast.ImportFrom)):
                for imported in node.names:
                    edge, unresolved_row = _full_repository_import_edge(
                        root, path, node, imported, audit, eligible
                    )
                    if edge:
                        edges.append(edge)
                    if unresolved_row:
                        unresolved.append(unresolved_row)
        return {
            "state": "lexical",
            "edges": sorted(
                edges, key=lambda row: (row["line"], row["target"], row["name"])
            ),
            "unresolved_relative_imports": sorted(
                unresolved, key=lambda row: (row["line"], row["module"], row["name"])
            ),
        }
    except (OSError, ValueError, RecursionError):
        return {**empty, "state": "incomplete"}


def _full_repository_import_edge(
    root: Path, path: Path, node, imported, audit, eligible
):
    is_from = isinstance(node, audit.ast.ImportFrom)
    module = (node.module or "") if is_from else imported.name
    target = audit._oracle_import_source(
        root, path, node, module, eligible, imported.name if is_from else None
    )
    if target is not None:
        return {
            "line": node.lineno,
            "module": module,
            "name": imported.name,
            "target": target.relative_to(root).as_posix(),
        }, None
    if is_from and node.level:
        return None, {
            "line": node.lineno,
            "module": module,
            "name": imported.name,
            "level": node.level,
        }
    return None, None


def _validate_full_repository_checkpoint(
    value: dict,
    root: Path,
    scanner: str,
    configuration: str,
    inventory: list[dict],
    context_profile: str = "isolated-v1",
) -> list[dict]:
    """Validate generation identity and the exact saved primary prefix."""
    _full_repository_checkpoint_identity(
        value, root, scanner, configuration, inventory, context_profile
    )
    results = _full_repository_checkpoint_rows(value, inventory)
    if not all(_full_repository_result_valid(row) for row in results):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint primary result is malformed"
        )
    return results


def _full_repository_checkpoint_identity(
    value, root, scanner, configuration, inventory, context_profile="isolated-v1"
):
    """Reject altered profile, schema, scanner or source-generation bindings."""
    workspace = context_profile == FULL_REPOSITORY_CONTEXT_PROFILE
    keys = {
        "schema",
        "root",
        "scanner_identity_sha256",
        "configuration_sha256",
        "inventory_sha256",
        "inventory",
        "batch_primary_limit",
        "primary_results",
        "result_digest",
    }
    if workspace:
        keys.update({"context_profile", "context_generation_sha256"})
    expected_schema = (
        FULL_REPOSITORY_CONTEXT_CHECKPOINT_SCHEMA
        if workspace
        else FULL_REPOSITORY_CHECKPOINT_SCHEMA
    )
    if (
        set(value) != keys
        or value["schema"] != expected_schema
        or (workspace and value["context_profile"] != context_profile)
        or (
            workspace
            and (
                not isinstance(value["context_generation_sha256"], str)
                or len(value["context_generation_sha256"]) != 64
            )
        )
        or value["batch_primary_limit"] != FULL_REPOSITORY_BATCH_LIMIT
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint fields or schema differ"
        )
    if value["scanner_identity_sha256"] != scanner:
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "scanner identity changed since checkpoint"
        )
    if (
        value["root"] != root.as_posix()
        or value["configuration_sha256"] != configuration
        or value["inventory_sha256"] != digest(inventory)
        or value["inventory"] != inventory
    ):
        raise RuntimeAuditError(
            "SOURCE_DRIFT", "source inventory or configuration changed since checkpoint"
        )


def _full_repository_checkpoint_rows(value, inventory):
    """Require an ordered, duplicate-free prefix with an intact result digest."""
    results = value["primary_results"]
    if (
        not isinstance(results, list)
        or len(results) > len(inventory)
        or value["result_digest"] != digest(results)
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint result digest or list is malformed"
        )
    paths = [row["path"] for row in inventory]
    if (
        paths != sorted(paths)
        or [row.get("path") for row in results if isinstance(row, dict)]
        != paths[: len(results)]
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint primary partition differs from inventory"
        )
    if len({row.get("path") for row in results if isinstance(row, dict)}) != len(
        results
    ):
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "duplicate checkpoint primary path"
        )
    return results


def _full_repository_result_valid(row):
    """Check the saved result shape before any native revalidation or reuse."""
    return (
        isinstance(row, dict)
        and set(row)
        == {
            "path",
            "input_sha256",
            "input_state",
            "bytes",
            "status",
            "findings",
            "dependencies",
        }
        and row["status"]
        in {"audited", "syntax_error", "unreadable", "too_large", "unsupported"}
        and isinstance(row["findings"], list)
        and isinstance(row["dependencies"], dict)
    )


def _full_repository_discovery_policy(audit) -> dict:
    constants = audit._security_source_files.__code__.co_consts
    ignored = next((item for item in constants if isinstance(item, frozenset)), None)
    pattern = next((item for item in constants if item == "*.py"), None)
    if ignored is None or pattern is None:
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "native source discovery policy is not inspectable"
        )
    return {
        "engine": "native _security_source_files",
        "include_pattern": pattern,
        "include": "all discovered Python paths, including untracked files",
        "ignored_directory_names": sorted(ignored),
        "symlink_python_paths": "accounted as unreadable; never followed",
    }


def _full_repository_scan_digest(
    generation, inventory, results, accounting, coverage, dependencies, counts, pending
):
    payload = {
        "schema": generation["report_schema"],
        "inventory": inventory,
        "inventory_sha256": generation["inventory_hash"],
        "configuration_sha256": generation["configuration"],
        "scanner_identity_sha256": generation["scanner"],
        "discovery": generation["discovery"],
        "batch_primary_limit": FULL_REPOSITORY_BATCH_LIMIT,
        "source_accounting_state": accounting,
        "primary_results_sha256": digest(results),
        "coverage": coverage,
        "status_counts": counts,
        "pending_paths": pending,
        "dependency_index": dependencies,
        "semantic_coverage": "INCOMPLETE",
        "global_consumer_closure_verified": _FULL_REPOSITORY_GLOBAL_CONSUMER_CLOSURE_VERIFIED,
        "target_execution": False,
        "target_source_writes": False,
        "dependency_installation": False,
        "release_approved": False,
        "native_completion_receipt": False,
    }
    if generation["context_profile"] == FULL_REPOSITORY_CONTEXT_PROFILE:
        evidence = generation.get("workspace_evidence", {})
        evidence = {
            key: value for key, value in evidence.items() if key != "primary_processing"
        }
        payload.update(
            {
                "context_profile": generation["context_profile"],
                "context_profile_schema": generation["context_profile_schema"],
                "context_generation_sha256": generation.get(
                    "context_generation_sha256"
                ),
                "primary_results_authority": "RAW_UNVERIFIED_SOURCE_ANALYSIS",
                "workspace_evidence_sha256": digest(evidence),
            }
        )
    return digest(payload)


def _full_repository_generation(
    root: Path, audit, context_profile="isolated-v1"
) -> dict:
    root = Path(root).resolve()
    files = audit._security_source_files(root)
    inventory = _full_repository_inventory(root, files)
    patterns, frame, collection_incomplete = _full_repository_profile_configuration(
        root, audit, context_profile
    )
    config_identity = {
        "patterns": sorted(patterns),
        "frame": frame,
        "tenant_reads": [],
        "oracle_context": None,
    }
    if context_profile == FULL_REPOSITORY_CONTEXT_PROFILE:
        config_identity["context_profile"] = FULL_REPOSITORY_CONTEXT_PROFILE
        config_identity["context_profile_schema"] = FULL_REPOSITORY_CONTEXT_SCHEMA
    elif context_profile != "isolated-v1":
        raise RuntimeAuditError(
            "E_CONTEXT_PROFILE", "unsupported full-repository context profile"
        )
    configuration = digest(config_identity)
    scanner, inventory_hash = _full_repository_scanner_identity(), digest(inventory)
    runtime_epoch = _full_repository_runtime_epoch(root, configuration, audit)
    discovery = _full_repository_discovery_policy(audit)
    workspace = context_profile == FULL_REPOSITORY_CONTEXT_PROFILE
    context_profile_schema = FULL_REPOSITORY_CONTEXT_SCHEMA if workspace else None
    report_schema = (
        FULL_REPOSITORY_CONTEXT_SCAN_SCHEMA
        if workspace
        else FULL_REPOSITORY_SCAN_SCHEMA
    )
    checkpoint_schema = (
        FULL_REPOSITORY_CONTEXT_CHECKPOINT_SCHEMA
        if workspace
        else FULL_REPOSITORY_CHECKPOINT_SCHEMA
    )
    run_id = FULL_REPOSITORY_CONTEXT_RUN_ID if workspace else _FULL_REPOSITORY_RUN_ID
    directory = run_directory(root, run_id, create=True)
    return {**locals(), "collection_incomplete": collection_incomplete}


def _full_repository_start_generation(generation: dict) -> list[dict]:
    checkpoint_path = generation["directory"] / "checkpoint.json"
    if checkpoint_path.exists() or checkpoint_path.is_symlink():
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "checkpoint exists; resume it explicitly"
        )
    return []


def _full_repository_resume_generation(generation: dict, audit):
    root = generation["root"]
    try:
        checkpoint = read_run_json(generation["directory"], "checkpoint.json")
        results = _validate_full_repository_checkpoint(
            checkpoint,
            root,
            generation["scanner"],
            generation["configuration"],
            generation["inventory"],
            generation["context_profile"],
        )
    except RuntimeAuditError as exc:
        if exc.code in {"SCANNER_DRIFT", "SOURCE_DRIFT", "INVALID_CHECKPOINT"}:
            raise
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "resume checkpoint failed integrity validation"
        ) from exc
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        raise RuntimeAuditError(
            "INVALID_CHECKPOINT", "resume checkpoint cannot be read"
        ) from exc
    if generation["context_profile"] == FULL_REPOSITORY_CONTEXT_PROFILE:
        generation["saved_context_generation_sha256"] = checkpoint[
            "context_generation_sha256"
        ]
        generation["saved_result_digest"] = checkpoint["result_digest"]
        cache_hit = _full_repository_checkpoint_cache_hit(generation, checkpoint)
        if cache_hit:
            generation["workspace_prefix_cache_key"] = (
                generation["root"].as_posix(),
                digest(checkpoint),
                generation["runtime_epoch"],
            )
            return results, 0, True
        return results, len(results), False
    cache_hit = _full_repository_checkpoint_cache_hit(generation, checkpoint)
    if cache_hit:
        return results, 0, True
    validated = _full_repository_revalidate_results(generation, audit, results)
    return results, validated, False


def _full_repository_checkpoint_cache_hit(generation: dict, checkpoint: dict) -> bool:
    checkpoint_digest = digest(checkpoint)
    binding = (generation["root"].as_posix(), checkpoint_digest)
    trusted = _FULL_REPOSITORY_TRUSTED_CHECKPOINT
    if (
        trusted is not None
        and trusted[:2] == binding
        and trusted[2] != generation["runtime_epoch"]
    ):
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "native helper objects changed since the saved batch"
        )
    return trusted == (*binding, generation["runtime_epoch"])


def _full_repository_revalidate_results(
    generation: dict, audit, results: list[dict]
) -> int:
    eligible = {
        item.resolve(): item for item in generation["files"] if not item.is_symlink()
    }
    for result, path, source in zip(
        results, generation["files"], generation["inventory"]
    ):
        actual = _full_repository_primary(
            generation["root"], path, source, generation["patterns"], audit, eligible
        )
        if actual != result:
            raise RuntimeAuditError(
                "INVALID_CHECKPOINT", "saved result differs from native source analysis"
            )
    return len(results)


def _full_repository_scan_batch(
    generation: dict, audit, results: list[dict], deadline_monotonic=None
) -> list[dict]:
    if generation["context_profile"] == FULL_REPOSITORY_CONTEXT_PROFILE:
        return _full_repository_workspace_scan_batch(
            generation, audit, results, deadline_monotonic
        )
    start = len(results)
    eligible = {
        item.resolve(): item for item in generation["files"] if not item.is_symlink()
    }
    return [
        _full_repository_primary(
            generation["root"], path, source, generation["patterns"], audit, eligible
        )
        for path, source in zip(
            generation["files"][start : start + FULL_REPOSITORY_BATCH_LIMIT],
            generation["inventory"][start : start + FULL_REPOSITORY_BATCH_LIMIT],
        )
    ]


def _full_repository_check_soft_deadline(deadline_monotonic):
    if deadline_monotonic is not None and time.monotonic() > deadline_monotonic:
        raise RuntimeAuditError(
            "E_FULL_REPOSITORY_DEADLINE",
            "workspace-v2 exceeded its shared soft deadline at a phase boundary",
        )


def _full_repository_security_context(generation, audit):
    """Delegate the security-only generation builder to its existing owner."""
    from .runtime_audit_integrity import _full_repository_workspace_security_context

    return _full_repository_workspace_security_context(
        sys.modules[__name__], generation, audit
    )


def _full_repository_workspace_scan_batch(
    generation, audit, results, deadline_monotonic
):
    from . import runtime_audit_integrity

    return runtime_audit_integrity.full_repository_workspace_scan_batch(
        sys.modules[__name__], generation, audit, results, deadline_monotonic
    )


def _full_repository_verify_generation(generation: dict, audit) -> None:
    root = generation["root"]
    files = audit._security_source_files(root)
    inventory = _full_repository_inventory(root, files)
    patterns, frame, _collection_incomplete = _full_repository_profile_configuration(
        root, audit, generation["context_profile"]
    )
    config_identity = {
        "patterns": sorted(patterns),
        "frame": frame,
        "tenant_reads": [],
        "oracle_context": None,
    }
    if generation["context_profile"] == FULL_REPOSITORY_CONTEXT_PROFILE:
        config_identity["context_profile"] = FULL_REPOSITORY_CONTEXT_PROFILE
        config_identity["context_profile_schema"] = FULL_REPOSITORY_CONTEXT_SCHEMA
    configuration = digest(config_identity)
    if (
        files != generation["files"]
        or inventory != generation["inventory"]
        or configuration != generation["configuration"]
    ):
        raise RuntimeAuditError(
            "SOURCE_DRIFT", "source inventory or configuration changed during the batch"
        )
    if (
        _full_repository_scanner_identity() != generation["scanner"]
        or _full_repository_runtime_epoch(root, configuration, audit)
        != generation["runtime_epoch"]
    ):
        raise RuntimeAuditError(
            "SCANNER_DRIFT", "scanner identity changed during the batch"
        )


def _full_repository_store_checkpoint(generation: dict, results: list[dict]) -> None:
    global _FULL_REPOSITORY_TRUSTED_CHECKPOINT
    workspace = generation["context_profile"] == FULL_REPOSITORY_CONTEXT_PROFILE
    checkpoint = {
        "schema": generation["checkpoint_schema"],
        "root": generation["root"].as_posix(),
        "scanner_identity_sha256": generation["scanner"],
        "configuration_sha256": generation["configuration"],
        "inventory_sha256": generation["inventory_hash"],
        "inventory": generation["inventory"],
        "batch_primary_limit": FULL_REPOSITORY_BATCH_LIMIT,
        "primary_results": results,
        "result_digest": digest(results),
    }
    if workspace:
        checkpoint.update(
            {
                "context_profile": generation["context_profile"],
                "context_generation_sha256": generation["context_generation_sha256"],
            }
        )
    write_run_json(generation["directory"], "checkpoint.json", checkpoint)
    _FULL_REPOSITORY_TRUSTED_CHECKPOINT = (
        generation["root"].as_posix(),
        digest(checkpoint),
        generation["runtime_epoch"],
    )
    if workspace and generation.get("workspace_prefix_raw_rows") is not None:
        from .runtime_audit_integrity import _full_repository_workspace_store_prefix

        _full_repository_workspace_store_prefix(
            _FULL_REPOSITORY_TRUSTED_CHECKPOINT,
            checkpoint["result_digest"],
            checkpoint["context_generation_sha256"],
            generation["workspace_prefix_raw_rows"],
            digest,
        )


def _full_repository_dependency_index(results: list[dict]) -> dict:
    rows = [item["dependencies"] for item in results]
    return {
        "method": "AST lexical local import resolution against the eligible Python inventory; imports are not executed",
        "sources_indexed": sum(row["state"] == "lexical" for row in rows),
        "edges": sum(len(row["edges"]) for row in rows),
        "unresolved_relative_imports": sum(
            len(row["unresolved_relative_imports"]) for row in rows
        ),
        "closure_verified": False,
    }


def _full_repository_report(
    generation, results, batch, start, checkpoint_revalidated, checkpoint_cache_hit
):
    inventory = generation["inventory"]
    pending = [row["path"] for row in inventory[len(results) :]]
    states = ("audited", "syntax_error", "unreadable", "too_large", "unsupported")
    counts = {state: sum(row["status"] == state for row in results) for state in states}
    discovered, audited = len(inventory), counts["audited"]
    complete = discovered > 0 and not pending and audited == discovered
    accounting = "COMPLETE" if complete else "PENDING" if pending else "INCOMPLETE"
    coverage = {
        "audit_rate": audited / discovered if discovered else None,
        "complete": complete,
        "files_discovered": discovered,
        "files_attempted": len(results),
        "files_audited": audited,
        "measurement_state": "complete" if complete else "incomplete",
        "rate_defined": discovered > 0,
    }
    dependencies = _full_repository_dependency_index(results)
    report_digest = _full_repository_scan_digest(
        generation,
        inventory,
        results,
        accounting,
        coverage,
        dependencies,
        counts,
        pending,
    )
    report = {
        "schema": generation["report_schema"],
        "state": "INCOMPLETE",
        "discovery": generation["discovery"],
        "source_accounting_state": accounting,
        "inventory": inventory,
        "inventory_sha256": generation["inventory_hash"],
        "inventory_path_count": discovered,
        "batch_primary_limit": FULL_REPOSITORY_BATCH_LIMIT,
        "configuration_sha256": generation["configuration"],
        "scanner_identity_sha256": generation["scanner"],
        "batch": {
            "number": start // FULL_REPOSITORY_BATCH_LIMIT + 1,
            "primary_results": len(batch),
            "checkpoint_revalidated": checkpoint_revalidated,
            "checkpoint_cache_hit": checkpoint_cache_hit,
        },
        "primary_results": results,
        "files_discovered": discovered,
        "files_attempted": len(results),
        "files_audited": audited,
        "syntax_errors": counts["syntax_error"],
        "unreadable_sources": counts["unreadable"],
        "oversized_sources": counts["too_large"],
        "analysis_errors": counts["unsupported"],
        "pending_paths": pending,
        "pending_count": len(pending),
        "audit_coverage": coverage,
        "dependency_index": dependencies,
        "global_consumer_closure_verified": _FULL_REPOSITORY_GLOBAL_CONSUMER_CLOSURE_VERIFIED,
        "semantic_coverage": "INCOMPLETE",
        "target_execution": False,
        "target_source_writes": False,
        "dependency_installation": False,
        "release_approved": False,
        "native_completion_receipt": False,
        "result_digest": digest(results),
        "scan_sha256": report_digest,
    }
    if generation["context_profile"] == FULL_REPOSITORY_CONTEXT_PROFILE:
        evidence = generation["workspace_evidence"]
        report.update(
            {
                "context_profile": generation["context_profile"],
                "context_profile_schema": generation["context_profile_schema"],
                "context_profile_state": evidence["oracle_context"]["state"],
                "context_generation_sha256": generation["context_generation_sha256"],
                "primary_results_authority": "RAW_UNVERIFIED_SOURCE_ANALYSIS",
                "workspace_evidence": evidence,
                "deadline_policy": {
                    "seconds": FULL_REPOSITORY_CONTEXT_DEADLINE_SECONDS,
                    "enforcement": "soft phase-boundary checks; synchronous context work is not preempted",
                },
            }
        )
    return report


def full_repository_scan(
    root: Path,
    *,
    resume: bool = False,
    context_profile: str = "isolated-v1",
    deadline_monotonic: float | None = None,
) -> dict:
    """Run at most 460 new native per-file scans; the distinct profile is non-authoritative."""
    from . import review_audits as audit

    started = time.monotonic()
    if context_profile == FULL_REPOSITORY_CONTEXT_PROFILE:
        deadline_monotonic = deadline_monotonic or (
            started + FULL_REPOSITORY_CONTEXT_DEADLINE_SECONDS
        )
    generation = _full_repository_generation(root, audit, context_profile)
    if context_profile == FULL_REPOSITORY_CONTEXT_PROFILE:
        _full_repository_check_soft_deadline(deadline_monotonic)
    if resume:
        results, validated, cache_hit = _full_repository_resume_generation(
            generation, audit
        )
    else:
        results, validated, cache_hit = (
            _full_repository_start_generation(generation),
            0,
            False,
        )
    start = len(results)
    batch = _full_repository_scan_batch(generation, audit, results, deadline_monotonic)
    results.extend(batch)
    _full_repository_verify_generation(generation, audit)
    if context_profile == FULL_REPOSITORY_CONTEXT_PROFILE:
        _full_repository_check_soft_deadline(deadline_monotonic)
    _full_repository_store_checkpoint(generation, results)
    return _full_repository_report(
        generation, results, batch, start, validated, cache_hit
    )


if __name__ == "__main__":
    raise SystemExit(importlib.import_module(".deep_audit", __package__).adapter_main())

_MOVED_EXPORT_MODULES = {
    "contract": "deep_audit_contract",
    "sarif": "deep_audit_sarif",
    "attestation": "deep_audit_attestation",
    "loop": "deep_audit_loop",
    "deep_audit": "deep_audit",
}
_MOVED_EXPORTS = {
    "contract": frozenset(
        """
        _adapter_argv_shape
        _adapter_command_failed
        _adapter_command_shape
        _adapter_commands
        _adapter_contract_parts
        _adapter_exit_shape
        _adapter_invocation
        _adapter_output_paths
        _adapter_profile
        _adapter_source_files
        _adapter_sources
        _bounded_json_bytes
        _codeql_query_ids
        _codeql_query_preflight
        _codeql_resolved_queries
        _codeql_selection_ids
        _codeql_selection_shape
        _codeql_suite_bytes
        _fuzz_execution_contract
        _fuzz_profile_preflight
        _gitleaks_coverage_preflight
        _gitleaks_disable_rule
        _gitleaks_mutation_valid
        _gitleaks_rule_ids
        _gitleaks_rule_inventory
        _json_size_upper_bound
        _json_string_size
        _json_value_size
        _native_argv
        _native_budget_error
        _native_profile
        _native_profile_challenges
        _native_version
        _osv_config_rule_ids
        _osv_expected_policy
        _osv_mutation_valid
        _osv_policy_inputs
        _osv_profile_preflight
        _runtime_disable_rule
        _runtime_mutation_valid
        _runtime_rule_ids
        _runtime_rule_inventory
        _runtime_ruleset_preflight
        _semgrep_disable_rule
        _semgrep_mutation_file
        _semgrep_mutation_valid
        _semgrep_rule_ids
        _semgrep_rule_sources
        _semgrep_scanned_sources
        _toml_parser
        _trivy_expected_ids
        _trivy_ignore_ids
        _trivy_json_argv
        _trivy_matrix_ids
        _trivy_mutation
        _trivy_mutation_valid
        _trivy_policy_inputs
        _trivy_rule_id_valid
        execute_adapter_profile
        resolve_codeql_query_inventory
        verify_codeql_query_isolation
        verify_codeql_query_selection
        """.split()
    ),
    "sarif": frozenset(
        """
        _ZAP_TRACE_BOOTSTRAP
        _challenge_source_uri
        _codeql_parse_rows
        _codeql_result_path
        _codeql_result_sets
        _codeql_source_query
        _indexed_artifact_uri
        _junit_bytes
        _junit_case
        _junit_observations
        _junit_suite_counts
        _native_artifact_path
        _native_artifact_uri
        _native_coverage_counts
        _native_coverage_report
        _native_dependency_paths
        _native_junit
        _native_profile_report
        _native_report
        _native_sarif_metadata
        _native_sarif_paths
        _native_source_counts
        _native_source_path
        _normalize_challenge_artifact_paths
        _normalize_challenge_bases
        _normalize_challenge_invocation
        _normalize_challenge_message_paths
        _normalize_challenge_run
        _normalize_challenge_sarif_paths
        _osv_challenge_source_paths
        _osv_lookup_paths
        _osv_normalize_lookup_path
        _osv_normalize_result_source
        _osv_suppression_bytes
        _parse_runtime_junit
        _runtime_exit_consistency
        _runtime_report_file
        _semgrep_json_findings
        _semgrep_sarif_findings
        _trivy_bind_report_targets
        _trivy_check_statuses
        _trivy_clean_hcl_comments
        _trivy_closed_argv
        _trivy_decode_source_bytes
        _trivy_expected_failures
        _trivy_full_source_execution
        _trivy_hcl_block
        _trivy_hcl_char
        _trivy_hcl_line_depth
        _trivy_hcl_string_char
        _trivy_local_module_members
        _trivy_match_failure_rows
        _trivy_module_sources
        _trivy_native_checks
        _trivy_native_failure_rows
        _trivy_normalized_sarif
        _trivy_observation
        _trivy_observation_bytes
        _trivy_pair_facts
        _trivy_pair_identity
        _trivy_paired_runner
        _trivy_parse_module_blocks
        _trivy_read_raw
        _trivy_root_module_graph
        _trivy_root_module_graphs
        _trivy_root_target_prefix
        _trivy_sarif_failures
        _trivy_source_bytes
        _trivy_source_map
        _trivy_target_bindings
        _trivy_target_members
        _trivy_target_name
        _trivy_terraform_file_target_members
        _trivy_validate_target_coverage
        _under_challenge_root
        _zap_trace_document
        _zap_trace_observations
        _zap_trace_routes
        _zap_trace_sources
        zap_source_trace_bootstrap
        zap_validate_source_trace
        """.split()
    ),
    "attestation": frozenset(
        """
        _atheris_challenge_retained_budget
        _attach_gitleaks_ledger
        _codeql_archived_sources
        _codeql_blob_bytes
        _codeql_native_blob
        _codeql_query_execution
        _codeql_query_result_record
        _codeql_retained_archive
        _codeql_retained_inventory
        _codeql_retained_invocation
        _codeql_source_accounting
        _codeql_source_measurement
        _codeql_source_state
        _codeql_steps_facts
        _codeql_verify_retained_query
        _codeql_verify_retained_source
        _fuzz_replay_control_evidence
        _fuzz_retained_bundle_shape
        _fuzz_retained_control_evidence
        _fuzz_retained_control_kinds
        _fuzz_retained_execution_artifacts
        _fuzz_retained_expected
        _fuzz_retained_gaps
        _fuzz_retained_obligation_valid
        _fuzz_retained_observations
        _gitleaks_accounting
        _gitleaks_accounting_complete
        _gitleaks_counter_values
        _gitleaks_coverage_errors
        _gitleaks_disposition
        _gitleaks_ledger_binding
        _gitleaks_ledger_identity
        _gitleaks_ledger_matrix
        _gitleaks_ledger_rows
        _gitleaks_ledger_shape
        _gitleaks_ledger_status
        _gitleaks_preflight
        _gitleaks_row_values
        _gitleaks_scanned_bytes
        _gitleaks_source_map
        _gitleaks_stderr_path
        _ledger_metadata_matches
        _native_profile_coverage
        _native_runtime_accounting
        _native_source_accounting
        _osv_challenge_retained_budget
        _osv_database_artifact
        _osv_database_identity
        _osv_native_blob
        _osv_native_bytes
        _osv_normalize_retained_paths
        _osv_primary_evidence
        _osv_primary_retained
        _osv_retained_controls_match
        _osv_retained_expected
        _osv_retained_observations
        _osv_retained_observed
        _osv_source_root_prefix
        _read_gitleaks_ledger
        _retained_fuzz_corpus
        _runtime_coverage_errors
        _semgrep_evidence_inputs
        _semgrep_fixture_binding
        _semgrep_observation_identity
        _semgrep_raw_bindings
        _semgrep_rule_inventory
        _semgrep_rule_runs
        _semgrep_source_accounting
        _stable_ledger_read
        _trivy_challenge_evidence
        _trivy_coverage_errors
        _trivy_evidence_inputs
        verify_codeql_retained_evidence
        verify_fuzz_retained_evidence
        verify_osv_retained_challenge
        verify_osv_retained_evidence
        verify_semgrep_rule_execution
        verify_trivy_rule_execution
        """.split()
    ),
    "loop": frozenset(
        """
        _atheris_challenge_command
        _atheris_challenge_control
        _atheris_challenge_gaps
        _atheris_challenge_report
        _atheris_challenges
        _atheris_obligations
        _challenge_bundle
        _challenge_error_code
        _challenge_gap_record
        _codeql_challenge_case
        _codeql_challenge_inputs
        _codeql_challenge_report
        _codeql_challenge_selection
        _codeql_challenge_steps
        _codeql_challenges
        _codeql_mutation_suite
        _codeql_replay_decode
        _codeql_replay_fresh
        _codeql_replay_queries
        _codeql_replay_remaining
        _codeql_replay_selection
        _codeql_replay_source_values
        _codeql_replay_sources
        _codeql_replay_values
        _codeql_step_streams
        _codeql_steps_runner
        _codeql_telemetry_notification
        _execute_codeql_challenge
        _finalize_fuzz_report
        _fuzz_control_args
        _fuzz_control_ids
        _fuzz_corpus_document
        _fuzz_corpus_entry
        _fuzz_disable_rule
        _fuzz_fixture_manifest_binding
        _fuzz_record_input
        _fuzz_replay_controls
        _fuzz_replay_expected
        _fuzz_replay_harness
        _fuzz_replay_inputs_main
        _fuzz_replay_module
        _fuzz_replay_profile
        _fuzz_replay_remaining
        _fuzz_replayed_failure_inputs_valid
        _fuzz_snapshot
        _gitleaks_challenge_allowed
        _gitleaks_challenge_report
        _gitleaks_challenges
        _gitleaks_challenges_complete
        _gitleaks_obligations
        _is_digest
        _native_challenge_bindings
        _osv_challenge_artifacts_valid
        _osv_challenge_command
        _osv_challenge_control
        _osv_challenge_controls_match
        _osv_challenge_execution
        _osv_challenge_gaps
        _osv_challenge_manifest
        _osv_challenge_report_bytes
        _osv_challenge_runner
        _osv_challenges
        _osv_challenges_complete
        _osv_check_deadline
        _osv_execution_bindings
        _osv_mutation_path
        _osv_obligations
        _osv_parse_challenge_report
        _osv_replay_compare_controls
        _osv_replay_control_ids
        _osv_replay_controls
        _osv_replay_execution_facts
        _osv_replay_identities
        _osv_replay_primary
        _osv_replay_remaining
        _osv_replay_row_map
        _osv_replay_semantics_match
        _run_atheris_challenge
        _run_codeql_challenge
        _run_gitleaks_challenge
        _run_osv_challenge
        _run_semgrep_challenge
        _run_trivy_challenge
        _runtime_challenge
        _runtime_challenge_report
        _runtime_challenges
        _runtime_encoded_argv
        _runtime_has_sentinel
        _runtime_mutation_config
        _runtime_obligations
        _semgrep_challenge_command
        _semgrep_challenge_report
        _semgrep_challenge_result
        _semgrep_challenges
        _semgrep_obligations
        _trivy_challenge_command
        _trivy_challenge_control
        _trivy_challenge_report
        _trivy_challenges
        _trivy_effective_ids
        _trivy_mutation_path
        _trivy_obligations
        _validate_fuzz_corpus
        _validate_fuzz_corpus_inputs
        _validate_fuzz_replay_observation
        _validate_fuzz_replayed_control
        _validate_fuzz_replayed_controls
        execute_codeql_native_replay
        execute_fuzz_native_replay
        execute_osv_native_replay
        native_fuzz_main
        """.split()
    ),
    "deep_audit": frozenset(
        """
        _native_challenge_executor
        _native_zap_main
        _profile_adapter_main
        _run_native_profile
        _run_zap_native_scan
        _zap_api
        _zap_api_arguments
        _zap_check_daemon
        _zap_daemon_argv
        _zap_daemon_environment
        _zap_enabled_inventory
        _zap_file_signature
        _zap_measure_scan
        _zap_native_request
        _zap_native_v2_context
        _zap_probe_target
        _zap_process_facts
        _zap_retained_ledger
        _zap_select_rules
        _zap_start_scan
        _zap_target_base_url
        _zap_validate_target_watch
        _zap_wait_passive_scan
        _zap_wait_ready
        _zap_wait_scan
        _zap_watch
        adapter_main
        execute_native_profile
        """.split()
    ),
}


def __getattr__(name: str):
    for owner, exports in _MOVED_EXPORTS.items():
        if name in exports:
            module = importlib.import_module(
                f".{_MOVED_EXPORT_MODULES[owner]}", __package__
            )
            return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

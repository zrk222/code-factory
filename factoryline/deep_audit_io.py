"""Bounded local input primitives for non-authoritative deep analysis evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import stat
import threading
import uuid
import tempfile
import time
from collections import Counter
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote

from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    exact_keys,
    require_digest,
    require_int,
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
    ".factory/scopes/",
    ".factory/repair-approvals/",
    ".factory/repair-attempts/",
)


def _generated_factory_path(name: str) -> bool:
    return name == ".factory/candidate.diff" or name.startswith(
        _GENERATED_FACTORY_PREFIXES
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


def _adapter_profile(profile: dict, lane: dict) -> list[dict]:
    """Commands come from the immutable image, never from scanned repository text."""
    expected = {
        "schema",
        "engine",
        "mode",
        "tool_version",
        "ruleset_sha256",
        "commands",
    }
    if set(profile) != expected or profile["schema"] != "factory.adapter-profile.v1":
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "invalid image-bundled profile")
    for key in ("engine", "mode", "tool_version", "ruleset_sha256"):
        if profile[key] != lane.get(key):
            raise RuntimeAuditError(
                "E_ADAPTER_PROFILE", "profile differs from signed lane"
            )
    commands = profile["commands"]
    if not isinstance(commands, list) or not 1 <= len(commands) <= 64:
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "bounded command list required")
    for command in commands:
        _adapter_command_shape(command)
    return commands


def _adapter_command_shape(command: dict) -> None:
    if not isinstance(command, dict) or set(command) != {"argv", "accepted_exit_codes"}:
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "invalid command fields")
    _adapter_argv_shape(command["argv"])
    _adapter_exit_shape(command["accepted_exit_codes"])


def _adapter_argv_shape(argv):
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "bounded argv required")
    for arg in argv:
        require_str(arg, "adapter argument", maximum=2048)
    if not Path(argv[0]).is_absolute():
        raise RuntimeAuditError(
            "E_ADAPTER_PROFILE", "absolute executable path required"
        )


def _adapter_exit_shape(exits):
    if not isinstance(exits, list) or not 1 <= len(exits) <= 16:
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "bounded exit codes required")
    if any(type(code) is not int or not 0 <= code <= 255 for code in exits):
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "invalid exit code")


def _adapter_sources(source: Path, inventory: dict) -> None:
    files = inventory.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 50_000:
        raise RuntimeAuditError("E_ADAPTER_INPUT", "bounded inventory required")
    names = set()
    for item in files:
        if not isinstance(item, dict) or item.get("path") in names:
            raise RuntimeAuditError(
                "E_ADAPTER_INPUT", "unique source bindings required"
            )
        path = relative_path(item.get("path"))
        names.add(path)
        bound_bytes(source, {"path": path, "sha256": item.get("sha256")})
    actual = _adapter_source_files(source)
    if actual != names:
        raise RuntimeAuditError(
            "E_ADAPTER_INPUT", "source file set differs from inventory"
        )


def _adapter_source_files(source):
    if source.is_symlink() or not source.is_dir():
        raise RuntimeAuditError(
            "E_ADAPTER_INPUT", "source root must be a real directory"
        )
    pending = [source]
    names = set()
    entries = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            for entry in iterator:
                entries += 1
                if entries > 100_000:
                    raise RuntimeAuditError(
                        "E_ADAPTER_INPUT", "source tree exceeds entry budget"
                    )
                if entry.is_symlink():
                    raise RuntimeAuditError(
                        "E_ADAPTER_INPUT", "source links are unsupported"
                    )
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise RuntimeAuditError(
                        "E_ADAPTER_INPUT", "special source entries are unsupported"
                    )
                relative = Path(entry.path).relative_to(source).as_posix()
                names.add(relative_path(relative))
    return names


def _adapter_commands(
    commands: list[dict], lane: dict, source: Path, scratch: Path
) -> list[dict]:
    from .runtime_audit_process import run_bounded_command

    timeout = lane.get("timeout_seconds")
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise RuntimeAuditError("E_ADAPTER_INPUT", "bounded signed timeout required")
    deadline = time.monotonic() + timeout
    invocations = []
    for index, command in enumerate(commands):
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            raise RuntimeAuditError("E_ADAPTER_TIMEOUT", "adapter deadline exhausted")
        directory = scratch / str(index)
        directory.mkdir()
        invocations.append(
            _adapter_invocation(
                run_bounded_command,
                command,
                lane,
                source,
                directory,
                remaining,
                deadline,
            )
        )
    return invocations


def _adapter_invocation(runner, command, lane, source, directory, remaining, deadline):
    argv = [
        value.replace("{factory_ledger}", str(directory / "rule-ledger.json"))
        for value in command["argv"]
    ]
    stderr_path = _gitleaks_stderr_path(directory, lane)
    facts = runner(argv, source, remaining, directory, stderr_path=stderr_path)
    if _adapter_command_failed(facts, command["accepted_exit_codes"], deadline):
        raise RuntimeAuditError("E_ADAPTER_COMMAND", "native command did not complete")
    invocation = {"argv_sha256": digest(command["argv"]), "execution": facts}
    _attach_gitleaks_ledger(invocation, command, directory)
    if stderr_path is not None:
        invocation["native_scanned_bytes"] = _gitleaks_scanned_bytes(
            stderr_path.read_bytes(), lane["tool_version"]
        )
    return invocation


def _gitleaks_stderr_path(directory, lane):
    if lane.get("engine") == "gitleaks" and lane.get("tool_version") == "8.28.0":
        return directory / "stderr.log"
    return None


def _attach_gitleaks_ledger(invocation, command, directory):
    if "{factory_ledger}" not in " ".join(command["argv"]):
        return
    try:
        ledger, ledger_sha256, ledger_json = _read_gitleaks_ledger(
            directory / "rule-ledger.json"
        )
        invocation["native_rule_ledger"] = ledger
        invocation["native_rule_ledger_sha256"] = ledger_sha256
        invocation["native_rule_ledger_json"] = ledger_json
    except RuntimeAuditError as exc:
        invocation["native_rule_ledger"] = None
        invocation["native_rule_ledger_error"] = exc.code


def _read_gitleaks_ledger(path: Path) -> tuple[dict, str, str]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeAuditError("E_GITLEAKS_LEDGER_MISSING", "native ledger missing")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > NATIVE_LEDGER_LIMIT:
                raise RuntimeAuditError(
                    "E_GITLEAKS_LEDGER_SIZE", "native ledger over budget"
                )
            raw = stream.read(NATIVE_LEDGER_LIMIT + 1)
            after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_READ", "native ledger could not be read safely"
        ) from exc
    if not _stable_ledger_read(opened, after, current, raw):
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native ledger changed while read"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_READ", "native ledger encoding invalid"
        ) from exc
    return strict_json(raw), sha256_bytes(raw), text


def _stable_ledger_read(opened, after, current, raw):
    if len(raw) > NATIVE_LEDGER_LIMIT or not stat.S_ISREG(current.st_mode):
        return False
    if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
        return False
    if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
        return False
    return _ledger_metadata_matches(opened, after, current, raw)


def _ledger_metadata_matches(opened, after, current, raw):
    return (
        opened.st_size == after.st_size
        and opened.st_mtime_ns == after.st_mtime_ns
        and opened.st_ctime_ns == after.st_ctime_ns
        and opened.st_mtime_ns == current.st_mtime_ns
        and opened.st_ctime_ns == current.st_ctime_ns
        and len(raw) == opened.st_size
    )


def _gitleaks_ledger_matrix(
    ledger, ledger_sha, lane, inventory, inventory_sha, invocations, raw_report
):
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    if not _gitleaks_ledger_shape(ledger):
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SHAPE", "native ledger schema differs"
        )
    if not _gitleaks_ledger_binding(ledger, lane, inventory):
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_BINDING", "native ledger binding incomplete"
        )
    source_map = _gitleaks_source_map(inventory["files"])
    source_map_sha = inventory["candidate_sha256"]
    counts = _gitleaks_ledger_rows(ledger["rows"], lane["rule_ids"], source_map)
    accounting = _gitleaks_accounting(
        ledger_sha,
        lane,
        required,
        counts,
        inventory_sha,
        source_map_sha,
        invocations,
        raw_report,
    )
    return accounting, source_map, source_map_sha


def _gitleaks_ledger_shape(ledger):
    expected = {
        "schema",
        "root_sha256",
        "source_identity_kind",
        "source_sha256",
        "config_sha256",
        "prefilter_bypassed",
        "complete",
        "overflow",
        "invalid_paths",
        "rows",
    }
    return (
        isinstance(ledger, dict)
        and set(ledger) == expected
        and isinstance(ledger.get("rows"), list)
        and len(ledger["rows"]) <= 200_000
    )


def _gitleaks_ledger_binding(ledger, lane, inventory):
    return _gitleaks_ledger_identity(
        ledger, lane, inventory
    ) and _gitleaks_ledger_status(ledger)


def _gitleaks_ledger_identity(ledger, lane, inventory):
    return (
        ledger["schema"] == "gitleaks.factory-rule-ledger.v1"
        and ledger["source_identity_kind"] == "adapter_candidate_sha256"
        and ledger["source_sha256"] == inventory["candidate_sha256"]
        and ledger["config_sha256"] == lane["ruleset_sha256"]
        and ledger["root_sha256"] == sha256_bytes(b"/src")
    )


def _gitleaks_ledger_status(ledger):
    return (
        ledger["prefilter_bypassed"] is True
        and ledger["complete"] is True
        and ledger["overflow"] is False
        and type(ledger["invalid_paths"]) is int
        and ledger["invalid_paths"] == 0
    )


def _gitleaks_source_map(files):
    estimate = sum(
        len(canonical_bytes(item["path"]))
        + len(canonical_bytes(item["language"]))
        + 112
        for item in files
    )
    if estimate > NATIVE_SOURCE_MAP_LIMIT:
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native source map over budget"
        )
    sources = {item["path"]: item["sha256"] for item in files}
    if _json_size_upper_bound(files) > NATIVE_SOURCE_MAP_LIMIT:
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native source map over budget"
        )
    if len(canonical_bytes(files)) > NATIVE_SOURCE_MAP_LIMIT:
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native source map over budget"
        )
    return sources


def _json_size_upper_bound(value):
    """Conservatively estimate canonical JSON bytes without materializing them."""
    total = 0
    pending = [value]
    while pending:
        total += _json_value_size(pending.pop(), pending)
    return total


def _json_value_size(item, pending):
    if isinstance(item, dict):
        pending.extend(item.values())
        for key in item:
            if not isinstance(key, str):
                raise RuntimeAuditError("E_NATIVE_BUNDLE_SIZE", "JSON key is not text")
        return 2 + max(0, len(item) - 1) + sum(_json_string_size(key) for key in item)
    if isinstance(item, (list, tuple)):
        pending.extend(item)
        return 2 + max(0, len(item) - 1)
    if isinstance(item, str):
        return _json_string_size(item)
    if item is None or isinstance(item, bool):
        return 5
    if isinstance(item, int):
        return len(str(item))
    if isinstance(item, float):
        return 32
    raise RuntimeAuditError("E_NATIVE_BUNDLE_SIZE", "unsupported JSON value")


def _json_string_size(value):
    size = 2
    for char in value:
        codepoint = ord(char)
        if char in {'"', "\\", "\b", "\t", "\n", "\f", "\r"}:
            size += 2
        elif codepoint < 32:
            size += 6
        else:
            size += len(char.encode("utf-8"))
    return size


def _native_budget_error(code, sources, rules, estimate, limit):
    pairs = sources * rules
    raise RuntimeAuditError(
        code,
        f"native budget requires {sources} sources x {rules} rules "
        f"({pairs} rows); estimated {estimate} bytes exceeds {limit}",
    )


def _gitleaks_coverage_preflight(
    execution, report, inventory, lane, challenges, obligations
):
    source_count = sum(
        item["language"] in lane["languages"] for item in inventory["files"]
    )
    rule_count = len(lane["rule_ids"])
    pairs = source_count * rule_count
    per_pair = 768 + (
        max(
            (_json_string_size(item["path"]) - 2 for item in inventory["files"]),
            default=0,
        )
        + max(
            (_json_string_size(rule_id) - 2 for rule_id in lane["rule_ids"]),
            default=0,
        )
    )
    fixed = (
        len(execution["ledger_json"].encode("utf-8"))
        + _json_size_upper_bound(inventory["files"])
        + _json_size_upper_bound(execution["invocations"])
        + _json_size_upper_bound(execution["version_probe"])
        + _json_size_upper_bound(execution["rule_inventory"])
        + _json_size_upper_bound(report)
        + _json_size_upper_bound(challenges)
        + _json_size_upper_bound(obligations)
        + 4096
    )
    estimate = fixed + pairs * per_pair
    if pairs > 200_000 or estimate > NATIVE_COVERAGE_LIMIT:
        _native_budget_error(
            "E_GITLEAKS_LEDGER_SIZE",
            source_count,
            rule_count,
            estimate,
            NATIVE_COVERAGE_LIMIT,
        )


def _bounded_json_bytes(value, limit, code, sources=0, rules=0):
    estimate = _json_size_upper_bound(value)
    if estimate > limit:
        _native_budget_error(code, sources, rules, estimate, limit)
    raw = canonical_bytes(value)
    if len(raw) > limit:
        _native_budget_error(code, sources, rules, len(raw), limit)
    return raw


def _gitleaks_ledger_rows(rows, rule_ids, required):
    observed = {}
    allowed = {
        "attempted",
        "suppressed_skip_report",
        "suppressed_rule_allowlist",
        "suppressed_global_allowlist",
        "path_evaluated",
        "not_applicable_path_mismatch",
        "not_applicable_no_regex",
        "not_run_size_limit",
        "regex_executed",
        "regex_match",
        "finding",
    }
    for row in rows:
        path, rule_id, counts = _gitleaks_row_values(row, allowed)
        if (
            path not in required
            or rule_id not in rule_ids
            or (path, rule_id) in observed
        ):
            raise RuntimeAuditError(
                "E_GITLEAKS_LEDGER_ROW", "native ledger row unbound"
            )
        observed[path, rule_id] = counts
    return observed


def _gitleaks_row_values(row, allowed):
    if not isinstance(row, dict) or set(row) != {"path", "rule_id", "counts"}:
        raise RuntimeAuditError("E_GITLEAKS_LEDGER_ROW", "native ledger row malformed")
    path, rule_id, counts = row["path"], row["rule_id"], row["counts"]
    if not isinstance(path, str) or not isinstance(rule_id, str):
        raise RuntimeAuditError("E_GITLEAKS_LEDGER_ROW", "native ledger row malformed")
    if not isinstance(counts, dict) or not counts or not set(counts) <= allowed:
        raise RuntimeAuditError("E_GITLEAKS_LEDGER_ROW", "native counters malformed")
    _gitleaks_counter_values(counts)
    return path, rule_id, counts


def _gitleaks_counter_values(counts):
    if any(
        type(value) is not int or not 1 <= value <= 2**63 - 1
        for value in counts.values()
    ):
        raise RuntimeAuditError("E_GITLEAKS_LEDGER_ROW", "native counter invalid")
    attempted = counts.get("attempted", 0)
    evaluated = max(counts.get("regex_executed", 0), counts.get("path_evaluated", 0))
    if attempted < evaluated or counts.get("finding", 0) > counts.get("regex_match", 0):
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_ROW", "native counters are inconsistent"
        )


def _gitleaks_accounting(
    ledger_sha,
    lane,
    required,
    counts,
    inventory_sha,
    source_map_sha,
    invocations,
    raw_report,
):
    pairs = len(lane["rule_ids"]) * len(required)
    estimate = 512 + pairs * 512
    estimate += len(lane["rule_ids"]) * sum(
        len(canonical_bytes(path)) for path in required
    )
    estimate += len(required) * sum(
        len(canonical_bytes(rule_id)) for rule_id in lane["rule_ids"]
    )
    if pairs > 200_000 or estimate > NATIVE_ACCOUNTING_LIMIT:
        _native_budget_error(
            "E_GITLEAKS_LEDGER_SIZE",
            len(required),
            len(lane["rule_ids"]),
            estimate,
            NATIVE_ACCOUNTING_LIMIT,
        )
    rules = []
    for rule_id in sorted(lane["rule_ids"]):
        sources = []
        for path, source_sha in sorted(required.items()):
            native_counts = counts.get((path, rule_id), {})
            disposition = _gitleaks_disposition(native_counts)
            evidence = {
                "ledger_sha256": ledger_sha,
                "source_sha256": source_sha,
                "path": path,
                "rule_id": rule_id,
                "counts": native_counts,
            }
            sources.append(
                {
                    "path": path,
                    "source_sha256": source_sha,
                    "disposition": disposition,
                    "native_counts": native_counts,
                    "evidence_sha256": digest(evidence),
                }
            )
        rules.append({"rule_id": rule_id, "sources": sources})
    body = {
        "schema": "factory.deep-rule-accounting.v1",
        "ruleset_sha256": lane["ruleset_sha256"],
        "rule_inventory_sha256": inventory_sha,
        "native_ledger_sha256": ledger_sha,
        "native_source_inventory_sha256": source_map_sha,
        "invocation_sha256": digest(invocations),
        "native_report_sha256": digest(raw_report),
        "rules": rules,
    }
    accounting = {**body, "accounting_sha256": digest(body)}
    if len(canonical_bytes(accounting)) > NATIVE_ACCOUNTING_LIMIT:
        raise RuntimeAuditError(
            "E_GITLEAKS_LEDGER_SIZE", "native accounting over budget"
        )
    return accounting


def _gitleaks_disposition(counts):
    if any(key.startswith("suppressed_") for key in counts):
        return "suppressed"
    if counts.get("not_run_size_limit", 0) > 0:
        return "not_run"
    if counts.get("regex_executed", 0) > 0 or counts.get("path_evaluated", 0) > 0:
        return "executed"
    if (
        counts.get("not_applicable_path_mismatch", 0) > 0
        or counts.get("not_applicable_no_regex", 0) > 0
    ):
        return "not_applicable"
    return "not_run"


def _adapter_command_failed(facts, accepted_exit_codes, deadline):
    if any(
        facts[key] for key in ("timed_out", "launch_error", "output_limit_exceeded")
    ):
        return True
    if not facts["cleanup_confirmed"] or facts["exit_code"] not in accepted_exit_codes:
        return True
    return time.monotonic() > deadline


def _adapter_contract_parts(contract: dict) -> tuple[dict, dict]:
    """Validate shared input identity before executing either worker format."""
    keys = {"schema", "run_id", "manifest_sha256", "inventory", "lane", "obligations"}
    if (
        not isinstance(contract, dict)
        or set(contract) != keys
        or contract["schema"] != "factory.deep-adapter-input.v1"
    ):
        raise RuntimeAuditError("E_ADAPTER_INPUT", "invalid adapter contract")
    require_str(contract["run_id"], "run_id", maximum=64)
    require_digest(contract["manifest_sha256"], "manifest_sha256")
    inventory, lane = contract["inventory"], contract["lane"]
    if not isinstance(inventory, dict) or not isinstance(lane, dict):
        raise RuntimeAuditError(
            "E_ADAPTER_INPUT", "inventory and lane objects required"
        )
    require_digest(inventory.get("candidate_sha256"), "candidate_sha256")
    return inventory, lane


def _adapter_output_paths(
    lane: dict, output: Path, *, create_parents: bool = False
) -> list[str]:
    """Reject stale or aliased artifacts before any native tool is started."""
    paths = [
        relative_path(lane[key]) for key in ("report", "coverage", "challenge_report")
    ]
    if len(set(paths)) != 3:
        raise RuntimeAuditError("E_ADAPTER_INPUT", "distinct artifact paths required")
    for path in paths:
        target = output / path
        if target.exists() or target.is_symlink():
            raise RuntimeAuditError("E_ADAPTER_STALE", "preexisting output rejected")
        if create_parents:
            target.parent.mkdir(parents=True, exist_ok=True)
    return paths


def execute_adapter_profile(
    profile: dict, contract: dict, source: Path, output: Path
) -> dict:
    """Join actual native artifacts; never synthesize coverage or challenge success."""
    inventory, lane = _adapter_contract_parts(contract)
    commands = _adapter_profile(profile, lane)
    _adapter_sources(source, inventory)
    report_paths = _adapter_output_paths(lane, Path(output))
    with tempfile.TemporaryDirectory(prefix="factory-adapter-") as temporary:
        invocations = _adapter_commands(commands, lane, Path(source), Path(temporary))
    artifacts = {}
    for path in sorted(report_paths):
        artifact = local_file(output, path)
        with artifact.open("rb") as stream:
            artifacts[path] = strict_json(stream.read(LIMIT + 1))
    coverage = artifacts[lane["coverage"]]
    coverage["native_coverage_sha256"] = digest(coverage)
    coverage["native_invocations"] = invocations
    coverage["invocation_sha256"] = digest(invocations)
    _adapter_sources(source, inventory)
    return {
        "schema": "factory.deep-worker.v1",
        "run_id": contract["run_id"],
        "candidate_sha256": inventory["candidate_sha256"],
        "artifacts": artifacts,
    }


def _native_profile(profile: dict, lane: dict) -> None:
    expected = {
        "schema",
        "engine",
        "mode",
        "tool_version",
        "ruleset_sha256",
        "commands",
        "version_argv",
        "report_format",
    }
    if set(profile) != expected or profile["schema"] != "factory.native-profile.v1":
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "invalid native profile")
    projected = {
        key: value
        for key, value in profile.items()
        if key not in {"version_argv", "report_format"}
    }
    projected["schema"] = "factory.adapter-profile.v1"
    _adapter_profile(projected, lane)
    _adapter_command_shape(
        {"argv": profile["version_argv"], "accepted_exit_codes": [0]}
    )
    formats = {
        "codeql": {"sarif"},
        "semgrep": {"sarif"},
        "gitleaks": {"sarif"},
        "trivy": {"sarif"},
        "osv": {"osv-json"},
        "syft": {"syft-json"},
        "runtime": {"runtime-json", "coverage-json", "runtime-junit"},
        "atheris": {"runtime-json"},
        "jazzer": {"runtime-json"},
        "zap": {"runtime-json"},
    }
    if profile["report_format"] not in formats.get(profile["engine"], set()):
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "unsupported native report")
    if profile["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        if len(profile["commands"]) != 1:
            raise RuntimeAuditError(
                "E_ADAPTER_PROFILE", "runtime requires one bounded command"
            )
        if lane.get("native_artifact_roles") != ["coverage_json", "junit_xml"]:
            raise RuntimeAuditError(
                "E_ADAPTER_PROFILE", "runtime artifact roles differ"
            )
        if not isinstance(lane.get("rule_ids"), list) or not lane["rule_ids"]:
            raise RuntimeAuditError(
                "E_ADAPTER_PROFILE", "runtime rule inventory required"
            )


def _native_version(profile: dict, source: Path, scratch: Path, timeout: int) -> dict:
    from .runtime_audit_process import run_bounded_command
    import re

    capture = scratch / "version.txt"
    facts = run_bounded_command(
        profile["version_argv"], source, timeout, scratch, stdout_path=capture
    )
    if (
        facts["exit_code"] != 0
        or facts["timed_out"]
        or facts["launch_error"]
        or facts["output_limit_exceeded"]
        or not facts["cleanup_confirmed"]
    ):
        raise RuntimeAuditError("E_TOOLCHAIN_PROBE", "native version probe failed")
    text = capture.read_text(encoding="utf-8")
    pattern = r"(?<![\w.])v?" + re.escape(profile["tool_version"]) + r"(?![\w.])"
    if not re.search(pattern, text):
        raise RuntimeAuditError("E_TOOLCHAIN_DRIFT", "native version differs")
    return facts


def _native_argv(commands: list, bindings: dict) -> list:
    result = []
    for command in commands:
        argv = []
        for value in command["argv"]:
            for name, bound in bindings.items():
                value = value.replace("{" + name + "}", str(bound))
            argv.append(value)
        _adapter_command_shape(
            {"argv": argv, "accepted_exit_codes": command["accepted_exit_codes"]}
        )
        result.append(
            {"argv": argv, "accepted_exit_codes": command["accepted_exit_codes"]}
        )
    return result


def _gitleaks_scanned_bytes(stderr: bytes, tool_version: str) -> int:
    """Read v8.28.0's integer detector counter; the parenthesized size is display-only."""
    import re

    if tool_version != "8.28.0":
        raise RuntimeAuditError(
            "E_GITLEAKS_COUNTER_VERSION", "counter format is unpinned"
        )
    plain = re.sub(rb"\x1b\[[0-9;]*m", b"", stderr)
    lines = [line for line in plain.splitlines() if b"scanned ~" in line]
    if len(lines) != 1:
        raise RuntimeAuditError(
            "E_GITLEAKS_COUNTER", "one consistent native byte counter required"
        )
    match = re.fullmatch(
        rb"[0-9]{1,2}:[0-9]{2}(?:AM|PM) INF scanned ~([0-9]+) bytes "
        rb"\(([0-9]+(?:\.[0-9]+)?) (bytes|KB|MB|GB)\) in [0-9.]+(?:ms|s)",
        lines[0],
    )
    if match is None:
        raise RuntimeAuditError("E_GITLEAKS_COUNTER", "malformed native byte counter")
    counter, _displayed, _unit = match.groups()
    value = int(counter)
    if value > SOURCE_LIMIT:
        raise RuntimeAuditError("E_GITLEAKS_COUNTER", "native byte count is invalid")
    return value


def _gitleaks_rule_inventory(config: bytes, lane: dict) -> dict:
    """Bind the signed rule IDs to the exact TOML consumed by the pinned worker."""
    actual = _gitleaks_rule_ids(config)
    expected = lane.get("rule_ids")
    if not isinstance(expected, list) or not expected:
        return {"state": "UNAVAILABLE", "rule_ids": [], "sha256": None}
    if sha256_bytes(config) != lane["ruleset_sha256"]:
        raise RuntimeAuditError("E_GITLEAKS_RULESET", "pinned ruleset bytes differ")
    if len(actual) != len(set(actual)) or set(actual) != set(expected):
        raise RuntimeAuditError("E_GITLEAKS_RULESET", "enabled rule inventory differs")
    identity = {"ruleset_sha256": lane["ruleset_sha256"], "rule_ids": sorted(actual)}
    return {
        "state": "VERIFIED",
        "rule_ids": sorted(actual),
        "sha256": digest(identity),
    }


def _gitleaks_rule_ids(config: bytes) -> list[str]:
    toml = _toml_parser()

    try:
        rules = toml.loads(config.decode("utf-8"))["rules"]
        actual = [item["id"] for item in rules]
    except (UnicodeError, KeyError, TypeError, toml.TOMLDecodeError) as exc:
        raise RuntimeAuditError(
            "E_GITLEAKS_RULESET", "pinned ruleset is malformed"
        ) from exc
    if not all(isinstance(rule_id, str) and rule_id for rule_id in actual):
        raise RuntimeAuditError("E_GITLEAKS_RULESET", "enabled rule inventory differs")
    return actual


def _gitleaks_disable_rule(config: bytes, detector_rule_id: str) -> bytes:
    import re

    toml = _toml_parser()

    starts = [
        item.start()
        for item in re.finditer(rb"(?m)^\[\[rules\]\][\t ]*(?:\r?\n|$)", config)
    ]
    if not starts:
        raise RuntimeAuditError("E_GITLEAKS_MUTATION", "rules section missing")
    chunks = [config[: starts[0]]]
    removed = 0
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(config)
        chunk = config[start:end]
        try:
            rule_id = toml.loads(chunk.decode("utf-8"))["rules"][0]["id"]
        except (
            UnicodeError,
            KeyError,
            IndexError,
            TypeError,
            toml.TOMLDecodeError,
        ) as exc:
            raise RuntimeAuditError(
                "E_GITLEAKS_MUTATION", "rule block malformed"
            ) from exc
        if rule_id == detector_rule_id:
            removed += 1
        else:
            chunks.append(chunk)
    mutated = b"".join(chunks)
    original_ids = _gitleaks_rule_ids(config)
    expected = [rule_id for rule_id in original_ids if rule_id != detector_rule_id]
    if removed != 1 or _gitleaks_rule_ids(mutated) != expected:
        raise RuntimeAuditError("E_GITLEAKS_MUTATION", "mutation must disable one rule")
    return mutated


def _toml_parser():
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError as exc:
            raise RuntimeAuditError(
                "E_GITLEAKS_RULESET", "TOML parser is unavailable"
            ) from exc
    return tomllib


def _gitleaks_mutation_valid(
    baseline: bytes, effective: bytes, detector_rule_id: str
) -> bool:
    try:
        return _gitleaks_disable_rule(baseline, detector_rule_id) == effective
    except RuntimeAuditError:
        return False


def _native_sarif_metadata(report: dict, profile: dict, invocations: list) -> dict:
    """Supplement absent metadata from measured execution; preserve native bytes hash."""
    import copy

    report = copy.deepcopy(report)
    runs = report.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= 16:
        raise RuntimeAuditError("E_REPORT_JSON", "native SARIF runs missing")
    for run in runs:
        driver = run["tool"]["driver"]
        if driver.get("version", profile["tool_version"]) != profile["tool_version"]:
            raise RuntimeAuditError(
                "E_TOOLCHAIN_DRIFT", "native report version differs"
            )
        driver.setdefault("version", profile["tool_version"])
        run.setdefault(
            "invocations",
            [
                {
                    "executionSuccessful": True,
                    "properties": {"factory_execution_sha256": digest(invocations)},
                }
            ],
        )
    return report


def _native_junit(
    output: Path, sources: dict, junit_name: str = "runtime.xml"
) -> tuple:
    return _parse_runtime_junit(_junit_bytes(output, junit_name), sources)


def _parse_runtime_junit(junit: bytes, sources: dict) -> tuple:
    import xml.etree.ElementTree as ET

    if (
        len(junit) > LIMIT
        or b"<!DOCTYPE" in junit.upper()
        or b"<!ENTITY" in junit.upper()
    ):
        raise RuntimeAuditError("E_RUNTIME_REPORT", "unsafe or oversized JUnit")
    try:
        tree = ET.fromstring(junit)
    except ET.ParseError as exc:
        raise RuntimeAuditError("E_RUNTIME_REPORT", "invalid native JUnit") from exc
    cases = list(tree.iter("testcase"))
    _junit_suite_counts(tree, cases)
    return _junit_observations(cases, sources, sha256_bytes(junit))


def _junit_suite_counts(tree, cases):
    suites = [tree] if tree.tag == "testsuite" else list(tree.iter("testsuite"))
    if not suites or not cases:
        raise RuntimeAuditError("E_RUNTIME_REPORT", "no executed source-bound tests")
    try:
        declared = sum(int(suite.attrib["tests"]) for suite in suites)
        declared_failures = sum(int(suite.get("failures", "0")) for suite in suites)
        declared_errors = sum(int(suite.get("errors", "0")) for suite in suites)
    except (KeyError, ValueError) as exc:
        raise RuntimeAuditError(
            "E_RUNTIME_REPORT", "JUnit suite counts malformed"
        ) from exc
    actual_failures = sum(case.find("failure") is not None for case in cases)
    actual_errors = sum(case.find("error") is not None for case in cases)
    if (
        declared != len(cases)
        or declared_failures != actual_failures
        or declared_errors != actual_errors
    ):
        raise RuntimeAuditError("E_RUNTIME_REPORT", "JUnit suite counts differ")


def _junit_observations(cases, sources, junit_hash):
    findings, identities, executed = [], set(), []
    for case in cases:
        result = _junit_case(case, sources)
        path, finding, skipped = result
        identity = (path, case.get("classname", ""), case.get("name", ""))
        if identity in identities:
            raise RuntimeAuditError("E_RUNTIME_REPORT", "duplicate JUnit testcase")
        identities.add(identity)
        if not skipped:
            executed.append(path)
        if finding is not None:
            findings.append(finding)
    if not executed:
        raise RuntimeAuditError("E_RUNTIME_REPORT", "no executed source-bound tests")
    harness_path = min(executed)
    findings.sort(key=lambda item: (item["path"], item["line"], item["rule_id"]))
    return (
        len(executed),
        findings,
        {
            "path": harness_path,
            "sha256": sources[harness_path],
        },
        junit_hash,
    )


def _junit_bytes(output, junit_name="runtime.xml"):
    with local_file(output, junit_name).open("rb") as stream:
        junit = stream.read(LIMIT + 1)
    if (
        len(junit) > LIMIT
        or b"<!DOCTYPE" in junit.upper()
        or b"<!ENTITY" in junit.upper()
    ):
        raise RuntimeAuditError("E_RUNTIME_REPORT", "unsafe or oversized JUnit")
    return junit


def _junit_case(case, sources):
    raw_path = case.get("file", "")
    if raw_path.startswith("/src/"):
        raw_path = raw_path.removeprefix("/src/")
    path = relative_path(raw_path)
    if path not in sources:
        raise RuntimeAuditError("E_HARNESS_BINDING", "JUnit test source is unbound")
    if case.find("skipped") is not None:
        return path, None, True
    finding = None
    if case.find("failure") is not None or case.find("error") is not None:
        try:
            line = int(case.get("line", "0")) + 1
        except ValueError as exc:
            raise RuntimeAuditError(
                "E_RUNTIME_REPORT", "invalid JUnit failure line"
            ) from exc
        finding = {
            "rule_id": "RUNTIME_TEST_FAILURE",
            "path": path,
            "line": line,
            "severity": "high",
        }
    return path, finding, False


def _native_coverage_report(
    raw: dict, lane: dict, inventory: dict, output: Path, junit_name="runtime.xml"
) -> dict:
    if raw.get("meta", {}).get("branch_coverage") is not True:
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native branch measurement required"
        )
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    tests, findings, harness, junit_hash = _native_junit(output, sources, junit_name)
    coverage = _native_source_counts(raw, sources)
    return {
        "schema": "factory.deep-runtime-observations.v1",
        "engine": "runtime",
        "tool_version": lane["tool_version"],
        "completed": True,
        "errors": [],
        "harness": harness,
        "metrics": {"tests": tests},
        "findings": findings,
        "source_coverage": coverage,
        "coverage_native_sha256": digest(raw),
        "junit_sha256": junit_hash,
    }


def _native_source_counts(raw: dict, sources: dict) -> dict:
    coverage = {}
    files = raw.get("files")
    if not isinstance(files, dict) or not all(isinstance(name, str) for name in files):
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native coverage files object required"
        )
    for name, measured in files.items():
        path = relative_path(name.removeprefix("/src/"))
        if path not in sources:
            raise RuntimeAuditError("E_RUNTIME_COVERAGE", "coverage source is unbound")
        if path in coverage:
            raise RuntimeAuditError(
                "E_RUNTIME_COVERAGE", "duplicate native coverage source"
            )
        counts = _native_coverage_counts(measured)
        coverage[path] = {
            "sha256": sources[path],
            "lines_total": counts["num_statements"],
            "lines_covered": counts["covered_lines"],
            "branches_total": counts["num_branches"],
            "branches_covered": counts["covered_branches"],
        }
    return coverage


def _native_coverage_counts(measured: dict) -> dict:
    """Validate measured totals before exposing them as runtime facts."""
    if not isinstance(measured, dict) or not isinstance(measured.get("summary"), dict):
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native coverage summary required"
        )
    counts = measured["summary"]
    for field in (
        "num_statements",
        "covered_lines",
        "num_branches",
        "covered_branches",
    ):
        require_int(counts.get(field), field, minimum=0, maximum=10_000_000)
    if (
        counts["covered_lines"] > counts["num_statements"]
        or counts["covered_branches"] > counts["num_branches"]
    ):
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "covered counts exceed measured totals"
        )
    return counts


def _native_runtime_accounting(report: dict, inventory: dict, lane: dict) -> dict:
    """Expose actual observed source accounting separately from requested inventory."""
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    measured = report.get("source_coverage")
    if not isinstance(measured, dict):
        return {
            "state": "UNAVAILABLE",
            "required_paths": sorted(required),
            "measured_paths": [],
            "missing_paths": sorted(required),
        }
    if set(measured) - set(required):
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "measured source is outside declared lane"
        )
    if any(
        not isinstance(item, dict) or item.get("sha256") != required[path]
        for path, item in measured.items()
    ):
        raise RuntimeAuditError("E_RUNTIME_COVERAGE", "measured source hash differs")
    missing = sorted(set(required) - set(measured))
    return {
        "state": "PARTIAL" if missing else "COMPLETE",
        "required_paths": sorted(required),
        "measured_paths": sorted(measured),
        "missing_paths": missing,
    }


def _fuzz_snapshot(
    cov, contract: dict, harness: str, output: Path, state: dict
) -> None:
    raw_path = output.with_suffix(".coverage.json")
    cov.json_report(outfile=str(raw_path))
    raw = strict_json(raw_path.read_bytes())
    sources = {item["path"]: item["sha256"] for item in contract["inventory"]["files"]}
    edges = sum(
        len(item.get("executed_branches", [])) for item in raw["files"].values()
    )
    corpus = _fuzz_corpus_document(state, harness, sources[harness])
    corpus_raw = canonical_bytes(corpus)
    output.with_suffix(".corpus.json").write_bytes(corpus_raw)
    report = {
        "schema": "factory.deep-atheris-observations.v1",
        "engine": "atheris",
        "tool_version": contract["lane"]["tool_version"],
        "completed": state.get("completed", False),
        "errors": state.get("errors", []),
        "harness": {"path": harness, "sha256": sources[harness]},
        "metrics": {
            "executions": state["executions"],
            "corpus_size": len(state["inputs"]),
            "coverage_edges": edges,
        },
        "metric_definitions": {
            "executions": "observed callbacks (lower bound at last snapshot)",
            "corpus_size": "distinct executed inputs retained in the bounded local corpus",
            "coverage_edges": "executed Python branch arcs from coverage.py",
        },
        "findings": state["findings"],
        "source_coverage": _native_source_counts(raw, sources),
        "coverage_native_sha256": digest(raw),
        "corpus": {
            "sha256": sha256_bytes(corpus_raw),
            "inputs": len(corpus["inputs"]),
            "bytes": state.get("corpus_bytes", 0),
        },
        "control_sha256": state.get("control_sha256"),
    }
    output.write_bytes(canonical_bytes(report))


def _fuzz_record_input(state, data):
    import base64

    fingerprint = sha256_bytes(data)
    new_bytes = len(data) if fingerprint not in state["inputs"] else 0
    limits = (
        len(data) > 1_048_576,
        state["executions"] >= 1_000_000,
        fingerprint not in state["inputs"] and len(state["inputs"]) >= 4096,
        state.get("corpus_bytes", 0) + new_bytes > 2_097_152,
    )
    if any(limits):
        state.update(completed=False, errors=["E_FUZZ_BUDGET"])
        raise RuntimeAuditError(
            "E_FUZZ_BUDGET", "bounded fuzz observation budget exhausted"
        )
    state["executions"] += 1
    state["inputs"].add(fingerprint)
    state.setdefault("corpus", {})[fingerprint] = {
        "sha256": fingerprint,
        "bytes": len(data),
        "data_base64": base64.b64encode(data).decode("ascii"),
    }
    state["corpus_bytes"] = state.get("corpus_bytes", 0) + new_bytes


def _fuzz_corpus_document(state, harness, source_sha):
    corpus = state.get("corpus", {})
    if set(corpus) != state["inputs"]:
        raise RuntimeAuditError("E_FUZZ_CORPUS", "recorded inputs and corpus differ")
    return {
        "schema": "factory.fuzz-corpus.v1",
        "harness": {"path": harness, "sha256": source_sha},
        "inputs": [corpus[key] for key in sorted(corpus)],
    }


def _fuzz_corpus_entry(entry):
    import base64

    if not isinstance(entry, dict) or set(entry) != {"sha256", "bytes", "data_base64"}:
        raise ValueError("exact corpus entry fields required")
    size = require_int(entry["bytes"], "input bytes", minimum=0, maximum=1_048_576)
    encoded = entry["data_base64"]
    if not isinstance(encoded, str) or len(encoded) > 1_398_104:
        raise ValueError("bounded input required")
    data = base64.b64decode(encoded, validate=True)
    if (
        len(data) != size
        or base64.b64encode(data).decode("ascii") != encoded
        or sha256_bytes(data) != entry["sha256"]
    ):
        raise ValueError("corpus input differs")
    return size


def _validate_fuzz_corpus(raw, report, sources):
    try:
        corpus = strict_json(raw)
        if set(corpus) != {"schema", "harness", "inputs"}:
            raise ValueError("exact corpus fields required")
        if (
            corpus["schema"] != "factory.fuzz-corpus.v1"
            or canonical_bytes(corpus) != raw
        ):
            raise ValueError("canonical corpus required")
        harness = corpus["harness"]
        if (
            set(harness) != {"path", "sha256"}
            or harness != report["harness"]
            or sources[relative_path(harness["path"])] != harness["sha256"]
        ):
            raise ValueError("harness binding differs")
        _validate_fuzz_corpus_inputs(corpus["inputs"], report, raw)
        return corpus
    except (RuntimeAuditError, ValueError, TypeError, KeyError, UnicodeError) as error:
        raise RuntimeAuditError(
            "E_FUZZ_CORPUS", "invalid retained fuzz corpus"
        ) from error


def _validate_fuzz_corpus_inputs(inputs, report, raw):
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 4096:
        raise ValueError("bounded nonempty corpus required")
    sizes = [_fuzz_corpus_entry(entry) for entry in inputs]
    hashes = [entry["sha256"] for entry in inputs]
    if hashes != sorted(set(hashes)) or sum(sizes) > 2_097_152:
        raise ValueError("corpus uniqueness or budget differs")
    expected = {"sha256": sha256_bytes(raw), "inputs": len(inputs), "bytes": sum(sizes)}
    require_int(report["corpus"]["inputs"], "retained inputs", minimum=1, maximum=4096)
    require_int(
        report["corpus"]["bytes"], "retained bytes", minimum=0, maximum=2_097_152
    )
    require_int(
        report["metrics"]["executions"], "callbacks", minimum=1, maximum=1_000_000
    )
    if report["corpus"] != expected or report["metrics"]["corpus_size"] != len(inputs):
        raise ValueError("corpus accounting differs")
    if report["metrics"]["executions"] < len(inputs):
        raise ValueError("corpus exceeds observed callbacks")
    for finding in report["findings"]:
        if finding.get("input_sha256") not in hashes:
            raise ValueError("failure input is not retained")


def _retained_fuzz_corpus(report, sources):
    try:
        raw = _codeql_blob_bytes(report.get("fuzz_corpus"), maximum=4_194_304)
        return _validate_fuzz_corpus(raw, report, sources)
    except RuntimeAuditError as error:
        raise RuntimeAuditError(
            "E_FUZZ_CORPUS", "retained fuzz evidence rejected"
        ) from error


def _fuzz_replay_expected(request, validated_controls=None):
    keys = {"lane", "inventory", "coverage", "report"}
    if isinstance(request, dict) and {"challenges", "obligations"} <= set(request):
        keys |= {"challenges", "obligations"}
    exact_keys(request, keys)
    lane, inventory, report = request["lane"], request["inventory"], request["report"]
    if lane["engine"] != "atheris" or lane["family"] != "fuzz":
        raise RuntimeAuditError("E_FUZZ_REPLAY", "fuzz lane required")
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    corpus = _retained_fuzz_corpus(report, sources)
    expected = {
        "schema": "factory.fuzz-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": require_digest(inventory["candidate_sha256"], "candidate"),
        "lane_sha256": digest(lane),
        "coverage_sha256": digest(request["coverage"]),
        "report_sha256": digest(report),
        "corpus_sha256": report["corpus"]["sha256"],
        "harness": corpus["harness"],
        "replayed_inputs": len(corpus["inputs"]),
        "failure_inputs": sorted({item["input_sha256"] for item in report["findings"]}),
    }
    if "obligations" in request:
        controls = validated_controls or verify_fuzz_retained_evidence(
            request["challenges"],
            request["obligations"],
            lane,
            sources,
            inventory["candidate_sha256"],
            request["coverage"],
        )
        expected.update(controls[0])
    return expected


def _fuzz_replay_inputs_main(request_path, source):
    """Image-owned driver; replay unique retained inputs in canonical hash order."""
    import base64
    import importlib.util

    with Path(request_path).open("rb") as stream:
        request = strict_json(stream.read(LIMIT + 1))
    retained_controls = None
    if "obligations" in request:
        retained_controls = verify_fuzz_retained_evidence(
            request["challenges"],
            request["obligations"],
            request["lane"],
            {item["path"]: item["sha256"] for item in request["inventory"]["files"]},
            request["inventory"]["candidate_sha256"],
            request["coverage"],
        )
    expected = _fuzz_replay_expected(request, retained_controls)
    sources = {item["path"]: item["sha256"] for item in request["inventory"]["files"]}
    corpus = _retained_fuzz_corpus(request["report"], sources)
    path = local_file(Path(source), corpus["harness"]["path"])
    bound_bytes(Path(source), corpus["harness"])
    spec = importlib.util.spec_from_file_location("factory_fuzz_replay_target", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    failures = _fuzz_replay_harness(module, corpus["inputs"], base64)
    result = {
        "schema": "factory.fuzz-input-replay.v1",
        "harness": expected["harness"],
        "corpus_sha256": expected["corpus_sha256"],
        "replayed_inputs": len(corpus["inputs"]),
        "failure_inputs": sorted(failures),
    }
    if "obligations" in request:
        result["controls"] = _fuzz_replay_controls(retained_controls[1], source, base64)
    return result


def _fuzz_replay_harness(module, inputs, base64):
    failures = []
    for entry in inputs:
        try:
            module.TestOneInput(base64.b64decode(entry["data_base64"], validate=True))
        except Exception:
            failures.append(entry["sha256"])
    return failures


def _fuzz_replay_controls(controls, source, base64):
    results = []
    for control in controls:
        module = _fuzz_replay_module(source, control)
        failures = _fuzz_replay_harness(module, control["corpus"]["inputs"], base64)
        reported = sorted(
            {item["input_sha256"] for item in control["report"]["findings"]}
        )
        enabled = _fuzz_control_ids(control["config"]) == ["FUZZ_EXCEPTION"]
        detected = failures if enabled else []
        results.append(
            {
                "obligation_id": control["obligation_id"],
                "kind": control["kind"],
                "failure_inputs": sorted(failures),
                "detector_inputs": sorted(detected),
                "retained_failure_inputs": reported,
            }
        )
    return results


def _fuzz_replay_module(source, control):
    import importlib.util

    path = local_file(source, control["harness"]["path"])
    bound_bytes(source, control["harness"])
    module_name = "factory_fuzz_control_" + control["obligation_id"]
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeAuditError("E_FUZZ_REPLAY", "control harness cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not callable(getattr(module, "TestOneInput", None)):
        raise RuntimeAuditError("E_FUZZ_REPLAY", "control callback is missing")
    return module


def _fuzz_replay_profile(request):
    profile = strict_json(Path("/opt/factory/adapter-profile.json").read_bytes())
    lane, coverage = request["lane"], request["coverage"]
    _native_profile(profile, lane)
    expected = {
        "profile_sha256": digest(profile),
        "image_binding_sha256": sha256_bytes(lane["image"].encode("utf-8")),
        "tool_version": profile["tool_version"],
        "ruleset_sha256": profile["ruleset_sha256"],
    }
    if any(coverage.get(key) != value for key, value in expected.items()):
        raise RuntimeAuditError("E_FUZZ_REPLAY", "pinned fuzz profile binding differs")


def execute_fuzz_native_replay(request, source, scratch, timeout):
    """Re-execute retained fuzz inputs under a bounded isolated worker lifecycle."""
    from .runtime_audit_process import run_bounded_command

    retained_controls = _fuzz_replay_control_evidence(request)
    expected = _fuzz_replay_expected(request, retained_controls)
    timeout = require_int(timeout, "fuzz replay timeout", minimum=1, maximum=3600)
    deadline = time.monotonic() + timeout
    _fuzz_replay_profile(request)
    _adapter_sources(source, request["inventory"])
    contract = scratch / "fuzz-replay-input.json"
    contract.write_bytes(canonical_bytes(request))
    capture = scratch / "fuzz-replay-output.json"
    runtime = str(Path(__file__).resolve().parent.parent)
    program = (
        "import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);"
        "from factoryline.deep_audit_io import _fuzz_replay_inputs_main;"
        "print(json.dumps(_fuzz_replay_inputs_main(sys.argv[2],Path(sys.argv[3]))),flush=True)"
    )
    facts = run_bounded_command(
        [
            "/usr/local/bin/python",
            "-I",
            "-c",
            program,
            runtime,
            str(contract),
            str(source),
        ],
        source,
        _fuzz_replay_remaining(deadline),
        scratch,
        stdout_path=capture,
    )
    with capture.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    _validate_fuzz_replay_observation(
        raw, facts, expected, retained_controls[1] if retained_controls else None
    )
    _adapter_sources(source, request["inventory"])
    _fuzz_replay_remaining(deadline)
    return {**expected, "native_execution_sha256": digest(facts)}


def _fuzz_replay_control_evidence(request):
    if "obligations" not in request:
        return None
    inventory = request["inventory"]
    return verify_fuzz_retained_evidence(
        request["challenges"],
        request["obligations"],
        request["lane"],
        {item["path"]: item["sha256"] for item in inventory["files"]},
        inventory["candidate_sha256"],
        request["coverage"],
    )


def _fuzz_replay_remaining(deadline):
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError("E_FUZZ_REPLAY", "fuzz replay deadline exhausted")
    return remaining


def _validate_fuzz_replay_observation(raw, facts, expected, controls=None):
    from .runtime_audit_common import _validate_runner_facts

    _validate_runner_facts(facts, facts["timeout_seconds"])
    if _adapter_command_failed(facts, [0], float("inf")) or facts.get("cancelled"):
        raise RuntimeAuditError("E_FUZZ_REPLAY", "fuzz replay process failed")
    if sha256_bytes(raw) != facts["stdout_sha256"] or len(raw) != facts["stdout_bytes"]:
        raise RuntimeAuditError("E_FUZZ_REPLAY", "fuzz replay stream differs")
    observed = strict_json(raw)
    require_int(
        observed.get("replayed_inputs"), "replayed inputs", minimum=1, maximum=4096
    )
    fields = {
        key: expected[key]
        for key in ("harness", "corpus_sha256", "replayed_inputs", "failure_inputs")
    }
    expected_observation = {"schema": "factory.fuzz-input-replay.v1", **fields}
    if controls is not None:
        expected_observation["controls"] = observed.get("controls")
        _validate_fuzz_replayed_controls(observed.get("controls"), controls)
    if observed != expected_observation:
        raise RuntimeAuditError("E_FUZZ_REPLAY", "retained input outcomes differ")


def _validate_fuzz_replayed_controls(observed, controls):
    if not isinstance(observed, list) or len(observed) != len(controls):
        raise RuntimeAuditError("E_FUZZ_REPLAY", "retained controls are incomplete")
    for actual, expected in zip(observed, controls):
        if not isinstance(actual, dict) or set(actual) != {
            "obligation_id",
            "kind",
            "failure_inputs",
            "detector_inputs",
            "retained_failure_inputs",
        }:
            raise RuntimeAuditError("E_FUZZ_REPLAY", "control replay shape differs")
        _validate_fuzz_replayed_control(actual, expected)


def _validate_fuzz_replayed_control(actual, expected):
    kind = expected["kind"]
    failures = actual["failure_inputs"]
    retained = expected["retained_failure_inputs"]
    if (
        actual["obligation_id"] != expected["obligation_id"]
        or kind != actual["kind"]
        or actual["retained_failure_inputs"] != retained
        or not _fuzz_replayed_failure_inputs_valid(failures, expected)
    ):
        raise RuntimeAuditError("E_FUZZ_REPLAY", "control exception replay differs")
    detected = failures if expected["detector_enabled"] else []
    if actual["detector_inputs"] != detected:
        raise RuntimeAuditError("E_FUZZ_REPLAY", "control detector result differs")


def _fuzz_replayed_failure_inputs_valid(failures, expected):
    if not isinstance(failures, list) or any(not _is_digest(item) for item in failures):
        return False
    if failures != sorted(set(failures)):
        return False
    if not set(failures) <= expected["corpus_hashes"]:
        return False
    kind = expected["kind"]
    if kind == "positive":
        return failures == expected["retained_failure_inputs"]
    if kind == "negative":
        return not failures
    return kind == "mutation" and bool(failures)


def _is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _finalize_fuzz_report(raw, invocations):
    from .runtime_audit_common import _validate_runner_facts

    if len(invocations) != 1 or raw.get("errors") != []:
        raise RuntimeAuditError(
            "E_FUZZ_REPORT", "one successful bounded fuzz lifecycle required"
        )
    facts = invocations[0]["execution"]
    _validate_runner_facts(facts, facts["timeout_seconds"])
    expected = 77 if raw.get("findings") else 0
    failures = (
        facts.get(key)
        for key in ("timed_out", "launch_error", "output_limit_exceeded", "cancelled")
    )
    if (
        any(failures)
        or not facts["cleanup_confirmed"]
        or facts["exit_code"] != expected
    ):
        raise RuntimeAuditError(
            "E_FUZZ_REPORT", "fuzz result and process termination differ"
        )
    report = dict(raw)
    report.update(completed=True, lifecycle_execution_sha256=digest(facts))
    return report


def _fuzz_control_ids(raw):
    value = strict_json(raw)
    if (
        canonical_bytes(value) != raw
        or set(value) != {"schema", "rules"}
        or value["schema"] != "factory.fuzz-control.v1"
        or not isinstance(value["rules"], dict)
        or set(value["rules"]) != {"FUZZ_EXCEPTION"}
        or type(value["rules"]["FUZZ_EXCEPTION"]) is not bool
    ):
        raise RuntimeAuditError(
            "E_FUZZ_CONTROL", "canonical exact fuzz rule config required"
        )
    return ["FUZZ_EXCEPTION"] if value["rules"]["FUZZ_EXCEPTION"] else []


def _fuzz_disable_rule(raw, rule_id):
    if rule_id != "FUZZ_EXCEPTION" or _fuzz_control_ids(raw) != [rule_id]:
        raise RuntimeAuditError("E_FUZZ_CONTROL", "enabled exact fuzz rule required")
    value = strict_json(raw)
    value["rules"][rule_id] = False
    return canonical_bytes(value)


def _fuzz_control_args(argv):
    path = Path("/opt/factory/rules/fuzz-control.json")
    offset = 3
    if len(argv) < 3:
        raise RuntimeAuditError(
            "E_FUZZ_CONTROL", "closed fuzz native arguments required"
        )
    if argv[2].startswith("--factory-control="):
        path = Path(argv[2].removeprefix("--factory-control="))
        offset = 4
    if len(argv) < offset or argv[offset - 1] != "--":
        raise RuntimeAuditError(
            "E_FUZZ_CONTROL", "closed fuzz native arguments required"
        )
    with path.open("rb") as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise RuntimeAuditError("E_FUZZ_CONTROL", "fuzz config budget exceeded")
    return _fuzz_control_ids(raw), sha256_bytes(raw), argv[offset:]


def _fuzz_execution_contract(contract, source):
    if source == Path("/src"):
        return contract
    bindings = {item["path"]: item for item in contract["inventory"]["files"]}
    names = _adapter_source_files(source)
    if not names or not names <= bindings.keys():
        raise RuntimeAuditError("E_FUZZ_CONTROL", "fixture source is not inventoried")
    inventory = {
        **contract["inventory"],
        "files": [bindings[name] for name in sorted(names)],
    }
    _adapter_sources(source, inventory)
    return {**contract, "inventory": inventory}


def _fuzz_profile_preflight(profile, lane):
    if lane["engine"] != "atheris":
        return None
    path = Path("/opt/factory/rules/fuzz-control.json")
    raw = path.read_bytes()
    if sha256_bytes(raw) != profile["ruleset_sha256"] or _fuzz_control_ids(raw) != [
        "FUZZ_EXCEPTION"
    ]:
        raise RuntimeAuditError("E_FUZZ_CONTROL", "pinned baseline fuzz rule required")
    return path


def native_fuzz_main(argv: list[str]) -> int:
    """Image-owned Atheris lifecycle; candidate exports only TestOneInput(bytes)."""
    import atheris
    import coverage
    import importlib.util
    import sys

    harness_path, output = Path(argv[0]), Path(argv[1])
    contract = strict_json(Path("/factory-contract.json").read_bytes())
    root = Path.cwd()
    contract = _fuzz_execution_contract(contract, root)
    harness = harness_path.relative_to(root).as_posix()
    sources = {item["path"]: item["sha256"] for item in contract["inventory"]["files"]}
    bound_bytes(root, {"path": harness, "sha256": sources[harness]})
    rule_ids, control_sha, native_args = _fuzz_control_args(argv)
    cov = coverage.Coverage(branch=True, data_file=None, source=[str(root)])
    cov.start()
    sys.dont_write_bytecode = True
    with atheris.instrument_imports():
        spec = importlib.util.spec_from_file_location(
            "factory_fuzz_target", harness_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    target = module.TestOneInput
    state = {
        "executions": 0,
        "inputs": set(),
        "findings": [],
        "completed": False,
        "control_sha256": control_sha,
    }

    def callback(data):
        try:
            _fuzz_record_input(state, data)
        except RuntimeAuditError:
            _fuzz_snapshot(cov, contract, harness, output, state)
            raise
        try:
            target(data)
        except Exception:
            if "FUZZ_EXCEPTION" in rule_ids:
                state["completed"] = True
                state["findings"].append(
                    {
                        "rule_id": "FUZZ_EXCEPTION",
                        "path": harness,
                        "line": 1,
                        "severity": "high",
                        "input_sha256": sha256_bytes(data),
                    }
                )
                _fuzz_snapshot(cov, contract, harness, output, state)
                raise
        if state["executions"] == 1 or state["executions"] % 64 == 0:
            _fuzz_snapshot(cov, contract, harness, output, state)

    atheris.Setup([sys.argv[0], *native_args], atheris.instrument_func(callback))
    atheris.Fuzz()
    state["completed"] = True
    _fuzz_snapshot(cov, contract, harness, output, state)
    return 0


def _native_report(
    raw: dict, profile: dict, contract: dict, output: Path, invocations: list
) -> dict:
    import copy

    sources = {item["path"]: item["sha256"] for item in contract["inventory"]["files"]}
    if profile["report_format"] == "sarif":
        report = _native_sarif_metadata(raw, profile, invocations)
        return _native_sarif_paths(report, sources)
    if profile["report_format"] == "runtime-junit":
        report = _runtime_report_file(
            raw, contract["lane"], contract["inventory"], output
        )
        _runtime_exit_consistency(report, invocations)
        return report
    if profile["report_format"] == "coverage-json":
        return _native_coverage_report(
            raw,
            contract["lane"],
            contract["inventory"],
            output,
        )
    if profile["engine"] == "atheris":
        report = _finalize_fuzz_report(raw, invocations)
        corpus_path = output / Path(contract["lane"]["report"]).with_suffix(
            ".corpus.json"
        )
        with local_file(output, corpus_path.relative_to(output).as_posix()).open(
            "rb"
        ) as stream:
            corpus_raw = stream.read(4_194_305)
        if len(corpus_raw) > 4_194_304:
            raise RuntimeAuditError("E_FUZZ_CORPUS", "corpus artifact budget exceeded")
        _validate_fuzz_corpus(corpus_raw, report, sources)
        report["fuzz_corpus"] = _codeql_native_blob(corpus_raw, maximum=4_194_304)
        return report
    report = copy.deepcopy(raw)
    _native_dependency_paths(report, profile["report_format"], sources)
    return report


def _native_source_path(uri: str, sources: dict, *, scan_root: bool = False) -> str:
    require_str(uri, "native source URI", maximum=2048)
    path = uri.removeprefix("file:///src/").removeprefix("/src/")
    if scan_root and path.startswith("/"):
        path = path[1:]  # Native Syft directory locations start at the scan root.
    path = relative_path(path)
    if path not in sources:
        raise RuntimeAuditError("E_TRACE_UNBOUND", "native source is outside candidate")
    return path


def _native_artifact_path(artifact: dict, run: dict, sources: dict) -> str:
    uri, indexed_uri = _native_artifact_uri(artifact, run)
    path = _native_source_path(uri, sources)
    if indexed_uri is not None and _native_source_path(indexed_uri, sources) != path:
        raise RuntimeAuditError(
            "E_SARIF_INDIRECTION", "native artifact reference differs"
        )
    return path


def _native_artifact_uri(artifact, run):
    indexed_uri = None
    if "index" in artifact:
        indexed_uri = _indexed_artifact_uri(artifact, run)
        if not isinstance(indexed_uri, dict):
            raise RuntimeAuditError(
                "E_SARIF_INDIRECTION", "indexed artifact is invalid"
            )
    value = artifact if "uri" in artifact else indexed_uri
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_SARIF_INDIRECTION", "native source URI missing")
    uri = require_str(value.get("uri"), "native source URI", maximum=2048)
    absolute_source = uri.startswith(("/src/", "file:///src/"))
    if "uriBaseId" in value and not absolute_source:
        base = run.get("originalUriBaseIds", {}).get(value["uriBaseId"], {})
        if base.get("uri") not in {"file:///src/", "file:///src", "/src/"}:
            raise RuntimeAuditError(
                "E_SARIF_INDIRECTION", "untrusted native source base"
            )
    return uri, indexed_uri.get("uri") if indexed_uri is not None else None


def _indexed_artifact_uri(artifact, run):
    index = require_int(artifact["index"], "artifact index", minimum=0, maximum=49999)
    items = run.get("artifacts", [])
    if index >= len(items):
        raise RuntimeAuditError("E_SARIF_INDIRECTION", "artifact index is absent")
    return items[index]["location"]


def _native_sarif_paths(report: dict, sources: dict) -> dict:
    for run in report["runs"]:
        stack = [run]
        count = 0
        while stack:
            item = stack.pop()
            count += 1
            if count > 200000:
                raise RuntimeAuditError(
                    "E_REPORT_SIZE", "native SARIF tree exceeds budget"
                )
            if isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, dict):
                if "artifactLocation" in item:
                    artifact = item["artifactLocation"]
                    path = _native_artifact_path(artifact, run, sources)
                    artifact.update(uri=path)
                    artifact.pop("uriBaseId", None)
                    artifact.pop("index", None)
                stack.extend(item.values())
    return report


def _native_dependency_paths(report: dict, kind: str, sources: dict) -> None:
    if kind == "osv-json":
        for result in report.get("results", []):
            result["source"]["path"] = _native_source_path(
                result["source"]["path"], sources
            )
    elif kind == "syft-json":
        for artifact in report.get("artifacts", []):
            for location in artifact.get("locations", []):
                location["path"] = _native_source_path(
                    location["path"], sources, scan_root=True
                )


def execute_native_profile(
    profile: dict, contract: dict, source: Path, output: Path
) -> dict:
    """Run native tools; incomplete coverage/challenges remain explicit, never inferred."""
    inventory, lane = _adapter_contract_parts(contract)
    _native_profile(profile, lane)
    _adapter_sources(source, inventory)
    if lane["engine"] == "gitleaks":
        _gitleaks_preflight(inventory, lane, contract)
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        _runtime_ruleset_preflight(lane)
    paths = _adapter_output_paths(lane, output, create_parents=True)
    started = time.monotonic()
    execution = _run_native_profile(
        profile, contract, Path(source), Path(output), inventory, lane, paths
    )
    report = _native_report(
        execution["raw_report"],
        profile,
        contract,
        Path(output),
        execution["invocations"],
    )
    challenges, covered_obligations = _native_profile_challenges(
        profile, contract, Path(source), lane, execution, started
    )
    coverage = _native_profile_coverage(
        execution, report, inventory, lane, profile, challenges, covered_obligations
    )
    if lane["engine"] == "osv":
        required = {
            item["path"]: item["sha256"]
            for item in inventory["files"]
            if item["language"] in lane["languages"]
        }
        coverage["osv_native_evidence"] = _osv_primary_evidence(execution, required)
    artifacts = {
        paths[0]: report,
        paths[1]: coverage,
        paths[2]: challenges,
    }
    bundle = {
        "schema": "factory.deep-worker.v1",
        "run_id": contract["run_id"],
        "candidate_sha256": inventory["candidate_sha256"],
        "artifacts": artifacts,
    }
    _bounded_json_bytes(
        bundle,
        LIMIT,
        "E_WORKER_BUNDLE_SIZE",
        len(coverage.get("sources", {})),
        len(lane.get("rule_ids", [])),
    )
    for path in paths[1:]:
        (output / path).write_bytes(canonical_bytes(artifacts[path]))
    return bundle


def _native_profile_challenges(profile, contract, source, lane, execution, started):
    challenges = {"schema": "factory.deep-challenges.v1", "observations": []}
    covered_obligations = []
    if lane["engine"] == "gitleaks":
        challenges, covered_obligations = _gitleaks_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "trivy":
        challenges, covered_obligations = _trivy_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "semgrep" and "native_artifact_roles" in lane:
        challenges, covered_obligations = _semgrep_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        challenges, covered_obligations = _runtime_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "codeql" and "native_artifact_roles" in lane:
        challenges, covered_obligations = _codeql_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "osv" and "native_policy" in lane:
        challenges, covered_obligations = _osv_challenges(
            profile, contract, source, lane, execution, started
        )
    elif lane["engine"] == "atheris" and "native_artifact_roles" in lane:
        challenges, covered_obligations = _atheris_challenges(
            profile, contract, source, lane, execution, started
        )
    return challenges, covered_obligations


def _atheris_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "atheris" and item["family"] == lane["family"]
    ]


def _atheris_challenge_gaps(obligations, code):
    return _challenge_bundle(
        [],
        [
            _challenge_gap_record(item, challenge, code)
            for item in obligations
            for challenge in item["challenges"]
        ],
    )


def _atheris_challenge_command(profile):
    if profile.get("engine") != "atheris" or len(profile.get("commands", [])) != 1:
        raise RuntimeAuditError("E_FUZZ_PROFILE", "one pinned Atheris command required")
    command = profile["commands"][0]
    argv = list(command.get("argv", []))
    prefix = [
        "/usr/local/bin/python",
        "-I",
        "-m",
        "factoryline.deep_audit_io",
        "native-fuzz",
        "{fixture}",
        "{report}",
        "--factory-control={config}",
        "--",
    ]
    if (
        argv[: len(prefix)] != prefix
        or argv[len(prefix) :] != ["-runs=1000", "-artifact_prefix={scratch}/"]
        or command.get("accepted_exit_codes") != [0, 77]
    ):
        raise RuntimeAuditError("E_FUZZ_PROFILE", "pinned Atheris argv differs")
    return {"argv": argv, "accepted_exit_codes": command["accepted_exit_codes"]}


def _atheris_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    obligations = _atheris_obligations(contract, lane)
    if (
        len(obligations) > 64
        or sum(len(item["challenges"]) for item in obligations) > 192
    ):
        return _atheris_challenge_gaps(obligations, "E_FUZZ_CHALLENGE_BUDGET"), []
    if not obligations:
        return _challenge_bundle([], []), []
    try:
        baseline_path = local_file(Path("/opt/factory/rules"), "fuzz-control.json")
        baseline = baseline_path.read_bytes()
        if (
            lane.get("rule_ids") != ["FUZZ_EXCEPTION"]
            or lane.get("ruleset_sha256") != profile.get("ruleset_sha256")
            or sha256_bytes(baseline) != lane["ruleset_sha256"]
            or _fuzz_control_ids(baseline) != ["FUZZ_EXCEPTION"]
        ):
            raise RuntimeAuditError("E_FUZZ_CONTROL", "signed fuzz baseline differs")
        command = _atheris_challenge_command(profile)
    except (OSError, RuntimeAuditError, ValueError, TypeError, KeyError) as exc:
        return _atheris_challenge_gaps(obligations, _challenge_error_code(exc)), []

    observations, gaps = [], []
    deadline = started + lane["timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="factory-atheris-challenges-") as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _atheris_challenge_control(
                    run_bounded_command,
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    command,
                    baseline_path,
                    baseline,
                    obligation,
                    challenge,
                    Path(root) / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                )
    return _challenge_bundle(observations, gaps), []


def _atheris_challenge_control(
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    expected_exit = {"positive": 77, "negative": 0, "mutation": 0}.get(
        challenge.get("kind")
    )
    if expected_exit is None or challenge.get("expected_exit_code") != expected_exit:
        gaps.append(_challenge_gap_record(obligation, challenge, "E_FUZZ_PROFILE"))
        return
    if expected_exit not in command["accepted_exit_codes"]:
        gaps.append(_challenge_gap_record(obligation, challenge, "E_FUZZ_PROFILE"))
        return
    try:
        observation = _run_atheris_challenge(
            _native_challenge_executor(),
            runner,
            profile,
            contract,
            source,
            lane,
            execution,
            command,
            baseline_path,
            baseline,
            obligation,
            challenge,
            case,
            deadline,
        )
        observations.append(observation)
        try:
            _atheris_challenge_retained_budget(observations)
        except RuntimeAuditError:
            observations.pop()
            raise
        if observation.get("execution", {}).get("status") != "VERIFIED":
            gaps.append(
                _challenge_gap_record(
                    obligation, challenge, "E_FUZZ_CHALLENGE_EXECUTION"
                )
            )
        gaps.append(
            _challenge_gap_record(
                obligation, challenge, "FUZZ_CHALLENGE_REPLAY_REQUIRED"
            )
        )
    except (OSError, RuntimeAuditError, ValueError, TypeError, KeyError) as exc:
        gaps.append(
            _challenge_gap_record(obligation, challenge, _challenge_error_code(exc))
        )


def _run_atheris_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
):
    manifest = challenge.get("fixture_manifest")
    if not isinstance(manifest, dict) or not manifest:
        raise RuntimeAuditError(
            "E_CHALLENGE_MANIFEST", "signed fixture manifest required"
        )
    manifest = dict(sorted(manifest.items()))
    _semgrep_fixture_binding(manifest, obligation, source, challenge["fixture_path"])
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in manifest.items():
        target = challenge_root.joinpath(*relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bound_bytes(source, {"path": path, "sha256": source_sha}))
    challenge_sha = digest(manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = case / "fuzz-control.json"
        config_path.write_bytes(
            _fuzz_disable_rule(baseline, obligation["detector_rule_id"])
        )
    scratch = case / "run"
    report_path = scratch / "report.json"
    corpus_path = report_path.with_suffix(".corpus.json")
    ledger_path = scratch / "unused-ledger.json"
    bindings = {
        "source": str(challenge_root),
        "output": str(scratch),
        "report": str(report_path),
        "scratch": str(scratch),
        "candidate_sha256": challenge_sha,
        "factory_ledger": str(ledger_path),
        "config": str(config_path),
        "fixture": str(challenge_root / challenge["fixture_path"]),
    }
    retained = {}

    def report_parser(raw):
        with local_file(scratch, corpus_path.name).open("rb") as stream:
            corpus_raw = stream.read(LIMIT + 1)
        if len(corpus_raw) > LIMIT:
            raise RuntimeAuditError("E_FUZZ_CORPUS", "retained corpus exceeds budget")
        with local_file(config_path.parent, config_path.name).open("rb") as stream:
            effective = stream.read(4097)
        if len(effective) > 4096:
            raise RuntimeAuditError("E_FUZZ_CONTROL", "control config exceeds budget")
        normalized = _atheris_challenge_report(
            raw, corpus_raw, effective, challenge, lane, manifest
        )
        retained.update(
            {
                "schema": "factory.atheris-retained-challenge.v1",
                "source_manifest": manifest,
                "source_manifest_sha256": digest(manifest),
                "raw_report": _codeql_native_blob(raw, LIMIT),
                "corpus_manifest": _codeql_native_blob(corpus_raw, LIMIT),
                "effective_config": _codeql_native_blob(effective, 4096),
            }
        )
        return normalized

    timeout = int(deadline - time.monotonic())
    if timeout < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )
    observation = execute(
        challenge,
        obligation_id=obligation["id"],
        engine="atheris",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings={
            "candidate_sha256": contract["inventory"]["candidate_sha256"],
            "challenge_source_sha256": challenge_sha,
            "profile_sha256": digest(profile),
            "image_sha256": sha256_bytes(lane["image"].encode("utf-8")),
            "tool_version": profile["tool_version"],
            "version_probe_sha256": digest(execution["version_probe"]),
            "version_probe_facts": execution["version_probe"],
        },
        runner=runner,
        report_parser=report_parser,
        config_rule_ids=_fuzz_control_ids,
        verify_mutation=lambda old, new, rule: _fuzz_disable_rule(old, rule) == new,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"fuzz_result": report_path, "corpus_manifest": corpus_path},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["atheris_native_evidence"] = retained
    _osv_check_deadline(deadline)
    return observation


def _atheris_challenge_report(
    raw, corpus_raw, effective_config, challenge, lane, manifest
):
    report = strict_json(raw)
    if (
        canonical_bytes(report) != raw
        or report.get("schema") != "factory.deep-atheris-observations.v1"
        or report.get("engine") != "atheris"
        or report.get("tool_version") != lane["tool_version"]
        or type(report.get("completed")) is not bool
        or (challenge["kind"] == "positive" and report["completed"] is not True)
        or report.get("errors") != []
        or report.get("control_sha256") != sha256_bytes(effective_config)
    ):
        raise RuntimeAuditError("E_FUZZ_REPORT", "native control report differs")
    harness_path = challenge["fixture_path"]
    harness = {"path": harness_path, "sha256": manifest[harness_path]}
    sources = dict(manifest)
    if report.get("harness") != harness:
        raise RuntimeAuditError("E_FUZZ_REPORT", "native harness binding differs")
    corpus = _validate_fuzz_corpus(corpus_raw, report, sources)
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise RuntimeAuditError("E_FUZZ_REPORT", "native findings list required")
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != {"rule_id", "path", "line", "severity", "input_sha256"}
            or finding.get("rule_id") != "FUZZ_EXCEPTION"
            or finding.get("path") != harness_path
            or type(finding.get("line")) is not int
            or finding.get("line") != 1
            or finding.get("severity") != "high"
        ):
            raise RuntimeAuditError("E_FUZZ_REPORT", "unknown or unbound fuzz finding")
        input_sha = require_digest(finding.get("input_sha256"), "input_sha256")
        if input_sha not in {item["sha256"] for item in corpus["inputs"]}:
            raise RuntimeAuditError("E_FUZZ_REPORT", "finding input is not retained")
    expected_count = 1 if challenge["kind"] == "positive" else 0
    if len(findings) != expected_count:
        raise RuntimeAuditError("E_FUZZ_REPORT", "fuzz control semantics differ")
    if _fuzz_control_ids(effective_config) != (
        ["FUZZ_EXCEPTION"] if challenge["kind"] != "mutation" else []
    ):
        raise RuntimeAuditError("E_FUZZ_CONTROL", "effective detector state differs")
    normalized_findings = (
        [{"rule_id": "FUZZ_EXCEPTION", "path": harness_path, "severity": "high"}]
        if findings
        else []
    )
    return {
        "schema": "factory.atheris-challenge-observation.v1",
        "kind": challenge["kind"],
        "control_sha256": sha256_bytes(effective_config),
        "harness": harness,
        "findings": normalized_findings,
    }


def _atheris_challenge_retained_budget(observations):
    total = 0
    for observation in observations:
        evidence = observation.get("atheris_native_evidence", {})
        for key in ("raw_report", "corpus_manifest", "effective_config"):
            total += require_int(
                evidence.get(key, {}).get("bytes"),
                "Atheris retained bytes",
                minimum=0,
                maximum=LIMIT,
            )
    if total > NATIVE_COVERAGE_LIMIT:
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "retained controls exceed budget")


def verify_fuzz_retained_evidence(
    challenges, obligations, lane, sources, candidate_sha256, coverage
):
    """Validate retained signed Atheris controls without granting coverage."""
    try:
        _fuzz_retained_bundle_shape(challenges)
        candidate_sha256 = require_digest(candidate_sha256, "candidate_sha256")
        expected = _fuzz_retained_expected(obligations, lane, sources)
        observed = _fuzz_retained_observations(
            challenges, expected, lane, sources, candidate_sha256, coverage
        )
        _fuzz_retained_gaps(challenges["gaps"], expected)
        _atheris_challenge_retained_budget(challenges["observations"])
        controls = [observed[key] for key in sorted(expected)]
    except RuntimeAuditError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as exc:
        raise RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "retained Atheris controls invalid"
        ) from exc
    control_bindings = [
        {
            "obligation_id": item["obligation_id"],
            "kind": item["kind"],
            "evidence": item["native_evidence"],
        }
        for item in controls
    ]
    return (
        {
            "challenge_sha256": digest(challenges),
            "obligations_sha256": digest(obligations),
            "covered_obligations": sorted({key[0] for key in expected}),
            "controls_sha256": digest(control_bindings),
            "control_count": len(controls),
        },
        controls,
    )


def _fuzz_retained_bundle_shape(challenges):
    exact_keys(challenges, {"schema", "observations", "gaps"})
    if (
        challenges["schema"] != "factory.deep-challenges.v1"
        or not isinstance(challenges["observations"], list)
        or not isinstance(challenges["gaps"], list)
    ):
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "challenge bundle shape differs")


def _fuzz_retained_expected(obligations, lane, sources):
    if (
        lane.get("engine") != "atheris"
        or lane.get("family") != "fuzz"
        or not isinstance(obligations, list)
        or not isinstance(sources, dict)
    ):
        raise RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "signed Atheris obligations required"
        )
    obligations = [
        item
        for item in obligations
        if isinstance(item, dict)
        and item.get("engine") == "atheris"
        and item.get("family") == "fuzz"
        and isinstance(item.get("paths"), list)
        and set(item["paths"]) <= set(sources)
    ]
    if not obligations or len(obligations) > 64:
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "applicable obligations required")
    expected = {}
    for obligation in obligations:
        _fuzz_retained_obligation_valid(obligation, sources)
        identity = require_str(obligation.get("id"), "obligation id", maximum=128)
        if identity in {key[0] for key in expected}:
            raise RuntimeAuditError("E_FUZZ_ARTIFACT", "duplicate obligation")
        by_kind = _fuzz_retained_control_kinds(obligation)
        for kind, challenge in by_kind.items():
            key = (identity, kind)
            if key in expected:
                raise RuntimeAuditError("E_FUZZ_ARTIFACT", "duplicate signed control")
            expected[key] = (challenge, obligation)
    if len(expected) > 192:
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "control count exceeds budget")
    return expected


def _fuzz_retained_obligation_valid(obligation, sources):
    if not isinstance(obligation, dict):
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "obligation object required")
    valid = (
        obligation.get("engine") == "atheris"
        and obligation.get("family") == "fuzz"
        and obligation.get("detector_rule_id") == "FUZZ_EXCEPTION"
        and isinstance(obligation.get("paths"), list)
        and set(obligation["paths"]) <= set(sources)
    )
    if not valid:
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "obligation binding differs")


def _fuzz_retained_control_kinds(obligation):
    controls = obligation.get("challenges")
    if not isinstance(controls, list) or len(controls) != 3:
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "three signed controls required")
    by_kind = {item.get("kind"): item for item in controls if isinstance(item, dict)}
    if set(by_kind) != {"positive", "negative", "mutation"} or len(by_kind) != 3:
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "signed control triplet differs")
    return by_kind


def _fuzz_retained_observations(
    challenges, expected, lane, sources, candidate_sha256, coverage
):
    from .deep_audit_sarif import _challenge_execution_gap, _challenge_gap

    approved = {key: value for key, value in expected.items()}
    observed = {}
    for observation in challenges["observations"]:
        if not isinstance(observation, dict):
            raise RuntimeAuditError("E_FUZZ_ARTIFACT", "challenge observation required")
        key = (observation.get("obligation_id"), observation.get("kind"))
        if key not in expected or key in observed:
            raise RuntimeAuditError("E_FUZZ_ARTIFACT", "unknown or duplicate control")
        challenge, obligation = expected[key]
        challenge_gap = _challenge_gap(observation, key, approved, lane, sources)
        execution_gap = _challenge_execution_gap(
            observation,
            challenge,
            obligation,
            key,
            lane,
            coverage,
            candidate_sha256,
        )
        if challenge_gap or execution_gap:
            raise RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "signed challenge validation failed"
            )
        observed[key] = _fuzz_retained_control_evidence(
            observation, challenge, obligation, lane, sources
        )
    if set(observed) != set(expected):
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "signed control triplet incomplete")
    return observed


def _fuzz_retained_control_evidence(observation, challenge, obligation, lane, sources):
    evidence = observation.get("atheris_native_evidence")
    exact_keys(
        evidence,
        {
            "schema",
            "source_manifest",
            "source_manifest_sha256",
            "raw_report",
            "corpus_manifest",
            "effective_config",
        },
    )
    manifest = evidence["source_manifest"]
    if (
        evidence["schema"] != "factory.atheris-retained-challenge.v1"
        or manifest != challenge.get("fixture_manifest")
        or evidence["source_manifest_sha256"] != digest(manifest)
    ):
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "retained source manifest differs")
    _fuzz_fixture_manifest_binding(
        manifest, obligation, sources, challenge["fixture_path"]
    )
    raw_report = _codeql_blob_bytes(evidence["raw_report"], LIMIT)
    corpus_raw = _codeql_blob_bytes(evidence["corpus_manifest"], LIMIT)
    config = _codeql_blob_bytes(evidence["effective_config"], 4096)
    _fuzz_retained_execution_artifacts(observation, raw_report, corpus_raw, config)
    raw = strict_json(raw_report)
    normalized = _atheris_challenge_report(
        raw_report, corpus_raw, config, challenge, lane, manifest
    )
    report = observation.get("report")
    if not isinstance(report, dict) or normalized != report.get("native_report"):
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "retained report differs")
    corpus = _validate_fuzz_corpus(corpus_raw, raw, manifest)
    return {
        "obligation_id": obligation["id"],
        "kind": challenge["kind"],
        "harness": {
            "path": challenge["fixture_path"],
            "sha256": manifest[challenge["fixture_path"]],
        },
        "report": raw,
        "corpus": corpus,
        "config": config,
        "native_evidence": evidence,
        "detector_enabled": _fuzz_control_ids(config) == ["FUZZ_EXCEPTION"],
        "corpus_hashes": {item["sha256"] for item in corpus["inputs"]},
        "retained_failure_inputs": sorted(
            {item["input_sha256"] for item in raw["findings"]}
        ),
    }


def _fuzz_fixture_manifest_binding(manifest, obligation, sources, fixture_path):
    paths = set(obligation["paths"])
    if (
        not isinstance(manifest, dict)
        or not manifest
        or fixture_path not in paths
        or fixture_path not in manifest
        or not set(manifest) <= paths
    ):
        raise RuntimeAuditError("E_CHALLENGE_BINDING", "fixture manifest differs")
    for path, source_sha in manifest.items():
        relative_path(path)
        require_digest(source_sha, "fixture_sha256")
        if sources.get(path) != source_sha:
            raise RuntimeAuditError("E_CHALLENGE_BINDING", "fixture source differs")


def _fuzz_retained_execution_artifacts(observation, raw_report, corpus_raw, config):
    execution = observation["execution"]
    expected = sorted(
        [
            {
                "kind": "fuzz_result",
                "bytes": len(raw_report),
                "sha256": sha256_bytes(raw_report),
            },
            {
                "kind": "corpus_manifest",
                "bytes": len(corpus_raw),
                "sha256": sha256_bytes(corpus_raw),
            },
        ],
        key=lambda item: item["kind"],
    )
    if (
        execution.get("native_artifacts") != expected
        or execution.get("raw_report_sha256") != sha256_bytes(raw_report)
        or execution.get("effective_config_sha256") != sha256_bytes(config)
    ):
        raise RuntimeAuditError(
            "E_FUZZ_ARTIFACT", "retained control execution artifacts differ"
        )


def _fuzz_retained_gaps(gaps, expected):
    if not isinstance(gaps, list) or len(gaps) != len(expected):
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "unexpected challenge gaps")
    actual = set()
    for gap in gaps:
        if (
            not isinstance(gap, dict)
            or set(gap) != {"obligation_id", "kind", "reason"}
            or gap.get("reason") != "FUZZ_CHALLENGE_REPLAY_REQUIRED"
        ):
            raise RuntimeAuditError(
                "E_FUZZ_ARTIFACT", "challenge gap is not replay-only"
            )
        key = (gap["obligation_id"], gap["kind"])
        if key not in expected or key in actual:
            raise RuntimeAuditError("E_FUZZ_ARTIFACT", "challenge gap identity differs")
        actual.add(key)
    if actual != set(expected):
        raise RuntimeAuditError("E_FUZZ_ARTIFACT", "replay gaps are incomplete")


def _osv_suppression_bytes(aliases):
    if (
        not isinstance(aliases, list)
        or not 1 <= len(aliases) <= 64
        or any(
            not isinstance(item, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", item) is None
            for item in aliases
        )
        or aliases != sorted(set(aliases))
    ):
        raise RuntimeAuditError("E_OSV_POLICY", "canonical advisory aliases required")
    return "".join(
        "[[IgnoredVulns]]\nid = " + json.dumps(item, ensure_ascii=True) + "\n\n"
        for item in aliases
    ).encode("ascii")


def _osv_check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )


def _osv_database_identity(lane, deadline=None):
    _osv_check_deadline(deadline)
    policy = lane.get("native_policy")
    path_text = "/opt/factory/osv-db/osv-scanner/PyPI/all.zip"
    if not isinstance(policy, dict) or policy.get("database_path") != path_text:
        raise RuntimeAuditError("E_OSV_POLICY", "pinned database path required")
    path = local_file(Path("/"), path_text.lstrip("/"))
    before = path.stat()
    if not path.is_file() or before.st_size > 128 * 1024 * 1024:
        raise RuntimeAuditError("E_OSV_DATABASE", "bounded database file required")
    hasher = hashlib.sha256()
    total = 0
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            while chunk := stream.read(1024 * 1024):
                _osv_check_deadline(deadline)
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise RuntimeAuditError(
                        "E_OSV_DATABASE", "database exceeds identity byte budget"
                    )
                hasher.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise RuntimeAuditError(
            "E_OSV_DATABASE", "database identity unavailable"
        ) from exc
    current = path.stat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        any(
            (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns) != identity
            for item in (opened, after, current)
        )
        or total != before.st_size
    ):
        raise RuntimeAuditError("E_OSV_DATABASE", "database changed while hashing")
    actual = hasher.hexdigest()
    if actual != require_digest(policy.get("database_sha256"), "database_sha256"):
        raise RuntimeAuditError("E_OSV_DATABASE", "pinned database hash differs")
    _osv_check_deadline(deadline)
    return {"path": path_text, "sha256": actual, "bytes": total}


def _osv_config_rule_ids(raw, lane):
    policy = lane.get("native_policy", {})
    rules = lane.get("rule_ids", [])
    if raw == b"\n":
        return list(rules)
    for rule, aliases in policy.get("advisory_aliases", {}).items():
        if raw == _osv_suppression_bytes(aliases):
            return [item for item in rules if item != rule]
    raise RuntimeAuditError("E_OSV_POLICY", "unapproved suppression config")


def _osv_mutation_valid(baseline, effective, rule_id, lane):
    try:
        policy = lane["native_policy"]
        aliases = policy["advisory_aliases"][rule_id]
        return (
            baseline == b"\n"
            and effective == _osv_suppression_bytes(aliases)
            and sha256_bytes(effective) == lane["mutation_config_sha256"][rule_id]
        )
    except (KeyError, RuntimeAuditError, TypeError, ValueError):
        return False


def _osv_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    obligations = _osv_obligations(contract, lane)
    observations, gaps, covered = [], [], []
    deadline = started + lane["timeout_seconds"]
    if len(obligations) > 64:
        return _osv_challenge_gaps(obligations, "E_OSV_CHALLENGE_BUDGET"), []
    if not obligations:
        return _challenge_bundle(observations, gaps), covered
    try:
        baseline_path = local_file(Path("/opt/factory/rules"), "osv-scanner.toml")
        baseline = baseline_path.read_bytes()
        _osv_policy_inputs(profile, baseline)
        policy = lane["native_policy"]
        if sha256_bytes(baseline) != policy["baseline_config_sha256"]:
            raise RuntimeAuditError("E_OSV_POLICY", "signed baseline hash differs")
        _osv_database_identity(lane, deadline)
        command = _osv_challenge_command(profile)
    except (OSError, RuntimeAuditError, ValueError, TypeError, KeyError) as exc:
        return _osv_challenge_gaps(obligations, _challenge_error_code(exc)), []
    with tempfile.TemporaryDirectory(prefix="factory-osv-challenges-") as root:
        for index, obligation in enumerate(obligations):
            results = {}
            for challenge in obligation["challenges"]:
                _osv_challenge_control(
                    run_bounded_command,
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    command,
                    baseline_path,
                    baseline,
                    obligation,
                    challenge,
                    Path(root) / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                    results,
                )
            if _osv_challenge_controls_match(results):
                covered.append(obligation["id"])
            else:
                for challenge in obligation["challenges"]:
                    if (obligation["id"], challenge["kind"]) not in {
                        (item.get("obligation_id"), item.get("kind")) for item in gaps
                    }:
                        gaps.append(
                            _challenge_gap_record(
                                obligation, challenge, "E_OSV_CHALLENGE_BINDING"
                            )
                        )
    return _challenge_bundle(observations, gaps), covered


def _osv_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "osv" and item["family"] == lane["family"]
    ]


def _osv_challenge_gaps(obligations, code):
    gaps = [
        _challenge_gap_record(item, challenge, code)
        for item in obligations
        for challenge in item["challenges"]
    ]
    return _challenge_bundle([], gaps)


def _osv_challenge_command(profile):
    if profile.get("engine") != "osv" or len(profile.get("commands", [])) != 1:
        raise RuntimeAuditError("E_OSV_PROFILE", "one pinned OSV command required")
    argv = list(profile["commands"][0].get("argv", []))
    try:
        if argv[argv.index("--config") + 1] != "/opt/factory/rules/osv-scanner.toml":
            raise ValueError
        argv[argv.index("--config") + 1] = "{config}"
        if argv[argv.index("-r") + 1] != "{source}" or argv[-1] != "{report}":
            raise ValueError
    except (ValueError, IndexError) as exc:
        raise RuntimeAuditError("E_OSV_PROFILE", "pinned OSV argv differs") from exc
    return {
        "argv": argv,
        "accepted_exit_codes": profile["commands"][0]["accepted_exit_codes"],
    }


def _osv_challenge_controls_match(results):
    if {"positive", "negative", "mutation"} != set(results):
        return False
    positive, mutation = results["positive"], results["mutation"]
    return (
        positive["inventory"] == mutation["inventory"]
        and positive["unrelated_rows"] == mutation["unrelated_rows"]
        and bool(positive["target_rows"])
        and not mutation["target_rows"]
    )


def _osv_challenge_retained_budget(observations):
    total = 0
    for observation in observations:
        evidence = observation.get("osv_native_evidence", {})
        for key in ("raw_report", "effective_config", "database_identity"):
            total += require_int(
                evidence.get(key, {}).get("bytes"),
                "OSV retained bytes",
                minimum=0,
                maximum=LIMIT,
            )
    if total > NATIVE_COVERAGE_LIMIT:
        raise RuntimeAuditError(
            "E_OSV_ARTIFACT", "retained OSV artifacts exceed aggregate budget"
        )


def _osv_challenge_control(
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
    results,
):
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        gaps.append(_challenge_gap_record(obligation, challenge, "E_ADAPTER_TIMEOUT"))
        return
    if challenge.get("expected_exit_code") not in command["accepted_exit_codes"]:
        gaps.append(_challenge_gap_record(obligation, challenge, "E_OSV_PROFILE"))
        return
    try:
        observation, summary = _run_osv_challenge(
            _native_challenge_executor(),
            runner,
            profile,
            contract,
            source,
            lane,
            execution,
            command,
            baseline_path,
            baseline,
            obligation,
            challenge,
            case,
            deadline,
            remaining,
        )
        observations.append(observation)
        if observation.get("execution", {}).get("status") == "VERIFIED":
            try:
                _osv_challenge_retained_budget(observations)
            except RuntimeAuditError:
                observations.pop()
                raise
            results[challenge["kind"]] = summary
        else:
            gaps.append(
                _challenge_gap_record(
                    obligation, challenge, "E_OSV_CHALLENGE_EXECUTION"
                )
            )
    except (OSError, RuntimeAuditError, ValueError, TypeError, KeyError) as exc:
        gaps.append(
            _challenge_gap_record(obligation, challenge, _challenge_error_code(exc))
        )


def _run_osv_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    deadline,
    timeout,
):
    manifest = dict(sorted(challenge["fixture_manifest"].items()))
    _semgrep_fixture_binding(manifest, obligation, source, challenge["fixture_path"])
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in manifest.items():
        target = challenge_root.joinpath(*relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bound_bytes(source, {"path": path, "sha256": source_sha}))
    challenge_sha = digest(manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = _osv_mutation_path(case, baseline, lane, obligation)
    scratch = case / "run"
    report_path, database_path = (
        scratch / "report.json",
        scratch / "database-identity.json",
    )
    ledger_path = scratch / "unused-ledger.json"
    bindings = _osv_challenge_bindings(
        challenge_root, scratch, report_path, ledger_path, config_path, challenge_sha
    )
    summary = {}
    retained = {}

    def report_parser(raw):
        report = _osv_parse_challenge_report(
            raw, challenge_root, manifest, lane, obligation, challenge
        )
        from .deep_audit_sarif import _osv_challenge_rows

        summary.update(
            _osv_challenge_rows(report, lane, manifest, obligation, challenge["kind"])
        )
        try:
            retained.update(
                {
                    "schema": "factory.osv-retained-challenge.v1",
                    "source_root": challenge_root.as_posix(),
                    "source_manifest": manifest,
                    "source_manifest_sha256": digest(manifest),
                    "raw_report": _osv_native_blob(raw),
                    "effective_config": _osv_native_blob(config_path.read_bytes()),
                    "database_identity": _osv_native_blob(database_path.read_bytes()),
                }
            )
        except OSError as exc:
            raise RuntimeAuditError(
                "E_OSV_ARTIFACT", "challenge native artifacts unavailable"
            ) from exc
        return report

    def challenge_runner(argv, cwd, budget, run_scratch):
        return _osv_challenge_runner(
            runner, argv, cwd, budget, run_scratch, database_path, lane, deadline
        )

    timeout = int(deadline - time.monotonic())
    if timeout < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )

    observation = execute(
        challenge,
        obligation_id=obligation["id"],
        engine="osv",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["native_policy"]["baseline_config_sha256"],
        execution_bindings=_osv_execution_bindings(
            profile, contract, lane, execution, challenge_sha
        ),
        runner=challenge_runner,
        report_parser=report_parser,
        config_rule_ids=lambda raw: _osv_config_rule_ids(raw, lane),
        verify_mutation=lambda original, effective, rule: _osv_mutation_valid(
            original, effective, rule, lane
        ),
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={
            "osv_json_report": report_path,
            "advisory_db_identity": database_path,
        },
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["osv_control_evidence"] = summary
    observation["osv_native_evidence"] = retained
    return observation, summary


def _osv_challenge_bindings(source, scratch, report, ledger, config, candidate_sha):
    return {
        "source": str(source),
        "output": str(scratch),
        "report": str(report),
        "scratch": str(scratch),
        "candidate_sha256": candidate_sha,
        "factory_ledger": str(ledger),
        "config": str(config),
    }


def _osv_execution_bindings(profile, contract, lane, execution, challenge_sha):
    from .runtime_audit_common import sha256_bytes as common_sha256

    version_probe = execution["version_probe"]
    image = require_str(lane.get("image"), "image", maximum=512)
    return {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_sha,
        "profile_sha256": digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": digest(version_probe),
        "version_probe_facts": version_probe,
    }


def _osv_parse_challenge_report(
    raw, source_root, manifest, lane, obligation, challenge
):
    report = strict_json(raw)
    if not isinstance(report, dict):
        raise RuntimeAuditError("E_OSV_REPORT", "native OSV report object required")
    _osv_challenge_source_paths(report, source_root, manifest)
    return report


def _osv_challenge_source_paths(report, source_root, manifest):
    results = report.get("results")
    if not isinstance(results, list):
        raise RuntimeAuditError("E_OSV_REPORT", "native source results required")
    prefix = source_root.resolve().as_posix().rstrip("/") + "/"
    for result in results:
        try:
            source = result["source"]
            raw_path = require_str(source.get("path"), "OSV source path", maximum=2048)
            if raw_path.startswith("file://"):
                raw_path = raw_path.removeprefix("file://")
            if raw_path.startswith(prefix):
                path = raw_path[len(prefix) :]
            elif raw_path in manifest:
                path = raw_path
            else:
                raise RuntimeAuditError("E_OSV_REPORT", "source path outside fixture")
            path = relative_path(path)
            if path not in manifest:
                raise RuntimeAuditError("E_OSV_REPORT", "source path is unbound")
            source["path"] = path
        except (KeyError, TypeError, AttributeError) as exc:
            raise RuntimeAuditError(
                "E_OSV_REPORT", "native source path malformed"
            ) from exc


def _osv_mutation_path(case, baseline, lane, obligation):
    rule = obligation["detector_rule_id"]
    aliases = lane["native_policy"]["advisory_aliases"][rule]
    effective = _osv_suppression_bytes(aliases)
    if sha256_bytes(effective) != lane["mutation_config_sha256"][rule]:
        raise RuntimeAuditError(
            "E_OSV_MUTATION_BINDING", "signed suppression digest differs"
        )
    path = case / "mutation-osv-scanner.toml"
    path.write_bytes(effective)
    return path


def _osv_challenge_runner(
    runner, argv, cwd, budget, scratch, database_path, lane, deadline
):
    expected = _osv_database_identity(lane, deadline)
    identity = canonical_bytes(expected)
    database_path.write_bytes(identity)
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )
    cancelled = threading.Event()
    timer = threading.Timer(remaining, cancelled.set)
    timer.daemon = True
    timer.start()
    try:
        facts = runner(argv, cwd, budget, scratch, cancelled=cancelled)
    finally:
        timer.cancel()
    if _osv_database_identity(lane, deadline) != expected:
        raise RuntimeAuditError(
            "E_OSV_DATABASE", "database identity drifted during scan"
        )
    if time.monotonic() >= deadline:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "shared challenge deadline expired"
        )
    return facts


def _run_native_profile(profile, contract, source, output, inventory, lane, paths):
    _osv_profile_preflight(profile, lane)
    rule_inventory = None
    config_path = _fuzz_profile_preflight(profile, lane)
    semgrep_rules = None
    trivy_config = None
    trivy_ignore = None
    if lane["engine"] == "gitleaks":
        config_path = Path("/opt/factory/rules/gitleaks.toml")
        config = config_path.read_bytes()
        rule_inventory = _gitleaks_rule_inventory(config, lane)
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        config_path = Path("/opt/factory/rules/runtime-control.toml")
        config = config_path.read_bytes()
        rule_inventory = _runtime_rule_inventory(config, lane)
    elif lane["engine"] == "semgrep" and "native_artifact_roles" in lane:
        if len(inventory["files"]) > 64:
            raise RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "bounded source inventory required"
            )
        config = Path("/opt/factory/rules/semgrep-pattern-limited.yml").read_bytes()
        semgrep_rules, rule_inventory = _semgrep_rule_inventory(config, lane)
    elif lane["engine"] == "trivy":
        trivy_config = Path("/opt/factory/rules/trivy.yaml").read_bytes()
        trivy_ignore = Path("/opt/factory/rules/empty-trivyignore").read_bytes()
        _trivy_policy_inputs(trivy_config, trivy_ignore, lane)
    timeout = require_int(
        lane.get("timeout_seconds"), "timeout", minimum=1, maximum=3600
    )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="factory-native-") as temporary:
        scratch = Path(temporary)
        probe = scratch / "probe"
        probe.mkdir()
        version = _native_version(profile, source, probe, timeout)
        query_inventory = _codeql_query_preflight(
            profile,
            source,
            scratch,
            int(timeout - (time.monotonic() - started)),
            engine=lane["engine"],
        )
        remaining = timeout - (time.monotonic() - started)
        if remaining < 1:
            raise RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "version probe exhausted deadline"
            )
        commands = _native_argv(
            profile["commands"],
            {
                "source": source,
                "output": output,
                "report": output / paths[0],
                "scratch": scratch,
                "candidate_sha256": inventory["candidate_sha256"],
                "fixture": source / ".factory/fuzz_harness.py",
                **({"config": str(config_path)} if config_path is not None else {}),
            },
        )
        invocations = _adapter_commands(
            commands, {**lane, "timeout_seconds": int(remaining)}, source, scratch
        )
        query_execution = (
            _codeql_query_execution(
                profile, query_inventory, source, scratch, started + timeout
            )
            if query_inventory is not None
            else None
        )
        source_execution = (
            _codeql_source_measurement(
                profile, source, scratch, inventory, lane, started + timeout
            )
            if query_inventory is not None
            else None
        )
        trivy_execution = None
        if lane["engine"] == "trivy" and lane.get("native_policy"):
            trivy_execution = _trivy_full_source_execution(
                profile,
                lane,
                inventory,
                source,
                output,
                paths,
                commands[0]["argv"],
                invocations[0],
                trivy_config,
                trivy_ignore,
                started,
                timeout,
                scratch,
            )
        ledger = None
        ledger_sha256 = None
        ledger_json = None
        if lane["engine"] == "gitleaks" and len(invocations) == 1:
            ledger = invocations[0].pop("native_rule_ledger", None)
            ledger_sha256 = invocations[0].get("native_rule_ledger_sha256")
            ledger_json = invocations[0].pop("native_rule_ledger_json", None)
        semgrep_execution = (
            _semgrep_rule_runs(profile, lane, source, scratch, semgrep_rules, started)
            if semgrep_rules is not None
            else None
        )
        if semgrep_execution is not None:
            import base64

            semgrep_execution["ruleset_base64"] = base64.b64encode(config).decode(
                "ascii"
            )
    raw_report, raw_report_bytes = _native_profile_report(profile, output, paths)
    _adapter_sources(source, inventory)
    return {
        "rule_inventory": rule_inventory,
        "invocations": invocations,
        "ledger": ledger,
        "ledger_sha256": ledger_sha256,
        "ledger_json": ledger_json,
        "raw_report": raw_report,
        "version_probe": version,
        "semgrep_rule_execution": semgrep_execution,
        "trivy_rule_execution": trivy_execution,
        "codeql_query_inventory": query_inventory,
        "codeql_query_execution": query_execution,
        "codeql_source_execution": source_execution,
        "raw_report_bytes": (
            raw_report_bytes if profile["report_format"] != "runtime-junit" else None
        ),
        **(
            {
                "osv_database_identity": canonical_bytes(
                    _osv_database_identity(lane, started + timeout)
                )
            }
            if lane["engine"] == "osv" and "native_policy" in lane
            else {}
        ),
    }


def _osv_profile_preflight(profile, lane):
    if (lane.get("engine"), lane.get("mode")) != (
        "osv",
        "offline-pypi-snapshot",
    ):
        return
    try:
        policy = local_file(Path("/opt/factory/rules"), "osv-scanner.toml").read_bytes()
    except (OSError, RuntimeAuditError) as exc:
        raise RuntimeAuditError(
            "E_OSV_POLICY", "trusted OSV configuration unavailable"
        ) from exc
    _osv_policy_inputs(profile, policy)


def _osv_policy_inputs(profile, policy_bytes):
    expected = {
        "argv": [
            "/opt/factory/bin/osv-offline",
            "scan",
            "source",
            "-r",
            "{source}",
            "--config",
            "/opt/factory/rules/osv-scanner.toml",
            "--offline",
            "--offline-vulnerabilities",
            "--allow-no-lockfiles",
            "--all-packages",
            "--format",
            "json",
            "--output",
            "{report}",
        ],
        "accepted_exit_codes": [0, 1],
    }
    if profile.get("commands") != [expected] or policy_bytes != b"\n":
        raise RuntimeAuditError(
            "E_OSV_POLICY", "baseline requires the trusted empty OSV configuration"
        )


def _osv_native_blob(raw):
    try:
        return _codeql_native_blob(raw, LIMIT)
    except RuntimeAuditError as exc:
        raise RuntimeAuditError(
            "E_OSV_ARTIFACT", "OSV artifact exceeds bounds"
        ) from exc


def _osv_native_bytes(blob):
    try:
        return _codeql_blob_bytes(blob, LIMIT)
    except RuntimeAuditError as exc:
        raise RuntimeAuditError(
            "E_OSV_ARTIFACT", "invalid retained OSV artifact"
        ) from exc


def _osv_primary_evidence(execution, required):
    raw = execution.get("raw_report_bytes")
    database = execution.get("osv_database_identity")
    if not isinstance(raw, bytes) or not isinstance(database, bytes):
        raise RuntimeAuditError("E_OSV_ARTIFACT", "primary native artifacts missing")
    return {
        "schema": "factory.osv-native-evidence.v1",
        "source_bindings": dict(sorted(required.items())),
        "primary": {
            "raw_report": _osv_native_blob(raw),
            "database_identity": _osv_native_blob(database),
        },
    }


def _osv_database_artifact(blob, lane):
    raw = _osv_native_bytes(blob)
    identity = strict_json(raw)
    if (
        not isinstance(identity, dict)
        or set(identity) != {"path", "sha256", "bytes"}
        or identity.get("path") != lane["native_policy"].get("database_path")
        or identity.get("sha256") != lane["native_policy"].get("database_sha256")
        or type(identity.get("bytes")) is not int
        or not 0 < identity["bytes"] <= 128 * 1024 * 1024
        or canonical_bytes(identity) != raw
    ):
        raise RuntimeAuditError("E_OSV_ARTIFACT", "database identity binding differs")
    return identity


def _osv_normalize_retained_paths(report, source_root, manifest):
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise RuntimeAuditError("E_OSV_ARTIFACT", "native OSV results required")
    root = _osv_source_root_prefix(source_root)
    for item in report["results"]:
        _osv_normalize_result_source(item, root, manifest)
    return report


def _osv_source_root_prefix(source_root):
    if not isinstance(source_root, str) or not source_root.startswith("/"):
        raise RuntimeAuditError("E_OSV_ARTIFACT", "absolute fixture root required")
    parts = source_root.split("/")
    if "\\" in source_root or any(part in {"", ".", ".."} for part in parts[1:]):
        raise RuntimeAuditError("E_OSV_ARTIFACT", "absolute fixture root required")
    return source_root + "/"


def _osv_normalize_result_source(item, root, manifest):
    try:
        source = item["source"]
        raw = require_str(source.get("path"), "source path", maximum=2048)
        if raw.startswith("file://"):
            raw = raw[7:]
        path = raw[len(root) :] if raw.startswith(root) else raw
        path = relative_path(path)
        if path not in manifest:
            raise ValueError("unbound source path")
        source["path"] = path
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise RuntimeAuditError("E_OSV_ARTIFACT", "unbound OSV source path") from exc


def verify_osv_retained_challenge(observation, lane, bound, obligation, kind):
    """Validate bounded retained OSV control artifacts against approved bindings."""
    from .deep_audit_sarif import _osv_challenge_rows

    try:
        evidence = observation["osv_native_evidence"]
        manifest = _osv_challenge_manifest(evidence, bound, kind)
        _osv_challenge_execution(observation, lane, manifest)
        raw = _osv_challenge_report_bytes(evidence, lane, observation, obligation, kind)
        report = _osv_normalize_retained_paths(
            strict_json(raw), evidence["source_root"], manifest
        )
        if canonical_bytes(report) != canonical_bytes(
            observation["report"]["native_report"]
        ):
            raise ValueError("normalized challenge report differs")
        summary = _osv_challenge_rows(report, lane, manifest, obligation, kind)
        if summary != observation.get("osv_control_evidence"):
            raise ValueError("challenge semantics differ")
        return summary
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise RuntimeAuditError(
            "E_OSV_ARTIFACT", "retained OSV challenge invalid"
        ) from exc


def _osv_challenge_manifest(evidence, bound, kind):
    exact_keys(
        evidence,
        {
            "schema",
            "source_root",
            "source_manifest",
            "source_manifest_sha256",
            "raw_report",
            "effective_config",
            "database_identity",
        },
    )
    manifest = evidence["source_manifest"]
    if (
        evidence["schema"] != "factory.osv-retained-challenge.v1"
        or not isinstance(manifest, dict)
        or evidence["source_manifest_sha256"] != digest(manifest)
        or manifest != bound["fixture_manifest"]
        or kind not in {"positive", "negative", "mutation"}
    ):
        raise ValueError("challenge evidence binding differs")
    return manifest


def _osv_challenge_execution(observation, lane, manifest):
    execution = observation["execution"]
    if (
        execution.get("status") != "VERIFIED"
        or execution.get("baseline_config_sha256")
        != lane["native_policy"]["baseline_config_sha256"]
        or execution.get("challenge_source_sha256") != digest(manifest)
        or observation.get("observation_sha256") != digest(observation["report"])
    ):
        raise ValueError("challenge execution binding differs")


def _osv_challenge_report_bytes(evidence, lane, observation, obligation, kind):
    execution = observation["execution"]
    raw = _osv_native_bytes(evidence["raw_report"])
    policy = _osv_native_bytes(evidence["effective_config"])
    _osv_database_artifact(evidence["database_identity"], lane)
    expected = _osv_expected_policy(lane, obligation, kind)
    if (
        policy != expected
        or sha256_bytes(policy) != execution["effective_config_sha256"]
        or execution["raw_report_sha256"] != sha256_bytes(raw)
        or not _osv_challenge_artifacts_valid(
            execution["native_artifacts"], lane["native_artifact_roles"], raw, evidence
        )
    ):
        raise ValueError("challenge artifact binding differs")
    return raw


def _osv_expected_policy(lane, obligation, kind):
    if kind != "mutation":
        return b"\n"
    aliases = lane["native_policy"]["advisory_aliases"][obligation["detector_rule_id"]]
    return _osv_suppression_bytes(aliases)


def _osv_challenge_artifacts_valid(records, roles, raw, evidence):
    if not isinstance(records, list) or len(records) != 2:
        return False
    by_role = {}
    total = 0
    for record in records:
        try:
            exact_keys(record, {"kind", "sha256", "bytes"})
            role = require_str(record["kind"], "artifact kind", maximum=64)
            require_digest(record["sha256"], "artifact hash")
            size = require_int(
                record["bytes"], "artifact bytes", minimum=0, maximum=8 * 1024 * 1024
            )
            if role in by_role:
                return False
            by_role[role] = record
            total += size
        except (RuntimeAuditError, TypeError, KeyError):
            return False
    database = _osv_native_bytes(evidence["database_identity"])
    expected = {"osv_json_report": raw, "advisory_db_identity": database}
    return (
        set(by_role) == set(roles) == set(expected)
        and all(
            by_role[role]["sha256"] == sha256_bytes(data)
            and by_role[role]["bytes"] == len(data)
            for role, data in expected.items()
        )
        and total <= 8 * 1024 * 1024
    )


def verify_osv_retained_evidence(
    coverage, lane, required, report, challenges, obligations
):
    """Validate primary and control artifacts without granting replay authority."""
    try:
        accounting = _osv_primary_retained(coverage, lane, required, report)
        observed = _osv_retained_observations(challenges, obligations, lane, required)
        return {
            "state": "REPLAY_REQUIRED",
            "source_accounting": accounting,
            "controls": len(observed),
        }
    except (RuntimeAuditError, ValueError, TypeError, KeyError, AttributeError) as exc:
        raise RuntimeAuditError(
            "E_OSV_ARTIFACT", "retained OSV evidence invalid"
        ) from exc


def _osv_primary_retained(coverage, lane, required, report):
    from .deep_audit_sarif import _osv_source_accounting

    evidence = coverage["osv_native_evidence"]
    exact_keys(evidence, {"schema", "source_bindings", "primary"})
    if (
        evidence["schema"] != "factory.osv-native-evidence.v1"
        or evidence["source_bindings"] != dict(sorted(required.items()))
        or set(evidence["primary"])
        != {
            "raw_report",
            "database_identity",
        }
    ):
        raise ValueError("primary evidence binding differs")
    raw = _osv_native_bytes(evidence["primary"]["raw_report"])
    _osv_database_artifact(evidence["primary"]["database_identity"], lane)
    native = strict_json(raw)
    if digest(native) != coverage["native_report_sha256"]:
        raise ValueError("retained primary native report hash differs")
    _native_dependency_paths(native, "osv-json", required)
    if canonical_bytes(native) != canonical_bytes(report):
        raise ValueError("primary normalized report differs")
    if digest(report) != coverage["report_sha256"]:
        raise ValueError("primary report hash differs")
    accounting = _osv_source_accounting(report, required, lane["mode"])
    if accounting["state"] != "COMPLETE" or accounting != coverage["source_accounting"]:
        raise ValueError("source accounting incomplete or differs")
    return accounting


def _osv_retained_observations(challenges, obligations, lane, required):
    exact_keys(challenges, {"schema", "observations", "gaps"})
    if challenges["schema"] != "factory.deep-challenges.v1":
        raise ValueError("challenge schema differs")
    expected = _osv_retained_expected(obligations, lane, required)
    observed = _osv_retained_observed(challenges, expected, lane)
    _osv_challenge_retained_budget(challenges["observations"])
    if set(observed) != set(expected) or challenges.get("gaps"):
        raise ValueError("retained controls incomplete")
    _osv_retained_controls_match(observed, obligations)
    return observed


def _osv_retained_expected(obligations, lane, required):
    expected = {
        (item["id"], control["kind"]): (item, control)
        for item in obligations
        if item["engine"] == "osv"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= set(required)
        for control in item["challenges"]
    }
    if not expected or len(expected) > 192:
        raise ValueError("complete bounded control set required")
    return expected


def _osv_retained_observed(challenges, expected, lane):
    observed = {}
    for observation in challenges.get("observations", []):
        key = (observation.get("obligation_id"), observation.get("kind"))
        if key not in expected or key in observed:
            raise ValueError("unexpected or duplicate control")
        item, control = expected[key]
        observed[key] = verify_osv_retained_challenge(
            observation, lane, control, item, control["kind"]
        )
    return observed


def _osv_retained_controls_match(observed, obligations):
    for item in obligations:
        if (item["id"], "positive") not in observed:
            continue
        rows = {
            kind: observed[(item["id"], kind)]
            for kind in ("positive", "negative", "mutation")
        }
        if not _osv_challenge_controls_match(rows):
            raise ValueError("OSV challenge controls do not match")


def execute_osv_native_replay(request, source, scratch, timeout):
    """Independently rerun the pinned offline scanner and every signed OSV control."""
    exact_keys(
        request,
        {"lane", "inventory", "coverage", "report", "challenges", "obligations"},
    )
    lane, inventory, coverage = (
        request["lane"],
        request["inventory"],
        request["coverage"],
    )
    started = time.monotonic()
    timeout = require_int(timeout, "OSV replay timeout", minimum=1, maximum=3600)
    deadline = started + timeout
    profile = strict_json(Path("/opt/factory/adapter-profile.json").read_bytes())
    _native_profile(profile, lane)
    if (
        coverage.get("profile_sha256") != digest(profile)
        or coverage.get("image_binding_sha256")
        != sha256_bytes(str(lane.get("image", "")).encode("utf-8"))
        or coverage.get("tool_version") != profile["tool_version"]
        or coverage.get("ruleset_sha256") != profile["ruleset_sha256"]
    ):
        raise RuntimeAuditError("E_OSV_REPLAY", "pinned profile binding differs")
    _adapter_sources(source, inventory)
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    verify_osv_retained_evidence(
        coverage,
        lane,
        required,
        request["report"],
        request["challenges"],
        request["obligations"],
    )
    fresh, report, findings, accounting = _osv_replay_primary(
        request, profile, source, scratch, lane, inventory, required, deadline
    )
    controls = _osv_replay_controls(
        request, profile, source, lane, fresh, report, required, deadline
    )
    _adapter_sources(source, inventory)
    expected_controls = _osv_replay_control_ids(request["obligations"], lane, required)
    return {
        "schema": "factory.osv-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": inventory["candidate_sha256"],
        "lane_sha256": digest(lane),
        "coverage_sha256": digest(coverage),
        "report_sha256": digest(request["report"]),
        "challenges_sha256": digest(request["challenges"]),
        "obligations_sha256": digest(request["obligations"]),
        "profile_sha256": coverage["profile_sha256"],
        "database_sha256": lane["native_policy"]["database_sha256"],
        "source_paths": sorted(required),
        "controls": expected_controls,
        "findings_sha256": digest(findings),
        "source_accounting_sha256": digest(accounting),
        "native_execution_sha256": digest(
            {"primary": fresh["invocations"], "controls": controls}
        ),
    }


def _osv_replay_primary(
    request, profile, source, scratch, lane, inventory, required, deadline
):
    from .deep_audit_sarif import _native_execution_report, _osv_source_accounting

    coverage = request["coverage"]
    _osv_database_identity(lane, deadline)
    replay_lane = {
        **lane,
        "timeout_seconds": min(
            lane["timeout_seconds"], _osv_replay_remaining(deadline)
        ),
    }
    output = Path(scratch) / "osv-primary"
    output.mkdir(parents=True, exist_ok=False)
    paths = _adapter_output_paths(replay_lane, output, create_parents=True)
    replay_lane = {
        **lane,
        "timeout_seconds": min(
            lane["timeout_seconds"], _osv_replay_remaining(deadline)
        ),
    }
    contract = {
        "inventory": inventory,
        "lane": replay_lane,
        "obligations": request["obligations"],
    }
    fresh = _run_native_profile(
        profile, contract, source, output, inventory, replay_lane, paths
    )
    _osv_check_deadline(deadline)
    report = _native_report(
        fresh["raw_report"], profile, contract, output, fresh["invocations"]
    )
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    findings = _native_execution_report(report, lane, sources)
    expected_findings = _native_execution_report(request["report"], lane, sources)
    if sorted(findings, key=canonical_bytes) != sorted(
        expected_findings, key=canonical_bytes
    ):
        raise RuntimeAuditError("E_OSV_REPLAY", "independent findings differ")
    accounting = _osv_source_accounting(report, required, lane["mode"])
    if accounting["state"] != "COMPLETE" or accounting != coverage["source_accounting"]:
        raise RuntimeAuditError("E_OSV_REPLAY", "independent source accounting differs")
    return fresh, report, findings, accounting


def _osv_replay_controls(
    request, profile, source, lane, fresh, report, required, deadline
):
    control_timeout = min(lane["timeout_seconds"], _osv_replay_remaining(deadline))
    replay_lane = {**lane, "timeout_seconds": control_timeout}
    replay_contract = {
        "inventory": request["inventory"],
        "lane": replay_lane,
        "obligations": request["obligations"],
    }
    replay_execution = {**fresh, "raw_report": report}
    fresh_challenges, covered = _native_profile_challenges(
        profile,
        replay_contract,
        source,
        replay_lane,
        replay_execution,
        deadline - control_timeout,
    )
    _osv_check_deadline(deadline)
    controls = _osv_replay_compare_controls(
        request["challenges"], fresh_challenges, request["obligations"], lane, required
    )
    expected_obligation_ids = {
        item["id"]
        for item in request["obligations"]
        if item["engine"] == "osv"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= set(required)
    }
    if set(covered) != expected_obligation_ids:
        raise RuntimeAuditError("E_OSV_REPLAY", "independent controls incomplete")
    return controls


def _osv_replay_remaining(deadline):
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError("E_OSV_REPLAY", "shared replay deadline expired")
    return remaining


def _osv_replay_control_ids(obligations, lane, required):
    rows = [
        {"id": item["id"], "kind": challenge["kind"]}
        for item in obligations
        if item["engine"] == "osv"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= set(required)
        for challenge in item["challenges"]
    ]
    rows.sort(key=lambda item: (item["id"], item["kind"]))
    if (
        not rows
        or len(rows) > 192
        or len({(r["id"], r["kind"]) for r in rows}) != len(rows)
    ):
        raise RuntimeAuditError(
            "E_OSV_REPLAY", "complete bounded control identities required"
        )
    return rows


def _osv_replay_compare_controls(expected, actual, obligations, lane, required):
    identities = _osv_replay_identities(obligations, lane, required)
    expected_rows = _osv_replay_row_map(expected)
    actual_rows = _osv_replay_row_map(actual)
    if (
        expected.get("gaps")
        or actual.get("gaps")
        or set(expected_rows) != identities
        or set(actual_rows) != identities
    ):
        raise RuntimeAuditError("E_OSV_REPLAY", "challenge set or execution differs")
    _osv_replay_semantics_match(expected_rows, actual_rows, identities)
    return _osv_replay_execution_facts(actual_rows)


def _osv_replay_identities(obligations, lane, required):
    return {
        (row["id"], challenge["kind"])
        for row in obligations
        if row["engine"] == "osv"
        and row["family"] == lane["family"]
        and set(row["paths"]) <= set(required)
        for challenge in row["challenges"]
    }


def _osv_replay_row_map(bundle):
    rows = bundle.get("observations", [])
    mapped = {}
    for row in rows:
        key = (row.get("obligation_id"), row.get("kind"))
        if key in mapped:
            raise RuntimeAuditError("E_OSV_REPLAY", "duplicate challenge observation")
        mapped[key] = row
    return mapped


def _osv_replay_semantics_match(expected_rows, actual_rows, identities):
    results = {}
    for key in sorted(identities):
        old, new = expected_rows[key], actual_rows[key]
        old_execution, new_execution = old["execution"], new["execution"]
        if (
            old_execution.get("status") != "VERIFIED"
            or new_execution.get("status") != "VERIFIED"
            or old.get("osv_control_evidence") != new.get("osv_control_evidence")
        ):
            raise RuntimeAuditError("E_OSV_REPLAY", "challenge evidence differs")
        results.setdefault(key[0], {})[key[1]] = new["osv_control_evidence"]
    for controls in results.values():
        if not _osv_challenge_controls_match(controls):
            raise RuntimeAuditError("E_OSV_REPLAY", "challenge semantics differ")


def _osv_replay_execution_facts(actual_rows):
    return {
        f"{key[0]}:{key[1]}": {
            "argv_sha256": actual_rows[key]["execution"]["argv_sha256"],
            "raw_report_sha256": actual_rows[key]["execution"]["raw_report_sha256"],
            "execution_sha256": actual_rows[key]["execution"]["execution_sha256"],
        }
        for key in sorted(actual_rows)
    }


def _native_profile_report(profile, output, paths):
    if profile["report_format"] == "runtime-junit":
        junit_path = local_file(output, paths[0])
        _junit_bytes(output, paths[0])
        with local_file(output, paths[1]).open("rb") as stream:
            raw_report = strict_json(stream.read(LIMIT + 1))
        if not junit_path.is_file():
            raise RuntimeAuditError("E_RUNTIME_REPORT", "native JUnit missing")
    else:
        with local_file(output, paths[0]).open("rb") as stream:
            raw_report_bytes = stream.read(LIMIT + 1)
        if len(raw_report_bytes) > LIMIT:
            raise RuntimeAuditError("E_REPORT_SIZE", "native report exceeds budget")
        raw_report = strict_json(raw_report_bytes)
    return raw_report, (
        raw_report_bytes if profile["report_format"] != "runtime-junit" else None
    )


def _trivy_policy_inputs(config, ignore, lane):
    policy = lane.get("native_policy")
    if policy is None:
        return
    if sha256_bytes(config) != policy.get("config_sha256") or sha256_bytes(
        ignore
    ) != policy.get("baseline_ignore_sha256"):
        raise RuntimeAuditError("E_TRIVY_POLICY", "pinned Trivy policy bytes differ")
    if _trivy_ignore_ids(ignore):
        raise RuntimeAuditError("E_TRIVY_POLICY", "baseline ignorefile must be empty")


def _trivy_ignore_ids(config):
    import re

    try:
        text = config.decode("ascii")
    except (AttributeError, UnicodeDecodeError) as exc:
        raise RuntimeAuditError(
            "E_TRIVY_POLICY", "Trivy ignorefile is malformed"
        ) from exc
    ids = text.splitlines()
    if not text.strip():
        return []
    if ids != sorted(set(ids)) or any(
        re.fullmatch(r"DS[0-9]{3}", item) is None for item in ids
    ):
        raise RuntimeAuditError("E_TRIVY_POLICY", "Trivy ignore IDs are invalid")
    return ids


def _trivy_mutation(ignore, rule_id):
    import re

    if _trivy_ignore_ids(ignore):
        raise RuntimeAuditError("E_TRIVY_MUTATION", "baseline ignorefile is not empty")
    if not isinstance(rule_id, str) or re.fullmatch(r"DS[0-9]{3}", rule_id) is None:
        raise RuntimeAuditError("E_TRIVY_MUTATION", "unsupported Trivy check ID")
    return f"{rule_id}\n".encode("ascii")


def _trivy_mutation_valid(baseline, effective, rule_id):
    try:
        return _trivy_mutation(baseline, rule_id) == effective
    except (RuntimeAuditError, ValueError, TypeError):
        return False


def _trivy_json_argv(sarif_argv, output_path):
    result = list(sarif_argv)
    try:
        format_index = result.index("--format") + 1
        output_index = result.index("--output") + 1
        if result[format_index] != "sarif":
            raise ValueError
        result[format_index] = "json"
        result[output_index] = str(output_path)
        result.insert(result.index("config") + 1, "--include-non-failures")
    except (ValueError, IndexError) as exc:
        raise RuntimeAuditError(
            "E_TRIVY_PROFILE", "pinned Trivy command differs"
        ) from exc
    return result


def _trivy_full_source_execution(
    profile,
    lane,
    inventory,
    source,
    output,
    paths,
    sarif_argv,
    invocation,
    config,
    ignore,
    started,
    timeout,
    scratch,
):
    import base64
    from .runtime_audit_process import run_bounded_command

    remaining = int(timeout - (time.monotonic() - started))
    if remaining < 1:
        raise RuntimeAuditError("E_ADAPTER_TIMEOUT", "Trivy inventory budget exhausted")
    raw_sarif = _trivy_read_raw(local_file(output, paths[0]))
    json_path = scratch / "trivy-full.json"
    json_run = scratch / "trivy-full-run"
    json_run.mkdir()
    argv = _trivy_json_argv(sarif_argv, json_path)
    deadline = time.monotonic() + remaining
    facts = run_bounded_command(argv, source, remaining, json_run)
    if _adapter_command_failed(facts, [0], deadline):
        raise RuntimeAuditError("E_TRIVY_EXECUTION", "Trivy JSON inventory failed")
    raw_json = _trivy_read_raw(local_file(scratch, "trivy-full.json"))
    _trivy_native_checks(strict_json(raw_json), _trivy_source_map(inventory, lane))
    return {
        "schema": "factory.trivy-rule-execution.v1",
        "config_base64": base64.b64encode(config).decode("ascii"),
        "ignore_base64": base64.b64encode(ignore).decode("ascii"),
        "sources": _trivy_source_map(inventory, lane),
        "observations": [
            _trivy_observation("sarif", sarif_argv, invocation["execution"], raw_sarif),
            _trivy_observation("json", argv, facts, raw_json),
        ],
    }


def _trivy_read_raw(path):
    raw = path.read_bytes()
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_TRIVY_REPORT", "Trivy report exceeds byte budget")
    return raw


def _trivy_observation(report_format, argv, facts, raw):
    import base64

    return {
        "format": report_format,
        "argv": argv,
        "execution": facts,
        "raw_report_base64": base64.b64encode(raw).decode("ascii"),
        "raw_report_sha256": sha256_bytes(raw),
    }


def _trivy_source_map(inventory, lane):
    return {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }


def _trivy_native_checks(report, sources):
    if not isinstance(report, dict) or report.get("SchemaVersion") != 2:
        raise RuntimeAuditError("E_TRIVY_REPORT", "Trivy JSON schema version differs")
    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Trivy reported no applicable sources"
        )
    matrix = {}
    for result in results:
        if not isinstance(result, dict) or result.get("Class") != "config":
            raise RuntimeAuditError("E_TRIVY_REPORT", "Trivy config result malformed")
        path = relative_path(result.get("Target"))
        if path not in sources:
            raise RuntimeAuditError("E_TRIVY_APPLICABILITY", "Trivy source is unbound")
        rows = result.get("Misconfigurations")
        if not isinstance(rows, list) or not rows:
            raise RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "Trivy check inventory missing"
            )
        statuses = _trivy_check_statuses(result, rows)
        if path in matrix:
            raise RuntimeAuditError("E_TRIVY_REPORT", "duplicate Trivy source result")
        matrix[path] = statuses
    if set(matrix) != set(sources):
        raise RuntimeAuditError(
            "E_TRIVY_APPLICABILITY", "Trivy omitted a required source"
        )
    return matrix


def _trivy_check_statuses(result, rows):
    statuses = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeAuditError("E_TRIVY_REPORT", "Trivy check row malformed")
        rule_id = require_str(row.get("ID"), "Trivy check ID", maximum=256)
        status = row.get("Status")
        if (
            not isinstance(status, str)
            or status not in {"PASS", "FAIL"}
            or rule_id in statuses
        ):
            raise RuntimeAuditError(
                "E_TRIVY_REPORT", "Trivy check status is unsupported"
            )
        statuses[rule_id] = status
    summary = result.get("MisconfSummary")
    if (
        not isinstance(summary, dict)
        or type(summary.get("Successes")) is not int
        or type(summary.get("Failures")) is not int
        or summary.get("Successes")
        != sum(status == "PASS" for status in statuses.values())
        or summary.get("Failures")
        != sum(status == "FAIL" for status in statuses.values())
    ):
        raise RuntimeAuditError("E_TRIVY_REPORT", "Trivy status summary differs")
    return statuses


def verify_trivy_rule_execution(
    evidence, lane, sources, report, *, disabled_rule_id=None
):
    """Re-derive Trivy applicability and outcomes from paired native JSON/SARIF bytes."""
    from .runtime_audit_common import _validate_runner_facts

    config, ignore, observations = _trivy_evidence_inputs(
        evidence, lane, sources, disabled_rule_id
    )
    expected_ids = _trivy_expected_ids(lane, disabled_rule_id)
    decoded = [_trivy_observation_bytes(item) for item in observations]
    _trivy_pair_identity(observations[0]["argv"], observations[1]["argv"])
    for item in observations:
        facts = item["execution"]
        _validate_runner_facts(facts, facts.get("timeout_seconds"))
        budget = require_int(
            facts["timeout_seconds"],
            "Trivy timeout",
            minimum=1,
            maximum=lane["timeout_seconds"],
        )
        require_int(
            facts["duration_ms"], "Trivy duration", minimum=0, maximum=budget * 1000
        )
        if _adapter_command_failed(facts, [0], float("inf")):
            raise RuntimeAuditError(
                "E_TRIVY_EXECUTION", "paired Trivy command did not complete"
            )
    matrix = _trivy_native_checks(strict_json(decoded[1]), sources)
    _trivy_matrix_ids(matrix, expected_ids)
    fail_rows = {
        (path, rule)
        for path, rows in matrix.items()
        for rule, status in rows.items()
        if status == "FAIL"
    }
    sarif = strict_json(decoded[0])
    if _trivy_sarif_failures(sarif, sources, observations[0]["argv"][-1]) != fail_rows:
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "native JSON and SARIF findings differ"
        )
    if _trivy_sarif_failures(report, sources) != fail_rows:
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "normalized report differs from native status"
        )
    return {"state": "VERIFIED", "checks": matrix, "findings": len(fail_rows)}


def _trivy_evidence_inputs(evidence, lane, sources, disabled_rule_id):
    import base64

    if (
        not isinstance(evidence, dict)
        or set(evidence)
        != {"schema", "config_base64", "ignore_base64", "sources", "observations"}
        or evidence["schema"] != "factory.trivy-rule-execution.v1"
        or evidence["sources"] != sources
        or not isinstance(lane.get("native_policy"), dict)
    ):
        raise RuntimeAuditError("E_TRIVY_EXECUTION", "signed Trivy evidence is missing")
    try:
        config = base64.b64decode(evidence["config_base64"], validate=True)
        ignore = base64.b64decode(evidence["ignore_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy policy bytes are malformed"
        ) from exc
    if sha256_bytes(config) != lane["native_policy"]["config_sha256"]:
        raise RuntimeAuditError("E_TRIVY_POLICY", "Trivy config identity differs")
    observations = evidence["observations"]
    if (
        not isinstance(observations, list)
        or len(observations) != 2
        or any(not isinstance(item, dict) for item in observations)
        or [item.get("format") for item in observations] != ["sarif", "json"]
    ):
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "paired Trivy observations are missing"
        )
    expected_ignore = lane["native_policy"]["baseline_ignore_sha256"]
    if disabled_rule_id is not None:
        expected_ignore = lane.get("mutation_config_sha256", {}).get(disabled_rule_id)
    if not expected_ignore or sha256_bytes(ignore) != expected_ignore:
        raise RuntimeAuditError("E_TRIVY_POLICY", "Trivy ignorefile identity differs")
    if disabled_rule_id is not None and not _trivy_mutation_valid(
        b"", ignore, disabled_rule_id
    ):
        raise RuntimeAuditError("E_TRIVY_MUTATION", "Trivy target ignore differs")
    return config, ignore, observations


def _trivy_expected_ids(lane, disabled_rule_id):
    ids = lane.get("rule_ids")
    if not isinstance(ids, list) or not ids or ids != sorted(set(ids)):
        raise RuntimeAuditError(
            "E_TRIVY_RULES", "signed Trivy check inventory is missing"
        )
    if disabled_rule_id is not None:
        if disabled_rule_id not in ids:
            raise RuntimeAuditError(
                "E_TRIVY_MUTATION", "target is not a signed Trivy check"
            )
        ids = [item for item in ids if item != disabled_rule_id]
    return ids


def _trivy_observation_bytes(item):
    import base64

    fields = {"format", "argv", "execution", "raw_report_base64", "raw_report_sha256"}
    if not isinstance(item, dict) or set(item) != fields:
        raise RuntimeAuditError("E_TRIVY_EXECUTION", "Trivy observation shape differs")
    try:
        raw = base64.b64decode(item["raw_report_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy report bytes are malformed"
        ) from exc
    if len(raw) > LIMIT or sha256_bytes(raw) != item["raw_report_sha256"]:
        raise RuntimeAuditError("E_TRIVY_EXECUTION", "Trivy report bytes differ")
    return raw


def _trivy_pair_identity(sarif_argv, json_argv):
    if not isinstance(sarif_argv, list) or not isinstance(json_argv, list):
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command vectors are missing"
        )
    _trivy_closed_argv(sarif_argv)
    expected = list(sarif_argv)
    try:
        expected[expected.index("--format") + 1] = "json"
        expected[expected.index("--output") + 1] = json_argv[
            json_argv.index("--output") + 1
        ]
        expected.insert(expected.index("config") + 1, "--include-non-failures")
    except (ValueError, IndexError) as exc:
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command pair is malformed"
        ) from exc
    try:
        first_output = sarif_argv[sarif_argv.index("--output") + 1]
        second_output = json_argv[json_argv.index("--output") + 1]
        formats_match = (
            sarif_argv[sarif_argv.index("--format") + 1] == "sarif"
            and json_argv[json_argv.index("--format") + 1] == "json"
        )
        input_match = sarif_argv[-1] == json_argv[-1]
        fixed = (
            sarif_argv[0:2] == ["/usr/local/bin/trivy", "config"]
            and sarif_argv[sarif_argv.index("--config") + 1]
            == "/opt/factory/rules/trivy.yaml"
            and sarif_argv[sarif_argv.index("--ignorefile") + 1]
            == json_argv[json_argv.index("--ignorefile") + 1]
        )
    except (ValueError, IndexError) as exc:
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command pair is incomplete"
        ) from exc
    if (
        json_argv != expected
        or first_output == second_output
        or not formats_match
        or not input_match
        or not fixed
    ):
        raise RuntimeAuditError("E_TRIVY_EXECUTION", "Trivy command pair differs")


def _trivy_closed_argv(argv):
    if len(argv) != 14:
        raise RuntimeAuditError("E_TRIVY_EXECUTION", "Trivy command is not closed")
    expected = [
        "/usr/local/bin/trivy",
        "config",
        "--config",
        "/opt/factory/rules/trivy.yaml",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
        "--ignorefile",
        argv[8],
        "--format",
        "sarif",
        "--output",
        argv[12],
        argv[13],
    ]
    if argv != expected or any(
        not value.startswith("/") for value in (argv[8], argv[12], argv[13])
    ):
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "Trivy command permits unbound options"
        )


def _trivy_matrix_ids(matrix, expected_ids):
    for rows in matrix.values():
        if sorted(rows) != expected_ids:
            raise RuntimeAuditError(
                "E_TRIVY_APPLICABILITY", "signed Trivy check IDs differ"
            )


def _trivy_sarif_failures(report, sources, source_root=None):
    import copy

    if not isinstance(report, dict) or not isinstance(report.get("runs"), list):
        raise RuntimeAuditError("E_TRIVY_REPORT", "Trivy SARIF is malformed")
    normalized = copy.deepcopy(report)
    if source_root is not None:
        for run in normalized["runs"]:
            _normalize_challenge_run(run, source_root.rstrip("/"))
    normalized = _native_sarif_paths(normalized, sources)
    failures = set()
    for run in normalized["runs"]:
        for result in run.get("results", []):
            rule = require_str(result.get("ruleId"), "Trivy SARIF rule ID", maximum=256)
            locations = result.get("locations", [])
            if len(locations) != 1:
                raise RuntimeAuditError(
                    "E_TRIVY_REPORT", "Trivy finding location is ambiguous"
                )
            location = (
                locations[0].get("physicalLocation", {}).get("artifactLocation", {})
            )
            path = relative_path(location.get("uri"))
            if path not in sources or (path, rule) in failures:
                raise RuntimeAuditError(
                    "E_TRIVY_REPORT", "Trivy SARIF finding is unbound"
                )
            failures.add((path, rule))
    return failures


def _semgrep_rule_inventory(config, lane):
    import yaml

    if sha256_bytes(config) != lane["ruleset_sha256"]:
        raise RuntimeAuditError("E_SEMGREP_RULESET", "pinned Semgrep ruleset differs")
    try:
        rules = yaml.safe_load(config)["rules"]
    except (yaml.YAMLError, KeyError, TypeError) as exc:
        raise RuntimeAuditError("E_SEMGREP_RULESET", "invalid Semgrep rules") from exc
    if not isinstance(rules, list) or not 1 <= len(rules) <= 64:
        raise RuntimeAuditError("E_SEMGREP_RULESET", "bounded rules required")
    if any(not isinstance(rule, dict) for rule in rules):
        raise RuntimeAuditError("E_SEMGREP_RULESET", "rule objects required")
    ids = [require_str(rule.get("id"), "rule id", maximum=256) for rule in rules]
    if len(set(ids)) != len(ids) or sorted(ids) != lane.get("rule_ids"):
        raise RuntimeAuditError("E_SEMGREP_RULESET", "signed rule inventory differs")
    inventory = {"ruleset_sha256": lane["ruleset_sha256"], "rule_ids": sorted(ids)}
    return sorted(rules, key=lambda rule: rule["id"]), {
        "state": "VERIFIED",
        "rule_ids": sorted(ids),
        "sha256": digest(inventory),
    }


def _semgrep_rule_runs(profile, lane, source, scratch, rules, started):
    import base64
    from .runtime_audit_process import run_bounded_command

    observations = []
    deadline = started + lane["timeout_seconds"]
    for index, rule in enumerate(rules):
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            raise RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "Semgrep rule budget exhausted"
            )
        directory = scratch / f"semgrep-rule-{index}"
        directory.mkdir()
        config = canonical_bytes({"rules": [rule]})
        config_path, report_path = directory / "rule.json", directory / "report.json"
        config_path.write_bytes(config)
        argv = [
            profile["commands"][0]["argv"][0],
            "scan",
            "--json",
            "--strict",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--disable-nosem",
            "--no-rewrite-rule-ids",
            "--config",
            str(config_path),
            "--json-output",
            str(report_path),
            str(source),
        ]
        facts = run_bounded_command(argv, source, remaining, directory)
        if _adapter_command_failed(facts, [0], deadline):
            raise RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "native rule execution failed"
            )
        with local_file(directory, "report.json").open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        report = strict_json(raw)
        observations.append(
            {
                "rule_id": rule["id"],
                "rule_config_sha256": sha256_bytes(config),
                "rule_config_base64": base64.b64encode(config).decode("ascii"),
                "argv_sha256": digest(argv),
                "argv": argv,
                "execution": facts,
                "native_report": report,
                "native_report_sha256": digest(report),
                "raw_report_sha256": sha256_bytes(raw),
                "raw_report_base64": base64.b64encode(raw).decode("ascii"),
            }
        )
    return {"schema": "factory.semgrep-rule-execution.v1", "observations": observations}


def verify_semgrep_rule_execution(evidence, lane, sources, report):
    """Re-derive execution and findings from exact pinned rules plus per-rule native JSON."""
    from .runtime_audit_common import _validate_runner_facts

    rules, observations = _semgrep_evidence_inputs(evidence, lane, sources)
    findings, dispositions = [], []
    for index, (rule, observation) in enumerate(zip(rules, observations)):
        _semgrep_observation_identity(rule, observation, index)
        facts = observation["execution"]
        _validate_runner_facts(facts, facts.get("timeout_seconds"))
        if facts["timeout_seconds"] > lane["timeout_seconds"]:
            raise RuntimeAuditError("E_SEMGREP_EXECUTION", "rule exceeds signed budget")
        if _adapter_command_failed(facts, [0], float("inf")):
            raise RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "native rule did not complete"
            )
        native = observation["native_report"]
        expected = _semgrep_rule_sources(rule, sources)
        scanned = _semgrep_scanned_sources(native, sources, lane)
        if scanned != expected:
            raise RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "native source execution differs"
            )
        findings.extend(_semgrep_json_findings(native, rule["id"], sources))
        dispositions.append(
            {
                "rule_id": rule["id"],
                "executed_sources": sorted(scanned),
                "not_applicable_sources": sorted(set(sources) - scanned),
                "native_report_sha256": observation["native_report_sha256"],
            }
        )
    baseline = _semgrep_sarif_findings(report, lane["rule_ids"], sources)
    if sorted(findings) != sorted(baseline):
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "per-rule findings contradict baseline"
        )
    return {"state": "VERIFIED", "rules": dispositions, "findings": len(findings)}


def _semgrep_evidence_inputs(evidence, lane, sources):
    import base64

    if (
        not isinstance(evidence, dict)
        or set(evidence) != {"schema", "ruleset_base64", "observations"}
        or evidence["schema"] != "factory.semgrep-rule-execution.v1"
    ):
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "native rule evidence missing")
    try:
        config = base64.b64decode(evidence["ruleset_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeAuditError("E_SEMGREP_RULESET", "invalid native ruleset") from exc
    rules, _inventory = _semgrep_rule_inventory(config, lane)
    observations = evidence["observations"]
    if not isinstance(observations, list) or len(observations) != len(rules):
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "rule observation inventory differs"
        )
    if len(sources) > 64:
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "bounded source inventory required"
        )
    return rules, observations


def _semgrep_observation_identity(rule, observation, index):
    import base64

    fields = {
        "rule_id",
        "rule_config_sha256",
        "rule_config_base64",
        "argv_sha256",
        "argv",
        "execution",
        "native_report",
        "native_report_sha256",
        "raw_report_sha256",
        "raw_report_base64",
    }
    if not isinstance(observation, dict) or set(observation) != fields:
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "invalid native rule record")
    if observation["rule_id"] != rule["id"] or observation[
        "rule_config_sha256"
    ] != digest({"rules": [rule]}):
        raise RuntimeAuditError("E_SEMGREP_RULESET", "isolated native rule differs")
    if observation["rule_config_base64"] != base64.b64encode(
        canonical_bytes({"rules": [rule]})
    ).decode("ascii"):
        raise RuntimeAuditError("E_SEMGREP_RULESET", "native config bytes differ")
    for key in ("argv_sha256", "raw_report_sha256"):
        require_digest(observation[key], key)
    if digest(observation["native_report"]) != observation["native_report_sha256"]:
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "native report digest differs")
    _semgrep_raw_bindings(observation, index)


def _semgrep_raw_bindings(observation, index):
    import base64
    from pathlib import PurePosixPath

    argv = observation["argv"]
    prefix = [
        "/usr/bin/semgrep",
        "scan",
        "--json",
        "--strict",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--disable-nosem",
        "--no-rewrite-rule-ids",
        "--config",
    ]
    if not isinstance(argv, list) or len(argv) != 14 or argv[:10] != prefix:
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "isolated command differs")
    config, report = PurePosixPath(argv[10]), PurePosixPath(argv[12])
    if (
        argv[11] != "--json-output"
        or argv[13] != "/src"
        or config.name != "rule.json"
        or report.name != "report.json"
        or config.parent != report.parent
        or config.parent.name != f"semgrep-rule-{index}"
        or not config.is_absolute()
        or ".." in config.parts
        or not str(config).startswith("/tmp/factory-native-")
        or digest(argv) != observation["argv_sha256"]
    ):
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "native command binding differs")
    encoded = observation["raw_report_base64"]
    if not isinstance(encoded, str) or len(encoded) > (LIMIT + 2) // 3 * 4:
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "bounded raw report required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "invalid raw report") from exc
    if (
        len(raw) > LIMIT
        or sha256_bytes(raw) != observation["raw_report_sha256"]
        or strict_json(raw) != observation["native_report"]
    ):
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "raw report binding differs")


def _semgrep_rule_sources(rule, sources):
    languages = rule.get("languages")
    if (
        not isinstance(languages, list)
        or not languages
        or not set(languages) <= {"python", "javascript", "typescript"}
    ):
        raise RuntimeAuditError(
            "E_SEMGREP_RULESET", "unsupported pinned rule languages"
        )
    return {path for path in sources if source_language(path, b"") in languages}


def _semgrep_scanned_sources(native, sources, lane):
    if (
        not isinstance(native, dict)
        or native.get("version") != lane["tool_version"]
        or native.get("errors") != []
    ):
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "native report failed or version drifted"
        )
    paths = native.get("paths", {}).get("scanned")
    if not isinstance(paths, list) or len(paths) > 64:
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "bounded native scanned paths required"
        )
    observed = [_native_source_path(path, sources) for path in paths]
    if len(set(observed)) != len(observed):
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "duplicate native source execution"
        )
    return set(observed)


def _semgrep_json_findings(native, rule_id, sources):
    results = native.get("results")
    if not isinstance(results, list) or len(results) > 20_000:
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "bounded native results required"
        )
    findings = []
    for result in results:
        if not isinstance(result, dict) or result.get("check_id") != rule_id:
            raise RuntimeAuditError(
                "E_SEMGREP_EXECUTION", "unselected detector finding"
            )
        path = _native_source_path(result.get("path"), sources)
        line = require_int(
            result.get("start", {}).get("line"),
            "finding line",
            minimum=1,
            maximum=10**9,
        )
        findings.append((rule_id, path, line))
    if len(set(findings)) != len(findings):
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "duplicate native findings")
    return findings


def _semgrep_sarif_findings(report, rule_ids, sources):
    findings = []
    for run in report["runs"]:
        for item in run.get("results", []):
            matches = [
                rule
                for rule in rule_ids
                if item["ruleId"] == rule or item["ruleId"].endswith("." + rule)
            ]
            if len(matches) != 1 or len(item["locations"]) != 1:
                raise RuntimeAuditError(
                    "E_SEMGREP_EXECUTION", "baseline detector identity differs"
                )
            place = item["locations"][0]["physicalLocation"]
            path = _native_source_path(place["artifactLocation"]["uri"], sources)
            findings.append((matches[0], path, place["region"]["startLine"]))
    if len(set(findings)) != len(findings):
        raise RuntimeAuditError("E_SEMGREP_EXECUTION", "duplicate baseline findings")
    return findings


def _runtime_exit_consistency(report, invocations):
    if len(invocations) != 1:
        raise RuntimeAuditError("E_RUNTIME_REPORT", "one runtime invocation required")
    code = invocations[0].get("execution", {}).get("exit_code")
    expected = 1 if report["findings"] else 0
    if type(code) is not int or code != expected:
        raise RuntimeAuditError("E_RUNTIME_REPORT", "JUnit and process exit differ")


def _runtime_report_file(raw, lane, inventory, output):
    if raw.get("meta", {}).get("branch_coverage") is not True:
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native branch measurement required"
        )
    report_name = lane["report"]
    return _native_coverage_report(raw, lane, inventory, output, report_name)


def _native_profile_coverage(
    execution, report, inventory, lane, profile, challenges, covered_obligations
):
    ledger = execution["ledger"]
    ledger_sha256 = execution["ledger_sha256"]
    rule_accounting = None
    native_source_inventory = None
    native_source_inventory_sha256 = None
    if lane["engine"] == "gitleaks" and ledger is not None and ledger_sha256:
        _gitleaks_coverage_preflight(
            execution, report, inventory, lane, challenges, covered_obligations
        )
        (
            rule_accounting,
            native_source_inventory,
            native_source_inventory_sha256,
        ) = _gitleaks_ledger_matrix(
            ledger,
            ledger_sha256,
            lane,
            inventory,
            execution["rule_inventory"]["sha256"],
            execution["invocations"],
            execution["raw_report"],
        )
    errors = ["NATIVE_SOURCE_ACCOUNTING_REQUIRED", "NATIVE_CHALLENGES_REQUIRED"]
    complete = False
    if lane["engine"] == "gitleaks":
        errors = _gitleaks_coverage_errors(
            rule_accounting, challenges, covered_obligations
        )
        complete = not errors
    elif lane["engine"] == "trivy":
        errors = _trivy_coverage_errors(
            execution, report, inventory, lane, challenges, covered_obligations
        )
        complete = not errors
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        errors = _runtime_coverage_errors(
            report, inventory, lane, challenges, covered_obligations
        )
        complete = not errors
    elif execution.get("semgrep_rule_execution") is not None:
        _semgrep_source_accounting(execution, inventory, lane)
        errors = (
            []
            if _gitleaks_challenges_complete(challenges, covered_obligations)
            else ["NATIVE_CHALLENGES_REQUIRED"]
        )
        complete = not errors
    elif lane["engine"] == "osv":
        errors = []
        if (
            _native_source_accounting(execution, report, inventory, lane)["state"]
            != "COMPLETE"
        ):
            errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
        if not _osv_challenges_complete(challenges, covered_obligations):
            errors.append("NATIVE_CHALLENGES_REQUIRED")
        complete = not errors
    coverage = {
        "profile_sha256": digest(profile),
        "image_binding_sha256": sha256_bytes(
            str(lane.get("image", "")).encode("utf-8")
        ),
        "schema": "factory.deep-coverage.v1",
        "complete": complete,
        "sources": {
            item["path"]: item["sha256"]
            for item in inventory["files"]
            if item["language"] in lane["languages"]
        },
        "mode": lane["mode"],
        "fallback": False,
        "tool_version": profile["tool_version"],
        "ruleset_sha256": profile["ruleset_sha256"],
        "report_sha256": digest(report),
        "native_report_sha256": digest(execution["raw_report"]),
        "source_accounting": _native_source_accounting(
            execution, report, inventory, lane
        ),
        "native_invocations": execution["invocations"],
        "invocation_sha256": digest(execution["invocations"]),
        "version_probe": execution["version_probe"],
        "errors": errors,
        "obligations": covered_obligations,
        **(
            {"codeql_query_inventory": execution["codeql_query_inventory"]}
            if execution.get("codeql_query_inventory") is not None
            else {}
        ),
        **(
            {"codeql_query_execution": execution["codeql_query_execution"]}
            if execution.get("codeql_query_execution") is not None
            else {}
        ),
        **(
            {"codeql_source_execution": execution["codeql_source_execution"]}
            if execution.get("codeql_source_execution") is not None
            else {}
        ),
        **(
            {"semgrep_rule_execution": execution["semgrep_rule_execution"]}
            if execution.get("semgrep_rule_execution") is not None
            else {}
        ),
        **(
            {"trivy_rule_execution": execution["trivy_rule_execution"]}
            if execution.get("trivy_rule_execution") is not None
            else {}
        ),
        **(
            {"rule_inventory": execution["rule_inventory"]}
            if execution["rule_inventory"] is not None
            else {}
        ),
        **(
            {
                "candidate_sha256": inventory["candidate_sha256"],
                "native_rule_ledger_json": execution["ledger_json"],
                "native_rule_ledger_sha256": ledger_sha256,
                "native_source_inventory": inventory["files"]
                if ledger is not None
                else None,
                "native_source_inventory_sha256": native_source_inventory_sha256,
            }
            if ledger is not None
            else {}
        ),
        **({"rule_accounting": rule_accounting} if rule_accounting is not None else {}),
    }
    if lane["engine"] == "gitleaks":
        source_count = len(coverage["sources"])
        rule_count = len(lane["rule_ids"])
        _bounded_json_bytes(
            coverage,
            NATIVE_COVERAGE_LIMIT,
            "E_GITLEAKS_LEDGER_SIZE",
            source_count,
            rule_count,
        )
    return coverage


def _osv_challenges_complete(challenges, covered_obligations):
    observations = challenges.get("observations", [])
    identities = {item.get("obligation_id") for item in observations}
    controls = {(item.get("obligation_id"), item.get("kind")) for item in observations}
    return (
        bool(identities)
        and not challenges.get("gaps")
        and controls
        == {
            (identity, kind)
            for identity in identities
            for kind in ("positive", "negative", "mutation")
        }
        and set(covered_obligations) == identities
        and len(covered_obligations) == len(identities)
        and all(
            item.get("execution", {}).get("status") == "VERIFIED"
            for item in observations
        )
    )


def _codeql_query_preflight(profile, source, scratch, remaining, *, engine="codeql"):
    if engine != "codeql":
        return None
    if remaining < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "query resolution deadline exhausted"
        )
    commands = profile.get("commands")
    if not isinstance(commands, list) or len(commands) < 2:
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "analyze command required")
    command = commands[1]
    argv = command.get("argv") if isinstance(command, dict) else None
    if not isinstance(argv, list) or len(argv) < 5:
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "bounded analyze argv required")
    if argv[1:3] != ["database", "analyze"] or not isinstance(argv[4], str):
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "native analyze suite required")
    return resolve_codeql_query_inventory(
        argv[0], Path(argv[4]), source, scratch, remaining
    )


def _codeql_suite_bytes(suite):
    with suite.open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576 or suite.is_symlink():
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "bounded regular suite required")
    return raw


def resolve_codeql_query_inventory(codeql, suite, source, scratch, timeout):
    """Record native suite resolution and query bytes, not query execution coverage."""
    from .runtime_audit_process import run_bounded_command

    timeout = require_int(timeout, "query resolution timeout", minimum=1, maximum=3600)
    suite = local_file(Path(suite).parent, Path(suite).name)
    suite_raw = _codeql_suite_bytes(suite)
    run_root = Path(scratch) / ("query-resolution-" + uuid.uuid4().hex)
    run_root.mkdir()
    capture = run_root / "queries.json"
    argv = [str(codeql), "resolve", "queries", "--format=json", "--", str(suite)]
    deadline = time.monotonic() + timeout
    facts = run_bounded_command(argv, source, timeout, run_root, stdout_path=capture)
    if _adapter_command_failed(facts, [0], deadline):
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "native query resolution failed")
    with capture.open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576 or sha256_bytes(raw) != facts["stdout_sha256"]:
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "query resolution output differs")
    try:
        paths = json.loads(raw, parse_constant=_finite)
    except (ValueError, RecursionError, UnicodeError) as error:
        raise RuntimeAuditError(
            "E_CODEQL_INVENTORY", "invalid query resolution JSON"
        ) from error
    queries = _codeql_resolved_queries(paths)
    if _codeql_suite_bytes(suite) != suite_raw:
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "suite changed during resolution")
    return dict(
        schema="factory.codeql-query-inventory.v1",
        suite_sha256=sha256_bytes(suite_raw),
        queries=queries,
        query_ids=_codeql_query_ids(queries),
        query_inventory_sha256=digest(queries),
        argv=argv,
        argv_sha256=digest(argv),
        execution=facts,
        raw_resolution_sha256=sha256_bytes(raw),
        claim_boundary="Native suite selection and query content identity only; not execution or source coverage",
    )


def _codeql_resolved_queries(paths):
    if not isinstance(paths, list) or not 1 <= len(paths) <= 1024:
        raise RuntimeAuditError(
            "E_CODEQL_INVENTORY", "bounded nonempty query list required"
        )
    queries, total = {}, 0
    root = Path("/opt/codeql/codeql/qlpacks")
    for value in paths:
        require_str(value, "resolved query", maximum=2048)
        path = Path(value)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as error:
            raise RuntimeAuditError(
                "E_CODEQL_INVENTORY", "query is outside pinned packs"
            ) from error
        relative_path(relative)
        if path.suffix != ".ql" or relative in queries:
            raise RuntimeAuditError("E_CODEQL_INVENTORY", "duplicate or non-query path")
        with local_file(root, relative).open("rb") as stream:
            raw = stream.read(1_048_577)
        total += len(raw)
        if len(raw) > 1_048_576 or total > 8_388_608:
            raise RuntimeAuditError(
                "E_CODEQL_INVENTORY", "query content budget exceeded"
            )
        queries[relative] = sha256_bytes(raw)
    return dict(sorted(queries.items()))


def verify_codeql_query_isolation(baseline, mutated, target_query):
    """Require exactly one removed query and unchanged nonempty sentinel inventory."""
    relative_path(target_query)
    for inventory in (baseline, mutated):
        if not isinstance(inventory, dict) or not inventory:
            raise RuntimeAuditError("E_CODEQL_MUTATION", "query inventory required")
        for path, seal in inventory.items():
            relative_path(path)
            require_digest(seal, "query content hash")
    expected = {path: seal for path, seal in baseline.items() if path != target_query}
    if target_query not in baseline or not expected or mutated != expected:
        raise RuntimeAuditError(
            "E_CODEQL_MUTATION", "mutation must remove only target query"
        )
    return dict(
        disabled_query=target_query, remaining_query_inventory_sha256=digest(mutated)
    )


def _codeql_query_ids(queries):
    import re

    identifiers = {}
    root = Path("/opt/codeql/codeql/qlpacks")
    for path, expected in queries.items():
        with local_file(root, path).open("rb") as stream:
            raw = stream.read(1_048_577)
        if sha256_bytes(raw) != expected:
            raise RuntimeAuditError(
                "E_CODEQL_INVENTORY", "query changed during metadata read"
            )
        text = raw.decode("utf-8")
        ids = re.findall(r"(?m)^\s*\*\s*@id\s+([^\s]+)\s*$", text)
        if len(ids) != 1 or ids[0] in identifiers:
            raise RuntimeAuditError(
                "E_CODEQL_INVENTORY", "unique native query ID required"
            )
        require_str(ids[0], "native query ID", maximum=256)
        identifiers[ids[0]] = path
    return dict(sorted(identifiers.items()))


def _codeql_selection_shape(inventory):
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema") != "factory.codeql-query-inventory.v1"
    ):
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "native query inventory required")
    queries, identifiers = inventory.get("queries"), inventory.get("query_ids")
    if not isinstance(queries, dict) or not 1 <= len(queries) <= 1024:
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "bounded query map required")
    for path, seal in queries.items():
        relative_path(path)
        require_digest(seal, "query content hash")
        if not path.startswith("codeql/") or not path.endswith(".ql"):
            raise RuntimeAuditError("E_CODEQL_INVENTORY", "pinned query path required")
    _codeql_selection_ids(identifiers, queries)
    require_digest(inventory.get("suite_sha256"), "suite hash")
    if inventory.get("query_inventory_sha256") != digest(queries):
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "query inventory hash differs")
    return queries, identifiers


def _codeql_selection_ids(identifiers, queries):
    if not isinstance(identifiers, dict) or len(identifiers) != len(queries):
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "complete query ID map required")
    for rule_id, path in identifiers.items():
        require_str(rule_id, "native query ID", maximum=256)
        relative_path(path)
    if set(identifiers.values()) != set(queries):
        raise RuntimeAuditError(
            "E_CODEQL_INVENTORY", "one-to-one query ID mapping required"
        )


def verify_codeql_query_selection(inventory, *, baseline=None, disabled_rule_id=None):
    """Validate selected query identity against a baseline, without claiming execution."""
    queries, identifiers = _codeql_selection_shape(inventory)
    if baseline is None:
        if disabled_rule_id is not None:
            raise RuntimeAuditError(
                "E_CODEQL_MUTATION", "baseline required for mutation"
            )
        return
    original, original_ids = _codeql_selection_shape(baseline)
    if disabled_rule_id is not None:
        if disabled_rule_id not in original_ids:
            raise RuntimeAuditError("E_CODEQL_MUTATION", "target query ID absent")
        verify_codeql_query_isolation(original, queries, original_ids[disabled_rule_id])
        expected_ids = {
            key: value for key, value in original_ids.items() if key != disabled_rule_id
        }
    else:
        expected_ids = original_ids
        if queries != original or inventory["suite_sha256"] != baseline["suite_sha256"]:
            raise RuntimeAuditError(
                "E_CODEQL_INVENTORY", "baseline query selection differs"
            )
    if identifiers != expected_ids:
        raise RuntimeAuditError("E_CODEQL_INVENTORY", "query ID binding differs")


def _codeql_result_path(query_path):
    try:
        parts = relative_path(query_path).split("/")
    except (RuntimeAuditError, TypeError, ValueError) as error:
        raise RuntimeAuditError(
            "E_CODEQL_EXECUTION", "relative query path required"
        ) from error
    if (
        len(parts) < 4
        or parts[0] != "codeql"
        or parts[1] not in {"javascript-queries", "python-queries", "actions-queries"}
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", parts[2]) is None
        or not parts[-1].endswith(".ql")
    ):
        raise RuntimeAuditError("E_CODEQL_EXECUTION", "pinned query path required")
    return "results/" + "/".join(parts[:2] + parts[3:])[:-3] + ".bqrs"


def _codeql_result_sets(raw):
    if not isinstance(raw, bytes) or len(raw) > 65_536:
        raise RuntimeAuditError("E_CODEQL_EXECUTION", "bounded result info required")
    try:
        sets = json.loads(raw)["result-sets"]
        if not isinstance(sets, list) or not 1 <= len(sets) <= 64:
            raise ValueError("result sets required")
        result, names = [], set()
        for item in sets:
            name = require_str(item["name"], "result name", maximum=256)
            rows = require_int(
                item["rows"], "result rows", minimum=0, maximum=2**63 - 1
            )
            columns = item["columns"]
            if name in names or not isinstance(columns, list) or len(columns) > 256:
                raise ValueError("unique bounded result sets required")
            names.add(name)
            result.append({"name": name, "rows": rows, "columns": len(columns)})
        return result
    except (ValueError, KeyError, TypeError, RuntimeAuditError) as error:
        raise RuntimeAuditError(
            "E_CODEQL_EXECUTION", "invalid native result info"
        ) from error


def _codeql_parse_rows(raw):
    if not isinstance(raw, bytes) or len(raw) > NATIVE_COVERAGE_LIMIT:
        raise RuntimeAuditError(
            "E_CODEQL_SOURCE", "bounded source query output required"
        )
    try:
        result = json.loads(raw)["#select"]
        if (
            not isinstance(result["columns"], list)
            or result["columns"]
            != [{"kind": "String"}, {"kind": "Integer"}, {"kind": "Integer"}]
            or not isinstance(result["tuples"], list)
        ):
            raise ValueError("three-column source rows required")
        if len(result["tuples"]) > 20_000:
            raise ValueError("source row budget exceeded")
        rows = {}
        for row in result["tuples"]:
            path, nodes, errors = row
            path = relative_path(path)
            if path in rows:
                raise ValueError("duplicate source row")
            rows[path] = {
                "syntax_nodes": require_int(
                    nodes, "syntax nodes", minimum=0, maximum=2**31 - 1
                ),
                "parse_errors": require_int(
                    errors, "parse errors", minimum=0, maximum=2**31 - 1
                ),
            }
        return rows
    except (RuntimeAuditError, ValueError, TypeError, KeyError) as error:
        raise RuntimeAuditError(
            "E_CODEQL_SOURCE", "invalid native source query output"
        ) from error


def _codeql_native_blob(raw, maximum=67_108_864):
    import base64
    import zlib

    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise RuntimeAuditError("E_CODEQL_ARTIFACT", "native artifact budget exceeded")
    compressed = zlib.compress(raw)
    if len(compressed) > NATIVE_COVERAGE_LIMIT:
        raise RuntimeAuditError(
            "E_CODEQL_ARTIFACT", "compressed artifact budget exceeded"
        )
    return {
        "encoding": "zlib-base64",
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "data": base64.b64encode(compressed).decode("ascii"),
    }


def _codeql_blob_bytes(blob, maximum=67_108_864):
    import base64
    import zlib

    try:
        if not isinstance(blob, dict) or set(blob) != {
            "encoding",
            "bytes",
            "sha256",
            "data",
        }:
            raise ValueError("exact artifact fields required")
        size = require_int(blob["bytes"], "artifact bytes", minimum=0, maximum=maximum)
        seal = require_digest(blob["sha256"], "artifact hash")
        if (
            blob["encoding"] != "zlib-base64"
            or not isinstance(blob["data"], str)
            or len(blob["data"]) > 4 * ((NATIVE_COVERAGE_LIMIT + 2) // 3)
        ):
            raise ValueError("bounded compressed artifact required")
        compressed = base64.b64decode(blob["data"], validate=True)
        if len(compressed) > NATIVE_COVERAGE_LIMIT:
            raise ValueError("compressed artifact budget exceeded")
        decoder = zlib.decompressobj()
        raw = decoder.decompress(compressed, size + 1)
        if (
            len(raw) != size
            or not decoder.eof
            or decoder.unconsumed_tail
            or decoder.unused_data
            or sha256_bytes(raw) != seal
        ):
            raise ValueError("native artifact bytes differ")
        return raw
    except (RuntimeAuditError, ValueError, TypeError, KeyError, zlib.error) as error:
        raise RuntimeAuditError(
            "E_CODEQL_ARTIFACT", "invalid retained native artifact"
        ) from error


def _codeql_source_query(profile):
    languages = {
        arg.removeprefix("--language=")
        for command in profile["commands"]
        for arg in command["argv"]
        if arg.startswith("--language=")
    }
    definitions = {
        "javascript-typescript": (
            "javascript",
            "TopLevel",
            "JSParseError",
            "e.getFile()",
            "",
        ),
        "python": ("python", "Module", "SyntaxError", "e.getFile()", ""),
        "actions": (
            "actions",
            "YamlDocument",
            "YamlParseError",
            "e.getLocation().getFile()",
            "import codeql.files.FileSystem\nimport codeql.actions.ast.internal.Yaml\n",
        ),
    }
    if len(languages) != 1 or not languages <= definitions.keys():
        raise RuntimeAuditError("E_CODEQL_SOURCE", "one supported extractor required")
    library, node, error, location, imports = definitions[languages.pop()]
    query = (
        f"import {library}\n{imports}from File f select f.getRelativePath(), "
        f"count({node} n | n.getFile()=f), count({error} e | {location}=f)\n"
    ).encode("utf-8")
    return library, query


def verify_codeql_retained_evidence(coverage, lane, required):
    """Verify retained native bytes; opaque BQRS still requires independent replay."""
    try:
        inventory, records = _codeql_retained_inventory(coverage, lane)
        seen, total = set(), 0
        for record in records:
            rule_id = record["rule_id"]
            if (
                rule_id in seen
                or inventory["query_ids"].get(rule_id) != record["query_path"]
            ):
                raise ValueError("duplicate or unexpected query record")
            seen.add(rule_id)
            total += _codeql_verify_retained_query(record, inventory)
            if total > 536_870_912:
                raise ValueError("aggregate native artifact budget exceeded")
        source = _codeql_verify_retained_source(
            coverage["codeql_source_execution"], required
        )
        return {
            "state": "REPLAY_REQUIRED",
            "queries": len(seen),
            "source_accounting": source,
        }
    except (
        RuntimeAuditError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
    ) as error:
        raise RuntimeAuditError(
            "E_CODEQL_ARTIFACT", "retained CodeQL evidence is unverified"
        ) from error


def _codeql_retained_inventory(coverage, lane):
    inventory = coverage["codeql_query_inventory"]
    verify_codeql_query_selection(inventory)
    execution = coverage["codeql_query_execution"]
    if (
        execution["schema"] != "factory.codeql-query-execution.v1"
        or execution["query_inventory_sha256"] != inventory["query_inventory_sha256"]
        or execution["ruleset_sha256"] != lane["ruleset_sha256"]
        or execution["suite_sha256"] != inventory["suite_sha256"]
    ):
        raise ValueError("query execution inventory differs")
    records = execution["rules"]
    if (
        not isinstance(records, list)
        or len(records) != len(inventory["query_ids"])
        or lane["rule_ids"] != sorted(inventory["query_ids"])
    ):
        raise ValueError("complete native query records required")
    return inventory, records


def _codeql_verify_retained_query(record, inventory):
    blobs = record["native_artifacts"]
    if set(blobs) != {"result", "info"}:
        raise ValueError("native query artifact roles differ")
    raw = _codeql_blob_bytes(blobs["result"])
    info = _codeql_blob_bytes(blobs["info"], 65_536)
    if (
        not raw
        or len(raw) != record["result_bytes"]
        or sha256_bytes(raw) != record["result_sha256"]
        or record["query_sha256"] != inventory["queries"][record["query_path"]]
        or record["result_path"] != _codeql_result_path(record["query_path"])
    ):
        raise ValueError("native result binding differs")
    invocation = record["invocation"]
    _codeql_retained_invocation(invocation)
    if (
        invocation["argv_sha256"] != digest(invocation["argv"])
        or sha256_bytes(info) != invocation["execution"]["stdout_sha256"]
        or len(info) != invocation["execution"]["stdout_bytes"]
        or _codeql_result_sets(info) != record["result_sets"]
    ):
        raise ValueError("native result metadata differs")
    return len(raw)


def _codeql_retained_invocation(invocation):
    from .runtime_audit_common import _validate_runner_facts

    facts = invocation["execution"]
    _validate_runner_facts(facts, facts["timeout_seconds"])
    if (
        invocation["argv_sha256"] != digest(invocation["argv"])
        or facts["exit_code"] != 0
        or facts["timed_out"]
        or facts["launch_error"]
        or facts["output_limit_exceeded"]
        or facts["cleanup_confirmed"] is not True
        or facts.get("cancelled")
    ):
        raise ValueError("native invocation incomplete")


def _codeql_verify_retained_source(measurement, required):
    blobs = measurement["native_artifacts"]
    if set(blobs) != {"query", "package", "result", "decoded", "archive", "info"}:
        raise ValueError("native source artifact roles differ")
    raw = {key: _codeql_blob_bytes(blob) for key, blob in blobs.items()}
    invocations = measurement["native_invocations"]
    if not isinstance(invocations, list) or len(invocations) != 3:
        raise ValueError("all source measurement steps required")
    for invocation in invocations:
        _codeql_retained_invocation(invocation)
    if invocations[-1]["execution"]["stdout_sha256"] != sha256_bytes(
        raw["info"]
    ) or invocations[-1]["execution"]["stdout_bytes"] != len(raw["info"]):
        raise ValueError("source metadata stream differs")
    for role, field in {
        "query": "query_sha256",
        "package": "package_sha256",
        "result": "result_sha256",
        "decoded": "decoded_sha256",
        "archive": "archive_sha256",
    }.items():
        if sha256_bytes(raw[role]) != measurement[field]:
            raise ValueError("source artifact binding differs")
    rows = _codeql_parse_rows(raw["decoded"])
    if rows != measurement["rows"] or _codeql_result_sets(raw["info"]) != [
        {"name": "#select", "rows": len(rows), "columns": 3}
    ]:
        raise ValueError("native source rows differ")
    archived = _codeql_retained_archive(
        raw["archive"], measurement["archive_prefix"], required
    )
    if archived != measurement["archived_sources"]:
        raise ValueError("archived source bindings differ")
    inventory = {
        "files": [
            {"path": path, "sha256": seal, "language": "required"}
            for path, seal in required.items()
        ]
    }
    return _codeql_source_accounting(
        measurement, inventory, {"languages": ["required"]}
    )


def _codeql_retained_archive(raw, prefix, required):
    import io
    import zipfile

    if (
        not isinstance(prefix, str)
        or not prefix.endswith("/")
        or prefix.startswith("/")
        or "\\" in prefix
        or ".." in prefix.split("/")
    ):
        raise ValueError("canonical archive prefix required")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
            entries = zipped.infolist()
            if (
                len(entries) > 100_000
                or sum(item.file_size for item in entries) > 536_870_912
            ):
                raise ValueError("source archive budget exceeded")
            names = Counter(item.filename for item in entries)
            archived = {}
            for path in required:
                name = prefix + relative_path(path)
                if names[name] != 1:
                    continue
                with zipped.open(name) as member:
                    captured = member.read(LIMIT + 1)
                if len(captured) > LIMIT:
                    raise ValueError("source member budget exceeded")
                archived[path] = sha256_bytes(captured)
            return archived
    except (zipfile.BadZipFile, OSError, RuntimeError) as error:
        raise ValueError("invalid retained source archive") from error


def execute_codeql_native_replay(request, source, scratch, timeout):
    """Rerun the pinned suite and compare native values, never worker verdicts."""
    from .deep_audit_sarif import _native_execution_report

    lane, inventory = request["lane"], request["inventory"]
    coverage = request["coverage"]
    profile = strict_json(Path("/opt/factory/adapter-profile.json").read_bytes())
    _native_profile(profile, lane)
    _adapter_sources(source, inventory)
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    verify_codeql_retained_evidence(coverage, lane, required)
    deadline = time.monotonic() + require_int(
        timeout, "replay timeout", minimum=1, maximum=3600
    )
    _native_version(profile, source, scratch, _codeql_replay_remaining(deadline))
    selected = _codeql_query_preflight(
        profile, source, scratch, _codeql_replay_remaining(deadline)
    )
    _codeql_replay_selection(selected, coverage["codeql_query_inventory"])
    fresh = _codeql_replay_fresh(profile, source, scratch, inventory, lane, deadline)
    decoded = _codeql_replay_queries(
        profile, coverage, fresh, source, scratch, deadline
    )
    _codeql_replay_source_values(profile, coverage, fresh, source, scratch, deadline)
    _codeql_replay_sources(
        coverage["codeql_source_execution"], fresh["source"], inventory, lane
    )
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    findings = _native_execution_report(fresh["report"], lane, sources)
    if sorted(findings, key=canonical_bytes) != sorted(
        _native_execution_report(request["report"], lane, sources), key=canonical_bytes
    ):
        raise RuntimeAuditError("E_CODEQL_REPLAY", "independent findings differ")
    _adapter_sources(source, inventory)
    return {
        "schema": "factory.codeql-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": inventory["candidate_sha256"],
        "lane_sha256": digest(lane),
        "coverage_sha256": digest(coverage),
        "queries": len(decoded),
        "decoded_queries_sha256": digest(decoded),
        "findings_sha256": digest(findings),
        "source_paths": sorted(required),
        "native_execution_sha256": digest(fresh["invocations"]),
    }


def _codeql_replay_remaining(deadline):
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            "E_CODEQL_REPLAY", "independent replay deadline exhausted"
        )
    return remaining


def _codeql_replay_selection(actual, expected):
    for field in ("queries", "query_ids", "suite_sha256", "query_inventory_sha256"):
        if actual[field] != expected[field]:
            raise RuntimeAuditError(
                "E_CODEQL_REPLAY", "independent query selection differs"
            )


def _codeql_replay_fresh(profile, source, scratch, inventory, lane, deadline):
    report = scratch / "replay.sarif"
    commands = _native_argv(
        profile["commands"], {"source": source, "scratch": scratch, "report": report}
    )
    _, invocations = _codeql_steps_runner(
        commands, source, _codeql_replay_remaining(deadline), scratch
    )
    selected = _codeql_query_preflight(
        profile, source, scratch, _codeql_replay_remaining(deadline)
    )
    execution = _codeql_query_execution(profile, selected, source, scratch, deadline)
    measured = _codeql_source_measurement(
        profile, source, scratch, inventory, lane, deadline
    )
    with local_file(scratch, report.name).open("rb") as stream:
        native_report = strict_json(stream.read(LIMIT + 1))
    native_report = _native_report(
        native_report,
        profile,
        {"inventory": inventory, "lane": lane},
        scratch,
        invocations,
    )
    return {
        "execution": execution,
        "source": measured,
        "report": native_report,
        "invocations": invocations,
    }


def _codeql_replay_queries(profile, coverage, fresh, source, scratch, deadline):
    expected = {
        row["rule_id"]: row for row in coverage["codeql_query_execution"]["rules"]
    }
    actual = {row["rule_id"]: row for row in fresh["execution"]["rules"]}
    if set(expected) != set(actual):
        raise RuntimeAuditError("E_CODEQL_REPLAY", "independent query records differ")
    decoded, total = {}, 0
    for index, rule_id in enumerate(sorted(expected)):
        old, new = expected[rule_id], actual[rule_id]
        directory = scratch / f"replay-values-{index}"
        directory.mkdir()
        left = _codeql_replay_decode(
            profile, old, source, directory, "worker", deadline
        )
        right = _codeql_replay_decode(
            profile, new, source, directory, "fresh", deadline
        )
        if left != right:
            raise RuntimeAuditError(
                "E_CODEQL_REPLAY", "independent query values differ"
            )
        total += len(canonical_bytes(left)) + len(canonical_bytes(right))
        if total > 536_870_912:
            raise RuntimeAuditError("E_CODEQL_REPLAY", "decoded replay budget exceeded")
        decoded[old["rule_id"]] = digest(left)
    return decoded


def _codeql_replay_source_values(profile, coverage, fresh, source, scratch, deadline):
    directory = scratch / "replay-source-values"
    directory.mkdir()
    values = []
    for label, measurement in (
        ("worker", coverage["codeql_source_execution"]),
        ("fresh", fresh["source"]),
    ):
        record = {
            "native_artifacts": measurement["native_artifacts"],
            "result_sets": _codeql_result_sets(
                _codeql_blob_bytes(measurement["native_artifacts"]["info"], 65_536)
            ),
        }
        values.append(
            _codeql_replay_decode(profile, record, source, directory, label, deadline)
        )
    if values[0] != values[1]:
        raise RuntimeAuditError("E_CODEQL_REPLAY", "independent source values differ")


def _codeql_replay_decode(profile, record, source, directory, label, deadline):
    result = directory / (label + ".bqrs")
    result.write_bytes(_codeql_blob_bytes(record["native_artifacts"]["result"]))
    executable = profile["version_argv"][0]
    commands = [
        [executable, "bqrs", "info", str(result), "--format=json"],
        [
            executable,
            "bqrs",
            "decode",
            "--format=json",
            "--entities=all",
            "--",
            str(result),
        ],
    ]
    capture = directory / label
    capture.mkdir()
    _codeql_steps_runner(
        [{"argv": argv, "accepted_exit_codes": [0]} for argv in commands],
        source,
        _codeql_replay_remaining(deadline),
        capture,
        expected_steps=2,
    )
    with local_file(capture, "step-0/stdout.log").open("rb") as stream:
        sets = _codeql_result_sets(stream.read(65_537))
    if sets != record["result_sets"]:
        raise RuntimeAuditError(
            "E_CODEQL_REPLAY", "independent result metadata differs"
        )
    with local_file(capture, "step-1/stdout.log").open("rb") as stream:
        values = strict_json(stream.read(NATIVE_COVERAGE_LIMIT + 1))
    return _codeql_replay_values(values, sets)


def _codeql_replay_values(values, sets):
    if set(values) != {item["name"] for item in sets}:
        raise RuntimeAuditError("E_CODEQL_REPLAY", "decoded result sets differ")
    canonical = {}
    for item in sets:
        value = values[item["name"]]
        if set(value) != {"columns", "tuples"}:
            raise RuntimeAuditError(
                "E_CODEQL_REPLAY", "unexpected decoded result fields"
            )
        columns, rows = value["columns"], value["tuples"]
        if not isinstance(columns, list) or len(columns) != item["columns"]:
            raise RuntimeAuditError("E_CODEQL_REPLAY", "decoded columns differ")
        if not isinstance(rows, list) or len(rows) != item["rows"]:
            raise RuntimeAuditError("E_CODEQL_REPLAY", "decoded row count differs")
        if any(not isinstance(row, list) or len(row) != len(columns) for row in rows):
            raise RuntimeAuditError("E_CODEQL_REPLAY", "decoded tuple shape differs")
        canonical[item["name"]] = {
            "columns": columns,
            "tuples": sorted(rows, key=canonical_bytes),
        }
    return canonical


def _codeql_replay_sources(expected, actual, inventory, lane):
    for field in ("query_sha256", "package_sha256", "rows", "archived_sources"):
        if expected[field] != actual[field]:
            raise RuntimeAuditError(
                "E_CODEQL_REPLAY", "independent source measurement differs"
            )
    for measurement in (expected, actual):
        if (
            _codeql_source_accounting(measurement, inventory, lane)["state"]
            != "COMPLETE"
        ):
            raise RuntimeAuditError(
                "E_CODEQL_REPLAY", "source extraction is incomplete"
            )


def _codeql_source_measurement(profile, source, scratch, inventory, lane, deadline):
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "source evidence deadline exhausted"
        )
    library, query = _codeql_source_query(profile)
    directory = scratch / "source-evidence"
    directory.mkdir()
    pack = directory / "pack"
    pack.mkdir()
    package = (
        f"name: factory/{library}-source-accounting\nversion: 0.0.1\n"
        f"dependencies:\n  codeql/{library}-all: '*'\n"
    ).encode("utf-8")
    (pack / "sources.ql").write_bytes(query)
    (pack / "qlpack.yml").write_bytes(package)
    executable = profile["version_argv"][0]
    result, decoded = directory / "sources.bqrs", directory / "sources.json"
    argv = [
        [
            executable,
            "query",
            "run",
            str(pack / "sources.ql"),
            f"--database={scratch / 'codeql-db'}",
            f"--output={result}",
            "--search-path=/opt/codeql/codeql/qlpacks",
            "--threads=2",
            "--ram=2048",
        ],
        [
            executable,
            "bqrs",
            "decode",
            str(result),
            "--format=json",
            f"--output={decoded}",
        ],
        [executable, "bqrs", "info", str(result), "--format=json"],
    ]
    _, invocations = _codeql_steps_runner(
        [{"argv": command, "accepted_exit_codes": [0]} for command in argv],
        source,
        remaining,
        directory,
    )
    with local_file(directory, decoded.name).open("rb") as stream:
        raw = stream.read(NATIVE_COVERAGE_LIMIT + 1)
    rows = _codeql_parse_rows(raw)
    with local_file(directory / "step-2", "stdout.log").open("rb") as stream:
        info = stream.read(65_537)
    if _codeql_result_sets(info) != [
        {"name": "#select", "rows": len(rows), "columns": 3}
    ]:
        raise RuntimeAuditError("E_CODEQL_SOURCE", "source result metadata differs")
    with local_file(directory, result.name).open("rb") as stream:
        binary = stream.read(67_108_865)
    if not binary or len(binary) > 67_108_864:
        raise RuntimeAuditError("E_CODEQL_SOURCE", "source result budget exceeded")
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    archived, archive_sha = _codeql_archived_sources(source, scratch, required)
    with local_file(scratch / "codeql-db", "src.zip").open("rb") as stream:
        archive = stream.read(67_108_865)
    if sha256_bytes(archive) != archive_sha:
        raise RuntimeAuditError("E_CODEQL_SOURCE", "source archive changed")
    return {
        "schema": "factory.codeql-source-execution.v1",
        "rows": rows,
        "archived_sources": archived,
        "archive_sha256": archive_sha,
        "query_sha256": sha256_bytes(query),
        "package_sha256": sha256_bytes(package),
        "decoded_sha256": sha256_bytes(raw),
        "result_sha256": sha256_bytes(binary),
        "native_invocations": invocations,
        "archive_prefix": source.resolve().as_posix().lstrip("/") + "/",
        "native_artifacts": {
            "query": _codeql_native_blob(query),
            "package": _codeql_native_blob(package),
            "result": _codeql_native_blob(binary),
            "decoded": _codeql_native_blob(raw),
            "archive": _codeql_native_blob(archive),
            "info": _codeql_native_blob(info),
        },
    }


def _codeql_source_accounting(measurement, inventory, lane):
    try:
        rows, archived = measurement["rows"], measurement["archived_sources"]
        if not isinstance(rows, dict) or not isinstance(archived, dict):
            raise ValueError("source evidence maps required")
        checks = {}
        for item in inventory["files"]:
            if item["language"] in lane["languages"]:
                path = relative_path(item["path"])
                if path in checks:
                    raise ValueError("duplicate source inventory")
                seal = require_digest(item["sha256"], "source hash")
                checks[path] = {
                    "state": _codeql_source_state(
                        rows.get(path), archived.get(path), seal
                    ),
                    "sha256": seal,
                }
        measured = sorted(
            path for path, item in checks.items() if item["state"] == "EXTRACTED"
        )
        missing = sorted(
            path for path, item in checks.items() if item["state"] == "NOT_EXTRACTED"
        )
        degraded = sorted(set(checks) - set(measured) - set(missing))
        unexpected = sorted(set(rows) - {item["path"] for item in inventory["files"]})
        return {
            "state": "COMPLETE"
            if checks and len(measured) == len(checks) and not unexpected
            else "INCOMPLETE",
            "checks": checks,
            "required_paths": sorted(checks),
            "measured_paths": measured,
            "missing_paths": missing,
            "degraded_paths": degraded,
            "unexpected_paths": unexpected,
            "claim_boundary": "Syntax model and parser diagnostics for candidate-bound archived source bytes; not runtime behavior or per-query source reachability.",
        }
    except (RuntimeAuditError, ValueError, TypeError, KeyError) as error:
        raise RuntimeAuditError(
            "E_CODEQL_SOURCE", "invalid source accounting evidence"
        ) from error


def _codeql_source_state(row, archived, seal):
    if row is None:
        return "NOT_EXTRACTED"
    nodes = require_int(
        row["syntax_nodes"], "syntax nodes", minimum=0, maximum=2**31 - 1
    )
    errors = require_int(
        row["parse_errors"], "parse errors", minimum=0, maximum=2**31 - 1
    )
    if errors:
        return "PARSE_ERROR"
    if not nodes:
        return "NO_SYNTAX_MODEL"
    if archived != seal:
        return "SOURCE_MISMATCH"
    return "EXTRACTED"


def _codeql_archived_sources(source, scratch, required):
    import io
    import zipfile

    archive = local_file(scratch / "codeql-db", "src.zip")
    with archive.open("rb") as stream:
        raw = stream.read(67_108_865)
    if len(raw) > 67_108_864:
        raise RuntimeAuditError("E_CODEQL_SOURCE", "source archive budget exceeded")
    prefix = source.resolve().as_posix().lstrip("/") + "/"
    measured = {}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zipped:
            names = zipped.namelist()
            if len(names) > 100_000:
                raise RuntimeAuditError(
                    "E_CODEQL_SOURCE", "source archive entry budget exceeded"
                )
            for path, seal in required.items():
                name = prefix + relative_path(path)
                if names.count(name) != 1:
                    continue
                candidate = bound_bytes(source, {"path": path, "sha256": seal})
                with zipped.open(name) as member:
                    captured = member.read(len(candidate) + 1)
                measured[path] = sha256_bytes(captured)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as error:
        raise RuntimeAuditError(
            "E_CODEQL_SOURCE", "invalid native source archive"
        ) from error
    return measured, sha256_bytes(raw)


def _codeql_query_execution(profile, inventory, source, scratch, deadline):
    verify_codeql_query_selection(inventory)
    records, total_bytes = [], 0
    database = scratch / "codeql-db"
    for rule_id, query_path in sorted(inventory["query_ids"].items()):
        result_path = _codeql_result_path(query_path)
        artifact = local_file(database, result_path)
        with artifact.open("rb") as stream:
            raw = stream.read(67_108_865)
        total_bytes += len(raw)
        if not raw or len(raw) > 67_108_864 or total_bytes > 536_870_912:
            raise RuntimeAuditError(
                "E_CODEQL_EXECUTION", "result artifact budget exceeded"
            )
        records.append(
            _codeql_query_result_record(
                profile,
                source,
                scratch,
                deadline,
                rule_id,
                query_path,
                inventory["queries"][query_path],
                result_path,
                artifact,
                raw,
            )
        )
    return {
        "schema": "factory.codeql-query-execution.v1",
        "ruleset_sha256": profile["ruleset_sha256"],
        "query_inventory_sha256": inventory["query_inventory_sha256"],
        "suite_sha256": inventory["suite_sha256"],
        "rules": records,
        "claim_boundary": "Native BQRS artifacts from the fresh database, including zero-row results; not per-source query coverage or detection accuracy.",
    }


def _codeql_query_result_record(
    profile,
    source,
    scratch,
    deadline,
    rule_id,
    query_path,
    query_sha,
    result_path,
    artifact,
    raw,
):
    from .runtime_audit_process import run_bounded_command
    from .runtime_audit_common import _validate_runner_facts

    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "query evidence deadline exhausted"
        )
    directory = scratch / ("query-evidence-" + sha256_bytes(rule_id.encode())[:16])
    directory.mkdir()
    out = directory / "stdout.json"
    argv = [profile["version_argv"][0], "bqrs", "info", str(artifact), "--format=json"]
    facts = run_bounded_command(argv, source, remaining, directory, stdout_path=out)
    _validate_runner_facts(facts, remaining)
    if _adapter_command_failed(facts, [0], deadline):
        raise RuntimeAuditError("E_CODEQL_EXECUTION", "native result inspection failed")
    with local_file(directory, out.name).open("rb") as stream:
        info = stream.read(65_537)
    if (
        len(info) != facts["stdout_bytes"]
        or sha256_bytes(info) != facts["stdout_sha256"]
    ):
        raise RuntimeAuditError("E_CODEQL_EXECUTION", "result info bytes differ")
    with local_file(artifact.parent, artifact.name).open("rb") as stream:
        current = stream.read(len(raw) + 1)
    if current != raw:
        raise RuntimeAuditError("E_CODEQL_EXECUTION", "result artifact changed")
    return {
        "rule_id": rule_id,
        "query_path": query_path,
        "query_sha256": query_sha,
        "result_path": result_path,
        "result_sha256": sha256_bytes(raw),
        "result_bytes": len(raw),
        "result_sets": _codeql_result_sets(info),
        "native_artifacts": {
            "result": _codeql_native_blob(raw),
            "info": _codeql_native_blob(info),
        },
        "invocation": {"argv": argv, "argv_sha256": digest(argv), "execution": facts},
    }


def _codeql_challenges(profile, contract, source, lane, execution, started):
    obligations = [
        item
        for item in contract["obligations"]
        if item["engine"] == "codeql" and item["family"] == lane["family"]
    ]
    deadline = started + lane["timeout_seconds"]
    observations, gaps = [], []
    with tempfile.TemporaryDirectory(prefix="factory-codeql-challenges-") as temporary:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _codeql_challenge_case(
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    obligation,
                    challenge,
                    Path(temporary) / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                )
    return _challenge_bundle(observations, gaps), [item["id"] for item in obligations]


def _codeql_challenge_case(
    profile,
    contract,
    source,
    lane,
    execution,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    try:
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            raise RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "CodeQL challenge deadline exhausted"
            )
        observations.append(
            _run_codeql_challenge(
                profile,
                contract,
                source,
                lane,
                execution,
                obligation,
                challenge,
                case,
                remaining,
            )
        )
    except (OSError, RuntimeAuditError, ValueError, TypeError, KeyError) as error:
        gaps.append(
            _challenge_gap_record(obligation, challenge, _challenge_error_code(error))
        )


def _codeql_challenge_inputs(
    profile, source, lane, execution, obligation, challenge, case
):
    if challenge.get("fixture_manifest") is None:
        raise RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "signed multi-file manifest required"
        )
    baseline = execution["codeql_query_inventory"]
    verify_codeql_query_selection(baseline)
    if lane.get("rule_ids") != sorted(baseline["query_ids"]):
        raise RuntimeAuditError("E_CODEQL_CHALLENGE", "complete query ID lane required")
    suite = local_file(
        Path(profile["commands"][1]["argv"][4]).parent,
        Path(profile["commands"][1]["argv"][4]).name,
    )
    if sha256_bytes(_codeql_suite_bytes(suite)) != baseline["suite_sha256"]:
        raise RuntimeAuditError("E_CODEQL_CHALLENGE", "baseline suite changed")
    manifest = dict(sorted(challenge["fixture_manifest"].items()))
    _semgrep_fixture_binding(manifest, obligation, source, challenge["fixture_path"])
    case.mkdir()
    root = case / "source"
    for path, seal in manifest.items():
        target = root.joinpath(*relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bound_bytes(source, {"path": path, "sha256": seal}))
    return suite, baseline, manifest, root


def _codeql_mutation_suite(case, suite, rule_id):
    require_str(rule_id, "CodeQL target ID", maximum=256)
    root = Path("/opt/codeql/codeql/qlpacks")
    relative = suite.relative_to(root).as_posix()
    relative_path(relative)
    parts = relative.split("/")
    if len(parts) != 5 or parts[0] != "codeql" or parts[3] != "codeql-suites":
        raise RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "pinned CodeQL suite location required"
        )
    raw = (
        f"- import: {parts[3]}/{parts[4]}\n  from: {parts[0]}/{parts[1]}\n  version: {parts[2]}\n- exclude:\n    id: {json.dumps(rule_id)}\n"
    ).encode()
    path = case / "target-disabled.qls"
    path.write_bytes(raw)
    return path


def _codeql_challenge_selection(
    profile, root, case, suite, baseline, challenge, rule_id, deadline
):
    selected_suite = (
        _codeql_mutation_suite(case, suite, rule_id)
        if challenge["kind"] == "mutation"
        else suite
    )
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "query selection deadline exhausted"
        )
    inventory = resolve_codeql_query_inventory(
        profile["version_argv"][0], selected_suite, root, case, remaining
    )
    verify_codeql_query_selection(
        inventory,
        baseline=baseline,
        disabled_rule_id=rule_id if challenge["kind"] == "mutation" else None,
    )
    return selected_suite, inventory


def _codeql_challenge_steps(profile, bindings, suite):
    commands = _native_argv(profile["commands"], bindings)
    if (
        len(commands) != 3
        or commands[0]["argv"][1:3] != ["database", "create"]
        or commands[1]["argv"][1:3] != ["database", "analyze"]
    ):
        raise RuntimeAuditError(
            "E_CODEQL_CHALLENGE", "pinned three-step CodeQL profile required"
        )
    commands[1]["argv"][4] = str(suite)
    return commands


def _codeql_steps_runner(commands, source, budget, scratch, *, expected_steps=3):
    from .runtime_audit_process import run_bounded_command
    from .runtime_audit_common import _validate_runner_facts

    started, invocations = time.monotonic(), []
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    for index, command in enumerate(commands):
        remaining = int(budget - (time.monotonic() - started))
        if remaining < 1:
            raise RuntimeAuditError(
                "E_ADAPTER_TIMEOUT", "CodeQL steps exhausted deadline"
            )
        directory = scratch / f"step-{index}"
        directory.mkdir()
        out, err = directory / "stdout.log", directory / "stderr.log"
        facts = run_bounded_command(
            command["argv"],
            source,
            remaining,
            directory,
            stdout_path=out,
            stderr_path=err,
        )
        _validate_runner_facts(facts, remaining)
        if _adapter_command_failed(
            facts, command["accepted_exit_codes"], started + budget
        ):
            raise RuntimeAuditError(
                "E_CODEQL_CHALLENGE", "CodeQL native step failed or cleanup uncertain"
            )
        _codeql_step_streams(facts, out, err, streams)
        invocations.append(
            {
                "argv": command["argv"],
                "argv_sha256": digest(command["argv"]),
                "execution": facts,
            }
        )
    return (
        _codeql_steps_facts(invocations, streams, started, budget, expected_steps),
        invocations,
    )


def _codeql_step_streams(facts, out, err, streams):
    for role, path in (("stdout", out), ("stderr", err)):
        with local_file(path.parent, path.name).open("rb") as stream:
            raw = stream.read(1_048_577)
        if (
            len(raw) > 1_048_576
            or sha256_bytes(raw) != facts[role + "_sha256"]
            or len(raw) != facts[role + "_bytes"]
        ):
            raise RuntimeAuditError("E_CODEQL_CHALLENGE", "native stream bytes differ")
        streams[role].extend(raw)


def _codeql_steps_facts(invocations, streams, started, budget, expected_steps=3):
    if expected_steps not in (2, 3) or len(invocations) != expected_steps:
        raise RuntimeAuditError("E_CODEQL_CHALLENGE", "all native steps required")
    return dict(
        exit_code=invocations[-1]["execution"]["exit_code"],
        timed_out=False,
        timeout_seconds=budget,
        duration_ms=int((time.monotonic() - started) * 1000),
        launch_error=False,
        output_limit_exceeded=False,
        cleanup_confirmed=True,
        stdout_sha256=sha256_bytes(bytes(streams["stdout"])),
        stdout_bytes=len(streams["stdout"]),
        stderr_sha256=sha256_bytes(bytes(streams["stderr"])),
        stderr_bytes=len(streams["stderr"]),
    )


def _run_codeql_challenge(
    profile, contract, source, lane, execution, obligation, challenge, case, timeout
):
    deadline = time.monotonic() + timeout
    suite, baseline, manifest, root = _codeql_challenge_inputs(
        profile, source, lane, execution, obligation, challenge, case
    )
    rule_id = obligation["detector_rule_id"]
    selected, inventory = _codeql_challenge_selection(
        profile, root, case, suite, baseline, challenge, rule_id, deadline
    )
    return _execute_codeql_challenge(
        profile,
        contract,
        lane,
        execution,
        obligation,
        challenge,
        case,
        root,
        manifest,
        suite,
        selected,
        baseline,
        inventory,
        deadline,
    )


def _execute_codeql_challenge(
    profile,
    contract,
    lane,
    execution,
    obligation,
    challenge,
    case,
    root,
    manifest,
    suite,
    selected,
    baseline,
    inventory,
    deadline,
):
    scratch = case / "run"
    report, ledger, artifact = (
        scratch / "report.sarif",
        scratch / "unused-ledger.json",
        scratch / "query-inventory.json",
    )
    bindings = _semgrep_challenge_bindings(
        root, scratch, report, ledger, selected, digest(manifest)
    )
    commands = _codeql_challenge_steps(profile, bindings, selected)
    configs = {
        _codeql_suite_bytes(suite): baseline,
        _codeql_suite_bytes(selected): inventory,
    }

    def runner(argv, cwd, budget, run_scratch):
        if argv != commands[0]["argv"]:
            raise RuntimeAuditError(
                "E_CODEQL_CHALLENGE", "create argv differs from profile"
            )
        facts, invocations = _codeql_steps_runner(commands, cwd, budget, run_scratch)
        inventory["native_invocations"] = invocations
        artifact.write_bytes(canonical_bytes(inventory))
        return facts

    def parser(raw):
        return _codeql_challenge_report(raw, profile, root, manifest)

    def rule_ids(raw):
        return sorted(configs[raw]["query_ids"])

    def mutation_valid(original, effective, rule_id):
        verify_codeql_query_selection(
            configs[effective], baseline=configs[original], disabled_rule_id=rule_id
        )
        return True

    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "native challenge deadline exhausted"
        )
    observation = _native_challenge_executor()(
        challenge,
        obligation_id=obligation["id"],
        engine="codeql",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=profile["commands"][0]["argv"],
        bindings=bindings,
        source_root=root,
        baseline_config_path=suite,
        effective_config_path=selected,
        report_path=report,
        ledger_path=ledger,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=remaining,
        expected_ruleset_sha256=baseline["suite_sha256"],
        execution_bindings={
            "candidate_sha256": contract["inventory"]["candidate_sha256"],
            "challenge_source_sha256": digest(manifest),
            "profile_sha256": digest(profile),
            "image_sha256": sha256_bytes(lane["image"].encode()),
            "tool_version": profile["tool_version"],
            "version_probe_sha256": digest(execution["version_probe"]),
            "version_probe_facts": execution["version_probe"],
        },
        runner=runner,
        report_parser=parser,
        config_rule_ids=rule_ids,
        verify_mutation=mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"sarif_report": report, "query_inventory": artifact},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["codeql_query_inventory"] = inventory
    return observation


def _codeql_challenge_report(raw, profile, root, manifest):
    report = _semgrep_challenge_report(raw, profile, root, manifest)
    report.get("properties", {}).pop("factory_native_raw_sha256", None)
    for run in report["runs"]:
        for invocation in run.get("invocations", []):
            notifications = invocation.get("toolExecutionNotifications", [])
            invocation["toolExecutionNotifications"] = sorted(
                [
                    item
                    for item in notifications
                    if not _codeql_telemetry_notification(item)
                ],
                key=canonical_bytes,
            )
    return report


def _codeql_telemetry_notification(item):
    return item.get("level") == "none" and item.get("descriptor", {}).get("id") in {
        "cli/file-coverage-baseline",
        "cli/platform",
        "cli/build-mode",
    }


def _native_source_accounting(execution, report, inventory, lane):
    if lane.get("engine") == "osv":
        from .deep_audit_sarif import _osv_source_accounting

        return _osv_source_accounting(
            report, _trivy_source_map(inventory, lane), lane.get("mode")
        )
    if execution.get("codeql_source_execution") is not None:
        return _codeql_source_accounting(
            execution["codeql_source_execution"], inventory, lane
        )
    if execution.get("semgrep_rule_execution") is not None:
        return _semgrep_source_accounting(execution, inventory, lane)
    if lane.get("engine") == "trivy":
        try:
            return verify_trivy_rule_execution(
                execution["trivy_rule_execution"],
                lane,
                _trivy_source_map(inventory, lane),
                report,
            )
        except (KeyError, RuntimeAuditError, TypeError, ValueError):
            return {"state": "INCOMPLETE", "checks": {}, "findings": 0}
    return _native_runtime_accounting(report, inventory, lane)


def _semgrep_source_accounting(execution, inventory, lane):
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    checked = verify_semgrep_rule_execution(
        execution["semgrep_rule_execution"], lane, sources, execution["raw_report"]
    )
    measured = set().union(
        *(set(rule["executed_sources"]) for rule in checked["rules"])
    )
    required = {
        item["path"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    missing = sorted(required - measured)
    if missing:
        raise RuntimeAuditError(
            "E_SEMGREP_EXECUTION", "native source accounting incomplete"
        )
    return {
        "state": "COMPLETE",
        "required_paths": sorted(required),
        "measured_paths": sorted(measured),
        "missing_paths": missing,
        "rule_execution_sha256": digest(checked),
    }


def _runtime_coverage_errors(report, inventory, lane, challenges, obligations):
    errors = []
    source_state = _native_runtime_accounting(report, inventory, lane)["state"]
    if source_state != "COMPLETE":
        errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
    if not _gitleaks_challenges_complete(challenges, obligations):
        errors.append("NATIVE_CHALLENGES_REQUIRED")
    return errors


def _trivy_coverage_errors(execution, report, inventory, lane, challenges, obligations):
    errors = []
    evidence = execution.get("trivy_rule_execution")
    if evidence is None or not lane.get("native_policy"):
        errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
    else:
        try:
            verify_trivy_rule_execution(
                evidence, lane, _trivy_source_map(inventory, lane), report
            )
        except (RuntimeAuditError, ValueError, TypeError, KeyError):
            errors.append("NATIVE_SOURCE_ACCOUNTING_INVALID")
    if not _gitleaks_challenges_complete(challenges, obligations):
        errors.append("NATIVE_CHALLENGES_REQUIRED")
    return errors


def _trivy_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    obligations = _trivy_obligations(contract, lane)
    observations, gaps = [], []
    if not lane.get("native_policy"):
        gaps = [
            _challenge_gap_record(item, control, "E_TRIVY_POLICY")
            for item in obligations
            for control in item["challenges"]
        ]
        return _challenge_bundle(observations, gaps), [
            item["id"] for item in obligations
        ]
    if len(obligations) > 64:
        gaps = [
            _challenge_gap_record(item, control, "E_TRIVY_CHALLENGE_BUDGET")
            for item in obligations
            for control in item["challenges"]
        ]
        return _challenge_bundle(observations, gaps), [
            item["id"] for item in obligations
        ]
    config = Path("/opt/factory/rules/trivy.yaml").read_bytes()
    baseline_path = Path("/opt/factory/rules/empty-trivyignore")
    baseline = baseline_path.read_bytes()
    _trivy_policy_inputs(config, baseline, lane)
    command = _trivy_challenge_command(profile)
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    deadline = started + lane["timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="factory-trivy-challenges-") as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _trivy_challenge_control(
                    run_bounded_command,
                    profile,
                    contract,
                    source,
                    lane,
                    execution,
                    command,
                    config,
                    baseline_path,
                    baseline,
                    source_bindings,
                    obligation,
                    challenge,
                    Path(root) / f"control-{index}-{challenge['kind']}",
                    deadline,
                    observations,
                    gaps,
                )
    return _challenge_bundle(observations, gaps), [item["id"] for item in obligations]


def _challenge_bundle(observations, gaps):
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }


def _trivy_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "trivy" and item["family"] == lane["family"]
    ]


def _trivy_challenge_command(profile):
    if profile.get("engine") != "trivy" or len(profile.get("commands", [])) != 1:
        raise RuntimeAuditError("E_TRIVY_PROFILE", "one pinned Trivy command required")
    argv = list(profile["commands"][0].get("argv", []))
    try:
        if argv[argv.index("--format") + 1] != "sarif":
            raise ValueError
        argv[argv.index("--output") + 1] = "{report}"
        argv[argv.index("--ignorefile") + 1] = "{config}"
        if argv[-1] != "{source}":
            raise ValueError
    except (ValueError, IndexError) as exc:
        raise RuntimeAuditError(
            "E_TRIVY_PROFILE", "pinned command template differs"
        ) from exc
    return {
        "argv": argv,
        "accepted_exit_codes": profile["commands"][0]["accepted_exit_codes"],
    }


def _trivy_challenge_control(
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    config,
    baseline_path,
    baseline,
    source_bindings,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    remaining = int(deadline - time.monotonic())
    fixture_path = challenge.get("fixture_path")
    fixture_map = challenge.get(
        "fixture_manifest", {fixture_path: challenge.get("fixture_sha256")}
    )
    if remaining < 1:
        gaps.append(_challenge_gap_record(obligation, challenge, "E_ADAPTER_TIMEOUT"))
        return
    if not _gitleaks_challenge_allowed(
        challenge, obligation, source_bindings, command, lane
    ):
        gaps.append(_challenge_gap_record(obligation, challenge, "E_CHALLENGE_BINDING"))
        return
    if (
        not isinstance(fixture_map, dict)
        or not set(obligation.get("paths", [])) <= set(source_bindings)
        or not set(fixture_map) <= set(obligation["paths"])
    ):
        gaps.append(_challenge_gap_record(obligation, challenge, "E_CHALLENGE_BINDING"))
        return
    try:
        observations.append(
            _run_trivy_challenge(
                _native_challenge_executor(),
                runner,
                profile,
                contract,
                source,
                lane,
                execution,
                command,
                config,
                baseline_path,
                baseline,
                obligation,
                challenge,
                fixture_map,
                case,
                remaining,
            )
        )
    except (OSError, RuntimeAuditError, ValueError, TypeError, KeyError) as exc:
        gaps.append(
            _challenge_gap_record(obligation, challenge, _challenge_error_code(exc))
        )


def _run_trivy_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    config,
    baseline_path,
    baseline,
    obligation,
    challenge,
    fixture_map,
    case,
    timeout,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    case.mkdir()
    challenge_root = case / "source"
    fixture_map = dict(sorted(fixture_map.items()))
    for path, source_sha in fixture_map.items():
        target = challenge_root.joinpath(*relative_path(path).split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bound_bytes(source, {"path": path, "sha256": source_sha}))
    challenge_sha = digest(fixture_map)
    effective = baseline_path
    if challenge["kind"] == "mutation":
        effective = _trivy_mutation_path(case, baseline, lane, obligation)
    scratch = case / "run"
    report_path, policy_path = scratch / "report.sarif", scratch / "policy.json"
    argv = dict(
        source=str(challenge_root),
        output=str(scratch),
        report=str(report_path),
        scratch=str(scratch),
        candidate_sha256=challenge_sha,
        factory_ledger=str(scratch / "unused-ledger.json"),
        config=str(effective),
    )
    paired = {}

    def challenge_runner(rendered, cwd, budget, run_scratch):
        return _trivy_paired_runner(
            runner, rendered, cwd, budget, run_scratch, policy_path, paired
        )

    def report_parser(raw):
        paired["sarif_raw"] = raw
        matrix = _trivy_native_checks(strict_json(paired["json_raw"]), fixture_map)
        return _trivy_challenge_report(
            raw, profile, challenge_root, fixture_map, matrix
        )

    image = lane["image"]
    bindings = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_sha,
        "profile_sha256": digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    observation = execute(
        challenge,
        obligation_id=obligation["id"],
        engine="trivy",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=argv,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=effective,
        report_path=report_path,
        ledger_path=scratch / "unused-ledger.json",
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["native_policy"]["baseline_ignore_sha256"],
        execution_bindings=bindings,
        runner=challenge_runner,
        report_parser=report_parser,
        config_rule_ids=lambda raw: _trivy_effective_ids(raw, lane),
        verify_mutation=_trivy_mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"sarif_report": report_path, "policy_inventory": policy_path},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )
    observation["trivy_rule_execution"] = _trivy_challenge_evidence(
        config, effective.read_bytes(), fixture_map, paired, observation
    )
    checked = verify_trivy_rule_execution(
        observation["trivy_rule_execution"],
        lane,
        fixture_map,
        observation["report"]["native_report"],
        disabled_rule_id=obligation["detector_rule_id"]
        if challenge["kind"] == "mutation"
        else None,
    )
    if checked["state"] != "VERIFIED":
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "paired native evidence did not verify"
        )
    return observation


def _trivy_paired_runner(runner, argv, cwd, budget, scratch, policy_path, paired):
    started = time.monotonic()
    deadline = started + budget
    sarif_facts = runner(argv, cwd, budget, scratch)
    json_facts = None
    if not _adapter_command_failed(sarif_facts, [0], deadline):
        remaining = int(deadline - time.monotonic())
        if remaining > 0:
            json_scratch = scratch / "json-run"
            json_scratch.mkdir()
            json_argv = _trivy_json_argv(argv, policy_path)
            json_facts = runner(json_argv, cwd, remaining, json_scratch)
            paired.update(json_argv=json_argv, json_facts=json_facts)
            if not _adapter_command_failed(json_facts, [0], deadline):
                paired["json_raw"] = local_file(scratch, "policy.json").read_bytes()
    paired.update(sarif_argv=argv, sarif_facts=sarif_facts)
    return _trivy_pair_facts(sarif_facts, json_facts, budget)


def _trivy_pair_facts(sarif, native, budget):
    facts = dict(sarif)
    other = native or {}
    facts.update(
        timeout_seconds=budget,
        duration_ms=min(
            3_600_000, sarif.get("duration_ms", 0) + other.get("duration_ms", 0)
        ),
        exit_code=(
            sarif.get("exit_code")
            if sarif.get("exit_code") != 0 or native is None
            else other.get("exit_code")
        ),
        timed_out=sarif.get("timed_out", False) or other.get("timed_out", False),
        launch_error=sarif.get("launch_error", False)
        or other.get("launch_error", False),
        output_limit_exceeded=sarif.get("output_limit_exceeded", False)
        or other.get("output_limit_exceeded", False),
        cleanup_confirmed=sarif.get("cleanup_confirmed", False)
        and (native is None or other.get("cleanup_confirmed", False)),
        stdout_sha256=digest([sarif.get("stdout_sha256"), other.get("stdout_sha256")]),
        stderr_sha256=digest([sarif.get("stderr_sha256"), other.get("stderr_sha256")]),
        stdout_bytes=sarif.get("stdout_bytes", 0) + other.get("stdout_bytes", 0),
        stderr_bytes=sarif.get("stderr_bytes", 0) + other.get("stderr_bytes", 0),
    )
    return facts


def _trivy_mutation_path(case, baseline, lane, obligation):
    rule_id = obligation["detector_rule_id"]
    effective = _trivy_mutation(baseline, rule_id)
    expected = lane.get("mutation_config_sha256", {}).get(rule_id)
    if sha256_bytes(effective) != expected:
        raise RuntimeAuditError(
            "E_TRIVY_MUTATION_BINDING", "signed ignorefile digest differs"
        )
    path = case / "mutation-trivyignore"
    path.write_bytes(effective)
    return path


def _trivy_effective_ids(ignore, lane):
    excluded = set(_trivy_ignore_ids(ignore))
    ids = lane.get("rule_ids")
    if not isinstance(ids, list) or not excluded <= set(ids):
        raise RuntimeAuditError("E_TRIVY_POLICY", "ignore IDs exceed signed checks")
    return [rule for rule in ids if rule not in excluded]


def _trivy_challenge_report(raw, profile, source_root, sources, matrix):
    report = strict_json(raw)
    if not isinstance(report, dict):
        raise RuntimeAuditError("E_CHALLENGE_REPORT", "native SARIF object required")
    report = _native_sarif_metadata(report, profile, [])
    _normalize_challenge_sarif_paths(report, source_root)
    report = _native_sarif_paths(report, sources)
    status_rows = [
        {
            "source": path,
            "checks": [
                {"id": rule, "status": status} for rule, status in sorted(rows.items())
            ],
        }
        for path, rows in sorted(matrix.items())
    ]
    for run in report["runs"]:
        properties = run.setdefault("properties", {})
        if not isinstance(properties, dict):
            raise RuntimeAuditError("E_CHALLENGE_REPORT", "SARIF properties malformed")
        properties["factory_trivy_checks"] = status_rows
    return report


def _trivy_challenge_evidence(config, ignore, sources, paired, observation):
    import base64

    sarif_raw = paired.get("sarif_raw")
    json_raw = paired.get("json_raw")
    if not isinstance(sarif_raw, bytes) or not isinstance(json_raw, bytes):
        raise RuntimeAuditError("E_TRIVY_EXECUTION", "paired native output is missing")
    artifact_rows = observation.get("execution", {}).get("native_artifacts", [])
    policy = next(
        (item for item in artifact_rows if item.get("kind") == "policy_inventory"), None
    )
    if (
        not isinstance(policy, dict)
        or policy.get("sha256") != sha256_bytes(json_raw)
        or policy.get("bytes") != len(json_raw)
    ):
        raise RuntimeAuditError(
            "E_TRIVY_EXECUTION", "native policy artifact binding differs"
        )
    return {
        "schema": "factory.trivy-rule-execution.v1",
        "config_base64": base64.b64encode(config).decode("ascii"),
        "ignore_base64": base64.b64encode(ignore).decode("ascii"),
        "sources": sources,
        "observations": [
            _trivy_observation(
                "sarif", paired["sarif_argv"], paired["sarif_facts"], sarif_raw
            ),
            _trivy_observation(
                "json", paired["json_argv"], paired["json_facts"], json_raw
            ),
        ],
    }


def _gitleaks_coverage_errors(accounting, challenges, obligations):
    errors = []
    if not _gitleaks_accounting_complete(accounting):
        errors.append("NATIVE_SOURCE_ACCOUNTING_REQUIRED")
    if not _gitleaks_challenges_complete(challenges, obligations):
        errors.append("NATIVE_CHALLENGES_REQUIRED")
    return errors


def _gitleaks_challenges_complete(challenges, obligations):
    if challenges.get("gaps"):
        return False
    expected = {
        (identity, kind)
        for identity in obligations
        for kind in ("positive", "negative", "mutation")
    }
    observed = set()
    all_verified = True
    for item in challenges.get("observations", []):
        identity = (item.get("obligation_id"), item.get("kind"))
        if identity in observed:
            all_verified = False
        observed.add(identity)
        all_verified = (
            all_verified
            and isinstance(item.get("execution"), dict)
            and item["execution"].get("status") == "VERIFIED"
            and isinstance(item.get("report"), dict)
            and item.get("observation_sha256") == digest(item["report"])
        )
    return bool(expected) and observed == expected and all_verified


def _gitleaks_accounting_complete(accounting):
    if not isinstance(accounting, dict) or not isinstance(
        accounting.get("rules"), list
    ):
        return False
    return all(
        isinstance(rule, dict)
        and isinstance(rule.get("sources"), list)
        and bool(rule["sources"])
        and all(row.get("disposition") == "executed" for row in rule["sources"])
        for rule in accounting["rules"]
    )


def _gitleaks_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_common import execute_native_challenge
    from .runtime_audit_process import run_bounded_command

    commands = profile["commands"]
    if len(commands) != 1:
        return {"schema": "factory.deep-challenges.v1", "observations": []}, []
    command = commands[0]
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    obligations = _gitleaks_obligations(contract, lane)
    ids = sorted(item["id"] for item in obligations)
    baseline_path = Path("/opt/factory/rules/gitleaks.toml")
    baseline = baseline_path.read_bytes()
    observations = []
    gaps = []
    deadline = started + lane["timeout_seconds"]
    with tempfile.TemporaryDirectory(
        prefix="factory-gitleaks-challenges-"
    ) as temporary:
        root = Path(temporary)
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                remaining = int(deadline - time.monotonic())
                if remaining < 1:
                    gaps.append(
                        _challenge_gap_record(
                            obligation, challenge, "E_ADAPTER_TIMEOUT"
                        )
                    )
                    continue
                if not _gitleaks_challenge_allowed(
                    challenge, obligation, source_bindings, command, lane
                ):
                    gaps.append(
                        _challenge_gap_record(
                            obligation, challenge, "E_CHALLENGE_BINDING"
                        )
                    )
                    continue
                try:
                    observation = _run_gitleaks_challenge(
                        execute_native_challenge,
                        run_bounded_command,
                        profile,
                        contract,
                        source,
                        lane,
                        execution,
                        command,
                        challenge,
                        obligation,
                        source_bindings,
                        baseline_path,
                        baseline,
                        root / f"control-{index}-{challenge['kind']}",
                        remaining,
                    )
                except (
                    OSError,
                    RuntimeAuditError,
                    ValueError,
                    TypeError,
                    KeyError,
                ) as exc:
                    gaps.append(
                        _challenge_gap_record(
                            obligation, challenge, _challenge_error_code(exc)
                        )
                    )
                    continue
                observations.append(observation)
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }, ids


def _runtime_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_common import execute_native_challenge
    from .runtime_audit_process import run_bounded_command

    obligations = _runtime_obligations(contract, lane)
    observations, gaps = [], []
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    command = profile["commands"][0]
    baseline_path = Path("/opt/factory/rules/runtime-control.toml")
    baseline = baseline_path.read_bytes()
    deadline = started + lane["timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="factory-runtime-challenges-") as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                try:
                    observation = _runtime_challenge(
                        execute_native_challenge,
                        run_bounded_command,
                        profile,
                        contract,
                        source,
                        lane,
                        execution,
                        command,
                        challenge,
                        obligation,
                        source_bindings,
                        baseline_path,
                        baseline,
                        Path(root) / f"control-{index}-{challenge['kind']}",
                        deadline,
                    )
                    observations.append(observation)
                except (
                    OSError,
                    RuntimeAuditError,
                    ValueError,
                    TypeError,
                    KeyError,
                ) as exc:
                    gaps.append(
                        _challenge_gap_record(
                            obligation, challenge, _challenge_error_code(exc)
                        )
                    )
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }, [item["id"] for item in obligations]


def _semgrep_challenges(profile, contract, source, lane, execution, started):
    from .runtime_audit_process import run_bounded_command

    command = _semgrep_challenge_command(profile)
    baseline_path = Path("/opt/factory/rules/semgrep-pattern-limited.yml")
    baseline = baseline_path.read_bytes()
    _semgrep_rule_inventory(baseline, lane)
    source_bindings = {
        item["path"]: item["sha256"] for item in contract["inventory"]["files"]
    }
    obligations = _semgrep_obligations(contract, lane)
    observations, gaps = [], []
    if len(obligations) > 64:
        gaps = [
            _challenge_gap_record(obligation, challenge, "E_SEMGREP_CHALLENGE_BUDGET")
            for obligation in obligations
            for challenge in obligation["challenges"]
        ]
        return {
            "schema": "factory.deep-challenges.v1",
            "observations": observations,
            "gaps": gaps,
        }, [item["id"] for item in obligations]
    deadline = started + lane["timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="factory-semgrep-challenges-") as root:
        for index, obligation in enumerate(obligations):
            for challenge in obligation["challenges"]:
                _semgrep_challenge_result(
                    execute_native_challenge=_native_challenge_executor(),
                    runner=run_bounded_command,
                    profile=profile,
                    contract=contract,
                    source=source,
                    lane=lane,
                    execution=execution,
                    command=command,
                    baseline_path=baseline_path,
                    baseline=baseline,
                    source_bindings=source_bindings,
                    obligation=obligation,
                    challenge=challenge,
                    case=Path(root) / f"control-{index}-{challenge['kind']}",
                    deadline=deadline,
                    observations=observations,
                    gaps=gaps,
                )
    return {
        "schema": "factory.deep-challenges.v1",
        "observations": observations,
        "gaps": gaps,
    }, [item["id"] for item in obligations]


def _native_challenge_executor():
    from .runtime_audit_common import execute_native_challenge

    return execute_native_challenge


def _semgrep_obligations(contract, lane):
    return [
        item
        for item in contract["obligations"]
        if item["engine"] == "semgrep" and item["family"] == lane["family"]
    ]


def _semgrep_challenge_result(
    *,
    execute_native_challenge,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    source_bindings,
    obligation,
    challenge,
    case,
    deadline,
    observations,
    gaps,
):
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        gaps.append(_challenge_gap_record(obligation, challenge, "E_ADAPTER_TIMEOUT"))
        return
    if not _gitleaks_challenge_allowed(
        challenge, obligation, source_bindings, command, lane
    ):
        gaps.append(_challenge_gap_record(obligation, challenge, "E_CHALLENGE_BINDING"))
        return
    try:
        observations.append(
            _run_semgrep_challenge(
                execute_native_challenge,
                runner,
                profile,
                contract,
                source,
                lane,
                execution,
                command,
                baseline_path,
                baseline,
                obligation,
                challenge,
                case,
                remaining,
            )
        )
    except (OSError, RuntimeAuditError, ValueError, TypeError, KeyError) as exc:
        gaps.append(
            _challenge_gap_record(obligation, challenge, _challenge_error_code(exc))
        )


def _semgrep_challenge_command(profile):
    if profile.get("engine") != "semgrep" or len(profile.get("commands", [])) != 1:
        raise RuntimeAuditError(
            "E_SEMGREP_PROFILE", "one pinned Semgrep command required"
        )
    argv = profile["commands"][0].get("argv")
    expected = [
        "/usr/bin/semgrep",
        "scan",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--disable-nosem",
        "--dataflow-traces",
        "--config",
        "/opt/factory/rules/semgrep-pattern-limited.yml",
        "--sarif-output",
        "{report}",
        "{source}",
    ]
    if argv != expected:
        raise RuntimeAuditError("E_SEMGREP_PROFILE", "pinned command differs")
    result = list(argv)
    result[8] = "{config}"
    result.insert(7, "--no-rewrite-rule-ids")
    return {
        "argv": result,
        "accepted_exit_codes": profile["commands"][0]["accepted_exit_codes"],
    }


def _run_semgrep_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    baseline_path,
    baseline,
    obligation,
    challenge,
    case,
    timeout,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    fixture_path = relative_path(challenge["fixture_path"])
    fixture_manifest = dict(
        sorted(
            challenge.get(
                "fixture_manifest", {fixture_path: challenge["fixture_sha256"]}
            ).items()
        )
    )
    _semgrep_fixture_binding(fixture_manifest, obligation, source, fixture_path)
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in fixture_manifest.items():
        target = challenge_root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bound_bytes(source, {"path": path, "sha256": source_sha}))
    challenge_sha = digest(fixture_manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = _semgrep_mutation_file(case, baseline, lane, obligation)
    scratch = case / "run"
    report_path = scratch / "report.sarif"
    inventory_path = scratch / "rule-inventory.json"
    ledger_path = scratch / "unused-ledger.json"
    bindings = _semgrep_challenge_bindings(
        challenge_root, scratch, report_path, ledger_path, config_path, challenge_sha
    )
    effective = config_path.read_bytes()
    effective_ids = _semgrep_rule_ids(effective)
    inventory_bytes = canonical_bytes(
        {"ruleset_sha256": sha256_bytes(effective), "rule_ids": effective_ids}
    )

    def challenge_runner(argv, cwd, budget, run_scratch):
        inventory_path.write_bytes(inventory_bytes)
        return runner(argv, cwd, budget, run_scratch)

    def report_parser(raw):
        return _semgrep_challenge_report(raw, profile, challenge_root, fixture_manifest)

    image = lane["image"]
    execution_bindings = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_sha,
        "profile_sha256": digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    return execute(
        challenge,
        obligation_id=obligation["id"],
        engine="semgrep",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings=execution_bindings,
        runner=challenge_runner,
        report_parser=report_parser,
        config_rule_ids=_semgrep_rule_ids,
        verify_mutation=_semgrep_mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={
            "sarif_report": report_path,
            "rule_inventory": inventory_path,
        },
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )


def _semgrep_fixture_binding(manifest, obligation, source, fixture_path):
    obligation_paths = set(obligation.get("paths", []))
    if (
        not isinstance(manifest, dict)
        or not manifest
        or fixture_path not in obligation_paths
        or fixture_path not in manifest
        or not set(manifest) <= obligation_paths
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_BINDING",
            "fixture paths must be a bound subset of obligation paths",
        )
    for path, source_sha in manifest.items():
        bound_bytes(source, {"path": relative_path(path), "sha256": source_sha})


def _semgrep_challenge_bindings(source, scratch, report, ledger, config, candidate_sha):
    return {
        "source": str(source),
        "output": str(scratch),
        "report": str(report),
        "scratch": str(scratch),
        "candidate_sha256": candidate_sha,
        "factory_ledger": str(ledger),
        "config": str(config),
    }


def _semgrep_challenge_report(raw, profile, source_root, sources):
    report = strict_json(raw)
    if not isinstance(report, dict):
        raise RuntimeAuditError("E_CHALLENGE_REPORT", "native SARIF object required")
    report = _native_sarif_metadata(report, profile, [])
    _normalize_challenge_sarif_paths(report, source_root)
    return _native_sarif_paths(report, sources)


def _semgrep_rule_ids(config):
    import yaml

    try:
        rules = yaml.safe_load(config)["rules"]
    except (yaml.YAMLError, KeyError, TypeError) as exc:
        raise RuntimeAuditError("E_SEMGREP_RULESET", "invalid Semgrep rules") from exc
    if not isinstance(rules, list) or not 1 <= len(rules) <= 64:
        raise RuntimeAuditError("E_SEMGREP_RULESET", "bounded Semgrep rules required")
    ids = [
        require_str(rule.get("id"), "rule id", maximum=256)
        for rule in rules
        if isinstance(rule, dict)
    ]
    if len(ids) != len(rules) or len(set(ids)) != len(ids):
        raise RuntimeAuditError("E_SEMGREP_RULESET", "invalid Semgrep rule IDs")
    return sorted(ids)


def _semgrep_mutation_file(case, baseline, lane, obligation):
    mutation = _semgrep_disable_rule(baseline, obligation["detector_rule_id"])
    expected = lane.get("mutation_config_sha256", {}).get(
        obligation["detector_rule_id"]
    )
    if sha256_bytes(mutation) != expected:
        raise RuntimeAuditError("E_SEMGREP_MUTATION", "signed target removal differs")
    path = case / "mutation.yml"
    path.write_bytes(mutation)
    return path


def _semgrep_disable_rule(config, rule_id):
    import yaml

    try:
        document = yaml.safe_load(config)
        rules = document["rules"]
    except (yaml.YAMLError, KeyError, TypeError) as exc:
        raise RuntimeAuditError(
            "E_SEMGREP_MUTATION", "pinned ruleset malformed"
        ) from exc
    before = _semgrep_rule_ids(config)
    if before.count(rule_id) != 1:
        raise RuntimeAuditError("E_SEMGREP_MUTATION", "target rule not unique")
    document["rules"] = [item for item in rules if item.get("id") != rule_id]
    mutated = yaml.safe_dump(document, sort_keys=True).encode("utf-8")
    expected = [item for item in before if item != rule_id]
    if _semgrep_rule_ids(mutated) != expected:
        raise RuntimeAuditError("E_SEMGREP_MUTATION", "mutation removed extra rules")
    return mutated


def _semgrep_mutation_valid(baseline, effective, rule_id):
    try:
        return _semgrep_disable_rule(baseline, rule_id) == effective
    except RuntimeAuditError:
        return False


def _runtime_obligations(contract, lane):
    required = {
        item["path"]
        for item in contract["inventory"]["files"]
        if item["language"] in lane["languages"]
    }
    candidates = [
        item
        for item in contract["obligations"]
        if item["engine"] == "runtime" and item["family"] == lane["family"]
    ]
    items = [item for item in candidates if set(item["paths"]) <= required]
    if len(items) > 64:
        _native_budget_error(
            "E_RUNTIME_CHALLENGE_BUDGET", len(items), 3, len(items) * 3, 192
        )
    return items


def _runtime_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    challenge,
    obligation,
    source_bindings,
    baseline_path,
    baseline,
    case,
    deadline,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    if not _gitleaks_challenge_allowed(
        challenge, obligation, source_bindings, command, lane
    ):
        raise RuntimeAuditError("E_CHALLENGE_BINDING", "runtime challenge is not bound")
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            "E_ADAPTER_TIMEOUT", "runtime challenge budget exhausted"
        )
    fixture_path = relative_path(challenge["fixture_path"])
    fixture_sha = challenge["fixture_sha256"]
    manifest = dict(
        sorted(challenge.get("fixture_manifest", {fixture_path: fixture_sha}).items())
    )
    case.mkdir()
    challenge_root = case / "source"
    for path, source_sha in manifest.items():
        target = challenge_root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bound_bytes(source, {"path": path, "sha256": source_sha}))
    source_sha = digest(manifest)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        config_path = _runtime_mutation_config(case, baseline, lane, obligation)
    scratch = case / "run"
    report_path, coverage_path = scratch / "runtime.xml", scratch / "coverage.json"
    bindings = {
        "source": str(challenge_root),
        "output": str(scratch),
        "report": str(report_path),
        "scratch": str(scratch),
        "candidate_sha256": source_sha,
        "factory_ledger": str(coverage_path),
        "config": str(config_path),
    }

    def parse_report(raw):
        return _runtime_challenge_report(raw, coverage_path, manifest, lane, challenge)

    image = lane["image"]
    bound = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": source_sha,
        "profile_sha256": digest(profile),
        "image_sha256": common_sha256(image.encode()),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    return execute(
        challenge,
        obligation_id=obligation["id"],
        engine="runtime",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=_runtime_encoded_argv(command["argv"]),
        bindings=bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=coverage_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=remaining,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings=bound,
        runner=runner,
        report_parser=parse_report,
        config_rule_ids=_runtime_rule_ids,
        verify_mutation=_runtime_mutation_valid,
        native_artifact_roles=lane["native_artifact_roles"],
        native_artifacts={"junit_xml": report_path, "coverage_json": coverage_path},
        rule_ids=lane["rule_ids"],
        mutation_ruleset_sha256=lane["mutation_config_sha256"],
    )


def _runtime_encoded_argv(argv):
    import base64

    result = list(argv)
    try:
        code_index = result.index("-c") + 1
        code = result[code_index].encode("utf-8")
    except (ValueError, IndexError, AttributeError) as exc:
        raise RuntimeAuditError(
            "E_RUNTIME_PROFILE", "runtime profile command malformed"
        ) from exc
    encoded = base64.b64encode(code).decode("ascii")
    result[code_index] = f"exec(__import__('base64').b64decode('{encoded}'))"
    return result


def _runtime_mutation_config(case, baseline, lane, obligation):
    rule_id = obligation["detector_rule_id"]
    changed = _runtime_disable_rule(baseline, rule_id)
    expected = lane.get("mutation_config_sha256", {}).get(rule_id)
    if sha256_bytes(changed) != expected or _runtime_rule_ids(changed) != []:
        raise RuntimeAuditError(
            "E_RUNTIME_MUTATION_BINDING", "signed mutation config differs"
        )
    path = case / "mutation.toml"
    path.write_bytes(changed)
    return path


def _runtime_challenge_report(junit, coverage_path, manifest, lane, challenge):
    if (
        len(junit) > LIMIT
        or b"<!DOCTYPE" in junit.upper()
        or b"<!ENTITY" in junit.upper()
    ):
        raise RuntimeAuditError("E_RUNTIME_REPORT", "unsafe or oversized JUnit")
    tests, findings, harness, _junit_hash = _parse_runtime_junit(junit, manifest)
    if challenge["kind"] == "positive" and not any(
        finding["path"] == challenge["fixture_path"] for finding in findings
    ):
        raise RuntimeAuditError(
            "E_CHALLENGE_SEMANTICS", "positive runtime control did not fail"
        )
    if challenge["kind"] in {"negative", "mutation"} and findings:
        raise RuntimeAuditError("E_CHALLENGE_SEMANTICS", "clean runtime control failed")
    if challenge["kind"] == "mutation" and not _runtime_has_sentinel(
        junit, challenge["fixture_path"]
    ):
        raise RuntimeAuditError(
            "E_RUNTIME_SENTINEL", "mutation control lacks a passing sentinel"
        )
    artifact = local_file(coverage_path.parent, "coverage.json")
    with artifact.open("rb") as stream:
        coverage = strict_json(stream.read(LIMIT + 1))
    if coverage.get("meta", {}).get("branch_coverage") is not True:
        raise RuntimeAuditError("E_RUNTIME_COVERAGE", "native branch coverage missing")
    native = {
        "schema": "factory.deep-runtime-observations.v1",
        "engine": "runtime",
        "tool_version": lane["tool_version"],
        "completed": True,
        "errors": [],
        "harness": harness,
        "metrics": {"tests": tests},
        "findings": findings,
        "source_coverage": _native_source_counts(coverage, manifest),
    }
    return native


def _runtime_has_sentinel(junit, target_path):
    import xml.etree.ElementTree as ET

    root = ET.fromstring(junit)
    target = relative_path(target_path)
    return any(
        relative_path(item.get("file", "").removeprefix("/src/")) != target
        and item.find("failure") is None
        and item.find("error") is None
        and item.find("skipped") is None
        for item in root.iter("testcase")
    )


def _gitleaks_obligations(contract, lane):
    required = {
        item["path"]
        for item in contract["inventory"]["files"]
        if item["language"] in lane["languages"]
    }
    obligations = [
        item
        for item in contract["obligations"]
        if item["engine"] == "gitleaks"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= required
    ]
    if len(obligations) > 64:
        _native_budget_error(
            "E_GITLEAKS_CHALLENGE_BUDGET",
            len(obligations),
            3,
            len(obligations) * 3,
            64 * 3,
        )
    return obligations


def _gitleaks_preflight(inventory, lane, contract):
    source_count = sum(
        item["language"] in lane["languages"] for item in inventory["files"]
    )
    rule_count = len(lane["rule_ids"])
    pairs = source_count * rule_count
    per_pair = (
        768
        + max(
            (_json_string_size(item["path"]) for item in inventory["files"]),
            default=0,
        )
        + max((_json_string_size(rule) for rule in lane["rule_ids"]), default=0)
    )
    estimate = pairs * per_pair + _json_size_upper_bound(inventory["files"])
    if pairs > 200_000 or estimate > NATIVE_COVERAGE_LIMIT:
        _native_budget_error(
            "E_GITLEAKS_LEDGER_SIZE",
            source_count,
            rule_count,
            estimate,
            NATIVE_COVERAGE_LIMIT,
        )
    _gitleaks_obligations(contract, lane)


def _runtime_ruleset_preflight(lane):
    config_path = Path("/opt/factory/rules/runtime-control.toml")
    _runtime_rule_inventory(config_path.read_bytes(), lane)


def _runtime_rule_ids(config):
    toml = _toml_parser()
    try:
        value = toml.loads(config.decode("utf-8"))
        selectors = value["selectors"]
        if selectors != {"RUNTIME_TEST_FAILURE": "factory_runtime_failure"}:
            raise ValueError
        rules = value.get("rules", [])
        actual = [item["id"] for item in rules]
    except (UnicodeError, KeyError, TypeError, ValueError, toml.TOMLDecodeError) as exc:
        raise RuntimeAuditError(
            "E_RUNTIME_RULESET", "runtime controls are malformed"
        ) from exc
    if actual not in ([], ["RUNTIME_TEST_FAILURE"]):
        raise RuntimeAuditError("E_RUNTIME_RULESET", "runtime rule inventory differs")
    return actual


def _runtime_rule_inventory(config, lane):
    actual = _runtime_rule_ids(config)
    if (
        sha256_bytes(config) != lane.get("ruleset_sha256")
        or lane.get("rule_ids") != ["RUNTIME_TEST_FAILURE"]
        or actual != lane["rule_ids"]
    ):
        raise RuntimeAuditError("E_RUNTIME_RULESET", "pinned runtime controls differ")
    return {"state": "VERIFIED", "rule_ids": actual, "sha256": digest(actual)}


def _runtime_mutation_valid(baseline, effective, rule_id):
    return (
        rule_id == "RUNTIME_TEST_FAILURE"
        and _runtime_disable_rule(baseline, rule_id) == effective
        and _runtime_rule_ids(effective) == []
    )


def _runtime_disable_rule(config, rule_id):
    import re

    if rule_id != "RUNTIME_TEST_FAILURE" or _runtime_rule_ids(config) != [rule_id]:
        raise RuntimeAuditError("E_RUNTIME_MUTATION", "exact runtime rule required")
    starts = [
        item.start()
        for item in re.finditer(rb"(?m)^\[\[rules\]\][\t ]*(?:\r?\n|$)", config)
    ]
    if len(starts) != 1:
        raise RuntimeAuditError("E_RUNTIME_MUTATION", "one runtime rule block required")
    return config[: starts[0]]


def _challenge_gap_record(obligation, challenge, reason):
    return {
        "obligation_id": obligation["id"],
        "kind": challenge.get("kind") if isinstance(challenge, dict) else None,
        "reason": reason,
    }


def _challenge_error_code(error):
    code = getattr(error, "code", None)
    if (
        isinstance(code, str)
        and code.startswith("E_")
        and code.replace("_", "").isalnum()
        and code == code.upper()
        and len(code) <= 58
    ):
        return code
    return "E_CHALLENGE_EXECUTION"


def _gitleaks_challenge_allowed(challenge, obligation, source_bindings, command, lane):
    accepted = command["accepted_exit_codes"]
    manifest = challenge.get("fixture_manifest")
    if manifest is not None and (
        not isinstance(manifest, dict)
        or not 1 <= len(manifest) <= 64
        or any(source_bindings.get(path) != sha for path, sha in manifest.items())
    ):
        return False
    return (
        challenge.get("fixture_path") in source_bindings
        and challenge.get("fixture_sha256")
        == source_bindings.get(challenge.get("fixture_path"))
        and obligation["detector_rule_id"] in lane["rule_ids"]
        and challenge.get("expected_exit_code") in accepted
    )


def _run_gitleaks_challenge(
    execute,
    runner,
    profile,
    contract,
    source,
    lane,
    execution,
    command,
    challenge,
    obligation,
    source_bindings,
    baseline_path,
    baseline,
    case,
    timeout,
):
    from .runtime_audit_common import sha256_bytes as common_sha256

    fixture_path = relative_path(challenge["fixture_path"])
    fixture_sha = challenge["fixture_sha256"]
    fixture_manifest = challenge.get("fixture_manifest", {fixture_path: fixture_sha})
    case.mkdir()
    challenge_root = case / "source"
    challenge_inventory = dict(sorted(fixture_manifest.items()))
    for path, source_sha in challenge_inventory.items():
        fixture = bound_bytes(source, {"path": path, "sha256": source_sha})
        target = challenge_root.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(fixture)
    challenge_source_sha = digest(challenge_inventory)
    config_path = baseline_path
    if challenge["kind"] == "mutation":
        mutation_hashes = lane.get("mutation_config_sha256")
        expected_mutation = (
            mutation_hashes.get(obligation["detector_rule_id"])
            if isinstance(mutation_hashes, dict)
            else None
        )
        mutated_config = _gitleaks_disable_rule(
            baseline, obligation["detector_rule_id"]
        )
        if (
            not isinstance(expected_mutation, str)
            or sha256_bytes(mutated_config) != expected_mutation
        ):
            raise RuntimeAuditError(
                "E_GITLEAKS_MUTATION_BINDING", "signed mutation config digest differs"
            )
        config_path = case / "mutation.toml"
        config_path.write_bytes(mutated_config)
    scratch = case / "run"
    report_path, ledger_path = scratch / "report.sarif", scratch / "rule-ledger.json"
    argv_bindings = {
        "source": str(challenge_root),
        "output": str(scratch),
        "report": str(report_path),
        "scratch": str(scratch),
        "candidate_sha256": challenge_source_sha,
        "factory_ledger": str(ledger_path),
        "config": str(config_path),
    }

    def report_parser(raw):
        return _gitleaks_challenge_report(
            raw, profile, challenge_root, challenge_inventory
        )

    image = lane["image"]
    execution_bindings = {
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "challenge_source_sha256": challenge_source_sha,
        "profile_sha256": digest(profile),
        "image_sha256": common_sha256(image.encode("utf-8")),
        "tool_version": profile["tool_version"],
        "version_probe_sha256": digest(execution["version_probe"]),
        "version_probe_facts": execution["version_probe"],
    }
    options = {}
    if "fixture_manifest" in challenge:
        options = {
            "native_artifact_roles": lane["native_artifact_roles"],
            "native_artifacts": {
                "sarif_report": report_path,
                "gitleaks_rule_ledger": ledger_path,
            },
            "rule_ids": lane["rule_ids"],
            "mutation_ruleset_sha256": lane["mutation_config_sha256"],
        }
    return execute(
        challenge,
        obligation_id=obligation["id"],
        engine="gitleaks",
        detector_rule_id=obligation["detector_rule_id"],
        detector_enabled=challenge["kind"] != "mutation",
        profile_argv=command["argv"],
        bindings=argv_bindings,
        source_root=challenge_root,
        baseline_config_path=baseline_path,
        effective_config_path=config_path,
        report_path=report_path,
        ledger_path=ledger_path,
        scratch=scratch,
        scratch_parent=case,
        timeout_seconds=timeout,
        expected_ruleset_sha256=lane["ruleset_sha256"],
        execution_bindings=execution_bindings,
        runner=runner,
        report_parser=report_parser,
        config_rule_ids=_gitleaks_rule_ids,
        verify_mutation=_gitleaks_mutation_valid,
        **options,
    )


def _gitleaks_challenge_report(raw, profile, source_root, sources):
    report = strict_json(raw)
    if not isinstance(report, dict):
        raise RuntimeAuditError("E_CHALLENGE_REPORT", "native report object required")
    report = _native_sarif_metadata(report, profile, [])
    _normalize_challenge_sarif_paths(report, source_root)
    return _native_sarif_paths(report, sources)


def _normalize_challenge_sarif_paths(report, source_root):
    root = source_root.resolve().as_posix().rstrip("/")
    for run in report.get("runs", []):
        _normalize_challenge_run(run, root)


def _normalize_challenge_run(run, root):
    _normalize_challenge_bases(run, root)
    run.pop("workingDirectory", None)
    for invocation in run.get("invocations", []):
        _normalize_challenge_invocation(invocation)
    _normalize_challenge_artifact_paths(run, root)
    _normalize_challenge_message_paths(run, root)


def _normalize_challenge_bases(run, root):
    bases = run.get("originalUriBaseIds", {})
    for base in bases.values():
        uri = base.get("uri") if isinstance(base, dict) else None
        if isinstance(uri, str) and _under_challenge_root(uri, root):
            base["uri"] = "file:///src/"


def _normalize_challenge_invocation(invocation):
    if not isinstance(invocation, dict):
        return
    for key in ("startTimeUtc", "endTimeUtc", "processId", "workingDirectory"):
        invocation.pop(key, None)


def _normalize_challenge_artifact_paths(run, root):
    stack = [run]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            artifact = item.get("artifactLocation")
            uri = artifact.get("uri") if isinstance(artifact, dict) else None
            if isinstance(uri, str):
                artifact["uri"] = _challenge_source_uri(uri, root)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _normalize_challenge_message_paths(run, root):
    stack = [run]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            message = item.get("message")
            if isinstance(message, dict) and isinstance(message.get("text"), str):
                text = message["text"]
                message["text"] = text.replace(root + "/", "/src/").replace(
                    root + "\\", "/src/"
                )
                if message["text"] == root:
                    message["text"] = "/src"
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _under_challenge_root(uri, root):
    clean = unquote(uri).removeprefix("file://")
    return clean == root or clean.startswith(root + "/")


def _challenge_source_uri(uri, root):
    clean = unquote(uri).removeprefix("file://")
    if clean == root:
        return "/src"
    if clean.startswith(root + "/"):
        return "/src/" + clean[len(root) + 1 :]
    return uri


def _zap_native_request(request):
    fields = {
        "schema",
        "run_id",
        "candidate_sha256",
        "profile_sha256",
        "rule_ids",
        "timeout_seconds",
    }
    exact_keys(request, fields)
    if set(request) != fields:
        raise RuntimeAuditError("E_ZAP_REQUEST", "native request fields differ")
    if request["schema"] != "factory.zap-native-request.v1":
        raise RuntimeAuditError("E_ZAP_REQUEST", "native request schema differs")
    from .deep_audit_sarif import _zap_ledger_bindings, _zap_ledger_plugins

    bindings = {
        key: request[key] for key in ("run_id", "candidate_sha256", "profile_sha256")
    }
    bindings["host_id"] = sha256_bytes(b"http://127.0.0.1:8765")
    _zap_ledger_bindings(bindings)
    _zap_ledger_plugins({"rule_ids": request["rule_ids"]})
    require_int(request["timeout_seconds"], "ZAP timeout", minimum=1, maximum=3600)
    return bindings


def _zap_api(component, kind, name, deadline, *, watch=None, **arguments):
    from urllib.request import ProxyHandler, build_opener
    from urllib.parse import urlencode

    if (component, kind, name) not in {
        ("core", "view", "version"),
        ("core", "view", "alerts"),
        ("core", "action", "accessUrl"),
        ("ascan", "view", "scanners"),
        ("ascan", "view", "status"),
        ("ascan", "action", "scan"),
        ("ascan", "action", "disableAllScanners"),
        ("ascan", "action", "enableScanners"),
    }:
        raise RuntimeAuditError("E_ZAP_API", "unapproved API action")
    _zap_api_arguments(component, kind, name, arguments)
    if watch is not None:
        _zap_check_daemon(watch)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeAuditError("E_ZAP_TIMEOUT", "native scan deadline exhausted")
    url = (
        "http://127.0.0.1:8090/JSON/"
        + "/".join((component, kind, name))
        + "/?"
        + urlencode(arguments)
    )
    with build_opener(ProxyHandler({})).open(
        url, timeout=min(5, remaining)
    ) as response:
        raw = response.read(NATIVE_COVERAGE_LIMIT + 1)
    if len(raw) > NATIVE_COVERAGE_LIMIT:
        raise RuntimeAuditError("E_ZAP_OUTPUT", "native API output budget exceeded")
    value = strict_json(raw)
    if not isinstance(value, dict) or "code" in value:
        raise RuntimeAuditError("E_ZAP_API", "native API request failed")
    if watch is not None:
        _zap_check_daemon(watch)
    return value


def _zap_api_arguments(component, kind, name, arguments):
    fixed = {
        ("core", "action", "accessUrl"): {
            "url": "http://127.0.0.1:8765/?input=seed",
            "followRedirects": "false",
        },
        ("ascan", "action", "scan"): {
            "url": "http://127.0.0.1:8765/?input=seed",
            "recurse": "false",
            "inScopeOnly": "false",
        },
        ("core", "view", "alerts"): {"baseurl": "http://127.0.0.1:8765"},
    }
    endpoint = (component, kind, name)
    if endpoint in fixed:
        if arguments != fixed[endpoint]:
            raise RuntimeAuditError("E_ZAP_TARGET", "native target or scope differs")
        return
    if endpoint == ("ascan", "view", "status"):
        value = arguments.get("scanId")
        if (
            set(arguments) != {"scanId"}
            or not isinstance(value, str)
            or re.fullmatch(r"[0-9]{1,20}", value) is None
        ):
            raise RuntimeAuditError("E_ZAP_SCAN", "native scan ID required")
        return
    if endpoint == ("ascan", "action", "enableScanners"):
        value = arguments.get("ids")
        if (
            set(arguments) != {"ids"}
            or not isinstance(value, str)
            or len(value) > 45_056
        ):
            raise RuntimeAuditError("E_ZAP_INVENTORY", "bounded plugin IDs required")
        from .deep_audit_sarif import _zap_ledger_plugins

        _zap_ledger_plugins({"rule_ids": value.split(",")})
        return
    if arguments:
        raise RuntimeAuditError("E_ZAP_API", "unexpected API arguments")


def _zap_daemon_argv(home):
    return [
        "/opt/factory/java/bin/java",
        "-Xmx512m",
        "-Djava.awt.headless=true",
        "-jar",
        "/zap/zap-2.17.0.jar",
        "-daemon",
        "-host",
        "127.0.0.1",
        "-port",
        "8090",
        "-dir",
        str(home),
        "-config",
        "api.disablekey=true",
        "-config",
        "autoupdate.checkOnStart=false",
        "-config",
        "autoupdate.installAddonUpdates=false",
        "-config",
        "autoupdate.downloadNewRelease=false",
    ]


def _zap_daemon_environment(bindings, home):
    return {
        "PATH": "/opt/factory/java/bin:/usr/local/bin:/usr/bin:/bin",
        "JAVA_HOME": "/opt/factory/java",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "FACTORY_ZAP_LEDGER_ENABLED": "1",
        "FACTORY_RUN_ID": bindings["run_id"],
        "FACTORY_CANDIDATE_SHA256": bindings["candidate_sha256"],
        "FACTORY_PROFILE_SHA256": bindings["profile_sha256"],
    }


def _zap_check_daemon(watch):
    if watch["overflow"].is_set():
        raise RuntimeAuditError("E_ZAP_OUTPUT", "native daemon output budget exceeded")
    if time.monotonic() >= watch["deadline"]:
        raise RuntimeAuditError("E_ZAP_TIMEOUT", "native scan deadline exhausted")
    if watch["child"].poll() is not None:
        raise RuntimeAuditError("E_ZAP_PROCESS", "native daemon exited unexpectedly")


def _zap_watch(child, deadline, overflow):
    return {"child": child, "deadline": deadline, "overflow": overflow}


def _zap_wait_ready(child, deadline, watch):
    from urllib.error import URLError

    while True:
        _zap_check_daemon(watch)
        try:
            version = _zap_api("core", "view", "version", deadline, watch=watch)
            if version != {"version": "2.17.0"}:
                raise RuntimeAuditError("E_ZAP_VERSION", "native core version differs")
            return version
        except URLError:
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def _zap_enabled_inventory(raw):
    scanners = raw.get("scanners")
    if not isinstance(scanners, list) or not 1 <= len(scanners) <= 4096:
        raise RuntimeAuditError("E_ZAP_INVENTORY", "native scanner inventory missing")
    identities, enabled = set(), []
    for row in scanners:
        if not isinstance(row, dict) or row.get("enabled") not in {"true", "false"}:
            raise RuntimeAuditError("E_ZAP_INVENTORY", "invalid scanner disposition")
        identifier = row.get("id")
        if (
            not isinstance(identifier, str)
            or re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", identifier) is None
            or identifier in identities
        ):
            raise RuntimeAuditError(
                "E_ZAP_INVENTORY", "invalid or duplicate scanner ID"
            )
        identities.add(identifier)
        if row["enabled"] == "true":
            enabled.append(identifier)
    return sorted(enabled)


def _zap_select_rules(rule_ids, deadline, watch):
    _zap_api("ascan", "action", "disableAllScanners", deadline, watch=watch)
    _zap_api(
        "ascan",
        "action",
        "enableScanners",
        deadline,
        watch=watch,
        ids=",".join(rule_ids),
    )
    raw = _zap_api("ascan", "view", "scanners", deadline, watch=watch)
    if _zap_enabled_inventory(raw) != rule_ids:
        raise RuntimeAuditError("E_ZAP_INVENTORY", "effective enabled rules differ")
    return raw


def _zap_start_scan(child, deadline, watch):
    from urllib.error import HTTPError

    target = "http://127.0.0.1:8765/?input=seed"
    access = _zap_api(
        "core",
        "action",
        "accessUrl",
        deadline,
        watch=watch,
        url=target,
        followRedirects="false",
    )
    while True:
        _zap_check_daemon(watch)
        try:
            scan = _zap_api(
                "ascan",
                "action",
                "scan",
                deadline,
                watch=watch,
                url=target,
                recurse="false",
                inScopeOnly="false",
            )
            identifier = require_str(scan.get("scan"), "scan ID", maximum=20)
            if re.fullmatch(r"[0-9]+", identifier) is None:
                raise RuntimeAuditError("E_ZAP_SCAN", "invalid scan identifier")
            return identifier, access
        except HTTPError as exc:
            raw = exc.read(4097)
            if (
                exc.code != 400
                or len(raw) > 4096
                or strict_json(raw).get("code") != "url_not_found"
            ):
                raise RuntimeAuditError(
                    "E_ZAP_SCAN", "native scan start rejected"
                ) from exc
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def _zap_wait_scan(child, identifier, deadline, watch):
    while True:
        _zap_check_daemon(watch)
        status = _zap_api(
            "ascan", "view", "status", deadline, watch=watch, scanId=identifier
        )
        value = status.get("status")
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[0-9]{1,3}", value) is None
            or int(value) > 100
        ):
            raise RuntimeAuditError("E_ZAP_SCAN", "invalid native scan status")
        if value == "100":
            return status
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def _zap_measure_scan(request, bindings, child, deadline, watch):
    from .deep_audit_sarif import _verify_zap_native_rule_ledger

    version = _zap_wait_ready(child, deadline, watch)
    before = _zap_select_rules(request["rule_ids"], deadline, watch)
    _zap_check_daemon(watch)
    identifier, access = _zap_start_scan(child, deadline, watch)
    status = _zap_wait_scan(child, identifier, deadline, watch)
    after = _zap_api("ascan", "view", "scanners", deadline, watch=watch)
    if _zap_enabled_inventory(after) != request["rule_ids"]:
        raise RuntimeAuditError("E_ZAP_INVENTORY", "effective enabled rules drifted")
    alerts = _zap_api(
        "core", "view", "alerts", deadline, watch=watch, baseurl="http://127.0.0.1:8765"
    )
    _zap_check_daemon(watch)
    ledger = _zap_retained_ledger(Path("/out"))
    verification = _verify_zap_native_rule_ledger(
        ledger, {"engine": "zap", "rule_ids": request["rule_ids"]}, bindings
    )
    _zap_check_daemon(watch)
    return {
        "schema": "factory.zap-native-observation.v1",
        **bindings,
        "version": version,
        "effective_inventory_before": before,
        "effective_inventory_after": after,
        "scan_status": status,
        "access": access,
        "alerts": alerts,
        "native_ledger": ledger.decode("utf-8"),
        "native_verification": verification,
    }


def _zap_retained_ledger(output):
    path = local_file(output, "zap-rule-ledger.jsonl")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        raw = stream.read(4 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    if _zap_file_signature(before) != _zap_file_signature(after) or _zap_file_signature(
        after
    ) != _zap_file_signature(current):
        raise RuntimeAuditError(
            "E_ZAP_LEDGER_DRIFT", "native ledger changed during read"
        )
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeAuditError("E_ZAP_OUTPUT", "native ledger byte budget exceeded")
    return raw


def _zap_file_signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _zap_process_facts(child, started, streams, cleanup_confirmed, streams_closed):
    from .runtime_audit_process import _cleanup_is_confirmed

    confirmed = _cleanup_is_confirmed(child, cleanup_confirmed, streams_closed)
    return {
        "pid": child.pid,
        "return_code": child.returncode,
        "duration_ms": max(0, round((time.monotonic() - started) * 1000)),
        "stdout_bytes": streams.get("stdout", (sha256_bytes(b""), 0))[1],
        "stdout_sha256": streams.get("stdout", (sha256_bytes(b""), 0))[0],
        "stderr_bytes": streams.get("stderr", (sha256_bytes(b""), 0))[1],
        "stderr_sha256": streams.get("stderr", (sha256_bytes(b""), 0))[0],
        "output_limit_exceeded": False,
        "cleanup_confirmed": confirmed,
        "termination_reason": "intentional_stop",
    }


def _run_zap_native_scan(request):
    from .runtime_audit_process import _await_cleanup, _start_stream_readers
    import socket

    bindings = _zap_native_request(request)
    output = Path("/out")
    if output.is_symlink() or not output.is_dir() or os.name != "posix":
        raise RuntimeAuditError(
            "E_ZAP_BOUNDARY", "isolated Linux worker output required"
        )
    if (output / "zap-rule-ledger.jsonl").exists():
        raise RuntimeAuditError("E_ZAP_OUTPUT", "native ledger must not preexist")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 8090))
    deadline = time.monotonic() + request["timeout_seconds"]
    with tempfile.TemporaryDirectory(prefix="factory-zap-") as root:
        started = time.monotonic()
        child = subprocess.Popen(
            _zap_daemon_argv(root),
            cwd="/zap",
            env=_zap_daemon_environment(bindings, root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        overflow = threading.Event()
        streams = {}
        readers = []
        deadline = started + request["timeout_seconds"]
        watch = _zap_watch(child, deadline, overflow)
        try:
            readers = _start_stream_readers(child, overflow, streams)
            result = _zap_measure_scan(request, bindings, child, deadline, watch)
            _zap_check_daemon(watch)
        finally:
            cleanup, streams_closed = _await_cleanup(child, readers)
        process_facts = _zap_process_facts(
            child, started, streams, cleanup, streams_closed
        )
        if overflow.is_set():
            raise RuntimeAuditError(
                "E_ZAP_OUTPUT", "native daemon output budget exceeded"
            )
        if not process_facts["cleanup_confirmed"] or child.poll() is None:
            raise RuntimeAuditError(
                "E_ZAP_CLEANUP", "native process cleanup unconfirmed"
            )
        result["process_facts"] = process_facts
    result["cleanup_complete"] = True
    result["claim_boundary"] = (
        "Native active-rule observations; not source line coverage, accuracy or release approval."
    )
    return result


def adapter_main(argv: list[str] | None = None) -> int:
    """Fixed in-image endpoint; Docker isolation and host validation remain mandatory."""
    import argparse
    import sys

    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "native-fuzz":
        return native_fuzz_main(argv[1:])

    parser = argparse.ArgumentParser()
    parser.add_argument("engine")
    parser.add_argument("--mode", required=True)
    args = parser.parse_args(argv)
    try:
        with Path("/opt/factory/adapter-profile.json").open("rb") as stream:
            profile = strict_json(stream.read(LIMIT + 1))
        with Path("/factory-contract.json").open("rb") as stream:
            contract = strict_json(stream.read(LIMIT + 1))
        if (profile.get("engine"), profile.get("mode")) != (args.engine, args.mode):
            raise RuntimeAuditError("E_ADAPTER_PROFILE", "entrypoint arguments differ")
        execute = (
            execute_native_profile
            if profile.get("schema") == "factory.native-profile.v1"
            else execute_adapter_profile
        )
        bundle = execute(profile, contract, Path("/src"), Path("/out"))
        raw = _bounded_json_bytes(bundle, LIMIT, "E_WORKER_BUNDLE_SIZE")
        print(raw.decode("utf-8"))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        import sys

        print(getattr(exc, "code", "E_ADAPTER_INPUT"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(adapter_main())

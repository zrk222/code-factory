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
        remaining = deadline - time.monotonic()
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
    report = {
        "schema": "factory.deep-atheris-observations.v1",
        "engine": "atheris",
        "tool_version": contract["lane"]["tool_version"],
        "completed": True,
        "errors": [],
        "harness": {"path": harness, "sha256": sources[harness]},
        "metrics": {
            "executions": state["executions"],
            "corpus_size": len(state["inputs"]),
            "coverage_edges": edges,
        },
        "metric_definitions": {
            "executions": "observed callbacks (lower bound at last snapshot)",
            "corpus_size": "distinct executed input hashes, not retained native corpus",
            "coverage_edges": "executed Python branch arcs from coverage.py",
        },
        "findings": state["findings"],
        "source_coverage": _native_source_counts(raw, sources),
        "coverage_native_sha256": digest(raw),
    }
    output.write_bytes(canonical_bytes(report))


def native_fuzz_main(argv: list[str]) -> int:
    """Image-owned Atheris lifecycle; candidate exports only TestOneInput(bytes)."""
    import atheris
    import coverage
    import importlib.util
    import sys

    harness_path, output = Path(argv[0]), Path(argv[1])
    contract = strict_json(Path("/factory-contract.json").read_bytes())
    harness = harness_path.relative_to(Path("/src")).as_posix()
    sources = {item["path"]: item["sha256"] for item in contract["inventory"]["files"]}
    bound_bytes(Path("/src"), {"path": harness, "sha256": sources[harness]})
    cov = coverage.Coverage(branch=True, data_file=None, source=["/src"])
    cov.start()
    with atheris.instrument_imports():
        spec = importlib.util.spec_from_file_location(
            "factory_fuzz_target", harness_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    target = module.TestOneInput
    state = {"executions": 0, "inputs": set(), "findings": []}

    def callback(data):
        state["executions"] += 1
        state["inputs"].add(sha256_bytes(data))
        try:
            target(data)
        except Exception:
            state["findings"].append(
                {
                    "rule_id": "FUZZ_EXCEPTION",
                    "path": harness,
                    "line": 1,
                    "severity": "high",
                }
            )
            _fuzz_snapshot(cov, contract, harness, output, state)
            raise
        if state["executions"] == 1 or state["executions"] % 64 == 0:
            _fuzz_snapshot(cov, contract, harness, output, state)

    atheris.Setup([sys.argv[0], *argv[3:]], atheris.instrument_func(callback))
    atheris.Fuzz()
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
    challenges = {"schema": "factory.deep-challenges.v1", "observations": []}
    covered_obligations = []
    if lane["engine"] == "gitleaks":
        challenges, covered_obligations = _gitleaks_challenges(
            profile, contract, Path(source), lane, execution, started
        )
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        challenges, covered_obligations = _runtime_challenges(
            profile, contract, Path(source), lane, execution, started
        )
    coverage = _native_profile_coverage(
        execution, report, inventory, lane, profile, challenges, covered_obligations
    )
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


def _run_native_profile(profile, contract, source, output, inventory, lane, paths):
    rule_inventory = None
    config_path = None
    semgrep_rules = None
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
    timeout = require_int(
        lane.get("timeout_seconds"), "timeout", minimum=1, maximum=3600
    )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="factory-native-") as temporary:
        scratch = Path(temporary)
        probe = scratch / "probe"
        probe.mkdir()
        version = _native_version(profile, source, probe, timeout)
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
                **({"config": str(config_path)} if config_path is not None else {}),
            },
        )
        invocations = _adapter_commands(
            commands, {**lane, "timeout_seconds": int(remaining)}, source, scratch
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
    if profile["report_format"] == "runtime-junit":
        junit_path = local_file(output, paths[0])
        _junit_bytes(output, paths[0])
        with local_file(output, paths[1]).open("rb") as stream:
            raw_report = strict_json(stream.read(LIMIT + 1))
        if not junit_path.is_file():
            raise RuntimeAuditError("E_RUNTIME_REPORT", "native JUnit missing")
    else:
        with local_file(output, paths[0]).open("rb") as stream:
            raw_report = strict_json(stream.read(LIMIT + 1))
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
    }


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
    import base64
    from .runtime_audit_common import _validate_runner_facts

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
    elif lane["engine"] == "runtime" and profile["report_format"] == "runtime-junit":
        errors = _runtime_coverage_errors(
            report, inventory, lane, challenges, covered_obligations
        )
        complete = not errors
    elif execution.get("semgrep_rule_execution") is not None:
        _semgrep_source_accounting(execution, inventory, lane)
        errors = ["NATIVE_CHALLENGES_REQUIRED"]
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
            {"semgrep_rule_execution": execution["semgrep_rule_execution"]}
            if execution.get("semgrep_rule_execution") is not None
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


def _native_source_accounting(execution, report, inventory, lane):
    if execution.get("semgrep_rule_execution") is not None:
        return _semgrep_source_accounting(execution, inventory, lane)
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

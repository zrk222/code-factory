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
            if not name.startswith(".factory/deep-runs/")
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
    if name.startswith(".factory/deep-runs/"):
        raise RuntimeAuditError(
            "E_RESERVED_SOURCE", "tracked source collides with audit state"
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
        if not name.startswith(".factory/deep-runs/")
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
    argv, exits = command["argv"], command["accepted_exit_codes"]
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "bounded argv required")
    for arg in argv:
        require_str(arg, "adapter argument", maximum=2048)
    if not Path(argv[0]).is_absolute():
        raise RuntimeAuditError(
            "E_ADAPTER_PROFILE", "absolute executable path required"
        )
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
        facts = run_bounded_command(command["argv"], source, remaining, directory)
        if (
            facts["timed_out"]
            or facts["launch_error"]
            or facts["output_limit_exceeded"]
            or not facts["cleanup_confirmed"]
            or facts["exit_code"] not in command["accepted_exit_codes"]
            or time.monotonic() > deadline
        ):
            raise RuntimeAuditError(
                "E_ADAPTER_COMMAND", "native command did not complete"
            )
        invocations.append({"argv_sha256": digest(command["argv"]), "execution": facts})
    return invocations


def execute_adapter_profile(
    profile: dict, contract: dict, source: Path, output: Path
) -> dict:
    """Join actual native artifacts; never synthesize coverage or challenge success."""
    keys = {"schema", "run_id", "manifest_sha256", "inventory", "lane", "obligations"}
    if set(contract) != keys or contract["schema"] != "factory.deep-adapter-input.v1":
        raise RuntimeAuditError("E_ADAPTER_INPUT", "invalid adapter contract")
    require_str(contract["run_id"], "run_id", maximum=64)
    require_digest(contract["manifest_sha256"], "manifest_sha256")
    inventory, lane = contract["inventory"], contract["lane"]
    if not isinstance(inventory, dict) or not isinstance(lane, dict):
        raise RuntimeAuditError(
            "E_ADAPTER_INPUT", "inventory and lane objects required"
        )
    require_digest(inventory.get("candidate_sha256"), "candidate_sha256")
    commands = _adapter_profile(profile, lane)
    _adapter_sources(source, inventory)
    report_paths = {lane[key] for key in ("report", "coverage", "challenge_report")}
    if len(report_paths) != 3:
        raise RuntimeAuditError("E_ADAPTER_INPUT", "distinct artifact paths required")
    for path in report_paths:
        target = Path(output) / relative_path(path)
        if target.exists() or target.is_symlink():
            raise RuntimeAuditError("E_ADAPTER_STALE", "preexisting output rejected")
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
        "runtime": {"runtime-json", "coverage-json"},
        "atheris": {"runtime-json"},
        "jazzer": {"runtime-json"},
        "zap": {"runtime-json"},
    }
    if profile["report_format"] not in formats.get(profile["engine"], set()):
        raise RuntimeAuditError("E_ADAPTER_PROFILE", "unsupported native report")


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


def _native_junit(output: Path, sources: dict) -> tuple:
    import xml.etree.ElementTree as ET

    with local_file(output, "runtime.xml").open("rb") as stream:
        junit = stream.read(LIMIT + 1)
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
    tests, findings, harness = 0, [], None
    for case in tree.iter("testcase"):
        if case.find("skipped") is not None:
            continue
        tests += 1
        path = relative_path(case.get("file", ""))
        if path not in sources:
            raise RuntimeAuditError("E_HARNESS_BINDING", "JUnit test source is unbound")
        harness = harness or {"path": path, "sha256": sources[path]}
        if case.find("failure") is not None or case.find("error") is not None:
            findings.append(
                {
                    "rule_id": "RUNTIME_TEST_FAILURE",
                    "path": path,
                    "line": int(case.get("line", "0")) + 1,
                    "severity": "high",
                }
            )
    if not tests or harness is None:
        raise RuntimeAuditError("E_RUNTIME_REPORT", "no executed source-bound tests")
    return tests, findings, harness, sha256_bytes(junit)


def _native_coverage_report(
    raw: dict, lane: dict, inventory: dict, output: Path
) -> dict:
    if raw.get("meta", {}).get("branch_coverage") is not True:
        raise RuntimeAuditError(
            "E_RUNTIME_COVERAGE", "native branch measurement required"
        )
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    tests, findings, harness, junit_hash = _native_junit(output, sources)
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
    for name, measured in raw.get("files", {}).items():
        path = relative_path(name.removeprefix("/src/"))
        if path not in sources:
            raise RuntimeAuditError("E_RUNTIME_COVERAGE", "coverage source is unbound")
        counts = measured["summary"]
        coverage[path] = {
            "sha256": sources[path],
            "lines_total": counts["num_statements"],
            "lines_covered": counts["covered_lines"],
            "branches_total": counts["num_branches"],
            "branches_covered": counts["covered_branches"],
        }
    return coverage


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
    if profile["report_format"] == "coverage-json":
        return _native_coverage_report(
            raw, contract["lane"], contract["inventory"], output
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
    indexed = None
    if "index" in artifact:
        index = require_int(
            artifact["index"], "artifact index", minimum=0, maximum=49999
        )
        items = run.get("artifacts", [])
        if index >= len(items):
            raise RuntimeAuditError("E_SARIF_INDIRECTION", "artifact index is absent")
        indexed = items[index]["location"]
    value = artifact if "uri" in artifact else indexed
    if not isinstance(value, dict):
        raise RuntimeAuditError("E_SARIF_INDIRECTION", "native source URI missing")
    absolute_source = value.get("uri", "").startswith(("/src/", "file:///src/"))
    if "uriBaseId" in value and not absolute_source:
        base = run.get("originalUriBaseIds", {}).get(value["uriBaseId"], {})
        if base.get("uri") not in {"file:///src/", "file:///src", "/src/"}:
            raise RuntimeAuditError(
                "E_SARIF_INDIRECTION", "untrusted native source base"
            )
    path = _native_source_path(value["uri"], sources)
    if indexed is not None and "uri" in artifact:
        if _native_source_path(indexed["uri"], sources) != path:
            raise RuntimeAuditError(
                "E_SARIF_INDIRECTION", "native artifact reference differs"
            )
    return path


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
    keys = {"schema", "run_id", "manifest_sha256", "inventory", "lane", "obligations"}
    if set(contract) != keys or contract["schema"] != "factory.deep-adapter-input.v1":
        raise RuntimeAuditError("E_ADAPTER_INPUT", "invalid native contract")
    lane, inventory = contract["lane"], contract["inventory"]
    _native_profile(profile, lane)
    require_str(contract["run_id"], "run_id", maximum=64)
    require_digest(contract["manifest_sha256"], "manifest_sha256")
    require_digest(inventory.get("candidate_sha256"), "candidate_sha256")
    _adapter_sources(source, inventory)
    paths = [
        relative_path(lane[key]) for key in ("report", "coverage", "challenge_report")
    ]
    if len(set(paths)) != 3:
        raise RuntimeAuditError("E_ADAPTER_INPUT", "distinct artifact paths required")
    for path in paths:
        target = output / path
        if target.exists() or target.is_symlink():
            raise RuntimeAuditError("E_ADAPTER_STALE", "preexisting output rejected")
        target.parent.mkdir(parents=True, exist_ok=True)
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
            },
        )
        invocations = _adapter_commands(
            commands, {**lane, "timeout_seconds": int(remaining)}, source, scratch
        )
    with local_file(output, paths[0]).open("rb") as stream:
        raw_report = strict_json(stream.read(LIMIT + 1))
    report = _native_report(raw_report, profile, contract, output, invocations)
    _adapter_sources(source, inventory)
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "complete": False,
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
        "native_report_sha256": digest(raw_report),
        "native_invocations": invocations,
        "invocation_sha256": digest(invocations),
        "version_probe": version,
        "errors": ["NATIVE_SOURCE_ACCOUNTING_REQUIRED", "NATIVE_CHALLENGES_REQUIRED"],
        "obligations": [],
    }
    artifacts = {
        paths[0]: report,
        paths[1]: coverage,
        paths[2]: {"schema": "factory.deep-challenges.v1", "observations": []},
    }
    for path in paths[1:]:
        (output / path).write_bytes(canonical_bytes(artifacts[path]))
    return {
        "schema": "factory.deep-worker.v1",
        "run_id": contract["run_id"],
        "candidate_sha256": inventory["candidate_sha256"],
        "artifacts": artifacts,
    }


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
        print(canonical_bytes(bundle).decode("utf-8"))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        import sys

        print(getattr(exc, "code", "E_ADAPTER_INPUT"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(adapter_main())

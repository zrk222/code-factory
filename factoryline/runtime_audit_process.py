"""Bounded, secret-minimized subprocess supervision; NOT a security sandbox."""

from __future__ import annotations

import hashlib
import json
import re
import os
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO

from . import assembly_process
from .runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    sha256_bytes,
    validate_production_mutation_origins,
    validate_production_mutation_trial,
)

MAX_OUTPUT = 8 * 1024 * 1024
_GO_OFFLINE_BINARY = "/usr/local/go/bin/go"
# Read-only module cache volume filled by prefetch-go-modules before the offline scan.
_GO_MODULES = Path("/go-modules")


def _offline_go_roots(source: Path) -> list[Path]:
    roots = []
    for directory, children, files in os.walk(source):
        children[:] = sorted(
            name
            for name in children
            if not name.startswith(".") and name not in {"vendor", "testdata"}
        )
        path = Path(directory)
        if "go.work" in files:
            raise SystemExit("Go workspaces require a separately qualified profile")
        if "go.mod" in files and not (path / "go.mod").is_symlink():
            roots.append(path)
            if len(roots) > 64:
                raise SystemExit("Go module limit exceeded")
    if not roots:
        raise SystemExit("No offline Go module root found")
    return roots


def _offline_go_module_option(root: Path, source: Path) -> str:
    module = json.loads(
        subprocess.check_output(
            [_GO_OFFLINE_BINARY, "mod", "edit", "-json"], cwd=root, encoding="utf-8"
        )
    )
    for replacement in module.get("Replace") or ():
        target = replacement["New"]
        if not target.get("Version"):
            resolved = (root / target["Path"]).resolve()
            if not resolved.is_relative_to(source) or not resolved.is_dir():
                raise SystemExit(
                    "Local Go module replacement is missing or leaves the source"
                )
    mode = "vendor" if (root / "vendor/modules.txt").is_file() else "readonly"
    return f"-mod={mode}"


def _compile_offline_go() -> None:
    """Compile packages and tests inside the worker without running them."""
    source = Path("/src")
    remaining = 2048
    os.environ.update(
        GOTOOLCHAIN="local",
        GOPROXY="off",
        GOSUMDB="off",
        GOENV="off",
        GOTELEMETRY="off",
        CGO_ENABLED="0",
        GOWORK="off",
    )
    os.environ.pop("GOFLAGS", None)
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(scratch)
        modules = _GO_MODULES if _GO_MODULES.is_dir() else directory / "modules"
        os.environ.update(GOPATH=str(directory / "gopath"), GOMODCACHE=str(modules))
        target = str(directory / "compiled.test")
        for root in _offline_go_roots(source):
            option = _offline_go_module_option(root, source)
            packages = subprocess.check_output(
                [_GO_OFFLINE_BINARY, "list", option, "./..."],
                cwd=root,
                encoding="utf-8",
            ).splitlines()
            if not packages or len(packages) > remaining:
                raise SystemExit("No Go packages or package limit exceeded")
            remaining -= len(packages)
            for package in packages:
                if not package or package.startswith("-"):
                    raise SystemExit("Invalid Go package path")
                subprocess.run(
                    [
                        _GO_OFFLINE_BINARY,
                        "test",
                        "-c",
                        option,
                        "-buildvcs=false",
                        "-o",
                        target,
                        package,
                    ],
                    cwd=root,
                    check=True,
                )


def _prefetch_go_modules() -> None:
    """Fill the module volume through the public proxy only; no repository code runs."""
    os.environ.update(
        GOTOOLCHAIN="local",
        GOPROXY="https://proxy.golang.org",
        GOSUMDB="sum.golang.org",
        GOVCS="*:off",
        GOENV="off",
        GOTELEMETRY="off",
        GOWORK="off",
        GOMODCACHE=str(_GO_MODULES),
    )
    os.environ.pop("GOFLAGS", None)
    with tempfile.TemporaryDirectory() as scratch:
        os.environ["GOPATH"] = scratch
        for root in _offline_go_roots(Path("/src")):
            subprocess.run(
                [_GO_OFFLINE_BINARY, "mod", "download"], cwd=root, check=False
            )


def validate_production_mutation_process(facts: dict) -> bool:
    """Accept only bounded child execution with confirmed cleanup and pytest exit codes."""
    return (
        isinstance(facts, dict)
        and facts.get("timed_out") is False
        and facts.get("output_limit_exceeded") is False
        and facts.get("cleanup_confirmed") is True
        and facts.get("launch_error") is False
        and facts.get("exit_code") in {0, 1}
    )


def mutation_trial_observed(trial, prepared, root, target, manifest, outcome, visible):
    """Require supervised completion, selected case evidence, and bound module origins."""
    data = trial.get("data")
    return (
        validate_production_mutation_process(trial.get("process", {}))
        and isinstance(data, dict)
        and data.get("runtime_context_before") == data.get("runtime_context_after")
        and isinstance(data.get("runtime_context_normalized_before"), str)
        and data.get("runtime_context_normalized_before")
        == data.get("runtime_context_normalized_after")
        and validate_production_mutation_trial(
            data, prepared["selector"], prepared["line"], outcome, visible
        )
        and validate_production_mutation_origins(data, root, manifest, target)
    )


def same_mutation_case_catalogs(baseline, mutation) -> bool:
    """Require exact selected-case identity across baseline and mutant runs."""
    first = baseline.get("data", {}).get("collected")
    second = mutation.get("data", {}).get("collected")
    return isinstance(first, list) and isinstance(second, list) and first == second


def new_output_path_inside(root: Path, path: Path) -> Path:
    """Resolve a new contained output path after rejecting linked existing ancestors."""
    root = Path(root).resolve(strict=True)
    candidate = Path(os.path.abspath(path if path.is_absolute() else root / path))
    try:
        parts = candidate.relative_to(root).parts
    except ValueError as exc:
        raise RuntimeAuditError(
            "E_OUTPUT_ESCAPE", "output path escapes workspace"
        ) from exc
    current = root
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    for part in parts:
        current /= part
        if current.exists() or current.is_symlink():
            info = current.stat()
            if current.is_symlink() or getattr(info, "st_file_attributes", 0) & reparse:
                raise RuntimeAuditError(
                    "E_MUTATION_OUTPUT", "output path has a linked ancestor"
                )
    if candidate == root or candidate.exists():
        raise RuntimeAuditError(
            "E_MUTATION_OUTPUT", "output path must be new inside workspace"
        )
    return candidate


def bounded_file_sha256(path: Path, maximum: int, *, include_bytes=False):
    """Hash one regular file while reading at most its declared byte limit."""
    if type(maximum) is not int or maximum < 0:
        raise ValueError("maximum must be a nonnegative integer")
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("captured file exceeded its size limit")
    digest.update(content)
    result = digest.hexdigest()
    return (result, content) if include_bytes else result


def tree_has_no_links_or_reparse_points(
    root: Path,
    ignored: set[str] | None = None,
    *,
    max_files=20000,
    max_bytes=512 * 1024 * 1024,
    deadline=float("inf"),
) -> bool:
    """Check a bounded copy tree for symbolic links and Windows reparse points."""
    return (
        _tree_observation_problem(
            root, ignored, max_files=max_files, max_bytes=max_bytes, deadline=deadline
        )
        is None
    )


def _tree_observation_problem(
    root, ignored=None, *, max_files, max_bytes, deadline, tolerate_disappeared=False
):
    info = _tree_entry_info(root)
    if info is None or not stat.S_ISDIR(info.st_mode):
        return "invalid_root"
    ignored = ignored or set()
    files, total_bytes, entries = 0, 0, 0
    errors = []
    for directory, dirs, names in os.walk(root, onerror=errors.append):
        dirs[:] = [name for name in dirs if name not in ignored]
        for name in dirs + names:
            entries += 1
            if problem := _tree_budget_problem(
                files, total_bytes, entries, max_files, max_bytes, deadline
            ):
                return problem
            info = _observe_tree_child(Path(directory) / name, tolerate_disappeared)
            if isinstance(info, str):
                return info
            if info is not None and stat.S_ISREG(info.st_mode):
                files += 1
                total_bytes += info.st_size
            if problem := _tree_budget_problem(
                files, total_bytes, entries, max_files, max_bytes, deadline
            ):
                return problem
    return _tree_walk_problem(root, errors, tolerate_disappeared)


def _observe_tree_child(path, tolerate_disappeared):
    try:
        info = _nonlinked_tree_lstat(path)
    except FileNotFoundError:
        return None if tolerate_disappeared else "entry_disappeared"
    except OSError:
        return "entry_unreadable"
    return info if info is not None else "linked_entry"


def _tree_walk_problem(root, errors, tolerate_disappeared):
    for error in errors:
        if not isinstance(error, FileNotFoundError):
            return "entry_unreadable"
        if not (
            tolerate_disappeared
            and error.filename is not None
            and root in Path(error.filename).parents
        ):
            return "entry_disappeared"
    return None


def _tree_entry_info(path):
    """Inspect each entry once without following links or Windows reparse points."""
    try:
        return _nonlinked_tree_lstat(path)
    except OSError:
        return None


def _nonlinked_tree_lstat(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    ):
        return None
    return info


def _tree_budget_exceeded(files, total_bytes, entries, max_files, max_bytes, deadline):
    """Apply the same file, entry, byte and deadline limits throughout one walk."""
    return (
        _tree_budget_problem(
            files, total_bytes, entries, max_files, max_bytes, deadline
        )
        is not None
    )


def _tree_budget_problem(files, total_bytes, entries, max_files, max_bytes, deadline):
    if files > max_files:
        return "file_count"
    if total_bytes > max_bytes:
        return "byte_count"
    if entries > max_files * 2:
        return "entry_count"
    if time.monotonic() >= deadline:
        return "deadline"
    return None


def regular_target_within(root: Path, target: Path) -> bool:
    """Require a regular target and every lexical ancestor to remain nonlinked under root."""
    try:
        root = Path(root).resolve(strict=True)
        lexical = Path(
            os.path.abspath(target if target.is_absolute() else root / target)
        )
        lexical.relative_to(root)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        for path in (lexical, *lexical.parents):
            if path != root and not path.is_relative_to(root):
                continue
            info = path.stat()
            if path.is_symlink() or getattr(info, "st_file_attributes", 0) & reparse:
                return False
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(root)
        return resolved.is_file()
    except (OSError, RuntimeError, ValueError):
        return False


def path_chain_has_no_links(root: Path, target: Path) -> bool:
    """Require a lexical path and every existing ancestor to stay nonlinked under root."""
    try:
        root = Path(root).resolve(strict=True)
        lexical = Path(
            os.path.abspath(target if target.is_absolute() else root / target)
        )
        parts = lexical.relative_to(root).parts
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        current = root
        for part in parts:
            current /= part
            if current.exists() or current.is_symlink():
                info = current.lstat()
                if (
                    current.is_symlink()
                    or getattr(info, "st_file_attributes", 0) & reparse
                ):
                    return False
        return lexical.resolve(strict=False).is_relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False


def create_bounded_temp_directory(prefix: str) -> tuple[Path, Path]:
    """Create a uniquely named child of the system temporary directory."""
    parent = Path(tempfile.gettempdir()).resolve()
    root = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    if root.parent != parent:
        shutil.rmtree(root, ignore_errors=True)
        raise RuntimeAuditError(
            "E_MUTATION_TEMP", "temporary directory escaped system temp"
        )
    return parent, root


def remove_bounded_temp_directory(root: Path | None, parent: Path, prefix: str) -> bool:
    """Remove only a nonlinked, named temporary directory directly under its parent."""
    if root is None:
        return False
    try:
        lexical = Path(os.path.abspath(root))
        if lexical.parent != parent or not lexical.name.startswith(prefix):
            return False
        if not path_chain_has_no_links(parent, lexical):
            return False
        shutil.rmtree(lexical)
        return not lexical.exists()
    except OSError:
        return False


def _facts() -> dict:
    empty_hash = hashlib.sha256(b"").hexdigest()
    return {
        "exit_code": None,
        "timed_out": False,
        "timeout_seconds": None,
        "duration_ms": 0,
        "termination_reason": "not_started",
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": False,
        "stdout_sha256": empty_hash,
        "stderr_sha256": empty_hash,
    }


def _environment(scratch: Path) -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in allowed
    }
    home = scratch.resolve() / "runtime-home"
    home.mkdir(parents=True, exist_ok=False)
    environment.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "TMP": str(home),
            "TEMP": str(home),
            "TMPDIR": str(home),
            "PYTHONNOUSERSITE": "1",
            "PYTHONHASHSEED": "0",
        }
    )
    return environment


def _launch(
    argv: list[str], cwd: Path, environment: dict[str, str]
) -> subprocess.Popen:
    if not argv:
        raise OSError("empty command")
    child, unit, error = assembly_process._launch(
        argv[0], argv[1:], cwd, env=environment
    )
    if child is None or unit is None:
        raise OSError(error or "process lifecycle setup failed")
    # Preserve the Popen-shaped runner interface while carrying the concrete
    # cleanup unit returned by the shared lifecycle helper.
    child._factory_cleanup_unit = unit
    return child


def _cleanup_unit(child: subprocess.Popen):
    return getattr(child, "_factory_cleanup_unit", None)


def _stop(child: subprocess.Popen) -> bool:
    unit = _cleanup_unit(child)
    if unit is not None:
        return assembly_process._terminate_unit(child, unit)

    # Keep direct helper callers and Popen-shaped test doubles bounded. Every
    # production invocation from _launch has the shared cleanup unit.
    cleanup_confirmed = True
    if os.name == "nt":
        # Only the process tree created by this invocation is addressed.
        try:
            stopped = subprocess.run(
                ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            cleanup_confirmed = stopped.returncode == 0
        except subprocess.TimeoutExpired:
            cleanup_confirmed = False
    else:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if child.poll() is None:
        child.kill()
    return cleanup_confirmed


def _drain_stream(
    name: str,
    stream: BinaryIO,
    overflow: threading.Event,
    streams: dict[str, tuple[str, int]],
    capture: BinaryIO | None = None,
) -> None:
    """Hash one captured stream and retain only its digest and byte count."""
    digest, size = hashlib.sha256(), 0
    try:
        while chunk := stream.read(65536):
            size += len(chunk)
            digest.update(chunk)
            if capture is not None and size <= MAX_OUTPUT:
                capture.write(chunk)
            if size > MAX_OUTPUT:
                overflow.set()
    except (OSError, ValueError):
        # A failed evidence sink is an execution failure, not an empty clean log.
        overflow.set()
    finally:
        streams[name] = (digest.hexdigest(), size)
        stream.close()


def _start_stream_readers(
    child: subprocess.Popen,
    overflow: threading.Event,
    streams: dict[str, tuple[str, int]],
    capture: BinaryIO | None = None,
    stderr_capture: BinaryIO | None = None,
) -> list[threading.Thread]:
    threads = [
        threading.Thread(
            target=_drain_stream,
            args=(
                name,
                stream,
                overflow,
                streams,
                capture if name == "stdout" else stderr_capture,
            ),
            daemon=True,
        )
        for name, stream in (("stdout", child.stdout), ("stderr", child.stderr))
    ]
    for thread in threads:
        thread.start()
    return threads


def _wait_for_exit_or_limit(
    child: subprocess.Popen,
    timeout_seconds: int,
    overflow: threading.Event,
    cancelled: threading.Event | None = None,
    *,
    deadline: float | None = None,
    unit=None,
    artifact_tree=None,
    facts=None,
) -> bool:
    deadline = deadline if deadline is not None else time.monotonic() + timeout_seconds
    while not overflow.is_set() and not (cancelled is not None and cancelled.is_set()):
        if time.monotonic() >= deadline:
            return True
        _observe_artifact_quota(
            artifact_tree, overflow, deadline, active=True, facts=facts
        )
        if overflow.is_set():
            break
        if unit is not None:
            assembly_process._observe_descendants(child, unit)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        try:
            child.wait(timeout=min(0.01, remaining))
            _observe_artifact_quota(
                artifact_tree, overflow, deadline, active=True, facts=facts
            )
            # A process may become observable as exited just after wait's
            # timeout boundary. Keep the signed deadline authoritative.
            return time.monotonic() > deadline
        except subprocess.TimeoutExpired:
            continue
    return False


def _observe_artifact_quota(
    root, overflow, deadline=float("inf"), *, active=False, facts=None
):
    """Cooperative observed quota, not a kernel filesystem quota or sandbox."""
    if root is None or time.monotonic() >= deadline:
        return
    limits = {"max_files": 200, "max_bytes": 32 * 1024 * 1024}
    native = isinstance(root, dict)
    if native:
        root, limits = root["root"], root["limits"]
    problem = _tree_observation_problem(
        root, **limits, deadline=deadline, tolerate_disappeared=active and native
    )
    if problem and problem != "deadline" and time.monotonic() < deadline:
        if native and facts is not None:
            facts.setdefault("artifact_limit_reason", problem)
        overflow.set()


def _join_stream_readers(
    child: subprocess.Popen, threads: list[threading.Thread], cleanup_confirmed: bool
) -> tuple[bool, bool]:
    deadline = time.monotonic() + assembly_process.CLEANUP_TIMEOUT_SECONDS
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        cleanup_confirmed = _stop(child) and cleanup_confirmed
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
    streams_closed = not any(thread.is_alive() for thread in threads)
    return cleanup_confirmed, streams_closed


def _await_cleanup(
    child: subprocess.Popen, threads: list[threading.Thread]
) -> tuple[bool, bool]:
    unit = _cleanup_unit(child)
    cleanup_confirmed = False
    streams_closed = False
    try:
        if unit is not None:
            # The helper observes descendants during the runner's polling loop,
            # then verifies the process group / assigned Job Object is empty.
            cleanup_confirmed = assembly_process._await_cleanup(
                child, unit, terminate=True
            )
        elif child.poll() is None:
            # An unbound test double may be stopped, but cannot be confirmed.
            _stop(child)
        cleanup_confirmed, streams_closed = _join_stream_readers(
            child, threads, cleanup_confirmed
        )
    finally:
        if unit is not None:
            try:
                unit.close()
            except OSError:
                cleanup_confirmed = False
    return cleanup_confirmed, streams_closed


def _cleanup_is_confirmed(
    child: subprocess.Popen, cleanup_confirmed: bool, streams_closed: bool
) -> bool:
    # Cleanup must have come from the bound process group / Job Object, with
    # the root exited and the runner's captured streams closed. This remains
    # bounded process supervision, not a general security sandbox.
    return (
        _cleanup_unit(child) is not None
        and cleanup_confirmed
        and child.poll() is not None
        and streams_closed
    )


def _stream_facts(facts: dict, streams: dict[str, tuple[str, int]]) -> None:
    empty_hash = hashlib.sha256(b"").hexdigest()
    for name in ("stdout", "stderr"):
        digest, size = streams.get(name, (empty_hash, 0))
        facts[f"{name}_sha256"] = digest
        facts[f"{name}_bytes"] = size


def run_bounded_command(
    argv: list[str],
    cwd: Path,
    timeout_seconds: int,
    scratch: Path,
    *,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    cancelled: threading.Event | None = None,
    go_cache: Path | None = None,
    artifact_tree: Path | None = None,
    tool_context: dict | None = None,
) -> dict:
    """Hash streams without retaining logs; terminate on timeout/output overflow."""
    facts = _facts()
    started = time.monotonic()
    facts["timeout_seconds"] = timeout_seconds
    _validate_artifact_directory(artifact_tree)
    if go_cache is not None:
        _validate_go_cache(go_cache, cwd, scratch)
    native_environment = None
    if tool_context is not None:
        if go_cache is not None:
            raise RuntimeAuditError(
                "E_NATIVE_CONTEXT", "native and Go contexts are exclusive"
            )
        native_environment = _native_tool_environment(
            tool_context, argv, cwd, scratch, deadline=started + timeout_seconds
        )
        artifact_tree = _native_artifact_tree(tool_context, artifact_tree)
    capture, stderr_capture = _open_capture_files(stdout_path, stderr_path)
    # Start the budget before process creation and stream setup. Those steps
    # must not create unmeasured runtime outside the signed timeout.
    execution_started = started if tool_context is not None else time.monotonic()
    deadline = execution_started + timeout_seconds
    if tool_context is not None and time.monotonic() >= deadline:
        _close_capture_files(capture, stderr_capture)
        raise RuntimeAuditError(
            "E_NATIVE_BUDGET", "native preflight exhausted deadline"
        )
    try:
        environment = _environment(scratch)
        if go_cache is not None:
            environment["GOCACHE"] = str(go_cache)
            environment["LOCALAPPDATA"] = environment["HOME"]
        if native_environment is not None:
            environment.update(native_environment)
        child = _launch(argv, cwd, environment)
    except OSError:
        _close_capture_files(capture, stderr_capture)
        return _launch_error_facts(facts, started)
    return _run_child_bounded(
        child,
        facts,
        timeout_seconds,
        deadline,
        execution_started,
        capture,
        stderr_capture,
        cancelled,
        artifact_tree,
    )


def _validate_artifact_directory(artifact_tree):
    """Require an optional quota tree to name an existing absolute directory."""
    if artifact_tree is not None and (
        not isinstance(artifact_tree, Path)
        or not artifact_tree.is_absolute()
        or not artifact_tree.is_dir()
    ):
        raise RuntimeAuditError(
            "E_ARTIFACT_QUOTA", "existing absolute artifact directory required"
        )


def _native_tool_environment(context, argv, cwd, scratch, *, deadline=None):
    """Bind native lookup paths; authenticity is separately checked by the operator caller."""
    fields = {
        "bundle_root",
        "executable",
        "resource_dirs",
        "cache_root",
        "manifest_sha256",
    }
    if not isinstance(context, dict) or set(context) != fields:
        raise RuntimeAuditError(
            "E_NATIVE_CONTEXT", "exact native tool context required"
        )
    from .runtime_audit_common import require_digest

    require_digest(context["manifest_sha256"], "native manifest")
    root, executable = context["bundle_root"], context["executable"]
    _native_tool_paths(root, executable, context["resource_dirs"])
    if not argv or argv[0] != str(executable) or Path(cwd) != root:
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "native executable or cwd differs")
    cache = context["cache_root"]
    _native_workflow_cache(cache, scratch, deadline)
    paths = [root, *context["resource_dirs"]]
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT")
        if not system_root or not Path(system_root).is_absolute():
            raise RuntimeAuditError(
                "E_NATIVE_CONTEXT", "absolute Windows system root required"
            )
        paths.append(Path(system_root) / "System32")
    local = cache / "AppData" / "Local"
    local.mkdir(parents=True, exist_ok=True)
    return {
        "PATH": os.pathsep.join(dict.fromkeys(map(str, paths))),
        "HOME": str(cache),
        "USERPROFILE": str(cache),
        "LOCALAPPDATA": str(local),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _native_artifact_tree(context, supplied):
    root = context["cache_root"].parent
    if supplied is not None and supplied != root:
        raise RuntimeAuditError(
            "E_NATIVE_CONTEXT", "native artifacts must use workflow quota"
        )
    return {"root": root, "limits": {"max_files": 512, "max_bytes": 512 * 1024 * 1024}}


def _native_tool_paths(root, executable, resources):
    paths = [root, executable]
    if not isinstance(resources, list) or not 1 <= len(resources) <= 16:
        raise RuntimeAuditError(
            "E_NATIVE_CONTEXT", "bounded resource directory list required"
        )
    paths.extend(resources)
    if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "absolute native paths required")
    if not root.is_dir() or not executable.is_file():
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "native root or executable missing")
    if any(path.resolve() != path for path in paths):
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "canonical native paths required")
    if not path_chain_has_no_links(Path(root.anchor), root):
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "native bundle ancestor is linked")
    if any(not path_chain_has_no_links(root, path) for path in paths[1:]):
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "native path escapes or is linked")
    if len(set(resources)) != len(resources) or any(
        not path.is_dir() for path in resources
    ):
        raise RuntimeAuditError(
            "E_NATIVE_CONTEXT", "distinct existing native resource directories required"
        )


def _native_workflow_cache(cache, scratch, deadline=None):
    scratch = Path(scratch)
    temporary = Path(tempfile.gettempdir()).resolve()
    roots = [
        path
        for path in scratch.parents
        if path.parent == temporary and path.name.startswith("factory-native-")
    ]
    if not roots or not isinstance(cache, Path) or not cache.is_absolute():
        raise RuntimeAuditError(
            "E_NATIVE_CONTEXT", "native workflow temp root required"
        )
    root = roots[0]
    if cache != root / "tool-cache" or not scratch.is_dir():
        raise RuntimeAuditError(
            "E_NATIVE_CONTEXT", "cache must belong to the current workflow"
        )
    if not path_chain_has_no_links(temporary, root) or not path_chain_has_no_links(
        root, scratch
    ):
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "native workflow is linked")
    if not path_chain_has_no_links(root, cache):
        raise RuntimeAuditError("E_NATIVE_CONTEXT", "native cache is linked")
    cache.mkdir(exist_ok=True)
    if not tree_has_no_links_or_reparse_points(
        cache,
        max_files=512,
        max_bytes=512 * 1024 * 1024,
        deadline=deadline or float("inf"),
    ):
        raise RuntimeAuditError(
            "E_NATIVE_CONTEXT", "native cache contains linked entries"
        )


def _validate_go_cache(cache, cwd, scratch):
    """Share compilation only inside this capture's fresh, nonlinked temp root."""
    parent = Path(scratch).parent
    valid = (
        isinstance(cache, Path)
        and cache.is_absolute()
        and cache.parent == parent
        and cache.name == "go-cache"
        and Path(cwd).parent == parent
        and parent.name.startswith("cf-polyglot-oracle-")
        and parent.parent == Path(tempfile.gettempdir()).resolve()
    )
    if not valid or not path_chain_has_no_links(parent, cache):
        raise RuntimeAuditError(
            "E_GO_CACHE", "cache must be a nonlinked child of this capture temp"
        )
    cache.mkdir(exist_ok=True)


def _open_capture_files(stdout_path, stderr_path):
    capture = stdout_path.open("xb") if stdout_path is not None else None
    try:
        stderr_capture = stderr_path.open("xb") if stderr_path is not None else None
    except OSError:
        if capture is not None:
            capture.close()
        raise
    return capture, stderr_capture


def _close_capture_files(capture, stderr_capture):
    if capture is not None:
        capture.close()
    if stderr_capture is not None:
        stderr_capture.close()


def _launch_error_facts(facts, started):
    facts.update(
        launch_error=True,
        termination_reason="launch_error",
        duration_ms=max(0, round((time.monotonic() - started) * 1000)),
    )
    return facts


def _run_child_bounded(
    child,
    facts,
    timeout_seconds,
    deadline,
    execution_started,
    capture,
    stderr_capture,
    cancelled,
    artifact_tree=None,
):
    overflow = threading.Event()
    streams: dict[str, tuple[str, int]] = {}
    threads = []
    execution_duration_ms = 0
    try:
        threads = _start_stream_readers(
            child, overflow, streams, capture, stderr_capture
        )
        facts["timed_out"] = _wait_for_exit_or_limit(
            child,
            timeout_seconds,
            overflow,
            cancelled,
            deadline=deadline,
            unit=_cleanup_unit(child),
            artifact_tree=artifact_tree,
            facts=facts,
        )
        execution_duration_ms = max(
            0, round((time.monotonic() - execution_started) * 1000)
        )
        facts["output_limit_exceeded"] = overflow.is_set()
        cleanup_confirmed, streams_closed = _await_cleanup(child, threads)
        _observe_artifact_quota(artifact_tree, overflow, deadline, facts=facts)
        if isinstance(artifact_tree, dict) and time.monotonic() >= deadline:
            facts["timed_out"] = True
    except BaseException:
        _stop(child)
        _await_cleanup(child, threads)
        raise
    finally:
        _close_capture_files(capture, stderr_capture)
    return _completed_child_facts(
        child,
        facts,
        overflow,
        streams,
        execution_duration_ms,
        cleanup_confirmed,
        streams_closed,
        cancelled,
    )


def _completed_child_facts(
    child,
    facts,
    overflow,
    streams,
    execution_duration_ms,
    cleanup_confirmed,
    streams_closed,
    cancelled,
):
    if cancelled is not None:
        facts["cancelled"] = cancelled.is_set()
    facts["cleanup_confirmed"] = _cleanup_is_confirmed(
        child, cleanup_confirmed, streams_closed
    )
    facts["exit_code"] = child.returncode
    _stream_facts(facts, streams)
    facts["output_limit_exceeded"] = overflow.is_set()
    facts["duration_ms"] = execution_duration_ms
    facts["termination_reason"] = _termination_reason(facts)
    return facts


def _termination_reason(facts):
    if facts.get("cancelled"):
        return "cancelled"
    if facts["timed_out"]:
        return "timeout"
    if facts["output_limit_exceeded"]:
        return "output_limit"
    return "process_exit"


def _polyglot_inventory(root, ignored, excluded=None):
    """Bound the complete copied input, including manifests and lock files."""
    rows, total, lines = [], 0, 0
    for path in _polyglot_source_files(
        root, ignored, limits=(200, 16 * 1024 * 1024), excluded=excluded
    ):
        relative = path.relative_to(root)
        digest, data = bounded_file_sha256(path, 16 * 1024 * 1024, include_bytes=True)
        total += len(data)
        lines += data.count(b"\n")
        rows.append({"path": relative.as_posix(), "sha256": digest})
        if len(rows) > 200 or total > 16 * 1024 * 1024 or lines > 50000:
            raise ValueError("workspace exceeds 200 files, 50000 lines or 16 MiB")
    packages = sum(
        Path(row["path"]).name in {"package.json", "go.mod", "Cargo.toml"}
        for row in rows
    )
    if packages > 10:
        raise ValueError("workspace exceeds ten packages")
    return rows


def _polyglot_source_files(
    root, ignored, *, include_bytecode=False, limits=None, excluded=None
):
    if limits is not None:
        info = _tree_entry_info(root)
        if info is None or not stat.S_ISDIR(info.st_mode):
            raise ValueError("tool dependency root must be a nonlinked directory")
    files, total, entries = 0, 0, 0
    onerror = _polyglot_walk_error if limits is not None else None
    for directory, dirs, names in os.walk(root, onerror=onerror):
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in ignored
            and (
                excluded is None
                or (Path(directory) / name).relative_to(root) != excluded
            )
        )
        if limits is not None:
            entries += len(dirs) + len(names)
            if entries > limits[0] * 2:
                raise ValueError("tool dependency entry limit exceeded")
            sizes = [
                _polyglot_entry_size(Path(directory) / name) for name in dirs + names
            ]
            files += sum(size is not None for size in sizes)
            total += sum(size for size in sizes if size is not None)
            if _tree_budget_exceeded(files, total, entries, *limits, float("inf")):
                raise ValueError(
                    "tool dependencies exceed bounded regular-file inventory"
                )
        for name in sorted(names):
            if name not in ignored and (
                include_bytecode or not name.endswith((".pyc", ".pyo"))
            ):
                yield Path(directory) / name


def _polyglot_walk_error(error):
    raise error


def _polyglot_entry_size(path):
    info = _tree_entry_info(path)
    if info is None:
        raise ValueError("tool dependency entry is linked or unreadable")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise ValueError("input entry must be a regular file or directory")
    return info.st_size if stat.S_ISREG(info.st_mode) else None


def _polyglot_argv(framework, tool, launcher, test, selector, report, coverage):
    pattern = "^" + re.escape(selector) + "$"
    if framework == "jest":
        return [
            str(launcher),
            str(tool),
            "--runInBand",
            "--runTestsByPath",
            test,
            "--testNamePattern",
            pattern,
            "--json",
            "--outputFile",
            str(report),
            "--coverage",
            "--coverageProvider=v8",
            "--coverageReporters=json",
            "--coverageDirectory",
            str(coverage),
        ]
    if framework == "vitest":
        return [
            str(launcher),
            str(tool),
            "run",
            test,
            "--testNamePattern",
            pattern,
            "--reporter=json",
            "--outputFile",
            str(report),
            "--coverage.enabled",
            "--coverage.provider=v8",
            "--coverage.reporter=json",
            "--coverage.reportsDirectory",
            str(coverage),
            "--coverage.reportOnFailure",
            "--maxWorkers=1",
            "--globals",
        ]
    if framework == "go":
        package = "./" + str(Path(test).parent).replace("\\", "/")
        return [
            str(tool),
            "test",
            package,
            "-json",
            "-count=1",
            "-run",
            pattern,
            "-coverprofile=" + str(coverage),
        ]
    rustc = tool.with_name("rustc.exe" if os.name == "nt" else "rustc")
    profiles = report.parent / "profiles"
    profiles.mkdir()
    flags = ["-C", "instrument-coverage"]
    profile_name = "%p-%m.profraw"
    if os.name == "nt":
        # Windows libtest exits via ExitProcess on failure, bypassing CRT flush.
        flags += ["-C", "llvm-args=-runtime-counter-relocation"]
        profile_name = "%p-%m%c.profraw"
    return [
        str(tool),
        "--config",
        'build.rustc="' + rustc.as_posix() + '"',
        "--config",
        "build.rustflags=" + json.dumps(flags, separators=(",", ":")),
        "--config",
        'env.LLVM_PROFILE_FILE.value="' + (profiles / profile_name).as_posix() + '"',
        "--config",
        "env.LLVM_PROFILE_FILE.force=true",
        "test",
        "--offline",
        "--locked",
        "--target-dir",
        str(coverage),
        "--test",
        Path(test).stem,
        "--message-format=json",
        selector,
        "--",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]


def _polyglot_js_observation(
    report, coverage, target, selector, test, line, target_line
):
    data = json.loads(report.read_text(encoding="utf-8"))
    cases = [
        case
        for suite in data.get("testResults", [])
        if Path(suite.get("name", "")).absolute() == Path(test).absolute()
        for case in suite.get("assertionResults", [])
        if case.get("fullName") == selector
    ]
    if len(cases) != 1 or not 1 <= data.get("numTotalTests", 0) <= 200:
        return {"valid": False}
    case = cases[0]
    failures = "\n".join(case.get("failureMessages", []))
    assertion = bool(
        re.search(re.escape(Path(test).name) + ":" + str(line) + r":\d+", failures)
    )
    reached = False
    coverage_file = coverage / "coverage-final.json"
    if coverage_file.is_file():
        entries = json.loads(coverage_file.read_text(encoding="utf-8"))
        row = entries.get(str(target), entries.get(target.as_posix(), {}))
        reached = any(
            row.get("s", {}).get(key, 0) > 0
            and span["start"]["line"] <= target_line <= span["end"]["line"]
            for key, span in row.get("statementMap", {}).items()
        )
    return {
        "valid": True,
        "outcome": case.get("status"),
        "reached": reached,
        "assertion_failed": assertion
        and bool(re.search(r"(?:expect\(|AssertionError|Expected:)", failures)),
        "selected": selector,
        "total": data.get("numTotalTests"),
    }


def _polyglot_go_observation(
    stdout, coverage, target, selector, test, line, target_line
):
    events = [
        json.loads(row)
        for row in stdout.read_text(encoding="utf-8").splitlines()
        if row.strip()
    ]
    cases = [
        row
        for row in events
        if row.get("Test") == selector and row.get("Action") in {"pass", "fail", "skip"}
    ]
    output = "".join(
        row.get("Output", "") for row in events if row.get("Test") == selector
    )
    reached = False
    if coverage.is_file():
        expected_path = _polyglot_go_source_path(target)
        for row in coverage.read_text(encoding="utf-8").splitlines()[1:]:
            match = re.match(r"(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)$", row)
            if match and match[1].replace("\\", "/") == expected_path:
                reached |= (
                    int(match[2]) <= target_line <= int(match[3]) and int(match[4]) > 0
                )
    outcome = {"pass": "passed", "fail": "failed", "skip": "pending"}
    return {
        "valid": len(cases) == 1 and len({row.get("Test") for row in events}) <= 200,
        "outcome": outcome.get(cases[0]["Action"]) if len(cases) == 1 else None,
        "reached": reached,
        "selected": selector,
        "assertion_failed": f"{Path(test).name}:{line}:" in output
        and "panic:" not in output,
    }


def _polyglot_go_source_path(target):
    for directory in target.parents:
        manifest = directory / "go.mod"
        if manifest.is_file():
            match = re.search(
                r"^module\s+([^\s]+)", manifest.read_text(encoding="utf-8"), re.M
            )
            if not match:
                raise ValueError("Go module identity missing")
            return match[1].strip('"') + "/" + target.relative_to(directory).as_posix()
    raise ValueError("Go coverage target has no module manifest")


def _polyglot_cargo_observation(stdout, stderr, selector, test, line):
    text = stdout.read_text(encoding="utf-8")
    builds = [
        json.loads(row) for row in text.splitlines() if row.startswith('{"reason":')
    ]
    cases = re.findall(
        r"^test " + re.escape(selector) + r" \.\.\. (ok|FAILED|ignored)$", text, re.M
    )
    failure = stderr.read_text(encoding="utf-8")
    return {
        "valid": len(cases) == 1
        and any(
            row.get("reason") == "build-finished" and row.get("success")
            for row in builds
        ),
        "outcome": {"ok": "passed", "FAILED": "failed", "ignored": "pending"}.get(
            cases[0]
        )
        if len(cases) == 1
        else None,
        "selected": selector,
        "framework": "cargo",
        "reached": False,
        "reason": "Cargo reach not yet measured",
        "assertion_failed": bool(re.search(r"assertion .+ failed", failure))
        and f"{Path(test).name}:{line}:" in failure,
    }


def _polyglot_llvm_tools(tool):
    root = tool.parent.parent
    suffix = ".exe" if os.name == "nt" else ""
    matches = list((root / "lib/rustlib").glob("*/bin/llvm-profdata" + suffix))
    if len(matches) != 1:
        raise ValueError("one toolchain-local llvm-profdata required")
    tools = [matches[0], matches[0].with_name("llvm-cov" + suffix)]
    if not all(regular_target_within(root, path) for path in tools):
        raise ValueError("toolchain-local LLVM tools must be regular and nonlinked")
    return tools


def _polyglot_cargo_coverage(tool, trial, test, target, line, scratch, deadline):
    tools = _polyglot_llvm_tools(tool)
    profiles = sorted((scratch / "profiles").glob("*.profraw"))
    if not 1 <= len(profiles) <= 200:
        raise ValueError("missing or excessive LLVM profiles")
    if sum(path.stat().st_size for path in profiles) > 16 * 1024 * 1024:
        raise ValueError("LLVM profiles exceed 16 MiB")
    messages = [
        json.loads(row)
        for row in (scratch / "stdout.log").read_text(encoding="utf-8").splitlines()
        if row.startswith('{"reason":')
    ]
    binaries = {
        row["executable"]
        for row in messages
        if row.get("reason") == "compiler-artifact"
        and row.get("executable")
        and Path(row.get("target", {}).get("src_path", "")) == trial / test
    }
    if len(binaries) != 1:
        raise ValueError("exact selected-test executable missing")
    merged = scratch / "profile.profdata"
    commands = [
        [str(tools[0]), "merge", "-sparse", *map(str, profiles), "-o", str(merged)],
        [str(tools[1]), "export", binaries.pop(), "-instr-profile=" + str(merged)],
    ]
    processes = _polyglot_coverage_commands(commands, trial, scratch, deadline)
    if any(
        not validate_production_mutation_process(row["process"])
        or row["process"]["exit_code"] != 0
        for row in processes
    ):
        return False, processes
    data = json.loads((scratch / "coverage-1.json").read_text(encoding="utf-8"))
    regions = [
        (fn, region)
        for item in data.get("data", [])
        for fn in item.get("functions", [])
        for region in fn.get("regions", [])
    ]
    reached = any(
        region[7] == 0
        and region[4] > 0
        and region[0] <= line <= region[2]
        and Path(fn["filenames"][region[5]]) == target
        for fn, region in regions
    )
    return reached, processes


def _polyglot_coverage_commands(commands, trial, scratch, deadline):
    processes = []
    for index, argv in enumerate(commands):
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            raise ValueError("shared coverage deadline exhausted")
        runtime = trial.parent / (scratch.name + f"-llvm-{index}")
        runtime.mkdir()
        facts = run_bounded_command(
            argv,
            trial,
            remaining,
            runtime,
            stdout_path=scratch / f"coverage-{index}.json",
            stderr_path=scratch / f"coverage-{index}.stderr",
            artifact_tree=scratch,
        )
        processes.append({"argv": argv, "process": facts})
        if not validate_production_mutation_process(facts) or facts["exit_code"] != 0:
            break
    return processes


def _polyglot_trial(
    framework,
    tool,
    launcher,
    trial,
    test,
    selector,
    target,
    target_line,
    assertion_line,
    evidence,
    name,
    deadline,
):
    scratch = evidence / name
    scratch.mkdir()
    stdout, stderr = scratch / "stdout.log", scratch / "stderr.log"
    report, coverage = scratch / "report.json", scratch / "coverage"
    if framework == "cargo":
        coverage = trial.parent / "cargo-build"
    argv = _polyglot_argv(framework, tool, launcher, test, selector, report, coverage)
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise ValueError("shared execution deadline exhausted")
    runtime = trial.parent / (name + "-runtime")
    runtime.mkdir()
    options = {"go_cache": trial.parent / "go-cache"} if framework == "go" else {}
    process = run_bounded_command(
        argv,
        trial,
        remaining,
        runtime,
        stdout_path=stdout,
        stderr_path=stderr,
        artifact_tree=scratch,
        **options,
    )
    observation = {"valid": False, "reason": "missing or unsupported target coverage"}
    coverage_processes = []
    artifacts = []
    try:
        if not tree_has_no_links_or_reparse_points(scratch):
            raise ValueError("linked or oversized native reports")
        artifacts = _polyglot_report_artifacts(scratch, evidence)
        if framework in {"jest", "vitest"}:
            observation = _polyglot_js_observation(
                report,
                coverage,
                target,
                selector,
                trial / test,
                assertion_line,
                target_line,
            )
        elif framework == "go":
            observation = _polyglot_go_observation(
                stdout, coverage, target, selector, test, assertion_line, target_line
            )
        elif framework == "cargo":
            observation = _polyglot_cargo_observation(
                stdout, stderr, selector, test, assertion_line
            )
            observation["reached"], coverage_processes = _polyglot_cargo_coverage(
                tool, trial, test, target, target_line, scratch, deadline
            )
            observation["reason"] = "LLVM instrumented source regions"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        observation = {"valid": False, "reason": f"{type(exc).__name__}: {exc}"}
    if framework == "cargo":
        artifacts = _polyglot_report_artifacts(scratch, evidence)
    return {
        "argv": argv,
        "process": process,
        "observation": observation,
        "artifacts": artifacts,
        "coverage_processes": coverage_processes,
    }


def _polyglot_report_artifacts(scratch, evidence):
    artifacts, total = [], 0
    for path in sorted(scratch.rglob("*")):
        if not path.is_file():
            continue
        if not regular_target_within(scratch, path):
            raise ValueError("native report is not a contained regular file")
        total += path.stat().st_size
        if len(artifacts) >= 200 or total > 32 * 1024 * 1024:
            raise ValueError("native reports exceed bounded capture budget")
        artifacts.append(
            {
                "path": path.relative_to(evidence).as_posix(),
                "sha256": bounded_file_sha256(path, 16 * 1024 * 1024),
            }
        )
    return artifacts


def _polyglot_result(baseline, mutant, stable):
    trials = [baseline, mutant]
    safe = all(
        _polyglot_process_complete(row)
        and row["observation"].get("valid")
        and row["observation"].get("reached")
        for row in trials
    )
    first, second = [row["observation"] for row in trials]
    if (
        not safe
        or not stable
        or first.get("outcome") != "passed"
        or baseline["process"]["exit_code"] != 0
    ):
        return "INCOMPLETE"
    if second.get("outcome") == "passed" and mutant["process"]["exit_code"] == 0:
        return "SURVIVED"
    failure_exit = 101 if second.get("framework") == "cargo" else 1
    if (
        second.get("outcome") == "failed"
        and second.get("assertion_failed")
        and mutant["process"]["exit_code"] == failure_exit
    ):
        return "KILLED"
    return "INCOMPLETE"


def _polyglot_process_complete(trial):
    facts = trial["process"]
    cargo_failed = (
        trial["observation"].get("framework") == "cargo"
        and facts.get("exit_code") == 101
    )
    return validate_production_mutation_process(
        {**facts, "exit_code": 1 if cargo_failed else facts.get("exit_code")}
    )


def _polyglot_bind_mutation(root, test, production, before, after):
    if (
        not all(regular_target_within(root, root / name) for name in (test, production))
        or test == production
    ):
        raise ValueError("test and production must be distinct contained regular files")
    path = Path(production)
    if (
        path.name.startswith("test")
        or path.stem.endswith((".test", ".spec", "_test"))
        or "tests" in path.parts
    ):
        raise ValueError("mutation must target production source")
    source = (root / production).read_bytes()
    old, new = before.encode(), after.encode()
    if source.count(old) != 1:
        raise ValueError("mutation must uniquely replace production bytes")
    return source, old, new, source[: source.index(old)].count(b"\n") + 1


def _polyglot_tools(framework, tool, launcher):
    paths = [tool, launcher] if framework in {"jest", "vitest"} else [tool]
    if framework == "cargo":
        paths.append(tool.with_name("rustc.exe" if os.name == "nt" else "rustc"))
        paths += _polyglot_llvm_tools(tool)
    if framework in {"jest", "vitest"}:
        locks = [
            parent / "package-lock.json"
            for parent in list(tool.parents)[:5]
            if (parent / "package-lock.json").is_file()
        ]
        if len(locks) != 1:
            raise ValueError("one source-bound tool dependency lock required")
        paths += locks
    result = [
        {"path": str(path), "sha256": bounded_file_sha256(path, 256 * 1024 * 1024)}
        for path in paths
    ]
    if framework in {"jest", "vitest"}:
        result.append(_polyglot_dependencies(locks[0].parent / "node_modules"))
    return result


def _polyglot_dependencies(root):
    """Bind installed bytes, including transitive packages, twice per capture."""
    rows, total = [], 0
    for path in _polyglot_source_files(
        root, set(), include_bytecode=True, limits=(10000, 128 * 1024 * 1024)
    ):
        digest, size = _polyglot_stream_hash(path, 64 * 1024 * 1024)
        total += size
        if len(rows) >= 10000 or total > 128 * 1024 * 1024:
            raise ValueError("tool dependencies exceed 10000 files or 128 MiB")
        rows.append({"path": path.relative_to(root).as_posix(), "sha256": digest})
    return {
        "path": str(root),
        "sha256": sha256_bytes(canonical_bytes(rows)),
        "files": rows,
        "bytes": total,
        "limits": {"files": 10000, "bytes": 128 * 1024 * 1024},
    }


def _polyglot_stream_hash(path, limit):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > limit:
                raise ValueError("dependency file exceeds bounded stream limit")
            digest.update(chunk)
    return digest.hexdigest(), size


def _capture_polyglot_challenge(
    root,
    framework,
    test,
    selector,
    line,
    production,
    before,
    after,
    output,
    tool,
    launcher,
    timeout,
    ignored,
    execute,
):
    _validate_polyglot_request(
        execute,
        framework,
        test,
        production,
        output,
        selector,
        before,
        after,
        timeout,
        line,
    )
    evidence = new_output_path_inside(root, Path(output))
    evidence.mkdir(parents=True)
    payload = {
        "schema": "factory.polyglot-oracle-capture.v1",
        "framework": framework,
        "status": "INCOMPLETE",
        "authority": "none",
        "signature_status": "UNSIGNED",
        "observer_integrity": "IN_PROCESS_NOT_ATTESTED",
        "cleanup": {"removed": False},
    }
    parent, temp = root, None
    try:
        excluded = evidence.relative_to(root)
        manifest = _polyglot_inventory(root, ignored, excluded)
        source, old, new, target_line = _polyglot_bind_mutation(
            root, test, production, before, after
        )
        tool = Path(tool or "__missing_tool__").absolute()
        launcher = Path(
            launcher or shutil.which("node") or "__missing_node__"
        ).absolute()
        payload.update(
            source_manifest=manifest,
            source_manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
            selection={"path": test, "selector": selector, "assertion_line": line},
            production_mutation={
                "path": production,
                "line": target_line,
                "before_sha256": sha256_bytes(source),
                "after_sha256": sha256_bytes(source.replace(old, new, 1)),
            },
        )
        payload["tools"] = _polyglot_tools(framework, tool, launcher)
        parent, temp = create_bounded_temp_directory("cf-polyglot-oracle-")
        trial = temp / "candidate"
        shutil.copytree(
            root, trial, ignore=_polyglot_copy_ignores(root, ignored, excluded)
        )
        dependencies = (
            _polyglot_copy_application_dependencies(root, temp)
            if framework in {"jest", "vitest"}
            else None
        )
        if dependencies is not None:
            payload["application_dependencies"] = dependencies
        if _polyglot_inventory(trial, ignored, excluded) != manifest:
            raise ValueError("copy source/configuration drift")
        copied = trial / production
        deadline = time.monotonic() + timeout
        args = (
            framework,
            tool,
            launcher,
            trial,
            test,
            selector,
            copied,
            target_line,
            line,
            evidence,
        )
        payload["baseline"] = _polyglot_trial(*args, "baseline", deadline)
        if _polyglot_inventory(
            trial, ignored, excluded
        ) != manifest or not _polyglot_application_dependencies_current(
            root, temp, dependencies
        ):
            raise ValueError("baseline changed source/configuration")
        copied.write_bytes(source.replace(old, new, 1))
        mutated = _polyglot_inventory(trial, ignored, excluded)
        payload["mutant"] = _polyglot_trial(*args, "mutant", deadline)
        stable = (
            _polyglot_inventory(trial, ignored, excluded) == mutated
            and _polyglot_inventory(root, ignored, excluded) == manifest
            and _polyglot_application_dependencies_current(root, temp, dependencies)
            and _polyglot_tools(framework, tool, launcher) == payload["tools"]
        )
        payload["source_unchanged"] = stable
        payload["status"] = _polyglot_result(
            payload["baseline"], payload["mutant"], stable
        )
    except (OSError, ValueError, RuntimeAuditError) as exc:
        payload.update(
            status="INCOMPLETE",
            error_code=getattr(exc, "code", "E_POLYGLOT_CAPTURE"),
            error=str(exc),
        )
    finally:
        payload["cleanup"]["removed"] = remove_bounded_temp_directory(
            temp, parent, "cf-polyglot-oracle-"
        )
        if not payload["cleanup"]["removed"]:
            payload["status"] = "INCOMPLETE"
        (evidence / "capture.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return payload


def _polyglot_copy_ignores(root, ignored, excluded):
    patterns = shutil.ignore_patterns(*ignored)

    def ignore(directory, names):
        omitted = patterns(directory, names)
        omitted.update(
            name
            for name in names
            if (Path(directory) / name).relative_to(root) == excluded
        )
        return omitted

    return ignore


def _polyglot_copy_application_dependencies(root, temp):
    source = root / "node_modules"
    if not source.exists() and not source.is_symlink():
        return {"path": str(source), "state": "ABSENT"}
    manifest = _polyglot_dependencies(source)
    copied = temp / "node_modules"
    shutil.copytree(source, copied, symlinks=True)
    if _polyglot_dependencies(copied)["files"] != manifest["files"]:
        raise ValueError("copied application dependencies differ")
    return manifest


def _polyglot_application_dependencies_current(root, temp, manifest):
    if manifest is None:
        return True
    if manifest.get("state") == "ABSENT":
        return not any(
            path.exists() or path.is_symlink()
            for path in (root / "node_modules", temp / "node_modules")
        )
    return (
        _polyglot_dependencies(root / "node_modules") == manifest
        and _polyglot_dependencies(temp / "node_modules")["files"] == manifest["files"]
    )


def _validate_polyglot_request(
    execute,
    framework,
    test_path,
    production_path,
    evidence_path,
    selector,
    before_text,
    after_text,
    timeout_seconds,
    assertion_line,
):
    if execute is not True:
        raise RuntimeAuditError(
            "E_EXECUTION_AUTHORIZATION", "explicit execute=True required"
        )
    if not isinstance(framework, str) or framework not in {
        "jest",
        "vitest",
        "go",
        "cargo",
    }:
        raise RuntimeAuditError("E_MUTATION_INPUT", "unsupported framework")
    if not all(
        isinstance(value, str) and value
        for value in (test_path, production_path, evidence_path, selector)
    ):
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "nonempty string paths and exact selector required"
        )
    if (
        not all(isinstance(text, str) and text for text in (before_text, after_text))
        or before_text == after_text
    ):
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "distinct nonempty patch text required"
        )
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
        raise RuntimeAuditError("E_MUTATION_INPUT", "timeout must be 1..120 seconds")
    if (
        not selector
        or len(selector) > 500
        or type(assertion_line) is not int
        or assertion_line < 1
    ):
        raise RuntimeAuditError(
            "E_MUTATION_INPUT", "exact selector and assertion line required"
        )


if __name__ == "__main__":
    _COMMANDS = {
        "compile-offline-go": _compile_offline_go,
        "prefetch-go-modules": _prefetch_go_modules,
    }
    if len(sys.argv) != 2 or sys.argv[1] not in _COMMANDS:
        raise SystemExit("Expected compile-offline-go or prefetch-go-modules")
    _COMMANDS[sys.argv[1]]()

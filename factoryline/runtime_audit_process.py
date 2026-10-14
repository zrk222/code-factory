"""Bounded, secret-minimized subprocess supervision; NOT a security sandbox."""

from __future__ import annotations

import hashlib
import os
import signal
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO

from . import assembly_process
from .runtime_audit_common import (
    RuntimeAuditError,
    validate_production_mutation_origins,
    validate_production_mutation_trial,
)

MAX_OUTPUT = 8 * 1024 * 1024


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
    root: Path, ignored: set[str] | None = None
) -> bool:
    """Check a bounded copy tree for symbolic links and Windows reparse points."""
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    ignored = ignored or set()
    files, total_bytes = 0, 0
    for directory, dirs, names in os.walk(root):
        dirs[:] = [name for name in dirs if name not in ignored]
        for name in dirs + names:
            path = Path(directory) / name
            try:
                info = path.stat()
                if (
                    path.is_symlink()
                    or getattr(info, "st_file_attributes", 0) & reparse
                ):
                    return False
                if path.is_file():
                    files += 1
                    total_bytes += info.st_size
            except OSError:
                return False
            if files > 20000 or total_bytes > 512 * 1024 * 1024:
                return False
    return True


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
) -> bool:
    deadline = deadline if deadline is not None else time.monotonic() + timeout_seconds
    while not overflow.is_set() and not (cancelled is not None and cancelled.is_set()):
        if unit is not None:
            assembly_process._observe_descendants(child, unit)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        try:
            child.wait(timeout=min(0.01, remaining))
            # A process may become observable as exited just after wait's
            # timeout boundary. Keep the signed deadline authoritative.
            return time.monotonic() > deadline
        except subprocess.TimeoutExpired:
            continue
    return False


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
) -> dict:
    """Hash streams without retaining logs; terminate on timeout/output overflow."""
    facts = _facts()
    started = time.monotonic()
    facts["timeout_seconds"] = timeout_seconds
    capture, stderr_capture = _open_capture_files(stdout_path, stderr_path)
    # Start the budget before process creation and stream setup. Those steps
    # must not create unmeasured runtime outside the signed timeout.
    execution_started = time.monotonic()
    deadline = execution_started + timeout_seconds
    try:
        child = _launch(argv, cwd, _environment(scratch))
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
    )


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
        )
        execution_duration_ms = max(
            0, round((time.monotonic() - execution_started) * 1000)
        )
        facts["output_limit_exceeded"] = overflow.is_set()
        cleanup_confirmed, streams_closed = _await_cleanup(child, threads)
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

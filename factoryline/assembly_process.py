"""Bounded CLI output capture with fail-closed process cleanup.

Each invocation is attached to one observable operating-system cleanup unit:
POSIX launches use a fresh process group and Windows launches use a Job Object.
This is process hygiene, not a security sandbox; it cannot prove that a hostile
process which escapes that unit does not exist.
"""
from __future__ import annotations

import ctypes
import errno
import os
import math
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MAX_STREAM_BYTES = 4_194_304
CLEANUP_TIMEOUT_SECONDS = 10.0
READ_CHUNK_BYTES = 65_536
PROCESS_SNAPSHOT_TIMEOUT_SECONDS = 1.0
PROCESS_SNAPSHOT_INTERVAL_SECONDS = 0.25


@dataclass(frozen=True)
class _PosixProcess:
    """One PID identity and lineage observation from the native process table."""

    pid: int
    ppid: int
    pgid: int
    identity: str


class _CleanupUnit:
    """The OS-owned unit used to observe and terminate one process tree."""

    def __init__(self, *, pgid: int, job_handle: int | None = None, setup_error: str | None = None) -> None:
        self.pgid = pgid
        self.job_handle = job_handle
        self.setup_error = setup_error
        self.observed_descendants: dict[int, str] = {}
        self.last_descendant_observation = 0.0

    def close(self) -> None:
        """Close the native cleanup handle after process exit is observed."""
        if os.name != "nt" or self.job_handle is None:
            return
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle(ctypes.c_void_p(self.job_handle))
        except (AttributeError, OSError):
            # The caller already has a fail-closed cleanup result; handle
            # closure is best effort and must not mask it.
            pass
        finally:
            self.job_handle = None


def _windows_job(child: subprocess.Popen) -> tuple[int | None, str | None]:
    """Create and bind a kill-on-close Windows Job Object to *child*."""
    if os.name != "nt":
        return None, None
    try:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None, f"CreateJobObjectW failed: {ctypes.get_last_error()}"
        handle_value = getattr(handle, "value", handle)
        if not handle_value:
            kernel32.CloseHandle(handle)
            return None, "CreateJobObjectW returned an invalid handle"
        value = ExtendedLimitInformation()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. Closing this handle is a bounded
        # final backstop if the explicit termination path races process exit.
        value.BasicLimitInformation.LimitFlags = 0x00002000
        if not kernel32.SetInformationJobObject(handle, 9, ctypes.byref(value), ctypes.sizeof(value)):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            return None, f"SetInformationJobObject failed: {error}"
        if not kernel32.AssignProcessToJobObject(handle, child._handle):
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            return None, f"AssignProcessToJobObject failed: {error}"
        return int(handle_value), None
    except (AttributeError, OSError, TypeError, ValueError) as error:
        return None, f"Windows Job Object setup failed: {error}"


def _posix_group_members(pgid: int) -> set[int] | None:
    """Return live PIDs in *pgid*, or ``None`` when enumeration is unavailable."""
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    try:
        entries = list(proc.iterdir())
    except OSError:
        return None
    members: set[int] = set()
    complete = True
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text(encoding="ascii")
            close = text.rfind(")")
            if close < 0:
                complete = False
                continue
            fields = text[close + 2:].split()
            # After the comm field: state, ppid, pgrp, session, ...
            if len(fields) < 3 or int(fields[2]) != pgid:
                continue
            if fields[0] != "Z":
                members.add(int(entry.name))
        except (OSError, UnicodeDecodeError, ValueError, IndexError):
            complete = False
    return members if complete else None


def _posix_group_status(pgid: int) -> bool | None:
    """Return true when no process remains in a POSIX group."""
    members = _posix_group_members(pgid)
    if members is not None:
        return not members
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return None
    except OSError as error:
        return True if error.errno == errno.ESRCH else None
    return False


def _posix_processes() -> dict[int, _PosixProcess] | None:
    """Read stable-enough native PID lineage for this short-lived invocation."""
    if os.name == "nt":
        return None
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,pgid=,lstart="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=PROCESS_SNAPSHOT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    observed: dict[int, _PosixProcess] = {}
    try:
        for line in result.stdout.splitlines():
            fields = line.split(maxsplit=3)
            if len(fields) != 4:
                return None
            pid, ppid, pgid = (int(value) for value in fields[:3])
            if pid <= 0 or ppid < 0 or pgid <= 0 or not fields[3]:
                return None
            observed[pid] = _PosixProcess(pid, ppid, pgid, fields[3])
    except ValueError:
        return None
    return observed


def _observe_descendants(child: subprocess.Popen, unit: _CleanupUnit, *, force: bool = False) -> None:
    """Record descendants while their parentage still proves invocation ownership."""
    now = time.monotonic()
    if not force and now - unit.last_descendant_observation < PROCESS_SNAPSHOT_INTERVAL_SECONDS:
        return
    unit.last_descendant_observation = now
    processes = _posix_processes()
    if processes is None:
        return
    known = {child.pid}
    # Existing observations may expose a grandchild in the next sample even if
    # its direct parent has already been reaped from the original process tree.
    for pid, identity in unit.observed_descendants.items():
        item = processes.get(pid)
        if item is not None and item.identity == identity:
            known.add(pid)
    while True:
        additions = [item for item in processes.values() if item.pid not in known and item.ppid in known]
        if not additions:
            return
        for item in additions:
            unit.observed_descendants[item.pid] = item.identity
            known.add(item.pid)


def _escaped_descendant_status(unit: _CleanupUnit) -> bool | None:
    """Return false for a still-live observed descendant outside the cleanup group."""
    if os.name == "nt" or not unit.observed_descendants:
        return True
    processes = _posix_processes()
    if processes is None:
        return None
    for pid, identity in unit.observed_descendants.items():
        item = processes.get(pid)
        if item is not None and item.identity == identity and item.pgid != unit.pgid:
            return False
    return True


def _windows_job_active(job_handle: int) -> int | None:
    """Return active process count, or ``None`` if Job Object state is unreadable."""
    if os.name != "nt" or job_handle is None:
        return None
    try:
        from ctypes import wintypes

        class AccountingInformation(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.QueryInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        value = AccountingInformation()
        size = wintypes.DWORD()
        if not kernel32.QueryInformationJobObject(ctypes.c_void_p(job_handle), 1, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(size)):
            return None
        return int(value.ActiveProcesses)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _drain(stream, output: bytearray, failed: threading.Event, limit: int) -> None:
    """Drain a pipe without retaining output beyond its configured byte budget."""
    try:
        while chunk := stream.read(READ_CHUNK_BYTES):
            remaining = limit - len(output)
            output.extend(chunk[:remaining])
            if len(chunk) > remaining:
                failed.set()
                break
    except (OSError, ValueError):
        failed.set()
    finally:
        stream.close()


def _emergency_terminate(child: subprocess.Popen) -> None:
    """Best-effort fallback used when the cleanup unit cannot be created."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=CLEANUP_TIMEOUT_SECONDS,
                           creationflags=subprocess.CREATE_NO_WINDOW, check=False)
        else:
            os.killpg(child.pid, signal.SIGKILL)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        child.wait(timeout=CLEANUP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        try:
            child.kill()
        except OSError:
            pass


def _launch(cli: str, args: list[str], cwd: Path) -> tuple[subprocess.Popen | None, _CleanupUnit | None, str | None]:
    """Start a command and bind it to a process-group or Job Object."""
    options = (
        {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
        if os.name == "nt" else {"start_new_session": True}
    )
    try:
        child = subprocess.Popen([cli, *args], cwd=str(cwd), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    except OSError:
        return None, None, f"{cli} unavailable or could not be started"
    unit = _CleanupUnit(pgid=child.pid)
    if os.name == "nt":
        handle, error = _windows_job(child)
        if handle is None:
            _emergency_terminate(child)
            return None, None, error or "Windows Job Object setup failed"
        unit.job_handle = handle
    return child, unit, None


def _unit_status(child: subprocess.Popen, unit: _CleanupUnit) -> bool | None:
    """Return true only when the root and every observable member have exited."""
    if child.poll() is None:
        return False
    if os.name == "nt":
        active = _windows_job_active(unit.job_handle)
        return None if active is None else active == 0
    return _posix_group_status(unit.pgid)


def _terminate_unit(child: subprocess.Popen, unit: _CleanupUnit) -> bool:
    """Request termination of the bound cleanup unit without unbounded waits."""
    clean = True
    # Take one final lineage snapshot while the root is still alive.  A child
    # can call ``setsid`` immediately after launch; observing it before the
    # group kill preserves the only reliable parentage proof we have before it
    # is reparented.  The snapshot is bounded and failure is handled by the
    # existing fail-closed receipt path.
    _observe_descendants(child, unit, force=True)
    try:
        if os.name == "nt":
            if unit.job_handle is not None:
                from ctypes import wintypes

                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
                kernel32.TerminateJobObject.restype = wintypes.BOOL
                if not kernel32.TerminateJobObject(ctypes.c_void_p(unit.job_handle), 1):
                    clean = False
            else:
                subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=CLEANUP_TIMEOUT_SECONDS,
                               creationflags=subprocess.CREATE_NO_WINDOW, check=False)
                clean = False
        else:
            status = _posix_group_status(unit.pgid)
            if status is not True:
                os.killpg(unit.pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError):
        clean = False
    try:
        if child.poll() is None:
            child.kill()
    except OSError:
        clean = False
    return clean


def _await_cleanup(child: subprocess.Popen, unit: _CleanupUnit, *, terminate: bool) -> bool:
    """Observe root and cleanup-unit exit within the ten-second hard bound."""
    clean = True
    if terminate:
        clean = _terminate_unit(child, unit)
    deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
    while True:
        status = _unit_status(child, unit)
        escaped = _escaped_descendant_status(unit)
        if escaped is not True:
            return False
        if status is True:
            return clean
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _stop(child: subprocess.Popen, unit: _CleanupUnit | None = None) -> bool:
    """Terminate only the bound unit and require observable exit of all members."""
    cleanup = unit or _CleanupUnit(pgid=child.pid)
    status = _unit_status(child, cleanup)
    return _await_cleanup(child, cleanup, terminate=status is not True)


def _monitor(child, unit, readers, failed, heartbeat, deadline: float) -> str:
    """Wait for exit and pipe EOF, checking interruption throughout."""
    while True:
        _observe_descendants(child, unit)
        if failed.is_set():
            return "output limit exceeded or stream read failed"
        if heartbeat is not None and heartbeat() is False:
            return "stop requested through the local Studio"
        if time.monotonic() >= deadline:
            return "stage timed out"
        if child.poll() is not None and not any(reader.is_alive() for reader in readers):
            return ""
        time.sleep(0.05)


def run_cli_detailed(cli: str, args: list[str], cwd: Path, *, heartbeat: Callable[[], bool] | None = None,
                     timeout: float = 300, max_stream_bytes: int = MAX_STREAM_BYTES) -> dict[str, object]:
    """Return a bounded CLI result with an explicit cleanup receipt.

    ``cleanup_confirmed`` is true only after the root process, its captured
    streams and every process observable in the invocation's cleanup unit have
    exited.  The legacy :func:`run_cli` wrapper keeps its two-value API for
    Assembly callers while this structured form lets evidence-producing paths
    distinguish a clean result from an unobservable or escaped descendant.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("positive finite execution deadline required")
    if type(max_stream_bytes) is not int or max_stream_bytes <= 0:
        raise ValueError("positive execution bounds required")
    child, unit, launch_error = _launch(cli, args, cwd)
    if child is None or unit is None:
        return {
            "ok": False,
            "output": launch_error or f"{cli} unavailable or could not be started",
            "cleanup_confirmed": False,
            "streams_closed": False,
            "reason": "launch failed",
            "exit_code": None,
        }
    outputs = [bytearray(), bytearray()]
    failed = threading.Event()
    readers = [threading.Thread(target=_drain, args=(stream, output, failed, max_stream_bytes), daemon=True)
               for stream, output in zip((child.stdout, child.stderr), outputs)]
    for reader in readers:
        reader.start()
    try:
        reason = _monitor(child, unit, readers, failed, heartbeat, time.monotonic() + timeout)
    except BaseException:
        _stop(child, unit)
        unit.close()
        raise
    try:
        return _finish_result(child, unit, readers, outputs, reason)
    finally:
        unit.close()


def run_cli(cli: str, args: list[str], cwd: Path, *, heartbeat: Callable[[], bool] | None = None,
            timeout: float = 300, max_stream_bytes: int = MAX_STREAM_BYTES) -> tuple[bool, str]:
    """Capture a CLI result with finite memory and finite failure cleanup waits."""
    result = run_cli_detailed(cli, args, cwd, heartbeat=heartbeat, timeout=timeout,
                              max_stream_bytes=max_stream_bytes)
    return bool(result["ok"]), str(result["output"])


def _finish_result(child, unit: _CleanupUnit, readers, outputs, reason: str) -> dict[str, object]:
    """Bound cleanup and never return success without observable tree exit."""
    cleanup_confirmed = _stop(child, unit)
    for reader in readers:
        reader.join(timeout=2)
    streams_closed = not any(reader.is_alive() for reader in readers)
    output = b"".join(outputs).decode("utf-8", errors="replace")
    if not streams_closed:
        cleanup_confirmed = False
    if not cleanup_confirmed:
        output = "factory process cleanup could not be confirmed\n" + output
    if reason:
        output = f"factory {reason}\n" + output
    return {
        "ok": not reason and cleanup_confirmed and streams_closed and child.returncode == 0,
        "output": output,
        "cleanup_confirmed": cleanup_confirmed,
        "streams_closed": streams_closed,
        "reason": reason or None,
        "exit_code": child.returncode,
    }


def _finish(child, unit: _CleanupUnit, readers, outputs, reason: str) -> tuple[bool, str]:
    """Compatibility wrapper for callers that use the historical tuple shape."""
    result = _finish_result(child, unit, readers, outputs, reason)
    return bool(result["ok"]), str(result["output"])

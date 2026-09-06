"""Bounded, secret-minimized subprocess supervision; NOT a security sandbox."""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import BinaryIO

MAX_OUTPUT = 8 * 1024 * 1024


def _facts() -> dict:
    empty_hash = hashlib.sha256(b"").hexdigest()
    return {
        "exit_code": None,
        "timed_out": False,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": False,
        "stdout_sha256": empty_hash,
        "stderr_sha256": empty_hash,
    }


def _environment(scratch: Path) -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    home = scratch.resolve() / "runtime-home"
    home.mkdir(parents=True, exist_ok=False)
    environment.update({
        "HOME": str(home), "USERPROFILE": str(home), "TMP": str(home), "TEMP": str(home),
        "TMPDIR": str(home), "PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0",
    })
    return environment


def _launch(argv: list[str], cwd: Path, environment: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        argv,
        cwd=cwd,
        shell=False,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
        creationflags=(subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)
        if os.name == "nt" else 0,
    )


def _stop(child: subprocess.Popen) -> bool:
    cleanup_confirmed = True
    if os.name == "nt":
        # Only the process tree created by this invocation is addressed.
        try:
            stopped = subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
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


def _drain_stream(name: str, stream: BinaryIO, overflow: threading.Event,
                  streams: dict[str, tuple[str, int]]) -> None:
    """Hash one captured stream and retain only its digest and byte count."""
    digest, size = hashlib.sha256(), 0
    try:
        while chunk := stream.read(65536):
            size += len(chunk)
            digest.update(chunk)
            if size > MAX_OUTPUT:
                overflow.set()
    finally:
        streams[name] = (digest.hexdigest(), size)
        stream.close()


def _start_stream_readers(child: subprocess.Popen, overflow: threading.Event,
                          streams: dict[str, tuple[str, int]]) -> list[threading.Thread]:
    threads = [
        threading.Thread(target=_drain_stream, args=(name, stream, overflow, streams), daemon=True)
        for name, stream in (("stdout", child.stdout), ("stderr", child.stderr))
    ]
    for thread in threads:
        thread.start()
    return threads


def _wait_for_exit_or_limit(child: subprocess.Popen, timeout_seconds: int,
                            overflow: threading.Event) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while child.poll() is None and time.monotonic() < deadline and not overflow.is_set():
        time.sleep(0.01)
    return child.poll() is None and time.monotonic() >= deadline


def _join_stream_readers(child: subprocess.Popen, threads: list[threading.Thread],
                         cleanup_confirmed: bool) -> tuple[bool, bool]:
    for thread in threads:
        thread.join(timeout=0.5)
    if any(thread.is_alive() for thread in threads):
        cleanup_confirmed = _stop(child) and cleanup_confirmed
        for thread in threads:
            thread.join(timeout=1)
    streams_closed = not any(thread.is_alive() for thread in threads)
    return cleanup_confirmed, streams_closed


def _await_cleanup(child: subprocess.Popen, threads: list[threading.Thread]) -> tuple[bool, bool]:
    cleanup_confirmed = True
    if child.poll() is None:
        cleanup_confirmed = _stop(child)
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        cleanup_confirmed = False
        _stop(child)
    return _join_stream_readers(child, threads, cleanup_confirmed)


def _cleanup_is_confirmed(child: subprocess.Popen, cleanup_confirmed: bool,
                          streams_closed: bool) -> bool:
    # A Windows taskkill can race an already-exiting supervisor and return a
    # nonzero status even after the inherited streams have closed. Do not turn
    # that transient status into a false failure, but require both the root
    # exit and closed captured streams before accepting cleanup. This remains
    # bounded process supervision, not a sandbox or hidden-descendant proof.
    if os.name == "nt" and not cleanup_confirmed and child.poll() is not None and streams_closed:
        cleanup_confirmed = True
    return cleanup_confirmed and child.poll() is not None and streams_closed


def _stream_facts(facts: dict, streams: dict[str, tuple[str, int]]) -> None:
    empty_hash = hashlib.sha256(b"").hexdigest()
    for name in ("stdout", "stderr"):
        digest, size = streams.get(name, (empty_hash, 0))
        facts[f"{name}_sha256"] = digest
        facts[f"{name}_bytes"] = size


def run_bounded_command(argv: list[str], cwd: Path, timeout_seconds: int, scratch: Path) -> dict:
    """Hash streams without retaining logs; terminate on timeout/output overflow."""
    facts = _facts()
    try:
        child = _launch(argv, cwd, _environment(scratch))
    except OSError:
        return {**facts, "launch_error": True}
    overflow = threading.Event()
    streams: dict[str, tuple[str, int]] = {}
    threads = _start_stream_readers(child, overflow, streams)
    facts["timed_out"] = _wait_for_exit_or_limit(child, timeout_seconds, overflow)
    facts["output_limit_exceeded"] = overflow.is_set()
    cleanup_confirmed, streams_closed = _await_cleanup(child, threads)
    facts["cleanup_confirmed"] = _cleanup_is_confirmed(child, cleanup_confirmed, streams_closed)
    facts["exit_code"] = child.returncode
    _stream_facts(facts, streams)
    facts["output_limit_exceeded"] = overflow.is_set()
    return facts

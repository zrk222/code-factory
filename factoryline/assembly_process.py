"""Bounded CLI output capture; OS cleanup is not a security sandbox."""
from __future__ import annotations

import os
import math
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

MAX_STREAM_BYTES = 4_194_304


def _drain(stream, output: bytearray, failed: threading.Event, limit: int) -> None:
    """Drain a pipe without retaining output beyond its configured byte budget."""
    try:
        while chunk := stream.read(65_536):
            remaining = limit - len(output)
            output.extend(chunk[:remaining])
            if len(chunk) > remaining:
                failed.set()
                break
    except (OSError, ValueError):
        failed.set()
    finally:
        stream.close()


def _stop(child: subprocess.Popen) -> bool:
    """Attempt tree termination and bound all waits; report OS cleanup failures."""
    clean = True
    try:
        if os.name == "nt":
            result = subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
            clean = result.returncode == 0
        else:
            os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except (OSError, subprocess.TimeoutExpired):
        clean = False
    try:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        clean = False
    return clean


def _monitor(child, readers, failed, heartbeat, deadline: float) -> str:
    """Wait for exit and pipe EOF, checking interruption throughout."""
    while True:
        if failed.is_set():
            return "output limit exceeded or stream read failed"
        if heartbeat is not None and heartbeat() is False:
            return "stop requested through the local Studio"
        if time.monotonic() >= deadline:
            return "stage timed out"
        if child.poll() is not None and not any(reader.is_alive() for reader in readers):
            return ""
        time.sleep(0.05)


def run_cli(cli: str, args: list[str], cwd: Path, *, heartbeat: Callable[[], bool] | None = None,
            timeout: float = 300, max_stream_bytes: int = MAX_STREAM_BYTES) -> tuple[bool, str]:
    """Capture a CLI result with finite memory and finite failure cleanup waits."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("positive finite execution deadline required")
    if type(max_stream_bytes) is not int or max_stream_bytes <= 0:
        raise ValueError("positive execution bounds required")
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {"start_new_session": True}
    try:
        child = subprocess.Popen([cli, *args], cwd=str(cwd), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    except OSError:
        return False, f"{cli} unavailable or could not be started"
    outputs = [bytearray(), bytearray()]
    failed = threading.Event()
    readers = [threading.Thread(target=_drain, args=(stream, output, failed, max_stream_bytes), daemon=True)
               for stream, output in zip((child.stdout, child.stderr), outputs)]
    for reader in readers:
        reader.start()
    try:
        reason = _monitor(child, readers, failed, heartbeat, time.monotonic() + timeout)
    except BaseException:
        _stop(child)
        raise
    return _finish(child, readers, outputs, reason)


def _finish(child, readers, outputs, reason: str) -> tuple[bool, str]:
    """Bound cleanup and never return success for an interrupted capture."""
    if reason and not _stop(child):
        reason += "; tree cleanup could not be confirmed"
    for reader in readers:
        reader.join(timeout=2)
    if any(reader.is_alive() for reader in readers):
        return False, "factory stage pipe cleanup could not be confirmed"
    output = b"".join(outputs).decode("utf-8", errors="replace")
    if reason:
        return False, f"factory {reason}\n" + output
    return child.returncode == 0, output

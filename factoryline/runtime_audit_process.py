"""Bounded, secret-minimized subprocess supervision; NOT a security sandbox."""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

MAX_OUTPUT = 8 * 1024 * 1024


def _stop(child: subprocess.Popen) -> bool:
    cleanup_confirmed = True
    if os.name == "nt":
        # Only the process tree created by this invocation is addressed.
        try:
            subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
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


def run_bounded_command(argv: list[str], cwd: Path, timeout_seconds: int, scratch: Path) -> dict:
    """Hash streams without retaining logs; terminate on timeout/output overflow."""
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    home = scratch.resolve() / "runtime-home"
    home.mkdir(parents=True, exist_ok=False)
    environment.update({"HOME": str(home), "USERPROFILE": str(home), "TMP": str(home), "TEMP": str(home),
                        "TMPDIR": str(home), "PYTHONNOUSERSITE": "1", "PYTHONHASHSEED": "0"})
    facts = {"exit_code": None, "timed_out": False, "launch_error": False,
             "output_limit_exceeded": False, "cleanup_confirmed": False,
             "stdout_sha256": hashlib.sha256(b"").hexdigest(), "stderr_sha256": hashlib.sha256(b"").hexdigest()}
    try:
        child = subprocess.Popen(argv, cwd=cwd, shell=False, env=environment,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=os.name != "nt", creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    except OSError:
        return {**facts, "launch_error": True}
    overflow = threading.Event()
    streams: dict[str, tuple[str, int]] = {}

    def drain(name: str, stream) -> None:
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

    threads = [threading.Thread(target=drain, args=(name, stream), daemon=True)
               for name, stream in (("stdout", child.stdout), ("stderr", child.stderr))]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout_seconds
    while child.poll() is None and time.monotonic() < deadline and not overflow.is_set():
        time.sleep(0.01)
    facts["timed_out"] = child.poll() is None and time.monotonic() >= deadline
    facts["output_limit_exceeded"] = overflow.is_set()
    cleanup_confirmed = True
    if child.poll() is None:
        cleanup_confirmed = _stop(child)
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        cleanup_confirmed = False
        _stop(child)
    for thread in threads:
        thread.join(timeout=0.5)
    if any(thread.is_alive() for thread in threads):
        cleanup_confirmed = _stop(child) and cleanup_confirmed
        for thread in threads:
            thread.join(timeout=1)
    facts["cleanup_confirmed"] = cleanup_confirmed and child.poll() is not None and not any(thread.is_alive() for thread in threads)
    facts["exit_code"] = child.returncode
    for name in ("stdout", "stderr"):
        digest, size = streams.get(name, (hashlib.sha256(b"").hexdigest(), 0))
        facts[f"{name}_sha256"] = digest
        facts[f"{name}_bytes"] = size
    facts["output_limit_exceeded"] = overflow.is_set()
    return facts

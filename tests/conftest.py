from collections import deque
import json
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_NODE_TIMEOUT_SECONDS = 20
_NODE_STDOUT_QUEUE_SIZE = 8
_NODE_STDERR_CHUNKS = 16
_NODE_STDERR_CHUNK_BYTES = 1024
_NODE_PROTOCOL_LINE_BYTES = 65536


class NodeIntakeWorkerError(RuntimeError):
    """The shared Node intake worker exited or violated its line protocol."""


class NodeIntakeSession:
    """Reuse one Node module import while revalidating every trial request."""

    def __init__(self, node, module_url, root=ROOT):
        self.node = node
        self.module_url = module_url
        self.root = root
        self.process = None
        self.dead = False
        self.request_id = 0
        self.stdout = queue.Queue(maxsize=_NODE_STDOUT_QUEUE_SIZE)
        self.stdout_eof = threading.Event()
        self.stdout_overflow = threading.Event()
        self.stderr_chunks = deque(maxlen=_NODE_STDERR_CHUNKS)
        self.stderr_lock = threading.Lock()
        self.readers = []

    @property
    def pid(self):
        return None if self.process is None else self.process.pid

    def _worker_script(self):
        return (
            "import { createInterface } from 'node:readline';\n"
            f"import {{ loadTrial }} from {json.dumps(self.module_url)};\n"
            "const send = value => process.stdout.write(`${JSON.stringify(value)}\\n`);\n"
            "const input = createInterface({ input: process.stdin, crlfDelay: Infinity });\n"
            "send({ type: 'ready', protocol: 1 });\n"
            "for await (const line of input) {\n"
            "  let request;\n"
            "  try { request = JSON.parse(line); }\n"
            "  catch { send({ type: 'fatal', code: 'invalid_request_json' }); process.exitCode = 70; break; }\n"
            "  if (!request || request.type !== 'request' || typeof request.id !== 'string' || !Array.isArray(request.args)) {\n"
            "    send({ type: 'fatal', id: request?.id ?? null, code: 'invalid_request' }); process.exitCode = 70; break;\n"
            "  }\n"
            "  try {\n"
            "    await loadTrial(...request.args);\n"
            "    send({ type: 'result', id: request.id, ok: true });\n"
            "  } catch (error) {\n"
            "    const isTrialError = error?.constructor?.name === 'TrialError' && typeof error.code === 'string' && error.code.length > 0;\n"
            "    send({ type: 'result', id: request.id, ok: false, errorType: isTrialError ? 'TrialError' : 'Unexpected',\n"
            "      code: isTrialError ? error.code : null, name: String(error?.name ?? error?.constructor?.name ?? 'Error').slice(0, 128),\n"
            "      message: String(error?.message ?? error).slice(0, 1024),\n"
            "      stack: isTrialError ? undefined : String(error?.stack ?? '').slice(0, 2048) });\n"
            "  }\n"
            "}\n"
        ).replace("\n", " ")

    def _read_stdout(self):
        try:
            while True:
                try:
                    line = self.process.stdout.readline(_NODE_PROTOCOL_LINE_BYTES + 1)
                except (OSError, ValueError):
                    break
                if not line:
                    break
                try:
                    self.stdout.put_nowait(line)
                except queue.Full:
                    self.stdout_overflow.set()
                    break
        finally:
            self.stdout_eof.set()

    def _read_stderr(self):
        while True:
            try:
                chunk = self.process.stderr.read(_NODE_STDERR_CHUNK_BYTES)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            with self.stderr_lock:
                self.stderr_chunks.append(chunk)

    def _stderr_text(self):
        with self.stderr_lock:
            return b"".join(self.stderr_chunks).decode("utf-8", "replace")

    def _start(self, deadline):
        command = [self.node, "--input-type=module", "--eval", self._worker_script()]
        self.command = command
        self.process = subprocess.Popen(
            command,
            cwd=self.root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.readers = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for reader in self.readers:
            reader.start()
        ready = self._next_message(deadline)
        if ready != {"type": "ready", "protocol": 1}:
            self._protocol_failure(f"invalid Node intake READY message: {ready!r}")

    def _next_message(self, deadline):
        while True:
            if self.stdout_overflow.is_set():
                self._protocol_failure("Node intake stdout queue overflow")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._timeout()
            try:
                line = self.stdout.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                if self.stdout_eof.is_set():
                    self._protocol_failure("Node intake worker closed stdout")
                continue
            if len(line) > _NODE_PROTOCOL_LINE_BYTES:
                self._protocol_failure("Node intake protocol line exceeded its bound")
            try:
                message = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                self._protocol_failure(f"invalid Node intake JSON line: {error}")
            if not isinstance(message, dict):
                self._protocol_failure("Node intake response must be an object")
            return message

    def _timeout(self):
        self._abort()
        raise subprocess.TimeoutExpired(
            self.command,
            _NODE_TIMEOUT_SECONDS,
            stderr=self._stderr_text(),
        )

    def _protocol_failure(self, message):
        stderr = self._stderr_text()
        self._abort()
        detail = f"{message}; stderr={stderr[-4096:]}" if stderr else message
        raise NodeIntakeWorkerError(detail)

    def _abort(self):
        self.dead = True
        process = self.process
        if process is None:
            return
        for stream in (process.stdin,):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        self._close_pipes()

    def _close_pipes(self):
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        for reader in self.readers:
            reader.join(timeout=1)

    def run(self, args):
        if self.dead:
            raise NodeIntakeWorkerError(
                "Node intake worker is unavailable; it will not be restarted"
            )
        deadline = time.monotonic() + _NODE_TIMEOUT_SECONDS
        if self.process is None:
            self._start(deadline)
        self.request_id += 1
        request_id = str(self.request_id)
        envelope = {"type": "request", "id": request_id, "args": args}
        try:
            self.process.stdin.write((json.dumps(envelope) + "\n").encode("utf-8"))
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            self._protocol_failure(f"could not send Node intake request: {error}")
        response = self._next_message(deadline)
        if response.get("type") != "result" or response.get("id") != request_id:
            self._protocol_failure(
                f"Node intake response ID/type mismatch: {response!r}"
            )
        if response.get("ok") is True and set(response) == {"type", "id", "ok"}:
            return subprocess.CompletedProcess(self.command, 0, "", "")
        if (
            response.get("ok") is False
            and response.get("errorType") == "TrialError"
            and isinstance(response.get("code"), str)
            and response["code"]
        ):
            detail = f"TrialError: {response['code']}: {response.get('message', '')}"
            return subprocess.CompletedProcess(self.command, 1, "", detail)
        self._protocol_failure(f"unexpected Node intake error response: {response!r}")

    def close(self):
        if self.process is None or self.dead:
            return
        try:
            self.process.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)
        self.dead = True
        self._close_pipes()


@pytest.fixture(scope="session")
def node_trial_session():
    """Provide one no-cache Node intake worker per pytest session/xdist worker."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("public JS intake profile requires Node")
    session = NodeIntakeSession(node, (ROOT / "scripts/evaluate_jev.mjs").as_uri())
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def isolated_ty_host_configuration(monkeypatch, tmp_path_factory):
    """Type-intent fixtures declare their own checker and Git configuration."""
    host = tmp_path_factory.mktemp("ty-host")
    for name in ("HOME", "USERPROFILE", "APPDATA", "XDG_CONFIG_HOME", "ProgramFiles"):
        directory = host / name.lower()
        directory.mkdir()
        monkeypatch.setenv(name, str(directory))
    for name in (
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "TY_CONFIG_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

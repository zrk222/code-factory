"""Bounded, lazily loaded deep, runtime, and senior-audit CLI."""

from __future__ import annotations

import hashlib
import base64
import json
import os
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "deep-audit"
OWNER = "senior-audit-maintainers"


def serve_deep_audit_coordinator(
    root, lease_seconds, session_nonce, input_stream, output_stream
) -> dict:
    """Serve owned signed audits; fresh children wait for verified acknowledgement."""
    import time
    from .agentic_control import CoordinatorRequestStore
    from .assembly_process import _process_identity_absent

    root = Path(root).resolve(strict=True)
    ttl = 300 if lease_seconds is None else lease_seconds
    if type(ttl) is not int or not 1 <= ttl <= 3600:
        raise ValueError("coordinator lease must be an integer from 1 through 3600")
    _coordinator_hex(session_nonce, 32)
    owner = _coordinator_owner(root, session_nonce)
    # Recovery may retire only leases/history whose processes are proven exited.
    store = CoordinatorRequestStore(root, process_absent=_process_identity_absent)
    store.reconcile_expired(time.monotonic())
    lease = store.acquire(owner, ttl, time.monotonic())
    context = dict(store=store, owner=owner, ttl=ttl, stop=False, job=None, root=root)
    context["expires_at"] = lease["expires_monotonic"]
    last = _coordinator_result("OBSERVED", execution_available=False)
    try:
        while not context["stop"]:
            try:
                raw = _coordinator_readline(input_stream, context)
            except (ValueError, OSError) as error:
                last = _coordinator_result(
                    "INCOMPLETE", code=getattr(error, "code", "E_COORDINATOR_INPUT")
                )
                _coordinator_emit(output_stream, last)
                break
            if not raw:
                break
            try:
                request = _coordinator_line(raw)
                last = dispatch_deep_audit_request(root, request, owner, context)
                _coordinator_renew(context, activity=True)
            except (ValueError, TypeError, KeyError, OSError) as error:
                last = _coordinator_result(
                    "INCOMPLETE", code=getattr(error, "code", "E_COORDINATOR_REQUEST")
                )
            _coordinator_emit(output_stream, last)
            if len(_coordinator_encoded(raw)) > 65536:
                break
    finally:
        if _coordinator_shutdown(context):
            store.release(owner)
        else:
            last = _coordinator_result("INCOMPLETE", code="E_COORDINATOR_CLEANUP")
            _coordinator_emit(output_stream, last)
    return last


def _coordinator_emit(stream, value):
    stream.write(json.dumps(value, sort_keys=True) + "\n")
    stream.flush()


def _coordinator_readline(stream, context):
    import io
    import time
    from .agentic_control import AgenticControlError

    buffer = context.setdefault("input_buffer", bytearray())
    while True:
        _coordinator_renew(context)
        if time.monotonic() >= context["expires_at"]:
            raise AgenticControlError(
                "E_COORDINATOR_LEASE_EXPIRED", "input lease expired"
            )
        if isinstance(stream, (io.BytesIO, io.StringIO)):
            return stream.readline(65537)
        if not isinstance(stream, io.FileIO):
            raise ValueError(
                "coordinator input requires exclusive unbuffered ownership"
            )
        end = buffer.find(b"\n") + 1
        if end or len(buffer) >= 65537:
            end = end or len(buffer)
            line = bytes(buffer[:end])
            del buffer[:end]
            return line
        chunk = _coordinator_input_chunk(stream.fileno(), 65537 - len(buffer), context)
        if chunk is None:
            continue
        if not chunk:
            line = bytes(buffer)
            buffer.clear()
            return line
        buffer.extend(chunk)


def _coordinator_renew(context, activity=False):
    """Renew the exact live owner while auditing or on accepted requests.

    Idle sessions still expire one TTL after their last request. Renewal never
    revives an expired lease; contention is retried on the next poll.
    """
    import time
    from .agentic_control import AgenticControlError

    ttl, job = context.get("ttl"), context.get("job")
    active = job is not None and job["thread"].is_alive()
    now = time.monotonic()
    if ttl is None or context["stop"] or not (activity or active):
        return
    if now >= context["expires_at"] or context["expires_at"] - now > ttl / 2:
        return
    try:
        lease = context["store"].acquire(context["owner"], ttl, now)
    except AgenticControlError:
        return
    context["expires_at"] = lease["expires_monotonic"]


def _coordinator_input_chunk(fd, capacity, context):
    import os
    import stat
    import time

    if stat.S_ISREG(os.fstat(fd).st_mode):
        return os.read(fd, min(capacity, 4096))
    if os.name == "nt":
        available = _coordinator_windows_pipe_bytes(fd)
        if available < 0:
            return b""
        if available:
            return os.read(fd, min(available, capacity, 4096))
        time.sleep(min(0.05, max(0, context["expires_at"] - time.monotonic())))
        return None
    import select

    remaining = max(0, context["expires_at"] - time.monotonic())
    try:
        ready, _, _ = select.select([fd], [], [], min(0.05, remaining))
    except InterruptedError:
        return None
    return os.read(fd, min(capacity, 4096)) if ready else None


def _coordinator_windows_pipe_bytes(fd):
    import ctypes
    import msvcrt
    from ctypes import wintypes

    handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    if kernel.GetFileType(handle) != 3:  # FILE_TYPE_PIPE, not an interactive console.
        raise ValueError("coordinator input requires a pipe or regular file")
    kernel.PeekNamedPipe.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel.PeekNamedPipe.restype = wintypes.BOOL
    available = wintypes.DWORD()
    if kernel.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
        return available.value
    error = ctypes.get_last_error()
    if error in (109, 233):  # Broken/disconnected pipe means EOF.
        return -1
    raise OSError(error, "coordinator input pipe observation failed")


def dispatch_deep_audit_request(
    root, request, owner_identity, execution_context
) -> dict:
    """Validate intent and live ownership before any admission or process creation."""
    _coordinator_request(root, request)
    _coordinator_check_owner(root, request, owner_identity, execution_context)
    execution_context.setdefault("root", Path(root))
    if request["operation"] == "stop":
        execution_context["stop"] = True
        clean = _coordinator_shutdown(execution_context)
        return _coordinator_result(
            "STOPPED" if clean else "INCOMPLETE",
            request_id=request["request_id"],
            cleanup_confirmed=clean,
        )
    if request["operation"] == "status":
        return _coordinator_status(request, execution_context)
    return _coordinator_admit(root, request, owner_identity, execution_context)


def _coordinator_result(state, **fields):
    return dict(
        schema="factory.deep-audit-coordinator.v1",
        state=state,
        authority="none",
        release_approval=False,
        **fields,
    )


def _coordinator_hex(value, length):
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError("invalid coordinator identity")


def _coordinator_line(raw):
    from .deep_audit_io import strict_json

    encoded = _coordinator_encoded(raw)
    if not isinstance(encoded, bytes) or not 1 <= len(encoded) <= 65536:
        raise ValueError("coordinator line exceeds byte boundary")
    return strict_json(encoded)


def _coordinator_encoded(raw):
    return raw.encode("utf-8") if isinstance(raw, str) else raw


def _coordinator_request(root, request):
    if not isinstance(request, dict):
        raise ValueError("coordinator request must be an object")
    required = {"version", "operation", "workspace", "session_nonce", "request_id"}
    operation = request.get("operation")
    if not isinstance(operation, str) or operation not in {"audit", "status", "stop"}:
        raise ValueError("unknown coordinator operation")
    _coordinator_envelope(request, required, operation)
    for key in ("session_nonce", "request_id"):
        _coordinator_hex(request[key], 32)
    if not isinstance(request["workspace"], str) or request["workspace"] != str(
        Path(root).resolve(strict=True)
    ):
        raise ValueError("coordinator workspace differs")
    if operation == "audit":
        _coordinator_payload_shape(request["payload"])


def _coordinator_envelope(request, required, operation):
    allowed = required | ({"payload"} if operation == "audit" else set())
    if (
        set(request) != allowed
        or type(request["version"]) is not int
        or request["version"] != 1
    ):
        raise ValueError("invalid coordinator request schema")


def _coordinator_payload(root, payload):
    from .deep_audit_io import local_file

    _coordinator_payload_shape(payload)
    for name in ("manifest", "authorization", "trust_root"):
        local_file(Path(root), payload[name])


def _coordinator_payload_shape(payload):
    from .deep_audit_io import relative_path

    expected = {
        "manifest",
        "manifest_sha256",
        "authorization",
        "trust_root",
        "trust_root_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("coordinator audit payload must bind the existing signed scan")
    for name in ("manifest_sha256", "trust_root_sha256"):
        _coordinator_hex(payload[name], 64)
    for name in ("manifest", "authorization", "trust_root"):
        relative_path(payload[name])


def _coordinator_python_executable():
    if os.name == "nt" and sys.prefix != sys.base_prefix:
        return sys._base_executable
    return sys.executable


def _coordinator_worker_launch():
    executable = _coordinator_python_executable()
    # A Windows venv redirector spawns a second PID. Start the real interpreter
    # with Python's own venv marker so the observed PID is the signed worker.
    env = (
        {**os.environ, "__PYVENV_LAUNCHER__": sys.executable}
        if executable != sys.executable
        else None
    )
    return executable, env


def _coordinator_runtime_identity():
    # Bind loaded bodies, not merely a source file which could change after import.
    # Marshal encodings can change reference flags after first execution; only
    # normalized executable code fields belong in this in-process identity.
    from . import (
        agentic_control,
        assembly_process,
        deep_audit,
        deep_audit_attestation,
        deep_audit_contract,
        deep_audit_io,
        deep_audit_sarif,
        enterprise_receipts,
        ops_telemetry,
        runtime_audit_common,
        runtime_audit_process,
    )

    modules = (
        sys.modules[__name__],
        deep_audit,
        deep_audit_attestation,
        deep_audit_contract,
        deep_audit_io,
        agentic_control,
        assembly_process,
        runtime_audit_process,
        deep_audit_sarif,
        enterprise_receipts,
        runtime_audit_common,
        ops_telemetry,
    )
    loaded = [_coordinator_loaded_identity(module) for module in modules]
    paths = dict.fromkeys((sys.executable, _coordinator_python_executable()))
    executables = [
        [str(Path(path).resolve()), hashlib.sha256(Path(path).read_bytes()).hexdigest()]
        for path in paths
    ]
    identity = [sys.version, executables, loaded]
    return hashlib.sha256(json.dumps(identity).encode()).hexdigest()


def _coordinator_loaded_identity(module):
    entries = []
    for name, value in sorted(vars(module).items()):
        if getattr(value, "__module__", None) != module.__name__:
            continue
        members = vars(value).items() if isinstance(value, type) else [("", value)]
        for member, body in sorted(members):
            body = getattr(body, "__func__", body)
            if hasattr(body, "__code__"):
                entries.append(
                    (name + "." + member, _coordinator_callable_identity(body))
                )
    return [module.__name__, entries]


def _coordinator_callable_identity(body):
    return [
        _coordinator_code_identity(body.__code__),
        _coordinator_constant(body.__defaults__),
        _coordinator_constant(body.__kwdefaults__),
        [_coordinator_constant(cell.cell_contents) for cell in body.__closure__ or ()],
    ]


def _coordinator_code_identity(code):
    return [
        code.co_code.hex(),
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_flags,
        code.co_names,
        code.co_varnames,
        code.co_freevars,
        code.co_cellvars,
        getattr(code, "co_exceptiontable", b"").hex(),
        [_coordinator_constant(value) for value in code.co_consts],
    ]


def _coordinator_constant(value):
    from types import CodeType

    if isinstance(value, CodeType):
        return ["code", _coordinator_code_identity(value)]
    if isinstance(value, tuple):
        return ["tuple", [_coordinator_constant(item) for item in value]]
    if isinstance(value, (set, frozenset)):
        return [
            type(value).__name__,
            sorted(json.dumps(_coordinator_constant(item)) for item in value),
        ]
    if isinstance(value, dict):
        return [
            "dict",
            sorted(
                (str(key), _coordinator_constant(item)) for key, item in value.items()
            ),
        ]
    if isinstance(value, list):
        return ["list", [_coordinator_constant(item) for item in value]]
    if hasattr(value, "__code__"):
        return [
            "callable",
            value.__module__,
            value.__qualname__,
            _coordinator_code_identity(value.__code__),
        ]
    if isinstance(value, type):
        return ["type", value.__module__, value.__qualname__]
    if type(value).__module__ == "dataclasses":
        return ["dataclasses", type(value).__name__, repr(value)]
    if type(value) not in (
        str,
        int,
        float,
        bool,
        bytes,
        complex,
        type(None),
        type(Ellipsis),
    ):
        raise ValueError("unsupported loaded coordinator constant")
    return [type(value).__name__, repr(value)]


def _coordinator_owner(root, session_nonce, runtime_sha256=None):
    import os
    from .assembly_process import _process_creation_identity

    creation = _process_creation_identity(os.getpid())
    if creation is None:
        raise ValueError("coordinator process creation identity is unavailable")
    return dict(
        pid=os.getpid(),
        creation=creation,
        session_nonce=session_nonce,
        runtime_sha256=runtime_sha256 or _coordinator_runtime_identity(),
        workspace_sha256=hashlib.sha256(
            str(Path(root).resolve(strict=True)).encode()
        ).hexdigest(),
    )


def _coordinator_check_owner(root, request, owner, context):
    import time

    expiry = context.get("expires_at")
    if type(expiry) not in (int, float) or not 0 < expiry < float("inf"):
        raise ValueError("invalid coordinator expiry")
    # Cheap native identity per request; loaded-runtime hashing is reserved for
    # admission and handshake preflight, which compare it to owner exactly.
    runtime = owner.get("runtime_sha256") if isinstance(owner, dict) else None
    if (
        owner != _coordinator_owner(root, request["session_nonce"], runtime)
        or context.get("stop") is not False
        or time.monotonic() >= expiry
    ):
        raise ValueError("coordinator owner is missing, stale or differs")
    context["store"].check_owner(owner, time.monotonic())


def _coordinator_identity_view(snapshot):
    """Signed/package/runtime identity without the per-call source inventory digest."""
    return {key: value for key, value in snapshot.items() if key != "inventory_sha256"}


def _coordinator_preflight(root, payload, inventory=True):
    from .deep_audit_contract import load_execution_manifest
    from .deep_audit_attestation import verify_execution_authorization
    from .deep_audit_io import (
        inventory_candidate,
        local_file,
        digest,
        _full_repository_scanner_identity,
    )

    _coordinator_payload(root, payload)
    paths = {
        name: local_file(root, payload[name])
        for name in ("manifest", "authorization", "trust_root")
    }
    plan = load_execution_manifest(
        paths["manifest"],
        payload["manifest_sha256"],
        candidate_root=root,
    )
    _, authorization = verify_execution_authorization(
        plan,
        payload["manifest_sha256"],
        paths["authorization"],
        paths["trust_root"],
        payload["trust_root_sha256"],
        return_envelope_sha256=True,
    )
    if not inventory:
        # Source drift is still rejected by the admission and post-ACK full
        # inventories and by the signed scan's own snapshot comparison.
        return dict(
            scanner_sha256=_full_repository_scanner_identity(),
            candidate_sha256=plan["candidate_sha256"],
            plan_sha256=digest(plan),
            authorization_sha256=authorization,
            runtime_sha256=_coordinator_runtime_identity(),
        )
    inventory = inventory_candidate(root)
    bound_plan = load_execution_manifest(
        paths["manifest"],
        payload["manifest_sha256"],
        inventory=inventory,
        candidate_root=root,
    )
    if bound_plan != plan:
        raise ValueError("signed execution plan changed during preflight")
    if (
        inventory["state"] != "COMPLETE"
        or inventory["candidate_sha256"] != plan["candidate_sha256"]
    ):
        raise ValueError("signed candidate inventory differs")
    return dict(
        scanner_sha256=_full_repository_scanner_identity(),
        candidate_sha256=inventory["candidate_sha256"],
        inventory_sha256=digest(inventory),
        plan_sha256=digest(plan),
        authorization_sha256=authorization,
        runtime_sha256=_coordinator_runtime_identity(),
    )


def _coordinator_status(request, context):
    fields = dict(request_id=request["request_id"], execution_available=False)
    if (job := context.get("job")) is not None:
        row = context["store"].read(request["session_nonce"], job["request_id"])
        fields.update(
            audit_request_id=row["request_id"],
            audit_state=row["state"],
            run_id=row["run_id"],
            cleanup_confirmed=row["cleanup_confirmed"],
            phase_timings=job.get("phase_timings"),
        )
    return _coordinator_result("OBSERVED", **fields)


def _coordinator_admit(root, request, owner, context):
    import threading
    from .agentic_control import AgenticControlError
    from .deep_audit_io import digest

    seal = digest(request)
    try:
        row = context["store"].read(request["session_nonce"], request["request_id"])
    except AgenticControlError as exc:
        if getattr(exc, "code", None) != "E_COORDINATOR_REQUEST":
            raise
    else:
        if row["request_sha256"] != seal:
            raise AgenticControlError(
                "E_COORDINATOR_REQUEST", "request identifier is already bound"
            )
        if row["owner_identity"] != owner:
            raise AgenticControlError("E_COORDINATOR_OWNER", "request owner differs")
        return _coordinator_result(
            row["state"],
            request_id=row["request_id"],
            run_id=row["run_id"],
            cleanup_confirmed=row["cleanup_confirmed"],
        )

    active = context.get("job")
    if (
        active is not None
        and active["thread"].is_alive()
        and active["request_id"] != request["request_id"]
    ):
        raise AgenticControlError(
            "E_COORDINATOR_BUSY", "retained request is still active"
        )
    snapshot = _coordinator_preflight(root, request["payload"])
    if snapshot["runtime_sha256"] != owner["runtime_sha256"]:
        raise ValueError("loaded runtime differs")
    _coordinator_live_lease(root, request, owner, context)
    row = context["store"].admit(
        request["session_nonce"], request["request_id"], seal, owner
    )
    if not row["created"]:
        return _coordinator_result(
            row["state"], request_id=row["request_id"], run_id=row["run_id"]
        )
    job = dict(
        request_id=request["request_id"],
        request_sha256=seal,
        snapshot=snapshot,
        cancel=threading.Event(),
        observed=None,
        run_id=None,
        cleanup_confirmed=False,
        acknowledged=False,
        launch_attempted=False,
    )
    thread = threading.Thread(
        target=_coordinator_execute,
        args=(root, request, owner, context, job),
        daemon=True,
    )
    job["thread"] = thread
    context["job"] = job
    try:
        thread.start()
    except RuntimeError:
        context["store"].abandon(
            request["session_nonce"], request["request_id"], seal, True
        )
        job["cleanup_confirmed"] = True
        raise
    return _coordinator_result("ADMITTED", request_id=request["request_id"])


def _coordinator_control_directory(root):
    import tempfile
    import stat

    current = Path(root).resolve(strict=True)
    for name in (".factory", "deep-runs", "requests"):
        current /= name
        current.mkdir(mode=0o700, exist_ok=True)
        info = current.lstat()
        if (
            current.is_symlink()
            or getattr(info, "st_file_attributes", 0) & 0x400
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise ValueError("linked coordinator control directory")
    return Path(tempfile.mkdtemp(prefix="coordinator-", dir=current))


def _coordinator_control_path(root, directory):
    from .runtime_audit_process import path_chain_has_no_links

    base = Path(root).resolve(strict=True)
    path = Path(directory)
    if path.parent != base / ".factory/deep-runs/requests" or not path.name.startswith(
        "coordinator-"
    ):
        raise ValueError("invalid coordinator control path")
    if not path_chain_has_no_links(base, path) or not path.is_dir():
        raise ValueError("unverified coordinator control path")
    return path


def _coordinator_write(root, directory, name, value):
    from .deep_audit_io import write_run_json

    write_run_json(_coordinator_control_path(root, directory), name, value)


def _coordinator_read(root, directory, name):
    from .deep_audit_io import read_run_json

    return read_run_json(_coordinator_control_path(root, directory), name)


def _coordinator_bootstrap():
    package = str(Path(__file__).resolve().parent.parent)
    return (
        "import sys;sys.path.insert(0," + repr(package) + ");"
        "from factoryline.cli_deep_audit import _coordinator_worker;"
        "_coordinator_worker(sys.argv[1],sys.argv[2],sys.argv[3])"
    )


def _coordinator_worker_args(root, directory, config):
    from .deep_audit_io import canonical_bytes

    raw = canonical_bytes(config)
    if len(raw) > 8192:
        raise ValueError("coordinator transient argument budget exceeded")
    args = [
        "-I",
        "-c",
        _coordinator_bootstrap(),
        str(root),
        str(directory),
        base64.urlsafe_b64encode(raw).decode("ascii"),
    ]
    if sum(len(arg) + 3 for arg in args) > 30000:
        raise ValueError("coordinator native command boundary exceeded")
    return args


def _coordinator_execute(root, request, owner, context, job):
    from .ops_telemetry import _phase_telemetry

    with _phase_telemetry(0) as telemetry:
        try:
            _coordinator_execute_job(root, request, owner, context, job)
        finally:
            snapshot = telemetry.snapshot()
            job["phase_timings"] = {
                key: snapshot[key]
                for key in ("status", "phases", "dropped_calls", "dropped_phase_names")
            }
            if not snapshot["phases"]:
                job["phase_timings"]["status"] = "not_observed"


def _coordinator_execute_job(root, request, owner, context, job):
    import time
    from .assembly_process import CLEANUP_TIMEOUT_SECONDS, run_cli_detailed

    directory, result = None, None
    try:
        # Start with a full renewal window so the ACK deadline is not near expiry.
        _coordinator_renew(context, activity=True)
        directory = _coordinator_control_directory(root)
        job["directory"] = directory
        config = dict(
            request=request,
            request_sha256=job["request_sha256"],
            snapshot=job["snapshot"],
            expires_at=context["expires_at"],
        )
        args = _coordinator_worker_args(root, directory, config)
        _coordinator_check_owner(root, request, owner, context)
        remaining = context["expires_at"] - time.monotonic()
        if remaining <= 0:
            raise ValueError("coordinator lease expired before launch")
        job["launch_attempted"] = True
        executable, child_env = _coordinator_worker_launch()
        result = run_cli_detailed(
            executable,
            args,
            root,
            timeout=remaining + CLEANUP_TIMEOUT_SECONDS,
            env=child_env,
            started_observer=lambda facts: _coordinator_launched(
                request, context, job, facts
            ),
            heartbeat=lambda: _coordinator_heartbeat(
                root, request, owner, context, job
            ),
        )
        job["cleanup_confirmed"] = (
            result["cleanup_confirmed"] is True
            and result["streams_closed"] is True
            and not job.get("cancel_hard_kill")
            and (not job["acknowledged"] or result["exit_code"] == 0)
        )
    except (ValueError, OSError, KeyError, TypeError, RuntimeError):
        job["cleanup_confirmed"] = not job["launch_attempted"]
    finally:
        _coordinator_settle(root, request, context, job, directory, result)


def _coordinator_launched(request, context, job, facts):
    # Persist the observed child before monitoring so crash recovery can prove
    # its exit; failure propagates and run_cli_detailed cleans up the launch.
    job.update(observed=facts)
    if facts.get("creation") is not None:
        context["store"].launched(
            request["session_nonce"],
            request["request_id"],
            job["request_sha256"],
            dict(facts),
        )


def _coordinator_settle(root, request, context, job, directory, result):
    try:
        phase = "lineage"
        _coordinator_bind_interrupted(root, request, context, job)
        phase = "completion_evidence"
        complete = _coordinator_completed(root, job, result)
        phase = "control_cleanup"
        if directory is not None and job["cleanup_confirmed"]:
            _coordinator_remove_control(root, directory)
        phase = "terminal_metadata"
        if job["run_id"] is None:
            _coordinator_record_failure(request, context, job)
        else:
            context["store"].finish(
                request["session_nonce"],
                request["request_id"],
                job["request_sha256"],
                job["run_id"],
                "COMPLETE" if complete else "INCOMPLETE",
                job["cleanup_confirmed"],
            )
    except (ValueError, OSError, KeyError, TypeError, RuntimeError) as error:
        job["failure_phase"] = phase
        job["failure_code"] = type(error).__name__
        job["cleanup_confirmed"] = False
        _coordinator_record_failure(request, context, job)


def _coordinator_bind_interrupted(root, request, context, job):
    # Preserve observed lineage after owned termination; this never writes ACK
    # or authorizes execution based on a dead or reused PID.
    directory = job.get("directory")
    if (
        job["run_id"] is not None
        or not job["cleanup_confirmed"]
        or directory is None
        or not (directory / "handshake.json").exists()
    ):
        return
    handshake = _coordinator_read(root, directory, "handshake.json")
    _coordinator_verify_handshake(request, job, handshake)
    row = context["store"].read(request["session_nonce"], request["request_id"])
    observed = job["observed"]
    expected = dict(
        row["owner_identity"], pid=observed["pid"], creation=observed["creation"]
    )
    if observed["creation"] is None or handshake["worker_identity"] != expected:
        raise ValueError("interrupted worker lineage differs")
    context["store"].bind(
        request["session_nonce"],
        request["request_id"],
        job["request_sha256"],
        handshake["run_id"],
        expected,
    )
    job["run_id"] = handshake["run_id"]


def _coordinator_worker(root, directory, encoded):
    """Fixed fresh child entry; no caller-selected executable or run UUID."""
    import time
    from .deep_audit import scan_deep_audit
    from .deep_audit_io import local_file, digest, strict_json

    root = Path(root).resolve(strict=True)
    if not isinstance(encoded, str) or len(encoded) > 10924:
        raise ValueError("worker transient argument budget exceeded")
    config = strict_json(base64.b64decode(encoded, altchars=b"-_", validate=True))
    if set(config) != {"request", "request_sha256", "snapshot", "expires_at"}:
        raise ValueError("worker input fields differ")
    request = config["request"]
    _coordinator_request(root, request)
    if digest(request) != config["request_sha256"]:
        raise ValueError("worker request differs")
    identity = _coordinator_preflight(root, request["payload"], inventory=False)
    if identity != _coordinator_identity_view(config["snapshot"]):
        raise ValueError("worker source or runtime differs")
    if time.monotonic() >= config["expires_at"]:
        raise ValueError("worker lease expired")
    payload = request["payload"]
    result = scan_deep_audit(
        root,
        local_file(root, payload["manifest"]),
        payload["manifest_sha256"],
        authorization=local_file(root, payload["authorization"]),
        trust_root=local_file(root, payload["trust_root"]),
        trust_root_sha256=payload["trust_root_sha256"],
        emit=lambda event: _coordinator_worker_event(root, directory, config, event),
    )
    _coordinator_write(
        root,
        directory,
        "done.json",
        dict(
            run_id=result["run_id"],
            analysis_complete=result.get("analysis_complete") is True,
        ),
    )


def _coordinator_worker_event(root, directory, config, event):
    import time
    from .deep_audit_io import digest

    if event["kind"] != "run_started":
        return
    request = config["request"]
    identity = _coordinator_owner(root, request["session_nonce"])
    handshake = dict(
        worker_identity=identity,
        run_id=event["run_id"],
        request_id=request["request_id"],
        request_sha256=config["request_sha256"],
        snapshot=config["snapshot"],
    )
    _coordinator_hex(event["run_id"], 32)
    _coordinator_write(root, directory, "handshake.json", handshake)
    while time.monotonic() < config["expires_at"]:
        if (Path(directory) / "ack.json").exists():
            ack = _coordinator_read(root, directory, "ack.json")
            if ack != dict(handshake_sha256=digest(handshake)):
                raise ValueError("worker acknowledgement differs")
            if _coordinator_preflight(root, request["payload"]) != config["snapshot"]:
                raise ValueError("worker inputs drifted before execution")
            if time.monotonic() >= config["expires_at"]:
                raise ValueError("worker lease expired before execution")
            return
        time.sleep(0.05)
    raise ValueError("worker acknowledgement lease expired")


def _coordinator_heartbeat(root, request, owner, context, job):
    import time
    from .assembly_process import CLEANUP_TIMEOUT_SECONDS

    try:
        if job["cancel"].is_set():
            return _coordinator_cancel_grace(job, time.monotonic())
        _coordinator_live_lease(root, request, owner, context)
        if job["acknowledged"]:
            return True
        directory = job["directory"]
        if not (directory / "handshake.json").exists():
            return True
        return _coordinator_handshake(root, request, owner, context, job)
    except (ValueError, OSError, KeyError, TypeError):
        _coordinator_begin_cancel(root, job, CLEANUP_TIMEOUT_SECONDS)
        return _coordinator_cancel_grace(job, time.monotonic())


def _coordinator_cancel_grace(job, now):
    if job.get("cancel_hard_kill") or now >= job.get("cancel_deadline", 0):
        if job.get("acknowledged"):
            job["cancel_hard_kill"] = True
        return False
    return True


def _coordinator_begin_cancel(root, job, grace_seconds):
    import time

    job["cancel"].set()
    if "cancel_deadline" in job:
        return
    job["cancel_deadline"] = time.monotonic() + grace_seconds
    if not job.get("acknowledged") or not job.get("run_id"):
        job["cancel_deadline"] = 0
        return
    try:
        from .deep_audit import cancel_deep_run

        result = cancel_deep_run(root, job["run_id"])
        if result.get("state") not in {
            "CANCELLATION_REQUESTED",
            "ALREADY_STOPPED",
        }:
            job["cancel_hard_kill"] = True
    except Exception:
        job["cancel_hard_kill"] = True


def _coordinator_live_lease(root, request, owner, context):
    import os
    import time
    from .assembly_process import _process_creation_identity

    if (
        context["stop"]
        or time.monotonic() >= context["expires_at"]
        or owner["pid"] != os.getpid()
        or owner["creation"] != _process_creation_identity(owner["pid"])
        or owner["session_nonce"] != request["session_nonce"]
        or request["workspace"] != str(root)
    ):
        raise ValueError("coordinator live ownership differs")
    context["store"].check_owner(owner, time.monotonic())


def _coordinator_handshake(root, request, owner, context, job):
    from .assembly_process import _process_creation_identity
    from .deep_audit_io import digest

    handshake = _coordinator_read(root, job["directory"], "handshake.json")
    worker = handshake["worker_identity"]
    observed = job["observed"]
    expected = dict(owner, pid=observed["pid"], creation=observed["creation"])
    if worker != expected or observed["creation"] is None:
        raise ValueError("worker native identity differs")
    if _process_creation_identity(observed["pid"]) != observed["creation"]:
        raise ValueError("worker native identity is stale")
    _coordinator_verify_handshake(request, job, handshake)
    # Package/runtime hashing without a second source inventory inside the
    # heartbeat; the worker's post-ACK full preflight still gates every lane.
    identity = _coordinator_preflight(root, request["payload"], inventory=False)
    if identity != _coordinator_identity_view(job["snapshot"]):
        raise ValueError("signed inputs or runtime drifted")
    _coordinator_live_lease(root, request, owner, context)
    row = context["store"].bind(
        request["session_nonce"],
        request["request_id"],
        job["request_sha256"],
        handshake["run_id"],
        worker,
    )
    job["run_id"] = row["run_id"]
    # Mark possible execution before publishing ACK to the independently running child.
    job["acknowledged"] = True
    _coordinator_write(
        root, job["directory"], "ack.json", dict(handshake_sha256=digest(handshake))
    )
    return True


def _coordinator_verify_handshake(request, job, handshake):
    expected = {"worker_identity", "run_id", "request_id", "request_sha256", "snapshot"}
    if set(handshake) != expected:
        raise ValueError("worker handshake fields differ")
    _coordinator_hex(handshake["run_id"], 32)
    if (
        handshake["request_id"],
        handshake["request_sha256"],
        handshake["snapshot"],
    ) != (request["request_id"], job["request_sha256"], job["snapshot"]):
        raise ValueError("worker handshake binding differs")


def _coordinator_completed(root, job, result):
    if (
        job["run_id"] is None
        or result is None
        or result["exit_code"] != 0
        or not job["cleanup_confirmed"]
        or not job["acknowledged"]
    ):
        return False
    done = _coordinator_read(root, job["directory"], "done.json")
    if set(done) != {"run_id", "analysis_complete"} or done["run_id"] != job["run_id"]:
        raise ValueError("worker completion run differs")
    from .deep_audit import deep_run_status

    evidence = deep_run_status(root, job["run_id"])
    if any("CLEANUP" in str(gap.get("code", "")) for gap in evidence.get("gaps", [])):
        raise ValueError("owned audit resource cleanup is incomplete")
    return (
        done["analysis_complete"] is True and evidence.get("analysis_complete") is True
    )


def _coordinator_record_failure(request, context, job):
    store = context["store"]
    args = (request["session_nonce"], request["request_id"], job["request_sha256"])
    if job["run_id"] is None:
        store.abandon(*args, job["cleanup_confirmed"])
    else:
        store.finish(*args, job["run_id"], "INCOMPLETE", job["cleanup_confirmed"])


def _coordinator_remove_control(root, directory):
    import time
    from .assembly_process import CLEANUP_TIMEOUT_SECONDS

    deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
    while True:
        try:
            _coordinator_unlink_control(root, directory)
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def _coordinator_unlink_control(root, directory):
    directory = _coordinator_control_path(root, directory)
    from .deep_audit_io import local_file

    for name in ("handshake.json", "ack.json", "done.json"):
        path = directory / name
        if path.exists() or path.is_symlink():
            local_file(directory, name).unlink()
    directory.rmdir()


def _coordinator_cancel(context):
    job = context.get("job")
    if job is not None:
        from .assembly_process import CLEANUP_TIMEOUT_SECONDS

        _coordinator_begin_cancel(context.get("root"), job, CLEANUP_TIMEOUT_SECONDS)


def _coordinator_shutdown(context):
    from .assembly_process import CLEANUP_TIMEOUT_SECONDS

    _coordinator_cancel(context)
    job = context.get("job")
    if job is None:
        return True
    job["thread"].join(timeout=CLEANUP_TIMEOUT_SECONDS * 2)
    return not job["thread"].is_alive() and job["cleanup_confirmed"] is True


def add_parser(sub: Any) -> None:
    """Register senior-audit commands without loading audit engines."""
    deep = sub.add_parser(
        "deep-audit",
        help="evaluate signed analyzer evidence or read local repair guidance; never release approval",
    )
    deep_sub = deep.add_subparsers(required=True, dest="deep_cmd")
    coordinator = deep_sub.add_parser(
        "coordinator",
        help="serve opt-in foreground signed audit requests over owned raw stdin",
    )
    coordinator.add_argument("--root", default=".")
    coordinator.add_argument("--session-nonce", required=True)
    coordinator.add_argument("--lease-seconds", type=int, default=300)
    blade = deep_sub.add_parser(
        "blade-structure", help="account for Blade echo expression spans"
    )
    blade.add_argument("source", type=Path)
    blade.add_argument("--grammar-dir", type=Path, required=True)
    blade.add_argument("--json", action="store_true")
    _add_execution_parsers(deep_sub)
    for action in ("evaluate", "status", "compare", "attestation"):
        command = deep_sub.add_parser(action)
        command.add_argument("--root", default=".")
        command.add_argument("--json", action="store_true")
        if action == "compare":
            command.add_argument("--before", required=True)
            command.add_argument("--after", required=True)
            command.add_argument("--before-attestation")
            command.add_argument("--after-attestation")
            command.add_argument("--trust-root")
            command.add_argument("--require-attestation", action="store_true")
            command.add_argument("--max-age-seconds", type=int, default=3600)
        if action == "attestation":
            command.add_argument("attestation")
            command.add_argument("--receipt", required=True)
            command.add_argument("--trust-root", required=True)
            command.add_argument("--max-age-seconds", type=int, default=3600)
        if action == "evaluate":
            command.add_argument("--plan", required=True)
            command.add_argument("--trust-root", required=True)
            command.add_argument("--trust-root-sha256", required=True)

    runtime = sub.add_parser(
        "runtime-audit", help="run or inspect six signed senior-engineering audit lanes"
    )
    runtime_sub = runtime.add_subparsers(required=True, dest="runtime_audit_cmd")
    diff = runtime_sub.add_parser(
        "mutation-diff", help="inspect unsigned historical local diff bytes"
    )
    diff.add_argument("capture")
    diff.add_argument("--root", default=".")
    diff.add_argument("--json", action="store_true")
    for action in ("inspect", "run"):
        command = runtime_sub.add_parser(
            action, help=f"{action} one signed runtime audit plan"
        )
        command.add_argument("plan")
        command.add_argument("--root", default=".")
        command.add_argument("--trust-root", required=True)
        command.add_argument("--trust-root-sha256", required=True)
        command.add_argument("--environment-sha256", required=True)
        command.add_argument(
            "--require-intake",
            action="store_true",
            help="require the signed plan to bind an authoritative intake-parameter envelope",
        )
        if action == "run":
            command.add_argument("--out", default=".factory/runtime-audits")
            command.add_argument(
                "--max-parallelism",
                type=int,
                default=1,
                choices=range(1, 9),
                metavar="1..8",
                help="bounded lane concurrency, allowed only by the signed execution policy",
            )
        command.add_argument("--json", action="store_true")
    status = runtime_sub.add_parser(
        "status", help="read the latest self-hash-verified local runtime audit receipt"
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")

    senior = sub.add_parser(
        "senior",
        help="independent evidence, real-defect benchmarks, and incremental scheduling",
    )
    senior_sub = senior.add_subparsers(required=True, dest="senior_cmd")
    attest = senior_sub.add_parser(
        "attest", help="verify one DSSE-signed independent execution attestation"
    )
    attest.add_argument("receipt")
    attest.add_argument("--trust-root", required=True)
    attest.add_argument("--candidate-sha256")
    attest.add_argument("--plan-sha256")
    attest.add_argument("--json", action="store_true")
    boundary = senior_sub.add_parser(
        "boundary", help="verify one DSSE-signed runtime-boundary attestation"
    )
    boundary.add_argument("receipt")
    boundary.add_argument("--trust-root", required=True)
    boundary.add_argument("--candidate-sha256")
    boundary.add_argument("--plan-sha256")
    boundary.add_argument("--environment-sha256")
    boundary.add_argument("--json", action="store_true")
    benchmark = senior_sub.add_parser(
        "benchmark", help="evaluate supplied defect benchmark or recall observations"
    )
    benchmark.add_argument("manifest")
    benchmark.add_argument("--observations", required=True)
    benchmark.add_argument("--out")
    benchmark.add_argument("--json", action="store_true")
    schedule = senior_sub.add_parser(
        "schedule", help="plan dependency-aware proof routing without executing gates"
    )
    schedule.add_argument("manifest")
    schedule.add_argument("--root", default=".")
    schedule.add_argument("--out")
    schedule.add_argument("--json", action="store_true")
    shadow = senior_sub.add_parser(
        "shadow", help="compare incremental and full plan obligations/findings"
    )
    shadow.add_argument("incremental")
    shadow.add_argument("full")
    shadow.add_argument("--out")
    shadow.add_argument("--json", action="store_true")
    replay = senior_sub.add_parser(
        "replay",
        help="reproduce one contract-bound candidate in a fresh process workspace",
    )
    replay.add_argument("manifest")
    replay.add_argument("--root", default=".")
    replay.add_argument(
        "--execute",
        action="store_true",
        help="run the declared argv; without this flag only validate the replay plan",
    )
    replay.add_argument("--out")
    replay.add_argument("--json", action="store_true")
    repair = senior_sub.add_parser(
        "repair", help="compare the original failure, repair, and negative controls"
    )
    repair.add_argument("manifest")
    repair.add_argument("--root", default=".")
    repair.add_argument(
        "--execute",
        action="store_true",
        help="run all declared replay legs; without this flag only validate the comparison",
    )
    repair.add_argument("--out")
    repair.add_argument("--json", action="store_true")
    reuse = senior_sub.add_parser(
        "reuse", help="explain exact proof reuse or the reason a gate must run"
    )
    reuse.add_argument("manifest")
    reuse.add_argument("--root", default=".")
    reuse.add_argument("--out")
    reuse.add_argument("--json", action="store_true")
    brief = senior_sub.add_parser(
        "brief", help="turn one failed receipt into an evidence-linked failure briefing"
    )
    brief.add_argument("receipt")
    brief.add_argument("--out")
    brief.add_argument("--json", action="store_true")
    live = senior_sub.add_parser(
        "live", help="give change-aware feedback and run only affected checks"
    )
    live.add_argument("manifest")
    live.add_argument("--root", default=".")
    live.add_argument(
        "--changed",
        action="append",
        help="override changed paths; repeat for multiple paths",
    )
    live.add_argument(
        "--execute",
        action="store_true",
        help="run affected checks in fresh temporary workspaces",
    )
    live.add_argument("--out")
    live.add_argument("--json", action="store_true")
    fix = senior_sub.add_parser(
        "fix",
        help="reproduce a failure, verify a repair, and challenge negative controls",
    )
    fix.add_argument("manifest")
    fix.add_argument("--root", default=".")
    fix.add_argument(
        "--execute",
        action="store_true",
        help="run all replay legs in fresh temporary workspaces",
    )
    fix.add_argument("--out")
    fix.add_argument("--json", action="store_true")
    fix.add_argument("--prior-attempt", action="append", default=[])
    fix.add_argument("--max-rounds", type=int, default=3)
    incident = senior_sub.add_parser(
        "incident", help="prepare an exposed incident regression packet"
    )
    incident.add_argument("manifest")
    incident.add_argument("--root", default=".")
    incident.add_argument("--out")
    incident.add_argument("--json", action="store_true")


def _add_execution_parsers(sub: Any) -> None:
    for action in (
        "inventory",
        "scan",
        "progress",
        "cancel",
        "pause",
        "playback",
        "review",
        "repairs",
    ):
        parser = sub.add_parser(
            action, help=f"{action} explicit isolated deep-audit execution"
        )
        parser.add_argument("--root", default=".")
        parser.add_argument("--json", action="store_true")
        if action in {"progress", "cancel", "pause", "playback", "review", "repairs"}:
            parser.add_argument("--run-id", required=True)
        if action == "playback":
            parser.add_argument("--after", type=int, default=0)
            parser.add_argument("--limit", type=int, default=100)
        if action == "repairs":
            parser.add_argument("--before-run")
        if action == "scan":
            parser.add_argument("--manifest", required=True)
            parser.add_argument("--manifest-sha256", required=True)
            parser.add_argument("--authorization", required=True)
            parser.add_argument(
                "--request-file",
                help="bounded exact operator request under .factory/deep-runs/requests",
            )
            parser.add_argument("--resume")
            parser.add_argument(
                "--events",
                action="store_true",
                help="emit NDJSON progress and final result",
            )
        if action in {"scan", "review"}:
            parser.add_argument("--trust-root", required=True)
            parser.add_argument("--trust-root-sha256", required=True)
        if action == "review":
            parser.add_argument("--attestation", required=True)
            parser.add_argument("--invocation", required=True)


def _run_control(args: Any, root: Path) -> dict:
    from .deep_audit import (
        cancel_deep_run,
        deep_run_status,
        pause_deep_run,
        playback_deep_run,
    )

    actions = {
        "progress": deep_run_status,
        "cancel": cancel_deep_run,
        "pause": pause_deep_run,
    }
    if args.deep_cmd == "playback":
        return playback_deep_run(root, args.run_id, after=args.after, limit=args.limit)
    return actions[args.deep_cmd](root, args.run_id)


def _run_execution(args: Any) -> int:
    from .deep_audit import (
        execution_repairs,
        scan_deep_audit,
    )
    from .deep_audit_attestation import verify_execution_review
    from .deep_audit_io import inventory_candidate

    root = Path(args.root).resolve()
    try:
        if args.deep_cmd == "inventory":
            result = inventory_candidate(root)
        elif args.deep_cmd == "scan":

            def event(value: dict) -> None:
                print(json.dumps(value, sort_keys=True), flush=True)

            result = scan_deep_audit(
                root,
                Path(args.manifest),
                args.manifest_sha256,
                authorization=Path(args.authorization),
                trust_root=Path(args.trust_root),
                trust_root_sha256=args.trust_root_sha256,
                request_file=Path(args.request_file) if args.request_file else None,
                resume=args.resume,
                emit=event if args.events else None,
            )
            if args.events:
                event({"kind": "final_result", "result": result})
                return 1
        elif args.deep_cmd in {"progress", "cancel", "pause", "playback"}:
            result = _run_control(args, root)
        elif args.deep_cmd == "repairs":
            result = execution_repairs(root, args.run_id, before_run=args.before_run)
        else:
            result = verify_execution_review(
                root,
                args.run_id,
                Path(args.attestation),
                Path(args.invocation),
                Path(args.trust_root),
                args.trust_root_sha256,
            )
        return _emit(
            result,
            0
            if result["state"]
            in {
                "COMPLETE",
                "READY_FOR_HUMAN_REVIEW",
                "CANCELLATION_REQUESTED",
                "PAUSE_REQUESTED",
                "OBSERVED",
                "ALREADY_STOPPED",
            }
            else 1,
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _emit(
            {
                "state": "INCOMPLETE",
                "code": getattr(exc, "code", "E_DEEP_EXECUTION"),
                "message": str(exc),
                "authority": "none",
                "release_approval": False,
            },
            2,
        )


def _emit(result: dict[str, Any], code: int) -> int:
    if "agent_actions" not in result:
        receipt = result.get("receipt")
        if isinstance(receipt, dict) and isinstance(receipt.get("agent_actions"), list):
            result["agent_actions"] = receipt["agent_actions"]
        elif isinstance(result.get("repair_queue"), list):
            result["agent_actions"] = result["repair_queue"]
        elif result.get("state") in {"INCOMPLETE", "FAIL", "NOT_RUN"} or code != 0:
            result["agent_actions"] = [
                {
                    "id": "deep-audit-report-incomplete",
                    "measurement_id": result.get("code", "deep_audit_execution"),
                    "priority": "P1",
                    "agent_role": "audit_orchestrator_agent",
                    "action": "Resolve the reported deep-audit execution or evidence issue, then rerun the same command against the candidate.",
                    "evidence_to_attach": "Exact command, candidate SHA, runner/tool versions, complete stdout/stderr, and hash-bound output receipt.",
                    "stop_condition": "Keep the audit INCOMPLETE until the command succeeds and its result is bound to the intended candidate.",
                }
            ]
        else:
            result["agent_actions"] = []
    print(
        json.dumps(result, indent=2, sort_keys=True),
        file=sys.stderr if code == 2 else sys.stdout,
    )
    return code


def _deep_compare(args: Any, root: Path, compare: Any) -> tuple[dict[str, Any], int]:
    result = compare(
        root,
        args.before,
        args.after,
        before_attestation=args.before_attestation,
        after_attestation=args.after_attestation,
        trust_root_path=Path(args.trust_root) if args.trust_root else None,
        require_attestation=args.require_attestation,
        max_age_seconds=args.max_age_seconds,
    )
    result["action_summary"] = (
        "Compared signed deep-audit observations; no analyzer or repair ran."
    )
    return result, 0 if result["state"] == "approval_required" else 1


def _deep_status(root: Path, status: Any) -> tuple[dict[str, Any], int]:
    result = status(root)
    result["action_summary"] = "Read local deep-audit evidence."
    return result, 0 if result["state"] == "READY_FOR_HUMAN_REVIEW" else 1


def _deep_attestation(args: Any, root: Path, verify: Any) -> tuple[dict[str, Any], int]:
    result = verify(
        root,
        Path(args.attestation),
        Path(args.trust_root),
        Path(args.receipt),
        max_age_seconds=args.max_age_seconds,
    )
    result["action_summary"] = (
        "Verified one offline DSSE deep-audit attestation; no analyzer or repair ran."
    )
    return result, 0 if result["state"] == "VERIFIED" else 1


def _deep_evaluate(args: Any, root: Path, execute: Any) -> tuple[dict[str, Any], int]:
    result = execute(
        Path(args.plan), Path(args.trust_root), args.trust_root_sha256, root
    )
    result["action_summary"] = (
        "Evaluated signed reports and saved a review receipt; no analyzer or repair ran."
    )
    code = 0 if result["receipt"]["decision"] == "READY_FOR_HUMAN_REVIEW" else 1
    return result, code


def _run_deep(args: Any) -> int:
    if args.deep_cmd == "coordinator":
        return _run_coordinator(args)
    if args.deep_cmd == "blade-structure":
        from .deep_audit_contract import blade_structure
        from .runtime_audit_common import RuntimeAuditError

        try:
            result = blade_structure(args.source, args.grammar_dir)
        except (OSError, ValueError, RuntimeAuditError) as exc:
            return _emit(
                {
                    "state": "INCOMPLETE",
                    "authority": "none",
                    "code": getattr(exc, "code", "E_BLADE_INPUT"),
                    "message": str(exc),
                },
                2,
            )
        return _emit(result, 0 if result["state"] == "STRUCTURE_OBSERVED" else 2)
    if args.deep_cmd in {
        "inventory",
        "scan",
        "progress",
        "cancel",
        "pause",
        "playback",
        "review",
        "repairs",
    }:
        return _run_execution(args)
    from .deep_audit import deep_audit_status, execute_deep_audit
    from .deep_audit_attestation import (
        DeepAuditAttestationError,
        verify_deep_audit_attestation,
    )
    from .repair_loop import compare_deep_audit_repairs
    from .runtime_audit_common import RuntimeAuditError

    try:
        root = Path(args.root).resolve()
        if args.deep_cmd == "compare":
            result, code = _deep_compare(args, root, compare_deep_audit_repairs)
        elif args.deep_cmd == "status":
            result, code = _deep_status(root, deep_audit_status)
        elif args.deep_cmd == "attestation":
            result, code = _deep_attestation(args, root, verify_deep_audit_attestation)
        else:
            result, code = _deep_evaluate(args, root, execute_deep_audit)
    except (
        DeepAuditAttestationError,
        RuntimeAuditError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        return _emit(
            {
                "code": getattr(exc, "code", "E_DEEP_AUDIT"),
                "message": str(exc),
                "authority": "none",
            },
            2,
        )
    return _emit(result, code)


def _run_coordinator(args: Any) -> int:
    """Hand exclusive raw stdin to the existing foreground coordinator."""
    import io
    from .agentic_control import AgenticControlError

    try:
        stream = getattr(sys.stdin, "buffer", None)
        stream = getattr(stream, "raw", stream)
        if not isinstance(stream, io.FileIO):
            raise ValueError("exclusive raw stdin pipe or file required")
        result = serve_deep_audit_coordinator(
            Path(args.root), args.lease_seconds, args.session_nonce, stream, sys.stdout
        )
        return 0 if result["state"] in {"OBSERVED", "STOPPED"} else 1
    except (AgenticControlError, ValueError, TypeError, KeyError, OSError) as error:
        _coordinator_emit(
            sys.stdout,
            _coordinator_result(
                "INCOMPLETE",
                code=getattr(error, "code", "E_COORDINATOR_INPUT"),
                execution_available=False,
            ),
        )
        return 2


def _run_runtime(args: Any) -> int:
    if args.runtime_audit_cmd == "mutation-diff":
        return _run_mutation_diff(args)
    from .runtime_audit import execute_runtime_audit, runtime_audit_status
    from .runtime_audit_common import RuntimeAuditError
    from .runtime_audit_contract import verify_runtime_audit_plan

    root = Path(args.root).resolve()
    try:
        if args.runtime_audit_cmd == "status":
            result = runtime_audit_status(root)
            code = 0 if result["state"] in {"NOT_RUN", "READY_FOR_HUMAN_REVIEW"} else 1
        elif args.runtime_audit_cmd == "inspect":
            result = verify_runtime_audit_plan(
                Path(args.plan),
                Path(args.trust_root),
                args.trust_root_sha256,
                root,
                args.environment_sha256,
                require_intake=args.require_intake,
            )
            result = {
                **result,
                "plan": {
                    "id": result["plan"]["id"],
                    "candidate_sha256": result["plan"]["candidate_sha256"],
                    "lanes": [item["kind"] for item in result["plan"]["lanes"]],
                },
                "action_summary": "Verified the signed audit authority and exact six-lane execution contract; no command ran.",
            }
            code = 0
        else:
            result = execute_runtime_audit(
                Path(args.plan),
                Path(args.trust_root),
                args.trust_root_sha256,
                root,
                args.environment_sha256,
                Path(args.out),
                require_intake=args.require_intake,
                max_parallelism=args.max_parallelism,
            )
            code = 0 if result["receipt"]["decision"] == "READY_FOR_HUMAN_REVIEW" else 1
    except (RuntimeAuditError, OSError, ValueError, KeyError, TypeError) as exc:
        return _emit(
            {
                "schema": "factory.runtime-audit.error.v1",
                "code": getattr(exc, "code", "E_RUNTIME_AUDIT"),
                "message": str(exc),
                "authority": "none",
            },
            2,
        )
    return _emit(result, code)


def _run_mutation_diff(args: Any) -> int:
    from .runtime_audit_common import RuntimeAuditError
    from .runtime_attestation import inspect_local_mutation_diff

    try:
        result = inspect_local_mutation_diff(Path(args.root), args.capture)
    except RuntimeAuditError as exc:
        return _emit(
            {
                "schema": "factory.runtime-audit.error.v1",
                "code": exc.code,
                "message": exc.message,
                "authority": "none",
            },
            2,
        )
    if args.json:
        return _emit(result, 0)
    # Paths are JSON escaped; diff bytes are never rendered as terminal controls.
    print("HISTORICAL HASH_VERIFIED UNSIGNED; currentness NOT_CHECKED; authority none")
    print("production=" + json.dumps(result["production_path"], ensure_ascii=True))
    print("test=" + json.dumps(result["test_path"], ensure_ascii=True))
    print("production.diff sha256=" + result["diff_sha256"])
    raw = base64.b64decode(result["diff_base64"])
    lines = raw[:8192].splitlines(keepends=True)
    print("diff preview (JSON-escaped byte values, not decoded Unicode):")
    for line in lines[:80]:
        print(json.dumps(line.decode("latin-1"), ensure_ascii=True))
    if len(raw) > 8192 or len(lines) > 80:
        print("[PREVIEW TRUNCATED: use --json for full base64 bytes]")
    return 0


def _senior_action(
    result: dict[str, Any], summary: str, code: int
) -> tuple[dict[str, Any], int]:
    result["action_summary"] = summary
    return result, code


def _optional_output(args: Any) -> Path | None:
    return Path(args.out) if args.out else None


def _senior_attest(args: Any) -> tuple[dict[str, Any], int]:
    from .independent_execution import verify_signed_execution_attestation

    result = verify_signed_execution_attestation(
        Path(args.receipt),
        Path(args.trust_root),
        candidate_sha256=args.candidate_sha256,
        plan_sha256=args.plan_sha256,
    )
    return _senior_action(
        result,
        "Verified an independently collected execution attestation; no command ran and release authority stayed disabled.",
        0,
    )


def _senior_boundary(args: Any) -> tuple[dict[str, Any], int]:
    from .runtime_attestation import verify_signed_runtime_attestation

    result = verify_signed_runtime_attestation(
        Path(args.receipt),
        Path(args.trust_root),
        candidate_sha256=args.candidate_sha256,
        plan_sha256=args.plan_sha256,
        environment_sha256=args.environment_sha256,
    )
    return _senior_action(
        result,
        "Verified an independently collected runtime boundary; no command ran and release authority stayed disabled.",
        0,
    )


def _senior_benchmark(args: Any) -> tuple[dict[str, Any], int]:
    from .benchmark_lab import evaluate_benchmark, load_benchmark_json
    from .senior_assurance import RECALL_SCHEMA, evaluate_source_bound_recall

    manifest = load_benchmark_json(Path(args.manifest))
    observations = load_benchmark_json(Path(args.observations))
    recall = manifest.get("schema") == RECALL_SCHEMA
    evaluate = evaluate_source_bound_recall if recall else evaluate_benchmark
    result = evaluate(manifest, observations, out=_optional_output(args))
    code = 0 if result["decision"] in {"PASS", "MEASURED"} else 1
    summary = (
        "Evaluated frozen recall captures against the supplied truth manifest."
        if recall
        else "Evaluated supplied buggy/fixed benchmark observations; no replay command ran."
    )
    return _senior_action(
        result,
        summary,
        code,
    )


def _senior_schedule(args: Any) -> tuple[dict[str, Any], int]:
    from .incremental_scheduler import load_schedule_json, plan_incremental

    result = plan_incremental(
        Path(args.root).resolve(),
        load_schedule_json(Path(args.manifest)),
        out=_optional_output(args),
    )
    code = 1 if result["counts"]["BLOCK"] else 0
    return _senior_action(
        result, "Planned dependency-aware proof routing; no gate command ran.", code
    )


def _senior_shadow(args: Any) -> tuple[dict[str, Any], int]:
    from .incremental_scheduler import compare_shadow, load_schedule_json

    result = compare_shadow(
        load_schedule_json(Path(args.incremental)),
        load_schedule_json(Path(args.full)),
        out=_optional_output(args),
    )
    code = 0 if result["shadow_equivalent"] else 1
    return _senior_action(
        result,
        "Compared supplied incremental and full obligations/findings; no plan ran.",
        code,
    )


def _senior_replay(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import load_assurance_json, run_replay

    result = run_replay(
        Path(args.root).resolve(),
        load_assurance_json(Path(args.manifest)),
        execute=args.execute,
        out=_optional_output(args),
    )
    summary = (
        "Replayed the declared candidate in a fresh process workspace; no release authority was granted."
        if args.execute
        else "Validated a contract-bound replay plan; no candidate command ran."
    )
    code = 0 if result["state"] in {"PLAN_ONLY", "PASS"} else 1
    return _senior_action(result, summary, code)


def _senior_repair(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import compare_repair, load_assurance_json

    result = compare_repair(
        Path(args.root).resolve(),
        load_assurance_json(Path(args.manifest)),
        execute=args.execute,
        out=_optional_output(args),
    )
    summary = (
        "Compared original, repaired, and negative-control executions; release authority stayed disabled."
        if args.execute
        else "Validated a repair comparison; no candidate command ran."
    )
    code = 0 if result["state"] in {"PLAN_ONLY", "PASS"} else 1
    return _senior_action(result, summary, code)


def _senior_live(args: Any) -> tuple[dict[str, Any], int]:
    from .live_feedback import load_live_json, run_live_feedback

    result = run_live_feedback(
        Path(args.root).resolve(),
        load_live_json(Path(args.manifest)),
        execute=args.execute,
        changed_paths=args.changed,
        out=_optional_output(args),
    )
    summary = (
        "Ran affected checks in fresh temporary workspaces; no source or release action ran."
        if args.execute
        else "Planned affected checks and next feedback actions; no command ran."
    )
    failed = result["counts"]["FAIL"] or result["counts"]["BLOCKED"]
    return _senior_action(result, summary, 1 if failed else 0)


def _prior_fix_refs(root: Path, paths: list[str]) -> list[dict[str, str]]:
    from .fix_workflow import _repair_history_path, FixWorkflowError
    import hashlib

    refs = []
    for name in paths:
        path = _repair_history_path(root, {"path": name, "sha256": ""})
        with path.open("rb") as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise FixWorkflowError("E_REPAIR_HISTORY", "history receipt is oversized")
        refs.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest()})
    return refs


def _senior_fix(args: Any) -> tuple[dict[str, Any], int]:
    from .fix_workflow import load_fix_json, run_fix_workflow

    root = Path(args.root).resolve()
    prior = _prior_fix_refs(root, args.prior_attempt)

    result = run_fix_workflow(
        Path(args.root).resolve(),
        load_fix_json(Path(args.manifest)),
        execute=args.execute,
        prior_attempts=prior,
        max_rounds=args.max_rounds,
        out=_optional_output(args),
    )
    summary = (
        "Reproduced the failure and compared the repair with negative controls; release authority stayed disabled."
        if args.execute
        else "Validated the reproduce-and-repair workflow; no candidate command ran."
    )
    if result["state"] in {"STEP_BACK", "NO_PROGRESS"}:
        summary = f"Repair stopped: {result['state']}; no candidate command ran."
    complete_branch_comparison = (
        result.get("state") == "COMPARED"
        and bool(result.get("branches"))
        and all(
            row.get("status") == "OBSERVED"
            and row.get("raw_comparison", {}).get("executed") is True
            for row in result["branches"]
        )
    )
    code = (
        0
        if result["state"] in {"PLAN_ONLY", "PASS"} or complete_branch_comparison
        else 1
    )
    return _senior_action(result, summary, code)


def _senior_reuse(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import explain_evidence_reuse, load_assurance_json

    result = explain_evidence_reuse(
        Path(args.root).resolve(),
        load_assurance_json(Path(args.manifest)),
        out=_optional_output(args),
    )
    code = 1 if result["counts"]["BLOCK"] else 0
    return _senior_action(
        result,
        "Explained exact evidence reuse and fail-closed reruns; no gate command ran.",
        code,
    )


def _senior_brief(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import failure_brief, load_assurance_json

    receipt_path = Path(args.receipt)
    receipt = load_assurance_json(receipt_path)
    result = failure_brief(
        receipt,
        receipt_path=receipt_path.as_posix(),
        receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        out=_optional_output(args),
    )
    return _senior_action(
        result,
        "Built an evidence-linked failure briefing; no repair or release action ran.",
        0,
    )


def _senior_incident(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import build_incident_regression_packet, load_assurance_json

    result = build_incident_regression_packet(
        Path(args.root).resolve(), load_assurance_json(Path(args.manifest))
    )
    if args.out:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(result, sort_keys=True) + "\n", encoding="utf-8"
        )
    return _senior_action(
        result, "Prepared an exposed regression; nothing executed.", 0
    )


def _senior_command(args: Any) -> tuple[dict[str, Any], int]:
    handlers = {
        "attest": _senior_attest,
        "boundary": _senior_boundary,
        "benchmark": _senior_benchmark,
        "schedule": _senior_schedule,
        "shadow": _senior_shadow,
        "replay": _senior_replay,
        "repair": _senior_repair,
        "live": _senior_live,
        "fix": _senior_fix,
        "incident": _senior_incident,
        "reuse": _senior_reuse,
        "brief": _senior_brief,
    }
    return handlers.get(args.senior_cmd, _senior_brief)(args)


def _run_senior(args: Any) -> int:
    from .benchmark_lab import BenchmarkError
    from .fix_workflow import FixWorkflowError
    from .incremental_scheduler import SchedulerError
    from .independent_execution import ExecutionAttestationError
    from .live_feedback import LiveFeedbackError
    from .senior_assurance import SeniorAssuranceError

    try:
        result, code = _senior_command(args)
    except (
        SeniorAssuranceError,
        FixWorkflowError,
        LiveFeedbackError,
        ExecutionAttestationError,
        BenchmarkError,
        SchedulerError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        return _emit(
            {
                "schema": "factory.senior.error.v1",
                "code": getattr(exc, "code", "E_SENIOR_INPUT"),
                "message": str(exc),
                "authority": "none",
                "release_approval": False,
            },
            2,
        )
    return _emit(result, code)


def run(args: Any) -> int:
    """Dispatch deep, runtime, and senior audit commands lazily."""
    if args.cmd == "deep-audit":
        return _run_deep(args)
    if args.cmd == "runtime-audit":
        return _run_runtime(args)
    return _run_senior(args)

"""Deterministic deep-audit decisions over externally bound analyzer evidence.

The execute entry point verifies signatures and re-normalizes reports itself.
The pure evaluator does not authenticate caller-supplied dictionaries. Neither
legacy entry point executes an analyzer or grants approval or release rights.
The explicit scan entry point runs authorized, isolated adapter containers.
"""

from __future__ import annotations

from collections import defaultdict
from itertools import islice
from pathlib import Path
import stat
import json
import os
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone

from .deep_audit_contract import verify_deep_audit_plan
from .deep_audit_io import LIMIT, digest, local_file, strict_json
from .deep_audit_sarif import normalize_sarif
from .runtime_audit_common import RuntimeAuditError, canonical_bytes, sha256_bytes
from .audit_action_refs import audit_remediation_packet


def _execution_gap(code: str, action: str, path: str = ".") -> dict:
    return {"code": code, "path": path, "action": action}


def _obligation_gaps(obligations: list[dict], files: dict[str, dict]) -> list[dict]:
    gaps = []
    for obligation in obligations:
        if not set(obligation["paths"] + obligation["requirements"]) <= files.keys():
            gaps.append(
                _execution_gap(
                    "UNBOUND_OBLIGATION",
                    "Bind every obligation and requirement to inventoried source.",
                    obligation["id"],
                )
            )
        for challenge in obligation["challenges"]:
            if (
                files.get(challenge["fixture_path"], {}).get("sha256")
                != challenge["fixture_sha256"]
            ):
                gaps.append(
                    _execution_gap(
                        "UNBOUND_CHALLENGE",
                        "Bind the challenge fixture bytes to the inventoried candidate.",
                        challenge["fixture_path"],
                    )
                )
    return gaps


def _language_lanes(plan: dict) -> dict[str, set[str]]:
    by_family = {}
    for lane in plan["lanes"]:
        by_family.setdefault(lane["family"], set()).update(lane["languages"])
    return by_family


def _source_families(language: str) -> set[str]:
    families = {"secrets"}
    if language == "dependency":
        families.add("dependencies")
    elif language == "configuration":
        families.add("configuration")
    elif language != "data":
        families.update({"static", "runtime", "fuzz"})
    return families


def _source_gaps(
    files: dict[str, dict],
    language_lanes: dict[str, set[str]],
    obligations: list[dict],
) -> list[dict]:
    gaps = []
    for path, item in files.items():
        language = item["language"]
        for family in sorted(_source_families(language)):
            if language not in language_lanes.get(family, set()) or not any(
                obligation["family"] == family and path in obligation["paths"]
                for obligation in obligations
            ):
                gaps.append(
                    _execution_gap(
                        "UNCOVERED_SOURCE",
                        f"Add a {family} analyzer and source-bound obligation for {language}.",
                        path,
                    )
                )
    return gaps


def _dependency_scope_gap(plan: dict) -> list[dict]:
    engines = {lane["engine"] for lane in plan["lanes"]}
    if {"syft", "osv"} <= engines:
        return []
    return [
        _execution_gap(
            "DEPENDENCY_DEPTH",
            "Declare both SBOM inventory (Syft) and vulnerability analysis (OSV).",
        )
    ]


def _scope_gaps(plan: dict, inventory: dict) -> list:
    """Source-derived obligations cannot be removed by a narrow PRD or lane."""
    files = {item["path"]: item for item in inventory["files"]}
    obligations = plan["obligations"]
    gaps = _obligation_gaps(obligations, files)
    gaps.extend(_source_gaps(files, _language_lanes(plan), obligations))
    gaps.extend(_dependency_scope_gap(plan))
    return gaps


_EVENT_LOCK = threading.RLock()


def _event(directory: Path, state: dict, kind: str, details: dict, emit=None) -> None:
    # Heartbeat and coordinator writes must not race the durable sequence/head.
    with _EVENT_LOCK:
        _write_event(directory, state, kind, details, emit)


def _write_event(
    directory: Path, state: dict, kind: str, details: dict, emit=None
) -> None:
    from .deep_audit_io import write_run_json

    sequence = state.get("sequence", 0) + 1
    event = {
        "sequence": sequence,
        "run_id": state["run_id"],
        "kind": kind,
        "at": datetime.now(timezone.utc).isoformat(),
        "previous_sha256": state.get("event_sha256"),
        "details": details,
    }
    write_run_json(directory, f"event-{sequence:05d}.json", event)
    state.update(sequence=sequence, event_sha256=digest(event), updated_at=event["at"])
    write_run_json(directory, "state.json", state)
    if emit is not None:
        emit(event)


def _docker_base() -> list[str]:
    executable = shutil.which("docker")
    if executable is None:
        raise RuntimeAuditError(
            "E_DOCKER_UNAVAILABLE",
            "Install and start a local Linux Docker engine; host execution is disabled",
        )
    endpoint = (
        "npipe:////./pipe/dockerDesktopLinuxEngine"
        if os.name == "nt"
        else "unix:///var/run/docker.sock"
    )
    return [executable, "--host", endpoint]


def _docker_control(base: list, args: list, timeout: int = 15) -> tuple[dict, bytes]:
    from .runtime_audit_process import run_bounded_command

    with tempfile.TemporaryDirectory(prefix="factory-docker-") as temporary:
        directory = Path(temporary)
        output = directory / "stdout"
        facts = run_bounded_command(
            base + args, directory, timeout, directory, stdout_path=output
        )
        raw = output.read_bytes() if output.exists() else b""
        if (
            facts["timed_out"]
            or facts["output_limit_exceeded"]
            or not facts["cleanup_confirmed"]
        ):
            raise RuntimeAuditError(
                "E_DOCKER_CONTROL",
                "Docker control request did not complete within bounds",
            )
        return facts, raw


def _docker_preflight(base: list, lane: dict, deadline=None) -> None:
    control = _docker_control if deadline is None else _zap_docker_control
    control_args = () if deadline is None else (deadline,)
    facts, raw = control(base, ["info", "--format", "{{json .OSType}}"], *control_args)
    if facts["exit_code"] != 0 or raw.strip() != b'"linux"':
        raise RuntimeAuditError(
            "E_DOCKER_UNAVAILABLE", "A running local Linux Docker engine is required"
        )
    local_id = lane["image"].startswith("sha256:")
    field = ".Id" if local_id else ".RepoDigests"
    facts, raw = control(
        base,
        ["image", "inspect", lane["image"], "--format", "{{json " + field + "}}"],
        *control_args,
    )
    if facts["exit_code"] != 0:
        raise RuntimeAuditError(
            "E_IMAGE_UNAVAILABLE",
            "Provision the pinned adapter image before running; automatic pulls are disabled",
        )
    try:
        pins = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise RuntimeAuditError(
            "E_IMAGE_PIN", "cannot verify the locally installed image"
        ) from exc
    matches = (
        isinstance(pins, str) and pins == lane["image"]
        if local_id
        else isinstance(pins, list) and lane["image"] in pins
    )
    if not matches:
        raise RuntimeAuditError(
            "E_IMAGE_PIN",
            "installed image does not match the declared immutable digest",
        )


def _container_argv(
    base: list,
    lane: dict,
    snapshot: Path,
    name: str,
    run_id: str,
    candidate: str,
    contract: Path | None = None,
) -> list:
    if "," in str(snapshot):
        raise RuntimeAuditError(
            "E_MOUNT_PATH", "Docker bind paths cannot contain commas"
        )
    mounts = []
    if contract is not None:
        if "," in str(contract):
            raise RuntimeAuditError(
                "E_MOUNT_PATH", "Docker contract paths cannot contain commas"
            )
        mounts = [
            "--mount",
            f"type=bind,source={contract},target=/factory-contract.json,readonly",
            "--env",
            "FACTORY_CONTRACT=/factory-contract.json",
        ]
    return base + [
        "run",
        "--pull=never",
        "--name",
        name,
        "--network=none",
        "--read-only",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=128",
        f"--memory={lane['memory_mib']}m",
        f"--memory-swap={lane['memory_mib']}m",
        "--cpus=2",
        "--ulimit",
        "nofile=256:256",
        "--log-driver=none",
        "--mount",
        f"type=bind,source={snapshot},target=/src,readonly,bind-recursive=readonly,bind-propagation=rprivate",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
        "--tmpfs",
        "/out:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--workdir=/src",
        "--env",
        f"FACTORY_RUN_ID={run_id}",
        "--env",
        f"FACTORY_CANDIDATE_SHA256={candidate}",
        *mounts,
        "--entrypoint",
        lane["argv"][0],
        lane["image"],
        *lane["argv"][1:],
    ]


def _container_cleanup(base: list, name: str) -> bool:
    try:
        _docker_control(base, ["rm", "--force", name])
        facts, raw = _docker_control(
            base,
            [
                "container",
                "ls",
                "--all",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.Names}}",
            ],
        )
        return facts["exit_code"] == 0 and not raw.strip()
    except (OSError, RuntimeAuditError):
        return False


def _monitor_lane(
    directory: Path,
    state: dict,
    stop: threading.Event,
    cancelled: threading.Event,
    emit,
) -> None:
    last = time.monotonic()
    while not stop.wait(0.25):
        if any((directory / name).exists() for name in ("cancel.json", "pause.json")):
            cancelled.set()
        if time.monotonic() - last >= 15:
            _event(
                directory,
                state,
                "lane_running",
                {"lane_id": state["active_lane"]},
                emit,
            )
            last = time.monotonic()


def _execute_lane(
    root: Path,
    directory: Path,
    state: dict,
    snapshot: Path,
    lane: dict,
    inventory: dict,
    plan: dict,
    emit,
) -> dict:
    if lane["engine"] == "zap" and "native_target" in lane:
        return _execute_zap_controlled_lane(
            directory, state, snapshot, lane, inventory, plan, emit
        )
    from .deep_audit_sarif import normalize_execution_bundle
    from .deep_audit_io import write_run_json
    from .runtime_audit_process import run_bounded_command

    deadline = time.monotonic() + lane["timeout_seconds"]
    base = _docker_base()
    _docker_preflight(base, lane)
    name = f"factory-deep-{state['run_id']}-{lane['id']}"
    cancelled, stop = threading.Event(), threading.Event()
    monitor = threading.Thread(
        target=_monitor_lane,
        args=(directory, state, stop, cancelled, emit),
        daemon=True,
    )
    monitor.start()
    cleanup = False
    argv = None
    try:
        with tempfile.TemporaryDirectory(prefix="factory-lane-") as temporary:
            scratch = Path(temporary)
            output = scratch / "worker.json"
            contract = scratch / "contract.json"
            contract.write_bytes(
                canonical_bytes(
                    {
                        "schema": "factory.deep-adapter-input.v1",
                        "run_id": state["run_id"],
                        "manifest_sha256": state["manifest_sha256"],
                        "inventory": inventory,
                        "lane": lane,
                        "obligations": plan["obligations"],
                    }
                )
            )
            argv = _container_argv(
                base,
                lane,
                snapshot,
                name,
                state["run_id"],
                inventory["candidate_sha256"],
                contract,
            )
            facts = run_bounded_command(
                argv,
                scratch,
                lane["timeout_seconds"],
                scratch,
                stdout_path=output,
                cancelled=cancelled,
            )
            raw = output.read_bytes() if output.exists() else b""
    finally:
        stop.set()
        monitor.join(timeout=2)
        cleanup = _container_cleanup(base, name)
    if not cleanup:
        raise RuntimeAuditError(
            "E_CONTAINER_CLEANUP", f"Container cleanup could not be verified: {name}"
        )
    if (
        facts["exit_code"] != 0
        or facts.get("cancelled")
        or facts["timed_out"]
        or facts["output_limit_exceeded"]
        or not facts["cleanup_confirmed"]
    ):
        return {
            "lane_id": lane["id"],
            "state": "INCOMPLETE",
            "findings": [],
            "gaps": ["WORKER_FAILED"],
            "execution": facts,
        }
    try:
        bundle = strict_json(raw)
        result = normalize_execution_bundle(
            bundle, lane, inventory, state["run_id"], plan["obligations"]
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        diagnostic = getattr(exc, "code", "E_WORKER_EVIDENCE")
        native_execution = {
            "completion": "COMMAND_COMPLETED_NORMALIZATION_FAILED",
            "diagnostic_code": diagnostic,
            "command_sha256": digest(argv) if argv is not None else None,
            "image": lane.get("image"),
            "image_sha256": digest(lane.get("image")),
            "source_candidate_sha256": inventory.get("candidate_sha256"),
            "manifest_sha256": state.get("manifest_sha256"),
            "config_sha256": lane.get("ruleset_sha256"),
            "lane_contract_sha256": digest(lane),
            "output_sha256": sha256_bytes(raw),
            "cleanup_confirmed": cleanup and facts.get("cleanup_confirmed", False),
        }
        return {
            "lane_id": lane["id"],
            "state": "INCOMPLETE",
            "findings": [],
            "gaps": [diagnostic],
            "worker_output_sha256": sha256_bytes(raw),
            "native_execution": native_execution,
            "execution": facts,
        }
    result = _codeql_replay_result(
        result,
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        state["run_id"],
        cancelled,
        deadline,
        (directory, state, emit),
    )
    result = _osv_replay_result(
        result,
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        state["run_id"],
        cancelled,
        deadline,
        (directory, state, emit),
        plan["obligations"],
    )
    result = _fuzz_replay_result(
        result,
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        state["run_id"],
        cancelled,
        deadline,
        (directory, state, emit),
        plan["obligations"],
    )
    # Retain normalized native evidence for independent review, never emit raw logs/secrets.
    write_run_json(directory, f"bundle-{lane['id']}.json", bundle)
    result.update(bundle_sha256=digest(bundle), execution=facts)
    return result


def _zap_docker_control(base, args, deadline):
    """Run one Docker control request within the shared ZAP lane deadline."""
    timeout = int(deadline - time.monotonic())
    if timeout < 1:
        raise RuntimeAuditError("E_ZAP_TIMEOUT", "signed target budget exhausted")
    return _docker_control(base, args, min(15, timeout))


def _zap_internal_network(base, name, deadline=None):
    """Create and verify a host-owned network without external routing."""
    control = _docker_control if deadline is None else _zap_docker_control
    control_args = () if deadline is None else (deadline,)
    facts, _ = control(base, ["network", "create", "--internal", name], *control_args)
    if facts["exit_code"] != 0:
        raise RuntimeAuditError("E_ZAP_NETWORK", "internal network creation failed")
    facts, raw = control(
        base,
        ["network", "inspect", name, "--format", "{{json .Internal}}"],
        *control_args,
    )
    if facts["exit_code"] != 0 or raw.strip() != b"true":
        raise RuntimeAuditError("E_ZAP_NETWORK", "internal routing boundary unverified")


def _zap_network_cleanup(base, name):
    """Confirm removal of the privately generated audit network."""
    try:
        _docker_control(base, ["network", "rm", name])
        facts, raw = _docker_control(base, ["network", "ls", "--format", "{{.Name}}"])
        return facts["exit_code"] == 0 and name not in raw.decode().splitlines()
    except (OSError, ValueError):
        return False


def _zap_app_argv(base, lane, snapshot, name, network, trace_bootstrap=None):
    """Isolate the pinned candidate service from worker output and contracts."""
    target = lane["native_target"]
    argv = _container_argv(
        base,
        {**lane, "image": target["image"], "argv": target["argv"]},
        snapshot,
        name,
        "candidate-app",
        "0" * 64,
    )
    argv[argv.index("--network=none")] = "--network=" + network
    output = argv.index("/out:rw,nosuid,nodev,noexec,size=64m,mode=1777")
    del argv[output - 1 : output + 1]
    for value in (
        "FACTORY_RUN_ID=candidate-app",
        "FACTORY_CANDIDATE_SHA256=" + "0" * 64,
    ):
        position = argv.index(value)
        del argv[position - 1 : position + 1]
    position = argv.index("--pull=never")
    argv[position:position] = ["--detach", "--network-alias=factory-target"]
    if trace_bootstrap is not None:
        argv = _zap_trace_app_argv(argv, target, trace_bootstrap)
    return argv


def _zap_trace_app_argv(argv, target, bootstrap):
    """Mount trusted instrumentation without sharing writable host output."""
    if "," in str(bootstrap):
        raise RuntimeAuditError("E_MOUNT_PATH", "trace mount path contains comma")
    position = argv.index("--entrypoint")
    argv[position:position] = [
        "--mount",
        f"type=bind,source={bootstrap},target=/factory-source-trace.py,readonly",
        "--tmpfs",
        "/trace:rw,nosuid,nodev,noexec,size=4m,mode=1777",
    ]
    # The signed Python executable remains the entrypoint. The host bootstrap
    # restores the original script argv; isolated mode ignores host user modules.
    tail = argv.index("--entrypoint") + 3
    argv[tail:] = ["-I", "/factory-source-trace.py"]
    return argv


def _zap_prepare_trace(directory, state, inventory, lane, deadline):
    target = lane["native_target"]
    if "source_trace" not in target:
        return None
    from .deep_audit_io import zap_source_trace_bootstrap

    request = _zap_target_request(state, inventory, lane, target["routes"][0], deadline)
    path = directory / ("zap-source-bootstrap-" + uuid.uuid4().hex + ".txt")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(zap_source_trace_bootstrap(request, inventory))
    return path, request


def _zap_capture_trace(base, app, directory, prepared, inventory, snapshot, deadline):
    """Capture bounded instrumentation before container removal and retain bytes."""
    if prepared is None:
        return None
    from .deep_audit_io import zap_validate_source_trace, write_run_json

    _, request = prepared
    destination = directory / ("zap-source-raw-" + uuid.uuid4().hex + ".jsonl")
    # Docker's archive API cannot reliably read tmpfs mounts. Use the signed
    # interpreter to stream only this fixed, bounded, no-follow trace artifact.
    capture = (
        "import os,stat,sys; "
        "fd=os.open('/trace/events.jsonl',os.O_RDONLY|os.O_NOFOLLOW); "
        "s=os.fstat(fd); "
        "assert stat.S_ISREG(s.st_mode) and s.st_size<=4194304; "
        "f=os.fdopen(fd,'rb'); b=f.read(4194305); "
        "assert len(b)<=4194304; sys.stdout.buffer.write(b)"
    )
    facts, raw = _zap_docker_control(
        base,
        ["exec", app, request["target"]["argv"][0], "-I", "-c", capture],
        deadline,
    )
    if facts["exit_code"] != 0:
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "source trace capture failed")
    with destination.open("xb") as stream:
        stream.write(raw)
    raw = _zap_read_trace(destination)
    trace = zap_validate_source_trace(raw, request, inventory, snapshot)
    trace["artifact"] = destination.name
    write_run_json(directory, "zap-source-trace.json", trace)
    return trace


def _zap_read_trace(path):
    """Reject copied links, devices, oversized files and replacement during read."""
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size > 4 * 1024 * 1024
        or getattr(before, "st_file_attributes", 0) & 0x400
    ):
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "unsafe source trace artifact")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(4 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())

    def identity(item):
        return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns

    if identity(before) != identity(opened) or identity(opened) != identity(after):
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "source trace artifact changed")
    return raw


def _zap_capture_trace_or_gap(*args):
    """Keep scanner findings available when optional instrumentation is invalid."""
    try:
        return _zap_capture_trace(*args), None
    except (OSError, ValueError) as error:
        from .deep_audit_io import write_run_json

        code = getattr(error, "code", "E_ZAP_SOURCE_TRACE")
        write_run_json(args[2], "zap-source-trace-failure.json", {"code": code})
        return None, code


def _zap_worker_argv(
    base, lane, snapshot, name, network, state, inventory, contract, request
):
    """Launch a fresh scanner for one host-bound route request."""
    worker = {
        **lane,
        "argv": [
            "/usr/local/bin/python",
            "-I",
            "-m",
            "factoryline.deep_audit_io",
            "native-zap",
            "--request",
            "/factory-zap-request.json",
        ],
    }
    argv = _container_argv(
        base,
        worker,
        snapshot,
        name,
        state["run_id"],
        inventory["candidate_sha256"],
        contract,
    )
    argv[argv.index("--network=none")] = "--network=" + network
    if "," in str(request):
        raise RuntimeAuditError("E_MOUNT_PATH", "request mount path contains comma")
    index = argv.index("--entrypoint")
    argv[index:index] = [
        "--mount",
        f"type=bind,source={request},target=/factory-zap-request.json,readonly",
    ]
    return argv


def _zap_target_request(state, inventory, lane, route, deadline, disabled_rule_id=None):
    """Bind execution to the signed lane and remaining host-owned budget."""
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError("E_ZAP_TIMEOUT", "signed target budget exhausted")
    request = {
        "schema": "factory.zap-native-request.v2",
        "run_id": state["run_id"],
        "candidate_sha256": inventory["candidate_sha256"],
        "profile_sha256": digest(lane),
        "rule_ids": lane["rule_ids"],
        "timeout_seconds": min(lane["timeout_seconds"], remaining),
        "target": lane["native_target"],
        "route_id": route["id"],
    }
    if disabled_rule_id is not None:
        policy = {
            "schema": "factory.zap-disabled-policy.v1",
            "rule_ids": lane["rule_ids"],
            "disabled_rule_id": disabled_rule_id,
        }
        if disabled_rule_id not in lane["rule_ids"] or lane.get(
            "mutation_config_sha256", {}
        ).get(disabled_rule_id) != digest(policy):
            raise RuntimeAuditError(
                "E_ZAP_MUTATION", "exact signed disabled policy required"
            )
        request["disabled_rule_id"] = disabled_rule_id
    return request


def _zap_target_route(
    base,
    snapshot,
    lane,
    route,
    network,
    state,
    inventory,
    plan,
    directory,
    deadline,
    cancelled,
    disabled_rule_id=None,
):
    """Retain bounded native observations from an independently isolated worker."""
    from .runtime_audit_process import run_bounded_command
    from .deep_audit_io import write_run_json

    name = "factory-zap-worker-" + uuid.uuid4().hex
    try:
        with tempfile.TemporaryDirectory(prefix="factory-zap-route-") as temporary:
            scratch = Path(temporary)
            request = _zap_target_request(
                state, inventory, lane, route, deadline, disabled_rule_id
            )
            request_file, contract_file = (
                scratch / "request.json",
                scratch / "contract.json",
            )
            request_file.write_bytes(canonical_bytes(request))
            contract_file.write_bytes(
                canonical_bytes(
                    {
                        "schema": "factory.deep-adapter-input.v1",
                        "run_id": state["run_id"],
                        "manifest_sha256": state["manifest_sha256"],
                        "inventory": inventory,
                        "lane": lane,
                        "obligations": plan["obligations"],
                    }
                )
            )
            argv = _zap_worker_argv(
                base,
                lane,
                snapshot,
                name,
                network,
                state,
                inventory,
                contract_file,
                request_file,
            )
            output = scratch / "observation.json"
            errors = scratch / "worker-errors.txt"
            facts = run_bounded_command(
                argv,
                scratch,
                request["timeout_seconds"],
                scratch,
                stdout_path=output,
                stderr_path=errors,
                cancelled=cancelled,
            )
            write_run_json(
                directory,
                f"zap-process-{lane['id']}-{route['id']}.json",
                {
                    "request_sha256": digest(request),
                    "process": facts,
                    "diagnostic_code": _zap_worker_diagnostic(errors),
                },
            )
            if (
                facts["exit_code"] != 0
                or facts["timed_out"]
                or facts["output_limit_exceeded"]
                or facts.get("cancelled")
                or not facts["cleanup_confirmed"]
            ):
                raise RuntimeAuditError("E_ZAP_WORKER", "native route execution failed")
            observation = strict_json(output.read_bytes())
            _zap_host_observation(observation, request)
            retained = {
                "request": request,
                "observation": observation,
                "process": facts,
            }
            write_run_json(directory, f"zap-{lane['id']}-{route['id']}.json", retained)
            return {
                "route_id": route["id"],
                "observation_sha256": digest(observation),
                "process": facts,
            }
    finally:
        if not _container_cleanup(base, name):
            raise RuntimeAuditError(
                "E_CONTAINER_CLEANUP", "ZAP worker cleanup unverified"
            )


def _zap_worker_diagnostic(path):
    """Retain only bounded machine codes, never raw worker logs or paths."""
    import re

    if not path.exists():
        return None
    with path.open("rb") as stream:
        raw = stream.read(257)
    text = raw.strip().decode("ascii", errors="replace")
    return text if re.fullmatch(r"E_[A-Z0-9_]{1,100}", text) else None


def _zap_host_observation(observation, request):
    """Reverify native bytes instead of trusting the worker's verification label."""
    from .deep_audit_contract import _zap_target_url

    target = request["target"]
    route = next(item for item in target["routes"] if item["id"] == request["route_id"])
    origin = f"http://factory-target:{target['port']}"
    bindings = {
        key: request[key] for key in ("run_id", "candidate_sha256", "profile_sha256")
    }
    bindings["host_id"] = sha256_bytes(origin.encode())
    expected = {
        **bindings,
        "target_sha256": digest(target),
        "route_sha256": digest(route),
    }
    if not isinstance(observation, dict) or any(
        observation.get(k) != v for k, v in expected.items()
    ):
        raise RuntimeAuditError(
            "E_ZAP_BINDING", "native route observation identity differs"
        )
    if observation.get("target_url") != _zap_target_url(target, route):
        raise RuntimeAuditError("E_ZAP_BINDING", "native route URL differs")
    if observation.get("schema") != "factory.zap-native-observation.v1":
        raise RuntimeAuditError("E_ZAP_SCAN", "native observation schema differs")
    if observation.get("version") != {"version": "2.17.0"} or observation.get(
        "scan_status"
    ) != {"status": "100"}:
        raise RuntimeAuditError("E_ZAP_SCAN", "native version or completion differs")
    _zap_host_rule_evidence(observation, request, bindings)
    if (
        observation.get("cleanup_complete") is not True
        or observation.get("process_facts", {}).get("cleanup_confirmed") is not True
    ):
        raise RuntimeAuditError("E_ZAP_CLEANUP", "native process cleanup unverified")


def _zap_host_rule_evidence(observation, request, bindings):
    from .deep_audit_sarif import _verify_zap_native_rule_ledger

    expected_rules = _zap_host_expected_rules(request)
    if observation.get("disabled_rule_id") != request.get("disabled_rule_id"):
        raise RuntimeAuditError("E_ZAP_DISABLED", "disabled rule observation differs")
    if expected_rules:
        _verify_zap_native_rule_ledger(
            observation["native_ledger"].encode(),
            {"engine": "zap", "rule_ids": expected_rules},
            bindings,
        )
    elif observation.get("native_ledger") != "":
        raise RuntimeAuditError("E_ZAP_DISABLED", "disabled scan produced rule records")
    for key in ("effective_inventory_before", "effective_inventory_after"):
        from .deep_audit_io import _zap_enabled_inventory

        if _zap_enabled_inventory(observation[key]) != expected_rules:
            raise RuntimeAuditError("E_ZAP_INVENTORY", "native effective rules differ")


def _zap_host_expected_rules(request):
    rules = request["rule_ids"]
    disabled = request.get("disabled_rule_id")
    if disabled is not None and disabled not in rules:
        raise RuntimeAuditError("E_ZAP_MUTATION", "disabled rule is undeclared")
    return [rule for rule in rules if rule != disabled]


def _zap_report_projection(observation):
    """Canonical native findings, excluding volatile alert IDs and raw payloads."""
    from .deep_audit_io import _zap_enabled_inventory

    rows = observation.get("alerts", {}).get("alerts")
    if not isinstance(rows, list) or len(rows) > 10000:
        raise RuntimeAuditError("E_ZAP_REPORT", "bounded native alerts required")
    alerts = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeAuditError("E_ZAP_REPORT", "native alert object required")
        alert = {
            key: str(row.get(key, "")) for key in ("pluginId", "risk", "url", "param")
        }
        if any(len(value) > 4096 for value in alert.values()):
            raise RuntimeAuditError("E_ZAP_REPORT", "native alert field exceeds budget")
        alerts.append(alert)
    return {
        "schema": "factory.zap-report.v1",
        "enabled_rule_ids": _zap_enabled_inventory(
            observation["effective_inventory_after"]
        ),
        "alerts": sorted(alerts, key=canonical_bytes),
    }


def _zap_control_tree(source, destination, manifest):
    from .deep_audit_io import bound_bytes

    files = []
    for path, seal in manifest.items():
        raw = bound_bytes(source, {"path": path, "sha256": seal})
        target = destination.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        files.append(
            {"path": path, "sha256": seal, "bytes": len(raw), "language": "data"}
        )
    return {"candidate_sha256": digest(files), "files": files}


def _zap_control_observation(directory, lane, challenge):
    from .deep_audit_io import read_run_json

    retained = read_run_json(
        directory, f"zap-{lane['id']}-{challenge['zap_route_id']}.json"
    )
    _zap_host_observation(retained["observation"], retained["request"])
    report = _zap_report_projection(retained["observation"])
    if digest(report) != challenge["expected_report_sha256"]:
        raise RuntimeAuditError(
            "E_ZAP_CONTROL_REPORT", "control report differs from signed expectation"
        )
    if challenge["expected_exit_code"] != 0:
        raise RuntimeAuditError(
            "E_ZAP_CONTROL_EXIT", "native control requires successful process"
        )
    return report, retained


def _zap_execute_control(
    directory, state, snapshot, lane, obligation, challenge, deadline, emit
):
    """Execute only hash-bound fixture bytes in a fresh service and worker pair."""
    with tempfile.TemporaryDirectory(prefix="factory-zap-control-") as temporary:
        source = Path(temporary)
        inventory = _zap_control_tree(snapshot, source, challenge["fixture_manifest"])
        control_lane = {**lane, "native_target": challenge["zap_target"]}
        disabled = (
            obligation["detector_rule_id"] if challenge["kind"] == "mutation" else None
        )
        _execute_zap_target(
            directory,
            state,
            source,
            control_lane,
            inventory,
            {"obligations": [obligation]},
            emit,
            disabled_rule_id=disabled,
            route_id=challenge["zap_route_id"],
            deadline=deadline,
        )
        report, retained = _zap_control_observation(directory, control_lane, challenge)
        found = any(
            row["pluginId"] == obligation["detector_rule_id"]
            for row in report["alerts"]
        )
        if found != (challenge["kind"] == "positive"):
            raise RuntimeAuditError(
                "E_ZAP_CONTROL_ORACLE", "positive/safe/disabled oracle differs"
            )
        return {
            "report_sha256": digest(report),
            "observation_sha256": digest(retained["observation"]),
            "request_sha256": digest(retained["request"]),
            "execution": retained["process"],
        }


def _zap_execute_controls(directory, state, snapshot, lane, controls, deadline, emit):
    receipts = []
    for obligation in controls:
        for challenge in obligation["challenges"]:
            pair = []
            for attempt in ("primary", "replay"):
                case = directory / ("zap-control-" + uuid.uuid4().hex)
                case.mkdir()
                evidence = _zap_execute_control(
                    case, state, snapshot, lane, obligation, challenge, deadline, emit
                )
                pair.append(evidence)
            if pair[0]["report_sha256"] != pair[1]["report_sha256"]:
                raise RuntimeAuditError(
                    "E_ZAP_REPLAY", "independent native reports disagree"
                )
            receipts.append(
                {
                    "obligation_id": obligation["id"],
                    "rule_id": obligation["detector_rule_id"],
                    "kind": challenge["kind"],
                    "challenge_sha256": digest(challenge),
                    "primary": pair[0],
                    "replay": pair[1],
                }
            )
    return receipts


def _execute_zap_controlled_lane(
    directory, state, snapshot, lane, inventory, plan, emit
):
    from .deep_audit_io import write_run_json

    deadline = time.monotonic() + lane["timeout_seconds"]
    result = _execute_zap_target(
        directory, state, snapshot, lane, inventory, plan, emit, deadline=deadline
    )
    primary_report = _zap_candidate_report(directory, lane)
    result["report_sha256"] = digest(primary_report)
    result["findings"] = _zap_candidate_findings(primary_report, lane, inventory)
    try:
        return _zap_finish_controls(
            directory,
            state,
            snapshot,
            lane,
            inventory,
            plan,
            emit,
            deadline,
            result,
            primary_report,
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        result["gaps"] = [getattr(error, "code", "E_ZAP_CONTROL_EVIDENCE")]
        write_run_json(
            directory,
            f"zap-control-failure-{lane['id']}.json",
            {
                "code": result["gaps"][0],
                "report_sha256": result["report_sha256"],
                "candidate_sha256": inventory["candidate_sha256"],
            },
        )
        return result


def _zap_finish_controls(
    directory,
    state,
    snapshot,
    lane,
    inventory,
    plan,
    emit,
    deadline,
    result,
    primary_report,
):
    from .deep_audit_contract import _zap_control_obligations
    from .deep_audit_io import write_run_json

    controls = _zap_control_obligations(lane, plan["obligations"], snapshot)
    receipts = _zap_execute_controls(
        directory, state, snapshot, lane, controls, deadline, emit
    )
    replay_directory = directory / ("zap-candidate-replay-" + uuid.uuid4().hex)
    replay_directory.mkdir()
    replay = _execute_zap_target(
        replay_directory,
        state,
        snapshot,
        lane,
        inventory,
        plan,
        emit,
        deadline=deadline,
    )
    replay_report = _zap_candidate_report(replay_directory, lane)
    if primary_report != replay_report:
        raise RuntimeAuditError("E_ZAP_REPLAY", "candidate route reports disagree")
    write_run_json(directory, f"zap-controls-{lane['id']}.json", {"controls": receipts})
    result["native_execution"]["controls"] = receipts
    result["native_execution"]["candidate_replay"] = replay["native_execution"]
    result["obligations"] = [item["id"] for item in controls]
    result["gaps"] = _zap_source_trace_gaps(result, replay, lane)
    result["state"] = "INCOMPLETE" if result["gaps"] else "OBSERVED"
    return result


def _zap_source_trace_gaps(result, replay, lane):
    """Require actual, replayed line hits for every declared route/source pair."""
    primary = result["native_execution"].get("source_trace")
    repeated = replay["native_execution"].get("source_trace")
    if not primary or not repeated:
        return list(
            dict.fromkeys(
                item["native_execution"].get("source_trace_error")
                or "ZAP_SOURCE_ROUTE_COVERAGE_REQUIRED"
                for item in (result, replay)
            )
        )
    if primary["observations"] != repeated["observations"]:
        return ["ZAP_SOURCE_TRACE_REPLAY_MISMATCH"]
    measured = {
        (item["route_id"], item["path"])
        for item in primary["observations"]
        if item["lines"]
    }
    required = {
        (route["id"], path)
        for route in lane["native_target"]["routes"]
        for path in route["source_bindings"]
    }
    missing = sorted(required - measured)
    result["native_execution"]["source_trace_missing"] = [
        {"route_id": route_id, "path": path} for route_id, path in missing
    ]
    return ["ZAP_SOURCE_ROUTE_COVERAGE_REQUIRED"] if missing else []


def _zap_candidate_report(directory, lane):
    from .deep_audit_io import read_run_json

    reports = []
    for route in lane["native_target"]["routes"]:
        retained = read_run_json(directory, f"zap-{lane['id']}-{route['id']}.json")
        _zap_host_observation(retained["observation"], retained["request"])
        reports.append(
            {
                "route_id": route["id"],
                "report": _zap_report_projection(retained["observation"]),
            }
        )
    return reports


def _zap_candidate_findings(reports, lane, inventory):
    from .deep_audit_sarif import _execution_finding

    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    routes = {item["id"]: item for item in lane["native_target"]["routes"]}
    findings = []
    for report in reports:
        route = routes[report["route_id"]]
        for alert in report["report"]["alerts"]:
            for path in route["source_bindings"]:
                finding = _execution_finding(
                    lane, alert["pluginId"], path, 1, alert["risk"], sources
                )
                finding.update(
                    location_kind="declared_route_source_binding",
                    exact_source_line=False,
                    route_id=route["id"],
                    alert_sha256=digest(alert),
                )
                findings.append(finding)
    return findings


def _execute_zap_target(
    directory,
    state,
    snapshot,
    lane,
    inventory,
    plan,
    emit,
    *,
    disabled_rule_id=None,
    route_id=None,
    deadline=None,
):
    """Execute signed targets with separate filesystems and an internal network."""
    from .deep_audit_contract import _validate_zap_target

    target = lane["native_target"]
    _validate_zap_target(target, inventory)
    if route_id is not None and route_id not in {
        item["id"] for item in target["routes"]
    }:
        raise RuntimeAuditError("E_ZAP_ROUTE", "selected control route is undeclared")
    base = _docker_base()
    deadline = deadline or time.monotonic() + lane["timeout_seconds"]
    _docker_preflight(base, lane, deadline)
    _docker_preflight(base, {"image": target["image"]}, deadline)
    suffix = uuid.uuid4().hex
    network, app = "factory-zap-network-" + suffix, "factory-zap-app-" + suffix
    cancelled, stop = threading.Event(), threading.Event()
    monitor = threading.Thread(
        target=_monitor_lane,
        args=(directory, state, stop, cancelled, emit),
        daemon=True,
    )
    observations = []
    prepared_trace = _zap_prepare_trace(directory, state, inventory, lane, deadline)
    source_trace = None
    source_trace_error = None
    try:
        _zap_internal_network(base, network, deadline)
        facts, _ = _zap_docker_control(
            base,
            _zap_app_argv(
                base,
                lane,
                snapshot,
                app,
                network,
                prepared_trace[0] if prepared_trace else None,
            )[len(base) :],
            deadline,
        )
        if facts["exit_code"] != 0:
            raise RuntimeAuditError(
                "E_ZAP_TARGET", "pinned candidate service failed to start"
            )
        facts, raw = _zap_docker_control(
            base,
            ["container", "inspect", app, "--format", "{{json .State.Running}}"],
            deadline,
        )
        if facts["exit_code"] != 0 or raw.strip() != b"true":
            raise RuntimeAuditError(
                "E_ZAP_TARGET", "candidate service exited before scanning"
            )
        monitor.start()
        for route in target["routes"]:
            if route_id is not None and route["id"] != route_id:
                continue
            if cancelled.is_set():
                raise RuntimeAuditError("E_ZAP_CANCELLED", "target audit cancelled")
            observations.append(
                _zap_target_route(
                    base,
                    snapshot,
                    lane,
                    route,
                    network,
                    state,
                    inventory,
                    plan,
                    directory,
                    deadline,
                    cancelled,
                    disabled_rule_id,
                )
            )
        source_trace, source_trace_error = _zap_capture_trace_or_gap(
            base, app, directory, prepared_trace, inventory, snapshot, deadline
        )
    finally:
        stop.set()
        if monitor.ident is not None:
            monitor.join(timeout=2)
        # Cleanup receives its own bounded 15-second grace after the scan deadline.
        app_removed = _container_cleanup(base, app)
        network_removed = _zap_network_cleanup(base, network)
        if not (app_removed and network_removed) or monitor.is_alive():
            raise RuntimeAuditError(
                "E_ZAP_CLEANUP", "candidate service isolation cleanup unverified"
            )
    return {
        "lane_id": lane["id"],
        "state": "INCOMPLETE",
        "findings": [],
        "gaps": ["ZAP_SIGNED_CONTROLS_REQUIRED", "ZAP_INDEPENDENT_REPLAY_REQUIRED"],
        "native_execution": {
            "target_sha256": digest(target),
            "routes": observations,
            "cleanup_confirmed": True,
            "source_trace": source_trace,
            "source_trace_error": source_trace_error,
            "claim_boundary": (
                "DAST alone is route evidence. Optional source_trace records "
                "observed request-associated lines, not complete branches or "
                "tamperproof execution."
            ),
        },
    }


def _codeql_replay_result(
    result,
    base,
    lane,
    snapshot,
    bundle,
    inventory,
    run_id,
    cancelled,
    deadline,
    monitoring,
):
    return _native_replay_result(
        result,
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        run_id,
        cancelled,
        deadline,
        monitoring,
        "codeql",
        [],
    )


def _osv_replay_result(
    result,
    base,
    lane,
    snapshot,
    bundle,
    inventory,
    run_id,
    cancelled,
    deadline,
    monitoring,
    obligations,
):
    return _native_replay_result(
        result,
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        run_id,
        cancelled,
        deadline,
        monitoring,
        "osv",
        obligations,
    )


def _fuzz_replay_result(
    result,
    base,
    lane,
    snapshot,
    bundle,
    inventory,
    run_id,
    cancelled,
    deadline,
    monitoring,
    obligations=None,
):
    obligations = obligations if has_fuzz_controls(lane, inventory, obligations) else []
    return _native_replay_result(
        result,
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        run_id,
        cancelled,
        deadline,
        monitoring,
        "fuzz",
        obligations or [],
    )


def _fuzz_replay_argv(
    base,
    lane,
    snapshot,
    name,
    run_id,
    candidate,
    contract,
    runtime,
    timeout,
):
    return _codeql_replay_argv(
        base,
        lane,
        snapshot,
        name,
        run_id,
        candidate,
        contract,
        runtime,
        timeout,
        engine="fuzz",
    )


def _replay_fuzz_lane(
    base,
    lane,
    snapshot,
    bundle,
    inventory,
    run_id,
    cancelled,
    *,
    timeout_seconds=None,
    obligations=None,
):
    obligations = obligations if has_fuzz_controls(lane, inventory, obligations) else []
    return _replay_native_lane(
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        run_id,
        cancelled,
        timeout_seconds=timeout_seconds,
        engine="fuzz",
        obligations=obligations or [],
    )


def _fuzz_replay_receipt(raw, facts, request):
    from .deep_audit_io import _fuzz_replay_expected
    from .runtime_audit_common import (
        _validate_runner_facts,
        require_digest,
        require_int,
    )

    _validate_runner_facts(facts, facts["timeout_seconds"])
    if not _osv_replay_process_valid(raw, facts):
        raise RuntimeAuditError("E_FUZZ_REPLAY", "native replay execution failed")
    replay = strict_json(raw)
    expected = _fuzz_replay_expected(request)
    if not isinstance(replay, dict) or set(replay) != set(expected) | {
        "native_execution_sha256"
    }:
        raise RuntimeAuditError("E_FUZZ_REPLAY", "native replay fields differ")
    if any(replay.get(key) != value for key, value in expected.items()):
        raise RuntimeAuditError("E_FUZZ_REPLAY", "native replay binding differs")
    require_int(replay["replayed_inputs"], "replayed inputs", minimum=1, maximum=4096)
    require_digest(replay["native_execution_sha256"], "native replay invocation hash")
    return replay


def apply_fuzz_control_replay(result, replay, lane, bundle, inventory, obligations):
    """Validate the host receipt without changing the immutable worker bundle."""
    from .deep_audit_io import _fuzz_replay_expected
    from .runtime_audit_common import _validate_runner_facts, require_digest

    request = {
        "lane": lane,
        "inventory": inventory,
        "coverage": bundle["artifacts"][lane["coverage"]],
        "report": bundle["artifacts"][lane["report"]],
        "challenges": bundle["artifacts"][lane["challenge_report"]],
        "obligations": obligations,
    }
    expected = _fuzz_replay_expected(request)
    if any(replay.get(key) != value for key, value in expected.items()):
        raise RuntimeAuditError(
            "E_FUZZ_REPLAY", "control replay receipt binding differs"
        )
    _validate_fuzz_host_replay(replay, lane, _validate_runner_facts, require_digest)
    raw = (
        json.dumps(
            {**expected, "native_execution_sha256": replay["native_execution_sha256"]}
        )
        + "\n"
    ).encode()
    _fuzz_replay_receipt(raw, replay["execution"], request)
    cleared = {
        "FUZZ_NATIVE_REPLAY_REQUIRED",
        "FUZZ_CHALLENGE_REPLAY_REQUIRED",
        "OBLIGATION_COVERAGE_MISSING",
    }
    result["gaps"] = [gap for gap in result["gaps"] if gap not in cleared]
    result["obligations"] = expected["covered_obligations"]
    result["state"] = "INCOMPLETE" if result["gaps"] else "OBSERVED"
    return result


def has_fuzz_controls(lane, inventory, obligations):
    """Identify signed fuzz controls applicable to the current source inventory."""
    sources = {item["path"] for item in inventory["files"]}
    return lane.get("engine") == "atheris" and any(
        item.get("engine") == "atheris"
        and item.get("family") == "fuzz"
        and set(item.get("paths", [])) <= sources
        for item in (obligations or [])
    )


def _validate_fuzz_host_replay(replay, lane, validate_facts, validate_digest):
    facts = replay.get("execution", {})
    validate_facts(facts, facts["timeout_seconds"])
    if (
        replay.get("image") != lane["image"]
        or replay.get("cleanup_confirmed") is not True
        or not _osv_replay_process_valid_for_review(facts)
    ):
        raise RuntimeAuditError(
            "E_FUZZ_REPLAY", "control replay execution is incomplete"
        )
    for key in ("native_execution_sha256", "runtime_sha256", "command_sha256"):
        validate_digest(replay.get(key), key)


def _osv_replay_process_valid_for_review(facts):
    return (
        facts.get("exit_code") == 0
        and facts.get("cleanup_confirmed") is True
        and all(
            facts.get(key) is False
            for key in (
                "timed_out",
                "output_limit_exceeded",
                "launch_error",
                "cancelled",
            )
        )
    )


def _native_replay_result(
    result,
    base,
    lane,
    snapshot,
    bundle,
    inventory,
    run_id,
    cancelled,
    deadline,
    monitoring,
    engine,
    obligations,
):
    prefix = engine.upper()
    required_gap = f"{prefix}_NATIVE_REPLAY_REQUIRED"
    if (
        lane["engine"] != {"fuzz": "atheris"}.get(engine, engine)
        or required_gap not in result["gaps"]
    ):
        return result
    directory, state, emit = monitoring
    stop = threading.Event()
    monitor = threading.Thread(
        target=_monitor_lane,
        args=(directory, state, stop, cancelled, emit),
        daemon=True,
    )
    monitor.start()
    try:
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            raise RuntimeAuditError(
                f"E_{prefix}_REPLAY", "lane replay deadline exhausted"
            )
        replay_function = {
            "codeql": _replay_codeql_lane,
            "osv": _replay_osv_lane,
            "fuzz": _replay_fuzz_lane,
        }[engine]
        extra = {"obligations": obligations} if engine in {"osv", "fuzz"} else {}
        replay = replay_function(
            base,
            lane,
            snapshot,
            bundle,
            inventory,
            run_id,
            cancelled,
            timeout_seconds=remaining,
            **extra,
        )
        if not isinstance(replay, dict) or replay.get("state") != "VERIFIED":
            raise RuntimeAuditError(
                f"E_{prefix}_REPLAY", "independent replay is incomplete"
            )
        if cancelled.is_set() or time.monotonic() >= deadline:
            raise RuntimeAuditError(
                f"E_{prefix}_REPLAY", "lane replay deadline expired"
            )
        result[f"{engine}_replay"] = replay
        result["gaps"] = [gap for gap in result["gaps"] if gap != required_gap]
        if engine == "fuzz" and obligations:
            apply_fuzz_control_replay(
                result, replay, lane, bundle, inventory, obligations
            )
    except (RuntimeAuditError, OSError, ValueError, KeyError, TypeError) as error:
        result[f"{engine}_replay"] = {
            "state": "INCOMPLETE",
            "diagnostic_code": getattr(error, "code", f"E_{prefix}_REPLAY"),
            "evidence": getattr(error, "replay_evidence", None),
        }
        result["gaps"].append(f"{prefix}_NATIVE_REPLAY_FAILED")
    finally:
        stop.set()
        monitor.join(timeout=2)
    result["gaps"] = sorted(set(result["gaps"]))
    result["state"] = "INCOMPLETE" if result["gaps"] else "OBSERVED"
    return result


def _codeql_replay_runtime(scratch):
    root = scratch / "runtime"
    target = root / "factoryline"
    target.mkdir(parents=True)
    records = {}
    for name in (
        "__init__.py",
        "deep_audit_io.py",
        "deep_audit_sarif.py",
        "runtime_audit_common.py",
        "runtime_audit_process.py",
    ):
        raw = local_file(Path(__file__).parent, name).read_bytes()
        (target / name).write_bytes(raw)
        records[name] = sha256_bytes(raw)
    return root, digest(records)


def _codeql_replay_argv(
    base,
    lane,
    snapshot,
    name,
    run_id,
    candidate,
    contract,
    runtime,
    timeout,
    *,
    engine="codeql",
):
    if engine not in {"codeql", "osv", "fuzz"}:
        raise RuntimeAuditError("E_NATIVE_REPLAY", "unsupported replay engine")
    program = (
        "import sys,json;from pathlib import Path;"
        "sys.path.insert(0,'/factory-runtime');"
        f"from factoryline.deep_audit_io import execute_{engine}_native_replay,strict_json;"
        f"s=Path('/tmp/{engine}-replay');s.mkdir();"
        f"r=execute_{engine}_native_replay(strict_json(Path('/factory-contract.json').read_bytes()),"
        "Path('/src'),s,int(sys.argv[1]));print(json.dumps(r),flush=True)"
    )
    argv = _container_argv(
        base,
        {**lane, "argv": ["/usr/local/bin/python", "-I", "-c", program, str(timeout)]},
        snapshot,
        name,
        run_id,
        candidate,
        contract,
    )
    if "," in str(runtime):
        raise RuntimeAuditError(
            "E_MOUNT_PATH", "Docker runtime bind path cannot contain commas"
        )
    index = argv.index("--entrypoint")
    argv[index:index] = [
        "--mount",
        f"type=bind,source={runtime},target=/factory-runtime,readonly",
    ]
    return argv


def _osv_replay_argv(
    base, lane, snapshot, name, run_id, candidate, contract, runtime, timeout
):
    return _codeql_replay_argv(
        base,
        lane,
        snapshot,
        name,
        run_id,
        candidate,
        contract,
        runtime,
        timeout,
        engine="osv",
    )


def _replay_codeql_lane(
    base, lane, snapshot, bundle, inventory, run_id, cancelled, *, timeout_seconds=None
):
    return _replay_native_lane(
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        run_id,
        cancelled,
        timeout_seconds=timeout_seconds,
        engine="codeql",
        obligations=[],
    )


def _replay_osv_lane(
    base,
    lane,
    snapshot,
    bundle,
    inventory,
    run_id,
    cancelled,
    obligations,
    *,
    timeout_seconds=None,
):
    return _replay_native_lane(
        base,
        lane,
        snapshot,
        bundle,
        inventory,
        run_id,
        cancelled,
        timeout_seconds=timeout_seconds,
        engine="osv",
        obligations=obligations,
    )


def _replay_native_lane(
    base,
    lane,
    snapshot,
    bundle,
    inventory,
    run_id,
    cancelled,
    *,
    timeout_seconds,
    engine,
    obligations,
):
    from .runtime_audit_process import run_bounded_command

    timeout = lane["timeout_seconds"] if timeout_seconds is None else timeout_seconds
    deadline = time.monotonic() + timeout
    _docker_preflight(base, lane)
    name = f"factory-replay-{run_id}-{lane['id']}"
    request = {
        "lane": lane,
        "inventory": inventory,
        "coverage": bundle["artifacts"][lane["coverage"]],
        "report": bundle["artifacts"][lane["report"]],
    }
    if engine == "osv" or (engine == "fuzz" and obligations):
        request.update(
            challenges=bundle["artifacts"][lane["challenge_report"]],
            obligations=obligations,
        )
    with tempfile.TemporaryDirectory(prefix="factory-replay-") as temporary:
        scratch = Path(temporary)
        contract = scratch / "input.json"
        contract.write_bytes(canonical_bytes(request))
        runtime, runtime_sha = _codeql_replay_runtime(scratch)
        output = scratch / "replay.json"
        remaining = _native_replay_remaining(deadline, engine)
        argv_function = {
            "codeql": _codeql_replay_argv,
            "osv": _osv_replay_argv,
            "fuzz": _fuzz_replay_argv,
        }[engine]
        argv = argv_function(
            base,
            lane,
            snapshot,
            name,
            run_id,
            inventory["candidate_sha256"],
            contract,
            runtime,
            remaining,
        )
        try:
            facts = run_bounded_command(
                argv,
                scratch,
                _native_replay_remaining(deadline, engine),
                scratch,
                stdout_path=output,
                cancelled=cancelled,
            )
        finally:
            cleanup = _container_cleanup(base, name)
        try:
            if not cleanup:
                raise RuntimeAuditError(
                    "E_CONTAINER_CLEANUP", "replay cleanup could not be verified"
                )
            raw = output.read_bytes() if output.exists() else b""
            receipt = {
                "codeql": _codeql_replay_receipt,
                "osv": _osv_replay_receipt,
                "fuzz": _fuzz_replay_receipt,
            }[engine]
            replay = receipt(raw, facts, request)
            _native_replay_remaining(deadline, engine)
        except (RuntimeAuditError, OSError, ValueError, KeyError, TypeError) as error:
            error.replay_evidence = {
                "image": lane["image"],
                "runtime_sha256": runtime_sha,
                "command_sha256": digest(argv),
                "execution": facts,
                "cleanup_confirmed": cleanup,
            }
            raise
    replay.update(
        image=lane["image"],
        runtime_sha256=runtime_sha,
        command_sha256=digest(argv),
        execution=facts,
        cleanup_confirmed=True,
    )
    return replay


def _native_replay_remaining(deadline, engine):
    remaining = int(deadline - time.monotonic())
    if remaining < 1:
        raise RuntimeAuditError(
            f"E_{engine.upper()}_REPLAY", "replay deadline exhausted"
        )
    return remaining


def _codeql_replay_receipt(raw, facts, request):
    from .runtime_audit_common import _validate_runner_facts

    _validate_runner_facts(facts, facts["timeout_seconds"])
    if (
        facts["exit_code"] != 0
        or facts["timed_out"]
        or facts["launch_error"]
        or facts["output_limit_exceeded"]
        or not facts["cleanup_confirmed"]
        or facts.get("cancelled")
        or sha256_bytes(raw) != facts["stdout_sha256"]
    ):
        raise RuntimeAuditError("E_CODEQL_REPLAY", "native replay execution failed")
    replay = strict_json(raw)
    expected = {
        "schema": "factory.codeql-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": request["inventory"]["candidate_sha256"],
        "lane_sha256": digest(request["lane"]),
        "coverage_sha256": digest(request["coverage"]),
        "queries": len(request["lane"]["rule_ids"]),
        "source_paths": sorted(
            item["path"]
            for item in request["inventory"]["files"]
            if item["language"] in request["lane"]["languages"]
        ),
    }
    if any(replay.get(key) != value for key, value in expected.items()):
        raise RuntimeAuditError("E_CODEQL_REPLAY", "native replay binding differs")
    return replay


def _osv_replay_receipt(raw, facts, request):
    from .runtime_audit_common import _validate_runner_facts, require_digest

    _validate_runner_facts(facts, facts["timeout_seconds"])
    if not _osv_replay_process_valid(raw, facts):
        raise RuntimeAuditError("E_OSV_REPLAY", "native replay execution failed")
    replay = strict_json(raw)
    expected = _osv_replay_expected(request)
    if not isinstance(replay, dict) or set(replay) != set(expected) | {
        "native_execution_sha256"
    }:
        raise RuntimeAuditError("E_OSV_REPLAY", "native replay fields differ")
    if any(replay.get(key) != value for key, value in expected.items()):
        raise RuntimeAuditError("E_OSV_REPLAY", "native replay binding differs")
    require_digest(replay["native_execution_sha256"], "native replay invocation hash")
    return replay


def _osv_replay_process_valid(raw, facts):
    return (
        facts["exit_code"] == 0
        and not facts["timed_out"]
        and not facts["launch_error"]
        and not facts["output_limit_exceeded"]
        and facts["cleanup_confirmed"] is True
        and not facts.get("cancelled")
        and sha256_bytes(raw) == facts["stdout_sha256"]
        and len(raw) == facts["stdout_bytes"]
    )


def _osv_replay_expected(request):
    from .deep_audit_sarif import _native_execution_report, _osv_source_accounting

    lane, inventory = request["lane"], request["inventory"]
    required = {
        item["path"]: item["sha256"]
        for item in inventory["files"]
        if item["language"] in lane["languages"]
    }
    sources = {item["path"]: item["sha256"] for item in inventory["files"]}
    accounting = _osv_source_accounting(request["report"], required, lane["mode"])
    if accounting["state"] != "COMPLETE" or accounting != request["coverage"].get(
        "source_accounting"
    ):
        raise RuntimeAuditError("E_OSV_REPLAY", "primary source accounting differs")
    controls = _osv_replay_controls(request["obligations"], lane, required)
    return {
        "schema": "factory.osv-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": inventory["candidate_sha256"],
        "lane_sha256": digest(lane),
        "coverage_sha256": digest(request["coverage"]),
        "report_sha256": digest(request["report"]),
        "challenges_sha256": digest(request["challenges"]),
        "obligations_sha256": digest(request["obligations"]),
        "profile_sha256": request["coverage"]["profile_sha256"],
        "database_sha256": lane["native_policy"]["database_sha256"],
        "source_paths": sorted(required),
        "controls": controls,
        "findings_sha256": digest(
            _native_execution_report(request["report"], lane, sources)
        ),
        "source_accounting_sha256": digest(accounting),
    }


def _osv_replay_controls(obligations, lane, required):
    expected = [
        {"id": item["id"], "kind": challenge["kind"]}
        for item in obligations
        if item["engine"] == "osv"
        and item["family"] == lane["family"]
        and set(item["paths"]) <= set(required)
        for challenge in item["challenges"]
    ]
    rows = sorted(expected, key=lambda item: (item["id"], item["kind"]))
    if (
        not rows
        or len(rows) > 192
        or len({(r["id"], r["kind"]) for r in rows}) != len(rows)
    ):
        raise RuntimeAuditError(
            "E_OSV_REPLAY", "complete bounded control identities required"
        )
    return rows


def _run_lanes(
    root: Path,
    directory: Path,
    state: dict,
    snapshot: Path,
    inventory: dict,
    plan: dict,
    emit,
    authorize,
) -> None:
    for lane in plan["lanes"]:
        if (directory / "cancel.json").exists():
            state["gaps"].append(
                _execution_gap(
                    "CANCELLED", "Start a fresh retry of this exact candidate."
                )
            )
            break
        if (directory / "pause.json").exists():
            state["pause_requested"] = True
            break
        state["active_lane"] = lane["id"]
        _event(
            directory,
            state,
            "lane_started",
            {"lane_id": lane["id"], "engine": lane["engine"]},
            emit,
        )
        try:
            authorize()
            result = _execute_lane(
                root, directory, state, snapshot, lane, inventory, plan, emit
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            code = getattr(exc, "code", "E_WORKER_EVIDENCE")
            result = {
                "lane_id": lane["id"],
                "state": "INCOMPLETE",
                "findings": [],
                "gaps": [code],
            }
        result.update(engine=lane["engine"], family=lane["family"])
        state["lanes"].append(result)
        _record_failures(
            directory,
            state,
            lane["id"],
            result["gaps"],
            emit,
            execution=result.get("execution", {}),
        )
        for finding in result["findings"]:
            finding["rerun"] = [
                "factory",
                "deep-audit",
                "scan",
                "--root",
                str(root),
                "--manifest",
                "<operator-manifest>",
                "--manifest-sha256",
                state["manifest_sha256"],
                "--authorization",
                "<fresh-coordinator-authorization>",
                "--trust-root",
                "<operator-trust-root>",
                "--trust-root-sha256",
                plan["trust_root_sha256"],
            ]
            _event(directory, state, "finding_observed", finding, emit)
        _event(
            directory,
            state,
            "lane_completed",
            {
                "lane_id": lane["id"],
                "state": result["state"],
                "gaps": result["gaps"],
                "report_sha256": result.get("report_sha256"),
                "coverage_sha256": result.get("coverage_sha256"),
                "rule_accounting_sha256": result.get("rule_accounting_sha256"),
                "challenge_sha256": result.get("challenge_sha256"),
                "findings_sha256": digest(result["findings"]),
                "finding_ids": sorted(
                    item.get("finding_id", "") for item in result["findings"]
                ),
            },
            emit,
        )
        if "E_CONTAINER_CLEANUP" in result["gaps"]:
            state["gaps"].append(
                _execution_gap(
                    "E_CONTAINER_CLEANUP",
                    "Remove the named run container and verify its absence before retrying.",
                )
            )
            break
        if (directory / "pause.json").exists():
            state["pause_requested"] = True
            break


def _check_resume(
    root: Path,
    resume: str | None,
    manifest_sha256: str,
    plan: dict,
    request_reference: dict | None,
    read_run_json,
    run_directory,
) -> None:
    if not resume:
        return
    previous = deep_run_status(root, resume)
    if previous["observed_state"] == "RUNNING":
        raise RuntimeAuditError(
            "E_RESUME_ACTIVE", "Pause or stop the previous run before retrying"
        )
    if (
        previous["manifest_sha256"] != manifest_sha256
        or previous["candidate_sha256"] != plan["candidate_sha256"]
        or previous.get("request_sha256")
        != (request_reference.get("sha256") if request_reference else None)
        or previous.get("request_path")
        != (request_reference.get("path") if request_reference else None)
    ):
        raise RuntimeAuditError(
            "E_RESUME_DRIFT", "retry must bind the identical manifest and candidate"
        )


def _initial_run_state(
    run_id: str,
    resume: str | None,
    manifest_sha256: str,
    plan: dict,
    request_reference: dict | None,
    authorization_sha256: str,
) -> dict:
    return {
        "schema": "factory.deep-run.v1",
        "run_id": run_id,
        "state": "RUNNING",
        "candidate_sha256": plan["candidate_sha256"],
        "manifest_sha256": manifest_sha256,
        "manifest_content_sha256": digest(plan),
        "parent_run": resume,
        "authorization_sha256": authorization_sha256,
        "request_path": request_reference.get("path") if request_reference else None,
        "request_sha256": request_reference.get("sha256")
        if request_reference
        else None,
        "request_bytes": request_reference.get("bytes") if request_reference else None,
        "lanes": [],
        "gaps": [],
        "authority": "none",
        "release_approval": False,
    }


def _capture_and_execute(
    root: Path,
    directory: Path,
    state: dict,
    plan: dict,
    manifest_sha256: str,
    authorization: Path,
    trust_root: Path,
    trust_root_sha256: str,
    emit,
    verify_authorization,
    inventory_candidate,
    write_run_json,
) -> None:
    with tempfile.TemporaryDirectory(prefix="factory-source-") as temporary:
        # Canonicalize the trusted system temp parent (macOS /var is linked).
        # inventory_candidate still rejects caller-supplied linked snapshots.
        snapshot = Path(temporary).resolve(strict=True) / "src"
        snapshot.mkdir()
        inventory = inventory_candidate(root, snapshot)
        write_run_json(directory, "inventory.json", inventory)
        state["gaps"].extend(inventory["gaps"] + _scope_gaps(plan, inventory))
        if inventory["candidate_sha256"] != plan["candidate_sha256"]:
            state["gaps"].append(
                _execution_gap(
                    "CANDIDATE_DRIFT",
                    "Regenerate the plan against the current complete inventory.",
                )
            )
        # Rehash live inputs before execution so file changes during capture fail closed.
        recheck = inventory_candidate(root)
        if (
            recheck["candidate_sha256"] != inventory["candidate_sha256"]
            or recheck["gaps"] != inventory["gaps"]
        ):
            state["gaps"].append(
                _execution_gap(
                    "SNAPSHOT_DRIFT", "Stop source edits and retry snapshot capture."
                )
            )
        _event(
            directory,
            state,
            "inventory_completed",
            {
                "accounted_paths": inventory["accounted_paths"],
                "gap_count": len(state["gaps"]),
            },
            emit,
        )
        if not state["gaps"]:
            verify_authorization(
                plan, manifest_sha256, authorization, trust_root, trust_root_sha256
            )
            _run_lanes(
                root,
                directory,
                state,
                snapshot,
                inventory,
                plan,
                emit,
                lambda: verify_authorization(
                    plan,
                    manifest_sha256,
                    authorization,
                    trust_root,
                    trust_root_sha256,
                ),
            )
        final = inventory_candidate(root)
        if final["candidate_sha256"] != plan["candidate_sha256"] or final["gaps"]:
            state["gaps"].append(
                _execution_gap(
                    "SOURCE_CHANGED_DURING_RUN",
                    "Review the new candidate and rerun all affected analysis.",
                )
            )


def _finish_scan(
    directory: Path,
    state: dict,
    plan: dict,
    emit,
    write_run_json,
) -> dict:
    state.pop("active_lane", None)
    paused = (
        state.get("pause_requested", False) and not (directory / "cancel.json").exists()
    )
    state["state"] = "PAUSED" if paused else "INCOMPLETE"
    _record_failures(
        directory, state, None, [gap["code"] for gap in state["gaps"]], emit
    )
    state["analysis_complete"] = (
        not paused
        and not state["gaps"]
        and len(state["lanes"]) == len(plan["lanes"])
        and all(lane["state"] == "OBSERVED" for lane in state["lanes"])
    )
    state["review"] = "REQUIRED"
    _event(
        directory,
        state,
        "run_paused" if paused else "run_completed",
        {"analysis_complete": state["analysis_complete"], "review": "REQUIRED"},
        emit,
    )
    write_run_json(directory, "evidence.json", state)
    return state


def scan_deep_audit(
    root: Path,
    manifest: Path,
    manifest_sha256: str,
    *,
    authorization: Path,
    trust_root: Path,
    trust_root_sha256: str,
    request_file: Path | None = None,
    resume: str | None = None,
    emit=None,
) -> dict:
    """Explicit isolated execution; unsigned observations never establish readiness."""
    from .deep_audit_contract import load_execution_manifest
    from .deep_audit_io import (
        inventory_candidate,
        read_run_json,
        run_directory,
        write_run_json,
    )
    from .deep_audit_attestation import verify_execution_authorization, _execution_bytes

    root = Path(root).resolve()
    request_reference = _request_file_reference(root, request_file)
    plan = load_execution_manifest(manifest, manifest_sha256)
    _authorized, verified_authorization_sha256 = verify_execution_authorization(
        plan,
        manifest_sha256,
        authorization,
        trust_root,
        trust_root_sha256,
        return_envelope_sha256=True,
    )
    _check_resume(
        root,
        resume,
        manifest_sha256,
        plan,
        request_reference,
        read_run_json,
        run_directory,
    )
    run_id = uuid.uuid4().hex
    directory = run_directory(root, run_id, create=True)
    authorization_document = strict_json(_execution_bytes(authorization))
    authorization_sha256 = digest(authorization_document)
    if authorization_sha256 != verified_authorization_sha256:
        raise RuntimeAuditError(
            "E_EXECUTION_AUTHORIZATION_DRIFT",
            "authorization envelope changed after signature verification",
        )
    state = _initial_run_state(
        run_id, resume, manifest_sha256, plan, request_reference, authorization_sha256
    )
    write_run_json(directory, "manifest.json", plan)
    write_run_json(directory, "authorization.json", authorization_document)
    _event(
        directory,
        state,
        "run_started",
        {
            "candidate_sha256": plan["candidate_sha256"],
            "manifest_sha256": manifest_sha256,
            "manifest_content_sha256": digest(plan),
            "authorization_sha256": authorization_sha256,
            "parent_run": resume,
            "request": request_reference,
            "lane_ids": [item["id"] for item in plan["lanes"]],
            "rule_ids": {
                item["id"]: list(item.get("rule_ids", [])) for item in plan["lanes"]
            },
        },
        emit,
    )
    try:
        _capture_and_execute(
            root,
            directory,
            state,
            plan,
            manifest_sha256,
            authorization,
            trust_root,
            trust_root_sha256,
            emit,
            verify_execution_authorization,
            inventory_candidate,
            write_run_json,
        )
    except (OSError, ValueError, KeyError, TypeError, KeyboardInterrupt) as exc:
        state["gaps"].append(
            _execution_gap(
                getattr(exc, "code", "RUN_INTERRUPTED"),
                "Inspect run events, restore prerequisites, and start an exact-bound retry.",
            )
        )
    if request_reference is not None:
        try:
            current_request = _request_file_reference(root, request_file)
        except (OSError, RuntimeAuditError, ValueError, TypeError):
            current_request = None
        if current_request != request_reference:
            state["gaps"].append(
                _execution_gap(
                    "REQUEST_SOURCE_CHANGED",
                    "Restore the exact request file and rerun with a fresh request binding.",
                    request_reference["path"],
                )
            )
            _event(
                directory,
                state,
                "request_source_changed",
                {"request": request_reference},
                emit,
            )
    return _finish_scan(directory, state, plan, emit, write_run_json)


def _request_file_reference(root: Path, value: Path | None) -> dict | None:
    """Hash a bounded operator request file from the run's reserved local evidence area."""
    if value is None:
        return None
    from .deep_audit_io import local_file

    raw_path = Path(value)
    if raw_path.is_absolute():
        raise RuntimeAuditError(
            "E_REQUEST_PATH", "request file must use a workspace-relative path"
        )
    relative = raw_path.as_posix()
    if not relative.startswith(".factory/deep-runs/requests/"):
        raise RuntimeAuditError(
            "E_REQUEST_PATH",
            "request file must be stored under .factory/deep-runs/requests",
        )
    path = local_file(root, relative)
    before = path.stat()
    if before.st_size > 65_536:
        raise RuntimeAuditError("E_REQUEST_SIZE", "request file exceeds 65536 bytes")
    with path.open("rb") as stream:
        raw = stream.read(65_537)
    after = path.stat()
    identity_before = (
        before.st_size,
        before.st_mtime_ns,
        getattr(before, "st_ino", 0),
    )
    identity_after = (
        after.st_size,
        after.st_mtime_ns,
        getattr(after, "st_ino", 0),
    )
    if len(raw) > 65_536 or identity_before != identity_after:
        raise RuntimeAuditError(
            "E_REQUEST_CHANGED", "request changed or exceeded its size limit"
        )
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeAuditError(
            "E_REQUEST_ENCODING", "request file must be UTF-8"
        ) from exc
    if not decoded.strip() or "\x00" in decoded:
        raise RuntimeAuditError(
            "E_REQUEST_EMPTY", "request file must contain nonempty text"
        )
    return {"path": relative, "sha256": sha256_bytes(raw), "bytes": len(raw)}


def deep_run_status(root: Path, run_id: str) -> dict:
    """Read and verify state hashes only; never execute Git, Docker, or analyzers."""
    from .deep_audit_io import read_run_json, run_directory

    directory = run_directory(root, run_id)
    state = read_run_json(directory, "state.json")
    if state.get("run_id") != run_id or state.get("schema") != "factory.deep-run.v1":
        raise RuntimeAuditError("E_RUN_INTEGRITY", "run identity mismatch")
    sequence = state.get("sequence")
    if type(sequence) is not int or not 1 <= sequence <= 100_000:
        raise RuntimeAuditError("E_EVENT_INTEGRITY", "event sequence outside bounds")
    previous = None
    for index in range(1, sequence + 1):
        event = read_run_json(directory, f"event-{index:05d}.json")
        if (
            event.get("sequence") != index
            or event.get("run_id") != run_id
            or event.get("previous_sha256") != previous
        ):
            raise RuntimeAuditError("E_EVENT_INTEGRITY", "event chain mismatch")
        previous = digest(event)
    if previous != state["event_sha256"]:
        raise RuntimeAuditError("E_EVENT_INTEGRITY", "event head mismatch")
    # Self hashes are not authentication. Read-only status never promotes a run.
    return {
        **state,
        "state": "INCOMPLETE",
        "observed_state": state["state"],
        "authority": "none",
        "release_approval": False,
        "status_limit": "Unreviewed local observations; use review with explicitly pinned trust to verify readiness.",
    }


def _record_failures(
    directory: Path,
    state: dict,
    lane_id,
    codes: list,
    emit,
    *,
    execution: dict | None = None,
) -> None:
    """Persist failure identities and bounded process facts without raw secrets."""
    for code in codes:
        _event(
            directory,
            state,
            "failure_recorded",
            {
                "code": code,
                "lane_id": lane_id,
                "candidate_sha256": state["candidate_sha256"],
                "manifest_sha256": state["manifest_sha256"],
                "execution": execution or {},
                "resolution": "Inspect the lane evidence, repair prerequisites or code, and retry with fresh authorization.",
            },
            emit,
        )


def pause_deep_run(root: Path, run_id: str) -> dict:
    """Request worker termination; PAUSED is recorded only by the stopped runner."""
    from .deep_audit_io import run_directory, write_run_json

    state = deep_run_status(root, run_id)
    if state["observed_state"] != "RUNNING":
        return {"run_id": run_id, "state": "ALREADY_STOPPED", "authority": "none"}
    write_run_json(
        run_directory(root, run_id),
        "pause.json",
        {
            "run_id": run_id,
            "requested_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return {"run_id": run_id, "state": "PAUSE_REQUESTED", "authority": "none"}


def playback_deep_run(
    root: Path, run_id: str, *, after: int = 0, limit: int = 100
) -> dict:
    """Read a verified, bounded event page; playback never re-executes commands."""
    state = deep_run_status(root, run_id)
    return _playback_verified_page(root, run_id, state, after=after, limit=limit)


def _playback_verified_page(
    root: Path, run_id: str, state: dict, *, after: int, limit: int
) -> dict:
    from .deep_audit_io import read_run_json, run_directory

    if type(after) is not int or not 0 <= after <= state["sequence"]:
        raise RuntimeAuditError(
            "E_PLAYBACK_RANGE", "after must be an existing event cursor"
        )
    if type(limit) is not int or not 1 <= limit <= 500:
        raise RuntimeAuditError("E_PLAYBACK_RANGE", "limit must be between 1 and 500")
    end = min(state["sequence"], after + limit)
    directory = run_directory(root, run_id)
    events = [
        read_run_json(directory, f"event-{index:05d}.json")
        for index in range(after + 1, end + 1)
    ]
    return {
        "schema": "factory.deep-playback.v1",
        "run_id": run_id,
        "state": "OBSERVED",
        "observed_state": state["observed_state"],
        "events": events,
        "next_cursor": end,
        "has_more": end < state["sequence"],
        "authority": "none",
        "release_approval": False,
    }


def _lineage_accounting(coverage, result, definition, lane_id, item, gaps):
    accounting = coverage.get("rule_accounting")
    if not isinstance(accounting, dict):
        gaps.append(f"RULE_ACCOUNTING_MISSING:{lane_id}")
    else:
        digest_core = {
            key: value
            for key, value in accounting.items()
            if key != "accounting_sha256"
        }
        accounting_sha = accounting.get("accounting_sha256")
        if accounting_sha != digest(digest_core) or accounting_sha != result.get(
            "rule_accounting_sha256"
        ):
            gaps.append(f"RULE_ACCOUNTING_DIGEST_MISMATCH:{lane_id}")
        expected_ids = sorted(definition.get("rule_ids", []))
        observed_ids = sorted(
            row.get("rule_id", "")
            for row in accounting.get("rules", [])
            if isinstance(row, dict)
        )
        if expected_ids != observed_ids:
            gaps.append(f"RULE_INVENTORY_MISMATCH:{lane_id}")
        for row in accounting.get("rules", []):
            if not isinstance(row, dict):
                continue
            sources = row.get("sources", [])
            for source in sources if isinstance(sources, list) else []:
                if not isinstance(source, dict):
                    continue
                disposition = source.get("disposition", "unknown")
                if disposition != "executed":
                    gaps.append(
                        f"RULE_SOURCE_NOT_EXECUTED:{lane_id}:{row.get('rule_id')}:{source.get('path')}"
                    )
        # Keep the exact bounded digest-bearing ledger so lineage can
        # independently recompute its native accounting digest.
        item["rule_accounting"] = accounting


def _lineage_normalization(
    bundle, definition, inventory, run_id, result, lane_id, gaps, plan
):
    from .deep_audit_sarif import normalize_execution_bundle

    try:
        normalized = normalize_execution_bundle(
            bundle,
            definition,
            inventory,
            run_id,
            plan.get("obligations", []),
        )
        saved_findings = [
            {key: value for key, value in finding.items() if key != "rerun"}
            for finding in result.get("findings", [])
        ]
        if (
            any(
                normalized.get(key) != result.get(key)
                for key in (
                    "state",
                    "gaps",
                    "report_sha256",
                    "coverage_sha256",
                    "rule_accounting_sha256",
                    "challenge_sha256",
                )
            )
            or normalized.get("findings") != saved_findings
        ):
            gaps.append(f"NORMALIZED_LANE_BINDING_MISMATCH:{lane_id}")
    except (OSError, ValueError, KeyError, TypeError, RuntimeAuditError):
        gaps.append(f"LANE_NORMALIZATION_FAILED:{lane_id}")


def _lineage_lane(directory, lane_id, definition, result, inventory, run_id, plan):
    from .deep_audit_io import read_run_json

    gaps = []
    item = {
        "lane_id": lane_id,
        "engine": definition.get("engine"),
        "family": definition.get("family"),
        "state": result.get("state", "INCOMPLETE"),
        "gaps": sorted(result.get("gaps", [])),
        "finding_ids": sorted(
            finding.get("finding_id", "") for finding in result.get("findings", [])
        ),
        "findings_sha256": digest(result.get("findings", [])),
        "report_sha256": result.get("report_sha256"),
        "coverage_sha256": result.get("coverage_sha256"),
        "challenge_sha256": result.get("challenge_sha256"),
        "rule_accounting_sha256": result.get("rule_accounting_sha256"),
        "native_execution": result.get("native_execution"),
        "execution": result.get("execution"),
        "expected_rule_ids": sorted(definition.get("rule_ids", [])),
        "source_paths": sorted(result.get("covered_paths", [])),
        "rule_accounting": None,
    }
    try:
        bundle = read_run_json(directory, f"bundle-{lane_id}.json")
        coverage = bundle["artifacts"][definition["coverage"]]
        if digest(coverage) != result.get("coverage_sha256"):
            raise ValueError("coverage digest mismatch")
        _lineage_accounting(coverage, result, definition, lane_id, item, gaps)
        _lineage_normalization(
            bundle, definition, inventory, run_id, result, lane_id, gaps, plan
        )
    except (OSError, ValueError, KeyError, TypeError, RuntimeAuditError):
        gap = (
            "LANE_NORMALIZATION_INCOMPLETE"
            if item.get("native_execution")
            else "LANE_ARTIFACT_UNAVAILABLE"
        )
        gaps.append(f"{gap}:{lane_id}")
    if item["state"] != "OBSERVED" or item["gaps"]:
        gaps.append(f"LANE_INCOMPLETE:{lane_id}")
    return item, gaps


def _lineage_request(root, directory, status, gaps):
    from .deep_audit_io import read_run_json

    request_reference = None
    request_fields = (
        status.get("request_path"),
        status.get("request_sha256"),
        status.get("request_bytes"),
    )
    if any(value is not None for value in request_fields):
        try:
            request_reference = _request_file_reference(
                root, Path(status["request_path"])
            )
            if request_reference != {
                "path": status.get("request_path"),
                "sha256": status.get("request_sha256"),
                "bytes": status.get("request_bytes"),
            }:
                gaps.append("REQUEST_ARTIFACT_MISMATCH")
            started = read_run_json(directory, "event-00001.json")
            if (
                started.get("kind") != "run_started"
                or started.get("details", {}).get("request") != request_reference
            ):
                gaps.append("REQUEST_EVENT_BINDING_MISMATCH")
        except (OSError, ValueError, KeyError, TypeError, RuntimeAuditError):
            gaps.append("REQUEST_ARTIFACT_UNAVAILABLE")

    return request_reference


def _lineage_playback(root, run_id, status, gaps):
    event_rows = []
    cursor = 0
    while cursor < status["sequence"]:
        page = _playback_verified_page(root, run_id, status, after=cursor, limit=500)
        if not page["events"] or page["next_cursor"] <= cursor:
            gaps.append("PLAYBACK_CURSOR_DID_NOT_ADVANCE")
            break
        for event in page["events"]:
            event_rows.append(
                {
                    "sequence": event["sequence"],
                    "kind": event.get("kind"),
                    "event_sha256": digest(event),
                    "details_sha256": digest(event.get("details", {})),
                }
            )
        cursor = page["next_cursor"]
    playback = {
        "state": "OBSERVED" if cursor == status["sequence"] else "INCOMPLETE",
        "event_count": len(event_rows),
        "through_sequence": cursor,
        "has_more": cursor < status["sequence"],
        "events_sha256": digest(event_rows),
        "head_sha256": status["event_sha256"],
    }
    return event_rows, playback


def _lineage_authorization(directory, status, gaps):
    from .deep_audit_io import read_run_json

    try:
        authorization = read_run_json(directory, "authorization.json")
        if digest(authorization) != status.get("authorization_sha256"):
            gaps.append("RUN_AUTHORIZATION_BINDING_MISMATCH")
    except (OSError, ValueError, KeyError, TypeError, RuntimeAuditError):
        gaps.append("RUN_AUTHORIZATION_MISSING")


def _lineage_inputs(directory):
    from .deep_audit_io import read_run_json

    try:
        plan = read_run_json(directory, "manifest.json")
        inventory = read_run_json(directory, "inventory.json")
    except (OSError, ValueError, KeyError, TypeError, RuntimeAuditError):
        plan, inventory = {}, {"files": []}
        gaps = ["RUN_PLAN_OR_INVENTORY_MISSING"]
    else:
        gaps = []
    return plan, inventory, gaps


def _lineage_run(root: Path, run_id: str) -> tuple[dict, list[dict], list[dict]]:
    from .deep_audit_io import read_run_json, run_directory

    status = deep_run_status(root, run_id)
    directory = run_directory(root, run_id)
    plan, inventory, gaps = _lineage_inputs(directory)
    plan_lanes = {item["id"]: item for item in plan.get("lanes", [])}
    from .deep_audit_contract import EXECUTION_FAMILIES

    families = {item.get("family") for item in plan.get("lanes", [])}
    if families != set(EXECUTION_FAMILIES):
        gaps.append("SIX_LANE_FAMILY_SET_MISMATCH")
    results = {item["lane_id"]: item for item in status.get("lanes", [])}
    lanes = []
    if (
        digest(plan) != status.get("manifest_content_sha256")
        or plan.get("candidate_sha256") != status.get("candidate_sha256")
        or inventory.get("candidate_sha256") != status.get("candidate_sha256")
    ):
        gaps.append("RUN_PLAN_OR_CANDIDATE_BINDING_MISMATCH")
    _lineage_authorization(directory, status, gaps)
    for lane_id, definition in plan_lanes.items():
        result = results.get(lane_id)
        if result is None:
            gaps.append(f"LANE_NOT_RECORDED:{lane_id}")
            lanes.append({"lane_id": lane_id, "state": "NOT_RUN"})
            continue
        item, lane_gaps = _lineage_lane(
            directory, lane_id, definition, result, inventory, run_id, plan
        )
        lanes.append(item)
        gaps.extend(lane_gaps)
    if set(results) != set(plan_lanes):
        gaps.append("LANE_SET_MISMATCH")

    request_reference = _lineage_request(root, directory, status, gaps)
    event_rows, playback = _lineage_playback(root, run_id, status, gaps)
    pause_file = directory / "pause.json"
    pause_ref = None
    if pause_file.is_file():
        pause_ref = digest(read_run_json(directory, "pause.json"))
    run = {
        "run_id": run_id,
        "request_sha256": status.get("request_sha256"),
        "request_path": status.get("request_path"),
        "request_bytes": status.get("request_bytes"),
        "request_state": "BOUND" if request_reference else "NOT_CAPTURED",
        "observed_state": status["observed_state"],
        "analysis_complete": status.get("analysis_complete") is True,
        "candidate_sha256": status.get("candidate_sha256"),
        "manifest_sha256": status.get("manifest_sha256"),
        "manifest_content_sha256": status.get("manifest_content_sha256"),
        "authorization_sha256": status.get("authorization_sha256"),
        "parent_run": status.get("parent_run"),
        "event_sequence": status["sequence"],
        "event_sha256": status["event_sha256"],
        "events": event_rows,
        "playback": playback,
        "pause_request_sha256": pause_ref,
        "lanes": lanes,
        "findings_sha256": digest(
            [
                finding
                for result in status.get("lanes", [])
                for finding in result.get("findings", [])
            ]
        ),
    }
    if run["request_state"] != "BOUND":
        gaps.append("REQUEST_NOT_CAPTURED")
    if (
        status.get("gaps")
        or not run["analysis_complete"]
        or playback["state"] != "OBSERVED"
    ):
        gaps.append("RUN_INCOMPLETE")
    return run, gaps, event_rows


def _lineage_chain(references: list[dict]) -> tuple[list[dict], str]:
    previous = "0" * 64
    chain = []
    for index, reference in enumerate(references, 1):
        core = {"sequence": index, "previous_sha256": previous, **reference}
        row = {**core, "step_sha256": digest(core)}
        chain.append(row)
        previous = row["step_sha256"]
    return chain, previous


def _lineage_references(runs: list[dict], repair: dict | None) -> list[dict]:
    origin = (repair or {}).get("origin_audit")
    origin_id = origin.get("run_id") if isinstance(origin, dict) else None
    boundary = next(
        (index for index, run in enumerate(runs) if run["run_id"] == origin_id),
        len(runs) - 1,
    )
    before, after = runs[: boundary + 1], runs[boundary + 1 :]
    ordered_runs = [*before, *after] if repair is None else before
    refs = [
        {
            "reference_id": f"deep_run_event:{run['run_id']}:{event['sequence']}",
            "reference_sha256": event["event_sha256"],
            "state": "OBSERVED",
        }
        for run in ordered_runs
        for event in run.get("events", [])
    ]
    if repair is not None:
        refs.extend(
            {
                "reference_id": f"repair_attempt_event:{repair['approval_sha256']}:{event['sequence']}",
                "reference_sha256": event["event_sha256"],
                "state": "OBSERVED",
            }
            for event in repair.get("events", [])
        )
        refs.extend(
            {
                "reference_id": f"deep_run_event:{run['run_id']}:{event['sequence']}",
                "reference_sha256": event["event_sha256"],
                "state": "OBSERVED",
            }
            for run in after
            for event in run.get("events", [])
        )
    return refs


def _lineage_schema_errors(value: dict) -> list[str]:
    errors = []
    core = {key: item for key, item in value.items() if key != "lineage_sha256"}
    try:
        if value.get("lineage_sha256") != digest(core):
            errors.append("lineage receipt digest mismatch")
    except (TypeError, ValueError, RecursionError):
        errors.append("lineage receipt cannot be canonically encoded")
    expected = {
        "schema",
        "state",
        "runs",
        "repair",
        "gaps",
        "chain",
        "chain_head",
        "authority",
        "authentication",
    }
    if set(core) != expected:
        errors.append("lineage receipt has missing or unknown fields")
    return errors


def _lineage_reference_errors(value: dict) -> list[str]:
    try:
        runs = value.get("runs") if isinstance(value.get("runs"), list) else []
        repair = value.get("repair") if isinstance(value.get("repair"), dict) else None
        chain, head = _lineage_chain(_lineage_references(runs, repair))
    except (TypeError, ValueError, KeyError, AttributeError):
        return ["lineage references are malformed"]
    if chain != value.get("chain") or head != value.get("chain_head"):
        return ["lineage reference chain mismatch"]
    return []


def _lineage_boundary_errors(value: dict) -> list[str]:
    errors = []
    authority = {
        "execution": False,
        "approval": False,
        "merge": False,
        "deployment": False,
        "signing": False,
    }
    if value.get("authority") != authority:
        errors.append("lineage authority boundary changed")
    if value.get("authentication") != "UNSIGNED_INTEGRITY_ONLY":
        errors.append("lineage authentication boundary changed")
    if value.get("state") not in {"INCOMPLETE", "LINEAGE_BOUND_UNAUTHENTICATED"}:
        errors.append("lineage state is unsupported")
    gaps = value.get("gaps")
    if not isinstance(gaps, list) or any(not isinstance(gap, str) for gap in gaps):
        errors.append("lineage gap list is malformed")
    return errors


def _lineage_lane_accounting_valid(lane: dict) -> bool:
    accounting = lane.get("rule_accounting")
    rules = accounting.get("rules") if isinstance(accounting, dict) else None
    if (
        not isinstance(accounting, dict)
        or accounting.get("schema") != "factory.deep-rule-accounting.v1"
        or not isinstance(rules, list)
        or not rules
    ):
        return False
    expected_ids = lane.get("expected_rule_ids")
    source_paths = lane.get("source_paths")
    if not _string_list(expected_ids) or not _string_list(source_paths):
        return False
    ids = [rule.get("rule_id") for rule in rules if isinstance(rule, dict)]
    if (
        len(ids) != len(rules)
        or sorted(ids) != expected_ids
        or len(set(ids)) != len(ids)
    ):
        return False
    if any(not _lineage_rule_sources(rule, source_paths) for rule in rules):
        return False
    return _lineage_accounting_digest_valid(accounting, lane)


def _string_list(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item for item in value)
        and len(set(value)) == len(value)
    )


def _lineage_rule_sources(rule: object, expected_paths: list[str]) -> bool:
    sources = rule.get("sources") if isinstance(rule, dict) else None
    if not isinstance(sources, list) or not sources:
        return False
    paths = [source.get("path") for source in sources if isinstance(source, dict)]
    if len(paths) != len(sources) or sorted(paths) != expected_paths:
        return False
    if len(set(paths)) != len(paths):
        return False
    return all(_lineage_source_executed(source) for source in sources)


def _lineage_source_executed(source: dict) -> bool:
    return (
        isinstance(source.get("path"), str)
        and bool(source["path"])
        and source.get("disposition") == "executed"
        and _valid_digest(source.get("source_sha256"))
        and _valid_digest(source.get("evidence_sha256"))
    )


def _lineage_accounting_digest_valid(accounting: dict, lane: dict) -> bool:
    core = {
        key: value for key, value in accounting.items() if key != "accounting_sha256"
    }
    return (
        accounting.get("accounting_sha256") == digest(core)
        and accounting.get("accounting_sha256") == lane.get("rule_accounting_sha256")
        and _valid_digest(accounting.get("ruleset_sha256"))
        and _valid_digest(accounting.get("invocation_sha256"))
        and _valid_digest(accounting.get("native_report_sha256"))
    )


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _lineage_lane_complete(lane: object) -> bool:
    if not isinstance(lane, dict):
        return False
    return lane.get("state") == "OBSERVED" and _lineage_lane_accounting_valid(lane)


def _lineage_complete_run_errors(run: object) -> list[str]:
    if not isinstance(run, dict):
        return ["complete lineage contains malformed run evidence"]
    errors = []
    if run.get("request_state") != "BOUND" or not run.get("analysis_complete"):
        errors.append("complete lineage lacks a bound request or six-lane result")
    lanes = run.get("lanes") if isinstance(run.get("lanes"), list) else []
    from .deep_audit_contract import ENGINE_FAMILIES, EXECUTION_FAMILIES

    if any(not isinstance(lane, dict) for lane in lanes):
        return ["complete lineage contains malformed lane evidence"]
    families = {lane.get("family") for lane in lanes}
    engines = {lane.get("engine") for lane in lanes}
    if (
        not lanes
        or len(engines) != len(lanes)
        or families != EXECUTION_FAMILIES
        or any(
            ENGINE_FAMILIES.get(lane.get("engine")) != lane.get("family")
            for lane in lanes
        )
        or any(not _lineage_lane_complete(lane) for lane in lanes)
    ):
        errors.append("complete lineage lacks executed per-rule evidence")
    return errors


def _lineage_complete_errors(value: dict) -> list[str]:
    if value.get("state") != "LINEAGE_BOUND_UNAUTHENTICATED":
        return []
    errors = []
    runs, repair = value.get("runs"), value.get("repair")
    if (
        value.get("gaps")
        or not isinstance(repair, dict)
        or not isinstance(runs, list)
        or len(runs) < 2
    ):
        errors.append("complete lineage state lacks required phase evidence")
    if isinstance(runs, list):
        for run in runs:
            errors.extend(_lineage_complete_run_errors(run))
    if isinstance(repair, dict) and (
        repair.get("attempt_status") != "VERIFIED"
        or repair.get("cleanup_confirmed") is not True
        or repair.get("primary_checkout_unchanged") is not True
        or not repair.get("candidate_after_sha256")
        or repair.get("candidate_after_sha256") != repair.get("rerun_candidate_sha256")
    ):
        errors.append("complete lineage lacks an exact verified repair rerun")
    return errors


def verify_deep_audit_lineage(value: object) -> dict:
    """Check lineage receipt structure, chain hashes, and unsigned authority boundary."""
    if (
        not isinstance(value, dict)
        or value.get("schema") != "factory.deep-audit-lineage.v1"
    ):
        return {"valid": False, "errors": ["unsupported lineage schema"]}
    try:
        errors = _lineage_schema_errors(value)
        errors.extend(_lineage_reference_errors(value))
        errors.extend(_lineage_boundary_errors(value))
        errors.extend(_lineage_complete_errors(value))
    except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
        errors = ["lineage receipt is malformed"]
    return {"valid": not errors, "errors": errors}


def _ordered_lineage_runs(
    workspace: Path, run_ids: list[str]
) -> tuple[list[dict], list[str]]:
    runs, gaps = [], []
    for index, run_id in enumerate(run_ids):
        run, run_gaps, _events = _lineage_run(workspace, run_id)
        expected_parent = run_ids[index - 1] if index else None
        if run.get("parent_run") and run["parent_run"] != expected_parent:
            run_gaps.append("RESUME_PARENT_NOT_IN_ORDERED_LINEAGE")
        runs.append(run)
        gaps.extend(run_gaps)
    return runs, gaps


def _repair_origin_gaps(
    origin: object, origin_run: dict | None, attempt: dict
) -> list[str]:
    gaps = []
    if origin_run is None or not isinstance(origin, dict):
        gaps.append("REPAIR_ORIGIN_NOT_IN_LINEAGE")
    elif any(
        origin.get(key) != origin_run.get(run_key)
        for key, run_key in (
            ("candidate_sha256", "candidate_sha256"),
            ("manifest_sha256", "manifest_sha256"),
            ("event_sha256", "event_sha256"),
            ("sequence", "event_sequence"),
        )
    ):
        gaps.append("REPAIR_ORIGIN_BINDING_MISMATCH")
    if attempt.get("candidate_before_sha256") != (origin or {}).get("candidate_sha256"):
        gaps.append("REPAIR_SOURCE_CANDIDATE_MISMATCH")
    return gaps


def _repair_rerun(
    runs: list[dict], origin_run: dict | None, attempt: dict
) -> dict | None:
    if origin_run is None:
        return None
    index = next(
        i for i, run in enumerate(runs) if run["run_id"] == origin_run["run_id"]
    )
    later = [run for run in runs[index + 1 :]]
    return later[-1] if later else None


def _repair_attempt_gaps(attempt: dict, rerun: dict | None) -> list[str]:
    gaps = []
    if rerun is None or rerun.get("candidate_sha256") != attempt.get(
        "candidate_after_sha256"
    ):
        gaps.append("REPAIRED_CANDIDATE_RERUN_MISSING_OR_MISMATCHED")
    checks = attempt.get("checks", [])
    if (
        attempt.get("status") != "VERIFIED"
        or attempt.get("cleanup_confirmed") is not True
        or attempt.get("primary_checkout_unchanged") is not True
        or not checks
        or any(check.get("result") != "PASS" for check in checks)
    ):
        gaps.append("REPAIR_EXECUTION_OR_CHECKS_INCOMPLETE")
    return gaps


def _repair_check_rows(checks: list[dict]) -> list[dict]:
    fields = (
        "check_id",
        "stage",
        "result",
        "log_sha256",
        "container_cleanup_confirmed",
        "process_cleanup_confirmed",
    )
    return [
        {key: item.get(key, "UNKNOWN" if key == "result" else None) for key in fields}
        for item in checks
    ]


def _repair_event_rows(events: list[dict]) -> list[dict]:
    return [
        {key: item[key] for key in ("sequence", "event_sha256", "state_sha256")}
        for item in events
    ]


def _repair_lineage_payload(
    approval_sha: str, approval: dict, journal: dict, origin: object, rerun: dict | None
) -> dict:
    attempt = journal["state"]
    return {
        "approval_sha256": approval_sha,
        "approval_schema": approval.get("schema"),
        "confirmation_sha256": approval.get("confirmation_sha256"),
        "approved_at": approval.get("approved_at"),
        "expires_at": approval.get("expires_at"),
        "origin_audit": origin,
        "attempt_status": attempt.get("status"),
        "attempt_event_sequence": attempt.get("event_sequence"),
        "attempt_event_sha256": journal["event_sha256"],
        "candidate_before_sha256": attempt.get("candidate_before_sha256"),
        "candidate_after_sha256": attempt.get("candidate_after_sha256"),
        "rerun_candidate_sha256": rerun.get("candidate_sha256") if rerun else None,
        "events": _repair_event_rows(journal["events"]),
        "checks": _repair_check_rows(attempt.get("checks", [])),
        "cleanup_confirmed": attempt.get("cleanup_confirmed"),
        "primary_checkout_unchanged": attempt.get("primary_checkout_unchanged"),
        "rerun_run_id": rerun.get("run_id") if rerun else None,
    }


def _load_lineage_repair(
    workspace: Path, runs: list[dict], run_gaps: list[str], approval_sha: str
) -> dict | None:
    from .repair_sandbox import (
        RepairSandboxError,
        _digest as valid_approval_digest,
        _approval_paths,
        _read_approval,
        _verify_approval,
        verify_repair_attempt_journal,
    )
    from .deep_audit_io import local_file

    try:
        if not valid_approval_digest(approval_sha):
            raise RepairSandboxError(
                "REPAIR_ATTEMPT_INVALID", "approval hash is invalid"
            )
        path, _ = _approval_paths(workspace, approval_sha)
        approval = _read_approval(
            local_file(workspace, path.relative_to(workspace).as_posix())
        )
        if _verify_approval(approval) != approval_sha:
            raise RepairSandboxError(
                "REPAIR_APPROVAL_TAMPERED", "approval hash mismatch"
            )
        origin = approval.get("origin_audit")
        origin_run = next(
            (
                run
                for run in runs
                if isinstance(origin, dict) and run["run_id"] == origin.get("run_id")
            ),
            None,
        )
        journal = verify_repair_attempt_journal(workspace, approval_sha)
        attempt = journal["state"]
        run_gaps.extend(_repair_origin_gaps(origin, origin_run, attempt))
        rerun = _repair_rerun(runs, origin_run, attempt)
        run_gaps.extend(_repair_attempt_gaps(attempt, rerun))
        return _repair_lineage_payload(approval_sha, approval, journal, origin, rerun)
    except (OSError, ValueError, KeyError, TypeError, RepairSandboxError) as exc:
        run_gaps.append(
            f"REPAIR_EVIDENCE_UNAVAILABLE:{getattr(exc, 'code', 'INVALID')}"
        )
        return None


def _lineage_receipt(runs: list[dict], repair: dict | None, gaps: list[str]) -> dict:
    complete = not gaps and repair is not None and bool(runs)
    references = _lineage_references(runs, repair)
    chain, head = _lineage_chain(references)
    body = {
        "schema": "factory.deep-audit-lineage.v1",
        "state": "LINEAGE_BOUND_UNAUTHENTICATED" if complete else "INCOMPLETE",
        "runs": runs,
        "repair": repair,
        "gaps": sorted(set(gaps)),
        "chain": chain,
        "chain_head": head,
        "authority": {
            "execution": False,
            "approval": False,
            "merge": False,
            "deployment": False,
            "signing": False,
        },
        "authentication": "UNSIGNED_INTEGRITY_ONLY",
    }
    value = {**body, "lineage_sha256": digest(body)}
    validation = verify_deep_audit_lineage(value)
    if not validation["valid"]:
        raise RuntimeAuditError("E_LINEAGE_INTEGRITY", "; ".join(validation["errors"]))
    return value


def build_deep_audit_lineage(
    root: Path, run_ids: list[str], *, approval_sha256: str | None = None
) -> dict:
    """Bind run, repair, check and rerun references without granting authority."""
    workspace = Path(root).resolve()
    if not 1 <= len(run_ids) <= 20 or len(set(run_ids)) != len(run_ids):
        raise RuntimeAuditError(
            "E_LINEAGE_RUNS", "provide 1 to 20 unique ordered run IDs"
        )
    runs, gaps = _ordered_lineage_runs(workspace, run_ids)
    repair = (
        _load_lineage_repair(workspace, runs, gaps, approval_sha256)
        if approval_sha256
        else None
    )
    if repair is None:
        gaps.append("REPAIR_NOT_BOUND")
    return _lineage_receipt(runs, repair, gaps)


def _lineage_output_directory(workspace: Path) -> Path:
    directory = workspace
    for part in (".factory", "deep-lineage"):
        child = directory / part
        if not child.exists() and not child.is_symlink():
            child.mkdir()
        info = child.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeAuditError(
                "E_LINEAGE_PATH", "lineage directory must not be linked"
            )
        directory = child
    return directory


def _write_lineage_file(target: Path, value: dict) -> None:
    if target.exists() or target.is_symlink():
        info = target.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RuntimeAuditError(
                "E_LINEAGE_PATH", "lineage receipt must be a regular file"
            )
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def write_deep_audit_lineage(
    root: Path, run_ids: list[str], *, approval_sha256: str | None = None
) -> dict:
    """Persist one content-addressed lineage receipt inside the workspace safely."""
    workspace = Path(root).resolve()
    value = build_deep_audit_lineage(
        workspace, run_ids, approval_sha256=approval_sha256
    )
    directory = _lineage_output_directory(workspace)
    target = directory / f"{value['lineage_sha256']}.json"
    _write_lineage_file(target, value)
    return {**value, "receipt_path": target.relative_to(workspace).as_posix()}


def cancel_deep_run(root: Path, run_id: str) -> dict:
    """Request cooperative cancellation of one verified local execution run."""
    from .deep_audit_io import run_directory, write_run_json

    directory = run_directory(root, run_id)
    state = deep_run_status(root, run_id)
    if state["observed_state"] != "RUNNING":
        return {"run_id": run_id, "state": "ALREADY_STOPPED", "authority": "none"}
    write_run_json(
        directory,
        "cancel.json",
        {"run_id": run_id, "requested_at": datetime.now(timezone.utc).isoformat()},
    )
    return {"run_id": run_id, "state": "CANCELLATION_REQUESTED", "authority": "none"}


def execution_repairs(
    root: Path, run_id: str, *, before_run: str | None = None
) -> dict:
    """Expose durable resolution tasks; disappearance alone never verifies repair."""
    current = deep_run_status(root, run_id)
    findings = [dict(item) for lane in current["lanes"] for item in lane["findings"]]
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda item: (ranks.get(item["severity"], 0), item["finding_id"]))
    gaps = list(current["gaps"])
    for lane in current["lanes"]:
        for code in lane["gaps"]:
            gaps.append(
                _execution_gap(
                    code,
                    "Resolve this analyzer prerequisite, inspect its bound report, and rerun the signed scan.",
                    lane["lane_id"],
                )
            )
    comparison = None
    if before_run:
        previous = deep_run_status(root, before_run)
        before_ids = {
            item["finding_id"]
            for lane in previous["lanes"]
            for item in lane["findings"]
        }
        after_ids = {item["finding_id"] for item in findings}
        comparison = {
            "before_run": before_run,
            "disappeared_pending_verification": sorted(before_ids - after_ids),
            "introduced": sorted(after_ids - before_ids),
            "remaining": sorted(before_ids & after_ids),
            "resolved": [],
            "reason": "Independent signed review and regression evidence are required to close a repair.",
        }
    return {
        "schema": "factory.deep-resolution-queue.v1",
        "run_id": run_id,
        "candidate_sha256": current["candidate_sha256"],
        "state": "INCOMPLETE",
        "findings": findings,
        "coverage_tasks": gaps,
        "comparison": comparison,
        "review": "REQUIRED",
        "authority": "none",
        "release_approval": False,
    }


SCHEMA = "factory.deep-audit-receipt.v1"
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _reports(plan: dict, supplied: list, field: str) -> dict:
    expected = {item["id"]: item for item in plan["analyzers"]}
    found = {}
    for report in supplied:
        body = {
            key: value for key, value in report.items() if key != "normalized_sha256"
        }
        identity = report["analyzer"]
        key = identity["id"]
        if (
            report.get("schema") != "factory.deep-sarif.v1"
            or report.get("authority") != "none"
        ):
            raise RuntimeAuditError("E_DEEP_REPORT", "unexpected normalized report")
        if (
            key not in expected
            or key in found
            or digest(body) != report.get("normalized_sha256")
        ):
            raise RuntimeAuditError(
                "E_DEEP_REPORT", "duplicate, unknown or modified report"
            )
        declared = expected[key]
        if (
            identity != {name: declared[name] for name in ("id", "driver", "version")}
            or report["report_sha256"] != declared[field]["sha256"]
        ):
            raise RuntimeAuditError(
                "E_DEEP_REPORT", "report differs from signed binding"
            )
        found[key] = report
    if set(found) != set(expected):
        raise RuntimeAuditError(
            "E_ANALYZER_INCOMPLETE", "required analyzer evidence missing"
        )
    return found


def _action(code: str, rule: dict | None = None, finding: dict | None = None) -> dict:
    rule, finding = rule or {}, finding or {}
    locations = finding.get("locations", [])
    return {
        "code": code,
        "severity": rule.get("severity", "high"),
        "rule_id": rule.get("id", finding.get("rule_id", "")),
        "obligation_id": rule.get("obligation_id", ""),
        "finding_id": finding.get("finding_id", ""),
        "path": locations[0]["path"] if locations else "",
        "remediation": rule.get(
            "remediation",
            "Restore independently produced evidence and request policy-owner review.",
        ),
        "consequence": rule.get(
            "consequence", "The supplied evidence cannot justify readiness."
        ),
    }


def _canary_actions(plan: dict, reports: dict) -> list:
    actions = []
    for canary in plan["canaries"]:
        findings = reports[canary["analyzer_id"]]["findings"]
        detected = any(
            item["rule_id"] == canary["rule_id"]
            and item["native_fingerprint_sha256"] == canary["fingerprint_sha256"]
            and item["kind"] == "fail"
            and item["baseline"] != "absent"
            and not item["suppressed"]
            for item in findings
        )
        if not detected:
            action = _action("HOLLOW_DEEP_AUDIT")
            action["canary_id"] = canary["id"]
            action["analyzer_id"] = canary["analyzer_id"]
            actions.append(action)
    return actions


def _ordered_source_sink(flows: list) -> bool:
    for flow in flows:
        source_seen = False
        for step in flow:
            if source_seen and "sink" in step["kinds"]:
                return True
            source_seen = source_seen or "source" in step["kinds"]
    return False


def _finding_actions(rule: dict | None, finding: dict) -> list:
    actions = []
    approved = (
        rule is not None
        and finding["native_fingerprint_sha256"] in rule["allowed_suppressions"]
    )
    if finding["suppressed"] and not approved:
        actions.append(_action("DEEP_SUPPRESSION_UNAPPROVED", rule, finding))
    if rule is None:
        if finding["level"] == "error" and finding["baseline"] in {
            "new",
            "updated",
            "unbaselined",
        }:
            actions.append(_action("DEEP_UNKNOWN_ERROR", None, finding))
        return actions
    if finding["trace_depth"] < rule["min_trace_steps"] or (
        rule["require_source_sink"] and not _ordered_source_sink(finding["flows"])
    ):
        actions.append(_action("DEEP_TRACE_INCOMPLETE", rule, finding))
    return actions


def _clusters(findings: list) -> list:
    grouped = defaultdict(list)
    for finding in findings:
        if finding.get("obligation_id"):
            for path in {item["path"] for item in finding["locations"]}:
                grouped[path].append(finding)
    clusters = []
    for path, members in sorted(grouped.items()):
        obligations = defaultdict(list)
        for finding in members:
            obligations[finding["obligation_id"]].append(finding)
        for obligation, same in sorted(obligations.items()):
            if len({item["analyzer_id"] for item in same}) > 1:
                clusters.append(
                    {
                        "kind": "corroboration",
                        "path": path,
                        "obligation_id": obligation,
                        "findings": sorted(item["finding_id"] for item in same),
                        "claim": "routing_signal_not_causation",
                    }
                )
        if len({item["category"] for item in members}) > 1:
            clusters.append(
                {
                    "kind": "compound_risk",
                    "path": path,
                    "findings": sorted(item["finding_id"] for item in members),
                    "claim": "routing_signal_not_causation",
                }
            )
    return clusters


def _collect_findings(plan: dict, target: dict, actions: list) -> tuple:
    aliases = {
        (alias["analyzer_id"], alias["rule_id"]): rule
        for rule in plan["rules"]
        for alias in rule["aliases"]
    }
    findings, counts = [], defaultdict(list)
    for analyzer_id in sorted(target):
        for original in target[analyzer_id]["findings"]:
            finding = dict(original)
            rule = aliases.get((analyzer_id, finding["rule_id"]))
            actions.extend(_finding_actions(rule, finding))
            if rule:
                finding.update(
                    obligation_id=rule["obligation_id"],
                    category=rule["category"],
                    severity=rule["severity"],
                )
                counts[rule["id"]].append(finding)
            findings.append(finding)
            if len(findings) > 20_000 or len(actions) > 20_000:
                raise RuntimeAuditError(
                    "E_DEEP_LIMIT", "aggregate finding or action limit exceeded"
                )
    return findings, counts


def _threshold_actions(plan: dict, counts: dict) -> list:
    actions = []
    for rule in plan["rules"]:
        items = counts[rule["id"]]
        introduced = sum(
            item["baseline"] in {"new", "updated", "unbaselined"} for item in items
        )
        if len(items) > rule["max_total"] or introduced > rule["max_new"]:
            action = _action("DEEP_RULE_THRESHOLD", rule)
            action.update(
                total=len(items),
                introduced=introduced,
                max_total=rule["max_total"],
                max_new=rule["max_new"],
            )
            actions.append(action)
    return actions


def evaluate_deep_audit(plan: dict, reports: list, canary_reports: list) -> dict:
    """Evaluate supplied normalized facts without authenticating dictionaries or granting any execution or release authority."""
    target = _reports(plan, reports, "report")
    canaries = _reports(plan, canary_reports, "canary_report")
    actions = _canary_actions(plan, canaries)
    findings, counts = _collect_findings(plan, target, actions)
    actions.extend(_threshold_actions(plan, counts))
    clusters = _clusters(findings)
    if len(actions) > 20_000 or len(clusters) > 20_000:
        raise RuntimeAuditError(
            "E_DEEP_LIMIT", "aggregate action or cluster limit exceeded"
        )
    actions.sort(
        key=lambda item: (
            SEVERITY[item["severity"]],
            item["path"],
            item["rule_id"],
            item["code"],
            item["finding_id"],
            item.get("canary_id", ""),
        )
    )
    receipt = {
        "schema": SCHEMA,
        "candidate_sha256": plan["candidate_sha256"],
        "plan_payload_sha256": digest(plan),
        "findings": sorted(findings, key=lambda item: item["finding_id"]),
        "clusters": clusters,
        "repair_queue": actions,
        "agent_actions": _agent_actions(plan["candidate_sha256"], actions),
        "decision": "BLOCKED" if actions else "READY_FOR_HUMAN_REVIEW",
        "report_hashes": {
            key: value["normalized_sha256"] for key, value in sorted(target.items())
        },
        "canary_hashes": {
            key: value["normalized_sha256"] for key, value in sorted(canaries.items())
        },
        "authority": "none",
        "claim_boundary": "Supplied analyzer evidence is not proof of defect absence or release approval.",
    }
    return {**receipt, "receipt_sha256": digest(receipt)}


def _agent_actions(candidate_sha256: str, repair_queue: list[dict]) -> list[dict]:
    """Expose the repair queue through a stable agent-facing work-item contract."""
    rows = []
    for index, item in enumerate(repair_queue, start=1):
        severity = str(item.get("severity", "high")).lower()
        security = any(
            token in str(item.get("obligation_id", "")).lower()
            for token in ("security", "privacy", "tenant")
        )
        rows.append(
            {
                "id": f"deep-audit-action-{index}",
                "measurement_id": item.get("rule_id")
                or item.get("code")
                or "deep_audit_finding",
                "priority": "P1" if severity in {"critical", "high"} else "P2",
                "agent_role": "specialty_ai_security_reviewer"
                if security
                else "specialty_ai_remediation_agent",
                "candidate_sha256": candidate_sha256,
                "action": item.get(
                    "remediation",
                    "Investigate the finding and propose a minimal repair.",
                ),
                "evidence_to_attach": "Candidate-bound patch diff, exact validation command, observed before/after behavior, and current hash-bound analyzer receipt.",
                "affected_paths": [item["path"]] if item.get("path") else [],
                "finding_id": item.get("finding_id"),
                "repair_packet": audit_remediation_packet(candidate_sha256, item),
                "stop_condition": item.get(
                    "consequence",
                    "Keep the deep audit BLOCKED until evidence proves the issue resolved.",
                ),
            }
        )
    return rows


def _write_receipt(root: Path, receipt: dict) -> Path:
    directory = root
    for part in (".factory", "deep-audits"):
        directory = directory / part
        directory.mkdir(exist_ok=True)
        info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeAuditError(
                "E_PATH_ESCAPE", "receipt directory must not be linked"
            )
    path = directory / (receipt["receipt_sha256"] + ".json")
    raw = canonical_bytes(receipt)
    if len(raw) > LIMIT:
        raise RuntimeAuditError("E_DEEP_LIMIT", "receipt exceeds byte budget")
    try:
        with path.open("xb") as stream:
            stream.write(raw)
    except FileExistsError:
        checked = local_file(root, path.relative_to(root).as_posix())
        with checked.open("rb") as stream:
            if stream.read(LIMIT + 1) != raw:
                raise RuntimeAuditError(
                    "E_RECEIPT_COLLISION", "existing receipt differs"
                )
    return path


def execute_deep_audit(
    plan_path: Path, trust_root_path: Path, trust_root_sha256: str, workspace_root: Path
) -> dict:
    """Verify signed inputs, normalize exact reports, evaluate policies and persist one non-authorizing audit receipt."""
    checked = verify_deep_audit_plan(
        plan_path, trust_root_path, trust_root_sha256, workspace_root
    )
    plan, sources = checked["plan"], checked["source_hashes"]
    targets, canaries = [], []
    for analyzer in plan["analyzers"]:
        targets.append(
            normalize_sarif(workspace_root, analyzer["report"], analyzer, sources)
        )
        canaries.append(
            normalize_sarif(
                workspace_root, analyzer["canary_report"], analyzer, sources
            )
        )
    receipt = evaluate_deep_audit(plan, targets, canaries)
    if (
        verify_deep_audit_plan(
            plan_path, trust_root_path, trust_root_sha256, workspace_root
        )
        != checked
    ):
        raise RuntimeAuditError("E_INPUT_CHANGED", "inputs changed across evaluation")
    receipt.pop("receipt_sha256")
    for name in ("plan_sha256", "ruleset_sha256", "canary_set_sha256"):
        receipt[name] = checked[name]
    receipt["receipt_sha256"] = digest(receipt)
    path = _write_receipt(Path(workspace_root).resolve(), receipt)
    return {"receipt": receipt, "receipt_path": str(path), "authority": "none"}


def _history(root: Path) -> list:
    directory = root
    for part in (".factory", "deep-audits"):
        directory = directory / part
        if not directory.exists() and not directory.is_symlink():
            return []
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("receipt history must be an unlinked directory")
    paths = list(islice(directory.glob("*.json"), 1025))
    if len(paths) > 1024:
        raise ValueError("receipt history exceeds inspection bound")
    return paths


def _read_receipt(root: Path, path: Path) -> tuple:
    path = local_file(root, path.relative_to(root).as_posix())
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("receipt exceeds inspection budget")
    receipt = strict_json(raw)
    claimed = receipt.pop("receipt_sha256")
    if (
        digest(receipt) != claimed
        or path.stem != claimed
        or receipt["schema"] != SCHEMA
        or receipt["authority"] != "none"
    ):
        raise ValueError("receipt integrity mismatch")
    expected = "BLOCKED" if receipt["repair_queue"] else "READY_FOR_HUMAN_REVIEW"
    if receipt["decision"] != expected:
        raise ValueError("decision inconsistent with blockers")
    return receipt, claimed, expected


def deep_audit_status(root: Path) -> dict:
    """Read bounded receipt history with tamper checks, never treating a self-hash as signer authentication."""
    root = Path(root).resolve()
    result = {
        "schema": "factory.deep-audit-status.v1",
        "state": "NOT_RUN",
        "authority": "none",
    }
    try:
        paths = _history(root)
        if not paths:
            return result
        path = max(paths, key=lambda item: (item.stat().st_mtime_ns, item.name))
        receipt, claimed, expected = _read_receipt(root, path)
        return {
            **result,
            "state": expected,
            "receipt_path": str(path),
            "receipt_sha256": claimed,
            "finding_count": len(receipt["findings"]),
            "repair_queue": receipt["repair_queue"],
            "agent_actions": receipt.get(
                "agent_actions",
                _agent_actions(
                    receipt.get("candidate_sha256", ""), receipt["repair_queue"]
                ),
            ),
            "verification": "self_hash_only_not_signature_or_freshness",
        }
    except (OSError, ValueError, KeyError, TypeError):
        return {**result, "state": "INCOMPLETE"}

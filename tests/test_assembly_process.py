import sys
import time
from types import SimpleNamespace
import pytest
import factoryline.assembly_process as assembly_process
from factoryline.assembly_process import run_cli, run_cli_detailed
import ast
import textwrap
from factoryline.credential_role_constructor_provider import binding_dominates
import os
import signal
from pathlib import Path
from factoryline.assembly_process import MAX_STREAM_BYTES


@pytest.mark.skipif(
    os.name != "nt" and sys.platform != "linux", reason="native identity unsupported"
)
def test_started_observer_matches_native_child_output_once(tmp_path):
    observed = []
    result = run_cli_detailed(
        sys.executable,
        ["-c", "import os,time; print(os.getpid(),flush=True); time.sleep(0.3)"],
        tmp_path,
        started_observer=observed.append,
    )
    assert result["ok"] and result["streams_closed"]
    assert len(observed) == 1
    assert set(observed[0]) == {"pid", "creation"}
    assert observed[0]["pid"] == int(result["stdout"])
    assert observed[0]["creation"] is not None


@pytest.mark.parametrize("failure", ["callback", "missing_identity", "identity_error"])
def test_started_observer_failure_cleans_owned_child_and_streams(
    monkeypatch, tmp_path, failure
):
    observed, finished = [], []
    finish = assembly_process._finish_and_close

    def capture_finish(child, unit, readers, outputs, reason):
        result = finish(child, unit, readers, outputs, reason)
        finished.append(
            (child.poll(), result, [reader.is_alive() for reader in readers])
        )
        return result

    def observer(context):
        observed.append(context)
        if failure == "callback":
            raise ValueError("observer rejected")

    if failure == "missing_identity":
        monkeypatch.setattr(
            assembly_process, "_process_creation_identity", lambda pid: None
        )
    elif failure == "identity_error":

        def broken_identity(pid):
            raise ValueError("identity unreadable")

        monkeypatch.setattr(
            assembly_process, "_process_creation_identity", broken_identity
        )
    monkeypatch.setattr(assembly_process, "_finish_and_close", capture_finish)
    with pytest.raises((ValueError, RuntimeError)):
        run_cli_detailed(
            sys.executable,
            [
                "-c",
                "import sys,time; print('out',flush=True); print('err',file=sys.stderr,flush=True); time.sleep(30)",
            ],
            tmp_path,
            started_observer=observer,
        )
    assert len(finished) == 1
    exit_code, result, readers_alive = finished[0]
    assert exit_code is not None and result["cleanup_confirmed"]
    assert result["streams_closed"] and not any(readers_alive)
    assert len(observed) == (0 if failure == "identity_error" else 1)
    if failure == "missing_identity":
        assert observed[0]["creation"] is None


def test_started_observer_default_never_queries_identity(monkeypatch, tmp_path):
    def unexpected(pid):
        raise AssertionError("default launch must not query process creation")

    monkeypatch.setattr(assembly_process, "_process_creation_identity", unexpected)
    result = run_cli_detailed(sys.executable, ["-c", "print('unchanged')"], tmp_path)
    assert result["ok"]
    assert result["stdout"].splitlines() == [b"unchanged"]


@pytest.mark.parametrize("pid", [True, False, 0, -1, 2**32, 1.0, "1", None])
def test_coordinator_creation_identity_invalid_pid(pid):
    assert assembly_process._process_creation_identity(pid) is None
    assert assembly_process._windows_process_creation_identity(pid) is None


def _identity_api(monkeypatch, *, waits=(258, 258), ticks=123, opened=99, got=True):
    events = []
    wait_values = iter(waits)

    def get_times(handle, creation, *others):
        events.append("times")
        creation._obj.dwLowDateTime = ticks & 0xFFFFFFFF
        creation._obj.dwHighDateTime = ticks >> 32
        return got

    def wait(handle, timeout):
        assert handle == opened and timeout == 0
        events.append("wait")
        return next(wait_values)

    def open_process(access, inherit, pid):
        assert access == 0x00101000 and inherit is False and pid == 42
        events.append("open")
        return opened

    api = SimpleNamespace(
        OpenProcess=open_process,
        WaitForSingleObject=wait,
        GetProcessTimes=get_times,
        CloseHandle=lambda handle: events.append("close") or True,
    )
    monkeypatch.setattr(assembly_process, "_windows_identity_api", lambda: api)
    return api, events


def test_coordinator_windows_creation_identity_order_and_high_bits(monkeypatch):
    _, events = _identity_api(monkeypatch, ticks=2**40 + 123)
    assert assembly_process._windows_process_creation_identity(42) == (
        "windows:42:000001000000007b"
    )
    assert events == ["open", "wait", "times", "wait", "close"]


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"opened": 0}, ["open"]),
        ({"waits": (0,)}, ["open", "wait", "close"]),
        ({"waits": (0xFFFFFFFF,)}, ["open", "wait", "close"]),
        ({"got": False}, ["open", "wait", "times", "close"]),
        ({"waits": (258, 0)}, ["open", "wait", "times", "wait", "close"]),
        ({"ticks": 0}, ["open", "wait", "times", "wait", "close"]),
    ],
)
def test_coordinator_windows_creation_identity_fail_closed(
    monkeypatch, options, expected
):
    _, events = _identity_api(monkeypatch, **options)
    assert assembly_process._windows_process_creation_identity(42) is None
    assert events == expected


@pytest.mark.parametrize(
    "operation", ["WaitForSingleObject", "GetProcessTimes", "CloseHandle"]
)
def test_coordinator_windows_creation_identity_exception_closes(monkeypatch, operation):
    api, events = _identity_api(monkeypatch)

    def fail(*args):
        events.append(operation)
        raise OSError("unreadable native observation")

    setattr(api, operation, fail)
    assert assembly_process._windows_process_creation_identity(42) is None
    assert events[-1] == ("CloseHandle" if operation == "CloseHandle" else "close")


def test_coordinator_windows_identity_api_and_close_failures(monkeypatch):
    api, _ = _identity_api(monkeypatch)
    api.CloseHandle = lambda handle: False
    assert assembly_process._windows_process_creation_identity(42) is None

    def unavailable():
        raise AttributeError("native API unavailable")

    monkeypatch.setattr(assembly_process, "_windows_identity_api", unavailable)
    assert assembly_process._windows_process_creation_identity(42) is None


@pytest.mark.skipif(os.name != "nt", reason="native Windows creation controls")
def test_coordinator_native_windows_creation_identity():
    import subprocess

    api = assembly_process._windows_identity_api()
    for name in [
        "OpenProcess",
        "WaitForSingleObject",
        "GetProcessTimes",
        "CloseHandle",
    ]:
        assert getattr(api, name).argtypes and getattr(api, name).restype

    first = assembly_process._process_creation_identity(os.getpid())
    assert first and first == assembly_process._process_creation_identity(os.getpid())
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        creationflags=assembly_process.WINDOWS_CREATE_NO_WINDOW,
    )
    try:
        identity = assembly_process._process_creation_identity(child.pid)
        assert identity and identity != first
        assert identity == assembly_process._process_creation_identity(child.pid)
    finally:
        child.terminate()
        child.wait(timeout=10)
    assert assembly_process._process_creation_identity(child.pid) is None


@pytest.mark.parametrize("state", ["Z", "X", "x", "RS", "?"])
def test_coordinator_linux_identity_rejects_dead_or_unknown_state(state):
    text = f"42 (command (with) parentheses) {state} " + "0 " * 18 + "123"
    assert assembly_process._linux_stat_start_ticks(text, 42) is None


def test_coordinator_linux_stat_identity_parser():
    text = "42 (command (with) parentheses) S " + "0 " * 18 + "123"
    assert assembly_process._linux_stat_start_ticks(text, 42) == "123"
    assert assembly_process._linux_stat_start_ticks(text, 43) is None
    for malformed in ["", "42 bad", "42 (x) S", text[:-3] + "-12", text[:-3] + "000"]:
        assert assembly_process._linux_stat_start_ticks(malformed, 42) is None


def test_coordinator_linux_identity_stability_and_errors(monkeypatch):
    monkeypatch.setattr(assembly_process.os, "name", "posix")
    monkeypatch.setattr(assembly_process.sys, "platform", "linux")
    values = iter(["linux:boot:42:123", "linux:boot:42:124"])
    monkeypatch.setattr(
        assembly_process, "_linux_creation_observation", lambda pid: next(values)
    )
    assert assembly_process._process_creation_identity(42) is None

    def fail(pid):
        raise PermissionError("unreadable")

    monkeypatch.setattr(assembly_process, "_linux_creation_observation", fail)
    assert assembly_process._process_creation_identity(42) is None
    monkeypatch.setattr(assembly_process.sys, "platform", "darwin")
    assert assembly_process._process_creation_identity(42) is None


def test_coordinator_linux_boot_identity_and_bounded_reads(monkeypatch, tmp_path):
    boot = "12345678-1234-1234-1234-123456789abc"
    stat = "42 (x) S " + "0 " * 18 + "123"
    monkeypatch.setattr(
        assembly_process,
        "_bounded_identity_text",
        lambda path, limit: boot if path.name == "boot_id" else stat,
    )
    assert assembly_process._linux_creation_observation(42) == f"linux:{boot}:42:123"
    boot = "not-a-boot-id"
    assert assembly_process._linux_creation_observation(42) is None
    boot = "zzzzzzzz-1234-1234-1234-123456789abc"
    assert assembly_process._linux_creation_observation(42) is None


def test_coordinator_identity_read_is_bounded(tmp_path):
    path = tmp_path / "identity"
    path.write_text("abc", encoding="ascii")
    assert assembly_process._bounded_identity_text(path, 3) == "abc"
    with pytest.raises(ValueError, match="oversized"):
        assembly_process._bounded_identity_text(path, 2)


@pytest.mark.skipif(sys.platform != "linux", reason="native Linux creation controls")
def test_coordinator_native_linux_creation_identity():
    import subprocess

    first = assembly_process._process_creation_identity(os.getpid())
    assert first and first == assembly_process._process_creation_identity(os.getpid())
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert assembly_process._process_creation_identity(child.pid) not in (
            None,
            first,
        )
    finally:
        child.terminate()
        child.wait(timeout=10)
    assert assembly_process._process_creation_identity(child.pid) is None


def test_success_preserves_both_streams(tmp_path):
    ok, output = run_cli(
        sys.executable,
        ["-c", "import sys; print('proof'); print('error', file=sys.stderr)"],
        tmp_path,
    )
    assert ok
    assert "proof" in output and "error" in output


def test_detailed_result_contains_cleanup_receipt(tmp_path):
    result = run_cli_detailed(sys.executable, ["-c", "print('proof')"], tmp_path)
    assert result["ok"] is True
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True
    assert result["exit_code"] == 0
    assert result["reason"] is None
    assert "proof" in result["output"]


def test_child_phase_telemetry_preserves_detailed_result(tmp_path):
    from factoryline.ops_telemetry import _phase_telemetry

    command = ["-c", "print('phase-safe')"]
    expected = run_cli_detailed(sys.executable, command, tmp_path)
    with _phase_telemetry(0) as telemetry:
        observed = run_cli_detailed(sys.executable, command, tmp_path)
    fields = (
        "ok",
        "output",
        "stdout",
        "stderr",
        "cleanup_confirmed",
        "streams_closed",
        "reason",
        "exit_code",
    )
    assert {field: observed[field] for field in fields} == {
        field: expected[field] for field in fields
    }
    phases = {phase["phase"]: phase for phase in telemetry.snapshot()["phases"]}
    assert {"child_launch", "child_wait", "child_cleanup"} <= phases.keys()
    assert all(phases[name]["completed"] == 1 for name in phases)
    assert str(tmp_path) not in str(telemetry.snapshot())


def test_child_wait_error_keeps_cleanup_and_hides_error_from_telemetry(
    tmp_path, monkeypatch
):
    from factoryline.ops_telemetry import _phase_telemetry

    def fail_wait(*args, **kwargs):
        raise RuntimeError("PRIVATE CHILD ARGUMENT")

    monkeypatch.setattr(assembly_process, "_monitor", fail_wait)
    with _phase_telemetry(0) as telemetry:
        with pytest.raises(RuntimeError, match="PRIVATE CHILD ARGUMENT"):
            run_cli_detailed(
                sys.executable, ["-c", "import time; time.sleep(30)"], tmp_path
            )
    phases = {phase["phase"]: phase for phase in telemetry.snapshot()["phases"]}
    assert phases["child_wait"]["incomplete"] == 1
    assert phases["child_cleanup"]["completed"] == 1
    assert "PRIVATE CHILD ARGUMENT" not in str(telemetry.snapshot())


def test_lifecycle_receipt_overhead_is_measured_outside_receipt(
    tmp_path, capsys, monkeypatch
):
    from factoryline import provenance
    from factoryline.cli import main

    monkeypatch.chdir(tmp_path)
    started = time.perf_counter_ns()
    expected_exit = main(["plan"])
    baseline_elapsed_ns = time.perf_counter_ns() - started
    expected_output = capsys.readouterr().out

    started = time.perf_counter_ns()
    observed_exit = provenance.main(["plan"])
    observed_elapsed_ns = time.perf_counter_ns() - started
    observed_output = capsys.readouterr().out

    assert observed_exit == expected_exit == 0
    assert observed_output == expected_output
    assert baseline_elapsed_ns >= 0 and observed_elapsed_ns >= 0
    receipts = list((tmp_path / ".factory" / "ops" / "lifecycle").glob("*.json"))
    assert len(receipts) == 2
    measured = [
        path
        for path in receipts
        if "phase_telemetry" in path.read_text(encoding="utf-8")
    ]
    assert len(measured) == 1


def test_detailed_timeout_keeps_cleanup_receipt_explicit(tmp_path):
    result = run_cli_detailed(
        sys.executable, ["-c", "import time; time.sleep(30)"], tmp_path, timeout=0.2
    )
    assert result["ok"] is False
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True
    assert result["reason"] == "stage timed out"
    assert "timed out" in result["output"]


def test_detailed_launch_failure_cannot_claim_cleanup(tmp_path):
    result = run_cli_detailed(str(tmp_path / "missing-cli"), [], tmp_path)
    assert result["ok"] is False
    assert result["cleanup_confirmed"] is False
    assert result["streams_closed"] is False
    assert result["reason"] == "launch failed"


def test_cleanup_accepts_later_confirmed_empty_state_after_terminate_failure(
    monkeypatch,
):
    class Child:
        pid = 100

        def poll(self):
            return 0

    unit = assembly_process._CleanupUnit(pgid=100)
    termination_requests = []
    monkeypatch.setattr(assembly_process, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(assembly_process, "_posix_group_status", lambda pgid: True)
    monkeypatch.setattr(assembly_process, "_posix_processes", lambda: {})
    monkeypatch.setattr(
        assembly_process,
        "_terminate_unit",
        lambda child, cleanup: termination_requests.append((child, cleanup)) or False,
    )

    assert assembly_process._unit_status(Child(), unit) is True
    assert assembly_process._escaped_descendant_status(unit) is True
    assert assembly_process._await_cleanup(Child(), unit, terminate=True) is True
    assert len(termination_requests) == 1


@pytest.mark.parametrize("group_status", [False, None])
def test_cleanup_rejects_live_or_unknown_bound_group(monkeypatch, group_status):
    class Child:
        pid = 100

        def poll(self):
            return 0

    unit = assembly_process._CleanupUnit(pgid=100)
    monotonic_values = iter([0, 1])
    monkeypatch.setattr(assembly_process, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(
        assembly_process, "_posix_group_status", lambda pgid: group_status
    )
    monkeypatch.setattr(assembly_process, "_posix_processes", lambda: {})
    monkeypatch.setattr(assembly_process, "CLEANUP_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(
        assembly_process.time, "monotonic", lambda: next(monotonic_values)
    )
    monkeypatch.setattr(assembly_process.time, "sleep", lambda _: None)

    assert assembly_process._await_cleanup(Child(), unit, terminate=False) is False


@pytest.mark.parametrize(
    "process_snapshot",
    [{101: assembly_process._PosixProcess(101, 1, 101, "escaped")}, None],
)
def test_cleanup_rejects_live_or_unknown_escaped_descendant(
    monkeypatch, process_snapshot
):
    class Child:
        pid = 100

        def poll(self):
            return 0

    unit = assembly_process._CleanupUnit(pgid=100)
    unit.observed_descendants[101] = "escaped"
    monkeypatch.setattr(assembly_process, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(assembly_process, "_posix_group_status", lambda pgid: True)
    monkeypatch.setattr(assembly_process, "_posix_processes", lambda: process_snapshot)

    assert assembly_process._unit_status(Child(), unit) is True
    assert assembly_process._escaped_descendant_status(unit) is (
        False if process_snapshot is not None else None
    )
    assert assembly_process._await_cleanup(Child(), unit, terminate=False) is False


def test_observed_posix_descendant_outside_cleanup_group_blocks_receipt(monkeypatch):
    unit = assembly_process._CleanupUnit(pgid=100)
    snapshot = {
        100: assembly_process._PosixProcess(100, 1, 100, "root"),
        101: assembly_process._PosixProcess(101, 100, 101, "escaped"),
    }
    monkeypatch.setattr(assembly_process, "_posix_processes", lambda: snapshot)
    monkeypatch.setattr(assembly_process.os, "name", "posix")
    assembly_process._observe_descendants(SimpleNamespace(pid=100), unit)
    assert unit.observed_descendants == {101: "escaped"}
    assert assembly_process._escaped_descendant_status(unit) is False


def test_posix_snapshot_accepts_host_owned_zero_process_group(monkeypatch):
    class _Result:
        returncode = 0
        stdout = "    1     0     0 Sun Sep  6 00:00:00 2026\n  100     1   100 Sun Sep  6 00:00:00 2026\n"

    monkeypatch.setattr(assembly_process.os, "name", "posix")
    monkeypatch.setattr(
        assembly_process.subprocess, "run", lambda *args, **kwargs: _Result()
    )
    snapshot = assembly_process._posix_processes()
    assert snapshot is not None
    assert snapshot[1].pgid == 0
    assert snapshot[100].pgid == 100


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_overflow_cannot_pass(tmp_path, stream):
    ok, output = run_cli(
        sys.executable,
        ["-c", f"import sys; sys.{stream}.write('x'*100000)"],
        tmp_path,
        max_stream_bytes=1024,
    )
    assert not ok
    assert "output limit" in output
    assert len(output) < 1400


def test_monitor_rechecks_stream_failure_at_completion(monkeypatch):
    failed = assembly_process.threading.Event()

    class _Child:
        def poll(self):
            failed.set()
            return 0

    class _Reader:
        def is_alive(self):
            return False

    monkeypatch.setattr(assembly_process, "_observe_descendants", lambda *_: None)
    reason = assembly_process._monitor(
        _Child(),
        object(),
        [_Reader()],
        failed,
        None,
        time.monotonic() + 10,
    )

    assert reason == "output limit exceeded or stream read failed"


@pytest.mark.parametrize("cancel", [False, True])
def test_deadline_and_cancellation_are_bounded(tmp_path, cancel):
    start = time.monotonic()
    ok, output = run_cli(
        sys.executable,
        ["-c", "import time; time.sleep(30)"],
        tmp_path,
        timeout=0.2,
        heartbeat=(lambda: False) if cancel else None,
    )
    assert not ok
    assert ("stop requested" if cancel else "timed out") in output
    assert time.monotonic() - start < 10


def test_nonzero_exit_and_invalid_bytes(tmp_path):
    ok, output = run_cli(
        sys.executable,
        ["-c", "import sys; sys.stdout.buffer.write(b'\\xff'); sys.exit(3)"],
        tmp_path,
    )
    assert not ok and "\ufffd" in output


def test_heartbeat_exception_is_not_success(tmp_path):
    def broken():
        raise RuntimeError("monitor failed")

    with pytest.raises(RuntimeError, match="monitor failed"):
        run_cli(
            sys.executable,
            ["-c", "import time; time.sleep(30)"],
            tmp_path,
            heartbeat=broken,
        )


def test_missing_cli_is_failure(tmp_path):
    assert run_cli(str(tmp_path / "missing-cli"), [], tmp_path)[0] is False


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), 0, -1])
def test_invalid_deadlines_cannot_disable_bounds(tmp_path, deadline):
    with pytest.raises(ValueError):
        run_cli(sys.executable, ["-c", "pass"], tmp_path, timeout=deadline)


def test_inherited_pipe_does_not_hang_caller(tmp_path):
    # A short-lived descendant inherits pipes after its parent exits. Even if
    # Windows cannot find that exited parent, caller cleanup remains bounded.
    code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(1)'])"
    start = time.monotonic()
    ok, output = run_cli(sys.executable, ["-c", code], tmp_path, timeout=0.2)
    assert not ok and "timed out" in output
    assert time.monotonic() - start < 10


def test_windows_child_is_bound_before_resume(monkeypatch, tmp_path):
    events = []

    class Child:
        pid = 42
        _handle = 99

    monkeypatch.setattr(assembly_process.os, "name", "nt")
    monkeypatch.setattr(
        assembly_process.subprocess,
        "Popen",
        lambda *args, **kwargs: (events.append(("launch", kwargs)) or Child()),
    )
    monkeypatch.setattr(
        assembly_process,
        "_windows_job",
        lambda child: (events.append("job") or (7, None)),
    )
    monkeypatch.setattr(
        assembly_process,
        "_resume_windows_process",
        lambda child: (events.append("resume") or (True, None)),
    )

    child, unit, error = assembly_process._launch("worker", [], tmp_path)

    assert error is None
    assert child is not None and unit is not None
    assert events[0][0] == "launch"
    assert events[0][1]["creationflags"] & assembly_process.WINDOWS_CREATE_SUSPENDED
    assert events[1:] == ["job", "resume"]


def test_windows_resume_failure_returns_non_success(monkeypatch, tmp_path):
    events = []

    class Child:
        pid = 42
        _handle = 99

        def poll(self):
            return None

        def kill(self):
            events.append("kill")

    monkeypatch.setattr(assembly_process.os, "name", "nt")
    monkeypatch.setattr(
        assembly_process.subprocess, "Popen", lambda *args, **kwargs: Child()
    )
    monkeypatch.setattr(
        assembly_process,
        "_windows_job",
        lambda child: (events.append("job") or (7, None)),
    )
    monkeypatch.setattr(
        assembly_process,
        "_resume_windows_process",
        lambda child: (False, "resume failed"),
    )
    monkeypatch.setattr(
        assembly_process,
        "_terminate_unit",
        lambda child, unit: events.append("terminate") or True,
    )
    monkeypatch.setattr(
        assembly_process._CleanupUnit, "close", lambda self: events.append("close")
    )

    child, unit, error = assembly_process._launch("worker", [], tmp_path)

    assert child is None and unit is None
    assert error == "resume failed"
    assert events == ["job", "terminate", "close"]


def test_shared_measure_call_facade_preserves_return_and_records_phase():
    from factoryline.ops_telemetry import _phase_telemetry

    with _phase_telemetry(0) as telemetry:
        value = assembly_process._measure_call("source_parse", lambda item: item, 17)

    assert value == 17
    phases = {item["phase"]: item for item in telemetry.snapshot()["phases"]}
    assert phases["source_parse"]["calls"] == 1
    assert phases["source_parse"]["completed"] == 1


"""Source-only ordering controls for branch-local response evidence."""


@pytest.mark.parametrize(
    "body,expected",
    [
        ("data = {}\nassert data", True),
        ("if condition:\n    data = {}\n    assert data", True),
        ("data = {}\nif condition:\n    assert data", True),
        ("if condition:\n    pass\nelse:\n    data = {}\n    assert data", True),
        ("if condition:\n    data = {}\nassert data", False),
        ("if condition:\n    data = {}\nelse:\n    assert data", False),
        ("assert data\ndata = {}", False),
        ("for item in items:\n    data = {}\nassert data", False),
        ("while condition:\n    data = {}\nassert data", False),
        ("try:\n    data = {}\nexcept Exception:\n    pass\nassert data", False),
        ("try:\n    data = {}\n    assert data\nexcept Exception:\n    pass", True),
        ("data = {}\ndef inner():\n    assert data", False),
        ("def inner():\n    data = {}\nassert data", False),
        ("data = {}\nclass Inner:\n    assert data", False),
    ],
)
def test_binding_order_requires_the_same_execution_branch(body, expected):
    tree = ast.parse("def outer():\n" + textwrap.indent(body, "    "))
    scope = tree.body[0]
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    binding = next(node for node in ast.walk(scope) if isinstance(node, ast.Assign))
    use = next(node for node in ast.walk(scope) if isinstance(node, ast.Assert))
    before = ast.dump(tree, include_attributes=True)
    assert binding_dominates(binding, use, parents, scope) is expected
    assert ast.dump(tree, include_attributes=True) == before


def test_assignment_cannot_prove_its_own_rhs_and_malformed_parents_fail_closed():
    tree = ast.parse("def outer():\n    data = source(data)\n")
    scope = tree.body[0]
    binding = scope.body[0]
    use = binding.value
    parents = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    assert not binding_dominates(binding, use, parents, scope)
    assert not binding_dominates(binding, use, {}, scope)
    assert not binding_dominates(binding, use, parents, tree)
    assert not binding_dominates(binding, use, {id(use): use}, scope)


def test_ci_runs_native_python_matrix_on_all_supported_host_families() -> None:
    import yaml

    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "os: [ubuntu-latest, windows-latest, macos-latest]" in workflow
    assert 'python: ["3.10", "3.11", "3.12"]' in workflow
    jobs = yaml.safe_load(workflow)["jobs"]
    runner = "${{ matrix.os == 'macos-latest' && 'macos-15-intel' || matrix.os }}"
    assert jobs["test"]["runs-on"] == "${{ matrix.os }}"
    assert jobs["native-process-parity"]["runs-on"] == runner
    assert "native-process-parity:" in workflow
    assert "os: [ubuntu-latest, macos-latest]" in workflow
    assert "native-process-parity-${{ matrix.os }}" in workflow
    assert "--junitxml=native-process-parity.junit.xml" in workflow


def test_candidate_quality_gate_keeps_attribution_floor_and_python_cap() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "report['attribution']['rate'] >= 0.9985" in workflow
    assert "max_python_files'] == 464" in workflow
    assert "<= 464" in workflow


def test_ci_windows_shards_keep_both_profiles_and_existing_bounds() -> None:
    import yaml

    jobs = yaml.safe_load(Path(".github/workflows/ci.yml").read_text())["jobs"]
    for version in ("3.11", "3.12"):
        assert {"os": "windows-latest", "python": version} in jobs["test"]["strategy"]["matrix"]["exclude"]
    shards = jobs["windows-shards"]
    assert shards["strategy"]["matrix"] == {"python": ["3.11", "3.12"], "shard": [1, 2, 3, 4]}
    assert shards["timeout-minutes"] == 20
    command = next(step["run"] for step in shards["steps"] if step.get("name") == "Test shard")
    assert "--factory-ci-shard=${{ matrix.shard }}/4" in command
    assert "--deselect" not in command and "--ignore" not in command
    gate = jobs["windows-test"]
    assert gate["name"] == "test (windows-latest, ${{ matrix.python }})"
    assert gate["needs"] == "windows-shards" and gate["if"] == "${{ always() }}"
    assert gate["strategy"]["matrix"]["python"] == ["3.11", "3.12"]
    assert gate["steps"][0]["run"] == 'test "$SHARD_RESULT" = success'


def test_ci_shards_assign_every_node_exactly_once() -> None:
    from types import SimpleNamespace
    from conftest import pytest_collection_modifyitems

    nodes = [SimpleNamespace(nodeid=f"tests/test_{index}.py::test_case[boundary-{index}]") for index in range(513)]
    partitions = []
    for number in range(1, 5):
        selected = list(nodes)
        config = SimpleNamespace(getoption=lambda key, n=number: (n, 4),
                                 hook=SimpleNamespace(pytest_deselected=lambda **kwargs: None))
        pytest_collection_modifyitems(config, selected)
        partitions.append({item.nodeid for item in selected})
    assert all(partitions)
    assert set.union(*partitions) == {item.nodeid for item in nodes}
    assert sum(map(len, partitions)) == len(nodes)


@pytest.mark.skipif(
    os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI"
)
def test_native_timeout_returns_closed_receipt(tmp_path) -> None:
    result = run_cli_detailed(
        sys.executable, ["-c", "import time; time.sleep(30)"], tmp_path, timeout=1
    )
    assert result["ok"] is False
    assert result["reason"] == "stage timed out"
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True


@pytest.mark.skipif(
    os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI"
)
def test_native_output_limit_returns_closed_receipt(tmp_path) -> None:
    code = f"import sys; sys.stdout.buffer.write(b'x' * {MAX_STREAM_BYTES + 1})"
    result = run_cli_detailed(sys.executable, ["-c", code], tmp_path, timeout=10)
    assert result["ok"] is False
    assert result["reason"] == "output limit exceeded or stream read failed"
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True


@pytest.mark.skipif(
    os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI"
)
def test_native_cancellation_returns_closed_receipt(tmp_path) -> None:
    result = run_cli_detailed(
        sys.executable,
        ["-c", "import time; time.sleep(30)"],
        tmp_path,
        timeout=10,
        heartbeat=lambda: False,
    )
    assert result["ok"] is False
    assert result["reason"] == "stop requested through the local Studio"
    assert result["cleanup_confirmed"] is True
    assert result["streams_closed"] is True


@pytest.mark.skipif(
    os.name == "nt", reason="native POSIX parity executes in Linux/macOS CI"
)
def test_native_surviving_child_is_unconfirmed(tmp_path) -> None:
    """A child that starts a new session is known but outside our cleanup unit."""
    pid_file = tmp_path / "escaped-child.pid"
    child = (
        "import os,pathlib,sys,time; os.setsid(); "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding='utf-8'); time.sleep(30)"
    )
    parent = (
        "import pathlib,subprocess,sys,time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(30)"
    )
    result = run_cli_detailed(
        sys.executable, ["-c", parent, str(pid_file), child], tmp_path, timeout=1
    )
    assert result["ok"] is False
    assert result["reason"] == "stage timed out"
    assert result["cleanup_confirmed"] is False
    assert "cleanup could not be confirmed" in result["output"]

    deadline = time.monotonic() + 2
    while not pid_file.is_file() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert pid_file.is_file()
    escaped_pid = int(pid_file.read_text(encoding="utf-8"))
    try:
        os.kill(escaped_pid, 0)
    finally:
        try:
            os.kill(escaped_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

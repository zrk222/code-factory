from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest

from test_deep_audit_contract import fixture
from test_deep_audit_sarif import report
from factoryline.deep_audit import (
    execute_deep_audit,
    evaluate_deep_audit,
    deep_audit_status,
)
from factoryline.deep_audit_contract import verify_deep_audit_plan
from factoryline.deep_audit_sarif import normalize_sarif
from factoryline.deep_audit_io import digest
from factoryline.runtime_audit_common import RuntimeAuditError, sha256_bytes


def _workspace_policy319_request_pickle_fixture(root):
    (root / "app.py").write_text(
        "import pickle\nfrom flask import request\n"
        "def decode():\n    return pickle.loads(request.get_data())\n",
        encoding="utf-8",
    )


def test_zap_source_trace_mount_preserves_isolation_and_signed_python(tmp_path):
    from factoryline.deep_audit import _zap_app_argv
    from test_deep_audit_sarif import _host_zap_lane_fixture

    lane = _host_zap_lane_fixture()
    lane["native_target"]["argv"] = ["/usr/local/bin/python", "/src/app.py", "arg"]
    bootstrap = tmp_path / "bootstrap.txt"
    argv = _zap_app_argv(["docker"], lane, tmp_path, "app", "internal", bootstrap)
    assert argv[-2:] == ["-I", "/factory-source-trace.py"]
    assert argv[argv.index("--entrypoint") + 1] == "/usr/local/bin/python"
    assert any(item.endswith("/factory-source-trace.py,readonly") for item in argv)
    assert "/trace:rw,nosuid,nodev,noexec,size=4m,mode=1777" in argv
    assert "--read-only" in argv and "--network=internal" in argv
    assert not any("target=/out" in item or "docker.sock" in item for item in argv)


def test_zap_prepare_trace_activates_only_signed_bound_python_provider(tmp_path):
    from factoryline.deep_audit import _zap_prepare_trace
    from test_deep_audit_sarif import _zap_source_trace_fixture

    request, inventory, _, _ = _zap_source_trace_fixture(tmp_path)
    inventory["candidate_sha256"] = digest(inventory["files"])
    lane = {
        "id": "zap",
        "rule_ids": request["rule_ids"],
        "timeout_seconds": request["timeout_seconds"],
        "native_target": request["target"],
    }
    state = {
        "run_id": request["run_id"],
        "manifest_sha256": "d" * 64,
        "active_lane": "zap",
    }

    prepared = _zap_prepare_trace(
        tmp_path, state, inventory, lane, time.monotonic() + 30
    )

    assert prepared is not None
    path, prepared_request = prepared
    assert path.is_file()
    assert prepared_request["target"] == lane["native_target"]
    assert prepared_request["profile_sha256"] == digest(lane)
    assert b"/trace/events.jsonl" in path.read_bytes()


def test_workspace_policy319_native_request_pickle_defect_is_admitted(tmp_path):
    from factoryline.deep_audit_io import full_repository_scan

    _workspace_policy319_request_pickle_fixture(tmp_path)
    report = full_repository_scan(
        tmp_path, context_profile="workspace-v2", defect_policy="trusted-core-v1"
    )
    decision = report["defect_policy_decision"]
    assert decision["state"] == "DEFECTS_PRESENT"
    assert decision["exit_code"] == 1
    assert decision["supported_defect_count"] >= 1
    assert decision["passed"] is False
    assert decision["clean"] is False
    assert decision["release_approved"] is False
    assert report["workspace_evidence"]["selected_defect_policy"] == "trusted-core-v1"
    assert any(
        row["code"] == "SECURITY_UNSAFE_DESERIALIZATION"
        for row in report["workspace_evidence"]["raw_findings"]
    )


def test_workspace_policy319_review_and_incomplete_states_stay_distinct(tmp_path):
    from factoryline.deep_audit_io import full_repository_scan

    (tmp_path / "opaque.py").write_text(
        "import pickle\ndef decode(value):\n    return pickle.loads(value)\n",
        encoding="utf-8",
    )
    review = full_repository_scan(
        tmp_path, context_profile="workspace-v2", defect_policy="trusted-core-v1"
    )["defect_policy_decision"]
    assert review["state"] == "NO_SUPPORTED_DEFECTS_REVIEW_REQUIRED"
    assert review["exit_code"] == 0
    assert review["passed"] is False and review["clean"] is False
    assert review["release_approved"] is False
    assert review["needs_context_count"] >= 1

    incomplete_root = tmp_path / "incomplete"
    incomplete_root.mkdir()
    (incomplete_root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    blocked = full_repository_scan(
        incomplete_root,
        context_profile="workspace-v2",
        defect_policy="trusted-core-v1",
    )["defect_policy_decision"]
    assert blocked["state"] == "BLOCKED" and blocked["exit_code"] == 2
    assert blocked["passed"] is False and blocked["clean"] is False
    assert blocked["release_approved"] is False


def test_workspace_policy319_legacy_shape_and_isolated_refusal(tmp_path):
    from factoryline.deep_audit_io import full_repository_scan

    (tmp_path / "opaque.py").write_text("value = 1\n", encoding="utf-8")
    legacy = full_repository_scan(tmp_path, context_profile="workspace-v2")
    assert "selected_defect_policy" not in legacy
    assert "defect_policy_sha256" not in legacy
    assert "defect_policy_decision" not in legacy
    assert "selected_defect_policy" not in legacy["workspace_evidence"]
    with pytest.raises(RuntimeAuditError, match="workspace-v2"):
        full_repository_scan(tmp_path, defect_policy="trusted-core-v1")


def test_workspace_policy319_selection_switch_rejects_checkpoint_reuse(tmp_path):
    from factoryline.deep_audit_io import full_repository_scan

    (tmp_path / "opaque.py").write_text("value = 1\n", encoding="utf-8")
    full_repository_scan(tmp_path, context_profile="workspace-v2")
    with pytest.raises(RuntimeAuditError, match="checkpoint|configuration|identity"):
        full_repository_scan(
            tmp_path,
            context_profile="workspace-v2",
            defect_policy="trusted-core-v1",
            resume=True,
        )


def test_workspace_policy319_rejects_inconsistent_native_tier_gate(
    tmp_path, monkeypatch
):
    from factoryline import deep_audit_io

    evidence = {
        "sources": {
            "capture_complete": True,
            "files_discovered": 1,
            "files_bound": 1,
            "source_manifest_sha256": "a" * 64,
        },
        "oracle_context": {"state": "captured"},
        "audit_coverage": {"complete": True, "files_processed": 1},
        "primitive_partition": {"state": "VALIDATED"},
        "raw_findings": [],
        "finding_tiers": {
            "defect_gate": {
                "state": "NO_SUPPORTED_DEFECTS_OBSERVED",
                "supported_defect_count": 1,
                "needs_context_count": 0,
                "passed": False,
                "clean": False,
                "completeness_state": "ASSESSED_WITHIN_DECLARED_SCOPE",
            },
            "ledger": [],
            "tier_counts": {},
            "policy_sha256": "x",
            "ledger_sha256": "x",
            "report_sha256": "x",
        },
    }
    generation = {
        "workspace_evidence": evidence,
        "inventory": [{"path": "x.py", "state": "ready", "sha256": "b" * 64}],
        "inventory_hash": "c" * 64,
        "scanner": "d" * 64,
        "configuration": "e" * 64,
        "context_generation_sha256": "f" * 64,
        "collection_incomplete": False,
    }
    decision = deep_audit_io._full_repository_trusted_core_decision(
        generation, [{"status": "audited"}]
    )
    assert decision["state"] == "BLOCKED" and decision["exit_code"] == 2


@pytest.mark.parametrize("mode", ["valid", "missing", "replay", "unmeasured"])
def test_zap_source_trace_cannot_clear_unobserved_or_unreplayed_sources(mode):
    from copy import deepcopy
    from factoryline.deep_audit import _zap_source_trace_gaps
    from test_deep_audit_sarif import _host_zap_lane_fixture

    trace = {"observations": [{"route_id": "home", "path": "app.py", "lines": [3]}]}
    primary = {"native_execution": {"source_trace": trace}}
    replay = deepcopy(primary)
    if mode == "missing":
        primary["native_execution"]["source_trace"] = None
    if mode == "replay":
        replay["native_execution"]["source_trace"]["observations"][0]["lines"] = [4]
    lane = _host_zap_lane_fixture()
    if mode == "unmeasured":
        lane["native_target"]["routes"][0]["source_bindings"]["other.py"] = "d" * 64
    gaps = _zap_source_trace_gaps(primary, replay, lane)
    assert bool(gaps) == (mode != "valid")
    if mode == "unmeasured":
        assert primary["native_execution"]["source_trace_missing"] == [
            {"route_id": "home", "path": "other.py"}
        ]


@pytest.mark.parametrize("unsafe", ["symlink", "oversize"])
def test_zap_source_trace_capture_rejects_unsafe_copied_artifact(tmp_path, unsafe):
    from factoryline.deep_audit import _zap_read_trace

    path = tmp_path / "trace.jsonl"
    if unsafe == "oversize":
        with path.open("wb") as stream:
            stream.truncate(4 * 1024 * 1024 + 1)
    else:
        target = tmp_path / "real"
        target.write_text("{}\n")
        try:
            path.symlink_to(target)
        except OSError:
            pytest.skip("symlink privilege unavailable")
    with pytest.raises(RuntimeAuditError, match="E_ZAP_SOURCE_TRACE"):
        _zap_read_trace(path)


def test_zap_invalid_trace_becomes_actionable_gap_without_discarding_reports(
    tmp_path, monkeypatch
):
    import factoryline.deep_audit as host

    def failed_capture(*args):
        raise RuntimeAuditError("E_ZAP_SOURCE_TRACE", "private host path must not leak")

    monkeypatch.setattr(host, "_zap_capture_trace", failed_capture)
    trace, code = host._zap_capture_trace_or_gap([], "app", tmp_path)
    assert trace is None and code == "E_ZAP_SOURCE_TRACE"
    from factoryline.deep_audit_io import read_run_json

    retained = read_run_json(tmp_path, "zap-source-trace-failure.json")
    assert retained["code"] == "E_ZAP_SOURCE_TRACE"
    assert "private" not in json.dumps(retained)


def test_zap_trace_capture_streams_fixed_tmpfs_path_with_signed_interpreter(
    tmp_path, monkeypatch
):
    import factoryline.deep_audit as host
    import factoryline.deep_audit_io as io

    calls = []

    def control(base, args, deadline):
        calls.append((args, deadline))
        return {"exit_code": 0}, b'{"sample":1}\n'

    monkeypatch.setattr(host, "_zap_docker_control", control)
    monkeypatch.setattr(
        io, "zap_validate_source_trace", lambda *args: {"observations": []}
    )
    request = {"target": {"argv": ["/usr/local/bin/python", "/src/app.py"]}}
    result = host._zap_capture_trace(
        ["docker"],
        "app",
        tmp_path,
        (tmp_path / "bootstrap", request),
        {},
        tmp_path,
        123,
    )
    args, deadline = calls[0]
    assert args[:5] == ["exec", "app", "/usr/local/bin/python", "-I", "-c"]
    assert "os.O_NOFOLLOW" in args[-1] and "/trace/events.jsonl" in args[-1]
    assert deadline == 123
    assert (tmp_path / result["artifact"]).read_bytes() == b'{"sample":1}\n'


def test_semgrep_signed_mutation_preserves_every_other_rule(tmp_path):
    import yaml
    from factoryline.deep_audit_io import (
        _semgrep_disable_rule,
        _semgrep_mutation_file,
        _semgrep_mutation_valid,
    )

    baseline = Path(
        "deploy/deep-adapters/rules/semgrep-pattern-limited.yml"
    ).read_bytes()
    original = yaml.safe_load(baseline)
    for rule in original["rules"]:
        target = rule["id"]
        effective = _semgrep_disable_rule(baseline, target)
        expected = deepcopy(original)
        expected["rules"] = [r for r in expected["rules"] if r["id"] != target]
        assert yaml.safe_load(effective) == expected
        assert _semgrep_mutation_valid(baseline, effective, target)
        assert not _semgrep_mutation_valid(baseline, baseline, target)
        lane = {"mutation_config_sha256": {target: sha256_bytes(effective)}}
        assert (
            _semgrep_mutation_file(
                tmp_path, baseline, lane, {"detector_rule_id": target}
            ).read_bytes()
            == effective
        )
        lane["mutation_config_sha256"][target] = "0" * 64
        with pytest.raises(RuntimeAuditError, match="E_SEMGREP_MUTATION"):
            _semgrep_mutation_file(
                tmp_path, baseline, lane, {"detector_rule_id": target}
            )
    with pytest.raises(RuntimeAuditError, match="E_SEMGREP_MUTATION"):
        _semgrep_disable_rule(baseline, "unknown-detector")


@pytest.mark.parametrize(
    "option", ["--disable-nosem", "--no-git-ignore", "--dataflow-traces"]
)
def test_semgrep_challenge_rejects_weakened_profile(option):
    from factoryline.deep_audit_io import _semgrep_challenge_command

    profile = json.loads(
        Path("deploy/deep-adapters/profiles/semgrep-pattern-limited.json").read_text()
    )
    command = _semgrep_challenge_command(profile)
    assert "--no-rewrite-rule-ids" in command["argv"]
    assert "{config}" in command["argv"]
    profile["commands"][0]["argv"].remove(option)
    with pytest.raises(RuntimeAuditError, match="E_SEMGREP_PROFILE"):
        _semgrep_challenge_command(profile)


def adapter_inputs(tmp_path):
    import sys

    source, output = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    output.mkdir()
    (source / "app.txt").write_bytes(b"candidate")
    lane = {
        "engine": "runtime",
        "mode": "native",
        "tool_version": "test-harness-1",
        "ruleset_sha256": "a" * 64,
        "timeout_seconds": 5,
        "report": "report.json",
        "coverage": "coverage.json",
        "challenge_report": "challenges.json",
    }
    script = (
        "import json; from pathlib import Path; "
        f"root=Path({str(output)!r}); "
        "[(root/name).write_text(json.dumps({'observed': name})) "
        "for name in ('report.json','coverage.json','challenges.json')]"
    )
    profile = {
        "schema": "factory.adapter-profile.v1",
        **{
            key: lane[key]
            for key in ("engine", "mode", "tool_version", "ruleset_sha256")
        },
        "commands": [
            {"argv": [sys.executable, "-c", script], "accepted_exit_codes": [0]}
        ],
    }
    contract = {
        "schema": "factory.deep-adapter-input.v1",
        "run_id": "test",
        "manifest_sha256": "b" * 64,
        "inventory": {
            "candidate_sha256": "c" * 64,
            "files": [{"path": "app.txt", "sha256": sha256_bytes(b"candidate")}],
        },
        "lane": lane,
        "obligations": [],
    }
    return profile, contract, source, output


@pytest.mark.parametrize(
    "engine", ["codeql", "osv", "gitleaks", "trivy", "runtime", "atheris"]
)
def test_adapter_joins_actual_artifacts_without_inventing_coverage(tmp_path, engine):
    from factoryline.deep_audit_io import execute_adapter_profile

    profile, contract, source, output = adapter_inputs(tmp_path)
    profile["engine"] = contract["lane"]["engine"] = engine
    # This is a synthetic artifact transport test, not execution of these tools.
    result = execute_adapter_profile(profile, contract, source, output)
    assert result["schema"] == "factory.deep-worker.v1"
    assert result["run_id"] == "test"
    assert result["candidate_sha256"] == "c" * 64
    coverage = result["artifacts"]["coverage.json"]
    assert coverage["observed"] == "coverage.json"
    assert "complete" not in coverage
    assert coverage["native_invocations"][0]["execution"]["exit_code"] == 0
    assert coverage["invocation_sha256"] == digest(coverage["native_invocations"])


def test_native_counter_stderr_capture_is_bounded_and_explicit(tmp_path):
    import sys

    from factoryline.runtime_audit_process import run_bounded_command

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    stderr = scratch / "native-stderr.txt"
    facts = run_bounded_command(
        [
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('SAMPLE_SECRET_VALUE scanned ~3 bytes (3 bytes)\\n')",
        ],
        tmp_path,
        5,
        scratch,
        stderr_path=stderr,
    )
    assert facts["exit_code"] == 0
    assert facts["cleanup_confirmed"] is True
    assert facts["stderr_bytes"] == stderr.stat().st_size
    assert "SAMPLE_SECRET_VALUE" in stderr.read_text(encoding="utf-8")
    assert "SAMPLE_SECRET_VALUE" not in json.dumps(facts)
    stderr.unlink()


def test_runtime_supervisor_uses_shared_cleanup_unit_and_preserves_stream_hashes(
    tmp_path, monkeypatch
):
    import hashlib

    from factoryline import assembly_process
    from factoryline.runtime_audit_process import run_bounded_command

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    stdout = scratch / "stdout.bin"
    stderr = scratch / "stderr.bin"
    launched = {}
    launch = assembly_process._launch

    def capture_launch(*args, **kwargs):
        child, unit, error = launch(*args, **kwargs)
        launched.update(child=child, unit=unit, error=error)
        return child, unit, error

    monkeypatch.setattr(assembly_process, "_launch", capture_launch)
    facts = run_bounded_command(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'capture-bound\\n'); "
            "sys.stderr.buffer.write(b'err\\n')",
        ],
        tmp_path,
        5,
        scratch,
        stdout_path=stdout,
        stderr_path=stderr,
    )

    assert launched["error"] is None
    assert launched["unit"] is launched["child"]._factory_cleanup_unit
    assert facts["cleanup_confirmed"] is True
    assert stdout.read_bytes() == b"capture-bound\n"
    assert facts["stdout_bytes"] == len(stdout.read_bytes())
    assert facts["stdout_sha256"] == hashlib.sha256(stdout.read_bytes()).hexdigest()
    assert stderr.read_bytes() == b"err\n"
    assert facts["stderr_sha256"] == hashlib.sha256(stderr.read_bytes()).hexdigest()
    assert launched["child"].returncode == 0


def test_runtime_supervisor_cleans_descendant_after_normal_root_exit(tmp_path):
    import hashlib

    from factoryline.runtime_audit_process import run_bounded_command

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    script = (
        "import subprocess,sys; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        "sys.stdout.buffer.write(b'root-exit\\n')"
    )
    facts = run_bounded_command([sys.executable, "-c", script], tmp_path, 5, scratch)

    assert facts["exit_code"] == 0
    assert facts["cleanup_confirmed"] is True
    assert facts["stdout_bytes"] == len(b"root-exit\n")
    assert facts["stdout_sha256"] == hashlib.sha256(b"root-exit\n").hexdigest()


def test_runtime_supervisor_caps_capture_but_hashes_full_overflow_stream(
    tmp_path,
):
    import hashlib

    from factoryline.runtime_audit_process import MAX_OUTPUT, run_bounded_command

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    output = scratch / "stdout.bin"
    size = MAX_OUTPUT + 1
    facts = run_bounded_command(
        [
            sys.executable,
            "-c",
            f"import sys; sys.stdout.buffer.write(b'x' * {size})",
        ],
        tmp_path,
        10,
        scratch,
        stdout_path=output,
    )

    expected = b"x" * size
    assert facts["output_limit_exceeded"] is True
    assert facts["stdout_bytes"] == size
    assert facts["stdout_sha256"] == hashlib.sha256(expected).hexdigest()
    assert output.stat().st_size <= MAX_OUTPUT
    assert facts["cleanup_confirmed"] is True


def test_runtime_supervisor_cleans_on_cancellation(tmp_path):
    import threading

    from factoryline.runtime_audit_process import run_bounded_command

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    cancelled = threading.Event()
    timer = threading.Timer(0.1, cancelled.set)
    timer.start()
    try:
        facts = run_bounded_command(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            tmp_path,
            5,
            scratch,
            cancelled=cancelled,
        )
    finally:
        timer.cancel()

    assert facts["cancelled"] is True
    assert facts["cleanup_confirmed"] is True


def test_runtime_supervisor_reports_native_handle_close_failure(tmp_path, monkeypatch):
    from factoryline import assembly_process
    from factoryline.runtime_audit_process import run_bounded_command

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    launch = assembly_process._launch

    def fail_after_close(*args, **kwargs):
        child, unit, error = launch(*args, **kwargs)
        if unit is not None:
            close = unit.close

            def close_then_fail():
                close()
                raise OSError("simulated native handle close failure")

            unit.close = close_then_fail
        return child, unit, error

    monkeypatch.setattr(assembly_process, "_launch", fail_after_close)
    facts = run_bounded_command([sys.executable, "-c", "pass"], tmp_path, 5, scratch)

    assert facts["exit_code"] == 0
    assert facts["cleanup_confirmed"] is False


@pytest.mark.parametrize(
    "stderr",
    [
        b"no scan counter",
        b"4:02AM INF scanned ~3 bytes (3 bytes) in 4ms\n"
        b"4:02AM INF scanned ~3 bytes (3 bytes) in 5ms",
        b"ERROR source says scanned ~3 bytes (3 bytes) in 4ms",
        b"4:02AM INF scanned ~16777217 bytes (16 MB) in 4ms",
    ],
)
def test_gitleaks_counter_rejects_missing_duplicate_and_inconsistent(stderr):
    from factoryline.deep_audit_io import _gitleaks_scanned_bytes

    with pytest.raises(RuntimeAuditError, match="E_GITLEAKS_COUNTER"):
        _gitleaks_scanned_bytes(stderr, "8.28.0")


def test_gitleaks_counter_reads_native_value_without_retaining_log_text():
    from factoryline.deep_audit_io import _gitleaks_scanned_bytes

    assert (
        _gitleaks_scanned_bytes(
            b"\x1b[90m4:02AM\x1b[0m \x1b[32mINF\x1b[0m "
            b"\x1b[1mscanned ~5000 bytes (5 KB) in 16.3ms\x1b[0m",
            "8.28.0",
        )
        == 5000
    )


def test_native_artifact_byte_budgets_accept_boundary_and_reject_overflow():
    from factoryline.deep_audit_io import (
        LIMIT,
        NATIVE_COVERAGE_LIMIT,
        _bounded_json_bytes,
    )

    for limit, code in (
        (NATIVE_COVERAGE_LIMIT, "E_GITLEAKS_LEDGER_SIZE"),
        (LIMIT, "E_WORKER_BUNDLE_SIZE"),
    ):
        assert len(_bounded_json_bytes("x" * (limit - 2), limit, code)) == limit
        with pytest.raises(RuntimeAuditError, match=code):
            _bounded_json_bytes("x" * (limit - 1), limit, code)


def test_gitleaks_matrix_budget_preflights_without_truncating_sources_or_rules():
    from factoryline.deep_audit_io import _gitleaks_coverage_preflight

    def fixture(source_count):
        files = [
            {
                "path": f"src/{index:03}.py",
                "sha256": "a" * 64,
                "bytes": 10,
                "mode": 420,
                "language": "python",
            }
            for index in range(source_count)
        ]
        return (
            {
                "ledger_json": "{}",
                "invocations": [],
                "version_probe": {},
                "rule_inventory": None,
            },
            {},
            {"files": files},
            {"languages": ["python"], "rule_ids": [f"rule-{i:03}" for i in range(200)]},
        )

    args = fixture(50)
    _gitleaks_coverage_preflight(*args, {}, [])
    args = fixture(55)
    with pytest.raises(
        RuntimeAuditError, match=r"55 sources x 200 rules \(11000 rows\)"
    ):
        _gitleaks_coverage_preflight(*args, {}, [])


def test_gitleaks_challenge_gaps_cannot_pass_complete():
    from factoryline.deep_audit_io import _gitleaks_challenges_complete

    assert not _gitleaks_challenges_complete(
        {"observations": [], "gaps": [{"reason": "E_ADAPTER_TIMEOUT"}]},
        ["obligation"],
    )


def test_challenge_gap_errors_keep_only_bounded_codes():
    from factoryline.deep_audit_io import _challenge_error_code
    from factoryline.runtime_audit_common import RuntimeAuditError

    assert _challenge_error_code(RuntimeAuditError("E_REPORT_JSON", "secret path")) == (
        "E_REPORT_JSON"
    )
    assert _challenge_error_code(ValueError("secret path")) == "E_CHALLENGE_EXECUTION"


def test_native_empty_string_fingerprints_are_preserved_and_location_bound(tmp_path):
    from test_deep_audit_sarif import location

    from factoryline.deep_audit_sarif import normalize_sarif

    source = tmp_path / "app.py"
    source.write_text("one\ntwo\n", encoding="utf-8")
    payload = report()
    result = payload["runs"][0]["results"][0]
    result["partialFingerprints"] = {
        "author": "",
        "commitMessage": "",
        "commitSha": "",
        "date": "",
        "email": "",
    }
    result["locations"] = [location(1)]
    first_path = tmp_path / "first.json"
    first_path.write_text(json.dumps(payload), encoding="utf-8")
    first = normalize_sarif(
        tmp_path,
        {"path": "first.json", "sha256": sha256_bytes(first_path.read_bytes())},
        {"id": "scanner", "driver": "Example", "version": "1"},
        {"app.py": sha256_bytes(source.read_bytes())},
    )["findings"][0]
    assert first["finding_identity_basis"] == "source_location_fallback"
    assert first["native_fingerprint_sha256"] == digest(
        {f"partialFingerprints:{key}": "" for key in result["partialFingerprints"]}
    )

    result["locations"] = [location(2)]
    second_path = tmp_path / "second.json"
    second_path.write_text(json.dumps(payload), encoding="utf-8")
    second = normalize_sarif(
        tmp_path,
        {"path": "second.json", "sha256": sha256_bytes(second_path.read_bytes())},
        {"id": "scanner", "driver": "Example", "version": "1"},
        {"app.py": sha256_bytes(source.read_bytes())},
    )["findings"][0]
    assert second["finding_identity_basis"] == "source_location_fallback"
    assert first["finding_id"] != second["finding_id"]


@pytest.mark.parametrize("value", [0, None, [], {}])
def test_native_fingerprint_rejects_non_string_values(value):
    from factoryline.deep_audit_sarif import _native

    with pytest.raises(RuntimeAuditError, match="E_FIELD"):
        _native({"partialFingerprints": {"author": value}})


def test_challenge_message_paths_normalize_exact_source_root(tmp_path):
    from factoryline.deep_audit_io import _normalize_challenge_sarif_paths

    roots = [tmp_path / "run-a" / "source", tmp_path / "run-b" / "source"]
    normalized = []
    for root in roots:
        run = {
            "results": [
                {
                    "message": {
                        "text": f"private-key detected in {root.as_posix()}/app.py."
                    }
                },
                {"message": {"text": f"unbound {root.as_posix()}-other/app.py"}},
            ]
        }
        _normalize_challenge_sarif_paths({"runs": [run]}, root)
        normalized.append(run)

    assert normalized[0]["results"][0]["message"]["text"] == (
        "private-key detected in /src/app.py."
    )
    assert normalized[1]["results"][0]["message"]["text"] == (
        "private-key detected in /src/app.py."
    )
    assert normalized[0]["results"][0] == normalized[1]["results"][0]
    assert (
        normalized[0]["results"][1]["message"]["text"]
        != (normalized[1]["results"][1]["message"]["text"])
    )


def test_gitleaks_rule_accounting_requires_exact_executed_source_matrix():
    from factoryline.deep_audit_sarif import _rule_accounting_gaps

    lane = {
        "engine": "gitleaks",
        "family": "secrets",
        "tool_version": "8.28.0",
        "rule_ids": ["rule-a"],
        "ruleset_sha256": "a" * 64,
    }
    required = {"app.py": "b" * 64}
    empty_report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitleaks",
                        "version": "8.28.0",
                        "rules": [{"id": "rule-a"}],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [],
            }
        ],
    }
    all_sources = {**required, "notes.md": "e" * 64}
    native_files = [
        {
            "path": path,
            "sha256": source_sha,
            "bytes": 1,
            "mode": 420,
            "language": language,
        }
        for path, source_sha, language in (
            ("app.py", required["app.py"], "python"),
            ("notes.md", all_sources["notes.md"], "markdown"),
        )
    ]
    candidate_sha = digest(native_files)
    source_map_sha = candidate_sha
    coverage = {
        "candidate_sha256": candidate_sha,
        "invocation_sha256": "c" * 64,
        "native_report_sha256": "d" * 64,
    }
    inventory_sha = digest(
        {"ruleset_sha256": lane["ruleset_sha256"], "rule_ids": ["rule-a"]}
    )
    coverage["rule_inventory"] = {
        "state": "VERIFIED",
        "rule_ids": ["rule-a"],
        "sha256": inventory_sha,
    }
    native_counts = {"attempted": 1, "regex_executed": 1}
    ledger = {
        "schema": "gitleaks.factory-rule-ledger.v1",
        "root_sha256": sha256_bytes(b"/src"),
        "source_identity_kind": "adapter_candidate_sha256",
        "source_sha256": coverage["candidate_sha256"],
        "config_sha256": lane["ruleset_sha256"],
        "prefilter_bypassed": True,
        "complete": True,
        "overflow": False,
        "invalid_paths": 0,
        "rows": [
            {"path": "app.py", "rule_id": "rule-a", "counts": native_counts},
            {
                "path": "notes.md",
                "rule_id": "rule-a",
                "counts": {"attempted": 1, "not_applicable_path_mismatch": 1},
            },
        ],
    }
    ledger_text = json.dumps(ledger, separators=(",", ":"))
    ledger_sha = sha256_bytes(ledger_text.encode())
    coverage["native_rule_ledger_json"] = ledger_text
    coverage["native_rule_ledger_sha256"] = ledger_sha
    coverage["native_source_inventory"] = native_files
    coverage["native_source_inventory_sha256"] = source_map_sha
    evidence = {
        "ledger_sha256": ledger_sha,
        "source_sha256": required["app.py"],
        "path": "app.py",
        "rule_id": "rule-a",
        "counts": native_counts,
    }
    row = {
        "path": "app.py",
        "source_sha256": required["app.py"],
        "disposition": "executed",
        "native_counts": native_counts,
        "evidence_sha256": digest(evidence),
    }
    accounting = {
        "schema": "factory.deep-rule-accounting.v1",
        "ruleset_sha256": lane["ruleset_sha256"],
        "rule_inventory_sha256": inventory_sha,
        "native_ledger_sha256": ledger_sha,
        "native_source_inventory_sha256": source_map_sha,
        "invocation_sha256": coverage["invocation_sha256"],
        "native_report_sha256": coverage["native_report_sha256"],
        "rules": [{"rule_id": "rule-a", "sources": [row]}],
    }
    accounting["accounting_sha256"] = digest(accounting)
    coverage["rule_accounting"] = accounting
    assert _rule_accounting_gaps(coverage, lane, required, empty_report) == []
    from factoryline.deep_audit_sarif import _coverage_source_gaps

    coverage.update(
        {
            "schema": "factory.deep-coverage.v1",
            "sources": required,
            "tool_version": lane["tool_version"],
            "ruleset_sha256": lane["ruleset_sha256"],
            "complete": True,
            "errors": [],
            "mode": "secrets-full",
            "fallback": False,
            "report_sha256": digest(empty_report),
            "obligations": [],
        }
    )
    lane["mode"] = "secrets-full"
    assert "SECRETS_NATIVE_ACCOUNTING_UNAVAILABLE" not in _coverage_source_gaps(
        empty_report, coverage, lane, required
    )
    invalid_accounting = deepcopy(coverage)
    invalid_accounting.pop("rule_accounting")
    accounting_gaps = _rule_accounting_gaps(
        invalid_accounting, lane, required, empty_report
    )
    assert accounting_gaps == ["RULE_ACCOUNTING_MISSING"]
    from factoryline.deep_audit_sarif import _coverage_gaps

    gaps, _, _ = _coverage_gaps(empty_report, invalid_accounting, lane, required, [])
    assert "SECRETS_NATIVE_ACCOUNTING_UNAVAILABLE" in gaps

    missing = deepcopy(coverage)
    missing.pop("rule_accounting")
    assert "RULE_ACCOUNTING_MISSING" in _rule_accounting_gaps(
        missing, lane, required, empty_report
    )
    assert "RULE_INVENTORY_UNVERIFIED" in _rule_accounting_gaps(
        coverage,
        {"engine": "gitleaks", "ruleset_sha256": "a" * 64},
        required,
        empty_report,
    )

    unverified = deepcopy(coverage)
    unverified["rule_inventory"]["state"] = "UNAVAILABLE"
    assert "RULE_INVENTORY_UNVERIFIED" in _rule_accounting_gaps(
        unverified, lane, required, empty_report
    )

    skipped = deepcopy(coverage)
    skipped["rule_accounting"]["rules"][0]["sources"][0]["disposition"] = "not_run"
    body = {
        key: value
        for key, value in skipped["rule_accounting"].items()
        if key != "accounting_sha256"
    }
    skipped["rule_accounting"]["accounting_sha256"] = digest(body)
    assert "RULE_NATIVE_DISPOSITION_DRIFT" in _rule_accounting_gaps(
        skipped, lane, required, empty_report
    )

    tampered = deepcopy(coverage)
    tampered["rule_accounting"]["rules"][0]["sources"][0]["source_sha256"] = "f" * 64
    body = {
        key: value
        for key, value in tampered["rule_accounting"].items()
        if key != "accounting_sha256"
    }
    tampered["rule_accounting"]["accounting_sha256"] = digest(body)
    assert "RULE_SOURCE_EVIDENCE_DRIFT" in _rule_accounting_gaps(
        tampered, lane, required, empty_report
    )

    malformed = deepcopy(coverage)
    malformed_ledger = json.loads(malformed["native_rule_ledger_json"])
    malformed_ledger["rows"][0]["path"] = []
    malformed_text = json.dumps(malformed_ledger, separators=(",", ":"))
    malformed["native_rule_ledger_json"] = malformed_text
    malformed["native_rule_ledger_sha256"] = sha256_bytes(malformed_text.encode())
    assert "RULE_NATIVE_LEDGER_INVALID" in _rule_accounting_gaps(
        malformed, lane, required, empty_report
    )

    malformed_container = deepcopy(coverage)
    malformed_container["native_rule_ledger_json"] = "[]"
    malformed_container["native_rule_ledger_sha256"] = sha256_bytes(b"[]")
    assert "RULE_NATIVE_LEDGER_INVALID" in _rule_accounting_gaps(
        malformed_container, lane, required, empty_report
    )

    altered_inventory = deepcopy(coverage)
    altered_inventory["native_source_inventory"][1]["bytes"] = 2
    assert "RULE_NATIVE_SOURCE_INVENTORY_INVALID" in _rule_accounting_gaps(
        altered_inventory, lane, required, empty_report
    )

    injected_path = deepcopy(coverage)
    injected_ledger = json.loads(injected_path["native_rule_ledger_json"])
    injected_ledger["rows"].append(
        {
            "path": "unbound.py",
            "rule_id": "rule-a",
            "counts": native_counts,
        }
    )
    injected_text = json.dumps(injected_ledger, separators=(",", ":"))
    injected_path["native_rule_ledger_json"] = injected_text
    injected_path["native_rule_ledger_sha256"] = sha256_bytes(injected_text.encode())
    assert "RULE_NATIVE_LEDGER_UNBOUND" in _rule_accounting_gaps(
        injected_path, lane, required, empty_report
    )

    mixed = deepcopy(coverage)
    mixed_ledger = json.loads(mixed["native_rule_ledger_json"])
    mixed_counts = {**native_counts, "not_run_size_limit": 1}
    mixed_ledger["rows"][0]["counts"] = mixed_counts
    mixed_text = json.dumps(mixed_ledger, separators=(",", ":"))
    mixed_sha = sha256_bytes(mixed_text.encode())
    mixed["native_rule_ledger_json"] = mixed_text
    mixed["native_rule_ledger_sha256"] = mixed_sha
    mixed_row = mixed["rule_accounting"]["rules"][0]["sources"][0]
    mixed_row["native_counts"] = mixed_counts
    mixed_row["evidence_sha256"] = digest(
        {**evidence, "ledger_sha256": mixed_sha, "counts": mixed_counts}
    )
    mixed["rule_accounting"]["native_ledger_sha256"] = mixed_sha
    body = {
        key: value
        for key, value in mixed["rule_accounting"].items()
        if key != "accounting_sha256"
    }
    mixed["rule_accounting"]["accounting_sha256"] = digest(body)
    assert "RULE_NATIVE_DISPOSITION_DRIFT" in _rule_accounting_gaps(
        mixed, lane, required, empty_report
    )


def test_gitleaks_ledger_retained_findings_match_sarif_results():
    from factoryline.deep_audit_sarif import _native_finding_counts_match

    lane = {"id": "gitleaks", "engine": "gitleaks", "tool_version": "8.28.0"}
    sources = {"app.py": "b" * 64}
    report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "gitleaks",
                        "version": "8.28.0",
                        "rules": [{"id": "rule-a"}],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [
                    {
                        "ruleId": "rule-a",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    assert not _native_finding_counts_match(
        report, lane, sources, {("app.py", "rule-a"): {"finding": 0}}
    )
    assert _native_finding_counts_match(
        report, lane, sources, {("app.py", "rule-a"): {"finding": 1}}
    )
    empty = deepcopy(report)
    empty["runs"][0]["results"] = []
    assert not _native_finding_counts_match(
        empty, lane, sources, {("app.py", "rule-a"): {"finding": 1}}
    )


def test_native_mutation_execution_requires_signed_exact_effective_config_hash():
    from factoryline.deep_audit_sarif import _challenge_execution_config_valid

    effective = "b" * 64
    lane = {
        "ruleset_sha256": "a" * 64,
        "rule_ids": ["rule-a", "rule-b"],
        "mutation_config_sha256": {"rule-a": effective, "rule-b": "c" * 64},
    }
    obligation = {"detector_rule_id": "rule-a"}
    execution = {
        "baseline_config_sha256": "a" * 64,
        "effective_config_sha256": effective,
        "mutation": {
            "disabled_rule_id": "rule-a",
            "remaining_rule_inventory_sha256": digest(["rule-b"]),
        },
    }
    assert _challenge_execution_config_valid(
        execution, {}, obligation, ("obligation", "mutation"), lane
    )
    execution["effective_config_sha256"] = "d" * 64
    assert not _challenge_execution_config_valid(
        execution, {}, obligation, ("obligation", "mutation"), lane
    )


def test_gitleaks_mutation_observation_is_host_validated_without_key_errors(tmp_path):
    from test_deep_audit_contract import execution_bundle, execution_fixture
    from factoryline.deep_audit_sarif import normalize_execution_bundle

    _, _, _, _, _, plan, inventory, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "gitleaks")
    lane["mutation_config_sha256"] = {"fixture-detection": "c" * 64}
    bundle = execution_bundle(lane, inventory, "0" * 32)
    coverage = bundle["artifacts"]["coverage.json"]
    coverage.update(
        candidate_sha256=inventory["candidate_sha256"],
        profile_sha256="c" * 64,
        version_probe={"probe": "verified-fixture"},
    )
    for observation in bundle["artifacts"]["challenges.json"]["observations"]:
        mutation = observation["kind"] == "mutation"
        expected_source = digest(
            {
                "app.py"
                if mutation or observation["kind"] == "positive"
                else "clean.py": observation["fixture_sha256"]
            }
        )
        execution = {
            "schema": "factory.native-challenge-execution.v1",
            "status": "VERIFIED",
            "launched": True,
            "completed": True,
            "timed_out": False,
            "cleanup_confirmed": True,
            "scratch_cleanup_verified": True,
            "timeout_seconds": 10,
            "duration_ms": 2,
            "exit_code": 0,
            "argv_sha256": "d" * 64,
            "raw_report_sha256": "e" * 64,
            "stdout_sha256": "f" * 64,
            "stdout_bytes": 0,
            "stderr_sha256": "a" * 64,
            "stderr_bytes": 0,
            "fixture_sha256": observation["fixture_sha256"],
            "candidate_binding_sha256": inventory["candidate_sha256"],
            "challenge_source_sha256": expected_source,
            "profile_binding_sha256": coverage["profile_sha256"],
            "image_binding_sha256": sha256_bytes(lane["image"].encode()),
            "tool_version": lane["tool_version"],
            "version_probe_sha256": digest(coverage["version_probe"]),
            "baseline_config_sha256": lane["ruleset_sha256"],
            "effective_config_sha256": "c" * 64 if mutation else lane["ruleset_sha256"],
            "ledger_sha256": "1" * 64,
            "mutation": (
                {
                    "disabled_rule_id": "fixture-detection",
                    "remaining_rule_inventory_sha256": digest([]),
                }
                if mutation
                else None
            ),
        }
        execution["execution_sha256"] = digest(execution)
        observation["execution"] = execution
    result = normalize_execution_bundle(
        bundle, lane, inventory, "0" * 32, plan["obligations"]
    )
    assert result["state"] == "INCOMPLETE"
    assert "CHALLENGE_FAILED" not in result["gaps"]


def _native_v2_validation_context(args):
    lane = {
        "engine": args["engine"],
        "family": "secrets",
        "image": "registry.example/gitleaks@sha256:" + "1" * 64,
        "tool_version": args["execution_bindings"]["tool_version"],
        "ruleset_sha256": args["expected_ruleset_sha256"],
        "rule_ids": args["rule_ids"],
        "mutation_config_sha256": args["mutation_ruleset_sha256"],
        "native_artifact_roles": args["native_artifact_roles"],
        "timeout_seconds": args["timeout_seconds"],
    }
    image_sha = sha256_bytes(lane["image"].encode())
    args["execution_bindings"]["image_sha256"] = image_sha
    coverage = {
        "profile_sha256": args["execution_bindings"]["profile_sha256"],
        "version_probe": args["execution_bindings"]["version_probe_facts"],
    }
    return lane, coverage, args["execution_bindings"]["candidate_sha256"]


def _native_v2_observation(args):
    execute = args.pop("execute")
    lane, coverage, candidate_sha = _native_v2_validation_context(args)
    observation = execute(**args)
    bound = args["challenge"]
    obligation = {"detector_rule_id": args["detector_rule_id"]}
    identity = (args["obligation_id"], bound["kind"])
    return observation, bound, obligation, identity, lane, coverage, candidate_sha


def test_native_v2_helper_output_passes_host_validator_and_resealed_tamper_fails(
    tmp_path,
):
    from test_runtime_audit import _native_challenge_v2
    from factoryline.deep_audit_sarif import _challenge_execution_v2_gap

    execute, args = _native_challenge_v2(tmp_path)
    observation, bound, obligation, identity, lane, coverage, candidate_sha = (
        _native_v2_observation({**args, "execute": execute})
    )
    assert not _challenge_execution_v2_gap(
        observation, bound, obligation, identity, lane, coverage, candidate_sha
    )

    tampered = deepcopy(observation)
    tampered["execution"]["native_artifacts"][0]["sha256"] = "0" * 64
    tampered["execution"]["execution_sha256"] = digest(
        {
            key: value
            for key, value in tampered["execution"].items()
            if key != "execution_sha256"
        }
    )
    assert _challenge_execution_v2_gap(
        tampered, bound, obligation, identity, lane, coverage, candidate_sha
    )


def test_native_v2_helper_mutation_is_checked_against_signed_digest_map(tmp_path):
    from test_runtime_audit import _native_challenge_v2
    from factoryline.deep_audit_sarif import _challenge_execution_v2_gap
    from factoryline.runtime_audit_common import canonical_bytes

    execute, args = _native_challenge_v2(tmp_path)
    args["challenge"]["kind"] = "mutation"
    args["detector_enabled"] = False
    effective = tmp_path / "mutation.toml"
    effective.write_bytes(b"id=rule-b\n")
    args["effective_config_path"] = effective
    args["bindings"]["config"] = str(effective)
    args["mutation_ruleset_sha256"]["rule-a"] = sha256_bytes(effective.read_bytes())
    expected = {
        "schema": "factory.deep-challenge-observation.v1",
        "engine": "gitleaks",
        "fixture_sha256": args["challenge"]["fixture_sha256"],
        "detector_rule_id": args["detector_rule_id"],
        "detector_enabled": False,
        "native_report": {"runs": [{"results": []}]},
    }
    args["challenge"]["expected_report_sha256"] = sha256_bytes(
        canonical_bytes(expected)
    )
    observation, bound, obligation, identity, lane, coverage, candidate_sha = (
        _native_v2_observation({**args, "execute": execute})
    )
    assert observation["execution"]["status"] == "VERIFIED"
    assert not _challenge_execution_v2_gap(
        observation, bound, obligation, identity, lane, coverage, candidate_sha
    )
    lane["mutation_config_sha256"]["rule-a"] = "f" * 64
    assert _challenge_execution_v2_gap(
        observation, bound, obligation, identity, lane, coverage, candidate_sha
    )


def test_gitleaks_v2_io_materializes_exact_fixture_tree_and_binds_roles(tmp_path):
    from factoryline.deep_audit_io import _run_gitleaks_challenge

    source = tmp_path / "candidate"
    source.mkdir()
    (source / "app.py").write_bytes(b"credential = 'fixture-secret'\n")
    (source / "clean.py").write_bytes(b"print('clean')\n")
    manifest = {
        "app.py": sha256_bytes((source / "app.py").read_bytes()),
        "clean.py": sha256_bytes((source / "clean.py").read_bytes()),
    }
    config = (
        b'[[rules]]\nid = "rule-a"\nregex = "fixture-secret"\n\n'
        b'[[rules]]\nid = "rule-b"\nregex = "other"\n'
    )
    baseline_path = tmp_path / "baseline.toml"
    baseline_path.write_bytes(config)
    lane = {
        "engine": "gitleaks",
        "image": "registry.example/gitleaks@sha256:" + "1" * 64,
        "tool_version": "8.28.0",
        "ruleset_sha256": sha256_bytes(config),
        "rule_ids": ["rule-a", "rule-b"],
        "mutation_config_sha256": {"rule-a": "f" * 64, "rule-b": "e" * 64},
        "native_artifact_roles": ["gitleaks_rule_ledger", "sarif_report"],
    }
    challenge = {
        "kind": "positive",
        "fixture_path": "app.py",
        "fixture_sha256": manifest["app.py"],
        "fixture_manifest": manifest,
        "fixture_manifest_sha256": digest(manifest),
        "expected_report_sha256": "a" * 64,
        "expected_exit_code": 10,
    }
    obligation = {
        "id": "obligation",
        "detector_rule_id": "rule-a",
        "challenges": [challenge],
    }
    contract = {"inventory": {"candidate_sha256": "c" * 64}}
    execution = {"version_probe": {"probe": "verified"}}
    observed = {}

    def capture(*args, **kwargs):
        observed["kwargs"] = kwargs
        observed["files"] = sorted(
            path.relative_to(kwargs["source_root"]).as_posix()
            for path in kwargs["source_root"].rglob("*")
            if path.is_file()
        )
        return {"status": "captured"}

    result = _run_gitleaks_challenge(
        capture,
        lambda *args, **kwargs: {},
        {"tool_version": "8.28.0"},
        contract,
        source,
        lane,
        execution,
        {"argv": ["/usr/bin/gitleaks", "dir", "{source}"]},
        challenge,
        obligation,
        manifest,
        baseline_path,
        config,
        tmp_path / "case",
        5,
    )
    assert result == {"status": "captured"}
    assert observed["files"] == sorted(manifest)
    assert observed["kwargs"]["native_artifact_roles"] == lane["native_artifact_roles"]
    assert observed["kwargs"]["native_artifacts"]["gitleaks_rule_ledger"].name == (
        "rule-ledger.json"
    )
    assert observed["kwargs"]["execution_bindings"][
        "challenge_source_sha256"
    ] == digest(manifest)


def test_signed_gitleaks_mutation_digest_map_must_cover_exact_rule_inventory(tmp_path):
    from test_deep_audit_contract import execution_fixture
    from factoryline.deep_audit_contract import _execution_lane

    _, _, _, _, _, plan, _, _ = execution_fixture(tmp_path)
    lane = next(item for item in plan["lanes"] if item["engine"] == "gitleaks")
    lane["mutation_config_sha256"] = {"fixture-detection": "c" * 64}
    _execution_lane(lane)
    lane["mutation_config_sha256"]["extra-rule"] = "d" * 64
    with pytest.raises(RuntimeAuditError, match="E_EXECUTION_LANE"):
        _execution_lane(lane)


def test_gitleaks_ledger_stable_read_rejects_metadata_drift(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from factoryline import deep_audit_io

    target = tmp_path / "ledger.json"
    target.write_text("{}", encoding="utf-8")
    actual_fstat = deep_audit_io.os.fstat
    calls = 0

    def changed_fstat(fd):
        nonlocal calls
        result = actual_fstat(fd)
        calls += 1
        if calls == 1:
            return result
        return SimpleNamespace(
            st_mode=result.st_mode,
            st_dev=result.st_dev,
            st_ino=result.st_ino,
            st_size=result.st_size,
            st_mtime_ns=result.st_mtime_ns + 1,
            st_ctime_ns=result.st_ctime_ns,
        )

    monkeypatch.setattr(deep_audit_io.os, "fstat", changed_fstat)
    with pytest.raises(RuntimeAuditError, match="E_GITLEAKS_LEDGER_SIZE"):
        deep_audit_io._read_gitleaks_ledger(target)


def test_gitleaks_rule_inventory_must_match_hash_pinned_toml():
    from factoryline.deep_audit_io import _gitleaks_rule_inventory

    config = b'[[rules]]\nid = "rule-a"\n\n[[rules]]\nid = "rule-b"\n'
    lane = {
        "ruleset_sha256": sha256_bytes(config),
        "rule_ids": ["rule-b", "rule-a"],
    }
    result = _gitleaks_rule_inventory(config, lane)
    assert result["state"] == "VERIFIED"
    assert result["rule_ids"] == ["rule-a", "rule-b"]
    assert len(result["sha256"]) == 64
    with pytest.raises(RuntimeAuditError, match="E_GITLEAKS_RULESET"):
        _gitleaks_rule_inventory(config, {**lane, "rule_ids": ["rule-a"]})
    with pytest.raises(RuntimeAuditError, match="E_GITLEAKS_RULESET"):
        _gitleaks_rule_inventory(config + b"# drift\n", lane)


def test_gitleaks_tomli_fallback_when_tomllib_is_unavailable(monkeypatch):
    import builtins
    import sys

    try:
        import tomllib as toml_parser
    except ModuleNotFoundError:
        import tomli as toml_parser

    from factoryline.deep_audit_io import _gitleaks_rule_ids

    monkeypatch.setitem(sys.modules, "tomli", toml_parser)
    original_import = builtins.__import__

    def without_tomllib(name, *args, **kwargs):
        if name == "tomllib":
            raise ModuleNotFoundError("simulated Python 3.10 stdlib")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_tomllib)
    assert _gitleaks_rule_ids(b'[[rules]]\nid="rule-a"\n') == ["rule-a"]
    with pytest.raises(RuntimeAuditError, match="E_GITLEAKS_RULESET"):
        _gitleaks_rule_ids(b"[[rules]\nmalformed")


def test_gitleaks_native_inventory_must_equal_authoritative_candidate(tmp_path):
    from factoryline.deep_audit_sarif import _worker_artifacts

    _, contract, _, _ = adapter_inputs(tmp_path)
    lane = {
        "engine": "gitleaks",
        "report": "report.json",
        "coverage": "coverage.json",
        "challenge_report": "challenges.json",
    }
    files = contract["inventory"]["files"]
    extra = {
        "path": "notes.md",
        "sha256": "d" * 64,
        "bytes": 0,
        "mode": 420,
        "language": "text",
    }
    forged = [*files, extra]
    coverage = {
        "native_source_inventory": forged,
        "candidate_sha256": digest(forged),
        "native_source_inventory_sha256": digest(forged),
    }
    bundle = {
        "schema": "factory.deep-worker.v1",
        "run_id": "test",
        "candidate_sha256": contract["inventory"]["candidate_sha256"],
        "artifacts": {
            "report.json": {},
            "coverage.json": coverage,
            "challenges.json": {},
        },
    }
    with pytest.raises(RuntimeAuditError, match="E_WORKER_BINDING"):
        _worker_artifacts(bundle, lane, contract["inventory"], "test")


def test_gitleaks_mutation_removes_only_declared_rule_block():
    from factoryline.deep_audit_io import _gitleaks_disable_rule, _gitleaks_rule_ids

    config = (
        b"[allowlist]\ndescription = 'keep'\n\n"
        b"[[rules]]\nid = 'rule-a'\nregex = 'alpha'\n\n"
        b"[[rules.allowlists]]\npaths = ['safe']\n\n"
        b"[[rules]]\nid = 'rule-b'\nregex = 'beta'\n"
    )
    mutated = _gitleaks_disable_rule(config, "rule-b")
    assert _gitleaks_rule_ids(mutated) == ["rule-a"]
    assert b"description = 'keep'" in mutated
    assert b"regex = 'alpha'" in mutated
    assert b"paths = ['safe']" in mutated
    assert b"regex = 'beta'" not in mutated
    with pytest.raises(RuntimeAuditError, match="E_GITLEAKS_MUTATION"):
        _gitleaks_disable_rule(config, "missing-rule")


def test_gitleaks_adapter_records_only_native_counter_not_stderr(tmp_path):
    import sys

    from factoryline.deep_audit_io import _adapter_commands

    source, scratch = tmp_path / "source", tmp_path / "scratch"
    source.mkdir()
    scratch.mkdir()
    line = "4:02AM INF scanned ~5000 bytes (5 KB) in 16.3ms"
    command = {
        "argv": [
            sys.executable,
            "-c",
            "import sys; sys.stderr.write(" + repr(line) + ")",
        ],
        "accepted_exit_codes": [0],
    }
    result = _adapter_commands(
        [command],
        {"engine": "gitleaks", "tool_version": "8.28.0", "timeout_seconds": 5},
        source,
        scratch,
    )
    assert result[0]["native_scanned_bytes"] == 5000
    assert line not in json.dumps(result)


@pytest.mark.parametrize(
    "failure", ["profile", "source", "stale", "missing", "exit", "drift"]
)
def test_adapter_rejects_drift_stale_missing_and_failed_execution(tmp_path, failure):
    from factoryline.deep_audit_io import execute_adapter_profile

    profile, contract, source, output = adapter_inputs(tmp_path)
    code = {
        "profile": "E_ADAPTER_PROFILE",
        "source": "E_REPORT_DRIFT",
        "stale": "E_ADAPTER_STALE",
        "missing": "E_SOURCE_MISSING",
        "exit": "E_ADAPTER_COMMAND",
        "drift": "E_REPORT_DRIFT",
    }[failure]
    if failure == "profile":
        profile["tool_version"] = "wrong-version"
    elif failure == "source":
        (source / "app.txt").write_bytes(b"changed")
    elif failure == "stale":
        (output / "report.json").write_text("{}")
    elif failure == "missing":
        profile["commands"][0]["argv"][-1] = "pass"
    elif failure == "exit":
        profile["commands"][0]["argv"][-1] = "raise SystemExit(7)"
    elif failure == "drift":
        profile["commands"][0]["argv"][-1] += "; Path('app.txt').write_text('changed')"
    with pytest.raises(RuntimeAuditError, match=code):
        execute_adapter_profile(profile, contract, source, output)


def test_adapter_rejects_relative_executable_and_boolean_exit_code(tmp_path):
    from factoryline.deep_audit_io import execute_adapter_profile

    profile, contract, source, output = adapter_inputs(tmp_path)
    profile["commands"][0]["accepted_exit_codes"] = [True]
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_PROFILE"):
        execute_adapter_profile(profile, contract, source, output)
    profile["commands"][0]["accepted_exit_codes"] = [0]
    profile["commands"][0]["argv"][0] = "python"
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_PROFILE"):
        execute_adapter_profile(profile, contract, source, output)


def native_inputs(tmp_path):
    import sys

    profile, contract, source, output = adapter_inputs(tmp_path)
    # Keep this as a generic incomplete native adapter fixture. OSV lanes now
    # require a pinned offline database identity and exercise that separately.
    profile["engine"] = contract["lane"]["engine"] = "runtime"
    profile.update(
        schema="factory.native-profile.v1",
        report_format="runtime-json",
        version_argv=[sys.executable, "-c", "print('test-harness-1')"],
    )
    contract["lane"]["languages"] = ["text"]
    contract["inventory"]["files"][0]["language"] = "text"
    profile["commands"][0]["argv"][-1] = (
        "from pathlib import Path; Path(r'{report}').write_text('{\"results\": []}')"
    )
    return profile, contract, source, output


def test_native_adapter_retains_execution_without_inventing_completion(tmp_path):
    from factoryline.deep_audit_io import execute_native_profile

    args = native_inputs(tmp_path)
    result = execute_native_profile(*args)
    coverage = result["artifacts"]["coverage.json"]
    assert coverage["complete"] is False
    assert coverage["errors"] == [
        "NATIVE_SOURCE_ACCOUNTING_REQUIRED",
        "NATIVE_CHALLENGES_REQUIRED",
    ]
    assert coverage["native_invocations"][0]["execution"]["exit_code"] == 0
    assert coverage["version_probe"]["exit_code"] == 0
    assert result["artifacts"]["challenges.json"]["observations"] == []


def test_runtime_junit_profile_normalizes_native_junit_and_coverage(tmp_path):
    from factoryline.deep_audit_io import _native_report

    output = tmp_path / "output"
    output.mkdir()
    (output / "runtime.xml").write_text(
        '<testsuite tests="1" failures="1" errors="0"><testcase file="/src/app.py" name="private-case" '
        'line="4"><failure message="private-output">secret text</failure>'
        "</testcase></testsuite>",
        encoding="utf-8",
    )
    raw_coverage = {
        "meta": {"branch_coverage": True},
        "files": {
            "/src/app.py": {
                "summary": {
                    "num_statements": 2,
                    "covered_lines": 1,
                    "num_branches": 1,
                    "covered_branches": 0,
                }
            }
        },
    }
    lane = {"tool_version": "runtime-test", "report": "runtime.xml"}
    inventory = {"files": [{"path": "app.py", "sha256": "a" * 64}]}
    report = _native_report(
        raw_coverage,
        {"report_format": "runtime-junit", "tool_version": "runtime-test"},
        {"lane": lane, "inventory": inventory},
        output,
        [{"execution": {"exit_code": 1}}],
    )
    assert report["metrics"] == {"tests": 1}
    assert report["findings"] == [
        {
            "rule_id": "RUNTIME_TEST_FAILURE",
            "path": "app.py",
            "line": 5,
            "severity": "high",
        }
    ]
    assert "private-case" not in json.dumps(report)
    assert "secret text" not in json.dumps(report)
    assert report["source_coverage"]["app.py"]["sha256"] == "a" * 64


def semgrep_execution_evidence():
    import base64
    from factoryline.deep_audit_io import canonical_bytes, sha256_bytes

    rules = [
        {
            "id": "js-rule",
            "languages": ["javascript"],
            "message": "control",
            "severity": "ERROR",
            "pattern": "bad()",
        },
        {
            "id": "py-rule",
            "languages": ["python"],
            "message": "control",
            "severity": "ERROR",
            "pattern": "bad()",
        },
    ]
    config = canonical_bytes({"rules": rules})
    lane = {
        "engine": "semgrep",
        "tool_version": "1.141.0",
        "ruleset_sha256": sha256_bytes(config),
        "rule_ids": ["js-rule", "py-rule"],
        "native_artifact_roles": ["rule_inventory", "sarif_report"],
        "timeout_seconds": 30,
    }
    sources = {"app.py": "a" * 64, "app.js": "b" * 64}
    observations = []
    for index, (rule, path) in enumerate(zip(rules, ("app.js", "app.py"))):
        native = {
            "version": lane["tool_version"],
            "errors": [],
            "paths": {"scanned": ["/src/" + path]},
            "results": [],
        }
        observations.append(
            {
                "rule_id": rule["id"],
                "rule_config_sha256": digest({"rules": [rule]}),
                "rule_config_base64": base64.b64encode(
                    canonical_bytes({"rules": [rule]})
                ).decode(),
                "argv_sha256": "c" * 64,
                "execution": {
                    "exit_code": 0,
                    "timed_out": False,
                    "timeout_seconds": 30,
                    "duration_ms": 1,
                    "launch_error": False,
                    "output_limit_exceeded": False,
                    "cleanup_confirmed": True,
                    "stdout_sha256": "d" * 64,
                    "stderr_sha256": "e" * 64,
                    "stdout_bytes": 0,
                    "stderr_bytes": 0,
                },
                "native_report": native,
                "native_report_sha256": digest(native),
                "raw_report_sha256": sha256_bytes(canonical_bytes(native)),
                "raw_report_base64": base64.b64encode(canonical_bytes(native)).decode(),
            }
        )
        argv = [
            "/usr/bin/semgrep",
            "scan",
            "--json",
            "--strict",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--disable-nosem",
            "--no-rewrite-rule-ids",
            "--config",
            f"/tmp/factory-native-test/semgrep-rule-{index}/rule.json",
            "--json-output",
            f"/tmp/factory-native-test/semgrep-rule-{index}/report.json",
            "/src",
        ]
        observations[-1].update(argv=argv, argv_sha256=digest(argv))
    evidence = {
        "schema": "factory.semgrep-rule-execution.v1",
        "ruleset_base64": base64.b64encode(config).decode(),
        "observations": observations,
    }
    return evidence, lane, sources, {"runs": [{"results": []}]}


def test_semgrep_native_source_budget_rejects_before_tool_execution(tmp_path):
    from factoryline.deep_audit_io import _run_native_profile

    with pytest.raises(RuntimeAuditError, match="bounded source inventory"):
        _run_native_profile(
            {},
            {},
            tmp_path,
            tmp_path,
            {"files": [{}] * 65},
            {"engine": "semgrep", "native_artifact_roles": []},
            [],
        )


def test_osv_baseline_policy_requires_one_trusted_config_and_offline_scope():
    from factoryline.deep_audit_io import _osv_policy_inputs

    command = {
        "argv": [
            "/opt/factory/bin/osv-offline",
            "scan",
            "source",
            "-r",
            "{source}",
            "--config",
            "/opt/factory/rules/osv-scanner.toml",
            "--offline",
            "--offline-vulnerabilities",
            "--allow-no-lockfiles",
            "--all-packages",
            "--format",
            "json",
            "--output",
            "{report}",
        ],
        "accepted_exit_codes": [0, 1],
    }
    profile = {"commands": [command]}
    policy_bytes = Path("deploy/deep-adapters/rules/empty-ignore.txt").read_bytes()
    assert policy_bytes == b"\n"
    assert _osv_policy_inputs(profile, policy_bytes) is None

    sabotages = []
    missing_config = deepcopy(profile)
    del missing_config["commands"][0]["argv"][5:7]
    sabotages.append(missing_config)
    duplicated_config = deepcopy(profile)
    duplicated_config["commands"][0]["argv"][7:7] = [
        "--config",
        "/src/osv-scanner.toml",
    ]
    sabotages.append(duplicated_config)
    candidate_config = deepcopy(profile)
    candidate_config["commands"][0]["argv"][6] = "/src/osv-scanner.toml"
    sabotages.append(candidate_config)
    for argv_flag in (
        "--offline",
        "--offline-vulnerabilities",
        "--all-packages",
    ):
        omitted = deepcopy(profile)
        omitted["commands"][0]["argv"].remove(argv_flag)
        sabotages.append(omitted)

    unknown_command = deepcopy(profile)
    unknown_command["commands"][0]["argv"].append("--unknown-option")
    sabotages.append(unknown_command)

    for sabotage in sabotages:
        with pytest.raises(RuntimeAuditError, match="E_OSV_POLICY"):
            _osv_policy_inputs(sabotage, policy_bytes)
    for invalid_policy in (b"", b"\r\n", b'ignore = ["CVE-2026-0001"]\n'):
        with pytest.raises(RuntimeAuditError, match="E_OSV_POLICY"):
            _osv_policy_inputs(profile, invalid_policy)


def test_osv_preflight_rejects_missing_trusted_config_before_runner(
    monkeypatch, tmp_path
):
    from factoryline.deep_audit_io import _run_native_profile

    profile = json.loads(Path("deploy/deep-adapters/profiles/osv.json").read_text())

    def missing_policy(*_args):
        raise FileNotFoundError("missing trusted config")

    def runner_must_not_start(*_args, **_kwargs):
        raise AssertionError("native runner started before policy preflight")

    monkeypatch.setattr("factoryline.deep_audit_io.local_file", missing_policy)
    monkeypatch.setattr(
        "factoryline.deep_audit_io._native_version", runner_must_not_start
    )
    with pytest.raises(RuntimeAuditError, match="E_OSV_POLICY"):
        _run_native_profile(
            profile,
            {},
            tmp_path,
            tmp_path,
            {"files": [], "candidate_sha256": "a" * 64},
            {
                "engine": "osv",
                "mode": "offline-pypi-snapshot",
                "timeout_seconds": 30,
            },
            ["report.json"],
        )


def test_osv_worker_copies_existing_empty_policy_asset():
    dockerfile = Path("deploy/deep-adapters/Dockerfile").read_text()
    assert (
        "COPY --chown=1000:1000 deploy/deep-adapters/rules/empty-ignore.txt "
        "/opt/factory/rules/osv-scanner.toml"
    ) in dockerfile
    sdk_copy = next(
        line
        for line in dockerfile.splitlines()
        if line.startswith("COPY factoryline/__init__.py")
    )
    assert "factoryline/deep_audit_sarif.py" in sdk_copy


_WORKER_IMPORT_MODULES = frozenset(
    {
        "factoryline/__init__.py",
        "factoryline/deep_audit_io.py",
        "factoryline/deep_audit.py",
        "factoryline/deep_audit_sarif.py",
        "factoryline/deep_audit_contract.py",
        "factoryline/deep_audit_loop.py",
        "factoryline/deep_audit_attestation.py",
        "factoryline/audit_action_refs.py",
        "factoryline/audit_taxonomy.py",
        "factoryline/enterprise_receipts.py",
        "factoryline/runtime_audit_common.py",
        "factoryline/runtime_audit_process.py",
        "factoryline/assembly_process.py",
    }
)


def _worker_copy_sources(dockerfile: str, destination: str) -> set[str]:
    sources = set()
    for line in dockerfile.splitlines():
        parts = line.split()
        if len(parts) > 2 and parts[0] == "COPY" and parts[-1] == destination:
            sources.update(
                part for part in parts[1:-1] if part.startswith("factoryline/")
            )
    return sources


def _copy_worker_modules(root: Path, package_root: Path, sources: set[str]) -> None:
    for source in sources:
        destination = package_root / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((root / source).read_bytes())
    resource = package_root / "factoryline/data/junie_pack.json"
    resource.parent.mkdir(parents=True, exist_ok=True)
    resource.write_bytes((root / "factoryline/data/junie_pack.json").read_bytes())


def _run_worker_import(package_root: Path) -> subprocess.CompletedProcess:
    code = (
        "import importlib.machinery,pathlib,runpy,sys; "
        "assert tuple(sys.meta_path)==(importlib.machinery.BuiltinImporter,"
        "importlib.machinery.FrozenImporter,importlib.machinery.PathFinder); "
        "root=pathlib.Path(sys.argv[1]).resolve(); sys.path.insert(0,str(root)); "
        "import factoryline; "
        "assert pathlib.Path(factoryline.__file__).resolve()==root/'factoryline/__init__.py'; "
        "factoryline.__path__=[str(root/'factoryline')]; "
        "import factoryline.deep_audit_loop; "
        "import factoryline.deep_audit_attestation; "
        "import factoryline.runtime_audit_process; "
        "sys.argv=['factoryline.deep_audit_io','--help']; "
        "runpy.run_module('factoryline.deep_audit_io',run_name='__main__')"
    )
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            code,
            str(package_root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _assert_worker_base_images_pinned(dockerfile: str) -> None:
    assert (
        "FROM python:3.11.17-slim-trixie@sha256:"
        "0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce AS python-source"
    ) in dockerfile
    assert (
        "FROM debian:forky-slim@sha256:"
        "3c80e257eff6274d593eb33a94bda5174ccd619836e6a728a73e11c97f2213e3 AS sdk"
    ) in dockerfile


def _assert_worker_image_imports(
    dockerfile: str, destination: str, package_root: Path
) -> None:
    copied = _worker_copy_sources(dockerfile, destination)
    assert _WORKER_IMPORT_MODULES <= copied
    assert (
        f"COPY factoryline/data/junie_pack.json {destination}data/junie_pack.json"
        in dockerfile.splitlines()
    )
    closure_bytes = sum((Path.cwd() / source).stat().st_size for source in copied)
    closure_bytes += Path("factoryline/data/junie_pack.json").stat().st_size
    assert closure_bytes <= 1_250_000
    _copy_worker_modules(Path.cwd(), package_root, copied)
    result = _run_worker_import(package_root)
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout


def _assert_missing_worker_module_fails(tmp_path: Path) -> None:
    missing_package = tmp_path / "worker-missing-module"
    _copy_worker_modules(
        Path.cwd(),
        missing_package,
        _WORKER_IMPORT_MODULES - {"factoryline/audit_action_refs.py"},
    )
    missing = _run_worker_import(missing_package)
    assert missing.returncode != 0
    assert "No module named 'factoryline.audit_action_refs'" in missing.stderr


def test_worker_images_ship_entrypoint_import_closure_and_detect_omissions(tmp_path):
    dockerfile = Path("deploy/deep-adapters/Dockerfile").read_text()
    _assert_worker_base_images_pinned(dockerfile)
    destinations = (
        "/usr/local/lib/python3.11/site-packages/factoryline/",
        "/usr/lib/python3.12/site-packages/factoryline/",
    )
    for index, destination in enumerate(destinations):
        _assert_worker_image_imports(
            dockerfile, destination, tmp_path / f"worker-{index}"
        )
    sdk_stage = dockerfile.split("FROM semgrep/semgrep:", 1)[0]
    semgrep_stage = dockerfile.split("FROM semgrep-tool AS semgrep-worker", 1)[1].split(
        "FROM sdk AS codeql-python-worker", 1
    )[0]
    assert "USER 1000:1000" in sdk_stage
    assert 'ENTRYPOINT ["/opt/factory/bin/audit-adapter"]' in sdk_stage
    assert "USER 1000:1000" in semgrep_stage
    assert (
        'ENTRYPOINT ["/usr/bin/python", "-I", "-m", "factoryline.deep_audit_io"]'
        in semgrep_stage
    )
    _assert_missing_worker_module_fails(tmp_path)


def _osv_package_accounting_fixture(
    path="requirements.txt", name="werkzeug", version="0.1", ecosystem="PyPI"
):
    return {
        "results": [
            {
                "source": {"path": path},
                "packages": [
                    {
                        "package": {
                            "name": name,
                            "version": version,
                            "ecosystem": ecosystem,
                        },
                        "vulnerabilities": [],
                    }
                ],
            }
        ]
    }


def test_osv_source_accounting_binds_and_sorts_duplicate_package_rows():
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_package_accounting_fixture()
    duplicate = deepcopy(report["results"][0]["packages"][0])
    report["results"][0]["packages"].extend(
        [
            deepcopy(duplicate),
            {
                "package": {
                    "name": "requests",
                    "version": "2.31.0",
                    "ecosystem": "PyPI",
                },
                "vulnerabilities": [],
            },
        ]
    )
    required = {"requirements.txt": "a" * 64}
    observed = _osv_source_accounting(report, required, "offline-pypi-snapshot")
    source = observed["sources"]["requirements.txt"]
    assert observed["schema"] == "factory.osv-source-accounting.v1"
    assert observed["scope"] == "native_manifest_package_reporting"
    assert observed["state"] == "COMPLETE"
    assert (
        observed["required_paths"] == observed["measured_paths"] == ["requirements.txt"]
    )
    assert observed["missing_paths"] == []
    assert source["sha256"] == required["requirements.txt"]
    assert source["package_count"] == 3
    werkzeug = {"name": "werkzeug", "version": "0.1", "ecosystem": "PyPI"}
    assert source["packages"].count(werkzeug) == 2
    from factoryline.runtime_audit_common import canonical_bytes

    assert source["packages"] == sorted(source["packages"], key=canonical_bytes)
    assert source["packages_sha256"] == digest(source["packages"])
    assert observed["report_sha256"] == digest(report)
    assert observed["errors"] == []


@pytest.mark.parametrize(
    "report,expected_state,expected_error",
    [
        ({"results": []}, "UNAVAILABLE", None),
        (
            {"results": [_osv_package_accounting_fixture()["results"][0]] + []},
            "PARTIAL",
            "MISSING_MANIFESTS",
        ),
        (
            {
                "results": [
                    {"source": {"path": "requirements.txt"}, "packages": []},
                    _osv_package_accounting_fixture("constraints.txt")["results"][0],
                ]
            },
            "INCOMPLETE",
            "EMPTY_PACKAGE_INVENTORY",
        ),
        (
            {
                "results": [
                    _osv_package_accounting_fixture(ecosystem="npm")["results"][0],
                    _osv_package_accounting_fixture("constraints.txt")["results"][0],
                ]
            },
            "INCOMPLETE",
            "UNSUPPORTED_ECOSYSTEM",
        ),
    ],
)
def test_osv_source_accounting_distinguishes_missing_empty_and_unsupported(
    report, expected_state, expected_error
):
    from factoryline.deep_audit_sarif import _osv_source_accounting

    observed = _osv_source_accounting(
        report,
        {"requirements.txt": "a" * 64, "constraints.txt": "b" * 64},
        "offline-pypi-snapshot",
    )
    assert observed["state"] == expected_state
    expected_missing = (
        ["constraints.txt"]
        if expected_error == "MISSING_MANIFESTS"
        else ["constraints.txt", "requirements.txt"]
        if expected_state == "UNAVAILABLE"
        else []
    )
    assert observed["missing_paths"] == expected_missing
    if expected_error:
        assert expected_error in observed["errors"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda report: report["results"].append(deepcopy(report["results"][0])),
        lambda report: report["results"][0]["source"].update(path="outside.txt"),
        lambda report: report["results"][0]["packages"][0]["package"].pop("version"),
        lambda report: report.update(errors=["analysis failed"]),
        lambda report: report.update(results="malformed"),
    ],
)
def test_osv_source_accounting_rejects_duplicate_unbound_and_malformed(mutate):
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_package_accounting_fixture()
    mutate(report)
    with pytest.raises(RuntimeAuditError):
        _osv_source_accounting(
            report, {"requirements.txt": "a" * 64}, "offline-pypi-snapshot"
        )


def test_osv_source_accounting_hashes_identity_and_required_source_changes():
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_package_accounting_fixture()
    required = {"requirements.txt": "a" * 64}
    initial = _osv_source_accounting(report, required, "offline-pypi-snapshot")
    changed_identity = _osv_source_accounting(
        _osv_package_accounting_fixture(version="0.2"),
        required,
        "offline-pypi-snapshot",
    )
    changed_source = _osv_source_accounting(
        report, {"requirements.txt": "b" * 64}, "offline-pypi-snapshot"
    )
    assert (
        initial["sources"]["requirements.txt"]["packages_sha256"]
        != changed_identity["sources"]["requirements.txt"]["packages_sha256"]
    )
    assert initial["report_sha256"] == changed_source["report_sha256"]
    assert (
        initial["sources"]["requirements.txt"]["sha256"]
        != changed_source["sources"]["requirements.txt"]["sha256"]
    )


def test_osv_native_worker_dispatch_and_coverage_keep_challenge_gap():
    from factoryline.deep_audit_io import (
        _native_profile_coverage,
        _native_source_accounting,
    )

    report = _osv_package_accounting_fixture()
    inventory = {
        "files": [
            {
                "path": "requirements.txt",
                "language": "python",
                "sha256": "a" * 64,
            }
        ]
    }
    lane = {
        "engine": "osv",
        "mode": "offline-pypi-snapshot",
        "languages": ["python"],
        "timeout_seconds": 30,
        "tool_version": "2.2.0",
        "ruleset_sha256": "b" * 64,
    }
    direct = _native_source_accounting({}, report, inventory, lane)
    coverage = _native_profile_coverage(
        {
            "ledger": None,
            "ledger_sha256": None,
            "raw_report": report,
            "invocations": [],
            "version_probe": {},
            "rule_inventory": None,
        },
        report,
        inventory,
        lane,
        {"tool_version": "2.2.0", "ruleset_sha256": "b" * 64},
        {"observations": []},
        [],
    )
    assert coverage["source_accounting"] == direct
    assert coverage["complete"] is False
    assert coverage["errors"] == [
        "OSV_NATIVE_LOOKUPS_REQUIRED",
        "NATIVE_CHALLENGES_REQUIRED",
    ]


def test_osv_empty_native_accounting_keeps_both_worker_gaps():
    from factoryline.deep_audit_io import _native_profile_coverage

    report = {"results": []}
    inventory = {
        "files": [
            {
                "path": "requirements.txt",
                "language": "python",
                "sha256": "a" * 64,
            }
        ]
    }
    lane = {
        "engine": "osv",
        "mode": "offline-pypi-snapshot",
        "languages": ["python"],
        "timeout_seconds": 30,
        "tool_version": "2.2.0",
        "ruleset_sha256": "b" * 64,
    }
    coverage = _native_profile_coverage(
        {
            "ledger": None,
            "ledger_sha256": None,
            "raw_report": report,
            "invocations": [],
            "version_probe": {},
            "rule_inventory": None,
        },
        report,
        inventory,
        lane,
        {"tool_version": "2.2.0", "ruleset_sha256": "b" * 64},
        {"observations": []},
        [],
    )
    assert coverage["source_accounting"]["state"] == "UNAVAILABLE"
    assert coverage["complete"] is False
    assert coverage["errors"] == [
        "OSV_NATIVE_LOOKUPS_REQUIRED",
        "NATIVE_SOURCE_ACCOUNTING_REQUIRED",
        "NATIVE_CHALLENGES_REQUIRED",
    ]


def test_osv_worker_challenge_helpers_bind_policy_command_and_mutation():
    from factoryline.deep_audit_io import (
        _osv_challenge_command,
        _osv_config_rule_ids,
        _osv_mutation_valid,
        _osv_suppression_bytes,
    )

    profile = json.loads(Path("deploy/deep-adapters/profiles/osv.json").read_text())
    command = _osv_challenge_command(profile)
    assert command["argv"][command["argv"].index("--config") + 1] == "{config}"
    assert command["accepted_exit_codes"] == [0, 1]
    lane = {
        "rule_ids": ["OSV-CVE-2026-0001", "OSV-GHSA-abcd-1234-efgh"],
        "native_policy": {
            "advisory_aliases": {
                "OSV-CVE-2026-0001": ["CVE-2026-0001", "GHSA-abcd-1234-efgh"],
                "OSV-GHSA-abcd-1234-efgh": ["GHSA-abcd-1234-efgh"],
            }
        },
    }
    baseline = b"\n"
    effective = _osv_suppression_bytes(
        lane["native_policy"]["advisory_aliases"]["OSV-CVE-2026-0001"]
    )
    lane["mutation_config_sha256"] = {"OSV-CVE-2026-0001": sha256_bytes(effective)}
    assert _osv_config_rule_ids(baseline, lane) == lane["rule_ids"]
    assert _osv_config_rule_ids(effective, lane) == [lane["rule_ids"][1]]
    assert _osv_mutation_valid(baseline, effective, lane["rule_ids"][0], lane)
    assert not _osv_mutation_valid(
        baseline, effective + b"# changed\n", lane["rule_ids"][0], lane
    )
    assert not _osv_mutation_valid(b"", effective, lane["rule_ids"][0], lane)
    with pytest.raises(RuntimeAuditError):
        _osv_config_rule_ids(effective + b"# changed\n", lane)

    for damage in ("config", "source", "report"):
        changed = deepcopy(profile)
        argv = changed["commands"][0]["argv"]
        if damage == "config":
            argv[argv.index("--config") + 1] = "/src/osv.toml"
        elif damage == "source":
            argv[argv.index("-r") + 1] = "/src"
        else:
            argv[-1] = "/tmp/report.json"
        with pytest.raises(RuntimeAuditError):
            _osv_challenge_command(changed)


def test_osv_worker_control_comparison_requires_all_matching_control_sets():
    from factoryline.deep_audit_io import _osv_challenge_controls_match

    rows = {
        "inventory": [{"path": "requirements.txt", "name": "werkzeug"}],
        "unrelated_rows": [{"path": "requirements.txt", "name": "other"}],
        "target_rows": [{"path": "requirements.txt", "name": "werkzeug"}],
    }
    results = {
        "positive": deepcopy(rows),
        "negative": {**deepcopy(rows), "target_rows": []},
        "mutation": {**deepcopy(rows), "target_rows": []},
    }
    assert _osv_challenge_controls_match(results)
    for damage in (
        "missing_negative",
        "inventory",
        "unrelated",
        "positive_empty",
        "mutation_target",
    ):
        changed = deepcopy(results)
        if damage == "missing_negative":
            changed.pop("negative")
        elif damage == "inventory":
            changed["mutation"]["inventory"].append({"path": "x", "name": "drift"})
        elif damage == "unrelated":
            changed["mutation"]["unrelated_rows"].clear()
        elif damage == "positive_empty":
            changed["positive"]["target_rows"] = []
        else:
            changed["mutation"]["target_rows"] = deepcopy(rows["target_rows"])
        assert not _osv_challenge_controls_match(changed), damage


def test_osv_worker_challenge_dispatch_covers_every_matching_obligation(
    monkeypatch, tmp_path
):
    import factoryline.deep_audit_io as audit_io

    baseline_path = tmp_path / "osv-scanner.toml"
    baseline_path.write_bytes(b"\n")
    monkeypatch.setattr(audit_io, "local_file", lambda root, name: baseline_path)
    monkeypatch.setattr(
        audit_io,
        "_osv_database_identity",
        lambda lane, deadline=None: {"sha256": "a" * 64},
    )
    seen = []

    def fake_control(
        runner,
        profile,
        contract,
        source,
        lane,
        execution,
        command,
        config_path,
        baseline,
        obligation,
        challenge,
        case,
        deadline,
        observations,
        gaps,
        results,
    ):
        seen.append((obligation["id"], challenge["kind"]))
        observations.append(
            {
                "obligation_id": obligation["id"],
                "kind": challenge["kind"],
                "execution": {"status": "VERIFIED"},
            }
        )
        results[challenge["kind"]] = {
            "inventory": [{"path": "requirements.txt", "name": "werkzeug"}],
            "unrelated_rows": [],
            "target_rows": [{"id": obligation["id"]}]
            if challenge["kind"] == "positive"
            else [],
        }

    monkeypatch.setattr(audit_io, "_osv_challenge_control", fake_control)
    profile = json.loads(Path("deploy/deep-adapters/profiles/osv.json").read_text())
    lane = {
        "engine": "osv",
        "family": "dependencies",
        "mode": "offline-pypi-snapshot",
        "timeout_seconds": 30,
        "native_policy": {
            "baseline_config_sha256": sha256_bytes(b"\n"),
            "database_path": "/opt/factory/osv-db/osv-scanner/PyPI/all.zip",
        },
    }
    obligations = [
        {
            "id": f"osv-{index}",
            "engine": "osv",
            "family": "dependencies",
            "detector_rule_id": f"OSV-{index}",
            "challenges": [
                {"kind": kind, "fixture_path": "requirements.txt"}
                for kind in ("positive", "negative", "mutation")
            ],
        }
        for index in range(2)
    ]
    challenges, covered = audit_io._osv_challenges(
        profile, {"obligations": obligations}, tmp_path, lane, {}, time.monotonic()
    )
    assert covered == ["osv-0", "osv-1"]
    assert len(seen) == 6
    assert challenges["gaps"] == []


def test_osv_worker_challenge_dispatch_reports_deadline_without_running_controls(
    monkeypatch, tmp_path
):
    import factoryline.deep_audit_io as audit_io

    baseline_path = tmp_path / "osv-scanner.toml"
    baseline_path.write_bytes(b"\n")
    monkeypatch.setattr(audit_io, "local_file", lambda root, name: baseline_path)
    monkeypatch.setattr(
        audit_io,
        "_osv_database_identity",
        lambda lane, deadline=None: {"sha256": "a" * 64},
    )
    obligations = [
        {
            "id": "osv-1",
            "engine": "osv",
            "family": "dependencies",
            "challenges": [
                {"kind": kind} for kind in ("positive", "negative", "mutation")
            ],
        }
    ]
    lane = {
        "engine": "osv",
        "family": "dependencies",
        "timeout_seconds": 1,
        "native_policy": {"baseline_config_sha256": sha256_bytes(b"\n")},
    }
    profile = json.loads(Path("deploy/deep-adapters/profiles/osv.json").read_text())
    challenges, covered = audit_io._osv_challenges(
        profile,
        {"obligations": obligations},
        tmp_path,
        lane,
        {},
        time.monotonic() - 5,
    )
    assert covered == []
    assert len(challenges["gaps"]) == 3
    assert {item["reason"] for item in challenges["gaps"]} == {"E_ADAPTER_TIMEOUT"}


def test_osv_worker_malformed_signed_policy_returns_structured_challenge_gaps(
    monkeypatch, tmp_path
):
    import factoryline.deep_audit_io as audit_io

    baseline_path = tmp_path / "osv-scanner.toml"
    baseline_path.write_bytes(b"\n")
    monkeypatch.setattr(audit_io, "local_file", lambda root, name: baseline_path)
    monkeypatch.setattr(
        audit_io,
        "_osv_database_identity",
        lambda lane, deadline=None: {"sha256": "a" * 64},
    )
    profile = json.loads(Path("deploy/deep-adapters/profiles/osv.json").read_text())
    obligations = [
        {
            "id": "osv-malformed-policy",
            "engine": "osv",
            "family": "dependencies",
            "challenges": [
                {"kind": kind} for kind in ("positive", "negative", "mutation")
            ],
        }
    ]
    lane = {
        "engine": "osv",
        "family": "dependencies",
        "mode": "offline-pypi-snapshot",
        "timeout_seconds": 30,
        "native_policy": {},
    }
    challenges, covered = audit_io._osv_challenges(
        profile,
        {"obligations": obligations},
        tmp_path,
        lane,
        {},
        time.monotonic(),
    )
    assert covered == []
    assert challenges["observations"] == []
    assert len(challenges["gaps"]) == 3
    assert all(item["reason"].startswith("E_") for item in challenges["gaps"])


def test_osv_worker_database_identity_and_unbound_source_fail_closed(
    monkeypatch, tmp_path
):
    import factoryline.deep_audit_io as audit_io

    database = tmp_path / "all.zip"
    database.write_bytes(b"offline advisory snapshot")
    policy = {
        "database_path": "/opt/factory/osv-db/osv-scanner/PyPI/all.zip",
        "database_sha256": sha256_bytes(database.read_bytes()),
    }
    lane = {"native_policy": policy}
    monkeypatch.setattr(audit_io, "local_file", lambda root, name: database)
    identity = audit_io._osv_database_identity(lane)
    assert identity["sha256"] == policy["database_sha256"]
    assert identity["bytes"] == len(database.read_bytes())
    lane["native_policy"]["database_sha256"] = "0" * 64
    with pytest.raises(RuntimeAuditError, match="E_OSV_DATABASE"):
        audit_io._osv_database_identity(lane)

    report = {"results": [{"source": {"path": "../outside.txt"}, "packages": []}]}
    with pytest.raises(RuntimeAuditError, match="E_OSV_REPORT"):
        audit_io._osv_challenge_source_paths(
            report, tmp_path / "source", {"requirements.txt": "a" * 64}
        )


def test_osv_worker_observation_retains_failed_cleanup_evidence(tmp_path):
    import factoryline.deep_audit_io as audit_io

    source = tmp_path / "candidate"
    source.mkdir()
    (source / "requirements.txt").write_text("werkzeug==0.16.1\n")
    fixture_sha = sha256_bytes((source / "requirements.txt").read_bytes())
    profile = json.loads(Path("deploy/deep-adapters/profiles/osv.json").read_text())
    lane = {
        "engine": "osv",
        "family": "dependencies",
        "mode": "offline-pypi-snapshot",
        "image": "sha256:" + "a" * 64,
        "rule_ids": ["OSV-CVE-2026-0001"],
        "native_policy": {"baseline_config_sha256": sha256_bytes(b"\n")},
        "native_artifact_roles": {
            "osv_json_report": "report",
            "advisory_db_identity": "db",
        },
        "mutation_config_sha256": {},
    }
    contract = {"inventory": {"candidate_sha256": "b" * 64}}
    obligation = {
        "id": "osv-obligation",
        "detector_rule_id": "OSV-CVE-2026-0001",
        "paths": ["requirements.txt"],
    }
    challenge = {
        "kind": "positive",
        "fixture_path": "requirements.txt",
        "fixture_manifest": {"requirements.txt": fixture_sha},
    }
    command = audit_io._osv_challenge_command(profile)

    def execute(challenge_arg, **kwargs):
        assert challenge_arg is challenge
        assert kwargs["engine"] == "osv"
        assert (
            kwargs["expected_ruleset_sha256"]
            == lane["native_policy"]["baseline_config_sha256"]
        )
        return {
            "execution": {"status": "INCOMPLETE", "cleanup": {"complete": False}},
            "native_report": {"results": []},
        }

    observation, summary = audit_io._run_osv_challenge(
        execute,
        lambda *args: {},
        profile,
        contract,
        source,
        lane,
        {"version_probe": {"status": "VERIFIED"}},
        command,
        tmp_path / "osv-scanner.toml",
        b"\n",
        obligation,
        challenge,
        tmp_path / "case",
        time.monotonic() + 20,
        10,
    )
    assert observation["execution"]["cleanup"] == {"complete": False}
    assert observation["osv_control_evidence"] == summary == {}


def test_osv_worker_fixture_setup_delay_exhausts_absolute_deadline(
    monkeypatch, tmp_path
):
    import factoryline.deep_audit_io as audit_io

    source = tmp_path / "candidate"
    source.mkdir()
    (source / "requirements.txt").write_text("werkzeug==0.16.1\n")
    fixture_sha = sha256_bytes((source / "requirements.txt").read_bytes())
    profile = json.loads(Path("deploy/deep-adapters/profiles/osv.json").read_text())
    lane = {
        "image": "sha256:" + "a" * 64,
        "native_policy": {"baseline_config_sha256": sha256_bytes(b"\n")},
        "native_artifact_roles": {
            "osv_json_report": "report",
            "advisory_db_identity": "db",
        },
        "rule_ids": ["OSV-CVE-2026-0001"],
        "mutation_config_sha256": {},
    }
    contract = {"inventory": {"candidate_sha256": "b" * 64}}
    obligation = {
        "id": "osv-obligation",
        "detector_rule_id": "OSV-CVE-2026-0001",
        "paths": ["requirements.txt"],
    }
    challenge = {
        "kind": "positive",
        "fixture_path": "requirements.txt",
        "fixture_manifest": {"requirements.txt": fixture_sha},
    }
    clock = {"now": 10.0}
    monkeypatch.setattr(audit_io.time, "monotonic", lambda: clock["now"])
    copy_bytes = audit_io.bound_bytes

    def slow_copy(candidate, ref):
        clock["now"] = 21.0
        return copy_bytes(candidate, ref)

    monkeypatch.setattr(audit_io, "bound_bytes", slow_copy)
    called = []

    def execute(*args, **kwargs):
        called.append(True)
        return {"execution": {"status": "VERIFIED"}}

    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_TIMEOUT"):
        audit_io._run_osv_challenge(
            execute,
            lambda *args, **kwargs: {},
            profile,
            contract,
            source,
            lane,
            {"version_probe": {"status": "VERIFIED"}},
            audit_io._osv_challenge_command(profile),
            tmp_path / "osv-scanner.toml",
            b"\n",
            obligation,
            challenge,
            tmp_path / "case",
            20.0,
            10,
        )
    assert called == []


def test_osv_worker_post_database_hash_deadline_overrun_cannot_return_verified(
    monkeypatch, tmp_path
):
    import factoryline.deep_audit_io as audit_io

    clock = {"now": 10.0}
    calls = []
    identity = {
        "path": "/opt/factory/osv-db/osv-scanner/PyPI/all.zip",
        "sha256": "a" * 64,
    }

    def database_identity(lane, deadline):
        calls.append(deadline)
        if len(calls) == 2:
            clock["now"] = deadline + 1
        return identity

    monkeypatch.setattr(audit_io.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(audit_io, "_osv_database_identity", database_identity)
    runner_calls = []

    def runner(argv, cwd, budget, scratch, *, cancelled):
        runner_calls.append((argv, cwd, budget, scratch, cancelled))
        return {"status": "EXITED", "exit_code": 0}

    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_TIMEOUT"):
        audit_io._osv_challenge_runner(
            runner,
            ["osv", "scan"],
            tmp_path,
            10,
            tmp_path / "scratch",
            tmp_path / "identity.json",
            {"native_policy": {}},
            20.0,
        )
    assert len(runner_calls) == 1
    assert runner_calls[0][1] == tmp_path
    assert runner_calls[0][4].is_set() is False
    assert len(calls) == 2


def test_semgrep_native_rejects_resealed_wrong_rule_config_path():
    from factoryline.deep_audit_io import verify_semgrep_rule_execution

    evidence, lane, sources, baseline = semgrep_execution_evidence()
    observation = evidence["observations"][1]
    observation["argv"][10] = observation["argv"][10].replace("rule-1", "rule-0")
    observation["argv"][12] = observation["argv"][12].replace("rule-1", "rule-0")
    observation["argv_sha256"] = digest(observation["argv"])
    with pytest.raises(RuntimeAuditError, match="native command binding differs"):
        verify_semgrep_rule_execution(evidence, lane, sources, baseline)


def test_semgrep_native_rules_account_for_applicable_and_other_languages():
    from factoryline.deep_audit_io import (
        _semgrep_source_accounting,
        verify_semgrep_rule_execution,
    )

    evidence, lane, sources, baseline = semgrep_execution_evidence()
    checked = verify_semgrep_rule_execution(evidence, lane, sources, baseline)
    assert checked["state"] == "VERIFIED"
    assert checked["rules"][0]["executed_sources"] == ["app.js"]
    assert checked["rules"][0]["not_applicable_sources"] == ["app.py"]
    assert checked["rules"][1]["executed_sources"] == ["app.py"]
    lane["languages"] = ["python", "javascript"]
    inventory = {
        "files": [
            {
                "path": path,
                "sha256": sha,
                "language": "python" if path.endswith(".py") else "javascript",
            }
            for path, sha in sources.items()
        ]
    }
    source_accounting = _semgrep_source_accounting(
        {"semgrep_rule_execution": evidence, "raw_report": baseline}, inventory, lane
    )
    assert source_accounting["state"] == "COMPLETE"
    assert source_accounting["missing_paths"] == []


@pytest.mark.parametrize(
    "invalid",
    [
        "missing",
        "ruleset",
        "config",
        "version",
        "error",
        "timeout",
        "cleanup",
        "source",
        "duplicate",
        "extra-rule",
        "finding-drift",
        "argv",
        "raw-digest",
        "budget",
    ],
)
def test_semgrep_native_rule_execution_rejects_incomplete_or_resealed_evidence(invalid):
    from factoryline.deep_audit_io import verify_semgrep_rule_execution

    evidence, lane, sources, baseline = semgrep_execution_evidence()
    observed = evidence["observations"][0]
    native = observed["native_report"]
    mutations = {
        "missing": lambda: evidence["observations"].pop(),
        "ruleset": lambda: lane.update(ruleset_sha256="0" * 64),
        "config": lambda: observed.update(rule_config_sha256="0" * 64),
        "argv": lambda: observed.update(argv_sha256="0" * 64),
        "raw-digest": lambda: observed.update(raw_report_sha256="0" * 64),
        "budget": lambda: observed["execution"].update(timeout_seconds=31),
        "version": lambda: native.update(version="old"),
        "error": lambda: native.update(errors=[{"message": "parse failed"}]),
        "timeout": lambda: observed["execution"].update(timed_out=True),
        "cleanup": lambda: observed["execution"].update(cleanup_confirmed=False),
        "source": lambda: native["paths"].update(scanned=[]),
        "duplicate": lambda: native["paths"]["scanned"].append("/src/app.js"),
        "extra-rule": lambda: native.update(
            results=[
                {"check_id": "unselected", "path": "/src/app.js", "start": {"line": 1}}
            ]
        ),
        "finding-drift": lambda: native.update(
            results=[
                {"check_id": "js-rule", "path": "/src/app.js", "start": {"line": 1}}
            ]
        ),
    }
    mutations[invalid]()
    observed["native_report_sha256"] = digest(native)
    with pytest.raises(RuntimeAuditError):
        verify_semgrep_rule_execution(evidence, lane, sources, baseline)


def test_runtime_mutation_report_requires_a_passing_sentinel(tmp_path):
    from factoryline.deep_audit_io import _runtime_challenge_report

    target = "tests/test_target.py"
    sentinel = "tests/test_sentinel.py"
    coverage = tmp_path / "coverage.json"
    coverage.write_text(
        '{"meta":{"branch_coverage":true},"files":{}}', encoding="utf-8"
    )
    manifest = {target: "a" * 64, sentinel: "b" * 64}
    junit = (
        '<testsuite tests="1"><testcase file="/src/tests/test_sentinel.py" '
        'name="private-sentinel" /></testsuite>'
    ).encode()
    report = _runtime_challenge_report(
        junit,
        coverage,
        manifest,
        {"tool_version": "runtime-test"},
        {"kind": "mutation", "fixture_path": target},
    )
    assert report["metrics"] == {"tests": 1}
    assert report["findings"] == []
    assert "private-sentinel" not in json.dumps(report)
    no_sentinel = (
        '<testsuite tests="1"><testcase file="/src/tests/test_target.py" '
        'name="private-target" /></testsuite>'
    ).encode()
    with pytest.raises(RuntimeAuditError, match="E_RUNTIME_SENTINEL"):
        _runtime_challenge_report(
            no_sentinel,
            coverage,
            manifest,
            {"tool_version": "runtime-test"},
            {"kind": "mutation", "fixture_path": target},
        )


def test_bundled_runtime_profile_preserves_sealed_source_tree():
    profile = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "deploy/deep-adapters/profiles/runtime-coverage.json"
        ).read_text(encoding="utf-8")
    )
    assert profile["commands"][0]["argv"][:3] == ["/usr/local/bin/python", "-B", "-I"]


def test_runtime_challenge_oracle_ignores_volatile_metadata_not_coverage(tmp_path):
    from factoryline.deep_audit_io import _runtime_challenge_report, digest

    path = "tests/test_target.py"
    manifest = {path: "a" * 64}
    coverage = {
        "meta": {"branch_coverage": True, "timestamp": "first"},
        "files": {
            path: {
                "summary": {
                    "num_statements": 2,
                    "covered_lines": 2,
                    "num_branches": 2,
                    "covered_branches": 1,
                }
            }
        },
    }
    artifact = tmp_path / "coverage.json"
    challenge = {"kind": "positive", "fixture_path": path}
    reports = []
    for timestamp in ("first", "second"):
        coverage["meta"]["timestamp"] = timestamp
        artifact.write_text(json.dumps(coverage))
        junit = (
            f'<testsuite tests="1" failures="1" timestamp="{timestamp}">'
            f'<testcase file="{path}" name="target" time="{len(timestamp)}">'
            "<failure/></testcase></testsuite>"
        ).encode()
        reports.append(
            _runtime_challenge_report(
                junit, artifact, manifest, {"tool_version": "runtime-test"}, challenge
            )
        )
    assert digest(reports[0]) == digest(reports[1])
    coverage["files"][path]["summary"]["covered_branches"] = 2
    artifact.write_text(json.dumps(coverage))
    changed = _runtime_challenge_report(
        junit, artifact, manifest, {"tool_version": "runtime-test"}, challenge
    )
    assert digest(changed) != digest(reports[0])


def test_runtime_positive_control_rejects_unrelated_test_failure(tmp_path):
    from factoryline.deep_audit_io import _runtime_challenge_report

    junit = (
        '<testsuite tests="1" failures="1"><testcase file="tests/test_other.py" '
        'name="other"><failure/></testcase></testsuite>'
    ).encode()
    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_SEMANTICS"):
        _runtime_challenge_report(
            junit,
            tmp_path / "coverage.json",
            {"tests/test_other.py": "b" * 64, "tests/test_target.py": "a" * 64},
            {"tool_version": "runtime-test"},
            {"kind": "positive", "fixture_path": "tests/test_target.py"},
        )


@pytest.mark.parametrize("kind", ["positive", "negative", "mutation"])
def test_runtime_v2_challenge_executes_and_binds_junit_and_coverage(tmp_path, kind):
    import sys
    import time

    from factoryline.deep_audit_io import (
        _runtime_disable_rule,
        _runtime_challenge,
        _runtime_challenge_report,
        _native_version,
        digest,
    )
    from factoryline.runtime_audit_common import execute_native_challenge
    from factoryline.runtime_audit_process import run_bounded_command

    source = tmp_path / "candidate"
    (source / "tests").mkdir(parents=True)
    target = "tests/test_target.py"
    sentinel = "tests/test_sentinel.py"
    (source / target).write_text(
        "PASS\n" if kind == "negative" else "FAIL\n", encoding="utf-8"
    )
    (source / sentinel).write_text("PASS\n", encoding="utf-8")
    manifest = {
        target: sha256_bytes((source / target).read_bytes()),
        sentinel: sha256_bytes((source / sentinel).read_bytes()),
    }
    baseline = (
        b'[selectors]\nRUNTIME_TEST_FAILURE = "factory_runtime_failure"\n\n'
        b'[[rules]]\nid = "RUNTIME_TEST_FAILURE"\n'
    )
    baseline_path = tmp_path / "runtime-control.toml"
    baseline_path.write_bytes(baseline)
    changed = _runtime_disable_rule(baseline, "RUNTIME_TEST_FAILURE")
    config_sha = sha256_bytes(changed)
    coverage_json = '{"meta":{"branch_coverage":true},"files":{}}'
    script = (
        """import pathlib,sys
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
source, report, config = sys.argv[1:]
enabled = bool(tomllib.loads(pathlib.Path(config).read_text()).get("rules", []))
target = pathlib.Path(source, "tests/test_target.py")
fails = enabled and target.read_text().strip() == "FAIL"
cases = []
if enabled:
    case = '<testcase file="/src/tests/test_target.py" name="target" line="1">'
    cases.append(case + ('<failure message="assertion">failed</failure></testcase>' if fails else '</testcase>'))
cases.append('<testcase file="/src/tests/test_sentinel.py" name="sentinel" />')
pathlib.Path(report).write_text('<testsuite tests="' + str(len(cases)) + '" failures="' + str(int(fails)) + '">' + ''.join(cases) + '</testsuite>')
pathlib.Path(report).parent.joinpath("coverage.json").write_text("""
        + repr(coverage_json)
        + """)
sys.exit(1 if fails else 0)
"""
    )
    profile = {
        "tool_version": "runtime-test",
        "commands": [
            {
                "argv": [
                    sys.executable,
                    "-I",
                    "-c",
                    "exec(" + repr(script) + ")",
                    "{source}",
                    "{report}",
                    "{config}",
                ],
                "accepted_exit_codes": [0, 1],
            }
        ],
    }
    lane = {
        "engine": "runtime",
        "image": "factory-runtime@sha256:" + "a" * 64,
        "tool_version": "runtime-test",
        "ruleset_sha256": sha256_bytes(baseline),
        "rule_ids": ["RUNTIME_TEST_FAILURE"],
        "mutation_config_sha256": {"RUNTIME_TEST_FAILURE": config_sha},
        "native_artifact_roles": ["coverage_json", "junit_xml"],
        "languages": ["python"],
        "timeout_seconds": 20,
    }
    fixture_sha = manifest[target]
    challenge = {
        "kind": kind,
        "fixture_path": target,
        "fixture_sha256": fixture_sha,
        "fixture_manifest": manifest,
        "fixture_manifest_sha256": digest(manifest),
        "expected_exit_code": 1 if kind == "positive" else 0,
        "expected_report_sha256": "0" * 64,
    }
    challenge_junit_cases = []
    if kind != "mutation":
        failed = kind == "positive"
        case = '<testcase file="/src/tests/test_target.py" name="target" line="1">'
        challenge_junit_cases.append(
            case
            + (
                '<failure message="assertion">failed</failure></testcase>'
                if failed
                else "</testcase>"
            )
        )
    challenge_junit_cases.append(
        '<testcase file="/src/tests/test_sentinel.py" name="sentinel" />'
    )
    expected_junit = (
        '<testsuite tests="'
        + str(len(challenge_junit_cases))
        + '" failures="'
        + str(int(kind == "positive"))
        + '">'
        + "".join(challenge_junit_cases)
        + "</testsuite>"
    ).encode()
    expected_artifacts = tmp_path / "expected-artifacts"
    expected_artifacts.mkdir()
    expected_coverage = expected_artifacts / "coverage.json"
    expected_coverage.write_text(coverage_json, encoding="utf-8")
    native_report = _runtime_challenge_report(
        expected_junit, expected_coverage, manifest, lane, challenge
    )
    expected_report = {
        "schema": "factory.deep-challenge-observation.v1",
        "engine": "runtime",
        "fixture_sha256": fixture_sha,
        "detector_rule_id": "RUNTIME_TEST_FAILURE",
        "detector_enabled": kind != "mutation",
        "native_report": native_report,
    }
    challenge["expected_report_sha256"] = digest(expected_report)
    probe = tmp_path / "version-probe"
    probe.mkdir()
    version = {
        "version_argv": [sys.executable, "-I", "-c", "print('runtime-test')"],
        "tool_version": "runtime-test",
    }
    version_facts = _native_version(version, tmp_path, probe, 5)
    execution = {"version_probe": version_facts}
    obligation = {"id": "runtime-control", "detector_rule_id": "RUNTIME_TEST_FAILURE"}
    contract = {"inventory": {"candidate_sha256": "c" * 64}}
    observation = _runtime_challenge(
        execute_native_challenge,
        run_bounded_command,
        profile,
        contract,
        source,
        lane,
        execution,
        profile["commands"][0],
        challenge,
        obligation,
        manifest,
        baseline_path,
        baseline,
        tmp_path / f"control-{kind}",
        time.monotonic() + 20,
    )
    assert observation["execution"]["status"] == "VERIFIED"
    assert observation["execution"]["cleanup_confirmed"] is True
    assert observation["execution"]["ledger_sha256"] is None
    assert {item["kind"] for item in observation["execution"]["native_artifacts"]} == {
        "coverage_json",
        "junit_xml",
    }


def test_native_adapter_rejects_uninventoried_source_files(tmp_path):
    from factoryline.deep_audit_io import _adapter_sources

    _, contract, source, _ = adapter_inputs(tmp_path)
    (source / "untracked.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_INPUT"):
        _adapter_sources(source, contract["inventory"])


@pytest.mark.parametrize(
    "failure", ["version", "version_exit", "native_exit", "missing", "stale"]
)
def test_native_adapter_rejects_failed_native_execution(tmp_path, failure):
    from factoryline.deep_audit_io import execute_native_profile

    profile, contract, source, output = native_inputs(tmp_path)
    codes = {
        "version": "E_TOOLCHAIN_DRIFT",
        "version_exit": "E_TOOLCHAIN_PROBE",
        "native_exit": "E_ADAPTER_COMMAND",
        "missing": "E_SOURCE_MISSING",
        "stale": "E_ADAPTER_STALE",
    }
    if failure == "version":
        profile["version_argv"][-1] = "print('test-harness-10')"
    elif failure == "version_exit":
        profile["version_argv"][-1] = "raise SystemExit(1)"
    elif failure == "native_exit":
        profile["commands"][0]["argv"][-1] = "raise SystemExit(8)"
    elif failure == "missing":
        profile["commands"][0]["argv"][-1] = "pass"
    elif failure == "stale":
        (output / "report.json").write_text("{}")
    with pytest.raises(RuntimeAuditError, match=codes[failure]):
        execute_native_profile(profile, contract, source, output)


def test_native_sarif_enrichment_uses_actual_invocation_and_preserves_failures():
    from factoryline.deep_audit_io import _native_sarif_metadata

    raw = {"runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}]}
    result = _native_sarif_metadata(
        raw, {"tool_version": "8.28.0"}, [{"execution": {"exit_code": 1}}]
    )
    assert result["runs"][0]["tool"]["driver"]["version"] == "8.28.0"
    assert "version" not in raw["runs"][0]["tool"]["driver"]
    raw["runs"][0]["invocations"] = [{"executionSuccessful": False}]
    assert (
        _native_sarif_metadata(raw, {"tool_version": "8.28.0"}, [])["runs"][0][
            "invocations"
        ][0]["executionSuccessful"]
        is False
    )


@pytest.mark.parametrize("code,findings", [(0, [1]), (1, []), (2, []), (False, [])])
def test_runtime_junit_rejects_process_report_mismatch(code, findings):
    from factoryline.deep_audit_io import _runtime_exit_consistency

    with pytest.raises(RuntimeAuditError, match="E_RUNTIME_REPORT"):
        _runtime_exit_consistency(
            {"findings": findings}, [{"execution": {"exit_code": code}}]
        )


def test_runtime_native_coverage_preserves_uncovered_branches(tmp_path):
    from factoryline.deep_audit_io import _native_coverage_report

    (tmp_path / "runtime.xml").write_text(
        '<testsuite tests="1"><testcase file="test_app.py" line="2"/></testsuite>'
    )
    raw = {
        "meta": {"branch_coverage": True},
        "files": {
            "app.py": {
                "summary": {
                    "num_statements": 4,
                    "covered_lines": 3,
                    "num_branches": 2,
                    "covered_branches": 1,
                }
            }
        },
    }
    inventory = {
        "files": [
            {"path": "app.py", "sha256": "a" * 64},
            {"path": "test_app.py", "sha256": "b" * 64},
        ]
    }
    report = _native_coverage_report(
        raw, {"tool_version": "7.10.7"}, inventory, tmp_path
    )
    assert report["metrics"]["tests"] == 1
    assert report["source_coverage"]["app.py"]["branches_covered"] == 1
    assert report["source_coverage"]["app.py"]["lines_covered"] == 3
    assert report["harness"]["sha256"] == "b" * 64


@pytest.mark.parametrize("invalid", ["no_branch", "entity", "unbound", "skipped"])
def test_runtime_native_coverage_rejects_unmeasured_or_unbound_evidence(
    tmp_path, invalid
):
    from factoryline.deep_audit_io import _native_coverage_report

    raw = {"meta": {"branch_coverage": invalid != "no_branch"}, "files": {}}
    xml = '<testsuite tests="1"><testcase file="test_app.py"/></testsuite>'
    if invalid == "entity":
        xml = '<!DOCTYPE testsuite [<!ENTITY x "unsafe">]>' + xml
    elif invalid == "unbound":
        xml = '<testsuite tests="1"><testcase file="other.py"/></testsuite>'
    elif invalid == "skipped":
        xml = '<testsuite tests="1"><testcase file="test_app.py"><skipped/></testcase></testsuite>'
    (tmp_path / "runtime.xml").write_text(xml)
    with pytest.raises(RuntimeAuditError):
        _native_coverage_report(
            raw,
            {"tool_version": "7"},
            {"files": [{"path": "test_app.py", "sha256": "a" * 64}]},
            tmp_path,
        )


def test_fuzz_snapshot_reports_measured_arcs_and_observed_callbacks(tmp_path):
    from factoryline.deep_audit_io import _fuzz_snapshot, _fuzz_record_input

    class MeasuredCoverage:
        def json_report(self, outfile):
            Path(outfile).write_text(
                json.dumps(
                    {
                        "files": {
                            "fuzz.py": {
                                "executed_branches": [[1, 2]],
                                "summary": {
                                    "num_statements": 3,
                                    "covered_lines": 2,
                                    "num_branches": 2,
                                    "covered_branches": 1,
                                },
                            }
                        }
                    }
                )
            )

    contract = {
        "lane": {"tool_version": "2.0.7"},
        "inventory": {"files": [{"path": "fuzz.py", "sha256": "a" * 64}]},
    }
    output = tmp_path / "fuzz.json"
    state = {"executions": 62, "inputs": set(), "findings": []}
    _fuzz_record_input(state, b"one")
    _fuzz_record_input(state, b"two")
    _fuzz_snapshot(
        MeasuredCoverage(),
        contract,
        "fuzz.py",
        output,
        state,
    )
    result = json.loads(output.read_text())
    assert result["metrics"] == {
        "executions": 64,
        "corpus_size": 2,
        "coverage_edges": 1,
    }
    assert result["source_coverage"]["fuzz.py"]["lines_covered"] == 2
    assert "lower bound" in result["metric_definitions"]["executions"]


def test_native_sarif_expands_only_bound_source_references():
    from factoryline.deep_audit_io import _native_sarif_paths

    report = {
        "runs": [
            {
                "originalUriBaseIds": {"SRC": {"uri": "file:///src/"}},
                "artifacts": [{"location": {"uri": "app.py", "uriBaseId": "SRC"}}],
                "results": [
                    {
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"index": 0},
                                    "region": {"startLine": 1},
                                }
                            }
                        ]
                    }
                ],
            }
        ]
    }
    result = _native_sarif_paths(report, {"app.py": "a" * 64})
    assert result["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ] == {"uri": "app.py"}
    report["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ] = {"uri": "app.py", "uriBaseId": "UNKNOWN"}
    with pytest.raises(RuntimeAuditError, match="E_SARIF_INDIRECTION"):
        _native_sarif_paths(report, {"app.py": "a" * 64})


@pytest.mark.parametrize(
    "uri", ["file:///etc/app.py", "../app.py", "/app.py", "https://host/app.py"]
)
def test_native_source_paths_reject_foreign_roots_and_traversal(uri):
    from factoryline.deep_audit_io import _native_source_path

    with pytest.raises(RuntimeAuditError):
        _native_source_path(uri, {"app.py": "a" * 64})


def test_native_dependency_paths_preserve_bound_manifest_identity():
    from factoryline.deep_audit_io import _native_dependency_paths

    sources = {"requirements.txt": "a" * 64}
    osv = {"results": [{"source": {"path": "/src/requirements.txt"}}]}
    syft = {"artifacts": [{"locations": [{"path": "/requirements.txt"}]}]}
    _native_dependency_paths(osv, "osv-json", sources)
    _native_dependency_paths(syft, "syft-json", sources)
    assert osv["results"][0]["source"]["path"] == "requirements.txt"
    assert syft["artifacts"][0]["locations"][0]["path"] == "requirements.txt"


@pytest.mark.parametrize("local_id", [False, True])
def test_docker_preflight_verifies_exact_immutable_pin(monkeypatch, local_id):
    import factoryline.deep_audit as module

    pin = ("" if local_id else "example/adapter@") + "sha256:" + "a" * 64
    calls = []

    def control(base, args):
        calls.append(args)
        value = "linux" if args[0] == "info" else (pin if local_id else [pin])
        return {"exit_code": 0}, json.dumps(value).encode()

    monkeypatch.setattr(module, "_docker_control", control)
    module._docker_preflight(["docker"], {"image": pin})
    field = ".Id" if local_id else ".RepoDigests"
    assert calls[-1] == ["image", "inspect", pin, "--format", "{{json " + field + "}}"]


@pytest.mark.parametrize("local_id", [False, True])
@pytest.mark.parametrize("actual", [None, {}, [], "sha256:" + "b" * 64])
def test_docker_preflight_rejects_wrong_pin_shape_or_digest(
    monkeypatch, local_id, actual
):
    import factoryline.deep_audit as module

    pin = ("" if local_id else "example/adapter@") + "sha256:" + "a" * 64

    def control(base, args):
        value = "linux" if args[0] == "info" else actual
        return {"exit_code": 0}, json.dumps(value).encode()

    monkeypatch.setattr(module, "_docker_control", control)
    with pytest.raises(RuntimeAuditError, match="E_IMAGE_PIN"):
        module._docker_preflight(["docker"], {"image": pin})


def test_docker_preflight_missing_local_image_never_pulls(monkeypatch):
    import factoryline.deep_audit as module

    calls = []

    def control(base, args):
        calls.append(args)
        return (
            ({"exit_code": 0}, b'"linux"')
            if args[0] == "info"
            else ({"exit_code": 1}, b"")
        )

    monkeypatch.setattr(module, "_docker_control", control)
    with pytest.raises(RuntimeAuditError, match="E_IMAGE_UNAVAILABLE"):
        module._docker_preflight(["docker"], {"image": "sha256:" + "a" * 64})
    assert [args[0] for args in calls] == ["info", "image"]


def test_missing_nested_source_has_typed_error(tmp_path: Path) -> None:
    from factoryline.deep_audit_io import local_file

    with pytest.raises(RuntimeAuditError) as exc:
        local_file(tmp_path, "missing/report.json")
    assert exc.value.code == "E_SOURCE_MISSING"


def inputs(tmp_path, *, clean=False, canary_kind="fail", canary_suppressed=False):
    def bind(plan):
        for key, name in (("report", "scan.json"), ("canary_report", "canary.json")):
            payload = report()
            result = payload["runs"][0]["results"][0]
            result["ruleId"] = "leak"
            payload["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "leak"
            result["partialFingerprints"]["primary/v1"] = key
            if key == "canary_report":
                result["kind"] = canary_kind
                if canary_suppressed:
                    result["suppressions"] = [
                        {"kind": "external", "status": "accepted"}
                    ]
            elif clean:
                payload["runs"][0]["results"] = []
            raw = json.dumps(payload).encode()
            (tmp_path / name).write_bytes(raw)
            plan["analyzers"][0][key]["sha256"] = sha256_bytes(raw)
        plan["canaries"][0]["fingerprint_sha256"] = digest(
            {"partialFingerprints:primary/v1": "canary_report"}
        )

    args = fixture(tmp_path, bind)
    checked = verify_deep_audit_plan(*args)
    analyzer = checked["plan"]["analyzers"][0]
    targets = [
        normalize_sarif(
            tmp_path, analyzer["report"], analyzer, checked["source_hashes"]
        )
    ]
    canaries = [
        normalize_sarif(
            tmp_path, analyzer["canary_report"], analyzer, checked["source_hashes"]
        )
    ]
    return args, checked["plan"], targets, canaries


def rehash(report):
    report.pop("normalized_sha256", None)
    report["normalized_sha256"] = digest(report)


def codes(receipt):
    return {action["code"] for action in receipt["repair_queue"]}


def test_signed_execution_threshold_and_idempotent_receipt(tmp_path):
    args, plan, targets, canaries = inputs(tmp_path)
    result = execute_deep_audit(*args)
    receipt = result["receipt"]
    packet = result["review_evidence"]
    assert packet["candidate_sha256"] == receipt["candidate_sha256"]
    assert packet["receipt_sha256"] == receipt["receipt_sha256"]
    assert result["review_evidence_path"].startswith(".factory/review-evidence/")
    assert (tmp_path / result["review_evidence_path"]).is_file()
    assert packet["authority"] == "none"
    assert any(
        "six distinct required audit lanes" in row["verification_action"]
        for row in packet["unknowns"]
    )
    assert receipt["decision"] == "BLOCKED"
    assert codes(receipt) == {"DEEP_RULE_THRESHOLD"}
    assert receipt["repair_queue"][0]["remediation"] == "Close owned resources"
    action = receipt["agent_actions"][0]
    assert action["measurement_id"] == receipt["repair_queue"][0]["rule_id"]
    assert action["candidate_sha256"] == receipt["candidate_sha256"]
    assert action["action"] == receipt["repair_queue"][0]["remediation"]
    assert action["evidence_to_attach"] and action["stop_condition"]
    assert execute_deep_audit(*args) == result
    status = deep_audit_status(tmp_path)
    assert status["state"] == "BLOCKED"
    assert status["agent_actions"] == receipt["agent_actions"]
    assert evaluate_deep_audit(plan, targets, canaries)["authority"] == "none"


def test_native_execution_outer_packet_uses_persisted_populated_lanes(tmp_path):
    from factoryline.deep_audit import _attach_execution_review_evidence
    from factoryline.deep_audit_io import write_run_json

    candidate = "a" * 64
    plan_lanes = []
    lanes = []
    for index in range(6):
        lane_id, engine = f"lane-{index}", f"engine-{index}"
        plan_lanes.append({"id": lane_id, "engine": engine})
        lanes.append(
            {
                "lane_id": lane_id,
                "family": "runtime" if index == 0 else "static",
                "engine": engine,
                "state": "OBSERVED",
                "gaps": [],
                "report_sha256": str(index) * 64,
                "coverage_sha256": str(index + 1) * 64,
                "native_execution": (
                    {"source_candidate_sha256": candidate, "cleanup_confirmed": True}
                    if index == 0
                    else None
                ),
                "findings": (
                    [
                        {
                            "rule_id": "R1",
                            "finding_id": "native-finding-1",
                            "kind": "fail",
                            "level": "warning",
                            "locations": [
                                {"path": "src/app.py", "source_sha256": "f" * 64}
                            ],
                            "flows": [],
                        }
                    ]
                    if index == 0
                    else []
                ),
            }
        )
    state = {"run_id": "native-test", "candidate_sha256": candidate, "lanes": lanes}
    root = tmp_path.resolve()
    run_dir = root / ".factory" / "deep-runs" / "native-test"
    run_dir.mkdir(parents=True)
    write_run_json(run_dir, "evidence.json", state)
    result = _attach_execution_review_evidence(
        root, run_dir, state, {"lanes": plan_lanes}
    )
    assert result["review_evidence"]["candidate_sha256"] == candidate
    assert len(result["review_evidence"]["claims"]) == 1
    assert (root / result["review_evidence_path"]).is_file()
    assert any(
        item["id"].startswith("source_link:")
        for item in result["review_evidence"]["unknowns"]
    )


def test_clean_with_detected_canary_requires_human_review(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    receipt = execute_deep_audit(*args)["receipt"]
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert receipt["repair_queue"] == []
    assert receipt["agent_actions"] == []
    assert receipt["authority"] == "none"
    assert (
        deep_audit_status(tmp_path)["verification"]
        == "self_hash_only_not_signature_or_freshness"
    )


@pytest.mark.parametrize(
    "kind", ["pass", "notApplicable", "review", "open", "informational"]
)
def test_nonfailure_canary_cannot_validate_analyzer(tmp_path, kind):
    args, _, _, _ = inputs(tmp_path, clean=True, canary_kind=kind)
    assert "HOLLOW_DEEP_AUDIT" in codes(execute_deep_audit(*args)["receipt"])


def test_suppressed_canary_cannot_validate_analyzer(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True, canary_suppressed=True)
    assert "HOLLOW_DEEP_AUDIT" in codes(execute_deep_audit(*args)["receipt"])


def test_missing_fingerprint_canary_fails_closed(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path, clean=True)
    canaries[0]["findings"] = []
    rehash(canaries[0])
    assert "HOLLOW_DEEP_AUDIT" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_trace_order_and_suppression_require_review(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    finding = targets[0]["findings"][0]
    finding["flows"][0].reverse()
    finding["suppressed"] = True
    rehash(targets[0])
    result = evaluate_deep_audit(plan, targets, canaries)
    assert {"DEEP_TRACE_INCOMPLETE", "DEEP_SUPPRESSION_UNAPPROVED"} <= codes(result)


def test_unknown_new_error_is_not_ignored(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    targets[0]["findings"][0]["rule_id"] = "unmapped"
    rehash(targets[0])
    assert "DEEP_UNKNOWN_ERROR" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_missing_duplicate_and_changed_reports_rejected(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_ANALYZER_INCOMPLETE"):
        evaluate_deep_audit(plan, [], canaries)
    with pytest.raises(RuntimeAuditError, match="E_DEEP_REPORT"):
        evaluate_deep_audit(plan, targets * 2, canaries)
    targets[0]["findings"] = []
    with pytest.raises(RuntimeAuditError, match="E_DEEP_REPORT"):
        evaluate_deep_audit(plan, targets, canaries)


def test_tampered_receipt_never_falls_back_to_green(tmp_path):
    args, _, _, _ = inputs(tmp_path, clean=True)
    result = execute_deep_audit(*args)
    from pathlib import Path

    Path(result["receipt_path"]).write_text("{}")
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"
    with pytest.raises(RuntimeAuditError, match="E_RECEIPT_COLLISION"):
        execute_deep_audit(*args)


def test_absent_and_pass_labels_do_not_hide_signed_threshold_findings(tmp_path):
    _, plan, targets, canaries = inputs(tmp_path)
    targets[0]["findings"][0].update(baseline="absent", kind="pass")
    rehash(targets[0])
    assert "DEEP_RULE_THRESHOLD" in codes(evaluate_deep_audit(plan, targets, canaries))


def test_cluster_signals_do_not_claim_causation(tmp_path):
    from factoryline.deep_audit import _clusters

    _, _, targets, _ = inputs(tmp_path)
    first = {**targets[0]["findings"][0], "obligation_id": "o", "category": "memory"}
    second = {
        **deepcopy(first),
        "analyzer_id": "second",
        "finding_id": "b" * 64,
        "category": "security",
    }
    clusters = _clusters([first, second])
    assert {item["kind"] for item in clusters} == {"corroboration", "compound_risk"}
    assert all(item["claim"] == "routing_signal_not_causation" for item in clusters)


def test_status_rejects_oversize_receipt(tmp_path, monkeypatch):
    args, _, _, _ = inputs(tmp_path, clean=True)
    execute_deep_audit(*args)
    monkeypatch.setattr("factoryline.deep_audit.LIMIT", 10)
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"


def test_status_rejects_non_directory_history(tmp_path):
    (tmp_path / ".factory").write_text("not a directory")
    assert deep_audit_status(tmp_path)["state"] == "INCOMPLETE"


@pytest.mark.parametrize("uri", ["/src/app.py", "file:///src/app.py"])
def test_native_absolute_source_ignores_unused_base(uri):
    from factoryline.deep_audit_io import _native_artifact_path

    assert (
        _native_artifact_path(
            {"uri": uri, "uriBaseId": "%SRCROOT%"}, {}, {"app.py": "a" * 64}
        )
        == "app.py"
    )


@pytest.mark.parametrize("target", [None, "/src", "/outside"])
def test_syft_native_metadata_source_is_exactly_bound(target):
    from factoryline.deep_audit_sarif import _execution_syft

    source = {"type": "directory", "name": "/src", "metadata": {"path": "/src"}}
    if target is not None:
        source["target"] = target
    report = {
        "source": source,
        "descriptor": {"name": "syft", "version": "1.33.0"},
        "schema": {"version": "16.0.0"},
        "artifacts": [
            {
                "id": "one",
                "name": "requests",
                "version": "2.31.0",
                "type": "python",
                "locations": [{"path": "requirements.txt"}],
            }
        ],
    }
    if target == "/outside":
        with pytest.raises(RuntimeAuditError, match="E_SBOM_SOURCE"):
            _execution_syft(
                report, {"tool_version": "1.33.0"}, {"requirements.txt": "a" * 64}
            )
    else:
        assert (
            _execution_syft(
                report, {"tool_version": "1.33.0"}, {"requirements.txt": "a" * 64}
            )
            == []
        )


def test_native_unbound_absolute_source_still_rejected():
    from factoryline.deep_audit_io import _native_artifact_path

    with pytest.raises(RuntimeAuditError):
        _native_artifact_path(
            {"uri": "/src/other.py", "uriBaseId": "%SRCROOT%"},
            {},
            {"app.py": "a" * 64},
        )


def test_osv_empty_native_results_remain_valid_not_complete():
    from factoryline.deep_audit_sarif import _execution_osv

    assert _execution_osv({"results": []}, {}, {"requirements.txt": "a" * 64}) == []
    with pytest.raises(RuntimeAuditError):
        _execution_osv({}, {}, {"requirements.txt": "a" * 64})
    with pytest.raises(RuntimeAuditError, match="E_DEPENDENCY_ERRORS"):
        _execution_osv({"results": [], "errors": ["analysis failed"]}, {}, {})


def test_status_without_history_is_not_run(tmp_path):
    assert deep_audit_status(tmp_path)["state"] == "NOT_RUN"


@pytest.mark.parametrize(
    "field,value",
    [
        ("num_statements", -1),
        ("covered_lines", True),
        ("covered_lines", 3),
        ("num_branches", 1.5),
        ("covered_branches", 4),
    ],
)
def test_native_coverage_rejects_invalid_or_impossible_measurements(field, value):
    from factoryline.deep_audit_io import _native_source_counts

    summary = {
        "num_statements": 2,
        "covered_lines": 1,
        "num_branches": 2,
        "covered_branches": 1,
    }
    summary[field] = value
    with pytest.raises(RuntimeAuditError):
        _native_source_counts(
            {"files": {"app.py": {"summary": summary}}}, {"app.py": "a" * 64}
        )


def test_native_coverage_rejects_duplicate_normalized_paths():
    from factoryline.deep_audit_io import _native_source_counts

    measured = {
        "summary": {
            "num_statements": 2,
            "covered_lines": 1,
            "num_branches": 2,
            "covered_branches": 1,
        }
    }
    with pytest.raises(RuntimeAuditError, match="duplicate native"):
        _native_source_counts(
            {"files": {"app.py": measured, "/src/app.py": measured}},
            {"app.py": "a" * 64},
        )


def test_native_runtime_accounting_distinguishes_measured_and_missing_sources():
    from factoryline.deep_audit_io import _native_runtime_accounting

    inventory = {
        "files": [
            {"path": "app.py", "sha256": "a" * 64, "language": "python"},
            {"path": "untouched.py", "sha256": "b" * 64, "language": "python"},
        ]
    }
    lane = {"languages": ["python"]}
    report = {"source_coverage": {"app.py": {"sha256": "a" * 64}}}
    partial = _native_runtime_accounting(report, inventory, lane)
    assert partial["state"] == "PARTIAL"
    assert partial["missing_paths"] == ["untouched.py"]
    report["source_coverage"]["untouched.py"] = {"sha256": "b" * 64}
    complete = _native_runtime_accounting(report, inventory, lane)
    assert complete["state"] == "COMPLETE"
    assert complete["missing_paths"] == []
    report["source_coverage"]["app.py"]["sha256"] = "c" * 64
    with pytest.raises(RuntimeAuditError, match="hash differs"):
        _native_runtime_accounting(report, inventory, lane)


def test_semgrep_challenge_fixture_may_bind_one_obligation_path(tmp_path):
    from factoryline.deep_audit_io import _semgrep_fixture_binding

    (tmp_path / "app.py").write_text("unsafe()\n", encoding="utf-8")
    (tmp_path / "clean.py").write_text("safe()\n", encoding="utf-8")
    source = {
        "app.py": sha256_bytes((tmp_path / "app.py").read_bytes()),
        "clean.py": sha256_bytes((tmp_path / "clean.py").read_bytes()),
    }

    _semgrep_fixture_binding(
        {"app.py": source["app.py"]},
        {"paths": ["app.py", "clean.py"]},
        tmp_path,
        "app.py",
    )


@pytest.mark.parametrize(
    ("manifest", "fixture_path"),
    [
        ({"clean.py": "b" * 64}, "app.py"),
        ({"outside.py": "c" * 64}, "outside.py"),
        ({}, "app.py"),
    ],
)
def test_semgrep_challenge_fixture_rejects_missing_or_unbound_anchor(
    tmp_path, manifest, fixture_path
):
    from factoryline.deep_audit_io import _semgrep_fixture_binding

    with pytest.raises(RuntimeAuditError, match="E_CHALLENGE_BINDING"):
        _semgrep_fixture_binding(
            manifest,
            {"paths": ["app.py", "clean.py"]},
            tmp_path,
            fixture_path,
        )


def test_codeql_query_resolution_records_native_selection(tmp_path, monkeypatch):
    from factoryline.deep_audit_io import resolve_codeql_query_inventory

    suite = tmp_path / "suite.qls"
    suite.write_text("- queries: .")
    query = tmp_path / "query.ql"
    query.write_text("/**\n * @id js/example\n */\n select 1")
    paths = ["/opt/codeql/codeql/qlpacks/codeql/javascript-queries/1/security/query.ql"]
    original = __import__(
        "factoryline.deep_audit_io", fromlist=["local_file"]
    ).local_file
    monkeypatch.setattr(
        "factoryline.deep_audit_io.local_file",
        lambda root, path: query
        if str(root).replace("\\", "/").endswith("/qlpacks")
        else original(root, path),
    )

    def run(argv, cwd, timeout, scratch, *, stdout_path):
        raw = json.dumps(paths).encode()
        stdout_path.write_bytes(raw)
        return dict(
            exit_code=0,
            timed_out=False,
            launch_error=False,
            output_limit_exceeded=False,
            cleanup_confirmed=True,
            stdout_sha256=sha256_bytes(raw),
        )

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    result = resolve_codeql_query_inventory("codeql", suite, tmp_path, tmp_path, 30)
    assert result["queries"] == {
        "codeql/javascript-queries/1/security/query.ql": sha256_bytes(
            query.read_bytes()
        )
    }
    assert result["suite_sha256"] == sha256_bytes(suite.read_bytes())
    assert result["query_ids"] == {"js/example": next(iter(result["queries"]))}
    assert result["argv"][1:3] == ["resolve", "queries"]
    assert "not execution" in result["claim_boundary"]


@pytest.mark.parametrize(
    "paths",
    [
        [],
        {},
        ["outside.ql"],
        ["/opt/codeql/codeql/qlpacks/../escape.ql"],
        ["/opt/codeql/codeql/qlpacks/test.txt"],
        ["x"] * 1025,
    ],
)
def test_codeql_query_inventory_rejects_invalid_selection(paths):
    from factoryline.deep_audit_io import _codeql_resolved_queries

    with pytest.raises(RuntimeAuditError):
        _codeql_resolved_queries(paths)


def test_codeql_query_inventory_rejects_duplicate_and_linked_query(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import _codeql_resolved_queries

    query = tmp_path / "query.ql"
    query.write_text("select 1")
    path = "/opt/codeql/codeql/qlpacks/test/query.ql"
    monkeypatch.setattr(
        "factoryline.deep_audit_io.local_file", lambda root, path: query
    )
    with pytest.raises(RuntimeAuditError, match="duplicate"):
        _codeql_resolved_queries([path, path])

    def linked(*args):
        raise RuntimeAuditError("E_SYMLINK", "linked query forbidden")

    monkeypatch.setattr("factoryline.deep_audit_io.local_file", linked)
    with pytest.raises(RuntimeAuditError, match="linked"):
        _codeql_resolved_queries([path])


@pytest.mark.parametrize(
    "mutant",
    [
        {"sentinel.ql": "b" * 64},
        {},
        {"target.ql": "a" * 64, "sentinel.ql": "b" * 64},
        {"sentinel.ql": "c" * 64},
        {"sentinel.ql": "b" * 64, "extra.ql": "d" * 64},
    ],
)
def test_codeql_query_mutation_requires_exact_target_only_removal(mutant):
    from factoryline.deep_audit_io import verify_codeql_query_isolation

    baseline = {"target.ql": "a" * 64, "sentinel.ql": "b" * 64}
    if mutant == {"sentinel.ql": "b" * 64}:
        assert (
            verify_codeql_query_isolation(baseline, mutant, "target.ql")[
                "disabled_query"
            ]
            == "target.ql"
        )
    else:
        with pytest.raises(RuntimeAuditError):
            verify_codeql_query_isolation(baseline, mutant, "target.ql")


def test_codeql_resolution_repeated_calls_use_isolated_runtime_homes(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import resolve_codeql_query_inventory

    suite = tmp_path / "suite.qls"
    suite.write_text("- queries: .")
    monkeypatch.setattr(
        "factoryline.deep_audit_io._codeql_resolved_queries",
        lambda paths: {"sentinel.ql": "a" * 64},
    )
    monkeypatch.setattr(
        "factoryline.deep_audit_io._codeql_query_ids",
        lambda queries: {"sentinel": "sentinel.ql"},
    )
    homes = []

    def run(argv, cwd, timeout, scratch, *, stdout_path):
        home = scratch / "runtime-home"
        home.mkdir(exist_ok=False)
        homes.append(home)
        raw = b'["native.ql"]'
        stdout_path.write_bytes(raw)
        return dict(
            exit_code=0,
            timed_out=False,
            launch_error=False,
            output_limit_exceeded=False,
            cleanup_confirmed=True,
            stdout_sha256=sha256_bytes(raw),
        )

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    for _ in range(2):
        assert resolve_codeql_query_inventory("codeql", suite, tmp_path, tmp_path, 30)[
            "queries"
        ]
    assert homes[0] != homes[1]


@pytest.mark.parametrize("raw", [b"not json", b"null", b"[]"])
def test_codeql_native_resolution_rejects_malformed_output(tmp_path, monkeypatch, raw):
    from factoryline.deep_audit_io import resolve_codeql_query_inventory

    suite = tmp_path / "suite.qls"
    suite.write_text("- queries: .")

    def run(argv, cwd, timeout, scratch, *, stdout_path):
        stdout_path.write_bytes(raw)
        return dict(
            exit_code=0,
            timed_out=False,
            launch_error=False,
            output_limit_exceeded=False,
            cleanup_confirmed=True,
            stdout_sha256=sha256_bytes(raw),
        )

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    with pytest.raises(RuntimeAuditError):
        resolve_codeql_query_inventory("codeql", suite, tmp_path, tmp_path, 30)


def test_codeql_native_resolution_refuses_timed_out_process(tmp_path, monkeypatch):
    from factoryline.deep_audit_io import resolve_codeql_query_inventory

    suite = tmp_path / "suite.qls"
    suite.write_text("- queries: .")
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.run_bounded_command",
        lambda *args, **kw: dict(
            exit_code=0,
            timed_out=True,
            launch_error=False,
            output_limit_exceeded=False,
            cleanup_confirmed=True,
        ),
    )
    with pytest.raises(RuntimeAuditError, match="resolution failed"):
        resolve_codeql_query_inventory("codeql", suite, tmp_path, tmp_path, 30)


@pytest.mark.parametrize(
    "commands",
    [
        None,
        [],
        [{}],
        [{}, {}],
        [{}, {"argv": []}],
        [{}, {"argv": ["codeql", "bad", "analyze", "db", "suite"]}],
    ],
)
def test_codeql_preflight_rejects_malformed_profile(commands, tmp_path):
    from factoryline.deep_audit_io import _codeql_query_preflight

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_INVENTORY"):
        _codeql_query_preflight({"commands": commands}, tmp_path, tmp_path, 30)


def test_codeql_preflight_rejects_exhausted_deadline_before_launch(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import _codeql_query_preflight

    def unexpected(*args):
        pytest.fail("deadline exhaustion must not launch CodeQL")

    monkeypatch.setattr(
        "factoryline.deep_audit_io.resolve_codeql_query_inventory", unexpected
    )
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_TIMEOUT"):
        _codeql_query_preflight({}, tmp_path, tmp_path, 0)


def test_codeql_preflight_leaves_other_engines_unchanged(tmp_path, monkeypatch):
    from factoryline.deep_audit_io import _codeql_query_preflight

    def unexpected(*args):
        pytest.fail("non-CodeQL engine must not resolve queries")

    monkeypatch.setattr(
        "factoryline.deep_audit_io.resolve_codeql_query_inventory", unexpected
    )
    assert _codeql_query_preflight({}, tmp_path, tmp_path, 0, engine="runtime") is None


def _codeql_selection_fixture():
    from factoryline.deep_audit_io import digest

    queries = {"codeql/test/target.ql": "a" * 64, "codeql/test/sentinel.ql": "b" * 64}
    return dict(
        schema="factory.codeql-query-inventory.v1",
        queries=queries,
        query_ids={
            "js/target": "codeql/test/target.ql",
            "js/sentinel": "codeql/test/sentinel.ql",
        },
        suite_sha256="c" * 64,
        query_inventory_sha256=digest(queries),
    )


def test_codeql_selection_verifier_accepts_baseline_and_exact_target_mutation():
    from factoryline.deep_audit_io import verify_codeql_query_selection, digest

    baseline = _codeql_selection_fixture()
    verify_codeql_query_selection(baseline, baseline=baseline)
    changed = json.loads(json.dumps(baseline))
    del changed["queries"]["codeql/test/target.ql"]
    del changed["query_ids"]["js/target"]
    changed["query_inventory_sha256"] = digest(changed["queries"])
    changed["suite_sha256"] = "d" * 64
    verify_codeql_query_selection(
        changed, baseline=baseline, disabled_rule_id="js/target"
    )


@pytest.mark.parametrize(
    "change", ["hash", "id", "path", "duplicate", "suite", "content", "schema", "empty"]
)
def test_codeql_selection_verifier_rejects_drift(change):
    from factoryline.deep_audit_io import verify_codeql_query_selection, digest

    baseline = _codeql_selection_fixture()
    changed = json.loads(json.dumps(baseline))
    if change == "hash":
        changed["query_inventory_sha256"] = "0" * 64
    if change == "id":
        changed["query_ids"]["js/unknown"] = changed["query_ids"].pop("js/target")
    if change == "path":
        changed["queries"]["../escape.ql"] = changed["queries"].pop(
            "codeql/test/target.ql"
        )
    if change == "duplicate":
        changed["query_ids"]["js/target"] = changed["query_ids"]["js/sentinel"]
    if change == "suite":
        changed["suite_sha256"] = "d" * 64
    if change == "content":
        changed["queries"]["codeql/test/target.ql"] = "e" * 64
        changed["query_inventory_sha256"] = digest(changed["queries"])
    if change == "schema":
        changed["schema"] = "untrusted"
    if change == "empty":
        changed["queries"] = {}
    with pytest.raises(RuntimeAuditError):
        verify_codeql_query_selection(changed, baseline=baseline)


@pytest.mark.parametrize("metadata", ["", " * @id js/one\n * @id js/two\n"])
def test_codeql_query_metadata_requires_unique_id(tmp_path, monkeypatch, metadata):
    from factoryline.deep_audit_io import _codeql_query_ids

    query = tmp_path / "query.ql"
    query.write_text("/**\n" + metadata + " */\nselect 1")
    monkeypatch.setattr("factoryline.deep_audit_io.local_file", lambda *args: query)
    with pytest.raises(RuntimeAuditError):
        _codeql_query_ids({"codeql/test/query.ql": sha256_bytes(query.read_bytes())})


def test_codeql_query_metadata_rejects_changed_content_and_duplicate_ids(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import _codeql_query_ids

    query = tmp_path / "query.ql"
    query.write_text("/**\n * @id js/one\n */\nselect 1")
    monkeypatch.setattr("factoryline.deep_audit_io.local_file", lambda *args: query)
    with pytest.raises(RuntimeAuditError, match="changed"):
        _codeql_query_ids({"codeql/test/one.ql": "a" * 64})
    seal = sha256_bytes(query.read_bytes())
    with pytest.raises(RuntimeAuditError, match="unique"):
        _codeql_query_ids({"codeql/test/one.ql": seal, "codeql/test/two.ql": seal})


def _codeql_test_profile(suite):
    executable = sys.executable
    return {
        "schema": "factory.native-profile.v1",
        "engine": "codeql",
        "mode": "interprocedural-full",
        "tool_version": "2.27.1",
        "ruleset_sha256": "a" * 64,
        "version_argv": [executable, "version", "--format=terse"],
        "report_format": "sarif",
        "commands": [
            {
                "argv": [
                    executable,
                    "database",
                    "create",
                    "{scratch}/db",
                    "--language=javascript-typescript",
                    "--source-root={source}",
                    "--build-mode=none",
                ],
                "accepted_exit_codes": [0],
            },
            {
                "argv": [
                    executable,
                    "database",
                    "analyze",
                    "{scratch}/db",
                    str(suite),
                    "--format=sarif-latest",
                    "--output={report}",
                ],
                "accepted_exit_codes": [0],
            },
            {
                "argv": [sys.executable, "-I", "-c", "pass", "{report}"],
                "accepted_exit_codes": [0],
            },
        ],
    }


def _codeql_process_facts(timeout, stdout, stderr, **updates):
    facts = {
        "exit_code": 0,
        "timed_out": False,
        "timeout_seconds": timeout,
        "duration_ms": 20,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout_bytes": len(stdout),
        "stderr_bytes": len(stderr),
    }
    facts.update(updates)
    return facts


def test_codeql_steps_runner_uses_closed_steps_shared_budget_and_real_streams(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import _codeql_steps_runner

    commands = [
        {
            "argv": [sys.executable, "step", str(i)],
            "accepted_exit_codes": [0],
        }
        for i in range(3)
    ]
    budgets = []
    clock = [0.0]
    monkeypatch.setattr("factoryline.deep_audit_io.time.monotonic", lambda: clock[0])

    def run(argv, cwd, timeout, scratch, *, stdout_path, stderr_path):
        budgets.append(timeout)
        index = int(argv[-1])
        stdout, stderr = f"out-{index}".encode(), f"err-{index}".encode()
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        clock[0] += 1.1
        return _codeql_process_facts(timeout, stdout, stderr)

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    scratch = tmp_path / "run"
    scratch.mkdir()
    facts, invocations = _codeql_steps_runner(commands, tmp_path, 5, scratch)
    assert len(invocations) == 3
    assert budgets == [5, 3, 2]
    assert facts["stdout_bytes"] == len(b"out-0out-1out-2")
    assert facts["stdout_sha256"] == sha256_bytes(b"out-0out-1out-2")
    assert facts["stderr_sha256"] == sha256_bytes(b"err-0err-1err-2")
    assert [item["argv"] for item in invocations] == [item["argv"] for item in commands]


@pytest.mark.parametrize(
    "updates", [{"exit_code": 1}, {"timed_out": True}, {"cleanup_confirmed": False}]
)
def test_codeql_steps_runner_fails_closed_on_child_state(
    tmp_path, monkeypatch, updates
):
    from factoryline.deep_audit_io import _codeql_steps_runner

    commands = [
        {
            "argv": [sys.executable, "step", str(i)],
            "accepted_exit_codes": [0],
        }
        for i in range(3)
    ]

    def run(argv, cwd, timeout, scratch, *, stdout_path, stderr_path):
        stdout, stderr = b"stdout", b"stderr"
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        return _codeql_process_facts(timeout, stdout, stderr, **updates)

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    (tmp_path / "run").mkdir()
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_CHALLENGE"):
        _codeql_steps_runner(commands, tmp_path, 5, tmp_path / "run")


@pytest.mark.parametrize("mismatch", ["sha256", "bytes"])
def test_codeql_step_streams_check_captured_bytes(tmp_path, mismatch):
    from factoryline.deep_audit_io import _codeql_step_streams

    out, err = tmp_path / "out.log", tmp_path / "err.log"
    out.write_bytes(b"actual out")
    err.write_bytes(b"actual err")
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    facts = _codeql_process_facts(2, b"actual out", b"actual err")
    facts["stdout_sha256" if mismatch == "sha256" else "stderr_bytes"] = (
        "0" * 64 if mismatch == "sha256" else facts["stderr_bytes"] + 1
    )
    with pytest.raises(RuntimeAuditError, match="stream bytes differ"):
        _codeql_step_streams(facts, out, err, streams)


@pytest.mark.parametrize(
    "commands",
    [
        [],
        [
            {
                "argv": [sys.executable, "database", "create"],
                "accepted_exit_codes": [0],
            }
        ],
        [
            {
                "argv": [sys.executable, "query"],
                "accepted_exit_codes": [0],
            },
            {
                "argv": [sys.executable, "database", "analyze"],
                "accepted_exit_codes": [0],
            },
            {
                "argv": [sys.executable, "-I", "-c", "pass"],
                "accepted_exit_codes": [0],
            },
        ],
    ],
)
def test_codeql_challenge_steps_reject_malformed_profiles(tmp_path, commands):
    from factoryline.deep_audit_io import _codeql_challenge_steps

    profile = {"commands": commands}
    with pytest.raises(RuntimeAuditError, match="three-step"):
        _codeql_challenge_steps(profile, {}, tmp_path / "suite.qls")


def test_codeql_mutation_suite_quotes_target_and_is_deterministic(tmp_path):
    from factoryline.deep_audit_io import _codeql_mutation_suite

    suite = Path(
        "/opt/codeql/codeql/qlpacks/codeql/javascript-queries/2.4.6/codeql-suites/javascript-security-extended.qls"
    )
    target = 'js/command-"injection\\target'
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first = _codeql_mutation_suite(tmp_path / "a", suite, target)
    second = _codeql_mutation_suite(tmp_path / "b", suite, target)
    expected = (
        "- import: codeql-suites/javascript-security-extended.qls\n"
        "  from: codeql/javascript-queries\n"
        "  version: 2.4.6\n"
        "- exclude:\n"
        f"    id: {json.dumps(target)}\n"
    ).encode()
    assert first.read_bytes() == second.read_bytes() == expected


def test_codeql_challenges_deadline_records_gap_without_observation(tmp_path):
    from factoryline.deep_audit_io import _codeql_challenges

    obligation = {
        "id": "codeql-control",
        "engine": "codeql",
        "family": "static",
        "challenges": [{"kind": "positive"}],
    }
    bundle, covered = _codeql_challenges(
        {},
        {"obligations": [obligation]},
        tmp_path,
        {"family": "static", "timeout_seconds": 1},
        {},
        time.monotonic() - 10,
    )
    assert covered == ["codeql-control"]
    assert bundle["observations"] == []
    assert bundle["gaps"][0]["reason"] == "E_ADAPTER_TIMEOUT"


def test_codeql_execute_challenge_passes_exact_suite_and_binds_inventory_artifact(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import (
        _execute_codeql_challenge,
        _native_argv,
        digest,
    )

    suite = tmp_path / "baseline.qls"
    selected = tmp_path / "target-disabled.qls"
    suite.write_text("baseline")
    selected.write_text("selected")
    baseline = {
        "schema": "factory.codeql-query-inventory.v1",
        "suite_sha256": sha256_bytes(suite.read_bytes()),
        "queries": {
            "codeql/test/target.ql": "a" * 64,
            "codeql/test/other.ql": "b" * 64,
        },
        "query_ids": {
            "js/target": "codeql/test/target.ql",
            "js/other": "codeql/test/other.ql",
        },
        "query_inventory_sha256": digest(
            {"codeql/test/target.ql": "a" * 64, "codeql/test/other.ql": "b" * 64}
        ),
    }
    inventory = {
        **baseline,
        "suite_sha256": sha256_bytes(selected.read_bytes()),
        "queries": {"codeql/test/other.ql": "b" * 64},
        "query_ids": {"js/other": "codeql/test/other.ql"},
        "query_inventory_sha256": digest({"codeql/test/other.ql": "b" * 64}),
    }
    profile = _codeql_test_profile(suite)
    lane = {
        "image": "sha256:image",
        "native_artifact_roles": ["query_inventory", "sarif_report"],
        "rule_ids": ["js/other", "js/target"],
        "mutation_config_sha256": {
            "js/target": inventory["suite_sha256"],
            "js/other": "c" * 64,
        },
    }
    execution = {"version_probe": {"exit_code": 0}}
    contract = {"inventory": {"candidate_sha256": "d" * 64}}
    obligation = {"id": "control", "detector_rule_id": "js/target"}
    challenge = {"kind": "mutation"}
    case = tmp_path / "case"
    case.mkdir()
    captured = {}

    def run(argv, cwd, timeout, scratch, *, stdout_path, stderr_path):
        out, err = b"step out", b"step err"
        stdout_path.write_bytes(out)
        stderr_path.write_bytes(err)
        return _codeql_process_facts(timeout, out, err)

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)

    def executor(challenge_arg, **kwargs):
        kwargs["scratch"].mkdir()
        baseline_bytes = kwargs["baseline_config_path"].read_bytes()
        selected_bytes = kwargs["effective_config_path"].read_bytes()
        assert kwargs["config_rule_ids"](baseline_bytes) == ["js/other", "js/target"]
        assert kwargs["config_rule_ids"](selected_bytes) == ["js/other"]
        assert kwargs["verify_mutation"](baseline_bytes, selected_bytes, "js/target")
        create = _native_argv(
            [{"argv": kwargs["profile_argv"], "accepted_exit_codes": [0]}],
            kwargs["bindings"],
        )[0]["argv"]
        facts = kwargs["runner"](create, kwargs["source_root"], 20, kwargs["scratch"])
        captured["facts"] = facts
        captured["report_path"] = kwargs["report_path"]
        return {"execution": {"status": "VERIFIED"}, "report": {}}

    monkeypatch.setattr(
        "factoryline.deep_audit_io._native_challenge_executor", lambda: executor
    )
    result = _execute_codeql_challenge(
        profile,
        contract,
        lane,
        execution,
        obligation,
        challenge,
        case,
        tmp_path / "source",
        {"route.js": "e" * 64},
        suite,
        selected,
        baseline,
        inventory,
        time.monotonic() + 30,
    )
    assert captured["facts"]["cleanup_confirmed"] is True
    analyze = next(
        item
        for item in result["codeql_query_inventory"]["native_invocations"]
        if item["argv"][1:3] == ["database", "analyze"]
    )
    assert analyze["argv"][4] == str(selected)
    raw = (case / "run" / "query-inventory.json").read_bytes()
    assert raw == __import__(
        "factoryline.runtime_audit_common", fromlist=["canonical_bytes"]
    ).canonical_bytes(result["codeql_query_inventory"])
    assert sha256_bytes(raw) == sha256_bytes(
        __import__(
            "factoryline.runtime_audit_common", fromlist=["canonical_bytes"]
        ).canonical_bytes(result["codeql_query_inventory"])
    )


def test_codeql_challenge_report_normalizes_only_volatile_telemetry(
    monkeypatch, tmp_path
):
    from factoryline.deep_audit_io import _codeql_challenge_report

    first = {
        "properties": {"factory_native_raw_sha256": "a" * 64, "kept": True},
        "runs": [
            {
                "invocations": [
                    {
                        "toolExecutionNotifications": [
                            {
                                "level": "none",
                                "descriptor": {"id": "cli/platform"},
                                "time": "now",
                            },
                            {
                                "level": "error",
                                "descriptor": {"id": "cli/platform"},
                                "message": {"text": "real failure"},
                            },
                            {
                                "level": "none",
                                "descriptor": {"id": "query-warning"},
                                "message": {"text": "keep"},
                            },
                        ]
                    }
                ],
                "results": [
                    {
                        "codeFlows": [
                            {"threadFlows": [{"locations": ["source", "sink"]}]}
                        ]
                    }
                ],
            }
        ],
    }

    def normalize(raw, profile, root, manifest):
        return json.loads(raw)

    monkeypatch.setattr(
        "factoryline.deep_audit_io._semgrep_challenge_report", normalize
    )
    changed = deepcopy(first)
    changed["properties"]["factory_native_raw_sha256"] = "b" * 64
    changed["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["time"] = (
        "later"
    )
    a = _codeql_challenge_report(json.dumps(first).encode(), {}, tmp_path, {})
    b = _codeql_challenge_report(json.dumps(changed).encode(), {}, tmp_path, {})
    assert a == b
    kept = a["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert {item["descriptor"]["id"] for item in kept} == {
        "cli/platform",
        "query-warning",
    }
    assert any(item["level"] == "error" for item in kept)
    assert (
        a["runs"][0]["results"][0]["codeFlows"]
        == first["runs"][0]["results"][0]["codeFlows"]
    )
    assert "factory_native_raw_sha256" not in a["properties"]


def test_codeql_result_path_maps_exact_versioned_inventory_path():
    from factoryline.deep_audit_io import _codeql_result_path

    assert (
        _codeql_result_path("codeql/javascript-queries/2.4.6/Security/A.ql")
        == "results/codeql/javascript-queries/Security/A.bqrs"
    )
    assert (
        _codeql_result_path("codeql/python-queries/1.8.11/Security/A.ql")
        == "results/codeql/python-queries/Security/A.bqrs"
    )
    assert (
        _codeql_result_path("codeql/actions-queries/0.6.36/Security/A.ql")
        == "results/codeql/actions-queries/Security/A.bqrs"
    )


@pytest.mark.parametrize(
    "query_path",
    [
        "codeql/unknown-queries/2.4.6/Security/A.ql",
        "codeql/javascript-queries/not-a-version/Security/A.ql",
        "codeql/javascript-queries/2.4.6/../A.ql",
        "../codeql/javascript-queries/2.4.6/Security/A.ql",
        "codeql/javascript-queries/2.4.6/Security/A.qll",
        "codeql/javascript-queries/2.4.6/Security/A.ql/extra",
    ],
)
def test_codeql_result_path_rejects_unbound_or_escaping_query_paths(query_path):
    from factoryline.deep_audit_io import _codeql_result_path

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_EXECUTION"):
        _codeql_result_path(query_path)


def test_codeql_result_sets_accepts_zero_rows_as_valid_positive_result():
    from factoryline.deep_audit_io import _codeql_result_sets

    raw = json.dumps(
        {"result-sets": [{"name": "js/security/A", "rows": 0, "columns": ["message"]}]}
    ).encode()
    assert _codeql_result_sets(raw) == [
        {"name": "js/security/A", "rows": 0, "columns": 1}
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"\xff",
        pytest.param(b" " * 65_537, id="oversized"),
        b"{}",
        json.dumps({"result-sets": []}).encode(),
        json.dumps(
            {
                "result-sets": [
                    {"name": "same", "rows": 0, "columns": []},
                    {"name": "same", "rows": 1, "columns": ["x"]},
                ]
            }
        ).encode(),
        json.dumps({"result-sets": [{"name": "", "rows": 0, "columns": []}]}).encode(),
        json.dumps(
            {"result-sets": [{"name": "x", "rows": True, "columns": []}]}
        ).encode(),
        json.dumps(
            {"result-sets": [{"name": "x", "rows": -1, "columns": []}]}
        ).encode(),
        json.dumps(
            {"result-sets": [{"name": "x", "rows": 2**63, "columns": []}]}
        ).encode(),
        json.dumps(
            {"result-sets": [{"name": "x", "rows": 0, "columns": "c"}]}
        ).encode(),
        json.dumps(
            {"result-sets": [{"name": "x", "rows": 0, "columns": list(range(257))}]}
        ).encode(),
    ],
)
def test_codeql_result_sets_rejects_malformed_or_ambiguous_metadata(raw):
    from factoryline.deep_audit_io import _codeql_result_sets

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_EXECUTION"):
        _codeql_result_sets(raw)


def _codeql_result_record_args(tmp_path):
    artifact = (
        tmp_path
        / "database"
        / "results"
        / "codeql"
        / "javascript-queries"
        / "Security"
        / "A.bqrs"
    )
    artifact.parent.mkdir(parents=True)
    raw = b"native BQRS bytes"
    artifact.write_bytes(raw)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    return {
        "profile": _codeql_test_profile(tmp_path / "security.qls"),
        "source": source,
        "scratch": scratch,
        "deadline": time.monotonic() + 30,
        "rule_id": "js/security/A",
        "query_path": "codeql/javascript-queries/2.4.6/Security/A.ql",
        "query_sha": "a" * 64,
        "result_path": "results/codeql/javascript-queries/Security/A.bqrs",
        "artifact": artifact,
        "raw": raw,
    }


def test_codeql_query_result_record_accepts_zero_row_bqrs_info(tmp_path, monkeypatch):
    from factoryline.deep_audit_io import (
        _codeql_blob_bytes,
        _codeql_query_result_record,
    )

    args = _codeql_result_record_args(tmp_path)
    stdout = json.dumps(
        {"result-sets": [{"name": "js/security/A", "rows": 0, "columns": []}]}
    ).encode()

    def run(argv, cwd, timeout, scratch, *, stdout_path):
        assert argv == [
            sys.executable,
            "bqrs",
            "info",
            str(args["artifact"]),
            "--format=json",
        ]
        stdout_path.write_bytes(stdout)
        return _codeql_process_facts(timeout, stdout, b"")

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    record = _codeql_query_result_record(**args)
    assert record["result_sha256"] == sha256_bytes(args["raw"])
    assert record["result_bytes"] == len(args["raw"])
    assert record["result_sets"] == [{"name": "js/security/A", "rows": 0, "columns": 0}]
    assert record["invocation"]["execution"]["stdout_sha256"] == sha256_bytes(stdout)
    assert _codeql_blob_bytes(record["native_artifacts"]["result"]) == args["raw"]
    assert _codeql_blob_bytes(record["native_artifacts"]["info"]) == stdout


@pytest.mark.parametrize(
    "failure", ["changed_bqrs", "stdout_hash", "timeout", "cleanup"]
)
def test_codeql_query_result_record_rejects_untrusted_native_inspection(
    tmp_path, monkeypatch, failure
):
    from factoryline.deep_audit_io import _codeql_query_result_record

    args = _codeql_result_record_args(tmp_path)
    stdout = json.dumps(
        {"result-sets": [{"name": "js/security/A", "rows": 0, "columns": []}]}
    ).encode()

    def run(argv, cwd, timeout, scratch, *, stdout_path):
        stdout_path.write_bytes(stdout)
        updates = {}
        if failure == "changed_bqrs":
            args["artifact"].write_bytes(b"changed BQRS")
        elif failure == "stdout_hash":
            updates["stdout_sha256"] = "0" * 64
        elif failure == "timeout":
            updates["timed_out"] = True
        else:
            updates["cleanup_confirmed"] = False
        return _codeql_process_facts(timeout, stdout, b"", **updates)

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_EXECUTION"):
        _codeql_query_result_record(**args)


def test_codeql_query_result_record_expired_deadline_skips_native_inspection(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import _codeql_query_result_record

    args = _codeql_result_record_args(tmp_path)
    args["deadline"] = time.monotonic() - 1
    calls = []
    monkeypatch.setattr(
        "factoryline.runtime_audit_process.run_bounded_command",
        lambda *a, **kw: calls.append((a, kw)),
    )
    with pytest.raises(RuntimeAuditError, match="E_ADAPTER_TIMEOUT"):
        _codeql_query_result_record(**args)
    assert calls == []


def _codeql_source_accounting_inputs():
    source_sha = "a" * 64
    path = "src/a.js"
    inventory = {
        "files": [{"path": path, "language": "javascript", "sha256": source_sha}]
    }
    lane = {"languages": ["javascript"]}
    measurement = {
        "rows": {path: {"syntax_nodes": 2, "parse_errors": 0}},
        "archived_sources": {path: source_sha},
    }
    return path, source_sha, inventory, lane, measurement


def _codeql_parse_column_kinds():
    return [{"kind": "String"}, {"kind": "Integer"}, {"kind": "Integer"}]


def test_codeql_parse_rows_parses_native_three_column_select():
    from factoryline.deep_audit_io import _codeql_parse_rows

    raw = json.dumps(
        {
            "#select": {
                "columns": _codeql_parse_column_kinds(),
                "tuples": [["src/a.js", 12, 0], ["src/b.js", 0, 3]],
            }
        }
    ).encode()
    assert _codeql_parse_rows(raw) == {
        "src/a.js": {"syntax_nodes": 12, "parse_errors": 0},
        "src/b.js": {"syntax_nodes": 0, "parse_errors": 3},
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"\xff",
        json.dumps({}).encode(),
        json.dumps(
            {
                "#select": {
                    "columns": [{"kind": "String"}, {"kind": "Integer"}],
                    "tuples": [],
                }
            }
        ).encode(),
        json.dumps(
            {
                "#select": {
                    "columns": _codeql_parse_column_kinds(),
                    "tuples": [["src/a.js", 1, 0], ["src/a.js", 2, 0]],
                }
            }
        ).encode(),
        json.dumps(
            {
                "#select": {
                    "columns": _codeql_parse_column_kinds(),
                    "tuples": [["src/a.js", True, 0]],
                }
            }
        ).encode(),
        json.dumps(
            {
                "#select": {
                    "columns": _codeql_parse_column_kinds(),
                    "tuples": [["../outside.js", 1, 0]],
                }
            }
        ).encode(),
        json.dumps(
            {
                "#select": {
                    "columns": [
                        {"kind": "String"},
                        {"kind": "String"},
                        {"kind": "Integer"},
                    ],
                    "tuples": [["src/a.js", 1, 0]],
                }
            }
        ).encode(),
        json.dumps(
            {
                "#select": {
                    "columns": _codeql_parse_column_kinds(),
                    "tuples": [["src/a.js", 1]],
                }
            }
        ).encode(),
        pytest.param(b" " * (8 * 1024 * 1024 + 1), id="over-8-MiB"),
    ],
)
def test_codeql_parse_rows_rejects_malformed_or_unbounded_output(raw):
    from factoryline.deep_audit_io import _codeql_parse_rows

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_SOURCE"):
        _codeql_parse_rows(raw)


def test_codeql_source_accounting_marks_matching_archived_syntax_complete():
    from factoryline.deep_audit_io import _codeql_source_accounting

    path, source_sha, inventory, lane, measurement = _codeql_source_accounting_inputs()
    accounting = _codeql_source_accounting(measurement, inventory, lane)
    assert accounting["state"] == "COMPLETE"
    assert accounting["checks"][path] == {"state": "EXTRACTED", "sha256": source_sha}
    assert accounting["measured_paths"] == [path]
    assert accounting["missing_paths"] == []
    assert accounting["degraded_paths"] == []


@pytest.mark.parametrize(
    ("row", "archived", "expected"),
    [
        (None, None, "NOT_EXTRACTED"),
        ({"syntax_nodes": 4, "parse_errors": 1}, "a" * 64, "PARSE_ERROR"),
        ({"syntax_nodes": 0, "parse_errors": 0}, "a" * 64, "NO_SYNTAX_MODEL"),
        ({"syntax_nodes": 4, "parse_errors": 0}, "b" * 64, "SOURCE_MISMATCH"),
    ],
)
def test_codeql_source_accounting_marks_missing_or_degraded_source_rows(
    row, archived, expected
):
    from factoryline.deep_audit_io import _codeql_source_accounting

    path, _, inventory, lane, measurement = _codeql_source_accounting_inputs()
    measurement["rows"] = {} if row is None else {path: row}
    measurement["archived_sources"] = {} if archived is None else {path: archived}
    accounting = _codeql_source_accounting(measurement, inventory, lane)
    assert accounting["state"] == "INCOMPLETE"
    assert accounting["checks"][path]["state"] == expected
    assert accounting["degraded_paths"] == (
        [] if expected == "NOT_EXTRACTED" else [path]
    )
    assert accounting["missing_paths"] == (
        [path] if expected == "NOT_EXTRACTED" else []
    )


def test_codeql_source_accounting_empty_required_set_is_incomplete():
    from factoryline.deep_audit_io import _codeql_source_accounting

    _, _, inventory, lane, measurement = _codeql_source_accounting_inputs()
    inventory["files"][0]["language"] = "python"
    accounting = _codeql_source_accounting(measurement, inventory, lane)
    assert accounting["state"] == "INCOMPLETE"
    assert accounting["checks"] == {}
    assert accounting["required_paths"] == []
    assert accounting["measured_paths"] == []


@pytest.mark.parametrize(
    "measurement",
    [
        {},
        {"rows": [], "archived_sources": {}},
        {"rows": {}, "archived_sources": []},
    ],
)
def test_codeql_source_accounting_rejects_malformed_measurement(measurement):
    from factoryline.deep_audit_io import _codeql_source_accounting

    _, _, inventory, lane, _ = _codeql_source_accounting_inputs()
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_SOURCE"):
        _codeql_source_accounting(measurement, inventory, lane)


def _codeql_archive_fixture(tmp_path, members):
    import zipfile

    source = tmp_path / "source-root"
    (source / "src").mkdir(parents=True)
    candidate = source / "src" / "a.js"
    candidate.write_bytes(b"candidate source bytes")
    scratch = tmp_path / "scratch"
    database = scratch / "codeql-db"
    database.mkdir(parents=True)
    archive = database / "src.zip"
    archive_member = source.resolve().as_posix().lstrip("/") + "/src/a.js"
    with zipfile.ZipFile(archive, "w") as zipped:
        for name, content in members(archive_member):
            zipped.writestr(name, content)
    source_sha = sha256_bytes(candidate.read_bytes())
    return source, scratch, archive, archive_member, source_sha


def test_codeql_archived_sources_rejects_malformed_zip(tmp_path):
    from factoryline.deep_audit_io import _codeql_archived_sources

    source, scratch, archive, _, source_sha = _codeql_archive_fixture(
        tmp_path, lambda member: [(member, b"candidate source bytes")]
    )
    archive.write_bytes(b"not a zip archive")
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_SOURCE"):
        _codeql_archived_sources(source, scratch, {"src/a.js": source_sha})


def test_codeql_archived_sources_ignores_duplicate_member_names(tmp_path):
    from factoryline.deep_audit_io import (
        _codeql_archived_sources,
        _codeql_source_accounting,
    )

    source, scratch, _, member, source_sha = _codeql_archive_fixture(
        tmp_path,
        lambda name: [
            (name, b"candidate source bytes"),
            (name, b"different duplicate bytes"),
        ],
    )
    archived, _ = _codeql_archived_sources(source, scratch, {"src/a.js": source_sha})
    assert archived == {}
    accounting = _codeql_source_accounting(
        {
            "rows": {"src/a.js": {"syntax_nodes": 1, "parse_errors": 0}},
            "archived_sources": archived,
        },
        {
            "files": [
                {
                    "path": "src/a.js",
                    "language": "javascript",
                    "sha256": source_sha,
                }
            ]
        },
        {"languages": ["javascript"]},
    )
    assert accounting["checks"]["src/a.js"]["state"] == "SOURCE_MISMATCH"


def test_codeql_archived_sources_mismatch_is_reported_against_candidate_hash(
    tmp_path,
):
    from factoryline.deep_audit_io import (
        _codeql_archived_sources,
        _codeql_source_accounting,
    )

    source, scratch, _, _, source_sha = _codeql_archive_fixture(
        tmp_path, lambda member: [(member, b"different archived bytes")]
    )
    archived, _ = _codeql_archived_sources(source, scratch, {"src/a.js": source_sha})
    accounting = _codeql_source_accounting(
        {
            "rows": {"src/a.js": {"syntax_nodes": 1, "parse_errors": 0}},
            "archived_sources": archived,
        },
        {
            "files": [
                {
                    "path": "src/a.js",
                    "language": "javascript",
                    "sha256": source_sha,
                }
            ]
        },
        {"languages": ["javascript"]},
    )
    assert accounting["checks"]["src/a.js"]["state"] == "SOURCE_MISMATCH"


def test_codeql_archived_sources_bounds_archive_read(tmp_path, monkeypatch):
    from factoryline.deep_audit_io import _codeql_archived_sources

    source, scratch, archive, _, source_sha = _codeql_archive_fixture(
        tmp_path, lambda member: [(member, b"candidate source bytes")]
    )
    original_open = Path.open
    read_sizes = []

    class ReadSpy:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            read_sizes.append(size)
            return self.stream.read(size)

    def open_spy(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        if Path(path) == archive:
            return ReadSpy(stream)
        return stream

    monkeypatch.setattr(Path, "open", open_spy)
    _codeql_archived_sources(source, scratch, {"src/a.js": source_sha})
    assert read_sizes[0] == 67_108_865


@pytest.mark.parametrize(
    ("language", "expected_library", "expected_symbol"),
    [
        ("javascript-typescript", "javascript", "TopLevel"),
        ("python", "python", "Module"),
        ("actions", "actions", "YamlDocument"),
    ],
)
def test_codeql_source_query_maps_supported_languages(
    language, expected_library, expected_symbol
):
    from factoryline.deep_audit_io import _codeql_source_query

    profile = _codeql_test_profile(Path("suite.qls"))
    profile["commands"][0]["argv"] = [
        arg if not arg.startswith("--language=") else f"--language={language}"
        for arg in profile["commands"][0]["argv"]
    ]
    library, query = _codeql_source_query(profile)
    assert library == expected_library
    assert expected_symbol.encode() in query
    assert b"count(" in query


def test_codeql_source_query_rejects_unsupported_language():
    from factoryline.deep_audit_io import _codeql_source_query

    profile = _codeql_test_profile(Path("suite.qls"))
    profile["commands"][0]["argv"] = [
        arg if not arg.startswith("--language=") else "--language=go"
        for arg in profile["commands"][0]["argv"]
    ]
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_SOURCE"):
        _codeql_source_query(profile)


def test_codeql_source_measurement_runs_native_steps_and_routes_accounting(
    tmp_path, monkeypatch
):
    import zipfile

    from factoryline.deep_audit_io import (
        _codeql_blob_bytes,
        _codeql_source_measurement,
        _native_source_accounting,
    )

    source = tmp_path / "source-root"
    (source / "src").mkdir(parents=True)
    candidate = source / "src" / "a.js"
    candidate.write_bytes(b"candidate source bytes")
    source_sha = sha256_bytes(candidate.read_bytes())
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    database = scratch / "codeql-db"
    database.mkdir()
    with zipfile.ZipFile(database / "src.zip", "w") as zipped:
        archived_path = source.resolve().as_posix().lstrip("/") + "/src/a.js"
        zipped.writestr(archived_path, candidate.read_bytes())

    profile = _codeql_test_profile(tmp_path / "security.qls")
    inventory = {
        "files": [{"path": "src/a.js", "language": "javascript", "sha256": source_sha}]
    }
    lane = {"languages": ["javascript"], "engine": "codeql"}
    decoded = json.dumps(
        {
            "#select": {
                "columns": _codeql_parse_column_kinds(),
                "tuples": [["src/a.js", 5, 0]],
            }
        }
    ).encode()
    bqrs = b"native source result bytes"
    captured_commands = []
    info_rows = [1]

    def run(argv, cwd, timeout, run_dir, *, stdout_path, stderr_path):
        captured_commands.append(argv)
        stdout, stderr = b"stdout", b"stderr"
        if argv[1:3] == ["query", "run"]:
            result_arg = next(arg for arg in argv if arg.startswith("--output="))
            Path(result_arg.split("=", 1)[1]).write_bytes(bqrs)
        elif argv[1:3] == ["bqrs", "decode"]:
            decoded_arg = next(arg for arg in argv if arg.startswith("--output="))
            Path(decoded_arg.split("=", 1)[1]).write_bytes(decoded)
        elif argv[1:3] == ["bqrs", "info"]:
            stdout = json.dumps(
                {
                    "result-sets": [
                        {
                            "name": "#select",
                            "rows": info_rows[0],
                            "columns": [
                                {"kind": "s"},
                                {"kind": "i"},
                                {"kind": "i"},
                            ],
                        }
                    ]
                }
            ).encode()
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        return _codeql_process_facts(timeout, stdout, stderr)

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    measurement = _codeql_source_measurement(
        profile, source, scratch, inventory, lane, time.monotonic() + 30
    )
    assert [command[1:3] for command in captured_commands] == [
        ["query", "run"],
        ["bqrs", "decode"],
        ["bqrs", "info"],
    ]
    assert measurement["rows"] == {"src/a.js": {"syntax_nodes": 5, "parse_errors": 0}}
    assert measurement["archived_sources"] == {"src/a.js": source_sha}
    assert measurement["result_sha256"] == sha256_bytes(bqrs)
    blobs = measurement["native_artifacts"]
    evidence_dir = scratch / "source-evidence"
    assert set(blobs) == {"query", "package", "result", "decoded", "archive", "info"}
    assert (
        _codeql_blob_bytes(blobs["query"])
        == (evidence_dir / "pack" / "sources.ql").read_bytes()
    )
    assert (
        _codeql_blob_bytes(blobs["package"])
        == (evidence_dir / "pack" / "qlpack.yml").read_bytes()
    )
    assert _codeql_blob_bytes(blobs["result"]) == bqrs
    assert _codeql_blob_bytes(blobs["decoded"]) == decoded
    assert _codeql_blob_bytes(blobs["archive"]) == (database / "src.zip").read_bytes()
    assert (
        _codeql_blob_bytes(blobs["info"])
        == (evidence_dir / "step-2" / "stdout.log").read_bytes()
    )
    result = _native_source_accounting(
        {"codeql_source_execution": measurement}, {}, inventory, lane
    )
    assert result["state"] == "COMPLETE"

    info_rows[0] = 2
    scratch_mismatch = tmp_path / "scratch-mismatch"
    scratch_mismatch.mkdir()
    (scratch_mismatch / "codeql-db").mkdir()
    (scratch_mismatch / "codeql-db" / "src.zip").write_bytes(
        (database / "src.zip").read_bytes()
    )
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_SOURCE"):
        _codeql_source_measurement(
            profile,
            source,
            scratch_mismatch,
            inventory,
            lane,
            time.monotonic() + 30,
        )

    parse_error_measurement = {
        **measurement,
        "rows": {"src/a.js": {"syntax_nodes": 5, "parse_errors": 1}},
    }
    incomplete = _native_source_accounting(
        {"codeql_source_execution": parse_error_measurement}, {}, inventory, lane
    )
    assert incomplete["state"] == "INCOMPLETE"


def test_codeql_native_blob_round_trips_exact_bytes():
    from base64 import b64decode

    from factoryline.deep_audit_io import _codeql_blob_bytes, _codeql_native_blob

    raw = b"\x00CodeQL\x00native result\n"
    blob = _codeql_native_blob(raw)
    assert set(blob) == {"encoding", "bytes", "sha256", "data"}
    assert blob["encoding"] == "zlib-base64"
    assert blob["bytes"] == len(raw)
    assert blob["sha256"] == sha256_bytes(raw)
    assert b64decode(blob["data"], validate=True)
    assert _codeql_blob_bytes(blob) == raw


@pytest.mark.parametrize(
    "raw,maximum",
    [(b"five!", 4), ("not bytes", 100)],
)
def test_codeql_native_blob_rejects_invalid_or_oversized_input(raw, maximum):
    from factoryline.deep_audit_io import _codeql_native_blob

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_ARTIFACT"):
        _codeql_native_blob(raw, maximum=maximum)


@pytest.mark.parametrize(
    "sabotage",
    [
        "extra_field",
        "missing_field",
        "encoding",
        "bad_base64",
        "hash",
        "byte_count",
        "trailing_compressed_data",
        "decompression_bomb",
    ],
)
def test_codeql_blob_bytes_rejects_tampered_or_unbounded_blob(sabotage, monkeypatch):
    import base64

    from factoryline.deep_audit_io import _codeql_blob_bytes, _codeql_native_blob

    raw = b"small native artifact"
    blob = _codeql_native_blob(raw)
    if sabotage == "extra_field":
        blob["unexpected"] = True
    elif sabotage == "missing_field":
        del blob["data"]
    elif sabotage == "encoding":
        blob["encoding"] = "raw-base64"
    elif sabotage == "bad_base64":
        blob["data"] = "%%%"
    elif sabotage == "hash":
        blob["sha256"] = "0" * 64
    elif sabotage == "byte_count":
        blob["bytes"] -= 1
    elif sabotage == "trailing_compressed_data":
        compressed = base64.b64decode(blob["data"], validate=True) + b"tail"
        blob["data"] = base64.b64encode(compressed).decode("ascii")
    else:
        bomb = _codeql_native_blob(b"A" * 100_000)
        bomb["bytes"] = 16
        blob = bomb

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_ARTIFACT"):
        _codeql_blob_bytes(blob)


def test_codeql_blob_bytes_rejects_oversized_declared_and_compressed_payloads(
    monkeypatch,
):
    import base64
    import zlib

    import factoryline.deep_audit_io as deep_audit_io

    raw = b"a payload larger than the configured limit"
    blob = deep_audit_io._codeql_native_blob(raw)
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_ARTIFACT"):
        deep_audit_io._codeql_blob_bytes(blob, maximum=4)

    monkeypatch.setattr(deep_audit_io, "NATIVE_COVERAGE_LIMIT", 8)
    oversized_compressed = {
        "encoding": "zlib-base64",
        "bytes": 3,
        "sha256": sha256_bytes(b"abc"),
        "data": base64.b64encode(zlib.compress(b"abc")).decode("ascii"),
    }
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_ARTIFACT"):
        deep_audit_io._codeql_blob_bytes(oversized_compressed)


def _codeql_retained_evidence_fixture():
    import io
    import zipfile

    from factoryline.deep_audit_io import _codeql_native_blob, digest

    source_path = "src/a.js"
    source_sha = sha256_bytes(b"candidate source bytes")
    required = {source_path: source_sha}
    query_path = "codeql/javascript-queries/2.4.6/Security/A.ql"
    query_sha = "b" * 64
    queries = {query_path: query_sha}
    suite_sha = "c" * 64
    ruleset_sha = "d" * 64
    inventory = {
        "schema": "factory.codeql-query-inventory.v1",
        "queries": queries,
        "query_ids": {"js/security/A": query_path},
        "suite_sha256": suite_sha,
        "query_inventory_sha256": digest(queries),
    }
    query_info = json.dumps(
        {"result-sets": [{"name": "query", "rows": 0, "columns": []}]}
    ).encode()
    query_raw = b"query bqrs bytes"
    from factoryline.deep_audit_io import _codeql_result_path

    query_argv = [sys.executable, "bqrs", "info", "query.bqrs", "--format=json"]
    query_execution = {
        "schema": "factory.codeql-query-execution.v1",
        "ruleset_sha256": ruleset_sha,
        "query_inventory_sha256": inventory["query_inventory_sha256"],
        "suite_sha256": suite_sha,
        "rules": [
            {
                "rule_id": "js/security/A",
                "query_path": query_path,
                "query_sha256": query_sha,
                "result_path": _codeql_result_path(query_path),
                "result_sha256": sha256_bytes(query_raw),
                "result_bytes": len(query_raw),
                "result_sets": [{"name": "query", "rows": 0, "columns": 0}],
                "native_artifacts": {
                    "result": _codeql_native_blob(query_raw),
                    "info": _codeql_native_blob(query_info),
                },
                "invocation": {
                    "argv": query_argv,
                    "argv_sha256": digest(query_argv),
                    "execution": _codeql_process_facts(20, query_info, b""),
                },
            }
        ],
    }

    decoded = json.dumps(
        {
            "#select": {
                "columns": _codeql_parse_column_kinds(),
                "tuples": [[source_path, 1, 0]],
            }
        }
    ).encode()
    source_info = json.dumps(
        {
            "result-sets": [
                {
                    "name": "#select",
                    "rows": 1,
                    "columns": [{"kind": "s"}, {"kind": "i"}, {"kind": "i"}],
                }
            ]
        }
    ).encode()
    source_query = b"import javascript\nselect source rows"
    package = b"name: factory/javascript-source-accounting\n"
    source_raw = b"source measurement bqrs"
    archive_prefix = "workspace/"
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w") as zipped:
        zipped.writestr(archive_prefix + source_path, b"candidate source bytes")
    archive = archive_buffer.getvalue()
    invocations = []
    for index, stdout in enumerate((b"query step", b"decode step", source_info)):
        argv = [sys.executable, "source-step", str(index)]
        invocations.append(
            {
                "argv": argv,
                "argv_sha256": digest(argv),
                "execution": _codeql_process_facts(20, stdout, b""),
            }
        )
    source_execution = {
        "schema": "factory.codeql-source-execution.v1",
        "rows": {source_path: {"syntax_nodes": 1, "parse_errors": 0}},
        "archived_sources": {source_path: source_sha},
        "archive_sha256": sha256_bytes(archive),
        "archive_prefix": archive_prefix,
        "query_sha256": sha256_bytes(source_query),
        "package_sha256": sha256_bytes(package),
        "decoded_sha256": sha256_bytes(decoded),
        "result_sha256": sha256_bytes(source_raw),
        "native_invocations": invocations,
        "native_artifacts": {
            "query": _codeql_native_blob(source_query),
            "package": _codeql_native_blob(package),
            "result": _codeql_native_blob(source_raw),
            "decoded": _codeql_native_blob(decoded),
            "archive": _codeql_native_blob(archive),
            "info": _codeql_native_blob(source_info),
        },
    }
    coverage = {
        "codeql_query_inventory": inventory,
        "codeql_query_execution": query_execution,
        "codeql_source_execution": source_execution,
    }
    lane = {"ruleset_sha256": ruleset_sha, "rule_ids": ["js/security/A"]}
    return coverage, lane, required


def test_codeql_retained_evidence_requires_replay_for_valid_artifacts():
    from factoryline.deep_audit_io import verify_codeql_retained_evidence

    coverage, lane, required = _codeql_retained_evidence_fixture()
    result = verify_codeql_retained_evidence(coverage, lane, required)
    assert result["state"] == "REPLAY_REQUIRED"
    assert result["queries"] == 1
    assert result["source_accounting"]["state"] == "COMPLETE"


@pytest.mark.parametrize(
    "sabotage",
    [
        "missing_blob",
        "corrupt_artifact",
        "duplicate_query",
        "query_binding",
        "result_binding",
        "ruleset_binding",
        "archive_mismatch",
        "source_rows",
        "failed_facts",
    ],
)
def test_codeql_retained_evidence_rejects_tampering(sabotage):
    import io
    import zipfile

    import factoryline.deep_audit_io as deep_audit_io

    coverage, lane, required = _codeql_retained_evidence_fixture()
    if sabotage == "missing_blob":
        del coverage["codeql_query_execution"]["rules"][0]["native_artifacts"]["info"]
    elif sabotage == "corrupt_artifact":
        coverage["codeql_query_execution"]["rules"][0]["native_artifacts"]["result"][
            "data"
        ] = "%%%"
    elif sabotage == "duplicate_query":
        coverage["codeql_query_execution"]["rules"].append(
            deepcopy(coverage["codeql_query_execution"]["rules"][0])
        )
        lane["rule_ids"].append("js/security/A")
    elif sabotage == "query_binding":
        coverage["codeql_query_execution"]["rules"][0]["query_sha256"] = "d" * 64
    elif sabotage == "result_binding":
        coverage["codeql_query_execution"]["rules"][0]["result_path"] = (
            "results/other.bqrs"
        )
    elif sabotage == "ruleset_binding":
        coverage["codeql_query_execution"]["ruleset_sha256"] = "e" * 64
    elif sabotage == "archive_mismatch":
        measurement = coverage["codeql_source_execution"]
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as zipped:
            zipped.writestr("workspace/src/a.js", b"different archived bytes")
        archive = archive_buffer.getvalue()
        measurement["native_artifacts"]["archive"] = deep_audit_io._codeql_native_blob(
            archive
        )
        measurement["archive_sha256"] = sha256_bytes(archive)
    elif sabotage == "source_rows":
        measurement = coverage["codeql_source_execution"]
        raw = json.dumps(
            {
                "#select": {
                    "columns": _codeql_parse_column_kinds(),
                    "tuples": [["src/a.js", 99, 0]],
                }
            }
        ).encode()
        measurement["native_artifacts"]["decoded"] = deep_audit_io._codeql_native_blob(
            raw
        )
        measurement["decoded_sha256"] = sha256_bytes(raw)
    else:
        invocation = coverage["codeql_query_execution"]["rules"][0]["invocation"]
        invocation["execution"]["cleanup_confirmed"] = False

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_ARTIFACT"):
        deep_audit_io.verify_codeql_retained_evidence(coverage, lane, required)


def _codeql_replay_values_fixture():
    sets = [
        {"name": "edges", "rows": 2, "columns": 2},
        {"name": "#select", "rows": 1, "columns": 1},
    ]
    values = {
        "edges": {
            "columns": [{"kind": "Entity"}, {"kind": "String"}],
            "tuples": [[{"label": "a"}, "edge"], [{"label": "a"}, "edge"]],
        },
        "#select": {
            "columns": [{"kind": "String"}],
            "tuples": [["finding"]],
        },
    }
    return values, sets


def test_codeql_replay_values_canonicalizes_tuple_order_and_preserves_duplicates():
    from factoryline.deep_audit_io import _codeql_replay_values

    values, sets = _codeql_replay_values_fixture()
    reordered = deepcopy(values)
    reordered["edges"]["tuples"].reverse()
    canonical = _codeql_replay_values(values, sets)
    assert _codeql_replay_values(reordered, sets) == canonical
    assert len(canonical["edges"]["tuples"]) == 2
    assert canonical["edges"]["tuples"][0] == canonical["edges"]["tuples"][1]


@pytest.mark.parametrize(
    "sabotage",
    [
        "missing_set",
        "extra_set",
        "unknown_field",
        "bad_columns",
        "bad_row_count",
        "bad_tuple_width",
    ],
)
def test_codeql_replay_values_rejects_shape_drift(sabotage):
    from factoryline.deep_audit_io import _codeql_replay_values

    values, sets = _codeql_replay_values_fixture()
    if sabotage == "missing_set":
        del values["edges"]
    elif sabotage == "extra_set":
        values["unexpected"] = {"columns": [], "tuples": []}
    elif sabotage == "unknown_field":
        values["edges"]["unexpected"] = []
    elif sabotage == "bad_columns":
        values["edges"]["columns"].pop()
    elif sabotage == "bad_row_count":
        values["edges"]["tuples"].pop()
    else:
        values["edges"]["tuples"][0].pop()

    with pytest.raises(RuntimeAuditError, match="E_CODEQL_REPLAY"):
        _codeql_replay_values(values, sets)


def test_codeql_replay_values_preserves_value_drift():
    from factoryline.deep_audit_io import _codeql_replay_values

    values, sets = _codeql_replay_values_fixture()
    actual = deepcopy(values)
    actual["#select"]["tuples"][0][0] = "different finding"
    assert _codeql_replay_values(values, sets) != _codeql_replay_values(actual, sets)


@pytest.mark.parametrize(
    "field", ["queries", "query_ids", "suite_sha256", "query_inventory_sha256"]
)
def test_codeql_replay_selection_binds_exact_inventory_fields(field):
    from factoryline.deep_audit_io import _codeql_replay_selection

    expected = {
        "queries": {"a.ql": "a" * 64},
        "query_ids": {"rule/a": "a.ql"},
        "suite_sha256": "b" * 64,
        "query_inventory_sha256": "c" * 64,
    }
    actual = deepcopy(expected)
    actual[field] = {"drift": "0" * 64} if isinstance(actual[field], dict) else "0" * 64
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_REPLAY"):
        _codeql_replay_selection(actual, expected)


def _codeql_replay_source_inputs():
    source_sha = "a" * 64
    path = "src/a.js"
    inventory = {
        "files": [{"path": path, "language": "javascript", "sha256": source_sha}]
    }
    lane = {"languages": ["javascript"]}
    measurement = {
        "query_sha256": "b" * 64,
        "package_sha256": "c" * 64,
        "archive_sha256": "d" * 64,
        "rows": {path: {"syntax_nodes": 3, "parse_errors": 0}},
        "archived_sources": {path: source_sha},
    }
    return inventory, lane, measurement


@pytest.mark.parametrize(
    "field", ["query_sha256", "package_sha256", "rows", "archived_sources"]
)
def test_codeql_replay_sources_rejects_source_binding_drift(field):
    from factoryline.deep_audit_io import _codeql_replay_sources

    inventory, lane, expected = _codeql_replay_source_inputs()
    actual = deepcopy(expected)
    actual[field] = {"drift": "0" * 64} if isinstance(actual[field], dict) else "0" * 64
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_REPLAY"):
        _codeql_replay_sources(expected, actual, inventory, lane)


def test_codeql_replay_sources_rejects_incomplete_parse_accounting():
    from factoryline.deep_audit_io import _codeql_replay_sources

    inventory, lane, expected = _codeql_replay_source_inputs()
    expected["rows"]["src/a.js"]["parse_errors"] = 1
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_REPLAY"):
        _codeql_replay_sources(expected, deepcopy(expected), inventory, lane)


def test_fuzz_native_replay_executes_trusted_runner_and_binds_result(
    tmp_path, monkeypatch
):
    import factoryline.runtime_audit_process as process
    from factoryline import deep_audit_io
    from factoryline.runtime_audit_common import canonical_bytes

    source, scratch = tmp_path / "source", tmp_path / "scratch"
    source.mkdir()
    scratch.mkdir()
    expected = {
        "harness": "harness.py",
        "corpus_sha256": "a" * 64,
        "replayed_inputs": 2,
        "failure_inputs": [],
    }
    request = {"inventory": {"candidate_sha256": "b" * 64}}
    monkeypatch.setattr(
        deep_audit_io, "_fuzz_replay_expected", lambda _r, _controls=None: expected
    )
    monkeypatch.setattr(deep_audit_io, "_fuzz_replay_profile", lambda _r: None)
    monkeypatch.setattr(deep_audit_io, "_adapter_sources", lambda *_a: None)
    observed = {"schema": "factory.fuzz-input-replay.v1", **expected}
    executions = []

    def run_bounded_command(argv, cwd, timeout, workdir, *, stdout_path):
        assert argv[0] == "/usr/local/bin/python"
        assert argv[1] == "-I"
        assert cwd == source
        assert timeout >= 1
        assert workdir == scratch
        raw = canonical_bytes(observed)
        stdout_path.write_bytes(raw)
        facts = {
            "exit_code": 0,
            "timed_out": False,
            "launch_error": False,
            "output_limit_exceeded": False,
            "cleanup_confirmed": True,
            "cancelled": False,
            "timeout_seconds": timeout,
            "duration_ms": 1,
            "stdout_sha256": sha256_bytes(raw),
            "stdout_bytes": len(raw),
            "stderr_sha256": "0" * 64,
            "stderr_bytes": 0,
        }
        executions.append(facts)
        return facts

    monkeypatch.setattr(process, "run_bounded_command", run_bounded_command)
    result = deep_audit_io.execute_fuzz_native_replay(request, source, scratch, 10)

    assert result == {**expected, "native_execution_sha256": digest(executions[0])}


def test_fuzz_native_replay_rejects_source_drift(tmp_path, monkeypatch):
    from factoryline import deep_audit_io

    source, scratch = tmp_path / "source", tmp_path / "scratch"
    source.mkdir()
    scratch.mkdir()
    request = {"inventory": {"candidate_sha256": "b" * 64}}
    monkeypatch.setattr(
        deep_audit_io,
        "_fuzz_replay_expected",
        lambda _r, _controls=None: {
            "harness": "h.py",
            "corpus_sha256": "a" * 64,
            "replayed_inputs": 1,
            "failure_inputs": [],
        },
    )
    monkeypatch.setattr(deep_audit_io, "_fuzz_replay_profile", lambda _r: None)

    def reject_drift(_source, _inventory):
        raise RuntimeAuditError("E_REPORT_DRIFT", "source changed")

    monkeypatch.setattr(deep_audit_io, "_adapter_sources", reject_drift)
    with pytest.raises(RuntimeAuditError, match="E_REPORT_DRIFT"):
        deep_audit_io.execute_fuzz_native_replay(request, source, scratch, 10)


def test_codeql_native_replay_runs_each_independent_stage(tmp_path, monkeypatch):
    from factoryline import deep_audit_io, deep_audit_sarif

    source, scratch = tmp_path / "source", tmp_path / "scratch"
    source.mkdir()
    scratch.mkdir()
    lane = {"languages": ["javascript"], "rule_ids": ["rule/a"]}
    inventory = {
        "candidate_sha256": "a" * 64,
        "files": [{"path": "src/a.js", "language": "javascript", "sha256": "b" * 64}],
    }
    query_inventory = {
        "queries": {"a.ql": "c" * 64},
        "query_ids": {"rule/a": "a.ql"},
        "suite_sha256": "d" * 64,
        "query_inventory_sha256": "e" * 64,
    }
    coverage = {
        "codeql_query_inventory": query_inventory,
        "codeql_query_execution": {"rules": [{"rule_id": "rule/a"}]},
        "codeql_source_execution": {"source": "retained"},
    }
    report = {"retained": True}
    request = {
        "lane": lane,
        "inventory": inventory,
        "coverage": coverage,
        "report": report,
    }
    profile = {"engine": "codeql", "tool_version": "1.2.3"}
    monkeypatch.setattr(deep_audit_io.Path, "read_bytes", lambda _p: b"trusted-profile")
    monkeypatch.setattr(deep_audit_io, "strict_json", lambda _raw: profile)
    monkeypatch.setattr(deep_audit_io, "_native_profile", lambda *_a: None)
    monkeypatch.setattr(deep_audit_io, "_adapter_sources", lambda *_a: None)
    monkeypatch.setattr(
        deep_audit_io, "verify_codeql_retained_evidence", lambda *_a: None
    )
    monkeypatch.setattr(deep_audit_io, "_native_version", lambda *_a: {"version": True})
    monkeypatch.setattr(
        deep_audit_io, "_codeql_query_preflight", lambda *_a: query_inventory
    )
    monkeypatch.setattr(
        deep_audit_io,
        "_codeql_replay_fresh",
        lambda *_a: {
            "execution": {"rules": [{"rule_id": "rule/a"}]},
            "source": {"fresh": True},
            "report": report,
            "invocations": [{"execution": {"exit_code": 0}}],
        },
    )
    monkeypatch.setattr(
        deep_audit_io, "_codeql_replay_queries", lambda *_a: {"rule/a": "f" * 64}
    )
    monkeypatch.setattr(deep_audit_io, "_codeql_replay_source_values", lambda *_a: None)
    monkeypatch.setattr(deep_audit_io, "_codeql_replay_sources", lambda *_a: None)
    monkeypatch.setattr(
        deep_audit_sarif, "_native_execution_report", lambda raw, *_a: [raw]
    )

    result = deep_audit_io.execute_codeql_native_replay(request, source, scratch, 10)

    assert result["state"] == "VERIFIED"
    assert result["candidate_sha256"] == inventory["candidate_sha256"]
    assert result["source_paths"] == ["src/a.js"]
    assert result["queries"] == 1


@pytest.mark.parametrize(
    "value",
    [
        {"schema": "factory.fuzz-control.v1", "rules": None},
        {"schema": "factory.fuzz-control.v1", "rules": []},
    ],
)
def test_fuzz_control_rejects_non_object_rules(value):
    from factoryline.runtime_audit_common import canonical_bytes
    from factoryline.deep_audit_io import _fuzz_control_ids

    with pytest.raises(RuntimeAuditError, match="E_FUZZ_CONTROL"):
        _fuzz_control_ids(canonical_bytes(value))


@pytest.mark.parametrize("argv", [[], ["h", "o"], ["h", "o", "--factory-control=x"]])
def test_fuzz_control_rejects_incomplete_native_argv(argv):
    from factoryline.deep_audit_io import _fuzz_control_args

    with pytest.raises(RuntimeAuditError, match="E_FUZZ_CONTROL"):
        _fuzz_control_args(argv)


def _codeql_replay_receipt_inputs():
    from factoryline.deep_audit_io import digest

    lane = {"rule_ids": ["js/security/A"], "languages": ["javascript"]}
    inventory = {
        "candidate_sha256": "a" * 64,
        "files": [{"path": "src/a.js", "language": "javascript"}],
    }
    coverage = {"native": "coverage"}
    request = {"lane": lane, "inventory": inventory, "coverage": coverage}
    replay = {
        "schema": "factory.codeql-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": inventory["candidate_sha256"],
        "lane_sha256": digest(lane),
        "coverage_sha256": digest(coverage),
        "queries": 1,
        "source_paths": ["src/a.js"],
        "decoded_queries_sha256": "b" * 64,
        "findings_sha256": "c" * 64,
        "native_execution_sha256": "d" * 64,
    }
    raw = json.dumps(replay).encode()
    facts = _codeql_process_facts(30, raw, b"")
    return raw, facts, request, replay


def test_codeql_replay_receipt_accepts_bound_success():
    from factoryline.deep_audit import _codeql_replay_receipt

    raw, facts, request, expected = _codeql_replay_receipt_inputs()
    assert _codeql_replay_receipt(raw, facts, request) == expected


@pytest.mark.parametrize(
    "sabotage", ["invalid_facts", "cancelled", "stdout_hash_drift", "binding_drift"]
)
def test_codeql_replay_receipt_rejects_execution_or_binding_drift(sabotage):
    from factoryline.deep_audit import _codeql_replay_receipt

    raw, facts, request, _ = _codeql_replay_receipt_inputs()
    if sabotage == "invalid_facts":
        facts["exit_code"] = 1
    elif sabotage == "cancelled":
        facts["cancelled"] = True
    elif sabotage == "stdout_hash_drift":
        facts["stdout_sha256"] = "0" * 64
    else:
        request["inventory"]["candidate_sha256"] = "0" * 64
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_REPLAY"):
        _codeql_replay_receipt(raw, facts, request)


def test_codeql_replay_argv_keeps_same_image_and_isolation(tmp_path):
    from factoryline.deep_audit import _codeql_replay_argv

    image = "registry.example/codeql@sha256:" + "a" * 64
    lane = {
        "image": image,
        "argv": ["/opt/codeql/codeql/codeql", "database", "analyze"],
        "memory_mib": 2048,
    }
    argv = _codeql_replay_argv(
        ["docker"],
        lane,
        tmp_path / "source",
        "replay-test",
        "run-id",
        "b" * 64,
        tmp_path / "input.json",
        tmp_path / "runtime",
        30,
    )
    for required in (
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=128",
        "--cpus=2",
        "--log-driver=none",
        "/tmp:rw,nosuid,nodev,size=512m,mode=1777",
        "/out:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        image,
    ):
        assert required in argv
    mounts = [
        argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--mount"
    ]
    assert any(
        "target=/src,readonly,bind-recursive=readonly" in mount for mount in mounts
    )
    assert any(
        f"source={tmp_path / 'runtime'},target=/factory-runtime,readonly" in mount
        for mount in mounts
    )


def test_codeql_replay_runtime_binds_exact_five_module_snapshot(tmp_path):
    from factoryline.deep_audit import _codeql_replay_runtime
    from factoryline.deep_audit_io import digest

    runtime, seal = _codeql_replay_runtime(tmp_path)
    names = (
        "__init__.py",
        "deep_audit_io.py",
        "deep_audit_sarif.py",
        "runtime_audit_common.py",
        "runtime_audit_process.py",
    )
    records = {}
    for name in names:
        source = Path(__file__).parents[1] / "factoryline" / name
        copied = runtime / "factoryline" / name
        assert copied.read_bytes() == source.read_bytes()
        records[name] = sha256_bytes(source.read_bytes())
    assert sorted(path.name for path in (runtime / "factoryline").iterdir()) == sorted(
        names
    )
    assert seal == digest(records)


def _codeql_replay_decode_record():
    from factoryline.deep_audit_io import _codeql_native_blob

    sets = [{"name": "#select", "rows": 1, "columns": 2}]
    info = json.dumps(
        {
            "result-sets": [
                {
                    "name": "#select",
                    "rows": 1,
                    "columns": [{"kind": "e"}, {"kind": "s"}],
                }
            ]
        }
    ).encode()
    decoded = json.dumps(
        {
            "#select": {
                "columns": [{"kind": "Entity"}, {"kind": "String"}],
                "tuples": [
                    [
                        {
                            "id": "entity-1",
                            "label": "source",
                            "url": {"uri": "src/a.py", "startLine": 7},
                        },
                        "finding",
                    ]
                ],
            }
        }
    ).encode()
    return (
        {
            "native_artifacts": {"result": _codeql_native_blob(b"fixture-bqrs")},
            "result_sets": sets,
        },
        info,
        decoded,
    )


def test_codeql_replay_decode_runs_info_and_unselected_json_decode(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import _codeql_replay_decode

    record, info, decoded = _codeql_replay_decode_record()
    profile = {"version_argv": ["/opt/codeql/codeql/codeql"]}
    source = tmp_path / "source"
    source.mkdir()
    directory = tmp_path / "replay"
    directory.mkdir()
    calls = []

    def run(argv, cwd, timeout, scratch, *, stdout_path, stderr_path):
        calls.append(argv)
        stdout = info if argv[1:3] == ["bqrs", "info"] else decoded
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(b"")
        return _codeql_process_facts(timeout, stdout, b"")

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    values = _codeql_replay_decode(
        profile, record, source, directory, "worker", time.monotonic() + 30
    )

    assert [argv[1:3] for argv in calls] == [
        ["bqrs", "info"],
        ["bqrs", "decode"],
    ]
    assert calls[1] == [
        "/opt/codeql/codeql/codeql",
        "bqrs",
        "decode",
        "--format=json",
        "--entities=all",
        "--",
        str(directory / "worker.bqrs"),
    ]
    assert values == {
        "#select": {
            "columns": [{"kind": "Entity"}, {"kind": "String"}],
            "tuples": [
                [
                    {
                        "id": "entity-1",
                        "label": "source",
                        "url": {"uri": "src/a.py", "startLine": 7},
                    },
                    "finding",
                ]
            ],
        }
    }


def test_codeql_replay_decode_rejects_native_metadata_mismatch(tmp_path, monkeypatch):
    from factoryline.deep_audit_io import _codeql_replay_decode

    record, info, decoded = _codeql_replay_decode_record()
    info = json.dumps(
        {"result-sets": [{"name": "#select", "rows": 0, "columns": []}]}
    ).encode()

    def run(argv, cwd, timeout, scratch, *, stdout_path, stderr_path):
        stdout = info if argv[1:3] == ["bqrs", "info"] else decoded
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(b"")
        return _codeql_process_facts(timeout, stdout, b"")

    source = tmp_path / "source"
    source.mkdir()
    directory = tmp_path / "replay"
    directory.mkdir()
    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_REPLAY"):
        _codeql_replay_decode(
            {"version_argv": ["/opt/codeql/codeql/codeql"]},
            record,
            source,
            directory,
            "worker",
            time.monotonic() + 30,
        )


@pytest.mark.parametrize(
    "drift", ["finding", "entity-id", "entity-label", "entity-url"]
)
def test_codeql_replay_query_orchestration_rejects_decoded_value_drift(
    tmp_path, monkeypatch, drift
):
    from factoryline.deep_audit_io import (
        _codeql_native_blob,
        _codeql_replay_queries,
    )

    record, info, worker_decoded = _codeql_replay_decode_record()
    record["rule_id"] = "js/security/A"
    fresh_record = deepcopy(record)
    fresh_record["native_artifacts"]["result"] = _codeql_native_blob(b"fresh-bqrs")
    fresh_value = json.loads(worker_decoded)
    entity = fresh_value["#select"]["tuples"][0][0]
    if drift == "finding":
        fresh_value["#select"]["tuples"][0][1] = "different finding"
    elif drift == "entity-id":
        entity["id"] = "entity-2"
    elif drift == "entity-label":
        entity["label"] = "different source"
    else:
        entity["url"]["startLine"] = 8
    fresh_decoded = json.dumps(fresh_value).encode()

    def run(argv, cwd, timeout, scratch, *, stdout_path, stderr_path):
        if argv[1:3] == ["bqrs", "info"]:
            stdout = info
        elif Path(argv[-1]).name == "worker.bqrs":
            stdout = worker_decoded
        else:
            stdout = fresh_decoded
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(b"")
        return _codeql_process_facts(timeout, stdout, b"")

    source = tmp_path / "source"
    source.mkdir()
    scratch = tmp_path / "replay-values"
    scratch.mkdir()
    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_REPLAY"):
        _codeql_replay_queries(
            {"version_argv": ["/opt/codeql/codeql/codeql"]},
            {"codeql_query_execution": {"rules": [record]}},
            {"execution": {"rules": [fresh_record]}},
            source,
            scratch,
            time.monotonic() + 30,
        )


def test_codeql_steps_runner_defaults_to_three_steps_and_rejects_two(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_io import _codeql_steps_runner

    commands = [
        {"argv": [sys.executable, "step", str(index)], "accepted_exit_codes": [0]}
        for index in range(2)
    ]

    def run(argv, cwd, timeout, scratch, *, stdout_path, stderr_path):
        stdout, stderr = b"stdout", b"stderr"
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        return _codeql_process_facts(timeout, stdout, stderr)

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    scratch = tmp_path / "steps"
    scratch.mkdir()
    with pytest.raises(RuntimeAuditError, match="E_CODEQL_CHALLENGE"):
        _codeql_steps_runner(commands, tmp_path, 10, scratch)


def _codeql_replay_sarif_fixture(uri="src/a.py", base="%SRCROOT%", index=None):
    location = (
        {"index": index} if index is not None else {"uri": uri, "uriBaseId": base}
    )
    run = {
        "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///src/"}},
        "tool": {
            "driver": {
                "name": "CodeQL",
                "rules": [{"id": "py/unsafe-shell"}],
            }
        },
        "results": [
            {
                "ruleId": "py/unsafe-shell",
                "ruleIndex": 0,
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": location,
                            "region": {"startLine": 7},
                        }
                    }
                ],
            }
        ],
    }
    if index is not None:
        run["artifacts"] = [{"location": {"uri": uri, "uriBaseId": base}}]
    return {"version": "2.1.0", "runs": [run]}


def _run_codeql_replay_fresh_with_report(tmp_path, monkeypatch, report):
    import sys

    from factoryline.deep_audit_io import _codeql_replay_fresh

    source = tmp_path / "source"
    source.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    raw = json.dumps(report).encode()
    profile = {
        "schema": "factory.native-profile.v1",
        "engine": "codeql",
        "mode": "interprocedural-full",
        "tool_version": "2.27.1",
        "ruleset_sha256": "a" * 64,
        "report_format": "sarif",
        "version_argv": [sys.executable, "version"],
        "commands": [
            {
                "argv": [
                    sys.executable,
                    "database",
                    "create",
                    "{scratch}/codeql-db",
                    "--language=python",
                    "--source-root={source}",
                    "--build-mode=none",
                ],
                "accepted_exit_codes": [0],
            },
            {
                "argv": [
                    sys.executable,
                    "database",
                    "analyze",
                    "{scratch}/codeql-db",
                    "/opt/codeql/codeql/qlpacks/codeql/python-queries/1.8.11/codeql-suites/python-security-extended.qls",
                    "--format=sarif-latest",
                    "--output={report}",
                ],
                "accepted_exit_codes": [0],
            },
            {
                "argv": [
                    sys.executable,
                    "-I",
                    "-c",
                    "pass",
                    "{report}",
                ],
                "accepted_exit_codes": [0],
            },
        ],
    }
    sources = [
        {"path": "src/a.py", "language": "python", "sha256": "b" * 64},
        {"path": "src/b.py", "language": "python", "sha256": "c" * 64},
    ]
    inventory = {"candidate_sha256": "d" * 64, "files": sources}
    lane = {
        "id": "codeql-python",
        "engine": "codeql",
        "tool_version": "2.27.1",
        "languages": ["python"],
        "rule_ids": ["py/unsafe-shell"],
    }
    invocation = {
        "argv": ["/opt/codeql/codeql/codeql", "database", "analyze"],
        "argv_sha256": "e" * 64,
        "execution": {"exit_code": 0},
    }

    def steps(commands, cwd, budget, run_scratch):
        report_arg = next(
            arg.removeprefix("--output=")
            for arg in commands[1]["argv"]
            if arg.startswith("--output=")
        )
        Path(report_arg).write_bytes(raw)
        return {}, [invocation]

    monkeypatch.setattr("factoryline.deep_audit_io._codeql_steps_runner", steps)
    monkeypatch.setattr(
        "factoryline.deep_audit_io._codeql_query_preflight",
        lambda *args, **kwargs: {"queries": {}, "query_ids": {}},
    )
    monkeypatch.setattr(
        "factoryline.deep_audit_io._codeql_query_execution",
        lambda *args, **kwargs: {"rules": []},
    )
    monkeypatch.setattr(
        "factoryline.deep_audit_io._codeql_source_measurement",
        lambda *args, **kwargs: {"rows": {}, "archived_sources": {}},
    )
    fresh = _codeql_replay_fresh(
        profile, source, scratch, inventory, lane, time.monotonic() + 30
    )
    return fresh, lane, {item["path"]: item["sha256"] for item in sources}


def test_codeql_replay_fresh_normalizes_metadata_uri_base_and_artifact_index(
    tmp_path, monkeypatch
):
    from factoryline.deep_audit_sarif import _native_execution_report

    report = _codeql_replay_sarif_fixture()
    report["runs"][0]["results"].append(
        {
            "ruleId": "py/unsafe-shell",
            "ruleIndex": 0,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"index": 0},
                        "region": {"startLine": 9},
                    }
                }
            ],
        }
    )
    report["runs"][0]["artifacts"] = [
        {"location": {"uri": "src/b.py", "uriBaseId": "%SRCROOT%"}}
    ]
    fresh, lane, sources = _run_codeql_replay_fresh_with_report(
        tmp_path, monkeypatch, report
    )
    run = fresh["report"]["runs"][0]

    assert run["tool"]["driver"]["version"] == "2.27.1"
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["properties"]["factory_execution_sha256"]
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"] == "file:///src/"
    locations = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]
        for result in run["results"]
    ]
    assert locations == [{"uri": "src/a.py"}, {"uri": "src/b.py"}]
    findings = _native_execution_report(fresh["report"], lane, sources)
    assert [(item["path"], item["line"]) for item in findings] == [
        ("src/a.py", 7),
        ("src/b.py", 9),
    ]


@pytest.mark.parametrize(
    ("report", "diagnostic"),
    [
        (_codeql_replay_sarif_fixture(uri="src/missing.py"), "E_TRACE_UNBOUND"),
        (_codeql_replay_sarif_fixture(uri="../escape.py"), "E_PATH"),
        (
            _codeql_replay_sarif_fixture(uri="src/a.py", base="file:///elsewhere/"),
            "E_SARIF_INDIRECTION",
        ),
    ],
)
def test_codeql_replay_fresh_rejects_off_candidate_or_malformed_paths(
    tmp_path, monkeypatch, report, diagnostic
):
    with pytest.raises(RuntimeAuditError, match=diagnostic):
        _run_codeql_replay_fresh_with_report(tmp_path, monkeypatch, report)


def _osv_replay_request_fixture():
    from factoryline.deep_audit_sarif import _osv_source_accounting

    source_sha = "a" * 64
    report = _osv_package_accounting_fixture()
    inventory = {
        "candidate_sha256": "b" * 64,
        "files": [
            {"path": "requirements.txt", "language": "python", "sha256": source_sha}
        ],
    }
    lane = {
        "id": "osv-replay-test",
        "engine": "osv",
        "family": "dependencies",
        "mode": "offline-pypi-snapshot",
        "languages": ["python"],
        "rule_ids": ["OSV-CVE-2026-0001"],
        "coverage": "coverage.json",
        "report": "report.json",
        "challenge_report": "challenges.json",
        "timeout_seconds": 60,
        "image": "registry.example/osv@sha256:" + "c" * 64,
        "memory_mib": 1024,
        "argv": ["/opt/factory/bin/osv-offline", "scan", "source"],
        "native_policy": {"database_sha256": "d" * 64},
    }
    required = {"requirements.txt": source_sha}
    coverage = {
        "profile_sha256": "e" * 64,
        "source_accounting": _osv_source_accounting(report, required, lane["mode"]),
    }
    challenges = {
        "schema": "factory.deep-challenges.v1",
        "observations": [],
        "gaps": [],
    }
    obligations = [
        {
            "id": "osv-dependency-control",
            "engine": "osv",
            "family": "dependencies",
            "paths": ["requirements.txt"],
            "challenges": [
                {"kind": kind} for kind in ("positive", "negative", "mutation")
            ],
        }
    ]
    return {
        "lane": lane,
        "inventory": inventory,
        "coverage": coverage,
        "report": report,
        "challenges": challenges,
        "obligations": obligations,
    }


def _osv_replay_receipt_inputs():
    from factoryline.deep_audit import _osv_replay_expected

    request = _osv_replay_request_fixture()
    receipt = {
        **_osv_replay_expected(request),
        "native_execution_sha256": "f" * 64,
    }
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    facts = _codeql_process_facts(60, raw, b"replay stderr", cancelled=False)
    return raw, facts, request, receipt


def test_osv_replay_receipt_accepts_source_database_and_all_control_bindings():
    from factoryline.deep_audit import _osv_replay_receipt

    raw, facts, request, expected = _osv_replay_receipt_inputs()
    assert _osv_replay_receipt(raw, facts, request) == expected
    assert expected["controls"] == [
        {"id": "osv-dependency-control", "kind": kind}
        for kind in ("mutation", "negative", "positive")
    ]
    assert expected["source_paths"] == ["requirements.txt"]


@pytest.mark.parametrize(
    "field",
    [
        "candidate_sha256",
        "lane_sha256",
        "coverage_sha256",
        "report_sha256",
        "challenges_sha256",
        "obligations_sha256",
        "profile_sha256",
        "database_sha256",
        "source_paths",
        "controls",
        "findings_sha256",
        "source_accounting_sha256",
    ],
)
def test_osv_replay_receipt_rejects_source_database_or_control_binding_drift(field):
    from factoryline.deep_audit import _osv_replay_receipt

    _, _, request, receipt = _osv_replay_receipt_inputs()
    altered = deepcopy(receipt)
    altered[field] = ["tampered"] if isinstance(altered[field], list) else "0" * 64
    raw = json.dumps(altered, sort_keys=True, separators=(",", ":")).encode()
    facts = _codeql_process_facts(60, raw, b"", cancelled=False)
    with pytest.raises(RuntimeAuditError, match="E_OSV_REPLAY"):
        _osv_replay_receipt(raw, facts, request)


@pytest.mark.parametrize(
    "failure",
    [
        {"exit_code": 7},
        {"timed_out": True},
        {"cancelled": True},
        {"cleanup_confirmed": False},
        {"launch_error": True},
        {"output_limit_exceeded": True},
        {"stdout_sha256": "0" * 64},
        {"stdout_bytes": 0},
    ],
)
def test_osv_replay_receipt_fails_closed_on_process_and_cleanup_failures(failure):
    from factoryline.deep_audit import _osv_replay_receipt

    raw, facts, request, _ = _osv_replay_receipt_inputs()
    facts.update(failure)
    with pytest.raises(RuntimeAuditError, match="E_OSV_REPLAY"):
        _osv_replay_receipt(raw, facts, request)


def test_osv_replay_argv_uses_pinned_image_and_isolated_read_only_runtime(tmp_path):
    from factoryline.deep_audit import _osv_replay_argv

    request = _osv_replay_request_fixture()
    runtime = tmp_path / "trusted runtime"
    argv = _osv_replay_argv(
        ["docker"],
        request["lane"],
        tmp_path / "source snapshot",
        "factory-replay-test",
        "run-id",
        request["inventory"]["candidate_sha256"],
        tmp_path / "contract.json",
        runtime,
        40,
    )
    for required in (
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user=1000:1000",
        request["lane"]["image"],
    ):
        assert required in argv
    assert any("execute_osv_native_replay" in value for value in argv)
    mounts = [
        argv[index + 1] for index, value in enumerate(argv[:-1]) if value == "--mount"
    ]
    assert any(
        "target=/src,readonly,bind-recursive=readonly" in mount for mount in mounts
    )
    assert any(
        f"source={runtime},target=/factory-runtime,readonly" in mount
        for mount in mounts
    )


def test_osv_replay_result_clears_only_required_gap_after_host_receipt(
    tmp_path, monkeypatch
):
    import threading

    import factoryline.deep_audit as module

    request = _osv_replay_request_fixture()
    result = {
        "gaps": ["OSV_NATIVE_REPLAY_REQUIRED", "UNRELATED_GAP"],
        "state": "INCOMPLETE",
    }
    called = []
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    monkeypatch.setattr(
        module,
        "_replay_osv_lane",
        lambda *args, **kwargs: called.append(kwargs)
        or {"schema": "factory.osv-native-replay.v1", "state": "VERIFIED"},
    )
    directory = tmp_path / "monitor"
    directory.mkdir()
    module._osv_replay_result(
        result,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        {
            "artifacts": {
                "coverage.json": request["coverage"],
                "report.json": request["report"],
                "challenges.json": request["challenges"],
            }
        },
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() + 60,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
        request["obligations"],
    )
    assert len(called) == 1
    assert called[0]["timeout_seconds"] > 0
    assert result["gaps"] == ["UNRELATED_GAP"]
    assert result["state"] == "INCOMPLETE"
    assert result["osv_replay"]["state"] == "VERIFIED"


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeAuditError("E_OSV_REPLAY", "receipt invalid"),
        {"state": "INCOMPLETE"},
    ],
)
def test_osv_replay_result_failure_keeps_mandatory_gap(tmp_path, monkeypatch, failure):
    import threading

    import factoryline.deep_audit as module

    request = _osv_replay_request_fixture()
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    if isinstance(failure, Exception):

        def replay_failure(*args, **kwargs):
            raise failure

        replay = replay_failure
    else:

        def replay(*args, **kwargs):
            return failure

    monkeypatch.setattr(module, "_replay_osv_lane", replay)
    result = {"gaps": ["OSV_NATIVE_REPLAY_REQUIRED"], "state": "INCOMPLETE"}
    directory = tmp_path / "monitor"
    directory.mkdir()
    module._osv_replay_result(
        result,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        {
            "artifacts": {
                "coverage.json": request["coverage"],
                "report.json": request["report"],
                "challenges.json": request["challenges"],
            }
        },
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() + 60,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
        request["obligations"],
    )
    assert result["state"] == "INCOMPLETE"
    assert "OSV_NATIVE_REPLAY_REQUIRED" in result["gaps"]
    assert "OSV_NATIVE_REPLAY_FAILED" in result["gaps"]
    assert result["osv_replay"]["state"] == "INCOMPLETE"


def test_osv_replay_result_requires_gap_and_shared_deadline(tmp_path, monkeypatch):
    import threading

    import factoryline.deep_audit as module

    request = _osv_replay_request_fixture()
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    calls = []
    monkeypatch.setattr(
        module, "_replay_osv_lane", lambda *args, **kwargs: calls.append(args)
    )
    artifacts = {
        "artifacts": {
            "coverage.json": request["coverage"],
            "report.json": request["report"],
            "challenges.json": request["challenges"],
        }
    }
    directory = tmp_path / "monitor"
    directory.mkdir()
    result = {"gaps": ["UNRELATED_GAP"], "state": "INCOMPLETE"}
    module._osv_replay_result(
        result,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        artifacts,
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() + 60,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
        request["obligations"],
    )
    assert calls == []
    expired = {"gaps": ["OSV_NATIVE_REPLAY_REQUIRED"], "state": "INCOMPLETE"}
    module._osv_replay_result(
        expired,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        artifacts,
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() - 1,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
        request["obligations"],
    )
    assert calls == []
    assert expired["state"] == "INCOMPLETE"
    assert "OSV_NATIVE_REPLAY_REQUIRED" in expired["gaps"]
    assert expired["osv_replay"]["diagnostic_code"] == "E_OSV_REPLAY"


def _osv_replay_container_stubs(
    monkeypatch, tmp_path, request, failure=None, cleanup=True
):
    import factoryline.deep_audit as module
    from factoryline.deep_audit import _osv_replay_expected

    raw = json.dumps(
        {
            **_osv_replay_expected(request),
            "native_execution_sha256": "f" * 64,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    runtime = tmp_path / "trusted-runtime"
    runtime.mkdir()
    monkeypatch.setattr(module, "_docker_preflight", lambda *args: None)
    monkeypatch.setattr(
        module, "_codeql_replay_runtime", lambda scratch: (runtime, "c" * 64)
    )
    monkeypatch.setattr(module, "_osv_replay_argv", lambda *args: ["docker", "run"])
    monkeypatch.setattr(module, "_container_cleanup", lambda *args: cleanup)

    def run(argv, cwd, timeout, scratch, *, stdout_path, cancelled):
        stdout_path.write_bytes(raw)
        facts = _codeql_process_facts(
            timeout, raw, b"private replay stderr", cancelled=False
        )
        if failure:
            facts.update(failure)
        return facts

    monkeypatch.setattr("factoryline.runtime_audit_process.run_bounded_command", run)
    return raw


@pytest.mark.parametrize(
    "failure,cleanup",
    [
        ({"exit_code": 7}, True),
        ({"timed_out": True}, True),
        ({"cancelled": True}, True),
        ({}, False),
    ],
)
def test_osv_replay_container_failures_keep_replay_gap_incomplete(
    tmp_path, monkeypatch, failure, cleanup
):
    import threading

    import factoryline.deep_audit as module

    request = _osv_replay_request_fixture()
    _osv_replay_container_stubs(monkeypatch, tmp_path, request, failure, cleanup)
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    result = {"gaps": ["OSV_NATIVE_REPLAY_REQUIRED"], "state": "INCOMPLETE"}
    directory = tmp_path / "monitor"
    directory.mkdir()
    module._osv_replay_result(
        result,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        {
            "artifacts": {
                "coverage.json": request["coverage"],
                "report.json": request["report"],
                "challenges.json": request["challenges"],
            }
        },
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() + 90,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
        request["obligations"],
    )
    assert result["state"] == "INCOMPLETE"
    assert "OSV_NATIVE_REPLAY_REQUIRED" in result["gaps"]
    assert "OSV_NATIVE_REPLAY_FAILED" in result["gaps"]
    assert result["osv_replay"]["state"] == "INCOMPLETE"


def test_osv_replay_container_success_clears_required_gap_only(tmp_path, monkeypatch):
    import threading

    import factoryline.deep_audit as module

    request = _osv_replay_request_fixture()
    _osv_replay_container_stubs(monkeypatch, tmp_path, request)
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    result = {
        "gaps": ["OSV_NATIVE_REPLAY_REQUIRED", "UNRELATED_GAP"],
        "state": "INCOMPLETE",
    }
    directory = tmp_path / "monitor"
    directory.mkdir()
    module._osv_replay_result(
        result,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        {
            "artifacts": {
                "coverage.json": request["coverage"],
                "report.json": request["report"],
                "challenges.json": request["challenges"],
            }
        },
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() + 90,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
        request["obligations"],
    )
    assert result["gaps"] == ["UNRELATED_GAP"]
    assert result["state"] == "INCOMPLETE"
    assert result["osv_replay"]["state"] == "VERIFIED"


@pytest.mark.parametrize("completed", [False, True])
def test_fuzz_snapshot_completion_is_explicit(tmp_path, completed):
    from factoryline.deep_audit_io import _fuzz_snapshot, _fuzz_record_input

    class Coverage:
        def json_report(self, outfile):
            Path(outfile).write_text(json.dumps({"files": {}}))

    output = tmp_path / "fuzz.json"
    state = {
        "executions": 0,
        "inputs": set(),
        "findings": [],
        "completed": completed,
        "errors": [],
    }
    _fuzz_record_input(state, b"x")
    _fuzz_snapshot(
        Coverage(),
        {
            "lane": {"tool_version": "3.0.0"},
            "inventory": {"files": [{"path": "fuzz.py", "sha256": "a" * 64}]},
        },
        "fuzz.py",
        output,
        state,
    )
    assert json.loads(output.read_text())["completed"] is completed


@pytest.mark.parametrize("limit", ["bytes", "executions", "distinct"])
def test_fuzz_input_budget_retains_incomplete_state(limit):
    from factoryline.deep_audit_io import _fuzz_record_input

    state = {
        "executions": 1_000_000 if limit == "executions" else 0,
        "inputs": {str(i) for i in range(4096)} if limit == "distinct" else set(),
        "findings": [],
        "completed": False,
    }
    before = (state["executions"], set(state["inputs"]))
    data = b"x" * 1_048_577 if limit == "bytes" else b"x"
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_BUDGET"):
        _fuzz_record_input(state, data)
    assert (state["executions"], state["inputs"]) == before
    assert state["completed"] is False
    assert state["errors"] == ["E_FUZZ_BUDGET"]
    assert state["findings"] == []


def test_fuzz_repeat_input_at_distinct_limit_remains_counted():
    from factoryline.deep_audit_io import _fuzz_record_input, sha256_bytes

    state = {
        "executions": 4096,
        "inputs": {str(i) for i in range(4095)} | {sha256_bytes(b"x")},
    }
    _fuzz_record_input(state, b"x")
    assert state["executions"] == 4097
    assert len(state["inputs"]) == 4096


def _retained_fuzz_fixture():
    from factoryline.deep_audit_io import (
        _fuzz_record_input,
        _fuzz_corpus_document,
        _codeql_native_blob,
        canonical_bytes,
        sha256_bytes,
    )

    state = {"executions": 0, "inputs": set()}
    for data in (b"", b"failure", b"failure"):
        _fuzz_record_input(state, data)
    corpus = _fuzz_corpus_document(state, "fuzz.py", "a" * 64)
    raw = canonical_bytes(corpus)
    report = {
        "harness": corpus["harness"],
        "metrics": {"executions": 3, "corpus_size": 2},
        "corpus": {"sha256": sha256_bytes(raw), "inputs": 2, "bytes": 7},
        "findings": [{"input_sha256": sha256_bytes(b"failure")}],
        "fuzz_corpus": _codeql_native_blob(raw),
    }
    return corpus, report


def test_fuzz_retained_corpus_binds_exact_inputs_and_failure():
    from factoryline.deep_audit_io import _retained_fuzz_corpus
    from factoryline.deep_audit_sarif import _fuzz_retained_evidence_gaps

    corpus, report = _retained_fuzz_fixture()
    assert _retained_fuzz_corpus(report, {"fuzz.py": "a" * 64}) == corpus
    assert _fuzz_retained_evidence_gaps(
        report, {"engine": "atheris"}, {"fuzz.py": "a" * 64}
    ) == ["FUZZ_NATIVE_REPLAY_REQUIRED"]


def test_fuzz_native_report_retains_corpus_without_disclosing_payload(tmp_path):
    from factoryline.deep_audit_io import _native_report, _codeql_blob_bytes
    from factoryline.deep_audit_sarif import _fuzz_retained_evidence_gaps

    corpus, raw = _retained_fuzz_fixture()
    encoded = raw.pop("fuzz_corpus")
    raw["errors"] = []
    (tmp_path / "fuzz.corpus.json").write_bytes(_codeql_blob_bytes(encoded))
    profile = {"engine": "atheris", "report_format": "runtime-json"}
    contract = {
        "lane": {"report": "fuzz.json"},
        "inventory": {"files": [{"path": "fuzz.py", "sha256": "a" * 64}]},
    }
    facts = _codeql_process_facts(30, b"stdout", b"stderr", exit_code=77)
    result = _native_report(raw, profile, contract, tmp_path, [{"execution": facts}])
    assert result["fuzz_corpus"] == encoded
    assert "fuzz_corpus" not in raw
    assert result["completed"] is True
    assert corpus["inputs"]
    assert _fuzz_retained_evidence_gaps(raw, profile, {"fuzz.py": "a" * 64}) == [
        "FUZZ_NATIVE_CORPUS_UNVERIFIED"
    ]


@pytest.mark.parametrize(
    "tamper",
    [
        "data",
        "hash",
        "size",
        "duplicate",
        "order",
        "harness",
        "count",
        "bytes",
        "failure",
        "callbacks",
        "encoding",
    ],
)
def test_fuzz_retained_corpus_rejects_tampering(tamper):
    from factoryline.deep_audit_io import (
        _retained_fuzz_corpus,
        _codeql_native_blob,
        canonical_bytes,
        sha256_bytes,
    )

    corpus, report = _retained_fuzz_fixture()
    if tamper in {"data", "hash", "size"}:
        key, value = {
            "data": ("data_base64", "eA=="),
            "hash": ("sha256", "b" * 64),
            "size": ("bytes", 5),
        }[tamper]
        corpus["inputs"][0][key] = value
    elif tamper == "duplicate":
        corpus["inputs"].append(corpus["inputs"][0])
    elif tamper == "order":
        corpus["inputs"].reverse()
    elif tamper == "harness":
        corpus["harness"] = {"path": "../fuzz.py", "sha256": "a" * 64}
    elif tamper == "failure":
        report["findings"][0]["input_sha256"] = "c" * 64
    else:
        target, key = {
            "count": (report["metrics"], "corpus_size"),
            "bytes": (report["corpus"], "bytes"),
            "callbacks": (report["metrics"], "executions"),
            "encoding": (corpus["inputs"][0], "data_base64"),
        }[tamper]
        target[key] = "!!!!" if tamper == "encoding" else 0
    raw = canonical_bytes(corpus)
    report["corpus"]["sha256"] = sha256_bytes(raw)
    report["fuzz_corpus"] = _codeql_native_blob(raw)
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_CORPUS"):
        _retained_fuzz_corpus(report, {"fuzz.py": "a" * 64})


def test_fuzz_aggregate_input_budget_preserves_last_good_state():
    from factoryline.deep_audit_io import _fuzz_record_input

    state = {"executions": 0, "inputs": set()}
    _fuzz_record_input(state, b"a" * 1_048_576)
    _fuzz_record_input(state, b"b" * 1_048_576)
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_BUDGET"):
        _fuzz_record_input(state, b"c")
    assert state["executions"] == 2
    assert state["corpus_bytes"] == 2_097_152
    assert len(state["corpus"]) == 2


@pytest.mark.parametrize("finding", [False, True])
def test_fuzz_finalization_requires_matching_native_terminal_exit(finding):
    from factoryline.deep_audit_io import _finalize_fuzz_report

    raw = {
        "completed": False,
        "errors": [],
        "findings": [{"rule_id": "FUZZ_EXCEPTION"}] if finding else [],
    }
    facts = _codeql_process_facts(30, b"", b"", exit_code=77 if finding else 0)
    result = _finalize_fuzz_report(raw, [{"execution": facts}])
    assert result["completed"] is True
    assert result["findings"] == raw["findings"]
    assert raw["completed"] is False
    assert result["lifecycle_execution_sha256"] == digest(facts)


@pytest.mark.parametrize(
    "change",
    [
        {"timed_out": True},
        {"cancelled": True},
        {"cleanup_confirmed": False},
        {"exit_code": 77},
        {"output_limit_exceeded": True},
    ],
)
def test_fuzz_finalization_never_promotes_failed_process(change):
    from factoryline.deep_audit_io import _finalize_fuzz_report

    facts = _codeql_process_facts(30, b"", b"", **change)
    with pytest.raises(RuntimeAuditError):
        _finalize_fuzz_report(
            {"completed": False, "errors": [], "findings": []}, [{"execution": facts}]
        )


def test_fuzz_budget_error_cannot_be_cleared_by_success_exit():
    from factoryline.deep_audit_io import _finalize_fuzz_report

    with pytest.raises(RuntimeAuditError, match="E_FUZZ_REPORT"):
        _finalize_fuzz_report(
            {"completed": False, "errors": ["E_FUZZ_BUDGET"], "findings": []},
            [{"execution": _codeql_process_facts(30, b"", b"")}],
        )


def test_fuzz_zero_branch_exception_remains_a_finding():
    from factoryline.deep_audit_sarif import _execution_runtime

    report = {
        "schema": "factory.deep-atheris-observations.v1",
        "engine": "atheris",
        "tool_version": "3.0.0",
        "completed": True,
        "errors": [],
        "harness": {"path": "fuzz.py", "sha256": "a" * 64},
        "metrics": {"executions": 1, "coverage_edges": 0, "corpus_size": 1},
        "findings": [
            {
                "rule_id": "FUZZ_EXCEPTION",
                "path": "fuzz.py",
                "line": 1,
                "severity": "high",
            }
        ],
    }
    lane = {
        "id": "fuzz",
        "engine": "atheris",
        "family": "fuzz",
        "tool_version": "3.0.0",
    }
    findings = _execution_runtime(report, lane, {"fuzz.py": "a" * 64})
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "FUZZ_EXCEPTION"
    report["metrics"]["executions"] = 0
    with pytest.raises(RuntimeAuditError):
        _execution_runtime(report, lane, {"fuzz.py": "a" * 64})


def _fuzz_control_bytes(enabled=True):
    from factoryline.deep_audit_io import canonical_bytes

    return canonical_bytes(
        {
            "schema": "factory.fuzz-control.v1",
            "rules": {"FUZZ_EXCEPTION": enabled},
        }
    )


def test_fuzz_control_ids_and_disable_exact_enabled_rule():
    from factoryline.deep_audit_io import _fuzz_control_ids, _fuzz_disable_rule

    enabled = _fuzz_control_bytes()
    disabled = _fuzz_disable_rule(enabled, "FUZZ_EXCEPTION")
    assert _fuzz_control_ids(enabled) == ["FUZZ_EXCEPTION"]
    assert _fuzz_control_ids(disabled) == []
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_CONTROL"):
        _fuzz_disable_rule(disabled, "FUZZ_EXCEPTION")
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_CONTROL"):
        _fuzz_disable_rule(enabled, "FUZZ_EXCEPTION-lookalike")


@pytest.mark.parametrize(
    "raw",
    [
        b'{"rules":{"FUZZ_EXCEPTION":true},"schema":"factory.fuzz-control.v1","extra":1}',
        b'{"rules":{"FUZZ_EXCEPTION":true,"OTHER":false},"schema":"factory.fuzz-control.v1"}',
        b'{"rules":{"FUZZ_EXCEPTION":true},"schema":"factory.fuzz-control.v2"}',
        b'{ "rules": {"FUZZ_EXCEPTION": true}, "schema": "factory.fuzz-control.v1" }',
        b'{"rules":{"FUZZ_EXCEPTION":1},"schema":"factory.fuzz-control.v1"}',
    ],
)
def test_fuzz_control_ids_rejects_unknown_or_noncanonical_config(raw):
    from factoryline.deep_audit_io import _fuzz_control_ids

    with pytest.raises(RuntimeAuditError, match="E_FUZZ_CONTROL"):
        _fuzz_control_ids(raw)


def test_fuzz_control_args_binds_exact_option_and_native_arguments(tmp_path):
    from factoryline.deep_audit_io import _fuzz_control_args, sha256_bytes

    config = tmp_path / "fuzz-control.json"
    raw = _fuzz_control_bytes()
    config.write_bytes(raw)
    assert _fuzz_control_args(
        ["harness.py", "report.json", f"--factory-control={config}", "--", "-runs=5"]
    ) == (["FUZZ_EXCEPTION"], sha256_bytes(raw), ["-runs=5"])
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_CONTROL"):
        _fuzz_control_args(
            ["harness.py", "report.json", f"--factory-control={config}", "-runs=5"]
        )


def test_fuzz_execution_contract_accepts_exact_inventoried_fixture_subset(tmp_path):
    from factoryline.deep_audit_io import _fuzz_execution_contract, sha256_bytes

    source = tmp_path / "fixture"
    source.mkdir()
    (source / "fuzz.py").write_bytes(b"def TestOneInput(data): pass\n")
    (source / "helper.py").write_bytes(b"VALUE = 1\n")
    contract = {
        "inventory": {
            "candidate_sha256": "a" * 64,
            "files": [
                {
                    "path": "fuzz.py",
                    "sha256": sha256_bytes((source / "fuzz.py").read_bytes()),
                },
                {
                    "path": "helper.py",
                    "sha256": sha256_bytes((source / "helper.py").read_bytes()),
                },
            ],
        }
    }
    (source / "helper.py").unlink()
    projected = _fuzz_execution_contract(contract, source)
    assert projected["inventory"]["files"] == [contract["inventory"]["files"][0]]


@pytest.mark.parametrize("damage", ["drift", "extra"])
def test_fuzz_execution_contract_rejects_fixture_drift_or_uninventoried_file(
    tmp_path, damage
):
    from factoryline.deep_audit_io import _fuzz_execution_contract, sha256_bytes

    source = tmp_path / "fixture"
    source.mkdir()
    target = source / "fuzz.py"
    target.write_bytes(b"def TestOneInput(data): pass\n")
    contract = {
        "inventory": {
            "candidate_sha256": "a" * 64,
            "files": [{"path": "fuzz.py", "sha256": sha256_bytes(target.read_bytes())}],
        }
    }
    if damage == "drift":
        target.write_bytes(b"def TestOneInput(data): return None\n")
    else:
        (source / "injected.py").write_bytes(b"PAYLOAD = True\n")
    with pytest.raises(RuntimeAuditError):
        _fuzz_execution_contract(contract, source)


def _fuzz_replay_request_fixture():
    _, report = _retained_fuzz_fixture()
    return {
        "lane": {
            "id": "fuzz-replay-test",
            "engine": "atheris",
            "family": "fuzz",
            "image": "ghcr.io/example/atheris@sha256:" + "b" * 64,
        },
        "inventory": {
            "candidate_sha256": "c" * 64,
            "files": [{"path": "fuzz.py", "sha256": "a" * 64}],
        },
        "coverage": {"schema": "factory.coverage.v1"},
        "report": report,
    }


def test_fuzz_replay_driver_executes_retained_inputs(tmp_path):
    from factoryline.deep_audit_io import (
        _fuzz_replay_inputs_main,
        _codeql_blob_bytes,
        _codeql_native_blob,
        canonical_bytes,
        sha256_bytes,
    )

    request = _fuzz_replay_request_fixture()
    source = tmp_path / "source"
    source.mkdir()
    target = source / "fuzz.py"
    target.write_text(
        "def TestOneInput(data):\n    if data == b'failure': raise ValueError('seeded')\n"
    )
    seal = sha256_bytes(target.read_bytes())
    corpus = json.loads(_codeql_blob_bytes(request["report"]["fuzz_corpus"]))
    corpus["harness"]["sha256"] = seal
    raw = canonical_bytes(corpus)
    request["report"]["fuzz_corpus"] = _codeql_native_blob(raw)
    request["report"]["harness"] = corpus["harness"]
    request["report"]["corpus"]["sha256"] = sha256_bytes(raw)
    request["inventory"]["files"][0]["sha256"] = seal
    contract = tmp_path / "request.json"
    contract.write_bytes(canonical_bytes(request))
    observed = _fuzz_replay_inputs_main(contract, source)
    assert observed["replayed_inputs"] == 2
    assert observed["failure_inputs"] == [sha256_bytes(b"failure")]
    target.write_text("def TestOneInput(data): return None\n")
    with pytest.raises(RuntimeAuditError):
        _fuzz_replay_inputs_main(contract, source)


@pytest.mark.parametrize("tamper", ["failure", "count", "boolean", "hash", "extra"])
def test_fuzz_replay_observation_rejects_changed_outcomes(tamper):
    from factoryline.deep_audit_io import (
        _validate_fuzz_replay_observation,
        _fuzz_replay_expected,
    )

    expected = _fuzz_replay_expected(_fuzz_replay_request_fixture())
    observed = {
        "schema": "factory.fuzz-input-replay.v1",
        **{
            key: expected[key]
            for key in ("harness", "corpus_sha256", "replayed_inputs", "failure_inputs")
        },
    }
    raw = json.dumps(observed).encode()
    _validate_fuzz_replay_observation(
        raw, _codeql_process_facts(30, raw, b""), expected
    )
    if tamper == "failure":
        observed["failure_inputs"] = []
    elif tamper == "extra":
        observed["unexpected"] = True
    else:
        key, value = {
            "count": ("replayed_inputs", 3),
            "boolean": ("replayed_inputs", True),
            "hash": ("corpus_sha256", "0" * 64),
        }[tamper]
        observed[key] = value
    raw = json.dumps(observed).encode()
    with pytest.raises(RuntimeAuditError):
        _validate_fuzz_replay_observation(
            raw, _codeql_process_facts(30, raw, b""), expected
        )


def test_fuzz_replay_expected_binds_retained_corpus_and_report():
    from factoryline.deep_audit_io import _fuzz_replay_expected, _retained_fuzz_corpus

    request = _fuzz_replay_request_fixture()
    expected = _fuzz_replay_expected(request)
    corpus = _retained_fuzz_corpus(request["report"], {"fuzz.py": "a" * 64})
    assert expected == {
        "schema": "factory.fuzz-native-replay.v1",
        "state": "VERIFIED",
        "candidate_sha256": "c" * 64,
        "lane_sha256": digest(request["lane"]),
        "coverage_sha256": digest(request["coverage"]),
        "report_sha256": digest(request["report"]),
        "corpus_sha256": request["report"]["corpus"]["sha256"],
        "harness": corpus["harness"],
        "replayed_inputs": len(corpus["inputs"]),
        "failure_inputs": sorted(
            {finding["input_sha256"] for finding in request["report"]["findings"]}
        ),
    }


@pytest.mark.parametrize("tamper", ["corpus", "request_inventory"])
def test_fuzz_replay_expected_rejects_corpus_or_inventory_drift(tamper):
    from factoryline.deep_audit_io import (
        _fuzz_replay_expected,
        _codeql_blob_bytes,
        _codeql_native_blob,
        canonical_bytes,
    )
    from factoryline.runtime_audit_common import sha256_bytes

    request = _fuzz_replay_request_fixture()
    if tamper == "corpus":
        corpus = json.loads(_codeql_blob_bytes(request["report"]["fuzz_corpus"]))
        corpus["inputs"][0]["sha256"] = "d" * 64
        raw = canonical_bytes(corpus)
        request["report"]["fuzz_corpus"] = _codeql_native_blob(raw)
        request["report"]["corpus"]["sha256"] = sha256_bytes(raw)
    else:
        request["inventory"]["files"][0]["sha256"] = "e" * 64
    with pytest.raises(RuntimeAuditError):
        _fuzz_replay_expected(request)


@pytest.mark.parametrize(
    "failure",
    [
        {"exit_code": 7},
        {"timed_out": True},
        {"cancelled": True},
        {"cleanup_confirmed": False},
        {"launch_error": True},
        {"output_limit_exceeded": True},
    ],
)
def test_fuzz_replay_receipt_rejects_process_and_cleanup_failures(failure):
    from factoryline.deep_audit import _fuzz_replay_receipt
    from factoryline.deep_audit_io import _fuzz_replay_expected

    request = _fuzz_replay_request_fixture()
    expected = _fuzz_replay_expected(request)
    raw = json.dumps(
        {**expected, "native_execution_sha256": "a" * 64},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    facts = _codeql_process_facts(60, raw, b"", cancelled=False)
    facts.update(failure)
    with pytest.raises(RuntimeAuditError):
        _fuzz_replay_receipt(raw, facts, request)


@pytest.mark.parametrize(
    "field", ["corpus_sha256", "failure_inputs", "replayed_inputs"]
)
def test_fuzz_replay_receipt_rejects_output_binding_drift(field):
    from factoryline.deep_audit import _fuzz_replay_receipt
    from factoryline.deep_audit_io import _fuzz_replay_expected

    request = _fuzz_replay_request_fixture()
    expected = _fuzz_replay_expected(request)
    receipt = {**expected, "native_execution_sha256": "a" * 64}
    if field == "failure_inputs":
        receipt[field] = ["0" * 64]
    elif field == "replayed_inputs":
        receipt[field] += 1
    else:
        receipt[field] = "0" * 64
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    facts = _codeql_process_facts(60, raw, b"", cancelled=False)
    with pytest.raises(RuntimeAuditError):
        _fuzz_replay_receipt(raw, facts, request)


def test_fuzz_control_host_receipt_clears_only_replayed_gaps(monkeypatch):
    from factoryline.deep_audit import apply_fuzz_control_replay

    expected = {
        "schema": "factory.fuzz-native-replay.v1",
        "state": "VERIFIED",
        "covered_obligations": ["signed-control"],
        "challenge_sha256": "a" * 64,
        "replayed_inputs": 1,
    }
    monkeypatch.setattr(
        "factoryline.deep_audit_io._fuzz_replay_expected", lambda request: expected
    )
    replay = {**expected, "native_execution_sha256": "b" * 64}
    raw = (json.dumps(replay) + "\n").encode()
    replay.update(
        image="sha256:" + "c" * 64,
        runtime_sha256="d" * 64,
        command_sha256="e" * 64,
        cleanup_confirmed=True,
        execution=_codeql_process_facts(60, raw, b"", cancelled=False),
    )
    result = {
        "gaps": [
            "FUZZ_NATIVE_REPLAY_REQUIRED",
            "FUZZ_CHALLENGE_REPLAY_REQUIRED",
            "OBLIGATION_COVERAGE_MISSING",
            "CHALLENGE_FAILED",
            "UNRELATED_GAP",
        ],
        "obligations": [],
        "state": "INCOMPLETE",
    }
    lane = {
        "image": replay["image"],
        "coverage": "coverage",
        "report": "report",
        "challenge_report": "challenges",
    }
    bundle = {"artifacts": {"coverage": {}, "report": {}, "challenges": {}}}
    apply_fuzz_control_replay(result, replay, lane, bundle, {}, [{}])
    assert result["gaps"] == ["CHALLENGE_FAILED", "UNRELATED_GAP"]
    assert result["obligations"] == ["signed-control"]
    assert result["state"] == "INCOMPLETE"
    original = json.loads(json.dumps(result))
    replay["challenge_sha256"] = "f" * 64
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_REPLAY"):
        apply_fuzz_control_replay(result, replay, lane, bundle, {}, [{}])
    assert result == original


@pytest.mark.parametrize(
    "failure",
    [
        {"exit_code": 1},
        {"cancelled": True},
        {"timed_out": True},
        {"launch_error": True},
        {"cleanup_confirmed": False},
        {"output_limit_exceeded": True},
    ],
)
def test_fuzz_host_replay_execution_fails_closed(failure):
    from factoryline.deep_audit import (
        _osv_replay_process_valid_for_review,
        _validate_fuzz_host_replay,
    )
    from factoryline.runtime_audit_common import _validate_runner_facts, require_digest

    facts = _codeql_process_facts(60, b"{}", b"", cancelled=False)
    assert _osv_replay_process_valid_for_review(facts)
    facts.update(failure)
    assert not _osv_replay_process_valid_for_review(facts)
    replay = {
        "image": "sha256:" + "c" * 64,
        "execution": facts,
        "cleanup_confirmed": True,
    }
    with pytest.raises(RuntimeAuditError):
        _validate_fuzz_host_replay(
            replay, {"image": replay["image"]}, _validate_runner_facts, require_digest
        )


def test_fuzz_replay_receipt_accepts_native_receipt_and_checks_stdout_binding():
    from factoryline.deep_audit import _fuzz_replay_receipt
    from factoryline.deep_audit_io import _fuzz_replay_expected

    request = _fuzz_replay_request_fixture()
    receipt = {**_fuzz_replay_expected(request), "native_execution_sha256": "a" * 64}
    raw = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    facts = _codeql_process_facts(60, raw, b"", cancelled=False)
    assert _fuzz_replay_receipt(raw, facts, request) == receipt
    for change in ({"stdout_sha256": "0" * 64}, {"stdout_bytes": len(raw) + 1}):
        tampered_facts = {**facts, **change}
        with pytest.raises(RuntimeAuditError, match="E_FUZZ_REPLAY"):
            _fuzz_replay_receipt(raw, tampered_facts, request)


def test_has_fuzz_controls_requires_matching_signed_paths():
    from factoryline.deep_audit import has_fuzz_controls

    lane = {"engine": "atheris", "family": "fuzz"}
    inventory = {"files": [{"path": "fuzz.py"}]}
    obligation = {
        "engine": "atheris",
        "family": "fuzz",
        "paths": ["fuzz.py"],
    }
    assert has_fuzz_controls(lane, inventory, [obligation])
    assert not has_fuzz_controls(
        lane, inventory, [{**obligation, "paths": ["other.py"]}]
    )
    assert not has_fuzz_controls(lane, inventory, [])
    assert not has_fuzz_controls({**lane, "engine": "semgrep"}, inventory, [obligation])


def test_verify_fuzz_retained_evidence_binds_signed_triplet_and_replay_only_gaps(
    monkeypatch,
):
    import factoryline.deep_audit_io as module

    control_kinds = ("positive", "negative", "mutation")
    obligation = {
        "id": "fuzz-control",
        "engine": "atheris",
        "family": "fuzz",
        "detector_rule_id": "FUZZ_EXCEPTION",
        "paths": ["fuzz.py"],
        "challenges": [{"kind": kind} for kind in control_kinds],
    }
    challenges = {
        "schema": "factory.deep-challenges.v1",
        "observations": [
            {
                "obligation_id": obligation["id"],
                "kind": kind,
                "atheris_native_evidence": {
                    key: {"bytes": 0}
                    for key in ("raw_report", "corpus_manifest", "effective_config")
                },
            }
            for kind in control_kinds
        ],
        "gaps": [
            {
                "obligation_id": obligation["id"],
                "kind": kind,
                "reason": "FUZZ_CHALLENGE_REPLAY_REQUIRED",
            }
            for kind in control_kinds
        ],
    }
    lane = {"engine": "atheris", "family": "fuzz"}
    sources = {"fuzz.py": "a" * 64}
    evidence = {"native_evidence": {"retained": True}}
    by_key = {
        (obligation["id"], kind): {
            "obligation_id": obligation["id"],
            "kind": kind,
            **evidence,
        }
        for kind in control_kinds
    }
    monkeypatch.setattr(module, "_fuzz_retained_observations", lambda *args: by_key)

    summary, controls = module.verify_fuzz_retained_evidence(
        challenges,
        [obligation],
        lane,
        sources,
        "b" * 64,
        {},
    )
    assert summary == {
        "challenge_sha256": digest(challenges),
        "obligations_sha256": digest([obligation]),
        "covered_obligations": [obligation["id"]],
        "controls_sha256": digest(
            [
                {
                    "obligation_id": obligation["id"],
                    "kind": control["kind"],
                    "evidence": control["native_evidence"],
                }
                for control in controls
            ]
        ),
        "control_count": 3,
    }
    assert [control["kind"] for control in controls] == sorted(control_kinds)

    challenges["gaps"][0]["reason"] = "CHALLENGE_FAILED"
    with pytest.raises(RuntimeAuditError, match="E_FUZZ_ARTIFACT"):
        module.verify_fuzz_retained_evidence(
            challenges, [obligation], lane, sources, "b" * 64, {}
        )


def test_fuzz_replay_result_clears_only_required_gap_after_host_receipt(
    tmp_path, monkeypatch
):
    import threading

    import factoryline.deep_audit as module

    request = _fuzz_replay_request_fixture()
    result = {
        "gaps": ["FUZZ_NATIVE_REPLAY_REQUIRED", "UNRELATED_GAP"],
        "state": "INCOMPLETE",
    }
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    monkeypatch.setattr(
        module,
        "_replay_fuzz_lane",
        lambda *args, **kwargs: {
            "schema": "factory.fuzz-native-replay.v1",
            "state": "VERIFIED",
        },
    )
    directory = tmp_path / "monitor"
    directory.mkdir()
    module._fuzz_replay_result(
        result,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        {
            "artifacts": {
                "coverage.json": request["coverage"],
                "report.json": request["report"],
            }
        },
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() + 60,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
    )
    assert result["gaps"] == ["UNRELATED_GAP"]
    assert result["state"] == "INCOMPLETE"
    assert result["fuzz_replay"]["state"] == "VERIFIED"


@pytest.mark.parametrize(
    "failure",
    [
        RuntimeAuditError("E_FUZZ_REPLAY", "receipt invalid"),
        {"state": "INCOMPLETE"},
    ],
)
def test_fuzz_replay_result_failure_keeps_required_gap(tmp_path, monkeypatch, failure):
    import threading

    import factoryline.deep_audit as module

    request = _fuzz_replay_request_fixture()
    monkeypatch.setattr(module, "_monitor_lane", lambda *args: None)
    if isinstance(failure, Exception):

        def replay(*args, **kwargs):
            raise failure
    else:

        def replay(*args, **kwargs):
            return failure

    monkeypatch.setattr(module, "_replay_fuzz_lane", replay)
    result = {"gaps": ["FUZZ_NATIVE_REPLAY_REQUIRED"], "state": "INCOMPLETE"}
    directory = tmp_path / "monitor"
    directory.mkdir()
    module._fuzz_replay_result(
        result,
        ["docker"],
        request["lane"],
        tmp_path / "snapshot",
        {
            "artifacts": {
                "coverage.json": request["coverage"],
                "report.json": request["report"],
            }
        },
        request["inventory"],
        "run-id",
        threading.Event(),
        time.monotonic() + 60,
        (directory, {"active_lane": request["lane"]["id"]}, lambda event: None),
    )
    assert result["state"] == "INCOMPLETE"
    assert "FUZZ_NATIVE_REPLAY_REQUIRED" in result["gaps"]
    assert "FUZZ_NATIVE_REPLAY_FAILED" in result["gaps"]


@pytest.mark.parametrize("kind", ["positive", "negative", "mutation"])
def test_atheris_challenge_report_binds_native_corpus_config_and_semantics(kind):
    from factoryline.deep_audit_io import (
        _atheris_challenge_report,
        _codeql_blob_bytes,
        canonical_bytes,
        _fuzz_disable_rule,
    )

    request = _fuzz_replay_request_fixture()
    request["lane"]["tool_version"] = "3.0.0"
    raw = deepcopy(request["report"])
    raw.update(
        schema="factory.deep-atheris-observations.v1",
        engine="atheris",
        tool_version="3.0.0",
        completed=True,
        errors=[],
    )
    raw["findings"][0].update(
        rule_id="FUZZ_EXCEPTION", path="fuzz.py", line=1, severity="high"
    )
    corpus = _codeql_blob_bytes(raw.pop("fuzz_corpus"))
    baseline = Path("deploy/deep-adapters/rules/fuzz-control.json").read_bytes()
    config = (
        _fuzz_disable_rule(baseline, "FUZZ_EXCEPTION")
        if kind == "mutation"
        else baseline
    )
    raw["control_sha256"] = sha256_bytes(config)
    if kind != "positive":
        raw["findings"] = []
        raw["completed"] = False  # Native -runs termination is sealed by process facts.
    manifest = {item["path"]: item["sha256"] for item in request["inventory"]["files"]}
    challenge = {"kind": kind, "fixture_path": raw["harness"]["path"]}
    result = _atheris_challenge_report(
        canonical_bytes(raw), corpus, config, challenge, request["lane"], manifest
    )
    assert result["control_sha256"] == sha256_bytes(config)
    assert result["harness"] == raw["harness"]
    assert len(result["findings"]) == (1 if kind == "positive" else 0)
    assert "corpus" not in result and "fuzz_corpus" not in result


@pytest.mark.parametrize(
    "tamper",
    [
        "config",
        "harness",
        "input",
        "corpus",
        "missing_positive",
        "unexpected_safe",
        "completion_missing",
        "completion_type",
        "positive_incomplete",
    ],
)
def test_atheris_challenge_report_rejects_forged_control_evidence(tamper):
    from factoryline.deep_audit_io import (
        _atheris_challenge_report,
        _codeql_blob_bytes,
        canonical_bytes,
    )

    request = _fuzz_replay_request_fixture()
    request["lane"]["tool_version"] = "3.0.0"
    raw = deepcopy(request["report"])
    raw.update(
        schema="factory.deep-atheris-observations.v1",
        engine="atheris",
        tool_version="3.0.0",
        completed=True,
        errors=[],
    )
    raw["findings"][0].update(
        rule_id="FUZZ_EXCEPTION", path="fuzz.py", line=1, severity="high"
    )
    corpus = _codeql_blob_bytes(raw.pop("fuzz_corpus"))
    config = Path("deploy/deep-adapters/rules/fuzz-control.json").read_bytes()
    raw["control_sha256"] = sha256_bytes(config)
    manifest = {item["path"]: item["sha256"] for item in request["inventory"]["files"]}
    challenge = {"kind": "positive", "fixture_path": raw["harness"]["path"]}
    if tamper == "config":
        raw["control_sha256"] = "0" * 64
    elif tamper == "harness":
        raw["harness"]["sha256"] = "0" * 64
    elif tamper == "input":
        raw["findings"][0]["input_sha256"] = "0" * 64
    elif tamper == "corpus":
        corpus = b"{}"
    elif tamper == "missing_positive":
        raw["findings"] = []
    elif tamper == "completion_missing":
        raw.pop("completed")
    elif tamper == "completion_type":
        raw["completed"] = 1
    elif tamper == "positive_incomplete":
        raw["completed"] = False
    else:
        challenge["kind"] = "negative"
    with pytest.raises(RuntimeAuditError):
        _atheris_challenge_report(
            canonical_bytes(raw), corpus, config, challenge, request["lane"], manifest
        )


@pytest.mark.parametrize("tamper", ["fixture", "config", "extra_command"])
def test_atheris_challenge_command_rejects_unbound_profile(tamper):
    from factoryline.deep_audit_io import _atheris_challenge_command

    profile = json.loads(Path("deploy/deep-adapters/profiles/atheris.json").read_text())
    command = _atheris_challenge_command(profile)
    assert (
        "{fixture}" in command["argv"]
        and "--factory-control={config}" in command["argv"]
    )
    if tamper == "extra_command":
        profile["commands"].append(deepcopy(command))
    elif tamper == "fixture":
        profile["commands"][0]["argv"][command["argv"].index("{fixture}")] = (
            "/unbound.py"
        )
    else:
        profile["commands"][0]["argv"].remove("--factory-control={config}")
    with pytest.raises(RuntimeAuditError):
        _atheris_challenge_command(profile)


def test_atheris_dispatcher_preserves_replay_gap_and_never_claims_coverage(
    tmp_path, monkeypatch
):
    from factoryline import deep_audit_io as module

    baseline = tmp_path / "fuzz-control.json"
    baseline.write_bytes(
        Path("deploy/deep-adapters/rules/fuzz-control.json").read_bytes()
    )
    profile = json.loads(Path("deploy/deep-adapters/profiles/atheris.json").read_text())
    lane = {
        "engine": "atheris",
        "family": "fuzz",
        "rule_ids": ["FUZZ_EXCEPTION"],
        "ruleset_sha256": sha256_bytes(baseline.read_bytes()),
        "timeout_seconds": 10,
    }
    challenges = [
        {
            "kind": kind,
            "fixture_path": "fuzz.py",
            "fixture_sha256": "a" * 64,
            "expected_exit_code": code,
        }
        for kind, code in [("positive", 77), ("negative", 0), ("mutation", 0)]
    ]
    contract = {
        "obligations": [
            {
                "id": "fuzz-rule",
                "engine": "atheris",
                "family": "fuzz",
                "challenges": challenges,
            }
        ]
    }
    monkeypatch.setattr(module, "local_file", lambda *_: baseline)
    calls = []

    def execute(*args):
        challenge = args[11]
        calls.append(challenge["kind"])
        blob = {"bytes": 1}
        return {
            "kind": challenge["kind"],
            "execution": {"status": "VERIFIED"},
            "atheris_native_evidence": {
                key: blob
                for key in ["raw_report", "corpus_manifest", "effective_config"]
            },
        }

    monkeypatch.setattr(module, "_run_atheris_challenge", execute)
    result, covered = module._atheris_challenges(
        profile, contract, tmp_path, lane, {}, time.monotonic()
    )
    assert calls == ["positive", "negative", "mutation"]
    assert len(result["observations"]) == 3 and covered == []
    assert {gap["reason"] for gap in result["gaps"]} == {
        "FUZZ_CHALLENGE_REPLAY_REQUIRED"
    }


@pytest.mark.parametrize("count", [65, 193])
def test_atheris_dispatcher_rejects_unbounded_obligations_before_execution(count):
    from factoryline.deep_audit_io import _atheris_challenges

    item = {
        "id": "fuzz-rule",
        "engine": "atheris",
        "family": "fuzz",
        "challenges": [
            {"kind": "positive", "fixture_path": "fuzz.py", "fixture_sha256": "a" * 64}
        ],
    }
    contract = {"obligations": [deepcopy(item) for _ in range(count)]}
    result, covered = _atheris_challenges(
        {}, contract, Path("."), {"family": "fuzz"}, {}, time.monotonic()
    )
    assert not result["observations"] and covered == []
    assert len(result["gaps"]) == count
    assert {gap["reason"] for gap in result["gaps"]} == {"E_FUZZ_CHALLENGE_BUDGET"}


def _native_zap_request_fixture():
    return {
        "schema": "factory.zap-native-request.v1",
        "run_id": "zap-native-test",
        "candidate_sha256": "a" * 64,
        "profile_sha256": "b" * 64,
        "rule_ids": ["40012"],
        "timeout_seconds": 120,
    }


def test_zap_native_request_binds_fixed_loopback_target():
    from factoryline.deep_audit_io import _zap_native_request

    request = _native_zap_request_fixture()
    result = _zap_native_request(request)
    assert result["host_id"] == sha256_bytes(b"http://127.0.0.1:8765")
    assert result["candidate_sha256"] == request["candidate_sha256"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other"),
        ("run_id", "../escape"),
        ("candidate_sha256", "x" * 64),
        ("profile_sha256", None),
        ("rule_ids", []),
        ("rule_ids", ["040012"]),
        ("rule_ids", ["40012", "40012"]),
        ("timeout_seconds", True),
        ("timeout_seconds", 0),
        ("target", "https://external.invalid"),
        ("passed", True),
    ],
)
def test_zap_native_request_rejects_unbound_inputs(field, value):
    from factoryline.deep_audit_io import _zap_native_request

    request = _native_zap_request_fixture()
    request[field] = value
    with pytest.raises(RuntimeAuditError):
        _zap_native_request(request)


def test_zap_native_inventory_requires_exact_unique_dispositions():
    from factoryline.deep_audit_io import _zap_enabled_inventory

    raw = {
        "scanners": [
            {"id": "40012", "enabled": "true"},
            {"id": "40013", "enabled": "false"},
        ]
    }
    assert _zap_enabled_inventory(raw) == ["40012"]
    raw["scanners"].append({"id": "40012", "enabled": "false"})
    with pytest.raises(RuntimeAuditError):
        _zap_enabled_inventory(raw)


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"scanners": []},
        {"scanners": [None]},
        {"scanners": [{"id": "40012", "enabled": True}]},
        {"scanners": [{"id": "40012", "enabled": "maybe"}]},
        {"scanners": [{"id": "../other", "enabled": "true"}]},
    ],
)
def test_zap_native_inventory_rejects_invalid_native_rows(raw):
    from factoryline.deep_audit_io import _zap_enabled_inventory

    with pytest.raises(RuntimeAuditError):
        _zap_enabled_inventory(raw)


def test_zap_native_environment_drops_operator_secrets(monkeypatch):
    from factoryline.deep_audit_io import _zap_daemon_environment, _zap_native_request

    monkeypatch.setenv("AI_GATEWAY_API_KEY", "must-not-propagate")
    monkeypatch.setenv("HTTP_PROXY", "http://external.invalid")
    env = _zap_daemon_environment(
        _zap_native_request(_native_zap_request_fixture()), "/tmp/zap"
    )
    assert "AI_GATEWAY_API_KEY" not in env and "HTTP_PROXY" not in env
    assert env["FACTORY_ZAP_LEDGER_ENABLED"] == "1"


def test_zap_native_api_rejects_unapproved_action_before_network():
    from factoryline.deep_audit_io import _zap_api

    with pytest.raises(RuntimeAuditError, match="E_ZAP_API"):
        _zap_api("core", "action", "shutdown", time.monotonic() + 10)


@pytest.mark.parametrize(
    "state,code",
    [
        ("overflow", "E_ZAP_OUTPUT"),
        ("deadline", "E_ZAP_TIMEOUT"),
        ("dead", "E_ZAP_PROCESS"),
    ],
)
def test_zap_daemon_watch_fails_closed_before_api_use(state, code, monkeypatch):
    import threading

    import factoryline.deep_audit_io as audit_io

    class Child:
        def poll(self):
            return 1 if state == "dead" else None

    overflow = threading.Event()
    if state == "overflow":
        overflow.set()
    deadline = time.monotonic() - 1 if state == "deadline" else time.monotonic() + 10
    watch = audit_io._zap_watch(Child(), deadline, overflow)
    monkeypatch.setattr(
        audit_io,
        "build_opener",
        lambda *_args, **_kwargs: pytest.fail("API request must not be opened"),
        raising=False,
    )

    with pytest.raises(RuntimeAuditError, match=code):
        audit_io._zap_api("core", "view", "version", deadline, watch=watch)


def test_zap_native_process_facts_include_bounded_stream_and_cleanup_evidence():
    import hashlib
    from types import SimpleNamespace

    from factoryline.deep_audit_io import _zap_process_facts

    class Child:
        pid = 321
        returncode = -9

        def poll(self):
            return self.returncode

    stdout = b"bounded daemon output"
    stderr = b""
    streams = {
        "stdout": (hashlib.sha256(stdout).hexdigest(), len(stdout)),
        "stderr": (hashlib.sha256(stderr).hexdigest(), len(stderr)),
    }
    child = Child()
    # The test double carries the lifecycle binding required for a positive receipt.
    child._factory_cleanup_unit = SimpleNamespace(kind="fixture", pid=child.pid)
    facts = _zap_process_facts(child, time.monotonic() - 0.1, streams, True, True)

    assert facts == {
        "pid": 321,
        "return_code": -9,
        "duration_ms": facts["duration_ms"],
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "termination_reason": "intentional_stop",
    }


def test_zap_daemon_stream_drain_sets_overflow_without_retaining_unbounded_output(
    monkeypatch,
):
    import io
    import threading

    import factoryline.runtime_audit_process as process

    monkeypatch.setattr(process, "MAX_OUTPUT", 32)

    class Child:
        stdout = io.BytesIO(b"x" * 33)
        stderr = io.BytesIO(b"y")

    overflow = threading.Event()
    streams = {}
    readers = process._start_stream_readers(Child(), overflow, streams)
    for reader in readers:
        reader.join(timeout=1)

    assert not any(reader.is_alive() for reader in readers)
    assert overflow.is_set()
    assert streams["stdout"][1] == 33
    assert streams["stderr"][1] == 1


def test_zap_native_inventory_accounts_for_core_rule_zero():
    from factoryline.deep_audit_io import _zap_enabled_inventory

    rows = {
        "scanners": [
            {"id": "0", "enabled": "false"},
            {"id": "40012", "enabled": "true"},
        ]
    }
    assert _zap_enabled_inventory(rows) == ["40012"]
    rows["scanners"][0]["enabled"] = "true"
    assert _zap_enabled_inventory(rows) == ["0", "40012"]


@pytest.mark.parametrize(
    "endpoint,arguments",
    [
        (
            ("core", "action", "accessUrl"),
            {"url": "https://external.invalid", "followRedirects": "false"},
        ),
        (
            ("core", "action", "accessUrl"),
            {"url": "http://127.0.0.1:8765/?input=seed", "followRedirects": "true"},
        ),
        (
            ("ascan", "action", "scan"),
            {
                "url": "http://127.0.0.1:8765/?input=seed",
                "recurse": "true",
                "inScopeOnly": "false",
            },
        ),
        (("core", "view", "alerts"), {"baseurl": "http://127.0.0.1:9999"}),
        (("ascan", "view", "status"), {"scanId": "../../escape"}),
        (("ascan", "action", "enableScanners"), {"ids": "40012,40012"}),
        (("core", "view", "version"), {"url": "https://external.invalid"}),
    ],
)
def test_zap_native_api_rejects_target_and_scope_drift(endpoint, arguments):
    from factoryline.deep_audit_io import _zap_api_arguments

    with pytest.raises(RuntimeAuditError):
        _zap_api_arguments(*endpoint, arguments)


def _native_zap_v2_fixture():
    from factoryline.deep_audit_io import digest

    source_sha = "c" * 64
    target = {
        "schema": "factory.zap-target.v1",
        "image": "sha256:" + "d" * 64,
        "argv": ["/app/server"],
        "port": 8765,
        "readiness_path": "/health",
        "routes": [
            {
                "id": "health_query",
                "method": "GET",
                "path": "/lookup",
                "query": {"input": "seed"},
                "source_bindings": {"app.py": source_sha},
            }
        ],
    }
    lane = {
        "engine": "zap",
        "timeout_seconds": 120,
        "rule_ids": ["40012"],
        "native_target": target,
    }
    inventory = {
        "candidate_sha256": "a" * 64,
        "files": [{"path": "app.py", "sha256": source_sha}],
    }
    contract = {
        "schema": "factory.deep-adapter-input.v1",
        "run_id": "e" * 32,
        "manifest_sha256": "f" * 64,
        "inventory": inventory,
        "lane": lane,
        "obligations": [],
    }
    request = {
        "schema": "factory.zap-native-request.v2",
        "run_id": contract["run_id"],
        "candidate_sha256": inventory["candidate_sha256"],
        "profile_sha256": digest(lane),
        "rule_ids": lane["rule_ids"],
        "timeout_seconds": 90,
        "target": deepcopy(target),
        "route_id": "health_query",
    }
    return request, contract


def test_zap_native_v2_request_binds_target_route_inventory_and_profile():
    from factoryline.deep_audit_io import _zap_native_v2_context, digest

    request, contract = _native_zap_v2_fixture()
    result = _zap_native_v2_context(request, contract)

    assert result["target_url"] == "http://factory-target:8765/lookup?input=seed"
    assert result["base_url"] == "http://factory-target:8765"
    assert result["route_id"] == "health_query"
    assert result["target_sha256"] == digest(request["target"])
    assert result["route_sha256"] == digest(request["target"]["routes"][0])
    assert result["bindings"]["host_id"] == sha256_bytes(result["base_url"].encode())
    assert result["bindings"]["profile_sha256"] == request["profile_sha256"]
    assert "disabled_rule_id" not in request
    assert result["disabled_rule_id"] is None


def test_zap_native_v2_disabled_control_requires_signed_exact_policy():
    from factoryline.deep_audit_io import _zap_native_v2_context, digest

    request, contract = _native_zap_v2_fixture()
    disabled = request["rule_ids"][0]
    policy = {
        "schema": "factory.zap-disabled-policy.v1",
        "rule_ids": request["rule_ids"],
        "disabled_rule_id": disabled,
    }
    contract["lane"]["mutation_config_sha256"] = {disabled: digest(policy)}
    request["profile_sha256"] = digest(contract["lane"])
    request["disabled_rule_id"] = disabled

    result = _zap_native_v2_context(request, contract)

    assert result["disabled_rule_id"] == disabled
    assert request["rule_ids"] == contract["lane"]["rule_ids"]

    contract["lane"]["mutation_config_sha256"][disabled] = "0" * 64
    request["profile_sha256"] = digest(contract["lane"])
    with pytest.raises(RuntimeAuditError, match="E_ZAP_MUTATION"):
        _zap_native_v2_context(request, contract)


def test_zap_rule_selection_supports_exact_zero_enabled_control(monkeypatch):
    import factoryline.deep_audit_io as audit_io

    calls = []

    def fake_api(component, kind, name, _deadline, *, watch=None, **kwargs):
        calls.append((component, kind, name, kwargs))
        if name == "scanners":
            return {"scanners": [{"id": "40012", "enabled": "false"}]}
        return {}

    monkeypatch.setattr(audit_io, "_zap_api", fake_api)
    raw = audit_io._zap_select_rules(["40012"], time.monotonic() + 10, {}, "40012")

    assert raw == {"scanners": [{"id": "40012", "enabled": "false"}]}
    assert [call[2] for call in calls] == ["disableAllScanners", "scanners"]


def test_zap_passive_scan_wait_requires_stable_zero_and_resets_on_pending(
    monkeypatch,
):
    import factoryline.deep_audit_io as audit_io

    values = iter(["2", "0", "1", "0", "0"])
    calls = []
    sleeps = []
    monkeypatch.setattr(audit_io, "_zap_check_daemon", lambda *_args: None)

    def api(component, kind, name, _deadline, *, watch=None, **kwargs):
        calls.append((component, kind, name))
        return {"recordsToScan": next(values)}

    monkeypatch.setattr(audit_io, "_zap_api", api)
    monkeypatch.setattr(audit_io.time, "sleep", sleeps.append)
    result = audit_io._zap_wait_passive_scan(object(), time.monotonic() + 10, {})

    assert result == {"recordsToScan": "0"}
    assert calls == [("pscan", "view", "recordsToScan")] * 5
    assert sleeps == [0.2] * 4


@pytest.mark.parametrize(
    "response",
    [
        {"recordsToScan": 0},
        {"recordsToScan": ""},
        {"recordsToScan": "01"},
        {"recordsToScan": "-1"},
        {"recordsToScan": "0", "extra": "0"},
        [],
    ],
)
def test_zap_passive_scan_rejects_malformed_queue_counts(monkeypatch, response):
    import factoryline.deep_audit_io as audit_io

    monkeypatch.setattr(audit_io, "_zap_check_daemon", lambda *_args: None)
    monkeypatch.setattr(audit_io, "_zap_api", lambda *_args, **_kwargs: response)
    with pytest.raises(RuntimeAuditError, match="E_ZAP_PASSIVE"):
        audit_io._zap_wait_passive_scan(object(), time.monotonic() + 10, {})


def test_zap_passive_scan_wait_fails_when_deadline_is_exhausted():
    import threading
    import factoryline.deep_audit_io as audit_io

    class Child:
        def poll(self):
            return None

    child = Child()
    watch = {
        "child": child,
        "deadline": time.monotonic() - 1,
        "overflow": threading.Event(),
    }
    with pytest.raises(RuntimeAuditError, match="E_ZAP_TIMEOUT"):
        audit_io._zap_wait_passive_scan(child, watch["deadline"], watch)


@pytest.mark.parametrize("ledger_state", ["absent", "empty"])
def test_zap_measurement_marks_zero_enabled_as_disabled_control_without_ledger(
    monkeypatch, ledger_state
):
    import factoryline.deep_audit_io as audit_io

    class LedgerPath:
        def __init__(self, value):
            assert value == "/out"

        def __truediv__(self, _name):
            return self

        def lstat(self):
            if ledger_state == "absent":
                raise FileNotFoundError
            return object()

    monkeypatch.setattr(audit_io, "Path", LedgerPath)
    monkeypatch.setattr(
        audit_io, "_zap_wait_ready", lambda *_args: {"version": "2.17.0"}
    )
    monkeypatch.setattr(audit_io, "_zap_start_scan", lambda *_args: ("1", {}))
    monkeypatch.setattr(audit_io, "_zap_wait_scan", lambda *_args: {"status": "100"})
    monkeypatch.setattr(audit_io, "_zap_check_daemon", lambda *_args: None)

    def fake_api(component, kind, name, _deadline, *, watch=None, **_kwargs):
        if (component, kind, name) == ("ascan", "view", "scanners"):
            return {"scanners": [{"id": "40012", "enabled": "false"}]}
        if (component, kind, name) == ("pscan", "view", "recordsToScan"):
            return {"recordsToScan": "0"}
        if (component, kind, name) == ("core", "view", "alerts"):
            return {"alerts": []}
        return {}

    monkeypatch.setattr(audit_io, "_zap_api", fake_api)
    retained = []

    def retained_ledger(path):
        retained.append(path)
        return b"" if ledger_state == "empty" else b"nonempty"

    monkeypatch.setattr(audit_io, "_zap_retained_ledger", retained_ledger)
    request = {"rule_ids": ["40012"]}
    watch = {"disabled_rule_id": "40012"}
    result = audit_io._zap_measure_scan(
        request,
        {
            "run_id": "run",
            "candidate_sha256": "a" * 64,
            "profile_sha256": "b" * 64,
            "host_id": "c" * 64,
        },
        object(),
        time.monotonic() + 10,
        watch,
    )

    assert result["native_ledger"] == ""
    assert result["native_verification"] == {
        "state": "DISABLED_CONTROL",
        "expected_rule_ids": [],
        "disabled_rule_id": "40012",
    }
    assert result["disabled_rule_id"] == "40012"
    assert bool(retained) is (ledger_state == "empty")


def test_zap_zero_enabled_control_rejects_nonempty_or_unsafe_ledger(monkeypatch):
    import factoryline.deep_audit_io as audit_io

    class PresentLedgerPath:
        def __init__(self, value):
            assert value == "/out"

        def __truediv__(self, _name):
            return self

        def lstat(self):
            return object()

    def prepare(state):
        monkeypatch.setattr(audit_io, "Path", PresentLedgerPath)
        monkeypatch.setattr(
            audit_io, "_zap_wait_ready", lambda *_args: {"version": "2.17.0"}
        )
        monkeypatch.setattr(audit_io, "_zap_start_scan", lambda *_args: ("1", {}))
        monkeypatch.setattr(
            audit_io, "_zap_wait_scan", lambda *_args: {"status": "100"}
        )
        monkeypatch.setattr(audit_io, "_zap_check_daemon", lambda *_args: None)

        def fake_api(component, kind, name, _deadline, *, watch=None, **_kwargs):
            return {
                ("ascan", "view", "scanners"): {
                    "scanners": [{"id": "40012", "enabled": "false"}]
                },
                ("pscan", "view", "recordsToScan"): {"recordsToScan": "0"},
                ("core", "view", "alerts"): {"alerts": []},
            }.get((component, kind, name), {})

        monkeypatch.setattr(audit_io, "_zap_api", fake_api)
        if state == "unsafe":

            def read_unsafe(_path):
                raise RuntimeAuditError("E_PATH_ESCAPE", "symlink rejected")

            monkeypatch.setattr(audit_io, "_zap_retained_ledger", read_unsafe)
        else:
            monkeypatch.setattr(
                audit_io, "_zap_retained_ledger", lambda _path: b"row\n"
            )

    for state, expected in (("nonempty", "E_ZAP_LEDGER"), ("unsafe", "E_PATH_ESCAPE")):
        prepare(state)
        with pytest.raises(RuntimeAuditError, match=expected):
            audit_io._zap_measure_scan(
                {"rule_ids": ["40012"]},
                {
                    "run_id": "run",
                    "candidate_sha256": "a" * 64,
                    "profile_sha256": "b" * 64,
                    "host_id": "c" * 64,
                },
                object(),
                time.monotonic() + 10,
                {"disabled_rule_id": "40012"},
            )


def test_zap_native_v2_api_watch_rejects_rewritten_target_before_network():
    import threading

    from factoryline.deep_audit_io import _zap_api, _zap_native_v2_context, _zap_watch

    request, contract = _native_zap_v2_fixture()
    context = _zap_native_v2_context(request, contract)

    class Child:
        def poll(self):
            return None

    watch = _zap_watch(Child(), time.monotonic() + 10, threading.Event(), context)
    watch.update(context)
    watch["target_url"] = "http://127.0.0.1:8765/unsafe"
    with pytest.raises(RuntimeAuditError, match="E_ZAP_TARGET"):
        _zap_api("core", "action", "accessUrl", watch["deadline"], watch=watch)


@pytest.mark.parametrize(
    "expected_base",
    [
        "http://127.0.0.1:8765",
        "http://factory-target:8765",
    ],
)
def test_zap_measurement_alerts_api_uses_worker_contract_origin(
    expected_base, monkeypatch
):
    import factoryline.deep_audit_io as audit_io

    captured = {}
    monkeypatch.setattr(
        audit_io,
        "_zap_wait_ready",
        lambda *_args: {"version": "2.17.0"},
    )
    monkeypatch.setattr(
        audit_io,
        "_zap_select_rules",
        lambda *_args: {"scanners": [{"id": "40012", "enabled": "true"}]},
    )
    monkeypatch.setattr(
        audit_io,
        "_zap_start_scan",
        lambda *_args: ("1", {"accessed": "ok"}),
    )
    monkeypatch.setattr(audit_io, "_zap_wait_scan", lambda *_args: {"status": "100"})

    def fake_api(component, kind, name, _deadline, *, watch=None, **kwargs):
        if (component, kind, name) == ("core", "view", "alerts"):
            captured.update(kwargs)
            return {"alerts": []}
        if (component, kind, name) == ("pscan", "view", "recordsToScan"):
            return {"recordsToScan": "0"}
        return {"scanners": [{"id": "40012", "enabled": "true"}]}

    monkeypatch.setattr(audit_io, "_zap_api", fake_api)
    monkeypatch.setattr(audit_io, "_zap_enabled_inventory", lambda _raw: ["40012"])
    monkeypatch.setattr(audit_io, "_zap_retained_ledger", lambda _path: b"{}\n")
    monkeypatch.setattr(
        "factoryline.deep_audit_sarif._verify_zap_native_rule_ledger",
        lambda *_args: {"state": "VERIFIED"},
    )
    monkeypatch.setattr(audit_io, "_zap_check_daemon", lambda *_args: None)
    watch = {
        "base_url": expected_base,
        "target_url": "http://127.0.0.1:8765/?input=seed",
    }
    request = {"rule_ids": ["40012"]}
    bindings = {
        "run_id": "run-123",
        "candidate_sha256": "a" * 64,
        "profile_sha256": "b" * 64,
        "host_id": "c" * 64,
    }

    audit_io._zap_measure_scan(
        request, bindings, object(), time.monotonic() + 20, watch
    )

    assert captured["baseurl"] == expected_base


def test_native_zap_cli_rejects_operator_selected_request_path(capsys):
    from factoryline.deep_audit_io import adapter_main

    assert adapter_main(["native-zap", "--request", "/tmp/untrusted.json"]) == 2
    assert capsys.readouterr().err.strip() == "E_ZAP_REQUEST"


def test_zap_native_driver_rejects_non_object_request_before_dispatch():
    from factoryline.deep_audit_io import _run_zap_native_scan

    with pytest.raises(RuntimeAuditError, match="E_ZAP_REQUEST"):
        _run_zap_native_scan([])


@pytest.mark.parametrize(
    "mutation",
    [
        "source_binding",
        "route_id",
        "candidate",
        "profile",
        "rules",
        "timeout",
        "target_url",
    ],
)
def test_zap_native_v2_request_rejects_target_or_binding_drift(mutation):
    from factoryline.deep_audit_io import _zap_native_v2_context

    request, contract = _native_zap_v2_fixture()
    if mutation == "source_binding":
        request["target"]["routes"][0]["source_bindings"]["app.py"] = "0" * 64
        contract["lane"]["native_target"] = deepcopy(request["target"])
    elif mutation == "route_id":
        request["route_id"] = "other"
    elif mutation == "candidate":
        request["candidate_sha256"] = "0" * 64
    elif mutation == "profile":
        request["profile_sha256"] = "0" * 64
    elif mutation == "rules":
        request["rule_ids"] = ["40013"]
    elif mutation == "timeout":
        request["timeout_seconds"] = 121
    else:
        request["target"]["routes"][0]["path"] = "https://external.invalid/"
        contract["lane"]["native_target"] = deepcopy(request["target"])

    with pytest.raises(RuntimeAuditError):
        _zap_native_v2_context(request, contract)


def _osv_lookup_execution_fixture():
    from factoryline.deep_audit_io import digest

    report = _osv_package_accounting_fixture()
    report["factory_lookup_execution"] = {
        "schema": "factory.osv-lookup-execution.v1",
        "upstream_commit": "a14aa98ab8408547083d4411091c5fbaf5b47d8e",
        "database_sha256": "c" * 64,
        "catalog_advisories": 120,
        "catalog_sha256": "d" * 64,
        "extractor_runs": [
            {
                "plugins": ["python/requirements"],
                "statuses": [{"name": "python/requirements", "state": "SUCCEEDED"}],
            }
        ],
        "queries": [
            {
                "name": "werkzeug",
                "version": "0.1",
                "ecosystem": "PyPI",
                "locations": ["requirements.txt"],
                "state": "EXECUTED",
                "evaluated_advisories": 120,
                "evaluated_sha256": "d" * 64,
                "decision_sha256": "e" * 64,
                "matched_advisories": [],
            }
        ],
    }
    query = report["factory_lookup_execution"]["queries"][0]
    query["decision_sha256"] = digest(
        {
            **{
                key: query[key]
                for key in (
                    "name",
                    "version",
                    "ecosystem",
                    "evaluated_advisories",
                    "matched_advisories",
                )
            },
            "catalog_sha256": report["factory_lookup_execution"]["catalog_sha256"],
        }
    )
    return report


def test_osv_native_lookup_zero_match_is_explicit_and_source_bound():
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_lookup_execution_fixture()
    report["results"][0]["packages"] *= 2  # Repeated package rows are legal.
    observed = _osv_source_accounting(
        report, {"requirements.txt": "a" * 64}, "offline-pypi-snapshot"
    )
    ledger = observed["lookup_execution"]
    assert ledger["queries"][0]["evaluated_advisories"] == 120
    assert ledger["queries"][0]["matched_advisories"] == []
    assert ledger["source_sha256"] == {"requirements.txt": "a" * 64}
    changed = _osv_source_accounting(
        report, {"requirements.txt": "b" * 64}, "offline-pypi-snapshot"
    )
    assert changed["lookup_execution"]["source_sha256"] != ledger["source_sha256"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "FAILED"),
        ("state", "NOT_RUN"),
        ("evaluated_advisories", 119),
        ("evaluated_advisories", True),
        ("evaluated_sha256", "f" * 64),
        ("decision_sha256", "invalid"),
        ("locations", []),
        ("locations", ["unbound.txt"]),
        ("locations", ["requirements.txt", "requirements.txt"]),
        ("matched_advisories", ["CVE-unreported"]),
        ("name", "other"),
    ],
)
def test_osv_native_lookup_rejects_missing_failed_or_contradictory_query(field, value):
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_lookup_execution_fixture()
    report["factory_lookup_execution"]["queries"][0][field] = value
    with pytest.raises(RuntimeAuditError):
        _osv_source_accounting(
            report, {"requirements.txt": "a" * 64}, "offline-pypi-snapshot"
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("queries", []),
        ("catalog_advisories", 0),
        ("catalog_advisories", True),
        ("catalog_sha256", "invalid"),
        ("database_sha256", "invalid"),
        ("upstream_commit", "f" * 40),
        ("schema", "unknown"),
        ("extractor_runs", []),
        ("extractor_runs", [{"plugins": ["python/requirements"], "statuses": []}]),
        (
            "extractor_runs",
            [
                {
                    "plugins": ["python/requirements"],
                    "statuses": [{"name": "python/requirements", "state": "PARTIAL"}],
                }
            ],
        ),
    ],
)
def test_osv_native_lookup_rejects_empty_or_incomplete_execution(field, value):
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_lookup_execution_fixture()
    report["factory_lookup_execution"][field] = value
    with pytest.raises(RuntimeAuditError):
        _osv_source_accounting(
            report, {"requirements.txt": "a" * 64}, "offline-pypi-snapshot"
        )


def test_osv_native_lookup_rejects_duplicate_and_omitted_queries():
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_lookup_execution_fixture()
    report["factory_lookup_execution"]["queries"] *= 2
    with pytest.raises(RuntimeAuditError, match="duplicate native"):
        _osv_source_accounting(
            report, {"requirements.txt": "a" * 64}, "offline-pypi-snapshot"
        )
    report = _osv_lookup_execution_fixture()
    report["results"][0]["packages"].append(
        {
            "package": {"name": "other", "version": "1", "ecosystem": "PyPI"},
            "vulnerabilities": [],
        }
    )
    with pytest.raises(RuntimeAuditError, match="not all executed"):
        _osv_source_accounting(
            report, {"requirements.txt": "a" * 64}, "offline-pypi-snapshot"
        )


def test_osv_native_lookup_database_and_missing_evidence_remain_gaps():
    from factoryline.deep_audit_sarif import _osv_lookup_binding_gaps

    report = _osv_lookup_execution_fixture()
    lane = {"native_policy": {"database_sha256": "c" * 64}}
    assert _osv_lookup_binding_gaps(report, lane) == []
    lane["native_policy"]["database_sha256"] = "f" * 64
    assert _osv_lookup_binding_gaps(report, lane) == [
        "OSV_NATIVE_LOOKUP_DATABASE_DRIFT"
    ]
    assert _osv_lookup_binding_gaps({}, lane) == ["OSV_NATIVE_LOOKUPS_REQUIRED"]


def test_osv_native_lookup_paths_normalize_primary_and_retained_reports():
    from copy import deepcopy
    from factoryline.deep_audit_io import (
        _native_dependency_paths,
        _osv_normalize_retained_paths,
    )

    report = _osv_lookup_execution_fixture()
    report["results"][0]["source"]["path"] = "/src/requirements.txt"
    report["factory_lookup_execution"]["queries"][0]["locations"] = [
        "/src/requirements.txt"
    ]
    retained = deepcopy(report)
    sources = {"requirements.txt": "a" * 64}
    _native_dependency_paths(report, "osv-json", sources)
    _osv_normalize_retained_paths(retained, "/src", sources)
    assert retained == report
    assert report["factory_lookup_execution"]["queries"][0]["locations"] == [
        "requirements.txt"
    ]


@pytest.mark.parametrize("change", ["decision", "missing", "database"])
def test_osv_fresh_replay_requires_independent_lookup_evidence(
    tmp_path, monkeypatch, change
):
    import time
    from copy import deepcopy
    import factoryline.deep_audit_io as module
    from factoryline.deep_audit_sarif import _osv_source_accounting

    request = _osv_replay_request_fixture()
    report = _osv_lookup_execution_fixture()
    required = {"requirements.txt": "a" * 64}
    request["report"] = report
    request["coverage"]["source_accounting"] = _osv_source_accounting(
        report, required, "offline-pypi-snapshot"
    )
    fresh = deepcopy(report)
    if change == "decision":
        fresh["factory_lookup_execution"]["queries"][0]["decision_sha256"] = "f" * 64
    elif change == "database":
        fresh["factory_lookup_execution"]["database_sha256"] = "f" * 64
    else:
        del fresh["factory_lookup_execution"]
    monkeypatch.setattr(module, "_osv_database_identity", lambda *args: {})
    monkeypatch.setattr(
        module, "_adapter_output_paths", lambda *args, **kwargs: ["report.json"]
    )
    monkeypatch.setattr(
        module,
        "_run_native_profile",
        lambda *args: {"raw_report": fresh, "invocations": []},
    )
    monkeypatch.setattr(module, "_native_report", lambda raw, *args: raw)
    with pytest.raises(
        RuntimeAuditError, match="decision hash|independent source accounting differs"
    ):
        module._osv_replay_primary(
            request,
            {},
            tmp_path,
            tmp_path,
            request["lane"],
            request["inventory"],
            required,
            time.monotonic() + 60,
        )


@pytest.mark.parametrize("value", [[], 1, "ledger"])
def test_osv_present_malformed_lookup_ledger_never_becomes_missing(value):
    from factoryline.deep_audit_sarif import _osv_lookup_binding_gaps

    with pytest.raises(RuntimeAuditError):
        _osv_lookup_binding_gaps({"factory_lookup_execution": value}, {})


def test_osv_native_lookup_reported_match_must_have_native_match_evidence():
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_lookup_execution_fixture()
    report["results"][0]["packages"][0]["vulnerabilities"] = [{"id": "CVE-2026-1234"}]
    required = {"requirements.txt": "a" * 64}
    with pytest.raises(RuntimeAuditError, match="decisions"):
        _osv_source_accounting(report, required, "offline-pypi-snapshot")
    report["factory_lookup_execution"]["queries"][0]["matched_advisories"] = [
        "CVE-2026-1234"
    ]
    from factoryline.deep_audit_io import digest

    query = report["factory_lookup_execution"]["queries"][0]
    query["decision_sha256"] = digest(
        {
            **{
                key: query[key]
                for key in (
                    "name",
                    "version",
                    "ecosystem",
                    "evaluated_advisories",
                    "matched_advisories",
                )
            },
            "catalog_sha256": report["factory_lookup_execution"]["catalog_sha256"],
        }
    )
    result = _osv_source_accounting(report, required, "offline-pypi-snapshot")
    assert result["lookup_execution"]["queries"][0]["matched_advisories"] == [
        "CVE-2026-1234"
    ]


def test_osv_complete_manifest_claim_cannot_bypass_lookup_execution_gate():
    from factoryline.deep_audit_io import digest
    from factoryline.deep_audit_sarif import (
        _coverage_source_gaps,
        _osv_source_accounting,
    )

    report = _osv_package_accounting_fixture()
    required = {"requirements.txt": "a" * 64}
    lane = {
        "engine": "osv",
        "mode": "offline-pypi-snapshot",
        "native_policy": {"database_sha256": "c" * 64},
    }
    coverage = {
        "schema": "factory.deep-coverage.v1",
        "sources": required,
        "complete": True,
        "errors": [],
        "mode": lane["mode"],
        "fallback": False,
        "report_sha256": digest(report),
        "source_accounting": _osv_source_accounting(report, required, lane["mode"]),
    }
    assert _coverage_source_gaps(report, coverage, lane, required) == [
        "OSV_NATIVE_LOOKUPS_REQUIRED"
    ]
    report = _osv_lookup_execution_fixture()
    coverage.update(
        report_sha256=digest(report),
        source_accounting=_osv_source_accounting(report, required, lane["mode"]),
    )
    assert _coverage_source_gaps(report, coverage, lane, required) == []
    lane["native_policy"]["database_sha256"] = "f" * 64
    assert _coverage_source_gaps(report, coverage, lane, required) == [
        "OSV_NATIVE_LOOKUP_DATABASE_DRIFT"
    ]


@pytest.mark.parametrize(
    "locations",
    [
        ["file:///src/requirements.txt"],
        ["/outside/requirements.txt"],
        ["/src/../requirements.txt"],
        ["/src/requirements.txt", "requirements.txt"],
    ],
)
def test_osv_lookup_path_aliases_cannot_hide_unbound_or_duplicate_sources(locations):
    from factoryline.deep_audit_io import _osv_normalize_retained_paths
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_lookup_execution_fixture()
    report["factory_lookup_execution"]["queries"][0]["locations"] = locations
    required = {"requirements.txt": "a" * 64}
    if locations == ["file:///src/requirements.txt"]:
        result = _osv_normalize_retained_paths(report, "/src", required)
        assert result["factory_lookup_execution"]["queries"][0]["locations"] == [
            "requirements.txt"
        ]
        assert (
            _osv_source_accounting(result, required, "offline-pypi-snapshot")["state"]
            == "COMPLETE"
        )
    else:
        with pytest.raises(RuntimeAuditError):
            result = _osv_normalize_retained_paths(report, "/src", required)
            _osv_source_accounting(result, required, "offline-pypi-snapshot")


def test_osv_native_lookup_budgets_reject_oversized_query_inventory():
    from factoryline.deep_audit_sarif import _osv_source_accounting

    report = _osv_lookup_execution_fixture()
    report["factory_lookup_execution"]["queries"] *= 20_001
    with pytest.raises(RuntimeAuditError):
        _osv_source_accounting(
            report, {"requirements.txt": "a" * 64}, "offline-pypi-snapshot"
        )


def test_deep_audit_io_moved_exports_keep_monkeypatch_seams(monkeypatch, tmp_path):
    import factoryline.deep_audit as audit
    import factoryline.deep_audit_attestation as attestation
    import factoryline.deep_audit_contract as contract
    import factoryline.deep_audit_io as audit_io
    import factoryline.deep_audit_loop as loop
    import factoryline.deep_audit_sarif as sarif

    assert audit_io._adapter_invocation is contract._adapter_invocation
    assert audit_io._native_sarif_metadata is sarif._native_sarif_metadata
    assert (
        audit_io.verify_codeql_retained_evidence
        is attestation.verify_codeql_retained_evidence
    )
    assert audit_io.execute_fuzz_native_replay is loop.execute_fuzz_native_replay
    assert audit_io._run_zap_native_scan is audit._run_zap_native_scan

    monkeypatch.setattr(audit_io, "digest", lambda _value: "patched-digest")
    facts = {
        "timed_out": False,
        "launch_error": False,
        "output_limit_exceeded": False,
        "cleanup_confirmed": True,
        "exit_code": 0,
    }
    invocation = contract._adapter_invocation(
        lambda *_args, **_kwargs: facts,
        {"argv": ["scanner"], "accepted_exit_codes": [0]},
        {"engine": "other", "tool_version": "1"},
        tmp_path,
        tmp_path,
        1,
        time.monotonic() + 10,
    )
    assert invocation["argv_sha256"] == "patched-digest"

    report = {"runs": [{"tool": {"driver": {"version": "1"}}}]}
    enriched = sarif._native_sarif_metadata(report, {"tool_version": "1"}, [])
    assert (
        enriched["runs"][0]["invocations"][0]["properties"]["factory_execution_sha256"]
        == "patched-digest"
    )

    monkeypatch.setattr(audit_io.time, "monotonic", lambda: 2)
    assert loop._codeql_replay_remaining(10) == 8

    def stop_at_challenge(_request):
        raise LookupError("challenge seam")

    monkeypatch.setattr(audit_io, "_fuzz_replay_control_evidence", stop_at_challenge)
    with pytest.raises(LookupError, match="challenge seam"):
        loop.execute_fuzz_native_replay({}, tmp_path, tmp_path, 1)

    monkeypatch.setattr(audit_io, "_zap_native_request", stop_at_challenge)
    with pytest.raises(LookupError, match="challenge seam"):
        audit._run_zap_native_scan({})

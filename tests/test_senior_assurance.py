import hashlib
import json
import sys
import pytest
from factoryline.senior_assurance import (
    ActivationHookRegistry,
    INCIDENT_TRIAGE_SCHEMA,
    ACTIVATION_EXPERIMENT_SCHEMA,
    REPAIR_SCHEMA,
    REUSE_REQUEST_SCHEMA,
    SeniorAssuranceError,
    compare_repair,
    explain_evidence_reuse,
    failure_brief,
    load_assurance_json,
    run_replay,
    run_activation_experiment,
    triage_incident_events,
    validate_replay_manifest,
)
from factoryline.benchmark_lab import SCHEMA as BENCHMARK_SCHEMA
from factoryline.cli import main
from factoryline.incremental_scheduler import SCHEMA as SCHEDULE_SCHEMA
from factoryline.benchmark_lab import load_benchmark_json
from factoryline.incremental_scheduler import load_schedule_json
from pathlib import Path
from factoryline.graph_ops import graph_ops_snapshot
from factoryline.incremental_scheduler import plan_incremental
from factoryline.runtime_attestation import capture_supervised_attestation
from factoryline.senior_engineering import senior_engineering_projection


def _sha_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _tree_sha(path):
    rows = []
    for item in sorted(path.rglob("*")):
        if item.is_file():
            rows.append(
                {
                    "path": item.relative_to(path).as_posix(),
                    "sha256": _sha_bytes(item.read_bytes()),
                    "size": item.stat().st_size,
                }
            )
    return _sha_bytes(_canonical(rows))


def _digest_file(path) -> str:
    return _sha_bytes(path.read_bytes())


def _replay(
    root,
    name,
    exit_code,
    contract,
    *,
    script="import sys; print('receipt'); sys.exit(%d)" % 0,
):
    source = root / name
    source.mkdir()
    (source / "run.py").write_text(script, encoding="utf-8")
    policy = root / f"{name}-policy.json"
    dependencies = root / f"{name}-dependencies.lock"
    policy.write_text('{"policy":"approved"}', encoding="utf-8")
    dependencies.write_text("dependency==1", encoding="utf-8")
    return {
        "schema": "factory.replay-manifest.v1",
        "replay_id": f"{name}-replay",
        "source_root": name,
        "source_sha256": _tree_sha(source),
        "dependencies_sha256": {
            "path": dependencies.name,
            "sha256": _digest_file(dependencies),
        },
        "policy_sha256": {"path": policy.name, "sha256": _digest_file(policy)},
        "input_files": [],
        "argv": [sys.executable, "run.py"],
        "env": {"PYTHONIOENCODING": "utf-8"},
        "expected_exit": exit_code,
        "timeout_seconds": 10,
        "max_output_bytes": 4096,
        "contract_sha256": contract,
    }


def test_replay_runs_fresh_workspace_without_inheriting_secrets(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = _replay(
        tmp_path,
        "candidate",
        1,
        contract,
        script="import sys; print('failure'); sys.exit(1)",
    )
    receipt = run_replay(tmp_path, manifest, execute=True)
    assert receipt["state"] == "PASS"
    assert receipt["observed_exit"] == 1
    assert receipt["cleanup"] is True
    assert receipt["authority"] == "none"
    assert "SECRET" not in receipt["stdout_preview"]


def test_replay_validation_and_bounded_json_loader_are_exercised(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = _replay(tmp_path, "candidate", 0, contract)
    normalized = validate_replay_manifest(tmp_path, manifest)
    assert normalized["replay_id"] == "candidate-replay"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(_canonical(manifest))
    assert load_assurance_json(manifest_path)["schema"] == "factory.replay-manifest.v1"


def test_replay_rejects_secret_environment_and_source_drift(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = _replay(tmp_path, "candidate", 0, contract)
    manifest["env"] = {"API_TOKEN": "do-not-accept"}
    with pytest.raises(SeniorAssuranceError) as error:
        run_replay(tmp_path, manifest)
    assert error.value.code == "E_REPLAY_SECRET"


def test_repair_comparison_requires_original_failure_and_negative_controls(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = {
        "schema": REPAIR_SCHEMA,
        "comparison_id": "repair-1",
        "contract_sha256": contract,
        "buggy": _replay(
            tmp_path, "buggy", 1, contract, script="import sys; sys.exit(1)"
        ),
        "fixed": _replay(
            tmp_path, "fixed", 0, contract, script="import sys; sys.exit(0)"
        ),
        "negative_controls": [
            _replay(tmp_path, "control", 1, contract, script="import sys; sys.exit(1)")
        ],
    }
    receipt = compare_repair(tmp_path, manifest, execute=True)
    assert receipt["state"] == "PASS"
    assert receipt["regression_checks"] == {
        "original_fails": True,
        "repaired_passes": True,
        "negative_controls_fail": True,
    }


def test_repair_blocks_unreviewed_expectation_change(tmp_path):
    contract = _sha_bytes(b"contract")
    manifest = {
        "schema": REPAIR_SCHEMA,
        "comparison_id": "repair-2",
        "contract_sha256": contract,
        "buggy": _replay(tmp_path, "buggy", 1, contract),
        "fixed": _replay(
            tmp_path, "fixed", 0, contract, script="import sys; sys.exit(0)"
        ),
        "negative_controls": [_replay(tmp_path, "control", 1, contract)],
        "expectations_changed": True,
    }
    with pytest.raises(SeniorAssuranceError) as error:
        compare_repair(tmp_path, manifest)
    assert error.value.code == "E_EXPECTATION_REVIEW_REQUIRED"


def test_reuse_explains_exact_match_and_unknown_policy_dependency(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {
        "schema": REUSE_REQUEST_SCHEMA,
        "request_id": "r1",
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "gates": [
            {
                "id": "lint",
                "read_only": True,
                "side_effects": False,
                "receipt_path": "proof.json",
                "receipt_sha256": _sha_bytes(receipt_path.read_bytes()),
                "toolchain": {"python": "3.11"},
                "environment": {"os": "windows"},
            }
        ],
    }
    exact = explain_evidence_reuse(tmp_path, request)
    assert exact["gates"][0]["decision"] == "REUSE"
    request["gates"][0].pop("toolchain")
    unknown = explain_evidence_reuse(tmp_path, request)
    assert unknown["gates"][0]["decision"] == "RUN"
    assert "toolchain" in unknown["gates"][0]["unknown_inputs"]


def test_reuse_runs_when_changed_directory_contains_receipt_input(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("pass", encoding="utf-8")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [{"path": "src/app.py"}],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {
        "schema": REUSE_REQUEST_SCHEMA,
        "request_id": "r2",
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "changed_paths": ["src"],
        "gates": [
            {
                "id": "lint",
                "read_only": True,
                "side_effects": False,
                "receipt_path": "proof.json",
                "receipt_sha256": _sha_bytes(receipt_path.read_bytes()),
                "toolchain": {"python": "3.11"},
                "environment": {"os": "windows"},
            }
        ],
    }
    result = explain_evidence_reuse(tmp_path, request)
    assert result["gates"][0]["decision"] == "RUN"


def test_reuse_runs_when_workspace_root_changes(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [{"path": "src/app.py"}],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {
        "schema": REUSE_REQUEST_SCHEMA,
        "request_id": "r3",
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "changed_paths": ["."],
        "gates": [
            {
                "id": "lint",
                "read_only": True,
                "side_effects": False,
                "receipt_path": "proof.json",
                "receipt_sha256": _sha_bytes(receipt_path.read_bytes()),
                "toolchain": {"python": "3.11"},
                "environment": {"os": "windows"},
            }
        ],
    }
    result = explain_evidence_reuse(tmp_path, request)
    assert result["gates"][0]["decision"] == "RUN"


def test_reuse_runs_for_traversal_changed_path(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [{"path": "src/app.py"}],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {
        "schema": REUSE_REQUEST_SCHEMA,
        "request_id": "r4",
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "changed_paths": ["src/../secrets.txt"],
        "gates": [
            {
                "id": "lint",
                "read_only": True,
                "side_effects": False,
                "receipt_path": "proof.json",
                "receipt_sha256": _sha_bytes(receipt_path.read_bytes()),
                "toolchain": {"python": "3.11"},
                "environment": {"os": "windows"},
            }
        ],
    }
    result = explain_evidence_reuse(tmp_path, request)
    assert result["gates"][0]["decision"] == "RUN"
    assert result["gates"][0]["reason"] == "UNSAFE_CHANGED_PATH_REQUIRES_EXECUTION"


def test_reuse_runs_for_windows_absolute_changed_path(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [{"path": "src/app.py"}],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {
        "schema": REUSE_REQUEST_SCHEMA,
        "request_id": "r5",
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "changed_paths": ["C:\\workspace\\src\\app.py"],
        "gates": [
            {
                "id": "lint",
                "read_only": True,
                "side_effects": False,
                "receipt_path": "proof.json",
                "receipt_sha256": _sha_bytes(receipt_path.read_bytes()),
                "toolchain": {"python": "3.11"},
                "environment": {"os": "windows"},
            }
        ],
    }
    result = explain_evidence_reuse(tmp_path, request)
    assert result["gates"][0]["decision"] == "RUN"
    assert result["gates"][0]["reason"] == "UNSAFE_CHANGED_PATH_REQUIRES_EXECUTION"


def test_reuse_runs_for_windows_drive_relative_changed_path(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [{"path": "src/app.py"}],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {
        "schema": REUSE_REQUEST_SCHEMA,
        "request_id": "r5b",
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "changed_paths": [r"C:src\app.py"],
        "gates": [
            {
                "id": "lint",
                "read_only": True,
                "side_effects": False,
                "receipt_path": "proof.json",
                "receipt_sha256": _sha_bytes(receipt_path.read_bytes()),
                "toolchain": {"python": "3.11"},
                "environment": {"os": "windows"},
            }
        ],
    }
    result = explain_evidence_reuse(tmp_path, request)
    assert result["gates"][0]["decision"] == "RUN"
    assert result["gates"][0]["reason"] == "UNSAFE_CHANGED_PATH_REQUIRES_EXECUTION"


def test_reuse_runs_for_unsafe_receipt_input(tmp_path):
    policy = _sha_bytes(b"policy")
    dependencies = _sha_bytes(b"deps")
    receipt = {
        "schema": "factory.proof-receipt.v1",
        "status": "green",
        "read_only": True,
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "toolchain": {"python": "3.11"},
        "environment": {"os": "windows"},
        "inputs": [{"path": "../outside.py"}],
    }
    receipt_path = tmp_path / "proof.json"
    receipt_path.write_bytes(_canonical(receipt))
    request = {
        "schema": REUSE_REQUEST_SCHEMA,
        "request_id": "r6",
        "policy_sha256": policy,
        "dependencies_sha256": dependencies,
        "changed_paths": [],
        "gates": [
            {
                "id": "lint",
                "read_only": True,
                "side_effects": False,
                "receipt_path": "proof.json",
                "receipt_sha256": _sha_bytes(receipt_path.read_bytes()),
                "toolchain": {"python": "3.11"},
                "environment": {"os": "windows"},
            }
        ],
    }
    result = explain_evidence_reuse(tmp_path, request)
    assert result["gates"][0]["decision"] == "RUN"
    assert result["gates"][0]["reason"] == "UNSAFE_RECEIPT_INPUT_REQUIRES_EXECUTION"


def test_incident_triage_deduplicates_and_retains_critical_under_group_pressure():
    result = triage_incident_events(
        [
            {"severity": "warning", "source": "api", "message": "slow"},
            {"severity": "error", "source": "api", "message": "same"},
            {"severity": "critical", "source": "api", "message": "same"},
            {"severity": "info", "source": "worker", "message": "idle"},
        ],
        max_groups=1,
    )

    assert result["schema"] == INCIDENT_TRIAGE_SCHEMA
    assert result["status"] == "BACKPRESSURE"
    assert result["counts"]["duplicates"] == 1
    assert result["groups"][0]["severity"] == "critical"
    assert result["counts"]["dropped_critical"] == 0
    assert result["execution_allowed"] is False
    assert result["execution_authority"] == "none"


def test_incident_triage_byte_pressure_preserves_all_events_as_unassessed():
    result = triage_incident_events(
        [
            {"severity": "warning", "source": "api", "message": "x" * 500},
            {"severity": "critical", "source": "db", "message": "corrupt"},
        ],
        max_input_bytes=100,
    )

    assert result["status"] == "NOT_ASSESSED"
    assert result["backpressure"] is True
    assert result["abstain"] is True
    assert result["groups"] == []
    assert result["pending_event_ids"] == ["event:0", "event:1"]
    assert result["critical_presence"] == "NOT_ASSESSED"
    assert result["raw_batch_sha256"] is None
    assert result["batch_digest_verified"] is False


def test_incident_triage_byte_preflight_stops_before_serialization(monkeypatch):
    import factoryline.senior_assurance as assurance

    def forbidden(_value):
        raise AssertionError("serialization ran beyond the byte budget")

    monkeypatch.setattr(assurance, "canonical_bytes", forbidden)
    result = triage_incident_events(
        [
            {"severity": "critical", "source": "db", "message": "x" * 2048},
            {"severity": "warning", "source": "api", "message": "later"},
        ],
        max_input_bytes=32,
    )
    assert result["status"] == "NOT_ASSESSED"
    assert result["pending_event_ids"] == ["event:0", "event:1"]


def test_incident_triage_rejects_oversized_event_before_serialization(monkeypatch):
    import factoryline.senior_assurance as assurance

    def forbidden(_value):
        raise AssertionError("invalid event was serialized")

    monkeypatch.setattr(assurance, "canonical_bytes", forbidden)
    with pytest.raises(SeniorAssuranceError, match="event message is invalid"):
        triage_incident_events(
            [{"severity": "critical", "source": "db", "message": "x" * 2049}]
        )


def test_incident_triage_rejects_explicit_null_fingerprint_before_serialization(
    monkeypatch,
):
    import factoryline.senior_assurance as assurance

    def forbidden(_value):
        raise AssertionError("invalid fingerprint was serialized")

    monkeypatch.setattr(assurance, "canonical_bytes", forbidden)
    with pytest.raises(SeniorAssuranceError, match="fingerprint must be"):
        triage_incident_events(
            [
                {
                    "severity": "info",
                    "source": "api",
                    "message": "x",
                    "event_id": "a",
                    "timestamp": "t",
                    "fingerprint": None,
                }
            ],
            max_input_bytes=83,
        )


def test_incident_triage_unknown_severity_abstains_and_oversized_batch_backpressures():
    unknown = triage_incident_events(
        [
            {
                "event_id": "unknown-1",
                "severity": "urgent-ish",
                "source": "api",
                "message": "check",
            },
            {
                "event_id": "critical-1",
                "severity": "critical",
                "source": "db",
                "message": "one",
            },
            {
                "event_id": "critical-2",
                "severity": "critical",
                "source": "db",
                "message": "two",
            },
        ],
        max_groups=1,
    )
    oversized = triage_incident_events(
        [
            {"severity": "critical", "source": "db", "message": str(index)}
            for index in range(3)
        ],
        max_events=2,
    )
    queued = triage_incident_events(
        [
            {"severity": "critical", "source": "db", "message": str(index)}
            for index in range(3)
        ],
        max_events=2,
        raw_batch_sha256="c" * 64,
        pending_event_ids=["event-0", "event-1", "event-2"],
    )

    assert unknown["status"] == "ABSTAIN"
    assert unknown["abstain"] is True
    assert unknown["counts"]["dropped_critical"] == 1
    assert set(unknown["pending_event_ids"]) == {"unknown-1", "critical-2"} or set(
        unknown["pending_event_ids"]
    ) == {"unknown-1", "critical-1"}
    assert oversized["status"] == "NOT_ASSESSED"
    assert oversized["abstain"] is True
    assert oversized["groups"] == []
    assert queued["status"] == "BACKPRESSURE"
    assert queued["raw_batch_sha256"] == "c" * 64
    assert queued["pending_event_ids"] == ["event-0", "event-1", "event-2"]
    assert queued["batch_digest_verified"] is False
    assert queued["pending_ids_verified"] is False


def test_incident_triage_rejects_a_fingerprint_that_does_not_bind_its_event():
    with pytest.raises(SeniorAssuranceError, match="fingerprint does not match"):
        triage_incident_events(
            [
                {
                    "severity": "critical",
                    "source": "api",
                    "message": "failure",
                    "fingerprint": "f" * 64,
                }
            ]
        )


def _activation_request():
    body = {
        "schema": "factory.activation-experiment-request.v1",
        "experiment_id": "local-test-run",
        "input": {"prompt_sha256": "1" * 64, "target": "target-token"},
    }
    return {**body, "request_sha256": _sha_bytes(_canonical(body))}


def _register_activation_hooks(
    registry, *, mismatch=False, identity_mismatch=False, calls=None
):
    request_sha = _activation_request()["request_sha256"]

    def record(name):
        if calls is not None:
            calls.append(name)

    registry.register(
        "reset_cache",
        lambda request, stage: (
            record(f"reset:{stage}")
            or {
                "request_sha256": request_sha,
                "condition": stage,
                "cache_epoch": f"cache-{stage}",
            }
        ),
        hook_id="local-cache-reset",
        model_id="local-model",
        model_version="v1",
        runtime_id="local-runtime",
        implementation_sha256="a" * 64,
    )

    def run(stage):
        def callback(request, *parents):
            record(stage)
            return {
                "request_sha256": "0" * 64
                if mismatch and stage == "corrupt"
                else request_sha,
                "run_id": stage,
                "state": {"condition": stage},
            }

        return callback

    def measure(request, observed):
        record(f"measure:{observed['run_id']}")
        score = {
            "baseline": 0.9,
            "clean": 0.8,
            "corrupt": 0.1,
            "denoise": 0.7,
            "noise": 0.2,
        }[observed["state"]["condition"]]
        return {
            "request_sha256": request_sha,
            "run_id": observed["run_id"],
            "metrics": {"target_logit": score},
        }

    for name in ("baseline", "clean", "corrupt", "denoise", "noise"):
        registry.register(
            name,
            run(name),
            hook_id=f"local-{name}",
            model_id="local-model",
            model_version="v2" if identity_mismatch and name == "noise" else "v1",
            runtime_id="local-runtime",
            implementation_sha256="a" * 64,
        )
    registry.register(
        "measure",
        measure,
        hook_id="local-measure",
        model_id="local-model",
        model_version="v1",
        runtime_id="local-runtime",
        implementation_sha256="a" * 64,
    )


def test_activation_experiment_requires_registered_capabilities_and_opt_in():
    request = _activation_request()
    missing = run_activation_experiment(request, ActivationHookRegistry(), execute=True)
    registry = ActivationHookRegistry()
    calls = []
    _register_activation_hooks(registry, calls=calls)
    not_run = run_activation_experiment(request, registry)

    assert missing["status"] == "INCOMPLETE"
    assert "baseline" in missing["missing_capabilities"]
    assert not_run["status"] == "NOT_RUN"
    assert not_run["reason"] == "EXPLICIT_EXECUTION_REQUIRED"
    assert calls == []


def test_activation_experiment_records_baseline_and_asymmetric_bound_observations():
    registry = ActivationHookRegistry()
    _register_activation_hooks(registry)
    result = run_activation_experiment(_activation_request(), registry, execute=True)

    assert result["schema"] == ACTIVATION_EXPERIMENT_SCHEMA
    assert result["status"] == "OBSERVED"
    assert set(result["observations"]) == {
        "baseline",
        "clean",
        "corrupt",
        "denoise",
        "noise",
    }
    assert result["observations"]["denoise"]["metrics"]["target_logit"] == 0.7
    assert result["observations"]["noise"]["metrics"]["target_logit"] == 0.2
    assert result["cache_epochs"]["baseline"] != result["cache_epochs"]["clean"]
    assert result["release_approval"] is False
    assert "not independently verified" in result["claim_boundary"]
    assert result["hook_identities"]["baseline"]["hook_name"] == "baseline"
    assert len(result["evidence_sha256"]) == 64


def test_activation_experiment_rejects_inconsistent_model_runtime_identity():
    registry = ActivationHookRegistry()
    _register_activation_hooks(registry, identity_mismatch=True)
    result = run_activation_experiment(_activation_request(), registry, execute=True)

    assert result["status"] == "INCOMPLETE"
    assert result["reason"] == "E_ACTIVATION_IDENTITY"
    assert "secret" not in json.dumps(result).lower()


def test_activation_experiment_rejects_mismatched_hook_and_measurement_bindings():
    registry = ActivationHookRegistry()
    _register_activation_hooks(registry, mismatch=True)
    result = run_activation_experiment(_activation_request(), registry, execute=True)

    assert result["status"] == "INCOMPLETE"
    assert result["reason"] == "E_ACTIVATION_BINDING"
    assert "0" * 64 not in json.dumps(result)


def test_failure_brief_links_finding_to_receipt_and_surfaces_uncertainty():
    brief = failure_brief(
        {
            "schema": "factory.replay-receipt.v1",
            "state": "FAIL",
            "replay_id": "r1",
            "source_root": "src",
            "failure_reason": "EXIT_MISMATCH",
            "argv": [sys.executable, "run.py"],
            "receipt_sha256": _sha_bytes(b"receipt"),
        },
        receipt_path=".factory/senior/replay.json",
    )
    assert brief["state"] == "ACTION_REQUIRED"
    assert brief["what_broke"][0]["evidence"] == _sha_bytes(b"receipt")
    assert brief["reproduce"]["argv"]
    assert brief["uncertainty"]


def test_runtime_audit_run_cli_exposes_bounded_parallelism(capsys):
    import pytest

    with pytest.raises(SystemExit) as error:
        main(
            [
                "runtime-audit",
                "run",
                "plan.json",
                "--trust-root",
                "trust.json",
                "--trust-root-sha256",
                "a" * 64,
                "--environment-sha256",
                "b" * 64,
                "--max-parallelism",
                "9",
            ]
        )
    assert error.value.code == 2


def _digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def test_senior_schedule_cli_emits_json(tmp_path, capsys):
    manifest = {
        "schema": SCHEDULE_SCHEMA,
        "plan_id": "cli-plan",
        "assurance_level": "isolated_worker",
        "changed_paths": ["src/a.py"],
        "dependency_closure": {"lint": ["src/a.py"]},
        "gates": [
            {"id": "lint", "depends_on": [], "side_effects": False, "proof": None}
        ],
    }
    path = tmp_path / "schedule.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["senior", "schedule", str(path), "--root", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "INCREMENTAL_PLAN_COMPACT"
    assert result["findings"]["lint"]["disposition"] == "RUN"


def test_senior_benchmark_cli_blocks_bad_observation(tmp_path, capsys):
    manifest = {
        "schema": BENCHMARK_SCHEMA,
        "benchmark_id": "cli",
        "version": "1",
        "cases": [
            {
                "id": "bug",
                "category": "failure_recovery",
                "source": "fixtures/bug",
                "source_sha256": _digest("a"),
                "expected_finding": "timeout",
                "replay_argv": ["pytest", "tests/bug.py"],
                "buggy_sha256": _digest("b"),
                "fixed_sha256": _digest("c"),
            }
        ],
    }
    observations = {
        "bug": {
            "buggy": {"state": "PASS", "finding": ""},
            "fixed": {"state": "PASS", "finding": ""},
        }
    }
    manifest_path = tmp_path / "manifest.json"
    observations_path = tmp_path / "observations.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    observations_path.write_text(json.dumps(observations), encoding="utf-8")
    assert (
        main(
            [
                "senior",
                "benchmark",
                str(manifest_path),
                "--observations",
                str(observations_path),
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result["decision"] == "BLOCKED"


def test_senior_json_loaders_are_bounded_cli_inputs(tmp_path):
    benchmark = tmp_path / "benchmark.json"
    schedule = tmp_path / "schedule.json"
    benchmark.write_text(json.dumps({"schema": BENCHMARK_SCHEMA}), encoding="utf-8")
    schedule.write_text(json.dumps({"schema": SCHEDULE_SCHEMA}), encoding="utf-8")
    assert load_benchmark_json(benchmark)["schema"] == BENCHMARK_SCHEMA
    assert load_schedule_json(schedule)["schema"] == SCHEDULE_SCHEMA


def test_senior_brief_cli_emits_actionable_evidence(tmp_path, capsys):
    receipt = tmp_path / "failed.json"
    receipt.write_text(
        json.dumps(
            {
                "schema": "factory.replay-receipt.v1",
                "state": "FAIL",
                "failure_reason": "EXIT_MISMATCH",
                "source_root": "src",
                "argv": ["python", "run.py"],
                "receipt_sha256": _digest("receipt"),
            }
        ),
        encoding="utf-8",
    )
    assert main(["senior", "brief", str(receipt)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["marker"] == "FAILURE_BRIEF_EVIDENCE_LINKED"
    assert result["what_broke"][0]["evidence"] == _digest("receipt")


def test_senior_reuse_cli_explains_missing_evidence_as_run(tmp_path, capsys):
    request = tmp_path / "reuse.json"
    request.write_text(
        json.dumps(
            {
                "schema": REUSE_REQUEST_SCHEMA,
                "request_id": "r",
                "policy_sha256": _digest("policy"),
                "dependencies_sha256": _digest("deps"),
                "gates": [{"id": "lint", "read_only": True, "side_effects": False}],
            }
        ),
        encoding="utf-8",
    )
    assert main(["senior", "reuse", str(request), "--root", str(tmp_path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["gates"][0]["decision"] == "RUN"
    assert result["gates"][0]["reason"] == "UNKNOWN_INPUT_REQUIRES_EXECUTION"


def _manifest():
    return {
        "schema": "factory.incremental-plan.v1",
        "plan_id": "graph-plan",
        "assurance_level": "isolated_worker",
        "changed_paths": ["src/app.py"],
        "dependency_closure": {"lint": ["src/app.py"]},
        "gates": [
            {"id": "lint", "depends_on": [], "side_effects": False, "proof": None}
        ],
    }


def test_empty_projection_is_explicitly_review_only(tmp_path: Path):
    result = senior_engineering_projection(tmp_path)
    assert result["receipt_count"] == 0
    assert result["authority_false"] is True
    assert result["authority"]["publication"] is False
    assert result["errors"] == []


def test_graph_ops_projects_valid_plan_and_fails_closed_on_tamper(tmp_path: Path):
    output = tmp_path / ".factory" / "senior" / "incremental.json"
    plan_incremental(tmp_path, _manifest(), out=output)
    snapshot = graph_ops_snapshot(tmp_path)
    assert snapshot["facts"]["senior_engineering_receipt_count"] == 1
    assert snapshot["facts"]["senior_engineering_invalid_count"] == 0
    assert "GRAPH_OPS_SENIOR_ENGINEERING_READ_ONLY" in snapshot["markers"]
    assert any(
        node["kind"] == "senior_engineering_evidence" for node in snapshot["nodes"]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["counts"]["RUN"] = 99
    output.write_text(json.dumps(payload), encoding="utf-8")
    tampered = graph_ops_snapshot(tmp_path)
    assert tampered["facts"]["senior_engineering_invalid_count"] == 1
    assert "GRAPH_OPS_SENIOR_ENGINEERING_REVIEW_REQUIRED" in tampered["markers"]
    assert tampered["recommendation"]["action"] == "review_senior_engineering_evidence"


def test_projection_rejects_receipts_that_claim_authority(tmp_path: Path):
    directory = tmp_path / ".factory" / "senior"
    directory.mkdir(parents=True)
    (directory / "authority.json").write_text(
        json.dumps(
            {
                "schema": "factory.incremental-shadow.v1",
                "authority": "publication",
                "shadow_equivalent": True,
            }
        ),
        encoding="utf-8",
    )
    result = senior_engineering_projection(tmp_path)
    assert result["invalid_count"] == 1
    assert result["errors"][0]["code"] == "AUTHORITY_NOT_NONE"


def test_projection_reads_failure_brief_as_review_only_evidence(tmp_path: Path):
    directory = tmp_path / ".factory" / "senior"
    directory.mkdir(parents=True)
    brief = {
        "schema": "factory.failure-brief.v1",
        "marker": "FAILURE_BRIEF_EVIDENCE_LINKED",
        "state": "ACTION_REQUIRED",
        "what_broke": [{"id": "x", "summary": "broken", "evidence": "a"}],
        "affected": ["src"],
        "reproduce": {"argv": ["python", "run.py"]},
        "next_fix": "repair",
        "uncertainty": ["owner unknown"],
        "evidence": [{"receipt_sha256": "a"}],
        "authority": "none",
        "release_approval": False,
    }
    brief["brief_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in brief.items() if key != "brief_sha256"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    (directory / "brief.json").write_text(json.dumps(brief), encoding="utf-8")
    result = senior_engineering_projection(tmp_path)
    assert result["receipt_count"] == 1
    assert result["invalid_count"] == 0
    assert result["receipts"][0]["schema"] == "factory.failure-brief.v1"


def test_projection_surfaces_runtime_boundary_attestation_and_detects_tamper(
    tmp_path: Path,
):
    directory = tmp_path / ".factory" / "senior"
    directory.mkdir(parents=True)
    attestation = capture_supervised_attestation(
        attestation_id="boundary-graph-001",
        candidate_sha256=hashlib.sha256(b"candidate").hexdigest(),
        plan_sha256=hashlib.sha256(b"plan").hexdigest(),
        environment_sha256=hashlib.sha256(b"environment").hexdigest(),
    )
    path = directory / "runtime-boundary.json"
    path.write_text(json.dumps(attestation), encoding="utf-8")
    result = senior_engineering_projection(tmp_path)
    assert result["invalid_count"] == 0
    assert result["receipts"][0]["status"] == "SUPERVISED_ONLY"
    assert (
        result["receipts"][0]["attestation_sha256"] == attestation["attestation_sha256"]
    )

    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["observations"]["platform"] = "tampered"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    failed = senior_engineering_projection(tmp_path)
    assert failed["invalid_count"] == 1
    assert failed["errors"][0]["code"] == "SELF_HASH_MISMATCH"

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.runtime_audit_common import (
    RuntimeAuditError,
    canonical_bytes,
    sha256_bytes,
)
from factoryline.runtime_audit_contract import (
    PLAN_SCHEMA,
    PLAN_TYPE,
    verify_runtime_audit_plan,
)
from factoryline.intake_parameters import REQUIRED_AUDIT_LANES
from test_intake_admission import _intake

D = hashlib.sha256(b"x").hexdigest()


def _configs():
    return {
        "stateful_invariant": {
            "invariant_ids": ["i"],
            "required_actions": ["a"],
            "min_examples": 2,
            "min_actions": 2,
        },
        "tenant_isolation": {
            "forbidden_fields": ["tenant_id"],
            "denial_statuses": [403],
            "surfaces": [
                {
                    "id": "api",
                    "category": "api",
                    "operation": "GET",
                    "resource": "/x",
                    "owner_data_sha256": D,
                    "owner_required_fields": ["id"],
                }
            ],
        },
        "failure_recovery": {
            "fault_modes": ["timeout"],
            "min_interleavings": 2,
            "postconditions": [
                {"id": "p", "metric": "count", "operator": "eq", "value": 1}
            ],
            "min_concurrency": 2,
            "max_attempts_per_key": 2,
        },
        "consumer_compatibility": {
            "provider_version": "1",
            "provider_branch": "main",
            "environment": "test",
            "deployment_matrix_required": True,
            "interactions": [
                {
                    "id": "i",
                    "consumer_id": "c",
                    "consumer_version": "1",
                    "expected_sha256": D,
                }
            ],
        },
        "migration_integrity": {
            "before_schema_sha256": D,
            "expected_after_schema_sha256": D,
            "invariants": [{"id": "i", "expected_sha256": D}],
            "tables": [{"id": "t", "before": 1, "after": 1}],
            "recovery_strategy": "rollback",
            "required_catalog_objects": ["t_pkey"],
            "max_lock_wait_seconds": 1,
        },
        "performance_regression": {
            "workload_sha256": D,
            "environment_sha256": D,
            "thresholds": [
                {
                    "id": "p",
                    "metric": "p95",
                    "mode": "absolute",
                    "operator": "lte",
                    "value": 10,
                    "origin": "human_confirmed",
                }
            ],
            "resource_metrics": ["rss"],
            "minimum_resource_samples": 3,
            "max_retained_growth_ratio": 0.1,
            "max_loadgen_cpu_pct": 80,
            "max_loadgen_memory_pct": 80,
            "max_dropped_iterations": 0,
            "min_soak_seconds": 1,
            "min_cooldown_seconds": 1,
            "leak_engine": "runtime_metrics",
        },
    }


def signed_plan(
    tmp_path: Path, *, execution_policy: dict | None = None, worker: str | None = None
):
    source = tmp_path / "candidate.txt"
    source.write_text("candidate", encoding="utf-8")
    raw = source.read_bytes()
    sources = [
        {"path": "candidate.txt", "sha256": sha256_bytes(raw), "bytes": len(raw)}
    ]
    if worker is not None:
        worker_bytes = worker.encode("utf-8")
        (tmp_path / "runner.py").write_bytes(worker_bytes)
        sources.append(
            {
                "path": "runner.py",
                "sha256": sha256_bytes(worker_bytes),
                "bytes": len(worker_bytes),
            }
        )
    engines = {
        "stateful_invariant": "hypothesis",
        "tenant_isolation": "runtime_http_matrix",
        "failure_recovery": "approved_fault_runner",
        "consumer_compatibility": "pact_verifier",
        "migration_integrity": "database_rehearsal",
        "performance_regression": "approved_load_runner",
    }
    now = datetime.now(timezone.utc)
    plan = {
        "schema": PLAN_SCHEMA,
        "id": "test-plan",
        "candidate_sha256": sha256_bytes(canonical_bytes(sources)),
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "environment": {
            "kind": "local_test",
            "digest": D,
            "origins": ["http://127.0.0.1"],
        },
        "sources": sources,
        "counterfactual_mesh": {
            "id": "checkout-retry",
            "scenario_sha256": D,
            "relations": ["same_business_operation", "same_runtime_environment"],
            "origin": "human_confirmed",
        },
        "lanes": [],
    }
    if execution_policy is not None:
        plan["execution_policy"] = execution_policy
    for kind, config in _configs().items():
        plan["lanes"].append(
            {
                "id": kind.replace("_", "-"),
                "kind": kind,
                "engine": engines[kind],
                "engine_version": "1",
                "timeout_seconds": 5,
                "target_argv": ["python", "runner.py", kind, "{artifact}"],
                "known_bad_argv": ["python", "runner.py", kind, "bad", "{artifact}"],
                "expected_negative_code": {
                    "stateful_invariant": "STATEFUL_INVARIANT_VIOLATION",
                    "tenant_isolation": "TENANT_ISOLATION_VIOLATION",
                    "failure_recovery": "RECOVERY_INVARIANT_VIOLATION",
                    "consumer_compatibility": "CONSUMER_CONTRACT_BROKEN",
                    "migration_integrity": "MIGRATION_INTEGRITY_VIOLATION",
                    "performance_regression": "PERFORMANCE_OR_RESOURCE_REGRESSION",
                }[kind],
                "config": config,
            }
        )
    material = generate_key_material(
        out_dir=tmp_path / "keys",
        keyid="operator",
        identity="operator@example.test",
        issuer="https://issuer.example.test",
    )
    envelope = sign_payload(
        plan,
        payload_type=PLAN_TYPE,
        private_key_path=Path(material["private_key"]),
        keyid=material["keyid"],
        identity=material["identity"],
        issuer=material["issuer"],
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(envelope), encoding="utf-8")
    trust = Path(material["trust_root"])
    trust_sha = sha256_bytes(trust.read_bytes())
    return plan_path, trust, trust_sha, plan


def test_signed_plan_binds_six_lanes_sources_environment_and_authority(tmp_path):
    plan_path, trust, trust_sha, plan = signed_plan(tmp_path)
    result = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    assert result["plan"] == plan and result["authority"] == "none"
    assert result["execution_policy"]["max_parallelism"] == 1


def test_signed_six_lane_run_rejects_wrong_scenario_and_persists_receipt(tmp_path):
    from factoryline.runtime_audit import execute_runtime_audit, runtime_audit_status

    worker = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "case = {'scenario_sha256': '0' * 64, 'passed': True, "
        "'lane': sys.argv[1], 'known_bad': len(sys.argv) == 4}\n"
        "Path(sys.argv[-1]).write_text(json.dumps(case), encoding='utf-8')\n"
        "sys.exit(int(case['known_bad']))\n"
    )
    plan, trust, pin, _ = signed_plan(tmp_path, worker=worker)
    output = tmp_path / ".factory" / "runtime-audits"
    result = execute_runtime_audit(plan, trust, pin, tmp_path, D, output)
    executions = result["execution"]["executions"]
    assert len(executions) == 6
    for execution in executions:
        target, bad = execution["target"], execution["known_bad"]
        assert (
            target["artifact"]["lane"] == bad["artifact"]["lane"] == execution["kind"]
        )
        assert target["artifact"]["known_bad"] is False
        assert bad["artifact"]["known_bad"] is True
        assert target["artifact_sha256"] != bad["artifact_sha256"]

    receipt = result["receipt"]
    assert receipt["decision"] == "BLOCKED"
    assert receipt["release_approval"] is False
    assert len(receipt["repair_queue"]) == 6
    assert {lane["finding"] for lane in receipt["lanes"]} == {
        "CROSS_LANE_SCENARIO_MISMATCH"
    }
    status = runtime_audit_status(tmp_path)
    assert status["state"] == "BLOCKED"
    assert status["receipt_sha256"] == receipt["receipt_sha256"]


def _runtime_rehearsal_plan(tmp_path):
    import runpy

    fixture = Path(__file__).parent / "fixtures" / "runtime_six_lane_worker.py"
    helpers = runpy.run_path(str(fixture))
    path, trust, pin, plan = signed_plan(tmp_path, worker=fixture.read_text())
    lanes = {lane["kind"]: lane for lane in plan["lanes"]}
    lanes["stateful_invariant"]["engine"] = "approved_state_machine"
    lanes["tenant_isolation"]["config"]["surfaces"][0]["owner_data_sha256"] = helpers[
        "digest"
    ]({"id": 1})
    lanes["consumer_compatibility"]["engine"] = "approved_schema_validator"
    lanes["consumer_compatibility"]["config"]["interactions"][0]["expected_sha256"] = (
        helpers["digest"]({"id": 1})
    )
    lanes["migration_integrity"]["config"].update(
        before_schema_sha256=helpers["digest"](
            [("CREATE TABLE orders(id INTEGER PRIMARY KEY, amount INTEGER)",)]
        ),
        expected_after_schema_sha256=helpers["digest"](
            [
                (
                    "CREATE TABLE orders(id INTEGER PRIMARY KEY, amount INTEGER, note TEXT)",
                )
            ]
        ),
        invariants=[{"id": "i", "expected_sha256": helpers["digest"](1)}],
        required_catalog_objects=["orders"],
        tables=[{"id": "orders", "before": 1, "after": 1}],
    )
    lanes["performance_regression"]["timeout_seconds"] = 15
    lanes["performance_regression"]["config"].update(
        resource_metrics=["python_bytes"],
        leak_engine="python_tracemalloc",
        max_loadgen_cpu_pct=100,
        max_loadgen_memory_pct=100,
    )
    lanes["performance_regression"]["config"]["thresholds"][0]["value"] = 0.2
    lanes["performance_regression"]["config"]["thresholds"][0]["metric"] = "p95_seconds"
    envelope = sign_payload(
        plan,
        payload_type=PLAN_TYPE,
        private_key_path=tmp_path / "keys" / "operator.private.pem",
        keyid="operator",
        identity="operator@example.test",
        issuer="https://issuer.example.test",
    )
    path.write_text(json.dumps(envelope), encoding="utf-8")
    return path, trust, pin, plan


def test_signed_six_lane_real_workloads_persist_human_review_receipt(tmp_path):
    """Local approved runners; retention and leak findings are snapshot-scoped.

    This does not verify native lost bytes, host saturation, Pact, k6, or
    production behavior. The schema's zero lost-byte field adds no such claim.
    """
    from factoryline.runtime_audit import execute_runtime_audit, runtime_audit_status

    plan_path, trust, pin, plan = _runtime_rehearsal_plan(tmp_path)
    output = tmp_path / ".factory" / "runtime-audits"
    result = execute_runtime_audit(plan_path, trust, pin, tmp_path, D, output)
    receipt = result["receipt"]
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW", receipt["lanes"]
    assert receipt["release_approval"] is False
    assert receipt["repair_queue"] == []
    assert {lane["state"] for lane in receipt["lanes"]} == {"PASS"}
    performance = next(
        lane for lane in receipt["lanes"] if lane["lane"] == "performance_regression"
    )
    assert performance["details"]["leak_engine"] == "python_tracemalloc"
    assert (
        performance["details"]["leak_claim"]
        == "no finding within declared profiler coverage"
    )
    executions = result["execution"]["executions"]
    assert len(executions) == 6
    for execution in executions:
        for role in ("target", "known_bad"):
            observed = execution[role]
            assert observed["artifact"]["scenario_sha256"] == D
            assert observed["execution"]["exit_code"] == int(role == "known_bad")
            assert observed["execution"]["cleanup_confirmed"] is True
        assert (
            execution["target"]["artifact_sha256"]
            != execution["known_bad"]["artifact_sha256"]
        )
    status = runtime_audit_status(tmp_path)
    assert status["state"] == "READY_FOR_HUMAN_REVIEW"
    assert status["receipt_sha256"] == receipt["receipt_sha256"]
    assert receipt["candidate_sha256"] == plan["candidate_sha256"]


def test_workload_helpers_measure_http_revocation_resources_and_bind_observations(
    monkeypatch,
    capsys,
):
    import tracemalloc
    from fixtures import runtime_six_lane_worker
    from fixtures.runtime_six_lane_worker import (
        Handler,
        digest,
        hashed_observation,
        http_cases,
        measured_run,
        process_memory_percent,
    )

    observation = hashed_observation(mode="timeout", observed=True)
    assert observation["evidence_sha256"] == digest(
        {"mode": "timeout", "observed": True}
    )
    assert observation["evidence_sha256"] != digest(
        {"mode": "timeout", "observed": False}
    )
    calls = {"get": 0, "log": 0}

    class ObservedHandler(Handler):
        def do_GET(self):
            calls["get"] += 1
            Handler.do_GET(self)

        def log_message(self, *args):
            calls["log"] += 1
            Handler.log_message(self, *args)

    monkeypatch.setattr(runtime_six_lane_worker, "Handler", ObservedHandler)
    cases = http_cases(False)
    assert calls == {"get": 14, "log": 14}
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    assert len(cases) == 12
    assert {case["status"] for case in cases if case["relation"] == "owner"} == {200}
    assert {
        case["status"] for case in cases if case["relation"] == "revoked_session"
    } == {403}
    assert 0 < process_memory_percent() <= 100
    tracemalloc.start()
    try:
        run, resource = measured_run(0.001)
    finally:
        tracemalloc.stop()
    assert run["observations"] == 10 and run["correctness_failures"] == 0
    assert run["metrics"]["p95_seconds"] >= 0.001
    assert run["soak_seconds"] >= 1 and run["cooldown_seconds"] >= 1
    assert len(resource["samples"]) == 10 and min(resource["samples"]) > 0
    assert len(resource["retained"]) == 3 and min(resource["retained"]) > 0


def test_signed_execution_policy_requires_safe_bounded_parallelism(tmp_path):
    plan_path, trust, trust_sha, plan = signed_plan(tmp_path)
    plan["execution_policy"] = {
        "max_parallelism": 2,
        "non_mutating": True,
        "resource_safe": True,
    }
    material = generate_key_material(
        out_dir=tmp_path / "keys2",
        keyid="operator2",
        identity="operator@example.test",
        issuer="https://issuer.example.test",
    )
    envelope = sign_payload(
        plan,
        payload_type=PLAN_TYPE,
        private_key_path=Path(material["private_key"]),
        keyid=material["keyid"],
        identity=material["identity"],
        issuer=material["issuer"],
    )
    plan_path.write_text(json.dumps(envelope), encoding="utf-8")
    trust = Path(material["trust_root"])
    trust_sha = sha256_bytes(trust.read_bytes())
    result = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    assert result["execution_policy"]["max_parallelism"] == 2
    for unsafe in (
        {"max_parallelism": 2, "non_mutating": False, "resource_safe": True},
        {"max_parallelism": 2, "non_mutating": True, "resource_safe": False},
    ):
        plan["execution_policy"] = unsafe
        envelope = sign_payload(
            plan,
            payload_type=PLAN_TYPE,
            private_key_path=Path(material["private_key"]),
            keyid=material["keyid"],
            identity=material["identity"],
            issuer=material["issuer"],
        )
        plan_path.write_text(json.dumps(envelope), encoding="utf-8")
        with pytest.raises(RuntimeAuditError, match="E_EXECUTION_POLICY"):
            verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)


def test_contract_rejects_environment_source_and_signature_drift(tmp_path):
    plan_path, trust, trust_sha, _ = signed_plan(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_ENVIRONMENT_DRIFT"):
        verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, "0" * 64)
    (tmp_path / "candidate.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_SOURCE_DRIFT"):
        verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    with pytest.raises(RuntimeAuditError, match="E_TRUST_ROOT_DRIFT"):
        verify_runtime_audit_plan(plan_path, trust, "0" * 64, tmp_path, D)


def test_strict_runtime_plan_requires_authoritative_intake_binding(tmp_path):
    plan_path, trust, trust_sha, _ = signed_plan(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_INTAKE_BINDING_REQUIRED"):
        verify_runtime_audit_plan(
            plan_path, trust, trust_sha, tmp_path, D, require_intake=True
        )


def test_runtime_plan_binding_matches_scope_digest_and_six_lanes(tmp_path):
    intake_path, _ = _intake(tmp_path, scope=["candidate.txt"])
    plan_path, trust, trust_sha, plan = signed_plan(tmp_path)
    intake = json.loads(intake_path.read_text(encoding="utf-8"))
    plan["intake_parameters"] = {
        "path": intake_path.relative_to(tmp_path).as_posix(),
        "parameter_sha256": intake["parameter_sha256"],
        "external_effects": "local_only",
    }
    envelope = sign_payload(
        plan,
        payload_type=PLAN_TYPE,
        private_key_path=tmp_path / "keys" / "operator.private.pem",
        keyid="operator",
        identity="operator@example.test",
        issuer="https://issuer.example.test",
    )
    plan_path.write_text(json.dumps(envelope), encoding="utf-8")
    result = verify_runtime_audit_plan(
        plan_path, trust, trust_sha, tmp_path, D, require_intake=True
    )
    assert result["intake_parameters"]["parameter_sha256"] == intake["parameter_sha256"]
    assert set(result["plan"]["lanes"][index]["kind"] for index in range(6)) == set(
        REQUIRED_AUDIT_LANES
    )


def test_runtime_plan_private_stages_respect_complexity_limit():
    import ast
    import inspect
    import textwrap
    import factoryline.runtime_audit_contract as module

    for name, value in vars(module).items():
        if not (
            name.startswith("_plan_") or name == "verify_runtime_audit_plan"
        ) or not callable(value):
            continue
        tree = ast.parse(textwrap.dedent(inspect.getsource(value)))
        count = 1
        for node in ast.walk(tree):
            if isinstance(
                node,
                (
                    ast.If,
                    ast.For,
                    ast.While,
                    ast.ExceptHandler,
                    ast.With,
                    ast.Assert,
                    ast.IfExp,
                ),
            ):
                count += 1
            elif isinstance(node, ast.BoolOp):
                count += len(node.values) - 1
        assert count <= 10, (name, count)

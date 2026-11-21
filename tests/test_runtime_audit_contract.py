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


def test_signed_plan_verifies_captured_documents_not_reopened_files(
    tmp_path, monkeypatch
):
    import factoryline.runtime_audit_contract as contract

    path, trust, pin, plan = signed_plan(tmp_path)
    original = contract.verify_signed_document_value

    def replace_paths_after_capture(envelope, **kwargs):
        path.write_text('{"tampered":true}')
        trust.write_text('{"keys":[]}')
        return original(envelope, **kwargs)

    monkeypatch.setattr(
        contract, "verify_signed_document_value", replace_paths_after_capture
    )
    result = verify_runtime_audit_plan(path, trust, pin, tmp_path, D)
    assert result["plan"] == plan
    assert result["trust_root_sha256"] == pin
    assert result["authority"] == "none"


def test_runtime_plan_pin_refuses_dispatch_before_execution(tmp_path, monkeypatch):
    import factoryline.runtime_audit as audit

    path, trust, pin, _ = signed_plan(tmp_path)
    monkeypatch.setattr(
        audit,
        "run_runtime_audit_plan",
        lambda *a, **kw: pytest.fail("unadmitted execution"),
    )
    with pytest.raises(RuntimeAuditError, match="E_PLAN_CHANGED"):
        audit.execute_runtime_audit(
            path,
            trust,
            pin,
            tmp_path,
            D,
            tmp_path / ".factory/runtime-audits",
            expected_plan_sha256="0" * 64,
        )


def _proof_agent_fixture(tmp_path, *, fail_target=False):
    import subprocess
    from factoryline.product_missions import bind_mission_candidate, decide_mission
    from test_product_missions import _pipeline

    _, _, mission = _pipeline(tmp_path)
    decision = decide_mission(
        Path(mission["path"]),
        tmp_path,
        owner="release-owner",
        decision="approved_execution",
        rationale="Run only the exact signed local proof commands.",
    )
    workspace = tmp_path / "candidate"
    workspace.mkdir()
    path, trust, pin, plan = _runtime_rehearsal_plan(workspace)
    if fail_target:
        plan["lanes"][0]["target_argv"] = list(plan["lanes"][0]["known_bad_argv"])
        plan["lanes"][0]["target_argv"][-2] = "approved-target-failure"
    parameters, _ = _intake(workspace, scope=[item["path"] for item in plan["sources"]])
    plan["intake_parameters"] = {
        "path": parameters.relative_to(workspace).as_posix(),
        "parameter_sha256": json.loads(parameters.read_text())["parameter_sha256"],
        "external_effects": "local_only",
    }
    plan["execution_policy"] = {
        "max_parallelism": 1,
        "non_mutating": True,
        "resource_safe": True,
    }
    path.write_text(
        json.dumps(
            sign_payload(
                plan,
                payload_type=PLAN_TYPE,
                private_key_path=workspace / "keys/operator.private.pem",
                keyid="operator",
                identity="operator@example.test",
                issuer="https://issuer.example.test",
            )
        )
    )
    (workspace / ".gitignore").write_text(
        ".factory/\nkeys/\nplan.json\nmission.md\nintake-request.json\n"
    )

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(workspace), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    git("init", "-q")
    git("add", "candidate.txt", "runner.py", ".gitignore")
    git(
        "-c",
        "user.name=Test Owner",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "bound audit candidate",
    )
    commands = [
        {"id": f"{side}-{i}", "argv": lane[key]}
        for i, lane in enumerate(plan["lanes"])
        for side, key in (("target", "target_argv"), ("bad", "known_bad_argv"))
    ]
    declaration = {
        "schema": "factory.mission.candidate-declaration.v1",
        "workspace": "candidate",
        "base_commit": git("rev-parse", "HEAD"),
        "paths": [item["path"] for item in plan["sources"]],
        "interfaces": ["signed local six-business-lane audit"],
        "profiles": ["factory.runtime-audit.v1"],
        "commands": commands,
        "audit_lanes": {
            family: {
                "applicable": family == "runtime",
                "reason": "This packet runs local business-workflow evidence only.",
            }
            for family in (
                "static",
                "secrets",
                "configuration",
                "dependencies",
                "runtime",
                "fuzz",
            )
        },
    }
    binding = bind_mission_candidate(
        Path(mission["path"]),
        Path(decision["path"]),
        tmp_path,
        owner="release-owner",
        declaration=declaration,
    )
    return path, trust, pin, workspace, plan, binding


def test_proof_agent_runs_real_approved_six_lane_packet(tmp_path):
    from factoryline.runtime_audit import execute_proof_agent

    path, trust, pin, workspace, plan, binding = _proof_agent_fixture(tmp_path)
    result = execute_proof_agent(
        path,
        trust,
        pin,
        workspace,
        D,
        Path(".factory/runtime-audits"),
        mission_binding_path=Path(binding["path"]),
        mission_root=tmp_path,
        owner="release-owner",
        confirmation="RUN Proof Agent",
    )
    assert result["state"] == "PASS", result["proof_debt"]
    assert result["valid"] and result["proof_debt"] == []
    assert len(result["lanes"]) == 6 and {
        lane["state"] for lane in result["lanes"]
    } == {"PASS"}
    assert result["authority"] == "none" and not result["release_approval"]
    assert result["signature_status"] == "UNSIGNED"
    receipt = json.loads((workspace / result["runtime_receipt"]["path"]).read_text())
    assert receipt["receipt_sha256"] == result["runtime_receipt"]["sha256"]
    assert result["mission_binding_sha256"] == binding["binding_sha256"]
    assert result["receipt_sha256"] == sha256_bytes(
        canonical_bytes({k: v for k, v in result.items() if k != "receipt_sha256"})
    )


@pytest.mark.parametrize("failure", ["target", "postflight"])
def test_proof_agent_cli_preserves_real_failure_and_returns_nonzero(
    tmp_path, capsys, monkeypatch, failure
):
    from factoryline.cli import main
    import factoryline.runtime_audit as audit

    path, trust, pin, workspace, _, binding = _proof_agent_fixture(
        tmp_path, fail_target=True
    )
    if failure == "postflight":
        validate = audit._proof_agent_receipt

        def contradict_written_receipt(result, *args):
            result["receipt"]["decision"] = "invented"
            return validate(result, *args)

        monkeypatch.setattr(audit, "_proof_agent_receipt", contradict_written_receipt)
    code = main(
        [
            "agent",
            "prove",
            "--plan",
            str(path),
            "--trust-root",
            str(trust),
            "--trust-root-sha256",
            pin,
            "--environment-digest",
            D,
            "--root",
            str(workspace),
            "--mission-root",
            str(tmp_path),
            "--mission-binding",
            binding["path"],
            "--owner",
            "release-owner",
            "--confirmation",
            "RUN Proof Agent",
            "--json",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert code == 1 and result["state"] == "BLOCKED"
    if failure == "postflight":
        assert result == {
            "schema": "factory.proof-agent.v1",
            "state": "BLOCKED",
            "valid": False,
            "finding": "E_PROOF_RECEIPT_DRIFT",
            "authority": "none",
            "release_approval": False,
        }
        receipts = list(
            workspace.glob(".factory/runtime-audits/run-*/runtime-audit-receipt.json")
        )
        assert len(receipts) == 1
        retained = json.loads(receipts[0].read_text(encoding="utf-8"))
        assert retained["decision"] == "BLOCKED" and retained["repair_queue"]
        return
    assert result.get("proof_debt") and not result["valid"], result
    assert not result["release_approval"]
    assert (workspace / result["runtime_receipt"]["path"]).is_file()


def test_proof_agent_incomplete_retains_evidence_and_never_passes(
    tmp_path, monkeypatch
):
    import factoryline.runtime_audit as audit

    path, trust, pin, workspace, _, binding = _proof_agent_fixture(tmp_path)
    original = audit.execute_runtime_audit

    def missing_output(*args, **kwargs):
        result = original(*args, **kwargs)
        receipt = result["receipt"]
        receipt["decision"] = "BLOCKED"
        receipt["lanes"][0]["state"] = "INCOMPLETE"
        receipt["lanes"][0]["finding"] = "RUNTIME_AUDIT_EXECUTION_MISSING"
        receipt.pop("receipt_sha256")
        receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
        (workspace / result["receipt_path"]).write_text(json.dumps(receipt))
        return result

    monkeypatch.setattr(audit, "execute_runtime_audit", missing_output)
    result = audit.execute_proof_agent(
        path,
        trust,
        pin,
        workspace,
        D,
        Path(".factory/runtime-audits"),
        mission_binding_path=Path(binding["path"]),
        mission_root=tmp_path,
        owner="release-owner",
        confirmation="RUN Proof Agent",
    )
    assert result["state"] == "INCOMPLETE" and not result["valid"]
    assert result["lanes"][0]["finding"] == "RUNTIME_AUDIT_EXECUTION_MISSING"


def test_execute_proof_agent_wall_includes_final_receipt_validation(
    tmp_path, monkeypatch
):
    import time
    import factoryline.runtime_audit as audit

    path, trust, pin, workspace, plan, binding = _proof_agent_fixture(tmp_path)
    clock = [100.0]
    receipt = {
        "decision": "READY_FOR_HUMAN_REVIEW",
        "receipt_sha256": D,
        "lanes": [{"lane": lane["kind"], "state": "PASS"} for lane in plan["lanes"]],
        "repair_queue": [],
    }
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        audit,
        "execute_runtime_audit",
        lambda *a, **kw: {
            "receipt": receipt,
            "receipt_path": ".factory/runtime-audits/unit/receipt.json",
        },
    )

    def final_validation(*args):
        clock[0] += binding["budgets"]["max_wall_seconds"] + 1
        return receipt

    monkeypatch.setattr(audit, "_proof_agent_receipt", final_validation)
    result = audit.execute_proof_agent(
        path,
        trust,
        pin,
        workspace,
        D,
        Path(".factory/runtime-audits"),
        mission_binding_path=Path(binding["path"]),
        mission_root=tmp_path,
        owner="release-owner",
        confirmation="RUN Proof Agent",
    )
    assert result["state"] == "INCOMPLETE" and not result["valid"]
    assert result["observed_wall_seconds"] == binding["budgets"]["max_wall_seconds"] + 1
    assert not result["within_wall_budget"]


@pytest.mark.parametrize("damage", ["persisted", "hash", "plan", "decision"])
def test_proof_agent_receipt_rechecks_child_proof(tmp_path, damage):
    from factoryline.runtime_audit import _proof_agent_receipt
    from factoryline.runtime_audit_contract import LANES

    receipt = {
        "schema": "factory.runtime-audit-receipt.v1",
        "candidate_sha256": D,
        "plan_payload_sha256": D,
        "decision": "READY_FOR_HUMAN_REVIEW",
        "lanes": [{"id": lane, "lane": lane, "state": "PASS"} for lane in LANES],
        "authority": "none",
        "release_approval": False,
    }
    if damage == "plan":
        receipt["plan_payload_sha256"] = "0" * 64
    if damage == "decision":
        receipt["lanes"][0]["state"] = "INCOMPLETE"
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    if damage == "hash":
        receipt["receipt_sha256"] = "0" * 64
    (tmp_path / "receipt.json").write_text(json.dumps(receipt))
    returned = json.loads(json.dumps(receipt))
    if damage == "persisted":
        returned["decision"] = "invented"
    with pytest.raises(RuntimeAuditError):
        _proof_agent_receipt(
            {"receipt_path": "receipt.json", "receipt": returned},
            {"payload_sha256": D, "plan": {"candidate_sha256": D}},
            tmp_path,
        )


@pytest.mark.parametrize("damage", ["confirmation", "owner", "source"])
def test_proof_agent_stops_before_dispatch_on_unapproved_or_stale_packet(
    tmp_path, monkeypatch, damage
):
    import factoryline.runtime_audit as audit
    from factoryline.product_missions import ProductMissionError

    path, trust, pin, workspace, _, binding = _proof_agent_fixture(tmp_path)
    monkeypatch.setattr(
        audit,
        "execute_runtime_audit",
        lambda *a, **kw: pytest.fail("unadmitted execution"),
    )
    if damage == "source":
        (workspace / "candidate.txt").write_text("changed")
    with pytest.raises((RuntimeAuditError, ProductMissionError)):
        audit.execute_proof_agent(
            path,
            trust,
            pin,
            workspace,
            D,
            Path(".factory/runtime-audits"),
            mission_binding_path=Path(binding["path"]),
            mission_root=tmp_path,
            owner="other" if damage == "owner" else "release-owner",
            confirmation="missing" if damage == "confirmation" else "RUN Proof Agent",
        )


@pytest.mark.parametrize(
    "damage,code",
    [
        ("commands", "E_PROOF_COMMAND_SCOPE"),
        ("sources", "E_PROOF_SCOPE"),
        ("profile", "E_PROOF_PROFILE"),
        ("policy", "E_PROOF_POLICY"),
        ("budget", "E_PROOF_BUDGET"),
    ],
)
def test_proof_agent_scope_requires_exact_commands_sources_and_budget(
    tmp_path, damage, code
):
    import copy
    from factoryline.runtime_audit import _proof_agent_scope

    path, trust, pin, workspace, _, binding = _proof_agent_fixture(tmp_path)
    verified = verify_runtime_audit_plan(
        path, trust, pin, workspace, D, require_intake=True
    )
    binding = copy.deepcopy(binding)
    if damage == "commands":
        binding["declaration"]["commands"][0]["argv"] = ["unapproved"]
    elif damage == "sources":
        binding["files"][0]["sha256"] = "0" * 64
    elif damage == "profile":
        binding["declaration"]["profiles"] = ["unrelated"]
    elif damage == "policy":
        verified["execution_policy"]["non_mutating"] = False
    else:
        binding["budgets"]["max_wall_seconds"] = 1
    with pytest.raises(RuntimeAuditError, match=code):
        _proof_agent_scope(binding, verified, workspace.resolve())


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
    failures = {
        lane["lane"]: (lane["state"], lane["finding"], lane["details"])
        for lane in receipt["lanes"]
        if lane["state"] != "PASS"
    }
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW", failures
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
    import socket
    import tracemalloc
    from types import SimpleNamespace
    from fixtures import runtime_six_lane_worker
    from fixtures.runtime_six_lane_worker import (
        Handler,
        digest,
        hashed_observation,
        http_cases,
        measured_run,
        process_memory_percent,
        wait_for_window,
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

    def unexpected_lookup(*_):
        raise AssertionError("loopback fixture must not perform a hostname lookup")

    monkeypatch.setattr(socket, "getfqdn", unexpected_lookup)
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
    clock = iter((0.0, 0.99, 1.001))
    sleeps = []
    monkeypatch.setattr(
        runtime_six_lane_worker,
        "time",
        SimpleNamespace(perf_counter=lambda: next(clock), sleep=sleeps.append),
    )
    assert wait_for_window(0) >= 1
    assert sleeps == pytest.approx([1, 0.01])


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

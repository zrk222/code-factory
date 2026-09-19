from __future__ import annotations

import json
from pathlib import Path

from factoryline.runtime_audit import (
    EVALUATORS,
    execute_runtime_audit,
    evaluate_runtime_audit,
    runtime_audit_status,
)
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes
from factoryline.runtime_audit_contract import LANES
from factoryline.runtime_attestation import capture_supervised_attestation


def _plan():
    return {
        "id": "p",
        "candidate_sha256": "c" * 64,
        "counterfactual_mesh": {
            "id": "shared",
            "scenario_sha256": "d" * 64,
            "relations": ["same_business_operation", "same_runtime_environment"],
            "origin": "human_confirmed",
        },
        "lanes": [
            {
                "id": kind,
                "kind": kind,
                "engine": "fixture",
                "engine_version": "1",
                "target_argv": ["fixture", "{artifact}"],
                "known_bad_argv": ["fixture", "bad", "{artifact}"],
                "timeout_seconds": 3,
                "expected_negative_code": f"NEG_{kind}",
                "config": {},
            }
            for kind in LANES
        ],
    }


def _command(kind, bad=False):
    artifact = {"kind": kind, "bad": bad, "scenario_sha256": "d" * 64}
    return {
        "artifact": artifact,
        "artifact_sha256": sha256_bytes(canonical_bytes(artifact)),
        "normalized_artifact_sha256": sha256_bytes(canonical_bytes(artifact)),
        "artifact_error": None,
        "execution": {
            "timed_out": False,
            "launch_error": False,
            "output_limit_exceeded": False,
            "cleanup_confirmed": True,
            "exit_code": 1 if bad else 0,
            "stdout_sha256": "0" * 64,
            "stderr_sha256": "0" * 64,
        },
    }


def test_six_lane_join_requires_real_negative_controls(monkeypatch, tmp_path):
    for kind in LANES:
        monkeypatch.setitem(
            EVALUATORS,
            kind,
            lambda artifact, config, engine, engine_version, k=kind: {
                "lane": k,
                "state": "FAIL" if artifact["bad"] else "PASS",
                "finding": f"NEG_{k}" if artifact["bad"] else "HELD",
                "consequence": "caught" if artifact["bad"] else "held",
                "details": {},
            },
        )
    executions = {
        "executions": [
            {
                "id": kind,
                "kind": kind,
                "target": _command(kind),
                "known_bad": _command(kind, True),
            }
            for kind in LANES
        ]
    }
    receipt = evaluate_runtime_audit(_plan(), executions, tmp_path)
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert len(receipt["lanes"]) == 6 and receipt["release_approval"] is False
    assert receipt["cross_lane_assurance"]["scenario_id"] == "shared"
    assert receipt["repair_queue"] == []
    assert receipt["fact_index"]["mutable"] is False
    keys = [item["key"] for item in receipt["fact_index"]["values"]]
    assert (
        len(keys) == 28
        and keys == sorted(keys)
        and "lane.tenant_isolation.finding" in keys
    )
    assert all("secret" not in key and "prompt" not in key for key in keys)
    executions["executions"][0]["known_bad"]["execution"]["exit_code"] = 0
    blocked = evaluate_runtime_audit(_plan(), executions, tmp_path)
    assert blocked["decision"] == "BLOCKED"
    assert blocked["lanes"][0]["finding"] == "HOLLOW_RUNTIME_AUDIT"
    assert blocked["repair_queue"][0]["lane"] == "stateful_invariant"


def test_cross_lane_scenario_mismatch_is_incomplete(monkeypatch, tmp_path):
    for kind in LANES:
        monkeypatch.setitem(
            EVALUATORS,
            kind,
            lambda artifact, config, engine, engine_version, k=kind: {
                "lane": k,
                "state": "FAIL" if artifact["bad"] else "PASS",
                "finding": f"NEG_{k}" if artifact["bad"] else "HELD",
                "consequence": "caught",
                "details": {},
            },
        )
    executions = {
        "executions": [
            {
                "id": kind,
                "kind": kind,
                "target": _command(kind),
                "known_bad": _command(kind, True),
            }
            for kind in LANES
        ]
    }
    executions["executions"][2]["target"]["artifact"]["scenario_sha256"] = "e" * 64
    receipt = evaluate_runtime_audit(_plan(), executions, tmp_path)
    lane = next(item for item in receipt["lanes"] if item["lane"] == "failure_recovery")
    assert lane["finding"] == "CROSS_LANE_SCENARIO_MISMATCH"
    assert receipt["decision"] == "BLOCKED"


def test_runtime_boundary_is_joined_without_promoting_supervision(
    monkeypatch, tmp_path
):
    for kind in LANES:
        monkeypatch.setitem(
            EVALUATORS,
            kind,
            lambda artifact, config, engine, engine_version, k=kind: {
                "lane": k,
                "state": "FAIL" if artifact["bad"] else "PASS",
                "finding": f"NEG_{k}" if artifact["bad"] else "HELD",
                "consequence": "caught",
                "details": {},
            },
        )
    plan = _plan()
    plan["environment"] = {
        "kind": "local_test",
        "digest": "e" * 64,
        "origins": ["http://127.0.0.1"],
    }
    plan["runtime_boundary"] = {
        "requested_isolation": "supervised_subprocess",
        "attestation_required": True,
    }
    executions = {
        "executions": [
            {
                "id": kind,
                "kind": kind,
                "target": _command(kind),
                "known_bad": _command(kind, True),
            }
            for kind in LANES
        ]
    }
    plan_digest = sha256_bytes(canonical_bytes(plan))
    executions["plan_sha256"] = plan_digest
    executions["runtime_boundary"] = capture_supervised_attestation(
        attestation_id="run",
        candidate_sha256=plan["candidate_sha256"],
        plan_sha256=plan_digest,
        environment_sha256=plan["environment"]["digest"],
    )
    receipt = evaluate_runtime_audit(plan, executions, tmp_path)
    assert receipt["decision"] == "READY_FOR_HUMAN_REVIEW"
    assert receipt["runtime_boundary"]["state"] == "SUPERVISED_ONLY"

    plan["runtime_boundary"]["requested_isolation"] = "hardened_vm"
    blocked = evaluate_runtime_audit(plan, executions, tmp_path)
    assert blocked["decision"] == "BLOCKED"
    assert blocked["runtime_boundary"]["finding"] == "E_ISOLATION_UNPROVEN"


def test_execute_runtime_audit_binds_verified_plan_digest(monkeypatch, tmp_path):
    plan = {"id": "plan", "candidate_sha256": "c" * 64}
    run_root = tmp_path / "run"
    run_root.mkdir()
    observed = {}

    def verify(*args, **kwargs):
        return {"plan": plan, "payload_sha256": "p" * 64}

    def run(current, workspace, output, *, plan_sha256=None):
        observed["plan_sha256"] = plan_sha256
        return {"run_root": str(run_root), "executions": [], "plan_sha256": plan_sha256}

    monkeypatch.setattr("factoryline.runtime_audit.verify_runtime_audit_plan", verify)
    monkeypatch.setattr("factoryline.runtime_audit.run_runtime_audit_plan", run)
    monkeypatch.setattr(
        "factoryline.runtime_audit.evaluate_runtime_audit",
        lambda current, execution, workspace: {
            "schema": "factory.runtime-audit-receipt.v1",
            "decision": "BLOCKED",
            "lanes": [],
            "authority": "none",
            "release_approval": False,
        },
    )
    result = execute_runtime_audit(
        tmp_path / "plan.json",
        tmp_path / "trust.json",
        "t" * 64,
        tmp_path,
        "e" * 64,
        run_root,
    )
    assert observed["plan_sha256"] == "p" * 64
    assert result["receipt_path"].endswith("runtime-audit-receipt.json")
    assert len(result["receipt"]["receipt_sha256"]) == 64


def test_status_rejects_tampered_receipt(tmp_path):
    run = tmp_path / ".factory/runtime-audits/run-x"
    run.mkdir(parents=True)
    payload = {
        "schema": "factory.runtime-audit-receipt.v1",
        "decision": "READY_FOR_HUMAN_REVIEW",
        "authority": "none",
        "release_approval": False,
        "lanes": [{"id": kind, "lane": kind, "state": "PASS"} for kind in LANES],
    }
    payload["receipt_sha256"] = sha256_bytes(canonical_bytes(payload))
    (run / "runtime-audit-receipt.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    assert runtime_audit_status(tmp_path)["state"] == "READY_FOR_HUMAN_REVIEW"
    payload["decision"] = "BLOCKED"
    (run / "runtime-audit-receipt.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    assert runtime_audit_status(tmp_path)["state"] == "INCOMPLETE"


def test_status_contains_receipt_stat_race(tmp_path, monkeypatch):
    run = tmp_path / ".factory/runtime-audits/run-x"
    run.mkdir(parents=True)
    receipt = run / "runtime-audit-receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    original = Path.stat

    def raced(path, *args, **kwargs):
        if path == receipt:
            raise FileNotFoundError(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", raced)
    assert runtime_audit_status(tmp_path)["state"] == "INCOMPLETE"

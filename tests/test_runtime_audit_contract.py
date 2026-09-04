from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from factoryline.enterprise_receipts import generate_key_material, sign_payload
from factoryline.runtime_audit_common import RuntimeAuditError, canonical_bytes, sha256_bytes
from factoryline.runtime_audit_contract import PLAN_SCHEMA, PLAN_TYPE, verify_runtime_audit_plan

D = hashlib.sha256(b"x").hexdigest()


def _configs():
    return {
        "stateful_invariant": {"invariant_ids": ["i"], "required_actions": ["a"], "min_examples": 2, "min_actions": 2},
        "tenant_isolation": {"forbidden_fields": ["tenant_id"], "denial_statuses": [403], "surfaces": [{"id": "api", "category": "api", "operation": "GET", "resource": "/x"}]},
        "failure_recovery": {"fault_modes": ["timeout"], "postconditions": [{"id": "p", "metric": "count", "operator": "eq", "value": 1}], "min_concurrency": 2, "max_attempts_per_key": 2},
        "consumer_compatibility": {"provider_version": "1", "provider_branch": "main", "environment": "test", "deployment_matrix_required": True, "interactions": [{"id": "i", "consumer_id": "c", "consumer_version": "1", "expected_sha256": D}]},
        "migration_integrity": {"before_schema_sha256": D, "expected_after_schema_sha256": D, "invariants": [{"id": "i", "expected_sha256": D}], "tables": [{"id": "t", "before": 1, "after": 1}], "recovery_strategy": "rollback", "required_catalog_objects": ["t_pkey"], "max_lock_wait_seconds": 1},
        "performance_regression": {"workload_sha256": D, "environment_sha256": D, "thresholds": [{"id": "p", "metric": "p95", "mode": "absolute", "operator": "lte", "value": 10, "origin": "human_confirmed"}], "resource_metrics": ["rss"], "minimum_resource_samples": 3, "max_retained_growth_ratio": .1, "max_loadgen_cpu_pct": 80, "max_loadgen_memory_pct": 80, "max_dropped_iterations": 0, "min_soak_seconds": 1, "min_cooldown_seconds": 1, "leak_engine": "runtime_metrics"},
    }


def signed_plan(tmp_path: Path):
    source = tmp_path / "candidate.txt"; source.write_text("candidate", encoding="utf-8")
    raw = source.read_bytes()
    sources = [{"path": "candidate.txt", "sha256": sha256_bytes(raw), "bytes": len(raw)}]
    engines = {"stateful_invariant": "hypothesis", "tenant_isolation": "runtime_http_matrix", "failure_recovery": "approved_fault_runner", "consumer_compatibility": "pact_verifier", "migration_integrity": "database_rehearsal", "performance_regression": "approved_load_runner"}
    now = datetime.now(timezone.utc)
    plan = {"schema": PLAN_SCHEMA, "id": "test-plan", "candidate_sha256": sha256_bytes(canonical_bytes(sources)), "issued_at": (now-timedelta(minutes=1)).isoformat(), "expires_at": (now+timedelta(hours=1)).isoformat(), "environment": {"kind": "local_test", "digest": D, "origins": ["http://127.0.0.1"]}, "sources": sources, "counterfactual_mesh": {"id": "checkout-retry", "scenario_sha256": D, "relations": ["same_business_operation", "same_runtime_environment"], "origin": "human_confirmed"}, "lanes": []}
    for kind, config in _configs().items():
        plan["lanes"].append({"id": kind.replace("_", "-"), "kind": kind, "engine": engines[kind], "engine_version": "1", "timeout_seconds": 5, "target_argv": ["python", "runner.py", kind, "{artifact}"], "known_bad_argv": ["python", "runner.py", kind, "bad", "{artifact}"], "expected_negative_code": {"stateful_invariant": "STATEFUL_INVARIANT_VIOLATION", "tenant_isolation": "TENANT_ISOLATION_VIOLATION", "failure_recovery": "RECOVERY_INVARIANT_VIOLATION", "consumer_compatibility": "CONSUMER_CONTRACT_BROKEN", "migration_integrity": "MIGRATION_INTEGRITY_VIOLATION", "performance_regression": "PERFORMANCE_OR_RESOURCE_REGRESSION"}[kind], "config": config})
    material = generate_key_material(out_dir=tmp_path/"keys", keyid="operator", identity="operator@example.test", issuer="https://issuer.example.test")
    envelope = sign_payload(plan, payload_type=PLAN_TYPE, private_key_path=Path(material["private_key"]), keyid=material["keyid"], identity=material["identity"], issuer=material["issuer"])
    plan_path = tmp_path/"plan.json"; plan_path.write_text(json.dumps(envelope), encoding="utf-8")
    trust = Path(material["trust_root"]); trust_sha = sha256_bytes(trust.read_bytes())
    return plan_path, trust, trust_sha, plan


def test_signed_plan_binds_six_lanes_sources_environment_and_authority(tmp_path):
    plan_path, trust, trust_sha, plan = signed_plan(tmp_path)
    result = verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    assert result["plan"] == plan and result["authority"] == "none"


def test_contract_rejects_environment_source_and_signature_drift(tmp_path):
    plan_path, trust, trust_sha, _ = signed_plan(tmp_path)
    with pytest.raises(RuntimeAuditError, match="E_ENVIRONMENT_DRIFT"):
        verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, "0"*64)
    (tmp_path/"candidate.txt").write_text("changed", encoding="utf-8")
    with pytest.raises(RuntimeAuditError, match="E_SOURCE_DRIFT"):
        verify_runtime_audit_plan(plan_path, trust, trust_sha, tmp_path, D)
    with pytest.raises(RuntimeAuditError, match="E_TRUST_ROOT_DRIFT"):
        verify_runtime_audit_plan(plan_path, trust, "0"*64, tmp_path, D)

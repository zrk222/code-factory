from __future__ import annotations

import copy
import hashlib

import pytest

from factoryline.runtime_audit_compatibility import evaluate_compatibility
from factoryline.runtime_audit_migration import evaluate_migration
from factoryline.runtime_audit_performance import evaluate_performance
from factoryline.runtime_audit_recovery import evaluate_recovery
from factoryline.runtime_audit_stateful import evaluate_stateful
from factoryline.runtime_audit_tenant import evaluate_tenant


D = hashlib.sha256(b"approved").hexdigest()
D2 = hashlib.sha256(b"candidate").hexdigest()


def test_stateful_requires_exercised_actions_and_catches_invariant_violation():
    config = {"invariant_ids": ["refund_lte_capture"], "required_actions": ["create", "cancel", "retry", "refund"], "min_examples": 10, "min_actions": 4}
    artifact = {"schema": "factory.runtime.stateful.v1", "engine": "hypothesis", "engine_version": "6.0", "examples": 20, "max_actions": 8, "seed": 7, "invariants": [{"id": "refund_lte_capture", "violations": 0, "trace": [], "checks": 20}], "action_counts": {name: 5 for name in config["required_actions"]}, "replay_stable": True, "examples_isolated": True}
    assert evaluate_stateful(artifact, config, engine="hypothesis", engine_version="6.0")["state"] == "PASS"
    bad = copy.deepcopy(artifact); bad["invariants"][0].update(violations=1, trace=["create", "refund", "retry"])
    assert evaluate_stateful(bad, config, engine="hypothesis", engine_version="6.0")["finding"] == "STATEFUL_INVARIANT_VIOLATION"
    hollow = copy.deepcopy(artifact); hollow["action_counts"]["refund"] = 0
    assert evaluate_stateful(hollow, config, engine="hypothesis", engine_version="6.0")["state"] == "INCOMPLETE"


def _tenant_fixture():
    surfaces = [
        {"id": "records", "category": "api", "operation": "GET", "resource": "/records/{id}"},
        {"id": "exports", "category": "export", "operation": "GENERATE", "resource": "customer-export"},
        {"id": "jobs", "category": "background_job", "operation": "RUN", "resource": "invoice-job"},
    ]
    config = {"forbidden_fields": ["email", "tenant_id"], "denial_statuses": [401, 403, 404], "surfaces": surfaces}
    cases = []
    for surface in surfaces:
        for phase in ("cold", "warm", "post_revocation"):
            for relation in ("owner", "cross_tenant", "anonymous", "revoked_session"):
                cases.append({"id": f"{surface['id']}-{phase}-{relation}", "surface_id": surface["id"], "phase": phase, "relation": relation, "status": 200 if relation == "owner" else 403, "tenant_data_sha256": D if relation == "owner" else None, "fields": ["email"] if relation == "owner" else [], "mutation_effect": False})
    return config, {"schema": "factory.runtime.tenant.v1", "engine": "runtime_http_matrix", "engine_version": "1", "cases": cases}


def test_tenant_covers_api_export_jobs_and_warm_revocation():
    config, artifact = _tenant_fixture()
    assert evaluate_tenant(artifact, config, engine="runtime_http_matrix", engine_version="1")["state"] == "PASS"
    bad = copy.deepcopy(artifact)
    victim = next(item for item in bad["cases"] if item["phase"] == "post_revocation" and item["relation"] == "revoked_session")
    victim.update(status=200, tenant_data_sha256=D, fields=["tenant_id"])
    assert evaluate_tenant(bad, config, engine="runtime_http_matrix", engine_version="1")["finding"] == "TENANT_ISOLATION_VIOLATION"


def test_failure_recovery_requires_faults_idempotency_cleanup_and_no_loss():
    config = {"fault_modes": ["timeout", "duplicate_delivery", "crash_after_effect"], "postconditions": [{"id": "balance", "metric": "balance", "operator": "eq", "value": 1}], "min_concurrency": 2, "max_attempts_per_key": 3}
    artifact = {"schema": "factory.runtime.recovery.v1", "engine": "approved_fault_runner", "engine_version": "1", "operations": [{"id": "a", "idempotency_key": "k", "effects": 1}, {"id": "b", "idempotency_key": "k", "effects": 0}], "fault_modes": config["fault_modes"], "phases": {"pre_fault": {"balance": 0}, "during_fault": {"balance": 1}, "recovered": {"balance": 1}}, "cleanup": {"attempted": True, "succeeded": True}, "max_concurrency": 2, "fault_observed": True, "lost_updates": 0}
    assert evaluate_recovery(artifact, config, engine="approved_fault_runner", engine_version="1")["state"] == "PASS"
    bad = copy.deepcopy(artifact); bad["operations"][1]["effects"] = 1
    assert evaluate_recovery(bad, config, engine="approved_fault_runner", engine_version="1")["finding"] == "RECOVERY_INVARIANT_VIOLATION"


def test_consumer_contract_requires_deployment_matrix_and_rejects_pending_failure():
    config = {"provider_version": "2.0.0", "provider_branch": "main", "environment": "test", "deployment_matrix_required": True, "interactions": [{"id": "mobile-v1", "consumer_id": "ios", "consumer_version": "1.0", "expected_sha256": D}]}
    artifact = {"schema": "factory.runtime.compatibility.v1", "engine": "pact_verifier", "engine_version": "2", "provider_version": "2.0.0", "provider_branch": "main", "environment": "test", "interactions": [{"id": "mobile-v1", "consumer_id": "ios", "consumer_version": "1.0", "actual_sha256": D, "provider_state_prepared": True, "request_exercised": True, "mismatch_count": 0, "pending": False}], "deployment_matrix": {"checked": True, "compatible": True, "missing_pairs": []}}
    assert evaluate_compatibility(artifact, config, engine="pact_verifier", engine_version="2")["state"] == "PASS"
    bad = copy.deepcopy(artifact); bad["interactions"][0].update(actual_sha256=D2, mismatch_count=1, pending=True)
    assert evaluate_compatibility(bad, config, engine="pact_verifier", engine_version="2")["state"] == "FAIL"


def test_migration_rehearsal_checks_catalog_locks_readers_and_recovery():
    config = {"before_schema_sha256": D, "expected_after_schema_sha256": D2, "invariants": [{"id": "sum", "expected_sha256": D}], "tables": [{"id": "orders", "before": 5, "after": 5}], "recovery_strategy": "forward_fix", "required_catalog_objects": ["orders_pkey", "orders_customer_idx"], "max_lock_wait_seconds": 1.5}
    artifact = {"schema": "factory.runtime.migration.v1", "engine": "database_rehearsal", "engine_version": "1", "isolated": True, "before_schema_sha256": D, "after_schema_sha256": D2, "history_valid": True, "drift_detected": False, "invariants": [{"id": "sum", "actual_sha256": D}], "record_counts": [{"table": "orders", "before": 5, "after": 5}], "integrity_violations": 0, "readers": {"old": True, "new": True}, "recovery": {"strategy": "forward_fix", "exercised": True, "succeeded": True}, "catalog_objects": config["required_catalog_objects"], "invalid_catalog_objects": [], "lock_wait_seconds": 0.2}
    assert evaluate_migration(artifact, config, engine="database_rehearsal", engine_version="1")["state"] == "PASS"
    bad = copy.deepcopy(artifact); bad["invalid_catalog_objects"] = ["orders_customer_idx"]
    assert evaluate_migration(bad, config, engine="database_rehearsal", engine_version="1")["finding"] == "MIGRATION_INTEGRITY_VIOLATION"


def test_performance_separates_authoritative_gates_retention_and_profiler_findings():
    config = {"workload_sha256": D, "environment_sha256": D2, "thresholds": [{"id": "p95", "metric": "p95_ms", "mode": "ratio", "operator": "lte", "value": 1.2, "origin": "human_confirmed"}, {"id": "idea", "metric": "rps", "mode": "absolute", "operator": "gte", "value": 80, "origin": "agent_proposed"}], "resource_metrics": ["rss_mb"], "minimum_resource_samples": 3, "max_retained_growth_ratio": .1, "max_loadgen_cpu_pct": 80, "max_loadgen_memory_pct": 80, "max_dropped_iterations": 0, "min_soak_seconds": 30, "min_cooldown_seconds": 10, "leak_engine": "python_tracemalloc"}
    run = lambda p95, rps: {"observations": 100, "metrics": {"p95_ms": p95, "rps": rps}, "workload_sha256": D, "environment_sha256": D2, "soak_seconds": 30, "cooldown_seconds": 10, "correctness_failures": 0}
    artifact = {"schema": "factory.runtime.performance.v1", "engine": "approved_load_runner", "engine_version": "1", "workload_sha256": D, "environment_sha256": D2, "baseline": run(100, 100), "candidate": run(110, 90), "resource_series": {"rss_mb": {"baseline": [100, 101, 100], "candidate": [100, 105, 106], "baseline_cooldown": [100, 100, 100], "candidate_cooldown": [101, 101, 101]}}, "load_generator": {"cpu_peak_pct": 50, "memory_peak_pct": 40, "dropped_iterations": 0}, "leak_check": {"engine": "python_tracemalloc", "findings": 0, "definitely_lost_bytes": 0, "exit_code": 0}}
    result = evaluate_performance(artifact, config, engine="approved_load_runner", engine_version="1")
    assert result["state"] == "PASS" and result["details"]["leak_claim"] == "no finding within declared profiler coverage"
    bad = copy.deepcopy(artifact); bad["candidate"]["metrics"]["p95_ms"] = 140
    assert evaluate_performance(bad, config, engine="approved_load_runner", engine_version="1")["finding"] == "PERFORMANCE_OR_RESOURCE_REGRESSION"


def test_malformed_or_self_declared_pass_fields_never_override_computation():
    config, artifact = _tenant_fixture()
    artifact["passed"] = True
    artifact["cases"][1]["status"] = 200
    assert evaluate_tenant(artifact, config, engine="runtime_http_matrix", engine_version="1")["state"] == "FAIL"
    with pytest.raises(Exception):
        evaluate_tenant({"passed": True}, config, engine="runtime_http_matrix", engine_version="1")

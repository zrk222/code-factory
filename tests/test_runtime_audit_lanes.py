from __future__ import annotations

import copy
import hashlib

from factoryline.runtime_audit_compatibility import evaluate_compatibility
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes
from factoryline.runtime_audit_migration import evaluate_migration
from factoryline.runtime_audit_performance import evaluate_performance
from factoryline.runtime_audit_recovery import evaluate_recovery
from factoryline.runtime_audit_stateful import evaluate_stateful
from factoryline.runtime_audit_tenant import evaluate_tenant


D = hashlib.sha256(b"approved").hexdigest()
D2 = hashlib.sha256(b"candidate").hexdigest()


def _observation_digest(observation, keys):
    return sha256_bytes(canonical_bytes({key: observation[key] for key in keys}))


def test_stateful_requires_exercised_actions_and_catches_invariant_violation():
    config = {
        "invariant_ids": ["refund_lte_capture"],
        "required_actions": ["create", "cancel", "retry", "refund"],
        "min_examples": 10,
        "min_actions": 4,
    }
    artifact = {
        "schema": "factory.runtime.stateful.v1",
        "engine": "hypothesis",
        "engine_version": "6.0",
        "examples": 20,
        "max_actions": 8,
        "seed": 7,
        "invariants": [
            {"id": "refund_lte_capture", "violations": 0, "trace": [], "checks": 20}
        ],
        "action_counts": {name: 5 for name in config["required_actions"]},
        "replay_stable": True,
        "examples_isolated": True,
    }
    assert (
        evaluate_stateful(artifact, config, engine="hypothesis", engine_version="6.0")[
            "state"
        ]
        == "PASS"
    )
    bad = copy.deepcopy(artifact)
    bad["invariants"][0].update(violations=1, trace=["create", "refund", "retry"])
    assert (
        evaluate_stateful(bad, config, engine="hypothesis", engine_version="6.0")[
            "finding"
        ]
        == "STATEFUL_INVARIANT_VIOLATION"
    )
    hollow = copy.deepcopy(artifact)
    hollow["action_counts"]["refund"] = 0
    assert (
        evaluate_stateful(hollow, config, engine="hypothesis", engine_version="6.0")[
            "state"
        ]
        == "INCOMPLETE"
    )
    unisolated = copy.deepcopy(artifact)
    unisolated["examples_isolated"] = False
    assert (
        evaluate_stateful(
            unisolated, config, engine="hypothesis", engine_version="6.0"
        )["finding"]
        == "STATEFUL_REPLAY_UNSTABLE"
    )
    unchecked = copy.deepcopy(artifact)
    unchecked["invariants"][0]["checks"] = 0
    assert (
        evaluate_stateful(unchecked, config, engine="hypothesis", engine_version="6.0")[
            "finding"
        ]
        == "STATEFUL_INVARIANT_UNEXERCISED"
    )
    sparsely_checked = copy.deepcopy(artifact)
    sparsely_checked["invariants"][0]["checks"] = 1
    assert (
        evaluate_stateful(
            sparsely_checked, config, engine="hypothesis", engine_version="6.0"
        )["finding"]
        == "STATEFUL_INVARIANT_UNEXERCISED"
    )
    overcounted = copy.deepcopy(artifact)
    overcounted["invariants"][0]["checks"] = 161
    assert (
        evaluate_stateful(
            overcounted, config, engine="hypothesis", engine_version="6.0"
        )["finding"]
        == "STATEFUL_OBSERVATION_CONTRADICTION"
    )
    malformed_trace = copy.deepcopy(artifact)
    malformed_trace["invariants"][0].update(violations=1, trace=[{"action": "refund"}])
    assert (
        evaluate_stateful(
            malformed_trace, config, engine="hypothesis", engine_version="6.0"
        )["finding"]
        == "STATEFUL_TRACE_INVALID"
    )


def _tenant_fixture():
    surfaces = [
        {
            "id": "records",
            "category": "api",
            "operation": "GET",
            "resource": "/records/{id}",
            "owner_data_sha256": D,
            "owner_required_fields": ["email"],
        },
        {
            "id": "exports",
            "category": "export",
            "operation": "GENERATE",
            "resource": "customer-export",
            "owner_data_sha256": D,
            "owner_required_fields": ["email"],
        },
        {
            "id": "jobs",
            "category": "background_job",
            "operation": "RUN",
            "resource": "invoice-job",
            "owner_data_sha256": D,
            "owner_required_fields": ["email"],
        },
    ]
    config = {
        "forbidden_fields": ["email", "tenant_id"],
        "denial_statuses": [401, 403, 404],
        "surfaces": surfaces,
    }
    cases = []
    for surface in surfaces:
        for phase in ("cold", "warm", "post_revocation"):
            for relation in ("owner", "cross_tenant", "anonymous", "revoked_session"):
                cases.append(
                    {
                        "id": f"{surface['id']}-{phase}-{relation}",
                        "surface_id": surface["id"],
                        "phase": phase,
                        "relation": relation,
                        "status": 200 if relation == "owner" else 403,
                        "tenant_data_sha256": D if relation == "owner" else None,
                        "fields": ["email"] if relation == "owner" else [],
                        "mutation_effect": False,
                    }
                )
    return config, {
        "schema": "factory.runtime.tenant.v1",
        "engine": "runtime_http_matrix",
        "engine_version": "1",
        "cases": cases,
    }


def test_tenant_covers_api_export_jobs_and_warm_revocation():
    config, artifact = _tenant_fixture()
    assert (
        evaluate_tenant(
            artifact, config, engine="runtime_http_matrix", engine_version="1"
        )["state"]
        == "PASS"
    )
    bad = copy.deepcopy(artifact)
    victim = next(
        item
        for item in bad["cases"]
        if item["phase"] == "post_revocation" and item["relation"] == "revoked_session"
    )
    victim.update(status=200, tenant_data_sha256=D, fields=["tenant_id"])
    assert (
        evaluate_tenant(bad, config, engine="runtime_http_matrix", engine_version="1")[
            "finding"
        ]
        == "TENANT_ISOLATION_VIOLATION"
    )
    missing_pair = copy.deepcopy(artifact)
    missing_pair["cases"].pop()
    assert (
        evaluate_tenant(
            missing_pair, config, engine="runtime_http_matrix", engine_version="1"
        )["finding"]
        == "TENANT_MATRIX_INCOMPLETE"
    )
    owner_denied = copy.deepcopy(artifact)
    owner_denied["cases"][0]["status"] = 403
    assert (
        evaluate_tenant(
            owner_denied, config, engine="runtime_http_matrix", engine_version="1"
        )["finding"]
        == "TENANT_ISOLATION_VIOLATION"
    )
    owner_empty = copy.deepcopy(artifact)
    owner_empty["cases"][0].update(tenant_data_sha256=None, fields=[])
    assert (
        evaluate_tenant(
            owner_empty, config, engine="runtime_http_matrix", engine_version="1"
        )["finding"]
        == "TENANT_ISOLATION_VIOLATION"
    )
    owner_wrong_digest = copy.deepcopy(artifact)
    owner_wrong_digest["cases"][0]["tenant_data_sha256"] = D2
    assert (
        evaluate_tenant(
            owner_wrong_digest, config, engine="runtime_http_matrix", engine_version="1"
        )["finding"]
        == "TENANT_ISOLATION_VIOLATION"
    )
    malformed_owner_fields = copy.deepcopy(artifact)
    malformed_owner_fields["cases"][0]["fields"] = [{"email": "unexpected"}]
    assert (
        evaluate_tenant(
            malformed_owner_fields,
            config,
            engine="runtime_http_matrix",
            engine_version="1",
        )["finding"]
        == "TENANT_FIELDS_INVALID"
    )


def test_failure_recovery_requires_faults_idempotency_cleanup_and_no_loss():
    config = {
        "fault_modes": ["timeout", "duplicate_delivery", "crash_after_effect"],
        "min_interleavings": 2,
        "postconditions": [
            {"id": "balance", "metric": "balance", "operator": "eq", "value": 1}
        ],
        "min_concurrency": 2,
        "max_attempts_per_key": 3,
    }
    artifact = {
        "schema": "factory.runtime.recovery.v2",
        "engine": "approved_fault_runner",
        "engine_version": "1",
        "operations": [
            {"id": "a", "idempotency_key": "k", "effects": 1},
            {"id": "b", "idempotency_key": "k", "effects": 0},
        ],
        "overlap_observations": [
            {
                "schedule_id": f"schedule-{index}",
                "operation_ids": ["a", "b"],
                "overlap_confirmed": True,
                "evidence_sha256": "",
            }
            for index in range(config["min_interleavings"])
        ],
        "fault_observations": [
            {
                "mode": mode,
                "observed": True,
                "phase": "during_fault",
                "operation_ids": ["a", "b"],
                "evidence_sha256": "",
            }
            for mode in config["fault_modes"]
        ],
        "phases": {
            "pre_fault": {"balance": 0},
            "during_fault": {"balance": 1},
            "recovered": {"balance": 1},
        },
        "cleanup": {"attempted": True, "succeeded": True},
        "max_concurrency": 2,
        "lost_updates": 0,
    }
    for observation in artifact["overlap_observations"]:
        observation["evidence_sha256"] = _observation_digest(
            observation, ("schedule_id", "operation_ids", "overlap_confirmed")
        )
    for observation in artifact["fault_observations"]:
        observation["evidence_sha256"] = _observation_digest(
            observation, ("mode", "observed", "phase", "operation_ids")
        )
    assert (
        evaluate_recovery(
            artifact, config, engine="approved_fault_runner", engine_version="1"
        )["state"]
        == "PASS"
    )
    bad = copy.deepcopy(artifact)
    bad["operations"][1]["effects"] = 1
    assert (
        evaluate_recovery(
            bad, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_INVARIANT_VIOLATION"
    )
    missing_fault = copy.deepcopy(artifact)
    missing_fault["fault_observations"].pop()
    assert (
        evaluate_recovery(
            missing_fault, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_FAULT_MISSING"
    )
    unobserved_fault = copy.deepcopy(artifact)
    unobserved_fault["fault_observations"][1]["observed"] = False
    unobserved_fault["fault_observations"][1]["evidence_sha256"] = _observation_digest(
        unobserved_fault["fault_observations"][1],
        ("mode", "observed", "phase", "operation_ids"),
    )
    assert (
        evaluate_recovery(
            unobserved_fault, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_FAULT_NOT_EXERCISED"
    )
    unbound_fault = copy.deepcopy(artifact)
    unbound_fault["fault_observations"][2]["operation_ids"] = ["unknown"]
    unbound_fault["fault_observations"][2]["evidence_sha256"] = _observation_digest(
        unbound_fault["fault_observations"][2],
        ("mode", "observed", "phase", "operation_ids"),
    )
    assert (
        evaluate_recovery(
            unbound_fault, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_FAULT_EVIDENCE_INVALID"
    )
    insufficient_schedules = copy.deepcopy(artifact)
    insufficient_schedules["overlap_observations"].pop()
    assert (
        evaluate_recovery(
            insufficient_schedules,
            config,
            engine="approved_fault_runner",
            engine_version="1",
        )["finding"]
        == "RECOVERY_RACE_COVERAGE_INCOMPLETE"
    )
    false_overlap = copy.deepcopy(artifact)
    false_overlap["overlap_observations"][0]["overlap_confirmed"] = False
    false_overlap["overlap_observations"][0]["evidence_sha256"] = _observation_digest(
        false_overlap["overlap_observations"][0],
        ("schedule_id", "operation_ids", "overlap_confirmed"),
    )
    assert (
        evaluate_recovery(
            false_overlap, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_RACE_NOT_EXERCISED"
    )
    cleanup_failed = copy.deepcopy(artifact)
    cleanup_failed["cleanup"]["succeeded"] = False
    assert (
        evaluate_recovery(
            cleanup_failed, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_INVARIANT_VIOLATION"
    )
    malformed_phase = copy.deepcopy(artifact)
    malformed_phase["phases"]["during_fault"] = ["timeout"]
    assert (
        evaluate_recovery(
            malformed_phase, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_PHASES_INVALID"
    )
    tampered_fault = copy.deepcopy(artifact)
    tampered_fault["fault_observations"][0]["operation_ids"] = ["a"]
    assert (
        evaluate_recovery(
            tampered_fault, config, engine="approved_fault_runner", engine_version="1"
        )["finding"]
        == "RECOVERY_FAULT_EVIDENCE_HASH_MISMATCH"
    )
    tampered_schedule = copy.deepcopy(artifact)
    tampered_schedule["overlap_observations"][0]["overlap_confirmed"] = False
    assert (
        evaluate_recovery(
            tampered_schedule,
            config,
            engine="approved_fault_runner",
            engine_version="1",
        )["finding"]
        == "RECOVERY_RACE_EVIDENCE_HASH_MISMATCH"
    )


def test_consumer_contract_requires_deployment_matrix_and_rejects_pending_failure():
    config = {
        "provider_version": "2.0.0",
        "provider_branch": "main",
        "environment": "test",
        "deployment_matrix_required": True,
        "interactions": [
            {
                "id": "mobile-v1",
                "consumer_id": "ios",
                "consumer_version": "1.0",
                "expected_sha256": D,
            }
        ],
    }
    artifact = {
        "schema": "factory.runtime.compatibility.v1",
        "engine": "pact_verifier",
        "engine_version": "2",
        "provider_version": "2.0.0",
        "provider_branch": "main",
        "environment": "test",
        "interactions": [
            {
                "id": "mobile-v1",
                "consumer_id": "ios",
                "consumer_version": "1.0",
                "actual_sha256": D,
                "provider_state_prepared": True,
                "request_exercised": True,
                "mismatch_count": 0,
                "pending": False,
            }
        ],
        "deployment_matrix": {"checked": True, "compatible": True, "missing_pairs": []},
    }
    assert (
        evaluate_compatibility(
            artifact, config, engine="pact_verifier", engine_version="2"
        )["state"]
        == "PASS"
    )
    bad = copy.deepcopy(artifact)
    bad["interactions"][0].update(actual_sha256=D2, mismatch_count=1, pending=True)
    assert (
        evaluate_compatibility(bad, config, engine="pact_verifier", engine_version="2")[
            "state"
        ]
        == "FAIL"
    )
    pending_only = copy.deepcopy(artifact)
    pending_only["interactions"][0]["pending"] = True
    assert (
        evaluate_compatibility(
            pending_only, config, engine="pact_verifier", engine_version="2"
        )["state"]
        == "FAIL"
    )
    missing_interaction = copy.deepcopy(artifact)
    missing_interaction["interactions"] = []
    assert (
        evaluate_compatibility(
            missing_interaction, config, engine="pact_verifier", engine_version="2"
        )["finding"]
        == "COMPATIBILITY_OBSERVATIONS_MISSING"
    )
    rejected_matrix = copy.deepcopy(artifact)
    rejected_matrix["deployment_matrix"]["compatible"] = False
    assert (
        evaluate_compatibility(
            rejected_matrix, config, engine="pact_verifier", engine_version="2"
        )["finding"]
        == "CONSUMER_CONTRACT_BROKEN"
    )


def test_migration_rehearsal_checks_catalog_locks_readers_and_recovery():
    config = {
        "before_schema_sha256": D,
        "expected_after_schema_sha256": D2,
        "invariants": [{"id": "sum", "expected_sha256": D}],
        "tables": [{"id": "orders", "before": 5, "after": 5}],
        "recovery_strategy": "forward_fix",
        "required_catalog_objects": ["orders_pkey", "orders_customer_idx"],
        "max_lock_wait_seconds": 1.5,
    }
    artifact = {
        "schema": "factory.runtime.migration.v1",
        "engine": "database_rehearsal",
        "engine_version": "1",
        "isolated": True,
        "before_schema_sha256": D,
        "after_schema_sha256": D2,
        "history_valid": True,
        "drift_detected": False,
        "invariants": [{"id": "sum", "actual_sha256": D}],
        "record_counts": [{"table": "orders", "before": 5, "after": 5}],
        "integrity_violations": 0,
        "readers": {"old": True, "new": True},
        "recovery": {"strategy": "forward_fix", "exercised": True, "succeeded": True},
        "catalog_objects": config["required_catalog_objects"],
        "invalid_catalog_objects": [],
        "lock_wait_seconds": 0.2,
    }
    assert (
        evaluate_migration(
            artifact, config, engine="database_rehearsal", engine_version="1"
        )["state"]
        == "PASS"
    )
    bad = copy.deepcopy(artifact)
    bad["invalid_catalog_objects"] = ["orders_customer_idx"]
    assert (
        evaluate_migration(
            bad, config, engine="database_rehearsal", engine_version="1"
        )["finding"]
        == "MIGRATION_INTEGRITY_VIOLATION"
    )
    unexpected = copy.deepcopy(artifact)
    unexpected["invariants"].append({"id": "unapproved", "actual_sha256": D})
    result = evaluate_migration(
        unexpected, config, engine="database_rehearsal", engine_version="1"
    )
    assert result["state"] == "FAIL" and result["details"]["unexpected_invariants"] == [
        "unapproved"
    ]
    old_reader = copy.deepcopy(artifact)
    old_reader["readers"]["old"] = False
    assert (
        evaluate_migration(
            old_reader, config, engine="database_rehearsal", engine_version="1"
        )["finding"]
        == "MIGRATION_INTEGRITY_VIOLATION"
    )
    lost_record = copy.deepcopy(artifact)
    lost_record["record_counts"][0]["after"] = 4
    assert (
        evaluate_migration(
            lost_record, config, engine="database_rehearsal", engine_version="1"
        )["finding"]
        == "MIGRATION_INTEGRITY_VIOLATION"
    )
    malformed_nested_count = copy.deepcopy(artifact)
    malformed_nested_count["record_counts"][0]["after"] = {"value": 5}
    assert (
        evaluate_migration(
            malformed_nested_count,
            config,
            engine="database_rehearsal",
            engine_version="1",
        )["state"]
        == "INCOMPLETE"
    )


def test_performance_separates_authoritative_gates_retention_and_profiler_findings():
    config = {
        "workload_sha256": D,
        "environment_sha256": D2,
        "thresholds": [
            {
                "id": "p95",
                "metric": "p95_ms",
                "mode": "ratio",
                "operator": "lte",
                "value": 1.2,
                "origin": "human_confirmed",
            },
            {
                "id": "idea",
                "metric": "rps",
                "mode": "absolute",
                "operator": "gte",
                "value": 80,
                "origin": "agent_proposed",
            },
        ],
        "resource_metrics": ["rss_mb"],
        "minimum_resource_samples": 3,
        "max_retained_growth_ratio": 0.1,
        "max_loadgen_cpu_pct": 80,
        "max_loadgen_memory_pct": 80,
        "max_dropped_iterations": 0,
        "min_soak_seconds": 30,
        "min_cooldown_seconds": 10,
        "leak_engine": "python_tracemalloc",
    }

    def run(p95, rps):
        return {
            "observations": 100,
            "metrics": {"p95_ms": p95, "rps": rps},
            "workload_sha256": D,
            "environment_sha256": D2,
            "soak_seconds": 30,
            "cooldown_seconds": 10,
            "correctness_failures": 0,
        }

    artifact = {
        "schema": "factory.runtime.performance.v1",
        "engine": "approved_load_runner",
        "engine_version": "1",
        "workload_sha256": D,
        "environment_sha256": D2,
        "baseline": run(100, 100),
        "candidate": run(110, 90),
        "resource_series": {
            "rss_mb": {
                "baseline": [100, 101, 100],
                "candidate": [100, 105, 106],
                "baseline_cooldown": [100, 100, 100],
                "candidate_cooldown": [101, 101, 101],
            }
        },
        "load_generator": {
            "cpu_peak_pct": 50,
            "memory_peak_pct": 40,
            "dropped_iterations": 0,
        },
        "leak_check": {
            "engine": "python_tracemalloc",
            "findings": 0,
            "definitely_lost_bytes": 0,
            "exit_code": 0,
        },
    }
    result = evaluate_performance(
        artifact, config, engine="approved_load_runner", engine_version="1"
    )
    assert (
        result["state"] == "PASS"
        and result["details"]["leak_claim"]
        == "no finding within declared profiler coverage"
    )
    bad = copy.deepcopy(artifact)
    bad["candidate"]["metrics"]["p95_ms"] = 140
    assert (
        evaluate_performance(
            bad, config, engine="approved_load_runner", engine_version="1"
        )["finding"]
        == "PERFORMANCE_OR_RESOURCE_REGRESSION"
    )
    advisory_only = copy.deepcopy(config)
    advisory_only["thresholds"][0]["origin"] = "agent_proposed"
    assert (
        evaluate_performance(
            artifact, advisory_only, engine="approved_load_runner", engine_version="1"
        )["finding"]
        == "PERFORMANCE_AUTHORITY_MISSING"
    )
    wrong_workload = copy.deepcopy(artifact)
    wrong_workload["candidate"]["workload_sha256"] = D2
    assert (
        evaluate_performance(
            wrong_workload, config, engine="approved_load_runner", engine_version="1"
        )["finding"]
        == "PERFORMANCE_COMPARISON_NOT_EQUIVALENT"
    )
    malformed_nested_metric = copy.deepcopy(artifact)
    malformed_nested_metric["candidate"]["metrics"]["p95_ms"] = {"value": 110}
    assert (
        evaluate_performance(
            malformed_nested_metric,
            config,
            engine="approved_load_runner",
            engine_version="1",
        )["state"]
        == "INCOMPLETE"
    )


def test_malformed_or_self_declared_pass_fields_never_override_computation():
    config, artifact = _tenant_fixture()
    artifact["passed"] = True
    artifact["cases"][1]["status"] = 200
    assert (
        evaluate_tenant(
            artifact, config, engine="runtime_http_matrix", engine_version="1"
        )["state"]
        == "FAIL"
    )
    malformed = evaluate_tenant(
        {"passed": True}, config, engine="runtime_http_matrix", engine_version="1"
    )
    assert malformed["state"] == "INCOMPLETE"
    assert malformed["finding"] == "E_ARTIFACT_FIELDS"
    assert malformed["details"] == {"error_code": "E_ARTIFACT_FIELDS"}

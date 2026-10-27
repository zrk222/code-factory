import pytest
from factoryline.runtime_audit_stateful import evaluate_stateful
from factoryline.runtime_audit_recovery import evaluate_recovery
from factoryline.runtime_audit_common import canonical_bytes, sha256_bytes
from hypothesis import settings
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)
import copy
import hashlib
from factoryline.runtime_audit_compatibility import evaluate_compatibility
from factoryline.runtime_audit_migration import evaluate_migration
from factoryline.runtime_audit_performance import evaluate_performance
from factoryline.runtime_audit_tenant import evaluate_tenant
from pathlib import Path
import json
from factoryline.ide_playbook import ide_playbook
from factoryline.mcp import dispatch
from factoryline.mission_control_status import (
    mission_control_status,
    prepare_security_scan_receipt_report,
    security_scan_status,
    security_scan_pytest_collection_snapshot,
    write_security_scan_receipt,
)


def evidence_digest(observation, fields):
    return sha256_bytes(canonical_bytes({key: observation[key] for key in fields}))


def stateful():
    config = {
        "invariant_ids": ["balance"],
        "required_actions": ["create", "refund"],
        "min_examples": 2,
        "min_actions": 2,
    }
    artifact = {
        "schema": "factory.runtime.stateful.v1",
        "engine": "hypothesis",
        "engine_version": "6",
        "examples": 2,
        "max_actions": 2,
        "seed": 0,
        "invariants": [{"id": "balance", "violations": 0, "checks": 2, "trace": []}],
        "action_counts": {"create": 2, "refund": 2},
        "replay_stable": True,
        "examples_isolated": True,
    }
    return artifact, config


@pytest.mark.parametrize("mutation", ["actions", "checks", "trace"])
def test_stateful_contradictions_cannot_pass(mutation):
    artifact, config = stateful()
    if mutation == "actions":
        artifact["action_counts"]["create"] = 3
    elif mutation == "checks":
        artifact["invariants"][0].update(violations=3, trace=["create", "refund"])
    else:
        artifact["invariants"][0].update(
            violations=1, trace=["create", "refund", "refund"]
        )
    result = evaluate_stateful(
        artifact, config, engine="hypothesis", engine_version="6"
    )
    assert result["state"] == "INCOMPLETE"
    assert result["finding"] == "STATEFUL_OBSERVATION_CONTRADICTION"


def test_equal_bounds_remain_valid_and_real_failures_are_preserved():
    artifact, config = stateful()
    assert (
        evaluate_stateful(artifact, config, engine="hypothesis", engine_version="6")[
            "state"
        ]
        == "PASS"
    )
    artifact["invariants"][0].update(violations=2, trace=["create", "refund"])
    result = evaluate_stateful(
        artifact, config, engine="hypothesis", engine_version="6"
    )
    assert result["state"] == "FAIL"
    assert result["finding"] == "STATEFUL_INVARIANT_VIOLATION"


@pytest.mark.parametrize("concurrency,expected", [(2, "PASS"), (3, "INCOMPLETE")])
def test_concurrency_requires_enough_observed_operations(concurrency, expected):
    config = {
        "fault_modes": ["timeout"],
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
                "schedule_id": "schedule-1",
                "operation_ids": ["a", "b"],
                "overlap_confirmed": True,
                "evidence_sha256": "",
            },
            {
                "schedule_id": "schedule-2",
                "operation_ids": ["a", "b"],
                "overlap_confirmed": True,
                "evidence_sha256": "",
            },
        ],
        "fault_observations": [
            {
                "mode": "timeout",
                "observed": True,
                "phase": "during_fault",
                "operation_ids": ["a", "b"],
                "evidence_sha256": "",
            }
        ],
        "phases": {"pre_fault": {}, "during_fault": {}, "recovered": {"balance": 1}},
        "cleanup": {"attempted": True, "succeeded": True},
        "max_concurrency": concurrency,
        "lost_updates": 0,
    }
    for observation in artifact["overlap_observations"]:
        observation["evidence_sha256"] = evidence_digest(
            observation, ("schedule_id", "operation_ids", "overlap_confirmed")
        )
    for observation in artifact["fault_observations"]:
        observation["evidence_sha256"] = evidence_digest(
            observation, ("mode", "observed", "phase", "operation_ids")
        )
    result = evaluate_recovery(
        artifact, config, engine="approved_fault_runner", engine_version="1"
    )
    assert result["state"] == expected
    if expected == "INCOMPLETE":
        assert result["finding"] == "RECOVERY_OBSERVATION_CONTRADICTION"


def test_native_fixture_placeholder_requires_signed_path_binding(tmp_path):
    from factoryline.runtime_audit_common import (
        _render_profile_argv,
        _validate_native_bindings,
        RuntimeAuditError,
    )
    import pytest

    source, scratch = tmp_path / "source", tmp_path / "run"
    report, ledger = scratch / "report.json", scratch / "corpus.json"
    config, fixture = tmp_path / "config.json", source / "positive.py"
    values = {
        "source": str(source),
        "output": str(scratch),
        "report": str(report),
        "scratch": str(scratch),
        "factory_ledger": str(ledger),
        "config": str(config),
        "candidate_sha256": "a" * 64,
        "fixture": str(fixture),
    }
    evidence = {"challenge_source_sha256": "a" * 64}
    _validate_native_bindings(
        values, source, scratch, report, ledger, config, evidence, fixture=fixture
    )
    assert _render_profile_argv(["python", "{fixture}", "{config}"], values) == [
        "python",
        str(fixture),
        str(config),
    ]
    with pytest.raises(RuntimeAuditError):
        _validate_native_bindings(
            values, source, scratch, report, ledger, config, evidence
        )
    values["fixture"] = str(source / "other.py")
    with pytest.raises(RuntimeAuditError):
        _validate_native_bindings(
            values, source, scratch, report, ledger, config, evidence, fixture=fixture
        )


# --- Merged from test_runtime_audit_lanes.py; test definitions and fixtures retained ---


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


class SafePayments(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.captured = 0
        self.refunded = 0

    @rule()
    def capture(self):
        self.captured = 10

    @precondition(lambda self: self.captured > self.refunded)
    @rule()
    def refund(self):
        self.refunded += min(6, self.captured - self.refunded)

    @invariant()
    def refund_never_exceeds_capture(self):
        assert self.refunded <= self.captured


class BrokenPayments(SafePayments):
    @precondition(lambda self: self.captured > 0)
    @rule()
    def duplicate_refund(self):
        self.refunded += 6


def test_native_hypothesis_control_accepts_safe_and_kills_known_bad_machine():
    profile = settings(
        max_examples=30, stateful_step_count=12, derandomize=True, deadline=None
    )
    run_state_machine_as_test(SafePayments, settings=profile)
    with pytest.raises(AssertionError):
        run_state_machine_as_test(BrokenPayments, settings=profile)


# --- Merged from test_runtime_audit_surfaces.py; test definitions and fixtures retained ---


def _complete_security_scan_receipt(root: Path, *, body="pass"):
    from factoryline.review_audits import _seal_security_scan, security_scan

    before_collection = security_scan_pytest_collection_snapshot(root)
    (root / ".factory").mkdir(exist_ok=True)
    contract = root / ".factory" / "tenant-read-contract.json"
    contract.write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (root / "test_case.py").write_text(
        f"def test_hollow():\n    {body}\n", encoding="utf-8"
    )
    report = security_scan(root)
    report["tenant_read_contract"]["configuration"] = {
        "path": ".factory/tenant-read-contract.json",
        "sha256": __import__("hashlib").sha256(contract.read_bytes()).hexdigest(),
        "bytes": contract.stat().st_size,
        "state": "loaded",
    }
    report = _seal_security_scan(report)
    report = prepare_security_scan_receipt_report(root, report, before_collection)
    return write_security_scan_receipt(root, report)


def test_runtime_assurance_is_visible_to_agents_humans_and_mcp(tmp_path: Path):
    playbook = ide_playbook()
    pack = next(
        item
        for item in playbook["capability_packs"]
        if item["id"] == "runtime_assurance"
    )
    assert pack["next"] == "factory.runtime_audit_status"
    mission = mission_control_status(tmp_path)
    assert mission["evidence"]["runtime_assurance"]["state"] == "NOT_RUN"
    inventory = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, tmp_path)
    assert "factory.runtime_audit_status" in [
        item["name"] for item in inventory["result"]["tools"]
    ]
    call = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "factory.runtime_audit_status"},
        },
        tmp_path,
    )
    assert call["result"]["content"][0]["text"].find("RUNTIME_AUDIT_MCP_READ_ONLY") >= 0


def test_graph_ops_ui_shows_six_lanes_and_actionable_output():
    html = Path("factoryline/graph_ops.html").read_text(encoding="utf-8")
    assert "RUNTIME_ASSURANCE_SIX_LANES" in html
    for label in (
        "Stateful workflows",
        "Tenant isolation",
        "Failure recovery",
        "Consumer compatibility",
        "Migration integrity",
        "Performance + memory",
    ):
        assert label in html
    assert "Next repair:" in html


def test_completed_runtime_assurance_routes_to_named_human_review(
    tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        "factoryline.mission_control_status.runtime_audit_status",
        lambda _root: {"state": "READY_FOR_HUMAN_REVIEW"},
    )
    mission = mission_control_status(tmp_path)
    assert mission["state"] == "review_required"
    assert mission["human_control_plane"]["review_required"] is True


def test_security_scan_receipt_is_current_hash_bound_and_advisory(tmp_path: Path):
    receipt = _complete_security_scan_receipt(tmp_path)

    status = security_scan_status(tmp_path)
    mission = mission_control_status(tmp_path)
    audit = mission["evidence"]["implementation_audit"]

    assert receipt["receipt_sha256"] == status["receipt_sha256"]
    assert status["state"] == "FINDINGS"
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"
    assert status["authority"]["execution"] is False
    assert status["verification"] == "local_self_hash_only_not_signature_or_approval"
    assert any(item["code"] == "QUALITY_HOLLOW_TEST" for item in status["findings"])
    probe = next(
        item["native_assertion_probe"]
        for item in status["findings"]
        if item.get("native_assertion_probe")
    )
    assert probe["available"] is False
    assert audit["receipt_sha256"] == status["receipt_sha256"]

    (tmp_path / "test_case.py").write_text(
        "def test_hollow():\n    changed_operation()\n", encoding="utf-8"
    )
    stale = security_scan_status(tmp_path)
    assert stale["state"] == "INCOMPLETE"
    assert stale["candidate_freshness"] == "SOURCE_HASH_MISMATCH"
    assert any(item["code"] == "QUALITY_HOLLOW_TEST" for item in stale["findings"])


@pytest.mark.parametrize(
    "policy", ["source-role-v1", "source-role-v2", "source-role-v3"]
)
@pytest.mark.parametrize("tenant_loaded", [False, True])
def test_source_role_review_required_receipt_is_advisory(
    tmp_path: Path, capsys, policy, tenant_loaded
):
    from factoryline import review_audits
    from factoryline.cli import main

    source = tmp_path / "app.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    if tenant_loaded:
        (tmp_path / ".factory").mkdir()
        (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
            json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
            encoding="utf-8",
        )
    with review_audits._security_only_scan_context(True):
        exit_code = main(
            [
                "audit",
                "security",
                "--root",
                str(tmp_path),
                "--defect-policy",
                policy,
                "--json",
            ]
        )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["state"] == "REVIEW_REQUIRED"
    assert report["findings"] == []
    decision = report["defect_policy_decision"]
    assert not any(decision[key] for key in ("clean", "passed", "release_approved"))
    status = security_scan_status(tmp_path)
    assert status["report_state"] == "REVIEW_REQUIRED"
    assert status["state"] == ("REVIEW_REQUIRED" if tenant_loaded else "INCOMPLETE")
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"
    assert status["authority"] == {
        "execution": False,
        "approval": False,
        "repair": False,
    }

    source.write_text("VALUE = 2\n", encoding="utf-8")
    stale = security_scan_status(tmp_path)
    assert stale["state"] == "INCOMPLETE"
    assert stale["report_state"] == "REVIEW_REQUIRED"
    assert stale["candidate_freshness"] == "SOURCE_HASH_MISMATCH"


def test_security_scan_receipt_rejects_unknown_state(tmp_path: Path):
    from factoryline.deep_audit_io import canonical_bytes, digest
    from factoryline.review_audits import _seal_security_scan

    _complete_security_scan_receipt(tmp_path)
    path = tmp_path / ".factory" / "security-scan" / "latest.json"
    envelope = json.loads(path.read_bytes())
    envelope["report"]["state"] = "NOT_A_SCAN_STATE"
    envelope["report"] = _seal_security_scan(envelope["report"])
    envelope["receipt_sha256"] = digest(
        {key: value for key, value in envelope.items() if key != "receipt_sha256"}
    )
    path.write_bytes(canonical_bytes(envelope))
    status = security_scan_status(tmp_path)
    assert status["state"] == "INVALID"
    assert status["reason"] == "scan state is invalid"


def test_security_scan_source_removed_after_receipt_is_incomplete(tmp_path: Path):
    _complete_security_scan_receipt(tmp_path)
    (tmp_path / "test_case.py").unlink()

    status = security_scan_status(tmp_path)

    assert status["state"] == "INCOMPLETE"
    assert status["candidate_freshness"] == "SOURCE_INVENTORY_MISMATCH"
    assert status["incomplete"] is True


def test_security_scan_receipt_rejects_finding_count_mismatch(tmp_path: Path):
    from factoryline.deep_audit_io import canonical_bytes, digest
    from factoryline.review_audits import _seal_security_scan

    _complete_security_scan_receipt(tmp_path)
    receipt_path = tmp_path / ".factory" / "security-scan" / "latest.json"
    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    envelope["report"]["finding_counts"] = {}
    envelope["report"] = _seal_security_scan(envelope["report"])
    unsigned = {
        key: value for key, value in envelope.items() if key != "receipt_sha256"
    }
    envelope["receipt_sha256"] = digest(unsigned)
    receipt_path.write_bytes(canonical_bytes(envelope))

    status = security_scan_status(tmp_path)

    assert status["state"] == "INVALID"
    assert status["reason"] == "finding count mismatch"


def test_security_scan_receipt_rejects_clean_state_with_findings(tmp_path: Path):
    from factoryline.deep_audit_io import canonical_bytes, digest
    from factoryline.review_audits import _seal_security_scan

    _complete_security_scan_receipt(tmp_path)
    receipt_path = tmp_path / ".factory" / "security-scan" / "latest.json"
    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    envelope["report"]["state"] = "CLEAN"
    envelope["report"] = _seal_security_scan(envelope["report"])
    unsigned = {
        key: value for key, value in envelope.items() if key != "receipt_sha256"
    }
    envelope["receipt_sha256"] = digest(unsigned)
    receipt_path.write_bytes(canonical_bytes(envelope))

    status = security_scan_status(tmp_path)

    assert status["state"] == "INVALID"
    assert status["reason"] == "clean scan contains findings"


def test_security_scan_receipt_detects_new_higher_priority_pytest_config(
    tmp_path: Path,
):
    from factoryline.review_audits import _seal_security_scan, security_scan

    (tmp_path / ".factory").mkdir()
    contract = tmp_path / ".factory" / "tenant-read-contract.json"
    contract.write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n", encoding="utf-8"
    )
    (tmp_path / "test_case.py").write_text(
        "def test_hollow():\n    pass\n", encoding="utf-8"
    )
    before_collection = security_scan_pytest_collection_snapshot(tmp_path)
    report = security_scan(tmp_path)
    report["tenant_read_contract"]["configuration"] = {
        "path": ".factory/tenant-read-contract.json",
        "sha256": __import__("hashlib").sha256(contract.read_bytes()).hexdigest(),
        "bytes": contract.stat().st_size,
        "state": "loaded",
    }
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\npython_files = test_*.py\n", encoding="utf-8"
    )
    report = prepare_security_scan_receipt_report(
        tmp_path, _seal_security_scan(report), before_collection
    )
    write_security_scan_receipt(tmp_path, report)

    status = security_scan_status(tmp_path)

    assert before_collection["path"] == "pyproject.toml"
    assert status["state"] == "INCOMPLETE"
    assert status["report_state"] == "INCOMPLETE"
    assert status["candidate_freshness"] == "PYTEST_COLLECTION_CHANGED_DURING_SCAN"
    assert any(item["code"] == "QUALITY_HOLLOW_TEST" for item in status["findings"])


def test_security_scan_receipt_missing_invalid_and_incomplete_are_never_clean(
    tmp_path: Path,
):
    assert security_scan_status(tmp_path)["state"] == "NOT_RUN"

    receipt_path = tmp_path / ".factory" / "security-scan" / "latest.json"
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_text("{not-json", encoding="utf-8")
    assert security_scan_status(tmp_path)["state"] == "INVALID"

    receipt_path.unlink()
    _complete_security_scan_receipt(tmp_path)
    envelope = json.loads(receipt_path.read_text(encoding="utf-8"))
    envelope["report"]["audit_coverage"]["complete"] = False
    from factoryline.deep_audit_io import canonical_bytes, digest

    from factoryline.review_audits import _seal_security_scan

    envelope["report"] = _seal_security_scan(envelope["report"])
    unsigned = {
        key: value for key, value in envelope.items() if key != "receipt_sha256"
    }
    envelope["receipt_sha256"] = digest(unsigned)
    receipt_path.write_bytes(canonical_bytes(envelope))
    incomplete = security_scan_status(tmp_path)
    assert incomplete["state"] == "INCOMPLETE"
    assert incomplete["incomplete"] is True
    assert incomplete["output_truncated"] is False


def test_security_scan_projection_bounds_findings_and_probe_advice(tmp_path: Path):
    from factoryline.review_audits import _seal_security_scan, security_scan

    before_collection = security_scan_pytest_collection_snapshot(tmp_path)
    (tmp_path / ".factory").mkdir()
    contract = tmp_path / ".factory" / "tenant-read-contract.json"
    contract.write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    tests = "\n".join(f"def test_hollow_{i}():\n    operation_{i}()" for i in range(28))
    (tmp_path / "test_cases.py").write_text(tests + "\n", encoding="utf-8")
    report = security_scan(tmp_path)
    report["tenant_read_contract"]["configuration"] = {
        "path": ".factory/tenant-read-contract.json",
        "sha256": __import__("hashlib").sha256(contract.read_bytes()).hexdigest(),
        "bytes": contract.stat().st_size,
        "state": "loaded",
    }
    report = prepare_security_scan_receipt_report(
        tmp_path, _seal_security_scan(report), before_collection
    )
    write_security_scan_receipt(tmp_path, report)

    status = security_scan_status(tmp_path)
    assert status["finding_count"] == 28
    assert len(status["findings"]) == 24
    assert status["display_truncated"] is True
    assert status["findings_truncated"] is True
    assert status["findings"][0]["native_assertion_probe"]["call_available"] is True


def test_security_scan_receipt_is_visible_in_graph_ops_ui_without_html_injection():
    html = Path("factoryline/graph_ops.html").read_text(encoding="utf-8")

    assert 'id="security-scan-panel"' in html
    assert 'id="security-scan-findings"' in html
    assert "renderSecurityScanReceipt(payload)" in html
    start = html.index("function renderSecurityScanReceipt(payload)")
    end = html.index("function renderAuditResults(payload)", start)
    renderer = html[start:end]
    assert "addText(" in renderer
    assert "innerHTML" not in renderer
    assert "native_assertion_probe" in renderer
    assert "output_truncated" in renderer
    assert "display_truncated" in renderer
    assert "security-scan-detail" in renderer


def test_security_scan_cli_writes_receipt_consumed_by_mission_control(
    tmp_path: Path, capsys
):
    from factoryline.cli import main

    factory = tmp_path / ".factory"
    factory.mkdir()
    (factory / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "def test_addition():\n    assert 1 + 1 == 2\n", encoding="utf-8"
    )

    exit_code = main(["audit", "security", "--root", str(tmp_path), "--json"])
    capsys.readouterr()

    receipt = tmp_path / ".factory" / "security-scan" / "latest.json"
    assert exit_code in {0, 1}
    assert receipt.is_file()
    status = security_scan_status(tmp_path)
    assert status["state"] in {"CLEAN", "FINDINGS"}
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"


def test_security_scan_cli_write_failure_is_bounded_and_does_not_leak_path(
    tmp_path: Path, monkeypatch, capsys
):
    from factoryline.cli import main

    factory = tmp_path / ".factory"
    factory.mkdir()
    (factory / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    (tmp_path / "test_case.py").write_text(
        "def test_addition():\n    assert 1 + 1 == 2\n", encoding="utf-8"
    )

    def fail_write(_root, _report):
        raise OSError(f"permission denied: {tmp_path / 'private-host-path'}")

    monkeypatch.setattr(
        "factoryline.mission_control_status.write_security_scan_receipt", fail_write
    )
    exit_code = main(["audit", "security", "--root", str(tmp_path), "--json"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert '"state": "INVALID"' in captured.err
    assert str(tmp_path) not in captured.err
    assert "private-host-path" not in captured.err


def test_security_scan_receipt_preserves_undefined_call_incompleteness(tmp_path):
    # Receipt transport cannot upgrade a source-unknown invocation into HOLLOW.
    _complete_security_scan_receipt(tmp_path, body="operation()")
    status = security_scan_status(tmp_path)
    assert status["state"] == "INCOMPLETE"
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"
    assert any(
        item["code"] == "QUALITY_UNKNOWN_TEST_ORACLE" for item in status["findings"]
    )
    assert not any(item["code"] == "QUALITY_HOLLOW_TEST" for item in status["findings"])


@pytest.mark.parametrize("policy", ["legacy-v1", "source-role-v3"])
@pytest.mark.parametrize("hook_file", ["conftest.py", "test_case.py"])
@pytest.mark.parametrize("mutation", ["hook", "config", "source"])
def test_security_only_unknown_collection_cli_receipt(
    tmp_path, capsys, policy, hook_file, mutation
):
    from factoryline.cli import main

    hook = tmp_path / hook_file
    hook.write_text(
        "pytest_plugins = ['external_plugin']\nraise AssertionError('must not execute')\n",
        encoding="utf-8",
    )
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\npython_files = test_*.py\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("def apply(program):\n    exec(program)\n", encoding="utf-8")
    (tmp_path / ".factory").mkdir()
    (tmp_path / ".factory" / "tenant-read-contract.json").write_text(
        json.dumps({"schema": "factory.tenant-read-contract.v1", "reads": []}),
        encoding="utf-8",
    )
    exit_code = main(
        [
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            policy,
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert exit_code == 2 and report["state"] == "INCOMPLETE"
    identity = report["oracle_context"]["pytest_collection"]
    assert identity["capture_state"] == "stable_pre_post"
    assert identity["collection_state"] == "UNKNOWN"
    assert identity["patterns"] == []
    assert (
        report["oracle_context"]["test_oracle_assessment"]
        == "NOT_ASSESSED_SECURITY_ONLY"
    )
    assert report["audit_coverage"]["complete"] is True
    assert any(
        row["code"] == "SECURITY_DYNAMIC_EXECUTION" for row in report["findings"]
    )
    assert not any(row["code"].startswith("QUALITY_") for row in report["findings"])
    status = security_scan_status(tmp_path)
    assert status["state"] == "INCOMPLETE"
    assert status["candidate_freshness"] == "PYTEST_COLLECTION_UNKNOWN"
    assert status["source_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"
    assert status["authority"] == {
        "execution": False,
        "approval": False,
        "repair": False,
    }
    changed = {"hook": hook, "config": config, "source": source}[mutation]
    changed.write_text(
        changed.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8"
    )
    stale = security_scan_status(tmp_path)
    assert stale["state"] == "INCOMPLETE"
    assert stale["source_freshness"] != "CURRENT_SOURCE_HASHES_VERIFIED"


@pytest.mark.parametrize(
    "argv",
    [
        ["audit", "patterns", "--security-only", "--json"],
        ["audit", "security", "--security-only", "--full-repository", "--json"],
    ],
)
def test_security_only_unknown_collection_rejects_wrong_scope(capsys, argv):
    from factoryline.cli import main

    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err)["code"] == "E_SECURITY_ONLY_SCOPE"


@pytest.mark.parametrize(
    "policy",
    [
        "legacy-v1",
        "trusted-core-v1",
        "source-role-v1",
        "source-role-v2",
        "source-role-v3",
    ],
)
def test_evidence_policy_remediation_requires_native_supported_tier(
    tmp_path, capsys, policy
):
    from factoryline.cli import main
    from factoryline import review_audits as audit

    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "password = 'demonstration-password'\n"
        "def run():\n    return eval(request.get_data(as_text=True))\n",
        encoding="utf-8",
    )
    code = main(
        [
            "audit",
            "security",
            "--root",
            str(tmp_path),
            "--security-only",
            "--defect-policy",
            policy,
            "--json",
        ]
    )
    output = capsys.readouterr()
    assert output.err == "" and code in {1, 2}
    report = json.loads(output.out)
    rows = report["finding_tier_report"]["ledger"]
    assert len(rows) == 2
    assert {r["tier"] for r in rows} == {"SUPPORTED_DEFECT", "NEEDS_CONTEXT"}
    assert len(report["findings"]) == 2
    actions = report["agent_actions"]
    assert len(actions) == (2 if policy == "legacy-v1" else 1)
    assert any(
        a["finding_context"]["code"] == "SECURITY_DYNAMIC_EXECUTION" for a in actions
    )
    if policy != "legacy-v1":
        assert not any(
            a["finding_context"]["code"] == "SECURITY_HARDCODED_SECRET" for a in actions
        )
        assert report["defect_policy_decision"]["clean"] is False
    status = security_scan_status(tmp_path)
    assert status["candidate_freshness"] == "CURRENT_SOURCE_HASHES_VERIFIED"
    receipt = json.loads((tmp_path / ".factory/security-scan/latest.json").read_text())
    assert receipt["report"] == report
    core = copy.deepcopy(report)
    core["_primitive_source_bytes"] = {"app.py": (tmp_path / "app.py").read_bytes()}
    assert audit._seal_security_scan(core)["agent_actions"] == actions
    if policy != "legacy-v1":
        for row in core["finding_tier_report"]["ledger"]:
            row["tier"] = "SUPPORTED_DEFECT"
        core["_primitive_source_bytes"] = {"app.py": (tmp_path / "app.py").read_bytes()}
        assert audit._seal_security_scan(core)["agent_actions"] == actions


def test_evidence_policy_remediation_retains_quality_hollow_handoff(tmp_path):
    from factoryline import review_audits as audit

    (tmp_path / "test_empty.py").write_text(
        "def test_empty():\n    pass\n", encoding="utf-8"
    )
    report = audit.security_scan(
        tmp_path, defect_policy="source-role-v3", cache_enabled=False
    )
    assert any(
        a["finding_context"]["code"] == "QUALITY_HOLLOW_TEST"
        for a in report["agent_actions"]
    )

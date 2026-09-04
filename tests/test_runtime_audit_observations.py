import pytest
from factoryline.runtime_audit_stateful import evaluate_stateful
from factoryline.runtime_audit_recovery import evaluate_recovery


def stateful():
    config = {"invariant_ids": ["balance"], "required_actions": ["create", "refund"], "min_examples": 2, "min_actions": 2}
    artifact = {"schema": "factory.runtime.stateful.v1", "engine": "hypothesis", "engine_version": "6",
                "examples": 2, "max_actions": 2, "seed": 0,
                "invariants": [{"id": "balance", "violations": 0, "checks": 2, "trace": []}],
                "action_counts": {"create": 2, "refund": 2}, "replay_stable": True, "examples_isolated": True}
    return artifact, config


@pytest.mark.parametrize("mutation", ["actions", "checks", "trace"])
def test_stateful_contradictions_cannot_pass(mutation):
    artifact, config = stateful()
    if mutation == "actions": artifact["action_counts"]["create"] = 3
    elif mutation == "checks": artifact["invariants"][0].update(violations=3, trace=["create", "refund"])
    else: artifact["invariants"][0].update(violations=1, trace=["create", "refund", "refund"])
    result = evaluate_stateful(artifact, config, engine="hypothesis", engine_version="6")
    assert result["state"] == "INCOMPLETE"
    assert result["finding"] == "STATEFUL_OBSERVATION_CONTRADICTION"


def test_equal_bounds_remain_valid_and_real_failures_are_preserved():
    artifact, config = stateful()
    assert evaluate_stateful(artifact, config, engine="hypothesis", engine_version="6")["state"] == "PASS"
    artifact["invariants"][0].update(violations=2, trace=["create", "refund"])
    result = evaluate_stateful(artifact, config, engine="hypothesis", engine_version="6")
    assert result["state"] == "FAIL"
    assert result["finding"] == "STATEFUL_INVARIANT_VIOLATION"


@pytest.mark.parametrize("concurrency,expected", [(2, "PASS"), (3, "INCOMPLETE")])
def test_concurrency_requires_enough_observed_operations(concurrency, expected):
    config = {"fault_modes": ["timeout"], "postconditions": [{"id": "balance", "metric": "balance", "operator": "eq", "value": 1}], "min_concurrency": 2, "max_attempts_per_key": 3}
    artifact = {"schema": "factory.runtime.recovery.v1", "engine": "approved_fault_runner", "engine_version": "1",
                "operations": [{"id": "a", "idempotency_key": "k", "effects": 1}, {"id": "b", "idempotency_key": "k", "effects": 0}],
                "fault_modes": ["timeout"], "phases": {"pre_fault": {}, "during_fault": {}, "recovered": {"balance": 1}},
                "cleanup": {"attempted": True, "succeeded": True}, "max_concurrency": concurrency, "fault_observed": True, "lost_updates": 0}
    result = evaluate_recovery(artifact, config, engine="approved_fault_runner", engine_version="1")
    assert result["state"] == expected
    if expected == "INCOMPLETE": assert result["finding"] == "RECOVERY_OBSERVATION_CONTRADICTION"

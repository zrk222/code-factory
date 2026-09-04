"""State-machine evidence evaluation; native engines generate, CF decides."""
from __future__ import annotations

from typing import Any

from .runtime_audit_common import exact_keys, lane_result, require_int, require_str, require_unique_strings
from .runtime_audit_policy import validate_lane_policy


def evaluate_stateful(artifact: dict[str, Any], config: dict[str, Any], *, engine: str, engine_version: str) -> dict[str, Any]:
    """Evaluate generated transition coverage, replay stability, and every approved business invariant."""
    validate_lane_policy("stateful_invariant", config)
    exact_keys(artifact, {"schema", "engine", "engine_version", "examples", "max_actions", "seed", "invariants", "action_counts", "replay_stable", "examples_isolated"})
    if artifact["schema"] != "factory.runtime.stateful.v1" or artifact["engine"] != engine or artifact["engine_version"] != engine_version:
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_IDENTITY_MISMATCH", "State-machine evidence is not bound to the signed engine.")
    examples = require_int(artifact["examples"], "examples", minimum=2, maximum=1000)
    actions = require_int(artifact["max_actions"], "max_actions", minimum=2, maximum=200)
    seed = require_int(artifact["seed"], "seed", minimum=0, maximum=4_294_967_295)
    expected = require_unique_strings(config.get("invariant_ids"), "config.invariant_ids", minimum=1, maximum=128)
    if artifact["replay_stable"] is not True or artifact["examples_isolated"] is not True:
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_REPLAY_UNSTABLE", "Stateful replay or example isolation was not demonstrated.")
    if examples < config["min_examples"] or actions < config["min_actions"]:
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_COVERAGE_SHORT", "Signed generation bounds were not reached.")
    counts = artifact["action_counts"]
    if not isinstance(counts, dict) or set(counts) != set(config["required_actions"]):
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_ACTION_MISSING", "Approved transitions were omitted.")
    if any(require_int(count, "action_count", minimum=0, maximum=200000) == 0 for count in counts.values()):
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_ACTION_UNEXERCISED", "A required transition was never exercised.")
    if sum(counts.values()) > examples * actions:
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_OBSERVATION_CONTRADICTION", "Action totals exceed the reported example and sequence bounds.", details={"observed_actions": sum(counts.values()), "maximum_actions": examples * actions})
    invariants = artifact["invariants"]
    if not isinstance(invariants, list) or not 1 <= len(invariants) <= 128:
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_INVARIANTS_MISSING", "Approved workflow invariants were not all exercised.")
    observed: dict[str, dict[str, Any]] = {}
    for item in invariants:
        if not isinstance(item, dict):
            return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_ARTIFACT_INVALID", "An invariant record is malformed.")
        exact_keys(item, {"id", "violations", "trace", "checks"})
        item_id = require_str(item["id"], "invariant.id")
        if item_id in observed:
            return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_DUPLICATE_INVARIANT", "Duplicate invariant evidence is ambiguous.")
        violations = require_int(item["violations"], "invariant.violations", minimum=0, maximum=1_000_000)
        checks = require_int(item["checks"], "invariant.checks", minimum=0, maximum=1000000)
        if checks == 0:
            return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_INVARIANT_UNEXERCISED", "An invariant was suppressed or never checked.")
        if violations > checks:
            return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_OBSERVATION_CONTRADICTION", "Invariant violations exceed recorded checks.", details={"invariant": item_id, "violations": violations, "checks": checks})
        trace = item["trace"]
        if not isinstance(trace, list) or len(trace) > 200 or not all(isinstance(step, str) and step for step in trace):
            return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_TRACE_INVALID", "A counterexample trace is not reproducible.")
        if violations and not trace:
            return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_TRACE_INVALID", "A failing invariant requires a replay trace.")
        if len(trace) > actions:
            return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_OBSERVATION_CONTRADICTION", "Replay trace exceeds the reported maximum sequence length.", details={"invariant": item_id, "trace_actions": len(trace), "max_actions": actions})
        for step in trace:
            require_str(step, "trace.step")
        observed[item_id] = {"violations": violations, "trace": trace}
    missing = sorted(set(expected) - set(observed))
    if missing or set(observed) - set(expected):
        return lane_result("stateful_invariant", "INCOMPLETE", "STATEFUL_INVARIANTS_MISSING", "Approved workflow invariants were omitted.", details={"missing": missing})
    failures = [{"id": item_id, **observed[item_id]} for item_id in expected if observed[item_id]["violations"] > 0]
    if failures:
        return lane_result("stateful_invariant", "FAIL", "STATEFUL_INVARIANT_VIOLATION", "A generated action sequence violated an approved business invariant.", details={"failures": failures, "examples": examples, "max_actions": actions, "seed": seed})
    return lane_result("stateful_invariant", "PASS", "STATEFUL_INVARIANTS_HELD", "No violation was observed within the signed state-machine bounds.", details={"examples": examples, "max_actions": actions, "seed": seed, "invariants": expected})

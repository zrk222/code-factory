"""State-machine evidence evaluation; native engines generate, CF decides."""

from __future__ import annotations

from typing import Any

from .runtime_audit_common import (
    exact_keys,
    lane_result,
    require_int,
    require_str,
    require_unique_strings,
)
from .runtime_audit_policy import validate_lane_policy


_ARTIFACT_KEYS = {
    "schema",
    "engine",
    "engine_version",
    "examples",
    "max_actions",
    "seed",
    "invariants",
    "action_counts",
    "replay_stable",
    "examples_isolated",
}


def _identity_result(
    artifact: dict[str, Any], engine: str, engine_version: str
) -> dict[str, Any] | None:
    if (
        artifact["schema"] != "factory.runtime.stateful.v1"
        or artifact["engine"] != engine
        or artifact["engine_version"] != engine_version
    ):
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_IDENTITY_MISMATCH",
            "State-machine evidence is not bound to the signed engine.",
        )
    return None


def _generation_bounds(
    artifact: dict[str, Any], config: dict[str, Any]
) -> tuple[int, int, int, list[str]]:
    examples = require_int(artifact["examples"], "examples", minimum=2, maximum=1000)
    actions = require_int(
        artifact["max_actions"], "max_actions", minimum=2, maximum=200
    )
    seed = require_int(artifact["seed"], "seed", minimum=0, maximum=4_294_967_295)
    expected = require_unique_strings(
        config.get("invariant_ids"), "config.invariant_ids", minimum=1, maximum=128
    )
    return examples, actions, seed, expected


def _coverage_result(
    artifact: dict[str, Any],
    config: dict[str, Any],
    examples: int,
    actions: int,
) -> dict[str, Any] | None:
    if (
        artifact["replay_stable"] is not True
        or artifact["examples_isolated"] is not True
    ):
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_REPLAY_UNSTABLE",
            "Stateful replay or example isolation was not demonstrated.",
        )
    if examples < config["min_examples"] or actions < config["min_actions"]:
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_COVERAGE_SHORT",
            "Signed generation bounds were not reached.",
        )
    return None


def _action_result(
    artifact: dict[str, Any],
    config: dict[str, Any],
    examples: int,
    actions: int,
) -> dict[str, Any] | None:
    counts = artifact["action_counts"]
    if not isinstance(counts, dict) or set(counts) != set(config["required_actions"]):
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_ACTION_MISSING",
            "Approved transitions were omitted.",
        )
    if any(
        require_int(count, "action_count", minimum=0, maximum=200000) == 0
        for count in counts.values()
    ):
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_ACTION_UNEXERCISED",
            "A required transition was never exercised.",
        )
    observed_actions = sum(counts.values())
    if observed_actions > examples * actions:
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_OBSERVATION_CONTRADICTION",
            "Action totals exceed the reported example and sequence bounds.",
            details={
                "observed_actions": observed_actions,
                "maximum_actions": examples * actions,
            },
        )
    return None


def _invariant_identity(
    item: object, observed: dict[str, dict[str, Any]]
) -> tuple[str, dict[str, Any]] | dict[str, Any]:
    if not isinstance(item, dict):
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_ARTIFACT_INVALID",
            "An invariant record is malformed.",
        )
    exact_keys(item, {"id", "violations", "trace", "checks"})
    item_id = require_str(item["id"], "invariant.id")
    if item_id in observed:
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_DUPLICATE_INVARIANT",
            "Duplicate invariant evidence is ambiguous.",
        )
    return item_id, item


def _invariant_counts(
    item_id: str, item: dict[str, Any]
) -> tuple[int, int] | dict[str, Any]:
    violations = require_int(
        item["violations"], "invariant.violations", minimum=0, maximum=1_000_000
    )
    checks = require_int(item["checks"], "invariant.checks", minimum=0, maximum=1000000)
    if checks == 0:
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_INVARIANT_UNEXERCISED",
            "An invariant was suppressed or never checked.",
        )
    if violations > checks:
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_OBSERVATION_CONTRADICTION",
            "Invariant violations exceed recorded checks.",
            details={"invariant": item_id, "violations": violations, "checks": checks},
        )
    return violations, checks


def _invariant_trace(
    item_id: str, item: dict[str, Any], violations: int, actions: int
) -> list[str] | dict[str, Any]:
    trace = item["trace"]
    if (
        not isinstance(trace, list)
        or len(trace) > 200
        or not all(isinstance(step, str) and step for step in trace)
    ):
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_TRACE_INVALID",
            "A counterexample trace is not reproducible.",
        )
    if violations and not trace:
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_TRACE_INVALID",
            "A failing invariant requires a replay trace.",
        )
    if len(trace) > actions:
        return lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_OBSERVATION_CONTRADICTION",
            "Replay trace exceeds the reported maximum sequence length.",
            details={
                "invariant": item_id,
                "trace_actions": len(trace),
                "max_actions": actions,
            },
        )
    for step in trace:
        require_str(step, "trace.step")
    return trace


def _invariant_record_result(
    item: object,
    observed: dict[str, dict[str, Any]],
    actions: int,
) -> tuple[str, dict[str, Any]] | dict[str, Any]:
    identity = _invariant_identity(item, observed)
    if not isinstance(identity, tuple):
        return identity
    item_id, normalized = identity
    counts = _invariant_counts(item_id, normalized)
    if not isinstance(counts, tuple):
        return counts
    violations, _checks = counts
    trace = _invariant_trace(item_id, normalized, violations, actions)
    if not isinstance(trace, list):
        return trace
    return item_id, {"violations": violations, "trace": trace}


def _invariants_result(
    artifact: dict[str, Any], expected: list[str], actions: int
) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
    invariants = artifact["invariants"]
    if not isinstance(invariants, list) or not 1 <= len(invariants) <= 128:
        return {}, lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_INVARIANTS_MISSING",
            "Approved workflow invariants were not all exercised.",
        )
    observed: dict[str, dict[str, Any]] = {}
    for item in invariants:
        result = _invariant_record_result(item, observed, actions)
        if not isinstance(result, tuple):
            return {}, result
        item_id, observation = result
        observed[item_id] = observation
    missing = sorted(set(expected) - set(observed))
    if missing or set(observed) - set(expected):
        return {}, lane_result(
            "stateful_invariant",
            "INCOMPLETE",
            "STATEFUL_INVARIANTS_MISSING",
            "Approved workflow invariants were omitted.",
            details={"missing": missing},
        )
    return observed, None


def _terminal_result(
    observed: dict[str, dict[str, Any]],
    expected: list[str],
    examples: int,
    actions: int,
    seed: int,
) -> dict[str, Any]:
    failures = [
        {"id": item_id, **observed[item_id]}
        for item_id in expected
        if observed[item_id]["violations"] > 0
    ]
    if failures:
        return lane_result(
            "stateful_invariant",
            "FAIL",
            "STATEFUL_INVARIANT_VIOLATION",
            "A generated action sequence violated an approved business invariant.",
            details={
                "failures": failures,
                "examples": examples,
                "max_actions": actions,
                "seed": seed,
            },
        )
    return lane_result(
        "stateful_invariant",
        "PASS",
        "STATEFUL_INVARIANTS_HELD",
        "No violation was observed within the signed state-machine bounds.",
        details={
            "examples": examples,
            "max_actions": actions,
            "seed": seed,
            "invariants": expected,
        },
    )


def evaluate_stateful(
    artifact: dict[str, Any],
    config: dict[str, Any],
    *,
    engine: str,
    engine_version: str,
) -> dict[str, Any]:
    """Evaluate generated transition coverage, replay stability, and every approved business invariant."""
    validate_lane_policy("stateful_invariant", config)
    exact_keys(artifact, _ARTIFACT_KEYS)
    identity_error = _identity_result(artifact, engine, engine_version)
    if identity_error is not None:
        return identity_error
    examples, actions, seed, expected = _generation_bounds(artifact, config)
    coverage_error = _coverage_result(artifact, config, examples, actions)
    if coverage_error is not None:
        return coverage_error
    action_error = _action_result(artifact, config, examples, actions)
    if action_error is not None:
        return action_error
    observed, invariant_error = _invariants_result(artifact, expected, actions)
    if invariant_error is not None:
        return invariant_error
    return _terminal_result(observed, expected, examples, actions, seed)

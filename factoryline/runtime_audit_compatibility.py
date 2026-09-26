"""Consumer/provider compatibility evaluation for exercised interactions."""

from __future__ import annotations

from typing import Any

from .runtime_audit_common import (
    exact_keys,
    lane_result,
    require_bool,
    require_digest,
    require_int,
    require_str,
    require_unique_strings,
)
from .runtime_audit_policy import validate_lane_policy

ENGINES = {"pact_verifier", "approved_schema_validator"}
LANE = "consumer_compatibility"


def _incomplete(finding: str, message: str, details: dict[str, Any] | None = None):
    """Build an incomplete result while keeping validation branches small."""
    options = {"details": details} if details is not None else {}
    return lane_result(LANE, "INCOMPLETE", finding, message, **options)


def _identity_matches(artifact: dict[str, Any], engine: str, version: str) -> bool:
    return (
        artifact["schema"] == "factory.runtime.compatibility.v1"
        and artifact["engine"] == engine
        and artifact["engine_version"] == version
        and engine in ENGINES
    )


def _context_matches(artifact: dict[str, Any], config: dict[str, Any]) -> bool:
    return all(
        artifact[key] == config[key]
        for key in ("provider_version", "provider_branch", "environment")
    )


def _collect_expected(required: Any):
    if not isinstance(required, list) or not 1 <= len(required) <= 256:
        return None, _incomplete(
            "COMPATIBILITY_CONTRACT_MISSING",
            "Signed consumer interactions are missing.",
        )
    expected: dict[str, dict[str, str]] = {}
    for item in required:
        if not isinstance(item, dict):
            return None, _incomplete(
                "COMPATIBILITY_CONTRACT_INVALID", "A signed interaction is malformed."
            )
        exact_keys(item, {"id", "consumer_id", "consumer_version", "expected_sha256"})
        item_id = require_str(item["id"], "config.interaction.id")
        if item_id in expected:
            return None, _incomplete(
                "COMPATIBILITY_DUPLICATE_INTERACTION", "Interaction IDs must be unique."
            )
        expected[item_id] = {
            key: require_str(
                item[key],
                f"config.interaction.{key}",
                minimum=64 if key == "expected_sha256" else 1,
                maximum=64 if key == "expected_sha256" else 256,
            )
            for key in ("consumer_id", "consumer_version", "expected_sha256")
        }
    return expected, None


def _collect_observed(observations: Any):
    if not isinstance(observations, list) or not 1 <= len(observations) <= 256:
        return None, _incomplete(
            "COMPATIBILITY_OBSERVATIONS_MISSING",
            "No exercised consumer interactions were supplied.",
        )
    observed: dict[str, dict[str, Any]] = {}
    for item in observations:
        if not isinstance(item, dict):
            return None, _incomplete(
                "COMPATIBILITY_OBSERVATION_INVALID",
                "An interaction observation is malformed.",
            )
        exact_keys(
            item,
            {
                "id",
                "consumer_id",
                "consumer_version",
                "actual_sha256",
                "provider_state_prepared",
                "request_exercised",
                "mismatch_count",
                "pending",
            },
        )
        item_id = require_str(item["id"], "interaction.id")
        if item_id in observed:
            return None, _incomplete(
                "COMPATIBILITY_DUPLICATE_INTERACTION",
                "Observed interaction IDs must be unique.",
            )
        observed[item_id] = item
    return observed, None


def _interaction_failure(item_id: str, contract: dict[str, str], item: dict[str, Any]):
    actual = require_str(
        item["actual_sha256"], "interaction.actual_sha256", minimum=64, maximum=64
    )
    require_digest(actual, "actual_sha256")
    mismatch_count = require_int(
        item["mismatch_count"], "mismatch_count", minimum=0, maximum=1000000
    )
    require_bool(item["pending"], "pending")
    failed = (
        item["consumer_id"] != contract["consumer_id"]
        or item["consumer_version"] != contract["consumer_version"]
        or actual != contract["expected_sha256"]
        or item["provider_state_prepared"] is not True
        or item["request_exercised"] is not True
        or mismatch_count
        or item["pending"] is not False
    )
    if not failed:
        return None
    return {
        "id": item_id,
        "consumer_id": item.get("consumer_id"),
        "consumer_version": item.get("consumer_version"),
        "response_match": actual == contract["expected_sha256"],
        "provider_state_prepared": item.get("provider_state_prepared"),
        "request_exercised": item.get("request_exercised"),
        "mismatch_count": mismatch_count,
        "pending": item["pending"],
    }


def _compare_interactions(
    expected: dict[str, dict[str, str]], observed: dict[str, Any]
):
    missing = sorted(set(expected) - set(observed))
    if missing or set(observed) - set(expected):
        return None, _incomplete(
            "COMPATIBILITY_INTERACTION_MISSING",
            "A signed consumer expectation was not exercised.",
            {"missing": missing},
        )
    failures = []
    for item_id, contract in expected.items():
        failure = _interaction_failure(item_id, contract, observed[item_id])
        if failure:
            failures.append(failure)
    return failures, None


def _matrix_failure(matrix: Any, config: dict[str, Any]):
    if not isinstance(matrix, dict):
        return None, _incomplete(
            "COMPATIBILITY_MATRIX_MISSING",
            "A deployment compatibility decision was not recorded.",
        )
    exact_keys(matrix, {"checked", "compatible", "missing_pairs"})
    missing_pairs = require_unique_strings(
        matrix["missing_pairs"],
        "deployment_matrix.missing_pairs",
        minimum=0,
        maximum=256,
    )
    if config["deployment_matrix_required"] and matrix["checked"] is not True:
        return None, _incomplete(
            "COMPATIBILITY_MATRIX_MISSING",
            "The signed plan requires a can-I-deploy style matrix check.",
        )
    return matrix if matrix["compatible"] is not True or missing_pairs else None, None


def evaluate_compatibility(
    artifact: dict[str, Any],
    config: dict[str, Any],
    *,
    engine: str,
    engine_version: str,
) -> dict[str, Any]:
    """Evaluate signed consumer interactions and deployment compatibility."""
    validate_lane_policy(LANE, config)
    exact_keys(
        artifact,
        {
            "schema",
            "engine",
            "engine_version",
            "provider_version",
            "provider_branch",
            "environment",
            "interactions",
            "deployment_matrix",
        },
    )
    if not _identity_matches(artifact, engine, engine_version):
        return _incomplete(
            "COMPATIBILITY_IDENTITY_MISMATCH",
            "Compatibility evidence is not from the signed supported verifier.",
        )
    for key in ("provider_version", "provider_branch", "environment"):
        require_str(artifact[key], key)
    if not _context_matches(artifact, config):
        return _incomplete(
            "COMPATIBILITY_VERSION_MISMATCH",
            "Provider version, branch or environment differs from the signed contract.",
        )
    expected, issue = _collect_expected(config.get("interactions"))
    if issue:
        return issue
    observed, issue = _collect_observed(artifact["interactions"])
    if issue:
        return issue
    failures, issue = _compare_interactions(expected, observed)
    if issue:
        return issue
    matrix, issue = _matrix_failure(artifact["deployment_matrix"], config)
    if issue:
        return issue
    if matrix:
        failures.append({"deployment_matrix": matrix})
    if failures:
        return lane_result(
            LANE,
            "FAIL",
            "CONSUMER_CONTRACT_BROKEN",
            "The candidate broke or failed to exercise a signed consumer interaction.",
            details={"failures": failures},
        )
    return lane_result(
        LANE,
        "PASS",
        "CONSUMER_CONTRACTS_HELD",
        "All signed consumer interactions were exercised against the candidate provider.",
        details={
            "interactions": len(expected),
            "provider_version": artifact["provider_version"],
        },
    )

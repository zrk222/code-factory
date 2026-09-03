"""Consumer/provider compatibility evaluation for exercised interactions."""
from __future__ import annotations

from typing import Any

from .runtime_audit_common import exact_keys, lane_result, require_str, require_unique_strings
from .runtime_audit_policy import validate_lane_policy

ENGINES = {"pact_verifier", "approved_schema_validator"}


def evaluate_compatibility(artifact: dict[str, Any], config: dict[str, Any], *, engine: str, engine_version: str) -> dict[str, Any]:
    """Evaluate exercised consumer interactions and any required deployment compatibility matrix without trusting pending status."""
    validate_lane_policy("consumer_compatibility", config)
    exact_keys(artifact, {"schema", "engine", "engine_version", "provider_version", "provider_branch", "environment", "interactions", "deployment_matrix"})
    if artifact["schema"] != "factory.runtime.compatibility.v1" or artifact["engine"] != engine or artifact["engine_version"] != engine_version or engine not in ENGINES:
        return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_IDENTITY_MISMATCH", "Compatibility evidence is not from the signed supported verifier.")
    require_str(artifact["provider_version"], "provider_version")
    require_str(artifact["provider_branch"], "provider_branch")
    require_str(artifact["environment"], "environment")
    if any(artifact[key] != config[key] for key in ("provider_version", "provider_branch", "environment")):
        return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_VERSION_MISMATCH", "Provider version, branch or environment differs from the signed contract.")
    required = config.get("interactions")
    if not isinstance(required, list) or not 1 <= len(required) <= 256:
        return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_CONTRACT_MISSING", "Signed consumer interactions are missing.")
    expected: dict[str, dict[str, str]] = {}
    for item in required:
        if not isinstance(item, dict):
            return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_CONTRACT_INVALID", "A signed interaction is malformed.")
        exact_keys(item, {"id", "consumer_id", "consumer_version", "expected_sha256"})
        item_id = require_str(item["id"], "config.interaction.id")
        if item_id in expected:
            return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_DUPLICATE_INTERACTION", "Interaction IDs must be unique.")
        expected[item_id] = {key: require_str(item[key], f"config.interaction.{key}", minimum=64 if key == "expected_sha256" else 1, maximum=64 if key == "expected_sha256" else 256) for key in ("consumer_id", "consumer_version", "expected_sha256")}
    observations = artifact["interactions"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= 256:
        return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_OBSERVATIONS_MISSING", "No exercised consumer interactions were supplied.")
    observed: dict[str, dict[str, Any]] = {}
    for item in observations:
        if not isinstance(item, dict):
            return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_OBSERVATION_INVALID", "An interaction observation is malformed.")
        exact_keys(item, {"id", "consumer_id", "consumer_version", "actual_sha256", "provider_state_prepared", "request_exercised", "mismatch_count", "pending"})
        item_id = require_str(item["id"], "interaction.id")
        if item_id in observed:
            return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_DUPLICATE_INTERACTION", "Observed interaction IDs must be unique.")
        observed[item_id] = item
    missing = sorted(set(expected) - set(observed))
    if missing or set(observed) - set(expected):
        return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_INTERACTION_MISSING", "A signed consumer expectation was not exercised.", details={"missing": missing})
    failures: list[dict[str, Any]] = []
    for item_id, contract in expected.items():
        item = observed[item_id]
        actual = require_str(item["actual_sha256"], "interaction.actual_sha256", minimum=64, maximum=64)
        from .runtime_audit_common import require_int, require_bool, require_digest
        require_digest(actual, "actual_sha256")
        mismatch_count = require_int(item["mismatch_count"], "mismatch_count", minimum=0, maximum=1000000)
        require_bool(item["pending"], "pending")
        if item["consumer_id"] != contract["consumer_id"] or item["consumer_version"] != contract["consumer_version"] or actual != contract["expected_sha256"] or item["provider_state_prepared"] is not True or item["request_exercised"] is not True or mismatch_count:
            failures.append({"id": item_id, "consumer_id": item.get("consumer_id"), "consumer_version": item.get("consumer_version"), "response_match": actual == contract["expected_sha256"], "provider_state_prepared": item.get("provider_state_prepared"), "request_exercised": item.get("request_exercised"), "mismatch_count": mismatch_count, "pending": item["pending"]})
    matrix = artifact["deployment_matrix"]
    if not isinstance(matrix, dict):
        return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_MATRIX_MISSING", "A deployment compatibility decision was not recorded.")
    exact_keys(matrix, {"checked", "compatible", "missing_pairs"})
    missing_pairs = require_unique_strings(matrix["missing_pairs"], "deployment_matrix.missing_pairs", minimum=0, maximum=256)
    if config["deployment_matrix_required"] and matrix["checked"] is not True:
        return lane_result("consumer_compatibility", "INCOMPLETE", "COMPATIBILITY_MATRIX_MISSING", "The signed plan requires a can-I-deploy style matrix check.")
    if matrix["compatible"] is not True or missing_pairs:
        failures.append({"deployment_matrix": matrix})
    if failures:
        return lane_result("consumer_compatibility", "FAIL", "CONSUMER_CONTRACT_BROKEN", "The candidate broke or failed to exercise a signed consumer interaction.", details={"failures": failures})
    return lane_result("consumer_compatibility", "PASS", "CONSUMER_CONTRACTS_HELD", "All signed consumer interactions were exercised against the candidate provider.", details={"interactions": len(expected), "provider_version": artifact["provider_version"]})

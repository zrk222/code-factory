"""Operations-plane evidence: telemetry, promotion, rollback, and response."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Mapping
from hashlib import sha256 as hashlib_sha256
from pathlib import Path
from typing import Any, Iterable

from .control_plane import canonical_json, sha256


OPERATIONS_SCHEMA = "factory.operations.v1"
TELEMETRY_SCHEMA = "factory.telemetry.span.v1"
DEPLOYMENT_SCHEMA = "factory.deployment.receipt.v1"
VULNERABILITY_SCHEMA = "factory.vulnerability.response.v1"
CONNECTOR_SCHEMA = "factory.connector.event.v1"


class OperationsError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _operation_fields(body: Any, schema: str, keys: set[str]) -> None:
    if (
        not isinstance(body, dict)
        or set(body) != keys | {"schema"}
        or body["schema"] != schema
    ):
        raise OperationsError(
            "E_TRACE_SCHEMA", "operation artifact violates its closed schema"
        )


def _sampling_policy(body: Any) -> dict[str, Any]:
    from .runtime_audit_common import require_number, require_int

    _operation_fields(
        body,
        "factory.trace-sampling-policy.v1",
        {
            "seed",
            "fractions",
            "max_cost_usd",
            "max_latency_ms",
            "approval_reference",
        },
    )
    _required(body["seed"], "seed")
    _required(body["approval_reference"], "approval reference")
    if not isinstance(body["fractions"], dict) or set(body["fractions"]) != {
        "low",
        "medium",
        "high",
    }:
        raise OperationsError("E_TRACE_SCHEMA", "three risk strata are required")
    for value in body["fractions"].values():
        if require_number(value, "sample fraction") > 1:
            raise OperationsError("E_TRACE_SCHEMA", "sample fraction exceeds one")
    require_number(body["max_cost_usd"], "cost budget")
    require_int(body["max_latency_ms"], "latency budget", minimum=0, maximum=10**12)
    return body


def _sampling_trace(row: Any) -> None:
    from .runtime_audit_common import require_number, require_digest

    _operation_fields(
        row,
        "factory.trace-sampling-observation.v1",
        {
            "trace_id",
            "trace_sha256",
            "risk",
            "estimated_cost_usd",
            "estimated_latency_ms",
            "actual_cost_usd",
            "actual_latency_ms",
            "scored",
        },
    )
    _required(row["trace_id"], "trace ID")
    require_digest(row["trace_sha256"], "trace digest")
    if row["risk"] not in {"low", "medium", "high"} or type(row["scored"]) is not bool:
        raise OperationsError("E_TRACE_SCHEMA", "risk or scored flag is invalid")
    for key in (
        "estimated_cost_usd",
        "estimated_latency_ms",
        "actual_cost_usd",
        "actual_latency_ms",
    ):
        if row[key] is not None:
            require_number(row[key], key)


def _sample_decision(row, policy, cost_reserved, latency_reserved):
    rank = (
        int(
            hashlib_sha256(
                canonical_json([policy["seed"], row["trace_id"], row["trace_sha256"]])
            ).hexdigest(),
            16,
        )
        / 2**256
    )
    if rank >= policy["fractions"][row["risk"]]:
        return "NOT_SELECTED"
    if row["estimated_cost_usd"] is None or row["estimated_latency_ms"] is None:
        return "UNKNOWN_ESTIMATE"
    if (
        cost_reserved + row["estimated_cost_usd"] > policy["max_cost_usd"]
        or latency_reserved + row["estimated_latency_ms"] > policy["max_latency_ms"]
    ):
        return "BUDGET_DENIED"
    return "SELECTED"


def _sample_ledger(body, policy):
    _operation_fields(
        body,
        "factory.trace-sampling-population.v1",
        {"window_id", "eligible_count", "traces"},
    )
    _required(body["window_id"], "window ID")
    traces = body["traces"]
    if (
        not isinstance(traces, list)
        or not 1 <= len(traces) <= 10_000
        or type(body["eligible_count"]) is not int
        or body["eligible_count"] != len(traces)
    ):
        raise OperationsError(
            "E_TRACE_SCHEMA", "eligible denominator must equal exact trace inventory"
        )
    for row in traces:
        _sampling_trace(row)
    if len({row["trace_id"] for row in traces}) != len(traces) or len(
        {row["trace_sha256"] for row in traces}
    ) != len(traces):
        raise OperationsError("E_TRACE_SCHEMA", "duplicate eligible traces")
    cost_reserved = latency_reserved = 0
    ledger = []
    for row in sorted(traces, key=lambda item: item["trace_id"]):
        decision = _sample_decision(row, policy, cost_reserved, latency_reserved)
        if decision == "SELECTED":
            cost_reserved += row["estimated_cost_usd"]
            latency_reserved += row["estimated_latency_ms"]
        ledger.append({**row, "selection": decision})
    return ledger


def _sampling_summary(ledger, policy):
    selected = [row for row in ledger if row["selection"] == "SELECTED"]
    scored = [row for row in ledger if row["scored"]]
    charged = [
        row
        for row in ledger
        if row["scored"]
        or row["selection"] == "SELECTED"
        or row["actual_cost_usd"] is not None
        or row["actual_latency_ms"] is not None
    ]
    unknown = any(
        row["actual_cost_usd"] is None or row["actual_latency_ms"] is None
        for row in charged
    )
    cost = None if unknown else sum(row["actual_cost_usd"] for row in charged)
    latency = None if unknown else sum(row["actual_latency_ms"] for row in charged)
    violations = [row["trace_id"] for row in scored if row["selection"] != "SELECTED"]
    breaches = not unknown and (
        cost > policy["max_cost_usd"] or latency > policy["max_latency_ms"]
    )
    incomplete = (
        unknown
        or any(
            row["selection"] in {"UNKNOWN_ESTIMATE", "BUDGET_DENIED"} for row in ledger
        )
        or len(scored) != len(selected)
    )
    return {
        "state": "FAIL"
        if violations or breaches
        else "INCOMPLETE"
        if incomplete
        else "OBSERVED_LOCAL_METRICS",
        "eligible": len(ledger),
        "selected": len(selected),
        "scored": len(scored),
        "unscored": len(ledger) - len(scored),
        "actual_cost_usd": cost,
        "actual_latency_ms": latency,
        "measurement_quality": "UNKNOWN" if unknown else "RECORDED_LOCAL",
        "selection_violations": violations,
        "budget_breached": breaches,
        "by_risk": {
            risk: {
                "eligible": sum(row["risk"] == risk for row in ledger),
                "scored": sum(row["risk"] == risk for row in scored),
            }
            for risk in ("low", "medium", "high")
        },
    }


def evaluate_trace_sampling(
    root: Path, binding_request: Mapping[str, Any]
) -> dict[str, Any]:
    """Account for a bound declared population; this does not start provider requests."""
    from .analysis_evidence import validate_evaluation_bindings

    result = {
        "schema": "factory.trace-sampling.v1",
        "state": "INCOMPLETE",
        "code": "TRACE_SAMPLING",
        "authority": "none",
        "population_completeness": "UNVERIFIED_OUTSIDE_SUPPLIED_WINDOW",
        "next_actions": [
            "Supply complete eligible inventory, measured usage and approved sampling policy."
        ],
    }
    try:
        bound = validate_evaluation_bindings(root, binding_request)
        if bound["state"] != "BOUND_LOCAL_EVIDENCE":
            return {**result, "errors": bound.get("errors", [])}
        policy = _sampling_policy(bound["artifacts"]["policy"]["body"])
        ledger = _sample_ledger(bound["artifacts"]["sampling"]["body"], policy)
        result.update(
            _sampling_summary(ledger, policy),
            ledger=ledger,
            binding_sha256=bound["binding_sha256"],
        )
    except (ValueError, TypeError, KeyError, OperationsError):
        pass
    result["receipt_sha256"] = _calibration_digest(result)
    return result


def _rollout_control(body, role, commit, target):
    from .runtime_audit_common import require_digest

    _operation_fields(
        body,
        "factory.rollout-control-observation.v1",
        {
            "control",
            "target",
            "candidate_commit",
            "observed_at",
            "before",
            "after",
            "evidence_sha256",
        },
    )
    if (
        body["control"] != role
        or body["target"] != target
        or body["candidate_commit"] != commit
    ):
        raise OperationsError(
            "E_ROLLOUT_BINDING", "control target or candidate differs"
        )
    _calibration_timestamp(body["observed_at"], "observed_at")
    require_digest(body["evidence_sha256"], "control evidence")
    transitions = {
        "deployment_control": ("STAGED", "RUNNING"),
        "killswitch_control": ("ENABLED", "DISABLED"),
        "rollback_control": ("CANDIDATE", "BASELINE"),
    }
    if (body["before"], body["after"]) != transitions[role]:
        raise OperationsError(
            "E_ROLLOUT_TRANSITION", "required observed control transition is missing"
        )


def _rollout_assignment(body):
    from math import erfc, sqrt
    from .runtime_audit_common import require_number

    _operation_fields(
        body,
        "factory.rollout-randomization.v1",
        {
            "seed",
            "treatment_fraction",
            "srm_alpha",
            "assignments",
        },
    )
    seed = _required(body["seed"], "randomization seed")
    fraction = require_number(body["treatment_fraction"], "treatment fraction")
    alpha = require_number(body["srm_alpha"], "SRM alpha")
    if not 0 < fraction < 1 or not 0 < alpha < 1:
        raise OperationsError(
            "E_ROLLOUT_RANDOMIZATION", "randomization parameters must be within (0,1)"
        )
    rows = body["assignments"]
    if not isinstance(rows, list) or not 10 <= len(rows) <= 10_000:
        raise OperationsError(
            "E_ROLLOUT_RANDOMIZATION", "randomized assignments require 10..10000 units"
        )
    assignments = _rollout_assignment_rows(rows, seed, fraction)
    treated = sum(value == "treatment" for value in assignments.values())
    expected = len(rows) * fraction
    chi2 = (treated - expected) ** 2 / expected + (
        len(rows) - treated - (len(rows) - expected)
    ) ** 2 / (len(rows) - expected)
    p_value = erfc(sqrt(chi2 / 2))
    return {
        "units": len(rows),
        "treatment": treated,
        "control": len(rows) - treated,
        "srm_p_value": p_value,
        "srm_alpha": alpha,
        "srm_failed": p_value < alpha,
        "statistical_power": None,
        "power_reason": "No effect size or outcome variance supplied.",
    }


def _rollout_assignment_rows(rows, seed, fraction):
    assignments = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"unit_sha256", "arm"}:
            raise OperationsError("E_ROLLOUT_RANDOMIZATION", "assignment fields differ")
        unit = row["unit_sha256"]
        if (
            not isinstance(unit, str)
            or len(unit) != 64
            or any(c not in "0123456789abcdef" for c in unit)
        ):
            raise OperationsError(
                "E_ROLLOUT_RANDOMIZATION", "units must be deidentified SHA-256"
            )
        rank = (
            int(hashlib_sha256(canonical_json([seed, unit])).hexdigest(), 16) / 2**256
        )
        expected = "treatment" if rank < fraction else "control"
        if row["arm"] != expected or unit in assignments:
            raise OperationsError(
                "E_ROLLOUT_RANDOMIZATION",
                "assignment violates sticky allocation or repeats a unit",
            )
        assignments[unit] = row["arm"]
    return assignments


def _rollout_observations(bound):
    artifacts = bound["artifacts"]
    body = artifacts["rollout"]["body"]
    _operation_fields(
        body,
        "factory.rollout-evidence.v1",
        {
            "mode",
            "target",
            "candidate_commit",
            "window_start",
            "window_end",
            "controls",
            "randomization",
        },
    )
    if (
        body["mode"] != "live"
        or body["candidate_commit"] != bound["candidate"]["commit"]
    ):
        raise OperationsError(
            "LIVE_ROLLOUT_UNVERIFIED", "offline evidence cannot establish live controls"
        )
    _required(body["target"], "deployment target")
    start = _calibration_timestamp(body["window_start"], "window start")
    end = _calibration_timestamp(body["window_end"], "window end")
    if start >= end:
        raise OperationsError("LIVE_ROLLOUT_UNVERIFIED", "control window is invalid")
    roles = {"deployment_control", "killswitch_control", "rollback_control"}
    if not isinstance(body["controls"], dict) or set(body["controls"]) != roles:
        raise OperationsError(
            "LIVE_ROLLOUT_UNVERIFIED", "all observed controls are required"
        )
    for role in sorted(roles):
        artifact = artifacts[role]
        if body["controls"][role] != artifact["sha256"]:
            raise OperationsError("LIVE_ROLLOUT_UNVERIFIED", "control hash differs")
        evidence_hashes = set(bound["source_hashes"].values()) | {
            item["sha256"]
            for key, item in artifacts.items()
            if key not in roles | {"rollout"}
        }
        if artifact["body"].get("evidence_sha256") not in evidence_hashes:
            raise OperationsError(
                "LIVE_ROLLOUT_UNVERIFIED", "control evidence was not bound and read"
            )
        _rollout_control(
            artifact["body"], role, body["candidate_commit"], body["target"]
        )
        if (
            not start
            <= _calibration_timestamp(artifact["body"]["observed_at"], "observed_at")
            <= end
        ):
            raise OperationsError(
                "LIVE_ROLLOUT_UNVERIFIED", "control observation is outside the window"
            )
    experiment = (
        None
        if body["randomization"] is None
        else _rollout_assignment(body["randomization"])
    )
    return {
        "controls": body["controls"],
        "randomization": experiment,
        "state": "FAIL"
        if experiment and experiment["srm_failed"]
        else "OBSERVED_LOCAL_CONTROLS",
    }


def evaluate_rollout_evidence(
    root: Path, binding_request: Mapping[str, Any]
) -> dict[str, Any]:
    """Inspect observed controls without deploying or authenticating a producer."""
    from .analysis_evidence import validate_evaluation_bindings

    result = {
        "schema": "factory.rollout-evaluation.v1",
        "state": "INCOMPLETE",
        "code": "LIVE_ROLLOUT_UNVERIFIED",
        "authority": "none",
        "promotion_authorized": False,
        "producer_authenticity": "UNVERIFIED",
        "next_actions": [
            "Supply bound live control observations; verify producer identity through the release route."
        ],
    }
    try:
        bound = validate_evaluation_bindings(root, binding_request)
        if bound["state"] == "BOUND_LOCAL_EVIDENCE":
            result.update(
                _rollout_observations(bound), binding_sha256=bound["binding_sha256"]
            )
    except (ValueError, TypeError, KeyError, OperationsError):
        pass
    result["receipt_sha256"] = _calibration_digest(result)
    return result


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperationsError("E_REQUIRED", f"{name} is required")
    return value.strip()


_CALIBRATION_SCHEMAS = {
    "dataset": "factory.judge-calibration.dataset.v1",
    "assignments": "factory.judge-calibration.assignments.v1",
    "annotations": "factory.judge-calibration.annotations.v1",
    "judgments": "factory.judge-calibration.judgments.v1",
    "adjudications": "factory.judge-calibration.adjudications.v1",
}
_CALIBRATION_ROWS = 10_000
_CALIBRATION_CATEGORIES = 128


def _calibration_digest(value: Any) -> str:
    return hashlib_sha256(canonical_json(value)).hexdigest()


def _calibration_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", f"{name} must be an ISO timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", f"{name} must be an ISO timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise OperationsError("E_CALIBRATION_SCHEMA", f"{name} must include a timezone")
    return parsed


def _calibration_labels(value: Any, categories: set[str], name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > len(categories):
        raise OperationsError("E_CALIBRATION_SCHEMA", f"{name} labels are invalid")
    if any(not isinstance(label, str) or label not in categories for label in value):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", f"{name} contains an unknown label"
        )
    if len(set(value)) != len(value):
        raise OperationsError("E_CALIBRATION_SCHEMA", f"{name} labels must be unique")
    return tuple(sorted(value))


def _calibration_rows(body: Any, schema: str, key: str) -> list[dict[str, Any]]:
    if (
        not isinstance(body, Mapping)
        or set(body) != {"schema", key}
        or body.get("schema") != schema
        or not isinstance(body.get(key), list)
        or len(body[key]) > _CALIBRATION_ROWS
    ):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", f"{schema} has invalid fields or row count"
        )
    return body[key]


def _calibration_validate_rows(
    rows: list[dict[str, Any]], case_ids: set[str], categories: set[str], *, kind: str
) -> dict[str, dict[str, Any]]:
    by_case: dict[str, dict[str, Any]] = {}
    expected = {
        "judgments": {
            "case_id",
            "predicted_at",
            "labels",
            "abstained",
            "input_sha256",
            "model_sha256",
            "prompt_sha256",
            "rubric_sha256",
        },
        "adjudications": {"case_id", "labels", "abstained"},
    }[kind]
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != expected:
            raise OperationsError(
                "E_CALIBRATION_SCHEMA", f"{kind} row fields are invalid"
            )
        case_id = row.get("case_id")
        if (
            not isinstance(case_id, str)
            or case_id not in case_ids
            or case_id in by_case
        ):
            raise OperationsError(
                "E_CALIBRATION_SCHEMA", f"{kind} case IDs must be exact and unique"
            )
        if not isinstance(row.get("abstained"), bool):
            raise OperationsError(
                "E_CALIBRATION_SCHEMA", f"{kind} abstained must be boolean"
            )
        labels = _calibration_labels(row.get("labels"), categories, kind)
        if row["abstained"] and labels:
            raise OperationsError(
                "E_CALIBRATION_SCHEMA", f"{kind} abstentions must have empty labels"
            )
        by_case[case_id] = {**row, "labels": labels}
    if set(by_case) != case_ids:
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", f"{kind} must cover every dataset case exactly once"
        )
    return by_case


def _calibration_annotations(
    body: Any, case_ids: set[str], categories: set[str]
) -> tuple[dict[str, dict[str, tuple[str, ...] | None]], tuple[str, str]]:
    if (
        not isinstance(body, Mapping)
        or set(body) != {"schema", "annotators", "rows"}
        or body.get("schema") != _CALIBRATION_SCHEMAS["annotations"]
        or not isinstance(body.get("annotators"), list)
        or len(body["annotators"]) != 2
        or any(not isinstance(item, str) or not item for item in body["annotators"])
        or len(set(body["annotators"])) != 2
        or not isinstance(body.get("rows"), list)
        or len(body["rows"]) > _CALIBRATION_ROWS
    ):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", "annotations require one declared two-person pair"
        )
    pair = tuple(body["annotators"])
    result: dict[str, dict[str, tuple[str, ...] | None]] = {cid: {} for cid in case_ids}
    for row in body["rows"]:
        if not isinstance(row, Mapping) or set(row) != {
            "case_id",
            "annotator_id",
            "labels",
            "abstained",
        }:
            raise OperationsError(
                "E_CALIBRATION_SCHEMA", "annotation row fields are invalid"
            )
        case_id, annotator_id = row.get("case_id"), row.get("annotator_id")
        if (
            case_id not in case_ids
            or annotator_id not in pair
            or annotator_id in result.get(case_id, {})
        ):
            raise OperationsError(
                "E_CALIBRATION_SCHEMA",
                "annotation case/annotator pair is invalid or duplicated",
            )
        if not isinstance(row.get("abstained"), bool):
            raise OperationsError(
                "E_CALIBRATION_SCHEMA", "annotation abstained must be boolean"
            )
        labels = _calibration_labels(row.get("labels"), categories, "annotation")
        if row["abstained"] and labels:
            raise OperationsError(
                "E_CALIBRATION_SCHEMA", "annotation abstentions must have empty labels"
            )
        result[case_id][annotator_id] = None if row["abstained"] else labels
    if any(set(row) != set(pair) for row in result.values()):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA",
            "annotations must cover each case for both declared annotators",
        )
    return result, pair


def _calibration_agreement(
    annotations: dict[str, dict[str, tuple[str, ...] | None]], pair: tuple[str, str]
) -> dict[str, Any]:
    decided = [
        (row[pair[0]], row[pair[1]])
        for row in annotations.values()
        if all(row[p] is not None for p in pair)
    ]
    if not decided:
        return {
            "annotator_pair": list(pair),
            "joint_decided": 0,
            "agreement_count": 0,
            "agreement": None,
            "cohen_kappa": None,
            "kappa_undefined_reason": "no_joint_decisions",
            "disagreements": [],
        }
    matches = sum(first == second for first, second in decided)
    marginals = [
        {
            label: sum(row[index] == label for row in decided) / len(decided)
            for label in {item[index] for item in decided}
        }
        for index in (0, 1)
    ]
    expected = sum(
        marginals[0].get(label, 0) * marginals[1].get(label, 0)
        for label in set(marginals[0]) | set(marginals[1])
    )
    observed = matches / len(decided)
    undefined = "constant_labels" if expected == 1 else None
    disagreements = sorted(
        case_id
        for case_id, row in annotations.items()
        if all(row[p] is not None for p in pair) and row[pair[0]] != row[pair[1]]
    )
    return {
        "annotator_pair": list(pair),
        "joint_decided": len(decided),
        "agreement_count": matches,
        "agreement": round(observed, 6),
        "cohen_kappa": None
        if undefined
        else round((observed - expected) / (1 - expected), 6),
        "kappa_undefined_reason": undefined,
        "disagreements": disagreements,
    }


def _calibration_category_bucket(
    case_ids: set[str],
    category: str,
    predictions: dict[str, dict[str, Any]],
    references: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    from .benchmark_lab import _public_metrics

    counts = {key: 0 for key in ("tp", "fp", "fn", "tn")}
    eligible = judged = abstentions = positive_abstentions = negative_abstentions = (
        reference_abstentions
    ) = 0
    for case_id in case_ids:
        reference, prediction = references[case_id], predictions[case_id]
        if reference["abstained"]:
            reference_abstentions += 1
            continue
        eligible += 1
        actual = category in reference["labels"]
        if prediction["abstained"]:
            abstentions += 1
            positive_abstentions += int(actual)
            negative_abstentions += int(not actual)
            continue
        judged += 1
        predicted = category in prediction["labels"]
        counts[
            {
                (True, True): "tp",
                (False, True): "fp",
                (True, False): "fn",
                (False, False): "tn",
            }[(actual, predicted)]
        ] += 1
    return {
        **_public_metrics(counts),
        "eligible": eligible,
        "judged": judged,
        "abstentions": abstentions,
        "positive_abstentions": positive_abstentions,
        "negative_abstentions": negative_abstentions,
        "reference_abstentions": reference_abstentions,
        "coverage": round(judged / eligible, 6) if eligible else None,
    }


def _calibration_metrics(
    case_ids: set[str],
    categories: set[str],
    predictions: dict[str, dict[str, Any]],
    references: dict[str, dict[str, Any]],
    splits: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    result = {}
    for category in sorted(categories):
        result[category] = {
            "overall": _calibration_category_bucket(
                case_ids, category, predictions, references
            ),
            "by_split": {
                split: _calibration_category_bucket(
                    {cid for cid in case_ids if splits[cid] == split},
                    category,
                    predictions,
                    references,
                )
                for split in ("train", "dev", "holdout")
            },
        }
    return result


def _calibration_dataset(
    dataset: Any,
) -> tuple[set[str], set[str], dict[str, str], dict[str, str]]:
    if (
        not isinstance(dataset, Mapping)
        or set(dataset) != {"schema", "categories", "cases"}
        or dataset.get("schema") != _CALIBRATION_SCHEMAS["dataset"]
    ):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", "dataset fields do not match the closed contract"
        )
    categories, cases = dataset["categories"], dataset["cases"]
    if (
        not isinstance(categories, list)
        or not categories
        or len(categories) > _CALIBRATION_CATEGORIES
        or len(set(categories)) != len(categories)
        or any(not isinstance(c, str) or not c for c in categories)
    ):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", "dataset categories must be nonempty and unique"
        )
    if not isinstance(cases, list) or not 1 <= len(cases) <= _CALIBRATION_ROWS:
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", "dataset case count is outside the bound"
        )
    ids = [row.get("case_id") for row in cases if isinstance(row, Mapping)]
    if (
        len(ids) != len(cases)
        or any(not isinstance(cid, str) or not cid for cid in ids)
        or len(set(ids)) != len(ids)
    ):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", "dataset case IDs must be exact and unique"
        )
    inputs, fingerprints = {}, {}
    for case in cases:
        if set(case) != {
            "case_id",
            "buggy_source",
            "fixed_source",
            "judge_input",
        } or any(
            not isinstance(case.get(key), str)
            for key in ("buggy_source", "fixed_source", "judge_input")
        ):
            raise OperationsError(
                "E_CALIBRATION_SCHEMA",
                "dataset case fields do not match the closed input contract",
            )
        case_id = case["case_id"]
        inputs[case_id] = _calibration_digest(case["judge_input"])
        fingerprints[case_id] = _calibration_digest(
            [case["buggy_source"], case["fixed_source"], case["judge_input"]]
        )
        fingerprints[f"{case_id}:buggy"] = _calibration_digest(case["buggy_source"])
        fingerprints[f"{case_id}:fixed"] = _calibration_digest(case["fixed_source"])
    return set(ids), set(categories), fingerprints, inputs


def _calibration_splits(
    body: Any, case_ids: set[str], fingerprints: dict[str, str]
) -> tuple[datetime, Mapping[str, str]]:
    if (
        not isinstance(body, Mapping)
        or set(body) != {"schema", "frozen_at", "splits"}
        or body.get("schema") != _CALIBRATION_SCHEMAS["assignments"]
        or not isinstance(body.get("splits"), Mapping)
        or set(body["splits"]) != case_ids
        or any(
            value not in {"train", "dev", "holdout"}
            for value in body["splits"].values()
        )
    ):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", "frozen assignments must cover each exact case ID"
        )
    split_by_case = body["splits"]
    owners: dict[str, str] = {}
    for key, digest in fingerprints.items():
        case_id = key.rsplit(":", 1)[0] if key.endswith((":buggy", ":fixed")) else key
        prior = owners.get(digest)
        if prior is not None and split_by_case[prior] != split_by_case[case_id]:
            raise OperationsError(
                "E_CALIBRATION_CROSS_SPLIT_DUPLICATE",
                "exact evidence/source duplication crosses frozen splits",
            )
        owners.setdefault(digest, case_id)
    return _calibration_timestamp(body["frozen_at"], "frozen_at"), split_by_case


def _calibration_predictions(
    body: Any,
    case_ids: set[str],
    categories: set[str],
    judge_inputs: dict[str, str],
    freeze_time: datetime,
    artifact_hashes: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    rows = _calibration_rows(body, _CALIBRATION_SCHEMAS["judgments"], "rows")
    predictions = _calibration_validate_rows(
        rows, case_ids, categories, kind="judgments"
    )
    for case_id, row in predictions.items():
        if _calibration_timestamp(row["predicted_at"], "predicted_at") < freeze_time:
            raise OperationsError(
                "E_CALIBRATION_SPLIT_NOT_FROZEN",
                "judge prediction predates frozen split assignment",
            )
        if row["input_sha256"] != judge_inputs[case_id]:
            raise OperationsError(
                "E_CALIBRATION_JUDGE_INPUT",
                "judgment input digest differs from sanitized case input",
            )
        for role in ("model", "prompt", "rubric"):
            if row[f"{role}_sha256"] != artifact_hashes.get(role):
                raise OperationsError(
                    "E_CALIBRATION_ARTIFACT_BINDING",
                    f"judgment {role} digest differs from the current bound artifact",
                )
    return predictions


def _calibration_evaluate_bound(bound: Mapping[str, Any]) -> dict[str, Any]:
    artifacts = bound["artifacts"]
    roles = {"dataset", "assignments", "annotations", "judgments", "adjudications"}
    if not roles <= set(artifacts):
        raise OperationsError(
            "E_CALIBRATION_SCHEMA", "all five bound calibration artifacts are required"
        )
    bodies = {role: artifacts[role]["body"] for role in roles}
    case_ids, category_set, fingerprints, judge_inputs = _calibration_dataset(
        bodies["dataset"]
    )
    freeze_time, split_by_case = _calibration_splits(
        bodies["assignments"], case_ids, fingerprints
    )
    annotations, pair = _calibration_annotations(
        bodies["annotations"], case_ids, category_set
    )
    predictions = _calibration_predictions(
        bodies["judgments"],
        case_ids,
        category_set,
        judge_inputs,
        freeze_time,
        {role: artifacts[role]["sha256"] for role in ("model", "prompt", "rubric")},
    )
    references = _calibration_validate_rows(
        _calibration_rows(
            bodies["adjudications"], _CALIBRATION_SCHEMAS["adjudications"], "rows"
        ),
        case_ids,
        category_set,
        kind="adjudications",
    )
    counts = _calibration_metrics(
        case_ids, category_set, predictions, references, split_by_case
    )
    agreement = _calibration_agreement(annotations, pair)
    raw_annotations = [
        {
            "case_id": case_id,
            "annotator_id": annotator_id,
            "labels": list(annotations[case_id][annotator_id] or ()),
            "abstained": annotations[case_id][annotator_id] is None,
        }
        for case_id in sorted(case_ids)
        for annotator_id in pair
    ]
    adjudication_disagreements = sorted(
        case_id
        for case_id in case_ids
        if any(
            annotations[case_id][annotator_id] is None
            or annotations[case_id][annotator_id] != references[case_id]["labels"]
            or references[case_id]["abstained"]
            for annotator_id in pair
        )
    )
    core = {
        "schema": "factory.judge-calibration.v1",
        "binding_sha256": bound["binding_sha256"],
        "artifact_hashes": {role: artifacts[role]["sha256"] for role in sorted(roles)},
        "case_source_hashes": {
            case_id: fingerprints[case_id] for case_id in sorted(case_ids)
        },
        "split_sizes": {
            split: sum(value == split for value in split_by_case.values())
            for split in ("train", "dev", "holdout")
        },
        "per_category": counts,
        "raw_annotator_agreement": agreement,
        "raw_annotations": raw_annotations,
        "human_adjudication_disagreements": adjudication_disagreements,
        "adjudicated_labels": [
            {
                "case_id": case_id,
                "labels": list(references[case_id]["labels"]),
                "abstained": references[case_id]["abstained"],
            }
            for case_id in sorted(case_ids)
        ],
        "independence": "UNVERIFIED",
        "judge_input_deidentification": "UNVERIFIED",
        "holdout_input_exposure": "UNVERIFIED",
        "assignment_temporality": "DECLARED_TIMESTAMP_ORDER_ONLY",
        "authority": "none",
        "next_actions": [
            "Verify annotator identity and split-freeze provenance independently before making an independence or holdout claim.",
            "Review judge input content for sensitive data and label leakage before provider use.",
        ],
    }
    return {**core, "evaluation_sha256": _calibration_digest(core)}


def evaluate_judge_calibration(
    root: Path, request: Mapping[str, Any]
) -> dict[str, Any]:
    """Compute bounded local calibration metrics; hashes do not authenticate annotators."""
    from .analysis_evidence import validate_evaluation_bindings

    if not isinstance(request, Mapping):
        return {"state": "INCOMPLETE", "code": "TRACE_UNBOUND", "authority": "none"}
    bound = validate_evaluation_bindings(Path(root), request)
    if bound.get("state") != "BOUND_LOCAL_EVIDENCE":
        return {**bound, "schema": "factory.judge-calibration.v1", "authority": "none"}
    try:
        result = {
            **_calibration_evaluate_bound(bound),
            "state": "OBSERVED_LOCAL_METRICS",
        }
        result.pop("evaluation_sha256", None)
        result["evaluation_sha256"] = _calibration_digest(result)
        return result
    except (OperationsError, KeyError, TypeError, ValueError) as exc:
        return {
            "schema": "factory.judge-calibration.v1",
            "state": "INCOMPLETE",
            "code": getattr(exc, "code", "E_CALIBRATION_SCHEMA"),
            "authority": "none",
        }


@dataclass
class TelemetryRecorder:
    tenant_id: str
    service: str = "factoryline"
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    spans: list[dict[str, Any]] = field(default_factory=list)
    _active: ContextVar = field(
        default_factory=lambda: ContextVar("factory_active_span", default=None),
        repr=False,
    )

    def span(
        self,
        name: str,
        *,
        attributes: dict[str, Any] | None = None,
        status: str = "OK",
        duration_ms: int = 0,
        span_id: str | None = None,
        parent_span_id: str | None = None,
    ) -> dict[str, Any]:
        """Record a bounded telemetry span after validating its status and duration."""
        if len(self.spans) >= 10000 or len(canonical_json(attributes or {})) > 4096:
            raise OperationsError("E_TELEMETRY_BOUND", "telemetry bound exceeded")
        if (
            status not in {"OK", "ERROR"}
            or type(duration_ms) is not int
            or duration_ms < 0
        ):
            raise OperationsError(
                "E_TELEMETRY_SCHEMA", "invalid span status or duration"
            )
        span = {
            "schema": TELEMETRY_SCHEMA,
            "trace_id": self.trace_id,
            "span_id": span_id or uuid.uuid4().hex[:16],
            "parent_span_id": parent_span_id,
            "tenant_id": _required(self.tenant_id, "tenant_id"),
            "service": _required(self.service, "service"),
            "name": _required(name, "name"),
            "status": status,
            "duration_ms": duration_ms,
            "attributes": attributes or {},
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        span["span_sha256"] = sha256(canonical_json(span))
        # Copy through canonical bytes so later attribute mutations cannot alter evidence.
        import json

        self.spans.append(json.loads(canonical_json(span)))
        return span


@contextmanager
def measured_span(
    recorder: TelemetryRecorder, name: str, *, attributes: dict[str, Any] | None = None
):
    """Context manager-like generator for a measured local span."""
    started = time.perf_counter()
    span_id = uuid.uuid4().hex[:16]
    parent_span_id = recorder._active.get()
    token = recorder._active.set(span_id)
    try:
        yield span_id
    except BaseException:
        recorder.span(
            name,
            attributes=attributes,
            status="ERROR",
            duration_ms=round((time.perf_counter() - started) * 1000),
            span_id=span_id,
            parent_span_id=parent_span_id,
        )
        raise
    else:
        recorder.span(
            name,
            attributes=attributes,
            duration_ms=round((time.perf_counter() - started) * 1000),
            span_id=span_id,
            parent_span_id=parent_span_id,
        )
    finally:
        recorder._active.reset(token)


@dataclass(frozen=True)
class CanaryPolicy:
    max_error_rate: float = 0.01
    max_latency_p95_ms: int = 1000
    min_requests: int = 100


def evaluate_canary(
    *,
    artifact_digest: str,
    environment: str,
    metrics: dict[str, Any],
    policy: CanaryPolicy = CanaryPolicy(),
    previous_digest: str | None = None,
) -> dict[str, Any]:
    """Evaluate canary metrics against explicit thresholds and emit a promotion verdict."""
    requests = int(metrics.get("requests", 0))
    error_rate = float(metrics.get("error_rate", 1.0))
    latency = int(metrics.get("latency_p95_ms", 2**31 - 1))
    reasons: list[str] = []
    if requests < policy.min_requests:
        reasons.append("insufficient_requests")
    if error_rate > policy.max_error_rate:
        reasons.append("error_rate_exceeded")
    if latency > policy.max_latency_p95_ms:
        reasons.append("latency_exceeded")
    promoted = not reasons
    return {
        "schema": DEPLOYMENT_SCHEMA,
        "deployment_id": uuid.uuid4().hex,
        "environment": _required(environment, "environment"),
        "artifact_digest": _required(artifact_digest, "artifact_digest"),
        "previous_digest": previous_digest,
        "strategy": "canary",
        "metrics": {
            "requests": requests,
            "error_rate": error_rate,
            "latency_p95_ms": latency,
        },
        "policy": {
            "max_error_rate": policy.max_error_rate,
            "max_latency_p95_ms": policy.max_latency_p95_ms,
            "min_requests": policy.min_requests,
        },
        "decision": "PROMOTE" if promoted else "ROLLBACK",
        "reasons": reasons,
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def rollback_receipt(
    deployment: dict[str, Any], *, actor: str, reason: str
) -> dict[str, Any]:
    """Build an auditable rollback receipt bound to the original deployment digest."""
    if deployment.get("decision") != "ROLLBACK":
        raise OperationsError(
            "E_ROLLBACK_NOT_REQUIRED",
            "rollback receipt requires a failed deployment decision",
        )
    previous = _required(deployment.get("previous_digest"), "previous_digest")
    receipt = {
        "schema": DEPLOYMENT_SCHEMA,
        "kind": "rollback",
        "deployment_id": deployment.get("deployment_id"),
        "environment": deployment.get("environment"),
        "from_digest": deployment.get("artifact_digest"),
        "to_digest": previous,
        "actor": _required(actor, "actor"),
        "reason": _required(reason, "reason"),
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    receipt["receipt_sha256"] = sha256(canonical_json(receipt))
    return receipt


def vulnerability_response(
    *,
    vulnerability: str,
    severity: str,
    components: Iterable[str],
    actions: Iterable[str],
    status: str = "OPEN",
) -> dict[str, Any]:
    """Create a severity-aware vulnerability response with deterministic next actions."""
    severity = _required(severity, "severity").upper()
    if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise OperationsError(
            "E_VULNERABILITY_SEVERITY",
            "severity must be LOW, MEDIUM, HIGH, or CRITICAL",
        )
    response = {
        "schema": VULNERABILITY_SCHEMA,
        "vulnerability": _required(vulnerability, "vulnerability"),
        "severity": severity,
        "components": sorted({_required(item, "component") for item in components}),
        "actions": sorted({_required(item, "action") for item in actions}),
        "status": _required(status, "status").upper(),
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    response["response_sha256"] = sha256(canonical_json(response))
    return response


def connector_event(
    *,
    target: str,
    event_type: str,
    tenant_id: str,
    subject_digest: str,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Normalize a tenant connector event while rejecting missing authority fields."""
    target = _required(target, "target").lower()
    if target not in {"siem", "ticketing"}:
        raise OperationsError("E_CONNECTOR_TARGET", "target must be siem or ticketing")
    event = {
        "schema": CONNECTOR_SCHEMA,
        "target": target,
        "event_type": _required(event_type, "event_type"),
        "tenant_id": _required(tenant_id, "tenant_id"),
        "subject_digest": _required(subject_digest, "subject_digest"),
        "attributes": attributes or {},
        "disclosure": "metadata-only",
    }
    event["event_sha256"] = sha256(canonical_json(event))
    return event

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

import pytest

from factoryline.audit_trace import build_audit_trace
from factoryline.control_plane import canonical_json
from factoryline.operations import (
    CanaryPolicy,
    OperationsError,
    TelemetryRecorder,
    connector_event,
    evaluate_canary,
    evaluate_judge_calibration,
    measured_span,
    rollback_receipt,
    vulnerability_response,
)


def _calibration_bundle(
    root: Path,
    *,
    case_labels: list[list[str]],
    predicted_labels: list[list[str]],
    annotations: list[list[list[str]]] | None = None,
    assignments: list[str] | None = None,
    predicted_at: str = "2026-10-11T00:00:00+00:00",
    abstain_predictions: bool = False,
) -> tuple[dict, dict[str, Path]]:
    source_dir = root / "src"
    source_dir.mkdir()
    source = source_dir / "sample.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    for args in (
        ["init", "--quiet"],
        ["config", "user.name", "Calibration Test"],
        ["config", "user.email", "calibration@example.invalid"],
        ["add", "src/sample.py"],
        ["commit", "--quiet", "-m", "fixture"],
    ):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    trace = build_audit_trace(
        root,
        changed_paths=["src/sample.py"],
        lane_states={"tests": "PASS"},
        steps=[
            {
                "step_id": "bound-source",
                "input": "sha256:" + hashlib.sha256(b"input").hexdigest(),
                "guard": "SOURCE_BOUND",
                "decision": "RECORD",
                "state": "PASS",
                "source_paths": ["src/sample.py"],
            }
        ],
    )
    bodies: dict[str, dict] = {
        "tool": {"version": "1"},
        "model": {"id": "review-model", "version": "1"},
        "prompt": {"version": "1", "template": "review"},
        "rubric": {"version": "1"},
        "policy": {"version": "1"},
    }
    identity_hashes = {
        role: hashlib.sha256(json.dumps(bodies[role]).encode("utf-8")).hexdigest()
        for role in ("model", "prompt", "rubric")
    }
    cases = []
    for index, _ in enumerate(case_labels):
        cases.append(
            {
                "case_id": f"case-{index}",
                "buggy_source": f"BUGGY_{index} = {index}\n",
                "fixed_source": f"FIXED_{index} = {index}\n",
                "judge_input": f"Review code sample {index}.",
            }
        )
    bodies["dataset"] = {
        "schema": "factory.judge-calibration.dataset.v1",
        "categories": ["risk"],
        "cases": cases,
    }
    split_names = assignments or ["holdout"] * len(cases)
    bodies["assignments"] = {
        "schema": "factory.judge-calibration.assignments.v1",
        "frozen_at": "2026-10-10T00:00:00+00:00",
        "splits": {f"case-{index}": split for index, split in enumerate(split_names)},
    }
    annotation_values = annotations or [[labels, labels] for labels in case_labels]
    annotation_rows = []
    for index, pair in enumerate(annotation_values):
        for annotator_id, labels in zip(("independent-a", "independent-b"), pair):
            annotation_rows.append(
                {
                    "case_id": f"case-{index}",
                    "annotator_id": annotator_id,
                    "labels": labels,
                    "abstained": False,
                }
            )
    bodies["annotations"] = {
        "schema": "factory.judge-calibration.annotations.v1",
        "annotators": ["independent-a", "independent-b"],
        "rows": annotation_rows,
    }
    judgments = []
    for index, labels in enumerate(predicted_labels):
        input_digest = hashlib.sha256(
            canonical_json(cases[index]["judge_input"])
        ).hexdigest()
        judgments.append(
            {
                "case_id": f"case-{index}",
                "predicted_at": predicted_at,
                "labels": [] if abstain_predictions else labels,
                "abstained": abstain_predictions,
                "input_sha256": input_digest,
                **{f"{role}_sha256": digest for role, digest in identity_hashes.items()},
            }
        )
    bodies["judgments"] = {
        "schema": "factory.judge-calibration.judgments.v1",
        "rows": judgments,
    }
    bodies["adjudications"] = {
        "schema": "factory.judge-calibration.adjudications.v1",
        "rows": [
            {
                "case_id": f"case-{index}",
                "labels": labels,
                "abstained": False,
            }
            for index, labels in enumerate(case_labels)
        ],
    }
    paths = {"trace": root / "trace.json", "candidate": root / "candidate.json"}
    paths["trace"].write_text(json.dumps(trace), encoding="utf-8")
    paths["candidate"].write_text(json.dumps(trace["candidate"]), encoding="utf-8")
    artifact_paths: dict[str, Path] = {}
    artifact_descriptors = {}
    for role, body in bodies.items():
        path = root / f"{role}.json"
        path.write_text(json.dumps(body), encoding="utf-8")
        artifact_paths[role] = path
        artifact_descriptors[role] = {
            "path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    binding = {
        "schema": "factory.span-evaluation.binding-request.v1",
        "trace": {
            "path": paths["trace"].name,
            "sha256": hashlib.sha256(paths["trace"].read_bytes()).hexdigest(),
        },
        "candidate": {
            "path": paths["candidate"].name,
            "sha256": hashlib.sha256(paths["candidate"].read_bytes()).hexdigest(),
        },
        "sources": [
            {
                "path": "src/sample.py",
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        ],
        "artifacts": artifact_descriptors,
        "applicability": {"model": "applicable"},
    }
    return binding, artifact_paths


def test_canary_promotes_only_after_policy_thresholds():
    good = evaluate_canary(
        artifact_digest="sha-good",
        environment="prod",
        metrics={"requests": 100, "error_rate": 0.0, "latency_p95_ms": 10},
    )
    assert good["decision"] == "PROMOTE"
    bad = evaluate_canary(
        artifact_digest="sha-bad",
        environment="prod",
        metrics={"requests": 100, "error_rate": 0.2, "latency_p95_ms": 10},
        previous_digest="sha-good",
        policy=CanaryPolicy(max_error_rate=0.01),
    )
    assert bad["decision"] == "ROLLBACK"
    receipt = rollback_receipt(
        bad, actor="release-manager", reason="error budget exceeded"
    )
    assert receipt["to_digest"] == "sha-good"


def test_telemetry_is_measured_and_errors_are_recorded():
    recorder = TelemetryRecorder("acme")
    with measured_span(recorder, "compile"):
        time.sleep(0.001)
    assert recorder.spans[0]["duration_ms"] >= 0
    with pytest.raises(RuntimeError):
        with measured_span(recorder, "failed"):
            raise RuntimeError("boom")
    assert recorder.spans[-1]["status"] == "ERROR"


def test_telemetry_nested_spans_retain_parent_and_snapshot_attributes():
    recorder = TelemetryRecorder("local")
    attributes = {"count": 1}
    with measured_span(recorder, "root") as root_id:
        with measured_span(recorder, "child", attributes=attributes):
            pass
    attributes["count"] = 9
    child, parent = recorder.spans
    assert child["parent_span_id"] == root_id == parent["span_id"]
    assert parent["parent_span_id"] is None
    assert child["attributes"] == {"count": 1}
    with measured_span(recorder, "next"):
        pass
    assert recorder.spans[-1]["parent_span_id"] is None


def test_telemetry_rejects_oversized_attributes_and_invalid_status():
    recorder = TelemetryRecorder("local")
    with pytest.raises(OperationsError, match="bound"):
        recorder.span("large", attributes={"data": "x" * 4096})
    with pytest.raises(OperationsError, match="status"):
        recorder.span("invalid", status="PASS")
    assert recorder.spans == []


def test_vulnerability_and_connector_outputs_are_digest_bound_and_redacted():
    response = vulnerability_response(
        vulnerability="CVE-1",
        severity="high",
        components=["pkg-a"],
        actions=["patch", "notify"],
    )
    assert response["severity"] == "HIGH" and response["response_sha256"]
    event = connector_event(
        target="siem",
        event_type="vulnerability.opened",
        tenant_id="acme",
        subject_digest="a" * 64,
        attributes={"severity": "HIGH"},
    )
    assert event["disclosure"] == "metadata-only"
    assert "raw_evidence" not in event
    with pytest.raises(OperationsError) as error:
        connector_event(
            target="email", event_type="x", tenant_id="acme", subject_digest="a"
        )
    assert error.value.code == "E_CONNECTOR_TARGET"


def test_judge_calibration_reports_confusion_per_split_and_raw_agreement(
    tmp_path: Path,
):
    truth = [["risk"], ["risk"], [], []]
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=truth,
        predicted_labels=[["risk"], [], ["risk"], []],
        annotations=[[["risk"], ["risk"]], [["risk"], []], [[], []], [[], []]],
        assignments=["train", "dev", "holdout", "holdout"],
    )

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "OBSERVED_LOCAL_METRICS"
    overall = result["per_category"]["risk"]["overall"]
    assert (overall["tp"], overall["fp"], overall["fn"], overall["tn"]) == (1, 1, 1, 1)
    assert result["split_sizes"] == {"train": 1, "dev": 1, "holdout": 2}
    assert result["per_category"]["risk"]["by_split"]["holdout"]["fp"] == 1
    assert result["per_category"]["risk"]["by_split"]["holdout"]["tn"] == 1
    assert result["raw_annotator_agreement"]["agreement"] == 0.75
    assert result["raw_annotator_agreement"]["cohen_kappa"] == 0.5
    assert result["human_adjudication_disagreements"] == ["case-1"]
    assert result["independence"] == "UNVERIFIED"
    assert result["judge_input_deidentification"] == "UNVERIFIED"
    assert result["holdout_input_exposure"] == "UNVERIFIED"
    assert result["authority"] == "none"
    receipt = {
        key: value for key, value in result.items() if key != "evaluation_sha256"
    }
    assert (
        result["evaluation_sha256"]
        == hashlib.sha256(canonical_json(receipt)).hexdigest()
    )


def test_judge_calibration_empty_negative_labels_and_all_abstentions_are_undefined(
    tmp_path: Path,
):
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=[[], []],
        predicted_labels=[[], []],
        abstain_predictions=True,
    )

    result = evaluate_judge_calibration(tmp_path, binding)
    metrics = result["per_category"]["risk"]["overall"]

    assert result["state"] == "OBSERVED_LOCAL_METRICS"
    assert metrics["eligible"] == 2
    assert metrics["judged"] == 0
    assert metrics["coverage"] == 0
    assert metrics["abstentions"] == 2
    assert metrics["positive_abstentions"] == 0
    assert metrics["negative_abstentions"] == 2
    assert metrics["recall"] is None and metrics["precision"] is None
    assert result["raw_annotator_agreement"]["cohen_kappa"] is None
    assert (
        result["raw_annotator_agreement"]["kappa_undefined_reason"] == "constant_labels"
    )


def test_judge_calibration_rejects_cross_split_duplicate_evidence(tmp_path: Path):
    binding, paths = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"], []],
        predicted_labels=[["risk"], []],
        assignments=["train", "holdout"],
    )
    dataset_path = paths["dataset"]
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    dataset["cases"][1]["buggy_source"] = dataset["cases"][0]["buggy_source"]
    dataset_path.write_text(json.dumps(dataset), encoding="utf-8")
    binding["artifacts"]["dataset"]["sha256"] = hashlib.sha256(
        dataset_path.read_bytes()
    ).hexdigest()

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["code"] == "E_CALIBRATION_CROSS_SPLIT_DUPLICATE"


def test_judge_calibration_rejects_prediction_before_split_freeze(tmp_path: Path):
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"]],
        predicted_labels=[["risk"]],
        predicted_at="2026-10-09T00:00:00+00:00",
    )

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["code"] == "E_CALIBRATION_SPLIT_NOT_FROZEN"


def test_judge_calibration_preserves_low_human_agreement_and_constant_kappa_reason(
    tmp_path: Path,
):
    binding, _ = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"], []],
        predicted_labels=[["risk"], []],
        annotations=[[["risk"], []], [["risk"], []]],
    )
    result = evaluate_judge_calibration(tmp_path, binding)
    assert result["raw_annotator_agreement"]["agreement"] == 0
    assert result["raw_annotator_agreement"]["cohen_kappa"] == 0
    assert result["adjudicated_labels"] == [
        {"case_id": "case-0", "labels": ["risk"], "abstained": False},
        {"case_id": "case-1", "labels": [], "abstained": False},
    ]

    constant_root = tmp_path / "constant"
    constant_root.mkdir()
    constant_binding, _ = _calibration_bundle(
        constant_root,
        case_labels=[["risk"], ["risk"]],
        predicted_labels=[["risk"], ["risk"]],
    )
    constant = evaluate_judge_calibration(constant_root, constant_binding)
    assert constant["raw_annotator_agreement"]["cohen_kappa"] is None
    assert (
        constant["raw_annotator_agreement"]["kappa_undefined_reason"]
        == "constant_labels"
    )
    assert constant["independence"] == "UNVERIFIED"


def test_judge_calibration_rejects_stale_bound_artifact_bytes(tmp_path: Path):
    binding, paths = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"]],
        predicted_labels=[["risk"]],
    )
    assignments = paths["assignments"]
    body = json.loads(assignments.read_text(encoding="utf-8"))
    body["splits"]["case-0"] = "train"
    assignments.write_text(json.dumps(body), encoding="utf-8")

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["errors"][0]["code"] == "TRACE_UNBOUND"


@pytest.mark.parametrize("role", ["model", "prompt", "rubric"])
def test_judge_calibration_rejects_prediction_identity_mismatch(
    tmp_path: Path, role: str
):
    binding, paths = _calibration_bundle(
        tmp_path,
        case_labels=[["risk"]],
        predicted_labels=[["risk"]],
    )
    judgments_path = paths["judgments"]
    judgments = json.loads(judgments_path.read_text(encoding="utf-8"))
    judgments["rows"][0][f"{role}_sha256"] = "0" * 64
    judgments_path.write_text(json.dumps(judgments), encoding="utf-8")
    binding["artifacts"]["judgments"]["sha256"] = hashlib.sha256(
        judgments_path.read_bytes()
    ).hexdigest()

    result = evaluate_judge_calibration(tmp_path, binding)

    assert result["state"] == "INCOMPLETE"
    assert result["code"] == "E_CALIBRATION_ARTIFACT_BINDING"


def _sampling_bundle(root):
    from test_analysis_evidence import _span_fixture

    request, _ = _span_fixture(root)
    binding = request["binding_request"]
    policy = {
        "schema": "factory.trace-sampling-policy.v1",
        "seed": "fixed-seed",
        "fractions": {"low": 1, "medium": 1, "high": 1},
        "max_cost_usd": 1,
        "max_latency_ms": 1000,
        "approval_reference": "approved-policy",
    }
    rows = [
        {
            "schema": "factory.trace-sampling-observation.v1",
            "trace_id": f"trace-{i}",
            "trace_sha256": hashlib.sha256(str(i).encode()).hexdigest(),
            "risk": risk,
            "estimated_cost_usd": 0.1,
            "estimated_latency_ms": 10,
            "actual_cost_usd": 0.1,
            "actual_latency_ms": 10,
            "scored": True,
        }
        for i, risk in enumerate(("low", "medium", "high"))
    ]
    population = {
        "schema": "factory.trace-sampling-population.v1",
        "window_id": "window-1",
        "eligible_count": 3,
        "traces": rows,
    }
    return binding, {"policy": policy, "sampling": population}


def _sampling_write(root, binding, bodies):
    for role, body in bodies.items():
        raw = canonical_json(body)
        (root / f"{role}.json").write_bytes(raw)
        binding["artifacts"][role] = {
            "path": f"{role}.json",
            "sha256": hashlib.sha256(raw).hexdigest(),
        }


def test_sampling_real_bound_population_preserves_denominators(tmp_path):
    from factoryline.operations import evaluate_trace_sampling

    binding, bodies = _sampling_bundle(tmp_path)
    _sampling_write(tmp_path, binding, bodies)
    result = evaluate_trace_sampling(tmp_path, binding)
    assert result["state"] == "OBSERVED_LOCAL_METRICS"
    assert (
        result["eligible"],
        result["selected"],
        result["scored"],
        result["unscored"],
    ) == (3, 3, 3, 0)
    assert all(
        item == {"eligible": 1, "scored": 1} for item in result["by_risk"].values()
    )
    assert result["population_completeness"] == "UNVERIFIED_OUTSIDE_SUPPLIED_WINDOW"
    assert result["authority"] == "none"


@pytest.mark.parametrize(
    "mutation,state",
    [
        ("denominator", "INCOMPLETE"),
        ("duplicate", "INCOMPLETE"),
        ("unknown", "INCOMPLETE"),
        ("budget", "FAIL"),
        ("overspend", "FAIL"),
        ("unscored", "INCOMPLETE"),
        ("unscored_overspend", "FAIL"),
    ],
)
def test_sampling_rejects_missing_usage_or_budget_bypass(tmp_path, mutation, state):
    from factoryline.operations import evaluate_trace_sampling

    binding, bodies = _sampling_bundle(tmp_path)
    population, policy = bodies["sampling"], bodies["policy"]
    if mutation == "denominator":
        population["eligible_count"] = 4
    elif mutation == "duplicate":
        population["traces"][1]["trace_id"] = "trace-0"
    elif mutation == "unknown":
        population["traces"][0]["actual_cost_usd"] = None
    elif mutation == "budget":
        policy["max_cost_usd"] = 0
    elif mutation == "overspend":
        population["traces"][0]["actual_cost_usd"] = 2
    elif mutation == "unscored_overspend":
        population["traces"][0]["actual_cost_usd"] = 2
        population["traces"][0]["scored"] = False
    else:
        population["traces"][0]["scored"] = False
    _sampling_write(tmp_path, binding, bodies)
    result = evaluate_trace_sampling(tmp_path, binding)
    assert result["state"] == state
    assert result["next_actions"]


def _rollout_bundle(root):
    from test_analysis_evidence import _span_fixture

    request, _ = _span_fixture(root)
    binding = request["binding_request"]
    commit = json.loads((root / "candidate.json").read_text())["commit"]
    bodies = {}
    for role, before, after in (
        ("deployment_control", "STAGED", "RUNNING"),
        ("killswitch_control", "ENABLED", "DISABLED"),
        ("rollback_control", "CANDIDATE", "BASELINE"),
    ):
        bodies[role] = {
            "schema": "factory.rollout-control-observation.v1",
            "control": role,
            "target": "authorized-staging",
            "candidate_commit": commit,
            "observed_at": "2026-10-12T10:10:00Z",
            "before": before,
            "after": after,
            "evidence_sha256": binding["sources"][0]["sha256"],
        }
    _sampling_write(root, binding, bodies)
    bodies["rollout"] = {
        "schema": "factory.rollout-evidence.v1",
        "mode": "live",
        "target": "authorized-staging",
        "candidate_commit": commit,
        "window_start": "2026-10-12T10:00:00Z",
        "window_end": "2026-10-12T11:00:00Z",
        "controls": {role: binding["artifacts"][role]["sha256"] for role in bodies},
        "randomization": None,
    }
    return binding, bodies


def test_rollout_evidence_bound_controls_do_not_authorize_promotion(tmp_path):
    from factoryline.operations import evaluate_rollout_evidence

    binding, bodies = _rollout_bundle(tmp_path)
    _sampling_write(tmp_path, binding, bodies)
    result = evaluate_rollout_evidence(tmp_path, binding)
    assert result["state"] == "OBSERVED_LOCAL_CONTROLS"
    assert result["randomization"] is None
    assert not result["promotion_authorized"]
    assert result["producer_authenticity"] == "UNVERIFIED"


@pytest.mark.parametrize(
    "mutation", ["offline", "target", "missing", "transition", "outside", "unbound"]
)
def test_rollout_evidence_rejects_missing_stale_or_offline_controls(tmp_path, mutation):
    from factoryline.operations import evaluate_rollout_evidence

    binding, bodies = _rollout_bundle(tmp_path)
    rollout, kill = bodies["rollout"], bodies["killswitch_control"]
    if mutation == "offline":
        rollout["mode"] = "replay"
    elif mutation == "target":
        kill["target"] = "different-target"
    elif mutation == "missing":
        rollout["controls"].pop("rollback_control")
    elif mutation == "transition":
        kill["after"] = "ENABLED"
    elif mutation == "outside":
        kill["observed_at"] = "2026-10-12T12:00:00Z"
    else:
        kill["evidence_sha256"] = "a" * 64
    _sampling_write(tmp_path, binding, bodies)
    if mutation not in {"offline", "missing"}:
        rollout["controls"]["killswitch_control"] = binding["artifacts"][
            "killswitch_control"
        ]["sha256"]
        _sampling_write(tmp_path, binding, bodies)
    assert evaluate_rollout_evidence(tmp_path, binding)["state"] == "INCOMPLETE"


def test_rollout_evidence_randomization_requires_sticky_unique_assignments():
    from factoryline.operations import _rollout_assignment, OperationsError

    seed = "cohort-seed"
    rows = []
    for index in range(100):
        unit = hashlib.sha256(str(index).encode()).hexdigest()
        rank = (
            int(hashlib.sha256(canonical_json([seed, unit])).hexdigest(), 16) / 2**256
        )
        rows.append(
            {"unit_sha256": unit, "arm": "treatment" if rank < 0.5 else "control"}
        )
    body = {
        "schema": "factory.rollout-randomization.v1",
        "seed": seed,
        "treatment_fraction": 0.5,
        "srm_alpha": 0.01,
        "assignments": rows,
    }
    result = _rollout_assignment(body)
    assert result["units"] == 100
    assert result["statistical_power"] is None
    rows[0]["arm"] = "control" if rows[0]["arm"] == "treatment" else "treatment"
    with pytest.raises(OperationsError):
        _rollout_assignment(body)

from __future__ import annotations

import time

import pytest

from factoryline.operations import (
    CanaryPolicy,
    OperationsError,
    TelemetryRecorder,
    connector_event,
    evaluate_canary,
    measured_span,
    rollback_receipt,
    vulnerability_response,
)


def test_canary_promotes_only_after_policy_thresholds():
    good = evaluate_canary(
        artifact_digest="sha-good", environment="prod",
        metrics={"requests": 100, "error_rate": 0.0, "latency_p95_ms": 10},
    )
    assert good["decision"] == "PROMOTE"
    bad = evaluate_canary(
        artifact_digest="sha-bad", environment="prod",
        metrics={"requests": 100, "error_rate": 0.2, "latency_p95_ms": 10},
        previous_digest="sha-good",
        policy=CanaryPolicy(max_error_rate=0.01),
    )
    assert bad["decision"] == "ROLLBACK"
    receipt = rollback_receipt(bad, actor="release-manager", reason="error budget exceeded")
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


def test_vulnerability_and_connector_outputs_are_digest_bound_and_redacted():
    response = vulnerability_response(
        vulnerability="CVE-1", severity="high", components=["pkg-a"], actions=["patch", "notify"]
    )
    assert response["severity"] == "HIGH" and response["response_sha256"]
    event = connector_event(
        target="siem", event_type="vulnerability.opened", tenant_id="acme",
        subject_digest="a" * 64, attributes={"severity": "HIGH"},
    )
    assert event["disclosure"] == "metadata-only"
    assert "raw_evidence" not in event
    with pytest.raises(OperationsError) as error:
        connector_event(target="email", event_type="x", tenant_id="acme", subject_digest="a")
    assert error.value.code == "E_CONNECTOR_TARGET"


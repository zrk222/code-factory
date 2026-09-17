from __future__ import annotations

import pytest

from factoryline.agui import (
    AguiError,
    build_release_completed_event,
    build_release_interrupt_event,
    build_review_events,
    validate_agui_events,
)
from factoryline.mcp_mrt import release_gate_input_required


def test_review_events_are_deterministic_and_ordered() -> None:
    status = {
        "state": "INITIALIZED",
        "marker": "FIRST_LAP_INITIALIZED",
        "receipt_path": ".factory/first-lap/init.json",
        "receipt_sha256": "a" * 64,
        "stale_paths": [],
        "next_actions": ["factory first-lap calibrate cases.json --root ."],
        "claim_boundary": "Local metadata only.",
        "authority": {"execution": False, "approval": False},
    }
    first = build_review_events(status, run_id="run-01", surface="mission_control")
    assert first == build_review_events(
        status, run_id="run-01", surface="mission_control"
    )
    assert [event["type"] for event in first] == [
        "RUN_STARTED",
        "STATE_SNAPSHOT",
        "REVIEW_CARD",
        "RUN_FINISHED",
    ]
    assert [event["sequence"] for event in first] == [0, 1, 2, 3]


def test_review_events_reject_sensitive_fields() -> None:
    with pytest.raises(AguiError) as error:
        validate_agui_events(
            [
                {
                    "schema": "factory.agui.events.v1",
                    "runId": "run-01",
                    "sequence": 0,
                    "type": "RUN_STARTED",
                    "payload": {"token": "secret"},
                    "eventId": "bad",
                    "payloadSha256": "bad",
                },
            ]
        )
    assert error.value.code in {"E_AGUI_SENSITIVE", "E_AGUI_HASH", "E_AGUI_BOUNDS"}


def test_release_gate_interrupt_is_human_owned_and_bounded() -> None:
    envelope = release_gate_input_required(
        {
            "feature": "checkout",
            "state": "BLOCKED",
            "classification": "proof_debt",
            "blockers": [
                {
                    "lane": "failure_recovery",
                    "code": "RETRY_NOT_PROVEN",
                    "severity": "HIGH",
                }
            ],
            "next_action": {"action": "inspect_receipt"},
        }
    )
    event = build_release_interrupt_event(envelope, run_id="gate-01")
    assert event["type"] == "INTERRUPT"
    assert event["payload"]["humanOwned"] is True
    assert event["payload"]["authority"]["release"] is False
    assert "prompt" not in event["payload"]


def test_release_completed_event_does_not_grant_release_authority() -> None:
    event = build_release_completed_event(
        {
            "type": "completed",
            "toolCallId": "release-gate:abc",
            "status": "RELEASE_APPROVED",
            "receiptHash": "sha256:" + "b" * 64,
            "summary": "Local decision sealed.",
        }
    )
    assert event["type"] == "RUN_FINISHED"
    assert event["payload"]["humanOwned"] is True
    assert event["payload"]["authority"]["release"] is False

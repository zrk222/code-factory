from __future__ import annotations

from factoryline.live_activity import LiveActivity, activity_snapshot, request_stop


def test_live_activity_projects_current_stage_and_cooperative_stop(tmp_path):
    activity = LiveActivity(tmp_path, "run-123", "proof-review", 3)
    activity.start()
    activity.stage_started("forgeline", "verify-tests")

    current = activity_snapshot(tmp_path)
    assert current["available"] is True
    assert current["status"] == "active"
    assert current["current_stage"] == {"module": "forgeline", "stage": "verify-tests", "started_at": current["current_stage"]["started_at"]}
    assert current["elapsed_ms"] is not None

    result = request_stop(tmp_path)
    assert result["marker"] == "LIVE_ACTIVITY_STOP_REQUESTED"
    assert activity.heartbeat() is False

    activity.finish("halted", halted_at="forgeline:verify-tests")
    completed = activity_snapshot(tmp_path)
    assert completed["status"] == "halted"
    assert completed["halted_at"] == "forgeline:verify-tests"


def test_live_activity_marks_missing_heartbeats_stale_without_rewriting_receipt_state(tmp_path):
    activity = LiveActivity(tmp_path, "run-456", "sample", 1)
    activity.start()

    stale = activity_snapshot(tmp_path, stale_after_seconds=-1)
    assert stale["status"] == "stale"
    assert "LIVE_ACTIVITY_STALE" in stale["markers"]

"""Habituation gate — calibrating the human approval signal.

Grouped by the guarantee under test. The guarantees that matter are: drift is
measured against a reviewer's own baseline and never against peers, an
uncorrected proxy cannot block a merge, and no identity or per-person row
reaches a public export.
"""
from __future__ import annotations

import json

import pytest

from factoryline.habituation import (
    BLOCK_DRIFT,
    HabituationError,
    MIN_AGENT_REVIEWS,
    MIN_DEFECT_SAMPLE,
    blind_spot_sample,
    calibrate_reviewer,
    defect_linkage,
    evaluate_gate,
    export_public_habituation_report,
    load_reviews,
    normalize_review,
    public_habituation_report,
    record_calibration,
    record_resample_outcome,
    record_review,
)


def review(rid, reviewer="alice", kind="agent", seconds=60.0, lines=100, comments=3, approved=True):
    return {
        "review_id": rid, "reviewer": reviewer, "author_kind": kind,
        "review_seconds": seconds, "changed_lines": lines,
        "inline_comments": comments, "approved": approved,
    }


def seed(root, *, agent_seconds=10.0, human_seconds=60.0, n=6, reviewer="alice"):
    """Habituated reviewer: fast on agent code, slow on human code.

    Review ids are namespaced per reviewer because a review id identifies a
    reviewer-and-change pair, not a change alone.
    """
    who = reviewer.split("@")[0]
    for i in range(n):
        record_review(root, review(f"a-{who}-{i}", reviewer, "agent", agent_seconds))
        record_review(root, review(f"h-{who}-{i}", reviewer, "human", human_seconds))


# ---------------------------------------------------------------------------
# Event validation
# ---------------------------------------------------------------------------
def test_scrutiny_ratio_is_seconds_per_hundred_lines():
    r = normalize_review(review("r-1", seconds=60.0, lines=200))
    assert r["scrutiny_ratio"] == 30.0


def test_zero_changed_lines_refused():
    """A review of nothing has no scrutiny ratio; inventing one poisons the window."""
    with pytest.raises(HabituationError) as exc:
        normalize_review(review("r-1", lines=0))
    assert exc.value.code == "CHANGED_LINES_INVALID"


def test_boolean_changed_lines_refused():
    with pytest.raises(HabituationError) as exc:
        normalize_review({**review("r-1"), "changed_lines": True})
    assert exc.value.code == "CHANGED_LINES_INVALID"


def test_unknown_author_kind_refused():
    with pytest.raises(HabituationError) as exc:
        normalize_review({**review("r-1"), "author_kind": "robot"})
    assert exc.value.code == "AUTHOR_KIND_INVALID"


def test_reviewer_identity_is_hashed_not_stored():
    r = normalize_review(review("r-1", reviewer="alice@example.com"))
    assert "alice" not in json.dumps(r)
    assert len(r["reviewer_key"]) == 16


def test_identity_hash_is_case_and_space_stable():
    a = normalize_review(review("r-1", reviewer="Alice@Example.com "))
    b = normalize_review(review("r-2", reviewer="alice@example.com"))
    assert a["reviewer_key"] == b["reviewer_key"]


def test_review_overwrite_refused(tmp_path):
    record_review(tmp_path, review("r-1"))
    with pytest.raises(HabituationError) as exc:
        record_review(tmp_path, review("r-1"))
    assert exc.value.code == "REVIEW_OVERWRITE_REFUSED"
    record_review(tmp_path, review("r-1"), replace=True)


# ---------------------------------------------------------------------------
# Calibration: self-baseline only
# ---------------------------------------------------------------------------
def test_drift_detected_against_own_baseline(tmp_path):
    seed(tmp_path, agent_seconds=10.0, human_seconds=60.0)
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["withheld"] is False
    assert result["scrutiny_drift"] == pytest.approx(1 - 10 / 60)
    assert result["drift_band"] == "block"


def test_no_drift_when_scrutiny_matches(tmp_path):
    seed(tmp_path, agent_seconds=60.0, human_seconds=60.0)
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["scrutiny_drift"] == 0.0
    assert result["drift_band"] == "nominal"


def test_drift_withheld_below_agent_sample_floor(tmp_path):
    for i in range(MIN_AGENT_REVIEWS - 1):
        record_review(tmp_path, review(f"a-{i}", kind="agent"))
    for i in range(10):
        record_review(tmp_path, review(f"h-{i}", kind="human"))
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["withheld"] is True
    assert result["scrutiny_drift"] is None
    assert "agent-authored reviews observed" in result["withheld_reason"]


def test_drift_withheld_without_a_personal_baseline(tmp_path):
    """No human-authored baseline means no comparison. Comparing against other
    reviewers would attribute an exposure effect to a person."""
    for i in range(10):
        record_review(tmp_path, review(f"a-{i}", kind="agent"))
    result = calibrate_reviewer(load_reviews(tmp_path))
    assert result["withheld"] is True
    assert "own baseline" in result["withheld_reason"]


def test_calibration_receipt_marks_self_baseline(tmp_path):
    seed(tmp_path)
    receipt = record_calibration(tmp_path)
    assert "BASELINE_IS_SELF_NOT_PEER" in receipt["markers"]
    assert "SCRUTINY_FLOOR_BREACHED" in receipt["markers"]


def test_calibration_refuses_empty_corpus(tmp_path):
    with pytest.raises(HabituationError) as exc:
        record_calibration(tmp_path)
    assert exc.value.code == "NO_REVIEWS"


def test_separate_reviewers_calibrated_independently(tmp_path):
    seed(tmp_path, reviewer="alice", agent_seconds=10.0, human_seconds=60.0)
    seed(tmp_path, reviewer="bob", agent_seconds=60.0, human_seconds=60.0)
    receipt = record_calibration(tmp_path)
    assert receipt["reviewers"] == 2
    bands = sorted(c["drift_band"] for c in receipt["calibrations"])
    assert bands == ["block", "nominal"]


# ---------------------------------------------------------------------------
# Blind-spot sampling
# ---------------------------------------------------------------------------
def test_sampling_is_deterministic(tmp_path):
    seed(tmp_path, n=20)
    first = blind_spot_sample(tmp_path, rate=50)
    second = blind_spot_sample(tmp_path, rate=50)
    assert first["selected"] == second["selected"]


def test_sampling_only_draws_from_low_scrutiny_half(tmp_path):
    for i in range(10):
        record_review(tmp_path, review(f"fast-{i}", kind="agent", seconds=1.0))
        record_review(tmp_path, review(f"slow-{i}", kind="agent", seconds=999.0))
    sample = blind_spot_sample(tmp_path, rate=100)
    assert all(s.startswith("fast-") for s in sample["selected"])


def test_invalid_sample_rate_refused(tmp_path):
    seed(tmp_path)
    for bad in (0, 101, True):
        with pytest.raises(HabituationError) as exc:
            blind_spot_sample(tmp_path, rate=bad)
        assert exc.value.code == "SAMPLE_RATE_INVALID"


def test_resample_reviewer_must_differ_from_approver(tmp_path):
    """A signal cannot correct itself; reuses the learning-loop identity rule."""
    record_review(tmp_path, review("a-1", reviewer="alice"))
    with pytest.raises(HabituationError) as exc:
        record_resample_outcome(tmp_path, "a-1", defect_found=True, reviewer="alice")
    assert exc.value.code == "RESAMPLE_IDENTITY_CONFLICT"


def test_resample_outcome_recorded(tmp_path):
    record_review(tmp_path, review("a-1", reviewer="alice"))
    receipt = record_resample_outcome(tmp_path, "a-1", defect_found=True, reviewer="bob")
    assert receipt["defect_found"] is True
    assert "alice" not in json.dumps(receipt) and "bob" not in json.dumps(receipt)


# ---------------------------------------------------------------------------
# The central safety property: an uncorrected proxy cannot block
# ---------------------------------------------------------------------------
def test_breach_alone_does_not_block(tmp_path):
    seed(tmp_path, agent_seconds=5.0, human_seconds=60.0)
    gate = evaluate_gate(tmp_path, allow_block=False)
    assert gate["action"] == "second_approver"
    assert gate["blocking"] is False


def test_blocking_refused_while_proxy_is_uncorrected(tmp_path):
    """allow_block is requested but no resample outcomes exist."""
    seed(tmp_path, agent_seconds=5.0, human_seconds=60.0)
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["blocking"] is False
    assert gate["action"] == "second_approver"
    assert "uncorrected proxy" in gate["reason"]
    assert "PROXY_UNCORRECTED" in gate["markers"]


def test_blocking_permitted_once_resampling_exists(tmp_path):
    seed(tmp_path, agent_seconds=5.0, human_seconds=60.0)
    record_resample_outcome(tmp_path, "a-alice-0", defect_found=False, reviewer="bob")
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["blocking"] is True
    assert gate["action"] == "fail_closed"
    assert "FAIL_CLOSED_ENGAGED" in gate["markers"]


def test_nominal_scrutiny_takes_no_action(tmp_path):
    seed(tmp_path, agent_seconds=60.0, human_seconds=60.0)
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["action"] == "none"
    assert gate["blocking"] is False


def test_warn_band_only_surfaces(tmp_path):
    seed(tmp_path, agent_seconds=25.0, human_seconds=60.0)  # ~58% drift, below block
    gate = evaluate_gate(tmp_path, allow_block=True)
    assert gate["action"] == "surface"
    assert gate["blocking"] is False


# ---------------------------------------------------------------------------
# Defect linkage: modeled, withheld by default, never individual blame
# ---------------------------------------------------------------------------
def test_defect_linkage_withheld_by_default(tmp_path):
    seed(tmp_path)
    linkage = defect_linkage(tmp_path)
    assert linkage["withheld"] is True
    assert linkage["tier"] == "modeled"
    assert linkage["assumptions"]


def test_defect_linkage_withheld_below_sample_floor(tmp_path):
    seed(tmp_path)
    record_resample_outcome(tmp_path, "a-alice-0", defect_found=True, reviewer="bob")
    linkage = defect_linkage(tmp_path, enable=True)
    assert linkage["withheld"] is True
    assert str(MIN_DEFECT_SAMPLE) in linkage["withheld_reason"]


def test_defect_linkage_emits_with_limits_once_sampled(tmp_path):
    for i in range(MIN_DEFECT_SAMPLE):
        record_review(tmp_path, review(f"a-{i}", reviewer="alice"))
        record_resample_outcome(tmp_path, f"a-{i}", defect_found=(i % 4 == 0), reviewer="bob")
    linkage = defect_linkage(tmp_path, enable=True)
    assert linkage["withheld"] is False
    assert linkage["defect_rate_in_low_scrutiny_sample"] == 0.25
    assert "not attributable to any individual" in linkage["interpretation_limit"]
    assert any("not evidence that low scrutiny caused" in a for a in linkage["assumptions"])


# ---------------------------------------------------------------------------
# Disclosure boundary
# ---------------------------------------------------------------------------
def test_public_report_exports_no_identity_or_per_person_row(tmp_path):
    seed(tmp_path, reviewer="alice@example.com")
    seed(tmp_path, reviewer="bob@example.com", n=6)
    report = public_habituation_report(tmp_path)
    blob = json.dumps(report)
    assert "alice" not in blob and "bob" not in blob
    for row in load_reviews(tmp_path):
        assert row["reviewer_key"] not in blob, "pseudonymous key still identifies a person"
        assert row["review_id"] not in blob
    assert "calibrations" not in report, "no per-reviewer rows may be exported"


def test_public_report_carries_band_distribution_only(tmp_path):
    seed(tmp_path, reviewer="alice", agent_seconds=5.0, human_seconds=60.0)
    seed(tmp_path, reviewer="bob", agent_seconds=60.0, human_seconds=60.0)
    report = public_habituation_report(tmp_path)
    assert report["reviewers_by_drift_band"] == {"block": 1, "nominal": 1}
    assert report["reviewers_observed"] == 2


def test_public_report_on_empty_store(tmp_path):
    report = public_habituation_report(tmp_path)
    assert report["reviews_observed"] == 0
    assert report["median_scrutiny_drift"] is None
    assert report["defect_linkage"]["withheld"] is True


def test_public_report_export_round_trips(tmp_path):
    seed(tmp_path)
    out = export_public_habituation_report(tmp_path, tmp_path / "pub.json")
    assert json.loads(out.read_text(encoding="utf-8"))["marker"] == "HABITUATION_PUBLIC_REPORT"

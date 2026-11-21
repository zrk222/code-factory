"""Deterministic tests for the approved commercial policy decisions."""

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from factoryline import commercial_policy as cp

ROOT = Path(__file__).resolve().parents[1]

NOW_PRELAUNCH = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
NOW_PAID_ERA = datetime(2027, 2, 15, 12, 0, tzinfo=timezone.utc)


def _activated_policy(**overrides):
    raw = dict(cp.DEFAULT_POLICY)
    raw["activation"] = True
    raw["prelaunch_free_until"] = "2027-01-01"
    allowances = dict(raw["allowances"])
    allowances.update(overrides)
    raw["allowances"] = allowances
    return cp.parse_policy(raw)


def test_repo_policy_document_is_inert_and_valid():
    raw = json.loads((ROOT / "commercial-policy.v1.json").read_text(encoding="utf-8"))
    policy = cp.parse_policy(raw)
    assert policy.activation is False
    assert policy.prelaunch_free_until.isoformat() == "2027-01-01"
    assert policy.seat_monthly_price == pytest.approx(12.95)
    assert policy.currency == "USD"
    assert policy.free_monthly_workflows == 5
    assert policy.paid_monthly_workflows == 100
    assert policy.repair_reruns_per_workflow == 2
    assert policy.repair_rerun_window_days == 7


def test_default_policy_is_free_before_2027_even_when_activated():
    policy = _activated_policy()
    decision = cp.decide(
        policy, now=NOW_PRELAUNCH, used=999, entitlement_valid=False
    )
    assert decision.outcome == cp.PRELAUNCH_FREE
    assert decision.counts_against_allowance is False


def test_inactive_policy_is_free_regardless_of_date():
    policy = cp.default_policy()
    decision = cp.decide(policy, now=NOW_PAID_ERA, used=999, entitlement_valid=False)
    assert decision.outcome == cp.PRELAUNCH_FREE


def test_free_allowance_then_hard_stop_without_overage():
    policy = _activated_policy()
    for used in range(5):
        decision = cp.decide(
            policy, now=NOW_PAID_ERA, used=used, entitlement_valid=False
        )
        assert decision.outcome == cp.ALLOW
        assert decision.remaining == 5 - used
    decision = cp.decide(policy, now=NOW_PAID_ERA, used=5, entitlement_valid=False)
    assert decision.outcome == cp.UPGRADE_REQUIRED
    assert decision.counts_against_allowance is False
    assert "no overage" in decision.reason


def test_paid_entitlement_raises_limit_to_100():
    policy = _activated_policy()
    decision = cp.decide(policy, now=NOW_PAID_ERA, used=5, entitlement_valid=True)
    assert decision.outcome == cp.ALLOW
    assert decision.limit == 100
    decision = cp.decide(policy, now=NOW_PAID_ERA, used=100, entitlement_valid=True)
    assert decision.outcome == cp.UPGRADE_REQUIRED


def test_invalid_presented_entitlement_rejects_without_consuming():
    policy = _activated_policy()
    decision = cp.decide(
        policy,
        now=NOW_PAID_ERA,
        used=0,
        entitlement_valid=False,
        entitlement_invalid_reason="E_INVALID_ENVELOPE: bad signature",
    )
    assert decision.outcome == cp.ENTITLEMENT_INVALID
    assert decision.counts_against_allowance is False


def test_eligible_rerun_is_included_and_free():
    policy = _activated_policy()
    decision = cp.decide(
        policy,
        now=NOW_PAID_ERA,
        used=5,
        entitlement_valid=False,
        rerun=cp.RerunView(requested=True, eligible=True),
    )
    assert decision.outcome == cp.ALLOW_INCLUDED_RERUN
    assert decision.counts_against_allowance is False


def test_ineligible_rerun_falls_through_to_new_workflow():
    policy = _activated_policy()
    decision = cp.decide(
        policy,
        now=NOW_PAID_ERA,
        used=1,
        entitlement_valid=False,
        rerun=cp.RerunView(requested=True, eligible=False, reason="repair window expired"),
    )
    assert decision.outcome == cp.ALLOW
    assert "repair window expired" in decision.reason
    assert decision.counts_against_allowance is True


def test_period_is_utc_calendar_month():
    assert cp.period_for(datetime(2026, 11, 30, 23, 59, tzinfo=timezone.utc)) == "2026-11"
    assert cp.period_for(datetime(2026, 12, 1, 0, 0, tzinfo=timezone.utc)) == "2026-12"


def test_policy_rejects_missing_fields_fail_closed():
    with pytest.raises(cp.CommercialPolicyError):
        cp.parse_policy({"schema": cp.SCHEMA})
    with pytest.raises(cp.CommercialPolicyError):
        cp.parse_policy({"schema": "wrong", "revision": "x"})
    raw = dict(cp.DEFAULT_POLICY)
    del raw["activation"]
    with pytest.raises(cp.CommercialPolicyError):
        cp.parse_policy(raw)

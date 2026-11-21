"""Tests for the atomic local commercial usage ledger."""

from datetime import datetime, timedelta, timezone
import threading

import pytest

from factoryline.commercial_usage import (
    COMPLETED,
    REJECTED,
    TOOL_ERROR,
    CommercialUsageError,
    UsageLedger,
)

T0 = datetime(2027, 2, 10, 12, 0, tzinfo=timezone.utc)


def _reserve(ledger, subject="rick", n=1, now=T0, limit=None, key_suffix=""):
    return ledger.try_reserve(
        subject=subject,
        period="2027-02",
        workflow_id=f"wf-{n}",
        idempotency_key=f"key-{n}{key_suffix}",
        binding={"scope_digest": "s", "plan_digest": "p"},
        limit=limit,
        now=now,
    )


def test_reserve_finalize_counts(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _reserve(ledger, limit=5)
    assert reservation is not None
    state = ledger.load(T0)
    assert state.used("rick", "2027-02") == 1  # open holds the slot
    ledger.settle(reservation.reservation_id, outcome=COMPLETED, now=T0)
    assert ledger.load(T0).used("rick", "2027-02") == 1


def test_tool_error_and_rejected_release_never_count(tmp_path):
    ledger = UsageLedger(tmp_path)
    for outcome in (TOOL_ERROR, REJECTED):
        reservation = _reserve(ledger, n=1, limit=5, key_suffix=outcome)
        ledger.settle(reservation.reservation_id, outcome=outcome, now=T0)
    assert ledger.load(T0).used("rick", "2027-02") == 0


def test_idempotent_retry_returns_same_reservation(tmp_path):
    ledger = UsageLedger(tmp_path)
    first = _reserve(ledger, limit=1)
    replay = ledger.try_reserve(
        subject="rick",
        period="2027-02",
        workflow_id="wf-1",
        idempotency_key="key-1",
        binding={},
        limit=1,
        now=T0,
    )
    assert replay.reservation_id == first.reservation_id
    assert replay.replayed is True
    assert ledger.load(T0).used("rick", "2027-02") == 1


def test_concurrent_reservations_never_exceed_limit(tmp_path):
    ledger = UsageLedger(tmp_path)
    results = []
    lock = threading.Lock()

    def worker(i):
        reservation = _reserve(ledger, n=i, now=T0, limit=5)
        with lock:
            results.append(reservation)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for r in results if r is not None) == 5
    assert ledger.load(T0).used("rick", "2027-02") == 5


def test_limit_recheck_refuses_over_allowance(tmp_path):
    ledger = UsageLedger(tmp_path)
    assert _reserve(ledger, n=1, limit=1) is not None
    assert _reserve(ledger, n=2, limit=1) is None


def test_crashed_open_reservation_expires_and_frees_slot(tmp_path):
    ledger = UsageLedger(tmp_path, ttl_seconds=60)
    reservation = _reserve(ledger, limit=1)
    later = T0 + timedelta(hours=2)
    state = ledger.load(later)
    assert state.used("rick", "2027-02") == 0
    assert state.reservations[reservation.reservation_id].status == "expired"
    assert _reserve(ledger, n=2, now=later, limit=1) is not None


def test_period_rollover_starts_fresh_count(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _reserve(ledger, limit=1)
    ledger.settle(reservation.reservation_id, outcome=COMPLETED, now=T0)
    march = datetime(2027, 3, 1, 0, 0, tzinfo=timezone.utc)
    state = ledger.load(march)
    assert state.used("rick", "2027-02") == 1
    assert state.used("rick", "2027-03") == 0


def test_clock_rollback_never_extends_allowance(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _reserve(ledger, limit=5)
    ledger.settle(reservation.reservation_id, outcome=COMPLETED, now=T0)
    earlier = T0 - timedelta(days=40)  # wall clock moved back across a period
    state = ledger.load(earlier)
    assert state.clock_rollback_seen is True
    # period math uses max(now, newest recorded), so February usage still shows
    assert state.effective_now(earlier) == T0


def test_export_is_read_only_and_reset_is_visible(tmp_path):
    ledger = UsageLedger(tmp_path)
    _reserve(ledger, limit=5)
    dump = ledger.export(T0)
    assert len(dump["reservations"]) == 1
    assert ledger.load(T0).used("rick", "2027-02") == 1
    removed = ledger.reset()
    assert removed >= 1
    assert ledger.load(T0).used("rick", "2027-02") == 0
    assert ledger.reset() == 0


def test_settle_rejects_unknown_outcome_and_reservation(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _reserve(ledger)
    with pytest.raises(CommercialUsageError):
        ledger.settle(reservation.reservation_id, outcome="defect_found", now=T0)
    with pytest.raises(CommercialUsageError):
        ledger.settle("nope", outcome=COMPLETED, now=T0)


def test_settle_is_idempotent(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _reserve(ledger)
    ledger.settle(reservation.reservation_id, outcome=COMPLETED, now=T0)
    again = ledger.settle(reservation.reservation_id, outcome=TOOL_ERROR, now=T0)
    assert again.status == "finalized"
    assert ledger.load(T0).used("rick", "2027-02") == 1

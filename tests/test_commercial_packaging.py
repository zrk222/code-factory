from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
import pytest
from factoryline import enterprise_enforcement as cp
from datetime import timedelta
import multiprocessing
import os
import threading
from factoryline.enterprise_ops import (
    COMPLETED,
    REJECTED,
    TOOL_ERROR,
    CommercialUsageError,
    UsageLedger,
)
from factoryline.enterprise_receipts import (
    CommercialEntitlementError,
    covering_entitlement,
    import_entitlement,
    load_entitlements,
    sign_entitlement,
    verify_entitlement_envelope,
    version_in_range,
)
from factoryline.enterprise_receipts import generate_key_material
from factoryline.enterprise_enforcement import (
    CommercialAdmissionError,
    CommercialGate,
)

UTF8 = "utf_8"
ROOT = Path(__file__).resolve().parent.parent


def _packaging() -> dict:
    return json.loads(
        (ROOT / "docs" / "COMMERCIAL_PACKAGING.json").read_text(encoding=UTF8)
    )


def test_commercial_packaging_marks_only_free_core_as_available():
    packaging = _packaging()

    assert packaging["schema"] == "factory.commercial-packaging.v2"
    assert packaging["governance"] == {
        "classification": "human_controlled",
        "commercial_activation_authority": [
            "product_owner",
            "chosen_billing_or_contracting_system",
        ],
        "automation_may_activate": False,
    }
    assert packaging["claim_boundary"] == {
        "state_marker": "COMMERCIAL_CAPABILITY_BOUNDARY_PRESERVED",
        "managed_service_claim": False,
        "compliance_certification_claim": False,
        "sso_or_scim_product_claim": False,
        "external_kms_claim": False,
        "sla_claim": False,
    }
    tiers = packaging["tiers"]
    assert tiers["free_core"]["availability"] == "available"
    assert tiers["free_core"]["state_marker"] == "COMMERCIAL_FREE_CORE_AVAILABLE"
    assert tiers["free_core"]["commercial_account_required"] is False
    assert tiers["team_proof_hub"]["availability"] == "design_partner_only"
    assert tiers["team_proof_hub"]["state_marker"] == "COMMERCIAL_TEAM_NOT_SELLABLE"
    assert tiers["team_proof_hub"]["purchasable"] is False
    assert tiers["team_proof_hub"]["pricing"] == {
        "state_marker": "COMMERCIAL_TEAM_PRICE_PROPOSED",
        "status": "proposed",
        "currency": "USD",
        "annual_commit_per_active_contributor_month": 20,
        "monthly_per_active_contributor": 24,
        "minimum_active_contributors": 3,
    }
    assert tiers["enterprise_assurance"]["availability"] == "discovery_only"
    assert (
        tiers["enterprise_assurance"]["state_marker"]
        == "COMMERCIAL_ENTERPRISE_DISCOVERY_ONLY"
    )
    assert tiers["enterprise_assurance"]["purchasable"] is False
    assert tiers["managed_proof_runner"]["availability"] == "not_offered"
    assert (
        tiers["managed_proof_runner"]["state_marker"]
        == "COMMERCIAL_MANAGED_RUNNER_NOT_OFFERED"
    )
    assert tiers["managed_proof_runner"]["purchasable"] is False
    assert packaging["promotion_trigger"]["minimum_selected_design_partners"] == 3
    assert packaging["design_partner_intake"] == {
        "state_marker": "COMMERCIAL_INTAKE_DISCOVERY_ONLY",
        "path": ".github/ISSUE_TEMPLATE/design-partner.yml",
        "acceptance_authority": False,
        "source_collection_authority": False,
        "contact_authority": False,
    }
    assert (
        packaging["separate_marketplace_plan"]
        == "docs/JETBRAINS_MONETIZATION_2027.json"
    )
    assert packaging["marketplace_reference"] == {
        "state_marker": "COMMERCIAL_MARKETPLACE_SEPARATE",
        "path": "docs/JETBRAINS_MONETIZATION_2027.json",
        "activation_authority": False,
        "revision_authority": False,
    }
    assert packaging["github_pricing_reference"] == {
        "state_marker": "COMMERCIAL_GITHUB_PRICE_SCHEDULED_NOT_ACTIVE",
        "path": "docs/GITHUB_MONETIZATION_2026.json",
        "activation_authority": False,
        "revision_authority": False,
    }
    assert packaging["open_vsx_pricing_reference"] == {
        "state_marker": "COMMERCIAL_OPEN_VSX_SERVICES_SCHEDULED_NOT_ACTIVE",
        "path": "docs/OPEN_VSX_MONETIZATION_2026.json",
        "activation_authority": False,
        "revision_authority": False,
    }
    assert packaging["current_verdict"] == "COMMERCIALIZATION_STAGED_NOT_SELLABLE"


def test_design_partner_intake_has_no_sales_or_source_collection_authority():
    guide = (ROOT / "docs" / "COMMERCIAL_PACKAGING.md").read_text(encoding=UTF8)
    intake = (ROOT / ".github" / "ISSUE_TEMPLATE" / "design-partner.yml").read_text(
        encoding=UTF8
    )

    assert "not purchasable today" in guide
    assert "planning hypothesis" in guide
    assert "purchase offer" in guide
    assert "human-controlled" in guide
    assert "There is no" in guide
    assert "customer support commitment" in guide
    assert (
        "does not accept a partner, create a contract, start a trial, or grant access"
        in intake
    )
    assert "Do not include source code, credentials, tokens, customer data" in intake
    assert "design-partner" in intake


def test_github_per_seat_plan_is_scheduled_but_not_active_or_enforced():
    plan = json.loads(
        (ROOT / "docs" / "GITHUB_MONETIZATION_2026.json").read_text(encoding=UTF8)
    )
    guide = (ROOT / "docs" / "GITHUB_MONETIZATION_2026.md").read_text(encoding=UTF8)
    readme = (ROOT / "README.md").read_text(encoding=UTF8)

    assert plan["schema"] == "factory.github-monetization-plan.v1"
    assert plan["offer"] == {
        "free_through": "2026-12-31T23:59:59-05:00",
        "paid_from": "2027-01-01",
        "price_per_named_seat_usd_month": 5.95,
        "price_per_named_seat_usd_year": 60.0,
        "price_status": "owner_approved_future_price_not_active",
        "billing_status": "not_configured",
        "checkout_status": "not_live",
        "taxes_and_currency_conversion": "must_be_shown_by_the_chosen_billing_or_contracting_system_before_purchase",
    }
    assert plan["scope"]["source_license"] == "MIT OR Apache-2.0 remains unchanged"
    assert plan["scope"]["repository_access"] == "not_restricted_by_this_plan"
    assert plan["scope"]["automatic_license_enforcement"] is False
    assert (
        plan["value_contract"]["state_marker"] == "GITHUB_ASSURANCE_SEAT_VALUE_DEFINED"
    )
    assert plan["value_contract"]["included_when_activated"] == [
        "commit-bound GitHub Proof Review Check and walkthrough",
        "human-approved Plan-to-Proof scope envelope and visible Proof Debt",
        "supplied-policy drift dossier bound to the exact commit and named expiring exceptions",
        "organization-authored policy bundles with named, expiring exception receipts",
        "exportable hash-bound evidence, attestations, and review packets",
        "customer-managed local evidence and no Code Factory source upload",
    ]
    assert "automatic merge" in plan["value_contract"]["does_not_include"][0]
    assert len(plan["activation_gates"]) == 6
    assert plan["current_verdict"] == "GITHUB_PER_SEAT_PRICE_SCHEDULED_NOT_ACTIVE"
    assert "$5.95 USD per named seat per month" in guide
    assert "The $5.95 Assurance Seat value contract" in guide
    assert "feature-by-feature availability matrix" in guide
    assert "not active yet" in guide
    assert "GitHub repository metadata cannot collect payment" in guide
    assert "Founding Proof Pro" not in readme
    assert "$5.95" not in readme
    assert "standard Proof Pro" not in readme
    assert "docs/COMMERCIAL_PACKAGING.md" in readme


def test_open_vsx_services_are_scheduled_without_paywalling_the_extension():
    plan = json.loads(
        (ROOT / "docs" / "OPEN_VSX_MONETIZATION_2026.json").read_text(encoding=UTF8)
    )
    guide = (ROOT / "docs" / "OPEN_VSX_MONETIZATION_2026.md").read_text(encoding=UTF8)
    adapter = (ROOT / "editors" / "vscode" / "README.md").read_text(encoding=UTF8)

    assert plan["schema"] == "factory.open-vsx-monetization-plan.v1"
    assert plan["registry_distribution"] == {
        "extension_price": 0,
        "extension_remains_free": True,
        "local_core_remains_free": True,
        "registry_account_required_for_local_core": False,
    }
    assert plan["schedule"] == {
        "all_shipped_capabilities_free_through": "2026-12-14T23:59:59-05:00",
        "optional_service_offers_may_start": "2026-12-15T00:00:00-05:00",
        "timezone": "America/Toronto",
    }
    assert plan["offers"]["proof_pro"]["price_usd_month"] == 9.0
    assert plan["offers"]["proof_pro"]["founding_price_usd_month"] == 5.95
    assert plan["offers"]["appforge_builder"]["price_usd_month"] == 24.0
    assert (
        plan["offers"]["team_assurance"]["monthly_price_usd_active_contributor"] == 24.0
    )
    assert len(plan["activation_gates"]) == 6
    assert all(
        gate["status"] == "pending_human" and gate["evidence"] is None
        for gate in plan["activation_gates"]
    )
    assert plan["authority"] == {
        "classification": "human_controlled",
        "automation_may_collect_payment": False,
        "automation_may_issue_entitlements": False,
        "automation_may_change_registry_access": False,
    }
    assert plan["current_verdict"] == "OPEN_VSX_OPTIONAL_SERVICES_SCHEDULED_NOT_ACTIVE"
    assert "extension and local proof core remain free" in guide
    assert "December 15" in adapter


"""Deterministic tests for the approved commercial policy decisions."""


ROOT = Path(__file__).resolve().parents[1]

COMMERCIAL_POLICY_NOW_PRELAUNCH = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
COMMERCIAL_POLICY_NOW_PAID_ERA = datetime(2027, 2, 15, 12, 0, tzinfo=timezone.utc)


def _commercial_policy_activated_policy(**overrides):
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
    policy = _commercial_policy_activated_policy()
    decision = cp.decide(
        policy, now=COMMERCIAL_POLICY_NOW_PRELAUNCH, used=999, entitlement_valid=False
    )
    assert decision.outcome == cp.PRELAUNCH_FREE
    assert decision.counts_against_allowance is False


def test_inactive_policy_is_free_regardless_of_date():
    policy = cp.default_policy()
    decision = cp.decide(
        policy, now=COMMERCIAL_POLICY_NOW_PAID_ERA, used=999, entitlement_valid=False
    )
    assert decision.outcome == cp.PRELAUNCH_FREE


def test_free_allowance_then_hard_stop_without_overage():
    policy = _commercial_policy_activated_policy()
    for used in range(5):
        decision = cp.decide(
            policy,
            now=COMMERCIAL_POLICY_NOW_PAID_ERA,
            used=used,
            entitlement_valid=False,
        )
        assert decision.outcome == cp.ALLOW
        assert decision.remaining == 5 - used
    decision = cp.decide(
        policy, now=COMMERCIAL_POLICY_NOW_PAID_ERA, used=5, entitlement_valid=False
    )
    assert decision.outcome == cp.UPGRADE_REQUIRED
    assert decision.counts_against_allowance is False
    assert "no overage" in decision.reason


def test_paid_entitlement_raises_limit_to_100():
    policy = _commercial_policy_activated_policy()
    decision = cp.decide(
        policy, now=COMMERCIAL_POLICY_NOW_PAID_ERA, used=5, entitlement_valid=True
    )
    assert decision.outcome == cp.ALLOW
    assert decision.limit == 100
    decision = cp.decide(
        policy, now=COMMERCIAL_POLICY_NOW_PAID_ERA, used=100, entitlement_valid=True
    )
    assert decision.outcome == cp.UPGRADE_REQUIRED


def test_invalid_presented_entitlement_rejects_without_consuming():
    policy = _commercial_policy_activated_policy()
    decision = cp.decide(
        policy,
        now=COMMERCIAL_POLICY_NOW_PAID_ERA,
        used=0,
        entitlement_valid=False,
        entitlement_invalid_reason="E_INVALID_ENVELOPE: bad signature",
    )
    assert decision.outcome == cp.ENTITLEMENT_INVALID
    assert decision.counts_against_allowance is False


def test_eligible_rerun_is_included_and_free():
    policy = _commercial_policy_activated_policy()
    decision = cp.decide(
        policy,
        now=COMMERCIAL_POLICY_NOW_PAID_ERA,
        used=5,
        entitlement_valid=False,
        rerun=cp.RerunView(requested=True, eligible=True),
    )
    assert decision.outcome == cp.ALLOW_INCLUDED_RERUN
    assert decision.counts_against_allowance is False


def test_ineligible_rerun_falls_through_to_new_workflow():
    policy = _commercial_policy_activated_policy()
    decision = cp.decide(
        policy,
        now=COMMERCIAL_POLICY_NOW_PAID_ERA,
        used=1,
        entitlement_valid=False,
        rerun=cp.RerunView(
            requested=True, eligible=False, reason="repair window expired"
        ),
    )
    assert decision.outcome == cp.ALLOW
    assert "repair window expired" in decision.reason
    assert decision.counts_against_allowance is True


def test_period_is_utc_calendar_month():
    assert (
        cp.period_for(datetime(2026, 11, 30, 23, 59, tzinfo=timezone.utc)) == "2026-11"
    )
    assert cp.period_for(datetime(2026, 12, 1, 0, 0, tzinfo=timezone.utc)) == "2026-12"


def test_policy_rejects_missing_fields_fail_closed():
    with pytest.raises(cp.CommercialPolicyError):
        cp.parse_policy({"schema": cp.COMMERCIAL_POLICY_SCHEMA})
    with pytest.raises(cp.CommercialPolicyError):
        cp.parse_policy({"schema": "wrong", "revision": "x"})
    raw = dict(cp.DEFAULT_POLICY)
    del raw["activation"]
    with pytest.raises(cp.CommercialPolicyError):
        cp.parse_policy(raw)


"""Tests for the atomic local commercial usage ledger."""


COMMERCIAL_USAGE_T0 = datetime(2027, 2, 10, 12, 0, tzinfo=timezone.utc)


def _commercial_usage_reserve(
    ledger, subject="rick", n=1, now=COMMERCIAL_USAGE_T0, limit=None, key_suffix=""
):
    return ledger.try_reserve(
        subject=subject,
        period="2027-02",
        workflow_id=f"wf-{n}",
        idempotency_key=f"key-{n}{key_suffix}",
        binding={"scope_digest": "s", "plan_digest": "p"},
        limit=limit,
        now=now,
    )


def _commercial_usage_process_reserve_last_slot(home, start, results, ordinal):
    try:
        ledger = UsageLedger(home)
        start.wait(timeout=15)
        reservation = ledger.try_reserve(
            subject="rick",
            period="2027-02",
            workflow_id=f"process-wf-{ordinal}",
            idempotency_key=f"process-key-{ordinal}",
            binding={"scope_digest": "s", "plan_digest": "p"},
            limit=1,
            now=COMMERCIAL_USAGE_T0,
        )
        results.put(("ok", reservation is not None))
    except BaseException as exc:
        results.put(("error", f"{type(exc).__name__}: {exc}"))
        raise


def test_reserve_finalize_counts(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _commercial_usage_reserve(ledger, limit=5)
    assert reservation is not None
    state = ledger.load(COMMERCIAL_USAGE_T0)
    assert state.used("rick", "2027-02") == 1  # open holds the slot
    ledger.settle(
        reservation.reservation_id, outcome=COMPLETED, now=COMMERCIAL_USAGE_T0
    )
    assert ledger.load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 1


def test_tool_error_and_rejected_release_never_count(tmp_path):
    ledger = UsageLedger(tmp_path)
    for outcome in (TOOL_ERROR, REJECTED):
        reservation = _commercial_usage_reserve(
            ledger, n=1, limit=5, key_suffix=outcome
        )
        ledger.settle(
            reservation.reservation_id, outcome=outcome, now=COMMERCIAL_USAGE_T0
        )
    assert ledger.load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 0


def test_idempotent_retry_returns_same_reservation(tmp_path):
    ledger = UsageLedger(tmp_path)
    first = _commercial_usage_reserve(ledger, limit=1)
    replay = ledger.try_reserve(
        subject="rick",
        period="2027-02",
        workflow_id="wf-1",
        idempotency_key="key-1",
        binding={},
        limit=1,
        now=COMMERCIAL_USAGE_T0,
    )
    assert replay.reservation_id == first.reservation_id
    assert replay.replayed is True
    assert ledger.load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 1


def test_concurrent_reservations_never_exceed_limit(tmp_path):
    ledgers = [UsageLedger(tmp_path), UsageLedger(tmp_path)]
    results = []
    errors = []
    lock = threading.Lock()
    start = threading.Barrier(25, timeout=5)

    def worker(i):
        try:
            start.wait()
            reservation = _commercial_usage_reserve(
                ledgers[i % 2], n=i, now=COMMERCIAL_USAGE_T0, limit=5
            )
            with lock:
                results.append(reservation)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert sum(1 for r in results if r is not None) == 5
    assert ledgers[0].load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 5


def test_multiprocess_reservations_never_exceed_last_slot(tmp_path):
    context = multiprocessing.get_context("spawn")
    process_count = 8
    start = context.Barrier(process_count, timeout=15)
    results = context.Queue()
    processes = [
        context.Process(
            target=_commercial_usage_process_reserve_last_slot,
            args=(str(tmp_path), start, results, index),
        )
        for index in range(process_count)
    ]
    try:
        for process in processes:
            process.start()
        outcomes = [results.get(timeout=15) for _ in processes]
        for process in processes:
            process.join(timeout=5)
        assert all(not process.is_alive() for process in processes)
        assert all(process.exitcode == 0 for process in processes)
        assert all(kind == "ok" for kind, _ in outcomes), outcomes
        reservations = [value for _, value in outcomes]
        assert reservations.count(True) == 1
        assert reservations.count(False) == process_count - 1
        assert (
            UsageLedger(tmp_path).load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 1
        )
        if os.name == "nt":
            assert (tmp_path / "usage-ledger.lock").stat().st_size == 1
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=2)
        results.close()
        results.join_thread()


def test_lock_is_released_after_exception_inside_critical_section(tmp_path):
    first = UsageLedger(tmp_path)
    second = UsageLedger(tmp_path)
    with pytest.raises(RuntimeError, match="simulated failure"):
        with first._locked():
            raise RuntimeError("simulated failure")

    assert _commercial_usage_reserve(second, limit=1) is not None
    assert _commercial_usage_reserve(first, n=2, limit=1) is None


def test_lock_fails_closed_when_platform_lock_is_unavailable(tmp_path, monkeypatch):
    import factoryline.enterprise_ops as commercial_usage

    monkeypatch.setattr(commercial_usage, "_OS_NAME", "unsupported")
    monkeypatch.setattr(commercial_usage, "fcntl", None)
    ledger = UsageLedger(tmp_path)
    with pytest.raises(CommercialUsageError, match="E_LEDGER_LOCK_UNAVAILABLE"):
        with ledger._locked():
            pytest.fail("unsupported platforms must not enter an unlocked section")
    assert not ledger.path.exists()


def test_lock_acquisition_failure_does_not_reserve(tmp_path, monkeypatch):
    import factoryline.enterprise_ops as commercial_usage

    def fail_lock(*_args):
        raise OSError("simulated lock failure")

    if commercial_usage._OS_NAME == "nt":
        import msvcrt

        monkeypatch.setattr(msvcrt, "locking", fail_lock)
    elif commercial_usage.fcntl is not None:
        monkeypatch.setattr(commercial_usage.fcntl, "flock", fail_lock)
    else:
        pytest.skip("no native locking backend is available to fault-inject")

    ledger = UsageLedger(tmp_path)
    with pytest.raises(CommercialUsageError, match="E_LEDGER_LOCK_UNAVAILABLE"):
        _commercial_usage_reserve(ledger, limit=1)
    assert not ledger.path.exists()


def test_limit_recheck_refuses_over_allowance(tmp_path):
    ledger = UsageLedger(tmp_path)
    assert _commercial_usage_reserve(ledger, n=1, limit=1) is not None
    assert _commercial_usage_reserve(ledger, n=2, limit=1) is None


def test_crashed_open_reservation_expires_and_frees_slot(tmp_path):
    ledger = UsageLedger(tmp_path, ttl_seconds=60)
    reservation = _commercial_usage_reserve(ledger, limit=1)
    later = COMMERCIAL_USAGE_T0 + timedelta(hours=2)
    state = ledger.load(later)
    assert state.used("rick", "2027-02") == 0
    assert state.reservations[reservation.reservation_id].status == "expired"
    assert _commercial_usage_reserve(ledger, n=2, now=later, limit=1) is not None


def test_period_rollover_starts_fresh_count(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _commercial_usage_reserve(ledger, limit=1)
    ledger.settle(
        reservation.reservation_id, outcome=COMPLETED, now=COMMERCIAL_USAGE_T0
    )
    march = datetime(2027, 3, 1, 0, 0, tzinfo=timezone.utc)
    state = ledger.load(march)
    assert state.used("rick", "2027-02") == 1
    assert state.used("rick", "2027-03") == 0


def test_clock_rollback_never_extends_allowance(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _commercial_usage_reserve(ledger, limit=5)
    ledger.settle(
        reservation.reservation_id, outcome=COMPLETED, now=COMMERCIAL_USAGE_T0
    )
    earlier = COMMERCIAL_USAGE_T0 - timedelta(
        days=40
    )  # wall clock moved back across a period
    state = ledger.load(earlier)
    assert state.clock_rollback_seen is True
    # period math uses max(now, newest recorded), so February usage still shows
    assert state.effective_now(earlier) == COMMERCIAL_USAGE_T0


def test_export_is_read_only_and_reset_is_visible(tmp_path):
    ledger = UsageLedger(tmp_path)
    _commercial_usage_reserve(ledger, limit=5)
    dump = ledger.export(COMMERCIAL_USAGE_T0)
    assert len(dump["reservations"]) == 1
    assert ledger.load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 1
    removed = ledger.reset()
    assert removed >= 1
    assert ledger.load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 0
    assert ledger.reset() == 0


def test_settle_rejects_unknown_outcome_and_reservation(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _commercial_usage_reserve(ledger)
    with pytest.raises(CommercialUsageError):
        ledger.settle(
            reservation.reservation_id, outcome="defect_found", now=COMMERCIAL_USAGE_T0
        )
    with pytest.raises(CommercialUsageError):
        ledger.settle("nope", outcome=COMPLETED, now=COMMERCIAL_USAGE_T0)


def test_settle_is_idempotent(tmp_path):
    ledger = UsageLedger(tmp_path)
    reservation = _commercial_usage_reserve(ledger)
    ledger.settle(
        reservation.reservation_id, outcome=COMPLETED, now=COMMERCIAL_USAGE_T0
    )
    again = ledger.settle(
        reservation.reservation_id, outcome=TOOL_ERROR, now=COMMERCIAL_USAGE_T0
    )
    assert again.status == "finalized"
    assert ledger.load(COMMERCIAL_USAGE_T0).used("rick", "2027-02") == 1


"""Tests for offline signed commercial entitlements."""


COMMERCIAL_ENTITLEMENT_NOW = datetime(2027, 2, 10, 12, 0, tzinfo=timezone.utc)


def _commercial_entitlement_payload(**overrides):
    payload = {
        "schema": "factory.commercial.entitlement.v1",
        "entitlement_id": "ent-test-1",
        "subject": "rick",
        "product": "code-factory",
        "covered_versions": {"min": "0.49.0", "max": "0.50.9"},
        "seats": 1,
        "not_before": "2027-01-01T00:00:00+00:00",
        "not_after": "2027-12-31T23:59:59+00:00",
        "issued_at": "2026-11-21T00:00:00+00:00",
    }
    payload.update(overrides)
    return payload


@pytest.fixture()
def _commercial_entitlement_keys(tmp_path):
    material = generate_key_material(
        out_dir=tmp_path / "_commercial_entitlement_keys",
        keyid="commercial-test",
        identity="commercial-issuer",
        issuer="factoryline",
    )
    return material


def _commercial_entitlement_sign(_commercial_entitlement_keys, payload):
    return sign_entitlement(
        payload,
        private_key_path=_commercial_entitlement_keys["private_key"],
        keyid=_commercial_entitlement_keys["keyid"],
        identity=_commercial_entitlement_keys["identity"],
        issuer=_commercial_entitlement_keys["issuer"],
    )


def _commercial_entitlement_trust_root(_commercial_entitlement_keys):
    return json.loads(
        open(_commercial_entitlement_keys["trust_root"], encoding="utf-8").read()
    )


def test_sign_and_verify_roundtrip(_commercial_entitlement_keys):
    envelope = _commercial_entitlement_sign(
        _commercial_entitlement_keys, _commercial_entitlement_payload()
    )
    entitlement = verify_entitlement_envelope(
        envelope,
        trust_root=_commercial_entitlement_trust_root(_commercial_entitlement_keys),
    )
    assert entitlement.subject == "rick"
    assert entitlement.covers(
        subject="rick",
        product="code-factory",
        version="0.50.0",
        now=COMMERCIAL_ENTITLEMENT_NOW,
    )


def test_tampered_payload_fails_verification(_commercial_entitlement_keys, tmp_path):
    envelope = _commercial_entitlement_sign(
        _commercial_entitlement_keys, _commercial_entitlement_payload()
    )
    other = _commercial_entitlement_sign(
        _commercial_entitlement_keys, _commercial_entitlement_payload(subject="mallory")
    )
    envelope["payload"] = other["payload"]  # swapped, signature no longer matches
    with pytest.raises(CommercialEntitlementError):
        verify_entitlement_envelope(
            envelope,
            trust_root=_commercial_entitlement_trust_root(_commercial_entitlement_keys),
        )


def test_wrong_trust_root_fails(_commercial_entitlement_keys, tmp_path):
    other = generate_key_material(
        out_dir=tmp_path / "other", keyid="k2", identity="i2", issuer="x"
    )
    envelope = _commercial_entitlement_sign(
        _commercial_entitlement_keys, _commercial_entitlement_payload()
    )
    with pytest.raises(CommercialEntitlementError):
        verify_entitlement_envelope(
            envelope, trust_root=_commercial_entitlement_trust_root(other)
        )


def test_open_ended_future_versions_are_not_issuable(_commercial_entitlement_keys):
    payload = _commercial_entitlement_payload()
    payload["covered_versions"] = {"min": "0.49.0", "max": None}
    with pytest.raises(CommercialEntitlementError) as exc:
        _commercial_entitlement_sign(_commercial_entitlement_keys, payload)
    assert exc.value.code == "E_ENTITLEMENT_VERSIONS"


def test_coverage_window_and_subject_and_version(_commercial_entitlement_keys):
    entitlement = verify_entitlement_envelope(
        _commercial_entitlement_sign(
            _commercial_entitlement_keys, _commercial_entitlement_payload()
        ),
        trust_root=_commercial_entitlement_trust_root(_commercial_entitlement_keys),
    )
    assert not entitlement.covers(
        subject="rick",
        product="code-factory",
        version="0.50.0",
        now=datetime(2028, 1, 1, tzinfo=timezone.utc),
    )
    assert not entitlement.covers(
        subject="someone-else",
        product="code-factory",
        version="0.50.0",
        now=COMMERCIAL_ENTITLEMENT_NOW,
    )
    assert not entitlement.covers(
        subject="rick",
        product="code-factory",
        version="0.51.0",
        now=COMMERCIAL_ENTITLEMENT_NOW,
    )
    assert not entitlement.covers(
        subject="rick",
        product="specline",
        version="0.50.0",
        now=COMMERCIAL_ENTITLEMENT_NOW,
    )


def test_version_in_range():
    assert version_in_range("0.50.0", "0.49.0", "0.50.9")
    assert not version_in_range("0.51.0", "0.49.0", "0.50.9")
    assert not version_in_range("0.48.9", "0.49.0", "0.50.9")


def test_import_stores_and_reverifies(_commercial_entitlement_keys, tmp_path):
    envelope_path = tmp_path / "ent.json"
    envelope_path.write_text(
        json.dumps(
            _commercial_entitlement_sign(
                _commercial_entitlement_keys, _commercial_entitlement_payload()
            )
        ),
        encoding="utf-8",
    )
    home = tmp_path / "home"
    imported = import_entitlement(
        envelope_path,
        trust_root_path=_commercial_entitlement_keys["trust_root"],
        home=home,
    )
    assert imported.entitlement_id == "ent-test-1"
    loaded = load_entitlements(home)
    assert len(loaded) == 1
    covering = covering_entitlement(
        loaded,
        subject="rick",
        product="code-factory",
        version="0.50.0",
        now=COMMERCIAL_ENTITLEMENT_NOW,
    )
    assert covering is not None


def test_tampered_stored_copy_is_dropped(_commercial_entitlement_keys, tmp_path):
    envelope_path = tmp_path / "ent.json"
    envelope_path.write_text(
        json.dumps(
            _commercial_entitlement_sign(
                _commercial_entitlement_keys, _commercial_entitlement_payload()
            )
        ),
        encoding="utf-8",
    )
    home = tmp_path / "home"
    import_entitlement(
        envelope_path,
        trust_root_path=_commercial_entitlement_keys["trust_root"],
        home=home,
    )
    stored = next((home / "entitlements").glob("*.json"))
    tampered = json.loads(stored.read_text(encoding="utf-8"))
    tampered["payload_sha256"] = "0" * 64
    stored.write_text(json.dumps(tampered), encoding="utf-8")
    assert load_entitlements(home) == []


def test_conflicting_trust_root_is_refused(_commercial_entitlement_keys, tmp_path):
    envelope_path = tmp_path / "ent.json"
    envelope_path.write_text(
        json.dumps(
            _commercial_entitlement_sign(
                _commercial_entitlement_keys, _commercial_entitlement_payload()
            )
        ),
        encoding="utf-8",
    )
    home = tmp_path / "home"
    import_entitlement(
        envelope_path,
        trust_root_path=_commercial_entitlement_keys["trust_root"],
        home=home,
    )
    other = generate_key_material(
        out_dir=tmp_path / "other", keyid="k2", identity="i2", issuer="x"
    )
    other_envelope = sign_entitlement(
        _commercial_entitlement_payload(entitlement_id="ent-test-2"),
        private_key_path=other["private_key"],
        keyid=other["keyid"],
        identity=other["identity"],
        issuer=other["issuer"],
    )
    other_path = tmp_path / "ent2.json"
    other_path.write_text(json.dumps(other_envelope), encoding="utf-8")
    with pytest.raises(CommercialEntitlementError) as exc:
        import_entitlement(other_path, trust_root_path=other["trust_root"], home=home)
    assert exc.value.code == "E_TRUST_ROOT_CONFLICT"


def test_invalid_envelope_is_never_stored(_commercial_entitlement_keys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "factory.dsse.envelope.v1"}), encoding="utf-8")
    home = tmp_path / "home"
    with pytest.raises(CommercialEntitlementError):
        import_entitlement(
            bad, trust_root_path=_commercial_entitlement_keys["trust_root"], home=home
        )
    assert load_entitlements(home) == []


"""Tests for the commercial gate and its Proof Agent wiring.

The wired-route tests use fakes for the proof internals so the commercial
behavior is tested deterministically: refusal before dispatch, settlement on
completion and on internal error, and the invariant that quota state never
changes a proof result.
"""


COMMERCIAL_GATE_T0 = datetime(2027, 2, 10, 12, 0, tzinfo=timezone.utc)


def _commercial_gate_activated_policy(free=2):
    raw = dict(cp.DEFAULT_POLICY)
    raw["activation"] = True
    raw["allowances"] = dict(raw["allowances"], free_monthly_workflows=free)
    return cp.parse_policy(raw)


def _commercial_gate_gate(tmp_path, **kwargs):
    kwargs.setdefault("policy", _commercial_gate_activated_policy())
    kwargs.setdefault("home", tmp_path)
    kwargs.setdefault("mode", "enforce")
    return CommercialGate(**kwargs)


def _commercial_gate_admit(gate, n=1, subject="rick", **kwargs):
    kwargs.setdefault("workflow_id", f"wf-{n}")
    kwargs.setdefault("idempotency_key", f"key-{n}")
    kwargs.setdefault("binding", {"scope_digest": "s", "plan_digest": "p"})
    kwargs.setdefault("now", COMMERCIAL_GATE_T0)
    return gate.admit(subject=subject, **kwargs)


def test_off_mode_is_fully_inert(tmp_path):
    gate = CommercialGate(
        policy=_commercial_gate_activated_policy(), home=tmp_path, mode="off"
    )
    admission = _commercial_gate_admit(gate)
    assert admission.decision.outcome == cp.DISABLED
    assert not (tmp_path / "usage-ledger.jsonl").exists()


def test_shadow_mode_computes_without_persisting_or_refusing(tmp_path):
    gate = CommercialGate(
        policy=_commercial_gate_activated_policy(free=0), home=tmp_path, mode="shadow"
    )
    admission = _commercial_gate_admit(gate)
    assert admission.decision.outcome == cp.UPGRADE_REQUIRED
    assert admission.admitted is True  # shadow never refuses
    assert not (tmp_path / "usage-ledger.jsonl").exists()


def test_enforce_prelaunch_policy_is_free(tmp_path):
    gate = CommercialGate(policy=cp.default_policy(), home=tmp_path, mode="enforce")
    admission = _commercial_gate_admit(gate)
    assert admission.decision.outcome == cp.PRELAUNCH_FREE
    assert admission.reservation is None


def test_enforce_allowance_then_upgrade_required(tmp_path):
    gate = _commercial_gate_gate(tmp_path)
    assert _commercial_gate_admit(gate, n=1).decision.outcome == cp.ALLOW
    assert _commercial_gate_admit(gate, n=2).decision.outcome == cp.ALLOW
    with pytest.raises(CommercialAdmissionError) as exc:
        _commercial_gate_admit(gate, n=3)
    assert exc.value.code == "E_COMMERCIAL_UPGRADE_REQUIRED"
    assert "no overage" in str(exc.value)


def test_enforce_invalid_presented_entitlement_rejected_free(tmp_path):
    gate = _commercial_gate_gate(tmp_path)
    with pytest.raises(CommercialAdmissionError) as exc:
        gate.admit(
            subject="rick",
            workflow_id="wf-x",
            idempotency_key="key-x",
            presented_envelope={"schema": "factory.dsse.envelope.v1"},
            presented_trust_root={"schema": "factory.trust.root.v1", "keys": []},
            now=COMMERCIAL_GATE_T0,
        )
    assert exc.value.code == "E_COMMERCIAL_ENTITLEMENT_INVALID"
    # rejected starts never consume allowance
    assert gate.ledger.load(COMMERCIAL_GATE_T0).used("rick", "2027-02") == 0


def test_settle_completed_counts_tool_error_releases(tmp_path):
    gate = _commercial_gate_gate(
        tmp_path, policy=_commercial_gate_activated_policy(free=2)
    )
    first = _commercial_gate_admit(gate, n=1)
    gate.settle(first, outcome="completed", now=COMMERCIAL_GATE_T0)
    second = _commercial_gate_admit(gate, n=2)
    gate.settle(second, outcome="tool_error", now=COMMERCIAL_GATE_T0)
    state = gate.ledger.load(COMMERCIAL_GATE_T0)
    assert state.used("rick", "2027-02") == 1
    third = _commercial_gate_admit(gate, n=3)  # the released slot is available again
    assert third.decision.outcome == cp.ALLOW


def test_retry_same_key_does_not_double_charge(tmp_path):
    gate = _commercial_gate_gate(
        tmp_path, policy=_commercial_gate_activated_policy(free=1)
    )
    first = _commercial_gate_admit(gate, n=1)
    gate.settle(first, outcome="completed", now=COMMERCIAL_GATE_T0)
    replay = _commercial_gate_admit(gate, n=1)
    assert replay.reservation.reservation_id == first.reservation.reservation_id
    assert gate.ledger.load(COMMERCIAL_GATE_T0).used("rick", "2027-02") == 1


def test_included_rerun_within_window_same_change(tmp_path):
    gate = _commercial_gate_gate(
        tmp_path, policy=_commercial_gate_activated_policy(free=1)
    )
    first = _commercial_gate_admit(gate, n=1)
    gate.settle(first, outcome="completed", now=COMMERCIAL_GATE_T0)
    rerun = gate.admit(
        subject="rick",
        workflow_id="wf-1-repair",
        idempotency_key="key-1-repair",
        binding={"scope_digest": "s", "plan_digest": "p", "candidate_digest": "new"},
        rerun_of="wf-1",
        now=COMMERCIAL_GATE_T0,
    )
    assert rerun.decision.outcome == cp.ALLOW_INCLUDED_RERUN
    gate.settle(rerun, outcome="completed", now=COMMERCIAL_GATE_T0)
    assert gate.ledger.load(COMMERCIAL_GATE_T0).used("rick", "2027-02") == 1


def test_rerun_scope_expansion_is_a_new_workflow(tmp_path):
    gate = _commercial_gate_gate(
        tmp_path, policy=_commercial_gate_activated_policy(free=5)
    )
    first = _commercial_gate_admit(gate, n=1)
    gate.settle(first, outcome="completed", now=COMMERCIAL_GATE_T0)
    expanded = gate.admit(
        subject="rick",
        workflow_id="wf-1-wide",
        idempotency_key="key-1-wide",
        binding={"scope_digest": "BIGGER", "plan_digest": "p"},
        rerun_of="wf-1",
        now=COMMERCIAL_GATE_T0,
    )
    assert expanded.decision.outcome == cp.ALLOW
    assert expanded.decision.counts_against_allowance is True


def test_rerun_window_expires_after_seven_days(tmp_path):
    from datetime import timedelta

    gate = _commercial_gate_gate(
        tmp_path, policy=_commercial_gate_activated_policy(free=5)
    )
    first = _commercial_gate_admit(gate, n=1)
    gate.settle(first, outcome="completed", now=COMMERCIAL_GATE_T0)
    late = gate.admit(
        subject="rick",
        workflow_id="wf-1-late",
        idempotency_key="key-1-late",
        binding={"scope_digest": "s", "plan_digest": "p"},
        rerun_of="wf-1",
        now=COMMERCIAL_GATE_T0 + timedelta(days=8),
    )
    assert late.decision.outcome == cp.ALLOW
    assert late.decision.counts_against_allowance is True


def test_rerun_slots_are_capped_at_two(tmp_path):
    gate = _commercial_gate_gate(
        tmp_path, policy=_commercial_gate_activated_policy(free=5)
    )
    first = _commercial_gate_admit(gate, n=1)
    gate.settle(first, outcome="completed", now=COMMERCIAL_GATE_T0)
    for i in (1, 2):
        rerun = gate.admit(
            subject="rick",
            workflow_id=f"wf-1-r{i}",
            idempotency_key=f"key-1-r{i}",
            binding={"scope_digest": "s", "plan_digest": "p"},
            rerun_of="wf-1",
            now=COMMERCIAL_GATE_T0,
        )
        assert rerun.decision.outcome == cp.ALLOW_INCLUDED_RERUN
        gate.settle(rerun, outcome="completed", now=COMMERCIAL_GATE_T0)
    third = gate.admit(
        subject="rick",
        workflow_id="wf-1-r3",
        idempotency_key="key-1-r3",
        binding={"scope_digest": "s", "plan_digest": "p"},
        rerun_of="wf-1",
        now=COMMERCIAL_GATE_T0,
    )
    assert third.decision.outcome == cp.ALLOW
    assert third.decision.counts_against_allowance is True


# --- Proof Agent wiring ----------------------------------------------------


def _commercial_gate_wire_fakes(monkeypatch, fail_dispatch=False):
    from factoryline import runtime_audit
    from factoryline import product_missions

    binding = {"binding_sha256": "b" * 64, "budgets": {"max_wall_seconds": 99999}}
    verification = {
        "payload_sha256": "a" * 64,
        "plan": {"candidate_sha256": "c" * 64},
    }
    receipt = {
        "lanes": [{"state": "COMPLETE"}],
        "decision": "READY_FOR_HUMAN_REVIEW",
        "receipt_sha256": "r" * 64,
        "repair_queue": [],
    }
    calls = {"dispatch": 0}

    monkeypatch.setattr(
        product_missions, "_mission_repair_snapshot", lambda *a, **k: binding
    )
    monkeypatch.setattr(
        runtime_audit, "verify_runtime_audit_plan", lambda *a, **k: verification
    )
    monkeypatch.setattr(runtime_audit, "_proof_agent_scope", lambda *a, **k: None)
    monkeypatch.setattr(runtime_audit, "_proof_agent_receipt", lambda *a, **k: receipt)

    def fake_execute(*a, **k):
        calls["dispatch"] += 1
        if fail_dispatch:
            raise RuntimeError("tool crashed")
        return {"receipt_path": "x", "receipt": receipt}

    monkeypatch.setattr(runtime_audit, "execute_runtime_audit", fake_execute)
    return calls


def _commercial_gate_run_proof_agent():
    from pathlib import Path

    from factoryline import runtime_audit

    return runtime_audit.execute_proof_agent(
        Path("plan.json"),
        Path("trust.json"),
        "t" * 64,
        Path("."),
        "env",
        Path("out"),
        mission_binding_path=Path("binding.json"),
        mission_root=Path("."),
        owner="rick",
        confirmation="RUN Proof Agent",
    )


def test_wiring_off_by_default_no_files(monkeypatch, tmp_path):
    monkeypatch.setenv("FACTORY_COMMERCIAL_HOME", str(tmp_path))
    monkeypatch.delenv("FACTORY_COMMERCIAL_MODE", raising=False)
    monkeypatch.delenv("FACTORY_COMMERCIAL_POLICY", raising=False)
    _commercial_gate_wire_fakes(monkeypatch)
    result = _commercial_gate_run_proof_agent()
    assert result["state"] == "PASS"
    assert not (tmp_path / "usage-ledger.jsonl").exists()


def test_wiring_enforce_counts_completed_runs(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.json"
    raw = dict(cp.DEFAULT_POLICY)
    raw["activation"] = True
    policy_path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("FACTORY_COMMERCIAL_HOME", str(tmp_path))
    monkeypatch.setenv("FACTORY_COMMERCIAL_MODE", "enforce")
    monkeypatch.setenv("FACTORY_COMMERCIAL_POLICY", str(policy_path))
    _commercial_gate_wire_fakes(monkeypatch)
    result = _commercial_gate_run_proof_agent()
    assert result["state"] == "PASS"
    ledger = UsageLedger(tmp_path)
    assert (
        ledger.load(COMMERCIAL_GATE_T0).used("rick", "2026-11") == 0
    )  # prelaunch free
    # activate-era clock: force a reservation directly to prove settlement path
    gate = CommercialGate(home=tmp_path, mode="enforce")
    admission = gate.admit(
        subject="rick",
        workflow_id="wf-direct",
        idempotency_key="key-direct",
        now=COMMERCIAL_GATE_T0,
    )
    gate.settle(admission, outcome="completed", now=COMMERCIAL_GATE_T0)
    assert ledger.load(COMMERCIAL_GATE_T0).used("rick", "2027-02") == 1


def test_wiring_refusal_happens_before_dispatch(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.json"
    raw = dict(cp.DEFAULT_POLICY)
    raw["activation"] = True
    raw["prelaunch_free_until"] = "2026-01-01"
    raw["allowances"] = dict(raw["allowances"], free_monthly_workflows=0)
    policy_path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("FACTORY_COMMERCIAL_HOME", str(tmp_path))
    monkeypatch.setenv("FACTORY_COMMERCIAL_MODE", "enforce")
    monkeypatch.setenv("FACTORY_COMMERCIAL_POLICY", str(policy_path))
    calls = _commercial_gate_wire_fakes(monkeypatch)

    from factoryline.runtime_audit_common import RuntimeAuditError

    with pytest.raises(RuntimeAuditError) as exc:
        _commercial_gate_run_proof_agent()
    assert exc.value.code == "E_COMMERCIAL_UPGRADE_REQUIRED"
    assert calls["dispatch"] == 0


def test_wiring_tool_error_releases_reservation(monkeypatch, tmp_path):
    policy_path = tmp_path / "policy.json"
    raw = dict(cp.DEFAULT_POLICY)
    raw["activation"] = True
    raw["prelaunch_free_until"] = "2026-01-01"
    policy_path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setenv("FACTORY_COMMERCIAL_HOME", str(tmp_path))
    monkeypatch.setenv("FACTORY_COMMERCIAL_MODE", "enforce")
    monkeypatch.setenv("FACTORY_COMMERCIAL_POLICY", str(policy_path))
    _commercial_gate_wire_fakes(monkeypatch, fail_dispatch=True)
    real_now = datetime.now(timezone.utc)
    with pytest.raises(RuntimeError):
        _commercial_gate_run_proof_agent()
    ledger = UsageLedger(tmp_path)
    state = ledger.load(real_now)
    period = real_now.strftime("%Y-%m")
    assert state.used("rick", period) == 0

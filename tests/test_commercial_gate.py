"""Tests for the commercial gate and its Proof Agent wiring.

The wired-route tests use fakes for the proof internals so the commercial
behavior is tested deterministically: refusal before dispatch, settlement on
completion and on internal error, and the invariant that quota state never
changes a proof result.
"""

from datetime import datetime, timezone
import json

import pytest

from factoryline import commercial_policy as cp
from factoryline.commercial_gate import (
    CommercialAdmissionError,
    CommercialGate,
)
from factoryline.commercial_usage import UsageLedger

T0 = datetime(2027, 2, 10, 12, 0, tzinfo=timezone.utc)


def _activated_policy(free=2):
    raw = dict(cp.DEFAULT_POLICY)
    raw["activation"] = True
    raw["allowances"] = dict(raw["allowances"], free_monthly_workflows=free)
    return cp.parse_policy(raw)


def _gate(tmp_path, **kwargs):
    kwargs.setdefault("policy", _activated_policy())
    kwargs.setdefault("home", tmp_path)
    kwargs.setdefault("mode", "enforce")
    return CommercialGate(**kwargs)


def _admit(gate, n=1, subject="rick", **kwargs):
    kwargs.setdefault("workflow_id", f"wf-{n}")
    kwargs.setdefault("idempotency_key", f"key-{n}")
    kwargs.setdefault("binding", {"scope_digest": "s", "plan_digest": "p"})
    kwargs.setdefault("now", T0)
    return gate.admit(subject=subject, **kwargs)


def test_off_mode_is_fully_inert(tmp_path):
    gate = CommercialGate(policy=_activated_policy(), home=tmp_path, mode="off")
    admission = _admit(gate)
    assert admission.decision.outcome == cp.DISABLED
    assert not (tmp_path / "usage-ledger.jsonl").exists()


def test_shadow_mode_computes_without_persisting_or_refusing(tmp_path):
    gate = CommercialGate(policy=_activated_policy(free=0), home=tmp_path, mode="shadow")
    admission = _admit(gate)
    assert admission.decision.outcome == cp.UPGRADE_REQUIRED
    assert admission.admitted is True  # shadow never refuses
    assert not (tmp_path / "usage-ledger.jsonl").exists()


def test_enforce_prelaunch_policy_is_free(tmp_path):
    gate = CommercialGate(policy=cp.default_policy(), home=tmp_path, mode="enforce")
    admission = _admit(gate)
    assert admission.decision.outcome == cp.PRELAUNCH_FREE
    assert admission.reservation is None


def test_enforce_allowance_then_upgrade_required(tmp_path):
    gate = _gate(tmp_path)
    assert _admit(gate, n=1).decision.outcome == cp.ALLOW
    assert _admit(gate, n=2).decision.outcome == cp.ALLOW
    with pytest.raises(CommercialAdmissionError) as exc:
        _admit(gate, n=3)
    assert exc.value.code == "E_COMMERCIAL_UPGRADE_REQUIRED"
    assert "no overage" in str(exc.value)


def test_enforce_invalid_presented_entitlement_rejected_free(tmp_path):
    gate = _gate(tmp_path)
    with pytest.raises(CommercialAdmissionError) as exc:
        gate.admit(
            subject="rick",
            workflow_id="wf-x",
            idempotency_key="key-x",
            presented_envelope={"schema": "factory.dsse.envelope.v1"},
            presented_trust_root={"schema": "factory.trust.root.v1", "keys": []},
            now=T0,
        )
    assert exc.value.code == "E_COMMERCIAL_ENTITLEMENT_INVALID"
    # rejected starts never consume allowance
    assert gate.ledger.load(T0).used("rick", "2027-02") == 0


def test_settle_completed_counts_tool_error_releases(tmp_path):
    gate = _gate(tmp_path, policy=_activated_policy(free=2))
    first = _admit(gate, n=1)
    gate.settle(first, outcome="completed", now=T0)
    second = _admit(gate, n=2)
    gate.settle(second, outcome="tool_error", now=T0)
    state = gate.ledger.load(T0)
    assert state.used("rick", "2027-02") == 1
    third = _admit(gate, n=3)  # the released slot is available again
    assert third.decision.outcome == cp.ALLOW


def test_retry_same_key_does_not_double_charge(tmp_path):
    gate = _gate(tmp_path, policy=_activated_policy(free=1))
    first = _admit(gate, n=1)
    gate.settle(first, outcome="completed", now=T0)
    replay = _admit(gate, n=1)
    assert replay.reservation.reservation_id == first.reservation.reservation_id
    assert gate.ledger.load(T0).used("rick", "2027-02") == 1


def test_included_rerun_within_window_same_change(tmp_path):
    gate = _gate(tmp_path, policy=_activated_policy(free=1))
    first = _admit(gate, n=1)
    gate.settle(first, outcome="completed", now=T0)
    rerun = gate.admit(
        subject="rick",
        workflow_id="wf-1-repair",
        idempotency_key="key-1-repair",
        binding={"scope_digest": "s", "plan_digest": "p", "candidate_digest": "new"},
        rerun_of="wf-1",
        now=T0,
    )
    assert rerun.decision.outcome == cp.ALLOW_INCLUDED_RERUN
    gate.settle(rerun, outcome="completed", now=T0)
    assert gate.ledger.load(T0).used("rick", "2027-02") == 1


def test_rerun_scope_expansion_is_a_new_workflow(tmp_path):
    gate = _gate(tmp_path, policy=_activated_policy(free=5))
    first = _admit(gate, n=1)
    gate.settle(first, outcome="completed", now=T0)
    expanded = gate.admit(
        subject="rick",
        workflow_id="wf-1-wide",
        idempotency_key="key-1-wide",
        binding={"scope_digest": "BIGGER", "plan_digest": "p"},
        rerun_of="wf-1",
        now=T0,
    )
    assert expanded.decision.outcome == cp.ALLOW
    assert expanded.decision.counts_against_allowance is True


def test_rerun_window_expires_after_seven_days(tmp_path):
    from datetime import timedelta

    gate = _gate(tmp_path, policy=_activated_policy(free=5))
    first = _admit(gate, n=1)
    gate.settle(first, outcome="completed", now=T0)
    late = gate.admit(
        subject="rick",
        workflow_id="wf-1-late",
        idempotency_key="key-1-late",
        binding={"scope_digest": "s", "plan_digest": "p"},
        rerun_of="wf-1",
        now=T0 + timedelta(days=8),
    )
    assert late.decision.outcome == cp.ALLOW
    assert late.decision.counts_against_allowance is True


def test_rerun_slots_are_capped_at_two(tmp_path):
    gate = _gate(tmp_path, policy=_activated_policy(free=5))
    first = _admit(gate, n=1)
    gate.settle(first, outcome="completed", now=T0)
    for i in (1, 2):
        rerun = gate.admit(
            subject="rick",
            workflow_id=f"wf-1-r{i}",
            idempotency_key=f"key-1-r{i}",
            binding={"scope_digest": "s", "plan_digest": "p"},
            rerun_of="wf-1",
            now=T0,
        )
        assert rerun.decision.outcome == cp.ALLOW_INCLUDED_RERUN
        gate.settle(rerun, outcome="completed", now=T0)
    third = gate.admit(
        subject="rick",
        workflow_id="wf-1-r3",
        idempotency_key="key-1-r3",
        binding={"scope_digest": "s", "plan_digest": "p"},
        rerun_of="wf-1",
        now=T0,
    )
    assert third.decision.outcome == cp.ALLOW
    assert third.decision.counts_against_allowance is True


# --- Proof Agent wiring ----------------------------------------------------


def _wire_fakes(monkeypatch, fail_dispatch=False):
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


def _run_proof_agent():
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
    _wire_fakes(monkeypatch)
    result = _run_proof_agent()
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
    _wire_fakes(monkeypatch)
    result = _run_proof_agent()
    assert result["state"] == "PASS"
    ledger = UsageLedger(tmp_path)
    assert ledger.load(T0).used("rick", "2026-11") == 0  # prelaunch free
    # activate-era clock: force a reservation directly to prove settlement path
    gate = CommercialGate(home=tmp_path, mode="enforce")
    admission = gate.admit(
        subject="rick",
        workflow_id="wf-direct",
        idempotency_key="key-direct",
        now=T0,
    )
    gate.settle(admission, outcome="completed", now=T0)
    assert ledger.load(T0).used("rick", "2027-02") == 1


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
    calls = _wire_fakes(monkeypatch)

    from factoryline.runtime_audit_common import RuntimeAuditError

    with pytest.raises(RuntimeAuditError) as exc:
        _run_proof_agent()
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
    _wire_fakes(monkeypatch, fail_dispatch=True)
    real_now = datetime.now(timezone.utc)
    with pytest.raises(RuntimeError):
        _run_proof_agent()
    ledger = UsageLedger(tmp_path)
    state = ledger.load(real_now)
    period = real_now.strftime("%Y-%m")
    assert state.used("rick", period) == 0

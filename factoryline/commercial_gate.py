"""factoryline.commercial_gate - admission orchestration for the commercial model.

The gate combines the versioned policy, the local usage ledger and any imported
signed entitlements into one admission call used by execution entry points.

Modes (FACTORY_COMMERCIAL_MODE):
- off (default): fully inert. No files are created, no decision is recorded,
  admission always returns DISABLED. This is the shipped default.
- shadow: the decision and hypothetical counts are computed and returned to
  the caller for inspection, but nothing is persisted and nothing is refused.
- enforce: soft local enforcement. Over-allowance starts are refused with
  E_COMMERCIAL_UPGRADE_REQUIRED before dispatch; invalid presented entitlements
  with E_COMMERCIAL_ENTITLEMENT_INVALID. "Soft" is literal: the ledger is a
  local file a determined user can reset, and enforcement only covers entry
  points actually wired to this gate.

Invariants enforced here and by the wiring in runtime_audit:
- Quota status never changes a proof finding, never skips a check or negative
  control, and never interrupts an admitted run.
- Admission happens after safety preflight and before dispatch; settlement
  happens once, at the terminal result.
- Internal tool errors and rejected starts release the reservation; only a
  workflow that actually ran to a terminal result consumes allowance.
- Payment status never replaces signed-plan verification or human approval.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from typing import Any

from . import commercial_policy as policy_mod
from .commercial_policy import Decision, Policy, RerunView
from .commercial_usage import (
    COMPLETED,
    REJECTED,
    TOOL_ERROR,
    CommercialUsageError,
    Reservation,
    UsageLedger,
    default_home,
)
from .commercial_entitlement import (
    PRODUCT,
    CommercialEntitlementError,
    covering_entitlement,
    load_entitlements,
    verify_entitlement_envelope,
)
from .commercial_usage import RERUN_BINDING_FIELDS

MODE_ENV = "FACTORY_COMMERCIAL_MODE"
POLICY_ENV = "FACTORY_COMMERCIAL_POLICY"
MODES = frozenset({"off", "shadow", "enforce"})


class CommercialAdmissionError(RuntimeError):
    def __init__(self, code: str, message: str, decision: Decision | None = None):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.decision = decision


@dataclass
class Admission:
    decision: Decision
    reservation: Reservation | None = None
    mode: str = "off"
    shadow: bool = False

    @property
    def admitted(self) -> bool:
        return self.decision.outcome in {
            policy_mod.DISABLED,
            policy_mod.PRELAUNCH_FREE,
            policy_mod.ALLOW,
            policy_mod.ALLOW_INCLUDED_RERUN,
        } or self.shadow


def commercial_mode(env: dict[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    mode = (env.get(MODE_ENV) or "off").strip().lower()
    return mode if mode in MODES else "off"


def load_configured_policy(env: dict[str, str] | None = None) -> Policy:
    env = os.environ if env is None else env
    override = env.get(POLICY_ENV)
    if override:
        return policy_mod.load_policy(override)
    return policy_mod.default_policy()


def _utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


class CommercialGate:
    """One admission boundary per execution entry point."""

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        ledger: UsageLedger | None = None,
        home: str | Path | None = None,
        mode: str | None = None,
    ):
        self.policy = policy if policy is not None else load_configured_policy()
        self.mode = commercial_mode() if mode is None else mode
        self.ledger = ledger if ledger is not None else UsageLedger(home)
        self.home = Path(home) if home is not None else default_home()

    def _rerun_view(
        self,
        *,
        subject: str,
        rerun_of: str | None,
        binding: dict[str, Any],
        now: datetime,
        state,
    ) -> RerunView:
        if rerun_of is None:
            return RerunView(requested=False, eligible=False)
        original = state.find_original(subject, rerun_of)
        if original is None:
            return RerunView(requested=True, eligible=False, reason="original workflow not found")
        if original.closed_at is None:
            return RerunView(
                requested=True, eligible=False, reason="original workflow has no terminal result"
            )
        window = timedelta(days=self.policy.repair_rerun_window_days)
        closed = _utc(datetime.fromisoformat(original.closed_at))
        if _utc(now) > closed + window:
            return RerunView(requested=True, eligible=False, reason="repair window expired")
        for field in RERUN_BINDING_FIELDS:
            if binding.get(field) != original.binding.get(field):
                return RerunView(
                    requested=True,
                    eligible=False,
                    reason=f"{field} differs from the original change",
                )
        used = state.reruns_used(subject, rerun_of)
        if used >= self.policy.repair_reruns_per_workflow:
            return RerunView(
                requested=True,
                eligible=False,
                reason="included repair reruns already used",
            )
        return RerunView(requested=True, eligible=True)

    def admit(
        self,
        *,
        subject: str,
        workflow_id: str,
        idempotency_key: str,
        binding: dict[str, Any] | None = None,
        rerun_of: str | None = None,
        version: str = "0.0.0",
        presented_envelope: dict[str, Any] | None = None,
        presented_trust_root: dict[str, Any] | None = None,
        now: datetime,
    ) -> Admission:
        """Decide and (in enforce mode) atomically reserve one workflow start."""
        if not subject:
            raise CommercialAdmissionError(
                "E_COMMERCIAL_SUBJECT", "a human seat subject is required"
            )
        if self.mode == "off":
            return Admission(
                Decision(
                    policy_mod.DISABLED,
                    policy_mod.period_for(now),
                    None,
                    0,
                    None,
                    "commercial gate is disabled",
                    False,
                ),
                mode="off",
            )
        binding = binding or {}
        now = _utc(now)
        state = self.ledger.load(now)
        period = policy_mod.period_for(state.effective_now(now))
        used = state.used(subject, period)

        entitlement_valid = False
        entitlement_invalid_reason: str | None = None
        if presented_envelope is not None:
            try:
                if presented_trust_root is None:
                    raise CommercialEntitlementError(
                        "E_TRUST_ROOT_REQUIRED",
                        "a presented entitlement needs its commercial trust root",
                    )
                presented = verify_entitlement_envelope(
                    presented_envelope, trust_root=presented_trust_root
                )
                entitlement_valid = presented.covers(
                    subject=subject, product=PRODUCT, version=version, now=state.effective_now(now)
                )
                if not entitlement_valid:
                    entitlement_invalid_reason = (
                        "entitlement does not cover this subject, product, version or date"
                    )
            except CommercialEntitlementError as exc:
                entitlement_invalid_reason = f"{exc.code}: {exc.message}"
        else:
            covering = covering_entitlement(
                load_entitlements(self.home),
                subject=subject,
                product=PRODUCT,
                version=version,
                now=state.effective_now(now),
            )
            entitlement_valid = covering is not None

        rerun = self._rerun_view(
            subject=subject, rerun_of=rerun_of, binding=binding, now=state.effective_now(now), state=state
        )
        decision = policy_mod.decide(
            self.policy,
            now=state.effective_now(now),
            used=used,
            entitlement_valid=entitlement_valid,
            entitlement_invalid_reason=entitlement_invalid_reason,
            rerun=rerun,
        )

        if self.mode == "shadow":
            return Admission(decision, mode="shadow", shadow=True)

        # enforce
        if decision.outcome == policy_mod.ENTITLEMENT_INVALID:
            raise CommercialAdmissionError(
                "E_COMMERCIAL_ENTITLEMENT_INVALID", decision.reason, decision
            )
        if decision.outcome in {policy_mod.PRELAUNCH_FREE, policy_mod.DISABLED}:
            return Admission(decision, mode="enforce")
        if decision.outcome == policy_mod.ALLOW_INCLUDED_RERUN:
            reservation = self.ledger.try_reserve(
                subject=subject,
                period=period,
                workflow_id=workflow_id,
                idempotency_key=idempotency_key,
                binding=binding,
                rerun_of=rerun_of,
                limit=None,
                now=now,
            )
            return Admission(decision, reservation=reservation, mode="enforce")
        # ALLOW or UPGRADE_REQUIRED: the ledger re-checks the limit atomically.
        limit = self.policy.monthly_limit(entitlement_valid)
        reservation = self.ledger.try_reserve(
            subject=subject,
            period=period,
            workflow_id=workflow_id,
            idempotency_key=idempotency_key,
            binding=binding,
            rerun_of=None,
            limit=limit,
            now=now,
        )
        if reservation is None:
            refused = Decision(
                policy_mod.UPGRADE_REQUIRED,
                period,
                limit,
                limit,
                0,
                f"monthly allowance of {limit} workflows used; no overage charges apply",
                False,
            )
            raise CommercialAdmissionError(
                "E_COMMERCIAL_UPGRADE_REQUIRED", refused.reason, refused
            )
        if decision.outcome != policy_mod.ALLOW:
            # The atomic ledger recheck won the race against a stale pre-check.
            decision = Decision(
                policy_mod.ALLOW,
                period,
                limit,
                decision.used,
                None,
                "within monthly allowance",
                True,
            )
        return Admission(decision, reservation=reservation, mode="enforce")

    def settle(self, admission: Admission, *, outcome: str, now: datetime) -> None:
        """Settle one admitted workflow at its terminal result.

        completed counts against the allowance; tool_error and rejected release
        the reservation. Never call this mid-run.
        """
        if admission.reservation is None:
            return
        try:
            self.ledger.settle(admission.reservation.reservation_id, outcome=outcome, now=now)
        except CommercialUsageError:
            # Settlement must never crash the workflow it meters.
            pass


__all__ = [
    "Admission",
    "CommercialAdmissionError",
    "CommercialGate",
    "COMPLETED",
    "TOOL_ERROR",
    "REJECTED",
    "commercial_mode",
    "load_configured_policy",
]

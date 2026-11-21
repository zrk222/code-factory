"""factoryline.commercial_policy - approved commercial policy, parsed and applied.

This module records the commercial model approved by the project owner on
2026-11-21 and turns it into deterministic admission decisions:

- Free: 5 complete proof workflows per person per calendar month (UTC).
- Paid: 100 workflows per named human seat per month at USD 12.95 per seat,
  starting 2027-01-01. Everything before that date is PRELAUNCH_FREE.
- Each workflow includes 2 repair reruns for the same change within 7 days.
- One seat covers that person's agents and devices; the seat subject is the
  human owner supplied by the caller, never an AI agent's declared identity.
- Reading and exporting results is free. Rejected starts and internal tool
  errors never consume allowance. There are no overage charges: a person over
  allowance gets UPGRADE_REQUIRED, never a bill.

The bundled DEFAULT_POLICY has activation=False, so even an explicitly enabled
commercial gate returns PRELAUNCH_FREE for every run. Nothing here restricts,
bills, phones home, or changes a proof result.

This module decides admission only. It never interrupts an admitted workflow,
never changes PASS/BLOCKED/INCOMPLETE, and is unrelated to agent_license.py,
which records agent-autonomy evidence, not paid access.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
import json
from pathlib import Path
from typing import Any

SCHEMA = "factory.commercial.policy.v1"

PRELAUNCH_FREE = "PRELAUNCH_FREE"
ALLOW = "ALLOW"
ALLOW_INCLUDED_RERUN = "ALLOW_INCLUDED_RERUN"
UPGRADE_REQUIRED = "UPGRADE_REQUIRED"
ENTITLEMENT_INVALID = "ENTITLEMENT_INVALID"
DISABLED = "DISABLED"

DECISIONS = frozenset(
    {
        PRELAUNCH_FREE,
        ALLOW,
        ALLOW_INCLUDED_RERUN,
        UPGRADE_REQUIRED,
        ENTITLEMENT_INVALID,
        DISABLED,
    }
)


class CommercialPolicyError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise CommercialPolicyError(code, message)


def _parse_date(value: Any, field: str) -> date:
    _require(isinstance(value, str) and value.strip(), "E_POLICY_FIELD", f"{field} is required")
    try:
        return date.fromisoformat(value.strip())
    except ValueError as exc:
        raise CommercialPolicyError(
            "E_POLICY_FIELD", f"{field} must be an ISO calendar date"
        ) from exc


def _require_int(value: Any, field: str, minimum: int) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool) and value >= minimum,
        "E_POLICY_FIELD",
        f"{field} must be an integer >= {minimum}",
    )
    return value


@dataclass(frozen=True)
class Policy:
    """One immutable, versioned commercial policy revision."""

    revision: str
    activation: bool
    prelaunch_free_until: date
    currency: str
    seat_monthly_price: float
    price_effective_from: date
    free_monthly_workflows: int
    paid_monthly_workflows: int
    repair_reruns_per_workflow: int
    repair_rerun_window_days: int

    def monthly_limit(self, paid: bool) -> int:
        return self.paid_monthly_workflows if paid else self.free_monthly_workflows


def parse_policy(value: Any) -> Policy:
    """Validate one policy document or raise CommercialPolicyError fail closed."""
    _require(isinstance(value, dict), "E_POLICY_SCHEMA", "policy must be an object")
    _require(
        value.get("schema") == SCHEMA,
        "E_POLICY_SCHEMA",
        f"policy schema must be {SCHEMA}",
    )
    _require(
        isinstance(value.get("revision"), str) and value["revision"].strip(),
        "E_POLICY_FIELD",
        "revision is required",
    )
    _require(
        isinstance(value.get("activation"), bool),
        "E_POLICY_FIELD",
        "activation must be an explicit boolean",
    )
    pricing = value.get("pricing")
    _require(isinstance(pricing, dict), "E_POLICY_FIELD", "pricing block is required")
    _require(
        isinstance(pricing.get("currency"), str) and len(pricing["currency"]) == 3,
        "E_POLICY_FIELD",
        "pricing.currency must be a 3-letter code",
    )
    price = pricing.get("seat_monthly")
    _require(
        isinstance(price, (int, float)) and not isinstance(price, bool) and price >= 0,
        "E_POLICY_FIELD",
        "pricing.seat_monthly must be a non-negative number",
    )
    allowances = value.get("allowances")
    _require(
        isinstance(allowances, dict), "E_POLICY_FIELD", "allowances block is required"
    )
    return Policy(
        revision=value["revision"].strip(),
        activation=value["activation"],
        prelaunch_free_until=_parse_date(
            value.get("prelaunch_free_until"), "prelaunch_free_until"
        ),
        currency=pricing["currency"].upper(),
        seat_monthly_price=float(price),
        price_effective_from=_parse_date(
            pricing.get("effective_from"), "pricing.effective_from"
        ),
        free_monthly_workflows=_require_int(
            allowances.get("free_monthly_workflows"), "free_monthly_workflows", 0
        ),
        paid_monthly_workflows=_require_int(
            allowances.get("paid_monthly_workflows"), "paid_monthly_workflows", 1
        ),
        repair_reruns_per_workflow=_require_int(
            allowances.get("repair_reruns_per_workflow"), "repair_reruns_per_workflow", 0
        ),
        repair_rerun_window_days=_require_int(
            allowances.get("repair_rerun_window_days"), "repair_rerun_window_days", 1
        ),
    )


def load_policy(path: str | Path) -> Policy:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise CommercialPolicyError("E_POLICY_IO", str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise CommercialPolicyError("E_POLICY_SCHEMA", f"invalid JSON: {exc}") from exc
    return parse_policy(raw)


DEFAULT_POLICY: dict[str, Any] = {
    "schema": SCHEMA,
    "revision": "2026-11-21-approved-start",
    "activation": False,
    "prelaunch_free_until": "2027-01-01",
    "pricing": {
        "currency": "USD",
        "seat_monthly": 12.95,
        "effective_from": "2027-01-01",
        "promotion_end": None,
    },
    "allowances": {
        "free_monthly_workflows": 5,
        "paid_monthly_workflows": 100,
        "repair_reruns_per_workflow": 2,
        "repair_rerun_window_days": 7,
    },
    "seat": {"subject": "named_human", "includes": ["agents", "devices"]},
    "never_charged": [
        "read_results",
        "export_receipts",
        "rejected_starts",
        "internal_tool_errors",
    ],
    "overage": "none_hard_stop",
}


def default_policy() -> Policy:
    return parse_policy(DEFAULT_POLICY)


def period_for(now: datetime) -> str:
    """Return the UTC calendar-month period key, e.g. '2026-11'."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).strftime("%Y-%m")


@dataclass(frozen=True)
class RerunView:
    """Pre-evaluated repair-rerun eligibility for one candidate admission."""

    requested: bool
    eligible: bool
    reason: str = ""


@dataclass(frozen=True)
class Decision:
    outcome: str
    period: str
    limit: int | None
    used: int
    remaining: int | None
    reason: str
    counts_against_allowance: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "period": self.period,
            "limit": self.limit,
            "used": self.used,
            "remaining": self.remaining,
            "reason": self.reason,
            "counts_against_allowance": self.counts_against_allowance,
        }


def decide(
    policy: Policy,
    *,
    now: datetime,
    used: int,
    entitlement_valid: bool,
    entitlement_invalid_reason: str | None = None,
    rerun: RerunView | None = None,
) -> Decision:
    """Pure admission decision. Quota state is supplied; nothing is mutated here.

    used is the count of allowance-consuming workflows already admitted for the
    subject in the current period. An invalid presented entitlement rejects the
    start without consuming allowance; an absent entitlement simply means the
    free tier applies.
    """
    period = period_for(now)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if not policy.activation or now.date() < policy.prelaunch_free_until:
        return Decision(
            PRELAUNCH_FREE,
            period,
            None,
            used,
            None,
            "commercial policy is not active before 2027-01-01",
            False,
        )
    if entitlement_invalid_reason is not None:
        return Decision(
            ENTITLEMENT_INVALID,
            period,
            None,
            used,
            None,
            entitlement_invalid_reason,
            False,
        )
    if rerun is not None and rerun.requested and rerun.eligible:
        return Decision(
            ALLOW_INCLUDED_RERUN,
            period,
            None,
            used,
            None,
            "included repair rerun for the same change",
            False,
        )
    limit = policy.monthly_limit(entitlement_valid)
    reason_prefix = ""
    if rerun is not None and rerun.requested and not rerun.eligible:
        reason_prefix = f"rerun not eligible ({rerun.reason}); admitted as a new workflow. "
    if used < limit:
        return Decision(
            ALLOW,
            period,
            limit,
            used,
            limit - used,
            reason_prefix + "within monthly allowance",
            True,
        )
    return Decision(
        UPGRADE_REQUIRED,
        period,
        limit,
        used,
        0,
        reason_prefix
        + f"monthly allowance of {limit} workflows used; no overage charges apply",
        False,
    )

"""Bounded, lazily loaded commercial policy, usage and entitlement CLI.

These commands inspect the approved commercial model and local usage state.
There is no purchase, activation, checkout, telemetry or network path here.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

COMMAND_GROUP = "commercial"
OWNER = "commercial-model-maintainers"


def add_parser(sub: Any) -> None:
    """Register commercial commands without importing the gate at parse time."""
    s = sub.add_parser(
        "commercial",
        help="show the approved commercial policy, local usage and entitlements",
    )
    commercial_sub = s.add_subparsers(required=True, dest="commercial_cmd")

    plan = commercial_sub.add_parser(
        "plan", help="show the configured commercial policy and activation state"
    )
    plan.add_argument("--policy", help="policy JSON path (defaults to the bundled policy)")
    plan.add_argument("--json", action="store_true")

    usage = commercial_sub.add_parser(
        "usage", help="show local allowance usage for the current period"
    )
    usage.add_argument("--subject", help="show only this seat subject")
    usage.add_argument("--json", action="store_true")

    export = commercial_sub.add_parser(
        "export", help="export the local usage ledger as JSON (read-only, always free)"
    )
    export.add_argument("--out", help="write to this path instead of stdout")

    reset = commercial_sub.add_parser(
        "reset", help="explicitly delete the local usage ledger (visible soft-counter reset)"
    )
    reset.add_argument("--yes", action="store_true", help="confirm the reset")

    import_cmd = commercial_sub.add_parser(
        "import-entitlement",
        help="verify and store one issuer-signed commercial entitlement offline",
    )
    import_cmd.add_argument("envelope")
    import_cmd.add_argument("--trust-root", required=True)

    entitlements = commercial_sub.add_parser(
        "entitlements", help="list imported entitlements and their current validity"
    )
    entitlements.add_argument("--subject", help="check coverage for this seat subject")
    entitlements.add_argument("--version", default="0.0.0")
    entitlements.add_argument("--json", action="store_true")


def _print(payload: Any, as_json: bool) -> None:
    if as_json or not isinstance(payload, str):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(payload)


def run(args: Any) -> int:
    """Execute one commercial command."""
    now = datetime.now(timezone.utc)
    from . import commercial_policy as policy_mod
    from .commercial_gate import commercial_mode
    from .commercial_entitlement import (
        PRODUCT,
        CommercialEntitlementError,
        import_entitlement,
        load_entitlements,
    )
    from .commercial_policy import CommercialPolicyError
    from .commercial_usage import CommercialUsageError, UsageLedger

    try:
        if args.commercial_cmd == "plan":
            policy = (
                policy_mod.load_policy(args.policy)
                if getattr(args, "policy", None)
                else policy_mod.default_policy()
            )
            _print(
                {
                    "revision": policy.revision,
                    "activation": policy.activation,
                    "mode": commercial_mode(),
                    "prelaunch_free_until": policy.prelaunch_free_until.isoformat(),
                    "price": {
                        "currency": policy.currency,
                        "seat_monthly": policy.seat_monthly_price,
                        "effective_from": policy.price_effective_from.isoformat(),
                    },
                    "allowances": {
                        "free_monthly_workflows": policy.free_monthly_workflows,
                        "paid_monthly_workflows": policy.paid_monthly_workflows,
                        "repair_reruns_per_workflow": policy.repair_reruns_per_workflow,
                        "repair_rerun_window_days": policy.repair_rerun_window_days,
                    },
                    "note": "reading plans and results is always free; nothing is charged or restricted while activation is false",
                },
                True,
            )
            return 0

        if args.commercial_cmd == "usage":
            ledger = UsageLedger()
            state = ledger.load(now)
            period = policy_mod.period_for(state.effective_now(now))
            subjects = sorted(
                {
                    r.subject
                    for r in state.reservations.values()
                    if r.period == period
                    and (args.subject is None or r.subject == args.subject)
                }
            )
            _print(
                {
                    "period": period,
                    "clock_rollback_seen": state.clock_rollback_seen,
                    "subjects": {
                        subject: {"used": state.used(subject, period)}
                        for subject in subjects
                    },
                },
                True,
            )
            return 0

        if args.commercial_cmd == "export":
            payload = json.dumps(UsageLedger().export(now), indent=2, sort_keys=True)
            if getattr(args, "out", None):
                from pathlib import Path

                Path(args.out).write_text(payload + "\n", encoding="utf-8")
                print(args.out)
            else:
                print(payload)
            return 0

        if args.commercial_cmd == "reset":
            if not args.yes:
                print("reset requires --yes; this visibly deletes the local usage ledger")
                return 2
            removed = UsageLedger().reset()
            _print({"reset": True, "events_removed": removed}, True)
            return 0

        if args.commercial_cmd == "import-entitlement":
            entitlement = import_entitlement(
                args.envelope, trust_root_path=args.trust_root
            )
            _print({"imported": entitlement.as_dict()}, True)
            return 0

        if args.commercial_cmd == "entitlements":
            loaded = load_entitlements()
            rows = []
            for entitlement in loaded:
                row = entitlement.as_dict()
                if args.subject:
                    row["covers_subject_now"] = entitlement.covers(
                        subject=args.subject,
                        product=PRODUCT,
                        version=args.version,
                        now=now,
                    )
                rows.append(row)
            _print({"entitlements": rows, "count": len(rows)}, True)
            return 0

        print(f"unknown commercial command {args.commercial_cmd}")
        return 2
    except (CommercialPolicyError, CommercialEntitlementError, CommercialUsageError) as exc:
        print(str(exc))
        return 2

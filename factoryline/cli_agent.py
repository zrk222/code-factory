"""Bounded, lazily loaded CLI commands for agent contracts and control."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMAND_GROUP = "agent"
OWNER = "agent-governance"


def add_parser(sub: Any) -> None:
    """Register the agent command family without loading verifier engines."""
    agent = sub.add_parser(
        "agent",
        help="validate secret-free Core-5 agent contracts and verifier receipts",
    )
    agent_sub = agent.add_subparsers(dest="agent_cmd", required=True)
    contract = agent_sub.add_parser(
        "contract", help="validate one hash-bound Core-5 contract"
    )
    contract.add_argument("manifest")
    contract.add_argument("--json", action="store_true")
    attestation = agent_sub.add_parser(
        "attestation", help="validate a fresh creator/verifier adapter attestation"
    )
    attestation.add_argument("receipt")
    attestation.add_argument("--mission-digest")
    attestation.add_argument("--contract-digest")
    attestation.add_argument("--json", action="store_true")
    control = agent_sub.add_parser(
        "control", help="show the deterministic agent-access control-plane projection"
    )
    control.add_argument("--root", default=".")
    control.add_argument("--json", action="store_true")
    plan = agent_sub.add_parser(
        "plan",
        help="compile a human-gated request-routing plan without dispatching work",
    )
    plan.add_argument(
        "request", help="JSON request with intent, workflows, recipes, and task ids"
    )
    plan.add_argument("--out", help="write the sealed plan to a workspace path")
    plan.add_argument("--json", action="store_true")
    route = agent_sub.add_parser(
        "route", help="compile a sealed, read-only tiered model-route receipt"
    )
    route.add_argument("task_class", choices=("routine", "standard", "critical"))
    route.add_argument(
        "--risk", choices=("low", "medium", "high", "critical"), default="medium"
    )
    route.add_argument("--latency-budget-ms", type=int)
    route.add_argument("--token-budget", type=int)
    route.add_argument("--json", action="store_true")
    route_audit = agent_sub.add_parser(
        "route-audit",
        help="recompute the sealed route against the current deterministic routing policy",
    )
    route_audit.add_argument("receipt", help="factory.model-route.v1 JSON receipt")
    route_audit.add_argument("--json", action="store_true")
    card_audit = agent_sub.add_parser(
        "card-audit",
        help="validate an imported A2A v0.3 Agent Card declaration without contacting it",
    )
    card_audit.add_argument("card", help="local JSON Agent Card file")
    card_audit.add_argument("--json", action="store_true")
    drift = agent_sub.add_parser(
        "drift", help="compare a prior control projection with the current one"
    )
    drift.add_argument("baseline", nargs="?")
    drift.add_argument(
        "--current", help="current projection JSON; defaults to the live projection"
    )
    drift.add_argument("--root", default=".")
    drift.add_argument("--out", help="write the hash-bound drift receipt")
    drift.add_argument("--verify", help="verify an existing drift receipt")
    drift.add_argument("--json", action="store_true")
    extended = agent_sub.add_parser(
        "extended",
        help="validate optional lanes 7-8 from supplied evidence into Receipt v2",
    )
    extended.add_argument("feature")
    extended.add_argument("--root", default=".")
    extended.add_argument(
        "--evidence", help="JSON evidence object for the two extended lanes"
    )
    extended.add_argument("--extended-assurance", action="store_true")
    extended.add_argument("--required-lane", action="append", default=[])
    extended.add_argument("--tenant-id", default="local")
    extended.add_argument("--run-id", default="extended-assurance")
    extended.add_argument("--timestamp")
    extended.add_argument(
        "--verify", help="verify an existing Receipt v2 payload instead of building one"
    )
    extended.add_argument("--json", action="store_true")


def run(args: Any) -> dict[str, Any]:
    """Execute one selected agent command after the parser has resolved it."""
    if args.agent_cmd in {"contract", "attestation"}:
        from .agent_contract import (
            validate_agent_contract,
            validate_verifier_attestation,
        )

        if args.agent_cmd == "contract":
            return validate_agent_contract(Path(args.manifest))
        return validate_verifier_attestation(
            Path(args.receipt),
            mission_digest=args.mission_digest,
            contract_digest=args.contract_digest,
        )

    from .agentic_control import (
        AgenticControlError,
        agentic_control_projection,
        audit_model_route_policy,
        audit_a2a_agent_card,
        build_extended_assurance_receipt,
        compare_agentic_control_drift,
        create_orchestrator_plan,
        route_model,
        verify_agentic_control_drift,
        verify_extended_assurance_receipt,
    )

    if args.agent_cmd == "control":
        return agentic_control_projection(Path(args.root))
    if args.agent_cmd == "plan":
        result = create_orchestrator_plan(
            json.loads(Path(args.request).read_text(encoding="utf-8"))
        )
        if args.out:
            destination = Path(args.out)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        return result
    if args.agent_cmd == "route":
        return route_model(
            args.task_class,
            risk=args.risk,
            latency_budget_ms=args.latency_budget_ms,
            token_budget=args.token_budget,
        )
    if args.agent_cmd == "route-audit":
        try:
            route_receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgenticControlError(
                "E_MODEL_ROUTE_INPUT", "route receipt could not be read as JSON"
            ) from exc
        if not isinstance(route_receipt, dict):
            raise AgenticControlError(
                "E_MODEL_ROUTE_INPUT", "route receipt must be a JSON object"
            )
        return audit_model_route_policy(route_receipt)
    if args.agent_cmd == "card-audit":
        try:
            card = json.loads(Path(args.card).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgenticControlError(
                "E_A2A_CARD_INPUT", "Agent Card file could not be read as UTF-8 JSON"
            ) from exc
        return audit_a2a_agent_card(card)
    if args.agent_cmd == "drift":
        if args.verify:
            return verify_agentic_control_drift(
                json.loads(Path(args.verify).read_text(encoding="utf-8"))
            )
        if not args.baseline:
            raise AgenticControlError(
                "E_AGENTIC_DRIFT_INPUT",
                "baseline projection is required unless --verify is used",
            )
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        current = (
            json.loads(Path(args.current).read_text(encoding="utf-8"))
            if args.current
            else agentic_control_projection(Path(args.root))
        )
        result = compare_agentic_control_drift(baseline, current)
        if args.out:
            destination = Path(args.out)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        return result
    if args.verify:
        return verify_extended_assurance_receipt(
            json.loads(Path(args.verify).read_text(encoding="utf-8"))
        )
    evidence = (
        json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        if args.evidence
        else {}
    )
    return build_extended_assurance_receipt(
        args.feature,
        extended_assurance=args.extended_assurance,
        evidence=evidence,
        required_lanes=args.required_lane,
        tenant_id=args.tenant_id,
        run_id=args.run_id,
        timestamp=args.timestamp,
    )

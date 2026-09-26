"""Bounded, lazily loaded domain and mission-control CLI."""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from importlib import import_module
from pathlib import Path
from typing import Any

COMMAND_GROUP = "domain"
OWNER = "domain-control-maintainers"


def add_parser(sub: Any) -> None:
    """Register ontology and mission-control readers without loading engines."""
    ontology = sub.add_parser(
        "ontology",
        help="validate an explicitly human-approved domain vocabulary without inferring or mutating intent",
    )
    ontology_sub = ontology.add_subparsers(required=True, dest="ontology_cmd")
    template = ontology_sub.add_parser(
        "template", help="render a domain-ontology template"
    )
    template.add_argument("--json", action="store_true")
    validate = ontology_sub.add_parser(
        "validate",
        help="fail closed when referenced concepts are not in the approved ontology",
    )
    validate.add_argument("--root", default=".")
    validate.add_argument(
        "--ontology",
        required=True,
        help="workspace-relative factory.domain-ontology.v1 JSON",
    )
    validate.add_argument(
        "--concept",
        required=True,
        action="append",
        help="referenced domain concept id; repeat as needed",
    )
    validate.add_argument("--json", action="store_true")

    mission = sub.add_parser(
        "mission-control",
        help="read one unified, zero-authority human and agent evidence status",
    )
    mission_sub = mission.add_subparsers(required=True, dest="mission_control_cmd")
    status = mission_sub.add_parser(
        "status", help="read local mission-control facts without granting authority"
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")
    profile = mission_sub.add_parser(
        "profile", help="measure local evidence readers with body-free fingerprints"
    )
    profile.add_argument("--root", default=".")
    profile.add_argument("--json", action="store_true")


def _run_ontology(args: Any) -> int:
    from .domain_ontology import (
        DomainOntologyError,
        domain_ontology_template,
        validate_domain_ontology,
    )

    root = Path(getattr(args, "root", ".")).resolve()
    try:
        result = (
            domain_ontology_template()
            if args.ontology_cmd == "template"
            else validate_domain_ontology(root, Path(args.ontology), args.concept)
        )
        code = (
            0
            if args.ontology_cmd == "template"
            or result.get("marker") == "ONTOLOGY_READY"
            else 1
        )
    except (
        DomainOntologyError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.domain-ontology.error.v1",
            "marker": "ONTOLOGY_INPUT_REJECTED",
            "code": getattr(exc, "code", "E_ONTOLOGY_SCHEMA"),
            "message": str(exc),
        }
        code = 2
    print(
        json.dumps(result, indent=2, sort_keys=True),
        file=sys.stderr if code else sys.stdout,
    )
    return code


def _run_mission(args: Any) -> int:
    from .mission_control_status import mission_control_profile, mission_control_status

    reader = (
        mission_control_profile
        if args.mission_control_cmd == "profile"
        else mission_control_status
    )
    result = reader(Path(args.root).resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


# Domain workflow dispatch stays in this adapter so the root CLI only routes commands.
_UNHANDLED = object()


@lru_cache(maxsize=256)
def _lazy_import(module: str, symbol: str):
    """Load workflow implementation symbols only when their command runs."""
    relative = f".{module}" if module else "."
    return getattr(import_module(relative, __package__), symbol)


def _workflow_action_01(a):
    if a.cmd == "prd" and a.prd_cmd == "grill":
        result = _lazy_import("prd_grill", "grill_prd")(
            Path(a.prd),
            Path(a.root),
            a.mode,
            a.project,
            Path(a.out) if a.out else None,
            a.confirm,
            a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_02(a):
    if a.cmd == "prd" and a.prd_cmd == "verify":
        result = _lazy_import("prd_grill", "verify_prd_grill")(Path(a.receipt))
        return result
    return _UNHANDLED


def _workflow_action_03(a):
    if a.cmd == "intake" and a.intake_cmd == "grill":
        result = _lazy_import("intake_grill", "grill_intake")(
            Path(a.prd),
            Path(a.root),
            a.project,
            Path(a.out) if a.out else None,
            a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_04(a):
    if a.cmd == "intake" and a.intake_cmd == "confirm":
        result = _lazy_import("intake_grill", "confirm_intake")(
            Path(a.root),
            Path(a.intake),
            a.framework,
            a.intent,
            a.acceptance,
            a.external_effects,
            a.approved_by,
            a.rationale,
            a.re_evaluate_when,
            Path(a.out) if a.out else None,
            a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_05(a):
    if a.cmd == "intake" and a.intake_cmd == "verify":
        result = (
            _lazy_import("intake_grill", "verify_intake_confirmation")(
                Path(a.root), Path(a.receipt)
            )
            if a.confirmation
            else _lazy_import("intake_grill", "verify_intake_grill")(
                Path(a.root), Path(a.receipt)
            )
        )
        return result
    return _UNHANDLED


def _workflow_action_06(a):
    if (
        a.cmd == "intake"
        and a.intake_cmd in {"parameters", "params"}
        and a.intake_parameters_cmd == "seal"
    ):
        result = _lazy_import("intake_parameters", "seal_intake_parameters")(
            Path(a.root),
            Path(a.request),
            Path(a.out) if a.out else None,
            a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_07(a):
    if (
        a.cmd == "intake"
        and a.intake_cmd in {"parameters", "params"}
        and a.intake_parameters_cmd == "verify"
    ):
        result = _lazy_import("intake_parameters", "verify_intake_parameters")(
            Path(a.root), Path(a.receipt)
        )
        return result
    return _UNHANDLED


def _workflow_action_08(a):
    if a.cmd == "intake" and a.intake_cmd in {"parameters", "params"}:
        result = _lazy_import("intake_parameters", "intake_parameters_status")(
            Path(a.root)
        )
        return result
    return _UNHANDLED


def _workflow_action_09(a):
    if a.cmd == "intake":
        result = _lazy_import("intake_grill", "intake_status")(
            Path(a.root), Path(a.prd) if a.prd else None
        )
        return result
    return _UNHANDLED


def _workflow_action_10(a):
    if a.cmd == "agent":
        from .cli_agent import run as run_agent

        result = run_agent(a)
        return result
    return _UNHANDLED


def _workflow_action_11(a):
    if a.cmd == "langgraph" and a.langgraph_cmd == "doctor":
        result = _lazy_import("mission_graph", "langgraph_doctor")()
        return result
    return _UNHANDLED


def _workflow_action_12(a):
    if a.cmd == "langgraph" and a.langgraph_cmd == "init":
        result = _lazy_import("mission_graph", "init_mission_graph")(
            Path(a.mission), Path(a.root)
        )
        return result
    return _UNHANDLED


def _workflow_action_13(a):
    if a.cmd == "langgraph" and a.langgraph_cmd == "status":
        result = _lazy_import("mission_graph", "mission_graph_status")(
            Path(a.mission), Path(a.root)
        )
        return result
    return _UNHANDLED


def _workflow_action_14(a):
    if a.cmd == "langgraph" and a.langgraph_cmd == "history":
        result = _lazy_import("mission_graph", "mission_graph_history")(
            Path(a.mission), Path(a.root)
        )
        return result
    return _UNHANDLED


def _workflow_action_15(a):
    if a.cmd == "langgraph" and a.langgraph_cmd == "verify":
        result = _lazy_import("mission_graph", "verify_mission_graph")(
            Path(a.mission), Path(a.root)
        )
        return result
    return _UNHANDLED


def _workflow_action_16(a):
    if a.cmd == "langgraph" and a.langgraph_cmd == "export":
        result = _lazy_import("mission_graph", "export_mission_graph")(
            Path(a.mission), Path(a.root)
        )
        return result
    return _UNHANDLED


def _workflow_action_17(a):
    if a.cmd == "langgraph" and a.langgraph_cmd == "replay-verify":
        result = _lazy_import("langgraph_assurance", "verify_langgraph_resume_parity")(
            Path(a.root),
            a.reference,
            a.resumed,
            out=a.out,
        )
        return result
    return _UNHANDLED


def _workflow_action_18(a):
    if a.cmd == "langgraph":
        payload = (
            json.loads(Path(a.payload).read_text(encoding="utf-8")) if a.payload else {}
        )
        if not isinstance(payload, dict):
            raise _lazy_import("mission_graph", "MissionGraphError")(
                "MISSION_GRAPH_EVENT_INVALID",
                "payload file must contain one JSON object",
            )
        result = _lazy_import("mission_graph", "apply_mission_event")(
            Path(a.mission),
            Path(a.root),
            a.event,
            a.actor,
            a.role,
            a.idempotency_key,
            Path(a.receipt),
            payload,
        )
        return result
    return _UNHANDLED


def _workflow_action_19(a):
    if a.cmd == "provider" and a.provider_cmd == "init":
        config = json.loads(Path(a.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise _lazy_import("provider_router", "ProviderRouterError")(
                "PROVIDER_POLICY_INVALID", "config must contain one JSON object"
            )
        result = _lazy_import("provider_router", "create_provider_policy")(
            Path(a.root),
            config.get("owner", ""),
            config.get("providers", []),
            config.get("allowed_ides", []),
            config.get("max_cost_usd"),
            config.get("quality_floor", "balanced"),
            config.get("routing_bias", 50),
            a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_20(a):
    if a.cmd == "provider" and a.provider_cmd == "verify":
        result = _lazy_import("provider_router", "verify_provider_policy")(
            Path(a.policy)
        )
        return result
    return _UNHANDLED


def _workflow_action_21(a):
    if a.cmd == "provider" and a.provider_cmd == "doctor":
        result = _lazy_import("provider_router", "provider_doctor")(Path(a.policy))
        return result
    return _UNHANDLED


def _workflow_action_22(a):
    if a.cmd == "provider":
        result = _lazy_import("provider_router", "route_provider")(
            Path(a.policy),
            Path(a.mission),
            Path(a.root),
            a.ide,
            a.risk,
            a.preferred_provider,
            a.preferred_model,
            a.cache_provider,
            a.cache_model,
            a.projected_tokens,
            a.projected_cost_usd,
            a.latency_budget_ms,
            a.required_capability,
            a.privacy_class,
            a.output_contract,
        )
        return result
    return _UNHANDLED


def _workflow_action_23(a):
    if a.cmd == "migration" and a.migration_cmd == "assess":
        result = _lazy_import("migration", "assess_migration_readiness")(
            Path(a.manifest), Path(a.root), force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_24(a):
    if a.cmd == "migration":
        result = _lazy_import("migration", "verify_migration_readiness")(
            Path(a.receipt)
        )
        return result
    return _UNHANDLED


def _workflow_action_25(a):
    if a.cmd == "context" and a.context_cmd == "build":
        result = _lazy_import("migration", "build_repository_context")(
            Path(a.root), force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_26(a):
    if a.cmd == "context":
        result = _lazy_import("migration", "verify_repository_context")(Path(a.receipt))
        return result
    return _UNHANDLED


def _workflow_action_27(a):
    if a.cmd == "product" and a.product_cmd == "compile":
        result = _lazy_import("product_missions", "compile_product_prd")(
            Path(a.prd),
            Path(a.root),
            a.project,
            a.force,
            Path(a.intake) if a.intake else None,
        )
        return result
    return _UNHANDLED


def _workflow_action_28(a):
    if a.cmd == "product" and a.product_cmd == "verify":
        result = _lazy_import("product_missions", "verify_product_graph")(Path(a.graph))
        return result
    return _UNHANDLED


def _workflow_action_29(a):
    if a.cmd == "product":
        result = _lazy_import("product_missions", "plan_value_slices")(
            Path(a.graph), Path(a.root), a.max_requirements, a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_30(a):
    if (
        a.cmd == "mission"
        and a.mission_cmd == "proof-delta"
        and a.mission_delta_cmd == "create"
    ):
        result = _lazy_import("proof_delta", "create_proof_delta")(
            Path(a.root),
            Path(a.mission),
            Path(a.prior_candidate),
            Path(a.repair_candidate),
            Path(a.failure),
            a.criterion,
            Path(a.out),
        )
        return result
    return _UNHANDLED


def _workflow_action_31(a):
    if (
        a.cmd == "mission"
        and a.mission_cmd == "proof-delta"
        and a.mission_delta_cmd == "verify"
    ):
        result = _lazy_import("proof_delta", "verify_proof_delta")(
            Path(a.root), Path(a.receipt)
        )
        return result
    return _UNHANDLED


def _workflow_action_32(a):
    if a.cmd == "mission" and a.mission_cmd == "proof-delta":
        result = _lazy_import("proof_delta", "proof_delta_status")(
            Path(a.root), a.mission_id
        )
        return result
    return _UNHANDLED


def _workflow_action_33(a):
    if a.cmd == "mission" and a.mission_cmd == "create":
        result = _lazy_import("product_missions", "create_mission")(
            Path(a.slices),
            a.slice_id,
            Path(a.root),
            a.owner,
            a.executor,
            a.force,
            a.max_iterations,
            a.max_wall_seconds,
            a.max_tokens,
            a.max_cost_usd,
            Path(a.readiness) if a.readiness else None,
            a.require_intake,
        )
        return result
    return _UNHANDLED


def _workflow_action_34(a):
    if a.cmd == "mission" and a.mission_cmd == "verify":
        result = _lazy_import("product_missions", "verify_mission")(Path(a.mission))
        return result
    return _UNHANDLED


def _workflow_action_35(a):
    if a.cmd == "mission" and a.mission_cmd == "close":
        result = _lazy_import("product_missions", "close_mission")(
            Path(a.mission), Path(a.validation), Path(a.root), force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_36(a):
    if a.cmd == "mission" and a.mission_cmd == "verify-completion":
        result = _lazy_import("product_missions", "verify_mission_completion")(
            Path(a.completion)
        )
        return result
    return _UNHANDLED


def _workflow_action_37(a):
    if a.cmd == "mission":
        result = _lazy_import("product_missions", "decide_mission")(
            Path(a.mission),
            Path(a.root),
            owner=a.owner,
            decision=a.decision,
            rationale=a.rationale,
            force=a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_38(a):
    if a.cmd == "opinion" and a.opinion_cmd == "init":
        result = _lazy_import("signal_loop", "init_opinion_dock")(
            Path(a.root), a.owner, force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_39(a):
    if a.cmd == "opinion" and a.opinion_cmd == "verify":
        result = _lazy_import("signal_loop", "verify_opinion_dock")(Path(a.dock))
        return result
    return _UNHANDLED


def _workflow_action_40(a):
    if a.cmd == "opinion":
        rule = json.loads(Path(a.rule_file).read_text(encoding="utf-8"))
        result = _lazy_import("signal_loop", "correct_opinion_dock")(
            Path(a.dock), a.owner, rule, a.rationale
        )
        return result
    return _UNHANDLED


def _workflow_action_41(a):
    if a.cmd == "signal" and a.signal_cmd == "capture":
        body = (
            a.body
            if a.body is not None
            else Path(a.body_file).read_text(encoding="utf-8")
        )
        result = _lazy_import("signal_loop", "capture_signal")(
            Path(a.root),
            source=a.source,
            title=a.title,
            body=body,
            authorization=a.authorization,
            severity=a.severity,
            external_id=a.external_id,
            url=a.url,
            observed_at=a.observed_at,
            hypotheses=a.hypothesis,
            requirements=a.requirement,
            outcomes=a.outcome,
            acceptance=a.acceptance,
        )
        return result
    return _UNHANDLED


def _workflow_action_42(a):
    if a.cmd == "signal" and a.signal_cmd == "triage":
        result = _lazy_import("signal_loop", "triage_signal")(
            Path(a.signal), Path(a.dock), Path(a.root), force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_43(a):
    if a.cmd == "signal" and a.signal_cmd == "decide":
        result = _lazy_import("signal_loop", "decide_triage")(
            Path(a.triage),
            Path(a.root),
            owner=a.owner,
            decision=a.decision,
            rationale=a.rationale,
            override_block=a.override_block,
            force=a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_44(a):
    if a.cmd == "signal" and a.signal_cmd == "feedback":
        result = _lazy_import("signal_loop", "capture_outcome_feedback")(
            Path(a.root),
            mission_id=a.mission_id,
            metric=a.metric,
            observed=a.observed,
            target=a.target,
            evidence_path=Path(a.evidence),
        )
        return result
    return _UNHANDLED


def _workflow_action_45(a):
    if a.cmd == "signal":
        result = _lazy_import("signal_loop", "promote_signal")(
            Path(a.decision), Path(a.root), project=a.project, force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_46(a):
    if a.cmd == "learning" and a.learning_cmd == "init":
        milestones = json.loads(Path(a.milestones).read_text(encoding="utf-8"))
        result = _lazy_import("learning_loop", "init_learning_task")(
            Path(a.root),
            a.task_id,
            a.owner,
            a.objective,
            milestones,
            force=a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_47(a):
    if a.cmd == "learning" and a.learning_cmd == "packet":
        result = _lazy_import("learning_loop", "build_fresh_worker_packet")(
            Path(a.task), a.milestone, a.worker, force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_48(a):
    if a.cmd == "learning" and a.learning_cmd == "propose":
        instructions = json.loads(Path(a.instructions).read_text(encoding="utf-8"))
        result = _lazy_import("learning_loop", "propose_instruction_candidate")(
            Path(a.task),
            Path(a.root),
            a.milestone,
            a.worker,
            Path(a.outcome),
            instructions,
            force=a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_49(a):
    if a.cmd == "learning" and a.learning_cmd == "validate":
        results = json.loads(Path(a.results).read_text(encoding="utf-8"))
        result = _lazy_import("learning_loop", "validate_instruction_candidate")(
            Path(a.candidate),
            Path(a.root),
            a.validator,
            results,
            force=a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_50(a):
    if a.cmd == "learning" and a.learning_cmd == "experiment":
        space = json.loads(Path(a.space).read_text(encoding="utf-8"))
        result = _lazy_import("learning_loop", "plan_learning_experiment")(
            Path(a.task),
            space,
            variant=a.variant,
            max_resource=a.max_resource,
            grace_period=a.grace_period,
            reduction_factor=a.reduction_factor,
            max_concurrent=a.max_concurrent,
            samples=a.samples,
            force=a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_51(a):
    if a.cmd == "learning":
        result = _lazy_import("learning_loop", "promote_instruction_candidate")(
            Path(a.validation), a.owner, force=a.force
        )
        return result
    return _UNHANDLED


def _workflow_action_52(a):
    if a.cmd == "pr":
        result = _lazy_import("product_missions", "draft_pr")(
            Path(a.mission),
            Path(a.root),
            [Path(item) for item in a.evidence],
            a.force,
        )
        return result
    return _UNHANDLED


def _workflow_action_53(a):
    if a.cmd == "outcome" and (a.outcome_cmd == "record"):
        result = _lazy_import("product_missions", "record_outcome")(
            Path(a.mission),
            Path(a.root),
            a.metric,
            a.value,
            a.target,
            a.evidence_class,
            a.source,
            a.notes,
        )
        return result
    return _UNHANDLED


def _workflow_outcome_summary(a):
    if a.cmd != "outcome":
        return _UNHANDLED
    result = _lazy_import("product_missions", "outcome_summary")(
        Path(a.root), a.mission_id
    )
    return result


_WORKFLOW_ACTIONS = {
    "prd": (
        _workflow_action_01,
        _workflow_action_02,
    ),
    "intake": (
        _workflow_action_03,
        _workflow_action_04,
        _workflow_action_05,
        _workflow_action_06,
        _workflow_action_07,
        _workflow_action_08,
        _workflow_action_09,
    ),
    "agent": (_workflow_action_10,),
    "langgraph": (
        _workflow_action_11,
        _workflow_action_12,
        _workflow_action_13,
        _workflow_action_14,
        _workflow_action_15,
        _workflow_action_16,
        _workflow_action_17,
        _workflow_action_18,
    ),
    "provider": (
        _workflow_action_19,
        _workflow_action_20,
        _workflow_action_21,
        _workflow_action_22,
    ),
    "migration": (
        _workflow_action_23,
        _workflow_action_24,
    ),
    "context": (
        _workflow_action_25,
        _workflow_action_26,
    ),
    "product": (
        _workflow_action_27,
        _workflow_action_28,
        _workflow_action_29,
    ),
    "mission": (
        _workflow_action_30,
        _workflow_action_31,
        _workflow_action_32,
        _workflow_action_33,
        _workflow_action_34,
        _workflow_action_35,
        _workflow_action_36,
        _workflow_action_37,
    ),
    "opinion": (
        _workflow_action_38,
        _workflow_action_39,
        _workflow_action_40,
    ),
    "signal": (
        _workflow_action_41,
        _workflow_action_42,
        _workflow_action_43,
        _workflow_action_44,
        _workflow_action_45,
    ),
    "learning": (
        _workflow_action_46,
        _workflow_action_47,
        _workflow_action_48,
        _workflow_action_49,
        _workflow_action_50,
        _workflow_action_51,
    ),
    "pr": (_workflow_action_52,),
    "outcome": (
        _workflow_action_53,
        _workflow_outcome_summary,
    ),
}


def _workflow_result(a):
    for handler in _WORKFLOW_ACTIONS.get(a.cmd, ()):
        result = handler(a)
        if result is not _UNHANDLED:
            return result
    return _UNHANDLED


def _workflow_domain_error(exc):
    print(
        json.dumps(
            {
                "schema": "factory.workflow_error.v1",
                "status": "failed",
                "code": exc.code,
                "message": exc.message,
                "marker": getattr(exc, "marker", "WORKFLOW_REJECTED"),
                "failure": getattr(
                    exc,
                    "guidance",
                    _lazy_import("failure_guidance", "explain_failure")(
                        exc.code, exc.message
                    ),
                ),
            },
            indent=2,
        ),
        file=sys.stderr,
    )
    return 1


def _workflow_input_error(exc):
    print(
        json.dumps(
            {
                "schema": "factory.workflow_error.v1",
                "status": "failed",
                "code": "E_INPUT",
                "message": str(exc),
                "failure": _lazy_import("failure_guidance", "explain_failure")(
                    "E_INPUT", str(exc)
                ),
            },
            indent=2,
        ),
        file=sys.stderr,
    )
    return 1


def _is_product_verification(a) -> bool:
    return a.cmd == "product" and a.product_cmd == "verify"


def _is_mission_verification(a) -> bool:
    return a.cmd == "mission" and (
        a.mission_cmd in {"verify", "verify-completion"}
        or (a.mission_cmd == "proof-delta" and a.mission_delta_cmd == "verify")
    )


def _is_langgraph_verification(a) -> bool:
    return a.cmd == "langgraph" and a.langgraph_cmd in {"verify", "replay-verify"}


def _is_agent_verification(a) -> bool:
    return a.cmd == "agent" and a.agent_cmd in {
        "contract",
        "attestation",
        "route-audit",
        "card-audit",
    }


def _is_intake_verification(a) -> bool:
    return (
        a.cmd == "intake"
        and a.intake_cmd in {"parameters", "params"}
        and a.intake_parameters_cmd == "verify"
    )


def _workflow_verification(a) -> bool:
    checks = (
        _is_product_verification,
        _is_mission_verification,
        _is_langgraph_verification,
        _is_agent_verification,
        _is_intake_verification,
    )
    return any(check(a) for check in checks) or (
        a.cmd in {"opinion", "provider"} and getattr(a, f"{a.cmd}_cmd") == "verify"
    )


def _workflow_output(a, result):
    if a.cmd == "langgraph" and a.langgraph_cmd == "replay-verify" and a.mermaid:
        print(result["mermaid"])
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return (
        0
        if not _workflow_verification(a)
        else (0 if result.get("valid", result.get("verdict") == "VERIFIED") else 1)
    )


def run_workflow_family(a):
    """Dispatch workflow commands and normalize domain failures for the CLI."""
    try:
        result = _workflow_result(a)
    except (
        _lazy_import("product_missions", "ProductMissionError"),
        _lazy_import("intake_parameters", "IntakeParametersError"),
        _lazy_import("signal_loop", "SignalLoopError"),
        _lazy_import("learning_loop", "LearningLoopError"),
        _lazy_import("migration", "MigrationError"),
        _lazy_import("mission_graph", "MissionGraphError"),
        _lazy_import("proof_delta", "ProofDeltaError"),
        _lazy_import("provider_router", "ProviderRouterError"),
        _lazy_import("agent_contract", "AgentContractError"),
        _lazy_import("agentic_control", "AgenticControlError"),
        _lazy_import("langgraph_assurance", "LangGraphAssuranceError"),
    ) as exc:
        return _workflow_domain_error(exc)
    except (OSError, json.JSONDecodeError) as exc:
        return _workflow_input_error(exc)
    return _workflow_output(a, result)


def run(args: Any) -> int:
    """Dispatch domain commands with lazy imports."""
    return _run_ontology(args) if args.cmd == "ontology" else _run_mission(args)

"""Bounded, lazily loaded deep, runtime, and senior-audit CLI."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "deep-audit"
OWNER = "senior-audit-maintainers"


def add_parser(sub: Any) -> None:
    """Register senior-audit commands without loading audit engines."""
    deep = sub.add_parser(
        "deep-audit",
        help="evaluate signed analyzer evidence or read local repair guidance; never release approval",
    )
    deep_sub = deep.add_subparsers(required=True, dest="deep_cmd")
    _add_execution_parsers(deep_sub)
    for action in ("evaluate", "status", "compare", "attestation"):
        command = deep_sub.add_parser(action)
        command.add_argument("--root", default=".")
        command.add_argument("--json", action="store_true")
        if action == "compare":
            command.add_argument("--before", required=True)
            command.add_argument("--after", required=True)
            command.add_argument("--before-attestation")
            command.add_argument("--after-attestation")
            command.add_argument("--trust-root")
            command.add_argument("--require-attestation", action="store_true")
            command.add_argument("--max-age-seconds", type=int, default=3600)
        if action == "attestation":
            command.add_argument("attestation")
            command.add_argument("--receipt", required=True)
            command.add_argument("--trust-root", required=True)
            command.add_argument("--max-age-seconds", type=int, default=3600)
        if action == "evaluate":
            command.add_argument("--plan", required=True)
            command.add_argument("--trust-root", required=True)
            command.add_argument("--trust-root-sha256", required=True)

    runtime = sub.add_parser(
        "runtime-audit", help="run or inspect six signed senior-engineering audit lanes"
    )
    runtime_sub = runtime.add_subparsers(required=True, dest="runtime_audit_cmd")
    for action in ("inspect", "run"):
        command = runtime_sub.add_parser(
            action, help=f"{action} one signed runtime audit plan"
        )
        command.add_argument("plan")
        command.add_argument("--root", default=".")
        command.add_argument("--trust-root", required=True)
        command.add_argument("--trust-root-sha256", required=True)
        command.add_argument("--environment-sha256", required=True)
        command.add_argument(
            "--require-intake",
            action="store_true",
            help="require the signed plan to bind an authoritative intake-parameter envelope",
        )
        if action == "run":
            command.add_argument("--out", default=".factory/runtime-audits")
        command.add_argument("--json", action="store_true")
    status = runtime_sub.add_parser(
        "status", help="read the latest self-hash-verified local runtime audit receipt"
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")

    senior = sub.add_parser(
        "senior",
        help="independent evidence, real-defect benchmarks, and incremental scheduling",
    )
    senior_sub = senior.add_subparsers(required=True, dest="senior_cmd")
    attest = senior_sub.add_parser(
        "attest", help="verify one DSSE-signed independent execution attestation"
    )
    attest.add_argument("receipt")
    attest.add_argument("--trust-root", required=True)
    attest.add_argument("--candidate-sha256")
    attest.add_argument("--plan-sha256")
    attest.add_argument("--json", action="store_true")
    boundary = senior_sub.add_parser(
        "boundary", help="verify one DSSE-signed runtime-boundary attestation"
    )
    boundary.add_argument("receipt")
    boundary.add_argument("--trust-root", required=True)
    boundary.add_argument("--candidate-sha256")
    boundary.add_argument("--plan-sha256")
    boundary.add_argument("--environment-sha256")
    boundary.add_argument("--json", action="store_true")
    benchmark = senior_sub.add_parser(
        "benchmark", help="evaluate a manifest-bound buggy/fixed defect corpus"
    )
    benchmark.add_argument("manifest")
    benchmark.add_argument("--observations", required=True)
    benchmark.add_argument("--out")
    benchmark.add_argument("--json", action="store_true")
    schedule = senior_sub.add_parser(
        "schedule", help="plan dependency-aware proof routing without executing gates"
    )
    schedule.add_argument("manifest")
    schedule.add_argument("--root", default=".")
    schedule.add_argument("--out")
    schedule.add_argument("--json", action="store_true")
    shadow = senior_sub.add_parser(
        "shadow", help="compare incremental and full plan obligations/findings"
    )
    shadow.add_argument("incremental")
    shadow.add_argument("full")
    shadow.add_argument("--out")
    shadow.add_argument("--json", action="store_true")
    replay = senior_sub.add_parser(
        "replay",
        help="reproduce one contract-bound candidate in a fresh process workspace",
    )
    replay.add_argument("manifest")
    replay.add_argument("--root", default=".")
    replay.add_argument(
        "--execute",
        action="store_true",
        help="run the declared argv; without this flag only validate the replay plan",
    )
    replay.add_argument("--out")
    replay.add_argument("--json", action="store_true")
    repair = senior_sub.add_parser(
        "repair", help="compare the original failure, repair, and negative controls"
    )
    repair.add_argument("manifest")
    repair.add_argument("--root", default=".")
    repair.add_argument(
        "--execute",
        action="store_true",
        help="run all declared replay legs; without this flag only validate the comparison",
    )
    repair.add_argument("--out")
    repair.add_argument("--json", action="store_true")
    reuse = senior_sub.add_parser(
        "reuse", help="explain exact proof reuse or the reason a gate must run"
    )
    reuse.add_argument("manifest")
    reuse.add_argument("--root", default=".")
    reuse.add_argument("--out")
    reuse.add_argument("--json", action="store_true")
    brief = senior_sub.add_parser(
        "brief", help="turn one failed receipt into an evidence-linked failure briefing"
    )
    brief.add_argument("receipt")
    brief.add_argument("--out")
    brief.add_argument("--json", action="store_true")
    live = senior_sub.add_parser(
        "live", help="give change-aware feedback and run only affected checks"
    )
    live.add_argument("manifest")
    live.add_argument("--root", default=".")
    live.add_argument(
        "--changed",
        action="append",
        help="override changed paths; repeat for multiple paths",
    )
    live.add_argument(
        "--execute",
        action="store_true",
        help="run affected checks in fresh temporary workspaces",
    )
    live.add_argument("--out")
    live.add_argument("--json", action="store_true")
    fix = senior_sub.add_parser(
        "fix",
        help="reproduce a failure, verify a repair, and challenge negative controls",
    )
    fix.add_argument("manifest")
    fix.add_argument("--root", default=".")
    fix.add_argument(
        "--execute",
        action="store_true",
        help="run all replay legs in fresh temporary workspaces",
    )
    fix.add_argument("--out")
    fix.add_argument("--json", action="store_true")


def _add_execution_parsers(sub: Any) -> None:
    for action in ("inventory", "scan", "progress", "cancel", "review", "repairs"):
        parser = sub.add_parser(
            action, help=f"{action} explicit isolated deep-audit execution"
        )
        parser.add_argument("--root", default=".")
        parser.add_argument("--json", action="store_true")
        if action in {"progress", "cancel", "review", "repairs"}:
            parser.add_argument("--run-id", required=True)
        if action == "repairs":
            parser.add_argument("--before-run")
        if action == "scan":
            parser.add_argument("--manifest", required=True)
            parser.add_argument("--manifest-sha256", required=True)
            parser.add_argument("--authorization", required=True)
            parser.add_argument("--resume")
            parser.add_argument(
                "--events",
                action="store_true",
                help="emit NDJSON progress and final result",
            )
        if action in {"scan", "review"}:
            parser.add_argument("--trust-root", required=True)
            parser.add_argument("--trust-root-sha256", required=True)
        if action == "review":
            parser.add_argument("--attestation", required=True)
            parser.add_argument("--invocation", required=True)


def _run_execution(args: Any) -> int:
    from .deep_audit import (
        cancel_deep_run,
        deep_run_status,
        execution_repairs,
        scan_deep_audit,
    )
    from .deep_audit_attestation import verify_execution_review
    from .deep_audit_io import inventory_candidate

    root = Path(args.root).resolve()
    try:
        if args.deep_cmd == "inventory":
            result = inventory_candidate(root)
        elif args.deep_cmd == "scan":

            def event(value: dict) -> None:
                print(json.dumps(value, sort_keys=True), flush=True)

            result = scan_deep_audit(
                root,
                Path(args.manifest),
                args.manifest_sha256,
                authorization=Path(args.authorization),
                trust_root=Path(args.trust_root),
                trust_root_sha256=args.trust_root_sha256,
                resume=args.resume,
                emit=event if args.events else None,
            )
            if args.events:
                event({"kind": "final_result", "result": result})
                return 1
        elif args.deep_cmd == "progress":
            result = deep_run_status(root, args.run_id)
        elif args.deep_cmd == "cancel":
            result = cancel_deep_run(root, args.run_id)
        elif args.deep_cmd == "repairs":
            result = execution_repairs(root, args.run_id, before_run=args.before_run)
        else:
            result = verify_execution_review(
                root,
                args.run_id,
                Path(args.attestation),
                Path(args.invocation),
                Path(args.trust_root),
                args.trust_root_sha256,
            )
        return _emit(
            result,
            0
            if result["state"]
            in {
                "COMPLETE",
                "READY_FOR_HUMAN_REVIEW",
                "CANCELLATION_REQUESTED",
                "ALREADY_STOPPED",
            }
            else 1,
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return _emit(
            {
                "state": "INCOMPLETE",
                "code": getattr(exc, "code", "E_DEEP_EXECUTION"),
                "message": str(exc),
                "authority": "none",
                "release_approval": False,
            },
            2,
        )


def _emit(result: dict[str, Any], code: int) -> int:
    print(
        json.dumps(result, indent=2, sort_keys=True),
        file=sys.stderr if code == 2 else sys.stdout,
    )
    return code


def _deep_compare(args: Any, root: Path, compare: Any) -> tuple[dict[str, Any], int]:
    result = compare(
        root,
        args.before,
        args.after,
        before_attestation=args.before_attestation,
        after_attestation=args.after_attestation,
        trust_root_path=Path(args.trust_root) if args.trust_root else None,
        require_attestation=args.require_attestation,
        max_age_seconds=args.max_age_seconds,
    )
    result["action_summary"] = (
        "Compared signed deep-audit observations; no analyzer or repair ran."
    )
    return result, 0 if result["state"] == "approval_required" else 1


def _deep_status(root: Path, status: Any) -> tuple[dict[str, Any], int]:
    result = status(root)
    result["action_summary"] = "Read local deep-audit evidence."
    return result, 0 if result["state"] == "READY_FOR_HUMAN_REVIEW" else 1


def _deep_attestation(args: Any, root: Path, verify: Any) -> tuple[dict[str, Any], int]:
    result = verify(
        root,
        Path(args.attestation),
        Path(args.trust_root),
        Path(args.receipt),
        max_age_seconds=args.max_age_seconds,
    )
    result["action_summary"] = (
        "Verified one offline DSSE deep-audit attestation; no analyzer or repair ran."
    )
    return result, 0 if result["state"] == "VERIFIED" else 1


def _deep_evaluate(args: Any, root: Path, execute: Any) -> tuple[dict[str, Any], int]:
    result = execute(
        Path(args.plan), Path(args.trust_root), args.trust_root_sha256, root
    )
    result["action_summary"] = (
        "Evaluated signed reports and saved a review receipt; no analyzer or repair ran."
    )
    code = 0 if result["receipt"]["decision"] == "READY_FOR_HUMAN_REVIEW" else 1
    return result, code


def _run_deep(args: Any) -> int:
    if args.deep_cmd in {
        "inventory",
        "scan",
        "progress",
        "cancel",
        "review",
        "repairs",
    }:
        return _run_execution(args)
    from .deep_audit import deep_audit_status, execute_deep_audit
    from .deep_audit_attestation import (
        DeepAuditAttestationError,
        verify_deep_audit_attestation,
    )
    from .repair_loop import compare_deep_audit_repairs
    from .runtime_audit_common import RuntimeAuditError

    try:
        root = Path(args.root).resolve()
        if args.deep_cmd == "compare":
            result, code = _deep_compare(args, root, compare_deep_audit_repairs)
        elif args.deep_cmd == "status":
            result, code = _deep_status(root, deep_audit_status)
        elif args.deep_cmd == "attestation":
            result, code = _deep_attestation(args, root, verify_deep_audit_attestation)
        else:
            result, code = _deep_evaluate(args, root, execute_deep_audit)
    except (
        DeepAuditAttestationError,
        RuntimeAuditError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        return _emit(
            {
                "code": getattr(exc, "code", "E_DEEP_AUDIT"),
                "message": str(exc),
                "authority": "none",
            },
            2,
        )
    return _emit(result, code)


def _run_runtime(args: Any) -> int:
    from .runtime_audit import execute_runtime_audit, runtime_audit_status
    from .runtime_audit_common import RuntimeAuditError
    from .runtime_audit_contract import verify_runtime_audit_plan

    root = Path(args.root).resolve()
    try:
        if args.runtime_audit_cmd == "status":
            result = runtime_audit_status(root)
            code = 0 if result["state"] in {"NOT_RUN", "READY_FOR_HUMAN_REVIEW"} else 1
        elif args.runtime_audit_cmd == "inspect":
            result = verify_runtime_audit_plan(
                Path(args.plan),
                Path(args.trust_root),
                args.trust_root_sha256,
                root,
                args.environment_sha256,
                require_intake=args.require_intake,
            )
            result = {
                **result,
                "plan": {
                    "id": result["plan"]["id"],
                    "candidate_sha256": result["plan"]["candidate_sha256"],
                    "lanes": [item["kind"] for item in result["plan"]["lanes"]],
                },
                "action_summary": "Verified the signed audit authority and exact six-lane execution contract; no command ran.",
            }
            code = 0
        else:
            result = execute_runtime_audit(
                Path(args.plan),
                Path(args.trust_root),
                args.trust_root_sha256,
                root,
                args.environment_sha256,
                Path(args.out),
                require_intake=args.require_intake,
            )
            code = 0 if result["receipt"]["decision"] == "READY_FOR_HUMAN_REVIEW" else 1
    except (RuntimeAuditError, OSError, ValueError, KeyError, TypeError) as exc:
        return _emit(
            {
                "schema": "factory.runtime-audit.error.v1",
                "code": getattr(exc, "code", "E_RUNTIME_AUDIT"),
                "message": str(exc),
                "authority": "none",
            },
            2,
        )
    return _emit(result, code)


def _senior_action(
    result: dict[str, Any], summary: str, code: int
) -> tuple[dict[str, Any], int]:
    result["action_summary"] = summary
    return result, code


def _optional_output(args: Any) -> Path | None:
    return Path(args.out) if args.out else None


def _senior_attest(args: Any) -> tuple[dict[str, Any], int]:
    from .independent_execution import verify_signed_execution_attestation

    result = verify_signed_execution_attestation(
        Path(args.receipt),
        Path(args.trust_root),
        candidate_sha256=args.candidate_sha256,
        plan_sha256=args.plan_sha256,
    )
    return _senior_action(
        result,
        "Verified an independently collected execution attestation; no command ran and release authority stayed disabled.",
        0,
    )


def _senior_boundary(args: Any) -> tuple[dict[str, Any], int]:
    from .runtime_attestation import verify_signed_runtime_attestation

    result = verify_signed_runtime_attestation(
        Path(args.receipt),
        Path(args.trust_root),
        candidate_sha256=args.candidate_sha256,
        plan_sha256=args.plan_sha256,
        environment_sha256=args.environment_sha256,
    )
    return _senior_action(
        result,
        "Verified an independently collected runtime boundary; no command ran and release authority stayed disabled.",
        0,
    )


def _senior_benchmark(args: Any) -> tuple[dict[str, Any], int]:
    from .benchmark_lab import evaluate_benchmark, load_benchmark_json

    result = evaluate_benchmark(
        load_benchmark_json(Path(args.manifest)),
        load_benchmark_json(Path(args.observations)),
        out=_optional_output(args),
    )
    code = 0 if result["decision"] == "PASS" else 1
    return _senior_action(
        result,
        "Evaluated supplied buggy/fixed benchmark observations; no replay command ran.",
        code,
    )


def _senior_schedule(args: Any) -> tuple[dict[str, Any], int]:
    from .incremental_scheduler import load_schedule_json, plan_incremental

    result = plan_incremental(
        Path(args.root).resolve(),
        load_schedule_json(Path(args.manifest)),
        out=_optional_output(args),
    )
    code = 1 if result["counts"]["BLOCK"] else 0
    return _senior_action(
        result, "Planned dependency-aware proof routing; no gate command ran.", code
    )


def _senior_shadow(args: Any) -> tuple[dict[str, Any], int]:
    from .incremental_scheduler import compare_shadow, load_schedule_json

    result = compare_shadow(
        load_schedule_json(Path(args.incremental)),
        load_schedule_json(Path(args.full)),
        out=_optional_output(args),
    )
    code = 0 if result["shadow_equivalent"] else 1
    return _senior_action(
        result,
        "Compared supplied incremental and full obligations/findings; no plan ran.",
        code,
    )


def _senior_replay(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import load_assurance_json, run_replay

    result = run_replay(
        Path(args.root).resolve(),
        load_assurance_json(Path(args.manifest)),
        execute=args.execute,
        out=_optional_output(args),
    )
    summary = (
        "Replayed the declared candidate in a fresh process workspace; no release authority was granted."
        if args.execute
        else "Validated a contract-bound replay plan; no candidate command ran."
    )
    code = 0 if result["state"] in {"PLAN_ONLY", "PASS"} else 1
    return _senior_action(result, summary, code)


def _senior_repair(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import compare_repair, load_assurance_json

    result = compare_repair(
        Path(args.root).resolve(),
        load_assurance_json(Path(args.manifest)),
        execute=args.execute,
        out=_optional_output(args),
    )
    summary = (
        "Compared original, repaired, and negative-control executions; release authority stayed disabled."
        if args.execute
        else "Validated a repair comparison; no candidate command ran."
    )
    code = 0 if result["state"] in {"PLAN_ONLY", "PASS"} else 1
    return _senior_action(result, summary, code)


def _senior_live(args: Any) -> tuple[dict[str, Any], int]:
    from .live_feedback import load_live_json, run_live_feedback

    result = run_live_feedback(
        Path(args.root).resolve(),
        load_live_json(Path(args.manifest)),
        execute=args.execute,
        changed_paths=args.changed,
        out=_optional_output(args),
    )
    summary = (
        "Ran affected checks in fresh temporary workspaces; no source or release action ran."
        if args.execute
        else "Planned affected checks and next feedback actions; no command ran."
    )
    failed = result["counts"]["FAIL"] or result["counts"]["BLOCKED"]
    return _senior_action(result, summary, 1 if failed else 0)


def _senior_fix(args: Any) -> tuple[dict[str, Any], int]:
    from .fix_workflow import load_fix_json, run_fix_workflow

    result = run_fix_workflow(
        Path(args.root).resolve(),
        load_fix_json(Path(args.manifest)),
        execute=args.execute,
        out=_optional_output(args),
    )
    summary = (
        "Reproduced the failure and compared the repair with negative controls; release authority stayed disabled."
        if args.execute
        else "Validated the reproduce-and-repair workflow; no candidate command ran."
    )
    code = 0 if result["state"] in {"PLAN_ONLY", "PASS"} else 1
    return _senior_action(result, summary, code)


def _senior_reuse(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import explain_evidence_reuse, load_assurance_json

    result = explain_evidence_reuse(
        Path(args.root).resolve(),
        load_assurance_json(Path(args.manifest)),
        out=_optional_output(args),
    )
    code = 1 if result["counts"]["BLOCK"] else 0
    return _senior_action(
        result,
        "Explained exact evidence reuse and fail-closed reruns; no gate command ran.",
        code,
    )


def _senior_brief(args: Any) -> tuple[dict[str, Any], int]:
    from .senior_assurance import failure_brief, load_assurance_json

    receipt_path = Path(args.receipt)
    receipt = load_assurance_json(receipt_path)
    result = failure_brief(
        receipt,
        receipt_path=receipt_path.as_posix(),
        receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        out=_optional_output(args),
    )
    return _senior_action(
        result,
        "Built an evidence-linked failure briefing; no repair or release action ran.",
        0,
    )


def _senior_command(args: Any) -> tuple[dict[str, Any], int]:
    handlers = {
        "attest": _senior_attest,
        "boundary": _senior_boundary,
        "benchmark": _senior_benchmark,
        "schedule": _senior_schedule,
        "shadow": _senior_shadow,
        "replay": _senior_replay,
        "repair": _senior_repair,
        "live": _senior_live,
        "fix": _senior_fix,
        "reuse": _senior_reuse,
        "brief": _senior_brief,
    }
    return handlers.get(args.senior_cmd, _senior_brief)(args)


def _run_senior(args: Any) -> int:
    from .benchmark_lab import BenchmarkError
    from .fix_workflow import FixWorkflowError
    from .incremental_scheduler import SchedulerError
    from .independent_execution import ExecutionAttestationError
    from .live_feedback import LiveFeedbackError
    from .senior_assurance import SeniorAssuranceError

    try:
        result, code = _senior_command(args)
    except (
        SeniorAssuranceError,
        FixWorkflowError,
        LiveFeedbackError,
        ExecutionAttestationError,
        BenchmarkError,
        SchedulerError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        return _emit(
            {
                "schema": "factory.senior.error.v1",
                "code": getattr(exc, "code", "E_SENIOR_INPUT"),
                "message": str(exc),
                "authority": "none",
                "release_approval": False,
            },
            2,
        )
    return _emit(result, code)


def run(args: Any) -> int:
    """Dispatch deep, runtime, and senior audit commands lazily."""
    if args.cmd == "deep-audit":
        return _run_deep(args)
    if args.cmd == "runtime-audit":
        return _run_runtime(args)
    return _run_senior(args)

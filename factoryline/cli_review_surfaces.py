"""CLI boundary for share cards, adoption, counterexamples, guardrails, and resilience."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register bounded review and evidence-surface command families."""
    proof_card = sub.add_parser(
        "proof-card",
        help="create a privacy-safe share card from one verified local E2E receipt",
    )
    proof_card.add_argument(
        "receipt", help="workspace-contained factory.e2e_proof_receipt.v1 JSON path"
    )
    proof_card.add_argument("--root", default=".")
    proof_card.add_argument(
        "--out-dir",
        default=".factory/share",
        help="workspace-contained Proof Card output directory",
    )
    proof_card.add_argument("--json", action="store_true")

    adoption = sub.add_parser(
        "adoption",
        help="record and inspect local opt-in activation milestones without central telemetry",
    )
    adoption_sub = adoption.add_subparsers(required=True, dest="adoption_cmd")
    adoption_status = adoption_sub.add_parser(
        "status", help="read local aggregate activation milestones"
    )
    adoption_status.add_argument("--root", default=".")
    adoption_status.add_argument("--json", action="store_true")
    adoption_record = adoption_sub.add_parser(
        "record", help="record one explicit local activation milestone"
    )
    adoption_record.add_argument(
        "milestone", choices=["first_proof_completed", "seven_day_return"]
    )
    adoption_record.add_argument("--root", default=".")
    adoption_record.add_argument("--evidence-sha256")
    adoption_record.add_argument("--json", action="store_true")
    adoption_export = adoption_sub.add_parser(
        "export", help="write an aggregate, identity-free activation status receipt"
    )
    adoption_export.add_argument("--root", default=".")
    adoption_export.add_argument("--out", required=True)
    adoption_export.add_argument("--json", action="store_true")

    counterexample = sub.add_parser(
        "counterexample",
        help="compile and verify deterministic negative-proof obligations without execution",
    )
    counterexample_sub = counterexample.add_subparsers(
        required=True, dest="counterexample_cmd"
    )
    counterexample_plan = counterexample_sub.add_parser(
        "plan",
        help="compile one hash-sealed negative-proof plan from bounded requirements",
    )
    counterexample_plan.add_argument(
        "source", help="workspace-contained factory.counterexample-source.v1 JSON path"
    )
    counterexample_plan.add_argument("--root", default=".")
    counterexample_plan.add_argument(
        "--out", required=True, help="explicit plan output path"
    )
    counterexample_plan.add_argument("--json", action="store_true")
    counterexample_verify = counterexample_sub.add_parser(
        "verify",
        help="fail closed for tampered, stale, or incomplete negative-proof plans",
    )
    counterexample_verify.add_argument(
        "plan", help="workspace-contained factory.counterexample-plan.v1 JSON path"
    )
    counterexample_verify.add_argument("--root", default=".")
    counterexample_verify.add_argument("--json", action="store_true")

    guardrail = sub.add_parser(
        "guardrail",
        help="evaluate promoted continuity metadata as redacted local guardrails",
    )
    guardrail_sub = guardrail.add_subparsers(required=True, dest="guardrail_cmd")
    guardrail_evaluate = guardrail_sub.add_parser(
        "evaluate",
        help="read promoted exact-scope metadata without retrieving memory content",
    )
    guardrail_evaluate.add_argument(
        "manifest", help="factory.guardrail-manifest.v1 JSON path"
    )
    guardrail_evaluate.add_argument(
        "--db", required=True, help="existing local continuity database"
    )
    guardrail_evaluate.add_argument("--tenant", required=True)
    guardrail_evaluate.add_argument("--subject", required=True)
    guardrail_evaluate.add_argument(
        "--roles",
        default="reader",
        help="comma-separated local roles; values are not authenticated identity",
    )
    guardrail_evaluate.add_argument(
        "--purposes", required=True, help="comma-separated exact purpose references"
    )
    guardrail_evaluate.add_argument(
        "--changed",
        action="append",
        required=True,
        help="workspace-relative changed path; repeat as needed",
    )
    guardrail_evaluate.add_argument("--json", action="store_true")
    guardrail_verify = guardrail_sub.add_parser(
        "verify", help="verify an evaluation hash and no-content redaction boundary"
    )
    guardrail_verify.add_argument(
        "evaluation", help="factory.guardrail-evaluation.v1 JSON path"
    )
    guardrail_verify.add_argument("--json", action="store_true")

    resilience = sub.add_parser(
        "resilience",
        help="derive bounded temporal fault schedules from sealed graph lineage without execution",
    )
    resilience_sub = resilience.add_subparsers(required=True, dest="resilience_cmd")
    resilience_plan = resilience_sub.add_parser(
        "plan", help="compile read-only stale, replay, and concurrency fault schedules"
    )
    resilience_plan.add_argument(
        "lineage", help="workspace-contained factory.graph-lineage.v1 JSON path"
    )
    resilience_plan.add_argument("--root", default=".")
    resilience_plan.add_argument(
        "--out", required=True, help="explicit plan output path"
    )
    resilience_plan.add_argument("--json", action="store_true")
    resilience_verify = resilience_sub.add_parser(
        "verify",
        help="fail closed for tampered, stale, or incomplete temporal schedules",
    )
    resilience_verify.add_argument(
        "plan", help="workspace-contained factory.temporal-resilience-plan.v1 JSON path"
    )
    resilience_verify.add_argument("--root", default=".")
    resilience_verify.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one bounded review-surface command."""
    if args.cmd == "proof-card":
        from .adoption import (
            AdoptionError,
            proof_card_from_receipt,
            record_adoption_event,
        )

        workspace = Path(args.root).resolve()
        try:
            result = proof_card_from_receipt(
                workspace, Path(args.receipt), Path(args.out_dir)
            )
            record_adoption_event(
                workspace,
                "proof_card_saved",
                evidence_sha256=result["card"]["card_sha256"],
            )
        except (AdoptionError, OSError) as exc:
            code = getattr(exc, "code", "E_PROOF_CARD_FAILED")
            error = {
                "schema": "factory.proof-card.error.v1",
                "code": code,
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if args.json
                else f"proof card failed: {code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("factory proof-card")
            print("=" * 44)
            print(f"outcome  : {result['card']['outcome']}")
            print(f"card     : {result['paths']['svg']}")
            print(
                "privacy  : no commands, paths, repository name, prompts, logs, or user identity"
            )
        return 0

    if args.cmd == "adoption":
        from .adoption import (
            AdoptionError,
            adoption_status,
            export_adoption_status,
            record_adoption_event,
        )

        workspace = Path(args.root).resolve()
        try:
            if args.adoption_cmd == "record":
                result = record_adoption_event(
                    workspace, args.milestone, evidence_sha256=args.evidence_sha256
                )
            elif args.adoption_cmd == "export":
                result = export_adoption_status(workspace, Path(args.out))
            else:
                result = adoption_status(workspace)
        except (AdoptionError, OSError) as exc:
            code = getattr(exc, "code", "E_ADOPTION_FAILED")
            error = {
                "schema": "factory.adoption.error.v1",
                "code": code,
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if args.json
                else f"adoption failed: {code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("factory adoption")
            print("=" * 44)
            if args.adoption_cmd == "record":
                print(f"milestone: {result['event']['milestone']}")
                print(f"receipt  : {result['path']}")
            else:
                status = result.get("status", result)
                print(f"events   : {status['events']}")
                print(f"first    : {status['milestones']['first_proof_completed']}")
                print(f"returns  : {status['milestones']['seven_day_return']}")
                print(
                    "boundary : local opt-in counts only; not users, conversion, or attribution"
                )
        return 0

    if args.cmd == "counterexample":
        from .counterexample import (
            CounterexampleError,
            compile_counterexample_plan,
            verify_counterexample_plan,
            write_counterexample_plan,
        )

        workspace = Path(args.root).resolve()
        try:
            if args.counterexample_cmd == "plan":
                source = Path(args.source)
                if not source.is_absolute():
                    source = workspace / source
                out = Path(args.out)
                if not out.is_absolute():
                    out = workspace / out
                try:
                    out.resolve().relative_to(workspace)
                except ValueError as exc:
                    raise CounterexampleError(
                        "COUNTEREXAMPLE_PATH_INVALID",
                        "plan output must stay inside the workspace",
                    ) from exc
                payload = compile_counterexample_plan(workspace, source)
                path = write_counterexample_plan(payload, out)
                payload = {**payload, "path": str(path.resolve())}
            else:
                plan = Path(args.plan)
                if not plan.is_absolute():
                    plan = workspace / plan
                payload = verify_counterexample_plan(workspace, plan)
        except CounterexampleError as exc:
            error = {
                "schema": "factory.counterexample.error.v1",
                "code": exc.code,
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if args.json
                else f"counterexample failed: {exc.code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory counterexample")
            print("=" * 44)
            print(f"marker    : {payload['marker']}")
            print(
                f"cases     : {payload.get('facts', {}).get('case_count', payload.get('case_count', 0))}"
            )
            print(
                "authority : negative-proof planning only; execution, source writes, repair, approval, and publication are locked"
            )
        return 0 if args.counterexample_cmd == "plan" or payload["ok"] else 1

    if args.cmd == "guardrail":
        from .continuity import (
            ContinuityError,
            principal_from_args as continuity_principal_from_args,
        )
        from .guardrails import (
            GuardrailError,
            evaluate_guardrails,
            verify_guardrail_evaluation,
        )

        try:
            if args.guardrail_cmd == "evaluate":
                principal = continuity_principal_from_args(
                    args.subject,
                    args.tenant,
                    args.roles.split(","),
                    args.purposes.split(","),
                )
                payload = evaluate_guardrails(
                    Path(args.manifest),
                    Path(args.db),
                    principal,
                    changed_paths=args.changed,
                )
            else:
                payload = verify_guardrail_evaluation(
                    json.loads(Path(args.evaluation).read_text(encoding="utf-8"))
                )
        except (GuardrailError, ContinuityError, OSError, json.JSONDecodeError) as exc:
            error = {
                "schema": "factory.guardrail.error.v1",
                "code": getattr(exc, "code", "GUARDRAIL_INPUT_INVALID"),
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if args.json
                else f"guardrail failed: {error['code']}: {exc}",
                file=sys.stderr,
            )
            return 2
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory guardrail")
            print("=" * 44)
            print(f"marker    : {payload['marker']}")
            print(f"active    : {payload.get('facts', {}).get('active_count', 0)}")
            print(f"withheld  : {payload.get('facts', {}).get('withheld_count', 0)}")
            print(
                "boundary  : only redacted promoted metadata is evaluated; memory content, edits, execution, and promotion remain unavailable"
            )
        return 0

    from .resilience import (
        ResilienceError,
        compile_temporal_resilience_plan,
        verify_temporal_resilience_plan,
        write_temporal_resilience_plan,
    )

    workspace = Path(args.root).resolve()
    try:
        if args.resilience_cmd == "plan":
            lineage = Path(args.lineage)
            if not lineage.is_absolute():
                lineage = workspace / lineage
            out = Path(args.out)
            if not out.is_absolute():
                out = workspace / out
            try:
                out.resolve().relative_to(workspace)
            except ValueError as exc:
                raise ResilienceError(
                    "RESILIENCE_PATH_INVALID",
                    "plan output must stay inside the workspace",
                ) from exc
            payload = compile_temporal_resilience_plan(workspace, lineage)
            path = write_temporal_resilience_plan(payload, out)
            payload = {**payload, "path": str(path.resolve())}
        else:
            plan = Path(args.plan)
            if not plan.is_absolute():
                plan = workspace / plan
            payload = verify_temporal_resilience_plan(workspace, plan)
    except ResilienceError as exc:
        error = {
            "schema": "factory.temporal-resilience.error.v1",
            "code": exc.code,
            "message": str(exc),
        }
        print(
            json.dumps(error, indent=2, sort_keys=True)
            if args.json
            else f"resilience failed: {exc.code}: {exc}",
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("factory temporal resilience")
        print("=" * 44)
        print(f"marker    : {payload['marker']}")
        print(
            f"schedules : {payload.get('facts', {}).get('schedule_count', payload.get('schedule_count', 0))}"
        )
        print(
            "authority : schedule derivation only; graph invocation, replay, checkpoint mutation, repair, and approval are locked"
        )
    return 0 if args.resilience_cmd == "plan" or payload["ok"] else 1

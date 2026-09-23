"""Bounded, lazily loaded proof-worklog and ProofSearch CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "proofsearch"
OWNER = "proof-evidence-maintainers"


def add_parser(sub: Any) -> None:
    """Register proof-search and worklog commands without loading engines."""
    worklog = sub.add_parser(
        "worklog",
        help="draft a local review-required update from one sealed Oracle Contract; never posts externally",
    )
    worklog_sub = worklog.add_subparsers(required=True, dest="worklog_cmd")
    draft = worklog_sub.add_parser(
        "draft", help="write one immutable local proof worklog draft"
    )
    draft.add_argument("--root", default=".")
    draft.add_argument(
        "--contract",
        required=True,
        help="workspace-relative current sealed Oracle Contract",
    )
    draft.add_argument("--out", help="workspace-relative immutable local draft path")
    draft.add_argument("--json", action="store_true")
    verify = worklog_sub.add_parser(
        "verify", help="verify one local proof worklog draft and current Oracle binding"
    )
    verify.add_argument("draft")
    verify.add_argument("--root", default=".")
    verify.add_argument("--json", action="store_true")
    status = worklog_sub.add_parser(
        "status", help="read bounded local proof worklog facts without posting anything"
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")

    proof = sub.add_parser(
        "proofsearch", help="compare hash-bound repair candidates without applying them"
    )
    proof_sub = proof.add_subparsers(required=True, dest="proofsearch_cmd")
    plan = proof_sub.add_parser(
        "plan", help="seal one graph divergence and its exact proof-impact slice"
    )
    plan.add_argument("--root", default=".")
    plan.add_argument("--baseline", required=True)
    plan.add_argument("--candidate", required=True)
    plan.add_argument("--changed", action="append", required=True)
    plan.add_argument("--out", required=True)
    plan.add_argument("--json", action="store_true")
    evaluate = proof_sub.add_parser(
        "evaluate", help="verify, reject, and rank supplied candidate evidence"
    )
    evaluate.add_argument("request")
    evaluate.add_argument("--root", default=".")
    evaluate.add_argument("--out", required=True)
    evaluate.add_argument("--json", action="store_true")
    verify = proof_sub.add_parser(
        "verify", help="verify one sealed ProofSearch evaluation and its evidence"
    )
    verify.add_argument("evaluation")
    verify.add_argument("--root", default=".")
    verify.add_argument("--json", action="store_true")
    frontier = proof_sub.add_parser(
        "frontier", help="rank or verify the next evidence experiment"
    )
    frontier_sub = frontier.add_subparsers(required=True, dest="frontier_cmd")
    frontier_plan = frontier_sub.add_parser(
        "plan", help="rank the next evidence experiment without executing it"
    )
    frontier_plan.add_argument("request")
    frontier_plan.add_argument("--root", default=".")
    frontier_plan.add_argument("--out", required=True)
    frontier_plan.add_argument("--json", action="store_true")
    frontier_verify = frontier_sub.add_parser(
        "verify", help="verify one sealed evidence frontier"
    )
    frontier_verify.add_argument("frontier")
    frontier_verify.add_argument("--root", default=".")
    frontier_verify.add_argument("--json", action="store_true")


def _run_worklog(args: Any) -> int:
    from .proof_worklog import (
        ProofWorklogError,
        create_proof_worklog,
        proof_worklog_projection,
        verify_proof_worklog,
    )

    root = Path(args.root).resolve()
    try:
        if args.worklog_cmd == "draft":
            result = create_proof_worklog(
                root, Path(args.contract), Path(args.out) if args.out else None
            )
        elif args.worklog_cmd == "verify":
            result = verify_proof_worklog(root, Path(args.draft))
        else:
            result = proof_worklog_projection(root)
        code = (
            0
            if result.get("ok", True) and int(result.get("invalid_count", 0)) == 0
            else 1
        )
    except (
        ProofWorklogError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.proof-worklog.error.v1",
            "marker": "PROOF_WORKLOG_INPUT_REJECTED",
            "code": getattr(exc, "code", "E_PROOF_WORKLOG_SCHEMA"),
            "message": str(exc),
        }
        code = 2
    print(
        json.dumps(result, indent=2, sort_keys=True),
        file=sys.stderr if code else sys.stdout,
    )
    return code


def _run_proofsearch(args: Any) -> int:
    from .evidence_frontier import (
        EvidenceFrontierError,
        plan_evidence_frontier,
        verify_evidence_frontier,
    )
    from .proofsearch import (
        ProofSearchError,
        create_proofsearch_plan,
        evaluate_proofsearch,
        verify_proofsearch_evaluation,
    )

    try:
        if args.proofsearch_cmd == "plan":
            payload = create_proofsearch_plan(
                Path(args.root),
                Path(args.baseline),
                Path(args.candidate),
                args.changed,
                Path(args.out),
            )
        elif args.proofsearch_cmd == "evaluate":
            payload = evaluate_proofsearch(
                Path(args.root), Path(args.request), Path(args.out)
            )
        elif args.proofsearch_cmd == "frontier" and args.frontier_cmd == "plan":
            payload = plan_evidence_frontier(
                Path(args.root), Path(args.request), Path(args.out)
            )
        elif args.proofsearch_cmd == "frontier":
            payload = verify_evidence_frontier(Path(args.root), Path(args.frontier))
        else:
            payload = verify_proofsearch_evaluation(
                Path(args.root), Path(args.evaluation)
            )
    except (ProofSearchError, EvidenceFrontierError) as exc:
        schema = (
            "factory.evidence-frontier.error.v1"
            if isinstance(exc, EvidenceFrontierError)
            else "factory.proofsearch.error.v1"
        )
        print(
            json.dumps(
                {"schema": schema, "code": exc.code, "message": str(exc)}, indent=2
            ),
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("factory ProofSearch (review only)")
        print("=" * 44)
        print(f"marker : {payload['marker']}")
        if "winner" in payload:
            print(f"winner : {payload['winner'] or 'none'}")
        if "next_experiment" in payload:
            print(f"next evidence : {payload['next_experiment'] or 'none'}")
        if "path" in payload:
            print(f"receipt: {payload['path']}")
        print("apply  : locked")
    if args.proofsearch_cmd == "verify" or (
        args.proofsearch_cmd == "frontier" and args.frontier_cmd == "verify"
    ):
        return 0 if payload["valid"] else 1
    return 0


def run(args: Any) -> int:
    """Dispatch proof evidence commands lazily."""
    return _run_worklog(args) if args.cmd == "worklog" else _run_proofsearch(args)

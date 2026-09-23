"""CLI registration and dispatch for the evidence-chain review commands.

The public ``factory`` entry point remains stable while change review,
continuous proof operations, and proof-review workflow commands are loaded
only when this bounded command family is registered or executed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register change, proof-operations, and proof-review CLI commands."""
    change = sub.add_parser(
        "change", help="prepare a deterministic, analysis-only diff-to-proof review"
    )
    change_sub = change.add_subparsers(required=True, dest="change_cmd")
    change_review = change_sub.add_parser(
        "review", help="join diff impact, coverage gaps, and plan-only reruns"
    )
    change_review.add_argument("--root", default=".")
    change_review.add_argument("--base", default="main")
    change_review.add_argument(
        "--audit-policy",
        help="workspace-relative code-audit policy; defaults to .factory/review-audits.json when present",
    )
    change_review.add_argument(
        "--changed",
        action="append",
        default=[],
        help="workspace-relative changed path; repeat as needed",
    )
    change_review.add_argument(
        "--out-dir",
        help="explicit local directory for JSON, Markdown, and Mermaid review artifacts",
    )
    change_review.add_argument("--json", action="store_true")

    proof_ops = sub.add_parser(
        "proof-ops",
        help="join intent, change, observed-session, and repair evidence into one local record",
    )
    proof_ops_sub = proof_ops.add_subparsers(required=True, dest="proof_ops_cmd")
    proof_ops_assess = proof_ops_sub.add_parser(
        "assess",
        help="write one fail-closed Continuous Proof Operations record without execution",
    )
    proof_ops_assess.add_argument("--root", default=".")
    proof_ops_assess.add_argument("--workflow-id", required=True)
    proof_ops_assess.add_argument(
        "--intent",
        required=True,
        help="workspace-contained human-authored intent artifact",
    )
    proof_ops_assess.add_argument(
        "--changed",
        action="append",
        required=True,
        help="exact workspace-relative changed path; repeat as needed",
    )
    proof_ops_assess.add_argument(
        "--session", help="optional workspace-contained observed-session receipt"
    )
    proof_ops_assess.add_argument(
        "--session-phase", choices=["change", "post_repair"], default="change"
    )
    proof_ops_assess.add_argument(
        "--repair-scope",
        help="optional workspace-contained sealed repair scope; requires --repair-patch",
    )
    proof_ops_assess.add_argument(
        "--repair-patch",
        help="optional workspace-contained textual patch; requires --repair-scope",
    )
    proof_ops_assess.add_argument(
        "--prior-receipt",
        help="prior scoped-repair record for a post-repair verification cycle",
    )
    proof_ops_assess.add_argument(
        "--out-dir", help="optional workspace-contained artifact directory"
    )
    proof_ops_assess.add_argument("--json", action="store_true")
    proof_ops_verify = proof_ops_sub.add_parser(
        "verify",
        help="verify one Continuous Proof Operations receipt and all bound bytes",
    )
    proof_ops_verify.add_argument("receipt")
    proof_ops_verify.add_argument("--root", default=".")
    proof_ops_verify.add_argument("--json", action="store_true")
    proof_ops_history = proof_ops_sub.add_parser(
        "history",
        help="aggregate verified local proof routes without user or savings inference",
    )
    proof_ops_history.add_argument("--root", default=".")
    proof_ops_history.add_argument("--json", action="store_true")

    proof_review = sub.add_parser(
        "proof-review",
        help="seal intent, review agent work, and route one human-controlled proof workflow",
    )
    proof_review_sub = proof_review.add_subparsers(
        required=True, dest="proof_review_cmd"
    )
    proof_review_contract = proof_review_sub.add_parser(
        "contract", help="seal one complete, named-human-confirmed intent contract"
    )
    proof_review_contract.add_argument("--root", default=".")
    proof_review_contract.add_argument("--id", required=True)
    proof_review_contract.add_argument("--draft", required=True)
    proof_review_contract.add_argument("--confirmed-by", required=True)
    proof_review_contract.add_argument("--json", action="store_true")
    proof_review_quick = proof_review_sub.add_parser(
        "quick", help="join intent and current evidence into a four-route review"
    )
    proof_review_quick.add_argument("--root", default=".")
    proof_review_quick.add_argument("--id", required=True)
    proof_review_quick.add_argument("--contract", required=True)
    proof_review_quick.add_argument("--changed", action="append", required=True)
    proof_review_quick.add_argument("--session")
    proof_review_quick.add_argument("--trajectory")
    proof_review_quick.add_argument("--repair-scope")
    proof_review_quick.add_argument("--repair-patch")
    proof_review_quick.add_argument("--prior-receipt")
    proof_review_quick.add_argument(
        "--session-phase", choices=["change", "post_repair"], default="change"
    )
    proof_review_quick.add_argument(
        "--intake-parameters",
        help="optional authoritative intake-parameter envelope bound to changed paths",
    )
    proof_review_quick.add_argument(
        "--require-intake",
        action="store_true",
        help="require an authoritative intake-parameter envelope",
    )
    proof_review_quick.add_argument("--json", action="store_true")
    proof_review_verify = proof_review_sub.add_parser(
        "verify", help="verify a proof review and every bound receipt"
    )
    proof_review_verify.add_argument("review")
    proof_review_verify.add_argument("--root", default=".")
    proof_review_verify.add_argument("--json", action="store_true")
    proof_review_hooks = proof_review_sub.add_parser(
        "hooks",
        help="write five reviewable agent-hook templates without installing them",
    )
    proof_review_hooks.add_argument("--root", default=".")
    proof_review_hooks.add_argument("--json", action="store_true")
    proof_review_trajectory = proof_review_sub.add_parser(
        "trajectory", help="seal and independently audit a bounded agent trajectory"
    )
    proof_review_trajectory.add_argument("--root", default=".")
    proof_review_trajectory.add_argument("--id", required=True)
    proof_review_trajectory.add_argument("--trace", required=True)
    proof_review_trajectory.add_argument("--policy", required=True)
    proof_review_trajectory.add_argument("--json", action="store_true")
    proof_review_trajectory_verify = proof_review_sub.add_parser(
        "trajectory-verify", help="verify a trajectory proof and its bound inputs"
    )
    proof_review_trajectory_verify.add_argument("trajectory")
    proof_review_trajectory_verify.add_argument("--root", default=".")
    proof_review_trajectory_verify.add_argument("--json", action="store_true")
    proof_review_learn = proof_review_sub.add_parser(
        "learn",
        help="promote one confirmed causal failure into an immutable regression capsule",
    )
    proof_review_learn.add_argument("--root", default=".")
    proof_review_learn.add_argument("--id", required=True)
    proof_review_learn.add_argument("--review", required=True)
    proof_review_learn.add_argument("--confirmed-by", required=True)
    proof_review_learn.add_argument("--title", required=True)
    proof_review_learn.add_argument("--json", action="store_true")
    proof_review_inbox = proof_review_sub.add_parser(
        "inbox", help="read the bounded team proof inbox"
    )
    proof_review_inbox.add_argument("--root", default=".")
    proof_review_inbox.add_argument("--json", action="store_true")
    proof_review_card = proof_review_sub.add_parser(
        "card", help="export an offline-verifiable public-safe proof card"
    )
    proof_review_card.add_argument("--root", default=".")
    proof_review_card.add_argument("--id", required=True)
    proof_review_card.add_argument("--review", required=True)
    proof_review_card.add_argument("--json", action="store_true")
    proof_review_card_verify = proof_review_sub.add_parser(
        "card-verify", help="verify a proof card offline"
    )
    proof_review_card_verify.add_argument("card")
    proof_review_card_verify.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch one evidence-chain command without performing external actions."""
    if a.cmd == "change":
        from .change_review import (
            ChangeReviewError,
            review_change,
            write_review_artifacts,
        )

        try:
            review = review_change(
                Path(a.root),
                base=a.base,
                changed=a.changed or None,
                audit_policy=a.audit_policy,
            )
            if a.out_dir:
                review["artifacts"] = write_review_artifacts(review, Path(a.out_dir))
        except ChangeReviewError as exc:
            payload = {
                "schema": "factory.change_review.error.v1",
                "marker": "DIFF_TO_PROOF_PATH_REJECTED"
                if exc.code in {"CHANGED_PATH_INVALID", "CHANGED_PATH_LIMIT"}
                else "DIFF_TO_PROOF_INPUT_UNAVAILABLE",
                "code": exc.code,
                "message": str(exc),
            }
            print(
                json.dumps(payload, indent=2)
                if a.json
                else f"change review failed: {exc.code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(review, indent=2, sort_keys=True))
        else:
            print("factory change review (analysis only)")
            print("=" * 44)
            print(f"changed paths: {len(review['changed_paths'])}")
            print(f"next action : {review['next_action']['action']}")
            print(f"findings    : {len(review['findings'])}")
            if review.get("artifacts"):
                print(f"packet      : {review['artifacts']['paths']['markdown']}")
            print(
                "authority   : no execution, merge, publication, deployment, or credential access"
            )
        return 0

    if a.cmd == "proof-ops":
        from .continuous_proof import (
            ContinuousProofError,
            assess_continuous_proof,
            continuous_proof_history,
            verify_continuous_proof,
        )

        try:
            if a.proof_ops_cmd == "assess":
                payload = assess_continuous_proof(
                    Path(a.root),
                    a.workflow_id,
                    Path(a.intent),
                    a.changed,
                    session_path=Path(a.session) if a.session else None,
                    session_phase=a.session_phase,
                    repair_scope_path=Path(a.repair_scope) if a.repair_scope else None,
                    repair_patch_path=Path(a.repair_patch) if a.repair_patch else None,
                    prior_receipt_path=Path(a.prior_receipt)
                    if a.prior_receipt
                    else None,
                    out_dir=Path(a.out_dir) if a.out_dir else None,
                )
            elif a.proof_ops_cmd == "verify":
                payload = verify_continuous_proof(Path(a.root), Path(a.receipt))
            else:
                payload = continuous_proof_history(Path(a.root))
        except (ContinuousProofError, OSError) as exc:
            error = {
                "schema": "factory.continuous-proof.error.v1",
                "marker": "CONTINUOUS_PROOF_REFUSED",
                "code": getattr(exc, "code", "CONTINUOUS_PROOF_INPUT_UNAVAILABLE"),
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if a.json
                else f"proof-ops {a.proof_ops_cmd} refused: {error['code']}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif a.proof_ops_cmd == "assess":
            print("factory continuous proof operations")
            print("=" * 44)
            print(f"route       : {payload['route']}")
            print(f"next action : {payload['next_action']['action']}")
            print(f"receipt     : {payload['artifacts']['json']}")
            print(
                "authority   : no execution, patch apply, approval, merge, publication, deployment, credential, connector, or network action"
            )
        elif a.proof_ops_cmd == "verify":
            print(f"{payload['marker']} {payload.get('path', '')}")
        else:
            print("factory continuous proof history (read-only)")
            print("=" * 44)
            print(f"verified records : {payload['verified_record_count']}")
            print(f"invalid or stale : {payload['invalid_or_stale_count']}")
            print(
                f"latest route     : {(payload['latest'] or {}).get('route', 'none')}"
            )
            print(
                "claim boundary   : records are not unique users; no savings are inferred"
            )
        if a.proof_ops_cmd == "verify" and not payload["ok"]:
            return 1
        return 0

    if a.cmd == "proof-review":
        from .proof_review_workflow import (
            ProofReviewError,
            create_intent_contract,
            create_proof_card,
            create_quick_review,
            install_hook_pack,
            promote_regression,
            prove_trajectory,
            team_proof_inbox,
            verify_proof_card,
            verify_quick_review,
            verify_trajectory,
        )

        root = Path(getattr(a, "root", "."))
        try:
            if a.proof_review_cmd == "contract":
                payload = create_intent_contract(
                    root, a.id, Path(a.draft), a.confirmed_by
                )
            elif a.proof_review_cmd == "quick":
                payload = create_quick_review(
                    root,
                    a.id,
                    Path(a.contract),
                    a.changed,
                    session_path=Path(a.session) if a.session else None,
                    trajectory_path=Path(a.trajectory) if a.trajectory else None,
                    repair_scope_path=Path(a.repair_scope) if a.repair_scope else None,
                    repair_patch_path=Path(a.repair_patch) if a.repair_patch else None,
                    prior_receipt_path=Path(a.prior_receipt)
                    if a.prior_receipt
                    else None,
                    session_phase=a.session_phase,
                    intake_parameters_path=Path(a.intake_parameters)
                    if a.intake_parameters
                    else None,
                    require_intake=a.require_intake,
                )
            elif a.proof_review_cmd == "verify":
                payload = verify_quick_review(root, Path(a.review))
            elif a.proof_review_cmd == "hooks":
                payload = install_hook_pack(root)
            elif a.proof_review_cmd == "trajectory":
                payload = prove_trajectory(root, Path(a.trace), Path(a.policy), a.id)
            elif a.proof_review_cmd == "trajectory-verify":
                payload = verify_trajectory(root, Path(a.trajectory))
            elif a.proof_review_cmd == "learn":
                payload = promote_regression(
                    root, Path(a.review), a.id, a.confirmed_by, a.title
                )
            elif a.proof_review_cmd == "inbox":
                payload = team_proof_inbox(root)
            elif a.proof_review_cmd == "card":
                payload = create_proof_card(root, Path(a.review), a.id)
            else:
                payload = verify_proof_card(Path(a.card))
        except (ProofReviewError, OSError) as exc:
            error = {
                "schema": "factory.proof-review.error.v1",
                "marker": "PROOF_REVIEW_REFUSED",
                "code": getattr(exc, "code", "PROOF_REVIEW_INPUT_UNAVAILABLE"),
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if a.json
                else f"proof-review {a.proof_review_cmd} refused: {error['code']}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"{payload.get('marker', 'PROOF_REVIEW_OK')}")
            if payload.get("route"):
                print(f"route       : {payload['route']}")
            if payload.get("artifact"):
                print(f"artifact    : {payload['artifact']}")
            print(
                "authority   : human review remains required; no execution, approval, merge, publication, deployment, credential, connector, or network action"
            )
        if a.proof_review_cmd in {
            "verify",
            "trajectory-verify",
            "card-verify",
        } and not payload.get("ok"):
            return 1
        return 0

    raise ValueError(f"unsupported evidence-chain command: {a.cmd}")

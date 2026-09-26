"""Lazy CLI boundary for local GitHub proof and assurance payloads."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register advisory GitHub proof-review and assurance-dossier commands."""
    github = sub.add_parser(
        "github",
        help="prepare an evidence-bound, advisory GitHub pull-request review without a network call",
    )
    github_sub = github.add_subparsers(required=True, dest="github_cmd")
    github_proof_review = github_sub.add_parser(
        "proof-review",
        help="compile a Diff-to-Proof Review into an advisory Check/comment payload",
    )
    github_proof_review.add_argument("--root", default=".")
    github_proof_review.add_argument("--base", default="main")
    github_proof_review.add_argument(
        "--changed",
        action="append",
        default=[],
        help="workspace-relative changed path; repeat as needed",
    )
    github_proof_review.add_argument(
        "--head-sha",
        required=True,
        help="exact 40-character lowercase pull-request head SHA",
    )
    github_proof_review.add_argument(
        "--out-dir",
        help="explicit local directory for JSON and Markdown payload artifacts",
    )
    github_proof_review.add_argument("--json", action="store_true")
    github_plan_proof = github_sub.add_parser(
        "plan-proof-review",
        help="compile Plan-to-Proof facts into one advisory Check/comment payload",
    )
    github_plan_proof.add_argument(
        "--plan", required=True, help="factory.agent_plan.v1 JSON path"
    )
    github_plan_proof.add_argument("--root", default=".")
    github_plan_proof.add_argument("--base", default="main")
    github_plan_proof.add_argument(
        "--changed",
        action="append",
        default=[],
        help="workspace-relative changed path; repeat as needed",
    )
    github_plan_proof.add_argument(
        "--head-sha",
        required=True,
        help="exact 40-character lowercase pull-request head SHA",
    )
    github_plan_proof.add_argument(
        "--out-dir",
        help="explicit local directory for JSON and Markdown payload artifacts",
    )
    github_plan_proof.add_argument("--json", action="store_true")
    github_policy_snapshot = github_sub.add_parser(
        "policy-snapshot",
        help="validate a supplied local GitHub policy snapshot without a network call",
    )
    github_policy_snapshot.add_argument(
        "snapshot", help="factory.github_policy_snapshot.v1 JSON path"
    )
    github_policy_snapshot.add_argument("--json", action="store_true")
    github_assurance = github_sub.add_parser(
        "assurance-dossier",
        help="join local proof review and supplied policy snapshots into merge evidence",
    )
    github_assurance.add_argument(
        "--proof-review", required=True, help="factory.github_proof_review.v1 JSON path"
    )
    github_assurance.add_argument(
        "--policy-snapshot",
        required=True,
        help="current factory.github_policy_snapshot.v1 JSON path",
    )
    github_assurance.add_argument(
        "--baseline-policy-snapshot",
        help="previous comparable policy snapshot JSON path",
    )
    github_assurance.add_argument(
        "--exception",
        action="append",
        default=[],
        help="named expiring exception JSON path; repeat as needed",
    )
    github_assurance.add_argument(
        "--out-dir",
        help="explicit local directory for dossier JSON, Markdown, and Mermaid artifacts",
    )
    github_assurance.add_argument(
        "--require-aligned",
        action="store_true",
        help="exit non-zero after writing when baseline or high drift needs human action",
    )
    github_assurance.add_argument("--json", action="store_true")


def _compile_policy_snapshot(a) -> dict:
    from .github_assurance_dossier import validate_policy_snapshot

    return validate_policy_snapshot(
        json.loads(Path(a.snapshot).read_text(encoding="utf-8"))
    )


def _compile_assurance_dossier(a) -> dict:
    from .github_assurance_dossier import build_assurance_dossier_from_paths

    return build_assurance_dossier_from_paths(
        Path(a.proof_review),
        Path(a.policy_snapshot),
        Path(a.baseline_policy_snapshot) if a.baseline_policy_snapshot else None,
        [Path(path) for path in a.exception],
    )


def _compile_plan_review(a) -> dict:
    from .github_plan_proof_review import compile_github_plan_proof_review

    return compile_github_plan_proof_review(
        Path(a.root),
        Path(a.plan),
        base=a.base,
        changed=a.changed or None,
        head_sha=a.head_sha,
    )


def _compile_diff_review(a) -> dict:
    from .github_proof_review import compile_github_proof_review

    return compile_github_proof_review(
        Path(a.root), base=a.base, changed=a.changed or None, head_sha=a.head_sha
    )


def _compile_payload(a) -> dict:
    """Dispatch to the command-specific local evidence compiler."""
    if a.github_cmd == "policy-snapshot":
        return _compile_policy_snapshot(a)
    if a.github_cmd == "assurance-dossier":
        return _compile_assurance_dossier(a)
    if a.github_cmd == "plan-proof-review":
        return _compile_plan_review(a)
    return _compile_diff_review(a)


def _write_payload_artifacts(a, payload: dict) -> dict:
    """Write artifacts only when an explicit output directory was supplied."""
    if not getattr(a, "out_dir", None):
        return payload
    destination = Path(a.out_dir)
    if a.github_cmd == "plan-proof-review":
        from .github_plan_proof_review import write_github_plan_proof_review_artifacts

        payload["artifacts"] = write_github_plan_proof_review_artifacts(
            payload, destination
        )
    elif a.github_cmd == "assurance-dossier":
        from .github_assurance_dossier import write_assurance_dossier_artifacts

        payload["artifacts"] = write_assurance_dossier_artifacts(payload, destination)
    elif a.github_cmd == "policy-snapshot":
        from .github_assurance_dossier import GitHubAssuranceDossierError

        raise GitHubAssuranceDossierError(
            "GITHUB_ASSURANCE_INPUT_INVALID",
            "policy-snapshot validation never writes artifacts",
        )
    else:
        from .github_proof_review import write_github_proof_review_artifacts

        payload["artifacts"] = write_github_proof_review_artifacts(payload, destination)
    return payload


def _error_payload(a, exc: Exception) -> dict:
    """Map a caught command failure to its stable public error envelope."""
    assurance = a.github_cmd in {"policy-snapshot", "assurance-dossier"}
    fallback = (
        "GITHUB_ASSURANCE_INPUT_INVALID"
        if assurance
        else "GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID"
        if a.github_cmd == "plan-proof-review"
        else "GITHUB_PROOF_REVIEW_INPUT_INVALID"
    )
    schema = (
        "factory.github_assurance_dossier.error.v1"
        if assurance
        else "factory.github_plan_proof_review.error.v1"
        if a.github_cmd == "plan-proof-review"
        else "factory.github_proof_review.error.v1"
    )
    code = getattr(exc, "code", fallback)
    return {
        "schema": schema,
        "marker": code,
        "code": code,
        "message": str(exc),
    }


def _report_error(a, exc: Exception) -> int:
    """Print the command failure in JSON or human-readable form."""
    error = _error_payload(a, exc)
    message = (
        json.dumps(error, indent=2, sort_keys=True)
        if a.json
        else f"github proof review failed: {error['code']}: {exc}"
    )
    print(message, file=sys.stderr)
    return 2


def _print_success(a, payload: dict) -> None:
    """Render the stable concise terminal summary for a successful command."""
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(f"factory github {a.github_cmd} (local, advisory only)")
    print("=" * 54)
    if a.github_cmd == "policy-snapshot":
        print(
            f"scope        : {payload['scope']['owner']}/{payload['scope']['repository']}"
        )
        print(f"rulesets     : {len(payload['rulesets'])}")
    elif a.github_cmd == "assurance-dossier":
        print(f"head SHA     : {payload['head_sha']}")
        print(f"status       : {payload['status']}")
        print(f"next action  : {payload['next_action']['action']}")
        print(f"high drift   : {payload['drift']['unresolved_high_count']}")
    else:
        print(f"head SHA     : {payload['head_sha']}")
        print(f"review SHA   : {payload['review_sha256']}")
        print(f"next action  : {payload['next_action']['action']}")
        print(f"cohorts      : {len(payload['path_cohorts'])}")
    if payload.get("artifacts"):
        print(f"packet       : {payload['artifacts']['paths']['markdown']}")
    print(
        "authority    : no network, source write, test execution, approval, merge, or credential access"
    )


def _success_exit_code(a, payload: dict) -> int:
    """Return review-required status only when explicitly requested."""
    if (
        a.github_cmd == "assurance-dossier"
        and a.require_aligned
        and payload["status"] == "review_required"
    ):
        return 3
    return 0


def run(a) -> int:
    """Compile local GitHub evidence without network, merge, or credential actions."""
    from .github_assurance_dossier import GitHubAssuranceDossierError
    from .github_plan_proof_review import GitHubPlanProofReviewError
    from .github_proof_review import GitHubProofReviewError
    from .plan_proof_review import PlanProofReviewError

    try:
        payload = _compile_payload(a)
        payload = _write_payload_artifacts(a, payload)
    except (
        PlanProofReviewError,
        GitHubProofReviewError,
        GitHubPlanProofReviewError,
        GitHubAssuranceDossierError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        return _report_error(a, exc)
    _print_success(a, payload)
    return _success_exit_code(a, payload)

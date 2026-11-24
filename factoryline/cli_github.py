"""Lazy CLI boundary for local GitHub proof and assurance payloads."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from . import CodedError

if TYPE_CHECKING:
    from .github_account_overview import CommandRunner


def add_parser(sub) -> None:
    """Register GitHub context and advisory proof-review commands."""
    github = sub.add_parser(
        "github",
        help="read connected GitHub context or prepare evidence-bound advisory reviews",
    )
    github_sub = github.add_subparsers(required=True, dest="github_cmd")
    workflow_sync = github_sub.add_parser(
        "workflow-sync",
        help="read a connected GitHub issue/PR and persist its local workflow state; no dispatch",
    )
    workflow_sync.add_argument("--root", default=".")
    workflow_sync.add_argument(
        "--account", required=True, help="allowed authenticated GitHub login"
    )
    workflow_sync.add_argument(
        "--repository", required=True, help="allowed owner/repository"
    )
    workflow_sync.add_argument("--number", type=int, required=True)
    workflow_sync.add_argument(
        "--kind", choices=["issue", "pull_request"], default="issue"
    )
    workflow_sync.add_argument("--json", action="store_true")
    history = github_sub.add_parser(
        "workflow-history",
        help="inspect persisted local transitions; no network or replay",
    )
    history.add_argument("--root", default=".")
    history.add_argument("--account", required=True)
    history.add_argument("--repository", required=True)
    history.add_argument("--source-key", required=True)
    history.add_argument("--after", type=int, default=0)
    history.add_argument("--limit", type=int, default=50)
    history.add_argument("--json", action="store_true")
    github_overview = github_sub.add_parser(
        "overview",
        help="read a bounded overview for this workspace's connected GitHub repository",
    )
    github_overview.add_argument("--root", default=".")
    github_overview.add_argument(
        "--limit", type=int, default=30, help="maximum rows per section (1-100)"
    )
    github_overview.add_argument("--json", action="store_true")
    readiness = github_sub.add_parser(
        "pr-readiness",
        help="inspect merge blockers on the current GitHub pull-request head",
    )
    readiness.add_argument(
        "number", type=int, help="pull request number at workspace origin"
    )
    readiness.add_argument("--root", default=".")
    readiness.add_argument("--head-sha", help="reject evidence if the PR head differs")
    readiness.add_argument(
        "--require-clear",
        action="store_true",
        help="exit 3 with blockers or incomplete evidence",
    )
    readiness.add_argument("--json", action="store_true")
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
    if a.github_cmd == "overview":
        from .github_account_overview import build_github_account_overview

        return build_github_account_overview(Path(a.root), limit=a.limit)
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
    if a.github_cmd == "overview":
        code = getattr(exc, "code", "GITHUB_OVERVIEW_FAILED")
        return {
            "schema": "factory.github-account-overview.error.v1",
            "marker": code,
            "code": code,
            "message": str(exc),
        }
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
    command = "github overview" if a.github_cmd == "overview" else "github proof review"
    message = (
        json.dumps(error, indent=2, sort_keys=True)
        if a.json
        else f"{command} failed: {error['code']}: {exc}"
    )
    print(message, file=sys.stderr)
    return 2


def _print_success(a, payload: dict) -> None:
    """Render the stable concise terminal summary for a successful command."""
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if a.github_cmd == "overview":
        repository = payload.get("repository") or {}
        account = payload.get("connected_account") or {}
        sections = payload.get("sections") or {}
        print("factory github overview (read-only, connected account context)")
        print("=" * 58)
        print(f"state        : {payload['state']}")
        print(
            f"repository   : {repository.get('hostname', 'unknown')}/{repository.get('owner', '')}/{repository.get('name', '')}"
        )
        print(f"account      : {account.get('login') or 'not connected'}")
        print(f"branch       : {payload['local_checkout'].get('branch') or 'unknown'}")
        inventory = sections.get("account_repositories") or {}
        repository_detail = inventory.get("state", "UNAVAILABLE")
        if "returned_count" in inventory:
            repository_detail = (
                f"{inventory['returned_count']} rows ({repository_detail})"
            )
        print(f"repositories : {repository_detail}")
        for name in (
            "pull_requests",
            "issues",
            "actions",
            "releases",
            "rulesets",
            "branch_protection",
        ):
            section = sections.get(name) or {}
            count = section.get("returned_count")
            detail = (
                f"{count} rows"
                if count is not None
                else section.get("state", "UNAVAILABLE")
            )
            print(f"{name:15}: {detail}")
        print(f"next action  : {payload['next_action']}")
        print(
            "authority    : read-only repository context; no token access or persistence"
        )
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
    if a.github_cmd == "overview":
        return 0 if payload.get("state") == "COMPLETE" else 3
    if (
        a.github_cmd == "assurance-dossier"
        and a.require_aligned
        and payload["status"] == "review_required"
    ):
        return 3
    return 0


def run(a) -> int:
    """Run bounded GitHub reads/local intake or compile advisory proof."""
    if a.github_cmd == "pr-readiness":
        return _run_pr_readiness(a)
    if a.github_cmd in {"workflow-sync", "workflow-history"}:
        return _run_workflow_sync(a)
    from .github_assurance_dossier import GitHubAssuranceDossierError
    from .github_plan_proof_review import GitHubPlanProofReviewError
    from .github_proof_review import GitHubProofReviewError
    from .github_account_overview import GitHubOverviewError
    from .plan_proof_review import PlanProofReviewError

    try:
        payload = _compile_payload(a)
        payload = _write_payload_artifacts(a, payload)
    except (
        PlanProofReviewError,
        GitHubProofReviewError,
        GitHubPlanProofReviewError,
        GitHubAssuranceDossierError,
        GitHubOverviewError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        return _report_error(a, exc)
    _print_success(a, payload)
    return _success_exit_code(a, payload)


def _run_pr_readiness(a) -> int:
    try:
        result = github_pr_readiness(Path(a.root), a.number, expected_head=a.head_sha)
    except GitHubReadinessError as error:
        payload = {
            "schema": "factory.github-pr-readiness.error.v1",
            "code": error.code,
            "message": str(error),
        }
        print(
            json.dumps(payload) if a.json else f"{error.code}: {error}", file=sys.stderr
        )
        return 2
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"{result['repository']} #{result['number']} at {result['head_sha'][:12]}"
        )
        print(
            f"{result['state']} | {', '.join(result['blockers']) or 'No blockers observed'}"
        )
        print(
            f"Unresolved threads: {len(result['review_threads']['unresolved'])} | Checks: {result['checks']['state']}"
        )
        print(result["next_action"])
    return 3 if a.require_clear and result["state"] != "NO_OBSERVED_BLOCKERS" else 0


def _run_workflow_sync(a) -> int:
    import sqlite3
    from .agentic_control import (
        AgenticControlError,
        WorkflowEventStore,
        sync_github_workflow_source,
    )

    try:
        store = WorkflowEventStore(Path(a.root), [("github", a.account, a.repository)])
        payload = (
            store.history(a.source_key, after=a.after, limit=a.limit)
            if a.github_cmd == "workflow-history"
            else sync_github_workflow_source(store, a.repository, a.number, kind=a.kind)
        )
    except (AgenticControlError, OSError, sqlite3.Error) as error:
        code = getattr(error, "code", "E_WORKFLOW_STORAGE")
        payload = dict(
            schema="factory.workflow-runtime.error.v1",
            status="error",
            code=code,
            summary="Workflow operation failed; no dispatch or remote write occurred",
            next_actions=[
                "Check the connected account, repository scope and local storage; retry only this read"
            ],
            artifacts=[],
        )
        print(
            json.dumps(payload, sort_keys=True)
            if a.json
            else f"{code}: {payload['summary']}"
        )
        return 2
    if a.json:
        print(json.dumps(payload, sort_keys=True))
    elif a.github_cmd == "workflow-history":
        print(
            f"recorded transitions: {len(payload['events'])}; more: {payload['has_more']}"
        )
        print(f"next cursor: {payload['next_cursor']}")
        print("Local history only; no network, replay, dispatch or approval")
    else:
        print(f"workflow {payload['status']}: {payload['item']['phase']}")
        print(f"source key: {payload['item']['source_key']}")
        print("next action: " + "; ".join(payload["next_actions"]))
        print("GitHub read; local workflow state persisted; no agent dispatch or merge")
    return 0


_PR_QUERY = """
query Readiness($owner: String!, $repo: String!, $number: Int!) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      state isDraft mergeable mergeStateStatus reviewDecision headRefOid
      reviewThreads(first: 100) {
        pageInfo { hasNextPage }
        nodes { id isResolved isOutdated path line }
      }
      commits(last: 1) {
        nodes { commit {
          oid
          statusCheckRollup {
            state
            contexts(first: 100) {
              pageInfo { hasNextPage }
              nodes {
                ... on CheckRun { name status conclusion }
                ... on StatusContext { context state }
              }
            }
          }
        } }
      }
    }
  }
}
"""
_PR_SHA = re.compile(r"[0-9a-f]{40}")
_PR_NEXT = {
    "PR_NOT_OPEN": "Select an open pull request.",
    "MERGE_CONFLICT": "Resolve the base conflict and check the new head.",
    "BASE_BEHIND": "Update against the base branch and check the new head.",
    "MERGE_STATE_UNKNOWN": "Check again after GitHub computes mergeability.",
    "REVIEW_THREADS_OPEN": "Review unresolved threads before asking for approval.",
    "REVIEW_THREADS_TRUNCATED": "Inspect the remaining threads in GitHub.",
    "CHECKS_FAILED": "Inspect failed checks on this head.",
    "CHECKS_PENDING": "Wait for checks on this head to finish.",
    "CHECKS_UNREPORTED": "Verify expected checks in GitHub.",
    "CHECKS_TRUNCATED": "Inspect the remaining checks in GitHub.",
    "CHANGES_REQUESTED": "Address the outstanding review decision.",
    "REVIEW_REQUIRED": "Obtain the required review on this head.",
    "PR_DRAFT": "Mark the pull request ready when its evidence is ready.",
    "PROVIDER_POLICY_BLOCK": "Inspect branch rules and required approvals in GitHub.",
}
_PR_UNKNOWN_BLOCKERS = {
    "MERGE_STATE_UNKNOWN",
    "REVIEW_THREADS_TRUNCATED",
    "CHECKS_UNREPORTED",
    "CHECKS_TRUNCATED",
}


class GitHubReadinessError(CodedError):
    """An unavailable or inconsistent pull-request snapshot."""


def _read_pr(
    root: Path, scope: tuple[str, str, str], number: int, runner: CommandRunner
) -> dict:
    from .github_account_overview import REQUEST_TIMEOUT_SECONDS, _http_status

    gh = shutil.which("gh")
    if gh is None:
        raise GitHubReadinessError("GH_CLI_UNAVAILABLE", "GitHub CLI is unavailable")
    host, owner, repo = scope
    command = [
        gh,
        "api",
        "graphql",
        "--hostname",
        host,
        "--method",
        "POST",
        "-f",
        f"query={_PR_QUERY}",
        "-f",
        f"owner={owner}",
        "-f",
        f"repo={repo}",
        "-F",
        f"number={number}",
    ]
    try:
        result = runner(command, root, REQUEST_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitHubReadinessError("GH_READ_FAILED", "GitHub read unavailable") from exc
    if result.returncode != 0:
        status = _http_status(result.stderr or "")
        detail = f" (HTTP {status})" if status is not None else ""
        raise GitHubReadinessError("GH_READ_FAILED", f"GitHub read failed{detail}")
    try:
        response = json.loads(result.stdout)
        pull = response["data"]["repository"]["pullRequest"]
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise GitHubReadinessError(
            "GH_RESPONSE_INCOMPLETE", "Missing GitHub pull request data"
        ) from exc
    if response.get("errors") or not isinstance(pull, dict):
        raise GitHubReadinessError(
            "GH_RESPONSE_INCOMPLETE", "GitHub returned partial pull request data"
        )
    return pull


def _pr_connection(value: dict) -> tuple[list[dict], bool]:
    rows = value["nodes"]
    more = value["pageInfo"]["hasNextPage"]
    if not isinstance(rows, list) or type(more) is not bool:
        raise TypeError("invalid GitHub connection")
    return rows, more


def _pr_check_state(rollup: dict | None) -> tuple[str, list[dict], bool]:
    if rollup is None:
        return "UNREPORTED", [], False
    rows, truncated = _pr_connection(rollup["contexts"])
    checks = [
        {"name": row["name"], "status": row["status"], "conclusion": row["conclusion"]}
        if "name" in row
        else {"name": row["context"], "status": row["state"]}
        for row in rows
    ]
    return rollup["state"] if rows else "UNREPORTED", checks, truncated


def _pr_merge_blocker(pull: dict) -> str | None:
    if pull["mergeable"] == "CONFLICTING" or pull["mergeStateStatus"] == "DIRTY":
        return "MERGE_CONFLICT"
    if pull["mergeStateStatus"] == "BEHIND":
        return "BASE_BEHIND"
    if pull["mergeable"] != "MERGEABLE" or pull["mergeStateStatus"] == "UNKNOWN":
        return "MERGE_STATE_UNKNOWN"
    return None


def _pr_blockers(
    pull: dict, open_threads: list, thread_limit: bool, checks: str, check_limit: bool
) -> list[str]:
    if pull["state"] != "OPEN":
        return ["PR_NOT_OPEN"]
    ci_blocker = {
        "SUCCESS": None,
        "ERROR": "CHECKS_FAILED",
        "FAILURE": "CHECKS_FAILED",
        "PENDING": "CHECKS_PENDING",
        "EXPECTED": "CHECKS_PENDING",
    }.get(checks, "CHECKS_UNREPORTED")
    review_blocker = {
        None: None,
        "APPROVED": None,
        "CHANGES_REQUESTED": "CHANGES_REQUESTED",
    }.get(pull["reviewDecision"], "REVIEW_REQUIRED")
    blockers = [
        _pr_merge_blocker(pull),
        "REVIEW_THREADS_OPEN" if open_threads else None,
        "REVIEW_THREADS_TRUNCATED" if thread_limit else None,
        ci_blocker,
        "CHECKS_TRUNCATED" if check_limit else None,
        review_blocker,
        "PR_DRAFT" if pull["isDraft"] else None,
    ]
    reasons = [code for code in blockers if code]
    if not reasons and pull["mergeStateStatus"] != "CLEAN":
        return ["PROVIDER_POLICY_BLOCK"]
    return reasons


def _pr_snapshot(pull: dict, expected_head: str | None) -> dict:
    try:
        head = pull["headRefOid"]
        (row,) = pull["commits"]["nodes"]
        commit = row["commit"]
        if (
            not _PR_SHA.fullmatch(head)
            or commit["oid"] != head
            or expected_head not in {None, head}
        ):
            raise GitHubReadinessError(
                "GH_HEAD_MISMATCH",
                "GitHub evidence does not bind to the expected PR head",
            )
        threads, thread_limit = _pr_connection(pull["reviewThreads"])
        if any(type(row["isResolved"]) is not bool for row in threads):
            raise TypeError("invalid review thread state")
        open_threads = [
            {key: row[key] for key in ("id", "isOutdated", "path", "line")}
            for row in threads
            if not row["isResolved"]
        ]
        check_state, checks, check_limit = _pr_check_state(commit["statusCheckRollup"])
        blockers = _pr_blockers(
            pull, open_threads, thread_limit, check_state, check_limit
        )
    except GitHubReadinessError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise GitHubReadinessError(
            "GH_RESPONSE_INCOMPLETE", "GitHub readiness evidence is incomplete"
        ) from exc
    return {
        "head_sha": head,
        "state": "BLOCKED"
        if set(blockers) - _PR_UNKNOWN_BLOCKERS
        else ("INCOMPLETE" if blockers else "NO_OBSERVED_BLOCKERS"),
        "pr_state": pull["state"],
        "is_draft": pull["isDraft"],
        "merge_state": pull["mergeStateStatus"],
        "review_decision": pull["reviewDecision"],
        "review_threads": {"unresolved": open_threads, "truncated": thread_limit},
        "checks": {"state": check_state, "items": checks, "truncated": check_limit},
        "blockers": blockers,
        "next_action": _PR_NEXT[blockers[0]]
        if blockers
        else "Review the evidence and apply your normal merge policy.",
    }


def github_pr_readiness(
    root: Path,
    number: int,
    *,
    expected_head: str | None = None,
    runner: CommandRunner | None = None,
) -> dict:
    """Report current, bounded provider evidence without approving or mutating a PR."""
    from .github_account_overview import _default_runner, _parse_remote, _run_git

    workspace = root.resolve()
    if not workspace.is_dir() or type(number) is not int or not 1 <= number < 2**31:
        raise GitHubReadinessError(
            "GH_INVALID_REQUEST", "Provide a checkout and a valid pull request number"
        )
    if expected_head is not None and not _PR_SHA.fullmatch(expected_head):
        raise GitHubReadinessError(
            "GH_INVALID_REQUEST",
            "Expected head must be a 40-character lowercase Git SHA",
        )
    run = runner or _default_runner
    scope = _parse_remote(_run_git(workspace, ["remote", "get-url", "origin"], run))
    if scope is None:
        raise GitHubReadinessError(
            "GH_ORIGIN_UNAVAILABLE", "Workspace origin is not a supported GitHub remote"
        )
    return {
        "schema": "factory.github-pr-readiness.v1",
        "repository": "/".join(scope),
        "number": number,
        **_pr_snapshot(_read_pr(workspace, scope, number, run), expected_head),
        "reported_text_trust": "UNTRUSTED_DATA",
        "authority": {"merge": False, "approval": False, "provider_write": False},
    }

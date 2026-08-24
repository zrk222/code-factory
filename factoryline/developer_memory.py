"""Deterministic next-proof and observed-team projection for local workspaces.

This module intentionally composes existing evidence rather than creating a
second memory store or another agent authority.  It may read local Git history
to attribute observed contributors, but Git authors are not identity-provider
members, licensed seats, or review approvers.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any

from .change_review import AUTHORITY as CHANGE_REVIEW_AUTHORITY
from .change_review import ChangeReviewError, review_change
from .continuity import continuity_projection


DEVELOPER_MEMORY_BRIEF_SCHEMA = "factory.developer-memory-brief.v1"
MAX_ACTIONS = 50
MAX_TEAM_SEATS = 50
_GIT_TIMEOUT_SECONDS = 5
_BASE_MARKERS = [
    "DEVELOPER_MEMORY_BRIEF_V1",
    "DEVELOPER_MEMORY_REDACTED_CONTINUITY",
    "DEVELOPER_MEMORY_STUDIO_CACHED",
    "DEVELOPER_MEMORY_VISUAL_EXPLAINED",
]


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _safe_text(value: object, *, limit: int = 240) -> str:
    return " ".join(str(value).replace("\x00", " ").split())[:limit]


def _git_author_rows(root: Path, paths: list[str] | None = None) -> tuple[list[tuple[str, str, str]], str | None]:
    """Read bounded local Git author facts without changing the repository."""
    command = ["git", "-C", str(root), "log", "--all", "--format=%aN%x1f%aE%x1f%aI"]
    if paths:
        command.extend(["--", *paths[:MAX_ACTIONS]])
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], "LOCAL_GIT_HISTORY_UNAVAILABLE"
    if completed.returncode != 0:
        return [], "LOCAL_GIT_HISTORY_UNAVAILABLE"
    rows: list[tuple[str, str, str]] = []
    for line in completed.stdout.splitlines():
        fields = line.split("\x1f")
        if len(fields) != 3:
            continue
        name, email, committed_at = (_safe_text(field, limit=160) for field in fields)
        if name and email and committed_at:
            rows.append((name, email, committed_at))
    return rows, None


def _seat_id(name: str, email: str) -> str:
    return f"git-{_sha({'name': name, 'email': email})[:16]}"


def _seat_counts(rows: list[tuple[str, str, str]]) -> dict[str, dict[str, Any]]:
    seats: dict[str, dict[str, Any]] = {}
    for name, email, committed_at in rows:
        seat_id = _seat_id(name, email)
        seat = seats.setdefault(
            seat_id,
            {"seat_id": seat_id, "display_name": name, "commit_count": 0, "most_recent_commit_at": committed_at},
        )
        seat["commit_count"] += 1
        if committed_at > seat["most_recent_commit_at"]:
            seat["most_recent_commit_at"] = committed_at
    return seats


def _team_attribution(root: Path, changed_paths: list[str]) -> dict[str, Any]:
    """Summarize local Git contributors, never an organization or billing roster."""
    all_rows, error = _git_author_rows(root)
    if error:
        return {
            "available": False,
            "source": {"kind": "local_git_history", "directory_connected": False, "roster_completeness": "unavailable"},
            "seats": [],
            "changed_path_attribution": {"available": False, "contributor_seat_ids": [], "error": error},
            "scope_limits": ["No local Git history was available; no contributor or seat is inferred."],
        }
    selected_rows, selected_error = _git_author_rows(root, changed_paths) if changed_paths else ([], None)
    all_counts = _seat_counts(all_rows)
    selected_counts = _seat_counts(selected_rows) if selected_error is None else {}
    seats = []
    for seat in all_counts.values():
        selected = selected_counts.get(seat["seat_id"], {})
        seats.append({
            "seat_id": seat["seat_id"],
            "display_name": seat["display_name"],
            "contribution": {
                "all_ref_commit_count": seat["commit_count"],
                "selected_path_commit_count": selected.get("commit_count", 0),
                "most_recent_commit_at": seat["most_recent_commit_at"],
            },
        })
    seats.sort(key=lambda item: (-item["contribution"]["all_ref_commit_count"], item["display_name"].casefold(), item["seat_id"]))
    return {
        "available": True,
        "marker": "DEVELOPER_MEMORY_TEAM_ATTRIBUTION_LOCAL_GIT",
        "source": {
            "kind": "local_git_history",
            "directory_connected": False,
            "roster_completeness": "observed_contributors_only",
            "scope": "all local Git refs",
        },
        "seats": seats[:MAX_TEAM_SEATS],
        "truncated": len(seats) > MAX_TEAM_SEATS,
        "changed_path_attribution": {
            "available": selected_error is None,
            "scope": "aggregate across the selected changed paths; not per-path authorship",
            "contributor_seat_ids": sorted(selected_counts),
            "error": selected_error,
        },
        "scope_limits": [
            "Observed Git contributors are not a verified identity-provider or billing-seat roster.",
            "Git authorship is evidence of local commits, not approval, ownership, productivity, or review attribution.",
        ],
    }


def _redacted_continuity(root: Path) -> dict[str, Any]:
    projection = continuity_projection(root)
    facts = projection.get("facts") if isinstance(projection.get("facts"), dict) else {}
    records = projection.get("records") if isinstance(projection.get("records"), list) else []
    return {
        "available": projection.get("available") is True,
        "facts": {
            "record_count": facts.get("record_count", 0),
            "draft_count": facts.get("draft_count", 0),
            "verified_current_count": facts.get("verified_current_count", 0),
            "expired_count": facts.get("expired_count", 0),
        },
        "record_ids": [item.get("record_id") for item in records if isinstance(item, dict) and isinstance(item.get("record_id"), str)],
        "truncated": projection.get("truncated") is True,
        "error": projection.get("error"),
        "redaction": "memory references, summaries, scope values, and recalled bodies are withheld",
    }


def _action(
    *,
    action_id: str,
    kind: str,
    severity: str,
    title: str,
    what_changed: str,
    why_it_matters: str,
    do_this_next: str,
    review_sha256: str | None,
    contributor_seat_ids: list[str],
    **evidence: Any,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "kind": kind,
        "severity": severity,
        "title": title,
        "what_changed": what_changed,
        "why_it_matters": why_it_matters,
        "do_this_next": do_this_next,
        "evidence": {"review_sha256": review_sha256, **evidence},
        "contributor_seat_ids": contributor_seat_ids,
        "authority": {"execute": False, "approve": False, "publish": False, "deploy": False},
    }


def _actions_from_review(review: dict[str, Any], team: dict[str, Any]) -> list[dict[str, Any]]:
    impact = review.get("impact") if isinstance(review.get("impact"), dict) else {}
    coverage = review.get("coverage") if isinstance(review.get("coverage"), dict) else {}
    risk = review.get("risk") if isinstance(review.get("risk"), dict) else {}
    review_sha256 = review.get("review_sha256") if isinstance(review.get("review_sha256"), str) else None
    contributor_ids = list((team.get("changed_path_attribution") or {}).get("contributor_seat_ids") or [])
    actions: list[dict[str, Any]] = []
    unmatched = impact.get("unmatched_changed_paths") if isinstance(impact.get("unmatched_changed_paths"), list) else []
    for path in unmatched:
        if not isinstance(path, str):
            continue
        actions.append(_action(
            action_id=f"scope-gap:{path}", kind="bind_changed_path_to_proof", severity="blocking",
            title="Bind this change to a proof", what_changed=path,
            why_it_matters="No declared Graph Ops proof-input edge covers this changed path.",
            do_this_next="Declare the path as a proof input, then request a fresh Diff-to-Proof review.",
            review_sha256=review_sha256, contributor_seat_ids=contributor_ids, changed_path=path,
        ))
    reruns = impact.get("rerun_proofs") if isinstance(impact.get("rerun_proofs"), list) else []
    for proof in reruns:
        if not isinstance(proof, dict) or not isinstance(proof.get("proof_id"), str):
            continue
        gates = proof.get("gates") if isinstance(proof.get("gates"), list) else []
        actions.append(_action(
            action_id=f"stale-proof:{proof['proof_id']}", kind="rerun_stale_proof", severity="required",
            title="Rerun a stale proof", what_changed=f"Declared input changed after proof {proof['proof_id']} was recorded.",
            why_it_matters="A green result from older inputs is not evidence for this current change.",
            do_this_next="Run the declared proof through its normal approved workflow; this brief does not execute it.",
            review_sha256=review_sha256, contributor_seat_ids=contributor_ids,
            proof_id=proof["proof_id"], gates=gates,
        ))
    if coverage.get("ok") is False:
        uncovered = coverage.get("uncovered") if isinstance(coverage.get("uncovered"), list) else []
        actions.append(_action(
            action_id="coverage-gap", kind="complete_requirement_coverage", severity="required",
            title="Close declared requirement coverage", what_changed=f"{len(uncovered)} requirement coverage gap(s) remain.",
            why_it_matters="Coverage gaps prevent a reviewer from tracing the changed behavior to evidence.",
            do_this_next="Bind the missing requirement(s) to an explicit slice, mission, and proof before approval.",
            review_sha256=review_sha256, contributor_seat_ids=contributor_ids, requirement_ids=uncovered,
        ))
    stages = risk.get("rerun_stages") if isinstance(risk.get("rerun_stages"), list) else []
    if stages:
        actions.append(_action(
            action_id="risk-plan", kind="review_rerun_plan", severity="review",
            title="Review the policy-selected rerun plan", what_changed=f"{len(stages)} validation stage(s) are recommended by current risk policy.",
            why_it_matters="The policy plan is a recommendation, not evidence that the stages ran.",
            do_this_next="Review the ordered validation plan and approve execution through the normal human-controlled flow.",
            review_sha256=review_sha256, contributor_seat_ids=contributor_ids, rerun_stages=stages,
        ))
    if not actions:
        actions.append(_action(
            action_id="review-packet", kind="review_packet", severity="ready",
            title="Prepare the human review packet", what_changed="No declared proof, coverage, or policy gap was found in the available local inputs.",
            why_it_matters="This is not a claim that quality or release readiness has been proven.",
            do_this_next="Review the evidence packet with a named human reviewer before any consequential action.",
            review_sha256=review_sha256, contributor_seat_ids=contributor_ids,
        ))
    return actions[:MAX_ACTIONS]


def _markers(*, explicit: bool, unavailable: bool, has_scope_gap: bool, has_stale_proof: bool, team_available: bool) -> list[str]:
    markers = list(_BASE_MARKERS)
    if explicit:
        markers.append("DEVELOPER_MEMORY_CHANGE_REVIEW_EXACT")
    if has_scope_gap:
        markers.append("DEVELOPER_MEMORY_SCOPE_GAP_ACTION")
    if has_stale_proof:
        markers.append("DEVELOPER_MEMORY_STALE_PROOF_ACTIONS")
    if team_available:
        markers.append("DEVELOPER_MEMORY_TEAM_ATTRIBUTION_LOCAL_GIT")
    if unavailable:
        markers.append("DEVELOPER_MEMORY_UNAVAILABLE_EXPLICIT")
    return markers


def developer_memory_brief(root: Path, base: str = "main", changed: list[str] | None = None) -> dict[str, Any]:
    """Return a read-only evidence brief; it never runs a proof or mutates memory."""
    workspace = Path(root).resolve()
    try:
        review = review_change(workspace, base=base, changed=changed)
    except ChangeReviewError as exc:
        team = _team_attribution(workspace, [])
        action = _action(
            action_id="change-review-unavailable", kind="change_review_unavailable", severity="blocking",
            title="Inspect the change set before acting", what_changed="The local change set could not be determined.",
            why_it_matters="Without exact changed paths, the system cannot honestly select a proof, coverage gap, or risk plan.",
            do_this_next="Supply explicit workspace-relative changed paths or repair the local Git base, then refresh this brief.",
            review_sha256=None, contributor_seat_ids=[], failure_code=exc.code,
        )
        core = {
            "schema": DEVELOPER_MEMORY_BRIEF_SCHEMA,
            "markers": _markers(explicit=False, unavailable=True, has_scope_gap=False, has_stale_proof=False, team_available=team["available"]),
            "root": str(workspace), "base": base,
            "change_review": {"available": False, "failure_code": exc.code, "message": str(exc), "input_source": "unavailable", "changed_paths": []},
            "actions": [action], "next_action": {"action": action["kind"], "id": action["id"]},
            "continuity": _redacted_continuity(workspace), "team": team,
            "authority": {**CHANGE_REVIEW_AUTHORITY, "external_effects": False, "memory_recall": False, "team_directory": False},
            "presentation": {"marker": "DEVELOPER_MEMORY_VISUAL_EXPLAINED", "layout": "evidence-flow", "action_fields": ["what_changed", "why_it_matters", "do_this_next", "evidence"], "execution_controls": False},
            "scope_limits": ["No change, proof, productivity, token, or cost claim is inferred when diff inspection is unavailable.", "This brief does not execute, approve, publish, deploy, or recall memory bodies."],
        }
    else:
        changed_paths = review["changed_paths"]
        team = _team_attribution(workspace, changed_paths)
        actions = _actions_from_review(review, team)
        impact = review["impact"]
        core = {
            "schema": DEVELOPER_MEMORY_BRIEF_SCHEMA,
            "markers": _markers(
                explicit=review.get("input_source") == "explicit", unavailable=False,
                has_scope_gap=bool(impact.get("unmatched_changed_paths")), has_stale_proof=bool(impact.get("rerun_proofs")),
                team_available=team["available"],
            ),
            "root": str(workspace), "base": review["base"],
            "change_review": {"available": True, "input_source": review["input_source"], "changed_paths": changed_paths, "review_sha256": review["review_sha256"], "unproven_claims": review["unproven_claims"]},
            "actions": actions, "next_action": {"action": actions[0]["kind"], "id": actions[0]["id"]},
            "continuity": _redacted_continuity(workspace), "team": team,
            "authority": {**CHANGE_REVIEW_AUTHORITY, "external_effects": False, "memory_recall": False, "team_directory": False},
            "presentation": {"marker": "DEVELOPER_MEMORY_VISUAL_EXPLAINED", "layout": "evidence-flow", "action_fields": ["what_changed", "why_it_matters", "do_this_next", "evidence"], "execution_controls": False},
            "scope_limits": ["The brief is analysis only; it does not run a proof or grant approval.", "Continuity content is withheld; only redacted counts and record IDs are shown.", "Observed Git contributors are not verified project seats, approvers, or owners."],
        }
    return {**core, "brief_sha256": _sha(core)}

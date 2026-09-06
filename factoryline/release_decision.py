"""Read-only, deterministic explanation of a local release decision.

This module deliberately composes existing release-workflow and strict evidence
validators.  It has no provider client, credential path, process execution, or
repair authority.  In particular, a local block is never evidence that an
external marketplace or provider rejected a release.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from .release_integrity import release_integrity
from .verification import verify_feature


SCHEMA = "factory.release-decision-card.v1"
MARKER = "RELEASE_DECISION_CARD_READ_ONLY"
_FEATURE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
AUTHORITY = {
    "execution": False,
    "approval": False,
    "repair": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


def _feature_id(value: object) -> str:
    if not isinstance(value, str) or _FEATURE.fullmatch(value) is None:
        raise ValueError("feature must use 1-64 lowercase letters, digits, dots, underscores, or hyphens")
    return value


def _external_gates(integrity: dict[str, Any]) -> list[dict[str, str]]:
    requirements = integrity.get("external_requirements", [])
    rows = [
        {
            "id": "PROVIDER_STATE_UNOBSERVED",
            "state": "unobserved",
            "detail": "No provider was contacted; this local card cannot prove rejection, acceptance, publication, processing, deployment, or approval.",
        }
    ]
    if isinstance(requirements, list):
        rows.extend(
            {"id": f"DECLARED_EXTERNAL_REQUIREMENT_{index:02d}", "state": "unobserved", "detail": str(requirement)}
            for index, requirement in enumerate(requirements, start=1)
            if isinstance(requirement, str)
        )
    return rows


def _base_card(workspace: Path, feature: str, integrity: dict[str, Any]) -> dict[str, Any]:
    passed = [str(item.get("id")) for item in integrity.get("checks", []) if item.get("passed") is True]
    failed = [str(item.get("id")) for item in integrity.get("checks", []) if item.get("passed") is False]
    return {
        "schema": SCHEMA,
        "marker": MARKER,
        "root": str(workspace),
        "feature": feature,
        "workflow_integrity": {
            "ok": integrity.get("ok") is True,
            "marker": str(integrity.get("marker", "RELEASE_INTEGRITY_FAILURE")),
            "failed_check_ids": failed,
            "passing_check_ids": passed,
        },
        "external_gates": _external_gates(integrity),
        "authority": dict(AUTHORITY),
        "claim_boundary": (
            "This card is a read-only local classification. It does not contact a provider or prove a provider rejection, "
            "publication, processing, deployment, signing, approval, or availability."
        ),
    }


def _workflow_blockers(integrity: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"source": "release_integrity", "code": str(item.get("id")), "detail": str(item.get("evidence", "workflow check failed"))}
        for item in integrity.get("checks", [])
        if item.get("passed") is False
    ]


def release_workflow_decision_projection(integrity: dict[str, Any]) -> dict[str, Any]:
    """Describe the release-workflow boundary before a feature is selected.

    This is the shared, read-only precursor to :func:`release_decision_card`.
    A healthy static workflow still requires a named feature's strict local
    evidence, and no result in this projection observes a provider.
    """
    applicable = integrity.get("applicable") is True
    workflow_ok = integrity.get("ok") is True
    failed_check_ids = [blocker["code"] for blocker in _workflow_blockers(integrity)]
    external_requirements = [
        str(item)
        for item in integrity.get("external_requirements", [])
        if isinstance(item, str)
    ]
    marker = str(integrity.get("marker", "RELEASE_INTEGRITY_NOT_APPLICABLE"))
    if not applicable:
        state, status, label = (
            "RELEASE_WORKFLOW_NOT_APPLICABLE",
            "not_applicable",
            "Release decision · no declared workflow",
        )
        next_action, feature_required, source = "select_or_declare_release_workflow", False, None
    elif not workflow_ok:
        state, status, label = (
            "LOCAL_WORKFLOW_BLOCKED",
            "blocked",
            "Release decision · local workflow blocked",
        )
        next_action, feature_required, source = "repair_release_workflow", False, ".github/workflows/publish.yml"
    else:
        state, status, label = (
            "FEATURE_DECISION_REQUIRED",
            "feature_required",
            "Release decision · choose feature",
        )
        next_action, feature_required, source = "factory release decision <feature> --root . --json", True, ".github/workflows/publish.yml"
    return {
        "marker": "RELEASE_DECISION_GRAPH_READ_ONLY",
        "id": "release-decision:workflow",
        "kind": "release_decision",
        "label": label,
        "source": source,
        "status": status,
        "facts": {
            "state": state,
            "workflow_marker": marker,
            "workflow_ok": workflow_ok if applicable else None,
            "failed_check_ids": failed_check_ids,
            "external_requirements": external_requirements,
            "provider_state": "unobserved",
            "provider_contacted": False,
            "feature_required": feature_required,
            "next_action": next_action,
            "authority": dict(AUTHORITY),
            "execution": False,
            "repair": False,
            "merge": False,
        },
    }


def _verification_blockers(result: dict[str, Any]) -> list[dict[str, str]]:
    rows = [
        {
            "source": "strict_release_verification",
            "code": str(item.get("code", "LOCAL_EVIDENCE_BLOCKED")),
            "detail": str(item.get("detail", "local release evidence is not ready")),
        }
        for item in result.get("blockers", [])
        if isinstance(item, dict)
    ]
    return sorted(rows, key=lambda item: (item["source"], item["code"], item["detail"]))


def _next_action(action: str, reason: str) -> dict[str, str]:
    return {"action": action, "reason": reason, "authority": "human-controlled"}


def release_decision_card(root: Path, feature: str) -> dict[str, Any]:
    """Classify one feature's local release state without causing side effects."""
    feature_id = _feature_id(feature)
    workspace = Path(root).resolve()
    integrity = release_integrity(workspace)
    card = _base_card(workspace, feature_id, integrity)
    contract_path = workspace / ".factory" / "release-contracts" / f"{feature_id}.json"

    if integrity.get("ok") is not True:
        card.update({
            "state": "LOCAL_WORKFLOW_BLOCKED",
            "classification": "local_workflow_failure",
            "headline": "A declared local release-workflow boundary failed before feature evidence was evaluated.",
            "explanation": "This is not a provider rejection. Repair the named local workflow boundary, then re-run the local decision card.",
            "local_evidence": {
                "evaluated": False,
                "release_ready": None,
                "contract_path": contract_path.relative_to(workspace).as_posix(),
                "contract_marker": "NOT_EVALUATED",
            },
            "blockers": _workflow_blockers(integrity),
            "next_action": _next_action("repair_release_workflow", "Static release workflow integrity is not OK."),
        })
        return card

    if not contract_path.is_file():
        card.update({
            "state": "LOCAL_EVIDENCE_MISSING",
            "classification": "local_evidence_missing",
            "headline": "No strict local release contract exists for this feature.",
            "explanation": "This is not a provider rejection. Create or restore the exact Oracle-bound local release contract before requesting a release decision.",
            "local_evidence": {
                "evaluated": False,
                "release_ready": False,
                "contract_path": contract_path.relative_to(workspace).as_posix(),
                "contract_marker": "RELEASE_CONTRACT_MISSING",
            },
            "blockers": [{
                "source": "strict_release_verification",
                "code": "RELEASE_CONTRACT_MISSING",
                "detail": f"required local release contract is missing: {contract_path.relative_to(workspace).as_posix()}",
            }],
            "next_action": _next_action("create_or_restore_release_contract", "The strict local contract is absent."),
        })
        return card

    result = verify_feature(workspace, feature_id, strict_release=True, release_contract_path=contract_path)
    release_contract = result.get("release_contract", {})
    marker = str(release_contract.get("marker", "RELEASE_CONTRACT_INVALID")) if isinstance(release_contract, dict) else "RELEASE_CONTRACT_INVALID"
    local_evidence = {
        "evaluated": True,
        "release_ready": result.get("release_ready") is True,
        "shippable": result.get("shippable") is True,
        "contract_path": contract_path.relative_to(workspace).as_posix(),
        "contract_marker": marker,
        "blocker_count": len(result.get("blockers", [])),
    }
    if result.get("release_ready") is not True:
        blockers = _verification_blockers(result)
        if not blockers:
            blockers = [{
                "source": "strict_release_verification",
                "code": "LOCAL_RELEASE_NOT_READY",
                "detail": "strict local verification returned release_ready=false without an individual blocker",
            }]
        card.update({
            "state": "LOCAL_EVIDENCE_BLOCKED",
            "classification": "local_evidence_failure",
            "headline": "Strict local release evidence is incomplete, failed, stale, or not bound to its current policy.",
            "explanation": "This is not a provider rejection. Repair the ordered local evidence blockers and re-run the strict verifier.",
            "local_evidence": local_evidence,
            "blockers": blockers,
            "next_action": _next_action("repair_local_evidence_chain", str(result.get("next_action", "local evidence must be repaired"))),
        })
        return card

    card.update({
        "state": "EXTERNAL_GATES_UNOBSERVED",
        "classification": "local_evidence_complete_external_state_unobserved",
        "headline": "Declared local workflow and strict feature evidence pass; external provider state remains unobserved.",
        "explanation": "No provider was contacted. This is not a publication, processing, deployment, or approval claim.",
        "local_evidence": local_evidence,
        "blockers": [],
        "next_action": _next_action("review_external_publish_gates", "A named human must inspect each external provider gate separately."),
    })
    return card


def render_release_decision_card(card: dict[str, Any]) -> str:
    """Render a concise local-only decision explanation for human operators."""
    lines = [f"release decision: {card['state']}", f"why: {card['headline']}"]
    lines.append(f"boundary: {card['explanation']}")
    for blocker in card.get("blockers", []):
        lines.append(f"- {blocker['source']} {blocker['code']}: {blocker['detail']}")
    lines.append(f"next: {card['next_action']['action']}")
    lines.append("provider state: unobserved; no provider rejection is inferred")
    lines.append("authority: no execution, approval, repair, merge, publication, deployment, signing, messaging, credential, or connector authority")
    return "\n".join(lines)

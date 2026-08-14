"""Deterministic, provider-neutral Plan-to-Proof review and proof-debt ledger.

An agent-plan envelope records only human-approved scope.  This module never
parses a vendor transcript, calls a provider, runs a command, or decides that a
change is ready to merge.  It joins the envelope to the existing Diff-to-Proof
facts and derives the remaining obligations a human must settle.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .change_review import AUTHORITY as CHANGE_REVIEW_AUTHORITY
from .change_review import ChangeReviewError, review_change


AGENT_PLAN_SCHEMA = "factory.agent_plan.v1"
PLAN_PROOF_REVIEW_SCHEMA = "factory.plan_proof_review.v1"
PROOF_DEBT_SCHEMA = "factory.proof_debt.v1"
MAX_PLAN_ITEMS = 50
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_PROVIDER = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_REVIEW_TIERS = frozenset({"light", "standard", "deep"})
AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
    "source_write": False,
    "test_execution": False,
    "repair": False,
}


class PlanProofReviewError(ValueError):
    """A rejected agent-plan envelope or Plan-to-Proof review payload."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _reject(message: str) -> None:
    raise PlanProofReviewError("PLAN_TO_PROOF_PLAN_INVALID", message)


def _text(value: object, field: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        _reject(f"{field} must be a non-empty string")
    result = value.strip()
    if len(result) > 96:
        _reject(f"{field} must be at most 96 characters")
    if pattern and not pattern.fullmatch(result):
        _reject(f"{field} has an unsupported format")
    return result


def _path(value: object, field: str) -> str:
    if not isinstance(value, str):
        _reject(f"{field} must contain workspace-relative paths")
    path = value.replace("\\", "/").strip().removeprefix("./")
    if (
        not path
        or path.startswith("/")
        or re.match(r"^[A-Za-z]:/", path)
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        _reject(f"{field} contains an invalid workspace-relative path")
    return path


def _paths(value: object, field: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        _reject(f"{field} must be a {'possibly empty' if allow_empty else 'non-empty'} array")
    paths = [_path(item, field) for item in value]
    if len(paths) != len(set(paths)):
        _reject(f"{field} contains duplicate paths")
    return paths


def _load_plan(value: Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, Path):
        try:
            loaded = json.loads(value.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PlanProofReviewError("PLAN_TO_PROOF_PLAN_INVALID", f"agent plan cannot be read as JSON: {exc}") from exc
    else:
        loaded = value
    if not isinstance(loaded, dict):
        _reject("agent plan must contain one JSON object")
    return loaded


def validate_agent_plan(value: Path | dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize one strict, human-approved agent-plan envelope."""
    plan = _load_plan(value)
    allowed = {"schema", "provider", "plan_id", "approval", "items"}
    if set(plan) != allowed:
        _reject("agent plan must contain exactly schema, provider, plan_id, approval, and items")
    if plan.get("schema") != AGENT_PLAN_SCHEMA:
        _reject(f"schema must be {AGENT_PLAN_SCHEMA}")
    provider = _text(plan.get("provider"), "provider", pattern=_PROVIDER)
    plan_id = _text(plan.get("plan_id"), "plan_id", pattern=_IDENTIFIER)
    approval = plan.get("approval")
    if not isinstance(approval, dict) or set(approval) != {"state", "approved_by"}:
        _reject("approval must contain exactly state and approved_by")
    if approval.get("state") != "approved":
        _reject("approval.state must be approved")
    approved_by = _text(approval.get("approved_by"), "approval.approved_by")
    items = plan.get("items")
    if not isinstance(items, list) or not items or len(items) > MAX_PLAN_ITEMS:
        _reject(f"items must be a non-empty array of at most {MAX_PLAN_ITEMS} entries")

    normalized_items: list[dict[str, Any]] = []
    item_ids: set[str] = set()
    source_paths: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            _reject(f"items[{index}] must be an object")
        allowed_item = {"id", "paths", "test_paths", "review_tier", "review_owner"}
        if set(item) - allowed_item or not {"id", "paths", "test_paths", "review_tier"}.issubset(item):
            _reject(f"items[{index}] contains unsupported or missing fields")
        item_id = _text(item.get("id"), f"items[{index}].id", pattern=_IDENTIFIER)
        if item_id in item_ids:
            _reject("items contains duplicate item IDs")
        item_ids.add(item_id)
        paths = _paths(item.get("paths"), f"items[{index}].paths", allow_empty=False)
        if source_paths.intersection(paths):
            _reject("items contains duplicate planned paths")
        source_paths.update(paths)
        test_paths = _paths(item.get("test_paths"), f"items[{index}].test_paths", allow_empty=True)
        review_tier = item.get("review_tier")
        if review_tier not in _REVIEW_TIERS:
            _reject(f"items[{index}].review_tier must be light, standard, or deep")
        owner = item.get("review_owner")
        if owner is not None:
            owner = _text(owner, f"items[{index}].review_owner")
        if review_tier == "deep" and not owner:
            _reject(f"items[{index}].review_owner is required for deep review")
        normalized_items.append({
            "id": item_id,
            "paths": paths,
            "test_paths": test_paths,
            "review_tier": review_tier,
            "review_owner": owner,
        })
    return {
        "schema": AGENT_PLAN_SCHEMA,
        "provider": provider,
        "plan_id": plan_id,
        "approval": {"state": "approved", "approved_by": approved_by},
        "items": normalized_items,
    }


def _item_for_path(plan: dict[str, Any], path: str) -> dict[str, Any] | None:
    matches = [item for item in plan["items"] if path in item["paths"] or path in item["test_paths"]]
    if len(matches) > 1:
        raise PlanProofReviewError("PLAN_TO_PROOF_PLAN_INVALID", f"path {path} maps to multiple plan items")
    return matches[0] if matches else None


def _finding(kind: str, severity: str, message: str, **facts: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "message": message, "facts": facts}


def _plan_findings(plan: dict[str, Any], changed_paths: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    matched: list[dict[str, str]] = []
    unplanned: list[str] = []
    changed_item_ids: set[str] = set()
    for path in changed_paths:
        item = _item_for_path(plan, path)
        if item is None:
            unplanned.append(path)
        else:
            changed_item_ids.add(item["id"])
            matched.append({"path": path, "item_id": item["id"]})
    declared_unmodified = [item["id"] for item in plan["items"] if item["id"] not in changed_item_ids]
    findings: list[dict[str, Any]] = []
    if unplanned:
        findings.append(_finding(
            "unplanned_changed_path", "blocking",
            "A changed path is not covered by the human-approved agent plan.",
            path=unplanned[0], paths=unplanned,
        ))
    for item in plan["items"]:
        source_changed = any(path in item["paths"] for path in changed_paths)
        test_changed = any(path in item["test_paths"] for path in changed_paths)
        if source_changed and item["test_paths"] and not test_changed:
            findings.append(_finding(
                "declared_test_path_missing", "required",
                "A changed plan item declares test paths, but none of those test paths changed.",
                item_id=item["id"], test_paths=item["test_paths"],
            ))
    for item in plan["items"]:
        if item["id"] in changed_item_ids and item["review_tier"] == "deep":
            findings.append(_finding(
                "named_human_review_required", "required",
                "A deep-review plan item changed and must be routed to its named human reviewer.",
                item_id=item["id"], review_owner=item["review_owner"],
            ))
    return {
        "matched": matched,
        "unplanned_changed_paths": unplanned,
        "declared_unmodified_item_ids": declared_unmodified,
    }, findings


def _next_action(plan_findings: list[dict[str, Any]], source_review: dict[str, Any]) -> dict[str, Any]:
    for finding in plan_findings:
        if finding["kind"] == "unplanned_changed_path":
            return {"action": "reconcile_unplanned_change", "reason": finding["message"], "path": finding["facts"]["path"]}
    for finding in plan_findings:
        if finding["kind"] == "declared_test_path_missing":
            return {"action": "provide_declared_test_change", "reason": finding["message"], "item_id": finding["facts"]["item_id"]}
    for finding in plan_findings:
        if finding["kind"] == "named_human_review_required":
            return {"action": "route_to_named_reviewer", "reason": finding["message"], "review_owner": finding["facts"]["review_owner"]}
    if source_review["next_action"]["action"] != "review_packet":
        return dict(source_review["next_action"])
    return {"action": "review_packet", "reason": "Plan scope and existing Diff-to-Proof facts have no higher-priority action."}


def _settlement_for(finding: dict[str, Any]) -> str:
    kind = finding["kind"]
    if kind == "unplanned_changed_path":
        return "Add the path to a new human-approved plan item or remove the change, then regenerate the review."
    if kind == "declared_test_path_missing":
        return "Change the declared test path, amend the approved plan, or explicitly split the work before regeneration."
    if kind == "named_human_review_required":
        return "Obtain the named reviewer’s decision outside this analysis-only tool and record it in the team’s review system."
    return "Resolve the underlying Diff-to-Proof gap and regenerate the review from fresh local facts."


def _proof_debt(plan_findings: list[dict[str, Any]], source_review: dict[str, Any]) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for finding in plan_findings:
        if finding["severity"] not in {"blocking", "required"}:
            continue
        facts = dict(finding["facts"])
        items.append({
            "id": f"plan:{finding['kind']}:{_sha(facts)[:12]}",
            "kind": finding["kind"],
            "severity": finding["severity"],
            "facts": facts,
            "settlement": _settlement_for(finding),
        })
    default_claim = "No release, quality, or productivity outcome is claimed by this analysis-only review."
    for claim in source_review["unproven_claims"]:
        if claim != default_claim:
            items.append({
                "id": f"source:unproven_claim:{_sha(claim)[:12]}",
                "kind": "diff_to_proof_unproven_claim",
                "severity": "required",
                "facts": {"claim": claim},
                "settlement": "Resolve the bound Diff-to-Proof evidence gap and regenerate the review from fresh local facts.",
            })
    return {
        "schema": PROOF_DEBT_SCHEMA,
        "state": "open" if items else "clear",
        "count": len(items),
        "items": items,
        "scope_limit": "Proof debt is a deterministic list of outstanding obligations, not an automated merge block or evidence that a test ran.",
    }


def _mermaid_label(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9._/: -]+", "?", str(value)).strip()
    return (text or "unknown")[:96]


def _mermaid(review: dict[str, Any]) -> str:
    lines = ["flowchart LR", '  PLAN["Approved agent plan"]', '  DIFF["Changed paths"]', '  PROOF["Diff-to-Proof facts"]']
    lines.extend(["  PLAN --> DIFF", "  DIFF --> PROOF"])
    for index, debt in enumerate(review["proof_debt"]["items"], 1):
        node = f"D{index}"
        lines.append(f'  {node}["Debt: {_mermaid_label(debt["kind"])}"]')
        lines.append(f"  DIFF --> {node}")
    action = _mermaid_label(review["next_action"]["action"])
    lines.append(f'  NEXT["Next: {action}"]')
    lines.append("  PROOF --> NEXT")
    return "\n".join(lines) + "\n"


def _markdown(review: dict[str, Any]) -> str:
    findings = "\n".join(
        f"- **{finding['severity']}** `{finding['kind']}` — {finding['message']}"
        for finding in review["findings"]
    ) or "- None."
    debt = "\n".join(
        f"- `{item['id']}` ({item['severity']}): {item['settlement']}"
        for item in review["proof_debt"]["items"]
    ) or "- Clear: no outstanding deterministic obligation was derived."
    changed = "\n".join(f"- `{path}`" for path in review["changed_paths"])
    return "\n".join([
        "# Plan-to-Proof Review",
        "",
        f"Plan: `{review['plan']['provider']}/{review['plan']['plan_id']}` approved by `{review['plan']['approval']['approved_by']}`",
        f"Plan SHA-256: `{review['plan_sha256']}`",
        f"Review SHA-256: `{review['review_sha256']}`",
        "",
        "## Changed paths",
        "",
        changed,
        "",
        "## Fact-derived next action",
        "",
        f"- `{review['next_action']['action']}` — {review['next_action']['reason']}",
        "",
        "## Findings",
        "",
        findings,
        "",
        "## Proof debt",
        "",
        debt,
        "",
        "## Authority boundary",
        "",
        "Analysis only. This review does not execute tests, validate an AI transcript, grant approval, merge, write source, publish, deploy, or access provider credentials.",
        "",
    ])


def review_plan_proof(root: Path, plan_path: Path, *, base: str = "main", changed: list[str] | None = None) -> dict[str, Any]:
    """Compile a no-write Plan-to-Proof review from a strict plan and local facts."""
    workspace = Path(root).resolve()
    plan = validate_agent_plan(Path(plan_path))
    source_review = review_change(workspace, base=base, changed=changed)
    alignment, plan_findings = _plan_findings(plan, source_review["changed_paths"])
    next_action = _next_action(plan_findings, source_review)
    proof_debt = _proof_debt(plan_findings, source_review)
    findings = plan_findings + list(source_review["findings"])
    core = {
        "schema": PLAN_PROOF_REVIEW_SCHEMA,
        "markers": [
            "PLAN_TO_PROOF_REVIEW_V1",
            "PLAN_TO_PROOF_ENVELOPE_STRICT",
            "PLAN_TO_PROOF_APPROVAL_EXACT",
            "PLAN_TO_PROOF_ALIGNMENT_EXACT",
            "PLAN_TO_PROOF_UNPLANNED_PATH_PRIORITY",
            "PLAN_TO_PROOF_DECLARED_TEST_EXACT",
            "PLAN_TO_PROOF_DEEP_REVIEW_ROUTED",
            "PLAN_TO_PROOF_INVALID_REJECTED",
            "PLAN_TO_PROOF_PROOF_DEBT_EXACT",
            "PLAN_TO_PROOF_NO_EXECUTION",
            "PLAN_TO_PROOF_ARTIFACTS_OPTIONAL",
        ],
        "root": str(workspace),
        "base": base,
        "plan": plan,
        "plan_sha256": _sha(plan),
        "source_review": {
            "schema": source_review["schema"],
            "review_sha256": source_review["review_sha256"],
            "findings": list(source_review["findings"]),
            "next_action": dict(source_review["next_action"]),
            "unproven_claims": list(source_review["unproven_claims"]),
        },
        "changed_paths": list(source_review["changed_paths"]),
        "alignment": alignment,
        "findings": findings,
        "next_action": next_action,
        "proof_debt": proof_debt,
        "authority": AUTHORITY,
        "scope_limits": [
            "Provider labels are caller-supplied metadata and do not prove a vendor integration.",
            "A changed test path is not evidence that a test executed or that its assertion can fail.",
            "A named deep-review owner is routing data, not evidence of a completed human review.",
            "Proof debt exposes outstanding obligations; it does not auto-block a pull request or change branch protection.",
        ],
    }
    review_sha256 = _sha(core)
    review = {**core, "review_sha256": review_sha256}
    review["mermaid"] = _mermaid(review)
    review["review_markdown"] = _markdown(review)
    return review


def validate_plan_proof_review(value: object) -> dict[str, Any]:
    """Validate the canonical Plan-to-Proof facts before a delivery adapter uses them."""
    if not isinstance(value, dict) or value.get("schema") != PLAN_PROOF_REVIEW_SCHEMA:
        raise PlanProofReviewError("PLAN_TO_PROOF_REVIEW_INVALID", "a factory.plan_proof_review.v1 payload is required")
    required = {
        "schema", "markers", "root", "base", "plan", "plan_sha256", "source_review", "changed_paths",
        "alignment", "findings", "next_action", "proof_debt", "authority", "scope_limits", "review_sha256",
        "mermaid", "review_markdown",
    }
    if not required.issubset(value) or set(value) - (required | {"artifacts"}):
        raise PlanProofReviewError("PLAN_TO_PROOF_REVIEW_INVALID", "the Plan-to-Proof review has unsupported or missing fields")
    plan = validate_agent_plan(value["plan"])
    if value["plan_sha256"] != _sha(plan):
        raise PlanProofReviewError("PLAN_TO_PROOF_REVIEW_INVALID", "the canonical agent-plan SHA-256 does not match")
    if value["authority"] != AUTHORITY:
        raise PlanProofReviewError("PLAN_TO_PROOF_REVIEW_INVALID", "the Plan-to-Proof authority boundary changed")
    core = {key: value[key] for key in required - {"review_sha256", "mermaid", "review_markdown"}}
    if value["review_sha256"] != _sha(core):
        raise PlanProofReviewError("PLAN_TO_PROOF_REVIEW_INVALID", "the Plan-to-Proof review SHA-256 does not match")
    return value


def _atomic_text(path: Path, content: str) -> str:
    encoded = content.encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return sha256(encoded).hexdigest()


def write_plan_proof_review_artifacts(review: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write canonical JSON, Markdown, and Mermaid only below an explicit directory."""
    review = validate_plan_proof_review(review)
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"plan-proof-review-{review['review_sha256'][:12]}"
    paths = {
        "json": destination / f"{stem}.json",
        "markdown": destination / f"{stem}.md",
        "mermaid": destination / f"{stem}.mmd",
    }
    payload = {key: value for key, value in review.items() if key not in {"artifacts", "review_markdown", "mermaid"}}
    digests = {
        "json": _atomic_text(paths["json"], json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"),
        "markdown": _atomic_text(paths["markdown"], review["review_markdown"]),
        "mermaid": _atomic_text(paths["mermaid"], review["mermaid"]),
    }
    return {
        "marker": "PLAN_TO_PROOF_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
    }

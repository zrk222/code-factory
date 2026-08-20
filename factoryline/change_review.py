"""Deterministic, analysis-only change review over existing Factory evidence."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .coverage import requirement_coverage
from .graph_ops import graph_ops_impact
from .proof import git_changed_paths, risk_for_paths


CHANGE_REVIEW_SCHEMA = "factory.change_review.v1"
# The PR delivery workflow analyzes release-sized source, docs, and media changes
# in one exact packet. Keep a firm cap so review rendering remains bounded, while
# accepting an ordinary multi-surface release without silently dropping paths.
MAX_CHANGED_PATHS = 200
AUTHORITY = {
    "execution": False,
    "approval": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
}


class ChangeReviewError(ValueError):
    """A rejected local change-review input."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _changed_path(value: str) -> str:
    path = str(value).replace("\\", "/").strip()
    path = path.removeprefix("./")
    if (
        not path
        or path.startswith("/")
        or re.match(r"^[A-Za-z]:/", path)
        or any(part == ".." for part in path.split("/"))
    ):
        raise ChangeReviewError(
            "CHANGED_PATH_INVALID",
            "changed paths must be non-empty workspace-relative paths without parent traversal",
        )
    return path.rstrip("/")


def _resolve_changed_paths(root: Path, base: str, changed: list[str] | None) -> tuple[str, list[str]]:
    if changed:
        source = "explicit"
        raw_paths = changed
    else:
        source = "git"
        try:
            raw_paths = git_changed_paths(root, base)
        except RuntimeError as exc:
            raise ChangeReviewError("DIFF_BASE_UNAVAILABLE", str(exc)) from exc
    normalized = sorted({_changed_path(value) for value in raw_paths})
    if not normalized:
        raise ChangeReviewError("NO_CHANGED_PATHS", "no changed paths were found")
    if len(normalized) > MAX_CHANGED_PATHS:
        raise ChangeReviewError("CHANGED_PATH_LIMIT", f"at most {MAX_CHANGED_PATHS} changed paths are supported")
    return source, normalized


def _finding(kind: str, severity: str, message: str, **facts: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "message": message, "facts": facts}


def _findings(impact: dict[str, Any], coverage: dict[str, Any], risk: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    unmatched = list(impact["unmatched_changed_paths"])
    if unmatched:
        path = unmatched[0]
        finding = _finding(
            "unmatched_changed_path",
            "blocking",
            "This changed path has no explicit Graph Ops proof-input edge.",
            path=path,
        )
        findings.append(finding)
        return findings, {"action": "bind_changed_path_to_proof", "reason": finding["message"], "path": path}

    for proof in impact["rerun_proofs"]:
        findings.append(_finding(
            "stale_proof",
            "required",
            "A declared proof input changed after the proof was recorded.",
            proof_id=proof["proof_id"],
            gates=proof["gates"],
        ))
    if findings:
        first = findings[0]
        return findings, {"action": "rerun_stale_proof", "reason": first["message"], "proof_id": first["facts"]["proof_id"]}

    if not coverage["ok"]:
        uncovered = list(coverage["uncovered"])
        finding = _finding(
            "coverage_incomplete",
            "required",
            "Requirement coverage is absent or incomplete; the review keeps that gap explicit.",
            uncovered=uncovered,
        )
        findings.append(finding)
        return findings, {"action": "complete_requirement_coverage", "reason": finding["message"], "requirements": uncovered}

    stages = list(risk["rerun_stages"])
    if stages:
        finding = _finding(
            "policy_rerun_plan",
            "review",
            "Existing risk-diff policy recommends a plan-only validation sequence.",
            stages=stages,
        )
        findings.append(finding)
        return findings, {"action": "review_rerun_plan", "reason": finding["message"], "stage": stages[0]}

    finding = _finding("ready_for_human_review", "info", "No declared proof, coverage, or policy gap was found.")
    findings.append(finding)
    return findings, {"action": "review_packet", "reason": finding["message"]}


def _unproven_claims(impact: dict[str, Any], coverage: dict[str, Any]) -> list[str]:
    claims: list[str] = []
    for path in impact["unmatched_changed_paths"]:
        claims.append(f"No explicit proof-input edge is declared for `{path}`.")
    for proof in impact["rerun_proofs"]:
        claims.append(f"Proof `{proof['label']}` is stale and has not been rerun.")
    if not coverage["ok"]:
        for requirement in coverage["uncovered"]:
            claims.append(f"Requirement coverage is unproven for `{requirement}`.")
    for error in impact["source_errors"]:
        claims.append(f"Graph source `{error['source']}` is unavailable: `{error['code']}`.")
    return claims or ["No release, quality, or productivity outcome is claimed by this analysis-only review."]


def _mermaid_label(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9._/: -]+", "?", str(value)).strip()
    return (text or "unknown")[:96]


def _review_mermaid(changed_paths: list[str], impact: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    lines = ["flowchart LR", '  REVIEW["Diff-to-Proof Review"]']
    for index, path in enumerate(changed_paths, 1):
        node = f"C{index}"
        lines.append(f'  {node}["Changed: {_mermaid_label(path)}"]')
        lines.append(f"  {node} --> REVIEW")
    for index, proof in enumerate(impact["rerun_proofs"], 1):
        node = f"P{index}"
        lines.append(f'  {node}["Rerun: {_mermaid_label(proof["label"])}"]')
        lines.append(f"  REVIEW --> {node}")
    for index, path in enumerate(impact["unmatched_changed_paths"], 1):
        node = f"U{index}"
        lines.append(f'  {node}["Unmatched: {_mermaid_label(path)}"]')
        lines.append(f"  REVIEW --> {node}")
    for index, finding in enumerate(findings, 1):
        node = f"F{index}"
        lines.append(f'  {node}["{_mermaid_label(finding["kind"])}"]')
        lines.append(f"  REVIEW --> {node}")
    return "\n".join(lines) + "\n"


def _review_markdown(review: dict[str, Any]) -> str:
    changed = "\n".join(f"- `{path}`" for path in review["changed_paths"])
    findings = "\n".join(f"- **{item['severity']}** `{item['kind']}` — {item['message']}" for item in review["findings"])
    stages = review["risk"]["rerun_stages"]
    stage_lines = "\n".join(f"- `{item['module']}:{item['stage']}` — {'; '.join(item['reasons'])}" for item in stages) or "- No policy rerun stage was selected."
    claims = "\n".join(f"- {claim}" for claim in review["unproven_claims"])
    return "\n".join([
        "# Diff-to-Proof Review",
        "",
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
        "## Plan-only rerun stages",
        "",
        stage_lines,
        "",
        "## Unproven claims",
        "",
        claims,
        "",
        "## Authority boundary",
        "",
        "Analysis only. No command was executed. This review cannot merge, publish, deploy, sign, send messages, access credentials, or grant connectors.",
        "",
    ])


def review_change(root: Path, base: str = "main", changed: list[str] | None = None) -> dict:
    """Compile a deterministic change review without executing a gate or writing files."""
    workspace = Path(root).resolve()
    input_source, changed_paths = _resolve_changed_paths(workspace, base, changed)
    impact = graph_ops_impact(workspace, changed_paths)
    coverage = requirement_coverage(workspace)
    risk = risk_for_paths(changed_paths)
    findings, next_action = _findings(impact, coverage, risk)
    core = {
        "schema": CHANGE_REVIEW_SCHEMA,
        "markers": [
            "DIFF_TO_PROOF_REVIEW_V1",
            "DIFF_TO_PROOF_INPUTS_EXACT",
            "DIFF_TO_PROOF_GRAPH_IMPACT_EXACT",
            "DIFF_TO_PROOF_COVERAGE_GAPS_EXPLICIT",
            "DIFF_TO_PROOF_RERUN_PLAN_EXACT",
            "DIFF_TO_PROOF_MERMAID_EXPORTED",
            "DIFF_TO_PROOF_ARTIFACTS_OPTIONAL",
            "DIFF_TO_PROOF_NO_EXECUTION",
        ] + (["DIFF_TO_PROOF_UNMATCHED_PRIORITY"] if impact["unmatched_changed_paths"] else []),
        "root": str(workspace),
        "base": base,
        "input_source": input_source,
        "changed_paths": changed_paths,
        "impact": impact,
        "coverage": coverage,
        "risk": risk,
        "findings": findings,
        "next_action": next_action,
        "unproven_claims": _unproven_claims(impact, coverage),
        "authority": AUTHORITY,
        "scope_limits": [
            "The review analyzes existing local facts and never executes a gate or replay plan.",
            "Risk recommendations are plan-only and do not prove a test has run.",
            "Missing coverage, unmatched paths, stale proofs, and source errors remain explicit.",
        ],
    }
    review_sha256 = _sha(core)
    review = {**core, "review_sha256": review_sha256}
    review["mermaid"] = _review_mermaid(changed_paths, impact, findings)
    review["review_markdown"] = _review_markdown(review)
    return review


def _atomic_text(path: Path, content: str) -> str:
    encoded = content.encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return sha256(encoded).hexdigest()


def write_review_artifacts(review: dict, out_dir: Path) -> dict:
    """Write optional local review artifacts below an explicit caller-selected directory."""
    if review.get("schema") != CHANGE_REVIEW_SCHEMA or not review.get("review_sha256"):
        raise ChangeReviewError("REVIEW_INVALID", "a valid change-review payload is required")
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"change-review-{review['review_sha256'][:12]}"
    payload = {key: value for key, value in review.items() if key not in {"review_markdown", "mermaid", "artifacts"}}
    json_path = destination / f"{stem}.json"
    markdown_path = destination / f"{stem}.md"
    mermaid_path = destination / f"{stem}.mmd"
    paths = {"json": json_path, "markdown": markdown_path, "mermaid": mermaid_path}
    digests = {
        "json": _atomic_text(json_path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"),
        "markdown": _atomic_text(markdown_path, review["review_markdown"]),
        "mermaid": _atomic_text(mermaid_path, review["mermaid"]),
    }
    return {
        "marker": "DIFF_TO_PROOF_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
    }

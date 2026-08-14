"""Local-only GitHub Check/comment renderer for Plan-to-Proof review facts."""
from __future__ import annotations

from hashlib import sha256
import json
import re
from pathlib import Path
from typing import Any

from .github_proof_review import AUTHORITY as GITHUB_AUTHORITY
from .plan_proof_review import (
    PLAN_PROOF_REVIEW_SCHEMA,
    PlanProofReviewError,
    review_plan_proof,
    validate_plan_proof_review,
)


GITHUB_PLAN_PROOF_REVIEW_SCHEMA = "factory.github_plan_proof_review.v1"
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


class GitHubPlanProofReviewError(ValueError):
    """A rejected SHA or plan-aware GitHub delivery payload."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _valid_head_sha(head_sha: str) -> str:
    value = str(head_sha)
    if not _COMMIT_SHA.fullmatch(value):
        raise GitHubPlanProofReviewError(
            "GITHUB_PLAN_PROOF_REVIEW_HEAD_SHA_INVALID",
            "head SHA must be exactly 40 lowercase hexadecimal characters",
        )
    return value


def _cohort_for(path: str) -> str:
    for prefix, cohort in (
        ("specs/", "contracts"), ("requirements/", "contracts"), ("tests/", "tests"), ("test/", "tests"),
        (".github/", "delivery"), ("deploy/", "delivery"), ("infra/", "delivery"), ("docs/", "docs"),
        ("factoryline/", "implementation"), ("src/", "implementation"), ("lib/", "implementation"),
        ("app/", "implementation"), ("services/", "implementation"), ("editors/", "implementation"),
        ("packages/", "implementation"), ("scripts/", "implementation"),
    ):
        if path.startswith(prefix):
            return cohort
    return "other"


def _cohorts(paths: list[str]) -> list[dict[str, Any]]:
    grouped: dict[str, list[str]] = {}
    for path in paths:
        grouped.setdefault(_cohort_for(path), []).append(path)
    return [
        {"id": key, "label": key.replace("_", " ").title(), "paths": sorted(value)}
        for key, value in sorted(grouped.items())
    ]


def _items(items: list[Any], render) -> str:
    return "\n".join(f"- {render(item)}" for item in items) if items else "- None."


def _walkthrough(core: dict[str, Any]) -> str:
    cohorts = _items(
        core["path_cohorts"],
        lambda cohort: f"**{cohort['label']}** — " + ", ".join(f"`{path}`" for path in cohort["paths"]),
    )
    findings = _items(
        core["findings"],
        lambda finding: f"**{finding['severity']}** `{finding['kind']}` — {finding['message']}",
    )
    debt = _items(
        core["proof_debt"]["items"],
        lambda item: f"**{item['severity']}** `{item['kind']}` — {item['settlement']}",
    )
    disabled = ", ".join(key.replace("_", " ") for key, value in core["authority"].items() if not value)
    return "\n".join([
        "<!-- factoryline-proof-review -->",
        "# FactoryLine Plan-to-Proof Review",
        "",
        f"Commit: `{core['head_sha']}`",
        f"Plan: `{core['plan']['provider']}/{core['plan']['plan_id']}` approved by `{core['plan']['approval']['approved_by']}`",
        f"Plan SHA-256: `{core['plan_sha256']}`",
        f"Plan-to-Proof Review SHA-256: `{core['review_sha256']}`",
        f"GitHub payload SHA-256: `{core['payload_sha256']}`",
        "",
        "## Changed-scope walkthrough",
        "",
        cohorts,
        "",
        "## Fact-derived next action",
        "",
        f"- `{core['next_action']['action']}` — {core['next_action']['reason']}",
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
        f"Advisory only. This payload has no {disabled} authority. It does not call a provider API, interpret AI comments as proof, approve, merge, or modify source.",
        "",
        "## Plan-to-Proof map",
        "",
        "```mermaid",
        core["mermaid"].rstrip(),
        "```",
        "",
    ])


def _review_fields(review: object) -> dict[str, Any]:
    try:
        review = validate_plan_proof_review(review)
    except PlanProofReviewError as exc:
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", str(exc)) from exc
    if not isinstance(review, dict) or review.get("schema") != PLAN_PROOF_REVIEW_SCHEMA:
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "a factory.plan_proof_review.v1 payload is required")
    required = {
        "plan", "plan_sha256", "review_sha256", "changed_paths", "findings", "next_action", "proof_debt",
        "mermaid", "authority", "scope_limits",
    }
    if not required.issubset(review) or review.get("authority", None) != {**GITHUB_AUTHORITY}:
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "the Plan-to-Proof payload shape or authority boundary is invalid")
    if not isinstance(review["changed_paths"], list) or not all(isinstance(path, str) and path for path in review["changed_paths"]):
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "changed paths are invalid")
    if not isinstance(review["findings"], list) or not all(isinstance(item, dict) for item in review["findings"]):
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "findings are invalid")
    if not isinstance(review["proof_debt"], dict) or not isinstance(review["proof_debt"].get("items"), list):
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "proof debt is invalid")
    return review


def render_github_plan_proof_review(review: object, head_sha: str) -> dict[str, Any]:
    """Render one neutral, no-network GitHub Check/comment from local facts."""
    source = _review_fields(review)
    commit = _valid_head_sha(head_sha)
    core = {
        "schema": GITHUB_PLAN_PROOF_REVIEW_SCHEMA,
        "markers": [
            "GITHUB_PLAN_PROOF_REVIEW_V1",
            "GITHUB_PLAN_PROOF_REVIEW_SHA_BOUND",
            "GITHUB_PLAN_PROOF_REVIEW_CHECK_ADVISORY",
            "GITHUB_PLAN_PROOF_REVIEW_PROOF_DEBT_EXACT",
            "GITHUB_PLAN_PROOF_REVIEW_LOCAL_ONLY",
            "GITHUB_PLAN_PROOF_REVIEW_WORKFLOW_SCOPED",
        ],
        "head_sha": commit,
        "source_review_schema": source["schema"],
        "review_sha256": source["review_sha256"],
        "plan": source["plan"],
        "plan_sha256": source["plan_sha256"],
        "changed_paths": list(source["changed_paths"]),
        "path_cohorts": _cohorts(source["changed_paths"]),
        "findings": list(source["findings"]),
        "next_action": dict(source["next_action"]),
        "proof_debt": dict(source["proof_debt"]),
        "mermaid": source["mermaid"],
        "authority": dict(GITHUB_AUTHORITY),
        "scope_limits": [
            "The renderer does not call a network service or execute a test, repair, or command.",
            "The workflow delivers only an advisory Check and one stable pull-request comment.",
            "Provider labels and review owners are plan metadata, not evidence of vendor access or completed review.",
        ],
    }
    payload_sha256 = _sha(core)
    walkthrough = _walkthrough({**core, "payload_sha256": payload_sha256})
    check = {
        "name": "FactoryLine / Proof Review",
        "head_sha": commit,
        "status": "completed",
        "conclusion": "neutral",
        "output": {"title": "Plan-to-Proof walkthrough", "summary": walkthrough},
    }
    return {**core, "payload_sha256": payload_sha256, "check": check, "github_comment": walkthrough}


def compile_github_plan_proof_review(
    root: Path, plan_path: Path, *, base: str = "main", changed: list[str] | None = None, head_sha: str = "",
) -> dict[str, Any]:
    """Compile a plan review and render its advisory GitHub delivery shape."""
    return render_github_plan_proof_review(
        review_plan_proof(Path(root), Path(plan_path), base=base, changed=changed), head_sha,
    )


def _atomic_text(path: Path, content: str) -> str:
    encoded = content.encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return sha256(encoded).hexdigest()


def write_github_plan_proof_review_artifacts(payload: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write the plan-aware GitHub JSON and comment only below an explicit directory."""
    if not isinstance(payload, dict) or payload.get("schema") != GITHUB_PLAN_PROOF_REVIEW_SCHEMA:
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "a GitHub Plan-to-Proof payload is required")
    core = {key: value for key, value in payload.items() if key not in {"payload_sha256", "check", "github_comment", "artifacts"}}
    if payload.get("payload_sha256") != _sha(core):
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "the GitHub Plan-to-Proof SHA-256 does not match")
    expected_walkthrough = _walkthrough({**core, "payload_sha256": payload["payload_sha256"]})
    expected_check = {
        "name": "FactoryLine / Proof Review",
        "head_sha": core.get("head_sha"),
        "status": "completed",
        "conclusion": "neutral",
        "output": {"title": "Plan-to-Proof walkthrough", "summary": expected_walkthrough},
    }
    if payload.get("github_comment") != expected_walkthrough or payload.get("check") != expected_check:
        raise GitHubPlanProofReviewError("GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID", "the GitHub Plan-to-Proof delivery fields do not match canonical facts")
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"github-plan-proof-review-{payload['payload_sha256'][:12]}"
    paths = {"json": destination / f"{stem}.json", "markdown": destination / f"{stem}.md"}
    serializable = {key: value for key, value in payload.items() if key != "artifacts"}
    digests = {
        "json": _atomic_text(paths["json"], json.dumps(serializable, ensure_ascii=False, indent=2, sort_keys=True) + "\n"),
        "markdown": _atomic_text(paths["markdown"], payload["github_comment"]),
    }
    return {
        "marker": "GITHUB_PLAN_PROOF_REVIEW_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
    }

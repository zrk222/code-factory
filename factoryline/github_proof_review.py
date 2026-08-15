"""Evidence-bound GitHub pull-request review payloads.

This module deliberately has no network or subprocess dependency.  It turns an
already-local Diff-to-Proof Review into a stable GitHub Check/comment payload;
the opt-in workflow is the separate, supervised delivery adapter.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .change_review import AUTHORITY as CHANGE_REVIEW_AUTHORITY
from .change_review import CHANGE_REVIEW_SCHEMA, review_change


GITHUB_PROOF_REVIEW_SCHEMA = "factory.github_proof_review.v1"
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_REVIEW_CORE_KEYS = frozenset({
    "schema", "markers", "root", "base", "input_source", "changed_paths", "impact",
    "coverage", "risk", "findings", "next_action", "unproven_claims", "authority",
    "scope_limits",
})
_REVIEW_RENDERED_KEYS = frozenset({"review_sha256", "mermaid", "review_markdown", "artifacts"})
_PATH_PREFIXES = (
    ("specs/", "contracts"),
    ("requirements/", "contracts"),
    ("tests/", "tests"),
    ("test/", "tests"),
    (".github/", "delivery"),
    ("deploy/", "delivery"),
    ("infra/", "delivery"),
    ("docs/", "docs"),
    ("factoryline/", "implementation"),
    ("src/", "implementation"),
    ("lib/", "implementation"),
    ("app/", "implementation"),
    ("services/", "implementation"),
    ("editors/", "implementation"),
    ("packages/", "implementation"),
    ("scripts/", "implementation"),
)
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


class GitHubProofReviewError(ValueError):
    """A rejected GitHub Proof Review input."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _reject(message: str) -> None:
    raise GitHubProofReviewError("GITHUB_PROOF_REVIEW_INPUT_INVALID", message)


def _valid_review(review: object) -> dict[str, Any]:
    if not isinstance(review, dict) or review.get("schema") != CHANGE_REVIEW_SCHEMA:
        _reject("a factory.change_review.v1 payload is required")
    if set(review) - (_REVIEW_CORE_KEYS | _REVIEW_RENDERED_KEYS):
        _reject("the change-review payload contains unsupported fields")
    if not _REVIEW_CORE_KEYS.issubset(review) or not _REVIEW_RENDERED_KEYS - {"artifacts"} <= set(review):
        _reject("the change-review payload is incomplete")
    if (
        not isinstance(review["markers"], list)
        or not all(isinstance(marker, str) for marker in review["markers"])
        or "DIFF_TO_PROOF_REVIEW_V1" not in review["markers"]
        or not all(isinstance(review[key], str) for key in ("root", "base", "input_source", "mermaid", "review_markdown"))
        or not isinstance(review["changed_paths"], list)
        or not all(isinstance(path, str) and path for path in review["changed_paths"])
        or any(not isinstance(review[key], dict) for key in ("impact", "coverage", "risk", "next_action"))
        or not all(isinstance(review["next_action"].get(key), str) for key in ("action", "reason"))
        or not isinstance(review["findings"], list)
        or any(
            not isinstance(finding, dict)
            or not all(isinstance(finding.get(key), str) for key in ("kind", "severity", "message"))
            for finding in review["findings"]
        )
        or not isinstance(review["unproven_claims"], list)
        or not all(isinstance(claim, str) for claim in review["unproven_claims"])
        or review["authority"] != CHANGE_REVIEW_AUTHORITY
        or not isinstance(review["scope_limits"], list)
        or not all(isinstance(limit, str) for limit in review["scope_limits"])
    ):
        _reject("the change-review payload has an invalid field shape or authority boundary")
    core = {key: review[key] for key in _REVIEW_CORE_KEYS}
    expected = _sha(core)
    if review.get("review_sha256") != expected:
        _reject("the change-review SHA-256 does not match its canonical facts")
    return review


def _valid_head_sha(head_sha: str) -> str:
    value = str(head_sha)
    if not _COMMIT_SHA.fullmatch(value):
        raise GitHubProofReviewError(
            "GITHUB_PROOF_REVIEW_HEAD_SHA_INVALID",
            "head SHA must be exactly 40 lowercase hexadecimal characters",
        )
    return value


def _cohort_for(path: str) -> str:
    for prefix, cohort in _PATH_PREFIXES:
        if path.startswith(prefix):
            return cohort
    return "other"


def _path_cohorts(paths: list[str]) -> list[dict[str, Any]]:
    grouped: dict[str, list[str]] = {}
    for path in paths:
        grouped.setdefault(_cohort_for(path), []).append(path)
    return [
        {"id": cohort, "label": cohort.replace("_", " ").title(), "paths": sorted(items)}
        for cohort, items in sorted(grouped.items())
    ]


def _list_or_none(items: list[Any], render) -> str:
    return "\n".join(f"- {render(item)}" for item in items) if items else "- None."


def _walkthrough(core: dict[str, Any]) -> str:
    cohorts = _list_or_none(
        core["path_cohorts"],
        lambda cohort: f"**{cohort['label']}** — " + ", ".join(f"`{path}`" for path in cohort["paths"]),
    )
    findings = _list_or_none(
        core["findings"],
        lambda finding: f"**{finding['severity']}** `{finding['kind']}` — {finding['message']}",
    )
    claims = _list_or_none(core["unproven_claims"], str)
    disabled = ", ".join(key.replace("_", " ") for key, value in core["authority"].items() if not value)
    return "\n".join([
        "<!-- factoryline-proof-review -->",
        "# FactoryLine Proof Review",
        "",
        f"Commit: `{core['head_sha']}`",
        f"Diff-to-Proof Review SHA-256: `{core['review_sha256']}`",
        f"Proof Review SHA-256: `{core['payload_sha256']}`",
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
        "## Unproven claims",
        "",
        claims,
        "",
        "## Authority boundary",
        "",
        f"Advisory only. This payload has no {disabled} authority. It does not use CodeRabbit credentials, interpret AI comments as proof, approve, merge, or modify source.",
        "",
        "## Existing Diff-to-Proof map",
        "",
        "```mermaid",
        core["mermaid"].rstrip(),
        "```",
        "",
    ])


def _payload_core(payload: dict[str, Any]) -> dict[str, Any]:
    excluded = {"payload_sha256", "check", "github_comment", "artifacts"}
    return {key: value for key, value in payload.items() if key not in excluded}


def _valid_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != GITHUB_PROOF_REVIEW_SCHEMA:
        raise GitHubProofReviewError("GITHUB_PROOF_REVIEW_INPUT_INVALID", "a valid GitHub Proof Review payload is required")
    core = _payload_core(payload)
    if payload.get("payload_sha256") != _sha(core):
        raise GitHubProofReviewError("GITHUB_PROOF_REVIEW_INPUT_INVALID", "the GitHub Proof Review SHA-256 does not match its canonical facts")
    expected_walkthrough = _walkthrough({**core, "payload_sha256": payload["payload_sha256"]})
    expected_check = {
        "name": "FactoryLine / Proof Review",
        "head_sha": core.get("head_sha"),
        "status": "completed",
        "conclusion": "neutral",
        "output": {"title": "Evidence-bound proof walkthrough", "summary": expected_walkthrough},
    }
    if payload.get("github_comment") != expected_walkthrough or payload.get("check") != expected_check:
        raise GitHubProofReviewError("GITHUB_PROOF_REVIEW_INPUT_INVALID", "the GitHub Proof Review delivery fields do not match its canonical facts")
    return payload


def validate_github_proof_review_payload(payload: object) -> dict[str, Any]:
    """Validate one rendered local proof-review payload for downstream evidence joins."""
    return _valid_payload(payload)


def render_github_proof_review(review: object, head_sha: str) -> dict[str, Any]:
    """Render a deterministic, advisory-only GitHub payload from trusted local facts."""
    source = _valid_review(review)
    commit = _valid_head_sha(head_sha)
    core = {
        "schema": GITHUB_PROOF_REVIEW_SCHEMA,
        "markers": [
            "GITHUB_PROOF_REVIEW_V1",
            "GITHUB_PROOF_REVIEW_SHA_BOUND",
            "GITHUB_PROOF_REVIEW_COHORTS_EXACT",
            "GITHUB_PROOF_REVIEW_CHECK_ADVISORY",
            "GITHUB_PROOF_REVIEW_WALKTHROUGH_EXACT",
            "GITHUB_PROOF_REVIEW_ARTIFACTS_OPTIONAL",
            "GITHUB_PROOF_REVIEW_LOCAL_ONLY",
            "GITHUB_PROOF_REVIEW_WORKFLOW_SCOPED",
        ],
        "head_sha": commit,
        "source_review_schema": source["schema"],
        "review_sha256": source["review_sha256"],
        "changed_paths": list(source["changed_paths"]),
        "path_cohorts": _path_cohorts(source["changed_paths"]),
        "findings": list(source["findings"]),
        "next_action": dict(source["next_action"]),
        "unproven_claims": list(source["unproven_claims"]),
        "mermaid": source["mermaid"],
        "authority": AUTHORITY,
        "scope_limits": [
            "The local renderer does not call a network service or execute a test, repair, or command.",
            "The workflow delivers only an advisory Check and one stable pull-request comment.",
            "CodeRabbit and other AI-review comments remain separate from deterministic FactoryLine evidence.",
        ],
    }
    payload_sha256 = _sha(core)
    walkthrough_core = {**core, "payload_sha256": payload_sha256}
    walkthrough = _walkthrough(walkthrough_core)
    check = {
        "name": "FactoryLine / Proof Review",
        "head_sha": commit,
        "status": "completed",
        "conclusion": "neutral",
        "output": {
            "title": "Evidence-bound proof walkthrough",
            "summary": walkthrough,
        },
    }
    return {
        **walkthrough_core,
        "check": check,
        "github_comment": walkthrough,
    }


def compile_github_proof_review(
    root: Path,
    base: str = "main",
    changed: list[str] | None = None,
    head_sha: str = "",
) -> dict[str, Any]:
    """Compile the current local review then render its GitHub delivery payload."""
    return render_github_proof_review(review_change(Path(root), base=base, changed=changed), head_sha)


def _atomic_text(path: Path, content: str) -> str:
    encoded = content.encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return sha256(encoded).hexdigest()


def write_github_proof_review_artifacts(payload: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    """Write optional JSON and Markdown payload artifacts below one explicit directory."""
    payload = _valid_payload(payload)
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"github-proof-review-{payload['payload_sha256'][:12]}"
    json_path = destination / f"{stem}.json"
    markdown_path = destination / f"{stem}.md"
    serializable = {key: value for key, value in payload.items() if key != "artifacts"}
    paths = {"json": json_path, "markdown": markdown_path}
    digests = {
        "json": _atomic_text(json_path, json.dumps(serializable, ensure_ascii=False, indent=2, sort_keys=True) + "\n"),
        "markdown": _atomic_text(markdown_path, payload["github_comment"]),
    }
    return {
        "marker": "GITHUB_PROOF_REVIEW_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
    }

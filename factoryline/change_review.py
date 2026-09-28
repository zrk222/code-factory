"""Deterministic, analysis-only change review over existing Factory evidence."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from typing import Any

from .coverage import requirement_coverage
from .graph_ops import graph_ops_impact
from .proof import git_changed_paths, risk_for_paths
from .review_audits import ReviewAuditError, audit_code


CHANGE_REVIEW_SCHEMA = "factory.change_review.v1"
REPOSITORY_SCOPE_SCHEMA = "factory.repository_scope.v1"
REPOSITORY_SCOPE_REVIEW_SCHEMA = "factory.repository_scope_review.v1"
# The PR delivery workflow analyzes release-sized source, docs, and media changes
# in one exact packet. Keep a firm cap so review rendering remains bounded, while
# accepting broad repository cleanup and multi-surface releases without silently
# dropping paths.
MAX_CHANGED_PATHS = 500
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


class RepositoryScopeError(ValueError):
    """A malformed scope policy or unavailable changed-path source."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _scope_policy_path(value: object) -> str:
    if not isinstance(value, str):
        raise RepositoryScopeError("SCOPE_PATH_INVALID", "changed path must be text")
    path = value.replace("\\", "/").strip().removeprefix("./")
    if (
        not path
        or path.startswith("/")
        or re.match(r"^[A-Za-z]:/", path)
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise RepositoryScopeError(
            "SCOPE_PATH_INVALID", "changed paths must be safe workspace-relative paths"
        )
    return path


def _scope_segment(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or "/" in value or "\\" in value:
        raise RepositoryScopeError(
            "SCOPE_POLICY_INVALID", "blocked_path_segments must contain path segments"
        )
    segment = _normalize_scope_name(value)
    if not segment or segment in {".", ".."}:
        raise RepositoryScopeError(
            "SCOPE_POLICY_INVALID", "blocked path segment is invalid"
        )
    return segment


def _normalize_scope_name(value: str) -> str:
    """Normalize separators, including camel-case product names in filenames."""
    split_words = re.sub(r"([A-Z])([A-Z][a-z])", r"\1-\2", value)
    split_words = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", split_words)
    return re.sub(r"[^a-z0-9]+", "-", split_words.casefold()).strip("-")


def _validate_scope_policy(value: object) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "blocked_path_segments"}
        or value.get("schema") != REPOSITORY_SCOPE_SCHEMA
        or not isinstance(value.get("blocked_path_segments"), list)
    ):
        raise RepositoryScopeError(
            "SCOPE_POLICY_INVALID",
            f"policy must contain schema {REPOSITORY_SCOPE_SCHEMA} and blocked_path_segments",
        )
    segments = [_scope_segment(item) for item in value["blocked_path_segments"]]
    if len(segments) != len(set(segments)):
        raise RepositoryScopeError(
            "SCOPE_POLICY_INVALID", "blocked_path_segments must be unique"
        )
    return {"schema": REPOSITORY_SCOPE_SCHEMA, "blocked_path_segments": segments}


def _read_scope_policy(
    root: Path, policy_path: str, policy_ref: str | None
) -> dict[str, Any]:
    relative = _scope_policy_path(policy_path)
    if policy_ref:
        if policy_ref.startswith("-") or any(char in policy_ref for char in "\r\n\0"):
            raise RepositoryScopeError("SCOPE_POLICY_INVALID", "policy ref is invalid")
        try:
            result = subprocess.run(
                ["git", "show", f"{policy_ref}:{relative}"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RepositoryScopeError(
                "SCOPE_POLICY_UNAVAILABLE",
                f"cannot read {relative} from trusted policy ref {policy_ref}",
            ) from exc
        raw = result.stdout
    else:
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root):
            raise RepositoryScopeError(
                "SCOPE_POLICY_INVALID", "policy path must remain inside the repository"
            )
        try:
            raw = candidate.read_text(encoding="utf-8")
        except OSError as exc:
            raise RepositoryScopeError(
                "SCOPE_POLICY_UNAVAILABLE", f"cannot read scope policy: {exc}"
            ) from exc
    try:
        return _validate_scope_policy(json.loads(raw))
    except json.JSONDecodeError as exc:
        raise RepositoryScopeError(
            "SCOPE_POLICY_INVALID", "scope policy is not valid JSON"
        ) from exc


def _git_scope_paths(root: Path, base: str, head: str) -> list[str]:
    for name, value in (("base", base), ("head", head)):
        if (
            not value
            or value.startswith("-")
            or any(char in value for char in "\r\n\0")
        ):
            raise RepositoryScopeError(
                f"SCOPE_{name.upper()}_INVALID", f"{name} ref is invalid"
            )
    try:
        result = subprocess.run(
            [
                "git",
                "diff",
                "--name-status",
                "-z",
                "--find-renames",
                "--find-copies-harder",
                base,
                head,
            ],
            cwd=root,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RepositoryScopeError(
            "SCOPE_DIFF_UNAVAILABLE", f"cannot compare changes with {base}"
        ) from exc
    try:
        fields = result.stdout.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as exc:
        raise RepositoryScopeError(
            "SCOPE_DIFF_INVALID", "Git returned a path that is not valid UTF-8"
        ) from exc
    paths: list[str] = []
    index = 0
    while index < len(fields) and fields[index]:
        status = fields[index]
        index += 1
        if status.startswith(("R", "C")):
            if index + 1 >= len(fields):
                raise RepositoryScopeError(
                    "SCOPE_DIFF_INVALID", "Git returned a truncated rename record"
                )
            source_path = fields[index]
            index += 1
            path = fields[index]
            index += 1
            paths.append(source_path)
        else:
            if index >= len(fields):
                raise RepositoryScopeError(
                    "SCOPE_DIFF_INVALID", "Git returned a truncated path record"
                )
            path = fields[index]
            index += 1
            if status.startswith("D"):
                continue
        if status.startswith(("A", "M", "R", "C", "T")):
            paths.append(path)
    return paths


def _matches_scope_segment(path: str, blocked: set[str]) -> str | None:
    segments = path.split("/")
    if segments and "products" in blocked:
        root = _normalize_scope_name(segments[0])
        if root == "products":
            return "products"
    for segment in segments:
        normalized = _normalize_scope_name(segment)
        compact = normalized.replace("-", "")
        tokens = normalized.split("-")
        for candidate in sorted(blocked, key=lambda value: (-len(value), value)):
            if candidate == "products":
                continue
            if candidate.replace("-", "") in compact:
                return candidate
            blocked_tokens = candidate.split("-")
            if any(
                tokens[index : index + len(blocked_tokens)] == blocked_tokens
                for index in range(len(tokens) - len(blocked_tokens) + 1)
            ):
                return candidate
    return None


def check_repository_scope(
    root: Path,
    *,
    policy_path: str = ".factory/repository-scope.json",
    policy_ref: str | None = None,
    base: str | None = None,
    head: str | None = None,
    changed_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Compare added or modified paths against a repository's trusted path policy."""
    workspace = Path(root).resolve()
    if changed_paths is None:
        if base is None:
            raise RepositoryScopeError(
                "SCOPE_DIFF_UNAVAILABLE", "provide changed paths or a base ref"
            )
        raw_paths = _git_scope_paths(workspace, base, head or "HEAD")
    else:
        raw_paths = changed_paths
    paths = sorted({_scope_policy_path(path) for path in raw_paths})
    policy = _read_scope_policy(workspace, policy_path, policy_ref)
    blocked_segments = set(policy["blocked_path_segments"])
    blocked_paths = [
        {"path": path, "matched_segment": match}
        for path in paths
        if (match := _matches_scope_segment(path, blocked_segments)) is not None
    ]
    state = "blocked" if blocked_paths else "clear"
    return {
        "schema": REPOSITORY_SCOPE_REVIEW_SCHEMA,
        "marker": "REPOSITORY_SCOPE_BLOCKED"
        if blocked_paths
        else "REPOSITORY_SCOPE_CLEAR",
        "state": state,
        "base": base,
        "head": head or ("HEAD" if base is not None else None),
        "policy_path": policy_path.replace("\\", "/"),
        "policy_ref": policy_ref,
        "policy_sha256": _sha(policy).lower(),
        "changed_paths": paths,
        "blocked_paths": blocked_paths,
        "next_action": (
            {
                "action": "remove_or_rehome_unrelated_product_files",
                "paths": [item["path"] for item in blocked_paths],
                "reason": "These paths match a product boundary reserved by the trusted repository policy.",
            }
            if blocked_paths
            else {
                "action": "continue_review",
                "reason": "No changed path matched a reserved product boundary.",
            }
        ),
        "authority": {
            "execution": False,
            "approval": False,
            "merge": False,
            "publication": False,
            "deployment": False,
            "credential": False,
        },
        "scope_limits": [
            "This check classifies paths only; it cannot determine semantic relevance from file contents.",
            "Deletions are allowed so a change can remove files outside the repository's product boundary.",
            "Trusted enforcement requires the checker and policy to come from the protected base revision.",
        ],
    }


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


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


def _resolve_changed_paths(
    root: Path, base: str, changed: list[str] | None
) -> tuple[str, list[str]]:
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
        raise ChangeReviewError(
            "CHANGED_PATH_LIMIT",
            f"at most {MAX_CHANGED_PATHS} changed paths are supported",
        )
    return source, normalized


def _finding(kind: str, severity: str, message: str, **facts: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "message": message, "facts": facts}


def _findings(
    impact: dict[str, Any], coverage: dict[str, Any], risk: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
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
        return findings, {
            "action": "bind_changed_path_to_proof",
            "reason": finding["message"],
            "path": path,
        }

    for proof in impact["rerun_proofs"]:
        findings.append(
            _finding(
                "stale_proof",
                "required",
                "A declared proof input changed after the proof was recorded.",
                proof_id=proof["proof_id"],
                gates=proof["gates"],
            )
        )
    if findings:
        first = findings[0]
        return findings, {
            "action": "rerun_stale_proof",
            "reason": first["message"],
            "proof_id": first["facts"]["proof_id"],
        }

    if not coverage["ok"]:
        uncovered = list(coverage["uncovered"])
        finding = _finding(
            "coverage_incomplete",
            "required",
            "Requirement coverage is absent or incomplete; the review keeps that gap explicit.",
            uncovered=uncovered,
        )
        findings.append(finding)
        return findings, {
            "action": "complete_requirement_coverage",
            "reason": finding["message"],
            "requirements": uncovered,
        }

    stages = list(risk["rerun_stages"])
    if stages:
        finding = _finding(
            "policy_rerun_plan",
            "review",
            "Existing risk-diff policy recommends a plan-only validation sequence.",
            stages=stages,
        )
        findings.append(finding)
        return findings, {
            "action": "review_rerun_plan",
            "reason": finding["message"],
            "stage": stages[0],
        }

    finding = _finding(
        "ready_for_human_review",
        "info",
        "No declared proof, coverage, or policy gap was found.",
    )
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
        claims.append(
            f"Graph source `{error['source']}` is unavailable: `{error['code']}`."
        )
    return claims or [
        "No release, quality, or productivity outcome is claimed by this analysis-only review."
    ]


def _repository_scope_review(
    workspace: Path, changed_paths: list[str]
) -> dict[str, Any]:
    policy = workspace / ".factory" / "repository-scope.json"
    try:
        return check_repository_scope(workspace, changed_paths=changed_paths)
    except RepositoryScopeError as exc:
        if (
            exc.code == "SCOPE_POLICY_UNAVAILABLE"
            and not policy.exists()
            and not policy.is_symlink()
        ):
            return {
                "schema": "factory.repository_scope_review.v1",
                "state": "not_configured",
                "policy_path": ".factory/repository-scope.json",
                "blocked_paths": [],
            }
        return {
            "schema": "factory.repository_scope_review.error.v1",
            "state": "unavailable",
            "policy_path": ".factory/repository-scope.json",
            "error": {"code": exc.code, "message": str(exc)},
            "blocked_paths": [],
        }


def _apply_repository_scope_finding(
    scope: dict[str, Any], findings: list[dict[str, Any]], next_action: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if scope["state"] == "blocked":
        blocked = scope["blocked_paths"]
        finding = _finding(
            "repository_scope_violation",
            "blocking",
            "Changed paths cross a reserved repository product boundary.",
            paths=[item["path"] for item in blocked],
            matches=blocked,
        )
        return [finding, *findings], {
            "action": "remove_or_rehome_unrelated_product_files",
            "reason": finding["message"],
            "paths": [item["path"] for item in blocked],
        }
    if scope["state"] == "unavailable":
        finding = _finding(
            "repository_scope_unavailable",
            "blocking",
            "The configured repository scope policy could not be verified.",
            error=scope["error"],
        )
        return [finding, *findings], {
            "action": "repair_repository_scope_policy",
            "reason": finding["message"],
            "policy_path": scope["policy_path"],
        }
    return findings, next_action


def _apply_code_audit(
    workspace: Path,
    audit_policy: str | None,
    findings: list[dict[str, Any]],
    next_action: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    policy_path = audit_policy or ".factory/review-audits.json"
    code_audits: dict[str, Any] = {
        "state": "not_configured",
        "unconfigured_tools": ["patterns", "guard-paths"],
    }
    if audit_policy is not None or (workspace / policy_path).exists():
        try:
            code_audits = audit_code(workspace, policy_path)
        except ReviewAuditError as exc:
            raise ChangeReviewError(exc.code, str(exc)) from exc
        for item in code_audits["findings"]:
            findings.append(
                _finding(item["code"], "review", item["message"], audit=item)
            )
        if code_audits["state"] == "incomplete":
            findings.append(
                _finding(
                    "code_audit_incomplete",
                    "review",
                    "Code audit coverage has unresolved analysis gaps.",
                )
            )
    if (
        code_audits["state"] != "no_structural_findings"
        and next_action["action"] == "review_packet"
    ):
        findings = [
            finding
            for finding in findings
            if finding["kind"] != "ready_for_human_review"
        ]
        next_action = {
            "action": "review_code_audit",
            "reason": "Resolve pattern, guard-path or analysis-gap findings.",
        }
    return code_audits, findings, next_action


def _mermaid_label(value: object) -> str:
    text = re.sub(r"[^A-Za-z0-9._/: -]+", "?", str(value)).strip()
    return (text or "unknown")[:96]


def _review_mermaid(
    changed_paths: list[str], impact: dict[str, Any], findings: list[dict[str, Any]]
) -> str:
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
    findings = "\n".join(
        f"- **{item['severity']}** `{item['kind']}` — {item['message']}"
        for item in review["findings"]
    )
    stages = review["risk"]["rerun_stages"]
    stage_lines = (
        "\n".join(
            f"- `{item['module']}:{item['stage']}` — {'; '.join(item['reasons'])}"
            for item in stages
        )
        or "- No policy rerun stage was selected."
    )
    claims = "\n".join(f"- {claim}" for claim in review["unproven_claims"])
    return "\n".join(
        [
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
        ]
    )


def review_change(
    root: Path,
    base: str = "main",
    changed: list[str] | None = None,
    audit_policy: str | None = None,
) -> dict:
    """Compile a deterministic change review without executing a gate or writing files."""
    workspace = Path(root).resolve()
    input_source, changed_paths = _resolve_changed_paths(workspace, base, changed)
    impact = graph_ops_impact(workspace, changed_paths)
    coverage = requirement_coverage(workspace)
    risk = risk_for_paths(changed_paths)
    findings, next_action = _findings(impact, coverage, risk)
    repository_scope = _repository_scope_review(workspace, changed_paths)
    findings, next_action = _apply_repository_scope_finding(
        repository_scope, findings, next_action
    )
    code_audits, findings, next_action = _apply_code_audit(
        workspace, audit_policy, findings, next_action
    )
    scope_claims = [
        f"Repository scope policy blocks `{item['path']}` (reserved segment `{item['matched_segment']}`)."
        for item in repository_scope["blocked_paths"]
    ]
    if repository_scope["state"] == "unavailable":
        scope_claims.append(
            "Repository scope policy is configured but could not be verified."
        )
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
        ]
        + (
            ["DIFF_TO_PROOF_UNMATCHED_PRIORITY"]
            if impact["unmatched_changed_paths"]
            else []
        )
        + (
            ["DIFF_TO_PROOF_REPOSITORY_SCOPE_ENFORCED"]
            if repository_scope["state"] != "not_configured"
            else []
        ),
        "root": str(workspace),
        "base": base,
        "input_source": input_source,
        "changed_paths": changed_paths,
        "impact": impact,
        "coverage": coverage,
        "risk": risk,
        "code_audits": code_audits,
        "repository_scope": repository_scope,
        "findings": findings,
        "next_action": next_action,
        "unproven_claims": _unproven_claims(impact, coverage)
        + scope_claims
        + [
            f"Pattern and guard-path audit state: {code_audits['state']}; no runtime correctness or release approval is implied."
        ],
        "authority": AUTHORITY,
        "scope_limits": [
            "The review analyzes existing local facts and never executes a gate or replay plan.",
            "Risk recommendations are plan-only and do not prove a test has run.",
            "Missing coverage, unmatched paths, stale proofs, and source errors remain explicit.",
            "Repository product-boundary checks are path-based and run when a workspace scope policy exists.",
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
        raise ChangeReviewError(
            "REVIEW_INVALID", "a valid change-review payload is required"
        )
    destination = Path(out_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"change-review-{review['review_sha256'][:12]}"
    payload = {
        key: value
        for key, value in review.items()
        if key not in {"review_markdown", "mermaid", "artifacts"}
    }
    json_path = destination / f"{stem}.json"
    markdown_path = destination / f"{stem}.md"
    mermaid_path = destination / f"{stem}.mmd"
    paths = {"json": json_path, "markdown": markdown_path, "mermaid": mermaid_path}
    digests = {
        "json": _atomic_text(
            json_path,
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        ),
        "markdown": _atomic_text(markdown_path, review["review_markdown"]),
        "mermaid": _atomic_text(mermaid_path, review["mermaid"]),
    }
    return {
        "marker": "DIFF_TO_PROOF_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": digests,
    }

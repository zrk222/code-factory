"""Sealed Change List scopes, approved repair execution, and candidate checks.

Execution is limited to one explicitly approved patch in a disposable Git
worktree. Candidate checks run only in a digest-pinned, network-disabled Docker
container. This module never commits, merges, publishes, or deploys.
"""

from __future__ import annotations

from hashlib import sha256
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tempfile
import time
from typing import Any

from .assembly_process import run_cli_detailed
from .change_review import ChangeReviewError, review_change


REPAIR_SCOPE_SCHEMA = "factory.repair_scope.v1"
REPAIR_CANDIDATE_SCHEMA = "factory.repair_candidate.v1"
SANDBOX_EXECUTION_SCHEMA = "factory.sandbox-execution.v1"
REPAIR_DISPATCH_BINDING_SCHEMA = "factory.repair.dispatch-binding.v1"
MAX_CHANGE_LIST_NAME = 160
MAX_PATCH_BYTES = 1_000_000
DEFAULT_CONTEXT_BUDGET_BYTES = 262_144
_CORE_SCOPE_KEYS = (
    "schema",
    "change_list",
    "paths",
    "context_budget",
    "review",
    "verification",
    "candidate",
    "authority",
    "scope_limits",
)
_AUTHORITY = {
    "source_modify": False,
    "patch_apply": False,
    "test_execute": False,
    "commit": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "messaging": False,
    "credential": False,
    "connector": False,
    "network": False,
}
_ISOLATION_LEVELS = (
    "UNENFORCED",
    "SUPERVISED_LOCAL",
    "PROCESS_BOUNDARY",
    "CONTAINER_BOUNDARY",
    "REMOTE_SANDBOX_VERIFIED",
)
REPAIR_APPROVAL_SCHEMA = "factory.repair_approval.v2"
_LEGACY_REPAIR_APPROVAL_SCHEMA = "factory.repair_approval.v1"
REPAIR_ATTEMPT_SCHEMA = "factory.repair_attempt.v1"
_APPROVE_PREFIX = "APPROVE REPAIR "
_DOCKER_LIMITS = (
    "--network=none",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--read-only",
    "--pids-limit=128",
    "--memory=2g",
    "--cpus=2",
    "--user=65532:65532",
    "--workdir=/workspace",
)
_DEFAULT_PROTECTED = (
    ".factory/",
    ".github/",
    ".github/workflows/",
    ".circleci/",
    ".azure-pipelines/",
    ".buildkite/",
    "scripts/",
    "azure-pipelines.yml",
    ".pre-commit-config.yaml",
    "Makefile",
    "tests/",
    "test/",
    "__tests__/",
    "pyproject.toml",
    "pytest.ini",
    "tox.ini",
)


class RepairSandboxError(ValueError):
    """A closed, machine-readable repair-sandbox input failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _workspace(root: Path) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise RepairSandboxError(
            "REPAIR_SCOPE_ROOT_INVALID",
            f"root must be an existing directory: {workspace}",
        )
    return workspace


def _mount_safe_workspace(root: Path) -> Path:
    workspace = _workspace(root)
    if any(character in str(workspace) for character in (",", "\n", "\r", "\0")):
        raise RepairSandboxError(
            "REPAIR_MOUNT_PATH_INVALID",
            "workspace path cannot be represented safely as a Docker mount",
        )
    return workspace


def _relative_path(value: object, *, code: str = "REPAIR_SCOPE_PATH_REJECTED") -> str:
    if not isinstance(value, str):
        raise RepairSandboxError(
            code, "paths must be non-empty workspace-relative strings"
        )
    path = value.replace("\\", "/").strip().removeprefix("./").rstrip("/")
    if (
        not path
        or path.startswith("/")
        or re.match(r"^[A-Za-z]:/", path)
        or any(part in {"", ".."} for part in path.split("/"))
    ):
        raise RepairSandboxError(
            code,
            "paths must be non-empty workspace-relative paths without parent traversal",
        )
    return path


def _text(value: object, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise RepairSandboxError(
            "REPAIR_SCOPE_INPUT_INVALID",
            f"{label} must be a non-empty printable string of at most {maximum} characters",
        )
    return value.strip()


def _under_workspace(
    workspace: Path,
    value: Path,
    *,
    code: str = "REPAIR_SCOPE_PATH_REJECTED",
    file_only: bool = False,
) -> Path:
    candidate = Path(value).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise RepairSandboxError(
            code, "path must resolve inside the current workspace"
        ) from exc
    if file_only and not candidate.is_file():
        raise RepairSandboxError(
            code, "path must be an existing regular file inside the current workspace"
        )
    return candidate


def _baseline_entry(workspace: Path, relative: str) -> dict[str, Any]:
    candidate = _under_workspace(workspace, workspace / relative)
    if not candidate.exists():
        return {"path": relative, "exists": False, "size_bytes": 0, "sha256": None}
    if not candidate.is_file():
        raise RepairSandboxError(
            "REPAIR_SCOPE_PATH_REJECTED",
            f"scope path must be a regular file or a deletion: {relative}",
        )
    contents = candidate.read_bytes()
    return {
        "path": relative,
        "exists": True,
        "size_bytes": len(contents),
        "sha256": sha256(contents).hexdigest(),
    }


def _review_excerpt(review: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_sha256": review["review_sha256"],
        "changed_paths": review["changed_paths"],
        "next_action": review["next_action"],
        "findings": [
            {
                "severity": item["severity"],
                "kind": item["kind"],
                "message": item["message"],
            }
            for item in review["findings"]
        ],
        "unproven_claims": review["unproven_claims"],
        "rerun_stages": review["risk"]["rerun_stages"],
    }


def _required_checks(review: dict[str, Any]) -> list[dict[str, str]]:
    checks = [
        {
            "id": "scope_current",
            "kind": "deterministic",
            "description": "The selected Change List bytes still match the sealed scope before candidate review.",
        },
        {
            "id": "candidate_patch_scoped",
            "kind": "deterministic",
            "description": "Every file declared by the candidate patch remains inside the sealed Change List scope.",
        },
        {
            "id": "independent_verifier",
            "kind": "external_evidence_required",
            "description": "A distinct verifier must check the candidate with its own fresh evidence before any human applies it.",
        },
        {
            "id": "human_apply",
            "kind": "human_control_required",
            "description": "A maintainer must inspect the candidate diff and choose whether to apply it in the IDE.",
        },
    ]
    if review["risk"]["rerun_stages"]:
        checks.insert(
            2,
            {
                "id": "declared_validation_plan",
                "kind": "plan_only",
                "description": "The existing risk policy has a declared rerun plan; it remains unexecuted until independently run.",
            },
        )
    return checks


def _scope_core(scope: dict[str, Any]) -> dict[str, Any]:
    missing = [key for key in _CORE_SCOPE_KEYS if key not in scope]
    if missing:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID",
            f"scope is missing required fields: {', '.join(missing)}",
        )
    return {key: scope[key] for key in _CORE_SCOPE_KEYS}


def _context_budget(paths: list[dict[str, Any]], limit_bytes: int) -> dict[str, Any]:
    if (
        isinstance(limit_bytes, bool)
        or not isinstance(limit_bytes, int)
        or not 1 <= limit_bytes <= 100_000_000
    ):
        raise RepairSandboxError(
            "REPAIR_SCOPE_INPUT_INVALID",
            "context_budget_bytes must be an integer from 1 through 100000000",
        )
    measured = sum(item["size_bytes"] for item in paths)
    return {
        "limit_bytes": limit_bytes,
        "measured_bytes": measured,
        "file_count": len(paths),
        "missing_paths": sum(1 for item in paths if not item["exists"]),
        "decision": "within_budget" if measured <= limit_bytes else "split_recommended",
        "scope_limits": "Measured bytes only; this is not a token, provider-credit, latency, or quality estimate.",
    }


def create_repair_scope(
    root: Path,
    change_list: str,
    changed: list[str],
    *,
    context_budget_bytes: int = DEFAULT_CONTEXT_BUDGET_BYTES,
) -> dict[str, Any]:
    """Seal one explicit native Change List scope without writing or executing."""
    workspace = _workspace(root)
    name = _text(change_list, "change_list", MAX_CHANGE_LIST_NAME)
    if not changed:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INPUT_INVALID",
            "at least one explicit Change List path is required",
        )
    try:
        review = review_change(workspace, changed=changed)
    except ChangeReviewError as exc:
        raise RepairSandboxError(
            exc.code.replace("CHANGED_", "REPAIR_SCOPE_"), str(exc)
        ) from exc
    paths = [_baseline_entry(workspace, item) for item in review["changed_paths"]]
    core = {
        "schema": REPAIR_SCOPE_SCHEMA,
        "change_list": name,
        "paths": paths,
        "context_budget": _context_budget(paths, context_budget_bytes),
        "review": _review_excerpt(review),
        "verification": {"required_checks": _required_checks(review)},
        "candidate": {
            "state": "not_started",
            "runner": "external_supervised_runner_required",
            "apply": "human_confirmation_required",
            "reason": "FactoryLine has sealed the scope only; it has not created, executed, or applied a repair candidate.",
        },
        "authority": _AUTHORITY,
        "scope_limits": [
            "The scope is built from explicitly supplied Change List paths; no Git-wide collection occurs.",
            "Scope creation records current file bytes but does not create a worktree, call an AI model, edit source, or run a test.",
            "A candidate patch must remain in scope and obtain independent evidence before a maintainer decides whether to apply it.",
        ],
    }
    scope_sha256 = _sha(core)
    return {
        **core,
        "scope_id": f"repair-scope-{scope_sha256[:12]}",
        "scope_sha256": scope_sha256,
        "markers": [
            "REPAIR_SCOPE_EXPLICIT",
            "REPAIR_SCOPE_HASH_BOUND",
            "REPAIR_CONTEXT_BYTES_EXACT",
            "REPAIR_SCOPE_ARTIFACTS_OPTIONAL",
            "REPAIR_SCOPE_NO_IMPLICIT_RUNNER",
            "REPAIR_SANDBOX_HUMAN_APPLY_REQUIRED",
        ],
        "scope_markdown": _scope_markdown({**core, "scope_sha256": scope_sha256}),
        "mermaid": _scope_mermaid({**core, "scope_sha256": scope_sha256}),
    }


def _scope_digest(scope: dict[str, Any], core: dict[str, Any]) -> str:
    if core["schema"] != REPAIR_SCOPE_SCHEMA:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", f"scope must use schema {REPAIR_SCOPE_SCHEMA}"
        )
    supplied = scope.get("scope_sha256")
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "scope_sha256 must be a SHA-256 hexadecimal digest"
        )
    if _sha(core) != supplied:
        raise RepairSandboxError(
            "REPAIR_SCOPE_TAMPERED", "scope_sha256 does not match canonical scope bytes"
        )
    return supplied


def _scope_baseline(item: object, seen: set[str]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "scope paths must contain objects"
        )
    relative = _relative_path(item.get("path"))
    if relative in seen:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "scope paths must not repeat a path"
        )
    seen.add(relative)
    expected = _baseline_payload(item, relative)
    _validate_baseline_payload(expected)
    return expected


def _baseline_payload(item: dict[str, Any], relative: str) -> dict[str, Any]:
    return {
        "path": relative,
        "exists": item.get("exists"),
        "size_bytes": item.get("size_bytes"),
        "sha256": item.get("sha256"),
    }


def _valid_baseline_size(value: object) -> bool:
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _valid_baseline_presence(expected: dict[str, Any]) -> bool:
    present = not expected["exists"] or isinstance(expected["sha256"], str)
    missing = expected["exists"] or (
        expected["sha256"] is None and expected["size_bytes"] == 0
    )
    return present and missing


def _validate_baseline_payload(expected: dict[str, Any]) -> None:
    valid = (
        isinstance(expected["exists"], bool)
        and _valid_baseline_size(expected["size_bytes"])
        and _valid_baseline_presence(expected)
    )
    if not valid:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "scope path baseline is malformed"
        )


def _verify_scope_paths(workspace: Path, paths: object) -> None:
    if not isinstance(paths, list) or not paths:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "scope paths must be a non-empty list"
        )
    seen: set[str] = set()
    for item in paths:
        expected = _scope_baseline(item, seen)
        current = _baseline_entry(workspace, expected["path"])
        if current != expected:
            raise RepairSandboxError(
                "REPAIR_SCOPE_DRIFT",
                f"sealed scope bytes changed for {expected['path']}; prepare a new scope",
            )


def _verify_context_budget(value: object, paths: list[dict[str, Any]]) -> None:
    if not isinstance(value, dict):
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "context_budget must be an object"
        )
    expected = _context_budget(paths, value.get("limit_bytes"))
    if value != expected:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID",
            "context_budget must match sealed path byte baselines",
        )


def verify_repair_scope(scope: dict[str, Any], root: Path) -> dict[str, Any]:
    """Validate scope integrity and reject original Change List byte drift."""
    workspace = _workspace(root)
    core = _scope_core(scope)
    supplied = _scope_digest(scope, core)
    _verify_scope_paths(workspace, core["paths"])
    _verify_context_budget(core["context_budget"], core["paths"])
    return {**scope, "scope_id": f"repair-scope-{supplied[:12]}"}


def validate_repair_scope_envelope(scope: dict[str, Any]) -> dict[str, Any]:
    """Validate the sealed scope envelope without requiring pre-agent file bytes.

    This is the post-agent handoff validator: the envelope remains hash-bound,
    while the returned workspace is expected to differ from its pre-agent
    baselines. Path admission is evaluated separately against the sealed list.
    """
    core = _scope_core(scope)
    supplied = _scope_digest(scope, core)
    paths = core.get("paths")
    if not isinstance(paths, list) or not paths:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "scope paths must be a non-empty list"
        )
    seen: set[str] = set()
    normalized = [_scope_baseline(item, seen) for item in paths]
    _verify_context_budget(core["context_budget"], normalized)
    return {**scope, "scope_id": f"repair-scope-{supplied[:12]}"}


def _scope_mermaid(scope: dict[str, Any]) -> str:
    lines = ["flowchart LR", '  S["Sealed Change List scope"]']
    for index, item in enumerate(scope["paths"], 1):
        node = f"P{index}"
        state = "present" if item["exists"] else "deletion"
        label = re.sub(r"[^A-Za-z0-9._/: -]+", "?", item["path"])[:96]
        lines.extend((f'  {node}["{state}: {label}"]', f"  {node} --> S"))
    lines.extend(
        (
            '  C["External supervised candidate"]',
            '  V["Independent verifier evidence"]',
            '  H["Human diff review and apply"]',
            "  S --> C --> V --> H",
        )
    )
    return "\n".join(lines) + "\n"


def _scope_markdown(scope: dict[str, Any]) -> str:
    paths = "\n".join(
        f"- `{item['path']}` â€” {'present' if item['exists'] else 'expected deletion'}"
        for item in scope["paths"]
    )
    checks = "\n".join(
        f"- `{item['id']}` â€” {item['description']}"
        for item in scope["verification"]["required_checks"]
    )
    return "\n".join(
        (
            "# FactoryLine Repair Scope",
            "",
            f"Scope SHA-256: `{scope['scope_sha256']}`",
            f"Change List: `{scope['change_list']}`",
            f"Measured context: `{scope['context_budget']['measured_bytes']}` of `{scope['context_budget']['limit_bytes']}` bytes ({scope['context_budget']['decision']}; no token or credit estimate)",
            "",
            "## Sealed paths",
            "",
            paths,
            "",
            "## Fact-derived next action",
            "",
            f"- `{scope['review']['next_action']['action']}` â€” {scope['review']['next_action']['reason']}",
            "",
            "## Required before a human applies a candidate",
            "",
            checks,
            "",
            "## Boundary",
            "",
            "Scope preparation does not create or run a repair agent, modify source, apply a patch, execute tests, commit, publish, deploy, access credentials, or use a network service.",
            "",
        )
    )


def _atomic_text(path: Path, content: str) -> str:
    encoded = content.encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return sha256(encoded).hexdigest()


def _artifact_directory(root: Path, out_dir: Path) -> Path:
    return _under_workspace(_workspace(root), out_dir)


def write_repair_scope_artifacts(
    scope: dict[str, Any], root: Path, out_dir: Path
) -> dict[str, Any]:
    """Write a selected local scope packet after validating it against current bytes."""
    checked = verify_repair_scope(scope, root)
    destination = _artifact_directory(root, out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    stem = checked["scope_id"]
    json_path = destination / f"{stem}.json"
    markdown_path = destination / f"{stem}.md"
    mermaid_path = destination / f"{stem}.mmd"
    payload = {
        key: checked[key]
        for key in (*_CORE_SCOPE_KEYS, "scope_id", "scope_sha256", "markers")
    }
    paths = {"json": json_path, "markdown": markdown_path, "mermaid": mermaid_path}
    return {
        "marker": "REPAIR_SCOPE_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": {
            "json": _atomic_text(
                json_path,
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n",
            ),
            "markdown": _atomic_text(
                markdown_path, checked.get("scope_markdown") or _scope_markdown(checked)
            ),
            "mermaid": _atomic_text(
                mermaid_path, checked.get("mermaid") or _scope_mermaid(checked)
            ),
        },
    }


def _load_scope(root: Path, path: Path) -> dict[str, Any]:
    workspace = _workspace(root)
    scope_path = _under_workspace(workspace, path, file_only=True)
    try:
        value = json.loads(scope_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", f"cannot read scope packet: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise RepairSandboxError(
            "REPAIR_SCOPE_INVALID", "scope packet must be a JSON object"
        )
    return verify_repair_scope(value, workspace)


def _patch_path(value: str) -> str:
    prefix, separator, remainder = value.partition("/")
    if prefix not in {"a", "b"} or not separator:
        raise RepairSandboxError(
            "REPAIR_PATCH_UNSUPPORTED",
            "patch paths must use unquoted a/<path> or b/<path> Git headers",
        )
    if '"' in value or "\t" in value:
        raise RepairSandboxError(
            "REPAIR_PATCH_UNSUPPORTED",
            "quoted or tab-separated patch paths are not supported in this first candidate protocol",
        )
    return _relative_path(remainder, code="REPAIR_CANDIDATE_PATH_REJECTED")


def _patch_header_path(value: str, prefix: str) -> str | None:
    if value == "/dev/null":
        return None
    return (
        _patch_path(value)
        if value.startswith(f"{prefix}/")
        else _relative_path(value, code="REPAIR_PATCH_UNSUPPORTED")
    )


def _patch_text(patch: Path) -> list[str]:
    data = patch.read_bytes()
    if not data or len(data) > MAX_PATCH_BYTES:
        raise RepairSandboxError(
            "REPAIR_PATCH_INVALID",
            f"candidate patch must contain 1 through {MAX_PATCH_BYTES} bytes",
        )
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RepairSandboxError(
            "REPAIR_PATCH_UNSUPPORTED", "candidate patch must be UTF-8 text"
        ) from exc
    return lines


def _reject_unsupported_patch_line(line: str) -> None:
    if line.startswith(
        ("diff --combined ", "diff --cc ", "GIT binary patch", "Binary files ")
    ):
        raise RepairSandboxError(
            "REPAIR_PATCH_UNSUPPORTED",
            "combined or binary patches are not supported by the first candidate protocol",
        )


def _add_git_diff_paths(line: str, paths: set[str]) -> None:
    parts = line[len("diff --git ") :].split(" ")
    if len(parts) != 2:
        raise RepairSandboxError(
            "REPAIR_PATCH_UNSUPPORTED",
            "candidate patch must use exactly two unquoted Git diff paths",
        )
    paths.add(_patch_path(parts[0]))
    paths.add(_patch_path(parts[1]))


def _add_file_header_path(line: str, prefix: str, paths: set[str]) -> None:
    path = _patch_header_path(line[4:].strip(), prefix)
    if path is not None:
        paths.add(path)


def _patch_line_paths(line: str, paths: set[str]) -> int:
    _reject_unsupported_patch_line(line)
    if line.startswith("diff --git "):
        _add_git_diff_paths(line, paths)
        return 1
    if line.startswith("--- "):
        _add_file_header_path(line, "a", paths)
    elif line.startswith("+++ "):
        _add_file_header_path(line, "b", paths)
    elif line.startswith(("rename from ", "rename to ")):
        path = _relative_path(line.split(" ", 2)[2], code="REPAIR_PATCH_UNSUPPORTED")
        paths.add(path)
    return 0


def _validate_patch_path_summary(headers: int, paths: set[str]) -> list[str]:
    if headers == 0 or not paths:
        raise RepairSandboxError(
            "REPAIR_PATCH_INVALID",
            "candidate patch must contain at least one Git diff header",
        )
    return sorted(paths)


def _candidate_patch_paths(patch: Path) -> list[str]:
    lines = _patch_text(patch)
    paths: set[str] = set()
    headers = 0
    for line in lines:
        headers += _patch_line_paths(line, paths)
    return _validate_patch_path_summary(headers, paths)


def inspect_repair_candidate(
    root: Path, scope_path: Path, patch_path: Path
) -> dict[str, Any]:
    """Bind an external textual patch to a current sealed scope without applying it."""
    workspace = _workspace(root)
    scope = _load_scope(workspace, scope_path)
    patch = _under_workspace(
        workspace, patch_path, file_only=True, code="REPAIR_CANDIDATE_PATH_REJECTED"
    )
    touched = _candidate_patch_paths(patch)
    allowed = {item["path"] for item in scope["paths"]}
    outside = sorted(set(touched) - allowed)
    if outside:
        raise RepairSandboxError(
            "REPAIR_CANDIDATE_OUT_OF_SCOPE",
            f"candidate patch touches path(s) outside the sealed scope: {', '.join(outside)}",
        )
    core = {
        "schema": REPAIR_CANDIDATE_SCHEMA,
        "scope_sha256": scope["scope_sha256"],
        "patch": {
            "path": patch.relative_to(workspace).as_posix(),
            "sha256": sha256(patch.read_bytes()).hexdigest(),
        },
        "touched_paths": touched,
        "verification": {
            "state": "independent_verifier_required",
            "required_checks": scope["verification"]["required_checks"],
        },
        "apply": {
            "state": "human_confirmation_required",
            "reason": "The patch is scoped only. Inspect it in the IDE and require independent verifier evidence before applying it.",
        },
        "authority": _AUTHORITY,
        "scope_limits": [
            "Candidate inspection validates patch paths and current scope bytes; it does not apply the patch or execute a test.",
            "A scoped patch is not an approval, quality verdict, commit, merge, publication, or deployment decision.",
        ],
    }
    candidate_sha256 = _sha(core)
    return {
        **core,
        "candidate_sha256": candidate_sha256,
        "markers": [
            "REPAIR_CANDIDATE_PATCH_SCOPED",
            "REPAIR_CANDIDATE_ARTIFACTS_OPTIONAL",
            "REPAIR_CANDIDATE_NO_APPLY",
            "REPAIR_SANDBOX_HUMAN_APPLY_REQUIRED",
        ],
        "candidate_markdown": _candidate_markdown(
            {**core, "candidate_sha256": candidate_sha256}
        ),
    }


def _candidate_markdown(candidate: dict[str, Any]) -> str:
    paths = "\n".join(f"- `{path}`" for path in candidate["touched_paths"])
    return "\n".join(
        (
            "# FactoryLine Scoped Repair Candidate",
            "",
            f"Candidate SHA-256: `{candidate['candidate_sha256']}`",
            f"Scope SHA-256: `{candidate['scope_sha256']}`",
            f"Patch: `{candidate['patch']['path']}`",
            "",
            "## Touched paths",
            "",
            paths,
            "",
            "## Boundary",
            "",
            "The candidate is path-scoped only. FactoryLine did not apply it, run tests, create a commit, publish, deploy, use credentials, or call a network service. A distinct verifier and a human maintainer must decide the next step.",
            "",
        )
    )


def write_repair_candidate_artifacts(
    candidate: dict[str, Any], root: Path, out_dir: Path
) -> dict[str, Any]:
    """Write a selected local candidate receipt; it never applies its patch."""
    if candidate.get("schema") != REPAIR_CANDIDATE_SCHEMA or not isinstance(
        candidate.get("candidate_sha256"), str
    ):
        raise RepairSandboxError(
            "REPAIR_CANDIDATE_INVALID", "a valid repair candidate payload is required"
        )
    core = {
        key: candidate[key]
        for key in (
            "schema",
            "scope_sha256",
            "patch",
            "touched_paths",
            "verification",
            "apply",
            "authority",
            "scope_limits",
        )
        if key in candidate
    }
    if _sha(core) != candidate["candidate_sha256"]:
        raise RepairSandboxError(
            "REPAIR_CANDIDATE_TAMPERED",
            "candidate_sha256 does not match canonical candidate bytes",
        )
    destination = _artifact_directory(root, out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"repair-candidate-{candidate['candidate_sha256'][:12]}"
    json_path = destination / f"{stem}.json"
    markdown_path = destination / f"{stem}.md"
    payload = {
        **core,
        "candidate_sha256": candidate["candidate_sha256"],
        "markers": candidate.get("markers", []),
    }
    paths = {"json": json_path, "markdown": markdown_path}
    return {
        "marker": "REPAIR_CANDIDATE_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": {
            "json": _atomic_text(
                json_path,
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n",
            ),
            "markdown": _atomic_text(markdown_path, candidate["candidate_markdown"]),
        },
    }


def _execution_digest(value: object, label: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", f"{label} must be a SHA-256 digest"
        )


def _validate_execution_identity(
    scope_sha256: str, runner_id: str, isolation_level: str
) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", scope_sha256):
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", "scope_sha256 must be a SHA-256 digest"
        )
    if not isinstance(runner_id, str) or not runner_id.strip() or len(runner_id) > 160:
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", "runner_id is required and bounded"
        )
    if isolation_level not in _ISOLATION_LEVELS:
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", "isolation_level is unsupported"
        )


def _validate_execution_environment(
    runtime_digest: str,
    toolchain_digest: str,
    network_policy: str,
    teardown_status: str,
    executed: bool,
) -> None:
    for digest, label in (
        (runtime_digest, "runtime_digest"),
        (toolchain_digest, "toolchain_digest"),
    ):
        _execution_digest(digest, label)
    if network_policy not in {"none", "restricted", "unrestricted", "unknown"}:
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", "network_policy is unsupported"
        )
    if teardown_status not in {"complete", "incomplete", "unknown"}:
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", "teardown_status is unsupported"
        )
    if not isinstance(executed, bool):
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", "executed must be boolean"
        )


def _sorted_execution_digests(values: list[str]) -> list[str]:
    return sorted(set(values))


def _validate_execution_digests(values: list[str], label: str) -> None:
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in values
    ):
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", f"{label} must contain SHA-256 digests"
        )


def _execution_status(
    executed: bool, isolation_level: str, teardown_status: str
) -> str:
    if executed and isolation_level == "UNENFORCED":
        return "UNENFORCED"
    if executed and teardown_status != "complete":
        return "REVIEW_REQUIRED"
    if executed:
        return "OBSERVED"
    return "DECLARED_ONLY"


def _sandbox_execution_core(
    scope_sha256: str,
    runner_id: str,
    isolation_level: str,
    runtime_digest: str,
    toolchain_digest: str,
    network_policy: str,
    input_digests: list[str],
    output_digests: list[str],
    teardown_status: str,
    executed: bool,
    observed_at: str,
) -> dict[str, Any]:
    return {
        "schema": SANDBOX_EXECUTION_SCHEMA,
        "scope_sha256": scope_sha256,
        "runner_id": runner_id.strip(),
        "isolation_level": isolation_level,
        "runtime_digest": runtime_digest,
        "toolchain_digest": toolchain_digest,
        "network_policy": network_policy,
        "input_digests": input_digests,
        "output_digests": output_digests,
        "teardown_status": teardown_status,
        "executed": executed,
        "status": _execution_status(executed, isolation_level, teardown_status),
        "observed_at": observed_at.strip() if isinstance(observed_at, str) else "",
        "authority": dict(_AUTHORITY),
        "claim_boundary": "External runner observation only; this receipt does not create isolation, execute work, approve release, or prove provider identity.",
    }


def create_sandbox_execution_receipt(
    scope_sha256: str,
    *,
    runner_id: str,
    isolation_level: str,
    runtime_digest: str,
    toolchain_digest: str,
    network_policy: str,
    input_digests: list[str],
    output_digests: list[str],
    teardown_status: str,
    executed: bool = False,
    observed_at: str = "",
) -> dict[str, Any]:
    """Normalize externally supplied runner evidence without claiming isolation.

    This is deliberately an observation boundary: FactoryLine does not start a
    runner, create a container, or infer that a local process was isolated.
    """
    _validate_execution_identity(scope_sha256, runner_id, isolation_level)
    _validate_execution_environment(
        runtime_digest, toolchain_digest, network_policy, teardown_status, executed
    )
    normalized_inputs = _sorted_execution_digests(input_digests)
    normalized_outputs = _sorted_execution_digests(output_digests)
    _validate_execution_digests(normalized_inputs, "input_digests")
    _validate_execution_digests(normalized_outputs, "output_digests")
    core = _sandbox_execution_core(
        scope_sha256,
        runner_id,
        isolation_level,
        runtime_digest,
        toolchain_digest,
        network_policy,
        normalized_inputs,
        normalized_outputs,
        teardown_status,
        executed,
        observed_at,
    )
    digest = sha256(_canonical(core)).hexdigest()
    return {**core, "receipt_sha256": digest, "marker": "SANDBOX_EXECUTION_OBSERVED"}


def _sandbox_receipt_envelope(receipt: object) -> dict[str, Any]:
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != SANDBOX_EXECUTION_SCHEMA
    ):
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", f"receipt must use {SANDBOX_EXECUTION_SCHEMA}"
        )
    if receipt.get("marker") != "SANDBOX_EXECUTION_OBSERVED":
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_INVALID", "receipt marker is invalid"
        )
    return {
        key: value
        for key, value in receipt.items()
        if key not in {"receipt_sha256", "marker"}
    }


def _validate_sandbox_receipt_digest(
    receipt: dict[str, Any], core: dict[str, Any]
) -> None:
    if receipt.get("receipt_sha256") != sha256(_canonical(core)).hexdigest():
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_TAMPERED", "receipt digest does not match contents"
        )


def _validate_sandbox_authority(core: dict[str, Any]) -> None:
    if not isinstance(core.get("authority"), dict) or any(
        value is not False for value in core["authority"].values()
    ):
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_AUTHORITY", "receipt cannot grant authority"
        )


def _expected_sandbox_status(core: dict[str, Any]) -> str:
    return _execution_status(
        core["executed"], core["isolation_level"], core["teardown_status"]
    )


def verify_sandbox_execution_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Verify runner observation integrity and keep isolation claims explicit."""
    core = _sandbox_receipt_envelope(receipt)
    _validate_sandbox_receipt_digest(receipt, core)
    _validate_sandbox_authority(core)
    expected = _expected_sandbox_status(core)
    if core.get("status") != expected:
        raise RepairSandboxError(
            "SANDBOX_EXECUTION_TAMPERED", "receipt status does not match observations"
        )
    return {
        "schema": SANDBOX_EXECUTION_SCHEMA,
        "status": expected,
        "receipt_sha256": receipt["receipt_sha256"],
        "claim_boundary": core["claim_boundary"],
    }


def _utc(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise RepairSandboxError("REPAIR_APPROVAL_INVALID", f"{label} must be ISO-8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RepairSandboxError(
            "REPAIR_APPROVAL_INVALID", f"{label} must be ISO-8601"
        ) from exc
    if parsed.tzinfo is None:
        raise RepairSandboxError(
            "REPAIR_APPROVAL_INVALID", f"{label} must include a timezone"
        )
    return parsed.astimezone(timezone.utc)


def _process_environment() -> dict[str, str]:
    keep = (
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "DOCKER_CONFIG",
    )
    return {key: os.environ[key] for key in keep if key in os.environ}


def _run_process(
    cli: str,
    args: list[str],
    root: Path,
    timeout: float = 30,
    *,
    env: dict[str, str] | None = None,
) -> dict[str, object]:
    executable = shutil.which(cli)
    if not executable:
        raise RepairSandboxError(
            "REPAIR_TOOL_UNAVAILABLE", f"trusted {cli} executable was not found"
        )
    result = run_cli_detailed(
        executable,
        args,
        root,
        timeout=timeout,
        max_stream_bytes=1_000_000,
        env=env or _process_environment(),
    )
    if not result.get("cleanup_confirmed"):
        raise RepairSandboxError(
            "REPAIR_PROCESS_CLEANUP_UNKNOWN", f"{cli} process cleanup is unknown"
        )
    return result


def _tool_path(name: str) -> str:
    executable = shutil.which(name)
    if not executable:
        raise RepairSandboxError(
            "REPAIR_TOOL_UNAVAILABLE", f"trusted {name} executable was not found"
        )
    return str(Path(executable).resolve())


def _git(root: Path, args: list[str], timeout: float = 30) -> dict[str, object]:
    env = _process_environment()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
    with tempfile.TemporaryDirectory(
        prefix="factory-repair-git-policy-"
    ) as safe_config:
        flags = [
            "-c",
            f"core.hooksPath={safe_config}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "diff.external=",
        ]
        return _run_process("git", [*flags, *args], root, timeout, env=env)


def _reject_checkout_filters(root: Path) -> None:
    filters = _git(
        root,
        [
            "config",
            "--show-origin",
            "--get-regexp",
            r"^filter\..*\.(clean|smudge|process)$",
        ],
    )
    output = bytes(filters.get("stdout", b"")).decode("utf-8", errors="replace").lower()
    active = any(
        "filter.lfs." not in line or ".git/config " in line
        for line in output.splitlines()
    )
    if active:
        raise RepairSandboxError(
            "REPAIR_CHECKOUT_FILTER_REJECTED",
            "repository filter drivers are not allowed",
        )
    if filters.get("exit_code") not in {0, 1}:
        raise RepairSandboxError(
            "REPAIR_GIT_FAILED", "could not inspect repository filter configuration"
        )
    attributes = _git(root, ["ls-files", "-z"])
    info_attributes = _git_value(root, ["rev-parse", "--git-path", "info/attributes"])
    has_attributes = any(
        item.lower().endswith(b".gitattributes")
        for item in bytes(attributes.get("stdout", b"")).split(b"\0")
    )
    if not attributes.get("ok") or has_attributes or (root / info_attributes).exists():
        raise RepairSandboxError(
            "REPAIR_CHECKOUT_FILTER_REJECTED",
            "Git attributes may invoke checkout filters",
        )


def _reject_runtime_secrets(worktree: Path) -> None:
    tracked = _git(worktree, ["ls-files", "-z"])
    if not tracked.get("ok"):
        raise RepairSandboxError(
            "REPAIR_GIT_FAILED", "could not inspect tracked runtime inputs"
        )
    protected_names = {
        ".env",
        ".npmrc",
        ".netrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_rsa",
        "id_ed25519",
    }
    protected_dirs = {".aws", ".azure", ".ssh", ".gnupg"}
    for raw_path in bytes(tracked["stdout"]).split(b"\0"):
        parts = raw_path.decode("utf-8", errors="replace").lower().split("/")
        if any(part in protected_names or part in protected_dirs for part in parts):
            raise RepairSandboxError(
                "REPAIR_RUNTIME_SECRET_PATH",
                "tracked credential material cannot enter the container",
            )


def _git_value(root: Path, args: list[str]) -> str:
    result = _git(root, args)
    if not result.get("ok"):
        raise RepairSandboxError(
            "REPAIR_GIT_FAILED", str(result.get("output", "git failed"))
        )
    return bytes(result["stdout"]).decode("utf-8", errors="strict").strip()


def _clean_base(root: Path, expected: str | None = None) -> str:
    head = _git_value(root, ["rev-parse", "--verify", "HEAD"])
    status = _git(root, ["status", "--porcelain=v1", "--untracked-files=all"])
    if not status.get("ok"):
        raise RepairSandboxError(
            "REPAIR_GIT_FAILED", "could not inspect primary checkout"
        )
    if bytes(status["stdout"]).strip():
        detail = bytes(status["stdout"]).decode("utf-8", errors="replace").strip()
        raise RepairSandboxError(
            "REPAIR_CHECKOUT_DIRTY", f"primary checkout must be clean: {detail[:500]}"
        )
    if expected is not None and head != expected:
        raise RepairSandboxError(
            "REPAIR_BASE_STALE", "primary checkout base commit changed"
        )
    return head


def _digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _active_docker_context(root: Path) -> str:
    result = _run_process("docker", ["context", "show"], root)
    if not result.get("ok"):
        raise RepairSandboxError(
            "REPAIR_DOCKER_UNAVAILABLE", "Docker context is unavailable"
        )
    context = bytes(result["stdout"]).decode("utf-8", errors="replace").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context):
        raise RepairSandboxError(
            "REPAIR_DOCKER_CONTEXT_INVALID", "Docker context name is malformed"
        )
    return context


def _docker(
    root: Path, context: str, args: list[str], timeout: float = 30
) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", context):
        raise RepairSandboxError(
            "REPAIR_DOCKER_CONTEXT_INVALID", "Docker context name is malformed"
        )
    return _run_process("docker", ["--context", context, *args], root, timeout)


def _docker_identity(root: Path, context: str | None = None) -> dict[str, str]:
    selected = context or _active_docker_context(root)
    endpoint = _docker(
        root,
        selected,
        ["context", "inspect", "--format", "{{json .Endpoints.docker}}", selected],
    )
    info = _docker(root, selected, ["info", "--format", "{{.ID}}|{{.DockerRootDir}}"])
    if not endpoint.get("ok") or not info.get("ok"):
        raise RepairSandboxError(
            "REPAIR_DOCKER_UNAVAILABLE", "Docker engine identity could not be read"
        )
    host = _local_docker_endpoint(endpoint["stdout"])
    engine_id, docker_root = _docker_engine_info(info["stdout"])
    return {
        "context": selected,
        "endpoint": host,
        "engine_id": engine_id,
        "docker_root": docker_root,
    }


def _local_docker_endpoint(raw: bytes) -> str:
    try:
        endpoint_value = json.loads(bytes(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RepairSandboxError(
            "REPAIR_DOCKER_CONTEXT_INVALID", "Docker endpoint metadata is malformed"
        ) from exc
    host = endpoint_value.get("Host") if isinstance(endpoint_value, dict) else None
    if not isinstance(host, str) or not host.startswith(("npipe://", "unix://")):
        raise RepairSandboxError(
            "REPAIR_DOCKER_REMOTE_REJECTED", "only a local Docker engine is permitted"
        )
    return host


def _docker_engine_info(raw: bytes) -> tuple[str, str]:
    identity = bytes(raw).decode("utf-8", errors="replace").strip().split("|", 1)
    if len(identity) != 2 or not identity[0] or not identity[1]:
        raise RepairSandboxError(
            "REPAIR_DOCKER_CONTEXT_INVALID", "Docker engine identity is incomplete"
        )
    return identity[0], identity[1]


def _image_ref(
    root: Path, image: object, digest: object, context: str | None = None
) -> str:
    if not isinstance(image, str) or not re.fullmatch(r"[A-Za-z0-9._/:+-]+", image):
        raise RepairSandboxError(
            "REPAIR_IMAGE_INVALID", "container image name is invalid"
        )
    if not _digest(digest):
        raise RepairSandboxError(
            "REPAIR_IMAGE_UNPINNED", "container image must use a SHA-256 digest"
        )
    repository = _image_repository(image)
    reference = f"{repository}@sha256:{digest}"
    selected = context or _active_docker_context(root)
    result = _docker(
        root,
        selected,
        ["image", "inspect", "--format", "{{json .RepoDigests}}", reference],
    )
    if not result.get("ok"):
        raise RepairSandboxError(
            "REPAIR_DOCKER_UNAVAILABLE", "Docker image inspection failed"
        )
    try:
        digests = json.loads(bytes(result["stdout"]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RepairSandboxError(
            "REPAIR_IMAGE_INVALID", "Docker returned malformed image metadata"
        ) from exc
    if reference not in digests:
        raise RepairSandboxError(
            "REPAIR_IMAGE_DIGEST_MISMATCH",
            "image digest is not present in Docker metadata",
        )
    return reference


def _image_repository(image: str) -> str:
    prefix, separator, leaf = image.rpartition("/")
    name = leaf.rpartition(":")[0] if ":" in leaf else leaf
    return f"{prefix}{separator}{name}" if separator else name


def _normalize_checks(checks: object) -> list[dict[str, Any]]:
    if not isinstance(checks, list) or not 2 <= len(checks) <= 16:
        raise RepairSandboxError(
            "REPAIR_CHECKS_INVALID", "positive and negative checks are required"
        )
    normalized = []
    seen = set()
    for item in checks:
        if not isinstance(item, dict):
            raise RepairSandboxError("REPAIR_CHECKS_INVALID", "checks must be objects")
        if not _valid_check(item, seen):
            raise RepairSandboxError(
                "REPAIR_CHECKS_INVALID", "check identity, kind, or argv is malformed"
            )
        check_id, kind, argv, failure = (
            item["id"],
            item["kind"],
            item["argv"],
            item["failure"],
        )
        seen.add(check_id)
        normalized.append(
            {
                "id": check_id,
                "kind": kind,
                "argv": list(argv),
                "failure": {
                    "exit_code": failure["exit_code"],
                    "signature": failure["signature"],
                },
            }
        )
    if {item["kind"] for item in normalized} != {"positive", "negative"}:
        raise RepairSandboxError(
            "REPAIR_CHECKS_INVALID",
            "both positive and negative check kinds are required",
        )
    return normalized


def _valid_failure(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    code, signature = value.get("exit_code"), value.get("signature")
    return (
        isinstance(code, int)
        and not isinstance(code, bool)
        and 1 <= code <= 255
        and code not in {125, 126, 127}
        and isinstance(signature, str)
        and bool(signature.strip())
        and len(signature) <= 512
    )


def _valid_check(item: dict[str, Any], seen: set[str]) -> bool:
    check_id, kind, argv = item.get("id"), item.get("kind"), item.get("argv")
    valid_id = isinstance(check_id, str) and re.fullmatch(
        r"[a-z][a-z0-9_-]{0,47}", check_id
    )
    valid_argv = (
        isinstance(argv, list)
        and 0 < len(argv) <= 64
        and all(isinstance(arg, str) and arg and len(arg) <= 4096 for arg in argv)
    )
    return bool(
        valid_id
        and check_id not in seen
        and kind in {"positive", "negative"}
        and valid_argv
        and _valid_failure(item.get("failure"))
    )


def _protected_paths(paths: object) -> list[str]:
    if not isinstance(paths, list):
        raise RepairSandboxError(
            "REPAIR_PROTECTED_PATHS_INVALID", "protected_paths must be a list"
        )
    values = {item.lower() for item in _DEFAULT_PROTECTED}
    for item in paths:
        if not isinstance(item, str):
            raise RepairSandboxError(
                "REPAIR_PROTECTED_PATHS_INVALID", "protected paths must be strings"
            )
        directory = item.endswith(("/", "\\"))
        normalized = _relative_path(item, code="REPAIR_PROTECTED_PATHS_INVALID").lower()
        values.add(normalized + ("/" if directory else ""))
    return sorted(values)


def _check_protected(candidate: dict[str, Any], protected: list[str]) -> None:
    blocked = []
    for path in candidate["touched_paths"]:
        lowered = path.lower()
        parts = lowered.split("/")
        is_test = any(
            part in {"test", "tests", "__tests__", "spec", "specs"}
            or part.startswith("test_")
            or part.endswith("_test.py")
            for part in parts
        )
        if is_test or any(
            lowered == item.rstrip("/") or lowered.startswith(item)
            for item in protected
        ):
            blocked.append(path)
    if blocked:
        raise RepairSandboxError(
            "REPAIR_PROTECTED_PATH",
            f"candidate changes protected paths: {', '.join(blocked)}",
        )


def _approval_paths(root: Path, approval_sha: str) -> tuple[Path, Path]:
    directory = root / ".factory" / "repair-approvals"
    return (
        directory / f"{approval_sha}.json",
        directory / f"{approval_sha}.revoked.json",
    )


def _repair_origin_binding(root: Path, run_id: str | None) -> dict[str, Any] | None:
    if run_id is None:
        return None
    from .deep_audit import deep_run_status
    from .deep_audit_io import inventory_candidate

    try:
        run = deep_run_status(root, run_id)
        current = inventory_candidate(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RepairSandboxError(
            "REPAIR_ORIGIN_INVALID", "origin audit run could not be verified"
        ) from exc
    if run.get("observed_state") == "RUNNING":
        raise RepairSandboxError(
            "REPAIR_ORIGIN_ACTIVE", "origin audit must be paused or terminal"
        )
    if run.get("candidate_sha256") != current.get("candidate_sha256") or current.get(
        "gaps"
    ):
        raise RepairSandboxError(
            "REPAIR_ORIGIN_STALE", "workspace candidate differs from the origin audit"
        )
    return {
        "run_id": run_id,
        "candidate_sha256": run["candidate_sha256"],
        "manifest_sha256": run["manifest_sha256"],
        "event_sha256": run["event_sha256"],
        "sequence": run["sequence"],
    }


def _verify_repair_origin(root: Path, origin: object) -> dict[str, Any] | None:
    if origin is None:
        return None
    if not isinstance(origin, dict) or set(origin) != {
        "run_id",
        "candidate_sha256",
        "manifest_sha256",
        "event_sha256",
        "sequence",
    }:
        raise RepairSandboxError(
            "REPAIR_ORIGIN_INVALID", "approval origin binding is malformed"
        )
    binding = _repair_origin_binding(root, origin.get("run_id"))
    if binding != origin:
        raise RepairSandboxError(
            "REPAIR_ORIGIN_STALE", "origin audit changed after approval"
        )
    return binding


def create_repair_approval(
    root: Path,
    scope_path: Path,
    patch_path: Path,
    *,
    approved_by: str,
    confirmation: str,
    expires_at: str,
    container_image: str,
    container_digest: str,
    checks: list[dict[str, Any]],
    protected_paths: list[str] | None = None,
    audit_run_id: str | None = None,
) -> dict[str, Any]:
    """Persist an explicit approval bound to one candidate and exact tool contract."""
    workspace = _mount_safe_workspace(root)
    signer = _text(approved_by, "approved_by", 160)
    expiry = _utc(expires_at, "expires_at")
    if expiry <= datetime.now(timezone.utc):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_EXPIRED", "approval expiry must be in the future"
        )
    _reject_checkout_filters(workspace)
    base = _clean_base(workspace)
    engine_identity = _docker_identity(workspace)
    image = _image_ref(
        workspace, container_image, container_digest, engine_identity["context"]
    )
    scope_file = _under_workspace(workspace, scope_path, file_only=True)
    patch_file = _under_workspace(workspace, patch_path, file_only=True)
    scope = json.loads(scope_file.read_text(encoding="utf-8"))
    verify_repair_scope(scope, workspace)
    candidate = inspect_repair_candidate(workspace, scope_file, patch_file)
    protected = _protected_paths(protected_paths or [])
    _check_protected(candidate, protected)
    if confirmation != f"{_APPROVE_PREFIX}{candidate['candidate_sha256']}":
        raise RepairSandboxError(
            "REPAIR_APPROVAL_CONFIRMATION_REQUIRED",
            "exact candidate confirmation is required",
        )
    normalized = _normalize_checks(checks)
    origin = _repair_origin_binding(workspace, audit_run_id) if audit_run_id else None
    contract = {
        "checks": normalized,
        "docker_image": image,
        "flags": list(_DOCKER_LIMITS),
        "worktree_mount": "readonly",
        "environment": ["PYTHONDONTWRITEBYTECODE=1"],
        "timeout_seconds": 180,
        "total_timeout_seconds": 600,
        "max_output_bytes": 1_000_000,
        "engine_identity": engine_identity,
        "git_executable": _tool_path("git"),
        "docker_executable": _tool_path("docker"),
    }
    core = {
        "schema": REPAIR_APPROVAL_SCHEMA,
        "workspace": str(workspace).casefold(),
        "base_commit": base,
        "scope_path": scope_file.relative_to(workspace).as_posix(),
        "scope_sha256": scope["scope_sha256"],
        "patch_path": patch_file.relative_to(workspace).as_posix(),
        "patch_sha256": candidate["patch"]["sha256"],
        "candidate_sha256": candidate["candidate_sha256"],
        "origin_audit": origin,
        "touched_paths": candidate["touched_paths"],
        "protected_paths": protected,
        "tool_contract": contract,
        "tool_contract_sha256": _sha(contract),
        "approved_by": signer,
        "confirmation_sha256": sha256(confirmation.encode("utf-8")).hexdigest(),
        "approval_trust_boundary": "The filesystem owner records this explicit confirmation; approved_by is a label, not authenticated identity.",
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expiry.isoformat(),
        "single_use": True,
        "authority": {
            "patch_apply": True,
            "test_execute": True,
            "commit": False,
            "merge": False,
            "publish": False,
            "deploy": False,
            "network": False,
            "credentials": False,
        },
    }
    approval_sha = _sha(core)
    payload = {**core, "approval_sha256": approval_sha}
    approval_file, _ = _approval_paths(workspace, approval_sha)
    approval_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with approval_file.open("x", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError as exc:
        raise RepairSandboxError(
            "REPAIR_APPROVAL_EXISTS", "approval already exists"
        ) from exc
    return {
        "approval_sha256": approval_sha,
        "path": approval_file.relative_to(workspace).as_posix(),
        "state": "APPROVED_NOT_EXECUTED",
    }


def _read_approval(path: Path) -> dict[str, Any]:
    return _read_approval_snapshot(path)[0]


def _read_approval_snapshot(path: Path) -> tuple[dict[str, Any], str]:
    descriptor = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or getattr(before, "st_file_attributes", 0) & 0x400
            or before.st_size > 2_000_000
        ):
            raise RepairSandboxError(
                "REPAIR_APPROVAL_INVALID",
                "approval must be a bounded regular file",
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or getattr(opened, "st_file_attributes", 0) & 0x400
            or opened.st_size > 2_000_000
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise RepairSandboxError(
                "REPAIR_APPROVAL_INVALID",
                "opened approval is not a bounded regular file",
            )
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, 2_000_001 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 2_000_000:
                raise RepairSandboxError(
                    "REPAIR_APPROVAL_INVALID", "approval file exceeds size limit"
                )
        raw = b"".join(chunks)
        payload = json.loads(raw.decode("utf-8"))
    except RepairSandboxError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise RepairSandboxError(
            "REPAIR_APPROVAL_MISSING", "approval file missing or malformed"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_INVALID", "approval must be an object"
        )
    return payload, sha256(raw).hexdigest()


def _valid_engine_identity(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "context",
        "endpoint",
        "engine_id",
        "docker_root",
    }:
        return False
    endpoint = value.get("endpoint")
    if not all(isinstance(item, str) and item for item in value.values()):
        return False
    return (
        _local_endpoint(endpoint)
        and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value["context"]) is not None
    )


def _local_endpoint(value: str) -> bool:
    return value.startswith(("npipe://", "unix://"))


def _contract_limits_valid(value: dict[str, Any]) -> bool:
    limits = (
        value.get("timeout_seconds"),
        value.get("total_timeout_seconds"),
        value.get("max_output_bytes"),
    )
    return (
        value.get("flags") == list(_DOCKER_LIMITS)
        and value.get("worktree_mount") == "readonly"
        and value.get("environment") == ["PYTHONDONTWRITEBYTECODE=1"]
        and limits == (180, 600, 1_000_000)
    )


def _contract_tools_valid(value: dict[str, Any]) -> bool:
    return value.get("git_executable") == _tool_path("git") and value.get(
        "docker_executable"
    ) == _tool_path("docker")


def _contract_checks_valid(value: dict[str, Any]) -> bool:
    image = value.get("docker_image")
    if (
        not isinstance(image, str)
        or re.fullmatch(r"[A-Za-z0-9._/:+-]+@sha256:[0-9a-f]{64}", image) is None
    ):
        return False
    try:
        return _normalize_checks(value.get("checks")) == value.get("checks")
    except RepairSandboxError:
        return False


def _valid_tool_contract(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    keys = {
        "checks",
        "docker_image",
        "flags",
        "worktree_mount",
        "environment",
        "timeout_seconds",
        "total_timeout_seconds",
        "max_output_bytes",
        "engine_identity",
        "git_executable",
        "docker_executable",
    }
    if set(value) != keys:
        return False
    return (
        _contract_limits_valid(value)
        and _valid_engine_identity(value.get("engine_identity"))
        and _contract_tools_valid(value)
        and _contract_checks_valid(value)
    )


def _valid_approval_authority(approval: dict[str, Any]) -> bool:
    expected = {
        "patch_apply": True,
        "test_execute": True,
        "commit": False,
        "merge": False,
        "publish": False,
        "deploy": False,
        "network": False,
        "credentials": False,
    }
    return (
        approval.get("authority") == expected
        and approval.get("single_use") is True
        and approval.get("approval_trust_boundary")
        == "The filesystem owner records this explicit confirmation; approved_by is a label, not authenticated identity."
        and _protected_paths(approval.get("protected_paths"))
        == approval.get("protected_paths")
    )


def _verify_approval_origin_fields(approval: dict[str, Any]) -> None:
    if approval.get("schema") == REPAIR_APPROVAL_SCHEMA:
        origin = approval.get("origin_audit")
        if not _digest(approval.get("confirmation_sha256")):
            raise RepairSandboxError(
                "REPAIR_APPROVAL_TAMPERED", "confirmation digest is malformed"
            )
        if origin is not None and (
            not isinstance(origin, dict)
            or set(origin)
            != {
                "run_id",
                "candidate_sha256",
                "manifest_sha256",
                "event_sha256",
                "sequence",
            }
            or not all(
                _digest(origin.get(key))
                for key in ("candidate_sha256", "manifest_sha256", "event_sha256")
            )
            or type(origin.get("sequence")) is not int
            or origin["sequence"] < 1
            or not isinstance(origin.get("run_id"), str)
        ):
            raise RepairSandboxError(
                "REPAIR_APPROVAL_TAMPERED", "origin audit binding is malformed"
            )


def _verify_approval(approval: dict[str, Any]) -> str:
    supplied = approval.get("approval_sha256")
    core = {key: value for key, value in approval.items() if key != "approval_sha256"}
    try:
        valid_hash = _digest(supplied) and _sha(core) == supplied
    except (TypeError, ValueError):
        valid_hash = False
    if not _valid_approval_envelope(approval, core, valid_hash):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_TAMPERED", "approval is malformed or tampered"
        )
    expected_keys = {
        "schema",
        "workspace",
        "base_commit",
        "scope_path",
        "scope_sha256",
        "patch_path",
        "patch_sha256",
        "candidate_sha256",
        "touched_paths",
        "protected_paths",
        "tool_contract",
        "tool_contract_sha256",
        "approved_by",
        "approval_trust_boundary",
        "approved_at",
        "expires_at",
        "single_use",
        "authority",
    }
    if approval.get("schema") == REPAIR_APPROVAL_SCHEMA:
        expected_keys.add("origin_audit")
        expected_keys.add("confirmation_sha256")
    elif approval.get("schema") != _LEGACY_REPAIR_APPROVAL_SCHEMA:
        expected_keys.add("origin_audit")
    if set(core) != expected_keys:
        raise RepairSandboxError(
            "REPAIR_APPROVAL_TAMPERED", "approval fields are unsupported"
        )
    _verify_approval_origin_fields(approval)
    contract = approval.get("tool_contract")
    if not _valid_tool_contract(contract) or _sha(contract) != approval.get(
        "tool_contract_sha256"
    ):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_TAMPERED", "tool command contract changed"
        )
    if not _valid_approval_authority(approval):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_AUTHORITY", "protected path policy was weakened"
        )
    for key in ("scope_sha256", "patch_sha256", "candidate_sha256"):
        if not _digest(approval.get(key)):
            raise RepairSandboxError(
                "REPAIR_APPROVAL_INVALID", f"{key} must be a SHA-256 digest"
            )
    _utc(approval.get("expires_at"), "expires_at")
    return supplied


def _valid_approval_envelope(
    approval: dict[str, Any], core: dict[str, Any], valid_hash: bool
) -> bool:
    if (
        approval.get("schema")
        not in {
            REPAIR_APPROVAL_SCHEMA,
            _LEGACY_REPAIR_APPROVAL_SCHEMA,
        }
        or not valid_hash
    ):
        return False
    expected_keys = {
        "schema",
        "workspace",
        "base_commit",
        "scope_path",
        "scope_sha256",
        "patch_path",
        "patch_sha256",
        "candidate_sha256",
        "touched_paths",
        "protected_paths",
        "tool_contract",
        "tool_contract_sha256",
        "approved_by",
        "approval_trust_boundary",
        "approved_at",
        "expires_at",
        "single_use",
        "authority",
    }
    if approval.get("schema") == REPAIR_APPROVAL_SCHEMA:
        expected_keys.add("origin_audit")
        expected_keys.add("confirmation_sha256")
    return set(core) == expected_keys


def _assert_docker_engine(root: Path, expected: dict[str, str]) -> None:
    actual = _docker_identity(root, expected["context"])
    if actual != expected:
        raise RepairSandboxError(
            "REPAIR_DOCKER_ENGINE_CHANGED",
            "Docker engine identity changed after approval",
        )


def revoke_repair_approval(
    root: Path, approval_sha256: str, *, revoked_by: str, reason: str
) -> dict[str, Any]:
    """Persist revocation; active runners check the marker between bounded stages."""
    workspace = _workspace(root)
    if not _digest(approval_sha256):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_INVALID", "approval hash is malformed"
        )
    approval_file, revoked_file = _approval_paths(workspace, approval_sha256)
    approval = _read_approval(approval_file)
    _verify_approval(approval)
    record = {
        "revoked_by": _text(revoked_by, "revoked_by", 160),
        "reason": _text(reason, "reason", 500),
        "revoked_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with revoked_file.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
    except FileExistsError as exc:
        raise RepairSandboxError(
            "REPAIR_APPROVAL_REVOKED", "approval is already revoked"
        ) from exc
    return {"approval_sha256": approval_sha256, "state": "REVOKED"}


def request_repair_stop(
    root: Path, approval_sha256: str, *, requested_by: str, reason: str
) -> dict[str, Any]:
    """Record a durable stop request for the active attempt."""
    workspace = _workspace(root)
    directory = workspace / ".factory" / "repair-attempts" / approval_sha256
    state_path = directory / "state.json"
    if not _digest(approval_sha256) or not state_path.is_file():
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_MISSING", "active attempt does not exist"
        )
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("status") != "RUNNING":
        raise RepairSandboxError("REPAIR_ATTEMPT_NOT_RUNNING", "attempt is not running")
    stop = {
        "requested_by": _text(requested_by, "requested_by", 160),
        "reason": _text(reason, "reason", 500),
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    _atomic_text(
        directory / "stop.json",
        json.dumps(stop, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    return {"approval_sha256": approval_sha256, "state": "STOP_REQUESTED"}


def _persist_attempt(directory: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    sequence = state.get("event_sequence", 0) + 1
    previous = state.get("event_sha256")
    snapshot = {
        key: value
        for key, value in state.items()
        if key not in {"event_sequence", "event_sha256"}
    }
    core = {
        "sequence": sequence,
        "approval_sha256": state.get("approval_sha256"),
        "at": state["updated_at"],
        "phase": state.get("phase"),
        "status": state.get("status"),
        "check_count": len(state.get("checks", [])),
        "state_sha256": _sha(snapshot),
        "previous_sha256": previous,
    }
    event = {**core, "event_sha256": _sha(core)}
    _atomic_text(
        directory / f"event-{sequence:05d}.json",
        json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n",
    )
    state["event_sequence"] = sequence
    state["event_sha256"] = event["event_sha256"]
    _atomic_text(
        directory / "state.json",
        json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )


def _attempt_directory(workspace: Path, approval_sha256: str) -> Path:
    directory = workspace / ".factory" / "repair-attempts" / approval_sha256
    current = workspace
    for part in (".factory", "repair-attempts", approval_sha256):
        current = current / part
        info = current.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
        ):
            raise RepairSandboxError(
                "REPAIR_ATTEMPT_INTEGRITY", "linked attempt directory"
            )
    return directory


def _attempt_state_file(workspace: Path, approval_sha256: str) -> dict[str, Any]:
    from .deep_audit_io import local_file
    from .runtime_audit_common import RuntimeAuditError

    try:
        path = local_file(
            workspace, f".factory/repair-attempts/{approval_sha256}/state.json"
        )
    except RuntimeAuditError as exc:
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_INTEGRITY", "attempt state is missing or linked"
        ) from exc
    if path.stat().st_size > 2_000_000:
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_INTEGRITY", "attempt state exceeds size limit"
        )
    state = json.loads(path.read_text(encoding="utf-8"))
    sequence = state.get("event_sequence")
    if type(sequence) is not int or not 1 <= sequence <= 100_000:
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_INTEGRITY", "event sequence is invalid"
        )
    return state


def _attempt_events(
    workspace: Path, approval_sha256: str, sequence: int
) -> tuple[list, str]:
    from .deep_audit_io import local_file
    from .runtime_audit_common import RuntimeAuditError

    events, previous, total_bytes = [], None, 0
    for index in range(1, sequence + 1):
        relative = f".factory/repair-attempts/{approval_sha256}/event-{index:05d}.json"
        try:
            path = local_file(workspace, relative)
        except RuntimeAuditError as exc:
            raise RepairSandboxError(
                "REPAIR_ATTEMPT_INTEGRITY", "attempt event is missing or linked"
            ) from exc
        total_bytes += path.stat().st_size
        if path.stat().st_size > 8192 or total_bytes > 32_000_000:
            raise RepairSandboxError(
                "REPAIR_ATTEMPT_INTEGRITY", "attempt events exceed size limits"
            )
        event = json.loads(path.read_text(encoding="utf-8"))
        core = {key: value for key, value in event.items() if key != "event_sha256"}
        if (
            event.get("sequence") != index
            or event.get("approval_sha256") != approval_sha256
            or event.get("previous_sha256") != previous
            or event.get("event_sha256") != _sha(core)
        ):
            raise RepairSandboxError(
                "REPAIR_ATTEMPT_INTEGRITY", "attempt event chain is invalid"
            )
        previous = event["event_sha256"]
        events.append(event)
    return events, previous


def _verify_attempt_head(
    state: dict, events: list, sequence: int, previous: str
) -> None:
    snapshot = {
        key: value
        for key, value in state.items()
        if key not in {"event_sequence", "event_sha256"}
    }
    if (
        previous != state.get("event_sha256")
        or sequence != len(events)
        or events[-1].get("state_sha256") != _sha(snapshot)
    ):
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_INTEGRITY", "attempt state does not match its event head"
        )


def verify_repair_attempt_journal(root: Path, approval_sha256: str) -> dict[str, Any]:
    """Verify local attempt event ordering and current state binding; no authority."""
    if not _digest(approval_sha256):
        raise RepairSandboxError("REPAIR_ATTEMPT_INVALID", "approval hash is invalid")
    workspace = _workspace(root)
    _attempt_directory(workspace, approval_sha256)
    state = _attempt_state_file(workspace, approval_sha256)
    sequence = state["event_sequence"]
    events, head = _attempt_events(workspace, approval_sha256, sequence)
    _verify_attempt_head(state, events, sequence, head)
    return {"state": state, "events": events, "event_sha256": head}


def _persist_failure(
    attempt: Path, *, stopped: bool, code: str, phase: str
) -> dict[str, Any]:
    state = _read_attempt_state(attempt)
    state["status"] = "STOPPED" if stopped else "FAILED"
    state["phase"] = phase
    state["error"] = {
        "code": code,
        "message": f"Repair execution stopped safely during {phase}.",
    }
    _persist_attempt(attempt, state)
    return state


def _approval_live(
    root: Path, approval: dict[str, Any], revoked: Path, attempt: Path
) -> bool:
    valid_until = _utc(approval.get("expires_at"), "expires_at")
    return (
        not revoked.exists()
        and not (attempt / "stop.json").exists()
        and datetime.now(timezone.utc) < valid_until
    )


def _remove_container(root: Path, context: str, name: str) -> bool:
    args = ["ps", "-aq", "--filter", f"name=^{name}$"]
    listed = _docker(root, context, args)
    if not listed.get("ok"):
        return False
    container_id = bytes(listed["stdout"]).decode("utf-8", errors="replace").strip()
    if container_id:
        removed = _docker(root, context, ["rm", "--force", container_id])
        if not removed.get("ok"):
            return False
    checked = _docker(root, context, args)
    return bool(checked.get("ok")) and not bytes(checked["stdout"]).strip()


def _container_check(
    root: Path,
    worktree: Path,
    image: str,
    context: str,
    check: dict[str, Any],
    name: str,
    heartbeat,
) -> dict[str, Any]:
    existing = _docker(root, context, ["ps", "-aq", "--filter", f"name=^{name}$"])
    if not existing.get("ok"):
        raise RepairSandboxError(
            "REPAIR_DOCKER_UNAVAILABLE", "could not verify unique container name"
        )
    if bytes(existing["stdout"]).strip():
        raise RepairSandboxError(
            "REPAIR_CONTAINER_NAME_COLLISION", "generated container name already exists"
        )
    args = ["run", "--name", name, *_DOCKER_LIMITS]
    args.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])
    args.extend(
        [
            "--env=PYTHONDONTWRITEBYTECODE=1",
            "--mount",
            f"type=bind,src={worktree},dst=/workspace,readonly",
        ]
    )
    args.extend(["--entrypoint", check["argv"][0], image, *check["argv"][1:]])
    docker_args = ["--context", context, *args]
    try:
        result = run_cli_detailed(
            _tool_path("docker"),
            docker_args,
            root,
            heartbeat=heartbeat,
            timeout=180,
            max_stream_bytes=1_000_000,
            env=_process_environment(),
        )
    finally:
        cleanup = _remove_container(root, context, name)
    return {"result": result, "container_cleanup_confirmed": cleanup}


def _record_check(
    directory: Path,
    state: dict[str, Any],
    check: dict[str, Any],
    stage: str,
    outcome: dict[str, Any],
    unchanged: bool,
) -> bool:
    result = outcome["result"]
    stdout = bytes(result.get("stdout", b""))
    stderr = bytes(result.get("stderr", b""))
    body = b"STDOUT\n" + stdout + b"\nSTDERR\n" + stderr
    label = f"{stage}-{check['id']}"
    log_path = directory / f"{label}.log"
    log_path.write_bytes(body)
    combined = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    failing = stage == "baseline" or check["kind"] == "negative"
    code = result.get("exit_code")
    no_runner_failure = result.get("reason") is None
    failure_matches = (
        code == check["failure"]["exit_code"]
        and check["failure"]["signature"] in combined
    )
    expected = failure_matches if failing else code == 0
    passed = (
        expected
        and unchanged
        and no_runner_failure
        and bool(result.get("cleanup_confirmed"))
        and bool(outcome["container_cleanup_confirmed"])
    )
    record = {
        "check_id": check["id"],
        "stage": stage,
        "exit_code": result.get("exit_code"),
        "process_cleanup_confirmed": bool(result.get("cleanup_confirmed")),
        "container_cleanup_confirmed": outcome["container_cleanup_confirmed"],
        "worktree_unchanged": unchanged,
        "log": log_path.name,
        "log_sha256": sha256(body).hexdigest(),
        "expected": "failure" if failing else "success",
        "result": "PASS" if passed else "FAIL",
    }
    state["checks"].append(record)
    _persist_attempt(directory, state)
    return bool(passed)


def _worktree_cleanup(root: Path, worktree: Path, temporary: Path) -> bool:
    removed = _git(root, ["worktree", "remove", "--force", str(worktree)], 60)
    if not removed.get("ok"):
        return False
    pruned = _git(root, ["worktree", "prune", "--expire", "now"], 60)
    listed = _git(root, ["worktree", "list", "--porcelain"], 60)
    output = bytes(listed.get("stdout", b"")).decode("utf-8", errors="replace")
    if (
        not pruned.get("ok")
        or not listed.get("ok")
        or str(worktree).casefold() in output.casefold()
        or worktree.exists()
    ):
        return False
    try:
        temporary.rmdir()
    except OSError:
        return False
    return not temporary.exists()


def _verify_approved_candidate(root: Path, approval: dict[str, Any]) -> None:
    if str(root).casefold() != approval.get("workspace"):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_WRONG_WORKSPACE", "approval belongs to another workspace"
        )
    scope_file = _under_workspace(root, root / approval["scope_path"], file_only=True)
    patch_file = _under_workspace(root, root / approval["patch_path"], file_only=True)
    if sha256(patch_file.read_bytes()).hexdigest() != approval["patch_sha256"]:
        raise RepairSandboxError(
            "REPAIR_CANDIDATE_STALE", "patch changed after approval"
        )
    scope = json.loads(scope_file.read_text(encoding="utf-8"))
    verify_repair_scope(scope, root)
    candidate = inspect_repair_candidate(root, scope_file, patch_file)
    if (
        scope.get("scope_sha256") != approval["scope_sha256"]
        or candidate["candidate_sha256"] != approval["candidate_sha256"]
        or candidate["patch"]["sha256"] != approval["patch_sha256"]
    ):
        raise RepairSandboxError(
            "REPAIR_CANDIDATE_STALE",
            "scope, patch, or candidate changed after approval",
        )
    _check_protected(candidate, approval["protected_paths"])


def _load_host_repair_approval(root: Path, approval_path: Path):
    workspace = _mount_safe_workspace(root)
    approval_file = _under_workspace(workspace, approval_path, file_only=True)
    approval, approval_file_sha = _read_approval_snapshot(approval_file)
    approval_sha = _verify_approval(approval)
    expected_file, revoked_file = _approval_paths(workspace, approval_sha)
    expiry = _utc(approval.get("expires_at"), "expires_at")
    if (
        approval.get("schema") != REPAIR_APPROVAL_SCHEMA
        or approval_file != expected_file
        or revoked_file.exists()
        or expiry <= datetime.now(timezone.utc)
    ):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_REJECTED",
            "host dispatch requires a current, unrevoked v2 approval at its bound path",
        )
    _verify_approved_candidate(workspace, approval)
    origin = _verify_repair_origin(workspace, approval.get("origin_audit"))
    return (
        workspace,
        approval_file,
        approval,
        approval_sha,
        approval_file_sha,
        revoked_file,
        origin,
    )


def repair_dispatch_evidence(
    root: Path, approval_path: Path, *, tenant_id: str, requester: str
) -> dict[str, Any]:
    """Build current tenant evidence for a host's independent repair approval request.

    The caller must store this object through the authenticated control plane.
    It does not authenticate the named requester or grant execution authority.
    """
    from .control_plane import ControlPlaneError

    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ControlPlaneError("E_TENANT_REQUIRED", "tenant id is required")
    if not isinstance(requester, str) or not requester.strip():
        raise ControlPlaneError("E_IDENTITY_REQUIRED", "requester is required")
    _, _, approval, approval_sha, approval_file_sha, _, _ = _load_host_repair_approval(
        root, approval_path
    )
    return _repair_dispatch_binding(
        approval, approval_sha, approval_file_sha, tenant_id, requester
    )


def _repair_dispatch_binding(
    approval, approval_sha, approval_file_sha, tenant_id, requester
):
    return {
        "schema": REPAIR_DISPATCH_BINDING_SCHEMA,
        "action": "repair.execute",
        "tenant_id": tenant_id,
        "requester": requester.strip(),
        "repair_approval_sha256": approval_sha,
        "repair_approval_file_sha256": approval_file_sha,
        "candidate_sha256": approval["candidate_sha256"],
        "scope_sha256": approval["scope_sha256"],
        "patch_sha256": approval["patch_sha256"],
        "tool_contract_sha256": approval["tool_contract_sha256"],
        "origin_audit": approval.get("origin_audit"),
        "expires_at": approval["expires_at"],
    }


def _current_dispatch_principal(principal, tenant_id, resolve_principal):
    from .control_plane import ControlPlaneError, Principal, authorize

    if not isinstance(principal, Principal) or principal.tenant_id != tenant_id:
        raise ControlPlaneError(
            "E_TENANT_BOUNDARY",
            "host-authenticated caller is not in the requested tenant",
        )
    if not callable(resolve_principal):
        raise ControlPlaneError(
            "E_IDENTITY_REQUIRED", "host current-identity resolver is required"
        )
    current = resolve_principal(principal.subject, tenant_id)
    if (
        not isinstance(current, Principal)
        or current.subject != principal.subject
        or current.tenant_id != tenant_id
    ):
        raise ControlPlaneError(
            "E_IDENTITY_REQUIRED", "current caller identity or tenant differs"
        )
    authorize(current, "repair.execute", tenant_id)
    return current


def execute_workflow_approved_repair(
    root: Path,
    approval_path: Path,
    *,
    principal,
    tenant_id: str,
    workflow_approval_id: str,
    evidence_store,
    resolve_principal,
) -> dict[str, Any]:
    """Dispatch only after current host identity and durable independent approval.

    `principal` must come from the host authentication dependency; constructing a
    Principal from request JSON is not authentication. The local CLI intentionally
    continues to expose only the separate filesystem-owner approval boundary.
    """
    current = _current_dispatch_principal(principal, tenant_id, resolve_principal)
    workspace, approval_file, approval, approval_sha, approval_file_sha, _, _ = (
        _load_host_repair_approval(root, approval_path)
    )
    expected = _repair_dispatch_binding(
        approval, approval_sha, approval_file_sha, tenant_id, current.subject
    )
    verifier = evidence_store.workflow_approval_verifier(
        current,
        tenant_id,
        workflow_approval_id,
        resolve_principal=resolve_principal,
        require_requester=True,
    )
    verifier(expected)
    _current_dispatch_principal(current, tenant_id, resolve_principal)
    result = execute_approved_repair(
        workspace,
        approval_file,
        expected_approval_sha256=approval_sha,
        expected_approval_file_sha256=approval_file_sha,
    )
    return _verify_host_dispatch_result(workspace, approval, approval_sha, result)


def _verify_host_dispatch_result(workspace, approval, approval_sha, result):
    journal = verify_repair_attempt_journal(workspace, approval_sha)
    state = journal["state"]
    expected_origin = approval.get("origin_audit")
    expected_candidate = (
        expected_origin["candidate_sha256"] if expected_origin is not None else None
    )
    if (
        result.get("approval_sha256") != approval_sha
        or result.get("status") != state.get("status")
        or result.get("event_sequence") != state.get("event_sequence")
        or result.get("event_sha256") != journal.get("event_sha256")
        or state.get("approval_sha256") != approval_sha
        or state.get("origin_audit") != expected_origin
        or state.get("candidate_before_sha256") != expected_candidate
    ):
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_INTEGRITY",
            "dispatched attempt receipt differs from its verified journal",
        )
    return result


def _run_stage(
    root: Path,
    attempt: Path,
    worktree: Path,
    approval: dict[str, Any],
    image: str,
    checks: list[dict[str, Any]],
    stage: str,
    heartbeat,
    deadline: float,
) -> None:
    contract = approval["tool_contract"]
    _assert_docker_engine(root, contract["engine_identity"])
    context = contract["engine_identity"]["context"]
    selected = [
        item for item in checks if stage != "baseline" or item["kind"] == "positive"
    ]
    for check in selected:
        _require_live(heartbeat, deadline)
        suffix = "b" if stage == "baseline" else "r"
        name = f"fr-{secrets.token_hex(6)}-{suffix}"
        before = _tree_fingerprint(worktree)
        outcome = _container_check(
            root, worktree, image, context, check, name, heartbeat
        )
        unchanged = before == _tree_fingerprint(worktree)
        passed = _record_check(
            attempt, _read_attempt_state(attempt), check, stage, outcome, unchanged
        )
        if not heartbeat():
            _require_live(heartbeat, deadline)
        if not passed:
            code = (
                "REPAIR_SANDBOX_SOURCE_MUTATED"
                if not unchanged
                else "REPAIR_BASELINE_NOT_REPRODUCED"
                if stage == "baseline"
                else "REPAIR_CHECK_FAILED"
            )
            raise RepairSandboxError(
                code,
                f"check {check['id']} changed source or missed its expected {stage} result",
            )


def _require_live(heartbeat, deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_BUDGET_EXHAUSTED",
            "total attempt budget of 600 seconds expired",
        )
    if not heartbeat():
        raise RepairSandboxError(
            "REPAIR_ATTEMPT_STOPPED", "approval expired, revoked, or stop requested"
        )


def _read_attempt_state(directory: Path) -> dict[str, Any]:
    return json.loads((directory / "state.json").read_text(encoding="utf-8"))


def _tree_fingerprint(worktree: Path) -> str:
    tracked = _git(worktree, ["ls-files", "-z"])
    status = _git(worktree, ["status", "--porcelain=v1", "--untracked-files=all"])
    if not tracked.get("ok") or not status.get("ok"):
        raise RepairSandboxError(
            "REPAIR_TREE_INSPECTION_FAILED", "worktree contents could not be inspected"
        )
    entries = []
    for raw_path in bytes(tracked["stdout"]).split(b"\0"):
        if not raw_path:
            continue
        relative = raw_path.decode("utf-8", errors="strict")
        path = _under_workspace(worktree, worktree / relative)
        entries.append(
            {
                "path": relative,
                "sha256": sha256(path.read_bytes()).hexdigest()
                if path.is_file()
                else None,
            }
        )
    return _sha(
        {
            "tracked": entries,
            "status": bytes(status["stdout"]).decode("utf-8", errors="replace"),
        }
    )


def _apply_candidate(worktree: Path, attempt: Path) -> None:
    patch = attempt / "candidate.patch"
    checked = _git(worktree, ["apply", "--check", str(patch)])
    if not checked.get("ok"):
        raise RepairSandboxError(
            "REPAIR_PATCH_REJECTED",
            str(checked.get("output", "git apply --check failed")),
        )
    applied = _git(worktree, ["apply", str(patch)])
    if not applied.get("ok"):
        raise RepairSandboxError(
            "REPAIR_PATCH_APPLY_FAILED", str(applied.get("output", "git apply failed"))
        )


def _attempt_state(
    approval_sha: str, origin: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "schema": REPAIR_ATTEMPT_SCHEMA,
        "approval_sha256": approval_sha,
        "status": "RUNNING",
        "phase": "VALIDATING",
        "checks": [],
        "origin_audit": origin,
        "candidate_before_sha256": None,
        "candidate_after_sha256": None,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }


def _begin_attempt(
    directory: Path, approval_sha: str, origin: dict[str, Any] | None = None
) -> dict[str, Any]:
    directory.parent.mkdir(parents=True, exist_ok=True)
    try:
        directory.mkdir()
    except FileExistsError as exc:
        raise RepairSandboxError(
            "REPAIR_APPROVAL_ALREADY_USED",
            "single-use approval has already been consumed",
        ) from exc
    state = _attempt_state(approval_sha, origin)
    _persist_attempt(directory, state)
    return state


def _finish_attempt(
    root: Path,
    directory: Path,
    state: dict[str, Any],
    base: str | None,
    worktree: Path | None,
    temporary: Path | None,
) -> None:
    cleanup = temporary is None
    if temporary is not None and worktree is not None:
        try:
            if worktree.exists():
                cleanup = _worktree_cleanup(root, worktree, temporary)
            else:
                temporary.rmdir()
                cleanup = not temporary.exists()
        except (OSError, RepairSandboxError):
            cleanup = False
    try:
        unchanged = base is not None and _clean_base(root, base) == base
    except RepairSandboxError:
        unchanged = False
    state["cleanup_confirmed"] = cleanup
    state["primary_checkout_unchanged"] = unchanged
    if not cleanup or not unchanged:
        state["status"] = "FAILED"
        state["phase"] = "CLEANUP_OR_PRIMARY_CHECKOUT_UNVERIFIED"
    _persist_attempt(directory, state)


def _prepare_repair_attempt(
    workspace: Path,
    attempt: Path,
    approval: dict,
    state: dict,
    revoked_file: Path,
    deadline: float,
    resources: dict,
) -> tuple:
    _reject_checkout_filters(workspace)
    base = _clean_base(workspace, approval["base_commit"])
    resources["base"] = base
    _verify_approved_candidate(workspace, approval)
    origin = approval.get("origin_audit")
    if origin is not None:
        current = _repair_origin_binding(workspace, origin["run_id"])
        if current != origin:
            raise RepairSandboxError(
                "REPAIR_ORIGIN_STALE", "origin audit changed before execution"
            )
        state["candidate_before_sha256"] = origin["candidate_sha256"]
        _persist_attempt(attempt, state)
    contract = approval["tool_contract"]
    _assert_docker_engine(workspace, contract["engine_identity"])
    image_name, image_digest = contract["docker_image"].rsplit("@sha256:", 1)
    image = _image_ref(
        workspace, image_name, image_digest, contract["engine_identity"]["context"]
    )
    patch = (workspace / approval["patch_path"]).read_bytes()
    if sha256(patch).hexdigest() != approval["patch_sha256"]:
        raise RepairSandboxError(
            "REPAIR_CANDIDATE_STALE", "patch changed before execution"
        )
    (attempt / "candidate.patch").write_bytes(patch)
    _reject_checkout_filters(workspace)
    temporary = attempt / "execution"
    resources["temporary"] = temporary
    temporary.mkdir()
    worktree = temporary / "checkout"
    resources["worktree"] = worktree
    created = _git(workspace, ["worktree", "add", "--detach", str(worktree), base], 120)
    if not created.get("ok"):
        raise RepairSandboxError(
            "REPAIR_WORKTREE_CREATE_FAILED",
            str(created.get("output", "git worktree add failed")),
        )
    _reject_runtime_secrets(worktree)

    def heartbeat() -> bool:
        return (
            _approval_live(workspace, approval, revoked_file, attempt)
            and time.monotonic() < deadline
        )

    return image, heartbeat


def _run_repair_stages(
    workspace: Path,
    attempt: Path,
    worktree: Path,
    approval: dict,
    image: str,
    heartbeat,
    deadline: float,
    state: dict,
) -> dict:
    checks = approval["tool_contract"]["checks"]
    state["phase"] = "BASELINE"
    _persist_attempt(attempt, state)
    _run_stage(
        workspace,
        attempt,
        worktree,
        approval,
        image,
        checks,
        "baseline",
        heartbeat,
        deadline,
    )
    state = _read_attempt_state(attempt)
    state["phase"] = "PATCH_APPLY"
    _persist_attempt(attempt, state)
    _require_live(heartbeat, deadline)
    _apply_candidate(worktree, attempt)
    if state.get("origin_audit") is not None:
        from .deep_audit_io import inventory_candidate

        inventory = inventory_candidate(worktree)
        if inventory.get("gaps"):
            raise RepairSandboxError(
                "REPAIR_RESULT_INCOMPLETE",
                "patched worktree candidate inventory has unresolved gaps",
            )
        state["candidate_after_sha256"] = inventory["candidate_sha256"]
    state["phase"] = "REPAIRED_CHECKS"
    _persist_attempt(attempt, state)
    _run_stage(
        workspace,
        attempt,
        worktree,
        approval,
        image,
        checks,
        "repaired",
        heartbeat,
        deadline,
    )
    state = _read_attempt_state(attempt)
    state["status"], state["phase"] = "VERIFIED", "VERIFIED"
    _persist_attempt(attempt, state)
    return state


def _execute_repair_lifecycle(
    workspace: Path,
    attempt: Path,
    approval: dict,
    origin: dict | None,
    revoked_file: Path,
    state: dict,
) -> tuple:
    deadline = time.monotonic() + 600
    resources = {"base": None, "temporary": None, "worktree": None}
    try:
        image, heartbeat = _prepare_repair_attempt(
            workspace, attempt, approval, state, revoked_file, deadline, resources
        )
        state = _run_repair_stages(
            workspace,
            attempt,
            resources["worktree"],
            approval,
            image,
            heartbeat,
            deadline,
            state,
        )
    except RepairSandboxError as exc:
        state = _persist_failure(
            attempt,
            stopped=exc.code
            in {"REPAIR_ATTEMPT_STOPPED", "REPAIR_ATTEMPT_BUDGET_EXHAUSTED"},
            code=exc.code,
            phase=exc.code,
        )
    except Exception:
        state = _persist_failure(
            attempt,
            stopped=False,
            code="REPAIR_EXECUTOR_ERROR",
            phase="UNEXPECTED_EXECUTOR_ERROR",
        )
    except BaseException:
        state = _persist_failure(
            attempt,
            stopped=True,
            code="REPAIR_EXECUTOR_INTERRUPTED",
            phase="INTERRUPTED",
        )
        raise
    finally:
        _finish_attempt(
            workspace,
            attempt,
            state,
            resources["base"],
            resources["worktree"],
            resources["temporary"],
        )
    return _read_attempt_state(attempt)


def execute_approved_repair(
    root: Path,
    approval_path: Path,
    *,
    expected_approval_sha256: str | None = None,
    expected_approval_file_sha256: str | None = None,
) -> dict[str, Any]:
    """Run locally owner-approved checks; this path does not authenticate identity."""
    workspace = _mount_safe_workspace(root)
    approval_file = _under_workspace(workspace, approval_path, file_only=True)
    approval, approval_file_sha = _read_approval_snapshot(approval_file)
    approval_sha = _verify_approval(approval)
    if (
        expected_approval_sha256 is not None
        and approval_sha != expected_approval_sha256
    ):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_CHANGED", "approval changed after host verification"
        )
    if (
        expected_approval_file_sha256 is not None
        and approval_file_sha != expected_approval_file_sha256
    ):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_CHANGED",
            "approval file bytes changed after host verification",
        )
    expected_file, revoked_file = _approval_paths(workspace, approval_sha)
    expiry = _utc(approval.get("expires_at"), "expires_at")
    if (
        approval_file != expected_file
        or revoked_file.exists()
        or expiry <= datetime.now(timezone.utc)
    ):
        raise RepairSandboxError(
            "REPAIR_APPROVAL_REJECTED",
            "approval is expired, revoked, or stored unexpectedly",
        )
    _verify_approved_candidate(workspace, approval)
    attempt = workspace / ".factory" / "repair-attempts" / approval_sha
    origin = _verify_repair_origin(workspace, approval.get("origin_audit"))
    _begin_attempt(attempt, approval_sha, origin)
    state = _execute_repair_lifecycle(
        workspace, attempt, approval, origin, revoked_file, _read_attempt_state(attempt)
    )
    return {
        "schema": REPAIR_ATTEMPT_SCHEMA,
        "attempt_path": (attempt / "state.json").relative_to(workspace).as_posix(),
        "approval_sha256": approval_sha,
        "status": state["status"],
        "state": state["status"],
        "phase": state["phase"],
        "cleanup_confirmed": state.get("cleanup_confirmed"),
        "primary_checkout_unchanged": state.get("primary_checkout_unchanged"),
        "origin_audit": state.get("origin_audit"),
        "candidate_before_sha256": state.get("candidate_before_sha256"),
        "candidate_after_sha256": state.get("candidate_after_sha256"),
        "event_sequence": state.get("event_sequence"),
        "event_sha256": state.get("event_sha256"),
        "checks": state["checks"],
        "error": state.get("error"),
    }

"""Sealed Change List scopes and patch-only repair candidates.

The repair sandbox is deliberately a preparation and verification surface.  It
does not create an agent, run a model, apply a patch, or change a workspace.
It gives a supervised runner or a maintainer one exact Change List scope and
rejects a candidate patch that crosses it.  Applying an accepted candidate is
still an explicit human action in the IDE.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from .change_review import ChangeReviewError, review_change


REPAIR_SCOPE_SCHEMA = "factory.repair_scope.v1"
REPAIR_CANDIDATE_SCHEMA = "factory.repair_candidate.v1"
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


class RepairSandboxError(ValueError):
    """A closed, machine-readable repair-sandbox input failure."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _workspace(root: Path) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise RepairSandboxError("REPAIR_SCOPE_ROOT_INVALID", f"root must be an existing directory: {workspace}")
    return workspace


def _relative_path(value: object, *, code: str = "REPAIR_SCOPE_PATH_REJECTED") -> str:
    if not isinstance(value, str):
        raise RepairSandboxError(code, "paths must be non-empty workspace-relative strings")
    path = value.replace("\\", "/").strip().removeprefix("./").rstrip("/")
    if (
        not path
        or path.startswith("/")
        or re.match(r"^[A-Za-z]:/", path)
        or any(part in {"", ".."} for part in path.split("/"))
    ):
        raise RepairSandboxError(code, "paths must be non-empty workspace-relative paths without parent traversal")
    return path


def _text(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > maximum or any(ord(char) < 32 for char in value):
        raise RepairSandboxError("REPAIR_SCOPE_INPUT_INVALID", f"{label} must be a non-empty printable string of at most {maximum} characters")
    return value.strip()


def _under_workspace(workspace: Path, value: Path, *, code: str = "REPAIR_SCOPE_PATH_REJECTED", file_only: bool = False) -> Path:
    candidate = Path(value).resolve()
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise RepairSandboxError(code, "path must resolve inside the current workspace") from exc
    if file_only and not candidate.is_file():
        raise RepairSandboxError(code, "path must be an existing regular file inside the current workspace")
    return candidate


def _baseline_entry(workspace: Path, relative: str) -> dict[str, Any]:
    candidate = _under_workspace(workspace, workspace / relative)
    if not candidate.exists():
        return {"path": relative, "exists": False, "size_bytes": 0, "sha256": None}
    if not candidate.is_file():
        raise RepairSandboxError("REPAIR_SCOPE_PATH_REJECTED", f"scope path must be a regular file or a deletion: {relative}")
    contents = candidate.read_bytes()
    return {"path": relative, "exists": True, "size_bytes": len(contents), "sha256": sha256(contents).hexdigest()}


def _review_excerpt(review: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_sha256": review["review_sha256"],
        "changed_paths": review["changed_paths"],
        "next_action": review["next_action"],
        "findings": [
            {"severity": item["severity"], "kind": item["kind"], "message": item["message"]}
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
        checks.insert(2, {
            "id": "declared_validation_plan",
            "kind": "plan_only",
            "description": "The existing risk policy has a declared rerun plan; it remains unexecuted until independently run.",
        })
    return checks


def _scope_core(scope: dict[str, Any]) -> dict[str, Any]:
    missing = [key for key in _CORE_SCOPE_KEYS if key not in scope]
    if missing:
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", f"scope is missing required fields: {', '.join(missing)}")
    return {key: scope[key] for key in _CORE_SCOPE_KEYS}


def _context_budget(paths: list[dict[str, Any]], limit_bytes: int) -> dict[str, Any]:
    if isinstance(limit_bytes, bool) or not isinstance(limit_bytes, int) or not 1 <= limit_bytes <= 100_000_000:
        raise RepairSandboxError("REPAIR_SCOPE_INPUT_INVALID", "context_budget_bytes must be an integer from 1 through 100000000")
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
        raise RepairSandboxError("REPAIR_SCOPE_INPUT_INVALID", "at least one explicit Change List path is required")
    try:
        review = review_change(workspace, changed=changed)
    except ChangeReviewError as exc:
        raise RepairSandboxError(exc.code.replace("CHANGED_", "REPAIR_SCOPE_"), str(exc)) from exc
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
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", f"scope must use schema {REPAIR_SCOPE_SCHEMA}")
    supplied = scope.get("scope_sha256")
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "scope_sha256 must be a SHA-256 hexadecimal digest")
    if _sha(core) != supplied:
        raise RepairSandboxError("REPAIR_SCOPE_TAMPERED", "scope_sha256 does not match canonical scope bytes")
    return supplied


def _scope_baseline(item: object, seen: set[str]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "scope paths must contain objects")
    relative = _relative_path(item.get("path"))
    if relative in seen:
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "scope paths must not repeat a path")
    seen.add(relative)
    expected = {
        "path": relative,
        "exists": item.get("exists"),
        "size_bytes": item.get("size_bytes"),
        "sha256": item.get("sha256"),
    }
    valid_size = not isinstance(expected["size_bytes"], bool) and isinstance(expected["size_bytes"], int) and expected["size_bytes"] >= 0
    valid_present = not expected["exists"] or isinstance(expected["sha256"], str)
    valid_missing = expected["exists"] or (expected["sha256"] is None and expected["size_bytes"] == 0)
    if not isinstance(expected["exists"], bool) or not valid_size or not valid_present or not valid_missing:
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "scope path baseline is malformed")
    return expected


def _verify_scope_paths(workspace: Path, paths: object) -> None:
    if not isinstance(paths, list) or not paths:
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "scope paths must be a non-empty list")
    seen: set[str] = set()
    for item in paths:
        expected = _scope_baseline(item, seen)
        current = _baseline_entry(workspace, expected["path"])
        if current != expected:
            raise RepairSandboxError("REPAIR_SCOPE_DRIFT", f"sealed scope bytes changed for {expected['path']}; prepare a new scope")


def _verify_context_budget(value: object, paths: list[dict[str, Any]]) -> None:
    if not isinstance(value, dict):
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "context_budget must be an object")
    expected = _context_budget(paths, value.get("limit_bytes"))
    if value != expected:
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "context_budget must match sealed path byte baselines")


def verify_repair_scope(scope: dict[str, Any], root: Path) -> dict[str, Any]:
    """Validate scope integrity and reject original Change List byte drift."""
    workspace = _workspace(root)
    core = _scope_core(scope)
    supplied = _scope_digest(scope, core)
    _verify_scope_paths(workspace, core["paths"])
    _verify_context_budget(core["context_budget"], core["paths"])
    return {**scope, "scope_id": f"repair-scope-{supplied[:12]}"}


def _scope_mermaid(scope: dict[str, Any]) -> str:
    lines = ["flowchart LR", '  S["Sealed Change List scope"]']
    for index, item in enumerate(scope["paths"], 1):
        node = f"P{index}"
        state = "present" if item["exists"] else "deletion"
        label = re.sub(r"[^A-Za-z0-9._/: -]+", "?", item["path"])[:96]
        lines.extend((f'  {node}["{state}: {label}"]', f"  {node} --> S"))
    lines.extend((
        '  C["External supervised candidate"]',
        '  V["Independent verifier evidence"]',
        '  H["Human diff review and apply"]',
        "  S --> C --> V --> H",
    ))
    return "\n".join(lines) + "\n"


def _scope_markdown(scope: dict[str, Any]) -> str:
    paths = "\n".join(
        f"- `{item['path']}` â€” {'present' if item['exists'] else 'expected deletion'}"
        for item in scope["paths"]
    )
    checks = "\n".join(f"- `{item['id']}` â€” {item['description']}" for item in scope["verification"]["required_checks"])
    return "\n".join((
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
    ))


def _atomic_text(path: Path, content: str) -> str:
    encoded = content.encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return sha256(encoded).hexdigest()


def _artifact_directory(root: Path, out_dir: Path) -> Path:
    return _under_workspace(_workspace(root), out_dir)


def write_repair_scope_artifacts(scope: dict[str, Any], root: Path, out_dir: Path) -> dict[str, Any]:
    """Write a selected local scope packet after validating it against current bytes."""
    checked = verify_repair_scope(scope, root)
    destination = _artifact_directory(root, out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    stem = checked["scope_id"]
    json_path = destination / f"{stem}.json"
    markdown_path = destination / f"{stem}.md"
    mermaid_path = destination / f"{stem}.mmd"
    payload = {key: checked[key] for key in (*_CORE_SCOPE_KEYS, "scope_id", "scope_sha256", "markers")}
    paths = {"json": json_path, "markdown": markdown_path, "mermaid": mermaid_path}
    return {
        "marker": "REPAIR_SCOPE_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": {
            "json": _atomic_text(json_path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"),
            "markdown": _atomic_text(markdown_path, checked.get("scope_markdown") or _scope_markdown(checked)),
            "mermaid": _atomic_text(mermaid_path, checked.get("mermaid") or _scope_mermaid(checked)),
        },
    }


def _load_scope(root: Path, path: Path) -> dict[str, Any]:
    workspace = _workspace(root)
    scope_path = _under_workspace(workspace, path, file_only=True)
    try:
        value = json.loads(scope_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", f"cannot read scope packet: {exc}") from exc
    if not isinstance(value, dict):
        raise RepairSandboxError("REPAIR_SCOPE_INVALID", "scope packet must be a JSON object")
    return verify_repair_scope(value, workspace)


def _patch_path(value: str) -> str:
    prefix, separator, remainder = value.partition("/")
    if prefix not in {"a", "b"} or not separator:
        raise RepairSandboxError("REPAIR_PATCH_UNSUPPORTED", "patch paths must use unquoted a/<path> or b/<path> Git headers")
    if '"' in value or "\t" in value:
        raise RepairSandboxError("REPAIR_PATCH_UNSUPPORTED", "quoted or tab-separated patch paths are not supported in this first candidate protocol")
    return _relative_path(remainder, code="REPAIR_CANDIDATE_PATH_REJECTED")


def _patch_header_path(value: str, prefix: str) -> str | None:
    if value == "/dev/null":
        return None
    return _patch_path(value) if value.startswith(f"{prefix}/") else _relative_path(value, code="REPAIR_PATCH_UNSUPPORTED")


def _candidate_patch_paths(patch: Path) -> list[str]:
    data = patch.read_bytes()
    if not data or len(data) > MAX_PATCH_BYTES:
        raise RepairSandboxError("REPAIR_PATCH_INVALID", f"candidate patch must contain 1 through {MAX_PATCH_BYTES} bytes")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RepairSandboxError("REPAIR_PATCH_UNSUPPORTED", "candidate patch must be UTF-8 text") from exc
    paths: set[str] = set()
    headers = 0
    for line in lines:
        if line.startswith(("diff --combined ", "diff --cc ", "GIT binary patch", "Binary files ")):
            raise RepairSandboxError("REPAIR_PATCH_UNSUPPORTED", "combined or binary patches are not supported by the first candidate protocol")
        if line.startswith("diff --git "):
            parts = line[len("diff --git "):].split(" ")
            if len(parts) != 2:
                raise RepairSandboxError("REPAIR_PATCH_UNSUPPORTED", "candidate patch must use exactly two unquoted Git diff paths")
            paths.add(_patch_path(parts[0]))
            paths.add(_patch_path(parts[1]))
            headers += 1
        elif line.startswith("--- "):
            path = _patch_header_path(line[4:].strip(), "a")
            if path is not None:
                paths.add(path)
        elif line.startswith("+++ "):
            path = _patch_header_path(line[4:].strip(), "b")
            if path is not None:
                paths.add(path)
        elif line.startswith("rename from ") or line.startswith("rename to "):
            paths.add(_relative_path(line.split(" ", 2)[2], code="REPAIR_PATCH_UNSUPPORTED"))
    if headers == 0 or not paths:
        raise RepairSandboxError("REPAIR_PATCH_INVALID", "candidate patch must contain at least one Git diff header")
    return sorted(paths)


def inspect_repair_candidate(root: Path, scope_path: Path, patch_path: Path) -> dict[str, Any]:
    """Bind an external textual patch to a current sealed scope without applying it."""
    workspace = _workspace(root)
    scope = _load_scope(workspace, scope_path)
    patch = _under_workspace(workspace, patch_path, file_only=True, code="REPAIR_CANDIDATE_PATH_REJECTED")
    touched = _candidate_patch_paths(patch)
    allowed = {item["path"] for item in scope["paths"]}
    outside = sorted(set(touched) - allowed)
    if outside:
        raise RepairSandboxError("REPAIR_CANDIDATE_OUT_OF_SCOPE", f"candidate patch touches path(s) outside the sealed scope: {', '.join(outside)}")
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
        "candidate_markdown": _candidate_markdown({**core, "candidate_sha256": candidate_sha256}),
    }


def _candidate_markdown(candidate: dict[str, Any]) -> str:
    paths = "\n".join(f"- `{path}`" for path in candidate["touched_paths"])
    return "\n".join((
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
    ))


def write_repair_candidate_artifacts(candidate: dict[str, Any], root: Path, out_dir: Path) -> dict[str, Any]:
    """Write a selected local candidate receipt; it never applies its patch."""
    if candidate.get("schema") != REPAIR_CANDIDATE_SCHEMA or not isinstance(candidate.get("candidate_sha256"), str):
        raise RepairSandboxError("REPAIR_CANDIDATE_INVALID", "a valid repair candidate payload is required")
    core = {key: candidate[key] for key in ("schema", "scope_sha256", "patch", "touched_paths", "verification", "apply", "authority", "scope_limits") if key in candidate}
    if _sha(core) != candidate["candidate_sha256"]:
        raise RepairSandboxError("REPAIR_CANDIDATE_TAMPERED", "candidate_sha256 does not match canonical candidate bytes")
    destination = _artifact_directory(root, out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    stem = f"repair-candidate-{candidate['candidate_sha256'][:12]}"
    json_path = destination / f"{stem}.json"
    markdown_path = destination / f"{stem}.md"
    payload = {**core, "candidate_sha256": candidate["candidate_sha256"], "markers": candidate.get("markers", [])}
    paths = {"json": json_path, "markdown": markdown_path}
    return {
        "marker": "REPAIR_CANDIDATE_ARTIFACTS_WRITTEN",
        "paths": {name: str(path) for name, path in paths.items()},
        "sha256": {
            "json": _atomic_text(json_path, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"),
            "markdown": _atomic_text(markdown_path, candidate["candidate_markdown"]),
        },
    }

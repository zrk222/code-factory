"""Evidence-only operational controls for supervised software-factory work.

The module deliberately observes a local checkout; it does not create a
worktree, run a reproduction, contact a dispatcher, or merge a change.  Its
receipt makes the preconditions for those separately authorized actions
reviewable and fail-closed.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any

from .e2e_proof import E2EProofError, validate_e2e_proof_receipt
from .journey_proof import JourneyProofError, validate_failure_capsule
from .protocol_enums import OperationsEvidenceTier, OperationsWorkKind


MANIFEST_SCHEMA = "factory.operations-control-manifest.v1"
RECEIPT_SCHEMA = "factory.operations-control-receipt.v1"
PROJECTION_SCHEMA = "factory.operations-control-projection.v1"
RECEIPT_DIR = Path(".factory/operations-control")
MAX_BYTES = 1_048_576
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_TIERS = OperationsEvidenceTier.values()
_WORK_KINDS = OperationsWorkKind.values()
AUTHORITY = {
    "execution": False, "approval": False, "repair": False, "merge": False,
    "publication": False, "deployment": False, "signing": False,
    "messaging": False, "credential": False, "connector": False,
}


class OperationsControlError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "input must be canonical JSON") from exc


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"{label} fields must be exact")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"{label} must be a safe identifier")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"{label} must be a lowercase SHA-256")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not _GIT_SHA.fullmatch(value):
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"{label} must be a 40-64 character lowercase Git hash")
    return value


def _path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"{label} must be a workspace-relative path")
    candidate = Path(value.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise OperationsControlError("E_OPS_CONTROL_PATH", f"{label} must remain beneath the workspace")
    return candidate.as_posix().rstrip("/") or "."


def _paths(value: object, label: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= 128:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"{label} must contain {minimum}-128 paths")
    result = sorted({_path(item, label) for item in value})
    if len(result) != len(value):
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"{label} must be unique")
    return result


def _inside(root: Path, relative: str, *, file: bool = False, directory: bool = False) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise OperationsControlError("E_OPS_CONTROL_PATH", "path escapes workspace") from exc
    if file and not target.is_file():
        raise OperationsControlError("E_OPS_CONTROL_EVIDENCE", f"required file is unavailable: {relative}")
    if directory and not target.is_dir():
        raise OperationsControlError("E_OPS_CONTROL_COORDINATION", f"required repository directory is unavailable: {relative}")
    return target


def _read_json(root: Path, relative: str, label: str) -> tuple[dict[str, Any], str]:
    path = _inside(root, relative, file=True)
    if path.stat().st_size > MAX_BYTES:
        raise OperationsControlError("E_OPS_CONTROL_EVIDENCE", f"{label} is too large")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperationsControlError("E_OPS_CONTROL_EVIDENCE", f"{label} is not readable JSON") from exc
    if not isinstance(value, dict):
        raise OperationsControlError("E_OPS_CONTROL_EVIDENCE", f"{label} must be a JSON object")
    return value, _file_sha(path)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if completed.returncode:
        raise OperationsControlError("E_OPS_CONTROL_GIT", completed.stderr.strip() or "git inspection failed")
    return completed.stdout.strip()


def _git_facts(root: Path, base: str) -> dict[str, Any]:
    if _git(root, "rev-parse", "--is-inside-work-tree") != "true":
        raise OperationsControlError("E_OPS_CONTROL_GIT", "workspace must be a Git worktree")
    head = _git(root, "rev-parse", "HEAD")
    branch = _git(root, "branch", "--show-current") or "DETACHED"
    merge_base = _git(root, "merge-base", base, "HEAD")
    status = _git(root, "status", "--porcelain=v1")
    diff = _git(root, "diff", "--numstat", f"{base}...HEAD")
    changed: list[dict[str, Any]] = []
    for line in diff.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        added, deleted, path = parts
        if added == "-" or deleted == "-":
            lines = None
        else:
            lines = int(added) + int(deleted)
        changed.append({"path": _path(path, "changed path"), "added": added, "deleted": deleted, "lines": lines})
    return {"head_sha": head, "branch": branch, "merge_base_sha": merge_base, "clean": not bool(status), "status_entries": len(status.splitlines()) if status else 0, "changed": changed}


def _under(prefixes: list[str], path: str) -> bool:
    return any(prefix == "." or path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


def _validate_manifest(root: Path, source: Path) -> tuple[dict[str, Any], str]:
    try:
        relative = source.resolve().relative_to(root).as_posix() if source.is_absolute() else _path(str(source), "manifest")
    except ValueError as exc:
        raise OperationsControlError("E_OPS_CONTROL_PATH", "manifest must remain beneath the workspace") from exc
    value, source_sha = _read_json(root, relative, "manifest")
    fields = {"schema", "id", "work_kind", "base", "scope_paths", "isolation", "reproduction", "change_envelope", "evidence", "architecture", "coordination"}
    entry = _exact(value, fields, "manifest")
    if entry["schema"] != MANIFEST_SCHEMA:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"schema must be {MANIFEST_SCHEMA}")
    _identifier(entry["id"], "id")
    if entry["work_kind"] not in _WORK_KINDS:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "work_kind must be bug_fix or feature")
    if not isinstance(entry["base"], str) or not entry["base"].strip():
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "base must be a non-empty Git revision")
    scopes = _paths(entry["scope_paths"], "scope_paths", minimum=1)
    isolation = _exact(entry["isolation"], {"expected_branch", "expected_base_sha", "require_clean"}, "isolation")
    if not isinstance(isolation["expected_branch"], str) or not isolation["expected_branch"].strip() or not isinstance(isolation["require_clean"], bool):
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "isolation branch and clean fields are invalid")
    _git_sha(isolation["expected_base_sha"], "isolation.expected_base_sha")
    reproduction = _exact(entry["reproduction"], {"failure_capsule", "execution_receipt", "max_attempts", "attempts_used", "token_budget", "observed_tokens"}, "reproduction")
    for name in ("failure_capsule", "execution_receipt"):
        _path(reproduction[name], f"reproduction.{name}")
    for name in ("max_attempts", "attempts_used", "token_budget", "observed_tokens"):
        if not isinstance(reproduction[name], int) or isinstance(reproduction[name], bool) or reproduction[name] < 0:
            raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"reproduction.{name} must be a non-negative integer")
    if reproduction["max_attempts"] < 1:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "reproduction.max_attempts must be at least one")
    envelope = _exact(entry["change_envelope"], {"purpose", "max_changed_files", "max_changed_lines"}, "change_envelope")
    if not isinstance(envelope["purpose"], str) or not envelope["purpose"].strip():
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "change_envelope.purpose is required")
    for name in ("max_changed_files", "max_changed_lines"):
        if not isinstance(envelope[name], int) or isinstance(envelope[name], bool) or envelope[name] < 1:
            raise OperationsControlError("E_OPS_CONTROL_SCHEMA", f"change_envelope.{name} must be a positive integer")
    evidence = _exact(entry["evidence"], {"task_kind", "tier", "artifacts"}, "evidence")
    if evidence["task_kind"] not in {"logic", "visual", "interaction"} or evidence["tier"] not in _TIERS:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "evidence task_kind or tier is unsupported")
    artifacts = _paths(evidence["artifacts"], "evidence.artifacts", minimum=1)
    architecture = _exact(entry["architecture"], {"core_paths", "interface_paths", "core_check_receipts"}, "architecture")
    core = _paths(architecture["core_paths"], "architecture.core_paths")
    interface = _paths(architecture["interface_paths"], "architecture.interface_paths")
    if any(_under(interface, item) for item in core) or any(_under(core, item) for item in interface):
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "architecture core and interface paths must not overlap")
    core_checks = _paths(architecture["core_check_receipts"], "architecture.core_check_receipts")
    coordination = _exact(entry["coordination"], {"repositories"}, "coordination")
    repositories = coordination["repositories"]
    if not isinstance(repositories, list) or not 1 <= len(repositories) <= 32:
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "coordination.repositories must contain 1-32 entries")
    normalized_repos = []
    for index, item in enumerate(repositories):
        repo = _exact(item, {"id", "path", "expected_head_sha", "dependencies"}, f"coordination.repositories[{index}]")
        normalized_repos.append({"id": _identifier(repo["id"], "repository id"), "path": _path(repo["path"], "repository path"), "expected_head_sha": _git_sha(repo["expected_head_sha"], "repository expected_head_sha"), "dependencies": sorted({_identifier(dep, "repository dependency") for dep in repo["dependencies"]})})
    ids = {item["id"] for item in normalized_repos}
    if len(ids) != len(normalized_repos) or any(dep not in ids for item in normalized_repos for dep in item["dependencies"]):
        raise OperationsControlError("E_OPS_CONTROL_SCHEMA", "coordination repository IDs and dependencies must be unique and declared")
    return {
        "id": entry["id"], "work_kind": entry["work_kind"], "base": entry["base"], "scope_paths": scopes,
        "isolation": isolation, "reproduction": reproduction, "change_envelope": envelope,
        "evidence": {**evidence, "artifacts": artifacts},
        "architecture": {"core_paths": core, "interface_paths": interface, "core_check_receipts": core_checks},
        "coordination": {"repositories": normalized_repos}, "path": relative,
    }, source_sha


def _artifact_facts(root: Path, paths: list[str]) -> list[dict[str, str]]:
    return [{"path": path, "sha256": _file_sha(_inside(root, path, file=True))} for path in paths]


def _reproduction(root: Path, value: dict[str, Any], work_kind: str) -> tuple[dict[str, Any], list[str]]:
    blockers: list[str] = []
    capsule, capsule_sha = _read_json(root, value["failure_capsule"], "failure capsule")
    receipt, receipt_sha = _read_json(root, value["execution_receipt"], "reproduction execution receipt")
    try:
        validate_failure_capsule(root, capsule)
        capsule_ok = True
    except (JourneyProofError, TypeError, ValueError):
        capsule_ok = False
    try:
        validated_receipt = validate_e2e_proof_receipt(receipt)
        receipt_ok = validated_receipt["marker"] == "E2E_POSITIVE_FAILED" and validated_receipt["ok"] is False
    except (E2EProofError, TypeError, ValueError):
        receipt_ok = False
    budget_ok = value["attempts_used"] <= value["max_attempts"] and value["observed_tokens"] <= value["token_budget"]
    if work_kind == "bug_fix" and not capsule_ok:
        blockers.append("REPRO_CAPSULE_UNBOUND")
    if work_kind == "bug_fix" and not receipt_ok:
        blockers.append("REPRO_NOT_OBSERVED")
    if not budget_ok:
        blockers.append("REPRO_BUDGET_EXCEEDED")
    return {"failure_capsule": {"path": value["failure_capsule"], "sha256": capsule_sha, "bound": capsule_ok}, "execution_receipt": {"path": value["execution_receipt"], "sha256": receipt_sha, "reproduced": receipt_ok}, "budget": {"max_attempts": value["max_attempts"], "attempts_used": value["attempts_used"], "token_budget": value["token_budget"], "observed_tokens": value["observed_tokens"], "within_budget": budget_ok}, "escalation": "human_shepherd" if blockers else None}, blockers


def _tier_ok(task_kind: str, tier: str) -> bool:
    return {"logic": {"logs_metrics", "visual_pair", "interaction_video"}, "visual": {"visual_pair", "interaction_video"}, "interaction": {"interaction_video"}}[task_kind].__contains__(tier)


def assess_operations_control(root: Path, manifest_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Write a local operational-readiness receipt without dispatching any work."""
    workspace = Path(root).resolve()
    manifest, manifest_sha = _validate_manifest(workspace, manifest_path)
    git = _git_facts(workspace, manifest["base"])
    blockers: list[str] = []
    isolation = manifest["isolation"]
    if git["branch"] != isolation["expected_branch"]:
        blockers.append("ISOLATION_BRANCH_DRIFT")
    if git["merge_base_sha"] != isolation["expected_base_sha"]:
        blockers.append("ISOLATION_BASE_DRIFT")
    if isolation["require_clean"] and not git["clean"]:
        blockers.append("ISOLATION_WORKTREE_DIRTY")
    changed = git["changed"]
    paths = [item["path"] for item in changed]
    if any(not _under(manifest["scope_paths"], path) for path in paths):
        blockers.append("CHANGE_SCOPE_ESCAPE")
    envelope = manifest["change_envelope"]
    measured_lines = sum(item["lines"] for item in changed if isinstance(item["lines"], int))
    binary_paths = [item["path"] for item in changed if item["lines"] is None]
    if len(changed) > envelope["max_changed_files"]:
        blockers.append("CHANGE_ENVELOPE_FILE_LIMIT")
    if measured_lines > envelope["max_changed_lines"] or binary_paths:
        blockers.append("CHANGE_ENVELOPE_LINE_LIMIT")
    reproduction, repro_blockers = _reproduction(workspace, manifest["reproduction"], manifest["work_kind"])
    blockers.extend(repro_blockers)
    evidence = manifest["evidence"]
    evidence_ok = _tier_ok(evidence["task_kind"], evidence["tier"])
    if not evidence_ok:
        blockers.append("EVIDENCE_TIER_TOO_WEAK")
    artifacts = _artifact_facts(workspace, evidence["artifacts"])
    architecture = manifest["architecture"]
    core_changed = sorted(path for path in paths if _under(architecture["core_paths"], path))
    interface_changed = sorted(path for path in paths if _under(architecture["interface_paths"], path))
    unclassified = sorted(path for path in paths if path not in core_changed and path not in interface_changed)
    checks = _artifact_facts(workspace, architecture["core_check_receipts"])
    if core_changed and not checks:
        blockers.append("CORE_CHECK_RECEIPT_MISSING")
    if unclassified:
        blockers.append("ARCHITECTURE_ZONE_UNCLASSIFIED")
    repositories = []
    for item in manifest["coordination"]["repositories"]:
        repo_path = _inside(workspace, item["path"], directory=True)
        try:
            actual = _git(repo_path, "rev-parse", "HEAD")
            valid = actual == item["expected_head_sha"]
        except OperationsControlError:
            actual, valid = None, False
        repositories.append({**item, "actual_head_sha": actual, "current": valid})
        if not valid:
            blockers.append("COORDINATION_REPOSITORY_DRIFT")
    core = {
        "schema": RECEIPT_SCHEMA,
        "marker": "OPS_CONTROL_READY" if not blockers else "OPS_CONTROL_BLOCKED",
        "manifest": {"path": manifest["path"], "sha256": manifest_sha, "id": manifest["id"], "work_kind": manifest["work_kind"]},
        "isolation": {"git": {key: git[key] for key in ("head_sha", "branch", "merge_base_sha", "clean", "status_entries")}, "expected": isolation, "host_isolation_verified": False, "claim_boundary": "Git facts verify a local worktree state only; they do not prove a sandbox, network egress policy, VM, container, or remote runtime."},
        "reproduction": reproduction,
        "change_envelope": {"purpose": envelope["purpose"], "limits": {"max_changed_files": envelope["max_changed_files"], "max_changed_lines": envelope["max_changed_lines"]}, "changed": changed, "measured": {"file_count": len(changed), "line_count": measured_lines, "binary_paths": binary_paths}},
        "evidence": {"task_kind": evidence["task_kind"], "tier": evidence["tier"], "tier_sufficient": evidence_ok, "artifacts": artifacts},
        "architecture": {"core_changed": core_changed, "interface_changed": interface_changed, "unclassified_changed": unclassified, "core_check_receipts": checks},
        "coordination": {"repositories": repositories},
        "blockers": sorted(set(blockers)),
        "next_action": {"action": "human_shepherd_review" if any(item.startswith("REPRO_") for item in blockers) else "repair_operations_contract" if blockers else "review_evidence_packet", "reason": "A reproduction budget or observation needs human review." if any(item.startswith("REPRO_") for item in blockers) else "One or more operational preconditions are unproven." if blockers else "All declared local operational controls are currently satisfied; merge and execution authority remain external."},
        "authority": dict(AUTHORITY),
        "scope_limits": ["This receipt never creates a worktree, runs a reproduction, starts an agent, dispatches a task, repairs code, merges, publishes, deploys, sends a message, or accesses credentials.", "Observed token and attempt values are supplied evidence; Code Factory preserves them as declared measurements and does not infer hidden model usage."],
    }
    # Timestamp is part of the immutable receipt, not projection-only metadata.
    # Otherwise an attacker can alter the apparent issuance time without
    # invalidating the local receipt hash.
    core["created_at"] = _now()
    receipt = {**core, "receipt_sha256": _sha(core)}
    target_relative = _path(str(out) if out else (RECEIPT_DIR / f"{manifest['id']}-{receipt['receipt_sha256'][:12]}.json").as_posix(), "output")
    target = _inside(workspace, target_relative)
    if not _under([RECEIPT_DIR.as_posix()], target_relative):
        raise OperationsControlError("E_OPS_CONTROL_PATH", "output must remain under .factory/operations-control")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {**receipt, "path": target_relative}


def operations_control_projection(root: Path) -> dict[str, Any]:
    """Project valid local operating-envelope receipts without dispatching work."""
    workspace = Path(root).resolve()
    receipts: list[dict[str, Any]] = []
    invalid: list[str] = []
    directory = workspace / RECEIPT_DIR
    if directory.is_dir():
        for path in sorted(directory.glob("*.json"))[:200]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                core = {key: value[key] for key in value if key not in {"receipt_sha256", "path"}}
                if value.get("schema") != RECEIPT_SCHEMA or value.get("receipt_sha256") != _sha(core):
                    raise ValueError("receipt digest mismatch")
                receipts.append({"path": path.relative_to(workspace).as_posix(), "id": value["manifest"]["id"], "marker": value["marker"], "blocker_count": len(value.get("blockers", [])), "created_at": value.get("created_at"), "receipt_sha256": value["receipt_sha256"]})
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                invalid.append(path.relative_to(workspace).as_posix())
    return {"schema": PROJECTION_SCHEMA, "marker": "OPS_CONTROL_READ_ONLY", "receipt_count": len(receipts), "ready_count": sum(item["marker"] == "OPS_CONTROL_READY" for item in receipts), "blocked_count": sum(item["marker"] == "OPS_CONTROL_BLOCKED" for item in receipts), "invalid_count": len(invalid), "latest": receipts[-1] if receipts else None, "receipts": receipts[-20:], "invalid": invalid[:100], "authority": dict(AUTHORITY), "claim_boundary": "Read-only local operations-control facts. The projection does not execute a reproduction, create a worktree, dispatch an agent, or authorize a merge or release."}


def operations_control_template() -> dict[str, Any]:
    """Return a secret-free manifest template for reviewed operating preconditions."""
    return {"schema": "factory.operations-control-template.v1", "manifest_schema": MANIFEST_SCHEMA, "authority": dict(AUTHORITY), "claim_boundary": "Template only. Fill every digest and receipt path from local reviewed evidence; it creates no worktree and performs no provider or agent action.", "manifest": {"schema": MANIFEST_SCHEMA, "id": "replace-with-control-id", "work_kind": "bug_fix", "base": "replace-with-base-revision", "scope_paths": ["src"], "isolation": {"expected_branch": "replace-with-branch", "expected_base_sha": "replace-with-40-or-64-char-lowercase-git-hash", "require_clean": True}, "reproduction": {"failure_capsule": ".factory/journey-proof/failure.json", "execution_receipt": ".factory/e2e/repro.json", "max_attempts": 2, "attempts_used": 1, "token_budget": 10000, "observed_tokens": 0}, "change_envelope": {"purpose": "replace-with-one-reviewable-purpose", "max_changed_files": 20, "max_changed_lines": 1000}, "evidence": {"task_kind": "logic", "tier": "logs_metrics", "artifacts": ["replace-with-local-evidence-file"]}, "architecture": {"core_paths": ["src"], "interface_paths": ["web"], "core_check_receipts": ["replace-with-local-core-check"]}, "coordination": {"repositories": [{"id": "primary", "path": ".", "expected_head_sha": "replace-with-40-or-64-char-lowercase-git-hash", "dependencies": []}]}}}

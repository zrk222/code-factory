"""Create review-required worklog drafts from already verified local evidence.

This is deliberately not a ticketing connector.  It reads the sealed Oracle
Contract and existing local proof receipts, writes an immutable local draft on
an explicit CLI request, and never posts to GitHub, Jira, Linear, Slack, or any
other service.  A draft is a concise handoff aid, not evidence of a completed
release or an external delivery.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
import tempfile
from typing import Any

from .agent_proof_bridge import agent_proof_projection
from .atomic_proof_adapter import atomic_proof_projection
from .oracle_firewall import verify_oracle_contract


SCHEMA = "factory.proof-worklog-draft.v1"
MARKER = "PROOF_WORKLOG_DRAFT_REVIEW_REQUIRED"
MAX_BYTES = 1_048_576
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
_APPLIED_CHANGE_TIMEOUT = 10
_APPLIED_CHANGE_TOTAL_SECONDS = 30
_APPLIED_CHANGE_MAX_PATHS = 1000
_APPLIED_CHANGE_MAX_BYTES = 8 * 1024 * 1024
_GIT_OID = re.compile(r"^[0-9a-f]{40,64}$")


def applied_change_projection(
    root: Path,
    baseline_oid: object,
    candidate_manifest: object,
    rationale: object,
    *,
    candidate_sha256: str | None = None,
    baseline_files: dict[str, str | None] | None = None,
    _budget: dict[str, float | int] | None = None,
    _snapshot_out: dict[str, object] | None = None,
) -> dict[str, Any]:
    """Project bounded Git changes only when baseline and candidate bytes bind."""
    unavailable = _unavailable_projection("baseline_unbound")
    if not isinstance(baseline_oid, str) or not _GIT_OID.fullmatch(baseline_oid):
        return unavailable
    manifest = _candidate_hash_map(candidate_manifest)
    if not manifest:
        return _unavailable_projection("candidate_manifest_unavailable")
    workspace = Path(root).resolve()
    budget = _budget or _new_applied_change_budget()
    try:
        return _available_applied_change_projection(
            workspace,
            baseline_oid,
            manifest,
            candidate_manifest,
            candidate_sha256,
            rationale,
            baseline_files,
            budget,
            _snapshot_out,
        )
    except (OSError, UnicodeDecodeError, ValueError, RuntimeError):
        return _unavailable_projection("projection_unavailable_or_stale")


def _available_applied_change_projection(
    workspace,
    baseline_oid,
    manifest,
    candidate_manifest,
    candidate_sha256,
    rationale,
    baseline_files,
    budget,
    snapshot_out,
):
    """Build and recheck an available projection from one bounded snapshot."""
    git = _AppliedChangeGit(workspace, budget)
    head, repo_id, entries, untracked, statuses, facts = git.inventory(baseline_oid)
    declared_before = dict(baseline_files or {})
    changes, unrelated, file_facts = _project_git_changes(
        git, entries, untracked, manifest, declared_before
    )
    _mark_mixed_edits(changes, unrelated, statuses, manifest)
    _complete_applied_file_facts(git, unrelated, file_facts, manifest)
    snapshot = {
        "baseline_oid": baseline_oid,
        "head_oid": head,
        "repository_identity_sha256": repo_id,
        "facts": facts,
        "manifest": manifest,
        "file_facts": file_facts,
        "baseline_files": declared_before,
    }
    _verify_applied_change_snapshot(workspace, snapshot, budget)
    if snapshot_out is not None:
        snapshot_out["value"] = snapshot
    return {
        "state": "available",
        "reason": None,
        "baseline_oid": baseline_oid,
        "head_oid": head,
        "candidate_sha256": candidate_sha256 or _sha(candidate_manifest),
        "changes": changes,
        "unrelated_dirty_paths": sorted(unrelated),
        "rationale": rationale.strip()[:240]
        if isinstance(rationale, str) and rationale.strip()
        else None,
        "repository_identity_sha256": repo_id,
        "limits": [
            "Git diff proves byte differences, not authorship or causal intent."
        ],
    }


def _complete_applied_file_facts(git, unrelated, file_facts, manifest):
    """Hash every displayed or declared file and reject stale candidate bytes."""
    for path in unrelated:
        if path not in file_facts:
            file_facts[path] = git.file_fact(path)
    for path, digest in manifest.items():
        if path not in file_facts:
            file_facts[path] = git.file_fact(path)
        if file_facts[path] != digest:
            raise ValueError("candidate_stale")


def _new_applied_change_budget() -> dict[str, float | int]:
    """Share the applied-change time and retained-byte budgets across reads."""
    return {"deadline": time.monotonic() + _APPLIED_CHANGE_TOTAL_SECONDS, "retained": 0}


def _check_applied_change_deadline(budget: dict[str, float | int]) -> None:
    """Raise when a shared applied-change operation has exhausted its deadline."""
    if time.monotonic() >= float(budget["deadline"]):
        raise ValueError("resource_exhausted")


def _unavailable_projection(reason: str) -> dict[str, Any]:
    return {
        "state": "unavailable",
        "reason": reason,
        "baseline_oid": None,
        "head_oid": None,
        "candidate_sha256": None,
        "changes": [],
        "unrelated_dirty_paths": [],
        "rationale": None,
    }


def _candidate_hash_map(value: object) -> dict[str, str]:
    if not isinstance(value, list) or len(value) > _APPLIED_CHANGE_MAX_PATHS:
        return {}
    result = {}
    for row in value:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256")))
            or row["path"] in result
        ):
            return {}
        result[row["path"]] = row["sha256"]
    return result


class _AppliedChangeGit:
    def __init__(self, root: Path, budget: dict[str, float | int]):
        """Create a bounded Git reader rooted at one candidate workspace."""
        from .assembly_process import run_cli_detailed

        self.root, self.run_cli = root, run_cli_detailed
        self.budget = budget

    def _remaining(self) -> float:
        """Return seconds left in the shared projection deadline."""
        return float(self.budget["deadline"]) - time.monotonic()

    def _retain(self, amount: int) -> None:
        """Account returned or hashed bytes against the shared data limit."""
        retained = int(self.budget["retained"]) + amount
        if amount < 0 or retained > _APPLIED_CHANGE_MAX_BYTES:
            raise ValueError("resource_exhausted")
        self.budget["retained"] = retained

    def run(self, args: list[str], expected: tuple[int, ...] = (0,)) -> bytes:
        """Run one Git read within per-child and aggregate resource limits."""
        remaining = self._remaining()
        available = _APPLIED_CHANGE_MAX_BYTES - int(self.budget["retained"])
        if remaining <= 0 or available < 2:
            raise ValueError("resource_exhausted")
        stream_cap = available // 2
        result = self.run_cli(
            "git",
            [
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(self.root),
                *args,
            ],
            self.root,
            timeout=min(_APPLIED_CHANGE_TIMEOUT, remaining),
            max_stream_bytes=stream_cap,
        )
        if (
            result.get("ok") is not True
            or result.get("reason") is not None
            or result.get("cleanup_confirmed") is not True
            or result.get("streams_closed") is not True
            or result.get("exit_code") not in expected
            or not isinstance(result.get("stdout"), bytes)
            or not isinstance(result.get("stderr"), bytes)
        ):
            raise ValueError(str(result.get("reason") or "git_unavailable"))
        output = result["stdout"]
        self._retain(len(output) + len(result["stderr"]))
        if self._remaining() <= 0:
            raise ValueError("resource_exhausted")
        return output

    def digest(self, path: Path) -> str:
        """Stream-hash one regular file within byte and shared time limits."""
        if self._remaining() <= 0:
            raise ValueError("resource_exhausted")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(65536):
                self._retain(len(chunk))
                if self._remaining() <= 0:
                    raise ValueError("resource_exhausted")
                digest.update(chunk)
        if self._remaining() <= 0:
            raise ValueError("resource_exhausted")
        return digest.hexdigest()

    def inventory(self, baseline: str):
        """Collect baseline-to-worktree paths, status, and repository identity."""
        top = Path(
            self.run(["rev-parse", "--show-toplevel"]).decode("utf-8", "strict").strip()
        ).resolve()
        if top != self.root:
            raise ValueError("repository_identity_mismatch")
        repo = (
            self.run(["rev-parse", "--absolute-git-dir"])
            .decode("utf-8", "strict")
            .strip()
        )
        head = self.run(["rev-parse", "HEAD"]).decode("ascii", "strict").strip()
        if not _GIT_OID.fullmatch(head):
            raise ValueError("git_unavailable")
        self.run(["cat-file", "-e", f"{baseline}^{{commit}}"])
        self.run(["merge-base", "--is-ancestor", baseline, head])
        raw = self.run(
            ["diff", "--raw", "-z", "--no-abbrev", "--find-renames", baseline, "--"]
        )
        index_raw = self.run(
            [
                "diff",
                "--cached",
                "--raw",
                "-z",
                "--no-abbrev",
                "--find-renames",
                baseline,
                "--",
            ]
        )
        untracked = self.run(["ls-files", "--others", "--exclude-standard", "-z"])
        status = self.run(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        entries = _parse_applied_git_diff(raw)
        index_entries = _parse_applied_git_diff(index_raw)
        paths = [item for item in untracked.split(b"\0") if item]
        statuses = _parse_status_paths(status)
        path_set = set(statuses) | {item.decode("utf-8", "strict") for item in paths}
        path_set.update(item[1].decode("utf-8", "strict") for item in entries)
        path_set.update(
            item[0].decode("utf-8", "strict") for item in entries if item[0] is not None
        )
        path_set.update(item[1].decode("utf-8", "strict") for item in index_entries)
        path_set.update(
            item[0].decode("utf-8", "strict")
            for item in index_entries
            if item[0] is not None
        )
        if len(path_set) > _APPLIED_CHANGE_MAX_PATHS:
            raise ValueError("resource_exhausted")
        facts = (raw, index_raw, untracked, status)
        return (
            head,
            hashlib.sha256(repo.encode("utf-8")).hexdigest(),
            entries,
            paths,
            statuses,
            facts,
        )

    def file_fact(self, value: str) -> str | None:
        """Hash one displayed path, or capture that it remains absent."""
        _check_applied_change_deadline(self.budget)
        target = _literal_workspace_file(self.root, value, may_be_missing=True)
        if not target.exists():
            _check_applied_change_deadline(self.budget)
            return None
        if not target.is_file():
            raise ValueError("unsafe_path")
        return self.digest(target)

    def verify_current(self, snapshot: dict[str, object]) -> None:
        """Reject any changed inventory, displayed file, or candidate fact."""
        current = self.inventory(str(snapshot["baseline_oid"]))
        if (
            current[0] != snapshot["head_oid"]
            or current[1] != snapshot["repository_identity_sha256"]
            or current[5] != snapshot["facts"]
        ):
            raise ValueError("head_or_repository_stale")
        expected = dict(snapshot["file_facts"])
        for path, digest in snapshot["manifest"].items():
            if path in expected and expected[path] != digest:
                raise ValueError("candidate_stale")
            expected[path] = digest
        for path, digest in expected.items():
            if self.file_fact(path) != digest:
                raise ValueError("candidate_or_displayed_file_stale")


def _verify_applied_change_snapshot(
    root: Path, snapshot: dict[str, object], budget: dict[str, float | int]
) -> None:
    """Recheck the complete Git and byte snapshot through the shared reader."""
    _AppliedChangeGit(Path(root).resolve(), budget).verify_current(snapshot)


def _project_git_changes(git, entries, untracked, manifest, baseline_files):
    changes, unrelated, file_facts = [], set(), {}
    for entry in entries:
        old_raw, path_raw, code, old_oid, _new_oid = entry
        path = path_raw.decode("utf-8", "strict")
        old = old_raw.decode("utf-8", "strict") if old_raw else None
        after = git.file_fact(path)
        git_before = (
            hashlib.sha256(git.run(["cat-file", "blob", old_oid])).hexdigest()
            if old_oid.strip("0")
            else None
        )
        baseline_path = old or path
        declared_present = baseline_path in baseline_files
        declared = baseline_files.get(baseline_path)
        before = declared if declared_present else git_before
        bound_before = (
            declared_present
            and declared is None
            and code.startswith("A")
            and git_before is None
        ) or (declared_present and declared is not None)
        candidate = manifest.get(path)
        bound = candidate == after and code != "D" and bound_before
        if not bound:
            unrelated.add(path)
        changes.append(_change_row(code, path, old, before, after, candidate, bound))
        file_facts[path] = after
        if old is not None:
            file_facts[old] = git.file_fact(old)
    for raw_path in untracked:
        path = raw_path.decode("utf-8", "strict")
        after = git.file_fact(path)
        candidate = manifest.get(path)
        bound = (
            candidate == after
            and path in baseline_files
            and baseline_files[path] is None
        )
        if not bound:
            unrelated.add(path)
        changes.append(_change_row("A", path, None, None, after, candidate, bound))
        file_facts[path] = after
    return changes, unrelated, file_facts


def _change_row(code, path, old, before, after, candidate, bound):
    kind = (
        "renamed"
        if code.startswith("R")
        else {"A": "added", "D": "deleted"}.get(code, "modified")
    )
    return {
        "kind": kind,
        "path": path,
        "old_path": old if old != path else None,
        "before_sha256": before,
        "after_sha256": after,
        "candidate_sha256": candidate,
        "disposition": "verified_candidate_bytes" if bound else "unverified",
        "reason": None
        if bound
        else "candidate_bytes_not_bound_or_deletion_tombstone_missing",
    }


def _mark_mixed_edits(changes, unrelated, statuses, manifest):
    for path, status in statuses.items():
        if status in {"??", "!!"}:
            if path not in manifest:
                unrelated.add(path)
            continue
        if path not in manifest:
            unrelated.add(path)
            continue
        if status.count(" ") == 1 and "U" not in status:
            continue
        for row in changes:
            if row["path"] == path:
                row["disposition"] = "unverified"
                row["reason"] = "mixed_or_ambiguous_same_file_edits"
                unrelated.add(path)


def bound_candidate_context(
    root: Path,
    mission_path: Path,
    mission: dict[str, Any],
    mission_file_sha256: str,
    *,
    _budget: dict[str, float | int] | None = None,
) -> tuple[str | None, Path | None, set[str], dict[str, str | None], str | None]:
    """Find the unique sealed pre-edit candidate binding linked to this mission."""
    unavailable = (None, None, set(), {}, None)
    workspace, mission_file = Path(root).resolve(), Path(mission_path).resolve()
    try:
        budget = _budget or _new_applied_change_budget()
        paths = []
        with os.scandir(mission_file.parent) as entries:
            for entry in entries:
                _check_applied_change_deadline(budget)
                if entry.name.startswith("candidate-binding-") and entry.name.endswith(
                    ".json"
                ):
                    paths.append(Path(entry.path))
                    if len(paths) > 100:
                        return unavailable
        paths.sort()
        _check_applied_change_deadline(budget)
        expected = {
            "path": str(mission_file),
            "file_sha256": mission_file_sha256,
            "mission_sha256": mission.get("mission_sha256"),
        }
        matches = [
            result
            for path in paths
            if (
                result := _matching_candidate_binding(
                    path, workspace, expected, mission.get("owner"), budget
                )
            )
        ]
        _check_applied_change_deadline(budget)
        return matches[0] if len(matches) == 1 else unavailable
    except (
        OSError,
        RuntimeError,
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return unavailable


def _matching_candidate_binding(path, workspace, expected_mission, owner, budget):
    value = _read_candidate_binding(path, workspace, budget)
    _check_applied_change_deadline(budget)
    if value.get("mission") != expected_mission or value.get("owner") != owner:
        return None
    declaration, decision_binding = value.get("declaration"), value.get("decision")
    if not isinstance(declaration, dict) or not isinstance(decision_binding, dict):
        raise ValueError("candidate binding is incomplete")
    from .runtime_audit_process import path_chain_has_no_links

    raw_candidate_root = Path(value.get("workspace", ""))
    baseline, candidate_root = (
        declaration.get("base_commit"),
        raw_candidate_root.resolve(),
    )
    if (
        not isinstance(baseline, str)
        or not _GIT_OID.fullmatch(baseline)
        or not candidate_root.is_relative_to(workspace)
        or not path_chain_has_no_links(workspace, raw_candidate_root)
    ):
        raise ValueError("candidate binding scope is invalid")
    if not _valid_bound_decision(
        decision_binding, workspace, expected_mission, owner, budget
    ):
        raise ValueError("candidate binding approval is unavailable")
    files = value.get("files")
    hashes = _candidate_baseline_files(declaration.get("paths"), files)
    if hashes is None or _sha({"base_commit": baseline, "files": files}) != value.get(
        "candidate_sha256"
    ):
        raise ValueError("candidate binding file facts are invalid")
    _check_applied_change_deadline(budget)
    return baseline, candidate_root, set(hashes), hashes, value["binding_sha256"]


def _read_candidate_binding(path, workspace, budget):
    """Read and seal-check one candidate record within the shared budget."""
    from .runtime_audit_process import regular_target_within

    _check_applied_change_deadline(budget)
    if not regular_target_within(workspace, path):
        raise ValueError("candidate binding path is unsafe")
    if path.stat().st_size > 1_048_576:
        raise ValueError("candidate binding size limit exceeded")
    remaining = _APPLIED_CHANGE_MAX_BYTES - int(budget["retained"])
    with path.open("rb") as stream:
        raw = stream.read(min(1_048_577, remaining + 1))
    if len(raw) > remaining or len(raw) > 1_048_576:
        raise ValueError("candidate binding resource limit")
    budget["retained"] = int(budget["retained"]) + len(raw)
    value = json.loads(raw.decode("utf-8-sig"))
    if (
        not isinstance(value, dict)
        or value.get("schema") != "factory.mission.candidate-binding.v1"
    ):
        raise ValueError("candidate binding is incomplete")
    core = {key: item for key, item in value.items() if key != "binding_sha256"}
    if value.get("binding_sha256") != _sha(core):
        raise ValueError("candidate binding seal is invalid")
    _check_applied_change_deadline(budget)
    return value


def _valid_bound_decision(binding, workspace, expected_mission, owner, budget):
    from .runtime_audit_process import regular_target_within
    from .product_missions import _candidate_approval

    _check_applied_change_deadline(budget)
    path = Path(binding.get("path", ""))
    path = path if path.is_absolute() else workspace / path
    if not regular_target_within(workspace, path) or path.stat().st_size > 1_048_576:
        return False
    remaining = _APPLIED_CHANGE_MAX_BYTES - int(budget["retained"])
    with path.open("rb") as stream:
        raw = stream.read(min(1_048_577, remaining + 1))
    if len(raw) > remaining or len(raw) > 1_048_576:
        return False
    budget["retained"] = int(budget["retained"]) + len(raw)
    _check_applied_change_deadline(budget)
    if hashlib.sha256(raw).hexdigest() != binding.get("file_sha256"):
        return False
    try:
        _mission, decision = _candidate_approval(
            Path(expected_mission["path"]), path, owner
        )
    except (OSError, ValueError, TypeError, KeyError):
        return False
    _check_applied_change_deadline(budget)
    return (
        decision.get("decision_sha256") == binding.get("sha256")
        and decision.get("mission") == expected_mission
    )


def _candidate_baseline_files(paths, files):
    if (
        not isinstance(paths, list)
        or not isinstance(files, list)
        or len(paths) != len(files)
        or len(files) > _APPLIED_CHANGE_MAX_PATHS
    ):
        return None
    result = {}
    for path, row in zip(paths, files, strict=True):
        if (
            not isinstance(path, str)
            or not isinstance(row, dict)
            or row.get("path") != path
            or path in result
        ):
            return None
        digest, state = row.get("sha256"), row.get("state")
        if state == "existing" and not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            return None
        if state not in {"existing", "planned_new"} or (
            state == "planned_new" and digest is not None
        ):
            return None
        result[path] = digest
    return result


def _parse_applied_git_diff(
    output: bytes,
) -> list[tuple[bytes | None, bytes, str, str, str]]:
    tokens = output.split(b"\0")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    rows = []
    index = 0
    while index < len(tokens):
        header = tokens[index].decode("ascii", "strict")
        index += 1
        match = re.fullmatch(
            r":\d{6} \d{6} ([0-9a-f]+) ([0-9a-f]+) ([A-Z][0-9]*)", header
        )
        if not match:
            raise ValueError("git_unavailable")
        status = match.group(3)
        if index >= len(tokens):
            raise ValueError("git_unavailable")
        first = tokens[index]
        index += 1
        if status.startswith("R"):
            if index >= len(tokens):
                raise ValueError("git_unavailable")
            old_path, path = first, tokens[index]
            index += 1
        else:
            old_path, path = None, first
        rows.append((old_path, path, status, match.group(1), match.group(2)))
        if len(rows) > _APPLIED_CHANGE_MAX_PATHS:
            raise ValueError("resource_exhausted")
    return rows


def _parse_status_paths(output: bytes) -> dict[str, str]:
    tokens = output.split(b"\0")
    paths = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if not token:
            continue
        if len(token) < 4:
            raise ValueError("git_unavailable")
        path = token[3:]
        status = token[:2]
        paths[path.decode("utf-8", "strict")] = status.decode("ascii", "strict")
        if b"R" in status or b"C" in status:
            if index >= len(tokens):
                raise ValueError("git_unavailable")
            index += 1
    if len(paths) > _APPLIED_CHANGE_MAX_PATHS:
        raise ValueError("resource_exhausted")
    return paths


def _literal_workspace_file(
    root: Path, value: str, *, may_be_missing: bool = False
) -> Path:
    if not value or "\x00" in value or Path(value).is_absolute():
        raise ValueError("unsafe_path")
    target = root / Path(value)
    try:
        target.relative_to(root)
        if any(part in {"", ".", ".."} for part in Path(value).parts):
            raise ValueError("unsafe_path")
        from .runtime_audit_process import (
            path_chain_has_no_links,
            regular_target_within,
        )

        safe = (
            path_chain_has_no_links(root, target)
            if may_be_missing
            else regular_target_within(root, target)
        )
        if not safe:
            raise ValueError("unsafe_path")
        return target
    except (OSError, RuntimeError) as exc:
        raise ValueError("unsafe_path") from exc


class ProofWorklogError(ValueError):
    """Stable refusal for a stale or unsafe local worklog request."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProofWorklogError(
            "E_PROOF_WORKLOG_SCHEMA", "worklog must be canonical JSON"
        ) from exc


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _relative(root: Path, value: Path, field: str, *, exists: bool) -> Path:
    if value.is_absolute():
        target = value.resolve()
    else:
        target = (root / value).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ProofWorklogError(
            "E_PROOF_WORKLOG_SCOPE", f"{field} must remain beneath the workspace"
        ) from exc
    if exists and not target.is_file():
        raise ProofWorklogError(
            "E_PROOF_WORKLOG_EVIDENCE", f"{field} must name an existing workspace file"
        )
    return target


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
        prefix=".proof-worklog-",
        suffix=".tmp",
    ) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    temporary.replace(path)


def _text(item: object, fallback: str) -> str:
    if (
        isinstance(item, dict)
        and isinstance(item.get("statement"), str)
        and item["statement"].strip()
    ):
        return item["statement"].strip()[:240]
    return fallback


def _draft_text(
    contract: dict[str, Any], agent: dict[str, Any], atomic: dict[str, Any]
) -> tuple[str, list[str]]:
    contract_id = str(contract.get("id", "sealed-contract"))
    scope = ", ".join(contract.get("scope_paths", [])) or "no declared scope"
    rules = contract.get("rules", {})
    requirements = (
        [
            _text(item, "Approved obligation")
            for item in rules.get("requirements", [])[:3]
        ]
        if isinstance(rules, dict)
        else []
    )
    forbidden = (
        [
            _text(item, "Forbidden behavior")
            for item in rules.get("forbidden_behaviors", [])[:2]
        ]
        if isinstance(rules, dict)
        else []
    )
    lines = [
        f"# Proof review: {contract_id}",
        "",
        "This is a local review draft generated from hash-verified receipts. It has not been posted or sent anywhere.",
        "",
        "## Sealed intent",
        f"- Scope: `{scope}`",
        *[f"- Obligation: {item}" for item in requirements],
        *[f"- Guardrail: {item}" for item in forbidden],
        "",
        "## Observed local evidence",
        f"- Provider-neutral agent proof receipts currently bound: {agent['bound_count']}; invalid: {agent['invalid_count']}.",
        f"- Atomic workflow receipts currently bound: {atomic['bound_count']}; invalid: {atomic['invalid_count']}.",
        "",
        "## Human review requested",
        "- Confirm the observed receipts are relevant to this change.",
        "- Confirm the independent validators and negative cases are sufficient.",
        "- Decide whether to copy this draft into your tracker or worklog. Code Factory will not post it for you.",
    ]
    return "\n".join(lines) + "\n", requirements + forbidden


def create_proof_worklog(
    root: Path, contract_path: Path, out: Path | None = None
) -> dict[str, Any]:
    """Write one immutable local, review-required worklog draft."""
    workspace = Path(root).resolve()
    contract_file = _relative(workspace, contract_path, "contract", exists=True)
    if contract_file.stat().st_size > MAX_BYTES:
        raise ProofWorklogError("E_PROOF_WORKLOG_EVIDENCE", "contract exceeds 1 MiB")
    checked = verify_oracle_contract(workspace, contract_file.relative_to(workspace))
    if not checked.get("ok"):
        raise ProofWorklogError(
            "E_PROOF_WORKLOG_UNBOUND_INTENT",
            "worklog requires one current sealed Oracle Contract",
        )
    contract = checked.get("contract")
    if (
        not isinstance(contract, dict)
        or not isinstance(contract.get("id"), str)
        or not contract["id"].strip()
        or not isinstance(contract.get("contract_sha256"), str)
    ):
        raise ProofWorklogError(
            "E_PROOF_WORKLOG_UNBOUND_INTENT", "sealed Oracle Contract is incomplete"
        )
    agent, atomic = (
        agent_proof_projection(workspace),
        atomic_proof_projection(workspace),
    )
    markdown, obligations = _draft_text(contract, agent, atomic)
    core: dict[str, Any] = {
        "schema": SCHEMA,
        "marker": MARKER,
        "created_at": _now(),
        "contract": {
            "id": contract["id"],
            "path": contract_file.relative_to(workspace).as_posix(),
            "contract_sha256": contract["contract_sha256"],
            "scope_paths": list(contract.get("scope_paths", [])),
        },
        "obligation_summary": obligations,
        "evidence": {
            "agent_bridge": {
                "bound_count": agent["bound_count"],
                "invalid_count": agent["invalid_count"],
                "receipt_sha256s": [
                    item["receipt_sha256"] for item in agent["receipts"]
                ],
            },
            "atomic": {
                "bound_count": atomic["bound_count"],
                "invalid_count": atomic["invalid_count"],
                "receipt_sha256s": [
                    item["receipt_sha256"] for item in atomic.get("receipts", [])
                ],
            },
        },
        "markdown": markdown,
        "review_required": True,
        "authority": dict(AUTHORITY),
        "claim_boundary": "A local review draft from verified receipt summaries. It does not prove an external delivery, ticket update, production result, team acknowledgement, release, or approval and never posts to a third-party service.",
    }
    receipt = {**core, "draft_sha256": _sha(core)}
    destination = (
        out
        or Path(".factory")
        / "worklogs"
        / f"{contract['id']}-{receipt['draft_sha256'][:12]}.json"
    )
    target = _relative(workspace, destination, "out", exists=False)
    if target.exists():
        raise ProofWorklogError(
            "E_PROOF_WORKLOG_EVIDENCE",
            "output draft already exists; use a new immutable path",
        )
    _write(target, receipt)
    return {**receipt, "path": target.relative_to(workspace).as_posix()}


def verify_proof_worklog(root: Path, draft_path: Path) -> dict[str, Any]:
    """Verify one draft and current sealed contract binding without posting it."""
    workspace = Path(root).resolve()
    try:
        target = _relative(workspace, draft_path, "draft", exists=True)
        if target.stat().st_size > MAX_BYTES:
            raise ProofWorklogError("E_PROOF_WORKLOG_EVIDENCE", "draft exceeds 1 MiB")
        value = json.loads(target.read_text(encoding="utf-8-sig"))
        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise ProofWorklogError(
                "E_PROOF_WORKLOG_SCHEMA", "draft schema is unsupported"
            )
        core = {key: item for key, item in value.items() if key != "draft_sha256"}
        if value.get("draft_sha256") != _sha(core):
            raise ProofWorklogError(
                "E_PROOF_WORKLOG_EVIDENCE",
                "draft digest does not match its canonical body",
            )
        contract = value.get("contract")
        if not isinstance(contract, dict) or not isinstance(contract.get("path"), str):
            raise ProofWorklogError(
                "E_PROOF_WORKLOG_UNBOUND_INTENT", "draft has no sealed contract binding"
            )
        checked = verify_oracle_contract(workspace, Path(contract["path"]))
        if not checked.get("ok") or checked.get("contract", {}).get(
            "contract_sha256"
        ) != contract.get("contract_sha256"):
            return {
                "ok": False,
                "marker": "PROOF_WORKLOG_DRAFT_INVALID",
                "reason": "oracle_binding_stale",
                "authority": dict(AUTHORITY),
            }
        return {
            "ok": True,
            "marker": "PROOF_WORKLOG_DRAFT_VALID",
            "draft": value,
            "path": target.relative_to(workspace).as_posix(),
            "authority": dict(AUTHORITY),
        }
    except (
        ProofWorklogError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        return {
            "ok": False,
            "marker": "PROOF_WORKLOG_DRAFT_INVALID",
            "reason": getattr(exc, "code", "E_PROOF_WORKLOG_SCHEMA"),
            "authority": dict(AUTHORITY),
        }


def proof_worklog_projection(root: Path) -> dict[str, Any]:
    """Return bounded, read-only draft facts for Graph Ops and MCP."""
    workspace = Path(root).resolve()
    drafts, invalid = [], []
    for path in sorted((workspace / ".factory" / "worklogs").glob("*.json"))[:200]:
        checked = verify_proof_worklog(workspace, path.relative_to(workspace))
        if not checked.get("ok"):
            invalid.append(path.relative_to(workspace).as_posix())
            continue
        draft = checked["draft"]
        drafts.append(
            {
                "path": checked["path"],
                "contract_id": draft["contract"].get("id"),
                "contract_sha256": draft["contract"].get("contract_sha256"),
                "draft_sha256": draft["draft_sha256"],
                "review_required": True,
            }
        )
    return {
        "schema": "factory.proof-worklog-projection.v1",
        "marker": MARKER,
        "draft_count": len(drafts),
        "invalid_count": len(invalid),
        "latest": drafts[-1] if drafts else None,
        "drafts": drafts[-20:],
        "invalid": invalid[:100],
        "authority": dict(AUTHORITY),
        "claim_boundary": "Read-only local worklog draft facts. Nothing was sent, posted, approved, or released.",
    }

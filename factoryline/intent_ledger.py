"""Local, hash-bound intent memory for one explicitly scoped change list.

The Intent Ledger is deliberately narrower than free-form project memory.  A
developer records one confirmed behavioral promise, non-goal, and negative case
for explicit local paths.  Inspection then composes the existing Diff-to-Proof
review without executing it.  A ledger can therefore make scope drift and stale
proof visible without inventing intent, running a test, or granting authority.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import time
from typing import Any

from .change_review import ChangeReviewError, review_change


INTENT_LEDGER_SCHEMA = "factory.intent-ledger.v1"
INTENT_LEDGER_INSPECTION_SCHEMA = "factory.intent-ledger-inspection.v1"
INTENT_LEDGER_DIRECTORY = Path(".factory") / "intent-ledgers"
MAX_RECORD_BYTES = 256 * 1024
MAX_CHANGED_PATHS = 200
MAX_TEXT = 600
MAX_CHANGE_LIST_NAME = 160
_PATH = re.compile(r"^[^/\\]+(?:[/\\][^/\\]+)*$")

CAPTURE_AUTHORITY = {
    "record_write": True,
    "source_write": False,
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
    "memory_recall": False,
}
INSPECTION_AUTHORITY = {**CAPTURE_AUTHORITY, "record_write": False}


class IntentLedgerError(ValueError):
    """Raised when an Intent Ledger input cannot be trusted."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _text(value: object, field: str, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise IntentLedgerError("INTENT_LEDGER_INPUT_INVALID", f"{field} must be a non-empty string")
    result = " ".join(value.replace("\x00", " ").split())
    if not result or len(result) > maximum:
        raise IntentLedgerError("INTENT_LEDGER_INPUT_INVALID", f"{field} must contain 1 through {maximum} characters")
    return result


def _changed_path(value: object) -> str:
    if not isinstance(value, str):
        raise IntentLedgerError("INTENT_LEDGER_PATH_INVALID", "changed paths must be strings")
    result = value.replace("\\", "/").strip().removeprefix("./").rstrip("/")
    if not result or result.startswith("/") or re.match(r"^[A-Za-z]:/", result) or ".." in result.split("/") or not _PATH.fullmatch(result):
        raise IntentLedgerError("INTENT_LEDGER_PATH_INVALID", "changed paths must be non-empty workspace-relative paths without parent traversal")
    return result


def _paths(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise IntentLedgerError("INTENT_LEDGER_PATH_INVALID", "changed must contain at least one workspace-relative path")
    result = sorted({_changed_path(item) for item in value})
    if len(result) > MAX_CHANGED_PATHS:
        raise IntentLedgerError("INTENT_LEDGER_PATH_LIMIT", f"at most {MAX_CHANGED_PATHS} changed paths are supported")
    return result


def _change_list(value: object) -> str:
    return _text(value, "change_list", maximum=MAX_CHANGE_LIST_NAME)


def _directory(root: Path, *, create: bool) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise IntentLedgerError("INTENT_LEDGER_ROOT_INVALID", "root must name an existing workspace directory")
    directory = workspace / INTENT_LEDGER_DIRECTORY
    if create:
        directory.mkdir(parents=True, exist_ok=True)
    return directory


def _change_list_token(change_list: str) -> str:
    return sha256(change_list.encode("utf-8")).hexdigest()[:16]


def _record_core(
    *,
    change_list: str,
    changed_paths: list[str],
    confirmed_by: str,
    promise: str,
    non_goal: str,
    failure_case: str,
    captured_at: str,
) -> dict[str, Any]:
    return {
        "schema": INTENT_LEDGER_SCHEMA,
        "marker": "INTENT_LEDGER_CAPTURED",
        "change_list": change_list,
        "declared_scope_paths": changed_paths,
        "intent": {"promise": promise, "non_goal": non_goal, "failure_case": failure_case},
        "confirmed_by": confirmed_by,
        "captured_at": captured_at,
        "authority": CAPTURE_AUTHORITY,
        "scope_limits": [
            "Capture writes only this local Intent Ledger record; it does not edit source or change a JetBrains Change List.",
            "Capture does not run a test, start an agent, recall memory, approve, repair, merge, publish, deploy, sign, message, access credentials, or grant a connector.",
        ],
    }


def validate_intent_ledger_record(value: object) -> dict[str, Any]:
    """Validate one canonical record before projection; no filesystem access occurs."""
    if not isinstance(value, dict):
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "Intent Ledger record must be a JSON object")
    required = {
        "schema", "marker", "change_list", "declared_scope_paths", "intent", "confirmed_by", "captured_at",
        "authority", "scope_limits", "ledger_sha256",
    }
    if set(value) != required or value.get("schema") != INTENT_LEDGER_SCHEMA or value.get("marker") != "INTENT_LEDGER_CAPTURED":
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "Intent Ledger record has unsupported fields or schema")
    change_list = _change_list(value.get("change_list"))
    paths = _paths(value.get("declared_scope_paths"))
    intent = value.get("intent")
    if not isinstance(intent, dict) or set(intent) != {"promise", "non_goal", "failure_case"}:
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "Intent Ledger intent must contain exactly promise, non_goal, and failure_case")
    normalized_intent = {field: _text(intent.get(field), f"intent.{field}") for field in ("promise", "non_goal", "failure_case")}
    confirmed_by = _text(value.get("confirmed_by"), "confirmed_by", maximum=MAX_CHANGE_LIST_NAME)
    captured_at = value.get("captured_at")
    if not isinstance(captured_at, str):
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "captured_at must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "captured_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "captured_at must include a timezone")
    if value.get("authority") != CAPTURE_AUTHORITY:
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "Intent Ledger authority boundary changed")
    scope_limits = value.get("scope_limits")
    if not isinstance(scope_limits, list) or len(scope_limits) != 2 or not all(isinstance(item, str) and item for item in scope_limits):
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "Intent Ledger scope limits are invalid")
    core = _record_core(
        change_list=change_list,
        changed_paths=paths,
        confirmed_by=confirmed_by,
        promise=normalized_intent["promise"],
        non_goal=normalized_intent["non_goal"],
        failure_case=normalized_intent["failure_case"],
        captured_at=parsed.isoformat(),
    )
    digest = value.get("ledger_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest) or digest != _sha(core):
        raise IntentLedgerError("INTENT_LEDGER_INVALID", "Intent Ledger SHA-256 does not match its declared facts")
    return {**core, "ledger_sha256": digest}


def _atomic_json(path: Path, payload: dict[str, Any]) -> Path:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    return path


def capture_intent_ledger(
    root: Path,
    *,
    change_list: str,
    changed: list[str],
    confirmed_by: str,
    promise: str,
    non_goal: str,
    failure_case: str,
    confirmation: str,
    captured_at: datetime | None = None,
) -> dict[str, Any]:
    """Write one named-confirmation local record; never runs code or mutates source."""
    selected_change_list = _change_list(change_list)
    expected_confirmation = f"CAPTURE {selected_change_list}"
    if confirmation != expected_confirmation:
        raise IntentLedgerError("INTENT_LEDGER_CONFIRMATION_REQUIRED", f"confirmation must equal {expected_confirmation!r}")
    paths = _paths(changed)
    timestamp = (captured_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    core = _record_core(
        change_list=selected_change_list,
        changed_paths=paths,
        confirmed_by=_text(confirmed_by, "confirmed_by", maximum=MAX_CHANGE_LIST_NAME),
        promise=_text(promise, "promise"),
        non_goal=_text(non_goal, "non_goal"),
        failure_case=_text(failure_case, "failure_case"),
        captured_at=timestamp,
    )
    record = {**core, "ledger_sha256": _sha(core)}
    directory = _directory(root, create=True)
    # The record digest alone is not a unique capture identifier: two captures
    # can legitimately contain identical facts and Windows may return the same
    # wall-clock tick for both.  Keep the content hash in the name, but prefix
    # it with a nanosecond sequence so a later capture never overwrites an
    # earlier receipt and remains the lexicographic tie-breaker for equal mtimes.
    capture_sequence = time.time_ns()
    filename = f"intent-{_change_list_token(selected_change_list)}-{capture_sequence:020d}-{record['ledger_sha256'][:12]}.json"
    while (directory / filename).exists():
        capture_sequence += 1
        filename = f"intent-{_change_list_token(selected_change_list)}-{capture_sequence:020d}-{record['ledger_sha256'][:12]}.json"
    path = _atomic_json(directory / filename, record)
    workspace = Path(root).resolve()
    return {
        "schema": "factory.intent-ledger-capture.v1",
        "marker": "INTENT_LEDGER_CAPTURED",
        "record": record,
        "path": path.relative_to(workspace).as_posix(),
        "authority": CAPTURE_AUTHORITY,
        "scope_limits": [
            "Capture stored only the named local Intent Ledger record.",
            "No source, Change List, test, agent, approval, repair, merge, publication, deployment, signing, messaging, credential, connector, or memory-recall action ran.",
        ],
    }


def _latest_record(root: Path, change_list: str) -> tuple[dict[str, Any] | None, str | None, str | None]:
    directory = _directory(root, create=False)
    if not directory.is_dir():
        return None, None, None
    pattern = f"intent-{_change_list_token(change_list)}-*.json"
    candidates = sorted(directory.glob(pattern), key=lambda path: (path.stat().st_mtime_ns, path.name), reverse=True)
    if not candidates:
        return None, None, None
    path = candidates[0]
    workspace = Path(root).resolve()
    try:
        size = path.stat().st_size
        if size > MAX_RECORD_BYTES:
            raise IntentLedgerError("INTENT_LEDGER_INVALID", f"Intent Ledger record exceeds {MAX_RECORD_BYTES} bytes")
        payload = json.loads(path.read_text(encoding="utf-8"))
        record = validate_intent_ledger_record(payload)
        if record["change_list"] != change_list:
            raise IntentLedgerError("INTENT_LEDGER_INVALID", "Intent Ledger record change list does not match its file selector")
        return record, path.relative_to(workspace).as_posix(), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, IntentLedgerError) as exc:
        code = exc.code if isinstance(exc, IntentLedgerError) else "INTENT_LEDGER_INVALID"
        return None, path.relative_to(workspace).as_posix(), code


def _state(kind: str, severity: str, message: str, **facts: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "message": message, "facts": facts}


def _next(action: str, reason: str, **facts: Any) -> dict[str, Any]:
    return {"action": action, "reason": reason, "facts": facts}


def _inspection(
    *,
    workspace: Path,
    change_list: str,
    changed_paths: list[str],
    record: dict[str, Any] | None,
    record_path: str | None,
    state: str,
    findings: list[dict[str, Any]],
    next_action: dict[str, Any],
    review: dict[str, Any],
    markers: list[str],
    scope_limits: list[str],
) -> dict[str, Any]:
    core = {
        "schema": INTENT_LEDGER_INSPECTION_SCHEMA,
        "marker": markers[0],
        "markers": markers,
        "state": state,
        "change_list": change_list,
        "current_changed_paths": changed_paths,
        "record": record,
        "record_path": record_path,
        "findings": findings,
        "next_action": next_action,
        "change_review": review,
        "authority": INSPECTION_AUTHORITY,
        "scope_limits": scope_limits,
    }
    return {**core, "inspection_sha256": _sha(core)}


def inspect_intent_ledger(
    root: Path,
    *,
    change_list: str,
    changed: list[str] | None = None,
    base: str = "main",
) -> dict[str, Any]:
    """Return current scope and proof status for one ledger without any write or execution."""
    workspace = Path(root).resolve()
    _directory(workspace, create=False)
    selected_change_list = _change_list(change_list)
    explicit = changed is not None
    changed_paths = _paths(changed) if changed is not None else []
    record, record_path, invalid_code = _latest_record(workspace, selected_change_list)
    shared_limits = [
        "Inspection is local and read-only: it does not run a test, edit source, change a Change List, start an agent, recall memory, approve, repair, merge, publish, deploy, sign, message, access credentials, or grant a connector.",
        "A ready-for-human-review result describes only declared local scope and available evidence; it is not production or release readiness.",
    ]
    if invalid_code:
        finding = _state("intent_ledger_invalid", "blocking", "The newest matching Intent Ledger record is malformed or tampered; no fallback record was used.", rejected_artifact=record_path, failure_code=invalid_code)
        return _inspection(
            workspace=workspace, change_list=selected_change_list, changed_paths=changed_paths, record=None, record_path=record_path,
            state="intent_ledger_invalid", findings=[finding], next_action=_next("repair_intent_ledger_record", finding["message"], rejected_artifact=record_path),
            review={"available": False, "reason": "intent_ledger_invalid"}, markers=["INTENT_LEDGER_INVALID", "INTENT_LEDGER_FAIL_CLOSED", "INTENT_LEDGER_NO_EXECUTION"], scope_limits=shared_limits,
        )
    if record is None:
        finding = _state("uncontracted", "required", "No intact Intent Ledger record exists for this Change List; FactoryLine did not infer a behavioral promise.")
        return _inspection(
            workspace=workspace, change_list=selected_change_list, changed_paths=changed_paths, record=None, record_path=None,
            state="uncontracted", findings=[finding], next_action=_next("capture_intent", finding["message"], change_list=selected_change_list),
            review={"available": False, "reason": "uncontracted"}, markers=["INTENT_LEDGER_UNCONTRACTED", "INTENT_LEDGER_NO_EXECUTION"], scope_limits=shared_limits,
        )
    try:
        review_value = review_change(workspace, base=base, changed=changed if explicit else None)
        current_paths = review_value["changed_paths"]
    except ChangeReviewError as exc:
        finding = _state("change_review_unavailable", "blocking", "The current change set could not be mapped to proof; FactoryLine did not select a proof by guesswork.", failure_code=exc.code)
        return _inspection(
            workspace=workspace, change_list=selected_change_list, changed_paths=changed_paths, record=record, record_path=record_path,
            state="change_review_unavailable", findings=[finding], next_action=_next("inspect_change_set", finding["message"], failure_code=exc.code),
            review={"available": False, "failure_code": exc.code, "message": str(exc)}, markers=["INTENT_LEDGER_CHANGE_REVIEW_UNAVAILABLE", "INTENT_LEDGER_NO_EXECUTION"], scope_limits=shared_limits,
        )
    declared_paths = record["declared_scope_paths"]
    scope_escape_paths = sorted(set(current_paths) - set(declared_paths))
    review_summary = {
        "available": True,
        "input_source": review_value["input_source"],
        "review_sha256": review_value["review_sha256"],
        "unproven_claims": review_value["unproven_claims"],
        "coverage_complete": review_value["coverage"]["ok"],
        "stale_proof_ids": [item["proof_id"] for item in review_value["impact"]["rerun_proofs"]],
    }
    if scope_escape_paths:
        finding = _state("scope_escape", "blocking", "Current Change List paths exceed the declared Intent Ledger scope.", paths=scope_escape_paths)
        return _inspection(
            workspace=workspace, change_list=selected_change_list, changed_paths=current_paths, record=record, record_path=record_path,
            state="scope_escape", findings=[finding], next_action=_next("amend_or_split_change_list", finding["message"], paths=scope_escape_paths),
            review=review_summary, markers=["INTENT_LEDGER_SCOPE_ESCAPE", "INTENT_LEDGER_CHANGE_REVIEW_EXACT", "INTENT_LEDGER_NO_EXECUTION"], scope_limits=shared_limits,
        )
    stale_proof_ids = review_summary["stale_proof_ids"]
    if stale_proof_ids:
        finding = _state("stale_proof", "required", "A declared proof input changed after the proof was recorded.", proof_ids=stale_proof_ids)
        return _inspection(
            workspace=workspace, change_list=selected_change_list, changed_paths=current_paths, record=record, record_path=record_path,
            state="stale_proof", findings=[finding], next_action=_next("rerun_stale_proof", finding["message"], proof_id=stale_proof_ids[0]),
            review=review_summary, markers=["INTENT_LEDGER_STALE_PROOF", "INTENT_LEDGER_CHANGE_REVIEW_EXACT", "INTENT_LEDGER_NO_EXECUTION"], scope_limits=shared_limits,
        )
    if review_summary["coverage_complete"] is False:
        uncovered = review_value["coverage"].get("uncovered", [])
        finding = _state("coverage_incomplete", "required", "Requirement coverage is absent or incomplete for this change set.", requirements=uncovered)
        return _inspection(
            workspace=workspace, change_list=selected_change_list, changed_paths=current_paths, record=record, record_path=record_path,
            state="coverage_incomplete", findings=[finding], next_action=_next("complete_requirement_coverage", finding["message"], requirements=uncovered),
            review=review_summary, markers=["INTENT_LEDGER_COVERAGE_INCOMPLETE", "INTENT_LEDGER_CHANGE_REVIEW_EXACT", "INTENT_LEDGER_NO_EXECUTION"], scope_limits=shared_limits,
        )
    finding = _state("ready_for_human_review", "review", "No declared local scope, stale-proof, or coverage gap was found.")
    return _inspection(
        workspace=workspace, change_list=selected_change_list, changed_paths=current_paths, record=record, record_path=record_path,
        state="ready_for_human_review", findings=[finding], next_action=_next("review_packet", finding["message"]),
        review=review_summary, markers=["INTENT_LEDGER_READY_FOR_HUMAN_REVIEW", "INTENT_LEDGER_CHANGE_REVIEW_EXACT", "INTENT_LEDGER_NO_EXECUTION"], scope_limits=shared_limits,
    )

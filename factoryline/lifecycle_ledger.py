"""Hash-linked, local lifecycle events for harnesses and Graph Ops.

The ledger is intentionally a narrow interoperability seam.  An agent may
record what it observed in a sealed run, while a human or Graph Ops can inspect
the ordered facts.  It does not dispatch work, invoke a provider, or turn a
lifecycle event into permission.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .oracle_firewall import OracleFirewallError, verify_oracle_contract
from .protocol_enums import LifecycleEvent, SessionTraceStage


EVENT_SCHEMA = "factory.lifecycle-event.v1"
RECEIPT_SCHEMA = "factory.lifecycle-receipt.v1"
PROJECTION_SCHEMA = "factory.lifecycle-projection.v1"
RECEIPT_DIR = Path(".factory/lifecycle")
MAX_BYTES = 1_048_576
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,95}$")
_EVENTS = tuple(event.value for event in LifecycleEvent)
_TRACE_STAGES = tuple(stage.value for stage in SessionTraceStage)
_ALLOWED = {
    "created": {"isolated", "stopped"}, "isolated": {"context_ready", "stopped"},
    "context_ready": {"proof_ready", "review_required", "escalated", "stopped"},
    "proof_ready": {"review_required", "completed", "escalated", "stopped"},
    "review_required": {"completed", "escalated", "stopped"},
    "escalated": {"stopped"}, "completed": set(), "stopped": set(),
}
AUTHORITY = {
    "execution": False, "approval": False, "repair": False, "merge": False,
    "publication": False, "deployment": False, "signing": False,
    "messaging": False, "credential": False, "connector": False,
}


class LifecycleLedgerError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "input must be canonical JSON") from exc


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


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", f"{label} must be a safe identifier")
    return value


def _hash(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", f"{label} must be a lowercase SHA-256")
    return value


def _relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", f"{label} must be a workspace-relative path")
    path = Path(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise LifecycleLedgerError("E_LIFECYCLE_PATH", f"{label} escapes the workspace")
    return path.as_posix().rstrip("/") or "."


def _inside(root: Path, relative: str, *, required: bool = False) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise LifecycleLedgerError("E_LIFECYCLE_PATH", "path escapes the workspace") from exc
    if required and not target.is_file():
        raise LifecycleLedgerError("E_LIFECYCLE_EVIDENCE", f"evidence file is unavailable: {relative}")
    return target


def _read(root: Path, relative: str) -> tuple[dict[str, Any], str]:
    path = _inside(root, relative, required=True)
    if path.stat().st_size > MAX_BYTES:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "event exceeds the 1 MiB limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "event must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "event must be an object")
    return value, _file_sha(path)


def _event(root: Path, source: Path) -> tuple[dict[str, Any], str]:
    try:
        relative = source.resolve().relative_to(root).as_posix() if source.is_absolute() else _relative(str(source), "event path")
    except ValueError as exc:
        raise LifecycleLedgerError("E_LIFECYCLE_PATH", "event path escapes the workspace") from exc
    value, digest = _read(root, relative)
    fields = {"schema", "event_id", "run_id", "sequence", "event", "actor", "oracle", "session_trace", "evidence", "previous_receipt_sha256"}
    if set(value) != fields or value.get("schema") != EVENT_SCHEMA:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", f"event must use exact {EVENT_SCHEMA} fields")
    sequence = value["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "sequence must be a positive integer")
    event = value["event"]
    if event not in _EVENTS:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "event is unsupported")
    actor = value["actor"]
    if not isinstance(actor, dict) or set(actor) != {"kind", "id"} or actor["kind"] not in {"human", "agent", "system"}:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "actor must declare human, agent, or system identity")
    oracle = value["oracle"]
    if not isinstance(oracle, dict) or set(oracle) != {"contract_path", "contract_sha256"}:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "oracle fields must be exact")
    contract_path = _relative(oracle["contract_path"], "oracle.contract_path")
    contract_sha = _hash(oracle["contract_sha256"], "oracle.contract_sha256")
    try:
        contract = verify_oracle_contract(root, Path(contract_path))
    except OracleFirewallError as exc:
        raise LifecycleLedgerError("E_LIFECYCLE_ORACLE", str(exc)) from exc
    if not contract.get("ok") or contract.get("contract", {}).get("contract_sha256") != contract_sha:
        raise LifecycleLedgerError("E_LIFECYCLE_ORACLE", "event must bind the current sealed Oracle Contract")
    session_trace = value["session_trace"]
    if not isinstance(session_trace, dict) or set(session_trace) != {"session_id", "harness", "stage", "input_sha256", "output_sha256"}:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "session_trace fields must be exact")
    if session_trace["stage"] not in _TRACE_STAGES:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "session_trace.stage is unsupported")
    normalized_trace = {
        "session_id": _identifier(session_trace["session_id"], "session_trace.session_id"),
        "harness": _identifier(session_trace["harness"], "session_trace.harness"),
        "stage": session_trace["stage"],
        "input_sha256": _hash(session_trace["input_sha256"], "session_trace.input_sha256"),
        "output_sha256": _hash(session_trace["output_sha256"], "session_trace.output_sha256"),
    }
    evidence = value["evidence"]
    if not isinstance(evidence, list) or len(evidence) > 32:
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "evidence must contain at most 32 files")
    normalized_evidence = []
    for index, item in enumerate(evidence):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", f"evidence[{index}] fields must be exact")
        evidence_path = _relative(item["path"], f"evidence[{index}].path")
        expected = _hash(item["sha256"], f"evidence[{index}].sha256")
        actual = _file_sha(_inside(root, evidence_path, required=True))
        if actual != expected:
            raise LifecycleLedgerError("E_LIFECYCLE_EVIDENCE", f"evidence[{index}] does not match local bytes")
        normalized_evidence.append({"path": evidence_path, "sha256": expected})
    if len({item["path"] for item in normalized_evidence}) != len(normalized_evidence):
        raise LifecycleLedgerError("E_LIFECYCLE_SCHEMA", "evidence paths must be unique")
    previous = value["previous_receipt_sha256"]
    if previous is not None:
        previous = _hash(previous, "previous_receipt_sha256")
    return {"event_id": _identifier(value["event_id"], "event_id"), "run_id": _identifier(value["run_id"], "run_id"), "sequence": sequence, "event": event, "actor": {"kind": actor["kind"], "id": _identifier(actor["id"], "actor.id")}, "oracle": {"contract_path": contract_path, "contract_sha256": contract_sha}, "session_trace": normalized_trace, "evidence": sorted(normalized_evidence, key=lambda item: item["path"]), "previous_receipt_sha256": previous, "source_path": relative, "source_sha256": digest}, digest


def _prior(root: Path, run_id: str) -> list[dict[str, Any]]:
    directory = root / RECEIPT_DIR
    result: list[dict[str, Any]] = []
    if not directory.is_dir():
        return result
    for path in sorted(directory.glob(f"{run_id}-*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            core = {key: value[key] for key in value if key != "receipt_sha256"}
            if value.get("schema") == RECEIPT_SCHEMA and value.get("run_id") == run_id and value.get("receipt_sha256") == _sha(core):
                result.append(value)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
    return sorted(result, key=lambda item: item.get("sequence", 0))


def record_lifecycle_event(root: Path, event_path: Path, out: Path | None = None) -> dict[str, Any]:
    """Append one Oracle-bound, hash-linked local session lifecycle receipt."""
    workspace = Path(root).resolve()
    event, _ = _event(workspace, event_path)
    prior = _prior(workspace, event["run_id"])
    if prior:
        last = prior[-1]
        if event["sequence"] != last["sequence"] + 1 or event["previous_receipt_sha256"] != last["receipt_sha256"]:
            raise LifecycleLedgerError("E_LIFECYCLE_CONTINUITY", "sequence and previous receipt must continue the exact local run")
        if event["event"] not in _ALLOWED.get(last["event"], set()):
            raise LifecycleLedgerError("E_LIFECYCLE_TRANSITION", "event transition is not allowed")
    elif event["sequence"] != 1 or event["event"] != "created" or event["previous_receipt_sha256"] is not None:
        raise LifecycleLedgerError("E_LIFECYCLE_CONTINUITY", "a new run must begin with sequence 1 created and no predecessor")
    core = {"schema": RECEIPT_SCHEMA, "marker": "LIFECYCLE_EVENT_RECORDED", **event, "session_trace_sha256": _sha(event["session_trace"]), "authority": dict(AUTHORITY), "scope_limits": ["A lifecycle event is local declared evidence, not proof of provider identity, actual execution, sandboxing, or model usage.", "Recording an event never dispatches work, resumes a run, approves a change, or contacts a connector."], "created_at": _now()}
    receipt = {**core, "receipt_sha256": _sha(core)}
    default = (RECEIPT_DIR / f"{event['run_id']}-{event['sequence']:04d}.json").as_posix()
    target_relative = _relative(str(out) if out else default, "output")
    if not target_relative.startswith(RECEIPT_DIR.as_posix() + "/"):
        raise LifecycleLedgerError("E_LIFECYCLE_PATH", "output must be beneath .factory/lifecycle")
    target = _inside(workspace, target_relative)
    if target.exists():
        raise LifecycleLedgerError("E_LIFECYCLE_EXISTS", "lifecycle receipt path is immutable; choose a new run or sequence")
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


def lifecycle_projection(root: Path) -> dict[str, Any]:
    """Project bounded valid lifecycle summaries without resuming an agent session."""
    workspace = Path(root).resolve()
    runs: dict[str, list[dict[str, Any]]] = {}
    invalid: list[str] = []
    directory = workspace / RECEIPT_DIR
    if directory.is_dir():
        for path in sorted(directory.glob("*.json"))[:500]:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                core = {key: value[key] for key in value if key not in {"receipt_sha256", "path"}}
                if value.get("schema") != RECEIPT_SCHEMA or value.get("receipt_sha256") != _sha(core):
                    raise ValueError("invalid receipt")
                runs.setdefault(value["run_id"], []).append(value)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
                invalid.append(path.relative_to(workspace).as_posix())
    summaries = []
    for run_id, events in sorted(runs.items()):
        ordered = sorted(events, key=lambda item: item["sequence"])
        latest = ordered[-1]
        trace = latest.get("session_trace") if isinstance(latest.get("session_trace"), dict) else {}
        summaries.append({"run_id": run_id, "event_count": len(ordered), "latest_event": latest["event"], "latest_sequence": latest["sequence"], "latest_receipt_sha256": latest["receipt_sha256"], "latest_session_trace": {"session_id": trace.get("session_id"), "harness": trace.get("harness"), "stage": trace.get("stage"), "trace_sha256": latest.get("session_trace_sha256")}, "requires_human": latest["event"] in {"review_required", "escalated"}})
    return {"schema": PROJECTION_SCHEMA, "marker": "LIFECYCLE_READ_ONLY", "run_count": len(summaries), "review_required_count": sum(item["requires_human"] for item in summaries), "invalid_count": len(invalid), "latest": summaries[-1] if summaries else None, "runs": summaries[-50:], "invalid": invalid[:100], "authority": dict(AUTHORITY), "claim_boundary": "Read-only local lifecycle facts. The projection does not dispatch a task, broadcast to a provider, start or resume an agent, or grant execution or approval authority."}


def lifecycle_template() -> dict[str, Any]:
    """Return a secret-free event template with required session-trace fields."""
    return {"schema": "factory.lifecycle-template.v1", "event_schema": EVENT_SCHEMA, "authority": dict(AUTHORITY), "claim_boundary": "Template only. It creates no event, session, provider connection, webhook, or approval.", "event": {"schema": EVENT_SCHEMA, "event_id": "replace-with-event-id", "run_id": "replace-with-run-id", "sequence": 1, "event": "created", "actor": {"kind": "agent", "id": "replace-with-declared-agent-id"}, "oracle": {"contract_path": ".factory/oracles/contracts/current.json", "contract_sha256": "replace-with-lowercase-sha256"}, "session_trace": {"session_id": "replace-with-session-id", "harness": "replace-with-harness", "stage": "intake", "input_sha256": "replace-with-lowercase-sha256", "output_sha256": "replace-with-lowercase-sha256"}, "evidence": [], "previous_receipt_sha256": None}}

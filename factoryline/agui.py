"""Deterministic AGUI-style review events for Code Factory.

This module is a provider-neutral presentation adapter.  It does not claim to
implement the complete external AGUI transport or an open-ended generative UI.
It converts existing local, read-only proof projections and MCP2 MRT payloads
into a small controlled/declarative event vocabulary that an IDE or dashboard
can render with its own component catalog.
"""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Iterable


SCHEMA = "factory.agui.events.v1"
MAX_EVENTS = 32
MAX_PAYLOAD_BYTES = 32_768
EVENT_TYPES = frozenset(
    {"RUN_STARTED", "STATE_SNAPSHOT", "REVIEW_CARD", "INTERRUPT", "RUN_FINISHED"}
)
_FORBIDDEN_KEYS = frozenset(
    {
        "credential",
        "credentials",
        "secret",
        "password",
        "pat",
        "token",
        "raw_prompt",
        "transcript",
    }
)
_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,95}$")


class AguiError(ValueError):
    """Fail-closed error at the controlled AGUI event boundary."""

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
    return sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _run_id(value: object) -> str:
    if not isinstance(value, str) or not _RUN_ID.fullmatch(value):
        raise AguiError(
            "E_AGUI_RUN_ID",
            "run_id must be lowercase and contain at most 96 safe characters",
        )
    return value


def _safe_object(value: dict[str, Any], depth: int) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or key.lower() in _FORBIDDEN_KEYS:
            raise AguiError(
                "E_AGUI_SENSITIVE",
                "event payload contains a forbidden sensitive field",
            )
        result[key] = _safe_value(item, depth=depth + 1)
    return result


def _safe_array(value: list[Any], depth: int) -> list[Any]:
    if len(value) > 64:
        raise AguiError("E_AGUI_BOUNDS", "event arrays may contain at most 64 items")
    return [_safe_value(item, depth=depth + 1) for item in value]


def _safe_value(value: Any, *, depth: int = 0) -> Any:
    """Copy only bounded JSON values and reject sensitive field names."""
    if depth > 5:
        raise AguiError("E_AGUI_DEPTH", "event payload nesting is too deep")
    if isinstance(value, dict):
        return _safe_object(value, depth)
    if isinstance(value, list):
        return _safe_array(value, depth)
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and len(value) > 4096:
            raise AguiError(
                "E_AGUI_BOUNDS", "event strings may contain at most 4096 characters"
            )
        return value
    raise AguiError("E_AGUI_PAYLOAD", "event payload must be JSON-compatible")


def _event(
    run_id: str, sequence: int, event_type: str, payload: dict[str, Any]
) -> dict[str, Any]:
    safe_payload = _safe_value(payload)
    core = {
        "schema": SCHEMA,
        "runId": run_id,
        "sequence": sequence,
        "type": event_type,
        "payload": safe_payload,
    }
    return {
        **core,
        "eventId": "agui:" + _sha(core)[:32],
        "payloadSha256": _sha(safe_payload),
    }


def _projection_payload(status: dict[str, Any]) -> dict[str, Any]:
    """Keep the card small while preserving the source-to-next-action path."""
    allowed = (
        "state",
        "marker",
        "receipt_path",
        "receipt_sha256",
        "stale_paths",
        "next_actions",
        "claim_boundary",
    )
    result = {key: status[key] for key in allowed if key in status}
    result["authority"] = status.get("authority", "none")
    return result


def build_review_events(
    status: dict[str, Any],
    *,
    run_id: str = "local-review",
    surface: str = "mission_control",
) -> list[dict[str, Any]]:
    """Build controlled/declarative review events from a local status projection."""
    rid = _run_id(run_id)
    if not isinstance(status, dict):
        raise AguiError("E_AGUI_STATUS", "status projection must be an object")
    if not isinstance(surface, str) or not surface.strip() or len(surface) > 64:
        raise AguiError("E_AGUI_SURFACE", "surface must be a bounded non-empty string")
    projection = _projection_payload(status)
    state = str(status.get("state", "UNKNOWN"))
    events = [
        _event(
            rid,
            0,
            "RUN_STARTED",
            {
                "surface": surface,
                "mode": "controlled_review",
                "authority": {"execution": False, "approval": False, "release": False},
            },
        ),
        _event(rid, 1, "STATE_SNAPSHOT", projection),
        _event(
            rid,
            2,
            "REVIEW_CARD",
            {
                "title": "Code Factory review",
                "state": state,
                "actionSummary": "Show the current evidence, blockers, and one next safe action.",
                "component": "ReviewCard",
                "humanDecisionRequired": state in {"BLOCKED", "READY"},
            },
        ),
        _event(
            rid,
            3,
            "RUN_FINISHED",
            {
                "state": state,
                "authority": {"execution": False, "approval": False, "release": False},
            },
        ),
    ]
    return validate_agui_events(events)


def build_release_interrupt_event(
    envelope: dict[str, Any], *, run_id: str = "release-gate"
) -> dict[str, Any]:
    """Map an MCP2 ``input_required`` payload to a human-owned AGUI interrupt."""
    rid = _run_id(run_id)
    if not isinstance(envelope, dict) or envelope.get("type") != "input_required":
        raise AguiError(
            "E_AGUI_INTERRUPT", "an MCP2 input_required envelope is required"
        )
    context = envelope.get("context")
    schema = envelope.get("inputSchema")
    if not isinstance(context, dict) or not isinstance(schema, dict):
        raise AguiError(
            "E_AGUI_INTERRUPT", "input_required must include context and inputSchema"
        )
    payload = {
        "toolCallId": envelope.get("toolCallId"),
        "message": envelope.get("prompt", "Human review is required."),
        "inputSchema": schema,
        "proofCardHash": context.get("proofCardHash"),
        "failedLanes": context.get("failedLanes", []),
        "proofDebt": context.get("proofDebt", []),
        "nextFactDerivedAction": context.get("nextFactDerivedAction"),
        "humanOwned": True,
        "authority": {"execution": False, "approval": False, "release": False},
    }
    event = _event(rid, 1, "INTERRUPT", payload)
    finish = _event(
        rid,
        2,
        "RUN_FINISHED",
        {
            "state": "WAITING_FOR_HUMAN",
            "authority": {"execution": False, "approval": False, "release": False},
        },
    )
    return validate_agui_events(
        [
            _event(
                rid,
                0,
                "RUN_STARTED",
                {"surface": "release_gate", "mode": "controlled_review"},
            ),
            event,
            finish,
        ]
    )[1]


def build_release_completed_event(
    envelope: dict[str, Any], *, run_id: str = "release-gate"
) -> dict[str, Any]:
    """Map an MCP2 ``completed`` payload to a bounded review event."""
    rid = _run_id(run_id)
    if not isinstance(envelope, dict) or envelope.get("type") != "completed":
        raise AguiError("E_AGUI_COMPLETED", "an MCP2 completed envelope is required")
    payload = {
        "toolCallId": envelope.get("toolCallId"),
        "status": envelope.get("status"),
        "receiptHash": envelope.get("receiptHash"),
        "summary": envelope.get("summary", ""),
        "humanOwned": True,
        "authority": {"execution": False, "approval": False, "release": False},
    }
    return _event(rid, 0, "RUN_FINISHED", payload)


def _validate_event(index: int, row: dict[str, Any]) -> None:
    """Check one event's schema, sequence, content binding, and size."""
    if not isinstance(row, dict) or row.get("schema") != SCHEMA:
        raise AguiError(
            "E_AGUI_SCHEMA", "every event must use the Code Factory AGUI schema"
        )
    if row.get("sequence") != index or row.get("type") not in EVENT_TYPES:
        raise AguiError(
            "E_AGUI_SEQUENCE",
            "event sequences must be contiguous and use known types",
        )
    rid = _run_id(row.get("runId"))
    payload = row.get("payload")
    if not isinstance(payload, dict) or row.get("payloadSha256") != _sha(payload):
        raise AguiError("E_AGUI_HASH", "payload hash does not match the event payload")
    core = {
        "schema": SCHEMA,
        "runId": rid,
        "sequence": index,
        "type": row["type"],
        "payload": payload,
    }
    if row.get("eventId") != "agui:" + _sha(core)[:32]:
        raise AguiError("E_AGUI_HASH", "event id does not match the event contents")
    if len(_canonical(row)) > MAX_PAYLOAD_BYTES:
        raise AguiError("E_AGUI_BOUNDS", "event exceeds the maximum encoded size")


def validate_agui_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate ordering, hashes, bounds, and the no-authority boundary."""
    rows = list(events)
    if not 1 <= len(rows) <= MAX_EVENTS:
        raise AguiError(
            "E_AGUI_BOUNDS", f"event stream must contain 1-{MAX_EVENTS} events"
        )
    for index, row in enumerate(rows):
        _validate_event(index, row)
    if rows[0]["type"] != "RUN_STARTED" or rows[-1]["type"] != "RUN_FINISHED":
        raise AguiError(
            "E_AGUI_SEQUENCE",
            "event stream must start with RUN_STARTED and end with RUN_FINISHED",
        )
    if (
        sum(row["type"] == "RUN_STARTED" for row in rows) != 1
        or sum(row["type"] == "RUN_FINISHED" for row in rows) != 1
    ):
        raise AguiError(
            "E_AGUI_SEQUENCE", "event stream must contain exactly one start and finish"
        )
    return rows

"""Bounded, local-only activity state for Factory Studio live views.

Meter rows are intentionally appended only after a stage has finished.  That is
right for immutable measurement, but it leaves an operator looking at a quiet
dashboard while a long-running stage is actually in flight.  This module adds
an atomic *ephemeral state projection* alongside that ledger.  It is not a
receipt, does not report tokens or cost, and never turns missing observations
into zero.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import time
from typing import Any


ACTIVITY_SCHEMA = "factory.live-activity.v1"
ACTIVITY_RELATIVE_PATH = Path(".factory") / "live-activity.json"
STALE_AFTER_SECONDS = 8.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


class LiveActivity:
    """Write one local assembly's activity state atomically.

    The file is deliberately overwriteable because it represents current
    operation state, not historical evidence.  Finished measurements and
    receipts remain append-only in their own ledgers.
    """

    def __init__(self, root: Path, run_id: str, feature: str, planned_stages: int):
        self.root = Path(root).resolve()
        self.path = self.root / ACTIVITY_RELATIVE_PATH
        self.run_id = run_id
        self.feature = feature
        self.planned_stages = planned_stages
        self._state: dict[str, Any] = {}

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(self._state, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as handle:
            handle.write(encoded)
            temporary = Path(handle.name)
        temporary.replace(self.path)

    def start(self) -> None:
        """Initialize and persist the active local Assembly projection.

        The new projection contains no inferred metering values and is replaced
        atomically so a reader cannot observe a partially written activity file.
        """
        now = _now()
        self._state = {
            "schema": ACTIVITY_SCHEMA,
            "status": "active",
            "operation": "assemble",
            "run_id": self.run_id,
            "feature": self.feature,
            "started_at": now,
            "heartbeat_at": now,
            "updated_at": now,
            "current_stage": None,
            "planned_stages": self.planned_stages,
            "completed_stages": 0,
            "failed_stages": 0,
            "skipped_stages": 0,
            "recent_stages": [],
            "markers": ["LIVE_ACTIVITY_LOCAL_ONLY", "TOKENS_COSTS_WITHHELD_UNTIL_REPORTED"],
        }
        self._write()

    def heartbeat(self) -> bool:
        """Refresh liveness unless a supervised cooperative stop was requested.

        A false result tells the Assembly loop to stop before launching another
        child stage; it never terminates a process or changes a receipt itself.
        """
        if self._state.get("status") != "active":
            return False
        if self.cancel_requested():
            return False
        now = _now()
        self._state["heartbeat_at"] = now
        self._state["updated_at"] = now
        self._write()
        return True

    def stage_started(self, module: str, stage: str) -> None:
        """Project the named stage as active for a local observer.

        This ephemeral state supports Studio refresh only and does not make the
        stage a completed measurement, verified proof, or durable receipt.
        """
        if self._state.get("status") != "active":
            return
        now = _now()
        self._state["current_stage"] = {"module": module, "stage": stage, "started_at": now}
        self._state["heartbeat_at"] = now
        self._state["updated_at"] = now
        self._write()

    def stage_finished(self, module: str, stage: str, status: str, *, wall_ms: int | None = None) -> None:
        """Record a bounded finished-stage summary in the live projection.

        Completed rows remain informational until their normal meter and proof
        paths write evidence; absent time, token, and cost fields stay absent.
        """
        if not self._state:
            return
        row: dict[str, Any] = {"module": module, "stage": stage, "status": status, "finished_at": _now()}
        if wall_ms is not None:
            row["wall_ms"] = wall_ms
        recent = list(self._state.get("recent_stages", []))[-11:]
        recent.append(row)
        self._state["recent_stages"] = recent
        if status == "ok":
            self._state["completed_stages"] = int(self._state.get("completed_stages", 0)) + 1
        elif status == "failed":
            self._state["failed_stages"] = int(self._state.get("failed_stages", 0)) + 1
        elif status in {"skipped", "would-run"}:
            self._state["skipped_stages"] = int(self._state.get("skipped_stages", 0)) + 1
        self._state["current_stage"] = None
        self.heartbeat()

    def finish(self, terminal: str, *, halted_at: str | None = None, paused_at: str | None = None) -> None:
        """Mark the current local projection terminal without altering receipts.

        The terminal marker helps refresh clients retire activity state while the
        Assembly's normal result, meter, and continuation records remain intact.
        """
        if not self._state:
            return
        now = _now()
        self._state.update({
            "status": terminal,
            "current_stage": None,
            "finished_at": now,
            "heartbeat_at": now,
            "updated_at": now,
            "halted_at": halted_at,
            "paused_at": paused_at,
        })
        self._write()

    def cancel_requested(self) -> bool:
        """Read a current cancellation request without overwriting it."""
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(value, dict) and value.get("run_id") == self.run_id and bool(value.get("cancel_requested_at"))


def activity_snapshot(root: Path, *, stale_after_seconds: float = STALE_AFTER_SECONDS) -> dict[str, Any]:
    """Return one safe, current local activity projection for Studio surfaces."""
    path = Path(root).resolve() / ACTIVITY_RELATIVE_PATH
    unavailable = {
        "schema": ACTIVITY_SCHEMA,
        "status": "idle",
        "available": False,
        "current_stage": None,
        "elapsed_ms": None,
        "markers": ["LIVE_ACTIVITY_UNAVAILABLE"],
    }
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return unavailable
    if not isinstance(value, dict) or value.get("schema") != ACTIVITY_SCHEMA:
        return unavailable
    result = dict(value)
    result["available"] = True
    now = datetime.now(timezone.utc)
    started = _parse_time(value.get("started_at"))
    heartbeat = _parse_time(value.get("heartbeat_at"))
    result["elapsed_ms"] = max(0, int((now - started).total_seconds() * 1000)) if started else None
    if value.get("status") == "active" and (heartbeat is None or (now - heartbeat).total_seconds() > stale_after_seconds):
        result["status"] = "stale"
        result["stale_reason"] = "No heartbeat was observed within the local activity freshness window."
        result["markers"] = list(value.get("markers", [])) + ["LIVE_ACTIVITY_STALE"]
    else:
        result["markers"] = list(value.get("markers", [])) + ["LIVE_ACTIVITY_FRESH"]
    return result


def request_stop(root: Path) -> dict[str, Any]:
    """Request a cooperative stop for the one active local assembly.

    The assembly runner checks this request while it waits for a child stage.
    It is intentionally not a process-kill API and cannot target arbitrary
    programs.
    """
    path = Path(root).resolve() / ACTIVITY_RELATIVE_PATH
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("No readable active Factory activity exists.") from exc
    if not isinstance(value, dict) or value.get("schema") != ACTIVITY_SCHEMA or value.get("status") != "active":
        raise ValueError("No active Factory assembly can be stopped.")
    value["cancel_requested_at"] = _now()
    value["updated_at"] = value["cancel_requested_at"]
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        handle.write(encoded)
        temporary = Path(handle.name)
    temporary.replace(path)
    return {
        "schema": ACTIVITY_SCHEMA,
        "marker": "LIVE_ACTIVITY_STOP_REQUESTED",
        "run_id": value.get("run_id"),
        "feature": value.get("feature"),
        "authority": {"stops_active_local_assembly": True, "publish": False, "deploy": False, "sign": False, "credentials": False},
    }

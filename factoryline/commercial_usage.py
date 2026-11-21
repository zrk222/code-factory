"""factoryline.commercial_usage - atomic local reservation ledger.

This is the local usage ledger behind the commercial gate. It lives in a
user-level data directory (default ~/.factoryline/commercial, override with
FACTORY_COMMERCIAL_HOME), NOT in any project's resettable .factory folder, so
deleting a workspace does not rewrite history.

Honesty boundary, stated up front: this is a transparent soft counter on the
user's own machine. A determined user can edit or delete it, and it cannot see
other devices. Strong cross-device limits require a separately approved
account/entitlement service; this ledger is the client-side half of that
contract (reserve/finalize/release with idempotency), not a tamper-proof meter.

Semantics:
- reserve -> one workflow admitted; holds a slot until finalize or release.
- finalize(outcome=completed) -> the workflow ran to a terminal result; counts.
- release(outcome=tool_error|rejected) -> internal error or rejected start;
  never counts. A real check finding a defect is a completed workflow, not a
  tool error.
- A retry with the same idempotency key returns the original reservation
  instead of double charging.
- Open reservations older than the TTL (default 6h) are expired on next load,
  so a crashed process cannot hold a slot forever.
- Clock rollback never grants extra allowance: periods and expiry are computed
  from max(now, newest timestamp ever recorded in this ledger).

All mutations happen under an exclusive flock around a read-modify-append of a
JSONL event log, so concurrent processes cannot both spend the last slot.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None

RESERVATION_TTL_SECONDS = 6 * 60 * 60
LEDGER_FILENAME = "usage-ledger.jsonl"
LOCK_FILENAME = "usage-ledger.lock"

RESERVE = "reserve"
FINALIZE = "finalize"
RELEASE = "release"
EXPIRE = "expire"

COMPLETED = "completed"
TOOL_ERROR = "tool_error"
REJECTED = "rejected"
SETTLE_OUTCOMES = frozenset({COMPLETED, TOOL_ERROR, REJECTED})

# Repair-rerun compatibility, defined explicitly: a rerun is the same change
# when scope and plan digests match the original workflow. A new candidate
# digest alone never disqualifies a repair (the repair changes the candidate);
# expanded scope or a different plan is a new workflow, not a rerun.
RERUN_BINDING_FIELDS = ("scope_digest", "plan_digest")


class CommercialUsageError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def default_home() -> Path:
    override = os.environ.get("FACTORY_COMMERCIAL_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".factoryline" / "commercial"


def _utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _parse_ts(value: Any) -> datetime:
    if not isinstance(value, str):
        raise CommercialUsageError("E_LEDGER_CORRUPT", "event timestamp missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CommercialUsageError("E_LEDGER_CORRUPT", f"bad timestamp {value!r}") from exc
    return _utc(parsed)


def _iso(now: datetime) -> str:
    return _utc(now).isoformat()


@dataclass
class Reservation:
    reservation_id: str
    subject: str
    period: str
    workflow_id: str
    idempotency_key: str
    binding: dict[str, Any]
    rerun_of: str | None
    status: str = "open"  # open | finalized | released | expired
    outcome: str | None = None
    created_at: str = ""
    closed_at: str | None = None
    replayed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "subject": self.subject,
            "period": self.period,
            "workflow_id": self.workflow_id,
            "idempotency_key": self.idempotency_key,
            "binding": self.binding,
            "rerun_of": self.rerun_of,
            "status": self.status,
            "outcome": self.outcome,
            "created_at": self.created_at,
            "closed_at": self.closed_at,
            "replayed": self.replayed,
        }


@dataclass
class LedgerState:
    reservations: dict[str, Reservation] = field(default_factory=dict)
    by_idempotency_key: dict[str, str] = field(default_factory=dict)
    max_seen: datetime = field(
        default_factory=lambda: datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    clock_rollback_seen: bool = False

    def effective_now(self, now: datetime) -> datetime:
        now = _utc(now)
        return max(now, self.max_seen)

    def counts_toward_allowance(self, reservation: Reservation) -> bool:
        return reservation.rerun_of is None and reservation.status in {
            "open",
            "finalized",
        }

    def used(self, subject: str, period: str) -> int:
        return sum(
            1
            for r in self.reservations.values()
            if r.subject == subject and r.period == period and self.counts_toward_allowance(r)
        )

    def reruns_used(self, subject: str, original_workflow_id: str) -> int:
        return sum(
            1
            for r in self.reservations.values()
            if r.subject == subject
            and r.rerun_of == original_workflow_id
            and r.status in {"open", "finalized"}
        )

    def find_original(self, subject: str, workflow_id: str) -> Reservation | None:
        for r in self.reservations.values():
            if (
                r.subject == subject
                and r.workflow_id == workflow_id
                and r.rerun_of is None
                and r.status == "finalized"
            ):
                return r
        return None


class UsageLedger:
    """Append-only JSONL ledger with flock-serialized read-modify-write."""

    def __init__(self, home: str | Path | None = None, *, ttl_seconds: int = RESERVATION_TTL_SECONDS):
        self.home = Path(home) if home is not None else default_home()
        self.path = self.home / LEDGER_FILENAME
        self.lock_path = self.home / LOCK_FILENAME
        self.ttl_seconds = ttl_seconds

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.home.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+") as lock_file:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _append(self, event: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")

    def _load_unlocked(self, now: datetime) -> LedgerState:
        state = LedgerState()
        if not self.path.exists():
            return state
        expire_pending: list[tuple[str, str]] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise CommercialUsageError(
                        "E_LEDGER_CORRUPT", f"unparseable ledger line: {exc}"
                    ) from exc
                ts = _parse_ts(event.get("ts"))
                if ts > state.max_seen:
                    state.max_seen = ts
                kind = event.get("event")
                rid = event.get("reservation_id")
                if kind == RESERVE:
                    reservation = Reservation(
                        reservation_id=rid,
                        subject=event["subject"],
                        period=event["period"],
                        workflow_id=event["workflow_id"],
                        idempotency_key=event["idempotency_key"],
                        binding=event.get("binding") or {},
                        rerun_of=event.get("rerun_of"),
                        created_at=event["ts"],
                    )
                    state.reservations[rid] = reservation
                    state.by_idempotency_key[reservation.idempotency_key] = rid
                elif kind in {FINALIZE, RELEASE, EXPIRE}:
                    reservation = state.reservations.get(rid)
                    if reservation is None or reservation.status != "open":
                        continue
                    reservation.status = {
                        FINALIZE: "finalized",
                        RELEASE: "released",
                        EXPIRE: "expired",
                    }[kind]
                    reservation.outcome = event.get("outcome")
                    reservation.closed_at = event["ts"]
                else:
                    raise CommercialUsageError(
                        "E_LEDGER_CORRUPT", f"unknown event {kind!r}"
                    )
        effective = state.effective_now(now)
        if effective > _utc(now):
            state.clock_rollback_seen = True
        cutoff = effective - timedelta(seconds=self.ttl_seconds)
        for reservation in state.reservations.values():
            if reservation.status == "open" and _parse_ts(reservation.created_at) < cutoff:
                expire_pending.append((reservation.reservation_id, _iso(effective)))
        for rid, ts in expire_pending:
            self._append(
                {"event": EXPIRE, "reservation_id": rid, "ts": ts, "outcome": "ttl"}
            )
            reservation = state.reservations[rid]
            reservation.status = "expired"
            reservation.outcome = "ttl"
            reservation.closed_at = ts
        return state

    def load(self, now: datetime) -> LedgerState:
        with self._locked():
            return self._load_unlocked(now)

    def try_reserve(
        self,
        *,
        subject: str,
        period: str,
        workflow_id: str,
        idempotency_key: str,
        binding: dict[str, Any] | None = None,
        rerun_of: str | None = None,
        limit: int | None,
        now: datetime,
    ) -> Reservation | None:
        """Atomically reserve one slot, or return None when the limit is reached.

        A retry with a known idempotency key returns the original reservation
        with replayed=True and never consumes another slot.
        """
        if not subject or not workflow_id or not idempotency_key:
            raise CommercialUsageError(
                "E_RESERVATION_FIELDS", "subject, workflow_id and idempotency_key required"
            )
        with self._locked():
            state = self._load_unlocked(now)
            existing_id = state.by_idempotency_key.get(idempotency_key)
            if existing_id is not None:
                replay = state.reservations[existing_id]
                replay.replayed = True
                return replay
            effective = state.effective_now(now)
            if rerun_of is None and limit is not None and state.used(subject, period) >= limit:
                return None
            reservation_id = hashlib.sha256(
                f"{subject}|{period}|{workflow_id}|{idempotency_key}".encode("utf-8")
            ).hexdigest()[:32]
            event = {
                "event": RESERVE,
                "reservation_id": reservation_id,
                "subject": subject,
                "period": period,
                "workflow_id": workflow_id,
                "idempotency_key": idempotency_key,
                "binding": binding or {},
                "rerun_of": rerun_of,
                "ts": _iso(effective),
                "clock_rollback": state.clock_rollback_seen,
            }
            self._append(event)
            reservation = Reservation(
                reservation_id=reservation_id,
                subject=subject,
                period=period,
                workflow_id=workflow_id,
                idempotency_key=idempotency_key,
                binding=binding or {},
                rerun_of=rerun_of,
                created_at=event["ts"],
            )
            return reservation

    def settle(
        self,
        reservation_id: str,
        *,
        outcome: str,
        now: datetime,
    ) -> Reservation:
        """Finalize (completed) or release (tool_error/rejected) one reservation."""
        if outcome not in SETTLE_OUTCOMES:
            raise CommercialUsageError(
                "E_SETTLE_OUTCOME", f"outcome must be one of {sorted(SETTLE_OUTCOMES)}"
            )
        with self._locked():
            state = self._load_unlocked(now)
            reservation = state.reservations.get(reservation_id)
            if reservation is None:
                raise CommercialUsageError(
                    "E_RESERVATION_UNKNOWN", f"no reservation {reservation_id}"
                )
            if reservation.status != "open":
                return reservation
            effective = state.effective_now(now)
            kind = FINALIZE if outcome == COMPLETED else RELEASE
            self._append(
                {
                    "event": kind,
                    "reservation_id": reservation_id,
                    "ts": _iso(effective),
                    "outcome": outcome,
                }
            )
            reservation.status = "finalized" if outcome == COMPLETED else "released"
            reservation.outcome = outcome
            reservation.closed_at = _iso(effective)
            return reservation

    def export(self, now: datetime) -> dict[str, Any]:
        """Read-only dump. Reading and exporting usage never consumes allowance."""
        state = self.load(now)
        return {
            "ledger": str(self.path),
            "clock_rollback_seen": state.clock_rollback_seen,
            "reservations": [
                r.as_dict()
                for r in sorted(state.reservations.values(), key=lambda r: r.created_at)
            ],
        }

    def reset(self) -> int:
        """Explicitly delete the local ledger; returns the event count removed.

        This is intentionally visible: resetting the soft local counter is the
        documented bypass boundary of offline enforcement, not a hidden path.
        """
        with self._locked():
            if not self.path.exists():
                return 0
            with self.path.open("r", encoding="utf-8") as f:
                count = sum(1 for line in f if line.strip())
            self.path.unlink()
            return count

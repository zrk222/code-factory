"""Local proof-carrying engineering-memory continuity ledger.

Factory Continuity is deliberately *not* a vector store, an embedding service,
or an alternate agent authority.  It records bounded metadata about a memory
reference, its purpose and scope, and the evidence required before the memory
can influence a future delivery decision.  The local SQLite implementation is
a reference boundary for one workspace; it is not a hosted identity, key
management, retention, or compliance service.

Consequential operations (recording and promotion) commit their audit event in
the same SQLite transaction.  Recall is read-only and returns only independently
promoted, purpose-authorized, scope-matching, non-expired records.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Iterator
import uuid


CONTINUITY_SCHEMA = "factory.continuity.v1"
CONTINUITY_RECORD_SCHEMA = "factory.continuity.record.v1"
CONTINUITY_AUDIT_SCHEMA = "factory.continuity.audit.v1"
CONTINUITY_PROOF_SCHEMA = "factory.continuity.proof.v1"
CONTINUITY_DB_RELATIVE_PATH = Path(".factory") / "continuity.sqlite3"
_ALLOWED_TYPES = frozenset({"decision", "constraint", "outcome", "lesson", "exception"})
_FORBIDDEN_PAYLOAD_KEYS = frozenset({"content", "payload", "embedding", "text", "messages", "vector"})
_ROLE_ACTIONS: dict[str, frozenset[str]] = {
    "reader": frozenset({"continuity.read", "continuity.prove"}),
    "writer": frozenset({"continuity.write", "continuity.read", "continuity.prove"}),
    "promoter": frozenset({"continuity.promote", "continuity.read", "continuity.prove"}),
    "admin": frozenset({"continuity.write", "continuity.read", "continuity.promote", "continuity.prove"}),
}


class ContinuityError(RuntimeError):
    """Structured, fail-closed continuity error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ContinuityPrincipal:
    """Trusted adapter identity for the local reference implementation.

    CLI values are not identity verification.  A hosted adapter must validate
    identity before it constructs this value.
    """

    subject: str
    tenant_id: str
    roles: tuple[str, ...] = ()
    purposes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise ContinuityError("E_IDENTITY_REQUIRED", "principal subject is required")
        if not self.tenant_id.strip():
            raise ContinuityError("E_TENANT_REQUIRED", "principal tenant_id is required")
        if not self.purposes:
            raise ContinuityError("E_PURPOSE_REQUIRED", "principal must declare at least one purpose reference")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContinuityError("E_NON_CANONICAL_DATA", f"value is not canonical JSON: {exc}") from exc


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_future_utc(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContinuityError("E_EXPIRY_REQUIRED", "expires_at is required as an RFC3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContinuityError("E_EXPIRY_INVALID", "expires_at must be RFC3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContinuityError("E_EXPIRY_INVALID", "expires_at must include a UTC offset")
    if parsed.astimezone(timezone.utc) <= datetime.now(timezone.utc):
        raise ContinuityError("E_EXPIRY_INVALID", "expires_at must be in the future")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_expired(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return True
    return parsed.astimezone(timezone.utc) <= datetime.now(timezone.utc)


def _required_string(payload: dict[str, Any], key: str, *, maximum: int = 240) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ContinuityError("E_RECORD_INVALID", f"{key} is required")
    result = value.strip()
    if len(result) > maximum:
        raise ContinuityError("E_RECORD_INVALID", f"{key} exceeds {maximum} characters")
    return result


def _purpose_ref(payload: dict[str, Any]) -> str:
    purpose = payload.get("purpose")
    if not isinstance(purpose, dict):
        raise ContinuityError("E_PURPOSE_REQUIRED", "purpose must be an object with id and version")
    purpose_id = _required_string(purpose, "id", maximum=120)
    version = _required_string(purpose, "version", maximum=80)
    return f"{purpose_id}@{version}"


def _scope_ref(payload: dict[str, Any]) -> str:
    scope = payload.get("scope")
    if not isinstance(scope, dict):
        raise ContinuityError("E_SCOPE_REQUIRED", "scope must be an object")
    return _required_string(scope, "repository_ref", maximum=240)


def _evidence_refs(payload: dict[str, Any]) -> list[str]:
    value = payload.get("evidence_refs")
    if not isinstance(value, list) or not value or len(value) > 24:
        raise ContinuityError("E_EVIDENCE_REQUIRED", "evidence_refs must contain 1 through 24 opaque references")
    refs: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item.strip()) > 320:
            raise ContinuityError("E_EVIDENCE_REQUIRED", "every evidence reference must be a bounded non-empty string")
        refs.append(item.strip())
    return sorted(set(refs))


def _ensure_metadata_only(payload: dict[str, Any]) -> None:
    forbidden = sorted(_FORBIDDEN_PAYLOAD_KEYS.intersection(payload))
    if forbidden:
        raise ContinuityError(
            "E_CONTENT_STORE_FORBIDDEN",
            "Factory Continuity records memory references and evidence metadata, not memory content: " + ", ".join(forbidden),
        )


def _validate_record(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ContinuityError("E_RECORD_INVALID", "record must be a JSON object")
    _ensure_metadata_only(payload)
    if payload.get("schema") != CONTINUITY_RECORD_SCHEMA:
        raise ContinuityError("E_SCHEMA_INVALID", f"record schema must be {CONTINUITY_RECORD_SCHEMA}")
    record_type = _required_string(payload, "record_type", maximum=40).lower()
    if record_type not in _ALLOWED_TYPES:
        raise ContinuityError("E_RECORD_INVALID", f"record_type must be one of {', '.join(sorted(_ALLOWED_TYPES))}")
    tenant_id = _required_string(payload, "tenant_id", maximum=160)
    memory_ref = _required_string(payload, "memory_ref", maximum=320)
    purpose_ref = _purpose_ref(payload)
    scope_ref = _scope_ref(payload)
    expires_at = _parse_future_utc(payload.get("expires_at"))
    refs = _evidence_refs(payload)
    summary = payload.get("summary")
    if summary is not None and (not isinstance(summary, str) or len(summary.strip()) > 280):
        raise ContinuityError("E_RECORD_INVALID", "summary must be a string of at most 280 characters")
    return {
        "schema": CONTINUITY_RECORD_SCHEMA,
        "tenant_id": tenant_id,
        "record_type": record_type,
        "memory_ref": memory_ref,
        "memory_ref_sha256": _sha({"memory_ref": memory_ref}),
        "purpose_ref": purpose_ref,
        "scope_ref": scope_ref,
        "scope_ref_sha256": _sha({"scope_ref": scope_ref}),
        "evidence_refs": refs,
        "evidence_sha256": _sha(refs),
        "summary": summary.strip() if isinstance(summary, str) and summary.strip() else None,
        "expires_at": expires_at,
    }


def _authorize(principal: ContinuityPrincipal, action: str, tenant_id: str, purpose_ref: str) -> None:
    allowed = frozenset().union(*(_ROLE_ACTIONS.get(role, frozenset()) for role in principal.roles))
    if action not in allowed:
        raise ContinuityError("E_ACTION_DENIED", f"action {action!r} is not granted to {principal.subject!r}")
    if principal.tenant_id != tenant_id:
        raise ContinuityError("E_TENANT_BOUNDARY", "principal cannot access another tenant")
    if "*" not in principal.purposes and purpose_ref not in principal.purposes:
        raise ContinuityError("E_PURPOSE_DENIED", f"purpose {purpose_ref!r} is not granted to {principal.subject!r}")


class ContinuityStore:
    """Bounded local ledger for governed, reusable engineering-memory metadata."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        """Commit or roll back one operation and always close its SQLite handle."""
        db = self._connect()
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._session() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS continuity_records (
                    record_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    memory_ref TEXT NOT NULL,
                    memory_ref_sha256 TEXT NOT NULL,
                    purpose_ref TEXT NOT NULL,
                    scope_ref TEXT NOT NULL,
                    scope_ref_sha256 TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    summary TEXT,
                    status TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    promoted_at TEXT,
                    promoted_by TEXT,
                    promotion_reason TEXT,
                    idempotency_key TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    UNIQUE(tenant_id, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS continuity_tenant_scope
                    ON continuity_records(tenant_id, purpose_ref, scope_ref, status, expires_at, record_id);
                CREATE TABLE IF NOT EXISTS continuity_audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS continuity_audit_tenant_sequence
                    ON continuity_audit_events(tenant_id, sequence);
                """
            )

    @staticmethod
    def _row(row: sqlite3.Row, *, redact_memory_ref: bool = False) -> dict[str, Any]:
        record = {
            "schema": CONTINUITY_RECORD_SCHEMA,
            "record_id": row["record_id"],
            "tenant_id": row["tenant_id"],
            "record_type": row["record_type"],
            "memory_ref_sha256": row["memory_ref_sha256"],
            "purpose_ref": row["purpose_ref"],
            "scope_ref": row["scope_ref"],
            "scope_ref_sha256": row["scope_ref_sha256"],
            "evidence_refs": json.loads(row["evidence_json"]),
            "evidence_sha256": row["evidence_sha256"],
            "summary": row["summary"],
            "status": row["status"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "created_by": row["created_by"],
            "promoted_at": row["promoted_at"],
            "promoted_by": row["promoted_by"],
            "promotion_reason": row["promotion_reason"],
            "idempotency_key": row["idempotency_key"],
            "record_sha256": row["record_sha256"],
        }
        if not redact_memory_ref:
            record["memory_ref"] = row["memory_ref"]
        return record

    def _audit(self, db: sqlite3.Connection, *, tenant_id: str, action: str, actor: str, record_id: str, payload: dict[str, Any]) -> None:
        previous = db.execute(
            "SELECT event_hash FROM continuity_audit_events WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1", (tenant_id,)
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else ""
        created_at = _now()
        db.execute(
            """INSERT INTO continuity_audit_events
               (tenant_id, action, actor, record_id, payload_json, previous_hash, event_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, action, actor, record_id, _canonical(payload).decode("utf-8"), previous_hash, "pending", created_at),
        )
        sequence = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
        event = {
            "schema": CONTINUITY_AUDIT_SCHEMA, "sequence": sequence, "tenant_id": tenant_id, "action": action,
            "actor": actor, "record_id": record_id, "payload": payload, "previous_hash": previous_hash, "created_at": created_at,
        }
        db.execute("UPDATE continuity_audit_events SET event_hash = ? WHERE sequence = ?", (_sha(event), sequence))

    def record(self, principal: ContinuityPrincipal, payload: dict[str, Any], *, idempotency_key: str, record_id: str | None = None) -> dict[str, Any]:
        """Atomically write a draft record and its audit event, or neither."""
        normalized = _validate_record(payload)
        _authorize(principal, "continuity.write", normalized["tenant_id"], normalized["purpose_ref"])
        if not isinstance(idempotency_key, str) or not idempotency_key.strip() or len(idempotency_key.strip()) > 160:
            raise ContinuityError("E_IDEMPOTENCY_REQUIRED", "idempotency_key is required and must be at most 160 characters")
        record_id = record_id or uuid.uuid4().hex
        created_at = _now()
        # The idempotency digest deliberately excludes server-assigned record
        # ID and creation time, so an exact retry returns the first immutable
        # record instead of looking like a conflicting second request.
        record_sha256 = _sha({**normalized, "idempotency_key": idempotency_key.strip()})
        with self._session() as db:
            existing = db.execute("SELECT * FROM continuity_records WHERE tenant_id = ? AND idempotency_key = ?", (normalized["tenant_id"], idempotency_key.strip())).fetchone()
            if existing:
                if existing["record_sha256"] != record_sha256:
                    raise ContinuityError("E_IDEMPOTENCY_CONFLICT", "idempotency key is already bound to different content")
                return self._row(existing)
            try:
                db.execute(
                    """INSERT INTO continuity_records
                    (record_id, tenant_id, record_type, memory_ref, memory_ref_sha256, purpose_ref, scope_ref, scope_ref_sha256,
                     evidence_json, evidence_sha256, summary, status, expires_at, created_at, created_by, idempotency_key, record_sha256)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?)""",
                    (record_id, normalized["tenant_id"], normalized["record_type"], normalized["memory_ref"], normalized["memory_ref_sha256"],
                     normalized["purpose_ref"], normalized["scope_ref"], normalized["scope_ref_sha256"], _canonical(normalized["evidence_refs"]).decode("utf-8"),
                     normalized["evidence_sha256"], normalized["summary"], normalized["expires_at"], created_at, principal.subject,
                     idempotency_key.strip(), record_sha256),
                )
            except sqlite3.IntegrityError as exc:
                raise ContinuityError("E_RECORD_IMMUTABLE", "record id is already bound to immutable content") from exc
            self._audit(db, tenant_id=normalized["tenant_id"], action="continuity.record", actor=principal.subject, record_id=record_id,
                        payload={"record_sha256": record_sha256, "purpose_ref": normalized["purpose_ref"], "evidence_sha256": normalized["evidence_sha256"]})
            row = db.execute("SELECT * FROM continuity_records WHERE record_id = ?", (record_id,)).fetchone()
            return self._row(row)

    def promote(self, principal: ContinuityPrincipal, tenant_id: str, record_id: str, *, reason: str) -> dict[str, Any]:
        """Independently promote one evidenced draft; agents cannot self-promote."""
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 280:
            raise ContinuityError("E_PROMOTION_REASON_REQUIRED", "promotion reason is required and must be at most 280 characters")
        with self._session() as db:
            row = db.execute("SELECT * FROM continuity_records WHERE record_id = ? AND tenant_id = ?", (record_id, tenant_id)).fetchone()
            if not row:
                raise ContinuityError("E_NOT_FOUND", "continuity record not found")
            _authorize(principal, "continuity.promote", tenant_id, row["purpose_ref"])
            if row["created_by"] == principal.subject:
                raise ContinuityError("E_SELF_PROMOTION", "record author cannot promote their own continuity record")
            if row["status"] != "draft":
                raise ContinuityError("E_ALREADY_PROMOTED", "only a draft continuity record can be promoted")
            if _is_expired(row["expires_at"]):
                raise ContinuityError("E_RECORD_EXPIRED", "an expired record cannot be promoted")
            if not json.loads(row["evidence_json"]):
                raise ContinuityError("E_EVIDENCE_REQUIRED", "a promoted record requires evidence references")
            promoted_at = _now()
            db.execute(
                """UPDATE continuity_records SET status = 'verified', promoted_at = ?, promoted_by = ?, promotion_reason = ?
                   WHERE record_id = ? AND tenant_id = ? AND status = 'draft'""",
                (promoted_at, principal.subject, reason.strip(), record_id, tenant_id),
            )
            self._audit(db, tenant_id=tenant_id, action="continuity.promote", actor=principal.subject, record_id=record_id,
                        payload={"record_sha256": row["record_sha256"], "reason": reason.strip()})
            return self._row(db.execute("SELECT * FROM continuity_records WHERE record_id = ?", (record_id,)).fetchone())

    def recall(self, principal: ContinuityPrincipal, tenant_id: str, *, purpose_ref: str, scope_ref: str) -> dict[str, Any]:
        """Return only current, independently-promoted, exact scope/purpose records."""
        _authorize(principal, "continuity.read", tenant_id, purpose_ref)
        with self._session() as db:
            rows = db.execute(
                """SELECT * FROM continuity_records WHERE tenant_id = ? AND purpose_ref = ? AND scope_ref = ?
                   AND status = 'verified' ORDER BY promoted_at DESC, record_id ASC""",
                (tenant_id, purpose_ref, scope_ref),
            ).fetchall()
        current = [self._row(row) for row in rows if not _is_expired(row["expires_at"])]
        withheld = [row["record_id"] for row in rows if _is_expired(row["expires_at"])]
        return {
            "schema": CONTINUITY_SCHEMA,
            "marker": "CONTINUITY_RECALL_SCOPE_AND_PURPOSE_EXACT",
            "authority": {"write": False, "promotion": False, "external_effects": False},
            "tenant_id": tenant_id, "purpose_ref": purpose_ref, "scope_ref": scope_ref,
            "records": current, "withheld_expired_record_ids": withheld,
        }

    def prove(self, principal: ContinuityPrincipal, tenant_id: str, record_id: str) -> dict[str, Any]:
        """Provide local lineage metadata and audit validity without granting mutation authority."""
        with self._session() as db:
            row = db.execute("SELECT * FROM continuity_records WHERE record_id = ? AND tenant_id = ?", (record_id, tenant_id)).fetchone()
            if not row:
                raise ContinuityError("E_NOT_FOUND", "continuity record not found")
            _authorize(principal, "continuity.prove", tenant_id, row["purpose_ref"])
            events = db.execute("SELECT * FROM continuity_audit_events WHERE tenant_id = ? AND record_id = ? ORDER BY sequence", (tenant_id, record_id)).fetchall()
        audit = self.verify_audit(principal, tenant_id, purpose_ref=row["purpose_ref"])
        return {
            "schema": CONTINUITY_PROOF_SCHEMA,
            "marker": "CONTINUITY_LOCAL_UNSIGNED_PROOF",
            "authority": {"signing": False, "publication": False, "external_effects": False},
            "record": self._row(row),
            "audit": audit,
            "lineage": [{"sequence": event["sequence"], "action": event["action"], "event_hash": event["event_hash"], "created_at": event["created_at"]} for event in events],
            "limitations": ["Local hash chain is unsigned.", "CLI principal arguments are not authenticated identity.", "This reference store does not hold memory contents or provide erasure, KMS, or external anchoring."],
        }

    def verify_audit(self, principal: ContinuityPrincipal, tenant_id: str, *, purpose_ref: str) -> dict[str, Any]:
        """Verify one tenant's local audit chain after purpose-bound read authorization."""
        _authorize(principal, "continuity.prove", tenant_id, purpose_ref)
        with self._session() as db:
            rows = db.execute("SELECT * FROM continuity_audit_events WHERE tenant_id = ? ORDER BY sequence", (tenant_id,)).fetchall()
        previous_hash = ""
        errors: list[str] = []
        for row in rows:
            if row["previous_hash"] != previous_hash:
                errors.append(f"sequence {row['sequence']}: previous hash mismatch")
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                errors.append(f"sequence {row['sequence']}: invalid payload JSON")
                previous_hash = row["event_hash"]
                continue
            event = {"schema": CONTINUITY_AUDIT_SCHEMA, "sequence": row["sequence"], "tenant_id": row["tenant_id"], "action": row["action"], "actor": row["actor"], "record_id": row["record_id"], "payload": payload, "previous_hash": row["previous_hash"], "created_at": row["created_at"]}
            if _sha(event) != row["event_hash"]:
                errors.append(f"sequence {row['sequence']}: event hash mismatch")
            previous_hash = row["event_hash"]
        return {"schema": CONTINUITY_SCHEMA, "tenant_id": tenant_id, "events": len(rows), "valid": not errors, "errors": errors}

    def status(self) -> dict[str, Any]:
        """Return aggregate local-ledger counts without exposing any continuity reference values."""
        with self._session() as db:
            rows = db.execute("SELECT tenant_id, status, expires_at FROM continuity_records ORDER BY tenant_id, record_id").fetchall()
        facts = {"record_count": len(rows), "draft_count": 0, "verified_current_count": 0, "expired_count": 0}
        for row in rows:
            if _is_expired(row["expires_at"]):
                facts["expired_count"] += 1
            elif row["status"] == "verified":
                facts["verified_current_count"] += 1
            else:
                facts["draft_count"] += 1
        return {"schema": CONTINUITY_SCHEMA, "marker": "CONTINUITY_LOCAL_REFERENCE_ONLY", "authority": {"external_effects": False, "signing": False, "erasure": False}, "facts": facts}


def continuity_projection(root: Path, *, limit: int = 100) -> dict[str, Any]:
    """Read a bounded redacted projection for Graph Ops; never writes or recalls content."""
    path = Path(root).resolve() / CONTINUITY_DB_RELATIVE_PATH
    empty = {"available": False, "records": [], "facts": {"record_count": 0, "draft_count": 0, "verified_current_count": 0, "expired_count": 0}, "error": None}
    if not path.is_file():
        return empty
    try:
        # Graph Ops is a projection surface, never a continuity-store writer.
        # SQLite URI read-only mode prevents accidental journal/schema writes
        # even if this helper changes in the future.
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT * FROM continuity_records ORDER BY created_at DESC, record_id ASC LIMIT ?", (limit + 1,)).fetchall()
            all_rows = connection.execute("SELECT status, expires_at FROM continuity_records").fetchall()
        finally:
            connection.close()
        if len(rows) > limit:
            rows = rows[:limit]
            truncated = True
        else:
            truncated = False
        facts = {"record_count": len(all_rows), "draft_count": 0, "verified_current_count": 0, "expired_count": 0}
        for row in all_rows:
            if _is_expired(row["expires_at"]):
                facts["expired_count"] += 1
            elif row["status"] == "verified":
                facts["verified_current_count"] += 1
            else:
                facts["draft_count"] += 1
        records = []
        for row in rows:
            record = ContinuityStore._row(row, redact_memory_ref=True)
            # A decision summary can itself be sensitive context. Graph Ops
            # works from redacted provenance facts, not the memory content.
            record.pop("summary", None)
            record["effective_status"] = "expired" if _is_expired(record["expires_at"]) else record["status"]
            records.append(record)
        return {"available": True, "records": records, "facts": facts, "truncated": truncated, "error": None}
    except (sqlite3.Error, OSError, json.JSONDecodeError) as exc:
        return {**empty, "error": "CONTINUITY_STORE_UNREADABLE"}


def principal_from_args(subject: str, tenant_id: str, roles: Iterable[str], purposes: Iterable[str]) -> ContinuityPrincipal:
    """Normalize explicit local CLI inputs; callers must not treat them as authenticated identity."""
    return ContinuityPrincipal(
        subject=subject,
        tenant_id=tenant_id,
        roles=tuple(sorted({item.strip() for item in roles if item.strip()})),
        purposes=tuple(sorted({item.strip() for item in purposes if item.strip()})),
    )


# Small top-level adapters keep the public architecture contract inspectable by
# static SSAT tooling while retaining the store as the sole mutation boundary.
def record_continuity(store: ContinuityStore, principal: ContinuityPrincipal, payload: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
    """Record one metadata-only draft through the governed continuity store."""
    return store.record(principal, payload, idempotency_key=idempotency_key)


def recall_continuity(store: ContinuityStore, principal: ContinuityPrincipal, tenant_id: str, purpose_ref: str, scope_ref: str) -> dict[str, Any]:
    """Recall only exact-scope, purpose-authorized, verified current records."""
    return store.recall(principal, tenant_id, purpose_ref=purpose_ref, scope_ref=scope_ref)


def promote_continuity(store: ContinuityStore, principal: ContinuityPrincipal, tenant_id: str, record_id: str, reason: str) -> dict[str, Any]:
    """Promote a record only through independent local reviewer authority."""
    return store.promote(principal, tenant_id, record_id, reason=reason)

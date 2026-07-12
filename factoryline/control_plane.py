"""Local-first control-plane primitives for tenant-scoped factory evidence.

This module is intentionally dependency-free.  It is the policy boundary that
hosted API and SCM adapters must call; it is not itself an identity provider or
multi-tenant network service.  SQLite gives the local verifier a durable,
inspectable store while the audit table provides a tamper-evident event chain.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
from typing import Any, Iterable


CONTROL_PLANE_SCHEMA = "factory.control-plane.v1"
EVIDENCE_SCHEMA = "factory.evidence.record.v1"
AUDIT_SCHEMA = "factory.audit.event.v1"
APPROVAL_SCHEMA = "factory.approval.request.v1"


class ControlPlaneError(RuntimeError):
    """Structured, fail-closed control-plane error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise ControlPlaneError("E_IDENTITY_REQUIRED", "principal subject is required")
        if not self.tenant_id.strip():
            raise ControlPlaneError("E_TENANT_REQUIRED", "principal tenant_id is required")


ROLE_ACTIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"evidence.read", "evidence.list", "audit.verify"}),
    "operator": frozenset({"evidence.read", "evidence.list", "evidence.write", "approval.request", "audit.verify"}),
    "approver": frozenset({"evidence.read", "evidence.list", "approval.decide", "audit.verify"}),
    "admin": frozenset({
        "evidence.read", "evidence.list", "evidence.write", "approval.request",
        "approval.decide", "audit.verify",
    }),
    "platform_admin": frozenset({
        "evidence.read", "evidence.list", "evidence.write", "approval.request",
        "approval.decide", "audit.verify",
    }),
}


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ControlPlaneError("E_NON_CANONICAL_DATA", f"value is not canonical JSON: {exc}") from exc


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def authorize(principal: Principal, action: str, tenant_id: str) -> None:
    """Authorize an action before any tenant-scoped store access occurs."""
    if not tenant_id.strip():
        raise ControlPlaneError("E_TENANT_REQUIRED", "resource tenant_id is required")
    allowed = frozenset().union(*(ROLE_ACTIONS.get(role, frozenset()) for role in principal.roles))
    if action not in allowed:
        raise ControlPlaneError("E_ACTION_DENIED", f"action {action!r} is not granted to {principal.subject!r}")
    is_platform = "platform_admin" in principal.roles and principal.tenant_id == "*"
    if principal.tenant_id != tenant_id and not is_platform:
        raise ControlPlaneError("E_TENANT_BOUNDARY", "principal cannot access another tenant")


class EvidenceStore:
    """Durable evidence and approval store with a hash-linked audit trail."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    schema TEXT NOT NULL,
                    subject_digest TEXT,
                    policy_digest TEXT,
                    verdict TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    inserted_by TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS evidence_tenant_created
                    ON evidence(tenant_id, created_at, evidence_id);
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
                    requester TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    decided_at TEXT,
                    approver TEXT,
                    decision_reason TEXT
                );
                CREATE INDEX IF NOT EXISTS approvals_tenant_status
                    ON approvals(tenant_id, status, requested_at, approval_id);
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS audit_tenant_sequence
                    ON audit_events(tenant_id, sequence);
                """
            )

    @staticmethod
    def _row_payload(row: sqlite3.Row) -> dict[str, Any]:
        payload = json.loads(row["payload_json"])
        return {
            "schema": EVIDENCE_SCHEMA,
            "evidence_id": row["evidence_id"],
            "tenant_id": row["tenant_id"],
            "payload": payload,
            "payload_sha256": row["payload_sha256"],
            "subject_digest": row["subject_digest"],
            "policy_digest": row["policy_digest"],
            "verdict": row["verdict"],
            "created_at": row["created_at"],
            "inserted_by": row["inserted_by"],
        }

    def _audit(
        self,
        db: sqlite3.Connection,
        *,
        tenant_id: str,
        action: str,
        actor: str,
        resource_id: str,
        payload: dict[str, Any],
    ) -> None:
        created_at = _now()
        payload_json = canonical_json(payload).decode("utf-8")
        previous = db.execute(
            "SELECT event_hash FROM audit_events WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else ""
        db.execute(
            """INSERT INTO audit_events
               (tenant_id, action, actor, resource_id, payload_json, previous_hash, event_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (tenant_id, action, actor, resource_id, payload_json, previous_hash, "pending", created_at),
        )
        sequence = int(db.execute("SELECT last_insert_rowid()").fetchone()[0])
        event = {
            "schema": AUDIT_SCHEMA,
            "sequence": sequence,
            "tenant_id": tenant_id,
            "action": action,
            "actor": actor,
            "resource_id": resource_id,
            "payload": payload,
            "previous_hash": previous_hash,
            "created_at": created_at,
        }
        event_hash = sha256(canonical_json(event))
        db.execute("UPDATE audit_events SET event_hash = ? WHERE sequence = ?", (event_hash, sequence))

    def put(self, principal: Principal, payload: dict[str, Any], *, evidence_id: str | None = None) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise ControlPlaneError("E_INVALID_EVIDENCE", "evidence payload must be a JSON object")
        tenant_id = str(payload.get("tenant_id", ""))
        authorize(principal, "evidence.write", tenant_id)
        schema = str(payload.get("schema", ""))
        if not schema.startswith("factory."):
            raise ControlPlaneError("E_INVALID_EVIDENCE", "evidence schema must start with factory.")
        verdict = str(payload.get("verdict", payload.get("ok", "UNKNOWN")))
        evidence_id = evidence_id or uuid.uuid4().hex
        payload_bytes = canonical_json(payload)
        digest = sha256(payload_bytes)
        created_at = _now()
        with self._connect() as db:
            existing = db.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
            if existing:
                if existing["tenant_id"] != tenant_id or existing["payload_sha256"] != digest:
                    raise ControlPlaneError("E_EVIDENCE_IMMUTABLE", "evidence id is already bound to different content")
                return self._row_payload(existing)
            db.execute(
                """INSERT INTO evidence
                   (evidence_id, tenant_id, payload_json, payload_sha256, schema, subject_digest,
                    policy_digest, verdict, created_at, inserted_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence_id, tenant_id, payload_bytes.decode("utf-8"), digest, schema,
                    payload.get("subject_digest"), payload.get("policy_sha256", payload.get("policy_digest")),
                    verdict, created_at, principal.subject,
                ),
            )
            self._audit(db, tenant_id=tenant_id, action="evidence.write", actor=principal.subject,
                        resource_id=evidence_id, payload={"payload_sha256": digest, "verdict": verdict})
            row = db.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
            return self._row_payload(row)

    def get(self, principal: Principal, tenant_id: str, evidence_id: str) -> dict[str, Any]:
        authorize(principal, "evidence.read", tenant_id)
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM evidence WHERE evidence_id = ? AND tenant_id = ?",
                (evidence_id, tenant_id),
            ).fetchone()
            if not row:
                raise ControlPlaneError("E_NOT_FOUND", "evidence not found")
            return self._row_payload(row)

    def list(self, principal: Principal, tenant_id: str) -> list[dict[str, Any]]:
        authorize(principal, "evidence.list", tenant_id)
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM evidence WHERE tenant_id = ? ORDER BY created_at, evidence_id",
                (tenant_id,),
            ).fetchall()
            return [self._row_payload(row) for row in rows]

    def request_approval(self, principal: Principal, tenant_id: str, evidence_id: str, reason: str) -> dict[str, Any]:
        authorize(principal, "approval.request", tenant_id)
        if not reason.strip():
            raise ControlPlaneError("E_REASON_REQUIRED", "approval reason is required")
        with self._connect() as db:
            evidence = db.execute(
                "SELECT evidence_id FROM evidence WHERE evidence_id = ? AND tenant_id = ?",
                (evidence_id, tenant_id),
            ).fetchone()
            if not evidence:
                raise ControlPlaneError("E_NOT_FOUND", "evidence not found")
            approval_id = uuid.uuid4().hex
            requested_at = _now()
            db.execute(
                """INSERT INTO approvals
                   (approval_id, tenant_id, evidence_id, requester, reason, status, requested_at)
                   VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
                (approval_id, tenant_id, evidence_id, principal.subject, reason.strip(), requested_at),
            )
            self._audit(db, tenant_id=tenant_id, action="approval.request", actor=principal.subject,
                        resource_id=approval_id, payload={"evidence_id": evidence_id, "reason": reason.strip()})
            # Read inside the same transaction; a second connection cannot see
            # the request until this context commits.
            return dict(db.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())

    def get_approval(self, principal: Principal, tenant_id: str, approval_id: str, *, allow_requester: bool = False) -> dict[str, Any]:
        authorize(principal, "evidence.read", tenant_id)
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM approvals WHERE approval_id = ? AND tenant_id = ?",
                (approval_id, tenant_id),
            ).fetchone()
            if not row:
                raise ControlPlaneError("E_NOT_FOUND", "approval request not found")
            return dict(row)

    def decide_approval(
        self,
        principal: Principal,
        tenant_id: str,
        approval_id: str,
        decision: str,
        reason: str,
    ) -> dict[str, Any]:
        authorize(principal, "approval.decide", tenant_id)
        decision = decision.strip().lower()
        if decision not in {"approved", "rejected"}:
            raise ControlPlaneError("E_INVALID_DECISION", "decision must be approved or rejected")
        if not reason.strip():
            raise ControlPlaneError("E_REASON_REQUIRED", "decision reason is required")
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM approvals WHERE approval_id = ? AND tenant_id = ?",
                (approval_id, tenant_id),
            ).fetchone()
            if not row:
                raise ControlPlaneError("E_NOT_FOUND", "approval request not found")
            if row["status"] != "pending":
                raise ControlPlaneError("E_ALREADY_DECIDED", "approval request has already been decided")
            if row["requester"] == principal.subject:
                raise ControlPlaneError("E_SELF_APPROVAL", "requester cannot approve its own request")
            decided_at = _now()
            db.execute(
                """UPDATE approvals SET status = ?, decided_at = ?, approver = ?, decision_reason = ?
                   WHERE approval_id = ? AND tenant_id = ? AND status = 'pending'""",
                (decision, decided_at, principal.subject, reason.strip(), approval_id, tenant_id),
            )
            self._audit(db, tenant_id=tenant_id, action="approval.decide", actor=principal.subject,
                        resource_id=approval_id, payload={"decision": decision, "reason": reason.strip()})
            return dict(db.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone())

    def verify_audit(self, principal: Principal, tenant_id: str) -> dict[str, Any]:
        authorize(principal, "audit.verify", tenant_id)
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_events WHERE tenant_id = ? ORDER BY sequence",
                (tenant_id,),
            ).fetchall()
        previous = ""
        errors: list[str] = []
        for row in rows:
            if row["previous_hash"] != previous:
                errors.append(f"sequence {row['sequence']}: previous hash mismatch")
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                errors.append(f"sequence {row['sequence']}: invalid payload JSON")
                previous = row["event_hash"]
                continue
            event = {
                "schema": AUDIT_SCHEMA,
                "sequence": row["sequence"],
                "tenant_id": row["tenant_id"],
                "action": row["action"],
                "actor": row["actor"],
                "resource_id": row["resource_id"],
                "payload": payload,
                "previous_hash": row["previous_hash"],
                "created_at": row["created_at"],
            }
            if sha256(canonical_json(event)) != row["event_hash"]:
                errors.append(f"sequence {row['sequence']}: event hash mismatch")
            previous = row["event_hash"]
        return {
            "schema": CONTROL_PLANE_SCHEMA,
            "tenant_id": tenant_id,
            "audit_schema": AUDIT_SCHEMA,
            "events": len(rows),
            "valid": not errors,
            "errors": errors,
        }


def principal_from_args(subject: str, tenant_id: str, roles: Iterable[str]) -> Principal:
    return Principal(subject=subject, tenant_id=tenant_id, roles=tuple(sorted({role.strip() for role in roles if role.strip()})))

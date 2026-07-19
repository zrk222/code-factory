"""PostgreSQL persistence for hosted PR assurance and its transactional outbox."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import uuid
from typing import Any, Callable, Iterator

from .control_plane import Principal, canonical_json, sha256
from .pr_assurance import PRAssuranceError, PullRequestEvent, github_check_request


POSTGRES_SCHEMA = "factory.hosted-pr-assurance.postgres.v1"
MAX_OUTBOX_ATTEMPTS = 25


def _validate_decision(principal: Principal, decision: str, reason: str) -> None:
    if "approver" not in principal.roles and "admin" not in principal.roles:
        raise PRAssuranceError("E_ACTION_DENIED", "verified identity lacks approval authority")
    if decision not in {"approved", "rejected"} or not reason.strip():
        raise PRAssuranceError("E_INVALID_DECISION", "approved or rejected decision and reason are required")


def _require_pending(row: Any, principal: Principal) -> None:
    if not row:
        raise PRAssuranceError("E_NOT_FOUND", "approval was not found in this tenant")
    if row[9] != "pending":
        raise PRAssuranceError("E_ALREADY_DECIDED", "approval is already terminal")
    if row[8] == principal.subject:
        raise PRAssuranceError("E_SELF_APPROVAL", "requester cannot approve its own request")

SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS factory_installations (
    installation_id BIGINT PRIMARY KEY,
    tenant_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS factory_pr_deliveries (
    tenant_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    installation_id BIGINT NOT NULL REFERENCES factory_installations(installation_id),
    repository TEXT NOT NULL,
    pull_request BIGINT NOT NULL,
    head_sha TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    evidence_sha256 TEXT NOT NULL,
    approval_id UUID NOT NULL UNIQUE,
    requester TEXT NOT NULL,
    approval_status TEXT NOT NULL DEFAULT 'pending',
    approver TEXT,
    decision_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, delivery_id)
);
CREATE TABLE IF NOT EXISTS factory_oidc_uses (
    tenant_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    jti TEXT NOT NULL,
    subject TEXT NOT NULL,
    approval_id UUID NOT NULL,
    used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, jti)
);
CREATE TABLE IF NOT EXISTS factory_check_outbox (
    outbox_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    approval_id UUID NOT NULL UNIQUE,
    installation_id BIGINT NOT NULL,
    repository TEXT NOT NULL,
    request_json JSONB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 25),
    last_error TEXT,
    check_run_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);
ALTER TABLE factory_pr_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_pr_deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE factory_oidc_uses ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_oidc_uses FORCE ROW LEVEL SECURITY;
ALTER TABLE factory_check_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_check_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS factory_pr_tenant ON factory_pr_deliveries;
CREATE POLICY factory_pr_tenant ON factory_pr_deliveries
  USING (tenant_id = current_setting('factory.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('factory.tenant_id', true));
DROP POLICY IF EXISTS factory_oidc_tenant ON factory_oidc_uses;
CREATE POLICY factory_oidc_tenant ON factory_oidc_uses
  USING (tenant_id = current_setting('factory.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('factory.tenant_id', true));
DROP POLICY IF EXISTS factory_outbox_tenant ON factory_check_outbox;
CREATE POLICY factory_outbox_tenant ON factory_check_outbox
  USING (tenant_id = current_setting('factory.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('factory.tenant_id', true));
"""


@dataclass(frozen=True)
class OutboxRecord:
    """One tenant-bound GitHub Check publication awaiting or recording dispatch."""

    outbox_id: str
    tenant_id: str
    approval_id: str
    installation_id: int
    repository: str
    request: dict[str, Any]
    attempts: int


def _default_connect(dsn: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - depends on optional install
        raise PRAssuranceError("E_HOSTED_DEPENDENCY", "install factoryline-code-factory[hosted]") from exc
    return psycopg.connect(dsn)


def _database_error(exc: Exception, duplicate_code: str) -> PRAssuranceError:
    if getattr(exc, "sqlstate", None) == "23505":
        return PRAssuranceError(duplicate_code, "unique hosted assurance record already exists")
    return PRAssuranceError("E_DATABASE", "hosted assurance database operation failed")


class PostgresAssuranceStore:
    """Tenant-isolated PostgreSQL store with atomic approval and Check outbox writes."""

    def __init__(self, dsn: str, *, connect: Callable[[str], Any] | None = None):
        if not dsn.strip():
            raise PRAssuranceError("E_DATABASE_CONFIG", "PostgreSQL DSN is required")
        self.dsn = dsn
        self.connect = connect or _default_connect

    @contextmanager
    def _transaction(self, tenant_id: str | None = None) -> Iterator[tuple[Any, Any]]:
        with self.connect(self.dsn) as db:
            with db.cursor() as cursor:
                if tenant_id is not None:
                    cursor.execute("SELECT set_config('factory.tenant_id', %s, true)", (tenant_id,))
                yield db, cursor

    def initialize(self) -> None:
        """Apply the idempotent schema and forced RLS policies or fail closed."""
        try:
            with self._transaction() as (_db, cursor):
                cursor.execute(SCHEMA_SQL)
        except Exception as exc:
            raise _database_error(exc, "E_DATABASE_CONFLICT") from exc

    def ping(self) -> bool:
        """Return true only when PostgreSQL accepts a minimal query."""
        try:
            with self._transaction() as (_db, cursor):
                cursor.execute("SELECT 1")
                return cursor.fetchone()[0] == 1
        except Exception as exc:
            raise _database_error(exc, "E_DATABASE_CONFLICT") from exc

    def register_installation(self, tenant_id: str, installation_id: int) -> None:
        """Create or confirm an immutable installation-to-tenant mapping."""
        if not tenant_id.strip() or installation_id <= 0:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "tenant and positive installation id are required")
        try:
            with self._transaction() as (_db, cursor):
                cursor.execute(
                    """INSERT INTO factory_installations (installation_id, tenant_id) VALUES (%s, %s)
                       ON CONFLICT (installation_id) DO UPDATE SET tenant_id = factory_installations.tenant_id
                       RETURNING tenant_id""",
                    (installation_id, tenant_id),
                )
                bound = cursor.fetchone()[0]
        except Exception as exc:
            raise _database_error(exc, "E_INSTALLATION_TENANT") from exc
        if bound != tenant_id:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "installation is already bound to another tenant")

    def tenant_for_installation(self, installation_id: int) -> str:
        """Resolve the immutable routing tenant for one GitHub installation."""
        try:
            with self._transaction() as (_db, cursor):
                cursor.execute("SELECT tenant_id FROM factory_installations WHERE installation_id = %s", (installation_id,))
                row = cursor.fetchone()
        except Exception as exc:
            raise _database_error(exc, "E_INSTALLATION_TENANT") from exc
        if not row:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "installation is not registered")
        return str(row[0])

    def ingest(self, tenant_id: str, event: PullRequestEvent) -> dict[str, Any]:
        """Commit authenticated PR evidence and one pending approval transactionally."""
        evidence = {
            "schema": "factory.hosted-pr-assurance.evidence.v1",
            "tenant_id": tenant_id,
            "event": event.to_dict(),
            "verdict": "PENDING_APPROVAL",
        }
        evidence_sha256 = sha256(canonical_json(evidence))
        approval_id = str(uuid.uuid4())
        requester = f"github-app:{event.installation_id}"
        try:
            with self._transaction(tenant_id) as (_db, cursor):
                cursor.execute(
                    "SELECT tenant_id FROM factory_installations WHERE installation_id = %s",
                    (event.installation_id,),
                )
                mapped = cursor.fetchone()
                if not mapped or mapped[0] != tenant_id:
                    raise PRAssuranceError("E_INSTALLATION_TENANT", "installation does not belong to routed tenant")
                cursor.execute(
                    """INSERT INTO factory_pr_deliveries
                       (tenant_id, delivery_id, installation_id, repository, pull_request, head_sha,
                        actor, action, payload_sha256, evidence_sha256, approval_id, requester)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        tenant_id, event.delivery_id, event.installation_id, event.repository,
                        event.pull_request, event.head_sha, event.actor, event.action,
                        event.payload_sha256, evidence_sha256, approval_id, requester,
                    ),
                )
        except PRAssuranceError:
            raise
        except Exception as exc:  # pragma: no cover - normalized by real driver
            raise _database_error(exc, "E_WEBHOOK_REPLAY") from exc
        return {
            "schema": POSTGRES_SCHEMA,
            "markers": [
                "POSTGRES_RLS_BOUND", "INSTALLATION_TENANT_ROUTED", "HOSTED_INGRESS_TRANSACTIONAL",
            ],
            "tenant_id": tenant_id,
            "approval_id": approval_id,
            "evidence_sha256": evidence_sha256,
            "event": event.to_dict(),
            "check_request": github_check_request(
                event, evidence_digest=evidence_sha256, approval_id=approval_id, status="pending"
            ),
        }

    def decide(
        self,
        principal: Principal,
        approval_id: str,
        *,
        issuer: str,
        jti: str,
        decision: str,
        reason: str,
    ) -> dict[str, Any]:
        """Commit one independent decision and its unique Check outbox row atomically."""
        _validate_decision(principal, decision, reason)
        try:
            with self._transaction(principal.tenant_id) as (_db, cursor):
                cursor.execute(
                    """SELECT installation_id, repository, pull_request, head_sha, actor, action,
                              payload_sha256, evidence_sha256, requester, approval_status, delivery_id
                       FROM factory_pr_deliveries WHERE tenant_id = %s AND approval_id = %s FOR UPDATE""",
                    (principal.tenant_id, approval_id),
                )
                row = cursor.fetchone()
                _require_pending(row, principal)
                (
                    installation_id,
                    repository,
                    pull_request,
                    head_sha,
                    actor,
                    action,
                    payload_sha256,
                    evidence_sha256,
                    _requester,
                    _approval_status,
                    delivery_id,
                ) = row
                cursor.execute(
                    "INSERT INTO factory_oidc_uses (tenant_id,issuer,jti,subject,approval_id) VALUES (%s,%s,%s,%s,%s)",
                    (principal.tenant_id, issuer, jti, principal.subject, approval_id),
                )
                event = PullRequestEvent(
                    delivery_id=delivery_id,
                    repository=repository,
                    pull_request=int(pull_request),
                    installation_id=int(installation_id),
                    head_sha=head_sha,
                    actor=actor,
                    action=action,
                    payload_sha256=payload_sha256,
                )
                request = github_check_request(
                    event, evidence_digest=evidence_sha256, approval_id=approval_id, status=decision
                )
                cursor.execute(
                    """UPDATE factory_pr_deliveries SET approval_status=%s,approver=%s,
                       decision_reason=%s,decided_at=now() WHERE tenant_id=%s AND approval_id=%s""",
                    (decision, principal.subject, reason.strip(), principal.tenant_id, approval_id),
                )
                outbox_id = str(uuid.uuid4())
                cursor.execute(
                    """INSERT INTO factory_check_outbox
                       (outbox_id,tenant_id,approval_id,installation_id,repository,request_json)
                       VALUES (%s,%s,%s,%s,%s,%s::jsonb)""",
                    (
                        outbox_id, principal.tenant_id, approval_id, event.installation_id,
                        event.repository, canonical_json(request).decode("utf-8"),
                    ),
                )
        except PRAssuranceError:
            raise
        except Exception as exc:  # pragma: no cover - normalized by real driver
            raise _database_error(exc, "E_OIDC_REPLAY") from exc
        return {
            "schema": POSTGRES_SCHEMA,
            "markers": ["CHECK_OUTBOX_TRANSACTIONAL", "HOSTED_DECISION_TRANSACTIONAL"],
            "tenant_id": principal.tenant_id,
            "approval_id": approval_id,
            "outbox_id": outbox_id,
            "status": decision,
            "publication": "pending",
        }

    def claim_outbox(self, tenant_id: str, *, limit: int = 20) -> list[OutboxRecord]:
        """Claim pending Check rows with PostgreSQL skip-locked concurrency semantics."""
        if not 1 <= limit <= 20:
            raise PRAssuranceError("E_OUTBOX_LIMIT", "outbox claim limit must be between 1 and 20")
        with self._transaction(tenant_id) as (_db, cursor):
            cursor.execute(
                """SELECT outbox_id,tenant_id,approval_id,installation_id,repository,request_json,attempts
                   FROM factory_check_outbox
                   WHERE tenant_id=%s AND state='pending' AND attempts < 25
                   ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT %s""",
                (tenant_id, limit),
            )
            rows = cursor.fetchall()
            ids = [row[0] for row in rows]
            if ids:
                cursor.execute(
                    "UPDATE factory_check_outbox SET attempts=attempts+1 WHERE outbox_id = ANY(%s)", (ids,)
                )
        records = []
        for row in rows:
            outbox_id, row_tenant, approval_id, installation_id, repository, request, attempts = row
            records.append(
                OutboxRecord(
                    outbox_id=str(outbox_id),
                    tenant_id=row_tenant,
                    approval_id=str(approval_id),
                    installation_id=int(installation_id),
                    repository=repository,
                    request=request if isinstance(request, dict) else json.loads(request),
                    attempts=int(attempts) + 1,
                )
            )
        return records

    def mark_published(self, record: OutboxRecord, check_run_id: int) -> dict[str, Any]:
        """Store a positive remote Check id and mark the outbox row published."""
        if check_run_id <= 0:
            raise PRAssuranceError("E_GITHUB_RESPONSE", "GitHub check-run id must be positive")
        with self._transaction(record.tenant_id) as (_db, cursor):
            cursor.execute(
                """UPDATE factory_check_outbox SET state='published',check_run_id=%s,published_at=now(),last_error=NULL
                   WHERE tenant_id=%s AND outbox_id=%s AND state='pending'""",
                (check_run_id, record.tenant_id, record.outbox_id),
            )
            if cursor.rowcount != 1:
                raise PRAssuranceError("E_OUTBOX_STATE", "outbox row is not publishable")
        return {
            "marker": "OUTBOX_PUBLISHED", "markers": ["GITHUB_APP_PUBLICATION_BOUND"],
            "outbox_id": record.outbox_id, "check_run_id": check_run_id,
        }

    def mark_failed(self, record: OutboxRecord, error_code: str) -> dict[str, Any]:
        """Retain or exhaust a failed outbox row without exposing credential data."""
        state = "exhausted" if record.attempts >= MAX_OUTBOX_ATTEMPTS else "pending"
        marker = "OUTBOX_EXHAUSTED" if state == "exhausted" else "OUTBOX_PENDING"
        safe_error = str(error_code)[:1000]
        with self._transaction(record.tenant_id) as (_db, cursor):
            cursor.execute(
                "UPDATE factory_check_outbox SET state=%s,last_error=%s WHERE tenant_id=%s AND outbox_id=%s",
                (state, safe_error, record.tenant_id, record.outbox_id),
            )
        return {
            "marker": marker, "markers": ["OUTBOX_FAILURE_RETAINED"],
            "outbox_id": record.outbox_id, "attempts": record.attempts,
        }


def initialize_schema(store: PostgresAssuranceStore) -> None:
    """Create and verify the PostgreSQL RLS and outbox schema or refuse startup."""
    store.initialize()

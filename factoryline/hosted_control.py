"""Supervised tenant lifecycle and operator read model for the hosted adapter."""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import secrets
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .control_plane import Principal, canonical_json
from .hosted_identity import HttpTransport, JwksCache, get_jwks
from .integrations import principal_from_verified_oidc
from .pr_assurance import PRAssuranceError, verify_oidc_token


CONTROL_SCHEMA = "factory.hosted-control.postgres.v1"
TENANT_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,62}\Z")
PURPOSE_RE = re.compile(r"[a-z][a-z0-9_]{1,62}\Z")
ENV_REFERENCE_RE = re.compile(r"env://([A-Z][A-Z0-9_]{1,126})\Z")
ALLOWED_ROLES = frozenset({"viewer", "operator", "approver", "admin"})
INSTALLATION_STATE_SECONDS = 600


CONTROL_SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS factory_tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS factory_tenant_identity (
    tenant_id TEXT PRIMARY KEY REFERENCES factory_tenants(tenant_id),
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jwks_url TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS factory_tenant_role_mappings (
    tenant_id TEXT NOT NULL REFERENCES factory_tenants(tenant_id),
    directory_group TEXT NOT NULL,
    factory_role TEXT NOT NULL CHECK (factory_role IN ('viewer','operator','approver','admin')),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, directory_group)
);
CREATE TABLE IF NOT EXISTS factory_tenant_secret_refs (
    tenant_id TEXT NOT NULL REFERENCES factory_tenants(tenant_id),
    purpose TEXT NOT NULL,
    secret_ref TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, purpose)
);
CREATE TABLE IF NOT EXISTS factory_installation_states (
    state_sha256 TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES factory_tenants(tenant_id),
    issued_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS factory_admin_audit (
    sequence BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES factory_tenants(tenant_id),
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS factory_admin_audit_tenant_sequence
  ON factory_admin_audit(tenant_id, sequence);
CREATE TABLE IF NOT EXISTS factory_installations (
    installation_id BIGINT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE factory_installations DROP CONSTRAINT IF EXISTS factory_installations_tenant_id_key;
ALTER TABLE factory_installations ADD COLUMN IF NOT EXISTS bound_by TEXT;
ALTER TABLE factory_installations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE factory_tenant_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_tenant_identity FORCE ROW LEVEL SECURITY;
ALTER TABLE factory_tenant_role_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_tenant_role_mappings FORCE ROW LEVEL SECURITY;
ALTER TABLE factory_tenant_secret_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_tenant_secret_refs FORCE ROW LEVEL SECURITY;
ALTER TABLE factory_admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE factory_admin_audit FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS factory_identity_tenant ON factory_tenant_identity;
CREATE POLICY factory_identity_tenant ON factory_tenant_identity
  USING (tenant_id = current_setting('factory.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('factory.tenant_id', true));
DROP POLICY IF EXISTS factory_roles_tenant ON factory_tenant_role_mappings;
CREATE POLICY factory_roles_tenant ON factory_tenant_role_mappings
  USING (tenant_id = current_setting('factory.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('factory.tenant_id', true));
DROP POLICY IF EXISTS factory_secret_refs_tenant ON factory_tenant_secret_refs;
CREATE POLICY factory_secret_refs_tenant ON factory_tenant_secret_refs
  USING (tenant_id = current_setting('factory.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('factory.tenant_id', true));
DROP POLICY IF EXISTS factory_admin_audit_tenant ON factory_admin_audit;
CREATE POLICY factory_admin_audit_tenant ON factory_admin_audit
  USING (tenant_id = current_setting('factory.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('factory.tenant_id', true));
"""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _tenant_id(value: str) -> str:
    normalized = str(value).strip()
    if not TENANT_RE.fullmatch(normalized):
        raise PRAssuranceError("E_TENANT_INVALID", "tenant id must be 2-63 lowercase letters, digits, or hyphens")
    return normalized


def _authorize(principal: Principal, tenant_id: str, *, write: bool) -> str:
    selected = _tenant_id(tenant_id)
    platform = "platform_admin" in principal.roles and principal.tenant_id == "*"
    if not platform and principal.tenant_id != selected:
        raise PRAssuranceError("E_TENANT_BOUNDARY", "principal cannot administer another tenant")
    allowed = {"admin"} if write else {"admin", "viewer"}
    if not platform and not allowed.intersection(principal.roles):
        raise PRAssuranceError("E_ACTION_DENIED", "verified identity lacks hosted control authority")
    return selected


def _https_url(value: str, name: str) -> str:
    parts = urlsplit(str(value).strip())
    if (
        parts.scheme != "https"
        or not parts.netloc
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
    ):
        raise PRAssuranceError("E_IDENTITY_CONFIG", f"{name} must be credential-free HTTPS without query or fragment")
    return str(value).strip().rstrip("/")


def _secret_reference(value: str) -> str:
    reference = str(value).strip()
    if not ENV_REFERENCE_RE.fullmatch(reference):
        raise PRAssuranceError("E_SECRET_REFERENCE", "reference must be env:// followed by an uppercase environment name")
    return reference


def _safe_role_map(value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping) or not 1 <= len(value) <= 50:
        raise PRAssuranceError("E_ROLE_MAPPING", "role mapping must contain 1-50 groups")
    result: dict[str, str] = {}
    for group, role in value.items():
        group_name = str(group).strip()
        role_name = str(role).strip()
        if not group_name or len(group_name) > 200 or role_name not in ALLOWED_ROLES or group_name in result:
            raise PRAssuranceError("E_ROLE_MAPPING", "role mapping contains an invalid group or role")
        result[group_name] = role_name
    return result


def _state_hint(token: str) -> str:
    if not isinstance(token, str) or len(token) > 16_384 or token.count(".") != 2:
        raise PRAssuranceError("E_OIDC_MALFORMED", "OIDC token must be one compact JWT")
    try:
        payload = token.split(".")[1]
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PRAssuranceError("E_OIDC_MALFORMED", "OIDC tenant lookup hint is invalid") from exc
    if not isinstance(claims, dict):
        raise PRAssuranceError("E_OIDC_MALFORMED", "OIDC tenant lookup hint must be an object")
    return _tenant_id(str(claims.get("tenant_id", "")))


@dataclass(frozen=True)
class TenantIdentityConfig:
    """One tenant's public OIDC verification configuration."""

    tenant_id: str
    issuer: str
    audience: str
    jwks_url: str


class EnvSecretResolver:
    """Resolve allowlisted environment references without persisting resolved values."""

    def __init__(self, environ: Mapping[str, str] | None = None):
        self.environ = dict(os.environ if environ is None else environ)

    def resolve(self, reference: str) -> bytes:
        """Return a referenced secret with at least 16 bytes or raise ``PRAssuranceError``."""
        match = ENV_REFERENCE_RE.fullmatch(_secret_reference(reference))
        name = match.group(1) if match else ""
        value = self.environ.get(name, "").encode("utf-8")
        if len(value) < 16:
            raise PRAssuranceError("E_SECRET_UNAVAILABLE", "referenced secret is missing or shorter than 16 bytes")
        return value


class PostgresControlStore:
    """PostgreSQL tenant lifecycle store with forced RLS and hash-linked audit events."""

    def __init__(self, assurance_store: Any, *, clock: Callable[[], datetime] = _utcnow):
        self.assurance_store = assurance_store
        self.clock = clock

    def _transaction(self, tenant_id: str | None = None):
        return self.assurance_store._transaction(tenant_id)

    def initialize(self) -> None:
        """Apply the idempotent control schema or raise a classified database refusal."""
        try:
            with self._transaction() as (_db, cursor):
                cursor.execute(CONTROL_SCHEMA_SQL)
        except Exception as exc:
            raise PRAssuranceError("E_DATABASE", "hosted control schema initialization failed") from exc

    def _audit(
        self,
        cursor: Any,
        *,
        tenant_id: str,
        action: str,
        actor: str,
        resource_id: str,
        payload: dict[str, Any],
    ) -> None:
        cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (tenant_id,))
        cursor.execute(
            "SELECT event_hash FROM factory_admin_audit WHERE tenant_id=%s ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        )
        row = cursor.fetchone()
        previous_hash = str(row[0]) if row else ""
        created_at = self.clock()
        cursor.execute(
            """INSERT INTO factory_admin_audit
               (tenant_id,action,actor,resource_id,payload_json,previous_hash,event_hash,created_at)
               VALUES (%s,%s,%s,%s,%s::jsonb,%s,'pending',%s) RETURNING sequence""",
            (
                tenant_id,
                action,
                actor,
                resource_id,
                canonical_json(payload).decode("utf-8"),
                previous_hash,
                created_at,
            ),
        )
        sequence = int(cursor.fetchone()[0])
        event = {
            "schema": "factory.hosted.admin-audit.v1",
            "sequence": sequence,
            "tenant_id": tenant_id,
            "action": action,
            "actor": actor,
            "resource_id": resource_id,
            "payload": payload,
            "previous_hash": previous_hash,
            "created_at": created_at.isoformat(),
        }
        cursor.execute(
            "UPDATE factory_admin_audit SET event_hash=%s WHERE tenant_id=%s AND sequence=%s",
            (hashlib.sha256(canonical_json(event)).hexdigest(), tenant_id, sequence),
        )

    def create_tenant(self, principal: Principal, tenant_id: str, display_name: str) -> dict[str, Any]:
        """Create one tenant for bootstrap platform authority or raise ``PRAssuranceError``."""
        if "platform_admin" not in principal.roles or principal.tenant_id != "*":
            raise PRAssuranceError("E_ACTION_DENIED", "tenant creation requires bootstrap platform_admin authority")
        selected = _tenant_id(tenant_id)
        name = str(display_name).strip()
        if not 1 <= len(name) <= 120:
            raise PRAssuranceError("E_TENANT_INVALID", "display name must contain 1-120 characters")
        try:
            with self._transaction() as (_db, cursor):
                cursor.execute("SELECT display_name FROM factory_tenants WHERE tenant_id=%s FOR UPDATE", (selected,))
                row = cursor.fetchone()
                if row:
                    if str(row[0]) != name:
                        raise PRAssuranceError("E_TENANT_CONFLICT", "tenant id is already bound to another display name")
                    return {"schema": CONTROL_SCHEMA, "marker": "TENANT_EXISTS", "tenant_id": selected}
                cursor.execute(
                    "INSERT INTO factory_tenants (tenant_id,display_name,created_by) VALUES (%s,%s,%s)",
                    (selected, name, principal.subject),
                )
                cursor.execute("SELECT set_config('factory.tenant_id', %s, true)", (selected,))
                self._audit(
                    cursor,
                    tenant_id=selected,
                    action="tenant.created",
                    actor=principal.subject,
                    resource_id=selected,
                    payload={"display_name": name},
                )
        except PRAssuranceError:
            raise
        except Exception as exc:
            raise PRAssuranceError("E_DATABASE", "tenant creation failed") from exc
        return {
            "schema": CONTROL_SCHEMA,
            "markers": ["TENANT_CREATED", "ADMIN_ACTION_AUDITED", "CONTROL_RLS_BOUND"],
            "tenant_id": selected,
            "display_name": name,
        }

    def configure_identity(
        self,
        principal: Principal,
        tenant_id: str,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
    ) -> dict[str, Any]:
        """Store public OIDC verification configuration or raise ``PRAssuranceError``."""
        selected = _authorize(principal, tenant_id, write=True)
        trusted_issuer = _https_url(issuer, "issuer")
        trusted_jwks = _https_url(jwks_url, "JWKS URL")
        trusted_audience = str(audience).strip()
        if not 1 <= len(trusted_audience) <= 200:
            raise PRAssuranceError("E_IDENTITY_CONFIG", "audience must contain 1-200 characters")
        with self._transaction(selected) as (_db, cursor):
            cursor.execute(
                """INSERT INTO factory_tenant_identity
                   (tenant_id,issuer,audience,jwks_url,updated_by) VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT (tenant_id) DO UPDATE SET issuer=EXCLUDED.issuer,audience=EXCLUDED.audience,
                     jwks_url=EXCLUDED.jwks_url,updated_by=EXCLUDED.updated_by,updated_at=now()""",
                (selected, trusted_issuer, trusted_audience, trusted_jwks, principal.subject),
            )
            self._audit(
                cursor,
                tenant_id=selected,
                action="identity.configured",
                actor=principal.subject,
                resource_id=selected,
                payload={"issuer": trusted_issuer, "audience": trusted_audience, "jwks_url": trusted_jwks},
            )
        return {
            "schema": CONTROL_SCHEMA,
            "markers": ["OIDC_CONFIG_VERIFIED", "ADMIN_ACTION_AUDITED", "CONTROL_RLS_BOUND"],
            "tenant_id": selected,
        }

    def replace_roles(self, principal: Principal, tenant_id: str, mappings: Mapping[str, str]) -> dict[str, Any]:
        """Atomically replace one tenant role map or raise ``PRAssuranceError``."""
        selected = _authorize(principal, tenant_id, write=True)
        safe = _safe_role_map(mappings)
        with self._transaction(selected) as (_db, cursor):
            cursor.execute("DELETE FROM factory_tenant_role_mappings WHERE tenant_id=%s", (selected,))
            for group, role in sorted(safe.items()):
                cursor.execute(
                    """INSERT INTO factory_tenant_role_mappings
                       (tenant_id,directory_group,factory_role,updated_by) VALUES (%s,%s,%s,%s)""",
                    (selected, group, role, principal.subject),
                )
            self._audit(
                cursor,
                tenant_id=selected,
                action="roles.replaced",
                actor=principal.subject,
                resource_id=selected,
                payload={"groups": sorted(safe), "count": len(safe)},
            )
        return {
            "schema": CONTROL_SCHEMA,
            "markers": ["ROLE_MAPPING_BOUND", "ADMIN_ACTION_AUDITED", "CONTROL_RLS_BOUND"],
            "tenant_id": selected,
            "count": len(safe),
        }

    def set_secret_reference(
        self, principal: Principal, tenant_id: str, purpose: str, reference: str
    ) -> dict[str, Any]:
        """Store one environment secret reference without resolving its value."""
        selected = _authorize(principal, tenant_id, write=True)
        safe_purpose = str(purpose).strip()
        if not PURPOSE_RE.fullmatch(safe_purpose):
            raise PRAssuranceError("E_SECRET_REFERENCE", "secret purpose is invalid")
        safe_reference = _secret_reference(reference)
        with self._transaction(selected) as (_db, cursor):
            cursor.execute(
                """INSERT INTO factory_tenant_secret_refs
                   (tenant_id,purpose,secret_ref,updated_by) VALUES (%s,%s,%s,%s)
                   ON CONFLICT (tenant_id,purpose) DO UPDATE SET secret_ref=EXCLUDED.secret_ref,
                     updated_by=EXCLUDED.updated_by,updated_at=now()""",
                (selected, safe_purpose, safe_reference, principal.subject),
            )
            self._audit(
                cursor,
                tenant_id=selected,
                action="secret-reference.configured",
                actor=principal.subject,
                resource_id=safe_purpose,
                payload={"purpose": safe_purpose, "scheme": "env"},
            )
        return {
            "schema": CONTROL_SCHEMA,
            "markers": ["SECRET_REFERENCE_BOUND", "ADMIN_ACTION_AUDITED", "CONTROL_RLS_BOUND"],
            "tenant_id": selected,
            "purpose": safe_purpose,
        }

    def issue_state(self, principal: Principal, tenant_id: str) -> dict[str, Any]:
        """Issue one 600-second installation state while storing only its digest."""
        selected = _authorize(principal, tenant_id, write=True)
        raw = secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
        created_at = self.clock()
        expires_at = created_at + timedelta(seconds=INSTALLATION_STATE_SECONDS)
        with self._transaction(selected) as (_db, cursor):
            cursor.execute(
                """INSERT INTO factory_installation_states
                   (state_sha256,tenant_id,issued_by,created_at,expires_at) VALUES (%s,%s,%s,%s,%s)""",
                (digest, selected, principal.subject, created_at, expires_at),
            )
            self._audit(
                cursor,
                tenant_id=selected,
                action="installation-state.issued",
                actor=principal.subject,
                resource_id=digest[:16],
                payload={"expires_in_seconds": INSTALLATION_STATE_SECONDS},
            )
        return {
            "schema": CONTROL_SCHEMA,
            "markers": ["INSTALLATION_STATE_ISSUED", "ADMIN_ACTION_AUDITED", "CONTROL_RLS_BOUND"],
            "tenant_id": selected,
            "state": raw,
            "expires_in": INSTALLATION_STATE_SECONDS,
        }

    def bind_installation(self, state: str, installation_id: int) -> dict[str, Any]:
        """Consume one state and immutably bind an installation or raise ``PRAssuranceError``."""
        self._validate_installation_callback(state, installation_id)
        digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
        now = self.clock()
        try:
            with self._transaction() as (_db, cursor):
                tenant_id, issued_by = self._locked_installation_state(cursor, digest, now)
                self._store_installation_binding(cursor, tenant_id, issued_by, installation_id)
                self._consume_installation_state(cursor, digest, now)
                cursor.execute("SELECT set_config('factory.tenant_id', %s, true)", (tenant_id,))
                self._audit(
                    cursor,
                    tenant_id=tenant_id,
                    action="installation.bound",
                    actor=issued_by,
                    resource_id=str(installation_id),
                    payload={"installation_id": installation_id},
                )
        except PRAssuranceError:
            raise
        except Exception as exc:
            raise PRAssuranceError("E_DATABASE", "installation binding failed") from exc
        return {
            "schema": CONTROL_SCHEMA,
            "markers": ["INSTALLATION_BOUND", "ADMIN_ACTION_AUDITED", "CONTROL_RLS_BOUND"],
            "tenant_id": tenant_id,
            "installation_id": installation_id,
        }

    @staticmethod
    def _validate_installation_callback(state: str, installation_id: int) -> None:
        if (
            not isinstance(state, str)
            or len(state) < 32
            or not isinstance(installation_id, int)
            or isinstance(installation_id, bool)
            or installation_id <= 0
        ):
            raise PRAssuranceError("E_INSTALLATION_STATE", "valid state and positive installation id are required")

    @staticmethod
    def _locked_installation_state(cursor: Any, digest: str, now: datetime) -> tuple[str, str]:
        cursor.execute(
            """SELECT tenant_id,issued_by,expires_at,used_at FROM factory_installation_states
               WHERE state_sha256=%s FOR UPDATE""",
            (digest,),
        )
        row = cursor.fetchone()
        if not row or row[3] is not None or row[2] < now:
            raise PRAssuranceError("E_INSTALLATION_STATE", "installation state is missing, expired, or already used")
        return str(row[0]), str(row[1])

    @staticmethod
    def _store_installation_binding(
        cursor: Any, tenant_id: str, issued_by: str, installation_id: int
    ) -> None:
        cursor.execute(
            "SELECT tenant_id FROM factory_installations WHERE installation_id=%s FOR UPDATE",
            (installation_id,),
        )
        bound = cursor.fetchone()
        if bound and str(bound[0]) != tenant_id:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "installation is already bound to another tenant")
        if not bound:
            cursor.execute(
                "INSERT INTO factory_installations (installation_id,tenant_id,bound_by) VALUES (%s,%s,%s)",
                (installation_id, tenant_id, issued_by),
            )

    @staticmethod
    def _consume_installation_state(cursor: Any, digest: str, now: datetime) -> None:
        cursor.execute(
            "UPDATE factory_installation_states SET used_at=%s WHERE state_sha256=%s AND used_at IS NULL",
            (now, digest),
        )
        if cursor.rowcount != 1:
            raise PRAssuranceError("E_INSTALLATION_STATE", "installation state lost a concurrent race")

    def identity_config(self, tenant_id: str) -> TenantIdentityConfig:
        """Return public tenant OIDC configuration or raise ``PRAssuranceError``."""
        selected = _tenant_id(tenant_id)
        with self._transaction(selected) as (_db, cursor):
            cursor.execute(
                "SELECT issuer,audience,jwks_url FROM factory_tenant_identity WHERE tenant_id=%s",
                (selected,),
            )
            row = cursor.fetchone()
        if not row:
            raise PRAssuranceError("E_IDENTITY_CONFIG", "tenant identity is not configured")
        return TenantIdentityConfig(selected, str(row[0]), str(row[1]), str(row[2]))

    def role_map(self, tenant_id: str) -> dict[str, str]:
        """Return one tenant's directory-group role map or raise ``PRAssuranceError``."""
        selected = _tenant_id(tenant_id)
        with self._transaction(selected) as (_db, cursor):
            cursor.execute(
                "SELECT directory_group,factory_role FROM factory_tenant_role_mappings WHERE tenant_id=%s",
                (selected,),
            )
            rows = cursor.fetchall()
        if not rows:
            raise PRAssuranceError("E_ROLE_MAPPING", "tenant role mapping is not configured")
        return {str(row[0]): str(row[1]) for row in rows}

    def secret_reference_for_installation(self, installation_id: int, purpose: str) -> tuple[str, str]:
        """Resolve installation routing to a tenant secret reference without reading its value."""
        with self._transaction() as (_db, cursor):
            cursor.execute("SELECT tenant_id FROM factory_installations WHERE installation_id=%s", (installation_id,))
            row = cursor.fetchone()
        if not row:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "installation is not registered")
        tenant_id = str(row[0])
        with self._transaction(tenant_id) as (_db, cursor):
            cursor.execute(
                "SELECT secret_ref FROM factory_tenant_secret_refs WHERE tenant_id=%s AND purpose=%s",
                (tenant_id, purpose),
            )
            reference = cursor.fetchone()
        if not reference:
            raise PRAssuranceError("E_SECRET_REFERENCE", "tenant secret reference is not configured")
        return tenant_id, str(reference[0])

    def overview(self, principal: Principal, tenant_id: str) -> dict[str, Any]:
        """Return an allowlisted tenant read model or raise ``PRAssuranceError``."""
        selected = _authorize(principal, tenant_id, write=False)
        with self._transaction(selected) as (_db, cursor):
            cursor.execute("SELECT display_name,status FROM factory_tenants WHERE tenant_id=%s", (selected,))
            tenant = cursor.fetchone()
            if not tenant:
                raise PRAssuranceError("E_NOT_FOUND", "tenant was not found")
            cursor.execute("SELECT 1 FROM factory_tenant_identity WHERE tenant_id=%s", (selected,))
            identity_configured = cursor.fetchone() is not None
            cursor.execute(
                "SELECT factory_role,count(*) FROM factory_tenant_role_mappings WHERE tenant_id=%s GROUP BY factory_role",
                (selected,),
            )
            role_counts = {str(row[0]): int(row[1]) for row in cursor.fetchall()}
            cursor.execute(
                "SELECT purpose FROM factory_tenant_secret_refs WHERE tenant_id=%s ORDER BY purpose", (selected,)
            )
            secret_purposes = [str(row[0]) for row in cursor.fetchall()]
            cursor.execute(
                """SELECT sequence,action,actor,resource_id,payload_json,previous_hash,event_hash,created_at
                   FROM factory_admin_audit WHERE tenant_id=%s ORDER BY sequence""",
                (selected,),
            )
            audit_rows = cursor.fetchall()
            cursor.execute(
                "SELECT state,count(*) FROM factory_check_outbox WHERE tenant_id=%s GROUP BY state", (selected,)
            )
            outbox_counts = {str(row[0]): int(row[1]) for row in cursor.fetchall()}
            cursor.execute(
                "SELECT approval_status,count(*) FROM factory_pr_deliveries WHERE tenant_id=%s GROUP BY approval_status",
                (selected,),
            )
            approval_counts = {str(row[0]): int(row[1]) for row in cursor.fetchall()}
        with self._transaction() as (_db, cursor):
            cursor.execute(
                "SELECT installation_id FROM factory_installations WHERE tenant_id=%s ORDER BY installation_id", (selected,)
            )
            installation_ids = [int(row[0]) for row in cursor.fetchall()]
        audit_events = []
        previous = ""
        audit_valid = True
        for row in audit_rows:
            created_at = row[7].isoformat()
            payload = row[4] if isinstance(row[4], dict) else json.loads(row[4])
            event = {
                "schema": "factory.hosted.admin-audit.v1",
                "sequence": int(row[0]),
                "tenant_id": selected,
                "action": str(row[1]),
                "actor": str(row[2]),
                "resource_id": str(row[3]),
                "payload": payload,
                "previous_hash": str(row[5]),
                "created_at": created_at,
            }
            expected = hashlib.sha256(canonical_json(event)).hexdigest()
            audit_valid = audit_valid and str(row[5]) == previous and str(row[6]) == expected
            previous = str(row[6])
            audit_events.append({
                "sequence": int(row[0]),
                "action": str(row[1]),
                "actor": str(row[2]),
                "resource_id": str(row[3]),
                "event_hash": str(row[6]),
                "created_at": created_at,
            })
        return {
            "schema": "factory.hosted-control.overview.v1",
            "markers": ["CONTROL_OVERVIEW_REDACTED", "CONTROL_RLS_BOUND"],
            "tenant": {"tenant_id": selected, "display_name": str(tenant[0]), "status": str(tenant[1])},
            "identity_configured": identity_configured,
            "role_counts": role_counts,
            "installation_ids": installation_ids,
            "secret_purposes": secret_purposes,
            "outbox_counts": outbox_counts,
            "approval_counts": approval_counts,
            "audit": {"valid": audit_valid, "events": audit_events[-20:]},
        }


class TenantIdentityVerifier:
    """Verify tenant OIDC tokens after using untrusted claims only as lookup hints."""

    def __init__(self, store: PostgresControlStore, transport: HttpTransport):
        self.store = store
        self.transport = transport
        self._caches: dict[tuple[str, str], JwksCache] = {}

    def verify(self, token: str) -> tuple[Principal, dict[str, Any]]:
        """Return a verified tenant principal and claims or raise ``PRAssuranceError``."""
        tenant_id = _state_hint(token)
        config = self.store.identity_config(tenant_id)
        cache = self._caches.setdefault(
            (tenant_id, config.jwks_url), JwksCache(config.jwks_url, self.transport)
        )
        claims = verify_oidc_token(token, get_jwks(cache), config.issuer, config.audience)
        principal = principal_from_verified_oidc(
            claims, expected_issuer=config.issuer, role_map=self.store.role_map(tenant_id)
        )
        if principal.tenant_id != tenant_id:
            raise PRAssuranceError("E_TENANT_BOUNDARY", "verified tenant differs from lookup hint")
        return principal, {**claims, "marker": "TENANT_IDENTITY_VERIFIED"}


def initialize_control_schema(store: PostgresControlStore) -> None:
    """Create and verify the tenant lifecycle, forced-RLS, and audit schema."""
    store.initialize()


def issue_installation_state(
    store: PostgresControlStore, principal: Principal, tenant_id: str
) -> dict[str, Any]:
    """Issue one 600-second state while storing only its SHA-256 digest."""
    return store.issue_state(principal, tenant_id)

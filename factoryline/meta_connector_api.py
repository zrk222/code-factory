"""OAuth-protected, receipt-backed REST resource for Meta AI Connectors.

The service accepts bounded audit summaries from an authenticated account. It
never clones repositories, executes code, or treats submitted evidence as an
independent attestation. OAuth authorization is delegated to a configured IdP.
"""

from __future__ import annotations

from base64 import b64encode
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
import re
import sqlite3
import time
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit
from urllib.parse import parse_qs
from uuid import uuid4

from .hosted_identity import HttpxTransport, JwksCache, get_jwks
from .pr_assurance import PRAssuranceError, verify_oidc_token


MAX_BODY = 524_288
MAX_FINDINGS = 500
MAX_AUDITS = 200
MAX_TOKEN_SECONDS = 900
RETENTION_SECONDS = 7 * 86400
SHA = re.compile(r"[a-f0-9]{40}(?:[a-f0-9]{24})?\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
LABELS = frozenset({"PASS", "FAIL", "NOT_RUN", "INCOMPLETE", "BLOCKED"})
LANES = ("code_factory", "forgeline", "appforge", "saasforge", "full_depth")


class StorageUnavailable(Exception):
    """A database operation failed without exposing provider details."""


class PostgresConnection:
    """Expose the subset of sqlite3.Connection used by the connector."""

    def __init__(self, dsn: str):
        try:
            import psycopg

            self._driver = psycopg
            self._connection = psycopg.connect(dsn, connect_timeout=5)
        except Exception:
            raise StorageUnavailable("audit storage is unavailable") from None

    def __enter__(self) -> PostgresConnection:
        return self

    def __exit__(self, kind: Any, value: Any, traceback: Any) -> None:
        try:
            if kind is None:
                self._connection.commit()
            else:
                self._connection.rollback()
        except self._driver.Error:
            raise StorageUnavailable("audit storage is unavailable") from None
        finally:
            self._connection.close()

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        """Execute the connector's limited SQL dialect using PostgreSQL parameters."""
        if statement == "BEGIN IMMEDIATE":
            return None
        try:
            return self._connection.execute(statement.replace("?", "%s"), parameters)
        except self._driver.Error:
            raise StorageUnavailable("audit storage is unavailable") from None


def connect(database: str) -> sqlite3.Connection | PostgresConnection:
    """Select durable PostgreSQL by DSN; retain SQLite for local workflows."""
    if is_postgres(database):
        return PostgresConnection(database)
    return sqlite3.connect(database, timeout=5)


def is_postgres(database: str) -> bool:
    """Identify PostgreSQL connection strings without opening a database connection."""
    return database.startswith(("postgresql://", "postgres://"))


class ClerkTokenError(Exception):
    """The access token could not be verified or is not authorized."""


def verify_clerk_oauth_token(
    token: str, endpoint: str, client_id: str, client_secret: str
) -> dict[str, Any]:
    """Require an active token from the one configured OAuth client."""
    import httpx

    if not token or len(token) > 8192 or not client_id or not client_secret:
        raise ClerkTokenError("access token could not be verified")
    credentials = b64encode(f"{client_id}:{client_secret}".encode()).decode()
    try:
        response = httpx.post(
            endpoint,
            data={"token": token},
            headers={"Authorization": f"Basic {credentials}"},
            timeout=5,
            follow_redirects=False,
        )
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        raise ClerkTokenError("access token could not be verified") from None
    if not isinstance(payload, dict) or payload.get("active") is not True:
        raise ClerkTokenError("access token is inactive")
    if payload.get("client_id") != client_id:
        raise ClerkTokenError("access token client does not match")
    if not isinstance(payload.get("sub"), str) or not payload["sub"]:
        raise ClerkTokenError("access token subject is invalid")
    if not isinstance(payload.get("scope"), str):
        raise ClerkTokenError("access token scopes are invalid")
    now = int(time.time())
    return {
        "signature_verified": True,
        "sub": payload["sub"],
        "scope": payload["scope"],
        "iat": now,
        "exp": now + 1,
    }


class ConnectorError(Exception):
    def __init__(self, status: str, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _text(value: Any, name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(0xD800 <= ord(char) <= 0xDFFF for char in value)
    ):
        raise ConnectorError("400 Bad Request", "INVALID_INPUT", f"{name} is invalid")
    return value.strip()


def _timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(
            _text(value, "created_at", 40).replace("Z", "+00:00")
        )
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc)
    except ValueError as exc:
        raise ConnectorError(
            "400 Bad Request", "INVALID_TIME", "created_at needs a timezone"
        ) from exc


def _validated_findings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_FINDINGS:
        raise ConnectorError(
            "400 Bad Request", "INVALID_FINDINGS", "findings exceed the 500 item limit"
        )
    return [_validated_finding(item) for item in value]


def _validated_finding(finding: Any) -> dict[str, Any]:
    required = {"path", "line", "severity", "title", "resolution", "lane"}
    if not isinstance(finding, dict) or set(finding) != required:
        raise ConnectorError(
            "400 Bad Request", "INVALID_FINDING", "finding fields are invalid"
        )
    line = finding["line"]
    if (
        not isinstance(line, int)
        or isinstance(line, bool)
        or not 0 <= line <= 1_000_000
    ):
        raise ConnectorError(
            "400 Bad Request", "INVALID_FINDING", "finding line is invalid"
        )
    path = _text(finding["path"], "path", 300)
    if (
        path.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:", path)
        or "://" in path
        or ".." in path.replace("\\", "/").split("/")
    ):
        raise ConnectorError(
            "400 Bad Request", "INVALID_FINDING", "finding path is unsafe"
        )
    lane = _text(finding["lane"], "lane", 30)
    severity = _text(finding["severity"], "severity", 10)
    if lane not in LANES or severity not in {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }:
        raise ConnectorError(
            "400 Bad Request", "INVALID_FINDING", "finding lane or severity is invalid"
        )
    return {
        "path": path,
        "line": line,
        "lane": lane,
        "severity": severity,
        "title": _text(finding["title"], "title", 160),
        "resolution": _text(finding["resolution"], "resolution", 500),
    }


def _validate_snapshot(value: Any, now: datetime) -> dict[str, Any]:
    fields = {
        "schema",
        "repository",
        "commit_sha",
        "policy_sha256",
        "created_at",
        "outcomes",
        "findings",
        "coverage",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value["schema"] != "factory.meta.audit.v1"
    ):
        raise ConnectorError(
            "400 Bad Request",
            "INVALID_SNAPSHOT",
            "snapshot fields or schema are invalid",
        )
    repository = _text(value["repository"], "repository", 201)
    commit = _text(value["commit_sha"], "commit_sha", 64)
    policy = (
        None
        if value["policy_sha256"] is None
        else _text(value["policy_sha256"], "policy_sha256", 64)
    )
    if (
        not REPOSITORY.fullmatch(repository)
        or any(part.startswith(".") or ".." in part for part in repository.split("/"))
        or not SHA.fullmatch(commit)
        or (policy is not None and not HEX64.fullmatch(policy))
    ):
        raise ConnectorError(
            "400 Bad Request",
            "INVALID_BINDING",
            "repository or digest binding is invalid",
        )
    created = _timestamp(value["created_at"])
    age = (now - created).total_seconds()
    if age < -60 or age > RETENTION_SECONDS:
        raise ConnectorError(
            "400 Bad Request",
            "STALE_SNAPSHOT",
            "snapshot must be recent and cannot be future dated",
        )
    outcomes = value["outcomes"]
    if (
        not isinstance(outcomes, dict)
        or set(outcomes) != set(LANES)
        or any(
            not isinstance(label, str) or label not in LABELS
            for label in outcomes.values()
        )
    ):
        raise ConnectorError(
            "400 Bad Request",
            "INVALID_OUTCOMES",
            "all five audit lanes need explicit states",
        )
    if policy is None and outcomes["code_factory"] == "PASS":
        raise ConnectorError(
            "400 Bad Request",
            "INVALID_OUTCOMES",
            "missing policy cannot pass Code Factory",
        )
    cleaned = _validated_findings(value["findings"])
    coverage = value["coverage"]
    if not isinstance(coverage, list) or len(coverage) > 50:
        raise ConnectorError(
            "400 Bad Request", "INVALID_COVERAGE", "coverage list is invalid"
        )
    return {
        "schema": value["schema"],
        "repository": repository,
        "commit_sha": commit,
        "policy_sha256": policy,
        "created_at": created.isoformat(),
        "outcomes": outcomes,
        "findings": cleaned,
        "coverage": [_text(item, "coverage item", 300) for item in coverage],
    }


def _openapi_operation(path: str, method: str) -> dict[str, Any]:
    operation: dict[str, Any] = {
        "operationId": f"{method}_{path.strip('/').replace('/', '_').replace('{id}', 'id') or 'health'}",
        "summary": {
            "/health": "Process liveness",
            "/ready": "Storage readiness",
            "/openapi.json": "API contract",
            "/v1/capabilities": "Audit capability and limits",
            "/v1/account": "Linked account state",
            "/v1/account/relink": "Relink after fresh OAuth consent",
            "/v1/audits": "Audit summaries",
            "/v1/audits/{id}": "One audit summary",
            "/v1/audits/{id}/findings": "Paginated findings",
            "/v1/audits/{id}/coverage": "Coverage limits",
            "/v1/audits/{id}/repair-plan": "Actionable repair steps",
        }[path],
        "responses": {
            "201" if method == "post" and path == "/v1/audits" else "200": {
                "description": "Bounded JSON result",
                "content": {"application/json": {"schema": {"type": "object"}}},
            },
            "400": {"description": "Invalid or oversized input"},
            "401": {"description": "Missing, expired, or revoked access token"},
            "403": {"description": "Required OAuth scope missing"},
            "404": {"description": "Unknown resource or account-owned audit"},
        },
    }
    if "{id}" in path:
        operation["parameters"] = [
            {
                "name": "id",
                "in": "path",
                "required": True,
                "schema": {"type": "string", "format": "uuid"},
            }
        ]
    if method == "get" and path in {"/v1/audits", "/v1/audits/{id}/findings"}:
        operation.setdefault("parameters", []).extend(
            [
                {
                    "name": "offset",
                    "in": "query",
                    "schema": {"type": "integer", "minimum": 0, "default": 0},
                },
                {
                    "name": "limit",
                    "in": "query",
                    "schema": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "default": 20,
                    },
                },
            ]
        )
    if method == "post" and path == "/v1/audits":
        operation["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/AuditSnapshot"}
                }
            },
        }
    if path not in {"/health", "/ready", "/openapi.json", "/v1/capabilities"}:
        operation["security"] = [
            {
                "oauth": [
                    "cf.audit.link"
                    if path == "/v1/account/relink"
                    else "cf.audit.write"
                    if method in {"post", "delete"}
                    else "cf.audit.read"
                ]
            }
        ]
    return operation


class MetaConnectorAPI:
    """WSGI application with exact-subject SQLite storage and injected JWT verifier."""

    def __init__(
        self,
        database: str,
        verifier: Callable[[str], dict[str, Any]],
        *,
        authorization_url: str,
        token_url: str,
        public_base_url: str | None = None,
        fixed_tenant: str | None = None,
        max_token_seconds: int = MAX_TOKEN_SECONDS,
    ):
        self.database, self.verifier = database, verifier
        self._postgres = is_postgres(database)
        self.authorization_url, self.token_url = authorization_url, token_url
        self.public_base_url = public_base_url
        self.fixed_tenant = fixed_tenant
        self.max_token_seconds = max_token_seconds
        with self._db() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS meta_accounts (tenant TEXT NOT NULL, subject TEXT NOT NULL, revoked_at INTEGER, PRIMARY KEY (tenant, subject))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS meta_audits (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, subject TEXT NOT NULL, created INTEGER NOT NULL, payload TEXT NOT NULL)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS meta_audits_owner ON meta_audits(tenant, subject, created)"
            )

    def _db(self):
        return connect(self.database)

    def purge_expired(self) -> int:
        """Delete expired summaries without requiring another user upload."""
        cutoff = int(datetime.now(timezone.utc).timestamp()) - RETENTION_SECONDS
        with self._db() as db:
            return db.execute("DELETE FROM meta_audits WHERE created<?", (cutoff,)).rowcount

    def _account_row(self, db: Any, tenant: str, subject: str) -> Any:
        statement = "SELECT revoked_at FROM meta_accounts WHERE tenant=? AND subject=?"
        if self._postgres:
            statement += " FOR UPDATE"
        return db.execute(statement, (tenant, subject)).fetchone()

    def _verified_identity(
        self, environ: Mapping[str, Any], scope: str
    ) -> tuple[str, str, dict[str, Any]]:
        header = environ.get("HTTP_AUTHORIZATION", "")
        if (
            not isinstance(header, str)
            or not header.startswith("Bearer ")
            or len(header) > 8192
        ):
            raise ConnectorError(
                "401 Unauthorized", "AUTH_REQUIRED", "Bearer access token required"
            )
        try:
            claims = self.verifier(header[7:])
        except (PRAssuranceError, ClerkTokenError, ValueError, TypeError) as exc:
            raise ConnectorError(
                "401 Unauthorized",
                "TOKEN_INVALID",
                "access token could not be verified",
            ) from exc
        if not isinstance(claims, dict) or claims.get("signature_verified") is not True:
            raise ConnectorError(
                "401 Unauthorized", "TOKEN_INVALID", "verified access token required"
            )
        try:
            tenant_claim = claims.get("tenant_id")
            if self.fixed_tenant is not None:
                if tenant_claim is not None and tenant_claim != self.fixed_tenant:
                    raise ConnectorError(
                        "401 Unauthorized",
                        "TOKEN_INVALID",
                        "identity claims are invalid",
                    )
                tenant_claim = self.fixed_tenant
            tenant = _text(tenant_claim, "tenant_id", 100)
            subject = _text(claims.get("sub"), "sub", 200)
            if tenant != tenant_claim or subject != claims["sub"]:
                raise ConnectorError(
                    "401 Unauthorized", "TOKEN_INVALID", "identity claims are invalid"
                )
        except ConnectorError as exc:
            raise ConnectorError(
                "401 Unauthorized", "TOKEN_INVALID", "identity claims are invalid"
            ) from exc
        issued, expires = claims.get("iat"), claims.get("exp")
        if (
            not isinstance(issued, int)
            or isinstance(issued, bool)
            or not isinstance(expires, int)
            or isinstance(expires, bool)
            or not 0 < expires - issued <= self.max_token_seconds
        ):
            raise ConnectorError(
                "401 Unauthorized",
                "TOKEN_LIFETIME",
                "access token lifetime exceeds the configured issuer limit",
            )
        scopes = claims.get("scope", "")
        if not isinstance(scopes, str) or scope not in scopes.split():
            raise ConnectorError(
                "403 Forbidden", "SCOPE_REQUIRED", f"{scope} scope required"
            )
        return tenant, subject, claims

    def _identity(self, environ: Mapping[str, Any], scope: str) -> tuple[str, str]:
        tenant, subject, _claims = self._verified_identity(environ, scope)
        with self._db() as db:
            row = db.execute(
                "SELECT revoked_at FROM meta_accounts WHERE tenant=? AND subject=?",
                (tenant, subject),
            ).fetchone()
            if row and row[0] is not None:
                raise ConnectorError(
                    "401 Unauthorized", "ACCOUNT_REVOKED", "linked account is revoked"
                )
            db.execute(
                "INSERT INTO meta_accounts(tenant, subject) VALUES (?,?) "
                "ON CONFLICT(tenant,subject) DO NOTHING",
                (tenant, subject),
            )
        return tenant, subject

    @staticmethod
    def _body(environ: Mapping[str, Any]) -> Any:
        try:
            length = int(environ.get("CONTENT_LENGTH", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError("body size")
            raw = environ["wsgi.input"].read(length)
            if len(raw) != length:
                raise ValueError("short body")
            return json.loads(raw.decode("utf-8"))
        except (
            KeyError,
            ValueError,
            UnicodeError,
            TypeError,
            json.JSONDecodeError,
        ) as exc:
            raise ConnectorError(
                "400 Bad Request", "INVALID_BODY", "bounded UTF-8 JSON body required"
            ) from exc

    @staticmethod
    def _page(environ: Mapping[str, Any]) -> tuple[int, int]:
        raw = str(environ.get("QUERY_STRING", ""))
        if len(raw) > 100:
            raise ConnectorError(
                "400 Bad Request", "INVALID_PAGE", "pagination query is too long"
            )
        query = parse_qs(raw, keep_blank_values=True)
        if set(query) - {"offset", "limit"} or any(
            len(values) != 1 for values in query.values()
        ):
            raise ConnectorError(
                "400 Bad Request", "INVALID_PAGE", "unsupported pagination parameter"
            )
        try:
            offset, limit = (
                int(query.get("offset", ["0"])[0]),
                int(query.get("limit", ["20"])[0]),
            )
        except ValueError as exc:
            raise ConnectorError(
                "400 Bad Request", "INVALID_PAGE", "pagination must be integer"
            ) from exc
        if not 0 <= offset <= 1_000_000 or not 1 <= limit <= 50:
            raise ConnectorError(
                "400 Bad Request", "INVALID_PAGE", "pagination outside bounds"
            )
        return offset, limit

    def _owned(self, audit_id: str, tenant: str, subject: str) -> dict[str, Any]:
        with self._db() as db:
            row = db.execute(
                "SELECT payload FROM meta_audits WHERE id=? AND tenant=? AND subject=? AND created>=?",
                (
                    audit_id,
                    tenant,
                    subject,
                    int(datetime.now(timezone.utc).timestamp()) - RETENTION_SECONDS,
                ),
            ).fetchone()
        if not row:
            raise ConnectorError("404 Not Found", "NOT_FOUND", "audit not found")
        return json.loads(row[0])

    def _route(
        self, method: str, path: str, environ: Mapping[str, Any]
    ) -> tuple[str, Any]:
        if method == "GET" and path == "/health":
            return "200 OK", {"schema": "factory.meta.health.v1", "ok": True}
        if method == "GET" and path == "/ready":
            with self._db() as db:
                db.execute("SELECT 1").fetchone()
            return "200 OK", {"schema": "factory.meta.ready.v1", "ok": True}
        if method == "GET" and path == "/openapi.json":
            return "200 OK", self.openapi()
        if method == "GET" and path == "/v1/capabilities":
            return "200 OK", {
                "schema": "factory.meta.capabilities.v1",
                "mode": "receipt-backed",
                "operations": [
                    "list audits",
                    "audit summary",
                    "findings",
                    "coverage",
                    "repair plan",
                    "delete account",
                ],
                "limits": [
                    "submitted summaries are not independent attestations",
                    "no repository execution",
                    "no release approval or certification",
                    "full-depth state follows supplied receipt",
                ],
            }
        if path == "/v1/account":
            return self._account_route(method, environ)
        if path == "/v1/account/relink":
            return self._relink_route(method, environ)
        if path == "/v1/audits":
            return self._collection_route(method, environ)
        parts = path.strip("/").split("/")
        if len(parts) in (3, 4) and parts[:2] == ["v1", "audits"]:
            return self._item_route(method, parts, environ)
        raise ConnectorError("404 Not Found", "NOT_FOUND", "route not found")

    def _account_route(
        self, method: str, environ: Mapping[str, Any]
    ) -> tuple[str, Any]:
        if method not in {"GET", "DELETE"}:
            raise ConnectorError("404 Not Found", "NOT_FOUND", "route not found")
        tenant, subject = self._identity(
            environ, "cf.audit.read" if method == "GET" else "cf.audit.write"
        )
        if method == "GET":
            return "200 OK", {
                "schema": "factory.meta.account.v1",
                "tenant_id": tenant,
                "subject": subject,
            }
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            self._account_row(db, tenant, subject)
            db.execute(
                "DELETE FROM meta_audits WHERE tenant=? AND subject=?",
                (tenant, subject),
            )
            db.execute(
                "UPDATE meta_accounts SET revoked_at=? WHERE tenant=? AND subject=?",
                (int(datetime.now(timezone.utc).timestamp()), tenant, subject),
            )
        return "200 OK", {
            "schema": "factory.meta.account.v1",
            "status": "revoked_and_deleted",
        }

    def _relink_route(self, method: str, environ: Mapping[str, Any]) -> tuple[str, Any]:
        if method != "POST":
            raise ConnectorError("404 Not Found", "NOT_FOUND", "route not found")
        tenant, subject, claims = self._verified_identity(environ, "cf.audit.link")
        auth_time = claims.get("auth_time")
        if (
            not isinstance(auth_time, int)
            or isinstance(auth_time, bool)
            or auth_time > claims["iat"]
        ):
            raise ConnectorError(
                "401 Unauthorized",
                "FRESH_LINK_REQUIRED",
                "fresh OAuth authorization required",
            )
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._account_row(db, tenant, subject)
            if row and row[0] is not None and auth_time <= row[0]:
                raise ConnectorError(
                    "401 Unauthorized",
                    "FRESH_LINK_REQUIRED",
                    "authorize again after unlinking",
                )
            db.execute(
                "INSERT INTO meta_accounts(tenant, subject, revoked_at) VALUES (?,?,NULL) "
                "ON CONFLICT(tenant,subject) DO UPDATE SET revoked_at=NULL",
                (tenant, subject),
            )
        return "200 OK", {"schema": "factory.meta.account.v1", "status": "linked"}

    def _collection_route(
        self, method: str, environ: Mapping[str, Any]
    ) -> tuple[str, Any]:
        if method not in {"GET", "POST"}:
            raise ConnectorError("404 Not Found", "NOT_FOUND", "route not found")
        tenant, subject = self._identity(
            environ, "cf.audit.write" if method == "POST" else "cf.audit.read"
        )
        if method == "POST":
            return self._create_audit(tenant, subject, environ)
        return self._list_audits(tenant, subject, environ)

    def _create_audit(
        self, tenant: str, subject: str, environ: Mapping[str, Any]
    ) -> tuple[str, Any]:
        now = datetime.now(timezone.utc)
        snapshot = _validate_snapshot(self._body(environ), now)
        digest = sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        audit_id = str(uuid4())
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            account = self._account_row(db, tenant, subject)
            if account is None or account[0] is not None:
                raise ConnectorError(
                    "401 Unauthorized", "ACCOUNT_REVOKED", "linked account is revoked"
                )
            db.execute(
                "DELETE FROM meta_audits WHERE created<?",
                (int(now.timestamp()) - RETENTION_SECONDS,),
            )
            count = db.execute(
                "SELECT COUNT(*) FROM meta_audits WHERE tenant=? AND subject=?",
                (tenant, subject),
            ).fetchone()[0]
            if count >= MAX_AUDITS:
                raise ConnectorError(
                    "409 Conflict",
                    "AUDIT_LIMIT",
                    "delete old audits before uploading more",
                )
            db.execute(
                "INSERT INTO meta_audits VALUES (?,?,?,?,?)",
                (audit_id, tenant, subject, int(now.timestamp()), json.dumps(snapshot)),
            )
        return "201 Created", {
            "id": audit_id,
            "snapshot_sha256": digest,
            "provenance": "authenticated_submitter; not independent attestation",
        }

    def _list_audits(
        self, tenant: str, subject: str, environ: Mapping[str, Any]
    ) -> tuple[str, Any]:
        offset, limit = self._page(environ)
        with self._db() as db:
            rows = db.execute(
                "SELECT id,payload FROM meta_audits WHERE tenant=? AND subject=? AND created>=? ORDER BY created DESC,id DESC LIMIT ? OFFSET ?",
                (
                    tenant,
                    subject,
                    int(datetime.now(timezone.utc).timestamp()) - RETENTION_SECONDS,
                    limit,
                    offset,
                ),
            ).fetchall()
        return "200 OK", {
            "items": [
                {
                    "id": item_id,
                    "repository": payload["repository"],
                    "commit_sha": payload["commit_sha"],
                    "outcomes": payload["outcomes"],
                }
                for item_id, raw in rows
                if (payload := json.loads(raw))
            ],
            "offset": offset,
            "limit": limit,
        }

    def _item_route(
        self, method: str, parts: list[str], environ: Mapping[str, Any]
    ) -> tuple[str, Any]:
        if method not in {"GET", "DELETE"}:
            raise ConnectorError("404 Not Found", "NOT_FOUND", "route not found")
        tenant, subject = self._identity(
            environ, "cf.audit.write" if method == "DELETE" else "cf.audit.read"
        )
        audit_id = parts[2]
        if not re.fullmatch(r"[0-9a-f-]{36}", audit_id):
            raise ConnectorError("404 Not Found", "NOT_FOUND", "audit not found")
        audit = self._owned(audit_id, tenant, subject)
        if len(parts) == 3:
            if method == "DELETE":
                with self._db() as db:
                    db.execute(
                        "DELETE FROM meta_audits WHERE id=? AND tenant=? AND subject=?",
                        (audit_id, tenant, subject),
                    )
                return "200 OK", {"id": audit_id, "status": "deleted"}
            return "200 OK", {
                "id": audit_id,
                **{k: v for k, v in audit.items() if k != "findings"},
                "finding_count": len(audit["findings"]),
                "provenance": "authenticated_submitter; not independent attestation",
            }
        if method == "GET":
            return self._audit_detail_route(parts[3], audit, environ)
        raise ConnectorError("404 Not Found", "NOT_FOUND", "route not found")

    def _audit_detail_route(
        self, resource: str, audit: dict[str, Any], environ: Mapping[str, Any]
    ) -> tuple[str, Any]:
        if resource == "findings":
            offset, limit = self._page(environ)
            return "200 OK", {
                "items": audit["findings"][offset : offset + limit],
                "total": len(audit["findings"]),
                "offset": offset,
                "limit": limit,
            }
        if resource == "coverage":
            return "200 OK", {
                "coverage": audit["coverage"],
                "outcomes": audit["outcomes"],
                "full_depth": audit["outcomes"]["full_depth"],
            }
        if resource == "repair-plan":
            return "200 OK", {
                "actions": [
                    {
                        "path": item["path"],
                        "line": item["line"],
                        "action": item["resolution"],
                    }
                    for item in audit["findings"][:50]
                ],
                "remaining_findings": max(0, len(audit["findings"]) - 50),
                "rerun": "Repair the exact candidate, rerun affected lanes, and upload a new commit-bound summary.",
                "authority": "advisory only",
            }
        raise ConnectorError("404 Not Found", "NOT_FOUND", "route not found")

    def openapi(self) -> dict[str, Any]:
        """Return the public OpenAPI contract for account-linked audit resource queries."""
        paths = {
            "/health": ["get"],
            "/ready": ["get"],
            "/openapi.json": ["get"],
            "/v1/capabilities": ["get"],
            "/v1/account": ["get", "delete"],
            "/v1/account/relink": ["post"],
            "/v1/audits": ["get", "post"],
            "/v1/audits/{id}": ["get", "delete"],
            "/v1/audits/{id}/findings": ["get"],
            "/v1/audits/{id}/coverage": ["get"],
            "/v1/audits/{id}/repair-plan": ["get"],
        }
        specification = {
            "openapi": "3.1.0",
            "info": {
                "title": "Code Factory Meta Connector",
                "version": "1.0.0",
                "description": "Receipt-backed audit queries; no code execution, certification, or release authority.",
            },
            "paths": {
                path: {method: _openapi_operation(path, method) for method in methods}
                for path, methods in paths.items()
            },
            "components": {
                "schemas": {
                    "Finding": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "path",
                            "line",
                            "severity",
                            "title",
                            "resolution",
                            "lane",
                        ],
                        "properties": {
                            "path": {"type": "string", "maxLength": 300},
                            "line": {"type": "integer", "minimum": 0},
                            "severity": {
                                "enum": ["critical", "high", "medium", "low", "info"]
                            },
                            "title": {"type": "string", "maxLength": 160},
                            "resolution": {"type": "string", "maxLength": 500},
                            "lane": {"enum": list(LANES)},
                        },
                    },
                    "AuditSnapshot": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "schema",
                            "repository",
                            "commit_sha",
                            "policy_sha256",
                            "created_at",
                            "outcomes",
                            "findings",
                            "coverage",
                        ],
                        "properties": {
                            "schema": {"const": "factory.meta.audit.v1"},
                            "repository": {
                                "type": "string",
                                "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
                            },
                            "commit_sha": {
                                "type": "string",
                                "pattern": "^[a-f0-9]{40}([a-f0-9]{24})?$",
                            },
                            "policy_sha256": {
                                "type": ["string", "null"],
                                "pattern": "^[a-f0-9]{64}$",
                            },
                            "created_at": {"type": "string", "format": "date-time"},
                            "outcomes": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": list(LANES),
                                "properties": {
                                    name: {"enum": sorted(LABELS)} for name in LANES
                                },
                            },
                            "findings": {
                                "type": "array",
                                "maxItems": MAX_FINDINGS,
                                "items": {"$ref": "#/components/schemas/Finding"},
                            },
                            "coverage": {
                                "type": "array",
                                "maxItems": 50,
                                "items": {"type": "string", "maxLength": 300},
                            },
                        },
                    },
                },
                "securitySchemes": {
                    "oauth": {
                        "type": "oauth2",
                        "flows": {
                            "authorizationCode": {
                                "authorizationUrl": self.authorization_url,
                                "tokenUrl": self.token_url,
                                "scopes": {
                                    "cf.audit.read": "Read own audit summaries",
                                    "cf.audit.write": "Upload and delete own audit summaries",
                                    "cf.audit.link": "Relink after a fresh OAuth authorization",
                                },
                            }
                        },
                    }
                },
            },
        }
        if self.public_base_url:
            specification["servers"] = [{"url": self.public_base_url}]
        return specification

    def __call__(
        self, environ: Mapping[str, Any], start_response: Callable
    ) -> list[bytes]:
        try:
            status, value = self._route(
                str(environ.get("REQUEST_METHOD", "GET")).upper(),
                str(environ.get("PATH_INFO", "/")),
                environ,
            )
        except ConnectorError as exc:
            status, value = (
                exc.status,
                {"error": {"code": exc.code, "message": exc.message}},
            )
        except (sqlite3.Error, StorageUnavailable):
            status, value = (
                "503 Service Unavailable",
                {
                    "error": {
                        "code": "STORAGE_UNAVAILABLE",
                        "message": "audit storage is unavailable",
                    }
                },
            )
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        start_response(
            status,
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
        return [body]


def _validated_provider(env: Mapping[str, str]) -> str:
    required = (
        "FACTORY_META_DATABASE",
        "FACTORY_META_OIDC_ISSUER",
        "FACTORY_META_AUTHORIZATION_URL",
        "FACTORY_META_TOKEN_URL",
    )
    if any(not env.get(key) for key in required):
        raise ConnectorError(
            "500 Internal Server Error",
            "CONFIG_MISSING",
            "Meta connector identity and storage configuration required",
        )
    if env.get("VERCEL") and not is_postgres(env["FACTORY_META_DATABASE"]):
        raise ConnectorError(
            "500 Internal Server Error",
            "CONFIG_INVALID",
            "Vercel connector requires durable PostgreSQL storage",
        )
    provider = env.get("FACTORY_META_OIDC_PROVIDER", "generic")
    if provider not in {"generic", "clerk"}:
        raise ConnectorError(
            "500 Internal Server Error", "CONFIG_INVALID", "unsupported OIDC provider"
        )
    provider_required = (
        ("FACTORY_META_OIDC_AUDIENCE", "FACTORY_META_JWKS_URL")
        if provider == "generic"
        else ("FACTORY_META_CLERK_CLIENT_ID", "FACTORY_META_CLERK_CLIENT_SECRET")
    )
    if any(not env.get(key) for key in provider_required):
        raise ConnectorError(
            "500 Internal Server Error",
            "CONFIG_MISSING",
            "Meta connector identity configuration required",
        )
    https_fields = (
        "FACTORY_META_OIDC_ISSUER",
        "FACTORY_META_AUTHORIZATION_URL",
        "FACTORY_META_TOKEN_URL",
    )
    if provider == "generic":
        https_fields += ("FACTORY_META_JWKS_URL",)
    if any(not env[key].startswith("https://") for key in https_fields):
        raise ConnectorError(
            "500 Internal Server Error",
            "CONFIG_INVALID",
            "identity endpoints must use HTTPS",
        )
    return provider


def _validated_public_base(env: Mapping[str, str]) -> str:
    public_base_url = env.get("FACTORY_META_PUBLIC_BASE_URL", "").rstrip("/")
    public_url = urlsplit(public_base_url)
    if public_base_url and (
        public_url.scheme != "https"
        or not public_url.hostname
        or public_url.username is not None
        or public_url.password is not None
        or public_url.query
        or public_url.fragment
    ):
        raise ConnectorError(
            "500 Internal Server Error",
            "CONFIG_INVALID",
            "public base URL must use HTTPS",
        )
    return public_base_url


def _connector_verifier(
    env: Mapping[str, str], provider: str
) -> tuple[Callable[[str], dict[str, Any]], str | None]:
    if provider == "clerk":
        fixed_tenant = env.get("FACTORY_META_TENANT_ID", "")
        if not fixed_tenant or len(fixed_tenant) > 100:
            raise ConnectorError(
                "500 Internal Server Error",
                "CONFIG_INVALID",
                "dedicated Clerk tenant ID required",
            )
        issuer = env["FACTORY_META_OIDC_ISSUER"].rstrip("/")
        introspection_url = f"{issuer}/oauth/token_info"

        def verify(token: str) -> dict[str, Any]:
            return verify_clerk_oauth_token(
                token,
                introspection_url,
                env["FACTORY_META_CLERK_CLIENT_ID"],
                env["FACTORY_META_CLERK_CLIENT_SECRET"],
            )

        return verify, fixed_tenant
    jwks = JwksCache(env["FACTORY_META_JWKS_URL"], HttpxTransport())

    def verify(token: str) -> dict[str, Any]:
        return verify_oidc_token(
            token,
            get_jwks(jwks),
            env["FACTORY_META_OIDC_ISSUER"],
            env["FACTORY_META_OIDC_AUDIENCE"],
        )

    return verify, None


def create_meta_connector_app_from_env(
    environ: Mapping[str, str] | None = None,
) -> MetaConnectorAPI:
    """Construct the production resource server; an external OAuth2 IdP owns linking."""
    env = dict(os.environ if environ is None else environ)
    # Piped provider CLI input can retain a terminal newline in a DSN or
    # client secret. Neither value permits raw line breaks.
    for key in ("FACTORY_META_DATABASE", "FACTORY_META_CLERK_CLIENT_SECRET"):
        if key in env:
            env[key] = env[key].rstrip("\r\n")
    provider = _validated_provider(env)
    public_base_url = _validated_public_base(env)
    verify, fixed_tenant = _connector_verifier(env, provider)

    return MetaConnectorAPI(
        env["FACTORY_META_DATABASE"],
        verify,
        authorization_url=env["FACTORY_META_AUTHORIZATION_URL"],
        token_url=env["FACTORY_META_TOKEN_URL"],
        public_base_url=public_base_url or None,
        fixed_tenant=fixed_tenant,
        max_token_seconds=MAX_TOKEN_SECONDS,
    )


def app(environ: Mapping[str, Any], start_response: Callable) -> list[bytes]:
    """Lazy WSGI entrypoint for gunicorn factoryline.meta_connector_api:app."""
    global _APP
    if _APP is None:
        _APP = create_meta_connector_app_from_env()
    return _APP(environ, start_response)


_APP: MetaConnectorAPI | None = None

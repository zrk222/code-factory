"""Stateless deployment adapter and PostgreSQL dialect checks."""

from __future__ import annotations

from io import BytesIO
import json
import sqlite3
import time

import api.index as vercel_entrypoint
from factoryline.meta_connector_api import (
    ConnectorError,
    MetaConnectorAPI,
    create_meta_connector_app_from_env,
)
from factoryline.meta_connector_storage import (
    PostgresConnection,
    StorageUnavailable,
    is_postgres,
)
from factoryline.meta_connector_clerk import ClerkTokenError, verify_clerk_oauth_token


def test_is_postgres_recognizes_only_postgres_dsns():
    assert is_postgres("postgresql://host/audit")
    assert is_postgres("postgres://host/audit")
    assert not is_postgres("/data/audit.sqlite")


def test_vercel_mount_strips_only_api_prefix(monkeypatch):
    seen = []

    def connector(environ, start_response):
        seen.append((environ["PATH_INFO"], environ["QUERY_STRING"]))
        start_response("200 OK", [])
        return [b"ok"]

    monkeypatch.setattr(vercel_entrypoint, "connector_app", connector)
    for path, expected in (
        ("/api", "/"),
        ("/api/v1/audits", "/v1/audits"),
        ("/v1/audits", "/v1/audits"),
    ):
        original = {"PATH_INFO": path, "QUERY_STRING": "limit=1"}
        assert vercel_entrypoint.app(original, lambda *_: None) == [b"ok"]
        assert original["PATH_INFO"] == path
        assert seen[-1] == (expected, "limit=1")


def test_openapi_uses_configured_public_base_url(tmp_path):
    app = MetaConnectorAPI(
        str(tmp_path / "audit.sqlite"),
        lambda _: {},
        authorization_url="https://id.example/authorize",
        token_url="https://id.example/token",
        public_base_url="https://wizeme.app/integrations/code-factory",
    )
    assert app.openapi()["servers"] == [
        {"url": "https://wizeme.app/integrations/code-factory"}
    ]


def test_postgres_adapter_keeps_audits_across_stateless_instances(
    tmp_path, monkeypatch
):
    """Use a DB-API fake to exercise SQL translation without another service."""
    database = tmp_path / "pg-dialect.sqlite"
    statements = []

    class FakePsycopgConnection:
        def __init__(self):
            self.db = sqlite3.connect(database)

        def execute(self, statement, parameters=()):
            statements.append(statement)
            translated = statement.replace("%s", "?").replace(" FOR UPDATE", "")
            return self.db.execute(translated, parameters)

        def commit(self):
            self.db.commit()

        def rollback(self):
            self.db.rollback()

        def close(self):
            self.db.close()

    import psycopg

    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: FakePsycopgConnection())
    now = int(time.time())
    claims = {
        "signature_verified": True,
        "tenant_id": "code-factory",
        "sub": "owner",
        "iat": now,
        "exp": now + 600,
        "scope": "cf.audit.read cf.audit.write",
    }

    def create():
        return MetaConnectorAPI(
            "postgresql://isolated.example/cf",
            lambda _token: claims,
            authorization_url="https://id.example/authorize",
            token_url="https://id.example/token",
        )

    def call(app, method, path, payload=None):
        raw = json.dumps(payload).encode() if payload is not None else b""
        state = {}

        def respond(status, _headers):
            state["status"] = status

        result = app(
            {
                "REQUEST_METHOD": method,
                "PATH_INFO": path,
                "CONTENT_LENGTH": str(len(raw)),
                "wsgi.input": BytesIO(raw),
                "HTTP_AUTHORIZATION": "Bearer test",
            },
            respond,
        )
        return state["status"], json.loads(b"".join(result))

    snapshot = {
        "schema": "factory.meta.audit.v1",
        "repository": "zrk222/code-factory",
        "commit_sha": "a" * 40,
        "policy_sha256": "b" * 64,
        "created_at": "2026-09-27T00:00:00Z",
        "outcomes": {
            "code_factory": "PASS",
            "forgeline": "NOT_RUN",
            "appforge": "NOT_RUN",
            "saasforge": "NOT_RUN",
            "full_depth": "INCOMPLETE",
        },
        "findings": [],
        "coverage": ["Only submitted summary is available"],
    }
    # The submitted timestamp must be inside the service's retention window.
    from datetime import datetime, timezone

    snapshot["created_at"] = datetime.now(timezone.utc).isoformat()
    status, created = call(create(), "POST", "/v1/audits", snapshot)
    assert status == "201 Created", created
    status, listed = call(create(), "GET", "/v1/audits")
    assert status == "200 OK" and listed["items"][0]["id"] == created["id"]
    assert any("FOR UPDATE" in statement for statement in statements)
    assert any("%s" in statement for statement in statements)


def test_postgres_connection_errors_do_not_expose_dsn(monkeypatch):
    import psycopg

    def fail(*_args, **_kwargs):
        raise RuntimeError("postgresql://secret:password@provider.example/db")

    monkeypatch.setattr(psycopg, "connect", fail)
    try:
        PostgresConnection("postgresql://secret:password@provider.example/db")
    except StorageUnavailable as exc:
        assert "secret" not in str(exc)
    else:
        raise AssertionError("broken storage must fail closed")


def test_vercel_rejects_ephemeral_sqlite_even_with_identity_configured(tmp_path):
    config = {
        "VERCEL": "1",
        "FACTORY_META_DATABASE": str(tmp_path / "ephemeral.sqlite"),
        "FACTORY_META_OIDC_ISSUER": "https://id.example/",
        "FACTORY_META_OIDC_AUDIENCE": "code-factory",
        "FACTORY_META_JWKS_URL": "https://id.example/jwks.json",
        "FACTORY_META_AUTHORIZATION_URL": "https://id.example/authorize",
        "FACTORY_META_TOKEN_URL": "https://id.example/token",
    }
    try:
        create_meta_connector_app_from_env(config)
    except ConnectorError as exc:
        assert exc.code == "CONFIG_INVALID"
    else:
        raise AssertionError("stateless storage must fail closed")


def test_dedicated_clerk_profile_accepts_one_day_scoped_token(tmp_path):
    now = int(time.time())
    claims = {
        "signature_verified": True,
        "sub": "clerk-user",
        "iat": now,
        "exp": now + 86_400,
        "scope": "cf.audit.read",
    }
    app = MetaConnectorAPI(
        str(tmp_path / "clerk.sqlite"),
        lambda _token: claims,
        authorization_url="https://id.example/authorize",
        token_url="https://id.example/token",
        fixed_tenant="code-factory",
        max_token_seconds=86_400,
    )
    state = {}

    def respond(status, _headers):
        state["status"] = status

    result = app(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/v1/account",
            "HTTP_AUTHORIZATION": "Bearer test",
        },
        respond,
    )
    assert state["status"] == "200 OK"
    assert json.loads(b"".join(result))["tenant_id"] == "code-factory"


def test_clerk_profile_rejects_cross_tenant_claim(tmp_path):
    now = int(time.time())
    app = MetaConnectorAPI(
        str(tmp_path / "clerk.sqlite"),
        lambda _token: {
            "signature_verified": True,
            "tenant_id": "other",
            "sub": "clerk-user",
            "iat": now,
            "exp": now + 86_400,
            "scope": "cf.audit.read",
        },
        authorization_url="https://id.example/authorize",
        token_url="https://id.example/token",
        fixed_tenant="code-factory",
        max_token_seconds=86_400,
    )
    status = {}
    app(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/v1/account",
            "HTTP_AUTHORIZATION": "Bearer test",
        },
        lambda code, _headers: status.setdefault("code", code),
    )
    assert status["code"] == "401 Unauthorized"


def test_clerk_profile_requires_dedicated_tenant_and_valid_public_url(tmp_path):
    config = {
        "FACTORY_META_DATABASE": str(tmp_path / "clerk.sqlite"),
        "FACTORY_META_OIDC_ISSUER": "https://id.example/",
        "FACTORY_META_OIDC_AUDIENCE": "code-factory",
        "FACTORY_META_JWKS_URL": "https://id.example/jwks.json",
        "FACTORY_META_AUTHORIZATION_URL": "https://id.example/authorize",
        "FACTORY_META_TOKEN_URL": "https://id.example/token",
        "FACTORY_META_OIDC_PROVIDER": "clerk",
        "FACTORY_META_CLERK_CLIENT_ID": "client-id",
        "FACTORY_META_CLERK_CLIENT_SECRET": "client-secret",
    }
    try:
        create_meta_connector_app_from_env(config)
    except ConnectorError as exc:
        assert exc.code == "CONFIG_INVALID"
    else:
        raise AssertionError("Clerk must be bound to a dedicated tenant")
    config["FACTORY_META_TENANT_ID"] = "code-factory"
    config["FACTORY_META_PUBLIC_BASE_URL"] = "https://user:pass@cf.wizeme.app/api"
    try:
        create_meta_connector_app_from_env(config)
    except ConnectorError as exc:
        assert exc.code == "CONFIG_INVALID"
    else:
        raise AssertionError("public URL must not contain credentials")


def test_clerk_introspection_pins_client_and_active_scope(monkeypatch):
    import httpx

    def respond(_endpoint, *, data, headers, timeout, follow_redirects):
        assert data == {"token": "access-token"}
        assert headers["Authorization"].startswith("Basic ")
        assert timeout == 5 and follow_redirects is False
        return httpx.Response(
            200,
            json={
                "active": True,
                "client_id": "expected-client",
                "sub": "user-1",
                "scope": "cf.audit.read",
            },
            request=httpx.Request("POST", _endpoint),
        )

    monkeypatch.setattr(httpx, "post", respond)
    claims = verify_clerk_oauth_token(
        "access-token", "https://id.example/oauth/token_info", "expected-client", "secret"
    )
    assert claims["signature_verified"] is True
    assert claims["scope"] == "cf.audit.read"
    try:
        verify_clerk_oauth_token(
            "access-token", "https://id.example/oauth/token_info", "other-client", "secret"
        )
    except ClerkTokenError:
        pass
    else:
        raise AssertionError("token from another client must be rejected")

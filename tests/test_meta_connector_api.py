from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
import time
from threading import Thread
from urllib.request import urlopen
from wsgiref.simple_server import make_server
from uuid import uuid4

import api.index as vercel_entrypoint
import factoryline.meta_connector_api as meta_connector_api
import pytest
from factoryline.meta_connector_api import (
    ClerkTokenError,
    ConnectorError,
    MetaConnectorAPI,
    PostgresConnection,
    StorageUnavailable,
    create_meta_connector_app_from_env,
    is_postgres,
    verify_clerk_oauth_token,
)


def _claims(subject="one", tenant="team", scopes="cf.audit.read cf.audit.write"):
    now = int(time.time())
    return {
        "signature_verified": True,
        "sub": subject,
        "tenant_id": tenant,
        "scope": scopes,
        "iat": now,
        "exp": now + 600,
    }


def _app(tmp_path, claims=None):
    return MetaConnectorAPI(
        str(tmp_path / "meta.sqlite"),
        lambda _: claims or _claims(),
        authorization_url="https://id.example/authorize",
        token_url="https://id.example/token",
    )


def _call(app, method, path, body=None, query="", token="test-token"):
    raw = json.dumps(body).encode() if body is not None else b""
    env = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_LENGTH": str(len(raw)),
        "wsgi.input": BytesIO(raw),
        "HTTP_AUTHORIZATION": f"Bearer {token}" if token else "",
    }
    captured = {}

    def respond(status, headers):
        captured["status"], captured["headers"] = status, dict(headers)

    result = json.loads(b"".join(app(env, respond)))
    return captured["status"], result, captured["headers"]


def _snapshot():
    return {
        "schema": "factory.meta.audit.v1",
        "repository": "zrk222/code-factory",
        "commit_sha": "a" * 40,
        "policy_sha256": "b" * 64,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "outcomes": {
            "code_factory": "PASS",
            "forgeline": "INCOMPLETE",
            "appforge": "NOT_RUN",
            "saasforge": "NOT_RUN",
            "full_depth": "INCOMPLETE",
        },
        "findings": [
            {
                "path": "src/app.py",
                "line": 12,
                "severity": "high",
                "title": "Missing validation",
                "resolution": "Validate input and rerun test.",
                "lane": "code_factory",
            }
        ],
        "coverage": ["Python AST only; JavaScript and DAST not run"],
    }


def test_full_audit_resource_lifecycle(tmp_path):
    app = _app(tmp_path)
    status, created, _ = _call(app, "POST", "/v1/audits", _snapshot())
    assert status == "201 Created"
    assert created["provenance"].startswith("authenticated_submitter")
    audit_id = created["id"]
    assert len(created["snapshot_sha256"]) == 64
    status, listed, _ = _call(app, "GET", "/v1/audits")
    assert status == "200 OK" and len(listed["items"]) == 1
    status, detail, headers = _call(app, "GET", f"/v1/audits/{audit_id}")
    assert status == "200 OK" and detail["finding_count"] == 1
    assert detail["outcomes"]["full_depth"] == "INCOMPLETE"
    assert "findings" not in detail and headers["Cache-Control"] == "no-store"
    assert _call(app, "GET", f"/v1/audits/{audit_id}/findings")[1]["total"] == 1
    assert (
        _call(app, "GET", f"/v1/audits/{audit_id}/coverage")[1]["full_depth"]
        == "INCOMPLETE"
    )
    assert (
        "Validate input"
        in _call(app, "GET", f"/v1/audits/{audit_id}/repair-plan")[1]["actions"][0][
            "action"
        ]
    )
    assert _call(app, "DELETE", f"/v1/audits/{audit_id}")[0] == "200 OK"
    assert _call(app, "GET", f"/v1/audits/{audit_id}")[0] == "404 Not Found"


def test_auth_scope_and_account_revocation(tmp_path):
    app = _app(tmp_path)
    assert _call(app, "GET", "/v1/audits", token="")[0] == "401 Unauthorized"
    read_only = _app(tmp_path, _claims(scopes="cf.audit.read"))
    assert _call(read_only, "POST", "/v1/audits", _snapshot())[0] == "403 Forbidden"
    assert _call(app, "DELETE", "/v1/account")[0] == "200 OK"
    assert _call(app, "GET", "/v1/account")[1]["error"]["code"] == "ACCOUNT_REVOKED"


def test_revocation_between_identity_check_and_upload_still_blocks(tmp_path):
    app = _app(tmp_path)
    tenant, subject = app._identity(
        {"HTTP_AUTHORIZATION": "Bearer test-token"}, "cf.audit.write"
    )
    assert _call(app, "DELETE", "/v1/account")[0] == "200 OK"
    raw = json.dumps(_snapshot()).encode()
    environment = {"CONTENT_LENGTH": str(len(raw)), "wsgi.input": BytesIO(raw)}
    try:
        app._create_audit(tenant, subject, environment)
    except ConnectorError as exc:
        assert exc.code == "ACCOUNT_REVOKED"
    else:
        raise AssertionError("upload after unlink must be refused")


def test_signed_identities_are_not_trimmed_or_aliased(tmp_path):
    claims = _claims(subject=" one ")
    app = _app(tmp_path, claims)
    assert _call(app, "GET", "/v1/account")[1]["error"]["code"] == "TOKEN_INVALID"


def test_relink_requires_fresh_oauth_grant(tmp_path):
    app = _app(tmp_path)
    assert _call(app, "DELETE", "/v1/account")[0] == "200 OK"
    stale = _claims(scopes="cf.audit.link")
    stale["auth_time"] = stale["iat"] - 10
    assert (
        _call(_app(tmp_path, stale), "POST", "/v1/account/relink")[1]["error"]["code"]
        == "FRESH_LINK_REQUIRED"
    )
    with sqlite3.connect(tmp_path / "meta.sqlite") as db:
        db.execute("UPDATE meta_accounts SET revoked_at=?", (int(time.time()) - 5,))
    fresh = _claims(scopes="cf.audit.link")
    fresh["auth_time"] = fresh["iat"]
    assert (
        _call(_app(tmp_path, fresh), "POST", "/v1/account/relink")[1]["status"]
        == "linked"
    )
    assert _call(app, "GET", "/v1/account")[0] == "200 OK"


def test_tenant_and_subject_isolation(tmp_path):
    owner = _app(tmp_path)
    audit_id = _call(owner, "POST", "/v1/audits", _snapshot())[1]["id"]
    assert (
        _call(_app(tmp_path, _claims(subject="two")), "GET", f"/v1/audits/{audit_id}")[
            0
        ]
        == "404 Not Found"
    )
    assert (
        _call(_app(tmp_path, _claims(tenant="other")), "GET", f"/v1/audits/{audit_id}")[
            0
        ]
        == "404 Not Found"
    )


def test_rejects_stale_unbound_and_oversized_input(tmp_path):
    app = _app(tmp_path)
    stale = _snapshot()
    stale["created_at"] = "2020-01-01T00:00:00Z"
    assert (
        _call(app, "POST", "/v1/audits", stale)[1]["error"]["code"] == "STALE_SNAPSHOT"
    )
    bad = _snapshot()
    bad["findings"][0]["path"] = "../private"
    assert (
        _call(app, "POST", "/v1/audits", bad)[1]["error"]["code"] == "INVALID_FINDING"
    )
    for unsafe_path in ("C:/private/key", "https://example.com/file"):
        bad = _snapshot()
        bad["findings"][0]["path"] = unsafe_path
        assert _call(app, "POST", "/v1/audits", bad)[0] == "400 Bad Request"
    bad = _snapshot()
    bad["outcomes"].pop("full_depth")
    assert (
        _call(app, "POST", "/v1/audits", bad)[1]["error"]["code"] == "INVALID_OUTCOMES"
    )
    bad = _snapshot()
    bad["outcomes"]["full_depth"] = []
    assert _call(app, "POST", "/v1/audits", bad)[0] == "400 Bad Request"
    bad = _snapshot()
    bad["findings"][0]["title"] = "broken\ud800"
    assert _call(app, "POST", "/v1/audits", bad)[0] == "400 Bad Request"
    missing_policy = _snapshot()
    missing_policy["policy_sha256"] = None
    missing_policy["outcomes"]["code_factory"] = "INCOMPLETE"
    assert _call(app, "POST", "/v1/audits", missing_policy)[0] == "201 Created"
    missing_policy["outcomes"]["code_factory"] = "PASS"
    assert _call(app, "POST", "/v1/audits", missing_policy)[0] == "400 Bad Request"
    bad = _snapshot()
    bad["findings"][0]["resolution"] = "x" * 501
    assert _call(app, "POST", "/v1/audits", bad)[0] == "400 Bad Request"


def test_openapi_and_capability_boundary(tmp_path):
    app = _app(tmp_path)
    status, spec, _ = _call(app, "GET", "/openapi.json", token="")
    assert status == "200 OK" and spec["openapi"] == "3.1.0"
    assert (
        spec["components"]["securitySchemes"]["oauth"]["flows"]["authorizationCode"][
            "authorizationUrl"
        ]
        == "https://id.example/authorize"
    )
    caps = _call(app, "GET", "/v1/capabilities", token="")[1]
    assert "no release approval or certification" in caps["limits"]
    config = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "deploy/meta-connector/meta-onboarding.example.json"
        ).read_text()
    )
    operations = {
        operation["operationId"]
        for path in spec["paths"].values()
        for operation in path.values()
    }
    assert set(config["assistant_operations"]).issubset(operations)
    assert set(config["private_operator_operations"]).issubset(operations)
    assert not set(config["assistant_operations"]) & set(
        config["private_operator_operations"]
    )


def test_documented_production_environment_accepts_non_url_audience(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(meta_connector_api, "HttpxTransport", lambda: object())
    monkeypatch.setattr(
        meta_connector_api, "JwksCache", lambda _url, _transport: object()
    )
    config = {
        "FACTORY_META_DATABASE": str(tmp_path / "meta.sqlite"),
        "FACTORY_META_OIDC_ISSUER": "https://id.example/",
        "FACTORY_META_OIDC_AUDIENCE": "code-factory-meta-connector",
        "FACTORY_META_JWKS_URL": "https://id.example/jwks.json",
        "FACTORY_META_AUTHORIZATION_URL": "https://id.example/authorize",
        "FACTORY_META_TOKEN_URL": "https://id.example/token",
    }
    assert create_meta_connector_app_from_env(config).openapi()["openapi"] == "3.1.0"
    config["FACTORY_META_TOKEN_URL"] = "http://id.example/token"
    try:
        create_meta_connector_app_from_env(config)
    except ConnectorError as exc:
        assert exc.code == "CONFIG_INVALID"
    else:
        raise AssertionError("HTTP OAuth token endpoint must be refused")


def test_real_loopback_http_serves_openapi_and_readiness(tmp_path):
    app = _app(tmp_path)
    server = make_server("127.0.0.1", 0, app)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with urlopen(
            f"http://127.0.0.1:{server.server_port}/ready", timeout=2
        ) as response:
            assert response.status == 200
            assert json.load(response)["ok"] is True
        with urlopen(
            f"http://127.0.0.1:{server.server_port}/openapi.json", timeout=2
        ) as response:
            spec = json.load(response)
        assert (
            spec["paths"]["/v1/audits"]["post"]["requestBody"]["content"][
                "application/json"
            ]["schema"]["$ref"]
            == "#/components/schemas/AuditSnapshot"
        )
        assert (
            spec["paths"]["/v1/audits/{id}/findings"]["get"]["parameters"][0][
                "required"
            ]
            is True
        )
    finally:
        server.shutdown()
        worker.join(timeout=2)
        server.server_close()


def test_is_postgres_recognizes_only_postgres_dsns():
    assert is_postgres("postgresql://host/audit")
    assert is_postgres("postgres://host/audit")
    assert not is_postgres("/data/audit.sqlite")


def test_hosted_config_trims_terminal_newlines_only(tmp_path, monkeypatch):
    database = str(tmp_path / "audit.sqlite")
    config = {
        "FACTORY_META_DATABASE": database + "\r\n",
        "FACTORY_META_OIDC_PROVIDER": "clerk",
        "FACTORY_META_OIDC_ISSUER": "https://clerk.example",
        "FACTORY_META_AUTHORIZATION_URL": "https://clerk.example/oauth/authorize",
        "FACTORY_META_TOKEN_URL": "https://clerk.example/oauth/token",
        "FACTORY_META_CLERK_CLIENT_ID": "client",
        "FACTORY_META_CLERK_CLIENT_SECRET": "secret\n",
        "FACTORY_META_TENANT_ID": "tenant",
    }
    app = create_meta_connector_app_from_env(config)
    assert app.database == database


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


def test_retention_purges_expired_rows_without_new_upload(tmp_path):
    database = str(tmp_path / "retention.sqlite")
    api = MetaConnectorAPI(
        database,
        lambda _: {},
        authorization_url="https://id.example/authorize",
        token_url="https://id.example/token",
    )
    now = int(time.time())
    with sqlite3.connect(database) as db:
        db.executemany(
            "INSERT INTO meta_audits(id,tenant,subject,created,payload) VALUES(?,?,?,?,?)",
            [("old", "t", "s", now - 8 * 86400, "{}"), ("new", "t", "s", now, "{}")],
        )
    assert api.purge_expired() == 1
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT id FROM meta_audits").fetchall() == [("new",)]


def test_vercel_retention_requires_configured_cron_secret(monkeypatch):
    class Stub:
        def purge_expired(self):
            return 3

    monkeypatch.setattr(vercel_entrypoint, "create_meta_connector_app_from_env", Stub)
    secret = "s" * 40
    monkeypatch.setenv("CRON_SECRET", secret)

    def request(token):
        status = {}
        body = vercel_entrypoint.app(
            {
                "PATH_INFO": "/api/internal/retention",
                "REQUEST_METHOD": "GET",
                "HTTP_AUTHORIZATION": token,
            },
            lambda code, _headers: status.setdefault("code", code),
        )
        return status["code"], json.loads(body[0])

    assert request("Bearer wrong")[0] == "401 Unauthorized"
    assert request(f"Bearer {secret}") == (
        "200 OK",
        {"schema": "factory.meta.retention.v1", "deleted": 3},
    )
    monkeypatch.delenv("CRON_SECRET")
    assert request(f"Bearer {secret}")[0] == "401 Unauthorized"


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

    monkeypatch.setattr(
        psycopg, "connect", lambda *_args, **_kwargs: FakePsycopgConnection()
    )
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


def test_clerk_profile_does_not_advertise_or_allow_unprovable_relink(tmp_path):
    config = {
        "FACTORY_META_DATABASE": str(tmp_path / "clerk.sqlite"),
        "FACTORY_META_OIDC_ISSUER": "https://id.example/",
        "FACTORY_META_AUTHORIZATION_URL": "https://id.example/authorize",
        "FACTORY_META_TOKEN_URL": "https://id.example/token",
        "FACTORY_META_OIDC_PROVIDER": "clerk",
        "FACTORY_META_CLERK_CLIENT_ID": "client-id",
        "FACTORY_META_CLERK_CLIENT_SECRET": "client-secret",
        "FACTORY_META_TENANT_ID": "code-factory",
    }
    application = create_meta_connector_app_from_env(config)
    specification = application.openapi()
    assert "/v1/account/relink" not in specification["paths"]
    scopes = specification["components"]["securitySchemes"]["oauth"]["flows"][
        "authorizationCode"
    ]["scopes"]
    assert "cf.audit.link" not in scopes
    status, body, _ = _call(application, "POST", "/v1/account/relink")
    assert status == "501 Not Implemented"
    assert body["error"]["code"] == "RELINK_UNSUPPORTED"
    assert "/v1/account/relink" in _app(tmp_path).openapi()["paths"]


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
        "access-token",
        "https://id.example/oauth/token_info",
        "expected-client",
        "secret",
    )
    assert claims["signature_verified"] is True
    assert claims["scope"] == "cf.audit.read"
    try:
        verify_clerk_oauth_token(
            "access-token",
            "https://id.example/oauth/token_info",
            "other-client",
            "secret",
        )
    except ClerkTokenError:
        pass
    else:
        raise AssertionError("token from another client must be rejected")


@pytest.mark.skipif(
    not os.environ.get("FACTORY_META_TEST_DATABASE"),
    reason="dedicated PostgreSQL integration DSN not configured",
)
def test_postgres_persists_across_instances_and_unlink_removes_rows():
    database = os.environ["FACTORY_META_TEST_DATABASE"]
    assert database.startswith(("postgresql://", "postgres://"))
    subject = f"storage-test-{uuid4()}"
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "signature_verified": True,
        "tenant_id": "code-factory-storage-test",
        "sub": subject,
        "iat": now,
        "exp": now + 600,
        "scope": "cf.audit.read cf.audit.write",
    }

    def make_app():
        return MetaConnectorAPI(
            database,
            lambda _token: claims,
            authorization_url="https://id.example/authorize",
            token_url="https://id.example/token",
        )

    def call(application, method, path, payload=None):
        raw = json.dumps(payload).encode() if payload is not None else b""
        status = {}
        body = application(
            {
                "REQUEST_METHOD": method,
                "PATH_INFO": path,
                "CONTENT_LENGTH": str(len(raw)),
                "wsgi.input": BytesIO(raw),
                "HTTP_AUTHORIZATION": "Bearer storage-test",
            },
            lambda code, _headers: status.setdefault("code", code),
        )
        return status["code"], json.loads(b"".join(body))

    snapshot = {
        "schema": "factory.meta.audit.v1",
        "repository": "zrk222/code-factory",
        "commit_sha": "a" * 40,
        "policy_sha256": "b" * 64,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "outcomes": {
            "code_factory": "PASS",
            "forgeline": "NOT_RUN",
            "appforge": "NOT_RUN",
            "saasforge": "NOT_RUN",
            "full_depth": "INCOMPLETE",
        },
        "findings": [],
        "coverage": ["Storage integration only; no audit execution"],
    }
    first = make_app()
    try:
        status, created = call(first, "POST", "/v1/audits", snapshot)
        assert status == "201 Created", created
        status, listed = call(make_app(), "GET", "/v1/audits")
        assert status == "200 OK" and listed["items"][0]["id"] == created["id"]
    finally:
        status, _body = call(make_app(), "DELETE", "/v1/account")
        assert status == "200 OK"
    status, blocked = call(make_app(), "GET", "/v1/audits")
    assert status == "401 Unauthorized"
    assert blocked["error"]["code"] == "ACCOUNT_REVOKED"

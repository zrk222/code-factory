from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import time
from threading import Thread
from urllib.request import urlopen
from wsgiref.simple_server import make_server

import factoryline.meta_connector_api as meta_connector_api
from factoryline.meta_connector_api import (
    ConnectorError,
    MetaConnectorAPI,
    create_meta_connector_app_from_env,
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

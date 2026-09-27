"""Opt-in integration check against a dedicated disposable connector database."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import json
import os
from uuid import uuid4

import pytest

from factoryline.meta_connector_api import MetaConnectorAPI


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

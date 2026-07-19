from __future__ import annotations

import base64
from io import BytesIO
import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from factoryline.hosted_api import (
    HostedConfig, HostedPRAssuranceService, create_hosted_app, create_hosted_app_from_env,
)
from factoryline.hosted_github import GitHubAppPublisher, publish_check
from factoryline.hosted_identity import JwksCache, get_jwks
from factoryline.hosted_storage import OutboxRecord, SCHEMA_SQL, initialize_schema
from factoryline.pr_assurance import PRAssuranceError


class Response:
    def __init__(self, status_code, value):
        self.status_code = status_code
        self.value = value

    def json(self):
        return self.value


class Transport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, *, headers=None, json=None):
        self.calls.append((method, url, headers or {}, json))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class FakeStore:
    def __init__(self):
        self.decisions = []
        self.outbox = []

    def ping(self):
        return True

    def tenant_for_installation(self, installation_id):
        if installation_id != 4421:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "unknown installation")
        return "tenant-a"

    def ingest(self, tenant_id, event):
        return {
            "markers": ["POSTGRES_RLS_BOUND", "INSTALLATION_TENANT_ROUTED", "HOSTED_INGRESS_TRANSACTIONAL"],
            "tenant_id": tenant_id, "approval_id": "approval-1", "event": event.to_dict(),
        }

    def decide(self, principal, approval_id, **values):
        if principal.subject == "github-app:4421":
            raise PRAssuranceError("E_SELF_APPROVAL", "self approval")
        self.decisions.append((principal, approval_id, values))
        return {
            "markers": ["CHECK_OUTBOX_TRANSACTIONAL", "HOSTED_DECISION_TRANSACTIONAL"], "tenant_id": principal.tenant_id,
            "approval_id": approval_id, "outbox_id": "outbox-1", "status": values["decision"],
        }

    def claim_outbox(self, tenant_id, *, limit=20):
        values, self.outbox = self.outbox, []
        return values

    def mark_published(self, record, check_id):
        return {"marker": "OUTBOX_PUBLISHED", "check_run_id": check_id}

    def mark_failed(self, record, error_code):
        return {"marker": "OUTBOX_PENDING", "error_code": error_code}


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _identity():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwks = {"keys": [{
        "kty": "RSA", "kid": "key-1", "use": "sig", "alg": "RS256",
        "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }]}
    return private, jwks


def _token(private, *, subject="reviewer", jti="jti-1"):
    header = _b64(b'{"alg":"RS256","kid":"key-1"}')
    payload = _b64(json.dumps({
        "iss": "https://id.example", "aud": "factory", "sub": subject,
        "tenant_id": "tenant-a", "groups": ["release"], "jti": jti,
        "nbf": 1_799_999_900, "exp": 1_800_000_300,
    }, separators=(",", ":")).encode())
    signature = private.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64(signature)}"


def _webhook():
    secret = b"hosted-webhook-secret-32-bytes!!"
    body = json.dumps({
        "action": "opened", "number": 7, "repository": {"full_name": "acme/app"},
        "installation": {"id": 4421}, "sender": {"login": "alice"},
        "pull_request": {"number": 7, "head": {"sha": "a" * 40}},
    }, separators=(",", ":")).encode()
    headers = {
        "X-GitHub-Event": "pull_request", "X-GitHub-Delivery": "delivery-1",
        "X-Hub-Signature-256": "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest(),
    }
    return secret, body, headers


def _service(store=None):
    private, jwks = _identity()
    secret, _body, _headers = _webhook()
    return HostedPRAssuranceService(
        store=store or FakeStore(),
        jwks=JwksCache("https://id.example/jwks", Transport([Response(200, jwks)]), clock=lambda: 1_800_000_000),
        publisher=object(),
        config=HostedConfig(
            "https://id.example", "factory", {"release": "approver"},
            {4421: secret}, {4421: "tenant-a"},
        ),
    ), private


def _api_call(app, method, path, *, body=b"", headers=None):
    captured = {}
    environ = {
        "REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body),
    }
    environ.update(headers or {})
    result = b"".join(app(environ, lambda status, values: captured.update(status=status, headers=values)))
    return captured["status"], json.loads(result)


def test_postgres_schema_forces_tenant_rls_and_transactional_outbox_contract():
    assert SCHEMA_SQL.count("FORCE ROW LEVEL SECURITY") == 3
    assert SCHEMA_SQL.count("current_setting('factory.tenant_id', true)") == 6
    assert "approval_id UUID NOT NULL UNIQUE" in SCHEMA_SQL
    assert "attempts BETWEEN 0 AND 25" in SCHEMA_SQL
    class Store:
        initialized = False
        def initialize(self):
            self.initialized = True
    store = Store()
    initialize_schema(store)
    assert store.initialized is True


def test_hosted_environment_contract_requires_matching_installation_maps():
    env = {
        "FACTORY_OIDC_ISSUER": "https://id.example", "FACTORY_OIDC_AUDIENCE": "factory",
        "FACTORY_WEBHOOK_SECRETS_JSON": json.dumps({"4421": "hosted-webhook-secret-32-bytes!!"}),
        "FACTORY_INSTALLATION_TENANTS_JSON": json.dumps({"4421": "tenant-a"}),
        "FACTORY_ROLE_MAP_JSON": json.dumps({"release": "approver"}),
    }
    assert HostedConfig.from_env(env).installation_tenants == {4421: "tenant-a"}
    with pytest.raises(PRAssuranceError) as missing:
        create_hosted_app_from_env({})
    assert missing.value.code == "E_HOSTED_CONFIG"


def test_jwks_cache_refreshes_and_rejects_cache_older_than_hard_limit():
    clock = [1000.0]
    transport = Transport([Response(200, {"keys": [{"kid": "one"}]}), PRAssuranceError("E_HTTP_UNAVAILABLE", "down")])
    cache = JwksCache("https://id.example/jwks", transport, clock=lambda: clock[0])
    assert get_jwks(cache)["keys"][0]["kid"] == "one"
    clock[0] = 1301.0
    assert get_jwks(cache)["keys"][0]["kid"] == "one"
    clock[0] = 1901.0
    with pytest.raises(PRAssuranceError) as stale:
        get_jwks(cache)
    assert stale.value.code == "E_JWKS_UNAVAILABLE"


def test_github_app_publisher_uses_short_lived_credentials_without_returning_them():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    transport = Transport([Response(201, {"token": "installation-secret"}), Response(201, {"id": 991})])
    publisher = GitHubAppPublisher(app_id=17, private_key_pem=pem, transport=transport, clock=lambda: 1_800_000_000)
    check_id = publish_check(publisher, 4421, "acme/app", {"schema": "x", "marker": "y", "name": "check", "head_sha": "a" * 40})
    assert check_id == 991
    assert transport.calls[1][3] == {"name": "check", "head_sha": "a" * 40}
    assert "installation-secret" not in json.dumps({"check_id": check_id})


def test_wsgi_routes_require_bearer_and_never_accept_tenant_headers(monkeypatch):
    service, private = _service()
    app = create_hosted_app(service)
    status, health = _api_call(app, "GET", "/healthz")
    assert status == "200 OK" and health["ok"] is True
    secret, body, headers = _webhook()
    wsgi_headers = {"HTTP_" + key.upper().replace("-", "_"): value for key, value in headers.items()}
    wsgi_headers["HTTP_X_FACTORY_TENANT"] = "tenant-b"
    status, accepted = _api_call(app, "POST", "/v1/github/webhooks", body=body, headers=wsgi_headers)
    assert status == "202 Accepted" and accepted["tenant_id"] == "tenant-a"
    decision_body = json.dumps({"decision": "approved", "reason": "reviewed"}).encode()
    status, denied = _api_call(app, "POST", "/v1/approvals/approval-1/decision", body=decision_body)
    assert status == "401 Unauthorized" and denied["error"]["code"] == "E_AUTH_REQUIRED"
    monkeypatch.setattr("factoryline.hosted_api.verify_oidc_token", lambda *args, **kwargs: {
        "signature_verified": True, "iss": "https://id.example", "aud": "factory", "sub": "reviewer",
        "tenant_id": "tenant-a", "groups": ["release"], "jti": "jti-1", "exp": 1_900_000_000,
    })
    status, decided = _api_call(
        app, "POST", "/v1/approvals/approval-1/decision", body=decision_body,
        headers={"HTTP_AUTHORIZATION": "Bearer " + _token(private)},
    )
    assert status == "202 Accepted"
    assert decided["markers"] == [
        "CHECK_OUTBOX_TRANSACTIONAL", "HOSTED_DECISION_TRANSACTIONAL",
        "JWKS_ROTATION_PINNED", "HOSTED_AUTH_BOUNDARY",
    ]


def test_service_rejects_self_approval_and_dispatch_retains_classified_failure(monkeypatch):
    store = FakeStore()
    service, private = _service(store)
    monkeypatch.setattr("factoryline.hosted_api.verify_oidc_token", lambda *args, **kwargs: {
        "signature_verified": True, "iss": "https://id.example", "aud": "factory", "sub": "github-app:4421",
        "tenant_id": "tenant-a", "groups": ["release"], "jti": "self", "exp": 1_900_000_000,
    })
    with pytest.raises(PRAssuranceError) as self_approval:
        service.decide("approval-1", _token(private), {"decision": "approved", "reason": "mine"})
    assert self_approval.value.code == "E_SELF_APPROVAL"
    store.outbox = [OutboxRecord("o-1", "tenant-a", "a-1", 4421, "acme/app", {"name": "check"}, 1)]
    class Publisher:
        def publish(self, *args):
            raise PRAssuranceError("E_GITHUB_PUBLISH", "failed with installation-secret")
    service.publisher = Publisher()
    assert service.dispatch("tenant-a") == [{"marker": "OUTBOX_PENDING", "error_code": "E_GITHUB_PUBLISH"}]

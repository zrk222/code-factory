from __future__ import annotations

import base64
from contextlib import contextmanager
from io import BytesIO
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from factoryline.control_plane import Principal
from factoryline.hosted_api import HostedConfig, HostedPRAssuranceService, create_hosted_app
from factoryline.hosted_control import (
    CONTROL_SCHEMA_SQL,
    EnvSecretResolver,
    PostgresControlStore,
    TenantIdentityConfig,
    TenantIdentityVerifier,
    initialize_control_schema,
    issue_installation_state,
)
from factoryline.pr_assurance import PRAssuranceError


class Response:
    def __init__(self, value):
        self.status_code = 200
        self.value = value

    def json(self):
        return self.value


class Transport:
    def __init__(self, value):
        self.value = value

    def request(self, method, url, *, headers=None, json=None):
        assert method == "GET" and url == "https://id.acme.test/jwks"
        return Response(self.value)


class IdentityStore:
    def identity_config(self, tenant_id):
        assert tenant_id == "acme"
        return TenantIdentityConfig("acme", "https://id.acme.test", "code-factory", "https://id.acme.test/jwks")

    def role_map(self, tenant_id):
        assert tenant_id == "acme"
        return {"release": "approver"}


def _b64(value: bytes) -> str:
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


def _token(private, *, tenant_id="acme"):
    header = _b64(b'{"alg":"RS256","kid":"key-1"}')
    payload = _b64(json.dumps({
        "iss": "https://id.acme.test", "aud": "code-factory", "sub": "reviewer",
        "tenant_id": tenant_id, "groups": ["release"], "jti": "control-jti",
        "nbf": 1_799_999_900, "exp": 1_900_000_300,
    }, separators=(",", ":")).encode())
    signature = private.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64(signature)}"


def test_control_schema_forces_rls_and_stores_references_and_state_digests_only():
    assert CONTROL_SCHEMA_SQL.count("FORCE ROW LEVEL SECURITY") == 4
    assert CONTROL_SCHEMA_SQL.count("current_setting('factory.tenant_id', true)") == 8
    assert "state_sha256 TEXT PRIMARY KEY" in CONTROL_SCHEMA_SQL
    assert "secret_ref TEXT NOT NULL" in CONTROL_SCHEMA_SQL
    lowered = CONTROL_SCHEMA_SQL.lower()
    assert "secret_value" not in lowered and "bearer_token" not in lowered and "private_key" not in lowered

    class Initializable:
        initialized = False

        def initialize(self):
            self.initialized = True

    wrapped = Initializable()
    initialize_control_schema(wrapped)
    assert wrapped.initialized is True


def test_env_secret_resolver_accepts_only_scoped_references_and_never_returns_reference_text():
    resolver = EnvSecretResolver({"FACTORY_ACME_WEBHOOK": "0123456789abcdef"})
    assert resolver.resolve("env://FACTORY_ACME_WEBHOOK") == b"0123456789abcdef"
    for value in ["plain-text", "env://lower", "vault://secret", "env://MISSING"]:
        with pytest.raises(PRAssuranceError):
            resolver.resolve(value)


def test_dynamic_tenant_identity_uses_hint_only_for_lookup_then_verifies_every_claim(monkeypatch):
    private, jwks = _identity()
    verifier = TenantIdentityVerifier(IdentityStore(), Transport(jwks))
    monkeypatch.setattr("factoryline.pr_assurance.time.time", lambda: 1_800_000_000)
    principal, claims = verifier.verify(_token(private))
    assert principal == Principal("reviewer", "acme", ("approver",))
    assert claims["marker"] == "TENANT_IDENTITY_VERIFIED"
    with pytest.raises(PRAssuranceError) as malformed_hint:
        verifier.verify(_token(private, tenant_id="../other"))
    assert malformed_hint.value.code == "E_TENANT_INVALID"


class FakeAssuranceStore:
    def ping(self):
        return True


class FakeControl:
    def __init__(self):
        self.calls = []
        self.states = set()

    def create_tenant(self, principal, tenant_id, display_name):
        self.calls.append(("tenant", principal, tenant_id, display_name))
        return {"markers": ["TENANT_CREATED", "ADMIN_ACTION_AUDITED"], "tenant_id": tenant_id}

    def configure_identity(self, principal, tenant_id, **values):
        if principal.tenant_id != "*" and principal.tenant_id != tenant_id:
            raise PRAssuranceError("E_TENANT_BOUNDARY", "cross tenant")
        self.calls.append(("identity", tenant_id, values))
        return {"marker": "OIDC_CONFIG_VERIFIED", "tenant_id": tenant_id}

    def replace_roles(self, principal, tenant_id, mappings):
        self.calls.append(("roles", tenant_id, mappings))
        return {"marker": "ROLE_MAPPING_BOUND", "tenant_id": tenant_id}

    def set_secret_reference(self, principal, tenant_id, purpose, reference):
        self.calls.append(("secret", tenant_id, purpose, reference))
        return {"marker": "SECRET_REFERENCE_BOUND", "tenant_id": tenant_id, "purpose": purpose}

    def issue_state(self, principal, tenant_id):
        self.states.add("one-time-state-value-that-is-long-enough")
        return {"marker": "INSTALLATION_STATE_ISSUED", "tenant_id": tenant_id,
                "state": "one-time-state-value-that-is-long-enough"}

    def bind_installation(self, state, installation_id):
        if state not in self.states:
            raise PRAssuranceError("E_INSTALLATION_STATE", "state replay")
        self.states.remove(state)
        return {"marker": "INSTALLATION_BOUND", "tenant_id": "acme", "installation_id": installation_id}

    def overview(self, principal, tenant_id):
        if principal.tenant_id != "*" and principal.tenant_id != tenant_id:
            raise PRAssuranceError("E_TENANT_BOUNDARY", "cross tenant")
        return {
            "markers": ["CONTROL_OVERVIEW_REDACTED"],
            "tenant": {"tenant_id": tenant_id, "display_name": "Acme", "status": "active"},
            "identity_configured": True, "role_counts": {"admin": 1}, "installation_ids": [42],
            "secret_purposes": ["github_webhook"], "outbox_counts": {}, "approval_counts": {},
            "audit": {"valid": True, "events": []},
        }


def _api_call(app, method, path, *, value=None, token="token"):
    captured = {}
    body = b"" if value is None else json.dumps(value).encode()
    environ = {
        "REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": BytesIO(body), "HTTP_AUTHORIZATION": "Bearer " + token,
    }
    response = b"".join(app(environ, lambda status, headers: captured.update(status=status, headers=headers)))
    return captured["status"], json.loads(response)


def _service(control, events):
    return HostedPRAssuranceService(
        store=FakeAssuranceStore(), jwks=object(), publisher=object(),
        config=HostedConfig("https://bootstrap.test", "factory", {"platform": "platform_admin"}, {}, {}),
        control=control, event_sink=events.append,
    )


def test_control_routes_are_authenticated_tenant_bound_replay_safe_and_secret_free(monkeypatch):
    events = []
    control = FakeControl()
    service = _service(control, events)
    platform = Principal("root", "*", ("platform_admin",))
    monkeypatch.setattr(service, "authenticate", lambda _token: (platform, {"iss": "x", "jti": "j"}, None))
    app = create_hosted_app(service)
    assert _api_call(app, "POST", "/v1/admin/tenants", value={"tenant_id": "acme", "display_name": "Acme"})[0] == "201 Created"
    assert _api_call(app, "PUT", "/v1/admin/tenants/acme/identity", value={
        "issuer": "https://id.acme.test", "audience": "factory", "jwks_url": "https://id.acme.test/jwks"
    })[1]["marker"] == "OIDC_CONFIG_VERIFIED"
    assert _api_call(app, "PUT", "/v1/admin/tenants/acme/roles", value={"mappings": {"ops": "admin"}})[1]["marker"] == "ROLE_MAPPING_BOUND"
    assert _api_call(app, "PUT", "/v1/admin/tenants/acme/secrets/github_webhook", value={
        "reference": "env://FACTORY_ACME_WEBHOOK"
    })[1]["marker"] == "SECRET_REFERENCE_BOUND"
    _status, issued = _api_call(app, "POST", "/v1/admin/tenants/acme/installation-state", value={})
    assert service.issue_installation_state("token", "acme")["marker"] == "INSTALLATION_STATE_ISSUED"
    assert issue_installation_state(control, platform, "acme")["marker"] == "INSTALLATION_STATE_ISSUED"
    callback = {"state": issued["state"], "installation_id": 42}
    assert _api_call(app, "POST", "/v1/github/installations/callback", value=callback)[0] == "201 Created"
    replay_status, replay = _api_call(app, "POST", "/v1/github/installations/callback", value=callback)
    assert replay_status == "409 Conflict" and replay["error"]["code"] == "E_INSTALLATION_STATE"
    overview_status, overview = _api_call(app, "GET", "/v1/admin/tenants/acme/overview")
    assert overview_status == "200 OK" and overview["markers"] == ["CONTROL_OVERVIEW_REDACTED"]
    serialized = json.dumps(overview).lower()
    assert all(term not in serialized for term in ["env://", "token", "private_key", "secret_ref"])
    service._emit("admin.test", tenant_id="acme", state="plaintext", reference="env://HIDDEN", token="hidden")
    assert events[-1] == {"schema": "factory.hosted.operation.v1", "operation": "admin.test", "tenant_id": "acme"}

    tenant_admin = Principal("admin", "acme", ("admin",))
    monkeypatch.setattr(service, "authenticate", lambda _token: (tenant_admin, {"iss": "x", "jti": "j2"}, None))
    denied_status, denied = _api_call(app, "PUT", "/v1/admin/tenants/other/identity", value={
        "issuer": "https://id.other.test", "audience": "factory", "jwks_url": "https://id.other.test/jwks"
    })
    assert denied_status == "403 Forbidden" and denied["error"]["code"] == "E_TENANT_BOUNDARY"


def test_secret_reference_lookup_routes_globally_then_reads_inside_tenant_rls():
    class Cursor:
        def __init__(self, row):
            self.row = row

        def execute(self, _sql, _params):
            return None

        def fetchone(self):
            return self.row

    rows = iter([("acme",), ("env://FACTORY_ACME_WEBHOOK",)])
    store = object.__new__(PostgresControlStore)

    @contextmanager
    def transaction(_tenant_id=None):
        yield object(), Cursor(next(rows))

    store._transaction = transaction
    assert store.secret_reference_for_installation(42, "github_webhook") == (
        "acme", "env://FACTORY_ACME_WEBHOOK"
    )


def test_control_console_route_sets_no_store_and_security_headers(monkeypatch):
    console = Path("factoryline/hosted_console.html").read_text(encoding="utf-8")
    service = _service(FakeControl(), [])
    service.console_html = console
    captured = {}
    response = b"".join(create_hosted_app(service)(
        {"REQUEST_METHOD": "GET", "PATH_INFO": "/console", "CONTENT_LENGTH": "0", "wsgi.input": BytesIO()},
        lambda status, headers: captured.update(status=status, headers=dict(headers)),
    ))
    assert captured["status"] == "200 OK"
    assert captured["headers"]["Cache-Control"] == "no-store"
    assert "Content-Security-Policy" in captured["headers"]
    assert b"CONTROL_CONSOLE_READ_ONLY" in response


def test_bootstrap_fallback_accepts_only_platform_admin_with_star_tenant(monkeypatch):
    class MissingTenantIdentity:
        def verify(self, _token):
            raise PRAssuranceError("E_TENANT_INVALID", "bootstrap hint")

    service = _service(FakeControl(), [])
    service.tenant_identity = MissingTenantIdentity()
    monkeypatch.setattr("factoryline.hosted_api.get_jwks", lambda _cache: {"keys": [{}]})
    monkeypatch.setattr("factoryline.hosted_api.verify_oidc_token", lambda *args, **kwargs: {
        "signature_verified": True, "iss": "https://bootstrap.test", "aud": "factory", "sub": "root",
        "tenant_id": "acme", "groups": ["platform"], "jti": "bootstrap", "exp": 1_900_000_000,
    })
    monkeypatch.setattr("factoryline.hosted_api.principal_from_verified_oidc", lambda *args, **kwargs: Principal(
        "root", "acme", ("platform_admin",)
    ))
    with pytest.raises(PRAssuranceError) as denied:
        service.authenticate("bootstrap-token")
    assert denied.value.code == "E_TENANT_BOUNDARY"
    monkeypatch.setattr("factoryline.hosted_api.principal_from_verified_oidc", lambda *args, **kwargs: Principal(
        "root", "*", ("platform_admin",)
    ))
    principal, _claims, marker = service.authenticate("bootstrap-token")
    assert principal.tenant_id == "*" and marker is None

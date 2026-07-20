"""Authenticated WSGI and worker adapter for hosted PR assurance."""
from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import json
import os
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urlsplit

from .hosted_github import GitHubAppPublisher
from .hosted_control import EnvSecretResolver, PostgresControlStore, TenantIdentityVerifier
from .hosted_identity import HttpxTransport, JwksCache, get_jwks
from .hosted_storage import PostgresAssuranceStore
from .integrations import principal_from_verified_oidc
from .pr_assurance import MAX_WEBHOOK_BYTES, PRAssuranceError, verify_github_webhook, verify_oidc_token


DECISION_BODY_MAX = 65_536


def _configured_maps(env: Mapping[str, str]) -> tuple[dict[int, bytes], dict[int, str], dict[str, str]]:
    try:
        raw_secrets = json.loads(env.get("FACTORY_WEBHOOK_SECRETS_JSON", "{}"))
        raw_tenants = json.loads(env.get("FACTORY_INSTALLATION_TENANTS_JSON", "{}"))
        raw_roles = json.loads(env.get("FACTORY_ROLE_MAP_JSON", '{"release-approvers":"approver"}'))
        secrets = {int(key): str(value).encode("utf-8") for key, value in raw_secrets.items()}
        tenants = {int(key): str(value) for key, value in raw_tenants.items()}
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PRAssuranceError("E_HOSTED_CONFIG", "hosted installation configuration is invalid") from exc
    if not isinstance(raw_roles, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in raw_roles.items()):
        raise PRAssuranceError("E_HOSTED_CONFIG", "role map must be a string mapping")
    return secrets, tenants, raw_roles


def _identity_config(env: Mapping[str, str]) -> tuple[str, str]:
    try:
        return env["FACTORY_OIDC_ISSUER"], env["FACTORY_OIDC_AUDIENCE"]
    except KeyError as exc:
        raise PRAssuranceError("E_HOSTED_CONFIG", "hosted identity configuration is invalid") from exc


def _validate_installation_maps(secrets: dict[int, bytes], tenants: dict[int, str]) -> None:
    if any(key <= 0 or len(value) < 16 for key, value in secrets.items()):
        raise PRAssuranceError("E_HOSTED_CONFIG", "each installation requires a secret of at least 16 bytes")
    if secrets.keys() != tenants.keys() or any(not tenant.strip() for tenant in tenants.values()):
        raise PRAssuranceError("E_HOSTED_CONFIG", "installation tenant and secret keys must match")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _finish(start_response: Callable, status: str, value: Any) -> list[bytes]:
    body = _json_bytes(value)
    start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
    return [body]


def _finish_html(start_response: Callable, value: str) -> list[bytes]:
    body = value.encode("utf-8")
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Content-Type-Options", "nosniff"),
        ],
    )
    return [body]


def _read_body(environ: Mapping[str, Any], maximum: int) -> bytes:
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError as exc:
        raise PRAssuranceError("E_HTTP_BODY", "Content-Length must be an integer") from exc
    if length < 1 or length > maximum:
        raise PRAssuranceError("E_HTTP_BODY", f"request body must contain 1-{maximum} bytes")
    value = environ.get("wsgi.input")
    if value is None:
        raise PRAssuranceError("E_HTTP_BODY", "request body stream is required")
    body = value.read(length)
    if len(body) != length:
        raise PRAssuranceError("E_HTTP_BODY", "request body ended before Content-Length")
    return body


def _json_body(environ: Mapping[str, Any]) -> dict[str, Any]:
    try:
        value = json.loads(_read_body(environ, DECISION_BODY_MAX))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PRAssuranceError("E_HTTP_JSON", "request body must be UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise PRAssuranceError("E_HTTP_JSON", "request JSON must be an object")
    return value


def _installation_id(body: bytes) -> int:
    try:
        value = json.loads(body)
        installation_id = (value.get("installation") or {}).get("id") if isinstance(value, dict) else None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", "webhook routing body is invalid JSON") from exc
    if not isinstance(installation_id, int) or isinstance(installation_id, bool) or installation_id <= 0:
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", "installation.id is required for secure routing")
    return installation_id


def _bearer(environ: Mapping[str, Any]) -> str:
    authorization = str(environ.get("HTTP_AUTHORIZATION", ""))
    if not authorization.startswith("Bearer ") or len(authorization) <= 7:
        raise PRAssuranceError("E_AUTH_REQUIRED", "decision route requires a Bearer token")
    return authorization[7:]


@dataclass(frozen=True)
class HostedConfig:
    """Secret-bearing hosted configuration loaded by the deployment boundary."""

    issuer: str
    audience: str
    role_map: dict[str, str]
    webhook_secrets: dict[int, bytes]
    installation_tenants: dict[int, str]

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "HostedConfig":
        """Load required hosted identity and webhook configuration or fail closed."""
        env = dict(os.environ if environ is None else environ)
        issuer, audience = _identity_config(env)
        secrets, tenants, raw_roles = _configured_maps(env)
        _validate_installation_maps(secrets, tenants)
        return cls(
            issuer=issuer, audience=audience, role_map=raw_roles,
            webhook_secrets=secrets, installation_tenants=tenants,
        )


class HostedPRAssuranceService:
    """Compose PostgreSQL, OIDC, webhook, outbox, and publisher authority safely."""

    def __init__(
        self,
        *,
        store: PostgresAssuranceStore,
        jwks: JwksCache,
        publisher: GitHubAppPublisher,
        config: HostedConfig,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        control: PostgresControlStore | None = None,
        tenant_identity: TenantIdentityVerifier | None = None,
        secret_resolver: EnvSecretResolver | None = None,
        console_html: str = "",
    ):
        self.store = store
        self.jwks = jwks
        self.publisher = publisher
        self.config = config
        self.event_sink = event_sink or (lambda _event: None)
        self.control = control
        self.tenant_identity = tenant_identity
        self.secret_resolver = secret_resolver
        self.console_html = console_html

    def _emit(self, operation: str, **fields: Any) -> None:
        allowed = {key: value for key, value in fields.items() if key in {
            "tenant_id", "installation_id", "repository", "approval_id", "outbox_id", "status", "error_code"
        }}
        self.event_sink({"schema": "factory.hosted.operation.v1", "operation": operation, **allowed})

    def health(self) -> dict[str, Any]:
        """Return a process-liveness response without probing dependencies."""
        return {"schema": "factory.hosted.health.v1", "ok": True}

    def ready(self) -> dict[str, Any]:
        """Return ready only when PostgreSQL and a usable JWKS are available."""
        if not self.store.ping():
            raise PRAssuranceError("E_DATABASE_UNAVAILABLE", "PostgreSQL readiness failed")
        get_jwks(self.jwks)
        return {"schema": "factory.hosted.readiness.v1", "ready": True, "marker": "JWKS_ROTATION_PINNED"}

    def ingest(self, body: bytes, headers: Mapping[str, str]) -> dict[str, Any]:
        """Route by installation, verify HMAC, and commit one tenant PR request."""
        installation_id = _installation_id(body)
        tenant_id = self.store.tenant_for_installation(installation_id)
        dynamic = False
        secret = None
        if self.control is not None and self.secret_resolver is not None:
            try:
                configured_tenant, reference = self.control.secret_reference_for_installation(
                    installation_id, "github_webhook"
                )
                if configured_tenant != tenant_id:
                    raise PRAssuranceError("E_TENANT_BOUNDARY", "installation secret tenant differs from route")
                secret = self.secret_resolver.resolve(reference)
                dynamic = True
            except PRAssuranceError as exc:
                if installation_id not in self.config.webhook_secrets:
                    raise exc
        secret = secret or self.config.webhook_secrets.get(installation_id)
        if secret is None:
            raise PRAssuranceError("E_SECRET_UNAVAILABLE", "installation webhook secret is unavailable")
        event = verify_github_webhook(body, headers, secret)
        result = self.store.ingest(tenant_id, event)
        result["markers"].append("HOSTED_AUTH_BOUNDARY")
        if dynamic:
            result["markers"].append("DYNAMIC_WEBHOOK_SECRET_BOUND")
        self._emit("webhook.accepted", tenant_id=tenant_id, installation_id=installation_id, repository=event.repository,
                   approval_id=result["approval_id"], status="pending")
        return result

    def decide(self, approval_id: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
        """Verify OIDC identity and atomically queue one terminal GitHub Check."""
        principal, claims, identity_marker = self.authenticate(token)
        result = self.store.decide(
            principal, approval_id, issuer=claims["iss"], jti=claims["jti"],
            decision=str(body.get("decision", "")), reason=str(body.get("reason", "")),
        )
        result["markers"].extend(["JWKS_ROTATION_PINNED", "HOSTED_AUTH_BOUNDARY"])
        if identity_marker:
            result["markers"].append(identity_marker)
        self._emit("approval.decided", tenant_id=principal.tenant_id, approval_id=approval_id,
                   outbox_id=result["outbox_id"], status=result["status"])
        return result

    def authenticate(self, token: str) -> tuple[Any, dict[str, Any], str | None]:
        """Verify a dynamic tenant or bootstrap OIDC token and return its principal."""
        bootstrap_only = False
        if self.tenant_identity is not None:
            try:
                principal, claims = self.tenant_identity.verify(token)
                return principal, claims, "TENANT_IDENTITY_VERIFIED"
            except PRAssuranceError as exc:
                if exc.code != "E_TENANT_INVALID":
                    raise
                bootstrap_only = True
        jwks = get_jwks(self.jwks)
        claims = verify_oidc_token(token, jwks, self.config.issuer, self.config.audience)
        principal = principal_from_verified_oidc(
            claims, expected_issuer=self.config.issuer, role_map=self.config.role_map
        )
        if bootstrap_only and not (
            principal.tenant_id == "*" and "platform_admin" in principal.roles
        ):
            raise PRAssuranceError("E_TENANT_BOUNDARY", "bootstrap identity requires platform_admin tenant authority")
        return principal, claims, None

    def create_tenant(self, token: str, body: dict[str, Any]) -> dict[str, Any]:
        """Create one tenant through verified bootstrap authority or refuse the request."""
        if self.control is None:
            raise PRAssuranceError("E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable")
        principal, _claims, _marker = self.authenticate(token)
        return self.control.create_tenant(principal, str(body.get("tenant_id", "")), str(body.get("display_name", "")))

    def configure_identity(self, token: str, tenant_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Store one tenant's public OIDC verification configuration or refuse it."""
        if self.control is None:
            raise PRAssuranceError("E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable")
        principal, _claims, _marker = self.authenticate(token)
        return self.control.configure_identity(
            principal,
            tenant_id,
            issuer=str(body.get("issuer", "")),
            audience=str(body.get("audience", "")),
            jwks_url=str(body.get("jwks_url", "")),
        )

    def replace_roles(self, token: str, tenant_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Replace one tenant role map through verified administrative authority."""
        if self.control is None:
            raise PRAssuranceError("E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable")
        principal, _claims, _marker = self.authenticate(token)
        mappings = body.get("mappings")
        if not isinstance(mappings, dict):
            raise PRAssuranceError("E_ROLE_MAPPING", "mappings must be a JSON object")
        return self.control.replace_roles(principal, tenant_id, mappings)

    def set_secret_reference(
        self, token: str, tenant_id: str, purpose: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """Store a secret-manager reference through verified administrative authority."""
        if self.control is None:
            raise PRAssuranceError("E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable")
        principal, _claims, _marker = self.authenticate(token)
        return self.control.set_secret_reference(principal, tenant_id, purpose, str(body.get("reference", "")))

    def issue_installation_state(self, token: str, tenant_id: str) -> dict[str, Any]:
        """Issue one tenant-bound GitHub installation state or refuse the request."""
        if self.control is None:
            raise PRAssuranceError("E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable")
        principal, _claims, _marker = self.authenticate(token)
        return self.control.issue_state(principal, tenant_id)

    def bind_installation(self, body: dict[str, Any]) -> dict[str, Any]:
        """Consume one installation callback state or reject replay and reassignment."""
        if self.control is None:
            raise PRAssuranceError("E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable")
        installation_id = body.get("installation_id")
        if not isinstance(installation_id, int) or isinstance(installation_id, bool):
            raise PRAssuranceError("E_INSTALLATION_STATE", "positive installation_id is required")
        return self.control.bind_installation(str(body.get("state", "")), installation_id)

    def overview(self, token: str, tenant_id: str) -> dict[str, Any]:
        """Return one redacted tenant overview through verified read authority."""
        if self.control is None:
            raise PRAssuranceError("E_CONTROL_UNAVAILABLE", "hosted control plane is unavailable")
        principal, _claims, _marker = self.authenticate(token)
        return self.control.overview(principal, tenant_id)

    def dispatch(self, tenant_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Dispatch one bounded tenant outbox batch and retain classified failures."""
        results: list[dict[str, Any]] = []
        for record in self.store.claim_outbox(tenant_id, limit=limit):
            try:
                check_id = self.publisher.publish(record.installation_id, record.repository, record.request)
                outcome = self.store.mark_published(record, check_id)
                self._emit("check.published", tenant_id=tenant_id, outbox_id=record.outbox_id, status="published")
            except PRAssuranceError as exc:
                outcome = self.store.mark_failed(record, exc.code)
                self._emit("check.failed", tenant_id=tenant_id, outbox_id=record.outbox_id,
                           status=outcome["marker"], error_code=exc.code)
            results.append(outcome)
        return results


class HostedPRAssuranceAPI:
    """WSGI surface exposing assurance and supervised hosted control routes."""

    def __init__(self, service: HostedPRAssuranceService):
        self.service = service

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = [unquote(part) for part in urlsplit(str(environ.get("PATH_INFO", "/"))).path.split("/") if part]
        try:
            if method == "GET" and path == ["healthz"]:
                return _finish(start_response, "200 OK", self.service.health())
            if method == "GET" and path == ["readyz"]:
                return _finish(start_response, "200 OK", self.service.ready())
            if method == "GET" and path == ["console"]:
                if not self.service.console_html:
                    raise PRAssuranceError("E_NOT_FOUND", "operator console is unavailable")
                return _finish_html(start_response, self.service.console_html)
            if method == "POST" and path == ["v1", "github", "webhooks"]:
                body = _read_body(environ, MAX_WEBHOOK_BYTES)
                headers = {
                    "X-Hub-Signature-256": str(environ.get("HTTP_X_HUB_SIGNATURE_256", "")),
                    "X-GitHub-Event": str(environ.get("HTTP_X_GITHUB_EVENT", "")),
                    "X-GitHub-Delivery": str(environ.get("HTTP_X_GITHUB_DELIVERY", "")),
                }
                return _finish(start_response, "202 Accepted", self.service.ingest(body, headers))
            if method == "POST" and len(path) == 4 and path[:2] == ["v1", "approvals"] and path[3] == "decision":
                return _finish(start_response, "202 Accepted", self.service.decide(path[2], _bearer(environ), _json_body(environ)))
            if method == "POST" and path == ["v1", "github", "installations", "callback"]:
                return _finish(start_response, "201 Created", self.service.bind_installation(_json_body(environ)))
            if method == "POST" and path == ["v1", "admin", "tenants"]:
                return _finish(start_response, "201 Created", self.service.create_tenant(_bearer(environ), _json_body(environ)))
            if len(path) >= 4 and path[:3] == ["v1", "admin", "tenants"]:
                tenant_id = path[3]
                if method == "PUT" and len(path) == 5 and path[4] == "identity":
                    return _finish(start_response, "200 OK", self.service.configure_identity(_bearer(environ), tenant_id, _json_body(environ)))
                if method == "PUT" and len(path) == 5 and path[4] == "roles":
                    return _finish(start_response, "200 OK", self.service.replace_roles(_bearer(environ), tenant_id, _json_body(environ)))
                if method == "PUT" and len(path) == 6 and path[4] == "secrets":
                    return _finish(start_response, "200 OK", self.service.set_secret_reference(
                        _bearer(environ), tenant_id, path[5], _json_body(environ)
                    ))
                if method == "POST" and len(path) == 5 and path[4] == "installation-state":
                    return _finish(start_response, "201 Created", self.service.issue_installation_state(
                        _bearer(environ), tenant_id
                    ))
                if method == "GET" and len(path) == 5 and path[4] == "overview":
                    return _finish(start_response, "200 OK", self.service.overview(_bearer(environ), tenant_id))
            raise PRAssuranceError("E_NOT_FOUND", "hosted route not found")
        except PRAssuranceError as exc:
            status = _status_for(exc.code)
            self.service._emit("request.rejected", error_code=exc.code, status=status.split()[0])
            return _finish(start_response, status, {
                "schema": "factory.hosted.result.v1", "verdict": "ERROR",
                "error": {"code": exc.code, "message": exc.message},
            })


def _status_for(code: str) -> str:
    if code == "E_NOT_FOUND":
        return "404 Not Found"
    if code in {"E_AUTH_REQUIRED", "E_OIDC_SIGNATURE", "E_OIDC_EXPIRED"}:
        return "401 Unauthorized"
    if code in {"E_ACTION_DENIED", "E_TENANT_BOUNDARY", "E_SELF_APPROVAL"}:
        return "403 Forbidden"
    if code in {"E_WEBHOOK_REPLAY", "E_ALREADY_DECIDED", "E_OIDC_REPLAY"}:
        return "409 Conflict"
    if code in {"E_INSTALLATION_STATE", "E_INSTALLATION_TENANT", "E_TENANT_CONFLICT"}:
        return "409 Conflict"
    if code.startswith("E_DATABASE") or code.startswith("E_JWKS"):
        return "503 Service Unavailable"
    if code == "E_CONTROL_UNAVAILABLE":
        return "503 Service Unavailable"
    return "400 Bad Request"


def create_hosted_app(service: HostedPRAssuranceService) -> HostedPRAssuranceAPI:
    """Create the authenticated WSGI surface without caller-controlled tenants."""
    return HostedPRAssuranceAPI(service)


def create_hosted_app_from_env(environ: Mapping[str, str] | None = None) -> HostedPRAssuranceAPI:
    """Construct the production adapter from secret-bearing environment configuration."""
    env = dict(os.environ if environ is None else environ)
    required = ("FACTORY_DATABASE_URL", "FACTORY_JWKS_URL", "FACTORY_GITHUB_APP_ID", "FACTORY_GITHUB_PRIVATE_KEY")
    if any(not env.get(name) for name in required):
        raise PRAssuranceError("E_HOSTED_CONFIG", "database, JWKS, and GitHub App configuration are required")
    config = HostedConfig.from_env(env)
    transport = HttpxTransport()
    store = PostgresAssuranceStore(env["FACTORY_DATABASE_URL"])
    store.initialize()
    control = PostgresControlStore(store)
    control.initialize()
    for installation_id, tenant_id in config.installation_tenants.items():
        store.register_installation(tenant_id, installation_id)
    service = HostedPRAssuranceService(
        store=store,
        jwks=JwksCache(env["FACTORY_JWKS_URL"], transport),
        publisher=GitHubAppPublisher(
            app_id=int(env["FACTORY_GITHUB_APP_ID"]),
            private_key_pem=env["FACTORY_GITHUB_PRIVATE_KEY"].replace("\\n", "\n"),
            transport=transport,
        ),
        config=config,
        control=control,
        tenant_identity=TenantIdentityVerifier(control, transport),
        secret_resolver=EnvSecretResolver(env),
        console_html=resources.files("factoryline").joinpath("hosted_console.html").read_text(encoding="utf-8"),
    )
    return create_hosted_app(service)

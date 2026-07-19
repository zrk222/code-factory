"""Authenticated WSGI and worker adapter for hosted PR assurance."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any, Callable, Mapping
from urllib.parse import unquote, urlsplit

from .hosted_github import GitHubAppPublisher
from .hosted_identity import HttpxTransport, JwksCache, get_jwks
from .hosted_storage import PostgresAssuranceStore
from .integrations import principal_from_verified_oidc
from .pr_assurance import MAX_WEBHOOK_BYTES, PRAssuranceError, verify_github_webhook, verify_oidc_token


DECISION_BODY_MAX = 65_536


def _configured_maps(env: Mapping[str, str]) -> tuple[dict[int, bytes], dict[int, str], dict[str, str]]:
    try:
        raw_secrets = json.loads(env["FACTORY_WEBHOOK_SECRETS_JSON"])
        raw_tenants = json.loads(env["FACTORY_INSTALLATION_TENANTS_JSON"])
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
    if not secrets or any(key <= 0 or len(value) < 16 for key, value in secrets.items()):
        raise PRAssuranceError("E_HOSTED_CONFIG", "each installation requires a secret of at least 16 bytes")
    if secrets.keys() != tenants.keys() or any(not tenant.strip() for tenant in tenants.values()):
        raise PRAssuranceError("E_HOSTED_CONFIG", "installation tenant and secret keys must match")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _finish(start_response: Callable, status: str, value: Any) -> list[bytes]:
    body = _json_bytes(value)
    start_response(status, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
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
    ):
        self.store = store
        self.jwks = jwks
        self.publisher = publisher
        self.config = config
        self.event_sink = event_sink or (lambda _event: None)

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
        secret = self.config.webhook_secrets.get(installation_id)
        if secret is None:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "installation has no configured webhook secret")
        tenant_id = self.store.tenant_for_installation(installation_id)
        event = verify_github_webhook(body, headers, secret)
        result = self.store.ingest(tenant_id, event)
        result["markers"].append("HOSTED_AUTH_BOUNDARY")
        self._emit("webhook.accepted", tenant_id=tenant_id, installation_id=installation_id, repository=event.repository,
                   approval_id=result["approval_id"], status="pending")
        return result

    def decide(self, approval_id: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
        """Verify OIDC identity and atomically queue one terminal GitHub Check."""
        jwks = get_jwks(self.jwks)
        claims = verify_oidc_token(token, jwks, self.config.issuer, self.config.audience)
        principal = principal_from_verified_oidc(
            claims, expected_issuer=self.config.issuer, role_map=self.config.role_map
        )
        result = self.store.decide(
            principal, approval_id, issuer=self.config.issuer, jti=claims["jti"],
            decision=str(body.get("decision", "")), reason=str(body.get("reason", "")),
        )
        result["markers"].extend(["JWKS_ROTATION_PINNED", "HOSTED_AUTH_BOUNDARY"])
        self._emit("approval.decided", tenant_id=principal.tenant_id, approval_id=approval_id,
                   outbox_id=result["outbox_id"], status=result["status"])
        return result

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
    """WSGI surface exposing only health, readiness, webhook, and decision routes."""

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
    if code.startswith("E_DATABASE") or code.startswith("E_JWKS"):
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
    )
    return create_hosted_app(service)

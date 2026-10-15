"""Provider-neutral identity and SCM claim adapters.

These adapters normalize already-verified claims into the control-plane
contract. They intentionally do not verify JWTs or webhook signatures; doing
that requires provider-specific key discovery and deployment configuration.
Failing closed when the caller omits a verification marker prevents a raw
webhook or unsigned header from becoming an authority decision.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.request
import base64
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, urlencode, urlsplit

from .control_plane import ControlPlaneError, Principal, canonical_json


SUPPORTED_SCM_PROVIDERS = frozenset({"github", "gitlab", "azure_devops"})


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ControlPlaneError(
            "E_IDENTITY_CLAIM", f"verified claim {name} is required"
        )
    return value.strip()


def roles_from_groups(
    groups: Iterable[str], role_map: dict[str, str]
) -> tuple[str, ...]:
    """Map verified directory groups to a sorted, deduplicated role tuple."""
    roles = {
        role_map[group]
        for group in groups
        if group in role_map and role_map[group].strip()
    }
    if not roles:
        raise ControlPlaneError(
            "E_NO_ROLE", "verified identity has no mapped factory role"
        )
    return tuple(sorted(roles))


def principal_from_verified_oidc(
    claims: dict[str, Any],
    *,
    expected_issuer: str,
    role_map: dict[str, str],
) -> Principal:
    """Build a tenant principal from already verified OIDC claims, failing closed."""
    if claims.get("signature_verified") is not True:
        raise ControlPlaneError(
            "E_UNVERIFIED_IDENTITY", "OIDC claims must be verified before authorization"
        )
    issuer = _required(claims.get("iss"), "iss")
    if issuer != expected_issuer:
        raise ControlPlaneError("E_IDENTITY_ISSUER", "OIDC issuer is not trusted")
    tenant_id = _required(claims.get("tenant_id"), "tenant_id")
    subject = _required(claims.get("sub"), "sub")
    groups = claims.get("groups", [])
    if not isinstance(groups, list) or not all(
        isinstance(group, str) for group in groups
    ):
        raise ControlPlaneError("E_IDENTITY_CLAIM", "groups must be a list of strings")
    return Principal(
        subject=subject, tenant_id=tenant_id, roles=roles_from_groups(groups, role_map)
    )


@dataclass(frozen=True)
class SCMEvent:
    schema: str
    provider: str
    tenant_id: str
    delivery_id: str
    event_type: str
    repository: str
    change_id: str
    actor: str
    payload_sha256: str

    def to_dict(self) -> dict[str, str]:
        """Return the normalized SCM event as a stable serializable dictionary."""
        return self.__dict__.copy()


def normalize_scm_event(
    provider: str,
    claims: dict[str, Any],
    *,
    tenant_id: str,
    actor_roles: Iterable[str],
) -> tuple[SCMEvent, Principal]:
    """Normalize a supported SCM webhook and its actor or reject unsafe claims."""
    provider = provider.strip().lower()
    _validate_scm_provider(provider)
    payload = _verified_scm_payload(claims)
    delivery_id, event_type = _event_header(claims)
    repository, actor, change = _provider_identity(provider, payload)
    change_id = _required(str(change) if change is not None else "", "change_id")
    tenant_id = _required(tenant_id, "tenant_id")
    roles = _mapped_roles(actor_roles)
    event = _scm_event(
        provider,
        tenant_id,
        delivery_id,
        event_type,
        repository,
        change_id,
        actor,
        payload,
    )
    principal = Principal(
        subject=f"scm:{provider}:{actor}", tenant_id=tenant_id, roles=roles
    )
    return event, principal


def _validate_scm_provider(provider: str) -> None:
    if provider not in SUPPORTED_SCM_PROVIDERS:
        raise ControlPlaneError(
            "E_SCM_PROVIDER", f"unsupported SCM provider: {provider}"
        )


def _verified_scm_payload(claims: dict[str, Any]) -> dict[str, Any]:
    if claims.get("signature_verified") is not True:
        raise ControlPlaneError(
            "E_UNVERIFIED_WEBHOOK",
            "SCM claims must be signature-verified before normalization",
        )
    payload = claims.get("payload")
    if not isinstance(payload, dict):
        raise ControlPlaneError(
            "E_SCM_PAYLOAD", "verified SCM payload must be an object"
        )
    return payload


def _event_header(claims: dict[str, Any]) -> tuple[str, str]:
    delivery_id = _required(claims.get("delivery_id"), "delivery_id")
    event_type = _required(claims.get("event_type"), "event_type")
    return delivery_id, event_type


def _github_identity(payload: dict[str, Any]) -> tuple[str, str, Any]:
    repository = _required(
        (payload.get("repository") or {}).get("full_name"), "repository.full_name"
    )
    actor = _required((payload.get("sender") or {}).get("login"), "sender.login")
    change = (
        (payload.get("pull_request") or {}).get("number")
        or payload.get("after")
        or payload.get("ref")
    )
    return repository, actor, change


def _gitlab_identity(payload: dict[str, Any]) -> tuple[str, str, Any]:
    repository = _required(
        (payload.get("project") or {}).get("path_with_namespace"),
        "project.path_with_namespace",
    )
    actor = _required(payload.get("user_username"), "user_username")
    change = (payload.get("object_attributes") or {}).get("iid") or payload.get(
        "checkout_sha"
    )
    return repository, actor, change


def _azure_identity(payload: dict[str, Any]) -> tuple[str, str, Any]:
    resource = payload.get("resource") or {}
    repository = _required(
        (resource.get("repository") or {}).get("name"), "resource.repository.name"
    )
    actor = _required(
        (resource.get("createdBy") or {}).get("id"), "resource.createdBy.id"
    )
    change = (
        resource.get("pullRequestId")
        or resource.get("sourceRefName")
        or payload.get("id")
    )
    return repository, actor, change


def _provider_identity(provider: str, payload: dict[str, Any]) -> tuple[str, str, Any]:
    if provider == "github":
        return _github_identity(payload)
    if provider == "gitlab":
        return _gitlab_identity(payload)
    return _azure_identity(payload)


def _mapped_roles(actor_roles: Iterable[str]) -> tuple[str, ...]:
    roles = tuple(sorted({role.strip() for role in actor_roles if role.strip()}))
    if not roles:
        raise ControlPlaneError("E_NO_ROLE", "SCM actor has no mapped factory role")
    return roles


def _scm_event(
    provider: str,
    tenant_id: str,
    delivery_id: str,
    event_type: str,
    repository: str,
    change_id: str,
    actor: str,
    payload: dict[str, Any],
) -> SCMEvent:
    return SCMEvent(
        schema="factory.scm.event.v1",
        provider=provider,
        tenant_id=tenant_id,
        delivery_id=delivery_id,
        event_type=event_type,
        repository=repository,
        change_id=change_id,
        actor=actor,
        payload_sha256=hashlib.sha256(canonical_json(payload)).hexdigest(),
    )


def event_json(event: SCMEvent) -> bytes:
    """Serialize an SCM event into deterministic canonical JSON bytes."""
    return canonical_json(event.to_dict())


# Explicit ticket operations share the existing workflow audit, not another runner.
_ISSUE_LIMIT = 1_048_576
_LINEAR_REDIRECT = "http://127.0.0.1:8767/linear/callback"
_LINEAR_AUTHORIZE = "https://linear.app/oauth/authorize"
_LINEAR_TOKEN_URL = "https://api.linear.app/oauth/token"
_LINEAR_REVOKE = "https://api.linear.app/oauth/revoke"
_LINEAR_VAULT = "factoryline-linear-oauth-v1"
_LINEAR_SCOPES = ("read", "comments:create")
_LINEAR_TOKEN_CONTEXT: ContextVar[str | None] = ContextVar(
    "factoryline_linear_oauth_token", default=None
)
_LINEAR_OAUTH_SESSIONS: dict[str, dict[str, Any]] = {}
_LINEAR_OAUTH_LOCK = threading.RLock()


class IssueIntegrationError(ValueError):
    """Safe refusal which never includes provider response bodies or credentials."""


def _issue_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _issue_text(value: object, maximum: int = 32768) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise IssueIntegrationError("ISSUE_INPUT_INVALID: missing or oversized text")
    return value


def _issue_target(provider: str, issue: str, site: str) -> str:
    if provider not in {"linear", "jira"}:
        raise IssueIntegrationError("ISSUE_PROVIDER_UNSUPPORTED")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,30}-[1-9][0-9]{0,12}", issue):
        raise IssueIntegrationError("ISSUE_IDENTIFIER_INVALID: use a project issue key")
    if provider == "linear":
        if site:
            raise IssueIntegrationError("ISSUE_SITE_INVALID: Linear uses its fixed API")
        return "https://api.linear.app/graphql"
    if not re.fullmatch(r"https://[a-z0-9][a-z0-9-]{0,61}\.atlassian\.net", site):
        raise IssueIntegrationError("ISSUE_SITE_INVALID: use an HTTPS Jira Cloud site")
    return site


class _IssueNoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Reject redirects so provider credentials cannot cross origins."""
        raise IssueIntegrationError("ISSUE_REDIRECT_REJECTED")


def _issue_opener():
    try:
        import truststore
    except ImportError:
        context = ssl.create_default_context()
    else:
        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    return urllib.request.build_opener(
        _IssueNoRedirect(), urllib.request.HTTPSHandler(context=context)
    )


def _issue_credentials(provider: str, *, token: str | None = None) -> str:
    if provider == "linear":
        selected = token or _LINEAR_TOKEN_CONTEXT.get()
        token = selected or os.environ.get("FACTORY_LINEAR_TOKEN", "")
        mode = "oauth" if selected else os.environ.get("FACTORY_LINEAR_AUTH", "api-key")
        if mode not in {"api-key", "oauth"}:
            raise IssueIntegrationError("ISSUE_AUTH_MODE_INVALID")
        result = ("Bearer " if selected or mode == "oauth" else "") + token
    else:
        token = os.environ.get("FACTORY_JIRA_TOKEN", "")
        email = (
            ""
            if _LINEAR_TOKEN_CONTEXT.get()
            else os.environ.get("FACTORY_JIRA_EMAIL", "")
        )
        if not email or any(c in email for c in "\r\n:"):
            raise IssueIntegrationError(
                "ISSUE_CREDENTIALS_MISSING: set Jira email privately"
            )
        result = "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()
    if not token or len(token) > 4096 or any(c.isspace() for c in token):
        raise IssueIntegrationError(
            "ISSUE_CREDENTIALS_MISSING: configure token privately"
        )
    return result


def _issue_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise IssueIntegrationError("ISSUE_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _issue_request(
    provider, issue, site, method, suffix="", payload=None, *, token=None
):
    base = _issue_target(provider, issue, site)
    url = base if provider == "linear" else f"{base}/rest/api/3/issue/{issue}{suffix}"
    data = canonical_json(payload) if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": _issue_credentials(provider, token=token),
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with _issue_opener().open(request, timeout=20) as response:
            raw = response.read(_ISSUE_LIMIT + 1)
        if len(raw) > _ISSUE_LIMIT:
            raise IssueIntegrationError("ISSUE_RESPONSE_TOO_LARGE")
        value = json.loads(raw, object_pairs_hook=_issue_pairs)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        if isinstance(exc, IssueIntegrationError):
            raise
        raise IssueIntegrationError(
            "ISSUE_PROVIDER_FAILED: response unavailable or invalid"
        ) from None
    if not isinstance(value, dict) or value.get("errors"):
        raise IssueIntegrationError(
            "ISSUE_PROVIDER_FAILED: incomplete provider response"
        )
    return value


def _issue_graphql(issue, query, variables, *, token=None):
    value = _issue_request(
        "linear",
        issue,
        "",
        "POST",
        payload={
            "query": query,
            "variables": variables,
        },
        token=token,
    ).get("data", {})
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_PROVIDER_FAILED: missing GraphQL data")
    return value


def _linear_alias(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value
    ):
        raise IssueIntegrationError("LINEAR_CONNECTION_INVALID")
    return value


def _linear_secure_keyring():
    try:
        import keyring

        backend = keyring.get_keyring()
    except Exception:
        raise IssueIntegrationError("LINEAR_SECURE_VAULT_UNAVAILABLE") from None
    safe = {
        ("keyring.backends.Windows", "WinVaultKeyring"),
        ("keyring.backends.macOS", "Keyring"),
        ("keyring.backends.SecretService", "Keyring"),
        ("keyring.backends.kwallet", "DBusKeyring"),
        ("keyring.backends.kwallet", "DBusKeyringKWallet4"),
        ("keyring.backends.libsecret", "Keyring"),
    }
    kind = (type(backend).__module__, type(backend).__name__)
    if kind in safe:
        return keyring, backend
    if kind == ("keyring.backends.chainer", "ChainerBackend"):
        backends = getattr(backend, "backends", ())
        if backends and all(
            (type(item).__module__, type(item).__name__) in safe for item in backends
        ):
            return keyring, backend
    raise IssueIntegrationError("LINEAR_SECURE_VAULT_UNAVAILABLE")


def _linear_vault_get(connection: str) -> dict[str, Any] | None:
    _, backend = _linear_secure_keyring()
    try:
        raw = backend.get_password(_LINEAR_VAULT, connection)
        value = json.loads(raw) if raw is not None else None
    except Exception:
        raise IssueIntegrationError("LINEAR_SECURE_VAULT_UNAVAILABLE") from None
    if value is None:
        return None
    required = set(
        "schema client_id access_token refresh_token expires_at viewer_id organization_id".split()
    )
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != "factory.linear-oauth-connection.v1"
        or not all(
            isinstance(value.get(name), str) and value[name]
            for name in required - {"expires_at", "schema"}
        )
        or type(value.get("expires_at")) not in {int, float}
    ):
        raise IssueIntegrationError("LINEAR_SECURE_VAULT_INVALID")
    return value


def _linear_vault_set(connection: str, value: dict[str, Any]) -> None:
    keyring, backend = _linear_secure_keyring()
    try:
        backend.set_password(
            _LINEAR_VAULT,
            connection,
            json.dumps(value, sort_keys=True, separators=(",", ":")),
        )
    except Exception:
        raise IssueIntegrationError("LINEAR_SECURE_VAULT_UNAVAILABLE") from None


def _linear_vault_delete(connection: str) -> None:
    keyring, backend = _linear_secure_keyring()
    try:
        backend.delete_password(_LINEAR_VAULT, connection)
    except Exception:
        raise IssueIntegrationError("LINEAR_SECURE_VAULT_UNAVAILABLE") from None


@contextmanager
def _linear_connection_lock(connection: str):
    alias = _linear_alias(connection)
    root = Path.home().resolve()
    relative = (
        Path(".cache/code-factory/linear")
        / f"{hashlib.sha256(alias.encode()).hexdigest()}.lock"
    )
    target = _issue_local(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = _issue_local(root, relative)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
        if os.name == "nt":
            import msvcrt

            if not os.fstat(descriptor).st_size:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, ImportError):
        if "descriptor" in locals():
            os.close(descriptor)
        raise IssueIntegrationError("LINEAR_CONNECTION_BUSY") from None
    with os.fdopen(descriptor, "r+b"):
        yield


def _linear_http_form(
    url: str, values: dict[str, str], *, revoke=False
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=urlencode(values).encode("ascii"),
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with _issue_opener().open(request, timeout=20) as response:
            status, raw = response.status, response.read(_ISSUE_LIMIT + 1)
    except Exception:
        raise IssueIntegrationError("LINEAR_OAUTH_PROVIDER_FAILED") from None
    if len(raw) > _ISSUE_LIMIT or status != 200:
        raise IssueIntegrationError("LINEAR_OAUTH_PROVIDER_FAILED")
    if revoke:
        return {}
    try:
        value = json.loads(raw, object_pairs_hook=_issue_pairs)
    except (ValueError, TypeError):
        raise IssueIntegrationError("LINEAR_OAUTH_RESPONSE_INVALID") from None
    if not isinstance(value, dict) or value.get("error"):
        raise IssueIntegrationError("LINEAR_OAUTH_RESPONSE_INVALID")
    return value


def _linear_tokens(value: dict[str, Any], *, previous=None) -> dict[str, Any]:
    access, refresh = value.get("access_token"), value.get("refresh_token")
    expires = value.get("expires_in")
    scope = value.get("scope")
    if isinstance(scope, str):
        scope = scope.replace(",", " ").split()
    if (
        not isinstance(access, str)
        or not access
        or not isinstance(refresh, str)
        or not refresh
        or type(expires) is not int
        or not 1 <= expires <= 31 * 86400
        or not isinstance(scope, list)
        or not all(isinstance(item, str) for item in scope)
        or len(scope) != len(_LINEAR_SCOPES)
        or set(scope) != set(_LINEAR_SCOPES)
    ):
        raise IssueIntegrationError("LINEAR_OAUTH_RESPONSE_INVALID")
    return {
        "schema": "factory.linear-oauth-connection.v1",
        "client_id": previous["client_id"] if previous else value.get("client_id", ""),
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": int(time.time()) + expires,
        "viewer_id": previous["viewer_id"] if previous else "",
        "organization_id": previous["organization_id"] if previous else "",
    }


def _linear_viewer(token: str) -> tuple[str, str]:
    value = _issue_graphql(
        "CF-1",
        "query CFConnectionViewer { viewer { id organization { id } } }",
        {},
        token=token,
    ).get("viewer")
    try:
        viewer = _issue_text(value["id"], 128)
        organization = _issue_text(value["organization"]["id"], 128)
    except (KeyError, TypeError, IssueIntegrationError):
        raise IssueIntegrationError("LINEAR_IDENTITY_UNVERIFIED")
    return viewer, organization


def begin_linear_oauth(client_id: str) -> dict[str, Any]:
    """Create a ten-minute, single-use PKCE authorization request."""
    if not isinstance(client_id, str) or not client_id.strip() or len(client_id) > 256:
        raise IssueIntegrationError("LINEAR_CLIENT_ID_INVALID")
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    expires_at = int(time.time()) + 600
    session = {
        "state": state,
        "verifier": verifier,
        "client_id": client_id.strip(),
        "expires_at": expires_at,
    }
    query = urlencode(
        {
            "response_type": "code",
            "client_id": session["client_id"],
            "redirect_uri": _LINEAR_REDIRECT,
            "scope": ",".join(_LINEAR_SCOPES),
            "actor": "user",
            "prompt": "consent",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    with _LINEAR_OAUTH_LOCK:
        _LINEAR_OAUTH_SESSIONS[state] = session.copy()
    return {**session, "authorization_url": f"{_LINEAR_AUTHORIZE}?{query}"}


def complete_linear_oauth(
    session: dict[str, Any], callback_url: str, connection: str
) -> dict[str, Any]:
    """Verify the loopback callback, then pin its verified Linear identity."""
    alias = _linear_alias(connection)
    state, expected = _linear_pending_session(session)
    code = _linear_callback_code(callback_url, expected)
    with _LINEAR_OAUTH_LOCK:
        if _LINEAR_OAUTH_SESSIONS.get(state) != expected:
            raise IssueIntegrationError("LINEAR_OAUTH_SESSION_INVALID")
        _LINEAR_OAUTH_SESSIONS.pop(state)
    session.clear()
    return _linear_connect(alias, expected, code)


def _linear_pending_session(session):
    state = session.get("state") if isinstance(session, dict) else None
    if not isinstance(state, str):
        raise IssueIntegrationError("LINEAR_OAUTH_SESSION_INVALID")
    with _LINEAR_OAUTH_LOCK:
        expected = _LINEAR_OAUTH_SESSIONS.get(state)
    if expected is None or any(
        session.get(key) != expected.get(key) for key in expected
    ):
        raise IssueIntegrationError("LINEAR_OAUTH_SESSION_INVALID")
    if expected["expires_at"] <= int(time.time()):
        with _LINEAR_OAUTH_LOCK:
            if _LINEAR_OAUTH_SESSIONS.get(state) == expected:
                _LINEAR_OAUTH_SESSIONS.pop(state, None)
        session.clear()
        raise IssueIntegrationError("LINEAR_OAUTH_SESSION_EXPIRED")
    return state, expected


def _linear_callback_code(callback_url, expected):
    try:
        parts = urlsplit(callback_url)
        query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True)
    except (ValueError, TypeError):
        raise IssueIntegrationError("LINEAR_OAUTH_CALLBACK_INVALID") from None
    if (
        parts.scheme != "http"
        or parts.netloc != "127.0.0.1:8767"
        or parts.path != "/linear/callback"
        or parts.fragment
        or set(query) != {"state", "code"}
        or any(len(items) != 1 or not items[0] for items in query.values())
        or not hmac.compare_digest(
            query["state"][0].encode(), expected["state"].encode()
        )
        or len(query["code"][0]) > 4096
    ):
        raise IssueIntegrationError("LINEAR_OAUTH_CALLBACK_INVALID")
    return query["code"][0]


def _linear_connect(alias, expected, code):
    with _linear_connection_lock(alias):
        if _linear_vault_get(alias) is not None:
            raise IssueIntegrationError("LINEAR_CONNECTION_EXISTS")
        tokens = _linear_http_form(
            _LINEAR_TOKEN_URL,
            {
                "grant_type": "authorization_code",
                "client_id": expected["client_id"],
                "code": code,
                "redirect_uri": _LINEAR_REDIRECT,
                "code_verifier": expected["verifier"],
            },
        )
        record = _linear_tokens(tokens)
        record["client_id"] = expected["client_id"]
        record["viewer_id"], record["organization_id"] = _linear_viewer(
            record["access_token"]
        )
        _linear_vault_set(alias, record)
        return {
            "connection": alias,
            "viewer_id": record["viewer_id"],
            "organization_id": record["organization_id"],
            "expires_at": record["expires_at"],
            "state": "CONNECTED",
        }


def cancel_linear_oauth(session: dict[str, Any]) -> None:
    """Discard one pending PKCE verifier when the loopback flow is abandoned."""
    state = session.get("state") if isinstance(session, dict) else None
    if isinstance(state, str):
        with _LINEAR_OAUTH_LOCK:
            expected = _LINEAR_OAUTH_SESSIONS.get(state)
            if expected and all(
                session.get(key) == value for key, value in expected.items()
            ):
                _LINEAR_OAUTH_SESSIONS.pop(state, None)
    if isinstance(session, dict):
        session.clear()


def linear_connection_status(connection: str) -> dict[str, Any]:
    """Return connection state and pinned identity without exposing tokens."""
    alias = _linear_alias(connection)
    record = _linear_vault_get(alias)
    if record is None:
        return {"connection": alias, "state": "NOT_CONNECTED"}
    return {
        "connection": alias,
        "state": "EXPIRED" if record["expires_at"] <= int(time.time()) else "CONNECTED",
        "viewer_id": record["viewer_id"],
        "organization_id": record["organization_id"],
        "expires_at": record["expires_at"],
    }


def _linear_refresh(connection: str, record: dict[str, Any]) -> dict[str, Any]:
    tokens = _linear_http_form(
        _LINEAR_TOKEN_URL,
        {
            "grant_type": "refresh_token",
            "client_id": record["client_id"],
            "refresh_token": record["refresh_token"],
        },
    )
    refreshed = _linear_tokens(tokens, previous=record)
    viewer, organization = _linear_viewer(refreshed["access_token"])
    if (viewer, organization) != (record["viewer_id"], record["organization_id"]):
        raise IssueIntegrationError("LINEAR_IDENTITY_CHANGED")
    _linear_vault_set(connection, refreshed)
    return refreshed


@contextmanager
def use_linear_connection(connection: str):
    """Bind a verified alias token to the current operation context."""
    alias = _linear_alias(connection)
    with _linear_connection_lock(alias):
        record = _linear_vault_get(alias)
        if record is None:
            raise IssueIntegrationError("LINEAR_CONNECTION_MISSING")
        refreshed = record["expires_at"] <= int(time.time()) + 60
        if refreshed:
            record = _linear_refresh(alias, record)
        viewer, organization = (record["viewer_id"], record["organization_id"])
        if not refreshed:
            viewer, organization = _linear_viewer(record["access_token"])
            if (viewer, organization) != (
                record["viewer_id"],
                record["organization_id"],
            ):
                raise IssueIntegrationError("LINEAR_IDENTITY_CHANGED")
    token = _LINEAR_TOKEN_CONTEXT.set(record["access_token"])
    try:
        yield {
            "connection": alias,
            "viewer_id": viewer,
            "organization_id": organization,
        }
    finally:
        _LINEAR_TOKEN_CONTEXT.reset(token)


def disconnect_linear_connection(connection: str) -> dict[str, Any]:
    """Revoke provider credentials before removing the secure local record."""
    alias = _linear_alias(connection)
    with _linear_connection_lock(alias):
        record = _linear_vault_get(alias)
        if record is None:
            return {"connection": alias, "state": "DISCONNECTED"}
        _linear_http_form(
            _LINEAR_REVOKE,
            {"token": record["refresh_token"], "token_type_hint": "refresh_token"},
            revoke=True,
        )
        _linear_vault_delete(alias)
        return {"connection": alias, "state": "DISCONNECTED", "revocation": "CONFIRMED"}


def _issue_object(value):
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_PROVIDER_FAILED: expected an object")
    return value


def _issue_description(value):
    """Flatten Jira ADF text without interpreting links, commands or rich objects."""
    if value is None:
        return ""
    if isinstance(value, str):
        return _issue_text(value)
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_DESCRIPTION_INVALID")
    stack, texts, count = [(value, 0)], [], 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > 4096 or depth > 32 or not isinstance(node, dict):
            raise IssueIntegrationError("ISSUE_DESCRIPTION_TOO_COMPLEX")
        if "text" in node:
            texts.append(_issue_text(node["text"]))
        content = node.get("content", [])
        if not isinstance(content, list):
            raise IssueIntegrationError("ISSUE_DESCRIPTION_INVALID")
        stack.extend((child, depth + 1) for child in reversed(content))
    return _issue_text("\n".join(texts)) if texts else ""


def _issue_fetch(provider, issue, site):
    _issue_target(provider, issue, site)
    if provider == "linear":
        value = _issue_graphql(
            issue,
            "query CFImport($id: String!) { issue(id: $id) { id identifier title description updatedAt } }",
            {"id": issue},
        ).get("issue")
        if not isinstance(value, dict) or value.get("identifier") != issue:
            raise IssueIntegrationError("ISSUE_IDENTITY_MISMATCH")
        return {
            "key": issue,
            "id": _issue_text(value.get("id"), 128),
            "title": _issue_text(value.get("title"), 512),
            "description": _issue_description(value.get("description")),
            "updated": _issue_text(value.get("updatedAt"), 128),
        }
    value = _issue_request(
        provider, issue, site, "GET", "?fields=summary,description,updated"
    )
    if value.get("key") != issue or not isinstance(value.get("fields"), dict):
        raise IssueIntegrationError("ISSUE_IDENTITY_MISMATCH")
    fields = value["fields"]
    return {
        "key": issue,
        "id": _issue_text(value.get("id"), 128),
        "title": _issue_text(fields.get("summary"), 512),
        "description": _issue_description(fields.get("description")),
        "updated": _issue_text(fields.get("updated"), 128),
    }


def _issue_local(root, path):
    root, value = Path(root).resolve(), Path(path)
    if value.is_absolute() or ".." in value.parts:
        raise IssueIntegrationError("ISSUE_PATH_REJECTED")
    target = root / value
    for parent in [target, *target.parents]:
        if parent == root:
            break
        if parent.is_symlink() or (
            parent.exists() and getattr(parent.lstat(), "st_file_attributes", 0) & 1024
        ):
            raise IssueIntegrationError("ISSUE_PATH_REJECTED")
    try:
        target.resolve().relative_to(root)
    except ValueError:
        raise IssueIntegrationError("ISSUE_PATH_REJECTED") from None
    return target


def _issue_load(root, path, with_hash=False):
    with _issue_local(root, path).open("rb") as handle:
        raw = handle.read(_ISSUE_LIMIT + 1)
    if len(raw) > _ISSUE_LIMIT:
        raise IssueIntegrationError("ISSUE_INPUT_TOO_LARGE")
    value = json.loads(raw, object_pairs_hook=_issue_pairs)
    if not isinstance(value, dict):
        raise IssueIntegrationError("ISSUE_INPUT_INVALID")
    return (value, hashlib.sha256(raw).hexdigest()) if with_hash else value


def _issue_save(root, body, label):
    digest = _issue_digest(body)
    result = {**body, "sha256": digest}
    encoded = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if len(encoded.encode("utf-8")) > _ISSUE_LIMIT:
        raise IssueIntegrationError("ISSUE_OUTPUT_TOO_LARGE")
    relative = f".factory/issues/{label}-{digest}.json"
    target = _issue_local(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("x", encoding="utf-8") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        if _issue_load(root, relative) != result:
            raise IssueIntegrationError("ISSUE_LOCAL_CONFLICT") from None
    return {**result, "path": relative}


def _issue_sealed(root, path, schema):
    value = _issue_load(root, path)
    core = {k: v for k, v in value.items() if k != "sha256"}
    if value.get("schema") != schema or value.get("sha256") != _issue_digest(core):
        raise IssueIntegrationError("ISSUE_BINDING_INVALID")
    return value


def import_issue(
    root: Path, provider: str, issue: str, *, site="", criteria=()
) -> dict:
    """Fetch one explicit issue; preserve untrusted text and operator requirements locally."""
    requirements = [_issue_text(item, 2048) for item in criteria]
    if len(requirements) > 64 or len(set(requirements)) != len(requirements):
        raise IssueIntegrationError("ISSUE_REQUIREMENTS_INVALID")
    return _issue_save(
        root,
        {
            "schema": "factory.issue-import.v1",
            "provider": provider,
            "site": site,
            "issue": _issue_fetch(provider, issue, site),
            "criteria": requirements,
            "content_trust": "UNTRUSTED_DATA",
            "execution": "NOT_RUN",
            "review_required": True,
        },
        "import",
    )


def _issue_draft(root, imported, contract, observations):
    from .workflow_audit import audit_workflows

    packet = _issue_sealed(root, imported, "factory.issue-import.v1")
    catalog, contract_hash = _issue_load(root, contract, with_hash=True)
    observations_value, observations_hash = _issue_load(
        root, observations, with_hash=True
    )
    receipt = audit_workflows(Path(root), contract, observations)
    if (contract_hash, observations_hash) != (
        receipt["contract_sha256"],
        receipt["observations_sha256"],
    ):
        raise IssueIntegrationError("ISSUE_EVIDENCE_CHANGED_DURING_REVIEW")
    requirements = [row["requirement"] for row in catalog.get("checks", [])]
    if not packet.get("criteria") or set(packet["criteria"]) != set(requirements):
        raise IssueIntegrationError(
            "ISSUE_REQUIREMENTS_UNMAPPED: review all ticket criteria"
        )
    observed = observations_value["observations"]
    bindings = [
        {
            "criterion": criterion,
            "checks": [
                {
                    "id": check["id"],
                    "profiles": check["profiles"],
                    "observations": [
                        {key: row[key] for key in ("profile", "status", "artifacts")}
                        for row in observed
                        if row["id"] == check["id"]
                    ],
                }
                for check in catalog["checks"]
                if check["requirement"] == criterion
            ],
        }
        for criterion in packet["criteria"]
    ]
    core = {
        "schema": "factory.issue-draft.v1",
        "import_path": imported,
        "import_sha256": packet["sha256"],
        "contract_path": contract,
        "observations_path": observations,
        "provider": packet["provider"],
        "site": packet["site"],
        "issue": packet["issue"]["key"],
        "issue_id": packet["issue"]["id"],
        "issue_updated": packet["issue"]["updated"],
        "workflow_receipt_sha256": receipt["receipt_sha256"],
        "candidate_sha256": receipt["candidate_sha256"],
        "declared_criteria_bindings": bindings,
        "criteria_assessment": "DECLARED_COVERAGE_NOT_SEMANTIC_VERIFICATION",
        "state": receipt["state"],
        "checks": receipt["checks"],
    }
    marker = _issue_digest(core)
    core["body"] = (
        f"Code Factory evidence update [cf-evidence:{marker}]\n"
        f"Workflow evidence: {receipt['state']}; declared checks: {receipt['checks']}.\n"
        f"Candidate: {receipt['candidate_sha256']}\n"
        f"Receipt: {receipt['receipt_sha256']}\n"
        "Criteria mapping is declared coverage, not semantic verification. "
        "This verifies recorded evidence completeness and hashes only. "
        "It does not certify software, approve release, or close this issue."
    )
    core["review_required"] = True
    return core


def draft_issue_update(
    root: Path, imported: str, contract: str, observations: str
) -> dict:
    """Prepare a source-current metadata-only comment from the existing workflow audit."""
    return _issue_save(
        root, _issue_draft(root, imported, contract, observations), "draft"
    )


def _issue_comments(provider, issue, site):
    if provider == "linear":
        issue_value = _issue_object(
            _issue_graphql(
                issue,
                "query CFDedup($id: String!) { issue(id: $id) { comments(first: 100) { nodes { id body } pageInfo { hasNextPage } } } }",
                {"id": issue},
            ).get("issue")
        )
        value = _issue_object(issue_value.get("comments"))
        if _issue_object(value.get("pageInfo")).get("hasNextPage") is not False:
            raise IssueIntegrationError("ISSUE_HISTORY_INCOMPLETE")
        rows = value.get("nodes")
    else:
        value = _issue_request(provider, issue, site, "GET", "/comment?maxResults=100")
        rows = value.get("comments")
        if (
            not isinstance(rows, list)
            or type(value.get("total")) is not int
            or value["total"] != len(rows)
        ):
            raise IssueIntegrationError("ISSUE_HISTORY_INCOMPLETE")
    if not isinstance(rows, list) or len(rows) > 100:
        raise IssueIntegrationError("ISSUE_HISTORY_INCOMPLETE")
    return [
        {
            "id": _issue_text(_issue_object(row).get("id"), 128),
            "body": _issue_description(row.get("body")),
        }
        for row in rows
    ]


def _issue_post(provider, issue, site, body, remote_id):
    if provider == "linear":
        value = _issue_object(
            _issue_graphql(
                issue,
                "mutation CFComment($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id body } } }",
                {"input": {"issueId": remote_id, "body": body}},
            ).get("commentCreate")
        )
        if value.get("success") is not True:
            raise IssueIntegrationError("ISSUE_DELIVERY_UNKNOWN")
        return _issue_object(value.get("comment")).get("id")
    adf = {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [{"type": "text", "text": body}]}],
    }
    return _issue_request(provider, issue, site, "POST", "/comment", {"body": adf}).get(
        "id"
    )


def _issue_existing(rows, body):
    marker = body.splitlines()[0]
    matches = [row for row in rows if marker in row["body"]]
    if len(matches) > 1 or any(row["body"] != body for row in matches):
        raise IssueIntegrationError("ISSUE_REMOTE_CONFLICT")
    return matches[0]["id"] if matches else None


def publish_issue_update(root: Path, draft: str, confirmation: str) -> dict:
    """Send one exact confirmed comment; uncertain prior deliveries are never resent."""
    value = _issue_sealed(root, draft, "factory.issue-draft.v1")
    if confirmation != f"publish:{value['sha256']}":
        raise IssueIntegrationError(
            "ISSUE_CONFIRMATION_REQUIRED: approve exact draft digest"
        )
    current = _issue_draft(
        root, value["import_path"], value["contract_path"], value["observations_path"]
    )
    if _issue_digest(current) != value["sha256"]:
        raise IssueIntegrationError("ISSUE_DRAFT_STALE")
    provider, issue, site = value["provider"], value["issue"], value["site"]
    remote = _issue_fetch(provider, issue, site)
    if remote["id"] != value["issue_id"]:
        raise IssueIntegrationError("ISSUE_IDENTITY_MISMATCH")
    comment = _issue_existing(_issue_comments(provider, issue, site), value["body"])
    confirmation_record = _issue_save(
        root,
        {
            "schema": "factory.issue-confirmation.v1",
            "draft_sha256": value["sha256"],
            "candidate_sha256": value["candidate_sha256"],
            "provider": provider,
            "site": site,
            "issue": issue,
            "body_sha256": _issue_digest(value["body"]),
            "basis": "EXPLICIT_OPERATOR_CONFIRMATION_UNAUTHENTICATED",
            "scope": "COMMENT_ONLY",
        },
        "confirmation",
    )
    if comment is None:
        if remote["updated"] != value["issue_updated"]:
            raise IssueIntegrationError(
                "ISSUE_REMOTE_STALE: import changed requirements again"
            )
        attempt = _issue_local(root, f".factory/issues/attempt-{value['sha256']}.json")
        try:
            with attempt.open("x", encoding="utf-8") as output:
                output.write(
                    json.dumps({"draft_sha256": value["sha256"], "state": "RESERVED"})
                )
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            raise IssueIntegrationError(
                "ISSUE_DELIVERY_UNKNOWN: reconcile prior attempt before retry"
            ) from None
        comment = _issue_text(
            _issue_post(provider, issue, site, value["body"], remote["id"]), 128
        )
        if (
            _issue_existing(_issue_comments(provider, issue, site), value["body"])
            != comment
        ):
            raise IssueIntegrationError(
                "ISSUE_DELIVERY_UNKNOWN: comment readback not confirmed"
            )
    return _issue_save(
        root,
        {
            "schema": "factory.issue-delivery.v1",
            "draft_sha256": value["sha256"],
            "provider": provider,
            "issue": issue,
            "comment_id": comment,
            "confirmation_sha256": confirmation_record["sha256"],
            "state": "COMMENT_VERIFIED",
            "issue_closed": False,
            "release_approved": False,
        },
        "delivery",
    )

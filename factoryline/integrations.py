"""Provider-neutral identity and SCM claim adapters.

These adapters normalize already-verified claims into the control-plane
contract. They intentionally do not verify JWTs or webhook signatures; doing
that requires provider-specific key discovery and deployment configuration.
Failing closed when the caller omits a verification marker prevents a raw
webhook or unsigned header from becoming an authority decision.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable

from .control_plane import ControlPlaneError, Principal, canonical_json


SUPPORTED_SCM_PROVIDERS = frozenset({"github", "gitlab", "azure_devops"})


def _required(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ControlPlaneError("E_IDENTITY_CLAIM", f"verified claim {name} is required")
    return value.strip()


def roles_from_groups(groups: Iterable[str], role_map: dict[str, str]) -> tuple[str, ...]:
    """Map verified directory groups to a sorted, deduplicated role tuple."""
    roles = {role_map[group] for group in groups if group in role_map and role_map[group].strip()}
    if not roles:
        raise ControlPlaneError("E_NO_ROLE", "verified identity has no mapped factory role")
    return tuple(sorted(roles))


def principal_from_verified_oidc(
    claims: dict[str, Any],
    *,
    expected_issuer: str,
    role_map: dict[str, str],
) -> Principal:
    """Build a tenant principal from already verified OIDC claims, failing closed."""
    if claims.get("signature_verified") is not True:
        raise ControlPlaneError("E_UNVERIFIED_IDENTITY", "OIDC claims must be verified before authorization")
    issuer = _required(claims.get("iss"), "iss")
    if issuer != expected_issuer:
        raise ControlPlaneError("E_IDENTITY_ISSUER", "OIDC issuer is not trusted")
    tenant_id = _required(claims.get("tenant_id"), "tenant_id")
    subject = _required(claims.get("sub"), "sub")
    groups = claims.get("groups", [])
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        raise ControlPlaneError("E_IDENTITY_CLAIM", "groups must be a list of strings")
    return Principal(subject=subject, tenant_id=tenant_id, roles=roles_from_groups(groups, role_map))


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
    if provider not in SUPPORTED_SCM_PROVIDERS:
        raise ControlPlaneError("E_SCM_PROVIDER", f"unsupported SCM provider: {provider}")
    if claims.get("signature_verified") is not True:
        raise ControlPlaneError("E_UNVERIFIED_WEBHOOK", "SCM claims must be signature-verified before normalization")
    payload = claims.get("payload")
    if not isinstance(payload, dict):
        raise ControlPlaneError("E_SCM_PAYLOAD", "verified SCM payload must be an object")
    delivery_id = _required(claims.get("delivery_id"), "delivery_id")
    event_type = _required(claims.get("event_type"), "event_type")
    if provider == "github":
        repository = _required((payload.get("repository") or {}).get("full_name"), "repository.full_name")
        actor = _required((payload.get("sender") or {}).get("login"), "sender.login")
        change = (payload.get("pull_request") or {}).get("number") or payload.get("after") or payload.get("ref")
    elif provider == "gitlab":
        repository = _required((payload.get("project") or {}).get("path_with_namespace"), "project.path_with_namespace")
        actor = _required(payload.get("user_username"), "user_username")
        change = (payload.get("object_attributes") or {}).get("iid") or payload.get("checkout_sha")
    else:
        resource = payload.get("resource") or {}
        repository = _required((resource.get("repository") or {}).get("name"), "resource.repository.name")
        actor = _required((resource.get("createdBy") or {}).get("id"), "resource.createdBy.id")
        change = resource.get("pullRequestId") or resource.get("sourceRefName") or payload.get("id")
    change_id = _required(str(change) if change is not None else "", "change_id")
    tenant_id = _required(tenant_id, "tenant_id")
    roles = tuple(sorted({role.strip() for role in actor_roles if role.strip()}))
    if not roles:
        raise ControlPlaneError("E_NO_ROLE", "SCM actor has no mapped factory role")
    event = SCMEvent(
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
    return event, Principal(subject=f"scm:{provider}:{actor}", tenant_id=tenant_id, roles=roles)


def event_json(event: SCMEvent) -> bytes:
    """Serialize an SCM event into deterministic canonical JSON bytes."""
    return canonical_json(event.to_dict())


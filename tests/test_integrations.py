from __future__ import annotations

import pytest

from factoryline.control_plane import ControlPlaneError
from factoryline.integrations import normalize_scm_event, principal_from_verified_oidc


def test_oidc_claims_require_verified_trusted_identity():
    claims = {"signature_verified": True, "iss": "https://issuer.example", "sub": "u-1", "tenant_id": "acme", "groups": ["release"]}
    principal = principal_from_verified_oidc(claims, expected_issuer="https://issuer.example", role_map={"release": "approver"})
    assert principal.subject == "u-1"
    assert principal.roles == ("approver",)
    with pytest.raises(ControlPlaneError) as error:
        principal_from_verified_oidc({**claims, "signature_verified": False}, expected_issuer="https://issuer.example", role_map={"release": "approver"})
    assert error.value.code == "E_UNVERIFIED_IDENTITY"


def test_unmapped_group_does_not_get_default_access():
    claims = {"signature_verified": True, "iss": "https://issuer.example", "sub": "u-1", "tenant_id": "acme", "groups": ["unknown"]}
    with pytest.raises(ControlPlaneError) as error:
        principal_from_verified_oidc(claims, expected_issuer="https://issuer.example", role_map={"release": "approver"})
    assert error.value.code == "E_NO_ROLE"


@pytest.mark.parametrize("provider,payload", [
    ("github", {"repository": {"full_name": "acme/app"}, "sender": {"login": "alice"}, "pull_request": {"number": 12}}),
    ("gitlab", {"project": {"path_with_namespace": "acme/app"}, "user_username": "alice", "object_attributes": {"iid": 12}}),
    ("azure_devops", {"resource": {"repository": {"name": "app"}, "createdBy": {"id": "alice"}, "pullRequestId": 12}}),
])
def test_scm_events_normalize_without_trusting_raw_payload(provider, payload):
    event, principal = normalize_scm_event(
        provider,
        {"signature_verified": True, "delivery_id": "delivery-1", "event_type": "pull_request", "payload": payload},
        tenant_id="acme",
        actor_roles=["operator"],
    )
    assert event.provider == provider
    assert event.change_id == "12"
    assert principal.subject.startswith(f"scm:{provider}:")


def test_scm_event_rejects_unverified_webhook():
    with pytest.raises(ControlPlaneError) as error:
        normalize_scm_event("github", {"signature_verified": False, "payload": {}}, tenant_id="acme", actor_roles=["operator"])
    assert error.value.code == "E_UNVERIFIED_WEBHOOK"


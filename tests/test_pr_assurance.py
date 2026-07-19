from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from factoryline.control_plane import ControlPlaneError, Principal
from factoryline.pr_assurance import (
    PRAssuranceError,
    PRAssuranceStore,
    decide_pull_request,
    github_check_request,
    ingest_pull_request,
    verify_github_webhook,
    verify_oidc_token,
)


NOW = 1_800_000_000
ISSUER = "https://id.example.test"
AUDIENCE = "code-factory"
SECRET = b"a-test-webhook-secret-with-32-bytes"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _identity():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwks = {
        "keys": [{
            "kty": "RSA", "kid": "key-1", "use": "sig", "alg": "RS256",
            "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }]
    }
    return private, jwks


def _token(private, *, subject="reviewer", tenant="tenant-a", audience=AUDIENCE, jti="token-1", groups=None):
    header = _b64(json.dumps({"alg": "RS256", "kid": "key-1", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps({
        "iss": ISSUER, "aud": audience, "sub": subject, "tenant_id": tenant,
        "groups": groups or ["release-approvers"], "jti": jti,
        "iat": NOW - 5, "nbf": NOW - 5, "exp": NOW + 300,
    }, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64(signature)}"


def _webhook(*, delivery="delivery-1", action="opened", actor="alice"):
    body = json.dumps({
        "action": action,
        "number": 17,
        "repository": {"full_name": "acme/payments"},
        "installation": {"id": 4421},
        "sender": {"login": actor},
        "pull_request": {"number": 17, "head": {"sha": "a" * 40}},
    }, separators=(",", ":")).encode()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest(),
    }
    return body, headers


def _ingest(store, *, delivery="delivery-1", actor="alice"):
    store.register_installation("tenant-a", 4421)
    body, headers = _webhook(delivery=delivery, actor=actor)
    return ingest_pull_request(store, body, headers, SECRET, "tenant-a")


def _decide(store, approval_id, token, jwks, *, tenant="tenant-a", decision="approved"):
    return decide_pull_request(
        store, approval_id, token, jwks, ISSUER, AUDIENCE,
        tenant_id=tenant, role_map={"release-approvers": "approver"},
        decision=decision, reason="independent review complete", now=NOW,
    )


def test_authenticated_pr_reaches_independent_approval_and_bound_check(tmp_path):
    store = PRAssuranceStore(tmp_path / "assurance.sqlite3")
    store.register_installation("tenant-a", 4421)
    private, jwks = _identity()
    pending = _ingest(store)
    assert pending["markers"] == [
        "WEBHOOK_SIGNATURE_VERIFIED", "PR_EVENT_BOUND", "DELIVERY_RECORDED",
        "PR_APPROVAL_SINGLETON", "AUTHORITY_BOUNDARY_OFFLINE",
    ]
    assert pending["check_request"]["status"] == "queued"
    completed = _decide(store, pending["approval_id"], _token(private), jwks)
    assert completed["markers"] == ["OIDC_IDENTITY_VERIFIED", "APPROVAL_APPROVED", "GITHUB_CHECK_BOUND"]
    assert completed["check_request"]["conclusion"] == "success"
    assert completed["check_request"]["head_sha"] == "a" * 40
    audit = store.evidence.verify_audit(Principal("audit", "tenant-a", ("viewer",)), "tenant-a")
    assert audit["valid"] is True and audit["events"] == 3


def test_webhook_signature_is_verified_before_json_and_replay_is_durable(tmp_path):
    body, headers = _webhook()
    bad_headers = {**headers, "X-Hub-Signature-256": "sha256=" + "0" * 64}
    with pytest.raises(PRAssuranceError) as invalid:
        verify_github_webhook(b"not-json", bad_headers, SECRET)
    assert invalid.value.code == "E_WEBHOOK_SIGNATURE"
    store = PRAssuranceStore(tmp_path / "assurance.sqlite3")
    store.register_installation("tenant-a", 4421)
    first = ingest_pull_request(store, body, headers, SECRET, "tenant-a")
    with pytest.raises(PRAssuranceError) as replay:
        ingest_pull_request(store, body, headers, SECRET, "tenant-a")
    assert replay.value.code == "E_WEBHOOK_REPLAY"
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM approvals").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM pr_assurance_deliveries").fetchone()[0] == 1
    assert first["approval_id"]


def test_unbound_installation_is_rejected_before_delivery_reservation(tmp_path):
    store = PRAssuranceStore(tmp_path / "assurance.sqlite3")
    body, headers = _webhook()
    with pytest.raises(PRAssuranceError) as error:
        ingest_pull_request(store, body, headers, SECRET, "tenant-a")
    assert error.value.code == "E_INSTALLATION_TENANT"
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM pr_assurance_deliveries").fetchone()[0] == 0


@pytest.mark.parametrize("mutation,code", [
    (lambda token: token.rsplit(".", 1)[0] + "." + _b64(b"bad"), "E_OIDC_SIGNATURE"),
    (lambda token: token.replace("RS256", "RS256"), None),
])
def test_oidc_signature_mutation_fails_closed(mutation, code):
    private, jwks = _identity()
    token = mutation(_token(private))
    if code is None:
        assert verify_oidc_token(token, jwks, ISSUER, AUDIENCE, now=NOW)["sub"] == "reviewer"
    else:
        with pytest.raises(PRAssuranceError) as error:
            verify_oidc_token(token, jwks, ISSUER, AUDIENCE, now=NOW)
        assert error.value.code == code


def test_oidc_pins_audience_and_rejects_jti_replay(tmp_path):
    store = PRAssuranceStore(tmp_path / "assurance.sqlite3")
    private, jwks = _identity()
    first = _ingest(store, delivery="d-1")
    second = _ingest(store, delivery="d-2")
    with pytest.raises(PRAssuranceError) as audience:
        _decide(store, first["approval_id"], _token(private, audience="other"), jwks)
    assert audience.value.code == "E_OIDC_AUDIENCE"
    token = _token(private, jti="one-use")
    _decide(store, first["approval_id"], token, jwks)
    with pytest.raises(PRAssuranceError) as replay:
        _decide(store, second["approval_id"], token, jwks)
    assert replay.value.code == "E_OIDC_REPLAY"


def test_cross_tenant_and_self_approval_leave_request_pending(tmp_path):
    store = PRAssuranceStore(tmp_path / "assurance.sqlite3")
    private, jwks = _identity()
    pending = _ingest(store)
    with pytest.raises(ControlPlaneError) as cross_tenant:
        _decide(store, pending["approval_id"], _token(private, tenant="tenant-b"), jwks)
    assert cross_tenant.value.code == "E_TENANT_BOUNDARY"
    with pytest.raises(ControlPlaneError) as self_approval:
        _decide(
            store, pending["approval_id"],
            _token(private, subject="github-app:4421", jti="self"), jwks,
        )
    assert self_approval.value.code == "E_SELF_APPROVAL"
    row = store.evidence.get_approval(
        Principal("audit", "tenant-a", ("viewer",)), "tenant-a", pending["approval_id"]
    )
    assert row["status"] == "pending"


def test_rejected_decision_emits_failure_without_network_authority(tmp_path, monkeypatch):
    store = PRAssuranceStore(tmp_path / "assurance.sqlite3")
    private, jwks = _identity()
    pending = _ingest(store)
    completed = _decide(store, pending["approval_id"], _token(private), jwks, decision="rejected")
    serialized = json.dumps(completed)
    assert completed["markers"] == ["OIDC_IDENTITY_VERIFIED", "APPROVAL_REJECTED", "GITHUB_CHECK_BOUND"]
    assert completed["check_request"]["conclusion"] == "failure"
    assert "url" not in serialized.lower() and "token" not in serialized.lower()


def test_github_check_request_rejects_unknown_status():
    body, headers = _webhook()
    event = verify_github_webhook(body, headers, SECRET)
    with pytest.raises(PRAssuranceError) as error:
        github_check_request(event, evidence_digest="b" * 64, approval_id="approval", status="unknown")
    assert error.value.code == "E_CHECK_STATUS"


def test_store_methods_enforce_state_and_lookup_boundaries(tmp_path):
    store = PRAssuranceStore(tmp_path / "direct.sqlite3")
    store.register_installation("tenant-a", 4421)
    store.require_installation("tenant-a", 4421)
    with pytest.raises(PRAssuranceError) as tenant_confusion:
        store.register_installation("tenant-b", 4421)
    assert tenant_confusion.value.code == "E_INSTALLATION_TENANT"
    body, headers = _webhook()
    event = verify_github_webhook(body, headers, SECRET)
    store.reserve_delivery("tenant-a", event)
    with pytest.raises(PRAssuranceError) as replay:
        store.reserve_delivery("tenant-a", event)
    assert replay.value.code == "E_WEBHOOK_REPLAY"
    store.bind_delivery("tenant-a", event.delivery_id, "evidence", "approval")
    loaded, metadata = store.by_approval("tenant-a", "approval")
    assert loaded.delivery_id == event.delivery_id and metadata["state"] == "pending"
    store.consume_jti(ISSUER, "jti-direct", "reviewer", "approval")
    with pytest.raises(PRAssuranceError) as token_replay:
        store.consume_jti(ISSUER, "jti-direct", "reviewer", "approval")
    assert token_replay.value.code == "E_OIDC_REPLAY"
    store.set_state("tenant-a", "approval", "approved")
    with pytest.raises(PRAssuranceError) as state:
        store.set_state("tenant-a", "approval", "rejected")
    assert state.value.code == "E_ASSURANCE_STATE"

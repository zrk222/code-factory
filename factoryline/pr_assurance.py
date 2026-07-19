"""Authenticated, tenant-bound pull-request assurance primitives.

The module verifies GitHub HMAC webhooks and offline OIDC JWTs before composing
them with :class:`factoryline.control_plane.EvidenceStore`.  It deliberately
returns GitHub Check request bodies without sending them: connector credentials
and network authority remain outside this local assurance boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .control_plane import ControlPlaneError, EvidenceStore, Principal, authorize, canonical_json
from .integrations import principal_from_verified_oidc


PR_ASSURANCE_SCHEMA = "factory.pr-assurance.v1"
CHECK_SCHEMA = "factory.github-check.request.v1"
MAX_WEBHOOK_BYTES = 1_048_576
DELIVERY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
ALLOWED_ACTIONS = frozenset({"opened", "reopened", "synchronize"})


class PRAssuranceError(ControlPlaneError):
    """Structured fail-closed PR-assurance error with a stable domain code."""


@dataclass(frozen=True)
class PullRequestEvent:
    """Normalized fields cryptographically bound to one GitHub webhook body."""

    delivery_id: str
    repository: str
    pull_request: int
    installation_id: int
    head_sha: str
    actor: str
    action: str
    payload_sha256: str

    def to_dict(self) -> dict[str, Any]:
        """Return a canonical-JSON-safe representation of the authenticated event."""
        return self.__dict__.copy()


def _header(headers: Mapping[str, str], name: str) -> str:
    values = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    return values.get(name.lower(), "")


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", f"GitHub field {field} is required")
    return value.strip()


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", f"{field} must be a positive integer")
    return value


def _verify_webhook_envelope(body: bytes, headers: Mapping[str, str], secret: bytes) -> str:
    if not isinstance(body, bytes) or not body or len(body) > MAX_WEBHOOK_BYTES:
        raise PRAssuranceError("E_WEBHOOK_BODY", f"webhook body must contain 1-{MAX_WEBHOOK_BYTES} bytes")
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise PRAssuranceError("E_WEBHOOK_SECRET", "webhook secret must contain at least 16 bytes")
    supplied = _header(headers, "X-Hub-Signature-256")
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise PRAssuranceError("E_WEBHOOK_SIGNATURE", "GitHub webhook signature is invalid")
    if _header(headers, "X-GitHub-Event") != "pull_request":
        raise PRAssuranceError("E_WEBHOOK_EVENT", "only pull_request events are accepted")
    delivery_id = _header(headers, "X-GitHub-Delivery")
    if not DELIVERY_RE.fullmatch(delivery_id):
        raise PRAssuranceError("E_WEBHOOK_DELIVERY", "GitHub delivery id is invalid")
    return delivery_id


def _parse_webhook_body(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", "webhook body is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", "webhook payload must be an object")
    return payload


def _normalize_pr_payload(payload: dict[str, Any], delivery_id: str, body: bytes) -> PullRequestEvent:
    action = _required_text(payload.get("action"), "action")
    if action not in ALLOWED_ACTIONS:
        raise PRAssuranceError("E_WEBHOOK_ACTION", f"unsupported pull_request action: {action}")
    repository = _required_text((payload.get("repository") or {}).get("full_name"), "repository.full_name")
    if not REPOSITORY_RE.fullmatch(repository):
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", "repository.full_name is invalid")
    pull_request = payload.get("pull_request") or {}
    head_sha = _required_text((pull_request.get("head") or {}).get("sha"), "pull_request.head.sha")
    if not SHA_RE.fullmatch(head_sha):
        raise PRAssuranceError("E_WEBHOOK_PAYLOAD", "pull_request.head.sha must be a 40 or 64 character hex digest")
    return PullRequestEvent(
        delivery_id=delivery_id,
        repository=repository,
        pull_request=_positive_int(pull_request.get("number") or payload.get("number"), "pull request number"),
        installation_id=_positive_int((payload.get("installation") or {}).get("id"), "installation.id"),
        head_sha=head_sha.lower(),
        actor=_required_text((payload.get("sender") or {}).get("login"), "sender.login"),
        action=action,
        payload_sha256=hashlib.sha256(body).hexdigest(),
    )


def verify_github_webhook(
    body: bytes,
    headers: Mapping[str, str],
    secret: bytes,
) -> PullRequestEvent:
    """Verify and normalize one GitHub PR webhook or raise ``PRAssuranceError``."""
    delivery_id = _verify_webhook_envelope(body, headers, secret)
    return _normalize_pr_payload(_parse_webhook_body(body), delivery_id, body)


def _decode_segment(value: str, code: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise PRAssuranceError(code, "OIDC token contains invalid base64url") from exc


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise PRAssuranceError("E_OIDC_MALFORMED", f"OIDC token repeats JSON member {key!r}")
        result[key] = item
    return result


def _json_segment(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(
            _decode_segment(value, "E_OIDC_MALFORMED"), object_pairs_hook=_reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PRAssuranceError("E_OIDC_MALFORMED", "OIDC token segment is not a JSON object") from exc
    if not isinstance(decoded, dict):
        raise PRAssuranceError("E_OIDC_MALFORMED", "OIDC token segment must be a JSON object")
    return decoded


def _integer_claim(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise PRAssuranceError("E_OIDC_CLAIM", f"OIDC {name} must be a numeric date")
    return int(value)


def _trusted_rsa_key(jwks: dict[str, Any], kid: str) -> dict[str, Any]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise PRAssuranceError("E_OIDC_KEY", "trusted JWKS must contain a keys list")
    matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
    if len(matches) != 1:
        raise PRAssuranceError("E_OIDC_KEY", "OIDC kid must resolve to exactly one trusted key")
    key = matches[0]
    if key.get("kty") != "RSA" or key.get("use", "sig") != "sig" or key.get("alg", "RS256") != "RS256":
        raise PRAssuranceError("E_OIDC_KEY", "trusted OIDC key is not an RS256 signing key")
    return key


def _verify_oidc_signature(key: dict[str, Any], signature: str, signing_input: bytes) -> None:
    try:
        modulus = int.from_bytes(_decode_segment(str(key["n"]), "E_OIDC_KEY"), "big")
        exponent = int.from_bytes(_decode_segment(str(key["e"]), "E_OIDC_KEY"), "big")
        if modulus.bit_length() < 2048:
            raise PRAssuranceError("E_OIDC_KEY", "trusted RSA key must contain at least 2048 bits")
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        public_key.verify(
            _decode_segment(signature, "E_OIDC_MALFORMED"), signing_input,
            padding.PKCS1v15(), hashes.SHA256(),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise PRAssuranceError("E_OIDC_KEY", "trusted RSA JWK is invalid") from exc
    except InvalidSignature as exc:
        raise PRAssuranceError("E_OIDC_SIGNATURE", "OIDC token signature is invalid") from exc


def _validate_oidc_claims(
    claims: dict[str, Any], expected_issuer: str, expected_audience: str, current: int, clock_skew_seconds: int
) -> None:
    if claims.get("iss") != expected_issuer:
        raise PRAssuranceError("E_OIDC_ISSUER", "OIDC issuer does not match the pinned issuer")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or expected_audience not in audiences:
        raise PRAssuranceError("E_OIDC_AUDIENCE", "OIDC audience does not contain the pinned audience")
    if _integer_claim(claims, "exp") < current - clock_skew_seconds:
        raise PRAssuranceError("E_OIDC_EXPIRED", "OIDC token has expired")
    if "nbf" in claims and _integer_claim(claims, "nbf") > current + clock_skew_seconds:
        raise PRAssuranceError("E_OIDC_PREMATURE", "OIDC token is not active yet")
    for required in ("sub", "tenant_id", "jti"):
        if not isinstance(claims.get(required), str) or not claims[required].strip():
            raise PRAssuranceError("E_OIDC_CLAIM", f"OIDC {required} is required")
    groups = claims.get("groups")
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        raise PRAssuranceError("E_OIDC_CLAIM", "OIDC groups must be a list of strings")


def _parse_oidc_token(
    token: str, expected_issuer: str, expected_audience: str, clock_skew_seconds: int
) -> tuple[str, str, str, dict[str, Any], dict[str, Any]]:
    if not isinstance(token, str) or len(token) > 16_384 or token.count(".") != 2:
        raise PRAssuranceError("E_OIDC_MALFORMED", "OIDC token must be one compact JWT")
    if not expected_issuer or not expected_audience:
        raise PRAssuranceError("E_OIDC_CONFIG", "expected issuer and audience are required")
    if not 0 <= clock_skew_seconds <= 300:
        raise PRAssuranceError("E_OIDC_CONFIG", "clock skew must be between 0 and 300 seconds")
    encoded_header, encoded_payload, encoded_signature = token.split(".")
    return (
        encoded_header, encoded_payload, encoded_signature,
        _json_segment(encoded_header), _json_segment(encoded_payload),
    )


def verify_oidc_token(
    token: str,
    jwks: dict[str, Any],
    expected_issuer: str,
    expected_audience: str,
    *,
    now: int | None = None,
    clock_skew_seconds: int = 60,
) -> dict[str, Any]:
    """Verify an RS256 OIDC JWT against offline JWKS and pinned claims or refuse it."""
    encoded_header, encoded_payload, encoded_signature, header, claims = _parse_oidc_token(
        token, expected_issuer, expected_audience, clock_skew_seconds
    )
    if header.get("alg") != "RS256":
        raise PRAssuranceError("E_OIDC_ALGORITHM", "only RS256 OIDC tokens are accepted")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise PRAssuranceError("E_OIDC_KEY", "OIDC token kid is required")
    _verify_oidc_signature(
        _trusted_rsa_key(jwks, kid), encoded_signature,
        f"{encoded_header}.{encoded_payload}".encode("ascii"),
    )
    current = int(time.time()) if now is None else int(now)
    _validate_oidc_claims(claims, expected_issuer, expected_audience, current, clock_skew_seconds)
    return {**claims, "signature_verified": True}


def github_check_request(
    event: PullRequestEvent,
    *,
    evidence_digest: str,
    approval_id: str,
    status: str,
) -> dict[str, Any]:
    """Build a deterministic publish-neutral GitHub Check request or reject status."""
    if status not in {"pending", "approved", "rejected"}:
        raise PRAssuranceError("E_CHECK_STATUS", "check status must be pending, approved, or rejected")
    conclusion = {"approved": "success", "rejected": "failure"}.get(status)
    request: dict[str, Any] = {
        "schema": CHECK_SCHEMA,
        "marker": "GITHUB_CHECK_BOUND",
        "name": "Code Factory / Enterprise PR Assurance",
        "head_sha": event.head_sha,
        "status": "completed" if conclusion else "queued",
        "external_id": approval_id,
        "output": {
            "title": f"PR assurance {status}",
            "summary": (
                f"Repository: {event.repository}\nPR: #{event.pull_request}\n"
                f"Evidence SHA-256: {evidence_digest}\nApproval: {approval_id}"
            ),
        },
    }
    if conclusion:
        request["conclusion"] = conclusion
    return request


class PRAssuranceStore:
    """Durable replay ledger composed with the existing tenant EvidenceStore."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.evidence = EvidenceStore(self.path)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS pr_assurance_deliveries (
                    tenant_id TEXT NOT NULL,
                    delivery_id TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    evidence_id TEXT,
                    approval_id TEXT,
                    state TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, delivery_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS pr_assurance_approval
                    ON pr_assurance_deliveries(approval_id) WHERE approval_id IS NOT NULL;
                CREATE TABLE IF NOT EXISTS github_installation_tenants (
                    installation_id INTEGER PRIMARY KEY,
                    tenant_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oidc_token_uses (
                    issuer TEXT NOT NULL,
                    jti TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    approval_id TEXT NOT NULL,
                    PRIMARY KEY (issuer, jti)
                );
                """
            )

    def register_installation(self, tenant_id: str, installation_id: int) -> None:
        """Create or confirm one immutable GitHub installation-to-tenant binding."""
        if not tenant_id.strip() or installation_id <= 0:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "tenant and positive installation id are required")
        with self._connect() as db:
            row = db.execute(
                "SELECT tenant_id FROM github_installation_tenants WHERE installation_id = ?", (installation_id,)
            ).fetchone()
            if row and row["tenant_id"] != tenant_id:
                raise PRAssuranceError("E_INSTALLATION_TENANT", "GitHub installation is bound to another tenant")
            if not row:
                db.execute("INSERT INTO github_installation_tenants VALUES (?, ?)", (installation_id, tenant_id))

    def require_installation(self, tenant_id: str, installation_id: int) -> None:
        """Reject webhook ingress unless its installation is pre-bound to the tenant."""
        with self._connect() as db:
            row = db.execute(
                "SELECT tenant_id FROM github_installation_tenants WHERE installation_id = ?", (installation_id,)
            ).fetchone()
        if not row or row["tenant_id"] != tenant_id:
            raise PRAssuranceError("E_INSTALLATION_TENANT", "GitHub installation is not bound to this tenant")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def reserve_delivery(self, tenant_id: str, event: PullRequestEvent) -> None:
        """Reserve one tenant delivery id or raise ``E_WEBHOOK_REPLAY`` atomically."""
        try:
            with self._connect() as db:
                db.execute(
                    "INSERT INTO pr_assurance_deliveries VALUES (?, ?, ?, NULL, NULL, 'reserved')",
                    (tenant_id, event.delivery_id, canonical_json(event.to_dict()).decode("utf-8")),
                )
        except sqlite3.IntegrityError as exc:
            raise PRAssuranceError("E_WEBHOOK_REPLAY", "GitHub delivery id has already been consumed") from exc

    def bind_delivery(self, tenant_id: str, delivery_id: str, evidence_id: str, approval_id: str) -> None:
        """Bind a reserved delivery to its immutable evidence and approval identifiers."""
        with self._connect() as db:
            changed = db.execute(
                """UPDATE pr_assurance_deliveries
                   SET evidence_id = ?, approval_id = ?, state = 'pending'
                   WHERE tenant_id = ? AND delivery_id = ? AND state = 'reserved'""",
                (evidence_id, approval_id, tenant_id, delivery_id),
            ).rowcount
        if changed != 1:
            raise PRAssuranceError("E_ASSURANCE_STATE", "delivery reservation is not bindable")

    def by_approval(self, tenant_id: str, approval_id: str) -> tuple[PullRequestEvent, dict[str, Any]]:
        """Load one tenant-bound PR event and approval metadata or refuse disclosure."""
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM pr_assurance_deliveries WHERE tenant_id = ? AND approval_id = ?",
                (tenant_id, approval_id),
            ).fetchone()
        if not row:
            raise PRAssuranceError("E_NOT_FOUND", "PR assurance approval was not found in this tenant")
        return PullRequestEvent(**json.loads(row["event_json"])), dict(row)

    def consume_jti(self, issuer: str, jti: str, subject: str, approval_id: str) -> None:
        """Consume one verified OIDC token identifier or reject an identity replay."""
        try:
            with self._connect() as db:
                db.execute("INSERT INTO oidc_token_uses VALUES (?, ?, ?, ?)", (issuer, jti, subject, approval_id))
        except sqlite3.IntegrityError as exc:
            raise PRAssuranceError("E_OIDC_REPLAY", "OIDC jti has already been consumed") from exc

    def set_state(self, tenant_id: str, approval_id: str, state: str) -> None:
        """Set the terminal assurance state after the control-plane decision commits."""
        with self._connect() as db:
            changed = db.execute(
                "UPDATE pr_assurance_deliveries SET state = ? WHERE tenant_id = ? AND approval_id = ? AND state = 'pending'",
                (state, tenant_id, approval_id),
            ).rowcount
        if changed != 1:
            raise PRAssuranceError("E_ASSURANCE_STATE", "PR assurance request is not pending")


def ingest_pull_request(
    store: PRAssuranceStore,
    body: bytes,
    headers: Mapping[str, str],
    secret: bytes,
    tenant_id: str,
) -> dict[str, Any]:
    """Authenticate a PR webhook, persist tenant evidence, and request approval."""
    if not tenant_id.strip():
        raise PRAssuranceError("E_TENANT_REQUIRED", "tenant_id is required")
    event = verify_github_webhook(body, headers, secret)
    store.require_installation(tenant_id, event.installation_id)
    store.reserve_delivery(tenant_id, event)
    principal = Principal(
        subject=f"github-app:{event.installation_id}", tenant_id=tenant_id, roles=("operator",)
    )
    evidence_id = "pr-" + hashlib.sha256(f"{tenant_id}:{event.delivery_id}".encode()).hexdigest()[:32]
    evidence = store.evidence.put(
        principal,
        {
            "schema": PR_ASSURANCE_SCHEMA,
            "tenant_id": tenant_id,
            "verdict": "PENDING_APPROVAL",
            "marker": "PR_EVENT_BOUND",
            "webhook_marker": "WEBHOOK_SIGNATURE_VERIFIED",
            "delivery_marker": "DELIVERY_RECORDED",
            "event": event.to_dict(),
        },
        evidence_id=evidence_id,
    )
    approval = store.evidence.request_approval(
        principal, tenant_id, evidence_id, f"independent assurance decision for {event.repository}#{event.pull_request}"
    )
    store.bind_delivery(tenant_id, event.delivery_id, evidence_id, approval["approval_id"])
    return {
        "schema": PR_ASSURANCE_SCHEMA,
        "markers": [
            "WEBHOOK_SIGNATURE_VERIFIED", "PR_EVENT_BOUND", "DELIVERY_RECORDED",
            "PR_APPROVAL_SINGLETON", "AUTHORITY_BOUNDARY_OFFLINE",
        ],
        "event": event.to_dict(),
        "evidence_id": evidence_id,
        "evidence_sha256": evidence["payload_sha256"],
        "approval_id": approval["approval_id"],
        "check_request": github_check_request(
            event, evidence_digest=evidence["payload_sha256"], approval_id=approval["approval_id"], status="pending"
        ),
    }


def decide_pull_request(
    store: PRAssuranceStore,
    approval_id: str,
    token: str,
    jwks: dict[str, Any],
    expected_issuer: str,
    expected_audience: str,
    *,
    tenant_id: str,
    role_map: dict[str, str],
    decision: str,
    reason: str,
    now: int | None = None,
) -> dict[str, Any]:
    """Authenticate an independent approver and return a terminal Check request."""
    claims = verify_oidc_token(token, jwks, expected_issuer, expected_audience, now=now)
    principal = principal_from_verified_oidc(claims, expected_issuer=expected_issuer, role_map=role_map)
    authorize(principal, "evidence.read", tenant_id)
    event, metadata = store.by_approval(tenant_id, approval_id)
    store.consume_jti(expected_issuer, claims["jti"], principal.subject, approval_id)
    approved = store.evidence.decide_approval(principal, tenant_id, approval_id, decision, reason)
    store.set_state(tenant_id, approval_id, approved["status"])
    evidence = store.evidence.get(principal, tenant_id, metadata["evidence_id"])
    marker = "APPROVAL_APPROVED" if approved["status"] == "approved" else "APPROVAL_REJECTED"
    return {
        "schema": PR_ASSURANCE_SCHEMA,
        "markers": ["OIDC_IDENTITY_VERIFIED", marker, "GITHUB_CHECK_BOUND"],
        "approval": approved,
        "check_request": github_check_request(
            event,
            evidence_digest=evidence["payload_sha256"],
            approval_id=approval_id,
            status=approved["status"],
        ),
    }

"""Offline signer, binding, and freshness checks for deep-audit evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .deep_audit import _read_receipt
from .deep_audit_io import local_file
from .enterprise_receipts import EnterpriseReceiptError, verify_signed_document
from .runtime_audit_common import (
    RuntimeAuditError,
    require_bool,
    require_digest,
    require_int,
    require_str,
)

SCHEMA = "factory.deep-audit-attestation.v1"
PAYLOAD_TYPE = "application/vnd.factory.deep-audit-attestation.v1+json"
RESULT_SCHEMA = "factory.deep-audit-attestation-verification.v1"
DEFAULT_MAX_AGE_SECONDS = 3600
MAX_VALIDITY_SECONDS = 86400


class DeepAuditAttestationError(ValueError):
    """Stable, review-safe error for an invalid external deep-audit attestation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise DeepAuditAttestationError(code, message)


def _relative(root: Path, value: Path | str, field: str) -> str:
    try:
        candidate = Path(value)
    except (TypeError, ValueError) as exc:
        _fail("E_DEEP_ATTESTATION_PATH", f"{field} must be a workspace path")
        raise AssertionError from exc
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        _fail("E_DEEP_ATTESTATION_PATH", f"{field} must be inside the workspace")
    return relative.as_posix()


def _file(root: Path, value: Path | str, field: str) -> Path:
    relative = _relative(root, value, field)
    try:
        return local_file(root, relative)
    except (RuntimeAuditError, OSError) as exc:
        _fail("E_DEEP_ATTESTATION_PATH", f"{field} is not a regular workspace file")
        raise AssertionError from exc


def _digest(value: object, field: str) -> str:
    try:
        return require_digest(value, field)
    except RuntimeAuditError as exc:
        _fail(
            "E_DEEP_ATTESTATION_BINDING", f"{field} is not a lowercase SHA-256 digest"
        )
        raise AssertionError from exc


def _text(value: object, field: str, maximum: int = 256) -> str:
    try:
        return require_str(value, field, maximum=maximum)
    except RuntimeAuditError as exc:
        _fail("E_DEEP_ATTESTATION_SCHEMA", f"{field} is invalid")
        raise AssertionError from exc


def _exact(value: object, required: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        _fail("E_DEEP_ATTESTATION_SCHEMA", f"{field} has missing or unknown fields")
    return value


def _instant(value: object, field: str) -> datetime:
    text = _text(value, field, 40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", f"{field} is not an ISO-8601 instant")
        raise AssertionError from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _verified_document(path: Path, trust_root: Path) -> dict[str, Any]:
    try:
        return verify_signed_document(
            path, payload_type=PAYLOAD_TYPE, schema=SCHEMA, trust_root_path=trust_root
        )
    except EnterpriseReceiptError as exc:
        _fail(
            "E_DEEP_ATTESTATION_SIGNATURE",
            f"offline DSSE verification failed ({exc.code})",
        )
        raise AssertionError from exc


def _validate_payload(
    payload: dict[str, Any], receipt: dict[str, Any], claimed_receipt: str
) -> tuple[dict, dict, datetime, datetime]:
    required = {
        "schema",
        "attestation_id",
        "receipt_sha256",
        "plan_sha256",
        "candidate_sha256",
        "ruleset_sha256",
        "canary_set_sha256",
        "issued_at",
        "expires_at",
        "verifier",
        "observations",
        "authority",
    }
    _exact(payload, required, "payload")
    if payload["schema"] != SCHEMA:
        _fail("E_DEEP_ATTESTATION_SCHEMA", "unexpected schema")
    _text(payload["attestation_id"], "attestation_id")
    if payload["authority"] != "none":
        _fail("E_DEEP_ATTESTATION_BINDING", "authority must remain none")
    for field, expected in (
        ("receipt_sha256", claimed_receipt),
        ("plan_sha256", receipt["plan_sha256"]),
        ("candidate_sha256", receipt["candidate_sha256"]),
        ("ruleset_sha256", receipt["ruleset_sha256"]),
        ("canary_set_sha256", receipt["canary_set_sha256"]),
    ):
        if _digest(payload[field], field) != _digest(expected, f"receipt.{field}"):
            _fail(
                "E_DEEP_ATTESTATION_BINDING", f"{field} differs from the signed receipt"
            )

    verifier = _exact(payload["verifier"], {"id", "version", "independent"}, "verifier")
    verifier_id = _text(verifier["id"], "verifier.id")
    _text(verifier["version"], "verifier.version")
    try:
        independent = require_bool(verifier["independent"], "verifier.independent")
    except RuntimeAuditError as exc:
        _fail("E_DEEP_ATTESTATION_INDEPENDENCE", "verifier.independent must be true")
        raise AssertionError from exc
    if not independent or verifier_id in set(receipt["report_hashes"]):
        _fail(
            "E_DEEP_ATTESTATION_INDEPENDENCE",
            "verifier must be independent of every analyzer",
        )

    observations = _exact(
        payload["observations"], {"report_hashes", "canary_hashes"}, "observations"
    )
    for field in ("report_hashes", "canary_hashes"):
        observed = observations[field]
        expected = receipt[field]
        if not isinstance(observed, dict) or not 1 <= len(observed) <= 8:
            _fail("E_DEEP_ATTESTATION_BINDING", f"{field} coverage is incomplete")
        if set(observed) != set(expected):
            _fail(
                "E_DEEP_ATTESTATION_BINDING",
                f"{field} coverage differs from the receipt",
            )
        for key, value in observed.items():
            _text(key, f"{field} analyzer id")
            if _digest(value, f"{field}.{key}") != _digest(
                expected[key], f"receipt.{field}.{key}"
            ):
                _fail(
                    "E_DEEP_ATTESTATION_BINDING",
                    f"{field}.{key} differs from the receipt",
                )

    return (
        verifier,
        observations,
        _instant(payload["issued_at"], "issued_at"),
        _instant(payload["expires_at"], "expires_at"),
    )


def _freshness(
    issued: datetime, expires: datetime, now: datetime | None, max_age_seconds: int
) -> dict[str, Any]:
    try:
        max_age = require_int(
            max_age_seconds, "max_age_seconds", minimum=1, maximum=MAX_VALIDITY_SECONDS
        )
    except RuntimeAuditError as exc:
        _fail(
            "E_DEEP_ATTESTATION_FRESHNESS",
            "max_age_seconds is outside the bounded window",
        )
        raise AssertionError from exc
    if expires <= issued or (expires - issued).total_seconds() > MAX_VALIDITY_SECONDS:
        _fail(
            "E_DEEP_ATTESTATION_FRESHNESS",
            "attestation validity exceeds the 24-hour bound",
        )
    actual = datetime.now(timezone.utc)
    supplied = actual if now is None else now
    if not isinstance(supplied, datetime):
        _fail("E_DEEP_ATTESTATION_FRESHNESS", "now must be a datetime")
    if supplied.tzinfo is None or supplied.utcoffset() is None:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", "now must include a timezone")
    current = max(actual, supplied.astimezone(timezone.utc))
    if issued > current or current >= expires:
        _fail("E_DEEP_ATTESTATION_FRESHNESS", "attestation is future-dated or expired")
    age = (current - issued).total_seconds()
    if age > max_age:
        _fail(
            "E_DEEP_ATTESTATION_FRESHNESS",
            "attestation is older than the allowed observation age",
        )
    return {
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "age_seconds": int(age),
        "max_age_seconds": max_age,
    }


def verify_deep_audit_attestation(
    root: Path,
    attestation_path: Path,
    trust_root_path: Path,
    receipt_path: Path,
    *,
    now: datetime | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Verify one fresh independent DSSE attestation without executing or authorizing anything."""
    root = Path(root).resolve()
    attestation = _file(root, attestation_path, "attestation")
    trust_root = _file(root, trust_root_path, "trust_root")
    receipt_file = _file(root, receipt_path, "receipt")
    try:
        receipt, claimed_receipt, _ = _read_receipt(root, receipt_file)
    except (RuntimeAuditError, OSError, ValueError, KeyError, TypeError) as exc:
        _fail(
            "E_DEEP_ATTESTATION_BINDING",
            "receipt is not a valid self-hash deep-audit receipt",
        )
        raise AssertionError from exc
    verified = _verified_document(attestation, trust_root)
    verifier, _, issued, expires = _validate_payload(
        verified["payload"], receipt, claimed_receipt
    )
    freshness = _freshness(issued, expires, now, max_age_seconds)
    return {
        "schema": RESULT_SCHEMA,
        "state": "VERIFIED",
        "marker": "DEEP_AUDIT_ATTESTATION_VERIFIED",
        "receipt_sha256": claimed_receipt,
        "attestation_sha256": verified["payload_sha256"],
        "plan_sha256": receipt["plan_sha256"],
        "candidate_sha256": receipt["candidate_sha256"],
        "keyid": verified["signature"]["keyid"],
        "identity": verified["signature"]["identity"],
        "issuer": verified["signature"]["issuer"],
        "verifier": verifier,
        "freshness": freshness,
        "authority": "none",
        "release_approval": False,
        "claim_boundary": "Offline DSSE signer, receipt binding, and freshness verification only; semantic correctness and release approval remain unproven.",
    }

"""Offline-verifiable Receipt v2, policy, and revocation envelopes.

The module implements the small DSSE subset needed by FactoryLine. It keeps
networked Sigstore verification as a separate v1 compatibility path and uses
Ed25519 plus an explicit local trust root for offline enterprise checks.
"""

from __future__ import annotations

from . import canonical_json_bytes as _canonical_encode
from datetime import datetime, timezone
import base64
import binascii
import hashlib
import json
import math
from pathlib import Path
from typing import Any
from dataclasses import dataclass
import re
import shutil
from typing import NoReturn
from .enterprise_ops import default_home

serialization: Any = None
Ed25519PrivateKey: Any = None
Ed25519PublicKey: Any = None
InvalidSignature: Any = ValueError
_CRYPTO_LOADED = False


RECEIPT_V2_SCHEMA = "factory.receipt.v2"
POLICY_BUNDLE_SCHEMA = "factory.policy.bundle.v1"
REVOCATIONS_SCHEMA = "factory.revocations.v1"
TRUST_ROOT_SCHEMA = "factory.trust.root.v1"
DSSE_SCHEMA = "factory.dsse.envelope.v1"
RECEIPT_PAYLOAD_TYPE = "application/vnd.factory.receipt.v2+json"
POLICY_PAYLOAD_TYPE = "application/vnd.factory.policy.bundle.v1+json"
REVOCATIONS_PAYLOAD_TYPE = "application/vnd.factory.revocations.v1+json"
RESULT_SCHEMA = "factory.enterprise.result.v1"
DEFAULT_MAX_REVOCATION_AGE_SECONDS = 86400
MAX_REVOCATION_AGE_SECONDS = 604800
MAX_REVOCATION_ENTRIES = 4096
MAX_JSON_DEPTH = 128


class EnterpriseReceiptError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _require_crypto() -> None:
    global serialization, Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature
    global _CRYPTO_LOADED
    if not _CRYPTO_LOADED:
        try:
            from cryptography.hazmat.primitives import serialization as encoding
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey as private_key_type,
                Ed25519PublicKey as public_key_type,
            )
            from cryptography.exceptions import InvalidSignature as invalid_signature
        except ImportError as exc:
            raise EnterpriseReceiptError(
                "E_CRYPTO_UNAVAILABLE",
                "install with: pip install factoryline-code-factory[enterprise]",
            ) from exc
        serialization = encoding
        Ed25519PrivateKey = private_key_type
        Ed25519PublicKey = public_key_type
        InvalidSignature = invalid_signature
        _CRYPTO_LOADED = True
    if Ed25519PrivateKey is None or Ed25519PublicKey is None:
        raise EnterpriseReceiptError(
            "E_CRYPTO_UNAVAILABLE",
            "install with: pip install factoryline-code-factory[enterprise]",
        )


def _canonical(value: Any) -> bytes:
    try:
        return _canonical_encode(value)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", str(exc)) from exc


def canonical_json(value: Any) -> bytes:
    """Return the stable UTF-8 bytes used by every enterprise digest."""
    return _canonical(value)


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64d(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise EnterpriseReceiptError("E_INVALID_ENVELOPE", f"{field} is required")
    try:
        encoded = value.encode("ascii")
        if ("-" in value or "_" in value) and ("+" in value or "/" in value):
            raise ValueError("mixed Base64 alphabets")
        padding = len(encoded) - len(encoded.rstrip(b"="))
        body = encoded[:-padding] if padding else encoded
        if b"=" in body or padding > 2 or len(body) % 4 == 1:
            raise ValueError("invalid Base64 padding")
        required_padding = -len(body) % 4
        if padding and padding != required_padding:
            raise ValueError("invalid Base64 padding")
        padded = body + b"=" * required_padding
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        # Reject non-zero unused pad bits while accepting the canonical standard
        # and URL-safe forms, with or without padding.
        if value not in {
            base64.b64encode(decoded).decode("ascii"),
            base64.b64encode(decoded).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(decoded).decode("ascii"),
            base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("="),
        }:
            raise ValueError("non-canonical Base64 encoding")
        return decoded
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise EnterpriseReceiptError("E_INVALID_ENVELOPE", f"invalid {field}") from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object member")
        value[key] = item
    return value


def _json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _check_json_depth(value: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds maximum depth")
        elif character in "]}":
            depth = max(0, depth - 1)


def _json_loads(value: str | bytes) -> Any:
    if isinstance(value, bytes):
        value = value.decode(json.detect_encoding(value), "surrogatepass")
    _check_json_depth(value)
    return json.loads(
        value,
        object_pairs_hook=_unique_json_object,
        parse_float=_json_float,
        parse_constant=_json_constant,
    )


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pae_field(value: bytes) -> bytes:
    return str(len(value)).encode("ascii") + b" " + value


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return the DSSE v1 pre-authentication encoding."""
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 " + _pae_field(type_bytes) + b" " + _pae_field(payload)


def _read_json(path: Path) -> dict:
    try:
        value = _json_loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise EnterpriseReceiptError("E_INVALID_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise EnterpriseReceiptError(
            "E_INVALID_JSON", "top-level JSON must be an object"
        )
    return value


def _write_json(path: Path, value: dict) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value) + b"\n")
    return path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnterpriseReceiptError(
            "E_INVALID_RECEIPT", "invalid receipt timestamp"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_optional_digest(payload: dict, field: str) -> None:
    if field not in payload:
        return
    value = payload[field]
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value.lower())
    ):
        raise EnterpriseReceiptError(
            "E_INVALID_RECEIPT", f"{field} must be a SHA-256 hex digest"
        )


def validate_receipt_v2(payload: dict) -> dict:
    """Validate a Receipt v2 payload or raise EnterpriseReceiptError with a stable code."""
    required = {
        "schema",
        "module",
        "stage",
        "feature",
        "ok",
        "tenant_id",
        "run_id",
        "ts",
    }
    if payload.get("schema") != RECEIPT_V2_SCHEMA:
        raise EnterpriseReceiptError(
            "E_INVALID_RECEIPT", "schema must be factory.receipt.v2"
        )
    missing = sorted(required - payload.keys())
    if missing:
        raise EnterpriseReceiptError("E_INVALID_RECEIPT", f"missing fields: {missing}")
    for field in ("module", "stage", "feature", "tenant_id", "run_id", "ts"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise EnterpriseReceiptError(
                "E_INVALID_RECEIPT", f"{field} must be non-empty"
            )
    if not isinstance(payload["ok"], bool):
        raise EnterpriseReceiptError("E_INVALID_RECEIPT", "ok must be boolean")
    _timestamp(payload["ts"])
    for field in ("policy_sha256", "subject_sha256"):
        _validate_optional_digest(payload, field)
    return payload


def receipt_v2_from_v1(
    payload: dict, *, tenant_id: str = "local", policy_sha256: str | None = None
) -> dict:
    """Convert a readable v1 receipt into an explicitly tenant-bound v2 payload."""
    if not isinstance(payload, dict) or not str(payload.get("schema", "")).startswith(
        "factory.receipt."
    ):
        raise EnterpriseReceiptError(
            "E_INVALID_RECEIPT", "input is not a factory receipt"
        )
    converted = dict(payload)
    converted.update(
        {
            "schema": RECEIPT_V2_SCHEMA,
            "tenant_id": tenant_id,
            "run_id": str(
                payload.get("run_id")
                or hashlib.sha256(_canonical(payload)).hexdigest()[:32]
            ),
            "ts": str(payload.get("ts") or _now()),
        }
    )
    if policy_sha256 is not None:
        converted["policy_sha256"] = policy_sha256
    return validate_receipt_v2(converted)


def _load_private_key(path: Path):
    _require_crypto()
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise EnterpriseReceiptError("E_PRIVATE_KEY_UNAVAILABLE", str(exc)) from exc
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except ValueError:
        try:
            key = Ed25519PrivateKey.from_private_bytes(
                _b64d(raw.decode("ascii").strip(), "private_key")
            )
        except (ValueError, UnicodeDecodeError, EnterpriseReceiptError) as exc:
            raise EnterpriseReceiptError(
                "E_PRIVATE_KEY_INVALID", "expected Ed25519 PEM or base64 key"
            ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EnterpriseReceiptError("E_PRIVATE_KEY_INVALID", "key is not Ed25519")
    return key


def _load_public_key(value: Any):
    _require_crypto()
    raw = _b64d(value, "public_key")
    if len(raw) != 32:
        raise EnterpriseReceiptError(
            "E_TRUST_ROOT_INVALID", "Ed25519 public key must be 32 bytes"
        )
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise EnterpriseReceiptError(
            "E_TRUST_ROOT_INVALID", "invalid Ed25519 public key"
        ) from exc


def _signature_metadata(
    *, keyid: str, identity: str, issuer: str, signature: bytes
) -> dict:
    if not all(
        isinstance(value, str) and value.strip() for value in (keyid, identity, issuer)
    ):
        raise EnterpriseReceiptError(
            "E_IDENTITY_REQUIRED", "key id, identity, and issuer are required"
        )
    return {
        "keyid": keyid,
        "algorithm": "ed25519",
        "identity": identity,
        "issuer": issuer,
        "sig": _b64e(signature),
    }


def sign_payload(
    payload: dict,
    *,
    payload_type: str,
    private_key_path: Path,
    keyid: str,
    identity: str,
    issuer: str,
) -> dict:
    """Create a DSSE envelope or raise EnterpriseReceiptError for invalid signing inputs."""
    _require_crypto()
    if not isinstance(payload, dict):
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", "payload must be an object")
    private_key = _load_private_key(Path(private_key_path))
    payload_bytes = _canonical(payload)
    signature = private_key.sign(dsse_pae(payload_type, payload_bytes))
    return {
        "schema": DSSE_SCHEMA,
        "payloadType": payload_type,
        "payload": _b64e(payload_bytes),
        "payload_sha256": _sha256(payload_bytes),
        "signatures": [
            _signature_metadata(
                keyid=keyid, identity=identity, issuer=issuer, signature=signature
            )
        ],
    }


def seal_receipt_v2(
    payload: dict,
    private_key_path: Path,
    keyid: str,
    identity: str,
    issuer: str,
    out: Path,
) -> dict:
    """Validate, sign, and write Receipt v2 or raise EnterpriseReceiptError fail closed."""
    validate_receipt_v2(payload)
    envelope = sign_payload(
        payload,
        payload_type=RECEIPT_PAYLOAD_TYPE,
        private_key_path=private_key_path,
        keyid=keyid,
        identity=identity,
        issuer=issuer,
    )
    _write_json(Path(out), envelope)
    return envelope


def _validate_trust_root(root: dict) -> dict:
    if root.get("schema") != TRUST_ROOT_SCHEMA or not isinstance(
        root.get("keys"), list
    ):
        raise EnterpriseReceiptError(
            "E_TRUST_ROOT_INVALID", "invalid trust root schema"
        )
    return root


def _verified_payload_bytes(envelope: dict, expected_payload_type: str) -> bytes:
    if envelope.get("schema") != DSSE_SCHEMA:
        raise EnterpriseReceiptError(
            "E_INVALID_ENVELOPE", "unsupported DSSE envelope schema"
        )
    if envelope.get("payloadType") != expected_payload_type:
        raise EnterpriseReceiptError(
            "E_PAYLOAD_TYPE_MISMATCH", "unexpected DSSE payload type"
        )
    payload_bytes = _b64d(envelope.get("payload"), "payload")
    if envelope.get("payload_sha256") != _sha256(payload_bytes):
        raise EnterpriseReceiptError(
            "E_PAYLOAD_DIGEST_MISMATCH", "payload digest does not match bytes"
        )
    return payload_bytes


def _envelope_signature(envelope: dict) -> dict:
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise EnterpriseReceiptError(
            "E_UNSUPPORTED_SIGNATURE", "exactly one Ed25519 signature is required"
        )
    signature = signatures[0]
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        raise EnterpriseReceiptError(
            "E_UNSUPPORTED_SIGNATURE", "only Ed25519 signatures are supported"
        )
    return signature


def _trusted_signer(signature: dict, trust_root: dict) -> tuple[Any, Any]:
    keyid = signature.get("keyid")
    key = next(
        (
            item
            for item in trust_root["keys"]
            if isinstance(item, dict) and item.get("keyid") == keyid
        ),
        None,
    )
    if key is None:
        raise EnterpriseReceiptError("E_UNKNOWN_KEY", f"untrusted key id: {keyid}")
    if signature.get("identity") != key.get("identity") or signature.get(
        "issuer"
    ) != key.get("issuer"):
        raise EnterpriseReceiptError(
            "E_IDENTITY_MISMATCH",
            "signature identity or issuer differs from trust root",
        )
    return key, _load_public_key(key.get("public_key"))


def _require_key_role(signature: dict, trust_root: dict, required_role: str) -> None:
    keyid = signature.get("keyid")
    key = next(
        (
            item
            for item in trust_root["keys"]
            if isinstance(item, dict) and item.get("keyid") == keyid
        ),
        None,
    )
    roles = key.get("roles") if key else None
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise EnterpriseReceiptError(
            "E_KEY_ROLE_MISMATCH", "trusted key has no valid role grants"
        )
    if required_role not in roles:
        raise EnterpriseReceiptError(
            "E_KEY_ROLE_MISMATCH", f"trusted key is not authorized for {required_role}"
        )


def _verify_signature(
    signature: dict,
    public_key: Any,
    expected_payload_type: str,
    payload_bytes: bytes,
) -> None:
    try:
        public_key.verify(
            _b64d(signature.get("sig"), "signature"),
            dsse_pae(expected_payload_type, payload_bytes),
        )
    except (InvalidSignature, ValueError):
        raise EnterpriseReceiptError(
            "E_SIGNATURE_INVALID", "DSSE signature verification failed"
        )


def _decode_envelope_payload(payload_bytes: bytes) -> dict:
    try:
        payload = _json_loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", str(exc)) from exc
    if not isinstance(payload, dict):
        raise EnterpriseReceiptError(
            "E_INVALID_PAYLOAD", "DSSE payload must be an object"
        )
    return payload


def _verify_envelope(
    envelope: dict, *, expected_payload_type: str, trust_root: dict
) -> tuple[dict, dict, bytes]:
    payload_bytes = _verified_payload_bytes(envelope, expected_payload_type)
    signature = _envelope_signature(envelope)
    _, public_key = _trusted_signer(signature, trust_root)
    _verify_signature(signature, public_key, expected_payload_type, payload_bytes)
    payload = _decode_envelope_payload(payload_bytes)
    return payload, signature, payload_bytes


def _verify_signed_document(
    path: Path, *, payload_type: str, schema: str, trust_root: dict
) -> tuple[dict, dict]:
    payload, signature, _ = _verify_envelope(
        _read_json(path), expected_payload_type=payload_type, trust_root=trust_root
    )
    if payload.get("schema") != schema:
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", f"expected {schema}")
    return payload, signature


def verify_signed_document(
    path: Path,
    *,
    payload_type: str,
    schema: str,
    trust_root_path: Path,
    required_key_role: str | None = None,
) -> dict:
    """Verify one typed DSSE document against an explicit offline trust root.

    This is deliberately a narrow cryptographic primitive for higher-level
    enterprise policy modules.  It authenticates the document signer against
    the supplied local trust root; it does not perform OIDC federation,
    network key discovery, authorization, or runtime enforcement.
    """
    return verify_signed_document_value(
        _read_json(Path(path)),
        payload_type=payload_type,
        schema=schema,
        trust_root=_read_json(Path(trust_root_path)),
        required_key_role=required_key_role,
    )


def verify_signed_document_value(
    envelope: dict,
    *,
    payload_type: str,
    schema: str,
    trust_root: dict,
    required_key_role: str | None = None,
) -> dict:
    """Verify already captured snapshots without reopening mutable file paths."""
    trust_root = _validate_trust_root(trust_root)
    payload, signature, _ = _verify_envelope(
        envelope, expected_payload_type=payload_type, trust_root=trust_root
    )
    if payload.get("schema") != schema:
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", f"expected {schema}")
    if required_key_role is not None:
        _require_key_role(signature, trust_root, required_key_role)
    return {
        "payload": payload,
        "signature": signature,
        "payload_sha256": _sha256(_canonical(payload)),
        "verification": "offline_dsse_ed25519",
    }


def _revoked(
    revocations: dict, *, keyid: str, identity: str, receipt_ts: datetime
) -> bool:
    for entry in revocations.get("entries", []):
        if not isinstance(entry, dict) or (
            entry.get("keyid") != keyid and entry.get("identity") != identity
        ):
            continue
        if "revoked_at" not in entry:
            return True
        revoked_at = entry.get("revoked_at")
        if isinstance(revoked_at, str) and _timestamp(revoked_at) <= receipt_ts:
            return True
    return False


def _revocation_timestamp(value: object, *, code: str, field: str) -> datetime:
    """Parse a revocation timestamp while requiring an explicit timezone."""
    if not isinstance(value, str):
        raise EnterpriseReceiptError(
            code, f"{field} must be a timezone-aware timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EnterpriseReceiptError(
            code, f"{field} must be a timezone-aware timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise EnterpriseReceiptError(
            code, f"{field} must be a timezone-aware timestamp"
        )
    return parsed.astimezone(timezone.utc)


def _validate_revocations_payload(payload: dict) -> datetime:
    """Validate the signed revocation snapshot and return its generation time."""
    if payload.get("schema") != REVOCATIONS_SCHEMA:
        raise EnterpriseReceiptError(
            "E_INVALID_REVOCATIONS", f"expected {REVOCATIONS_SCHEMA}"
        )
    generated_at = _revocation_timestamp(
        payload.get("generated_at"), code="E_REVOCATION_FRESHNESS", field="generated_at"
    )
    entries = payload.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_REVOCATION_ENTRIES:
        raise EnterpriseReceiptError(
            "E_INVALID_REVOCATIONS",
            f"entries must contain 0 to {MAX_REVOCATION_ENTRIES} objects",
        )
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not (
            isinstance(entry.get("keyid"), str)
            or isinstance(entry.get("identity"), str)
        ):
            raise EnterpriseReceiptError(
                "E_INVALID_REVOCATIONS",
                f"entry {index} must identify a keyid or identity",
            )
        if "revoked_at" in entry:
            _revocation_timestamp(
                entry["revoked_at"],
                code="E_INVALID_REVOCATIONS",
                field=f"entry {index} revoked_at",
            )
    return generated_at


def _revocation_freshness(
    generated_at: datetime, *, now: datetime | None, max_age_seconds: int
) -> int:
    if (
        not isinstance(max_age_seconds, int)
        or isinstance(max_age_seconds, bool)
        or not 1 <= max_age_seconds <= MAX_REVOCATION_AGE_SECONDS
    ):
        raise EnterpriseReceiptError(
            "E_REVOCATION_FRESHNESS",
            f"max_revocation_age_seconds must be 1 through {MAX_REVOCATION_AGE_SECONDS}",
        )
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise EnterpriseReceiptError(
            "E_REVOCATION_FRESHNESS", "now must be a timezone-aware timestamp"
        )
    current = current.astimezone(timezone.utc)
    age = int((current - generated_at).total_seconds())
    if age < 0:
        raise EnterpriseReceiptError(
            "E_REVOCATION_FRESHNESS", "revocation snapshot is issued in the future"
        )
    if age > max_age_seconds:
        raise EnterpriseReceiptError(
            "E_REVOCATION_FRESHNESS", "revocation snapshot is stale"
        )
    return age


def _verify_policy_status(
    payload: dict, *, trust_root: dict, policy_bundle_path: Path | None
) -> str:
    """Verify a declared policy bundle and return its evidence status."""
    policy_digest = payload.get("policy_sha256")
    if not policy_digest:
        return "NOT_DECLARED"
    if policy_bundle_path is None:
        raise EnterpriseReceiptError(
            "E_POLICY_REQUIRED",
            "receipt declares policy_sha256 but no bundle was supplied",
        )
    policy, _ = _verify_signed_document(
        Path(policy_bundle_path),
        payload_type=POLICY_PAYLOAD_TYPE,
        schema=POLICY_BUNDLE_SCHEMA,
        trust_root=trust_root,
    )
    if policy.get("policy_sha256") != policy_digest:
        raise EnterpriseReceiptError(
            "E_POLICY_DIGEST_MISMATCH", "receipt and policy bundle digests differ"
        )
    return "VERIFIED"


def _verify_revocation_status(
    *,
    signature: dict,
    receipt_ts: datetime,
    trust_root: dict,
    revocations_path: Path | None,
    require_revocations: bool,
    max_revocation_age_seconds: int,
    now: datetime | None,
) -> tuple[str, str, int | None]:
    """Verify an optional or strict revocation snapshot and return its markers."""
    if require_revocations and revocations_path is None:
        raise EnterpriseReceiptError(
            "E_REVOCATION_REQUIRED",
            "strict verification requires a signed revocation snapshot",
        )
    if revocations_path is None:
        return "NOT_CHECKED", "NOT_CHECKED", None
    revocations, _ = _verify_signed_document(
        Path(revocations_path),
        payload_type=REVOCATIONS_PAYLOAD_TYPE,
        schema=REVOCATIONS_SCHEMA,
        trust_root=trust_root,
    )
    generated_at = _validate_revocations_payload(revocations)
    age = (
        _revocation_freshness(
            generated_at, now=now, max_age_seconds=max_revocation_age_seconds
        )
        if require_revocations
        else None
    )
    freshness = "CURRENT" if require_revocations else "NOT_ASSERTED"
    if _revoked(
        revocations,
        keyid=signature["keyid"],
        identity=signature["identity"],
        receipt_ts=receipt_ts,
    ):
        raise EnterpriseReceiptError(
            "E_SIGNER_REVOKED", "signer was revoked at receipt timestamp"
        )
    status = "FRESH_CHECKED" if require_revocations else "CHECKED"
    return status, freshness, age


def verify_receipt_v2(
    path: Path,
    trust_root_path: Path,
    policy_bundle_path: Path | None = None,
    revocations_path: Path | None = None,
    *,
    require_revocations: bool = False,
    max_revocation_age_seconds: int = DEFAULT_MAX_REVOCATION_AGE_SECONDS,
    now: datetime | None = None,
) -> dict:
    """Verify DSSE, identity, policy, and revocation or raise EnterpriseReceiptError."""
    envelope = _read_json(Path(path))
    if envelope.get("schema") != DSSE_SCHEMA:
        if str(envelope.get("schema", "")).startswith("factory.receipt.v1"):
            return {
                "schema": RESULT_SCHEMA,
                "verdict": "LEGACY_UNVERIFIED",
                "path": str(Path(path).resolve()),
            }
        raise EnterpriseReceiptError(
            "E_INVALID_ENVELOPE", "expected a DSSE Receipt v2 envelope"
        )
    trust_root = _validate_trust_root(_read_json(Path(trust_root_path)))
    payload, signature, _ = _verify_envelope(
        envelope, expected_payload_type=RECEIPT_PAYLOAD_TYPE, trust_root=trust_root
    )
    validate_receipt_v2(payload)
    receipt_ts = _timestamp(payload["ts"])
    policy_status = _verify_policy_status(
        payload, trust_root=trust_root, policy_bundle_path=policy_bundle_path
    )
    revocation_status, revocation_freshness, revocation_age_seconds = (
        _verify_revocation_status(
            signature=signature,
            receipt_ts=receipt_ts,
            trust_root=trust_root,
            revocations_path=revocations_path,
            require_revocations=require_revocations,
            max_revocation_age_seconds=max_revocation_age_seconds,
            now=now,
        )
    )
    return {
        "schema": RESULT_SCHEMA,
        "verdict": "VERIFIED",
        "verification": "offline_dsse_ed25519",
        "receipt_sha256": _sha256(_canonical(payload)),
        "tenant_id": payload["tenant_id"],
        "identity": signature["identity"],
        "issuer": signature["issuer"],
        "keyid": signature["keyid"],
        "policy_status": policy_status,
        "revocation_status": revocation_status,
        "revocation_freshness": revocation_freshness,
        "revocation_age_seconds": revocation_age_seconds,
        "authority": "none",
    }


def sign_policy_bundle(
    policy: dict,
    private_key_path: Path,
    keyid: str,
    identity: str,
    issuer: str,
    out: Path,
) -> dict:
    """Sign and persist a policy bundle or raise EnterpriseReceiptError on invalid input."""
    if not isinstance(policy, dict):
        raise EnterpriseReceiptError("E_INVALID_POLICY", "policy must be an object")
    policy_bytes = _canonical(policy)
    payload = {
        "schema": POLICY_BUNDLE_SCHEMA,
        "policy_sha256": _sha256(policy_bytes),
        "policy": policy,
        "created_at": _now(),
    }
    envelope = sign_payload(
        payload,
        payload_type=POLICY_PAYLOAD_TYPE,
        private_key_path=private_key_path,
        keyid=keyid,
        identity=identity,
        issuer=issuer,
    )
    _write_json(Path(out), envelope)
    return envelope


def sign_revocations(
    entries: list[dict],
    private_key_path: Path,
    keyid: str,
    identity: str,
    issuer: str,
    out: Path,
) -> dict:
    """Sign a revocation list or raise EnterpriseReceiptError on malformed entries."""
    if not isinstance(entries, list) or any(
        not isinstance(item, dict) for item in entries
    ):
        raise EnterpriseReceiptError(
            "E_INVALID_REVOCATIONS", "entries must be a list of objects"
        )
    payload = {"schema": REVOCATIONS_SCHEMA, "generated_at": _now(), "entries": entries}
    envelope = sign_payload(
        payload,
        payload_type=REVOCATIONS_PAYLOAD_TYPE,
        private_key_path=private_key_path,
        keyid=keyid,
        identity=identity,
        issuer=issuer,
    )
    _write_json(Path(out), envelope)
    return envelope


def generate_key_material(
    *, out_dir: Path, keyid: str, identity: str, issuer: str
) -> dict:
    """Generate local Ed25519 material or raise EnterpriseReceiptError fail closed."""
    _require_crypto()
    if not all(
        isinstance(value, str) and value.strip() for value in (keyid, identity, issuer)
    ):
        raise EnterpriseReceiptError(
            "E_IDENTITY_REQUIRED", "key id, identity, and issuer are required"
        )
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_path = out_dir / f"{keyid}.private.pem"
    public_path = out_dir / f"{keyid}.public.b64"
    trust_path = out_dir / "trust-root.json"
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_b64 = _b64e(
        private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    public_path.write_text(public_b64 + "\n", encoding="ascii")
    _write_json(
        trust_path,
        {
            "schema": TRUST_ROOT_SCHEMA,
            "version": 1,
            "keys": [
                {
                    "keyid": keyid,
                    "algorithm": "ed25519",
                    "public_key": public_b64,
                    "identity": identity,
                    "issuer": issuer,
                }
            ],
        },
    )
    return {
        "private_key": str(private_path),
        "public_key": str(public_path),
        "trust_root": str(trust_path),
        "keyid": keyid,
        "identity": identity,
        "issuer": issuer,
    }


"""factoryline.enterprise_receipts - offline signed-entitlement verification.

A commercial entitlement is a DSSE Ed25519 envelope (the same offline envelope
machinery as enterprise_receipts) whose payload names:

- the human seat subject it belongs to,
- the product and the EXACT covered version range (min and max),
- its validity window (not_before / not_after),
- the seat count.

Verification authenticates the issuer against a separately configured
commercial trust root. There is no embedded issuer private key, no credential
collection and no network call anywhere in this module.

Two deliberate constraints keep grants honest:

- covered_versions.max is REQUIRED. An open-ended "all future versions" grant
  cannot be issued, because the covered future versions are an explicit
  per-entitlement decision, not a silent default.
- An entitlement authenticates an issuer statement; it does not make
  user-controlled code or counters tamper-proof, and existing MIT/Apache
  grants for prior releases are untouched by it.
"""


ENTITLEMENT_SCHEMA = "factory.commercial.entitlement.v1"
ENTITLEMENT_PAYLOAD_TYPE = "application/vnd.factory.commercial.entitlement.v1+json"
PRODUCT = "code-factory"
TRUST_ROOT_FILENAME = "commercial-trust-root.json"
ENTITLEMENTS_DIR = "entitlements"


class CommercialEntitlementError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _commercial_entitlement_utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _parse_instant(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise CommercialEntitlementError(
            "E_ENTITLEMENT_FIELD", f"{field_name} is required"
        )
    try:
        return _commercial_entitlement_utc(
            datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        )
    except ValueError as exc:
        raise CommercialEntitlementError(
            "E_ENTITLEMENT_FIELD", f"{field_name} must be an ISO timestamp"
        ) from exc


def _version_key(version: str) -> tuple:
    parts = re.split(r"[^0-9A-Za-z]+", version)
    key: list[tuple[int, Any]] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return tuple(key)


def version_in_range(version: str, minimum: str, maximum: str) -> bool:
    """Check inclusive explicit minimum and maximum version bounds."""
    return _version_key(minimum) <= _version_key(version) <= _version_key(maximum)


@dataclass(frozen=True)
class Entitlement:
    entitlement_id: str
    subject: str
    product: str
    version_min: str
    version_max: str
    seats: int
    not_before: datetime
    not_after: datetime
    payload_sha256: str

    def covers(
        self, *, subject: str, product: str, version: str, now: datetime
    ) -> bool:
        """Check subject, product, version and validity-window coverage."""
        return (
            self.subject == subject
            and self.product == product
            and version_in_range(version, self.version_min, self.version_max)
            and self.not_before <= _commercial_entitlement_utc(now) <= self.not_after
        )

    def as_dict(self) -> dict[str, Any]:
        """Return the stable JSON-serializable public representation."""
        return {
            "entitlement_id": self.entitlement_id,
            "subject": self.subject,
            "product": self.product,
            "covered_versions": {"min": self.version_min, "max": self.version_max},
            "seats": self.seats,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "payload_sha256": self.payload_sha256,
        }


def entitlement_from_payload(
    payload: dict[str, Any], *, payload_sha256: str
) -> Entitlement:
    """Validate the commercial payload and return its immutable view."""

    def fail(code: str, message: str) -> NoReturn:
        raise CommercialEntitlementError(code, message)

    if not isinstance(payload, dict) or payload.get("schema") != ENTITLEMENT_SCHEMA:
        fail("E_ENTITLEMENT_SCHEMA", f"payload schema must be {ENTITLEMENT_SCHEMA}")
    for name in ("entitlement_id", "subject", "product"):
        if not isinstance(payload.get(name), str) or not payload[name].strip():
            fail("E_ENTITLEMENT_FIELD", f"{name} is required")
    versions = payload.get("covered_versions")
    if not isinstance(versions, dict):
        fail("E_ENTITLEMENT_FIELD", "covered_versions block is required")
    # covered_versions.max is required on purpose: no silent open-ended grants
    # over future versions. Each entitlement names its exact coverage ceiling.
    for name in ("min", "max"):
        if not isinstance(versions.get(name), str) or not versions[name].strip():
            fail(
                "E_ENTITLEMENT_VERSIONS",
                f"covered_versions.{name} must be an explicit version; "
                "open-ended future-version grants are not issuable",
            )
    seats = payload.get("seats")
    if not isinstance(seats, int) or isinstance(seats, bool) or seats < 1:
        fail("E_ENTITLEMENT_FIELD", "seats must be a positive integer")
    not_before = _parse_instant(payload.get("not_before"), "not_before")
    not_after = _parse_instant(payload.get("not_after"), "not_after")
    if not_before >= not_after:
        fail("E_ENTITLEMENT_WINDOW", "not_before must be before not_after")
    return Entitlement(
        entitlement_id=payload["entitlement_id"].strip(),
        subject=payload["subject"].strip(),
        product=payload["product"].strip(),
        version_min=versions["min"].strip(),
        version_max=versions["max"].strip(),
        seats=seats,
        not_before=not_before,
        not_after=not_after,
        payload_sha256=payload_sha256,
    )


def verify_entitlement_envelope(
    envelope: dict[str, Any], *, trust_root: dict[str, Any]
) -> Entitlement:
    """Verify one entitlement envelope against an explicit offline trust root."""
    try:
        verified = verify_signed_document_value(
            envelope,
            payload_type=ENTITLEMENT_PAYLOAD_TYPE,
            schema=ENTITLEMENT_SCHEMA,
            trust_root=trust_root,
        )
    except EnterpriseReceiptError as exc:
        raise CommercialEntitlementError(exc.code, exc.message) from exc
    return entitlement_from_payload(
        verified["payload"], payload_sha256=verified["payload_sha256"]
    )


def sign_entitlement(
    payload: dict[str, Any],
    *,
    private_key_path: str | Path,
    keyid: str,
    identity: str,
    issuer: str,
) -> dict[str, Any]:
    """Sign one entitlement payload. Issuer tooling only; never called at runtime."""
    entitlement_from_payload(payload, payload_sha256="unsigned")
    try:
        return sign_payload(
            payload,
            payload_type=ENTITLEMENT_PAYLOAD_TYPE,
            private_key_path=Path(private_key_path),
            keyid=keyid,
            identity=identity,
            issuer=issuer,
        )
    except EnterpriseReceiptError as exc:
        raise CommercialEntitlementError(exc.code, exc.message) from exc


def _commercial_read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CommercialEntitlementError("E_ENTITLEMENT_IO", str(exc)) from exc


def import_entitlement(
    envelope_path: str | Path,
    *,
    trust_root_path: str | Path,
    home: str | Path | None = None,
) -> Entitlement:
    """Verify, then store one entitlement and its trust root locally.

    The stored copy is re-verified against the stored trust root on every load;
    importing never skips verification.
    """
    envelope_path = Path(envelope_path)
    trust_root_path = Path(trust_root_path)
    envelope = _commercial_read_json(envelope_path)
    trust_root = _commercial_read_json(trust_root_path)
    if not isinstance(envelope, dict):
        raise CommercialEntitlementError(
            "E_ENTITLEMENT_SCHEMA", "entitlement envelope must be an object"
        )
    entitlement = verify_entitlement_envelope(envelope, trust_root=trust_root)
    base = Path(home) if home is not None else default_home()
    entitlements_dir = base / ENTITLEMENTS_DIR
    entitlements_dir.mkdir(parents=True, exist_ok=True)
    stored_root = base / TRUST_ROOT_FILENAME
    if stored_root.exists():
        existing = _commercial_read_json(stored_root)
        if existing != trust_root:
            raise CommercialEntitlementError(
                "E_TRUST_ROOT_CONFLICT",
                "a different commercial trust root is already imported; "
                "refusing to mix issuers silently",
            )
    else:
        shutil.copyfile(trust_root_path, stored_root)
    target = entitlements_dir / f"{entitlement.payload_sha256}.json"
    target.write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return entitlement


def load_entitlements(home: str | Path | None = None) -> list[Entitlement]:
    """Load and re-verify every imported entitlement. Tampered copies are dropped."""
    base = Path(home) if home is not None else default_home()
    entitlements_dir = base / ENTITLEMENTS_DIR
    stored_root = base / TRUST_ROOT_FILENAME
    if not entitlements_dir.is_dir() or not stored_root.exists():
        return []
    trust_root = _commercial_read_json(stored_root)
    valid: list[Entitlement] = []
    for path in sorted(entitlements_dir.glob("*.json")):
        envelope = _commercial_read_json(path)
        if not isinstance(envelope, dict):
            continue
        try:
            valid.append(verify_entitlement_envelope(envelope, trust_root=trust_root))
        except CommercialEntitlementError:
            continue
    return valid


def covering_entitlement(
    entitlements: list[Entitlement],
    *,
    subject: str,
    product: str,
    version: str,
    now: datetime,
) -> Entitlement | None:
    """Return the first entitlement covering this exact subject and version."""
    for entitlement in entitlements:
        if entitlement.covers(
            subject=subject, product=product, version=version, now=now
        ):
            return entitlement
    return None

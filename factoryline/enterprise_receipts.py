"""Offline-verifiable Receipt v2, policy, and revocation envelopes.

The module implements the small DSSE subset needed by FactoryLine. It keeps
networked Sigstore verification as a separate v1 compatibility path and uses
Ed25519 plus an explicit local trust root for offline enterprise checks.
"""
from __future__ import annotations

from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    serialization = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None

    class InvalidSignature(Exception):
        pass


RECEIPT_V2_SCHEMA = "factory.receipt.v2"
POLICY_BUNDLE_SCHEMA = "factory.policy.bundle.v1"
REVOCATIONS_SCHEMA = "factory.revocations.v1"
TRUST_ROOT_SCHEMA = "factory.trust.root.v1"
DSSE_SCHEMA = "factory.dsse.envelope.v1"
RECEIPT_PAYLOAD_TYPE = "application/vnd.factory.receipt.v2+json"
POLICY_PAYLOAD_TYPE = "application/vnd.factory.policy.bundle.v1+json"
REVOCATIONS_PAYLOAD_TYPE = "application/vnd.factory.revocations.v1+json"
RESULT_SCHEMA = "factory.enterprise.result.v1"


class EnterpriseReceiptError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _require_crypto() -> None:
    if Ed25519PrivateKey is None or Ed25519PublicKey is None:
        raise EnterpriseReceiptError("E_CRYPTO_UNAVAILABLE", "install with: pip install factoryline-code-factory[enterprise]")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", str(exc)) from exc


def canonical_json(value: Any) -> bytes:
    """Return the stable UTF-8 bytes used by every enterprise digest."""
    return _canonical(value)


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64d(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise EnterpriseReceiptError("E_INVALID_ENVELOPE", f"{field} is required")
    try:
        return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnterpriseReceiptError("E_INVALID_ENVELOPE", f"invalid {field}") from exc


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
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnterpriseReceiptError("E_INVALID_JSON", str(exc)) from exc
    if not isinstance(value, dict):
        raise EnterpriseReceiptError("E_INVALID_JSON", "top-level JSON must be an object")
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
        raise EnterpriseReceiptError("E_INVALID_RECEIPT", "invalid receipt timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_receipt_v2(payload: dict) -> dict:
    required = {"schema", "module", "stage", "feature", "ok", "tenant_id", "run_id", "ts"}
    if payload.get("schema") != RECEIPT_V2_SCHEMA:
        raise EnterpriseReceiptError("E_INVALID_RECEIPT", "schema must be factory.receipt.v2")
    missing = sorted(required - payload.keys())
    if missing:
        raise EnterpriseReceiptError("E_INVALID_RECEIPT", f"missing fields: {missing}")
    for field in ("module", "stage", "feature", "tenant_id", "run_id", "ts"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise EnterpriseReceiptError("E_INVALID_RECEIPT", f"{field} must be non-empty")
    if not isinstance(payload["ok"], bool):
        raise EnterpriseReceiptError("E_INVALID_RECEIPT", "ok must be boolean")
    _timestamp(payload["ts"])
    for field in ("policy_sha256", "subject_sha256"):
        if field in payload and (not isinstance(payload[field], str) or len(payload[field]) != 64 or any(ch not in "0123456789abcdef" for ch in payload[field].lower())):
            raise EnterpriseReceiptError("E_INVALID_RECEIPT", f"{field} must be a SHA-256 hex digest")
    return payload


def receipt_v2_from_v1(payload: dict, *, tenant_id: str = "local", policy_sha256: str | None = None) -> dict:
    """Convert a readable v1 receipt into an explicitly tenant-bound v2 payload."""
    if not isinstance(payload, dict) or not str(payload.get("schema", "")).startswith("factory.receipt."):
        raise EnterpriseReceiptError("E_INVALID_RECEIPT", "input is not a factory receipt")
    converted = dict(payload)
    converted.update({
        "schema": RECEIPT_V2_SCHEMA,
        "tenant_id": tenant_id,
        "run_id": str(payload.get("run_id") or hashlib.sha256(_canonical(payload)).hexdigest()[:32]),
        "ts": str(payload.get("ts") or _now()),
    })
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
            key = Ed25519PrivateKey.from_private_bytes(_b64d(raw.decode("ascii").strip(), "private_key"))
        except (ValueError, UnicodeDecodeError, EnterpriseReceiptError) as exc:
            raise EnterpriseReceiptError("E_PRIVATE_KEY_INVALID", "expected Ed25519 PEM or base64 key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EnterpriseReceiptError("E_PRIVATE_KEY_INVALID", "key is not Ed25519")
    return key


def _load_public_key(value: str):
    _require_crypto()
    raw = _b64d(value, "public_key")
    if len(raw) != 32:
        raise EnterpriseReceiptError("E_TRUST_ROOT_INVALID", "Ed25519 public key must be 32 bytes")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise EnterpriseReceiptError("E_TRUST_ROOT_INVALID", "invalid Ed25519 public key") from exc


def _signature_metadata(*, keyid: str, identity: str, issuer: str, signature: bytes) -> dict:
    if not all(isinstance(value, str) and value.strip() for value in (keyid, identity, issuer)):
        raise EnterpriseReceiptError("E_IDENTITY_REQUIRED", "key id, identity, and issuer are required")
    return {"keyid": keyid, "algorithm": "ed25519", "identity": identity, "issuer": issuer, "sig": _b64e(signature)}


def sign_payload(payload: dict, *, payload_type: str, private_key_path: Path, keyid: str, identity: str, issuer: str) -> dict:
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
        "signatures": [_signature_metadata(keyid=keyid, identity=identity, issuer=issuer, signature=signature)],
    }


def seal_receipt_v2(payload: dict, private_key_path: Path, keyid: str, identity: str, issuer: str, out: Path) -> dict:
    validate_receipt_v2(payload)
    envelope = sign_payload(payload, payload_type=RECEIPT_PAYLOAD_TYPE, private_key_path=private_key_path, keyid=keyid, identity=identity, issuer=issuer)
    _write_json(Path(out), envelope)
    return envelope


def _validate_trust_root(root: dict) -> dict:
    if root.get("schema") != TRUST_ROOT_SCHEMA or not isinstance(root.get("keys"), list):
        raise EnterpriseReceiptError("E_TRUST_ROOT_INVALID", "invalid trust root schema")
    return root


def _verify_envelope(envelope: dict, *, expected_payload_type: str, trust_root: dict) -> tuple[dict, dict, bytes]:
    if envelope.get("schema") != DSSE_SCHEMA:
        raise EnterpriseReceiptError("E_INVALID_ENVELOPE", "unsupported DSSE envelope schema")
    if envelope.get("payloadType") != expected_payload_type:
        raise EnterpriseReceiptError("E_PAYLOAD_TYPE_MISMATCH", "unexpected DSSE payload type")
    payload_bytes = _b64d(envelope.get("payload"), "payload")
    if envelope.get("payload_sha256") != _sha256(payload_bytes):
        raise EnterpriseReceiptError("E_PAYLOAD_DIGEST_MISMATCH", "payload digest does not match bytes")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise EnterpriseReceiptError("E_UNSUPPORTED_SIGNATURE", "exactly one Ed25519 signature is required")
    signature = signatures[0]
    if not isinstance(signature, dict) or signature.get("algorithm") != "ed25519":
        raise EnterpriseReceiptError("E_UNSUPPORTED_SIGNATURE", "only Ed25519 signatures are supported")
    keyid = signature.get("keyid")
    key = next((item for item in trust_root["keys"] if isinstance(item, dict) and item.get("keyid") == keyid), None)
    if key is None:
        raise EnterpriseReceiptError("E_UNKNOWN_KEY", f"untrusted key id: {keyid}")
    if signature.get("identity") != key.get("identity") or signature.get("issuer") != key.get("issuer"):
        raise EnterpriseReceiptError("E_IDENTITY_MISMATCH", "signature identity or issuer differs from trust root")
    public_key = _load_public_key(key.get("public_key"))
    try:
        public_key.verify(_b64d(signature.get("sig"), "signature"), dsse_pae(expected_payload_type, payload_bytes))
    except (InvalidSignature, ValueError):
        raise EnterpriseReceiptError("E_SIGNATURE_INVALID", "DSSE signature verification failed")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", str(exc)) from exc
    if not isinstance(payload, dict):
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", "DSSE payload must be an object")
    return payload, signature, payload_bytes


def _verify_signed_document(path: Path, *, payload_type: str, schema: str, trust_root: dict) -> tuple[dict, dict]:
    payload, signature, _ = _verify_envelope(_read_json(path), expected_payload_type=payload_type, trust_root=trust_root)
    if payload.get("schema") != schema:
        raise EnterpriseReceiptError("E_INVALID_PAYLOAD", f"expected {schema}")
    return payload, signature


def _revoked(revocations: dict, *, keyid: str, identity: str, receipt_ts: datetime) -> bool:
    for entry in revocations.get("entries", []):
        if not isinstance(entry, dict) or (entry.get("keyid") != keyid and entry.get("identity") != identity):
            continue
        revoked_at = entry.get("revoked_at")
        if isinstance(revoked_at, str) and _timestamp(revoked_at) <= receipt_ts:
            return True
    return False


def verify_receipt_v2(path: Path, trust_root_path: Path, policy_bundle_path: Path | None = None, revocations_path: Path | None = None) -> dict:
    envelope = _read_json(Path(path))
    if envelope.get("schema") != DSSE_SCHEMA:
        if str(envelope.get("schema", "")).startswith("factory.receipt.v1"):
            return {"schema": RESULT_SCHEMA, "verdict": "LEGACY_UNVERIFIED", "path": str(Path(path).resolve())}
        raise EnterpriseReceiptError("E_INVALID_ENVELOPE", "expected a DSSE Receipt v2 envelope")
    trust_root = _validate_trust_root(_read_json(Path(trust_root_path)))
    payload, signature, _ = _verify_envelope(envelope, expected_payload_type=RECEIPT_PAYLOAD_TYPE, trust_root=trust_root)
    validate_receipt_v2(payload)
    receipt_ts = _timestamp(payload["ts"])
    policy_status = "NOT_DECLARED"
    if payload.get("policy_sha256"):
        if policy_bundle_path is None:
            raise EnterpriseReceiptError("E_POLICY_REQUIRED", "receipt declares policy_sha256 but no bundle was supplied")
        policy, _ = _verify_signed_document(Path(policy_bundle_path), payload_type=POLICY_PAYLOAD_TYPE, schema=POLICY_BUNDLE_SCHEMA, trust_root=trust_root)
        if policy.get("policy_sha256") != payload["policy_sha256"]:
            raise EnterpriseReceiptError("E_POLICY_DIGEST_MISMATCH", "receipt and policy bundle digests differ")
        policy_status = "VERIFIED"
    revocation_status = "NOT_CHECKED"
    if revocations_path is not None:
        revocations, _ = _verify_signed_document(Path(revocations_path), payload_type=REVOCATIONS_PAYLOAD_TYPE, schema=REVOCATIONS_SCHEMA, trust_root=trust_root)
        if _revoked(revocations, keyid=signature["keyid"], identity=signature["identity"], receipt_ts=receipt_ts):
            raise EnterpriseReceiptError("E_SIGNER_REVOKED", "signer was revoked at receipt timestamp")
        revocation_status = "CHECKED"
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
    }


def sign_policy_bundle(policy: dict, private_key_path: Path, keyid: str, identity: str, issuer: str, out: Path) -> dict:
    if not isinstance(policy, dict):
        raise EnterpriseReceiptError("E_INVALID_POLICY", "policy must be an object")
    policy_bytes = _canonical(policy)
    payload = {"schema": POLICY_BUNDLE_SCHEMA, "policy_sha256": _sha256(policy_bytes), "policy": policy, "created_at": _now()}
    envelope = sign_payload(payload, payload_type=POLICY_PAYLOAD_TYPE, private_key_path=private_key_path, keyid=keyid, identity=identity, issuer=issuer)
    _write_json(Path(out), envelope)
    return envelope


def sign_revocations(entries: list[dict], private_key_path: Path, keyid: str, identity: str, issuer: str, out: Path) -> dict:
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise EnterpriseReceiptError("E_INVALID_REVOCATIONS", "entries must be a list of objects")
    payload = {"schema": REVOCATIONS_SCHEMA, "generated_at": _now(), "entries": entries}
    envelope = sign_payload(payload, payload_type=REVOCATIONS_PAYLOAD_TYPE, private_key_path=private_key_path, keyid=keyid, identity=identity, issuer=issuer)
    _write_json(Path(out), envelope)
    return envelope


def generate_key_material(*, out_dir: Path, keyid: str, identity: str, issuer: str) -> dict:
    _require_crypto()
    if not all(isinstance(value, str) and value.strip() for value in (keyid, identity, issuer)):
        raise EnterpriseReceiptError("E_IDENTITY_REQUIRED", "key id, identity, and issuer are required")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_path = out_dir / f"{keyid}.private.pem"
    public_path = out_dir / f"{keyid}.public.b64"
    trust_path = out_dir / "trust-root.json"
    private_path.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_b64 = _b64e(private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    public_path.write_text(public_b64 + "\n", encoding="ascii")
    _write_json(trust_path, {"schema": TRUST_ROOT_SCHEMA, "version": 1, "keys": [{"keyid": keyid, "algorithm": "ed25519", "public_key": public_b64, "identity": identity, "issuer": issuer}]})
    return {"private_key": str(private_path), "public_key": str(public_path), "trust_root": str(trust_path), "keyid": keyid, "identity": identity, "issuer": issuer}

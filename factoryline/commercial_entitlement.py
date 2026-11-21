"""factoryline.commercial_entitlement - offline signed-entitlement verification.

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

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
from typing import Any

from .commercial_usage import default_home
from .enterprise_receipts import (
    EnterpriseReceiptError,
    sign_payload,
    verify_signed_document_value,
)

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


def _utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def _parse_instant(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise CommercialEntitlementError(
            "E_ENTITLEMENT_FIELD", f"{field_name} is required"
        )
    try:
        return _utc(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
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

    def covers(self, *, subject: str, product: str, version: str, now: datetime) -> bool:
        return (
            self.subject == subject
            and self.product == product
            and version_in_range(version, self.version_min, self.version_max)
            and self.not_before <= _utc(now) <= self.not_after
        )

    def as_dict(self) -> dict[str, Any]:
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


def entitlement_from_payload(payload: dict[str, Any], *, payload_sha256: str) -> Entitlement:
    def fail(code: str, message: str) -> None:
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


def verify_entitlement_envelope(envelope: dict[str, Any], *, trust_root: dict[str, Any]) -> Entitlement:
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


def _read_json(path: Path) -> Any:
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
    envelope = _read_json(envelope_path)
    trust_root = _read_json(trust_root_path)
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
        existing = _read_json(stored_root)
        if existing != trust_root:
            raise CommercialEntitlementError(
                "E_TRUST_ROOT_CONFLICT",
                "a different commercial trust root is already imported; "
                "refusing to mix issuers silently",
            )
    else:
        shutil.copyfile(trust_root_path, stored_root)
    target = entitlements_dir / f"{entitlement.payload_sha256}.json"
    target.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return entitlement


def load_entitlements(home: str | Path | None = None) -> list[Entitlement]:
    """Load and re-verify every imported entitlement. Tampered copies are dropped."""
    base = Path(home) if home is not None else default_home()
    entitlements_dir = base / ENTITLEMENTS_DIR
    stored_root = base / TRUST_ROOT_FILENAME
    if not entitlements_dir.is_dir() or not stored_root.exists():
        return []
    trust_root = _read_json(stored_root)
    valid: list[Entitlement] = []
    for path in sorted(entitlements_dir.glob("*.json")):
        envelope = _read_json(path)
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
    for entitlement in entitlements:
        if entitlement.covers(subject=subject, product=product, version=version, now=now):
            return entitlement
    return None

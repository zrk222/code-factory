"""Offline mutation challenge for the enterprise receipt verification chain."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import tempfile

from .enterprise_receipts import (
    EnterpriseReceiptError,
    canonical_json,
    generate_key_material,
    seal_receipt_v2,
    sign_revocations,
    verify_receipt_v2,
)


MUTATION_GATE_SCHEMA = "factory.enterprise.receipt-mutation-gate.v1"
IDENTITY = "urn:code-factory:offline-receipt-challenge"
ISSUER = "urn:code-factory:local-ephemeral-issuer"


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value) + b"\n")


def _receipt_payload() -> dict[str, Any]:
    return {
        "schema": "factory.receipt.v2",
        "module": "factoryline",
        "stage": "verify-receipts",
        "feature": "receipt-mutation-gate",
        "ok": True,
        "tenant_id": "local-challenge",
        "run_id": "receipt-mutation-control",
        "ts": "2026-07-18T00:00:00+00:00",
    }


def _challenge(
    name: str,
    expected_code: str,
    verifier: Any,
) -> dict[str, Any]:
    observed_code: str
    message = ""
    try:
        verifier()
        observed_code = "VERIFIED"
    except EnterpriseReceiptError as exc:
        observed_code = exc.code
        message = exc.message
    except Exception as exc:  # The gate must record an unexpected verifier failure, never call it a pass.
        observed_code = f"UNCLASSIFIED:{type(exc).__name__}"
        message = str(exc)
    return {
        "name": name,
        "expected_code": expected_code,
        "observed_code": observed_code,
        "rejected": observed_code == expected_code,
        "message": message,
    }


def verify_receipt_mutations(root: Path, out: Path | None = None) -> dict[str, Any]:
    """Challenge Receipt v2 digest, signature, identity, and revocation checks offline."""
    root = Path(root).resolve()
    output = Path(out) if out is not None else root / ".factory" / "challenges" / "verify-receipts.json"
    if not output.is_absolute():
        output = root / output

    with tempfile.TemporaryDirectory(prefix="factory-receipt-challenge-") as temporary:
        workspace = Path(temporary)
        keys = generate_key_material(
            out_dir=workspace / "keys",
            keyid="receipt-mutation-key",
            identity=IDENTITY,
            issuer=ISSUER,
        )
        control_path = workspace / "control.dsse.json"
        seal_receipt_v2(
            _receipt_payload(),
            private_key_path=Path(keys["private_key"]),
            keyid=keys["keyid"],
            identity=keys["identity"],
            issuer=keys["issuer"],
            out=control_path,
        )
        trust_root = Path(keys["trust_root"])
        control = verify_receipt_v2(control_path, trust_root_path=trust_root)
        envelope = json.loads(control_path.read_text(encoding="utf-8"))

        flipped = copy.deepcopy(envelope)
        flipped_payload = bytearray(_b64d(flipped["payload"]))
        flipped_payload[len(flipped_payload) // 2] ^= 1
        flipped["payload"] = _b64e(bytes(flipped_payload))
        flipped_path = workspace / "payload-byte-flip.dsse.json"
        _write(flipped_path, flipped)

        rebound = copy.deepcopy(flipped)
        rebound["payload_sha256"] = hashlib.sha256(bytes(flipped_payload)).hexdigest()
        rebound_path = workspace / "digest-rebound.dsse.json"
        _write(rebound_path, rebound)

        swapped = copy.deepcopy(envelope)
        swapped["signatures"][0]["identity"] = "https://example.invalid/swapped-identity"
        swapped_path = workspace / "identity-swap.dsse.json"
        _write(swapped_path, swapped)

        revocations_path = workspace / "backdated-revocations.dsse.json"
        sign_revocations(
            [{"keyid": keys["keyid"], "revoked_at": "2026-07-17T00:00:00+00:00", "reason": "mutation challenge"}],
            private_key_path=Path(keys["private_key"]),
            keyid=keys["keyid"],
            identity=keys["identity"],
            issuer=keys["issuer"],
            out=revocations_path,
        )

        mutations = [
            _challenge(
                "payload_byte_flip",
                "E_PAYLOAD_DIGEST_MISMATCH",
                lambda: verify_receipt_v2(flipped_path, trust_root_path=trust_root),
            ),
            _challenge(
                "digest_rebound_without_signature",
                "E_SIGNATURE_INVALID",
                lambda: verify_receipt_v2(rebound_path, trust_root_path=trust_root),
            ),
            _challenge(
                "identity_swap",
                "E_IDENTITY_MISMATCH",
                lambda: verify_receipt_v2(swapped_path, trust_root_path=trust_root),
            ),
            _challenge(
                "backdated_revocation",
                "E_SIGNER_REVOKED",
                lambda: verify_receipt_v2(
                    control_path,
                    trust_root_path=trust_root,
                    revocations_path=revocations_path,
                ),
            ),
        ]

    rejected = sum(item["rejected"] for item in mutations)
    passed = rejected == len(mutations)
    receipt = {
        "schema": MUTATION_GATE_SCHEMA,
        "passed": passed,
        "marker": "RECEIPT_MUTATIONS_REJECTED" if passed else "RECEIPT_MUTATION_SURVIVED",
        "control": {
            "verdict": control["verdict"],
            "receipt_sha256": control["receipt_sha256"],
            "verification": control["verification"],
        },
        "mutations": mutations,
        "attempted": len(mutations),
        "rejected": rejected,
        "offline_marker": "RECEIPT_CHALLENGE_OFFLINE",
        "ephemeral_private_keys_preserved": False,
        "authority": {
            "sign": False,
            "merge": False,
            "publish": False,
            "deploy": False,
            "connector_grant": False,
            "credential_access": False,
            "external_message": False,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    _write(output, receipt)
    return {**receipt, "path": str(output.resolve())}

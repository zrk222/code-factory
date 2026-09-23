"""Lazy CLI boundary for provider-neutral SaaS proof verification."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register SaaS proof verification and local receipt status commands."""
    saas = sub.add_parser(
        "saas",
        help="verify provider-neutral SaaS identity, billing, entitlement, and revocation evidence",
    )
    saas_sub = saas.add_subparsers(required=True, dest="saas_cmd")
    saas_verify = saas_sub.add_parser(
        "verify",
        help="compare local OAuth/OIDC and entitlement observations with a reviewed promise contract",
    )
    saas_verify.add_argument("--root", default=".")
    saas_verify.add_argument("--contract", required=True)
    saas_verify.add_argument("--evidence", required=True)
    saas_verify.add_argument("--out", default=".factory/saas-proof/latest.json")
    saas_verify.add_argument("--json", action="store_true")
    saas_status = saas_sub.add_parser(
        "status", help="read hash-valid local SaaS proof receipt status"
    )
    saas_status.add_argument("--root", default=".")
    saas_status.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch SaaS proof work without contacting providers or changing source."""
    from .saas_proof import SaasProofError, saas_proof_projection, verify_saas_proof

    root = Path(a.root).resolve()
    try:
        payload = (
            verify_saas_proof(root, Path(a.contract), Path(a.evidence), Path(a.out))
            if a.saas_cmd == "verify"
            else saas_proof_projection(root)
        )
    except (
        SaasProofError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        error = {
            "schema": "factory.saas-proof.error.v1",
            "marker": "SAAS_PROOF_REFUSED",
            "code": getattr(exc, "code", "SAAS_PROOF_INPUT_INVALID"),
            "message": str(exc),
        }
        print(
            json.dumps(error, indent=2, sort_keys=True)
            if a.json
            else f"saas {a.saas_cmd} refused: {error['code']}: {exc}",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else payload.get("marker", "SAAS_PROOF_OK")
    )
    return 0 if a.saas_cmd == "status" or payload.get("verdict") == "verified" else 1

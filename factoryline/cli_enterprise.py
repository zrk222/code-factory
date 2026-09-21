"""Bounded, lazily loaded enterprise receipt and enforcement CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMAND_GROUP = "enterprise"
OWNER = "enterprise-controls-maintainers"


def add_parser(sub: Any) -> None:
    """Register enterprise commands without importing signing engines."""
    s = sub.add_parser(
        "enterprise", help="create and verify offline Receipt v2 evidence"
    )
    enterprise_sub = s.add_subparsers(required=True, dest="enterprise_cmd")
    keygen = enterprise_sub.add_parser(
        "keygen", help="generate Ed25519 key material and a local trust root"
    )
    keygen.add_argument("--out-dir", required=True)
    keygen.add_argument("--keyid", required=True)
    keygen.add_argument("--identity", required=True)
    keygen.add_argument("--issuer", required=True)
    seal = enterprise_sub.add_parser(
        "receipt-seal", help="sign a Receipt v2 payload into a DSSE envelope"
    )
    seal.add_argument("payload")
    seal.add_argument("--private-key", required=True)
    seal.add_argument("--keyid", required=True)
    seal.add_argument("--identity", required=True)
    seal.add_argument("--issuer", required=True)
    seal.add_argument("--out", required=True)
    verify = enterprise_sub.add_parser(
        "verify", help="verify Receipt v2, policy, and revocation evidence offline"
    )
    verify.add_argument("envelope")
    verify.add_argument("--trust-root", required=True)
    verify.add_argument("--policy-bundle")
    verify.add_argument("--revocations")
    verify.add_argument(
        "--require-revocations",
        action="store_true",
        help="require a signed current revocation snapshot",
    )
    verify.add_argument(
        "--max-revocation-age",
        type=int,
        default=86400,
        help="maximum revocation snapshot age in seconds",
    )
    policy = enterprise_sub.add_parser(
        "policy-sign", help="sign a policy JSON document into a policy bundle"
    )
    policy.add_argument("policy")
    policy.add_argument("--private-key", required=True)
    policy.add_argument("--keyid", required=True)
    policy.add_argument("--identity", required=True)
    policy.add_argument("--issuer", required=True)
    policy.add_argument("--out", required=True)
    revocations = enterprise_sub.add_parser(
        "revocations-sign", help="sign a revocation entries JSON array"
    )
    revocations.add_argument("entries")
    revocations.add_argument("--private-key", required=True)
    revocations.add_argument("--keyid", required=True)
    revocations.add_argument("--identity", required=True)
    revocations.add_argument("--issuer", required=True)
    revocations.add_argument("--out", required=True)
    enforcement_identity = enterprise_sub.add_parser(
        "workload-identity-seal",
        help="sign a local workload identity reference document",
    )
    enforcement_identity.add_argument("payload")
    enforcement_identity.add_argument("--private-key", required=True)
    enforcement_identity.add_argument("--keyid", required=True)
    enforcement_identity.add_argument("--identity", required=True)
    enforcement_identity.add_argument("--issuer", required=True)
    enforcement_identity.add_argument("--out", required=True)
    enforcement_policy = enterprise_sub.add_parser(
        "enforcement-policy-seal", help="sign a tenant-bound PEP reference policy"
    )
    enforcement_policy.add_argument("payload")
    enforcement_policy.add_argument("--private-key", required=True)
    enforcement_policy.add_argument("--keyid", required=True)
    enforcement_policy.add_argument("--identity", required=True)
    enforcement_policy.add_argument("--issuer", required=True)
    enforcement_policy.add_argument("--out", required=True)
    enforcement_revocations = enterprise_sub.add_parser(
        "workload-revocations-seal", help="sign workload identity revocations"
    )
    enforcement_revocations.add_argument("entries")
    enforcement_revocations.add_argument("--private-key", required=True)
    enforcement_revocations.add_argument("--keyid", required=True)
    enforcement_revocations.add_argument("--identity", required=True)
    enforcement_revocations.add_argument("--issuer", required=True)
    enforcement_revocations.add_argument("--out", required=True)
    enforcement_authorize = enterprise_sub.add_parser(
        "authorize",
        help="record a local non-executing enterprise PEP reference decision",
    )
    enforcement_authorize.add_argument("request")
    enforcement_authorize.add_argument("--root", default=".")
    enforcement_authorize.add_argument("--workload-identity", required=True)
    enforcement_authorize.add_argument("--policy", required=True)
    enforcement_authorize.add_argument("--trust-root", required=True)
    enforcement_authorize.add_argument("--workload-revocations")
    enforcement_authorize.add_argument("--out", required=True)
    runner_admission = enterprise_sub.add_parser(
        "runner-admission-seal",
        help="seal one non-executing, decision-bound runner argv packet",
    )
    runner_admission.add_argument("payload")
    runner_admission.add_argument("--root", default=".")
    runner_admission.add_argument("--out", required=True)


def run(args: Any) -> int:
    """Execute one enterprise command and render its deterministic receipt."""
    a = args
    if a.cmd == "enterprise":
        from .enterprise_receipts import (
            EnterpriseReceiptError,
            generate_key_material,
            seal_receipt_v2,
            sign_policy_bundle,
            sign_revocations,
            verify_receipt_v2,
        )
        from .enterprise_enforcement import (
            EnterpriseEnforcementError,
            record_enterprise_decision,
            sign_enforcement_policy,
            sign_workload_identity,
            sign_workload_revocations,
        )
        from .enterprise_runner_admission import (
            EnterpriseRunnerAdmissionError,
            prepare_runner_admission,
        )

        try:
            if a.enterprise_cmd == "keygen":
                result = generate_key_material(
                    out_dir=Path(a.out_dir),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                )
            elif a.enterprise_cmd == "receipt-seal":
                payload = json.loads(Path(a.payload).read_text(encoding="utf-8"))
                result = seal_receipt_v2(
                    payload,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {
                    "schema": "factory.enterprise.result.v1",
                    "verdict": "SIGNED",
                    "path": str(Path(a.out).resolve()),
                    "payload_type": result["payloadType"],
                }
            elif a.enterprise_cmd == "verify":
                result = verify_receipt_v2(
                    Path(a.envelope),
                    trust_root_path=Path(a.trust_root),
                    policy_bundle_path=Path(a.policy_bundle)
                    if a.policy_bundle
                    else None,
                    revocations_path=Path(a.revocations) if a.revocations else None,
                    require_revocations=a.require_revocations,
                    max_revocation_age_seconds=a.max_revocation_age,
                )
            elif a.enterprise_cmd == "policy-sign":
                policy_payload = json.loads(Path(a.policy).read_text(encoding="utf-8"))
                signed = sign_policy_bundle(
                    policy_payload,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {
                    "schema": "factory.enterprise.result.v1",
                    "verdict": "SIGNED",
                    "path": str(Path(a.out).resolve()),
                    "payload_type": signed["payloadType"],
                }
            elif a.enterprise_cmd == "revocations-sign":
                entries = json.loads(Path(a.entries).read_text(encoding="utf-8"))
                signed = sign_revocations(
                    entries,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {
                    "schema": "factory.enterprise.result.v1",
                    "verdict": "SIGNED",
                    "path": str(Path(a.out).resolve()),
                    "payload_type": signed["payloadType"],
                }
            elif a.enterprise_cmd == "workload-identity-seal":
                payload = json.loads(Path(a.payload).read_text(encoding="utf-8"))
                signed = sign_workload_identity(
                    payload,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {
                    "schema": "factory.enterprise.result.v1",
                    "verdict": "SIGNED",
                    "path": str(Path(a.out).resolve()),
                    "payload_type": signed["payloadType"],
                }
            elif a.enterprise_cmd == "enforcement-policy-seal":
                payload = json.loads(Path(a.payload).read_text(encoding="utf-8"))
                signed = sign_enforcement_policy(
                    payload,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {
                    "schema": "factory.enterprise.result.v1",
                    "verdict": "SIGNED",
                    "path": str(Path(a.out).resolve()),
                    "payload_type": signed["payloadType"],
                }
            elif a.enterprise_cmd == "workload-revocations-seal":
                entries = json.loads(Path(a.entries).read_text(encoding="utf-8"))
                signed = sign_workload_revocations(
                    entries,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {
                    "schema": "factory.enterprise.result.v1",
                    "verdict": "SIGNED",
                    "path": str(Path(a.out).resolve()),
                    "payload_type": signed["payloadType"],
                }
            elif a.enterprise_cmd == "runner-admission-seal":
                result = prepare_runner_admission(
                    Path(a.root), Path(a.payload), Path(a.out)
                )
            else:
                request = json.loads(Path(a.request).read_text(encoding="utf-8"))
                result = record_enterprise_decision(
                    Path(a.root),
                    request,
                    Path(a.out),
                    workload_identity_path=Path(a.workload_identity),
                    policy_path=Path(a.policy),
                    trust_root_path=Path(a.trust_root),
                    revocations_path=Path(a.workload_revocations)
                    if a.workload_revocations
                    else None,
                )
        except (
            EnterpriseReceiptError,
            EnterpriseEnforcementError,
            EnterpriseRunnerAdmissionError,
            json.JSONDecodeError,
            OSError,
        ) as exc:
            if isinstance(
                exc,
                (
                    EnterpriseReceiptError,
                    EnterpriseEnforcementError,
                    EnterpriseRunnerAdmissionError,
                ),
            ):
                error = {"code": exc.code, "message": exc.message}
            else:
                error = {"code": "E_INPUT", "message": str(exc)}
            print(
                json.dumps(
                    {
                        "schema": "factory.enterprise.result.v1",
                        "verdict": "ERROR",
                        "error": error,
                    },
                    indent=2,
                )
            )
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

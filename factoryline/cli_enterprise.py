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


def _read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _signed_result(out: str | Path, signed: dict[str, Any]) -> dict[str, str]:
    return {
        "schema": "factory.enterprise.result.v1",
        "verdict": "SIGNED",
        "path": str(Path(out).resolve()),
        "payload_type": signed["payloadType"],
    }


def _run_receipt_command(
    a: Any,
    *,
    generate_key_material: Any,
    seal_receipt_v2: Any,
    verify_receipt_v2: Any,
    sign_policy_bundle: Any,
    sign_revocations: Any,
) -> tuple[bool, Any]:
    """Run one command from the Receipt v2 command family."""
    if a.enterprise_cmd == "keygen":
        result = generate_key_material(
            out_dir=Path(a.out_dir),
            keyid=a.keyid,
            identity=a.identity,
            issuer=a.issuer,
        )
        return True, result
    if a.enterprise_cmd == "receipt-seal":
        signed = seal_receipt_v2(
            _read_json(a.payload),
            private_key_path=Path(a.private_key),
            keyid=a.keyid,
            identity=a.identity,
            issuer=a.issuer,
            out=Path(a.out),
        )
        return True, _signed_result(a.out, signed)
    if a.enterprise_cmd == "verify":
        result = verify_receipt_v2(
            Path(a.envelope),
            trust_root_path=Path(a.trust_root),
            policy_bundle_path=Path(a.policy_bundle) if a.policy_bundle else None,
            revocations_path=Path(a.revocations) if a.revocations else None,
            require_revocations=a.require_revocations,
            max_revocation_age_seconds=a.max_revocation_age,
        )
        return True, result
    if a.enterprise_cmd == "policy-sign":
        signed = sign_policy_bundle(
            _read_json(a.policy),
            private_key_path=Path(a.private_key),
            keyid=a.keyid,
            identity=a.identity,
            issuer=a.issuer,
            out=Path(a.out),
        )
        return True, _signed_result(a.out, signed)
    if a.enterprise_cmd == "revocations-sign":
        signed = sign_revocations(
            _read_json(a.entries),
            private_key_path=Path(a.private_key),
            keyid=a.keyid,
            identity=a.identity,
            issuer=a.issuer,
            out=Path(a.out),
        )
        return True, _signed_result(a.out, signed)
    return False, None


def _run_enforcement_seal_command(
    a: Any,
    *,
    sign_workload_identity: Any,
    sign_enforcement_policy: Any,
    sign_workload_revocations: Any,
) -> tuple[bool, Any]:
    """Run one command that signs an enforcement reference artifact."""
    if a.enterprise_cmd == "workload-identity-seal":
        signed = sign_workload_identity(
            _read_json(a.payload),
            private_key_path=Path(a.private_key),
            keyid=a.keyid,
            identity=a.identity,
            issuer=a.issuer,
            out=Path(a.out),
        )
        return True, _signed_result(a.out, signed)
    if a.enterprise_cmd == "enforcement-policy-seal":
        signed = sign_enforcement_policy(
            _read_json(a.payload),
            private_key_path=Path(a.private_key),
            keyid=a.keyid,
            identity=a.identity,
            issuer=a.issuer,
            out=Path(a.out),
        )
        return True, _signed_result(a.out, signed)
    if a.enterprise_cmd == "workload-revocations-seal":
        signed = sign_workload_revocations(
            _read_json(a.entries),
            private_key_path=Path(a.private_key),
            keyid=a.keyid,
            identity=a.identity,
            issuer=a.issuer,
            out=Path(a.out),
        )
        return True, _signed_result(a.out, signed)
    return False, None


def _dispatch_enterprise_command(a: Any, engines: dict[str, Any]) -> Any:
    """Dispatch commands across separately bounded enterprise engine families."""
    matched, result = _run_receipt_command(
        a,
        generate_key_material=engines["generate_key_material"],
        seal_receipt_v2=engines["seal_receipt_v2"],
        verify_receipt_v2=engines["verify_receipt_v2"],
        sign_policy_bundle=engines["sign_policy_bundle"],
        sign_revocations=engines["sign_revocations"],
    )
    if matched:
        return result
    matched, result = _run_enforcement_seal_command(
        a,
        sign_workload_identity=engines["sign_workload_identity"],
        sign_enforcement_policy=engines["sign_enforcement_policy"],
        sign_workload_revocations=engines["sign_workload_revocations"],
    )
    if matched:
        return result
    if a.enterprise_cmd == "runner-admission-seal":
        return engines["prepare_runner_admission"](
            Path(a.root), Path(a.payload), Path(a.out)
        )
    return engines["record_enterprise_decision"](
        Path(a.root),
        _read_json(a.request),
        Path(a.out),
        workload_identity_path=Path(a.workload_identity),
        policy_path=Path(a.policy),
        trust_root_path=Path(a.trust_root),
        revocations_path=Path(a.workload_revocations)
        if a.workload_revocations
        else None,
    )


def _enterprise_error(
    exc: Exception, engine_errors: tuple[type[Exception], ...]
) -> dict[str, str]:
    if isinstance(exc, engine_errors):
        return {"code": exc.code, "message": exc.message}
    return {"code": "E_INPUT", "message": str(exc)}


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

        engine_errors = (
            EnterpriseReceiptError,
            EnterpriseEnforcementError,
            EnterpriseRunnerAdmissionError,
        )
        engines = {
            "generate_key_material": generate_key_material,
            "seal_receipt_v2": seal_receipt_v2,
            "verify_receipt_v2": verify_receipt_v2,
            "sign_policy_bundle": sign_policy_bundle,
            "sign_revocations": sign_revocations,
            "sign_workload_identity": sign_workload_identity,
            "sign_enforcement_policy": sign_enforcement_policy,
            "sign_workload_revocations": sign_workload_revocations,
            "prepare_runner_admission": prepare_runner_admission,
            "record_enterprise_decision": record_enterprise_decision,
        }
        try:
            result = _dispatch_enterprise_command(a, engines)
        except (*engine_errors, json.JSONDecodeError, OSError) as exc:
            error = _enterprise_error(exc, engine_errors)
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

"""CLI boundary for admission, E2E, and reality-proof execution surfaces."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register runtime-proof command families."""
    e2e = sub.add_parser("e2e", help="run a native proof-by-sabotage E2E command pair")
    e2e_sub = e2e.add_subparsers(required=True, dest="e2e_cmd")
    e2e_verify = e2e_sub.add_parser("verify", help="run approved positive and negative argv commands without vendor access")
    e2e_verify.add_argument("--root", default=".")
    e2e_verify.add_argument("--manifest", required=True, help="workspace-contained factory.e2e_proof_manifest.v1 JSON path")
    e2e_verify.add_argument("--out-dir", help="explicit local directory for receipt, Mermaid, and captured output artifacts")
    e2e_verify.add_argument("--json", action="store_true")

    reality = sub.add_parser("reality", help="run one approved behavior promise through a supervised local proof pair")
    reality_sub = reality.add_subparsers(required=True, dest="reality_cmd")
    reality_verify = reality_sub.add_parser("verify", help="bind an approved happy and negative check to one product behavior")
    reality_verify.add_argument("--root", default=".")
    reality_verify.add_argument("--manifest", required=True, help="workspace-contained factory.reality-check-manifest.v1 JSON path")
    reality_verify.add_argument("--out-dir", help="explicit local directory for public receipt, Markdown, and Mermaid artifacts")
    reality_verify.add_argument("--json", action="store_true")
    reality_inspect = reality_sub.add_parser("inspect", help="validate declared positive and negative intent assertions without execution")
    reality_inspect.add_argument("--root", default=".")
    reality_inspect.add_argument("--manifest", required=True, help="workspace-contained factory.reality-check-manifest.v1 JSON path")
    reality_inspect.add_argument("--json", action="store_true")

    admission = sub.add_parser("admission", help="seal and revalidate a local external-run admission packet")
    admission_sub = admission.add_subparsers(required=True, dest="admission_cmd")
    admission_prepare = admission_sub.add_parser("prepare", help="seal one externally enforced run proposal without invoking it")
    admission_prepare.add_argument("passport")
    admission_prepare.add_argument("request")
    admission_prepare.add_argument("--root", default=".")
    admission_prepare.add_argument("--out-dir")
    admission_prepare.add_argument("--require-intake", action="store_true", help="require an authoritative intake-parameter binding before sealing admission")
    admission_prepare.add_argument("--json", action="store_true")
    admission_verify = admission_sub.add_parser("verify", help="revalidate one sealed packet before a harness consumes it")
    admission_verify.add_argument("packet")
    admission_verify.add_argument("--root", default=".")
    admission_verify.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one runtime-proof command after parser selection."""
    if args.cmd == "admission":
        from .run_admission import AdmissionError, prepare_admission, verify_admission

        try:
            if args.admission_cmd == "prepare":
                result = prepare_admission(Path(args.root), Path(args.passport), Path(args.request), Path(args.out_dir) if args.out_dir else None, require_intake=args.require_intake)
                code = 0
            else:
                result = verify_admission(Path(args.root), Path(args.packet))
                code = 0 if result["verdict"] == "READY" else 1
        except AdmissionError as exc:
            result = {"schema": "factory.run-admission.error.v1", "code": exc.code, "message": str(exc)}
            code = 2
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        elif code == 0:
            print(f"admission: {result.get('marker', result.get('verdict'))}")
        else:
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
        return code

    if args.cmd == "e2e":
        from .e2e_proof import E2EProofError, public_e2e_proof_receipt, verify_e2e_proof, write_e2e_proof_artifacts

        workspace = Path(args.root).resolve()
        manifest = Path(args.manifest)
        if not manifest.is_absolute():
            manifest = workspace / manifest
        try:
            receipt = verify_e2e_proof(workspace, manifest)
            artifacts = write_e2e_proof_artifacts(receipt, Path(args.out_dir)) if args.out_dir else None
        except E2EProofError as exc:
            error = {"schema": "factory.e2e_proof.error.v1", "marker": exc.code, "code": exc.code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if args.json else f"e2e proof failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        public = public_e2e_proof_receipt(receipt)
        if args.json:
            output = {"receipt": public}
            if artifacts:
                output["artifacts"] = artifacts
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            print("factory e2e verify")
            print("=" * 44)
            print(f"proof id : {public['manifest']['id']}")
            print(f"result   : {public['marker']} ({'passing' if public['ok'] else 'non-passing'})")
            print(f"positive : {public['commands']['positive']['status']} / exit {public['commands']['positive']['exit_code']}")
            print(f"negative : {public['commands']['negative']['status']} / exit {public['commands']['negative']['exit_code']}")
            print("authority: caller-approved local test execution only; no release, deployment, credential, or egress enforcement")
            if artifacts:
                print(f"packet   : {artifacts['paths']['markdown']}")
        return 0 if public["ok"] else 1

    from .reality_check import RealityCheckError, inspect_reality_intent, run_reality_check, write_reality_check_artifacts

    workspace = Path(args.root).resolve()
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = workspace / manifest
    try:
        if args.reality_cmd == "inspect":
            inspection = inspect_reality_intent(workspace, manifest)
            if args.json:
                print(json.dumps(inspection, indent=2, sort_keys=True))
            else:
                print("factory reality inspect")
                print("=" * 44)
                print(f"promise  : {inspection['manifest']['behavior']['promise']}")
                print(f"coverage : {len(inspection['positive_assertion_ids'])} positive / {len(inspection['negative_assertion_ids'])} negative assertions")
                print("execution: locked; this only validates the declared intent contract")
            return 0
        receipt = run_reality_check(workspace, manifest)
        artifacts = write_reality_check_artifacts(receipt, Path(args.out_dir)) if args.out_dir else None
    except RealityCheckError as exc:
        error = {"schema": "factory.reality-check.error.v1", "marker": exc.code, "code": exc.code, "message": str(exc)}
        print(json.dumps(error, indent=2, sort_keys=True) if args.json else f"reality check failed: {exc.code}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        output = {"receipt": receipt}
        if artifacts:
            output["artifacts"] = artifacts
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print("factory reality verify")
        print("=" * 44)
        print(f"promise  : {receipt['manifest']['behavior']['promise']}")
        print(f"result   : {receipt['marker']} ({'passing' if receipt['ok'] else 'non-passing'})")
        print("authority: caller-approved local test execution only; no repair, merge, release, deployment, credential, or egress enforcement")
        if artifacts:
            print(f"packet   : {artifacts['markdown']}")
    return 0 if receipt["ok"] else 1

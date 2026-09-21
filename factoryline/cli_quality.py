"""Bounded, lazily loaded CLI commands for full-stack evidence assurance."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "quality-harness"
OWNER = "quality-assurance"


def add_parser(sub: Any) -> None:
    """Register quality and capability-evidence parsers without loading engines."""
    quality_harness = sub.add_parser(
        "quality-harness",
        help="bind full-stack engineering evidence and six human UX judgments",
    )
    quality_sub = quality_harness.add_subparsers(required=True, dest="quality_cmd")
    quality_template = quality_sub.add_parser(
        "template", help="write a closed, unverified quality manifest"
    )
    quality_template.add_argument("--root", default=".")
    quality_template.add_argument("--out", required=True)
    quality_template.add_argument("--ui", action="store_true", help="include the seven UI evidence checks")
    quality_template.add_argument("--json", action="store_true")
    quality_verify = quality_sub.add_parser(
        "verify", help="verify bound evidence and human judgments without executing checks"
    )
    quality_verify.add_argument("manifest")
    quality_verify.add_argument("--root", default=".")
    quality_verify.add_argument("--out")
    quality_verify.add_argument("--json", action="store_true")
    quality_spec_validate = quality_sub.add_parser(
        "spec-validate",
        help="strictly validate the Full-Stack UX Harness SSAT/YAML contract and write a local receipt",
    )
    quality_spec_validate.add_argument("spec")
    quality_spec_validate.add_argument("--root", default=".")
    quality_spec_validate.add_argument("--out")
    quality_spec_validate.add_argument("--json", action="store_true")
    quality_spec_verify = quality_sub.add_parser(
        "spec-verify", help="replay a Full-Stack UX Harness spec receipt against its current source"
    )
    quality_spec_verify.add_argument("receipt")
    quality_spec_verify.add_argument("--root", default=".")
    quality_spec_verify.add_argument("--json", action="store_true")

    evidence_audit = sub.add_parser(
        "evidence-audit",
        help="bind capability claims to source and tests; execute only with --execute",
    )
    evidence_audit.add_argument("manifest", nargs="?", default="evidence/capability-evidence.json")
    evidence_audit.add_argument("--root", default=".")
    evidence_audit.add_argument("--execute", action="store_true", help="run the reviewed manifest commands locally without a shell")
    evidence_audit.add_argument("--json", action="store_true")


def run_evidence(args: Any) -> int:
    """Run capability evidence with its implementation imported on demand."""
    from .capability_evidence import CapabilityEvidenceError, audit_capability_evidence

    try:
        result = audit_capability_evidence(Path(args.root), Path(args.manifest), execute=args.execute)
    except (CapabilityEvidenceError, OSError, json.JSONDecodeError) as exc:
        error = {
            "marker": "CAPABILITY_EVIDENCE_BLOCKED",
            "code": getattr(exc, "code", "E_CAPABILITY_EVIDENCE_INPUT"),
            "message": str(exc),
        }
        print(json.dumps(error, indent=2) if args.json else f"{error['code']}: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(result, indent=2)
        if args.json
        else f"{result['marker']}: {len(result['claims'])} claims; {result['execution_count']} executions.\n{result['claim_boundary']}"
    )
    return 0 if result["ok"] else 1


def run_quality(args: Any) -> int:
    """Run full-stack quality assurance after the command is selected."""
    from .full_stack_ux_harness import (
        FullStackUXHarnessError,
        verify_quality_harness,
        write_quality_harness_template,
    )
    from .full_stack_ux_spec import (
        FullStackUXSpecError,
        validate_ux_harness_spec,
        verify_ux_harness_spec_receipt,
    )

    try:
        if args.quality_cmd == "template":
            result = write_quality_harness_template(Path(args.root), Path(args.out), ui_in_scope=args.ui)
            code = 0
        elif args.quality_cmd == "spec-validate":
            result = validate_ux_harness_spec(Path(args.root), Path(args.spec), out=Path(args.out) if args.out else None)
            code = 0 if result["ok"] else 1
        elif args.quality_cmd == "spec-verify":
            result = verify_ux_harness_spec_receipt(Path(args.root), Path(args.receipt))
            code = 0 if result["ok"] else 1
        else:
            result = verify_quality_harness(Path(args.root), Path(args.manifest), out=Path(args.out) if args.out else None)
            code = 0 if result["decision"] == "READY_FOR_HUMAN_RELEASE_REVIEW" else 1
    except (FullStackUXHarnessError, FullStackUXSpecError, OSError, json.JSONDecodeError, ValueError) as exc:
        result = {
            "schema": "factory.full-stack-ux-harness.error.v1",
            "decision": "REJECTED",
            "code": getattr(exc, "code", "E_UX_INPUT"),
            "message": getattr(exc, "message", str(exc)),
            "authority": "none",
        }
        code = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr if code == 2 else sys.stdout)
    elif code == 0:
        print(f"Quality harness: {result.get('decision', 'TEMPLATE_WRITTEN')}")
        if result.get("path"):
            print(f"Receipt: {result['path']}")
        elif result.get("source"):
            print(f"Source: {result['source']}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr if code == 2 else sys.stdout)
    return code

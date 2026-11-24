"""Bounded, lazily loaded CLI commands for full-stack evidence assurance."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

COMMAND_GROUP = "quality-harness"
OWNER = "quality-assurance"


def add_parser(sub: Any) -> None:
    """Register quality and capability-evidence parsers without loading engines."""
    add_quality_parser(sub)
    add_evidence_parser(sub)


def add_quality_parser(sub: Any) -> None:
    """Register quality evidence parsers without loading command engines."""
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
    quality_template.add_argument(
        "--ui", action="store_true", help="include the seven UI evidence checks"
    )
    quality_template.add_argument("--json", action="store_true")
    quality_verify = quality_sub.add_parser(
        "verify",
        help="verify bound evidence and human judgments without executing checks",
    )
    quality_verify.add_argument("manifest")
    quality_verify.add_argument("--root", default=".")
    quality_verify.add_argument("--out")
    quality_verify.add_argument(
        "--visual-receipt", help="replay optical evidence before quality review"
    )
    quality_verify.add_argument("--json", action="store_true")
    quality_spec_validate = quality_sub.add_parser(
        "spec-validate",
        help="strictly validate the Full-Stack UX Harness SSAT/YAML contract and write a local receipt",
    )
    quality_spec_validate.add_argument(
        "spec",
        help="workspace-contained full-stack-ux-harness-v1.ssat.yaml or explicit v1alpha1 contract",
    )
    quality_spec_validate.add_argument("--root", default=".")
    quality_spec_validate.add_argument("--out")
    quality_spec_validate.add_argument("--json", action="store_true")
    quality_spec_verify = quality_sub.add_parser(
        "spec-verify",
        help="replay a Full-Stack UX Harness spec receipt against its current source",
    )
    quality_spec_verify.add_argument("receipt", help="workspace-contained spec receipt")
    quality_spec_verify.add_argument("--root", default=".")
    quality_spec_verify.add_argument("--json", action="store_true")
    visual = quality_sub.add_parser(
        "visual", help="measure a pinned local optical/behavior contract"
    )
    visual.add_argument("manifest")
    visual.add_argument("--contract-sha256", required=True)
    visual.add_argument("--execute", action="store_true")
    visual.add_argument("--root", default=".")
    visual.add_argument("--out")
    visual.add_argument("--json", action="store_true")
    visual_compare = quality_sub.add_parser(
        "visual-compare", help="compare two verified visual journey receipts"
    )
    visual_compare.add_argument("before", help="baseline visual behavior receipt")
    visual_compare.add_argument("after", help="candidate visual behavior receipt")
    visual_compare.add_argument("--root", default=".", help="baseline workspace root")
    visual_compare.add_argument(
        "--after-root", help="candidate workspace root, defaults to --root"
    )
    visual_compare.add_argument(
        "--html-out", help="fresh standalone HTML report path within --root"
    )
    visual_compare.add_argument("--json", action="store_true")


def add_evidence_parser(sub: Any) -> None:
    """Register capability evidence arguments without executing commands."""
    evidence_audit = sub.add_parser(
        "evidence-audit",
        help="bind capability claims to source and tests; execute only with --execute",
    )
    evidence_audit.add_argument(
        "manifest", nargs="?", default="evidence/capability-evidence.json"
    )
    evidence_audit.add_argument("--root", default=".")
    evidence_audit.add_argument(
        "--execute",
        action="store_true",
        help="run the reviewed manifest commands locally without a shell",
    )
    evidence_audit.add_argument("--json", action="store_true")


def run_evidence(args: Any) -> int:
    """Run capability evidence with its implementation imported on demand."""
    from .capability_evidence import CapabilityEvidenceError, audit_capability_evidence

    try:
        result = audit_capability_evidence(
            Path(args.root), Path(args.manifest), execute=args.execute
        )
    except (CapabilityEvidenceError, OSError, json.JSONDecodeError) as exc:
        error = {
            "marker": "CAPABILITY_EVIDENCE_BLOCKED",
            "code": getattr(exc, "code", "E_CAPABILITY_EVIDENCE_INPUT"),
            "message": str(exc),
        }
        print(
            json.dumps(error, indent=2) if args.json else f"{error['code']}: {exc}",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(result, indent=2)
        if args.json
        else f"{result['marker']}: {len(result['claims'])} claims; {result['execution_count']} executions.\n{result['claim_boundary']}"
    )
    return 0 if result["ok"] else 1


def _execute_quality_command(
    args: Any,
    write_quality_harness_template: Any,
    validate_ux_harness_spec: Any,
    verify_ux_harness_spec_receipt: Any,
    verify_quality_harness: Any,
) -> tuple[dict[str, Any], int]:
    if args.quality_cmd == "template":
        result = write_quality_harness_template(
            Path(args.root), Path(args.out), ui_in_scope=args.ui
        )
        return result, 0
    if args.quality_cmd == "spec-validate":
        result = validate_ux_harness_spec(
            Path(args.root),
            Path(args.spec),
            out=Path(args.out) if args.out else None,
        )
        return result, 0 if result["ok"] else 1
    if args.quality_cmd == "spec-verify":
        result = verify_ux_harness_spec_receipt(Path(args.root), Path(args.receipt))
        return result, 0 if result["ok"] else 1
    if args.quality_cmd == "visual":
        from .full_stack_ux_harness import run_visual_behavior_gate

        result = run_visual_behavior_gate(
            Path(args.root),
            Path(args.manifest),
            args.contract_sha256,
            execute=args.execute,
            out=Path(args.out) if args.out else None,
        )
        return result, 0 if result["decision"] == "PASS" else 1
    if args.quality_cmd == "visual-compare":
        return _run_visual_comparison(args)
    result = verify_quality_harness(
        Path(args.root),
        Path(args.manifest),
        out=Path(args.out) if args.out else None,
        visual_receipt=Path(args.visual_receipt)
        if getattr(args, "visual_receipt", None)
        else None,
    )
    code = 0 if result["decision"] == "READY_FOR_HUMAN_RELEASE_REVIEW" else 1
    return result, code


def _run_visual_comparison(args: Any) -> tuple[dict[str, Any], int]:
    from .full_stack_ux_harness import compare_journey_evidence

    root = Path(args.root).resolve()
    after_root = Path(args.after_root).resolve() if args.after_root else root
    comparison = compare_journey_evidence(
        root, Path(args.before), after_root, Path(args.after)
    )
    result = {**comparison, "decision": comparison["status"]}
    if args.html_out:
        from .full_stack_ux_harness import (
            _visual_destination,
            render_journey_comparison,
        )

        destination = _visual_destination(root, args.html_out)
        if destination.suffix.lower() != ".html":
            raise ValueError("comparison report must use the .html extension")
        html = render_journey_comparison(comparison)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
        try:
            temporary.write_bytes(html.encode("utf-8"))
            os.link(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        result["path"] = destination.relative_to(root).as_posix()
    return result, 0 if comparison["status"] == "PASS" else 1


def _quality_error(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "factory.full-stack-ux-harness.error.v1",
        "decision": "REJECTED",
        "code": getattr(exc, "code", "E_UX_INPUT"),
        "message": getattr(exc, "message", str(exc)),
        "authority": "none",
    }


def _print_quality_json(result: dict[str, Any], code: int) -> None:
    print(
        json.dumps(result, indent=2, sort_keys=True),
        file=sys.stderr if code == 2 else sys.stdout,
    )


def _print_quality_result(args: Any, result: dict[str, Any], code: int) -> None:
    if args.json:
        _print_quality_json(result, code)
    elif code == 0:
        print(f"Quality harness: {result.get('decision', 'TEMPLATE_WRITTEN')}")
        if result.get("path"):
            print(f"Receipt: {result['path']}")
        elif result.get("source"):
            print(f"Source: {result['source']}")
    else:
        _print_quality_json(result, code)


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
        result, code = _execute_quality_command(
            args,
            write_quality_harness_template,
            validate_ux_harness_spec,
            verify_ux_harness_spec_receipt,
            verify_quality_harness,
        )
    except (
        FullStackUXHarnessError,
        FullStackUXSpecError,
        OSError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = _quality_error(exc)
        code = 2
    _print_quality_result(args, result, code)
    return code

"""CLI boundary for architecture, external evidence, journey, and efficiency."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .failure_guidance import explain_failure


def emit_version(as_json: bool) -> int:
    """Format the CLI's version response from the shared provenance receipt."""
    from .provenance import provenance

    payload = provenance()
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if as_json
        else f"factory {payload['version']}"
    )
    return 0


def cli_command(name: str) -> str:
    """Prefer the launcher's script directory over an ambient PATH lookup."""
    script_dirs = [
        Path(sys.argv[0]).resolve().parent,
        Path(sys.executable).resolve().parent,
    ]
    for scripts in dict.fromkeys(script_dirs):
        for suffix in (".exe", ".cmd", ""):
            candidate = scripts / f"{name}{suffix}"
            if candidate.exists():
                return str(candidate)
    return name


def add_parser(sub: Any) -> None:
    """Register the foundational proof and architecture command families."""
    architecture = sub.add_parser(
        "architecture", help="measure architecture debt and enforce growth budgets"
    )
    architecture_sub = architecture.add_subparsers(
        required=True, dest="architecture_cmd"
    )
    architecture_health = architecture_sub.add_parser(
        "health",
        help="report documentation, CLI, module-surface, and release-cadence health",
    )
    architecture_health.add_argument("--root", default=".")
    architecture_health.add_argument(
        "--policy", help="policy JSON; defaults to architecture-policy.json below root"
    )
    architecture_health.add_argument(
        "--strict",
        action="store_true",
        help="treat existing architecture debt as blocking",
    )
    architecture_health.add_argument("--json", action="store_true")

    external = sub.add_parser(
        "external", help="import and compare offline external runtime evidence"
    )
    external_sub = external.add_subparsers(required=True, dest="external_cmd")
    external_import = external_sub.add_parser(
        "import", help="verify one provider bundle and write an observed-only receipt"
    )
    external_import.add_argument(
        "bundle",
        help="workspace-contained factory.external-runtime-bundle.v1 JSON path",
    )
    external_import.add_argument("--root", default=".")
    external_import.add_argument(
        "--provider", required=True, help="declared adapter id, for example testsprite"
    )
    external_import.add_argument(
        "--out", help="receipt path below .factory/external-evidence/"
    )
    external_import.add_argument("--json", action="store_true")
    external_diff = external_sub.add_parser(
        "diff", help="compare two verified receipts without provider execution"
    )
    external_diff.add_argument("left", help="left receipt path")
    external_diff.add_argument("right", help="right receipt path")
    external_diff.add_argument("--root", default=".")
    external_diff.add_argument("--json", action="store_true")

    journey = sub.add_parser(
        "journey",
        help="prove runtime journeys, stateful workflows, failures, and bounded healing",
    )
    journey_sub = journey.add_subparsers(required=True, dest="journey_cmd")
    journey_reality = journey_sub.add_parser(
        "reality", help="compare declared and observed journey graphs without inference"
    )
    journey_reality.add_argument(
        "declaration", help="factory.journey-declaration.v1 JSON path"
    )
    journey_reality.add_argument(
        "observation", help="factory.journey-observation.v1 JSON path"
    )
    journey_reality.add_argument("--root", default=".")
    journey_reality.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_reality.add_argument("--json", action="store_true")
    journey_capsule = journey_sub.add_parser(
        "capsule",
        help="bind a failed step and adjacent evidence into JSON and Markdown",
    )
    journey_capsule.add_argument(
        "input", help="factory.failure-capsule-input.v1 JSON path"
    )
    journey_capsule.add_argument("--root", default=".")
    journey_capsule.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_capsule.add_argument("--json", action="store_true")
    journey_workflow = journey_sub.add_parser(
        "workflow-proof", help="prove state flow, cleanup, and idempotency"
    )
    journey_workflow.add_argument(
        "input", help="factory.stateful-workflow-input.v1 JSON path"
    )
    journey_workflow.add_argument("--root", default=".")
    journey_workflow.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_workflow.add_argument("--json", action="store_true")
    journey_healing = journey_sub.add_parser(
        "heal-verify", help="challenge a repair under human or supervised-auto review"
    )
    journey_healing.add_argument(
        "input", help="factory.proof-gated-healing-input.v1 JSON path"
    )
    journey_healing.add_argument("--root", default=".")
    journey_healing.add_argument(
        "--out", help="receipt path below .factory/journey-proof/"
    )
    journey_healing.add_argument("--timeout-seconds", type=int, default=300)
    journey_healing.add_argument("--json", action="store_true")
    journey_status = journey_sub.add_parser(
        "status", help="read verified local Journey Proof receipts without execution"
    )
    journey_status.add_argument("--root", default=".")
    journey_status.add_argument("--json", action="store_true")

    efficiency = sub.add_parser(
        "efficiency", help="compile and verify bounded, cacheable context packets"
    )
    efficiency_sub = efficiency.add_subparsers(dest="efficiency_cmd", required=True)
    efficiency_pack = efficiency_sub.add_parser(
        "pack", help="build a read-only bounded context packet"
    )
    efficiency_pack.add_argument(
        "--manifest", required=True, help="JSON request manifest"
    )
    efficiency_pack.add_argument("--root", default=".")
    efficiency_pack.add_argument("--out")
    efficiency_pack.add_argument("--json", action="store_true")
    efficiency_verify = efficiency_sub.add_parser(
        "verify", help="verify packet and source hashes"
    )
    efficiency_verify.add_argument("packet")
    efficiency_verify.add_argument("--root", default=".")
    efficiency_verify.add_argument("--json", action="store_true")
    efficiency_status = efficiency_sub.add_parser(
        "status", help="show bounded packet/cache metadata"
    )
    efficiency_status.add_argument("--root", default=".")
    efficiency_status.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one foundational command after parser selection."""
    if args.cmd == "architecture":
        from .architecture_health import (
            ArchitectureHealthError,
            evaluate_architecture_health,
        )

        try:
            result = evaluate_architecture_health(
                Path(args.root),
                Path(args.policy) if args.policy else None,
                strict=args.strict,
            )
        except (
            ArchitectureHealthError,
            OSError,
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            error = {
                "schema": "factory.architecture-health-error.v1",
                "status": "failed",
                "code": getattr(exc, "code", "E_ARCHITECTURE_HEALTH"),
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if result.get("decision") == "BLOCKED" else 0

    if args.cmd == "external":
        from .external_evidence import (
            ExternalEvidenceError,
            diff_external_runtime_receipts,
            import_external_runtime_bundle,
        )

        try:
            if args.external_cmd == "import":
                result = import_external_runtime_bundle(
                    Path(args.root),
                    Path(args.bundle),
                    args.provider,
                    Path(args.out) if args.out else None,
                )
            else:
                result = diff_external_runtime_receipts(
                    Path(args.root), Path(args.left), Path(args.right)
                )
        except ExternalEvidenceError as exc:
            print(
                json.dumps(
                    {
                        "schema": "factory.workflow_error.v1",
                        "status": "failed",
                        "code": exc.code,
                        "message": exc.message,
                        "marker": exc.code,
                        "failure": explain_failure(exc.code, exc.message),
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.external_cmd == "diff" and result.get("comparable") is not True:
            return 1
        return 0

    if args.cmd == "journey":
        from .journey_proof import (
            JourneyProofError,
            compile_reality_graph,
            create_failure_capsule,
            journey_proof_status,
            verify_proof_gated_healing,
            verify_stateful_workflow,
        )

        try:
            root = Path(args.root)
            if args.journey_cmd == "reality":
                result = compile_reality_graph(
                    root,
                    Path(args.declaration),
                    Path(args.observation),
                    Path(args.out) if args.out else None,
                )
            elif args.journey_cmd == "capsule":
                result = create_failure_capsule(
                    root, Path(args.input), Path(args.out) if args.out else None
                )
            elif args.journey_cmd == "workflow-proof":
                result = verify_stateful_workflow(
                    root, Path(args.input), Path(args.out) if args.out else None
                )
            elif args.journey_cmd == "heal-verify":
                result = verify_proof_gated_healing(
                    root,
                    Path(args.input),
                    Path(args.out) if args.out else None,
                    args.timeout_seconds,
                )
            else:
                result = journey_proof_status(root)
        except JourneyProofError as exc:
            print(
                json.dumps(
                    {
                        "schema": "factory.workflow_error.v1",
                        "status": "failed",
                        "code": exc.code,
                        "message": str(exc),
                        "marker": exc.code,
                        "failure": explain_failure(exc.code, str(exc)),
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.journey_cmd == "reality" and result.get("decision") != "matched":
            return 1
        if args.journey_cmd in {"workflow-proof", "heal-verify"} and result.get(
            "decision"
        ) not in {"passed", "admissible_for_human_review"}:
            return 1
        return 0

    from .context_efficiency import (
        ContextEfficiencyError,
        build_context_packet,
        context_efficiency_status,
        verify_context_packet,
    )

    root = Path(args.root).resolve()
    try:
        if args.efficiency_cmd == "pack":
            request = json.loads(Path(args.manifest).read_text(encoding="utf-8-sig"))
            result = build_context_packet(
                root, request, Path(args.out) if args.out else None
            )
            code = 0
        elif args.efficiency_cmd == "verify":
            result = verify_context_packet(root, Path(args.packet))
            code = 0 if result.get("valid") is True else 1
        else:
            result = context_efficiency_status(root)
            code = 0
    except (
        ContextEfficiencyError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.context-efficiency-error.v1",
            "marker": "CONTEXT_EFFICIENCY_REFUSED",
            "code": getattr(exc, "code", "E_CONTEXT_INPUT"),
            "message": getattr(exc, "message", str(exc)),
        }
        code = 2
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        print(result.get("marker", result.get("state", "CONTEXT_EFFICIENCY_OK")))
        print(
            "authority   : bounded local context metadata only; no execution, approval, repair, release, publication, or credentials"
        )
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
    return code

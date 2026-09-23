"""Bounded, lazily loaded operational coordination CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "coordination"
OWNER = "coordination-maintainers"


def add_parser(sub: Any) -> None:
    """Register coordination boundaries without loading their ledgers."""
    operations = sub.add_parser(
        "operations-control",
        help="bind verified isolation, repro budgets, change envelopes, proof tiers, architecture zones, and local repository heads without dispatching work",
    )
    operations_sub = operations.add_subparsers(
        required=True, dest="operations_control_cmd"
    )
    template = operations_sub.add_parser(
        "template", help="render a secret-free operations-control manifest template"
    )
    template.add_argument("--json", action="store_true")
    assess = operations_sub.add_parser(
        "assess", help="write one fail-closed local operations-control receipt"
    )
    assess.add_argument("--root", default=".")
    assess.add_argument(
        "--manifest",
        required=True,
        help="workspace-relative factory.operations-control-manifest.v1 JSON",
    )
    assess.add_argument(
        "--out", help="workspace-relative output below .factory/operations-control"
    )
    assess.add_argument("--json", action="store_true")
    status = operations_sub.add_parser(
        "status", help="read local operations-control receipt summaries"
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")

    lifecycle = sub.add_parser(
        "lifecycle",
        help="record or inspect local hash-linked harness lifecycle facts without dispatching an agent",
    )
    lifecycle_sub = lifecycle.add_subparsers(required=True, dest="lifecycle_cmd")
    template = lifecycle_sub.add_parser(
        "template", help="render a secret-free lifecycle event template"
    )
    template.add_argument("--json", action="store_true")
    record = lifecycle_sub.add_parser(
        "record", help="append one hash-linked local lifecycle event"
    )
    record.add_argument("--root", default=".")
    record.add_argument(
        "--event",
        required=True,
        help="workspace-relative factory.lifecycle-event.v1 JSON",
    )
    record.add_argument(
        "--out", help="workspace-relative output below .factory/lifecycle"
    )
    record.add_argument("--json", action="store_true")
    status = lifecycle_sub.add_parser(
        "status", help="read local lifecycle run summaries"
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")

    boundary = sub.add_parser(
        "service-boundary",
        help="check declared action, service, adapter, and core boundaries for changed source without rewriting code",
    )
    boundary_sub = boundary.add_subparsers(required=True, dest="service_boundary_cmd")
    template = boundary_sub.add_parser(
        "template", help="render a secret-free service-boundary manifest template"
    )
    template.add_argument("--json", action="store_true")
    check = boundary_sub.add_parser(
        "check",
        help="classify changed source and fail closed on declared boundary violations",
    )
    check.add_argument("--root", default=".")
    check.add_argument(
        "--manifest",
        required=True,
        help="workspace-relative factory.service-boundary-manifest.v1 JSON",
    )
    check.add_argument(
        "--changed",
        required=True,
        action="append",
        help="workspace-relative changed source path; repeat as needed",
    )
    check.add_argument("--json", action="store_true")

    repair = sub.add_parser(
        "repair-loop",
        help="bind one exact failure, consequence assessment, candidate, independent re-check, and named human review without attempting a repair",
    )
    repair_sub = repair.add_subparsers(required=True, dest="repair_loop_cmd")
    template = repair_sub.add_parser(
        "template",
        help="render a secret-free proof-gated repair-loop manifest template",
    )
    template.add_argument("--json", action="store_true")
    assess = repair_sub.add_parser(
        "assess",
        help="write one immutable local repair-loop packet after binding all supplied evidence",
    )
    assess.add_argument("--root", default=".")
    assess.add_argument(
        "--manifest",
        required=True,
        help="workspace-relative factory.repair-loop-manifest.v1 JSON",
    )
    assess.add_argument(
        "--out", help="workspace-relative output below .factory/repair-loops"
    )
    assess.add_argument("--json", action="store_true")
    status = repair_sub.add_parser(
        "status",
        help="read bounded local repair-loop packets without running any candidate",
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")

    coordinate = sub.add_parser(
        "repo-coordinate",
        help="inspect a pinned multi-repository dependency order without changing any repository",
    )
    coordinate_sub = coordinate.add_subparsers(
        required=True, dest="repo_coordinate_cmd"
    )
    template = coordinate_sub.add_parser(
        "template",
        help="render a secret-free multi-repository coordination manifest template",
    )
    template.add_argument("--json", action="store_true")
    plan = coordinate_sub.add_parser(
        "plan", help="derive a fail-closed sequential plan from pinned local Git heads"
    )
    plan.add_argument("--root", default=".")
    plan.add_argument(
        "--manifest",
        required=True,
        help="workspace-relative factory.repo-coordination-manifest.v1 JSON",
    )
    plan.add_argument("--json", action="store_true")


def _emit(result: dict[str, Any], code: int) -> int:
    print(
        json.dumps(result, indent=2, sort_keys=True),
        file=sys.stderr if code else sys.stdout,
    )
    return code


def _run_operations(args: Any) -> int:
    from .operations_control import (
        OperationsControlError,
        assess_operations_control,
        operations_control_projection,
        operations_control_template,
    )

    root = Path(args.root).resolve()
    try:
        if args.operations_control_cmd == "template":
            result = operations_control_template()
        elif args.operations_control_cmd == "assess":
            result = assess_operations_control(
                root, Path(args.manifest), Path(args.out) if args.out else None
            )
        else:
            result = operations_control_projection(root)
        code = (
            0
            if args.operations_control_cmd == "template"
            or (
                result.get("marker") in {"OPS_CONTROL_READY", "OPS_CONTROL_READ_ONLY"}
                and int(result.get("invalid_count", 0)) == 0
            )
            else 1
        )
    except (
        OperationsControlError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.operations-control.error.v1",
            "marker": "OPS_CONTROL_INPUT_REJECTED",
            "code": getattr(exc, "code", "E_OPS_CONTROL_SCHEMA"),
            "message": str(exc),
        }
        code = 2
    return _emit(result, code)


def _run_lifecycle(args: Any) -> int:
    from .lifecycle_ledger import (
        LifecycleLedgerError,
        lifecycle_projection,
        lifecycle_template,
        record_lifecycle_event,
    )

    root = Path(args.root).resolve()
    try:
        if args.lifecycle_cmd == "template":
            result = lifecycle_template()
        elif args.lifecycle_cmd == "record":
            result = record_lifecycle_event(
                root, Path(args.event), Path(args.out) if args.out else None
            )
        else:
            result = lifecycle_projection(root)
        code = (
            0
            if args.lifecycle_cmd == "template"
            or (
                result.get("marker")
                in {"LIFECYCLE_EVENT_RECORDED", "LIFECYCLE_READ_ONLY"}
                and int(result.get("invalid_count", 0)) == 0
            )
            else 1
        )
    except (
        LifecycleLedgerError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.lifecycle.error.v1",
            "marker": "LIFECYCLE_INPUT_REJECTED",
            "code": getattr(exc, "code", "E_LIFECYCLE_SCHEMA"),
            "message": str(exc),
        }
        code = 2
    return _emit(result, code)


def _run_boundary(args: Any) -> int:
    from .service_boundaries import (
        ServiceBoundaryError,
        check_service_boundaries,
        service_boundary_template,
    )

    root = Path(args.root).resolve()
    try:
        result = (
            service_boundary_template()
            if args.service_boundary_cmd == "template"
            else check_service_boundaries(root, Path(args.manifest), args.changed)
        )
        code = (
            0
            if args.service_boundary_cmd == "template"
            or result.get("marker") == "SERVICE_BOUNDARY_READY"
            else 1
        )
    except (
        ServiceBoundaryError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.service-boundary.error.v1",
            "marker": "SERVICE_BOUNDARY_INPUT_REJECTED",
            "code": getattr(exc, "code", "E_SERVICE_BOUNDARY_SCHEMA"),
            "message": str(exc),
        }
        code = 2
    return _emit(result, code)


def _run_repair(args: Any) -> int:
    from .repair_loop import (
        RepairLoopError,
        assess_repair_loop,
        repair_loop_projection,
        repair_loop_template,
    )

    root = Path(args.root).resolve()
    try:
        if args.repair_loop_cmd == "template":
            result = repair_loop_template()
        elif args.repair_loop_cmd == "assess":
            result = assess_repair_loop(
                root, Path(args.manifest), Path(args.out) if args.out else None
            )
        else:
            result = repair_loop_projection(root)
        code = (
            0
            if args.repair_loop_cmd == "template"
            or (
                result.get("marker") in {"REPAIR_LOOP_READY", "REPAIR_LOOP_READ_ONLY"}
                and int(result.get("invalid_count", 0)) == 0
            )
            else 1
        )
    except (
        RepairLoopError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.repair-loop.error.v1",
            "marker": "REPAIR_LOOP_INPUT_REJECTED",
            "code": getattr(exc, "code", "E_REPAIR_LOOP_SCHEMA"),
            "message": str(exc),
        }
        code = 2
    return _emit(result, code)


def _run_coordinate(args: Any) -> int:
    from .repo_coordination import (
        RepoCoordinationError,
        coordinate_repositories,
        repo_coordination_template,
    )

    root = Path(args.root).resolve()
    try:
        result = (
            repo_coordination_template()
            if args.repo_coordinate_cmd == "template"
            else coordinate_repositories(root, Path(args.manifest))
        )
        code = (
            0
            if args.repo_coordinate_cmd == "template"
            or result.get("marker") == "REPO_COORDINATION_READY"
            else 1
        )
    except (
        RepoCoordinationError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        result = {
            "schema": "factory.repo-coordination.error.v1",
            "marker": "REPO_COORDINATION_INPUT_REJECTED",
            "code": getattr(exc, "code", "E_REPO_COORDINATION_SCHEMA"),
            "message": str(exc),
        }
        code = 2
    return _emit(result, code)


def run(args: Any) -> int:
    """Dispatch coordination commands without importing their engines eagerly."""
    return {
        "operations-control": _run_operations,
        "lifecycle": _run_lifecycle,
        "service-boundary": _run_boundary,
        "repair-loop": _run_repair,
        "repo-coordinate": _run_coordinate,
    }[args.cmd](args)

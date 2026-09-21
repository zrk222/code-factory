"""Bounded, lazily loaded enterprise operations CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "ops"
OWNER = "operations-controls-maintainers"


def add_parser(sub: Any) -> None:
    """Register enterprise operations commands without loading execution engines."""
    ops = sub.add_parser("ops", help="run the local enterprise operations golden path")
    ops_sub = ops.add_subparsers(dest="ops_cmd", required=True)
    ops_init = ops_sub.add_parser(
        "init", help="initialize a tenant-bound evidence and operations workspace"
    )
    ops_init.add_argument("--root", default=".")
    ops_init.add_argument("--tenant", required=True)
    ops_init.add_argument("--owner", required=True)
    ops_init.add_argument("--retention-days", type=int, default=90)
    ops_init.add_argument("--force", action="store_true")
    ops_init.add_argument("--json", action="store_true")
    ops_status = ops_sub.add_parser(
        "status",
        help="show evidence, identity, runner, outcome, SLA, and next-action state",
    )
    ops_status.add_argument("--root", default=".")
    ops_status.add_argument("--json", action="store_true")
    ops_identity = ops_sub.add_parser(
        "identity", help="provision, suspend, or revoke a local identity"
    )
    ops_identity.add_argument("subject")
    ops_identity.add_argument("--root", default=".")
    ops_identity.add_argument("--tenant", required=True)
    ops_identity.add_argument("--role", required=True)
    ops_identity.add_argument(
        "--status", default="active", choices=["active", "suspended", "revoked"]
    )
    ops_identity.add_argument("--actor", required=True)
    ops_identity.add_argument("--json", action="store_true")
    ops_evidence = ops_sub.add_parser(
        "evidence", help="record one immutable tenant evidence payload"
    )
    ops_evidence.add_argument("payload", help="JSON evidence object path")
    ops_evidence.add_argument("--root", default=".")
    ops_evidence.add_argument("--tenant", required=True)
    ops_evidence.add_argument("--subject", required=True)
    ops_evidence.add_argument("--evidence-id")
    ops_evidence.add_argument("--json", action="store_true")
    ops_export = ops_sub.add_parser(
        "export", help="export aggregate-safe evidence metadata"
    )
    ops_export.add_argument("--root", default=".")
    ops_export.add_argument("--out", required=True)
    ops_export.add_argument("--json", action="store_true")
    ops_run = ops_sub.add_parser(
        "run", help="run one bounded proof argv with explicit isolation posture"
    )
    ops_run.add_argument("--root", default=".")
    ops_run.add_argument("--backend", choices=["docker", "process"], default="docker")
    ops_run.add_argument("--command", nargs="+")
    ops_run.add_argument(
        "--command-json",
        help="JSON argv list; use this when an argument begins with '-' ",
    )
    ops_run.add_argument("--timeout-seconds", type=int, default=120)
    ops_run.add_argument("--output-limit", type=int, default=65536)
    ops_run.add_argument("--allow-process-boundary", action="store_true")
    ops_run.add_argument("--json", action="store_true")
    ops_checks = ops_sub.add_parser(
        "checks", help="evaluate required proof checks for changed paths"
    )
    ops_checks.add_argument("--root", default=".")
    ops_checks.add_argument("--changed", action="append", required=True)
    ops_checks.add_argument("--proof", action="append", default=[])
    ops_checks.add_argument("--json", action="store_true")
    ops_outcome = ops_sub.add_parser(
        "outcome", help="append one allowlisted deployment or incident outcome"
    )
    ops_outcome.add_argument("--root", default=".")
    ops_outcome.add_argument("--tenant", required=True)
    ops_outcome.add_argument("--subject", required=True)
    ops_outcome.add_argument("--service", required=True)
    ops_outcome.add_argument("--environment", required=True)
    ops_outcome.add_argument("--result", required=True)
    ops_outcome.add_argument("--duration-ms", required=True, type=int)
    ops_outcome.add_argument("--deployed", action="store_true")
    ops_outcome.add_argument("--incident", action="store_true")
    ops_outcome.add_argument("--rollback", action="store_true")
    ops_outcome.add_argument("--json", action="store_true")
    ops_summary = ops_sub.add_parser(
        "summary", help="summarize hash-linked outcome telemetry"
    )
    ops_summary.add_argument("--root", default=".")
    ops_summary.add_argument("--json", action="store_true")
    ops_otel = ops_sub.add_parser(
        "otel", help="export aggregate-safe outcome telemetry in OTLP-shaped JSON"
    )
    ops_otel.add_argument("--root", default=".")
    ops_otel.add_argument("--out", required=True)
    ops_otel.add_argument("--json", action="store_true")
    ops_sla = ops_sub.add_parser(
        "sla", help="evaluate seven evidence gates without activating an SLA"
    )
    ops_sla.add_argument("--root", default=".")
    ops_sla.add_argument("--manifest")
    ops_sla.add_argument("--out")
    ops_sla.add_argument("--json", action="store_true")
    ops_policy = ops_sub.add_parser(
        "policy", help="compile explicit policy rules into deterministic checks"
    )
    ops_policy.add_argument("policy", help="factory.policy.v1 JSON path")
    ops_policy.add_argument("--root", default=".")
    ops_policy.add_argument("--out", help="workspace-contained compiled manifest path")
    ops_policy.add_argument("--json", action="store_true")
    ops_metadata = ops_sub.add_parser(
        "metadata",
        help="audit local Codex/workflow metadata for unbound or contradictory claims",
    )
    ops_metadata.add_argument("--root", default=".")
    ops_metadata.add_argument(
        "--path",
        action="append",
        help="workspace-contained metadata file or directory; repeatable",
    )
    ops_metadata.add_argument(
        "--out", help="workspace-contained metadata audit receipt path"
    )
    ops_metadata.add_argument(
        "--scope",
        choices=["active", "archive", "all"],
        default="active",
        help="audit active records by default; choose archive or all explicitly",
    )
    ops_metadata.add_argument("--json", action="store_true")
    ops_receipts = ops_sub.add_parser(
        "receipts", help="index receipts and produce a non-destructive retention plan"
    )
    ops_receipts.add_argument("--root", default=".")
    ops_receipts.add_argument("--out")
    ops_receipts.add_argument("--hot-days", type=int, default=30)
    ops_receipts.add_argument("--max-files", type=int, default=2000)
    ops_receipts.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one operations command and render its deterministic receipt."""
    from .codex_metadata import MetadataAuditError, write_metadata_audit
    from .enterprise_ops import (
        EnterpriseOpsError,
        evaluate_required_checks,
        evaluate_sla,
        export_evidence,
        export_otel,
        initialize_workspace,
        outcome_summary,
        provision_identity,
        put_evidence,
        record_outcome,
        run_proof,
        verify_workspace,
        workspace_status,
    )
    from .policy_compiler import PolicyCompileError, write_compiled_policy
    from .receipt_index import write_receipt_index

    try:
        root = Path(args.root)
        if args.ops_cmd == "init":
            result = initialize_workspace(
                root,
                args.tenant,
                args.owner,
                retention_days=args.retention_days,
                force=args.force,
            )
        elif args.ops_cmd == "status":
            result = workspace_status(root)
        elif args.ops_cmd == "identity":
            result = provision_identity(
                root, args.tenant, args.subject, args.role, actor=args.actor, status=args.status
            )
        elif args.ops_cmd == "evidence":
            payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
            result = put_evidence(
                root, args.tenant, args.subject, payload, evidence_id=args.evidence_id
            )
        elif args.ops_cmd == "export":
            result = export_evidence(root, Path(args.out))
        elif args.ops_cmd == "run":
            command = json.loads(args.command_json) if args.command_json else args.command
            result = run_proof(
                root,
                command,
                backend=args.backend,
                timeout_seconds=args.timeout_seconds,
                output_limit=args.output_limit,
                allow_process_boundary=args.allow_process_boundary,
            )
        elif args.ops_cmd == "checks":
            result = evaluate_required_checks(root, args.changed, proof_receipts=args.proof)
        elif args.ops_cmd == "outcome":
            result = record_outcome(
                root,
                args.tenant,
                args.subject,
                service=args.service,
                environment=args.environment,
                result=args.result,
                duration_ms=args.duration_ms,
                deployed=args.deployed,
                incident=args.incident,
                rollback=args.rollback,
            )
        elif args.ops_cmd == "summary":
            result = outcome_summary(root)
        elif args.ops_cmd == "otel":
            result = export_otel(root, Path(args.out))
        elif args.ops_cmd == "sla":
            result = evaluate_sla(
                root,
                Path(args.manifest) if args.manifest else None,
                out=Path(args.out) if args.out else None,
            )
        elif args.ops_cmd == "policy":
            result = write_compiled_policy(
                root, Path(args.policy), Path(args.out) if args.out else None
            )
        elif args.ops_cmd == "metadata":
            selected = [Path(item) for item in args.path] if args.path else None
            result = write_metadata_audit(
                root, selected, Path(args.out) if args.out else None, scope=args.scope
            )
        elif args.ops_cmd == "receipts":
            result = write_receipt_index(
                root,
                Path(args.out) if args.out else None,
                hot_days=args.hot_days,
                max_files=args.max_files,
            )
        else:
            result = verify_workspace(root)
    except (
        EnterpriseOpsError,
        PolicyCompileError,
        MetadataAuditError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        error = {
            "schema": "factory.enterprise-ops.error.v1",
            "marker": "EOPS_FAIL_CLOSED",
            "status": "failed",
            "code": getattr(exc, "code", "E_OPS_INPUT"),
            "message": getattr(exc, "message", str(exc)),
        }
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.ops_cmd == "run":
        return 0 if result.get("status") == "passed" else 1
    if args.ops_cmd == "checks":
        return 0 if result.get("decision") == "READY_FOR_HUMAN_REVIEW" else 1
    if args.ops_cmd == "sla":
        return 0 if result.get("status") == "READY_FOR_CONTRACT" else 1
    if args.ops_cmd == "policy":
        return 0 if result.get("status") == "COMPILED" else 1
    if args.ops_cmd == "metadata":
        return 0 if result.get("status") == "VERIFIED" else 1
    if args.ops_cmd == "receipts":
        return 0
    if args.ops_cmd in {"summary", "otel", "export"}:
        return 0 if result.get("integrity", {}).get("valid", True) else 1
    return 0

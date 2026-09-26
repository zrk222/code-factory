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


_FAILED = object()
_INPUT_ERRORS = (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError)


def _guard(operation: Any) -> Any:
    """Render a fail-closed error receipt for expected input and I/O failures."""
    try:
        return operation()
    except _INPUT_ERRORS as exc:
        error = {
            "schema": "factory.enterprise-ops.error.v1",
            "marker": "EOPS_FAIL_CLOSED",
            "status": "failed",
            "code": getattr(exc, "code", "E_OPS_INPUT"),
            "message": getattr(exc, "message", str(exc)),
        }
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return _FAILED


def _lifecycle_result(args: Any) -> Any:
    """Run workspace setup, status, identity, or evidence commands."""
    from .enterprise_ops import (
        initialize_workspace,
        provision_identity,
        put_evidence,
        workspace_status,
    )

    root = Path(args.root)
    if args.ops_cmd == "init":
        return _guard(
            lambda: initialize_workspace(
                root,
                args.tenant,
                args.owner,
                retention_days=args.retention_days,
                force=args.force,
            )
        )
    if args.ops_cmd == "status":
        return _guard(lambda: workspace_status(root))
    if args.ops_cmd == "identity":
        return _guard(
            lambda: provision_identity(
                root,
                args.tenant,
                args.subject,
                args.role,
                actor=args.actor,
                status=args.status,
            )
        )
    return _guard(
        lambda: put_evidence(
            root,
            args.tenant,
            args.subject,
            json.loads(Path(args.payload).read_text(encoding="utf-8")),
            evidence_id=args.evidence_id,
        )
    )


def _execution_result(args: Any) -> Any:
    """Run evidence export, proof execution, or required-check evaluation."""
    from .enterprise_ops import evaluate_required_checks, export_evidence, run_proof

    root = Path(args.root)
    if args.ops_cmd == "export":
        return _guard(lambda: export_evidence(root, Path(args.out)))
    if args.ops_cmd == "run":
        return _guard(
            lambda: run_proof(
                root,
                json.loads(args.command_json) if args.command_json else args.command,
                backend=args.backend,
                timeout_seconds=args.timeout_seconds,
                output_limit=args.output_limit,
                allow_process_boundary=args.allow_process_boundary,
            )
        )
    return _guard(
        lambda: evaluate_required_checks(root, args.changed, proof_receipts=args.proof)
    )


def _outcome_result(args: Any) -> Any:
    """Run outcome recording, summaries, telemetry export, or SLA evaluation."""
    from .enterprise_ops import (
        evaluate_sla,
        export_otel,
        outcome_summary,
        record_outcome,
    )

    root = Path(args.root)
    if args.ops_cmd == "outcome":
        return _guard(
            lambda: record_outcome(
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
        )
    if args.ops_cmd == "summary":
        return _guard(lambda: outcome_summary(root))
    if args.ops_cmd == "otel":
        return _guard(lambda: export_otel(root, Path(args.out)))
    manifest = Path(args.manifest) if args.manifest else None
    output = Path(args.out) if args.out else None
    return _guard(lambda: evaluate_sla(root, manifest, out=output))


def _policy_result(args: Any) -> Any:
    """Compile policy rules into a local deterministic manifest."""
    from .policy_compiler import write_compiled_policy

    output = Path(args.out) if args.out else None
    return _guard(
        lambda: write_compiled_policy(Path(args.root), Path(args.policy), output)
    )


def _metadata_result(args: Any) -> Any:
    """Audit selected Codex or workflow metadata."""
    from .codex_metadata import write_metadata_audit

    selected = [Path(item) for item in args.path] if args.path else None
    output = Path(args.out) if args.out else None
    return _guard(
        lambda: write_metadata_audit(
            Path(args.root), selected, output, scope=args.scope
        )
    )


def _receipt_result(args: Any) -> Any:
    """Build a non-destructive receipt retention index."""
    from .receipt_index import write_receipt_index

    output = Path(args.out) if args.out else None
    return _guard(
        lambda: write_receipt_index(
            Path(args.root), output, hot_days=args.hot_days, max_files=args.max_files
        )
    )


def _verify_result(args: Any) -> Any:
    """Verify an operations workspace when no explicit action is selected."""
    from .enterprise_ops import verify_workspace

    return _guard(lambda: verify_workspace(Path(args.root)))


def _dispatch(args: Any) -> Any:
    """Route the command to its lazily imported execution family."""
    if args.ops_cmd in {"init", "status", "identity", "evidence"}:
        return _lifecycle_result(args)
    if args.ops_cmd in {"export", "run", "checks"}:
        return _execution_result(args)
    if args.ops_cmd in {"outcome", "summary", "otel", "sla"}:
        return _outcome_result(args)
    if args.ops_cmd == "policy":
        return _policy_result(args)
    if args.ops_cmd == "metadata":
        return _metadata_result(args)
    if args.ops_cmd == "receipts":
        return _receipt_result(args)
    return _verify_result(args)


def _exit_code(command: str, result: dict[str, Any]) -> int:
    """Apply the existing command-specific readiness exit rules."""
    expected = {
        "run": ("status", "passed"),
        "checks": ("decision", "READY_FOR_HUMAN_REVIEW"),
        "sla": ("status", "READY_FOR_CONTRACT"),
        "policy": ("status", "COMPILED"),
        "metadata": ("status", "VERIFIED"),
    }
    if command in {"summary", "otel", "export"}:
        return 0 if result.get("integrity", {}).get("valid", True) else 1
    key, value = expected.get(command, (None, None))
    return 0 if key is None or result.get(key) == value else 1


def run(args: Any) -> int:
    """Execute one operations command and render its deterministic receipt."""
    result = _dispatch(args)
    if result is _FAILED:
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return _exit_code(args.ops_cmd, result)

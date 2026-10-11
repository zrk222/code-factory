"""Lazy CLI boundary for supervised repair and JetBrains proof handshakes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register repair-sandbox and JetBrains handshake commands."""
    repair = sub.add_parser(
        "repair",
        help="inspect, explicitly approve, and verify an isolated candidate repair",
    )
    repair_sub = repair.add_subparsers(required=True, dest="repair_cmd")
    repair_scope = repair_sub.add_parser(
        "scope",
        help="seal explicit Change List paths and optional local handoff artifacts",
    )
    repair_scope.add_argument("--root", default=".")
    repair_scope.add_argument(
        "--change-list",
        required=True,
        help="native Change List label supplied by the IDE",
    )
    repair_scope.add_argument(
        "--changed",
        action="append",
        required=True,
        help="explicit workspace-relative Change List path; repeat as needed",
    )
    repair_scope.add_argument(
        "--context-budget-bytes",
        type=int,
        default=262144,
        help="measured-byte threshold that recommends splitting an oversized agent context",
    )
    repair_scope.add_argument(
        "--out-dir",
        help="explicit workspace-contained directory for local scope artifacts",
    )
    repair_scope.add_argument("--json", action="store_true")
    repair_candidate = repair_sub.add_parser(
        "candidate",
        help="bind a textual Git patch to a current sealed scope without applying it",
    )
    repair_candidate.add_argument("--root", default=".")
    repair_candidate.add_argument(
        "--scope",
        required=True,
        help="workspace-contained factory.repair_scope.v1 JSON packet",
    )
    repair_candidate.add_argument(
        "--patch", required=True, help="workspace-contained textual Git candidate patch"
    )
    repair_candidate.add_argument(
        "--out-dir",
        help="explicit workspace-contained directory for local candidate artifacts",
    )
    repair_candidate.add_argument("--json", action="store_true")
    _add_repair_execution_parsers(repair_sub)
    lineage = repair_sub.add_parser(
        "trace", help="bind deep-audit runs, repair evidence, and exact rerun lineage"
    )
    lineage.add_argument("--run-id", action="append", required=True)
    lineage.add_argument("--approval-sha256")
    lineage.add_argument("--root", default=".")
    lineage.add_argument("--json", action="store_true")

    jetbrains = sub.add_parser(
        "jetbrains",
        help="join a sealed agent mission, Qodana or SonarQube SARIF, and non-hollow proof without provider execution",
    )
    jetbrains_sub = jetbrains.add_subparsers(required=True, dest="jetbrains_cmd")
    jetbrains_mission = jetbrains_sub.add_parser(
        "mission",
        help="render one Junie-compatible proof mission from a sealed repair scope",
    )
    jetbrains_mission.add_argument("--root", default=".")
    jetbrains_mission.add_argument("--scope", required=True)
    jetbrains_mission.add_argument("--changed", action="append", default=[])
    jetbrains_mission.add_argument("--json", action="store_true")
    jetbrains_handshake = jetbrains_sub.add_parser(
        "handshake",
        help="cross-check returned paths, analyzer SARIF, intent, and optional E2E proof",
    )
    jetbrains_handshake.add_argument("--root", default=".")
    jetbrains_handshake.add_argument("--scope", required=True)
    jetbrains_handshake.add_argument("--changed", action="append", required=True)
    analysis_input = jetbrains_handshake.add_mutually_exclusive_group(required=True)
    analysis_input.add_argument(
        "--analysis-sarif",
        help="workspace-local Qodana or SonarQube SARIF 2.1.0 report",
    )
    analysis_input.add_argument(
        "--qodana-sarif",
        help="compatibility alias for --analysis-sarif with provider qodana",
    )
    jetbrains_handshake.add_argument(
        "--analysis-provider", choices=["auto", "qodana", "sonarqube"], default="auto"
    )
    jetbrains_handshake.add_argument("--e2e-receipt")
    jetbrains_handshake.add_argument("--max-new-errors", type=int, default=0)
    jetbrains_handshake.add_argument("--max-new-warnings", type=int, default=0)
    jetbrains_handshake.add_argument(
        "--out", default=".factory/jetbrains-handshake/latest.json"
    )
    jetbrains_handshake.add_argument("--json", action="store_true")
    jetbrains_status = jetbrains_sub.add_parser(
        "status", help="read the latest hash-valid local JetBrains handshake receipt"
    )
    jetbrains_status.add_argument("--root", default=".")
    jetbrains_status.add_argument("--json", action="store_true")


def _add_repair_execution_parsers(sub) -> None:
    """Expose explicit one-patch approval, execution, revocation and stop commands."""
    approve = sub.add_parser(
        "approve", help="approve one exact candidate and container check contract"
    )
    approve.add_argument("--scope", required=True)
    approve.add_argument("--patch", required=True)
    approve.add_argument("--approved-by", required=True)
    approve.add_argument("--confirmation", required=True)
    approve.add_argument("--expires-at", required=True)
    approve.add_argument("--container-image", required=True)
    approve.add_argument("--container-digest", required=True)
    approve.add_argument(
        "--checks",
        required=True,
        help="workspace-contained JSON array of positive and negative argv checks",
    )
    approve.add_argument(
        "--checks-sha256",
        help="SHA256 of the exact checks file bytes reviewed by the operator",
    )
    approve.add_argument(
        "--audit-run-id",
        help="terminal deep-audit run whose candidate this repair resolves",
    )
    run = sub.add_parser(
        "run", help="consume approval once and verify a disposable-worktree repair"
    )
    run.add_argument("--approval", required=True)
    for name in ("revoke", "stop"):
        parser = sub.add_parser(name, help=f"{name} an explicitly approved repair")
        parser.add_argument("--approval-sha256", required=True)
        parser.add_argument("--requested-by", required=True)
        parser.add_argument("--reason", required=True)
    for parser in (approve, run, *[sub.choices[name] for name in ("revoke", "stop")]):
        parser.add_argument("--root", default=".")
        parser.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch repair commands with explicit authority or JetBrains proof work."""
    if a.cmd == "repair":
        return _run_repair(a)
    return _run_jetbrains(a)


def _run_repair(args) -> int:
    from . import repair_sandbox

    try:
        result = _execute_repair_command(args, repair_sandbox)
    except repair_sandbox.RepairSandboxError as exc:
        return _repair_error(args, exc)
    except ValueError as exc:
        return _repair_error(args, exc)
    _render_repair_result(args, result)
    if args.repair_cmd == "run" and result.get("status") != "VERIFIED":
        return 2
    if args.repair_cmd == "trace" and result.get("state") == "INCOMPLETE":
        return 2
    return 0


def _execute_repair_command(args, repair_sandbox):
    if args.repair_cmd == "trace":
        from .deep_audit import write_deep_audit_lineage

        return write_deep_audit_lineage(
            Path(args.root), args.run_id, approval_sha256=args.approval_sha256
        )
    if args.repair_cmd in {"approve", "run", "revoke", "stop"}:
        return _execute_approved_command(args, repair_sandbox)
    if args.repair_cmd == "scope":
        result = repair_sandbox.create_repair_scope(
            Path(args.root),
            args.change_list,
            args.changed,
            context_budget_bytes=args.context_budget_bytes,
        )
        if args.out_dir:
            result["artifacts"] = repair_sandbox.write_repair_scope_artifacts(
                result, Path(args.root), Path(args.out_dir)
            )
        return result
    result = repair_sandbox.inspect_repair_candidate(
        Path(args.root), Path(args.scope), Path(args.patch)
    )
    if args.out_dir:
        result["artifacts"] = repair_sandbox.write_repair_candidate_artifacts(
            result, Path(args.root), Path(args.out_dir)
        )
    return result


def _load_repair_checks(root: Path, value: str, repair_sandbox, expected_sha256=None):
    """Read bounded local check data without granting execution authority."""
    try:
        workspace = root.resolve()
        path = (workspace / value).resolve()
        path.relative_to(workspace)
        if not path.is_file() or path.stat().st_size > 1_000_000:
            raise ValueError("checks must be an existing file of at most 1 MB")
        with path.open("rb") as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError("checks exceed the input limit")
        if expected_sha256 is not None:
            if hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise ValueError("checks changed after operator review")
        checks = json.loads(raw.decode("utf-8"))
        if not isinstance(checks, list):
            raise ValueError("checks must be a JSON array")
        return checks
    except (OSError, ValueError) as exc:
        raise repair_sandbox.RepairSandboxError(
            "REPAIR_CHECKS_INPUT_INVALID",
            "checks must be a bounded workspace-contained JSON array",
        ) from exc


def _execute_approved_command(args, repair_sandbox):
    """Route explicit operator commands to the sealed repair controller."""
    root = Path(args.root)
    if args.repair_cmd == "approve":
        return repair_sandbox.create_repair_approval(
            root,
            Path(args.scope),
            Path(args.patch),
            approved_by=args.approved_by,
            confirmation=args.confirmation,
            expires_at=args.expires_at,
            container_image=args.container_image,
            container_digest=args.container_digest,
            checks=_load_repair_checks(
                root, args.checks, repair_sandbox, args.checks_sha256
            ),
            audit_run_id=args.audit_run_id,
        )
    if args.repair_cmd == "run":
        return repair_sandbox.execute_approved_repair(root, Path(args.approval))
    if args.repair_cmd == "revoke":
        return repair_sandbox.revoke_repair_approval(
            root, args.approval_sha256, revoked_by=args.requested_by, reason=args.reason
        )
    return repair_sandbox.request_repair_stop(
        root, args.approval_sha256, requested_by=args.requested_by, reason=args.reason
    )


def _repair_error(args, exc) -> int:
    message = str(exc)
    if args.repair_cmd in {"approve", "run", "revoke", "stop"}:
        schema = "factory.repair_approval.error.v1"
        message = "repair command rejected; use the error code to correct the approval or inspect local attempt evidence"
    else:
        schema = (
            "factory.repair_scope.error.v1"
            if args.repair_cmd == "scope"
            else "factory.repair_candidate.error.v1"
        )
    marker = (
        "REPAIR_SANDBOX_PATH_REJECTED"
        if "PATH" in exc.code or exc.code == "REPAIR_CANDIDATE_OUT_OF_SCOPE"
        else "REPAIR_SANDBOX_INPUT_UNAVAILABLE"
    )
    payload = {
        "schema": schema,
        "marker": marker,
        "code": exc.code,
        "message": message,
    }
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if args.json
        else f"repair {args.repair_cmd} failed: {exc.code}: {message}",
        file=sys.stderr,
    )
    return 2


def _render_repair_result(args, result) -> None:
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    if args.repair_cmd in {"approve", "run", "revoke", "stop", "trace"}:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"factory repair {args.repair_cmd} (supervised, no patch apply)")
    print("=" * 54)
    if args.repair_cmd == "scope":
        print(f"scope       : {result['scope_id']}")
        print(f"changed path: {len(result['paths'])}")
        print(
            f"context     : {result['context_budget']['measured_bytes']} / {result['context_budget']['limit_bytes']} bytes ({result['context_budget']['decision']})"
        )
        print(
            "next        : external supervised candidate, independent verifier, human apply"
        )
    else:
        print(f"candidate   : {result['candidate_sha256']}")
        print(f"touched path: {len(result['touched_paths'])}")
        print("next        : independent verifier, then human diff review and apply")
    if result.get("artifacts"):
        print(f"packet      : {result['artifacts']['paths']['markdown']}")
    print(
        "authority   : no source modification, test execution, commit, merge, publication, deployment, credential, or network action"
    )


def _run_jetbrains(args) -> int:
    from . import jetbrains_handshake

    root = Path(args.root).resolve()
    try:
        payload = _jetbrains_payload(args, root, jetbrains_handshake)
    except (
        jetbrains_handshake.JetBrainsHandshakeError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        return _jetbrains_error(args, exc)
    _render_jetbrains_result(args, payload)
    return _jetbrains_exit_code(args, payload)


def _jetbrains_payload(args, root: Path, handshake):
    if args.jetbrains_cmd == "mission":
        return handshake.build_agent_proof_mission(
            root, Path(args.scope), args.changed or None
        )
    if args.jetbrains_cmd == "status":
        return handshake.jetbrains_handshake_projection(root)
    analysis_path = args.qodana_sarif or args.analysis_sarif
    analysis_provider = "qodana" if args.qodana_sarif else args.analysis_provider
    payload = handshake.evaluate_jetbrains_handshake(
        root,
        Path(args.scope),
        args.changed,
        Path(analysis_path),
        Path(args.e2e_receipt) if args.e2e_receipt else None,
        analysis_provider=analysis_provider,
        max_new_errors=args.max_new_errors,
        max_new_warnings=args.max_new_warnings,
    )
    handshake.write_jetbrains_handshake(root, payload, Path(args.out))
    return payload


def _jetbrains_error(args, exc) -> int:
    code = getattr(exc, "code", "JETBRAINS_HANDSHAKE_INPUT_INVALID")
    error = {
        "schema": "factory.jetbrains-proof-handshake.error.v1",
        "marker": "JETBRAINS_PROOF_HANDSHAKE_REFUSED",
        "code": code,
        "message": str(exc),
    }
    print(
        json.dumps(error, indent=2, sort_keys=True)
        if args.json
        else f"jetbrains {args.jetbrains_cmd} refused: {code}: {exc}",
        file=sys.stderr,
    )
    return 2


def _render_jetbrains_result(args, payload) -> None:
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if args.json
        else payload.get(
            "mission_text", payload.get("marker", "JETBRAINS_PROOF_HANDSHAKE_OK")
        )
    )


def _jetbrains_exit_code(args, payload) -> int:
    if (
        args.jetbrains_cmd == "handshake"
        and payload["verdict"] != "ready_for_human_review"
    ):
        return 1
    return 0

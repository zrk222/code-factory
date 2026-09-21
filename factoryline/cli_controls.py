"""Bounded, lazily loaded control-plane and policy-controls CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMAND_GROUP = "controls"
OWNER = "control-plane-maintainers"


def _add_identity(parser: Any, *, default_role: str) -> None:
    parser.add_argument("--db", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--roles", default=default_role, help="comma-separated local roles")


def add_parser(sub: Any) -> None:
    """Register control-plane and policy controls without loading their engines."""
    control = sub.add_parser("control", help="manage local tenant-scoped evidence and approvals")
    control_sub = control.add_subparsers(required=True, dest="control_cmd")
    control_init = control_sub.add_parser("init", help="create a local evidence database")
    control_init.add_argument("--db", required=True)
    control_serve = control_sub.add_parser("serve", help="serve the local REST adapter for integration testing")
    control_serve.add_argument("--db", required=True)
    control_serve.add_argument("--host", default="127.0.0.1")
    control_serve.add_argument("--port", type=int, default=8765)
    evidence_put = control_sub.add_parser("evidence-put", help="store immutable tenant-scoped evidence")
    evidence_put.add_argument("payload")
    evidence_put.add_argument("--evidence-id")
    _add_identity(evidence_put, default_role="operator")
    evidence_get = control_sub.add_parser("evidence-get", help="read one evidence record")
    evidence_get.add_argument("evidence_id")
    _add_identity(evidence_get, default_role="viewer")
    evidence_list = control_sub.add_parser("evidence-list", help="list evidence for one tenant")
    _add_identity(evidence_list, default_role="viewer")
    approval_request = control_sub.add_parser("approval-request", help="request independent human approval")
    approval_request.add_argument("evidence_id")
    approval_request.add_argument("--reason", required=True)
    _add_identity(approval_request, default_role="operator")
    approval_decide = control_sub.add_parser("approval-decide", help="approve or reject a pending request")
    approval_decide.add_argument("approval_id")
    approval_decide.add_argument("--decision", required=True, choices=["approved", "rejected"])
    approval_decide.add_argument("--reason", required=True)
    _add_identity(approval_decide, default_role="approver")
    audit_verify = control_sub.add_parser("audit-verify", help="verify the tenant audit hash chain")
    _add_identity(audit_verify, default_role="viewer")

    controls = sub.add_parser("controls", help="evaluate versioned policy packs and evidence without release authority")
    controls_sub = controls.add_subparsers(required=True, dest="controls_cmd")
    manifest = controls_sub.add_parser("manifest", help="resolve a policy pack and inherited controls")
    manifest.add_argument("--root", default=".")
    manifest.add_argument("--policy", default="controls/policy-pack.json")
    manifest.add_argument("--json", action="store_true")
    evaluate = controls_sub.add_parser("evaluate", help="evaluate supplied immutable receipts for an event")
    evaluate.add_argument("--root", default=".")
    evaluate.add_argument("--policy", default="controls/policy-pack.json")
    evaluate.add_argument("--event-kind", choices=["working_tree", "merge", "agent_action", "deployment"], default="working_tree")
    evaluate.add_argument("--actor", default="local")
    evaluate.add_argument("--commit")
    evaluate.add_argument("--changed", action="append", default=[])
    evaluate.add_argument("--evidence", action="append", default=[])
    evaluate.add_argument("--exception", action="append", default=[])
    evaluate.add_argument("--baseline", help="workspace-relative baseline evaluation JSON")
    evaluate.add_argument("--out")
    evaluate.add_argument("--json", action="store_true")
    exception = controls_sub.add_parser("exception", help="create an expiry-bound, separately approved exception")
    exception.add_argument("control_id")
    exception.add_argument("--root", default=".")
    exception.add_argument("--policy", default="controls/policy-pack.json")
    exception.add_argument("--owner", required=True)
    exception.add_argument("--reason", required=True)
    exception.add_argument("--scope", required=True)
    exception.add_argument("--ttl-days", required=True, type=int)
    exception.add_argument("--evidence", required=True)
    exception.add_argument("--author", required=True)
    exception.add_argument("--approver", required=True)
    exception.add_argument("--out", required=True)
    exception.add_argument("--json", action="store_true")
    dossier = controls_sub.add_parser("dossier", help="write JSON, Markdown, and Mermaid review artifacts")
    dossier.add_argument("evaluation")
    dossier.add_argument("--root", default=".")
    dossier.add_argument("--out-dir", default=".factory/controls/dossiers")
    dossier.add_argument("--json", action="store_true")
    fleet = controls_sub.add_parser("fleet", help="show cross-repository policy coverage")
    fleet.add_argument("--root", default=".")
    fleet.add_argument("--manifest", default="controls/fleet.json")
    fleet.add_argument("--json", action="store_true")
    projection = controls_sub.add_parser("projection", help="read the bounded Graph Ops controls projection")
    projection.add_argument("--root", default=".")
    projection.add_argument("--json", action="store_true")


def _run_control(args: Any) -> int:
    from .control_plane import ControlPlaneError, EvidenceStore, principal_from_args

    try:
        if args.control_cmd == "init":
            EvidenceStore(Path(args.db))
            result = {"schema": "factory.control-plane.v1", "verdict": "READY", "db": str(Path(args.db).resolve())}
        elif args.control_cmd == "serve":
            from wsgiref.simple_server import make_server
            from .control_api import create_app

            print(f"factory control API listening on http://{args.host}:{args.port}")
            make_server(args.host, args.port, create_app(Path(args.db))).serve_forever()
            return 0
        else:
            store = EvidenceStore(Path(args.db))
            principal = principal_from_args(args.subject, args.tenant, args.roles.split(","))
            if args.control_cmd == "evidence-put":
                payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
                result = store.put(principal, payload, evidence_id=args.evidence_id)
            elif args.control_cmd == "evidence-get":
                result = store.get(principal, args.tenant, args.evidence_id)
            elif args.control_cmd == "evidence-list":
                result = {"schema": "factory.evidence.list.v1", "tenant_id": args.tenant, "records": store.list(principal, args.tenant)}
            elif args.control_cmd == "approval-request":
                result = store.request_approval(principal, args.tenant, args.evidence_id, args.reason)
            elif args.control_cmd == "approval-decide":
                result = store.decide_approval(principal, args.tenant, args.approval_id, args.decision, args.reason)
            else:
                result = store.verify_audit(principal, args.tenant)
    except (ControlPlaneError, json.JSONDecodeError, OSError) as exc:
        print(json.dumps({"schema": "factory.control-plane.result.v1", "verdict": "ERROR", "error": {"code": getattr(exc, "code", "E_INPUT"), "message": getattr(exc, "message", str(exc))}}, indent=2))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.control_cmd == "audit-verify":
        return 0 if result["valid"] else 1
    return 0


def _run_controls(args: Any) -> int:
    from .continuous_controls import ControlsError, continuous_controls_projection, create_exception, evaluate_controls, fleet_coverage, load_policy_pack, write_control_evaluation, write_controls_dossier

    try:
        root = Path(args.root).resolve()
        if args.controls_cmd == "manifest":
            result = load_policy_pack(root, args.policy)
            code = 0
        elif args.controls_cmd == "evaluate":
            baseline = json.loads((root / args.baseline).read_text(encoding="utf-8")) if args.baseline else None
            evaluation = evaluate_controls(root, args.policy, evidence_paths=args.evidence, exception_paths=args.exception, baseline=baseline, event={"kind": args.event_kind, "actor": args.actor, "commit": args.commit, "changed_paths": args.changed})
            stored = write_control_evaluation(root, evaluation, args.out)
            result = {"evaluation": evaluation, "receipt": {"path": stored["path"], "sha256": stored["sha256"]}}
            code = 0 if evaluation["decision"] == "READY_FOR_HUMAN_REVIEW" else 1
        elif args.controls_cmd == "exception":
            result = create_exception(root, args.policy, args.control_id, owner=args.owner, reason=args.reason, scope=args.scope, ttl_days=args.ttl_days, evidence_path=args.evidence, author=args.author, approver=args.approver, out=args.out)
            code = 0
        elif args.controls_cmd == "dossier":
            evaluation_path = (root / args.evaluation).resolve() if not Path(args.evaluation).is_absolute() else Path(args.evaluation)
            result = write_controls_dossier(root, json.loads(evaluation_path.read_text(encoding="utf-8")), args.out_dir)
            code = 0
        elif args.controls_cmd == "fleet":
            result = fleet_coverage(root, args.manifest)
            code = 0 if all(not item["missing_baseline"] for item in result["repositories"]) else 1
        else:
            result = continuous_controls_projection(root)
            code = 0 if result["invalid_count"] == 0 else 1
    except (ControlsError, OSError, json.JSONDecodeError, ValueError) as exc:
        result = {"schema": "factory.continuous-controls.result.v1", "verdict": "ERROR", "error": {"code": getattr(exc, "code", "E_INPUT"), "message": str(exc)}}
        code = 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        if args.controls_cmd == "manifest":
            print(f"policy {result['pack_id']}@{result['version']}: {result['status']} ({len(result['controls'])} controls)")
        elif args.controls_cmd == "evaluate":
            print(f"controls: {result['evaluation']['decision']} ({result['receipt']['path']})")
        elif args.controls_cmd == "dossier":
            print(f"controls dossier: {result['directory']}")
        elif args.controls_cmd == "fleet":
            print(f"fleet coverage: {len(result['repositories'])} repositories")
        else:
            print(f"controls projection: {result['evaluation_count']} evaluations")
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=__import__("sys").stderr)
    return code


def run(args: Any) -> int:
    """Dispatch control-plane and policy-control commands lazily."""
    if args.cmd == "control":
        return _run_control(args)
    return _run_controls(args)

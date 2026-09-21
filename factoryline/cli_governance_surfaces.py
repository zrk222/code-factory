"""CLI boundary for agent licenses and governed evidence scoreboards."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register license and Combine command families."""
    license_parser = sub.add_parser("license", help="derive and verify expiring, evidence-governed local agent autonomy tiers")
    license_sub = license_parser.add_subparsers(required=True, dest="license_cmd")
    record = license_sub.add_parser("record", help="record one already-admitted, independently verified governed run")
    record.add_argument("event", help="workspace-contained factory.agent-run.v1 JSON path")
    record.add_argument("--root", default=".")
    record.add_argument("--out-dir", help="optional workspace-contained immutable event directory")
    record.add_argument("--json", action="store_true")
    status = license_sub.add_parser("status", help="derive read-only current license facts for one declared agent identity")
    status.add_argument("--agent", required=True, help="workspace-contained factory.agent-identity.v1 JSON path")
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")
    issue = license_sub.add_parser("issue", help="write one locally hash-bound license derived from current governed evidence")
    issue.add_argument("--agent", required=True, help="workspace-contained factory.agent-identity.v1 JSON path")
    issue.add_argument("--root", default=".")
    issue.add_argument("--out", help="optional workspace-contained license JSON path")
    issue.add_argument("--json", action="store_true")
    verify = license_sub.add_parser("verify", help="verify one existing local license hash offline")
    verify.add_argument("license")
    verify.add_argument("--json", action="store_true")
    seal = license_sub.add_parser("seal", help="optionally bind one verified license to a Receipt v2 DSSE envelope")
    seal.add_argument("license")
    seal.add_argument("--private-key", required=True)
    seal.add_argument("--keyid", required=True)
    seal.add_argument("--identity", required=True)
    seal.add_argument("--issuer", required=True)
    seal.add_argument("--tenant", default="local")
    seal.add_argument("--out", required=True)
    seal.add_argument("--json", action="store_true")

    combine = sub.add_parser("combine", help="seal and compare completed governed agent evidence without launching an agent")
    combine_sub = combine.add_subparsers(required=True, dest="combine_cmd")
    task = combine_sub.add_parser("task", help="seal a human-written task declaration; the description stays hashed")
    task.add_argument("source", help="workspace-contained factory.combine-task.v1 JSON path")
    task.add_argument("--root", default=".")
    task.add_argument("--out", help="optional workspace-contained sealed task JSON path")
    task.add_argument("--json", action="store_true")
    score = combine_sub.add_parser("score", help="rank existing exact governed run events for one sealed task")
    score.add_argument("task", help="workspace-contained sealed Combine task JSON path")
    score.add_argument("--event", action="append", default=[], help="optional exact immutable governed event path; repeat for each candidate")
    score.add_argument("--root", default=".")
    score.add_argument("--out", help="optional workspace-contained scoreboard JSON path")
    score.add_argument("--json", action="store_true")
    combine_status = combine_sub.add_parser("status", help="read locally verified Combine scoreboards without execution")
    combine_status.add_argument("--root", default=".")
    combine_status.add_argument("--json", action="store_true")
    combine_verify = combine_sub.add_parser("verify", help="verify one Combine scoreboard hash offline")
    combine_verify.add_argument("scoreboard")
    combine_verify.add_argument("--json", action="store_true")
    combine_seal = combine_sub.add_parser("seal", help="optionally bind one verified Combine scoreboard to a Receipt v2 DSSE envelope")
    combine_seal.add_argument("scoreboard")
    combine_seal.add_argument("--private-key", required=True)
    combine_seal.add_argument("--keyid", required=True)
    combine_seal.add_argument("--identity", required=True)
    combine_seal.add_argument("--issuer", required=True)
    combine_seal.add_argument("--tenant", default="local")
    combine_seal.add_argument("--out", required=True)
    combine_seal.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one license or Combine command."""
    if args.cmd == "license":
        from .agent_license import AgentLicenseError, derive_license, issue_license, record_governed_run, seal_license, verify_license

        def local_path(workspace: Path, value: str) -> Path:
            candidate = Path(value)
            resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
            try:
                resolved.relative_to(workspace)
            except ValueError as exc:
                raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", "path must remain inside the workspace") from exc
            return resolved

        try:
            if args.license_cmd == "verify":
                payload = verify_license(Path(args.license))
                code = 0 if payload["ok"] else 1
            elif args.license_cmd == "seal":
                payload = seal_license(Path(args.license), private_key_path=Path(args.private_key), keyid=args.keyid, identity=args.identity, issuer=args.issuer, tenant_id=args.tenant, out=Path(args.out))
                code = 0
            else:
                workspace = Path(args.root).resolve()
                if not workspace.is_dir():
                    raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", "root must be an existing workspace directory")
                if args.license_cmd == "record":
                    payload = record_governed_run(workspace, local_path(workspace, args.event), out_dir=local_path(workspace, args.out_dir) if args.out_dir else None)
                else:
                    identity = json.loads(local_path(workspace, args.agent).read_text(encoding="utf-8-sig"))
                    payload = {"marker": "AGENT_LICENSE_STATUS_READ_ONLY", "license": derive_license(workspace, identity), "authority": {"execution": False, "approval": False, "repair": False, "merge": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False}} if args.license_cmd == "status" else issue_license(workspace, identity, out=local_path(workspace, args.out) if args.out else None)
                    code = 0
        except (AgentLicenseError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            error = {"schema": "factory.agent-license.error.v1", "marker": getattr(exc, "code", "E_LICENSE_INPUT_UNREADABLE"), "code": getattr(exc, "code", "E_LICENSE_INPUT_UNREADABLE"), "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if args.json else f"agent license failed: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory license")
            print("=" * 44)
            if args.license_cmd == "status":
                value = payload["license"]
                print(f"tier      : {value['tier']}")
                print(f"reason    : {value['reason']}")
                print(f"evidence  : {value['evidence']['current_governed_event_count']} current governed event(s)")
                print(f"expires   : {value['expires_at'] or 'no evidence'}")
            else:
                print(f"marker    : {payload['marker']}")
            print("authority : local evidence only; no agent execution, approval, repair, merge, publication, deployment, or credential authority")
        return code

    from .combine import CombineError, combine_projection, score_combine, seal_combine_scoreboard, seal_combine_task, verify_combine_scoreboard
    from .agent_license import AgentLicenseError

    def local_path(workspace: Path, value: str) -> Path:
        candidate = Path(value)
        resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
        try:
            resolved.relative_to(workspace)
        except ValueError as exc:
            raise CombineError("COMBINE_PATH_OUT_OF_SCOPE", "path must remain inside the workspace") from exc
        return resolved

    try:
        if args.combine_cmd == "verify":
            payload = verify_combine_scoreboard(Path(args.scoreboard))
            code = 0 if payload["ok"] else 1
        elif args.combine_cmd == "seal":
            payload = seal_combine_scoreboard(Path(args.scoreboard), private_key_path=Path(args.private_key), keyid=args.keyid, identity=args.identity, issuer=args.issuer, tenant_id=args.tenant, out=Path(args.out))
            code = 0
        else:
            workspace = Path(args.root).resolve()
            if not workspace.is_dir():
                raise CombineError("COMBINE_PATH_OUT_OF_SCOPE", "root must be an existing workspace directory")
            if args.combine_cmd == "task":
                payload = seal_combine_task(workspace, local_path(workspace, args.source), out=local_path(workspace, args.out) if args.out else None)
            elif args.combine_cmd == "score":
                payload = score_combine(workspace, local_path(workspace, args.task), event_paths=[local_path(workspace, event) for event in args.event] or None, out=local_path(workspace, args.out) if args.out else None)
            else:
                payload = combine_projection(workspace)
            code = 0
    except (CombineError, AgentLicenseError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        error = {"schema": "factory.combine.error.v1", "marker": getattr(exc, "code", "COMBINE_INPUT_UNREADABLE"), "code": getattr(exc, "code", "COMBINE_INPUT_UNREADABLE"), "message": str(exc)}
        print(json.dumps(error, indent=2, sort_keys=True) if args.json else f"combine failed: {error['code']}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("factory combine")
        print("=" * 44)
        if args.combine_cmd == "status":
            print(f"scoreboards: {len(payload['scoreboards'])}")
        elif args.combine_cmd == "score":
            print(f"passed    : {payload['scoreboard']['summary']['passed_count']}/{payload['scoreboard']['summary']['candidate_count']}")
            print(f"scoreboard: {payload['path']}")
        else:
            print(f"marker    : {payload['marker']}")
        print("authority : completed governed evidence only; no agent execution, vendor ranking, repair, approval, merge, publication, or deployment")
    return code

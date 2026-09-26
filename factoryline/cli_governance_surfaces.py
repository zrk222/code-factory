"""CLI boundary for agent licenses and governed evidence scoreboards."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register license and Combine command families."""
    license_parser = sub.add_parser(
        "license",
        help="derive and verify expiring, evidence-governed local agent autonomy tiers",
    )
    license_sub = license_parser.add_subparsers(required=True, dest="license_cmd")
    record = license_sub.add_parser(
        "record",
        help="record one already-admitted, independently verified governed run",
    )
    record.add_argument(
        "event", help="workspace-contained factory.agent-run.v1 JSON path"
    )
    record.add_argument("--root", default=".")
    record.add_argument(
        "--out-dir", help="optional workspace-contained immutable event directory"
    )
    record.add_argument("--json", action="store_true")
    status = license_sub.add_parser(
        "status",
        help="derive read-only current license facts for one declared agent identity",
    )
    status.add_argument(
        "--agent",
        required=True,
        help="workspace-contained factory.agent-identity.v1 JSON path",
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")
    issue = license_sub.add_parser(
        "issue",
        help="write one locally hash-bound license derived from current governed evidence",
    )
    issue.add_argument(
        "--agent",
        required=True,
        help="workspace-contained factory.agent-identity.v1 JSON path",
    )
    issue.add_argument("--root", default=".")
    issue.add_argument("--out", help="optional workspace-contained license JSON path")
    issue.add_argument("--json", action="store_true")
    verify = license_sub.add_parser(
        "verify", help="verify one existing local license hash offline"
    )
    verify.add_argument("license")
    verify.add_argument("--json", action="store_true")
    seal = license_sub.add_parser(
        "seal",
        help="optionally bind one verified license to a Receipt v2 DSSE envelope",
    )
    seal.add_argument("license")
    seal.add_argument("--private-key", required=True)
    seal.add_argument("--keyid", required=True)
    seal.add_argument("--identity", required=True)
    seal.add_argument("--issuer", required=True)
    seal.add_argument("--tenant", default="local")
    seal.add_argument("--out", required=True)
    seal.add_argument("--json", action="store_true")

    combine = sub.add_parser(
        "combine",
        help="seal and compare completed governed agent evidence without launching an agent",
    )
    combine_sub = combine.add_subparsers(required=True, dest="combine_cmd")
    task = combine_sub.add_parser(
        "task",
        help="seal a human-written task declaration; the description stays hashed",
    )
    task.add_argument(
        "source", help="workspace-contained factory.combine-task.v1 JSON path"
    )
    task.add_argument("--root", default=".")
    task.add_argument(
        "--out", help="optional workspace-contained sealed task JSON path"
    )
    task.add_argument("--json", action="store_true")
    score = combine_sub.add_parser(
        "score", help="rank existing exact governed run events for one sealed task"
    )
    score.add_argument("task", help="workspace-contained sealed Combine task JSON path")
    score.add_argument(
        "--event",
        action="append",
        default=[],
        help="optional exact immutable governed event path; repeat for each candidate",
    )
    score.add_argument("--root", default=".")
    score.add_argument(
        "--out", help="optional workspace-contained scoreboard JSON path"
    )
    score.add_argument("--json", action="store_true")
    combine_status = combine_sub.add_parser(
        "status", help="read locally verified Combine scoreboards without execution"
    )
    combine_status.add_argument("--root", default=".")
    combine_status.add_argument("--json", action="store_true")
    combine_verify = combine_sub.add_parser(
        "verify", help="verify one Combine scoreboard hash offline"
    )
    combine_verify.add_argument("scoreboard")
    combine_verify.add_argument("--json", action="store_true")
    combine_seal = combine_sub.add_parser(
        "seal",
        help="optionally bind one verified Combine scoreboard to a Receipt v2 DSSE envelope",
    )
    combine_seal.add_argument("scoreboard")
    combine_seal.add_argument("--private-key", required=True)
    combine_seal.add_argument("--keyid", required=True)
    combine_seal.add_argument("--identity", required=True)
    combine_seal.add_argument("--issuer", required=True)
    combine_seal.add_argument("--tenant", default="local")
    combine_seal.add_argument("--out", required=True)
    combine_seal.add_argument("--json", action="store_true")


def _workspace_path(
    workspace: Path,
    value: str,
    error_type: type[Exception],
    code: str,
    message: str,
) -> Path:
    candidate = Path(value)
    resolved = (
        candidate.resolve()
        if candidate.is_absolute()
        else (workspace / candidate).resolve()
    )
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise error_type(code, message) from exc
    return resolved


def _require_workspace(root: str, error_type: type[Exception], code: str) -> Path:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise error_type(code, "root must be an existing workspace directory")
    return workspace


def _license_workspace_path(workspace: Path, value: str) -> Path:
    from .agent_license import AgentLicenseError

    return _workspace_path(
        workspace,
        value,
        AgentLicenseError,
        "E_LICENSE_PATH_OUT_OF_SCOPE",
        "path must remain inside the workspace",
    )


def _license_payload(args: Any) -> tuple[dict[str, Any], int]:
    from .agent_license import (
        derive_license,
        issue_license,
        record_governed_run,
        seal_license,
        verify_license,
    )

    if args.license_cmd == "verify":
        payload = verify_license(Path(args.license))
        return payload, 0 if payload["ok"] else 1
    if args.license_cmd == "seal":
        payload = seal_license(
            Path(args.license),
            private_key_path=Path(args.private_key),
            keyid=args.keyid,
            identity=args.identity,
            issuer=args.issuer,
            tenant_id=args.tenant,
            out=Path(args.out),
        )
        return payload, 0
    from .agent_license import AgentLicenseError

    workspace = _require_workspace(
        args.root, AgentLicenseError, "E_LICENSE_PATH_OUT_OF_SCOPE"
    )
    if args.license_cmd == "record":
        return _record_license(args, workspace, record_governed_run), 0
    identity = json.loads(
        _license_workspace_path(workspace, args.agent).read_text(encoding="utf-8-sig")
    )
    if args.license_cmd == "status":
        return _license_status(workspace, identity, derive_license), 0
    output = _license_workspace_path(workspace, args.out) if args.out else None
    return issue_license(workspace, identity, out=output), 0


def _record_license(args: Any, workspace: Path, record: Any) -> dict[str, Any]:
    event = _license_workspace_path(workspace, args.event)
    output = _license_workspace_path(workspace, args.out_dir) if args.out_dir else None
    return record(workspace, event, out_dir=output)


def _license_status(
    workspace: Path, identity: dict[str, Any], derive: Any
) -> dict[str, Any]:
    return {
        "marker": "AGENT_LICENSE_STATUS_READ_ONLY",
        "license": derive(workspace, identity),
        "authority": {
            "execution": False,
            "approval": False,
            "repair": False,
            "merge": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "messaging": False,
            "credential": False,
            "connector": False,
        },
    }


def _print_error(args: Any, error: dict[str, str], exc: Exception, label: str) -> None:
    rendered = (
        json.dumps(error, indent=2, sort_keys=True)
        if args.json
        else f"{label} failed: {error['code']}: {exc}"
    )
    print(rendered, file=sys.stderr)


def _render_license(args: Any, payload: dict[str, Any]) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print("factory license")
    print("=" * 44)
    if args.license_cmd == "status":
        value = payload["license"]
        print(f"tier      : {value['tier']}")
        print(f"reason    : {value['reason']}")
        print(
            f"evidence  : {value['evidence']['current_governed_event_count']} current governed event(s)"
        )
        print(f"expires   : {value['expires_at'] or 'no evidence'}")
    else:
        print(f"marker    : {payload['marker']}")
    print(
        "authority : local evidence only; no agent execution, approval, repair, merge, publication, deployment, or credential authority"
    )


def _run_license(args: Any) -> int:
    from .agent_license import AgentLicenseError

    try:
        payload, code = _license_payload(args)
    except (
        AgentLicenseError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        error = {
            "schema": "factory.agent-license.error.v1",
            "marker": getattr(exc, "code", "E_LICENSE_INPUT_UNREADABLE"),
            "code": getattr(exc, "code", "E_LICENSE_INPUT_UNREADABLE"),
            "message": str(exc),
        }
        _print_error(args, error, exc, "agent license")
        return 2
    _render_license(args, payload)
    return code


def _combine_workspace_path(workspace: Path, value: str) -> Path:
    from .combine import CombineError

    return _workspace_path(
        workspace,
        value,
        CombineError,
        "COMBINE_PATH_OUT_OF_SCOPE",
        "path must remain inside the workspace",
    )


def _combine_payload(args: Any) -> tuple[dict[str, Any], int]:
    from .combine import (
        combine_projection,
        score_combine,
        seal_combine_scoreboard,
        seal_combine_task,
        verify_combine_scoreboard,
    )

    if args.combine_cmd == "verify":
        payload = verify_combine_scoreboard(Path(args.scoreboard))
        return payload, 0 if payload["ok"] else 1
    if args.combine_cmd == "seal":
        payload = seal_combine_scoreboard(
            Path(args.scoreboard),
            private_key_path=Path(args.private_key),
            keyid=args.keyid,
            identity=args.identity,
            issuer=args.issuer,
            tenant_id=args.tenant,
            out=Path(args.out),
        )
        return payload, 0
    from .combine import CombineError

    workspace = _require_workspace(args.root, CombineError, "COMBINE_PATH_OUT_OF_SCOPE")
    return _combine_workspace_payload(
        args, workspace, seal_combine_task, score_combine, combine_projection
    ), 0


def _combine_workspace_payload(
    args: Any, workspace: Path, seal_task: Any, score: Any, project: Any
) -> dict[str, Any]:
    if args.combine_cmd == "task":
        source = _combine_workspace_path(workspace, args.source)
        output = _combine_workspace_path(workspace, args.out) if args.out else None
        return seal_task(workspace, source, out=output)
    if args.combine_cmd == "score":
        task = _combine_workspace_path(workspace, args.task)
        events = [_combine_workspace_path(workspace, item) for item in args.event]
        output = _combine_workspace_path(workspace, args.out) if args.out else None
        return score(workspace, task, event_paths=events or None, out=output)
    return project(workspace)


def _render_combine(args: Any, payload: dict[str, Any]) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print("factory combine")
    print("=" * 44)
    if args.combine_cmd == "status":
        print(f"scoreboards: {len(payload['scoreboards'])}")
    elif args.combine_cmd == "score":
        summary = payload["scoreboard"]["summary"]
        print(f"passed    : {summary['passed_count']}/{summary['candidate_count']}")
        print(f"scoreboard: {payload['path']}")
    else:
        print(f"marker    : {payload['marker']}")
    print(
        "authority : completed governed evidence only; no agent execution, vendor ranking, repair, approval, merge, publication, or deployment"
    )


def _run_combine(args: Any) -> int:
    from .agent_license import AgentLicenseError
    from .combine import CombineError

    try:
        payload, code = _combine_payload(args)
    except (
        CombineError,
        AgentLicenseError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        error = {
            "schema": "factory.combine.error.v1",
            "marker": getattr(exc, "code", "COMBINE_INPUT_UNREADABLE"),
            "code": getattr(exc, "code", "COMBINE_INPUT_UNREADABLE"),
            "message": str(exc),
        }
        _print_error(args, error, exc, "combine")
        return 2
    _render_combine(args, payload)
    return code


def run(args: Any) -> int:
    """Execute one license or Combine command."""
    if args.cmd == "license":
        return _run_license(args)
    return _run_combine(args)

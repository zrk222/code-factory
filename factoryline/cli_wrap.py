"""CLI boundary for observed agent sessions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register the observed-session wrapper command."""
    wrap = sub.add_parser(
        "wrap",
        help="run any admitted local agent CLI as an observed, validated evidence session",
    )
    wrap.add_argument("--root", default=".")
    wrap.add_argument(
        "--admission", required=True, help="READY factory.run-admission.packet.v1 path"
    )
    wrap.add_argument(
        "--validators",
        required=True,
        help="factory.session-recorder.validators.v1 path",
    )
    wrap.add_argument(
        "--run-id", required=True, help="unique lowercase immutable event id"
    )
    wrap.add_argument("--json", action="store_true")
    wrap.add_argument(
        "command", nargs=argparse.REMAINDER, help="agent command argv after --"
    )


def run(args: Any) -> int:
    """Execute an admitted observed session and print its receipt."""
    from .session_recorder import SessionRecorderError, run_observed_session
    from .agent_license import AgentLicenseError

    workspace = Path(args.root).resolve()
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        payload = run_observed_session(
            workspace,
            workspace / args.admission,
            workspace / args.validators,
            command,
            args.run_id,
        )
    except (SessionRecorderError, AgentLicenseError) as exc:
        code = getattr(exc, "code", "SESSION_FAILED")
        error = {
            "schema": "factory.observed-session.error.v1",
            "marker": code,
            "code": code,
            "message": str(exc),
        }
        print(
            json.dumps(error, indent=2, sort_keys=True)
            if args.json
            else f"wrap failed: {code}: {exc}",
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("factory wrap")
        print("=" * 44)
        print(f"result   : {'PASSED' if payload['session']['passed'] else 'FAILED'}")
        print(f"receipt  : {payload['path']}")
        print(
            "authority: observed local execution and declared validators; not a sandbox, approval, repair, merge, publication, or deployment"
        )
    return 0 if payload["session"]["passed"] else 1

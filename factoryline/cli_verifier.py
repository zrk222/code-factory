"""Bounded, lazily loaded verifier-plane CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMAND_GROUP = "verifier"
OWNER = "verification-plane-maintainers"


def add_parser(sub: Any) -> None:
    """Register verifier commands without importing the verifier engine."""
    verifier = sub.add_parser(
        "verifier",
        help="bind independent verifier evidence without execution, merge, or publish authority",
    )
    verifier_sub = verifier.add_subparsers(dest="verifier_cmd", required=True)
    verifier_session = verifier_sub.add_parser(
        "session", help="create a hash-bound verifier session contract"
    )
    verifier_session.add_argument("mission", help="factory.mission.v1 mission receipt")
    verifier_session.add_argument(
        "candidate_root", help="candidate tree the worker may change"
    )
    verifier_session.add_argument(
        "--bundle",
        action="append",
        required=True,
        help="immutable verifier bundle file; repeatable",
    )
    verifier_session.add_argument(
        "--owner", required=True, help="human owner responsible for review"
    )
    verifier_session.add_argument("--root", default=".")
    verifier_session.add_argument("--max-attempts", type=int, default=5)
    verifier_session.add_argument("--max-wall-seconds", type=int, default=3600)
    verifier_session.add_argument("--max-tokens", type=int, default=100000)
    verifier_session.add_argument("--max-cost-usd", type=float, default=25.0)
    verifier_session.add_argument("--force", action="store_true")
    verifier_session.add_argument("--json", action="store_true")
    verifier_verify = verifier_sub.add_parser(
        "verify",
        help="validate one independent verifier result against its bound session",
    )
    verifier_verify.add_argument("session", help="verifier session receipt")
    verifier_verify.add_argument(
        "worker_result", help="factory.verifier-worker-result.v1 receipt"
    )
    verifier_verify.add_argument(
        "verifier_result", help="factory.verifier-result.v1 receipt"
    )
    verifier_verify.add_argument("--root", default=".")
    verifier_verify.add_argument("--json", action="store_true")
    verifier_progress = verifier_sub.add_parser(
        "progress",
        help="halt repeated deterministic failures without using an LLM judgment",
    )
    verifier_progress.add_argument(
        "attempts", help="JSON array of worker attempt observations"
    )
    verifier_progress.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one verifier-plane command and emit its receipt."""
    from .verifier_plane import (
        VerifierPlaneError,
        create_verifier_session,
        evaluate_progress,
        verify_verifier_result,
    )

    try:
        if args.verifier_cmd == "session":
            result = create_verifier_session(
                Path(args.root),
                Path(args.mission),
                Path(args.candidate_root),
                [Path(item) for item in args.bundle],
                args.owner,
                max_attempts=args.max_attempts,
                max_wall_seconds=args.max_wall_seconds,
                max_tokens=args.max_tokens,
                max_cost_usd=args.max_cost_usd,
                force=args.force,
            )
        elif args.verifier_cmd == "verify":
            result = verify_verifier_result(
                Path(args.session),
                Path(args.worker_result),
                Path(args.verifier_result),
                Path(args.root),
            )
        else:
            attempts = json.loads(Path(args.attempts).read_text(encoding="utf-8"))
            result = evaluate_progress(attempts)
    except VerifierPlaneError as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.workflow_error.v1",
                    "status": "failed",
                    "code": exc.code,
                    "message": exc.message,
                    "marker": getattr(exc, "marker", "WORKFLOW_REJECTED"),
                },
                indent=2,
            )
        )
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.workflow_error.v1",
                    "status": "failed",
                    "code": "E_INPUT",
                    "message": str(exc),
                },
                indent=2,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.verifier_cmd == "verify":
        return 0 if result.get("valid", result.get("verdict") == "VERIFIED") else 1
    return 0

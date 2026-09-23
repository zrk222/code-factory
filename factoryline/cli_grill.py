"""CLI boundary for the deterministic intent-grill workflow."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register the ``factory grill`` command family."""
    grill = sub.add_parser(
        "grill", help="run a deterministic one-question-at-a-time intent grill"
    )
    grill_sub = grill.add_subparsers(dest="grill_cmd", required=True)
    grill_start = grill_sub.add_parser(
        "start", help="start a source-bound grill session"
    )
    grill_start.add_argument("session_id")
    grill_start.add_argument("--root", default=".")
    grill_start.add_argument("--source")
    grill_start.add_argument("--json", action="store_true")
    grill_next = grill_sub.add_parser(
        "next", help="show only the next unresolved question"
    )
    grill_next.add_argument("session_id")
    grill_next.add_argument("--root", default=".")
    grill_next.add_argument("--json", action="store_true")
    grill_answer = grill_sub.add_parser(
        "answer", help="record one human answer and advance the frontier"
    )
    grill_answer.add_argument("session_id")
    grill_answer.add_argument("question_id")
    grill_answer.add_argument("answer")
    grill_answer.add_argument("--answered-by", required=True)
    grill_answer.add_argument("--root", default=".")
    grill_answer.add_argument("--json", action="store_true")
    grill_confirm = grill_sub.add_parser(
        "confirm", help="confirm shared understanding before implementation"
    )
    grill_confirm.add_argument("session_id")
    grill_confirm.add_argument("--approved-by", required=True)
    grill_confirm.add_argument("--root", default=".")
    grill_confirm.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute a grill operation after the parser has selected the command."""
    from .grill_engine import answer_question, confirm_grill, next_question, start_grill

    root = Path(args.root).resolve()
    try:
        if args.grill_cmd == "start":
            result = start_grill(
                root, args.session_id, Path(args.source) if args.source else None
            )
        elif args.grill_cmd == "next":
            result = next_question(root, args.session_id)
        elif args.grill_cmd == "answer":
            result = answer_question(
                root,
                args.session_id,
                args.question_id,
                args.answer,
                answered_by=args.answered_by,
            )
        else:
            result = confirm_grill(root, args.session_id, approved_by=args.approved_by)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        result = {
            "schema": "factory.grill.error.v1",
            "status": "BLOCKED",
            "code": "GRILL_INPUT_INVALID",
            "message": str(exc),
        }
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(result, indent=2, sort_keys=True)
        if getattr(args, "json", False)
        else f"grill {args.grill_cmd}: {result.get('status', 'READY')}"
    )
    return 0

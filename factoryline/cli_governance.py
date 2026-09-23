"""Lazy CLI boundary for intent, judgment, and memory governance commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register human-intent, judgment, and compact memory CLI commands."""
    intent = sub.add_parser(
        "intent",
        help="capture or inspect a human-confirmed, local Change List behavioral contract",
    )
    intent_sub = intent.add_subparsers(required=True, dest="intent_cmd")
    intent_capture = intent_sub.add_parser(
        "capture",
        help="write one explicitly confirmed local Intent Ledger record; no source or Change List change",
    )
    intent_capture.add_argument("--root", default=".")
    intent_capture.add_argument(
        "--change-list",
        required=True,
        help="native Change List label supplied by the IDE",
    )
    intent_capture.add_argument(
        "--changed",
        action="append",
        required=True,
        help="explicit workspace-relative Change List path; repeat as needed",
    )
    intent_capture.add_argument(
        "--confirmed-by",
        required=True,
        help="named human confirming the behavioral contract",
    )
    intent_capture.add_argument(
        "--promise",
        required=True,
        help="observable behavior this Change List must provide",
    )
    intent_capture.add_argument(
        "--non-goal",
        required=True,
        help="explicit behavior excluded from this Change List",
    )
    intent_capture.add_argument(
        "--failure-case",
        required=True,
        help="negative behavior the eventual proof must be able to detect",
    )
    intent_capture.add_argument(
        "--confirmation", required=True, help="must exactly equal CAPTURE <change-list>"
    )
    intent_capture.add_argument("--json", action="store_true")
    intent_inspect = intent_sub.add_parser(
        "inspect",
        help="read the current scope, stale-proof, and coverage state without writing or executing",
    )
    intent_inspect.add_argument("--root", default=".")
    intent_inspect.add_argument(
        "--change-list",
        required=True,
        help="native Change List label supplied by the IDE",
    )
    intent_inspect.add_argument(
        "--changed",
        action="append",
        default=[],
        help="explicit workspace-relative Change List path; repeat as needed",
    )
    intent_inspect.add_argument("--base", default="main")
    intent_inspect.add_argument("--json", action="store_true")

    judgment = sub.add_parser(
        "judgment",
        help="record human-promoted engineering decisions and compile read-only Change Safety Cases",
    )
    judgment_sub = judgment.add_subparsers(required=True, dest="judgment_cmd")
    judgment_propose = judgment_sub.add_parser(
        "propose",
        help="store one named human Capsule proposal; no safety-case authority until independent promotion",
    )
    judgment_propose.add_argument(
        "capsule", help="candidate factory.judgment.capsule.v1 JSON path"
    )
    judgment_propose.add_argument("--root", default=".")
    judgment_propose.add_argument("--proposed-by", required=True)
    judgment_propose.add_argument("--json", action="store_true")
    judgment_promote = judgment_sub.add_parser(
        "promote", help="independently promote one proposed Capsule"
    )
    judgment_promote.add_argument("capsule_id")
    judgment_promote.add_argument("--root", default=".")
    judgment_promote.add_argument("--promoted-by", required=True)
    judgment_promote.add_argument("--reason", required=True)
    judgment_promote.add_argument("--json", action="store_true")
    judgment_reconsider = judgment_sub.add_parser(
        "reconsider",
        help="record a successor proposal while retaining an active Capsule",
    )
    judgment_reconsider.add_argument("capsule_id")
    judgment_reconsider.add_argument("--successor", required=True)
    judgment_reconsider.add_argument("--root", default=".")
    judgment_reconsider.add_argument("--requested-by", required=True)
    judgment_reconsider.add_argument("--reason", required=True)
    judgment_reconsider.add_argument("--json", action="store_true")
    judgment_status_parser = judgment_sub.add_parser(
        "status", help="read tracked Capsule state without writes"
    )
    judgment_status_parser.add_argument("--root", default=".")
    judgment_status_parser.add_argument("--json", action="store_true")
    judgment_safety = judgment_sub.add_parser(
        "safety-case", help="compile a deterministic, no-execution Change Safety Case"
    )
    judgment_safety.add_argument("--root", default=".")
    judgment_safety.add_argument(
        "--changed",
        action="append",
        required=True,
        help="explicit workspace-relative changed path; repeat as needed",
    )
    judgment_safety.add_argument(
        "--proof-receipt",
        action="append",
        default=[],
        help="workspace-contained hash-bound obligation receipt; repeat as needed",
    )
    judgment_safety.add_argument(
        "--change-profile",
        help="optional workspace-contained, hash-bound declared change profile JSON",
    )
    judgment_safety.add_argument("--json", action="store_true")

    memory = sub.add_parser(
        "memory",
        help="read a compact next-proof brief with redacted continuity and observed local Git attribution",
    )
    memory_sub = memory.add_subparsers(required=True, dest="memory_cmd")
    memory_brief = memory_sub.add_parser(
        "brief",
        help="inspect current change evidence without running a proof or recalling memory bodies",
    )
    memory_brief.add_argument("--root", default=".")
    memory_brief.add_argument("--base", default="main")
    memory_brief.add_argument(
        "--changed",
        action="append",
        default=[],
        help="workspace-relative changed path; repeat as needed",
    )
    memory_brief.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch governance commands with human-owned authority boundaries."""
    if a.cmd == "memory":
        from .developer_memory import developer_memory_brief

        brief = developer_memory_brief(
            Path(a.root), base=a.base, changed=a.changed or None
        )
        if a.json:
            print(json.dumps(brief, indent=2, sort_keys=True))
        else:
            next_action = brief["next_action"]
            team = brief["team"]
            print("factory memory brief (read-only)")
            print("=" * 44)
            print(f"next action : {next_action['action']}")
            print(f"actions     : {len(brief['actions'])}")
            print(
                f"team source : {team['source']['kind']} ({team['source']['roster_completeness']})"
            )
            print(
                "authority   : no proof execution, approval, memory recall, publication, deployment, or credential access"
            )
        return 0

    if a.cmd == "intent":
        from .change_review import ChangeReviewError
        from .intent_ledger import (
            IntentLedgerError,
            capture_intent_ledger,
            inspect_intent_ledger,
        )

        root = Path(a.root)
        try:
            if a.intent_cmd == "capture":
                payload = capture_intent_ledger(
                    root,
                    change_list=a.change_list,
                    changed=a.changed,
                    confirmed_by=a.confirmed_by,
                    promise=a.promise,
                    non_goal=a.non_goal,
                    failure_case=a.failure_case,
                    confirmation=a.confirmation,
                )
            else:
                payload = inspect_intent_ledger(
                    root,
                    change_list=a.change_list,
                    changed=a.changed or None,
                    base=a.base,
                )
        except (IntentLedgerError, ChangeReviewError, OSError) as exc:
            code = getattr(exc, "code", "INTENT_LEDGER_INPUT_UNAVAILABLE")
            error = {
                "schema": "factory.intent-ledger.error.v1",
                "marker": "INTENT_LEDGER_REFUSED",
                "code": code,
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if a.json
                else f"intent {a.intent_cmd} refused: {code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif a.intent_cmd == "capture":
            print(f"INTENT_LEDGER_CAPTURED {payload['path']}")
            print(
                "authority : local record only; no source, test, agent, approval, repair, merge, publication, deployment, signing, messaging, credential, connector, or memory-recall action ran"
            )
        else:
            print("factory intent inspect (local, read-only)")
            print("=" * 44)
            print(f"change list : {payload['change_list']}")
            print(f"state       : {payload['state']}")
            print(f"next action : {payload['next_action']['action']}")
            print(
                "authority   : no record write, source write, execution, agent start, approval, repair, merge, publication, deployment, signing, messaging, credential, connector, or memory recall"
            )
        return (
            2
            if a.intent_cmd == "inspect"
            and payload["state"]
            in {"intent_ledger_invalid", "change_review_unavailable"}
            else 0
        )

    if a.cmd == "judgment":
        from .judgment import (
            JudgmentError,
            judgment_status,
            promote_capsule,
            propose_capsule,
            reconsider_capsule,
            safety_case,
        )

        try:
            if a.judgment_cmd == "propose":
                candidate = json.loads(Path(a.capsule).read_text(encoding="utf-8"))
                payload = propose_capsule(
                    Path(a.root), candidate, proposed_by=a.proposed_by
                )
            elif a.judgment_cmd == "promote":
                payload = promote_capsule(
                    Path(a.root),
                    a.capsule_id,
                    promoted_by=a.promoted_by,
                    reason=a.reason,
                )
            elif a.judgment_cmd == "reconsider":
                payload = reconsider_capsule(
                    Path(a.root),
                    a.capsule_id,
                    a.successor,
                    requested_by=a.requested_by,
                    reason=a.reason,
                )
            elif a.judgment_cmd == "safety-case":
                payload = safety_case(
                    Path(a.root),
                    changed=a.changed,
                    proof_receipts=[Path(item) for item in a.proof_receipt],
                    change_profile=Path(a.change_profile) if a.change_profile else None,
                )
            else:
                payload = judgment_status(Path(a.root))
        except (
            JudgmentError,
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            code = getattr(exc, "code", "JUDGMENT_INPUT_INVALID")
            error = {
                "schema": "factory.judgment.error.v1",
                "marker": "JUDGMENT_REFUSED",
                "code": code,
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if a.json
                else f"judgment {a.judgment_cmd} refused: {code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif a.judgment_cmd == "status":
            print("factory judgment status (read-only)")
            print("=" * 44)
            print(f"state    : {payload['state']}")
            print(f"active   : {payload.get('counts', {}).get('active', 0)}")
            print(f"proposed : {payload.get('counts', {}).get('proposed', 0)}")
            print(
                "authority: no model, source write, execution, approval, repair, merge, publication, deployment, signing, messaging, or credential access"
            )
        elif a.judgment_cmd == "safety-case":
            print("factory judgment safety-case (read-only)")
            print("=" * 44)
            print(f"route         : {payload['route']}")
            print(f"capsules      : {len(payload['matching_capsules'])}")
            print(f"missing proofs: {len(payload['missing_obligations'])}")
            print(f"unclassified  : {len(payload['unclassified_changed_paths'])}")
            print(
                "authority     : no execution, approval, repair, merge, publication, deployment, signing, messaging, or credential access"
            )
        else:
            print(f"{payload['marker']} {payload['path']}")
            print(
                "authority: tracked human-decision metadata only; no source, proof, approval, repair, merge, publication, deployment, signing, messaging, credential, connector, or model action ran"
            )
        return (
            1
            if a.judgment_cmd == "safety-case" and payload["route"] in {"BLACK", "RED"}
            else 0
        )

    raise ValueError(f"unsupported governance command: {a.cmd}")

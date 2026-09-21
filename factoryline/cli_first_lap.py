"""CLI boundary for the human-observed First Lap activation gate."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register the First Lap activation and observation subcommands."""
    first_lap = sub.add_parser(
        "first-lap", help="prepare and verify the human-observed first activation lap"
    )
    first_lap_sub = first_lap.add_subparsers(required=True, dest="first_lap_cmd")
    first_lap_init = first_lap_sub.add_parser(
        "init", help="write MISSION.md, END-TO-END.md, verifier-only HOLDOUT.md, and an immutable receipt"
    )
    first_lap_init.add_argument("--root", default=".")
    first_lap_init.add_argument("--mission", default="Deliver the requested outcome without violating the forbidden outcomes.")
    first_lap_init.add_argument("--journey", action="append", dest="journeys")
    first_lap_init.add_argument("--holdout", action="append", dest="holdouts")
    first_lap_init.add_argument("--force", action="store_true", help="replace only the generated files and receipt")
    first_lap_init.add_argument("--json", action="store_true")
    first_lap_status = first_lap_sub.add_parser("status", help="read and integrity-check the initialized First Lap files without executing them")
    first_lap_status.add_argument("--root", default=".")
    first_lap_status.add_argument("--json", action="store_true")
    first_lap_calibrate = first_lap_sub.add_parser("calibrate", help="verify approved, defective, and wrong-candidate calibration cases")
    first_lap_calibrate.add_argument("input", help="JSON object containing approved_candidate, defective_candidate, and wrong_candidate statuses")
    first_lap_calibrate.add_argument("--root", default=".")
    first_lap_calibrate.add_argument("--strict", action="store_true", help="require candidate and contract identity bindings")
    first_lap_calibrate.add_argument("--json", action="store_true")
    first_lap_incident = first_lap_sub.add_parser("incident", help="append a complete incident-to-invariant chain")
    first_lap_incident.add_argument("input", help="incident JSON object")
    first_lap_incident.add_argument("--root", default=".")
    first_lap_incident.add_argument("--promote", action="store_true", help="also compile the incident into a permanent regression gate")
    first_lap_incident.add_argument("--json", action="store_true")
    first_lap_promote = first_lap_sub.add_parser("promote", help="compile an incident JSON object into a permanent regression gate")
    first_lap_promote.add_argument("input", help="incident JSON object")
    first_lap_promote.add_argument("--root", default=".")
    first_lap_promote.add_argument("--json", action="store_true")
    first_lap_holdout = first_lap_sub.add_parser("holdout", help="verify verifier-only holdout binding and contamination state")
    first_lap_holdout.add_argument("input", help="holdout boundary JSON object")
    first_lap_holdout.add_argument("--root", default=".")
    first_lap_holdout.add_argument("--json", action="store_true")
    first_lap_holdout.add_argument("--strict", action="store_true", help="require an externally isolated holdout")
    first_lap_observe = first_lap_sub.add_parser("observe", help="verify the exact human-observed first-lap phase sequence")
    first_lap_observe.add_argument("input", help="JSON array of phase/evidence_sha256 events")
    first_lap_observe.add_argument("--strict", action="store_true", help="require named human observer and run metadata")
    first_lap_observe.add_argument("--json", action="store_true")
    first_lap_failure = first_lap_sub.add_parser("failure", help="classify a failure and derive its retry policy")
    first_lap_failure.add_argument("kind", choices=["definitive_product_failure", "transient_provider_failure", "unverifiable_candidate_identity", "stale_evidence", "environment_setup_failure"])
    first_lap_failure.add_argument("--provider")
    first_lap_failure.add_argument("--retry-after", type=int)
    first_lap_failure.add_argument("--strict", action="store_true", help="require provider evidence for retryable failures")
    first_lap_failure.add_argument("--json", action="store_true")
    first_lap_verify = first_lap_sub.add_parser("verify", help="compose calibration, holdout, and observed-lap receipts into one activation gate")
    first_lap_verify.add_argument("--calibration", required=True)
    first_lap_verify.add_argument("--holdout", required=True)
    first_lap_verify.add_argument("--observed", required=True)
    first_lap_verify.add_argument("--root", default=".")
    first_lap_verify.add_argument("--strict", action="store_true", help="require all identity, isolation, observation, and incident gates")
    first_lap_verify.add_argument("--persist", action="store_true", help="write immutable activation receipt")
    first_lap_verify.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute a First Lap command after parser selection."""
    from .first_lap import (
        FirstLapError,
        classify_failure,
        first_lap_status,
        initialize_first_lap,
        promote_incident,
        record_incident,
        verify_activation,
        verify_holdout_boundary,
        verify_observed_first_lap,
        verify_verifier_calibration,
    )

    workspace = Path(args.root).resolve() if hasattr(args, "root") else Path(".").resolve()
    try:
        if args.first_lap_cmd == "init":
            result = initialize_first_lap(workspace, mission=args.mission, journeys=args.journeys, holdouts=args.holdouts, overwrite=args.force)
            code = 0
        elif args.first_lap_cmd == "status":
            result = first_lap_status(workspace)
            code = 0 if result.get("state") in {"INITIALIZED", "NOT_INITIALIZED"} else 1
        elif args.first_lap_cmd == "calibrate":
            result = verify_verifier_calibration(workspace, json.loads(Path(args.input).read_text(encoding="utf-8")), strict=args.strict)
            code = 0 if result.get("state") == "CALIBRATED" else 1
        elif args.first_lap_cmd == "incident":
            payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
            result = record_incident(workspace, payload)
            if args.promote:
                result = {"recorded": result, "promoted": promote_incident(workspace, payload)}
            code = 0
        elif args.first_lap_cmd == "promote":
            result = promote_incident(workspace, json.loads(Path(args.input).read_text(encoding="utf-8")))
            code = 0
        elif args.first_lap_cmd == "holdout":
            result = verify_holdout_boundary(workspace, json.loads(Path(args.input).read_text(encoding="utf-8")), strict=args.strict)
            code = 0 if result.get("state") == "VERIFIED" else 1
        elif args.first_lap_cmd == "observe":
            result = verify_observed_first_lap(json.loads(Path(args.input).read_text(encoding="utf-8")), strict=args.strict)
            code = 0 if result.get("state") == "OBSERVED" else 1
        elif args.first_lap_cmd == "failure":
            result = classify_failure(args.kind, provider=args.provider, retry_after_seconds=args.retry_after, strict=args.strict)
            code = 0
        else:
            result = verify_activation(
                workspace,
                calibration=json.loads(Path(args.calibration).read_text(encoding="utf-8")),
                holdout=json.loads(Path(args.holdout).read_text(encoding="utf-8")),
                observed=json.loads(Path(args.observed).read_text(encoding="utf-8")),
                strict=args.strict,
                persist=args.persist,
            )
            code = 0 if result.get("state") == "READY" else 1
    except (FirstLapError, OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        result = {"schema": "factory.first-lap.error.v1", "marker": "FIRST_LAP_BLOCKED", "code": getattr(exc, "code", "E_FIRST_LAP_INPUT"), "message": str(exc), "authority": "none"}
        code = 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        print(f"first lap: {result.get('marker', result.get('state', 'READY'))}")
        if result.get("paths"):
            for name, path in result["paths"].items():
                print(f"  {name}: {path}")
        if result.get("retry_allowed") is not None:
            print(f"retry allowed: {result['retry_allowed']}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
    return code

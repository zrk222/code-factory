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
        "init",
        help="write MISSION.md, END-TO-END.md, verifier-only HOLDOUT.md, and an immutable receipt",
    )
    first_lap_init.add_argument("--root", default=".")
    first_lap_init.add_argument(
        "--mission",
        default="Deliver the requested outcome without violating the forbidden outcomes.",
    )
    first_lap_init.add_argument("--journey", action="append", dest="journeys")
    first_lap_init.add_argument("--holdout", action="append", dest="holdouts")
    first_lap_init.add_argument(
        "--force",
        action="store_true",
        help="replace only the generated files and receipt",
    )
    first_lap_init.add_argument("--json", action="store_true")
    first_lap_status = first_lap_sub.add_parser(
        "status",
        help="read and integrity-check the initialized First Lap files without executing them",
    )
    first_lap_status.add_argument("--root", default=".")
    first_lap_status.add_argument("--json", action="store_true")
    first_lap_calibrate = first_lap_sub.add_parser(
        "calibrate",
        help="verify approved, defective, and wrong-candidate calibration cases",
    )
    first_lap_calibrate.add_argument(
        "input",
        help="JSON object containing approved_candidate, defective_candidate, and wrong_candidate statuses",
    )
    first_lap_calibrate.add_argument("--root", default=".")
    first_lap_calibrate.add_argument(
        "--strict",
        action="store_true",
        help="require candidate and contract identity bindings",
    )
    first_lap_calibrate.add_argument("--json", action="store_true")
    first_lap_incident = first_lap_sub.add_parser(
        "incident", help="append a complete incident-to-invariant chain"
    )
    first_lap_incident.add_argument("input", help="incident JSON object")
    first_lap_incident.add_argument("--root", default=".")
    first_lap_incident.add_argument(
        "--promote",
        action="store_true",
        help="also compile the incident into a permanent regression gate",
    )
    first_lap_incident.add_argument("--json", action="store_true")
    first_lap_promote = first_lap_sub.add_parser(
        "promote",
        help="compile an incident JSON object into a permanent regression gate",
    )
    first_lap_promote.add_argument("input", help="incident JSON object")
    first_lap_promote.add_argument("--root", default=".")
    first_lap_promote.add_argument("--json", action="store_true")
    first_lap_holdout = first_lap_sub.add_parser(
        "holdout", help="verify verifier-only holdout binding and contamination state"
    )
    first_lap_holdout.add_argument("input", help="holdout boundary JSON object")
    first_lap_holdout.add_argument("--root", default=".")
    first_lap_holdout.add_argument("--json", action="store_true")
    first_lap_holdout.add_argument(
        "--strict", action="store_true", help="require an externally isolated holdout"
    )
    first_lap_observe = first_lap_sub.add_parser(
        "observe", help="verify the exact human-observed first-lap phase sequence"
    )
    first_lap_observe.add_argument(
        "input", help="JSON array of phase/evidence_sha256 events"
    )
    first_lap_observe.add_argument(
        "--strict",
        action="store_true",
        help="require named human observer and run metadata",
    )
    first_lap_observe.add_argument("--json", action="store_true")
    first_lap_failure = first_lap_sub.add_parser(
        "failure", help="classify a failure and derive its retry policy"
    )
    first_lap_failure.add_argument(
        "kind",
        choices=[
            "definitive_product_failure",
            "transient_provider_failure",
            "unverifiable_candidate_identity",
            "stale_evidence",
            "environment_setup_failure",
        ],
    )
    first_lap_failure.add_argument("--provider")
    first_lap_failure.add_argument("--retry-after", type=int)
    first_lap_failure.add_argument(
        "--strict",
        action="store_true",
        help="require provider evidence for retryable failures",
    )
    first_lap_failure.add_argument("--json", action="store_true")
    first_lap_verify = first_lap_sub.add_parser(
        "verify",
        help="compose calibration, holdout, and observed-lap receipts into one activation gate",
    )
    first_lap_verify.add_argument("--calibration", required=True)
    first_lap_verify.add_argument("--holdout", required=True)
    first_lap_verify.add_argument("--observed", required=True)
    first_lap_verify.add_argument("--root", default=".")
    first_lap_verify.add_argument(
        "--strict",
        action="store_true",
        help="require all identity, isolation, observation, and incident gates",
    )
    first_lap_verify.add_argument(
        "--persist", action="store_true", help="write immutable activation receipt"
    )
    first_lap_verify.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute a First Lap command after parser selection."""
    from . import first_lap

    workspace = (
        Path(args.root).resolve() if hasattr(args, "root") else Path(".").resolve()
    )
    try:
        result, code = _execute_first_lap_command(args, workspace, first_lap)
    except (
        first_lap.FirstLapError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        result = _first_lap_error(exc)
        code = 2
    _render_first_lap_result(args, result, code)
    return code


def _read_input(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _first_lap_init(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.initialize_first_lap(
        workspace,
        mission=args.mission,
        journeys=args.journeys,
        holdouts=args.holdouts,
        overwrite=args.force,
    )
    return result, 0


def _first_lap_status(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.first_lap_status(workspace)
    code = 0 if result.get("state") in {"INITIALIZED", "NOT_INITIALIZED"} else 1
    return result, code


def _first_lap_calibrate(
    args: Any, workspace: Path, first_lap: Any
) -> tuple[dict, int]:
    result = first_lap.verify_verifier_calibration(
        workspace, _read_input(args.input), strict=args.strict
    )
    code = 0 if result.get("state") == "CALIBRATED" else 1
    return result, code


def _first_lap_incident(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    payload = _read_input(args.input)
    result = first_lap.record_incident(workspace, payload)
    if args.promote:
        result = {
            "recorded": result,
            "promoted": first_lap.promote_incident(workspace, payload),
        }
    return result, 0


def _first_lap_promote(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    return first_lap.promote_incident(workspace, _read_input(args.input)), 0


def _first_lap_holdout(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.verify_holdout_boundary(
        workspace, _read_input(args.input), strict=args.strict
    )
    code = 0 if result.get("state") == "VERIFIED" else 1
    return result, code


def _first_lap_observe(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.verify_observed_first_lap(
        _read_input(args.input), strict=args.strict
    )
    code = 0 if result.get("state") == "OBSERVED" else 1
    return result, code


def _first_lap_failure(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    return (
        first_lap.classify_failure(
            args.kind,
            provider=args.provider,
            retry_after_seconds=args.retry_after,
            strict=args.strict,
        ),
        0,
    )


def _first_lap_verify(args: Any, workspace: Path, first_lap: Any) -> tuple[dict, int]:
    result = first_lap.verify_activation(
        workspace,
        calibration=_read_input(args.calibration),
        holdout=_read_input(args.holdout),
        observed=_read_input(args.observed),
        strict=args.strict,
        persist=args.persist,
    )
    code = 0 if result.get("state") == "READY" else 1
    return result, code


def _execute_first_lap_command(
    args: Any, workspace: Path, first_lap: Any
) -> tuple[dict, int]:
    handlers = {
        "init": _first_lap_init,
        "status": _first_lap_status,
        "calibrate": _first_lap_calibrate,
        "incident": _first_lap_incident,
        "promote": _first_lap_promote,
        "holdout": _first_lap_holdout,
        "observe": _first_lap_observe,
        "failure": _first_lap_failure,
    }
    handler = handlers.get(args.first_lap_cmd, _first_lap_verify)
    return handler(args, workspace, first_lap)


def _first_lap_error(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "factory.first-lap.error.v1",
        "marker": "FIRST_LAP_BLOCKED",
        "code": getattr(exc, "code", "E_FIRST_LAP_INPUT"),
        "message": str(exc),
        "authority": "none",
    }


def _render_first_lap_success(result: dict[str, Any]) -> None:
    print(f"first lap: {result.get('marker', result.get('state', 'READY'))}")
    if result.get("paths"):
        for name, path in result["paths"].items():
            print(f"  {name}: {path}")
    if result.get("retry_allowed") is not None:
        print(f"retry allowed: {result['retry_allowed']}")


def _render_first_lap_result(args: Any, result: dict[str, Any], code: int) -> None:
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif code == 0:
        _render_first_lap_success(result)
    else:
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)

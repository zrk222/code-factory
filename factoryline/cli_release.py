"""Bounded, lazily loaded release-control CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

COMMAND_GROUP = "release"
OWNER = "release-controls-maintainers"


def add_parser(sub: Any) -> None:
    """Register release inspection commands without loading release engines."""
    release = sub.add_parser(
        "release", help="inspect local release workflow boundaries without publishing"
    )
    release_sub = release.add_subparsers(required=True, dest="release_cmd")
    integrity = release_sub.add_parser(
        "integrity", help="verify release workflow fan-in and protected-gate topology"
    )
    integrity.add_argument("--root", default=".")
    integrity.add_argument("--json", action="store_true")
    preflight = release_sub.add_parser(
        "preflight", help="verify one exact release contract and candidate artifact set"
    )
    preflight.add_argument("--root", default=".")
    preflight.add_argument(
        "--candidate-tag",
        help="draft release tag at HEAD to exclude from prior-release cadence",
    )
    preflight.add_argument(
        "--contract",
        required=True,
        help="workspace-contained release contract with candidate source binding",
    )
    preflight.add_argument(
        "--artifact-dir",
        action="append",
        help="workspace-contained artifact directory; repeatable",
    )
    preflight.add_argument(
        "--metadata-path",
        action="append",
        help="workspace-contained active metadata file; repeatable and audited when supplied",
    )
    preflight.add_argument(
        "--supply-chain-manifest",
        help="optional workspace-contained signed-evidence manifest; blocks when supplied evidence is invalid",
    )
    preflight.add_argument(
        "--intake-parameters",
        help="optional workspace-contained authoritative intake-parameter envelope",
    )
    preflight.add_argument(
        "--require-intake",
        action="store_true",
        help="require an authoritative intake-parameter envelope for this release",
    )
    preflight.add_argument(
        "--out", help="optional workspace-contained JSON receipt path"
    )
    preflight.add_argument("--json", action="store_true")
    decision = release_sub.add_parser(
        "decision",
        help="explain one strict local release decision without contacting a provider",
    )
    decision.add_argument("feature")
    decision.add_argument("--root", default=".")
    decision.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Execute one release inspection command without publishing."""
    if args.release_cmd == "integrity":
        return _run_integrity(args)
    if args.release_cmd == "preflight":
        return _run_preflight(args)
    return _run_decision(args)


def _run_integrity(args: Any) -> int:
    from .release_integrity import release_integrity, render_release_integrity

    result = release_integrity(Path(args.root))
    print(
        json.dumps(result, indent=2, sort_keys=True)
        if args.json
        else render_release_integrity(result)
    )
    return 0 if result["ok"] else 1


def _preflight_payload(args: Any, root: Path, candidate: Any) -> dict[str, Any]:
    artifact_dirs = (
        [Path(item) for item in args.artifact_dir] if args.artifact_dir else None
    )
    metadata_paths = (
        [Path(item) for item in args.metadata_path] if args.metadata_path else None
    )
    supply_chain_manifest = (
        Path(args.supply_chain_manifest) if args.supply_chain_manifest else None
    )
    intake_parameters = Path(args.intake_parameters) if args.intake_parameters else None
    preflight = (
        candidate.write_release_candidate_preflight
        if args.out
        else candidate.release_candidate_preflight
    )
    call_args = (root, Path(args.contract), artifact_dirs)
    options = {
        "metadata_paths": metadata_paths,
        "supply_chain_manifest": supply_chain_manifest,
        "intake_parameters": intake_parameters,
        "require_intake": args.require_intake,
        "candidate_tag": args.candidate_tag,
    }
    if args.out:
        return preflight(*call_args, Path(args.out), **options)
    return preflight(*call_args, **options)


def _preflight_blocked(exc: Exception) -> dict[str, Any]:
    return {
        "schema": "factory.release-candidate-preflight.v1",
        "marker": "RELEASE_CANDIDATE_PREFLIGHT_BLOCKED",
        "ok": False,
        "blockers": [
            {
                "code": "RELEASE_CANDIDATE_INPUT_INVALID",
                "detail": str(exc)[:240],
            }
        ],
        "authority": {
            key: False
            for key in (
                "execution",
                "approval",
                "repair",
                "merge",
                "publication",
                "deployment",
                "signing",
                "credential",
                "provider_call",
            )
        },
    }


def _render_preflight(args: Any, result: dict[str, Any]) -> None:
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(f"release candidate preflight: {'PASS' if result.get('ok') else 'BLOCKED'}")
    for check in result.get("checks", []):
        print(
            f"- {'PASS' if check.get('passed') else 'FAIL'} {check.get('id')}: {check.get('evidence')}"
        )
    for blocker in result.get("blockers", []):
        print(f"- BLOCK {blocker.get('code')}: {blocker.get('detail')}")
    print(
        "authority: no execution, credential, provider, publication, deployment, signing, merge, or approval authority"
    )


def _run_preflight(args: Any) -> int:
    from . import release_candidate

    root = Path(args.root).resolve()
    try:
        result = _preflight_payload(args, root, release_candidate)
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        result = _preflight_blocked(exc)
    _render_preflight(args, result)
    return 0 if result.get("ok") else 1


def _decision_rejected(exc: ValueError, schema: str) -> dict[str, Any]:
    return {
        "schema": schema,
        "marker": "RELEASE_DECISION_INPUT_REJECTED",
        "state": "INPUT_REJECTED",
        "reason": str(exc),
        "authority": {
            key: False
            for key in (
                "execution",
                "approval",
                "repair",
                "merge",
                "publication",
                "deployment",
                "signing",
                "messaging",
                "credential",
                "connector",
            )
        },
        "claim_boundary": "Input validation only; no local workflow, feature evidence, provider, credential, or release action ran.",
    }


def _render_decision(args: Any, result: dict[str, Any], renderer: Any) -> None:
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result.get("state") == "INPUT_REJECTED":
        print(f"release decision: INPUT_REJECTED ({result['reason']})")
    else:
        print(renderer(result))


def _run_decision(args: Any) -> int:
    from . import release_decision

    try:
        result = release_decision.release_decision_card(Path(args.root), args.feature)
    except ValueError as exc:
        result = _decision_rejected(exc, release_decision.SCHEMA)
    _render_decision(args, result, release_decision.render_release_decision_card)
    return 0 if result.get("state") == "EXTERNAL_GATES_UNOBSERVED" else 1

"""Lazy CLI boundary for the AI-native blueprint contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def add_parser(sub: Any) -> None:
    """Register the lazy blueprint command group on the factory CLI."""
    blueprint = sub.add_parser(
        "blueprint",
        help="validate local AI-native SDLC memory, trust, access, signal, and team contracts",
    )
    commands = blueprint.add_subparsers(required=True, dest="blueprint_cmd")
    status = commands.add_parser(
        "status", help="read local blueprint receipt inventory"
    )
    status.add_argument("--root", default=".")
    status.add_argument("--json", action="store_true")
    retain = commands.add_parser("retain", help="seal one Bronze memory observation")
    retain.add_argument("payload")
    retain.add_argument("--out", required=True)
    retain.add_argument("--json", action="store_true")
    recall = commands.add_parser("recall", help="recall observations from a JSON list")
    recall.add_argument("observations")
    recall.add_argument("--project")
    recall.add_argument("--query")
    recall.add_argument("--tag", action="append", default=[])
    recall.add_argument("--limit", type=int, default=50)
    recall.add_argument("--json", action="store_true")
    reflect = commands.add_parser(
        "reflect", help="aggregate recalled memory without an LLM"
    )
    reflect.add_argument("observations")
    reflect.add_argument("--json", action="store_true")
    librarian = commands.add_parser(
        "librarian", help="promote one observation through human review"
    )
    librarian.add_argument("observation")
    librarian.add_argument("--reviewer", required=True)
    librarian.add_argument(
        "--stage", required=True, choices=["silver", "gold", "contested"]
    )
    librarian.add_argument("--source-digest", required=True)
    librarian.add_argument("--feedback", default="")
    librarian.add_argument("--out", required=True)
    librarian.add_argument("--json", action="store_true")
    signal = commands.add_parser(
        "signal-intent",
        help="create a human-reviewable intent proposal from a normalized signal",
    )
    signal.add_argument("signal")
    signal.add_argument("--owner", required=True)
    signal.add_argument("--out", required=True)
    signal.add_argument("--json", action="store_true")
    access = commands.add_parser(
        "access", help="seal a declaration-only runtime access profile"
    )
    access.add_argument("payload")
    access.add_argument("--out", required=True)
    access.add_argument("--json", action="store_true")
    team = commands.add_parser(
        "team-plan", help="compile a typed, non-dispatching team plan"
    )
    team.add_argument("payload")
    team.add_argument("--out", required=True)
    team.add_argument("--json", action="store_true")
    chain = commands.add_parser(
        "artifact-chain", help="bind Intent, Spec, and Plan documents"
    )
    chain_sub = chain.add_subparsers(required=True, dest="artifact_cmd")
    build = chain_sub.add_parser("build", help="seal an Intent-to-Plan lineage receipt")
    build.add_argument("--intent", required=True)
    build.add_argument("--spec", required=True)
    build.add_argument("--plan", required=True)
    build.add_argument("--author", required=True)
    build.add_argument("--project", required=True)
    build.add_argument(
        "--intent-status", choices=["draft", "approved", "processed"], default="draft"
    )
    build.add_argument("--files-changed", nargs="+", required=True)
    build.add_argument("--work-order", nargs="+", required=True)
    build.add_argument("--risks", nargs="*", default=[])
    build.add_argument("--proof-of-completion", nargs="+", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--json", action="store_true")
    verify = chain_sub.add_parser(
        "verify", help="verify an Intent-to-Plan lineage receipt"
    )
    verify.add_argument("receipt")
    verify.add_argument("--json", action="store_true")


def _read(path: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("payload must be a JSON object")
    return value


def _write(path: str, value: dict[str, Any]) -> dict[str, Any]:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "path": str(destination),
        "sha256": value.get("memory_sha256")
        or value.get("librarian_sha256")
        or value.get("intent_sha256")
        or value.get("access_sha256")
        or value.get("plan_sha256")
        or value.get("chain_sha256"),
    }


def _read_observation_list(path: str) -> list[Any]:
    observations = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(observations, list):
        raise ValueError("observations must be a JSON list")
    return observations


def _run_memory_command(args: Any, engines: dict[str, Any]) -> tuple[bool, Any]:
    """Run status, observation, and librarian memory commands."""
    if args.blueprint_cmd == "status":
        return True, engines["blueprint_projection"](Path(args.root))
    if args.blueprint_cmd == "retain":
        result = engines["retain_observation"](**_read(args.payload))
        result["artifact"] = _write(args.out, result)
        return True, result
    if args.blueprint_cmd == "recall":
        result = engines["recall_observations"](
            _read_observation_list(args.observations),
            project=args.project,
            query=args.query,
            tags=args.tag,
            limit=args.limit,
        )
        return True, result
    if args.blueprint_cmd == "reflect":
        result = engines["reflect_observations"](
            _read_observation_list(args.observations)
        )
        return True, result
    if args.blueprint_cmd == "librarian":
        result = engines["librarian_promotion"](
            _read(args.observation),
            reviewer=args.reviewer,
            stage=args.stage,
            source_digest=args.source_digest,
            feedback=args.feedback,
        )
        result["artifact"] = _write(args.out, result)
        return True, result
    return False, None


def _run_artifact_chain(args: Any, engines: dict[str, Any]) -> dict[str, Any]:
    if args.artifact_cmd == "build":
        result = engines["build_artifact_chain"](
            intent=Path(args.intent).read_text(encoding="utf-8"),
            spec=Path(args.spec).read_text(encoding="utf-8"),
            plan=Path(args.plan).read_text(encoding="utf-8"),
            author=args.author,
            project=args.project,
            intent_status=args.intent_status,
            files_changed=args.files_changed,
            work_order=args.work_order,
            risks=args.risks,
            proof_of_completion=args.proof_of_completion,
        )
        result["artifact"] = _write(args.out, result)
        return result
    return engines["verify_artifact_chain"](_read(args.receipt))


def _run_contract_command(args: Any, engines: dict[str, Any]) -> Any:
    """Run intent, access, artifact-chain, and team-plan commands."""
    if args.blueprint_cmd == "signal-intent":
        result = engines["signal_intent_proposal"](_read(args.signal), owner=args.owner)
        result["artifact"] = _write(args.out, result)
        return result
    if args.blueprint_cmd == "access":
        result = engines["access_profile"](**_read(args.payload))
        result["artifact"] = _write(args.out, result)
        return result
    if args.blueprint_cmd == "artifact-chain":
        return _run_artifact_chain(args, engines)
    result = engines["team_plan"](**_read(args.payload))
    result["artifact"] = _write(args.out, result)
    return result


def _dispatch_blueprint_command(args: Any, engines: dict[str, Any]) -> Any:
    matched, result = _run_memory_command(args, engines)
    if matched:
        return result
    return _run_contract_command(args, engines)


def run(args: Any) -> int:
    """Execute a blueprint subcommand and emit deterministic JSON errors."""
    from .blueprint import (
        BlueprintError,
        access_profile,
        build_artifact_chain,
        blueprint_projection,
        librarian_promotion,
        recall_observations,
        reflect_observations,
        retain_observation,
        signal_intent_proposal,
        team_plan,
        verify_artifact_chain,
    )

    engines = {
        "access_profile": access_profile,
        "build_artifact_chain": build_artifact_chain,
        "blueprint_projection": blueprint_projection,
        "librarian_promotion": librarian_promotion,
        "recall_observations": recall_observations,
        "reflect_observations": reflect_observations,
        "retain_observation": retain_observation,
        "signal_intent_proposal": signal_intent_proposal,
        "team_plan": team_plan,
        "verify_artifact_chain": verify_artifact_chain,
    }
    try:
        result = _dispatch_blueprint_command(args, engines)
    except (
        BlueprintError,
        OSError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": "factory.blueprint.error.v1",
                    "marker": "BLUEPRINT_REFUSED",
                    "code": getattr(exc, "code", "E_INPUT"),
                    "message": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(result, indent=2, sort_keys=True)
        if args.json
        else result.get("marker", "BLUEPRINT_OK")
    )
    return 0

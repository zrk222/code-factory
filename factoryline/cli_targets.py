"""Lazy CLI boundary for target compilation and contained MVP starters."""

from __future__ import annotations

import json
from pathlib import Path

from .failure_guidance import explain_failure


TARGET_KINDS = ("agent-ui", "api", "cli", "mcp", "mobile", "web", "worker")
SUPPORTED_TRIGGERS = ("manual", "cron", "hook", "goal", "heartbeat")


def add_parser(sub) -> None:
    """Register target inventory, compilation, and MVP commands."""
    targets = sub.add_parser(
        "targets", help="list target kinds supported by the deterministic compiler"
    )
    targets.add_argument(
        "--json", action="store_true", help="emit the target inventory as JSON"
    )
    target = sub.add_parser(
        "create", help="compile one prompt or PRD into one governed starter target"
    )
    target.add_argument(
        "prompt", nargs="?", help="plain-language intent; mutually exclusive with --prd"
    )
    target.add_argument("--prd", help="UTF-8 PRD path; mutually exclusive with prompt")
    target.add_argument("--target", required=True, choices=TARGET_KINDS)
    target.add_argument("--out", required=True, help="empty output directory")
    target.add_argument("--name", help="target slug override")
    target.add_argument(
        "--purpose",
        default="auto",
        help="auto, developer, healthcare, fintech, marketplace, saas",
    )
    target.add_argument("--trigger", default="manual", choices=SUPPORTED_TRIGGERS)
    target.add_argument(
        "--deployment-profile",
        help="deployment route id shown by `factory targets --json`; defaults to the local or preview route",
    )
    target.add_argument("--json", action="store_true")
    mvp = sub.add_parser(
        "mvp", help="turn one outcome into a contained local web MVP starter"
    )
    mvp.add_argument("outcome", help="plain-language outcome for the first MVP")
    mvp.add_argument(
        "--root", default=".", help="workspace that receives the new my-mvp directory"
    )
    mvp.add_argument(
        "--name", help="optional product name; the output directory remains my-mvp"
    )
    mvp.add_argument(
        "--purpose",
        default="auto",
        help="auto, developer, healthcare, fintech, marketplace, saas",
    )
    mvp.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch target commands without executing deployment or publication."""
    if a.cmd == "targets":
        from .target_compiler import TARGETS

        payload = {"schema": "factory.targets.v1", "targets": TARGETS}
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            for target_kind, metadata in TARGETS.items():
                print(f"{target_kind}: {metadata['label']}")
                print(f"  {metadata['summary']}")
                for profile in metadata["deployment_profiles"]:
                    print(
                        f"  - {profile['id']}: {profile['label']} [approval: {profile['approval']}]"
                    )
        return 0
    if a.cmd == "create":
        return _run_create(a)
    return _run_mvp(a)


def _run_create(a) -> int:
    from .target_compiler import (
        TargetCompileError,
        create_target_from_prd,
        create_target_from_prompt,
    )

    if bool(a.prompt) == bool(a.prd):
        payload = {
            "schema": "factory.target_compile_error.v1",
            "status": "failed",
            "code": "SOURCE_EXACTLY_ONE",
            "marker": "COMPILE_FAILED",
            "message": "provide exactly one source: prompt or --prd",
            "failure": explain_failure(
                "SOURCE_EXACTLY_ONE", "provide exactly one source: prompt or --prd"
            ),
        }
        print(json.dumps(payload, indent=2), file=__import__("sys").stderr)
        return 2
    try:
        if a.prd:
            result = create_target_from_prd(
                Path(a.prd),
                target=a.target,
                out_dir=Path(a.out),
                name=a.name,
                purpose=a.purpose,
                trigger=a.trigger,
                deployment_profile=a.deployment_profile,
            )
        else:
            result = create_target_from_prompt(
                a.prompt,
                target=a.target,
                out_dir=Path(a.out),
                name=a.name,
                purpose=a.purpose,
                trigger=a.trigger,
                deployment_profile=a.deployment_profile,
            )
    except (TargetCompileError, UnicodeDecodeError) as exc:
        code = (
            exc.code if isinstance(exc, TargetCompileError) else "PRD_ENCODING_INVALID"
        )
        message = (
            exc.message
            if isinstance(exc, TargetCompileError)
            else "PRD must be valid UTF-8"
        )
        payload = {
            "schema": "factory.target_compile_error.v1",
            "status": "failed",
            "code": code,
            "marker": "COMPILE_FAILED",
            "message": message,
            "failure": exc.guidance
            if isinstance(exc, TargetCompileError)
            else explain_failure(code, message),
        }
        print(json.dumps(payload, indent=2), file=__import__("sys").stderr)
        return 1
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"target compiled: {result['out_dir']}")
        print(f"kind           : {result['target_kind']}")
        print(f"state          : {result['status']}")
        print(
            f"deploy route   : {result['deployment']['profile']['label']} ({result['deployment']['selected_profile_id']})"
        )
        print(f"deploy approval: {result['deployment']['profile']['approval']}")
        print(f"receipt        : {result['receipt']}")
    return 0


def _run_mvp(a) -> int:
    from .target_compiler import TargetCompileError, create_target_from_prompt

    root = Path(a.root).resolve()
    try:
        result = create_target_from_prompt(
            a.outcome,
            target="web",
            out_dir=root / "my-mvp",
            name=a.name,
            purpose=a.purpose,
            trigger="manual",
        )
    except TargetCompileError as exc:
        payload = {
            "schema": "factory.mvp.error.v1",
            "status": "failed",
            "code": exc.code,
            "marker": "MVP_STARTER_FAILED",
            "message": exc.message,
            "failure": exc.guidance,
        }
        print(
            json.dumps(payload, indent=2)
            if a.json
            else f"MVP starter failed: {exc.code}: {exc.message}",
            file=__import__("sys").stderr,
        )
        return 1
    payload = {
        "schema": "factory.mvp.v1",
        "marker": "MVP_STARTER_CONTAINED",
        "markers": sorted(
            set(
                result["markers"] + ["MVP_STARTER_CONTAINED", "MVP_PROOF_PATH_EXPLICIT"]
            )
        ),
        "status": result["status"],
        "out_dir": result["out_dir"],
        "target_kind": result["target_kind"],
        "name": result["name"],
        "output_map": result["output_map"],
        "output_map_sha256": result["output_map_sha256"],
        "next_proof_commands": result["next_commands"],
        "authority": {
            "execution": False,
            "approval": False,
            "publication": False,
            "deployment": False,
            "signing": False,
            "messaging": False,
            "credential": False,
            "connector": False,
        },
        "claims": result["claims"],
    }
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Your local MVP starter is ready.")
        print(f"path       : {payload['out_dir']}")
        print(f"output map : {payload['output_map']}")
        print("next proof :")
        for command in payload["next_proof_commands"]:
            print(f"  {command}")
        print(
            "boundary   : deployment, publication, credentials, connectors, and messages remain unavailable"
        )
    return 0

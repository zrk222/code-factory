"""Lazy CLI boundary for supervised repair and JetBrains proof handshakes."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register repair-sandbox and JetBrains handshake commands."""
    repair = sub.add_parser(
        "repair",
        help="prepare a sealed Change List scope and inspect a candidate patch without applying it",
    )
    repair_sub = repair.add_subparsers(required=True, dest="repair_cmd")
    repair_scope = repair_sub.add_parser(
        "scope",
        help="seal explicit Change List paths and optional local handoff artifacts",
    )
    repair_scope.add_argument("--root", default=".")
    repair_scope.add_argument(
        "--change-list",
        required=True,
        help="native Change List label supplied by the IDE",
    )
    repair_scope.add_argument(
        "--changed",
        action="append",
        required=True,
        help="explicit workspace-relative Change List path; repeat as needed",
    )
    repair_scope.add_argument(
        "--context-budget-bytes",
        type=int,
        default=262144,
        help="measured-byte threshold that recommends splitting an oversized agent context",
    )
    repair_scope.add_argument(
        "--out-dir",
        help="explicit workspace-contained directory for local scope artifacts",
    )
    repair_scope.add_argument("--json", action="store_true")
    repair_candidate = repair_sub.add_parser(
        "candidate",
        help="bind a textual Git patch to a current sealed scope without applying it",
    )
    repair_candidate.add_argument("--root", default=".")
    repair_candidate.add_argument(
        "--scope",
        required=True,
        help="workspace-contained factory.repair_scope.v1 JSON packet",
    )
    repair_candidate.add_argument(
        "--patch", required=True, help="workspace-contained textual Git candidate patch"
    )
    repair_candidate.add_argument(
        "--out-dir",
        help="explicit workspace-contained directory for local candidate artifacts",
    )
    repair_candidate.add_argument("--json", action="store_true")

    jetbrains = sub.add_parser(
        "jetbrains",
        help="join a sealed agent mission, Qodana or SonarQube SARIF, and non-hollow proof without provider execution",
    )
    jetbrains_sub = jetbrains.add_subparsers(required=True, dest="jetbrains_cmd")
    jetbrains_mission = jetbrains_sub.add_parser(
        "mission",
        help="render one Junie-compatible proof mission from a sealed repair scope",
    )
    jetbrains_mission.add_argument("--root", default=".")
    jetbrains_mission.add_argument("--scope", required=True)
    jetbrains_mission.add_argument("--changed", action="append", default=[])
    jetbrains_mission.add_argument("--json", action="store_true")
    jetbrains_handshake = jetbrains_sub.add_parser(
        "handshake",
        help="cross-check returned paths, analyzer SARIF, intent, and optional E2E proof",
    )
    jetbrains_handshake.add_argument("--root", default=".")
    jetbrains_handshake.add_argument("--scope", required=True)
    jetbrains_handshake.add_argument("--changed", action="append", required=True)
    analysis_input = jetbrains_handshake.add_mutually_exclusive_group(required=True)
    analysis_input.add_argument(
        "--analysis-sarif",
        help="workspace-local Qodana or SonarQube SARIF 2.1.0 report",
    )
    analysis_input.add_argument(
        "--qodana-sarif",
        help="compatibility alias for --analysis-sarif with provider qodana",
    )
    jetbrains_handshake.add_argument(
        "--analysis-provider", choices=["auto", "qodana", "sonarqube"], default="auto"
    )
    jetbrains_handshake.add_argument("--e2e-receipt")
    jetbrains_handshake.add_argument("--max-new-errors", type=int, default=0)
    jetbrains_handshake.add_argument("--max-new-warnings", type=int, default=0)
    jetbrains_handshake.add_argument(
        "--out", default=".factory/jetbrains-handshake/latest.json"
    )
    jetbrains_handshake.add_argument("--json", action="store_true")
    jetbrains_status = jetbrains_sub.add_parser(
        "status", help="read the latest hash-valid local JetBrains handshake receipt"
    )
    jetbrains_status.add_argument("--root", default=".")
    jetbrains_status.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch supervised repair or JetBrains proof work without applying changes."""
    if a.cmd == "repair":
        from .repair_sandbox import (
            RepairSandboxError,
            create_repair_scope,
            inspect_repair_candidate,
            write_repair_candidate_artifacts,
            write_repair_scope_artifacts,
        )

        try:
            if a.repair_cmd == "scope":
                result = create_repair_scope(
                    Path(a.root),
                    a.change_list,
                    a.changed,
                    context_budget_bytes=a.context_budget_bytes,
                )
                if a.out_dir:
                    result["artifacts"] = write_repair_scope_artifacts(
                        result, Path(a.root), Path(a.out_dir)
                    )
            else:
                result = inspect_repair_candidate(
                    Path(a.root), Path(a.scope), Path(a.patch)
                )
                if a.out_dir:
                    result["artifacts"] = write_repair_candidate_artifacts(
                        result, Path(a.root), Path(a.out_dir)
                    )
        except RepairSandboxError as exc:
            schema = (
                "factory.repair_scope.error.v1"
                if a.repair_cmd == "scope"
                else "factory.repair_candidate.error.v1"
            )
            marker = (
                "REPAIR_SANDBOX_PATH_REJECTED"
                if "PATH" in exc.code or exc.code == "REPAIR_CANDIDATE_OUT_OF_SCOPE"
                else "REPAIR_SANDBOX_INPUT_UNAVAILABLE"
            )
            payload = {
                "schema": schema,
                "marker": marker,
                "code": exc.code,
                "message": str(exc),
            }
            print(
                json.dumps(payload, indent=2, sort_keys=True)
                if a.json
                else f"repair {a.repair_cmd} failed: {exc.code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"factory repair {a.repair_cmd} (supervised, no patch apply)")
            print("=" * 54)
            if a.repair_cmd == "scope":
                print(f"scope       : {result['scope_id']}")
                print(f"changed path: {len(result['paths'])}")
                print(
                    f"context     : {result['context_budget']['measured_bytes']} / {result['context_budget']['limit_bytes']} bytes ({result['context_budget']['decision']})"
                )
                print(
                    "next        : external supervised candidate, independent verifier, human apply"
                )
            else:
                print(f"candidate   : {result['candidate_sha256']}")
                print(f"touched path: {len(result['touched_paths'])}")
                print(
                    "next        : independent verifier, then human diff review and apply"
                )
            if result.get("artifacts"):
                print(f"packet      : {result['artifacts']['paths']['markdown']}")
            print(
                "authority   : no source modification, test execution, commit, merge, publication, deployment, credential, or network action"
            )
        return 0

    from .jetbrains_handshake import (
        JetBrainsHandshakeError,
        build_agent_proof_mission,
        evaluate_jetbrains_handshake,
        jetbrains_handshake_projection,
        write_jetbrains_handshake,
    )

    root = Path(a.root).resolve()
    try:
        if a.jetbrains_cmd == "mission":
            payload = build_agent_proof_mission(root, Path(a.scope), a.changed or None)
        elif a.jetbrains_cmd == "status":
            payload = jetbrains_handshake_projection(root)
        else:
            analysis_path = a.qodana_sarif or a.analysis_sarif
            analysis_provider = "qodana" if a.qodana_sarif else a.analysis_provider
            payload = evaluate_jetbrains_handshake(
                root,
                Path(a.scope),
                a.changed,
                Path(analysis_path),
                Path(a.e2e_receipt) if a.e2e_receipt else None,
                analysis_provider=analysis_provider,
                max_new_errors=a.max_new_errors,
                max_new_warnings=a.max_new_warnings,
            )
            write_jetbrains_handshake(root, payload, Path(a.out))
    except (
        JetBrainsHandshakeError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        code = getattr(exc, "code", "JETBRAINS_HANDSHAKE_INPUT_INVALID")
        error = {
            "schema": "factory.jetbrains-proof-handshake.error.v1",
            "marker": "JETBRAINS_PROOF_HANDSHAKE_REFUSED",
            "code": code,
            "message": str(exc),
        }
        print(
            json.dumps(error, indent=2, sort_keys=True)
            if a.json
            else f"jetbrains {a.jetbrains_cmd} refused: {code}: {exc}",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else payload.get(
            "mission_text", payload.get("marker", "JETBRAINS_PROOF_HANDSHAKE_OK")
        )
    )
    return (
        1
        if a.jetbrains_cmd == "handshake"
        and payload["verdict"] != "ready_for_human_review"
        else 0
    )

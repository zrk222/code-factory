"""factoryline CLI — drive the code factory from any IDE / agent / OS.

factory doctor            # which Lego pieces are installed + how to get the rest
factory plan              # print the assembly pipeline (no execution)
factory assemble <feat>   # run the chain for a feature (skips missing modules)
factory mvp <outcome>     # compile a contained local web MVP starter
factory meter [--runs N --baseline T]   # real savings summary from your runs
factory trace <feat>      # write a hash-linked proof-carrying PR trace
factory graph ops         # inspect the unified local Graph Ops result
factory init <root>       # create the shared factory layout
"""

from __future__ import annotations
import argparse
import json
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any
from functools import lru_cache
from importlib import import_module


@lru_cache(maxsize=256)
def _lazy_import(module: str, symbol: str):
    """Load command implementation symbols only when their command runs."""
    relative = f".{module}" if module else "."
    return getattr(import_module(relative, __package__), symbol)


def _cli_command(name: str) -> str:
    from .cli_foundations import cli_command

    return cli_command(name)


def _emit_version(as_json: bool) -> int:
    from .cli_foundations import emit_version

    return emit_version(as_json)


def _canary_version(module) -> tuple[dict | None, dict | None]:
    if not module.installed:
        return None, {"ok": False, "reason": "cli not installed"}
    try:
        version = subprocess.run(
            [_cli_command(module.cli), "--version", "--json"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, {"ok": False, "reason": type(error).__name__}
    if version.returncode != 0:
        return None, {"ok": False, "reason": "version command failed"}
    try:
        payload = json.loads(version.stdout)
    except json.JSONDecodeError:
        return None, {"ok": False, "reason": "version command was not JSON"}
    return payload, None


def _canary_provenance(payload: dict) -> tuple[bool | None, dict | None]:
    required = {
        "package",
        "version",
        "build_hash",
        "install_origin",
        "runtime",
        "receipt_schema",
    }
    missing = sorted(name for name in required if not payload.get(name))
    if missing:
        return None, {
            "ok": False,
            "provenance_ok": False,
            "reason": f"incomplete provenance: {', '.join(missing)}",
            "provenance": payload,
        }
    complete = bool(payload.get("identity_complete") and payload.get("source_commit"))
    return complete, None


def _run_feature_canary(
    module, root: Path, payload: dict, provenance_ok: bool, suffix: str
) -> dict | None:
    source, args = (
        (
            "/** Recall a verified value. */\nexport function recall(id) { return id; }\n",
            "[id]",
        )
        if suffix == "mjs"
        else (
            "/** Recall a verified value. */\nexport function recall(id: string): string { return id; }\n",
            '["id: string"]',
        )
    )
    target = root / "services" / f"canary.{suffix}"
    target.write_text(source, encoding="utf-8")
    (root / "services" / f"canary.test.{suffix}").write_text(
        f"import {{ recall }} from './canary.{suffix}';\nrecall('ok');\n",
        encoding="utf-8",
    )
    ssat = root / f"canary-{suffix}.ssat.yaml"
    ssat.write_text(
        f"name: canary-{suffix}\nmodules:\n  - name: canary\n    path: services/canary.{suffix}\n    functions:\n      - name: recall\n        args: {args}\n        returns: string\ndependencies: []\ninvariants: []\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            _cli_command(module.cli),
            "qa",
            f"canary-{suffix}",
            "--ssat",
            str(ssat),
            "--root",
            str(root),
            "--strict",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return {
            "ok": False,
            "provenance_ok": provenance_ok,
            "reason": f"{suffix} feature canary failed",
            "output": (result.stdout + result.stderr)[-1000:],
            "provenance": payload,
        }
    try:
        qa = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "provenance_ok": provenance_ok,
            "reason": f"{suffix} feature canary was not JSON",
            "provenance": payload,
        }
    if qa.get("metrics", {}).get("coverage_assessment") != "measured":
        return {
            "ok": False,
            "provenance_ok": provenance_ok,
            "reason": f"{suffix} symbols were not measured",
            "provenance": payload,
        }
    return None


def _forgeline_feature_canaries(module, payload: dict, provenance_ok: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="factory-doctor-") as directory:
        root = Path(directory)
        (root / "services").mkdir()
        for suffix in ("mjs", "ts"):
            failure = _run_feature_canary(module, root, payload, provenance_ok, suffix)
            if failure is not None:
                return failure
    return {
        "ok": True,
        "provenance_ok": provenance_ok,
        "provenance": payload,
        "canary": "mjs-and-ts-feature-qa",
    }


def _workflow_canary(module) -> dict:
    """Run a bounded, non-mutating behavior check rather than trusting --help."""
    payload, error = _canary_version(module)
    if error is not None:
        return error
    provenance_ok, error = _canary_provenance(payload)
    if error is not None:
        return error
    if module.name != "forgeline":
        return {"ok": True, "provenance_ok": provenance_ok, "provenance": payload}
    return _forgeline_feature_canaries(module, payload, provenance_ok)


def _home(root: Path = Path("."), as_json: bool = False) -> int:
    """Return compact, live state for agents without requiring command discovery."""
    modules = _lazy_import("assembly", "detect")()
    factory_root = root / ".factory"
    counts = {
        "receipts": len(list((factory_root / "receipts").glob("*.json")))
        if factory_root.exists()
        else 0,
        "traces": len(list((factory_root / "traces").glob("*.json")))
        if factory_root.exists()
        else 0,
        "challenges": len(list((factory_root / "challenges").glob("*.json")))
        if factory_root.exists()
        else 0,
        "passports": len(list((factory_root / "passports").glob("*.json")))
        if factory_root.exists()
        else 0,
        "loop_passports": len(list((factory_root / "loop-passports").glob("*.json")))
        if factory_root.exists()
        else 0,
    }
    installed = sum(module.installed for module in modules)
    payload = {
        "bin": str(Path(sys.argv[0]).resolve()),
        "description": "Five-brick spec-to-proof software factory",
        "root": str(root.resolve()),
        "bricks": {"installed": installed, "total": len(modules)},
        "proof": counts,
        "next": [
            "factory doctor --json",
            "factory plan",
            "factory init ."
            if not factory_root.exists()
            else "factory evidence <feature>",
        ],
    }
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"bin: {payload['bin']}")
        print(f"description: {payload['description']}")
        print(f"root: {payload['root']}")
        print(f"bricks: {installed} of {len(modules)} installed")
        print("proof:")
        for name, count in counts.items():
            print(f"  {name}: {count}")
        print("next:")
        for command in payload["next"]:
            print(f"  - {command}")
    return 0


def _doctor_checks() -> tuple[list, list]:
    mods = _lazy_import("assembly", "detect")()
    checks = []
    for module in mods:
        help_text = None
        if module.installed:
            proc = subprocess.run(
                [_cli_command(module.cli), "--help"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            help_text = proc.stdout + proc.stderr
        workflow = _workflow_canary(module)
        provenance = workflow.get("provenance")
        if not isinstance(provenance, dict):
            provenance = {}
        reported_version = provenance.get("version")
        if not isinstance(reported_version, str):
            reported_version = None
        check = _lazy_import("protocol", "compatibility")(
            module.name,
            _lazy_import("contract", "MODULES")[module.name],
            help_text,
            reported_version=reported_version,
        )
        checks.append((check, workflow))
    return mods, checks


def _doctor_json(checks: list, strict: bool) -> int:
    installation_ok = all(item[0].ok for item in checks)
    workflow_ok = all(item[1]["ok"] for item in checks)
    provenance_ok = all(item[1].get("provenance_ok", False) for item in checks)
    print(
        json.dumps(
            {
                "ok": installation_ok and workflow_ok and provenance_ok,
                "installation_ok": installation_ok,
                "workflow_ok": workflow_ok,
                "provenance_ok": provenance_ok,
                "modules": [
                    check.__dict__ | {"installation_ok": check.ok, "workflow": workflow}
                    for check, workflow in checks
                ],
            },
            indent=2,
        )
    )
    return 0 if (installation_ok and workflow_ok and provenance_ok) or not strict else 1


def _doctor_module_mark(module: Any, check: Any, workflow: dict) -> str:
    if check.ok and workflow["ok"] and workflow.get("provenance_ok"):
        return "compatible"
    if check.ok and workflow["ok"]:
        return "provenance-incomplete"
    if not check.installed:
        return "missing"
    return "workflow-failed" if check.ok else "incompatible"


def _print_doctor_module(module: Any, check: Any, workflow: dict) -> None:
    mark = _doctor_module_mark(module, check, workflow)
    version = check.version or "not installed"
    print(
        f"  [{mark:>12}]  {module.name:<10} {version:<10} requires >= {check.minimum}"
    )
    if check.missing_commands:
        print(f"                 missing commands: {', '.join(check.missing_commands)}")
    if not workflow["ok"]:
        print(f"                 workflow: {workflow['reason']}")
    elif not workflow.get("provenance_ok"):
        print("                 provenance: source identity is incomplete")


def _doctor_failures(checks: list) -> list:
    return [
        check
        for check, workflow in checks
        if not check.ok or not workflow["ok"] or not workflow.get("provenance_ok")
    ]


def _print_doctor_summary(failed: list) -> None:
    if failed:
        print("\nInstall or upgrade incompatible bricks:")
        for item in failed:
            print(f"  pip install --upgrade {item.package}>={item.minimum}")
    else:
        print(
            "\nAll four companion bricks plus FactoryLine satisfy the five-brick factory protocol."
        )


def _doctor_text(mods: list, checks: list, strict: bool) -> int:
    print("factoryline doctor - Lego assembly compatibility\n" + "=" * 48)
    for module, (check, workflow) in zip(mods, checks):
        _print_doctor_module(module, check, workflow)
    failed = _doctor_failures(checks)
    _print_doctor_summary(failed)
    return 1 if strict and failed else 0


def _doctor(strict: bool = False, as_json: bool = False) -> int:
    mods, checks = _doctor_checks()
    if as_json:
        return _doctor_json(checks, strict)
    return _doctor_text(mods, checks, strict)


def _plan() -> int:
    print("factoryline assembly pipeline\n" + "=" * 44)
    installed = {m.name: m.installed for m in _lazy_import("assembly", "detect")()}
    for module, args in _lazy_import("assembly", "DEFAULT_CHAIN"):
        cli = _lazy_import("contract", "MODULES")[module]["cli"]
        tag = "" if installed.get(module) else "   (skipped - not installed)"
        if module == "prestige":
            tag += "   (runs only when smoke/<feature>.ui declares UI scope)"
        print(f"  {module:<10} -> {cli} {' '.join(args)}{tag}")
    print(
        "\nEach arrow is a Lego seam: the output of one stage is the input of the next,"
    )
    print(
        "passed on disk under the shared factory layout (portable across IDE/agent/OS)."
    )
    return 0


def __getattr__(name: str):
    """Preserve legacy lazy imports for compatibility-tested CLI seams."""
    if name == "release_decision_card":
        from .release_decision import release_decision_card

        return release_decision_card
    raise AttributeError(name)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="factory",
        description="Snap SpecLine, ForgeLine, HSF and Prestige into one assembly line.",
    )
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("home", help="show compact live factory and proof state")
    s.add_argument("--root", default=".")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("doctor", help="show brick versions and command compatibility")
    s.add_argument("--strict", action="store_true")
    s.add_argument("--json", action="store_true")
    plan = sub.add_parser(
        "plan", help="print the assembly pipeline or verify a human-approved agent plan"
    )
    plan_sub = plan.add_subparsers(dest="plan_cmd")
    plan_verify = plan_sub.add_parser(
        "verify",
        help="join an agent-plan envelope to local Diff-to-Proof facts without execution",
    )
    plan_verify.add_argument(
        "--plan", required=True, help="factory.agent_plan.v1 JSON path"
    )
    plan_verify.add_argument("--root", default=".")
    plan_verify.add_argument("--base", default="main")
    plan_verify.add_argument(
        "--changed",
        action="append",
        default=[],
        help="workspace-relative changed path; repeat as needed",
    )
    plan_verify.add_argument(
        "--out-dir",
        help="explicit local directory for JSON, Markdown, and Mermaid review artifacts",
    )
    plan_verify.add_argument("--json", action="store_true")

    from .cli_foundations import add_parser as add_foundation_parsers

    add_foundation_parsers(sub)

    first_proof = sub.add_parser(
        "first-proof",
        help="run a local sandbox demonstration that catches an intentionally hollow check",
    )
    first_proof.add_argument("--root", default=".")
    first_proof.add_argument(
        "--out-dir", help="optional workspace-contained output directory"
    )
    first_proof.add_argument("--json", action="store_true")

    from .cli_first_lap import add_parser as add_first_lap_parser

    add_first_lap_parser(sub)

    agui = sub.add_parser(
        "agui", help="emit controlled, deterministic AGUI-style review events"
    )
    agui_sub = agui.add_subparsers(required=True, dest="agui_cmd")
    agui_review = agui_sub.add_parser(
        "review-events",
        help="map local First Lap status to review cards for Mission Control or an IDE",
    )
    agui_review.add_argument("--root", default=".")
    agui_review.add_argument("--run-id", default="local-review")
    agui_review.add_argument("--surface", default="mission_control")
    agui_review.add_argument("--json", action="store_true")

    guide = sub.add_parser(
        "guide", help="choose one plain-language path before opening advanced controls"
    )
    guide.add_argument("--journey", help="one of: solo, team, enterprise")
    guide.add_argument("--json", action="store_true")

    quality_harness = sub.add_parser(
        "quality-harness",
        help="bind full-stack engineering evidence and six human UX judgments",
    )
    quality_sub = quality_harness.add_subparsers(required=True, dest="quality_cmd")
    quality_template = quality_sub.add_parser(
        "template", help="write a closed, unverified quality manifest"
    )
    quality_template.add_argument("--root", default=".")
    quality_template.add_argument("--out", required=True)
    quality_template.add_argument(
        "--ui", action="store_true", help="include the seven UI evidence checks"
    )
    quality_template.add_argument("--json", action="store_true")
    quality_verify = quality_sub.add_parser(
        "verify",
        help="verify bound evidence and human judgments without executing checks",
    )
    quality_verify.add_argument("manifest")
    quality_verify.add_argument("--root", default=".")
    quality_verify.add_argument("--out")
    quality_verify.add_argument("--json", action="store_true")
    quality_spec_validate = quality_sub.add_parser(
        "spec-validate",
        help="strictly validate the Full-Stack UX Harness SSAT/YAML contract and write a local receipt",
    )
    quality_spec_validate.add_argument(
        "spec",
        help="workspace-contained full-stack-ux-harness-v1.ssat.yaml or explicit v1alpha1 contract",
    )
    quality_spec_validate.add_argument("--root", default=".")
    quality_spec_validate.add_argument("--out")
    quality_spec_validate.add_argument("--json", action="store_true")
    quality_spec_verify = quality_sub.add_parser(
        "spec-verify",
        help="replay a Full-Stack UX Harness spec receipt against its current source",
    )
    quality_spec_verify.add_argument("receipt", help="workspace-contained spec receipt")
    quality_spec_verify.add_argument("--root", default=".")
    quality_spec_verify.add_argument("--json", action="store_true")

    from .cli_audit import add_parser as add_audit_parser

    add_audit_parser(sub)

    evidence_audit = sub.add_parser(
        "evidence-audit",
        help="bind capability claims to source and tests; execute only with --execute",
    )
    evidence_audit.add_argument(
        "manifest", nargs="?", default="evidence/capability-evidence.json"
    )
    evidence_audit.add_argument("--root", default=".")
    evidence_audit.add_argument(
        "--execute",
        action="store_true",
        help="run the reviewed manifest commands locally without a shell",
    )
    evidence_audit.add_argument("--json", action="store_true")

    from .cli_review_surfaces import add_parser as add_review_surface_parsers

    add_review_surface_parsers(sub)

    from .cli_runtime_proof import add_parser as add_runtime_proof_parsers

    add_runtime_proof_parsers(sub)

    from .cli_wrap import add_parser as add_wrap_parser

    add_wrap_parser(sub)

    gauntlet = sub.add_parser(
        "gauntlet",
        help="draft, compile, admit, run, and verify a supervised proof-of-survival batch",
    )
    gauntlet_sub = gauntlet.add_subparsers(required=True, dest="gauntlet_cmd")
    gauntlet_draft = gauntlet_sub.add_parser(
        "draft",
        help="statically propose inert promise and E2E drafts from repository structure",
    )
    gauntlet_draft.add_argument("--root", default=".")
    gauntlet_draft.add_argument("--source-id", required=True)
    gauntlet_draft.add_argument("--json", action="store_true")
    gauntlet_plan = gauntlet_sub.add_parser(
        "plan",
        help="compile declared promise sabotages from human-written E2E manifests without execution",
    )
    gauntlet_plan.add_argument("--root", default=".")
    gauntlet_plan.add_argument(
        "--source",
        required=True,
        help="workspace-contained factory.gauntlet-source.v1 JSON path",
    )
    gauntlet_plan.add_argument(
        "--out", help="optional workspace-contained proposal output path"
    )
    gauntlet_plan.add_argument("--json", action="store_true")
    gauntlet_admit = gauntlet_sub.add_parser(
        "admit", help="seal one named, expiring admission for an exact current proposal"
    )
    gauntlet_admit.add_argument(
        "proposal", help="workspace-contained factory.gauntlet-proposal.v1 JSON path"
    )
    gauntlet_admit.add_argument("--root", default=".")
    gauntlet_admit.add_argument("--approved-by", required=True)
    gauntlet_admit.add_argument("--rationale", required=True)
    gauntlet_admit.add_argument(
        "--confirmation",
        required=True,
        help="exact confirmation phrase shown by the proposal source id",
    )
    gauntlet_admit.add_argument("--valid-for-minutes", type=int, default=30)
    gauntlet_admit.add_argument(
        "--out", help="optional workspace-contained admission output path"
    )
    gauntlet_admit.add_argument("--json", action="store_true")
    gauntlet_run = gauntlet_sub.add_parser(
        "run", help="run only one current, named-admitted local E2E sabotage batch"
    )
    gauntlet_run.add_argument(
        "proposal", help="workspace-contained factory.gauntlet-proposal.v1 JSON path"
    )
    gauntlet_run.add_argument("--root", default=".")
    gauntlet_run.add_argument(
        "--admission",
        help="workspace-contained factory.gauntlet-admission.v1 JSON path",
    )
    gauntlet_run.add_argument(
        "--out", help="optional workspace-contained Survival Card output path"
    )
    gauntlet_run.add_argument("--json", action="store_true")
    gauntlet_card = gauntlet_sub.add_parser(
        "card",
        help="verify, challenge, or optionally DSSE-seal an existing Survival Card",
    )
    gauntlet_card_sub = gauntlet_card.add_subparsers(
        required=True, dest="gauntlet_card_cmd"
    )
    gauntlet_card_verify = gauntlet_card_sub.add_parser(
        "verify", help="verify one card offline and optionally its exact DSSE binding"
    )
    gauntlet_card_verify.add_argument("card")
    gauntlet_card_verify.add_argument("--envelope")
    gauntlet_card_verify.add_argument("--trust-root")
    gauntlet_card_verify.add_argument("--json", action="store_true")
    gauntlet_card_challenge = gauntlet_card_sub.add_parser(
        "challenge",
        help="prove the card verifier rejects a changed summary without editing the card",
    )
    gauntlet_card_challenge.add_argument("card")
    gauntlet_card_challenge.add_argument("--json", action="store_true")
    gauntlet_card_seal = gauntlet_card_sub.add_parser(
        "seal", help="optionally bind one card to a Receipt v2 DSSE envelope"
    )
    gauntlet_card_seal.add_argument("card")
    gauntlet_card_seal.add_argument("--private-key", required=True)
    gauntlet_card_seal.add_argument("--keyid", required=True)
    gauntlet_card_seal.add_argument("--identity", required=True)
    gauntlet_card_seal.add_argument("--issuer", required=True)
    gauntlet_card_seal.add_argument("--tenant", default="local")
    gauntlet_card_seal.add_argument("--out", required=True)
    gauntlet_card_seal.add_argument("--json", action="store_true")
    gauntlet_status_parser = gauntlet_sub.add_parser(
        "status", help="read local Survival Card facts without execution"
    )
    gauntlet_status_parser.add_argument("--root", default=".")
    gauntlet_status_parser.add_argument("--source-id")
    gauntlet_status_parser.add_argument("--json", action="store_true")

    from .cli_governance_surfaces import add_parser as add_governance_surface_parsers

    add_governance_surface_parsers(sub)

    team_pilot = sub.add_parser(
        "team-pilot",
        help="validate customer-managed Team Pilot readiness without commercial activation",
    )
    team_pilot_sub = team_pilot.add_subparsers(required=True, dest="team_pilot_cmd")
    team_pilot_readiness = team_pilot_sub.add_parser(
        "readiness",
        help="hash-bind selected-partner and operating evidence for owner review",
    )
    team_pilot_readiness.add_argument("--root", default=".")
    team_pilot_readiness.add_argument(
        "--manifest",
        required=True,
        help="workspace-contained factory.team-pilot-launch.v1 JSON path",
    )
    team_pilot_readiness.add_argument(
        "--out-dir",
        help="explicit local directory for public receipt, Markdown, and Mermaid artifacts",
    )
    team_pilot_readiness.add_argument("--json", action="store_true")
    team_pilot_verify = team_pilot_sub.add_parser(
        "verify", help="verify a hash-bound Team Pilot readiness receipt"
    )
    team_pilot_verify.add_argument("receipt")
    team_pilot_verify.add_argument("--json", action="store_true")

    s = sub.add_parser("init", help="create the shared factory layout")
    s.add_argument("root", nargs="?", default=".")

    s = sub.add_parser("assemble", help="run the assembly line for a feature")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument(
        "--release-contract",
        help="explicit release contract path to carry into stage receipts",
    )

    s = sub.add_parser(
        "release-contract", help="create or verify a hash-bound local release policy"
    )
    release_sub = s.add_subparsers(required=True, dest="release_contract_cmd")
    release_template = release_sub.add_parser(
        "template", help="write a deterministic contract template from a sealed Oracle"
    )
    release_template.add_argument("feature")
    release_template.add_argument("--root", default=".")
    release_template.add_argument("--oracle-contract", required=True)
    release_template.add_argument(
        "--stage",
        action="append",
        dest="stages",
        help="required module:stage; repeat as needed",
    )
    release_template.add_argument("--approved-by", required=True)
    release_template.add_argument(
        "--evidence",
        action="append",
        default=[],
        metavar="STAGE=PATH",
        help="bind a supported external evidence stage",
    )
    release_template.add_argument("--out", required=True)
    release_template.add_argument("--json", action="store_true")
    release_verify = release_sub.add_parser(
        "verify", help="verify the contract and current Oracle/evidence bindings"
    )
    release_verify.add_argument("feature")
    release_verify.add_argument("contract")
    release_verify.add_argument("--root", default=".")
    release_verify.add_argument("--json", action="store_true")

    s = sub.add_parser("continue", help="resume assembly from the next safe stage")
    s.add_argument("feature", nargs="?")
    s.add_argument("--root", default=".")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--usage-json", help="exact measured usage JSON file")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("metrics", help="export privacy-safe Assembly run metrics")
    s.add_argument("--root", default=".")
    s.add_argument("--out")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("savings", help="record and report exact paired savings")
    savings_sub = s.add_subparsers(dest="savings_cmd")
    record = savings_sub.add_parser(
        "record", help="record one baseline-versus-Factory pair"
    )
    record.add_argument("pair_id")
    record.add_argument("--root", default=".")
    record.add_argument("--baseline-elapsed-ms", type=int, required=True)
    record.add_argument("--factory-elapsed-ms", type=int, required=True)
    record.add_argument("--baseline-tokens", type=int)
    record.add_argument("--factory-tokens", type=int)
    record.add_argument("--baseline-cost-usd", type=float)
    record.add_argument("--factory-cost-usd", type=float)
    record.add_argument("--equivalent-outcome", action="store_true")
    record.add_argument("--evidence")
    record.add_argument("--replace", action="store_true")
    record.add_argument("--json", action="store_true")
    report = savings_sub.add_parser(
        "report", help="show or export aggregate-safe savings"
    )
    report.add_argument("--root", default=".")
    report.add_argument("--out")
    report.add_argument("--json", action="store_true")

    s = sub.add_parser(
        "update-check", help="report whether a newer release exists; installs nothing"
    )
    s.add_argument("--root", default=".")
    s.add_argument("--force", action="store_true", help="ignore the 24h cache")
    s.add_argument("--json", action="store_true")

    # Habituation: thin delegates only; logic lives in factoryline/habituation.py.
    s = sub.add_parser(
        "habituation", help="calibrate the human approval signal instead of trusting it"
    )
    hab_sub = s.add_subparsers(dest="hab_cmd")
    hab_record = hab_sub.add_parser("record", help="record one observed review event")
    hab_record.add_argument("review_id")
    hab_record.add_argument("--root", default=".")
    hab_record.add_argument("--reviewer", required=True)
    hab_record.add_argument("--author-kind", required=True, choices=["agent", "human"])
    hab_record.add_argument("--review-seconds", type=float, required=True)
    hab_record.add_argument("--changed-lines", type=int, required=True)
    hab_record.add_argument("--inline-comments", type=int, default=0)
    hab_record.add_argument("--approved", action="store_true")
    hab_record.add_argument("--replace", action="store_true")
    hab_record.add_argument("--json", action="store_true")
    hab_status = hab_sub.add_parser(
        "status", help="evaluate the gate and show the intervention"
    )
    hab_status.add_argument("--root", default=".")
    hab_status.add_argument(
        "--allow-block",
        action="store_true",
        help="permit fail-closed; refused until blind-spot outcomes exist",
    )
    hab_status.add_argument("--json", action="store_true")
    hab_sample = hab_sub.add_parser(
        "sample", help="select low-scrutiny approvals for independent re-review"
    )
    hab_sample.add_argument("--root", default=".")
    hab_sample.add_argument("--rate", type=int, default=10)
    hab_sample.add_argument("--json", action="store_true")
    hab_resample = hab_sub.add_parser(
        "resample", help="record what an independent re-review found"
    )
    hab_resample.add_argument("review_id")
    hab_resample.add_argument("--root", default=".")
    hab_resample.add_argument("--reviewer", required=True)
    hab_resample.add_argument("--defect-found", action="store_true")
    hab_resample.add_argument("--notes", default="")
    hab_resample.add_argument("--json", action="store_true")
    hab_report = hab_sub.add_parser(
        "report", help="show or export the aggregate-safe public report"
    )
    hab_report.add_argument("--root", default=".")
    hab_report.add_argument("--out")
    hab_report.add_argument(
        "--enable-defect-linkage",
        action="store_true",
        help="opt in to the modeled correlation; read its assumptions first",
    )

    # CDTE: thin delegates only. Logic lives in factoryline/cdte.py — cli.py is
    # already the largest module in the package and the architecture gate flags it.
    s = sub.add_parser(
        "cdte", help="detect NFR contradictions before any code is generated"
    )
    cdte_sub = s.add_subparsers(dest="cdte_cmd")
    scan = cdte_sub.add_parser(
        "scan", help="scan extracted NFR constraints for lethal pairs"
    )
    scan.add_argument("run_id")
    scan.add_argument(
        "constraints", help="path to a JSON file of extracted NFR constraints"
    )
    scan.add_argument("--root", default=".")
    scan.add_argument(
        "--evidence",
        help="benchmark file to hash-bind, promoting modeled proofs to measured",
    )
    scan.add_argument(
        "--adr", action="store_true", help="draft an ADR for each detected conflict"
    )
    scan.add_argument("--replace", action="store_true")
    scan.add_argument("--json", action="store_true")
    cdte_report = cdte_sub.add_parser(
        "report", help="show or export aggregate-safe conflict statistics"
    )
    cdte_report.add_argument("--root", default=".")
    cdte_report.add_argument("--out")
    cdte_report.add_argument("--json", action="store_true")
    resolve = cdte_sub.add_parser(
        "resolve", help="record an ADR decision or an expiring override"
    )
    resolve.add_argument("run_id")
    resolve.add_argument("conflict_id")
    resolve.add_argument("--root", default=".")
    resolve.add_argument("--decision", required=True)
    resolve.add_argument("--approved-by", required=True)
    resolve.add_argument("--adr-path")
    resolve.add_argument(
        "--override",
        action="store_true",
        help="accept the contradiction; requires --expires",
    )
    resolve.add_argument("--expires", help="ISO date after which the override lapses")
    resolve.add_argument("--json", action="store_true")

    s = sub.add_parser(
        "proofs", help="record and route content-addressed read-only proof receipts"
    )
    proofs_sub = s.add_subparsers(dest="proofs_cmd")
    proof_record = proofs_sub.add_parser(
        "record", help="record one completed green proof from a request manifest"
    )
    proof_record.add_argument("manifest")
    proof_record.add_argument(
        "--gate", help="gate name; required when the manifest contains multiple gates"
    )
    proof_record.add_argument("--root", default=".")
    proof_record.add_argument("--elapsed-ms", type=int, required=True)
    proof_record.add_argument("--tokens", type=int)
    proof_record.add_argument("--replace", action="store_true")
    proof_record.add_argument("--json", action="store_true")
    proof_plan = proofs_sub.add_parser(
        "plan", help="route requested gates to RUN, REUSE, SKIP, or BLOCK"
    )
    proof_plan.add_argument("manifest")
    proof_plan.add_argument("--root", default=".")
    proof_plan.add_argument("--changed", action="append", default=[])
    proof_plan.add_argument("--auto-savings", action="store_true")
    proof_plan.add_argument("--out")
    proof_plan.add_argument("--json", action="store_true")
    proof_verify = proofs_sub.add_parser(
        "verify", help="verify a private proof receipt and all current hashes"
    )
    proof_verify.add_argument("receipt")
    proof_verify.add_argument("--root", default=".")
    proof_verify.add_argument("--json", action="store_true")
    proof_challenge = proofs_sub.add_parser(
        "challenge", help="prove an isolated input mutation invalidates reuse"
    )
    proof_challenge.add_argument("receipt")
    proof_challenge.add_argument("--root", default=".")
    proof_challenge.add_argument("--json", action="store_true")

    s = sub.add_parser(
        "verify", help="summarize local receipts into a fail-closed readiness decision"
    )
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument(
        "--strict-release",
        action="store_true",
        help="also require a current Oracle-bound release contract",
    )
    s.add_argument(
        "--release-contract",
        default=None,
        help="workspace-relative release contract; defaults to .factory/release-contracts/<feature>.json",
    )
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("meter", help="real savings summary from your runs")
    s.add_argument("--root", default=".")
    s.add_argument("--runs", type=int, default=1000, help="projected production runs")
    s.add_argument(
        "--baseline",
        type=int,
        default=4000,
        help="baseline tokens per run (declare your real agent cost)",
    )
    s.add_argument(
        "--json", action="store_true", help="emit a machine-readable current snapshot"
    )
    s.add_argument(
        "--watch",
        action="store_true",
        help="refresh the local meter as new stages finish",
    )
    s.add_argument(
        "--interval", type=float, default=1.0, help="watch refresh interval in seconds"
    )
    s.add_argument(
        "--max-updates",
        type=int,
        default=None,
        help="stop after N snapshots (useful for automation)",
    )
    s.add_argument(
        "--feature",
        default="local-observation",
        help="feature label for a captured local command",
    )
    s.add_argument(
        "--module", default="local", help="module label for a captured local command"
    )
    s.add_argument(
        "--stage", default="command", help="stage label for a captured local command"
    )
    s.add_argument(
        "--capture",
        action="store_true",
        help="run a command and append its measured local wall time",
    )

    s = sub.add_parser("overhead", help="show measured wall-clock overhead per gate")
    s.add_argument("--root", default=".")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser(
        "override",
        help="record an owned, expiring exception without hiding a failed gate",
    )
    s.add_argument("issue")
    s.add_argument("--root", default=".")
    s.add_argument("--reason", required=True)
    s.add_argument("--approved-by", required=True)
    s.add_argument("--expires", default=None)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser(
        "receipt", help="sign or verify factory receipts with Sigstore identity"
    )
    receipt_sub = s.add_subparsers(required=True, dest="receipt_cmd")
    receipt_sign = receipt_sub.add_parser(
        "sign", help="keylessly sign a receipt with Sigstore"
    )
    receipt_sign.add_argument("path")
    receipt_sign.add_argument("--overwrite", action="store_true")
    receipt_sign.add_argument("--timeout", type=int, default=300)
    receipt_verify = receipt_sub.add_parser(
        "verify", help="verify receipt bytes and expected OIDC identity"
    )
    receipt_verify.add_argument("path")
    receipt_verify.add_argument("--cert-identity", required=True)
    receipt_verify.add_argument("--cert-oidc-issuer", required=True)
    receipt_verify.add_argument("--timeout", type=int, default=300)
    receipt_status = receipt_sub.add_parser(
        "status",
        help="report signature presence or UNSIGNED without claiming verification",
    )
    receipt_status.add_argument("path")

    s = sub.add_parser(
        "verify-receipts", help="challenge the offline Receipt v2 verification chain"
    )
    s.add_argument("--root", default=".")
    s.add_argument("--out")
    s.add_argument("--json", action="store_true")

    from .cli_enterprise import add_parser as add_enterprise_parser

    add_enterprise_parser(sub)
    from .cli_controls import add_parser as add_control_parser

    add_control_parser(sub)

    # control and controls are registered together by the bounded lazy boundary.

    engineering_memory = sub.add_parser(
        "evidence-memory",
        help="recall current evidence-backed engineering metadata without gate authority",
    )
    engineering_memory.add_argument("--root", default=".")
    engineering_memory.add_argument("--tenant", required=True)
    engineering_memory.add_argument("--subject", required=True)
    engineering_memory.add_argument("--purpose", required=True)
    engineering_memory.add_argument("--scope", required=True)
    engineering_memory.add_argument(
        "--sender", choices=sorted(_lazy_import("contract", "MODULES"))
    )
    engineering_memory.add_argument(
        "--receiver", choices=sorted(_lazy_import("contract", "MODULES"))
    )
    engineering_memory.add_argument(
        "--accept", help="workspace-relative handoff JSON to revalidate"
    )
    continuity = sub.add_parser(
        "continuity", help="govern local proof-carrying engineering-memory references"
    )
    continuity_sub = continuity.add_subparsers(required=True, dest="continuity_cmd")
    continuity_init = continuity_sub.add_parser(
        "init", help="create a local Factory Continuity metadata ledger"
    )
    continuity_init.add_argument("--db", required=True)

    def add_continuity_identity(parser, *, default_role: str):
        parser.add_argument("--db", required=True)
        parser.add_argument("--tenant", required=True)
        parser.add_argument("--subject", required=True)
        parser.add_argument(
            "--roles",
            default=default_role,
            help="comma-separated local roles; CLI values are not authenticated identity",
        )
        parser.add_argument(
            "--purposes",
            required=True,
            help="comma-separated exact purpose references, e.g. delivery-review@1",
        )

    continuity_record = continuity_sub.add_parser(
        "record",
        help="atomically record one draft memory reference and its audit event",
    )
    continuity_record.add_argument(
        "payload",
        help="metadata-only continuity record JSON; memory contents are rejected",
    )
    continuity_record.add_argument("--idempotency-key", required=True)
    continuity_record.add_argument("--record-id")
    add_continuity_identity(continuity_record, default_role="writer")
    continuity_recall = continuity_sub.add_parser(
        "recall",
        help="recall only verified, current, exact-scope purpose-authorized records",
    )
    continuity_recall.add_argument(
        "--purpose",
        required=True,
        help="exact purpose reference, e.g. delivery-review@1",
    )
    continuity_recall.add_argument(
        "--scope", required=True, help="exact opaque repository scope reference"
    )
    add_continuity_identity(continuity_recall, default_role="reader")
    continuity_promote = continuity_sub.add_parser(
        "promote", help="independently promote one evidence-bound draft record"
    )
    continuity_promote.add_argument("record_id")
    continuity_promote.add_argument("--reason", required=True)
    add_continuity_identity(continuity_promote, default_role="promoter")
    withdraw = continuity_sub.add_parser(
        "withdraw", help="withdraw a reviewed memory with an atomic audit event"
    )
    withdraw.add_argument("record_id")
    withdraw.add_argument(
        "--status", choices=["superseded", "contradicted", "revoked"], required=True
    )
    withdraw.add_argument("--reason", required=True)
    withdraw.add_argument("--replacement-id")
    add_continuity_identity(withdraw, default_role="promoter")
    continuity_prove = continuity_sub.add_parser(
        "prove",
        help="show local unsigned lineage for one record without mutation authority",
    )
    continuity_prove.add_argument("record_id")
    add_continuity_identity(continuity_prove, default_role="reader")
    continuity_status = continuity_sub.add_parser(
        "status", help="show bounded local continuity ledger state"
    )
    continuity_status.add_argument("--db", required=True)

    from .cli_assurance import add_parser as add_assurance_parser

    add_assurance_parser(sub)

    s = sub.add_parser(
        "verify-policy",
        help="prove a policy evaluator catches every delete/invert mutation",
    )
    s.add_argument("--root", default=".")
    s.add_argument("--policy", default="factory.policy.json")
    s.add_argument(
        "--challenge",
        required=True,
        help="JSON manifest with argv command containing {policy}",
    )
    s.add_argument(
        "--out", help="receipt output; defaults under .factory/policy-challenges"
    )

    s = sub.add_parser(
        "compliance", help="export versioned non-certifying compliance evidence"
    )
    compliance_sub = s.add_subparsers(required=True, dest="compliance_cmd")
    compliance_sub.add_parser("packs", help="list available control packs")
    compliance_export = compliance_sub.add_parser(
        "export", help="write an OSCAL-shaped assessment"
    )
    compliance_export.add_argument("pack")
    compliance_export.add_argument("evidence")
    compliance_export.add_argument("--tenant", required=True)
    compliance_export.add_argument("--out", required=True)
    compliance_export.add_argument(
        "--controls", help="reviewed customer control JSON array"
    )

    s = sub.add_parser(
        "privacy",
        help="create selective-disclosure proofs and report optional backend status",
    )
    privacy_sub = s.add_subparsers(required=True, dest="privacy_cmd")
    privacy_sub.add_parser("status", help="report BBS and zkVM backend availability")
    privacy_merkle = privacy_sub.add_parser(
        "merkle", help="write a one-leaf Merkle disclosure"
    )
    privacy_merkle.add_argument("leaves")
    privacy_merkle.add_argument("--disclose", required=True)
    privacy_merkle.add_argument("--out", required=True)

    s = sub.add_parser(
        "loop", help="create and verify portable governed-loop contracts"
    )
    loop_sub = s.add_subparsers(required=True, dest="loop_cmd")
    loop_init = loop_sub.add_parser(
        "init", help="write a conservative Loop Passport manifest"
    )
    loop_init.add_argument("loop_id")
    loop_init.add_argument("--owner", required=True)
    loop_init.add_argument("--root", default=".")
    loop_init.add_argument("--force", action="store_true")
    loop_init.add_argument("--json", action="store_true")
    loop_validate = loop_sub.add_parser(
        "validate", help="validate a Loop Passport manifest fail closed"
    )
    loop_validate.add_argument("manifest")
    loop_validate.add_argument("--json", action="store_true")
    loop_passport = loop_sub.add_parser(
        "passport", help="write a hash-bound Loop Passport and Mermaid graph"
    )
    loop_passport.add_argument("manifest")
    loop_passport.add_argument("--root", default=".")
    loop_passport.add_argument("--json", action="store_true")
    loop_verify = loop_sub.add_parser(
        "verify", help="verify a Loop Passport and its manifest binding"
    )
    loop_verify.add_argument("passport")
    loop_verify.add_argument("--json", action="store_true")
    loop_budget = loop_sub.add_parser(
        "budget", help="write a fail-closed receipt for supplied loop usage"
    )
    loop_budget.add_argument("manifest")
    loop_budget.add_argument("usage")
    loop_budget.add_argument("--root", default=".")
    loop_budget.add_argument("--json", action="store_true")

    s = sub.add_parser("ci", help="write an opt-in GitHub PR-comment workflow")
    ci_sub = s.add_subparsers(required=True, dest="ci_cmd")
    ci_init = ci_sub.add_parser("init")
    ci_init.add_argument("--feature", required=True)
    ci_init.add_argument("--out", default=".github/workflows/factory-proof.yml")

    s = sub.add_parser("rollup", help="aggregate per-node attribution from receipts")
    s.add_argument("feature")
    s.add_argument("--root", default=".")

    s = sub.add_parser("trace", help="write a proof-carrying PR trace from receipts")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument(
        "--out",
        help="trace output path; defaults to .factory/traces/<feature>.trace.json",
    )
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("verify-trace", help="verify a proof-carrying PR trace")
    s.add_argument("trace")
    s.add_argument("--root", default=None)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser(
        "replay", help="plan or execute the minimal rerun set for changed paths"
    )
    s.add_argument("trace")
    s.add_argument("--root", default=None)
    s.add_argument(
        "--changed", action="append", default=[], help="changed path; repeat as needed"
    )
    s.add_argument("--base", help="git base ref for changed paths, e.g. main")
    s.add_argument(
        "--execute",
        action="store_true",
        help="verify trace, then execute the replay plan",
    )
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("evidence", help="print public-safe proof for a feature")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument(
        "--trace", help="trace path; defaults to .factory/traces/<feature>.trace.json"
    )
    s.add_argument("--json", action="store_true")

    s = sub.add_parser(
        "risk-diff", help="map changed paths to invalidated factory guarantees"
    )
    s.add_argument("--root", default=".")
    s.add_argument("--base", default="main")
    s.add_argument(
        "--changed", action="append", default=[], help="changed path; repeat as needed"
    )
    s.add_argument("--json", action="store_true")

    workspace = sub.add_parser(
        "workspace",
        help="inspect local workspace shape and remote/WSL preflight without IDE mutation",
    )
    workspace_sub = workspace.add_subparsers(required=True, dest="workspace_cmd")
    workspace_inspect = workspace_sub.add_parser(
        "inspect", help="measure bounded filesystem shape and offer manual review paths"
    )
    workspace_inspect.add_argument("--root", default=".")
    workspace_inspect.add_argument(
        "--out-dir",
        help="explicit workspace-contained directory for local JSON, Markdown, and Mermaid advice artifacts",
    )
    workspace_inspect.add_argument("--json", action="store_true")
    workspace_continuity = workspace_sub.add_parser(
        "continuity",
        help="capture or compare a local structural index-continuity baseline",
    )
    workspace_continuity_sub = workspace_continuity.add_subparsers(
        required=True, dest="continuity_cmd"
    )
    workspace_continuity_baseline = workspace_continuity_sub.add_parser(
        "baseline",
        help="capture and explicitly save a workspace-contained structural baseline",
    )
    workspace_continuity_baseline.add_argument("--root", default=".")
    workspace_continuity_baseline.add_argument(
        "--out", required=True, help="workspace-contained .json baseline path"
    )
    workspace_continuity_baseline.add_argument("--json", action="store_true")
    workspace_continuity_compare = workspace_continuity_sub.add_parser(
        "compare",
        help="compare a verified structural baseline with the current workspace",
    )
    workspace_continuity_compare.add_argument("--root", default=".")
    workspace_continuity_compare.add_argument(
        "--baseline", required=True, help="workspace-contained baseline .json path"
    )
    workspace_continuity_compare.add_argument("--json", action="store_true")

    s = sub.add_parser("graph", help="inspect bounded, read-only Factory graph views")
    graph_sub = s.add_subparsers(required=True, dest="graph_cmd")
    graph_ops = graph_sub.add_parser(
        "ops", help="compile the unified local Graph Ops result without writes"
    )
    graph_ops.add_argument("--root", default=".")
    graph_ops.add_argument("--json", action="store_true")
    graph_ops.add_argument(
        "--mermaid", action="store_true", help="print the bounded Mermaid projection"
    )
    graph_impact = graph_sub.add_parser(
        "impact",
        help="map changed paths to explicit bound proof inputs without execution",
    )
    graph_impact.add_argument("--root", default=".")
    graph_impact.add_argument(
        "--changed",
        action="append",
        required=True,
        help="workspace-relative changed path; repeat as needed",
    )
    graph_impact.add_argument("--json", action="store_true")
    graph_portfolio = graph_sub.add_parser(
        "portfolio",
        help="compile a deterministic structural work proposal without execution",
    )
    graph_portfolio.add_argument("--root", default=".")
    graph_portfolio.add_argument(
        "--durations",
        help="JSON object mapping every dependency node id to supplied positive wall milliseconds",
    )
    graph_portfolio.add_argument("--json", action="store_true")
    graph_lineage = graph_sub.add_parser(
        "lineage-verify", help="verify one hash-sealed semantic graph lineage receipt"
    )
    graph_lineage.add_argument("lineage")
    graph_lineage.add_argument(
        "--candidate-sha256",
        help="require this candidate digest in the lineage receipt",
    )
    graph_lineage.add_argument("--json", action="store_true")
    graph_seal = graph_sub.add_parser(
        "lineage-seal",
        help="validate step objects and atomically write a hash-sealed lineage receipt",
    )
    graph_seal.add_argument("--run-id", required=True)
    graph_seal.add_argument("--graph-id", required=True)
    graph_seal.add_argument("--steps", required=True)
    graph_seal.add_argument("--out", required=True)
    graph_seal.add_argument(
        "--candidate-sha256", help="bind the sealed lineage to a candidate digest"
    )
    graph_seal.add_argument("--json", action="store_true")
    graph_mission = graph_sub.add_parser(
        "lineage-mission",
        help="export a verified native mission event chain as sealed lineage",
    )
    graph_mission.add_argument("mission")
    graph_mission.add_argument("--root", default=".")
    graph_mission.add_argument("--run-id", required=True)
    graph_mission.add_argument("--out", required=True)
    graph_mission.add_argument(
        "--candidate-sha256", help="bind the exported lineage to a candidate digest"
    )
    graph_mission.add_argument("--json", action="store_true")
    graph_continuity = graph_sub.add_parser(
        "lineage-continuity",
        help="verify one candidate across Oracle, deep-audit, and graph lineage evidence",
    )
    graph_continuity.add_argument("manifest")
    graph_continuity.add_argument("--root", default=".")
    graph_continuity.add_argument("--json", action="store_true")
    graph_forensic = graph_sub.add_parser(
        "forensics",
        help="compare verified graph runs and preview a bounded recovery fork",
    )
    graph_forensic.add_argument("--baseline", required=True)
    graph_forensic.add_argument("--candidate", required=True)
    graph_forensic.add_argument("--json", action="store_true")
    graph_forensic.add_argument("--mermaid", action="store_true")

    from .cli_authority import add_parser as add_authority_parsers

    add_authority_parsers(sub)

    atomic = sub.add_parser(
        "atomic",
        help="bind a hash-only Atomic workflow export to a sealed Oracle Contract without executing Atomic",
    )
    atomic_sub = atomic.add_subparsers(required=True, dest="atomic_cmd")
    atomic_import = atomic_sub.add_parser(
        "import", help="validate and store one immutable local Atomic mechanics receipt"
    )
    atomic_import.add_argument("--root", default=".")
    atomic_import.add_argument(
        "--envelope",
        required=True,
        help="workspace-relative factory.atomic-run-envelope.v1 JSON",
    )
    atomic_import.add_argument(
        "--out", help="workspace-relative immutable receipt path"
    )
    atomic_import.add_argument("--json", action="store_true")
    atomic_verify = atomic_sub.add_parser(
        "verify",
        help="verify one imported Atomic mechanics receipt and its current Oracle binding",
    )
    atomic_verify.add_argument("receipt")
    atomic_verify.add_argument("--root", default=".")
    atomic_verify.add_argument("--json", action="store_true")
    atomic_status = atomic_sub.add_parser(
        "status",
        help="read bounded imported Atomic mechanics facts without changing a receipt",
    )
    atomic_status.add_argument("--root", default=".")
    atomic_status.add_argument("--json", action="store_true")
    atomic_template = atomic_sub.add_parser(
        "template",
        help="render a secret-free Atomic handoff template without starting Atomic or writing a configuration",
    )
    atomic_template.add_argument("--json", action="store_true")

    agent_bridge = sub.add_parser(
        "agent-bridge",
        help="bind a hash-only Eve, Junie, Grok Build, or generic agent export to a sealed Oracle Contract without contacting a provider",
    )
    agent_bridge_sub = agent_bridge.add_subparsers(
        required=True, dest="agent_bridge_cmd"
    )
    agent_bridge_import = agent_bridge_sub.add_parser(
        "import",
        help="validate and store one immutable provider-neutral agent proof receipt",
    )
    agent_bridge_import.add_argument("--root", default=".")
    agent_bridge_import.add_argument(
        "--envelope",
        required=True,
        help="workspace-relative factory.agent-proof-envelope.v1 JSON",
    )
    agent_bridge_import.add_argument(
        "--out", help="workspace-relative immutable receipt path"
    )
    agent_bridge_import.add_argument("--json", action="store_true")
    agent_bridge_verify = agent_bridge_sub.add_parser(
        "verify",
        help="verify one imported agent proof receipt and current Oracle binding",
    )
    agent_bridge_verify.add_argument("receipt")
    agent_bridge_verify.add_argument("--root", default=".")
    agent_bridge_verify.add_argument("--json", action="store_true")
    agent_bridge_status = agent_bridge_sub.add_parser(
        "status",
        help="read bounded provider-bridge facts without contacting a provider",
    )
    agent_bridge_status.add_argument("--root", default=".")
    agent_bridge_status.add_argument("--json", action="store_true")
    agent_bridge_template = agent_bridge_sub.add_parser(
        "template",
        help="render a secret-free provider envelope template without writing a provider configuration",
    )
    agent_bridge_template.add_argument(
        "--provider",
        required=True,
        choices=["eve", "junie", "grok_build", "coderabbit", "devin", "generic"],
    )
    agent_bridge_template.add_argument("--json", action="store_true")
    agent_bridge_mission = agent_bridge_sub.add_parser(
        "mission",
        help="render the sealed original intent for a worker and human reviewer without contacting a provider",
    )
    agent_bridge_mission.add_argument("--root", default=".")
    agent_bridge_mission.add_argument(
        "--contract",
        required=True,
        help="workspace-relative current sealed Oracle Contract",
    )
    agent_bridge_mission.add_argument("--json", action="store_true")

    from .cli_coordination import add_parser as add_coordination_parser

    add_coordination_parser(sub)

    from .cli_domain import add_parser as add_domain_parser

    add_domain_parser(sub)

    from .cli_deep_audit import add_parser as add_deep_audit_parser

    add_deep_audit_parser(sub)

    from .cli_proofsearch import add_parser as add_proofsearch_parser

    add_proofsearch_parser(sub)

    from .cli_evidence_chain import add_parser as add_evidence_chain_parser

    add_evidence_chain_parser(sub)

    from .cli_revenue import add_parser as add_revenue_parser

    add_revenue_parser(sub)
    from .cli_saas import add_parser as add_saas_parser

    add_saas_parser(sub)

    from .cli_governance import add_parser as add_governance_parser

    add_governance_parser(sub)

    from .cli_github import add_parser as add_github_parser

    add_github_parser(sub)

    from .cli_ide import add_parser as add_ide_parser

    add_ide_parser(sub)

    from .cli_release import add_parser as add_release_parser

    add_release_parser(sub)

    from .cli_integrations import add_parser as add_integrations_parser

    add_integrations_parser(sub)

    from .cli_artifacts import add_parser as add_artifacts_parser

    add_artifacts_parser(sub)

    from .cli_pr import add_parser as add_pr_parser

    add_pr_parser(sub)

    from .cli_app import add_parser as add_app_parser

    add_app_parser(sub)

    from .cli_pack import add_parser as add_pack_parser

    add_pack_parser(sub)

    from .cli_agent import add_parser as add_agent_parser

    add_agent_parser(sub)

    __import__("factoryline.cli_blueprint", fromlist=["add_parser"]).add_parser(sub)
    __import__("factoryline.cli_update", fromlist=["add_parser"]).add_parser(sub)

    from .cli_telemetry import add_parser as add_telemetry_parser

    add_telemetry_parser(sub)

    from .cli_ops import add_parser as add_ops_parser

    add_ops_parser(sub)

    from .cli_verifier import add_parser as add_verifier_parser

    add_verifier_parser(sub)

    from .cli_targets import add_parser as add_targets_parser

    add_targets_parser(sub)

    from .cli_studio import add_parser as add_studio_parser

    add_studio_parser(sub)

    product = sub.add_parser(
        "product",
        help="compile a PRD into a deterministic Product Graph and value slices",
    )
    product_sub = product.add_subparsers(dest="product_cmd", required=True)
    product_compile = product_sub.add_parser(
        "compile", help="compile and gap-check a UTF-8 PRD"
    )
    product_compile.add_argument("prd")
    product_compile.add_argument("--root", default=".")
    product_compile.add_argument("--project")
    product_compile.add_argument(
        "--intake", help="verified source-bound intake confirmation to bind"
    )
    product_compile.add_argument("--force", action="store_true")
    product_compile.add_argument("--json", action="store_true")
    product_verify = product_sub.add_parser(
        "verify", help="verify Product Graph and captured PRD hashes"
    )
    product_verify.add_argument("graph")
    product_verify.add_argument("--json", action="store_true")
    product_slices = product_sub.add_parser(
        "slices", help="compile complete requirement coverage into bounded value slices"
    )
    product_slices.add_argument("graph")
    product_slices.add_argument("--root", default=".")
    product_slices.add_argument("--max-requirements", type=int, default=3)
    product_slices.add_argument("--force", action="store_true")
    product_slices.add_argument("--json", action="store_true")

    prd = sub.add_parser(
        "prd", help="clarify a PRD before optimization and product compilation"
    )
    prd_sub = prd.add_subparsers(dest="prd_cmd", required=True)
    prd_grill = prd_sub.add_parser(
        "grill", help="write a bounded local PRD clarification frontier"
    )
    prd_grill.add_argument("prd")
    prd_grill.add_argument("--root", default=".")
    prd_grill.add_argument("--mode", default="quick", choices=("quick", "deep"))
    prd_grill.add_argument("--project")
    prd_grill.add_argument("--out")
    prd_grill.add_argument("--confirm", action="store_true")
    prd_grill.add_argument("--force", action="store_true")
    prd_grill.add_argument("--json", action="store_true")
    prd_verify = prd_sub.add_parser(
        "verify", help="verify a source-bound PRD Grill receipt"
    )
    prd_verify.add_argument("receipt")
    prd_verify.add_argument("--json", action="store_true")

    intake = sub.add_parser(
        "intake",
        help="resolve framework, intent, and acceptance evidence before mission creation",
    )
    intake_sub = intake.add_subparsers(dest="intake_cmd", required=True)
    intake_grill = intake_sub.add_parser(
        "grill", help="write a source-bound framework and intent decision worksheet"
    )
    intake_grill.add_argument("prd")
    intake_grill.add_argument("--root", default=".")
    intake_grill.add_argument("--project")
    intake_grill.add_argument("--out")
    intake_grill.add_argument("--force", action="store_true")
    intake_grill.add_argument("--json", action="store_true")
    intake_confirm = intake_sub.add_parser(
        "confirm", help="bind named human framework, intent, and acceptance decisions"
    )
    intake_confirm.add_argument("intake")
    intake_confirm.add_argument("--root", default=".")
    intake_confirm.add_argument("--framework", required=True)
    intake_confirm.add_argument("--intent", required=True)
    intake_confirm.add_argument("--acceptance", required=True)
    intake_confirm.add_argument(
        "--external-effects", required=True, choices=("local_only", "human_controlled")
    )
    intake_confirm.add_argument("--approved-by", required=True)
    intake_confirm.add_argument("--rationale", required=True)
    intake_confirm.add_argument("--re-evaluate-when")
    intake_confirm.add_argument("--out")
    intake_confirm.add_argument("--force", action="store_true")
    intake_confirm.add_argument("--json", action="store_true")
    intake_verify = intake_sub.add_parser(
        "verify", help="verify an intake worksheet or confirmation"
    )
    intake_verify.add_argument("receipt")
    intake_verify.add_argument("--root", default=".")
    intake_verify.add_argument("--confirmation", action="store_true")
    intake_verify.add_argument("--json", action="store_true")
    intake_read = intake_sub.add_parser(
        "status", help="read local intake confirmation status"
    )
    intake_read.add_argument("--root", default=".")
    intake_read.add_argument("--prd")
    intake_read.add_argument("--json", action="store_true")
    intake_parameters = intake_sub.add_parser(
        "parameters",
        aliases=("params",),
        help="seal or verify bounded intake operating parameters",
    )
    intake_parameters_sub = intake_parameters.add_subparsers(
        dest="intake_parameters_cmd", required=True
    )
    intake_parameters_seal = intake_parameters_sub.add_parser(
        "seal", help="seal a confirmation-bound intake parameter envelope"
    )
    intake_parameters_seal.add_argument("request")
    intake_parameters_seal.add_argument("--root", default=".")
    intake_parameters_seal.add_argument("--out")
    intake_parameters_seal.add_argument("--force", action="store_true")
    intake_parameters_seal.add_argument("--json", action="store_true")
    intake_parameters_verify = intake_parameters_sub.add_parser(
        "verify", help="verify a sealed intake parameter envelope"
    )
    intake_parameters_verify.add_argument("receipt")
    intake_parameters_verify.add_argument("--root", default=".")
    intake_parameters_verify.add_argument("--json", action="store_true")
    intake_parameters_read = intake_parameters_sub.add_parser(
        "status", help="read intake parameter envelope status"
    )
    intake_parameters_read.add_argument("--root", default=".")
    intake_parameters_read.add_argument("--json", action="store_true")

    mission = sub.add_parser(
        "mission", help="create or verify a supervised, passport-bound value mission"
    )
    mission_sub = mission.add_subparsers(dest="mission_cmd", required=True)
    mission_create = mission_sub.add_parser(
        "create", help="bind one value slice to a bounded mission"
    )
    mission_create.add_argument("slices")
    mission_create.add_argument("slice_id")
    mission_create.add_argument("--root", default=".")
    mission_create.add_argument("--owner", required=True)
    mission_create.add_argument(
        "--executor",
        default="manual",
        choices=sorted(_lazy_import("product_missions", "EXECUTORS")),
    )
    mission_create.add_argument("--max-iterations", type=int)
    mission_create.add_argument("--max-wall-seconds", type=int)
    mission_create.add_argument("--max-tokens", type=int)
    mission_create.add_argument("--max-cost-usd", type=float)
    mission_create.add_argument(
        "--readiness", help="verified migration readiness receipt to bind"
    )
    mission_create.add_argument(
        "--require-intake",
        action="store_true",
        help="require a verified intake confirmation bound to the Product Graph",
    )
    mission_create.add_argument("--force", action="store_true")
    mission_create.add_argument("--json", action="store_true")
    mission_verify = mission_sub.add_parser(
        "verify", help="verify mission, source, budget, and Loop Passport bindings"
    )
    mission_verify.add_argument("mission")
    mission_verify.add_argument("--json", action="store_true")
    mission_close = mission_sub.add_parser(
        "close", help="close only after independent exact-criteria verification"
    )
    mission_close.add_argument("mission")
    mission_close.add_argument("validation")
    mission_close.add_argument("--root", default=".")
    mission_close.add_argument("--force", action="store_true")
    mission_close.add_argument("--json", action="store_true")
    mission_completion = mission_sub.add_parser(
        "verify-completion", help="verify mission, validator, and evidence hashes"
    )
    mission_completion.add_argument("completion")
    mission_completion.add_argument("--json", action="store_true")
    mission_decide = mission_sub.add_parser(
        "decide", help="approve, defer, or reject bounded mission execution"
    )
    mission_decide.add_argument("mission")
    mission_decide.add_argument("--root", default=".")
    mission_decide.add_argument("--owner", required=True)
    mission_decide.add_argument(
        "--decision",
        required=True,
        choices=sorted(_lazy_import("product_missions", "MISSION_DECISIONS")),
    )
    mission_decide.add_argument("--rationale", required=True)
    mission_decide.add_argument("--force", action="store_true")
    mission_decide.add_argument("--json", action="store_true")
    mission_delta = mission_sub.add_parser(
        "proof-delta", help="bind new evidence before a supervised mission retry"
    )
    mission_delta_sub = mission_delta.add_subparsers(
        dest="mission_delta_cmd", required=True
    )
    mission_delta_create = mission_delta_sub.add_parser(
        "create",
        help="write one hash-bound retry admission or no-progress halt receipt",
    )
    mission_delta_create.add_argument("mission")
    mission_delta_create.add_argument("--root", default=".")
    mission_delta_create.add_argument("--prior-candidate", required=True)
    mission_delta_create.add_argument("--repair-candidate", required=True)
    mission_delta_create.add_argument("--failure", required=True)
    mission_delta_create.add_argument("--criterion", required=True)
    mission_delta_create.add_argument("--out", required=True)
    mission_delta_create.add_argument("--json", action="store_true")
    mission_delta_verify = mission_delta_sub.add_parser(
        "verify",
        help="verify one Proof-Delta receipt without admitting or running work",
    )
    mission_delta_verify.add_argument("receipt")
    mission_delta_verify.add_argument("--root", default=".")
    mission_delta_verify.add_argument("--json", action="store_true")
    mission_delta_status = mission_delta_sub.add_parser(
        "status", help="read the newest local Proof-Delta receipt"
    )
    mission_delta_status.add_argument("--root", default=".")
    mission_delta_status.add_argument("--mission-id")
    mission_delta_status.add_argument("--json", action="store_true")

    langgraph = sub.add_parser(
        "langgraph", help="operate receipt-governed durable mission graphs"
    )
    langgraph_sub = langgraph.add_subparsers(dest="langgraph_cmd", required=True)
    langgraph_doctor_parser = langgraph_sub.add_parser(
        "doctor", help="check optional LangGraph and SQLite checkpoint support"
    )
    langgraph_doctor_parser.add_argument("--json", action="store_true")
    for command, help_text in (
        ("init", "initialize or reopen a durable mission graph"),
        ("status", "show state, milestones, budget, and allowed events"),
        ("history", "show the verified ordered transition chain"),
        ("verify", "verify mission, event-chain, and receipt bindings"),
        ("export", "write a Mermaid mission graph with current state"),
    ):
        parser = langgraph_sub.add_parser(command, help=help_text)
        parser.add_argument("mission")
        parser.add_argument("--root", default=".")
        parser.add_argument("--json", action="store_true")
    langgraph_event = langgraph_sub.add_parser(
        "event", help="append one guarded, idempotent mission event"
    )
    langgraph_event.add_argument("mission")
    langgraph_event.add_argument("--root", default=".")
    langgraph_event.add_argument("--event", required=True)
    langgraph_event.add_argument("--actor", required=True)
    langgraph_event.add_argument(
        "--role", required=True, choices=["owner", "worker", "validator", "operator"]
    )
    langgraph_event.add_argument("--idempotency-key", required=True)
    langgraph_event.add_argument("--receipt", required=True)
    langgraph_event.add_argument("--payload", help="path to a secret-free JSON object")
    langgraph_event.add_argument("--json", action="store_true")
    langgraph_replay = langgraph_sub.add_parser(
        "replay-verify",
        help="compare recorded reference and resumed transitions without invoking a graph",
    )
    langgraph_replay.add_argument("--root", default=".")
    langgraph_replay.add_argument(
        "--reference",
        required=True,
        help="workspace-relative sealed reference lineage JSON",
    )
    langgraph_replay.add_argument(
        "--resumed",
        required=True,
        help="workspace-relative sealed resumed lineage JSON",
    )
    langgraph_replay.add_argument(
        "--out", help="optional workspace-relative assurance receipt JSON"
    )
    langgraph_replay.add_argument(
        "--mermaid",
        action="store_true",
        help="print only the parity or incident Mermaid map",
    )
    langgraph_replay.add_argument("--json", action="store_true")

    provider = sub.add_parser(
        "provider",
        help="configure secret-free BYOK references and deterministic routing rails",
    )
    provider_sub = provider.add_subparsers(dest="provider_cmd", required=True)
    provider_init = provider_sub.add_parser(
        "init", help="write a provider policy from a secret-free JSON config"
    )
    provider_init.add_argument("config")
    provider_init.add_argument("--root", default=".")
    provider_init.add_argument("--force", action="store_true")
    provider_init.add_argument("--json", action="store_true")
    provider_verify = provider_sub.add_parser(
        "verify", help="verify provider policy schema, rails, and hash"
    )
    provider_verify.add_argument("policy")
    provider_verify.add_argument("--json", action="store_true")
    provider_doctor_parser = provider_sub.add_parser(
        "doctor", help="show credential-reference presence without key values"
    )
    provider_doctor_parser.add_argument("policy")
    provider_doctor_parser.add_argument("--json", action="store_true")
    provider_route = provider_sub.add_parser(
        "route", help="select a provider/model under mission and IDE rails"
    )
    provider_route.add_argument("policy")
    provider_route.add_argument("mission")
    provider_route.add_argument("--root", default=".")
    provider_route.add_argument(
        "--ide",
        required=True,
        choices=sorted(_lazy_import("provider_router", "SUPPORTED_IDES")),
    )
    provider_route.add_argument(
        "--risk", required=True, choices=["low", "medium", "high"]
    )
    provider_route.add_argument("--preferred-provider")
    provider_route.add_argument("--preferred-model")
    provider_route.add_argument("--cache-provider")
    provider_route.add_argument("--cache-model")
    provider_route.add_argument("--projected-tokens", type=int, default=0)
    provider_route.add_argument("--projected-cost-usd", type=float)
    provider_route.add_argument("--latency-budget-ms", type=int, default=5000)
    provider_route.add_argument("--required-capability", action="append", default=[])
    provider_route.add_argument(
        "--privacy-class",
        choices=["standard", "restricted", "local_only"],
        default="standard",
    )
    provider_route.add_argument(
        "--output-contract", choices=["text", "json", "jsonl"], default="json"
    )
    provider_route.add_argument("--json", action="store_true")

    migration = sub.add_parser(
        "migration", help="prove agent readiness before a large migration mission"
    )
    migration_sub = migration.add_subparsers(dest="migration_cmd", required=True)
    migration_assess = migration_sub.add_parser(
        "assess", help="separate registered checks from executable readiness proof"
    )
    migration_assess.add_argument("manifest")
    migration_assess.add_argument("--root", default=".")
    migration_assess.add_argument("--force", action="store_true")
    migration_assess.add_argument("--json", action="store_true")
    migration_verify = migration_sub.add_parser(
        "verify", help="verify readiness and bound evidence hashes"
    )
    migration_verify.add_argument("receipt")
    migration_verify.add_argument("--json", action="store_true")

    context = sub.add_parser(
        "context", help="build compact tracked-fact AutoWiki and Lore artifacts"
    )
    context_sub = context.add_subparsers(dest="context_cmd", required=True)
    context_build = context_sub.add_parser(
        "build", help="generate AutoWiki and Lore from Git-tracked facts"
    )
    context_build.add_argument("--root", default=".")
    context_build.add_argument("--force", action="store_true")
    context_build.add_argument("--json", action="store_true")
    context_verify = context_sub.add_parser(
        "verify", help="verify AutoWiki and Lore hashes"
    )
    context_verify.add_argument("receipt")
    context_verify.add_argument("--json", action="store_true")

    from .cli_grill import add_parser as add_grill_parser

    add_grill_parser(sub)

    opinion = sub.add_parser(
        "opinion", help="maintain the owner-controlled architecture Opinion Dock"
    )
    opinion_sub = opinion.add_subparsers(dest="opinion_cmd", required=True)
    opinion_init = opinion_sub.add_parser(
        "init", help="create a compact default Opinion Dock"
    )
    opinion_init.add_argument("--root", default=".")
    opinion_init.add_argument("--owner", required=True)
    opinion_init.add_argument("--force", action="store_true")
    opinion_init.add_argument("--json", action="store_true")
    opinion_verify = opinion_sub.add_parser(
        "verify", help="verify the dock hash and 2,000-line budget"
    )
    opinion_verify.add_argument("dock")
    opinion_verify.add_argument("--json", action="store_true")
    opinion_correct = opinion_sub.add_parser(
        "correct", help="append one owner-authored, hash-linked rule correction"
    )
    opinion_correct.add_argument("dock")
    opinion_correct.add_argument("--owner", required=True)
    opinion_correct.add_argument("--rule-file", required=True)
    opinion_correct.add_argument("--rationale", required=True)
    opinion_correct.add_argument("--json", action="store_true")

    signal = sub.add_parser(
        "signal", help="capture and govern untrusted environmental signals locally"
    )
    signal_sub = signal.add_subparsers(dest="signal_cmd", required=True)
    signal_capture = signal_sub.add_parser(
        "capture",
        help="normalize one owner-supplied signal without polling or execution",
    )
    signal_capture.add_argument("--root", default=".")
    signal_capture.add_argument(
        "--source",
        required=True,
        choices=sorted(_lazy_import("signal_loop", "SOURCES")),
    )
    signal_capture.add_argument("--title", required=True)
    signal_capture_body = signal_capture.add_mutually_exclusive_group(required=True)
    signal_capture_body.add_argument("--body")
    signal_capture_body.add_argument("--body-file")
    signal_capture.add_argument(
        "--authorization",
        required=True,
        choices=sorted(_lazy_import("signal_loop", "AUTHORIZATIONS")),
    )
    signal_capture.add_argument("--severity", type=int, default=3)
    signal_capture.add_argument("--external-id")
    signal_capture.add_argument("--url")
    signal_capture.add_argument("--observed-at")
    signal_capture.add_argument("--hypothesis", action="append", default=[])
    signal_capture.add_argument("--requirement", action="append", default=[])
    signal_capture.add_argument("--outcome", action="append", default=[])
    signal_capture.add_argument("--acceptance", action="append", default=[])
    signal_capture.add_argument("--json", action="store_true")
    signal_triage = signal_sub.add_parser(
        "triage", help="score a signal against explicit Opinion Dock rules"
    )
    signal_triage.add_argument("signal")
    signal_triage.add_argument("dock")
    signal_triage.add_argument("--root", default=".")
    signal_triage.add_argument("--force", action="store_true")
    signal_triage.add_argument("--json", action="store_true")
    signal_decide = signal_sub.add_parser(
        "decide", help="record the Product Owner decision for one triage receipt"
    )
    signal_decide.add_argument("triage")
    signal_decide.add_argument("--root", default=".")
    signal_decide.add_argument("--owner", required=True)
    signal_decide.add_argument(
        "--decision",
        required=True,
        choices=sorted(_lazy_import("signal_loop", "DECISIONS")),
    )
    signal_decide.add_argument("--rationale", required=True)
    signal_decide.add_argument("--override-block", action="store_true")
    signal_decide.add_argument("--force", action="store_true")
    signal_decide.add_argument("--json", action="store_true")
    signal_promote = signal_sub.add_parser(
        "promote",
        help="promote an approved signal to a Product Graph or needs-input draft",
    )
    signal_promote.add_argument("decision")
    signal_promote.add_argument("--root", default=".")
    signal_promote.add_argument("--project")
    signal_promote.add_argument("--force", action="store_true")
    signal_promote.add_argument("--json", action="store_true")
    signal_feedback = signal_sub.add_parser(
        "feedback",
        help="turn measured outcome evidence into a new local telemetry signal",
    )
    signal_feedback.add_argument("--root", default=".")
    signal_feedback.add_argument("--mission-id", required=True)
    signal_feedback.add_argument("--metric", required=True)
    signal_feedback.add_argument("--observed", type=float, required=True)
    signal_feedback.add_argument("--target", type=float, required=True)
    signal_feedback.add_argument("--evidence", required=True)
    signal_feedback.add_argument("--json", action="store_true")

    learning = sub.add_parser(
        "learning",
        help="refine task-specific worker instructions through independent proof",
    )
    learning_sub = learning.add_subparsers(dest="learning_cmd", required=True)
    learning_init = learning_sub.add_parser(
        "init", help="bind a task objective and ordered milestone gates"
    )
    learning_init.add_argument("task_id")
    learning_init.add_argument("--root", default=".")
    learning_init.add_argument("--owner", required=True)
    learning_init.add_argument("--objective", required=True)
    learning_init.add_argument(
        "--milestones", required=True, help="JSON file containing milestone objects"
    )
    learning_init.add_argument("--force", action="store_true")
    learning_init.add_argument("--json", action="store_true")
    learning_packet = learning_sub.add_parser(
        "packet", help="create a fresh worker context from promoted instructions only"
    )
    learning_packet.add_argument("task")
    learning_packet.add_argument("--milestone", required=True)
    learning_packet.add_argument("--worker", required=True)
    learning_packet.add_argument("--force", action="store_true")
    learning_packet.add_argument("--json", action="store_true")
    learning_propose = learning_sub.add_parser(
        "propose", help="bind an outcome to an untrusted instruction candidate"
    )
    learning_propose.add_argument("task")
    learning_propose.add_argument("--root", default=".")
    learning_propose.add_argument("--milestone", required=True)
    learning_propose.add_argument("--worker", required=True)
    learning_propose.add_argument("--outcome", required=True)
    learning_propose.add_argument(
        "--instructions",
        required=True,
        help="JSON file containing a dimensioned instruction-edit array",
    )
    learning_propose.add_argument("--force", action="store_true")
    learning_propose.add_argument("--json", action="store_true")
    learning_validate = learning_sub.add_parser(
        "validate", help="independently validate every milestone criterion"
    )
    learning_validate.add_argument("candidate")
    learning_validate.add_argument("--root", default=".")
    learning_validate.add_argument("--validator", required=True)
    learning_validate.add_argument(
        "--results",
        required=True,
        help="JSON file containing criterion results and evidence",
    )
    learning_validate.add_argument("--force", action="store_true")
    learning_validate.add_argument("--json", action="store_true")
    learning_promote = learning_sub.add_parser(
        "promote",
        help="activate a validated instruction candidate under owner authority",
    )
    learning_promote.add_argument("validation")
    learning_promote.add_argument("--owner", required=True)
    learning_promote.add_argument("--force", action="store_true")
    learning_promote.add_argument("--json", action="store_true")
    learning_experiment = learning_sub.add_parser(
        "experiment",
        help="write a bounded correctness-first ASHA, Hyperband, or BOHB plan",
    )
    learning_experiment.add_argument("task")
    learning_experiment.add_argument(
        "--space", required=True, help="JSON d1-d6 search-space mapping"
    )
    learning_experiment.add_argument(
        "--variant", choices=["asha", "hyperband", "bohb"], default="asha"
    )
    learning_experiment.add_argument("--max-resource", type=int, default=50)
    learning_experiment.add_argument("--grace-period", type=int, default=5)
    learning_experiment.add_argument("--reduction-factor", type=int, default=3)
    learning_experiment.add_argument("--max-concurrent", type=int, default=4)
    learning_experiment.add_argument("--samples", type=int, default=20)
    learning_experiment.add_argument("--force", action="store_true")
    learning_experiment.add_argument("--json", action="store_true")

    pr = sub.add_parser(
        "pr", help="prepare local reviewer artifacts without merge authority"
    )
    pr_sub = pr.add_subparsers(dest="pr_cmd", required=True)
    pr_draft = pr_sub.add_parser(
        "draft", help="write an evidence-linked PR draft packet"
    )
    pr_draft.add_argument("mission")
    pr_draft.add_argument("--root", default=".")
    pr_draft.add_argument("--evidence", action="append", default=[])
    pr_draft.add_argument("--force", action="store_true")
    pr_draft.add_argument("--json", action="store_true")

    outcome = sub.add_parser(
        "outcome", help="record and summarize hash-linked product outcome evidence"
    )
    outcome_sub = outcome.add_subparsers(dest="outcome_cmd", required=True)
    outcome_record = outcome_sub.add_parser(
        "record", help="append one classified outcome observation"
    )
    outcome_record.add_argument("mission")
    outcome_record.add_argument("--root", default=".")
    outcome_record.add_argument("--metric", required=True)
    outcome_record.add_argument("--value", type=float)
    outcome_record.add_argument("--target", type=float)
    outcome_record.add_argument(
        "--evidence-class",
        required=True,
        choices=sorted(_lazy_import("product_missions", "EVIDENCE_CLASSES")),
    )
    outcome_record.add_argument("--source")
    outcome_record.add_argument("--notes", default="")
    outcome_record.add_argument("--json", action="store_true")
    outcome_summary_parser = outcome_sub.add_parser(
        "summary", help="verify and summarize local outcome chains"
    )
    outcome_summary_parser.add_argument("--root", default=".")
    outcome_summary_parser.add_argument("--mission-id")
    outcome_summary_parser.add_argument("--json", action="store_true")

    version = sub.add_parser("version", help="show package provenance")
    version.add_argument("--json", action="store_true")
    return p


_UNHANDLED = object()


def _dispatch_routes(a, capture_command, p):
    for handler in (
        _dispatch_route_group_01,
        _dispatch_route_group_02,
        _dispatch_route_group_03,
        _dispatch_route_group_04,
        _dispatch_route_group_05,
        _dispatch_route_group_06,
        _dispatch_route_group_07,
        _dispatch_route_group_08,
        _dispatch_route_group_09,
        _dispatch_route_group_10,
        _dispatch_route_group_11,
        _dispatch_route_group_12,
        _dispatch_route_group_13,
        _dispatch_route_group_14,
        _dispatch_route_group_15,
        _dispatch_route_group_16,
        _dispatch_route_group_17,
        _dispatch_route_group_18,
        _dispatch_route_group_19,
        _dispatch_route_group_20,
        _dispatch_route_group_21,
        _dispatch_route_group_22,
        _dispatch_route_group_23,
        _dispatch_route_group_24,
        _dispatch_route_group_25,
        _dispatch_route_group_26,
        _dispatch_route_group_27,
        _dispatch_route_group_28,
        _dispatch_route_group_29,
        _dispatch_route_group_30,
        _dispatch_route_group_31,
        _dispatch_route_group_32,
        _dispatch_route_group_33,
        _dispatch_route_group_34,
        _dispatch_route_group_35,
        _dispatch_route_group_36,
        _dispatch_route_group_37,
        _dispatch_route_group_38,
        _dispatch_route_group_39,
        _dispatch_route_group_40,
        _dispatch_route_group_41,
        _dispatch_route_group_42,
    ):
        result = handler(a, capture_command, p)
        if result is not _UNHANDLED:
            return result
    return _UNHANDLED


def _dispatch_route_group_01(a, capture_command, p):
    if a.cmd == "ops":
        from .cli_ops import run as run_ops

        return run_ops(a)

    if a.cmd is None:
        return _home()
    if a.cmd == "version":
        return _emit_version(a.json)
    if a.cmd == "blueprint":
        return __import__("factoryline.cli_blueprint", fromlist=["run"]).run(a)
    if a.cmd == "update":
        return __import__("factoryline.cli_update", fromlist=["run"]).run(a)
    if a.cmd == "home":
        return _home(Path(a.root), a.json)
    if a.cmd == "doctor":
        return _doctor(a.strict, a.json)
    if a.cmd in {"architecture", "external", "journey", "efficiency"}:
        from .cli_foundations import run as run_foundation

        return run_foundation(a)
    if a.cmd == "grill":
        from .cli_grill import run as run_grill

        return run_grill(a)
    return _UNHANDLED


def _dispatch_route_group_02(a, capture_command, p):
    if a.cmd == "verifier":
        from .cli_verifier import run as run_verifier

        return run_verifier(a)
    if a.cmd == "telemetry":
        from .cli_telemetry import run as run_telemetry

        return run_telemetry(a)
    return _UNHANDLED


def _dispatch_route_group_03(a, capture_command, p):
    if a.cmd in {
        "prd",
        "intake",
        "product",
        "mission",
        "pr",
        "outcome",
        "opinion",
        "signal",
        "learning",
        "migration",
        "context",
        "langgraph",
        "provider",
        "agent",
    }:
        from .cli_domain import _UNHANDLED as domain_unhandled
        from .cli_domain import run_workflow_family

        result = run_workflow_family(a)
        return _UNHANDLED if result is domain_unhandled else result
    return _UNHANDLED


def _dispatch_route_group_04(a, capture_command, p):
    if a.cmd in {"targets", "create", "mvp"}:
        from .cli_targets import run as run_targets

        return run_targets(a)
    if a.cmd in {"admission", "e2e", "reality"}:
        from .cli_runtime_proof import run as run_runtime_proof

        return run_runtime_proof(a)
    if a.cmd in {"proof-continuity", "oracle", "semantic-authority"}:
        from .cli_authority import run as run_authority

        return run_authority(a)
    return _UNHANDLED


def _atomic_action(a, root: Path) -> dict:
    if a.atomic_cmd == "import":
        return _lazy_import("atomic_proof_adapter", "import_atomic_run")(
            root, Path(a.envelope), Path(a.out) if a.out else None
        )
    if a.atomic_cmd == "verify":
        return _lazy_import("atomic_proof_adapter", "verify_atomic_receipt")(
            root, Path(a.receipt)
        )
    if a.atomic_cmd == "template":
        return _lazy_import("atomic_proof_adapter", "atomic_envelope_template")()
    return _lazy_import("atomic_proof_adapter", "atomic_proof_projection")(root)


def _atomic_exit_code(result: dict) -> int:
    valid = result.get("ok", True) and int(result.get("invalid_count", 0)) == 0
    return 0 if valid else 1


def _atomic_error(exc: Exception) -> tuple[dict, int]:
    return {
        "schema": "factory.atomic-proof-adapter.error.v1",
        "marker": "ATOMIC_INPUT_REJECTED",
        "code": getattr(exc, "code", "E_ATOMIC_ENVELOPE_SCHEMA"),
        "message": str(exc),
    }, 2


def _emit_atomic_result(a, result: dict, code: int) -> None:
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            json.dumps(result, indent=2, sort_keys=True),
            file=sys.stderr if code else sys.stdout,
        )


def _dispatch_route_group_05(a, capture_command, p):
    if a.cmd == "atomic":
        root = Path(getattr(a, "root", ".")).resolve()
        try:
            result = _atomic_action(a, root)
            code = _atomic_exit_code(result)
        except (
            _lazy_import("atomic_proof_adapter", "AtomicProofAdapterError"),
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            result, code = _atomic_error(exc)
        _emit_atomic_result(a, result, code)
        return code
    return _UNHANDLED


def _agent_bridge_action(a, root: Path) -> dict:
    if a.agent_bridge_cmd == "import":
        return _lazy_import("agent_proof_bridge", "import_agent_proof")(
            root, Path(a.envelope), Path(a.out) if a.out else None
        )
    if a.agent_bridge_cmd == "verify":
        return _lazy_import("agent_proof_bridge", "verify_agent_proof")(
            root, Path(a.receipt)
        )
    if a.agent_bridge_cmd == "template":
        return _lazy_import("agent_proof_bridge", "provider_template")(a.provider)
    if a.agent_bridge_cmd == "mission":
        return _lazy_import("agent_proof_bridge", "agent_handoff_brief")(
            root, Path(a.contract)
        )
    return _lazy_import("agent_proof_bridge", "agent_proof_projection")(root)


def _agent_bridge_error(exc: Exception) -> tuple[dict, int]:
    return {
        "schema": "factory.agent-proof-bridge.error.v1",
        "marker": "AGENT_PROOF_INPUT_REJECTED",
        "code": getattr(exc, "code", "E_AGENT_BRIDGE_SCHEMA"),
        "message": str(exc),
    }, 2


def _emit_agent_bridge_result(result: dict, code: int) -> None:
    print(
        json.dumps(result, indent=2, sort_keys=True),
        file=sys.stderr if code else sys.stdout,
    )


def _dispatch_route_group_06(a, capture_command, p):
    if a.cmd == "agent-bridge":
        root = Path(getattr(a, "root", ".")).resolve()
        try:
            result = _agent_bridge_action(a, root)
            code = _atomic_exit_code(result)
        except (
            _lazy_import("agent_proof_bridge", "AgentProofBridgeError"),
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            result, code = _agent_bridge_error(exc)
        _emit_agent_bridge_result(result, code)
        return code
    return _UNHANDLED


def _dispatch_route_group_07(a, capture_command, p):
    if a.cmd in {
        "operations-control",
        "lifecycle",
        "service-boundary",
        "repair-loop",
        "repo-coordinate",
    }:
        from .cli_coordination import run as run_coordination

        return run_coordination(a)
    if a.cmd in {"ontology", "mission-control"}:
        from .cli_domain import run as run_domain

        return run_domain(a)
    if a.cmd in {"deep-audit", "runtime-audit", "senior"}:
        from .cli_deep_audit import run as run_deep_audit

        return run_deep_audit(a)
    if a.cmd in {"worklog", "proofsearch"}:
        from .cli_proofsearch import run as run_proofsearch

        return run_proofsearch(a)
    if a.cmd == "pack":
        from .cli_pack import run as run_pack

        return run_pack(a)
    if a.cmd == "studio":
        from .cli_studio import run as run_studio

        return run_studio(a)
    if a.cmd == "audit":
        from .cli_audit import run as run_audit

        return run_audit(a)
    # Kept unreachable for one release so old tracebacks retain their source
    # shape while the bounded command module becomes the only audit dispatch.

    if a.cmd == "evidence-audit":
        from .cli_quality import run_evidence

        return run_evidence(a)

    if a.cmd == "quality-harness":
        from .cli_quality import run_quality

        return run_quality(a)
    return _UNHANDLED


def _dispatch_route_group_08(a, capture_command, p):
    if a.cmd == "guide":
        try:
            result = _lazy_import("ide_playbook", "adoption_guide")(a.journey)
        except _lazy_import("ide_playbook", "AdoptionGuideError") as exc:
            error = {
                "schema": "factory.adoption-guide.error.v1",
                "code": exc.code,
                "message": str(exc),
                "supported": ["solo", "team", "enterprise"],
                "actions_executed": False,
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if a.json
                else f"guide failed: {exc.code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("Code Factory guide")
            print("=" * 44)
            if a.journey is None:
                print("Recommended: solo")
            for item in result["journeys"]:
                primary = "  [start here]" if item["primary"] else ""
                print(f"\n{item['label']}{primary}")
                print(f"Question : {item['question']}")
                print(f"Start    : {item['first_command']}")
                print(f"Evidence : {item['expected_local_evidence']}")
                print(f"Next     : {item['next_safe_action']}")
                print(f"Control  : {item['authority_boundary']}")
            print(
                "\nAdvanced modules stay hidden until their trigger applies. No action was executed."
            )
        return 0
    if a.cmd == "first-lap":
        from .cli_first_lap import run as run_first_lap

        return run_first_lap(a)
    return _UNHANDLED


def _dispatch_route_group_09(a, capture_command, p):
    if a.cmd == "agui":
        workspace = Path(a.root).resolve()
        try:
            status = _lazy_import("first_lap", "first_lap_status")(workspace)
            result = {
                "schema": "factory.agui.events.v1",
                "marker": "AGUI_REVIEW_EVENTS_READY",
                "events": _lazy_import("agui", "build_review_events")(
                    status, run_id=a.run_id, surface=a.surface
                ),
                "scope": "Controlled/declarative review events only; no agent, execution, approval, provider, credential, or transport action ran.",
            }
            code = 0
        except (
            _lazy_import("first_lap", "FirstLapError"),
            _lazy_import("agui", "AguiError"),
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            result = {
                "schema": "factory.agui.error.v1",
                "marker": "AGUI_REVIEW_EVENTS_BLOCKED",
                "code": getattr(exc, "code", "E_AGUI_INPUT"),
                "message": str(exc),
                "authority": "none",
            }
            code = 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        elif code == 0:
            print(f"AGUI review events: {len(result['events'])} controlled events")
            print(
                "authority: read-only review cards and human interrupts; no execution or release authority"
            )
        else:
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
        return code
    if a.cmd == "first-proof":
        workspace = Path(a.root).resolve()
        out_dir = Path(a.out_dir) if a.out_dir else None
        try:
            result = _lazy_import("adoption", "run_first_proof")(
                workspace, out_dir=out_dir
            )
        except (
            _lazy_import("adoption", "AdoptionError"),
            _lazy_import("e2e_proof", "E2EProofError"),
            OSError,
        ) as exc:
            code = getattr(exc, "code", "E_FIRST_PROOF_FAILED")
            error = {
                "schema": "factory.first-proof.error.v1",
                "code": code,
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if a.json
                else f"first proof failed: {code}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("factory first-proof")
            print("=" * 44)
            print("result   : HOLLOW_TEST_DETECTED")
            print(
                "meaning  : the sandbox negative check also passed, so the test could not say no"
            )
            print(f"receipt  : {result['activation_path']}")
            print(f"share    : {result['proof_card']['paths']['svg']}")
            print(
                "boundary : demo only; your project was not assessed and nothing was uploaded"
            )
        return 0
    return _UNHANDLED


def _dispatch_route_group_10(a, capture_command, p):
    if a.cmd in {"proof-card", "adoption", "counterexample", "guardrail", "resilience"}:
        from .cli_review_surfaces import run as run_review_surface

        return run_review_surface(a)
    if a.cmd in {"license", "combine"}:
        from .cli_governance_surfaces import run as run_governance_surface

        return run_governance_surface(a)
    if a.cmd == "wrap":
        from .cli_wrap import run as run_wrap

        return run_wrap(a)
    return _UNHANDLED


def _gauntlet_workspace_path(workspace: Path, value: str | None) -> Path | None:
    if value is None:
        return None
    candidate = Path(value)
    return candidate if candidate.is_absolute() else workspace / candidate


def _gauntlet_card_action(a) -> tuple[dict, int]:
    if a.gauntlet_card_cmd == "verify":
        payload = _lazy_import("gauntlet", "verify_survival_card")(
            Path(a.card),
            envelope_path=Path(a.envelope) if a.envelope else None,
            trust_root_path=Path(a.trust_root) if a.trust_root else None,
        )
        return payload, 0
    if a.gauntlet_card_cmd == "challenge":
        payload = _lazy_import("gauntlet", "challenge_survival_card")(Path(a.card))
        return payload, 0 if payload["ok"] else 1
    payload = _lazy_import("gauntlet", "seal_survival_card")(
        Path(a.card),
        private_key_path=Path(a.private_key),
        keyid=a.keyid,
        identity=a.identity,
        issuer=a.issuer,
        tenant_id=a.tenant,
        out=Path(a.out),
    )
    return payload, 0


def _gauntlet_action(a, workspace: Path) -> tuple[dict, int]:
    if a.gauntlet_cmd == "draft":
        payload = _lazy_import("gauntlet_draft", "draft_gauntlet")(
            workspace, a.source_id
        )
        return payload, 0
    if a.gauntlet_cmd == "plan":
        proposal = _lazy_import("gauntlet", "compile_gauntlet_proposal")(
            workspace, _gauntlet_workspace_path(workspace, a.source)
        )
        written = _lazy_import("gauntlet", "write_gauntlet_proposal")(
            workspace, proposal, _gauntlet_workspace_path(workspace, a.out)
        )
        return {"proposal": proposal, "path": str(written)}, 0
    if a.gauntlet_cmd == "admit":
        payload = _lazy_import("gauntlet", "admit_gauntlet")(
            workspace,
            _gauntlet_workspace_path(workspace, a.proposal),
            approved_by=a.approved_by,
            rationale=a.rationale,
            confirmation=a.confirmation,
            valid_for_minutes=a.valid_for_minutes,
            out=_gauntlet_workspace_path(workspace, a.out),
        )
        return payload, 0
    if a.gauntlet_cmd == "run":
        payload = _lazy_import("gauntlet", "run_gauntlet")(
            workspace,
            _gauntlet_workspace_path(workspace, a.proposal),
            _gauntlet_workspace_path(workspace, a.admission),
            _gauntlet_workspace_path(workspace, a.out),
        )
        return payload, 0 if payload["card"]["ok"] else 1
    if a.gauntlet_cmd == "status":
        payload = _lazy_import("gauntlet", "gauntlet_status")(workspace, a.source_id)
        return payload, 0
    return _gauntlet_card_action(a)


def _gauntlet_error(a, exc: Exception) -> int:
    error = {
        "schema": "factory.gauntlet.error.v1",
        "marker": exc.code,
        "code": exc.code,
        "message": str(exc),
    }
    print(
        json.dumps(error, indent=2, sort_keys=True)
        if getattr(a, "json", False)
        else f"gauntlet failed: {exc.code}: {exc}",
        file=sys.stderr,
    )
    return 2


def _gauntlet_text(a, payload: dict) -> None:
    print("factory gauntlet")
    print("=" * 44)
    if a.gauntlet_cmd == "draft":
        print(f"draft    : {payload['path']}")
        print(f"promises : {payload['draft']['facts']['cli_entrypoint_count']}")
        print(
            "authority: static DRAFT only; no command execution, approval, admission, repair, or release"
        )
        return
    if a.gauntlet_cmd == "run":
        card = payload["card"]
        print(f"result   : {card['marker']}")
        print(
            f"survived : {card['summary']['survived_count']}/{card['summary']['case_count']}"
        )
        print(f"unproven : {card['summary']['unproven_promise_count']}")
        print(
            "authority: exact admitted local E2E execution only; no repair, merge, release, deployment, signing, credentials, or connectors"
        )
        print(f"card     : {payload['path']}")
        return
    if a.gauntlet_cmd == "plan":
        print(f"proposal : {payload['path']}")
        print("authority: planning only; no command execution or admission")
        return
    if a.gauntlet_cmd == "admit":
        print(f"admission: {payload['path']}")
        print(f"expires  : {payload['expires_at']}")
        print("authority: named one-batch admission only; no command executed")
        return
    if a.gauntlet_cmd == "status":
        print(f"cards    : {len(payload['entries'])}")
        print("authority: local read-only status")
        return
    print(f"marker   : {payload['marker']}")
    print("authority: offline card validation or explicit optional signing only")


def _gauntlet_output(a, payload: dict) -> None:
    if getattr(a, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _gauntlet_text(a, payload)


def _dispatch_route_group_11(a, capture_command, p):
    if a.cmd != "gauntlet":
        return _UNHANDLED
    workspace = Path(getattr(a, "root", ".")).resolve()
    try:
        payload, code = _gauntlet_action(a, workspace)
    except (
        _lazy_import("gauntlet", "GauntletError"),
        _lazy_import("gauntlet_draft", "GauntletDraftError"),
    ) as exc:
        return _gauntlet_error(a, exc)
    _gauntlet_output(a, payload)
    return code


def _team_pilot_verify(a) -> int:
    receipt = json.loads(Path(a.receipt).read_text(encoding="utf-8"))
    result = _lazy_import("team_pilot", "validate_team_pilot_receipt")(receipt)
    if a.json:
        print(json.dumps({"receipt": result}, indent=2, sort_keys=True))
    else:
        print("factory team-pilot verify")
        print("=" * 44)
        print(f"pilot    : {result['manifest']['pilot_id']}")
        print(f"result   : {result['marker']}")
        print(
            "authority: owner review only; no contract, payment, entitlement, Marketplace, deployment, or service activation"
        )
    return 0


def _team_pilot_readiness(a) -> tuple[dict, dict | None]:
    workspace = Path(a.root).resolve()
    manifest = Path(a.manifest)
    if not manifest.is_absolute():
        manifest = workspace / manifest
    receipt = _lazy_import("team_pilot", "evaluate_team_pilot_readiness")(
        workspace, manifest
    )
    artifacts = (
        _lazy_import("team_pilot", "write_team_pilot_artifacts")(
            receipt, Path(a.out_dir)
        )
        if a.out_dir
        else None
    )
    return receipt, artifacts


def _team_pilot_error(a, exc: Exception) -> int:
    error_type = _lazy_import("team_pilot", "TeamPilotError")
    code = exc.code if isinstance(exc, error_type) else "E_TEAM_PILOT_RECEIPT_INVALID"
    error = {
        "schema": "factory.team-pilot.error.v1",
        "marker": code,
        "code": code,
        "message": str(exc),
    }
    print(
        json.dumps(error, indent=2, sort_keys=True)
        if a.json
        else f"team pilot failed: {code}: {exc}",
        file=sys.stderr,
    )
    return 2


def _team_pilot_output(a, receipt: dict, artifacts: dict | None) -> None:
    if a.json:
        output = {"receipt": receipt}
        if artifacts:
            output["artifacts"] = artifacts
        print(json.dumps(output, indent=2, sort_keys=True))
        return
    print("factory team-pilot readiness")
    print("=" * 44)
    print(f"pilot    : {receipt['manifest']['pilot_id']}")
    print(f"partners : {receipt['manifest']['partner_count']} / 3")
    print(f"result   : {receipt['marker']}")
    print(
        "authority: owner review only; no contract, payment, entitlement, Marketplace, deployment, or service activation"
    )
    if artifacts:
        print(f"packet   : {artifacts['paths']['markdown']}")


def _dispatch_route_group_12(a, capture_command, p):
    if a.cmd != "team-pilot":
        return _UNHANDLED
    try:
        if a.team_pilot_cmd == "verify":
            return _team_pilot_verify(a)
        receipt, artifacts = _team_pilot_readiness(a)
    except (
        _lazy_import("team_pilot", "TeamPilotError"),
        UnicodeDecodeError,
        json.JSONDecodeError,
        OSError,
    ) as exc:
        return _team_pilot_error(a, exc)
    _team_pilot_output(a, receipt, artifacts)
    return 0


def _dispatch_route_group_13(a, capture_command, p):
    if a.cmd == "plan":
        if a.plan_cmd is None:
            return _plan()
        try:
            review = _lazy_import("plan_proof_review", "review_plan_proof")(
                Path(a.root),
                Path(a.plan),
                base=a.base,
                changed=a.changed or None,
            )
            if a.out_dir:
                review["artifacts"] = _lazy_import(
                    "plan_proof_review", "write_plan_proof_review_artifacts"
                )(review, Path(a.out_dir))
        except (
            _lazy_import("change_review", "ChangeReviewError"),
            _lazy_import("plan_proof_review", "PlanProofReviewError"),
        ) as exc:
            error = {
                "schema": "factory.plan_proof_review.error.v1",
                "marker": getattr(exc, "code", "PLAN_TO_PROOF_PLAN_INVALID"),
                "code": getattr(exc, "code", "PLAN_TO_PROOF_PLAN_INVALID"),
                "message": str(exc),
            }
            print(
                json.dumps(error, indent=2, sort_keys=True)
                if a.json
                else f"plan proof review failed: {error['code']}: {exc}",
                file=sys.stderr,
            )
            return 2
        if a.json:
            print(json.dumps(review, indent=2, sort_keys=True))
        else:
            print("factory plan verify (analysis only)")
            print("=" * 44)
            print(
                f"plan         : {review['plan']['provider']}/{review['plan']['plan_id']}"
            )
            print(f"changed paths: {len(review['changed_paths'])}")
            print(
                f"proof debt   : {review['proof_debt']['count']} ({review['proof_debt']['state']})"
            )
            print(f"next action  : {review['next_action']['action']}")
            if review.get("artifacts"):
                print(f"packet       : {review['artifacts']['paths']['markdown']}")
            print(
                "authority    : no execution, approval, merge, publication, deployment, or credential access"
            )
        return 0
    return _UNHANDLED


def _dispatch_route_group_14(a, capture_command, p):
    if a.cmd == "init":
        _lazy_import("contract", "ensure_layout")(Path(a.root))
        print(f"factory layout created under {Path(a.root).resolve()}")
        for sub_name in _lazy_import("contract", "LAYOUT").values():
            print(f"  {sub_name}/")
        return 0
    return _UNHANDLED


def _release_oracle_binding(a, workspace: Path) -> tuple[Path, str]:
    oracle_path = Path(a.oracle_contract)
    if not oracle_path.is_absolute():
        oracle_path = workspace / oracle_path
    oracle_path = oracle_path.resolve()
    oracle_path.relative_to(workspace)
    oracle = json.loads(oracle_path.read_text(encoding="utf-8-sig"))
    digest = oracle.get("contract_sha256") if isinstance(oracle, dict) else None
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError(
            "sealed Oracle contract must expose a 64-character contract_sha256"
        )
    return oracle_path, digest


def _release_stages(a) -> list[str]:
    defaults = [
        "specline:strict",
        "specline:verify-validators",
        "specline:gate-spec",
        "specline:tasks",
        "specline:gate-plan",
        "forgeline:architect",
        "forgeline:review",
        "forgeline:arch-gate",
        "forgeline:verify-tests",
        "forgeline:smoke",
        "forgeline:ship",
    ]
    return list(a.stages or defaults)


def _release_evidence(items: list[str]) -> dict[str, str]:
    evidence = {}
    for item in items:
        if "=" not in item:
            raise ValueError("--evidence must use STAGE=PATH")
        key, value = item.split("=", 1)
        evidence[key] = value
    return evidence


def _release_source(workspace: Path) -> tuple[dict, dict]:
    source = _lazy_import("release_candidate", "source_snapshot")(workspace)
    if not source.get("ok"):
        raise ValueError(
            str(source.get("reason", "core source binding is unavailable"))
        )
    versions = {
        key: value
        for key, value in source.get(
            "platform_versions", {"python": source["version"]}
        ).items()
        if isinstance(value, str) and value
    }
    return source, versions


def _release_contract_core(a, workspace: Path) -> dict:
    oracle_path, oracle_sha = _release_oracle_binding(a, workspace)
    source, versions = _release_source(workspace)
    core = {
        "schema": _lazy_import("release_contract", "SCHEMA"),
        "feature": a.feature,
        "oracle_contract": oracle_path.relative_to(workspace).as_posix(),
        "oracle_contract_sha256": oracle_sha,
        "required_stages": _release_stages(a),
        "approved_by": a.approved_by.strip(),
        "candidate": {
            "source_version": source["version"],
            "source_commit": source["commit"],
            "artifact_versions": versions,
        },
    }
    evidence = _release_evidence(a.evidence)
    if evidence:
        core["evidence"] = evidence
    return core


def _write_release_contract(a, workspace: Path, core: dict) -> dict:
    payload = {
        **core,
        "policy_digest": _lazy_import("release_contract", "_sha")(core),
    }
    destination = Path(a.out)
    if not destination.is_absolute():
        destination = workspace / destination
    destination = destination.resolve()
    destination.relative_to(workspace)
    if destination.exists():
        raise ValueError("release contract output already exists; choose a new path")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "ok": True,
        "marker": "RELEASE_CONTRACT_TEMPLATE_WRITTEN",
        "path": destination.relative_to(workspace).as_posix(),
        "policy_digest": payload["policy_digest"],
        "claim_boundary": "Template generation only; it does not approve, execute, publish, deploy, sign, or authenticate an approver.",
    }


def _verify_release_contract(a, workspace: Path) -> dict:
    contract_path = Path(a.contract)
    if not contract_path.is_absolute():
        contract_path = workspace / contract_path
    value = json.loads(contract_path.read_text(encoding="utf-8-sig"))
    required = (
        set(value.get("required_stages", [])) if isinstance(value, dict) else set()
    )
    return _lazy_import("release_contract", "verify_release_contract")(
        workspace, a.feature, contract_path, required
    )


def _release_contract_result(a, workspace: Path) -> dict:
    if a.release_contract_cmd == "template":
        core = _release_contract_core(a, workspace)
        return _write_release_contract(a, workspace, core)
    return _verify_release_contract(a, workspace)


def _print_release_contract(a, result: dict) -> None:
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    suffix = f" ({result.get('reason')})" if result.get("reason") else ""
    print(f"release contract: {result.get('marker')}{suffix}")


def _dispatch_route_group_15(a, capture_command, p):
    if a.cmd != "release-contract":
        return _UNHANDLED
    workspace = Path(a.root).resolve()
    try:
        result = _release_contract_result(a, workspace)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        result = {
            "ok": False,
            "marker": "RELEASE_CONTRACT_INVALID",
            "reason": str(exc)[:240],
        }
    _print_release_contract(a, result)
    return 0 if result.get("ok") else 1


def _dispatch_route_group_16(a, capture_command, p):
    if a.cmd == "assemble":
        report = _lazy_import("assembly", "assemble")(
            Path(a.root),
            a.feature,
            dry_run=a.dry_run,
            release_contract_path=Path(a.release_contract)
            if a.release_contract
            else None,
        )
        print(json.dumps(report, indent=2))
        return 0 if "halted_at" not in report else 1
    return _UNHANDLED


def _continuation_error(a, exc: Exception) -> int:
    code = getattr(exc, "code", "CONTINUATION_INPUT_INVALID")
    payload = {
        "schema": "factory.assembly-continuation.error.v1",
        "code": code,
        "message": str(exc),
    }
    error_type = _lazy_import("continuation", "ContinuationError")
    if isinstance(exc, error_type):
        payload["candidates"] = exc.candidates
    print(
        json.dumps(payload, indent=2) if a.json else f"continue failed: {code}: {exc}",
        file=sys.stderr,
    )
    return 2


def _print_continuation_report(a, report: dict) -> None:
    if a.json:
        print(json.dumps(report, indent=2))
        return
    print("factory continuation")
    print(f"feature : {report['feature']}")
    print(f"status  : {report['status']}")
    print(f"stages  : {len(report['stages'])}")
    action = report.get("next_action")
    if action:
        print(f"next    : {action['label']}")
        if action.get("command"):
            print(f"command : {action['command']}")
    if report.get("receipt"):
        print(f"receipt : {report['receipt']}")


def _continuation_exit_code(report: dict) -> int:
    if report["status"] == "waiting_for_human":
        return 3
    return 1 if report["status"] == "halted" else 0


def _dispatch_route_group_17(a, capture_command, p):
    if a.cmd != "continue":
        return _UNHANDLED
    try:
        usage = (
            json.loads(Path(a.usage_json).read_text(encoding="utf-8"))
            if a.usage_json
            else None
        )
        report = _lazy_import("continuation", "continue_assembly")(
            Path(a.root), a.feature, dry_run=a.dry_run, usage=usage
        )
    except (
        _lazy_import("continuation", "ContinuationError"),
        ValueError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        return _continuation_error(a, exc)
    _print_continuation_report(a, report)
    return _continuation_exit_code(report)


def _dispatch_route_group_18(a, capture_command, p):
    if a.cmd == "metrics":
        payload = _lazy_import("run_metrics", "public_metrics")(Path(a.root))
        if a.out:
            _lazy_import("run_metrics", "export_public_metrics")(
                Path(a.root), Path(a.out)
            )
        if a.json or not a.out:
            print(json.dumps(payload, indent=2))
        else:
            print(f"public Assembly metrics written to {Path(a.out).resolve()}")
        return 0
    return _UNHANDLED


def _workspace_inspection(a) -> dict:
    root = Path(a.root)
    payload = dict(_lazy_import("workspace_advisor", "inspect_workspace")(root))
    payload["artifacts"] = {}
    if a.out_dir:
        artifacts = _lazy_import(
            "workspace_advisor", "write_workspace_advisor_artifacts"
        )(payload, root, Path(a.out_dir))
        payload["artifacts"] = {"paths": artifacts, "write_mode": "explicit_local"}
        payload["markers"] = [
            *payload["markers"],
            "WORKSPACE_ADVISOR_ARTIFACTS_EXPLICIT",
        ]
    return payload


def _workspace_continuity(a) -> dict:
    root = Path(a.root)
    if a.continuity_cmd == "baseline":
        payload = dict(
            _lazy_import("index_continuity", "capture_continuity_baseline")(root)
        )
        payload["baseline_path"] = _lazy_import(
            "index_continuity", "write_continuity_baseline"
        )(payload, root, Path(a.out))
        payload["markers"] = [*payload["markers"], "INDEX_CONTINUITY_ARTIFACT_EXPLICIT"]
        return payload
    return _lazy_import("index_continuity", "compare_continuity")(
        root, Path(a.baseline)
    )


def _workspace_command_error(a, exc: Exception) -> int:
    continuity_error = _lazy_import("index_continuity", "IndexContinuityError")
    is_continuity = isinstance(exc, continuity_error)
    error = {
        "schema": "factory.index_continuity.error.v1"
        if is_continuity
        else "factory.workspace_advisor.error.v1",
        "status": "failed",
        "code": exc.code,
        "marker": "INDEX_CONTINUITY_REFUSED"
        if is_continuity
        else "WORKSPACE_ADVISOR_REFUSED",
        "message": str(exc),
    }
    print(
        json.dumps(error, indent=2, sort_keys=True)
        if a.json
        else f"workspace command refused: {exc.code}: {exc}",
        file=sys.stderr,
    )
    return 2


def _print_continuity_payload(payload: dict) -> None:
    print("FactoryLine Index Continuity Guard")
    print(f"scope     : {payload.get('review_scope', 'baseline captured')}")
    print("boundary  : local structure only; no IDE, cache, index, or remote changes.")
    if payload.get("baseline_path"):
        print(f"baseline  : {payload['baseline_path']}")
    if payload.get("recommendation"):
        print(f"next step : {payload['recommendation']}")


def _print_workspace_payload(payload: dict) -> None:
    scan = payload["scan"]
    workspace = payload["workspace"]
    print("FactoryLine Workspace Load Advisor")
    print(f"workspace : {workspace['name']} ({workspace['path_classification']})")
    print(
        f"observed  : {scan['files_scanned']} files, {scan['bytes_scanned']} bytes; limited={scan['scan_limited']}"
    )
    print(
        "boundary  : local filesystem shape only; no IDE, cache, index, or remote changes."
    )
    for recommendation in payload["recommendations"]:
        print(f"  - [{recommendation['priority']}] {recommendation['action']}")
    if payload.get("artifacts"):
        print(f"artifacts : {payload['artifacts']['paths']}")


def _workspace_output(a, payload: dict) -> None:
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif a.workspace_cmd == "continuity":
        _print_continuity_payload(payload)
    else:
        _print_workspace_payload(payload)


def _dispatch_route_group_19(a, capture_command, p):
    if a.cmd != "workspace":
        return _UNHANDLED
    try:
        payload = (
            _workspace_inspection(a)
            if a.workspace_cmd == "inspect"
            else _workspace_continuity(a)
        )
    except (
        _lazy_import("workspace_advisor", "WorkspaceAdvisorError"),
        _lazy_import("index_continuity", "IndexContinuityError"),
    ) as exc:
        return _workspace_command_error(a, exc)
    _workspace_output(a, payload)
    return 0


def _dispatch_route_group_20(a, capture_command, p):
    if a.cmd == "update-check":
        from .update_check import check_for_update, render

        result = check_for_update(Path(a.root), force=a.force)
        print(
            json.dumps(result, indent=2, sort_keys=True) if a.json else render(result)
        )
        return 0
    return _UNHANDLED


def _habituation_record(a, root: Path) -> int:
    payload = _lazy_import("habituation", "record_review")(
        root,
        {
            "review_id": a.review_id,
            "reviewer": a.reviewer,
            "author_kind": a.author_kind,
            "review_seconds": a.review_seconds,
            "changed_lines": a.changed_lines,
            "inline_comments": a.inline_comments,
            "approved": a.approved,
        },
        replace=a.replace,
    )
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else f"REVIEW_OBSERVED {a.review_id} scrutiny={payload['scrutiny_ratio']:.1f}s/100L"
    )
    return 0


def _habituation_status(a, root: Path) -> int:
    gate = _lazy_import("habituation", "evaluate_gate")(root, allow_block=a.allow_block)
    if a.json:
        print(json.dumps(gate, indent=2, sort_keys=True))
    else:
        print(f"HABITUATION_GATE action={gate['action']} blocking={gate['blocking']}")
        print(
            f"  warned={gate['reviewers_warned']} breached={gate['reviewers_breached']} "
            f"proxy_corrected={gate['proxy_corrected_by_resampling']}"
        )
        print(f"  {gate['reason']}")
    return 1 if gate["blocking"] else 0


def _habituation_sample(a, root: Path) -> int:
    payload = _lazy_import("habituation", "blind_spot_sample")(root, rate=a.rate)
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else f"BLIND_SPOT_SAMPLE_RECEIPTED selected={payload['selected_count']} "
        f"of {payload['eligible_low_scrutiny']} low-scrutiny approvals"
    )
    return 0


def _habituation_resample(a, root: Path) -> int:
    payload = _lazy_import("habituation", "record_resample_outcome")(
        root,
        a.review_id,
        defect_found=a.defect_found,
        reviewer=a.reviewer,
        notes=a.notes,
    )
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else f"RESAMPLE_OUTCOME_RECEIPTED {a.review_id} defect={payload['defect_found']}"
    )
    return 0


def _habituation_report(a, root: Path) -> int:
    if a.out:
        path = _lazy_import("habituation", "export_public_habituation_report")(
            root, Path(a.out), enable_defect_linkage=a.enable_defect_linkage
        )
        print(f"HABITUATION_PUBLIC_REPORT_EXPORTED {path}")
        return 0
    payload = _lazy_import("habituation", "public_habituation_report")(
        root, enable_defect_linkage=a.enable_defect_linkage
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _habituation_action(a, root: Path) -> int:
    actions = {
        "record": _habituation_record,
        "status": _habituation_status,
        "sample": _habituation_sample,
        "resample": _habituation_resample,
        "report": _habituation_report,
    }
    action = actions.get(a.hab_cmd)
    if action is None:
        print("usage: factory habituation {record|status|sample|resample|report}")
        return 2
    return action(a, root)


def _dispatch_route_group_21(a, capture_command, p):
    if a.cmd != "habituation":
        return _UNHANDLED
    from .habituation import HabituationError

    try:
        return _habituation_action(a, Path(a.root))
    except (HabituationError, OSError) as exc:
        print(f"HABITUATION_REFUSED {getattr(exc, 'code', '')}: {exc}")
        return 2


def _cdte_scan(a, root: Path, record_scan, draft_adr, error_type) -> int:
    try:
        raw = json.loads(Path(a.constraints).read_text(encoding="utf-8"))
        constraints = raw["constraints"] if isinstance(raw, dict) else raw
        payload = record_scan(
            root,
            a.run_id,
            constraints,
            evidence=Path(a.evidence) if a.evidence else None,
            replace=a.replace,
        )
    except (error_type, OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        code = getattr(exc, "code", type(exc).__name__)
        print(f"CDTE_SCAN_REFUSED {code}: {exc}")
        return 2
    if a.adr:
        for index, conflict in enumerate(payload["conflicts"], start=1):
            path = draft_adr(root, payload, conflict["conflict_id"], number=index)
            print(f"ADR_DRAFTED {path}")
    _print_cdte_scan(a, payload)
    return 1 if payload["fail_closed"] else 0


def _print_cdte_scan(a, payload: dict) -> None:
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(
        f"CDTE_SCAN_RECEIPTED {payload['run_id']} "
        f"conflicts={len(payload['conflicts'])} "
        f"fail_closed={payload['fail_closed']}"
    )
    for conflict in payload["conflicts"]:
        analysis = conflict["incompatibility_analysis"]
        state = "withheld" if analysis["withheld"] else analysis["tier"]
        print(
            f"  [{conflict['severity']}] {conflict['conflict_id']} "
            f"{conflict['pair_id']} (analysis: {state})"
        )


def _cdte_report(a, root: Path, export_report, public_report) -> int:
    if a.out:
        path = export_report(root, Path(a.out))
        print(f"CDTE_PUBLIC_REPORT_EXPORTED {path}")
    else:
        print(json.dumps(public_report(root), indent=2, sort_keys=True))
    return 0


def _cdte_resolve(a, root: Path, resolve_conflict, error_type) -> int:
    try:
        payload = resolve_conflict(
            root,
            a.run_id,
            a.conflict_id,
            decision=a.decision,
            approved_by=a.approved_by,
            adr_path=Path(a.adr_path) if a.adr_path else None,
            override=a.override,
            expires=a.expires,
        )
    except (error_type, OSError) as exc:
        print(f"CDTE_RESOLUTION_REFUSED {getattr(exc, 'code', '')}: {exc}")
        return 2
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else f"CDTE_RESOLUTION_RECEIPTED {a.conflict_id} by {payload['approved_by']}"
    )
    return 0


def _dispatch_route_group_22(a, capture_command, p):
    if a.cmd != "cdte":
        return _UNHANDLED
    from .cdte import (
        CDTEError,
        draft_adr,
        export_public_cdte_report,
        public_cdte_report,
        record_scan,
        resolve_conflict,
    )

    root = Path(a.root)
    if a.cdte_cmd == "scan":
        return _cdte_scan(a, root, record_scan, draft_adr, CDTEError)
    if a.cdte_cmd == "report":
        return _cdte_report(a, root, export_public_cdte_report, public_cdte_report)
    if a.cdte_cmd == "resolve":
        return _cdte_resolve(a, root, resolve_conflict, CDTEError)
    print("usage: factory cdte {scan|report|resolve}")
    return 2


def _savings_record_error(a, exc: Exception) -> int:
    code = getattr(exc, "code", "SAVINGS_INPUT_INVALID")
    print(
        json.dumps({"code": code, "message": str(exc)}, indent=2)
        if a.json
        else f"savings failed: {code}: {exc}",
        file=sys.stderr,
    )
    return 2


def _print_savings_record(a, payload: dict) -> None:
    if a.json:
        print(json.dumps(payload, indent=2))
        return
    values = payload["savings"]
    print("factory paired savings")
    print(f"pair          : {payload['pair_id']}")
    print(f"time saved    : {values['time_saved_ms']} ms")
    print(
        f"tokens saved  : {values['tokens_saved'] if values['tokens_saved'] is not None else 'unknown'}"
    )
    print(
        f"cost saved    : {values['cost_saved_usd'] if values['cost_saved_usd'] is not None else 'unknown'}"
    )
    print(
        f"productivity  : {values['productivity_gain_rate'] if values['productivity_gain_rate'] is not None else 'unknown'}"
    )
    print(f"receipt       : {payload['receipt']}")


def _savings_record(a) -> int:
    baseline = {
        "elapsed_ms": a.baseline_elapsed_ms,
        "tokens": a.baseline_tokens,
        "cost_usd": a.baseline_cost_usd,
    }
    factory_observation = {
        "elapsed_ms": a.factory_elapsed_ms,
        "tokens": a.factory_tokens,
        "cost_usd": a.factory_cost_usd,
    }
    try:
        payload = _lazy_import("savings", "record_savings_pair")(
            Path(a.root),
            a.pair_id,
            baseline,
            factory_observation,
            equivalent_outcome=a.equivalent_outcome,
            evidence=Path(a.evidence) if a.evidence else None,
            replace=a.replace,
        )
    except (_lazy_import("savings", "SavingsError"), OSError) as exc:
        return _savings_record_error(a, exc)
    _print_savings_record(a, payload)
    return 0


def _savings_report(a) -> int:
    root = Path(a.root)
    payload = _lazy_import("savings", "public_savings_report")(root)
    if a.out:
        _lazy_import("savings", "export_public_savings_report")(root, Path(a.out))
    if a.json or not a.out:
        print(json.dumps(payload, indent=2))
    else:
        print(f"public savings report written to {Path(a.out).resolve()}")
    return 0


def _dispatch_route_group_23(a, capture_command, p):
    if a.cmd != "savings":
        return _UNHANDLED
    if a.savings_cmd == "record":
        return _savings_record(a)
    if a.savings_cmd == "report":
        return _savings_report(a)
    p.error("savings requires record or report")
    return 2


def _proofs_record(a) -> dict:
    manifest = _lazy_import("proof_reuse", "load_manifest")(Path(a.manifest))
    gates = manifest.get("gates") if isinstance(manifest, dict) else None
    if not isinstance(gates, list) or not gates:
        raise _lazy_import("proof_reuse", "ProofReuseError")(
            "PROOF_MANIFEST_INVALID", "manifest contains no gates"
        )
    selected = [
        gate
        for gate in gates
        if isinstance(gate, dict) and (a.gate is None or gate.get("name") == a.gate)
    ]
    if len(selected) != 1:
        raise _lazy_import("proof_reuse", "ProofReuseError")(
            "PROOF_GATE_AMBIGUOUS", "select exactly one gate with --gate"
        )
    return _lazy_import("proof_reuse", "record_proof")(
        Path(a.root),
        selected[0],
        elapsed_ms=a.elapsed_ms,
        tokens=a.tokens,
        replace=a.replace,
    )


def _proofs_result(a, p) -> dict:
    if a.proofs_cmd == "record":
        return _proofs_record(a)
    if a.proofs_cmd == "plan":
        return _lazy_import("proof_reuse", "plan_proofs")(
            Path(a.root),
            _lazy_import("proof_reuse", "load_manifest")(Path(a.manifest)),
            changed_paths=a.changed,
            auto_savings=a.auto_savings,
            out=Path(a.out) if a.out else None,
        )
    if a.proofs_cmd == "verify":
        return _lazy_import("proof_reuse", "verify_proof_receipt")(
            Path(a.root), Path(a.receipt)
        )
    if a.proofs_cmd == "challenge":
        return _lazy_import("proof_reuse", "challenge_proof_receipt")(
            Path(a.root), Path(a.receipt)
        )
    p.error("proofs requires record, plan, verify, or challenge")
    return {}


def _proofs_error(a, exc: Exception) -> int:
    failure = {
        "schema": "factory.proof-error.v1",
        "code": exc.code,
        "message": str(exc),
    }
    print(
        json.dumps(failure, indent=2)
        if getattr(a, "json", False)
        else f"proofs failed: {exc.code}: {exc}",
        file=sys.stderr,
    )
    return 2


def _proofs_output(a, payload: dict) -> None:
    if getattr(a, "json", False):
        print(json.dumps(payload, indent=2))
        return
    if a.proofs_cmd == "plan":
        print("factory proof plan")
        print("=" * 44)
        for item in payload["items"]:
            print(f"{item['gate']}: {item['disposition']} - {item['reason']}")
        print(f"receipt: {payload['plan']}")
        return
    print(json.dumps(payload, indent=2))


def _proofs_exit_code(a, payload: dict) -> int:
    if a.proofs_cmd not in {"verify", "challenge"}:
        return 0
    return 0 if payload.get("valid", payload.get("passed", False)) else 1


def _dispatch_route_group_24(a, capture_command, p):
    if a.cmd != "proofs":
        return _UNHANDLED
    try:
        payload = _proofs_result(a, p)
    except _lazy_import("proof_reuse", "ProofReuseError") as exc:
        return _proofs_error(a, exc)
    _proofs_output(a, payload)
    return _proofs_exit_code(a, payload)


def _verification_text(a, result: dict) -> None:
    print("factory verification")
    print("=" * 44)
    for module in result["modules"]:
        print(f"{module['label']:<8} {module['status'].upper()}")
    decision = result["release_ready"] if a.strict_release else result["shippable"]
    if a.strict_release and decision:
        label = "STRICT LOCAL GATES PASS"
    elif decision:
        label = "LOCAL GATES PASS"
    else:
        label = "NOT READY"
    print(f"FACTORY  {label}")
    print(f"next action: {result['next_action']}")


def _verification_output(a, result: dict) -> None:
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        _verification_text(a, result)


def _verification_exit_code(a, result: dict) -> int:
    ready = result["release_ready"] if a.strict_release else result["shippable"]
    return 0 if ready else 1


def _dispatch_route_group_25(a, capture_command, p):
    if a.cmd == "verify":
        result = _lazy_import("verification", "verify_feature")(
            Path(a.root),
            a.feature,
            strict_release=a.strict_release,
            release_contract_path=Path(a.release_contract)
            if a.release_contract
            else None,
        )
        _verification_output(a, result)
        return _verification_exit_code(a, result)
    return _UNHANDLED


def _validate_meter_args(a) -> bool:
    if a.interval <= 0:
        print("meter failed: --interval must be positive", file=sys.stderr)
        return False
    if a.max_updates is not None and a.max_updates <= 0:
        print("meter failed: --max-updates must be positive", file=sys.stderr)
        return False
    return True


def _capture_meter_command(a, capture_command: list[str] | None) -> int:
    if capture_command is None:
        return 0
    command = list(capture_command)
    if not command:
        print("meter failed: --capture requires a command after --", file=sys.stderr)
        return 2
    started = time.monotonic()
    try:
        proc = subprocess.run(command, cwd=str(Path(a.root)))
        capture_exit = proc.returncode
    except FileNotFoundError:
        print(
            f"meter capture failed: executable not found: {command[0]}", file=sys.stderr
        )
        capture_exit = 127
    elapsed_ms = round((time.monotonic() - started) * 1000)
    from .meter import MeterLog, StageTiming

    MeterLog(Path(a.root)).record(
        StageTiming(
            module=a.module,
            stage=a.stage,
            wall_ms=elapsed_ms,
            model_calls=0,
            tokens_in=0,
            tokens_out=0,
            ok=capture_exit == 0,
            feature=a.feature,
            run_id=uuid.uuid4().hex,
        )
    )
    return capture_exit


def _watch_meter(a) -> None:
    updates = 0
    while True:
        snapshot = _lazy_import("meter", "live_snapshot")(
            Path(a.root),
            baseline_tokens_per_run=a.baseline,
            runs_projected=a.runs,
        )
        if a.json:
            print(json.dumps(snapshot, sort_keys=True))
        else:
            print(_lazy_import("meter", "live_summary_table")(snapshot))
        updates += 1
        if not a.watch or (a.max_updates is not None and updates >= a.max_updates):
            break
        time.sleep(a.interval)


def _dispatch_route_group_26(a, capture_command, p):
    if a.cmd != "meter":
        return _UNHANDLED
    if not _validate_meter_args(a):
        return 2
    capture_exit = _capture_meter_command(a, capture_command)
    if capture_exit == 2 and capture_command == []:
        return 2
    _watch_meter(a)
    return capture_exit


def _dispatch_route_group_27(a, capture_command, p):
    if a.cmd == "rollup":
        print(
            json.dumps(
                _lazy_import("assembly", "rollup_receipts")(Path(a.root), a.feature),
                indent=2,
            )
        )
        return 0
    if a.cmd == "trace":
        try:
            trace = _lazy_import("proof", "build_trace")(
                Path(a.root), a.feature, out=Path(a.out) if a.out else None
            )
        except ValueError as exc:
            print(f"trace failed: {exc}", file=sys.stderr)
            return 1
        if a.json:
            print(json.dumps(trace, indent=2))
        else:
            print(f"proof trace written: {trace['trace_path']}")
            print(f"trace_sha256       : {trace['trace_sha256']}")
            print(f"chain_head         : {trace['chain_head']}")
            print(f"nodes              : {len(trace['nodes'])}")
            print(
                f"earliest failure   : {trace['rollup'].get('earliest_failing_stage') or 'none'}"
            )
        return 0
    return _UNHANDLED


def _dispatch_route_group_28(a, capture_command, p):
    if a.cmd == "verify-trace":
        result = _lazy_import("proof", "verify_trace")(
            Path(a.trace), root=Path(a.root) if a.root else None
        )
        if a.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"trace      : {result['trace']}")
            print(f"valid      : {result['valid']}")
            print(f"chain_head : {result['chain_head']}")
            if result["errors"]:
                print("errors:")
                for error in result["errors"]:
                    print(f"  - {error}")
        return 0 if result["valid"] else 1
    return _UNHANDLED


def _replay_trace_root(a, trace_path: Path) -> Path:
    if a.root:
        return Path(a.root)
    trace = _lazy_import("proof", "load_trace")(trace_path)
    return Path(trace.get("root", "."))


def _replay_plan(a, trace_path: Path, trace_root: Path) -> dict:
    changed = list(a.changed)
    if a.base:
        changed.extend(_lazy_import("proof", "git_changed_paths")(trace_root, a.base))
    trace = _lazy_import("proof", "load_trace")(trace_path)
    return _lazy_import("proof", "replay_plan")(trace, changed)


def _replay_execute(a, plan: dict, trace_path: Path, trace_root: Path) -> int:
    verification = _lazy_import("proof", "verify_trace")(trace_path, root=trace_root)
    if not verification["valid"]:
        print(
            json.dumps(verification, indent=2)
            if a.json
            else "trace verification failed; replay refused"
        )
        return 1
    result = _lazy_import("proof", "execute_replay")(plan, root=trace_root)
    output = (
        json.dumps(result, indent=2)
        if a.json
        else "\n".join(
            f"{item['module']}:{item['stage']} {item['status']}"
            for item in result["results"]
        )
    )
    print(output)
    return 0 if result["ok"] else 1


def _replay_plan_output(a, plan: dict) -> None:
    if a.json:
        print(json.dumps(plan, indent=2))
        return
    print("factory replay plan")
    print("=" * 44)
    if not plan["commands"]:
        print("no changed paths supplied; verify the trace, no replay planned")
    for item in plan["commands"]:
        print(f"{item['module']}:{item['stage']}")
        for reason in item["reasons"]:
            print(f"  reason: {reason}")
        if item["command"]:
            print(f"  run   : {item['command']}")


def _dispatch_route_group_29(a, capture_command, p):
    if a.cmd != "replay":
        return _UNHANDLED
    trace_path = Path(a.trace)
    trace_root = _replay_trace_root(a, trace_path)
    plan = _replay_plan(a, trace_path, trace_root)
    if a.execute:
        return _replay_execute(a, plan, trace_path, trace_root)
    _replay_plan_output(a, plan)
    return 0


def _dispatch_route_group_30(a, capture_command, p):
    if a.cmd == "evidence":
        evidence = _lazy_import("proof", "public_evidence")(
            Path(a.root), a.feature, trace_path=Path(a.trace) if a.trace else None
        )
        print(
            json.dumps(evidence, indent=2)
            if a.json
            else _lazy_import("proof", "public_evidence_text")(evidence)
        )
        return 0 if evidence["verified"] else 1
    return _UNHANDLED


def _dispatch_route_group_31(a, capture_command, p):
    if a.cmd == "risk-diff":
        changed = list(a.changed)
        if not changed:
            try:
                changed = _lazy_import("proof", "git_changed_paths")(
                    Path(a.root), a.base
                )
            except RuntimeError as exc:
                print(f"risk-diff failed: {exc}", file=sys.stderr)
                return 1
        risk = _lazy_import("proof", "risk_for_paths")(changed)
        if a.json:
            print(json.dumps(risk, indent=2))
        else:
            print("factory risk diff")
            print("=" * 44)
            for stage in risk["rerun_stages"]:
                print(f"{stage['module']}:{stage['stage']}")
                for reason in stage["reasons"]:
                    print(f"  reason: {reason}")
        return 0
    return _UNHANDLED


def _graph_lineage_error(schema: str, exc: Exception, code: str | None = None) -> int:
    print(
        json.dumps(
            {
                "schema": schema,
                "code": code or getattr(exc, "code", "E_GRAPH_LINEAGE"),
                "message": str(exc),
            },
            indent=2,
        ),
        file=sys.stderr,
    )
    return 2


def _graph_lineage_continuity(a) -> int:
    try:
        payload = _lazy_import("candidate_lineage", "verify_candidate_lineage")(
            Path(a.root), Path(a.manifest)
        )
    except _lazy_import("candidate_lineage", "CandidateLineageError") as exc:
        return _graph_lineage_error("factory.candidate-lineage-error.v1", exc)
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else "candidate lineage: verified (review only)"
    )
    return 0


def _graph_lineage_mission(a) -> int:
    try:
        payload = _lazy_import("graph_forensics", "seal_mission_graph_lineage")(
            Path(a.mission), Path(a.root), a.run_id, Path(a.out), a.candidate_sha256
        )
    except (_lazy_import("graph_forensics", "GraphForensicsError"), ValueError) as exc:
        code = getattr(exc, "code", "GRAPH_LINEAGE_HISTORY_INVALID")
        return _graph_lineage_error("factory.graph-lineage.error.v1", exc, code)
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else f"exported mission lineage: {payload['path']}"
    )
    return 0


def _graph_lineage_seal(a) -> int:
    try:
        payload = _lazy_import("graph_forensics", "seal_graph_lineage")(
            a.run_id, a.graph_id, Path(a.steps), Path(a.out), a.candidate_sha256
        )
    except _lazy_import("graph_forensics", "GraphForensicsError") as exc:
        return _graph_lineage_error("factory.graph-lineage.error.v1", exc)
    print(
        json.dumps(payload, indent=2, sort_keys=True)
        if a.json
        else f"sealed graph lineage: {payload['path']}"
    )
    return 0


def _graph_lineage_verify(a) -> int:
    try:
        payload = _lazy_import("graph_forensics", "verify_graph_lineage")(
            Path(a.lineage), a.candidate_sha256
        )
    except _lazy_import("graph_forensics", "GraphForensicsError") as exc:
        return _graph_lineage_error("factory.graph-lineage.error.v1", exc)
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"graph lineage: {'valid' if payload['valid'] else 'invalid'}")
        for error in payload["errors"]:
            print(f"- {error}")
    return 0 if payload["valid"] else 1


def _graph_forensics(a) -> int:
    try:
        payload = _lazy_import("graph_forensics", "graph_forensics")(
            Path(a.baseline), Path(a.candidate)
        )
    except _lazy_import("graph_forensics", "GraphForensicsError") as exc:
        return _graph_lineage_error("factory.graph-forensics.error.v1", exc)
    if a.mermaid:
        print(payload["mermaid"])
    elif a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        divergence = payload["divergence"]
        print("factory graph forensics (read-only)")
        print("=" * 44)
        print(
            f"first divergence: {divergence['candidate_node'] if divergence else 'none'}"
        )
        print(f"anomalies       : {len(payload['anomalies'])}")
        print(f"recovery        : {payload['recovery_plan']['action']}")
    return 0


def _graph_impact(a, graph_ops_impact) -> int:
    try:
        payload = graph_ops_impact(Path(a.root), a.changed)
    except ValueError as exc:
        return _graph_lineage_error(
            "factory.graph-impact.error.v1", exc, "CHANGED_PATH_INVALID"
        )
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("factory graph impact (read-only)")
        print("=" * 44)
        print(f"matched proofs  : {len(payload['matched_proofs'])}")
        print(f"rerun proofs    : {len(payload['rerun_proofs'])}")
        print(f"verified current: {len(payload['verified_current_proofs'])}")
        if payload["unmatched_changed_paths"]:
            print("unmatched paths : " + ", ".join(payload["unmatched_changed_paths"]))
    return 0


def _graph_portfolio(a, graph_ops_snapshot) -> int:
    durations = None
    if a.durations:
        try:
            durations = json.loads(Path(a.durations).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            return _graph_lineage_error(
                "factory.graph-portfolio.error.v1", exc, "DURATION_INPUT_INVALID"
            )
    payload = _lazy_import("graph_portfolio", "graph_portfolio_plan")(
        graph_ops_snapshot(Path(a.root)), durations
    )
    payload = {**payload, "cli_marker": "GRAPH_PORTFOLIO_CLI_READ_ONLY"}
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("factory graph portfolio (read-only)")
        print("=" * 44)
        print(f"verdict      : {payload['verdict']}")
        print(f"critical path: {' -> '.join(payload['critical_path']) or 'none'}")
        print(f"work items   : {len(payload['workset'])}")
        print(f"parallel wave: {len(payload.get('parallel_waves', []))}")
    return 0 if payload["verdict"] == "READY" else 1


def _graph_snapshot(a, graph_ops_snapshot) -> int:
    snapshot = graph_ops_snapshot(Path(a.root))
    if a.mermaid:
        print(snapshot["mermaid"])
        return 0
    payload = {**snapshot, "cli_marker": "GRAPH_OPS_CLI_READ_ONLY"}
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("factory graph ops (read-only)")
        print("=" * 44)
        print(f"nodes       : {snapshot['facts']['node_count']}")
        print(f"edges       : {snapshot['facts']['edge_count']}")
        print(f"complete    : {snapshot['complete']}")
        print(f"next action : {snapshot['recommendation']['action']}")
        print(f"reason      : {snapshot['recommendation']['reason']}")
    return 0


def _dispatch_route_group_32(a, capture_command, p):
    if a.cmd != "graph":
        return _UNHANDLED
    from .graph_ops import graph_ops_impact, graph_ops_snapshot

    handlers = {
        "lineage-continuity": _graph_lineage_continuity,
        "lineage-mission": _graph_lineage_mission,
        "lineage-seal": _graph_lineage_seal,
        "lineage-verify": _graph_lineage_verify,
        "forensics": _graph_forensics,
        "impact": lambda: _graph_impact(a, graph_ops_impact),
        "portfolio": lambda: _graph_portfolio(a, graph_ops_snapshot),
    }
    handler = handlers.get(a.graph_cmd)
    if handler is not None:
        return handler() if a.graph_cmd in {"impact", "portfolio"} else handler(a)
    return _graph_snapshot(a, graph_ops_snapshot)


def _dispatch_route_group_33(a, capture_command, p):
    if a.cmd == "memory":
        from .cli_governance import run as run_governance

        return run_governance(a)
    if a.cmd == "change":
        from .cli_evidence_chain import run as run_evidence_chain

        return run_evidence_chain(a)
    if a.cmd == "proof-ops":
        from .cli_evidence_chain import run as run_evidence_chain

        return run_evidence_chain(a)
    if a.cmd == "proof-review":
        from .cli_evidence_chain import run as run_evidence_chain

        return run_evidence_chain(a)
    if a.cmd == "revenue":
        from .cli_revenue import run as run_revenue

        return run_revenue(a)
    if a.cmd == "saas":
        from .cli_saas import run as run_saas

        return run_saas(a)
    if a.cmd == "intent":
        from .cli_governance import run as run_governance

        return run_governance(a)
    if a.cmd == "judgment":
        from .cli_governance import run as run_governance

        return run_governance(a)
    if a.cmd == "github":
        from .cli_github import run as run_github

        return run_github(a)
    return _UNHANDLED


def _dispatch_route_group_34(a, capture_command, p):
    if a.cmd == "repair":
        from .cli_ide import run as run_ide

        return run_ide(a)
    if a.cmd == "release":
        from .cli_release import run as run_release

        return run_release(a)
    if a.cmd == "jetbrains":
        from .cli_ide import run as run_ide

        return run_ide(a)
    if a.cmd in {"mcp", "junie"}:
        from .cli_integrations import run as run_integrations

        return run_integrations(a)
    if a.cmd == "attest":
        from .cli_artifacts import run as run_artifacts

        return run_artifacts(a)
    if a.cmd == "overhead":
        payload = _lazy_import("meter", "overhead")(Path(a.root))
        if a.json:
            print(json.dumps(payload, indent=2))
        else:
            print("factory gate overhead (measured local wall time)")
            for item in payload["gates"]:
                print(
                    f"{item['module']}:{item['stage']} avg={item['avg_wall_ms']}ms runs={item['runs']} failed={item['failed_runs']}"
                )
        return 0
    return _UNHANDLED


def _dispatch_route_group_35(a, capture_command, p):
    if a.cmd == "override":
        from .overrides import record_override

        payload = record_override(
            Path(a.root),
            a.issue,
            reason=a.reason,
            approved_by=a.approved_by,
            expires=a.expires,
        )
        print(
            json.dumps(payload, indent=2)
            if a.json
            else f"override receipt written: {payload['path']}"
        )
        return 0
    if a.cmd == "receipt":
        from .signed_receipts import (
            SignedReceiptError,
            receipt_status,
            sign_receipt,
            verify_receipt,
        )

        try:
            if a.receipt_cmd == "sign":
                result = sign_receipt(
                    Path(a.path), timeout=a.timeout, overwrite=a.overwrite
                )
            elif a.receipt_cmd == "verify":
                result = verify_receipt(
                    Path(a.path),
                    cert_identity=a.cert_identity,
                    cert_oidc_issuer=a.cert_oidc_issuer,
                    timeout=a.timeout,
                )
            else:
                result = receipt_status(Path(a.path))
        except SignedReceiptError as exc:
            print(
                json.dumps(
                    {
                        "schema": "factory.sigstore.result.v1",
                        "verdict": "ERROR",
                        "error": {"code": exc.code, "message": exc.message},
                    },
                    indent=2,
                )
            )
            return 1
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.verdict != "UNSIGNED" else 1
    return _UNHANDLED


def _dispatch_route_group_36(a, capture_command, p):
    if a.cmd == "verify-receipts":
        from .enterprise_receipts import EnterpriseReceiptError
        from .receipt_challenge import MUTATION_GATE_SCHEMA, verify_receipt_mutations

        try:
            result = verify_receipt_mutations(
                Path(a.root), Path(a.out) if a.out else None
            )
        except (EnterpriseReceiptError, OSError) as exc:
            code = exc.code if isinstance(exc, EnterpriseReceiptError) else "E_INPUT"
            message = (
                exc.message if isinstance(exc, EnterpriseReceiptError) else str(exc)
            )
            print(
                json.dumps(
                    {
                        "schema": MUTATION_GATE_SCHEMA,
                        "passed": False,
                        "error": {"code": code, "message": message},
                    },
                    indent=2,
                )
            )
            return 1
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(
                f"{result['marker']}: {result['rejected']}/{result['attempted']} receipt mutations rejected; receipt={result['path']}"
            )
        return 0 if result["passed"] else 1
    if a.cmd == "enterprise":
        from .cli_enterprise import run as run_enterprise

        return run_enterprise(a)
    if a.cmd in {"control", "controls"}:
        from .cli_controls import run as run_controls

        return run_controls(a)
    return _UNHANDLED


def _dispatch_route_group_37(a, capture_command, p):
    if a.cmd == "evidence-memory":
        from .engineering_memory import recall_engineering_memory
        from .continuity import principal_from_args, ContinuityError
        import sqlite3

        try:
            principal = principal_from_args(
                a.subject, a.tenant, ["reader"], [a.purpose]
            )
            from .knowledge_handoff import (
                create_knowledge_handoff,
                receive_knowledge_handoff,
            )
            from .deep_audit_io import local_file, strict_json, LIMIT

            args = (Path(a.root), principal, a.tenant, a.purpose, a.scope)
            if a.accept:
                with local_file(Path(a.root).resolve(), a.accept).open("rb") as stream:
                    packet = strict_json(stream.read(LIMIT + 1))
                result = receive_knowledge_handoff(*args, a.sender, a.receiver, packet)
            elif a.sender or a.receiver:
                result = create_knowledge_handoff(*args, a.sender, a.receiver)
            else:
                result = recall_engineering_memory(*args)
        except (
            ValueError,
            OSError,
            KeyError,
            TypeError,
            ContinuityError,
            sqlite3.Error,
        ) as exc:
            print(
                json.dumps(
                    {
                        "state": "blocked",
                        "code": getattr(exc, "code", "E_MEMORY_INVALID"),
                        "authority": "none",
                    }
                )
            )
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    return _UNHANDLED


def _dispatch_route_group_38(a, capture_command, p):
    if a.cmd == "continuity":
        from .continuity import (
            ContinuityError,
            ContinuityStore,
            principal_from_args as continuity_principal_from_args,
        )

        try:
            if a.continuity_cmd == "init":
                store = ContinuityStore(Path(a.db))
                result = {
                    "schema": "factory.continuity.v1",
                    "marker": "CONTINUITY_LOCAL_REFERENCE_ONLY",
                    "verdict": "READY",
                    "db": str(store.path.resolve()),
                    "authority": {
                        "external_effects": False,
                        "signing": False,
                        "erasure": False,
                    },
                }
            else:
                store = ContinuityStore(Path(a.db))
                if a.continuity_cmd == "status":
                    result = store.status()
                else:
                    principal = continuity_principal_from_args(
                        a.subject, a.tenant, a.roles.split(","), a.purposes.split(",")
                    )
                    if a.continuity_cmd == "record":
                        payload = json.loads(
                            Path(a.payload).read_text(encoding="utf-8")
                        )
                        result = store.record(
                            principal,
                            payload,
                            idempotency_key=a.idempotency_key,
                            record_id=a.record_id,
                        )
                    elif a.continuity_cmd == "recall":
                        result = store.recall(
                            principal,
                            a.tenant,
                            purpose_ref=a.purpose,
                            scope_ref=a.scope,
                        )
                    elif a.continuity_cmd == "promote":
                        result = store.promote(
                            principal, a.tenant, a.record_id, reason=a.reason
                        )
                    elif a.continuity_cmd == "withdraw":
                        result = store.withdraw(
                            principal,
                            a.tenant,
                            a.record_id,
                            status=a.status,
                            reason=a.reason,
                            replacement_id=a.replacement_id,
                        )
                    else:
                        result = store.prove(principal, a.tenant, a.record_id)
        except (ContinuityError, json.JSONDecodeError, OSError) as exc:
            error = {
                "code": getattr(exc, "code", "E_INPUT"),
                "message": getattr(exc, "message", str(exc)),
            }
            print(
                json.dumps(
                    {
                        "schema": "factory.continuity.result.v1",
                        "verdict": "ERROR",
                        "error": error,
                    },
                    indent=2,
                )
            )
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if a.cmd == "assurance":
        from .cli_assurance import run as run_assurance

        return run_assurance(a)
    return _UNHANDLED


def _dispatch_route_group_39(a, capture_command, p):
    if a.cmd == "verify-policy":
        from .assurance import AssuranceError, verify_policy_command

        root = Path(a.root)
        try:
            policy = json.loads((root / a.policy).read_text(encoding="utf-8"))
            challenge = json.loads(Path(a.challenge).read_text(encoding="utf-8"))
            result = verify_policy_command(
                policy,
                challenge.get("command"),
                root=root,
                cwd=str(challenge.get("cwd", ".")),
                timeout=int(challenge.get("timeout", 60)),
            )
            out = (
                Path(a.out)
                if a.out
                else root / ".factory" / "policy-challenges" / "verify-policy.json"
            )
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(
                json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
            )
        except (AssuranceError, OSError, json.JSONDecodeError, ValueError) as exc:
            error = {
                "code": getattr(exc, "code", "E_INPUT"),
                "message": getattr(exc, "message", str(exc)),
            }
            print(
                json.dumps(
                    {
                        "schema": "factory.policy.verify.v1",
                        "verdict": "ERROR",
                        "error": error,
                    },
                    indent=2,
                )
            )
            return 1
        print(json.dumps(result | {"receipt_path": str(out)}, indent=2, sort_keys=True))
        return 0 if result["status"] == "VERIFIED" else 1
    if a.cmd == "compliance":
        from .compliance import CONTROL_PACKS, build_oscal_assessment

        try:
            if a.compliance_cmd == "packs":
                print(
                    json.dumps(
                        {
                            "schema": "factory.compliance.packs.v1",
                            "packs": sorted(CONTROL_PACKS),
                        },
                        indent=2,
                    )
                )
                return 0
            evidence = json.loads(Path(a.evidence).read_text(encoding="utf-8"))
            controls = (
                json.loads(Path(a.controls).read_text(encoding="utf-8"))
                if a.controls
                else None
            )
            result = build_oscal_assessment(
                a.pack, tenant_id=a.tenant, evidence=evidence, custom_controls=controls
            )
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(
                json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "schema": "factory.compliance.result.v1",
                        "verdict": "ERROR",
                        "error": {"code": "E_INPUT", "message": str(exc)},
                    },
                    indent=2,
                )
            )
            return 1
        except Exception as exc:
            error = {
                "code": getattr(exc, "code", "E_COMPLIANCE"),
                "message": getattr(exc, "message", str(exc)),
            }
            print(
                json.dumps(
                    {
                        "schema": "factory.compliance.result.v1",
                        "verdict": "ERROR",
                        "error": error,
                    },
                    indent=2,
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "schema": "factory.compliance.result.v1",
                    "verdict": "WRITTEN",
                    "path": str(Path(a.out).resolve()),
                },
                indent=2,
            )
        )
        return 0
    return _UNHANDLED


def _dispatch_route_group_40(a, capture_command, p):
    if a.cmd == "privacy":
        from .privacy import bbs_status, merkle_disclosure, zkvm_pilot_status

        try:
            if a.privacy_cmd == "status":
                print(
                    json.dumps(
                        {
                            "schema": "factory.privacy.status.v1",
                            "bbs": bbs_status(),
                            "zkvm": zkvm_pilot_status(),
                        },
                        indent=2,
                    )
                )
                return 0
            leaves = json.loads(Path(a.leaves).read_text(encoding="utf-8"))
            result = merkle_disclosure(leaves, a.disclose)
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(
                json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(
                json.dumps(
                    {
                        "schema": "factory.privacy.result.v1",
                        "verdict": "ERROR",
                        "error": {"code": "E_INPUT", "message": str(exc)},
                    },
                    indent=2,
                )
            )
            return 1
        except Exception as exc:
            error = {
                "code": getattr(exc, "code", "E_PRIVACY"),
                "message": getattr(exc, "message", str(exc)),
            }
            print(
                json.dumps(
                    {
                        "schema": "factory.privacy.result.v1",
                        "verdict": "ERROR",
                        "error": error,
                    },
                    indent=2,
                )
            )
            return 1
        print(
            json.dumps(
                {
                    "schema": "factory.privacy.result.v1",
                    "verdict": "WRITTEN",
                    "path": str(Path(a.out).resolve()),
                },
                indent=2,
            )
        )
        return 0
    if a.cmd == "ci":
        from .overrides import ci_template

        path = Path(a.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(ci_template(a.feature), encoding="utf-8")
        print(f"GitHub PR-comment workflow written: {path}")
        return 0
    return _UNHANDLED


def _loop_action(
    a,
    init_loop,
    validate_manifest,
    build_loop_passport,
    verify_loop_passport,
    evaluate_budget,
) -> tuple[dict, int]:
    if a.loop_cmd == "init":
        result = init_loop(Path(a.root), a.loop_id, a.owner, force=a.force)
        return result, 0
    if a.loop_cmd == "validate":
        result = validate_manifest(Path(a.manifest))
        return result, 0 if result["valid"] else 1
    if a.loop_cmd == "passport":
        result = build_loop_passport(Path(a.root), Path(a.manifest))
        return result, 0 if result["verdict"] == "VERIFIED" else 1
    if a.loop_cmd == "verify":
        result = verify_loop_passport(Path(a.passport))
        return result, 0 if result["valid"] else 1
    result = evaluate_budget(Path(a.root), Path(a.manifest), Path(a.usage))
    return result, 0 if result["ok"] else 1


def _loop_error(exc: Exception) -> tuple[dict, int]:
    return {
        "schema": "factory.loop.result.v1",
        "verdict": "ERROR",
        "error": {"code": "E_INPUT", "message": str(exc)},
    }, 1


def _loop_output(a, result: dict, code: int) -> None:
    if a.json:
        print(json.dumps(result, indent=2))
    elif code == 0:
        print(f"Loop Passport: {result.get('verdict', 'WRITTEN')}")
        for name, path in result.get("paths", {}).items():
            print(f"  {name:<8}: {path}")
    else:
        print(json.dumps(result, indent=2), file=sys.stderr)


def _dispatch_route_group_41(a, capture_command, p):
    if a.cmd != "loop":
        return _UNHANDLED
    from .loop_passport import (
        build_loop_passport,
        evaluate_budget,
        init_loop,
        validate_manifest,
        verify_loop_passport,
    )

    try:
        result, code = _loop_action(
            a,
            init_loop,
            validate_manifest,
            build_loop_passport,
            verify_loop_passport,
            evaluate_budget,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result, code = _loop_error(exc)
    _loop_output(a, result, code)
    return code


def _dispatch_route_group_42(a, capture_command, p):
    if a.cmd == "passport":
        from .cli_artifacts import run as run_artifacts

        return run_artifacts(a)
    if a.cmd == "verify-passport":
        from .cli_artifacts import run as run_artifacts

        return run_artifacts(a)
    if a.cmd == "challenge":
        from .cli_artifacts import run as run_artifacts

        return run_artifacts(a)
    if a.cmd == "coverage":
        from .cli_artifacts import run as run_artifacts

        return run_artifacts(a)
    if a.cmd == "policy":
        from .cli_artifacts import run as run_artifacts

        return run_artifacts(a)
    if a.cmd in {"pr-pack", "optimize-pr"}:
        from .cli_pr import run as run_pr

        return run_pr(a)
    if a.cmd == "app":
        from .cli_app import run as run_app

        return run_app(a)
    return _UNHANDLED


def _dispatch(argv=None) -> int:
    """Parse FactoryLine commands, dispatch one handler, and return its process code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--version":
        return _emit_version("--json" in argv)
    # A captured command may legitimately contain flags that belong to the
    # child process.  Pull it out before argparse interprets those flags as
    # FactoryLine options.  ``--`` remains optional for a natural CLI shape.
    capture_command = None
    if argv[:1] == ["meter"] and "--capture" in argv:
        capture_index = argv.index("--capture")
        capture_command = argv[capture_index + 1 :]
        if capture_command[:1] == ["--"]:
            capture_command = capture_command[1:]
        argv = argv[:capture_index]
    p = _build_parser()
    a = p.parse_args(argv)

    result = _dispatch_routes(a, capture_command, p)
    if result is not _UNHANDLED:
        return result
    p.print_help()
    return 0


def main(argv=None) -> int:
    """Record one lifecycle receipt around the command dispatcher."""
    from .ops_telemetry import _root_from_argv, is_read_only_command, record_lifecycle

    started = time.monotonic()
    values = list(sys.argv[1:] if argv is None else argv)
    root = _root_from_argv(values, Path.cwd())
    read_only = is_read_only_command(values)
    try:
        code = int(_dispatch(values))
    except BaseException as exc:
        if not read_only:
            try:
                record_lifecycle(
                    root,
                    values,
                    started_monotonic=started,
                    exit_code=2,
                    status="error",
                    error_code=type(exc).__name__,
                )
            except Exception:
                pass
        raise
    if not read_only:
        try:
            record_lifecycle(
                root,
                values,
                started_monotonic=started,
                exit_code=code,
                status="completed" if code == 0 else "blocked",
            )
        except Exception:
            # Telemetry must never change the command's release semantics.
            pass
    return code


if __name__ == "__main__":
    sys.exit(main())

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

from .contract import MODULES, STAGES, ensure_layout, LAYOUT
from .assembly import detect, assemble, DEFAULT_CHAIN, rollup_receipts
from .continuation import ContinuationError, continue_assembly
from .run_metrics import export_public_metrics, public_metrics
from .telemetry import telemetry_inventory
from .agent_contract import AgentContractError, validate_agent_contract, validate_verifier_attestation
from .verifier_plane import (
    VerifierPlaneError,
    create_verifier_session,
    evaluate_progress,
    verify_verifier_result,
)
from .savings import (
    SavingsError,
    export_public_savings_report,
    public_savings_report,
    record_savings_pair,
)
from .proof_reuse import (
    ProofReuseError,
    challenge_proof_receipt,
    load_manifest as load_proof_manifest,
    plan_proofs,
    record_proof,
    verify_proof_receipt,
)
from .meter import live_snapshot, live_summary_table, overhead, summarize, summary_table
from .proof import (
    build_trace,
    execute_replay,
    export_attestations,
    git_changed_paths,
    load_trace,
    public_evidence,
    public_evidence_text,
    replay_plan,
    risk_for_paths,
    verify_trace,
)
from .optimizer import optimize_pr, pr_pack, write_policy
from .app_builder import STACKS, app_from_prd, app_from_prompt
from .target_compiler import (
    SUPPORTED_TRIGGERS,
    TARGETS,
    TargetCompileError,
    create_target_from_prd,
    create_target_from_prompt,
)
from .capability_packs import CapabilityPackError, builtin_packs, compose_packs, install_pack, validate_pack
from .failure_guidance import explain_failure
from .migration import (
    MigrationError,
    assess_migration_readiness,
    build_repository_context,
    verify_migration_readiness,
    verify_repository_context,
)
from .studio import StudioRequestError, serve_studio, studio_status
from .graph_ops import graph_ops_impact, graph_ops_snapshot
from .graph_portfolio import graph_portfolio_plan
from .graph_forensics import GraphForensicsError, graph_forensics, seal_graph_lineage, seal_mission_graph_lineage, verify_graph_lineage
from .langgraph_assurance import LangGraphAssuranceError, verify_langgraph_resume_parity
from .proofsearch import ProofSearchError, create_proofsearch_plan, evaluate_proofsearch, verify_proofsearch_evaluation
from .evidence_frontier import EvidenceFrontierError, plan_evidence_frontier, verify_evidence_frontier
from .coverage import requirement_coverage
from .change_review import ChangeReviewError, review_change, write_review_artifacts
from .continuous_proof import (
    ContinuousProofError,
    assess_continuous_proof,
    continuous_proof_history,
    verify_continuous_proof,
)
from .proof_review_workflow import (
    ProofReviewError,
    create_intent_contract,
    create_proof_card,
    create_quick_review,
    install_hook_pack,
    promote_regression,
    prove_trajectory,
    team_proof_inbox,
    verify_proof_card,
    verify_quick_review,
    verify_trajectory,
)
from .revenueforge import (
    RevenueForgeError,
    benchmark_cell,
    build_revenue_bundle,
    plan_growth,
    validate_products,
)
from .revenue_evidence import (
    evaluate_failure_matrix,
    promote_evidence_memory,
    query_evidence_memory,
    replay_purchase_journey,
    sync_testflight_evidence,
    watch_policy_drift,
)
from .appforge_design import compile_appforge_design
from .saas_proof import SaasProofError, saas_proof_projection, verify_saas_proof
from .developer_memory import developer_memory_brief
from .intent_ledger import IntentLedgerError, capture_intent_ledger, inspect_intent_ledger
from .judgment import JudgmentError, judgment_status, promote_capsule, propose_capsule, reconsider_capsule, safety_case
from .external_evidence import ExternalEvidenceError, diff_external_runtime_receipts, import_external_runtime_bundle
from .journey_proof import (
    JourneyProofError,
    compile_reality_graph,
    create_failure_capsule,
    journey_proof_status,
    verify_proof_gated_healing,
    verify_stateful_workflow,
)
from .github_proof_review import (
    GitHubProofReviewError,
    compile_github_proof_review,
    write_github_proof_review_artifacts,
)
from .plan_proof_review import PlanProofReviewError, review_plan_proof, write_plan_proof_review_artifacts
from .github_plan_proof_review import (
    GitHubPlanProofReviewError,
    compile_github_plan_proof_review,
    write_github_plan_proof_review_artifacts,
)
from .github_assurance_dossier import (
    GitHubAssuranceDossierError,
    build_assurance_dossier_from_paths,
    validate_policy_snapshot,
    write_assurance_dossier_artifacts,
)
from .e2e_proof import (
    E2EProofError,
    public_e2e_proof_receipt,
    verify_e2e_proof,
    write_e2e_proof_artifacts,
)
from .adoption import (
    AdoptionError,
    MILESTONES,
    adoption_status,
    export_adoption_status,
    proof_card_from_receipt,
    record_adoption_event,
    run_first_proof,
)
from .counterexample import CounterexampleError, compile_counterexample_plan, verify_counterexample_plan, write_counterexample_plan
from .guardrails import GuardrailError, evaluate_guardrails, verify_guardrail_evaluation
from .resilience import ResilienceError, compile_temporal_resilience_plan, verify_temporal_resilience_plan, write_temporal_resilience_plan
from .reality_check import RealityCheckError, inspect_reality_intent, run_reality_check, write_reality_check_artifacts
from .gauntlet import (
    GauntletError,
    admit_gauntlet,
    challenge_survival_card,
    compile_gauntlet_proposal,
    gauntlet_status,
    run_gauntlet,
    seal_survival_card,
    verify_gauntlet_proposal,
    verify_survival_card,
    write_gauntlet_proposal,
)
from .gauntlet_draft import GauntletDraftError, draft_gauntlet
from .agent_license import AgentLicenseError, derive_license, issue_license, record_governed_run, seal_license, verify_license
from .session_recorder import SessionRecorderError, run_observed_session
from .combine import CombineError, combine_projection, score_combine, seal_combine_scoreboard, seal_combine_task, verify_combine_scoreboard
from .team_pilot import (
    TeamPilotError,
    evaluate_team_pilot_readiness,
    validate_team_pilot_receipt,
    write_team_pilot_artifacts,
)
from .repair_sandbox import (
    RepairSandboxError,
    create_repair_scope,
    inspect_repair_candidate,
    write_repair_candidate_artifacts,
    write_repair_scope_artifacts,
)
from .workspace_advisor import (
    WorkspaceAdvisorError,
    inspect_workspace,
    write_workspace_advisor_artifacts,
)
from .index_continuity import (
    IndexContinuityError,
    capture_continuity_baseline,
    compare_continuity,
    write_continuity_baseline,
)
from .release_integrity import release_integrity, render_release_integrity
from .passport import build_passport, verify_passport
from .protocol import compatibility
from .verification import verify_feature
from .product_missions import (
    EXECUTORS,
    EVIDENCE_CLASSES,
    MISSION_DECISIONS,
    ProductMissionError,
    close_mission,
    compile_product_prd,
    create_mission,
    decide_mission,
    draft_pr,
    outcome_summary,
    plan_value_slices,
    record_outcome,
    verify_mission,
    verify_mission_completion,
    verify_product_graph,
)
from .prd_grill import grill_prd, verify_prd_grill
from .proof_delta import ProofDeltaError, create_proof_delta, proof_delta_status, verify_proof_delta
from .intake_grill import confirm_intake, grill_intake, intake_status, verify_intake_confirmation, verify_intake_grill
from .mission_graph import (
    MissionGraphError,
    apply_mission_event,
    export_mission_graph,
    init_mission_graph,
    langgraph_doctor,
    mission_graph_history,
    mission_graph_status,
    verify_mission_graph,
)
from .provider_router import (
    SUPPORTED_IDES,
    ProviderRouterError,
    create_provider_policy,
    provider_doctor,
    route_provider,
    verify_provider_policy,
)
from .signal_loop import (
    AUTHORIZATIONS,
    DECISIONS,
    SOURCES,
    SignalLoopError,
    capture_signal,
    capture_outcome_feedback,
    correct_opinion_dock,
    decide_triage,
    init_opinion_dock,
    promote_signal,
    triage_signal,
    verify_opinion_dock,
)
from .learning_loop import (
    LearningLoopError,
    build_fresh_worker_packet,
    init_learning_task,
    plan_learning_experiment,
    promote_instruction_candidate,
    propose_instruction_candidate,
    validate_instruction_candidate,
)


def _cli_command(name: str) -> str:
    """Prefer this launcher's script directory over an ambient PATH lookup."""
    script_dirs = [Path(sys.argv[0]).resolve().parent, Path(sys.executable).resolve().parent]
    for scripts in dict.fromkeys(script_dirs):
        for suffix in (".exe", ".cmd", ""):
            candidate = scripts / f"{name}{suffix}"
            if candidate.exists():
                return str(candidate)
    return name


def _emit_version(as_json: bool) -> int:
    from .provenance import provenance
    payload = provenance()
    print(json.dumps(payload, indent=2, sort_keys=True) if as_json else f"factory {payload['version']}")
    return 0


def _workflow_canary(module) -> dict:
    """Run a bounded, non-mutating behavior check rather than trusting --help."""
    if not module.installed:
        return {"ok": False, "reason": "cli not installed"}
    try:
        version = subprocess.run([_cli_command(module.cli), "--version", "--json"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"ok": False, "reason": type(error).__name__}
    if version.returncode != 0:
        return {"ok": False, "reason": "version command failed"}
    try:
        payload = json.loads(version.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "reason": "version command was not JSON"}
    required = {"package", "version", "build_hash", "install_origin", "runtime", "receipt_schema"}
    missing = sorted(name for name in required if not payload.get(name))
    if missing:
        return {"ok": False, "provenance_ok": False, "reason": f"incomplete provenance: {', '.join(missing)}", "provenance": payload}
    provenance_ok = bool(payload.get("identity_complete") and payload.get("source_commit"))
    if module.name != "forgeline":
        return {"ok": True, "provenance_ok": provenance_ok, "provenance": payload}
    with tempfile.TemporaryDirectory(prefix="factory-doctor-") as directory:
        root = Path(directory)
        (root / "services").mkdir()
        for suffix, source, args in (
            ("mjs", "/** Recall a verified value. */\nexport function recall(id) { return id; }\n", "[id]"),
            ("ts", "/** Recall a verified value. */\nexport function recall(id: string): string { return id; }\n", '["id: string"]'),
        ):
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
            result = subprocess.run([_cli_command(module.cli), "qa", f"canary-{suffix}", "--ssat", str(ssat), "--root", str(root), "--strict"], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return {"ok": False, "provenance_ok": provenance_ok, "reason": f"{suffix} feature canary failed", "output": (result.stdout + result.stderr)[-1000:], "provenance": payload}
            try:
                qa = json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"ok": False, "provenance_ok": provenance_ok, "reason": f"{suffix} feature canary was not JSON", "provenance": payload}
            if qa.get("metrics", {}).get("coverage_assessment") != "measured":
                return {"ok": False, "provenance_ok": provenance_ok, "reason": f"{suffix} symbols were not measured", "provenance": payload}
    return {"ok": True, "provenance_ok": provenance_ok, "provenance": payload, "canary": "mjs-and-ts-feature-qa"}


def _home(root: Path = Path("."), as_json: bool = False) -> int:
    """Return compact, live state for agents without requiring command discovery."""
    modules = detect()
    factory_root = root / ".factory"
    counts = {
        "receipts": len(list((factory_root / "receipts").glob("*.json"))) if factory_root.exists() else 0,
        "traces": len(list((factory_root / "traces").glob("*.json"))) if factory_root.exists() else 0,
        "challenges": len(list((factory_root / "challenges").glob("*.json"))) if factory_root.exists() else 0,
        "passports": len(list((factory_root / "passports").glob("*.json"))) if factory_root.exists() else 0,
        "loop_passports": len(list((factory_root / "loop-passports").glob("*.json"))) if factory_root.exists() else 0,
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
            "factory init ." if not factory_root.exists() else "factory evidence <feature>",
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


def _doctor(strict: bool = False, as_json: bool = False) -> int:
    mods = detect()
    checks = []
    for module in mods:
        help_text = None
        if module.installed:
            proc = subprocess.run([_cli_command(module.cli), "--help"], capture_output=True, text=True, timeout=20)
            help_text = proc.stdout + proc.stderr
        workflow = _workflow_canary(module)
        provenance = workflow.get("provenance") if isinstance(workflow.get("provenance"), dict) else {}
        reported_version = provenance.get("version") if isinstance(provenance.get("version"), str) else None
        check = compatibility(
            module.name,
            MODULES[module.name],
            help_text,
            reported_version=reported_version,
        )
        checks.append((check, workflow))
    if as_json:
        installation_ok = all(item[0].ok for item in checks)
        workflow_ok = all(item[1]["ok"] for item in checks)
        provenance_ok = all(item[1].get("provenance_ok", False) for item in checks)
        print(json.dumps({
            "ok": installation_ok and workflow_ok and provenance_ok,
            "installation_ok": installation_ok,
            "workflow_ok": workflow_ok,
            "provenance_ok": provenance_ok,
            "modules": [check.__dict__ | {"installation_ok": check.ok, "workflow": workflow} for check, workflow in checks],
        }, indent=2))
        return 0 if (installation_ok and workflow_ok and provenance_ok) or not strict else 1

    print("factoryline doctor - Lego assembly compatibility\n" + "=" * 48)
    for module, (check, workflow) in zip(mods, checks):
        mark = "compatible" if check.ok and workflow["ok"] and workflow.get("provenance_ok") else "provenance-incomplete" if check.ok and workflow["ok"] else "missing" if not check.installed else "workflow-failed" if check.ok else "incompatible"
        version = check.version or "not installed"
        print(f"  [{mark:>12}]  {module.name:<10} {version:<10} requires >= {check.minimum}")
        if check.missing_commands:
            print(f"                 missing commands: {', '.join(check.missing_commands)}")
        if not workflow["ok"]:
            print(f"                 workflow: {workflow['reason']}")
        elif not workflow.get("provenance_ok"):
            print("                 provenance: source identity is incomplete")
    failed = [check for check, workflow in checks if not check.ok or not workflow["ok"] or not workflow.get("provenance_ok")]
    if failed:
        print("\nInstall or upgrade incompatible bricks:")
        for item in failed:
            print(f"  pip install --upgrade {item.package}>={item.minimum}")
    else:
        print("\nAll four companion bricks plus FactoryLine satisfy the five-brick factory protocol.")
    return 1 if strict and failed else 0


def _plan() -> int:
    print("factoryline assembly pipeline\n" + "=" * 44)
    installed = {m.name: m.installed for m in detect()}
    for module, args in DEFAULT_CHAIN:
        cli = MODULES[module]["cli"]
        tag = "" if installed.get(module) else "   (skipped - not installed)"
        if module == "prestige":
            tag += "   (runs only when smoke/<feature>.ui declares UI scope)"
        print(f"  {module:<10} -> {cli} {' '.join(args)}{tag}")
    print("\nEach arrow is a Lego seam: the output of one stage is the input of the next,")
    print("passed on disk under the shared factory layout (portable across IDE/agent/OS).")
    return 0


def main(argv=None) -> int:
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
        capture_command = argv[capture_index + 1:]
        if capture_command[:1] == ["--"]:
            capture_command = capture_command[1:]
        argv = argv[:capture_index]
    p = argparse.ArgumentParser(prog="factory",
                                description="Snap SpecLine, ForgeLine, HSF and Prestige into one assembly line.")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("home", help="show compact live factory and proof state")
    s.add_argument("--root", default=".")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("doctor", help="show brick versions and command compatibility")
    s.add_argument("--strict", action="store_true")
    s.add_argument("--json", action="store_true")
    plan = sub.add_parser("plan", help="print the assembly pipeline or verify a human-approved agent plan")
    plan_sub = plan.add_subparsers(dest="plan_cmd")
    plan_verify = plan_sub.add_parser("verify", help="join an agent-plan envelope to local Diff-to-Proof facts without execution")
    plan_verify.add_argument("--plan", required=True, help="factory.agent_plan.v1 JSON path")
    plan_verify.add_argument("--root", default=".")
    plan_verify.add_argument("--base", default="main")
    plan_verify.add_argument("--changed", action="append", default=[], help="workspace-relative changed path; repeat as needed")
    plan_verify.add_argument("--out-dir", help="explicit local directory for JSON, Markdown, and Mermaid review artifacts")
    plan_verify.add_argument("--json", action="store_true")

    e2e = sub.add_parser("e2e", help="run a native proof-by-sabotage E2E command pair")
    e2e_sub = e2e.add_subparsers(required=True, dest="e2e_cmd")
    e2e_verify = e2e_sub.add_parser("verify", help="run approved positive and negative argv commands without vendor access")
    e2e_verify.add_argument("--root", default=".")
    e2e_verify.add_argument("--manifest", required=True, help="workspace-contained factory.e2e_proof_manifest.v1 JSON path")
    e2e_verify.add_argument("--out-dir", help="explicit local directory for receipt, Mermaid, and captured output artifacts")
    e2e_verify.add_argument("--json", action="store_true")

    external = sub.add_parser("external", help="import and compare offline external runtime evidence")
    external_sub = external.add_subparsers(required=True, dest="external_cmd")
    external_import = external_sub.add_parser("import", help="verify one provider bundle and write an observed-only receipt")
    external_import.add_argument("bundle", help="workspace-contained factory.external-runtime-bundle.v1 JSON path")
    external_import.add_argument("--root", default=".")
    external_import.add_argument("--provider", required=True, help="declared adapter id, for example testsprite")
    external_import.add_argument("--out", help="receipt path below .factory/external-evidence/")
    external_import.add_argument("--json", action="store_true")
    external_diff = external_sub.add_parser("diff", help="compare two verified receipts without provider execution")
    external_diff.add_argument("left", help="left receipt path")
    external_diff.add_argument("right", help="right receipt path")
    external_diff.add_argument("--root", default=".")
    external_diff.add_argument("--json", action="store_true")

    journey = sub.add_parser("journey", help="prove runtime journeys, stateful workflows, failures, and bounded healing")
    journey_sub = journey.add_subparsers(required=True, dest="journey_cmd")
    journey_reality = journey_sub.add_parser("reality", help="compare declared and observed journey graphs without inference")
    journey_reality.add_argument("declaration", help="factory.journey-declaration.v1 JSON path")
    journey_reality.add_argument("observation", help="factory.journey-observation.v1 JSON path")
    journey_reality.add_argument("--root", default=".")
    journey_reality.add_argument("--out", help="receipt path below .factory/journey-proof/")
    journey_reality.add_argument("--json", action="store_true")
    journey_capsule = journey_sub.add_parser("capsule", help="bind a failed step and adjacent evidence into JSON and Markdown")
    journey_capsule.add_argument("input", help="factory.failure-capsule-input.v1 JSON path")
    journey_capsule.add_argument("--root", default=".")
    journey_capsule.add_argument("--out", help="receipt path below .factory/journey-proof/")
    journey_capsule.add_argument("--json", action="store_true")
    journey_workflow = journey_sub.add_parser("workflow-proof", help="prove state flow, cleanup, and idempotency")
    journey_workflow.add_argument("input", help="factory.stateful-workflow-input.v1 JSON path")
    journey_workflow.add_argument("--root", default=".")
    journey_workflow.add_argument("--out", help="receipt path below .factory/journey-proof/")
    journey_workflow.add_argument("--json", action="store_true")
    journey_healing = journey_sub.add_parser("heal-verify", help="challenge a repair under human or supervised-auto review")
    journey_healing.add_argument("input", help="factory.proof-gated-healing-input.v1 JSON path")
    journey_healing.add_argument("--root", default=".")
    journey_healing.add_argument("--out", help="receipt path below .factory/journey-proof/")
    journey_healing.add_argument("--timeout-seconds", type=int, default=300)
    journey_healing.add_argument("--json", action="store_true")
    journey_status_parser = journey_sub.add_parser("status", help="read verified local Journey Proof receipts without execution")
    journey_status_parser.add_argument("--root", default=".")
    journey_status_parser.add_argument("--json", action="store_true")

    first_proof = sub.add_parser("first-proof", help="run a local sandbox demonstration that catches an intentionally hollow check")
    first_proof.add_argument("--root", default=".")
    first_proof.add_argument("--out-dir", help="optional workspace-contained output directory")
    first_proof.add_argument("--json", action="store_true")

    proof_card = sub.add_parser("proof-card", help="create a privacy-safe share card from one verified local E2E receipt")
    proof_card.add_argument("receipt", help="workspace-contained factory.e2e_proof_receipt.v1 JSON path")
    proof_card.add_argument("--root", default=".")
    proof_card.add_argument("--out-dir", default=".factory/share", help="workspace-contained Proof Card output directory")
    proof_card.add_argument("--json", action="store_true")

    adoption = sub.add_parser("adoption", help="record and inspect local opt-in activation milestones without central telemetry")
    adoption_sub = adoption.add_subparsers(required=True, dest="adoption_cmd")
    adoption_status_parser = adoption_sub.add_parser("status", help="read local aggregate activation milestones")
    adoption_status_parser.add_argument("--root", default=".")
    adoption_status_parser.add_argument("--json", action="store_true")
    adoption_record = adoption_sub.add_parser("record", help="record one explicit local activation milestone")
    adoption_record.add_argument("milestone", choices=sorted(MILESTONES))
    adoption_record.add_argument("--root", default=".")
    adoption_record.add_argument("--evidence-sha256")
    adoption_record.add_argument("--json", action="store_true")
    adoption_export = adoption_sub.add_parser("export", help="write an aggregate, identity-free activation status receipt")
    adoption_export.add_argument("--root", default=".")
    adoption_export.add_argument("--out", required=True)
    adoption_export.add_argument("--json", action="store_true")

    counterexample = sub.add_parser("counterexample", help="compile and verify deterministic negative-proof obligations without execution")
    counterexample_sub = counterexample.add_subparsers(required=True, dest="counterexample_cmd")
    counterexample_plan = counterexample_sub.add_parser("plan", help="compile one hash-sealed negative-proof plan from bounded requirements")
    counterexample_plan.add_argument("source", help="workspace-contained factory.counterexample-source.v1 JSON path")
    counterexample_plan.add_argument("--root", default=".")
    counterexample_plan.add_argument("--out", required=True, help="explicit plan output path")
    counterexample_plan.add_argument("--json", action="store_true")
    counterexample_verify = counterexample_sub.add_parser("verify", help="fail closed for tampered, stale, or incomplete negative-proof plans")
    counterexample_verify.add_argument("plan", help="workspace-contained factory.counterexample-plan.v1 JSON path")
    counterexample_verify.add_argument("--root", default=".")
    counterexample_verify.add_argument("--json", action="store_true")

    guardrail = sub.add_parser("guardrail", help="evaluate promoted continuity metadata as redacted local guardrails")
    guardrail_sub = guardrail.add_subparsers(required=True, dest="guardrail_cmd")
    guardrail_evaluate = guardrail_sub.add_parser("evaluate", help="read promoted exact-scope metadata without retrieving memory content")
    guardrail_evaluate.add_argument("manifest", help="factory.guardrail-manifest.v1 JSON path")
    guardrail_evaluate.add_argument("--db", required=True, help="existing local continuity database")
    guardrail_evaluate.add_argument("--tenant", required=True)
    guardrail_evaluate.add_argument("--subject", required=True)
    guardrail_evaluate.add_argument("--roles", default="reader", help="comma-separated local roles; values are not authenticated identity")
    guardrail_evaluate.add_argument("--purposes", required=True, help="comma-separated exact purpose references")
    guardrail_evaluate.add_argument("--changed", action="append", required=True, help="workspace-relative changed path; repeat as needed")
    guardrail_evaluate.add_argument("--json", action="store_true")
    guardrail_verify = guardrail_sub.add_parser("verify", help="verify an evaluation hash and no-content redaction boundary")
    guardrail_verify.add_argument("evaluation", help="factory.guardrail-evaluation.v1 JSON path")
    guardrail_verify.add_argument("--json", action="store_true")

    resilience = sub.add_parser("resilience", help="derive bounded temporal fault schedules from sealed graph lineage without execution")
    resilience_sub = resilience.add_subparsers(required=True, dest="resilience_cmd")
    resilience_plan = resilience_sub.add_parser("plan", help="compile read-only stale, replay, and concurrency fault schedules")
    resilience_plan.add_argument("lineage", help="workspace-contained factory.graph-lineage.v1 JSON path")
    resilience_plan.add_argument("--root", default=".")
    resilience_plan.add_argument("--out", required=True, help="explicit plan output path")
    resilience_plan.add_argument("--json", action="store_true")
    resilience_verify = resilience_sub.add_parser("verify", help="fail closed for tampered, stale, or incomplete temporal schedules")
    resilience_verify.add_argument("plan", help="workspace-contained factory.temporal-resilience-plan.v1 JSON path")
    resilience_verify.add_argument("--root", default=".")
    resilience_verify.add_argument("--json", action="store_true")

    reality = sub.add_parser("reality", help="run one approved behavior promise through a supervised local proof pair")
    reality_sub = reality.add_subparsers(required=True, dest="reality_cmd")
    reality_verify = reality_sub.add_parser("verify", help="bind an approved happy and negative check to one product behavior")
    reality_verify.add_argument("--root", default=".")
    reality_verify.add_argument("--manifest", required=True, help="workspace-contained factory.reality-check-manifest.v1 JSON path")
    reality_verify.add_argument("--out-dir", help="explicit local directory for public receipt, Markdown, and Mermaid artifacts")
    reality_verify.add_argument("--json", action="store_true")
    reality_inspect = reality_sub.add_parser("inspect", help="validate declared positive and negative intent assertions without execution")
    reality_inspect.add_argument("--root", default=".")
    reality_inspect.add_argument("--manifest", required=True, help="workspace-contained factory.reality-check-manifest.v1 JSON path")
    reality_inspect.add_argument("--json", action="store_true")

    wrap = sub.add_parser("wrap", help="run any admitted local agent CLI as an observed, validated evidence session")
    wrap.add_argument("--root", default=".")
    wrap.add_argument("--admission", required=True, help="READY factory.run-admission.packet.v1 path")
    wrap.add_argument("--validators", required=True, help="factory.session-recorder.validators.v1 path")
    wrap.add_argument("--run-id", required=True, help="unique lowercase immutable event id")
    wrap.add_argument("--json", action="store_true")
    wrap.add_argument("command", nargs=argparse.REMAINDER, help="agent command argv after --")

    gauntlet = sub.add_parser("gauntlet", help="draft, compile, admit, run, and verify a supervised proof-of-survival batch")
    gauntlet_sub = gauntlet.add_subparsers(required=True, dest="gauntlet_cmd")
    gauntlet_draft = gauntlet_sub.add_parser("draft", help="statically propose inert promise and E2E drafts from repository structure")
    gauntlet_draft.add_argument("--root", default=".")
    gauntlet_draft.add_argument("--source-id", required=True)
    gauntlet_draft.add_argument("--json", action="store_true")
    gauntlet_plan = gauntlet_sub.add_parser("plan", help="compile declared promise sabotages from human-written E2E manifests without execution")
    gauntlet_plan.add_argument("--root", default=".")
    gauntlet_plan.add_argument("--source", required=True, help="workspace-contained factory.gauntlet-source.v1 JSON path")
    gauntlet_plan.add_argument("--out", help="optional workspace-contained proposal output path")
    gauntlet_plan.add_argument("--json", action="store_true")
    gauntlet_admit = gauntlet_sub.add_parser("admit", help="seal one named, expiring admission for an exact current proposal")
    gauntlet_admit.add_argument("proposal", help="workspace-contained factory.gauntlet-proposal.v1 JSON path")
    gauntlet_admit.add_argument("--root", default=".")
    gauntlet_admit.add_argument("--approved-by", required=True)
    gauntlet_admit.add_argument("--rationale", required=True)
    gauntlet_admit.add_argument("--confirmation", required=True, help="exact confirmation phrase shown by the proposal source id")
    gauntlet_admit.add_argument("--valid-for-minutes", type=int, default=30)
    gauntlet_admit.add_argument("--out", help="optional workspace-contained admission output path")
    gauntlet_admit.add_argument("--json", action="store_true")
    gauntlet_run = gauntlet_sub.add_parser("run", help="run only one current, named-admitted local E2E sabotage batch")
    gauntlet_run.add_argument("proposal", help="workspace-contained factory.gauntlet-proposal.v1 JSON path")
    gauntlet_run.add_argument("--root", default=".")
    gauntlet_run.add_argument("--admission", help="workspace-contained factory.gauntlet-admission.v1 JSON path")
    gauntlet_run.add_argument("--out", help="optional workspace-contained Survival Card output path")
    gauntlet_run.add_argument("--json", action="store_true")
    gauntlet_card = gauntlet_sub.add_parser("card", help="verify, challenge, or optionally DSSE-seal an existing Survival Card")
    gauntlet_card_sub = gauntlet_card.add_subparsers(required=True, dest="gauntlet_card_cmd")
    gauntlet_card_verify = gauntlet_card_sub.add_parser("verify", help="verify one card offline and optionally its exact DSSE binding")
    gauntlet_card_verify.add_argument("card")
    gauntlet_card_verify.add_argument("--envelope")
    gauntlet_card_verify.add_argument("--trust-root")
    gauntlet_card_verify.add_argument("--json", action="store_true")
    gauntlet_card_challenge = gauntlet_card_sub.add_parser("challenge", help="prove the card verifier rejects a changed summary without editing the card")
    gauntlet_card_challenge.add_argument("card")
    gauntlet_card_challenge.add_argument("--json", action="store_true")
    gauntlet_card_seal = gauntlet_card_sub.add_parser("seal", help="optionally bind one card to a Receipt v2 DSSE envelope")
    gauntlet_card_seal.add_argument("card")
    gauntlet_card_seal.add_argument("--private-key", required=True)
    gauntlet_card_seal.add_argument("--keyid", required=True)
    gauntlet_card_seal.add_argument("--identity", required=True)
    gauntlet_card_seal.add_argument("--issuer", required=True)
    gauntlet_card_seal.add_argument("--tenant", default="local")
    gauntlet_card_seal.add_argument("--out", required=True)
    gauntlet_card_seal.add_argument("--json", action="store_true")
    gauntlet_status_parser = gauntlet_sub.add_parser("status", help="read local Survival Card facts without execution")
    gauntlet_status_parser.add_argument("--root", default=".")
    gauntlet_status_parser.add_argument("--source-id")
    gauntlet_status_parser.add_argument("--json", action="store_true")

    license_parser = sub.add_parser("license", help="derive and verify expiring, evidence-governed local agent autonomy tiers")
    license_sub = license_parser.add_subparsers(required=True, dest="license_cmd")
    license_record = license_sub.add_parser("record", help="record one already-admitted, independently verified governed run")
    license_record.add_argument("event", help="workspace-contained factory.agent-run.v1 JSON path")
    license_record.add_argument("--root", default=".")
    license_record.add_argument("--out-dir", help="optional workspace-contained immutable event directory")
    license_record.add_argument("--json", action="store_true")
    license_status = license_sub.add_parser("status", help="derive read-only current license facts for one declared agent identity")
    license_status.add_argument("--agent", required=True, help="workspace-contained factory.agent-identity.v1 JSON path")
    license_status.add_argument("--root", default=".")
    license_status.add_argument("--json", action="store_true")
    license_issue = license_sub.add_parser("issue", help="write one locally hash-bound license derived from current governed evidence")
    license_issue.add_argument("--agent", required=True, help="workspace-contained factory.agent-identity.v1 JSON path")
    license_issue.add_argument("--root", default=".")
    license_issue.add_argument("--out", help="optional workspace-contained license JSON path")
    license_issue.add_argument("--json", action="store_true")
    license_verify = license_sub.add_parser("verify", help="verify one existing local license hash offline")
    license_verify.add_argument("license")
    license_verify.add_argument("--json", action="store_true")
    license_seal = license_sub.add_parser("seal", help="optionally bind one verified license to a Receipt v2 DSSE envelope")
    license_seal.add_argument("license")
    license_seal.add_argument("--private-key", required=True)
    license_seal.add_argument("--keyid", required=True)
    license_seal.add_argument("--identity", required=True)
    license_seal.add_argument("--issuer", required=True)
    license_seal.add_argument("--tenant", default="local")
    license_seal.add_argument("--out", required=True)
    license_seal.add_argument("--json", action="store_true")

    combine = sub.add_parser("combine", help="seal and compare completed governed agent evidence without launching an agent")
    combine_sub = combine.add_subparsers(required=True, dest="combine_cmd")
    combine_task = combine_sub.add_parser("task", help="seal a human-written task declaration; the description stays hashed")
    combine_task.add_argument("source", help="workspace-contained factory.combine-task.v1 JSON path")
    combine_task.add_argument("--root", default=".")
    combine_task.add_argument("--out", help="optional workspace-contained sealed task JSON path")
    combine_task.add_argument("--json", action="store_true")
    combine_score = combine_sub.add_parser("score", help="rank existing exact governed run events for one sealed task")
    combine_score.add_argument("task", help="workspace-contained sealed Combine task JSON path")
    combine_score.add_argument("--event", action="append", default=[], help="optional exact immutable governed event path; repeat for each candidate")
    combine_score.add_argument("--root", default=".")
    combine_score.add_argument("--out", help="optional workspace-contained scoreboard JSON path")
    combine_score.add_argument("--json", action="store_true")
    combine_status = combine_sub.add_parser("status", help="read locally verified Combine scoreboards without execution")
    combine_status.add_argument("--root", default=".")
    combine_status.add_argument("--json", action="store_true")
    combine_verify = combine_sub.add_parser("verify", help="verify one Combine scoreboard hash offline")
    combine_verify.add_argument("scoreboard")
    combine_verify.add_argument("--json", action="store_true")
    combine_seal = combine_sub.add_parser("seal", help="optionally bind one verified Combine scoreboard to a Receipt v2 DSSE envelope")
    combine_seal.add_argument("scoreboard")
    combine_seal.add_argument("--private-key", required=True)
    combine_seal.add_argument("--keyid", required=True)
    combine_seal.add_argument("--identity", required=True)
    combine_seal.add_argument("--issuer", required=True)
    combine_seal.add_argument("--tenant", default="local")
    combine_seal.add_argument("--out", required=True)
    combine_seal.add_argument("--json", action="store_true")

    team_pilot = sub.add_parser("team-pilot", help="validate customer-managed Team Pilot readiness without commercial activation")
    team_pilot_sub = team_pilot.add_subparsers(required=True, dest="team_pilot_cmd")
    team_pilot_readiness = team_pilot_sub.add_parser("readiness", help="hash-bind selected-partner and operating evidence for owner review")
    team_pilot_readiness.add_argument("--root", default=".")
    team_pilot_readiness.add_argument("--manifest", required=True, help="workspace-contained factory.team-pilot-launch.v1 JSON path")
    team_pilot_readiness.add_argument("--out-dir", help="explicit local directory for public receipt, Markdown, and Mermaid artifacts")
    team_pilot_readiness.add_argument("--json", action="store_true")
    team_pilot_verify = team_pilot_sub.add_parser("verify", help="verify a hash-bound Team Pilot readiness receipt")
    team_pilot_verify.add_argument("receipt")
    team_pilot_verify.add_argument("--json", action="store_true")

    s = sub.add_parser("init", help="create the shared factory layout")
    s.add_argument("root", nargs="?", default=".")

    s = sub.add_parser("assemble", help="run the assembly line for a feature")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--dry-run", action="store_true")

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
    record = savings_sub.add_parser("record", help="record one baseline-versus-Factory pair")
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
    report = savings_sub.add_parser("report", help="show or export aggregate-safe savings")
    report.add_argument("--root", default=".")
    report.add_argument("--out")
    report.add_argument("--json", action="store_true")

    s = sub.add_parser("update-check", help="report whether a newer release exists; installs nothing")
    s.add_argument("--root", default=".")
    s.add_argument("--force", action="store_true", help="ignore the 24h cache")
    s.add_argument("--json", action="store_true")

    # Habituation: thin delegates only; logic lives in factoryline/habituation.py.
    s = sub.add_parser("habituation", help="calibrate the human approval signal instead of trusting it")
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
    hab_status = hab_sub.add_parser("status", help="evaluate the gate and show the intervention")
    hab_status.add_argument("--root", default=".")
    hab_status.add_argument("--allow-block", action="store_true",
                            help="permit fail-closed; refused until blind-spot outcomes exist")
    hab_status.add_argument("--json", action="store_true")
    hab_sample = hab_sub.add_parser("sample", help="select low-scrutiny approvals for independent re-review")
    hab_sample.add_argument("--root", default=".")
    hab_sample.add_argument("--rate", type=int, default=10)
    hab_sample.add_argument("--json", action="store_true")
    hab_resample = hab_sub.add_parser("resample", help="record what an independent re-review found")
    hab_resample.add_argument("review_id")
    hab_resample.add_argument("--root", default=".")
    hab_resample.add_argument("--reviewer", required=True)
    hab_resample.add_argument("--defect-found", action="store_true")
    hab_resample.add_argument("--notes", default="")
    hab_resample.add_argument("--json", action="store_true")
    hab_report = hab_sub.add_parser("report", help="show or export the aggregate-safe public report")
    hab_report.add_argument("--root", default=".")
    hab_report.add_argument("--out")
    hab_report.add_argument("--enable-defect-linkage", action="store_true",
                            help="opt in to the modeled correlation; read its assumptions first")

    # CDTE: thin delegates only. Logic lives in factoryline/cdte.py — cli.py is
    # already the largest module in the package and the architecture gate flags it.
    s = sub.add_parser("cdte", help="detect NFR contradictions before any code is generated")
    cdte_sub = s.add_subparsers(dest="cdte_cmd")
    scan = cdte_sub.add_parser("scan", help="scan extracted NFR constraints for lethal pairs")
    scan.add_argument("run_id")
    scan.add_argument("constraints", help="path to a JSON file of extracted NFR constraints")
    scan.add_argument("--root", default=".")
    scan.add_argument("--evidence", help="benchmark file to hash-bind, promoting modeled proofs to measured")
    scan.add_argument("--adr", action="store_true", help="draft an ADR for each detected conflict")
    scan.add_argument("--replace", action="store_true")
    scan.add_argument("--json", action="store_true")
    cdte_report = cdte_sub.add_parser("report", help="show or export aggregate-safe conflict statistics")
    cdte_report.add_argument("--root", default=".")
    cdte_report.add_argument("--out")
    cdte_report.add_argument("--json", action="store_true")
    resolve = cdte_sub.add_parser("resolve", help="record an ADR decision or an expiring override")
    resolve.add_argument("run_id")
    resolve.add_argument("conflict_id")
    resolve.add_argument("--root", default=".")
    resolve.add_argument("--decision", required=True)
    resolve.add_argument("--approved-by", required=True)
    resolve.add_argument("--adr-path")
    resolve.add_argument("--override", action="store_true",
                         help="accept the contradiction; requires --expires")
    resolve.add_argument("--expires", help="ISO date after which the override lapses")
    resolve.add_argument("--json", action="store_true")

    s = sub.add_parser("proofs", help="record and route content-addressed read-only proof receipts")
    proofs_sub = s.add_subparsers(dest="proofs_cmd")
    proof_record = proofs_sub.add_parser("record", help="record one completed green proof from a request manifest")
    proof_record.add_argument("manifest")
    proof_record.add_argument("--gate", help="gate name; required when the manifest contains multiple gates")
    proof_record.add_argument("--root", default=".")
    proof_record.add_argument("--elapsed-ms", type=int, required=True)
    proof_record.add_argument("--tokens", type=int)
    proof_record.add_argument("--replace", action="store_true")
    proof_record.add_argument("--json", action="store_true")
    proof_plan = proofs_sub.add_parser("plan", help="route requested gates to RUN, REUSE, SKIP, or BLOCK")
    proof_plan.add_argument("manifest")
    proof_plan.add_argument("--root", default=".")
    proof_plan.add_argument("--changed", action="append", default=[])
    proof_plan.add_argument("--auto-savings", action="store_true")
    proof_plan.add_argument("--out")
    proof_plan.add_argument("--json", action="store_true")
    proof_verify = proofs_sub.add_parser("verify", help="verify a private proof receipt and all current hashes")
    proof_verify.add_argument("receipt")
    proof_verify.add_argument("--root", default=".")
    proof_verify.add_argument("--json", action="store_true")
    proof_challenge = proofs_sub.add_parser("challenge", help="prove an isolated input mutation invalidates reuse")
    proof_challenge.add_argument("receipt")
    proof_challenge.add_argument("--root", default=".")
    proof_challenge.add_argument("--json", action="store_true")

    s = sub.add_parser("verify", help="summarize all existing receipts into one shippability decision")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("meter", help="real savings summary from your runs")
    s.add_argument("--root", default=".")
    s.add_argument("--runs", type=int, default=1000, help="projected production runs")
    s.add_argument("--baseline", type=int, default=4000, help="baseline tokens per run (declare your real agent cost)")
    s.add_argument("--json", action="store_true", help="emit a machine-readable current snapshot")
    s.add_argument("--watch", action="store_true", help="refresh the local meter as new stages finish")
    s.add_argument("--interval", type=float, default=1.0, help="watch refresh interval in seconds")
    s.add_argument("--max-updates", type=int, default=None, help="stop after N snapshots (useful for automation)")
    s.add_argument("--feature", default="local-observation", help="feature label for a captured local command")
    s.add_argument("--module", default="local", help="module label for a captured local command")
    s.add_argument("--stage", default="command", help="stage label for a captured local command")
    s.add_argument("--capture", action="store_true", help="run a command and append its measured local wall time")

    s = sub.add_parser("overhead", help="show measured wall-clock overhead per gate")
    s.add_argument("--root", default=".")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("override", help="record an owned, expiring exception without hiding a failed gate")
    s.add_argument("issue")
    s.add_argument("--root", default=".")
    s.add_argument("--reason", required=True)
    s.add_argument("--approved-by", required=True)
    s.add_argument("--expires", default=None)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("receipt", help="sign or verify factory receipts with Sigstore identity")
    receipt_sub = s.add_subparsers(required=True, dest="receipt_cmd")
    receipt_sign = receipt_sub.add_parser("sign", help="keylessly sign a receipt with Sigstore")
    receipt_sign.add_argument("path")
    receipt_sign.add_argument("--overwrite", action="store_true")
    receipt_sign.add_argument("--timeout", type=int, default=300)
    receipt_verify = receipt_sub.add_parser("verify", help="verify receipt bytes and expected OIDC identity")
    receipt_verify.add_argument("path")
    receipt_verify.add_argument("--cert-identity", required=True)
    receipt_verify.add_argument("--cert-oidc-issuer", required=True)
    receipt_verify.add_argument("--timeout", type=int, default=300)
    receipt_status = receipt_sub.add_parser("status", help="report signature presence or UNSIGNED without claiming verification")
    receipt_status.add_argument("path")

    s = sub.add_parser("verify-receipts", help="challenge the offline Receipt v2 verification chain")
    s.add_argument("--root", default=".")
    s.add_argument("--out")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("enterprise", help="create and verify offline Receipt v2 evidence")
    enterprise_sub = s.add_subparsers(required=True, dest="enterprise_cmd")
    keygen = enterprise_sub.add_parser("keygen", help="generate Ed25519 key material and a local trust root")
    keygen.add_argument("--out-dir", required=True)
    keygen.add_argument("--keyid", required=True)
    keygen.add_argument("--identity", required=True)
    keygen.add_argument("--issuer", required=True)
    seal = enterprise_sub.add_parser("receipt-seal", help="sign a Receipt v2 payload into a DSSE envelope")
    seal.add_argument("payload")
    seal.add_argument("--private-key", required=True)
    seal.add_argument("--keyid", required=True)
    seal.add_argument("--identity", required=True)
    seal.add_argument("--issuer", required=True)
    seal.add_argument("--out", required=True)
    verify = enterprise_sub.add_parser("verify", help="verify Receipt v2, policy, and revocation evidence offline")
    verify.add_argument("envelope")
    verify.add_argument("--trust-root", required=True)
    verify.add_argument("--policy-bundle")
    verify.add_argument("--revocations")
    policy = enterprise_sub.add_parser("policy-sign", help="sign a policy JSON document into a policy bundle")
    policy.add_argument("policy")
    policy.add_argument("--private-key", required=True)
    policy.add_argument("--keyid", required=True)
    policy.add_argument("--identity", required=True)
    policy.add_argument("--issuer", required=True)
    policy.add_argument("--out", required=True)
    revocations = enterprise_sub.add_parser("revocations-sign", help="sign a revocation entries JSON array")
    revocations.add_argument("entries")
    revocations.add_argument("--private-key", required=True)
    revocations.add_argument("--keyid", required=True)
    revocations.add_argument("--identity", required=True)
    revocations.add_argument("--issuer", required=True)
    revocations.add_argument("--out", required=True)

    s = sub.add_parser("control", help="manage local tenant-scoped evidence and approvals")
    control_sub = s.add_subparsers(required=True, dest="control_cmd")
    control_init = control_sub.add_parser("init", help="create a local evidence database")
    control_init.add_argument("--db", required=True)
    control_serve = control_sub.add_parser("serve", help="serve the local REST adapter for integration testing")
    control_serve.add_argument("--db", required=True)
    control_serve.add_argument("--host", default="127.0.0.1")
    control_serve.add_argument("--port", type=int, default=8765)

    def add_control_identity(parser, *, default_role: str):
        parser.add_argument("--db", required=True)
        parser.add_argument("--tenant", required=True)
        parser.add_argument("--subject", required=True)
        parser.add_argument("--roles", default=default_role, help="comma-separated local roles")

    evidence_put = control_sub.add_parser("evidence-put", help="store immutable tenant-scoped evidence")
    evidence_put.add_argument("payload")
    evidence_put.add_argument("--evidence-id")
    add_control_identity(evidence_put, default_role="operator")
    evidence_get = control_sub.add_parser("evidence-get", help="read one evidence record")
    evidence_get.add_argument("evidence_id")
    add_control_identity(evidence_get, default_role="viewer")
    evidence_list = control_sub.add_parser("evidence-list", help="list evidence for one tenant")
    add_control_identity(evidence_list, default_role="viewer")
    approval_request = control_sub.add_parser("approval-request", help="request independent human approval")
    approval_request.add_argument("evidence_id")
    approval_request.add_argument("--reason", required=True)
    add_control_identity(approval_request, default_role="operator")
    approval_decide = control_sub.add_parser("approval-decide", help="approve or reject a pending request")
    approval_decide.add_argument("approval_id")
    approval_decide.add_argument("--decision", required=True, choices=["approved", "rejected"])
    approval_decide.add_argument("--reason", required=True)
    add_control_identity(approval_decide, default_role="approver")
    audit_verify = control_sub.add_parser("audit-verify", help="verify the tenant audit hash chain")
    add_control_identity(audit_verify, default_role="viewer")

    continuity = sub.add_parser("continuity", help="govern local proof-carrying engineering-memory references")
    continuity_sub = continuity.add_subparsers(required=True, dest="continuity_cmd")
    continuity_init = continuity_sub.add_parser("init", help="create a local Factory Continuity metadata ledger")
    continuity_init.add_argument("--db", required=True)

    def add_continuity_identity(parser, *, default_role: str):
        parser.add_argument("--db", required=True)
        parser.add_argument("--tenant", required=True)
        parser.add_argument("--subject", required=True)
        parser.add_argument("--roles", default=default_role, help="comma-separated local roles; CLI values are not authenticated identity")
        parser.add_argument("--purposes", required=True, help="comma-separated exact purpose references, e.g. delivery-review@1")

    continuity_record = continuity_sub.add_parser("record", help="atomically record one draft memory reference and its audit event")
    continuity_record.add_argument("payload", help="metadata-only continuity record JSON; memory contents are rejected")
    continuity_record.add_argument("--idempotency-key", required=True)
    continuity_record.add_argument("--record-id")
    add_continuity_identity(continuity_record, default_role="writer")
    continuity_recall = continuity_sub.add_parser("recall", help="recall only verified, current, exact-scope purpose-authorized records")
    continuity_recall.add_argument("--purpose", required=True, help="exact purpose reference, e.g. delivery-review@1")
    continuity_recall.add_argument("--scope", required=True, help="exact opaque repository scope reference")
    add_continuity_identity(continuity_recall, default_role="reader")
    continuity_promote = continuity_sub.add_parser("promote", help="independently promote one evidence-bound draft record")
    continuity_promote.add_argument("record_id")
    continuity_promote.add_argument("--reason", required=True)
    add_continuity_identity(continuity_promote, default_role="promoter")
    continuity_prove = continuity_sub.add_parser("prove", help="show local unsigned lineage for one record without mutation authority")
    continuity_prove.add_argument("record_id")
    add_continuity_identity(continuity_prove, default_role="reader")
    continuity_status = continuity_sub.add_parser("status", help="show bounded local continuity ledger state")
    continuity_status.add_argument("--db", required=True)

    s = sub.add_parser("assurance", help="produce deterministic assurance artifacts")
    assurance_sub = s.add_subparsers(required=True, dest="assurance_cmd")
    graph = assurance_sub.add_parser("graph", help="build a tenant-scoped evidence graph")
    graph.add_argument("records")
    graph.add_argument("--tenant", required=True)
    graph.add_argument("--out", required=True)
    sbom = assurance_sub.add_parser("sbom", help="build a sorted CycloneDX-shaped SBOM")
    sbom.add_argument("components")
    sbom.add_argument("--out", required=True)
    vex = assurance_sub.add_parser("vex", help="build a validated VEX artifact")
    vex.add_argument("entries")
    vex.add_argument("--out", required=True)
    mutation = assurance_sub.add_parser("policy-mutate", help="emit explicit policy mutations for a challenge run")
    mutation.add_argument("policy")
    mutation.add_argument("--out", required=True)

    s = sub.add_parser("verify-policy", help="prove a policy evaluator catches every delete/invert mutation")
    s.add_argument("--root", default=".")
    s.add_argument("--policy", default="factory.policy.json")
    s.add_argument("--challenge", required=True, help="JSON manifest with argv command containing {policy}")
    s.add_argument("--out", help="receipt output; defaults under .factory/policy-challenges")

    s = sub.add_parser("compliance", help="export versioned non-certifying compliance evidence")
    compliance_sub = s.add_subparsers(required=True, dest="compliance_cmd")
    compliance_sub.add_parser("packs", help="list available control packs")
    compliance_export = compliance_sub.add_parser("export", help="write an OSCAL-shaped assessment")
    compliance_export.add_argument("pack")
    compliance_export.add_argument("evidence")
    compliance_export.add_argument("--tenant", required=True)
    compliance_export.add_argument("--out", required=True)
    compliance_export.add_argument("--controls", help="reviewed customer control JSON array")

    s = sub.add_parser("privacy", help="create selective-disclosure proofs and report optional backend status")
    privacy_sub = s.add_subparsers(required=True, dest="privacy_cmd")
    privacy_status = privacy_sub.add_parser("status", help="report BBS and zkVM backend availability")
    privacy_merkle = privacy_sub.add_parser("merkle", help="write a one-leaf Merkle disclosure")
    privacy_merkle.add_argument("leaves")
    privacy_merkle.add_argument("--disclose", required=True)
    privacy_merkle.add_argument("--out", required=True)

    s = sub.add_parser("loop", help="create and verify portable governed-loop contracts")
    loop_sub = s.add_subparsers(required=True, dest="loop_cmd")
    loop_init = loop_sub.add_parser("init", help="write a conservative Loop Passport manifest")
    loop_init.add_argument("loop_id")
    loop_init.add_argument("--owner", required=True)
    loop_init.add_argument("--root", default=".")
    loop_init.add_argument("--force", action="store_true")
    loop_init.add_argument("--json", action="store_true")
    loop_validate = loop_sub.add_parser("validate", help="validate a Loop Passport manifest fail closed")
    loop_validate.add_argument("manifest")
    loop_validate.add_argument("--json", action="store_true")
    loop_passport = loop_sub.add_parser("passport", help="write a hash-bound Loop Passport and Mermaid graph")
    loop_passport.add_argument("manifest")
    loop_passport.add_argument("--root", default=".")
    loop_passport.add_argument("--json", action="store_true")
    loop_verify = loop_sub.add_parser("verify", help="verify a Loop Passport and its manifest binding")
    loop_verify.add_argument("passport")
    loop_verify.add_argument("--json", action="store_true")
    loop_budget = loop_sub.add_parser("budget", help="write a fail-closed receipt for supplied loop usage")
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
    s.add_argument("--out", help="trace output path; defaults to .factory/traces/<feature>.trace.json")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("verify-trace", help="verify a proof-carrying PR trace")
    s.add_argument("trace")
    s.add_argument("--root", default=None)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("replay", help="plan or execute the minimal rerun set for changed paths")
    s.add_argument("trace")
    s.add_argument("--root", default=None)
    s.add_argument("--changed", action="append", default=[], help="changed path; repeat as needed")
    s.add_argument("--base", help="git base ref for changed paths, e.g. main")
    s.add_argument("--execute", action="store_true", help="verify trace, then execute the replay plan")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("evidence", help="print public-safe proof for a feature")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--trace", help="trace path; defaults to .factory/traces/<feature>.trace.json")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("risk-diff", help="map changed paths to invalidated factory guarantees")
    s.add_argument("--root", default=".")
    s.add_argument("--base", default="main")
    s.add_argument("--changed", action="append", default=[], help="changed path; repeat as needed")
    s.add_argument("--json", action="store_true")

    workspace = sub.add_parser("workspace", help="inspect local workspace shape and remote/WSL preflight without IDE mutation")
    workspace_sub = workspace.add_subparsers(required=True, dest="workspace_cmd")
    workspace_inspect = workspace_sub.add_parser("inspect", help="measure bounded filesystem shape and offer manual review paths")
    workspace_inspect.add_argument("--root", default=".")
    workspace_inspect.add_argument("--out-dir", help="explicit workspace-contained directory for local JSON, Markdown, and Mermaid advice artifacts")
    workspace_inspect.add_argument("--json", action="store_true")
    workspace_continuity = workspace_sub.add_parser("continuity", help="capture or compare a local structural index-continuity baseline")
    workspace_continuity_sub = workspace_continuity.add_subparsers(required=True, dest="continuity_cmd")
    workspace_continuity_baseline = workspace_continuity_sub.add_parser("baseline", help="capture and explicitly save a workspace-contained structural baseline")
    workspace_continuity_baseline.add_argument("--root", default=".")
    workspace_continuity_baseline.add_argument("--out", required=True, help="workspace-contained .json baseline path")
    workspace_continuity_baseline.add_argument("--json", action="store_true")
    workspace_continuity_compare = workspace_continuity_sub.add_parser("compare", help="compare a verified structural baseline with the current workspace")
    workspace_continuity_compare.add_argument("--root", default=".")
    workspace_continuity_compare.add_argument("--baseline", required=True, help="workspace-contained baseline .json path")
    workspace_continuity_compare.add_argument("--json", action="store_true")

    s = sub.add_parser("graph", help="inspect bounded, read-only Factory graph views")
    graph_sub = s.add_subparsers(required=True, dest="graph_cmd")
    graph_ops = graph_sub.add_parser("ops", help="compile the unified local Graph Ops result without writes")
    graph_ops.add_argument("--root", default=".")
    graph_ops.add_argument("--json", action="store_true")
    graph_ops.add_argument("--mermaid", action="store_true", help="print the bounded Mermaid projection")
    graph_impact = graph_sub.add_parser("impact", help="map changed paths to explicit bound proof inputs without execution")
    graph_impact.add_argument("--root", default=".")
    graph_impact.add_argument("--changed", action="append", required=True, help="workspace-relative changed path; repeat as needed")
    graph_impact.add_argument("--json", action="store_true")
    graph_portfolio = graph_sub.add_parser("portfolio", help="compile a deterministic structural work proposal without execution")
    graph_portfolio.add_argument("--root", default=".")
    graph_portfolio.add_argument("--durations", help="JSON object mapping every dependency node id to supplied positive wall milliseconds")
    graph_portfolio.add_argument("--json", action="store_true")
    graph_lineage = graph_sub.add_parser("lineage-verify", help="verify one hash-sealed semantic graph lineage receipt")
    graph_lineage.add_argument("lineage")
    graph_lineage.add_argument("--json", action="store_true")
    graph_seal = graph_sub.add_parser("lineage-seal", help="validate step objects and atomically write a hash-sealed lineage receipt")
    graph_seal.add_argument("--run-id", required=True)
    graph_seal.add_argument("--graph-id", required=True)
    graph_seal.add_argument("--steps", required=True)
    graph_seal.add_argument("--out", required=True)
    graph_seal.add_argument("--json", action="store_true")
    graph_mission = graph_sub.add_parser("lineage-mission", help="export a verified native mission event chain as sealed lineage")
    graph_mission.add_argument("mission")
    graph_mission.add_argument("--root", default=".")
    graph_mission.add_argument("--run-id", required=True)
    graph_mission.add_argument("--out", required=True)
    graph_mission.add_argument("--json", action="store_true")
    graph_forensic = graph_sub.add_parser("forensics", help="compare verified graph runs and preview a bounded recovery fork")
    graph_forensic.add_argument("--baseline", required=True)
    graph_forensic.add_argument("--candidate", required=True)
    graph_forensic.add_argument("--json", action="store_true")
    graph_forensic.add_argument("--mermaid", action="store_true")

    admission = sub.add_parser("admission", help="seal and revalidate a local external-run admission packet")
    admission_sub = admission.add_subparsers(required=True, dest="admission_cmd")
    admission_prepare = admission_sub.add_parser("prepare", help="seal one externally enforced run proposal without invoking it")
    admission_prepare.add_argument("passport")
    admission_prepare.add_argument("request")
    admission_prepare.add_argument("--root", default=".")
    admission_prepare.add_argument("--out-dir")
    admission_prepare.add_argument("--json", action="store_true")
    admission_verify = admission_sub.add_parser("verify", help="revalidate one sealed packet before a harness consumes it")
    admission_verify.add_argument("packet")
    admission_verify.add_argument("--root", default=".")
    admission_verify.add_argument("--json", action="store_true")

    proofsearch = sub.add_parser("proofsearch", help="compare hash-bound repair candidates without applying them")
    proofsearch_sub = proofsearch.add_subparsers(required=True, dest="proofsearch_cmd")
    proofsearch_plan = proofsearch_sub.add_parser("plan", help="seal one graph divergence and its exact proof-impact slice")
    proofsearch_plan.add_argument("--root", default=".")
    proofsearch_plan.add_argument("--baseline", required=True)
    proofsearch_plan.add_argument("--candidate", required=True)
    proofsearch_plan.add_argument("--changed", action="append", required=True)
    proofsearch_plan.add_argument("--out", required=True)
    proofsearch_plan.add_argument("--json", action="store_true")
    proofsearch_evaluate = proofsearch_sub.add_parser("evaluate", help="verify, reject, and rank supplied candidate evidence")
    proofsearch_evaluate.add_argument("request")
    proofsearch_evaluate.add_argument("--root", default=".")
    proofsearch_evaluate.add_argument("--out", required=True)
    proofsearch_evaluate.add_argument("--json", action="store_true")
    proofsearch_verify = proofsearch_sub.add_parser("verify", help="verify one sealed ProofSearch evaluation and its evidence")
    proofsearch_verify.add_argument("evaluation")
    proofsearch_verify.add_argument("--root", default=".")
    proofsearch_verify.add_argument("--json", action="store_true")
    proofsearch_frontier = proofsearch_sub.add_parser("frontier", help="rank the next evidence experiment without executing it")
    proofsearch_frontier_sub = proofsearch_frontier.add_subparsers(required=True, dest="frontier_cmd")
    proofsearch_frontier_plan = proofsearch_frontier_sub.add_parser("plan", help="seal a bounded Evidence Frontier from a verified evaluation")
    proofsearch_frontier_plan.add_argument("request")
    proofsearch_frontier_plan.add_argument("--root", default=".")
    proofsearch_frontier_plan.add_argument("--out", required=True)
    proofsearch_frontier_plan.add_argument("--json", action="store_true")
    proofsearch_frontier_verify = proofsearch_frontier_sub.add_parser("verify", help="verify one sealed Evidence Frontier and its evaluation binding")
    proofsearch_frontier_verify.add_argument("frontier")
    proofsearch_frontier_verify.add_argument("--root", default=".")
    proofsearch_frontier_verify.add_argument("--json", action="store_true")

    change = sub.add_parser("change", help="prepare a deterministic, analysis-only diff-to-proof review")
    change_sub = change.add_subparsers(required=True, dest="change_cmd")
    change_review = change_sub.add_parser("review", help="join diff impact, coverage gaps, and plan-only reruns")
    change_review.add_argument("--root", default=".")
    change_review.add_argument("--base", default="main")
    change_review.add_argument("--changed", action="append", default=[], help="workspace-relative changed path; repeat as needed")
    change_review.add_argument("--out-dir", help="explicit local directory for JSON, Markdown, and Mermaid review artifacts")
    change_review.add_argument("--json", action="store_true")

    proof_ops = sub.add_parser("proof-ops", help="join intent, change, observed-session, and repair evidence into one local record")
    proof_ops_sub = proof_ops.add_subparsers(required=True, dest="proof_ops_cmd")
    proof_ops_assess = proof_ops_sub.add_parser("assess", help="write one fail-closed Continuous Proof Operations record without execution")
    proof_ops_assess.add_argument("--root", default=".")
    proof_ops_assess.add_argument("--workflow-id", required=True)
    proof_ops_assess.add_argument("--intent", required=True, help="workspace-contained human-authored intent artifact")
    proof_ops_assess.add_argument("--changed", action="append", required=True, help="exact workspace-relative changed path; repeat as needed")
    proof_ops_assess.add_argument("--session", help="optional workspace-contained observed-session receipt")
    proof_ops_assess.add_argument("--session-phase", choices=["change", "post_repair"], default="change")
    proof_ops_assess.add_argument("--repair-scope", help="optional workspace-contained sealed repair scope; requires --repair-patch")
    proof_ops_assess.add_argument("--repair-patch", help="optional workspace-contained textual patch; requires --repair-scope")
    proof_ops_assess.add_argument("--prior-receipt", help="prior scoped-repair record for a post-repair verification cycle")
    proof_ops_assess.add_argument("--out-dir", help="optional workspace-contained artifact directory")
    proof_ops_assess.add_argument("--json", action="store_true")
    proof_ops_verify = proof_ops_sub.add_parser("verify", help="verify one Continuous Proof Operations receipt and all bound bytes")
    proof_ops_verify.add_argument("receipt")
    proof_ops_verify.add_argument("--root", default=".")
    proof_ops_verify.add_argument("--json", action="store_true")
    proof_ops_history = proof_ops_sub.add_parser("history", help="aggregate verified local proof routes without user or savings inference")
    proof_ops_history.add_argument("--root", default=".")
    proof_ops_history.add_argument("--json", action="store_true")

    proof_review = sub.add_parser("proof-review", help="seal intent, review agent work, and route one human-controlled proof workflow")
    proof_review_sub = proof_review.add_subparsers(required=True, dest="proof_review_cmd")
    proof_review_contract = proof_review_sub.add_parser("contract", help="seal one complete, named-human-confirmed intent contract")
    proof_review_contract.add_argument("--root", default=".")
    proof_review_contract.add_argument("--id", required=True)
    proof_review_contract.add_argument("--draft", required=True)
    proof_review_contract.add_argument("--confirmed-by", required=True)
    proof_review_contract.add_argument("--json", action="store_true")
    proof_review_quick = proof_review_sub.add_parser("quick", help="join intent and current evidence into a four-route review")
    proof_review_quick.add_argument("--root", default=".")
    proof_review_quick.add_argument("--id", required=True)
    proof_review_quick.add_argument("--contract", required=True)
    proof_review_quick.add_argument("--changed", action="append", required=True)
    proof_review_quick.add_argument("--session")
    proof_review_quick.add_argument("--trajectory")
    proof_review_quick.add_argument("--repair-scope")
    proof_review_quick.add_argument("--repair-patch")
    proof_review_quick.add_argument("--prior-receipt")
    proof_review_quick.add_argument("--session-phase", choices=["change", "post_repair"], default="change")
    proof_review_quick.add_argument("--json", action="store_true")
    proof_review_verify = proof_review_sub.add_parser("verify", help="verify a proof review and every bound receipt")
    proof_review_verify.add_argument("review")
    proof_review_verify.add_argument("--root", default=".")
    proof_review_verify.add_argument("--json", action="store_true")
    proof_review_hooks = proof_review_sub.add_parser("hooks", help="write five reviewable agent-hook templates without installing them")
    proof_review_hooks.add_argument("--root", default=".")
    proof_review_hooks.add_argument("--json", action="store_true")
    proof_review_trajectory = proof_review_sub.add_parser("trajectory", help="seal and independently audit a bounded agent trajectory")
    proof_review_trajectory.add_argument("--root", default=".")
    proof_review_trajectory.add_argument("--id", required=True)
    proof_review_trajectory.add_argument("--trace", required=True)
    proof_review_trajectory.add_argument("--policy", required=True)
    proof_review_trajectory.add_argument("--json", action="store_true")
    proof_review_trajectory_verify = proof_review_sub.add_parser("trajectory-verify", help="verify a trajectory proof and its bound inputs")
    proof_review_trajectory_verify.add_argument("trajectory")
    proof_review_trajectory_verify.add_argument("--root", default=".")
    proof_review_trajectory_verify.add_argument("--json", action="store_true")
    proof_review_learn = proof_review_sub.add_parser("learn", help="promote one confirmed causal failure into an immutable regression capsule")
    proof_review_learn.add_argument("--root", default=".")
    proof_review_learn.add_argument("--id", required=True)
    proof_review_learn.add_argument("--review", required=True)
    proof_review_learn.add_argument("--confirmed-by", required=True)
    proof_review_learn.add_argument("--title", required=True)
    proof_review_learn.add_argument("--json", action="store_true")
    proof_review_inbox = proof_review_sub.add_parser("inbox", help="read the bounded team proof inbox")
    proof_review_inbox.add_argument("--root", default=".")
    proof_review_inbox.add_argument("--json", action="store_true")
    proof_review_card = proof_review_sub.add_parser("card", help="export an offline-verifiable public-safe proof card")
    proof_review_card.add_argument("--root", default=".")
    proof_review_card.add_argument("--id", required=True)
    proof_review_card.add_argument("--review", required=True)
    proof_review_card.add_argument("--json", action="store_true")
    proof_review_card_verify = proof_review_sub.add_parser("card-verify", help="verify a proof card offline")
    proof_review_card_verify.add_argument("card")
    proof_review_card_verify.add_argument("--json", action="store_true")

    revenue = sub.add_parser("revenue", help="validate and generate human-governed iOS monetization artifacts")
    revenue_sub = revenue.add_subparsers(required=True, dest="revenue_cmd")
    revenue_validate = revenue_sub.add_parser("validate", help="validate products.yaml and deterministic disclosure gates")
    revenue_validate.add_argument("--root", default=".")
    revenue_validate.add_argument("--products", required=True)
    revenue_validate.add_argument("--json", action="store_true")
    revenue_build = revenue_sub.add_parser("build", help="generate RevenueKit, paywall, entitlement-server, and evidence scaffolds")
    revenue_build.add_argument("--root", default=".")
    revenue_build.add_argument("--products", required=True)
    revenue_build.add_argument("--out-dir", default=".factory/revenueforge/default")
    revenue_build.add_argument("--json", action="store_true")
    revenue_growth = revenue_sub.add_parser("growth-plan", help="compile provider-write-free Phase 8 growth operations")
    revenue_growth.add_argument("--root", default=".")
    revenue_growth.add_argument("--products", required=True)
    revenue_growth.add_argument("--growth", required=True)
    revenue_growth.add_argument("--out")
    revenue_growth.add_argument("--json", action="store_true")
    revenue_benchmark = revenue_sub.add_parser("benchmark", help="publish a benchmark cell only at k >= 20 distinct apps")
    revenue_benchmark.add_argument("--records", required=True)
    revenue_benchmark.add_argument("--json", action="store_true")
    revenue_replay = revenue_sub.add_parser("replay", help="compare build-bound purchase observations with the required lifecycle")
    revenue_replay.add_argument("--root", default=".")
    revenue_replay.add_argument("--products", required=True)
    revenue_replay.add_argument("--events", required=True)
    revenue_replay.add_argument("--out", default=".factory/revenueforge/default/replay.json")
    revenue_replay.add_argument("--json", action="store_true")
    revenue_testflight = revenue_sub.add_parser("testflight-sync", help="normalize an authorized local TestFlight feedback export")
    revenue_testflight.add_argument("--root", default=".")
    revenue_testflight.add_argument("--feedback", required=True)
    revenue_testflight.add_argument("--out", default=".factory/revenueforge/default/testflight-inbox.json")
    revenue_testflight.add_argument("--json", action="store_true")
    revenue_matrix = revenue_sub.add_parser("failure-matrix", help="fail closed across observed monetization negative paths")
    revenue_matrix.add_argument("--root", default=".")
    revenue_matrix.add_argument("--products", required=True)
    revenue_matrix.add_argument("--evidence", required=True)
    revenue_matrix.add_argument("--out", default=".factory/revenueforge/default/failure-matrix.json")
    revenue_matrix.add_argument("--json", action="store_true")
    revenue_policy = revenue_sub.add_parser("policy-watch", help="compare hash-bound official Apple policy snapshots")
    revenue_policy.add_argument("--root", default=".")
    revenue_policy.add_argument("--registry", required=True)
    revenue_policy.add_argument("--snapshot", required=True)
    revenue_policy.add_argument("--out", default=".factory/revenueforge/default/policy-drift.json")
    revenue_policy.add_argument("--json", action="store_true")
    revenue_memory_promote = revenue_sub.add_parser("memory-promote", help="promote one human-approved receipt-backed operational lesson")
    revenue_memory_promote.add_argument("--root", default=".")
    revenue_memory_promote.add_argument("--entry", required=True)
    revenue_memory_promote.add_argument("--out", required=True)
    revenue_memory_promote.add_argument("--json", action="store_true")
    revenue_memory_query = revenue_sub.add_parser("memory-query", help="retrieve exact-app unexpired evidence lessons")
    revenue_memory_query.add_argument("--root", default=".")
    revenue_memory_query.add_argument("--app-id", required=True)
    revenue_memory_query.add_argument("--journey", required=True)
    revenue_memory_query.add_argument("--at")
    revenue_memory_query.add_argument("--json", action="store_true")
    revenue_design = revenue_sub.add_parser("appforge-design", help="compile user intent into a story-led seven-discipline iOS design workspace")
    revenue_design.add_argument("--root", default=".")
    revenue_design.add_argument("--brief", required=True)
    revenue_design.add_argument("--out-dir", default=".factory/appforge/design")
    revenue_design.add_argument("--json", action="store_true")

    saas = sub.add_parser("saas", help="verify provider-neutral SaaS identity, billing, entitlement, and revocation evidence")
    saas_sub = saas.add_subparsers(required=True, dest="saas_cmd")
    saas_verify = saas_sub.add_parser("verify", help="compare local OAuth/OIDC and entitlement observations with a reviewed promise contract")
    saas_verify.add_argument("--root", default=".")
    saas_verify.add_argument("--contract", required=True)
    saas_verify.add_argument("--evidence", required=True)
    saas_verify.add_argument("--out", default=".factory/saas-proof/latest.json")
    saas_verify.add_argument("--json", action="store_true")
    saas_status = saas_sub.add_parser("status", help="read hash-valid local SaaS proof receipt status")
    saas_status.add_argument("--root", default=".")
    saas_status.add_argument("--json", action="store_true")

    intent = sub.add_parser("intent", help="capture or inspect a human-confirmed, local Change List behavioral contract")
    intent_sub = intent.add_subparsers(required=True, dest="intent_cmd")
    intent_capture = intent_sub.add_parser("capture", help="write one explicitly confirmed local Intent Ledger record; no source or Change List change")
    intent_capture.add_argument("--root", default=".")
    intent_capture.add_argument("--change-list", required=True, help="native Change List label supplied by the IDE")
    intent_capture.add_argument("--changed", action="append", required=True, help="explicit workspace-relative Change List path; repeat as needed")
    intent_capture.add_argument("--confirmed-by", required=True, help="named human confirming the behavioral contract")
    intent_capture.add_argument("--promise", required=True, help="observable behavior this Change List must provide")
    intent_capture.add_argument("--non-goal", required=True, help="explicit behavior excluded from this Change List")
    intent_capture.add_argument("--failure-case", required=True, help="negative behavior the eventual proof must be able to detect")
    intent_capture.add_argument("--confirmation", required=True, help="must exactly equal CAPTURE <change-list>")
    intent_capture.add_argument("--json", action="store_true")
    intent_inspect = intent_sub.add_parser("inspect", help="read the current scope, stale-proof, and coverage state without writing or executing")
    intent_inspect.add_argument("--root", default=".")
    intent_inspect.add_argument("--change-list", required=True, help="native Change List label supplied by the IDE")
    intent_inspect.add_argument("--changed", action="append", default=[], help="explicit workspace-relative Change List path; repeat as needed")
    intent_inspect.add_argument("--base", default="main")
    intent_inspect.add_argument("--json", action="store_true")

    judgment = sub.add_parser("judgment", help="record human-promoted engineering decisions and compile read-only Change Safety Cases")
    judgment_sub = judgment.add_subparsers(required=True, dest="judgment_cmd")
    judgment_propose = judgment_sub.add_parser("propose", help="store one named human Capsule proposal; no safety-case authority until independent promotion")
    judgment_propose.add_argument("capsule", help="candidate factory.judgment.capsule.v1 JSON path")
    judgment_propose.add_argument("--root", default=".")
    judgment_propose.add_argument("--proposed-by", required=True)
    judgment_propose.add_argument("--json", action="store_true")
    judgment_promote = judgment_sub.add_parser("promote", help="independently promote one proposed Capsule")
    judgment_promote.add_argument("capsule_id")
    judgment_promote.add_argument("--root", default=".")
    judgment_promote.add_argument("--promoted-by", required=True)
    judgment_promote.add_argument("--reason", required=True)
    judgment_promote.add_argument("--json", action="store_true")
    judgment_reconsider = judgment_sub.add_parser("reconsider", help="record a successor proposal while retaining an active Capsule")
    judgment_reconsider.add_argument("capsule_id")
    judgment_reconsider.add_argument("--successor", required=True)
    judgment_reconsider.add_argument("--root", default=".")
    judgment_reconsider.add_argument("--requested-by", required=True)
    judgment_reconsider.add_argument("--reason", required=True)
    judgment_reconsider.add_argument("--json", action="store_true")
    judgment_status_parser = judgment_sub.add_parser("status", help="read tracked Capsule state without writes")
    judgment_status_parser.add_argument("--root", default=".")
    judgment_status_parser.add_argument("--json", action="store_true")
    judgment_safety = judgment_sub.add_parser("safety-case", help="compile a deterministic, no-execution Change Safety Case")
    judgment_safety.add_argument("--root", default=".")
    judgment_safety.add_argument("--changed", action="append", required=True, help="explicit workspace-relative changed path; repeat as needed")
    judgment_safety.add_argument("--proof-receipt", action="append", default=[], help="workspace-contained hash-bound obligation receipt; repeat as needed")
    judgment_safety.add_argument("--change-profile", help="optional workspace-contained, hash-bound declared change profile JSON")
    judgment_safety.add_argument("--json", action="store_true")

    memory = sub.add_parser("memory", help="read a compact next-proof brief with redacted continuity and observed local Git attribution")
    memory_sub = memory.add_subparsers(required=True, dest="memory_cmd")
    memory_brief = memory_sub.add_parser("brief", help="inspect current change evidence without running a proof or recalling memory bodies")
    memory_brief.add_argument("--root", default=".")
    memory_brief.add_argument("--base", default="main")
    memory_brief.add_argument("--changed", action="append", default=[], help="workspace-relative changed path; repeat as needed")
    memory_brief.add_argument("--json", action="store_true")

    github = sub.add_parser("github", help="prepare an evidence-bound, advisory GitHub pull-request review without a network call")
    github_sub = github.add_subparsers(required=True, dest="github_cmd")
    github_proof_review = github_sub.add_parser("proof-review", help="compile a Diff-to-Proof Review into an advisory Check/comment payload")
    github_proof_review.add_argument("--root", default=".")
    github_proof_review.add_argument("--base", default="main")
    github_proof_review.add_argument("--changed", action="append", default=[], help="workspace-relative changed path; repeat as needed")
    github_proof_review.add_argument("--head-sha", required=True, help="exact 40-character lowercase pull-request head SHA")
    github_proof_review.add_argument("--out-dir", help="explicit local directory for JSON and Markdown payload artifacts")
    github_proof_review.add_argument("--json", action="store_true")
    github_plan_proof = github_sub.add_parser("plan-proof-review", help="compile Plan-to-Proof facts into one advisory Check/comment payload")
    github_plan_proof.add_argument("--plan", required=True, help="factory.agent_plan.v1 JSON path")
    github_plan_proof.add_argument("--root", default=".")
    github_plan_proof.add_argument("--base", default="main")
    github_plan_proof.add_argument("--changed", action="append", default=[], help="workspace-relative changed path; repeat as needed")
    github_plan_proof.add_argument("--head-sha", required=True, help="exact 40-character lowercase pull-request head SHA")
    github_plan_proof.add_argument("--out-dir", help="explicit local directory for JSON and Markdown payload artifacts")
    github_plan_proof.add_argument("--json", action="store_true")
    github_policy_snapshot = github_sub.add_parser("policy-snapshot", help="validate a supplied local GitHub policy snapshot without a network call")
    github_policy_snapshot.add_argument("snapshot", help="factory.github_policy_snapshot.v1 JSON path")
    github_policy_snapshot.add_argument("--json", action="store_true")
    github_assurance = github_sub.add_parser("assurance-dossier", help="join local proof review and supplied policy snapshots into merge evidence")
    github_assurance.add_argument("--proof-review", required=True, help="factory.github_proof_review.v1 JSON path")
    github_assurance.add_argument("--policy-snapshot", required=True, help="current factory.github_policy_snapshot.v1 JSON path")
    github_assurance.add_argument("--baseline-policy-snapshot", help="previous comparable policy snapshot JSON path")
    github_assurance.add_argument("--exception", action="append", default=[], help="named expiring exception JSON path; repeat as needed")
    github_assurance.add_argument("--out-dir", help="explicit local directory for dossier JSON, Markdown, and Mermaid artifacts")
    github_assurance.add_argument("--require-aligned", action="store_true", help="exit non-zero after writing when baseline or high drift needs human action")
    github_assurance.add_argument("--json", action="store_true")

    repair = sub.add_parser("repair", help="prepare a sealed Change List scope and inspect a candidate patch without applying it")
    repair_sub = repair.add_subparsers(required=True, dest="repair_cmd")
    repair_scope = repair_sub.add_parser("scope", help="seal explicit Change List paths and optional local handoff artifacts")
    repair_scope.add_argument("--root", default=".")
    repair_scope.add_argument("--change-list", required=True, help="native Change List label supplied by the IDE")
    repair_scope.add_argument("--changed", action="append", required=True, help="explicit workspace-relative Change List path; repeat as needed")
    repair_scope.add_argument("--context-budget-bytes", type=int, default=262144, help="measured-byte threshold that recommends splitting an oversized agent context")
    repair_scope.add_argument("--out-dir", help="explicit workspace-contained directory for local scope artifacts")
    repair_scope.add_argument("--json", action="store_true")
    repair_candidate = repair_sub.add_parser("candidate", help="bind a textual Git patch to a current sealed scope without applying it")
    repair_candidate.add_argument("--root", default=".")
    repair_candidate.add_argument("--scope", required=True, help="workspace-contained factory.repair_scope.v1 JSON packet")
    repair_candidate.add_argument("--patch", required=True, help="workspace-contained textual Git candidate patch")
    repair_candidate.add_argument("--out-dir", help="explicit workspace-contained directory for local candidate artifacts")
    repair_candidate.add_argument("--json", action="store_true")

    release = sub.add_parser("release", help="inspect local release workflow boundaries without publishing")
    release_sub = release.add_subparsers(required=True, dest="release_cmd")
    release_integrity_parser = release_sub.add_parser("integrity", help="verify release workflow fan-in and protected-gate topology")
    release_integrity_parser.add_argument("--root", default=".")
    release_integrity_parser.add_argument("--json", action="store_true")

    mcp = sub.add_parser("mcp", help="serve or inspect the local read-only MCP adapter")
    mcp_sub = mcp.add_subparsers(required=True, dest="mcp_cmd")
    mcp_status = mcp_sub.add_parser("status", help="show the stdio-only MCP boundary")
    mcp_status.add_argument("--root", default=".")
    mcp_status.add_argument("--json", action="store_true")
    mcp_config = mcp_sub.add_parser("config", help="render copy-only setup for a local stdio MCP client")
    mcp_config.add_argument("--root", default=".")
    mcp_config.add_argument("--client", choices=["generic", "cursor", "opencode", "codex"], default="generic")
    mcp_config.add_argument("--json", action="store_true")
    mcp_serve = mcp_sub.add_parser("serve", help="serve newline-delimited JSON-RPC over stdio only")
    mcp_serve.add_argument("--root", default=".")

    s = sub.add_parser("attest", help="export in-toto/SLSA-shaped proof statements for a trace")
    s.add_argument("trace")
    s.add_argument("--out-dir", default="dist/attestations")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("passport", help="build a Factory Passport and Mermaid proof graph")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--trace", required=True)
    s.add_argument("--challenge", action="append", default=[], required=True)
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("verify-passport", help="verify passport, trace, and challenge hashes")
    s.add_argument("passport")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("challenge", help="prove trace verification rejects integrity sabotage")
    s.add_argument("feature")
    s.add_argument("--trace", required=True)
    s.add_argument("--root", default=".")
    s.add_argument("--out", default=None)

    s = sub.add_parser("coverage", help="verify every requirement has a non-hollow test")
    s.add_argument("--root", default=".")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("policy", help="write or show factory.policy.json")
    s.add_argument("--root", default=".")
    s.add_argument("--force", action="store_true")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("pr-pack", help="write a reviewer-ready PR evidence packet")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--trace", help="trace path; defaults to .factory/traces/<feature>.trace.json")
    s.add_argument("--out", help="markdown output path")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("optimize-pr", help="plan bounded PR hardening from the current diff")
    s.add_argument("--root", default=".")
    s.add_argument("--base", default="main")
    s.add_argument("--changed", action="append", default=[])
    s.add_argument("--feature")
    s.add_argument("--json", action="store_true")

    s = sub.add_parser("app", help="PRD-to-full-stack app builder")
    app_sub = s.add_subparsers(dest="app_cmd", required=True)
    app_sub.add_parser("stacks", help="list supported deterministic starter stacks")
    a_prd = app_sub.add_parser("from-prd", help="scaffold an app from a PRD markdown file")
    a_prd.add_argument("prd")
    a_prd.add_argument("--out", help="output directory; defaults to app slug")
    a_prd.add_argument("--name", help="app slug override")
    a_prd.add_argument("--stack", default="nextjs-fastapi-postgres", choices=sorted(STACKS))
    a_prd.add_argument("--purpose", default="auto", help="auto, developer, healthcare, fintech, marketplace, saas")
    a_prd.add_argument("--json", action="store_true")
    a_prompt = app_sub.add_parser("from-prompt", help="scaffold an app from a plain-English app idea")
    a_prompt.add_argument("prompt")
    a_prompt.add_argument("--out", help="output directory; defaults to app slug")
    a_prompt.add_argument("--name", help="app slug override")
    a_prompt.add_argument("--stack", default="nextjs-fastapi-postgres", choices=sorted(STACKS))
    a_prompt.add_argument("--purpose", default="auto", help="auto, developer, healthcare, fintech, marketplace, saas")
    a_prompt.add_argument("--json", action="store_true")

    targets = sub.add_parser("targets", help="list target kinds supported by the deterministic compiler")
    targets.add_argument("--json", action="store_true", help="emit the target inventory as JSON")

    pack = sub.add_parser("pack", help="list, verify, and install signed mutation-tested capability packs")
    pack_sub = pack.add_subparsers(dest="pack_cmd", required=True)
    pack_sub.add_parser("list", help="list first-party packs and their trust status")
    pack_validate = pack_sub.add_parser("validate", help="verify structure, signature, and validator mutations")
    pack_validate.add_argument("path")
    pack_install = pack_sub.add_parser("install", help="atomically install one verified pack into a workspace")
    pack_install.add_argument("path")
    pack_install.add_argument("--root", default=".")
    pack_install.add_argument("--force", action="store_true")
    pack_compose = pack_sub.add_parser("compose", help="write a compatible, hash-bound pack composition plan")
    pack_compose.add_argument("paths", nargs="+")
    pack_compose.add_argument("--root", default=".")
    pack_compose.add_argument("--name", default="default")
    pack_compose.add_argument("--force", action="store_true")

    agent = sub.add_parser("agent", help="validate secret-free Core-5 agent contracts and verifier receipts")
    agent_sub = agent.add_subparsers(dest="agent_cmd", required=True)
    agent_contract = agent_sub.add_parser("contract", help="validate one hash-bound Core-5 contract")
    agent_contract.add_argument("manifest")
    agent_contract.add_argument("--json", action="store_true")
    agent_attest = agent_sub.add_parser("attestation", help="validate a fresh creator/verifier adapter attestation")
    agent_attest.add_argument("receipt")
    agent_attest.add_argument("--mission-digest")
    agent_attest.add_argument("--contract-digest")
    agent_attest.add_argument("--json", action="store_true")

    telemetry = sub.add_parser("telemetry", help="reconcile local receipts, runs, traces, and meter ledgers")
    telemetry_sub = telemetry.add_subparsers(dest="telemetry_cmd", required=True)
    telemetry_inventory_parser = telemetry_sub.add_parser("inventory", help="emit a privacy-safe reconciled inventory")
    telemetry_inventory_parser.add_argument("--root", default=".")
    telemetry_inventory_parser.add_argument("--json", action="store_true")

    ops = sub.add_parser("ops", help="run the local enterprise operations golden path")
    ops_sub = ops.add_subparsers(dest="ops_cmd", required=True)
    ops_init = ops_sub.add_parser("init", help="initialize a tenant-bound evidence and operations workspace")
    ops_init.add_argument("--root", default=".")
    ops_init.add_argument("--tenant", required=True)
    ops_init.add_argument("--owner", required=True)
    ops_init.add_argument("--retention-days", type=int, default=90)
    ops_init.add_argument("--force", action="store_true")
    ops_init.add_argument("--json", action="store_true")
    ops_status = ops_sub.add_parser("status", help="show evidence, identity, runner, outcome, SLA, and next-action state")
    ops_status.add_argument("--root", default=".")
    ops_status.add_argument("--json", action="store_true")
    ops_identity = ops_sub.add_parser("identity", help="provision, suspend, or revoke a local identity")
    ops_identity.add_argument("subject")
    ops_identity.add_argument("--root", default=".")
    ops_identity.add_argument("--tenant", required=True)
    ops_identity.add_argument("--role", required=True)
    ops_identity.add_argument("--status", default="active", choices=["active", "suspended", "revoked"])
    ops_identity.add_argument("--actor", required=True)
    ops_identity.add_argument("--json", action="store_true")
    ops_evidence = ops_sub.add_parser("evidence", help="record one immutable tenant evidence payload")
    ops_evidence.add_argument("payload", help="JSON evidence object path")
    ops_evidence.add_argument("--root", default=".")
    ops_evidence.add_argument("--tenant", required=True)
    ops_evidence.add_argument("--subject", required=True)
    ops_evidence.add_argument("--evidence-id")
    ops_evidence.add_argument("--json", action="store_true")
    ops_export = ops_sub.add_parser("export", help="export aggregate-safe evidence metadata")
    ops_export.add_argument("--root", default=".")
    ops_export.add_argument("--out", required=True)
    ops_export.add_argument("--json", action="store_true")
    ops_run = ops_sub.add_parser("run", help="run one bounded proof argv with explicit isolation posture")
    ops_run.add_argument("--root", default=".")
    ops_run.add_argument("--backend", choices=["docker", "process"], default="docker")
    ops_run.add_argument("--command", nargs="+")
    ops_run.add_argument("--command-json", help="JSON argv list; use this when an argument begins with '-' ")
    ops_run.add_argument("--timeout-seconds", type=int, default=120)
    ops_run.add_argument("--output-limit", type=int, default=65536)
    ops_run.add_argument("--allow-process-boundary", action="store_true")
    ops_run.add_argument("--json", action="store_true")
    ops_checks = ops_sub.add_parser("checks", help="evaluate required proof checks for changed paths")
    ops_checks.add_argument("--root", default=".")
    ops_checks.add_argument("--changed", action="append", required=True)
    ops_checks.add_argument("--proof", action="append", default=[])
    ops_checks.add_argument("--json", action="store_true")
    ops_outcome = ops_sub.add_parser("outcome", help="append one allowlisted deployment or incident outcome")
    ops_outcome.add_argument("--root", default=".")
    ops_outcome.add_argument("--tenant", required=True)
    ops_outcome.add_argument("--subject", required=True)
    ops_outcome.add_argument("--service", required=True)
    ops_outcome.add_argument("--environment", required=True)
    ops_outcome.add_argument("--result", required=True)
    ops_outcome.add_argument("--duration-ms", required=True, type=int)
    ops_outcome.add_argument("--deployed", action="store_true")
    ops_outcome.add_argument("--incident", action="store_true")
    ops_outcome.add_argument("--rollback", action="store_true")
    ops_outcome.add_argument("--json", action="store_true")
    ops_summary = ops_sub.add_parser("summary", help="summarize hash-linked outcome telemetry")
    ops_summary.add_argument("--root", default=".")
    ops_summary.add_argument("--json", action="store_true")
    ops_otel = ops_sub.add_parser("otel", help="export aggregate-safe outcome telemetry in OTLP-shaped JSON")
    ops_otel.add_argument("--root", default=".")
    ops_otel.add_argument("--out", required=True)
    ops_otel.add_argument("--json", action="store_true")
    ops_sla = ops_sub.add_parser("sla", help="evaluate seven evidence gates without activating an SLA")
    ops_sla.add_argument("--root", default=".")
    ops_sla.add_argument("--manifest")
    ops_sla.add_argument("--out")
    ops_sla.add_argument("--json", action="store_true")
    ops_policy = ops_sub.add_parser("policy", help="compile explicit policy rules into deterministic checks")
    ops_policy.add_argument("policy", help="factory.policy.v1 JSON path")
    ops_policy.add_argument("--root", default=".")
    ops_policy.add_argument("--out", help="workspace-contained compiled manifest path")
    ops_policy.add_argument("--json", action="store_true")
    ops_metadata = ops_sub.add_parser("metadata", help="audit local Codex/workflow metadata for unbound or contradictory claims")
    ops_metadata.add_argument("--root", default=".")
    ops_metadata.add_argument("--path", action="append", help="workspace-contained metadata file or directory; repeatable")
    ops_metadata.add_argument("--out", help="workspace-contained metadata audit receipt path")
    ops_metadata.add_argument("--json", action="store_true")

    verifier = sub.add_parser(
        "verifier",
        help="bind independent verifier evidence without execution, merge, or publish authority",
    )
    verifier_sub = verifier.add_subparsers(dest="verifier_cmd", required=True)
    verifier_session = verifier_sub.add_parser("session", help="create a hash-bound verifier session contract")
    verifier_session.add_argument("mission", help="factory.mission.v1 mission receipt")
    verifier_session.add_argument("candidate_root", help="candidate tree the worker may change")
    verifier_session.add_argument("--bundle", action="append", required=True, help="immutable verifier bundle file; repeatable")
    verifier_session.add_argument("--owner", required=True, help="human owner responsible for review")
    verifier_session.add_argument("--root", default=".")
    verifier_session.add_argument("--max-attempts", type=int, default=5)
    verifier_session.add_argument("--max-wall-seconds", type=int, default=3600)
    verifier_session.add_argument("--max-tokens", type=int, default=100000)
    verifier_session.add_argument("--max-cost-usd", type=float, default=25.0)
    verifier_session.add_argument("--force", action="store_true")
    verifier_session.add_argument("--json", action="store_true")
    verifier_verify = verifier_sub.add_parser("verify", help="validate one independent verifier result against its bound session")
    verifier_verify.add_argument("session", help="verifier session receipt")
    verifier_verify.add_argument("worker_result", help="factory.verifier-worker-result.v1 receipt")
    verifier_verify.add_argument("verifier_result", help="factory.verifier-result.v1 receipt")
    verifier_verify.add_argument("--root", default=".")
    verifier_verify.add_argument("--json", action="store_true")
    verifier_progress = verifier_sub.add_parser("progress", help="halt repeated deterministic failures without using an LLM judgment")
    verifier_progress.add_argument("attempts", help="JSON array of worker attempt observations")
    verifier_progress.add_argument("--json", action="store_true")

    target = sub.add_parser("create", help="compile one prompt or PRD into one governed starter target")
    target.add_argument("prompt", nargs="?", help="plain-language intent; mutually exclusive with --prd")
    target.add_argument("--prd", help="UTF-8 PRD path; mutually exclusive with prompt")
    target.add_argument("--target", required=True, choices=sorted(TARGETS))
    target.add_argument("--out", required=True, help="empty output directory")
    target.add_argument("--name", help="target slug override")
    target.add_argument("--purpose", default="auto", help="auto, developer, healthcare, fintech, marketplace, saas")
    target.add_argument("--trigger", default="manual", choices=SUPPORTED_TRIGGERS)
    target.add_argument(
        "--deployment-profile",
        help="deployment route id shown by `factory targets --json`; defaults to the local or preview route",
    )
    target.add_argument("--json", action="store_true")

    mvp = sub.add_parser("mvp", help="turn one outcome into a contained local web MVP starter")
    mvp.add_argument("outcome", help="plain-language outcome for the first MVP")
    mvp.add_argument("--root", default=".", help="workspace that receives the new my-mvp directory")
    mvp.add_argument("--name", help="optional product name; the output directory remains my-mvp")
    mvp.add_argument("--purpose", default="auto", help="auto, developer, healthcare, fintech, marketplace, saas")
    mvp.add_argument("--json", action="store_true")

    studio = sub.add_parser("studio", help="run the loopback-only local target builder")
    studio.add_argument("--root", default=".", help="directory beneath which Studio may create targets")
    studio.add_argument("--port", default=0, type=int, help="loopback port; 0 selects an available port")
    studio.add_argument("--no-browser", action="store_true", help="do not open the local URL automatically")
    studio.add_argument("--check", action="store_true", help="report the exact Studio boundary without starting a server")
    studio.add_argument("--json", action="store_true")

    product = sub.add_parser("product", help="compile a PRD into a deterministic Product Graph and value slices")
    product_sub = product.add_subparsers(dest="product_cmd", required=True)
    product_compile = product_sub.add_parser("compile", help="compile and gap-check a UTF-8 PRD")
    product_compile.add_argument("prd")
    product_compile.add_argument("--root", default=".")
    product_compile.add_argument("--project")
    product_compile.add_argument("--intake", help="verified source-bound intake confirmation to bind")
    product_compile.add_argument("--force", action="store_true")
    product_compile.add_argument("--json", action="store_true")
    product_verify = product_sub.add_parser("verify", help="verify Product Graph and captured PRD hashes")
    product_verify.add_argument("graph")
    product_verify.add_argument("--json", action="store_true")
    product_slices = product_sub.add_parser("slices", help="compile complete requirement coverage into bounded value slices")
    product_slices.add_argument("graph")
    product_slices.add_argument("--root", default=".")
    product_slices.add_argument("--max-requirements", type=int, default=3)
    product_slices.add_argument("--force", action="store_true")
    product_slices.add_argument("--json", action="store_true")

    prd = sub.add_parser("prd", help="clarify a PRD before optimization and product compilation")
    prd_sub = prd.add_subparsers(dest="prd_cmd", required=True)
    prd_grill = prd_sub.add_parser("grill", help="write a bounded local PRD clarification frontier")
    prd_grill.add_argument("prd")
    prd_grill.add_argument("--root", default=".")
    prd_grill.add_argument("--mode", default="quick", choices=("quick", "deep"))
    prd_grill.add_argument("--project")
    prd_grill.add_argument("--out")
    prd_grill.add_argument("--confirm", action="store_true")
    prd_grill.add_argument("--force", action="store_true")
    prd_grill.add_argument("--json", action="store_true")
    prd_verify = prd_sub.add_parser("verify", help="verify a source-bound PRD Grill receipt")
    prd_verify.add_argument("receipt")
    prd_verify.add_argument("--json", action="store_true")

    intake = sub.add_parser("intake", help="resolve framework, intent, and acceptance evidence before mission creation")
    intake_sub = intake.add_subparsers(dest="intake_cmd", required=True)
    intake_grill = intake_sub.add_parser("grill", help="write a source-bound framework and intent decision worksheet")
    intake_grill.add_argument("prd")
    intake_grill.add_argument("--root", default=".")
    intake_grill.add_argument("--project")
    intake_grill.add_argument("--out")
    intake_grill.add_argument("--force", action="store_true")
    intake_grill.add_argument("--json", action="store_true")
    intake_confirm = intake_sub.add_parser("confirm", help="bind named human framework, intent, and acceptance decisions")
    intake_confirm.add_argument("intake")
    intake_confirm.add_argument("--root", default=".")
    intake_confirm.add_argument("--framework", required=True)
    intake_confirm.add_argument("--intent", required=True)
    intake_confirm.add_argument("--acceptance", required=True)
    intake_confirm.add_argument("--external-effects", required=True, choices=("local_only", "human_controlled"))
    intake_confirm.add_argument("--approved-by", required=True)
    intake_confirm.add_argument("--rationale", required=True)
    intake_confirm.add_argument("--re-evaluate-when")
    intake_confirm.add_argument("--out")
    intake_confirm.add_argument("--force", action="store_true")
    intake_confirm.add_argument("--json", action="store_true")
    intake_verify = intake_sub.add_parser("verify", help="verify an intake worksheet or confirmation")
    intake_verify.add_argument("receipt")
    intake_verify.add_argument("--root", default=".")
    intake_verify.add_argument("--confirmation", action="store_true")
    intake_verify.add_argument("--json", action="store_true")
    intake_read = intake_sub.add_parser("status", help="read local intake confirmation status")
    intake_read.add_argument("--root", default=".")
    intake_read.add_argument("--prd")
    intake_read.add_argument("--json", action="store_true")

    mission = sub.add_parser("mission", help="create or verify a supervised, passport-bound value mission")
    mission_sub = mission.add_subparsers(dest="mission_cmd", required=True)
    mission_create = mission_sub.add_parser("create", help="bind one value slice to a bounded mission")
    mission_create.add_argument("slices")
    mission_create.add_argument("slice_id")
    mission_create.add_argument("--root", default=".")
    mission_create.add_argument("--owner", required=True)
    mission_create.add_argument("--executor", default="manual", choices=sorted(EXECUTORS))
    mission_create.add_argument("--max-iterations", type=int)
    mission_create.add_argument("--max-wall-seconds", type=int)
    mission_create.add_argument("--max-tokens", type=int)
    mission_create.add_argument("--max-cost-usd", type=float)
    mission_create.add_argument("--readiness", help="verified migration readiness receipt to bind")
    mission_create.add_argument("--require-intake", action="store_true", help="require a verified intake confirmation bound to the Product Graph")
    mission_create.add_argument("--force", action="store_true")
    mission_create.add_argument("--json", action="store_true")
    mission_verify = mission_sub.add_parser("verify", help="verify mission, source, budget, and Loop Passport bindings")
    mission_verify.add_argument("mission")
    mission_verify.add_argument("--json", action="store_true")
    mission_close = mission_sub.add_parser("close", help="close only after independent exact-criteria verification")
    mission_close.add_argument("mission")
    mission_close.add_argument("validation")
    mission_close.add_argument("--root", default=".")
    mission_close.add_argument("--force", action="store_true")
    mission_close.add_argument("--json", action="store_true")
    mission_completion = mission_sub.add_parser("verify-completion", help="verify mission, validator, and evidence hashes")
    mission_completion.add_argument("completion")
    mission_completion.add_argument("--json", action="store_true")
    mission_decide = mission_sub.add_parser("decide", help="approve, defer, or reject bounded mission execution")
    mission_decide.add_argument("mission")
    mission_decide.add_argument("--root", default=".")
    mission_decide.add_argument("--owner", required=True)
    mission_decide.add_argument("--decision", required=True, choices=sorted(MISSION_DECISIONS))
    mission_decide.add_argument("--rationale", required=True)
    mission_decide.add_argument("--force", action="store_true")
    mission_decide.add_argument("--json", action="store_true")
    mission_delta = mission_sub.add_parser("proof-delta", help="bind new evidence before a supervised mission retry")
    mission_delta_sub = mission_delta.add_subparsers(dest="mission_delta_cmd", required=True)
    mission_delta_create = mission_delta_sub.add_parser("create", help="write one hash-bound retry admission or no-progress halt receipt")
    mission_delta_create.add_argument("mission")
    mission_delta_create.add_argument("--root", default=".")
    mission_delta_create.add_argument("--prior-candidate", required=True)
    mission_delta_create.add_argument("--repair-candidate", required=True)
    mission_delta_create.add_argument("--failure", required=True)
    mission_delta_create.add_argument("--criterion", required=True)
    mission_delta_create.add_argument("--out", required=True)
    mission_delta_create.add_argument("--json", action="store_true")
    mission_delta_verify = mission_delta_sub.add_parser("verify", help="verify one Proof-Delta receipt without admitting or running work")
    mission_delta_verify.add_argument("receipt")
    mission_delta_verify.add_argument("--root", default=".")
    mission_delta_verify.add_argument("--json", action="store_true")
    mission_delta_status = mission_delta_sub.add_parser("status", help="read the newest local Proof-Delta receipt")
    mission_delta_status.add_argument("--root", default=".")
    mission_delta_status.add_argument("--mission-id")
    mission_delta_status.add_argument("--json", action="store_true")

    langgraph = sub.add_parser("langgraph", help="operate receipt-governed durable mission graphs")
    langgraph_sub = langgraph.add_subparsers(dest="langgraph_cmd", required=True)
    langgraph_doctor_parser = langgraph_sub.add_parser("doctor", help="check optional LangGraph and SQLite checkpoint support")
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
    langgraph_event = langgraph_sub.add_parser("event", help="append one guarded, idempotent mission event")
    langgraph_event.add_argument("mission")
    langgraph_event.add_argument("--root", default=".")
    langgraph_event.add_argument("--event", required=True)
    langgraph_event.add_argument("--actor", required=True)
    langgraph_event.add_argument("--role", required=True, choices=["owner", "worker", "validator", "operator"])
    langgraph_event.add_argument("--idempotency-key", required=True)
    langgraph_event.add_argument("--receipt", required=True)
    langgraph_event.add_argument("--payload", help="path to a secret-free JSON object")
    langgraph_event.add_argument("--json", action="store_true")
    langgraph_replay = langgraph_sub.add_parser("replay-verify", help="compare recorded reference and resumed transitions without invoking a graph")
    langgraph_replay.add_argument("--root", default=".")
    langgraph_replay.add_argument("--reference", required=True, help="workspace-relative sealed reference lineage JSON")
    langgraph_replay.add_argument("--resumed", required=True, help="workspace-relative sealed resumed lineage JSON")
    langgraph_replay.add_argument("--out", help="optional workspace-relative assurance receipt JSON")
    langgraph_replay.add_argument("--mermaid", action="store_true", help="print only the parity or incident Mermaid map")
    langgraph_replay.add_argument("--json", action="store_true")

    provider = sub.add_parser("provider", help="configure secret-free BYOK references and deterministic routing rails")
    provider_sub = provider.add_subparsers(dest="provider_cmd", required=True)
    provider_init = provider_sub.add_parser("init", help="write a provider policy from a secret-free JSON config")
    provider_init.add_argument("config")
    provider_init.add_argument("--root", default=".")
    provider_init.add_argument("--force", action="store_true")
    provider_init.add_argument("--json", action="store_true")
    provider_verify = provider_sub.add_parser("verify", help="verify provider policy schema, rails, and hash")
    provider_verify.add_argument("policy")
    provider_verify.add_argument("--json", action="store_true")
    provider_doctor_parser = provider_sub.add_parser("doctor", help="show credential-reference presence without key values")
    provider_doctor_parser.add_argument("policy")
    provider_doctor_parser.add_argument("--json", action="store_true")
    provider_route = provider_sub.add_parser("route", help="select a provider/model under mission and IDE rails")
    provider_route.add_argument("policy")
    provider_route.add_argument("mission")
    provider_route.add_argument("--root", default=".")
    provider_route.add_argument("--ide", required=True, choices=sorted(SUPPORTED_IDES))
    provider_route.add_argument("--risk", required=True, choices=["low", "medium", "high"])
    provider_route.add_argument("--preferred-provider")
    provider_route.add_argument("--preferred-model")
    provider_route.add_argument("--cache-provider")
    provider_route.add_argument("--cache-model")
    provider_route.add_argument("--projected-tokens", type=int, default=0)
    provider_route.add_argument("--projected-cost-usd", type=float)
    provider_route.add_argument("--latency-budget-ms", type=int, default=5000)
    provider_route.add_argument("--required-capability", action="append", default=[])
    provider_route.add_argument("--privacy-class", choices=["standard", "restricted", "local_only"], default="standard")
    provider_route.add_argument("--output-contract", choices=["text", "json", "jsonl"], default="json")
    provider_route.add_argument("--json", action="store_true")

    migration = sub.add_parser("migration", help="prove agent readiness before a large migration mission")
    migration_sub = migration.add_subparsers(dest="migration_cmd", required=True)
    migration_assess = migration_sub.add_parser("assess", help="separate registered checks from executable readiness proof")
    migration_assess.add_argument("manifest")
    migration_assess.add_argument("--root", default=".")
    migration_assess.add_argument("--force", action="store_true")
    migration_assess.add_argument("--json", action="store_true")
    migration_verify = migration_sub.add_parser("verify", help="verify readiness and bound evidence hashes")
    migration_verify.add_argument("receipt")
    migration_verify.add_argument("--json", action="store_true")

    context = sub.add_parser("context", help="build compact tracked-fact AutoWiki and Lore artifacts")
    context_sub = context.add_subparsers(dest="context_cmd", required=True)
    context_build = context_sub.add_parser("build", help="generate AutoWiki and Lore from Git-tracked facts")
    context_build.add_argument("--root", default=".")
    context_build.add_argument("--force", action="store_true")
    context_build.add_argument("--json", action="store_true")
    context_verify = context_sub.add_parser("verify", help="verify AutoWiki and Lore hashes")
    context_verify.add_argument("receipt")
    context_verify.add_argument("--json", action="store_true")

    opinion = sub.add_parser("opinion", help="maintain the owner-controlled architecture Opinion Dock")
    opinion_sub = opinion.add_subparsers(dest="opinion_cmd", required=True)
    opinion_init = opinion_sub.add_parser("init", help="create a compact default Opinion Dock")
    opinion_init.add_argument("--root", default=".")
    opinion_init.add_argument("--owner", required=True)
    opinion_init.add_argument("--force", action="store_true")
    opinion_init.add_argument("--json", action="store_true")
    opinion_verify = opinion_sub.add_parser("verify", help="verify the dock hash and 2,000-line budget")
    opinion_verify.add_argument("dock")
    opinion_verify.add_argument("--json", action="store_true")
    opinion_correct = opinion_sub.add_parser("correct", help="append one owner-authored, hash-linked rule correction")
    opinion_correct.add_argument("dock")
    opinion_correct.add_argument("--owner", required=True)
    opinion_correct.add_argument("--rule-file", required=True)
    opinion_correct.add_argument("--rationale", required=True)
    opinion_correct.add_argument("--json", action="store_true")

    signal = sub.add_parser("signal", help="capture and govern untrusted environmental signals locally")
    signal_sub = signal.add_subparsers(dest="signal_cmd", required=True)
    signal_capture = signal_sub.add_parser("capture", help="normalize one owner-supplied signal without polling or execution")
    signal_capture.add_argument("--root", default=".")
    signal_capture.add_argument("--source", required=True, choices=sorted(SOURCES))
    signal_capture.add_argument("--title", required=True)
    signal_capture_body = signal_capture.add_mutually_exclusive_group(required=True)
    signal_capture_body.add_argument("--body")
    signal_capture_body.add_argument("--body-file")
    signal_capture.add_argument("--authorization", required=True, choices=sorted(AUTHORIZATIONS))
    signal_capture.add_argument("--severity", type=int, default=3)
    signal_capture.add_argument("--external-id")
    signal_capture.add_argument("--url")
    signal_capture.add_argument("--observed-at")
    signal_capture.add_argument("--hypothesis", action="append", default=[])
    signal_capture.add_argument("--requirement", action="append", default=[])
    signal_capture.add_argument("--outcome", action="append", default=[])
    signal_capture.add_argument("--acceptance", action="append", default=[])
    signal_capture.add_argument("--json", action="store_true")
    signal_triage = signal_sub.add_parser("triage", help="score a signal against explicit Opinion Dock rules")
    signal_triage.add_argument("signal")
    signal_triage.add_argument("dock")
    signal_triage.add_argument("--root", default=".")
    signal_triage.add_argument("--force", action="store_true")
    signal_triage.add_argument("--json", action="store_true")
    signal_decide = signal_sub.add_parser("decide", help="record the Product Owner decision for one triage receipt")
    signal_decide.add_argument("triage")
    signal_decide.add_argument("--root", default=".")
    signal_decide.add_argument("--owner", required=True)
    signal_decide.add_argument("--decision", required=True, choices=sorted(DECISIONS))
    signal_decide.add_argument("--rationale", required=True)
    signal_decide.add_argument("--override-block", action="store_true")
    signal_decide.add_argument("--force", action="store_true")
    signal_decide.add_argument("--json", action="store_true")
    signal_promote = signal_sub.add_parser("promote", help="promote an approved signal to a Product Graph or needs-input draft")
    signal_promote.add_argument("decision")
    signal_promote.add_argument("--root", default=".")
    signal_promote.add_argument("--project")
    signal_promote.add_argument("--force", action="store_true")
    signal_promote.add_argument("--json", action="store_true")
    signal_feedback = signal_sub.add_parser("feedback", help="turn measured outcome evidence into a new local telemetry signal")
    signal_feedback.add_argument("--root", default=".")
    signal_feedback.add_argument("--mission-id", required=True)
    signal_feedback.add_argument("--metric", required=True)
    signal_feedback.add_argument("--observed", type=float, required=True)
    signal_feedback.add_argument("--target", type=float, required=True)
    signal_feedback.add_argument("--evidence", required=True)
    signal_feedback.add_argument("--json", action="store_true")

    learning = sub.add_parser("learning", help="refine task-specific worker instructions through independent proof")
    learning_sub = learning.add_subparsers(dest="learning_cmd", required=True)
    learning_init = learning_sub.add_parser("init", help="bind a task objective and ordered milestone gates")
    learning_init.add_argument("task_id")
    learning_init.add_argument("--root", default=".")
    learning_init.add_argument("--owner", required=True)
    learning_init.add_argument("--objective", required=True)
    learning_init.add_argument("--milestones", required=True, help="JSON file containing milestone objects")
    learning_init.add_argument("--force", action="store_true")
    learning_init.add_argument("--json", action="store_true")
    learning_packet = learning_sub.add_parser("packet", help="create a fresh worker context from promoted instructions only")
    learning_packet.add_argument("task")
    learning_packet.add_argument("--milestone", required=True)
    learning_packet.add_argument("--worker", required=True)
    learning_packet.add_argument("--force", action="store_true")
    learning_packet.add_argument("--json", action="store_true")
    learning_propose = learning_sub.add_parser("propose", help="bind an outcome to an untrusted instruction candidate")
    learning_propose.add_argument("task")
    learning_propose.add_argument("--root", default=".")
    learning_propose.add_argument("--milestone", required=True)
    learning_propose.add_argument("--worker", required=True)
    learning_propose.add_argument("--outcome", required=True)
    learning_propose.add_argument("--instructions", required=True, help="JSON file containing a dimensioned instruction-edit array")
    learning_propose.add_argument("--force", action="store_true")
    learning_propose.add_argument("--json", action="store_true")
    learning_validate = learning_sub.add_parser("validate", help="independently validate every milestone criterion")
    learning_validate.add_argument("candidate")
    learning_validate.add_argument("--root", default=".")
    learning_validate.add_argument("--validator", required=True)
    learning_validate.add_argument("--results", required=True, help="JSON file containing criterion results and evidence")
    learning_validate.add_argument("--force", action="store_true")
    learning_validate.add_argument("--json", action="store_true")
    learning_promote = learning_sub.add_parser("promote", help="activate a validated instruction candidate under owner authority")
    learning_promote.add_argument("validation")
    learning_promote.add_argument("--owner", required=True)
    learning_promote.add_argument("--force", action="store_true")
    learning_promote.add_argument("--json", action="store_true")
    learning_experiment = learning_sub.add_parser("experiment", help="write a bounded correctness-first ASHA, Hyperband, or BOHB plan")
    learning_experiment.add_argument("task")
    learning_experiment.add_argument("--space", required=True, help="JSON d1-d6 search-space mapping")
    learning_experiment.add_argument("--variant", choices=["asha", "hyperband", "bohb"], default="asha")
    learning_experiment.add_argument("--max-resource", type=int, default=50)
    learning_experiment.add_argument("--grace-period", type=int, default=5)
    learning_experiment.add_argument("--reduction-factor", type=int, default=3)
    learning_experiment.add_argument("--max-concurrent", type=int, default=4)
    learning_experiment.add_argument("--samples", type=int, default=20)
    learning_experiment.add_argument("--force", action="store_true")
    learning_experiment.add_argument("--json", action="store_true")

    pr = sub.add_parser("pr", help="prepare local reviewer artifacts without merge authority")
    pr_sub = pr.add_subparsers(dest="pr_cmd", required=True)
    pr_draft = pr_sub.add_parser("draft", help="write an evidence-linked PR draft packet")
    pr_draft.add_argument("mission")
    pr_draft.add_argument("--root", default=".")
    pr_draft.add_argument("--evidence", action="append", default=[])
    pr_draft.add_argument("--force", action="store_true")
    pr_draft.add_argument("--json", action="store_true")

    outcome = sub.add_parser("outcome", help="record and summarize hash-linked product outcome evidence")
    outcome_sub = outcome.add_subparsers(dest="outcome_cmd", required=True)
    outcome_record = outcome_sub.add_parser("record", help="append one classified outcome observation")
    outcome_record.add_argument("mission")
    outcome_record.add_argument("--root", default=".")
    outcome_record.add_argument("--metric", required=True)
    outcome_record.add_argument("--value", type=float)
    outcome_record.add_argument("--target", type=float)
    outcome_record.add_argument("--evidence-class", required=True, choices=sorted(EVIDENCE_CLASSES))
    outcome_record.add_argument("--source")
    outcome_record.add_argument("--notes", default="")
    outcome_record.add_argument("--json", action="store_true")
    outcome_summary_parser = outcome_sub.add_parser("summary", help="verify and summarize local outcome chains")
    outcome_summary_parser.add_argument("--root", default=".")
    outcome_summary_parser.add_argument("--mission-id")
    outcome_summary_parser.add_argument("--json", action="store_true")

    version = sub.add_parser("version", help="show package provenance")
    version.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "ops":
        from .enterprise_ops import (
            EnterpriseOpsError,
            evaluate_required_checks,
            evaluate_sla,
            export_evidence,
            export_otel,
            initialize_workspace,
            outcome_summary,
            provision_identity,
            put_evidence,
            record_outcome,
            run_proof,
            verify_workspace,
            workspace_status,
        )
        from .policy_compiler import PolicyCompileError, write_compiled_policy
        from .codex_metadata import MetadataAuditError, write_metadata_audit
        try:
            root = Path(a.root)
            if a.ops_cmd == "init":
                result = initialize_workspace(root, a.tenant, a.owner, retention_days=a.retention_days, force=a.force)
            elif a.ops_cmd == "status":
                result = workspace_status(root)
            elif a.ops_cmd == "identity":
                result = provision_identity(root, a.tenant, a.subject, a.role, actor=a.actor, status=a.status)
            elif a.ops_cmd == "evidence":
                payload = json.loads(Path(a.payload).read_text(encoding="utf-8"))
                result = put_evidence(root, a.tenant, a.subject, payload, evidence_id=a.evidence_id)
            elif a.ops_cmd == "export":
                result = export_evidence(root, Path(a.out))
            elif a.ops_cmd == "run":
                command = json.loads(a.command_json) if a.command_json else a.command
                result = run_proof(root, command, backend=a.backend, timeout_seconds=a.timeout_seconds, output_limit=a.output_limit, allow_process_boundary=a.allow_process_boundary)
            elif a.ops_cmd == "checks":
                result = evaluate_required_checks(root, a.changed, proof_receipts=a.proof)
            elif a.ops_cmd == "outcome":
                result = record_outcome(root, a.tenant, a.subject, service=a.service, environment=a.environment, result=a.result, duration_ms=a.duration_ms, deployed=a.deployed, incident=a.incident, rollback=a.rollback)
            elif a.ops_cmd == "summary":
                result = outcome_summary(root)
            elif a.ops_cmd == "otel":
                result = export_otel(root, Path(a.out))
            elif a.ops_cmd == "sla":
                result = evaluate_sla(root, Path(a.manifest) if a.manifest else None, out=Path(a.out) if a.out else None)
            elif a.ops_cmd == "policy":
                result = write_compiled_policy(root, Path(a.policy), Path(a.out) if a.out else None)
            elif a.ops_cmd == "metadata":
                selected = [Path(item) for item in a.path] if a.path else None
                result = write_metadata_audit(root, selected, Path(a.out) if a.out else None)
            else:
                result = verify_workspace(root)
        except (EnterpriseOpsError, PolicyCompileError, MetadataAuditError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            error = {"schema": "factory.enterprise-ops.error.v1", "marker": "EOPS_FAIL_CLOSED", "status": "failed", "code": getattr(exc, "code", "E_OPS_INPUT"), "message": getattr(exc, "message", str(exc))}
            print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
            return 2
        if getattr(a, "json", False):
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        if a.ops_cmd == "run":
            return 0 if result.get("status") == "passed" else 1
        if a.ops_cmd == "checks":
            return 0 if result.get("decision") == "READY_FOR_HUMAN_REVIEW" else 1
        if a.ops_cmd == "sla":
            return 0 if result.get("status") == "READY_FOR_CONTRACT" else 1
        if a.ops_cmd == "policy":
            return 0 if result.get("status") == "COMPILED" else 1
        if a.ops_cmd == "metadata":
            return 0 if result.get("status") == "VERIFIED" else 1
        if a.ops_cmd in {"summary", "otel", "export"}:
            return 0 if result.get("integrity", {}).get("valid", True) else 1
        return 0

    if a.cmd is None:
        return _home()
    if a.cmd == "version":
        return _emit_version(a.json)
    if a.cmd == "home":
        return _home(Path(a.root), a.json)
    if a.cmd == "doctor":
        return _doctor(a.strict, a.json)
    if a.cmd == "external":
        try:
            if a.external_cmd == "import":
                result = import_external_runtime_bundle(
                    Path(a.root), Path(a.bundle), a.provider,
                    Path(a.out) if a.out else None,
                )
            else:
                result = diff_external_runtime_receipts(Path(a.root), Path(a.left), Path(a.right))
        except ExternalEvidenceError as exc:
            print(json.dumps({
                "schema": "factory.workflow_error.v1", "status": "failed",
                "code": exc.code, "message": exc.message,
                "marker": exc.code,
                "failure": explain_failure(exc.code, exc.message),
            }, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        if a.external_cmd == "diff" and result.get("comparable") is not True:
            return 1
        return 0
    if a.cmd == "journey":
        try:
            root = Path(a.root)
            if a.journey_cmd == "reality":
                result = compile_reality_graph(root, Path(a.declaration), Path(a.observation), Path(a.out) if a.out else None)
            elif a.journey_cmd == "capsule":
                result = create_failure_capsule(root, Path(a.input), Path(a.out) if a.out else None)
            elif a.journey_cmd == "workflow-proof":
                result = verify_stateful_workflow(root, Path(a.input), Path(a.out) if a.out else None)
            elif a.journey_cmd == "heal-verify":
                result = verify_proof_gated_healing(root, Path(a.input), Path(a.out) if a.out else None, a.timeout_seconds)
            else:
                result = journey_proof_status(root)
        except JourneyProofError as exc:
            print(json.dumps({
                "schema": "factory.workflow_error.v1", "status": "failed",
                "code": exc.code, "message": str(exc), "marker": exc.code,
                "failure": explain_failure(exc.code, str(exc)),
            }, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        if a.journey_cmd == "reality" and result.get("decision") != "matched":
            return 1
        if a.journey_cmd in {"workflow-proof", "heal-verify"} and result.get("decision") not in {"passed", "admissible_for_human_review"}:
            return 1
        return 0
    if a.cmd in {"prd", "intake", "product", "mission", "pr", "outcome", "opinion", "signal", "learning", "migration", "context", "langgraph", "provider", "agent", "telemetry", "verifier"}:
        try:
            if a.cmd == "prd" and a.prd_cmd == "grill":
                result = grill_prd(
                    Path(a.prd), Path(a.root), a.mode, a.project,
                    Path(a.out) if a.out else None, a.confirm, a.force,
                )
            elif a.cmd == "prd" and a.prd_cmd == "verify":
                result = verify_prd_grill(Path(a.receipt))
            elif a.cmd == "intake" and a.intake_cmd == "grill":
                result = grill_intake(Path(a.prd), Path(a.root), a.project, Path(a.out) if a.out else None, a.force)
            elif a.cmd == "intake" and a.intake_cmd == "confirm":
                result = confirm_intake(
                    Path(a.root), Path(a.intake), a.framework, a.intent, a.acceptance,
                    a.external_effects, a.approved_by, a.rationale, a.re_evaluate_when,
                    Path(a.out) if a.out else None, a.force,
                )
            elif a.cmd == "intake" and a.intake_cmd == "verify":
                result = verify_intake_confirmation(Path(a.root), Path(a.receipt)) if a.confirmation else verify_intake_grill(Path(a.root), Path(a.receipt))
            elif a.cmd == "intake":
                result = intake_status(Path(a.root), Path(a.prd) if a.prd else None)
            elif a.cmd == "agent" and a.agent_cmd == "contract":
                result = validate_agent_contract(Path(a.manifest))
            elif a.cmd == "agent" and a.agent_cmd == "attestation":
                result = validate_verifier_attestation(
                    Path(a.receipt), mission_digest=a.mission_digest, contract_digest=a.contract_digest,
                )
            elif a.cmd == "telemetry":
                result = telemetry_inventory(Path(a.root))
            elif a.cmd == "verifier" and a.verifier_cmd == "session":
                result = create_verifier_session(
                    Path(a.root), Path(a.mission), Path(a.candidate_root),
                    [Path(item) for item in a.bundle], a.owner,
                    max_attempts=a.max_attempts, max_wall_seconds=a.max_wall_seconds,
                    max_tokens=a.max_tokens, max_cost_usd=a.max_cost_usd, force=a.force,
                )
            elif a.cmd == "verifier" and a.verifier_cmd == "verify":
                result = verify_verifier_result(
                    Path(a.session), Path(a.worker_result), Path(a.verifier_result), Path(a.root),
                )
            elif a.cmd == "verifier":
                attempts = json.loads(Path(a.attempts).read_text(encoding="utf-8"))
                result = evaluate_progress(attempts)
            elif a.cmd == "langgraph" and a.langgraph_cmd == "doctor":
                result = langgraph_doctor()
            elif a.cmd == "langgraph" and a.langgraph_cmd == "init":
                result = init_mission_graph(Path(a.mission), Path(a.root))
            elif a.cmd == "langgraph" and a.langgraph_cmd == "status":
                result = mission_graph_status(Path(a.mission), Path(a.root))
            elif a.cmd == "langgraph" and a.langgraph_cmd == "history":
                result = mission_graph_history(Path(a.mission), Path(a.root))
            elif a.cmd == "langgraph" and a.langgraph_cmd == "verify":
                result = verify_mission_graph(Path(a.mission), Path(a.root))
            elif a.cmd == "langgraph" and a.langgraph_cmd == "export":
                result = export_mission_graph(Path(a.mission), Path(a.root))
            elif a.cmd == "langgraph" and a.langgraph_cmd == "replay-verify":
                result = verify_langgraph_resume_parity(
                    Path(a.root), a.reference, a.resumed, out=a.out,
                )
            elif a.cmd == "langgraph":
                payload = json.loads(Path(a.payload).read_text(encoding="utf-8")) if a.payload else {}
                if not isinstance(payload, dict):
                    raise MissionGraphError("MISSION_GRAPH_EVENT_INVALID", "payload file must contain one JSON object")
                result = apply_mission_event(
                    Path(a.mission), Path(a.root), a.event, a.actor, a.role,
                    a.idempotency_key, Path(a.receipt), payload,
                )
            elif a.cmd == "provider" and a.provider_cmd == "init":
                config = json.loads(Path(a.config).read_text(encoding="utf-8"))
                if not isinstance(config, dict):
                    raise ProviderRouterError("PROVIDER_POLICY_INVALID", "config must contain one JSON object")
                result = create_provider_policy(
                    Path(a.root), config.get("owner", ""), config.get("providers", []),
                    config.get("allowed_ides", []), config.get("max_cost_usd"),
                    config.get("quality_floor", "balanced"), config.get("routing_bias", 50), a.force,
                )
            elif a.cmd == "provider" and a.provider_cmd == "verify":
                result = verify_provider_policy(Path(a.policy))
            elif a.cmd == "provider" and a.provider_cmd == "doctor":
                result = provider_doctor(Path(a.policy))
            elif a.cmd == "provider":
                result = route_provider(
                    Path(a.policy), Path(a.mission), Path(a.root), a.ide, a.risk,
                    a.preferred_provider, a.preferred_model, a.cache_provider, a.cache_model,
                    a.projected_tokens, a.projected_cost_usd, a.latency_budget_ms,
                    a.required_capability, a.privacy_class, a.output_contract,
                )
            elif a.cmd == "migration" and a.migration_cmd == "assess":
                result = assess_migration_readiness(Path(a.manifest), Path(a.root), force=a.force)
            elif a.cmd == "migration":
                result = verify_migration_readiness(Path(a.receipt))
            elif a.cmd == "context" and a.context_cmd == "build":
                result = build_repository_context(Path(a.root), force=a.force)
            elif a.cmd == "context":
                result = verify_repository_context(Path(a.receipt))
            elif a.cmd == "product" and a.product_cmd == "compile":
                result = compile_product_prd(Path(a.prd), Path(a.root), a.project, a.force, Path(a.intake) if a.intake else None)
            elif a.cmd == "product" and a.product_cmd == "verify":
                result = verify_product_graph(Path(a.graph))
            elif a.cmd == "product":
                result = plan_value_slices(Path(a.graph), Path(a.root), a.max_requirements, a.force)
            elif a.cmd == "mission" and a.mission_cmd == "proof-delta" and a.mission_delta_cmd == "create":
                result = create_proof_delta(
                    Path(a.root), Path(a.mission), Path(a.prior_candidate), Path(a.repair_candidate),
                    Path(a.failure), a.criterion, Path(a.out),
                )
            elif a.cmd == "mission" and a.mission_cmd == "proof-delta" and a.mission_delta_cmd == "verify":
                result = verify_proof_delta(Path(a.root), Path(a.receipt))
            elif a.cmd == "mission" and a.mission_cmd == "proof-delta":
                result = proof_delta_status(Path(a.root), a.mission_id)
            elif a.cmd == "mission" and a.mission_cmd == "create":
                result = create_mission(
                    Path(a.slices), a.slice_id, Path(a.root), a.owner, a.executor, a.force,
                    a.max_iterations, a.max_wall_seconds, a.max_tokens, a.max_cost_usd,
                    Path(a.readiness) if a.readiness else None, a.require_intake,
                )
            elif a.cmd == "mission" and a.mission_cmd == "verify":
                result = verify_mission(Path(a.mission))
            elif a.cmd == "mission" and a.mission_cmd == "close":
                result = close_mission(Path(a.mission), Path(a.validation), Path(a.root), force=a.force)
            elif a.cmd == "mission" and a.mission_cmd == "verify-completion":
                result = verify_mission_completion(Path(a.completion))
            elif a.cmd == "mission":
                result = decide_mission(
                    Path(a.mission), Path(a.root), owner=a.owner, decision=a.decision,
                    rationale=a.rationale, force=a.force,
                )
            elif a.cmd == "opinion" and a.opinion_cmd == "init":
                result = init_opinion_dock(Path(a.root), a.owner, force=a.force)
            elif a.cmd == "opinion" and a.opinion_cmd == "verify":
                result = verify_opinion_dock(Path(a.dock))
            elif a.cmd == "opinion":
                rule = json.loads(Path(a.rule_file).read_text(encoding="utf-8"))
                result = correct_opinion_dock(Path(a.dock), a.owner, rule, a.rationale)
            elif a.cmd == "signal" and a.signal_cmd == "capture":
                body = a.body if a.body is not None else Path(a.body_file).read_text(encoding="utf-8")
                result = capture_signal(
                    Path(a.root), source=a.source, title=a.title, body=body,
                    authorization=a.authorization, severity=a.severity,
                    external_id=a.external_id, url=a.url, observed_at=a.observed_at,
                    hypotheses=a.hypothesis, requirements=a.requirement,
                    outcomes=a.outcome, acceptance=a.acceptance,
                )
            elif a.cmd == "signal" and a.signal_cmd == "triage":
                result = triage_signal(Path(a.signal), Path(a.dock), Path(a.root), force=a.force)
            elif a.cmd == "signal" and a.signal_cmd == "decide":
                result = decide_triage(
                    Path(a.triage), Path(a.root), owner=a.owner, decision=a.decision,
                    rationale=a.rationale, override_block=a.override_block, force=a.force,
                )
            elif a.cmd == "signal" and a.signal_cmd == "feedback":
                result = capture_outcome_feedback(
                    Path(a.root), mission_id=a.mission_id, metric=a.metric,
                    observed=a.observed, target=a.target, evidence_path=Path(a.evidence),
                )
            elif a.cmd == "signal":
                result = promote_signal(Path(a.decision), Path(a.root), project=a.project, force=a.force)
            elif a.cmd == "learning" and a.learning_cmd == "init":
                milestones = json.loads(Path(a.milestones).read_text(encoding="utf-8"))
                result = init_learning_task(Path(a.root), a.task_id, a.owner, a.objective, milestones, force=a.force)
            elif a.cmd == "learning" and a.learning_cmd == "packet":
                result = build_fresh_worker_packet(Path(a.task), a.milestone, a.worker, force=a.force)
            elif a.cmd == "learning" and a.learning_cmd == "propose":
                instructions = json.loads(Path(a.instructions).read_text(encoding="utf-8"))
                result = propose_instruction_candidate(
                    Path(a.task), Path(a.root), a.milestone, a.worker,
                    Path(a.outcome), instructions, force=a.force,
                )
            elif a.cmd == "learning" and a.learning_cmd == "validate":
                results = json.loads(Path(a.results).read_text(encoding="utf-8"))
                result = validate_instruction_candidate(
                    Path(a.candidate), Path(a.root), a.validator, results, force=a.force,
                )
            elif a.cmd == "learning" and a.learning_cmd == "experiment":
                space = json.loads(Path(a.space).read_text(encoding="utf-8"))
                result = plan_learning_experiment(
                    Path(a.task), space, variant=a.variant, max_resource=a.max_resource,
                    grace_period=a.grace_period, reduction_factor=a.reduction_factor,
                    max_concurrent=a.max_concurrent, samples=a.samples, force=a.force,
                )
            elif a.cmd == "learning":
                result = promote_instruction_candidate(Path(a.validation), a.owner, force=a.force)
            elif a.cmd == "pr":
                result = draft_pr(Path(a.mission), Path(a.root), [Path(item) for item in a.evidence], a.force)
            elif a.outcome_cmd == "record":
                result = record_outcome(
                    Path(a.mission), Path(a.root), a.metric, a.value, a.target,
                    a.evidence_class, a.source, a.notes,
                )
            else:
                result = outcome_summary(Path(a.root), a.mission_id)
        except (ProductMissionError, SignalLoopError, LearningLoopError, MigrationError, MissionGraphError, ProofDeltaError, ProviderRouterError, AgentContractError, VerifierPlaneError, LangGraphAssuranceError) as exc:
            print(json.dumps({
                "schema": "factory.workflow_error.v1", "status": "failed",
                "code": exc.code, "message": exc.message,
                "marker": getattr(exc, "marker", "WORKFLOW_REJECTED"),
                "failure": getattr(exc, "guidance", explain_failure(exc.code, exc.message)),
            }, indent=2), file=sys.stderr)
            return 1
        except (OSError, json.JSONDecodeError) as exc:
            print(json.dumps({
                "schema": "factory.workflow_error.v1", "status": "failed",
                "code": "E_INPUT", "message": str(exc),
                "failure": explain_failure("E_INPUT", str(exc)),
            }, indent=2), file=sys.stderr)
            return 1
        if a.cmd == "langgraph" and a.langgraph_cmd == "replay-verify" and a.mermaid:
            print(result["mermaid"])
        else:
            print(json.dumps(result, indent=2, sort_keys=True))
        if (
            (a.cmd == "product" and a.product_cmd == "verify")
            or (a.cmd == "mission" and a.mission_cmd in {"verify", "verify-completion"})
            or (a.cmd == "mission" and a.mission_cmd == "proof-delta" and a.mission_delta_cmd == "verify")
            or (a.cmd == "opinion" and a.opinion_cmd == "verify")
            or (a.cmd == "langgraph" and a.langgraph_cmd == "verify")
            or (a.cmd == "langgraph" and a.langgraph_cmd == "replay-verify")
            or (a.cmd == "provider" and a.provider_cmd == "verify")
            or (a.cmd == "agent" and a.agent_cmd in {"contract", "attestation"})
            or (a.cmd == "verifier" and a.verifier_cmd == "verify")
        ):
            return 0 if result.get("valid", result.get("verdict") == "VERIFIED") else 1
        return 0
    if a.cmd == "targets":
        payload = {"schema": "factory.targets.v1", "targets": TARGETS}
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            for target_kind, metadata in TARGETS.items():
                print(f"{target_kind}: {metadata['label']}")
                print(f"  {metadata['summary']}")
                for profile in metadata["deployment_profiles"]:
                    print(f"  - {profile['id']}: {profile['label']} [approval: {profile['approval']}]")
        return 0
    if a.cmd == "admission":
        from .run_admission import AdmissionError, prepare_admission, verify_admission
        try:
            if a.admission_cmd == "prepare":
                result = prepare_admission(Path(a.root), Path(a.passport), Path(a.request), Path(a.out_dir) if a.out_dir else None)
                code = 0
            else:
                result = verify_admission(Path(a.root), Path(a.packet))
                code = 0 if result["verdict"] == "READY" else 1
        except AdmissionError as exc:
            result = {"schema": "factory.run-admission.error.v1", "code": exc.code, "message": str(exc)}
            code = 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        elif code == 0:
            print(f"admission: {result.get('marker', result.get('verdict'))}")
        else:
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
        return code
    if a.cmd == "pack":
        try:
            if a.pack_cmd == "list":
                packs = []
                for item in builtin_packs():
                    validation = validate_pack(Path(item["path"]))
                    packs.append({
                        "id": item["id"], "version": item["version"], "kind": item["kind"],
                        "target_kind": item.get("target_kind"), "label": item["label"],
                        "path": item["path"], "valid": validation["valid"],
                        "signature": validation["signature"], "mutations": validation["mutations"],
                    })
                result = {
                    "schema": "factory.capability_pack.inventory.v1", "packs": packs,
                    "markers": ["PACK_INVENTORY_DERIVED", "PACK_SIGNATURE_BYPASS_DENIED"],
                }
            elif a.pack_cmd == "validate":
                result = validate_pack(Path(a.path), verify_signature=True, mutate=True)
            elif a.pack_cmd == "install":
                result = install_pack(Path(a.path), Path(a.root), force=a.force)
            else:
                result = compose_packs(
                    [Path(path) for path in a.paths], Path(a.root), name=a.name, force=a.force,
                )
        except CapabilityPackError as exc:
            print(json.dumps({
                "schema": "factory.capability_pack.error.v1", "status": "failed",
                "code": exc.code, "message": exc.message, "markers": exc.markers, "failure": exc.guidance,
            }, indent=2), file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("valid", True) else 1
    if a.cmd == "create":
        if bool(a.prompt) == bool(a.prd):
            payload = {
                "schema": "factory.target_compile_error.v1",
                "status": "failed",
                "code": "SOURCE_EXACTLY_ONE",
                "marker": "COMPILE_FAILED",
                "message": "provide exactly one source: prompt or --prd",
                "failure": explain_failure("SOURCE_EXACTLY_ONE", "provide exactly one source: prompt or --prd"),
            }
            print(json.dumps(payload, indent=2), file=sys.stderr)
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
            code = exc.code if isinstance(exc, TargetCompileError) else "PRD_ENCODING_INVALID"
            message = exc.message if isinstance(exc, TargetCompileError) else "PRD must be valid UTF-8"
            payload = {
                "schema": "factory.target_compile_error.v1",
                "status": "failed",
                "code": code,
                "marker": "COMPILE_FAILED",
                "message": message,
                "failure": exc.guidance if isinstance(exc, TargetCompileError) else explain_failure(code, message),
            }
            print(json.dumps(payload, indent=2), file=sys.stderr)
            return 1
        if a.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"target compiled: {result['out_dir']}")
            print(f"kind           : {result['target_kind']}")
            print(f"state          : {result['status']}")
            print(f"deploy route   : {result['deployment']['profile']['label']} ({result['deployment']['selected_profile_id']})")
            print(f"deploy approval: {result['deployment']['profile']['approval']}")
            print(f"receipt        : {result['receipt']}")
        return 0
    if a.cmd == "studio":
        if a.check:
            payload = studio_status(Path(a.root), a.port)
            if a.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print("Factory Studio check")
                print(f"marker  : {payload['marker']}")
                print(f"listener: {payload['listener']['host']}:{payload['listener']['port']}")
                print(f"root    : {payload['root']}")
            return 0
        try:
            print("marker: STUDIO_STARTED", flush=True)
            serve_studio(Path(a.root), port=a.port, open_browser=not a.no_browser)
        except StudioRequestError as exc:
            print(f"studio failed: {exc.code}: {exc.message}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"studio failed: LISTENER_ERROR: {exc}", file=sys.stderr)
            return 1
        return 0
    if a.cmd == "first-proof":
        workspace = Path(a.root).resolve()
        out_dir = Path(a.out_dir) if a.out_dir else None
        try:
            result = run_first_proof(workspace, out_dir=out_dir)
        except (AdoptionError, E2EProofError, OSError) as exc:
            code = getattr(exc, "code", "E_FIRST_PROOF_FAILED")
            error = {"schema": "factory.first-proof.error.v1", "code": code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"first proof failed: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("factory first-proof")
            print("=" * 44)
            print("result   : HOLLOW_TEST_DETECTED")
            print("meaning  : the sandbox negative check also passed, so the test could not say no")
            print(f"receipt  : {result['activation_path']}")
            print(f"share    : {result['proof_card']['paths']['svg']}")
            print("boundary : demo only; your project was not assessed and nothing was uploaded")
        return 0
    if a.cmd == "proof-card":
        workspace = Path(a.root).resolve()
        try:
            result = proof_card_from_receipt(workspace, Path(a.receipt), Path(a.out_dir))
            record_adoption_event(workspace, "proof_card_saved", evidence_sha256=result["card"]["card_sha256"])
        except (AdoptionError, OSError) as exc:
            code = getattr(exc, "code", "E_PROOF_CARD_FAILED")
            error = {"schema": "factory.proof-card.error.v1", "code": code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"proof card failed: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("factory proof-card")
            print("=" * 44)
            print(f"outcome  : {result['card']['outcome']}")
            print(f"card     : {result['paths']['svg']}")
            print("privacy  : no commands, paths, repository name, prompts, logs, or user identity")
        return 0
    if a.cmd == "adoption":
        workspace = Path(a.root).resolve()
        try:
            if a.adoption_cmd == "record":
                result = record_adoption_event(workspace, a.milestone, evidence_sha256=a.evidence_sha256)
            elif a.adoption_cmd == "export":
                result = export_adoption_status(workspace, Path(a.out))
            else:
                result = adoption_status(workspace)
        except (AdoptionError, OSError) as exc:
            code = getattr(exc, "code", "E_ADOPTION_FAILED")
            error = {"schema": "factory.adoption.error.v1", "code": code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"adoption failed: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print("factory adoption")
            print("=" * 44)
            if a.adoption_cmd == "record":
                print(f"milestone: {result['event']['milestone']}")
                print(f"receipt  : {result['path']}")
            else:
                status = result.get("status", result)
                print(f"events   : {status['events']}")
                print(f"first    : {status['milestones']['first_proof_completed']}")
                print(f"returns  : {status['milestones']['seven_day_return']}")
                print("boundary : local opt-in counts only; not users, conversion, or attribution")
        return 0
    if a.cmd == "e2e":
        workspace = Path(a.root).resolve()
        manifest = Path(a.manifest)
        if not manifest.is_absolute():
            manifest = workspace / manifest
        try:
            receipt = verify_e2e_proof(workspace, manifest)
            artifacts = write_e2e_proof_artifacts(receipt, Path(a.out_dir)) if a.out_dir else None
        except E2EProofError as exc:
            error = {
                "schema": "factory.e2e_proof.error.v1",
                "marker": exc.code,
                "code": exc.code,
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"e2e proof failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        public = public_e2e_proof_receipt(receipt)
        if a.json:
            output = {"receipt": public}
            if artifacts:
                output["artifacts"] = artifacts
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            print("factory e2e verify")
            print("=" * 44)
            print(f"proof id : {public['manifest']['id']}")
            print(f"result   : {public['marker']} ({'passing' if public['ok'] else 'non-passing'})")
            print(f"positive : {public['commands']['positive']['status']} / exit {public['commands']['positive']['exit_code']}")
            print(f"negative : {public['commands']['negative']['status']} / exit {public['commands']['negative']['exit_code']}")
            print("authority: caller-approved local test execution only; no release, deployment, credential, or egress enforcement")
            if artifacts:
                print(f"packet   : {artifacts['paths']['markdown']}")
        return 0 if public["ok"] else 1
    if a.cmd == "counterexample":
        workspace = Path(a.root).resolve()
        try:
            if a.counterexample_cmd == "plan":
                source = Path(a.source)
                if not source.is_absolute():
                    source = workspace / source
                out = Path(a.out)
                if not out.is_absolute():
                    out = workspace / out
                try:
                    out.resolve().relative_to(workspace)
                except ValueError as exc:
                    raise CounterexampleError("COUNTEREXAMPLE_PATH_INVALID", "plan output must stay inside the workspace") from exc
                payload = compile_counterexample_plan(workspace, source)
                path = write_counterexample_plan(payload, out)
                payload = {**payload, "path": str(path.resolve())}
            else:
                plan = Path(a.plan)
                if not plan.is_absolute():
                    plan = workspace / plan
                payload = verify_counterexample_plan(workspace, plan)
        except CounterexampleError as exc:
            error = {"schema": "factory.counterexample.error.v1", "code": exc.code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"counterexample failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory counterexample")
            print("=" * 44)
            print(f"marker    : {payload['marker']}")
            print(f"cases     : {payload.get('facts', {}).get('case_count', payload.get('case_count', 0))}")
            print("authority : negative-proof planning only; execution, source writes, repair, approval, and publication are locked")
        return 0 if a.counterexample_cmd == "plan" or payload["ok"] else 1
    if a.cmd == "guardrail":
        from .continuity import ContinuityError, principal_from_args as continuity_principal_from_args

        try:
            if a.guardrail_cmd == "evaluate":
                principal = continuity_principal_from_args(a.subject, a.tenant, a.roles.split(","), a.purposes.split(","))
                payload = evaluate_guardrails(Path(a.manifest), Path(a.db), principal, changed_paths=a.changed)
            else:
                payload = verify_guardrail_evaluation(json.loads(Path(a.evaluation).read_text(encoding="utf-8")))
        except (GuardrailError, ContinuityError, OSError, json.JSONDecodeError) as exc:
            error = {"schema": "factory.guardrail.error.v1", "code": getattr(exc, "code", "GUARDRAIL_INPUT_INVALID"), "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"guardrail failed: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory guardrail")
            print("=" * 44)
            print(f"marker    : {payload['marker']}")
            print(f"active    : {payload.get('facts', {}).get('active_count', 0)}")
            print(f"withheld  : {payload.get('facts', {}).get('withheld_count', 0)}")
            print("boundary  : only redacted promoted metadata is evaluated; memory content, edits, execution, and promotion remain unavailable")
        return 0
    if a.cmd == "resilience":
        workspace = Path(a.root).resolve()
        try:
            if a.resilience_cmd == "plan":
                lineage = Path(a.lineage)
                if not lineage.is_absolute():
                    lineage = workspace / lineage
                out = Path(a.out)
                if not out.is_absolute():
                    out = workspace / out
                try:
                    out.resolve().relative_to(workspace)
                except ValueError as exc:
                    raise ResilienceError("RESILIENCE_PATH_INVALID", "plan output must stay inside the workspace") from exc
                payload = compile_temporal_resilience_plan(workspace, lineage)
                path = write_temporal_resilience_plan(payload, out)
                payload = {**payload, "path": str(path.resolve())}
            else:
                plan = Path(a.plan)
                if not plan.is_absolute():
                    plan = workspace / plan
                payload = verify_temporal_resilience_plan(workspace, plan)
        except ResilienceError as exc:
            error = {"schema": "factory.temporal-resilience.error.v1", "code": exc.code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"resilience failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory temporal resilience")
            print("=" * 44)
            print(f"marker    : {payload['marker']}")
            print(f"schedules : {payload.get('facts', {}).get('schedule_count', payload.get('schedule_count', 0))}")
            print("authority : schedule derivation only; graph invocation, replay, checkpoint mutation, repair, and approval are locked")
        return 0 if a.resilience_cmd == "plan" or payload["ok"] else 1
    if a.cmd == "reality":
        workspace = Path(a.root).resolve()
        manifest = Path(a.manifest)
        if not manifest.is_absolute():
            manifest = workspace / manifest
        try:
            if a.reality_cmd == "inspect":
                inspection = inspect_reality_intent(workspace, manifest)
                if a.json:
                    print(json.dumps(inspection, indent=2, sort_keys=True))
                else:
                    print("factory reality inspect")
                    print("=" * 44)
                    print(f"promise  : {inspection['manifest']['behavior']['promise']}")
                    print(f"coverage : {len(inspection['positive_assertion_ids'])} positive / {len(inspection['negative_assertion_ids'])} negative assertions")
                    print("execution: locked; this only validates the declared intent contract")
                return 0
            receipt = run_reality_check(workspace, manifest)
            artifacts = write_reality_check_artifacts(receipt, Path(a.out_dir)) if a.out_dir else None
        except RealityCheckError as exc:
            error = {"schema": "factory.reality-check.error.v1", "marker": exc.code, "code": exc.code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"reality check failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            output = {"receipt": receipt}
            if artifacts:
                output["artifacts"] = artifacts
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            print("factory reality verify")
            print("=" * 44)
            print(f"promise  : {receipt['manifest']['behavior']['promise']}")
            print(f"result   : {receipt['marker']} ({'passing' if receipt['ok'] else 'non-passing'})")
            print("authority: caller-approved local test execution only; no repair, merge, release, deployment, credential, or egress enforcement")
            if artifacts:
                print(f"packet   : {artifacts['markdown']}")
        return 0 if receipt["ok"] else 1
    if a.cmd == "license":
        def local_path(workspace: Path, value: str) -> Path:
            candidate = Path(value)
            resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
            try:
                resolved.relative_to(workspace)
            except ValueError as exc:
                raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", "path must remain inside the workspace") from exc
            return resolved

        try:
            if a.license_cmd == "verify":
                payload = verify_license(Path(a.license))
                code = 0 if payload["ok"] else 1
            elif a.license_cmd == "seal":
                payload = seal_license(
                    Path(a.license), private_key_path=Path(a.private_key), keyid=a.keyid,
                    identity=a.identity, issuer=a.issuer, tenant_id=a.tenant, out=Path(a.out),
                )
                code = 0
            else:
                workspace = Path(a.root).resolve()
                if not workspace.is_dir():
                    raise AgentLicenseError("E_LICENSE_PATH_OUT_OF_SCOPE", "root must be an existing workspace directory")
                if a.license_cmd == "record":
                    payload = record_governed_run(workspace, local_path(workspace, a.event), out_dir=local_path(workspace, a.out_dir) if a.out_dir else None)
                else:
                    identity = json.loads(local_path(workspace, a.agent).read_text(encoding="utf-8-sig"))
                    if a.license_cmd == "status":
                        payload = {"marker": "AGENT_LICENSE_STATUS_READ_ONLY", "license": derive_license(workspace, identity), "authority": {"execution": False, "approval": False, "repair": False, "merge": False, "publication": False, "deployment": False, "signing": False, "messaging": False, "credential": False, "connector": False}}
                    else:
                        payload = issue_license(workspace, identity, out=local_path(workspace, a.out) if a.out else None)
                code = 0
        except (AgentLicenseError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            error = {"schema": "factory.agent-license.error.v1", "marker": getattr(exc, "code", "E_LICENSE_INPUT_UNREADABLE"), "code": getattr(exc, "code", "E_LICENSE_INPUT_UNREADABLE"), "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"agent license failed: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory license")
            print("=" * 44)
            if a.license_cmd == "status":
                license_value = payload["license"]
                print(f"tier      : {license_value['tier']}")
                print(f"reason    : {license_value['reason']}")
                print(f"evidence  : {license_value['evidence']['current_governed_event_count']} current governed event(s)")
                print(f"expires   : {license_value['expires_at'] or 'no evidence'}")
            else:
                print(f"marker    : {payload['marker']}")
            print("authority : local evidence only; no agent execution, approval, repair, merge, publication, deployment, or credential authority")
        return code
    if a.cmd == "combine":
        def local_path(workspace: Path, value: str) -> Path:
            candidate = Path(value)
            resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
            try:
                resolved.relative_to(workspace)
            except ValueError as exc:
                raise CombineError("COMBINE_PATH_OUT_OF_SCOPE", "path must remain inside the workspace") from exc
            return resolved

        try:
            if a.combine_cmd == "verify":
                payload = verify_combine_scoreboard(Path(a.scoreboard))
                code = 0 if payload["ok"] else 1
            elif a.combine_cmd == "seal":
                payload = seal_combine_scoreboard(
                    Path(a.scoreboard), private_key_path=Path(a.private_key), keyid=a.keyid,
                    identity=a.identity, issuer=a.issuer, tenant_id=a.tenant, out=Path(a.out),
                )
                code = 0
            else:
                workspace = Path(a.root).resolve()
                if not workspace.is_dir():
                    raise CombineError("COMBINE_PATH_OUT_OF_SCOPE", "root must be an existing workspace directory")
                if a.combine_cmd == "task":
                    payload = seal_combine_task(workspace, local_path(workspace, a.source), out=local_path(workspace, a.out) if a.out else None)
                elif a.combine_cmd == "score":
                    payload = score_combine(workspace, local_path(workspace, a.task), event_paths=[local_path(workspace, event) for event in a.event] or None, out=local_path(workspace, a.out) if a.out else None)
                else:
                    payload = combine_projection(workspace)
                code = 0
        except (CombineError, AgentLicenseError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            error = {"schema": "factory.combine.error.v1", "marker": getattr(exc, "code", "COMBINE_INPUT_UNREADABLE"), "code": getattr(exc, "code", "COMBINE_INPUT_UNREADABLE"), "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"combine failed: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory combine")
            print("=" * 44)
            if a.combine_cmd == "status":
                print(f"scoreboards: {len(payload['scoreboards'])}")
            elif a.combine_cmd == "score":
                print(f"passed    : {payload['scoreboard']['summary']['passed_count']}/{payload['scoreboard']['summary']['candidate_count']}")
                print(f"scoreboard: {payload['path']}")
            else:
                print(f"marker    : {payload['marker']}")
            print("authority : completed governed evidence only; no agent execution, vendor ranking, repair, approval, merge, publication, or deployment")
        return code
    if a.cmd == "wrap":
        workspace = Path(a.root).resolve()
        command = list(a.command)
        if command and command[0] == "--":
            command = command[1:]
        try:
            payload = run_observed_session(
                workspace,
                workspace / a.admission,
                workspace / a.validators,
                command,
                a.run_id,
            )
        except (SessionRecorderError, AgentLicenseError) as exc:
            code = getattr(exc, "code", "SESSION_FAILED")
            error = {"schema": "factory.observed-session.error.v1", "marker": code, "code": code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"wrap failed: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory wrap")
            print("=" * 44)
            print(f"result   : {'PASSED' if payload['session']['passed'] else 'FAILED'}")
            print(f"receipt  : {payload['path']}")
            print("authority: observed local execution and declared validators; not a sandbox, approval, repair, merge, publication, or deployment")
        return 0 if payload["session"]["passed"] else 1
    if a.cmd == "gauntlet":
        workspace = Path(getattr(a, "root", ".")).resolve()

        def workspace_path(value: str | None) -> Path | None:
            if value is None:
                return None
            candidate = Path(value)
            return candidate if candidate.is_absolute() else workspace / candidate

        try:
            if a.gauntlet_cmd == "draft":
                payload = draft_gauntlet(workspace, a.source_id)
                code = 0
            elif a.gauntlet_cmd == "plan":
                proposal = compile_gauntlet_proposal(workspace, workspace_path(a.source))
                path = write_gauntlet_proposal(workspace, proposal, workspace_path(a.out))
                payload: dict[str, object] = {"proposal": proposal, "path": str(path)}
                code = 0
            elif a.gauntlet_cmd == "admit":
                payload = admit_gauntlet(
                    workspace,
                    workspace_path(a.proposal),
                    approved_by=a.approved_by,
                    rationale=a.rationale,
                    confirmation=a.confirmation,
                    valid_for_minutes=a.valid_for_minutes,
                    out=workspace_path(a.out),
                )
                code = 0
            elif a.gauntlet_cmd == "run":
                payload = run_gauntlet(workspace, workspace_path(a.proposal), workspace_path(a.admission), workspace_path(a.out))
                code = 0 if payload["card"]["ok"] else 1
            elif a.gauntlet_cmd == "status":
                payload = gauntlet_status(workspace, a.source_id)
                code = 0
            elif a.gauntlet_card_cmd == "verify":
                payload = verify_survival_card(Path(a.card), envelope_path=Path(a.envelope) if a.envelope else None, trust_root_path=Path(a.trust_root) if a.trust_root else None)
                code = 0
            elif a.gauntlet_card_cmd == "challenge":
                payload = challenge_survival_card(Path(a.card))
                code = 0 if payload["ok"] else 1
            else:
                payload = seal_survival_card(
                    Path(a.card), private_key_path=Path(a.private_key), keyid=a.keyid,
                    identity=a.identity, issuer=a.issuer, tenant_id=a.tenant, out=Path(a.out),
                )
                code = 0
        except (GauntletError, GauntletDraftError) as exc:
            error = {"schema": "factory.gauntlet.error.v1", "marker": exc.code, "code": exc.code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if getattr(a, "json", False) else f"gauntlet failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if getattr(a, "json", False):
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory gauntlet")
            print("=" * 44)
            if a.gauntlet_cmd == "draft":
                print(f"draft    : {payload['path']}")
                print(f"promises : {payload['draft']['facts']['cli_entrypoint_count']}")
                print("authority: static DRAFT only; no command execution, approval, admission, repair, or release")
            elif a.gauntlet_cmd == "run":
                card = payload["card"]
                print(f"result   : {card['marker']}")
                print(f"survived : {card['summary']['survived_count']}/{card['summary']['case_count']}")
                print(f"unproven : {card['summary']['unproven_promise_count']}")
                print("authority: exact admitted local E2E execution only; no repair, merge, release, deployment, signing, credentials, or connectors")
                print(f"card     : {payload['path']}")
            elif a.gauntlet_cmd == "plan":
                print(f"proposal : {payload['path']}")
                print("authority: planning only; no command execution or admission")
            elif a.gauntlet_cmd == "admit":
                print(f"admission: {payload['path']}")
                print(f"expires  : {payload['expires_at']}")
                print("authority: named one-batch admission only; no command executed")
            elif a.gauntlet_cmd == "status":
                print(f"cards    : {len(payload['entries'])}")
                print("authority: local read-only status")
            else:
                print(f"marker   : {payload['marker']}")
                print("authority: offline card validation or explicit optional signing only")
        return code
    if a.cmd == "team-pilot":
        try:
            if a.team_pilot_cmd == "verify":
                receipt = json.loads(Path(a.receipt).read_text(encoding="utf-8"))
                result = validate_team_pilot_receipt(receipt)
                if a.json:
                    print(json.dumps({"receipt": result}, indent=2, sort_keys=True))
                else:
                    print("factory team-pilot verify")
                    print("=" * 44)
                    print(f"pilot    : {result['manifest']['pilot_id']}")
                    print(f"result   : {result['marker']}")
                    print("authority: owner review only; no contract, payment, entitlement, Marketplace, deployment, or service activation")
                return 0
            workspace = Path(a.root).resolve()
            manifest = Path(a.manifest)
            if not manifest.is_absolute():
                manifest = workspace / manifest
            receipt = evaluate_team_pilot_readiness(workspace, manifest)
            artifacts = write_team_pilot_artifacts(receipt, Path(a.out_dir)) if a.out_dir else None
        except (TeamPilotError, UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
            code = exc.code if isinstance(exc, TeamPilotError) else "E_TEAM_PILOT_RECEIPT_INVALID"
            error = {
                "schema": "factory.team-pilot.error.v1",
                "marker": code,
                "code": code,
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"team pilot failed: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            output = {"receipt": receipt}
            if artifacts:
                output["artifacts"] = artifacts
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            print("factory team-pilot readiness")
            print("=" * 44)
            print(f"pilot    : {receipt['manifest']['pilot_id']}")
            print(f"partners : {receipt['manifest']['partner_count']} / 3")
            print(f"result   : {receipt['marker']}")
            print("authority: owner review only; no contract, payment, entitlement, Marketplace, deployment, or service activation")
            if artifacts:
                print(f"packet   : {artifacts['paths']['markdown']}")
        return 0
    if a.cmd == "plan":
        if a.plan_cmd is None:
            return _plan()
        try:
            review = review_plan_proof(
                Path(a.root), Path(a.plan), base=a.base, changed=a.changed or None,
            )
            if a.out_dir:
                review["artifacts"] = write_plan_proof_review_artifacts(review, Path(a.out_dir))
        except (ChangeReviewError, PlanProofReviewError) as exc:
            error = {
                "schema": "factory.plan_proof_review.error.v1",
                "marker": getattr(exc, "code", "PLAN_TO_PROOF_PLAN_INVALID"),
                "code": getattr(exc, "code", "PLAN_TO_PROOF_PLAN_INVALID"),
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"plan proof review failed: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(review, indent=2, sort_keys=True))
        else:
            print("factory plan verify (analysis only)")
            print("=" * 44)
            print(f"plan         : {review['plan']['provider']}/{review['plan']['plan_id']}")
            print(f"changed paths: {len(review['changed_paths'])}")
            print(f"proof debt   : {review['proof_debt']['count']} ({review['proof_debt']['state']})")
            print(f"next action  : {review['next_action']['action']}")
            if review.get("artifacts"):
                print(f"packet       : {review['artifacts']['paths']['markdown']}")
            print("authority    : no execution, approval, merge, publication, deployment, or credential access")
        return 0
    if a.cmd == "init":
        ensure_layout(Path(a.root))
        print(f"factory layout created under {Path(a.root).resolve()}")
        for sub_name in LAYOUT.values():
            print(f"  {sub_name}/")
        return 0
    if a.cmd == "assemble":
        report = assemble(Path(a.root), a.feature, dry_run=a.dry_run)
        print(json.dumps(report, indent=2))
        return 0 if "halted_at" not in report else 1
    if a.cmd == "continue":
        try:
            usage = json.loads(Path(a.usage_json).read_text(encoding="utf-8")) if a.usage_json else None
            report = continue_assembly(Path(a.root), a.feature, dry_run=a.dry_run, usage=usage)
        except (ContinuationError, ValueError, OSError, json.JSONDecodeError) as exc:
            code = getattr(exc, "code", "CONTINUATION_INPUT_INVALID")
            payload = {"schema": "factory.assembly-continuation.error.v1", "code": code, "message": str(exc)}
            if isinstance(exc, ContinuationError):
                payload["candidates"] = exc.candidates
            print(json.dumps(payload, indent=2) if a.json else f"continue failed: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(report, indent=2))
        else:
            print("factory continuation")
            print(f"feature : {report['feature']}")
            print(f"status  : {report['status']}")
            print(f"stages  : {len(report['stages'])}")
            if report.get("next_action"):
                print(f"next    : {report['next_action']['label']}")
                if report["next_action"].get("command"):
                    print(f"command : {report['next_action']['command']}")
            if report.get("receipt"):
                print(f"receipt : {report['receipt']}")
        return 3 if report["status"] == "waiting_for_human" else 1 if report["status"] == "halted" else 0
    if a.cmd == "metrics":
        payload = public_metrics(Path(a.root))
        if a.out:
            export_public_metrics(Path(a.root), Path(a.out))
        if a.json or not a.out:
            print(json.dumps(payload, indent=2))
        else:
            print(f"public Assembly metrics written to {Path(a.out).resolve()}")
        return 0
    if a.cmd == "workspace":
        try:
            if a.workspace_cmd == "inspect":
                root = Path(a.root)
                payload = inspect_workspace(root)
                payload = dict(payload)
                payload["artifacts"] = {}
                if a.out_dir:
                    artifacts = write_workspace_advisor_artifacts(payload, root, Path(a.out_dir))
                    payload["artifacts"] = {"paths": artifacts, "write_mode": "explicit_local"}
                    payload["markers"] = [*payload["markers"], "WORKSPACE_ADVISOR_ARTIFACTS_EXPLICIT"]
            elif a.continuity_cmd == "baseline":
                root = Path(a.root)
                payload = capture_continuity_baseline(root)
                payload = dict(payload)
                payload["baseline_path"] = write_continuity_baseline(payload, root, Path(a.out))
                payload["markers"] = [*payload["markers"], "INDEX_CONTINUITY_ARTIFACT_EXPLICIT"]
            else:
                payload = compare_continuity(Path(a.root), Path(a.baseline))
        except (WorkspaceAdvisorError, IndexContinuityError) as exc:
            is_continuity = isinstance(exc, IndexContinuityError)
            error = {
                "schema": "factory.index_continuity.error.v1" if is_continuity else "factory.workspace_advisor.error.v1",
                "status": "failed",
                "code": exc.code,
                "marker": "INDEX_CONTINUITY_REFUSED" if is_continuity else "WORKSPACE_ADVISOR_REFUSED",
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"workspace command refused: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif a.workspace_cmd == "continuity":
            print("FactoryLine Index Continuity Guard")
            print(f"scope     : {payload.get('review_scope', 'baseline captured')}")
            print(f"boundary  : local structure only; no IDE, cache, index, or remote changes.")
            if payload.get("baseline_path"):
                print(f"baseline  : {payload['baseline_path']}")
            if payload.get("recommendation"):
                print(f"next step : {payload['recommendation']}")
        else:
            scan = payload["scan"]
            workspace = payload["workspace"]
            print("FactoryLine Workspace Load Advisor")
            print(f"workspace : {workspace['name']} ({workspace['path_classification']})")
            print(f"observed  : {scan['files_scanned']} files, {scan['bytes_scanned']} bytes; limited={scan['scan_limited']}")
            print("boundary  : local filesystem shape only; no IDE, cache, index, or remote changes.")
            for recommendation in payload["recommendations"]:
                print(f"  - [{recommendation['priority']}] {recommendation['action']}")
            if payload.get("artifacts"):
                print(f"artifacts : {payload['artifacts']['paths']}")
        return 0
    if a.cmd == "update-check":
        from .update_check import check_for_update, render
        result = check_for_update(Path(a.root), force=a.force)
        print(json.dumps(result, indent=2, sort_keys=True) if a.json else render(result))
        return 0

    if a.cmd == "habituation":
        from .habituation import (
            HabituationError, blind_spot_sample, evaluate_gate,
            export_public_habituation_report, public_habituation_report,
            record_resample_outcome, record_review,
        )
        root = Path(a.root)
        try:
            if a.hab_cmd == "record":
                payload = record_review(root, {
                    "review_id": a.review_id, "reviewer": a.reviewer,
                    "author_kind": a.author_kind, "review_seconds": a.review_seconds,
                    "changed_lines": a.changed_lines, "inline_comments": a.inline_comments,
                    "approved": a.approved,
                }, replace=a.replace)
                print(json.dumps(payload, indent=2, sort_keys=True) if a.json
                      else f"REVIEW_OBSERVED {a.review_id} scrutiny={payload['scrutiny_ratio']:.1f}s/100L")
                return 0
            if a.hab_cmd == "status":
                gate = evaluate_gate(root, allow_block=a.allow_block)
                if a.json:
                    print(json.dumps(gate, indent=2, sort_keys=True))
                else:
                    print(f"HABITUATION_GATE action={gate['action']} blocking={gate['blocking']}")
                    print(f"  warned={gate['reviewers_warned']} breached={gate['reviewers_breached']} "
                          f"proxy_corrected={gate['proxy_corrected_by_resampling']}")
                    print(f"  {gate['reason']}")
                return 1 if gate["blocking"] else 0
            if a.hab_cmd == "sample":
                payload = blind_spot_sample(root, rate=a.rate)
                print(json.dumps(payload, indent=2, sort_keys=True) if a.json
                      else f"BLIND_SPOT_SAMPLE_RECEIPTED selected={payload['selected_count']} "
                           f"of {payload['eligible_low_scrutiny']} low-scrutiny approvals")
                return 0
            if a.hab_cmd == "resample":
                payload = record_resample_outcome(
                    root, a.review_id, defect_found=a.defect_found,
                    reviewer=a.reviewer, notes=a.notes)
                print(json.dumps(payload, indent=2, sort_keys=True) if a.json
                      else f"RESAMPLE_OUTCOME_RECEIPTED {a.review_id} defect={payload['defect_found']}")
                return 0
            if a.hab_cmd == "report":
                if a.out:
                    path = export_public_habituation_report(
                        root, Path(a.out), enable_defect_linkage=a.enable_defect_linkage)
                    print(f"HABITUATION_PUBLIC_REPORT_EXPORTED {path}")
                else:
                    print(json.dumps(public_habituation_report(
                        root, enable_defect_linkage=a.enable_defect_linkage),
                        indent=2, sort_keys=True))
                return 0
        except (HabituationError, OSError) as exc:
            print(f"HABITUATION_REFUSED {getattr(exc, 'code', '')}: {exc}")
            return 2
        print("usage: factory habituation {record|status|sample|resample|report}")
        return 2

    if a.cmd == "cdte":
        from .cdte import (
            CDTEError, draft_adr, export_public_cdte_report,
            public_cdte_report, record_scan, resolve_conflict,
        )
        root = Path(a.root)
        if a.cdte_cmd == "scan":
            try:
                raw = json.loads(Path(a.constraints).read_text(encoding="utf-8"))
                constraints = raw["constraints"] if isinstance(raw, dict) else raw
                payload = record_scan(
                    root, a.run_id, constraints,
                    evidence=Path(a.evidence) if a.evidence else None,
                    replace=a.replace,
                )
            except (CDTEError, OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
                code = getattr(exc, "code", type(exc).__name__)
                print(f"CDTE_SCAN_REFUSED {code}: {exc}")
                return 2
            if a.adr:
                for index, conflict in enumerate(payload["conflicts"], start=1):
                    path = draft_adr(root, payload, conflict["conflict_id"], number=index)
                    print(f"ADR_DRAFTED {path}")
            if a.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(f"CDTE_SCAN_RECEIPTED {payload['run_id']} "
                      f"conflicts={len(payload['conflicts'])} "
                      f"fail_closed={payload['fail_closed']}")
                for conflict in payload["conflicts"]:
                    analysis = conflict["incompatibility_analysis"]
                    state = "withheld" if analysis["withheld"] else analysis["tier"]
                    print(f"  [{conflict['severity']}] {conflict['conflict_id']} "
                          f"{conflict['pair_id']} (analysis: {state})")
            # Non-zero exit so CI fails closed on a blocking contradiction.
            return 1 if payload["fail_closed"] else 0
        if a.cdte_cmd == "report":
            if a.out:
                print(f"CDTE_PUBLIC_REPORT_EXPORTED {export_public_cdte_report(root, Path(a.out))}")
            else:
                print(json.dumps(public_cdte_report(root), indent=2, sort_keys=True))
            return 0
        if a.cdte_cmd == "resolve":
            try:
                payload = resolve_conflict(
                    root, a.run_id, a.conflict_id,
                    decision=a.decision, approved_by=a.approved_by,
                    adr_path=Path(a.adr_path) if a.adr_path else None,
                    override=a.override, expires=a.expires,
                )
            except (CDTEError, OSError) as exc:
                print(f"CDTE_RESOLUTION_REFUSED {getattr(exc, 'code', '')}: {exc}")
                return 2
            print(json.dumps(payload, indent=2, sort_keys=True) if a.json
                  else f"CDTE_RESOLUTION_RECEIPTED {a.conflict_id} by {payload['approved_by']}")
            return 0
        print("usage: factory cdte {scan|report|resolve}")
        return 2

    if a.cmd == "savings":
        if a.savings_cmd == "record":
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
                payload = record_savings_pair(
                    Path(a.root), a.pair_id, baseline, factory_observation,
                    equivalent_outcome=a.equivalent_outcome,
                    evidence=Path(a.evidence) if a.evidence else None,
                    replace=a.replace,
                )
            except (SavingsError, OSError) as exc:
                code = getattr(exc, "code", "SAVINGS_INPUT_INVALID")
                print(
                    json.dumps({"code": code, "message": str(exc)}, indent=2)
                    if a.json else f"savings failed: {code}: {exc}",
                    file=sys.stderr,
                )
                return 2
            if a.json:
                print(json.dumps(payload, indent=2))
            else:
                values = payload["savings"]
                print("factory paired savings")
                print(f"pair          : {payload['pair_id']}")
                print(f"time saved    : {values['time_saved_ms']} ms")
                print(f"tokens saved  : {values['tokens_saved'] if values['tokens_saved'] is not None else 'unknown'}")
                print(f"cost saved    : {values['cost_saved_usd'] if values['cost_saved_usd'] is not None else 'unknown'}")
                print(f"productivity  : {values['productivity_gain_rate'] if values['productivity_gain_rate'] is not None else 'unknown'}")
                print(f"receipt       : {payload['receipt']}")
            return 0
        if a.savings_cmd == "report":
            payload = public_savings_report(Path(a.root))
            if a.out:
                export_public_savings_report(Path(a.root), Path(a.out))
            if a.json or not a.out:
                print(json.dumps(payload, indent=2))
            else:
                print(f"public savings report written to {Path(a.out).resolve()}")
            return 0
        p.error("savings requires record or report")

    if a.cmd == "proofs":
        try:
            if a.proofs_cmd == "record":
                manifest = load_proof_manifest(Path(a.manifest))
                gates = manifest.get("gates") if isinstance(manifest, dict) else None
                if not isinstance(gates, list) or not gates:
                    raise ProofReuseError("PROOF_MANIFEST_INVALID", "manifest contains no gates")
                selected = [gate for gate in gates if isinstance(gate, dict) and (a.gate is None or gate.get("name") == a.gate)]
                if len(selected) != 1:
                    raise ProofReuseError("PROOF_GATE_AMBIGUOUS", "select exactly one gate with --gate")
                payload = record_proof(
                    Path(a.root), selected[0], elapsed_ms=a.elapsed_ms,
                    tokens=a.tokens, replace=a.replace,
                )
            elif a.proofs_cmd == "plan":
                payload = plan_proofs(
                    Path(a.root), load_proof_manifest(Path(a.manifest)),
                    changed_paths=a.changed, auto_savings=a.auto_savings,
                    out=Path(a.out) if a.out else None,
                )
            elif a.proofs_cmd == "verify":
                payload = verify_proof_receipt(Path(a.root), Path(a.receipt))
            elif a.proofs_cmd == "challenge":
                payload = challenge_proof_receipt(Path(a.root), Path(a.receipt))
            else:
                p.error("proofs requires record, plan, verify, or challenge")
        except ProofReuseError as exc:
            failure = {"schema": "factory.proof-error.v1", "code": exc.code, "message": str(exc)}
            print(json.dumps(failure, indent=2) if getattr(a, "json", False) else f"proofs failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if getattr(a, "json", False):
            print(json.dumps(payload, indent=2))
        else:
            if a.proofs_cmd == "plan":
                print("factory proof plan")
                print("=" * 44)
                for item in payload["items"]:
                    print(f"{item['gate']}: {item['disposition']} - {item['reason']}")
                print(f"receipt: {payload['plan']}")
            else:
                print(json.dumps(payload, indent=2))
        if a.proofs_cmd in {"verify", "challenge"}:
            return 0 if payload.get("valid", payload.get("passed", False)) else 1
        return 0
    if a.cmd == "verify":
        result = verify_feature(Path(a.root), a.feature)
        if a.json:
            print(json.dumps(result, indent=2))
        else:
            print("factory verification")
            print("=" * 44)
            for module in result["modules"]:
                print(f"{module['label']:<8} {module['status'].upper()}")
            print(f"FACTORY  {'SHIPPABLE' if result['shippable'] else 'NOT SHIPPABLE'}")
            print(f"next action: {result['next_action']}")
        return 0 if result["shippable"] else 1
    if a.cmd == "meter":
        if a.interval <= 0:
            print("meter failed: --interval must be positive", file=sys.stderr)
            return 2
        if a.max_updates is not None and a.max_updates <= 0:
            print("meter failed: --max-updates must be positive", file=sys.stderr)
            return 2
        capture_exit = 0
        if capture_command is not None:
            command = list(capture_command)
            if not command:
                print("meter failed: --capture requires a command after --", file=sys.stderr)
                return 2
            started = time.monotonic()
            try:
                proc = subprocess.run(command, cwd=str(Path(a.root)))
                capture_exit = proc.returncode
            except FileNotFoundError:
                print(f"meter capture failed: executable not found: {command[0]}", file=sys.stderr)
                capture_exit = 127
            elapsed_ms = round((time.monotonic() - started) * 1000)
            from .meter import MeterLog, StageTiming
            MeterLog(Path(a.root)).record(StageTiming(
                module=a.module,
                stage=a.stage,
                wall_ms=elapsed_ms,
                model_calls=0,
                tokens_in=0,
                tokens_out=0,
                ok=capture_exit == 0,
                feature=a.feature,
                run_id=uuid.uuid4().hex,
            ))
        updates = 0
        while True:
            snapshot = live_snapshot(
                Path(a.root),
                baseline_tokens_per_run=a.baseline,
                runs_projected=a.runs,
            )
            if a.json:
                print(json.dumps(snapshot, sort_keys=True))
            else:
                print(live_summary_table(snapshot))
            updates += 1
            if not a.watch or (a.max_updates is not None and updates >= a.max_updates):
                break
            time.sleep(a.interval)
        return capture_exit
    if a.cmd == "rollup":
        print(json.dumps(rollup_receipts(Path(a.root), a.feature), indent=2))
        return 0
    if a.cmd == "trace":
        try:
            trace = build_trace(Path(a.root), a.feature, out=Path(a.out) if a.out else None)
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
            print(f"earliest failure   : {trace['rollup'].get('earliest_failing_stage') or 'none'}")
        return 0
    if a.cmd == "verify-trace":
        result = verify_trace(Path(a.trace), root=Path(a.root) if a.root else None)
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
    if a.cmd == "replay":
        trace_path = Path(a.trace)
        trace_root = Path(a.root) if a.root else Path(load_trace(trace_path).get("root", "."))
        changed = list(a.changed)
        if a.base:
            changed.extend(git_changed_paths(trace_root, a.base))
        plan = replay_plan(load_trace(trace_path), changed)
        if a.execute:
            verification = verify_trace(trace_path, root=trace_root)
            if not verification["valid"]:
                print(json.dumps(verification, indent=2) if a.json else "trace verification failed; replay refused")
                return 1
            result = execute_replay(plan, root=trace_root)
            print(json.dumps(result, indent=2) if a.json else "\n".join(
                f"{item['module']}:{item['stage']} {item['status']}" for item in result["results"]
            ))
            return 0 if result["ok"] else 1
        if a.json:
            print(json.dumps(plan, indent=2))
        else:
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
        return 0
    if a.cmd == "evidence":
        evidence = public_evidence(Path(a.root), a.feature, trace_path=Path(a.trace) if a.trace else None)
        print(json.dumps(evidence, indent=2) if a.json else public_evidence_text(evidence))
        return 0 if evidence["verified"] else 1
    if a.cmd == "risk-diff":
        changed = list(a.changed)
        if not changed:
            try:
                changed = git_changed_paths(Path(a.root), a.base)
            except RuntimeError as exc:
                print(f"risk-diff failed: {exc}", file=sys.stderr)
                return 1
        risk = risk_for_paths(changed)
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
    if a.cmd == "mvp":
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
            print(json.dumps(payload, indent=2) if a.json else f"MVP starter failed: {exc.code}: {exc.message}", file=sys.stderr)
            return 1
        payload = {
            "schema": "factory.mvp.v1",
            "marker": "MVP_STARTER_CONTAINED",
            "markers": sorted(set(result["markers"] + ["MVP_STARTER_CONTAINED", "MVP_PROOF_PATH_EXPLICIT"])),
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
            print("boundary   : deployment, publication, credentials, connectors, and messages remain unavailable")
        return 0
    if a.cmd == "proofsearch":
        try:
            if a.proofsearch_cmd == "plan":
                payload = create_proofsearch_plan(Path(a.root), Path(a.baseline), Path(a.candidate), a.changed, Path(a.out))
            elif a.proofsearch_cmd == "evaluate":
                payload = evaluate_proofsearch(Path(a.root), Path(a.request), Path(a.out))
            elif a.proofsearch_cmd == "frontier" and a.frontier_cmd == "plan":
                payload = plan_evidence_frontier(Path(a.root), Path(a.request), Path(a.out))
            elif a.proofsearch_cmd == "frontier":
                payload = verify_evidence_frontier(Path(a.root), Path(a.frontier))
            else:
                payload = verify_proofsearch_evaluation(Path(a.root), Path(a.evaluation))
        except (ProofSearchError, EvidenceFrontierError) as exc:
            schema = "factory.evidence-frontier.error.v1" if isinstance(exc, EvidenceFrontierError) else "factory.proofsearch.error.v1"
            print(json.dumps({"schema": schema, "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("factory ProofSearch (review only)")
            print("=" * 44)
            print(f"marker : {payload['marker']}")
            if "winner" in payload:
                print(f"winner : {payload['winner'] or 'none'}")
            if "next_experiment" in payload:
                print(f"next evidence : {payload['next_experiment'] or 'none'}")
            if "path" in payload:
                print(f"receipt: {payload['path']}")
            print("apply  : locked")
        if a.proofsearch_cmd == "verify" or (a.proofsearch_cmd == "frontier" and a.frontier_cmd == "verify"):
            return 0 if payload["valid"] else 1
        return 0
    if a.cmd == "graph":
        if a.graph_cmd == "lineage-mission":
            try:
                payload = seal_mission_graph_lineage(Path(a.mission), Path(a.root), a.run_id, Path(a.out))
            except (GraphForensicsError, ValueError) as exc:
                code = exc.code if isinstance(exc, GraphForensicsError) else "GRAPH_LINEAGE_HISTORY_INVALID"
                print(json.dumps({"schema": "factory.graph-lineage.error.v1", "code": code, "message": str(exc)}, indent=2), file=sys.stderr)
                return 2
            print(json.dumps(payload, indent=2, sort_keys=True) if a.json else f"exported mission lineage: {payload['path']}")
            return 0
        if a.graph_cmd == "lineage-seal":
            try:
                payload = seal_graph_lineage(a.run_id, a.graph_id, Path(a.steps), Path(a.out))
            except GraphForensicsError as exc:
                print(json.dumps({"schema": "factory.graph-lineage.error.v1", "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
                return 2
            print(json.dumps(payload, indent=2, sort_keys=True) if a.json else f"sealed graph lineage: {payload['path']}")
            return 0
        if a.graph_cmd == "lineage-verify":
            try:
                payload = verify_graph_lineage(Path(a.lineage))
            except GraphForensicsError as exc:
                print(json.dumps({"schema": "factory.graph-lineage.error.v1", "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
                return 2
            if a.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(f"graph lineage: {'valid' if payload['valid'] else 'invalid'}")
                for error in payload["errors"]:
                    print(f"- {error}")
            return 0 if payload["valid"] else 1
        if a.graph_cmd == "forensics":
            try:
                payload = graph_forensics(Path(a.baseline), Path(a.candidate))
            except GraphForensicsError as exc:
                print(json.dumps({"schema": "factory.graph-forensics.error.v1", "code": exc.code, "message": str(exc)}, indent=2), file=sys.stderr)
                return 2
            if a.mermaid:
                print(payload["mermaid"])
            elif a.json:
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                divergence = payload["divergence"]
                print("factory graph forensics (read-only)")
                print("=" * 44)
                print(f"first divergence: {divergence['candidate_node'] if divergence else 'none'}")
                print(f"anomalies       : {len(payload['anomalies'])}")
                print(f"recovery        : {payload['recovery_plan']['action']}")
            return 0
        if a.graph_cmd == "impact":
            try:
                payload = graph_ops_impact(Path(a.root), a.changed)
            except ValueError as exc:
                print(json.dumps({"schema": "factory.graph-impact.error.v1", "code": "CHANGED_PATH_INVALID", "message": str(exc)}, indent=2), file=sys.stderr)
                return 2
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
        elif a.graph_cmd == "portfolio":
            durations = None
            if a.durations:
                try:
                    durations = json.loads(Path(a.durations).read_text(encoding="utf-8-sig"))
                except (OSError, json.JSONDecodeError) as exc:
                    print(json.dumps({"schema": "factory.graph-portfolio.error.v1", "code": "DURATION_INPUT_INVALID", "message": str(exc)}, indent=2), file=sys.stderr)
                    return 2
            payload = graph_portfolio_plan(graph_ops_snapshot(Path(a.root)), durations)
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
        else:
            snapshot = graph_ops_snapshot(Path(a.root))
            if a.mermaid:
                print(snapshot["mermaid"])
            else:
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
    if a.cmd == "memory":
        brief = developer_memory_brief(Path(a.root), base=a.base, changed=a.changed or None)
        if a.json:
            print(json.dumps(brief, indent=2, sort_keys=True))
        else:
            next_action = brief["next_action"]
            team = brief["team"]
            print("factory memory brief (read-only)")
            print("=" * 44)
            print(f"next action : {next_action['action']}")
            print(f"actions     : {len(brief['actions'])}")
            print(f"team source : {team['source']['kind']} ({team['source']['roster_completeness']})")
            print("authority   : no proof execution, approval, memory recall, publication, deployment, or credential access")
        return 0
    if a.cmd == "change":
        try:
            review = review_change(Path(a.root), base=a.base, changed=a.changed or None)
            if a.out_dir:
                review["artifacts"] = write_review_artifacts(review, Path(a.out_dir))
        except ChangeReviewError as exc:
            payload = {
                "schema": "factory.change_review.error.v1",
                "marker": "DIFF_TO_PROOF_PATH_REJECTED" if exc.code in {"CHANGED_PATH_INVALID", "CHANGED_PATH_LIMIT"} else "DIFF_TO_PROOF_INPUT_UNAVAILABLE",
                "code": exc.code,
                "message": str(exc),
            }
            print(json.dumps(payload, indent=2) if a.json else f"change review failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(review, indent=2, sort_keys=True))
        else:
            print("factory change review (analysis only)")
            print("=" * 44)
            print(f"changed paths: {len(review['changed_paths'])}")
            print(f"next action : {review['next_action']['action']}")
            print(f"findings    : {len(review['findings'])}")
            if review.get("artifacts"):
                print(f"packet      : {review['artifacts']['paths']['markdown']}")
            print("authority   : no execution, merge, publication, deployment, or credential access")
        return 0
    if a.cmd == "proof-ops":
        try:
            if a.proof_ops_cmd == "assess":
                payload = assess_continuous_proof(
                    Path(a.root),
                    a.workflow_id,
                    Path(a.intent),
                    a.changed,
                    session_path=Path(a.session) if a.session else None,
                    session_phase=a.session_phase,
                    repair_scope_path=Path(a.repair_scope) if a.repair_scope else None,
                    repair_patch_path=Path(a.repair_patch) if a.repair_patch else None,
                    prior_receipt_path=Path(a.prior_receipt) if a.prior_receipt else None,
                    out_dir=Path(a.out_dir) if a.out_dir else None,
                )
            elif a.proof_ops_cmd == "verify":
                payload = verify_continuous_proof(Path(a.root), Path(a.receipt))
            else:
                payload = continuous_proof_history(Path(a.root))
        except (ContinuousProofError, OSError) as exc:
            error = {
                "schema": "factory.continuous-proof.error.v1",
                "marker": "CONTINUOUS_PROOF_REFUSED",
                "code": getattr(exc, "code", "CONTINUOUS_PROOF_INPUT_UNAVAILABLE"),
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"proof-ops {a.proof_ops_cmd} refused: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif a.proof_ops_cmd == "assess":
            print("factory continuous proof operations")
            print("=" * 44)
            print(f"route       : {payload['route']}")
            print(f"next action : {payload['next_action']['action']}")
            print(f"receipt     : {payload['artifacts']['json']}")
            print("authority   : no execution, patch apply, approval, merge, publication, deployment, credential, connector, or network action")
        elif a.proof_ops_cmd == "verify":
            print(f"{payload['marker']} {payload.get('path', '')}")
        else:
            print("factory continuous proof history (read-only)")
            print("=" * 44)
            print(f"verified records : {payload['verified_record_count']}")
            print(f"invalid or stale : {payload['invalid_or_stale_count']}")
            print(f"latest route     : {(payload['latest'] or {}).get('route', 'none')}")
            print("claim boundary   : records are not unique users; no savings are inferred")
        if a.proof_ops_cmd == "verify" and not payload["ok"]:
            return 1
        return 0
    if a.cmd == "proof-review":
        root = Path(getattr(a, "root", "."))
        try:
            if a.proof_review_cmd == "contract":
                payload = create_intent_contract(root, a.id, Path(a.draft), a.confirmed_by)
            elif a.proof_review_cmd == "quick":
                payload = create_quick_review(
                    root, a.id, Path(a.contract), a.changed,
                    session_path=Path(a.session) if a.session else None,
                    trajectory_path=Path(a.trajectory) if a.trajectory else None,
                    repair_scope_path=Path(a.repair_scope) if a.repair_scope else None,
                    repair_patch_path=Path(a.repair_patch) if a.repair_patch else None,
                    prior_receipt_path=Path(a.prior_receipt) if a.prior_receipt else None,
                    session_phase=a.session_phase,
                )
            elif a.proof_review_cmd == "verify":
                payload = verify_quick_review(root, Path(a.review))
            elif a.proof_review_cmd == "hooks":
                payload = install_hook_pack(root)
            elif a.proof_review_cmd == "trajectory":
                payload = prove_trajectory(root, Path(a.trace), Path(a.policy), a.id)
            elif a.proof_review_cmd == "trajectory-verify":
                payload = verify_trajectory(root, Path(a.trajectory))
            elif a.proof_review_cmd == "learn":
                payload = promote_regression(root, Path(a.review), a.id, a.confirmed_by, a.title)
            elif a.proof_review_cmd == "inbox":
                payload = team_proof_inbox(root)
            elif a.proof_review_cmd == "card":
                payload = create_proof_card(root, Path(a.review), a.id)
            else:
                payload = verify_proof_card(Path(a.card))
        except (ProofReviewError, OSError) as exc:
            error = {
                "schema": "factory.proof-review.error.v1",
                "marker": "PROOF_REVIEW_REFUSED",
                "code": getattr(exc, "code", "PROOF_REVIEW_INPUT_UNAVAILABLE"),
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"proof-review {a.proof_review_cmd} refused: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"{payload.get('marker', 'PROOF_REVIEW_OK')}")
            if payload.get("route"):
                print(f"route       : {payload['route']}")
            if payload.get("artifact"):
                print(f"artifact    : {payload['artifact']}")
            print("authority   : human review remains required; no execution, approval, merge, publication, deployment, credential, connector, or network action")
        if a.proof_review_cmd in {"verify", "trajectory-verify", "card-verify"} and not payload.get("ok"):
            return 1
        return 0
    if a.cmd == "revenue":
        try:
            root = Path(getattr(a, "root", ".")).resolve()
            if a.revenue_cmd == "validate":
                payload = validate_products(root, Path(a.products))
            elif a.revenue_cmd == "build":
                payload = build_revenue_bundle(root, Path(a.products), Path(a.out_dir))
            elif a.revenue_cmd == "growth-plan":
                payload = plan_growth(root, Path(a.products), Path(a.growth))
                if a.out:
                    out = Path(a.out)
                    out = out.resolve() if out.is_absolute() else (root / out).resolve()
                    out.relative_to(root)
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                    payload = {**payload, "path": str(out)}
            elif a.revenue_cmd == "benchmark":
                records = json.loads(Path(a.records).read_text(encoding="utf-8-sig"))
                payload = benchmark_cell(records)
            elif a.revenue_cmd == "replay":
                payload = replay_purchase_journey(root, Path(a.products), Path(a.events), Path(a.out))
            elif a.revenue_cmd == "testflight-sync":
                payload = sync_testflight_evidence(root, Path(a.feedback), Path(a.out))
            elif a.revenue_cmd == "failure-matrix":
                payload = evaluate_failure_matrix(root, Path(a.products), Path(a.evidence), Path(a.out))
            elif a.revenue_cmd == "policy-watch":
                payload = watch_policy_drift(root, Path(a.registry), Path(a.snapshot), Path(a.out))
            elif a.revenue_cmd == "memory-promote":
                payload = promote_evidence_memory(root, Path(a.entry), Path(a.out))
            elif a.revenue_cmd == "memory-query":
                payload = query_evidence_memory(root, a.app_id, a.journey, a.at)
            else:
                payload = compile_appforge_design(root, Path(a.brief), Path(a.out_dir))
        except (RevenueForgeError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            error = {"schema": "factory.revenueforge.error.v1", "marker": "REVENUEFORGE_REFUSED", "code": getattr(exc, "code", "REVENUEFORGE_INPUT_INVALID"), "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"revenue {a.revenue_cmd} refused: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(payload.get("marker", "REVENUEFORGE_OK"))
            if payload.get("receipt_sha256"):
                print(f"receipt     : {payload['receipt_sha256']}")
            print("authority   : no App Store write, offer send, experiment promotion, review publication, deployment, or credential access")
        return 0 if payload.get("ok", True) else 1
    if a.cmd == "saas":
        root = Path(a.root).resolve()
        try:
            payload = (
                verify_saas_proof(root, Path(a.contract), Path(a.evidence), Path(a.out))
                if a.saas_cmd == "verify"
                else saas_proof_projection(root)
            )
        except (SaasProofError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            error = {"schema": "factory.saas-proof.error.v1", "marker": "SAAS_PROOF_REFUSED", "code": getattr(exc, "code", "SAAS_PROOF_INPUT_INVALID"), "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"saas {a.saas_cmd} refused: {error['code']}: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(payload, indent=2, sort_keys=True) if a.json else payload.get("marker", "SAAS_PROOF_OK"))
        return 0 if a.saas_cmd == "status" or payload.get("verdict") == "verified" else 1
    if a.cmd == "intent":
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
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"intent {a.intent_cmd} refused: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif a.intent_cmd == "capture":
            print(f"INTENT_LEDGER_CAPTURED {payload['path']}")
            print("authority : local record only; no source, test, agent, approval, repair, merge, publication, deployment, signing, messaging, credential, connector, or memory-recall action ran")
        else:
            print("factory intent inspect (local, read-only)")
            print("=" * 44)
            print(f"change list : {payload['change_list']}")
            print(f"state       : {payload['state']}")
            print(f"next action : {payload['next_action']['action']}")
            print("authority   : no record write, source write, execution, agent start, approval, repair, merge, publication, deployment, signing, messaging, credential, connector, or memory recall")
        return 2 if a.intent_cmd == "inspect" and payload["state"] in {"intent_ledger_invalid", "change_review_unavailable"} else 0
    if a.cmd == "judgment":
        try:
            if a.judgment_cmd == "propose":
                candidate = json.loads(Path(a.capsule).read_text(encoding="utf-8"))
                payload = propose_capsule(Path(a.root), candidate, proposed_by=a.proposed_by)
            elif a.judgment_cmd == "promote":
                payload = promote_capsule(Path(a.root), a.capsule_id, promoted_by=a.promoted_by, reason=a.reason)
            elif a.judgment_cmd == "reconsider":
                payload = reconsider_capsule(Path(a.root), a.capsule_id, a.successor, requested_by=a.requested_by, reason=a.reason)
            elif a.judgment_cmd == "safety-case":
                payload = safety_case(
                    Path(a.root),
                    changed=a.changed,
                    proof_receipts=[Path(item) for item in a.proof_receipt],
                    change_profile=Path(a.change_profile) if a.change_profile else None,
                )
            else:
                payload = judgment_status(Path(a.root))
        except (JudgmentError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            code = getattr(exc, "code", "JUDGMENT_INPUT_INVALID")
            error = {"schema": "factory.judgment.error.v1", "marker": "JUDGMENT_REFUSED", "code": code, "message": str(exc)}
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"judgment {a.judgment_cmd} refused: {code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif a.judgment_cmd == "status":
            print("factory judgment status (read-only)")
            print("=" * 44)
            print(f"state    : {payload['state']}")
            print(f"active   : {payload.get('counts', {}).get('active', 0)}")
            print(f"proposed : {payload.get('counts', {}).get('proposed', 0)}")
            print("authority: no model, source write, execution, approval, repair, merge, publication, deployment, signing, messaging, or credential access")
        elif a.judgment_cmd == "safety-case":
            print("factory judgment safety-case (read-only)")
            print("=" * 44)
            print(f"route         : {payload['route']}")
            print(f"capsules      : {len(payload['matching_capsules'])}")
            print(f"missing proofs: {len(payload['missing_obligations'])}")
            print(f"unclassified  : {len(payload['unclassified_changed_paths'])}")
            print("authority     : no execution, approval, repair, merge, publication, deployment, signing, messaging, or credential access")
        else:
            print(f"{payload['marker']} {payload['path']}")
            print("authority: tracked human-decision metadata only; no source, proof, approval, repair, merge, publication, deployment, signing, messaging, credential, connector, or model action ran")
        return 1 if a.judgment_cmd == "safety-case" and payload["route"] in {"BLACK", "RED"} else 0
    if a.cmd == "github":
        try:
            if a.github_cmd == "policy-snapshot":
                payload = validate_policy_snapshot(json.loads(Path(a.snapshot).read_text(encoding="utf-8")))
            elif a.github_cmd == "assurance-dossier":
                payload = build_assurance_dossier_from_paths(
                    Path(a.proof_review), Path(a.policy_snapshot),
                    Path(a.baseline_policy_snapshot) if a.baseline_policy_snapshot else None,
                    [Path(path) for path in a.exception],
                )
            elif a.github_cmd == "plan-proof-review":
                payload = compile_github_plan_proof_review(
                    Path(a.root), Path(a.plan), base=a.base, changed=a.changed or None, head_sha=a.head_sha,
                )
            else:
                payload = compile_github_proof_review(
                    Path(a.root), base=a.base, changed=a.changed or None, head_sha=a.head_sha,
                )
            if getattr(a, "out_dir", None):
                if a.github_cmd == "plan-proof-review":
                    payload["artifacts"] = write_github_plan_proof_review_artifacts(payload, Path(a.out_dir))
                elif a.github_cmd == "assurance-dossier":
                    payload["artifacts"] = write_assurance_dossier_artifacts(payload, Path(a.out_dir))
                elif a.github_cmd == "policy-snapshot":
                    raise GitHubAssuranceDossierError("GITHUB_ASSURANCE_INPUT_INVALID", "policy-snapshot validation never writes artifacts")
                else:
                    payload["artifacts"] = write_github_proof_review_artifacts(payload, Path(a.out_dir))
        except (ChangeReviewError, PlanProofReviewError, GitHubProofReviewError, GitHubPlanProofReviewError, GitHubAssuranceDossierError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            assurance = a.github_cmd in {"policy-snapshot", "assurance-dossier"}
            error = {
                "schema": "factory.github_assurance_dossier.error.v1" if assurance else "factory.github_plan_proof_review.error.v1" if a.github_cmd == "plan-proof-review" else "factory.github_proof_review.error.v1",
                "marker": getattr(exc, "code", "GITHUB_ASSURANCE_INPUT_INVALID" if assurance else "GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID" if a.github_cmd == "plan-proof-review" else "GITHUB_PROOF_REVIEW_INPUT_INVALID"),
                "code": getattr(exc, "code", "GITHUB_ASSURANCE_INPUT_INVALID" if assurance else "GITHUB_PLAN_PROOF_REVIEW_INPUT_INVALID" if a.github_cmd == "plan-proof-review" else "GITHUB_PROOF_REVIEW_INPUT_INVALID"),
                "message": str(exc),
            }
            print(json.dumps(error, indent=2, sort_keys=True) if a.json else f"github proof review failed: {error['code']}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"factory github {a.github_cmd} (local, advisory only)")
            print("=" * 54)
            if a.github_cmd == "policy-snapshot":
                print(f"scope        : {payload['scope']['owner']}/{payload['scope']['repository']}")
                print(f"rulesets     : {len(payload['rulesets'])}")
            elif a.github_cmd == "assurance-dossier":
                print(f"head SHA     : {payload['head_sha']}")
                print(f"status       : {payload['status']}")
                print(f"next action  : {payload['next_action']['action']}")
                print(f"high drift   : {payload['drift']['unresolved_high_count']}")
            else:
                print(f"head SHA     : {payload['head_sha']}")
                print(f"review SHA   : {payload['review_sha256']}")
                print(f"next action  : {payload['next_action']['action']}")
                print(f"cohorts      : {len(payload['path_cohorts'])}")
            if payload.get("artifacts"):
                print(f"packet       : {payload['artifacts']['paths']['markdown']}")
            print("authority    : no network, source write, test execution, approval, merge, or credential access")
        return 3 if a.github_cmd == "assurance-dossier" and a.require_aligned and payload["status"] == "review_required" else 0
    if a.cmd == "repair":
        try:
            if a.repair_cmd == "scope":
                result = create_repair_scope(Path(a.root), a.change_list, a.changed, context_budget_bytes=a.context_budget_bytes)
                if a.out_dir:
                    result["artifacts"] = write_repair_scope_artifacts(result, Path(a.root), Path(a.out_dir))
            else:
                result = inspect_repair_candidate(Path(a.root), Path(a.scope), Path(a.patch))
                if a.out_dir:
                    result["artifacts"] = write_repair_candidate_artifacts(result, Path(a.root), Path(a.out_dir))
        except RepairSandboxError as exc:
            schema = "factory.repair_scope.error.v1" if a.repair_cmd == "scope" else "factory.repair_candidate.error.v1"
            marker = "REPAIR_SANDBOX_PATH_REJECTED" if "PATH" in exc.code or exc.code == "REPAIR_CANDIDATE_OUT_OF_SCOPE" else "REPAIR_SANDBOX_INPUT_UNAVAILABLE"
            payload = {"schema": schema, "marker": marker, "code": exc.code, "message": str(exc)}
            print(json.dumps(payload, indent=2, sort_keys=True) if a.json else f"repair {a.repair_cmd} failed: {exc.code}: {exc}", file=sys.stderr)
            return 2
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"factory repair {a.repair_cmd} (supervised, no patch apply)")
            print("=" * 54)
            if a.repair_cmd == "scope":
                print(f"scope       : {result['scope_id']}")
                print(f"changed path: {len(result['paths'])}")
                print(f"context     : {result['context_budget']['measured_bytes']} / {result['context_budget']['limit_bytes']} bytes ({result['context_budget']['decision']})")
                print("next        : external supervised candidate, independent verifier, human apply")
            else:
                print(f"candidate   : {result['candidate_sha256']}")
                print(f"touched path: {len(result['touched_paths'])}")
                print("next        : independent verifier, then human diff review and apply")
            if result.get("artifacts"):
                print(f"packet      : {result['artifacts']['paths']['markdown']}")
            print("authority   : no source modification, test execution, commit, merge, publication, deployment, credential, or network action")
        return 0
    if a.cmd == "release":
        result = release_integrity(Path(a.root))
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(render_release_integrity(result))
        return 0 if result["ok"] else 1
    if a.cmd == "mcp":
        from .mcp import McpError, mcp_status, serve_stdio
        from .mcp_setup import McpSetupError, mcp_connection_config

        try:
            if a.mcp_cmd == "status":
                payload = mcp_status(Path(a.root))
                if a.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print("Factory MCP status")
                    print(f"marker    : {payload['marker']}")
                    print(f"transport : {payload['transport']}")
                    print(f"tools     : {', '.join(payload['tools'])}")
                    print("authority : all external-effect authority is false")
                return 0
            if a.mcp_cmd == "config":
                payload = mcp_connection_config(Path(a.root), a.client)
                if a.json:
                    print(json.dumps(payload, indent=2, sort_keys=True))
                else:
                    print(f"Factory MCP config ({payload['client']})")
                    print("=" * 44)
                    print(f"target       : {payload['target']}")
                    print(f"workspace    : {payload['workspace_root']}")
                    print("authority    : read-only local context; no execution, approval, publish, deploy, signing, messaging, credentials, or connectors")
                    if "command_line" in payload:
                        print(f"copy command : {payload['command_line']}")
                    else:
                        print(json.dumps(payload["config"], indent=2))
                return 0
            return serve_stdio(Path(a.root))
        except (McpError, McpSetupError) as exc:
            print(f"mcp failed: {exc.marker}: {exc}", file=sys.stderr)
            return 2
    if a.cmd == "attest":
        outputs = export_attestations(load_trace(Path(a.trace)), out_dir=Path(a.out_dir))
        if a.json:
            print(json.dumps(outputs, indent=2))
        else:
            print("proof attestations written")
            for name, path in outputs.items():
                print(f"  {name}: {path}")
        return 0
    if a.cmd == "overhead":
        payload = overhead(Path(a.root))
        if a.json:
            print(json.dumps(payload, indent=2))
        else:
            print("factory gate overhead (measured local wall time)")
            for item in payload["gates"]:
                print(f"{item['module']}:{item['stage']} avg={item['avg_wall_ms']}ms runs={item['runs']} failed={item['failed_runs']}")
        return 0
    if a.cmd == "override":
        from .overrides import record_override
        payload = record_override(Path(a.root), a.issue, reason=a.reason, approved_by=a.approved_by, expires=a.expires)
        print(json.dumps(payload, indent=2) if a.json else f"override receipt written: {payload['path']}")
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
                result = sign_receipt(Path(a.path), timeout=a.timeout, overwrite=a.overwrite)
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
            print(json.dumps({
                "schema": "factory.sigstore.result.v1",
                "verdict": "ERROR",
                "error": {"code": exc.code, "message": exc.message},
            }, indent=2))
            return 1
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.verdict != "UNSIGNED" else 1
    if a.cmd == "verify-receipts":
        from .enterprise_receipts import EnterpriseReceiptError
        from .receipt_challenge import MUTATION_GATE_SCHEMA, verify_receipt_mutations
        try:
            result = verify_receipt_mutations(Path(a.root), Path(a.out) if a.out else None)
        except (EnterpriseReceiptError, OSError) as exc:
            code = exc.code if isinstance(exc, EnterpriseReceiptError) else "E_INPUT"
            message = exc.message if isinstance(exc, EnterpriseReceiptError) else str(exc)
            print(json.dumps({"schema": MUTATION_GATE_SCHEMA, "passed": False, "error": {"code": code, "message": message}}, indent=2))
            return 1
        if a.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(f"{result['marker']}: {result['rejected']}/{result['attempted']} receipt mutations rejected; receipt={result['path']}")
        return 0 if result["passed"] else 1
    if a.cmd == "enterprise":
        from .enterprise_receipts import (
            EnterpriseReceiptError,
            generate_key_material,
            seal_receipt_v2,
            sign_policy_bundle,
            sign_revocations,
            verify_receipt_v2,
        )
        try:
            if a.enterprise_cmd == "keygen":
                result = generate_key_material(
                    out_dir=Path(a.out_dir), keyid=a.keyid, identity=a.identity, issuer=a.issuer
                )
            elif a.enterprise_cmd == "receipt-seal":
                payload = json.loads(Path(a.payload).read_text(encoding="utf-8"))
                result = seal_receipt_v2(
                    payload,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {"schema": "factory.enterprise.result.v1", "verdict": "SIGNED", "path": str(Path(a.out).resolve()), "payload_type": result["payloadType"]}
            elif a.enterprise_cmd == "verify":
                result = verify_receipt_v2(
                    Path(a.envelope),
                    trust_root_path=Path(a.trust_root),
                    policy_bundle_path=Path(a.policy_bundle) if a.policy_bundle else None,
                    revocations_path=Path(a.revocations) if a.revocations else None,
                )
            elif a.enterprise_cmd == "policy-sign":
                policy_payload = json.loads(Path(a.policy).read_text(encoding="utf-8"))
                signed = sign_policy_bundle(
                    policy_payload,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {"schema": "factory.enterprise.result.v1", "verdict": "SIGNED", "path": str(Path(a.out).resolve()), "payload_type": signed["payloadType"]}
            else:
                entries = json.loads(Path(a.entries).read_text(encoding="utf-8"))
                signed = sign_revocations(
                    entries,
                    private_key_path=Path(a.private_key),
                    keyid=a.keyid,
                    identity=a.identity,
                    issuer=a.issuer,
                    out=Path(a.out),
                )
                result = {"schema": "factory.enterprise.result.v1", "verdict": "SIGNED", "path": str(Path(a.out).resolve()), "payload_type": signed["payloadType"]}
        except (EnterpriseReceiptError, json.JSONDecodeError, OSError) as exc:
            if isinstance(exc, EnterpriseReceiptError):
                error = {"code": exc.code, "message": exc.message}
            else:
                error = {"code": "E_INPUT", "message": str(exc)}
            print(json.dumps({"schema": "factory.enterprise.result.v1", "verdict": "ERROR", "error": error}, indent=2))
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if a.cmd == "control":
        from .control_plane import ControlPlaneError, EvidenceStore, principal_from_args
        try:
            if a.control_cmd == "init":
                EvidenceStore(Path(a.db))
                result = {"schema": "factory.control-plane.v1", "verdict": "READY", "db": str(Path(a.db).resolve())}
            elif a.control_cmd == "serve":
                from wsgiref.simple_server import make_server
                from .control_api import create_app
                print(f"factory control API listening on http://{a.host}:{a.port}")
                make_server(a.host, a.port, create_app(Path(a.db))).serve_forever()
                return 0
            else:
                store = EvidenceStore(Path(a.db))
                principal = principal_from_args(a.subject, a.tenant, a.roles.split(","))
                if a.control_cmd == "evidence-put":
                    payload = json.loads(Path(a.payload).read_text(encoding="utf-8"))
                    result = store.put(principal, payload, evidence_id=a.evidence_id)
                elif a.control_cmd == "evidence-get":
                    result = store.get(principal, a.tenant, a.evidence_id)
                elif a.control_cmd == "evidence-list":
                    result = {"schema": "factory.evidence.list.v1", "tenant_id": a.tenant, "records": store.list(principal, a.tenant)}
                elif a.control_cmd == "approval-request":
                    result = store.request_approval(principal, a.tenant, a.evidence_id, a.reason)
                elif a.control_cmd == "approval-decide":
                    result = store.decide_approval(principal, a.tenant, a.approval_id, a.decision, a.reason)
                else:
                    result = store.verify_audit(principal, a.tenant)
        except (ControlPlaneError, json.JSONDecodeError, OSError) as exc:
            error = {"code": getattr(exc, "code", "E_INPUT"), "message": getattr(exc, "message", str(exc))}
            print(json.dumps({"schema": "factory.control-plane.result.v1", "verdict": "ERROR", "error": error}, indent=2))
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        if a.control_cmd == "audit-verify":
            return 0 if result["valid"] else 1
        return 0
    if a.cmd == "continuity":
        from .continuity import ContinuityError, ContinuityStore, principal_from_args as continuity_principal_from_args
        try:
            if a.continuity_cmd == "init":
                store = ContinuityStore(Path(a.db))
                result = {
                    "schema": "factory.continuity.v1",
                    "marker": "CONTINUITY_LOCAL_REFERENCE_ONLY",
                    "verdict": "READY",
                    "db": str(store.path.resolve()),
                    "authority": {"external_effects": False, "signing": False, "erasure": False},
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
                        payload = json.loads(Path(a.payload).read_text(encoding="utf-8"))
                        result = store.record(principal, payload, idempotency_key=a.idempotency_key, record_id=a.record_id)
                    elif a.continuity_cmd == "recall":
                        result = store.recall(principal, a.tenant, purpose_ref=a.purpose, scope_ref=a.scope)
                    elif a.continuity_cmd == "promote":
                        result = store.promote(principal, a.tenant, a.record_id, reason=a.reason)
                    else:
                        result = store.prove(principal, a.tenant, a.record_id)
        except (ContinuityError, json.JSONDecodeError, OSError) as exc:
            error = {"code": getattr(exc, "code", "E_INPUT"), "message": getattr(exc, "message", str(exc))}
            print(json.dumps({"schema": "factory.continuity.result.v1", "verdict": "ERROR", "error": error}, indent=2))
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if a.cmd == "assurance":
        from .assurance import build_cyclonedx_sbom, build_evidence_graph, build_vex, policy_mutations
        try:
            if a.assurance_cmd == "graph":
                records = json.loads(Path(a.records).read_text(encoding="utf-8"))
                result = build_evidence_graph(records, tenant_id=a.tenant)
            elif a.assurance_cmd == "sbom":
                components = json.loads(Path(a.components).read_text(encoding="utf-8"))
                result = build_cyclonedx_sbom(components)
            elif a.assurance_cmd == "vex":
                entries = json.loads(Path(a.entries).read_text(encoding="utf-8"))
                result = build_vex(entries)
            else:
                policy_payload = json.loads(Path(a.policy).read_text(encoding="utf-8"))
                result = {"schema": "factory.assurance.policy-mutations.v1", "mutations": policy_mutations(policy_payload)}
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(json.dumps({"schema": "factory.assurance.result.v1", "verdict": "ERROR", "error": {"code": "E_INPUT", "message": str(exc)}}, indent=2))
            return 1
        except Exception as exc:
            error = {"code": getattr(exc, "code", "E_ASSURANCE"), "message": getattr(exc, "message", str(exc))}
            print(json.dumps({"schema": "factory.assurance.result.v1", "verdict": "ERROR", "error": error}, indent=2))
            return 1
        print(json.dumps({"schema": "factory.assurance.result.v1", "verdict": "WRITTEN", "path": str(Path(a.out).resolve())}, indent=2))
        return 0
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
            out = Path(a.out) if a.out else root / ".factory" / "policy-challenges" / "verify-policy.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        except (AssuranceError, OSError, json.JSONDecodeError, ValueError) as exc:
            error = {"code": getattr(exc, "code", "E_INPUT"), "message": getattr(exc, "message", str(exc))}
            print(json.dumps({"schema": "factory.policy.verify.v1", "verdict": "ERROR", "error": error}, indent=2))
            return 1
        print(json.dumps(result | {"receipt_path": str(out)}, indent=2, sort_keys=True))
        return 0 if result["status"] == "VERIFIED" else 1
    if a.cmd == "compliance":
        from .compliance import CONTROL_PACKS, build_oscal_assessment
        try:
            if a.compliance_cmd == "packs":
                print(json.dumps({"schema": "factory.compliance.packs.v1", "packs": sorted(CONTROL_PACKS)}, indent=2))
                return 0
            evidence = json.loads(Path(a.evidence).read_text(encoding="utf-8"))
            controls = json.loads(Path(a.controls).read_text(encoding="utf-8")) if a.controls else None
            result = build_oscal_assessment(a.pack, tenant_id=a.tenant, evidence=evidence, custom_controls=controls)
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(json.dumps({"schema": "factory.compliance.result.v1", "verdict": "ERROR", "error": {"code": "E_INPUT", "message": str(exc)}}, indent=2))
            return 1
        except Exception as exc:
            error = {"code": getattr(exc, "code", "E_COMPLIANCE"), "message": getattr(exc, "message", str(exc))}
            print(json.dumps({"schema": "factory.compliance.result.v1", "verdict": "ERROR", "error": error}, indent=2))
            return 1
        print(json.dumps({"schema": "factory.compliance.result.v1", "verdict": "WRITTEN", "path": str(Path(a.out).resolve())}, indent=2))
        return 0
    if a.cmd == "privacy":
        from .privacy import bbs_status, merkle_disclosure, zkvm_pilot_status
        try:
            if a.privacy_cmd == "status":
                print(json.dumps({"schema": "factory.privacy.status.v1", "bbs": bbs_status(), "zkvm": zkvm_pilot_status()}, indent=2))
                return 0
            leaves = json.loads(Path(a.leaves).read_text(encoding="utf-8"))
            result = merkle_disclosure(leaves, a.disclose)
            Path(a.out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.out).write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(json.dumps({"schema": "factory.privacy.result.v1", "verdict": "ERROR", "error": {"code": "E_INPUT", "message": str(exc)}}, indent=2))
            return 1
        except Exception as exc:
            error = {"code": getattr(exc, "code", "E_PRIVACY"), "message": getattr(exc, "message", str(exc))}
            print(json.dumps({"schema": "factory.privacy.result.v1", "verdict": "ERROR", "error": error}, indent=2))
            return 1
        print(json.dumps({"schema": "factory.privacy.result.v1", "verdict": "WRITTEN", "path": str(Path(a.out).resolve())}, indent=2))
        return 0
    if a.cmd == "ci":
        from .overrides import ci_template
        path = Path(a.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(ci_template(a.feature), encoding="utf-8")
        print(f"GitHub PR-comment workflow written: {path}")
        return 0
    if a.cmd == "loop":
        from .loop_passport import build_loop_passport, evaluate_budget, init_loop, validate_manifest, verify_loop_passport
        try:
            if a.loop_cmd == "init":
                result = init_loop(Path(a.root), a.loop_id, a.owner, force=a.force)
                code = 0
            elif a.loop_cmd == "validate":
                result = validate_manifest(Path(a.manifest))
                code = 0 if result["valid"] else 1
            elif a.loop_cmd == "passport":
                result = build_loop_passport(Path(a.root), Path(a.manifest))
                code = 0 if result["verdict"] == "VERIFIED" else 1
            elif a.loop_cmd == "verify":
                result = verify_loop_passport(Path(a.passport))
                code = 0 if result["valid"] else 1
            else:
                result = evaluate_budget(Path(a.root), Path(a.manifest), Path(a.usage))
                code = 0 if result["ok"] else 1
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result = {"schema": "factory.loop.result.v1", "verdict": "ERROR", "error": {"code": "E_INPUT", "message": str(exc)}}
            code = 1
        if a.json:
            print(json.dumps(result, indent=2))
        elif code == 0:
            print(f"Loop Passport: {result.get('verdict', 'WRITTEN')}")
            for name, path in result.get("paths", {}).items():
                print(f"  {name:<8}: {path}")
        else:
            print(json.dumps(result, indent=2), file=sys.stderr)
        return code
    if a.cmd == "passport":
        try:
            passport = build_passport(
                Path(a.root), a.feature, Path(a.trace), [Path(path) for path in a.challenge]
            )
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            print(f"passport failed: {exc}", file=sys.stderr)
            return 1
        if a.json:
            print(json.dumps(passport, indent=2))
        else:
            print(f"Factory Passport: {'VERIFIED' if passport['verified'] else 'BLOCKED'}")
            for name, path in passport["paths"].items():
                print(f"  {name:<8}: {path}")
        return 0 if passport["verified"] else 1
    if a.cmd == "verify-passport":
        result = verify_passport(Path(a.passport))
        print(json.dumps(result, indent=2) if a.json else f"passport valid: {result['valid']}")
        return 0 if result["valid"] else 1
    if a.cmd == "challenge":
        from .challenge import challenge_trace
        payload = challenge_trace(Path(a.trace), root=Path(a.root))
        out = Path(a.out) if a.out else Path(a.root) / ".factory" / "challenges" / f"{a.feature}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        print(json.dumps(payload | {"receipt_path": str(out)}, indent=2))
        return 0 if payload["passed"] else 1
    if a.cmd == "coverage":
        result = requirement_coverage(Path(a.root))
        if a.json:
            print(json.dumps(result, indent=2))
        else:
            print("factory requirement coverage")
            print("=" * 44)
            print(f"covered   : {len(result['covered'])}")
            print(f"uncovered : {len(result['uncovered'])}")
            for req_id in result["uncovered"]:
                print(f"  - {req_id}")
        return 0 if result["ok"] else 1
    if a.cmd == "policy":
        path = write_policy(Path(a.root), force=a.force)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if a.json:
            print(json.dumps({"path": str(path), "policy": payload}, indent=2))
        else:
            print(f"factory policy: {path}")
            print(f"risk default      : {payload['risk']['default']}")
            print(f"hollow tests      : {payload['quality']['require_hollow_tests']}")
            print(f"hollow validators : {payload['quality']['require_hollow_validators']}")
        return 0
    if a.cmd == "pr-pack":
        try:
            packet = pr_pack(
                Path(a.root),
                a.feature,
                trace_path=Path(a.trace) if a.trace else None,
                out=Path(a.out) if a.out else None,
            )
        except FileNotFoundError as exc:
            print(f"pr-pack failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(packet, indent=2) if a.json else f"PR evidence packet written: {packet['packet_path']}")
        return 0 if packet["evidence"]["verified"] else 1
    if a.cmd == "optimize-pr":
        plan = optimize_pr(Path(a.root), base=a.base, changed=a.changed, feature=a.feature)
        if a.json:
            print(json.dumps(plan, indent=2))
        else:
            print("factory PR optimization plan")
            print("=" * 44)
            print(f"base: {plan['base']}")
            print(f"changed paths: {len(plan['changed_paths'])}")
            for stage in plan["recommended_stages"]:
                print(f"  - {stage}")
            print("loop: max 5 iterations; no merge/publish/deploy without approval")
        return 0
    if a.cmd == "app":
        if a.app_cmd == "stacks":
            payload = {"stacks": STACKS}
            print(json.dumps(payload, indent=2))
            return 0
        if a.app_cmd == "from-prd":
            result = app_from_prd(
                Path(a.prd),
                out_dir=Path(a.out) if a.out else None,
                name=a.name,
                stack=a.stack,
                purpose=a.purpose,
            )
        else:
            result = app_from_prompt(
                a.prompt,
                out_dir=Path(a.out) if a.out else None,
                name=a.name,
                stack=a.stack,
                purpose=a.purpose,
            )
        if a.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"app scaffolded: {result['out_dir']}")
            print(f"files         : {len(result['files'])}")
            print("next:")
            for command in result["next_commands"]:
                print(f"  {command}")
        return 0
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

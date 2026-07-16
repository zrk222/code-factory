"""factoryline CLI — drive the code factory from any IDE / agent / OS.

    factory doctor            # which Lego pieces are installed + how to get the rest
    factory plan              # print the assembly pipeline (no execution)
    factory assemble <feat>   # run the chain for a feature (skips missing modules)
    factory meter [--runs N --baseline T]   # real savings summary from your runs
    factory trace <feat>      # write a hash-linked proof-carrying PR trace
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
from .studio import StudioRequestError, serve_studio, studio_status
from .coverage import requirement_coverage
from .passport import build_passport, verify_passport
from .protocol import compatibility
from .verification import verify_feature


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
        check = compatibility(module.name, MODULES[module.name], help_text)
        checks.append((check, _workflow_canary(module)))
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
        print(f"  {module:<10} -> {cli} {' '.join(args)}{tag}")
    print("\nEach arrow is a Lego seam: the output of one stage is the input of the next,")
    print("passed on disk under the shared factory layout (portable across IDE/agent/OS).")
    return 0


def main(argv=None) -> int:
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
    sub.add_parser("plan", help="print the assembly pipeline")

    s = sub.add_parser("init", help="create the shared factory layout")
    s.add_argument("root", nargs="?", default=".")

    s = sub.add_parser("assemble", help="run the assembly line for a feature")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--dry-run", action="store_true")

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

    target = sub.add_parser("create", help="compile one prompt or PRD into one governed starter target")
    target.add_argument("prompt", nargs="?", help="plain-language intent; mutually exclusive with --prd")
    target.add_argument("--prd", help="UTF-8 PRD path; mutually exclusive with prompt")
    target.add_argument("--target", required=True, choices=sorted(TARGETS))
    target.add_argument("--out", required=True, help="empty output directory")
    target.add_argument("--name", help="target slug override")
    target.add_argument("--purpose", default="auto", help="auto, developer, healthcare, fintech, marketplace, saas")
    target.add_argument("--trigger", default="manual", choices=SUPPORTED_TRIGGERS)
    target.add_argument("--json", action="store_true")

    studio = sub.add_parser("studio", help="run the loopback-only local target builder")
    studio.add_argument("--root", default=".", help="directory beneath which Studio may create targets")
    studio.add_argument("--port", default=0, type=int, help="loopback port; 0 selects an available port")
    studio.add_argument("--no-browser", action="store_true", help="do not open the local URL automatically")
    studio.add_argument("--check", action="store_true", help="report the exact Studio boundary without starting a server")
    studio.add_argument("--json", action="store_true")

    version = sub.add_parser("version", help="show package provenance")
    version.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    if a.cmd is None:
        return _home()
    if a.cmd == "version":
        return _emit_version(a.json)
    if a.cmd == "home":
        return _home(Path(a.root), a.json)
    if a.cmd == "doctor":
        return _doctor(a.strict, a.json)
    if a.cmd == "targets":
        print(json.dumps({"schema": "factory.targets.v1", "targets": TARGETS}, indent=2, sort_keys=True))
        return 0
    if a.cmd == "create":
        if bool(a.prompt) == bool(a.prd):
            payload = {
                "schema": "factory.target_compile_error.v1",
                "status": "failed",
                "code": "SOURCE_EXACTLY_ONE",
                "marker": "COMPILE_FAILED",
                "message": "provide exactly one source: prompt or --prd",
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
                )
            else:
                result = create_target_from_prompt(
                    a.prompt,
                    target=a.target,
                    out_dir=Path(a.out),
                    name=a.name,
                    purpose=a.purpose,
                    trigger=a.trigger,
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
            }
            print(json.dumps(payload, indent=2), file=sys.stderr)
            return 1
        if a.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"target compiled: {result['out_dir']}")
            print(f"kind           : {result['target_kind']}")
            print(f"state          : {result['status']}")
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
    if a.cmd == "plan":
        return _plan()
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

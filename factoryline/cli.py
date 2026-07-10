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
import sys
from pathlib import Path

from .contract import MODULES, STAGES, ensure_layout, LAYOUT
from .assembly import detect, assemble, DEFAULT_CHAIN, rollup_receipts
from .meter import summarize, summary_table
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


def _doctor() -> int:
    mods = detect()
    print("factoryline doctor — Lego assembly status\n" + "=" * 44)
    any_missing = False
    for m in mods:
        mark = "installed" if m.installed else "missing"
        print(f"  [{mark:>9}]  {m.name:<10} ({m.cli}) - {m.role}")
        if not m.installed:
            any_missing = True
    if any_missing:
        print("\nTo add a missing piece (each is independent):")
        for m in mods:
            if not m.installed:
                print(f"  pip install {MODULES[m.name]['pip']}")
    else:
        print("\nAll four pieces installed - full assembly line available.")
        print("\nThe factory works with whatever is present; missing pieces are skipped.")
        return 0
    print("\nThe factory works with whatever is present; missing pieces are skipped.")
    return 0


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
    p = argparse.ArgumentParser(prog="factory",
                                description="Snap SpecLine, ForgeLine, HSF and Prestige into one assembly line.")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("doctor", help="show which modules are installed")
    sub.add_parser("plan", help="print the assembly pipeline")

    s = sub.add_parser("init", help="create the shared factory layout")
    s.add_argument("root", nargs="?", default=".")

    s = sub.add_parser("assemble", help="run the assembly line for a feature")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument("--dry-run", action="store_true")

    s = sub.add_parser("meter", help="real savings summary from your runs")
    s.add_argument("--root", default=".")
    s.add_argument("--runs", type=int, default=1000, help="projected production runs")
    s.add_argument("--baseline", type=int, default=4000, help="baseline tokens per run (declare your real agent cost)")

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

    a = p.parse_args(argv)

    if a.cmd == "doctor":
        return _doctor()
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
    if a.cmd == "meter":
        summ = summarize(Path(a.root), baseline_tokens_per_run=a.baseline, runs_projected=a.runs)
        print(summary_table(summ))
        return 0
    if a.cmd == "rollup":
        print(json.dumps(rollup_receipts(Path(a.root), a.feature), indent=2))
        return 0
    if a.cmd == "trace":
        trace = build_trace(Path(a.root), a.feature, out=Path(a.out) if a.out else None)
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

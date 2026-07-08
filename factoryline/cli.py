"""factoryline CLI — drive the code factory from any IDE / agent / OS.

    factory doctor            # which Lego pieces are installed + how to get the rest
    factory plan              # print the assembly pipeline (no execution)
    factory assemble <feat>   # run the chain for a feature (skips missing modules)
    factory meter [--runs N --baseline T]   # real savings summary from your runs
    factory init <root>       # create the shared factory layout
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from .contract import MODULES, STAGES, ensure_layout, LAYOUT
from .assembly import detect, assemble, DEFAULT_CHAIN
from .meter import summarize, summary_table


def _doctor() -> int:
    mods = detect()
    print("factoryline doctor — Lego assembly status\n" + "=" * 44)
    any_missing = False
    for m in mods:
        mark = "✓ installed" if m.installed else "✗ missing"
        print(f"  [{mark:>11}]  {m.name:<10} ({m.cli}) — {m.role}")
        if not m.installed:
            any_missing = True
    if any_missing:
        print("\nTo add a missing piece (each is independent):")
        for m in mods:
            if not m.installed:
                print(f"  pip install {MODULES[m.name]['pip']}")
    else:
        print("\nAll four pieces installed — full assembly line available.")
    print("\nThe factory works with whatever is present; missing pieces are skipped.")
    return 0


def _plan() -> int:
    print("factoryline assembly pipeline\n" + "=" * 44)
    installed = {m.name: m.installed for m in detect()}
    for module, args in DEFAULT_CHAIN:
        cli = MODULES[module]["cli"]
        tag = "" if installed.get(module) else "   (skipped — not installed)"
        print(f"  {module:<10} → {cli} {' '.join(args)}{tag}")
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
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

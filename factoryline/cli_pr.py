"""Lazy CLI boundary for pull-request evidence and optimization planning."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register reviewer packet and bounded PR optimization commands."""
    s = sub.add_parser("pr-pack", help="write a reviewer-ready PR evidence packet")
    s.add_argument("feature")
    s.add_argument("--root", default=".")
    s.add_argument(
        "--trace", help="trace path; defaults to .factory/traces/<feature>.trace.json"
    )
    s.add_argument("--out", help="markdown output path")
    s.add_argument("--json", action="store_true")
    s = sub.add_parser(
        "optimize-pr", help="plan bounded PR hardening from the current diff"
    )
    s.add_argument("--root", default=".")
    s.add_argument("--base", default="main")
    s.add_argument("--changed", action="append", default=[])
    s.add_argument("--feature")
    s.add_argument("--json", action="store_true")


def run(a) -> int:
    """Dispatch PR evidence planning without merging, publishing, or deployment."""
    from .optimizer import optimize_pr, pr_pack

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
        print(
            json.dumps(packet, indent=2)
            if a.json
            else f"PR evidence packet written: {packet['packet_path']}"
        )
        return 0 if packet["evidence"]["verified"] else 1
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

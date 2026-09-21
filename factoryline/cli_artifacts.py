"""Lazy CLI boundary for proof artifacts, challenge, coverage, and policy."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def add_parser(sub) -> None:
    """Register proof export, passport, challenge, coverage, and policy commands."""
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


def run(a) -> int:
    """Dispatch local proof artifacts without network, merge, or deployment authority."""
    if a.cmd == "attest":
        from .proof import export_attestations, load_trace

        outputs = export_attestations(load_trace(Path(a.trace)), out_dir=Path(a.out_dir))
        if a.json:
            print(json.dumps(outputs, indent=2))
        else:
            print("proof attestations written")
            for name, path in outputs.items():
                print(f"  {name}: {path}")
        return 0
    if a.cmd == "passport":
        from .passport import build_passport

        try:
            passport = build_passport(Path(a.root), a.feature, Path(a.trace), [Path(path) for path in a.challenge])
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
        from .passport import verify_passport

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
        from .coverage import requirement_coverage

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
        from .optimizer import write_policy

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
    raise ValueError(f"unsupported artifact command: {a.cmd}")

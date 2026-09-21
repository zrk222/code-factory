"""Bounded, lazily loaded CLI commands for code-quality and security audits."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

COMMAND_GROUP = "audit"
OWNER = "quality-security"


def add_parser(sub: Any) -> None:
    """Register the audit command family without importing audit engines."""
    code_audit = sub.add_parser(
        "audit",
        help="inspect peer-pattern irregularities and guard-bypass paths without executing code",
    )
    code_audit.add_argument(
        "tool",
        choices=["patterns", "guard-paths", "all", "fingerprint", "security", "evals"],
    )
    code_audit.add_argument("--policy", default=".factory/review-audits.json")
    code_audit.add_argument("--root", default=".")
    code_audit.add_argument(
        "--baseline",
        help="previous fingerprint receipt for deterministic drift comparison",
    )
    code_audit.add_argument(
        "--out", help="optional workspace-contained fingerprint receipt path"
    )
    code_audit.add_argument("--json", action="store_true")


def run(args: Any) -> int:
    """Run one audit command, importing the engine only after selection."""
    from .review_audits import (
        ReviewAuditError,
        audit_code,
        audit_fingerprint,
        security_evals,
        security_scan,
    )

    try:
        if args.tool == "evals":
            result = security_evals()
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(
                    f"Security evals: {result['state']} "
                    f"({result['mutation_coverage']['caught']}/"
                    f"{result['mutation_coverage']['attempted']} adversarial rules caught)"
                )
                print(result["action_summary"])
            return 0 if result["state"] == "PASS" else 2
        if args.tool == "security":
            result = security_scan(Path(args.root))
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(
                    f"Security audit: {result['state']} "
                    f"({len(result['findings'])} findings)"
                )
                for item in result["findings"]:
                    print(
                        f"{item['severity']} {item['code']}: "
                        f"{item['path']}:{item['line']} — {item['message']}"
                    )
                print(result["action_summary"])
            return 0 if result["state"] == "CLEAN" else 2 if result["state"] == "BLOCKED" else 1
        if args.tool == "fingerprint":
            result = audit_fingerprint(
                Path(args.root),
                args.policy,
                baseline_path=Path(args.baseline) if args.baseline else None,
                out_path=Path(args.out) if args.out else None,
            )
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(
                    f"Audit fingerprint: {result['state']} "
                    f"({result['fingerprint_sha256']})"
                )
                print(result.get("action_summary", ""))
            return 0 if result["state"] == "CURRENT" else 1 if result["state"] == "DRIFT_DETECTED" else 2
        result = audit_code(Path(args.root), args.policy, tool=args.tool)
    except ReviewAuditError as exc:
        print(
            json.dumps({"state": "invalid", "code": exc.code, "message": str(exc)}),
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Code audit: {result['state']} ({len(result['findings'])} findings)")
        for item in result["findings"]:
            print(
                f"{item['code']}: {item['target']['path']}:{item['target']['line']} — {item['message']}"
            )
        for item in result["results"]:
            for gap in item.get("analysis_gaps", []):
                print(f"INCOMPLETE {item['rule_id']}: {gap}")
        if result["unconfigured_tools"]:
            print(f"Unconfigured: {', '.join(result['unconfigured_tools'])}")
        print("Analysis only; declared policy is not authenticated approval.")
    return 0 if result["state"] == "no_structural_findings" else 2

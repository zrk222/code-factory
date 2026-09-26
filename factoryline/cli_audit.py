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
        choices=[
            "patterns",
            "guard-paths",
            "all",
            "fingerprint",
            "security",
            "evals",
            "governance",
        ],
    )
    code_audit.add_argument("--policy", default=".factory/review-audits.json")
    code_audit.add_argument("--root", default=".")
    code_audit.add_argument(
        "--base", default="origin/main", help="Git base for dated-evidence review"
    )
    code_audit.add_argument(
        "--baseline",
        help="previous fingerprint receipt for deterministic drift comparison",
    )
    code_audit.add_argument(
        "--out", help="optional workspace-contained fingerprint receipt path"
    )
    code_audit.add_argument("--json", action="store_true")


def _run_evals(args: Any) -> int:
    from .review_audits import security_evals

    result = security_evals()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"Security evals: {result['state']} ({result['mutation_coverage']['caught']}/{result['mutation_coverage']['attempted']} adversarial rules caught)"
        )
        print(result["action_summary"])
    return 0 if result["state"] == "PASS" else 2


def _run_security(args: Any) -> int:
    from .review_audits import security_scan

    result = security_scan(Path(args.root))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Security audit: {result['state']} ({len(result['findings'])} findings)")
        for item in result["findings"]:
            print(
                f"{item['severity']} {item['code']}: {item['path']}:{item['line']} — {item['message']}"
            )
        print(result["action_summary"])
    return 0 if result["state"] == "CLEAN" else 2 if result["state"] == "BLOCKED" else 1


def _run_governance(args: Any) -> int:
    from .release_integrity import review_regression_audit

    result = review_regression_audit(Path(args.root), args.base)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(
            f"Review governance: {result['state']} ({len(result['findings'])} findings)"
        )
        for item in result["findings"]:
            print(f"{item['code']}: {item['path']} — {item['action']}")
        for gap in result["gaps"]:
            print(f"INCOMPLETE: {gap}")
    return 0 if result["state"] == "CLEAN" else 2


def _run_fingerprint(args: Any) -> int:
    from .review_audits import audit_fingerprint

    result = audit_fingerprint(
        Path(args.root),
        args.policy,
        baseline_path=Path(args.baseline) if args.baseline else None,
        out_path=Path(args.out) if args.out else None,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Audit fingerprint: {result['state']} ({result['fingerprint_sha256']})")
        print(result.get("action_summary", ""))
    return (
        0
        if result["state"] == "CURRENT"
        else 1
        if result["state"] == "DRIFT_DETECTED"
        else 2
    )


def _run_code(args: Any) -> int:
    from .review_audits import audit_code

    result = audit_code(Path(args.root), args.policy, tool=args.tool)
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


def run(args: Any) -> int:
    """Run one audit command, importing the engine only after selection."""
    from .review_audits import ReviewAuditError

    handlers = {
        "evals": _run_evals,
        "security": _run_security,
        "governance": _run_governance,
        "fingerprint": _run_fingerprint,
    }
    try:
        return handlers.get(args.tool, _run_code)(args)
    except ReviewAuditError as exc:
        print(
            json.dumps({"state": "invalid", "code": exc.code, "message": str(exc)}),
            file=sys.stderr,
        )
        return 2

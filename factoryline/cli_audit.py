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
            "workflows",
            "taxonomy",
            "agent-context",
        ],
    )
    code_audit.add_argument("--policy", default=".factory/review-audits.json")
    code_audit.add_argument("--root", default=".")
    code_audit.add_argument(
        "--tenant-read-call",
        action="append",
        default=[],
        help="qualified read call requiring a tenant-scope argument check (repeatable; security audit only)",
    )
    code_audit.add_argument(
        "--tenant-read-binding",
        action="append",
        default=[],
        help=(
            "bind a read call argument to its required enclosing function parameter: "
            "CALL=position:INDEX:PARAMETER or CALL=keyword:NAME:PARAMETER "
            "(repeatable across calls; exactly one per call; position is zero-based)"
        ),
    )
    code_audit.add_argument(
        "--tenant-contract",
        default=".factory/tenant-read-contract.json",
        help="workspace-relative tenant-read contract JSON (optional; repeatable CLI declarations supplement it)",
    )
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
    code_audit.add_argument(
        "--oracle-evidence",
        help="workspace-relative DSSE per-test mutation attestation (security only)",
    )
    code_audit.add_argument(
        "--oracle-trust-root",
        help="workspace-relative oracle-verifier public trust root",
    )
    code_audit.add_argument(
        "--oracle-trust-sha256", help="operator-pinned trust root SHA-256"
    )
    code_audit.add_argument(
        "--oracle-environment-sha256",
        help="expected runner/environment contract SHA-256",
    )
    code_audit.add_argument(
        "--contract", default=".factory/workflow-audit-contract.json"
    )
    code_audit.add_argument(
        "--observations", default=".factory/workflow-audit-observations.json"
    )
    code_audit.add_argument(
        "--role",
        help="specialist role for the host-neutral agent context projection",
    )


def _run_workflows(args: Any) -> int:
    from .journey_proof import JourneyProofError
    from .workflow_audit import audit_workflows

    try:
        result = audit_workflows(Path(args.root), args.contract, args.observations)
    except (JourneyProofError, OSError) as error:
        result = {
            "state": "INVALID",
            "message": str(error),
            "execution_authority": False,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["state"] == "PASS" else 2


def _run_taxonomy(args: Any) -> int:
    from .audit_taxonomy import audit_taxonomy

    result = audit_taxonomy()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _run_agent_context(args: Any) -> int:
    from .audit_taxonomy import agent_taxonomy_context

    try:
        result = agent_taxonomy_context(args.role)
    except ValueError as error:
        print(json.dumps({"state": "INVALID", "message": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


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
    from .review_audits import (
        ReviewAuditError,
        _seal_security_scan,
        load_tenant_read_contract,
        security_scan,
    )

    try:
        contract_calls, contract_bindings, contract_evidence = (
            load_tenant_read_contract(Path(args.root), args.tenant_contract)
        )
        calls = tuple(
            dict.fromkeys([*contract_calls, *getattr(args, "tenant_read_call", [])])
        )
        bindings = tuple(
            dict.fromkeys(
                [*contract_bindings, *getattr(args, "tenant_read_binding", [])]
            )
        )
        result = security_scan(
            Path(args.root),
            tenant_read_calls=calls,
            tenant_read_bindings=bindings,
            tenant_read_scopes=contract_evidence.get("scoped_reads"),
            oracle_evidence=getattr(args, "oracle_evidence", None),
            oracle_trust_root=getattr(args, "oracle_trust_root", None),
            oracle_trust_sha256=getattr(args, "oracle_trust_sha256", None),
            oracle_environment_sha256=getattr(args, "oracle_environment_sha256", None),
        )
        result["tenant_read_contract"]["configuration"] = contract_evidence
        if contract_evidence["state"] == "missing":
            if result["state"] == "CLEAN":
                result["state"] = "INCOMPLETE"
            result["action_summary"] += (
                " Tenant isolation remains unassessed for custom reads; add "
                "`.factory/tenant-read-contract.json` with every tenant-scoped "
                "read and its binding, or explicitly declare an empty read set."
            )
        result = _seal_security_scan(result)
    except ReviewAuditError as error:
        print(json.dumps({"state": "INVALID", "message": str(error)}), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Security audit: {result['state']} ({len(result['findings'])} findings)")
        coverage = result.get("audit_coverage", {})
        rate = coverage.get("audit_rate")
        state = coverage.get("measurement_state", "unknown")
        if isinstance(rate, (int, float)) and not isinstance(rate, bool):
            coverage_text = (
                f"{rate:.1%} ({coverage.get('files_audited', 0)}/"
                f"{coverage.get('files_discovered', 0)} Python sources; {state})"
            )
        else:
            coverage_text = (
                f"N/A ({coverage.get('files_discovered', 0)} eligible Python "
                f"sources; {state})"
            )
        print(f"Coverage: {coverage_text}")
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
        "workflows": _run_workflows,
        "taxonomy": _run_taxonomy,
        "agent-context": _run_agent_context,
    }
    try:
        return handlers.get(args.tool, _run_code)(args)
    except ReviewAuditError as exc:
        print(
            json.dumps({"state": "invalid", "code": exc.code, "message": str(exc)}),
            file=sys.stderr,
        )
        return 2

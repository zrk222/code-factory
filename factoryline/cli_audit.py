"""Bounded, lazily loaded CLI commands for code-quality and security audits."""

from __future__ import annotations

import json
import argparse
import sys
import time
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
            "actionability",
        ],
    )
    code_audit.add_argument("--policy", default=".factory/review-audits.json")
    code_audit.add_argument("--root", default=".")
    code_audit.add_argument("--cases", help="bound JEV actionability case JSON")
    code_audit.add_argument(
        "--live", action="store_true", help="opt in to Vercel Gateway JEV review"
    )
    code_audit.add_argument(
        "--budget-policy", help="hash-bound JEV dispatch budget JSON"
    )
    code_audit.add_argument("--timeout-ms", type=int, default=30000)
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
        "--defect-policy",
        choices=[
            "legacy-v1",
            "trusted-core-v1",
            "source-role-v1",
            "source-role-v2",
            "source-role-v3",
        ],
        default=argparse.SUPPRESS,
        help="explicit bounded security defect policy; trusted-core keeps unresolved items visible without establishing a clean security result",
    )
    code_audit.add_argument(
        "--full-repository",
        action="store_true",
        help="use the separate bounded full-repository source profile (security only)",
    )
    code_audit.add_argument(
        "--context-profile",
        choices=["isolated-v1", "workspace-v2"],
        default="isolated-v1",
        help="source-context profile for --full-repository (workspace-v2 is opt-in)",
    )
    code_audit.add_argument(
        "--resume",
        action="store_true",
        help="resume and revalidate the full-repository checkpoint (requires --full-repository)",
    )
    code_audit.add_argument(
        "--max-batches",
        type=int,
        default=1,
        help="maximum 460-source batches for this invocation (full-repository only)",
    )
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


def _jev_evaluation_assets():
    """Find the existing evaluator in a source checkout or installed wheel."""
    import sysconfig

    package = Path(__file__).resolve().parent
    candidates = (
        package.parent / "scripts/evaluate_jev.mjs",
        Path(sysconfig.get_path("data"))
        / "share/code-factory/evaluation/evaluate_jev.mjs",
    )
    runner = next((path for path in candidates if path.is_file()), None)
    rubric = package / "data/judge_framework.json"
    if runner is None or not rubric.is_file():
        raise ValueError("Packaged JEV evaluator assets are missing; reinstall CF.")
    return runner, rubric


def _jev_node():
    import shutil
    from .cli import _run_cli_bounded

    node = shutil.which("node")
    if node is None:
        raise ValueError("JEV evaluation requires Node.js 18 or newer on PATH.")
    version = _run_cli_bounded(node, ["--version"], Path.cwd(), timeout=5)
    text = version["stdout"].decode("utf-8", errors="replace").strip().lstrip("v")
    if (
        not version["ok"]
        or not text.split(".")[0].isdigit()
        or int(text.split(".")[0]) < 18
    ):
        raise ValueError("JEV evaluation requires Node.js 18 or newer on PATH.")
    return node


def _jev_workspace_path(root, value, *, required=False):
    if not value:
        raise ValueError("JEV case and evidence paths are required.")
    path = (root / value).resolve()
    if not path.is_relative_to(root) or (required and not path.is_file()):
        raise ValueError(
            "JEV paths must resolve to the selected workspace; input must exist."
        )
    return path


def _jev_review_command(args, root):
    import os

    cases = _jev_workspace_path(root, args.cases, required=True)
    output = _jev_workspace_path(
        root, args.out or ".factory/jev/actionability-report.json"
    )
    if not 1 <= args.timeout_ms <= 60000:
        raise ValueError("JEV timeout must be 1..60000 milliseconds.")
    argv = [
        "--cases",
        str(cases),
        "--profile",
        "security_actionability",
        "--out",
        str(output),
        "--timeout-ms",
        str(args.timeout_ms),
    ]
    deadline = 45.0
    if args.live:
        if not os.environ.get("AI_GATEWAY_API_KEY", "").strip():
            raise ValueError("Configure AI_GATEWAY_API_KEY locally before live review.")
        budget = _jev_workspace_path(root, args.budget_policy, required=True)
        if budget.stat().st_size > 1048576:
            raise ValueError("JEV budget policy exceeds the size limit.")
        policy = json.loads(budget.read_bytes())
        if not isinstance(policy, dict):
            raise ValueError("JEV budget policy must be a JSON object.")
        duration = policy.get("max_latency_ms")
        if type(duration) not in (int, float) or not 0 < duration <= 3600000:
            raise ValueError("JEV total dispatch budget must be at most one hour.")
        deadline = duration / 1000 + 15
        argv.extend(["--live", "--budget-policy", str(budget)])
    runner, rubric = _jev_evaluation_assets()
    return {
        "node": _jev_node(),
        "argv": [str(runner), "--rubric", str(rubric), *argv],
        "deadline_seconds": deadline,
    }


def _run_actionability(args: Any) -> int:
    """Use the shipped Gateway evaluator; never alter deterministic findings."""
    from .cli import _run_cli_bounded

    try:
        root = Path(args.root).resolve(strict=True)
        command = _jev_review_command(args, root)
        output = _jev_workspace_path(
            root, args.out or ".factory/jev/actionability-report.json"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        result = _run_cli_bounded(
            command["node"], command["argv"], root, timeout=command["deadline_seconds"]
        )
        print(result["stdout"].decode("utf-8", errors="replace"), end="")
        if not result["ok"]:
            print(
                json.dumps(
                    {
                        "state": "UNAVAILABLE",
                        "code": "E_JEV_EVALUATION",
                        "message": "JEV evaluation did not complete; inspect the local journal.",
                        "exit_code": result.get("exit_code"),
                    }
                ),
                file=sys.stderr,
            )
            return 2
        return 0
    except (OSError, ValueError, TypeError) as error:
        print(
            json.dumps(
                {
                    "state": "UNAVAILABLE",
                    "code": "E_JEV_PREFLIGHT",
                    "message": str(error),
                }
            ),
            file=sys.stderr,
        )
        return 2


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


def _security_receipt_error_message(error: Exception) -> str:
    if isinstance(error, OSError):
        return "Security scan receipt could not be written."
    return str(error)


def _security_mode_option_error(args: Any) -> str | None:
    """Validate opt-in full-profile controls before selecting an engine."""
    full_repository = bool(getattr(args, "full_repository", False))
    resume = bool(getattr(args, "resume", False))
    max_batches = getattr(args, "max_batches", 1)
    context_profile = getattr(args, "context_profile", "isolated-v1")
    if context_profile != "isolated-v1" and not full_repository:
        return "--context-profile requires --full-repository"
    if context_profile not in {"isolated-v1", "workspace-v2"}:
        return "--context-profile must be isolated-v1 or workspace-v2"
    if resume and not full_repository:
        return "--resume requires --full-repository"
    if (
        not isinstance(max_batches, int)
        or isinstance(max_batches, bool)
        or not 1 <= max_batches <= 64
        or (max_batches != 1 and not full_repository)
    ):
        return "--max-batches must be 1..64 and requires --full-repository"
    return None


def _full_security_unsupported_options(args: Any) -> bool:
    fields = (
        "out",
        "baseline",
        "oracle_evidence",
        "oracle_trust_root",
        "oracle_trust_sha256",
        "oracle_environment_sha256",
        "tenant_read_call",
        "tenant_read_binding",
    )
    return any(getattr(args, field, None) for field in fields) or (
        getattr(args, "tenant_contract", ".factory/tenant-read-contract.json")
        != ".factory/tenant-read-contract.json"
    )


def _print_full_security(args: Any, result: dict) -> None:
    """Keep raw findings and source-bound observations visibly distinct."""
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    workspace_profile = result.get("context_profile") == "workspace-v2"
    print(
        f"Full repository security profile: {result['source_accounting_state']} ({result['files_audited']}/{result['files_discovered']} audited)"
    )
    if workspace_profile:
        authority = result.get("workspace_evidence", {}).get("findings_authority")
        print(
            "Active findings use the native source-bound partition; raw primary findings remain in JSON."
            if authority == "native_source_bound_partition"
            else "Partition incomplete; active findings retain unverified execution or credential risk."
        )
    _print_full_security_findings(result, workspace_profile)
    if workspace_profile:
        evidence = result.get("workspace_evidence", {})
        observations = evidence.get("primitive_observations", [])
        if not isinstance(observations, list):
            observations = []
        partition = evidence.get("primitive_partition", {})
        if not isinstance(partition, dict):
            partition = {}
        processing = evidence.get("primary_processing", {})
        if not isinstance(processing, dict):
            processing = {}
        print(
            f"Primitive partition: {partition.get('state', 'INCOMPLETE')} "
            f"(error={partition.get('error_code') or 'none'}); observations are not clearances."
        )
        print(
            f"Primary accounting: {processing.get('checkpoint_rows_recomputed_and_matched', 0)} "
            f"saved rows reconciled; {processing.get('new_primary_rows_assessed', 0)} new rows assessed; "
            f"{processing.get('consume_calls', 0)} consume chunks, limit "
            f"{processing.get('consume_call_limit', 460)} each."
        )
        print(f"Source-bound primitive observations: {len(observations)}.")
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            facts = observation.get("facts", {})
            if not isinstance(facts, dict):
                facts = {}
            disposition = facts.get("disposition", "source-bound")
            print(
                f"  {disposition}: {observation.get('path', '?')}:{observation.get('line', '?')} [{observation.get('code', '?')}]"
            )
        print(
            f"Workspace context: {evidence.get('oracle_context', {}).get('state', 'INCOMPLETE')}; "
            f"full primary inventory assessed: {evidence.get('audit_coverage', {}).get('complete', False)}."
        )
        _print_finding_tier_report(evidence.get("finding_tiers"))
    print("Semantic coverage: INCOMPLETE; global consumer closure is not verified.")


def _print_full_security_findings(result, workspace_profile):
    """Render active partition rows while JSON retains raw source history."""
    findings = (
        result.get("workspace_evidence", {}).get("findings", [])
        if workspace_profile
        else [
            finding
            for row in result.get("primary_results", [])
            for finding in row.get("findings", [])
        ]
    )
    for finding in findings:
        print(
            f"{finding['severity']} {finding['code']}: {finding['path']}:{finding['line']} — {finding['message']}"
        )


def _print_finding_tier_report(report):
    """Render additive finding tiers without implying a clean security result."""
    if not isinstance(report, dict):
        print("Finding tiers: unavailable; no tier claim is made.")
        return
    counts = report.get("tier_counts", {})
    if not isinstance(counts, dict):
        counts = {}
    abstention = report.get("abstention", {})
    if not isinstance(abstention, dict):
        abstention = {}
    fraction = abstention.get("fraction")
    fraction_text = f"{fraction:.1%}" if isinstance(fraction, (int, float)) else "N/A"
    gate = report.get("defect_gate", {})
    if not isinstance(gate, dict):
        gate = {}
    print(
        "Finding tiers: "
        f"supported={counts.get('SUPPORTED_DEFECT', 0)}, "
        f"needs_context={counts.get('NEEDS_CONTEXT', 0)}, "
        f"proven_primitive={counts.get('PROVEN_PRIMITIVE', 0)}."
    )
    print(
        f"Tier abstention: {abstention.get('count', 0)}/{abstention.get('denominator', 0)} "
        f"({fraction_text}); this-run diagnostics only."
    )
    print(
        f"Finding tier defect gate: {gate.get('state', 'BLOCKED')} "
        f"({gate.get('reason', 'tier_report_unavailable')}); no clean result is established."
    )
    for row in report.get("ledger", []):
        if not isinstance(row, dict) or row.get("tier") != "NEEDS_CONTEXT":
            continue
        source = row.get("source_identity", {})
        missing = row.get("missing_premises", [])
        raw = row.get("raw_finding", {})
        if not isinstance(source, dict) or not isinstance(raw, dict):
            continue
        print(
            f"  NEEDS_CONTEXT {source.get('code', '?')}: "
            f"{source.get('path', '?')}:{source.get('line', '?')} "
            f"[{raw.get('severity', '?')}] missing={','.join(str(item) for item in missing)}"
        )


def _run_full_security(args: Any) -> int:
    from .deep_audit_io import RuntimeAuditError, full_repository_scan

    if _full_security_unsupported_options(args):
        print(
            json.dumps(
                {
                    "state": "INVALID",
                    "code": "E_FULL_REPOSITORY_OPTIONS",
                    "message": "full-repository mode does not accept legacy receipt, tenant-read, or oracle options",
                }
            ),
            file=sys.stderr,
        )
        return 2
    try:
        context_profile = getattr(args, "context_profile", "isolated-v1")
        policy_options = (
            {"defect_policy": "trusted-core-v1"}
            if getattr(args, "defect_policy", "legacy-v1") == "trusted-core-v1"
            else {}
        )
        deadline = time.monotonic() + 180 if context_profile == "workspace-v2" else None
        result = full_repository_scan(
            Path(args.root),
            resume=getattr(args, "resume", False),
            context_profile=context_profile,
            deadline_monotonic=deadline,
            **policy_options,
        )
        completed_batches = 1
        max_batches = getattr(args, "max_batches", 1)
        while result["pending_count"] and completed_batches < max_batches:
            result = full_repository_scan(
                Path(args.root),
                resume=True,
                context_profile=context_profile,
                deadline_monotonic=deadline,
                **policy_options,
            )
            completed_batches += 1
        result["invocation"] = {
            "batches": completed_batches,
            "max_batches": max_batches,
            "batch_primary_limit": 460,
        }
        if context_profile != "isolated-v1":
            result["invocation"].update(
                {
                    "context_profile": context_profile,
                    "shared_deadline_seconds": 180,
                }
            )
    except (RuntimeAuditError, OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "state": "INVALID",
                    "code": getattr(error, "code", "E_FULL_REPOSITORY"),
                    "message": str(error),
                }
            ),
            file=sys.stderr,
        )
        return 2
    return _finish_full_security(args, result, policy_options)


def _finish_full_security(args, result, policy_options):
    if policy_options and not args.json:
        _print_selected_security_policy(result)
        print("Semantic coverage: INCOMPLETE; global consumer closure is not verified.")
    else:
        _print_full_security(args, result)
    if policy_options:
        return result.get("defect_policy_decision", {}).get("exit_code", 2)
    # File accounting is not a clean security result while semantic coverage is incomplete.
    return 1


def _run_security(args: Any) -> int:
    if getattr(args, "defect_policy", "legacy-v1") in {
        "source-role-v1",
        "source-role-v2",
        "source-role-v3",
    } and getattr(args, "full_repository", False):
        print(
            json.dumps(
                {
                    "state": "INVALID",
                    "code": "E_DEFECT_POLICY_SCOPE",
                    "message": "source-role policies currently require a bounded native scan",
                }
            ),
            file=sys.stderr,
        )
        return 2
    if (
        getattr(args, "defect_policy", "legacy-v1") != "legacy-v1"
        and getattr(args, "full_repository", False)
        and getattr(args, "context_profile", "isolated-v1") != "workspace-v2"
    ):
        print(
            json.dumps(
                {
                    "state": "INVALID",
                    "code": "E_DEFECT_POLICY_SCOPE",
                    "message": "trusted-core-v1 requires a bounded native scan or the native workspace-v2 partition",
                }
            ),
            file=sys.stderr,
        )
        return 2
    if error := _security_mode_option_error(args):
        print(
            json.dumps(
                {
                    "state": "INVALID",
                    "code": "E_FULL_REPOSITORY_OPTIONS",
                    "message": error,
                }
            ),
            file=sys.stderr,
        )
        return 2
    if getattr(args, "full_repository", False):
        return _run_full_security(args)
    return _run_bounded_security(args)


def _run_bounded_security(args: Any) -> int:
    """Run the existing bounded scan after shared option/profile dispatch."""
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
        from .mission_control_status import security_scan_pytest_collection_snapshot

        before_collection = security_scan_pytest_collection_snapshot(Path(args.root))
        result = security_scan(
            Path(args.root),
            tenant_read_calls=calls,
            tenant_read_bindings=bindings,
            tenant_read_scopes=contract_evidence.get("scoped_reads"),
            tenant_policy_applies=contract_evidence.get("policy_applies", False),
            oracle_evidence=getattr(args, "oracle_evidence", None),
            oracle_trust_root=getattr(args, "oracle_trust_root", None),
            oracle_trust_sha256=getattr(args, "oracle_trust_sha256", None),
            oracle_environment_sha256=getattr(args, "oracle_environment_sha256", None),
            **(
                {"defect_policy": args.defect_policy}
                if getattr(args, "defect_policy", "legacy-v1") != "legacy-v1"
                else {}
            ),
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
        from .mission_control_status import (
            prepare_security_scan_receipt_report,
            write_security_scan_receipt,
        )

        result = prepare_security_scan_receipt_report(
            Path(args.root), result, before_collection=before_collection
        )
        write_security_scan_receipt(Path(args.root), result)
    except (ReviewAuditError, OSError, ValueError) as error:
        message = _security_receipt_error_message(error)
        print(json.dumps({"state": "INVALID", "message": message}), file=sys.stderr)
        return 2
    return _finish_bounded_security(args, result)


def _finish_bounded_security(args, result):
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif getattr(args, "defect_policy", "legacy-v1") != "legacy-v1":
        _print_selected_security_policy(result)
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
        _print_finding_tier_report(result.get("finding_tier_report"))
    if getattr(args, "defect_policy", "legacy-v1") != "legacy-v1":
        return result.get("defect_policy_decision", {}).get("exit_code", 2)
    return 0 if result["state"] == "CLEAN" else 2 if result["state"] == "BLOCKED" else 1


def _print_selected_security_policy(result):
    """Keep policy nonblocking status distinct from source and release approval."""
    decision = result.get("defect_policy_decision", {})
    print(
        f"Defect policy {result.get('selected_defect_policy', 'trusted-core-v1')}: {decision.get('state', 'BLOCKED')}"
    )
    print(
        decision.get("action_summary", "Current native policy evidence is unavailable.")
    )
    coverage = result.get("audit_coverage", {})
    print(
        f"Source coverage: {coverage.get('files_audited', 0)}/{coverage.get('files_discovered', 0)}; complete={coverage.get('complete') is True}"
    )
    tiers = result.get(
        "finding_tier_report",
        result.get("workspace_evidence", {}).get("finding_tiers", {}),
    )
    if result.get("selected_defect_policy") in {
        "source-role-v1",
        "source-role-v2",
        "source-role-v3",
    }:
        for raw in result.get("findings", []):
            print(
                f"ACTIVE [{raw['severity']}] {raw['code']}: {raw['path']}:{raw['line']} — {raw['message']}"
            )
        print(
            f"NEEDS_CONTEXT reviews: {len(result.get('context_reviews', []))}; operation safety remains unassessed."
        )
        print(
            "Original diagnostics and severities remain in the JSON report and receipt. No clean security result or release approval established."
        )
        return
    for row in tiers.get("ledger", []):
        if row.get("tier") != "SUPPORTED_DEFECT":
            continue
        raw = row["raw_finding"]
        print(
            f"SUPPORTED_DEFECT [{raw['severity']}] {raw['code']}: {raw['path']}:{raw['line']} — {raw['message']}"
        )
    _print_finding_tier_report(tiers)
    print(
        "Original diagnostics and severities remain in the JSON report and receipt. Policy exit zero does not approve a release or establish a clean security result."
    )


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

    if args.tool != "security" and hasattr(args, "defect_policy"):
        print(
            json.dumps(
                {
                    "state": "INVALID",
                    "code": "E_DEFECT_POLICY_SCOPE",
                    "message": "--defect-policy is valid only for audit security",
                }
            ),
            file=sys.stderr,
        )
        return 2
    if args.tool != "security" and (
        getattr(args, "full_repository", False)
        or getattr(args, "resume", False)
        or getattr(args, "max_batches", 1) != 1
    ):
        print(
            json.dumps(
                {
                    "state": "INVALID",
                    "code": "E_FULL_REPOSITORY_OPTIONS",
                    "message": "full-repository options are valid only for audit security",
                }
            ),
            file=sys.stderr,
        )
        return 2

    handlers = {
        "evals": _run_evals,
        "security": _run_security,
        "governance": _run_governance,
        "fingerprint": _run_fingerprint,
        "workflows": _run_workflows,
        "taxonomy": _run_taxonomy,
        "agent-context": _run_agent_context,
        "actionability": _run_actionability,
    }
    try:
        return handlers.get(args.tool, _run_code)(args)
    except ReviewAuditError as exc:
        print(
            json.dumps({"state": "invalid", "code": exc.code, "message": str(exc)}),
            file=sys.stderr,
        )
        return 2

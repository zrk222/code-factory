"""Read-only, source-bound review context for Junie's JetBrains changelist."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from .audit_trace import AuditTraceError, build_audit_trace
from .audit_taxonomy import (
    audit_domain_ids,
    audit_taxonomy,
    normalize_measurement_state as _measurement_state,
    resolve_agent_action_reference,
    validate_measurement_ledger,
)
from .benchmark_lab import run_public_benchmark
from .runtime_coverage import read_runtime_coverage_report


MAX_CHANGED_PATHS = 20
MAX_RESPONSE_BYTES = 64 * 1024
MAX_COVERAGE_LOCATIONS = 20
_SECURITY_LANGUAGES = frozenset(
    {
        "python",
        "javascript",
        "typescript",
        "java",
        "kotlin",
        "go",
        "rust",
        "csharp",
        "c",
        "c_header",
        "cpp",
        "objc",
        "swift",
        "ruby",
        "php",
        "shell",
    }
)
_SOURCE_LANGUAGES = _SECURITY_LANGUAGES | frozenset(
    {
        "sql",
        "terraform",
        "hcl",
        "gradle",
        "gradle_kotlin",
        "scala",
        "dart",
        "vue",
        "svelte",
    }
)
_DEPENDENCY_FILES = frozenset(
    {
        "cargo.lock",
        "composer.lock",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    }
)
_API_CONTRACT_NAMES = frozenset(
    {
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "swagger.json",
        "swagger.yaml",
        "asyncapi.json",
        "asyncapi.yaml",
        "asyncapi.yml",
    }
)
_CONFIG_LANGUAGES = frozenset(
    {
        "terraform",
        "hcl",
        "dockerfile",
        "yaml",
        "toml",
        "ini",
        "properties",
    }
)
_GAP_MEASUREMENT_LINKS = {
    "pattern_and_guard_path_audit": "pattern_and_guard_path_audit",
    "security_language_coverage": "security_language_coverage",
    "candidate_runtime_execution": "target_project_runtime_coverage",
    "test_oracle_strength": "mutation_and_test_oracle",
    "receipt_authenticity": "authenticated_runner_provenance",
    "independent_specialty_review": "specialty_ai_review_and_consensus",
    "review_consensus": "reviewer_consensus",
    "repository_prompt_injection": "repository_instruction_injection",
    "repository_instruction_and_injection_resistance": "repository_instruction_injection",
    "tenant_boundary_applicability": "tenant_and_production_observability",
    "tenant_boundary_and_production_observability": "tenant_and_production_observability",
    "production_observability": "production_observability",
    "dependency_and_supply_chain": "dependencies_and_configuration",
    "configuration_and_infrastructure_policy": "configuration_and_infrastructure_policy",
    "secrets_and_sensitive_data": "secrets",
    "dynamic_runtime_and_fuzz": "dynamic_runtime_and_fuzz",
    "api_and_external_service_contracts": "api_contracts",
    "migration_and_data_integrity": "migration_integrity",
    "performance_and_concurrency": "performance_and_concurrency",
    "accessibility_and_platform_compatibility": "accessibility_and_platform",
    "ci_architecture_and_artifact_provenance": "architecture_and_ci",
    "attribution_integrity": "attribution_integrity",
}
_GAP_DENOMINATOR_FIELDS = {
    "pattern_and_guard_path_audit": "candidate_path_denominator",
    "candidate_runtime_execution": "candidate_path_denominator",
    "dependency_and_supply_chain": "candidate_path_denominator",
    "configuration_and_infrastructure_policy": "candidate_path_denominator",
    "secrets_and_sensitive_data": "candidate_path_denominator",
    "dynamic_runtime_and_fuzz": "candidate_path_denominator",
    "api_and_external_service_contracts": "candidate_path_denominator",
    "migration_and_data_integrity": "candidate_path_denominator",
    "performance_and_concurrency": "candidate_path_denominator",
    "accessibility_and_platform_compatibility": "candidate_path_denominator",
    "ci_architecture_and_artifact_provenance": "candidate_path_denominator",
    "repository_instruction_and_injection_resistance": "candidate_path_denominator",
    "tenant_boundary_and_production_observability": "candidate_path_denominator",
}
_AUTHORITY = {
    "execution": False,
    "approval": False,
    "merge": False,
    "publication": False,
    "deployment": False,
    "signing": False,
    "credential": False,
    "network": False,
}


class JunieReviewError(ValueError):
    """A changelist review request is outside the documented safe scope."""

    def __init__(self, message: str, code: str = "JUNIE_REVIEW_INPUT_REJECTED") -> None:
        super().__init__(message)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _changed_paths(root: Path, arguments: object) -> list[str]:
    if (
        not isinstance(arguments, dict)
        or set(arguments) != {"source", "changed_paths"}
        or arguments.get("source") != "jetbrains_active_changelist"
    ):
        raise JunieReviewError(
            "factory.junie_review requires source=jetbrains_active_changelist and changed_paths",
            "JUNIE_REVIEW_SOURCE_REQUIRED",
        )
    supplied = arguments["changed_paths"]
    if not isinstance(supplied, list) or not 1 <= len(supplied) <= MAX_CHANGED_PATHS:
        raise JunieReviewError("changed_paths must contain 1 to 20 paths")
    workspace = root.resolve()
    result: list[str] = []
    for raw in supplied:
        if not isinstance(raw, str) or not raw or len(raw) > 512:
            raise JunieReviewError("each changelist path must be 1 to 512 characters")
        relative = PurePosixPath(raw)
        if (
            relative.as_posix() != raw
            or raw.startswith("/")
            or ":" in relative.parts[0]
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise JunieReviewError(
                "changelist paths must be normalized and workspace-relative"
            )
        target = (workspace / Path(*relative.parts)).resolve()
        try:
            target.relative_to(workspace)
        except ValueError as exc:
            raise JunieReviewError("a changelist path escapes the workspace") from exc
        if not target.is_file():
            raise JunieReviewError(
                "every changelist path must name an existing regular file"
            )
        result.append(relative.as_posix())
    if len(result) != len(set(result)):
        raise JunieReviewError("changelist paths must be unique")
    return result


def _steps(
    trace_inputs: dict[str, str], paths: list[str], gaps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    references = [
        (
            "changed-paths",
            trace_inputs["candidate"],
            "CHANGELIST_PATH_VALIDATION",
            "SCOPE_HASHED",
            "PASS",
        ),
        (
            "runtime-receipt",
            trace_inputs["runtime"],
            "RUNTIME_RECEIPT_VALIDATION",
            "RUNTIME_EVIDENCE_BOUND",
            trace_inputs["runtime_state"],
        ),
    ]
    result = [
        {
            "step_id": step_id,
            "input": f"sha256:{digest}",
            "guard": guard,
            "decision": decision if state == "PASS" else f"RETAIN_{state}",
            "state": state,
            "source_paths": paths,
        }
        for step_id, digest, guard, decision, state in references
    ]
    source_paths = paths[:10]
    for gap in gaps:
        gap_state = gap["trace_state"]
        result.append(
            {
                "step_id": f"gap-{gap['id']}",
                "input": f"sha256:{_hash({key: value for key, value in gap.items() if key != 'trace_state'})}",
                "guard": f"GAP_{gap['id'].upper()}",
                "decision": f"REPORT_{gap_state}",
                "state": gap_state,
                "source_paths": source_paths,
            }
        )
    return result


def _known_gaps(
    root: Path, paths: list[str], coverage: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return explicit, actionable audit limits for the current changed paths."""
    manifest = root / ".factory" / "review-audits.json"
    manifest_digest = None
    manifest_status = "MISSING"
    try:
        manifest_resolved = manifest.resolve()
        manifest_present = (
            manifest_resolved.is_relative_to(root.resolve())
            and manifest_resolved.is_file()
        )
        if manifest_present and manifest_resolved.stat().st_size <= 4 * 1024 * 1024:
            manifest_digest = hashlib.sha256(manifest_resolved.read_bytes()).hexdigest()
            manifest_status = "PRESENT_UNVERIFIED"
        elif manifest_present:
            manifest_present = False
            manifest_status = "TOO_LARGE"
    except OSError:
        manifest_present = False
        manifest_status = "UNREADABLE"
    non_python = [
        path
        for path in paths
        if _language(path) in _SECURITY_LANGUAGES and _language(path) != "python"
    ]
    python_paths = [path for path in paths if _language(path) == "python"]
    test_candidate_paths = [path for path in paths if _is_test_path(path)]
    unclassified_paths = [path for path in paths if _language(path) == "other"]
    runtime_state = coverage.get("state")
    if runtime_state == "BOUND_UNAUTHENTICATED":
        runtime_trace_state = "INCOMPLETE"
    elif runtime_state in {"NOT_RUN", "INCOMPLETE", "FAIL", "UNBOUND"}:
        runtime_trace_state = runtime_state
    else:
        runtime_trace_state = "UNBOUND"
    dependency_paths = [
        path for path in paths if PurePosixPath(path).name.lower() in _DEPENDENCY_FILES
    ]
    configuration_paths = [
        path
        for path in paths
        if _language(path) in _CONFIG_LANGUAGES
        or any(
            part.lower()
            in {
                "config",
                "configuration",
                "infra",
                "infrastructure",
                "deploy",
                "k8s",
                "helm",
            }
            for part in PurePosixPath(path).parts
        )
    ]
    migration_paths = [
        path
        for path in paths
        if any(
            part.lower() in {"migration", "migrations", "alembic", "versions"}
            for part in PurePosixPath(path).parts
        )
        or (
            PurePosixPath(path).suffix.lower() == ".sql"
            and any(
                token in PurePosixPath(path).name.lower()
                for token in ("migration", "schema", "ddl")
            )
        )
    ]
    api_paths = [
        path
        for path in paths
        if PurePosixPath(path).name.lower() in _API_CONTRACT_NAMES
        or PurePosixPath(path).suffix.lower() in {".proto", ".graphql", ".gql"}
    ]
    ui_paths = [
        path
        for path in paths
        if _language(path)
        in {"javascript", "typescript", "vue", "svelte", "html", "css"}
        or any(
            part.lower() in {"ui", "web", "frontend", "mobile", "views", "components"}
            for part in PurePosixPath(path).parts
        )
    ]
    workflow_paths = [
        path
        for path in paths
        if "/.github/workflows/" in f"/{path.lower()}"
        or PurePosixPath(path).name.lower()
        in {"gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml"}
    ]
    source_paths = [path for path in paths if _language(path) in _SOURCE_LANGUAGES]
    prompt_paths = [
        path
        for path in paths
        if any(
            token in PurePosixPath(path).name.lower()
            for token in ("prompt", "instruction", "agent", "skill", "policy")
        )
    ]
    benchmark = _public_benchmark_measurement()
    manifest_gap_status = {
        "MISSING": "BLOCKED_MISSING_MANIFEST",
        "TOO_LARGE": "BLOCKED_MANIFEST_TOO_LARGE",
        "UNREADABLE": "BLOCKED_MANIFEST_UNREADABLE",
    }.get(manifest_status, f"BLOCKED_MANIFEST_{manifest_status}")
    gaps = [
        {
            "id": "pattern_and_guard_path_audit",
            "status": "MANIFEST_PRESENT_UNVERIFIED"
            if manifest_present
            else manifest_gap_status,
            "trace_state": "NOT_RUN" if manifest_present else "UNBOUND",
            "manifest_sha256": manifest_digest,
            "candidate_path_denominator": len(paths),
            "candidate_paths_measured": 0,
            "affected_paths": paths,
            "action": "Validate the project .factory/review-audits.json and run the pattern and guard-path review; manifest presence alone is not an audit result.",
        },
        {
            "id": "security_language_coverage",
            "status": "NON_PYTHON_NOT_COVERED"
            if non_python
            else "PYTHON_AST_ONLY_NOT_RUN"
            if python_paths
            else "NO_CODE_PATHS",
            "trace_state": "UNBOUND" if non_python else "NOT_RUN",
            "python_candidate_denominator": len(python_paths),
            "non_python_candidate_denominator": len(non_python),
            "recognized_source_candidate_denominator": len(python_paths)
            + len(non_python),
            "unclassified_candidate_denominator": len(unclassified_paths),
            "candidate_paths_measured": 0,
            "affected_paths": non_python or python_paths,
            "action": "Run a language-specific security scanner for every non-Python code path; the built-in security pattern lane covers Python AST only and has not run in this review.",
        },
        {
            "id": "candidate_runtime_execution",
            "status": "NOT_RUN",
            "trace_state": runtime_trace_state,
            "candidate_path_denominator": len(paths),
            "candidate_paths_executed": 0,
            "affected_paths": paths,
            "action": "Run the candidate's declared checks in a clean CI runner and bind the receipt to this commit and the changed-source hashes.",
        },
        {
            "id": "test_oracle_strength",
            "status": "NOT_EVALUATED",
            "trace_state": "NOT_RUN",
            "seeded_scanner_benchmark": benchmark,
            "candidate_behavior_denominator": None,
            "candidate_test_file_scope": len(test_candidate_paths),
            "denominator_requirement": "A candidate behavior inventory with test-to-behavior mapping and mutation or seeded-defect outcomes.",
            "affected_paths": paths,
            "action": "Run mutation or seeded-defect checks for changed behavior. The attached public benchmark measures only the bundled Python AST scanner against its public corpus; it is not evidence about this candidate's tests.",
        },
        {
            "id": "receipt_authenticity",
            "status": "UNAUTHENTICATED",
            "trace_state": "UNBOUND"
            if runtime_state != "BOUND_UNAUTHENTICATED"
            else "INCOMPLETE",
            "receipt_sha256": coverage.get("receipt_sha256"),
            "denominator_requirement": "A risk-tiered execution-profile inventory listing every required receipt for this candidate.",
            "affected_paths": paths,
            "action": "Use a signed or provider-authenticated clean-runner receipt before treating runtime evidence as release-grade.",
        },
        {
            "id": "independent_specialty_review",
            "status": "NOT_AUTHENTICATED",
            "trace_state": "UNBOUND",
            "denominator_requirement": "A risk-tiered policy defining required reviewer roles and independent passes.",
            "affected_paths": paths,
            "action": "Obtain a separate specialty AI review bound to the same candidate and include its evidence; this MCP result cannot authenticate reviewer identity or approval.",
        },
        {
            "id": "repository_prompt_injection",
            "status": "NOT_RUN_FOR_CANDIDATE",
            "trace_state": "NOT_RUN",
            "affected_paths": paths,
            "action": "Exercise repository-controlled instructions and receipts as adversarial data in the candidate's review and tool-output paths.",
        },
        {
            "id": "tenant_boundary_applicability",
            "status": "REVIEW_REQUIRED",
            "trace_state": "UNBOUND",
            "affected_paths": paths,
            "action": "Declare whether this project has tenant or principal boundaries; when applicable, run cross-tenant read, list, write, and approval tests.",
        },
        {
            "id": "production_observability",
            "status": "NOT_RUN",
            "trace_state": "NOT_RUN",
            "affected_paths": paths,
            "action": "For deployment-bound changes, verify the isolated staging/runtime path and inspect logs, telemetry, and rollback behavior.",
        },
        {
            "id": "review_consensus",
            "status": "NOT_ESTABLISHED",
            "trace_state": "NOT_RUN",
            "denominator_requirement": "A policy-defined count of independent passes and eligible findings for consensus/adjudication.",
            "affected_paths": paths,
            "action": "Do not treat one model pass as consensus; record independent reviewer findings and adjudication when the risk profile requires multi-pass review.",
        },
        {
            "id": "dependency_and_supply_chain",
            "status": "NOT_RUN" if dependency_paths else "NOT_TRIGGERED_BY_CHANGELIST",
            "trace_state": "NOT_RUN" if dependency_paths else "UNBOUND",
            "candidate_path_denominator": len(dependency_paths),
            "candidate_paths_measured": 0,
            "affected_paths": dependency_paths,
            "action": "For changed package manifests or lockfiles, run pinned SBOM and advisory scanners and bind their outputs to this candidate; this Junie projection does not execute them.",
        },
        {
            "id": "configuration_and_infrastructure_policy",
            "status": "NOT_RUN"
            if configuration_paths
            else "NOT_TRIGGERED_BY_CHANGELIST",
            "trace_state": "NOT_RUN" if configuration_paths else "UNBOUND",
            "candidate_path_denominator": len(configuration_paths),
            "candidate_paths_measured": 0,
            "affected_paths": configuration_paths,
            "action": "Run configuration and IaC policy checks for each changed deployment/config path, including effective environment and secret-reference validation.",
        },
        {
            "id": "secrets_and_sensitive_data",
            "status": "NOT_RUN",
            "trace_state": "NOT_RUN",
            "candidate_path_denominator": len(paths),
            "candidate_paths_measured": 0,
            "affected_paths": paths,
            "action": "Run secret scanning on changed content and repository history where required; this review only hashes supplied paths and does not inspect them with a secrets detector.",
        },
        {
            "id": "dynamic_runtime_and_fuzz",
            "status": "NOT_RUN" if source_paths else "NOT_APPLICABLE_TO_CHANGELIST",
            "trace_state": "NOT_RUN" if source_paths else "UNBOUND",
            "candidate_path_denominator": len(source_paths),
            "candidate_paths_executed": 0,
            "affected_paths": source_paths,
            "action": "Run the declared runtime, property, and fuzz lanes in the isolated deep-audit runner; no target code is executed by this Junie review.",
        },
        {
            "id": "api_and_external_service_contracts",
            "status": "NOT_RUN" if api_paths else "NOT_TRIGGERED_BY_CHANGELIST",
            "trace_state": "NOT_RUN" if api_paths else "UNBOUND",
            "candidate_path_denominator": len(api_paths),
            "denominator_quality": "PARTIAL_PATH_HEURISTIC",
            "denominator_requirement": "A candidate API/service inventory that maps changed route, client, and provider code to applicable contract checks.",
            "candidate_paths_executed": 0,
            "affected_paths": api_paths,
            "action": "Build or update the API/service applicability inventory, then validate changed schemas and exercise provider contracts against a controlled environment; schema presence alone does not prove compatibility.",
        },
        {
            "id": "migration_and_data_integrity",
            "status": "NOT_RUN" if migration_paths else "NOT_TRIGGERED_BY_CHANGELIST",
            "trace_state": "NOT_RUN" if migration_paths else "UNBOUND",
            "candidate_path_denominator": len(migration_paths),
            "denominator_quality": "PARTIAL_PATH_HEURISTIC",
            "denominator_requirement": "A migration/data-store inventory that includes ORM models, schema declarations, backfills, and migration scripts.",
            "candidate_paths_executed": 0,
            "affected_paths": migration_paths,
            "action": "Complete the migration/data-store inventory, then exercise forward migration, rollback, and data-integrity invariants against disposable representative data.",
        },
        {
            "id": "performance_and_concurrency",
            "status": "NOT_RUN" if source_paths else "NOT_APPLICABLE_TO_CHANGELIST",
            "trace_state": "NOT_RUN" if source_paths else "UNBOUND",
            "candidate_path_denominator": len(source_paths),
            "candidate_paths_executed": 0,
            "affected_paths": source_paths,
            "action": "Run workload-specific latency/resource and race/concurrency checks; no performance or concurrent execution measurement is produced here.",
        },
        {
            "id": "accessibility_and_platform_compatibility",
            "status": "NOT_RUN" if ui_paths else "NOT_TRIGGERED_BY_CHANGELIST",
            "trace_state": "NOT_RUN" if ui_paths else "UNBOUND",
            "candidate_path_denominator": len(ui_paths),
            "denominator_quality": "PARTIAL_PATH_HEURISTIC",
            "denominator_requirement": "A surface inventory of user-facing web, IDE, mobile, and accessibility entry points affected by the candidate.",
            "candidate_paths_measured": 0,
            "affected_paths": ui_paths,
            "action": "Complete the affected UI/platform surface inventory, then run accessibility-tree and supported-platform checks; no accessibility tree or platform matrix ran.",
        },
        {
            "id": "ci_architecture_and_artifact_provenance",
            "status": "NOT_RUN"
            if workflow_paths or source_paths
            else "NOT_TRIGGERED_BY_CHANGELIST",
            "trace_state": "NOT_RUN" if workflow_paths or source_paths else "UNBOUND",
            "candidate_path_denominator": len(workflow_paths) + len(source_paths),
            "candidate_paths_executed": 0,
            "affected_paths": list(dict.fromkeys(workflow_paths + source_paths)),
            "action": "Run architecture policy and clean-runner CI; capture reproducible build inputs and authenticated artifact provenance for this exact candidate.",
        },
        {
            "id": "repository_instruction_and_injection_resistance",
            "status": "NOT_RUN" if prompt_paths else "NOT_TRIGGERED_BY_CHANGELIST",
            "trace_state": "NOT_RUN" if prompt_paths else "UNBOUND",
            "candidate_path_denominator": len(prompt_paths),
            "candidate_paths_executed": 0,
            "affected_paths": prompt_paths,
            "action": "Run adversarial instruction/tool-output fixtures against the candidate path; path names and hashes here do not demonstrate injection resistance.",
        },
        {
            "id": "tenant_boundary_and_production_observability",
            "status": "APPLICABILITY_REQUIRED",
            "trace_state": "UNBOUND",
            "candidate_path_denominator": None,
            "candidate_paths_measured": 0,
            "denominator_requirement": "A declared tenant/principal model and deployment/service inventory for this project.",
            "affected_paths": paths,
            "action": "Declare tenant/principal and production-runtime applicability; if applicable, run isolation and telemetry/rollback checks with isolated staging data.",
        },
        {
            "id": "attribution_integrity",
            "status": "UNMEASURABLE",
            "trace_state": "UNBOUND",
            "candidate_path_denominator": None,
            "candidate_paths_measured": 0,
            "denominator_requirement": "Authenticated host task/tool events joined to completed candidate changes in the applicable time window.",
            "affected_paths": paths,
            "action": "Join authenticated host task and tool events to the candidate's completed changes; keep attribution null until both numerator and denominator are evidenced.",
        },
    ]
    return gaps


def _public_benchmark_measurement() -> dict[str, Any]:
    """Measure bundled scanner quality without presenting fixtures as target evidence."""
    try:
        receipt = run_public_benchmark()
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        return {
            "state": "INCOMPLETE",
            "reason": str(exc)[:200],
            "scope": "bundled FactoryLine Python AST scanner only; not the reviewed project",
        }
    categories = {}
    for name, row in receipt["metrics"].items():
        if name == "overall":
            continue
        categories[name] = {
            "state": "MEASURED"
            if row["n_positive"] or row["n_negative"]
            else "NO_CASES",
            "positive_cases": row["n_positive"],
            "negative_cases": row["n_negative"],
            "tp": row["tp"],
            "fp": row["fp"],
            "tn": row["tn"],
            "fn": row["fn"],
            "precision": row["precision"],
            "precision_ci95_wilson": row["precision_ci95_wilson"],
            "recall": row["recall"],
            "recall_ci95_wilson": row["recall_ci95_wilson"],
        }
    return {
        "state": "MEASURED",
        "decision": receipt["decision"],
        "scanner": receipt["scanner"],
        "scanner_version": receipt["scanner_version"],
        "corpus_sha256": receipt["corpus_sha256"],
        "case_count": len(receipt["cases"]),
        "categories": categories,
        "overall": {
            key: receipt["metrics"]["overall"][key]
            for key in (
                "tp",
                "fp",
                "tn",
                "fn",
                "n_positive",
                "n_negative",
                "precision",
                "precision_ci95_wilson",
                "recall",
                "recall_ci95_wilson",
            )
        },
        "agent_actions": receipt.get("agent_actions", []),
        "scope": "Bundled FactoryLine Python AST scanner against public hand-labeled seeds; not the reviewed project, an independent holdout, or production evidence.",
    }


def _coverage_details(
    root: Path, paths: list[str], trace: dict[str, Any]
) -> dict[str, Any]:
    snapshot = read_runtime_coverage_report(root, include_files=True)
    binding = trace["runtime_coverage"]
    if (
        binding["state"] != "BOUND_UNAUTHENTICATED"
        or snapshot.get("receipt_status") != "MATCHED_UNAUTHENTICATED"
        or snapshot.get("source_sha256") != binding.get("report_sha256")
        or snapshot.get("receipt_sha256") != binding.get("receipt_sha256")
    ):
        status = snapshot.get("state")
        return {
            "state": status
            if status in {"NOT_RUN", "INCOMPLETE", "FAIL"}
            else "UNBOUND",
            "reason": str(
                snapshot.get("receipt_reason")
                or snapshot.get("reason")
                or "Coverage receipt does not bind to the traced candidate."
            )[:240],
            "report_sha256": snapshot.get("source_sha256"),
            "receipt_sha256": snapshot.get("receipt_sha256"),
            "receipt_status": snapshot.get("receipt_status"),
            "candidate_binding": snapshot.get("candidate_binding"),
            "statements": snapshot.get("statements"),
            "branches": snapshot.get("branches"),
            "file_count": snapshot.get("file_count"),
            "modules": [],
            "limitation": snapshot["RUNTIME_COVERAGE_LIMITATION"],
        }
    changed = {
        path
        for path in paths
        if path.startswith("factoryline/") and path.endswith(".py")
    }
    rows = [
        item
        for item in snapshot.get("files", [])
        if isinstance(item, dict) and item.get("path") in changed
    ]
    modules: list[dict[str, Any]] = []
    remaining = MAX_COVERAGE_LOCATIONS
    for item in rows:
        missing_lines = item.get("missing_lines", [])
        missing_branches = item.get("missing_branches", [])
        line_rows = missing_lines[:remaining] if isinstance(missing_lines, list) else []
        remaining -= len(line_rows)
        branch_rows = (
            missing_branches[:remaining] if isinstance(missing_branches, list) else []
        )
        remaining -= len(branch_rows)
        modules.append(
            {
                "path": item["path"],
                "statements": item["statements"],
                "branches": item["branches"],
                "missing_lines": line_rows,
                "missing_branches": branch_rows,
                "detail_truncated": item.get("detail_truncated") is True
                or remaining == 0,
            }
        )
        if remaining == 0:
            break
    return {
        "state": "BOUND_UNAUTHENTICATED",
        "report_sha256": binding["report_sha256"],
        "receipt_sha256": binding["receipt_sha256"],
        "candidate_binding": snapshot["candidate_binding"],
        "statements": snapshot["statements"],
        "branches": snapshot["branches"],
        "file_count": snapshot["file_count"],
        "modules": modules,
        "max_locations": MAX_COVERAGE_LOCATIONS,
        "limitation": snapshot["RUNTIME_COVERAGE_LIMITATION"],
    }


def _language(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    filename = PurePosixPath(path).name.lower()
    if filename == "dockerfile" or filename.startswith("dockerfile."):
        return "dockerfile"
    if filename == "makefile" or filename.startswith("makefile."):
        return "makefile"
    if suffix == ".kts" and "gradle" in filename:
        return "gradle_kotlin"
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".go": "go",
        ".rs": "rust",
        ".cs": "csharp",
        ".c": "c",
        ".h": "c_header",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".hpp": "cpp",
        ".m": "objc",
        ".mm": "objc",
        ".swift": "swift",
        ".rb": "ruby",
        ".php": "php",
        ".sql": "sql",
        ".sh": "shell",
        ".bash": "shell",
        ".tf": "terraform",
        ".tfvars": "terraform",
        ".hcl": "hcl",
        ".gradle": "gradle",
        ".scala": "scala",
        ".sc": "scala",
        ".dart": "dart",
        ".vue": "vue",
        ".svelte": "svelte",
        ".html": "html",
        ".css": "css",
        ".scss": "css",
        ".less": "css",
        ".xml": "xml",
        ".json": "json",
        ".toml": "toml",
        ".ini": "ini",
        ".properties": "properties",
        ".proto": "protobuf",
        ".graphql": "graphql",
        ".gql": "graphql",
        ".md": "documentation",
        ".mdx": "documentation",
        ".ipynb": "notebook",
        ".yml": "yaml",
        ".yaml": "yaml",
    }.get(suffix, "other")


def _measurements(
    paths: list[str],
    coverage: dict[str, Any],
    gaps: list[dict[str, Any]],
    trace: dict[str, Any],
) -> dict[str, Any]:
    language_counts: dict[str, int] = {}
    for path in paths:
        language = _language(path)
        language_counts[language] = language_counts.get(language, 0) + 1
    python_count = language_counts.get("python", 0)
    modules = coverage.get("modules", [])
    modules = modules if isinstance(modules, list) else []
    runtime_supported = [
        path
        for path in paths
        if path.startswith("factoryline/") and _language(path) == "python"
    ]
    runtime_bound = coverage.get("state") == "BOUND_UNAUTHENTICATED"
    matched_modules = (
        [
            item
            for item in modules
            if isinstance(item, dict) and item.get("path") in runtime_supported
        ]
        if runtime_bound
        else []
    )
    statement = _aggregate_runtime_measure(matched_modules, "statements")
    branch = _aggregate_runtime_measure(matched_modules, "branches")
    test_paths = [path for path in paths if _is_test_path(path)]
    source_paths = [path for path in paths if _language(path) in _SOURCE_LANGUAGES]
    unsupported_languages = sorted(
        language
        for language in language_counts
        if language in _SOURCE_LANGUAGES and language != "python"
    )
    unclassified_path_count = language_counts.get("other", 0)
    dependency_paths = [
        path for path in paths if PurePosixPath(path).name.lower() in _DEPENDENCY_FILES
    ]
    configuration_paths = [
        path
        for path in paths
        if _language(path) in _CONFIG_LANGUAGES
        or any(
            part.lower()
            in {
                "config",
                "configuration",
                "infra",
                "infrastructure",
                "deploy",
                "k8s",
                "helm",
            }
            for part in PurePosixPath(path).parts
        )
    ]
    gap_counts: dict[str, int] = {}
    for gap in gaps:
        status = str(gap["status"])
        gap_counts[status] = gap_counts.get(status, 0) + 1
    gap_by_id = {gap["id"]: gap for gap in gaps}
    api_count = gap_by_id["api_and_external_service_contracts"][
        "candidate_path_denominator"
    ]
    migration_count = gap_by_id["migration_and_data_integrity"][
        "candidate_path_denominator"
    ]
    ui_count = gap_by_id["accessibility_and_platform_compatibility"][
        "candidate_path_denominator"
    ]
    benchmark = gap_by_id["test_oracle_strength"].get(
        "seeded_scanner_benchmark", {"state": "NOT_RUN"}
    )
    result = {
        "schema": "factory.audit-measurements.v1",
        "candidate": {
            "changed_path_count": len(paths),
            "language_path_counts": dict(sorted(language_counts.items())),
            "source_path_count": len(source_paths),
            "test_path_count": len(test_paths),
            "dependency_manifest_or_lock_path_count": len(dependency_paths),
            "configuration_or_infrastructure_path_count": len(configuration_paths),
            "unclassified_path_count": unclassified_path_count,
            "python_path_count": python_count,
            "non_python_path_count": len(paths) - python_count,
            "candidate_source_scope_sha256": _hash(
                {"changed_files": trace.get("changed_files", {})}
            ),
        },
        "audit_lane_coverage": {
            "measurement_definition": "evidence paths divided by eligible changed paths; zero evidence is not a passing audit",
            "candidate_inventory": _evidence_measure(
                "MEASURED",
                len(paths),
                len(paths),
                "Exact scope is the changed path list supplied to this interface; it is not an assertion that the IDE supplied every changed path.",
                "Compare the supplied path inventory with the authoritative IDE/SCM changelist and resolve any omitted or unknown files.",
            ),
            "pattern_and_guard_path_audit": _evidence_measure(
                "NOT_RUN"
                if gap_by_id["pattern_and_guard_path_audit"]["status"]
                == "MANIFEST_PRESENT_UNVERIFIED"
                else "BLOCKED",
                0,
                len(paths),
                "Denominator is every supplied changed path. Manifest presence is tracked separately and does not count as pattern or guard-path evidence.",
                gap_by_id["pattern_and_guard_path_audit"]["action"],
            ),
            "security_language_coverage": _evidence_measure(
                "UNSUPPORTED"
                if unsupported_languages
                else "NOT_RUN"
                if python_count
                else "APPLICABILITY_REQUIRED",
                0,
                len(source_paths),
                "Denominator is recognized changed source paths only; unclassified paths are reported separately and may require additional scanners.",
                "Run Python AST and language-appropriate security analyzers for every source language represented in the candidate; bind each result to path hashes.",
            ),
            "python_ast_security": _evidence_measure(
                "NOT_RUN" if python_count else "APPLICABILITY_REQUIRED",
                0,
                python_count,
                "Eligible scope is changed Python source paths only. This read-only report did not execute the scanner.",
                "Run the Python AST security lane on the exact changed Python source hashes and attach its result receipt.",
            ),
            "non_python_security": _evidence_measure(
                "UNSUPPORTED" if unsupported_languages else "APPLICABILITY_REQUIRED",
                0,
                sum(
                    language_counts.get(language, 0)
                    for language in unsupported_languages
                ),
                "The built-in scanner contributes no evidence for changed non-Python source paths.",
                "Run language-appropriate security analyzers for each changed non-Python source language and bind their receipts.",
            ),
            "secrets": _evidence_measure(
                "NOT_RUN" if paths else "APPLICABILITY_REQUIRED",
                0,
                len(paths),
                "Changed paths are the denominator; the Junie changelist projection does not execute a secret scanner.",
                "Run secret scanning on changed content and repository history where policy requires it.",
            ),
            "dependencies_and_configuration": _evidence_measure(
                "NOT_RUN" if dependency_paths else "NOT_TRIGGERED",
                0,
                len(dependency_paths),
                "Denominator is only changed, recognized package manifests and lockfiles; this does not inventory unchanged transitive dependencies.",
                "Run SBOM generation and advisory analysis against the full resolved dependency graph when applicable.",
            ),
            "configuration_and_infrastructure_policy": _evidence_measure(
                "NOT_RUN" if configuration_paths else "NOT_TRIGGERED",
                0,
                len(configuration_paths),
                "Denominator is configuration and IaC paths identified by known extensions or deployment directory names.",
                "Run declared configuration/IaC policy checks and bind the effective-environment result to these paths.",
            ),
            "unclassified_file_scope": _evidence_measure(
                "CLASSIFICATION_REQUIRED"
                if unclassified_path_count
                else "COMPLETE_BY_EXTENSION",
                0 if unclassified_path_count else len(paths),
                len(paths),
                "Files with unrecognized extensions are counted as unclassified; no binary/content sniffing is performed.",
                "Classify each unrecognized path as source, generated, binary, data, or documentation and assign applicable audit lanes.",
            ),
            "runtime_statement_coverage": _evidence_measure(
                "UNSUPPORTED",
                0,
                0,
                "Target-project statement totals are not available from the internal Coverage.py report. Internal module receipt binding is reported separately under runtime_coverage.",
                "Run the target project's native statement instrumentation and attach discovered/covered statement counts with a candidate-bound receipt.",
            ),
            "runtime_branch_coverage": _evidence_measure(
                "UNSUPPORTED",
                0,
                0,
                "Target-project branch totals are not available from the internal Coverage.py report. Internal module receipt binding is reported separately under runtime_coverage.",
                "Run target-native branch instrumentation and attach discovered/covered branch counts with a candidate-bound receipt.",
            ),
            "mutation_and_test_oracle": {
                "state": "UNMEASURABLE",
                "eligible_changed_paths": len(test_paths) if test_paths else None,
                "evidence_paths": 0,
                "evidence_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "A candidate behavior inventory with test-to-behavior mapping and mutation or seeded-defect outcomes.",
                "basis": "Changed test-file count is a scope signal, not the eligible behavior denominator. No candidate mutation run or behavior inventory was supplied; zero would falsely imply a measured 0% result.",
                "next_action": "Run mutation or seeded-defect checks against changed behavior and bind surviving-mutant results to this candidate.",
            },
            "dynamic_runtime_and_fuzz": _evidence_measure(
                "NOT_RUN" if source_paths else "APPLICABILITY_REQUIRED",
                0,
                len(source_paths),
                "Changed source paths are a scope signal only; runtime scenarios, reachable states, and fuzz/property input domains were not inventoried.",
                "Declare runtime scenarios and invariants, then run bounded property/fuzz and dynamic checks in an isolated runner.",
            ),
            "seeded_scanner_benchmark": {
                "state": benchmark.get("state", "NOT_MEASURED"),
                "measurement_state": _measurement_state(
                    str(benchmark.get("state", "NOT_MEASURED"))
                ),
                "eligible_cases": benchmark.get("case_count"),
                "measured_cases": benchmark.get("case_count"),
                "observation_completion_percent": 100.0
                if benchmark.get("case_count")
                else None,
                "denominator_state": "KNOWN_PUBLIC_CORPUS_CASES"
                if benchmark.get("case_count")
                else "UNKNOWN",
                "basis": "This measures the public, hand-labeled FactoryLine scanner corpus; it is not the target candidate or independent holdout.",
                "next_action": "Resolve every case-level benchmark action, add independent representative holdout cases, and publish category confusion counts with confidence intervals.",
                "agent_actions": benchmark.get("agent_actions", []),
            },
            "api_contracts": _evidence_measure(
                "NOT_RUN" if api_count else "NOT_TRIGGERED",
                0,
                api_count,
                "Changed schema filenames are a partial path heuristic and miss routes or provider clients implemented only in source.",
                "Inventory affected routes, clients and providers, then validate schemas and execute controlled consumer/provider contract checks.",
            ),
            "migration_integrity": _evidence_measure(
                "NOT_RUN" if migration_count else "NOT_TRIGGERED",
                0,
                migration_count,
                "Migration filenames/directories are a partial heuristic and miss ORM-only model changes, backfills, and application schema changes.",
                "Inventory changed stores, ORM models, schemas and backfills, then run forward/rollback/data-invariant checks on disposable representative data.",
            ),
            "performance_and_concurrency": _evidence_measure(
                "NOT_RUN" if source_paths else "APPLICABILITY_REQUIRED",
                0,
                len(source_paths),
                "Changed source files provide a scope denominator only; no workload oracle or concurrent execution was supplied.",
                "Define workload and race invariants, then run bounded performance and concurrency checks.",
            ),
            "accessibility_and_platform": _evidence_measure(
                "NOT_RUN" if ui_count else "NOT_TRIGGERED",
                0,
                ui_count,
                "UI paths are a partial language/directory heuristic; non-obvious surfaces and platform variants require an explicit surface inventory.",
                "Inventory affected web/IDE/mobile interactions, then run accessibility-tree and supported-platform checks.",
            ),
            "architecture_and_ci": _evidence_measure(
                "NOT_RUN" if source_paths else "APPLICABILITY_REQUIRED",
                0,
                len(source_paths),
                "Changed source count is scope only; this read-only MCP operation did not run architecture gates or CI.",
                "Run ForgeLine architecture checks and required CI on the exact candidate SHA.",
            ),
            "repository_instruction_injection": _evidence_measure(
                "NOT_RUN"
                if gap_by_id["repository_instruction_and_injection_resistance"][
                    "candidate_path_denominator"
                ]
                else "NOT_TRIGGERED",
                0,
                gap_by_id["repository_instruction_and_injection_resistance"][
                    "candidate_path_denominator"
                ],
                "Denominator is changed paths whose file names indicate agent, prompt, instruction, skill, or policy content.",
                "Run adversarial repository-instruction fixtures through candidate review and tool-output routes.",
            ),
            "authenticated_runner_provenance": {
                "state": "UNAUTHENTICATED"
                if coverage.get("receipt_status") == "MATCHED_UNAUTHENTICATED"
                else "NOT_AVAILABLE",
                "eligible_receipts": 1 if coverage.get("receipt_sha256") else 0,
                "authenticated_receipts": 0,
                "evidence_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "A declared execution-profile inventory for all required CI receipts on this candidate.",
                "basis": "Receipt presence is reported separately. The complete required receipt set is not declared here, so an authentication percentage is not measurable.",
                "next_action": "Use a verified clean-runner/provider-attested receipt bound to candidate, tools, environment, and commands.",
            },
            "specialty_ai_review_and_consensus": {
                "state": "NOT_AUTHENTICATED",
                "eligible_candidate_reviews": None,
                "authenticated_specialty_reviews": 0,
                "evidence_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "A risk-tiered review policy defining the required specialty roles and independent review passes.",
                "basis": "No review policy declares how many specialty roles or passes are required; a 0% score would invent that denominator.",
                "next_action": "Attach a separate specialty AI review bound to the same candidate SHA and retain dissent/adjudication evidence.",
            },
            "reviewer_consensus": {
                "state": "UNMEASURABLE",
                "eligible_review_passes": None,
                "agreed_findings": None,
                "evidence_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "A risk-tiered policy defining independent review passes, reviewer diversity, and consensus/adjudication criteria.",
                "basis": "No policy-defined number or diversity of independent review passes is supplied.",
                "next_action": "Declare the applicable review-pass policy, collect independent candidate-bound assessments, and retain disagreements with adjudication.",
            },
            "attribution_integrity": {
                "state": "UNMEASURABLE",
                "measurement_state": "UNMEASURABLE",
                "applicability_state": "UNDETERMINED",
                "eligible_completed_tasks": None,
                "authenticated_factoryline_uses": 0,
                "attribution_rate_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "Authenticated host task events for completed work in the candidate change window.",
                "basis": "The changelist request provides no trusted Junie/Codex task-usage events; self-declared tool names cannot be counted as authenticated use.",
                "next_action": "Bind contribution receipts to authenticated host task/tool events before calculating an attribution rate; keep the value null until a trusted denominator is available.",
            },
            "agent_workflow_effectiveness": {
                "state": "UNMEASURABLE",
                "measurement_state": "UNMEASURABLE",
                "applicability_state": "UNDETERMINED",
                "eligible_completed_tasks": None,
                "verified_prevention_claims": None,
                "verified_resolutions": None,
                "recurrence_rate_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "Authenticated host task/tool events joined to candidate-bound CF/FL receipts and deduplicated finding/fix identities over a declared time window.",
                "basis": "The selected skill history ends on 2026-09-13 and has no authenticated Codex task IDs, host event IDs, candidate digest, or post-fix verification link. Its 529 learning rows and 982 lesson rows cannot establish distinct runs, proven prevention, or workflow effectiveness.",
                "next_action": "Add an opt-in host adapter that binds each agent task and CF/FL receipt to stable finding and fix identities, records a verified rerun, and reports distinct-task recurrence with explicit inclusion rules.",
            },
            "tenant_and_production_observability": {
                "state": "UNMEASURABLE",
                "eligible_changed_paths": None,
                "evidence_paths": 0,
                "evidence_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "A project applicability declaration plus the affected tenant/data-plane and deployed-service inventory.",
                "basis": "No applicability declaration or staging/production observation was supplied; a safe denominator cannot be inferred from filenames.",
                "next_action": "Declare tenant and production-runtime applicability; when applicable, run isolation and staging observability/rollback checks.",
            },
            "production_observability": {
                "state": "UNMEASURABLE",
                "eligible_deployed_services": None,
                "observed_services": 0,
                "evidence_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "A deployment/service inventory plus declared staging/production verification requirements for this candidate.",
                "basis": "The candidate changelist does not establish which services or external runtime jobs are affected.",
                "next_action": "Map affected deployables and dependent jobs, then inspect isolated runtime logs, telemetry, health, and rollback behavior.",
            },
            "target_project_runtime_coverage": {
                "state": "UNSUPPORTED",
                "eligible_changed_paths": None,
                "evidence_paths": 0,
                "evidence_percent": None,
                "denominator_state": "UNKNOWN",
                "denominator_requirement": "A target-project runtime coverage receipt in a supported language, bound to the candidate and execution profile.",
                "basis": "The attached Coverage.py data covers only Code Factory's internal factoryline/*.py paths; it is not target-project runtime coverage.",
                "next_action": "Run the target project's native instrumentation in a clean runner and attach statement and branch denominators with the receipt.",
            },
        },
        "runtime_coverage": {
            "state": coverage.get("state", "UNBOUND"),
            "receipt_status": coverage.get("receipt_status", "MISSING"),
            "eligible_changed_factoryline_python_modules": len(runtime_supported),
            "source_bound_changed_modules": len(matched_modules),
            "authenticated_changed_modules": 0,
            "changed_python_modules_measured": len(matched_modules),
            "changed_python_module_evidence_percent": _percent(
                len(matched_modules), len(runtime_supported)
            )
            if runtime_supported
            else None,
            "statement_counts": statement,
            "branch_counts": branch,
            "report_file_count": coverage.get("file_count"),
            "scope_limit": "The current Coverage.py validator binds the Code Factory factoryline/ Python inventory; it does not measure arbitrary target-project languages or paths.",
        },
        "audit_gaps": {
            "total": len(gaps),
            "counts_by_status": dict(sorted(gap_counts.items())),
        },
        "seeded_scanner_benchmark": benchmark,
        "trace": {
            "step_count": len(trace.get("steps", [])),
            "trace_sha256": trace.get("trace_sha256"),
            "authentication": trace.get("authentication"),
        },
        "interpretation": "Counts describe inspected inputs and bound evidence only. They do not represent correctness, security, test strength, authenticated review, or release readiness.",
    }
    for measurement_id in audit_domain_ids():
        row = result["audit_lane_coverage"].get(measurement_id)
        if not isinstance(row, dict):
            continue
        row.setdefault(
            "measurement_state",
            _measurement_state(str(row.get("state", "NOT_MEASURED"))),
        )
        if "applicability_state" not in row:
            denominator = next(
                (
                    row[field]
                    for field in (
                        "eligible_changed_paths",
                        "eligible_cases",
                        "eligible_receipts",
                        "eligible_candidate_reviews",
                        "eligible_completed_tasks",
                        "eligible_review_passes",
                        "eligible_deployed_services",
                    )
                    if type(row.get(field)) is int
                ),
                None,
            )
            row["applicability_state"] = (
                "APPLICABLE"
                if denominator is not None and denominator > 0
                else "UNDETERMINED"
            )
    return result


def _percent(numerator: int, denominator: int) -> float | None:
    return round(100 * numerator / denominator, 2) if denominator else None


def _evidence_measure(
    state: str, evidence_paths: int, eligible_paths: int, basis: str, next_action: str
) -> dict[str, Any]:
    return {
        "state": state,
        "measurement_state": _measurement_state(state),
        "eligible_changed_paths": eligible_paths,
        "denominator_state": "KNOWN_CHANGED_PATH_SCOPE",
        "evidence_paths": evidence_paths,
        "evidence_percent": _percent(evidence_paths, eligible_paths),
        "basis": basis,
        "next_action": next_action,
    }


def _aggregate_runtime_measure(
    modules: list[dict[str, Any]], key: str
) -> dict[str, Any]:
    valid = [item[key] for item in modules if isinstance(item.get(key), dict)]
    covered = sum(item["covered"] for item in valid)
    total = sum(item["total"] for item in valid)
    return {
        "modules": len(valid),
        "covered": covered if valid else None,
        "total": total if valid else None,
        "coverage_percent": _percent(covered, total) if valid else None,
    }


def _gap_measurement(gap: dict[str, Any]) -> dict[str, Any]:
    gap_id = gap["id"]
    denominator_field = _GAP_DENOMINATOR_FIELDS.get(gap_id)
    denominator = gap.get(denominator_field) if denominator_field else None
    if type(denominator) is not int:
        denominator = None
    if gap_id == "security_language_coverage":
        denominator = gap.get("recognized_source_candidate_denominator")
        if type(denominator) is not int:
            denominator = None
        components = {
            "python": gap.get("python_candidate_denominator"),
            "non_python": gap.get("non_python_candidate_denominator"),
            "unclassified": gap.get("unclassified_candidate_denominator"),
        }
        denominator_state = (
            "PARTIAL_LANGUAGE_CLASSIFICATION"
            if components["unclassified"]
            else "KNOWN_RECOGNIZED_SOURCE_SCOPE"
        )
    else:
        components = None
        denominator_state = (
            gap.get("denominator_quality", "KNOWN_CHANGED_PATH_SCOPE")
            if denominator is not None
            else "UNKNOWN_APPLICABILITY"
        )
    evidence = gap.get(
        "candidate_paths_measured", gap.get("candidate_paths_executed", 0)
    )
    if type(evidence) is not int:
        evidence = 0
    affected = gap.get("affected_paths", [])
    result = {
        "id": gap_id,
        "measurement_id": _GAP_MEASUREMENT_LINKS.get(gap_id, gap_id),
        "status": gap["status"],
        "measurement_state": _measurement_state(str(gap["status"])),
        "trace_state": gap["trace_state"],
        "eligible_changed_paths": denominator,
        "candidate_scope_paths": len(affected) if isinstance(affected, list) else None,
        "denominator_state": denominator_state,
        "evidence_paths": evidence,
        "evidence_percent": _percent(evidence, denominator)
        if denominator is not None
        else None,
        "action": gap["action"],
        "denominator_requirement": gap.get("denominator_requirement"),
    }
    if components is not None:
        result["component_denominators"] = components
    return result


def _is_test_path(path: str) -> bool:
    relative = PurePosixPath(path)
    lowered = [part.lower() for part in relative.parts]
    filename = relative.name.lower()
    return (
        any(part in {"test", "tests", "spec", "specs", "__tests__"} for part in lowered)
        or filename.startswith(("test_", "spec_"))
        or filename.endswith(
            ("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")
        )
    )


def _review_workspace_paths(
    root: Path | str, arguments: object
) -> tuple[Path, list[str]]:
    workspace = Path(root).resolve()
    if not workspace.is_dir():
        raise JunieReviewError("workspace root must be an existing directory")
    return workspace, _changed_paths(workspace, arguments)


def _assert_trace_snapshot(
    trace: dict[str, Any], path_hashes: dict[str, str], runtime_snapshot: dict[str, Any]
) -> None:
    runtime_state = _state_for(runtime_snapshot)
    if (
        trace["changed_files"] != path_hashes
        or _trace_runtime_state(trace) != runtime_state
        or (
            runtime_state == "PASS"
            and (
                trace["runtime_coverage"].get("report_sha256")
                != runtime_snapshot.get("source_sha256")
                or trace["runtime_coverage"].get("receipt_sha256")
                != runtime_snapshot.get("receipt_sha256")
            )
        )
    ):
        raise JunieReviewError(
            "candidate or evidence changed while the review trace was being assembled",
            "JUNIE_REVIEW_TRACE_RACE",
        )


def _build_review_trace(
    workspace: Path, paths: list[str]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        path_hashes = {
            path: hashlib.sha256(
                (workspace / Path(*PurePosixPath(path).parts)).read_bytes()
            ).hexdigest()
            for path in paths
        }
        runtime_snapshot = read_runtime_coverage_report(workspace)
        gaps = _known_gaps(workspace, paths, runtime_snapshot)
        digest = (
            runtime_snapshot.get("receipt_sha256")
            or runtime_snapshot.get("source_sha256")
            or runtime_snapshot.get("state")
            or "UNBOUND"
        )
        trace = build_audit_trace(
            workspace,
            changed_paths=paths,
            lane_states={"junie_changelist_review": "PASS"},
            steps=_steps(
                {
                    "candidate": _hash({"paths": path_hashes}),
                    "runtime": _hash({"digest": digest}),
                    "runtime_state": _state_for(runtime_snapshot),
                },
                paths,
                gaps,
            ),
        )
        _assert_trace_snapshot(trace, path_hashes, runtime_snapshot)
        return trace, gaps
    except AuditTraceError as exc:
        raise JunieReviewError(str(exc), "JUNIE_REVIEW_TRACE_INCOMPLETE") from exc
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, JunieReviewError):
            raise
        raise JunieReviewError(
            str(exc)[:240], "JUNIE_REVIEW_EVIDENCE_UNAVAILABLE"
        ) from exc


def _action_execution_contract() -> dict[str, Any]:
    from .audit_action_refs import ACTION_EXECUTION_CONTRACT

    return dict(ACTION_EXECUTION_CONTRACT)


def _review_measurements(
    workspace: Path, paths: list[str], trace: dict[str, Any], gaps: list[dict[str, Any]]
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    dict[str, Any],
    str,
    dict[str, Any],
]:
    coverage = _coverage_details(workspace, paths, trace)
    graph = trace["graph_impact"]
    evidence_state = (
        "BOUND_UNAUTHENTICATED"
        if graph["state"] == "BOUND" and coverage["state"] == "BOUND_UNAUTHENTICATED"
        else "INCOMPLETE"
    )
    candidate_sha256 = _hash(
        {
            "candidate": trace["candidate"],
            "changed_files": trace["changed_files"],
            "trace_sha256": trace["trace_sha256"],
        }
    )
    taxonomy_sha256 = audit_taxonomy()["taxonomy_sha256"]
    measurements = _measurements(paths, coverage, gaps, trace)
    measurements["candidate_sha256"] = candidate_sha256
    measurements["taxonomy_sha256"] = taxonomy_sha256
    candidate = {**trace["candidate"], "candidate_sha256": candidate_sha256}
    agent_actions = _agent_actions(measurements)
    contract = _action_execution_contract()
    measurements["measurement_sha256"] = _hash(
        {
            "candidate_sha256": candidate_sha256,
            "changed_files": trace["changed_files"],
            "trace_contract": (trace["trace_sha256"], contract),
            "measurements": {
                key: value
                for key, value in measurements.items()
                if key not in {"measurement_sha256", "completeness"}
            },
            "agent_actions": agent_actions,
        }
    )
    measurements["completeness"] = _measurement_completeness(
        measurements, agent_actions, candidate, contract, trace
    )
    return coverage, candidate, agent_actions, contract, evidence_state, measurements


def _review_result(
    paths: list[str],
    trace: dict[str, Any],
    gaps: list[dict[str, Any]],
    coverage: dict[str, Any],
    candidate: dict[str, Any],
    agent_actions: list[dict[str, Any]],
    contract: dict[str, Any],
    evidence_state: str,
    measurements: dict[str, Any],
) -> dict[str, Any]:
    path_indexes = {path: index for index, path in enumerate(paths)}
    return {
        "schema": "factory.junie-review.v1",
        "marker": "JUNIE_CHANGE_REVIEW_READ_ONLY",
        "source": "jetbrains_active_changelist",
        "evidence_state": evidence_state,
        "audit_state": "INCOMPLETE",
        "candidate": candidate,
        "changed_files": [
            {"path": path, "sha256": trace["changed_files"][path]} for path in paths
        ],
        "graph_impact": trace["graph_impact"],
        "runtime_coverage": coverage,
        "known_gaps": {
            gap["id"]: {
                "status": gap["status"],
                "trace_state": gap["trace_state"],
                "affected_path_indices": [
                    path_indexes[path]
                    for path in gap.get("affected_paths", [])
                    if path in path_indexes
                ],
                **(
                    {"manifest_sha256": gap["manifest_sha256"]}
                    if gap.get("manifest_sha256")
                    else {}
                ),
            }
            for gap in gaps
        },
        "measurements": measurements,
        "agent_actions": agent_actions,
        "action_execution_contract": contract,
        "trace": trace,
        "authority": dict(_AUTHORITY),
        "claim_boundary": "Paths came from MCP input; this tool cannot inspect JetBrains UI or authenticate Junie. It ran no code or tests and has no approval, merge, publication, deployment, signing, credential, network, or certification authority.",
    }


def build_junie_review(root: Path | str, arguments: object) -> dict[str, Any]:
    """Bind JetBrains-supplied changed paths to read-only graph and runtime evidence."""
    workspace, paths = _review_workspace_paths(root, arguments)
    trace, gaps = _build_review_trace(workspace, paths)
    coverage, candidate, actions, contract, state, measurements = _review_measurements(
        workspace, paths, trace, gaps
    )
    result = _review_result(
        paths, trace, gaps, coverage, candidate, actions, contract, state, measurements
    )
    if len(_canonical(result)) > MAX_RESPONSE_BYTES:
        raise JunieReviewError(
            "review response exceeds the 64 KiB response limit",
            "JUNIE_REVIEW_TOO_LARGE",
        )
    return result


def _unresolved_measurements(
    rows: dict[str, Any], measurement_ids: set[str]
) -> list[dict[str, Any]]:
    unresolved = []
    for measurement_id in sorted(measurement_ids):
        item = rows.get(measurement_id)
        if not isinstance(item, dict):
            unresolved.append(
                {
                    "measurement_id": measurement_id,
                    "state": "NOT_MEASURED",
                    "denominator_state": "MISSING_LEDGER_ENTRY",
                    "action_ref": f"agent_actions[{measurement_id}]",
                }
            )
            continue
        state = item.get("measurement_state") or _measurement_state(
            str(item.get("state", "NOT_RUN"))
        )
        if state not in {"MEASURED", "NOT_APPLICABLE"}:
            unresolved.append(
                {
                    "measurement_id": measurement_id,
                    "state": state,
                    "denominator_state": item.get("denominator_state"),
                    "action_ref": f"agent_actions[{measurement_id}]",
                }
            )
    return unresolved


def _action_id_error(action: dict[str, Any], action_ids: set[str]) -> str | None:
    measurement_id = action.get("measurement_id")
    fallback = (
        f"benchmark-{action.get('benchmark_action_index')}"
        if action.get("benchmark_action_index") is not None
        else measurement_id
    )
    action_id = action.get("id", fallback)
    if not isinstance(action_id, str) or action_id in action_ids:
        return "agent action IDs must be present and unique"
    action_ids.add(action_id)
    return None


def _action_structure_error(action: dict[str, Any]) -> str | None:
    required = (
        "priority",
        "specialist_role",
        "measurement_state",
        "execution_profile",
        "runner_state",
    )
    if not all(action.get(key) for key in required):
        return "agent action is incomplete or lacks a candidate-bound work item"
    if action.get("applicability_state") not in {
        "APPLICABLE",
        "NOT_APPLICABLE",
        "UNDETERMINED",
    }:
        return "agent action is incomplete or lacks a candidate-bound work item"
    if not isinstance(action.get("dependencies"), list):
        return "agent action is incomplete or lacks a candidate-bound work item"
    if action.get("runner_state") != "HOST_AGENT_EXECUTION":
        return "agent work item must use the supported host-agent execution route"
    return None


def _action_role_error(
    action: dict[str, Any], measurement_ids: set[str], roles: dict[str, set[str]]
) -> str | None:
    measurement_id = action.get("measurement_id")
    if measurement_id not in measurement_ids:
        return "agent action references an unknown taxonomy ID"
    role = action.get("specialist_role")
    if role not in roles:
        return "agent action references an unknown specialist role"
    if (
        action.get("benchmark_action_index") is None
        and measurement_id not in roles[role]
    ):
        return "agent action role does not own its measurement domain"
    if (
        action.get("benchmark_action_index") is not None
        and measurement_id != "seeded_scanner_benchmark"
    ):
        return "benchmark action references a non-benchmark measurement"
    return None


def _resolved_action_types_valid(resolved: dict[str, Any]) -> bool:
    expected = {
        "action": str,
        "evidence": str,
        "denominator": (dict, int, float),
        "completion": str,
        "stop": str,
    }
    return all(isinstance(resolved.get(key), kind) for key, kind in expected.items())


def _action_reference_error(
    action: dict[str, Any], context: dict[str, Any], taxonomy: dict[str, Any]
) -> str | None:
    try:
        resolved = {
            field: resolve_agent_action_reference(context, action, field, taxonomy)
            for field in ("action", "evidence", "denominator", "completion", "stop")
        }
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        return f"agent action reference does not resolve: {exc}"
    if not _resolved_action_types_valid(resolved):
        return "agent action reference resolves to an invalid value type"
    return None


def _validate_agent_actions(
    actions: list[dict[str, Any]],
    context: dict[str, Any],
    taxonomy: dict[str, Any],
    measurement_ids: set[str],
) -> list[str]:
    action_ids: set[str] = set()
    roles = {
        role["specialist_role"]: set(role["measurement_ids"])
        for role in taxonomy["specialist_roles"]
    }
    for action in actions:
        error = _action_id_error(action, action_ids) or _action_structure_error(action)
        error = error or _action_role_error(action, measurement_ids, roles)
        error = error or _action_reference_error(action, context, taxonomy)
        if error:
            return [error]
    return []


def _measurement_completeness(
    measurements: dict[str, Any],
    agent_actions: list[dict[str, Any]],
    candidate: dict[str, Any],
    action_execution_contract: dict[str, Any],
    trace: dict[str, Any],
) -> dict[str, Any]:
    measurement_ids = set(audit_domain_ids())
    rows = measurements.get("audit_lane_coverage", {})
    structural_errors = validate_measurement_ledger(
        {key: rows.get(key) for key in measurement_ids}
    )
    taxonomy = audit_taxonomy()
    if (
        not isinstance(measurements.get("candidate_sha256"), str)
        or len(measurements["candidate_sha256"]) != 64
    ):
        structural_errors.append("candidate digest is missing or malformed")
    if measurements.get("taxonomy_sha256") != taxonomy["taxonomy_sha256"]:
        structural_errors.append("report taxonomy digest is missing or stale")
    context = {
        "candidate": candidate,
        "measurements": measurements,
        "action_execution_contract": action_execution_contract,
        "agent_actions": agent_actions,
        "trace": trace,
    }
    unresolved = _unresolved_measurements(rows, measurement_ids)
    structural_errors.extend(
        _validate_agent_actions(agent_actions, context, taxonomy, measurement_ids)
    )
    action_measurements = {action.get("measurement_id") for action in agent_actions}
    missing_actions = {
        item["measurement_id"] for item in unresolved
    } - action_measurements
    if missing_actions:
        structural_errors.append(
            "unresolved measurements lack agent actions: "
            + ", ".join(sorted(missing_actions))
        )
    benchmark = measurements.get("seeded_scanner_benchmark", {})
    if benchmark.get("state") != "MEASURED" or not benchmark.get("case_count"):
        structural_errors.append("seeded scanner benchmark lacks measured cases")
    return {
        "state": "COMPLETE"
        if not unresolved and not structural_errors
        else "INCOMPLETE",
        "required_measurement_count": len(audit_domain_ids()),
        "unresolved_count": len(unresolved),
        "unresolved": unresolved,
        "structural_errors": structural_errors,
        "agent_action_count": len(agent_actions),
        "interpretation": "A complete ledger requires taxonomy parity, explicit denominators or evidenced unknowns, a valid benchmark record, and an agent work item for each unresolved applicable measurement.",
    }


def _agent_actions(measurements: dict[str, Any]) -> list[dict[str, Any]]:
    """Create one taxonomy-routed agent task for every unresolved measurement."""
    from .audit_taxonomy import domain_definition

    rows = measurements.get("audit_lane_coverage", {})
    actions = []
    for measurement_id in audit_domain_ids():
        measurement = rows.get(measurement_id)
        if not isinstance(measurement, dict):
            continue
        state = measurement.get("measurement_state") or _measurement_state(
            str(measurement.get("state", "NOT_RUN"))
        )
        domain = domain_definition(measurement_id) or {}
        if state in {"MEASURED", "NOT_APPLICABLE"}:
            if measurement_id != "seeded_scanner_benchmark":
                continue
            benchmark_actions = measurement.get("agent_actions", [])
            for index, row in enumerate(benchmark_actions):
                role = row.get(
                    "agent_role",
                    domain.get("specialist_role", "specialty_ai_evaluation_agent"),
                )
                actions.append(
                    {
                        "measurement_id": measurement_id,
                        "benchmark_action_index": index,
                        "specialist_role": role,
                        "priority": row.get("priority", "P2"),
                        "measurement_state": "BLOCKED",
                        "applicability_state": "APPLICABLE",
                        "dependencies": [],
                        "execution_profile": "factoryline_public_seeded_corpus",
                        "runner_state": "HOST_AGENT_EXECUTION",
                    }
                )
            continue
        role = domain.get("specialist_role", "audit_orchestrator_agent")
        priority = (
            "P1"
            if domain.get("category")
            in {
                "security",
                "security_privacy",
                "security_operations",
                "test_oracle",
                "evidence_trust",
                "supply_chain",
                "data_safety",
                "agent_security",
                "delivery_integrity",
                "runtime_behavior",
            }
            else "P2"
        )
        actions.append(
            {
                "measurement_id": measurement_id,
                "priority": priority,
                "measurement_state": state,
                "specialist_role": role,
                "applicability_state": measurement.get(
                    "applicability_state", "UNDETERMINED"
                ),
                "execution_profile": "isolated_clean_ci"
                if state != "UNMEASURABLE"
                else "applicability_or_denominator_inventory",
                "runner_state": "HOST_AGENT_EXECUTION",
                "dependencies": [],
            }
        )
    return actions


def _state_for(snapshot: dict[str, Any]) -> str:
    if snapshot.get("receipt_status") == "MATCHED_UNAUTHENTICATED":
        return "INCOMPLETE"
    state = snapshot.get("state")
    if state in {"NOT_RUN", "INCOMPLETE", "FAIL"}:
        return state
    return "UNBOUND"


def _trace_runtime_state(trace: dict[str, Any]) -> str:
    state = trace.get("runtime_coverage", {}).get("state")
    if state == "BOUND_UNAUTHENTICATED":
        return "INCOMPLETE"
    return state if state in {"NOT_RUN", "INCOMPLETE", "FAIL", "UNBOUND"} else "UNBOUND"
